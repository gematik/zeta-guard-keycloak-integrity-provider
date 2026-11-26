/*-
 * #%L
 * keycloak-integrity-provider
 * %%
 * (C) tech@Spree GmbH, 2026, licensed for gematik GmbH
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 * #L%
 */
package de.spree.keycloak.plugins.integrity

import de.spree.keycloak.commons.configuration.IT_FAILED
import de.spree.keycloak.commons.configuration.SpreeEntityConfiguration
import de.spree.keycloak.commons.configuration.SystemStatus.ERROR_ROW_CHECKSUM
import de.spree.keycloak.commons.configuration.SystemStatusService
import de.spree.keycloak.commons.debug.SpreeLog
import de.spree.keycloak.commons.isIntegrityException
import de.spree.keycloak.commons.isKeycloakModelClass
import de.spree.keycloak.commons.logger
import de.spree.keycloak.integrity.*
import de.spree.keycloak.plugins.integrity.Action.*
import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import jakarta.persistence.EntityManager
import java.util.logging.Logger
import org.hibernate.Session
import org.hibernate.event.spi.*

data class EntityAction(val action: Action, val entityName: String, val entityManager: EntityManager, val optionalInfo: String? = null) {
  val clazz: Class<*>
    get() = Class.forName(entityName)

  override fun toString() = action.name + (optionalInfo?.let { "($it)" } ?: "")
}

enum class Action {
  INITIALIZE,
  SCAN,
  LOAD,
  INSERT,
  UPDATE,
  UPSERT,
  COLLECTION_UPDATE,
  DELETE,
}

private val unhandledClasses = SPREE_ENTITY_CLASSES.map { it.name }

/**
 * Hibernate event listener for validating and updating entity checksums in Keycloak.
 *
 * This listener implements several post-database operation events to ensure data integrity by validating checksums on load and updating them on
 * insert, update, or collection changes.
 */
@ApplicationScoped
class SpreeIntegrityValidationListener :
    PostInsertEventListener,
    PostUpdateEventListener,
    PostDeleteEventListener,
    PostLoadEventListener,
    PostCollectionUpdateEventListener,
    PostCollectionRecreateEventListener,
    PostCollectionRemoveEventListener,
    PostUpsertEventListener {
  @Inject //
  private lateinit var rowChecksumService: RowChecksumService

  @Inject //
  private lateinit var tableChecksumService: TableChecksumService

  @Inject //
  private lateinit var systemStatusService: SystemStatusService

  @Suppress("CdiInjectionPointsInspection") @Inject @SpreeLog private lateinit var spreeLogger: Logger

  @Inject //
  private lateinit var entityConfiguration: SpreeEntityConfiguration

  @Inject //
  private lateinit var configurationService: ConfigurationService

  /**
   * Handles post-insert events by updating the entity's checksum.
   *
   * @param event The post-insert event.
   */
  override fun onPostInsert(event: PostInsertEvent) {
    if (integrityEnabled()) {
      handleUpdateEvent(event, INSERT)
    }
  }

  /**
   * Handles post-update events by updating the entity's checksum.
   *
   * @param event The post-update event.
   */
  override fun onPostUpdate(event: PostUpdateEvent) {
    if (integrityEnabled()) {
      handleUpdateEvent(event, UPDATE)
    }
  }

  /**
   * Handles post-upsert events by updating the entity's checksum.
   *
   * @param event The post-upsert event.
   */
  override fun onPostUpsert(event: PostUpsertEvent) {
    if (integrityEnabled()) {
      handleUpdateEvent(event, UPSERT)
    }
  }

  /**
   * Handles post-update collection events by updating the owner's checksum.
   *
   * @param event The post-collection update event.
   */
  override fun onPostUpdateCollection(event: PostCollectionUpdateEvent) {
    if (integrityEnabled()) {
      handleCollectionChange(event)
    }
  }

  /**
   * Handles post-recreate collection events by updating the owner's checksum.
   *
   * @param event The post-collection recreate event.
   */
  override fun onPostRecreateCollection(event: PostCollectionRecreateEvent) {
    if (integrityEnabled()) {
      handleCollectionChange(event)
    }
  }

  /**
   * Handles post-remove collection events by updating the owner's checksum.
   *
   * @param event The post-collection remove event.
   */
  override fun onPostRemoveCollection(event: PostCollectionRemoveEvent) {
    if (integrityEnabled()) {
      handleCollectionChange(event)
    }
  }

  /**
   * Handles post-load events by validating the entity's checksum.
   *
   * Throws an [IllegalStateException] if validation fails.
   *
   * @param event The post-load event.
   */
  override fun onPostLoad(event: PostLoadEvent) {
    if (integrityEnabled()) {
      handleLoadEvent(event)
    }
  }

  /**
   * Handles post-delete events.
   *
   * @param event The post-delete event.
   */
  override fun onPostDelete(event: PostDeleteEvent) {
    if (integrityEnabled()) {
      handleDeletionEvent(event)
    }
  }

  private fun integrityEnabled(): Boolean =
      systemStatusService.spreeIntegrityProviderRunning() || configurationService.getConversionState() == SpreeDatabaseConversionState.DONE

  /**
   * Handles update events (insert or update) by updating the entity's checksum.
   *
   * Throws an [IllegalStateException] if the checksum update fails.
   *
   * @param event The post-database operation event.
   */
  private fun handleUpdateEvent(event: AbstractPostDatabaseOperationEvent, action: Action) {
    val entity = event.entity
    val entityClass = entity.javaClass
    val eventType = event.javaClass.simpleName
    val entityId = event.id
    val session = event.session.unwrap(Session::class.java)

    spreeLogger.info("[$eventType] entity: »${entityClass.simpleName}#$entityId« was altered")

    if (entityClass.isHandled()) {
      tableChecksumService.updateEntityChecksums(listOf(entity), EntityAction(action, entityClass.name, session)).onLeft { throw it }
    }
  }

  /**
   * Handles collection change events by updating the affected owner's checksum.
   *
   * @param event The collection event.
   */
  private fun handleCollectionChange(event: AbstractCollectionEvent) {
    val parentEntity = event.affectedOwnerOrNull ?: return
    val entityClass = parentEntity.javaClass
    val eventType = event.javaClass.simpleName
    val collectionName = event.collection.role
    val entityId = event.affectedOwnerIdOrNull

    spreeLogger.info("[$eventType] Collection »$collectionName« on »${entityClass.simpleName}#$entityId« was altered")

    if (entityClass.isHandled()) {
      tableChecksumService
          .updateEntityChecksums(
              listOf(parentEntity),
              EntityAction(COLLECTION_UPDATE, entityClass.name, event.session, "»$collectionName«@»$entityId«"),
          )
          .onLeft { throw it }
    }
  }

  /**
   * Validates the loaded entity's checksum against the stored checksum.
   *
   * Throws a [RuntimeException] if checksum validation fails.
   *
   * @param event The post-load event.
   */
  private fun handleLoadEvent(event: PostLoadEvent) {
    val entity = event.entity
    val entityClass = entity.javaClass
    val eventType = event.javaClass.simpleName
    val entityId = event.id

    spreeLogger.info("[$eventType] entity: »${entityClass.simpleName}#$entityId« was loaded")

    if (entityClass.isHandled()) {
      rowChecksumService.validateEntityChecksum(entity, EntityAction(LOAD, entityClass.name, event.session)).onLeft {
        if (it.isIntegrityException()) {
          systemStatusService.setSystemStatus(ERROR_ROW_CHECKSUM, it)

          throw RuntimeException("$IT_FAILED Checksum validation failed for »${entityClass.simpleName}#$entityId«", it)
        } else {
          throw RuntimeException("Checksum validation failed for »${entityClass.simpleName}#$entityId«", it)
        }
      }
    }
  }

  /**
   * Handles entity deletion events by updating the checksum table for the deleted entity.
   *
   * @param event The post-delete event.
   */
  private fun handleDeletionEvent(event: PostDeleteEvent) {
    val entity = event.entity
    val entityClass = entity.javaClass

    if (entityClass.isHandled()) {
      val entityId = event.id
      val eventType = event.javaClass.simpleName
      val session = event.session.unwrap(Session::class.java)

      spreeLogger.info("[$eventType] entity: »${entityClass.simpleName}#$entityId« was deleted")

      tableChecksumService.updateEntityChecksums(listOf(entity), EntityAction(DELETE, entityClass.name, session)).onLeft { throw it }
    }
  }

  /**
   * Checks if the entity is a Keycloak entity (i.e., not a checksum-related entity).
   *
   * @return True if the entity has to be handled, false otherwise.
   */
  fun isHandled(entityName: String): Boolean {
    val handled = !unhandledClasses.contains(entityName)

    return when {
      handled && !entityName.isKeycloakModelClass() -> {
        logger.warn("⚠️ Not handling non-Keycloak model class »$entityName«")
        false
      }

      handled && !entityConfiguration.entityNames.contains(entityName) -> {
        logger.warn("⚠️ Ignoring Keycloak model class »$entityName«")
        false
      }

      else -> {
        handled
      }
    }
  }

  /**
   * Helper extension to check if a class is configured to have its integrity validated.
   *
   * @return True if the class is handled, false otherwise.
   */
  private fun Class<*>.isHandled() = isHandled(name)
}
