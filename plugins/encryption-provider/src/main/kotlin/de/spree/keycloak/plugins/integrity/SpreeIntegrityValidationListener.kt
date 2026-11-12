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

import arrow.core.recover
import de.spree.keycloak.commons.configuration.IT_FAILED
import de.spree.keycloak.commons.configuration.SpreeEntityConfiguration
import de.spree.keycloak.commons.configuration.SystemState.ERROR_ROW_CHECKSUM
import de.spree.keycloak.commons.configuration.SystemStateService
import de.spree.keycloak.commons.debug.SpreeLog
import de.spree.keycloak.commons.isIntegrityException
import de.spree.keycloak.commons.isKeycloakModelClass
import de.spree.keycloak.commons.logger
import de.spree.keycloak.integrity.ChecksumService
import de.spree.keycloak.integrity.ConfigurationService
import de.spree.keycloak.integrity.SpreeDatabaseConversionState
import de.spree.keycloak.plugins.integrity.Action.*
import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import org.hibernate.Session
import org.hibernate.collection.spi.PersistentCollection
import org.hibernate.event.spi.*
import java.util.logging.Logger

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
	private lateinit var checksumService: ChecksumService

	@Inject //
	private lateinit var systemStateService: SystemStateService

	@Suppress("CdiInjectionPointsInspection")
	@Inject
	@SpreeLog
	private lateinit var spreeLogger: Logger

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
		val entityAction = event.toEntityAction(INSERT)

		if (checkIntegrity(entityAction)) {
			handleUpdateEvent(event, entityAction)
		}
	}

	/**
	 * Handles post-update events by updating the entity's checksum.
	 *
	 * @param event The post-update event.
	 */
	override fun onPostUpdate(event: PostUpdateEvent) {
		val entityAction = event.toEntityAction(UPDATE)

		if (checkIntegrity(entityAction)) {
			handleUpdateEvent(event, entityAction)
		}
	}

	/**
	 * Handles post-upsert events by updating the entity's checksum.
	 *
	 * @param event The post-upsert event.
	 */
	override fun onPostUpsert(event: PostUpsertEvent) {
		val entityClass = event.entity.javaClass.simpleName
		val entityId = event.id

		error("Unsupported UPSERT on »$entityClass#$entityId«")
	}

	/**
	 * Handles post-update collection events by updating the owner's checksum.
	 *
	 * @param event The post-collection update event.
	 */
	override fun onPostUpdateCollection(event: PostCollectionUpdateEvent) {
		val entityAction = event.toEntityAction()

		if (entityAction != null && checkIntegrity(entityAction)) {
			handleCollectionChange(event, entityAction)
		}
	}

	/**
	 * Handles post-recreate collection events by updating the owner's checksum.
	 *
	 * @param event The post-collection recreate event.
	 */
	override fun onPostRecreateCollection(event: PostCollectionRecreateEvent) {
		val entityAction = event.toEntityAction()

		if (entityAction != null && checkIntegrity(entityAction)) {
			handleCollectionChange(event, entityAction)
		}
	}

	/**
	 * Handles post-remove collection events by updating the owner's checksum.
	 *
	 * @param event The post-collection remove event.
	 */
	override fun onPostRemoveCollection(event: PostCollectionRemoveEvent) {
		val entityAction = event.toEntityAction()

		if (entityAction != null && checkIntegrity(entityAction)) {
			handleCollectionChange(event, entityAction)
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
		val entityAction = event.toEntityAction()

		if (checkIntegrity(entityAction)) {
			handleLoadEvent(event, entityAction)
		}
	}

	/**
	 * Handles post-delete events.
	 *
	 * @param event The post-delete event.
	 */
	override fun onPostDelete(event: PostDeleteEvent) {
		val entityAction = event.toEntityAction(DELETE)

		if (checkIntegrity(entityAction)) {
			handleDeletionEvent(event, entityAction)
		}
	}

	/**
	 * Decides whether the event for [action] has to be processed at all.
	 *
	 * The cheap entity filter has to come first: [ConfigurationService.getConversionState] reads Spree's own configuration table, which fires another
	 * post-load event per [Configuration][de.spree.keycloak.integrity.Configuration] row. Asking for the conversion state before knowing whether the
	 * entity is one of ours would recurse until the stack blows up. All `handleXxx` bodies below are guarded by [isHandled] anyway, so hoisting the
	 * check here does not change what we act upon.
	 */
	private fun checkIntegrity(action: EntityAction) =
		rowIntegrityChecksEnabled(action.entityName) &&
			(systemStateService.spreeIntegrityProviderRunning() || configurationService.getConversionState(action) == SpreeDatabaseConversionState.DONE)

	/**
	 * Handles update events (insert or update) by updating the entity's checksum.
	 *
	 * Throws an [IllegalStateException] if the checksum update fails.
	 *
	 * @param event The post-database operation event.
	 */
	private fun handleUpdateEvent(event: AbstractPostDatabaseOperationEvent, entityAction: EntityAction) {
		val entity = event.entity
		val entityClass = entity.javaClass
		val eventType = event.javaClass.simpleName
		val entityId = event.id

		spreeLogger.info("[$eventType] entity: »${entityClass.simpleName}#$entityId« was altered")

		if (entityClass.isHandled()) {
			checksumService.updateEntityChecksums(entityAction, entity).onLeft { throw it }
		}
	}

	/**
	 * Handles collection change events by updating the affected owner's checksum.
	 *
	 * @param event The collection event.
	 */
	private fun handleCollectionChange(event: AbstractCollectionEvent, entityAction: EntityAction) {
		val parentEntity = event.affectedOwnerOrNull ?: return
		val entityClass = parentEntity.javaClass
		val eventType = event.javaClass.simpleName
		val collectionName = event.collection.collectionName()
		val entityId = event.affectedOwnerIdOrNull
		val ignoredProperty = entityConfiguration.isPropertyIgnored(entityAction.entityName, collectionName)

		spreeLogger.info(
			"[$eventType] Collection »$collectionName« on »${entityAction.entityName}#$entityId« was altered" + (if (ignoredProperty) " (IGNORED)" else "")
		)

		if (entityClass.isHandled() && !ignoredProperty) {
			checksumService.updateEntityChecksums(entityAction, parentEntity).onLeft { throw it }
		}
	}

	private fun PersistentCollection<*>.collectionName() = when (val index = role?.lastIndexOf('.')) {
		null -> "<unknown>"
		else -> role!!.substring(index + 1)
	}

	/**
	 * Validates the loaded entity's checksum against the stored checksum.
	 *
	 * Throws a [RuntimeException] if checksum validation fails.
	 *
	 * @param event The post-load event.
	 */
	private fun handleLoadEvent(event: PostLoadEvent, entityAction: EntityAction) {
		val entity = event.entity
		val entityClass = entity.javaClass
		val entityName = entityClass.name
		val eventType = event.javaClass.simpleName
		val entityId = event.id.toString()

		spreeLogger.info("[$eventType] entity: »${entityClass.simpleName}#$entityId« was loaded")

		if (entityClass.isHandled()) {
			checksumService.validateEntityChecksum(entityAction, entity)
				.onRight { systemStateService.clearVolatileError(entityName, entityId) }
				.recover { if (systemStateService.shouldIgnoreVolatileError(entityName, entityId)) Unit else raise(it) }
				.onLeft {
					if (it.isIntegrityException()) {
						systemStateService.setSystemState(ERROR_ROW_CHECKSUM, it)

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
	private fun handleDeletionEvent(event: PostDeleteEvent, entityAction: EntityAction) {
		val entity = event.entity
		val entityClass = entity.javaClass

		if (entityClass.isHandled()) {
			val entityId = event.id
			val eventType = event.javaClass.simpleName

			spreeLogger.info("[$eventType] entity: »${entityClass.simpleName}#$entityId« was deleted")

			checksumService.updateEntityChecksums(entityAction, entity).onLeft { throw it }
		}
	}

	private fun AbstractPostDatabaseOperationEvent.toEntityAction(action: Action) =
		EntityAction(action, entity.javaClass.name, session.unwrap(Session::class.java))

	private fun AbstractCollectionEvent.toEntityAction(): EntityAction? {
		val parentEntity = affectedOwnerOrNull

		return if (parentEntity != null) {
			EntityAction(COLLECTION_UPDATE, parentEntity.javaClass.name, session, "Collection: »${collection.collectionName()}«")
		} else {
			null
		}
	}

	private fun PostLoadEvent.toEntityAction() = EntityAction(LOAD, entity.javaClass.name, session)

	/**
	 * Checks if the entity is a Keycloak entity (i.e., not a checksum-related entity).
	 *
	 * @return True if the entity has to be handled, false otherwise.
	 */
	fun rowIntegrityChecksEnabled(entityName: String): Boolean {
		val handledByDefault = !unhandledClasses.contains(entityName)

		return handledByDefault && isEntityHandled(entityName)
	}

	private fun isEntityHandled(entityName: String): Boolean = when {
		!entityName.isKeycloakModelClass() -> {
			logger.debug("⚠️ Not handling non-Keycloak model class »$entityName«")
			false
		}

		!entityConfiguration.entityNames.contains(entityName) -> {
			logger.debug("⚠️ Ignoring Keycloak model class »$entityName«")
			false
		}

		else -> {
			entityConfiguration.rowChecksumEnabled(entityName)
		}
	}

	/**
	 * Helper extension to check if a entity is configured to have its integrity validated.
	 *
	 * @return True if the entity is checked, false otherwise.
	 */
	private fun Class<*>.isHandled() = rowIntegrityChecksEnabled(name)
}
