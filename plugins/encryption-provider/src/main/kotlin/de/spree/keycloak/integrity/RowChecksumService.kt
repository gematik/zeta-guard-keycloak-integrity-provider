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
package de.spree.keycloak.integrity

import arrow.core.Either
import arrow.core.raise.either
import arrow.core.raise.ensure
import de.spree.keycloak.commons.*
import de.spree.keycloak.commons.EntityConverter.convertToJSON
import de.spree.keycloak.commons.EntityConverter.lookupEntityInfo
import de.spree.keycloak.commons.configuration.STRING
import de.spree.keycloak.commons.configuration.SpreeEntityConfiguration
import de.spree.keycloak.commons.debug.SpreeLog
import de.spree.keycloak.crypto.*
import de.spree.keycloak.crypto.keychain.CurrentKeychain
import de.spree.keycloak.plugins.integrity.EntityAction
import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import java.util.logging.Logger
import org.hibernate.SessionFactory

/**
 * Service responsible for calculating, validating, and managing entity checksums.
 *
 * This service handles the core logic for ensuring data integrity by generating checksums for entities, signing them, and verifying them against
 * stored values. It interacts with the [EntityConverter] to serialize entities, the [SigningService] to sign and verify hashes, and the
 * [RowChecksumDao] to persist and retrieve checksums.
 */
@ApplicationScoped
class RowChecksumService {
  @Inject //
  private lateinit var signingService: SigningService

  @Inject //
  private lateinit var rowChecksumDao: RowChecksumDao

  @Suppress("CdiInjectionPointsInspection") @Inject @SpreeLog private lateinit var spreeLogger: Logger

  @Inject //
  private lateinit var currentKeychain: CurrentKeychain

  @Inject //
  private lateinit var spreeConfiguration: SpreeEntityConfiguration

  /**
   * Calculates the checksum for a given entity.
   *
   * The process involves:
   * 1. Converting the entity to its JSON representation.
   * 2. Hashing the JSON bytes.
   * 3. Signing the hash using the [SigningService].
   * 4. Combining the hash and signature into a single Base64 encoded string.
   *
   * @param entityInfo Information about the entity
   * @return An [Either] containing the calculated checksum string or a [Throwable] if an error occurs.
   */
  fun calculateRowChecksum(entityInfo: EntityInfo, action: EntityAction): Either<Throwable, Checksum> = either {
    val jsonRepresentation = action.entityManager.convertToJSON(entityInfo.entity).bind()
    val bytes = jsonRepresentation.toByteArray()
    val hash = toHash(bytes)
    val signature = signingService.sign(hash).bind()
    val keychain = currentKeychain.keychain().bind()

    spreeLogger.info("[$action] CHECKSUM: ${entityInfo.entityAsString()}\n$jsonRepresentation")

    ensure(hash.size == HASH_SIZE) { IllegalStateException("Invalid hash size: ${hash.size}") }

    Checksum(keychain.keychainId.toByteArray(), hash, signature)
  }

  /**
   * Validates a stored checksum against a currently calculated checksum.
   *
   * This method verifies that:
   * 1. The hash part of the stored checksum matches the hash part of the current checksum.
   * 2. The signature of the stored checksum is valid for its hash.
   * 3. The signature of the current checksum is valid for its hash.
   *
   * @param storedChecksum The checksum retrieved from storage.
   * @param currentChecksum The checksum calculated from the current state of the entity.
   * @param entityInfo Information about the entity being validated (used for error messaging).
   * @return An [Either] containing [Success] if validation passes, or a [Throwable] if it fails.
   */
  fun validateChecksum(
      storedChecksum: Checksum,
      currentChecksum: Checksum,
      entityInfo: EntityInfo,
      action: EntityAction,
  ): Either<Throwable, Success> = either {
    val storedHash = storedChecksum.hash

    spreeLogger.info("[$action]: VALIDATE: ${entityInfo.entityAsString()}\n${storedHash.toBase64()}\n${currentChecksum.hash.toBase64()}\n ")

    ensure(storedHash.contentEquals(currentChecksum.hash)) { RuntimeException("Row checksum mismatch for $entityInfo") }

    signingService.verify(entityInfo.entityAsString(), storedHash, storedChecksum.signature).bind()
    signingService.verify(entityInfo.entityAsString(), storedHash, currentChecksum.signature).bind()

    SimpleSuccess
  }

  /**
   * Updates or creates the checksum for a given entity.
   *
   * This method:
   * 1. Identifies if the object is a valid entity.
   * 2. Calculates its new checksum.
   * 3. Retrieves the existing [RowChecksum] or creates a new one.
   * 4. Updates the checksum value.
   * 5. Persists the [RowChecksum] if it's new.
   *
   * @param entities The entity object to update the checksum for.
   * @return An [Either] containing the result of the operation or a [Throwable].
   */
  fun updateEntityChecksum(entities: List<Any>, action: EntityAction) = either {
    entities.forEach {
      val entityInfo = action.entityManager.lookupEntityInfo(it).bind()

      updateEntityInfoChecksum(entityInfo, action).bind()
    }
  }

  /**
   * Calculates and updates (or inserts) the checksum for a single entity.
   *
   * @param entityInfo The metadata and actual instance of the entity.
   * @param action The EntityAction context under which the checksum is updated.
   * @return An [Either] containing [Success] if updated/inserted successfully, or a [Throwable].
   */
  fun updateEntityInfoChecksum(entityInfo: EntityInfo, action: EntityAction) = either {
    val checksum = calculateRowChecksum(entityInfo, action).bind()
    val dbChecksum = checksum.toDatabaseRepresentation()
    val existingRowChecksum: RowChecksum? = rowChecksumDao.findByEntityId(entityInfo.rowChecksumId)

    if (existingRowChecksum == null) {
      val currentRowChecksum = RowChecksum(entityName = entityInfo.entityName, entityId = entityInfo.id, checksum = dbChecksum)

      rowChecksumDao.save(currentRowChecksum)
    } else {
      spreeLogger.fine("[$action]: UPDATE_CHECKSUM: ${entityInfo.entityAsString()}\n${existingRowChecksum.checksum} → ${dbChecksum}\n")

      existingRowChecksum.checksum = dbChecksum
    }

    SimpleSuccess
  }

  /**
   * Validates the integrity of a given entity.
   *
   * This method:
   * 1. Identifies the entity.
   * 2. Retrieves its stored checksum.
   * 3. Calculates the current checksum based on the entity's current state.
   * 4. Validates the stored checksum against the current checksum.
   *
   * @param entity The entity object to validate.
   * @return An [Either] containing the result of the validation or a [Throwable].
   */
  fun validateEntityChecksum(entity: Any, action: EntityAction) = either {
    val entityInfo = action.entityManager.lookupEntityInfo(entity).bind()
    val rowChecksum =
        catchAll { rowChecksumDao.findByEntityId(entityInfo.rowChecksumId) }
            ?: raise(IllegalStateException("No row checksum data found for entity ${entityInfo.entityAsString()}"))
    val storedChecksum = rowChecksum.checksum.toChecksum().bind()
    val currentChecksum = calculateRowChecksum(entityInfo, action).bind()

    validateChecksum(storedChecksum, currentChecksum, entityInfo, action).bind()
  }

  /**
   * Deletes the checksum for a given deleted entity.
   *
   * @param entities An entity that has been deleted
   * @return An [Either] containing [Unit] if the deletion was successful or a [Throwable]
   */
  fun deleteEntityChecksum(entities: List<Any>, action: EntityAction) = either {
    catchAll {
      entities.forEach {
        val entityInfo = action.entityManager.lookupEntityInfo(it).bind()

        rowChecksumDao.deleteByEntityId(entityInfo.rowChecksumId)
      }
    }
  }

  /**
   * Deletes a list of [RowChecksum] entities from the database.
   *
   * @param deletedChecksums The list of row checksums to delete.
   * @return An [Either] containing the operation result or a [Throwable].
   */
  fun deleteRowChecksums(deletedChecksums: List<RowChecksum>) = Either.catch { rowChecksumDao.deleteEntityChecksums(deletedChecksums) }

  /**
   * Checks whether the row checksum table is empty (initial state).
   *
   * @return An [Either] containing true if empty, false otherwise, or a [Throwable].
   */
  fun isInitialState() = Either.catch { rowChecksumDao.isTableEmpty() }

  /**
   * Finds all checksum records for a given entity name.
   *
   * @param entityName The class name of the target entity.
   * @return An [Either] containing the list of row checksums, or a [Throwable].
   */
  fun findAllByEntityName(entityName: String) = Either.catch { rowChecksumDao.findAllByEntityName(entityName) }

  /**
   * Finds stored checksums whose corresponding entities no longer exist in the database (abandoned checksums).
   *
   * @param entityName The class name of the entity.
   * @return An [Either] containing the list of abandoned row checksums, or a [Throwable].
   */
  fun findAbandonedChecksums(entityName: String) = either {
    val primaryKey =
        spreeConfiguration.findPrimaryKeyInformation(entityName)
            ?: raise(IllegalStateException("No primary key information found for entity »$entityName«."))

    catchAll {
      if (primaryKey.className == STRING) {
        rowChecksumDao.findAbandonedChecksumsByStringId(entityName)
      } else {
        rowChecksumDao.findAbandonedChecksumsByCompositeKey(entityName, primaryKey)
      }
    }
  }

  /**
   * Finds new database rows that do not yet have a corresponding checksum entry (extraneous entities).
   *
   * @param action The EntityAction context describing the query configuration and entity target.
   * @return An [Either] containing the list of new entities, or a [Throwable].
   */
  fun findExtraneousEntities(action: EntityAction) = either {
    val primaryKey =
        spreeConfiguration.findPrimaryKeyInformation(action.entityName)
            ?: raise(IllegalStateException("No primary key information found for entity »${action.entityName}«."))

    catchAll {
      val entityIds =
          if (primaryKey.className == STRING) {
            rowChecksumDao.findExtraneousEntitiesByStringId(action.entityName)
          } else {
            rowChecksumDao.findExtraneousEntitiesByCompositeKey(action.entityName, primaryKey)
          }

      val result = directlyLoadEntities(action, entityIds)

      result
    }
  }

  /**
   * Normal loading of the new entities (via a query, e.g.) would trigger
   * [de.spree.keycloak.plugins.integrity.SpreeIntegrityValidationListener.onPostLoad], which in turn would call
   * [RowChecksumService.validateEntityChecksum] and thus cause an error. The checksums for the new entities are not yet created at this point.
   * Actually, that's the point here.
   *
   * So we have to use a different mechanism to load the entities bypassing the event listener mechanism. This has however the great disdavantage if
   * sequentially loading the entities from the database. We assume the number of loaded entities to be small.
   *
   * Alternatively, one would have to temporarily disable the event listener mechanism on a ThreadLocal basis which might cause other problems, since
   * this is the core feature of the provider.
   */
  private fun directlyLoadEntities(action: EntityAction, entityIds: List<Any>): MutableList<Any> {
    val sessionFactory = action.entityManager.entityManagerFactory.unwrap(SessionFactory::class.java)
    val result = mutableListOf<Any>()

    sessionFactory.openStatelessSession().use { statelessSession ->
      val tx = statelessSession.beginTransaction()

      result.addAll(entityIds.map { statelessSession.get(action.clazz, it) })

      tx.commit()
    }

    return result
  }

  companion object {
    init {
      setupBouncyCastle()
    }
  }
}
