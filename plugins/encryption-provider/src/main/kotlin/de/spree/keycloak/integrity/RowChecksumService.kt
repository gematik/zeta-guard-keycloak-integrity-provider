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
import de.spree.keycloak.commons.crypto.Checksum
import de.spree.keycloak.commons.crypto.DBChecksum
import de.spree.keycloak.commons.crypto.HashingService
import de.spree.keycloak.commons.crypto.setupBouncyCastle
import de.spree.keycloak.commons.crypto.toDatabaseRepresentation
import de.spree.keycloak.commons.debug.EntityInfoWriter
import de.spree.keycloak.commons.debug.SpreeEntityInfoWriter
import de.spree.keycloak.commons.debug.SpreeLog
import de.spree.keycloak.plugins.integrity.EntityAction
import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import java.util.logging.Logger

/**
 * Service responsible for calculating, validating, and managing entity checksums.
 *
 * This service handles the core logic for ensuring data integrity by generating checksums for entities, signing them, and verifying them against
 * stored values. It interacts with the [EntityConverter] to serialize entities, the [de.spree.keycloak.commons.crypto.HashingService] to calculate and verify hashes, and the
 * [RowChecksumDao] to persist and retrieve checksums.
 */
@ApplicationScoped
@Suppress("CdiInjectionPointsInspection")
open class RowChecksumService {
	@Inject //
	private lateinit var hashingService: HashingService

	@Inject
	@SpreeLog //
	private lateinit var spreeLogger: Logger

	@Inject
	@SpreeEntityInfoWriter //
	private lateinit var entityInfoWriter: EntityInfoWriter

	@Inject //
	private lateinit var spreeConfiguration: SpreeEntityConfiguration

	/**
	 * Calculates the checksum for a given entity.
	 * Only used for tests.
	 *
	 * The process involves:
	 * 1. Converting the entity to its JSON representation.
	 * 2. Hashing the JSON bytes using the [HashingService].
	 * 3. Combining the keychain-ID and hash into a single Base64 encoded string.
	 *
	 * @param entityInfo Information about the entity
	 * @return An [Either] containing the calculated checksum string or a [Throwable] if an error occurs.
	 */
	fun calculateRowChecksum(entityInfo: EntityInfo, action: EntityAction): Either<Throwable, Checksum> = either {
		val jsonRepresentation = action.spreeEntityManager.convertToJSON(entityInfo.entity).bind()
		val bytes = jsonRepresentation.toByteArray()
		val checksum = hashingService.hash(bytes).bind()

		spreeLogger.info("[$action] CHECKSUM: ${entityInfo.entityAsString()}\n$jsonRepresentation")

		ensure(checksum.hash.size == HASH_SIZE) { IllegalStateException("Invalid hash size: ${checksum.hash.size}") }

		checksum
	}

	/**
	 * Validates a stored checksum against a currently calculated checksum.
	 *
	 * This method verifies that the hash part of the stored checksum matches the hash part of the current checksum.
	 *
	 * @param storedChecksum The checksum retrieved from storage.
	 * @param entityInfo Information about the entity being validated
	 * @return An [Either] containing [Success] if validation passes, or a [Throwable] if it fails.
	 */
	internal fun validateChecksum(
		action: EntityAction,
		storedChecksum: Checksum,
		entityInfo: EntityInfo,
	): Either<Throwable, Success> = either {
		val storedHash = storedChecksum.hash
		val actionName = "[$action]→VALIDATE"

		val jsonRepresentation = action.spreeEntityManager.convertToJSON(entityInfo.entity).bind()
		val bytes = jsonRepresentation.toByteArray()
		val currentChecksum = hashingService.hashWith(storedChecksum.keychainId, bytes).bind()

		spreeLogger.info(
			"""
				|$actionName: ${entityInfo.entityAsString()}
				|${storedHash.toBase64()}
				|{${currentChecksum.hash.toBase64()}""".trimMargin()
		)

		ensure(storedHash.contentEquals(currentChecksum.hash)) { RuntimeException("Row checksum mismatch for $entityInfo") }

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
	internal fun updateEntityChecksum(action: EntityAction, entities: List<Any>) = either {
		entities.forEach {
			val entityInfo = action.spreeEntityManager.lookupEntityInfo(it).bind()

			updateEntityInfoChecksum(entityInfo, action).bind()
		}
	}

	/**
	 * Calculates and updates (or inserts) the checksum for a single entity.
	 * Also indicates if the checksum was changed.
	 *
	 * @param entityInfo The metadata and actual instance of the entity.
	 * @param action The EntityAction context under which the checksum is updated.
	 * @return An [Either] containing [Boolean] if updated/inserted successfully, or a [Throwable].
	 */
	fun updateEntityInfoChecksum(entityInfo: EntityInfo, action: EntityAction) = either {
		val checksum = calculateRowChecksum(entityInfo, action).bind()
		val dbChecksum = checksum.toDatabaseRepresentation()
		val rowChecksumDao = createSpreeContextRowChecksumDao(action)
		val existingRowChecksum: RowChecksum? = catchAll { rowChecksumDao.findForUpdate(entityInfo.rowChecksumId) }

		return@either if (existingRowChecksum == null) {
			val primaryKey =
				spreeConfiguration.findPrimaryKeyInformation(action.entityName)
					?: raise(IllegalStateException("No primary key information found for entity »${action.entityName}«."))

			val currentRowChecksum = if (primaryKey.className == STRING) {
				RowChecksum(entityName = entityInfo.entityName, entityId = entityInfo.id, compositeId1 = null, compositeId2 = null, checksum = dbChecksum)
			} else {
				val compositeIds = entityInfo.entityId.idAsMap().values.toList()

				ensure(compositeIds.size == 2) { IllegalStateException("Composite ID of size ${compositeIds.size} not supported yet") }

				RowChecksum(
					entityName = entityInfo.entityName,
					entityId = entityInfo.id,
					checksum = dbChecksum,
					compositeId1 = compositeIds[0],
					compositeId2 = compositeIds[1]
				)
			}

			logAction(action, false, entityInfo, "", dbChecksum)

			rowChecksumDao.save(currentRowChecksum)

			true
		} else {
			logAction(action, true, entityInfo, existingRowChecksum.checksum, dbChecksum)

			val changed = existingRowChecksum.checksum != dbChecksum

			existingRowChecksum.checksum = dbChecksum

			changed
		}
	}

	private fun logAction(
		action: EntityAction,
		update: Boolean,
		entityInfo: EntityInfo,
		existingChecksum: DBChecksum,
		dbChecksum: DBChecksum
	) {
		val actionName = "[$action]→" + if (update) "UPDATE" else "CREATE"

		spreeLogger.info(
			"""
					|$actionName: ${entityInfo.entityAsString()}
					|${dbChecksum}""".trimMargin()
		)
		entityInfoWriter.writeEntityInfo(entityInfo, actionName, existingChecksum, dbChecksum)
	}

	/**
	 * Deletes the checksum for a given deleted entity.
	 *
	 * @param entities An entity that has been deleted
	 * @return An [Either] containing [Unit] if the deletion was successful or a [Throwable]
	 */
	fun deleteEntityChecksum(action: EntityAction, entities: List<Any>) = either {
		catchAll {
			entities.forEach {
				val entityInfo = action.spreeEntityManager.lookupEntityInfo(it).bind()
				val rowChecksumDao = createSpreeContextRowChecksumDao(action)

				rowChecksumDao.deleteRowChecksums(entityInfo.rowChecksumId)
			}
		}
	}

	/**
	 * Deletes a list of [RowChecksum] entities from the database.
	 *
	 * @param deletedChecksums The list of row checksums to delete.
	 * @return An [Either] containing the operation result or a [Throwable].
	 */
	fun deleteRowChecksums(action: EntityAction, deletedChecksums: List<RowChecksum>) = Either.catch {
		val rowChecksumDao = createSpreeContextRowChecksumDao(action)

		rowChecksumDao.deleteRowChecksums(*deletedChecksums.map { it.rowChecksumId }.toTypedArray())
	}

	/**
	 * Checks whether the row checksum table is empty (initial state).
	 *
	 * @return An [Either] containing true if empty, false otherwise, or a [Throwable].
	 */
	fun isInitialState(action: EntityAction) = Either.catch {
		val rowChecksumDao = createSpreeContextRowChecksumDao(action)
		rowChecksumDao.isTableEmpty()
	}

	/**
	 * Finds all checksum records for a given entity name.
	 *
	 * @param action The class name of the target entity.
	 * @return An [Either] containing the list of row checksums, or a [Throwable].
	 */
	fun findAllByEntityName(action: EntityAction) = Either.catch {
		val rowChecksumDao = createSpreeContextRowChecksumDao(action)

		rowChecksumDao.findAllByEntityName(action.entityName)
	}

	/**
	 * Finds stored checksums whose corresponding entities no longer exist in the database (abandoned checksums).
	 *
	 * @param action The class name of the entity.
	 * @return An [Either] containing the list of abandoned row checksums, or a [Throwable].
	 */
	fun findAbandonedChecksums(action: EntityAction) = either {
		val primaryKey =
			spreeConfiguration.findPrimaryKeyInformation(action.entityName)
				?: raise(IllegalStateException("No primary key information found for entity »${action.entityName}«."))
		val rowChecksumDao = createKeycloakContextRowChecksumDao(action)

		catchAll {
			if (primaryKey.className == STRING) {
				rowChecksumDao.findAbandonedChecksumsByStringId(action.entityName)
			} else {
				rowChecksumDao.findAbandonedChecksumsByCompositeKey(action.entityName, primaryKey)
			}
		}
	}

	fun loadRowChecksum(action: EntityAction, id: RowChecksumKeyId) = either {
		val rowChecksumDao = createSpreeContextRowChecksumDao(action)

		rowChecksumDao.findByEntityId(id) ?: raise(IllegalStateException("No row checksum data found for »$id«"))
	}

	/**
	 * Finds new database rows that do not yet have a corresponding checksum entry (extraneous entities).
	 *
	 * @param action The EntityAction context describing the query configuration and entity target.
	 * @return An [Either] containing the list of new entities, or a [Throwable].
	 */
	fun findExtraneousEntities(action: EntityAction) = either {
		val primaryKey = spreeConfiguration.findPrimaryKeyInformation(action.entityName)
			?: raise(IllegalStateException("No primary key information found for entity »${action.entityName}«."))
		val rowChecksumDao = createKeycloakContextRowChecksumDao(action)

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

	protected open fun createSpreeContextRowChecksumDao(action: EntityAction) = RowChecksumDao(action.spreeEntityManager)

	protected open fun createKeycloakContextRowChecksumDao(action: EntityAction) = RowChecksumDao(action.keycloakEntityManager)

	/**
	 * Normal loading of the new entities (via a query, e.g.) would trigger
	 * [de.spree.keycloak.plugins.integrity.SpreeIntegrityValidationListener.onPostLoad], which in turn would call
	 * [ChecksumService.validateEntityChecksum] and thus cause an error. The checksums for the new entities are not yet created at this point.
	 * Actually, that's the point here.
	 *
	 * So we have to use a different mechanism to load the entities bypassing the event listener mechanism. This has however the great disdavantage if
	 * sequentially loading the entities from the database. We assume the number of loaded entities to be small.
	 *
	 * Alternatively, one would have to temporarily disable the event listener mechanism on a ThreadLocal basis which might cause other problems, since
	 * this is the core feature of the provider.
	 */
	private fun directlyLoadEntities(action: EntityAction, entityIds: List<Any>): List<Any> {
		val result = mutableListOf<Any>()

		action.keycloakEntityManager.createStatelessSession().use { statelessSession ->
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
