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
package de.spree.keycloak.scanner

import arrow.core.Either
import arrow.core.raise.either
import arrow.core.raise.ensure
import de.spree.keycloak.commons.EntityInfo
import de.spree.keycloak.commons.automaticCryptoUpdateEnabled
import de.spree.keycloak.commons.catchAll
import de.spree.keycloak.commons.columnEncryptionEnabled
import de.spree.keycloak.commons.configuration.EntityConfiguration
import de.spree.keycloak.commons.integrityChecksEnabled
import de.spree.keycloak.commons.logger
import de.spree.keycloak.commons.retrieveValue
import de.spree.keycloak.commons.rowChecksEnabled
import de.spree.keycloak.commons.tableChecksEnabled
import de.spree.keycloak.commons.crypto.CryptoService
import de.spree.keycloak.integrity.ConfigurationService
import de.spree.keycloak.integrity.EntityDao
import de.spree.keycloak.integrity.RowChecksumService
import de.spree.keycloak.integrity.TableChecksumService
import de.spree.keycloak.plugins.encryption.jpa.SpreeEncryptionAttributeConverter
import de.spree.keycloak.plugins.integrity.Action.INITIALIZE
import de.spree.keycloak.plugins.integrity.EntityAction
import io.quarkus.runtime.Startup
import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import jakarta.persistence.EntityManager

@ApplicationScoped
@Startup // Enforce creation at startup, so the bean will be available using CDI.current()
open class ScannerService {
	@Inject //
	private lateinit var tableChecksumService: TableChecksumService

	@Inject //
	private lateinit var rowChecksumService: RowChecksumService

	@Inject //
	private lateinit var cryptoService: CryptoService

	@Inject //
	private lateinit var configurationService: ConfigurationService

	fun getKeychainId() = cryptoService.getCurrentKeychainId()

	/**
	 * We need a crypto update if
	 * - there is a previous keychain, and
	 * - the current keychain ID does not match the configuration value in the database.
	 */
	fun needsCryptoUpdate(action: EntityAction): Boolean =
		automaticCryptoUpdateEnabled &&
		cryptoService.hasPreviousKeychain() &&
				configurationService.getKeychainId(action).fold(
					ifEmpty = { true },
					ifSome = { it != cryptoService.getCurrentKeychainId() }
				)

	fun canPerformCryptoUpdate(): Boolean =
		!cryptoService.hasFutureKeychain()

	fun setCurrentKeychainId(action: EntityAction) =
		configurationService.setKeychainId(action, cryptoService.getCurrentKeychainId())

	/**
	 * Retrieves entity information for all entities affected by the given action.
	 */
	fun loadEntities(action: EntityAction): Either<Throwable, List<EntityInfo>> = either {
		val entityDao = createEntityDao(action)
		val entities = catchAll { entityDao.loadEntities(action.entityName) }

		entities.map { entityDao.lookupEntityInfo(it).bind() }
	}

	private fun update(action: EntityAction, entityInfo: EntityInfo, propertyName: String, value: String) = Either.catch {
		val entityDao = createEntityDao(action)

		entityDao.update(entityInfo, propertyName, value)
	}

	protected open fun createEntityDao(action: EntityAction): EntityDao = EntityDao(action.keycloakEntityManager)

	protected open fun createEntityDao(entityManager: EntityManager): EntityDao = EntityDao(entityManager)


	/**
	 * Computes the initial checksums for all rows in a given managed table and encrypts relevant data.
	 *
	 * This may be used either for initial database encryption or during a later crypto update.
	 *
	 * The caller is responsible for managing [SpreeIntegrityScanner.scannerState] before and after invoking this function.
	 */
	fun updateEntity(entityConfiguration: EntityConfiguration, spreeEntityManager: EntityManager) = either {
		val entityAction = EntityAction(INITIALIZE, entityConfiguration.name, spreeEntityManager)
		val entityInfos = loadEntities(entityAction).bind()

		var updated = 0
		if (entityInfos.isNotEmpty()) {
			if (integrityChecksEnabled) {
				updated = computeChecksums(entityAction, entityConfiguration, entityInfos).bind()
			}

			if (columnEncryptionEnabled && entityConfiguration.encryptedProperties.isNotEmpty()) {
				encryptColumns(entityAction, entityConfiguration, entityInfos).bind()
			}
		}
		return@either updated
	}

	/**
	 * Verifies that every configured column of [entityConfiguration] really holds ciphertext.
	 *
	 * Run this once the whole database has been converted: rows that were written while the conversion was running are stored in plain text — the
	 * converter still passes values through until the system is [SystemState.OPERATIONAL][de.spree.keycloak.commons.configuration.SystemState], and
	 * the conversion has already passed that table. Such a row is unreadable afterwards, and without this check that only shows up much later, when
	 * something reads it and decryption fails.
	 *
	 * The persistence context is flushed and cleared beforehand: the conversion wrote the ciphertext with an update query, so the entities it left
	 * behind still carry the plain values in memory.
	 *
	 * It is cleared afterwards as well: the entities read here were loaded with the conversion suspended and thus hold the ciphertext as their
	 * attribute value and in their snapshot. Touching one of them later on the same session would encrypt that ciphertext a second time.
	 */
	fun verifyEncryptedColumns(entityConfiguration: EntityConfiguration, spreeEntityManager: EntityManager) = either {
		if (columnEncryptionEnabled && entityConfiguration.encryptedProperties.isNotEmpty()) {
			logger.info("🔎 Verifying encrypted columns of »${entityConfiguration.name}«...")

			spreeEntityManager.flush()
			spreeEntityManager.clear()

			val plainColumns = SpreeEncryptionAttributeConverter.withoutConversion {
				catchAll { createEntityDao(spreeEntityManager).loadEntities(entityConfiguration.name) }.sumOf { entity ->
					entityConfiguration.encryptedProperties.count { property ->
						val data: String? = entity.retrieveValue(property.name)

						data != null && !cryptoService.isEncrypted(data)
					}
				}
			}

			spreeEntityManager.clear()

			ensure(plainColumns == 0) {
				IllegalStateException(
					"💣 $plainColumns column(s) of »${entityConfiguration.name}« are not encrypted. " +
						"Was the database written to while it was being converted?"
				)
			}

			logger.info("☑️ Verifying encrypted columns of »${entityConfiguration.name}« DONE")
		}
	}

	/**
	 * Encrypts configured properties (columns) of the specified entities.
	 *
	 * Iterates over the properties/columns defined in [entityConfiguration] that require encryption, encrypts their plaintext values using the
	 * [CryptoService], and updates them in the database.
	 *
	 * @param entityConfiguration the configuration detailing which properties to encrypt.
	 * @param entityInfos the list of entities to process.
	 */
	private fun encryptColumns(action: EntityAction, entityConfiguration: EntityConfiguration, entityInfos: List<EntityInfo>) = either {
		logger.info("🔐 Encrypting columns of »${entityConfiguration.name}«...")

		entityInfos.forEach { entityInfo ->
			entityConfiguration.encryptedProperties.forEach { epc ->
				val data: String? = entityInfo.entity.retrieveValue(epc.name)

				if (data != null) {
					if (cryptoService.isEncrypted(data)) {
						// Encrypting again would produce data that a single read cannot decrypt anymore, so skip it
						logger.warn("⚠️ Skipping »${entityConfiguration.name}/${epc.name}« of »${entityInfo.entityId.id}«: value is already encrypted")
					} else {
						val encrypted = cryptoService.encrypt(data).bind()

						// Updating the entity in memory via reflection does not work, so we have to use a database update query
						update(action, entityInfo, epc.name, encrypted).bind()
					}
				}
			}
		}

		logger.info("☑️ Encrypting columns of »${entityConfiguration.name}« DONE")
	}

	/**
	 * Computes and saves both row-level and table-level checksums for a list of entities.
	 *
	 * For each entity in [entityInfos], a row checksum is computed and saved, and then the overall table-level checksum is computed and updated.
	 *
	 * @param entityAction the context of the checksum computation action.
	 * @param entityInfos the list of entity records to compute checksums for.
	 * @return number of updated rows
	 */
	private fun computeChecksums(entityAction: EntityAction, entityConfiguration: EntityConfiguration, entityInfos: List<EntityInfo>) = either {
		logger.info("🛡 Computing checksums for »${entityAction.entityName}«...")

		val updated = if (rowChecksEnabled) {
			entityInfos.map { rowChecksumService.updateEntityInfoChecksum(it, entityAction).bind() }.count { it }
		} else {
			0
		}

		if (tableChecksEnabled && entityConfiguration.tableChecksumEnabled) {
			val entityIds = entityInfos.map { it.id }
			tableChecksumService.updateTableChecksum(entityAction, entityIds).bind()
		}

		logger.info("☑️ Computing checksums for »${entityAction.entityName}« DONE")
		return@either updated
	}
}
