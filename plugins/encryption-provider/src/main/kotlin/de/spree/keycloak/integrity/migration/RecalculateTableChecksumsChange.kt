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
@file:Suppress("SqlSourceToSinkFlow")

package de.spree.keycloak.integrity.migration

import arrow.core.getOrElse
import de.spree.keycloak.commons.configuration.TABLE_ROW_CHECKSUM
import de.spree.keycloak.commons.configuration.TABLE_TABLE_CHECKSUM
import de.spree.keycloak.commons.crypto.Checksum
import de.spree.keycloak.commons.crypto.hmac
import de.spree.keycloak.commons.crypto.keychain.Keychain
import de.spree.keycloak.commons.crypto.keychain.KeychainType
import de.spree.keycloak.commons.crypto.keychain.loadKeychain
import de.spree.keycloak.commons.crypto.muhash.MuHash3072
import de.spree.keycloak.commons.crypto.setupBouncyCastle
import de.spree.keycloak.commons.crypto.toDatabaseRepresentation
import de.spree.keycloak.commons.crypto.withStandaloneHSMCryptoService
import de.spree.keycloak.commons.logger
import de.spree.keycloak.commons.toBase64
import de.spree.keycloak.commons.toByteArray
import de.spree.keycloak.integrity.COLUMN_CHECKSUM
import de.spree.keycloak.integrity.COLUMN_ENTITY_ID
import de.spree.keycloak.integrity.COLUMN_ENTITY_NAME
import de.spree.keycloak.integrity.COLUMN_HASH
import liquibase.change.custom.CustomTaskChange
import liquibase.database.Database
import liquibase.database.jvm.JdbcConnection
import liquibase.exception.ValidationErrors
import liquibase.resource.ResourceAccessor

/**
 * Liquibase [CustomTaskChange] that recalculates all rows of [TABLE_TABLE_CHECKSUM] for the separation of multihash and HMAC.
 *
 * Previously, [COLUMN_CHECKSUM] held a MuHash over the HMACs of all entity IDs of a table. Now [COLUMN_HASH] holds the MuHash over the plain entity
 * IDs and [COLUMN_CHECKSUM] a single HMAC over that hash. The entity IDs are taken from [TABLE_ROW_CHECKSUM], just like
 * [de.spree.keycloak.integrity.TableChecksumService.checkTableChecksum] does. The database is assumed to be consistent, so existing checksums are
 * overwritten without verification. New checksums always use the current keychain.
 */
open class RecalculateTableChecksumsChange : CustomTaskChange {
	// Loaded only when there is anything to migrate, so an empty database does not need the HSM
	private val keychain: Keychain by lazy { loadCurrentKeychain() }

	override fun execute(database: Database) {
		setupBouncyCastle()

		val connection = database.connection as JdbcConnection
		val entityNames = readEntityNames(connection)

		logger.infof("🏃 Database migration STARTED for %d table checksums", entityNames.size)

		connection
			.prepareStatement("UPDATE $TABLE_TABLE_CHECKSUM SET $COLUMN_HASH = ?, $COLUMN_CHECKSUM = ? WHERE $COLUMN_ENTITY_NAME = ?")
			.use { updateStatement ->
				entityNames.forEach { entityName ->
					val hash = calculateHash(connection, entityName)
					val checksum = Checksum(keychain.keychainId.toByteArray(), hmac(keychain.hmacKey, hash).getOrElse { throw it })

					updateStatement.setString(1, hash.toBase64())
					updateStatement.setString(2, checksum.toDatabaseRepresentation())
					updateStatement.setString(3, entityName)
					updateStatement.executeUpdate()

					logger.infof("🛠️ Table checksum of »%s« recalculated", entityName)
				}
			}

		connection.commit()

		logger.info("☑️ Database migration COMPLETED")
	}

	private fun readEntityNames(connection: JdbcConnection): List<String> =
		connection.createStatement().use { statement ->
			statement.executeQuery("SELECT $COLUMN_ENTITY_NAME FROM $TABLE_TABLE_CHECKSUM").use { rs ->
				buildList { while (rs.next()) add(rs.getString(COLUMN_ENTITY_NAME)) }
			}
		}

	private fun calculateHash(connection: JdbcConnection, entityName: String): ByteArray =
		connection
			.prepareStatement("SELECT $COLUMN_ENTITY_ID FROM $TABLE_ROW_CHECKSUM WHERE $COLUMN_ENTITY_NAME = ?")
			.use { statement ->
				statement.setString(1, entityName)
				statement.executeQuery().use { rs ->
					val multiHash = MuHash3072()
					while (rs.next()) multiHash.insert(rs.getString(COLUMN_ENTITY_ID).toByteArray())
					multiHash.current()
				}
			}

	// exposed for testing
	protected open fun loadCurrentKeychain(): Keychain =
		withStandaloneHSMCryptoService { hsmCryptoService ->
			loadKeychain(hsmCryptoService, KeychainType.CURRENT).getOrElse { throw IllegalStateException("Could not load current keychain", it) }
		}

	override fun getConfirmationMessage() = "Recalculated $COLUMN_HASH and $COLUMN_CHECKSUM for $TABLE_TABLE_CHECKSUM"

	override fun setUp() {}

	override fun setFileOpener(resourceAccessor: ResourceAccessor) {}

	override fun validate(database: Database) = ValidationErrors()
}
