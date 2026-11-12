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
package de.spree.keycloak.bootstrap

import arrow.core.Either
import arrow.core.raise.either
import arrow.core.raise.ensure
import de.spree.keycloak.commons.SimpleSuccess
import de.spree.keycloak.commons.Success
import de.spree.keycloak.commons.cdiService
import de.spree.keycloak.commons.configuration.SpreeEntityConfiguration
import de.spree.keycloak.commons.logger
import de.spree.keycloak.integrity.RowChecksumService
import de.spree.keycloak.scanner.ScannerService
import de.spree.keycloak.scanner.ScannerState
import de.spree.keycloak.scanner.SpreeIntegrityScanner.scannerState
import de.spree.keycloak.integrity.TableChecksumService
import de.spree.keycloak.plugins.integrity.EntityAction

object SpreeDatabaseConverter {
	private val tableChecksumService: TableChecksumService by lazy { cdiService() }
	private val rowChecksumService: RowChecksumService by lazy { cdiService() }
	private val scannerService: ScannerService by lazy { cdiService() }
	private val entityConfiguration: SpreeEntityConfiguration by lazy { cdiService() }

	/**
	 * Computes the initial checksums for all rows in the managed tables and encrypts relevant data.
	 *
	 * This function is intended to be run once during application startup (e.g., after migration) to establish a baseline for data integrity checks.
	 *
	 * Once, cluster-wide: a second run over an already converted database leaves row checksums that match no reader. [SpreeBootstrapProcessor]
	 * documents how that is prevented and why the guard below is the last of three nets rather than the only one.
	 */
	fun convertDatabase(action: EntityAction): Either<Throwable, Success> = either {
		val entityConfigurations = entityConfiguration.entities

		// Losing the race against another cluster node is not an error — but converting a second time would overwrite its checksums
		if (!rowChecksumService.isInitialState(action).bind()) {
			logger.warn("⏭️ Checksums already exist — the database has been converted by another node. Skipping conversion.")

			return@either SimpleSuccess
		}

		ensure(tableChecksumService.isInitialState(action).bind()) { IllegalStateException("Table checksums already initialized") }

		scannerState = ScannerState.INITIALIZING
		logger.info("🛡️ Computing initial checksums for ${entityConfigurations.size} entities...")

		entityConfigurations.forEach {
			scannerService.updateEntity(it, action.spreeEntityManager).bind()
		}

		logger.info("☑️ Computing initial checksums for ${entityConfigurations.size} entities DONE")

		// Anything written while we were converting is still in plain text — fail here rather than on the first read
		entityConfigurations.forEach {
			scannerService.verifyEncryptedColumns(it, action.spreeEntityManager).bind()
		}
		scannerState = ScannerState.IDLE
		SimpleSuccess
	}

	fun getKeychainId() = scannerService.getKeychainId()
}