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
@file:Suppress("unused")

package de.spree.keycloak.integrity

import arrow.core.Either
import arrow.core.None
import arrow.core.Option
import arrow.core.Some
import arrow.core.raise.either
import arrow.core.raise.ensure
import arrow.core.recover
import de.spree.keycloak.commons.*
import de.spree.keycloak.commons.configuration.IT_FAILED
import de.spree.keycloak.commons.configuration.SpreeEntityConfiguration
import de.spree.keycloak.commons.configuration.SystemState
import de.spree.keycloak.commons.configuration.SystemStateService
import de.spree.keycloak.commons.debug.SpreeLog
import de.spree.keycloak.crypto.CryptoService
import de.spree.keycloak.crypto.HashingService
import de.spree.keycloak.plugins.integrity.Action.SCAN
import de.spree.keycloak.plugins.integrity.EntityAction
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.models.utils.KeycloakModelUtils.runJobInTransaction
import org.keycloak.timer.ScheduledTask
import org.keycloak.timer.TimerProvider
import org.keycloak.timer.TimerProviderFactory
import java.time.Duration
import java.util.logging.Level
import java.util.logging.Logger
import kotlin.random.Random

private val SPREE_SCANNER_INTERVAL = getEnvironment(ENV_SCANNER_INTERVAL, "PT20S")
private val SPREE_SCANNER_DELAY = getEnvironment(ENV_SCANNER_DELAY, "PT5M")

/**
 * Option to perform periodic row integrity checks for all entities.
 * If disabled, the scanner only performs table integrity checks when configured.
 */
private val periodicRowCheckEnabled: Boolean by lazy { getEnvironment(ENV_PERIODIC_ROW_CHECK, "true").toBoolean() }


/**
 * A singleton object responsible for scanning and verifying database integrity.
 *
 * This scanner is initialized with Hibernate metadata and run scans to detect any data tampering.
 *
 * CDI injection does not work here, unfortunately.
 */
object SpreeIntegrityScanner {
	private val tableChecksumService: TableChecksumService by lazy { cdiService() }
	private val checksumService: ChecksumService by lazy { cdiService() }
	private val rowChecksumService: RowChecksumService by lazy { cdiService() }
	private val scannerService: ScannerService by lazy { cdiService() }
	private val hashingService: HashingService by lazy { cdiService() }
	private val systemStateService: SystemStateService by lazy { cdiService() }
	private val spreeLogger: Logger by lazy { cdiService(SpreeLog()) }
	private val cryptoService: CryptoService by lazy { cdiService() }
	private val cryptoUpdateService: CryptoUpdateService by lazy { cdiService() }
	private val entityConfiguration: SpreeEntityConfiguration by lazy { cdiService() }

	private val remainingScanTasks = mutableListOf<String>()

	var scannerError: Throwable? = null
	var scannerState: ScannerState = ScannerState.IDLE

	/**
	 * Schedules a periodic task to validate row and table integrity (if enabled) and perform pending crypto updates.
	 *
	 * @param factory The Keycloak session factory.
	 */
	fun scheduleIntegrityScanner(factory: KeycloakSessionFactory) {
		val interval = Duration.parse(SPREE_SCANNER_INTERVAL)
		val delay = Duration.parse(SPREE_SCANNER_DELAY)
		val timerProviderFactory = factory.getProviderFactory(TimerProvider::class.java) as TimerProviderFactory

		logger.info("🔎 Processing tables every $interval with initial delay $delay")

		timerProviderFactory.create(factory.create()).scheduleTask(
			createScannerTask(factory),
			delay.toMillis(),
			interval.toMillis(),
			"spree-integrity-scanner"
		)

		if (!integrityChecksEnabled) {
			logger.info("⚠️ Integrity checks are disabled")
		}
	}

	private fun createScannerTask(factory: KeycloakSessionFactory): ScheduledTask = {
		if (systemStateService.currentSystemState() == SystemState.OPERATIONAL && scannerState == ScannerState.IDLE) {
			runJobInTransaction(factory) { session ->
				runScanCycle(session)
			}
		}
	}

	/** Exposed for testing! */
	fun runScanCycle(session: KeycloakSession) {
		if (systemStateService.currentSystemState() == SystemState.OPERATIONAL && scannerState == ScannerState.IDLE) {
			cryptoUpdateService.reserveUpdateTask(session).onSome { task ->
				scannerError = null // assume caused by concurrent crypto update
				runCryptoUpdate(session, task.entityName)
					.onLeft { handleIntegrityError(session, it); throw it }
					.onRight { cryptoUpdateService.finishUpdateTask(session, task); return }
			}

			scannerError?.let {
				handleIntegrityError(session, it)
				throw it
			}

			if (integrityChecksEnabled) {
				nextScanTask().onSome { entityName ->
					runTableScan(session, entityName).onLeft {
						scannerError = it // delay in case of started crypto update
					}
				}
			}
		}
	}

	private fun handleIntegrityError(session: KeycloakSession, error: Throwable) {
		if (error.isIntegrityException()) {
			logger.error("💣 Scanning tables failed", error)
			systemStateService.setSystemState(SystemState.ERROR_TABLE_CHECKSUM, error, session)
		}
	}

	internal fun nextScanTask(): Option<String> {
		if (rowChecksEnabled) {
			if (remainingScanTasks.isEmpty()) {
				entityConfiguration.entities
					.filter { it.rowChecksumEnabled }
					.filter { periodicRowCheckEnabled || it.tableChecksumEnabled }
					.map { it.name }
					.let { entities ->
						val offset = if (entities.isNotEmpty()) Random.nextInt(entities.size) else 0
						remainingScanTasks.addAll(entities.drop(offset))
						remainingScanTasks.addAll(entities.take(offset))
						logger.info("⟳ Starting new scan cycle")
					}
			}
			if (remainingScanTasks.isNotEmpty()) {
				return Some(remainingScanTasks.removeFirst())
			}
		}
		return None
	}

	/**
	 * Runs a scan across all managed tables to verify data integrity.
	 *
	 * This is mainly used for testing, normally scans should be spaced out to not degrade business logic performance.
	 *
	 * @return An [Either] containing [Success] if the scan completes without errors, or a message text otherwise.
	 */
	fun runTableScan(session: KeycloakSession): Either<Throwable, Success> = either {
		if (rowChecksEnabled) {
			ensure(systemStateService.currentSystemState() == SystemState.OPERATIONAL) {
				IllegalStateException("Invalid system status ${systemStateService.currentSystemState()}")
			}

			entityConfiguration.entities.forEach {
				if (it.rowChecksumEnabled) {
					runTableScan(session, it.name)
						.onLeft { t -> handleIntegrityError(session, t) }
						.bind()
				}
			}
		}

		SimpleSuccess
	}

	/**
	 * Runs a scan across all managed tables to verify data integrity.
	 *
	 * This is mainly used for testing, normally updates should be spaced out to not degrade business logic performance.
	 *
	 * @return An [Either] containing [Success] if the update completes without errors, or a message text otherwise.
	 */
	fun runCryptoUpdate(session: KeycloakSession): Either<Throwable, Success> = either {
		ensure(systemStateService.currentSystemState() == SystemState.OPERATIONAL) {
			IllegalStateException("Invalid system status ${systemStateService.currentSystemState()}")
		}

		entityConfiguration.entities.forEach {
			runCryptoUpdate(session, it.name)
				.onLeft { t -> handleIntegrityError(session, t) }
				.bind()
		}

		SimpleSuccess
	}

	/**
	 * Scans a specific entity table for data integrity.
	 *
	 * This helper function loads all records for the specified [entityName] (verifying row-level checksums during load)
	 * and subsequently verifies the overall table checksum.
	 *
	 * @param entityName the fully qualified name of the JPA entity to scan.
	 * @return [Either] containing [Success] if validation succeeds, or a [Throwable] representing the failure.
	 */
	internal fun runTableScan(session: KeycloakSession, entityName: String) = either {
		scannerState = ScannerState.SCANNING
		logger.info("🔎 Scanning »$entityName« for integrity...")

		val action = EntityAction(SCAN, entityName, session.entityManager)
		val entityInfos = if (periodicRowCheckEnabled) {
			 scannerService
				.loadEntities(action)
				.onLeft { t -> spreeLogger.log(Level.SEVERE, "Row checksum validation failed for »$entityName«", t) }
				.bind() // Loading implicitly validates checksums and signatures
		} else emptyList()

		if (entityInfos.isNotEmpty() && tableChecksEnabled && entityConfiguration.tableChecksumEnabled(entityName)) {
			tableChecksumService
				.checkTableChecksum(action)
				.onRight { systemStateService.clearVolatileError(entityName) }
				.recover { if (systemStateService.shouldIgnoreVolatileError(entityName)) SimpleSuccess else raise(it) }
				.onLeft { t -> spreeLogger.log(Level.SEVERE, "Table checksum validation failed for »$entityName«", t) }
				.bind()
		}

		SimpleSuccess
	}
		.onLeft { logger.error("💣 $IT_FAILED Table check failed for »$entityName«", it) }
		.onRight { logger.info("☑️ Scanning »$entityName« for integrity DONE") }
		.also { scannerState = ScannerState.IDLE }

	/**
	 * Updates encryption and data integrity for a specific entity table.
	 *
	 * This helper function loads updates records for the specified [entityName], their associated row checksum,
	 * and subsequently updates the overall table checksum.
	 *
	 * @param session the current keycloak session.
	 * @param entityName the fully qualified name of the JPA entity to update.
	 * @return [Either] containing [Success] if updating succeeds, or a [Throwable] representing the failure.
	 */
	private fun runCryptoUpdate(session: KeycloakSession, entityName: String) = either {
		scannerState = ScannerState.SCANNING
		logger.info("🛠 Crypto update starts for »$entityName« ...")

		entityConfiguration.findEntity(entityName)?.let {
			scannerService.updateEntity(it, session.entityManager).bind()
		}

		SimpleSuccess
	}
		.onLeft { logger.error("💣 Crypto update failed for »$entityName«", it) }
		.onRight { logger.info("☑️ Crypto update for »$entityName« DONE") }
		.also { scannerState = ScannerState.IDLE }

	/** Exposed for testing only! */
	fun reset() {
		remainingScanTasks.clear()
		scannerError = null
		scannerState = ScannerState.IDLE
	}
}

enum class ScannerState {
	IDLE,
	SCANNING,
	INITIALIZING,
}
