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
import arrow.core.raise.Raise
import arrow.core.raise.either
import de.spree.keycloak.commons.*
import de.spree.keycloak.commons.configuration.*
import de.spree.keycloak.commons.configuration.SystemState.ERROR_STARTUP
import de.spree.keycloak.commons.configuration.SystemState.OPERATIONAL
import de.spree.keycloak.integrity.*
import de.spree.keycloak.integrity.SpreeDatabaseConversionState.DONE
import de.spree.keycloak.integrity.SpreeDatabaseConversionState.IN_PROGRESS
import de.spree.keycloak.bootstrap.SpreeDatabaseConverter.convertDatabase
import de.spree.keycloak.bootstrap.SpreeDatabaseConverter.getKeychainId
import de.spree.keycloak.plugins.integrity.Action
import de.spree.keycloak.plugins.integrity.EntityAction
import de.spree.keycloak.scanner.ScannerState
import de.spree.keycloak.scanner.SpreeIntegrityScanner
import io.quarkus.runtime.Quarkus
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.models.cache.CacheRealmProvider
import org.keycloak.models.cache.UserCache
import org.keycloak.models.dblock.DBLockManager
import org.keycloak.models.dblock.DBLockProvider
import org.keycloak.models.utils.KeycloakModelUtils.runJobInTransaction
import org.keycloak.timer.TimerProvider
import org.keycloak.timer.TimerProviderFactory
import java.time.Duration

private const val SPREE_BOOTSTRAP_PROCESSOR = "spree-bootstrap-processor"

/**
 * Drives the one-off conversion of an existing Keycloak database into an encrypted and checksummed one.
 *
 * **In a cluster, exactly one node may run that conversion.** A second run recomputes the row checksums over a database that the first node has
 * already converted; whichever writes last wins, and any row the two nodes saw differently keeps a checksum that matches neither. The first read
 * afterwards fails with `ERROR_ROW_CHECKSUM` and the node is dead.
 *
 * Three independent mechanisms keep it at one run, in the order they take effect:
 * 1. [withExclusiveDatabaseAccess] serialises the candidates and — crucially — hands the lock on only after the conversion has been committed.
 * 2. [ConfigurationService.getConversionState] is read from the database rather than from a cached field, so the runner-up sees
 *    [DONE] and goes straight to [OPERATIONAL]. This is the check that failed in August 2026.
 * 3. [convertDatabase] skips its work if row checksums already exist — the last net, in case the state says otherwise.
 */
@Suppress("unused")
object SpreeBootstrapProcessor {
	private val systemStateService: SystemStateService by lazy { cdiService() }
	private val configurationService: ConfigurationService by lazy { cdiService() }

	private val bootstrapInterval: Duration by lazy { Duration.parse(getEnvironment(ENV_BOOTSTRAP_INTERVAL, "PT1M")) }
	private val maxBootstrapAttempts: Int by lazy { getEnvironment(ENV_BOOTSTRAP_ATTEMPTS, "10").toInt() }

	private var attempts = 0
	private var done = false

	fun scheduleRealmSetupCheck(factory: KeycloakSessionFactory) {
		val timerProviderFactory = factory.getProviderFactory(TimerProvider::class.java) as TimerProviderFactory

		logger.info("⏳️ Schedule realm setup check (${bootstrapInterval.toSeconds()} seconds) ...")

		timerProviderFactory.create(factory.create()).schedule({ checkRealmSetup(factory) }, bootstrapInterval.toMillis(), SPREE_BOOTSTRAP_PROCESSOR)
	}

	private fun checkRealmSetup(factory: KeycloakSessionFactory) {
		val state = systemStateService.currentSystemState()
		attempts++

		logger.info("🛠️ Checking realm setup... Current state is: »$state« (Attempt #$attempts)")

		when {
			state.isErrorState() -> {
				logger.fatal("💣 Bootstrapping FAILED with error", systemStateService.error)

				if (!done && shutdownOnError) {
					Quarkus.asyncExit()
				}

				cancelJob(factory)
			}

			state == SystemState.CONVERT_DATABASE -> {
				logger.info("🛠️ Realm initialization in progress...")
			}

			state.isBootstrapState() && (attempts >= maxBootstrapAttempts) -> {
				logger.fatal("💣 Bootstrapping FAILED. Could not bootstrap within $maxBootstrapAttempts attempts.")

				if (!done && shutdownOnError) {
					Quarkus.asyncExit()
				}

				cancelJob(factory)
			}

			state.isBootstrapState() -> {
				logger.info("🛠️ Checking realm configuration...")

				withExclusiveDatabaseAccess(factory) {
					runJobInTransaction(factory) { session ->
						initializeDatabase(session)
							.onLeft { e ->
								logger.warn("Error while checking setup completion", e)
								throw e
							}
							.onRight {
								done = it

								logger.info("🗑️ Clearing caches...")
								session.getProvider(UserCache::class.java)?.clear()
								session.getProvider(CacheRealmProvider::class.java)?.clear()
							}
					}
				}
			}

			state == OPERATIONAL -> {
				cancelJob(factory)
			}

			else -> {
				logger.warn("⚠️ Unhandled system status »$state«")
			}
		}
	}

	/**
	 * Runs [body] while holding Keycloak's exclusive database lock.
	 *
	 * The order that matters is **lock → work → commit → unlock**. [body] therefore has to open its own transaction and see it committed before
	 * returning; the lock must not live inside that transaction. Taking it inside — the way this was written until August 2026 — releases it in the
	 * `finally` block *before* the surrounding transaction commits, so the next node acquires the lock while our writes are still invisible to it and
	 * converts a database it believes to be untouched.
	 *
	 * Holding the lock across a transaction of its own session is safe by design of Keycloak's `LiquibaseDBLockProvider`: `lazyInit()` opens a
	 * dedicated JDBC connection via `JpaConnectionProviderFactory.getConnection()`, and both `waitForLock` and `releaseLock` run inside
	 * `KeycloakModelUtils.suspendJtaTransaction(...)`. The lock is thus tied to the session, not to any transaction, and closing the session (`use`)
	 * closes that connection again.
	 */
	private fun withExclusiveDatabaseAccess(factory: KeycloakSessionFactory, body: () -> Unit) {
		factory.create().use { lockSession ->
			val dbLock = DBLockManager(lockSession).dbLock

			logger.info("⏳️ Waiting for exclusive DB access...")
			dbLock.waitForLock(DBLockProvider.Namespace.DATABASE)
			logger.info("☑️ Exclusive DB access obtained...")

			try {
				body()
			} finally {
				dbLock.releaseLock()
				logger.info("🔓 Exclusive DB access released...")
			}
		}
	}

	private fun cancelJob(factory: KeycloakSessionFactory) {
		logger.info("⏳ Cancelling scheduled job...")

		runJobInTransaction(factory) {
			val timerProvider = it.getProvider(TimerProvider::class.java)
			timerProvider.cancelTask(SPREE_BOOTSTRAP_PROCESSOR)
			logger.info("⏳️ Scheduled task cancelled.")
		}
	}

	private fun initializeDatabase(session: KeycloakSession): Either<Throwable, Boolean> = either {
		logger.info("🛠️ Checking realm setup...")

		val encryptedRealm = session.loadEncryptedRealm().bind()
		val readyForConversion = encryptedRealm?.getAttribute(CONFIG_REALM_ENABLE_PROVIDER).toBoolean()

		if (readyForConversion) {
			val action = EntityAction(Action.INITIALIZE, "", session.entityManager)
			val conversionState = configurationService.getConversionState(action)

			logger.info("☑️ Realm exists, with conversion state: $conversionState...")

			if (conversionState == IN_PROGRESS) {
				// Another cluster node holds (or died holding) the conversion. Never convert on top of it — its checksums would be overwritten.
				logger.warn("⚠️️ Database conversion is in progress on another node — waiting...")

				return@either false
			}

			if (conversionState != DONE) {
				if (SpreeIntegrityScanner.scannerState == ScannerState.IDLE) {
					systemStateService.setSystemState(SystemState.CONVERT_DATABASE, keycloakSession = session)

					initializeRealm(session, action)

					return@either true
				} else {
					logger.info("⚠️️ Initialization is already in progress...")

					return@either false
				}
			} else {
				systemStateService.setSystemState(OPERATIONAL, keycloakSession = session)

				logger.info("🏃 Database already converted. $LOG_STATE_OPERATIONAL")
				logger.infof("🛠️ Database conversion state: »%s« ", conversionState)
				logger.infof("🛠️ Installed features: %s", configurationService.getFeatures(action))

				return@either true
			}
		} else {
			logger.info("⚠️️ Realm does not exist (yet)...")

			return@either false
		}
	}

	private fun Raise<Throwable>.initializeRealm(session: KeycloakSession, action: EntityAction) {
		action.runInTransaction {
			configurationService.setConversionState(action, IN_PROGRESS).bind()

			convertDatabase(action)
				.onLeft {
					systemStateService.setSystemState(ERROR_STARTUP, it, session)
					logger.error("💣 $IT_FAILED Error while computing initial checksums", it)
				}
				.onRight {
					val features = features()
					val keychainId = getKeychainId()

					configurationService.setConversionState(action, DONE).bind()
					configurationService.setFeatures(action, features).bind()
					configurationService.setKeychainId(action, keychainId).bind()
					systemStateService.setSystemState(OPERATIONAL, keycloakSession = session)

					logger.info("🏃 Database conversion completed. $LOG_STATE_OPERATIONAL")
					logger.infof("🛠️ Database conversion state: »%s« ", DONE)
					logger.infof("🛠️ Installed features: »%s«", features)
					logger.infof("🛠️ Stored initial keychain ID: »%s«", keychainId)

				}.bind()
		}
	}

	private fun features() = mutableSetOf<SpreeFeature>().apply {
		if (columnEncryptionEnabled) {
			add(SpreeFeature.COLUMN_ENCRYPTION)
		}

		if (rowChecksEnabled) {
			add(SpreeFeature.ROW_INTEGRITY)

			if (tableChecksEnabled) {
				add(SpreeFeature.TABLE_INTEGRITY)
			}
		}
	}
}