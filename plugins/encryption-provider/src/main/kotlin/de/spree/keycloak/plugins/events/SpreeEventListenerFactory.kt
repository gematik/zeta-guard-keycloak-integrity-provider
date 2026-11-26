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
package de.spree.keycloak.plugins.events

import arrow.core.Either
import arrow.core.raise.either
import de.spree.keycloak.commons.*
import de.spree.keycloak.commons.configuration.*
import de.spree.keycloak.integrity.ConfigurationService
import de.spree.keycloak.integrity.ScannerStatus
import de.spree.keycloak.integrity.SpreeDatabaseConversionState
import de.spree.keycloak.integrity.SpreeFeature
import de.spree.keycloak.integrity.SpreeIntegrityScanner
import io.quarkus.runtime.Quarkus
import java.time.Duration
import org.keycloak.Config
import org.keycloak.events.Event
import org.keycloak.events.EventListenerProvider
import org.keycloak.events.EventListenerProviderFactory
import org.keycloak.events.admin.AdminEvent
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.models.RealmModel
import org.keycloak.models.utils.KeycloakModelUtils.runJobInTransaction
import org.keycloak.models.utils.PostMigrationEvent
import org.keycloak.timer.TimerProvider
import org.keycloak.timer.TimerProviderFactory

/** The ID of the event listener provider. */
const val EVENTS_PROVIDER_ID = "spree-event-listener"

/**
 * This factory primarily serves as a hook to compute initial table checksums after Keycloak migration is finished.
 *
 * See META-INF/services/org.keycloak.events.EventListenerProviderFactory
 */
class SpreeEventListenerFactory : EventListenerProviderFactory {
  private val systemStatusService: SystemStatusService by lazy { cdiService() }
  private val configurationService: ConfigurationService by lazy { cdiService() }
  private val bootstrapInterval: Duration by lazy { Duration.parse(getEnvironment(ENV_BOOTSTRAP_INTERVAL, "PT1M")) }
  private val maxBootstrapAttempts: Int by lazy { getEnvironment(ENV_BOOTSTRAP_ATTEMPTS, "10").toInt() }

  private var attempts = 0
  private var done = false

  /**
   * Creates a new EventListenerProvider instance (a dummy listener).
   *
   * @param session The Keycloak session.
   * @return A DummyEventListener instance.
   */
  override fun create(session: KeycloakSession) = DummyEventListener

  /**
   * Initializes the factory with configuration. Currently a no-op.
   *
   * @param config The configuration scope.
   */
  override fun init(config: Config.Scope) {
    // No-op
  }

  /**
   * Performs post-initialization.
   *
   * @param factory The Keycloak session factory.
   */
  override fun postInit(factory: KeycloakSessionFactory) {
    registerSystemStatusEventListener(factory)

    scheduleRealmSetupCheck(factory)
  }

  private fun scheduleRealmSetupCheck(factory: KeycloakSessionFactory) {
    val timerProviderFactory = factory.getProviderFactory(TimerProvider::class.java) as TimerProviderFactory

    logger.info("⏳️ Schedule realm setup check (${bootstrapInterval.toSeconds()} seconds) ...")

    timerProviderFactory.create(factory.create()).schedule({ checkRealmSetup(factory) }, bootstrapInterval.toMillis(), EVENTS_PROVIDER_ID)
  }

  private fun checkRealmSetup(factory: KeycloakSessionFactory) {
    val status = systemStatusService.currentSystemStatus()
    attempts++

    logger.info("🛠️ Checking realm setup... Current status is: »$status« (Attempt #$attempts)")

    when {
      status.isErrorState() -> {
        logger.fatal("💣 Bootstrapping FAILED with error", systemStatusService.error)

        if (!done && shutdownOnError) {
          Quarkus.asyncExit()
        }

        cancelJob(factory)
      }

      status == SystemStatus.INITIALIZING_CHECKSUMS -> {
        logger.info("🛠️ Realm initialization in progress...")
      }

      status.isBootstrapState() && (attempts >= maxBootstrapAttempts) -> {
        logger.fatal("💣 Bootstrapping FAILED. Could not bootstrap within $maxBootstrapAttempts attempts.")

        if (!done && shutdownOnError) {
          Quarkus.asyncExit()
        }

        cancelJob(factory)
      }

      status.isBootstrapState() -> {
        logger.info("🛠️ Checking realm configuration...")

        runJobInTransaction(factory) { session ->
          checkBootstrappingDone(session)
              .onLeft { e ->
                logger.warn("Error while checking setup completion", e)
                throw e
              }
              .onRight { done = it }
        }
      }

      status == SystemStatus.RUNNING -> {
        cancelJob(factory)
      }

      else -> {
        logger.warn("⚠️ Unhandled system status »$status«")
      }
    }
  }

  private fun cancelJob(factory: KeycloakSessionFactory) {
    logger.info("⏳ Cancelling scheduled job...")

    runJobInTransaction(factory) {
      val timerProvider = it.getProvider(TimerProvider::class.java)
      timerProvider.cancelTask(EVENTS_PROVIDER_ID)
      logger.info("⏳️ Scheduled task cancelled.")
    }
  }

  private fun registerSystemStatusEventListener(factory: KeycloakSessionFactory) {
    factory.register {
      when (it) {
        is PostMigrationEvent -> {
          logger.info("🛠️ Keycloak database migration completed ...")
          systemStatusService.setSystemStatus(SystemStatus.WAITING_FOR_INITIAL_SETUP)
        }

        is RealmModel.RealmPostCreateEvent -> {
          if (it.createdRealm.name == realmName) {
            logger.info("🛠️ Realm »$realmName« created ...")
            systemStatusService.setSystemStatus(SystemStatus.WAITING_FOR_INITIAL_SETUP)
          }
        }

        else -> {
          logger.debug("Received event: »${it.javaClass}« → ${it.javaClass.interfaces.joinToString(", ")}")
        }
      }
    }
  }

  private fun checkBootstrappingDone(session: KeycloakSession): Either<Throwable, Boolean> = either {
    logger.info("🛠️ Checking realm setup...")
    val realmExists = session.encryptedRealmExists().bind()

    if (realmExists) {
      val conversionState = configurationService.getConversionState()

      if (conversionState != SpreeDatabaseConversionState.DONE) {
        if (SpreeIntegrityScanner.scannerStatus == ScannerStatus.IDLE) {
          systemStatusService.setSystemStatus(SystemStatus.INITIALIZING_CHECKSUMS)

          SpreeIntegrityScanner.initializeRealm()
              .onLeft {
                systemStatusService.setSystemStatus(SystemStatus.ERROR_STARTUP, it)
                logger.error("💣 $IT_FAILED Error while computing initial checksums", it)
              }
              .onRight {
                systemStatusService.setSystemStatus(SystemStatus.RUNNING)
                configurationService.setConversionState(SpreeDatabaseConversionState.DONE)
                configurationService.setFeatures(features())

                logger.info("🏃 $LOG_STATUS_RUNNING")
              }
              .bind()

          return@either true
        } else {
          logger.info("⚠️️ Initialization is already in progress...")

          return@either false
        }
      } else {
        logger.info("🏃 Conversion state already marked as DONE. $LOG_STATUS_RUNNING")
        systemStatusService.setSystemStatus(SystemStatus.RUNNING)

        return@either true
      }
    } else {
      logger.info("⚠️️ Realm does not exist (yet)...")

      return@either false
    }
  }

  private fun features(): MutableSet<SpreeFeature> {
    val features = mutableSetOf(SpreeFeature.COLUMN_ENCRYPTION) // default

    if (checkIntegrity) { // Currently its all or nothing
      features.add(SpreeFeature.ROW_INTEGRITY)
      features.add(SpreeFeature.TABLE_INTEGRITY)
    }
    return features
  }

  /** Closes the factory. Currently a no-op. */
  override fun close() {
    // No-op
  }

  /**
   * Returns the ID of the factory.
   *
   * @return The factory ID.
   */
  override fun getId() = EVENTS_PROVIDER_ID
}

/**
 * A dummy event listener that performs no actions.
 *
 * This is used as the provider instance since the factory's main purpose is the post-migration hook.
 */
object DummyEventListener : EventListenerProvider {
  /**
   * Handles an event. Currently a no-op.
   *
   * @param event The event to handle.
   */
  override fun onEvent(event: Event) {
    // No-op
  }

  /**
   * Handles an admin event. Currently a no-op.
   *
   * @param event The admin event.
   * @param includeRepresentation Whether to include the event representation.
   */
  override fun onEvent(event: AdminEvent, includeRepresentation: Boolean) {
    // No-op
  }

  /** Closes the listener. Currently a no-op. */
  override fun close() {
    // No-op
  }
}
