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

import de.spree.keycloak.commons.ENV_SPREE_SCANNER_INTERVAL
import de.spree.keycloak.commons.cdiService
import de.spree.keycloak.commons.configuration.SystemStatus
import de.spree.keycloak.commons.configuration.SystemStatusService
import de.spree.keycloak.commons.getEnvironment
import de.spree.keycloak.commons.logger
import de.spree.keycloak.commons.shutdownOnError
import de.spree.keycloak.integrity.SpreeIntegrityScanner.runTableScan
import io.quarkus.runtime.Quarkus
import java.time.Duration
import org.keycloak.Config
import org.keycloak.connections.jpa.entityprovider.JpaEntityProviderFactory
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.models.utils.KeycloakModelUtils.runJobInTransaction
import org.keycloak.timer.TimerProvider
import org.keycloak.timer.TimerProviderFactory

const val INTEGRITY_JPA_PROVIDER_ID = "spree-integrity-provider"

private val SPREE_SCANNER_INTERVAL = getEnvironment(ENV_SPREE_SCANNER_INTERVAL, "PT5M")

/**
 * Factory for creating the Spree Integrity JPA Entity Provider.
 *
 * This factory initializes the provider and schedules periodic table scans for integrity checks. The scan interval can be configured via the
 * SPREE_SCANNER_INTERVAL environment variable.
 */
class SpreeIntegrityProviderFactory : JpaEntityProviderFactory {
  private val systemStatusService: SystemStatusService by lazy { cdiService() }

  /**
   * Creates a new instance of the integrity provider.
   *
   * @param keycloakSession The Keycloak session.
   * @return The SpreeIntegrityProvider instance.
   */
  override fun create(keycloakSession: KeycloakSession) = SpreeIntegrityProvider()

  /**
   * Initializes the factory with configuration. Currently a no-op.
   *
   * @param scope The configuration scope.
   */
  override fun init(scope: Config.Scope?) {
    // No-op
  }

  /**
   * Performs post-initialization, scheduling the integrity scanner task.
   *
   * @param factory The Keycloak session factory.
   */
  override fun postInit(factory: KeycloakSessionFactory) {
    systemStatusService.setSystemStatus(SystemStatus.INITIALIZE_PROVIDERS)

    val interval = Duration.parse(SPREE_SCANNER_INTERVAL)
    val timerProviderFactory = factory.getProviderFactory(TimerProvider::class.java) as TimerProviderFactory

    logger.info("🔎 Scanning tables every $interval")

    timerProviderFactory
        .create(factory.create())
        .scheduleTask(
            {
              runJobInTransaction(factory) {
                if (systemStatusService.currentSystemStatus() == SystemStatus.RUNNING) {
                  runTableScan().onLeft {
                    logger.fatal("💣 Scanning tables failed", it)

                    if (shutdownOnError) {
                      Quarkus.asyncExit()
                    }

                    throw it
                  }
                }
              }
            },
            interval.toMillis(),
            "spree-integrity-scanner",
        )
  }

  /** Closes the factory. Currently a no-op. */
  override fun close() {
    // No-op
  }

  /**
   * Returns the factory ID.
   *
   * @return The provider ID string.
   */
  override fun getId() = INTEGRITY_JPA_PROVIDER_ID
}
