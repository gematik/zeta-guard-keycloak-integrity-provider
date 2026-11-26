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
package de.spree.keycloak.commons.configuration

import de.spree.keycloak.commons.debug.SpreeLog
import de.spree.keycloak.commons.logger
import io.quarkus.runtime.Startup
import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import java.util.logging.Logger

/** Hold current system status, including bootstrapping phase and any errors that occur during startup or runtime. */
@ApplicationScoped
@Startup
class SystemStatusService {
  @Suppress("CdiInjectionPointsInspection") @Inject @SpreeLog private lateinit var spreeLogger: Logger

  var error: Throwable? = null

  private var status = SystemStatus.BOOTSTRAP

  fun currentSystemStatus() = status

  fun setSystemStatus(status: SystemStatus, cause: Throwable? = null) {
    if (status.ordinal >= this.status.ordinal || status.isErrorState()) {
      if (!this.status.isErrorState()) { // Don't override existing error
        this.status = status
        this.error = cause

        if (status.isErrorState()) {
          logger.fatal("💣 System entered error state »$status«", cause)
          spreeLogger.severe("💣 System entered error state »$status«.: ${cause?.message}")
        }
      }
    } else {
      val message = "Cannot reset system status from »${this.status}« to »$status«."
      logger.error("🛠️ $message")
      throw IllegalStateException(message, cause)
    }
  }

  fun spreeIntegrityProviderRunning(): Boolean =
      currentSystemStatus().let {
        if (it.isErrorState()) {
          throw RuntimeException("Cannot encrypt/decrypt when in status »$it«")
        } else {
          it == SystemStatus.RUNNING
        }
      }

  /** This is for integration tests only! */
  fun resetStatus() {
    this.status = SystemStatus.RUNNING
    this.error = null
  }
}

const val IT_FAILED = "Integrity check failure:"

enum class SystemStatus {
  BOOTSTRAP,
  STARTUP_JPA,
  STARTUP_QUARKUS,
  INITIALIZE_PROVIDERS,
  WAITING_FOR_INITIAL_SETUP,
  INITIALIZING_CHECKSUMS,
  RUNNING,
  ERROR_STARTUP,
  ERROR_ROW_CHECKSUM,
  ERROR_TABLE_CHECKSUM,
  ERROR_ENCRYPTION,
  ERROR_DECRYPTION,
  ERROR_HSM,
  ERROR_UPDATE_CHECKSUMS;

  fun isErrorState() = ordinal > RUNNING.ordinal

  fun isBootstrapState() = ordinal < RUNNING.ordinal
}
