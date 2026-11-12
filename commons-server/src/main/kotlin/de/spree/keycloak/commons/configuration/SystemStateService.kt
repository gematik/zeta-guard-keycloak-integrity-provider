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

import de.spree.keycloak.commons.ENV_VOLATILE_ERROR_TIMEOUT
import de.spree.keycloak.commons.currentKeycloakSession
import de.spree.keycloak.commons.debug.SpreeLog
import de.spree.keycloak.commons.getEnvironment
import de.spree.keycloak.commons.lockdownOnError
import de.spree.keycloak.commons.logger
import de.spree.keycloak.commons.reportFailure
import de.spree.keycloak.commons.reportSuccess
import de.spree.keycloak.commons.shutdownOnError
import io.quarkus.runtime.Quarkus
import io.quarkus.runtime.Startup
import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import org.keycloak.models.KeycloakSession
import java.time.Duration
import java.time.Instant
import java.util.logging.Logger

private val SPREE_VOLATILE_ERROR_TIMEOUT = Duration.parse(getEnvironment(ENV_VOLATILE_ERROR_TIMEOUT, "PT5S"))

/**
 * Hold current system state, including bootstrapping phase and any errors that occur during startup or runtime.
 *
 * Cannot be altered after reaching error state.
 */
@ApplicationScoped
@Startup
class SystemStateService {
	@Suppress("CdiInjectionPointsInspection")
	@Inject
	@SpreeLog
	private lateinit var spreeLogger: Logger

	@Inject
	private lateinit var entityConfiguration: SpreeEntityConfiguration

	var error: Throwable? = null

	private var state = SystemState.STARTUP

	private val volatileErrors = mutableMapOf<String, Instant>()

	fun currentSystemState() = state

	fun setSystemState(state: SystemState, cause: Throwable? = null, keycloakSession: KeycloakSession? = null) {
		if (state.ordinal >= this.state.ordinal || state.isErrorState()) {
			if (!this.state.isErrorState()) { // Don't override existing error
				if (state.isErrorState()) {
					handleErrorState(state, cause, keycloakSession)
				} else {
					handleRegularState(state, cause, keycloakSession)
				}
			}
		} else {
			val message = "Cannot reset system state from »${this.state}« to »$state«"
			logger.error("🛑️ $message")
			throw IllegalStateException(message, cause)
		}
	}

	private fun applyState(state: SystemState, cause: Throwable? = null) {
		this.state = state
		this.error = cause
	}

	private fun handleErrorState(state: SystemState, cause: Throwable?, keycloakSession: KeycloakSession?) {
		if (lockdownOnError) {
			applyState(state, cause)

			logger.fatal("💣 System entered error state »$state«", cause)
			spreeLogger.severe("💣 System entered error state »$state«: ${cause?.message}")

			(keycloakSession ?: currentKeycloakSession()).reportFailure("System entered error state", state, cause)

			if (shutdownOnError) {
				Quarkus.asyncExit()
			}
		} else {
			logger.error("💣 Integrity error detected »$state«", cause)
			spreeLogger.severe("💣 Integrity error detected »$state«: ${cause?.message}")

			(keycloakSession ?: currentKeycloakSession()).reportFailure("Integrity error detected", state, cause)
		}
	}

	private fun handleRegularState(state: SystemState, cause: Throwable?, keycloakSession: KeycloakSession?) {
		applyState(state, cause)

		logger.info("ℹ️ System entering state »$state«")

		if (state == SystemState.OPERATIONAL) {
			(keycloakSession ?: currentKeycloakSession()).reportSuccess()
		}
	}


	fun spreeIntegrityProviderRunning(): Boolean =
		currentSystemState().let {
			if (it.isErrorState()) {
				throw RuntimeException("Cannot encrypt/decrypt when in state »$it«")
			} else {
				it == SystemState.OPERATIONAL
			}
		}

	fun shouldIgnoreVolatileError(entityName: String, entityId: String = "", now: Instant = Instant.now()): Boolean {
		if (currentSystemState() !== SystemState.OPERATIONAL) return false
		if (!entityConfiguration.isVolatileEntity(entityName)) return false

		val errorKey = "$entityName#$entityId"
		val timeSinceError = volatileErrors[errorKey]?.let {	Duration.between(it, now) } ?: Duration.ZERO
		if (timeSinceError > SPREE_VOLATILE_ERROR_TIMEOUT) return false

		logger.warn("⚠ Possible temporary checksum inconsistency on »${errorKey}«")
        volatileErrors[errorKey] = now
        return true
	}

	fun clearVolatileError(entityName: String, entityId: String = "") {
		val errorKey = "$entityName#$entityId"
		volatileErrors.remove(errorKey)
	}

	/** This is for integration tests only! */
	fun resetState(state: SystemState = SystemState.OPERATIONAL) {
		this.state = state
		this.error = null
		this.volatileErrors.clear()
	}
}

const val IT_FAILED = "Integrity check failure:"

enum class SystemState {
	STARTUP,
	STARTUP_JPA,
	STARTUP_QUARKUS,
	INITIALIZE_PROVIDERS,
	CHECK_DATABASE_SETUP,
	CONVERT_DATABASE,
	OPERATIONAL,
	ERROR_STARTUP,
	ERROR_ROW_CHECKSUM,
	ERROR_TABLE_CHECKSUM,
	ERROR_ENCRYPTION,
	ERROR_DECRYPTION,
	ERROR_HSM,
	ERROR_UPDATE_CHECKSUMS;

	fun isErrorState() = ordinal > OPERATIONAL.ordinal

	fun isBootstrapState() = ordinal < OPERATIONAL.ordinal
}
