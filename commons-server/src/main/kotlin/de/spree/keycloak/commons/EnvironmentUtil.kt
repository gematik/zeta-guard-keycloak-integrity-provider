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
package de.spree.keycloak.commons

import arrow.core.Either

const val ENV_HSM_PROXY_ENDPOINT = "HSM_PROXY_ENDPOINT"
const val ENV_HSM_PROXY_KEK_ID = "HSM_PROXY_KEK_ID"
const val ENV_KEYCHAIN_KEK_ID = "SPREE_KEYCHAIN_KEK_ID"
const val ENV_KEYCHAIN_FILE = "SPREE_KEYCHAIN_FILE"
const val ENV_KEYCHAIN_DATA = "SPREE_KEYCHAIN_DATA"
const val ENV_KEYCHAIN_KEY = "SPREE_KEYCHAIN_KEY"
const val ENV_PREVIOUS_KEYCHAIN_KEK_ID = "SPREE_PREVIOUS_KEYCHAIN_KEK_ID"
const val ENV_PREVIOUS_KEYCHAIN_FILE = "SPREE_PREVIOUS_KEYCHAIN_FILE"
const val ENV_PREVIOUS_KEYCHAIN_DATA = "SPREE_PREVIOUS_KEYCHAIN_DATA"
const val ENV_PREVIOUS_KEYCHAIN_KEY = "SPREE_PREVIOUS_KEYCHAIN_KEY"
const val ENV_FUTURE_KEYCHAIN_KEK_ID = "SPREE_FUTURE_KEYCHAIN_KEK_ID"
const val ENV_FUTURE_KEYCHAIN_FILE = "SPREE_FUTURE_KEYCHAIN_FILE"
const val ENV_FUTURE_KEYCHAIN_DATA = "SPREE_FUTURE_KEYCHAIN_DATA"
const val ENV_FUTURE_KEYCHAIN_KEY = "SPREE_FUTURE_KEYCHAIN_KEY"

const val ENV_REALM_NAME = "SPREE_ENCRYPTED_REALM"
const val ENV_BOOTSTRAP_INTERVAL = "SPREE_BOOTSTRAP_INTERVAL"
const val ENV_BOOTSTRAP_ATTEMPTS = "SPREE_BOOTSTRAP_ATTEMPTS"
const val ENV_PERIODIC_ROW_CHECK = "SPREE_PERIODIC_ROW_CHECK"
const val ENV_LOCKDOWN_ON_ERROR = "SPREE_LOCKDOWN_ON_ERROR"
const val ENV_SHUTDOWN_ON_ERROR = "SPREE_SHUTDOWN_ON_ERROR"
const val ENV_SCANNER_INTERVAL = "SPREE_SCANNER_INTERVAL"
const val ENV_SCANNER_DELAY = "SPREE_SCANNER_DELAY"
const val ENV_CONFIGURATION_PATH = "SPREE_CONFIGURATION_PATH"
const val ENV_CRYPTO_UPDATE_TIMEOUT = "SPREE_CRYPTO_UPDATE_TIMEOUT"
const val ENV_VOLATILE_ERROR_TIMEOUT = "SPREE_VOLATILE_ERROR_TIMEOUT"
const val ENV_AUTOMATIC_CRYPTO_UPDATE = "SPREE_AUTOMATIC_CRYPTO_UPDATE"

const val ENV_SPREE_INTEGRITY_PROVIDER_ENABLED = "SPREE_INTEGRITY_PROVIDER_ENABLED"
const val ENV_ENABLE_INTEGRITY_CHECK = "SPREE_ENABLE_INTEGRITY_CHECK"
const val ENV_ENABLE_INTEGRITY_ROW_CHECK = "SPREE_ENABLE_INTEGRITY_ROW_CHECK"
const val ENV_ENABLE_INTEGRITY_TABLE_CHECK = "SPREE_ENABLE_INTEGRITY_TABLE_CHECK"
const val ENV_ENABLE_ENCRYPTION = "SPREE_ENABLE_COLUMN_ENCRYPTION"

/**
 * Handle safe reading of required environment variables
 */

fun eitherGetEnvironment(name: String) = Either.catch { getEnvironment(name) }

fun getEnvironment(name: String, defaultValue: String? = null): String =
	System.getenv(name) ?: defaultValue ?: throw IllegalStateException("»$name« environment variable not available")

val integrityProviderEnabled: Boolean by lazy { getEnvironment(ENV_SPREE_INTEGRITY_PROVIDER_ENABLED, "false").toBoolean() }

/**
 * Lock down Keycloak into an error state that prevents authentication but allows admin access for diagnostics.
 */
val lockdownOnError: Boolean by lazy { getEnvironment(ENV_LOCKDOWN_ON_ERROR, "true").toBoolean() }

/**
 *  Optionally shutdown entire Keycloak server on error
 */
val shutdownOnError: Boolean by lazy { integrityProviderEnabled && getEnvironment(ENV_SHUTDOWN_ON_ERROR, "false").toBoolean() }

val integrityChecksEnabled: Boolean by lazy { integrityProviderEnabled && getEnvironment(ENV_ENABLE_INTEGRITY_CHECK, "false").toBoolean() }

val rowChecksEnabled: Boolean by lazy { integrityChecksEnabled && getEnvironment(ENV_ENABLE_INTEGRITY_ROW_CHECK, "true").toBoolean() }

val tableChecksEnabled: Boolean by lazy { rowChecksEnabled && getEnvironment(ENV_ENABLE_INTEGRITY_TABLE_CHECK, "true").toBoolean() }

val columnEncryptionEnabled: Boolean by lazy { integrityProviderEnabled && getEnvironment(ENV_ENABLE_ENCRYPTION, "true").toBoolean() }

val automaticCryptoUpdateEnabled: Boolean by lazy { integrityProviderEnabled && getEnvironment(ENV_AUTOMATIC_CRYPTO_UPDATE, "true").toBoolean() }
