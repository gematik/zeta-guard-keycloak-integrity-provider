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
const val ENV_KEYCHAIN_FILE = "SPREE_KEYCHAIN_FILE"
const val ENV_KEYCHAIN_DATA = "SPREE_KEYCHAIN_DATA"
const val ENV_KEYCHAIN_KEY = "SPREE_KEYCHAIN_KEY"
const val ENV_HSM_AAD = "SPREE_HSM_AAD"
const val ENV_REALM_NAME = "SPREE_ENCRYPTED_REALM"
const val ENV_BOOTSTRAP_INTERVAL = "SPREE_BOOTSTRAP_INTERVAL"
const val ENV_BOOTSTRAP_ATTEMPTS = "SPREE_BOOTSTRAP_ATTEMPTS"
const val ENV_SHUTDOWN_ON_ERROR = "SPREE_SHUTDOWN_ON_ERROR"
const val ENV_SPREE_SCANNER_INTERVAL = "SPREE_SCANNER_INTERVAL"
const val ENV_ENABLE_INTEGRITY_CHECK = "SPREE_ENABLE_INTEGRITY_CHECK"
const val ENV_SPREE_CONFIGURATION_PATH = "SPREE_CONFIGURATION_PATH"

/** Handle safe reading of required environment variables */
fun safeGetenv(name: String) = Either.catch { getEnvironment(name) }

fun getEnvironment(name: String, defaultValue: String? = null): String =
    System.getenv(name) ?: defaultValue ?: throw IllegalStateException("»$name« environment variable not set")

/** Optionally shutdown entire Keycloak server on initialization error */
val shutdownOnError: Boolean by lazy { getEnvironment(ENV_SHUTDOWN_ON_ERROR, "false").toBoolean() }

val checkIntegrity: Boolean by lazy { getEnvironment(ENV_ENABLE_INTEGRITY_CHECK, "false").toBoolean() }
