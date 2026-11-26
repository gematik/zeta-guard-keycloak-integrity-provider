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

package de.spree.keycloak.commons

import arrow.core.Either
import arrow.core.raise.Raise
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import jakarta.ws.rs.core.Response.Status
import org.jboss.logging.Logger
import org.keycloak.representations.idm.OAuth2ErrorRepresentation

/** Interface representing a general failure with a message and optional exception. */
interface GeneralFailure {
  val message: String
  val exception: Throwable?
    get() = null
}

/** Interface representing a successful outcome. */
interface Success

/** Simple success object implementing the Success interface. */
object SimpleSuccess : Success

/**
 * Success response containing a Keycloak response object.
 *
 * @param T The type of the response object.
 * @property reponseObject The response object (note: likely a typo for 'responseObject').
 */
data class KeycloakSuccessResponse<T>(val reponseObject: T) : Success

/** Keycloak error representation extending OAuth2ErrorRepresentation. Includes status code and custom toString implementation. */
@JsonIgnoreProperties(ignoreUnknown = true)
open class KeycloakError(error: String, errorDescription: String, var statusCode: Int) : OAuth2ErrorRepresentation(error, errorDescription) {
  @Suppress("unused") constructor() : this("", "", 0)

  constructor(error: String, errorDescription: String, status: Status) : this(error, errorDescription, status.statusCode)

  override fun toString() = "$error: $errorDescription (HTTP $statusCode)"
}

/** Logger instance for the keycloak-spree module. */
val logger: Logger = Logger.getLogger("keycloak-spree")

/**
 * Extension function to map a Throwable to a string message, logging the exception.
 *
 * @param message The message to log and return.
 * @return The message or the exception's message if available.
 */
fun Throwable.map(message: String): String {
  logger.warn(message, this)

  return this.message ?: message
}

fun <T> Raise<Throwable>.catchAll(block: () -> T): T = Either.catch { block() }.bind()
