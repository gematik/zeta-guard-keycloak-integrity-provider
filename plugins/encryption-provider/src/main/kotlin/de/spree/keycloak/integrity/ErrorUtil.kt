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
package de.spree.keycloak.integrity

import arrow.core.Either

/**
 * Ensures that a left error message contains an entity name.
 *
 * If the left error message does not contain the required entity name already,
 * this wraps the Throwable into a RuntimeException where the error message consists of
 * a message prefix, the entity name, and the original message or error class name.
 *
 * @param entityName the required entity name
 * @param messagePrefix a prefix string for the wrapper error message if needed
 * @return Either with right as is, or left with error message including entity name
 */
fun <T> Either<Throwable, T>.asEntityError(entityName: String, messagePrefix: String): Either<Throwable, T> =
    mapLeft { error ->
        error.takeIf { it.message?.contains(entityName) == true }
            ?: RuntimeException("$messagePrefix for »$entityName«: $error", error)
    }
