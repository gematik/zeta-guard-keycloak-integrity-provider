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
import de.spree.keycloak.commons.configuration.CONFIG_REALM_ENABLE_INTEGRITY_PROVIDER
import de.spree.keycloak.commons.configuration.realmName
import jakarta.persistence.EntityManager
import org.keycloak.connections.jpa.JpaConnectionProvider
import org.keycloak.models.KeycloakSession
import org.keycloak.models.jpa.JpaRealmProvider

val KeycloakSession.entityManager: EntityManager
  get() = getProvider(JpaConnectionProvider::class.java).entityManager

val KeycloakSession.realmProvider: JpaRealmProvider
  get() = JpaRealmProvider(this, this.entityManager, null, null)

fun KeycloakSession.encryptedRealmExists(): Either<Throwable, Boolean> =
    Either.catch {
      val realmModel = realmProvider.getRealmByName(realmName)

      "true" == realmModel?.attributes[CONFIG_REALM_ENABLE_INTEGRITY_PROVIDER]
    }
