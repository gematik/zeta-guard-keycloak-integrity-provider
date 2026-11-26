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

package de.spree.keycloak.it

import de.spree.keycloak.commons.it.TEST_REALM
import jakarta.ws.rs.core.UriBuilder
import java.net.URI
import org.keycloak.constants.ServiceUrlConstants
import org.keycloak.models.KeycloakUriInfo

const val KC_HOST = "localhost"
const val KC_PORT = 18080
const val ADMIN_REALM = "master"
const val ADMIN_USER = "wasadmin"
const val ADMIN_PASSWORD = "wasadmin"
const val ADMIN_CLIENT = "admin-cli"

// https://www.keycloak.org/docs-api/latest/rest-api/index.html#_client_initial_access
const val INITIAL_ACCESS_TOKEN_PATH = "/admin/realms/{realm-name}/clients-initial-access"
const val WELLKNOWN_BASE_PATH = "/realms/{realm-name}/.well-known"
const val USERINFO_PATH = "/realms/{realm-name}/protocol/openid-connect/userinfo"

// https://www.keycloak.org/securing-apps/client-registration
const val KEYCLOAK_CLIENT_REGISTRATION_PATH = "/realms/{realm-name}/clients-registrations/default"
const val OIDC_CLIENT_REGISTRATION_PATH = "/realms/{realm-name}/clients-registrations/openid-connect"

const val KEYCLOAK_REALM_PATH = "/realms/{realm-name}"

class KeycloakUriBuilder(private val uriBuilder: UriBuilder) {
  constructor(uriInfo: KeycloakUriInfo) : this(uriInfo.baseUriBuilder)

  constructor(
      hostname: String,
      port: Int,
      scheme: String,
      path: String,
  ) : this(UriBuilder.newInstance().host(hostname).port(mapPort(port, scheme)).scheme(scheme).path(path))

  fun tokenUrl(realm: String = TEST_REALM) = createUri(ServiceUrlConstants.TOKEN_PATH, realm)

  fun authUrl(realm: String = TEST_REALM) = createUri(ServiceUrlConstants.AUTH_PATH, realm)

  fun userinfoUrl(realm: String = TEST_REALM) = createUri(USERINFO_PATH, realm)

  fun initialAccessTokenUrl(realm: String = TEST_REALM) = createUri(INITIAL_ACCESS_TOKEN_PATH, realm)

  fun realmUrl(realm: String = TEST_REALM) = createUri(KEYCLOAK_REALM_PATH, realm)

  fun clientRegistrationKeycloakUrl(realm: String = TEST_REALM) = createUri(KEYCLOAK_CLIENT_REGISTRATION_PATH, realm)

  fun clientRegistrationOIDCUrl(realm: String = TEST_REALM) = createUri(OIDC_CLIENT_REGISTRATION_PATH, realm)

  fun logoutUrl(realm: String = TEST_REALM) = createUri(ServiceUrlConstants.TOKEN_SERVICE_LOGOUT_PATH, realm)

  fun createUri(path: String, realm: String, vararg parameter: Pair<String, String>): URI {
    var path1 = path.replace("\\{realm-name}".toRegex(), realm)

    for (entry in parameter) {
      path1 = path1.replace("\\{${entry.first}}".toRegex(), entry.second)
    }

    return uriBuilder.path(path1).build()
  }

  fun build(): URI = uriBuilder.build()
}

/**
 * Omit port from uri, if defaults apply
 *
 * Otherwise "audience" claims, e.g. may not match anymore
 */
private fun mapPort(port: Int, scheme: String): Int =
    when (port) {
      443 if scheme == "https" -> -1
      80 if scheme == "http" -> -1
      else -> port
    }
