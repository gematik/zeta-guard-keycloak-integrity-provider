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
package de.spree.keycloak.it

import de.spree.keycloak.commons.USER_ID
import de.spree.keycloak.commons.it.TEST_REALM
import de.spree.keycloak.commons.logger
import io.kotest.matchers.shouldBe
import org.apache.http.HttpStatus
import org.keycloak.admin.client.CreatedResponseUtil
import org.keycloak.representations.idm.ClientRepresentation
import org.keycloak.representations.idm.ClientScopeRepresentation
import org.keycloak.representations.idm.IdentityProviderRepresentation
import org.keycloak.representations.idm.UserRepresentation

private val keycloakAdminClient = KeycloakAdminClient(DockerControllerFactory.instance.kchost, DockerControllerFactory.instance.kcport)

fun updateUserEmail(email: String) {
  keycloakAdminClient.withKeycloak(clientId = ADMIN_CLIENT) {
    val realmResource = realm(TEST_REALM)
    val usersResource = realmResource.users()

    usersResource.count() shouldBe 1
    val userResource = usersResource.get(USER_ID)
    val representation = userResource.toRepresentation()
    representation.email = email
    userResource.update(representation)
  }
}

fun clearCaches() {
  try {
    keycloakAdminClient.withKeycloak(clientId = ADMIN_CLIENT) {
      val realmResource = realm(TEST_REALM)

      realmResource.clearRealmCache()
      realmResource.clearUserCache()
    }
  } catch (e: Exception) {
    logger.error("Error clearing caches", e)
  }
}

fun getUser(id: String): UserRepresentation =
    keycloakAdminClient.withKeycloak(clientId = ADMIN_CLIENT) {
      val realmResource = realm(TEST_REALM)
      val usersResource = realmResource.users()
      val userResource = usersResource.get(id)

      userResource.toRepresentation()
    }

fun removeUser(userId: String): Unit =
    keycloakAdminClient.withKeycloak(clientId = ADMIN_CLIENT) {
      val realmResource = realm(TEST_REALM)
      val usersResource = realmResource.users()

      usersResource.delete(userId)
    }

fun addUser(userRepresentation: UserRepresentation): String =
    keycloakAdminClient.withKeycloak(clientId = ADMIN_CLIENT) {
      val realmResource = realm(TEST_REALM)
      val usersResource = realmResource.users()
      val response = usersResource.create(userRepresentation)

      response.status shouldBe HttpStatus.SC_CREATED

      CreatedResponseUtil.getCreatedId(response)
    }

fun createIDP(): String =
    keycloakAdminClient.withKeycloak(clientId = ADMIN_CLIENT) {
      val realmResource = realm(TEST_REALM)
      val resource = realmResource.identityProviders()
      val response =
          resource.create(
              IdentityProviderRepresentation().apply {
                this.alias = "test-idp"
                this.providerId = "oidc"
                this.internalId = "test-idp"
                this.internalId = "test-idp"
              }
          )

      response.status shouldBe HttpStatus.SC_CREATED

      CreatedResponseUtil.getCreatedId(response)
    }

fun createClient(clientId: String): String =
    keycloakAdminClient.withKeycloak(clientId = ADMIN_CLIENT) {
      val realmResource = realm(TEST_REALM)
      val clientsResource = realmResource.clients()
      val clientCreatedResponse =
          clientsResource.create(
              ClientRepresentation().apply {
                this.id = clientId
                this.clientId = clientId
                this.name = clientId
                this.isEnabled = true
                defaultClientScopes = listOf("web-origins", "roles", "profile")
              }
          )

      clientCreatedResponse.status shouldBe HttpStatus.SC_CREATED

      CreatedResponseUtil.getCreatedId(clientCreatedResponse)
    }

fun createClientScope(clientScope: String): String =
    keycloakAdminClient.withKeycloak(clientId = ADMIN_CLIENT) {
      val realmResource = realm(TEST_REALM)
      val clientScopesResource = realmResource.clientScopes()

      val clientScopeCreatedResponse =
          clientScopesResource.create(
              ClientScopeRepresentation().apply {
                this.id = clientScope
                this.name = clientScope
                this.protocol = "openid-connect"
              }
          )

      clientScopeCreatedResponse.status shouldBe HttpStatus.SC_CREATED

      CreatedResponseUtil.getCreatedId(clientScopeCreatedResponse)
    }

fun deleteClient(clientId: String) =
    keycloakAdminClient.withKeycloak(clientId = ADMIN_CLIENT) {
      val realmResource = realm(TEST_REALM)
      val clientsResource = realmResource.clients()
      val clientResource = clientsResource.get(clientId)

      clientResource.remove()
    }

fun removeIDP(): Unit =
    keycloakAdminClient.withKeycloak(clientId = ADMIN_CLIENT) {
      val realmResource = realm(TEST_REALM)
      val resource = realmResource.identityProviders()

      resource.get("test-idp").remove()
    }
