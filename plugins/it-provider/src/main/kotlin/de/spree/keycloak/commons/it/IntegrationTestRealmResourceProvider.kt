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
package de.spree.keycloak.commons.it

import arrow.core.Either
import de.spree.keycloak.commons.KeycloakError
import de.spree.keycloak.commons.configuration.SystemStateService
import de.spree.keycloak.commons.entityManager
import de.spree.keycloak.commons.message
import de.spree.keycloak.scanner.SpreeIntegrityScanner
import jakarta.inject.Inject
import jakarta.ws.rs.*
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import org.eclipse.microprofile.openapi.annotations.parameters.Parameter
import org.keycloak.models.KeycloakSession
import org.keycloak.models.jpa.RealmAdapter
import org.keycloak.models.jpa.UserAdapter
import org.keycloak.models.jpa.entities.RealmEntity
import org.keycloak.models.jpa.entities.UserEntity
import org.keycloak.models.utils.KeycloakModelUtils
import org.keycloak.models.utils.ModelToRepresentation
import org.keycloak.services.resource.RealmResourceProvider

const val TEST_REALM = "encrypted-realm"

const val RS_METHOD_GET_STATE = "currentState"
const val RS_METHOD_RESET_STATE = "resetState"
const val RS_METHOD_ADD_ATTRIBUTES = "/{user-id}/addUserAttributes"
const val RS_METHOD_ADDCLIENTSCOPETOALLCLIENTS = "addClientScopeToAllClients"
const val RS_METHOD_START_SCAN = "scanTables"
const val RS_METHOD_START_UPDATE = "updateTables"
const val RS_METHOD_RUN_SCAN_CYCLE = "runScanCycle"
const val RS_PATH_IT = "/it"

@Path(RS_PATH_IT)
class IntegrationTestRealmResourceProvider : RealmResourceProvider {
  @Inject //
  private lateinit var systemStateService: SystemStateService

  @Suppress("CdiInjectionPointsInspection")
  @Inject //
  private lateinit var keycloakSession: KeycloakSession

  override fun getResource() = this

  @POST
  @Path(RS_METHOD_RESET_STATE)
  @Produces(MediaType.TEXT_PLAIN)
  fun resetState(): Response {
    val result = systemStateService.currentSystemState().name

    systemStateService.resetState()

    return Response.ok(result).build()
  }

  @POST
  @Path(RS_METHOD_ADD_ATTRIBUTES)
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  fun addAttributes(
      @Parameter(name = "user-id") @PathParam("user-id") userId: String,
      // Body
      attributes: Map<String, List<String>>,
  ): Response {
    val entityManager = keycloakSession.entityManager
    val realm = entityManager.find(RealmEntity::class.java, TEST_REALM)
    val realmAdapter = RealmAdapter(keycloakSession, entityManager, realm)
    val user = entityManager.find(UserEntity::class.java, userId)
    val userAdapter = UserAdapter(keycloakSession, realmAdapter, entityManager, user)

    for ((key, value) in attributes) {
      userAdapter.setAttribute(key, value)
    }

    val representation = ModelToRepresentation.toBriefRepresentation(userAdapter)

    return Response.ok(representation).build()
  }

  @POST
  @Path(RS_METHOD_ADDCLIENTSCOPETOALLCLIENTS)
  @Consumes(MediaType.TEXT_PLAIN)
  @Produces(MediaType.APPLICATION_JSON)
  fun addClientScopeToAllClients(clientScope: String): Response {
    val realm = keycloakSession.realms().getRealmByName(TEST_REALM)
    val clientScopeModel = KeycloakModelUtils.getClientScopeByName(realm, clientScope)

    keycloakSession.clients().addClientScopeToAllClients(realm, clientScopeModel, true)

    val representation = ModelToRepresentation.toRepresentation(clientScopeModel)

    return Response.ok(representation).build()
  }

  @POST
  @Path(RS_METHOD_START_SCAN)
  @Produces(MediaType.APPLICATION_JSON)
  fun startScan(): Response =
      SpreeIntegrityScanner.runTableScan(keycloakSession)
          .fold(
              ifLeft = { errorResponse(it) },
              ifRight = { Response.ok(systemStateService.currentSystemState()).build() },
          )

  @GET
  @Path(RS_METHOD_GET_STATE)
  @Produces(MediaType.TEXT_PLAIN)
  fun currentState(): Response = Response.ok(systemStateService.currentSystemState().name).build()

  @POST
  @Path(RS_METHOD_START_UPDATE)
  @Produces(MediaType.APPLICATION_JSON)
  fun startUpdate(): Response =
    SpreeIntegrityScanner.runAllCryptoUpdates(keycloakSession)
      .fold(
        ifLeft = { errorResponse(it) },
        ifRight = { Response.ok(systemStateService.currentSystemState()).build() },
      )

  @POST
  @Path(RS_METHOD_RUN_SCAN_CYCLE)
  @Produces(MediaType.APPLICATION_JSON)
  fun runScanCycle(): Response =
    Either.catch { SpreeIntegrityScanner.runScanCycle(keycloakSession) }
      .fold(
        ifLeft = { errorResponse(it) },
        ifRight = { Response.ok(systemStateService.currentSystemState()).build() },
      )

  private fun errorResponse(t: Throwable): Response {
    val message = t.getNestedExceptions().joinToString(" ➡ ") { e -> e.message() }
    return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
      .entity(KeycloakError(message, message, Response.Status.INTERNAL_SERVER_ERROR))
      .build()
  }

  override fun close() {
    // No-op
  }
}
