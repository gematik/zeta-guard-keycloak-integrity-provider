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
package de.spree.keycloak.crypto.admin

import arrow.core.getOrElse
import de.spree.keycloak.commons.cdiService
import de.spree.keycloak.commons.configuration.SpreeEntityConfiguration
import de.spree.keycloak.crypto.CryptoUpdateService
import jakarta.ws.rs.DELETE
import jakarta.ws.rs.GET
import jakarta.ws.rs.NotFoundException
import jakarta.ws.rs.POST
import jakarta.ws.rs.Path
import jakarta.ws.rs.PathParam
import jakarta.ws.rs.Produces
import jakarta.ws.rs.core.MediaType
import org.keycloak.events.admin.OperationType
import org.keycloak.events.admin.ResourceType
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.services.resources.admin.AdminEventBuilder
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator

/**
 * Admin interface for crypto updates.
 * Available under <pre>/admin/realms/{realm}/crypto-update</pre>
 */
class CryptoUpdateResource(
	val session: KeycloakSession,
	val realm: RealmModel,
	val auth: AdminPermissionEvaluator,
	adminEventBase: AdminEventBuilder,
) {
	private val cryptoUpdateService: CryptoUpdateService by lazy { cdiService() }
	private val entityConfiguration: SpreeEntityConfiguration by lazy { cdiService() }

	private val adminEvent: AdminEventBuilder = adminEventBase.realm(realm).resource(ResourceType.CUSTOM)

	private fun requireAdmin() {
		auth.realm().requireManageRealm()
	}

	/**
	 * Start crypto updates for all entities.
	 */
	@POST
	fun startCryptoUpdates() {
		requireAdmin()
		cryptoUpdateService.enqueueAllEntities(session).getOrElse { throw it }
		adminEvent.operation(OperationType.CREATE).resourcePath(session.context.uri).success()
	}

	/**
	 * Start crypto update for a single entity.
	 * Requires fully qualified class name.
	 * Rejects unknown entities.
	 */
	@POST
	@Path("{entityName}")
	fun startCryptoUpdate(@PathParam("entityName") entityName: String) {
		requireAdmin()

		if (entityConfiguration.findEntity(entityName) == null) {
			throw NotFoundException("Unknown entity »$entityName«")
		}

		cryptoUpdateService.enqueueEntity(session, entityName).getOrElse { throw it }
		adminEvent.operation(OperationType.CREATE).resourcePath(session.context.uri).success()
	}

	/**
	 * Clear all remaining crypto update tasks.
	 * Currently active tasks will still finish to process.
	 */
	@DELETE
	fun deleteAllTasks() {
		requireAdmin()
		cryptoUpdateService.clearTaskQueue(session)
		adminEvent.operation(OperationType.DELETE).resourcePath(session.context.uri).success()
	}

	/**
	 * Get the number of remaining crypto update tasks.
	 */
	@GET
	@Produces(MediaType.TEXT_PLAIN)
	fun remainingTasks(): Long {
		requireAdmin()
		return cryptoUpdateService.getRemainingTasks(session)
	}
}