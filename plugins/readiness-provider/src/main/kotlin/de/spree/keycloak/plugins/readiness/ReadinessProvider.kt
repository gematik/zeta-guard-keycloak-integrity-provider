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
package de.spree.keycloak.plugins.readiness

import de.spree.keycloak.commons.configuration.SystemState
import de.spree.keycloak.commons.configuration.SystemStateService
import jakarta.inject.Inject
import jakarta.ws.rs.*
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import org.keycloak.services.cors.Cors
import org.keycloak.services.resource.RealmResourceProvider
import org.keycloak.services.util.CacheControlUtil

const val RS_PATH_READY = "/spree-ready"

@Path(RS_PATH_READY)
class ReadinessProvider : RealmResourceProvider {
	@Inject //
	private lateinit var systemStateService: SystemStateService

	@GET
	@Produces(MediaType.TEXT_PLAIN)
	fun ready(): Response {
		val status = if (systemStateService.currentSystemState() == SystemState.OPERATIONAL)
			Response.Status.OK
		else
			Response.Status.SERVICE_UNAVAILABLE

		return Response.status(status).type(MediaType.TEXT_PLAIN).build()
	}

	@OPTIONS
	@Path("{any:.*}")
	fun preflight(): Response =
		Cors.builder().allowedMethods(HttpMethod.GET).preflight().auth().add(Response.ok().cacheControl(CacheControlUtil.noCache()))

	override fun getResource() = this

	override fun close() {
		// No-op
	}
}
