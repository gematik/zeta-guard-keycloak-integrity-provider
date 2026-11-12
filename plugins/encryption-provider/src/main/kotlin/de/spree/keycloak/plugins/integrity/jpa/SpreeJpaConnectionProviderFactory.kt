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
package de.spree.keycloak.plugins.integrity.jpa

import de.spree.keycloak.commons.cdiService
import de.spree.keycloak.commons.configuration.SystemState
import de.spree.keycloak.commons.configuration.SystemStateService
import de.spree.keycloak.commons.integrityChecksEnabled
import org.keycloak.connections.jpa.DefaultJpaConnectionProvider
import org.keycloak.connections.jpa.JpaConnectionProvider
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.quarkus.runtime.storage.database.jpa.QuarkusJpaConnectionProviderFactory

/**
 * Custom JpaConnectionProviderFactory that intercepts and wraps the default Quarkus JPA connection provider.
 *
 * It overrides [create] to return a [DefaultJpaConnectionProvider] backed by [SpreeEntityManager], ensuring that database operations executed by
 * Keycloak are subject to checksum integrity validation.
 */
class SpreeJpaConnectionProviderFactory : QuarkusJpaConnectionProviderFactory() {
	private val systemStateService: SystemStateService by lazy { cdiService() }

	/**
	 * Returns the factory order. Set to 1000 to ensure this custom factory takes precedence over the default provider.
	 *
	 * @return The priority order value.
	 */
	override fun order() = 1000 // Higher priority

	override fun postInit(factory: KeycloakSessionFactory) {
		super.postInit(factory)
		factory.create().use { session ->
			systemStateService.setSystemState(SystemState.INITIALIZE_PROVIDERS, keycloakSession = session)
		}
	}

	/**
	 * Creates and returns the connection provider wrapping the SpreeEntityManager.
	 *
	 * @param session The Keycloak session.
	 * @return The wrapped JpaConnectionProvider instance.
	 */
	override fun create(session: KeycloakSession): JpaConnectionProvider = if (integrityChecksEnabled) {
		val provider = super.create(session)
		val entityManager = SpreeEntityManager(provider.entityManager)

		DefaultJpaConnectionProvider(entityManager)
	} else {
		super.create(session)
	}
}
