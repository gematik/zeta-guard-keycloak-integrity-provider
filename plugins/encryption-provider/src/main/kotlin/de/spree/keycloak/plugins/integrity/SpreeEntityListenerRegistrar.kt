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
package de.spree.keycloak.plugins.integrity

import de.spree.keycloak.commons.configuration.SystemState
import de.spree.keycloak.commons.configuration.SystemStateService
import de.spree.keycloak.commons.logger
import de.spree.keycloak.commons.rowChecksEnabled
import io.quarkus.runtime.StartupEvent
import jakarta.enterprise.context.ApplicationScoped
import jakarta.enterprise.event.Observes
import jakarta.persistence.EntityManagerFactory
import org.hibernate.SessionFactory
import org.hibernate.event.service.spi.EventListenerRegistry
import org.hibernate.event.spi.EventType
import org.hibernate.internal.SessionFactoryImpl

/**
 * Registers the SpreeIntegrityValidationListener with Hibernate's event system on startup.
 *
 * This class observes the Quarkus StartupEvent to append the listener to various Hibernate event types, enabling integrity validation for database
 * operations.
 */
@ApplicationScoped
class SpreeEntityListenerRegistrar(
	@Suppress("CdiInjectionPointsInspection") //
	private val entityManagerFactory: EntityManagerFactory,
	private val systemStateService: SystemStateService,
	private val listener: SpreeIntegrityValidationListener,
) {
	/**
	 * Handles the startup event by registering the listener with Hibernate. Bootstrapping phase, before access to the database is feasible.
	 *
	 * @param event The StartupEvent (unused).
	 */
	fun onStart(@Suppress("unused") @Observes event: StartupEvent) {
		systemStateService.setSystemState(SystemState.STARTUP_QUARKUS)

		if (rowChecksEnabled) {
			logger.info("🛠️ Registering listeners via Hibernate event system")

			val registry =
				entityManagerFactory
					.unwrap(SessionFactory::class.java)
					.let { it as SessionFactoryImpl }
					.serviceRegistry
					.getService(EventListenerRegistry::class.java)!!

			registry.apply {
				appendListeners(EventType.POST_COLLECTION_UPDATE, listener)
				appendListeners(EventType.POST_COLLECTION_RECREATE, listener)
				appendListeners(EventType.POST_COLLECTION_REMOVE, listener)
				appendListeners(EventType.POST_INSERT, listener)
				appendListeners(EventType.POST_UPSERT, listener)
				appendListeners(EventType.POST_UPDATE, listener)
				appendListeners(EventType.POST_LOAD, listener)
				appendListeners(EventType.POST_DELETE, listener)
			}
		} else {
			logger.info("⚠️ Integrity checks are disabled, skipping listener registration")
		}
	}
}
