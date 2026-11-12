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
package de.spree.keycloak.bootstrap

import de.spree.keycloak.commons.cdiService
import de.spree.keycloak.commons.configuration.SystemState
import de.spree.keycloak.commons.configuration.SystemStateService
import de.spree.keycloak.commons.configuration.realmName
import de.spree.keycloak.commons.configuration.version
import de.spree.keycloak.commons.integrityProviderEnabled
import de.spree.keycloak.commons.logger
import de.spree.keycloak.scanner.SpreeIntegrityScanner.scheduleIntegrityScanner
import de.spree.keycloak.bootstrap.SpreeBootstrapProcessor.scheduleRealmSetupCheck
import org.keycloak.Config
import org.keycloak.events.Event
import org.keycloak.events.EventListenerProvider
import org.keycloak.events.EventListenerProviderFactory
import org.keycloak.events.admin.AdminEvent
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.models.RealmModel
import org.keycloak.models.utils.PostMigrationEvent


/** The ID of the event listener provider. */
const val EVENTS_PROVIDER_ID = "spree-event-listener"

/**
 * This factory primarily serves as a hook to compute initial table checksums after Keycloak migration is finished.
 *
 * See META-INF/services/org.keycloak.events.EventListenerProviderFactory
 */
class SpreeEventListenerFactory : EventListenerProviderFactory {
	private val systemStateService: SystemStateService by lazy { cdiService() }

	/**
	 * Creates a new EventListenerProvider instance (a dummy listener).
	 *
	 * @param session The Keycloak session.
	 * @return A DummyEventListener instance.
	 */
	override fun create(session: KeycloakSession) = DummyEventListener

	/**
	 * Initializes the factory with configuration. Currently a no-op.
	 *
	 * @param config The configuration scope.
	 */
	override fun init(config: Config.Scope) {
		// No-op
	}

	/**
	 * Performs post-initialization.
	 *
	 * @param factory The Keycloak session factory.
	 */
	override fun postInit(factory: KeycloakSessionFactory) {
		factory.create().use { session ->
			systemStateService.setSystemState(SystemState.INITIALIZE_PROVIDERS, keycloakSession = session)
		}

		if (integrityProviderEnabled) {
			logger.info("🛡️️ Spree integrity provider »${version}« enabled")
			registerSystemStatusEventListener(factory)
		} else {
			logger.warn("⚠️ Spree integrity provider »${version}« disabled")
		}
	}

	private fun registerSystemStatusEventListener(factory: KeycloakSessionFactory) {
		factory.register {
			when (it) { // It is not deterministic which events occurs first 🤷‍♂️, so set same state on both
				is RealmModel.RealmPostCreateEvent -> {
					if (it.createdRealm.name == realmName) {
						logger.info("🛠️ Realm »$realmName« created ...")
						systemStateService.setSystemState(SystemState.CHECK_DATABASE_SETUP, keycloakSession = it.keycloakSession)
					}
				}

				is PostMigrationEvent -> {
					logger.info("🛠️ Keycloak database migration completed ...")
					systemStateService.setSystemState(SystemState.CHECK_DATABASE_SETUP, keycloakSession = it.keycloakSession)

					logger.info("🛡️️ Booting Spree integrity provider »${version}«...")
					scheduleRealmSetupCheck(factory)
					scheduleIntegrityScanner(factory)
				}

				else -> {
					logger.debug("Received event: »${it.javaClass}« → ${it.javaClass.interfaces.joinToString(", ")}")
				}
			}
		}
	}

	override fun close() {
		// No-op
	}

	/**
	 * Returns the ID of the factory.
	 *
	 * @return The factory ID.
	 */
	override fun getId() = EVENTS_PROVIDER_ID
}

/**
 * A dummy event listener that performs no actions.
 *
 * This is used as the provider instance since the factory's main purpose is the post-migration hook.
 */
object DummyEventListener : EventListenerProvider {
	/**
	 * Handles an event. Currently a no-op.
	 *
	 * @param event The event to handle.
	 */
	override fun onEvent(event: Event) {
		// No-op
	}

	/**
	 * Handles an admin event. Currently a no-op.
	 *
	 * @param event The admin event.
	 * @param includeRepresentation Whether to include the event representation.
	 */
	override fun onEvent(event: AdminEvent, includeRepresentation: Boolean) {
		// No-op
	}

	/** Closes the listener. Currently a no-op. */
	override fun close() {
		// No-op
	}
}
