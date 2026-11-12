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

import de.spree.keycloak.commons.configuration.SpreeEntityConfiguration
import de.spree.keycloak.commons.configuration.SystemStateService
import de.spree.keycloak.commons.configuration.realmName
import de.spree.keycloak.commons.debug.SpreeLog
import de.spree.keycloak.commons.crypto.CryptoService
import de.spree.keycloak.commons.crypto.setupBouncyCastle
import io.kotest.core.spec.style.FunSpec
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import jakarta.enterprise.inject.spi.CDI
import org.jboss.logmanager.Logger
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.models.RealmProvider
import org.keycloak.quarkus.runtime.tracing.OTelTracingProviderFactory
import org.keycloak.tracing.TracingProvider
import org.keycloak.utils.KeycloakSessionUtil

abstract class AbstractCDITest : FunSpec() {
	val cdi: CDI<Any> = mockk()

	protected val cryptoService = CryptoService().apply { setValue("keychainBundle", keychainBundle) }
	protected val systemStateService = SystemStateService()
	protected val keycloakSession: KeycloakSession = mockk()
	protected val realmProvider: RealmProvider = mockk()
	protected val tracingProvider: TracingProvider = mockk()
	protected val realmModel: RealmModel = mockk()

	init {
		beforeTest {
//			keychainBundle = TestKeychainBundle()

			mockkStatic(CDI::class)
			every { CDI.current() } returns cdi

			trainCDIService<SpreeEntityConfiguration>(spreeConfiguration)
			trainCDIService<CryptoService>(cryptoService)
			trainCDIService<SystemStateService>(systemStateService)
			trainCDIService<java.util.logging.Logger>(Logger.getLogger("de.spree.keycloak"), SpreeLog())

			KeycloakSessionUtil.setKeycloakSession(keycloakSession)
			systemStateService.setValue("entityConfiguration", spreeConfiguration)

			every { keycloakSession.getProvider(TracingProvider::class.java, OTelTracingProviderFactory.PROVIDER_ID) } returns tracingProvider
			every { keycloakSession.realms() } returns realmProvider
			every { keycloakSession.context } returns mockk(relaxed = true)
			every { realmProvider.getRealmByName(realmName) } returns realmModel
			every { realmModel.attributes } returns mutableMapOf()
			every { tracingProvider.getTracer(any()) } returns mockk(relaxed = true)
		}
	}

	companion object {
		val spreeConfiguration = AbstractCDITest::class.java.getResourceAsStream("/spree-configuration.yml")!!.toYamlObject<SpreeEntityConfiguration>()

		init {
			setupBouncyCastle()
		}
	}

	inline fun <reified T> trainCDIService(service: T, vararg qualifiers: Annotation) {
		val serviceCDI: CDI<T> = mockk()
		every { cdi.select(T::class.java, *qualifiers) } returns serviceCDI
		every { serviceCDI.get() } returns service
	}
}
