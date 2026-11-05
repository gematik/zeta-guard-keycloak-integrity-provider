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

import de.spree.keycloak.commons.configuration.SystemState
import io.kotest.assertions.fail
import io.kotest.core.spec.Order
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.lang.Thread.sleep

private const val ATTEMPTS = 20

/**
 * First "test" that starts Docker compose
 *
 * Also creates DB backup for all consecutive tests to restore from corrupted states
 */
@Order(0)
class AAStartupIT : FunSpec() {
	private val log: Logger = LoggerFactory.getLogger(this.javaClass)

	init {
		beforeSpec { DockerControllerFactory.instance.start() }

		test("Wait for bootstrapping to complete") {
			var status: SystemState? = null
			var attempt = 0
			val keycloakWebClient = KeycloakWebClient()

			keycloakWebClient.ready() shouldBe DockerControllerFactory.instance.standalone

			do {
				sleep(5000)
				attempt++
				status = keycloakWebClient.systemStateEnum()
				log.info("Current system status: $status, attempt: #$attempt")
			} while (status != SystemState.OPERATIONAL && attempt < ATTEMPTS)

			if (status != SystemState.OPERATIONAL) {
				DockerControllerFactory.instance.stop()

				fail("System status is not OPERATIONAL after $ATTEMPTS attempts (Status: $status)")
			} else {
				DockerControllerFactory.instance.createDatabaseBackup()
			}

			keycloakWebClient.ready() shouldBe true
		}
	}
}
