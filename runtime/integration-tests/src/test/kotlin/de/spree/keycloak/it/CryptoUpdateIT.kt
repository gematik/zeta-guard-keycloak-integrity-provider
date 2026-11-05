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
import de.spree.keycloak.commons.configuration.SystemState
import io.kotest.assertions.arrow.core.shouldBeLeft
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.core.spec.Order
import io.kotest.matchers.ints.shouldBeLessThanOrEqual
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import org.apache.http.HttpStatus.SC_NOT_FOUND
import org.keycloak.models.jpa.entities.UserEntity

@Order(1)
class CryptoUpdateIT : AbstractDatabaseIT() {
	init {
		val keycloakWebClient = KeycloakWebClient()

		test("Crypto update of a single entity re-encrypts its columns") {
			val emailBefore = loadEncryptedEmail()

			keycloakWebClient.enqueueCryptoUpdate(UserEntity::class.java.name).shouldBeRight()
			keycloakWebClient.remainingTasks() shouldBe 1

			keycloakWebClient.processCryptoUpdates()

			keycloakWebClient.remainingTasks() shouldBe 0
			loadEncryptedEmail() shouldNotBe emailBefore // Re-encrypted with a fresh nonce
			keycloakWebClient.startScan().shouldBeRight()
			keycloakWebClient.systemStateEnum() shouldBe SystemState.OPERATIONAL
			keycloakWebClient.login().shouldBeRight()
		}

		test("Unknown entity cannot be queued for crypto update") {
			keycloakWebClient.enqueueCryptoUpdate("org.example.UnknownEntity").shouldBeLeft().statusCode shouldBe SC_NOT_FOUND
			keycloakWebClient.remainingTasks() shouldBe 0
		}

		test("Pending crypto updates can be cleared") {
			keycloakWebClient.enqueueCryptoUpdate(UserEntity::class.java.name).shouldBeRight()
			keycloakWebClient.remainingTasks() shouldBe 1

			keycloakWebClient.clearCryptoUpdates().shouldBeRight()

			keycloakWebClient.remainingTasks() shouldBe 0
		}
	}

	private fun loadEncryptedEmail(): String = runJPA { it.entityManager.find(UserEntity::class.java, USER_ID).email }
}

private fun KeycloakWebClient.remainingTasks() = remainingCryptoUpdates().shouldBeRight().reponseObject.trim().toLong()

/** Runs scan cycles until all crypto updates are done = no more row checksums changed. */
private fun KeycloakWebClient.processCryptoUpdates() {
	val maxCycles = 2 * remainingTasks().toInt() + 1
	var cycles = 0

	while (remainingTasks() > 0) {
		runScanCycle().shouldBeRight()
		cycles++ shouldBeLessThanOrEqual maxCycles
	}
}
