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

import de.spree.keycloak.commons.TestData.dataBytes
import de.spree.keycloak.crypto.Checksum
import de.spree.keycloak.crypto.HashingService
import de.spree.keycloak.crypto.keychain.Keychain
import de.spree.keycloak.crypto.muhash.MuHash3072
import io.kotest.assertions.arrow.core.shouldBeLeft
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.matchers.ints.shouldBeGreaterThan
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain

class HashingServiceTest : AbstractTest() {
	val objectUnderTest = HashingService().setValue("keychainBundle", keychainBundle)

	init {
		"should hash and verify successfully" {
			val checksum = objectUnderTest.hash(dataBytes).shouldBeRight()

			checksum.hash shouldNotBe dataBytes
			checksum.hash.size shouldBeGreaterThan 0

			objectUnderTest.verify("entity", checksum, dataBytes).shouldBeRight()
		}

		"should not verify with unknown keychain" {
			val unknownKeychain = Keychain()

			val hash = objectUnderTest.hashInternal(unknownKeychain, dataBytes).shouldBeRight()
			val checksum = Checksum(unknownKeychain.keychainId.toByteArray(), hash)

			objectUnderTest.verify("entity", checksum, dataBytes).shouldBeLeft().message shouldContain "Unresolvable Keychain ID"
		}

		"should not verify if data is modified" {
			val hash = objectUnderTest.hash(dataBytes).shouldBeRight()
			val modified = dataBytes.copyOf()
			modified[0]++

			objectUnderTest.verify("entity", hash, modified).shouldBeLeft().message shouldContain "HMAC verification failed"
		}

		"should not verify if hash is tampered with" {
			val checksum = objectUnderTest.hash(dataBytes).shouldBeRight()
			val tampered = Checksum(checksum.keychainId, checksum.hash.copyOf())
			tampered.hash[0]++

			objectUnderTest.verify("entity", tampered, dataBytes).shouldBeLeft().message shouldContain "HMAC verification failed"
		}

		"should throw exception for invalid data" {
			val checksum = objectUnderTest.hash(dataBytes).shouldBeRight()
			objectUnderTest.verify("entity", checksum, checksum.hash).shouldBeLeft().message shouldContain "HMAC verification failed"
		}

		"should throw exception for invalid hash" {
			objectUnderTest.verify("entity", Checksum(dataBytes, dataBytes), dataBytes).shouldBeLeft().message shouldContain "Unresolvable Keychain ID"
		}

		"finishing multi hash without modifications yields identity" {
			val multi = objectUnderTest.init().shouldBeRight()
			val checksum = objectUnderTest.finish(multi).shouldBeRight()
			checksum.keychainId shouldBe keychainBundle.currentKeychain().keychainId.toByteArray()
			checksum.hash shouldBe MuHash3072().current()
		}

		"can update and remove from multi hash" {
			val multi = objectUnderTest.init().shouldBeRight()
			val empty = objectUnderTest.finish(multi).shouldBeRight()
			objectUnderTest.isEmpty(multi).shouldBeRight() shouldBe true

			objectUnderTest.insert(multi, dataBytes).shouldBeRight()
			val filled = objectUnderTest.finish(multi).shouldBeRight()
			filled shouldNotBe empty
			objectUnderTest.isEmpty(multi).shouldBeRight() shouldBe false

			objectUnderTest.remove(multi, dataBytes).shouldBeRight()
			val done = objectUnderTest.finish(multi).shouldBeRight()
			done shouldBe empty
			objectUnderTest.isEmpty(multi).shouldBeRight() shouldBe true
		}

		"can restart multi hash from previous value" {
			val multi = objectUnderTest.init().shouldBeRight()
			val empty = objectUnderTest.finish(multi).shouldBeRight()

			objectUnderTest.insert(multi, dataBytes).shouldBeRight()
			val filled = objectUnderTest.finish(multi).shouldBeRight()
			filled shouldNotBe empty

			val multi2 = objectUnderTest.init(filled).shouldBeRight()
			objectUnderTest.remove(multi2, dataBytes).shouldBeRight()
			val done = objectUnderTest.finish(multi2).shouldBeRight()
			done shouldBe empty
		}

		"can verify multi hash against expected checksum" {
			val multi = objectUnderTest.init().shouldBeRight()
			objectUnderTest.insert(multi, dataBytes).shouldBeRight()
			val expected = objectUnderTest.finish(multi).shouldBeRight()

			val multi2 = objectUnderTest.init().shouldBeRight()
			objectUnderTest.insert(multi2, dataBytes).shouldBeRight()
			val actual = objectUnderTest.finish(multi2).shouldBeRight()
			actual shouldBe expected

			objectUnderTest.verify("entity", multi2, expected).shouldBeRight()
		}
	}
}
