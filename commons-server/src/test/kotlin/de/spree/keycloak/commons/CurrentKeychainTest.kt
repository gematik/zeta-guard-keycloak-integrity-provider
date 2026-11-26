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

import arrow.core.getOrElse
import arrow.core.right
import de.spree.keycloak.commons.configuration.SystemStatusService
import de.spree.keycloak.crypto.HSMCryptoService
import de.spree.keycloak.crypto.encrypt
import de.spree.keycloak.crypto.keychain.AAD_SIZE
import de.spree.keycloak.crypto.keychain.CurrentKeychain
import de.spree.keycloak.crypto.keychain.GCM_KEY_SIZE
import de.spree.keycloak.crypto.keychain.Keychain
import de.spree.keycloak.crypto.keychain.KeychainUtil
import de.spree.keycloak.crypto.keychain.serialize
import io.kotest.assertions.arrow.core.shouldBeLeft
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.core.spec.style.StringSpec
import io.kotest.engine.spec.tempfile
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.verify

class CurrentKeychainTest :
    StringSpec({
      val hsmCryptoService: HSMCryptoService = mockk()
      val systemStatusService: SystemStatusService = mockk(relaxed = true)
      val hsmAad = KeychainUtil.generateDataBytes(AAD_SIZE)
      val keychain = Keychain()
      val serialized = keychain.serialize()
      val keychainKey = KeychainUtil.generateDataBytes(GCM_KEY_SIZE)
      val encryptedKeychain = serialized.encrypt(keychainKey, hsmAad).getOrElse { throw it }
      val file =
          tempfile().also {
            it.writeText(
                """
			|$ENV_KEYCHAIN_DATA="${encryptedKeychain.toBase64()}"
			|$ENV_KEYCHAIN_KEY="${keychainKey.toBase64()}"
			|$ENV_HSM_AAD="${hsmAad.toBase64()}"
		"""
                    .trimMargin()
            )
          }
      val brokenFile =
          tempfile().also {
            it.writeText(
                """
			|$ENV_KEYCHAIN_DATA:"${encryptedKeychain.toBase64()}"
			|$ENV_KEYCHAIN_KEY="${keychainKey.toBase64()}"
			|$ENV_HSM_AAD="${hsmAad.toBase64()}"
		"""
                    .trimMargin()
            )
          }
      var objectUnderTest = CurrentKeychain()

      beforeTest {
        mockkStatic(::getEnvironment)
        objectUnderTest = CurrentKeychain().setValue("systemStatusService", systemStatusService).setValue("hsmCryptoService", hsmCryptoService)
      }

      "Read Keychain from file" {
        every { getEnvironment(ENV_KEYCHAIN_FILE) } returns file.absolutePath
        every { hsmCryptoService.decrypt(keychainKey, hsmAad) } returns keychainKey.right()

        objectUnderTest.keychain().shouldBeRight() shouldBe keychain
      }

      "Read Keychain from file, missing data" {
        every { getEnvironment(ENV_KEYCHAIN_FILE) } returns brokenFile.absolutePath

        objectUnderTest.keychain().shouldBeLeft().message shouldContain ENV_KEYCHAIN_DATA
      }

      "Read Keychain from environment" {
        every { getEnvironment(ENV_KEYCHAIN_FILE) } throws IllegalStateException()
        every { getEnvironment(ENV_KEYCHAIN_DATA) } returns encryptedKeychain.toBase64()
        every { getEnvironment(ENV_KEYCHAIN_KEY) } returns keychainKey.toBase64()
        every { getEnvironment(ENV_HSM_AAD) } returns hsmAad.toBase64()
        every { hsmCryptoService.decrypt(keychainKey, hsmAad) } returns keychainKey.right()

        objectUnderTest.keychain().shouldBeRight() shouldBe keychain
        verify { getEnvironment(ENV_HSM_AAD) }
      }
    })
