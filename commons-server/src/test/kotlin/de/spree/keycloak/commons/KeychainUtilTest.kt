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
import de.spree.keycloak.commons.crypto.HSMCryptoService
import de.spree.keycloak.commons.crypto.encrypt
import de.spree.keycloak.commons.crypto.keychain.GCM_KEY_SIZE
import de.spree.keycloak.commons.crypto.keychain.KEYCHAIN_SIZE
import de.spree.keycloak.commons.crypto.keychain.Keychain
import de.spree.keycloak.commons.crypto.keychain.KeychainType
import de.spree.keycloak.commons.crypto.keychain.KeychainUtil
import de.spree.keycloak.commons.crypto.keychain.loadKeychain
import de.spree.keycloak.commons.crypto.keychain.serialize
import de.spree.keycloak.commons.crypto.keychain.toKeychain
import io.kotest.assertions.arrow.core.shouldBeLeft
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.engine.spec.tempfile
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.verify

class KeychainUtilTest :
    AbstractTest({
      val hsmCryptoService: HSMCryptoService = mockk()
      val keychain = Keychain()
      val keychainKey = KeychainUtil.generateDataBytes(GCM_KEY_SIZE)
      val hsmKekId = "hsm-key-v1"
      val encryptedKeychain = keychain.serialize().encrypt(keychainKey).getOrElse { throw it }

      beforeTest {
        mockkStatic(::getEnvironment)
      }

      "Keychain conversion" {
        val encoded = keychain.serialize().apply { size shouldBe KEYCHAIN_SIZE }
        val keychain2 = encoded.toKeychain().shouldBeRight(keychain)

        keychain2.hmacKey shouldBe keychain.hmacKey
        keychain2.gcmEncryptionKey shouldBe keychain.gcmEncryptionKey
        keychain2.gcmAad shouldBe keychain.gcmAad
        keychain2.creationDate shouldBe keychain.creationDate
      }

      "Read Keychain from file, missing data" {
        val brokenFile = tempfile().apply {
          writeText(
            """
		  	  |$ENV_KEYCHAIN_DATA:"${encryptedKeychain.toBase64()}" // NOTE: wrong format, colon instead of equals
			  |$ENV_KEYCHAIN_KEY="${keychainKey.toBase64()}"
		      """.trimMargin()
          )
        }

        every { getEnvironment(ENV_KEYCHAIN_FILE) } returns brokenFile.absolutePath

        loadKeychain(hsmCryptoService, KeychainType.CURRENT).shouldBeLeft().message shouldContain ENV_KEYCHAIN_DATA
      }

      "Read Keychain from file" {
        val file = tempfile().apply {
          writeText(
            """
			  |$ENV_KEYCHAIN_DATA="${encryptedKeychain.toBase64()}"
			  |$ENV_KEYCHAIN_KEY="${keychainKey.toBase64()}"
			  |$ENV_KEYCHAIN_KEK_ID="$hsmKekId"
		      """.trimMargin()
          )
        }

        every { getEnvironment(ENV_KEYCHAIN_FILE) } returns file.absolutePath
        every { hsmCryptoService.decrypt(keychainKey, hsmKekId) } returns keychainKey.right()

        loadKeychain(hsmCryptoService, KeychainType.CURRENT).shouldBeRight() shouldBe keychain
      }

      "Read Keychain from file with comment" {
        val file = tempfile().apply {
            writeText(
                """
          |# ID: ${keychain.keychainId}
          |$ENV_KEYCHAIN_DATA="${encryptedKeychain.toBase64()}"
          |$ENV_KEYCHAIN_KEY="${keychainKey.toBase64()}"
          |$ENV_KEYCHAIN_KEK_ID="$hsmKekId"
          """.trimMargin()
            )
        }

        every { getEnvironment(ENV_KEYCHAIN_FILE) } returns file.absolutePath
        every { hsmCryptoService.decrypt(keychainKey, hsmKekId) } returns keychainKey.right()

        loadKeychain(hsmCryptoService, KeychainType.CURRENT).shouldBeRight() shouldBe keychain
      }

      "Read Keychain from file with KEK fallback" {
        val file = tempfile().apply {
            writeText(
                """
          |$ENV_KEYCHAIN_DATA="${encryptedKeychain.toBase64()}"
          |$ENV_KEYCHAIN_KEY="${keychainKey.toBase64()}"
          """.trimMargin() // missing KEK ID
            )
        }

        every { getEnvironment(ENV_KEYCHAIN_FILE) } returns file.absolutePath
        every { getEnvironment(ENV_HSM_PROXY_KEK_ID) } returns hsmKekId // KEK ID taken from environment
        every { hsmCryptoService.decrypt(keychainKey, hsmKekId) } returns keychainKey.right()

        loadKeychain(hsmCryptoService, KeychainType.CURRENT).shouldBeRight() shouldBe keychain
        verify { getEnvironment(ENV_KEYCHAIN_FILE) }
        verify { getEnvironment(ENV_HSM_PROXY_KEK_ID) }
      }

      "Read Keychain from environment" {
        every { getEnvironment(ENV_KEYCHAIN_FILE) } throws IllegalStateException()
        every { getEnvironment(ENV_KEYCHAIN_DATA) } returns encryptedKeychain.toBase64()
        every { getEnvironment(ENV_KEYCHAIN_KEY) } returns keychainKey.toBase64()
        every { getEnvironment(ENV_KEYCHAIN_KEK_ID) } returns hsmKekId
        every { hsmCryptoService.decrypt(keychainKey, hsmKekId) } returns keychainKey.right()

        loadKeychain(hsmCryptoService, KeychainType.CURRENT).shouldBeRight() shouldBe keychain
        verify { getEnvironment(ENV_KEYCHAIN_DATA) }
        verify { getEnvironment(ENV_KEYCHAIN_KEY) }
        verify { getEnvironment(ENV_KEYCHAIN_KEK_ID) }
      }

      "Read previous Keychain from file" {
        val file = tempfile().apply {
          writeText(
            """
			  |$ENV_KEYCHAIN_DATA="${encryptedKeychain.toBase64()}"
			  |$ENV_KEYCHAIN_KEY="${keychainKey.toBase64()}"
			  |$ENV_KEYCHAIN_KEK_ID="$hsmKekId"
		      """.trimMargin()
          )
        }

        every { getEnvironment(ENV_PREVIOUS_KEYCHAIN_FILE) } returns file.absolutePath
        every { hsmCryptoService.decrypt(keychainKey, hsmKekId) } returns keychainKey.right()

        loadKeychain(hsmCryptoService, KeychainType.PREVIOUS).shouldBeRight() shouldBe keychain
      }

      "Read previous Keychain from environment" {
        every { getEnvironment(ENV_PREVIOUS_KEYCHAIN_FILE) } throws IllegalStateException()
        every { getEnvironment(ENV_PREVIOUS_KEYCHAIN_DATA) } returns encryptedKeychain.toBase64()
        every { getEnvironment(ENV_PREVIOUS_KEYCHAIN_KEY) } returns keychainKey.toBase64()
        every { getEnvironment(ENV_PREVIOUS_KEYCHAIN_KEK_ID) } returns hsmKekId
        every { hsmCryptoService.decrypt(keychainKey, hsmKekId) } returns keychainKey.right()

        loadKeychain(hsmCryptoService, KeychainType.PREVIOUS).shouldBeRight() shouldBe keychain
        verify { getEnvironment(ENV_PREVIOUS_KEYCHAIN_DATA) }
        verify { getEnvironment(ENV_PREVIOUS_KEYCHAIN_KEY) }
        verify { getEnvironment(ENV_PREVIOUS_KEYCHAIN_KEK_ID) }
      }

      "Read future Keychain from file" {
        val file = tempfile().apply {
          writeText(
            """
			  |$ENV_KEYCHAIN_DATA="${encryptedKeychain.toBase64()}"
			  |$ENV_KEYCHAIN_KEY="${keychainKey.toBase64()}"
			  |$ENV_KEYCHAIN_KEK_ID="$hsmKekId"
		      """.trimMargin()
          )
        }

        every { getEnvironment(ENV_FUTURE_KEYCHAIN_FILE) } returns file.absolutePath
        every { hsmCryptoService.decrypt(keychainKey, hsmKekId) } returns keychainKey.right()

        loadKeychain(hsmCryptoService, KeychainType.FUTURE).shouldBeRight() shouldBe keychain
      }

      "Read future Keychain from environment" {
        every { getEnvironment(ENV_FUTURE_KEYCHAIN_FILE) } throws IllegalStateException()
        every { getEnvironment(ENV_FUTURE_KEYCHAIN_DATA) } returns encryptedKeychain.toBase64()
        every { getEnvironment(ENV_FUTURE_KEYCHAIN_KEY) } returns keychainKey.toBase64()
        every { getEnvironment(ENV_FUTURE_KEYCHAIN_KEK_ID) } returns hsmKekId
        every { hsmCryptoService.decrypt(keychainKey, hsmKekId) } returns keychainKey.right()

        loadKeychain(hsmCryptoService, KeychainType.FUTURE).shouldBeRight() shouldBe keychain
        verify { getEnvironment(ENV_FUTURE_KEYCHAIN_DATA) }
        verify { getEnvironment(ENV_FUTURE_KEYCHAIN_KEY) }
        verify { getEnvironment(ENV_FUTURE_KEYCHAIN_KEK_ID) }
      }
    })
