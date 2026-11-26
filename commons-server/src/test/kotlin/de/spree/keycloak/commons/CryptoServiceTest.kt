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

import de.spree.keycloak.crypto.*
import de.spree.keycloak.crypto.keychain.AAD_SIZE
import de.spree.keycloak.crypto.keychain.GCM_KEY_SIZE
import de.spree.keycloak.crypto.keychain.KeychainUtil.generateDataBytes
import io.kotest.assertions.arrow.core.shouldBeLeft
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import org.bouncycastle.crypto.InvalidCipherTextException

private val plaintext = "should encrypt and decrypt correctly".toByteArray()
private val nonce = generateDataBytes()

class CryptoServiceTest : AbstractTest() {
  private lateinit var objectUnderTest: CryptoService

  init {
    beforeTest { objectUnderTest = CryptoService().apply { setValue("currentKeychain", currentKeychain) } }

    "should encrypt and decrypt correctly" {
      val ciphertext = objectUnderTest.encrypt(plaintext, nonce).shouldBeRight()
      val decrypted = objectUnderTest.decrypt(ciphertext).shouldBeRight()

      ciphertext.encrypted shouldNotBe plaintext
      decrypted shouldBe plaintext

      ciphertext.toDatabaseRepresentation().toCipherText().shouldBeRight(ciphertext)
    }

    "should fail decryption if the MAC tag is tampered with" {
      val ciphertext = objectUnderTest.encrypt(plaintext, nonce).shouldBeRight()

      // Tamper with the last byte (the MAC tag area)
      ciphertext.encrypted[ciphertext.encrypted.size - 1]++

      objectUnderTest.decrypt(ciphertext).shouldBeLeft().shouldBeInstanceOf<InvalidCipherTextException>()
    }

    "should fail decryption if nonce is tampered with" {
      val ciphertext = objectUnderTest.encrypt(plaintext, nonce).shouldBeRight()
      val tamperedCiphertext = ciphertext.copy(nonce = generateDataBytes())

      objectUnderTest.decrypt(tamperedCiphertext).shouldBeLeft().shouldBeInstanceOf<InvalidCipherTextException>().message shouldBe
          "mac check in GCM failed"
    }

    "should fail decryption if wrong AAD is provided" {
      val ciphertext = objectUnderTest.encrypt(plaintext, nonce).shouldBeRight()

      keychainData.setValue("gcmAad", "Nonsense".toByteArray())

      objectUnderTest.decrypt(ciphertext).shouldBeLeft().shouldBeInstanceOf<InvalidCipherTextException>().message shouldBe "mac check in GCM failed"
    }

    "should re-encrypt with different key" {
      val ciphertext = objectUnderTest.encrypt(plaintext, nonce).shouldBeRight()
      val newKey = generateDataBytes(GCM_KEY_SIZE)
      val newCiphertext = objectUnderTest.recrypt(ciphertext, keychainData.gcmEncryptionKey, newKey).shouldBeRight()

      newCiphertext.encrypted shouldNotBe plaintext
      newCiphertext.encrypted shouldNotBe ciphertext.encrypted

      keychainData.setValue("gcmEncryptionKey", newKey)
      objectUnderTest.decrypt(newCiphertext).shouldBeRight(plaintext)
    }

    "Encrypt/decrypt data" {
      val aad = generateDataBytes(AAD_SIZE)
      val key = generateDataBytes(GCM_KEY_SIZE)
      val ciphertext = plaintext.encrypt(key, aad).shouldBeRight()

      ciphertext.decrypt(key, aad).shouldBeRight(plaintext)
      ciphertext.decrypt(key, generateDataBytes(AAD_SIZE)).shouldBeLeft().message shouldContain "failed"
      ciphertext.decrypt(plaintext, aad).shouldBeLeft().message shouldContain "32 bytes"
      ciphertext.decrypt(generateDataBytes(GCM_KEY_SIZE), aad).shouldBeLeft().message shouldContain "failed"
    }
  }
}
