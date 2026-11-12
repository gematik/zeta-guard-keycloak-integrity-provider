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
package de.spree.keycloak.commons.crypto.keychain

import arrow.core.Either
import de.spree.keycloak.commons.toByteArray
import java.time.LocalDateTime
import java.util.*

/** Holds configuration date, private and GCM keys, in particular, obtained from HSM proxy. */
data class Keychain(
    val keychainId: UUID = UUID.randomUUID(), // Key ID
    val creationDate: LocalDateTime = currentTime(), // Creation date of the keychain
    val hmacKey: ByteArray = KeychainUtil.generateDataBytes(HMAC_KEY_SIZE), // Byte Array containing HMAC key
    val gcmEncryptionKey: ByteArray = KeychainUtil.generateDataBytes(GCM_KEY_SIZE), // Byte array containing the AES key
    val gcmAad: ByteArray = KeychainUtil.generateDataBytes(AAD_SIZE), // additional authenticated data (AAD)
) {
  fun isValid() = INVALID_KEYCHAIN != this

  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is Keychain) return false

    return keychainId == other.keychainId
  }

  override fun hashCode() = keychainId.hashCode()
}

fun Keychain.keychainId() = Either.catch { keychainId.toByteArray() }

fun ByteArray.isValidKeychainId(): Boolean = !this.contentEquals(INVALID_UUID)
