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
package de.spree.keycloak.crypto.keychain

import arrow.core.Either
import de.spree.keycloak.commons.*
import de.spree.keycloak.crypto.IV_SIZE
import de.spree.keycloak.crypto.setupBouncyCastle
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.time.LocalDateTime
import java.time.temporal.ChronoUnit.SECONDS

/** Length of GCM key ID in bytes (UUID) */
const val KEYCHAIN_ID_SIZE = UUID_SIZE

const val AAD_SIZE = 16 // 128 Bits

const val GCM_KEY_SIZE = 32 // 256 bit precision

const val KEYCHAIN_SIZE = KEYCHAIN_ID_SIZE + LOCALDATETIME_SIZE + KEYPAIR_SIZE + GCM_KEY_SIZE + AAD_SIZE

object KeychainUtil {
  private val secureRandom = SecureRandom()

  init {
    setupBouncyCastle()
  }

  /**
   * Generate a cryptographically secure nonce/IV.
   *
   * @param sizeBytes Number of bytes to generate. Defaults to [IV_SIZE].
   * @return Byte array filled with cryptographically secure random bytes.
   */
  fun generateDataBytes(sizeBytes: Int = IV_SIZE) = ByteArray(sizeBytes).also { secureRandom.nextBytes(it) }
}

fun currentTime(): LocalDateTime = LocalDateTime.now().truncatedTo(SECONDS)

fun Keychain.serialize() = (keychainId.toByteArray() + creationDate.toByteArray() + signingKeyPair.toByteArray() + gcmEncryptionKey + gcmAad)

fun ByteArray.toKeychain(): Either<Throwable, Keychain> =
    Either.catch {
      val buffer = ByteBuffer.wrap(this)

      check(buffer.remaining() == KEYCHAIN_SIZE) { "Expected $KEYCHAIN_SIZE bytes, got ${buffer.remaining()}" }

      val keychainId = buffer.getBytes(KEYCHAIN_ID_SIZE).toUUID()
      val creationDate = buffer.getBytes(LOCALDATETIME_SIZE).toLocalDateTime()
      val signingKeyPair = buffer.getBytes(KEYPAIR_SIZE).toKeyPair()
      val gcmEncryptionKey = buffer.getBytes(GCM_KEY_SIZE)
      val gcmAad = buffer.getBytes(AAD_SIZE)

      Keychain(keychainId, creationDate, signingKeyPair, gcmEncryptionKey, gcmAad)
    }
