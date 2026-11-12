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
import arrow.core.getOrElse
import arrow.core.raise.either
import arrow.core.recover
import de.spree.keycloak.commons.*
import de.spree.keycloak.commons.crypto.HSMCryptoService
import de.spree.keycloak.commons.crypto.IV_SIZE
import de.spree.keycloak.commons.crypto.decrypt
import de.spree.keycloak.commons.crypto.setupBouncyCastle
import java.io.File
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.time.LocalDateTime
import java.time.temporal.ChronoUnit.SECONDS

/** Length of GCM key ID in bytes (UUID) */
const val KEYCHAIN_ID_SIZE = UUID_SIZE

const val AAD_SIZE = 16 // 128 Bits

const val GCM_KEY_SIZE = 32 // 256 bit precision
const val HMAC_KEY_SIZE = 32 // 256 bit precision

const val KEYCHAIN_SIZE = KEYCHAIN_ID_SIZE + LOCALDATETIME_SIZE + HMAC_KEY_SIZE + GCM_KEY_SIZE + AAD_SIZE

internal val INVALID_UUID = ByteArray(UUID_SIZE)
internal val INVALID_KEYCHAIN = ByteArray(KEYCHAIN_SIZE).toKeychain().getOrElse { error("Could not create empty Keychain") } // keychainID is INVALID_UUID

enum class KeychainType {
  FUTURE,
  CURRENT,
  PREVIOUS
}

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

fun Keychain.serialize() = (keychainId.toByteArray() + creationDate.toByteArray() + hmacKey + gcmEncryptionKey + gcmAad)

fun ByteArray.toKeychain(): Either<Throwable, Keychain> =
    Either.catch {
      val buffer = ByteBuffer.wrap(this)

      check(buffer.remaining() == KEYCHAIN_SIZE) { "Expected $KEYCHAIN_SIZE bytes, got ${buffer.remaining()}" }

      val keychainId = buffer.getBytes(KEYCHAIN_ID_SIZE).toUUID()
      val creationDate = buffer.getBytes(LOCALDATETIME_SIZE).toLocalDateTime()
      val hmacKey = buffer.getBytes(HMAC_KEY_SIZE)
      val gcmEncryptionKey = buffer.getBytes(GCM_KEY_SIZE)
      val gcmAad = buffer.getBytes(AAD_SIZE)

      Keychain(keychainId, creationDate, hmacKey, gcmEncryptionKey, gcmAad)
    }

fun loadKeychain(hsmCryptoService: HSMCryptoService, type: KeychainType): Either<Throwable, Keychain> = either {
  fun retrieveDataFromEnvironment(): Triple<ByteArray, ByteArray, String> {
    val encryptedKeychain = eitherGetEnvironment(type.keychainDataEnv()).bind().fromBase64()
    val encryptedKey = eitherGetEnvironment(type.keychainKeyEnv()).bind().fromBase64()
    val hsmKeyId = eitherGetEnvironment(type.keychainKekIdEnv())
      .recover { eitherGetEnvironment(ENV_HSM_PROXY_KEK_ID).bind() }.bind()
    return Triple(encryptedKeychain, encryptedKey, hsmKeyId)
  }

  fun retrieveDataFromFile(path: String): Triple<ByteArray, ByteArray, String> {
    val configurationMap = File(path).readLines().map { it.trim().split("=") }.filter { it.size == 2 }.associate { it[0] to it[1].trim('"') }
    val encryptedKeychain = configurationMap[ENV_KEYCHAIN_DATA]?.fromBase64() ?: raise(missing(ENV_KEYCHAIN_DATA))
    val encryptedKey = configurationMap[ENV_KEYCHAIN_KEY]?.fromBase64() ?: raise(missing(ENV_KEYCHAIN_KEY))
    val hsmKeyId = configurationMap[ENV_KEYCHAIN_KEK_ID] ?: eitherGetEnvironment(ENV_HSM_PROXY_KEK_ID).bind()
    return Triple(encryptedKeychain, encryptedKey, hsmKeyId)
  }

  val (encryptedKeychain, encryptedKey, hsmKeyId) = eitherGetEnvironment(type.keychainFileEnv())
    .fold(ifLeft = { retrieveDataFromEnvironment() }, ifRight = { retrieveDataFromFile(it) })
  val key = hsmCryptoService.decrypt(ciphertext = encryptedKey, keyId = hsmKeyId).bind()
  val decryptedKeychain = encryptedKeychain.decrypt(key).bind()

  decryptedKeychain.toKeychain().bind()
}

private fun missing(name: String) = IllegalStateException("Missing »$name« in keychain file")

private fun KeychainType.keychainDataEnv(): String = when (this) {
  KeychainType.FUTURE -> ENV_FUTURE_KEYCHAIN_DATA
  KeychainType.CURRENT -> ENV_KEYCHAIN_DATA
  KeychainType.PREVIOUS -> ENV_PREVIOUS_KEYCHAIN_DATA
}

private fun KeychainType.keychainKeyEnv(): String = when (this) {
  KeychainType.FUTURE -> ENV_FUTURE_KEYCHAIN_KEY
  KeychainType.CURRENT -> ENV_KEYCHAIN_KEY
  KeychainType.PREVIOUS -> ENV_PREVIOUS_KEYCHAIN_KEY
}

private fun KeychainType.keychainFileEnv(): String = when (this) {
  KeychainType.FUTURE -> ENV_FUTURE_KEYCHAIN_FILE
  KeychainType.CURRENT -> ENV_KEYCHAIN_FILE
  KeychainType.PREVIOUS -> ENV_PREVIOUS_KEYCHAIN_FILE
}

private fun KeychainType.keychainKekIdEnv(): String = when (this) {
  KeychainType.FUTURE -> ENV_FUTURE_KEYCHAIN_KEK_ID
  KeychainType.CURRENT -> ENV_KEYCHAIN_KEK_ID
  KeychainType.PREVIOUS -> ENV_PREVIOUS_KEYCHAIN_KEK_ID
}
