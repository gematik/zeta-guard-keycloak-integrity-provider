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
@file:Suppress("unused")

package de.spree.keycloak.commons.crypto

import arrow.core.Either
import arrow.core.raise.either
import de.spree.keycloak.commons.crypto.keychain.AAD_SIZE
import de.spree.keycloak.commons.crypto.keychain.GCM_KEY_SIZE
import de.spree.keycloak.commons.crypto.keychain.Keychain
import de.spree.keycloak.commons.crypto.keychain.KeychainBundle
import de.spree.keycloak.commons.crypto.keychain.KeychainUtil
import de.spree.keycloak.commons.toByteArray
import io.quarkus.runtime.Startup
import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.modes.GCMBlockCipher
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter

const val ALGORITHM = "AES/GCM/NoPadding"

/** NIST-recommended IV size for AES-GCM (12 bytes / 96 bits). */
const val IV_SIZE = 12

/** NIST-recommended Authentication tag length in bits used for AES-GCM (128 bits). */
const val TAG_SIZE_BITS = 128

/**
 * Utility class performing AES-GCM encryption and decryption with a provided key and AAD. The implementation uses Bouncy Castle's low-level cipher
 * API (GCMBlockCipher with AESEngine).
 *
 * The instance holds a symmetric key and associated additional data (AAD). Encryption will produce a byte array containing the nonce/IV followed by
 * the ciphertext and authentication tag. Decryption expects the same format.
 */
@ApplicationScoped
@Startup // Enforce creation at startup, thus the bean will be available using CDI.current()
class CryptoService {
	@Inject //
	private lateinit var keychainBundle: KeychainBundle

	/**
	 * Encrypts the given plaintext using AES-GCM with the provided nonce.
	 *
	 * @param plaintext Bytes to encrypt.
	 * @param nonce IV/nonce to use for this encryption operation. Must be `IV_SIZE_BYTES` long (recommended 12 bytes).
	 * @return ciphertext-with-tag.
	 */
	fun encrypt(plaintext: ByteArray, nonce: ByteArray): Either<Throwable, CipherText> = either {
		encrypt(keychainBundle.currentKeychain(), plaintext, nonce).bind()
	}

	/**
	 * Decrypts a byte array produced by [encrypt].
	 *
	 * @param ciphertext Encrypted text
	 * @return Decrypted plaintext bytes.
	 */
	fun decrypt(ciphertext: CipherText): Either<Throwable, ByteArray> = either {
		val keychain = keychainBundle.retrieveKeychain(ciphertext.keychainId).bind()

		decrypt(ciphertext, keychain.gcmEncryptionKey, keychain.gcmAad).bind()
	}

	internal fun encrypt(keychain: Keychain, plaintext: ByteArray, nonce: ByteArray): Either<Throwable, CipherText> =
		Either.catch {
			check(keychain.gcmAad.size == AAD_SIZE) { "AAD must be ${AAD_SIZE} bytes long, but was ${keychain.gcmAad.size}" }
			check(keychain.gcmEncryptionKey.size == GCM_KEY_SIZE) { "Key must be ${GCM_KEY_SIZE} long, but was ${keychain.gcmEncryptionKey.size}" }
			check(nonce.size == IV_SIZE) { "Nonce must be $IV_SIZE bytes long, but was ${nonce.size}" }

			val cipher = GCMBlockCipher.newInstance(AESEngine.newInstance())
			val parameters = AEADParameters(KeyParameter(keychain.gcmEncryptionKey), TAG_SIZE_BITS, nonce, keychain.gcmAad)

			cipher.init(true, parameters)

			val encrypted = ByteArray(cipher.getOutputSize(plaintext.size))
			val len = cipher.processBytes(plaintext, 0, plaintext.size, encrypted, 0)

			cipher.doFinal(encrypted, len)

			CipherText(keychain.keychainId.toByteArray(), nonce, encrypted)
		}

	private fun decrypt(ciphertext: CipherText, key: ByteArray, aad: ByteArray): Either<Throwable, ByteArray> =
		Either.catch {
			val cipher = GCMBlockCipher.newInstance(AESEngine.newInstance())
			val parameters = AEADParameters(KeyParameter(key), TAG_SIZE_BITS, ciphertext.nonce, aad)

			cipher.init(false, parameters)

			val encrypted = ciphertext.encrypted
			val output = ByteArray(cipher.getOutputSize(encrypted.size))
			val len = cipher.processBytes(encrypted, 0, encrypted.size, output, 0)
			val finalLen = cipher.doFinal(output, len)

			output.copyOf(len + finalLen)
		}

	fun encrypt(attribute: String): Either<Throwable, DBCipherText> = either {
		val nonce = KeychainUtil.generateDataBytes()
		val ciphertext = encrypt(attribute.toByteArray(), nonce).bind()

		ciphertext.toDatabaseRepresentation()
	}

	fun decrypt(dbData: String): Either<Throwable, String> = either {
		val ciphertext = dbData.toCipherText().bind()
		val decrypted = decrypt(ciphertext).bind()

		String(decrypted)
	}

	/**
	 * Checks whether [dbData] already is a ciphertext produced by [encrypt], i.e. whether it carries a known keychain ID and authenticates against
	 * the corresponding key. Used to keep encryption idempotent: encrypting an already encrypted value would render it unreadable.
	 */
	fun isEncrypted(dbData: String): Boolean = decrypt(dbData).isRight()

	fun getCurrentKeychainId() = keychainBundle.currentKeychain().keychainId

	fun hasPreviousKeychain() = keychainBundle.previousKeychain().isValid()

	fun hasFutureKeychain() = keychainBundle.futureKeychain().isValid()
}

/**
 * Data class representing the ciphertext produced by the encryption operation. It contains the keychain ID (to identify which key was used for
 * encryption), the nonce/IV, and the encrypted data (which includes the authentication tag).
 */
data class CipherText(val keychainId: ByteArray, val nonce: ByteArray, val encrypted: ByteArray) {
	override fun equals(other: Any?): Boolean {
		if (this === other) return true
		if (other !is CipherText) return false

		if (!keychainId.contentEquals(other.keychainId)) return false
		if (!nonce.contentEquals(other.nonce)) return false
		if (!encrypted.contentEquals(other.encrypted)) return false

		return true
	}

	override fun hashCode(): Int {
		var result = keychainId.contentHashCode()
		result = 31 * result + nonce.contentHashCode()
		result = 31 * result + encrypted.contentHashCode()
		return result
	}
}
