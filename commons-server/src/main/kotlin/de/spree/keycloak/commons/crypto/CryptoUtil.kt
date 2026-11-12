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
import de.spree.keycloak.commons.*
import de.spree.keycloak.commons.crypto.keychain.GCM_KEY_SIZE
import de.spree.keycloak.commons.crypto.keychain.KEYCHAIN_ID_SIZE
import de.spree.keycloak.commons.crypto.keychain.KeychainUtil.generateDataBytes
import org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME
import java.nio.ByteBuffer
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

typealias DBCipherText = BASE64

/** Convert the binary ciphertext to the database representation (VARCHAR) */
fun CipherText.toDatabaseRepresentation(): DBCipherText = (keychainId + nonce + encrypted).toBase64()

/** Inverse operation to read the binary ciphertext object from a String. Note that this requires to use fixed-length subsequent byte arrays. */
fun DBCipherText.toCipherText(): Either<Throwable, CipherText> =
	Either.catch {
		val buffer = ByteBuffer.wrap(fromBase64())
		val keychainId = buffer.getBytes(KEYCHAIN_ID_SIZE)
		val nonce = buffer.getBytes(IV_SIZE)
		val ciphertext = buffer.getBytes(buffer.remaining())

		CipherText(keychainId, nonce, ciphertext)
	}

/** Convert the binary checksum to the database representation (VARCHAR) */
fun Checksum.toDatabaseRepresentation(): DBChecksum = (keychainId + hash).toBase64()

/** Inverse operation to read the binary checksum object from a String. Note that this requires to use fixed-length subsequent byte arrays. */
fun DBChecksum.toChecksum(): Either<Throwable, Checksum> =
	Either.catch {
		val buffer = ByteBuffer.wrap(fromBase64())
		val keychainId = buffer.getBytes(KEYCHAIN_ID_SIZE)
		check(buffer.remaining() >= HASH_SIZE) { "Hash must be at least $HASH_SIZE bytes long, but was ${buffer.remaining()}" }
		val hash = buffer.getBytes(buffer.remaining())

		Checksum(keychainId, hash)
	}

/** Inverse operation to read the binary hash of a [MultiChecksumResult] from a String. */
fun DBHash.toHash(): Either<Throwable, ByteArray> = Either.catch { fromBase64() }

fun ByteArray.encrypt(key: ByteArray): Either<Throwable, ByteArray> =
	Either.catch {
		check(key.size == GCM_KEY_SIZE) { "Key must be $GCM_KEY_SIZE bytes long, but was ${key.size}" }

		val iv = generateDataBytes(IV_SIZE)
		val spec = GCMParameterSpec(TAG_SIZE_BITS, iv)
		val cipher =
			Cipher.getInstance(ALGORITHM, PROVIDER_NAME).apply {
				init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), spec)
			}

		val ciphertext = cipher.doFinal(this)

		iv + ciphertext
	}

fun ByteArray.decrypt(key: ByteArray): Either<Throwable, ByteArray> =
	Either.catch {
		check(key.size == GCM_KEY_SIZE) { "Key must be $GCM_KEY_SIZE bytes long, but was ${key.size}" }

		val buffer = ByteBuffer.wrap(this)
		val iv = buffer.getBytes(IV_SIZE)
		val ciphertext = buffer.getBytes(buffer.remaining())
		val spec = GCMParameterSpec(TAG_SIZE_BITS, iv)
		val cipher =
			Cipher.getInstance(ALGORITHM, PROVIDER_NAME).apply {
				init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), spec)
			}

		cipher.doFinal(ciphertext)
	}

fun hmac(key: ByteArray, vararg data: ByteArray): Either<Throwable, ByteArray> = Either.catch {
	val mac = Mac.getInstance(HMAC_ALGORITHM, PROVIDER_NAME)
	val secretKeySpec = SecretKeySpec(key, HMAC_ALGORITHM)

	mac.init(secretKeySpec)
	data.forEach(mac::update)
	mac.doFinal()
}
