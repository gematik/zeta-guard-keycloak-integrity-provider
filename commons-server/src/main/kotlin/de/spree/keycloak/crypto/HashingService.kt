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
package de.spree.keycloak.crypto

import arrow.core.Either
import arrow.core.raise.either
import arrow.core.raise.ensure
import arrow.core.right
import de.spree.keycloak.commons.BASE64
import de.spree.keycloak.commons.SimpleSuccess
import de.spree.keycloak.commons.Success
import de.spree.keycloak.commons.toByteArray
import de.spree.keycloak.crypto.keychain.Keychain
import de.spree.keycloak.crypto.keychain.KeychainBundle
import de.spree.keycloak.crypto.muhash.MuHash3072
import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

const val HMAC_ALGORITHM = "HMAC-SHA256"

/** Service to calculate a message authentication code over given data */
@ApplicationScoped
class HashingService {
	@Inject //
	private lateinit var keychainBundle: KeychainBundle

	/**
	 * Hashes given data via HMAC-SHA256.
	 *
	 * @param data The byte arrays to hash.
	 * @return The hash as a byte array.
	 */
	fun hash(vararg data: ByteArray): Either<Throwable, Checksum> = either {
		val keychain = keychainBundle.currentKeychain()
		val hash = hashInternal(keychain, *data).bind()
		Checksum(keychain.keychainId.toByteArray(), hash)
	}

	/**
	 * Verifies the hash of the given data using the public key.
	 *
	 * @param entity The entity (representation) that was hashed.
	 * @param checksum The hash to verify.
	 * @param data The data that was hashed.
	 */
	fun verify(entity: String, checksum: Checksum, vararg data: ByteArray): Either<Throwable, Success> = either {
		val keychain = keychainBundle.retrieveKeychain(checksum.keychainId).bind()
		val actual = hashInternal(keychain, *data).bind()

		ensure(actual.contentEquals(checksum.hash)) { RuntimeException("HMAC verification failed for entity $entity") }

		SimpleSuccess
	}

	/**
	 * Begins a chain of operations on a [MultiChecksum], optionally starting with a previous value.
	 *
	 * @param previous a checksum value to start with.
	 */
	fun init(previous: Checksum? = null): Either<Throwable, MultiChecksum> = either {
		val hash = Either.catch {
			if (previous != null) MuHash3072(previous.hash) else MuHash3072()
		}.bind()

		val keychain = previous?.let {
			keychainBundle.retrieveKeychain(it.keychainId).bind()
		} ?: keychainBundle.currentKeychain()

		return MultiChecksum(keychain, hash).right()
	}

	/**
	 * Insert a value into a given [MultiChecksum].
	 * The data value is hashed using the checksums key before insertion.
	 *
	 * @param checksum the checksum to update
	 * @param data the data item to insert
	 */
	fun insert(checksum: MultiChecksum, vararg data: ByteArray): Either<Throwable, MultiChecksum> = either {
		data.forEach { array ->
			hashInternal(checksum.keychain, array).bind()
				.let { hash -> Either.catch { checksum.hash.insert(hash) }.bind() }
		}
		checksum
	}

	/**
	 * Remove a value from a given [MultiChecksum].
	 * The data value is hashed using the checksums key before removal.
	 *
	 * @param checksum the checksum to update
	 * @param data the data item to remove
	 */
	fun remove(checksum: MultiChecksum, vararg data: ByteArray): Either<Throwable, MultiChecksum> = either {
		data.forEach { array ->
			hashInternal(checksum.keychain, array).bind()
				.let { hash -> Either.catch { checksum.hash.remove(hash) }.bind() }
		}
		checksum
	}

	/**
	 * Check if a [MultiChecksum] represents an empty set.
	 *
	 * @param checksum the checksum to check
	 */
	fun isEmpty(checksum: MultiChecksum): Either<Throwable, Boolean> = Either.catch {
		checksum.hash.isEmpty()
	}

	/**
	 * Finish a chain of operations on a [MultiChecksum], yielding the result.
	 *
	 * @param checksum the checksum to finalize.
	 */
	fun finish(checksum: MultiChecksum): Either<Throwable, Checksum> = Either.catch {
		Checksum(checksum.keychain.keychainId.toByteArray(), checksum.hash.current())
	}

	/**
	 * Finish a chain of operations on a [MultiChecksum] and compare the result to an expected checksum value.
	 *
	 * @param entity the name of entity values used in the checksum
     * @param actual the current checksum
	 * @param expected the expected checksum to compare against
	 */
	fun verify(entity: String, actual: MultiChecksum, expected: Checksum): Either<Throwable, Success> = either {
		val checksum = finish(actual).bind()
		ensure(checksum == expected) { RuntimeException("HMAC verification failed for entity $entity") }
		SimpleSuccess
	}

	internal fun hashInternal(keychain: Keychain, vararg data: ByteArray): Either<Throwable, ByteArray> = Either.catch {
		val mac = Mac.getInstance(HMAC_ALGORITHM, PROVIDER_NAME)
		val secretKeySpec = SecretKeySpec(keychain.hmacKey, HMAC_ALGORITHM)

		mac.init(secretKeySpec)
		data.forEach(mac::update)
		mac.doFinal()
	}

	companion object {
		init {
			setupBouncyCastle()
		}
	}
}

typealias DBChecksum = BASE64

/**
 * Data class representing the checksum produced by the hashing operation. It contains the keychain ID (to identify
 * which key was used for MAC calculation), and the resulting MAC itself.
 */
data class Checksum(val keychainId: ByteArray, val hash: ByteArray) {
	override fun equals(other: Any?): Boolean {
		if (this === other) return true
		if (other !is Checksum) return false

		if (!hash.contentEquals(other.hash)) return false

		return true
	}

	override fun hashCode(): Int = hash.contentHashCode()
}

/**
 * Accumulator of a [MultiChecksum] during various update operations.
 */
data class MultiChecksum(internal val keychain: Keychain, internal val hash: MultiHash) {}