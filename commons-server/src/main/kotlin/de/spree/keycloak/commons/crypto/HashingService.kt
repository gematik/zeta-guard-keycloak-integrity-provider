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
package de.spree.keycloak.commons.crypto

import arrow.core.Either
import arrow.core.raise.either
import arrow.core.raise.ensure
import de.spree.keycloak.commons.BASE64
import de.spree.keycloak.commons.SimpleSuccess
import de.spree.keycloak.commons.Success
import de.spree.keycloak.commons.toByteArray
import de.spree.keycloak.commons.crypto.keychain.Keychain
import de.spree.keycloak.commons.crypto.keychain.KeychainBundle
import de.spree.keycloak.commons.crypto.muhash.MuHash3072
import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject

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
	 * Hashes data via HMAC-SHA256 with a given keychain ID.
	 *
	 * @param keychainId The keychain ID to use for hashing
	 * @param data The byte arrays to hash.
	 * @return The hash as a byte array.
	 */
	fun hashWith(keychainId: ByteArray, vararg data: ByteArray): Either<Throwable, Checksum> = either {
		val keychain = keychainBundle.retrieveKeychain(keychainId).bind()
		val hash = hashInternal(keychain, *data).bind()
		Checksum(keychain.keychainId.toByteArray(), hash)
	}

	/**
	 * Verifies the hash of the given data against an expected checksum.
	 * Only used for testing.
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
	 * Begins a chain of operations on a [MultiChecksum], optionally starting with a previous [MultiChecksumResult].
	 *
	 * The previous hash and checksum must be given both or not at all. If given, the checksum is verified to be the HMAC of the hash,
	 * using the keychain it was created with. Otherwise, the chain starts empty.
	 *
	 * @param previousHash a hash value previously returned by [finish] to start with.
	 * @param previousChecksum the checksum previously returned by [finish] along with [previousHash].
	 */
	fun init(previousHash: ByteArray? = null, previousChecksum: Checksum? = null): Either<Throwable, MultiChecksum> = either {
		ensure((previousHash == null) == (previousChecksum == null)) {
			IllegalArgumentException("Previous hash and checksum must be given both or not at all")
		}

		if (previousHash != null && previousChecksum != null) {
			val keychain = keychainBundle.retrieveKeychain(previousChecksum.keychainId).bind()
			val expected = hashInternal(keychain, previousHash).bind()

			ensure(expected.contentEquals(previousChecksum.hash)) { RuntimeException("HMAC verification failed for previous multi checksum") }

			MultiChecksum(keychain, Either.catch { MuHash3072(previousHash) }.bind())
		} else {
			MultiChecksum(keychainBundle.currentKeychain(), MuHash3072())
		}
	}

	/**
	 * Insert a value into a given [MultiChecksum].
	 *
	 * @param checksum the checksum to update
	 * @param data the data item to insert
	 */
	fun insert(checksum: MultiChecksum, vararg data: ByteArray): Either<Throwable, MultiChecksum> = Either.catch {
		data.forEach(checksum.hash::insert)
		checksum
	}

	/**
	 * Remove a value from a given [MultiChecksum].
	 *
	 * @param checksum the checksum to update
	 * @param data the data item to remove
	 */
	fun remove(checksum: MultiChecksum, vararg data: ByteArray): Either<Throwable, MultiChecksum> = Either.catch {
		data.forEach(checksum.hash::remove)
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
	 * Finish a chain of operations on a [MultiChecksum], yielding the resulting hash and a fresh HMAC over it.
	 * The HMAC always uses the current keychain, regardless of the keychain of a previous checksum passed to [init].
	 *
	 * @param checksum the checksum to finalize.
	 */
	fun finish(checksum: MultiChecksum): Either<Throwable, MultiChecksumResult> = either {
		val hash = Either.catch { checksum.hash.current() }.bind()
		val keychain = keychainBundle.currentKeychain()
		val mac = hashInternal(keychain, hash).bind()

		MultiChecksumResult(hash, Checksum(keychain.keychainId.toByteArray(), mac))
	}

	/**
	 * Finish a chain of operations on a [MultiChecksum] and verify the expected checksum is the HMAC of the resulting hash.
	 * The expected checksum may use a different keychain than [actual].
	 *
	 * @param entity the name of entity values used in the checksum
	 * @param actual the current checksum
	 * @param expected the expected checksum to compare against
	 */
	fun verify(entity: String, actual: MultiChecksum, expected: Checksum): Either<Throwable, Success> = either {
		val hash = Either.catch { actual.hash.current() }.bind()
		verify(entity, expected, hash).bind()
	}

	private fun hashInternal(keychain: Keychain, vararg data: ByteArray): Either<Throwable, ByteArray> =
		hmac(keychain.hmacKey, *data)

	companion object {
		init {
			setupBouncyCastle()
		}
	}
}

typealias DBChecksum = BASE64
typealias DBHash = BASE64

/**
 * Data class representing the checksum produced by the hashing operation. It contains the keychain ID (to identify
 * which key was used for MAC calculation), and the resulting MAC itself.
 */
data class Checksum(val keychainId: ByteArray, val hash: ByteArray) {
	override fun equals(other: Any?): Boolean {
		if (this === other) return true
		if (other !is Checksum) return false

		return hash.contentEquals(other.hash)
	}

	override fun hashCode(): Int = hash.contentHashCode()
}

/**
 * Accumulator of a [MultiChecksum] during various update operations.
 */
data class MultiChecksum(internal val keychain: Keychain, internal val hash: MultiHash)

/**
 * Result of [HashingService.finish]: the (unkeyed) multiset hash, used to continue later via [HashingService.init],
 * and the [Checksum] authenticating it.
 */
data class MultiChecksumResult(val hash: ByteArray, val checksum: Checksum) {
	override fun equals(other: Any?): Boolean {
		if (this === other) return true
		if (other !is MultiChecksumResult) return false

		return hash.contentEquals(other.hash) && checksum == other.checksum
	}

	override fun hashCode(): Int = hash.contentHashCode() * 31 + checksum.hashCode()
}