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
package de.spree.keycloak.crypto.muhash

import de.spree.keycloak.crypto.MultiHash
import org.bouncycastle.crypto.digests.SHAKEDigest
import java.math.BigInteger

private const val SIZE = 3072 / 8
private val PRIME_3072 = BigInteger(
	"""
		|FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1
		|29024E088A67CC74020BBEA63B139B22514A08798E3404DD
		|EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245
		|E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED
		|EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D
		|C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F
		|83655D23DCA3AD961C62F356208552BB9ED529077096966D
		|670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B
		|E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9
		|DE2BCBF6955817183995497CEA956AE515D2261898FA0510
		|15728E5A8AACAA68FFFFFFFFFFFFFFFF""".trimMargin().replace("\n", ""), 16
)

private val EMPTY = MuHash3072().current()

/**
 * MultiHash implementation based on the MuHash algorithm, using the
 * official 3072-Bit-Safe-Prime (RFC 3526, Group 15) as modulus.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc3526#page-4">(RFC 3526</a>
 *
 * It is guaranteed to fulfill: p = 2q + 1 where q is a prime number, too.
 */
class MuHash3072(): MultiHash {
	private var numerator = BigInteger.ONE
	private var denominator = BigInteger.ONE

	/**
	 * Create a new instance from a previous [current] result.
	 */
	constructor(initialHash: ByteArray) : this() {
		init(initialHash)
	}

	/**
	 * Initialize this instance from a previous [current] result.
	 */
	override fun init(initialHash: ByteArray): MultiHash {
		numerator = BigInteger(initialHash)
		denominator = BigInteger.ONE
		return this
	}

	/**
	 * Create a new instance by copying this ones' current state.
	 */
	override fun copy(): MuHash3072 {
		val copy = MuHash3072()
		copy.numerator = this.numerator
		copy.denominator = this.denominator
		return copy
	}

	/**
	 * Adds an element to the multi set (multiplies numerator)
	 */
	override fun insert(data: ByteArray): MuHash3072 {
		numerator = numerator.multiply(data.asBigInteger()).mod(PRIME_3072)
		return this
	}

	/**
	 * Removes an element from the multi set (multiplies denominator)
	 */
	override fun remove(data: ByteArray): MuHash3072 {
		denominator = denominator.multiply(data.asBigInteger()).mod(PRIME_3072)
		return this
	}

	/**
	 * Computes the current hash value of the multi set.
	 *
	 * Modular division (numerator * Inverse (i.e. x^-1) of Denominator)
	 */
	override fun current(): ByteArray {
		val inverseDenominator = denominator.modInverse(PRIME_3072)

		return numerator.multiply(inverseDenominator).mod(PRIME_3072).toByteArray()
	}

	/**
	 * Indicates if the multi set is empty.
	 */
	override fun isEmpty(): Boolean {
		return EMPTY.contentEquals(current())
	}

	private fun ByteArray.asBigInteger(): BigInteger {
		val buffer = ByteArray(SIZE)
		val digest = SHAKEDigest()
		digest.update(this, 0, size)
		digest.doFinal(buffer, 0, SIZE)
		return BigInteger(1, buffer).mod(PRIME_3072).add(BigInteger.ONE)
	}
}