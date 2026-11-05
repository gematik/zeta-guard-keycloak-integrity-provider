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
package de.spree.keycloak.commons.crypto.muhash

import de.spree.keycloak.commons.crypto.MultiHash
import org.bouncycastle.crypto.digests.SHAKEDigest
import java.math.BigInteger

private const val SIZE = 3072 / 8
private val PRIME_3072 = BigInteger(
	"""
		|FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
    |29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
    |EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
    |E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
    |EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
    |C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
    |83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
    |670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
    |E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
    |DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
    |15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64
    |ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7
    |ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B
    |F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
    |BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31
    |43DB5BFC E0FD108E 4B82D120 A93AD2CA FFFFFFFF FFFFFFFF""".trimMargin()
    .replace("\n", "")
    .replace(" ", "")
  , 16
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