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

import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.KeyPair
import java.security.MessageDigest
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneOffset
import java.time.temporal.ChronoUnit.SECONDS
import java.util.*
import org.bouncycastle.jce.interfaces.ECPrivateKey
import org.bouncycastle.jce.interfaces.ECPublicKey
import org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME
import org.bouncycastle.jce.spec.ECPrivateKeySpec
import org.bouncycastle.jce.spec.ECPublicKeySpec
import org.bouncycastle.util.BigIntegers.asUnsignedByteArray
import org.bouncycastle.util.BigIntegers.fromUnsignedByteArray
import org.keycloak.common.util.Base64Url
import org.keycloak.jose.jwk.ECPublicJWK

/** The digest algorithm used for hashing */
const val DIGEST_ALGORITHM = "SHA3-256"

/** The number of bytes in the hash output, which is 32 for SHA3-256. */
const val HASH_SIZE = 32

/** The number of bytes for a UUID */
const val UUID_SIZE = 16

const val PRIV_KEY_SIZE = 32
const val PUB_KEY_SIZE = 33

const val KEYPAIR_SIZE = PRIV_KEY_SIZE + PUB_KEY_SIZE

const val LOCALDATETIME_SIZE = 8 // Long

typealias BASE64 = String

/** Converts a ByteArray to a Base64 URL-safe encoded string. */
fun ByteArray.toBase64(): BASE64 = Base64Url.encode(this)

/** Decodes a Base64 URL-safe encoded string back to a ByteArray. */
fun BASE64.fromBase64(): ByteArray = Base64Url.decode(this)

/** Computes a hash of the provided byte arrays using the specified digest algorithm. Concatenates all input byte arrays and produces a digest. */
fun toHash(vararg bytes: ByteArray): ByteArray = MessageDigest.getInstance(DIGEST_ALGORITHM).apply { bytes.forEach { update(it) } }.digest()

/** "Read" n bytes from the [ByteBuffer] and return them as a ByteArray. */
fun ByteBuffer.getBytes(count: Int): ByteArray = ByteArray(count).apply { get(this) }

/** Encodes [UUID] into a ByteArray. */
fun UUID.toByteArray(): ByteArray {
  val buffer = ByteBuffer.allocate(UUID_SIZE)
  buffer.putLong(mostSignificantBits)
  buffer.putLong(leastSignificantBits)
  return buffer.array()
}

/** Decodes ByteArray back into UUID. */
fun ByteArray.toUUID(): UUID = ByteBuffer.wrap(this).let { UUID(it.long, it.long) }

/** Encodes [KeyPair] into [ByteArray]. */
fun KeyPair.toByteArray(): ByteArray {
  val publicKeyBytes = (public as ECPublicKey).q.getEncoded(true)
  val privateKeyBytes = asUnsignedByteArray((private as ECPrivateKey).d)

  require(publicKeyBytes.size == PUB_KEY_SIZE) { "Expected compressed public key to be $PUB_KEY_SIZE bytes, got ${publicKeyBytes.size}" }
  require(privateKeyBytes.size == PRIV_KEY_SIZE) { "Expected private key to be $PRIV_KEY_SIZE bytes, got ${privateKeyBytes.size}" }

  return publicKeyBytes + privateKeyBytes
}

/** Decodes ByteArray back into KeyPair. */
fun ByteArray.toKeyPair(): KeyPair {
  require(size == KEYPAIR_SIZE) { "Expected size is $KEYPAIR_SIZE but was $size" }

  val pubBytes = sliceArray(0 until PUB_KEY_SIZE)
  val privBytes = sliceArray(PUB_KEY_SIZE until size)
  val d = fromUnsignedByteArray(privBytes)
  val q = CURVE.curve.decodePoint(pubBytes)
  val keyFactory = KeyFactory.getInstance(ECPublicJWK.EC, PROVIDER_NAME)
  val privSpec = ECPrivateKeySpec(d, EC_SPEC)
  val privateKey = keyFactory.generatePrivate(privSpec)
  val pubSpec = ECPublicKeySpec(q, EC_SPEC)
  val publicKey = keyFactory.generatePublic(pubSpec)

  return KeyPair(publicKey, privateKey)
}

fun LocalDateTime.toByteArray(): ByteArray =
    ByteBuffer.allocate(LOCALDATETIME_SIZE).apply { putLong(toInstant(ZoneOffset.UTC).truncatedTo(SECONDS).epochSecond) }.array()

fun ByteArray.toLocalDateTime(): LocalDateTime {
  require(size == LOCALDATETIME_SIZE) { "Expected $LOCALDATETIME_SIZE bytes, got $size" }

  val seconds = ByteBuffer.wrap(this).long

  return LocalDateTime.ofInstant(Instant.ofEpochSecond(seconds), ZoneOffset.UTC)
}
