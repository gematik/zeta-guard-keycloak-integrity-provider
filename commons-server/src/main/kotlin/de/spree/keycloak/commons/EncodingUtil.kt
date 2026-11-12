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
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneOffset
import java.time.temporal.ChronoUnit.SECONDS
import java.util.*
import org.keycloak.common.util.Base64Url

/** The number of bytes in the hash output, which is 32 for SHA-256. */
const val HASH_SIZE = 32

/** The number of bytes for a UUID */
const val UUID_SIZE = 16

const val LOCALDATETIME_SIZE = 8 // Long

typealias BASE64 = String

/** Converts a ByteArray to a Base64 URL-safe encoded string. */
fun ByteArray.toBase64(): BASE64 = Base64Url.encode(this)

/** Decodes a Base64 URL-safe encoded string back to a ByteArray. */
fun BASE64.fromBase64(): ByteArray = Base64Url.decode(this)

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

fun LocalDateTime.toByteArray(): ByteArray =
    ByteBuffer.allocate(LOCALDATETIME_SIZE).apply { putLong(toInstant(ZoneOffset.UTC).truncatedTo(SECONDS).epochSecond) }.array()

fun ByteArray.toLocalDateTime(): LocalDateTime {
  require(size == LOCALDATETIME_SIZE) { "Expected $LOCALDATETIME_SIZE bytes, got $size" }

  val seconds = ByteBuffer.wrap(this).long

  return LocalDateTime.ofInstant(Instant.ofEpochSecond(seconds), ZoneOffset.UTC)
}
