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
import de.spree.keycloak.commons.BASE64
import de.spree.keycloak.commons.SimpleSuccess
import de.spree.keycloak.commons.Success
import de.spree.keycloak.commons.catchAll
import de.spree.keycloak.crypto.keychain.CurrentKeychain
import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import java.security.Signature
import org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME

const val ECDSA_SIGNATURE_ALGORITHM = "SHA256WithECDSA"

/** Service to sign and verify given data */
@ApplicationScoped
class SigningService {
  @Inject //
  private lateinit var currentKeychain: CurrentKeychain

  /**
   * Signs the given data using SHA256withECDSA.
   *
   * @param data The byte array to sign.
   * @return The signature as a byte array.
   */
  fun sign(data: ByteArray): Either<Throwable, ByteArray> = either {
    val signer = Signature.getInstance(ECDSA_SIGNATURE_ALGORITHM, PROVIDER_NAME)
    val keychain = currentKeychain.keychain().bind()

    catchAll {
      signer.initSign(keychain.signingKeyPair.private)
      signer.update(data)

      signer.sign()
    }
  }

  /**
   * Verifies the signature of the given data using the public key.
   *
   * @param entity The entity (representation) that was signed.
   * @param data The data that was signed.
   * @param signature The signature to verify.
   * @return true if the signature is valid, false otherwise.
   */
  fun verify(entity: String, data: ByteArray, signature: ByteArray): Either<Throwable, Success> = either {
    val verifier = Signature.getInstance(ECDSA_SIGNATURE_ALGORITHM, PROVIDER_NAME)
    val keychain = currentKeychain.keychain().bind()
    val success = catchAll {
      verifier.initVerify(keychain.signingKeyPair.public)
      verifier.update(data)

      verifier.verify(signature)
    }

    ensure(success) { RuntimeException("Signature verification failed for entity $entity") }

    SimpleSuccess
  }

  companion object {
    init {
      setupBouncyCastle()
    }
  }
}

typealias DBChecksum = BASE64

/**
 * Data class representing the ciphertext produced by the signing operation. It contains the keychain ID (to identify which key was used for
 * encryption), hash and the signature.
 */
data class Checksum(val keychainId: ByteArray, val hash: ByteArray, val signature: ByteArray) {
  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is Checksum) return false

    if (!hash.contentEquals(other.hash)) return false
    if (!signature.contentEquals(other.signature)) return false

    return true
  }

  override fun hashCode(): Int {
    var result = hash.contentHashCode()
    result = 31 * result + signature.contentHashCode()
    return result
  }
}
