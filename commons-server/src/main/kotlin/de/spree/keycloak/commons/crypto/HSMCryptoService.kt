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
import arrow.core.getOrElse
import de.gematik.zetaguard.hsmproxy.HsmCrypto
import de.spree.keycloak.commons.ENV_HSM_PROXY_ENDPOINT
import de.spree.keycloak.commons.eitherGetEnvironment
import io.quarkus.runtime.Startup
import jakarta.annotation.PreDestroy
import jakarta.enterprise.context.ApplicationScoped

private val noAAD = ByteArray(0)

@ApplicationScoped
@Startup
class HSMCryptoService {
  // Kept separately to check whether the client (and its gRPC channel) was ever created
  private val cryptoDelegate = lazy { HsmCrypto(endpoint()) }
  private val crypto: HsmCrypto by cryptoDelegate

  fun encrypt(plaintext: ByteArray, keyId: String): Either<Throwable, ByteArray> = Either.catch {
    crypto.encrypt(plaintext = plaintext, aad = noAAD, keyId = keyId)
  }

  fun decrypt(ciphertext: ByteArray, keyId: String): Either<Throwable, ByteArray> = Either.catch {
    crypto.decrypt(data = ciphertext, aad = noAAD, keyId = keyId)
  }

  /** Shuts down the gRPC channel to the HSM proxy, if it was opened at all. */
  @PreDestroy
  internal fun shutdown() {
    if (cryptoDelegate.isInitialized()) crypto.close()
  }
}

/**
 * Runs [block] with a temporary [HSMCryptoService] outside of CDI, e.g. in database migrations, and shuts it down afterward.
 * Within CDI, inject the application-scoped service instead.
 */
fun <T> withStandaloneHSMCryptoService(block: (HSMCryptoService) -> T): T {
  val hsmCryptoService = HSMCryptoService()

  try {
    return block(hsmCryptoService)
  } finally {
    hsmCryptoService.shutdown()
  }
}

private fun endpoint(): String = eitherGetEnvironment(ENV_HSM_PROXY_ENDPOINT).getOrElse { throw it }
