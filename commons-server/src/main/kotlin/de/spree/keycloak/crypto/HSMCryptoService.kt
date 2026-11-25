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
import arrow.core.getOrElse
import de.gematik.zetaguard.hsmproxy.HsmCrypto
import de.spree.keycloak.commons.ENV_HSM_PROXY_ENDPOINT
import de.spree.keycloak.commons.eitherGetEnvironment
import io.quarkus.runtime.Startup
import jakarta.enterprise.context.ApplicationScoped

@ApplicationScoped
@Startup
class HSMCryptoService {
  private val crypto: HsmCrypto by lazy { HsmCrypto(endpoint()) }

  fun encrypt(plaintext: ByteArray): Either<Throwable, ByteArray> = Either.catch { crypto.encrypt(plaintext = plaintext) }

  fun decrypt(ciphertext: ByteArray): Either<Throwable, ByteArray> = Either.catch { crypto.decrypt(data = ciphertext) }
}

private fun endpoint(): String = eitherGetEnvironment(ENV_HSM_PROXY_ENDPOINT).getOrElse { throw it }
