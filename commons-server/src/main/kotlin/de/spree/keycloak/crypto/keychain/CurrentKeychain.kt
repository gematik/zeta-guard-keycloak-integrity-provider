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
package de.spree.keycloak.crypto.keychain

import arrow.core.Either
import arrow.core.raise.either
import de.spree.keycloak.commons.*
import de.spree.keycloak.commons.configuration.SystemStatus
import de.spree.keycloak.commons.configuration.SystemStatusService
import de.spree.keycloak.crypto.HSMCryptoService
import de.spree.keycloak.crypto.decrypt
import io.quarkus.runtime.Startup
import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import java.io.File

/** Singleton object holding the current encryption-related data */
@ApplicationScoped
@Startup
open class CurrentKeychain {
  @Inject //
  private lateinit var hsmCryptoService: HSMCryptoService

  @Inject //
  private lateinit var systemStatusService: SystemStatusService

  private val keychain: Either<Throwable, Keychain> by lazy {
    loadKeychain().onLeft {
      systemStatusService.setSystemStatus(SystemStatus.ERROR_HSM, it)
      logger.fatal("💣 Failed to load keychain", it)
    }
  }

  open fun keychain(): Either<Throwable, Keychain> = keychain

  private fun loadKeychain(): Either<Throwable, Keychain> = either {
    fun retrieveDataFromEnvironment(): Triple<ByteArray, ByteArray, ByteArray> {
      val encryptedKeychain = safeGetenv(ENV_KEYCHAIN_DATA).bind().fromBase64()
      val encryptedKey = safeGetenv(ENV_KEYCHAIN_KEY).bind().fromBase64()
      val hsmAad = safeGetenv(ENV_HSM_AAD).bind().fromBase64()

      return Triple(encryptedKeychain, encryptedKey, hsmAad)
    }

    fun retrieveDataFromFile(path: String): Triple<ByteArray, ByteArray, ByteArray> {
      val configurationMap = File(path).readLines().map { it.trim().split("=") }.filter { it.size == 2 }.associate { it[0] to it[1].trim('"') }

      val encryptedKeychain = configurationMap[ENV_KEYCHAIN_DATA]?.fromBase64() ?: raise(missing(ENV_KEYCHAIN_DATA))
      val encryptedKey = configurationMap[ENV_KEYCHAIN_KEY]?.fromBase64() ?: raise(missing(ENV_KEYCHAIN_KEY))
      val hsmAad = configurationMap[ENV_HSM_AAD]?.fromBase64() ?: raise(missing(ENV_HSM_AAD))

      return Triple(encryptedKeychain, encryptedKey, hsmAad)
    }

    val (encryptedKeychain, encryptedKey, hsmAad) =
        safeGetenv(ENV_KEYCHAIN_FILE).fold(ifLeft = { retrieveDataFromEnvironment() }, ifRight = { retrieveDataFromFile(it) })
    val key = hsmCryptoService.decrypt(ciphertext = encryptedKey, aad = hsmAad).bind()
    val decryptedKeychain = encryptedKeychain.decrypt(key, hsmAad).bind()

    decryptedKeychain.toKeychain().bind()
  }

  private fun missing(name: String) = IllegalStateException("Missing »$name« in keychain file")
}
