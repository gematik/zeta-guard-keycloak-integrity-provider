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
package de.spree.keycloak.crypto.keychaingenerator

import arrow.core.getOrElse
import de.spree.keycloak.commons.crypto.HSMCryptoService
import de.spree.keycloak.commons.crypto.decrypt
import de.spree.keycloak.commons.crypto.keychain.toKeychain
import de.spree.keycloak.commons.crypto.setupBouncyCastle
import de.spree.keycloak.commons.fromBase64
import de.spree.keycloak.commons.logger
import de.spree.keycloak.commons.toBase64
import java.io.FileInputStream
import java.util.*

object KeychainConsumer {
	private val hsmCryptoService = HSMCryptoService()

	init {
		setupBouncyCastle()
	}

	@JvmStatic
	fun main(args: Array<String>) {
		val properties = Properties().apply { load(FileInputStream("/tmp/kc.properties")) }

		val hsmKeyId = properties.getProperty("SPREE_KEYCHAIN_KEK_ID").trim('"')
		val encryptedKey = properties.getProperty("SPREE_KEYCHAIN_KEY").trim('"').fromBase64()
		val decryptedKey = hsmCryptoService.decrypt(ciphertext = encryptedKey, keyId = hsmKeyId).getOrElse { throw it }
		val keychainKey = properties.getProperty("KEY")?.trim('"')?.fromBase64() ?: decryptedKey

		logger.info("Decrypted: ${decryptedKey.toBase64()}")
		logger.info("Plaintext: ${keychainKey.toBase64()}")

		check(keychainKey.contentEquals(decryptedKey)) { "Keys are not equal!" }

		val encryptedKeychain = properties.getProperty("SPREE_KEYCHAIN_DATA").trim('"').fromBase64()
		val decryptedKeychain = encryptedKeychain.decrypt(decryptedKey).getOrElse { throw it }
		val keychain = decryptedKeychain.toKeychain().getOrElse { throw it }

		logger.info("Keychain: ${keychain.keychainId}")
	}
}
