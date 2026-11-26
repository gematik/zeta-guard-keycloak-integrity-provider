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

import arrow.core.getOrElse
import de.spree.keycloak.commons.ENV_HSM_AAD
import de.spree.keycloak.commons.ENV_KEYCHAIN_DATA
import de.spree.keycloak.commons.ENV_KEYCHAIN_FILE
import de.spree.keycloak.commons.ENV_KEYCHAIN_KEY
import de.spree.keycloak.commons.getEnvironment
import de.spree.keycloak.commons.logger
import de.spree.keycloak.commons.toBase64
import de.spree.keycloak.crypto.HSMCryptoService
import de.spree.keycloak.crypto.encrypt
import de.spree.keycloak.crypto.setupBouncyCastle
import java.io.File
import java.io.FileOutputStream
import java.io.PrintStream
import kotlin.system.exitProcess

private val SPREE_KEYCHAIN_FILE = getEnvironment(ENV_KEYCHAIN_FILE)

object KeychainGenerator {
	private val hsmCryptoService = HSMCryptoService()

	init {
		setupBouncyCastle()
	}

	@JvmStatic
	fun main(args: Array<String>) {
		val outputFile = File(SPREE_KEYCHAIN_FILE)

		if (outputFile.exists()) {
			logger.info("🔐 Keychain file already exists at »$SPREE_KEYCHAIN_FILE«!")

			if (outputFile.isDirectory) {
				logger.error("💣 »$SPREE_KEYCHAIN_FILE« is a directory!")
				exitProcess(2)
			}
		} else {
			if (!outputFile.parentFile.exists() && !outputFile.parentFile.mkdirs()) {
				logger.error("💣 Could not create »$SPREE_KEYCHAIN_FILE« directory!")
				exitProcess(2)
			}

			val hsmAad = KeychainUtil.generateDataBytes(AAD_SIZE)
			val keychain = Keychain()
			val serialized = keychain.serialize()
			val keychainKey = KeychainUtil.generateDataBytes(GCM_KEY_SIZE)
			val encryptedKey = hsmCryptoService.encrypt(keychainKey, hsmAad).getOrElse { throw it }
			val encryptedKeychain = serialized.encrypt(keychainKey, hsmAad).getOrElse { throw it }

			logger.info("🔐 Generating new keychain file at »$SPREE_KEYCHAIN_FILE«!")

			if (!outputFile.createNewFile()) {
				logger.error("💣 Could not create »$SPREE_KEYCHAIN_FILE« file!")
				exitProcess(3)
			}

			PrintStream(FileOutputStream(outputFile)).use {
				it.println(
					"""
			|$ENV_KEYCHAIN_DATA="${encryptedKeychain.toBase64()}"
			|$ENV_KEYCHAIN_KEY="${encryptedKey.toBase64()}"
			|$ENV_HSM_AAD="${hsmAad.toBase64()}"
		""".trimMargin()
				)

				it.flush()
			}

			logger.info("☑️ Keychain generator exiting...")
			exitProcess(0)
		}
	}
}