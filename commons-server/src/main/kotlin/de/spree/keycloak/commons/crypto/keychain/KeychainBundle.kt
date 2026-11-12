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
package de.spree.keycloak.commons.crypto.keychain

import arrow.core.Either
import arrow.core.getOrElse
import arrow.core.raise.either
import arrow.core.raise.ensure
import de.spree.keycloak.commons.configuration.SystemState
import de.spree.keycloak.commons.configuration.SystemStateService
import de.spree.keycloak.commons.logger
import de.spree.keycloak.commons.message
import de.spree.keycloak.commons.toBase64
import de.spree.keycloak.commons.toUUID
import de.spree.keycloak.commons.crypto.HSMCryptoService
import io.quarkus.runtime.Startup
import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject

/** Singleton object holding the current encryption-related data */
@ApplicationScoped
@Startup
open class KeychainBundle {
	@Inject //
	private lateinit var hsmCryptoService: HSMCryptoService

	@Inject //
	private lateinit var systemStateService: SystemStateService

	private val currentKeychain: Keychain by lazy { loadCurrentKeychain() }
	private val futureKeychain: Keychain by lazy { loadFutureKeychain() }
	private val previousKeychain: Keychain by lazy { loadPreviousKeychain() }

	protected open fun loadCurrentKeychain(): Keychain = loadKeychain(hsmCryptoService, KeychainType.CURRENT).getOrElse {
		systemStateService.setSystemState(SystemState.ERROR_HSM, it)
		logger.fatal("💣 Failed to load current keychain", it)
		throw it
	}

	// A missing future/previous keychain is a valid configuration (no rotation pending), so report it without a stack trace
	protected open fun loadFutureKeychain(): Keychain = loadKeychain(hsmCryptoService, KeychainType.FUTURE).getOrElse {
		logger.warnf("⚠️ No future keychain available: %s", it.message())
		INVALID_KEYCHAIN
	}

	protected open fun loadPreviousKeychain(): Keychain = loadKeychain(hsmCryptoService, KeychainType.PREVIOUS).getOrElse {
		logger.warnf("⚠️ No previous keychain available: %s", it.message())
		INVALID_KEYCHAIN
	}

	open fun futureKeychain() = futureKeychain

	open fun currentKeychain() = currentKeychain

	open fun previousKeychain() = previousKeychain

	fun retrieveKeychain(keychainId: ByteArray): Either<Throwable, Keychain> = either {
		ensure(keychainId.isValidKeychainId()) { IllegalStateException("Invalid Keychain ID: »${keychainId.toBase64()}«") }

		when {
			currentKeychain.keychainId().bind().contentEquals(keychainId) -> currentKeychain
			previousKeychain.keychainId().bind().contentEquals(keychainId) -> previousKeychain
			futureKeychain.keychainId().bind().contentEquals(keychainId) -> futureKeychain
			else -> raise(IllegalStateException("Unresolvable Keychain ID »${keychainId.toUUID()}«"))
		}
	}
}
