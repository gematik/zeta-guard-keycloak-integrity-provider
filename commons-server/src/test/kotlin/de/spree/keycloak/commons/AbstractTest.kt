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

import de.spree.keycloak.commons.crypto.keychain.INVALID_KEYCHAIN
import de.spree.keycloak.commons.crypto.keychain.Keychain
import de.spree.keycloak.commons.crypto.keychain.KeychainBundle
import de.spree.keycloak.commons.crypto.setupBouncyCastle
import io.kotest.core.spec.style.StringSpec

var keychainBundle = TestKeychainBundle()

class TestKeychainBundle : KeychainBundle() {
	override fun loadCurrentKeychain(): Keychain = Keychain()
	override fun loadFutureKeychain(): Keychain = Keychain()
	override fun loadPreviousKeychain(): Keychain = INVALID_KEYCHAIN
}

abstract class AbstractTest(body: StringSpec.() -> Unit = {}) : StringSpec(body) {
	companion object {
		init {
			setupBouncyCastle()
		}
	}
}
