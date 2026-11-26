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

import de.spree.keycloak.crypto.keychain.KEYCHAIN_SIZE
import de.spree.keycloak.crypto.keychain.Keychain
import de.spree.keycloak.crypto.keychain.serialize
import de.spree.keycloak.crypto.keychain.toKeychain
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.matchers.shouldBe

class KeychainUtilTest :
    AbstractTest({
      "Keychain conversion" {
        val keychain = Keychain()
        val encoded = keychain.serialize().apply { size shouldBe KEYCHAIN_SIZE }
        val keychain2 = encoded.toKeychain().shouldBeRight(keychain)

        keychain2.signingKeyPair.public shouldBe keychain.signingKeyPair.public
        keychain2.signingKeyPair.private shouldBe keychain.signingKeyPair.private
        keychain2.gcmEncryptionKey shouldBe keychain.gcmEncryptionKey
        keychain2.gcmAad shouldBe keychain.gcmAad
        keychain2.creationDate shouldBe keychain.creationDate
      }
    })
