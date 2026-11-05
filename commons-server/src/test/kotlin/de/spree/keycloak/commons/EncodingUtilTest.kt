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

import de.spree.keycloak.commons.TestData.dataBytes
import de.spree.keycloak.commons.crypto.keychain.currentTime
import io.kotest.matchers.shouldBe
import java.util.*

class EncodingUtilTest :
    AbstractTest({
      "UUID conversion" {
        val uuid = UUID.randomUUID()

        uuid.toByteArray().toUUID() shouldBe uuid
      }

      "BASE64 conversion" { dataBytes.toBase64().fromBase64() shouldBe dataBytes }

      "LocalDateTime conversion" {
        val date = currentTime()
        val bytes = date.toByteArray()

        bytes.size shouldBe LOCALDATETIME_SIZE

        bytes.toLocalDateTime() shouldBe date
      }
    })
