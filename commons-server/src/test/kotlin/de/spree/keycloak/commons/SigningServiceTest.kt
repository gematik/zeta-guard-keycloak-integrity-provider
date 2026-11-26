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
import de.spree.keycloak.crypto.SigningService
import io.kotest.assertions.arrow.core.shouldBeLeft
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.matchers.ints.shouldBeGreaterThan
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain

class SigningServiceTest : AbstractTest() {
  val objectUnderTest = SigningService().setValue("currentKeychain", currentKeychain)

  init {
    "should sign and verify successfully" {
      val signature = objectUnderTest.sign(dataBytes).shouldBeRight()

      signature shouldNotBe dataBytes
      signature.size shouldBeGreaterThan 0

      objectUnderTest.verify("entity", dataBytes, signature).shouldBeRight()
    }

    "should not verify if data is modified" {
      val signature = objectUnderTest.sign(dataBytes).shouldBeRight()
      val modified = dataBytes.copyOf()
      modified[0]++

      objectUnderTest.verify("entity", modified, signature).shouldBeLeft().message shouldContain "Signature verification failed"
    }

    "should not verify if signature is tampered with" {
      val signature = objectUnderTest.sign(dataBytes).shouldBeRight()
      val tampered = signature.copyOf()
      tampered[0]++

      objectUnderTest.verify("entity", tampered, signature).shouldBeLeft().message shouldContain "Signature verification failed"
    }

    "should throw exception for invalid data" {
      val signature = objectUnderTest.sign(dataBytes).shouldBeRight()
      objectUnderTest.verify("entity", signature, signature).shouldBeLeft().message shouldContain "Signature verification failed"
    }

    "should throw exception for invalid signature" {
      objectUnderTest.verify("entity", dataBytes, dataBytes).shouldBeLeft().message shouldContain "error decoding signature bytes"
    }
  }
}
