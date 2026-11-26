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
package de.spree.keycloak.plugins.encryption

import arrow.core.getOrElse
import de.spree.keycloak.commons.*
import de.spree.keycloak.commons.EntityConverter.convertToJSON
import de.spree.keycloak.commons.TestData.user
import de.spree.keycloak.crypto.toChecksum
import de.spree.keycloak.crypto.toDatabaseRepresentation
import de.spree.keycloak.integrity.RowChecksumService
import de.spree.keycloak.plugins.integrity.Action.LOAD
import de.spree.keycloak.plugins.integrity.EntityAction
import io.kotest.assertions.arrow.core.shouldBeLeft
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import org.jboss.logmanager.Logger

class RowChecksumServiceTest : AbstractMockTest() {
  private val entityInfo = EntityInfo(EntityId(user.id), "USER_ENTITY", user)
  private val objectUnderTest =
      RowChecksumService()
          .setValue("signingService", signingService)
          .setValue("spreeLogger", Logger.getLogger("de.spree.keycloak"))
          .setValue("currentKeychain", this@RowChecksumServiceTest.currentKeychain)
  private val data: String by lazy { entityManager.convertToJSON(user).getOrElse { throw it } }
  private val dataBytes by lazy { data.toByteArray() }

  init {
    test("Calculating checksum") {
      val checksum = objectUnderTest.calculateRowChecksum(entityInfo, EntityAction(LOAD, "UserEntity", entityManager)).shouldBeRight()
      val bytes = checksum.toDatabaseRepresentation().fromBase64()
      val keychain = currentKeychain.keychain().shouldBeRight()

      checksum.toDatabaseRepresentation().toChecksum().shouldBeRight() shouldBe checksum

      checksum.keychainId shouldBe keychain.keychainId.toByteArray()
      checksum.keychainId.size shouldBe UUID_SIZE
      checksum.hash.size shouldBe HASH_SIZE
      checksum.signature.size shouldBe (bytes.size - (UUID_SIZE + HASH_SIZE))
      checksum.hash.contentEquals(toHash(dataBytes)) shouldBe true

      signingService.verify("entity", checksum.hash, checksum.signature).shouldBeRight()
    }

    test("Valid checksum") {
      val checksum = objectUnderTest.calculateRowChecksum(entityInfo, EntityAction(LOAD, "UserEntity", entityManager)).shouldBeRight()

      objectUnderTest.validateChecksum(checksum, checksum, entityInfo, EntityAction(LOAD, "UserEntity", entityManager)).shouldBeRight()
    }

    test("Validation of checksum should fail if hash is tampered with") {
      val checksum = objectUnderTest.calculateRowChecksum(entityInfo, EntityAction(LOAD, "UserEntity", entityManager)).shouldBeRight()
      val tamperedChecksum = checksum.copy(hash = dataBytes)

      objectUnderTest
          .validateChecksum(tamperedChecksum, checksum, entityInfo, EntityAction(LOAD, "UserEntity", entityManager))
          .shouldBeLeft()
          .message shouldContain "Row checksum mismatch"
    }

    test("Validation of checksum should fail if signature is tampered with") {
      val checksum = objectUnderTest.calculateRowChecksum(entityInfo, EntityAction(LOAD, "UserEntity", entityManager)).shouldBeRight()
      val tamperedChecksum = checksum.copy(signature = dataBytes)

      objectUnderTest
          .validateChecksum(tamperedChecksum, checksum, entityInfo, EntityAction(LOAD, "UserEntity", entityManager))
          .shouldBeLeft()
          .message shouldContain "error decoding signature bytes"
    }
  }
}
