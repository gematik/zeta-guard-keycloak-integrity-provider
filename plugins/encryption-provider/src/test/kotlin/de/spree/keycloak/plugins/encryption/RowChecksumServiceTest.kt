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
import de.spree.keycloak.commons.EntityConverter.lookupEntityInfo
import de.spree.keycloak.commons.TestData.client1
import de.spree.keycloak.commons.TestData.clientAttributeEntity
import de.spree.keycloak.commons.TestData.user
import de.spree.keycloak.commons.crypto.keychain.keychainId
import de.spree.keycloak.commons.crypto.toChecksum
import de.spree.keycloak.commons.crypto.toDatabaseRepresentation
import de.spree.keycloak.commons.debug.EntityInfoWriter
import de.spree.keycloak.integrity.RowChecksum
import de.spree.keycloak.integrity.RowChecksumDao
import de.spree.keycloak.integrity.RowChecksumService
import de.spree.keycloak.integrity.rowChecksumId
import de.spree.keycloak.plugins.integrity.Action.INSERT
import de.spree.keycloak.plugins.integrity.Action.LOAD
import de.spree.keycloak.plugins.integrity.Action.UPDATE
import de.spree.keycloak.plugins.integrity.EntityAction
import io.kotest.assertions.arrow.core.shouldBeLeft
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.mockk.Runs
import io.mockk.clearMocks
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import org.jboss.logmanager.Logger
import org.keycloak.models.jpa.entities.ClientAttributeEntity
import org.keycloak.models.jpa.entities.UserEntity

class RowChecksumServiceTest : AbstractMockTest() {
  private val entityInfo = EntityInfo(EntityId(user.id), "USER_ENTITY", user)
  private val rowChecksumDao: RowChecksumDao = mockk()
  private val objectUnderTest = object : RowChecksumService() {
    override fun createSpreeContextRowChecksumDao(action: EntityAction) = rowChecksumDao

    override fun createKeycloakContextRowChecksumDao(action: EntityAction) = rowChecksumDao
  }.apply {
    setValue("hashingService", hashingService, RowChecksumService::class.java)
    setValue("spreeLogger", Logger.getLogger("de.spree.keycloak"), RowChecksumService::class.java)
    setValue("entityInfoWriter", EntityInfoWriter { _, _ -> }, RowChecksumService::class.java)
    setValue("spreeConfiguration", spreeConfiguration, RowChecksumService::class.java)
  }
  private val data: String by lazy { entityManager.convertToJSON(user).getOrElse { throw it } }
  private val dataBytes by lazy { data.toByteArray() }

  private val userAction by lazy { EntityAction(UPDATE, UserEntity::class.java.name, entityManager) }
  private val userChecksum by lazy { objectUnderTest.calculateRowChecksum(entityInfo, userAction).getOrElse { throw it }.toDatabaseRepresentation() }

  init {
    beforeTest {
      clearMocks(rowChecksumDao)
      every { rowChecksumDao.save(any()) } just Runs
    }

    test("Updating existing row checksum with unchanged value") {
      val existing = RowChecksum(UserEntity::class.java.name, user.id, checksum = userChecksum)
      every { rowChecksumDao.findForUpdate(entityInfo.rowChecksumId) } returns existing

      objectUnderTest.updateEntityInfoChecksum(entityInfo, userAction).shouldBeRight() shouldBe false

      existing.checksum shouldBe userChecksum
      verify(exactly = 0) { rowChecksumDao.save(any()) }
    }

    test("Updating existing row checksum with changed value") {
      val existing = RowChecksum(UserEntity::class.java.name, user.id, checksum = "outdated")
      every { rowChecksumDao.findForUpdate(entityInfo.rowChecksumId) } returns existing

      objectUnderTest.updateEntityInfoChecksum(entityInfo, userAction).shouldBeRight() shouldBe true

      existing.checksum shouldBe userChecksum
      verify(exactly = 0) { rowChecksumDao.save(any()) }
    }

    test("Creating new row checksum for entity with string ID") {
      val checksum = slot<RowChecksum>()
      every { rowChecksumDao.findForUpdate(entityInfo.rowChecksumId) } returns null
      every { rowChecksumDao.save(capture(checksum)) } just Runs

      objectUnderTest.updateEntityInfoChecksum(entityInfo, userAction).shouldBeRight() shouldBe true

      checksum.captured.entityName shouldBe UserEntity::class.java.name
      checksum.captured.entityId shouldBe user.id
      checksum.captured.compositeId1 shouldBe null
      checksum.captured.compositeId2 shouldBe null
      checksum.captured.checksum shouldBe userChecksum
    }

    test("Creating new row checksum for entity with composite ID") {
      val action = EntityAction(INSERT, ClientAttributeEntity::class.java.name, entityManager)
      val clientAttributeInfo = entityManager.lookupEntityInfo(clientAttributeEntity).shouldBeRight()
      val checksum = slot<RowChecksum>()
      every { rowChecksumDao.findForUpdate(clientAttributeInfo.rowChecksumId) } returns null
      every { rowChecksumDao.save(capture(checksum)) } just Runs

      objectUnderTest.updateEntityInfoChecksum(clientAttributeInfo, action).shouldBeRight() shouldBe true

      checksum.captured.entityName shouldBe ClientAttributeEntity::class.java.name
      checksum.captured.entityId shouldBe clientAttributeInfo.id
      checksum.captured.compositeId1 shouldBe client1.id // composite IDs are sorted by property name: client, name
      checksum.captured.compositeId2 shouldBe clientAttributeEntity.name
      checksum.captured.checksum shouldBe objectUnderTest.calculateRowChecksum(clientAttributeInfo, action).shouldBeRight().toDatabaseRepresentation()
    }

    test("Calculating row checksum") {
      val checksum = objectUnderTest.calculateRowChecksum(entityInfo, EntityAction(LOAD, "UserEntity", entityManager)).shouldBeRight()

      checksum.toDatabaseRepresentation().toChecksum().shouldBeRight() shouldBe checksum

      checksum.keychainId shouldBe keychainBundle.currentKeychain().keychainId().shouldBeRight()
      checksum.keychainId.size shouldBe UUID_SIZE
      checksum.hash.size shouldBe HASH_SIZE

      hashingService.verify("entity", checksum, dataBytes).shouldBeRight()
    }

    test("Valid checksum") {
      val checksum = objectUnderTest.calculateRowChecksum(entityInfo, EntityAction(LOAD, "UserEntity", entityManager)).shouldBeRight()

      objectUnderTest.validateChecksum(EntityAction(LOAD, "UserEntity", entityManager), checksum, entityInfo).shouldBeRight()
    }

    test("Validation of checksum should fail if hash is tampered with") {
      val checksum = objectUnderTest.calculateRowChecksum(entityInfo, EntityAction(LOAD, "UserEntity", entityManager)).shouldBeRight()
      val tamperedChecksum = checksum.copy(hash = dataBytes)

      objectUnderTest
          .validateChecksum(EntityAction(LOAD, "UserEntity", entityManager), tamperedChecksum, entityInfo)
          .shouldBeLeft()
          .message shouldContain "Row checksum mismatch"
    }

    test("Validation of checksum should fail if signature is tampered with") {
      val checksum = objectUnderTest.calculateRowChecksum(entityInfo, EntityAction(LOAD, "UserEntity", entityManager)).shouldBeRight()
      val tamperedChecksum = checksum.copy(hash = dataBytes)

      objectUnderTest
          .validateChecksum(EntityAction(LOAD, "UserEntity", entityManager), tamperedChecksum, entityInfo)
          .shouldBeLeft()
          .message shouldContain "Row checksum mismatch"
    }
  }
}
