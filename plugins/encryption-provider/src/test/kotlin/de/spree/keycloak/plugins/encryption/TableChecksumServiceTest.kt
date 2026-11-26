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

import de.spree.keycloak.commons.*
import de.spree.keycloak.commons.TestData.user
import de.spree.keycloak.crypto.Checksum
import de.spree.keycloak.crypto.toChecksum
import de.spree.keycloak.crypto.toDatabaseRepresentation
import de.spree.keycloak.integrity.*
import de.spree.keycloak.plugins.integrity.Action
import de.spree.keycloak.plugins.integrity.Action.LOAD
import de.spree.keycloak.plugins.integrity.EntityAction
import io.kotest.assertions.arrow.core.shouldBeLeft
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import org.jboss.logmanager.Logger
import org.keycloak.models.jpa.entities.UserEntity

class TableChecksumServiceTest : AbstractMockTest() {
  private val entityInfo = EntityInfo(EntityId(user.id), "USER_ENTITY", user)
  private val rowChecksumDao: RowChecksumDao = mockk()
  private val entityDao: EntityDao = mockk()
  private val tableChecksumDao: TableChecksumDao = mockk()
  private val rowChecksumService =
      RowChecksumService().apply {
        setValue("signingService", signingService)
        setValue("spreeLogger", Logger.getLogger("de.spree.keycloak"))
        setValue("currentKeychain", this@TableChecksumServiceTest.currentKeychain)
        setValue("rowChecksumDao", this@TableChecksumServiceTest.rowChecksumDao)
      }
  private val objectUnderTest =
      TableChecksumService().apply {
        setValue("rowChecksumService", rowChecksumService)
        setValue("entityDao", entityDao)
        setValue("tableChecksumDao", tableChecksumDao)
        setValue("signingService", signingService)
        setValue("entityManager", entityManager, AbstractDao::class.java)
        setValue("currentKeychain", this@TableChecksumServiceTest.currentKeychain)
      }
  val entityName: String = UserEntity::class.java.name
  val rowChecksum: Checksum by lazy {
    rowChecksumService.calculateRowChecksum(entityInfo, EntityAction(LOAD, entityName, entityManager)).shouldBeRight()
  }
  val rowChecksums: List<RowChecksum> by lazy { listOf(RowChecksum(entityName, user.id, rowChecksum.toDatabaseRepresentation())) }
  val tableChecksum: Checksum by lazy { objectUnderTest.calculateTableChecksum(rowChecksums).shouldBeRight() }

  init {
    beforeTest {
      every { rowChecksumDao.findAllByEntityName(entityName) } returns rowChecksums
      every { tableChecksumDao.findChecksum(entityName) } returns null
      every { tableChecksumDao.save(any()) } returns Unit
    }

    test("Calculating table checksum") {
      val bytes = tableChecksum.toDatabaseRepresentation().fromBase64()
      val keychain = currentKeychain.keychain().shouldBeRight()

      tableChecksum.toDatabaseRepresentation().toChecksum().shouldBeRight() shouldBe tableChecksum

      tableChecksum.keychainId shouldBe keychain.keychainId.toByteArray()
      tableChecksum.keychainId.size shouldBe UUID_SIZE
      tableChecksum.hash.size shouldBe HASH_SIZE
      tableChecksum.signature.size shouldBe (bytes.size - (UUID_SIZE + HASH_SIZE))
      tableChecksum.hash.contentEquals(toHash(rowChecksum.hash)) shouldBe true
    }

    test("Update table checksum") {
      val slot = slot<TableChecksum>()

      every { entityDao.getEntityRowCount(entityName) } returns 0
      objectUnderTest.updateTableChecksum(EntityAction(Action.INSERT, entityName, entityManager)).shouldBeRight()

      verify { tableChecksumDao.save(capture(slot)) }
      slot.captured.entityName shouldBe entityName
      slot.captured.checksum.shouldBeBase64()
    }

    test("Check table checksum") {
      val checksum = TableChecksum(entityName = entityName, checksum = tableChecksum.toDatabaseRepresentation())

      every { entityDao.getEntityRowCount(entityName) } returns 1
      every { tableChecksumDao.findChecksum(entityName) } returns checksum

      objectUnderTest.checkTableChecksum(entityName).shouldBeRight()
    }

    test("Check table checksum missing") {
      every { entityDao.getEntityRowCount(entityName) } returns 1
      every { tableChecksumDao.findChecksum(entityName) } returns null

      objectUnderTest.checkTableChecksum(entityName).shouldBeLeft().message shouldContain "No table checksum found"
    }

    test("Number of row checksums should match entity count") {
      every { entityDao.getEntityRowCount(entityName) } returns 5

      objectUnderTest.loadRowChecksums(EntityAction(Action.SCAN, entityName, entityManager)).shouldBeLeft().message shouldContain
          "does not match entity count"
    }
  }
}
