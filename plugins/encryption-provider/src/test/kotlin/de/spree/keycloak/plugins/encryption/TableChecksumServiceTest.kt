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
import de.spree.keycloak.commons.crypto.Checksum
import de.spree.keycloak.commons.crypto.muhash.MuHash3072
import de.spree.keycloak.commons.crypto.keychain.keychainId
import de.spree.keycloak.commons.crypto.toChecksum
import de.spree.keycloak.commons.crypto.toDatabaseRepresentation
import de.spree.keycloak.integrity.*
import de.spree.keycloak.plugins.integrity.Action
import de.spree.keycloak.plugins.integrity.Action.LOAD
import de.spree.keycloak.plugins.integrity.Action.SCAN
import de.spree.keycloak.plugins.integrity.EntityAction
import io.kotest.assertions.arrow.core.shouldBeLeft
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.jboss.logmanager.Logger
import org.keycloak.models.jpa.entities.UserEntity

class TableChecksumServiceTest : AbstractMockTest() {
	private val entityInfo = EntityInfo(EntityId(user.id), "USER_ENTITY", user)
	private val rowChecksumDao: RowChecksumDao = mockk()
	private val entityDao: EntityDao = mockk()
	private val tableChecksumDao: TableChecksumDao = mockk()
	private val rowChecksumService =
		object : RowChecksumService() {
			override fun createKeycloakContextRowChecksumDao(action: EntityAction) = rowChecksumDao
			override fun createSpreeContextRowChecksumDao(action: EntityAction) = rowChecksumDao
		}.apply {
			setValue("hashingService", hashingService, RowChecksumService::class.java)
			setValue("spreeLogger", Logger.getLogger("de.spree.keycloak"), RowChecksumService::class.java)
		}
	private val objectUnderTest =
		object : TableChecksumService() {
			override fun createSpreeContextTableChecksumDao(action: EntityAction) = tableChecksumDao
			override fun createSpreeContextEntityDao(action: EntityAction) = entityDao
		}.apply {
			setValue("rowChecksumService", rowChecksumService, TableChecksumService::class.java)
			setValue("hashingService", hashingService, TableChecksumService::class.java)
		}
	val entityName: String = UserEntity::class.java.name
	val rowChecksum: Checksum by lazy {
		rowChecksumService.calculateRowChecksum(entityInfo, EntityAction(LOAD, entityName, entityManager)).shouldBeRight()
	}
	val rowChecksums: List<RowChecksum> by lazy { listOf(RowChecksum(entityName, user.id, compositeId1 = null,compositeId2 = null, rowChecksum.toDatabaseRepresentation())) }
	val tableHash: ByteArray = MuHash3072().insert(user.id.toByteArray()).current()

	init {
		beforeTest {
			every { rowChecksumDao.findAllByEntityName(entityName) } returns rowChecksums
			every { tableChecksumDao.findForUpdate(entityName) } returns null
			every { tableChecksumDao.save(any()) } returns Unit
			every { tableChecksumDao.delete(any()) } returns Unit
		}

		test("Calculating table checksum") {
			val multi = objectUnderTest.calculateTableChecksum(rowChecksums).shouldBeRight()
			val result = hashingService.finish(multi).shouldBeRight()

			result.hash shouldBe tableHash
			result.checksum.keychainId shouldBe keychainBundle.currentKeychain().keychainId().shouldBeRight()
			result.checksum.keychainId.size shouldBe UUID_SIZE
			hashingService.verify(entityName, result.checksum, tableHash).shouldBeRight()
		}

		test("Update table checksum") {
			val checksums = mutableListOf<TableChecksum>()

			var action = EntityAction(Action.INITIALIZE, entityName, entityManager)
			objectUnderTest.updateTableChecksum(action, listOf()).shouldBeRight()

			verify { tableChecksumDao.save(capture(checksums)) }
			val emptyChecksum = checksums.last()
			emptyChecksum.entityName shouldBe entityName
			emptyChecksum.hash.shouldBeBase64()
			emptyChecksum.checksum.shouldBeBase64()
			emptyChecksum.checksum.toChecksum().shouldBeRight().keychainId shouldBe keychainBundle.currentKeychain().keychainId().shouldBeRight()
			hashingService.verify(entityName, emptyChecksum.checksum.toChecksum().shouldBeRight(), emptyChecksum.hash.fromBase64()).shouldBeRight()

			action = EntityAction(Action.INSERT, entityName, entityManager)
			objectUnderTest.updateTableChecksum(action, listOf(entityInfo.id)).shouldBeRight()

			verify { tableChecksumDao.save(capture(checksums)) }
			val insertChecksum = checksums.last()
			insertChecksum.entityName shouldBe entityName
			insertChecksum.checksum.shouldBeBase64()
			insertChecksum.hash shouldBe tableHash.toBase64()
			insertChecksum.checksum.shouldNotBe(emptyChecksum.checksum)

			action = EntityAction(Action.DELETE, entityName, entityManager)
			every { tableChecksumDao.findForUpdate(entityName) } returns insertChecksum
			objectUnderTest.updateTableChecksum(action, listOf(entityInfo.id)).shouldBeRight()

			verify { tableChecksumDao.delete(capture(checksums)) }
			val deleteChecksum = checksums.last()
			deleteChecksum.entityName shouldBe entityName
			deleteChecksum.checksum.shouldBeBase64()
			deleteChecksum.checksum.shouldBe(insertChecksum.checksum)
		}

		test("Update table checksum rejects tampered hash") {
			val tampered = TableChecksum(
				entityName = entityName,
				hash = MuHash3072().insert("badguy-id".toByteArray()).current().toBase64(),
				checksum = hashingService.hash(tableHash).shouldBeRight().toDatabaseRepresentation()
			)
			every { tableChecksumDao.findForUpdate(entityName) } returns tampered

			val action = EntityAction(Action.INSERT, entityName, entityManager)
			objectUnderTest.updateTableChecksum(action, listOf(entityInfo.id)).shouldBeLeft().message shouldContain "HMAC verification failed"
		}

		test("Check table checksum") {
			// must recalculate since keychain changes for each test
			val tableChecksum = hashingService.hash(tableHash).shouldBeRight()
			val checksum = TableChecksum(entityName = entityName, hash = tableHash.toBase64(), checksum = tableChecksum.toDatabaseRepresentation())
			val action = EntityAction(SCAN, entityName, entityManager)

			every { entityDao.getEntityRowCount(entityName) } returns 1
			every { tableChecksumDao.findByEntityName(entityName) } returns checksum

			objectUnderTest.checkTableChecksum(action).shouldBeRight()
		}

		test("Check table checksum mismatch") {
			val emptyHash = MuHash3072().current()
			val checksum = TableChecksum(
				entityName = entityName,
				hash = emptyHash.toBase64(),
				checksum = hashingService.hash(emptyHash).shouldBeRight().toDatabaseRepresentation()
			)
			val action = EntityAction(SCAN, entityName, entityManager)

			every { entityDao.getEntityRowCount(entityName) } returns 1
			every { tableChecksumDao.findByEntityName(entityName) } returns checksum

			objectUnderTest.checkTableChecksum(action).shouldBeLeft().message shouldContain "HMAC verification failed"
		}

		test("Check table checksum missing") {
			val action = EntityAction(SCAN, entityName, entityManager)

			every { entityDao.getEntityRowCount(entityName) } returns 1
			every { tableChecksumDao.findByEntityName(entityName) } returns null

			objectUnderTest.checkTableChecksum(action).shouldBeLeft().message shouldContain "No table checksum found"
		}

		test("Number of row checksums should match entity count") {
			every { entityDao.getEntityRowCount(entityName) } returns 5

			objectUnderTest.loadRowChecksums(EntityAction(SCAN, entityName, entityManager)).shouldBeLeft().message shouldContain
				"does not match entity count"
		}
	}
}
