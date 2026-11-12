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
package de.spree.keycloak.integrity.migration

import de.spree.keycloak.commons.AbstractDatabaseTest
import de.spree.keycloak.commons.crypto.HashingService
import de.spree.keycloak.commons.crypto.keychain.Keychain
import de.spree.keycloak.commons.crypto.keychain.keychainId
import de.spree.keycloak.commons.crypto.muhash.MuHash3072
import de.spree.keycloak.commons.crypto.toChecksum
import de.spree.keycloak.commons.crypto.toHash
import de.spree.keycloak.commons.keychainBundle
import de.spree.keycloak.commons.setValue
import de.spree.keycloak.integrity.RowChecksum
import de.spree.keycloak.integrity.TableChecksum
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.matchers.shouldBe
import liquibase.database.DatabaseFactory
import liquibase.database.jvm.JdbcConnection
import org.keycloak.models.jpa.entities.ClientScopeClientMappingEntity
import org.keycloak.models.jpa.entities.UserEntity
import java.sql.Connection

class RecalculateTableChecksumsChangeTest : AbstractDatabaseTest() {
	private var keychainLoaded = false
	private val hashingService = HashingService().setValue("keychainBundle", keychainBundle)

	val objectUnderTest = object : RecalculateTableChecksumsChange() {
		override fun loadCurrentKeychain(): Keychain = keychainBundle.currentKeychain().also { keychainLoaded = true }
	}

	private fun runMigration() {
		entityManager.runWithConnection<Connection> { connection ->
			objectUnderTest.execute(DatabaseFactory.getInstance().findCorrectDatabaseImplementation(JdbcConnection(connection)))
		}

		newTransaction()
	}

	init {
		test("recalculate table checksums") {
			val userEntity = UserEntity::class.java.name
			val userIds = (1..200).map { "user$it" }
			val mappingEntity = ClientScopeClientMappingEntity::class.java.name
			val mappingIds = (1..3).map { """{"clientId":"clientId$it","clientScopeId":"clientScopeId$it"}""" }

			userIds.forEach { entityManager.persist(RowChecksum(userEntity, it, null, null, "checksum")) }
			mappingIds.forEach { entityManager.persist(RowChecksum(mappingEntity, it, null, null, "checksum")) }
			entityManager.persist(TableChecksum(userEntity, "", "old"))
			entityManager.persist(TableChecksum(mappingEntity, "", "old"))
			newTransaction()

			runMigration()

			mapOf(userEntity to userIds, mappingEntity to mappingIds).forEach { (entityName, entityIds) ->
				val tableChecksum = entityManager.find(TableChecksum::class.java, entityName)
				val expectedHash = MuHash3072().apply { entityIds.forEach { insert(it.toByteArray()) } }.current()
				val hash = tableChecksum.hash.toHash().shouldBeRight()
				val checksum = tableChecksum.checksum.toChecksum().shouldBeRight()

				hash shouldBe expectedHash
				checksum.keychainId shouldBe keychainBundle.currentKeychain().keychainId().shouldBeRight()
				hashingService.verify(entityName, checksum, hash).shouldBeRight()
			}
		}

		test("table checksum without row checksums yields empty hash") {
			val entityName = UserEntity::class.java.name
			entityManager.persist(TableChecksum(entityName, "", "old"))
			newTransaction()

			runMigration()

			val tableChecksum = entityManager.find(TableChecksum::class.java, entityName)
			tableChecksum.hash.toHash().shouldBeRight() shouldBe MuHash3072().current()
		}

		test("empty database does not load keychain") {
			keychainLoaded = false

			runMigration()

			keychainLoaded shouldBe false
		}
	}
}
