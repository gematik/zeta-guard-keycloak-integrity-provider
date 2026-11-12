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
package de.spree.keycloak.crypto

import de.spree.keycloak.commons.AbstractDatabaseTest
import de.spree.keycloak.commons.configuration.TABLE_CRYPTO_UPDATE
import io.kotest.matchers.comparables.shouldBeGreaterThanOrEqualTo
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import org.keycloak.models.jpa.entities.UserEntity
import java.time.Instant

class CryptoUpdateDaoTest : AbstractDatabaseTest(
	tableNames = listOf(TABLE_CRYPTO_UPDATE),
	entities = listOf(CryptoUpdate::class.java)
) {
	private lateinit var objectUnderTest: CryptoUpdateDao

	init {
		val entityName = UserEntity::class.java.name

		beforeTest { objectUnderTest = CryptoUpdateDao(entityManager) }

		test("check remaining tasks") {
			objectUnderTest.remaining() shouldBe 0
			objectUnderTest.add(entityName)

			newTransaction()
			objectUnderTest.remaining() shouldBe 1
		}

		test("add and delete by entity name") {
			objectUnderTest.add(entityName)

			newTransaction()
			objectUnderTest.delete(entityName)
			objectUnderTest.remaining() shouldBe 0
		}

		test("deletes all pending tasks") {
			objectUnderTest.add(entityName)

			newTransaction()
			objectUnderTest.deleteAll()
			objectUnderTest.remaining() shouldBe 0
		}


		test("reserve and delete a fresh task") {
			objectUnderTest.add(entityName)

			newTransaction()
			val now = Instant.now()
			val task = objectUnderTest.reserve(30).shouldNotBeNull()
			task.startTime.shouldNotBeNull().shouldBeGreaterThanOrEqualTo(now)
			objectUnderTest.delete(task)
			objectUnderTest.remaining() shouldBe 0
		}

		test("reserve an abandoned task") {
			objectUnderTest.add(entityName)
			objectUnderTest.reserve(30).shouldNotBeNull()

			newTransaction()
			objectUnderTest.reserve(30).shouldBeNull() // already reserved but not older than 30s

			newTransaction()
			val now = Instant.now()
			val task = objectUnderTest.reserve(0).shouldNotBeNull() // can reserve again since older than 0s
			task.startTime.shouldNotBeNull().shouldBeGreaterThanOrEqualTo(now)
		}
	}
}