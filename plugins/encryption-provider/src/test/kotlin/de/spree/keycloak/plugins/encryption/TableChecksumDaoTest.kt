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

import de.spree.keycloak.commons.AbstractDatabaseTest
import de.spree.keycloak.integrity.TableChecksum
import de.spree.keycloak.integrity.TableChecksumDao
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import org.keycloak.models.jpa.entities.UserEntity

class TableChecksumDaoTest : AbstractDatabaseTest() {
	private lateinit var objectUnderTest: TableChecksumDao

	init {
		val entityName = UserEntity::class.java.name

		beforeTest {
			objectUnderTest = TableChecksumDao(entityManager)
		}

		test("check if empty") {
			objectUnderTest.isTableEmpty() shouldBe true
			objectUnderTest.save(TableChecksum(entityName = entityName, hash = "hash", checksum = "checksum"))

			newTransaction()
			objectUnderTest.isTableEmpty() shouldBe false
		}

		test("find and delete by entity id") {
			val checksum = TableChecksum(entityName = entityName, hash = "hash", checksum = "checksum")
			objectUnderTest.save(checksum)

			newTransaction()
			val tableChecksum = objectUnderTest.findByEntityName(entityName)!! shouldBe checksum

			objectUnderTest.delete(tableChecksum)
			objectUnderTest.findByEntityName(entityName).shouldBeNull()
		}
	}
}
