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
@file:Suppress("SqlSourceToSinkFlow")

package de.spree.keycloak.integrity.migration

import de.spree.keycloak.commons.AbstractDatabaseTest
import de.spree.keycloak.commons.configuration.SpreeEntityConfiguration
import de.spree.keycloak.integrity.RowChecksum
import de.spree.keycloak.integrity.RowChecksumKeyId
import io.kotest.matchers.shouldBe
import liquibase.database.DatabaseFactory
import liquibase.database.jvm.JdbcConnection
import org.keycloak.models.jpa.entities.ClientScopeClientMappingEntity
import org.keycloak.models.jpa.entities.UserRoleMappingEntity
import java.sql.Connection

class ConvertEntityIdToCompositeIdChangeTest : AbstractDatabaseTest() {
	val objectUnderTest = object : ConvertEntityIdToCompositeIdChange() {
		override fun getConfiguration(): SpreeEntityConfiguration = spreeConfiguration
	}

	init {
		test("convert ClientScopeClientMappingEntity") {
			val entityName = ClientScopeClientMappingEntity::class.java.name

			for(i in 1..200) {
				val entityId = """{"clientId":"clientId$i","clientScopeId":"clientScopeId$i"}"""
				val rowChecksum = RowChecksum(
					entityName = entityName,
					entityId = entityId,
					null,
					null,
					"checksum"
				)

				entityManager.persist(rowChecksum)
			}
			newTransaction()

			entityManager.runWithConnection<Connection> { connection ->
				objectUnderTest.execute(DatabaseFactory.getInstance().findCorrectDatabaseImplementation(JdbcConnection(connection)))
			}

			newTransaction()

			val entityId = """{"clientId":"clientId7","clientScopeId":"clientScopeId7"}"""
			val rowChecksum2 = entityManager.find(RowChecksum::class.java, RowChecksumKeyId(entityName, entityId))

			rowChecksum2.entityId shouldBe entityId
			rowChecksum2.entityName shouldBe entityName
			rowChecksum2.compositeId1 shouldBe "clientId7"
			rowChecksum2.compositeId2 shouldBe "clientScopeId7"
			rowChecksum2.checksum shouldBe "checksum"
		}
		test("convert UserRoleMappingEntity") {
			val entityName = UserRoleMappingEntity::class.java.name

			for(i in 1..200) {
				val entityId = """{"roleId":"role$i","user":{"id":"user$i"}}"""
				val rowChecksum = RowChecksum(
					entityName = entityName,
					entityId = entityId,
					null,
					null,
					"checksum"
				)

				entityManager.persist(rowChecksum)
			}
			newTransaction()

			entityManager.runWithConnection<Connection> { connection ->
				objectUnderTest.execute(DatabaseFactory.getInstance().findCorrectDatabaseImplementation(JdbcConnection(connection)))
			}

			newTransaction()

			val entityId = """{"roleId":"role7","user":{"id":"user7"}}"""
			val rowChecksum2 = entityManager.find(RowChecksum::class.java, RowChecksumKeyId(entityName, entityId))

			rowChecksum2.entityId shouldBe entityId
			rowChecksum2.entityName shouldBe entityName
			rowChecksum2.compositeId1 shouldBe "role7"
			rowChecksum2.compositeId2 shouldBe "user7"
			rowChecksum2.checksum shouldBe "checksum"
		}
	}
}
