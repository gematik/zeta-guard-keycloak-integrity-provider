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

package de.spree.keycloak.plugins.encryption

import de.spree.keycloak.commons.*
import de.spree.keycloak.commons.EntityConverter.lookupEntityInfo
import de.spree.keycloak.commons.TestData.user
import de.spree.keycloak.commons.configuration.SystemState
import de.spree.keycloak.integrity.RowChecksum
import de.spree.keycloak.integrity.RowChecksumDao
import de.spree.keycloak.integrity.RowChecksumKeyId
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldContainExactly
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import org.keycloak.models.jpa.entities.ClientScopeClientMappingEntity
import org.keycloak.models.jpa.entities.RealmEntity
import org.keycloak.models.jpa.entities.UserEntity
import org.keycloak.models.jpa.entities.UserRoleMappingEntity

class RowChecksumDaoTest : AbstractDatabaseTest() {
	private lateinit var objectUnderTest: RowChecksumDao

	init {
		val mapping1 =
			ClientScopeClientMappingEntity().apply {
				clientScopeId = "clientScopeId1"
				clientId = "clientId1"
			}
		val urmel1 =
			UserRoleMappingEntity().apply {
				user = TestData.user
				roleId = "roleId1"
			}
		val urmel2 =
			UserRoleMappingEntity().apply {
				user = TestData.user
				roleId = "roleId2"
			}
		val mapping2 =
			ClientScopeClientMappingEntity().apply {
				clientScopeId = "clientScopeId2"
				clientId = "clientId1"
			}

		beforeTest {
			objectUnderTest = RowChecksumDao(entityManager)
			systemStateService.setSystemState(SystemState.OPERATIONAL)
		}

		test("find deleted entity") {
			val entityName = UserEntity::class.java.name
			val user2 = UserEntity().apply { id = "jens" }
			val rowChecksum1 = RowChecksum(entityId = user.id, entityName = entityName, checksum = "checksum", compositeId1 = null, compositeId2 = null)
			val rowChecksum2 = RowChecksum(entityId = "jens", entityName = entityName, checksum = "checksum", compositeId1 = null, compositeId2 = null)
			entityManager.persist(user)
			entityManager.persist(user2)
			objectUnderTest.save(rowChecksum1)
			objectUnderTest.save(rowChecksum2)
			newTransaction()

			objectUnderTest.findAbandonedChecksumsByStringId(entityName).shouldBeEmpty()
			val user1 = entityManager.find(UserEntity::class.java, user.id).shouldNotBeNull()
			entityManager.remove(user1)

			objectUnderTest.findAbandonedChecksumsByStringId(entityName).shouldContainExactly(rowChecksum1)
		}

		test("find and delete user entities") {
			val entityName = UserEntity::class.java.name
			val userId = RowChecksumKeyId(entityName, user.id)
			objectUnderTest.findByEntityId(userId).shouldBeNull()

			val rowChecksum = RowChecksum(entityId = user.id, entityName = entityName, checksum = "checksum", compositeId1 = null, compositeId2 = null)
			objectUnderTest.save(rowChecksum)
			newTransaction()

			objectUnderTest.findByEntityId(userId) shouldBe rowChecksum
			objectUnderTest.findAllByEntityName(RealmEntity::class.java.name).shouldBeEmpty()
			objectUnderTest.findAllByEntityName(entityName) shouldBe listOf(rowChecksum)
			objectUnderTest.deleteRowChecksums(userId)
			objectUnderTest.findAllByEntityName(entityName).shouldBeEmpty()
		}

		test("find extraneous user entities") {
			val entityName = UserEntity::class.java.name
			val userId = RowChecksumKeyId(entityName, user.id)
			val rowChecksum = RowChecksum(entityId = user.id, entityName = entityName, checksum = "checksum", compositeId1 = null, compositeId2 = null)
			val user2 = UserEntity().apply { id = "jens" }
			val mapping1 =
				ClientScopeClientMappingEntity().apply {
					clientScopeId = "clientScopeId1"
					clientId = "clientId1"
				}
			val info1 = entityManager.lookupEntityInfo(mapping1).shouldBeRight()
			val rowChecksum1 = RowChecksum(entityId = user.id, entityName = info1.entityName, checksum = "checksum", compositeId1 = null, compositeId2 = null)

			entityManager.persist(user)
			entityManager.persist(mapping1)
			entityManager.persist(user2)
			objectUnderTest.save(rowChecksum)
			objectUnderTest.save(rowChecksum1)
			newTransaction()

			objectUnderTest.findByEntityId(userId) shouldBe rowChecksum
			objectUnderTest.findAllByEntityName(entityName) shouldBe listOf(rowChecksum)
			objectUnderTest.findExtraneousEntitiesByStringId(entityName) shouldBe listOf("jens")
		}

		test("find ClientScopeClientMappingEntity entities with composite key") {
			val entity =
				ClientScopeClientMappingEntity().apply {
					clientScopeId = "clientScopeId"
					clientId = "clientId"
				}
			val id = ClientScopeClientMappingEntity.Key("clientScopeId", "clientId")

			entityManager.persist(user)
			entityManager.persist(entity)
			newTransaction()

			entityManager.find(ClientScopeClientMappingEntity::class.java, id) shouldBe entity

			entityManager.createQuery("FROM ClientScopeClientMappingEntity WHERE id = :id").setParameter("id", id).singleResult shouldBe entity
			entityManager
				.createQuery("FROM ClientScopeClientMappingEntity WHERE id = :id")
				.setParameter("id", ClientScopeClientMappingEntity.Key("jens", "clientId"))
				.resultList
				.shouldBeEmpty()
		}

		test("find deleted UserRoleMappingEntity entities with composite key") {
			entityManager.persist(user)

			findAbandonedChecksumsByCompositeKey(urmel1, urmel2)
		}

		test("find deleted ClientScopeClientMappingEntity entities with composite key") {
			findAbandonedChecksumsByCompositeKey(mapping1, mapping2)
		}

		test("find extraneous UserRoleMappingEntity entities with composite key") {
			findExtraneousEntitiesByCompositeKey(
				urmel1, urmel2, UserRoleMappingEntity.Key(user, "roleId2")
			)
		}

		test("find extraneous ClientScopeClientMappingEntity entities with composite key") {
			findExtraneousEntitiesByCompositeKey(
				mapping1, mapping2, ClientScopeClientMappingEntity.Key("clientScopeId2", "clientId1")
			)
		}
	}

	private fun findExtraneousEntitiesByCompositeKey(
		mapping1: Any,
		mapping2: Any,
		key: Any
	) {
		val info1 = entityManager.lookupEntityInfo(mapping1).shouldBeRight()
		val compositeKeys = info1.entityId.idAsMap().values.toList()
		val rowChecksum1 = RowChecksum(
			entityId = info1.id, entityName = info1.entityName, checksum = "checksum",
			compositeId1 = compositeKeys[0], compositeId2 = compositeKeys[1]
		)
		val rowChecksum =
			RowChecksum(entityId = user.id, entityName = UserEntity::class.java.name, checksum = "checksum", compositeId1 = null, compositeId2 = null)

		entityManager.persist(user)
		entityManager.persist(mapping1)
		entityManager.persist(mapping2)
		entityManager.persist(rowChecksum1)
		entityManager.persist(rowChecksum)

		newTransaction()

		val primaryKey = spreeConfiguration.findPrimaryKeyInformation(info1.entityName).shouldNotBeNull()

		objectUnderTest.findExtraneousEntitiesByCompositeKey(info1.entityName, primaryKey).shouldContainExactly(key)
	}

	private fun findAbandonedChecksumsByCompositeKey(mapping1: Any, mapping2: Any) {
		entityManager.persist(mapping1)

		val info1 = entityManager.lookupEntityInfo(mapping1).shouldBeRight()
		val compositeKeys1 = info1.entityId.idAsMap().values.toList()
		val rowChecksum1 = RowChecksum(entityId = info1.id, entityName = info1.entityName, checksum = "checksum",
			compositeId1 = compositeKeys1[0], compositeId2 = compositeKeys1[1])
		val info2 = entityManager.lookupEntityInfo(mapping2).shouldBeRight()
		val compositeKeys2 = info2.entityId.idAsMap().values.toList()
		val rowChecksum2 = RowChecksum(entityId = info2.id, entityName = info2.entityName, checksum = "checksum",
			compositeId1 = compositeKeys2[0], compositeId2 = compositeKeys2[1])

		entityManager.persist(rowChecksum1)
		entityManager.persist(rowChecksum2)

		newTransaction()

		val primaryKey = spreeConfiguration.findPrimaryKeyInformation(info1.entityName).shouldNotBeNull()

		objectUnderTest.findAbandonedChecksumsByCompositeKey(info1.entityName, primaryKey).shouldContainExactly(rowChecksum2)
	}
}
