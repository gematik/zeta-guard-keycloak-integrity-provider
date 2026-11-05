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

import de.spree.keycloak.commons.AbstractDatabaseTest
import de.spree.keycloak.commons.EntityConverter.lookupEntityInfo
import de.spree.keycloak.commons.TestData.user
import de.spree.keycloak.commons.configuration.SystemState
import de.spree.keycloak.integrity.EntityDao
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldContainExactly
import io.kotest.matchers.shouldBe
import org.keycloak.models.jpa.entities.RealmEntity
import org.keycloak.models.jpa.entities.UserEntity

class EntityDaoTest : AbstractDatabaseTest() {
  private lateinit var objectUnderTest: EntityDao

  init {
    beforeTest {
      objectUnderTest = EntityDao(entityManager)

      systemStateService.setSystemState(SystemState.OPERATIONAL)
    }

    test("retrieve row count") {
      entityManager.persist(user)

      objectUnderTest.getEntityRowCount(RealmEntity::class.java.name) shouldBe 0
      objectUnderTest.getEntityRowCount(UserEntity::class.java.name) shouldBe 1

      entityManager.remove(user)
    }

    test("load entities") {
      entityManager.persist(user)

      objectUnderTest.loadEntities(RealmEntity::class.java.name).shouldBeEmpty()
      objectUnderTest.loadEntities(UserEntity::class.java.name).shouldContainExactly(user)

      entityManager.remove(user)
      newTransaction()
      objectUnderTest.loadEntities(RealmEntity::class.java.name).shouldBeEmpty()
    }

    test("update property") {
      entityManager.persist(user)

      newTransaction()
      entityManager.find(UserEntity::class.java, user.id)?.username shouldBe "jens"
      val entityInfo = entityManager.lookupEntityInfo(user).shouldBeRight()
      objectUnderTest.update(entityInfo, "username", "hippe")
      newTransaction()
      entityManager.find(UserEntity::class.java, user.id)?.username shouldBe "hippe"
    }
  }
}
