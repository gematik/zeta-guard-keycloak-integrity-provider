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
package de.spree.keycloak.commons

import de.spree.keycloak.commons.EntityConverter.convertToJSON
import de.spree.keycloak.commons.EntityConverter.lookupEntityInfo
import de.spree.keycloak.commons.TestData.client1
import de.spree.keycloak.commons.TestData.clientAttributeEntity
import de.spree.keycloak.commons.TestData.clientAttributeEntityKey
import de.spree.keycloak.commons.TestData.user
import io.kotest.assertions.arrow.core.shouldBeLeft
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain

class EntityConverterTest : AbstractMockTest() {
  init {
    test("Returns EntityInfo for plain user entity") {
      val result = entityManager.lookupEntityInfo(user).shouldBeRight()

      result.entityId.id shouldBe USER_ID
      result.tableName shouldBe "USER_ENTITY"
      result.entity shouldBe user
      result.entityId.toIdObject() shouldBe USER_ID

      entityManager.lookupEntityInfo("jens").shouldBeLeft()
    }

    test("Returns EntityInfo client attribute entity with complex composite ID") {
      val result = entityManager.lookupEntityInfo(clientAttributeEntity).shouldBeRight()

      result.entityId.id shouldContain IdObject(client1.id).toJSON()
      result.tableName shouldBe "CLIENT_ATTRIBUTES"
      result.entity shouldBe clientAttributeEntity

      result.entityId.toIdObject() shouldBe clientAttributeEntityKey
    }

    test("JSON serialization for complex object with recursive structure") {
      val result = entityManager.convertToJSON(client1).shouldBeRight()

      result shouldContain "\"id\":\"${client1.id}\""
      result shouldContain """attributes":[{"id":"{\"client\":{\"id\":\"${client1.id}\"},\"name\":\"${clientAttributeEntity.name}\"}"""
    }
  }
}
