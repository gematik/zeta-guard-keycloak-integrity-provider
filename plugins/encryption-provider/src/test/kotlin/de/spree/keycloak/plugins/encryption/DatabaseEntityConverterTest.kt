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
import de.spree.keycloak.commons.EntityConverter.convertToJSON
import de.spree.keycloak.commons.IdObject
import de.spree.keycloak.commons.TestData
import de.spree.keycloak.commons.TestData.component
import de.spree.keycloak.commons.TestData.componentConfig1
import de.spree.keycloak.commons.TestData.componentConfig2
import de.spree.keycloak.commons.TestData.realm
import de.spree.keycloak.commons.TestData.realmAttribute
import de.spree.keycloak.commons.USER_ID
import de.spree.keycloak.commons.toJSON
import io.kotest.assertions.arrow.core.shouldBeLeft
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.matchers.comparables.shouldBeLessThan
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain

class DatabaseEntityConverterTest : AbstractDatabaseTest() {
  init {
    test("Converting component to JSON should flatten hierarchies") {
      val json = entityManager.convertToJSON(component).shouldBeRight()

      json shouldContain "\"realm\":${idObject(realm.id)}"
      json shouldContain "\"componentConfigs\":[${idObject(componentConfig1.id)},${idObject(componentConfig2.id)}]"

      // Alphabetial order
      json.indexOf("\"componentConfigs\":") shouldBeLessThan json.indexOf("\"realm\":")
    }

    test("Converting component config to JSON should be flat") {
      val json = entityManager.convertToJSON(component.componentConfigs.first()).shouldBeRight()

      json shouldContain "\"component\":${idObject(component.id)}"
      json.indexOf("\"component\":") shouldBeLessThan json.indexOf("\"id\":")
    }

    test("Converting realm to JSON should be flat") {
      val json = entityManager.convertToJSON(realm).shouldBeRight()

      json shouldContain "\"refreshTokenMaxReuse\":42"
      json shouldContain """"attributes":[{"id":"{\"name\":\"${realmAttribute.name}\",\"realm\":{\"id\":\"${realm.id}\"}}"}]"""
    }

    test("Converting realm atribute to JSON should be flat") {
      val json = entityManager.convertToJSON(realmAttribute).shouldBeRight()

      json shouldBe "{\"name\":\"${realmAttribute.name}\",\"realm\":${idObject(realm.id)},\"value\":\"${realmAttribute.value}\"}"
    }

    test("Is no entity") { entityManager.convertToJSON(listOf("jens")).shouldBeLeft() }

    test("Converting user omits »federatedIdentities« property") {
      val json = entityManager.convertToJSON(TestData.user).shouldBeRight()

      json shouldContain """"id":"$USER_ID""""
      json shouldNotContain """"federatedIdentities":"""
    }
  }
}

private fun idObject(id: String) = IdObject(id).toJSON()
