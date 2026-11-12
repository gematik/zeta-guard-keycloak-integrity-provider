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
@file:Suppress("unused")

package de.spree.keycloak.commons

import io.kotest.matchers.Matcher
import io.kotest.matchers.MatcherResult
import io.kotest.matchers.should
import org.keycloak.models.jpa.entities.*
import org.keycloak.representations.idm.UserRepresentation

const val EMAIL = "user1@foo.bar.com"
const val USER_ID = "user1_id"

object TestData {
  val user =
      UserEntity().apply {
        id = USER_ID
        username = "jens"
        firstName = "Jens"
        lastName = "Jensen"
        isEnabled = true
        setEmail(EMAIL, false)
        federatedIdentities = mutableSetOf()
      }

  val userAttribute =
      UserAttributeEntity().apply {
        id = "userattr"
        name = "foo"
        value = "bar"
        this.user = this@TestData.user
      }

  val newUser =
      UserRepresentation().apply {
        username = "gwontz"
        firstName = "Jens"
        lastName = "Gwontz"
        email = "hippe@blubb.com"
        isEmailVerified = true
        isEnabled = true
        attributes = mapOf("foo" to listOf("bar"))
      }

  val client1 =
      ClientEntity().apply {
        id = "client1"
        name = "client1"
      }

  val clientAttributeEntity =
      ClientAttributeEntity().apply {
        name = "foo"
        value = "bar"
        client = client1
      }

  val clientAttributeEntityKey = ClientAttributeEntity.Key(clientAttributeEntity.client, clientAttributeEntity.name)

  val componentConfig1 =
      ComponentConfigEntity().apply {
        id = "config1"
        name = "foo"
        value = "bar"
      }
  val componentConfig2 =
      ComponentConfigEntity().apply {
        id = "config2"
        name = "jens"
        value = "hippe"
      }

  val component =
      ComponentEntity().apply {
        id = "component1"
        name = "jens"
      }

  val component2 =
      ComponentEntity().apply {
        id = "component2"
        name = "jens2"
      }

  val component3 =
      ComponentEntity().apply {
        id = "01234567-89ab-cdef-0123-456789abcdef"
        name = "jens3"
      }

  val realm =
      RealmEntity().apply {
        id = "realm"
        name = "realm"
        isEnabled = true
        sslRequired = "none"
        isRegistrationAllowed = true
        refreshTokenMaxReuse = 42
      }

  // Has composite ID 😬
  val realmAttribute =
      RealmAttributeEntity().apply {
        name = "hippe"
        value = "jens"
      }

  val realmAttributeKey = RealmAttributeEntity.Key(realmAttribute.realm, realmAttribute.name)

  val data: String = user.toJSON()
  val dataBytes = data.toByteArray()

  val realmLocalizationTextsEntity =
      RealmLocalizationTextsEntity().apply {
        locale = "de_DE"
        texts = mapOf("incomprehensible" to "unverständlich")
      }

  val realmLocalizationTextsEntityKey =
      RealmLocalizationTextsEntity.RealmLocalizationTextEntityKey().apply {
        locale = realmLocalizationTextsEntity.locale
      }

  val realmLocalizationTextsKey = "whatever"

  init {
    val componentConfigs = listOf(componentConfig2, componentConfig1)
    componentConfigs.forEach { it.component = component }
    component.realm = realm
    realmAttribute.realm = realm
    realmLocalizationTextsEntity.realm = realm
    realmLocalizationTextsEntityKey.realm = realm
    component.componentConfigs.addAll(componentConfigs)
    realm.components.add(component)
    realm.components.add(component2)
    realm.components.add(component3)
    realm.attributes.add(realmAttribute)
    realm.realmLocalizationTexts[realmLocalizationTextsKey] = realmLocalizationTextsEntity

    client1.attributes.add(clientAttributeEntity)
    user.attributes.add(userAttribute)
  }
}

fun beBase64() =
    Matcher<String> { value ->
      val success =
          try {
            value.fromBase64()
            true
          } catch (_: Exception) {
            false
          }

      MatcherResult(success, { "'$value' should be valid BASE64" }, { "'$value' should not be valid BASE64" })
    }

fun String.shouldBeBase64() = this should beBase64()
