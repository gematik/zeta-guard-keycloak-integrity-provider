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
package de.spree.keycloak.it

import de.spree.keycloak.commons.*
import de.spree.keycloak.commons.configuration.SystemState
import de.spree.keycloak.integrity.RowChecksumDao
import de.spree.keycloak.integrity.RowChecksumKeyId
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.Order
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.ints.shouldBeGreaterThan
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import jakarta.ws.rs.NotFoundException
import org.keycloak.models.jpa.entities.ClientScopeClientMappingEntity
import org.keycloak.models.jpa.entities.ComponentConfigEntity
import org.keycloak.models.jpa.entities.UserEntity

@Order(1)
class RowChecksumIT : AbstractDatabaseIT() {
  val userId = RowChecksumKeyId(UserEntity::class.java.name, USER_ID)

  init {
    test("Verify row checksums are initially created") {
      runJPA { jpa ->
        val checksumService = RowChecksumDao(jpa.entityManager)
        val entityName = ComponentConfigEntity::class.java.name
        val rowChecksums = checksumService.findAllByEntityName(entityName).shouldNotBeEmpty()
        val checksums = rowChecksums.filter { it.entityName == entityName }

        checksums.shouldNotBeEmpty().first().checksum.shouldBeBase64()
      }
    }

    // https://wiki.tech.spree.de/wiki/spaces/120137/pages/628555793/Integrit+tspr+fung+-+Szenarien#Aktualisieren-einer-Entit%C3%A4t-(POST-UPDATE)
    test("Entity checksum is updated when user is updated") {
      runJPA { jpa ->
        val checksumService = RowChecksumDao(jpa.entityManager)
        val checksum1 = checksumService.findByEntityId(userId).shouldNotBeNull()
        val entityName = UserEntity::class.java.name

        checksum1.checksum.shouldBeBase64()
        checksum1.entityName shouldBe entityName

        updateUserEmail(EMAIL3)
        jpa.newTransaction()

        val checksum2 = checksumService.findByEntityId(userId).shouldNotBeNull()
        checksum2.checksum.shouldBeBase64()
        checksum2.checksum shouldNotBe checksum1.checksum

        KeycloakWebClient().startScan().shouldBeRight()
      }
    }

    // https://wiki.tech.spree.de/wiki/spaces/120137/pages/628555793/Integrit+tspr+fung+-+Szenarien#Aktualisieren-einer-Entit%C3%A4t-(POST-UPDATE)
    test("Entity checksum is updated when user attributes are updated") {
      runJPA { jpa ->
        val checksumService = RowChecksumDao(jpa.entityManager)
        val checksum1 = checksumService.findByEntityId(userId).shouldNotBeNull()
        val entityName = UserEntity::class.java.name
        val keycloakWebClient = KeycloakWebClient()

        checksum1.checksum.shouldBeBase64()
        checksum1.entityName shouldBe entityName

        keycloakWebClient.setUserAttributes(USER_ID, "bla" to listOf("blubb"), "jens" to listOf("hippe")).shouldBeRight()
        jpa.newTransaction()
        keycloakWebClient.startScan().shouldBeRight()
        keycloakWebClient.setUserAttributes(USER_ID, "jens" to listOf("hippe", "beckmann")).shouldBeRight()
        jpa.newTransaction()

        val checksum2 = checksumService.findByEntityId(userId).shouldNotBeNull()
        checksum2.checksum.shouldBeBase64()
        checksum2.checksum shouldNotBe checksum1.checksum

        keycloakWebClient.startScan().shouldBeRight()
      }
    }

    // https://wiki.tech.spree.de/wiki/spaces/120137/pages/628555793/Integrit+tspr+fung+-+Szenarien#Speichern-einer-Entit%C3%A4t-(POST-PERSIST)
    test("Entity checksum is updated when user is added") {
      runJPA { jpa ->
        val checksumService = RowChecksumDao(jpa.entityManager)
        val entityName = UserEntity::class.java.name
        val userId = addUser(TestData.newUser).shouldNotBeNull()
        val checksum = checksumService.findByEntityId(RowChecksumKeyId(UserEntity::class.java.name, userId)).shouldNotBeNull()

        checksum.checksum.shouldBeBase64()
        checksum.entityName shouldBe entityName
      }
    }

    // https://wiki.tech.spree.de/wiki/spaces/120137/pages/628555793/Integrit+tspr+fung+-+Szenarien#Laden-einer-Entit%C3%A4t--(LOAD)
    test("Entity with tampered checksum is not loaded") {
      getUser(USER_ID).shouldNotBeNull()

      runJPA { jpa ->
        val checksumService = RowChecksumDao(jpa.entityManager)
        val checksum1 = checksumService.findByEntityId(userId).shouldNotBeNull()

        val someHash = "TheQuickBrownFoxJumpsOverTheLazyDog1234567890xyz".toByteArray().toBase64()
        checksum1.checksum = someHash

        jpa.newTransaction()
      }

      shouldThrow<Exception> { getUser(USER_ID) }.message shouldContain "Internal Server Error"

      KeycloakWebClient().systemStateEnum() shouldBe SystemState.ERROR_ROW_CHECKSUM
    }

    test("Manipulation of encrypted user data is detected") {
      runJPA { jpa ->
        val user = jpa.entityManager.find(UserEntity::class.java, USER_ID)
        val someHash = "TheQuickBrownFoxJumpsOverTheLazyDog1234567890xyz".toByteArray().toBase64()

        user.setEmail(someHash, false)
        jpa.newTransaction()
      }

      shouldThrow<Exception> { getUser(USER_ID) }.message shouldContain "Internal Server Error"

      KeycloakWebClient().systemStateEnum() shouldBe SystemState.ERROR_DECRYPTION
    }

    test("Manipulation of user data is detected") {
      runJPA { jpa ->
        val user = jpa.entityManager.find(UserEntity::class.java, USER_ID)

        user.firstName = "Torsten"
        jpa.newTransaction()
      }

      shouldThrow<Exception> { getUser(USER_ID) }.message shouldContain "Internal Server Error"

      KeycloakWebClient().systemStateEnum() shouldBe SystemState.ERROR_ROW_CHECKSUM
    }

    test("Entity without checksum is not loaded") {
      getUser(USER_ID).shouldNotBeNull()

      runJPA { jpa ->
        val checksumService = RowChecksumDao(jpa.entityManager)
        val checksum1 = checksumService.findByEntityId(userId).shouldNotBeNull()

        jpa.entityManager.remove(checksum1)
        jpa.newTransaction()
        checksumService.findByEntityId(userId).shouldBeNull()
      }

      shouldThrow<Exception> { getUser(USER_ID) }.message shouldContain "Internal Server Error"
      KeycloakWebClient().systemStateEnum() shouldBe SystemState.ERROR_ROW_CHECKSUM
    }

    // https://wiki.tech.spree.de/wiki/spaces/120137/pages/628555793/Integrit+tspr+fung+-+Szenarien#L%C3%B6schen-einer-Entit%C3%A4t-(POST-REMOVE)
    test("Checksum is deleted when entity is deleted") {
      getUser(USER_ID).shouldNotBeNull()

      runJPA { jpa ->
        val checksumService = RowChecksumDao(jpa.entityManager)

        checksumService.findByEntityId(userId).shouldNotBeNull()

        removeUser(USER_ID)

        jpa.newTransaction()
        checksumService.findByEntityId(userId).shouldBeNull()
      }

      shouldThrow<NotFoundException> { getUser(USER_ID) }
      KeycloakWebClient().systemStateEnum() shouldBe SystemState.OPERATIONAL
    }

    // Testing use case where a DELETE query is used to delete an entity, see ClientScopeClientMappingEntity "deleteClientScopeClientMappingByClient"
    test("Entity checksum is updated when client is deleted") {
      runJPA { jpa ->
        val checksumService = RowChecksumDao(jpa.entityManager)
        val entityName = ClientScopeClientMappingEntity::class.java.name
        val keycloakWebClient = KeycloakWebClient()
        val scopesBefore = checksumService.findAllByEntityName(entityName).size

        val clientId = createClient("jens").shouldNotBeNull()
        jpa.newTransaction()

        val scopesAfter1 = checksumService.findAllByEntityName(entityName).size
        scopesAfter1 shouldBeGreaterThan scopesBefore

        deleteClient(clientId)
        jpa.newTransaction()

        val scopesAfter2 = checksumService.findAllByEntityName(entityName).size
        scopesAfter2 shouldBe scopesBefore

        keycloakWebClient.startScan().shouldBeRight()
      }
    }

    // Testing use case where a INSERT query is used to add an entity, see ClientScopeClientMappingEntity "addClientScopeToAllClients"
    test("Entity checksum is updated when client scope is added") {
      runJPA { jpa ->
        val checksumService = RowChecksumDao(jpa.entityManager)
        val entityName = ClientScopeClientMappingEntity::class.java.name
        val keycloakWebClient = KeycloakWebClient()
        val scopesBefore = checksumService.findAllByEntityName(entityName).size
        val scopeId = createClientScope("jens").shouldNotBeNull()

        keycloakWebClient.addClientScopeToAllClients(scopeId).shouldBeRight()
        jpa.newTransaction()

        keycloakWebClient.startScan().shouldBeRight()

        val scopesAfter = checksumService.findAllByEntityName(entityName).size
        scopesAfter shouldBeGreaterThan scopesBefore
      }
    }
  }
}
