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

import de.spree.keycloak.commons.TestData
import de.spree.keycloak.commons.USER_ID
import de.spree.keycloak.commons.shouldBeBase64
import de.spree.keycloak.integrity.TableChecksumDao
import io.kotest.core.spec.Order
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import org.keycloak.models.jpa.entities.ComponentConfigEntity
import org.keycloak.models.jpa.entities.IdentityProviderEntity
import org.keycloak.models.jpa.entities.UserEntity

@Order(1)
class TableChecksumIT : AbstractDatabaseIT() {
  init {
    test("Verify table checksums have been created initially") {
      runJPA { jpa ->
        val checksumService = TableChecksumDao(jpa.entityManager)
        val entityName = ComponentConfigEntity::class.java.name
        val checksum = checksumService.findByEntityName(entityName).shouldNotBeNull()

        checksum.entityName shouldBe entityName
        checksum.checksum.shouldBeBase64()
      }
    }

    // https://wiki.tech.spree.de/wiki/spaces/120137/pages/628555793/Integrit+tspr+fung+-+Szenarien#Aktualisieren-einer-Entit%C3%A4t-(POST-UPDATE)
    test("Table checksum is NOT updated when entity is updated") {
      runJPA { jpa ->
        val checksumService = TableChecksumDao(jpa.entityManager)
        val entityName = UserEntity::class.java.name
        val checksum1 = checksumService.findByEntityName(entityName).shouldNotBeNull()

        checksum1.checksum.shouldBeBase64()

        updateUserEmail(EMAIL3)
        jpa.newTransaction()

        val checksum2 = checksumService.findByEntityName(entityName).shouldNotBeNull()
        checksum2 shouldBe checksum1 // not affected by update

        checksumService.findByEntityName(IdentityProviderEntity::class.java.name).shouldBeNull()
      }
    }

    // https://wiki.tech.spree.de/wiki/spaces/120137/pages/628555793/Integrit+tspr+fung+-+Szenarien#Speichern-einer-Entit%C3%A4t-(POST-PERSIST)
    test("Table checksum is updated when entity is added") {
      runJPA { jpa ->
        val checksumService = TableChecksumDao(jpa.entityManager)
        val entityName = UserEntity::class.java.name
        val checksum1 = checksumService.findByEntityName(entityName).shouldNotBeNull()

        addUser(TestData.newUser).shouldNotBeNull()
        jpa.newTransaction()

        val checksum2 = checksumService.findByEntityName(entityName).shouldNotBeNull()
        checksum2 shouldNotBe checksum1
      }
    }

    // https://wiki.tech.spree.de/wiki/spaces/120137/pages/628555793/Integrit+tspr+fung+-+Szenarien#L%C3%B6schen-einer-Entit%C3%A4t-(POST-REMOVE)
    test("Table checksum is updated when entity is deleted") {
      runJPA { jpa ->
        val checksumService = TableChecksumDao(jpa.entityManager)
        val entityName = UserEntity::class.java.name
        val checksum1 = checksumService.findByEntityName(entityName).shouldNotBeNull()

        removeUser(USER_ID)
        jpa.newTransaction()

        val checksum2 = checksumService.findByEntityName(entityName).shouldNotBeNull()
        checksum2 shouldNotBe checksum1
      }
    }

    // https://wiki.tech.spree.de/wiki/spaces/120137/pages/628555793/Integrit+tspr+fung+-+Szenarien#L%C3%B6schen-einer-Entit%C3%A4t-(POST-REMOVE)
    test("Checksum is deleted when there are no more entities") {
      createIDP().shouldNotBeNull()

      runJPA { jpa ->
        val checksumService = TableChecksumDao(jpa.entityManager)
        val entityName = IdentityProviderEntity::class.java.name
        checksumService.findByEntityName(entityName).shouldNotBeNull()

        removeIDP()
        jpa.newTransaction()

        checksumService.findByEntityName(entityName).shouldBeNull()
      }
    }
  }

}
