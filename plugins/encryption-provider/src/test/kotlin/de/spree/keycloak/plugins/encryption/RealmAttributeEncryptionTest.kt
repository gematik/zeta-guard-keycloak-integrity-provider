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
import de.spree.keycloak.commons.TestData
import de.spree.keycloak.commons.configuration.SystemState
import de.spree.keycloak.plugins.encryption.jpa.SpreeEncryptionAttributeConverter
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import jakarta.persistence.ConnectionFunction
import java.sql.Connection
import org.keycloak.models.jpa.entities.RealmAttributeEntity

private const val ATTRIBUTE_VALUE = "jens"

class RealmAttributeEncryptionTest : AbstractDatabaseTest() {
  init {
    beforeTest { systemStateService.setSystemState(SystemState.OPERATIONAL) }

    test("Store and retrieve encrypted realm attribute (@Nationalized column)") {
      entityManager.persist(TestData.realm)
      entityManager.persist(TestData.realmAttribute)
      newTransaction()

      loadValueFromDB(TestData.realmAttribute.name) shouldNotBe ATTRIBUTE_VALUE

      loadAttribute().value shouldBe ATTRIBUTE_VALUE
    }

    // Hibernate applies the encrypting converter to bulk update parameters as well, which is why writing ciphertext
    // (as de.spree.keycloak.integrity.ScannerService does) has to suspend the conversion, see EntityDao.update.
    test("JPQL bulk update passes its parameter through the encrypting converter") {
      val alreadyEncrypted = "PRE-ENCRYPTED-VALUE"

      bulkUpdateValue(alreadyEncrypted)

      loadValueFromDB(TestData.realmAttribute.name) shouldNotBe alreadyEncrypted
    }

    test("Suspending the conversion writes and reads values verbatim") {
      val alreadyEncrypted = "PRE-ENCRYPTED-VALUE"

      SpreeEncryptionAttributeConverter.withoutConversion { bulkUpdateValue(alreadyEncrypted) }

      loadValueFromDB(TestData.realmAttribute.name) shouldBe alreadyEncrypted
      SpreeEncryptionAttributeConverter.withoutConversion { loadAttribute().value } shouldBe alreadyEncrypted
    }
  }

  private fun bulkUpdateValue(value: String) {
    entityManager
        .createQuery("UPDATE RealmAttributeEntity e SET e.value = :value WHERE e.name = :name")
        .setParameter("value", value)
        .setParameter("name", TestData.realmAttribute.name)
        .executeUpdate()

    newTransaction()
  }

  private fun loadAttribute(): RealmAttributeEntity =
      entityManager
          .createQuery("FROM RealmAttributeEntity a WHERE a.name = :name", RealmAttributeEntity::class.java)
          .setParameter("name", TestData.realmAttribute.name)
          .singleResult

  private fun loadValueFromDB(name: String): String? =
      entityManager.callWithConnection(
          ConnectionFunction<Connection, String> {
            val rs = it.createStatement().executeQuery("SELECT \"VALUE\" FROM \"REALM_ATTRIBUTE\" WHERE \"NAME\" = '$name'")
            require(rs.next()) { "Realm attribute not found" }
            rs.getString(1)
          }
      )
}
