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
import de.spree.keycloak.commons.EMAIL
import de.spree.keycloak.commons.TestData.user
import de.spree.keycloak.commons.configuration.SystemState
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import jakarta.persistence.ConnectionFunction
import java.sql.Connection
import org.keycloak.models.jpa.entities.UserEntity

private const val EMAIL2 = "bla@foo.bar.com"

class UserEntityEncryptionTest : AbstractDatabaseTest() {
  init {
    beforeTest { @Suppress("UNCHECKED_CAST") systemStateService.setSystemState(SystemState.OPERATIONAL) }

    test("Store and retrieve encrypted user email") {
      entityManager.persist(user)
      newTransaction()

      val encryptedEmail1 = loadEmailFromDB(user) shouldNotBe EMAIL

      val userEntity1 = entityManager.find(UserEntity::class.java, user.id) shouldBe user
      userEntity1.email shouldBe EMAIL
      userEntity1.setEmail(EMAIL2, true)

      newTransaction()

      val encryptedEmail2 = loadEmailFromDB(user) shouldNotBe EMAIL
      encryptedEmail2 shouldNotBe encryptedEmail1

      val userEntity2 = entityManager.find(UserEntity::class.java, user.id) shouldBe user
      userEntity2.email shouldBe EMAIL2
    }
  }

  private fun loadEmailFromDB(user: UserEntity): String? =
      entityManager.callWithConnection(
          ConnectionFunction<Connection, String> {
            val rs = it.createStatement().executeQuery("SELECT email FROM user_entity WHERE id = '${user.id}'")
            require(rs.next()) { "User not found" }
            rs.getString(1)
          }
      )
}
