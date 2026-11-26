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

import de.spree.keycloak.commons.EMAIL
import de.spree.keycloak.commons.TestData.user
import de.spree.keycloak.commons.shouldBeBase64
import io.kotest.core.spec.Order
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import org.keycloak.models.jpa.entities.UserEntity

@Order(3)
class ColumnEncryptionIT : AbstractDatabaseIT() {
  init {
    test("Check column encryption") {
      runJPA {
        val loadedUser1 =
            it.entityManager.createQuery("SELECT c FROM UserEntity c WHERE id = :id", UserEntity::class.java).setParameter("id", user.id).singleResult

        loadedUser1 shouldBe user
        loadedUser1.email shouldNotBe EMAIL
        loadedUser1.email.shouldBeBase64()

        updateUserEmail(EMAIL2)
        it.newTransaction()
        val loadedUser2 =
            it.entityManager.createQuery("SELECT c FROM UserEntity c WHERE id = :id", UserEntity::class.java).setParameter("id", user.id).singleResult

        loadedUser2.email shouldNotBe loadedUser1.email
        loadedUser2.email.shouldBeBase64()
      }
    }
  }
}
