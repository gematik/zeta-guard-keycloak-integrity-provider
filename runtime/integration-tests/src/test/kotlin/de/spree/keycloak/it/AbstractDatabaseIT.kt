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

package de.spree.keycloak.it

import de.spree.keycloak.commons.AbstractCDITest
import de.spree.keycloak.commons.configuration.SpreeEntityConfiguration
import de.spree.keycloak.commons.configuration.SystemState
import de.spree.keycloak.commons.toEnum
import de.spree.keycloak.commons.toYamlObject
import de.spree.keycloak.integrity.RowChecksum
import de.spree.keycloak.integrity.TableChecksum
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.matchers.shouldBe
import java.sql.Connection
import org.hibernate.Session
import org.keycloak.models.jpa.entities.RealmLocalizationTextsEntity

const val EMAIL2 = "bla@foobar.com"
const val EMAIL3 = "jens@foobar.com"

abstract class AbstractDatabaseIT : AbstractCDITest() {
  init {
    beforeSpec { DockerControllerFactory.instance.isStarted() shouldBe true }

    afterEach {
      DockerControllerFactory.instance.resetDatabase()

      KeycloakWebClient().resetSystemState()
    }
  }

  protected fun <T> runJPA(block: (JpaEntityManagerFactory) -> T): T =
      JpaEntityManagerFactory(DockerControllerFactory.instance.dbhost, DockerControllerFactory.instance.dbport, *entities.toTypedArray()).use {
        it.entityManager.transaction.begin()

        try {
          block(it).also { _ -> it.entityManager.transaction.commit() }
        } finally {
          it.entityManager.close()

          clearCaches()
        }
      }

  protected fun runWithConnection(block: (Connection) -> Unit) =
      JpaEntityManagerFactory(DockerControllerFactory.instance.dbhost, DockerControllerFactory.instance.dbport, *entities.toTypedArray()).use {
        it.entityManager.unwrap(Session::class.java).doWork { connection -> connection.use { block(connection) } }
      }

  companion object {
    val CHECKSUM_ENTITIES = listOf(RowChecksum::class.java, TableChecksum::class.java)
    val DEPENDENT_ENTITIES = listOf(RealmLocalizationTextsEntity::class.java)
    val configuration: SpreeEntityConfiguration by lazy {
      val stream = AbstractDatabaseIT::class.java.getResourceAsStream("/spree-configuration.yml")!!
      stream.toYamlObject<SpreeEntityConfiguration>()
    }

    val KEYCLOAK_ENTITIES: List<Class<*>> by lazy { configuration.entities.map { Class.forName(it.name) } }

    val entities: List<Class<*>> by lazy { CHECKSUM_ENTITIES + KEYCLOAK_ENTITIES + DEPENDENT_ENTITIES }
  }
}

fun KeycloakWebClient.systemStateEnum() = systemState().shouldBeRight().reponseObject.toEnum<SystemState>()
