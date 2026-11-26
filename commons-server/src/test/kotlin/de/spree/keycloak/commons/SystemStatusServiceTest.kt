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

import de.spree.keycloak.commons.configuration.SystemStatus
import de.spree.keycloak.commons.configuration.SystemStatusService
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockk
import jakarta.persistence.EntityManager
import org.jboss.logmanager.Logger
import org.keycloak.connections.jpa.JpaConnectionProvider

class SystemStatusServiceTest : AbstractMockTest() {
  init {
    val objectUnderTest = SystemStatusService().setValue("spreeLogger", Logger.getLogger("de.spree.keycloak"))
    val exception = Exception()
    val jpaConnectionProvider: JpaConnectionProvider = mockk()
    val entityManager: EntityManager = mockk(relaxed = true)

    beforeTest {
      every { keycloakSession.getProvider(JpaConnectionProvider::class.java) } returns jpaConnectionProvider
      every<EntityManager> { jpaConnectionProvider.entityManager } returns entityManager
    }

    test("Subsequent state is OK") {
      objectUnderTest.setSystemStatus(SystemStatus.RUNNING)
      objectUnderTest.currentSystemStatus() shouldBe SystemStatus.RUNNING
    }

    test("Setting to previous state is not OK") {
      objectUnderTest.setSystemStatus(SystemStatus.RUNNING)
      shouldThrow<IllegalStateException> { objectUnderTest.setSystemStatus(SystemStatus.STARTUP_JPA) }
    }

    test("If already in error state, stay there") {
      objectUnderTest.setSystemStatus(SystemStatus.ERROR_DECRYPTION, exception)
      objectUnderTest.setSystemStatus(SystemStatus.ERROR_ROW_CHECKSUM)

      objectUnderTest.currentSystemStatus() shouldBe SystemStatus.ERROR_DECRYPTION
      objectUnderTest.error shouldBe exception
    }

    test("Reset state") {
      objectUnderTest.setSystemStatus(SystemStatus.ERROR_DECRYPTION, exception)
      objectUnderTest.resetStatus()

      objectUnderTest.currentSystemStatus() shouldBe SystemStatus.RUNNING
      objectUnderTest.error.shouldBeNull()
    }
  }
}
