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

import de.spree.keycloak.commons.configuration.SystemState
import de.spree.keycloak.commons.configuration.SystemStateService
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockk
import jakarta.persistence.EntityManager
import org.jboss.logmanager.Logger
import org.keycloak.connections.jpa.JpaConnectionProvider
import org.keycloak.models.jpa.entities.UserAttributeEntity
import java.time.Instant

class SystemStateServiceTest : AbstractMockTest() {
  init {
    val objectUnderTest = SystemStateService().apply {
      setValue("spreeLogger", Logger.getLogger("de.spree.keycloak"))
      setValue("entityConfiguration", spreeConfiguration)
    }
    val exception = Exception()
    val jpaConnectionProvider: JpaConnectionProvider = mockk()
    val entityManager: EntityManager = mockk(relaxed = true)
    val volatileEntity = UserAttributeEntity::class.qualifiedName!! // configured as volatile

    beforeTest {
      every { keycloakSession.getProvider(JpaConnectionProvider::class.java) } returns jpaConnectionProvider
      every<EntityManager> { jpaConnectionProvider.entityManager } returns entityManager
      systemStateService.resetState(SystemState.STARTUP)
    }

    test("Subsequent state is OK") {
      objectUnderTest.setSystemState(SystemState.OPERATIONAL)
      objectUnderTest.currentSystemState() shouldBe SystemState.OPERATIONAL
    }

    test("Setting to previous state is not OK") {
      objectUnderTest.setSystemState(SystemState.OPERATIONAL)
      shouldThrow<IllegalStateException> { objectUnderTest.setSystemState(SystemState.STARTUP_JPA) }
    }

    test("If already in error state, stay there") {
      objectUnderTest.setSystemState(SystemState.ERROR_DECRYPTION, exception)
      objectUnderTest.setSystemState(SystemState.ERROR_ROW_CHECKSUM)

      objectUnderTest.currentSystemState() shouldBe SystemState.ERROR_DECRYPTION
      objectUnderTest.error shouldBe exception
    }

    test("Does not ignore errors before operational") {
      objectUnderTest.resetState(SystemState.STARTUP)
      objectUnderTest.shouldIgnoreVolatileError(volatileEntity) shouldBe false
    }

    test("Does not ignore errors of non-volatile entities") {
      objectUnderTest.setSystemState(SystemState.OPERATIONAL)
      objectUnderTest.shouldIgnoreVolatileError("org.whatever.Test") shouldBe false
    }

    test("Ignores volatile errors within short timeframe") {
      objectUnderTest.setSystemState(SystemState.OPERATIONAL)
      objectUnderTest.shouldIgnoreVolatileError(volatileEntity) shouldBe true
      objectUnderTest.shouldIgnoreVolatileError(volatileEntity) shouldBe true
    }

    test("Handles first volatile exception") {
      val later = Instant.now().plusSeconds(60)
      objectUnderTest.setSystemState(SystemState.OPERATIONAL)
      objectUnderTest.shouldIgnoreVolatileError(volatileEntity) shouldBe true
      objectUnderTest.shouldIgnoreVolatileError(volatileEntity, "", later) shouldBe false
    }

    test("Can clear volatile exception") {
      val later = Instant.now().plusSeconds(60)
      objectUnderTest.setSystemState(SystemState.OPERATIONAL)
      objectUnderTest.shouldIgnoreVolatileError(volatileEntity) shouldBe true
      objectUnderTest.clearVolatileError(volatileEntity)
      objectUnderTest.shouldIgnoreVolatileError(volatileEntity) shouldBe true
      objectUnderTest.shouldIgnoreVolatileError(volatileEntity, "", later) shouldBe false
    }

    test("distinguishes row and table exceptions") {
      val later = Instant.now().plusSeconds(60)
      val entityId = "my_row"
      objectUnderTest.setSystemState(SystemState.OPERATIONAL)

      objectUnderTest.shouldIgnoreVolatileError(volatileEntity) shouldBe true
      objectUnderTest.shouldIgnoreVolatileError(volatileEntity, entityId) shouldBe true

      objectUnderTest.shouldIgnoreVolatileError(volatileEntity, "", later) shouldBe false
      objectUnderTest.shouldIgnoreVolatileError(volatileEntity, entityId, later) shouldBe false

      objectUnderTest.clearVolatileError(volatileEntity)
      objectUnderTest.shouldIgnoreVolatileError(volatileEntity, "", later) shouldBe true
      objectUnderTest.shouldIgnoreVolatileError(volatileEntity, entityId, later) shouldBe false

      objectUnderTest.clearVolatileError(volatileEntity, entityId)
      objectUnderTest.shouldIgnoreVolatileError(volatileEntity, "", later) shouldBe true
      objectUnderTest.shouldIgnoreVolatileError(volatileEntity, entityId, later) shouldBe true
    }

    test("Reset state") {
      objectUnderTest.setSystemState(SystemState.ERROR_DECRYPTION, exception)
      objectUnderTest.resetState()

      objectUnderTest.currentSystemState() shouldBe SystemState.OPERATIONAL
      objectUnderTest.error.shouldBeNull()
    }
  }
}
