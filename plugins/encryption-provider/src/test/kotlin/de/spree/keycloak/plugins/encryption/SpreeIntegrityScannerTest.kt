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

import arrow.core.right
import de.spree.keycloak.commons.*
import de.spree.keycloak.commons.TestData.user
import de.spree.keycloak.commons.configuration.SystemStatus
import de.spree.keycloak.commons.debug.SpreeLog
import de.spree.keycloak.integrity.*
import de.spree.keycloak.plugins.integrity.Action.INITIALIZE
import de.spree.keycloak.plugins.integrity.EntityAction
import io.kotest.assertions.arrow.core.shouldBeLeft
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.jboss.logmanager.Logger
import org.keycloak.models.jpa.entities.UserEntity

class SpreeIntegrityScannerTest : AbstractMockTest() {
  private val objectUnderTest = SpreeIntegrityScanner
  private val tableChecksumService = mockk<TableChecksumService>()
  private val rowChecksumService = mockk<RowChecksumService>()
  private val scannerService = mockk<ScannerService>()
  private val entityInfo = EntityInfo(EntityId(USER_ID), "USER_ENTITY", user)
  private val entityName = UserEntity::class.qualifiedName!!
  private val action = EntityAction(INITIALIZE, entityName, entityManager)

  init {
    beforeTest {
      trainCDIService(tableChecksumService)
      trainCDIService(rowChecksumService)
      trainCDIService(signingService)
      trainCDIService(entityManager)
      trainCDIService(scannerService)

      every { tableChecksumService.isInitialState() } returns true.right()
      every { rowChecksumService.isInitialState() } returns true.right()
      every { scannerService.loadEntities(any()) } returns emptyList<EntityInfo>().right()
      every { scannerService.loadEntities(entityName) } returns listOf(entityInfo).right()

      every { rowChecksumService.updateEntityInfoChecksum(entityInfo, action) } returns SimpleSuccess.right()
      every { tableChecksumService.updateTableChecksum(action) } returns SimpleSuccess.right()
      every { tableChecksumService.checkTableChecksum(any()) } returns SimpleSuccess.right()

      every { scannerService.update(entityInfo, any(), any()) } returns true.right()

      trainCDIService(Logger.getLogger("de.spree.keycloak"), SpreeLog())
    }

    test("Initializing checksums and encryption") {
      objectUnderTest.scannerStatus shouldBe ScannerStatus.IDLE
      objectUnderTest.initializeRealm().shouldBeRight()
      objectUnderTest.scannerStatus shouldBe ScannerStatus.IDLE

      verify { rowChecksumService.updateEntityInfoChecksum(entityInfo, action) }
      verify { tableChecksumService.updateTableChecksum(action) }
      verify { scannerService.update(entityInfo, "email", any()) }
      verify { scannerService.update(entityInfo, "emailConstraint", any()) }
    }

    test("Checking checksums and encryption") {
      objectUnderTest.runTableScan().shouldBeLeft().message shouldContain "Invalid system status"
      systemStatusService.setSystemStatus(SystemStatus.RUNNING)
      objectUnderTest.runTableScan().shouldBeRight()
    }
  }
}
