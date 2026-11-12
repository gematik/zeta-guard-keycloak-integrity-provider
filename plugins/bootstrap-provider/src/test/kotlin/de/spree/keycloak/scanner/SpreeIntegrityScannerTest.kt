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
package de.spree.keycloak.scanner

import arrow.core.None
import arrow.core.Some
import arrow.core.left
import arrow.core.right
import de.spree.keycloak.commons.*
import de.spree.keycloak.commons.TestData.user
import de.spree.keycloak.commons.configuration.SystemState
import de.spree.keycloak.crypto.CryptoUpdate
import de.spree.keycloak.crypto.CryptoUpdateService
import de.spree.keycloak.integrity.*
import de.spree.keycloak.scanner.SpreeIntegrityScanner.scannerError
import de.spree.keycloak.scanner.SpreeIntegrityScanner.scannerState
import de.spree.keycloak.plugins.integrity.Action.INITIALIZE
import de.spree.keycloak.plugins.integrity.EntityAction
import io.kotest.assertions.arrow.core.shouldBeLeft
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.string.shouldContain
import io.mockk.*
import org.keycloak.models.jpa.entities.UserEntity
import java.time.Instant

class SpreeIntegrityScannerTest : AbstractMockTest() {
	private val objectUnderTest = SpreeIntegrityScanner
	private val tableChecksumService = mockk<TableChecksumService>()
	private val rowChecksumService = mockk<RowChecksumService>()
	private val scannerService = mockk<ScannerService>()
	private val cryptoUpdateService = mockk<CryptoUpdateService>()

	private val entityInfo = EntityInfo(EntityId(USER_ID), "USER_ENTITY", user)
	private val entityName = UserEntity::class.qualifiedName!!
	private val action = EntityAction(INITIALIZE, entityName, entityManager)
	private val updateTask = CryptoUpdate(entityName, Instant.now())

	init {
		beforeTest {
			trainCDIService(tableChecksumService)
			trainCDIService(rowChecksumService)
			trainCDIService(hashingService)
			trainCDIService(entityManager)
			trainCDIService(scannerService)
			trainCDIService(cryptoUpdateService)

			every { scannerService.canPerformCryptoUpdate() } returns true

			every { scannerService.loadEntities(any()) } returns emptyList<EntityInfo>().right()
			every { scannerService.loadEntities(action) } returns listOf(entityInfo).right()

			every { rowChecksumService.updateEntityInfoChecksum(entityInfo, action) } returns true.right()
			every { tableChecksumService.updateTableChecksum(action, any()) } returns SimpleSuccess.right()
			every { tableChecksumService.checkTableChecksum(any()) } returns SimpleSuccess.right()

			every { scannerService.updateEntity(any(), any()) } returns 0.right()
			every { cryptoUpdateService.finishUpdateTask(any(), any()) } just Runs

			systemStateService.resetState()
			objectUnderTest.reset()
		}

		test("Checking checksums and encryption") {
			systemStateService.resetState(SystemState.STARTUP)
			objectUnderTest.runTableScan(keycloakSession).shouldBeLeft().message shouldContain "Invalid system status"
			systemStateService.setSystemState(SystemState.OPERATIONAL)
			objectUnderTest.runTableScan(keycloakSession).shouldBeRight()
		}

		test("Updating checksums and encryption") {
			systemStateService.resetState(SystemState.STARTUP)
			objectUnderTest.runAllCryptoUpdates(keycloakSession).shouldBeLeft().message shouldContain "Invalid system status"
			systemStateService.setSystemState(SystemState.OPERATIONAL)
			objectUnderTest.runAllCryptoUpdates(keycloakSession).shouldBeRight()
		}

		test("does nothing if work in progress") {
			scannerState = ScannerState.SCANNING

			objectUnderTest.runScanCycle(keycloakSession)
			scannerError.shouldBeNull()

			verify(exactly = 0) { cryptoUpdateService.reserveUpdateTask(any()) }
		}

		// cycle tests

		test("skips update if not eligible for updates") {
			clearMocks(scannerService)
			every { scannerService.canPerformCryptoUpdate() } returns false
			every { scannerService.loadEntities(any()) } returns emptyList<EntityInfo>().right() // for scan instead

			objectUnderTest.runScanCycle(keycloakSession)
			scannerError.shouldBeNull()

			verify(exactly = 0) { cryptoUpdateService.reserveUpdateTask(keycloakSession) }
			verify(exactly = 0) { scannerService.updateEntity(any(), any()) }
			verify(exactly = 0) { cryptoUpdateService.finishUpdateTask(any(), any()) }
		}

		test("performs update if task is available") {
			every { cryptoUpdateService.reserveUpdateTask(keycloakSession) } returns Some(updateTask)
			every { scannerService.updateEntity(any(), any()) } returns 1.right()

			objectUnderTest.runScanCycle(keycloakSession)
			scannerError.shouldBeNull()

			verify { scannerService.updateEntity(any(), any()) }
			verify(exactly = 0) { cryptoUpdateService.finishUpdateTask(any(), any()) } // needs verify
		}

		test("completes update if task is available") {
			every { cryptoUpdateService.reserveUpdateTask(keycloakSession) } returns Some(updateTask)
			every { scannerService.updateEntity(any(), any()) } returns 0.right()

			objectUnderTest.runScanCycle(keycloakSession)
			scannerError.shouldBeNull()

			verify { scannerService.updateEntity(any(), any()) }
			verify { cryptoUpdateService.finishUpdateTask(any(), any()) } // done, no more updates
		}

		test("performs scan if no update available") {
			every { cryptoUpdateService.reserveUpdateTask(keycloakSession) } returns None

			objectUnderTest.runScanCycle(keycloakSession)
			scannerError.shouldBeNull()

			verify { scannerService.loadEntities(any()) }
		}

		test("delays throw if scan fails") {
			every { cryptoUpdateService.reserveUpdateTask(keycloakSession) } returns None
			clearMocks(scannerService)
			every { scannerService.canPerformCryptoUpdate() } returns true
			every { scannerService.loadEntities(any()) } returns RuntimeException().left()

			objectUnderTest.runScanCycle(keycloakSession) // OK, delayed
			scannerError.shouldNotBeNull()

			// next cycle throws
			shouldThrow<RuntimeException> { objectUnderTest.runScanCycle(keycloakSession) }
			systemStateService.resetState()
		}

		test("ignores scan error if update task available") {
			every { cryptoUpdateService.reserveUpdateTask(keycloakSession) } returns None
			clearMocks(scannerService)
			every { scannerService.canPerformCryptoUpdate() } returns true
			every { scannerService.loadEntities(any()) } returns RuntimeException().left()

			objectUnderTest.runScanCycle(keycloakSession) // OK, delayed
			scannerError.shouldNotBeNull()

			every { scannerService.updateEntity(any(), any()) } returns 1.right()
			clearMocks(cryptoUpdateService)
			every { cryptoUpdateService.reserveUpdateTask(keycloakSession) } returns Some(updateTask)
			every { cryptoUpdateService.finishUpdateTask(any(), any()) } just Runs

			objectUnderTest.runScanCycle(keycloakSession) // OK, resets error
			scannerError.shouldBeNull()
		}
	}
}
