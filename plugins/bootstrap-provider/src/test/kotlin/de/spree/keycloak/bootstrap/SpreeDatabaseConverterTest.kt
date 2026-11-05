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
package de.spree.keycloak.bootstrap

import arrow.core.right
import de.spree.keycloak.commons.*
import de.spree.keycloak.integrity.*
import de.spree.keycloak.plugins.integrity.Action.INITIALIZE
import de.spree.keycloak.plugins.integrity.EntityAction
import de.spree.keycloak.scanner.ScannerService
import de.spree.keycloak.scanner.ScannerState
import de.spree.keycloak.scanner.SpreeIntegrityScanner
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.matchers.shouldBe
import io.mockk.clearMocks
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.keycloak.models.jpa.entities.UserEntity

class SpreeDatabaseConverterTest : AbstractMockTest() {
	private val objectUnderTest = SpreeDatabaseConverter
	private val tableChecksumService = mockk<TableChecksumService>()
	private val rowChecksumService = mockk<RowChecksumService>()
	private val scannerService = mockk<ScannerService>()

	private val entityName = UserEntity::class.qualifiedName!!
	private val action = EntityAction(INITIALIZE, entityName, entityManager)

	init {
		beforeTest {
			trainCDIService(tableChecksumService)
			trainCDIService(rowChecksumService)
			trainCDIService(hashingService)
			trainCDIService(entityManager)
			trainCDIService(scannerService)

			every { tableChecksumService.isInitialState(any()) } returns true.right()
			every { rowChecksumService.isInitialState(any()) } returns true.right()

			every { scannerService.updateEntity(any(), any()) } returns 1.right()
			every { scannerService.verifyEncryptedColumns(any(), any()) } returns Unit.right()
		}

		test("Initializing checksums and encryption") {
			SpreeIntegrityScanner.scannerState shouldBe ScannerState.IDLE
			objectUnderTest.convertDatabase(action).shouldBeRight()
			SpreeIntegrityScanner.scannerState shouldBe ScannerState.IDLE
			verify { scannerService.updateEntity(any(), any()) }
			verify { scannerService.verifyEncryptedColumns(any(), any()) }
		}

		test("Conversion is skipped when another node has already written the row checksums") {
			clearMocks(scannerService, answers = false) // keep the stubs, drop the calls recorded by the previous test
			every { rowChecksumService.isInitialState(any()) } returns false.right()

			objectUnderTest.convertDatabase(action).shouldBeRight()

			verify(exactly = 0) { scannerService.updateEntity(any(), any()) }
			verify(exactly = 0) { scannerService.verifyEncryptedColumns(any(), any()) }
		}
	}
}
