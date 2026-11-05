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

import arrow.core.right
import de.spree.keycloak.commons.AbstractMockTest
import de.spree.keycloak.commons.EntityId
import de.spree.keycloak.commons.EntityInfo
import de.spree.keycloak.commons.SimpleSuccess
import de.spree.keycloak.commons.TestData.user
import de.spree.keycloak.commons.USER_ID
import de.spree.keycloak.commons.setValue
import de.spree.keycloak.integrity.EntityDao
import de.spree.keycloak.integrity.RowChecksumService
import de.spree.keycloak.integrity.TableChecksumService
import de.spree.keycloak.plugins.integrity.Action.INITIALIZE
import de.spree.keycloak.plugins.integrity.EntityAction
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.keycloak.models.jpa.entities.UserEntity

class ScannerServiceTest : AbstractMockTest() {
    private val entityDao: EntityDao = mockk()
    private val tableChecksumService = mockk<TableChecksumService>()
    private val rowChecksumService = mockk<RowChecksumService>()

    private val objectUnderTest =
        object : ScannerService() {
            override fun createEntityDao(action: EntityAction) = entityDao
        }.apply {
            setValue("tableChecksumService", tableChecksumService, ScannerService::class.java)
            setValue("rowChecksumService", rowChecksumService, ScannerService::class.java)
            setValue("cryptoService", cryptoService, ScannerService::class.java)
        }

    private val entityInfo = EntityInfo(EntityId(USER_ID), "USER_ENTITY", user)
    private val entityName = UserEntity::class.qualifiedName!!
    private val action = EntityAction(INITIALIZE, entityName, entityManager)

    init {
        beforeTest {
            trainCDIService(entityDao)
            trainCDIService(tableChecksumService)
            trainCDIService(rowChecksumService)
            trainCDIService(hashingService)
            trainCDIService(entityManager)

            every { entityDao.loadEntities(entityName) } returns listOf(entityInfo)
            every { entityDao.lookupEntityInfo(any()) } returns entityInfo.right()

            every { tableChecksumService.isInitialState(any()) } returns true.right()
            every { rowChecksumService.isInitialState(any()) } returns true.right()

            every { rowChecksumService.updateEntityInfoChecksum(entityInfo, action) } returns true.right()
            every { tableChecksumService.updateTableChecksum(action, any()) } returns SimpleSuccess.right()
            every { tableChecksumService.checkTableChecksum(any()) } returns SimpleSuccess.right()
        }

        test("loads entities of a given type") {
            val entities = objectUnderTest.loadEntities(action).shouldBeRight()
            entities.size shouldBe 1
            entities[0] shouldBe entityInfo
        }

        test("updates encryption and integrity") {
            every { entityDao.update(entityInfo, "email", any()) } returns true
            every { entityDao.update(entityInfo, "emailConstraint", any()) } returns true

            val config = spreeConfiguration.findEntity(entityName).shouldNotBeNull()
            objectUnderTest.updateEntity(config, entityManager).shouldBeRight(1)

            verify { rowChecksumService.updateEntityInfoChecksum(entityInfo, action) }
            verify { tableChecksumService.updateTableChecksum(action, listOf(entityInfo.id)) }
			verify { entityDao.update(entityInfo, "email", any()) }
			verify { entityDao.update(entityInfo, "emailConstraint", any()) }
        }
    }
}