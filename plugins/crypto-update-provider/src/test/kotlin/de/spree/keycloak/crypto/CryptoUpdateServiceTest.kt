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
package de.spree.keycloak.crypto

import arrow.core.None
import arrow.core.Some
import de.spree.keycloak.commons.AbstractMockTest
import de.spree.keycloak.commons.configuration.SpreeEntityConfiguration
import de.spree.keycloak.commons.setValue
import io.kotest.assertions.arrow.core.shouldBeLeft
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.keycloak.models.KeycloakSession
import org.keycloak.models.jpa.entities.UserEntity
import java.time.Instant

class CryptoUpdateServiceTest : AbstractMockTest() {
    val entityName: String = UserEntity::class.java.name

    private val cryptoUpdateDao: CryptoUpdateDao = mockk()
    private val entityConfiguration: SpreeEntityConfiguration = mockk()
    private val session: KeycloakSession = mockk()

    private val objectUnderTest = object : CryptoUpdateService() {
        override fun createSpreeContextCryptoUpdateDao(session: KeycloakSession): CryptoUpdateDao = cryptoUpdateDao
    }.apply {
        setValue("entityConfiguration", entityConfiguration, CryptoUpdateService::class.java)
    }

    private fun makeTask() = CryptoUpdate(entityName, Instant.now())

    init {

        test("reserve none") {
            every { cryptoUpdateDao.reserve(any()) } returns null

            objectUnderTest.reserveUpdateTask(session) shouldBe None
        }

        test("reserve available task") {
            val task = makeTask()
            every { cryptoUpdateDao.reserve(any()) } returns task

            objectUnderTest.reserveUpdateTask(session) shouldBe Some(task)
        }

        test("reserve ignores exceptions") {
            every { cryptoUpdateDao.reserve(any()) } throws IllegalStateException("test")

            objectUnderTest.reserveUpdateTask(session) shouldBe None
        }

        test("finish available task") {
            val task = makeTask()

            objectUnderTest.finishUpdateTask(session, task)
            verify { cryptoUpdateDao.delete(task) }
        }

        test("finish ignores exceptions") {
            val task = makeTask()
            every { cryptoUpdateDao.delete(any(CryptoUpdate::class)) } throws IllegalStateException("test")

            objectUnderTest.finishUpdateTask(session, task)
        }

        test("enqueue a single task") {
            every { cryptoUpdateDao.add(any()) } returns mockk()

            objectUnderTest.enqueueEntity(session, entityName).shouldBeRight()
            verify { cryptoUpdateDao.add(entityName) }
        }

        test("enqueue fails") {
            every { cryptoUpdateDao.add(any()) } throws IllegalStateException("test")

            objectUnderTest.enqueueEntity(session, entityName).shouldBeLeft().message shouldBe "test"
        }

        test("enqueue all entities") {
            every { entityConfiguration.entityNames } returns setOf("foo", "bar", "baz")
            every { cryptoUpdateDao.add(any()) } returns mockk()

            objectUnderTest.enqueueAllEntities(session).shouldBeRight()
            verify {
                cryptoUpdateDao.add("foo")
                cryptoUpdateDao.add("bar")
                cryptoUpdateDao.add("baz")
            }
        }

        test("enqueue all fails") {
            every { entityConfiguration.entityNames } returns setOf("foo", "bar", "baz")
            every { cryptoUpdateDao.add(any()) } throws IllegalStateException("test")

            objectUnderTest.enqueueAllEntities(session).shouldBeLeft().message shouldBe "test"
        }

        test("clear task queue") {
            objectUnderTest.clearTaskQueue(session)
            verify { cryptoUpdateDao.deleteAll() }
        }

        test("clear ignores exceptions") {
            every { cryptoUpdateDao.deleteAll() } throws IllegalStateException("test")

            objectUnderTest.clearTaskQueue(session)
            verify { cryptoUpdateDao.deleteAll() }
        }

        test("count remaining tasks") {
            every { cryptoUpdateDao.remaining() } returns 3L

            objectUnderTest.getRemainingTasks(session) shouldBe 3L
        }

        test("count remaining ignores exceptions") {
            every { cryptoUpdateDao.remaining() } throws IllegalStateException("test")

            objectUnderTest.getRemainingTasks(session) shouldBe 0L // treat as empty
        }
    }
}