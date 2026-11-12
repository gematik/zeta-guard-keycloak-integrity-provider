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
import de.spree.keycloak.integrity.*
import de.spree.keycloak.plugins.integrity.Action
import de.spree.keycloak.plugins.integrity.EntityAction
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.matchers.booleans.shouldBeFalse
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.maps.shouldBeEmpty
import io.kotest.matchers.maps.shouldContainExactly
import io.kotest.matchers.shouldBe
import jakarta.persistence.Persistence

class ConfigurationServiceTest : AbstractDatabaseTest() {
	private lateinit var configurationDao: ConfigurationDao
	private lateinit var configurationService: ConfigurationService

	init {
		beforeTest {
			configurationDao = ConfigurationDao(entityManager)
			configurationService = object : ConfigurationService() {
				override fun createSpreeContextConfigurationDao(entityAction: EntityAction) = configurationDao
			}
		}

		test("Configuration table does not exist (yet)") {
			val entityManagerFactory = Persistence.createEntityManagerFactory("empty")
			val entityManager = entityManagerFactory.createEntityManager().apply { transaction.begin() }
			val configurationDao = ConfigurationDao(entityManager)

			configurationDao.configurationTableExists().shouldBeFalse()
		}

		test("basics") {
			configurationDao.configurationTableExists().shouldBeTrue()
			configurationDao.loadConfiguration().shouldBeEmpty()
			configurationDao.addConfiguration("jens", "hippe")
			configurationDao.loadConfiguration().shouldContainExactly(mapOf("jens" to listOf("hippe")))
			configurationDao.addConfiguration("jens", "foo")
			configurationDao.loadConfiguration().shouldContainExactly(mapOf("jens" to listOf("hippe", "foo")))

			configurationDao.deleteConfiguration("hippe")
			configurationDao.loadConfiguration().shouldContainExactly(mapOf("jens" to listOf("hippe", "foo")))
			configurationDao.deleteConfiguration("jens")
			configurationDao.loadConfiguration().shouldBeEmpty()
		}

		test("enabled features") {
			val action = EntityAction(Action.INITIALIZE, "", entityManager)
			configurationService.getFeatures(action).shouldBeEmpty()

			configurationService.setFeatures(action, setOf(SpreeFeature.COLUMN_ENCRYPTION)).shouldBeRight()
			configurationService.getFeatures(action) shouldBe setOf(SpreeFeature.COLUMN_ENCRYPTION)
		}

		test("conversion state") {
			val action = EntityAction(Action.INITIALIZE, "", entityManager)

			configurationService.getConversionState(action) shouldBe SpreeDatabaseConversionState.PRISTINE
			configurationService.setConversionState(action, SpreeDatabaseConversionState.DONE).shouldBeRight()
			configurationService.getConversionState(action) shouldBe SpreeDatabaseConversionState.DONE
		}

		test("conversion state of another cluster node is picked up") {
			val action = EntityAction(Action.INITIALIZE, "", entityManager)

			configurationDao.deleteConfiguration(CONFIG_CONVERSION_STATE) // the database is shared with the preceding tests
			configurationService.getConversionState(action) shouldBe SpreeDatabaseConversionState.PRISTINE

			// another node converts the database, bypassing this instance
			configurationDao.addConfiguration(CONFIG_CONVERSION_STATE, SpreeDatabaseConversionState.DONE.name)

			configurationService.getConversionState(action) shouldBe SpreeDatabaseConversionState.DONE
		}

		test("conversion state is cached once it is DONE") {
			val action = EntityAction(Action.INITIALIZE, "", entityManager)

			configurationService.setConversionState(action, SpreeDatabaseConversionState.DONE).shouldBeRight()
			configurationDao.deleteConfiguration(CONFIG_CONVERSION_STATE)

			configurationService.getConversionState(action) shouldBe SpreeDatabaseConversionState.DONE
		}
	}
}
