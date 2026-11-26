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
import de.spree.keycloak.commons.setValue
import de.spree.keycloak.integrity.ConfigurationDao
import de.spree.keycloak.integrity.ConfigurationService
import de.spree.keycloak.integrity.SpreeDatabaseConversionState
import de.spree.keycloak.integrity.SpreeFeature
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.maps.shouldBeEmpty
import io.kotest.matchers.maps.shouldContainExactly
import io.kotest.matchers.shouldBe

class ConfigurationServiceTest : AbstractDatabaseTest() {
  private lateinit var configurationDao: ConfigurationDao
  private lateinit var configurationService: ConfigurationService

  init {
    beforeTest {
      configurationDao = ConfigurationDao(entityManager)
      configurationService = ConfigurationService().setValue("configurationDao", configurationDao)
    }

    test("basics") {
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
      configurationService.getFeatures().shouldBeEmpty()

      configurationService.setFeatures(setOf(SpreeFeature.COLUMN_ENCRYPTION))
      configurationService.getFeatures() shouldBe setOf(SpreeFeature.COLUMN_ENCRYPTION)
    }

    test("conversion state") {
      configurationService.getConversionState() shouldBe SpreeDatabaseConversionState.PRISTINE
      configurationService.setConversionState(SpreeDatabaseConversionState.DONE)
      configurationService.getConversionState() shouldBe SpreeDatabaseConversionState.DONE
    }
  }
}
