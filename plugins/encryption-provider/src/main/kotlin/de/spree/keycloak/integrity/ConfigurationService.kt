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
package de.spree.keycloak.integrity

import de.spree.keycloak.commons.toEnum
import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject

/**
 * Service responsible for reading configuration data.
 *
 * This service handles the core logic for provider specific configuration and state.
 */
@ApplicationScoped
class ConfigurationService {
  @Inject //
  private lateinit var configurationDao: ConfigurationDao

  private lateinit var conversionState: SpreeDatabaseConversionState

  fun setFeatures(features: Set<SpreeFeature>) {
    configurationDao.deleteConfiguration(CONFIG_FEATURES)

    features.forEach { configurationDao.addConfiguration(CONFIG_FEATURES, it.name) }
  }

  fun getFeatures(): Set<SpreeFeature> {
    val configuration = configurationDao.loadConfiguration()
    val features = configuration[CONFIG_FEATURES] ?: emptyList()

    return features.map { it.toEnum<SpreeFeature>() ?: throw IllegalStateException("Unknown enum value »$it«") }.toSet()
  }

  fun getConversionState(): SpreeDatabaseConversionState {
    if (!this::conversionState.isInitialized) {
      val configuration = configurationDao.loadConfiguration()
      val status = configuration[CONFIG_CONVERSION_STATUS]?.firstOrNull() ?: SpreeDatabaseConversionState.PRISTINE.name

      conversionState = status.toEnum<SpreeDatabaseConversionState>() ?: throw IllegalStateException("Unknown enum value »${status}«")
    }

    return conversionState
  }

  fun setConversionState(state: SpreeDatabaseConversionState) {
    configurationDao.deleteConfiguration(CONFIG_CONVERSION_STATUS)

    configurationDao.addConfiguration(CONFIG_CONVERSION_STATUS, state.name)

    conversionState = state
  }
}

enum class SpreeFeature {
  COLUMN_ENCRYPTION,
  ROW_INTEGRITY,
  TABLE_INTEGRITY,
}

enum class SpreeDatabaseConversionState {
  PRISTINE,
  IN_PROGRESS,
  DONE,
}
