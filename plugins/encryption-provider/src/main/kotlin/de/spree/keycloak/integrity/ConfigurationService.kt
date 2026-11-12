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

import arrow.core.Either
import arrow.core.Option
import arrow.core.firstOrNone
import arrow.core.raise.option
import arrow.core.toOption
import de.spree.keycloak.commons.logger
import de.spree.keycloak.commons.toEnum
import de.spree.keycloak.plugins.integrity.EntityAction
import jakarta.enterprise.context.ApplicationScoped
import java.util.UUID

/**
 * Guards against re-entrant configuration reads on the same thread, see [ConfigurationService.loadConfiguration].
 *
 * Kept outside the bean so it is unaffected by CDI proxying.
 */
private val loadingConfiguration = ThreadLocal.withInitial { false }

/**
 * Service responsible for reading Spree-specific configuration data.
 *
 * This service handles the core logic for provider specific configuration and state.
 */
@ApplicationScoped
open class ConfigurationService {
	private lateinit var conversionState: SpreeDatabaseConversionState

	private var tableExists = false

	fun getFeatures(entityAction: EntityAction): Set<SpreeFeature> {
		val configuration = loadConfiguration(entityAction)
		val features = configuration?.get(CONFIG_FEATURES) ?: emptyList()

		return features.map { it.toEnum<SpreeFeature>() ?: throw IllegalStateException("Unknown enum value »$it«") }.toSet()
	}

	/**
	 * Reads the conversion state, caching only the terminal [SpreeDatabaseConversionState.DONE].
	 *
	 * Every other state is volatile in a cluster: another node may convert the database at any time, and a cached
	 * [SpreeDatabaseConversionState.PRISTINE] would make this node convert a second time over an already converted database — see
	 * [de.spree.keycloak.plugins.events.SpreeBootstrapProcessor] for why that is fatal. Caching it is exactly what took the cluster down in August
	 * 2026: the second node had read the state once during startup and never looked again.
	 *
	 * Reading through to the database on every call is affordable because the hot path is not affected: while the system is
	 * [SystemState.OPERATIONAL][de.spree.keycloak.commons.configuration.SystemState.OPERATIONAL] the state is `DONE` and served from the field.
	 */
	fun getConversionState(entityAction: EntityAction): SpreeDatabaseConversionState {
		if (this::conversionState.isInitialized && conversionState == SpreeDatabaseConversionState.DONE) {
			return conversionState
		}

		val configuration = loadConfiguration(entityAction)

		if (configuration != null) {
			val status = configuration[CONFIG_CONVERSION_STATE]?.firstOrNull() ?: SpreeDatabaseConversionState.PRISTINE.name

			conversionState = status.toEnum<SpreeDatabaseConversionState>() ?: throw IllegalStateException("Unknown enum value »${status}«")
		} else if (!this::conversionState.isInitialized) {
			return SpreeDatabaseConversionState.UNKNOWN
		}

		return conversionState
	}

	fun getKeychainId(entityAction: EntityAction): Option<UUID> = option {
		val configuration = loadConfiguration(entityAction).bind()
		val keychainId = configuration[CONFIG_KEYCHAIN_ID].bind().firstOrNone().bind()
		UUID.fromString(keychainId).toOption().bind()
	}

	/**
	 * Reads the configuration through a session of its own, see [EntityAction.spreeSession].
	 *
	 * [SpreeEncryptionAttributeConverter][de.spree.keycloak.plugins.encryption.jpa.SpreeEncryptionAttributeConverter] asks for the conversion state
	 * while Hibernate is loading or flushing an entity, so this must not run on Keycloak's own session.
	 *
	 * The isolated session still shares the session factory and hence its event listeners: loading [Configuration] rows fires post-load events, and
	 * whoever handles those may ask for the configuration again. Such a re-entrant read yields `null` instead of recursing.
	 */
	private fun loadConfiguration(entityAction: EntityAction): Map<String, List<String>>? {
		if (loadingConfiguration.get()) {
			logger.debug("⚠️ Ignoring re-entrant configuration read")

			return null
		}

		loadingConfiguration.set(true)

		try {
				val configurationDao = createSpreeContextConfigurationDao(entityAction)

				if (!tableExists) { // check until table has been created
					tableExists = configurationDao.configurationTableExists()
				}

			return if (tableExists) {
					configurationDao.loadConfiguration()
				} else {
					logger.warn("⚠️ Spree configuration table does not exist (yet)")
					null
				}
		} finally {
			loadingConfiguration.remove()
		}
	}

	fun setConversionState(entityAction: EntityAction, state: SpreeDatabaseConversionState) = Either.catch {
		val configurationDao = createSpreeContextConfigurationDao(entityAction)
		configurationDao.deleteConfiguration(CONFIG_CONVERSION_STATE)

		configurationDao.addConfiguration(CONFIG_CONVERSION_STATE, state.name)

		conversionState = state
	}

	fun setFeatures(entityAction: EntityAction, features: Set<SpreeFeature>) = Either.catch {
		val configurationDao = createSpreeContextConfigurationDao(entityAction)
		configurationDao.deleteConfiguration(CONFIG_FEATURES)

		features.forEach { configurationDao.addConfiguration(CONFIG_FEATURES, it.name) }
	}

	fun setKeychainId(entityAction: EntityAction, keychainId: UUID) = Either.catch {
		val configurationDao = createSpreeContextConfigurationDao(entityAction)
		configurationDao.deleteConfiguration(CONFIG_KEYCHAIN_ID)

		configurationDao.addConfiguration(CONFIG_KEYCHAIN_ID, keychainId.toString())
	}

	protected open fun createSpreeContextConfigurationDao(entityAction: EntityAction): ConfigurationDao = ConfigurationDao(entityAction.spreeEntityManager)
}

enum class SpreeFeature {
	COLUMN_ENCRYPTION,
	ROW_INTEGRITY,
	TABLE_INTEGRITY,
}

enum class SpreeDatabaseConversionState {
	UNKNOWN,
	PRISTINE,
	IN_PROGRESS,
	DONE,
}
