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
package de.spree.keycloak.plugins.encryption.jpa

import de.spree.keycloak.commons.cdiService
import de.spree.keycloak.commons.configuration.*
import de.spree.keycloak.commons.logger
import org.hibernate.boot.Metadata
import org.hibernate.boot.model.process.internal.InferredBasicValueResolution
import org.hibernate.mapping.BasicValue

private val ENCRYPTION_CONVERTER_CLASS = SpreeEncryptionAttributeConverter::class.java

/**
 * Enhances Hibernate metadata for encryption and entity listeners based on configuration.
 *
 * This object processes ORM mappings to enable entity listeners and attribute converters for encryption, using settings to control their activation.
 */
object SpreeEncryptionEnhancer {
	private val configuration: SpreeEntityConfiguration by lazy { cdiService() }
	private val systemStateService: SystemStateService by lazy { cdiService() }

	/**
	 * Enhances the provided metadata with entity listeners and attribute converters if enabled.
	 *
	 * @param metadata The Hibernate metadata to enhance.
	 */
	fun enhance(metadata: Metadata) {
		logger.info("🛠️ Enhancing Hibernate metadata with encrypting converter setup")
		systemStateService.setSystemState(SystemState.STARTUP_JPA)

		configuration.entities.forEach { entity ->
			val entityBinding = metadata.getEntityBinding(entity.name) ?: throw IllegalStateException("Entity binding not found for »${entity.name}«")

			entity.encryptedProperties.forEach {
				val property = entityBinding.getProperty(it.name)
				val value = property.value as BasicValue

				if (value.resolution is InferredBasicValueResolution<*, *>) {
					/** Passing parameters to the attribute converter only works if the flag
					 * [org.hibernate.cfg.ManagedBeanSettings.ALLOW_EXTENSIONS_IN_CDI] is set.
					 * See [BasicValue.getConfiguredUserTypeBean] for details
					 */
					property.value = value.copy().apply {
						setExplicitTypeParams(
							mapOf(
								TYPE_PARAM_ENTITY_NAME to entity.name,
								TYPE_PARAM_PROPERTY_NAME to property.name
							)
						)
						setExplicitCustomType(ENCRYPTION_CONVERTER_CLASS)
					}
				}
			}
		}
	}
}
