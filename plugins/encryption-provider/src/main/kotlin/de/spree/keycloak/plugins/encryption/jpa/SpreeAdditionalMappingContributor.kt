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

import de.spree.keycloak.commons.columnEncryptionEnabled
import de.spree.keycloak.commons.configuration.CONFIG_SETTINGS_ENABLE_COLUMN_ENCRYPTION
import de.spree.keycloak.plugins.encryption.jpa.SpreeEncryptionEnhancer.enhance
import org.hibernate.boot.ResourceStreamLocator
import org.hibernate.boot.spi.AdditionalMappingContributions
import org.hibernate.boot.spi.AdditionalMappingContributor
import org.hibernate.boot.spi.InFlightMetadataCollector
import org.hibernate.boot.spi.MetadataBuildingContext

/**
 * Contributes additional mappings and types to Hibernate for encryption and integrity checking.
 *
 * This contributor enhances Hibernate's [Metadata].
 */
class SpreeAdditionalMappingContributor : AdditionalMappingContributor {
	/**
	 * Contributes to additional mapping contributions
	 *
	 * @param contributions The additional mapping contributions.
	 * @param metadata The in-flight metadata collector.
	 * @param resourceStreamLocator The resource stream locator.
	 * @param buildingContext The metadata building context.
	 */
	override fun contribute(
		contributions: AdditionalMappingContributions,
		metadata: InFlightMetadataCollector,
		resourceStreamLocator: ResourceStreamLocator,
		buildingContext: MetadataBuildingContext,
	) {
		val settings = metadata.bootstrapContext.configurationService.settings
		val columnEncryptionEnabledFromSettings = settings.getOrElse(CONFIG_SETTINGS_ENABLE_COLUMN_ENCRYPTION) { "true" }.toString().toBoolean()

		if (columnEncryptionEnabled && columnEncryptionEnabledFromSettings) {
			enhance(metadata)
		}
	}

	/**
	 * Returns the name of this contributor.
	 *
	 * @return The contributor name.
	 */
	override fun getContributorName(): String = "spree-contributor"
}
