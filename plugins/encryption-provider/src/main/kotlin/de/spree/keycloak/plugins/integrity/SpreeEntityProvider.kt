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
package de.spree.keycloak.plugins.integrity

import de.spree.keycloak.integrity.Configuration
import de.spree.keycloak.integrity.RowChecksum
import de.spree.keycloak.integrity.TableChecksum
import org.keycloak.connections.jpa.entityprovider.JpaEntityProvider

val SPREE_ENTITY_CLASSES = listOf(RowChecksum::class.java, TableChecksum::class.java, Configuration::class.java)

/**
 * This provider registers RowChecksum and TableChecksum entities with Keycloak's JPA system and specifies the changelog location for database
 * migrations.
 */
class SpreeEntityProvider : JpaEntityProvider {
  /**
   * Returns the list of entities created by this provider.
   *
   * @return List containing RowChecksum and TableChecksum classes.
   */
  override fun getEntities(): List<Class<out Any>> {
    return SPREE_ENTITY_CLASSES
  }

  /**
   * Returns the location of the changelog file for database migrations.
   *
   * @return The changelog file path.
   */
  override fun getChangelogLocation() = "META-INF/jpa-spree-integrity-changelog.xml"

  /**
   * Returns the factory ID for this provider.
   *
   * @return The provider ID.
   */
  override fun getFactoryId() = INTEGRITY_JPA_PROVIDER_ID

  /** Closes the provider. Currently a no-op. */
  override fun close() {
    // No-op
  }
}
