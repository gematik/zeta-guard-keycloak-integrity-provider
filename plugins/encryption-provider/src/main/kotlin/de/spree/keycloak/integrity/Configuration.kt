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
@file:Suppress("unused")

package de.spree.keycloak.integrity

import de.spree.keycloak.commons.configuration.TABLE_CONFIGURATION
import jakarta.persistence.*

const val CONFIG_FEATURES = "spree.config.features.enabled"
const val CONFIG_CONVERSION_STATE = "spree.config.conversion.state"
const val CONFIG_KEYCHAIN_ID = "spree.config.keychain.id"

const val QUERY_LOAD_ALL = "Configuration.LOAD_ALL"
const val QUERY_DELETE_BY_NAME = "Configuration.DELETE_BY_NAME"

@Entity
@Table(name = TABLE_CONFIGURATION)
@NamedQueries(
    NamedQuery(name = QUERY_LOAD_ALL, query = """SELECT c FROM Configuration c"""),
    NamedQuery(name = QUERY_DELETE_BY_NAME, query = """DELETE FROM Configuration c WHERE c.name = :name"""),
)
@Suppress("JpaEntityWithValAttributesInspection")
class Configuration(
    @Id @Column(name = "ID", length = 255, nullable = false, updatable = false) val id: String,
    @Column(name = "NAME", length = 255, nullable = false, updatable = false) val name: String,
    @Column(name = "VALUE", length = 1024, nullable = false) var value: String,
) {
  /**
   * No-argument constructor required by JPA.
   *
   * Initializes the entity with empty strings. Should not be used directly.
   */
  @Suppress("unused", "KotlinRedundantDefaultConstructorJpaCompilerPluginInspection") constructor() : this("", "", "")

  /**
   * Checks if this [RowChecksum] is equal to another object.
   *
   * @param other The object to compare with.
   * @return `true` if the objects are equal, `false` otherwise.
   */
  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (javaClass != other?.javaClass) return false

    other as Configuration

    if (id != other.id) return false
    if (name != other.name) return false
    if (value != other.value) return false

    return true
  }

  /**
   * Returns a hash code value for the object.
   *
   * @return A hash code value for this object.
   */
  override fun hashCode(): Int {
    var result = id.hashCode()
    result = 31 * result + name.hashCode()
    result = 31 * result + value.hashCode()
    return result
  }

  /**
   * Returns a string representation of the object.
   *
   * @return A string representation of the object.
   */
  override fun toString(): String {
    return "RowChecksum(id='$id', name='$name', value='$value')"
  }
}
