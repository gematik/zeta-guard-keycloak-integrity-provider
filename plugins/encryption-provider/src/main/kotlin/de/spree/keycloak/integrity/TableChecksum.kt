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

import de.spree.keycloak.commons.configuration.TABLE_TABLE_CHECKSUM
import de.spree.keycloak.crypto.DBChecksum
import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Index
import jakarta.persistence.NamedQueries
import jakarta.persistence.NamedQuery
import jakarta.persistence.Table

const val QUERY_LOAD_CHECKSUM_BY_ENTITYNAME = "TableChecksum.LOAD_CHECKSUM_BY_ENTITYNAME"
const val QUERY_TABLE_CHECKSUMS_EMPTY = "TableChecksum.CHECK_EMPTY"
const val QUERY_DELETE_TABLE_CHECKSUM = "TableChecksum.DELETE_TABLE_CHECKSUM"

/**
 * Represents a checksum for a specific database table.
 *
 * This entity is used to verify the integrity of an entire table by storing a checksum that is a combination of all checksums of the table's
 * entities.
 *
 * @property entityName The name of the entity table serving as primary key.
 * @property checksum The calculated checksum value for the table.
 */
@Entity
@Table(name = TABLE_TABLE_CHECKSUM, indexes = [Index(name = "IDX_ENTITY_NAME", columnList = "ENTITY_NAME")])
@NamedQueries(
    NamedQuery(name = QUERY_LOAD_CHECKSUM_BY_ENTITYNAME, query = """SELECT t FROM TableChecksum t WHERE t.entityName = :entityName"""),
    NamedQuery(name = QUERY_TABLE_CHECKSUMS_EMPTY, query = "SELECT COUNT(*) = 0 FROM TableChecksum"),
    NamedQuery(name = QUERY_DELETE_TABLE_CHECKSUM, query = "DELETE FROM TableChecksum WHERE entityName = :entityName"),
)
@Suppress("JpaEntityWithValAttributesInspection")
class TableChecksum(
    /** The name of the entity class. */
    @Id @Column(name = "ENTITY_NAME", length = 255, nullable = false, updatable = false) val entityName: String,

    /** The checksum value. */
    @Column(name = "CHECKSUM", length = 1024, nullable = false) var checksum: DBChecksum,
) {
  /**
   * No-argument constructor required by JPA.
   *
   * Initializes the entity with empty strings. Should not be used directly.
   */
  @Suppress("unused", "KotlinRedundantDefaultConstructorJpaCompilerPluginInspection") constructor() : this("", "")

  /**
   * Checks if this [TableChecksum] is equal to another object.
   *
   * @param other The object to compare with.
   * @return `true` if the objects are equal, `false` otherwise.
   */
  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (javaClass != other?.javaClass) return false

    other as TableChecksum

    if (entityName != other.entityName) return false
    if (checksum != other.checksum) return false

    return true
  }

  /**
   * Returns a hash code value for the object.
   *
   * @return A hash code value for this object.
   */
  override fun hashCode() = entityName.hashCode() * 31 + checksum.hashCode()

  /**
   * Returns a string representation of the object.
   *
   * @return A string representation of the object.
   */
  override fun toString(): String = "TableChecksum(entityName='$entityName', checksum='$checksum')"
}
