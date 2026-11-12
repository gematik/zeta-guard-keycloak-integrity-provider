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
import de.spree.keycloak.commons.crypto.DBChecksum
import de.spree.keycloak.commons.crypto.DBHash
import jakarta.persistence.*

const val QUERY_TABLE_CHECKSUMS_EMPTY = "TableChecksum.CHECK_EMPTY"

const val COLUMN_ENTITY_NAME = "ENTITY_NAME"
const val COLUMN_HASH = "HASH"
const val COLUMN_CHECKSUM = "CHECKSUM"

/**
 * Represents a checksum for a specific database table.
 *
 * This entity is used to verify the integrity of an entire table by storing a multiset hash over the IDs of all the table's entities,
 * plus an HMAC over that hash.
 *
 * @property entityName The name of the entity table serving as primary key.
 * @property hash The (unkeyed) multiset hash over all entity IDs of the table, used as starting point for incremental updates.
 * @property checksum The HMAC over [hash], authenticating it.
 */
@Entity
@Table(name = TABLE_TABLE_CHECKSUM, indexes = [Index(name = "IDX_ENTITY_NAME", columnList = COLUMN_ENTITY_NAME)])
@NamedQueries(
	NamedQuery(name = QUERY_TABLE_CHECKSUMS_EMPTY, query = "SELECT COUNT(*) = 0 FROM TableChecksum")
)
@Suppress("JpaEntityWithValAttributesInspection")
class TableChecksum(
	/** The name of the entity class. */
	@Id @Column(name = COLUMN_ENTITY_NAME, length = 255, nullable = false, updatable = false)
	val entityName: String,

	/** The multiset hash value. */
	@Column(name = COLUMN_HASH, length = 1024, nullable = false)
	var hash: DBHash,

	/** The HMAC over the hash value. */
	@Column(name = COLUMN_CHECKSUM, length = 1024, nullable = false)
	var checksum: DBChecksum,
) {
	/**
	 * No-argument constructor required by JPA.
	 *
	 * Initializes the entity with empty strings. Should not be used directly.
	 */
	@Suppress("unused", "KotlinRedundantDefaultConstructorJpaCompilerPluginInspection")
	constructor() : this("", "", "")

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
		if (hash != other.hash) return false
		if (checksum != other.checksum) return false

		return true
	}

	/**
	 * Returns a hash code value for the object.
	 *
	 * @return A hash code value for this object.
	 */
	override fun hashCode() = (entityName.hashCode() * 31 + hash.hashCode()) * 31 + checksum.hashCode()

	/**
	 * Returns a string representation of the object.
	 *
	 * @return A string representation of the object.
	 */
	override fun toString(): String = "TableChecksum(entityName='$entityName', hash='$hash', checksum='$checksum')"
}
