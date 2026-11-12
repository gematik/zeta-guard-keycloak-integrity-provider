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

import de.spree.keycloak.commons.EntityInfo
import de.spree.keycloak.commons.configuration.TABLE_ROW_CHECKSUM
import de.spree.keycloak.commons.crypto.DBChecksum
import jakarta.persistence.*
import java.io.Serializable

const val QUERY_DELETE_CHECKSUMS = "RowChecksum.QUERY_DELETE_CHECKSUMS"

/** The name of the named query to load [RowChecksum] entities */
const val QUERY_LOAD_ROWS_BY_ENTITYNAME = "RowChecksum.LOAD_ROWS_BY_ENTITYNAME"

const val QUERY_ROW_CHECKSUMS_EMPTY = "RowChecksum.CHECK_EMPTY"

const val COLUMN_ENTITY_ID = "ENTITY_ID"
const val COLUMN_COMPOSITE_ID1 = "COMPOSITE_ID1"
const val COLUMN_COMPOSITE_ID2 = "COMPOSITE_ID2"

/**
 * Represents a checksum for a specific row in a database table.
 *
 * This entity is used to verify the integrity of individual rows by storing a checksum that corresponds to the state of the row's data. It uses a
 * composite primary key consisting of the table name and the entity ID.
 *
 * @property entityName The name of the entity table the row belongs to. Part of the composite primary key.
 * @property entityId The ID of the entity (row) this checksum is for. Part of the composite primary key.
 * @property checksum The calculated checksum value for the row.
 */
@Entity
@Table(
	name = TABLE_ROW_CHECKSUM,
	indexes = [Index(name = "IDX_ENTITY_NAME", columnList = COLUMN_ENTITY_NAME),
		Index(name = "IDX_ENTITY_ID", columnList = COLUMN_ENTITY_ID),
		Index(name = "IDX_ENTITY_NAME_ID", columnList = "$COLUMN_ENTITY_NAME,$COLUMN_ENTITY_ID"),
		Index(name = "IDX_COMPOSITE_ID", columnList = "$COLUMN_ENTITY_NAME,$COLUMN_COMPOSITE_ID1,$COLUMN_COMPOSITE_ID2")],
)
@IdClass(RowChecksumKeyId::class)
@NamedQueries(
	NamedQuery(
		name = QUERY_LOAD_ROWS_BY_ENTITYNAME,
		query = """SELECT r FROM RowChecksum r WHERE r.entityName = :entityName ORDER BY r.entityId ASC""",
	),
	NamedQuery(
		name = QUERY_DELETE_CHECKSUMS,
		query = """DELETE FROM RowChecksum r WHERE r.id IN (:entityIds)""",
	),
	NamedQuery(name = QUERY_ROW_CHECKSUMS_EMPTY, query = "SELECT COUNT(*) = 0 FROM RowChecksum"),
)
@Suppress("JpaEntityWithValAttributesInspection")
class RowChecksum(
	/** The name of the entity class. */
	@Id @Column(name = COLUMN_ENTITY_NAME, length = 255, nullable = false, updatable = false) //
	val entityName: String,

	/** The string-based ID of the entity. */
	@Id @Column(name = COLUMN_ENTITY_ID, length = 255, nullable = false, updatable = false) //
	val entityId: String,

	/** first part of the composite ID of the entity */
	@Column(name = COLUMN_COMPOSITE_ID1, length = 255, nullable = true, updatable = false) //
	val compositeId1: String? = null,

	/** second part of the composite ID of the entity */
	@Column(name = COLUMN_COMPOSITE_ID2, length = 255, nullable = true, updatable = false) //
	val compositeId2: String? = null,

	@Column(name = COLUMN_CHECKSUM, length = 1024, nullable = false) //
	var checksum: DBChecksum,
) {
	/**
	 * No-argument constructor required by JPA.
	 *
	 * Initializes the entity with empty strings. Should not be used directly.
	 */
	@Suppress("unused", "KotlinRedundantDefaultConstructorJpaCompilerPluginInspection")
	constructor() : this("", "", null, null, "")

	/**
	 * Checks if this [RowChecksum] is equal to another object.
	 *
	 * @param other The object to compare with.
	 * @return `true` if the objects are equal, `false` otherwise.
	 */
	override fun equals(other: Any?): Boolean {
		if (this === other) return true
		if (javaClass != other?.javaClass) return false

		other as RowChecksum

		if (entityName != other.entityName) return false
		if (entityId != other.entityId) return false
		if (checksum != other.checksum) return false

		return true
	}

	/**
	 * Returns a hash code value for the object.
	 *
	 * @return A hash code value for this object.
	 */
	override fun hashCode(): Int {
		var result = entityName.hashCode()
		result = 31 * result + entityId.hashCode()
		result = 31 * result + checksum.hashCode()
		return result
	}

	/**
	 * Returns a string representation of the object.
	 *
	 * @return A string representation of the object.
	 */
	override fun toString(): String {
		return "RowChecksum(tableName='$entityName', entityId='$entityId', checksum='$checksum')"
	}
}

/**
 * Composite primary key class for [RowChecksum].
 *
 * This class is used by JPA to handle the composite key (tableName + entityId) of the [RowChecksum] entity.
 *
 * @property entityName The name of the table.
 * @property entityId The ID of the entity.
 */
data class RowChecksumKeyId(var entityName: String, var entityId: String) : Serializable {
	/** No-argument constructor required by JPA. */
	constructor() : this("", "")
}

val RowChecksum.rowChecksumId: RowChecksumKeyId
	get() = RowChecksumKeyId(entityName, entityId)

val EntityInfo.rowChecksumId: RowChecksumKeyId
	get() = RowChecksumKeyId(entityName, id)
