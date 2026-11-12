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
package de.spree.keycloak.crypto

import de.spree.keycloak.commons.configuration.TABLE_CRYPTO_UPDATE
import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Index
import jakarta.persistence.NamedQueries
import jakarta.persistence.NamedQuery
import jakarta.persistence.Table
import java.time.Instant

const val QUERY_LOAD_TASK_BY_MAX_AGE = "CryptoUpdate.LOAD_TASK_BY_MAX_AGE"
const val QUERY_DELETE_TASK_BY_ENTITY_NAME = "CryptoUpdate.DELETE_TASK_BY_ENTITY_NAME"
const val QUERY_DELETE_ALL_TASKS = "CryptoUpdate.DELETE_DELETE_ALL_TASKS"
const val QUERY_COUNT_REMAINING_TASKS = "CryptoUpdate.COUNT_REMAINING_TASKS"

const val COLUMN_UPDATE_ENTITY_NAME = "ENTITY_NAME"
const val COLUMN_START_TIME = "START_TIME"


/**
 * Represents a pending crypto update for a specific database table.
 *
 * This entity is used to schedule crypto updates for specific entities, which is
 *  - a key rotation
 *  - a hash reset
 * or potentially both. A worker picks a crypto update by setting its start time to the current time.
 * It may pick any update whose start time is still unset, i.e. not started yet, or where it is older than
 * a configurable timeout. The latter ensures the task is completed even if its original worker crashed.
 * After finishing its task the worker deletes the respective crypto update entry.
 *
 * @property entityName The name of the entity table serving as primary key.
 * @property startTime The time at which this update was started, or null if not started yet.
 */
@Entity
@Table(name = TABLE_CRYPTO_UPDATE, indexes = [Index(name = "IDX_ENTITY_NAME", columnList = COLUMN_UPDATE_ENTITY_NAME)])
@NamedQueries(
    NamedQuery(name = QUERY_LOAD_TASK_BY_MAX_AGE, query = """
        SELECT u FROM CryptoUpdate u 
        WHERE u.startTime IS NULL 
        OR u.startTime < CURRENT_TIMESTAMP - :maxAge SECOND
        LIMIT 1
    """),
    NamedQuery(name = QUERY_DELETE_TASK_BY_ENTITY_NAME, query = "DELETE FROM CryptoUpdate WHERE entityName = :entityName"),
    NamedQuery(name = QUERY_DELETE_ALL_TASKS, query = "DELETE FROM CryptoUpdate"),
    NamedQuery(name = QUERY_COUNT_REMAINING_TASKS, query = "SELECT COUNT(*) FROM CryptoUpdate"),
)
@Suppress("JpaEntityWithValAttributesInspection")
class CryptoUpdate(
    /** The name of the entity class. */
    @Id @Column(name = COLUMN_UPDATE_ENTITY_NAME, length = 255, nullable = false, updatable = false)
    val entityName: String,

    /** The processing start time. */
    @Column(name = COLUMN_START_TIME, nullable = true)
    var startTime: Instant? = null,
) {
    /**
     * No-argument constructor required by JPA.
     *
     * Initializes the entity with empty strings. Should not be used directly.
     */
    @Suppress("unused", "KotlinRedundantDefaultConstructorJpaCompilerPluginInspection") constructor() : this("", null)

    /**
     * Checks if this [CryptoUpdate] is equal to another object.
     *
     * @param other The object to compare with.
     * @return `true` if the objects are equal, `false` otherwise.
     */
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as CryptoUpdate

        if (entityName != other.entityName) return false
        if (startTime != other.startTime) return false

        return true
    }

    /**
     * Returns a hash code value for the object.
     *
     * @return A hash code value for this object.
     */
    override fun hashCode(): Int {
        var result = entityName.hashCode()
        result = 31 * result + startTime.hashCode()
        return result
    }

    /**
     * Returns a string representation of the object.
     *
     * @return A string representation of the object.
     */
    override fun toString(): String {
        return "CryptoUpdate(tableName='$entityName', startTime='$startTime')"
    }
}
