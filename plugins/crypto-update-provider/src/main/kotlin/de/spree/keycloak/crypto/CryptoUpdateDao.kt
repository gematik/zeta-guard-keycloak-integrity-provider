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

import de.spree.keycloak.commons.AbstractDao
import jakarta.enterprise.context.ApplicationScoped
import jakarta.persistence.EntityManager
import jakarta.persistence.LockModeType
import org.hibernate.Timeouts
import org.hibernate.jpa.SpecHints
import java.time.Instant

/**
 * Data Access Object (DAO) for managing [CryptoUpdate] entities.
 *
 * This class provides methods to find, retrieve all, and save and delete pending crypto updates.
 */
@ApplicationScoped
class CryptoUpdateDao(entityManager: EntityManager) : AbstractDao(entityManager) {
    /**
     * Adds a pending crypto update for an entity.
     *
     * @param entityName The name of the entity to add
     */
    fun add(entityName: String) {
        val task = CryptoUpdate(entityName)
        em().merge(task)
    }

    /**
     * Retrieves an existing [CryptoUpdate] and marks it as started
     *
     * @return [CryptoUpdate] if it exists
     */
    fun reserve(maxAge: Long): CryptoUpdate? {
        val task = em().createNamedQuery(QUERY_LOAD_TASK_BY_MAX_AGE, CryptoUpdate::class.java)
            .setParameter("maxAge", maxAge)
            .setLockMode(LockModeType.PESSIMISTIC_WRITE)
            .setHint(SpecHints.HINT_SPEC_LOCK_TIMEOUT, Timeouts.SKIP_LOCKED_MILLI)
            .singleResultOrNull

        if (task != null) {
            task.startTime = Instant.now()
            em().merge(task)
        }

        return task
    }

    /** Deletes a (loaded) [CryptoUpdate] entity. */
    fun delete(task: CryptoUpdate) {
        em().remove(task)
    }

    /** Deletes the pending task for a named entity. */
    fun delete(entityName: String) {
        em().createNamedQuery(QUERY_DELETE_TASK_BY_ENTITY_NAME).setParameter("entityName", entityName).executeUpdate()
    }

    /** Remove all remaining tasks. Tasks already started will still finish. */
    fun deleteAll() {
        em().createNamedQuery(QUERY_DELETE_ALL_TASKS).executeUpdate()
    }

    /**
     * Retrieves the number of remaining tasks.
     *
     * @return task count
     */
    fun remaining(): Long = em().createNamedQuery(QUERY_COUNT_REMAINING_TASKS, Long::class.java).singleResult
}
