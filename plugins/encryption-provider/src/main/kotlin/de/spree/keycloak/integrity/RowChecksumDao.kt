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

import de.spree.keycloak.commons.AbstractDao
import de.spree.keycloak.commons.configuration.PrimaryKey
import de.spree.keycloak.commons.configuration.clazz
import de.spree.keycloak.commons.configuration.toJPAJoinClause
import de.spree.keycloak.commons.configuration.toJPAWhereNullClause
import jakarta.persistence.EntityManager
import jakarta.persistence.LockModeType
import org.hibernate.jpa.HibernateHints.HINT_CACHEABLE

/**
 * Data Access Object (DAO) for managing [RowChecksum] entities.
 *
 * This class provides methods to find, retrieve all, and save row checksums.
 */
@Suppress("SqlSourceToSinkFlow")
class RowChecksumDao(entityManager: EntityManager) : AbstractDao(entityManager) {
	/**
	 * Finds a [RowChecksum] by its associated entity ID.
	 *
	 * @param entityId The ID of the entity to find the checksum for.
	 * @return The [RowChecksum] if found, or `null` otherwise.
	 */
	fun findByEntityId(entityId: RowChecksumKeyId): RowChecksum? = em().find(RowChecksum::class.java, entityId)

	/**
	 * Finds a [RowChecksum] by its associated entity ID and creates a row lock for atomic updates.
	 *
	 * @param entityId The ID of the entity to find the checksum for.
	 * @return The [RowChecksum] if found, or `null` otherwise.
	 */
	fun findForUpdate(entityId: RowChecksumKeyId): RowChecksum? = em().find(RowChecksum::class.java, entityId, LockModeType.PESSIMISTIC_WRITE)

	/**
	 * Retrieves all [RowChecksum] entities.
	 *
	 * @return A list of all [RowChecksum]s.
	 */
	fun findAllByEntityName(entityName: String): List<RowChecksum> =
		em()
			.createNamedQuery(QUERY_LOAD_ROWS_BY_ENTITYNAME, RowChecksum::class.java)
			.setParameter("entityName", entityName)
			.setHint(HINT_CACHEABLE, "true")
			.resultList

	/**
	 * Find deleted entities by performing a left join between the [RowChecksum] table and the specified entity table.
	 *
	 * Only works if the entity has a VARCHAR ID field and no composite key.
	 */
	fun findAbandonedChecksumsByStringId(entityName: String): List<RowChecksum> =
		em()
			.createQuery(
				"""
			SELECT r FROM RowChecksum r
				LEFT JOIN $entityName e ON r.entityId = e.id
				WHERE e.id IS NULL AND r.entityName = :entityName
			"""
					.trimIndent(),
				RowChecksum::class.java,
			)
			.setParameter("entityName", entityName)
			.resultList

	/**
	 * Find extraneous entities by performing a left join between the specified entity table and the [RowChecksum] table. Avoids triggering the event
	 * listener mechanism [de.spree.keycloak.plugins.integrity.SpreeIntegrityValidationListener] by just return the IDs
	 *
	 * Only works if the entity has a VARCHAR ID field and no composite key.
	 */
	fun findExtraneousEntitiesByStringId(entityName: String): List<String> =
		em()
			.createQuery(
				"""
			SELECT e.id FROM $entityName e
				LEFT JOIN RowChecksum r ON r.entityId = e.id AND r.entityName = :entityName
				WHERE r.entityId IS NULL
			"""
					.trimIndent(),
				String::class.java
			)
			.setParameter("entityName", entityName)
			.resultList

	/** Find deleted entities by performing a left join between the [RowChecksum] table and the specified entity table. */
	fun findAbandonedChecksumsByCompositeKey(entityName: String, primaryKey: PrimaryKey): List<RowChecksum> =
		em()
			.createQuery(
				"""
			SELECT r FROM RowChecksum r
				LEFT JOIN $entityName e ON ${primaryKey.toJPAJoinClause("r", "e")}
				WHERE ${primaryKey.toJPAWhereNullClause("e")} AND r.entityName = :entityName
			""",
				RowChecksum::class.java
			)
			.setParameter("entityName", entityName)
			.resultList

	/**
	 * Find extraneous entities by performing a left join between the specified entity table and the [RowChecksum] table.
	 *
	 * Avoids triggering the event listener mechanism [de.spree.keycloak.plugins.integrity.SpreeIntegrityValidationListener] by just returning the IDs
	 */
	fun findExtraneousEntitiesByCompositeKey(entityName: String, primaryKey: PrimaryKey): List<Any> =
		em()
			.createQuery(
				"""
			SELECT e.id FROM $entityName e
				LEFT JOIN RowChecksum r ON ${primaryKey.toJPAJoinClause("r", "e")}
					AND r.entityName = :entityName
				WHERE r.entityId IS NULL
			""",
				primaryKey.clazz
			)
			.setParameter("entityName", entityName)
			.resultList

	/**
	 * Persists a [RowChecksum] entity.
	 *
	 * @param rowChecksum The [RowChecksum] to save.
	 */
	fun save(rowChecksum: RowChecksum) {
		em().persist(rowChecksum)
	}

	fun deleteRowChecksums(vararg entityIds: RowChecksumKeyId) {
		// Avoid StaleObjectStateException
		em().createNamedQuery(QUERY_DELETE_CHECKSUMS)
			.setParameter("entityIds", entityIds.toList())
			.executeUpdate()
	}

	fun isTableEmpty(): Boolean = em().createNamedQuery(QUERY_ROW_CHECKSUMS_EMPTY, Boolean::class.java).singleResult
}
