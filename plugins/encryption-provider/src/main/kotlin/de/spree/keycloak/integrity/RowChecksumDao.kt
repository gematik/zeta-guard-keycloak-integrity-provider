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
import de.spree.keycloak.commons.toObject
import jakarta.enterprise.context.ApplicationScoped
import jakarta.persistence.EntityManager
import org.hibernate.jpa.HibernateHints.HINT_CACHEABLE

/**
 * Data Access Object (DAO) for managing [RowChecksum] entities.
 *
 * This class provides methods to find, retrieve all, and save row checksums.
 */
@ApplicationScoped
@Suppress("SqlSourceToSinkFlow")
class RowChecksumDao @JvmOverloads constructor(explicitEntityManager: EntityManager? = null) : AbstractDao(explicitEntityManager) {
  /**
   * Finds a [RowChecksum] by its associated entity ID.
   *
   * @param entityId The ID of the entity to find the checksum for.
   * @return The [RowChecksum] if found, or `null` otherwise.
   */
  fun findByEntityId(entityId: RowChecksumKeyId): RowChecksum? = em().find(RowChecksum::class.java, entityId)

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
              String::class.java,
          )
          .setParameter("entityName", entityName)
          .resultList

  /** Find deleted entities by performing a left join between the [RowChecksum] table and the specified entity table. */
  fun findAbandonedChecksumsByCompositeKey(entityName: String, primaryKey: PrimaryKey): List<RowChecksum> {
    val keyClass = primaryKey.clazz
    val rowChecksums = findAllByEntityName(entityName).associateBy { it.entityId.toObject(keyClass) }.toMutableMap()
    val existingIds =
        em().createQuery("SELECT e.id FROM $entityName e WHERE e.id IN (:ids)", keyClass).setParameter("ids", rowChecksums.keys).resultList

    rowChecksums.keys.removeAll(existingIds)

    return rowChecksums.values.toList()
  }

  /**
   * Find extraneous entities by performing a left join between the specified entity table and the [RowChecksum] table.
   *
   * Avoids triggering the event listener mechanism [de.spree.keycloak.plugins.integrity.SpreeIntegrityValidationListener] by just return the IDs
   */
  fun findExtraneousEntitiesByCompositeKey(entityName: String, primaryKey: PrimaryKey): List<Any> {
    val keyClass = primaryKey.clazz
    val entityIds = findAllByEntityName(entityName).map { it.entityId.toObject(keyClass) }

    return em().createQuery("SELECT e.id FROM $entityName e WHERE e.id NOT IN (:ids)", keyClass).setParameter("ids", entityIds).resultList
  }

  /**
   * Persists a [RowChecksum] entity.
   *
   * @param rowChecksum The [RowChecksum] to save.
   */
  fun save(rowChecksum: RowChecksum) {
    em().persist(rowChecksum)
  }

  /**
   * Deletes a [RowChecksum] entity
   *
   * @param entityId The entityId of the [RowChecksum] to be deleted
   */
  fun deleteByEntityId(entityId: RowChecksumKeyId) {
    findByEntityId(entityId)?.let { em().remove(it) }
  }

  fun deleteEntityChecksums(deletedChecksums: List<RowChecksum>) {
    deletedChecksums.forEach {
      check(em().contains(it))

      em().remove(it)
    }
  }

  fun isTableEmpty(): Boolean = em().createNamedQuery(QUERY_ROW_CHECKSUMS_EMPTY, Boolean::class.java).singleResult
}
