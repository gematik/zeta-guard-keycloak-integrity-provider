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
import de.spree.keycloak.commons.EntityConverter.lookupEntityInfo
import de.spree.keycloak.commons.EntityInfo
import de.spree.keycloak.commons.toIdObject
import de.spree.keycloak.plugins.encryption.jpa.SpreeEncryptionAttributeConverter
import jakarta.persistence.EntityManager
import org.hibernate.jpa.HibernateHints.HINT_CACHEABLE

/**
 * Data Access Object (DAO) for generic entities
 *
 * This class provides methods to find, retrieve all, and update entities by name.
 */
class EntityDao(entityManager: EntityManager) : AbstractDao(entityManager) {
	/**
	 * Retrieves row count for given entity name
	 *
	 * @return row count
	 */
	@Suppress("SqlSourceToSinkFlow")
	fun getEntityRowCount(entityName: String): Long =
		em().createQuery("SELECT COUNT(*) FROM $entityName", Long::class.java).setHint(HINT_CACHEABLE, "true").singleResult

	/** Retrieves all entities from table */
	@Suppress("SqlSourceToSinkFlow")
	fun loadEntities(entityName: String): List<Any> = em().createQuery("FROM $entityName", Any::class.java).setHint(HINT_CACHEABLE, "true").resultList

	/**
	 * Writes [value] to the given property, verbatim.
	 *
	 * The value is written as-is: callers such as [ScannerService] hand in data they encrypted themselves, and Hibernate would otherwise apply
	 * [SpreeEncryptionAttributeConverter] to the bulk update parameter on top of that, storing doubly encrypted data. The persistence context is
	 * flushed beforehand so that no pending change is written while conversion is suspended.
	 */
	@Suppress("SqlSourceToSinkFlow")
	fun update(entityInfo: EntityInfo, propertyName: String, value: String): Boolean {
		val entity = entityInfo.entity
		val id = entityInfo.entityId.toIdObject()

		em().flush()

		val result =
			SpreeEncryptionAttributeConverter.withoutConversion {
				em()
					.createQuery("UPDATE ${entity.javaClass.simpleName} e SET e.$propertyName = :value WHERE e.id = :id")
					.setParameter("value", value)
					.setParameter("id", id)
					.executeUpdate()
			}

		return result > 0
	}

	fun lookupEntityInfo(entity: Any) = em().lookupEntityInfo(entity)
}
