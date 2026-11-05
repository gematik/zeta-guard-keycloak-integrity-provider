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
import de.spree.keycloak.commons.configuration.TABLE_CONFIGURATION
import jakarta.persistence.EntityManager
import org.hibernate.jpa.HibernateHints.HINT_CACHEABLE
import org.keycloak.common.util.SecretGenerator
import java.sql.Connection

/**
 * Data Access Object (DAO) for managing [Configuration] entities.
 *
 * This class provides methods to find and set configuration data.
 */
class ConfigurationDao(entityManager: EntityManager) : AbstractDao(entityManager) {
	fun deleteConfiguration(name: String) {
		em().createNamedQuery(QUERY_DELETE_BY_NAME).setParameter("name", name).executeUpdate()
	}

	fun configurationTableExists(): Boolean =
		em().callWithConnection<Connection, Boolean> { connection ->
			val databaseMetaData = connection.metaData
			val tables = mutableSetOf<String>()

			databaseMetaData.getTables(null, null, null, arrayOf("TABLE")).use {
				while (it.next()) {
					val table = it.getString("TABLE_NAME")

					tables.add(table.uppercase())
				}
			}

			return@callWithConnection tables.contains(TABLE_CONFIGURATION)
		}

	fun loadConfiguration(): Map<String, List<String>> =
		em().createNamedQuery(QUERY_LOAD_ALL, Configuration::class.java)
			.setHint(HINT_CACHEABLE, "true").resultList.groupBy(keySelector = { it.name }, valueTransform = { it.value })

	fun addConfiguration(name: String, value: String) {
		em().persist(Configuration(SecretGenerator.getInstance().generateSecureID(), name, value))
	}
}
