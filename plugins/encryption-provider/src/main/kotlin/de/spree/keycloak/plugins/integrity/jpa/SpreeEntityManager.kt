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
package de.spree.keycloak.plugins.integrity.jpa

import de.spree.keycloak.commons.cdiService
import de.spree.keycloak.commons.configuration.SpreeEntityConfiguration
import de.spree.keycloak.commons.debug.SpreeLog
import jakarta.persistence.EntityManager
import jakarta.persistence.Query
import jakarta.persistence.TypedQuery
import org.hibernate.query.hql.spi.SqmQueryImplementor
import org.hibernate.query.sqm.tree.SqmDmlStatement
import java.util.logging.Logger

/**
 * Custom EntityManager wrapper that intercepts named queries to perform integrity checks.
 *
 * This implementation delegates all standard operations to the underlying [EntityManager] and wraps update/delete DML named queries in [SpreeQuery]
 * instances if integrity checks are enabled.
 */
class SpreeEntityManager(private val entityManager: EntityManager) : EntityManager by entityManager {
	private val spreeLogger: Logger by lazy { cdiService(SpreeLog()) }
	private val spreeConfiguration: SpreeEntityConfiguration by lazy { cdiService() }

	/**
	 * Critical: allow callers to reach the underlying Hibernate Session.
	 *
	 * Keycloak's own code calls em.unwrap(Session.class) in several places.
	 */
	override fun <T> unwrap(clazz: Class<T>): T = if (clazz.isAssignableFrom(javaClass)) clazz.cast(this) else entityManager.unwrap(clazz)

	/**
	 * Creates a named query and wraps it in a [SpreeQuery] if it is a DML statement.
	 *
	 * @param queryName The name of the query defined in metadata.
	 * @return The Query instance.
	 */
	override fun createNamedQuery(queryName: String): Query {
		val query = entityManager.createNamedQuery(queryName)

		return if (query is SqmQueryImplementor<*>) {
			createNamedQuery(queryName, query)
		} else {
			query
		}
	}

	/**
	 * Creates a typed named query and wraps it in a [SpreeQuery] if it is a DML statement.
	 *
	 * @param queryName The name of the query defined in metadata.
	 * @param clazz The type of the query result.
	 * @return The TypedQuery instance.
	 */
	override fun <T> createNamedQuery(queryName: String, clazz: Class<T>): TypedQuery<T> {
		val query = entityManager.createNamedQuery(queryName, clazz)

		return if (query is SqmQueryImplementor<T>) {
			createNamedQuery(queryName, query)
		} else {
			query
		}
	}

	/**
	 * Internal helper to check if a named query is a DML statement (insert/update/delete) and wrap it in [SpreeQuery] if it requires integrity checks.
	 */
	private fun <T> createNamedQuery(queryName: String, query: SqmQueryImplementor<T>): TypedQuery<T> {
		if (query.isDMLStatement()) {
			val entityName = query.entityName
			val queryConfiguration = spreeConfiguration.findNamedQuery(entityName, queryName)

			spreeLogger.info("Create named query »$queryName« for entity »$entityName«: ${query.queryString}")

			if (queryConfiguration != null && queryConfiguration.checkQuery) {
				return SpreeQuery(query, entityName, queryConfiguration)
			}
		}

		return query
	}
}

/** Extension function to check if the query is a DML statement. */
private fun SqmQueryImplementor<*>.isDMLStatement() = sqmStatement is SqmDmlStatement

/** Extension property to retrieve the target entity name from a DML query statement. */
private val SqmQueryImplementor<*>.entityName: String
	get() = (sqmStatement as SqmDmlStatement).target.entityName
