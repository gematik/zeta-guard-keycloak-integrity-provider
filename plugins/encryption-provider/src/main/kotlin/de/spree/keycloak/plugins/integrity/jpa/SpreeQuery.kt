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
import de.spree.keycloak.commons.configuration.QueryConfiguration
import de.spree.keycloak.commons.configuration.SystemState
import de.spree.keycloak.commons.configuration.SystemStateService
import de.spree.keycloak.commons.debug.SpreeLog
import de.spree.keycloak.commons.logger
import de.spree.keycloak.plugins.integrity.Action
import de.spree.keycloak.plugins.integrity.EntityAction
import de.spree.keycloak.plugins.integrity.SpreeIntegrityValidationListener
import jakarta.persistence.*
import org.hibernate.query.hql.spi.SqmQueryImplementor
import org.hibernate.query.sqm.tree.SqmDmlStatement
import org.hibernate.query.sqm.tree.delete.SqmDeleteStatement
import org.hibernate.query.sqm.tree.insert.SqmInsertStatement
import org.hibernate.query.sqm.tree.update.SqmUpdateStatement
import java.util.*
import java.util.logging.Logger

/**
 * A custom JPA [TypedQuery] wrapper that delegates database query operations to [SqmQueryImplementor] and triggers checksum re-computation when a DML
 * statement (INSERT/UPDATE/DELETE) is executed.
 *
 * @param T The type of the query result.
 * @param query The underlying Hibernate query implementor.
 * @param entityName The name of the target entity.
 * @param queryConfiguration The configuration rules for the query.
 */
@Suppress("OVERRIDE_DEPRECATION", "DEPRECATION")
class SpreeQuery<T>(private val query: SqmQueryImplementor<T>, private val entityName: String, private val queryConfiguration: QueryConfiguration) :
	TypedQuery<T> by query {
	private val spreeLogger: Logger by lazy { cdiService(SpreeLog()) }
	private val validationListener: SpreeIntegrityValidationListener by lazy { cdiService() }
	private val systemStateService: SystemStateService by lazy { cdiService() }

	/**
	 * Unwraps the query to retrieve the underlying implementation or session context.
	 *
	 * @param clazz The class type to unwrap to.
	 * @return The unwrapped instance.
	 */
	override fun <T> unwrap(clazz: Class<T>): T = if (clazz.isAssignableFrom(javaClass)) clazz.cast(this) else query.unwrap(clazz)

	/**
	 * Executes the query as an update/delete DML statement and recomputes entity checksums.
	 *
	 * Throws [IllegalStateException] if there is a query type mismatch or checksum update failure.
	 *
	 * @return The number of database rows affected.
	 */
	override fun executeUpdate(): Int {
		val result = query.executeUpdate()

		if (result > 0) {
			val statement = query.sqmStatement as SqmDmlStatement
			val handled = validationListener.rowIntegrityChecksEnabled(entityName)
			val action = statement.toAction()
			val entityManager = unwrap(EntityManager::class.java)

			check(action.name == queryConfiguration.queryType.name) {
				"Query type mismatch: expected »${queryConfiguration.queryType}«, but got »$action« for query »${query.queryString}«"
			}

			spreeLogger.info("[$action]: Executed DML statement affecting $result rows on entity $entityName with query: »${query.queryString}«")

			if (handled) {
				val entityAction = EntityAction(action, entityName, entityManager)

				QueryChecksumService.recomputeRowAndTableChecksums(entityAction).onLeft { error ->
					logger.error("💣 Failed to recompute checksums for entity $entityName after query »${query.queryString}«", error)
					systemStateService.setSystemState(SystemState.ERROR_UPDATE_CHECKSUMS, error)
				}
			}
		}

		return result
	}

	override fun setMaxResults(maxResult: Int): TypedQuery<T> {
		query.maxResults = maxResult

		return this
	}

	override fun setFirstResult(startPosition: Int): TypedQuery<T> {
		query.firstResult = startPosition

		return this
	}

	override fun setHint(hintName: String, value: Any): TypedQuery<T> {
		query.setHint(hintName, value)

		return this
	}

	override fun <X> setParameter(param: Parameter<X>, value: X): TypedQuery<T> {
		query.setParameter(param, value)

		return this
	}

	override fun setParameter(param: Parameter<Calendar>, value: Calendar, temporalType: TemporalType): TypedQuery<T> {
		query.setParameter(param, value, temporalType)

		return this
	}

	override fun setParameter(param: Parameter<Date>, value: Date, temporalType: TemporalType): TypedQuery<T> {
		query.setParameter(param, value, temporalType)

		return this
	}

	override fun setParameter(name: String, value: Any): TypedQuery<T> {
		query.setParameter(name, value)

		return this
	}

	override fun setParameter(name: String, value: Calendar, temporalType: TemporalType): TypedQuery<T> {
		query.setParameter(name, value, temporalType)

		return this
	}

	override fun setParameter(name: String, value: Date, temporalType: TemporalType): TypedQuery<T> {
		query.setParameter(name, value, temporalType)

		return this
	}

	override fun setParameter(position: Int, value: Any): TypedQuery<T> {
		query.setParameter(position, value)

		return this
	}

	override fun setParameter(position: Int, value: Calendar, temporalType: TemporalType): TypedQuery<T> {
		query.setParameter(position, value, temporalType)

		return this
	}

	override fun setParameter(position: Int, value: Date, temporalType: TemporalType): TypedQuery<T> {
		query.setParameter(position, value, temporalType)

		return this
	}

	override fun setFlushMode(flushMode: FlushModeType): TypedQuery<T> {
		query.flushMode = flushMode

		return this
	}

	override fun setLockMode(lockMode: LockModeType): TypedQuery<T> {
		query.lockMode = lockMode

		return this
	}

	override fun setCacheRetrieveMode(cacheRetrieveMode: CacheRetrieveMode): TypedQuery<T> {
		query.cacheRetrieveMode = cacheRetrieveMode

		return this
	}

	override fun setCacheStoreMode(cacheStoreMode: CacheStoreMode): TypedQuery<T> {
		query.cacheStoreMode = cacheStoreMode

		return this
	}

	override fun setTimeout(timeout: Int): TypedQuery<T> {
		query.timeout = timeout

		return this
	}
}

/**
 * Maps a [SqmDmlStatement] to the corresponding [Action] (INSERT, UPDATE, or DELETE).
 *
 * Throws [IllegalStateException] if the statement is not one of the supported DML types.
 */
private fun SqmDmlStatement<*>.toAction() =
	when (this) {
		is SqmInsertStatement -> Action.INSERT
		is SqmUpdateStatement -> Action.UPDATE
		is SqmDeleteStatement -> Action.DELETE
		else -> throw IllegalStateException("Unsupported DML statement type: ${this::class.java.name}")
	}
