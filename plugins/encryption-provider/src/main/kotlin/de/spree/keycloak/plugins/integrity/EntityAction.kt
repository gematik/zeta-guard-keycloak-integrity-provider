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
package de.spree.keycloak.plugins.integrity

import arrow.core.Either
import arrow.core.raise.either
import de.spree.keycloak.commons.createNewSession
import de.spree.keycloak.commons.logger
import jakarta.persistence.EntityManager
import org.hibernate.Session

open class EntityAction(val action: Action, val entityName: String, val keycloakEntityManager: EntityManager, val optionalInfo: String? = null) {
	val clazz: Class<*>
		get() = Class.forName(entityName)

	private val spreeSession: Session by lazy { keycloakEntityManager.createNewSession() }

	open val spreeEntityManager: EntityManager get() = spreeSession.unwrap(EntityManager::class.java)

	fun runInTransaction(body: () -> Unit) = either {
		spreeSession.use { session ->
			val transaction = session.beginTransaction()

			Either.catch { body() }
				.fold(
					ifLeft = {
						logger.error("⚠️ Rolling back internal transaction", it)
						Either.catch { transaction.rollback() }
					},
					ifRight = { Either.catch { transaction.commit() } })
				.bind()
		}
	}

	override fun toString() = action.name + (optionalInfo?.let { "($it)" } ?: "")

	override fun equals(other: Any?): Boolean {
		if (this === other) return true
		if (other !is EntityAction) return false

		if (action != other.action) return false
		if (entityName != other.entityName) return false

		return true
	}

	override fun hashCode(): Int {
		var result = action.hashCode()
		result = 31 * result + entityName.hashCode()
		return result
	}
}

enum class Action {
	INITIALIZE,
	SCAN,
	LOAD,
	INSERT,
	UPDATE,
	COLLECTION_UPDATE,
	DELETE,
}