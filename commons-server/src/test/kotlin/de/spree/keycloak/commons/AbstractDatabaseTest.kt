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
@file:Suppress("SqlSourceToSinkFlow")

package de.spree.keycloak.commons

import de.spree.keycloak.commons.configuration.TABLE_ROW_CHECKSUM
import de.spree.keycloak.commons.configuration.TABLE_TABLE_CHECKSUM
import io.mockk.every
import io.mockk.mockk
import jakarta.persistence.EntityManager
import jakarta.persistence.Persistence
import org.keycloak.connections.jpa.JpaConnectionProvider
import org.keycloak.models.jpa.entities.ClientScopeClientMappingEntity
import org.keycloak.models.jpa.entities.UserEntity
import org.keycloak.models.jpa.entities.UserRoleMappingEntity

abstract class AbstractDatabaseTest(
	tableNames: List<String> = listOf(TABLE_ROW_CHECKSUM, TABLE_TABLE_CHECKSUM),
	entities: List<Class<*>> = listOf(UserRoleMappingEntity::class.java, ClientScopeClientMappingEntity::class.java, UserEntity::class.java)
) : AbstractCDITest() {
	private val entityManagerFactory by lazy { Persistence.createEntityManagerFactory("test") }

	protected lateinit var entityManager: EntityManager
	protected val jpaConnectionProvider: JpaConnectionProvider = mockk()

	init {
		beforeTest {
			entityManager = entityManagerFactory.createEntityManager().apply { transaction.begin() }

			every { keycloakSession.getProvider(JpaConnectionProvider::class.java) } returns jpaConnectionProvider
			every<EntityManager> { jpaConnectionProvider.entityManager } returns entityManager
		}

		afterTest {
			if (entityManager.isOpen) {
				tableNames.forEach { entityManager.createNativeQuery("TRUNCATE TABLE $it").executeUpdate() }

				entities.forEach {
					entityManager.createQuery("SELECT e FROM ${it.name} e").resultList.forEach { e ->
						entityManager.remove(e)
					}
				}
				entityManager.transaction.commit()
				entityManager.close()
			}
		}
	}

	protected fun newTransaction() {
		entityManager.flush()
		entityManager.transaction.commit()
		entityManager.transaction.begin()
		entityManager.clear()
	}
}
