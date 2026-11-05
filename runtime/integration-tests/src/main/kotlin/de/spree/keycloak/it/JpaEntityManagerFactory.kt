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
package de.spree.keycloak.it

import de.spree.keycloak.commons.configuration.CONFIG_SETTINGS_ENABLE_COLUMN_ENCRYPTION
import jakarta.persistence.EntityManager
import jakarta.persistence.EntityManagerFactory
import org.hibernate.Session
import org.hibernate.cfg.CacheSettings.USE_QUERY_CACHE
import org.hibernate.cfg.CacheSettings.USE_SECOND_LEVEL_CACHE
import org.hibernate.cfg.JdbcSettings.*
import org.hibernate.jpa.boot.internal.EntityManagerFactoryBuilderImpl
import org.hibernate.jpa.boot.internal.PersistenceUnitInfoDescriptor

@Suppress("unused")
class JpaEntityManagerFactory(host: String, port: Int, vararg entityClasses: Class<*>) : AutoCloseable {
	private val entityClasses = entityClasses.map<Class<*>, String> { obj: Class<*> -> obj.getName() }.toSet()
	private val entityManagerFactory: EntityManagerFactory by lazy { createEntityManagerFactory() }
	val entityManager: EntityManager by lazy { entityManagerFactory.createEntityManager() }
	val session: Session
		get() = entityManager.unwrap(Session::class.java)

	var debugSQL = false

	private val properties: Map<String, String> =
		mapOf(
			DIALECT to "org.hibernate.dialect.PostgreSQLDialect",
			JAKARTA_JDBC_DRIVER to "org.postgresql.Driver",
			JAKARTA_JDBC_URL to "jdbc:postgresql://$host:$port/keycloak?ssl=false",
			JAKARTA_JDBC_USER to "wasadmin",
			JAKARTA_JDBC_PASSWORD to "geheim",
			SHOW_SQL to debugSQL.toString(),
			FORMAT_SQL to debugSQL.toString(),
			USE_SECOND_LEVEL_CACHE to "false",
			USE_QUERY_CACHE to "false",
			CONFIG_SETTINGS_ENABLE_COLUMN_ENCRYPTION to "false"
		)

	private fun createEntityManagerFactory(): EntityManagerFactory {
		val persistenceUnitInfo = HibernatePersistenceUnitInfo(javaClass.getSimpleName(), entityClasses, properties.toProperties())
		val builder = EntityManagerFactoryBuilderImpl(PersistenceUnitInfoDescriptor(persistenceUnitInfo), properties)

		return builder.build()
	}

	fun shutdown() {
		entityManagerFactory.close()
	}

	fun newTransaction() {
		if (!entityManager.transaction.isActive) {
			entityManager.transaction.begin()
		} else {
			entityManager.flush()
			entityManager.transaction.commit()
			entityManager.transaction.begin()
			entityManager.clear()
		}
	}

	override fun close() {
		shutdown()
	}
}
