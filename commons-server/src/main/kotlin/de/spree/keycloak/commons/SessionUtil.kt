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
package de.spree.keycloak.commons

import arrow.core.Either
import de.spree.keycloak.commons.configuration.realmName
import jakarta.persistence.EntityManager
import org.hibernate.Session
import org.hibernate.SessionFactory
import org.hibernate.StatelessSession
import org.keycloak.connections.jpa.JpaConnectionProvider
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.models.jpa.JpaRealmProvider
import org.keycloak.utils.KeycloakSessionUtil

val KeycloakSession.entityManager: EntityManager
	get() = getProvider(JpaConnectionProvider::class.java).entityManager

val KeycloakSession.realmProvider: ExtendedRealmProvider
	get() = ExtendedRealmProvider(this, this.entityManager)

fun KeycloakSession.loadEncryptedRealm(): Either<Throwable, RealmModel?> =
	Either.catch { realmProvider.realmByName(realmName) }

class ExtendedRealmProvider(session: KeycloakSession, entityManager: EntityManager) : JpaRealmProvider(session, entityManager, null, null) {
	/**
	 * Inspired by [getRealmByName], but bypasses caching and directly returns model.
	 *
	 * Possibly contains encrypted data, since the attribute converter is not enabled at this point.
	 */
	fun realmByName(name: String): RealmModel? {
		val ids = em.createNamedQuery("getRealmIdByName", String::class.java).setParameter("name", name).getResultList()

		return when (ids.size) {
			0 -> null
			1 -> getRealm(ids[0])
			else -> throw IllegalStateException("Should not be more than one realm with same name »$name«")
		}
	}
}

fun currentKeycloakSession(): KeycloakSession = KeycloakSessionUtil.getKeycloakSession() ?: throw IllegalStateException("KeycloakSession is not available")

fun EntityManager.createStatelessSession(): StatelessSession = entityManagerFactory.unwrap(SessionFactory::class.java).openStatelessSession()

fun EntityManager.createNewSession(): Session = entityManagerFactory.unwrap(SessionFactory::class.java).openSession()
