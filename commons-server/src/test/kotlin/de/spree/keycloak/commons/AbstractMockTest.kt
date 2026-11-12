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

import de.spree.keycloak.commons.TestData.client1
import de.spree.keycloak.commons.TestData.clientAttributeEntity
import de.spree.keycloak.commons.TestData.clientAttributeEntityKey
import de.spree.keycloak.commons.TestData.user
import de.spree.keycloak.commons.TestData.userAttribute
import de.spree.keycloak.commons.crypto.HashingService
import de.spree.keycloak.commons.crypto.setupBouncyCastle
import io.mockk.every
import io.mockk.mockk
import jakarta.persistence.EntityManager
import jakarta.persistence.EntityManagerFactory
import jakarta.persistence.PersistenceUnitUtil
import org.hibernate.Session
import org.hibernate.SessionFactory

abstract class AbstractMockTest : AbstractCDITest() {
  val entityManager: Session = mockk()
  val entityManagerFactory: EntityManagerFactory = mockk()
  val sessionFactory: SessionFactory = mockk()
  val persistenceUnitUtil: PersistenceUnitUtil = mockk()
  val hashingService = HashingService().setValue("keychainBundle", keychainBundle)

  init {
    beforeTest {
      every { entityManager.entityManagerFactory } returns entityManagerFactory
      every { entityManagerFactory.persistenceUnitUtil } returns persistenceUnitUtil
      every { entityManagerFactory.unwrap(SessionFactory::class.java) } returns sessionFactory
      every { sessionFactory.openSession() } returns entityManager
      every { entityManager.unwrap(EntityManager::class.java) } returns entityManager
      every { persistenceUnitUtil.getIdentifier(user) } returns USER_ID
      every { persistenceUnitUtil.getIdentifier(userAttribute) } returns userAttribute.id
      every { persistenceUnitUtil.getIdentifier(client1) } returns client1.id
      every { persistenceUnitUtil.getIdentifier(clientAttributeEntity) } returns clientAttributeEntityKey
      every { keycloakSession.entityManager } returns entityManager
    }
  }

  companion object {
    init {
      setupBouncyCastle()
    }
  }
}
