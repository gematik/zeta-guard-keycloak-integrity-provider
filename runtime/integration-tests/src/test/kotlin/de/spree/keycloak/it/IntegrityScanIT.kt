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
@file:Suppress("JpaQlInspection")

package de.spree.keycloak.it

import de.spree.keycloak.commons.USER_ID
import de.spree.keycloak.commons.configuration.SystemState
import de.spree.keycloak.commons.toBase64
import de.spree.keycloak.commons.toObject
import de.spree.keycloak.integrity.*
import io.kotest.assertions.arrow.core.shouldBeLeft
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.core.spec.Order
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.or
import io.kotest.matchers.should
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.contain
import io.kotest.matchers.string.shouldContain
import org.keycloak.models.jpa.entities.UserEntity

@Order(1)
class IntegrityScanIT : AbstractDatabaseIT() {
	init {
		val keycloakWebClient = KeycloakWebClient()
		val userId = RowChecksumKeyId(UserEntity::class.java.name, USER_ID)

		// https://wiki.tech.spree.de/wiki/spaces/120137/pages/628555793/Integrit+tspr+fung+-+Szenarien#%C3%84nderung-von-Daten-in-der-Integrit%C3%A4ts-Tabelle-(Entit%C3%A4ten)
		test("Entity with tampered row checksum causes error") {
			runJPA { jpa ->
				val checksumService = RowChecksumDao(jpa.entityManager)
				val checksum1 = checksumService.findByEntityId(userId).shouldNotBeNull()

				checksum1.checksum = "TheQuickBrownFoxJumpsOverTheLazyDog".toByteArray().toBase64()

				jpa.newTransaction()
			}

			keycloakWebClient.startScan().shouldBeLeft().errorDescription shouldContain "validation failed"
			keycloakWebClient.systemStateEnum() shouldBe SystemState.ERROR_ROW_CHECKSUM
		}

		// https://wiki.tech.spree.de/wiki/spaces/120137/pages/628555793/Integrit+tspr+fung+-+Szenarien#%C3%84nderung-von-Daten-in-der-Integrit%C3%A4ts-Tabelle-(Entit%C3%A4ten)
		test("Entity with tampered table checksum causes error") {
			runJPA { jpa ->
				val checksumService = TableChecksumDao(jpa.entityManager)
				val checksum = checksumService.findByEntityName(UserEntity::class.java.name).shouldNotBeNull()

				checksum.checksum = "TheQuickBrownFoxJumpsOverTheLazyDog".toByteArray().toBase64()

				jpa.newTransaction()
			}

			keycloakWebClient.startScan().shouldBeLeft()
			keycloakWebClient.systemStateEnum() shouldBe SystemState.ERROR_TABLE_CHECKSUM
		}

		// https://wiki.tech.spree.de/wiki/spaces/120137/pages/628555793/Integrit+tspr+fung+-+Szenarien#L%C3%B6schen-von-Daten-aus-der-Integrit%C3%A4ts-Tabelle-(Tabellen)
		test("Entity with deleted table checksum causes error") {
			runJPA { jpa ->
				val checksumService = TableChecksumDao(jpa.entityManager)
				val checksum = checksumService.findByEntityName(UserEntity::class.java.name).shouldNotBeNull()

				jpa.entityManager.remove(checksum)

				jpa.newTransaction()
			}

			keycloakWebClient.startScan().shouldBeLeft().errorDescription shouldContain "No table checksum found"
			keycloakWebClient.systemStateEnum() shouldBe SystemState.ERROR_TABLE_CHECKSUM
		}

		// https://wiki.tech.spree.de/wiki/spaces/120137/pages/628555793/Integrit+tspr+fung+-+Szenarien#%C3%84nderung-von-Daten-einer-Entit%C3%A4t
		test("Entity manipulation is detected") {
			runJPA { jpa ->
				val user = jpa.entityManager.find(UserEntity::class.java, USER_ID)

				user.firstName = "Torsten"
				jpa.newTransaction()
			}

			keycloakWebClient.startScan().shouldBeLeft().errorDescription shouldContain "validation failed"
			keycloakWebClient.systemStateEnum() shouldBe SystemState.ERROR_ROW_CHECKSUM
		}

		// https://wiki.tech.spree.de/wiki/spaces/120137/pages/628555793/Integrit+tspr+fung+-+Szenarien#L%C3%B6schen-einer-Entit%C3%A4t
		test("User deletion is detected") {
			runJPA { jpa ->
				val user = jpa.entityManager.find(UserEntity::class.java, USER_ID)

				jpa.entityManager.createQuery("DELETE FROM UserRoleMappingEntity urmel WHERE urmel.user.id = :id").setParameter("id", user.id).executeUpdate()
				jpa.entityManager.remove(user)

				jpa.newTransaction()
			}

			keycloakWebClient.startScan().shouldBeLeft().errorDescription shouldContain "does not match entity count"
			keycloakWebClient.systemStateEnum() shouldBe SystemState.ERROR_TABLE_CHECKSUM
		}

		// https://wiki.tech.spree.de/wiki/spaces/120137/pages/628555793/Integrit+tspr+fung+-+Szenarien#L%C3%B6schen-einer-Entit%C3%A4ta
		test("User deletion is detected even if checksum table is manipulated, too") {
			runJPA { jpa ->
				val user = jpa.entityManager.find(UserEntity::class.java, USER_ID)

				jpa.entityManager.createQuery("DELETE FROM UserRoleMappingEntity urmel WHERE urmel.user.id = :id").setParameter("id", user.id).executeUpdate()
				jpa.entityManager.createQuery("DELETE FROM RowChecksum rc WHERE rc.entityId = :id").setParameter("id", user.id).executeUpdate()
				jpa.entityManager.remove(user)

				jpa.newTransaction()
			}

			keycloakWebClient.startScan()
				.shouldBeLeft().errorDescription should (contain("HMAC verification failed") or contain("does not match entity count"))
			keycloakWebClient.systemStateEnum() shouldBe SystemState.ERROR_TABLE_CHECKSUM
		}

		// https://wiki.tech.spree.de/wiki/spaces/120137/pages/628555793/Integrit+tspr+fung+-+Szenarien#Hinzuf%C3%BCgen-einer-Entit%C3%A4t
		test("Adding a user is detected") {
			runJPA { jpa ->
				val checksumService = RowChecksumDao(jpa.entityManager)
				val existingChecksum = checksumService.findByEntityId(userId).shouldNotBeNull()
				val existingUser = jpa.entityManager.find(UserEntity::class.java, USER_ID)
				val user =
					UserEntity().apply {
						id = "badguy"
						username = "admin"
						isEnabled = true
						setEmail(existingUser.email, false)
					}
				val rowChecksum = RowChecksum(UserEntity::class.java.name, user.id, null, null, existingChecksum.checksum)

				jpa.entityManager.persist(user)
				jpa.entityManager.persist(rowChecksum)

				jpa.newTransaction()
			}

			keycloakWebClient.startScan().shouldBeLeft().errorDescription shouldContain "Checksum validation failed"
			keycloakWebClient.systemStateEnum() shouldBe SystemState.ERROR_ROW_CHECKSUM
		}

		// https://wiki.tech.spree.de/wiki/spaces/120137/pages/628555793/Integrit+tspr+fung+-+Szenarien#Hinzuf%C3%BCgen-von-Daten-in-die-Integrit%C3%A4ts-Tabelle-(Entit%C3%A4ten)
		test("Adding a row checksum is detected") {
			runJPA { jpa ->
				val checksumService = RowChecksumDao(jpa.entityManager)
				val existingChecksum = checksumService.findByEntityId(userId).shouldNotBeNull()
				val rowChecksum = RowChecksum(UserEntity::class.java.name, "badguy-id", null, null, existingChecksum.checksum)

				jpa.entityManager.persist(rowChecksum)

				jpa.newTransaction()
			}

			keycloakWebClient.startScan().shouldBeLeft().errorDescription shouldContain "does not match entity count"
			keycloakWebClient.systemStateEnum() shouldBe SystemState.ERROR_TABLE_CHECKSUM
		}

		// https://wiki.tech.spree.de/wiki/spaces/120137/pages/628555793/Integrit+tspr+fung+-+Szenarien#Hinzuf%C3%BCgen-von-Daten-in-der-Integrit%C3%A4ts-Tabelle-(Tabellen)
		test("Adding a table checksum is ignored") {
			runJPA { jpa ->
				val checksumService = TableChecksumDao(jpa.entityManager)
				val existingChecksum = checksumService.findByEntityName(UserEntity::class.java.name).shouldNotBeNull()
				val tableChecksum = TableChecksum(TableChecksum::class.java.name, existingChecksum.hash, existingChecksum.checksum)

				jpa.entityManager.persist(tableChecksum)

				jpa.newTransaction()
			}

			keycloakWebClient.startScan().shouldBeRight().reponseObject.toObject<String>() shouldBe SystemState.OPERATIONAL.name
		}

		test("Can perform crypto update") {
			keycloakWebClient.startUpdate().shouldBeRight().reponseObject.toObject<String>() shouldBe SystemState.OPERATIONAL.name
		}
	}

	//	inner class BackgroundLockingService : AutoCloseable {
	//		private val signal = CountDownLatch(1)
	//
	//		fun start() = Thread {
	//			println("Service running...")
	//
	//			runWithConnection { connection ->
	//				val statement = connection.createStatement()
	//				statement.executeUpdate("BEGIN;\nLOCK TABLE keycloak.public.$TABLE_TABLE_CHECKSUM IN ACCESS EXCLUSIVE MODE;")
	//				// Do not COMMIT yet to keep lock alive
	//
	//				signal.await(20, TimeUnit.SECONDS)
	//				statement.executeUpdate("ROLLBACK;")
	//				println("Service shutting down...")
	//			}
	//		}.apply { isDaemon = true }.start()
	//
	//		fun stop() {
	//			signal.countDown()
	//		}
	//
	//		override fun close() {
	//			stop()
	//		}
	//	}

}
