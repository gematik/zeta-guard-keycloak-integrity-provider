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

package de.spree.keycloak.plugins.encryption

import de.spree.keycloak.commons.AbstractDatabaseTest
import de.spree.keycloak.commons.TestData.realm
import de.spree.keycloak.commons.TestData.realmAttribute
import de.spree.keycloak.integrity.CONFIG_CONVERSION_STATE
import de.spree.keycloak.integrity.CONFIG_FEATURES
import de.spree.keycloak.integrity.ConfigurationDao
import de.spree.keycloak.integrity.ConfigurationService
import de.spree.keycloak.integrity.SpreeDatabaseConversionState
import de.spree.keycloak.integrity.SpreeFeature
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import jakarta.persistence.ConnectionFunction
import java.sql.Connection
import org.keycloak.models.jpa.entities.RealmEntity

/**
 * This is what ZETAVAU-53 looked like — Keycloak refused to start (log abridged, timestamps and tracing fields removed):
 *
 * ```
 * ERROR [org.hibernate.orm.core] (executor-thread-1) HHH000099: an assertion failure occurred (this may indicate a bug in
 *     Hibernate, but is more likely due to unsafe use of the session): org.hibernate.AssertionFailure:
 *     collection owner not associated with session: org.keycloak.models.jpa.entities.RealmEntity.attributes
 * ERROR [...cli.ExecutionExceptionHandler] ERROR: Failed to start server in (production) mode
 * ERROR [...cli.ExecutionExceptionHandler] ERROR: Database operation failed
 * ERROR [...cli.ExecutionExceptionHandler] ERROR: Error attempting to apply AttributeConverter
 * ERROR [...cli.ExecutionExceptionHandler] ERROR: collection owner not associated with session:
 *     org.keycloak.models.jpa.entities.RealmEntity.attributes
 * ```
 *
 * Read from the bottom: »Error attempting to apply AttributeConverter« comes from `AttributeConverterBean.toDomainValue`, i.e. Hibernate was
 * *reading* a realm attribute and handed it to this plugin's converter. Hibernate's own hint says the rest — »unsafe use of the session«.
 *
 * **The problem was never the conversion, it was the side lookup that comes with it.** As long as the integrity provider has not reached
 * »OPERATIONAL« — which only happens once `SpreeBootstrapProcessor` has checked the realm setup — the converter cannot tell from memory whether
 * the database is encrypted and has to ask `ConfigurationService` for the conversion state, which lives in the SPREE_CONFIGURATION table. That query
 * used to run on Keycloak's own session, and a Hibernate session is not reentrant: the converter is called from inside Hibernate, while a load or a
 * flush is halfway through, and a query makes that very session auto-flush itself. Two consequences, both fatal, both observed:
 * - **on startup:** the collection of realm attributes was being loaded and its owner was not yet registered in the persistence context, because
 *   Hibernate registers the entity only at the end of a two-phase load. `Collections.processDereferencedCollection` looked the owner up, found
 *   nothing — the assertion above;
 * - **in this test:** the auto-flush re-enters the action queue that the outer flush is currently working off, so the still pending insert of a
 *   configuration row is executed a second time and H2 answers with a `ConstraintViolationException`. That stack shows the reentrancy directly —
 *   `AbstractFlushingEventListener.performExecutions` appears twice, with the converter in between:
 *
 * ```
 * SessionImpl.flush → performExecutions → SpreeEncryptionAttributeConverter.convertToDatabaseColumn
 *   → ConfigurationService.loadConfiguration → SessionImpl.autoFlushIfRequired → performExecutions 💥
 * ```
 *
 * Note that the table the query touches is irrelevant: `DefaultAutoFlushEventListener` walks the whole persistence context in
 * `flushEverythingToExecutions` and only afterwards checks whether the query spaces overlap at all.
 *
 * **The conversion itself belongs into Keycloak's session and stays there.** The converter protects exactly the values Keycloak reads and writes, so
 * it runs where Keycloak works: it encrypts what Keycloak's session flushes, decrypts what that session loads, and takes part in Keycloak's
 * transaction — a rollback takes the encrypted value with it. Moving that elsewhere would encrypt the wrong data at the wrong time.
 *
 * **Only the lookup got a session of its own,** see
 * [EntityAction.withIsolatedSession][de.spree.keycloak.plugins.integrity.EntityAction.withIsolatedSession]: its own persistence context and its own
 * action queue, so there is nothing to re-enter. The transaction boundary stays as it was — under JTA that session joins Keycloak's transaction. It
 * does see committed data only, which is fine for a state written once during database conversion, and the `Given` steps below are arranged
 * accordingly.
 *
 * This test pins both halves — Keycloak's own attributes are encrypted, decrypted and rolled back with its transaction, and the lookup leaves that
 * session's pending work untouched.
 *
 * **Keep this class down to a single test:** the converter instances belong to the EntityManagerFactory and cache their `ConfigurationService`
 * (which in turn caches the conversion state) on first use. From the second test onwards the converter would answer from that cache and no longer
 * touch the database — the test would still be green, but would no longer cover the lookup.
 */
class BootstrapConversionTest : AbstractDatabaseTest() {
	init {
		// A converter that has never run yet, i.e. one that still has to look up the conversion state
		beforeTest { trainCDIService<ConfigurationService>(ConfigurationService()) }

		test("Convert realm attributes while the integrity provider is still bootstrapping") {
			// Given: a fresh SystemStateService starts in »STARTUP« and nothing here advances it to »OPERATIONAL«. So the converter
			// cannot answer »is this database encrypted?« from memory and has to look the conversion state up in the database.
			systemStateService.currentSystemState().isBootstrapState().shouldBeTrue()

			// Given: the state it is going to find there. Committed, because the lookup uses a session of its own and such a session
			// sees committed data only — on startup that state likewise comes from an earlier run or from another node.
			ConfigurationDao(entityManager).addConfiguration(CONFIG_CONVERSION_STATE, SpreeDatabaseConversionState.DONE.name)

			newTransaction()

			// Given: one more configuration row, this one left unflushed on purpose. It is the tripwire: were the lookup issued on
			// Keycloak's session, that session would auto-flush and insert this row — and the flush below would insert it again.
			ConfigurationDao(entityManager).addConfiguration(CONFIG_FEATURES, SpreeFeature.COLUMN_ENCRYPTION.name)

			// When: flushing the realm attribute . Its value is the only encrypted property in play (see spree-configuration.yml),
			// so this is where Hibernate calls the converter for the first time — and therefore where the lookup happens, mid-flush.
			entityManager.persist(realm)
			entityManager.persist(realmAttribute)

			newTransaction()

			// Then: encrypted on the way in. Read past Hibernate, the column no longer holds the plain value.
			loadAttributeValueFromDatabase() shouldNotBe realmAttribute.value

			// Then: decrypted on the way out. The converter runs once more, this time while Hibernate loads the attribute collection.
			val realmEntity = entityManager.find(RealmEntity::class.java, realm.id)

			realmEntity.attributes.map { it.value } shouldBe listOf(realmAttribute.value)

			// Then: Keycloak's transaction governs the encrypted value. An encrypted write that is rolled back leaves nothing behind,
			// which it would not if the converter wrote through a transaction of its own.
			realmEntity.attributes.first().value = "rolled back"
			entityManager.flush()
			rollbackTransaction()

			entityManager.find(RealmEntity::class.java, realm.id).attributes.map { it.value } shouldBe listOf(realmAttribute.value)
		}
	}

	private fun rollbackTransaction() {
		entityManager.transaction.rollback()
		entityManager.transaction.begin()
		entityManager.clear()
	}

	/** Bypasses Hibernate, so we see what is actually stored in the column rather than the decrypted value. */
	private fun loadAttributeValueFromDatabase(): String? =
		entityManager.callWithConnection(
			ConnectionFunction<Connection, String> {
				val resultSet = it.createStatement().executeQuery("""SELECT "VALUE" FROM realm_attribute WHERE realm_id = '${realm.id}'""")

				require(resultSet.next()) { "Realm attribute not found" }

				resultSet.getString(1)
			})
}
