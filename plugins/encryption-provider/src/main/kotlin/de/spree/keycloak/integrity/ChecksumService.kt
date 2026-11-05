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

import arrow.core.Either
import arrow.core.raise.either
import de.spree.keycloak.commons.EntityConverter.extractIdFromEntity
import de.spree.keycloak.commons.EntityConverter.lookupEntityInfo
import de.spree.keycloak.commons.SimpleSuccess
import de.spree.keycloak.commons.configuration.SpreeEntityConfiguration
import de.spree.keycloak.commons.tableChecksEnabled
import de.spree.keycloak.commons.crypto.toChecksum
import de.spree.keycloak.plugins.integrity.Action.*
import de.spree.keycloak.plugins.integrity.EntityAction
import io.quarkus.runtime.Startup
import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject

@ApplicationScoped
@Startup
class ChecksumService {
	@Inject //
	private lateinit var rowChecksumService: RowChecksumService

	@Inject //
	private lateinit var tableChecksumService: TableChecksumService

	@Inject //
	private lateinit var entityConfiguration: SpreeEntityConfiguration

	/**
	 * Updates the checksums for the given entity.
	 *
	 * This method checks the system status and performs the provided action to update the row checksum if the status allows it. If the status is
	 * RUNNING, it also updates the table checksum.
	 *
	 * Transaction handling is crucial: We are called within a running [org.hibernate.Session.flush] operation. Thus we cannot run additional actions
	 * within this session/transaction, so we have to avoid loading entities or running JPQL from within the listener.
	 *
	 * For example, when an entity has been deleted, the row is gone from the database within the transaction scope, the entity is gone from the session
	 * cache, but other transactions DO NOT see the deletion yet.
	 *
	 * @param entities The entity for which to update the checksums.
	 * @param entityAction The action to perform on the entity, typically updating or deleting the row checksum.
	 */
	fun updateEntityChecksums(entityAction: EntityAction, vararg entities: Any) = either {
		val entityList = entities.toList()

		entityAction.runInTransaction {
			when (entityAction.action) {
				INSERT,
				UPDATE,
				COLLECTION_UPDATE -> rowChecksumService.updateEntityChecksum(entityAction, entityList).bind()

				DELETE -> rowChecksumService.deleteEntityChecksum(entityAction, entityList).bind()

				else -> raise(IllegalStateException("Invalid action »$entityAction« for updating checksums."))
			}

			if (tableChecksEnabled && entityConfiguration.tableChecksumEnabled(entityAction.entityName)) {
				when (entityAction.action) {
					INSERT,
					DELETE -> {
						val entityIds =	entityList.map {
							entityAction.spreeEntityManager.extractIdFromEntity(it).bind()
						}.map { it.id }
						tableChecksumService.updateTableChecksum(entityAction, entityIds).bind()
					}
					else -> { /* other actions do not affect the table checksum */ }
				}
			}
		}.bind()

		SimpleSuccess
	}

	/**
	 * Validates the integrity of a given entity.
	 *
	 * This method:
	 * 1. Identifies the entity.
	 * 2. Retrieves its stored checksum.
	 * 3. Calculates the current checksum based on the entity's current state.
	 * 4. Validates the stored checksum against the current checksum.
	 *
	 * @param entity The entity object to validate.
	 * @return An [Either] containing the result of the validation or a [Throwable].
	 */
	fun validateEntityChecksum(entityAction: EntityAction, entity: Any) = either {
		entityAction.runInTransaction {
			val entityInfo = entityAction.spreeEntityManager.lookupEntityInfo(entity).bind()
			val rowChecksum = rowChecksumService.loadRowChecksum(entityAction, entityInfo.rowChecksumId).bind()
			val storedChecksum = rowChecksum.checksum.toChecksum().bind()

			rowChecksumService.validateChecksum(entityAction, storedChecksum, entityInfo).bind()
		}.bind()
	}.asEntityError(entityAction.entityName, "Verifying row checksum")
}