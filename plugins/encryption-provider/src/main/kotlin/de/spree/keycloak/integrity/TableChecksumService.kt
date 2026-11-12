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
import arrow.core.raise.ensure
import de.spree.keycloak.commons.*
import de.spree.keycloak.commons.configuration.SpreeEntityConfiguration
import de.spree.keycloak.commons.crypto.HashingService
import de.spree.keycloak.commons.crypto.MultiChecksum
import de.spree.keycloak.commons.crypto.toChecksum
import de.spree.keycloak.commons.crypto.toDatabaseRepresentation
import de.spree.keycloak.commons.crypto.toHash
import de.spree.keycloak.plugins.integrity.Action.*
import de.spree.keycloak.plugins.integrity.EntityAction
import io.quarkus.runtime.Startup
import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject

@ApplicationScoped
@Startup
open // Enforce creation at startup, thus the bean will be available using CDI.current()
class TableChecksumService {
	@Inject //
	private lateinit var rowChecksumService: RowChecksumService

	@Inject //
	private lateinit var hashingService: HashingService

	@Inject //
	private lateinit var entityConfiguration: SpreeEntityConfiguration

	fun updateDeletedEntityChecksums(entityAction: EntityAction, deletedChecksums: List<RowChecksum>) = either {
		ensure(entityAction.action == DELETE) { IllegalStateException("Only DELETE action supported for updating checksums with deleted entities.") }

		entityAction.runInTransaction {
			rowChecksumService.deleteRowChecksums(entityAction, deletedChecksums).bind()

			if (tableChecksEnabled && entityConfiguration.tableChecksumEnabled(entityAction.entityName)) {
				val entityIds = deletedChecksums.map { it.entityId }
				updateTableChecksum(entityAction, entityIds).bind()
			}
		}.bind()

		SimpleSuccess
	}

	internal fun calculateTableChecksum(rowChecksums: List<RowChecksum>): Either<Throwable, MultiChecksum> = either {
		val entityIds = rowChecksums.map { it.entityId.toByteArray() }
		val multi = hashingService.init().bind()
		hashingService.insert(multi, *entityIds.toTypedArray()).bind()
	}

	/**
	 * Load all [RowChecksum]s for given entity type and checks if the current entity count matches the count of [RowChecksum] entries.
	 *
	 * We have to respect the circumstance that the current session/transaction does not "see" the entire database state. When called from
	 * [de.spree.keycloak.plugins.integrity.SpreeIntegrityValidationListener], the session has not yet completed flushing, and the checksum might be
	 * calculated based on stale data.
	 *
	 * This applies for two cases: Entity creation and entity deletion.
	 */
	internal fun loadRowChecksums(action: EntityAction) = either {
		val rowChecksums = rowChecksumService.findAllByEntityName(action).bind()

		if (action.action == SCAN) {
			val entityDao = createSpreeContextEntityDao(action)

			val entityCount = catchAll { entityDao.getEntityRowCount(action.entityName) }

			ensure(rowChecksums.size.toLong() == entityCount) {
				IllegalStateException(
					"${action}: Row checksum count (${rowChecksums.size}) does not match entity count ($entityCount) for table »${action.entityName}«"
				)
			}
		}

		rowChecksums
	}

	/**
	 * Updates the table checksum for the specified entities according to the given action.
	 * If there are no more entities afterward also remove the empty table checksum.
	 *
	 * @param action The current operation performed on the entity
	 * @param entityIds The ids of all entities affected by the action
	 */
	fun updateTableChecksum(action: EntityAction, entityIds: List<String>) = either {
		logger.debug("Update table checksum: [${action.action}] for ${action.entityName} affects ${entityIds.size} entities")

		val tableChecksumDao = createSpreeContextTableChecksumDao(action)
		val storedChecksum = catchAll { tableChecksumDao.findForUpdate(action.entityName) }

		val multi = if (action.action == INITIALIZE || storedChecksum == null)
			hashingService.init().bind()
		else
			hashingService.init(storedChecksum.hash.toHash().bind(), storedChecksum.checksum.toChecksum().bind()).bind()

		entityIds.forEach { entityId ->
			when (action.action) {
				INITIALIZE, INSERT -> hashingService.insert(multi, entityId.toByteArray()).bind()
				DELETE -> hashingService.remove(multi, entityId.toByteArray()).bind()
				else -> raise(IllegalStateException("Invalid action »${action.action}« for updating table checksums."))
			}
		}

		if (hashingService.isEmpty(multi).bind() && storedChecksum != null) {
			tableChecksumDao.delete(storedChecksum)
		} else {
			val result = hashingService.finish(multi).bind()
			val hash = result.hash.toBase64()
			val checksum = result.checksum.toDatabaseRepresentation()

			if (storedChecksum == null) {
				val tableChecksum = TableChecksum(action.entityName, hash, checksum)
				tableChecksumDao.save(tableChecksum)
			} else {
				storedChecksum.hash = hash
				storedChecksum.checksum = checksum
			}
		}

		SimpleSuccess
	}

	/**
	 * Check the table checksum for the specified entity.
	 *
	 * @param action The entities for which to perform the check
	 */
	fun checkTableChecksum(action: EntityAction): Either<Throwable, Success> = either {
		val rowChecksums = loadRowChecksums(action).bind()
		val tableChecksum = calculateTableChecksum(rowChecksums).bind()
		val tableChecksumDao = createSpreeContextTableChecksumDao(action)

		val storedTableChecksum = catchAll { tableChecksumDao.findByEntityName(action.entityName) }
			?: raise(IllegalStateException("No table checksum found for entity »${action.entityName}«"))
		val storedChecksum = storedTableChecksum.checksum.toChecksum().bind()

		hashingService.verify(action.entityName, tableChecksum, storedChecksum).bind()

		SimpleSuccess
	}.asEntityError(action.entityName, "Verifying table checksum")

	fun isInitialState(action: EntityAction) = Either.catch {
		val tableChecksumDao = createSpreeContextTableChecksumDao(action)

		tableChecksumDao.isTableEmpty()
	}

	protected open fun createSpreeContextEntityDao(action: EntityAction): EntityDao = EntityDao(action.spreeEntityManager)

	protected open fun createSpreeContextTableChecksumDao(action: EntityAction): TableChecksumDao = TableChecksumDao(action.spreeEntityManager)
}
