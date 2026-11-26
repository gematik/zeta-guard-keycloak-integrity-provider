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
import de.spree.keycloak.crypto.Checksum
import de.spree.keycloak.crypto.SigningService
import de.spree.keycloak.crypto.keychain.CurrentKeychain
import de.spree.keycloak.crypto.toChecksum
import de.spree.keycloak.crypto.toDatabaseRepresentation
import de.spree.keycloak.plugins.integrity.Action.*
import de.spree.keycloak.plugins.integrity.EntityAction
import io.quarkus.runtime.Startup
import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject

@ApplicationScoped
@Startup // Enforce creation at startup, thus the bean will be available using CDI.current()
class TableChecksumService : AbstractDao() {
  @Inject //
  private lateinit var rowChecksumService: RowChecksumService

  @Inject //
  private lateinit var entityDao: EntityDao

  @Inject //
  private lateinit var tableChecksumDao: TableChecksumDao

  @Inject //
  private lateinit var signingService: SigningService

  @Inject //
  private lateinit var currentKeychain: CurrentKeychain

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
  fun updateEntityChecksums(entities: List<Any>, entityAction: EntityAction) = either {
    when (entityAction.action) {
      INSERT,
      UPDATE,
      UPSERT,
      COLLECTION_UPDATE -> rowChecksumService.updateEntityChecksum(entities, entityAction).bind()

      DELETE -> rowChecksumService.deleteEntityChecksum(entities, entityAction).bind()

      else -> raise(IllegalStateException("Invalid action »$entityAction« for updating checksums."))
    }

    updateTableChecksum(entityAction).bind()

    SimpleSuccess
  }

  fun updateDeletedEntityChecksums(entityAction: EntityAction, deletedChecksums: List<RowChecksum>) = either {
    ensure(entityAction.action == DELETE) { IllegalStateException("Only DELETE action supported for updating checksums with deleted entities.") }

    rowChecksumService.deleteRowChecksums(deletedChecksums).bind()

    updateTableChecksum(entityAction).bind()

    SimpleSuccess
  }

  fun calculateTableChecksum(rowChecksums: List<RowChecksum>): Either<Throwable, Checksum> = either {
    val checksums = rowChecksums.map { it.checksum.toChecksum().bind().hash }.toTypedArray()
    val hash = toHash(*checksums)
    val signature = signingService.sign(hash).bind()
    val keychain = currentKeychain.keychain().bind()

    ensure(hash.size == HASH_SIZE) { IllegalStateException("Invalid hash size: ${hash.size}") }

    Checksum(keychain.keychainId.toByteArray(), hash, signature)
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
  fun loadRowChecksums(action: EntityAction) = either {
    val rowChecksums = rowChecksumService.findAllByEntityName(action.entityName).bind()

    if (action.action == SCAN) {
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
   * Updates the table checksum for the specified entity.
   *
   * @param action The current operation performed on the entity
   */
  fun updateTableChecksum(action: EntityAction) = either {
    val rowChecksums = loadRowChecksums(action).bind()
    val storedChecksum = catchAll { tableChecksumDao.findChecksum(action.entityName) }

    if (rowChecksums.isNotEmpty()) {
      val checksum = calculateTableChecksum(rowChecksums).bind().toDatabaseRepresentation()
      val tableChecksum = storedChecksum ?: TableChecksum(action.entityName, checksum)

      tableChecksum.checksum = checksum

      if (storedChecksum == null) {
        tableChecksumDao.save(tableChecksum)
      }
    } else if (storedChecksum != null) {
      tableChecksumDao.delete(storedChecksum)
    }

    SimpleSuccess
  }

  /**
   * Check the table checksum for the specified entity.
   *
   * @param entityName The entities for which to perform the check
   */
  fun checkTableChecksum(entityName: String): Either<Throwable, Success> = either {
    val action = EntityAction(SCAN, entityName, em())
    val rowChecksums = loadRowChecksums(action).bind()
    val tableChecksum = calculateTableChecksum(rowChecksums).bind()
    val storedTableChecksum =
        catchAll { tableChecksumDao.findChecksum(entityName) } ?: raise(IllegalStateException("No table checksum found for entity »$entityName«"))
    val storedChecksum = storedTableChecksum.checksum.toChecksum().bind()

    ensure(storedChecksum.hash.contentEquals(tableChecksum.hash)) { RuntimeException("Table checksum mismatch for »$entityName«") }

    SimpleSuccess
  }

  fun delete(entityName: String) = either { catchAll { tableChecksumDao.delete(entityName) } }

  fun isInitialState() = Either.catch { tableChecksumDao.isTableEmpty() }
}
