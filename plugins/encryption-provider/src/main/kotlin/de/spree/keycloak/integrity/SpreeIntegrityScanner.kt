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
@file:Suppress("unused")

package de.spree.keycloak.integrity

import arrow.core.Either
import arrow.core.raise.either
import arrow.core.raise.ensure
import de.spree.keycloak.commons.*
import de.spree.keycloak.commons.configuration.*
import de.spree.keycloak.commons.debug.SpreeLog
import de.spree.keycloak.crypto.CryptoService
import de.spree.keycloak.crypto.SigningService
import de.spree.keycloak.plugins.integrity.Action.*
import de.spree.keycloak.plugins.integrity.EntityAction
import jakarta.persistence.EntityManager
import java.util.logging.Level
import java.util.logging.Logger

/**
 * A singleton object responsible for scanning and verifying database integrity.
 *
 * This scanner is initialized with Hibernate metadata and run scans to detect any data tampering.
 *
 * CDI injection does not work here, unfortunately.
 */
object SpreeIntegrityScanner {
  private val tableChecksumService: TableChecksumService by lazy { cdiService() }
  private val rowChecksumService: RowChecksumService by lazy { cdiService() }
  private val scannerService: ScannerService by lazy { cdiService() }
  private val signingService: SigningService by lazy { cdiService() }
  private val configuration: SpreeEntityConfiguration by lazy { cdiService() }
  private val systemStatusService: SystemStatusService by lazy { cdiService() }
  private val spreeLogger: Logger by lazy { cdiService(SpreeLog()) }
  private val cryptoService: CryptoService by lazy { cdiService() }
  private val entityManager: EntityManager by lazy { cdiService() }

  var scannerStatus: ScannerStatus = ScannerStatus.IDLE
    private set

  /**
   * Computes the initial checksums for all rows in the managed tables and encrypts relevant data.
   *
   * This function is intended to be run once during application startup (e.g., after migration) to establish a baseline for data integrity checks.
   */
  fun initializeRealm(): Either<Throwable, Success> = either {
    val entityConfigurations = configuration.entities

    ensure(rowChecksumService.isInitialState().bind()) { IllegalStateException("Row checksums already initialized") }
    ensure(tableChecksumService.isInitialState().bind()) { IllegalStateException("Table checksums already initialized") }

    scannerStatus = ScannerStatus.INITIALIZING
    logger.info("🛡️ Computing initial checksums for ${entityConfigurations.size} entities...")

    entityConfigurations.forEach { ec ->
      val entityInfos = scannerService.loadEntities(ec.name).bind()

      if (entityInfos.isNotEmpty()) {
        if (checkIntegrity) {
          computeChecksums(EntityAction(INITIALIZE, ec.name, entityManager), entityInfos).bind()
        }

        if (ec.encryptedProperties.isNotEmpty()) {
          encryptColumns(ec, entityInfos).bind()
        }
      }
    }

    logger.info("☑️ Computing initial checksums for ${entityConfigurations.size} entities DONE")
    scannerStatus = ScannerStatus.IDLE
    SimpleSuccess
  }

  /**
   * Runs a scan across all managed tables to verify data integrity.
   *
   * @return An [Either] containing [Success] if the scan completes without errors, or a message text otherwise.
   */
  fun runTableScan(): Either<Throwable, Success> = either {
    ensure(systemStatusService.currentSystemStatus() == SystemStatus.RUNNING) {
      IllegalStateException("Invalid system status ${systemStatusService.currentSystemStatus()}")
    }

    if (checkIntegrity) {
      scannerStatus = ScannerStatus.INITIALIZING

      configuration.entities.forEach {
        val entityName = it.name
        logger.info("🔎 Scanning »$entityName« for integrity...")

        runTableScan(entityName)
            .onLeft { t ->
              val message = "💣 $IT_FAILED Table check failed for »$entityName«"

              if (t.isIntegrityException()) {
                systemStatusService.setSystemStatus(SystemStatus.ERROR_TABLE_CHECKSUM, t)
                logger.fatal(message, t)
              } else {
                logger.error(message, t)
              }
            }
            .onRight { logger.info("☑️ Scanning »$entityName« for integrity DONE") }
            .bind()
      }

      scannerStatus = ScannerStatus.IDLE
    } else {
      logger.info("⚠️ Integrity checks are disabled, skipping table scan")
    }

    SimpleSuccess
  }

  /**
   * Scans a specific entity table for data integrity.
   *
   * This helper function loads all records for the specified [entityName] (verifying row-level checksums and signatures during load) and subsequently
   * verifies the overall table checksum.
   *
   * @param entityName the fully qualified name of the JPA entity to scan.
   * @return [Either] containing [Success] if validation succeeds, or a [Throwable] representing the failure.
   */
  private fun runTableScan(entityName: String) = either {
    val entityInfos =
        scannerService
            .loadEntities(entityName)
            .onLeft { t -> spreeLogger.log(Level.SEVERE, "Row checksum validation failed for »$entityName«", t) }
            .bind() // Loading implicitely validates checksums and signatures

    if (entityInfos.isNotEmpty()) {
      tableChecksumService
          .checkTableChecksum(entityName)
          .onLeft { t -> spreeLogger.log(Level.SEVERE, "Table checksum validation failed for »$entityName«", t) }
          .bind()
    }

    SimpleSuccess
  }

  /**
   * Encrypts configured properties (columns) of the specified entities.
   *
   * Iterates over the properties/columns defined in [entityConfiguration] that require encryption, encrypts their plaintext values using the
   * [CryptoService], and updates them in the database.
   *
   * @param entityConfiguration the configuration detailing which properties to encrypt.
   * @param entityInfos the list of entities to process.
   */
  private fun encryptColumns(entityConfiguration: EntityConfiguration, entityInfos: List<EntityInfo>) = either {
    logger.info("🔐 Encrypting columns of »${entityConfiguration.name}«...")

    entityInfos.forEach { entityInfo ->
      entityConfiguration.encryptedProperties.forEach { epc ->
        val data: String? = entityInfo.entity.retrieveValue(epc.name)

        if (data != null) {
          val encrypted = cryptoService.encrypt(data).bind()

          // Updating the entity in memory via reflection does not work, so we have to use a database update query
          scannerService.update(entityInfo, epc.name, encrypted).bind()
        }
      }
    }

    logger.info("☑️ Encrypting columns of »${entityConfiguration.name}« DONE")
  }

  /**
   * Recomputes and updates checksums in response to lifecycle events/database changes.
   *
   * Supports handling inserts, updates, and deletes to keep checksums in sync. Currently, only the [DELETE] action is supported, which identifies and
   * cleans up abandoned checksums and updates the respective table checksum.
   *
   * @param action the action triggering the re-computation (e.g. INSERT, UPDATE, DELETE).
   * @param queryConfiguration the configuration of the query that triggered the action.
   * @return [Either] containing [Success] on success, or a [Throwable] if the operation is unsupported or fails.
   */
  fun recomputeChecksums(action: EntityAction, queryConfiguration: QueryConfiguration) = either {
    when (action.action) {
      INSERT -> {
        val newEntities = rowChecksumService.findExtraneousEntities(action).bind()

        if (newEntities.isNotEmpty()) {
          tableChecksumService.updateEntityChecksums(newEntities, action).bind()
        }
      }

      DELETE -> {
        val deletedChecksums = rowChecksumService.findAbandonedChecksums(action.entityName).bind()

        if (deletedChecksums.isNotEmpty()) {
          tableChecksumService.updateDeletedEntityChecksums(action, deletedChecksums).bind()
        }
      }

      UPDATE -> TODO("Updating entities not supported yet.")

      else -> raise(IllegalStateException("Invalid action »$action« for updating checksums."))
    }

    SimpleSuccess
  }

  /**
   * Computes and saves both row-level and table-level checksums for a list of entities.
   *
   * For each entity in [entityInfos], a row checksum is computed and saved, and then the overall table-level checksum is computed and updated.
   *
   * @param action the context of the checksum computation action.
   * @param entityInfos the list of entity records to compute checksums for.
   */
  private fun computeChecksums(action: EntityAction, entityInfos: List<EntityInfo>) = either {
    logger.info("🛡 Computing checksums for »${action.entityName}«...")

    entityInfos.forEach { rowChecksumService.updateEntityInfoChecksum(it, action).bind() }
    tableChecksumService.updateTableChecksum(action).bind()

    logger.info("☑️ Computing checksums for »${action.entityName}« DONE")
  }
}

enum class ScannerStatus {
  IDLE,
  SCANNING,
  INITIALIZING,
}
