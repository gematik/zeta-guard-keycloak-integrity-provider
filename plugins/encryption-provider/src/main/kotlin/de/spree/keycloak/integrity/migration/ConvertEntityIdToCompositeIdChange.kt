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

package de.spree.keycloak.integrity.migration

import de.spree.keycloak.commons.EntityConverter.convertToMap
import de.spree.keycloak.commons.configuration.STRING
import de.spree.keycloak.commons.configuration.SpreeConfigurationProducer
import de.spree.keycloak.commons.configuration.TABLE_ROW_CHECKSUM
import de.spree.keycloak.commons.convertIdValues
import de.spree.keycloak.commons.logger
import de.spree.keycloak.integrity.COLUMN_COMPOSITE_ID1
import de.spree.keycloak.integrity.COLUMN_COMPOSITE_ID2
import de.spree.keycloak.integrity.COLUMN_ENTITY_ID
import de.spree.keycloak.integrity.COLUMN_ENTITY_NAME
import liquibase.change.custom.CustomTaskChange
import liquibase.database.Database
import liquibase.database.jvm.JdbcConnection
import liquibase.exception.ValidationErrors
import liquibase.resource.ResourceAccessor
import java.sql.PreparedStatement
import java.sql.ResultSet

/**
 * Liquibase [CustomTaskChange] that backfills [COLUMN_COMPOSITE_ID1]/[COLUMN_COMPOSITE_ID2] of [TABLE_ROW_CHECKSUM] from the existing [COLUMN_ENTITY_ID] values.
 *
 * For composite entity keys, [COLUMN_ENTITY_ID] holds a JSON object (see [de.spree.keycloak.commons.EntityConverter]); its values, ordered alphabetically by key
 * name, become [COLUMN_COMPOSITE_ID1] and [COLUMN_COMPOSITE_ID2] -- matching how [de.spree.keycloak.integrity.RowChecksumService] populates them for new rows.
 * Plain string entity IDs get empty composite IDs.
 */
open class ConvertEntityIdToCompositeIdChange : CustomTaskChange {
	override fun execute(database: Database) {
		val connection = database.connection as JdbcConnection
		val configuration = getConfiguration()
		val entitiesWithCompositeKeys = configuration.entities.filter { it.primaryKey.className != STRING }.associateBy { it.name }

		logger.infof("🏃 Database migration STARTED for %d entity classes with composited IDs", entitiesWithCompositeKeys.size)

		entitiesWithCompositeKeys.keys.forEach { entityName ->
			logger.infof("🔎 Reading data for entity class »%s«", entityName)

			connection
				.prepareStatement(
					"""UPDATE $TABLE_ROW_CHECKSUM SET $COLUMN_COMPOSITE_ID1 = ?, $COLUMN_COMPOSITE_ID2 = ?
										WHERE $COLUMN_ENTITY_NAME = ? 
										AND $COLUMN_ENTITY_ID = ?""".trimIndent()
				).use { updateStatement ->
					readAndUpdateRowChecksums(connection, updateStatement, entityName)

					updateStatement.executeBatch()
					connection.commit()

					logger.infof("🛠️ Final rows of »%s« updated and committed", entityName)
				}
		}

		logger.info("☑️ Database migration COMPLETED")
	}

	private fun readAndUpdateRowChecksums(connection: JdbcConnection, updateStatement: PreparedStatement, entityName: String) {
		connection.createStatement().use { statement ->
			statement
				.executeQuery(
					"""SELECT $COLUMN_ENTITY_ID FROM $TABLE_ROW_CHECKSUM
															WHERE $COLUMN_ENTITY_NAME = '$entityName' 
															AND $COLUMN_COMPOSITE_ID1 IS NULL""".trimIndent()
				)
				.use { rs ->
					createUpdateStatements(connection, rs, updateStatement, entityName)
				}
		}
	}

	private fun createUpdateStatements(connection: JdbcConnection, rs: ResultSet, updateStatement: PreparedStatement, entityName: String) {
		var updates = 0

		while (rs.next()) {
			val entityId = rs.getString(COLUMN_ENTITY_ID)
			val compositeKeyMap = convertToMap(entityId).convertIdValues()
			val compositeIds = compositeKeyMap.values.toList()

			check(compositeIds.size == 2)

			updateStatement.setString(1, compositeIds[0])
			updateStatement.setString(2, compositeIds[1])
			updateStatement.setString(3, entityName)
			updateStatement.setString(4, entityId)

			updateStatement.addBatch()
			updates++

			if (updates % 100 == 0) {
				updateStatement.executeBatch()
				connection.commit()

				logger.infof("🛠️ 100 rows updated and committed, total %d", updates)
			}
		}
	}

	protected open fun getConfiguration() = SpreeConfigurationProducer().getConfiguration()

	override fun getConfirmationMessage() =
		"Converted $COLUMN_ENTITY_ID into $COLUMN_COMPOSITE_ID1/$COLUMN_COMPOSITE_ID2 for $TABLE_ROW_CHECKSUM"

	override fun setUp() {}

	override fun setFileOpener(resourceAccessor: ResourceAccessor) {}

	override fun validate(database: Database) = ValidationErrors()
}
