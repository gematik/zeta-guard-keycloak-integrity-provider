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
package de.spree.keycloak.plugins.integrity.jpa

import arrow.core.Either
import arrow.core.raise.either
import de.spree.keycloak.commons.SimpleSuccess
import de.spree.keycloak.commons.Success
import de.spree.keycloak.commons.cdiService
import de.spree.keycloak.integrity.ChecksumService
import de.spree.keycloak.integrity.RowChecksumService
import de.spree.keycloak.integrity.TableChecksumService
import de.spree.keycloak.plugins.integrity.Action.*
import de.spree.keycloak.plugins.integrity.EntityAction

object QueryChecksumService {
	private val tableChecksumService: TableChecksumService by lazy { cdiService() }
	private val checksumService: ChecksumService by lazy { cdiService() }
	private val rowChecksumService: RowChecksumService by lazy { cdiService() }

	/**
	 * Recomputes and updates checksums in response to lifecycle events/database changes.
	 *
	 * Supports handling inserts, updates, and deletes to keep checksums in sync.
	 * For an [INSERT] action, identify newly added entities and update the respective row and table checksums.
	 * For a [DELETE] action, identify and clean up abandoned checksums and update the respective table checksum.
	 *
	 * Currently, [UPDATE] and other actions are not supported.
	 *
	 * @param action the action triggering the re-computation (e.g. INSERT, UPDATE, DELETE).
	 * @return [Either] containing [Success] on success, or a [Throwable] if the operation is unsupported or fails.
	 */
	fun recomputeRowAndTableChecksums(action: EntityAction) = either {
		when (action.action) {
			INSERT -> {
				val newEntities = rowChecksumService.findExtraneousEntities(action).bind()

				if (newEntities.isNotEmpty()) {
					checksumService.updateEntityChecksums(action, *newEntities.toTypedArray()).bind()
				}
			}

			DELETE -> {
				val deletedChecksums = rowChecksumService.findAbandonedChecksums(action).bind()

				if (deletedChecksums.isNotEmpty()) {
					tableChecksumService.updateDeletedEntityChecksums(action, deletedChecksums).bind()
				}
			}

			UPDATE -> raise(UnsupportedOperationException("Updating entities not supported (yet)."))

			else -> raise(IllegalStateException("Invalid action »$action« for updating checksums."))
		}

		SimpleSuccess
	}
}