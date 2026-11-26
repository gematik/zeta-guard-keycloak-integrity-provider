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
import de.spree.keycloak.commons.EntityInfo
import de.spree.keycloak.commons.catchAll
import io.quarkus.runtime.Startup
import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject

@ApplicationScoped
@Startup // Enforce creation at startup, thus the bean will be available using CDI.current()
class ScannerService {
  @Inject //
  private lateinit var entityDao: EntityDao

  fun loadEntities(entityName: String): Either<Throwable, List<EntityInfo>> = either {
    val entities = catchAll { entityDao.loadEntities(entityName) }

    entities.map { entityDao.lookupEntityInfo(it).bind() }
  }

  fun update(entityInfo: EntityInfo, propertyName: String, value: String) = Either.catch { entityDao.update(entityInfo, propertyName, value) }
}
