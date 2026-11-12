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
package de.spree.keycloak.crypto

import arrow.core.*
import arrow.core.raise.either
import de.spree.keycloak.commons.ENV_CRYPTO_UPDATE_TIMEOUT
import de.spree.keycloak.commons.configuration.SpreeEntityConfiguration
import de.spree.keycloak.commons.entityManager
import de.spree.keycloak.commons.getEnvironment
import de.spree.keycloak.commons.logger
import io.quarkus.runtime.Startup
import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import org.keycloak.models.KeycloakSession
import java.time.Duration

private val CRYPTO_UPDATE_TIMEOUT = Duration.parse(getEnvironment(ENV_CRYPTO_UPDATE_TIMEOUT, "PT10M")).toSeconds()


@ApplicationScoped
@Startup // Enforce creation at startup, thus the bean will be available using CDI.current()
open class CryptoUpdateService {

    @Inject //
    private lateinit var entityConfiguration: SpreeEntityConfiguration

    fun reserveUpdateTask(session: KeycloakSession): Option<CryptoUpdate> = Either.catch {
        createSpreeContextCryptoUpdateDao(session).reserve(CRYPTO_UPDATE_TIMEOUT)
    }.onLeft {
        logger.info("Failed to reserve update task", it)
    }.getOrNull().toOption()

    fun finishUpdateTask(session: KeycloakSession, task: CryptoUpdate) = Either.catch {
        createSpreeContextCryptoUpdateDao(session).delete(task)
    }.mapLeft {
        logger.info("Failed to mark update as finished for »${task.entityName}«", it)
    }.merge()

    fun enqueueEntity(session: KeycloakSession, entityName: String): Either<Throwable, Unit> = Either.catch {
        createSpreeContextCryptoUpdateDao(session).add(entityName)
    }

    fun enqueueAllEntities(session: KeycloakSession): Either<Throwable, Unit> = either {
        entityConfiguration.entityNames.forEach {
            enqueueEntity(session, it).bind()
        }
    }

    fun clearTaskQueue(session: KeycloakSession) = Either.catch {
        createSpreeContextCryptoUpdateDao(session).deleteAll()
    }.mapLeft {
        logger.info("Failed to clear task queue", it)
    }.merge()

    fun getRemainingTasks(session: KeycloakSession): Long = Either.catch {
        createSpreeContextCryptoUpdateDao(session).remaining()
    }.onLeft {
        logger.info("Failed to get remaining tasks", it)
    }.getOrElse { 0L }

    protected open fun createSpreeContextCryptoUpdateDao(session: KeycloakSession) = CryptoUpdateDao(session.entityManager)
}