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
package de.spree.keycloak.commons.debug

import jakarta.enterprise.context.ApplicationScoped
import jakarta.enterprise.inject.Produces
import java.util.logging.Logger

/**
 * Create a [SpreeLog] implementation for development.
 *
 * Configure an sepcial logger writing checksum data and the like to a file for debugging purposes
 */
@ApplicationScoped
class SpreeDebugProducer {
	@Produces
	@SpreeLog //
	fun produceSpreeLogger(): Logger = SpreeDebuggingConfigurator.spreeLogger

	@Produces
	@SpreeEntityInfoWriter //
	fun produceSpreeEntityInfoWriter(): EntityInfoWriter = SpreeEntityInfoWriterImpl()
}
