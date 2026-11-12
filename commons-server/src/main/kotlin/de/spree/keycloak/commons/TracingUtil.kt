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
package de.spree.keycloak.commons

import arrow.core.Either
import arrow.core.getOrElse
import de.spree.keycloak.commons.configuration.LOG_STATE_OPERATIONAL
import de.spree.keycloak.commons.configuration.SystemState
import de.spree.keycloak.commons.crypto.keychain.currentTime
import io.opentelemetry.api.trace.Tracer
import io.opentelemetry.semconv.ServerAttributes
import org.keycloak.models.KeycloakSession
import org.keycloak.quarkus.runtime.tracing.OTelTracingProviderFactory
import org.keycloak.tracing.TracingProvider
import java.net.InetAddress
import java.time.ZoneId

private const val TRACER = "spree.integrity-provider"

val KeycloakSession.tracingProvider: TracingProvider
	get() = getProvider(TracingProvider::class.java, OTelTracingProviderFactory.PROVIDER_ID)

fun KeycloakSession.getTracer(name: String): Tracer = tracingProvider.getTracer(name)

fun KeycloakSession.reportFailure(message: String, systemState: SystemState, error: Throwable? = null) {
	val hostname = Either.catch { InetAddress.getLocalHost().canonicalHostName }.getOrElse { "localhost" }

	val span = getTracer(TRACER)
		.spanBuilder(systemState.name)
		.setAttribute("details", message)
		.setAttribute("error", error?.message ?: "")
		.setAttribute(ServerAttributes.SERVER_ADDRESS, hostname)
		.startSpan()
		.addEvent(systemState.name, currentTime().atZone(ZoneId.systemDefault()).toInstant())

	span.end()
}

fun KeycloakSession.reportSuccess() {
	val hostname = Either.catch { InetAddress.getLocalHost().canonicalHostName }.getOrElse { "localhost" }
	val span = getTracer(TRACER)
		.spanBuilder(SystemState.OPERATIONAL.name)
		.setAttribute("details", LOG_STATE_OPERATIONAL)
		.setAttribute(ServerAttributes.SERVER_ADDRESS, hostname)
		.startSpan()
		.addEvent(SystemState.OPERATIONAL.name, currentTime().atZone(ZoneId.systemDefault()).toInstant())

	span.end()
}
