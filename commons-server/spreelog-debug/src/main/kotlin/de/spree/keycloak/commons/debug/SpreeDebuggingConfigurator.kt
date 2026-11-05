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

import org.jboss.logmanager.Level
import org.jboss.logmanager.LogContext
import org.jboss.logmanager.Logger
import org.jboss.logmanager.formatters.PatternFormatter
import org.jboss.logmanager.handlers.FileHandler
import java.io.File

internal val spreeDirectory: File by lazy {
	File("/opt/keycloak/data/log/spree").also {
		if (!it.exists()) {
			require(it.mkdirs())
		}
	}
}

object SpreeDebuggingConfigurator {
	internal val spreeLogger: Logger by lazy { createSpreeLogger() }

	private fun createSpreeLogger(): Logger {
		val logFile = File(spreeDirectory, "spree.log")
		val formatter = PatternFormatter("%d{yyyy-MM-dd HH:mm:ss,SSS} %-5p [%c] (%t) %s%e%n")
		val fileHandler =
			FileHandler(formatter, logFile, false).apply {
				level = java.util.logging.Level.ALL
				isAutoFlush = true
			}

		val spreeLogger = LogContext.getLogContext().getLogger(PACKAGE_LOGGER)

		spreeLogger.addHandler(fileHandler)
		spreeLogger.level = Level.DEBUG
		spreeLogger.useParentHandlers = false // Set to false to log ONLY to this file

		return spreeLogger
	}
}
