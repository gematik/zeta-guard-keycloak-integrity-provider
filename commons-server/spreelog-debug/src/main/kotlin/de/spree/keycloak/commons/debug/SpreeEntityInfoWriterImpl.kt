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

import de.spree.keycloak.commons.EntityInfo
import java.io.File
import java.io.OutputStreamWriter
import java.time.LocalDateTime
import java.time.temporal.ChronoUnit.SECONDS

private const val SEPARATOR = ","
private const val QUOTE = '"'

class SpreeEntityInfoWriterImpl : EntityInfoWriter {
	private val writerCache: MutableMap<String, OutputStreamWriter> = mutableMapOf()

	override fun writeEntityInfo(entity: EntityInfo, vararg args: Any) {
		val id = escape(entity.id)
		val date = escape(LocalDateTime.now().truncatedTo(SECONDS))
		val thread = escape(Thread.currentThread().name)
		val columns = listOf(id, thread, date).plus(args.map { escape(it) })
		val text = columns.joinToString(separator = SEPARATOR)
		val writer = getWriter(entity)

		writer.appendLine(text)
		writer.flush()
	}

	private fun getWriter(entity: EntityInfo): OutputStreamWriter {
		if (!writerCache.containsKey(entity.entityName)) {
			val writer = File(spreeDirectory, entity.entityName + ".csv").writer()

			writer.appendLine("ID,THREAD,DATE,ACTION,OLD,NEW")
			writerCache[entity.entityName] = writer
		}

		return writerCache[entity.entityName]!!
	}

	private fun escape(value: Any): String {
		val text = value.toString()
		val escape = text.contains(SEPARATOR) || text.contains(QUOTE)

		return if (escape) {
			QUOTE + text.replace("$QUOTE", "$QUOTE$QUOTE") + QUOTE
		} else {
			text
		}
	}
}