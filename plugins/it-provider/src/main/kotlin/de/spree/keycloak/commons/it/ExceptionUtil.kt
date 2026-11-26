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
package de.spree.keycloak.commons.it

import java.lang.reflect.UndeclaredThrowableException
import java.sql.SQLException
import kotlin.reflect.full.memberProperties

fun Throwable.getNestedExceptions(): List<Throwable> {
  var cause: Throwable? = this
  val result = mutableListOf<Throwable>()

  while (cause != null) {
    val e = cause
    cause = getCause(cause)
    result.add(e)
  }

  return result
}

private fun getCause(exc: Throwable): Throwable? {
  val cause = exc.cause

  return when {
    (cause == null && exc is SQLException) -> exc.nextException
    (cause == null && exc is UndeclaredThrowableException) -> exc.undeclaredThrowable
    (cause == null && exc.javaClass.name == "org.hibernate.JDBCException") ->
        exc::class.memberProperties.firstOrNull() { it.name == "sqlException" } as Throwable?

    else -> cause
  }
}
