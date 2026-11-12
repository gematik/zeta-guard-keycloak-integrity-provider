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

package de.spree.keycloak.commons

import jakarta.enterprise.inject.spi.CDI
import kotlin.reflect.KClass
import kotlin.reflect.full.declaredMemberProperties
import kotlin.reflect.jvm.isAccessible

/**
 * Injects a value into a field of the given object using reflection. Makes the field accessible if necessary.
 *
 * @param name The name of the field to inject into.
 * @param value The value to set in the field.
 * @param clazz The class containing the field (defaults to the object's class).
 */
inline fun <reified T> T.setValue(name: String, value: Any, clazz: Class<T> = T::class.java): T {
  val field = clazz.getDeclaredField(name)
  field.isAccessible = true
  field.set(this, value)

  return this
}

/** Reads a value from a field of the given object using reflection. */
@Suppress("UNCHECKED_CAST")
fun <T> Any.retrieveValue(propertyName: String, clazz: KClass<*> = this::class): T? {
  val property =
      clazz.declaredMemberProperties.find { it.name == propertyName }
          ?: throw IllegalArgumentException("Property $propertyName not found in class ${clazz.simpleName}")
  property.getter.isAccessible = true
  return property.getter.call(this) as T?
}

/** Convert String value to Enum object */
inline fun <reified E : Enum<*>> String?.toEnum(): E? {
  val enumConstants = E::class.java.enumConstants
  val index = enumConstants.map { e -> e.name }.indexOf(this)

  return if (index >= 0) enumConstants[index] else null
}

/** Obtain service from CDI in objects/classes where injection is not possible */
inline fun <reified T> cdiService(vararg qualifiers: Annotation): T = CDI.current().select(T::class.java, *qualifiers).get()
