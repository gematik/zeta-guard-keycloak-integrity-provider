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

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.databind.MapperFeature
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.databind.json.JsonMapper
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule

/**
 * Custom Jackson ObjectMapper configured for consistent JSON serialization. Features include ordering map entries by keys, sorting properties
 * alphabetically, including only non-null values, and handling Java 8 and time types.
 */
val jsonMapper: JsonMapper =
    JsonMapper.builder()
        .addModules(Jdk8Module(), JavaTimeModule())
        .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS)
        .disable(SerializationFeature.FAIL_ON_EMPTY_BEANS)
        .enable(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY)
        .disable(SerializationFeature.WRITE_DURATIONS_AS_TIMESTAMPS)
        .configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, true)
        .serializationInclusion(JsonInclude.Include.NON_NULL)
        .build()

/** Converts any object to its JSON string representation using the configured mapper. */
fun Any.toJSON(): String = jsonMapper.writeValueAsString(this)

/** Convert JSON string back to an object */
inline fun <reified T> String.toObject(): T = toObject(T::class.java)

/** Convert JSON string back to an object */
fun <T> String.toObject(clazz: Class<T>): T = jsonMapper.readValue(this, clazz)
