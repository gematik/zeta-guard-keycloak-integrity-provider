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
package de.spree.keycloak.commons.crypto

interface MultiHash {
    /**
     * Initialize this instance from a previous [current] result.
     */
    fun init(initialHash: ByteArray) : MultiHash

    /**
     * Create a new instance by copying this ones' current state.
     */
    fun copy(): MultiHash

    /**
     * Adds a data element to the multi set.
     */
    fun insert(data: ByteArray): MultiHash

    /**
     * Removes a data element from the multi set.
     */
    fun remove(data: ByteArray): MultiHash

    /**
     * Computes the current hash value of the multi set.
     */
    fun current(): ByteArray

    /**
     * Indicates if the multi set is empty.
     */
    fun isEmpty(): Boolean
}