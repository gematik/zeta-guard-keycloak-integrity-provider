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
package de.spree.keycloak.it

interface DockerController {
	val kcport: Int
	val kchost: String
	val dbport: Int
	val dbhost: String
	val standalone: Boolean

  fun isStarted(): Boolean

	fun start()

	fun stop()

	fun resetDatabase()

	fun createDatabaseBackup()

}

const val TESTCONTAINERS = "testcontainers"
const val COMPOSE = "docker-compose"
const val PROP_CONTROLLER_IMPL = "spree.docker.controller"

@Suppress("unused")
object DockerControllerFactory {
	val instance: DockerController by lazy {
		when (val property: String = System.getProperty(PROP_CONTROLLER_IMPL, TESTCONTAINERS)) {
			TESTCONTAINERS -> TestContainerDockerController()
			COMPOSE -> DockerComposeController()
			else -> throw IllegalArgumentException("Unknown docker controller: $property")
		}
	}
}
