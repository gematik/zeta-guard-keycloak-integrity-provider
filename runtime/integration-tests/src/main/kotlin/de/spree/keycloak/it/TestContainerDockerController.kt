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

package de.spree.keycloak.it

import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.testcontainers.containers.ComposeContainer
import org.testcontainers.containers.ContainerState
import org.testcontainers.containers.output.Slf4jLogConsumer
import org.testcontainers.containers.wait.strategy.Wait
import org.testcontainers.utility.MountableFile.forClasspathResource
import java.io.File
import java.time.Duration
import kotlin.jvm.optionals.getOrElse
import kotlin.system.exitProcess

class TestContainerDockerController : DockerController {
	private var running = false

	private val log: Logger = LoggerFactory.getLogger(this.javaClass)

	private val docker: ComposeContainer =
		ComposeContainer(File("./docker-compose-it.yml"))
			.withLogConsumer("keycloak", Slf4jLogConsumer(log).withMdc("container", "keycloak"))
			.withLogConsumer("keycloak-db", Slf4jLogConsumer(log).withMdc("container", "keycloak-db"))
			.withExposedService("keycloak", 8080, Wait.forHttp("/realms/master").forPort(8080).withStartupTimeout(Duration.ofSeconds(240)))
			.withExposedService("keycloak-db", 5432, Wait.forListeningPort())
			.withRemoveVolumes(true)
			.withPull(true)

	override val kchost: String by lazy { if (running) docker.getServiceHost("keycloak", 8080) else "localhost" }
	override val kcport: Int by lazy { if (running) docker.getServicePort("keycloak", 8080) else 18080 }
	override val dbhost: String by lazy { if (running) docker.getServiceHost("keycloak-db", 5432) else "localhost" }
	override val standalone: Boolean = false

	override fun isStarted(): Boolean = running

	override val dbport: Int by lazy { if (running) docker.getServicePort("keycloak-db", 5432) else 15432 }

	//	val jdbcUrl: String by lazy { "jdbc:postgresql://$dbhost:$dbport/keycloak?ssl=false&user=wasadmin&password=geheim" }

	override fun start() {
		log.info("Starting Docker compose ... " + running())

		if (!isStarted()) {
			try {
				docker.start()
				running = true
			} catch (e: Throwable) {
				log.error("Error starting Docker compose ...", e)
				exitProcess(1)
			}
		}
	}

	override fun stop() {
		log.info("Shutdown Docker compose ... " + running())

		if (running) {
			try {
				docker.stop()
			} catch (e: Throwable) {
				log.error("Error stopping Docker compose ...", e)
			}

			running = false
		}
	}

	override fun resetDatabase() {
		val container: ContainerState = lookupContainer("keycloak-db")

		log.info("Resetting database ...")

		//		container.executeSQLScript("/tmp/cancel_locks.sql")
		container.executeSQLScript("/tmp/truncate_tables.sql")
		container.executeSQLScript("/tmp/keycloak_dump.sql")

		log.info("Database restored")
	}

	private fun running(): String = if (running) "already running" else "not running"

	private fun ContainerState.executeSQL(command: String, database: String = "keycloak") =
		executeCommand("psql", "-U", "wasadmin", "-d", database, "-c", command)

	private fun ContainerState.executeSQLScript(file: String, database: String = "keycloak") =
		executeCommand("psql", "-U", "wasadmin", "-d", database, "-f", file)

	private fun ContainerState.executeCommand(vararg commands: String) =
		execInContainer(*commands).let {
			if (it.stdout.isNotBlank()) {
				log.info("Command output: ${it.stdout.replace('\n', ' ')}")
			}

			if (it.stderr.isNotBlank()) {
				log.info("Command error output: ${it.stderr}")
			}

			if (it.exitCode != 0) {
				throw IllegalStateException("Error running psql: ${it.stderr}")
			}
		}

	private fun lookupContainer(@Suppress("SameParameterValue") name: String): ContainerState =
		docker.getContainerByServiceName(name).getOrElse { throw IllegalStateException("Container $name not found") }

	override fun createDatabaseBackup() {
		val container = lookupContainer("keycloak-db")

		log.info("Creating database backup ...")

		container.copyFileToContainer(forClasspathResource("/truncate_tables.sql"), "/tmp/truncate_tables.sql")
		container.copyFileToContainer(forClasspathResource("/cancel_locks.sql"), "/tmp/cancel_locks.sql")
		container.copyFileToContainer(forClasspathResource("/create_backup.sh"), "/tmp/create_backup.sh")

		container.executeCommand("sh", "/tmp/create_backup.sh")
	}
}
