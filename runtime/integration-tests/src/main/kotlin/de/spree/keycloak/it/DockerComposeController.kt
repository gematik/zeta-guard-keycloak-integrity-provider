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

import com.github.dockerjava.api.DockerClient
import com.github.dockerjava.api.async.ResultCallback
import com.github.dockerjava.api.model.Container
import com.github.dockerjava.api.model.Frame
import com.github.dockerjava.core.DockerClientBuilder
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.util.concurrent.TimeUnit
import org.apache.commons.compress.archivers.tar.TarArchiveEntry
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream
import org.apache.commons.io.IOUtils
import org.slf4j.Logger
import org.slf4j.LoggerFactory

class DockerComposeController : DockerController {
  private val log: Logger = LoggerFactory.getLogger(this.javaClass)
  private val docker: DockerClient by lazy { DockerClientBuilder.getInstance().build() }

  override val kcport: Int = 18080
  override val kchost: String = "localhost"
  override val dbport: Int = 15432
  override val dbhost: String = "localhost"
  override val standalone: Boolean = true

  override fun isStarted(): Boolean = docker.listContainersCmd().exec().isNotEmpty()

  override fun start() {
    isStarted() // access docker object
  }

  override fun stop() {
    log.warn("To be stopped manually")
  }

  override fun resetDatabase() {
    val container: Container = lookupContainer("keycloak-db")

    log.info("Resetting database ...")

    //		container.executeSQLScript("/tmp/cancel_locks.sql")
    container.executeSQLScript("/tmp/truncate_tables.sql")
    container.executeSQLScript("/tmp/keycloak_dump.sql")

    log.info("Database restored")
  }

  fun lookupContainer(containerName: String): Container =
      docker.listContainersCmd().withNameFilter(listOf(containerName)).exec().firstOrNull()
          ?: throw IllegalStateException("Container $containerName not found")

  private fun Container.executeCommand(vararg commands: String) {
    val exec = docker.execCreateCmd(this.id).withCmd(*commands).withAttachStdout(true).withAttachStderr(true).exec()

    log.info("Executing command: ${commands.joinToString(" ")} ...")
    val buffer = StringBuilder()
    val resultCallback =
        object : ResultCallback.Adapter<Frame>() {
          override fun onNext(frame: Frame) {
            buffer.append(String(frame.payload))
          }
        }
    docker.execStartCmd(exec.id).exec<ResultCallback<Frame>>(resultCallback)
    resultCallback.awaitCompletion(20, TimeUnit.SECONDS)
    log.info("Command output: $buffer")
    log.info("Executing command: ${commands.joinToString(" ")} DONE")
  }

  private fun Container.executeSQLScript(file: String, database: String = "keycloak") =
      executeCommand("psql", "-U", "wasadmin", "-d", database, "-f", file)

  override fun createDatabaseBackup() {
    val container = lookupContainer("keycloak-db")

    log.info("Copying scripts to container ...")

    val tarStream =
        createTar(
            mapOf(
                "truncate_tables.sql" to IOUtils.resourceToByteArray("/truncate_tables.sql"),
                "cancel_locks.sql" to IOUtils.resourceToByteArray("/cancel_locks.sql"),
                "create_backup.sh" to IOUtils.resourceToByteArray("/create_backup.sh"),
            )
        )

    docker.copyArchiveToContainerCmd(container.id).withTarInputStream(tarStream).withRemotePath("/tmp/").exec()

    log.info("Creating database backup ...")

    container.executeCommand("sh", "/tmp/create_backup.sh")
  }
}

fun createTar(entries: Map<String, ByteArray>): InputStream {
  val baos = ByteArrayOutputStream()
  val tarOut = TarArchiveOutputStream(baos)

  entries.forEach { (filename, content) ->
    val entry = TarArchiveEntry(filename).apply { size = content.size.toLong() }

    tarOut.putArchiveEntry(entry)
    tarOut.write(content)
    tarOut.closeArchiveEntry()
  }

  tarOut.finish()
  tarOut.close()

  return ByteArrayInputStream(baos.toByteArray())
}
