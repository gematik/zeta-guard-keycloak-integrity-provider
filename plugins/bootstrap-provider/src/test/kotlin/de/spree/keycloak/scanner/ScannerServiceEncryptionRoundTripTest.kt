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
@file:Suppress("SqlSourceToSinkFlow")

package de.spree.keycloak.scanner

import arrow.core.right
import de.spree.keycloak.commons.AbstractDatabaseTest
import de.spree.keycloak.commons.EMAIL
import de.spree.keycloak.commons.SimpleSuccess
import de.spree.keycloak.commons.TestData.user
import de.spree.keycloak.commons.configuration.SystemState
import de.spree.keycloak.commons.setValue
import de.spree.keycloak.integrity.RowChecksumService
import de.spree.keycloak.integrity.TableChecksumService
import de.spree.keycloak.plugins.encryption.jpa.SpreeEncryptionAttributeConverter
import io.kotest.assertions.arrow.core.shouldBeLeft
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import io.mockk.every
import io.mockk.mockk
import jakarta.persistence.ConnectionFunction
import java.sql.Connection
import org.keycloak.models.jpa.entities.UserEntity

private const val ENTITY_NAME = "org.keycloak.models.jpa.entities.UserEntity"

/**
 * Covers encrypting columns through the real [ScannerService]/[de.spree.keycloak.integrity.EntityDao] chain, as used by the initial database
 * conversion and by crypto updates. The written data has to survive a single decryption on read — encrypting it twice would make Keycloak read back
 * ciphertext.
 */
class ScannerServiceEncryptionRoundTripTest : AbstractDatabaseTest() {
  private val tableChecksumService = mockk<TableChecksumService>()
  private val rowChecksumService = mockk<RowChecksumService>()

  private val objectUnderTest =
      ScannerService().apply {
        setValue("tableChecksumService", tableChecksumService, ScannerService::class.java)
        setValue("rowChecksumService", rowChecksumService, ScannerService::class.java)
        setValue("cryptoService", cryptoService, ScannerService::class.java)
      }

  init {
    beforeTest {
      every { rowChecksumService.updateEntityInfoChecksum(any(), any()) } returns true.right()
      every { tableChecksumService.updateTableChecksum(any(), any()) } returns SimpleSuccess.right()

      // building the entity manager factory sets the system state, so switch to OPERATIONAL only afterwards
      entityManager.isOpen
      systemStateService.resetState(SystemState.OPERATIONAL)
    }

    test("Re-encrypting a column keeps it readable") {
      entityManager.persist(user)
      newTransaction()

      updateEntity()

      loadEmailFromDB() shouldNotBe EMAIL
      loadUser().email shouldBe EMAIL
    }

    test("Already encrypted data is not encrypted again") {
      entityManager.persist(user)
      newTransaction()

      // as during the initial conversion: the database holds ciphertext while the converter passes values through
      val ciphertext = loadEmailFromDB().shouldNotBeNull()

      SpreeEncryptionAttributeConverter.withoutConversion { updateEntity() }

      loadEmailFromDB() shouldBe ciphertext
      loadUser().email shouldBe EMAIL
    }

    test("Verification accepts a converted table") {
      entityManager.persist(user)
      newTransaction()

      SpreeEncryptionAttributeConverter.withoutConversion {
        updateEntity()

        objectUnderTest.verifyEncryptedColumns(configuration(), entityManager).shouldBeRight()
      }
    }

    test("Verification rejects data that was written while the table was being converted") {
      SpreeEncryptionAttributeConverter.withoutConversion {
        updateEntity()

        // the converter passes values through during the conversion, so this row stays in plain text — and the conversion is already past this table
        entityManager.persist(user)
        newTransaction()

        objectUnderTest
            .verifyEncryptedColumns(configuration(), entityManager)
            .shouldBeLeft()
            .message shouldContain "are not encrypted"
      }

      loadEmailFromDB() shouldBe EMAIL

      // the row stays in plain text on purpose, so drop it here: reading it back would fail in the converter during cleanup
      entityManager.createQuery("DELETE FROM UserEntity").executeUpdate()
      newTransaction()
    }
  }

  private fun configuration() = spreeConfiguration.findEntity(ENTITY_NAME).shouldNotBeNull()

  private fun updateEntity() {
    objectUnderTest.updateEntity(configuration(), entityManager).shouldBeRight()

    newTransaction()
  }

  private fun loadUser(): UserEntity = entityManager.find(UserEntity::class.java, user.id)

  private fun loadEmailFromDB(): String? =
      entityManager.callWithConnection(
          ConnectionFunction<Connection, String> {
            val rs = it.createStatement().executeQuery("SELECT email FROM user_entity WHERE id = '${user.id}'")
            require(rs.next()) { "User not found" }
            rs.getString(1)
          }
      )
}
