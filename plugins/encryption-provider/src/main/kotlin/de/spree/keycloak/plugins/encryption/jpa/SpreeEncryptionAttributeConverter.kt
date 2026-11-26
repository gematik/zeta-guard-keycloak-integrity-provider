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
package de.spree.keycloak.plugins.encryption.jpa

import arrow.core.getOrElse
import de.spree.keycloak.commons.cdiService
import de.spree.keycloak.commons.configuration.IT_FAILED
import de.spree.keycloak.commons.configuration.SystemStatus
import de.spree.keycloak.commons.configuration.SystemStatusService
import de.spree.keycloak.crypto.CryptoService
import de.spree.keycloak.crypto.keychain.CurrentKeychain
import de.spree.keycloak.integrity.ConfigurationService
import de.spree.keycloak.integrity.SpreeDatabaseConversionState
import jakarta.persistence.AttributeConverter
import java.sql.PreparedStatement
import java.sql.ResultSet
import java.sql.Types
import org.hibernate.type.descriptor.WrapperOptions
import org.hibernate.type.spi.TypeConfiguration
import org.hibernate.type.spi.TypeConfigurationAware
import org.hibernate.usertype.UserType

/**
 * JPA Attribute Converter and Hibernate UserType for encrypting/decrypting String attributes.
 *
 * This converter uses a CryptoService to encrypt data before storing in the database and decrypt it when loading. It generates a nonce for the
 * ciphertext for each encryption operation.
 *
 * CDI injection is not available here, so the crypto service is lazily resolved.
 */
@Suppress("unused")
class SpreeEncryptionAttributeConverter : UserType<String>, AttributeConverter<String, String>, TypeConfigurationAware {
  private lateinit var typeConfiguration: TypeConfiguration

  private val cryptoService: CryptoService by lazy { cdiService() }
  private val currentKeychain: CurrentKeychain by lazy { cdiService() }
  private val systemStatusService: SystemStatusService by lazy { cdiService() }
  private val configurationService: ConfigurationService by lazy { cdiService() }

  /**
   * Converts an entity attribute to its database representation
   *
   * @param attribute The plain string attribute.
   * @return The base64-encoded encrypted string, or null if input is null.
   */
  override fun convertToDatabaseColumn(attribute: String?): String? =
      if (encryptionEnabled()) {
        if (attribute != null) {
          cryptoService.encrypt(attribute).getOrElse {
            systemStatusService.setSystemStatus(SystemStatus.ERROR_ENCRYPTION, it)

            throw RuntimeException("💣 $IT_FAILED Encryption failed", it)
          }
        } else {
          null
        }
      } else {
        attribute
      }

  /**
   * Converts a database value to its entity attribute
   *
   * @param dbData The base64-encoded encrypted string.
   * @return The decrypted plain string, or null if input is null.
   */
  override fun convertToEntityAttribute(dbData: String?): String? =
      if (encryptionEnabled()) {
        if (dbData != null) {
          cryptoService.decrypt(dbData).getOrElse {
            systemStatusService.setSystemStatus(SystemStatus.ERROR_DECRYPTION, it)

            throw RuntimeException("$IT_FAILED Decryption failed", it)
          }
        } else {
          null
        }
      } else {
        dbData
      }

  private fun encryptionEnabled(): Boolean =
      systemStatusService.spreeIntegrityProviderRunning() || configurationService.getConversionState() == SpreeDatabaseConversionState.DONE

  /**
   * Returns the SQL type for this UserType.
   *
   * @return The VARCHAR SQL type.
   */
  override fun getSqlType(): Int = Types.VARCHAR

  /**
   * Returns the class of the returned value.
   *
   * @return The String class.
   */
  override fun returnedClass(): Class<String> = String::class.java

  /**
   * Creates a deep copy of the value.
   *
   * @param value The value to copy.
   * @return The copied value.
   */
  override fun deepCopy(value: String?): String? = value

  /** @return False, as strings are immutable. */
  override fun isMutable() = false

  /**
   * Retrieves a value from a ResultSet, decrypting it.
   *
   * @param rs The ResultSet.
   * @param position The column position.
   * @param options Wrapper options.
   * @return The decrypted string value.
   */
  override fun nullSafeGet(rs: ResultSet, position: Int, options: WrapperOptions): String? {
    return convertToEntityAttribute(super.nullSafeGet(rs, position, options))
  }

  /**
   * Sets a value in a PreparedStatement, encrypting it.
   *
   * @param st The PreparedStatement.
   * @param value The value to set.
   * @param position The parameter position.
   * @param options Wrapper options.
   */
  override fun nullSafeSet(st: PreparedStatement, value: String?, position: Int, options: WrapperOptions) {
    super.nullSafeSet(st, convertToDatabaseColumn(value), position, options)
  }

  /**
   * Returning »null« means: Use this very UserType as converter, i.e. [nullSafeSet] methods, not the JPA attribute converter methods. Returning
   * »this« means: Use the JPA attribute converter methods.
   */
  override fun getValueConverter() = this

  /**
   * Returns the type configuration.
   *
   * @return The TypeConfiguration instance.
   */
  override fun getTypeConfiguration() = typeConfiguration

  /**
   * Sets the type configuration.
   *
   * @param typeConfiguration The TypeConfiguration to set.
   */
  override fun setTypeConfiguration(typeConfiguration: TypeConfiguration) {
    this.typeConfiguration = typeConfiguration
  }
}
