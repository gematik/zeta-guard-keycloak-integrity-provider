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
import de.spree.keycloak.commons.configuration.*
import de.spree.keycloak.commons.currentKeycloakSession
import de.spree.keycloak.commons.debug.SpreeLog
import de.spree.keycloak.commons.entityManager
import de.spree.keycloak.commons.logger
import de.spree.keycloak.commons.crypto.CryptoService
import de.spree.keycloak.integrity.ConfigurationService
import de.spree.keycloak.integrity.SpreeDatabaseConversionState
import de.spree.keycloak.plugins.integrity.Action
import de.spree.keycloak.plugins.integrity.EntityAction
import jakarta.persistence.AttributeConverter
import org.hibernate.type.descriptor.WrapperOptions
import org.hibernate.type.spi.TypeConfiguration
import org.hibernate.type.spi.TypeConfigurationAware
import org.hibernate.usertype.ParameterizedType
import org.hibernate.usertype.UserType
import java.sql.PreparedStatement
import java.sql.ResultSet
import java.sql.Types
import java.util.*
import java.util.logging.Logger
import kotlin.math.min

/**
 * Suspends encryption/decryption on the current thread, see [SpreeEncryptionAttributeConverter.withoutConversion].
 *
 * Kept outside the class as the converter is instantiated per mapped property.
 */
private val conversionSuspended = ThreadLocal.withInitial { false }

/**
 * JPA Attribute Converter and Hibernate UserType for encrypting/decrypting String attributes.
 *
 * This converter uses a CryptoService to encrypt data before storing in the database and decrypt it when loading. It generates a nonce for the
 * ciphertext for each encryption operation.
 *
 * CDI injection is not available here, so the crypto service is lazily resolved.
 */
@Suppress("unused")
class SpreeEncryptionAttributeConverter : UserType<String>, AttributeConverter<String, String>, TypeConfigurationAware, ParameterizedType {
	private var parameters: Map<String, String> = mapOf()
	private lateinit var typeConfiguration: TypeConfiguration

	private val cryptoService: CryptoService by lazy { cdiService() }
	private val systemStateService: SystemStateService by lazy { cdiService() }
	private val configurationService: ConfigurationService by lazy { cdiService() }
	private val spreeLogger: Logger by lazy { cdiService(SpreeLog()) }

	/**
	 * Converts an entity attribute to its database representation
	 *
	 * @param attribute The plain string attribute.
	 * @return The base64-encoded encrypted string, or null if input is null.
	 */
	override fun convertToDatabaseColumn(attribute: String?): String? {
		val encryptionEnabled = handleEncryption()
		val entityInfo = entityInfo()
		val action = if (encryptionEnabled) "Encrypting" else "Not encrypting"
		val msg = "$action »$entityInfo«"

		logger.debug("$msg data")
		spreeLogger.info("$msg → »${attribute.abbreviate()}«")

		return if (encryptionEnabled) {
			if (attribute != null) {
				cryptoService.encrypt(attribute).getOrElse {
					systemStateService.setSystemState(SystemState.ERROR_ENCRYPTION, it)

					throw RuntimeException("💣 $IT_FAILED Encryption failed", it)
				}
			} else {
				null
			}
		} else {
			attribute
		}
	}

	/**
	 * Converts a database value to its entity attribute
	 *
	 * @param dbData The base64-encoded encrypted string.
	 * @return The decrypted plain string, or null if input is null.
	 */
	override fun convertToEntityAttribute(dbData: String?): String? {
		val encryptionEnabled = handleEncryption()
		val state = if (encryptionEnabled) "encrypted" else "plain"
		val entityInfo = entityInfo()
		val msg = "$state »$entityInfo«"

		logger.debug("Reading $msg data")
		spreeLogger.info("Reading $msg → »${dbData.abbreviate()}«")

		return if (encryptionEnabled) {
			if (dbData != null) {
				cryptoService.decrypt(dbData).getOrElse {
					systemStateService.setSystemState(SystemState.ERROR_DECRYPTION, it)

					throw RuntimeException("$IT_FAILED Decryption failed", it)
				}
			} else {
				null
			}
		} else {
			dbData
		}
	}

	private fun String?.abbreviate(): String? = this?.substring(0, min(this.length, 5))

	private fun handleEncryption(): Boolean {
		if (conversionSuspended.get()) {
			logger.debug("⚠️ Conversion is suspended, passing value through")

			return false
		}

		val action = EntityAction(Action.INITIALIZE, entityName(), currentKeycloakSession().entityManager)

		return systemStateService.spreeIntegrityProviderRunning() || configurationService.getConversionState(action) == SpreeDatabaseConversionState.DONE
	}

	companion object {
		/**
		 * Runs [block] with this converter passing values through unchanged on the current thread.
		 *
		 * Needed wherever ciphertext is written to (or read from) the database verbatim: Hibernate applies this converter to bulk update parameters
		 * as well, so data that has already been encrypted by hand — as done by [de.spree.keycloak.integrity.ScannerService] during database
		 * conversion and crypto updates — would be encrypted a second time and could never be decrypted again by a single read.
		 *
		 * Keep the block as small as possible and make sure there is nothing pending in the persistence context when entering it, as any flush
		 * happening inside would write plaintext.
		 */
		fun <T> withoutConversion(block: () -> T): T {
			val suspendedBefore = conversionSuspended.get()
			conversionSuspended.set(true)

			try {
				return block()
			} finally {
				// Only the outermost call clears the flag: a nested block must not end the enclosing suspension early.
				if (!suspendedBefore) conversionSuspended.remove()
			}
		}
	}

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

	override fun setParameterValues(parameters: Properties) {
		this.parameters = parameters.entries.associate { it.key.toString() to it.value.toString() }
	}

	private fun entityInfo() = (entityName()) + "/" + (parameters[TYPE_PARAM_PROPERTY_NAME] ?: "?")

	private fun entityName(): String = parameters[TYPE_PARAM_ENTITY_NAME] ?: "?"
}
