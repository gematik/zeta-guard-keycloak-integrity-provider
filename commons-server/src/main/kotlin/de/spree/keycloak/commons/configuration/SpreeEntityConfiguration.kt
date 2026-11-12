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
package de.spree.keycloak.commons.configuration

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonProperty
import de.spree.keycloak.commons.ENV_CONFIGURATION_PATH
import de.spree.keycloak.commons.ENV_REALM_NAME
import de.spree.keycloak.commons.getEnvironment
import de.spree.keycloak.commons.toYamlObject
import io.quarkus.runtime.Startup
import jakarta.enterprise.context.ApplicationScoped
import jakarta.enterprise.inject.Produces
import java.io.FileInputStream
import kotlin.reflect.KProperty1
import kotlin.reflect.full.memberProperties
import kotlin.reflect.jvm.javaType

/** The name of the database table used to store row-level checksums. */
const val TABLE_ROW_CHECKSUM = "SPREE_ROW_CHECKSUM"
const val TABLE_CONFIGURATION = "SPREE_CONFIGURATION"
const val TABLE_TABLE_CHECKSUM = "SPREE_TABLE_CHECKSUM"
const val TABLE_CRYPTO_UPDATE = "SPREE_TABLE_CRYPTO_UPDATE"

const val CONFIG_SETTINGS_ENABLE_COLUMN_ENCRYPTION = "spree.config.jpa.enable.column-encryption"
const val CONFIG_REALM_ENABLE_PROVIDER = "spree.config.realm.enabled"

val LOG_STATE_OPERATIONAL = "System state is now »${SystemState.OPERATIONAL.name}« ..."

const val TYPE_PARAM_ENTITY_NAME = "spree.config.jpa.type.entity-name"
const val TYPE_PARAM_PROPERTY_NAME = "spree.config.jpa.type.property-name"

val realmName: String by lazy { getEnvironment(ENV_REALM_NAME) }

/**
 * See spree-configuration.yml for the structure of this configuration class.
 *
 * The file contains all relevant classes and, e.g., which columns to encrypt
 */
data class SpreeEntityConfiguration(@field:JsonProperty("entities") private val entityList: List<Entity>) {
	private val entityMap: Map<String, EntityConfiguration> by lazy { entityList.map { it.entity }.associateBy { it.name } }

	val entityNames: Set<String>
		get() = entityMap.keys

	val entities: Collection<EntityConfiguration>
		get() = entityMap.values

	fun findEntity(entityName: String): EntityConfiguration? = entityMap[entityName]

	fun tableChecksumEnabled(entityName: String): Boolean = findEntity(entityName)?.tableChecksumEnabled ?: false

	fun rowChecksumEnabled(entityName: String): Boolean = findEntity(entityName)?.rowChecksumEnabled ?: false

	fun findNamedQuery(entityName: String, name: String): QueryConfiguration? = findEntity(entityName)?.findNamedQuery(name)

	fun findPrimaryKeyInformation(entityName: String) = findEntity(entityName)?.primaryKey

	fun isPropertyIgnored(entityName: String, propertyName: String) =
		findEntity(entityName)?.ignoredProperties?.firstOrNull { it.name == propertyName } != null

	fun isVolatileEntity(entityName: String): Boolean = findEntity(entityName)?.isVolatile ?: false
}

private val SPREE_CONFIGURATION_PATH = getEnvironment(ENV_CONFIGURATION_PATH, "/opt/keycloak/conf/spree-configuration.yml")

@ApplicationScoped
@Startup
class SpreeConfigurationProducer {
	@Produces
	@ApplicationScoped // The produced object is a singleton
	fun getConfiguration(): SpreeEntityConfiguration = INSTANCE

	companion object {
		private val INSTANCE: SpreeEntityConfiguration by lazy {
			val stream = FileInputStream(SPREE_CONFIGURATION_PATH)

			stream.toYamlObject<SpreeEntityConfiguration>()
		}
	}
}

data class Entity(val entity: EntityConfiguration)

data class NamedQuery(val query: QueryConfiguration)

enum class DmlAction {
	INSERT,
	UPDATE,
	DELETE,
}

const val STRING = "java.lang.String"

data class EntityConfiguration(
	@field:JsonProperty("name") //
	val name: String,
	@field:JsonProperty("encrypted_properties") //
	val encryptedProperties: List<EncryptedPropertyConfiguration> = emptyList(),

	// Properties not to be included in the checksum
	@field:JsonProperty("ignored_properties") //
	val ignoredProperties: List<IgnoredPropertyConfiguration> = emptyList(),
	@field:JsonProperty("primary_key") //
	val primaryKey: PrimaryKey = PrimaryKey(STRING, listOf(PrimaryKeyProperty("id"))),
	@field:JsonProperty("named_queries") //
	private val namedQueries: List<NamedQuery> = emptyList(),

	@field:JsonProperty("is_volatile") //
	val isVolatile: Boolean = false,

	@field:JsonProperty("row_checksum_enabled") //
	val rowChecksumEnabled: Boolean = true,
	@field:JsonProperty("table_checksum_enabled") //
	val tableChecksumEnabled: Boolean = false
) {
	private val namedQueryMap: Map<String, QueryConfiguration> by lazy { namedQueries.map { it.query }.associateBy { it.name } }

	fun findNamedQuery(name: String): QueryConfiguration? = namedQueryMap[name]
}

data class PrimaryKey(
	@field:JsonProperty("class_name") //
	val className: String,
	@field:JsonProperty("properties") //
	val properties: List<PrimaryKeyProperty> = emptyList(),
) {
	fun properties() = properties.sortedBy { it.name } // Order must be stable
}

val PrimaryKey.clazz: Class<*>
	get() = Class.forName(className)

data class QueryConfiguration(
	@field:JsonProperty("name") //
	val name: String,
	@field:JsonProperty("query_type") //
	val queryType: DmlAction,
	@field:JsonProperty("check_query") //
	val checkQuery: Boolean,
)

@JsonIgnoreProperties(ignoreUnknown = true)
data class EncryptedPropertyConfiguration(val name: String)

@JsonIgnoreProperties(ignoreUnknown = true)
data class IgnoredPropertyConfiguration(val name: String)

@JsonIgnoreProperties(ignoreUnknown = true)
data class PrimaryKeyProperty(val name: String)

fun PrimaryKey.toJPAWhereNullClause(entityTable: String): String {
	val getters = getters()

	return getters.joinToString(" OR ", prefix = "(", postfix = ")") {
		val propertyPath = if (it.returnType.javaType.typeName == STRING) it.name else it.name + ".id"

		"""$entityTable.id.$propertyPath IS NULL"""
	}
}

fun PrimaryKey.toJPAJoinClause(rowChecksumTable: String, entityTable: String): String {
	var i = 1

	return getters().joinToString(" AND ", prefix = "(", postfix = ")") {
		val compositeId = "compositeId${i++}"
		val propertyPath = if (it.returnType.javaType.typeName == STRING) it.name else it.name + ".id"

		"""$rowChecksumTable.$compositeId = $entityTable.id.$propertyPath"""
	}
}

fun PrimaryKey.getters(): List<KProperty1<*, *>> {
	val keyClass = Class.forName(className).kotlin

	return properties().map { pk -> keyClass.memberProperties.first { it.name == pk.name } }
}