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
@file:Suppress("UNCHECKED_CAST")

package de.spree.keycloak.commons

import arrow.core.Either
import arrow.core.getOrElse
import arrow.core.raise.either
import arrow.core.raise.ensure
import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.*
import com.fasterxml.jackson.databind.module.SimpleModule
import com.fasterxml.jackson.databind.ser.BeanPropertyWriter
import com.fasterxml.jackson.databind.ser.BeanSerializerModifier
import com.fasterxml.jackson.databind.type.CollectionType
import de.spree.keycloak.commons.EntityConverter.convertToMap
import de.spree.keycloak.commons.configuration.SpreeEntityConfiguration
import jakarta.persistence.Entity
import jakarta.persistence.EntityManager
import jakarta.persistence.PersistenceException
import jakarta.persistence.Table
import org.hibernate.Hibernate
import org.keycloak.util.JsonSerialization
import java.util.SortedMap

/**
 * Internal service for mapping (Keycloak) JPA entities to a JSON representations.
 *
 * The output is digested and signed in later processing and used as a checksum for the entity in its current state.
 *
 * The converter customizes serialization to replace nested entities with their IDs and ensures deterministic ordering of collections and maps. In
 * order to obtain information about an entity, in particular its ID, we need the entity manager of the current transaction. The entity manager is
 * therefore passed to the serialization module.
 *
 * Some properties are excludedd as configured by the current [SpreeEntityConfiguration]. Currently this is used for properties/fields that cannot be
 * monitored for changes using the default Entity listener mechanism. See [org.keycloak.models.jpa.JpaUserProvider.addFederatedIdentity] for an
 * example of such a property using [EntityManager.getReference].
 */
@Suppress("DEPRECATION")
object EntityConverter {
	private val mapper: ObjectMapper by lazy {
		JsonSerialization.mapper
			.copy() // No pretty-printing or formatting
			.registerModule(ReplaceByIdModule())
			.configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true)
			.configure(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY, true)
			.setSerializationInclusion(JsonInclude.Include.NON_EMPTY)
	}
	private val configuration: SpreeEntityConfiguration by lazy { cdiService() }

	/**
	 * Converts a Keycloak entity to its JSON string representation. Ensures that the input is a valid Keycloak model class before serialization.
	 *
	 * @param entity The entity to convert.
	 * @return Either a Throwable or the JSON string.
	 */
	@Suppress("UNCHECKED_CAST")
		/** Converts a Keycloak entity to its JSON string representation. */
	fun EntityManager.convertToJSON(entity: Any): Either<Throwable, String> = either {
		ensure(entity.javaClass.isKeycloakModelClass()) { IllegalArgumentException("»$entity« is no entity class") }

		catchAll { mapper.writer().withAttribute(EntityManager::class.java, this@convertToJSON).writeValueAsString(entity) }
	}

	fun convertToMap(json: String): SortedMap<String, Any> {
		val map = mapper.readValue(json, object : TypeReference<Map<String, Any>>() {}) as Map<String, Any>

		return map.toSortedMap() // enforce stable order
	}

	/**
	 * Checks if the given object is a JPA entity and extracts its ID and table name.
	 *
	 * @param entity The object to check.
	 * @return Either a Throwable or EntityInfo containing ID, table name, and the entity.
	 */
	fun EntityManager.lookupEntityInfo(entity: Any): Either<Throwable, EntityInfo> = either {
		val clazz = entity.javaClass

		ensure(clazz.isEntity()) { IllegalArgumentException("»$clazz« is no entity class") }

		val id = extractIdFromEntity(entity).bind()
		val tableName = clazz.extractTableName().bind()

		EntityInfo(id, tableName, entity)
	}

	/**
	 * Extracts the ID of the entity using standard JPA utilities. If the ID is not just a string, convert it to JSON, too.
	 *
	 * @return Either a Throwable or the ID value.
	 */
	fun EntityManager.extractIdFromEntity(entity: Any): Either<Throwable, EntityId> = either {
		val util = entityManagerFactory.persistenceUnitUtil
		val id = util.getIdentifier(entity)

		if (id is String) {
			EntityId(id)
		} else {
			val idAsString = convertToJSON(id).bind()

			EntityId(idAsString, id.javaClass)
		}
	}

	/**
	 * Extracts the table name from the entity's @Table annotation.
	 *
	 * @return Either a Throwable or the table name.
	 */
	private fun Class<Any>.extractTableName() = either {
		ensure(isAnnotationPresent(Table::class.java)) { IllegalArgumentException("»$this« has not table name defined") }

		getAnnotation(Table::class.java).name
	}

	/** Jackson module that registers custom serializers for entities and collections. */
	private class ReplaceByIdModule : SimpleModule() {
		init {
			setSerializerModifier(ReplaceByIdBeanSerializerModifier())
		}
	}

	/** Modifier replacing the default serializer for (nested) entities with the [ReplaceByIdSerializer] and filters ignored properties. */
	private class ReplaceByIdBeanSerializerModifier : BeanSerializerModifier() {
		/** Filter properties, if configured in [SpreeEntityConfiguration] for the current entity class. */
		override fun changeProperties(
			config: SerializationConfig,
			beanDesc: BeanDescription,
			beanProperties: List<BeanPropertyWriter>,
		): List<BeanPropertyWriter> {
			val ignoredProperties =
				configuration.entities.firstOrNull { it.name == beanDesc.beanClass.name }?.ignoredProperties?.map { it.name }?.toSet() ?: emptySet()

			return beanProperties.filter { !ignoredProperties.contains(it.name) }
		}

		/** Use our serializer for JPA entities */
		override fun modifySerializer(config: SerializationConfig, beanDesc: BeanDescription, serializer: JsonSerializer<*>) =
			if (beanDesc.beanClass.isEntity()) {
				ReplaceByIdSerializer(serializer as JsonSerializer<Any>)
			} else {
				serializer
			}

		/** Use our serializer for JPA entity collections */
		override fun modifyCollectionSerializer(
			config: SerializationConfig,
			valueType: CollectionType,
			beanDesc: BeanDescription,
			serializer: JsonSerializer<*>,
		) = ReplaceByIdCollectionSerializer(serializer as JsonSerializer<Collection<*>>)
	}

	/**
	 * Custom JSON serializer that replaces nested entities with their IDs during serialization.
	 *
	 * For root objects, serialize fully; for nested entities, only the ID is written. This also applies for collections and maps.
	 *
	 * Additionally filter any properties that are configured to be ignored in [SpreeEntityConfiguration].
	 */
	private class ReplaceByIdSerializer(private val delegatingSerializer: JsonSerializer<Any>) : JsonSerializer<Any>() {
		override fun serialize(value: Any, gen: JsonGenerator, serializers: SerializerProvider) {
			val context = gen.outputContext
			val isRoot = context.parent == null
			val entityManager = serializers.getAttribute(EntityManager::class.java) as EntityManager
			val entityInfo = entityManager.lookupEntityInfo(value)

			Hibernate.initialize(value)

			when {
				isRoot -> {
					// Normal full serialization for the root object, ID in particaular
					delegatingSerializer.serialize(value, gen, serializers)
				}

				entityInfo is Either.Right -> {
					val id = entityInfo.value.entityId.id

					// Nested: serialize only the ID field as an object
					gen.writeObject(IdObject(id))
				}

				else -> { // Primitives, collections, maps, ...
					delegatingSerializer.serialize(value, gen, serializers)
				}
			}
		}
	}

	/** Custom serializer for collections that ensures deterministic ordering of the elements. */
	private class ReplaceByIdCollectionSerializer(private val delegatingSerializer: JsonSerializer<Collection<*>>) : JsonSerializer<Collection<*>>() {
		override fun serialize(value: Collection<*>, gen: JsonGenerator, serializers: SerializerProvider) {
			val entityManager = serializers.getAttribute(EntityManager::class.java) as EntityManager

			value.forEach { Hibernate.initialize(it) }

			// We have to ensure a deterministic order of collections, even if the entrie values are no [Comparable]s.
			val sortedValue = value.sortedWith(UniversalComparator(entityManager))

			delegatingSerializer.serialize(sortedValue, gen, serializers)
		}
	}

	/**
	 * Comparator that sorts generic elements:
	 * - if objects are [Comparable], use the [Comparable.compareTo] method
	 * - otherwise objects are assumed to be JPA entities and sorted by their ID
	 */
	private class UniversalComparator(private val entityManager: EntityManager) : Comparator<Any?> {
		override fun compare(a: Any?, b: Any?): Int =
			when {
				// 1. Handle Nulls (nulls first)
				a == null && b == null -> return 0
				a == null -> return -1
				b == null -> return 1
				// 2. Try Natural Order (Comparable)
				(a is Comparable<*> && b is Comparable<*>) -> (a as Comparable<Any>).compareTo(b)
				// 3. Assume JPA entities
				else -> {
					val entityInfoA = entityManager.lookupEntityInfo(a).getOrElse { throw IllegalStateException("Unknown type: $a") }
					val entityInfoB = entityManager.lookupEntityInfo(b).getOrElse { throw IllegalStateException("Unknown type: $b") }

					entityInfoA.entityId.compareTo(entityInfoB.entityId)
				}
			}
	}
}

data class IdObject(val id: String)

/** Checks if the class is annotated with @Entity. */
fun Class<*>.isEntity() = isAnnotationPresent(Entity::class.java)

/** Checks if the class is a Keycloak model class based on its package name. */
fun String.isKeycloakModelClass() = startsWith("org.keycloak.")

fun Class<*>.isKeycloakModelClass() = packageName.isKeycloakModelClass()

data class EntityId(val id: String, val idClass: Class<*> = String::class.java) : Comparable<EntityId> {
	override fun compareTo(other: EntityId) = id.compareTo(other.id)
}

/** Write Entity as plain String or complex Key object */
fun EntityId.toIdObject(): Any = if (idClass == String::class.java) id else id.toObject(idClass)

/** Extract composite keys as map */
fun EntityId.idAsMap(): Map<String, String> = if (idClass == String::class.java) {
	error("Not supported on plain string")
} else {
	convertToMap(id).convertIdValues()
}

fun Map<String, Any>.convertIdValues(): SortedMap<String, String> = mapValues { entry ->
	if (entry.value is String) entry.value as String else {
		// Nested map
		val nestedMap = entry.value as Map<String, String>

		// Hard-coded "id" for now is sufficient for all known queries
		nestedMap["id"]!!
	}
}.toSortedMap()

/** Data class holding information about an entity: its ID, table name, and the entity object itself. */
data class EntityInfo(val entityId: EntityId, val tableName: String, val entity: Any) {
	val entityName: String
		get() = entity.javaClass.name

	val id: String
		get() = entityId.id

	fun entityAsString() = entityAsString(id, entityName)
}

fun entityAsString(id: String, entityName: String) = "»${entityName}#$id«"

/** Return null-safe message */
fun Throwable.message(): String = message ?: javaClass.name

/** Regard persistence exceptions as recoverable */
fun Throwable.isIntegrityException() = this !is PersistenceException
