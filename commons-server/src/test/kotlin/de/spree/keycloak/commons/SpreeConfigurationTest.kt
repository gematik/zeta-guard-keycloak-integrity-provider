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
package de.spree.keycloak.commons

import de.spree.keycloak.commons.AbstractCDITest.Companion.spreeConfiguration
import de.spree.keycloak.commons.configuration.DmlAction
import de.spree.keycloak.commons.configuration.PrimaryKeyProperty
import de.spree.keycloak.commons.configuration.STRING
import de.spree.keycloak.commons.configuration.toJPAJoinClause
import de.spree.keycloak.commons.configuration.toJPAWhereNullClause
import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.ints.shouldBeGreaterThan
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe

@Suppress("CanConvertToMultiDollarString")
class SpreeConfigurationTest : StringSpec({
	"Check user entity configuration" {
		spreeConfiguration.entities.size shouldBeGreaterThan 10
		spreeConfiguration.entityNames.size shouldBe spreeConfiguration.entities.size

		val entityName = "org.keycloak.models.jpa.entities.UserEntity"
		val entity = spreeConfiguration.findEntity(entityName).shouldNotBeNull()
		entity.name shouldBe entityName
		entity.encryptedProperties.map { it.name } shouldBe listOf("email", "emailConstraint")
		entity.ignoredProperties.map { it.name } shouldBe listOf("federatedIdentities")

		val (className, properties) = spreeConfiguration.findPrimaryKeyInformation(entityName).shouldNotBeNull()
		className shouldBe STRING
		properties.shouldBe(listOf(PrimaryKeyProperty("id")))

		spreeConfiguration.findNamedQuery(entityName, "deleteUserByNameAndUser").shouldBeNull()
	}

	"Check user attribute configuration" {
		val entityName = "org.keycloak.models.jpa.entities.UserAttributeEntity"
		val entity = spreeConfiguration.findEntity(entityName).shouldNotBeNull()
		entity.isVolatile shouldBe true

		val query = spreeConfiguration.findNamedQuery(entityName, "deleteUserAttributesByNameAndUser").shouldNotBeNull()
		query.name shouldBe "deleteUserAttributesByNameAndUser"
		query.checkQuery shouldBe true
		query.queryType shouldBe DmlAction.DELETE

		val (className, properties) = spreeConfiguration.findPrimaryKeyInformation(entityName).shouldNotBeNull()
		className shouldBe STRING
		properties shouldBe listOf(PrimaryKeyProperty("id"))
	}

	"Check client scope configuration" {
		val entityName = "org.keycloak.models.jpa.entities.ClientScopeClientMappingEntity"
		val query = spreeConfiguration.findNamedQuery(entityName, "deleteClientScopeClientMappingByClient").shouldNotBeNull()
		query.name shouldBe "deleteClientScopeClientMappingByClient"
		query.checkQuery shouldBe true
		query.queryType shouldBe DmlAction.DELETE

		val (className, properties) = spreeConfiguration.findPrimaryKeyInformation(entityName).shouldNotBeNull()
		val keyClass = Class.forName(className)
		keyClass.name shouldBe "$entityName\$Key"

		val fields = keyClass.declaredFields.map { PrimaryKeyProperty(it.name) }.sortedBy { it.name }
		properties shouldBe fields
	}

	"Create JPA WHERE clause for ClientScopeClientMappingEntity" {
		val entityName = "org.keycloak.models.jpa.entities.ClientScopeClientMappingEntity"
		val primaryKey = spreeConfiguration.findPrimaryKeyInformation(entityName).shouldNotBeNull()

		primaryKey.toJPAWhereNullClause("e") shouldBe """(e.id.clientId IS NULL OR e.id.clientScopeId IS NULL)"""
	}

	"Create JPA JOIN clause for ClientScopeClientMappingEntity" {
		val entityName = "org.keycloak.models.jpa.entities.ClientScopeClientMappingEntity"
		val primaryKey = spreeConfiguration.findPrimaryKeyInformation(entityName).shouldNotBeNull()

		primaryKey.toJPAJoinClause("r", "e") shouldBe
			"""(r.compositeId1 = e.id.clientId AND r.compositeId2 = e.id.clientScopeId)"""
	}

	"Create JPA JOIN clause for UserRoleMappingEntity" {
		val entityName = "org.keycloak.models.jpa.entities.UserRoleMappingEntity"
		val primaryKey = spreeConfiguration.findPrimaryKeyInformation(entityName).shouldNotBeNull()

		primaryKey.toJPAJoinClause("r", "e") shouldBe
			"""(r.compositeId1 = e.id.roleId AND r.compositeId2 = e.id.user.id)"""
	}

	"Create JPA WHERE clause for UserRoleMappingEntity" {
		val entityName = "org.keycloak.models.jpa.entities.UserRoleMappingEntity"
		val primaryKey = spreeConfiguration.findPrimaryKeyInformation(entityName).shouldNotBeNull()

		primaryKey.toJPAWhereNullClause("e") shouldBe """(e.id.roleId IS NULL OR e.id.user.id IS NULL)"""
	}

	"Check ignored properties" {
		val entityName = "org.keycloak.models.jpa.entities.UserEntity"

		spreeConfiguration.isPropertyIgnored(entityName, "jens") shouldBe false
		spreeConfiguration.isPropertyIgnored(entityName, "username") shouldBe false
		spreeConfiguration.isPropertyIgnored(entityName, "federatedIdentities") shouldBe true
	}
})
