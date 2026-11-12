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

import arrow.core.Either
import arrow.core.left
import arrow.core.merge
import arrow.core.right
import com.fasterxml.jackson.databind.ObjectMapper
import de.spree.keycloak.commons.KeycloakError
import de.spree.keycloak.commons.KeycloakSuccessResponse
import de.spree.keycloak.commons.it.*
import de.spree.keycloak.commons.toJSON
import de.spree.keycloak.crypto.admin.CRYPTO_UPDATE_PROVIDER
import de.spree.keycloak.plugins.readiness.RS_PATH_READY
import org.apache.http.HttpHeaders.*
import org.apache.http.HttpResponse
import org.apache.http.HttpStatus.SC_NO_CONTENT
import org.apache.http.HttpStatus.SC_OK
import org.apache.http.HttpStatus.SC_SERVICE_UNAVAILABLE
import org.apache.http.client.methods.RequestBuilder
import org.apache.http.client.methods.RequestBuilder.delete
import org.apache.http.client.methods.RequestBuilder.get
import org.apache.http.client.methods.RequestBuilder.post
import org.apache.http.conn.ssl.NoopHostnameVerifier
import org.apache.http.conn.ssl.TrustAllStrategy
import org.apache.http.entity.ContentType.*
import org.apache.http.entity.StringEntity
import org.apache.http.impl.client.CloseableHttpClient
import org.apache.http.impl.client.HttpClients
import org.apache.http.ssl.SSLContextBuilder
import org.keycloak.OAuth2Constants.*
import org.keycloak.admin.client.resource.BearerAuthFilter.AUTH_HEADER_PREFIX
import org.keycloak.representations.AccessTokenResponse
import org.keycloak.representations.UserInfo
import org.keycloak.representations.idm.ClientScopeRepresentation
import org.keycloak.representations.idm.UserRepresentation
import java.io.BufferedReader

typealias KeycloakResponse<T> = Either<KeycloakError, KeycloakSuccessResponse<T>>

const val CRYPTO_UPDATE_PATH = "/admin/realms/{realm-name}/$CRYPTO_UPDATE_PROVIDER"

const val USER1 = "user1"
const val USER1_PASSWORD = "password"
const val TEST_CLIENT = "initial-client"

/**
 * A web client for interacting with Keycloak.
 *
 * @param hostname The hostname of the Keycloak server.
 * @param port The port of the Keycloak server.
 */
class KeycloakWebClient(hostname: String = KC_HOST, port: Int = KC_PORT) : KeycloakAdminClient(hostname, port, "http") {
	private var currentBody: String? = null

	/**
	 * Logs in a user and returns an access token.
	 *
	 * @param realm The realm to authenticate against.
	 * @param user The username.
	 * @param password The user's password.
	 * @param client The client ID.
	 * @param clientSecret The client secret.
	 * @param requestedClientScope The requested client scope.
	 * @return A [KeycloakResponse] containing an [AccessTokenResponse].
	 */
	fun login(
		realm: String = TEST_REALM,
		user: String = USER1,
		password: String = USER1_PASSWORD,
		client: String = TEST_CLIENT,
		clientSecret: String? = null,
		requestedClientScope: String? = null,
	): KeycloakResponse<AccessTokenResponse> {
		val request =
			post(uriBuilder().tokenUrl(realm))
				.addFormHeaders()
				.addParameter(CLIENT_ID, client)
				.addParameter(USERNAME, user)
				.addParameter(PASSWORD, password)
				.addParameter(GRANT_TYPE, PASSWORD)

		if (clientSecret != null) {
			request.addParameter(CLIENT_SECRET, clientSecret)
		}

		if (requestedClientScope != null) {
			request.addParameter(SCOPE, requestedClientScope)
		}

		return createHttpClient().use { it.execute(request.build()) }.mapJSONResponse<AccessTokenResponse>()
	}

	fun logout() {
		val request = get(uriBuilder().tokenUrl(TEST_REALM)).addHeader(CONTENT_TYPE, APPLICATION_FORM_URLENCODED.mimeType)

		createHttpClient().use { it.execute(request.build()) }
	}

	/**
	 * Gets user information.
	 *
	 * @param realm The realm.
	 * @param token The access token.
	 * @return A [KeycloakResponse] containing a [UserInfo].
	 */
	fun getUserInfo(realm: String, token: String): KeycloakResponse<UserInfo> {
		val request = get(uriBuilder().userinfoUrl(realm)).addHeader(AUTHORIZATION, "$AUTH_HEADER_PREFIX$token")

		return createHttpClient().use { it.execute(request.build()) }.mapJSONResponse<UserInfo>()
	}

	fun resetSystemState(): KeycloakResponse<String> {
		val request = post(uriBuilder().createUri("$RS_PATH_IT/$RS_METHOD_RESET_STATE", TEST_REALM))

		return createHttpClient().use { it.execute(request.build()) }.mapStringResponse()
	}

	fun ready(): Boolean {
		val request = get(uriBuilder().createUri(RS_PATH_READY, TEST_REALM))
		val response = createHttpClient().use { it.execute(request.build()) }

		return when (response.statusLine.statusCode) {
			SC_OK -> true
			SC_SERVICE_UNAVAILABLE -> false
			else -> throw IllegalStateException("Unexpected HTTP status code: ${response.statusLine.statusCode}")
		}
	}

	fun startScan(): KeycloakResponse<String> {
		val request = post(uriBuilder().createUri("$RS_PATH_IT/$RS_METHOD_START_SCAN", TEST_REALM))

		return createHttpClient().use { it.execute(request.build()) }.mapStringResponse()
	}

	fun startUpdate(): KeycloakResponse<String> {
		val request = post(uriBuilder().createUri("$RS_PATH_IT/$RS_METHOD_START_UPDATE", TEST_REALM))

		return createHttpClient().use { it.execute(request.build()) }.mapStringResponse()
	}

	fun runScanCycle(): KeycloakResponse<String> {
		val request = post(uriBuilder().createUri("$RS_PATH_IT/$RS_METHOD_RUN_SCAN_CYCLE", TEST_REALM))
		return createHttpClient().use { it.execute(request.build()) }.mapStringResponse()
	}

	fun enqueueCryptoUpdate(entityName: String): KeycloakResponse<String> =
		executeAsAdmin(post(uriBuilder().createUri("$CRYPTO_UPDATE_PATH/$entityName", TEST_REALM))).mapStringResponse(SC_NO_CONTENT)

	fun clearCryptoUpdates(): KeycloakResponse<String> =
		executeAsAdmin(delete(uriBuilder().createUri(CRYPTO_UPDATE_PATH, TEST_REALM))).mapStringResponse(SC_NO_CONTENT)

	fun remainingCryptoUpdates(): KeycloakResponse<String> =
		executeAsAdmin(get(uriBuilder().createUri(CRYPTO_UPDATE_PATH, TEST_REALM))).mapStringResponse()

	private fun executeAsAdmin(request: RequestBuilder): HttpResponse = withKeycloak(clientId = ADMIN_CLIENT) {
		request.addHeader(AUTHORIZATION, AUTH_HEADER_PREFIX + tokenManager().accessTokenString)
		createHttpClient().use { it.execute(request.build()) }
	}

	fun setUserAttributes(userId: String, vararg attributes: Pair<String, List<String>>): KeycloakResponse<UserRepresentation> {
		val request =
			post(uriBuilder().createUri("$RS_PATH_IT$RS_METHOD_ADD_ATTRIBUTES", TEST_REALM, "user-id" to userId))
				.apply { entity = StringEntity(attributes.toMap().toJSON()) }
				.addJsonHeaders()

		return createHttpClient().use { it.execute(request.build()) }.mapJSONResponse<UserRepresentation>()
	}

	fun addClientScopeToAllClients(clientScope: String): KeycloakResponse<ClientScopeRepresentation> {
		val request =
			post(uriBuilder().createUri("$RS_PATH_IT/$RS_METHOD_ADDCLIENTSCOPETOALLCLIENTS", TEST_REALM))
				.apply { entity = StringEntity(clientScope) }
				.addHeader(CONTENT_TYPE, TEXT_PLAIN.mimeType)
		return createHttpClient().use { it.execute(request.build()) }.mapJSONResponse<ClientScopeRepresentation>()
	}

	fun systemState(): KeycloakResponse<String> {
		val request = get(uriBuilder().createUri("$RS_PATH_IT/$RS_METHOD_GET_STATE", TEST_REALM))

		return createHttpClient().use { it.execute(request.build()) }.mapStringResponse()
	}

	/**
	 * Maps an [HttpResponse] to an [Either] of [KeycloakError] or [KeycloakSuccessResponse].
	 *
	 * @param T The type of the success response.
	 * @param expectedStatusCode The expected status code.
	 * @return An [Either] containing a [KeycloakError] or a [KeycloakSuccessResponse] with a [T].
	 */
	inline fun <reified T> HttpResponse.mapJSONResponse(expectedStatusCode: Int = SC_OK): KeycloakResponse<T> =
		if (this.statusLine.statusCode != expectedStatusCode) {
			mapError()
		} else {
			val clazz = T::class.java
			val body = `as`<T>()

			body
				.map { KeycloakSuccessResponse(it) }
				.mapLeft { KeycloakError(it.message(), "Could not create ${clazz.simpleName} from " + asString(), this.statusLine.statusCode) }
		}

	fun HttpResponse.mapError(): Either<KeycloakError, Nothing> =
		asError().mapLeft { KeycloakError(it.message(), asString(), this.statusLine.statusCode) }.merge().left()

	/**
	 * Maps an [HttpResponse] to an [Either] of [KeycloakError] or [KeycloakSuccessResponse].
	 *
	 * @param expectedStatusCode The expected status code.
	 * @return An [Either] containing a [KeycloakError] or a [KeycloakSuccessResponse] containing the response body string
	 */
	fun HttpResponse.mapStringResponse(expectedStatusCode: Int = SC_OK): KeycloakResponse<String> =
		if (this.statusLine.statusCode != expectedStatusCode) {
			mapError()
		} else {
			KeycloakSuccessResponse(asString()).right()
		}

	/**
	 * Deserializes a [HttpResponse] to an object of type [T].
	 *
	 * @param T The type to deserialize to.
	 * @return An [Either] containing a [Throwable] or an object of type [T].
	 */
	inline fun <reified T> HttpResponse.`as`(): Either<Throwable, T> = Either.catch { ObjectMapper().readValue(asString(), T::class.java) }

	/**
	 * Deserializes a [HttpResponse] to a [KeycloakError] in case of an error.
	 *
	 * @return An [Either] containing a [Throwable] or a [KeycloakError].
	 */
	fun HttpResponse.asError(): Either<Throwable, KeycloakError> = `as`<KeycloakError>().map { it.apply { statusCode = statusLine.statusCode } }

	/**
	 * Buffers [HttpResponse] body as a string.
	 *
	 * @return The response as a string.
	 */
	fun HttpResponse.asString(): String {
		if (currentBody == null) {
			currentBody = entity?.content?.bufferedReader()?.use(BufferedReader::readText) // No entity for 204 No Content
		}

		return currentBody ?: ""
	}

	/**
	 * Create HTTP client with SSL (PKIX) and hostname checks disabled if needed.
	 *
	 * See logback.xml to enable request/response logging
	 *
	 * Also reset cached body for every request
	 */
	fun createHttpClient(): CloseableHttpClient {
		val httpClientBuilder = HttpClients.custom()

		if (scheme == "https") {
			httpClientBuilder
				.setSSLContext(SSLContextBuilder().loadTrustMaterial(null, TrustAllStrategy.INSTANCE).build())
				.setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
		}

		currentBody = null

		return httpClientBuilder.build()
	}
}

private fun RequestBuilder.addJsonHeaders(): RequestBuilder =
	addHeader(CONTENT_TYPE, APPLICATION_JSON.mimeType).addHeader(ACCEPT, APPLICATION_JSON.mimeType)

private fun RequestBuilder.addFormHeaders(): RequestBuilder =
	addHeader(CONTENT_TYPE, APPLICATION_FORM_URLENCODED.mimeType).addHeader(ACCEPT, APPLICATION_JSON.mimeType)

fun Throwable.message() = message ?: "<unknown eror>"
