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

import de.spree.keycloak.commons.EMAIL
import de.spree.keycloak.commons.it.TEST_REALM
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.core.spec.Order
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import jakarta.security.enterprise.authentication.mechanism.http.openid.OpenIdConstant.OPENID_SCOPE

@Order(1)
class UserInfoIT : FunSpec() {
  init {
    test("Get user info") {
      val keycloakWebClient = KeycloakWebClient()
      val accessTokenResponse = keycloakWebClient.login(requestedClientScope = OPENID_SCOPE).shouldBeRight().reponseObject
      val userInfo = keycloakWebClient.getUserInfo(TEST_REALM, accessTokenResponse.token).shouldBeRight().reponseObject

      userInfo.email shouldBe EMAIL
      userInfo.preferredUsername shouldBe "user1"

      keycloakWebClient.logout()
    }
  }
}
