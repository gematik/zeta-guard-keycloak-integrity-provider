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

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.SecureRandom
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import org.keycloak.jose.jwk.ECPublicJWK

/** The default elliptic curve name for EC key generation */
const val EC_CURVE_P256 = "SECP256R1"

val CURVE: ECNamedCurveParameterSpec = ECNamedCurveTable.getParameterSpec(EC_CURVE_P256)
val DOMAIN = ECDomainParameters(CURVE.curve, CURVE.g, CURVE.n, CURVE.h)
val EC_SPEC = ECNamedCurveParameterSpec(EC_CURVE_P256, DOMAIN.curve, DOMAIN.g, DOMAIN.n, DOMAIN.h)

/** Generates an elliptic curve (EC) key pair. */
fun generateKeyPair(): KeyPair {
  try {
    val randomGen = SecureRandom()
    val keyGen = KeyPairGenerator.getInstance(ECPublicJWK.EC, PROVIDER_NAME).apply { initialize(CURVE, randomGen) }

    return keyGen.generateKeyPair()
  } catch (e: Exception) {
    throw RuntimeException(e)
  }
}
