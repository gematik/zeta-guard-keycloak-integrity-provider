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

import de.spree.keycloak.commons.crypto.muhash.MuHash3072
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

@Suppress("LocalVariableName")
class MuHash3072Test : FunSpec() {
	var objectUnderTest = MuHash3072()

	val itemA: ByteArray = "Unless required by applicable law or agreed to in writing, software".toByteArray()
	val itemB: ByteArray = "distributed under the License is distributed on an \"AS IS\" BASIS,".toByteArray()
	val itemC: ByteArray = "WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.".toByteArray()

	init {
		beforeTest {
			objectUnderTest = MuHash3072()
		}

		test("Add and remove values") {
			objectUnderTest.insert(itemA)
			objectUnderTest.insert(itemB)
			objectUnderTest.insert(itemC)

			val hashAll = objectUnderTest.current()

			objectUnderTest.remove(itemB)

			val hashA_C = objectUnderTest.current()

			MuHash3072().insert(itemA).insert(itemC).current() shouldBe hashA_C
			MuHash3072().insert(itemC).insert(itemA).insert(itemB).current() shouldBe hashAll
		}

		test("Add is order independent") {
			val hashA_B = objectUnderTest.insert(itemA).insert(itemB).current()

			MuHash3072().insert(itemB).insert(itemA).current() shouldBe hashA_B
		}

		test("Remove is order independent") {
			val initial = objectUnderTest.insert(itemA).insert(itemB).insert(itemC).copy()
			val hashA = objectUnderTest.remove(itemB).remove(itemC).current()

			initial.remove(itemC).remove(itemB).current() shouldBe hashA
		}

		test("Add and remove multiples of same value") {
			objectUnderTest.insert(itemA).insert(itemB)
			val hashA_B = objectUnderTest.current()

			objectUnderTest.insert(itemB)
			objectUnderTest.current() shouldNotBe hashA_B

			objectUnderTest.remove(itemB)
			objectUnderTest.current() shouldBe hashA_B

			objectUnderTest.remove(itemB)
			objectUnderTest.current() shouldNotBe hashA_B
			MuHash3072().insert(itemA).current() shouldBe objectUnderTest.current()
		}

		test("current is consistent") {
			objectUnderTest.insert(itemA).insert(itemB)
			val hash1 = objectUnderTest.current()
			val hash2 = objectUnderTest.current()
			hash1 shouldBe hash2
		}

		test("can detect empty state after removal") {
			objectUnderTest.isEmpty() shouldBe true
			objectUnderTest.insert(itemA)
			objectUnderTest.isEmpty() shouldBe false

			objectUnderTest.remove(itemA)
			objectUnderTest.isEmpty() shouldBe true
			objectUnderTest.current() shouldBe MuHash3072().current()
		}

		test("Serialization") {
			objectUnderTest.insert(itemA)
			objectUnderTest.insert(itemB)
			val hashA_B = objectUnderTest.current()

			MuHash3072(hashA_B).current() shouldBe hashA_B

			MuHash3072(hashA_B).insert(itemC).current() shouldBe objectUnderTest.insert(itemC).current()
		}
	}
}
