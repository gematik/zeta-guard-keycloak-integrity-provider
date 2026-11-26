<img align="right" width="250" height="47" src="docs/img/Gematik_Logo_Flag.png"/> <br/>

# Keycloak encryption and integrity check

A Keycloak plugin that provides encryption for sensitive data like security settings.
It also checks for data integrity.

# Content

## plugins/encryption-provider

Contains the business logic for encryption and integrity checks.

Encryption is handled by using an [attribute converter](https://vladmihalcea.com/jpa-attributeconverter/), which is implemented in
[SpreeEncryptionAttributeConverter](plugins/encryption-provider/src/main/kotlin/de/spree/keycloak/plugins/encryption/jpa/SpreeEncryptionAttributeConverter.kt).

Integrity of database rows is checked by hooking into the JPA lifecycle using a listener, which is implemented in 
[SpreeIntegrityValidationListener](plugins/encryption-provider/src/main/kotlin/de/spree/keycloak/plugins/integrity/SpreeIntegrityValidationListener.kt).

For checking integrity for a whole database table, there is
[SpreeIntegrityScanner](plugins/encryption-provider/src/main/kotlin/de/spree/keycloak/integrity/SpreeIntegrityScanner.kt).

## commons-server

Contains utility classes, like encryption operations and test helpers.

## docker-keycloak

Used to build a Keycloak image containing test data to be used in integration tests.

## runtime/integration-tests

Testcases for testing the encryption and integrity functionality integrated into Keycloak can be found here.

# Build Keycloak

To run Keycloak with the encryption and integrity check plugin installed, first execute

```shell
  mvn clean install
```

from the project root. After that, you can start Keycloak by executing

```shell
  docker compose -f runtime/compose.yaml up
```

Keycloak can then be reached at [http://localhost:18080](http://localhost:18080). Login with user "wasadmin" and password "geheim"

## Production build

If you want to build a production-ready version of Keycloak, use

```shell
  mvn clean install -Pprod,\!integration-tests
```

instead.

## License

(C) tech@Spree GmbH, 2026, licensed for gematik GmbH

Apache License, Version 2.0

See the [LICENSE](./LICENSE) for the specific language governing permissions and limitations under the License

## Additional Notes and Disclaimer from gematik GmbH

1. Copyright notice: Each published work result is accompanied by an explicit statement of the license conditions for use. These are regularly typical conditions in connection with open source or free software. Programs described/provided/linked here are free software, unless otherwise stated.
2. Permission notice: Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
    1. The copyright notice (Item 1) and the permission notice (Item 2) shall be included in all copies or substantial portions of the Software.
    2. The software is provided "as is" without warranty of any kind, either express or implied, including, but not limited to, the warranties of fitness for a particular purpose, merchantability, and/or non-infringement. The authors or copyright holders shall not be liable in any manner whatsoever for any damages or other claims arising from, out of or in connection with the software or the use or other dealings with the software, whether in an action of contract, tort, or otherwise.
    3. We take open source license compliance very seriously. We are always striving to achieve compliance at all times and to improve our processes. If you find any issues or have any suggestions or comments, or if you see any other ways in which we can improve, please reach out to: ospo@gematik.de
3. Please note: Parts of this code may have been generated using AI-supported technology. Please take this into account, especially when troubleshooting, for security analyses and possible adjustments.
