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

## plugins/bootstrapping-provider

Handles bootstrapping process of SIP and periodic checks

For checking integrity for a whole database table, there is
[SpreeIntegrityScanner](plugins/bootstrap-provider/src/main/kotlin/de/spree/keycloak/scanner/SpreeIntegrityScanner.kt).

## plugins/readiness-provider

Provide REST endpoint for health checks

## plugins/crypto-update-provider

Provide REST endpoint and logic fr re-encyrption of the database and checksum updates with a new keychain

## commons-server

Contains utility classes, like encryption operations and test helpers.

## docker-keycloak

Used to build a Keycloak image containing test data to be used in integration tests.

## runtime/integration-tests

Testcases for testing the encryption and integrity functionality integrated into Keycloak can be found here.

# Build

Some dependencies are hosted in its own registry rather than Maven Central, so you need to add
that repository to your local Maven configuration (e.g. `~/.m2/settings.xml`) before building, otherwise
`mvn clean install` will fail to resolve them. See [ci_settings.xml](ci_settings.xml) for the repository
and mirror configuration used in CI as a reference.

To run Keycloak with the encryption and integrity check plugin installed, first execute

```shell
  mvn clean install
```

from the project root. After that, you can start Keycloak by executing

```shell
  docker compose -f runtime/compose.yaml up
```

> **Note:** This requires a local registry login and environment variables for the `hsm-sim` service, see [Local setup for hsm-sim](#local-setup-for-hsm-sim-integration-tests) below.

Keycloak may then be reached at [http://localhost:18080](http://localhost:18080). Login with user "wasadmin" and password "geheim"

## Local setup for hsm-sim (integration tests)

`runtime/compose.yaml` and `runtime/integration-tests/docker-compose-it.yml` reference an `hsm-sim` service whose image is hosted in a different registry, not on Docker Hub. To pull it locally you need to:

1. Log in to the registry that hosts the image, e.g.:
   ```shell
   docker login YOUR_DOCKER_REGISTRY
   ```
   with credentials that have read access to the `hsm_sim` image.

2. Set the following environment variables in your shell before running Docker Compose or the integration tests. `.env` files are no longer used:
   ```shell
   # Complete Image repository name
   # e.g. registry.some-domain.de/zeta/hsm_sim
   export HSM_SIM_IMAGE=COMPLETE_IMAGE_NAME
   export HSM_SIM_TAG=main
   ```
   The registry, image path, and tag above are just an example — the actual values depend on where `hsm_sim` is hosted in your environment.

   > **Tip:** [direnv](https://direnv.net/) can be used to set these variables automatically when you enter the project
   > directory. The project ships an `.envrc` that sources an optional, gitignored `.envrc.local` — put your personal
   > `export` statements there and run `direnv allow` once.

Without this, `docker compose up` and the local integration tests will fail with a `pull access denied` error, since the default image name in the compose files is not resolvable against Docker Hub.


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
