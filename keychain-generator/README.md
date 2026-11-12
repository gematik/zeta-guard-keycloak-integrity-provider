# Keycloak encryption and integrity check - Keychain-Generator

A simple generator that creates key material in the expected format for the Keycloak encryption and integrity plugin.

# Build

To build the keychain generator, simply run:

```shell
  mvn clean install
```

from the module root. After that, you can generate a keychain via the command

```shell
  java -jar target/keychain-generator-x.z.y-SNAPSHOT-fat.jar
```

Replace `x.y.z` with the current version number.

This requires an HSM proxy to be running and available at `127.0.0.1:50051`.
For example, go to the `runtime` directory of this project and execute:

```shell
  docker compose up -d hsm-sim
```

The generator supports several environment variables to adjust its operation.
See `.envrc` in this directory for an example. 

**Note:** If there is already a keychain file at the target location, the generator will **not** write over it!
Make sure to move or rename the existing file first, or set a different target location.



## License

(C) tech@Spree GmbH, 2026, licensed for gematik GmbH

Apache License, Version 2.0

See the [LICENSE](../LICENSE) for the specific language governing permissions and limitations under the License

## Additional Notes and Disclaimer from gematik GmbH

1. Copyright notice: Each published work result is accompanied by an explicit statement of the license conditions for use. These are regularly typical conditions in connection with open source or free software. Programs described/provided/linked here are free software, unless otherwise stated.
2. Permission notice: Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
    1. The copyright notice (Item 1) and the permission notice (Item 2) shall be included in all copies or substantial portions of the Software.
    2. The software is provided "as is" without warranty of any kind, either express or implied, including, but not limited to, the warranties of fitness for a particular purpose, merchantability, and/or non-infringement. The authors or copyright holders shall not be liable in any manner whatsoever for any damages or other claims arising from, out of or in connection with the software or the use or other dealings with the software, whether in an action of contract, tort, or otherwise.
    3. We take open source license compliance very seriously. We are always striving to achieve compliance at all times and to improve our processes. If you find any issues or have any suggestions or comments, or if you see any other ways in which we can improve, please reach out to: ospo@gematik.de
3. Please note: Parts of this code may have been generated using AI-supported technology. Please take this into account, especially when troubleshooting, for security analyses and possible adjustments.
