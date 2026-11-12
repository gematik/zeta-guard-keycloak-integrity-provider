#!/usr/bin/env sh

echo "🔐Running Keychain generator..."

if [ -n "${SPREE_KEYCHAIN_FILE}" ] ; then
  echo "🔐 SPREE_KEYCHAIN_FILE environment variable is set, configuring Keychain generator..."
else
  echo "🚧 SPREE_KEYCHAIN_FILE environment variable is not set, exiting..."
  exit 1
fi

if [ -n "${HSM_PROXY_ENDPOINT}" ] && [ -n "${HSM_PROXY_KEK_ID}" ]; then
  echo "🔐 HSM_PROXY_ENDPOINT and HSM_PROXY_KEK_ID environment variables are set, configuring Keychain generator for HSM..."
else
  echo "🚧 HSM_PROXY_ENDPOINT and/or HSM_PROXY_KEK_ID environment variables are not set, exiting..."
  exit 1
fi

exec java -jar /opt/keychain-generator/spree-keychain-generator.jar "$@"
