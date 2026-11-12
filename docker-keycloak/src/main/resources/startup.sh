#!/bin/bash


# shellcheck disable=SC2164
cd /opt/keycloak/bin

echo "Running build"
KC_DEBUG=false ./kc.sh build

echo "Running Keycloak"
exec ./kc.sh start "$@"
