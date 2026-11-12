#!/bin/bash

if [ ! -f /tmp/keycloak_dump.sql ] ; then
  echo "Creating database backup"

  pg_dump -U wasadmin -d keycloak --data-only --no-privileges --no-owner > /tmp/keycloak_dump.sql
else
  echo "Database backup already exists"
fi