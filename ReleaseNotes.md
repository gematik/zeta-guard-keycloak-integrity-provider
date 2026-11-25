<img align="right" width="250" height="47" src="docs/img/Gematik_Logo_Flag.png"/> <br/>

# Release Notes Keycloak Integrity Provider

## Release 2.0.4-1

### changed

- Keychain generator image rebuilt on OpenJDK 27.0.1.1 (`cgr.dev/chainguard/jdk`, previously OpenJDK 26.0.1) because of
  CVE-2026-114938; no code changes compared to 2.0.4

## Release 2.0.4

### changed

- Table checksum logic for integrity checks is now based on MuHash Implementation 
- Periodic table checksum checks can now be disabled
- Having a permanent error state when integrity check fails is now configurable

## Release 2.0.3

### changed

- Added table checksum logic for integrity checks
- Adjusted initial configuration for keycloak entities used for integrity checks and encryption  
- Further hardening bootstrapping keycloak DB and initial conversion steps in multicluster environments

## Release 2.0.2

### changed

- Added endpoint and logic for Crypto Updates
- Added data integrity checks
- Fixed startup problems in keycloak while DB setup for encryption

## Release 1.4.1

### changed

- Refactored bootstrapping
- Implement atomic database conversion in a clustered environment
- Fix java.lang.ClassCastException: class org.hibernate.query.sql.internal.NativeQueryImpl
- Allow for fine-grained feature configuration

## Release 1.3.3

### changed

- Fix bootstrapping problem with cached realms

## Release 1.3.0

### changed:
- fix crash when restart

## Release 1.2.0

### added:

- initial public release
