<img align="right" width="250" height="47" src="docs/img/Gematik_Logo_Flag.png"/> <br/>

# Release Notes Spree Integrity Provider (SIP)

## Release 2.0.10

### changed
- **no rolling update** Split table checksums into separate MultiHash and HMAC to improve performance

## Release 2.0.9

### changed
- Automatic crypto update is now configurable via environment variable
  SPREE_AUTOMATIC_CRYPTO_UPDATE (default true)
- Exclude nodes with outdated keys from participating in crypto update

## Release 2.0.8

### changed
- Automatically starts crypto update on keychain change
- Verifies crypto updates by repeating until no more changes

## Release 2.0.7

### changed
- Composite keys are now stored in distinct columns in SPREE_ROW_CHECKSUM
- According queries adapted
- Delta script added

## Release 2.0.6

### changed
- Refactored code/extract new modules bootstrap-provider, crypto-update-provider
- readiness-provider: Provide REST endpoint for health checks
- Recompute checksum of collection parent only when necessary
- Rewrote queries for improved performance
- Fixed various minor glitches

## Release 2.0.5

### changed
- Used correct prime for group 15 in MuHash Implementation

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
