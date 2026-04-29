# Configuration & Threshold Changelog

## 2026.03.27

- Added `CONFIG_VERSION`
- Added baseline validation functions:
  - `validate_security_baseline()`
  - `enforce_security_baseline()`
- Added P2P policy controls:
  - `P2P_REQUIRE_MUTUAL_AUTH`
  - `P2P_TRUSTED_PEER_FINGERPRINTS`
- Added security baseline requirements:
  - Minimum HMAC secret length
  - Non-default HMAC secret requirement
  - Valid threshold bounds for enforcer, vault, whisper, mimicry
  - Fingerprint presence when P2P mutual auth is required
