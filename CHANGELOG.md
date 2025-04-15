# Changelog

## Unreleased

- Add `key_expressions` module that can parse key expressions (BIP380)
  - Note we only support key expressions that contain an xpub (no private keys or bare compressed or uncompressed public keys)
- Create descriptor from key expression

## [0.3.1] [2025-03-07]

### Fixed

- Incorrect descriptor derivation path, creating wrong change descriptor

## [0.3.0] (YANKED) [2025-03-06]

### Added

- Get descriptors from bare child xpub

### Breaking

- Renamed `json::Name` to `json::ScriptType`
- `xpub::Xpub` now has the xpub as a `Bip32Xpub` instead of a `String`
