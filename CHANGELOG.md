# Changelog

## Unreleased

### Added

- Support Bitcoin public SLIP-132 extended keys across bare key, JSON,
  Electrum, Wasabi, and BIP380 key-expression imports
- Support testnet single-sig SLIP-132 prefixes `upub` and `vpub`

### Changed

- Bare `ypub` and `upub` imports now create only BIP49 descriptors
- Bare `zpub` and `vpub` imports now create only BIP84 descriptors
- SLIP-132 keys are normalized to standard `xpub` or `tpub` in descriptor
  output

### Deprecated

- `xpub::zpub_to_xpub` and `xpub::ypub_to_xpub`; use
  `xpub::to_standard_extended_public_key` instead

### Breaking

- Private extended keys and uppercase multisig SLIP-132 prefixes now return
  typed unsupported-key errors instead of generic xpub parse failures
- `KeyExpression` now includes the original extended public key format so
  origin-less SLIP-132 key expressions keep their advertised script purpose

## [0.5.0] [2025-11-27]

### Added

- BIP86 (taproot) support in `GenericJson` and `Json` formats
- Support for Passport hardware wallet exports (and other wallets that use zpub/ypub directly in JSON)
- Update deps

### Breaking

- `Format::Json` now contains `Box<Json>` instead of `Json`
- Added `bip86` field to `Json` and `GenericJson` structs

## [0.4.1] [2025-11-27]

### Fixed

- P2shP2wpkh (BIP49) derivation path was incorrectly `49'/0'` instead of `49'/0'/0'`

## [0.4.0] [2025-04-23]

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
