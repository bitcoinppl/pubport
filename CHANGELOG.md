# Changelog

## Unreleased

## [0.6.0] [2026-06-18]

### Added

- Add `descriptor::DescriptorBuilder` for building external/internal
  descriptors from account xpubs, fingerprints, script types, and explicit or
  coin-type-derived account paths
- Add coin-type-aware descriptor construction with
  `Descriptors::try_from_child_xpub_with_coin_type`, `ScriptType::purpose`,
  and `ScriptType::account_derivation_path_for_coin_type`
- Support Bitcoin public SLIP-132 extended keys across bare key, JSON,
  descriptor, Electrum, Wasabi, and BIP380 key-expression imports
- Support testnet single-sig SLIP-132 prefixes `upub` and `vpub`
- Add extended-key metadata and normalization helpers, including
  `xpub::OriginalFormat`, `xpub::SingleSigPurpose`, `Xpub::original_format`,
  `Xpub::coin_type`, `Xpub::single_sig_purpose`,
  `xpub::to_standard_extended_public_key`, and
  `xpub::normalize_slip132_public_keys`
- Add structured format-detection error details through
  `FormatDetectionErrors` and the related detection error enums

### Changed

- `Format::try_new_from_str` now returns `UnsupportedFormat` with collected
  detection errors when no supported format matches
- Bare `ypub` and `upub` imports now create only BIP49 descriptors
- Bare `zpub` and `vpub` imports now create only BIP84 descriptors
- Bare `tpub`, `upub`, and `vpub` imports now use testnet/signet coin type
  paths in generated descriptors
- SLIP-132 keys are normalized to standard `xpub` or `tpub` in descriptor
  output

### Deprecated

- `xpub::zpub_to_xpub` and `xpub::ypub_to_xpub`; use
  `xpub::to_standard_extended_public_key` instead

### Breaking

- `formats::Error` now uses `UnsupportedFormat(Box<FormatDetectionErrors>)`
  for unsupported inputs, removes `InvalidDescriptorInJson`, and renames
  `JsonNoDecriptor` to `MissingJsonDescriptorData`
- `xpub::Error` variants now distinguish base58, length, unsupported private
  key, and unsupported version failures instead of the older
  `InvalidZpub`/`InvalidYpub*`/`NotXpub` variants
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
