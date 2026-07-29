# PubPort

[![crates.io](https://img.shields.io/crates/v/pubport.svg)](https://crates.io/crates/pubport)
[![docs.rs](https://img.shields.io/docsrs/pubport)](https://docs.rs/pubport)
[![Downloads](https://img.shields.io/crates/d/pubport.svg)](https://crates.io/crates/pubport)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/bitcoinppl/pubport/blob/master/LICENSE)
[![CI](https://github.com/bitcoinppl/pubport/workflows/CI/badge.svg)](https://github.com/bitcoinppl/pubport/actions?query=workflow%3ACI)

<!-- cargo-rdme start -->

Parse wallet public-key exports into descriptors

Pubport accepts common single-sig wallet export formats and converts them
into external and internal output descriptors. Use [`parse_from_str`] or
[`Format::try_new_from_str`] when you have an unknown export string, then
match on [`Format`] to inspect the parsed descriptors

## Supported formats

- Descriptors
- Electrum
- Wasabi
- JSON
- Bare XPUB
- BIP380 Key Expressions
  - note: XPUBs only, key expressions with private keys, bare compressed or uncompressed public keys are not supported)

## Supported descriptors

- Single Sig

## Examples

### Import in generic JSON format used by many wallets
```rust
use pubport::Format;

let string = std::fs::read_to_string("test/data/sparrow-export.json").unwrap();
let format = Format::try_new_from_str(&string);

assert!(format.is_ok());

let format = format.unwrap();
assert!(matches!(format, Format::Json(_)));
```

### Import from file containing descriptors

***note: need external and internal descriptors, but can be single descriptor or multiple descriptor format***

```rust
use pubport::Format;

let string = std::fs::read_to_string("test/data/descriptor.txt").unwrap();
let format = Format::try_new_from_str(&string);

assert!(format.is_ok());

let format = format.unwrap();
assert!(matches!(format, Format::Descriptor(_)));
```

### Import from wasabi wallet format

```rust
use pubport::Format;

let string = std::fs::read_to_string("test/data/new-wasabi.json").unwrap();
let format = Format::try_new_from_str(&string);

assert!(format.is_ok());

let format = format.unwrap();
assert!(matches!(format, Format::Wasabi(_)));
```

### Import from electrum wallet format

```rust
use pubport::Format;

let string = std::fs::read_to_string("test/data/new-electrum.json").unwrap();
let format = Format::try_new_from_str(&string);

assert!(format.is_ok());

let format = format.unwrap();
assert!(matches!(format, Format::Electrum(_)));
```

<!-- cargo-rdme end -->
