# PubPort

<p>
    <a href="https://crates.io/crates/pubport"><img alt="Crate Info" src="https://img.shields.io/crates/v/pubport.svg"/></a>
    <a href="https://github.com/bitcoinppl/pubport/blob/master/LICENSE"><img alt="Apache-2.0 Licensed" src="https://img.shields.io/badge/Apache--2.0-blue.svg"/></a>
    <a href="https://github.com/bitcoinppl/pubport/actions?query=workflow%3ACI"><img alt="CI Status" src="https://github.com/bitcoinppl/pubport/workflows/CI/badge.svg"></a>
    <a href="https://docs.rs/pubport"><img alt="Docs" src="https://img.shields.io/badge/docs.rs-green"/></a>
</p>

<!-- cargo-rdme start -->

A tool to import a wallet public key with descriptors from many different formats seamlessly

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

**_note: need external and internal descriptors, but can be single descriptor or multiple descriptor format_**

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
