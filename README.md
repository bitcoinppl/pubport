# PubPort

<!-- cargo-rdme start -->

A tool to import a wallet public key with descriptors from many different formats seamlessly


## Supported formats

- Descriptors
- Electrum
- Wasabi
- JSON

## Supported descriptors

- Single Sig

## Example

```rust
use pubport::Format;

let string = std::fs::read_to_string("test/data/coldcard-export.json").unwrap();
let format = Format::try_new_from_str(&string);

assert!(format.is_ok());

let format = format.unwrap();
matches!(format, Format::Json(_));
```

<!-- cargo-rdme end -->
