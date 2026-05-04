//! A tool to import a wallet public key with descriptors from many different formats seamlessly
//!
//!
//! # Supported formats
//!
//! - Descriptors
//! - Electrum
//! - Wasabi
//! - JSON
//!
//! # Supported descriptors
//!
//! - Single Sig
//! - Watch-only public multisig (`wsh(multi(...))` and `wsh(sortedmulti(...))`)
//!
//! # Examples
//!
//! ## Import in generic JSON format used by many wallets
//! ```rust
//! use pubport::Format;
//!
//! let string = std::fs::read_to_string("test/data/sparrow-export.json").unwrap();
//! let format = Format::try_new_from_str(&string);
//!
//! assert!(format.is_ok());
//!
//! let format = format.unwrap();
//! assert!(matches!(format, Format::Json(_)));
//! ```
//!
//! ## Import from file containing descriptors
//!
//! ***note: need external and internal descriptors, but can be single descriptor or multiple descriptor format***
//!
//! ```rust
//! use pubport::Format;
//!
//! let string = std::fs::read_to_string("test/data/descriptor.txt").unwrap();
//! let format = Format::try_new_from_str(&string);
//!
//! assert!(format.is_ok());
//!
//! let format = format.unwrap();
//! assert!(matches!(format, Format::Descriptor(_)));
//! ```
//!
//! ## Import from a public multisig descriptor
//!
//! ```rust
//! use pubport::Format;
//!
//! let string = "wsh(sortedmulti(2,\
//!     [6f53d49c/44h/1h/0h]tpubDDjsCRDQ9YzyaAq9rspCfq8RZFrWoBpYnLxK6sS2hS2yukqSczgcYiur8Scx4Hd5AZatxTuzMtJQJhchufv1FRFanLqUP7JHwusSSpfcEp2/<0;1>/*,\
//!     [e6807791/44h/1h/0h]tpubDDAfvogaaAxaFJ6c15ht7Tq6ZmiqFYfrSmZsHu7tHXBgnjMZSHAeHSwhvjARNA6Qybon4ksPksjRbPDVp7yXA1KjTjSd5x18KHqbppnXP1s/<0;1>/*,\
//!     [367c9cfa/44h/1h/0h]tpubDDtPnSgWYk8dDnaDwnof4ehcnjuL5VoUt1eW2MoAed1grPHuXPDnkX1fWMvXfcz3NqFxPbhqNZ3QBdYjLz2hABeM9Z2oqMR1Gt2HHYDoCgh/<0;1>/*))";
//! let format = Format::try_new_from_str(string);
//!
//! assert!(format.is_ok());
//!
//! let format = format.unwrap();
//! assert!(matches!(format, Format::MultisigDescriptor(_)));
//! ```
//!
//! ## Import from wasabi wallet format
//!
//! ```rust
//! use pubport::Format;
//!
//! let string = std::fs::read_to_string("test/data/new-wasabi.json").unwrap();
//! let format = Format::try_new_from_str(&string);
//!
//! assert!(format.is_ok());
//!
//! let format = format.unwrap();
//! assert!(matches!(format, Format::Wasabi(_)));
//! ```
//!
//! ## Import from electrum wallet format
//!
//! ```rust
//! use pubport::Format;
//!
//! let string = std::fs::read_to_string("test/data/new-electrum.json").unwrap();
//! let format = Format::try_new_from_str(&string);
//!
//! assert!(format.is_ok());
//!
//! let format = format.unwrap();
//! assert!(matches!(format, Format::Electrum(_)));
//! ```

pub mod descriptor;
pub mod formats;
pub mod json;
pub mod key_expression;
pub mod multisig;
pub mod xpub;

pub type Format = formats::Format;
pub type Error = formats::Error;

pub fn parse_from_str(string: &str) -> Result<formats::Format, formats::Error> {
    formats::Format::try_new_from_str(string)
}

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
