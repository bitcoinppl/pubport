#![warn(missing_docs)]

//! Parse wallet public-key exports into descriptors
//!
//! Pubport accepts common single-sig wallet export formats and converts them
//! into external and internal output descriptors. Use [`parse_from_str`] or
//! [`Format::try_new_from_str`] when you have an unknown export string, then
//! match on [`Format`] to inspect the parsed descriptors
//!
//! # Supported formats
//!
//! - Descriptors
//! - Electrum
//! - Wasabi
//! - JSON
//! - Bare XPUB
//! - BIP380 Key Expressions
//!   - note: XPUBs only, key expressions with private keys, bare compressed or uncompressed public keys are not supported)
//!
//! # Supported descriptors
//!
//! - Single Sig
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

/// Descriptor parsing and construction utilities
pub mod descriptor;
/// Format detection for supported wallet export strings
pub mod formats;
/// Serde models for supported JSON wallet export formats
pub mod json;
/// BIP380 key-expression parsing
pub mod key_expression;
/// Extended public-key normalization helpers
pub mod xpub;

/// Supported parsed wallet export format
pub type Format = formats::Format;
/// Error returned by top-level format parsing
pub type Error = formats::Error;

/// Parse a wallet export string into the first supported format that matches
pub fn parse_from_str(string: &str) -> Result<formats::Format, formats::Error> {
    formats::Format::try_new_from_str(string)
}

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
