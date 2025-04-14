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

pub mod descriptor;
pub mod formats;
pub mod json;
pub mod key_expression;
pub mod xpub;

pub type Format = formats::Format;
pub type Error = formats::Error;

pub fn parse_from_str(string: &str) -> Result<formats::Format, formats::Error> {
    formats::Format::try_new_from_str(string)
}

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
