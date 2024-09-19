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

pub mod descriptors;
pub mod formats;
pub mod json;
pub mod xpub;

pub type Format = formats::Format;

pub fn parse_from_str(string: &str) -> Result<formats::Format, formats::Error> {
    formats::Format::try_new_from_str(string)
}
