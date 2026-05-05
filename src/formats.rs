use crate::{
    descriptor::{self, Descriptors, ScriptType},
    json::{self, GenericJson, WasabiJson},
    key_expression::KeyExpression,
    xpub,
};
use serde::{Deserialize, Serialize};

/// A parsed wallet export format
#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub enum Format {
    /// Output descriptors parsed from descriptor text
    Descriptor(Descriptors),
    /// Descriptors parsed from a generic JSON export or bare child xpub
    Json(Box<Json>),
    /// Descriptors parsed from a Wasabi wallet JSON export
    Wasabi(Descriptors),
    /// Descriptors parsed from an Electrum wallet JSON export
    Electrum(Descriptors),
    /// Descriptors parsed from a BIP380 key expression
    KeyExpression(Descriptors),
}

/// Errors returned while detecting or parsing a wallet export format
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Descriptor parsing failed
    #[error("Invalid descriptor: {0}")]
    InvalidDescriptor(#[from] descriptor::Error),

    /// JSON parsing failed
    #[error("Invalid json: {0}")]
    InvalidJsonParse(#[from] serde_json::Error),

    /// A generic JSON export did not contain descriptor or xpub data
    #[error("Invalid json, no xpubs or descriptor")]
    MissingJsonDescriptorData,

    /// Extended public-key parsing failed
    #[error("Invalid xpub: {0}")]
    InvalidXpub(#[from] xpub::Error),

    /// No supported wallet export format matched the input
    #[error("Unsupported wallet export format")]
    UnsupportedFormat(Box<FormatDetectionErrors>),
}

/// Errors collected while trying to detect a wallet export format
#[derive(Debug)]
pub struct FormatDetectionErrors {
    /// Generic JSON export parse or conversion failure
    pub generic_json: Option<GenericJsonDetectionError>,
    /// Wasabi JSON export parse or conversion failure
    pub wasabi_json: Option<WalletJsonDetectionError>,
    /// Electrum JSON export parse or conversion failure
    pub electrum_json: Option<WalletJsonDetectionError>,
    /// Descriptor text parse failure
    pub descriptor: Option<descriptor::Error>,
    /// Bare child xpub parse or conversion failure
    pub child_xpub: Option<ChildXpubDetectionError>,
    /// BIP380 key-expression parse failure
    pub key_expression: Option<crate::key_expression::Error>,
}

impl std::fmt::Display for FormatDetectionErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("no supported wallet export format matched")
    }
}

impl std::error::Error for FormatDetectionErrors {}

/// Generic JSON detection failure
#[derive(Debug, thiserror::Error)]
pub enum GenericJsonDetectionError {
    /// JSON parsing failed
    #[error("Invalid generic json: {0}")]
    Parse(serde_json::Error),

    /// The JSON did not contain descriptor or xpub data
    #[error("Generic json did not contain descriptor or xpub data")]
    MissingDescriptorData,

    /// Descriptor construction from JSON failed
    #[error("Unable to create descriptor from generic json: {0}")]
    Descriptor(#[source] descriptor::Error),
}

/// Wallet-specific JSON detection failure
#[derive(Debug, thiserror::Error)]
pub enum WalletJsonDetectionError {
    /// JSON parsing failed
    #[error("Invalid wallet json: {0}")]
    Parse(serde_json::Error),

    /// Descriptor construction from JSON failed
    #[error("Unable to create descriptor from wallet json: {0}")]
    Descriptor(#[source] descriptor::Error),
}

/// Bare child xpub detection failure
#[derive(Debug, thiserror::Error)]
pub enum ChildXpubDetectionError {
    /// Extended public-key parsing failed
    #[error("Invalid child xpub: {0}")]
    Xpub(#[source] xpub::Error),

    /// Descriptor construction from the child xpub failed
    #[error("Unable to create descriptor from child xpub: {0}")]
    Descriptor(#[source] descriptor::Error),
}

/// Descriptors grouped by standard single-sig BIP purpose
#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct Json {
    /// BIP44 P2PKH descriptors
    pub bip44: Option<Descriptors>,
    /// BIP49 P2SH-P2WPKH descriptors
    pub bip49: Option<Descriptors>,
    /// BIP84 P2WPKH descriptors
    pub bip84: Option<Descriptors>,
    /// BIP86 P2TR descriptors
    pub bip86: Option<Descriptors>,
}

impl TryFrom<GenericJson> for Json {
    type Error = Error;

    fn try_from(json: GenericJson) -> Result<Self, Self::Error> {
        if json.bip44.is_none()
            && json.bip49.is_none()
            && json.bip84.is_none()
            && json.bip86.is_none()
        {
            return Err(Error::MissingJsonDescriptorData);
        }

        let bip44 = json
            .bip44
            .map(|mut single_sig| {
                single_sig.name.get_or_insert(ScriptType::P2pkh);
                Descriptors::try_from_single_sig(single_sig, json.xfp.as_deref())
            })
            .transpose()?;

        let bip49 = json
            .bip49
            .map(|mut single_sig| {
                single_sig.name.get_or_insert(ScriptType::P2shP2wpkh);
                Descriptors::try_from_single_sig(single_sig, json.xfp.as_deref())
            })
            .transpose()?;

        let bip84 = json
            .bip84
            .map(|mut single_sig| {
                single_sig.name.get_or_insert(ScriptType::P2wpkh);
                Descriptors::try_from_single_sig(single_sig, json.xfp.as_deref())
            })
            .transpose()?;

        let bip86 = json
            .bip86
            .map(|mut single_sig| {
                single_sig.name.get_or_insert(ScriptType::P2tr);
                Descriptors::try_from_single_sig(single_sig, json.xfp.as_deref())
            })
            .transpose()?;

        if bip44.is_none() && bip49.is_none() && bip84.is_none() && bip86.is_none() {
            return Err(Error::MissingJsonDescriptorData);
        }

        Ok(Json {
            bip44,
            bip49,
            bip84,
            bip86,
        })
    }
}

impl Format {
    fn detect_generic_json(string: &str) -> Result<Result<Self, GenericJsonDetectionError>, Error> {
        let json = match serde_json::from_str::<json::GenericJson>(string) {
            Ok(json) => json,
            Err(error) => return Ok(Err(GenericJsonDetectionError::Parse(error))),
        };

        match Json::try_from(json) {
            Ok(json) => Ok(Ok(Format::Json(Box::new(json)))),
            Err(Error::MissingJsonDescriptorData) => {
                Ok(Err(GenericJsonDetectionError::MissingDescriptorData))
            }
            Err(Error::InvalidDescriptor(error)) => {
                Ok(Err(GenericJsonDetectionError::Descriptor(error)))
            }
            Err(error) => Err(error),
        }
    }

    fn detect_wasabi_json(string: &str) -> Result<Self, WalletJsonDetectionError> {
        let json: WasabiJson =
            serde_json::from_str(string).map_err(WalletJsonDetectionError::Parse)?;

        let desc = Descriptors::try_from(json).map_err(WalletJsonDetectionError::Descriptor)?;
        Ok(Format::Wasabi(desc))
    }

    /// Detect and parse a supported wallet export string
    ///
    /// Detection tries generic JSON, Wasabi JSON, Electrum JSON, descriptor
    /// text, bare child xpubs, and BIP380 key expressions in that order
    ///
    /// # Examples
    ///
    /// ```rust
    /// use pubport::Format;
    ///
    /// let descriptor = "wpkh([817e7be0/84h/0h/0h]xpub6CiKnWv7PPyyeb4kCwK4fidKqVjPfD9TP6MiXnzBVGZYNanNdY3mMvywcrdDc6wK82jyBSd95vsk26QujnJWPrSaPfYeyW7NyX37HHGtfQM/<0;1>/*)#60tjs4c7";
    /// let format = Format::try_new_from_str(descriptor)?;
    ///
    /// assert!(matches!(format, Format::Descriptor(_)));
    ///
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn try_new_from_str(string: &str) -> Result<Self, Error> {
        let generic_json = match Self::detect_generic_json(string)? {
            Ok(format) => return Ok(format),
            Err(error) => Some(error),
        };

        let wasabi_json = match Self::detect_wasabi_json(string) {
            Ok(format) => return Ok(format),
            Err(error) => Some(error),
        };

        let electrum_json = match serde_json::from_str::<json::ElectrumJson>(string) {
            Ok(json) => match Descriptors::try_from(json) {
                Ok(desc) => return Ok(Format::Electrum(desc)),
                Err(error) => Some(WalletJsonDetectionError::Descriptor(error)),
            },
            Err(error) => Some(WalletJsonDetectionError::Parse(error)),
        };

        let descriptor = match Descriptors::try_from(string) {
            Ok(desc) => return Ok(Format::Descriptor(desc)),
            Err(error) => Some(error),
        };

        let child_xpub = match Json::try_from_child_xpub_str(string) {
            Ok(json) => return Ok(Format::Json(Box::new(json))),
            Err(Error::InvalidXpub(error)) => Some(ChildXpubDetectionError::Xpub(error)),
            Err(Error::InvalidDescriptor(error)) => {
                Some(ChildXpubDetectionError::Descriptor(error))
            }
            Err(error) => return Err(error),
        };

        let key_expression = match KeyExpression::try_from_str(string) {
            Ok(key_expression) => key_expression,
            Err(error) => {
                return Err(Error::UnsupportedFormat(Box::new(FormatDetectionErrors {
                    generic_json,
                    wasabi_json,
                    electrum_json,
                    descriptor,
                    child_xpub,
                    key_expression: Some(error),
                })));
            }
        };

        if key_expression.has_descriptor_fields() {
            let desc = Descriptors::try_from_key_expression(&key_expression)?;
            return Ok(Format::KeyExpression(desc));
        }

        let json = match key_expression.xpub_original_format {
            Some(original_format) => Json::try_from_child_xpub_with_original_format(
                key_expression.xpub,
                original_format,
            )?,

            None => Json::try_from_child_xpub(key_expression.xpub)?,
        };

        Ok(Format::Json(Box::new(json)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::base58;

    const BIP49_YPUB: &str = "ypub6Ww3ibxVfGzLrAH1PNcjyAWenMTbbAosGNB6VvmSEgytSER9azLDWCxoJwW7Ke7icmizBMXrzBx9979FfaHxHcrArf3zbeJJJUZPf663zsP";
    const BIP84_ZPUB: &str = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";
    const TPUB_VERSION: [u8; 4] = [0x04, 0x35, 0x87, 0xcf];
    const UPUB_VERSION: [u8; 4] = [0x04, 0x4a, 0x52, 0x62];
    const VPUB_VERSION: [u8; 4] = [0x04, 0x5f, 0x1c, 0xf6];

    #[test]
    fn test_parse_all_formats() {
        let files = std::fs::read_dir("test/data").unwrap();

        for file in files {
            let file = file.unwrap();
            let path = file.path();

            if !path.ends_with(".json") || path.ends_with(".txt") {
                continue;
            }

            let string = std::fs::read_to_string(&path).unwrap();

            let format = Format::try_new_from_str(&string);
            assert!(format.is_ok());
        }
    }

    #[test]
    fn test_parse_with_base_xpub() {
        let xpub = "xpub6CiKnWv7PPyyeb4kCwK4fidKqVjPfD9TP6MiXnzBVGZYNanNdY3mMvywcrdDc6wK82jyBSd95vsk26QujnJWPrSaPfYeyW7NyX37HHGtfQM";
        let format = Format::try_new_from_str(xpub);
        assert!(format.is_ok());
    }

    #[test]
    fn test_parse_bare_ypub_only_returns_bip49() {
        let format = Format::try_new_from_str(BIP49_YPUB).unwrap();
        let Format::Json(json) = format else {
            panic!("Expected Format::Json");
        };

        assert!(json.bip44.is_none());
        assert!(json.bip49.is_some());
        assert!(json.bip84.is_none());
        assert!(json.bip86.is_none());
        assert!(json
            .bip49
            .unwrap()
            .external
            .to_string()
            .starts_with("sh(wpkh("));
    }

    #[test]
    fn test_parse_bare_zpub_only_returns_bip84() {
        let format = Format::try_new_from_str(BIP84_ZPUB).unwrap();
        let Format::Json(json) = format else {
            panic!("Expected Format::Json");
        };

        assert!(json.bip44.is_none());
        assert!(json.bip49.is_none());
        assert!(json.bip84.is_some());
        assert!(json.bip86.is_none());
        assert!(json
            .bip84
            .unwrap()
            .external
            .to_string()
            .starts_with("wpkh("));
    }

    #[test]
    fn test_parse_suffixed_zpub_only_returns_bip84() {
        let input = format!("{BIP84_ZPUB}/0/*");
        let format = Format::try_new_from_str(&input).unwrap();
        let Format::Json(json) = format else {
            panic!("Expected Format::Json");
        };

        assert!(json.bip44.is_none());
        assert!(json.bip49.is_none());
        assert!(json.bip84.is_some());
        assert!(json.bip86.is_none());
    }

    #[test]
    fn test_parse_key_expression_only_falls_back_when_incomplete() {
        let input = format!("{BIP84_ZPUB}/0/*");
        let format = Format::try_new_from_str(&input).unwrap();
        let Format::Json(json) = format else {
            panic!("Expected Format::Json");
        };

        assert!(json.bip44.is_none());
        assert!(json.bip49.is_none());
        assert!(json.bip84.is_some());
        assert!(json.bip86.is_none());
    }

    #[test]
    fn test_parse_key_expression_returns_non_incomplete_descriptor_errors() {
        let input = format!("[deadbeef/84/0h/0h]{BIP84_ZPUB}/0/*");
        let result = Format::try_new_from_str(&input);

        assert!(matches!(
            result,
            Err(Error::InvalidDescriptor(
                descriptor::Error::ScriptTypeParseError(_)
            ))
        ));
    }

    #[test]
    fn test_parse_unsupported_format_returns_detection_errors() {
        let result = Format::try_new_from_str("not a wallet export");

        let Err(Error::UnsupportedFormat(errors)) = result else {
            panic!("Expected UnsupportedFormat");
        };

        assert!(matches!(
            errors.generic_json,
            Some(GenericJsonDetectionError::Parse(_))
        ));
        assert!(matches!(
            errors.wasabi_json,
            Some(WalletJsonDetectionError::Parse(_))
        ));
        assert!(matches!(
            errors.electrum_json,
            Some(WalletJsonDetectionError::Parse(_))
        ));
        assert!(errors.descriptor.is_some());
        assert!(matches!(
            errors.child_xpub,
            Some(ChildXpubDetectionError::Xpub(_))
        ));
        assert!(errors.key_expression.is_some());
    }

    #[test]
    fn test_parse_malformed_json_records_generic_json_parse_error() {
        let result = Format::try_new_from_str("{");

        let Err(Error::UnsupportedFormat(errors)) = result else {
            panic!("Expected UnsupportedFormat");
        };

        assert!(matches!(
            errors.generic_json,
            Some(GenericJsonDetectionError::Parse(_))
        ));
    }

    #[test]
    fn test_parse_generic_json_without_descriptor_data_records_missing_data() {
        let result = Format::try_new_from_str("{}");

        let Err(Error::UnsupportedFormat(errors)) = result else {
            panic!("Expected UnsupportedFormat");
        };

        assert!(matches!(
            errors.generic_json,
            Some(GenericJsonDetectionError::MissingDescriptorData)
        ));
    }

    #[test]
    fn test_parse_bare_testnet_slip132_uses_testnet_coin_type() {
        let upub = key_with_version(BIP49_YPUB, UPUB_VERSION);
        let vpub = key_with_version(BIP84_ZPUB, VPUB_VERSION);

        let upub_format = Format::try_new_from_str(&upub).unwrap();
        let Format::Json(upub_json) = upub_format else {
            panic!("Expected Format::Json");
        };
        let vpub_format = Format::try_new_from_str(&vpub).unwrap();
        let Format::Json(vpub_json) = vpub_format else {
            panic!("Expected Format::Json");
        };

        let upub_desc = upub_json.bip49.unwrap().external.to_string();
        let vpub_desc = vpub_json.bip84.unwrap().external.to_string();

        assert!(upub_desc.contains("/49'/1'/0']tpub"));
        assert!(vpub_desc.contains("/84'/1'/0']tpub"));
    }

    #[test]
    fn test_parse_bare_tpub_uses_testnet_coin_type() {
        let tpub = key_with_version(BIP84_ZPUB, TPUB_VERSION);
        let format = Format::try_new_from_str(&tpub).unwrap();
        let Format::Json(json) = format else {
            panic!("Expected Format::Json");
        };

        assert!(json
            .bip84
            .unwrap()
            .external
            .to_string()
            .contains("/84'/1'/0']tpub"));
    }

    #[test]
    fn test_parse_generic_json_with_testnet_slip132_keys() {
        let upub = key_with_version(BIP49_YPUB, UPUB_VERSION);
        let vpub = key_with_version(BIP84_ZPUB, VPUB_VERSION);
        let json_str = format!(
            r#"{{
  "xfp": "73c5da0a",
  "bip49": {{
    "deriv": "m/49'/1'/0'",
    "xpub": "{upub}"
  }},
  "bip84": {{
    "deriv": "m/84'/1'/0'",
    "xpub": "{vpub}"
  }}
}}"#
        );

        let format = Format::try_new_from_str(&json_str).unwrap();
        let Format::Json(json) = format else {
            panic!("Expected Format::Json");
        };

        let bip49 = json.bip49.expect("bip49 should be present");
        let bip84 = json.bip84.expect("bip84 should be present");

        assert!(bip49.external.to_string().contains("tpub"));
        assert!(bip49.external.to_string().starts_with("sh(wpkh("));
        assert!(bip49.external.to_string().contains("/49'/1'/0']tpub"));
        assert!(bip84.external.to_string().contains("tpub"));
        assert!(bip84.external.to_string().starts_with("wpkh("));
        assert!(bip84.external.to_string().contains("/84'/1'/0']tpub"));
        assert!(json.bip44.is_none());
        assert!(json.bip86.is_none());
    }

    #[test]
    fn test_parse_electrum_with_testnet_slip132_keys() {
        for (derivation, key, expected_start) in [
            (
                "m/49h/1h/0h",
                key_with_version(BIP49_YPUB, UPUB_VERSION),
                "sh(wpkh(",
            ),
            (
                "m/84h/1h/0h",
                key_with_version(BIP84_ZPUB, VPUB_VERSION),
                "wpkh(",
            ),
        ] {
            let json_str = format!(
                r#"{{
  "seed_version": 17,
  "use_encryption": false,
  "wallet_type": "standard",
  "keystore": {{
    "type": "hardware",
    "hw_type": "coldcard",
    "label": "Testnet Import",
    "derivation": "{derivation}",
    "xpub": "{key}"
  }}
}}"#
            );

            let format = Format::try_new_from_str(&json_str).unwrap();
            let Format::Electrum(desc) = format else {
                panic!("Expected Format::Electrum");
            };

            assert!(desc.external.to_string().starts_with(expected_start));
            assert!(desc.external.to_string().contains("tpub"));
        }
    }

    #[test]
    fn test_parse_krux() {
        let string = std::fs::read_to_string("test/data/krux.txt").unwrap();
        let krux = KeyExpression::try_from_str(&string);
        assert!(krux.is_ok());
    }

    /// Test bip86 parsing with zpub (SLIP-132 format)
    #[test]
    fn test_json_format_includes_bip86_with_zpub() {
        let json_str = r#"{
  "xfp": "73c5da0a",
  "bip84": {
    "deriv": "m/84'/0'/0'",
    "xpub": "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs",
    "first": "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
  },
  "bip86": {
    "deriv": "m/86'/0'/0'",
    "xpub": "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ",
    "first": "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
  }
}"#;

        let format = Format::try_new_from_str(json_str).expect("Failed to parse");

        match format {
            Format::Json(json) => {
                assert!(json.bip84.is_some(), "bip84 should be present");
                assert!(json.bip86.is_some(), "bip86 should be present");
            }
            _ => panic!("Expected Format::Json"),
        }
    }

    /// Test bip86 parsing with standard xpub format
    #[test]
    fn test_json_format_includes_bip86_with_xpub() {
        let json_str = r#"{
  "xfp": "817e7be0",
  "bip84": {
    "deriv": "m/84'/0'/0'",
    "xpub": "xpub6CiKnWv7PPyyeb4kCwK4fidKqVjPfD9TP6MiXnzBVGZYNanNdY3mMvywcrdDc6wK82jyBSd95vsk26QujnJWPrSaPfYeyW7NyX37HHGtfQM",
    "first": "bc1q0g0vn4yqyk0zjwxw0zv5pltyyczty004zc9g7r"
  },
  "bip86": {
    "deriv": "m/86'/0'/0'",
    "xpub": "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ",
    "first": "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
  }
}"#;

        let format = Format::try_new_from_str(json_str).expect("Failed to parse");

        match format {
            Format::Json(json) => {
                assert!(json.bip84.is_some(), "bip84 should be present");
                assert!(json.bip86.is_some(), "bip86 should be present");
            }
            _ => panic!("Expected Format::Json"),
        }
    }

    fn key_with_version(key: &str, version: [u8; 4]) -> String {
        let mut decoded = base58::decode_check(key).expect("valid test vector");
        decoded[0..4].copy_from_slice(&version);
        base58::encode_check(&decoded)
    }
}
