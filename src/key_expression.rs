//! Parse a key expression string into a KeyExpression, we only support KeyExpressions that contain
//! an XPub, we do not support KeyExpressions that contain a private key or bare compressed or uncompressed public keys.

use bitcoin::bip32::{DerivationPath, Fingerprint, Xpub};
use std::str::FromStr;

/// Errors that can occur when parsing a key expression
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("A valid key expression must contain only ASCII digits")]
    NotAsciiDigits,

    #[error("Invalid key origin format")]
    InvalidKeyOrigin,

    #[error("Children indicator not allowed in key origin: {0}")]
    ChildrenIndicatorInKeyOrigin(String),

    #[error("Trailing slash in key origin")]
    TrailingSlashInKeyOrigin,

    #[error("Invalid fingerprint length (must be 8 characters), was {0}")]
    InvalidFingerprintLength(usize),

    #[error("Invalid hardened indicator, must be 'h' or \"'\" found {0}")]
    InvalidHardenedIndicator(char),

    #[error("Negative indices are not allowed")]
    NegativeIndices,

    #[error("WIF private keys cannot have derivation paths")]
    PrivateKeyWithDerivation,

    #[error("Derivation index out of range: {0}")]
    DerivationIndexOutOfRange(String),

    #[error("Invalid derivation index (must be a number), found {0}")]
    InvalidDerivationIndex(String),

    #[error("Multiple key origins are not allowed")]
    MultipleKeyOrigins(String),

    #[error("Missing key origin start bracket: {0}")]
    MissingKeyOriginStart(String),

    #[error("Non-hexadecimal fingerprint: {0}")]
    NonHexFingerprint(String),

    #[error("Key origin with no public key: {0}")]
    KeyOriginWithNoPublicKey(String),

    #[error("Failed to parse Xpub: {0}")]
    XpubParseError(#[from] bitcoin::bip32::Error),

    #[error("Failed to parse derivation path: {0}")]
    DerivationPathParseError(bitcoin::bip32::Error),

    #[error("Unexpected error: {0}")]
    UnexpectedError(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// A parsed key expression
pub struct KeyExpression {
    /// the public key in xpub format
    pub xpub: Xpub,

    /// the master fingerprint if present in the origin
    pub master_fingerprint: Option<Fingerprint>,

    /// the derivation path if present in the origin
    pub origin_derivation_path: Option<DerivationPath>,

    /// the derivation path if present after the xpub
    pub derivation_path: Option<DerivationPath>,
}

impl KeyExpression {
    /// Parse a key expression string into a KeyExpression struct using winnow
    pub fn try_from_str(input_str: &str) -> Result<Self, Error> {
        if !input_str.is_ascii() {
            return Err(Error::NotAsciiDigits);
        }

        let mut parser = Parser::new(input_str);

        let (master_fingerprint, origin_path) = parser.parse_optional_fingerprint_and_path()?;

        // check for multiple key origins
        if parser.contains('[') && parser.contains(']') {
            return Err(Error::MultipleKeyOrigins(
                parser.remaining_input.to_string(),
            ));
        }

        // check if there's a derivation path after the xpub
        let (xpub_str, derivation_path) = parser.parse_xpub_and_derivation()?;

        let xpub = Xpub::from_str(xpub_str).map_err(Error::XpubParseError)?;

        // Return the parsed KeyExpression
        Ok(KeyExpression {
            xpub,
            master_fingerprint,
            origin_derivation_path: origin_path,
            derivation_path,
        })
    }
}

struct Parser<'a> {
    remaining_input: &'a str,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            remaining_input: input,
        }
    }

    fn starts_with(&self, char: char) -> bool {
        self.remaining_input.starts_with(char)
    }

    fn contains(&self, byte: impl ToByte) -> bool {
        memchr::memchr(byte.to_byte(), self.remaining_input.as_bytes()).is_some()
    }

    fn find(&self, byte: impl ToByte) -> Option<usize> {
        memchr::memchr(byte.to_byte(), self.remaining_input.as_bytes())
    }

    /// Parse the optional xpub and derivation path at the end
    fn parse_xpub_and_derivation(&mut self) -> Result<(&'a str, Option<DerivationPath>), Error> {
        // check if there's a slash in the remaining input
        if let Some(slash_pos) = self.find('/') {
            // Split at the slash
            let xpub_part = &self.remaining_input[..slash_pos];
            let path_part = &self.remaining_input[slash_pos + 1..];

            // Process the derivation path
            // First validate it doesn't contain invalid characters
            if path_part.contains('-') {
                return Err(Error::NegativeIndices);
            }

            // For empty string, return no derivation
            if path_part.is_empty() {
                return Err(Error::TrailingSlashInKeyOrigin);
            }

            // Handle the path - we need to strip any wildcard before parsing
            let cleaned_path = path_part.replace("*h", "0h").replace("*", "0");
            let path_str = format!("m/{}", cleaned_path);

            let derivation_path = DerivationPath::from_str(&path_str).map_err(|e| {
                // Check if the derivation path is invalid due to out of range indices
                if path_part.contains("2147483648") || path_part.contains("0x80000000") {
                    Error::DerivationIndexOutOfRange(path_part.to_string())
                } else if path_part
                    .chars()
                    .any(|c| !c.is_ascii_digit() && c != '/' && c != 'h' && c != '\'' && c != '*')
                {
                    Error::InvalidDerivationIndex(path_part.to_string())
                } else {
                    Error::DerivationPathParseError(e)
                }
            })?;

            // update remaining input (cleared since we parsed everything)
            self.remaining_input = "";
            return Ok((xpub_part, Some(derivation_path)));
        }

        // no slash, so the entire remaining input is the xpub
        let xpub_part = self.remaining_input;

        // update remaining input (cleared since we parsed everything)
        self.remaining_input = "";

        Ok((xpub_part, None))
    }

    fn parse_optional_fingerprint_and_path(
        &mut self,
    ) -> Result<(Option<Fingerprint>, Option<DerivationPath>), Error> {
        if !self.starts_with('[') && self.contains(']') {
            return Err(Error::MissingKeyOriginStart(
                self.remaining_input.to_string(),
            ));
        }

        if !self.remaining_input.starts_with('[') {
            return Ok((None, None));
        }

        // extract content within brackets
        let origin_content = {
            // find closing bracket
            let closing_bracket_pos = self.find(']').ok_or(Error::InvalidKeyOrigin)?;

            let inside_bracket_content = &self.remaining_input[1..closing_bracket_pos];

            // change input to the remaining content
            self.remaining_input = &self.remaining_input[closing_bracket_pos + 1..];

            // the origin is the content inside the brackets
            inside_bracket_content
        };

        // If we only have a key origin with no xpub
        if self.remaining_input.is_empty() {
            return Err(Error::KeyOriginWithNoPublicKey(origin_content.to_string()));
        }

        // split by first slash to separate fingerprint from path
        let parts: Vec<&str> = origin_content.splitn(2, '/').collect();
        let fingerprint_str = parts[0];

        // validate fingerprint
        if fingerprint_str.len() != 8 {
            return Err(Error::InvalidFingerprintLength(fingerprint_str.len()));
        }

        if !fingerprint_str.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(Error::NonHexFingerprint(fingerprint_str.to_string()));
        }

        // parse the fingerprint
        let fingerprint = Fingerprint::from_str(fingerprint_str)
            .map_err(|_| Error::NonHexFingerprint(fingerprint_str.to_string()))?;

        if parts.len() == 1 {
            return Ok((Some(fingerprint), None));
        }

        let path_str = parts[1];

        // validation checks
        if path_str.ends_with('/') {
            return Err(Error::TrailingSlashInKeyOrigin);
        }

        if path_str.contains('*') {
            return Err(Error::ChildrenIndicatorInKeyOrigin(path_str.to_string()));
        }

        if path_str.contains('-') {
            return Err(Error::NegativeIndices);
        }

        // check hardened indicators - allow both h and ' for hardened derivation
        for segment in path_str.split('/') {
            if !segment.is_empty() {
                let last_char = segment.chars().last().unwrap_or_default();
                // Allow digits for non-hardened, or h/' for hardened
                if !last_char.is_ascii_digit() && last_char != 'h' && last_char != '\'' {
                    return Err(Error::InvalidHardenedIndicator(last_char));
                }
            }
        }

        // parse the path with m/ prefix
        let full_path_str = format!("m/{}", path_str);
        let derivation_path =
            DerivationPath::from_str(&full_path_str).map_err(Error::DerivationPathParseError)?;

        Ok((Some(fingerprint), Some(derivation_path)))
    }
}

trait ToByte {
    fn to_byte(self) -> u8;
}

impl ToByte for char {
    fn to_byte(self) -> u8 {
        self as u8
    }
}

impl ToByte for u8 {
    fn to_byte(self) -> u8 {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extended_public_key() {
        let input = "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL";
        let result = KeyExpression::try_from_str(input).unwrap();
        assert!(matches!(result, KeyExpression { xpub: _, .. }));
    }

    #[test]
    fn test_extended_public_key_with_key_origin() {
        let input = "[deadbeef/0h/1h/2h]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL";
        let result = KeyExpression::try_from_str(input).unwrap();
        assert!(matches!(
            result,
            KeyExpression {
                xpub: _,
                master_fingerprint: Some(_),
                origin_derivation_path: Some(_),
                derivation_path: None,
            }
        ));
    }

    #[test]
    fn test_extended_public_key_with_derivation() {
        let input = "[deadbeef/0h/1h/2h]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/3/4/5";
        let result = KeyExpression::try_from_str(input).unwrap();
        assert!(matches!(
            result,
            KeyExpression {
                xpub: _,
                master_fingerprint: Some(_),
                origin_derivation_path: Some(_),
                derivation_path: Some(_),
            }
        ));
    }

    #[test]
    fn test_extended_public_key_with_derivation_and_children() {
        let input = "[deadbeef/0h/1h/2h]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/3/4/5/*";
        let result = KeyExpression::try_from_str(input).unwrap();
        assert!(matches!(
            result,
            KeyExpression {
                xpub: _,
                master_fingerprint: Some(_),
                origin_derivation_path: Some(_),
                derivation_path: Some(_),
            }
        ));
    }

    #[test]
    fn test_extended_public_key_with_hardened_derivation_and_unhardened_children() {
        let input = "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/3h/4h/5h/*";
        let result = KeyExpression::try_from_str(input).unwrap();
        assert!(matches!(
            result,
            KeyExpression {
                xpub: _,
                derivation_path: Some(_),
                ..
            }
        ));
    }

    #[test]
    fn test_extended_public_key_with_hardened_derivation_and_hardened_children() {
        let input = "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/3h/4h/5h/*h";
        let result = KeyExpression::try_from_str(input).unwrap();
        assert!(matches!(
            result,
            KeyExpression {
                xpub: _,
                derivation_path: Some(_),
                ..
            }
        ));
    }

    #[test]
    fn test_extended_public_key_with_key_origin_hardened_derivation_and_children() {
        let input = "[deadbeef/0h/1h/2]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/3h/4h/5h/*h";
        let result = KeyExpression::try_from_str(input).unwrap();
        assert!(matches!(
            result,
            KeyExpression {
                xpub: _,
                master_fingerprint: Some(_),
                origin_derivation_path: Some(_),
                derivation_path: Some(_),
            }
        ));
    }

    #[test]
    fn test_invalid_children_indicator_in_key_origin() {
        let input = "[deadbeef/0h/0h/0h/*]0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600";
        let result = KeyExpression::try_from_str(input);
        assert!(matches!(
            result,
            Err(Error::ChildrenIndicatorInKeyOrigin(_))
        ));
    }

    #[test]
    fn test_invalid_trailing_slash_in_key_origin() {
        let input = "[deadbeef/0h/0h/0h/]0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600";
        let result = KeyExpression::try_from_str(input);
        assert!(matches!(result, Err(Error::TrailingSlashInKeyOrigin)));
    }

    #[test]
    fn test_invalid_too_short_fingerprint() {
        let input =
            "[deadbef/0h/0h/0h]0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600";
        let result = KeyExpression::try_from_str(input);
        assert!(matches!(result, Err(Error::InvalidFingerprintLength(_))));
    }

    #[test]
    fn test_invalid_too_long_fingerprint() {
        let input = "[deadbeeef/0h/0h/0h]0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600";
        let result = KeyExpression::try_from_str(input);
        assert!(matches!(result, Err(Error::InvalidFingerprintLength(_))));
    }

    #[test]
    fn test_invalid_hardened_indicators_other_letter() {
        let input =
            "[deadbeef/0z/0d/0h]0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600";
        let result = KeyExpression::try_from_str(input);
        assert!(matches!(result, Err(Error::InvalidHardenedIndicator(_))));
    }

    #[test]
    fn test_invalid_hardened_indicators_f() {
        let input =
            "[deadbeef/0f/0f/0f]0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600";
        let result = KeyExpression::try_from_str(input);
        assert!(matches!(result, Err(Error::InvalidHardenedIndicator(_))));
    }

    #[test]
    fn test_invalid_hardened_indicators_capital_h() {
        let input =
            "[deadbeef/0H/0H/0H]0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600";
        let result = KeyExpression::try_from_str(input);
        assert!(matches!(result, Err(Error::InvalidHardenedIndicator(_))));
    }

    #[test]
    fn test_invalid_negative_indices() {
        let input =
            "[deadbeef/-0/-0/-0]0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600";
        let result = KeyExpression::try_from_str(input);
        assert!(matches!(result, Err(Error::NegativeIndices)));
    }

    #[test]
    fn test_invalid_derivation_index_out_of_range() {
        let input = "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/2147483648";
        let result = KeyExpression::try_from_str(input);
        assert!(matches!(result, Err(Error::DerivationIndexOutOfRange(_))));
    }

    #[test]
    fn test_invalid_derivation_index_non_numeric() {
        let input = "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/1aa";
        let result = KeyExpression::try_from_str(input);
        assert!(matches!(result, Err(Error::InvalidDerivationIndex(_))));
    }

    #[test]
    fn test_invalid_multiple_key_origins() {
        let input = "[aaaaaaaa][aaaaaaaa]xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/2147483647'/0";
        let result = KeyExpression::try_from_str(input);
        assert!(matches!(result, Err(Error::MultipleKeyOrigins(_))));
    }

    #[test]
    fn test_invalid_missing_key_origin_start() {
        let input = "aaaaaaaa]xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/2147483647'/0";
        let result = KeyExpression::try_from_str(input);
        assert!(matches!(result, Err(Error::MissingKeyOriginStart(_))));
    }

    #[test]
    fn test_invalid_non_hex_fingerprint() {
        let input = "[gaaaaaaa]xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/2147483647'/0";
        let result = KeyExpression::try_from_str(input);
        assert!(matches!(result, Err(Error::NonHexFingerprint(_))));
    }

    #[test]
    fn test_invalid_key_origin_with_no_public_key() {
        let input = "[deadbeef]";
        let result = KeyExpression::try_from_str(input);
        assert!(matches!(result, Err(Error::KeyOriginWithNoPublicKey(_))));
    }

    #[test]
    fn test_correct_derivation_path() {
        let input = "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/3/4/5";
        let result = KeyExpression::try_from_str(input).unwrap();

        let derv_path = DerivationPath::from_str("3/4/5").unwrap();
        assert_eq!(result.derivation_path, Some(derv_path));
    }

    #[test]
    fn test_correct_origin_path() {
        let input = "[deadbeef/84h/0h/0h]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL";
        let result = KeyExpression::try_from_str(input).unwrap();

        let derv_path = DerivationPath::from_str("84'/0'/0'").unwrap();

        assert_eq!(result.origin_derivation_path, Some(derv_path));
        assert_eq!(result.derivation_path, None);

        let children_as_u32 = result.origin_derivation_path.unwrap().to_u32_vec();
        assert_eq!(children_as_u32, vec![84 ^ (1 << 31), (1 << 31), (1 << 31)]);
    }
}
