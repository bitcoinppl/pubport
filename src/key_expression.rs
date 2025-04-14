use bitcoin::bip32::{DerivationPath, Fingerprint, Xpub};
use thiserror::Error;

/// Errors that can occur when parsing a key expression
#[derive(Debug, Error)]
pub enum KeyExpressionError {
    #[error("Invalid key origin format")]
    InvalidKeyOrigin,
    
    #[error("Children indicator not allowed in key origin: {0}")]
    ChildrenIndicatorInKeyOrigin(String),
    
    #[error("Trailing slash in key origin: {0}")]
    TrailingSlashInKeyOrigin(String),
    
    #[error("Invalid fingerprint length (must be 8 characters): {0}")]
    InvalidFingerprintLength(String),
    
    #[error("Invalid hardened indicator, must be 'h' or \"'\": {0}")]
    InvalidHardenedIndicator(String),
    
    #[error("Negative indices are not allowed: {0}")]
    NegativeIndices(String),
    
    #[error("WIF private keys cannot have derivation paths: {0}")]
    PrivateKeyWithDerivation(String),
    
    #[error("Derivation index out of range: {0}")]
    DerivationIndexOutOfRange(String),
    
    #[error("Invalid derivation index (must be a number): {0}")]
    InvalidDerivationIndex(String),
    
    #[error("Multiple key origins are not allowed: {0}")]
    MultipleKeyOrigins(String),
    
    #[error("Missing key origin start bracket: {0}")]
    MissingKeyOriginStart(String),
    
    #[error("Non-hexadecimal fingerprint: {0}")]
    NonHexFingerprint(String),
    
    #[error("Key origin with no public key: {0}")]
    KeyOriginWithNoPublicKey(String),
    
    #[error("Failed to parse Xpub: {0}")]
    XpubParseError(#[from] bitcoin::bip32::Error),
    
    #[error("Failed to parse fingerprint: {0}")]
    FingerprintParseError(String),
    
    #[error("Failed to parse derivation path: {0}")]
    DerivationPathParseError(String),
    
    #[error("Unexpected error: {0}")]
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyExpression {
    pub xpub: Xpub,
    pub master_fingerprint: Option<Fingerprint>,
    pub derivation_path: Option<DerivationPath>,
}

impl KeyExpression {
    pub fn try_from_str(input: &str) -> Result<Self, KeyExpressionError> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_compressed_pubkey() {
        let input = "0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600";
        let result = KeyExpression::try_from_str(input).unwrap();
        assert!(matches!(result, KeyExpression { xpub: _, .. }));
    }

    #[test]
    fn test_valid_uncompressed_pubkey() {
        let input = "04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235";
        let result = KeyExpression::try_from_str(input).unwrap();
        assert!(matches!(result, KeyExpression { xpub: _, .. }));
    }

    #[test]
    fn test_pubkey_with_key_origin() {
        let input =
            "[deadbeef/0h/0h/0h]0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600";
        let result = KeyExpression::try_from_str(input).unwrap();
        assert!(matches!(
            result,
            KeyExpression {
                xpub: _,
                master_fingerprint: Some(_),
                derivation_path: Some(_),
            }
        ));
    }

    #[test]
    fn test_pubkey_with_key_origin_apostrophe_hardened() {
        let input =
            "[deadbeef/0'/0'/0']0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600";
        let result = KeyExpression::try_from_str(input).unwrap();
        assert!(matches!(
            result,
            KeyExpression {
                xpub: _,
                master_fingerprint: Some(_),
                derivation_path: Some(_),
            }
        ));
    }

    #[test]
    fn test_pubkey_with_key_origin_mixed_hardened() {
        let input =
            "[deadbeef/0'/0h/0']0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600";
        let result = KeyExpression::try_from_str(input).unwrap();
        assert!(matches!(
            result,
            KeyExpression {
                xpub: _,
                master_fingerprint: Some(_),
                derivation_path: Some(_),
            }
        ));
    }

    #[test]
    fn test_wif_uncompressed_private_key() {
        let input = "5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss";
        let result = KeyExpression::try_from_str(input).unwrap();
        assert!(matches!(result, KeyExpression { xpub: _, .. }));
    }

    #[test]
    fn test_wif_compressed_private_key() {
        let input = "L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1";
        let result = KeyExpression::try_from_str(input).unwrap();
        assert!(matches!(result, KeyExpression { xpub: _, .. }));
    }

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
                derivation_path: Some(_),
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
                derivation_path: Some(_),
            }
        ));
    }

    #[test]
    fn test_extended_private_key() {
        let input = "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc";
        let result = KeyExpression::try_from_str(input).unwrap();
        assert!(matches!(result, KeyExpression { xpub: _, .. }));
    }

    #[test]
    fn test_extended_private_key_with_key_origin() {
        let input = "[deadbeef/0h/1h/2h]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc";
        let result = KeyExpression::try_from_str(input).unwrap();
        assert!(matches!(
            result,
            KeyExpression {
                xpub: _,
                master_fingerprint: Some(_),
                derivation_path: Some(_),
            }
        ));
    }

    #[test]
    fn test_extended_private_key_with_derivation() {
        let input = "[deadbeef/0h/1h/2h]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc/3/4/5";
        let result = KeyExpression::try_from_str(input).unwrap();
        assert!(matches!(
            result,
            KeyExpression {
                xpub: _,
                master_fingerprint: Some(_),
                derivation_path: Some(_),
            }
        ));
    }

    #[test]
    fn test_extended_private_key_with_derivation_and_children() {
        let input = "[deadbeef/0h/1h/2h]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc/3/4/5/*";
        let result = KeyExpression::try_from_str(input).unwrap();
        assert!(matches!(
            result,
            KeyExpression {
                xpub: _,
                master_fingerprint: Some(_),
                derivation_path: Some(_),
            }
        ));
    }

    #[test]
    fn test_extended_private_key_with_hardened_derivation_and_unhardened_children() {
        let input = "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc/3h/4h/5h/*";
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
    fn test_extended_private_key_with_hardened_derivation_and_hardened_children() {
        let input = "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc/3h/4h/5h/*h";
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
    fn test_extended_private_key_with_key_origin_hardened_derivation_and_children() {
        let input = "[deadbeef/0h/1h/2]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc/3h/4h/5h/*h";
        let result = KeyExpression::try_from_str(input).unwrap();
        assert!(matches!(
            result,
            KeyExpression {
                xpub: _,
                master_fingerprint: Some(_),
                derivation_path: Some(_),
            }
        ));
    }

    #[test]
    fn test_invalid_children_indicator_in_key_origin() {
        let input = "[deadbeef/0h/0h/0h/*]0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600";
        let result = KeyExpression::try_from_str(input);
        assert!(matches!(result, Err(KeyExpressionError::ChildrenIndicatorInKeyOrigin(_))));
    }

    #[test]
    fn test_invalid_trailing_slash_in_key_origin() {
        let input = "[deadbeef/0h/0h/0h/]0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600";
        let result = KeyExpression::try_from_str(input);
        assert!(matches!(result, Err(KeyExpressionError::TrailingSlashInKeyOrigin(_))));
    }

    #[test]
    fn test_invalid_too_short_fingerprint() {
        let input = "[deadbef/0h/0h/0h]0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600";
        let result = KeyExpression::try_from_str(input);
        assert!(matches!(result, Err(KeyExpressionError::InvalidFingerprintLength(_))));
    }

    #[test]
    fn test_invalid_too_long_fingerprint() {
        let input = "[deadbeeef/0h/0h/0h]0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600";
        let result = KeyExpression::try_from_str(input);
        assert!(matches!(result, Err(KeyExpressionError::InvalidFingerprintLength(_))));
    }

    #[test]
    fn test_invalid_hardened_indicators_f() {
        let input = "[deadbeef/0f/0f/0f]0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600";
        let result = KeyExpression::try_from_str(input);
        assert!(matches!(result, Err(KeyExpressionError::InvalidHardenedIndicator(_))));
    }

    #[test]
    fn test_invalid_hardened_indicators_capital_h() {
        let input = "[deadbeef/0H/0H/0H]0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600";
        let result = KeyExpression::try_from_str(input);
        assert!(matches!(result, Err(KeyExpressionError::InvalidHardenedIndicator(_))));
    }

    #[test]
    fn test_invalid_negative_indices() {
        let input = "[deadbeef/-0/-0/-0]0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600";
        let result = KeyExpression::try_from_str(input);
        assert!(matches!(result, Err(KeyExpressionError::NegativeIndices(_))));
    }

    #[test]
    fn test_invalid_private_key_with_derivation() {
        let input = "L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1/0";
        let result = KeyExpression::try_from_str(input);
        assert!(matches!(result, Err(KeyExpressionError::PrivateKeyWithDerivation(_))));
    }

    #[test]
    fn test_invalid_private_key_with_derivation_children() {
        let input = "L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1/*";
        let result = KeyExpression::try_from_str(input);
        assert!(matches!(result, Err(KeyExpressionError::PrivateKeyWithDerivation(_))));
    }

    #[test]
    fn test_invalid_derivation_index_out_of_range() {
        let input = "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/2147483648";
        let result = KeyExpression::try_from_str(input);
        assert!(matches!(result, Err(KeyExpressionError::DerivationIndexOutOfRange(_))));
    }

    #[test]
    fn test_invalid_derivation_index_non_numeric() {
        let input = "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/1aa";
        let result = KeyExpression::try_from_str(input);
        assert!(matches!(result, Err(KeyExpressionError::InvalidDerivationIndex(_))));
    }

    #[test]
    fn test_invalid_multiple_key_origins() {
        let input = "[aaaaaaaa][aaaaaaaa]xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/2147483647'/0";
        let result = KeyExpression::try_from_str(input);
        assert!(matches!(result, Err(KeyExpressionError::MultipleKeyOrigins(_))));
    }

    #[test]
    fn test_invalid_missing_key_origin_start() {
        let input = "aaaaaaaa]xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/2147483647'/0";
        let result = KeyExpression::try_from_str(input);
        assert!(matches!(result, Err(KeyExpressionError::MissingKeyOriginStart(_))));
    }

    #[test]
    fn test_invalid_non_hex_fingerprint() {
        let input = "[gaaaaaaa]xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/2147483647'/0";
        let result = KeyExpression::try_from_str(input);
        assert!(matches!(result, Err(KeyExpressionError::NonHexFingerprint(_))));
    }

    #[test]
    fn test_invalid_key_origin_with_no_public_key() {
        let input = "[deadbeef]";
        let result = KeyExpression::try_from_str(input);
        assert!(matches!(result, Err(KeyExpressionError::KeyOriginWithNoPublicKey(_))));
    }
}
