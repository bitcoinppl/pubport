use bitcoin::bip32::{DerivationPath, Fingerprint, Xpub};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyExpression {
    pub xpub: Xpub,
    pub master_fingerprint: Option<Fingerprint>,
    pub derivation_path: Option<DerivationPath>,
}

impl KeyExpression {
    pub fn try_from_str(input: &str) -> Self {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_compressed_pubkey() {
        let input = "0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600";
        assert!(matches!(
            KeyExpression::try_from_str(input),
            KeyExpression { xpub: _, .. }
        ));
    }

    #[test]
    fn test_valid_uncompressed_pubkey() {
        let input = "04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235";
        assert!(matches!(
            KeyExpression::try_from_str(input),
            KeyExpression { xpub: _, .. }
        ));
    }

    #[test]
    fn test_pubkey_with_key_origin() {
        let input =
            "[deadbeef/0h/0h/0h]0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600";
        assert!(matches!(
            KeyExpression::try_from_str(input),
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
        assert!(matches!(
            KeyExpression::try_from_str(input),
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
        assert!(matches!(
            KeyExpression::try_from_str(input),
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
        assert!(matches!(
            KeyExpression::try_from_str(input),
            KeyExpression { xpub: _, .. }
        ));
    }

    #[test]
    fn test_wif_compressed_private_key() {
        let input = "L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1";
        assert!(matches!(
            KeyExpression::try_from_str(input),
            KeyExpression { xpub: _, .. }
        ));
    }

    #[test]
    fn test_extended_public_key() {
        let input = "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL";
        assert!(matches!(
            KeyExpression::try_from_str(input),
            KeyExpression { xpub: _, .. }
        ));
    }

    #[test]
    fn test_extended_public_key_with_key_origin() {
        let input = "[deadbeef/0h/1h/2h]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL";
        assert!(matches!(
            KeyExpression::try_from_str(input),
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
        assert!(matches!(
            KeyExpression::try_from_str(input),
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
        assert!(matches!(
            KeyExpression::try_from_str(input),
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
        assert!(matches!(
            KeyExpression::try_from_str(input),
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
        assert!(matches!(
            KeyExpression::try_from_str(input),
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
        assert!(matches!(
            KeyExpression::try_from_str(input),
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
        assert!(matches!(
            KeyExpression::try_from_str(input),
            KeyExpression { xpub: _, .. }
        ));
    }

    #[test]
    fn test_extended_private_key_with_key_origin() {
        let input = "[deadbeef/0h/1h/2h]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc";
        assert!(matches!(
            KeyExpression::try_from_str(input),
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
        assert!(matches!(
            KeyExpression::try_from_str(input),
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
        assert!(matches!(
            KeyExpression::try_from_str(input),
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
        assert!(matches!(
            KeyExpression::try_from_str(input),
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
        assert!(matches!(
            KeyExpression::try_from_str(input),
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
        assert!(matches!(
            KeyExpression::try_from_str(input),
            KeyExpression {
                xpub: _,
                master_fingerprint: Some(_),
                derivation_path: Some(_),
            }
        ));
    }

    #[test]
    #[should_panic]
    fn test_invalid_children_indicator_in_key_origin() {
        let input = "[deadbeef/0h/0h/0h/*]0260b2003c386519fc9eadf2b5cf124dd8eea4c4e68d5e154050a9346ea98ce600";
        KeyExpression::try_from_str(input);
    }
}
