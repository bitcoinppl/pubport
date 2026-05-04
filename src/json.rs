use crate::{
    descriptor::{Descriptors, ScriptType},
    formats::Json,
    xpub::{self, SingleSigPurpose},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenericJson {
    #[serde(default)]
    pub chain: Option<String>,
    #[serde(default)]
    pub xfp: Option<String>,
    #[serde(default)]
    pub xpub: Option<String>,
    pub bip44: Option<SingleSig>,
    pub bip49: Option<SingleSig>,
    pub bip84: Option<SingleSig>,
    pub bip86: Option<SingleSig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct WasabiJson {
    pub cold_card_firmware_version: String,
    pub master_fingerprint: String,
    pub ext_pub_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ElectrumJson {
    pub seed_version: u32,
    pub use_encryption: bool,
    pub wallet_type: String,
    pub keystore: Keystore,
}

// electrum
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Keystore {
    pub derivation: String,
    pub xpub: String,
    #[serde(default)]
    pub ckcc_xfp: Option<u32>,
    #[serde(default)]
    pub ckcc_xpub: Option<String>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SingleSig {
    #[serde(default)]
    pub name: Option<ScriptType>,
    #[serde(default)]
    pub xfp: Option<String>,
    #[serde(default)]
    pub deriv: Option<String>,
    #[serde(default)]
    pub xpub: Option<String>,
    #[serde(default)]
    #[serde(rename = "desc")]
    pub descriptor: Option<String>,
    #[serde(default)]
    pub first: Option<String>,
}

impl Json {
    pub fn try_from_child_xpub_str(string: &str) -> Result<Self, crate::Error> {
        let xpub = xpub::Xpub::try_from(string)?;

        Self::try_from_parsed_child_xpub(xpub)
    }

    pub fn try_from_child_xpub(xpub: bitcoin::bip32::Xpub) -> Result<Self, crate::Error> {
        let bip44 = Descriptors::try_from_child_xpub(xpub, ScriptType::P2pkh)?;
        let bip49 = Descriptors::try_from_child_xpub(xpub, ScriptType::P2shP2wpkh)?;
        let bip84 = Descriptors::try_from_child_xpub(xpub, ScriptType::P2wpkh)?;
        let bip86 = Descriptors::try_from_child_xpub(xpub, ScriptType::P2tr)?;

        Ok(Self {
            bip44: Some(bip44),
            bip49: Some(bip49),
            bip84: Some(bip84),
            bip86: Some(bip86),
        })
    }

    fn try_from_parsed_child_xpub(xpub: xpub::Xpub) -> Result<Self, crate::Error> {
        let single_sig_purpose = xpub.single_sig_purpose();
        let xpub = xpub.into_bip32();

        match single_sig_purpose {
            Some(SingleSigPurpose::Bip49) => Ok(Self {
                bip44: None,
                bip49: Some(Descriptors::try_from_child_xpub(
                    xpub,
                    ScriptType::P2shP2wpkh,
                )?),
                bip84: None,
                bip86: None,
            }),
            Some(SingleSigPurpose::Bip84) => Ok(Self {
                bip44: None,
                bip49: None,
                bip84: Some(Descriptors::try_from_child_xpub(xpub, ScriptType::P2wpkh)?),
                bip86: None,
            }),
            None => Self::try_from_child_xpub(xpub),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_wasabi() {
        let json = std::fs::read_to_string("test/data/new-wasabi.json").unwrap();
        let wasabi = serde_json::from_str::<WasabiJson>(&json);
        assert!(wasabi.is_ok());
    }

    #[test]
    fn test_deserialize_electrum() {
        let json = std::fs::read_to_string("test/data/new-electrum.json").unwrap();
        let electrum = serde_json::from_str::<ElectrumJson>(&json);
        assert!(electrum.is_ok());
    }

    #[test]
    fn test_deserialize_generic() {
        let json = std::fs::read_to_string("test/data/coldcard-export.json").unwrap();
        let generic = serde_json::from_str::<GenericJson>(&json);
        assert!(generic.is_ok());
    }

    #[test]
    fn test_single_sig_defaults() {
        let json = r#"{
            "name": "p2wpkh",
            "xfp": "8DFECFC3",
            "deriv": "m/84h/0h/0h",
            "xpub": "xpub6CiKnWv7PPyyeb4kCwK4fidKqVjPfD9TP6MiXnzBVGZYNanNdY3mMvywcrdDc6wK82jyBSd95vsk26QujnJWPrSaPfYeyW7NyX37HHGtfQM",
            "_pub": "zpub6rNrPrFwgm4wMBSysetK5tpLBS2HYT8TDKQA6amxFHKJUnQq8rNtc4JDfGYPbvF9wJyagPpG1Faqnfe3BB8XzKon8LwW9KkMWyAQ4RQHzB1",
            "first": "bc1q0g0vn4yqyk0zjwxw0zv5pltyyczty004zc9g7r"
        }"#;

        let single_sig = serde_json::from_str::<SingleSig>(json);
        assert!(single_sig.is_ok());
    }

    /// Test Passport wallet export JSON format (Foundation Devices)
    ///
    /// This JSON format is used by Passport hardware wallet when exporting
    /// wallet data via ur:bytes QR codes.
    ///
    /// Uses the "abandon" seed test vector:
    /// - BIP39: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    /// - Master fingerprint: 73c5da0a
    /// - BIP84 first address: bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu
    #[test]
    fn test_deserialize_passport_format() {
        let passport_json = r#"{
  "xfp": "73c5da0a",
  "bip84": {
    "deriv": "m/84'/0'/0'",
    "xpub": "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs",
    "first": "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
  }
}"#;

        let generic = serde_json::from_str::<GenericJson>(passport_json);
        assert!(
            generic.is_ok(),
            "Failed to parse Passport JSON: {:?}",
            generic.err()
        );

        let generic = generic.unwrap();

        // verify master fingerprint
        assert_eq!(generic.xfp, Some("73c5da0a".to_string()));

        // verify bip84 data
        let bip84 = generic.bip84.expect("Should have bip84 data");
        assert_eq!(bip84.deriv, Some("m/84'/0'/0'".to_string()));
        assert!(bip84.xpub.as_ref().unwrap().starts_with("zpub"));
        assert_eq!(
            bip84.first,
            Some("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu".to_string())
        );
    }

    /// Test GenericJson with only bip84 (single path)
    #[test]
    fn test_deserialize_generic_single_path() {
        let json = r#"{
  "xfp": "73c5da0a",
  "bip84": {
    "deriv": "m/84'/0'/0'",
    "xpub": "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs",
    "first": "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
  }
}"#;

        let generic = serde_json::from_str::<GenericJson>(json).unwrap();

        assert_eq!(generic.xfp, Some("73c5da0a".to_string()));
        assert!(generic.bip84.is_some());
        assert!(generic.bip44.is_none());
        assert!(generic.bip49.is_none());
        assert!(generic.bip86.is_none());
    }

    /// Test GenericJson with bip84 and bip86 (taproot)
    #[test]
    fn test_deserialize_generic_with_taproot() {
        let json = r#"{
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

        let generic = serde_json::from_str::<GenericJson>(json).unwrap();

        assert_eq!(generic.xfp, Some("73c5da0a".to_string()));
        assert!(generic.bip84.is_some());
        assert!(generic.bip86.is_some());
        assert!(generic.bip44.is_none());
        assert!(generic.bip49.is_none());
    }

    /// Test Passport export with multiple BIP paths including taproot
    #[test]
    fn test_deserialize_passport_full_export() {
        let passport_json = r#"{
  "chain": "BTC",
  "xfp": "73c5da0a",
  "account": 0,
  "bip44": {
    "deriv": "m/44'/0'/0'",
    "xpub": "xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj",
    "first": "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"
  },
  "bip49": {
    "deriv": "m/49'/0'/0'",
    "xpub": "ypub6Ww3ibxVfGzLtJR4F9SRBicspAfvmvw54yern9Q6qZWFC9T6FYA34K57La5Sgs8pXuyvpDfEHX5KNZRiZRukUWaVPyL4NxA69sEAqdoV8ve",
    "first": "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf"
  },
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

        let generic = serde_json::from_str::<GenericJson>(passport_json);
        assert!(
            generic.is_ok(),
            "Failed to parse full Passport export: {:?}",
            generic.err()
        );

        let generic = generic.unwrap();

        // verify chain
        assert_eq!(generic.chain, Some("BTC".to_string()));

        // verify all four BIP paths are present
        assert!(generic.bip44.is_some(), "Should have bip44");
        assert!(generic.bip49.is_some(), "Should have bip49");
        assert!(generic.bip84.is_some(), "Should have bip84");
        assert!(generic.bip86.is_some(), "Should have bip86");

        // verify xpub prefixes match expected formats
        assert!(generic
            .bip44
            .as_ref()
            .unwrap()
            .xpub
            .as_ref()
            .unwrap()
            .starts_with("xpub"));
        assert!(generic
            .bip49
            .as_ref()
            .unwrap()
            .xpub
            .as_ref()
            .unwrap()
            .starts_with("ypub"));
        assert!(generic
            .bip84
            .as_ref()
            .unwrap()
            .xpub
            .as_ref()
            .unwrap()
            .starts_with("zpub"));
        assert!(generic
            .bip86
            .as_ref()
            .unwrap()
            .xpub
            .as_ref()
            .unwrap()
            .starts_with("xpub"));

        // verify taproot address format (bc1p prefix)
        assert!(generic
            .bip86
            .as_ref()
            .unwrap()
            .first
            .as_ref()
            .unwrap()
            .starts_with("bc1p"));
    }
}
