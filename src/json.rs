use std::str::FromStr as _;

use crate::{
    descriptor::{Descriptors, ScriptType},
    formats::Json,
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
    pub fn try_from_child_xpub(string: &str) -> Result<Self, crate::Error> {
        let xpub =
            bitcoin::bip32::Xpub::from_str(string).map_err(crate::xpub::Error::InvalidXpub)?;

        let bip44 = Descriptors::try_from_child_xpub(xpub, ScriptType::P2pkh)?;
        let bip49 = Descriptors::try_from_child_xpub(xpub, ScriptType::P2shP2wpkh)?;
        let bip84 = Descriptors::try_from_child_xpub(xpub, ScriptType::P2wpkh)?;

        Ok(Self {
            bip44: Some(bip44),
            bip49: Some(bip49),
            bip84: Some(bip84),
        })
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
}
