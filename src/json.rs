use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenericJson {
    pub chain: String,
    pub xfp: String,
    pub account: u32,
    pub xpub: String,
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
#[serde(rename_all = "snake_case")]
pub struct Keystore {
    pub derivation: String,
    pub xpub: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SingleSig {
    #[serde(default)]
    pub name: Option<Name>,
    #[serde(default)]
    pub xfp: Option<String>,
    pub deriv: String,
    pub xpub: String,
    pub desc: String,
    #[serde(default)]
    pub first: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Name {
    // BIP44
    P2pkh,

    // BIP49
    P2shP2wpkh,

    // BIP84
    P2wpkh,
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
}
