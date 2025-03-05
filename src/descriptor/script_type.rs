use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ScriptType {
    /// BIP44
    P2pkh,

    /// BIP49
    P2shP2wpkh,

    /// BIP84
    P2wpkh,
}

impl ScriptType {
    pub fn descriptor_derivation_path(&self) -> &'static str {
        match self {
            ScriptType::P2pkh => "44'/0'/0'/0",
            ScriptType::P2shP2wpkh => "49'/0'/0'/0",
            ScriptType::P2wpkh => "84'/0'/0'/0",
        }
    }

    pub fn wrap_with(&self, script: &str) -> String {
        match &self {
            ScriptType::P2pkh => format!("pkh({})", script),
            ScriptType::P2shP2wpkh => format!("sh(wpkh({}))", script),
            ScriptType::P2wpkh => format!("wpkh({})", script),
        }
    }
}
