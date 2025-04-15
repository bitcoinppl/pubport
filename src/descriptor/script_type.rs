use bitcoin::bip32::DerivationPath;
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

const HARDENED_FLAG: u32 = 1 << 31;

const HARDENED_0: u32 = HARDENED_FLAG;
const HARDENED_44: u32 = 44 ^ HARDENED_FLAG;
const HARDENED_49: u32 = 49 ^ HARDENED_FLAG;
const HARDENED_84: u32 = 84 ^ HARDENED_FLAG;

#[derive(Debug, Clone, Serialize, Deserialize, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("Invalid path: {0:?}")]
    InvalidPath(Vec<u32>),

    #[error("Path is not hardened")]
    NotHardened,
}

type Result<T, E = Error> = std::result::Result<T, E>;

impl ScriptType {
    /// Try to parse a derivation path into a ScriptType
    /// Will only work for hardened paths
    pub fn try_from_derivation_path(path: &DerivationPath) -> Result<Self> {
        let path = path.to_u32_vec();

        match path.as_slice() {
            [HARDENED_44, HARDENED_0, HARDENED_0] => Ok(ScriptType::P2pkh),
            [HARDENED_49, HARDENED_0, HARDENED_0] => Ok(ScriptType::P2shP2wpkh),
            [HARDENED_84, HARDENED_0, HARDENED_0] => Ok(ScriptType::P2wpkh),
            [44, 0, 0] => Err(Error::NotHardened),
            [49, 0, 0] => Err(Error::NotHardened),
            [84, 0, 0] => Err(Error::NotHardened),
            _ => Err(Error::InvalidPath(path.to_vec())),
        }
    }

    pub fn descriptor_derivation_path(&self) -> &'static str {
        match self {
            ScriptType::P2pkh => "44'/0'/0'",
            ScriptType::P2shP2wpkh => "49'/0'",
            ScriptType::P2wpkh => "84'/0'/0'",
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
