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
            [HARDENED_44, _, _] => hardened_or_error(&path[1..], ScriptType::P2pkh),
            [HARDENED_49, _, _] => hardened_or_error(&path[1..], ScriptType::P2shP2wpkh),
            [HARDENED_84, _, _] => hardened_or_error(&path[1..], ScriptType::P2wpkh),
            [44, _, _] => Err(Error::NotHardened),
            [49, _, _] => Err(Error::NotHardened),
            [84, _, _] => Err(Error::NotHardened),
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

fn hardened_or_error(path: &[u32], script_type: ScriptType) -> Result<ScriptType, Error> {
    if is_hardened(path) {
        Ok(script_type)
    } else {
        Err(Error::NotHardened)
    }
}

fn is_hardened(path: &[u32]) -> bool {
    path.iter().all(|&p| p >= HARDENED_FLAG)
}
