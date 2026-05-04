use bitcoin::bip32::{ChildNumber, DerivationPath};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum ScriptType {
    /// BIP44 [44h/0h/0h]
    P2pkh,

    /// BIP49 [49h/0h/0h]
    P2shP2wpkh,

    /// BIP84 [84h/0h/0h]
    P2wpkh,

    /// BIP86 [86h/0h/0h]
    P2tr,
}

const HARDENED_FLAG: u32 = 1 << 31;

const HARDENED_44: u32 = 44 ^ HARDENED_FLAG;
const HARDENED_49: u32 = 49 ^ HARDENED_FLAG;
const HARDENED_84: u32 = 84 ^ HARDENED_FLAG;
const HARDENED_86: u32 = 86 ^ HARDENED_FLAG;

#[derive(Debug, Clone, Serialize, Deserialize, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("Invalid path: {0:?}")]
    InvalidPath(Vec<u32>),

    #[error("Path is not hardened")]
    NotHardened,

    #[error("Invalid child number: {0}")]
    InvalidChildNumber(u32),
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
            [HARDENED_86, _, _] => hardened_or_error(&path[1..], ScriptType::P2tr),
            [44, _, _] => Err(Error::NotHardened),
            [49, _, _] => Err(Error::NotHardened),
            [84, _, _] => Err(Error::NotHardened),
            [86, _, _] => Err(Error::NotHardened),
            _ => Err(Error::InvalidPath(path.to_vec())),
        }
    }

    pub fn purpose(&self) -> u32 {
        match self {
            ScriptType::P2pkh => 44,
            ScriptType::P2shP2wpkh => 49,
            ScriptType::P2wpkh => 84,
            ScriptType::P2tr => 86,
        }
    }

    pub fn account_derivation_path_for_coin_type(&self, coin_type: u32) -> Result<DerivationPath> {
        let path = vec![
            hardened_child_number(self.purpose())?,
            hardened_child_number(coin_type)?,
            hardened_child_number(0)?,
        ];

        Ok(DerivationPath::from(path))
    }
}

fn hardened_child_number(index: u32) -> Result<ChildNumber, Error> {
    ChildNumber::from_hardened_idx(index).map_err(|_| Error::InvalidChildNumber(index))
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
