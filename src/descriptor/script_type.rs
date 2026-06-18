use bitcoin::bip32::{ChildNumber, DerivationPath};
use serde::{Deserialize, Serialize};

/// Supported single-sig descriptor script types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum ScriptType {
    /// BIP44 P2PKH, usually `44h/coin_typeh/0h`
    P2pkh,

    /// BIP49 nested SegWit, usually `49h/coin_typeh/0h`
    P2shP2wpkh,

    /// BIP84 native SegWit, usually `84h/coin_typeh/0h`
    P2wpkh,

    /// BIP86 Taproot, usually `86h/coin_typeh/0h`
    P2tr,
}

const HARDENED_FLAG: u32 = 1 << 31;

const HARDENED_44: u32 = 44 ^ HARDENED_FLAG;
const HARDENED_49: u32 = 49 ^ HARDENED_FLAG;
const HARDENED_84: u32 = 84 ^ HARDENED_FLAG;
const HARDENED_86: u32 = 86 ^ HARDENED_FLAG;

/// Errors returned while inferring or building script-type paths
#[derive(Debug, Clone, Serialize, Deserialize, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// The path does not match a supported account path shape
    #[error("Invalid path: {0:?}")]
    InvalidPath(Vec<u32>),

    /// The account path contains a non-hardened component
    #[error("Path is not hardened")]
    NotHardened,

    /// The path component cannot be represented as a child number
    #[error("Invalid child number: {0}")]
    InvalidChildNumber(u32),
}

type Result<T, E = Error> = std::result::Result<T, E>;

impl ScriptType {
    /// Try to infer the script type from an account derivation path
    ///
    /// Only BIP44, BIP49, BIP84, and BIP86 account paths with hardened
    /// purpose, coin type, and account components are supported
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

    /// Return the BIP purpose number for this script type
    pub fn purpose(&self) -> u32 {
        match self {
            ScriptType::P2pkh => 44,
            ScriptType::P2shP2wpkh => 49,
            ScriptType::P2wpkh => 84,
            ScriptType::P2tr => 86,
        }
    }

    /// Build the account derivation path for a coin type
    pub fn account_derivation_path_for_coin_type(&self, coin_type: u32) -> Result<DerivationPath> {
        let path = vec![
            hardened_child_number(self.purpose())?,
            hardened_child_number(coin_type)?,
            hardened_child_number(0)?,
        ];

        Ok(DerivationPath::from(path))
    }

    /// Return the default mainnet account derivation path string
    pub fn descriptor_derivation_path(&self) -> &'static str {
        match self {
            Self::P2pkh => "44'/0'/0'",
            Self::P2shP2wpkh => "49'/0'/0'",
            Self::P2wpkh => "84'/0'/0'",
            Self::P2tr => "86'/0'/0'",
        }
    }

    /// Wrap a descriptor key expression in this script type's descriptor function
    pub fn wrap_with(&self, script: &str) -> String {
        match self {
            Self::P2pkh => format!("pkh({script})"),
            Self::P2shP2wpkh => format!("sh(wpkh({script}))"),
            Self::P2wpkh => format!("wpkh({script})"),
            Self::P2tr => format!("tr({script})"),
        }
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
