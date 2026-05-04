use std::str::FromStr as _;

use bitcoin::{
    base58,
    bip32::{Fingerprint, Xpub as Bip32Xpub},
};

const EXTENDED_KEY_LENGTH: usize = 78;

const XPUB_VERSION: [u8; 4] = [0x04, 0x88, 0xb2, 0x1e];
const YPUB_VERSION: [u8; 4] = [0x04, 0x9d, 0x7c, 0xb2];
const ZPUB_VERSION: [u8; 4] = [0x04, 0xb2, 0x47, 0x46];
const TPUB_VERSION: [u8; 4] = [0x04, 0x35, 0x87, 0xcf];
const UPUB_VERSION: [u8; 4] = [0x04, 0x4a, 0x52, 0x62];
const VPUB_VERSION: [u8; 4] = [0x04, 0x5f, 0x1c, 0xf6];

const XPRV_VERSION: [u8; 4] = [0x04, 0x88, 0xad, 0xe4];
const YPRV_VERSION: [u8; 4] = [0x04, 0x9d, 0x78, 0x78];
const ZPRV_VERSION: [u8; 4] = [0x04, 0xb2, 0x43, 0x0c];
const TPRV_VERSION: [u8; 4] = [0x04, 0x35, 0x83, 0x94];
const UPRV_VERSION: [u8; 4] = [0x04, 0x4a, 0x4e, 0x28];
const VPRV_VERSION: [u8; 4] = [0x04, 0x5f, 0x18, 0xbc];

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Invalid xpub: {0}")]
    InvalidXpub(#[from] bitcoin::bip32::Error),

    #[error("Invalid extended public key: {0}")]
    InvalidBase58(#[from] base58::Error),

    #[error("Invalid extended public key length: {0}")]
    InvalidExtendedKeyLength(usize),

    #[error("Private extended keys are not supported: {0}")]
    UnsupportedPrivateKey(&'static str),

    #[error("Unsupported extended public key version: {0:02x?}")]
    UnsupportedVersion([u8; 4]),

    #[error("Too short, only {0} chars long")]
    TooShort(usize),

    #[error("Missing xpub")]
    MissingXpub,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Xpub {
    xpub: Bip32Xpub,
    original_format: OriginalFormat,
}

impl std::fmt::Display for Xpub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.xpub)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, derive_more::Display)]
pub enum OriginalFormat {
    Xpub,
    Ypub,
    Zpub,
    Tpub,
    Upub,
    Vpub,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SingleSigPurpose {
    Bip49,
    Bip84,
}

impl Xpub {
    pub fn into_bip32(self) -> Bip32Xpub {
        self.xpub
    }

    pub fn original_format(&self) -> OriginalFormat {
        self.original_format
    }

    pub fn single_sig_purpose(&self) -> Option<SingleSigPurpose> {
        match self.original_format {
            OriginalFormat::Ypub | OriginalFormat::Upub => Some(SingleSigPurpose::Bip49),
            OriginalFormat::Zpub | OriginalFormat::Vpub => Some(SingleSigPurpose::Bip84),
            OriginalFormat::Xpub | OriginalFormat::Tpub => None,
        }
    }

    pub fn master_fingerprint(&self) -> Option<Fingerprint> {
        let fingerprint = xpub_to_fingerprint(&self.xpub).ok()?;
        if fingerprint == Fingerprint::default() {
            return None;
        }

        Some(fingerprint)
    }

    pub fn fingerprint(&self) -> Fingerprint {
        self.xpub.fingerprint()
    }
}

impl TryFrom<&str> for Xpub {
    type Error = Error;

    fn try_from(xpub: &str) -> Result<Self, Self::Error> {
        if xpub.len() < 4 {
            return Err(Error::TooShort(xpub.len()));
        }

        let decoded = base58::decode_check(xpub)?;
        let (standard_xpub, original_format) = standardize_extended_public_key(decoded)?;

        Ok(Self {
            xpub: Bip32Xpub::from_str(&standard_xpub)?,
            original_format,
        })
    }
}

pub fn to_standard_extended_public_key(xpub: &str) -> Result<String, Error> {
    let decoded = base58::decode_check(xpub)?;
    let (standard_xpub, _) = standardize_extended_public_key(decoded)?;
    Ok(standard_xpub)
}

pub fn xpub_to_fingerprint(xpub: &Bip32Xpub) -> Result<Fingerprint, Error> {
    let fingerprint = match xpub.parent_fingerprint.as_bytes() {
        [0, 0, 0, 0] => xpub.fingerprint(),
        _ => xpub.parent_fingerprint,
    };
    Ok(fingerprint)
}

pub fn xpub_str_to_fingerprint(xpub: &str) -> Result<Fingerprint, Error> {
    let xpub = Xpub::try_from(xpub)?;
    let fingerprint = xpub_to_fingerprint(&xpub.xpub)?;
    Ok(fingerprint)
}

fn standardize_extended_public_key(
    mut decoded: Vec<u8>,
) -> Result<(String, OriginalFormat), Error> {
    if decoded.len() != EXTENDED_KEY_LENGTH {
        return Err(Error::InvalidExtendedKeyLength(decoded.len()));
    }

    let version = version_bytes(&decoded);
    let info = version_info(version)?;

    decoded[0..4].copy_from_slice(&info.standard_version);
    let standard_xpub = base58::encode_check(&decoded);
    Ok((standard_xpub, info.original_format))
}

fn version_bytes(decoded: &[u8]) -> [u8; 4] {
    decoded[0..4]
        .try_into()
        .expect("checked extended key length")
}

fn version_info(version: [u8; 4]) -> Result<VersionInfo, Error> {
    let info = match version {
        XPUB_VERSION => VersionInfo::new(OriginalFormat::Xpub, XPUB_VERSION),
        YPUB_VERSION => VersionInfo::new(OriginalFormat::Ypub, XPUB_VERSION),
        ZPUB_VERSION => VersionInfo::new(OriginalFormat::Zpub, XPUB_VERSION),
        TPUB_VERSION => VersionInfo::new(OriginalFormat::Tpub, TPUB_VERSION),
        UPUB_VERSION => VersionInfo::new(OriginalFormat::Upub, TPUB_VERSION),
        VPUB_VERSION => VersionInfo::new(OriginalFormat::Vpub, TPUB_VERSION),
        XPRV_VERSION => return Err(Error::UnsupportedPrivateKey("xprv")),
        YPRV_VERSION => return Err(Error::UnsupportedPrivateKey("yprv")),
        ZPRV_VERSION => return Err(Error::UnsupportedPrivateKey("zprv")),
        TPRV_VERSION => return Err(Error::UnsupportedPrivateKey("tprv")),
        UPRV_VERSION => return Err(Error::UnsupportedPrivateKey("uprv")),
        VPRV_VERSION => return Err(Error::UnsupportedPrivateKey("vprv")),
        version => return Err(Error::UnsupportedVersion(version)),
    };

    Ok(info)
}

struct VersionInfo {
    original_format: OriginalFormat,
    standard_version: [u8; 4],
}

impl VersionInfo {
    fn new(original_format: OriginalFormat, standard_version: [u8; 4]) -> Self {
        Self {
            original_format,
            standard_version,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    const BIP49_XPUB: &str = "xpub6C6nQwHaWbSrzs5tZ1q7m5R9cPK9eYpNMFesiXsYrgc1P8bvLLAet9JfHjYXKjToD8cBRswJXXbbFpXgwsswVPAZzKMa1jUp2kVkGVUaJa7";
    const BIP49_YPUB: &str = "ypub6Ww3ibxVfGzLrAH1PNcjyAWenMTbbAosGNB6VvmSEgytSER9azLDWCxoJwW7Ke7icmizBMXrzBx9979FfaHxHcrArf3zbeJJJUZPf663zsP";
    const BIP84_XPUB: &str = "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V";
    const BIP84_ZPUB: &str = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";

    #[test]
    fn test_zpub_to_xpub() {
        let xpub = Xpub::try_from(BIP84_ZPUB);

        assert!(xpub.is_ok());
        let xpub = xpub.unwrap();

        assert_eq!(xpub.xpub.to_string(), BIP84_XPUB);
        assert_eq!(xpub.original_format(), OriginalFormat::Zpub);
        assert_eq!(xpub.single_sig_purpose(), Some(SingleSigPurpose::Bip84));
    }

    #[test]
    fn test_ypub_to_xpub() {
        let xpub = Xpub::try_from(BIP49_YPUB);

        assert!(xpub.is_ok());
        let xpub = xpub.unwrap();

        assert_eq!(xpub.xpub.to_string().as_str(), BIP49_XPUB);
        assert_eq!(xpub.original_format(), OriginalFormat::Ypub);
        assert_eq!(xpub.single_sig_purpose(), Some(SingleSigPurpose::Bip49));
    }

    #[test]
    fn test_upub_to_tpub() {
        let upub = key_with_version(BIP49_YPUB, UPUB_VERSION);
        let tpub = key_with_version(BIP49_XPUB, TPUB_VERSION);

        let xpub = Xpub::try_from(upub.as_str()).expect("should convert upub to tpub");

        assert_eq!(xpub.xpub.to_string(), tpub);
        assert_eq!(xpub.original_format(), OriginalFormat::Upub);
        assert_eq!(xpub.single_sig_purpose(), Some(SingleSigPurpose::Bip49));
    }

    #[test]
    fn test_vpub_to_tpub() {
        let vpub = key_with_version(BIP84_ZPUB, VPUB_VERSION);
        let tpub = key_with_version(BIP84_XPUB, TPUB_VERSION);

        let xpub = Xpub::try_from(vpub.as_str()).expect("should convert vpub to tpub");

        assert_eq!(xpub.xpub.to_string(), tpub);
        assert_eq!(xpub.original_format(), OriginalFormat::Vpub);
        assert_eq!(xpub.single_sig_purpose(), Some(SingleSigPurpose::Bip84));
    }

    #[test]
    fn test_to_standard_extended_public_key() {
        let result =
            to_standard_extended_public_key(BIP84_ZPUB).expect("should convert zpub to xpub");
        assert_eq!(result, BIP84_XPUB);
    }

    #[test]
    fn test_invalid_slip132_key() {
        let invalid = "zpubINVALID";
        let result = to_standard_extended_public_key(invalid);
        assert!(result.is_err());
    }

    #[test]
    fn test_private_prefixes_are_not_supported() {
        for (version, prefix) in [
            (XPRV_VERSION, "xprv"),
            (YPRV_VERSION, "yprv"),
            (ZPRV_VERSION, "zprv"),
            (TPRV_VERSION, "tprv"),
            (UPRV_VERSION, "uprv"),
            (VPRV_VERSION, "vprv"),
        ] {
            let key = key_with_version(BIP49_XPUB, version);
            let result = Xpub::try_from(key.as_str());

            assert!(matches!(
                result,
                Err(Error::UnsupportedPrivateKey(actual)) if actual == prefix
            ));
        }
    }

    #[test]
    fn test_multisig_prefixes_are_not_supported() {
        for version in [
            [0x02, 0x95, 0xb4, 0x3f],
            [0x02, 0xaa, 0x7e, 0xd3],
            [0x02, 0x42, 0x89, 0xef],
            [0x02, 0x57, 0x54, 0x83],
        ] {
            let key = key_with_version(BIP49_XPUB, version);
            let result = Xpub::try_from(key.as_str());

            assert!(matches!(result, Err(Error::UnsupportedVersion(_))));
        }
    }

    fn key_with_version(key: &str, version: [u8; 4]) -> String {
        let mut decoded = base58::decode_check(key).expect("valid test vector");
        decoded[0..4].copy_from_slice(&version);
        base58::encode_check(&decoded)
    }
}
