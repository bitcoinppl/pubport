use std::str::FromStr as _;

use bitcoin::{
    base58,
    bip32::{Fingerprint, Xpub as Bip32Xpub},
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Invalid xpub: {0}")]
    InvalidXpub(#[from] bitcoin::bip32::Error),

    #[error("Invalid zpub: {0}")]
    InvalidZpub(#[from] base58::Error),

    #[error("Invalid ypub: {0}")]
    InvalidYpubDecode(base58::Error),

    #[error("Invalid ypub: {0}")]
    InvalidYpubLength(usize),

    #[error("Not an xpub, zpub or ypub, starts with: {0}")]
    NotXpub(String),

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

#[derive(Debug, Clone, PartialEq, Eq, derive_more::Display)]
pub enum OriginalFormat {
    Zpub,
    Ypub,
    Xpub,
}

impl Xpub {
    pub fn master_fingerprint(&self) -> Result<Fingerprint, Error> {
        xpub_to_fingerprint(&self.xpub)
    }
}

impl TryFrom<&str> for Xpub {
    type Error = Error;

    fn try_from(xpub: &str) -> Result<Self, Self::Error> {
        let (xpub, original_format) = match &xpub[..4] {
            "zpub" => (zpub_to_xpub(xpub)?, OriginalFormat::Zpub),
            "ypub" => (ypub_to_xpub(xpub)?, OriginalFormat::Ypub),
            "xpub" => (xpub.to_string(), OriginalFormat::Xpub),
            starting => return Err(Error::NotXpub(starting.to_string())),
        };

        Ok(Self {
            xpub: Bip32Xpub::from_str(&xpub)?,
            original_format,
        })
    }
}

pub fn zpub_to_xpub(zpub: &str) -> Result<String, Error> {
    let decoded = base58::decode_check(zpub)?;

    // Replace version bytes (first 4 bytes) with xpub version
    let mut xpub_bytes = [0u8; 78];
    xpub_bytes[0..4].copy_from_slice(&[0x04, 0x88, 0xB2, 0x1E]); // xpub version bytes
    xpub_bytes[4..].copy_from_slice(&decoded[4..]);

    // Re-encode as xpub
    let xpub = base58::encode_check(&xpub_bytes);

    Ok(xpub)
}

pub fn ypub_to_xpub(ypub: &str) -> Result<String, Error> {
    let decoded = base58::decode_check(ypub).map_err(Error::InvalidYpubDecode)?;

    if decoded.len() != 78 {
        return Err(Error::InvalidYpubLength(decoded.len()));
    }

    let mut xpub_bytes = [0u8; 78];
    xpub_bytes.copy_from_slice(&decoded);
    xpub_bytes[0..4].copy_from_slice(&[0x04, 0x88, 0xB2, 0x1E]); // xpub version bytes

    // Re-encode as xpub
    let xpub = base58::encode_check(&xpub_bytes);

    Ok(xpub)
}

pub fn xpub_to_fingerprint(xpub: &Bip32Xpub) -> Result<Fingerprint, Error> {
    let fingerprint = match xpub.parent_fingerprint.as_bytes() {
        [0, 0, 0, 0] => xpub.fingerprint(),
        _ => xpub.parent_fingerprint,
    };
    Ok(fingerprint)
}

pub fn xpub_str_to_fingerprint(xpub: &str) -> Result<Fingerprint, Error> {
    let xpub = Bip32Xpub::from_str(xpub)?;
    let fingerprint = xpub_to_fingerprint(&xpub)?;
    Ok(fingerprint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_zpub_to_xpub() {
        let zpub = "zpub6rNrPrFwgm4wMBSysetK5tpLBS2HYT8TDKQA6amxFHKJUnQq8rNtc4JDfGYPbvF9wJyagPpG1Faqnfe3BB8XzKon8LwW9KkMWyAQ4RQHzB1";
        let xpub_str = "xpub6CiKnWv7PPyyeb4kCwK4fidKqVjPfD9TP6MiXnzBVGZYNanNdY3mMvywcrdDc6wK82jyBSd95vsk26QujnJWPrSaPfYeyW7NyX37HHGtfQM";
        let xpub = Xpub::try_from(zpub);

        assert!(xpub.is_ok());
        let xpub = xpub.unwrap();

        assert_eq!(xpub.xpub.to_string(), xpub_str);
    }

    #[test]
    fn test_ypub_to_xpub() {
        let ypub = "ypub6X2aUb9NXbQM65mQy6oFECSB1CdSanwXHGTUcw7vt2LaAteuYtLoDQ6ao1fXDsenrZjgJKJyHvLypBBeo59cSKUivvwW8S6k7PVvQkVosxZ";
        let xpub_str = "xpub6CCKAvUTNursEnaJ8k1d27LfqEUzeAx2N9wFqYE3W1xh7nqgJEBEbLSSmohwDxzsSvcsYqiQqFzRvta65Njbe5o84bF5YXHFqfSH2Dkhonm";
        let xpub = Xpub::try_from(ypub);

        assert!(xpub.is_ok());
        let xpub = xpub.unwrap();

        assert_eq!(xpub.xpub.to_string().as_str(), xpub_str);
    }
}
