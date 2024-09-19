use std::str::FromStr as _;

use bitcoin::{
    base58,
    bip32::{Fingerprint, Xpub},
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

pub fn xpub_to_fingerprint(xpub: &str) -> Result<Fingerprint, Error> {
    let extended_pubkey = Xpub::from_str(xpub).map_err(Error::InvalidXpub)?;
    let fingerprint = match extended_pubkey.parent_fingerprint.as_bytes() {
        [0, 0, 0, 0] => extended_pubkey.fingerprint(),
        _ => extended_pubkey.parent_fingerprint,
    };

    Ok(fingerprint)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zpub_to_xpub() {
        let zpub = "zpub6rNrPrFwgm4wMBSysetK5tpLBS2HYT8TDKQA6amxFHKJUnQq8rNtc4JDfGYPbvF9wJyagPpG1Faqnfe3BB8XzKon8LwW9KkMWyAQ4RQHzB1";
        let xpub = "xpub6CiKnWv7PPyyeb4kCwK4fidKqVjPfD9TP6MiXnzBVGZYNanNdY3mMvywcrdDc6wK82jyBSd95vsk26QujnJWPrSaPfYeyW7NyX37HHGtfQM";

        assert_eq!(zpub_to_xpub(zpub).unwrap(), xpub);
    }

    #[test]
    fn test_ypub_to_xpub() {
        let ypub = "ypub6X2aUb9NXbQM65mQy6oFECSB1CdSanwXHGTUcw7vt2LaAteuYtLoDQ6ao1fXDsenrZjgJKJyHvLypBBeo59cSKUivvwW8S6k7PVvQkVosxZ";
        let xpub = "xpub6CCKAvUTNursEnaJ8k1d27LfqEUzeAx2N9wFqYE3W1xh7nqgJEBEbLSSmohwDxzsSvcsYqiQqFzRvta65Njbe5o84bF5YXHFqfSH2Dkhonm";

        assert_eq!(ypub_to_xpub(ypub).unwrap(), xpub);
    }
}
