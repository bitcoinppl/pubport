use bitcoin::base58;

pub fn zpub_to_xpub(zpub: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Decode zpub
    let decoded = base58::decode_check(zpub)?;

    // Replace version bytes (first 4 bytes) with xpub version
    let mut xpub_data = [0u8; 78];
    xpub_data[0..4].copy_from_slice(&[0x04, 0x88, 0xB2, 0x1E]); // xpub version bytes
    xpub_data[4..].copy_from_slice(&decoded[4..]);

    // Re-encode as xpub
    let xpub = base58::encode_check(&xpub_data);

    Ok(xpub)
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
}
