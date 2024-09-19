use miniscript::{descriptor::DescriptorKeyParseError, Descriptor, DescriptorPublicKey};

use crate::json::{Name, SingleSig, WasabiJson};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Invalid descriptor: {0:?}")]
    InvalidDescriptor(#[from] DescriptorKeyParseError),

    #[error("Single descriptor line did not contain both external and internal keys")]
    MissingKeys,

    #[error("Too many keys in descriptor, only supports 1 external and 1 internal key")]
    TooManyKeys,

    #[error("Unable to parse descriptor: {0}")]
    InvalidDescriptorParse(#[from] miniscript::Error),

    #[error("Missing descriptor")]
    MissingDescriptor,

    #[error("Missing xpub")]
    MissingXpub,

    #[error("Missing derivation path")]
    MissingDerivationPath,

    #[error("Missing script type")]
    MissingScriptType,

    #[error("Missing fingerprint (xfp)")]
    MissingFingerprint,
}

#[derive(Debug, Clone)]
pub struct Descriptors {
    pub external: Descriptor<DescriptorPublicKey>,
    pub internal: Descriptor<DescriptorPublicKey>,
}

impl Descriptors {
    pub fn try_from_line(line: &str) -> Result<Self, Error> {
        let secp = &secp256k1::Secp256k1::signing_only();
        let (descriptor, _keymap) =
            Descriptor::<DescriptorPublicKey>::parse_descriptor(secp, line)?;

        if !descriptor.is_multipath() {
            return Err(Error::MissingKeys);
        }

        let multi = descriptor.into_single_descriptors()?;

        match multi.len() {
            2 => (),
            1 => return Err(Error::MissingKeys),
            _ => return Err(Error::TooManyKeys),
        };

        Ok(Self {
            external: multi[0].clone(),
            internal: multi[1].clone(),
        })
    }

    pub fn try_from_single_sig(
        single_sig: SingleSig,
        fingerprint: Option<&str>,
    ) -> Result<Self, Error> {
        if let Some(desc) = &single_sig.descriptor {
            let desc = Descriptors::try_from_line(desc)?;
            return Ok(desc);
        }

        let script_type = single_sig.name.ok_or(Error::MissingScriptType)?;
        let xpub = single_sig.xpub.ok_or(Error::MissingXpub)?;

        let fingerprint = fingerprint
            .ok_or(Error::MissingFingerprint)?
            .to_ascii_lowercase();

        let derivation_path = single_sig
            .deriv
            .ok_or(Error::MissingDerivationPath)?
            .replace("m/", "");

        let script = format!("[{fingerprint}/{derivation_path}]{xpub}/<0;1>/*");
        let desc = wrap_in_script_type(script_type, &script);

        let desc = Descriptors::try_from_line(&desc)?;
        Ok(desc)
    }
}

impl TryFrom<WasabiJson> for Descriptors {
    type Error = Error;

    fn try_from(json: WasabiJson) -> Result<Self, Self::Error> {
        let fingerprint = json.master_fingerprint.to_ascii_lowercase();
        let derivation_path = "84h/0h/0h";
        let xpub = json.ext_pub_key;

        let script = format!("[{fingerprint}/{derivation_path}]{xpub}/<0;1>/*");
        let desc = wrap_in_script_type(Name::P2wpkh, &script);

        println!("wasabi desc: {}", desc);

        let desc = Descriptors::try_from_line(&desc)?;
        Ok(desc)
    }
}

fn wrap_in_script_type(script_type: Name, script: &str) -> String {
    match script_type {
        Name::P2pkh => format!("pkh({})", script),
        Name::P2shP2wpkh => format!("sh(wpkh({}))", script),
        Name::P2wpkh => format!("wpkh({})", script),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_combination_descriptor() {
        let secp = &secp256k1::Secp256k1::signing_only();
        let descriptor = "wpkh([817e7be0/84h/0h/0h]xpub6CiKnWv7PPyyeb4kCwK4fidKqVjPfD9TP6MiXnzBVGZYNanNdY3mMvywcrdDc6wK82jyBSd95vsk26QujnJWPrSaPfYeyW7NyX37HHGtfQM/<0;1>/*)#60tjs4c7";
        let desc = Descriptors::try_from_line(descriptor);

        assert!(desc.is_ok());
        let desc = desc.unwrap();

        let (external, _) = Descriptor::parse_descriptor(secp, "wpkh([817e7be0/84h/0h/0h]xpub6CiKnWv7PPyyeb4kCwK4fidKqVjPfD9TP6MiXnzBVGZYNanNdY3mMvywcrdDc6wK82jyBSd95vsk26QujnJWPrSaPfYeyW7NyX37HHGtfQM/0/*)#sqx4cjta").unwrap();
        let (internal, _) = Descriptor::parse_descriptor(secp, "wpkh([817e7be0/84h/0h/0h]xpub6CiKnWv7PPyyeb4kCwK4fidKqVjPfD9TP6MiXnzBVGZYNanNdY3mMvywcrdDc6wK82jyBSd95vsk26QujnJWPrSaPfYeyW7NyX37HHGtfQM/1/*)#p5r598m9").unwrap();

        assert_eq!(desc.external, external);
        assert_eq!(desc.internal, internal);
    }

    #[test]
    fn test_parse_without_descriptor() {
        let single_sig = r#"{
    "name": "p2wpkh",
    "xfp": "8DFECFC3",
    "deriv": "m/84h/0h/0h",
    "xpub": "xpub6CiKnWv7PPyyeb4kCwK4fidKqVjPfD9TP6MiXnzBVGZYNanNdY3mMvywcrdDc6wK82jyBSd95vsk26QujnJWPrSaPfYeyW7NyX37HHGtfQM",
    "_pub": "zpub6rNrPrFwgm4wMBSysetK5tpLBS2HYT8TDKQA6amxFHKJUnQq8rNtc4JDfGYPbvF9wJyagPpG1Faqnfe3BB8XzKon8LwW9KkMWyAQ4RQHzB1",
    "first": "bc1q0g0vn4yqyk0zjwxw0zv5pltyyczty004zc9g7r"
        }"#;

        let single_sig: SingleSig = serde_json::from_str(single_sig).unwrap();

        let desc = "wpkh([817e7be0/84h/0h/0h]xpub6CiKnWv7PPyyeb4kCwK4fidKqVjPfD9TP6MiXnzBVGZYNanNdY3mMvywcrdDc6wK82jyBSd95vsk26QujnJWPrSaPfYeyW7NyX37HHGtfQM/<0;1>/*)#60tjs4c7";
        let desc = Descriptors::try_from_line(desc).unwrap();

        let parse_desc = Descriptors::try_from_single_sig(single_sig, Some("817E7BE0"));

        assert!(parse_desc.is_ok());
        let parse_desc = parse_desc.unwrap();

        assert_eq!(desc.external, parse_desc.external);
        assert_eq!(desc.internal, parse_desc.internal);

        assert_eq!(parse_desc.external.to_string(), desc.external.to_string());
        assert_eq!(parse_desc.internal.to_string(), desc.internal.to_string());
    }

    #[test]
    fn test_parse_wasabi() {
        let json = r#"{
            "ColdCardFirmwareVersion": "5.4.0",
            "MasterFingerprint": "817E7BE0",
            "ExtPubKey": "xpub6CiKnWv7PPyyeb4kCwK4fidKqVjPfD9TP6MiXnzBVGZYNanNdY3mMvywcrdDc6wK82jyBSd95vsk26QujnJWPrSaPfYeyW7NyX37HHGtfQM"
        }"#;

        let json = serde_json::from_str::<WasabiJson>(json).unwrap();
        let desc = Descriptors::try_from(json);

        assert!(desc.is_ok());
        let desc = desc.unwrap();
        let known_desc = "wpkh([817e7be0/84h/0h/0h]xpub6CiKnWv7PPyyeb4kCwK4fidKqVjPfD9TP6MiXnzBVGZYNanNdY3mMvywcrdDc6wK82jyBSd95vsk26QujnJWPrSaPfYeyW7NyX37HHGtfQM/<0;1>/*)#60tjs4c7";
        let known_desc = Descriptors::try_from_line(known_desc).unwrap();

        assert_eq!(desc.external, known_desc.external);
        assert_eq!(desc.internal, known_desc.internal);
    }
}
