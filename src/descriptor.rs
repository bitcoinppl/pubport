mod script_type;

use bitcoin::{bip32::Fingerprint, secp256k1};
use miniscript::{descriptor::DescriptorKeyParseError, Descriptor, DescriptorPublicKey};
use serde::{Deserialize, Serialize};

use crate::{
    json::{ElectrumJson, SingleSig, WasabiJson},
    key_expression::KeyExpression,
    xpub,
};

pub use script_type::ScriptType;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Invalid descriptor: {0:?}")]
    InvalidDescriptor(#[from] DescriptorKeyParseError),

    #[error("Single descriptor line did not contain both external and internal keys")]
    MissingKeys,

    #[error("Too many keys in descriptor, only supports 1 external and 1 internal key, found {0}")]
    TooManyKeys(usize),

    #[error("Unable to parse descriptor: {0}")]
    InvalidDescriptorParse(#[from] miniscript::Error),

    #[error("Invalid JSON descriptor: {0}")]
    InvalidJsonDescriptor(#[from] serde_json::Error),

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

    #[error("Unable to parse xpub: {0:?}")]
    InvalidXpub(#[from] xpub::Error),

    #[error("Unable to parse xpub: {0}")]
    UnableToParseXpub(bitcoin::bip32::Error),

    #[error("Unable to get xpub from descriptor")]
    NoXpubInDescriptor,

    #[error("Single pubkey is not supported, must be an extended key")]
    SinglePubkeyNotSupported,

    #[error("Xpub is a master key, please use the child xpub for the derivation path")]
    MasterXpub,

    #[error("ScriptType parse error: {0}")]
    ScriptTypeParseError(#[from] script_type::Error),

    #[error("Creating descriptor from key expression requires a master fingerprint and origin derivation path")]
    MissingKeyExpressionFields,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JsonDescriptor {
    descriptor: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct Descriptors {
    #[serde(
        serialize_with = "serialize_descriptor",
        deserialize_with = "deserialize_descriptor"
    )]
    pub external: Descriptor<DescriptorPublicKey>,
    #[serde(
        serialize_with = "serialize_descriptor",
        deserialize_with = "deserialize_descriptor"
    )]
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
            0 | 1 => return Err(Error::MissingKeys),
            n => return Err(Error::TooManyKeys(n)),
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
        let desc = script_type.wrap_with(&script);

        let desc = Descriptors::try_from_line(&desc)?;
        Ok(desc)
    }

    pub fn try_from_child_xpub(
        xpub: bitcoin::bip32::Xpub,
        script_type: ScriptType,
    ) -> Result<Self, Error> {
        if xpub.depth == 0 {
            return Err(Error::MasterXpub);
        }

        let descriptor_derivation_path = script_type.descriptor_derivation_path();

        // with just the child xpub we can't get the master fingerprint
        let fingerprint = "00000000";
        let desc_script = format!("[{fingerprint}/{descriptor_derivation_path}]{xpub}/<0;1>/*");
        let desc_string = script_type.wrap_with(&desc_script);

        let desc = Descriptors::try_from_line(&desc_string)?;
        Ok(desc)
    }

    pub fn try_from_key_expression(key_expression: &KeyExpression) -> Result<Self, Error> {
        if let KeyExpression {
            xpub,
            master_fingerprint: Some(master_fingerprint),
            origin_derivation_path: Some(path),
            xpub_derivation_path: _,
        } = key_expression
        {
            let script_type = ScriptType::try_from_derivation_path(path)?;
            let script = format!("[{master_fingerprint}/{path}]{xpub}/<0;1>/*");
            let desc = script_type.wrap_with(&script);

            return Descriptors::try_from_line(&desc);
        }

        Err(Error::MissingKeyExpressionFields)
    }

    pub fn fingerprint(&self) -> Option<Fingerprint> {
        let desc = &self.external;

        let inner = match desc {
            Descriptor::Pkh(pkh) => Some(pkh.as_inner()),
            Descriptor::Wpkh(wpkh) => Some(wpkh.as_inner()),
            Descriptor::Wsh(_) => None,
            Descriptor::Sh(_) => None,
            Descriptor::Tr(_) => None,
            Descriptor::Bare(_) => None,
        }?;

        let fingerprint = inner.master_fingerprint();
        if fingerprint == Fingerprint::default() {
            return None;
        }

        Some(fingerprint)
    }

    pub fn xpub(&self) -> Result<bitcoin::bip32::Xpub, Error> {
        let desc = &self.external;

        let inner = match desc {
            Descriptor::Pkh(pkh) => pkh.as_inner(),
            Descriptor::Wpkh(wpkh) => wpkh.as_inner(),
            Descriptor::Wsh(_) => return Err(Error::NoXpubInDescriptor),
            Descriptor::Sh(_) => return Err(Error::NoXpubInDescriptor),
            Descriptor::Tr(_) => return Err(Error::NoXpubInDescriptor),
            Descriptor::Bare(_) => return Err(Error::NoXpubInDescriptor),
        };

        let xpub: bitcoin::bip32::Xpub = match inner {
            DescriptorPublicKey::XPub(inner) => inner.xkey,
            DescriptorPublicKey::MultiXPub(inner) => inner.xkey,
            DescriptorPublicKey::Single(_) => return Err(Error::SinglePubkeyNotSupported),
        };

        Ok(xpub)
    }
}

#[cfg(feature = "uniffi")]
mod ffi {
    use super::Descriptors;

    impl Descriptors {
        pub fn external(&self) -> String {
            self.external.to_string()
        }

        pub fn internal(&self) -> String {
            self.internal.to_string()
        }
    }
}

impl TryFrom<WasabiJson> for Descriptors {
    type Error = Error;

    fn try_from(json: WasabiJson) -> Result<Self, Self::Error> {
        let fingerprint = json.master_fingerprint.to_ascii_lowercase();
        let derivation_path = "84h/0h/0h";
        let xpub = json.ext_pub_key;

        let script = format!("[{fingerprint}/{derivation_path}]{xpub}/<0;1>/*");
        let desc = ScriptType::P2wpkh.wrap_with(&script);

        let desc = Descriptors::try_from_line(&desc)?;
        Ok(desc)
    }
}

impl TryFrom<ElectrumJson> for Descriptors {
    type Error = Error;

    fn try_from(json: ElectrumJson) -> Result<Self, Self::Error> {
        let keystore = &json.keystore;

        let mut script_type = None;
        if keystore.derivation.starts_with("m/84") {
            script_type = Some(ScriptType::P2wpkh);
        }

        if keystore.derivation.starts_with("m/49") {
            script_type = Some(ScriptType::P2shP2wpkh);
        }

        if keystore.derivation.starts_with("m/44") {
            script_type = Some(ScriptType::P2pkh);
        }

        if script_type.is_none() {
            return Err(Error::MissingScriptType);
        }

        let script_type = script_type.expect("checked above");
        if keystore.xpub.len() < 4 {
            return Err(xpub::Error::TooShort(keystore.xpub.len()).into());
        }

        let xpub = xpub::Xpub::try_from(keystore.xpub.as_str())?;

        let fingerprint = match (&keystore.ckcc_xfp, &keystore.ckcc_xpub) {
            (Some(fingerprint), _) => {
                let xfp = fingerprint.swap_bytes();
                format!("{:08X}", xfp)
            }
            (None, Some(ck_xpub)) => xpub::xpub_str_to_fingerprint(ck_xpub)?.to_string(),
            (None, None) => xpub
                .master_fingerprint()
                .ok_or(Error::NoXpubInDescriptor)?
                .to_string(),
        };

        let derivation_path = keystore.derivation.replace("m/", "");
        let script = format!("[{fingerprint}/{derivation_path}]{xpub}/<0;1>/*");
        let desc = script_type.wrap_with(&script);

        let desc = Descriptors::try_from_line(&desc)?;
        Ok(desc)
    }
}

impl TryFrom<&str> for Descriptors {
    type Error = Error;

    fn try_from(desc: &str) -> Result<Self, Self::Error> {
        let lines = desc
            .trim()
            .split('\n')
            .filter(|line| !line.is_empty())
            .map(|line| line.trim())
            .collect::<Vec<&str>>();

        if let Some(line) = lines.first() {
            // json descriptor
            if line.trim().starts_with('{') {
                let json: JsonDescriptor =
                    serde_json::from_str(desc).map_err(Error::InvalidJsonDescriptor)?;
                return Self::try_from_line(&json.descriptor);
            }
        }

        match lines.len() {
            1 => Descriptors::try_from_line(lines[0]),
            2 => {
                let external = lines[0];
                let internal = lines[1];

                let secp = &secp256k1::Secp256k1::signing_only();
                let (internal_desc, _keymap) =
                    Descriptor::<DescriptorPublicKey>::parse_descriptor(secp, internal)?;

                let (external_desc, _keymap) =
                    Descriptor::<DescriptorPublicKey>::parse_descriptor(secp, external)?;

                Ok(Descriptors {
                    external: external_desc,
                    internal: internal_desc,
                })
            }
            0 => Err(Error::MissingDescriptor),
            n => Err(Error::TooManyKeys(n)),
        }
    }
}

fn serialize_descriptor<S>(
    descriptor: &Descriptor<DescriptorPublicKey>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let desc = descriptor.to_string();
    serializer.serialize_str(&desc)
}

fn deserialize_descriptor<'de, D>(
    deserializer: D,
) -> Result<Descriptor<DescriptorPublicKey>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let secp = &secp256k1::Secp256k1::signing_only();
    let desc = String::deserialize(deserializer)?;
    let (descriptor, _) = Descriptor::<DescriptorPublicKey>::parse_descriptor(secp, desc.as_str())
        .map_err(serde::de::Error::custom)?;

    Ok(descriptor)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use super::*;
    use pretty_assertions::assert_eq;

    fn known_desc() -> Descriptors {
        let known_desc = "wpkh([817e7be0/84h/0h/0h]xpub6CiKnWv7PPyyeb4kCwK4fidKqVjPfD9TP6MiXnzBVGZYNanNdY3mMvywcrdDc6wK82jyBSd95vsk26QujnJWPrSaPfYeyW7NyX37HHGtfQM/<0;1>/*)#60tjs4c7";
        Descriptors::try_from_line(known_desc).unwrap()
    }

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
    fn test_fingerprint_getter() {
        let single_sig = r#"{
    "name": "p2wpkh",
    "xfp": "8DFECFC3",
    "deriv": "m/84h/0h/0h",
    "xpub": "xpub6CiKnWv7PPyyeb4kCwK4fidKqVjPfD9TP6MiXnzBVGZYNanNdY3mMvywcrdDc6wK82jyBSd95vsk26QujnJWPrSaPfYeyW7NyX37HHGtfQM",
    "desc": "wpkh([817e7be0/84h/0h/0h]xpub6CiKnWv7PPyyeb4kCwK4fidKqVjPfD9TP6MiXnzBVGZYNanNdY3mMvywcrdDc6wK82jyBSd95vsk26QujnJWPrSaPfYeyW7NyX37HHGtfQM/<0;1>/*)#60tjs4c7",
    "_pub": "zpub6rNrPrFwgm4wMBSysetK5tpLBS2HYT8TDKQA6amxFHKJUnQq8rNtc4JDfGYPbvF9wJyagPpG1Faqnfe3BB8XzKon8LwW9KkMWyAQ4RQHzB1",
    "first": "bc1q0g0vn4yqyk0zjwxw0zv5pltyyczty004zc9g7r"
        }"#;

        let single_sig: SingleSig = serde_json::from_str(single_sig).unwrap();
        let parse_desc = Descriptors::try_from_single_sig(single_sig, None).unwrap();

        assert_eq!(
            parse_desc
                .fingerprint()
                .unwrap()
                .to_string()
                .to_uppercase()
                .as_str(),
            "817E7BE0"
        );
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

        let parse_desc = Descriptors::try_from_single_sig(single_sig, Some("817E7BE0"));

        assert!(parse_desc.is_ok());
        let parse_desc = parse_desc.unwrap();

        assert_eq!(known_desc().external, parse_desc.external);
        assert_eq!(known_desc().internal, parse_desc.internal);

        assert_eq!(
            parse_desc.external.to_string(),
            known_desc().external.to_string()
        );

        assert_eq!(
            parse_desc.internal.to_string(),
            known_desc().internal.to_string()
        );
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

        assert_eq!(desc.external, known_desc().external);
        assert_eq!(desc.internal, known_desc().internal);
    }

    #[test]
    fn test_parse_electrum() {
        let json = r#"{
            "seed_version": 17,
            "use_encryption": false,
            "wallet_type": "standard",
            "keystore": {
                "type": "hardware",
                "hw_type": "coldcard",
                "label": "Coldcard Import 817E7BE0",
                "ckcc_xfp": 3766189697,
                "ckcc_xpub": "xpub661MyMwAqRbcFFr2SGY3dUn7g8P9VKNZdKWL2Z2pZMEkBWH2D1KTcwTn7keZQCaScCx7BUDjHFJJHnzBvDgUFgNjYsQTRvo7LWfYEtt78Pb",
                "derivation": "m/84h/0h/0h",
                "xpub": "zpub6rNrPrFwgm4wMBSysetK5tpLBS2HYT8TDKQA6amxFHKJUnQq8rNtc4JDfGYPbvF9wJyagPpG1Faqnfe3BB8XzKon8LwW9KkMWyAQ4RQHzB1"
            }
        }"#;

        let electrum = serde_json::from_str::<ElectrumJson>(json);
        assert!(electrum.is_ok());

        let electrum = electrum.unwrap();
        let desc = Descriptors::try_from(electrum);

        assert!(desc.is_ok());
        let desc = desc.unwrap();

        assert_eq!(desc.external, known_desc().external);
        assert_eq!(desc.internal, known_desc().internal);
    }

    #[test]
    fn test_parse_electrum_without_xfp() {
        let json = r#"{
            "seed_version": 17,
            "use_encryption": false,
            "wallet_type": "standard",
            "keystore": {
                "type": "hardware",
                "hw_type": "coldcard",
                "label": "Coldcard Import 817E7BE0",
                "ckcc_xpub": "xpub661MyMwAqRbcFFr2SGY3dUn7g8P9VKNZdKWL2Z2pZMEkBWH2D1KTcwTn7keZQCaScCx7BUDjHFJJHnzBvDgUFgNjYsQTRvo7LWfYEtt78Pb",
                "derivation": "m/84h/0h/0h",
                "xpub": "zpub6rNrPrFwgm4wMBSysetK5tpLBS2HYT8TDKQA6amxFHKJUnQq8rNtc4JDfGYPbvF9wJyagPpG1Faqnfe3BB8XzKon8LwW9KkMWyAQ4RQHzB1"
            }
        }"#;

        let electrum = serde_json::from_str::<ElectrumJson>(json);
        assert!(electrum.is_ok());

        let electrum = electrum.unwrap();
        let desc = Descriptors::try_from(electrum);

        assert!(desc.is_ok());
        let desc = desc.unwrap();

        assert_eq!(desc.external, known_desc().external);
        assert_eq!(desc.internal, known_desc().internal);
    }

    #[test]
    fn test_parse_electrum_without_ckcc() {
        let json = r#"{
            "seed_version": 17,
            "use_encryption": false,
            "wallet_type": "standard",
            "keystore": {
                "type": "hardware",
                "hw_type": "coldcard",
                "label": "Coldcard Import 817E7BE0",
                "derivation": "m/84h/0h/0h",
                "xpub": "zpub6rNrPrFwgm4wMBSysetK5tpLBS2HYT8TDKQA6amxFHKJUnQq8rNtc4JDfGYPbvF9wJyagPpG1Faqnfe3BB8XzKon8LwW9KkMWyAQ4RQHzB1"
            }
        }"#;

        let electrum = serde_json::from_str::<ElectrumJson>(json);
        assert!(electrum.is_ok());

        let electrum = electrum.unwrap();
        let desc = Descriptors::try_from(electrum);

        assert!(desc.is_ok());
        let desc = desc.unwrap();

        let known_desc = "wpkh([90645a28/84h/0h/0h]xpub6CiKnWv7PPyyeb4kCwK4fidKqVjPfD9TP6MiXnzBVGZYNanNdY3mMvywcrdDc6wK82jyBSd95vsk26QujnJWPrSaPfYeyW7NyX37HHGtfQM/<0;1>/*)#ujst24qf";
        let known_desc = Descriptors::try_from_line(known_desc).unwrap();

        assert_eq!(desc.external, known_desc.external);
        assert_eq!(desc.internal, known_desc.internal);
    }

    #[test]
    fn test_from_descriptors_file() {
        let desc = r#"
            wpkh([817e7be0/84h/0h/0h]xpub6CiKnWv7PPyyeb4kCwK4fidKqVjPfD9TP6MiXnzBVGZYNanNdY3mMvywcrdDc6wK82jyBSd95vsk26QujnJWPrSaPfYeyW7NyX37HHGtfQM/0/*)#sqx4cjta
            wpkh([817e7be0/84h/0h/0h]xpub6CiKnWv7PPyyeb4kCwK4fidKqVjPfD9TP6MiXnzBVGZYNanNdY3mMvywcrdDc6wK82jyBSd95vsk26QujnJWPrSaPfYeyW7NyX37HHGtfQM/1/*)#p5r598m9
        "#;

        let desc = Descriptors::try_from(desc).unwrap();

        assert_eq!(desc.external.to_string(), known_desc().external.to_string());
        assert_eq!(desc.internal.to_string(), known_desc().internal.to_string());
    }

    #[test]
    fn test_xpub_output() {
        let know_desc = known_desc();
        let xpub = know_desc.xpub();

        assert!(xpub.is_ok());
        assert!(xpub.unwrap().to_string().starts_with("xpub6CiKnWv7PPyyeb4kCwK4fidKqVjPfD9TP6MiXnzBVGZYNanNdY3mMvywcrdDc6wK82jyBSd95vsk26QujnJWPrSaPfYeyW7NyX37HHGtfQM"));
    }

    #[test]
    fn test_get_master_fingerprint() {
        let know_desc = known_desc();
        let master_fingerprint = know_desc.fingerprint().unwrap();
        assert_eq!(master_fingerprint.to_string().as_str(), "817e7be0");
    }

    #[test]
    fn test_json_descriptor() {
        let json_descriptor = r##"{   "label": "test1",   "blockheight": 607985,   "descriptor": "wpkh([73c5da0a/84h/0h/0h]xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V/<0;1>/*)" }"##;
        let desc = Descriptors::try_from(json_descriptor);
        assert!(desc.is_ok());
    }

    #[test]
    fn test_try_from_child_xpub() {
        let xpub = bitcoin::bip32::Xpub::from_str("xpub6CiKnWv7PPyyeb4kCwK4fidKqVjPfD9TP6MiXnzBVGZYNanNdY3mMvywcrdDc6wK82jyBSd95vsk26QujnJWPrSaPfYeyW7NyX37HHGtfQM").unwrap();
        let desc = Descriptors::try_from_child_xpub(xpub, ScriptType::P2wpkh).unwrap();
        let expected_desc = Descriptors::try_from_line("wpkh([00000000/84h/0h/0h]xpub6CiKnWv7PPyyeb4kCwK4fidKqVjPfD9TP6MiXnzBVGZYNanNdY3mMvywcrdDc6wK82jyBSd95vsk26QujnJWPrSaPfYeyW7NyX37HHGtfQM/<0;1>/*)").unwrap();

        assert_eq!(desc.external, expected_desc.external);
        assert_eq!(desc.internal, expected_desc.internal);
    }

    #[test]
    fn test_try_from_key_expression() {
        let input = "[deadbeef/84h/0h/0h]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL";
        let result =
            Descriptors::try_from_key_expression(&KeyExpression::try_from_str(input).unwrap());

        let test_desc = Descriptors::try_from_line("wpkh([deadbeef/84h/0h/0h]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/<0;1>/*)").unwrap();

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), test_desc);
    }

    #[test]
    fn test_try_from_key_expression_bip_44() {
        let input = "[deadbeef/44h/1h/0h]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/3/4/5";
        let test_desc = Descriptors::try_from_line("pkh([deadbeef/44h/1h/0h]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/<0;1>/*)").unwrap();
        let desc =
            Descriptors::try_from_key_expression(&KeyExpression::try_from_str(input).unwrap())
                .unwrap();

        assert_eq!(desc.internal.to_string(), test_desc.internal.to_string());
        assert_eq!(desc.external.to_string(), test_desc.external.to_string());
        assert_eq!(desc, test_desc);
    }

    #[test]
    fn test_try_from_key_expression_bip_49() {
        let input = "[deadbeef/49h/10h/20h]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/*";
        let test_desc = Descriptors::try_from_line("sh(wpkh([deadbeef/49h/10h/20h]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/<0;1>/*))").unwrap();
        let desc =
            Descriptors::try_from_key_expression(&KeyExpression::try_from_str(input).unwrap())
                .unwrap();

        assert_eq!(desc.internal.to_string(), test_desc.internal.to_string());
        assert_eq!(desc.external.to_string(), test_desc.external.to_string());
        assert_eq!(desc, test_desc);
    }
}
