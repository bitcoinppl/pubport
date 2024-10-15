use serde::{Deserialize, Serialize};

use crate::{
    descriptor::{self, Descriptors},
    json::{self, GenericJson},
};

#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub enum Format {
    Descriptor(Descriptors),
    Json(Json),
    Wasabi(Descriptors),
    Electrum(Descriptors),
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Invalid descriptor: {0:?}")]
    InvalidDescriptor(#[from] descriptor::Error),

    #[error("Invalid json: {0}")]
    InvalidJsonParse(#[from] serde_json::Error),

    #[error("Unable to create descriptor from json")]
    InvalidDescriptorInJson,

    #[error("Invalid json, no xpubs or descriptor")]
    JsonNoDecriptor,
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct Json {
    pub bip44: Option<Descriptors>,
    pub bip49: Option<Descriptors>,
    pub bip84: Option<Descriptors>,
}

impl TryFrom<GenericJson> for Json {
    type Error = Error;

    fn try_from(json: GenericJson) -> Result<Self, Self::Error> {
        if json.bip44.is_none() && json.bip49.is_none() && json.bip84.is_none() {
            return Err(Error::JsonNoDecriptor);
        }

        let bip44 = json
            .bip44
            .map(|single_sig| Descriptors::try_from_single_sig(single_sig, json.xfp.as_deref()))
            .transpose()?;

        let bip49 = json
            .bip49
            .map(|single_sig| Descriptors::try_from_single_sig(single_sig, json.xfp.as_deref()))
            .transpose()?;

        let bip84 = json
            .bip84
            .map(|single_sig| Descriptors::try_from_single_sig(single_sig, json.xfp.as_deref()))
            .transpose()?;

        if bip44.is_none() && bip49.is_none() && bip84.is_none() {
            return Err(Error::JsonNoDecriptor);
        }

        Ok(Json {
            bip44,
            bip49,
            bip84,
        })
    }
}

impl Format {
    pub fn try_new_from_str(string: &str) -> Result<Self, Error> {
        if let Ok(json) = serde_json::from_str::<json::GenericJson>(string) {
            if let Ok(json) = Json::try_from(json) {
                return Ok(Format::Json(json));
            }
        }

        if let Ok(json) = serde_json::from_str::<json::WasabiJson>(string) {
            if let Ok(desc) = Descriptors::try_from(json) {
                return Ok(Format::Wasabi(desc));
            }
        }

        if let Ok(json) = serde_json::from_str::<json::ElectrumJson>(string) {
            if let Ok(desc) = Descriptors::try_from(json) {
                return Ok(Format::Electrum(desc));
            }
        }

        let desc = Descriptors::try_from(string)?;
        Ok(Format::Descriptor(desc))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_all_formats() {
        let files = std::fs::read_dir("test/data").unwrap();

        for file in files {
            let file = file.unwrap();
            let path = file.path();

            if !path.ends_with(".json") || path.ends_with(".txt") {
                continue;
            }

            let string = std::fs::read_to_string(&path).unwrap();

            let format = Format::try_new_from_str(&string);
            assert!(format.is_ok());
        }
    }
}
