use crate::{
    descriptors::{self, Descriptors},
    json::{self, GenericJson},
};

#[derive(Debug, Clone)]
pub enum Format {
    Descriptor(Descriptors),
    Json(Json),
    Wasabi(Descriptors),
    Electrum(Descriptors),
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Invalid descriptor: {0:?}")]
    InvalidDescriptor(#[from] descriptors::Error),

    #[error("Invalid json: {0}")]
    InvalidJsonParse(#[from] serde_json::Error),

    #[error("Unable to create descriptor from json")]
    InvalidDescriptorInJson,

    #[error("Invalid json, no xpubs or descriptor")]
    JsonNoDecriptor,
}

#[derive(Debug, Clone)]
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
            .map(|single_sig| {
                Descriptors::try_from_single_sig(single_sig, json.xfp.as_ref().map(|s| s.as_str()))
            })
            .transpose()?;

        let bip49 = json
            .bip49
            .map(|single_sig| {
                Descriptors::try_from_single_sig(single_sig, json.xfp.as_ref().map(|s| s.as_str()))
            })
            .transpose()?;

        let bip84 = json
            .bip84
            .map(|single_sig| {
                Descriptors::try_from_single_sig(single_sig, json.xfp.as_ref().map(|s| s.as_str()))
            })
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
            let json = Json::try_from(json)?;
            return Ok(Format::Json(json));
        }

        todo!()
    }
}
