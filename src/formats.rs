use bdk_wallet::keys::DescriptorPublicKey;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub enum Format {
    Descriptor(Descriptors),
    Json(Json),
    Wasabi(Descriptors),
    Electrum(Descriptors),
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Invalid descriptor")]
    InvalidDescriptor,

    #[error("Invalid json: {0}")]
    InvalidJsonParse(#[from] serde_json::Error),

    #[error("Invalid json, no xpubs or descriptor")]
    JsonNoDecriptor,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Descriptors {
    pub external: DescriptorPublicKey,
    pub internal: DescriptorPublicKey,
}

#[derive(Debug, Clone, Serialize)]
pub struct Json {
    #[serde(default)]
    pub bip44: Option<Descriptors>,
    #[serde(default)]
    pub bip49: Option<Descriptors>,
    #[serde(default)]
    pub bip84: Option<Descriptors>,
}

impl Json {
    pub fn try_new(
        bip44: Option<Descriptors>,
        bip49: Option<Descriptors>,
        bip84: Option<Descriptors>,
    ) -> Result<Self, Error> {
        if bip44.is_none() && bip49.is_none() && bip84.is_none() {
            return Err(Error::JsonNoDecriptor);
        }

        Ok(Self {
            bip44,
            bip49,
            bip84,
        })
    }
}
