use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpub};
use miniscript::{
    descriptor::{DerivPaths, DescriptorMultiXKey, Wildcard},
    Descriptor, DescriptorPublicKey,
};

use super::{split_multipath_descriptor, Descriptors, Error, ScriptType};

#[derive(Debug, Clone)]
pub struct DescriptorBuilder {
    script_type: ScriptType,
    xpub: Xpub,
    fingerprint: Fingerprint,
    origin_derivation_path: DerivationPath,
}

impl DescriptorBuilder {
    pub fn new(
        script_type: ScriptType,
        xpub: Xpub,
        fingerprint: Fingerprint,
        origin_derivation_path: DerivationPath,
    ) -> Self {
        Self {
            script_type,
            xpub,
            fingerprint,
            origin_derivation_path,
        }
    }

    pub fn account_xpub_for_coin_type(
        script_type: ScriptType,
        xpub: Xpub,
        fingerprint: Fingerprint,
        coin_type: u32,
    ) -> Result<Self, Error> {
        let origin_derivation_path =
            script_type.account_derivation_path_for_coin_type(coin_type)?;

        Ok(Self::new(
            script_type,
            xpub,
            fingerprint,
            origin_derivation_path,
        ))
    }

    pub fn build(self) -> Result<Descriptors, Error> {
        let key = DescriptorPublicKey::MultiXPub(DescriptorMultiXKey {
            origin: Some((self.fingerprint, self.origin_derivation_path)),
            xkey: self.xpub,
            derivation_paths: multipath_change_derivations(),
            wildcard: Wildcard::Unhardened,
        });

        let descriptor = match self.script_type {
            ScriptType::P2pkh => Descriptor::new_pkh(key)?,
            ScriptType::P2shP2wpkh => Descriptor::new_sh_wpkh(key)?,
            ScriptType::P2wpkh => Descriptor::new_wpkh(key)?,
            ScriptType::P2tr => Descriptor::new_tr(key, None)?,
        };

        split_multipath_descriptor(descriptor)
    }
}

fn multipath_change_derivations() -> DerivPaths {
    let external = ChildNumber::from_normal_idx(0).expect("0 is a valid normal child number");
    let internal = ChildNumber::from_normal_idx(1).expect("1 is a valid normal child number");

    DerivPaths::new(vec![
        DerivationPath::from(vec![external]),
        DerivationPath::from(vec![internal]),
    ])
    .expect("external and internal paths are present")
}
