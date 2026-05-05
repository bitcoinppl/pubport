use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpub};
use miniscript::{
    descriptor::{DerivPaths, DescriptorMultiXKey, Wildcard},
    Descriptor, DescriptorPublicKey,
};

use super::{split_multipath_descriptor, Descriptors, Error, ScriptType};

/// Builds external and internal single-sig descriptors from an account xpub
///
/// Use this when you already have an account-level xpub plus the master
/// fingerprint and origin account path. The built descriptors use the standard
/// external `/0/*` and internal `/1/*` branches for the selected script type
///
/// # Examples
///
/// ```rust
/// use std::str::FromStr as _;
///
/// use bitcoin::bip32::{Fingerprint, Xpub};
/// use pubport::descriptor::{DescriptorBuilder, ScriptType};
///
/// let xpub = Xpub::from_str(
///     "xpub6CiKnWv7PPyyeb4kCwK4fidKqVjPfD9TP6MiXnzBVGZYNanNdY3mMvywcrdDc6wK82jyBSd95vsk26QujnJWPrSaPfYeyW7NyX37HHGtfQM",
/// )?;
/// let fingerprint = Fingerprint::from_str("817e7be0")?;
///
/// let descriptors =
///     DescriptorBuilder::account_xpub_for_coin_type(ScriptType::P2wpkh, xpub, fingerprint, 0)?
///         .build()?;
///
/// assert!(descriptors.external.to_string().starts_with("wpkh("));
/// assert!(descriptors.internal.to_string().contains("/1/*"));
///
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone)]
pub struct DescriptorBuilder {
    script_type: ScriptType,
    xpub: Xpub,
    fingerprint: Fingerprint,
    origin_derivation_path: DerivationPath,
}

impl DescriptorBuilder {
    /// Create a builder from an explicit origin account derivation path
    ///
    /// `origin_derivation_path` should be the account path for `xpub`, such as
    /// `84h/0h/0h` for a mainnet BIP84 account xpub. If you only need a
    /// standard account-zero path for a coin type, use
    /// [`DescriptorBuilder::account_xpub_for_coin_type`]
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

    /// Create a builder for a standard account-zero BIP path and coin type
    ///
    /// The path is derived from `script_type`: BIP44 for P2PKH, BIP49 for
    /// P2SH-P2WPKH, BIP84 for P2WPKH, and BIP86 for P2TR. `coin_type` is the
    /// hardened BIP44 coin type component, such as `0` for mainnet bitcoin and
    /// `1` for testnet or signet bitcoin
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

    /// Build split external and internal descriptors
    ///
    /// The generated descriptor key expression is a multipath account xpub
    /// using `<0;1>/*`, then it is split into a [`Descriptors`] value with
    /// external `/0/*` and internal `/1/*` descriptors
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
