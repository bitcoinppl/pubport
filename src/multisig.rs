//! Multisig descriptor parsing and validation.
//!
//! Supports watch-only public multisig descriptors in the following forms:
//! - `wsh(sortedmulti(k, KEY_1, ..., KEY_n))`
//! - `wsh(multi(k, KEY_1, ..., KEY_n))`
//!
//! Both single multipath (`/<0;1>/*`) and two-line (external + internal) inputs
//! are accepted. Private key material, taproot multisig, bare multi, sh(multi),
//! and miniscript policy descriptors are explicitly rejected.

use bitcoin::secp256k1;
use miniscript::{Descriptor, DescriptorPublicKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MultiFunctionKind {
    Multi,
    SortedMulti,
}

impl std::fmt::Display for MultiFunctionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MultiFunctionKind::Multi => write!(f, "multi"),
            MultiFunctionKind::SortedMulti => write!(f, "sortedmulti"),
        }
    }
}

/// A validated, parsed multisig descriptor pair (external + internal).
///
/// Guaranteed invariants on construction:
/// - Both descriptors are `wsh(multi(...))` or `wsh(sortedmulti(...))`.
/// - No private key material is present.
/// - `threshold >= 1` and `threshold <= num_signers`.
/// - External and internal descriptors are structurally matching
///   (same threshold, same keys, same function kind) differing only in
///   the derivation branch (`/0/*` vs `/1/*`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct MultisigDescriptorPair {
    /// Receive descriptor — cosigner keys derive via `/0/*`.
    #[serde(
        serialize_with = "serialize_descriptor",
        deserialize_with = "deserialize_descriptor"
    )]
    pub external: Descriptor<DescriptorPublicKey>,

    /// Change descriptor — cosigner keys derive via `/1/*`.
    #[serde(
        serialize_with = "serialize_descriptor",
        deserialize_with = "deserialize_descriptor"
    )]
    pub internal: Descriptor<DescriptorPublicKey>,

    /// Signature threshold `k` in `k`-of-`n`.
    pub threshold: usize,

    /// Total signer count `n` in `k`-of-`n`.
    pub num_signers: usize,

    /// Whether `multi` or `sortedmulti` is used.
    pub function: MultiFunctionKind,
}

/// Errors specific to multisig descriptor parsing and validation.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Unable to parse descriptor: {0}")]
    ParseError(#[from] miniscript::Error),

    #[error("Private key material (xprv/tprv) is not allowed in watch-only multisig descriptors")]
    PrivateKeyMaterialNotAllowed,

    #[error("Unsupported descriptor kind: {0}")]
    UnsupportedDescriptorKind(String),

    #[error("Unsupported policy descriptor: wsh(thresh(...)) is not supported in v1")]
    UnsupportedPolicyDescriptor,

    #[error("Invalid threshold: k={k} exceeds signer count n={n}")]
    InvalidThreshold { k: usize, n: usize },

    #[error("At least one cosigner is required")]
    InvalidSignerCount,

    #[error("A change descriptor (internal, /1/*) is required for wallet import")]
    MissingInternalDescriptor,

    #[error(
        "Multipath descriptors must expand to exactly two single descriptors (external and internal, e.g. <0;1>); got {count}"
    )]
    WrongNumberOfSingleDescriptors { count: usize },

    #[error("External and internal descriptors do not match: {0}")]
    DescriptorPairMismatch(String),
}

// Internal helper: a parsed single descriptor plus extracted metadata.
struct ParsedSingle {
    descriptor: Descriptor<DescriptorPublicKey>,
    threshold: usize,
    num_signers: usize,
    function: MultiFunctionKind,
}

impl MultisigDescriptorPair {
    /// Returns `true` if the input looks like any form of multisig descriptor.
    ///
    /// Used to short-circuit to the multisig parsing path before attempting
    /// single-sig parsing.  Recognises supported forms (`wsh(multi(...))`,
    /// `wsh(sortedmulti(...))`) as well as explicitly rejected forms
    /// (`sh(multi(...))`, bare `multi(...)`, taproot, miniscript policy) so
    /// that the rejected forms produce clear errors instead of a generic
    /// "no format matched" failure.
    pub fn is_multisig_like(s: &str) -> bool {
        s.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(strip_checksum)
            .any(|line| {
                line.starts_with("wsh(multi(")
                    || line.starts_with("wsh(sortedmulti(")
                    || line.starts_with("sh(multi(")
                    || line.starts_with("sh(sortedmulti(")
                    || line.starts_with("multi(")
                    || line.starts_with("sortedmulti(")
                    || (line.starts_with("tr(")
                        && (line.contains("sortedmulti_a(") || line.contains("multi_a(")))
                    || line.contains("wsh(thresh(")
            })
    }

    /// Parse and validate a multisig descriptor string into a
    /// [`MultisigDescriptorPair`].
    ///
    /// Accepts:
    /// - A single **multipath** descriptor:
    ///   `wsh(sortedmulti(k, KEY/<0;1>/*, ...))` — split into external/internal
    ///   automatically.
    /// - A **two-line** pair: external descriptor on line 1, internal on line 2.
    ///
    /// Returns [`Error::MissingInternalDescriptor`] when given a single
    /// non-multipath descriptor (e.g. only the receive descriptor), and
    /// [`Error::WrongNumberOfSingleDescriptors`] when a multipath descriptor
    /// expands to anything other than exactly two descriptors.
    pub fn try_from_str(s: &str) -> Result<Self, Error> {
        let s = s.trim();

        check_no_private_keys(s)?;

        let lines: Vec<&str> = s.lines().map(str::trim).filter(|l| !l.is_empty()).collect();

        // Validate each line for unsupported forms before expensive parsing.
        for line in &lines {
            check_unsupported_forms(line)?;
        }

        match lines.len() {
            0 => {
                // Delegate to miniscript so the caller gets a proper ParseError
                // rather than the confusing InvalidSignerCount.
                let secp = secp256k1::Secp256k1::signing_only();
                let _ = Descriptor::<DescriptorPublicKey>::parse_descriptor(&secp, s)?;
                // miniscript accepted empty string — shouldn't happen, but guard.
                Err(Error::MissingInternalDescriptor)
            }

            1 => {
                let secp = secp256k1::Secp256k1::signing_only();
                let (descriptor, _) =
                    Descriptor::<DescriptorPublicKey>::parse_descriptor(&secp, lines[0])?;

                if descriptor.is_multipath() {
                    // Split multipath (<0;1>) into external (/0/*) and internal (/1/*).
                    let singles = descriptor.into_single_descriptors()?;
                    if singles.len() != 2 {
                        return Err(Error::WrongNumberOfSingleDescriptors {
                            count: singles.len(),
                        });
                    }
                    let ext = parse_and_validate_single(&singles[0].to_string())?;
                    let int = parse_and_validate_single(&singles[1].to_string())?;
                    validate_pair(&ext, &int)?;
                    Ok(Self {
                        external: ext.descriptor,
                        internal: int.descriptor,
                        threshold: ext.threshold,
                        num_signers: ext.num_signers,
                        function: ext.function,
                    })
                } else {
                    // Single non-multipath descriptor — caller must also supply
                    // the change descriptor.
                    Err(Error::MissingInternalDescriptor)
                }
            }

            2 => {
                let ext = parse_and_validate_single(lines[0])?;
                let int = parse_and_validate_single(lines[1])?;
                validate_pair(&ext, &int)?;
                Ok(Self {
                    external: ext.descriptor,
                    internal: int.descriptor,
                    threshold: ext.threshold,
                    num_signers: ext.num_signers,
                    function: ext.function,
                })
            }

            n => Err(Error::DescriptorPairMismatch(format!(
                "expected 1 or 2 descriptor lines, got {n}"
            ))),
        }
    }
}

// ── Public helpers ────────────────────────────────────────────────────────────

/// Extract `(threshold, num_signers, function)` from a descriptor string
/// **without** constructing a full pair.  Useful for metadata inspection and
/// unit testing single-descriptor inputs.
///
/// Accepts a descriptor in any format miniscript can parse; does not require
/// both external and internal descriptors.
pub fn extract_multisig_metadata(
    desc_str: &str,
) -> Result<(usize, usize, MultiFunctionKind), Error> {
    let secp = secp256k1::Secp256k1::signing_only();

    // Parse through miniscript to validate and get the canonical representation
    // (e.g. normalises `h` → `'` in hardened path notation).
    let (parsed, _) = Descriptor::<DescriptorPublicKey>::parse_descriptor(&secp, desc_str)?;
    let canonical = parsed.to_string();
    let canonical = strip_checksum(&canonical);

    extract_metadata_from_canonical(canonical)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn extract_metadata_from_canonical(s: &str) -> Result<(usize, usize, MultiFunctionKind), Error> {
    // Check for "sortedmulti(" before "multi(" to avoid the substring overlap.
    let (arg_start, function) = if let Some(pos) = s.find("sortedmulti(") {
        (pos + "sortedmulti(".len(), MultiFunctionKind::SortedMulti)
    } else if let Some(pos) = s.find("multi(") {
        (pos + "multi(".len(), MultiFunctionKind::Multi)
    } else {
        return Err(Error::UnsupportedDescriptorKind(s.to_string()));
    };

    let rest = &s[arg_start..];

    let comma_pos = rest.find(',').ok_or(Error::InvalidSignerCount)?;
    let threshold: usize = rest[..comma_pos]
        .trim()
        .parse()
        .map_err(|_| Error::InvalidSignerCount)?;

    // Number of top-level commas == number of keys (the first item is the
    // threshold, remaining items are keys — so commas == num_signers).
    let num_signers = count_top_level_commas(rest);

    Ok((threshold, num_signers, function))
}

fn check_no_private_keys(s: &str) -> Result<(), Error> {
    if s.contains("xprv") || s.contains("tprv") {
        return Err(Error::PrivateKeyMaterialNotAllowed);
    }
    Ok(())
}

fn check_unsupported_forms(line: &str) -> Result<(), Error> {
    let line = strip_checksum(line);

    // Taproot multisig (tr + sortedmulti_a / multi_a).
    if line.starts_with("tr(") && (line.contains("sortedmulti_a(") || line.contains("multi_a(")) {
        return Err(Error::UnsupportedDescriptorKind(
            "taproot multisig (tr with sortedmulti_a/multi_a) is not supported".to_string(),
        ));
    }

    // Miniscript policy inside wsh.
    if line.contains("wsh(thresh(") {
        return Err(Error::UnsupportedPolicyDescriptor);
    }

    // Legacy P2SH multisig wrapping.
    if line.starts_with("sh(multi(") || line.starts_with("sh(sortedmulti(") {
        return Err(Error::UnsupportedDescriptorKind(
            "sh(multi(...)) / sh(sortedmulti(...)) are not supported; use wsh(...)".to_string(),
        ));
    }

    // Bare multi/sortedmulti (no script hash wrapper).
    if line.starts_with("multi(") || line.starts_with("sortedmulti(") {
        return Err(Error::UnsupportedDescriptorKind(
            "bare multi(...) / sortedmulti(...) without a wsh(...) wrapper are not supported"
                .to_string(),
        ));
    }

    Ok(())
}

fn parse_and_validate_single(line: &str) -> Result<ParsedSingle, Error> {
    let secp = secp256k1::Secp256k1::signing_only();
    let (descriptor, _) = Descriptor::<DescriptorPublicKey>::parse_descriptor(&secp, line)?;

    let desc_str = descriptor.to_string();
    let canonical = strip_checksum(&desc_str);
    let (threshold, num_signers, function) = extract_metadata_from_canonical(canonical)?;

    if num_signers == 0 {
        return Err(Error::InvalidSignerCount);
    }
    if threshold == 0 || threshold > num_signers {
        return Err(Error::InvalidThreshold {
            k: threshold,
            n: num_signers,
        });
    }

    Ok(ParsedSingle {
        descriptor,
        threshold,
        num_signers,
        function,
    })
}

fn validate_pair(ext: &ParsedSingle, int: &ParsedSingle) -> Result<(), Error> {
    if ext.threshold != int.threshold {
        return Err(Error::DescriptorPairMismatch(format!(
            "threshold mismatch: external={}, internal={}",
            ext.threshold, int.threshold
        )));
    }
    if ext.num_signers != int.num_signers {
        return Err(Error::DescriptorPairMismatch(format!(
            "signer count mismatch: external={}, internal={}",
            ext.num_signers, int.num_signers
        )));
    }
    if ext.function != int.function {
        return Err(Error::DescriptorPairMismatch(
            "function kind mismatch: one uses multi and the other sortedmulti".to_string(),
        ));
    }

    let ext_norm = normalize_for_comparison(&ext.descriptor.to_string());
    let int_norm = normalize_for_comparison(&int.descriptor.to_string());
    if ext_norm != int_norm {
        return Err(Error::DescriptorPairMismatch(
            "descriptor structure mismatch: keys or wrapper differ between external and internal"
                .to_string(),
        ));
    }

    Ok(())
}

/// Normalise a descriptor string for pair comparison by stripping the checksum
/// and replacing branch indices (`/0/*` and `/1/*`) with a common placeholder.
fn normalize_for_comparison(s: &str) -> String {
    strip_checksum(s)
        .replace("/0/*", "/BRANCH/*")
        .replace("/1/*", "/BRANCH/*")
}

/// Count the number of commas at bracket-depth 0 in `s`.
///
/// The string is expected to begin immediately after the opening `(` of
/// `multi(` or `sortedmulti(`.  In `multi(2, k1, k2, k3)` the argument
/// string is `2, k1, k2, k3)`: there are 3 commas at depth 0, which equals
/// the number of keys (the threshold is the first item).
fn count_top_level_commas(s: &str) -> usize {
    let mut depth = 0i32;
    let mut commas = 0usize;
    for c in s.chars() {
        match c {
            '(' | '[' => depth += 1,
            ')' | ']' => {
                if depth == 0 {
                    break;
                }
                depth -= 1;
            }
            ',' if depth == 0 => commas += 1,
            _ => {}
        }
    }
    commas
}

fn strip_checksum(s: &str) -> &str {
    match s.rfind('#') {
        Some(pos) => &s[..pos],
        None => s,
    }
}

// ── Serde helpers (mirrors descriptor.rs) ────────────────────────────────────

fn serialize_descriptor<S>(
    descriptor: &Descriptor<DescriptorPublicKey>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&descriptor.to_string())
}

fn deserialize_descriptor<'de, D>(
    deserializer: D,
) -> Result<Descriptor<DescriptorPublicKey>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let secp = secp256k1::Secp256k1::signing_only();
    let s = String::deserialize(deserializer)?;
    let (desc, _) = Descriptor::<DescriptorPublicKey>::parse_descriptor(&secp, &s)
        .map_err(serde::de::Error::custom)?;
    Ok(desc)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Positive vectors ──────────────────────────────────────────────────────

    /// Ordered multi with raw compressed public keys — spec positive vector 1.
    /// Tests metadata extraction without requiring a full pair.
    #[test]
    fn test_ordered_multi_raw_pubkeys_metadata() {
        let desc = "wsh(multi(2,\
            03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,\
            03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb,\
            03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a))";

        let (threshold, num_signers, function) = extract_multisig_metadata(desc).unwrap();

        assert_eq!(threshold, 2);
        assert_eq!(num_signers, 3);
        assert_eq!(function, MultiFunctionKind::Multi);
    }

    /// sh(sortedmulti(...)) — kept as a parser regression test even though it
    /// is rejected as unsupported for import (spec positive vector 2 note).
    #[test]
    fn test_sh_sortedmulti_rejected() {
        let desc = "sh(sortedmulti(2,\
            03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe,\
            022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01))";

        let err = MultisigDescriptorPair::try_from_str(desc).unwrap_err();
        assert!(
            matches!(err, Error::UnsupportedDescriptorKind(_)),
            "expected UnsupportedDescriptorKind, got: {err}"
        );
    }

    /// Xpub-based watch-only sortedmulti — spec positive vector 3.
    /// Single descriptor (non-multipath) — metadata extraction only.
    #[test]
    fn test_xpub_sortedmulti_metadata() {
        let desc = "wsh(sortedmulti(1,\
            xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*,\
            xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*))";

        let (threshold, num_signers, function) = extract_multisig_metadata(desc).unwrap();

        assert_eq!(threshold, 1);
        assert_eq!(num_signers, 2);
        assert_eq!(function, MultiFunctionKind::SortedMulti);
    }

    /// Full Bitcoin Core 2-of-3 receive descriptor with tpubs, origin info,
    /// and checksum — spec positive vector 4.
    #[test]
    fn test_core_2of3_tpub_single_descriptor_metadata() {
        let desc = "wsh(sortedmulti(2,\
            [6f53d49c/44h/1h/0h]tpubDDjsCRDQ9YzyaAq9rspCfq8RZFrWoBpYnLxK6sS2hS2yukqSczgcYiur8Scx4Hd5AZatxTuzMtJQJhchufv1FRFanLqUP7JHwusSSpfcEp2/0/*,\
            [e6807791/44h/1h/0h]tpubDDAfvogaaAxaFJ6c15ht7Tq6ZmiqFYfrSmZsHu7tHXBgnjMZSHAeHSwhvjARNA6Qybon4ksPksjRbPDVp7yXA1KjTjSd5x18KHqbppnXP1s/0/*,\
            [367c9cfa/44h/1h/0h]tpubDDtPnSgWYk8dDnaDwnof4ehcnjuL5VoUt1eW2MoAed1grPHuXPDnkX1fWMvXfcz3NqFxPbhqNZ3QBdYjLz2hABeM9Z2oqMR1Gt2HHYDoCgh/0/*))#av0kxgw0";

        let (threshold, num_signers, function) = extract_multisig_metadata(desc).unwrap();

        assert_eq!(threshold, 2);
        assert_eq!(num_signers, 3);
        assert_eq!(function, MultiFunctionKind::SortedMulti);
    }

    /// Full Bitcoin Core 2-of-3 external + internal pair — spec positive vector 4
    /// extended.
    #[test]
    fn test_core_2of3_tpub_pair() {
        let external = "wsh(sortedmulti(2,\
            [6f53d49c/44h/1h/0h]tpubDDjsCRDQ9YzyaAq9rspCfq8RZFrWoBpYnLxK6sS2hS2yukqSczgcYiur8Scx4Hd5AZatxTuzMtJQJhchufv1FRFanLqUP7JHwusSSpfcEp2/0/*,\
            [e6807791/44h/1h/0h]tpubDDAfvogaaAxaFJ6c15ht7Tq6ZmiqFYfrSmZsHu7tHXBgnjMZSHAeHSwhvjARNA6Qybon4ksPksjRbPDVp7yXA1KjTjSd5x18KHqbppnXP1s/0/*,\
            [367c9cfa/44h/1h/0h]tpubDDtPnSgWYk8dDnaDwnof4ehcnjuL5VoUt1eW2MoAed1grPHuXPDnkX1fWMvXfcz3NqFxPbhqNZ3QBdYjLz2hABeM9Z2oqMR1Gt2HHYDoCgh/0/*))";

        let internal = "wsh(sortedmulti(2,\
            [6f53d49c/44h/1h/0h]tpubDDjsCRDQ9YzyaAq9rspCfq8RZFrWoBpYnLxK6sS2hS2yukqSczgcYiur8Scx4Hd5AZatxTuzMtJQJhchufv1FRFanLqUP7JHwusSSpfcEp2/1/*,\
            [e6807791/44h/1h/0h]tpubDDAfvogaaAxaFJ6c15ht7Tq6ZmiqFYfrSmZsHu7tHXBgnjMZSHAeHSwhvjARNA6Qybon4ksPksjRbPDVp7yXA1KjTjSd5x18KHqbppnXP1s/1/*,\
            [367c9cfa/44h/1h/0h]tpubDDtPnSgWYk8dDnaDwnof4ehcnjuL5VoUt1eW2MoAed1grPHuXPDnkX1fWMvXfcz3NqFxPbhqNZ3QBdYjLz2hABeM9Z2oqMR1Gt2HHYDoCgh/1/*))";

        let input = format!("{external}\n{internal}");
        let pair = MultisigDescriptorPair::try_from_str(&input).unwrap();

        assert_eq!(pair.threshold, 2);
        assert_eq!(pair.num_signers, 3);
        assert_eq!(pair.function, MultiFunctionKind::SortedMulti);
        // miniscript normalises `h` to `'` in hardened path notation, so compare
        // the canonical descriptor object rather than the raw input string.
        let ext_str = pair.external.to_string();
        let int_str = pair.internal.to_string();
        assert!(ext_str.contains("/0/*"), "external should contain /0/*");
        assert!(int_str.contains("/1/*"), "internal should contain /1/*");
        assert!(
            ext_str.contains("tpubDDjsCRDQ9Yzy"),
            "expected first tpub in external"
        );
        assert!(
            int_str.contains("tpubDDjsCRDQ9Yzy"),
            "expected first tpub in internal"
        );
    }

    /// Single multipath descriptor — spec positive vector 5 (matching pair).
    #[test]
    fn test_multipath_sortedmulti_pair() {
        // Multipath form using <0;1> — miniscript splits into external/internal.
        let multipath = "wsh(sortedmulti(2,\
            [6f53d49c/44h/1h/0h]tpubDDjsCRDQ9YzyaAq9rspCfq8RZFrWoBpYnLxK6sS2hS2yukqSczgcYiur8Scx4Hd5AZatxTuzMtJQJhchufv1FRFanLqUP7JHwusSSpfcEp2/<0;1>/*,\
            [e6807791/44h/1h/0h]tpubDDAfvogaaAxaFJ6c15ht7Tq6ZmiqFYfrSmZsHu7tHXBgnjMZSHAeHSwhvjARNA6Qybon4ksPksjRbPDVp7yXA1KjTjSd5x18KHqbppnXP1s/<0;1>/*,\
            [367c9cfa/44h/1h/0h]tpubDDtPnSgWYk8dDnaDwnof4ehcnjuL5VoUt1eW2MoAed1grPHuXPDnkX1fWMvXfcz3NqFxPbhqNZ3QBdYjLz2hABeM9Z2oqMR1Gt2HHYDoCgh/<0;1>/*))";

        let pair = MultisigDescriptorPair::try_from_str(multipath).unwrap();

        assert_eq!(pair.threshold, 2);
        assert_eq!(pair.num_signers, 3);
        assert_eq!(pair.function, MultiFunctionKind::SortedMulti);

        // External keys must use /0/*, internal must use /1/*.
        let ext_str = pair.external.to_string();
        let int_str = pair.internal.to_string();
        assert!(ext_str.contains("/0/*"), "external should contain /0/*");
        assert!(int_str.contains("/1/*"), "internal should contain /1/*");
    }

    #[test]
    fn test_multipath_requires_exactly_two_paths() {
        let multipath = "wsh(sortedmulti(2,\
            [6f53d49c/44h/1h/0h]tpubDDjsCRDQ9YzyaAq9rspCfq8RZFrWoBpYnLxK6sS2hS2yukqSczgcYiur8Scx4Hd5AZatxTuzMtJQJhchufv1FRFanLqUP7JHwusSSpfcEp2/<0;1;2>/*,\
            [e6807791/44h/1h/0h]tpubDDAfvogaaAxaFJ6c15ht7Tq6ZmiqFYfrSmZsHu7tHXBgnjMZSHAeHSwhvjARNA6Qybon4ksPksjRbPDVp7yXA1KjTjSd5x18KHqbppnXP1s/<0;1;2>/*,\
            [367c9cfa/44h/1h/0h]tpubDDtPnSgWYk8dDnaDwnof4ehcnjuL5VoUt1eW2MoAed1grPHuXPDnkX1fWMvXfcz3NqFxPbhqNZ3QBdYjLz2hABeM9Z2oqMR1Gt2HHYDoCgh/<0;1;2>/*))";

        let err = MultisigDescriptorPair::try_from_str(multipath).unwrap_err();
        assert!(
            matches!(err, Error::WrongNumberOfSingleDescriptors { count: 3 }),
            "expected WrongNumberOfSingleDescriptors {{ count: 3 }}, got: {err}"
        );
    }

    /// wsh(multi(...)) two-line pair.
    #[test]
    fn test_wsh_multi_pair() {
        // Uses a plain 1-of-2 ordered multi pair with xpubs.
        let external = "wsh(multi(1,\
            xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/0/*,\
            xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/0/*))";
        let internal = "wsh(multi(1,\
            xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/*,\
            xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/*))";

        let input = format!("{external}\n{internal}");
        let pair = MultisigDescriptorPair::try_from_str(&input).unwrap();

        assert_eq!(pair.threshold, 1);
        assert_eq!(pair.num_signers, 2);
        assert_eq!(pair.function, MultiFunctionKind::Multi);
    }

    // ── Negative vectors ──────────────────────────────────────────────────────

    /// Threshold exceeds signer count — spec negative vector.
    #[test]
    fn test_invalid_threshold_too_large() {
        // k=3 but only 2 keys — invalid.
        let external = "wsh(sortedmulti(3,\
            xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/0/*,\
            xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/0/*))";

        // miniscript itself rejects k > n, so we get a ParseError
        let err = MultisigDescriptorPair::try_from_str(external).unwrap_err();
        // miniscript will reject this at parse time as well, which is fine
        assert!(
            matches!(err, Error::ParseError(_) | Error::InvalidThreshold { .. }),
            "expected ParseError or InvalidThreshold, got: {err}"
        );
    }

    /// Private key material (xprv) rejected — spec negative vector.
    #[test]
    fn test_private_key_material_rejected() {
        let desc = "wsh(sortedmulti(1,\
            xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/0/*,\
            xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/*))";

        let err = MultisigDescriptorPair::try_from_str(desc).unwrap_err();
        assert!(
            matches!(err, Error::PrivateKeyMaterialNotAllowed),
            "expected PrivateKeyMaterialNotAllowed, got: {err}"
        );
    }

    /// Taproot multisig (tr + sortedmulti_a) rejected — spec negative vector.
    #[test]
    fn test_taproot_multisig_rejected() {
        // tr() with multi_a is tapscript multisig — not supported in v1.
        let desc = "tr(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,multi_a(1))";

        let err = MultisigDescriptorPair::try_from_str(desc).unwrap_err();
        assert!(
            matches!(err, Error::UnsupportedDescriptorKind(_)),
            "expected UnsupportedDescriptorKind, got: {err}"
        );
    }

    /// Miniscript policy wsh(thresh(...)) rejected — spec negative vector.
    #[test]
    fn test_miniscript_policy_rejected() {
        let desc = "wsh(thresh(2,pk(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/0/*),pk(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/*)))";

        let err = MultisigDescriptorPair::try_from_str(desc).unwrap_err();
        assert!(
            matches!(err, Error::UnsupportedPolicyDescriptor),
            "expected UnsupportedPolicyDescriptor, got: {err}"
        );
    }

    /// Single descriptor without a pair — spec negative vector.
    #[test]
    fn test_missing_internal_descriptor() {
        let external = "wsh(sortedmulti(2,\
            [6f53d49c/44h/1h/0h]tpubDDjsCRDQ9YzyaAq9rspCfq8RZFrWoBpYnLxK6sS2hS2yukqSczgcYiur8Scx4Hd5AZatxTuzMtJQJhchufv1FRFanLqUP7JHwusSSpfcEp2/0/*,\
            [e6807791/44h/1h/0h]tpubDDAfvogaaAxaFJ6c15ht7Tq6ZmiqFYfrSmZsHu7tHXBgnjMZSHAeHSwhvjARNA6Qybon4ksPksjRbPDVp7yXA1KjTjSd5x18KHqbppnXP1s/0/*))";

        let err = MultisigDescriptorPair::try_from_str(external).unwrap_err();
        assert!(
            matches!(err, Error::MissingInternalDescriptor),
            "expected MissingInternalDescriptor, got: {err}"
        );
    }

    /// sh(multi(...)) rejected — spec negative vector.
    #[test]
    fn test_sh_multi_rejected() {
        let desc = "sh(multi(1,\
            xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,\
            xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL))";

        let err = MultisigDescriptorPair::try_from_str(desc).unwrap_err();
        assert!(
            matches!(err, Error::UnsupportedDescriptorKind(_)),
            "expected UnsupportedDescriptorKind, got: {err}"
        );
    }

    /// Bare multi(...) rejected — spec negative vector.
    #[test]
    fn test_bare_multi_rejected() {
        let desc = "multi(1,\
            xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL,\
            xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL)";

        let err = MultisigDescriptorPair::try_from_str(desc).unwrap_err();
        assert!(
            matches!(err, Error::UnsupportedDescriptorKind(_)),
            "expected UnsupportedDescriptorKind, got: {err}"
        );
    }

    /// Mismatched pair — different thresholds — spec negative vector.
    #[test]
    fn test_mismatched_pair_different_threshold() {
        // External uses k=1, internal uses k=2 — should fail.
        let external = "wsh(sortedmulti(1,\
            xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/0/*,\
            xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/0/*))";
        let internal = "wsh(sortedmulti(2,\
            xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/*,\
            xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/*))";

        let input = format!("{external}\n{internal}");
        let err = MultisigDescriptorPair::try_from_str(&input).unwrap_err();
        assert!(
            matches!(err, Error::DescriptorPairMismatch(_)),
            "expected DescriptorPairMismatch, got: {err}"
        );
    }

    /// Mismatched pair — different keys — spec negative vector.
    #[test]
    fn test_mismatched_pair_different_keys() {
        // External and internal use different xpubs — should fail.
        let external = "wsh(sortedmulti(1,\
            xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/0/*,\
            xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/0/*))";
        // Internal uses a different second key.
        let internal = "wsh(sortedmulti(1,\
            xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/*,\
            xpub6CiKnWv7PPyyeb4kCwK4fidKqVjPfD9TP6MiXnzBVGZYNanNdY3mMvywcrdDc6wK82jyBSd95vsk26QujnJWPrSaPfYeyW7NyX37HHGtfQM/1/*))";

        let input = format!("{external}\n{internal}");
        let err = MultisigDescriptorPair::try_from_str(&input).unwrap_err();
        assert!(
            matches!(err, Error::DescriptorPairMismatch(_)),
            "expected DescriptorPairMismatch, got: {err}"
        );
    }

    // ── is_multisig_like detection ────────────────────────────────────────────

    #[test]
    fn test_is_multisig_like_positive() {
        assert!(MultisigDescriptorPair::is_multisig_like(
            "wsh(sortedmulti(2,key1,key2))"
        ));
        assert!(MultisigDescriptorPair::is_multisig_like(
            "wsh(multi(1,key1,key2))"
        ));
        assert!(MultisigDescriptorPair::is_multisig_like(
            "sh(multi(1,key1,key2))"
        ));
        assert!(MultisigDescriptorPair::is_multisig_like(
            "multi(1,key1,key2)"
        ));
        assert!(MultisigDescriptorPair::is_multisig_like(
            "tr(key,multi_a(1,k1,k2))"
        ));
        assert!(MultisigDescriptorPair::is_multisig_like(
            "wsh(thresh(2,pk(k1),pk(k2)))"
        ));
    }

    #[test]
    fn test_is_multisig_like_negative() {
        assert!(!MultisigDescriptorPair::is_multisig_like(
            "wpkh([deadbeef/84h/0h/0h]xpub123/<0;1>/*)"
        ));
        assert!(!MultisigDescriptorPair::is_multisig_like(
            "not a descriptor"
        ));
        assert!(!MultisigDescriptorPair::is_multisig_like(
            "xpub6CiKnWv7PPyyeb4kCwK4fidKqVjPfD9TP6MiXnzBVGZYNanNdY3mMvywcrdDc6wK82jyBSd95vsk26QujnJWPrSaPfYeyW7NyX37HHGtfQM"
        ));
    }

    // ── Metadata extraction edge cases ────────────────────────────────────────

    #[test]
    fn test_count_top_level_commas_simple() {
        // "2,k1,k2,k3)" → 3 commas → 3 keys
        assert_eq!(count_top_level_commas("2,k1,k2,k3)"), 3);
    }

    #[test]
    fn test_count_top_level_commas_with_brackets() {
        // "[fp/path]xpub/0/*" contains slashes but no nested commas.
        assert_eq!(
            count_top_level_commas("2,[fp/path]xpub1/0/*,[fp/path]xpub2/0/*)"),
            2
        );
    }
}
