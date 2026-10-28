//! Static output-size estimation for flow steps (`--explain`).
//!
//! `dpa run --explain` prints a per-step input→output estimate before
//! execution, so users can spot runaway inflations *before* the dynamic
//! `--max-step-output-bytes` cap trips mid-run. Estimation is deliberately
//! conservative and advisory-only:
//!
//! - fixed-length families (hash / uuid / random) return exact sizes;
//! - codec families return a constant ratio (hex ×2, base64 ×4/3, ...);
//! - content-dependent ops (analyze / extract / transform / compress ...)
//!   return [`StaticEstimate::Unknown`] and the explain table prints "?"
//!   instead of inventing a number.
//!
//! Nothing here feeds back into execution: estimates never change an op's
//! default behaviour nor the dynamic cap.

use std::collections::HashMap;

use crate::i18n;
use crate::ops::Op;

/// A static, argument-aware output-size estimate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StaticEstimate {
    /// Fixed byte count regardless of input size.
    Fixed(usize),
    /// Output ≈ input × num / den (rounded down; shown with a `~` prefix).
    Scale { num: u64, den: u64 },
    /// Content-dependent: cannot be estimated without running the op.
    Unknown,
}

/// Fixed hex digest lengths (in characters) for known hash ops.
fn hash_fixed_len(op_name: &str) -> Option<usize> {
    match op_name {
        "dpa:md5" | "dpa:nt-hash" | "dpa:lm-hash" => Some(32),
        "dpa:sha1" => Some(40),
        "dpa:sha224" | "dpa:sha3:224" | "dpa:sm3" => Some(56),
        "dpa:sha256" | "dpa:sha3:256" => Some(64),
        "dpa:sha384" | "dpa:sha3:384" => Some(96),
        "dpa:sha512" | "dpa:sha3:512" => Some(128),
        "dpa:crc16" => Some(4),
        "dpa:crc32" | "dpa:crc32c" => Some(8),
        _ => None,
    }
}

/// Estimate an op's output byte count from its family/kind and arguments.
/// `input_len` is only consumed by ratio families; fixed estimates ignore it.
pub fn estimate_for_op(
    op: &Op,
    args: &HashMap<String, String>,
    _input_len: Option<usize>,
) -> StaticEstimate {
    // Name-based overrides for variants whose derived family is not the
    // generic codec family (base64:url keeps `family = base64:url`) and for
    // fixed-length ops with parameter-dependent registration.
    match op.name.as_str() {
        "dpa:base64:url:encode" => return StaticEstimate::Scale { num: 4, den: 3 },
        "dpa:base64:url:decode" => return StaticEstimate::Scale { num: 3, den: 4 },
        "dpa:sm4:mac" => return StaticEstimate::Fixed(32),
        _ => {}
    }
    match (op.family.as_str(), op.kind.as_str()) {
        ("hex", "encode") => StaticEstimate::Scale { num: 2, den: 1 },
        ("hex", "decode") => StaticEstimate::Scale { num: 1, den: 2 },
        ("base64", "encode") => StaticEstimate::Scale { num: 4, den: 3 },
        ("base64", "decode") => StaticEstimate::Scale { num: 3, den: 4 },
        ("base32", "encode") => StaticEstimate::Scale { num: 8, den: 5 },
        ("base32", "decode") => StaticEstimate::Scale { num: 5, den: 8 },
        ("base58" | "base62" | "base85", "encode") => StaticEstimate::Scale { num: 4, den: 3 },
        ("base58" | "base62" | "base85", "decode") => StaticEstimate::Scale { num: 3, den: 4 },
        ("hash", _) => match hash_fixed_len(&op.name) {
            Some(n) => StaticEstimate::Fixed(n),
            None => StaticEstimate::Unknown,
        },
        ("generate", "uuid" | "uuid4") => StaticEstimate::Fixed(36),
        ("generate", "random") => {
            let n = args
                .get("bytes")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(16);
            StaticEstimate::Fixed(n)
        }
        ("random", "hex") => {
            let n = args
                .get("bytes")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(16);
            StaticEstimate::Fixed(n * 2)
        }
        // Length-preserving crypto / byte transforms (encrypt/decrypt/xor).
        (
            "xor" | "aes" | "blowfish" | "chacha20" | "des" | "des3" | "sm4" | "rc4" | "tea"
            | "xtea" | "xxtea",
            _,
        ) => StaticEstimate::Scale { num: 1, den: 1 },
        _ => StaticEstimate::Unknown,
    }
}

/// Human-readable input-size cell ("?" for unknown stdin / multi-input).
pub fn render_size(n: Option<usize>) -> String {
    match n {
        Some(x) => x.to_string(),
        None => "?".to_string(),
    }
}

/// Render an estimate as a localized explain-table cell.
pub fn render_estimate(est: &StaticEstimate, input_len: Option<usize>) -> String {
    match est {
        StaticEstimate::Unknown => i18n::t("explain.out_unknown").to_string(),
        StaticEstimate::Fixed(n) => i18n::tf("explain.out_fixed", &[n.to_string().as_str()]),
        StaticEstimate::Scale { num, den } => match input_len {
            Some(len) => i18n::tf(
                "explain.out_ratio",
                &[
                    ((len as u64 * num / den) as usize).to_string().as_str(),
                    num.to_string().as_str(),
                    den.to_string().as_str(),
                ],
            ),
            None => i18n::t("explain.out_unknown").to_string(),
        },
    }
}

/// Best-effort input size for the *next* step after `est`.
pub fn next_input(est: &StaticEstimate, cur: Option<usize>) -> Option<usize> {
    match (est, cur) {
        (StaticEstimate::Fixed(n), _) => Some(*n),
        (StaticEstimate::Scale { num, den }, Some(len)) => Some((len as u64 * num / den) as usize),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops;

    fn args_of(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn codec_ratio_estimates() {
        let a = args_of(&[]);
        let hex = ops::find_op("dpa:hex:encode").unwrap();
        assert_eq!(
            estimate_for_op(hex, &a, None),
            StaticEstimate::Scale { num: 2, den: 1 }
        );
        let b64 = ops::find_op("dpa:base64:decode").unwrap();
        assert_eq!(
            estimate_for_op(b64, &a, None),
            StaticEstimate::Scale { num: 3, den: 4 }
        );
    }

    #[test]
    fn fixed_length_estimates() {
        let a = args_of(&[]);
        let sha = ops::find_op("dpa:sha256").unwrap();
        assert_eq!(estimate_for_op(sha, &a, None), StaticEstimate::Fixed(64));
        let uuid = ops::find_op("dpa:uuid").unwrap();
        assert_eq!(estimate_for_op(uuid, &a, None), StaticEstimate::Fixed(36));
        let rnd = ops::find_op("dpa:random").unwrap();
        assert_eq!(estimate_for_op(rnd, &a, None), StaticEstimate::Fixed(16));
        let rnd32 = ops::find_op("dpa:random:hex").unwrap();
        let a32 = args_of(&[("bytes", "32")]);
        assert_eq!(
            estimate_for_op(rnd32, &a32, None),
            StaticEstimate::Fixed(64)
        );
    }

    #[test]
    fn content_dependent_is_unknown() {
        let a = args_of(&[]);
        for name in ["dpa:analyze:hash", "dpa:entropy", "dpa:extract:domains"] {
            let op = ops::find_op(name).unwrap();
            assert_eq!(estimate_for_op(op, &a, None), StaticEstimate::Unknown);
        }
    }

    #[test]
    fn next_input_propagates_sizes() {
        let est = StaticEstimate::Scale { num: 2, den: 1 };
        assert_eq!(next_input(&est, Some(10)), Some(20));
        assert_eq!(next_input(&est, None), None);
        let est = StaticEstimate::Fixed(64);
        assert_eq!(next_input(&est, None), Some(64));
        assert_eq!(next_input(&StaticEstimate::Unknown, Some(10)), None);
    }
}
