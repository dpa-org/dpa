//! hmac_kdf ops (split from mod.rs).

use super::super::{ArgSpec, Op, StreamingOp};
use super::*;
use crate::i18n;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use sha3::{Sha3_256, Sha3_512};
use sm3::Sm3;
use std::collections::HashMap;

/// Upper bound for derived key material (1 GiB). Guards against accidental
/// resource exhaustion from a huge `length` argument; typical derivations
/// (a few KiB) are unaffected.
const MAX_DERIVED_LENGTH: u64 = 1 << 30;

pub fn ops() -> Vec<Op> {
    vec![
        stream_op!(
            "dpa:hmac",
            "crypto",
            "op.hmac.desc",
            &[
                ArgSpec {
                    name: "key",
                    required: true,
                    description: "op.hmac.arg.key",
                    format: crate::ops::ArgFormat::HexOrUtf8,
                },
                ArgSpec {
                    name: "algo",
                    required: false,
                    description: "op.hmac.arg.algo",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            hmac,
            make_hmac
        ),
        op!(
            "dpa:pbkdf2",
            "crypto",
            "op.pbkdf2.desc",
            &[
                ArgSpec {
                    name: "key",
                    required: false,
                    description: "op.pbkdf2.arg.key",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "salt",
                    required: false,
                    description: "op.pbkdf2.arg.salt",
                    format: crate::ops::ArgFormat::HexOrUtf8,
                },
                ArgSpec {
                    name: "iterations",
                    required: false,
                    description: "op.pbkdf2.arg.iterations",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "length",
                    required: false,
                    description: "op.pbkdf2.arg.length",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "hash",
                    required: false,
                    description: "op.pbkdf2.arg.hash",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            pbkdf2
        ),
        op!(
            "dpa:hkdf",
            "crypto",
            "op.hkdf.desc",
            &[
                ArgSpec {
                    name: "key",
                    required: false,
                    description: "op.hkdf.arg.key",
                    format: crate::ops::ArgFormat::HexOrUtf8,
                },
                ArgSpec {
                    name: "salt",
                    required: false,
                    description: "op.hkdf.arg.salt",
                    format: crate::ops::ArgFormat::HexOrUtf8,
                },
                ArgSpec {
                    name: "info",
                    required: false,
                    description: "op.hkdf.arg.info",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "length",
                    required: false,
                    description: "op.hkdf.arg.length",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "hash",
                    required: false,
                    description: "op.hkdf.arg.hash",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            hkdf
        ),
    ]
}

/// Streaming HMAC: Mac updates incrementally; finish outputs the digest.
struct HmacStream {
    mac: Box<dyn MacDyn>,
}

trait MacDyn {
    fn update(&mut self, data: &[u8]);
    fn finalize_bytes(&mut self) -> Vec<u8>;
}

struct MacWrap<M: Mac>(M);

impl<M: Mac + Clone> MacDyn for MacWrap<M> {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
    fn finalize_bytes(&mut self) -> Vec<u8> {
        self.0.clone().finalize().into_bytes().to_vec()
    }
}

impl StreamingOp for HmacStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.mac.update(chunk);
        Ok(Vec::new())
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        Ok(self.mac.finalize_bytes())
    }
}

pub(crate) fn make_hmac(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    let key = require_key(args)?;
    let algo = opt_arg(args, "algo", "sha256");
    let mac: Box<dyn MacDyn> = match algo {
        "sha1" => Box::new(MacWrap(<Hmac<Sha1> as Mac>::new_from_slice(&key).map_err(
            |e| {
                anyhow::anyhow!(
                    "{}",
                    i18n::tf("err.hmac_sha1_init", &[e.to_string().as_str()])
                )
            },
        )?)),
        "sha256" => Box::new(MacWrap(
            <Hmac<Sha256> as Mac>::new_from_slice(&key).map_err(|e| {
                anyhow::anyhow!(
                    "{}",
                    i18n::tf("err.hmac_sha256_init", &[e.to_string().as_str()])
                )
            })?,
        )),
        "sha512" => Box::new(MacWrap(
            <Hmac<Sha512> as Mac>::new_from_slice(&key).map_err(|e| {
                anyhow::anyhow!(
                    "{}",
                    i18n::tf("err.hmac_sha512_init", &[e.to_string().as_str()])
                )
            })?,
        )),
        "sm3" => Box::new(MacWrap(<Hmac<Sm3> as Mac>::new_from_slice(&key).map_err(
            |e| {
                anyhow::anyhow!(
                    "{}",
                    i18n::tf("err.hmac_sm3_init", &[e.to_string().as_str()])
                )
            },
        )?)),
        "sha3-256" => Box::new(MacWrap(
            <Hmac<Sha3_256> as Mac>::new_from_slice(&key).map_err(|e| {
                anyhow::anyhow!(
                    "{}",
                    i18n::tf("err.hmac_sha3_256_init", &[e.to_string().as_str()])
                )
            })?,
        )),
        "sha3-512" => Box::new(MacWrap(
            <Hmac<Sha3_512> as Mac>::new_from_slice(&key).map_err(|e| {
                anyhow::anyhow!(
                    "{}",
                    i18n::tf("err.hmac_sha3_512_init", &[e.to_string().as_str()])
                )
            })?,
        )),
        other => anyhow::bail!(
            "{}",
            i18n::tf(
                "err.unknown_algo",
                &[other, "sha1 / sha256 / sha512 / sm3 / sha3-256 / sha3-512"]
            )
        ),
    };
    Ok(Box::new(HmacStream { mac }))
}

pub(crate) fn hmac(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let key = require_key(args)?;
    let algo = opt_arg(args, "algo", "sha256");
    match algo {
        "sha1" => Ok(<Hmac<Sha1> as Mac>::new_from_slice(&key)
            .map_err(|e| {
                anyhow::anyhow!(
                    "{}",
                    i18n::tf("err.hmac_sha1_init", &[e.to_string().as_str()])
                )
            })?
            .chain_update(input)
            .finalize()
            .into_bytes()
            .to_vec()),
        "sha256" => Ok(<Hmac<Sha256> as Mac>::new_from_slice(&key)
            .map_err(|e| {
                anyhow::anyhow!(
                    "{}",
                    i18n::tf("err.hmac_sha256_init", &[e.to_string().as_str()])
                )
            })?
            .chain_update(input)
            .finalize()
            .into_bytes()
            .to_vec()),
        "sha512" => Ok(<Hmac<Sha512> as Mac>::new_from_slice(&key)
            .map_err(|e| {
                anyhow::anyhow!(
                    "{}",
                    i18n::tf("err.hmac_sha512_init", &[e.to_string().as_str()])
                )
            })?
            .chain_update(input)
            .finalize()
            .into_bytes()
            .to_vec()),
        "sm3" => Ok(<Hmac<Sm3> as Mac>::new_from_slice(&key)
            .map_err(|e| {
                anyhow::anyhow!(
                    "{}",
                    i18n::tf("err.hmac_sm3_init", &[e.to_string().as_str()])
                )
            })?
            .chain_update(input)
            .finalize()
            .into_bytes()
            .to_vec()),
        "sha3-256" => Ok(<Hmac<Sha3_256> as Mac>::new_from_slice(&key)
            .map_err(|e| {
                anyhow::anyhow!(
                    "{}",
                    i18n::tf("err.hmac_sha3_256_init", &[e.to_string().as_str()])
                )
            })?
            .chain_update(input)
            .finalize()
            .into_bytes()
            .to_vec()),
        "sha3-512" => Ok(<Hmac<Sha3_512> as Mac>::new_from_slice(&key)
            .map_err(|e| {
                anyhow::anyhow!(
                    "{}",
                    i18n::tf("err.hmac_sha3_512_init", &[e.to_string().as_str()])
                )
            })?
            .chain_update(input)
            .finalize()
            .into_bytes()
            .to_vec()),
        other => anyhow::bail!(
            "{}",
            i18n::tf(
                "err.unknown_algo",
                &[other, "sha1 / sha256 / sha512 / sm3 / sha3-256 / sha3-512"]
            )
        ),
    }
}

/// One-shot HMAC over `data` with `key` (SHA-1 / SHA-256 / SHA-512 / SM3 /
/// SHA3-256 / SHA3-512).
pub(crate) fn hmac_bytes(hash: &str, key: &[u8], data: &[u8]) -> anyhow::Result<Vec<u8>> {
    macro_rules! do_hmac {
        ($t:ty) => {{
            let mut m = <$t as Mac>::new_from_slice(key)?;
            m.update(data);
            Ok(m.finalize().into_bytes().to_vec())
        }};
    }
    match hash {
        "sha1" => do_hmac!(Hmac<Sha1>),
        "sha256" => do_hmac!(Hmac<Sha256>),
        "sha512" => do_hmac!(Hmac<Sha512>),
        "sm3" => do_hmac!(Hmac<Sm3>),
        "sha3-256" => do_hmac!(Hmac<Sha3_256>),
        "sha3-512" => do_hmac!(Hmac<Sha3_512>),
        other => anyhow::bail!(
            "{}",
            i18n::tf(
                "err.unknown_hash_variant",
                &[other, "sha1 / sha256 / sha512 / sm3 / sha3-256 / sha3-512"]
            )
        ),
    }
}

pub(crate) fn parse_derivation_args(
    args: &HashMap<String, String>,
) -> anyhow::Result<(Vec<u8>, String)> {
    let key = match args.get("key") {
        None => Vec::new(),
        Some(s) => parse_key(s)?,
    };
    let hash = opt_arg(args, "hash", "sha256").to_string();
    Ok((key, hash))
}

pub(crate) fn parse_u64_arg(
    args: &HashMap<String, String>,
    name: &str,
    default: u64,
) -> anyhow::Result<u64> {
    match args.get(name) {
        None => Ok(default),
        Some(s) => s
            .trim()
            .parse::<u64>()
            .map_err(|_| anyhow::anyhow!("{}", i18n::tf("err.invalid_number", &[s.as_str()]))),
    }
}

pub(crate) fn pbkdf2(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let (password, hash) = parse_derivation_args(args)?;
    // Password priority: explicit 'key' arg wins; otherwise the op input is the password.
    let password = if password.is_empty() {
        input
    } else {
        &password
    };
    let salt = match args.get("salt") {
        None => Vec::new(),
        Some(s) => parse_key(s)?,
    };
    let iterations = parse_u64_arg(args, "iterations", 10_000)?;
    if iterations > u32::MAX as u64 {
        anyhow::bail!(
            "{}",
            crate::i18n::tf(
                "err.kdf_iterations_exceeded",
                &[
                    iterations.to_string().as_str(),
                    u32::MAX.to_string().as_str()
                ]
            )
        );
    }
    let iterations = iterations as u32;
    let length = parse_u64_arg(args, "length", 32)?;
    if length > MAX_DERIVED_LENGTH {
        anyhow::bail!(
            "{}",
            crate::i18n::tf(
                "err.kdf_length_exceeded",
                &[
                    length.to_string().as_str(),
                    MAX_DERIVED_LENGTH.to_string().as_str()
                ]
            )
        );
    }
    let length = length as usize;
    let mut out = Vec::with_capacity(length);
    let mut block_index: u32 = 1;
    while out.len() < length {
        let mut salt_block = salt.clone();
        salt_block.extend_from_slice(&block_index.to_be_bytes());
        let mut u = hmac_bytes(&hash, password, &salt_block)?;
        let mut t = u.clone();
        for _ in 1..iterations {
            u = hmac_bytes(&hash, password, &u)?;
            for (a, b) in t.iter_mut().zip(u.iter()) {
                *a ^= b;
            }
        }
        out.extend_from_slice(&t);
        block_index += 1;
    }
    out.truncate(length);
    Ok(out)
}

pub(crate) fn hkdf(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let (ikm, hash) = parse_derivation_args(args)?;
    let ikm = if ikm.is_empty() { input } else { &ikm };
    let salt = match args.get("salt") {
        None => Vec::new(),
        Some(s) => parse_key(s)?,
    };
    let info = match args.get("info") {
        None => Vec::new(),
        Some(s) => parse_key(s)?,
    };
    let length = parse_u64_arg(args, "length", 32)?;
    if length > MAX_DERIVED_LENGTH {
        anyhow::bail!(
            "{}",
            crate::i18n::tf(
                "err.kdf_length_exceeded",
                &[
                    length.to_string().as_str(),
                    MAX_DERIVED_LENGTH.to_string().as_str()
                ]
            )
        );
    }
    let length = length as usize;
    let h_len = match hash.as_str() {
        "sha1" => 20usize,
        "sha256" => 32,
        "sha512" => 64,
        "sm3" => 32,
        "sha3-256" => 32,
        "sha3-512" => 64,
        _ => anyhow::bail!(
            "{}",
            i18n::tf(
                "err.unknown_hash_variant",
                &[
                    hash.as_str(),
                    "sha1 / sha256 / sha512 / sm3 / sha3-256 / sha3-512"
                ]
            )
        ),
    };
    // RFC 5869 restricts the expand loop to 255 blocks (T(1)..=T(255)); a
    // larger length would overflow the u8 block counter, so reject it here
    // with a descriptive error instead of panicking in debug builds.
    let hkdf_max = 255usize * h_len;
    if length > hkdf_max {
        anyhow::bail!(
            "{}",
            crate::i18n::tf(
                "err.kdf_length_exceeded",
                &[length.to_string().as_str(), hkdf_max.to_string().as_str()]
            )
        );
    }
    // Extract: PRK = HMAC-Hash(salt || all-zero salt of HashLen, IKM)
    let salt_eff = if salt.is_empty() {
        vec![0u8; h_len]
    } else {
        salt
    };
    let prk = hmac_bytes(&hash, &salt_eff, ikm)?;
    // Expand: T(i) = HMAC-Hash(PRK, T(i-1) || info || byte(i))
    let mut out = Vec::with_capacity(length);
    let mut t: Vec<u8> = Vec::new();
    let mut counter: u8 = 0;
    while out.len() < length {
        counter += 1;
        let mut input = t.clone();
        input.extend_from_slice(&info);
        input.push(counter);
        t = hmac_bytes(&hash, &prk, &input)?;
        out.extend_from_slice(&t);
    }
    out.truncate(length);
    Ok(out)
}
