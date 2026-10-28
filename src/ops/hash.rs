//! Hash ops: MD5 / SHA-1 / SHA-224 / SHA-256 / SHA-384 / SHA-512 / SM3 /
//! SHA3-256 / SHA3-512 / BLAKE2b-256 / BLAKE2b-512 / RIPEMD-160 / CRC-32 / CRC-32C.
//!
//! Design note: ops output raw digest bytes (not hex strings) to stay composable -
//! chain a `dpa:hex:encode` step to display, Unix-pipeline style.

use std::collections::HashMap;

use blake2::digest::{Update, VariableOutput};
use blake2::{Blake2b512, Blake2bVar, Blake2sVar};
use md4::Md4;
use md5::Md5;
use ripemd::{Ripemd128, Ripemd160, Ripemd256, Ripemd320};
use sha1::Sha1;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
use sha3::digest::{ExtendableOutput, XofReader};
use sha3::{
    Keccak224, Keccak256, Keccak384, Keccak512, Sha3_224, Sha3_256, Sha3_384, Sha3_512, Shake128,
    Shake256,
};
use sm3::Sm3;
use whirlpool::Whirlpool;

use super::crypto::opt_arg;
use super::{ArgSpec, Op, StreamingOp};
use crate::i18n;

pub fn ops() -> Vec<Op> {
    vec![
        stream_op!(
            "dpa:md5",
            "hash",
            "op.md5.desc",
            &[],
            hash_md5,
            make_hash_md5
        ),
        stream_op!(
            "dpa:sha1",
            "hash",
            "op.sha1.desc",
            &[ArgSpec {
                name: "rounds",
                required: false,
                description: "op.sha1.arg.rounds",
                format: crate::ops::ArgFormat::Utf8,
            }],
            hash_sha1,
            make_hash_sha1
        ),
        stream_op!(
            "dpa:sha224",
            "hash",
            "op.sha224.desc",
            &[ArgSpec {
                name: "rounds",
                required: false,
                description: "op.sha224.arg.rounds",
                format: crate::ops::ArgFormat::Utf8,
            }],
            hash_sha224,
            make_hash_sha224
        ),
        stream_op!(
            "dpa:sha256",
            "hash",
            "op.sha256.desc",
            &[ArgSpec {
                name: "rounds",
                required: false,
                description: "op.sha256.arg.rounds",
                format: crate::ops::ArgFormat::Utf8,
            }],
            hash_sha256,
            make_hash_sha256
        ),
        stream_op!(
            "dpa:sha384",
            "hash",
            "op.sha384.desc",
            &[ArgSpec {
                name: "rounds",
                required: false,
                description: "op.sha384.arg.rounds",
                format: crate::ops::ArgFormat::Utf8,
            }],
            hash_sha384,
            make_hash_sha384
        ),
        stream_op!(
            "dpa:sha512",
            "hash",
            "op.sha512.desc",
            &[ArgSpec {
                name: "rounds",
                required: false,
                description: "op.sha512.arg.rounds",
                format: crate::ops::ArgFormat::Utf8,
            }],
            hash_sha512,
            make_hash_sha512
        ),
        stream_op!(
            "dpa:sm3",
            "hash",
            "op.sm3.desc",
            &[ArgSpec {
                name: "rounds",
                required: false,
                description: "op.sm3.arg.rounds",
                format: crate::ops::ArgFormat::Utf8,
            }],
            hash_sm3,
            make_hash_sm3
        ),
        stream_op!(
            "dpa:sha3:256",
            "hash",
            "op.sha3.256.desc",
            &[],
            hash_sha3_256,
            make_hash_sha3_256
        ),
        stream_op!(
            "dpa:sha3:224",
            "hash",
            "op.sha3.224.desc",
            &[],
            hash_sha3_224,
            make_hash_sha3_224
        ),
        stream_op!(
            "dpa:sha3:384",
            "hash",
            "op.sha3.384.desc",
            &[],
            hash_sha3_384,
            make_hash_sha3_384
        ),
        stream_op!(
            "dpa:sha3:512",
            "hash",
            "op.sha3.512.desc",
            &[],
            hash_sha3_512,
            make_hash_sha3_512
        ),
        stream_op!(
            "dpa:whirlpool",
            "hash",
            "op.whirlpool.desc",
            &[],
            hash_whirlpool,
            make_hash_whirlpool
        ),
        stream_op!(
            "dpa:blake2b:256",
            "hash",
            "op.blake2b.256.desc",
            &[],
            hash_blake2b_256,
            make_hash_blake2b_256
        ),
        stream_op!(
            "dpa:blake2b:512",
            "hash",
            "op.blake2b.512.desc",
            &[],
            hash_blake2b_512,
            make_hash_blake2b_512
        ),
        stream_op!(
            "dpa:blake2b:384",
            "hash",
            "op.blake2b.384.desc",
            &[],
            hash_blake2b_384,
            make_hash_blake2b_384
        ),
        stream_op!(
            "dpa:blake2s:256",
            "hash",
            "op.blake2s.256.desc",
            &[],
            hash_blake2s_256,
            make_hash_blake2s_256
        ),
        stream_op!(
            "dpa:md4",
            "hash",
            "op.md4.desc",
            &[],
            hash_md4,
            make_hash_md4
        ),
        stream_op!(
            "dpa:xxhash32",
            "hash",
            "op.xxhash32.desc",
            &[ArgSpec {
                name: "seed",
                required: false,
                description: "op.xxhash32.arg.seed",
                format: crate::ops::ArgFormat::Utf8,
            }],
            hash_xxhash32,
            make_hash_xxhash32
        ),
        stream_op!(
            "dpa:xxhash64",
            "hash",
            "op.xxhash64.desc",
            &[ArgSpec {
                name: "seed",
                required: false,
                description: "op.xxhash64.arg.seed",
                format: crate::ops::ArgFormat::Utf8,
            }],
            hash_xxhash64,
            make_hash_xxhash64
        ),
        stream_op!(
            "dpa:ripemd160",
            "hash",
            "op.ripemd160.desc",
            &[ArgSpec {
                name: "size",
                required: false,
                description: "op.ripemd160.arg.size",
                format: crate::ops::ArgFormat::Utf8,
            }],
            hash_ripemd160,
            make_hash_ripemd160
        ),
        stream_op!(
            "dpa:crc32",
            "hash",
            "op.crc32.desc",
            &[ArgSpec {
                name: "variant",
                required: false,
                description: "op.crc32.arg.variant",
                format: crate::ops::ArgFormat::Utf8,
            },],
            hash_crc32,
            make_hash_crc32
        ),
        stream_op!(
            "dpa:crc32c",
            "hash",
            "op.crc32c.desc",
            &[ArgSpec {
                name: "variant",
                required: false,
                description: "op.crc32c.arg.variant",
                format: crate::ops::ArgFormat::Utf8,
            },],
            hash_crc32c,
            make_hash_crc32c
        ),
        stream_op!(
            "dpa:crc16",
            "hash",
            "op.crc16.desc",
            &[ArgSpec {
                name: "variant",
                required: false,
                description: "op.crc16.arg.variant",
                format: crate::ops::ArgFormat::Utf8,
            },],
            hash_crc16,
            make_hash_crc16
        ),
        stream_op!(
            "dpa:adler32",
            "hash",
            "op.adler32.desc",
            &[],
            hash_adler32,
            make_hash_adler32
        ),
        stream_op!(
            "dpa:fletcher16",
            "hash",
            "op.fletcher16.desc",
            &[],
            hash_fletcher16,
            make_hash_fletcher16
        ),
        stream_op!(
            "dpa:fletcher32",
            "hash",
            "op.fletcher32.desc",
            &[],
            hash_fletcher32,
            make_hash_fletcher32
        ),
        // Fletcher-8 / Fletcher-64 variants (CyberChef parity)
        stream_op!(
            "dpa:fletcher8",
            "hash",
            "op.fletcher8.desc",
            &[],
            hash_fletcher8,
            make_hash_fletcher8
        ),
        stream_op!(
            "dpa:fletcher64",
            "hash",
            "op.fletcher64.desc",
            &[],
            hash_fletcher64,
            make_hash_fletcher64
        ),
        stream_op!(
            "dpa:keccak",
            "hash",
            "op.keccak.desc",
            &[ArgSpec {
                name: "variant",
                required: false,
                description: "op.keccak.arg.variant",
                format: crate::ops::ArgFormat::Utf8,
            },],
            hash_keccak,
            make_hash_keccak
        ),
        stream_op!(
            "dpa:shake",
            "hash",
            "op.shake.desc",
            &[
                ArgSpec {
                    name: "variant",
                    required: false,
                    description: "op.shake.arg.variant",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "length",
                    required: false,
                    description: "op.shake.arg.length",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            hash_shake,
            make_hash_shake
        ),
        // Windows credential hashes
        op!("dpa:nt-hash", "hash", "op.nt-hash.desc", &[], hash_nt),
        op!("dpa:lm-hash", "hash", "op.lm-hash.desc", &[], hash_lm),
        op!("dpa:ssdeep", "hash", "op.ssdeep.desc", &[], hash_ssdeep),
        // ssdeep signature comparison (CyberChef parity)
        op!(
            "dpa:ssdeep:compare",
            "hash",
            "op.ssdeep.compare.desc",
            &[ArgSpec {
                name: "delimiter",
                required: false,
                description: "op.ssdeep.compare.arg.delimiter",
                format: crate::ops::ArgFormat::Utf8,
            },],
            ssdeep_compare
        ),
        // Luhn checksum (CyberChef parity)
        op!(
            "dpa:luhn",
            "hash",
            "op.luhn.desc",
            &[ArgSpec {
                name: "mode",
                required: false,
                description: "op.luhn.arg.mode",
                format: crate::ops::ArgFormat::Utf8,
            }],
            luhn
        ),
    ]
}

// ---------------------------------------------------------------------------
// Streaming implementation: digest updates incrementally; finish emits the digest once.
// ---------------------------------------------------------------------------

struct DigestStream<D: Digest> {
    h: D,
}

#[allow(clippy::type_complexity)]
fn make_hash<D: Digest + Clone + 'static>()
-> fn(&HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    |args| -> anyhow::Result<Box<dyn StreamingOp>> {
        let rounds = rounds_from_args(args)?;
        if rounds <= 1 {
            Ok(Box::new(DigestStream { h: D::new() }))
        } else {
            let run = move |input: &[u8]| iterated_digest::<D>(input, rounds);
            Ok(Box::new(CollectHashStream {
                buf: Vec::new(),
                run,
            }))
        }
    }
}

fn make_hash_md5(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    make_hash::<Md5>()(args)
}
fn make_hash_sha1(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    make_hash::<Sha1>()(args)
}
fn make_hash_sha256(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    make_hash::<Sha256>()(args)
}
fn make_hash_sha512(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    make_hash::<Sha512>()(args)
}
fn make_hash_sha224(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    make_hash::<Sha224>()(args)
}
fn make_hash_sha384(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    make_hash::<Sha384>()(args)
}
fn make_hash_sm3(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    make_hash::<Sm3>()(args)
}
fn make_hash_sha3_256(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    make_hash::<Sha3_256>()(args)
}
fn make_hash_sha3_224(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    make_hash::<Sha3_224>()(args)
}
fn make_hash_sha3_384(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    make_hash::<Sha3_384>()(args)
}
fn make_hash_sha3_512(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    make_hash::<Sha3_512>()(args)
}
fn make_hash_whirlpool(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    make_hash::<Whirlpool>()(args)
}
fn make_hash_blake2b_512(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    make_hash::<Blake2b512>()(args)
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum RipemdKind {
    R128,
    R160,
    R256,
    R320,
}

fn parse_ripemd_size(args: &HashMap<String, String>) -> anyhow::Result<RipemdKind> {
    match args.get("size").map(|s| s.as_str()).unwrap_or("160") {
        "128" => Ok(RipemdKind::R128),
        "160" => Ok(RipemdKind::R160),
        "256" => Ok(RipemdKind::R256),
        "320" => Ok(RipemdKind::R320),
        other => anyhow::bail!(
            "{}",
            i18n::tf("err.ripemd160.size", &[other, "128 / 160 / 256 / 320"])
        ),
    }
}

struct RipemdStream {
    kind: RipemdKind,
    r128: Option<Ripemd128>,
    r160: Option<Ripemd160>,
    r256: Option<Ripemd256>,
    r320: Option<Ripemd320>,
}

fn make_hash_ripemd160(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    let kind = parse_ripemd_size(args)?;
    Ok(Box::new(RipemdStream {
        kind,
        r128: (kind == RipemdKind::R128).then(Ripemd128::new),
        r160: (kind == RipemdKind::R160).then(Ripemd160::new),
        r256: (kind == RipemdKind::R256).then(Ripemd256::new),
        r320: (kind == RipemdKind::R320).then(Ripemd320::new),
    }))
}

impl StreamingOp for RipemdStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        match self.kind {
            RipemdKind::R128 => Update::update(self.r128.as_mut().unwrap(), chunk),
            RipemdKind::R160 => Update::update(self.r160.as_mut().unwrap(), chunk),
            RipemdKind::R256 => Update::update(self.r256.as_mut().unwrap(), chunk),
            RipemdKind::R320 => Update::update(self.r320.as_mut().unwrap(), chunk),
        }
        Ok(Vec::new())
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        Ok(match self.kind {
            RipemdKind::R128 => self.r128.as_ref().unwrap().clone().finalize().to_vec(),
            RipemdKind::R160 => self.r160.as_ref().unwrap().clone().finalize().to_vec(),
            RipemdKind::R256 => self.r256.as_ref().unwrap().clone().finalize().to_vec(),
            RipemdKind::R320 => self.r320.as_ref().unwrap().clone().finalize().to_vec(),
        })
    }
}

// ---------------------------------------------------------------------------
// BLAKE2b-256: variable-output digest, 32-byte output.
// ---------------------------------------------------------------------------

struct Blake2bVarStream {
    h: Blake2bVar,
}

fn make_hash_blake2b_256(_args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    let h = Blake2bVar::new(32)?;
    Ok(Box::new(Blake2bVarStream { h }))
}

impl StreamingOp for Blake2bVarStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.h.update(chunk);
        Ok(Vec::new())
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        Ok(self.h.clone().finalize_boxed().to_vec())
    }
}

fn hash_blake2b_256(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let mut h = Blake2bVar::new(32)?;
    h.update(input);
    Ok(h.finalize_boxed().to_vec())
}

impl<D: Digest + Clone> StreamingOp for DigestStream<D> {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.h.update(chunk);
        Ok(Vec::new())
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        Ok(self.h.clone().finalize().to_vec())
    }
}

fn digest<D: Digest>(input: &[u8]) -> Vec<u8> {
    let mut h = D::new();
    h.update(input);
    h.finalize().to_vec()
}

/// Parse the optional `rounds` argument (digest iteration count).
/// Defaults to 1; 0 is rejected; the upper bound guards against runaway cost.
fn rounds_from_args(args: &HashMap<String, String>) -> anyhow::Result<usize> {
    match args.get("rounds").filter(|s| !s.is_empty()) {
        Some(v) => {
            let n: usize = v
                .parse()
                .map_err(|_| anyhow::anyhow!("{}", i18n::tf("err.bad_rounds", &[v.as_str()])))?;
            if n == 0 || n > 100_000 {
                return Err(anyhow::anyhow!(
                    "{}",
                    i18n::tf("err.bad_rounds", &[v.as_str()])
                ));
            }
            Ok(n)
        }
        None => Ok(1),
    }
}

/// Iterated digest: hash the input, then hash the previous digest `rounds-1`
/// more times. `rounds == 1` is a single plain digest.
fn iterated_digest<D: Digest>(input: &[u8], rounds: usize) -> Vec<u8> {
    let mut out = digest::<D>(input);
    for _ in 1..rounds {
        out = digest::<D>(&out);
    }
    out
}

/// Fallback streaming wrapper used when `rounds > 1`: the incremental
/// `DigestStream` cannot re-hash intermediate digests, so we buffer the whole
/// input and run the iterated digest once at finish.
struct CollectHashStream<F: Fn(&[u8]) -> Vec<u8> + Send + 'static> {
    buf: Vec<u8>,
    run: F,
}

impl<F: Fn(&[u8]) -> Vec<u8> + Send + 'static> StreamingOp for CollectHashStream<F> {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.buf.extend_from_slice(chunk);
        Ok(Vec::new())
    }
    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        Ok((self.run)(&self.buf))
    }
}

fn hash_md5(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    Ok(digest::<Md5>(input))
}

fn hash_sha1(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    Ok(iterated_digest::<Sha1>(input, rounds_from_args(args)?))
}

fn hash_sha256(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    Ok(iterated_digest::<Sha256>(input, rounds_from_args(args)?))
}

fn hash_sha512(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    Ok(iterated_digest::<Sha512>(input, rounds_from_args(args)?))
}

fn hash_sha224(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    Ok(iterated_digest::<Sha224>(input, rounds_from_args(args)?))
}

fn hash_sha384(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    Ok(iterated_digest::<Sha384>(input, rounds_from_args(args)?))
}

fn hash_sm3(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    Ok(iterated_digest::<Sm3>(input, rounds_from_args(args)?))
}

fn hash_sha3_256(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    Ok(digest::<Sha3_256>(input))
}

fn hash_sha3_224(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    Ok(digest::<Sha3_224>(input))
}

fn hash_sha3_384(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    Ok(digest::<Sha3_384>(input))
}

fn hash_sha3_512(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    Ok(digest::<Sha3_512>(input))
}

fn hash_whirlpool(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    Ok(digest::<Whirlpool>(input))
}

fn hash_blake2b_512(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    Ok(digest::<Blake2b512>(input))
}

fn make_hash_blake2b_384(_args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    let h = Blake2bVar::new(48)?;
    Ok(Box::new(Blake2bVarStream { h }))
}

fn hash_blake2b_384(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let mut h = Blake2bVar::new(48)?;
    h.update(input);
    Ok(h.finalize_boxed().to_vec())
}

struct Blake2sVarStream {
    h: Blake2sVar,
}

fn make_hash_blake2s_256(_args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    let h = Blake2sVar::new(32)?;
    Ok(Box::new(Blake2sVarStream { h }))
}

impl StreamingOp for Blake2sVarStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.h.update(chunk);
        Ok(Vec::new())
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        Ok(self.h.clone().finalize_boxed().to_vec())
    }
}

fn hash_blake2s_256(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let mut h = Blake2sVar::new(32)?;
    h.update(input);
    Ok(h.finalize_boxed().to_vec())
}

fn make_hash_md4(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    make_hash::<Md4>()(args)
}

fn hash_md4(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    Ok(digest::<Md4>(input))
}

// --- XXHash (XXH32 / XXH64, seed 0, little-endian output) -------------------

/// Buffer-style streaming wrapper: accumulates the full input and emits the
/// digest at finish. Byte-identical to the one-shot path, matching the
/// LzmaBufferStream precedent for algorithms without a digest trait impl.
struct Xxh32Stream {
    buf: Vec<u8>,
    seed: u32,
}

struct Xxh64Stream {
    buf: Vec<u8>,
    seed: u64,
}

fn parse_seed_u32(args: &HashMap<String, String>) -> anyhow::Result<u32> {
    match args.get("seed") {
        None => Ok(0),
        Some(s) => s
            .parse::<u32>()
            .map_err(|_| anyhow::anyhow!("invalid xxhash32 seed: {s} (u32)")),
    }
}

fn parse_seed_u64(args: &HashMap<String, String>) -> anyhow::Result<u64> {
    match args.get("seed") {
        None => Ok(0),
        Some(s) => s
            .parse::<u64>()
            .map_err(|_| anyhow::anyhow!("invalid xxhash64 seed: {s} (u64)")),
    }
}

fn make_hash_xxhash32(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    let seed = parse_seed_u32(args)?;
    Ok(Box::new(Xxh32Stream {
        buf: Vec::new(),
        seed,
    }))
}

fn make_hash_xxhash64(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    let seed = parse_seed_u64(args)?;
    Ok(Box::new(Xxh64Stream {
        buf: Vec::new(),
        seed,
    }))
}

impl StreamingOp for Xxh32Stream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.buf.extend_from_slice(chunk);
        Ok(Vec::new())
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        Ok(xxh32(&self.buf, self.seed).to_be_bytes().to_vec())
    }
}

impl StreamingOp for Xxh64Stream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.buf.extend_from_slice(chunk);
        Ok(Vec::new())
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        Ok(xxh64(&self.buf, self.seed).to_be_bytes().to_vec())
    }
}

fn hash_xxhash32(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let seed = parse_seed_u32(args)?;
    Ok(xxh32(input, seed).to_be_bytes().to_vec())
}

fn hash_xxhash64(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let seed = parse_seed_u64(args)?;
    Ok(xxh64(input, seed).to_be_bytes().to_vec())
}

const PRIME32_1: u32 = 0x9E37_79B1;
const PRIME32_2: u32 = 0x85EB_CA77;
const PRIME32_3: u32 = 0xC2B2_AE3D;
const PRIME32_4: u32 = 0x27D4_EB2F;
const PRIME32_5: u32 = 0x1656_67B1;

fn rotl32(x: u32, r: u32) -> u32 {
    x.rotate_left(r)
}

fn xxh32_round(acc: u32, input: u32) -> u32 {
    rotl32(acc.wrapping_add(input.wrapping_mul(PRIME32_2)), 13).wrapping_mul(PRIME32_1)
}

fn xxh32(input: &[u8], seed: u32) -> u32 {
    let len = input.len() as u32;
    let mut p = 0usize;
    let mut h: u32;
    if input.len() >= 16 {
        let mut v1 = PRIME32_1.wrapping_add(PRIME32_2).wrapping_add(seed);
        let mut v2 = PRIME32_2.wrapping_add(seed);
        let mut v3 = seed;
        let mut v4 = seed.wrapping_sub(PRIME32_1);
        while p + 16 <= input.len() {
            v1 = xxh32_round(v1, u32::from_le_bytes(input[p..p + 4].try_into().unwrap()));
            v2 = xxh32_round(
                v2,
                u32::from_le_bytes(input[p + 4..p + 8].try_into().unwrap()),
            );
            v3 = xxh32_round(
                v3,
                u32::from_le_bytes(input[p + 8..p + 12].try_into().unwrap()),
            );
            v4 = xxh32_round(
                v4,
                u32::from_le_bytes(input[p + 12..p + 16].try_into().unwrap()),
            );
            p += 16;
        }
        h = rotl32(v1, 1)
            .wrapping_add(rotl32(v2, 7))
            .wrapping_add(rotl32(v3, 12))
            .wrapping_add(rotl32(v4, 18));
    } else {
        h = seed.wrapping_add(PRIME32_5);
    }
    h = h.wrapping_add(len);
    while p + 4 <= input.len() {
        let w = u32::from_le_bytes(input[p..p + 4].try_into().unwrap());
        h = rotl32(h.wrapping_add(w.wrapping_mul(PRIME32_3)), 17).wrapping_mul(PRIME32_4);
        p += 4;
    }
    while p < input.len() {
        h = rotl32(
            h.wrapping_add((input[p] as u32).wrapping_mul(PRIME32_5)),
            11,
        )
        .wrapping_mul(PRIME32_1);
        p += 1;
    }
    h ^= h >> 15;
    h = h.wrapping_mul(PRIME32_2);
    h ^= h >> 13;
    h = h.wrapping_mul(PRIME32_3);
    h ^= h >> 16;
    h
}

const PRIME64_1: u64 = 0x9E37_79B1_85EB_CA87;
const PRIME64_2: u64 = 0xC2B2_AE3D_27D4_EB4F;
const PRIME64_3: u64 = 0x1656_67B1_9E37_79F9;
const PRIME64_4: u64 = 0x85EB_CA77_C2B2_AE63;
const PRIME64_5: u64 = 0x27D4_EB2F_1656_67C5;

fn rotl64(x: u64, r: u32) -> u64 {
    x.rotate_left(r)
}

fn xxh64_round(acc: u64, input: u64) -> u64 {
    rotl64(acc.wrapping_add(input.wrapping_mul(PRIME64_2)), 31).wrapping_mul(PRIME64_1)
}

fn xxh64_merge_round(acc: u64, val: u64) -> u64 {
    let v = xxh64_round(0, val);
    let acc = acc ^ v;
    acc.wrapping_mul(PRIME64_1).wrapping_add(PRIME64_4)
}

fn xxh64(input: &[u8], seed: u64) -> u64 {
    let len = input.len() as u64;
    let mut p = 0usize;
    let mut h: u64;
    if input.len() >= 32 {
        let mut v1 = PRIME64_1.wrapping_add(PRIME64_2).wrapping_add(seed);
        let mut v2 = PRIME64_2.wrapping_add(seed);
        let mut v3 = seed;
        let mut v4 = seed.wrapping_sub(PRIME64_1);
        while p + 32 <= input.len() {
            v1 = xxh64_round(v1, u64::from_le_bytes(input[p..p + 8].try_into().unwrap()));
            v2 = xxh64_round(
                v2,
                u64::from_le_bytes(input[p + 8..p + 16].try_into().unwrap()),
            );
            v3 = xxh64_round(
                v3,
                u64::from_le_bytes(input[p + 16..p + 24].try_into().unwrap()),
            );
            v4 = xxh64_round(
                v4,
                u64::from_le_bytes(input[p + 24..p + 32].try_into().unwrap()),
            );
            p += 32;
        }
        h = rotl64(v1, 1)
            .wrapping_add(rotl64(v2, 7))
            .wrapping_add(rotl64(v3, 12))
            .wrapping_add(rotl64(v4, 18));
        h = xxh64_merge_round(h, v1);
        h = xxh64_merge_round(h, v2);
        h = xxh64_merge_round(h, v3);
        h = xxh64_merge_round(h, v4);
    } else {
        h = seed.wrapping_add(PRIME64_5);
    }
    h = h.wrapping_add(len);
    while p + 8 <= input.len() {
        let w = u64::from_le_bytes(input[p..p + 8].try_into().unwrap());
        h ^= xxh64_round(0, w);
        h = rotl64(h, 27)
            .wrapping_mul(PRIME64_1)
            .wrapping_add(PRIME64_4);
        p += 8;
    }
    if p + 4 <= input.len() {
        let w = u32::from_le_bytes(input[p..p + 4].try_into().unwrap()) as u64;
        h ^= w.wrapping_mul(PRIME64_1);
        h = rotl64(h, 23)
            .wrapping_mul(PRIME64_2)
            .wrapping_add(PRIME64_3);
        p += 4;
    }
    while p < input.len() {
        h ^= (input[p] as u64).wrapping_mul(PRIME64_5);
        h = rotl64(h, 11).wrapping_mul(PRIME64_1);
        p += 1;
    }
    h ^= h >> 33;
    h = h.wrapping_mul(PRIME64_2);
    h ^= h >> 29;
    h = h.wrapping_mul(PRIME64_3);
    h ^= h >> 32;
    h
}

fn hash_ripemd160(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    Ok(match parse_ripemd_size(args)? {
        RipemdKind::R128 => digest::<Ripemd128>(input),
        RipemdKind::R160 => digest::<Ripemd160>(input),
        RipemdKind::R256 => digest::<Ripemd256>(input),
        RipemdKind::R320 => digest::<Ripemd320>(input),
    })
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// CRC family: unified parametrised engine for CRC-16 / CRC-32 /
// CRC-32C. Every variant is (width, poly, init, refin, refout, xorout) which
// covers the whole CRC catalogue (CyberChef's CRC Checksum operates the same
// way). Digest is emitted big-endian, width/8 bytes. Use `dpa:hex:encode` to
// display.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct CrcSpec {
    width: u8,
    poly: u64,
    init: u64,
    refin: bool,
    refout: bool,
    xorout: u64,
}

impl CrcSpec {
    fn mask(&self) -> u64 {
        if self.width >= 64 {
            u64::MAX
        } else {
            (1u64 << self.width) - 1
        }
    }

    fn reflected_poly(&self) -> u64 {
        let mut p = self.poly;
        let mut r = 0u64;
        for _ in 0..self.width {
            r = (r << 1) | (p & 1);
            p >>= 1;
        }
        r
    }

    fn table(&self) -> [u64; 256] {
        let mut t = [0u64; 256];
        let mask = self.mask();
        let poly = if self.refin {
            self.reflected_poly()
        } else {
            self.poly
        };
        for i in 0..256u64 {
            let mut c = if self.refin { i } else { i << (self.width - 8) };
            for _ in 0..8 {
                c = if self.refin {
                    if c & 1 != 0 { (c >> 1) ^ poly } else { c >> 1 }
                } else if c & (1u64 << (self.width - 1)) != 0 {
                    (c << 1) ^ poly
                } else {
                    c << 1
                };
                c &= mask;
            }
            t[i as usize] = c;
        }
        t
    }

    fn reflected(&self, v: u64) -> u64 {
        let mut r = 0u64;
        let mut x = v;
        for _ in 0..self.width {
            r = (r << 1) | (x & 1);
            x >>= 1;
        }
        r
    }

    /// Rocksoft parameter semantics: when refin is true the table engine runs
    /// in the reflected domain, so the initial register must be reflected too;
    /// the digest reflection is applied only when refin != refout (the state
    /// is in the opposite domain to the output).
    fn initial_state(&self) -> u64 {
        if self.refin {
            self.reflected(self.init)
        } else {
            self.init
        }
    }

    fn digest(&self, state: u64) -> Vec<u8> {
        let mut s = state;
        if self.refin != self.refout {
            s = self.reflected(s);
        }
        s ^= self.xorout;
        let n = (self.width / 8) as usize;
        let be = s.to_be_bytes();
        be[8 - n..].to_vec()
    }

    fn update(&self, state: u64, chunk: &[u8]) -> u64 {
        let t = self.table();
        let mask = self.mask();
        let mut s = state;
        if self.refin {
            for &b in chunk {
                s = (s >> 8) ^ t[((s ^ b as u64) & 0xFF) as usize];
            }
        } else {
            let sh = self.width - 8;
            for &b in chunk {
                s = (s << 8) ^ t[(((s >> sh) ^ b as u64) & 0xFF) as usize];
            }
        }
        s & mask
    }
}

fn crc_spec(kind: &str, name: &str, args: &HashMap<String, String>) -> anyhow::Result<CrcSpec> {
    let parse_u64 = |s: &str| -> anyhow::Result<u64> {
        let t = s.trim().trim_start_matches("0x");
        u64::from_str_radix(t, 16)
            .or_else(|_| t.parse::<u64>())
            .map_err(|_| anyhow::anyhow!("invalid number: {}", s))
    };
    if name == "custom" {
        let width: u8 = args
            .get("width")
            .map(|s| s.parse::<u8>())
            .transpose()
            .map_err(|_| anyhow::anyhow!("invalid width"))?
            .unwrap_or(16);
        if width != 8 && width != 16 && width != 32 && width != 64 {
            anyhow::bail!("unsupported custom width: {}", width);
        }
        let poly = args
            .get("poly")
            .map(|s| parse_u64(s))
            .transpose()?
            .unwrap_or(0);
        let init = args
            .get("init")
            .map(|s| parse_u64(s))
            .transpose()?
            .unwrap_or(0);
        let refin = args
            .get("refin")
            .map(|s| s.eq_ignore_ascii_case("true") || s == "1")
            .unwrap_or(false);
        let refout = args
            .get("refout")
            .map(|s| s.eq_ignore_ascii_case("true") || s == "1")
            .unwrap_or(false);
        let xorout = args
            .get("xorout")
            .map(|s| parse_u64(s))
            .transpose()?
            .unwrap_or(0);
        return Ok(CrcSpec {
            width,
            poly,
            init,
            refin,
            refout,
            xorout,
        });
    }
    // (width, poly, init, refin, refout, xorout)
    let table: &[(&str, u8, u64, u64, bool, bool, u64)] = match kind {
        "crc16" => &[
            ("arc", 16, 0x8005, 0x0000, true, true, 0x0000),
            ("modbus", 16, 0x8005, 0xFFFF, true, true, 0x0000),
            ("maxim", 16, 0x8005, 0x0000, true, true, 0xFFFF),
            ("usb", 16, 0x8005, 0xFFFF, true, true, 0xFFFF),
            ("ccitt-false", 16, 0x1021, 0xFFFF, false, false, 0x0000),
            ("xmodem", 16, 0x1021, 0x0000, false, false, 0x0000),
            ("ccitt-true", 16, 0x1021, 0x0000, true, true, 0x0000),
            ("kermit", 16, 0x1021, 0x0000, true, true, 0x0000),
            ("x-25", 16, 0x1021, 0xFFFF, true, true, 0xFFFF),
            ("dnp", 16, 0x3D65, 0x0000, true, true, 0xFFFF),
            ("buypass", 16, 0x8005, 0x0000, false, false, 0x0000),
            ("gsm", 16, 0x1021, 0x0000, false, false, 0xFFFF),
            ("dect-r", 16, 0x0589, 0x0000, false, false, 0x0001),
            ("riello", 16, 0x1021, 0xB2AA, true, true, 0x0000),
            ("spi-fujitsu", 16, 0x1021, 0x1D0F, false, false, 0x0000),
            ("t10-dif", 16, 0x8BB7, 0x0000, false, false, 0x0000),
            ("teledisk", 16, 0xA097, 0x0000, false, false, 0x0000),
            ("genibus", 16, 0x1021, 0xFFFF, false, false, 0xFFFF),
            ("ibm-3740", 16, 0x1021, 0xFFFF, false, false, 0x0000),
            ("ibm-sdlc", 16, 0x1021, 0xFFFF, true, true, 0xFFFF),
            ("mcrf4xx", 16, 0x1021, 0xFFFF, true, true, 0x0000),
        ],
        "crc32" => &[
            ("pkzip", 32, 0x04C11DB7, 0xFFFFFFFF, true, true, 0xFFFFFFFF),
            (
                "iso-hdlc", 32, 0x04C11DB7, 0xFFFFFFFF, true, true, 0xFFFFFFFF,
            ),
            (
                "bzip2", 32, 0x04C11DB7, 0xFFFFFFFF, false, false, 0xFFFFFFFF,
            ),
            (
                "mpeg-2", 32, 0x04C11DB7, 0xFFFFFFFF, false, false, 0x00000000,
            ),
            (
                "posix", 32, 0x04C11DB7, 0x00000000, false, false, 0xFFFFFFFF,
            ),
            ("xfer", 32, 0x000000AF, 0x00000000, false, false, 0x00000000),
            ("jamcrc", 32, 0x04C11DB7, 0xFFFFFFFF, true, true, 0x00000000),
            ("c", 32, 0x1EDC6F41, 0xFFFFFFFF, true, true, 0xFFFFFFFF),
            ("d", 32, 0xA833982B, 0xFFFFFFFF, true, true, 0xFFFFFFFF),
            ("q", 32, 0x814141AB, 0x00000000, false, false, 0x00000000),
            ("xz", 32, 0x04C11DB7, 0xFFFFFFFF, true, true, 0xFFFFFFFF),
            (
                "autosar", 32, 0xF4ACFB13, 0xFFFFFFFF, true, true, 0xFFFFFFFF,
            ),
        ],
        "crc32c" => &[
            (
                "castagnoli",
                32,
                0x1EDC6F41,
                0xFFFFFFFF,
                true,
                true,
                0xFFFFFFFF,
            ),
            ("iscsi", 32, 0x1EDC6F41, 0xFFFFFFFF, true, true, 0xFFFFFFFF),
            ("nvme", 32, 0x1EDC6F41, 0xFFFFFFFF, true, true, 0xFFFFFFFF),
        ],
        _ => &[],
    };
    for &(v, w, poly, init, refin, refout, xorout) in table {
        if v == name {
            return Ok(CrcSpec {
                width: w,
                poly,
                init,
                refin,
                refout,
                xorout,
            });
        }
    }
    let supported: Vec<&str> = table.iter().map(|(v, ..)| *v).collect();
    anyhow::bail!(
        "{}",
        i18n::tf("err.unknown_crc", &[name, &supported.join("/"), kind])
    )
}

struct CrcStream {
    state: u64,
    spec: CrcSpec,
}

impl StreamingOp for CrcStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.state = self.spec.update(self.state, chunk);
        Ok(Vec::new())
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        Ok(self.spec.digest(self.state))
    }
}

fn make_hash_crc32(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    let spec = crc_spec("crc32", opt_arg(args, "variant", "pkzip"), args)?;
    Ok(Box::new(CrcStream {
        state: spec.initial_state(),
        spec,
    }))
}

fn hash_crc32(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let spec = crc_spec("crc32", opt_arg(args, "variant", "pkzip"), args)?;
    Ok(spec.digest(spec.update(spec.initial_state(), input)))
}

fn make_hash_crc32c(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    let spec = crc_spec("crc32c", opt_arg(args, "variant", "castagnoli"), args)?;
    Ok(Box::new(CrcStream {
        state: spec.initial_state(),
        spec,
    }))
}

fn hash_crc32c(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let spec = crc_spec("crc32c", opt_arg(args, "variant", "castagnoli"), args)?;
    Ok(spec.digest(spec.update(spec.initial_state(), input)))
}

fn make_hash_crc16(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    let spec = crc_spec("crc16", opt_arg(args, "variant", "arc"), args)?;
    Ok(Box::new(CrcStream {
        state: spec.initial_state(),
        spec,
    }))
}

fn hash_crc16(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let spec = crc_spec("crc16", opt_arg(args, "variant", "arc"), args)?;
    Ok(spec.digest(spec.update(spec.initial_state(), input)))
}

// ---------------------------------------------------------------------------
// Adler-32 (RFC 1950): sum1/sum2 mod 65521, big-endian 4 bytes.
// ---------------------------------------------------------------------------

struct Adler32Stream {
    a: u32,
    b: u32,
}

fn make_hash_adler32(_args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    Ok(Box::new(Adler32Stream { a: 1, b: 0 }))
}

impl StreamingOp for Adler32Stream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        const MOD: u32 = 65521;
        for &byte in chunk {
            self.a = (self.a + byte as u32) % MOD;
            self.b = (self.b + self.a) % MOD;
        }
        Ok(Vec::new())
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        Ok(((self.b << 16) | self.a).to_be_bytes().to_vec())
    }
}

fn hash_adler32(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let mut h = make_hash_adler32(&HashMap::new())?;
    h.write(input)?;
    h.finish()
}

// ---------------------------------------------------------------------------
// Fletcher-16 / Fletcher-32: classic block checksums, big-endian output.
// ---------------------------------------------------------------------------

struct Fletcher16Stream {
    s1: u16,
    s2: u16,
}

fn make_hash_fletcher16(_args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    Ok(Box::new(Fletcher16Stream { s1: 0xFF, s2: 0xFF }))
}

impl StreamingOp for Fletcher16Stream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        for &byte in chunk {
            self.s1 = (self.s1 + byte as u16) % 255;
            self.s2 = (self.s2 + self.s1) % 255;
        }
        Ok(Vec::new())
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        Ok(((self.s2 << 8) | self.s1).to_be_bytes().to_vec())
    }
}

fn hash_fletcher16(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let mut h = make_hash_fletcher16(&HashMap::new())?;
    h.write(input)?;
    h.finish()
}

struct Fletcher32Stream {
    s1: u32,
    s2: u32,
    pending: Option<u16>,
}

fn make_hash_fletcher32(_args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    Ok(Box::new(Fletcher32Stream {
        s1: 0xFFFF,
        s2: 0xFFFF,
        pending: None,
    }))
}

impl StreamingOp for Fletcher32Stream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        const MOD: u32 = 65535;
        for &byte in chunk {
            let word = match self.pending.take() {
                Some(hi) => ((hi as u32) << 8) | byte as u32,
                None => {
                    self.pending = Some(byte as u16);
                    continue;
                }
            };
            self.s1 = (self.s1 + word) % MOD;
            self.s2 = (self.s2 + self.s1) % MOD;
        }
        Ok(Vec::new())
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        const MOD: u32 = 65535;
        if let Some(b) = self.pending.take() {
            let word = b as u32;
            self.s1 = (self.s1 + word) % MOD;
            self.s2 = (self.s2 + self.s1) % MOD;
        }
        Ok(((self.s2 << 16) | self.s1).to_be_bytes().to_vec())
    }
}

fn hash_fletcher32(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let mut h = make_hash_fletcher32(&HashMap::new())?;
    h.write(input)?;
    h.finish()
}

// ---------------------------------------------------------------------------
// Fletcher-8 / Fletcher-64 (CyberChef parity).
// Fletcher-8: nibble-wide sums modulo 15, emits one byte ((b << 4) | a).
// Fletcher-64: 4-byte little-endian words, sums modulo 0xFFFFFFFF, emits
// 8 bytes as b (big-endian 4) followed by a (big-endian 4).
// ---------------------------------------------------------------------------

struct Fletcher8Stream {
    s1: u8,
    s2: u8,
}

fn make_hash_fletcher8(_args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    Ok(Box::new(Fletcher8Stream { s1: 0xFF, s2: 0xFF }))
}

impl StreamingOp for Fletcher8Stream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        const MOD: u16 = 0x0F;
        for &byte in chunk {
            self.s1 = ((self.s1 as u16 + byte as u16) % MOD) as u8;
            self.s2 = ((self.s2 as u16 + self.s1 as u16) % MOD) as u8;
        }
        Ok(Vec::new())
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        Ok(vec![(self.s2 << 4) | self.s1])
    }
}

fn hash_fletcher8(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let mut h = make_hash_fletcher8(&HashMap::new())?;
    h.write(input)?;
    h.finish()
}

struct Fletcher64Stream {
    s1: u64,
    s2: u64,
    pending: [u8; 4],
    pending_len: usize,
}

fn make_hash_fletcher64(_args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    Ok(Box::new(Fletcher64Stream {
        s1: 0xFFFF_FFFF,
        s2: 0xFFFF_FFFF,
        pending: [0; 4],
        pending_len: 0,
    }))
}

impl StreamingOp for Fletcher64Stream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        const MOD: u64 = 0xFFFF_FFFF;
        for &byte in chunk {
            self.pending[self.pending_len] = byte;
            self.pending_len += 1;
            if self.pending_len == 4 {
                let word = u32::from_le_bytes(self.pending) as u64;
                self.s1 = (self.s1 + word) % MOD;
                self.s2 = (self.s2 + self.s1) % MOD;
                self.pending_len = 0;
            }
        }
        Ok(Vec::new())
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        const MOD: u64 = 0xFFFF_FFFF;
        if self.pending_len > 0 {
            let mut buf = self.pending;
            buf[self.pending_len..4].fill(0);
            let word = u32::from_le_bytes(buf) as u64;
            self.s1 = (self.s1 + word) % MOD;
            self.s2 = (self.s2 + self.s1) % MOD;
        }
        let mut out = Vec::with_capacity(8);
        out.extend_from_slice(&(self.s2 as u32).to_be_bytes());
        out.extend_from_slice(&(self.s1 as u32).to_be_bytes());
        Ok(out)
    }
}

fn hash_fletcher64(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let mut h = make_hash_fletcher64(&HashMap::new())?;
    h.write(input)?;
    h.finish()
}

// ---------------------------------------------------------------------------
// Keccak (original padding, NOT SHA-3): variants 224/256/384/512.
// ---------------------------------------------------------------------------

fn parse_keccak_variant(args: &HashMap<String, String>) -> anyhow::Result<KeccakVariant> {
    match opt_arg(args, "variant", "256") {
        "224" => Ok(KeccakVariant::K224),
        "256" => Ok(KeccakVariant::K256),
        "384" => Ok(KeccakVariant::K384),
        "512" => Ok(KeccakVariant::K512),
        other => anyhow::bail!(
            "{}",
            i18n::tf("err.unknown_hash_variant", &[other, "224/256/384/512"])
        ),
    }
}

#[derive(Clone, Copy)]
enum KeccakVariant {
    K224,
    K256,
    K384,
    K512,
}

fn keccak_digest(variant: KeccakVariant, input: &[u8]) -> Vec<u8> {
    match variant {
        KeccakVariant::K224 => Keccak224::digest(input).to_vec(),
        KeccakVariant::K256 => Keccak256::digest(input).to_vec(),
        KeccakVariant::K384 => Keccak384::digest(input).to_vec(),
        KeccakVariant::K512 => Keccak512::digest(input).to_vec(),
    }
}

struct KeccakStream {
    variant: KeccakVariant,
    buffer: Vec<u8>,
}

fn make_hash_keccak(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    let variant = parse_keccak_variant(args)?;
    Ok(Box::new(KeccakStream {
        variant,
        buffer: Vec::new(),
    }))
}

impl StreamingOp for KeccakStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.buffer.extend_from_slice(chunk);
        Ok(Vec::new())
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        Ok(keccak_digest(self.variant, &self.buffer))
    }
}

fn hash_keccak(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let variant = parse_keccak_variant(args)?;
    Ok(keccak_digest(variant, input))
}

// ---------------------------------------------------------------------------
// SHAKE128 / SHAKE256: extendable-output functions, length in bytes.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum ShakeVariant {
    S128,
    S256,
}

fn parse_shake_variant(args: &HashMap<String, String>) -> anyhow::Result<ShakeVariant> {
    match opt_arg(args, "variant", "256") {
        "128" => Ok(ShakeVariant::S128),
        "256" => Ok(ShakeVariant::S256),
        other => anyhow::bail!(
            "{}",
            i18n::tf("err.unknown_hash_variant", &[other, "128/256"])
        ),
    }
}

fn shake_length(args: &HashMap<String, String>) -> anyhow::Result<usize> {
    let raw = opt_arg(args, "length", "32");
    raw.parse::<usize>()
        .map_err(|_| anyhow::anyhow!("{}", i18n::tf("err.invalid_length", &[raw])))
}

fn shake_digest(variant: ShakeVariant, input: &[u8], len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    match variant {
        ShakeVariant::S128 => {
            let mut h = Shake128::default();
            Update::update(&mut h, input);
            let mut r = h.finalize_xof();
            r.read(&mut out);
        }
        ShakeVariant::S256 => {
            let mut h = Shake256::default();
            Update::update(&mut h, input);
            let mut r = h.finalize_xof();
            r.read(&mut out);
        }
    }
    out
}

struct ShakeStream {
    len: usize,
    state: ShakeState,
}

enum ShakeState {
    S128(Shake128),
    S256(Shake256),
}

fn make_hash_shake(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    let variant = parse_shake_variant(args)?;
    let len = shake_length(args)?;
    let state = match variant {
        ShakeVariant::S128 => ShakeState::S128(Shake128::default()),
        ShakeVariant::S256 => ShakeState::S256(Shake256::default()),
    };
    Ok(Box::new(ShakeStream { len, state }))
}

impl StreamingOp for ShakeStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        match &mut self.state {
            ShakeState::S128(h) => Update::update(h, chunk),
            ShakeState::S256(h) => Update::update(h, chunk),
        }
        Ok(Vec::new())
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        let mut out = vec![0u8; self.len];
        match std::mem::replace(&mut self.state, ShakeState::S128(Shake128::default())) {
            ShakeState::S128(h) => {
                let mut r = h.finalize_xof();
                r.read(&mut out);
            }
            ShakeState::S256(h) => {
                let mut r = h.finalize_xof();
                r.read(&mut out);
            }
        }
        Ok(out)
    }
}

fn hash_shake(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let variant = parse_shake_variant(args)?;
    let len = shake_length(args)?;
    Ok(shake_digest(variant, input, len))
}

// ---------------------------------------------------------------------------
// NT hash: MD4 of the UTF-16LE encoding of the password.
// Input bytes are interpreted as UTF-8 (the op's documented contract).
// ---------------------------------------------------------------------------

fn hash_nt(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let text = String::from_utf8_lossy(input);
    let mut utf16le = Vec::with_capacity(text.len() * 2);
    for u in text.encode_utf16() {
        utf16le.extend_from_slice(&u.to_le_bytes());
    }
    Ok(md4_digest(&utf16le).to_vec())
}

/// MD4 (RFC 1320) - minimal in-house one-shot implementation used by the NT
/// hash op. Kept dependency-free: the RustCrypto `md-4` crate is not available
/// on the configured registry mirror, and NT hash only needs a single digest.
fn md4_digest(data: &[u8]) -> [u8; 16] {
    // RFC 1320 message-word order per round (column-major, unlike MD5's (5i+1) pattern).
    const R2: [usize; 16] = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15];
    const R3: [usize; 16] = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15];

    let mut a0: u32 = 0x67452301;
    let mut b0: u32 = 0xefcdab89;
    let mut c0: u32 = 0x98badcfe;
    let mut d0: u32 = 0x10325476;

    // Padding (RFC 1320 §3.1): 0x80, zeros to 56 mod 64, then 64-bit LE bit length.
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = Vec::with_capacity(((data.len() + 72) / 64) * 64);
    msg.extend_from_slice(data);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    for chunk in msg.as_chunks::<64>().0 {
        let mut x = [0u32; 16];
        for (i, w) in chunk.as_chunks::<4>().0.iter().enumerate() {
            x[i] = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);

        // Round 1: F = (B&C)|(~B&D), no constant, shifts [3,7,11,19].
        // Update order A,D,C,B; each step feeds the just-updated registers.
        for i in 0..16u32 {
            let (f, rot) = match i % 4 {
                0 => ((b & c) | (!b & d), 3u32),
                1 => ((a & b) | (!a & c), 7u32),
                2 => ((d & a) | (!d & b), 11u32),
                _ => ((c & d) | (!c & a), 19u32),
            };
            match i % 4 {
                0 => {
                    a = a
                        .wrapping_add(f)
                        .wrapping_add(x[i as usize])
                        .rotate_left(rot)
                }
                1 => {
                    d = d
                        .wrapping_add(f)
                        .wrapping_add(x[i as usize])
                        .rotate_left(rot)
                }
                2 => {
                    c = c
                        .wrapping_add(f)
                        .wrapping_add(x[i as usize])
                        .rotate_left(rot)
                }
                _ => {
                    b = b
                        .wrapping_add(f)
                        .wrapping_add(x[i as usize])
                        .rotate_left(rot)
                }
            }
        }
        // Round 2: G = (B&C)|(B&D)|(C&D), constant 0x5a827999, shifts [3,5,9,13],
        // word index is the RFC 1320 column order: 0,4,8,12, 1,5,9,13, ...
        for i in 0..16u32 {
            let g = R2[i as usize];
            let (f, rot) = match i % 4 {
                0 => ((b & c) | (b & d) | (c & d), 3u32),
                1 => ((a & b) | (a & c) | (b & c), 5u32),
                2 => ((d & a) | (d & b) | (a & b), 9u32),
                _ => ((c & d) | (c & a) | (d & a), 13u32),
            };
            match i % 4 {
                0 => {
                    a = a
                        .wrapping_add(f)
                        .wrapping_add(x[g])
                        .wrapping_add(0x5a827999)
                        .rotate_left(rot)
                }
                1 => {
                    d = d
                        .wrapping_add(f)
                        .wrapping_add(x[g])
                        .wrapping_add(0x5a827999)
                        .rotate_left(rot)
                }
                2 => {
                    c = c
                        .wrapping_add(f)
                        .wrapping_add(x[g])
                        .wrapping_add(0x5a827999)
                        .rotate_left(rot)
                }
                _ => {
                    b = b
                        .wrapping_add(f)
                        .wrapping_add(x[g])
                        .wrapping_add(0x5a827999)
                        .rotate_left(rot)
                }
            }
        }
        // Round 3: H = B^C^D, constant 0x6ed9eba1, shifts [3,9,11,15],
        // word index is the RFC 1320 column order: 0,8,4,12, 2,10,6,14, ...
        for i in 0..16u32 {
            let g = R3[i as usize];
            let (f, rot) = match i % 4 {
                0 => (b ^ c ^ d, 3u32),
                1 => (a ^ b ^ c, 9u32),
                2 => (d ^ a ^ b, 11u32),
                _ => (c ^ d ^ a, 15u32),
            };
            match i % 4 {
                0 => {
                    a = a
                        .wrapping_add(f)
                        .wrapping_add(x[g])
                        .wrapping_add(0x6ed9eba1)
                        .rotate_left(rot)
                }
                1 => {
                    d = d
                        .wrapping_add(f)
                        .wrapping_add(x[g])
                        .wrapping_add(0x6ed9eba1)
                        .rotate_left(rot)
                }
                2 => {
                    c = c
                        .wrapping_add(f)
                        .wrapping_add(x[g])
                        .wrapping_add(0x6ed9eba1)
                        .rotate_left(rot)
                }
                _ => {
                    b = b
                        .wrapping_add(f)
                        .wrapping_add(x[g])
                        .wrapping_add(0x6ed9eba1)
                        .rotate_left(rot)
                }
            }
        }

        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out
}

// ---------------------------------------------------------------------------
// LM hash: uppercase password -> two 7-byte keys -> DES-ECB of
// the constant "KGS!@#$%" with the two 8-byte results concatenated (16 bytes).
// ---------------------------------------------------------------------------

const LM_MAGIC: [u8; 8] = *b"KGS!@#$%";

fn lm_key_from_7(block: &[u8]) -> [u8; 8] {
    debug_assert_eq!(block.len(), 7);
    let p = |i: usize| block[i];
    [
        p(0),
        (p(0) << 7) | (p(1) >> 1),
        (p(1) << 6) | (p(2) >> 2),
        (p(2) << 5) | (p(3) >> 3),
        (p(3) << 4) | (p(4) >> 4),
        (p(4) << 3) | (p(5) >> 5),
        (p(5) << 2) | (p(6) >> 6),
        p(6) << 1,
    ]
}

fn lm_des_encrypt(key: &[u8; 8], msg: &[u8; 8]) -> anyhow::Result<[u8; 8]> {
    use des::cipher::{BlockEncrypt, KeyInit};
    let cipher = des::Des::new_from_slice(key)
        .map_err(|_| anyhow::anyhow!("{}", i18n::t("err.invalid_des_key")))?;
    let mut block: des::cipher::Block<des::Des> =
        des::cipher::Block::<des::Des>::clone_from_slice(msg);
    cipher.encrypt_block(&mut block);
    let mut out = [0u8; 8];
    out.copy_from_slice(&block);
    Ok(out)
}

fn hash_lm(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    // LM is OEM-uppercase; we only map ASCII and pass other bytes through.
    let mut text = Vec::with_capacity(14);
    for &b in input {
        if text.len() == 14 {
            break;
        }
        text.push(if b.is_ascii() {
            b.to_ascii_uppercase()
        } else {
            b
        });
    }
    while text.len() < 14 {
        text.push(0);
    }
    let k1 = lm_key_from_7(&text[0..7]);
    let k2 = lm_key_from_7(&text[7..14]);
    let c1 = lm_des_encrypt(&k1, &LM_MAGIC)?;
    let c2 = lm_des_encrypt(&k2, &LM_MAGIC)?;
    let mut out = Vec::with_capacity(16);
    out.extend_from_slice(&c1);
    out.extend_from_slice(&c2);
    Ok(out)
}

fn hash_ssdeep(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    Ok(ssdeep_digest(input))
}

// ---------------------------------------------------------------------------
// ssdeep:compare (CyberChef parity): split two fuzzy signatures by a
// delimiter and return their similarity score 0-100. Mirrors ssdeep.js:
//   * blocksize difference > 1 -> 0
//   * equal blocksize -> matchScore(sig1a, sig2a)
//   * adjacent blocksize -> matchScore(small.sig2, big.sig1)
// matchScore = (1 - levenshtein/max_len) * 100 (rounded to an integer).
// ---------------------------------------------------------------------------

fn ssdeep_compare(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let delimiter = opt_arg(args, "delimiter", ",");
    let text = std::str::from_utf8(input)?;
    let parts: Vec<&str> = text.split(delimiter).collect();
    if parts.len() != 2 {
        anyhow::bail!("{}", i18n::tf("err.ssdeep.compare.needs_two", &[delimiter]));
    }
    let score = ssdeep_similarity(parts[0].trim(), parts[1].trim());
    Ok(score.to_string().into_bytes())
}

/// Parse a "blocksize:sig1:sig2" signature into its three components.
fn parse_ssdeep(sig: &str) -> Option<(u32, &str, &str)> {
    let mut it = sig.splitn(3, ':');
    let bs: u32 = it.next()?.trim().parse().ok()?;
    let sig1 = it.next()?;
    let sig2 = it.next()?;
    Some((bs, sig1, sig2))
}

fn ssdeep_similarity(d1: &str, d2: &str) -> u32 {
    let (bs1, sig1a, sig1b) = match parse_ssdeep(d1) {
        Some(t) => t,
        None => return 0,
    };
    let (bs2, sig2a, sig2b) = match parse_ssdeep(d2) {
        Some(t) => t,
        None => return 0,
    };
    let (small_bs, small_sig2, big_bs, big_sig1) = if bs1 > bs2 {
        (bs2, sig2b, bs1, sig1a)
    } else {
        (bs1, sig1b, bs2, sig2a)
    };
    if big_bs - small_bs > 1 {
        return 0;
    }
    let raw = if small_bs == big_bs {
        ssdeep_match_score(sig1a, sig2a)
    } else {
        ssdeep_match_score(small_sig2, big_sig1)
    };
    (raw * 100.0).round() as u32
}

fn ssdeep_match_score(s1: &str, s2: &str) -> f64 {
    let e = ssdeep_levenshtein(s1, s2);
    let max = s1.len().max(s2.len()) as f64;
    if max == 0.0 {
        return 1.0;
    }
    1.0 - e as f64 / max
}

/// Classic two-row Levenshtein distance over ASCII signatures.
fn ssdeep_levenshtein(a: &str, b: &str) -> usize {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.is_empty() {
        return b.len();
    }
    if b.is_empty() {
        return a.len();
    }
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0usize; b.len() + 1];
    for (i, &ca) in a.iter().enumerate() {
        cur[0] = i + 1;
        for (j, &cb) in b.iter().enumerate() {
            let cost = if ca == cb { 0 } else { 1 };
            cur[j + 1] = (prev[j] + cost).min(cur[j] + 1).min(prev[j + 1] + 1);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

// ---------------------------------------------------------------------------
// ssdeep (CTPH) fuzzy hash - a clean-room re-implementation of the libfuzzy
// (ssdeep 2.14+) engine so that produced signatures match `ssdeep` CLI output
// byte for byte. Algorithm highlights:
//   * A 7-byte-window rolling hash (h1 + h2 Adler-style sums plus a
//     shift/xor h3) emits a "reset point" when roll_sum % blocksize == bs - 1.
//   * A partial (6-bit) FNV-1 hash accumulates piece content between reset
//     points and is base64-encoded as signature characters (b64 alphabet).
//   * A chain of 31 parallel block-hash states (one per doubling blocksize
//     3, 6, 12, ...) grows lazily via forking; the digest pass picks the
//     smallest state whose digest reached 32 characters.
//   * The last, not-yet-triggered piece is appended during the digest pass
//     (unless the rolling sum is zero), and the second signature is truncated
//     to 31 characters plus the trailing piece character.
// Reference vectors (generated with libfuzzy): see tests below.
const SSDEEP_SPAMSUM_LENGTH: usize = 64;
const SSDEEP_MIN_BLOCKSIZE: u32 = 3;
const SSDEEP_NUM_BLOCKHASHES: usize = 31;
const SSDEEP_HASH_INIT: u8 = 0x27; // partial FNV initial value (39)
const SSDEEP_HASH_PRIME: u32 = 0x0100_0193;
const SSDEEP_B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#[derive(Clone, Copy)]
struct SsdeepRoll {
    window: [u8; 7],
    h1: u32,
    h2: u32,
    h3: u32,
    n: usize,
}

impl SsdeepRoll {
    fn new() -> Self {
        SsdeepRoll {
            window: [0; 7],
            h1: 0,
            h2: 0,
            h3: 0,
            n: 0,
        }
    }

    fn update(&mut self, c: u8) {
        self.h2 = self.h2.wrapping_sub(self.h1).wrapping_add(7 * c as u32);
        self.h1 = self
            .h1
            .wrapping_add(c as u32)
            .wrapping_sub(self.window[self.n] as u32);
        self.window[self.n] = c;
        self.n = (self.n + 1) % 7;
        // h3 is a shift/xor based rolling hash; important for large blocksizes.
        self.h3 = self.h3.wrapping_shl(5) ^ c as u32;
    }

    fn sum(&self) -> u32 {
        self.h1.wrapping_add(self.h2).wrapping_add(self.h3)
    }
}

/// Partial FNV-1 (6-bit output), identical to libfuzzy's precomputed sum table.
fn ssdeep_sum_hash(c: u8, h: u8) -> u8 {
    (((h as u32 * SSDEEP_HASH_PRIME) ^ c as u32) & 0x3f) as u8
}

#[derive(Clone, Copy)]
struct SsdeepBlockHash {
    dindex: usize,
    digest: [u8; SSDEEP_SPAMSUM_LENGTH],
    h: u8,
    halfh: u8,
    halfdigest: u8,
}

impl SsdeepBlockHash {
    fn new() -> Self {
        SsdeepBlockHash {
            dindex: 0,
            digest: [0; SSDEEP_SPAMSUM_LENGTH],
            h: SSDEEP_HASH_INIT,
            halfh: SSDEEP_HASH_INIT,
            halfdigest: 0,
        }
    }
}

fn ssdeep_digest(data: &[u8]) -> Vec<u8> {
    let total = data.len() as u64;
    let mut bhs = [SsdeepBlockHash::new(); SSDEEP_NUM_BLOCKHASHES];
    let mut bhstart = 0usize;
    let mut bhend = 1usize;

    // fuzzy_set_total_input_length: precompute the highest interesting blocksize.
    let mut bi = 0u32;
    while (((SSDEEP_MIN_BLOCKSIZE as u64) << bi) * (SSDEEP_SPAMSUM_LENGTH as u64)) < total {
        bi += 1;
        if bi as usize == SSDEEP_NUM_BLOCKHASHES - 2 {
            break;
        }
    }
    let bhendlimit = bi as usize + 1;

    let mut reduce_border: u64 = SSDEEP_MIN_BLOCKSIZE as u64 * SSDEEP_SPAMSUM_LENGTH as u64;
    let mut rollmask: u32 = 0;
    let mut roll = SsdeepRoll::new();
    let mut lasth = 0u8;
    let mut need_lasthash = false;

    for &c in data {
        roll.update(c);
        let horg = roll.sum().wrapping_add(1);
        let mut h = horg / SSDEEP_MIN_BLOCKSIZE;
        for bh in &mut bhs[bhstart..bhend] {
            bh.h = ssdeep_sum_hash(c, bh.h);
            bh.halfh = ssdeep_sum_hash(c, bh.halfh);
        }
        if need_lasthash {
            lasth = ssdeep_sum_hash(c, lasth);
        }
        // Prevent piece-splitting trigger on roll_sum() == 0xffffffff (== -1 mod 3).
        if horg == 0 {
            continue;
        }
        if h & rollmask != 0 {
            continue;
        }
        if !horg.is_multiple_of(SSDEEP_MIN_BLOCKSIZE) {
            continue;
        }
        h >>= bhstart;
        let mut i = bhstart;
        loop {
            // Fork: lazily grow the chain of blocksize states.
            if bhs[i].dindex == 0 {
                if bhend <= bhendlimit {
                    let src = bhs[i];
                    let nbh = &mut bhs[bhend];
                    nbh.h = src.h;
                    nbh.halfh = src.halfh;
                    nbh.digest[0] = 0;
                    nbh.halfdigest = 0;
                    nbh.dindex = 0;
                    bhend += 1;
                } else if bhend == SSDEEP_NUM_BLOCKHASHES && !need_lasthash {
                    need_lasthash = true;
                    lasth = bhs[i].h;
                }
            }
            let bh = &mut bhs[i];
            bh.digest[bh.dindex] = SSDEEP_B64[bh.h as usize];
            bh.halfdigest = SSDEEP_B64[bh.halfh as usize];
            if bh.dindex < SSDEEP_SPAMSUM_LENGTH - 1 {
                bh.dindex += 1;
                bh.digest[bh.dindex] = 0;
                bh.h = SSDEEP_HASH_INIT;
                if bh.dindex < SSDEEP_SPAMSUM_LENGTH / 2 {
                    bh.halfh = SSDEEP_HASH_INIT;
                    bh.halfdigest = 0;
                }
            } else {
                // digest full: drop the smallest blocksize state.
                if !(bhend - bhstart < 2
                    || reduce_border >= total
                    || bhs[bhstart + 1].dindex < SSDEEP_SPAMSUM_LENGTH / 2)
                {
                    bhstart += 1;
                    reduce_border *= 2;
                    rollmask = rollmask.wrapping_mul(2).wrapping_add(1);
                }
            }
            if h & 1 != 0 {
                break;
            }
            h >>= 1;
            i += 1;
            if i >= bhend {
                break;
            }
        }
    }

    // ---- digest pass (mirrors fuzzy_digest) ----
    let mut bi = bhstart;
    let h = roll.sum();
    while (((SSDEEP_MIN_BLOCKSIZE as u64) << bi) * (SSDEEP_SPAMSUM_LENGTH as u64)) < total {
        bi += 1;
    }
    if bi >= bhend {
        bi = bhend - 1;
    }
    while bi > bhstart && bhs[bi].dindex < SSDEEP_SPAMSUM_LENGTH / 2 {
        bi -= 1;
    }

    let bs = SSDEEP_MIN_BLOCKSIZE << bi;
    let mut out = format!("{}:", bs);
    let d = &bhs[bi];
    let sz = d.dindex;
    out.push_str(std::str::from_utf8(&d.digest[..sz]).unwrap_or(""));
    let ch = if h != 0 {
        SSDEEP_B64[d.h as usize]
    } else {
        d.digest[d.dindex]
    };
    if ch != 0 {
        out.push(ch as char);
    }
    out.push(':');
    if bi < bhend - 1 {
        // Second signature: digest of the next blocksize state, truncated to 31 chars.
        let d2 = &bhs[bi + 1];
        let mut sz2 = d2.dindex;
        if sz2 > SSDEEP_SPAMSUM_LENGTH / 2 - 1 {
            sz2 = SSDEEP_SPAMSUM_LENGTH / 2 - 1;
        }
        out.push_str(std::str::from_utf8(&d2.digest[..sz2]).unwrap_or(""));
        let ch2 = if h != 0 {
            SSDEEP_B64[d2.halfh as usize]
        } else {
            d2.halfdigest
        };
        if ch2 != 0 {
            out.push(ch2 as char);
        }
    } else if h != 0 {
        // No higher state: use the last (single-character) hash.
        let ch3 = if bi == 0 {
            SSDEEP_B64[bhs[0].h as usize]
        } else {
            lasth
        };
        out.push(ch3 as char);
    }
    out.into_bytes()
}

// ---------------------------------------------------------------------------
// Luhn checksum (mod-10). mode: check-digit (default) | append | verify
// ---------------------------------------------------------------------------

fn luhn_check_digit(digits: &[u8]) -> u8 {
    let mut sum = 0u32;
    let mut double = true; // reversed position 1 (rightmost prefix digit) is doubled
    for &d in digits.iter().rev() {
        let mut v = (d - b'0') as u32;
        if double {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
        double = !double;
    }
    ((10 - (sum % 10)) % 10) as u8
}

fn luhn(data: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let mode = args
        .get("mode")
        .map(|s| s.as_str())
        .unwrap_or("check-digit");
    let digits: Vec<u8> = data
        .iter()
        .copied()
        .filter(|b| b.is_ascii_digit())
        .collect();
    match mode {
        "check-digit" => {
            if digits.is_empty() {
                anyhow::bail!("luhn: no digits found in input");
            }
            Ok(vec![b'0' + luhn_check_digit(&digits)])
        }
        "append" => {
            if digits.is_empty() {
                anyhow::bail!("luhn: no digits found in input");
            }
            let cd = luhn_check_digit(&digits);
            let mut out = digits;
            out.push(b'0' + cd);
            Ok(out)
        }
        "verify" => {
            if digits.len() < 2 {
                anyhow::bail!("luhn: verify needs at least 2 digits");
            }
            let cd = luhn_check_digit(&digits[..digits.len() - 1]);
            let ok = cd == digits[digits.len() - 1] - b'0';
            Ok(if ok {
                b"true".to_vec()
            } else {
                b"false".to_vec()
            })
        }
        other => anyhow::bail!("luhn: unknown mode {other:?} (check-digit|append|verify)"),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::type_complexity)]
    use super::*;

    #[test]
    fn luhn_vectors() {
        let check = luhn(b"7992739871", &HashMap::new()).unwrap();
        assert_eq!(check, b"3");
        let append = luhn(
            b"7992739871",
            &HashMap::from([("mode".to_string(), "append".to_string())]),
        )
        .unwrap();
        assert_eq!(append, b"79927398713");
        let ok = luhn(
            b"79927398713",
            &HashMap::from([("mode".to_string(), "verify".to_string())]),
        )
        .unwrap();
        assert_eq!(ok, b"true");
        let bad = luhn(
            b"79927398710",
            &HashMap::from([("mode".to_string(), "verify".to_string())]),
        )
        .unwrap();
        assert_eq!(bad, b"false");
    }

    #[test]
    fn luhn_ignores_non_digits() {
        let check = luhn(b"7992-7398-71", &HashMap::new()).unwrap();
        assert_eq!(check, b"3");
    }

    fn hex_of(
        f: fn(&[u8], &HashMap<String, String>) -> anyhow::Result<Vec<u8>>,
        input: &[u8],
    ) -> String {
        hex::encode(f(input, &HashMap::new()).unwrap())
    }

    #[test]
    fn empty_vectors() {
        assert_eq!(hex_of(hash_md5, b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(
            hex_of(hash_sha1, b""),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        assert_eq!(
            hex_of(hash_sha256, b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex_of(hash_sha512, b""),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
    }

    #[test]
    fn known_vector() {
        assert_eq!(hex_of(hash_md5, b"abc"), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn crc32_known_values() {
        // CRC-32("123456789") = 0xCBF43926 (standard check value).
        assert_eq!(
            hash_crc32(b"123456789", &HashMap::new()).unwrap(),
            0xcbf43926u32.to_be_bytes()
        );
        assert_eq!(
            hash_crc32(b"", &HashMap::new()).unwrap(),
            0u32.to_be_bytes()
        );
    }

    #[test]
    fn crc32_stream_matches_memory() {
        let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let mut h = make_hash_crc32(&HashMap::new()).unwrap();
        let mut acc = Vec::new();
        for c in data.chunks(7) {
            acc.extend(h.write(c).unwrap());
        }
        acc.extend(h.finish().unwrap());
        assert_eq!(acc, hash_crc32(&data, &HashMap::new()).unwrap());
    }

    #[test]
    fn sm3_known_vectors() {
        assert_eq!(
            hex_of(hash_sm3, b""),
            "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"
        );
        assert_eq!(
            hex_of(hash_sm3, b"abc"),
            "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
        );
    }

    #[test]
    fn sha3_known_vectors() {
        assert_eq!(
            hex_of(hash_sha3_256, b""),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
        assert_eq!(
            hex_of(hash_sha3_512, b""),
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
        );
    }

    #[test]
    fn sha2_variant_known_vectors() {
        assert_eq!(
            hex_of(hash_sha224, b"abc"),
            "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
        );
        assert_eq!(
            hex_of(hash_sha384, b"abc"),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        );
    }

    #[test]
    fn blake2b_known_vectors() {
        assert_eq!(
            hex_of(hash_blake2b_512, b""),
            "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
        );
        assert_eq!(
            hex_of(hash_blake2b_256, b""),
            "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
        );
    }

    #[test]
    fn blake2_384_256_known_vectors() {
        // BLAKE2b-384("abc") and BLAKE2s-256("abc"), verified via hashlib.
        assert_eq!(
            hex_of(hash_blake2b_384, b"abc"),
            "6f56a82c8e7ef526dfe182eb5212f7db9df1317e57815dbda46083fc30f54ee6c66ba83be64b302d7cba6ce15bb556f4"
        );
        assert_eq!(
            hex_of(hash_blake2b_384, b""),
            "b32811423377f52d7862286ee1a72ee540524380fda1724a6f25d7978c6fd3244a6caf0498812673c5e05ef583825100"
        );
        assert_eq!(
            hex_of(hash_blake2s_256, b"abc"),
            "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"
        );
        assert_eq!(
            hex_of(hash_blake2s_256, b""),
            "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
        );
    }

    #[test]
    fn md4_known_vectors() {
        // RFC 1320 test vectors.
        assert_eq!(hex_of(hash_md4, b""), "31d6cfe0d16ae931b73c59d7e0c089c0");
        assert_eq!(hex_of(hash_md4, b"abc"), "a448017aaf21d8525fc10ae87aa6729d");
    }

    #[test]
    fn xxhash_known_vectors() {
        // Official xxHash sanity vectors (seed 0), output big-endian to match
        // xxhsum and Python's xxhash module.
        assert_eq!(hex_of(hash_xxhash32, b""), "02cc5d05"); // 0x02CC5D05
        assert_eq!(hex_of(hash_xxhash32, b"abc"), "32d153ff"); // 0x32D153FF
        assert_eq!(hex_of(hash_xxhash64, b""), "ef46db3751d8e999"); // 0xEF46DB3751D8E999
        assert_eq!(hex_of(hash_xxhash64, b"abc"), "44bc2cf5ad770999"); // 0x44BC2CF5AD770999
        // Long input (>32 bytes) exercises the striped main loop.
        let long: Vec<u8> = (0..=255u8).cycle().take(1024).collect();
        assert_eq!(hex_of(hash_xxhash32, &long), "58654d5a"); // 0x58654D5A
        assert_eq!(hex_of(hash_xxhash64, &long), "6f3914f18fe4df57"); // 0x6F3914F18FE4DF57
    }

    #[test]
    fn whirlpool_known_vectors() {
        // NESSIE / ISO 10118-3: Whirlpool("abc") starts with these 16 bytes and
        // always outputs exactly 64 bytes (512-bit digest).
        let out = hash_whirlpool(b"abc", &HashMap::new()).unwrap();
        assert_eq!(out.len(), 64);
        assert_eq!(
            &hex_of(hash_whirlpool, b"abc")[..32],
            "4e2448a4c6f486bb16b6562c73b4020b"
        );
        // Determinism + differs from SHA-256 for the same input.
        assert_eq!(hash_whirlpool(b"abc", &HashMap::new()).unwrap(), out);
        assert_ne!(hex_of(hash_whirlpool, b"abc"), hex_of(hash_sha256, b"abc"));
    }

    #[test]
    fn ripemd160_known_vectors() {
        assert_eq!(
            hex_of(hash_ripemd160, b""),
            "9c1185a5c5e9fc54612808977ee8f548b2258d31"
        );
        assert_eq!(
            hex_of(hash_ripemd160, b"abc"),
            "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
        );
    }

    #[test]
    fn crc32c_known_values() {
        // CRC-32C("123456789") = 0xE3069283 (Castagnoli check value).
        assert_eq!(
            hash_crc32c(b"123456789", &HashMap::new()).unwrap(),
            0xe3069283u32.to_be_bytes()
        );
        assert_eq!(
            hash_crc32c(b"", &HashMap::new()).unwrap(),
            0u32.to_be_bytes()
        );
    }

    #[test]
    fn new_hash_streams_match_memory() {
        let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let cases: [(
            &str,
            fn(&HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>>,
            fn(&[u8], &HashMap<String, String>) -> anyhow::Result<Vec<u8>>,
        ); 14] = [
            ("sm3", make_hash_sm3, hash_sm3),
            ("sha224", make_hash_sha224, hash_sha224),
            ("sha384", make_hash_sha384, hash_sha384),
            ("sha3-256", make_hash_sha3_256, hash_sha3_256),
            ("sha3-512", make_hash_sha3_512, hash_sha3_512),
            ("blake2b-256", make_hash_blake2b_256, hash_blake2b_256),
            ("blake2b-512", make_hash_blake2b_512, hash_blake2b_512),
            ("blake2b-384", make_hash_blake2b_384, hash_blake2b_384),
            ("blake2s-256", make_hash_blake2s_256, hash_blake2s_256),
            ("md4", make_hash_md4, hash_md4),
            ("xxhash32", make_hash_xxhash32, hash_xxhash32),
            ("xxhash64", make_hash_xxhash64, hash_xxhash64),
            ("ripemd160", make_hash_ripemd160, hash_ripemd160),
            ("whirlpool", make_hash_whirlpool, hash_whirlpool),
        ];
        for (name, make, run) in cases {
            let mut h = make(&HashMap::new()).unwrap();
            let mut acc = Vec::new();
            for c in data.chunks(3) {
                acc.extend(h.write(c).unwrap());
            }
            acc.extend(h.finish().unwrap());
            assert_eq!(
                acc,
                run(&data, &HashMap::new()).unwrap(),
                "stream mismatch: {name}"
            );
        }
    }

    #[test]
    fn crc32c_stream_matches_memory() {
        let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let mut h = make_hash_crc32c(&HashMap::new()).unwrap();
        let mut acc = Vec::new();
        for c in data.chunks(7) {
            acc.extend(h.write(c).unwrap());
        }
        acc.extend(h.finish().unwrap());
        assert_eq!(acc, hash_crc32c(&data, &HashMap::new()).unwrap());
    }

    fn hargs(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn crc16_known_values() {
        // Standard CRC-16 check values for "123456789" (reveng catalogue).
        let cases = [
            ("arc", "bb3d"),
            ("modbus", "4b37"),
            ("maxim", "44c2"),
            ("usb", "b4c8"),
            ("ccitt-false", "29b1"),
            ("xmodem", "31c3"),
            ("ccitt-true", "2189"),
            ("kermit", "2189"),
            ("x-25", "906e"),
            ("dnp", "ea82"),
            ("buypass", "fee8"),
            ("gsm", "ce3c"),
            ("dect-r", "007e"),
            ("riello", "63d0"),
            ("spi-fujitsu", "e5cc"),
            ("t10-dif", "d0db"),
            ("teledisk", "0fb3"),
            ("genibus", "d64e"),
            ("ibm-3740", "29b1"),
            ("ibm-sdlc", "906e"),
            ("mcrf4xx", "6f91"),
        ];
        for (variant, expected) in cases {
            let args = hargs(&[("variant", variant)]);
            let got = hex::encode(hash_crc16(b"123456789", &args).unwrap());
            assert_eq!(got, expected, "crc16 {variant}");
        }
        assert_eq!(
            hex::encode(hash_crc16(b"abc", &hargs(&[("variant", "arc")])).unwrap()),
            "9738"
        );
        assert_eq!(
            hex::encode(hash_crc16(b"abc", &hargs(&[("variant", "modbus")])).unwrap()),
            "5749"
        );
    }

    #[test]
    fn crc16_stream_matches_memory() {
        let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        for variant in ["arc", "modbus", "maxim", "usb", "ccitt-false", "xmodem"] {
            let args = hargs(&[("variant", variant)]);
            let mut h = make_hash_crc16(&args).unwrap();
            let mut acc = Vec::new();
            for c in data.chunks(11) {
                acc.extend(h.write(c).unwrap());
            }
            acc.extend(h.finish().unwrap());
            assert_eq!(
                acc,
                hash_crc16(&data, &args).unwrap(),
                "stream mismatch: {variant}"
            );
        }
    }

    #[test]
    fn crc16_unknown_variant() {
        let args = hargs(&[("variant", "bogus")]);
        assert!(hash_crc16(b"x", &args).is_err());
    }

    #[test]
    fn adler32_known_values() {
        assert_eq!(hex_of(hash_adler32, b""), "00000001");
        assert_eq!(hex_of(hash_adler32, b"123456789"), "091e01de");
        assert_eq!(hex_of(hash_adler32, b"Wikipedia"), "11e60398");
    }

    #[test]
    fn adler32_stream_matches_memory() {
        let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let mut h = make_hash_adler32(&HashMap::new()).unwrap();
        let mut acc = Vec::new();
        for c in data.chunks(5) {
            acc.extend(h.write(c).unwrap());
        }
        acc.extend(h.finish().unwrap());
        assert_eq!(acc, hash_adler32(&data, &HashMap::new()).unwrap());
    }

    #[test]
    fn fletcher16_known_values() {
        assert_eq!(hex_of(hash_fletcher16, b""), "ffff");
        assert_eq!(hex_of(hash_fletcher16, b"abcde"), "c8f0");
        assert_eq!(hex_of(hash_fletcher16, b"abcdef"), "2057");
        assert_eq!(hex_of(hash_fletcher16, b"abcdefgh"), "0627");
    }

    #[test]
    fn fletcher32_known_values() {
        assert_eq!(hex_of(hash_fletcher32, b""), "ffffffff");
        assert_eq!(hex_of(hash_fletcher32, b"abcde"), "eb54c52b");
        assert_eq!(hex_of(hash_fletcher32, b"abcdef"), "50562a2d");
        assert_eq!(hex_of(hash_fletcher32, b"abcdefgh"), "e1eb9195");
    }

    #[test]
    fn fletcher_streams_match_memory() {
        let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let cases: [(
            &str,
            fn(&HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>>,
            fn(&[u8], &HashMap<String, String>) -> anyhow::Result<Vec<u8>>,
        ); 4] = [
            ("fletcher8", make_hash_fletcher8, hash_fletcher8),
            ("fletcher16", make_hash_fletcher16, hash_fletcher16),
            ("fletcher32", make_hash_fletcher32, hash_fletcher32),
            ("fletcher64", make_hash_fletcher64, hash_fletcher64),
        ];
        for (name, make, run) in cases {
            let mut h = make(&HashMap::new()).unwrap();
            let mut acc = Vec::new();
            for c in data.chunks(9) {
                acc.extend(h.write(c).unwrap());
            }
            acc.extend(h.finish().unwrap());
            assert_eq!(
                acc,
                run(&data, &HashMap::new()).unwrap(),
                "stream mismatch: {name}"
            );
        }
    }

    #[test]
    fn fletcher8_known_values() {
        assert_eq!(hex_of(hash_fletcher8, b""), "ff");
        assert_eq!(hex_of(hash_fletcher8, b"abc"), "19");
        assert_eq!(hex_of(hash_fletcher8, b"abcde"), "50");
        assert_eq!(hex_of(hash_fletcher8, b"hello"), "07");
    }

    #[test]
    fn fletcher64_known_values() {
        assert_eq!(hex_of(hash_fletcher64, b""), "ffffffffffffffff");
        assert_eq!(hex_of(hash_fletcher64, b"hello world"), "2497dd8adc47f249");
        assert_eq!(hex_of(hash_fletcher64, b"abcde"), "c8c6c527646362c6");
        assert_eq!(hex_of(hash_fletcher64, b"abcdefgh"), "312e2b28cccac8c6");
    }

    #[test]
    fn keccak_known_values() {
        let empty256 = hex::encode(hash_keccak(b"", &hargs(&[("variant", "256")])).unwrap());
        assert_eq!(
            empty256,
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
        let abc256 = hex::encode(hash_keccak(b"abc", &hargs(&[("variant", "256")])).unwrap());
        assert_eq!(
            abc256,
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        );
        let empty512 = hex::encode(hash_keccak(b"", &hargs(&[("variant", "512")])).unwrap());
        assert_eq!(
            empty512,
            "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e"
        );
        // Variants produce different widths.
        assert_eq!(
            hash_keccak(b"", &hargs(&[("variant", "224")]))
                .unwrap()
                .len(),
            28
        );
        assert_eq!(
            hash_keccak(b"", &hargs(&[("variant", "384")]))
                .unwrap()
                .len(),
            48
        );
    }

    #[test]
    fn keccak_stream_matches_memory() {
        let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        for variant in ["224", "256", "384", "512"] {
            let args = hargs(&[("variant", variant)]);
            let mut h = make_hash_keccak(&args).unwrap();
            let mut acc = Vec::new();
            for c in data.chunks(13) {
                acc.extend(h.write(c).unwrap());
            }
            acc.extend(h.finish().unwrap());
            assert_eq!(
                acc,
                hash_keccak(&data, &args).unwrap(),
                "stream mismatch: {variant}"
            );
        }
    }

    #[test]
    fn keccak_unknown_variant() {
        assert!(hash_keccak(b"x", &hargs(&[("variant", "123")])).is_err());
    }

    #[test]
    fn shake_known_values() {
        // hashlib shake_128/shake_256, 32-byte digests.
        let cases = [
            (
                "128",
                "",
                "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
            ),
            (
                "128",
                "abc",
                "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8",
            ),
            (
                "256",
                "",
                "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f",
            ),
            (
                "256",
                "abc",
                "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739",
            ),
        ];
        for (variant, input, expected) in cases {
            let args = hargs(&[("variant", variant)]);
            let got = hex::encode(hash_shake(input.as_bytes(), &args).unwrap());
            assert_eq!(got, expected, "shake {variant}({input})");
        }
    }

    #[test]
    fn shake_length_respected() {
        let args = hargs(&[("variant", "256"), ("length", "64")]);
        assert_eq!(hash_shake(b"abc", &args).unwrap().len(), 64);
        let args0 = hargs(&[("variant", "128"), ("length", "0")]);
        assert_eq!(hash_shake(b"abc", &args0).unwrap().len(), 0);
    }

    #[test]
    fn shake_stream_matches_memory() {
        let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        for variant in ["128", "256"] {
            let args = hargs(&[("variant", variant), ("length", "48")]);
            let mut h = make_hash_shake(&args).unwrap();
            let mut acc = Vec::new();
            for c in data.chunks(17) {
                acc.extend(h.write(c).unwrap());
            }
            acc.extend(h.finish().unwrap());
            assert_eq!(
                acc,
                hash_shake(&data, &args).unwrap(),
                "stream mismatch: shake{variant}"
            );
        }
    }

    #[test]
    fn shake_invalid_length() {
        assert!(hash_shake(b"x", &hargs(&[("length", "nan")])).is_err());
    }

    #[test]
    fn nt_hash_known_vectors() {
        // Well-known vectors: NT hash of "password" and of the empty string.
        assert_eq!(
            hex_of(hash_nt, b"password"),
            "8846f7eaee8fb117ad06bdd830b7586c"
        );
        assert_eq!(hex_of(hash_nt, b""), "31d6cfe0d16ae931b73c59d7e0c089c0");
    }

    #[test]
    fn md4_rfc1320_vectors() {
        // RFC 1320 test suite exercised through the in-house MD4 (used by NT hash).
        let cases: &[(&[u8], &str)] = &[
            (b"", "31d6cfe0d16ae931b73c59d7e0c089c0"),
            (b"a", "bde52cb31de33e46245e05fbdbd6fb24"),
            (b"abc", "a448017aaf21d8525fc10ae87aa6729d"),
            (b"message digest", "d9130a8164549fe818874806e1c7014b"),
            (
                b"abcdefghijklmnopqrstuvwxyz",
                "d79e1c308aa5bbcdeea8ed63df412da9",
            ),
            (
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "043f8582f241db351ce627e153e7f0e4",
            ),
            (
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "e33b4ddc9c38f2199c3e7b164fcc0536",
            ),
        ];
        for (input, expected) in cases {
            let mut s = String::new();
            for b in md4_digest(input) {
                s.push_str(&format!("{:02x}", b));
            }
            assert_eq!(&s, *expected, "MD4({:?})", String::from_utf8_lossy(input));
        }
    }

    #[test]
    fn ssdeep_reference_vectors() {
        // Reference signatures generated with libfuzzy (ssdeep 2.14+).
        // The trailing piece character is part of the signature; a "3:" prefix
        // means the smallest (3-byte) blocksize was used.
        let cases: &[(&[u8], &str)] = &[
            (b"", "3::"),
            (b"a", "3:E:E"),
            (b"hello world", "3:iKFSMPn:rJPn"),
            (
                b"The quick brown fox jumps over the lazy dog",
                "3:FJKKIUKact:FHIGi",
            ),
            (&[b'x'; 1000], "3:H:H"),
            (&[b'a'; 5000], "3:tjt:f"),
        ];
        // bytes 0..=255 repeated 10x exercises a larger blocksize (48)
        // and the 31-char truncation of the second signature.
        let seq: Vec<u8> = (0u8..=255).cycle().take(2560).collect();
        let expected_seq = "48:XDfLTTLTDfLTTf7fTL377fTL3TDfLTTLTDfLTTf7fTL377fTL3TDfLTTLTDfLTTn:zf33Pf3ff33Pf33Pf33Pf3ff33Pf33Pb";
        assert_eq!(
            String::from_utf8(hash_ssdeep(&seq, &HashMap::new()).unwrap()).unwrap(),
            expected_seq
        );

        for (input, expected) in cases {
            assert_eq!(
                String::from_utf8(hash_ssdeep(input, &HashMap::new()).unwrap()).unwrap(),
                *expected,
                "ssdeep({:?})",
                String::from_utf8_lossy(input)
            );
        }
    }

    #[test]
    fn ssdeep_compare_known_scores() {
        // Mirrors ssdeep.js similarity semantics (scores rounded to integers).
        let run = |input: &str, delim: &str| {
            String::from_utf8(
                ssdeep_compare(input.as_bytes(), &hargs(&[("delimiter", delim)])).unwrap(),
            )
            .unwrap()
        };
        // identical signatures -> 100
        assert_eq!(run("3:E:E,3:E:E", ","), "100");
        // same blocksize, differing sig1 -> matchScore(sig1a, sig2a)
        assert_eq!(run("3:E:E,3:F:E", ","), "0");
        assert_eq!(run("3:FJKKIUKact:FHIGi,3:FJKKIUKajt:FHIGi", ","), "90");
        assert_eq!(run("3:abc:def,3:abd:ghi", ","), "67");
        // blocksize difference > 1 -> 0
        assert_eq!(run("3:ABC:DE,6:XYZ:UV", ","), "0");
        // adjacent blocksize -> matchScore(small.sig2, big.sig1)
        assert_eq!(run("3:ABC:DE,4:ABD:UV", ","), "0");
        assert_eq!(run("3:ABC:DE,4:ABCDE:UV", ","), "40");
        // custom delimiter
        assert_eq!(run("3:abc:def;3:abd:ghi", ";"), "67");
        // malformed signature -> 0
        assert_eq!(run("3:E:E,not-a-signature", ","), "0");
    }

    #[test]
    fn ssdeep_compare_needs_two_signatures() {
        let err = ssdeep_compare(b"3:E:E", &HashMap::new())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("exactly two"),
            "unexpected error message: {err}"
        );
    }

    #[test]
    fn ssdeep_compare_eicar_parity() {
        // Full-pipeline regression: hash two real inputs, then compare the
        // generated signatures (libfuzzy-style) via the similarity score.
        let eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        let variant = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDERD-ANTIVIRUS-TEST-FILE!$H+H*";
        let run = |a: &[u8], b: &[u8]| {
            let sa = String::from_utf8(hash_ssdeep(a, &HashMap::new()).unwrap()).unwrap();
            let sb = String::from_utf8(hash_ssdeep(b, &HashMap::new()).unwrap()).unwrap();
            String::from_utf8(
                ssdeep_compare(format!("{sa},{sb}").as_bytes(), &HashMap::new()).unwrap(),
            )
            .unwrap()
        };
        assert_eq!(run(eicar, eicar), "100");
        assert_eq!(run(eicar, variant), "83");
    }

    #[test]
    fn lm_hash_known_vectors() {
        // "password" -> e52cac67419a9a224a3b108f3fa6cb6d (classic vector).
        assert_eq!(
            hex_of(hash_lm, b"password"),
            "e52cac67419a9a224a3b108f3fa6cb6d"
        );
        assert_eq!(hex_of(hash_lm, b""), "aad3b435b51404eeaad3b435b51404ee");
        // Uppercase folding: "Password" hashes identically to "password".
        assert_eq!(
            hex_of(hash_lm, b"Password"),
            "e52cac67419a9a224a3b108f3fa6cb6d"
        );
        // Long passwords are truncated to 14 bytes.
        assert_eq!(
            hex_of(hash_lm, b"passwordpassword"),
            hex_of(hash_lm, b"passwordpasswordX")
        );
    }

    #[test]
    fn ripemd_known_vectors() {
        let cases: &[(&str, &[u8], &str)] = &[
            ("128", b"", "cdf26213a150dc3ecb610f18f6b38b46"),
            ("128", b"abc", "c14a12199c66e4ba84636b0f69144c77"),
            ("160", b"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
            ("160", b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
            (
                "256",
                b"",
                "02ba4c4e5f8ecd1877fc52d64d30e37a2d9774fb1e5d026380ae0168e3c5522d",
            ),
            (
                "256",
                b"abc",
                "afbd6e228b9d8cbbcef5ca2d03e6dba10ac0bc7dcbe4680e1e42d2e975459b65",
            ),
            (
                "320",
                b"",
                "22d65d5661536cdc75c1fdf5c6de7b41b9f27325ebc61e8557177d705a0ec880151c3a32a00899b8",
            ),
            (
                "320",
                b"abc",
                "de4c01b3054f8930a79d09ae738e92301e5a17085beffdc1b8d116713e74f82fa942d64cdbc4682d",
            ),
        ];
        for (sz, inp, expect) in cases {
            let args = [("size".to_string(), sz.to_string())]
                .into_iter()
                .collect::<HashMap<_, _>>();
            assert_eq!(
                hex::encode(hash_ripemd160(inp, &args).unwrap()),
                *expect,
                "size={}",
                sz
            );
        }
    }

    #[test]
    fn ripemd_default_size_is_160() {
        assert_eq!(
            hex::encode(hash_ripemd160(b"abc", &HashMap::new()).unwrap()),
            "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
        );
    }

    #[test]
    fn ripemd_stream_matches_memory() {
        for sz in ["128", "160", "256", "320"] {
            let args = [("size".to_string(), sz.to_string())]
                .into_iter()
                .collect::<HashMap<_, _>>();
            let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
            let mut h = make_hash_ripemd160(&args).unwrap();
            let mut acc = Vec::new();
            for c in data.chunks(7) {
                acc.extend(h.write(c).unwrap());
            }
            acc.extend(h.finish().unwrap());
            assert_eq!(acc, hash_ripemd160(&data, &args).unwrap(), "size={}", sz);
        }
    }

    #[test]
    fn ripemd_rejects_bad_size() {
        let args = [("size".to_string(), "999".to_string())]
            .into_iter()
            .collect::<HashMap<_, _>>();
        assert!(hash_ripemd160(b"x", &args).is_err());
        assert!(make_hash_ripemd160(&args).is_err());
    }

    fn args_of(kvs: &[(&str, &str)]) -> HashMap<String, String> {
        kvs.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn sha2_rounds_iteration_vectors() {
        let cases: &[(
            &str,
            fn(&[u8], &HashMap<String, String>) -> anyhow::Result<Vec<u8>>,
            &str,
            &str,
        )] = &[
            (
                "sha1",
                hash_sha1,
                "a9993e364706816aba3e25717850c26c9cd0d89d",
                "0d3ced9bec10a777aec23ccc353a8c08a633045e",
            ),
            (
                "sha224",
                hash_sha224,
                "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
                "2f6268de8b61017569d68593c00a7b442f9dcb898743f4262be4d444",
            ),
            (
                "sha256",
                hash_sha256,
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358",
            ),
            (
                "sha384",
                hash_sha384,
                "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
                "73100f01cf258766906c34a30f9a486f07259c627ea0696d97c4582560447f59a6df4a7cf960708271a30324b1481ef4",
            ),
            (
                "sha512",
                hash_sha512,
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
                "373a9f3a902cf561003b513c94c5164ba4af135cbc4eb4d856b89ea5609523f130bbe5e453e6c645b2765a265aaeb1390c82c913130870636cd0c8ecf980d851",
            ),
        ];
        for (name, f, e1, e2) in cases {
            assert_eq!(
                hex::encode(f(b"abc", &HashMap::new()).unwrap()),
                *e1,
                "{} default",
                name
            );
            assert_eq!(
                hex::encode(f(b"abc", &args_of(&[("rounds", "2")])).unwrap()),
                *e2,
                "{} rounds=2",
                name
            );
            assert_eq!(
                hex::encode(f(b"abc", &args_of(&[("rounds", "1")])).unwrap()),
                *e1,
                "{} rounds=1",
                name
            );
        }
    }

    #[test]
    fn sm3_rounds_iterates() {
        let one = hex::encode(hash_sm3(b"abc", &HashMap::new()).unwrap());
        let two = hex::encode(hash_sm3(b"abc", &args_of(&[("rounds", "2")])).unwrap());
        let three = hex::encode(hash_sm3(b"abc", &args_of(&[("rounds", "3")])).unwrap());
        assert_eq!(two, hex::encode(digest::<Sm3>(&hex::decode(&one).unwrap())));
        assert_eq!(
            three,
            hex::encode(digest::<Sm3>(&hex::decode(&two).unwrap()))
        );
    }

    #[test]
    fn rounds_rejects_bad_values() {
        for v in ["0", "abc", "100001", "-1"] {
            let args = args_of(&[("rounds", v)]);
            assert!(hash_sha256(b"x", &args).is_err(), "rounds={}", v);
            assert!(make_hash_sha256(&args).is_err(), "make rounds={}", v);
        }
    }

    #[test]
    fn rounds_stream_matches_memory() {
        let data: Vec<u8> = (0..=255u8).cycle().take(2048).collect();
        let makes: &[(
            &str,
            fn(&HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>>,
            fn(&[u8], &HashMap<String, String>) -> anyhow::Result<Vec<u8>>,
        )] = &[
            ("sha1", make_hash_sha1, hash_sha1),
            ("sha256", make_hash_sha256, hash_sha256),
            ("sha512", make_hash_sha512, hash_sha512),
            ("sm3", make_hash_sm3, hash_sm3),
        ];
        for (name, make, mem) in makes {
            let args = args_of(&[("rounds", "3")]);
            let mut h = make(&args).unwrap();
            let mut acc = Vec::new();
            for c in data.chunks(13) {
                acc.extend(h.write(c).unwrap());
            }
            acc.extend(h.finish().unwrap());
            assert_eq!(acc, mem(&data, &args).unwrap(), "{} rounds stream", name);
        }
    }

    #[test]
    fn rounds_one_stream_is_incremental() {
        // rounds absent/1 must keep the incremental DigestStream path.
        let data: Vec<u8> = (0..=255u8).cycle().take(1024).collect();
        let pairs: &[(
            fn(&HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>>,
            fn(&[u8], &HashMap<String, String>) -> anyhow::Result<Vec<u8>>,
        )] = &[(make_hash_sha256, hash_sha256), (make_hash_sm3, hash_sm3)];
        for (make, mem) in pairs {
            for args in [HashMap::new(), args_of(&[("rounds", "1")])] {
                let mut h = make(&args).unwrap();
                let mut acc = Vec::new();
                for c in data.chunks(11) {
                    acc.extend(h.write(c).unwrap());
                }
                acc.extend(h.finish().unwrap());
                assert_eq!(acc, mem(&data, &args).unwrap());
            }
        }
    }
}
