//! aes ops (split from mod.rs).

use super::super::cipher::{
    BlockCipherOps, BufBlockStream, CfbStream, CtrStream, OfbStream, cfb_crypt, ctr_crypt,
    ofb_crypt,
};
use super::super::gcm;
use super::super::{ArgSpec, Op, StreamingOp};
use super::*;
use crate::i18n;
use ::aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use ::aes::{Aes128, Aes192, Aes256, Block};
use rand::RngCore;
use std::collections::HashMap;
pub fn ops() -> Vec<Op> {
    vec![
        stream_op!(
            "dpa:aes:encrypt",
            "crypto",
            "op.aes.encrypt.desc",
            &[
                ArgSpec {
                    name: "key",
                    required: true,
                    description: "op.aes.encrypt.arg.key",
                    format: crate::ops::ArgFormat::HexOrUtf8,
                },
                ArgSpec {
                    name: "mode",
                    required: false,
                    description: "op.aes.encrypt.arg.mode",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "iv",
                    required: false,
                    description: "op.aes.encrypt.arg.iv",
                    format: crate::ops::ArgFormat::HexOrUtf8,
                },
                ArgSpec {
                    name: "padding",
                    required: false,
                    description: "op.aes.encrypt.arg.padding",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "aad",
                    required: false,
                    description: "op.aes.encrypt.arg.aad",
                    format: crate::ops::ArgFormat::HexOrUtf8,
                },
                ArgSpec {
                    name: "zero-iv-ok",
                    required: false,
                    description: "op.aes.encrypt.arg.zero_iv_ok",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            aes_encrypt,
            make_aes_enc
        ),
        stream_op!(
            "dpa:aes:decrypt",
            "crypto",
            "op.aes.decrypt.desc",
            &[
                ArgSpec {
                    name: "key",
                    required: true,
                    description: "op.aes.decrypt.arg.key",
                    format: crate::ops::ArgFormat::HexOrUtf8,
                },
                ArgSpec {
                    name: "mode",
                    required: false,
                    description: "op.aes.decrypt.arg.mode",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "iv",
                    required: false,
                    description: "op.aes.decrypt.arg.iv",
                    format: crate::ops::ArgFormat::HexOrUtf8,
                },
                ArgSpec {
                    name: "padding",
                    required: false,
                    description: "op.aes.decrypt.arg.padding",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "aad",
                    required: false,
                    description: "op.aes.decrypt.arg.aad",
                    format: crate::ops::ArgFormat::HexOrUtf8,
                },
                ArgSpec {
                    name: "tag",
                    required: false,
                    description: "op.aes.decrypt.arg.tag",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "zero-iv-ok",
                    required: false,
                    description: "op.aes.decrypt.arg.zero_iv_ok",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            aes_decrypt,
            make_aes_dec
        ),
    ]
}

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum AesMode {
    Ecb,
    Cbc,
    Cfb,
    Ofb,
    Ctr,
    Gcm,
}

impl AesMode {
    fn name(&self) -> &'static str {
        match self {
            Self::Ecb => "ecb",
            Self::Cbc => "cbc",
            Self::Cfb => "cfb",
            Self::Ofb => "ofb",
            Self::Ctr => "ctr",
            Self::Gcm => "gcm",
        }
    }
}

pub(crate) enum AesBlock {
    A128(Aes128),
    A192(Aes192),
    A256(Aes256),
}

impl AesBlock {
    fn encrypt_block(&self, block: &mut [u8; 16]) {
        let mut b = Block::clone_from_slice(block);
        match self {
            Self::A128(c) => c.encrypt_block(&mut b),
            Self::A192(c) => c.encrypt_block(&mut b),
            Self::A256(c) => c.encrypt_block(&mut b),
        }
        block.copy_from_slice(&b);
    }

    fn decrypt_block(&self, block: &mut [u8; 16]) {
        let mut b = Block::clone_from_slice(block);
        match self {
            Self::A128(c) => c.decrypt_block(&mut b),
            Self::A192(c) => c.decrypt_block(&mut b),
            Self::A256(c) => c.decrypt_block(&mut b),
        }
        block.copy_from_slice(&b);
    }
}

impl BlockCipherOps for AesBlock {
    const BLOCK: usize = 16;

    fn encrypt(&self, blk: &mut [u8]) {
        let mut b = [0u8; 16];
        b.copy_from_slice(blk);
        self.encrypt_block(&mut b);
        blk.copy_from_slice(&b);
    }

    fn decrypt(&self, blk: &mut [u8]) {
        let mut b = [0u8; 16];
        b.copy_from_slice(blk);
        self.decrypt_block(&mut b);
        blk.copy_from_slice(&b);
    }
}

impl gcm::GcmBlock for AesBlock {
    fn encrypt_block(&self, blk: &mut [u8; 16]) {
        AesBlock::encrypt_block(self, blk);
    }
}

/// GCM is memory-only (no cross-chunk state); buffer the whole input and
/// run the one-shot AES-GCM path at finish so the CLI can use GCM too.
struct GcmBufferStream {
    buf: Vec<u8>,
    args: HashMap<String, String>,
    encrypt: bool,
}

impl StreamingOp for GcmBufferStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.buf.extend_from_slice(chunk);
        Ok(Vec::new())
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        aes_gcm_run(&self.buf, &self.args, self.encrypt)
    }
}

pub(crate) fn parse_aes_mode(args: &HashMap<String, String>) -> anyhow::Result<AesMode> {
    let m = args.get("mode").map(String::as_str).unwrap_or("cbc");
    match m {
        "ecb" => Ok(AesMode::Ecb),
        "cbc" => Ok(AesMode::Cbc),
        "cfb" => Ok(AesMode::Cfb),
        "ofb" => Ok(AesMode::Ofb),
        "ctr" => Ok(AesMode::Ctr),
        "gcm" => Ok(AesMode::Gcm),
        other => anyhow::bail!(
            "{}",
            i18n::tf("err.unknown_mode", &[other, "ecb/cbc/cfb/ofb/ctr/gcm"])
        ),
    }
}

pub(crate) fn aes_block_from_args(args: &HashMap<String, String>) -> anyhow::Result<AesBlock> {
    let key = require_key(args)?;
    let mk = |e: ::aes::cipher::InvalidLength| {
        anyhow::anyhow!("{}", i18n::tf("err.aes_init", &[e.to_string().as_str()]))
    };
    let block = match key.len() {
        16 => AesBlock::A128(Aes128::new_from_slice(&key).map_err(mk)?),
        24 => AesBlock::A192(Aes192::new_from_slice(&key).map_err(mk)?),
        32 => AesBlock::A256(Aes256::new_from_slice(&key).map_err(mk)?),
        n => anyhow::bail!("{}", i18n::tf("err.aes_key_len", &[n.to_string().as_str()])),
    };
    Ok(block)
}

pub(crate) fn aes_encrypt(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    aes_run(input, args, true)
}

pub(crate) fn aes_decrypt(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    aes_run(input, args, false)
}

pub(crate) fn aes_run(
    input: &[u8],
    args: &HashMap<String, String>,
    encrypt: bool,
) -> anyhow::Result<Vec<u8>> {
    match parse_aes_mode(args)? {
        AesMode::Ecb => aes_block_crypt(input, args, true, encrypt),
        AesMode::Cbc => aes_block_crypt(input, args, false, encrypt),
        AesMode::Cfb => cfb_crypt(input, args, aes_block_from_args(args)?, encrypt),
        AesMode::Ofb => ofb_crypt(input, args, aes_block_from_args(args)?),
        AesMode::Ctr => ctr_crypt(input, args, aes_block_from_args(args)?),
        AesMode::Gcm => aes_gcm_run(input, args, encrypt),
    }
}

/// In-memory ECB/CBC for AES, sharing the generic buffered block-mode stream
/// (BufBlockStream): one-shot write + finish. Block modes use PKCS#7 (or
/// padding=none); iv defaults to the all-zero block.
pub(crate) fn aes_block_crypt(
    input: &[u8],
    args: &HashMap<String, String>,
    ecb: bool,
    encrypt: bool,
) -> anyhow::Result<Vec<u8>> {
    let mut s = BufBlockStream::new(args, aes_block_from_args(args)?, ecb, encrypt)?;
    let mut out = s.write(input)?;
    out.extend(s.finish()?);
    Ok(out)
}

/// GCM encrypt IV + output-layout decision.
///
/// - explicit `iv` → use it; output stays `ct || tag` (classic layout, so NIST
///   vectors and interop with other tools remain unchanged);
/// - no `iv` (default) → random 12-byte IV; output becomes `iv || ct || tag`
///   so the decrypt side can auto-split it;
/// - no `iv` + `zero-iv-ok` → deterministic 12 zero bytes; output stays
///   `ct || tag` (INSECURE escape hatch for legacy scripts / reproducibility).
///
/// Returns `(iv, prefix)` where `prefix` means "prepend iv to the output".
pub(crate) fn gcm_encrypt_iv(args: &HashMap<String, String>) -> anyhow::Result<(Vec<u8>, bool)> {
    if let Some(s) = args.get("iv") {
        let v = parse_key(s)?;
        if v.is_empty() {
            anyhow::bail!("{}", i18n::t("err.empty_iv"));
        }
        return Ok((v, false));
    }
    if opt_bool(args, "zero-iv-ok")? {
        return Ok((vec![0u8; gcm::GCM_IV_LEN], false));
    }
    let mut iv = [0u8; gcm::GCM_IV_LEN];
    rand::rng().fill_bytes(&mut iv);
    Ok((iv.to_vec(), true))
}

/// GCM decrypt input layout + optional `tag` cross-check.
///
/// - explicit `iv` → input is `ct || tag` (trailing 16 bytes = tag);
/// - no `iv` (default) → input is `iv || ct || tag`, auto-split;
/// - no `iv` + `zero-iv-ok` → input is `ct || tag` with a 12-zero IV.
///
/// A provided `tag` argument is cross-checked against the trailing tag (legacy
/// scripts keep working); it is no longer required.
pub(crate) fn gcm_split_decrypt_input(
    input: &[u8],
    args: &HashMap<String, String>,
) -> anyhow::Result<(Vec<u8>, Vec<u8>, [u8; 16])> {
    let iv: Vec<u8>;
    let ct: &[u8];
    let tag: [u8; 16];
    // Legacy layout: explicit iv + tag argument → input is ct only, tag from args.
    let legacy_tag: Option<[u8; 16]> = if let Some(t) = args.get("tag") {
        let t = parse_key(t)?;
        if t.len() != gcm::GCM_TAG_LEN {
            anyhow::bail!(
                "{}",
                i18n::tf("err.gcm_tag_len", &[t.len().to_string().as_str()])
            );
        }
        Some(t.try_into().unwrap())
    } else {
        None
    };
    if let Some(s) = args.get("iv") {
        let v = parse_key(s)?;
        if v.is_empty() {
            anyhow::bail!("{}", i18n::t("err.empty_iv"));
        }
        iv = v;
        if let Some(t) = legacy_tag {
            ct = input;
            tag = t;
        } else {
            if input.len() < gcm::GCM_TAG_LEN {
                anyhow::bail!("{}", i18n::t("err.gcm_payload_short"));
            }
            ct = &input[..input.len() - gcm::GCM_TAG_LEN];
            tag = input[input.len() - gcm::GCM_TAG_LEN..].try_into().unwrap();
        }
    } else if opt_bool(args, "zero-iv-ok")? {
        if let Some(t) = legacy_tag {
            ct = input;
            tag = t;
        } else {
            if input.len() < gcm::GCM_TAG_LEN {
                anyhow::bail!("{}", i18n::t("err.gcm_payload_short"));
            }
            ct = &input[..input.len() - gcm::GCM_TAG_LEN];
            tag = input[input.len() - gcm::GCM_TAG_LEN..].try_into().unwrap();
        }
        iv = vec![0u8; gcm::GCM_IV_LEN];
    } else {
        if input.len() < gcm::GCM_IV_LEN + gcm::GCM_TAG_LEN {
            anyhow::bail!("{}", i18n::t("err.gcm_payload_short"));
        }
        iv = input[..gcm::GCM_IV_LEN].to_vec();
        ct = &input[gcm::GCM_IV_LEN..input.len() - gcm::GCM_TAG_LEN];
        tag = input[input.len() - gcm::GCM_TAG_LEN..].try_into().unwrap();
    }
    if let Some(t) = legacy_tag
        && t != tag
    {
        anyhow::bail!("{}", i18n::t("err.gcm_tag_mismatch"));
    }
    Ok((iv, ct.to_vec(), tag))
}

/// Parse an optional boolean argument (default false).
pub(crate) fn opt_bool(args: &HashMap<String, String>, name: &str) -> anyhow::Result<bool> {
    match args.get(name) {
        None => Ok(false),
        Some(s) => crate::ops::parse_bool(s),
    }
}

/// GCM additional authenticated data: hex or UTF-8 bytes, default empty.
pub(crate) fn opt_aad(args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    match args.get("aad") {
        None => Ok(Vec::new()),
        Some(s) => parse_key(s),
    }
}

pub(crate) fn aes_gcm_run(
    input: &[u8],
    args: &HashMap<String, String>,
    encrypt: bool,
) -> anyhow::Result<Vec<u8>> {
    let block = aes_block_from_args(args)?;
    let aad = opt_aad(args)?;
    if encrypt {
        let (iv, prefix) = gcm_encrypt_iv(args)?;
        let (mut ct, tag) = gcm::encrypt(&block, &iv, &aad, input);
        if prefix {
            let mut out = Vec::with_capacity(gcm::GCM_IV_LEN + ct.len() + gcm::GCM_TAG_LEN);
            out.extend_from_slice(&iv);
            out.extend_from_slice(&ct);
            out.extend_from_slice(&tag);
            Ok(out)
        } else {
            ct.extend_from_slice(&tag);
            Ok(ct)
        }
    } else {
        let (iv, ct, tag) = gcm_split_decrypt_input(input, args)?;
        gcm::decrypt(&block, &iv, &aad, &ct, &tag)
    }
}

pub(crate) fn make_aes_enc(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    make_aes(args, true)
}

pub(crate) fn make_aes_dec(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    make_aes(args, false)
}

pub(crate) fn make_aes(
    args: &HashMap<String, String>,
    encrypt: bool,
) -> anyhow::Result<Box<dyn StreamingOp>> {
    let mode = parse_aes_mode(args)?;
    if let Some(w) = implicit_zero_iv_warning(args, mode.name(), encrypt) {
        eprintln!("{}", w);
    }
    let block = aes_block_from_args(args)?;
    match mode {
        AesMode::Ecb => Ok(Box::new(BufBlockStream::new(args, block, true, encrypt)?)),
        AesMode::Cbc => Ok(Box::new(BufBlockStream::new(args, block, false, encrypt)?)),
        AesMode::Cfb => Ok(Box::new(CfbStream::new(args, block, encrypt)?)),
        AesMode::Ofb => Ok(Box::new(OfbStream::new(args, block)?)),
        AesMode::Ctr => Ok(Box::new(CtrStream::new(args, block)?)),
        AesMode::Gcm => Ok(Box::new(GcmBufferStream {
            buf: Vec::new(),
            args: args.clone(),
            encrypt,
        })),
    }
}
