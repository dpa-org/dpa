//! Symmetric block ciphers: SM4 / DES.
//!
//! Same "direction split, mode parameterized" convention as AES (see crypto.rs):
//! one encrypt op + one decrypt op; the mode is an optional parameter with a
//! default (cbc); the iv is optional and defaults to the all-zero block.
//! Block modes (ecb/cbc) use PKCS#7 padding; ctr needs no padding.

use std::collections::HashMap;

use super::{ArgSpec, Op, StreamingOp};
use crate::i18n;

// SM4 re-exports cipher 0.3 traits under sm4::cipher (not compatible with the
// cipher 0.4 traits used by aes/des below; keep the two worlds separate).
use sm4::Sm4;
use sm4::cipher::{
    Block as Sm4Block, BlockDecrypt as Sm4BlockDecrypt, BlockEncrypt as Sm4BlockEncrypt,
    NewBlockCipher,
};

// DES uses cipher 0.4.
use des::Des;
use des::cipher::{
    Block as DesBlock, BlockDecrypt as DesBlockDecrypt, BlockEncrypt as DesBlockEncrypt, KeyInit,
};

pub fn ops() -> Vec<Op> {
    vec![
        stream_op!(
            "dpa:sm4:encrypt",
            "crypto",
            "op.sm4.encrypt.desc",
            &[
                ArgSpec {
                    name: "key",
                    required: true,
                    description: "op.sm4.encrypt.arg.key",
                    format: crate::ops::ArgFormat::HexOrUtf8,
                },
                ArgSpec {
                    name: "mode",
                    required: false,
                    description: "op.sm4.encrypt.arg.mode",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "iv",
                    required: false,
                    description: "op.sm4.encrypt.arg.iv",
                    format: crate::ops::ArgFormat::HexOrUtf8,
                },
                ArgSpec {
                    name: "padding",
                    required: false,
                    description: "op.sm4.encrypt.arg.padding",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            sm4_encrypt,
            make_sm4_enc
        ),
        stream_op!(
            "dpa:sm4:decrypt",
            "crypto",
            "op.sm4.decrypt.desc",
            &[
                ArgSpec {
                    name: "key",
                    required: true,
                    description: "op.sm4.decrypt.arg.key",
                    format: crate::ops::ArgFormat::HexOrUtf8,
                },
                ArgSpec {
                    name: "mode",
                    required: false,
                    description: "op.sm4.decrypt.arg.mode",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "iv",
                    required: false,
                    description: "op.sm4.decrypt.arg.iv",
                    format: crate::ops::ArgFormat::HexOrUtf8,
                },
                ArgSpec {
                    name: "padding",
                    required: false,
                    description: "op.sm4.decrypt.arg.padding",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            sm4_decrypt,
            make_sm4_dec
        ),
        stream_op!(
            "dpa:des:encrypt",
            "crypto",
            "op.des.encrypt.desc",
            &[
                ArgSpec {
                    name: "key",
                    required: true,
                    description: "op.des.encrypt.arg.key",
                    format: crate::ops::ArgFormat::HexOrUtf8,
                },
                ArgSpec {
                    name: "mode",
                    required: false,
                    description: "op.des.encrypt.arg.mode",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "iv",
                    required: false,
                    description: "op.des.encrypt.arg.iv",
                    format: crate::ops::ArgFormat::HexOrUtf8,
                },
                ArgSpec {
                    name: "padding",
                    required: false,
                    description: "op.des.encrypt.arg.padding",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            des_encrypt,
            make_des_enc
        ),
        stream_op!(
            "dpa:des:decrypt",
            "crypto",
            "op.des.decrypt.desc",
            &[
                ArgSpec {
                    name: "key",
                    required: true,
                    description: "op.des.decrypt.arg.key",
                    format: crate::ops::ArgFormat::HexOrUtf8,
                },
                ArgSpec {
                    name: "mode",
                    required: false,
                    description: "op.des.decrypt.arg.mode",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "iv",
                    required: false,
                    description: "op.des.decrypt.arg.iv",
                    format: crate::ops::ArgFormat::HexOrUtf8,
                },
                ArgSpec {
                    name: "padding",
                    required: false,
                    description: "op.des.decrypt.arg.padding",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            des_decrypt,
            make_des_dec
        ),
    ]
}

// ---------------------------------------------------------------------------
// PKCS#7 padding / unpadding (block modes only).
// ---------------------------------------------------------------------------

pub(crate) fn pkcs7_pad(data: &[u8], block: usize) -> Vec<u8> {
    let pad = block - (data.len() % block);
    let mut out = data.to_vec();
    out.extend(std::iter::repeat_n(pad as u8, pad));
    out
}

pub(crate) fn pkcs7_unpad(data: &[u8], block: usize) -> Result<Vec<u8>, &'static str> {
    if data.is_empty() || data.len() % block != 0 {
        return Err("ciphertext length is not a multiple of the block size");
    }
    let pad = data[data.len() - 1] as usize;
    if pad == 0 || pad > block {
        return Err("invalid PKCS#7 padding length");
    }
    let start = data.len() - pad;
    if !data[start..].iter().all(|&b| b as usize == pad) {
        return Err("invalid PKCS#7 padding bytes");
    }
    Ok(data[..start].to_vec())
}

// ---------------------------------------------------------------------------
// Generic buffered block-mode stream (ecb / cbc) shared by SM4 and DES.
// Encrypt buffers whole blocks and pads at finish; decrypt holds the final
// block back until finish so padding is validated over the full ciphertext.
// ---------------------------------------------------------------------------

/// Padding policy for block modes (ecb/cbc). `Pkcs7` is the default; `None`
/// requires block-aligned input and does not add or strip padding bytes.
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Padding {
    Pkcs7,
    None,
}

pub(crate) fn parse_padding(args: &HashMap<String, String>) -> anyhow::Result<Padding> {
    match opt_arg(args, "padding", "pkcs7") {
        "pkcs7" => Ok(Padding::Pkcs7),
        "none" => Ok(Padding::None),
        other => anyhow::bail!("{}", i18n::tf("err.bad_padding", &[other])),
    }
}

pub(crate) trait BlockCipherOps {
    const BLOCK: usize;
    fn encrypt(&self, blk: &mut [u8]);
    fn decrypt(&self, blk: &mut [u8]);
}

impl BlockCipherOps for Sm4 {
    const BLOCK: usize = 16;

    fn encrypt(&self, blk: &mut [u8]) {
        let mut b = Sm4Block::<Sm4>::clone_from_slice(blk);
        Sm4BlockEncrypt::encrypt_block(self, &mut b);
        blk.copy_from_slice(&b);
    }

    fn decrypt(&self, blk: &mut [u8]) {
        let mut b = Sm4Block::<Sm4>::clone_from_slice(blk);
        Sm4BlockDecrypt::decrypt_block(self, &mut b);
        blk.copy_from_slice(&b);
    }
}

impl BlockCipherOps for Des {
    const BLOCK: usize = 8;

    fn encrypt(&self, blk: &mut [u8]) {
        let mut b = DesBlock::<Des>::clone_from_slice(blk);
        DesBlockEncrypt::encrypt_block(self, &mut b);
        blk.copy_from_slice(&b);
    }

    fn decrypt(&self, blk: &mut [u8]) {
        let mut b = DesBlock::<Des>::clone_from_slice(blk);
        DesBlockDecrypt::decrypt_block(self, &mut b);
        blk.copy_from_slice(&b);
    }
}

pub(crate) struct BufBlockStream<C: BlockCipherOps> {
    cipher: C,
    ecb: bool,
    encrypt: bool,
    padding: Padding,
    prev: Vec<u8>, // CBC chaining: previous ciphertext block
    buf: Vec<u8>,
    pending: Option<Vec<u8>>, // decrypt: last full block held back for unpad
    finished: bool,
}

impl<C: BlockCipherOps> BufBlockStream<C> {
    pub(crate) fn new(
        args: &HashMap<String, String>,
        cipher: C,
        ecb: bool,
        encrypt: bool,
    ) -> anyhow::Result<Self> {
        let prev = opt_iv(args, C::BLOCK)?;
        let padding = parse_padding(args)?;
        Ok(Self {
            cipher,
            ecb,
            encrypt,
            padding,
            prev,
            buf: Vec::new(),
            pending: None,
            finished: false,
        })
    }

    fn process_block(&mut self, blk: &[u8]) -> Vec<u8> {
        let mut b = blk.to_vec();
        if self.encrypt {
            if !self.ecb {
                for (i, bi) in b.iter_mut().enumerate() {
                    *bi ^= self.prev[i];
                }
            }
            self.cipher.encrypt(&mut b);
            self.prev = b.clone();
        } else {
            let prev = if self.ecb {
                vec![0u8; C::BLOCK]
            } else {
                self.prev.clone()
            };
            let cur = b.clone();
            self.cipher.decrypt(&mut b);
            if !self.ecb {
                for i in 0..C::BLOCK {
                    b[i] ^= prev[i];
                }
            }
            self.prev = cur;
        }
        b
    }
}

impl<C: BlockCipherOps> StreamingOp for BufBlockStream<C> {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        if self.finished {
            anyhow::bail!("{}", i18n::t("err.stream_finished"));
        }
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();
        if let Some(p) = self.pending.take() {
            out.extend_from_slice(&p);
        }
        let bs = C::BLOCK;
        let mut n_full = self.buf.len() / bs;
        if !self.encrypt && self.padding == Padding::Pkcs7 && n_full > 0 {
            n_full -= 1; // hold the last full block back for unpad at finish
        }
        for i in 0..n_full {
            let blk = self.buf[i * bs..(i + 1) * bs].to_vec();
            let processed = self.process_block(&blk);
            out.extend_from_slice(&processed);
        }
        self.buf.drain(..n_full * bs);
        if !self.encrypt && self.padding == Padding::Pkcs7 && self.buf.len() >= bs {
            let blk: Vec<u8> = self.buf[..bs].to_vec();
            let b = self.process_block(&blk);
            self.pending = Some(b);
            self.buf.drain(..bs);
        }
        Ok(out)
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        if self.finished {
            return Ok(Vec::new());
        }
        self.finished = true;
        let bs = C::BLOCK;
        if self.encrypt {
            let data = match self.padding {
                Padding::Pkcs7 => pkcs7_pad(&self.buf, bs),
                Padding::None => {
                    if !self.buf.is_empty() {
                        anyhow::bail!(
                            "{}",
                            i18n::tf(
                                "err.block_alignment",
                                &[self.buf.len().to_string().as_str()]
                            )
                        );
                    }
                    Vec::new()
                }
            };
            let mut out = Vec::with_capacity(data.len());
            for blk in data.chunks_exact(bs) {
                out.extend_from_slice(&self.process_block(blk));
            }
            Ok(out)
        } else {
            if !self.buf.is_empty() {
                anyhow::bail!(
                    "{}",
                    i18n::tf("err.ciphertext_len", &[self.buf.len().to_string().as_str()])
                );
            }
            match self.padding {
                Padding::Pkcs7 => match self.pending.take() {
                    Some(last) => pkcs7_unpad(&last, bs)
                        .map_err(|e| anyhow::anyhow!("{}", i18n::tf("err.unpad", &[e]))),
                    None => anyhow::bail!(
                        "{}",
                        i18n::tf("err.ciphertext_len", &["0".to_string().as_str()])
                    ),
                },
                // no padding: every aligned block was already emitted by write()
                Padding::None => Ok(Vec::new()),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Generic CTR stream (SM4): keystream block = E_K(counter block), counter
// starts at the iv value and increments as a big-endian whole block.
// ---------------------------------------------------------------------------

pub(crate) struct CtrStream<C: BlockCipherOps> {
    cipher: C,
    ctr: Vec<u8>,
    cur: Vec<u8>,
    pos: usize,
}

impl<C: BlockCipherOps> CtrStream<C> {
    pub(crate) fn new(args: &HashMap<String, String>, cipher: C) -> anyhow::Result<Self> {
        let iv = opt_iv(args, C::BLOCK)?;
        let mut cur = vec![0u8; C::BLOCK];
        let mut s = Self {
            cipher,
            ctr: iv,
            cur: cur.clone(),
            pos: C::BLOCK,
        };
        next_keystream(&s.cipher, &mut s.ctr, &mut cur);
        s.cur = cur;
        s.pos = 0;
        Ok(s)
    }
}

/// Fills `out` with the keystream block E_K(counter), then increments the
/// counter block as a big-endian whole block.
fn next_keystream<C: BlockCipherOps>(cipher: &C, ctr: &mut [u8], out: &mut [u8]) {
    out.copy_from_slice(ctr);
    cipher.encrypt(out);
    let bs = C::BLOCK;
    for i in (0..bs).rev() {
        ctr[i] = ctr[i].wrapping_add(1);
        if ctr[i] != 0 {
            break;
        }
    }
}

impl<C: BlockCipherOps> StreamingOp for CtrStream<C> {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(chunk.len());
        let bs = C::BLOCK;
        let mut i = 0;
        while i < chunk.len() {
            if self.pos == bs {
                next_keystream(&self.cipher, &mut self.ctr, &mut self.cur);
                self.pos = 0;
            }
            let n = (chunk.len() - i).min(bs - self.pos);
            for (j, &b) in chunk[i..i + n].iter().enumerate() {
                out.push(b ^ self.cur[self.pos + j]);
            }
            self.pos += n;
            i += n;
        }
        Ok(out)
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        Ok(Vec::new())
    }
}

// ---------------------------------------------------------------------------
// Generic CFB stream: standard CFB with full-block feedback (CFB-128 for 16-byte
// ciphers, CFB-64 for 8-byte ciphers). Keystream = E_K(feedback); the feedback
// block is refreshed only at block boundaries: cipher output on encrypt, cipher
// input on decrypt. Trailing partial blocks reuse the current keystream without
// a feedback shift (review fix 3.1: the previous byte-wise sliding window was
// CFB-8 and diverged from the standard mode on multi-block inputs).
// ---------------------------------------------------------------------------

pub(crate) struct CfbStream<C: BlockCipherOps> {
    cipher: C,
    fb: Vec<u8>,
    encrypt: bool,
    /// Bytes of the in-flight block that have not crossed a full block boundary.
    pending: Vec<u8>,
}

impl<C: BlockCipherOps> CfbStream<C> {
    pub(crate) fn new(
        args: &HashMap<String, String>,
        cipher: C,
        encrypt: bool,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            cipher,
            fb: opt_iv(args, C::BLOCK)?,
            encrypt,
            pending: Vec::with_capacity(C::BLOCK),
        })
    }
}

fn cfb_block<C: BlockCipherOps>(s: &mut CfbStream<C>, block_in: &[u8]) -> Vec<u8> {
    let bs = C::BLOCK;
    let mut ks = s.fb.clone();
    s.cipher.encrypt(&mut ks);
    let mut out = vec![0u8; bs];
    for j in 0..bs {
        out[j] = block_in[j] ^ ks[j];
    }
    if s.encrypt {
        s.fb = out.clone();
    } else {
        s.fb = block_in.to_vec();
    }
    out
}

impl<C: BlockCipherOps> StreamingOp for CfbStream<C> {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        let bs = C::BLOCK;
        let mut out = Vec::with_capacity(chunk.len() + self.pending.len());
        self.pending.extend_from_slice(chunk);
        let mut consumed = 0;
        while self.pending.len() - consumed >= bs {
            let block = self.pending[consumed..consumed + bs].to_vec();
            out.extend_from_slice(&cfb_block(self, &block));
            consumed += bs;
        }
        if consumed > 0 {
            self.pending.drain(..consumed);
        }
        Ok(out)
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        // Trailing partial block: XOR with E_K(current feedback), no feedback
        // update (standard full-block CFB semantics for a final partial block).
        if !self.pending.is_empty() {
            let mut ks = self.fb.clone();
            self.cipher.encrypt(&mut ks);
            let out: Vec<u8> = self
                .pending
                .iter()
                .zip(ks.iter())
                .map(|(&a, &k)| a ^ k)
                .collect();
            self.pending.clear();
            return Ok(out);
        }
        Ok(Vec::new())
    }
}

// ---------------------------------------------------------------------------
// Generic OFB stream: keystream block = E_K(feedback), feedback refreshed with
// the whole keystream block at block boundaries (standard OFB). Encryption and
// decryption are the same operation.
// ---------------------------------------------------------------------------

pub(crate) struct OfbStream<C: BlockCipherOps> {
    cipher: C,
    fb: Vec<u8>,
    cur: Vec<u8>,
    pos: usize,
}

impl<C: BlockCipherOps> OfbStream<C> {
    pub(crate) fn new(args: &HashMap<String, String>, cipher: C) -> anyhow::Result<Self> {
        let bs = C::BLOCK;
        let fb = opt_iv(args, bs)?;
        let mut s = Self {
            cipher,
            fb: fb.clone(),
            cur: vec![0u8; bs],
            pos: bs,
        };
        s.refresh();
        Ok(s)
    }

    fn refresh(&mut self) {
        self.cur = self.fb.clone();
        self.cipher.encrypt(&mut self.cur);
        self.fb = self.cur.clone();
        self.pos = 0;
    }
}

impl<C: BlockCipherOps> StreamingOp for OfbStream<C> {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        let bs = C::BLOCK;
        let mut out = Vec::with_capacity(chunk.len());
        let mut i = 0;
        while i < chunk.len() {
            if self.pos == bs {
                self.refresh();
            }
            let n = (chunk.len() - i).min(bs - self.pos);
            for (j, &b) in chunk[i..i + n].iter().enumerate() {
                out.push(b ^ self.cur[self.pos + j]);
            }
            self.pos += n;
            i += n;
        }
        Ok(out)
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        Ok(Vec::new())
    }
}

/// In-memory CFB encryption/decryption (standard full-block feedback CFB).
pub(crate) fn cfb_crypt<C: BlockCipherOps>(
    input: &[u8],
    args: &HashMap<String, String>,
    cipher: C,
    encrypt: bool,
) -> anyhow::Result<Vec<u8>> {
    let mut s = CfbStream::new(args, cipher, encrypt)?;
    let mut out = s.write(input)?;
    out.extend(s.finish()?);
    Ok(out)
}

/// In-memory OFB encryption/decryption (standard whole-block keystream feedback).
pub(crate) fn ofb_crypt<C: BlockCipherOps>(
    input: &[u8],
    args: &HashMap<String, String>,
    cipher: C,
) -> anyhow::Result<Vec<u8>> {
    let mut s = OfbStream::new(args, cipher)?;
    let mut out = s.write(input)?;
    out.extend(s.finish()?);
    Ok(out)
}

/// In-memory CTR encryption/decryption (big-endian whole-block counter).
pub(crate) fn ctr_crypt<C: BlockCipherOps>(
    input: &[u8],
    args: &HashMap<String, String>,
    cipher: C,
) -> anyhow::Result<Vec<u8>> {
    let bs = C::BLOCK;
    let mut ctr = opt_iv(args, bs)?;
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        let mut ks = vec![0u8; bs];
        ks.copy_from_slice(&ctr);
        cipher.encrypt(&mut ks);
        for i2 in (0..bs).rev() {
            ctr[i2] = ctr[i2].wrapping_add(1);
            if ctr[i2] != 0 {
                break;
            }
        }
        let n = (input.len() - i).min(bs);
        for (j, &b) in input[i..i + n].iter().enumerate() {
            out.push(b ^ ks[j]);
        }
        i += n;
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Shared argument helpers (duplicated locally to avoid coupling with crypto.rs
// private helpers; keep in sync).
// ---------------------------------------------------------------------------

fn require_key(args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let key_str = args
        .get("key")
        .ok_or_else(|| anyhow::anyhow!("{}", i18n::t("err.missing_key")))?;
    let key = parse_key(key_str)?;
    if key.is_empty() {
        anyhow::bail!("{}", i18n::t("err.empty_key"));
    }
    Ok(key)
}

fn opt_arg<'a>(args: &'a HashMap<String, String>, name: &str, default: &'a str) -> &'a str {
    args.get(name).map(String::as_str).unwrap_or(default)
}

fn parse_key(key: &str) -> anyhow::Result<Vec<u8>> {
    let t = key.trim();
    if let Some(hex_part) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        let cleaned: String = hex_part.chars().filter(|c| !c.is_whitespace()).collect();
        hex::decode(&cleaned).map_err(|e| {
            anyhow::anyhow!("{}", i18n::tf("err.key_not_hex", &[e.to_string().as_str()]))
        })
    } else {
        Ok(key.as_bytes().to_vec())
    }
}

/// Optional iv with an all-zero default of the given block width.
fn opt_iv(args: &HashMap<String, String>, width: usize) -> anyhow::Result<Vec<u8>> {
    match args.get("iv") {
        None => Ok(vec![0u8; width]),
        Some(s) => {
            let v = parse_key(s)?;
            if v.len() != width {
                anyhow::bail!(
                    "{}",
                    i18n::tf("err.iv_len", &[v.len().to_string().as_str()])
                );
            }
            Ok(v)
        }
    }
}

// ---------------------------------------------------------------------------
// SM4
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
enum Sm4Mode {
    Ecb,
    Cbc,
    Cfb,
    Ofb,
    Ctr,
}

fn parse_sm4_mode(args: &HashMap<String, String>) -> anyhow::Result<Sm4Mode> {
    match opt_arg(args, "mode", "cbc") {
        "ecb" => Ok(Sm4Mode::Ecb),
        "cbc" => Ok(Sm4Mode::Cbc),
        "cfb" => Ok(Sm4Mode::Cfb),
        "ofb" => Ok(Sm4Mode::Ofb),
        "ctr" => Ok(Sm4Mode::Ctr),
        other => anyhow::bail!(
            "{}",
            i18n::tf("err.unknown_mode", &[other, "ecb/cbc/cfb/ofb/ctr"])
        ),
    }
}

fn sm4_from_args(args: &HashMap<String, String>) -> anyhow::Result<Sm4> {
    let key = require_key(args)?;
    if key.len() != 16 {
        anyhow::bail!(
            "{}",
            i18n::tf("err.sm4_key_len", &[key.len().to_string().as_str()])
        );
    }
    Sm4::new_from_slice(&key)
        .map_err(|_| anyhow::anyhow!("{}", i18n::tf("err.sm4_init", &["invalid key material"])))
}

fn sm4_encrypt(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    sm4_run(input, args, true)
}

fn sm4_decrypt(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    sm4_run(input, args, false)
}

fn sm4_run(input: &[u8], args: &HashMap<String, String>, encrypt: bool) -> anyhow::Result<Vec<u8>> {
    match parse_sm4_mode(args)? {
        Sm4Mode::Ecb => sm4_block_crypt(input, args, true, encrypt),
        Sm4Mode::Cbc => sm4_block_crypt(input, args, false, encrypt),
        Sm4Mode::Cfb => cfb_crypt(input, args, sm4_from_args(args)?, encrypt),
        Sm4Mode::Ofb => ofb_crypt(input, args, sm4_from_args(args)?),
        Sm4Mode::Ctr => ctr_crypt(input, args, sm4_from_args(args)?),
    }
}

fn sm4_block_crypt(
    input: &[u8],
    args: &HashMap<String, String>,
    ecb: bool,
    encrypt: bool,
) -> anyhow::Result<Vec<u8>> {
    let mut s = BufBlockStream::new(args, sm4_from_args(args)?, ecb, encrypt)?;
    let mut out = s.write(input)?;
    out.extend(s.finish()?);
    Ok(out)
}

fn make_sm4_enc(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    make_sm4(args, true)
}

fn make_sm4_dec(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    make_sm4(args, false)
}

fn make_sm4(args: &HashMap<String, String>, encrypt: bool) -> anyhow::Result<Box<dyn StreamingOp>> {
    match parse_sm4_mode(args)? {
        Sm4Mode::Ecb => Ok(Box::new(BufBlockStream::new(
            args,
            sm4_from_args(args)?,
            true,
            encrypt,
        )?)),
        Sm4Mode::Cbc => Ok(Box::new(BufBlockStream::new(
            args,
            sm4_from_args(args)?,
            false,
            encrypt,
        )?)),
        Sm4Mode::Cfb => Ok(Box::new(CfbStream::new(
            args,
            sm4_from_args(args)?,
            encrypt,
        )?)),
        Sm4Mode::Ofb => Ok(Box::new(OfbStream::new(args, sm4_from_args(args)?)?)),
        Sm4Mode::Ctr => Ok(Box::new(CtrStream::new(args, sm4_from_args(args)?)?)),
    }
}

// ---------------------------------------------------------------------------
// DES
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
enum DesMode {
    Ecb,
    Cbc,
    Cfb,
    Ofb,
    Ctr,
}

fn parse_des_mode(args: &HashMap<String, String>) -> anyhow::Result<DesMode> {
    match opt_arg(args, "mode", "cbc") {
        "ecb" => Ok(DesMode::Ecb),
        "cbc" => Ok(DesMode::Cbc),
        "cfb" => Ok(DesMode::Cfb),
        "ofb" => Ok(DesMode::Ofb),
        "ctr" => Ok(DesMode::Ctr),
        other => anyhow::bail!(
            "{}",
            i18n::tf("err.unknown_mode", &[other, "ecb/cbc/cfb/ofb/ctr"])
        ),
    }
}

fn des_from_args(args: &HashMap<String, String>) -> anyhow::Result<Des> {
    let key = require_key(args)?;
    if key.len() != 8 {
        anyhow::bail!(
            "{}",
            i18n::tf("err.des_key_len", &[key.len().to_string().as_str()])
        );
    }
    Des::new_from_slice(&key)
        .map_err(|_| anyhow::anyhow!("{}", i18n::tf("err.des_init", &["invalid key material"])))
}

fn des_encrypt(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    des_run(input, args, true)
}

fn des_decrypt(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    des_run(input, args, false)
}

fn des_run(input: &[u8], args: &HashMap<String, String>, encrypt: bool) -> anyhow::Result<Vec<u8>> {
    match parse_des_mode(args)? {
        DesMode::Ecb => des_block_crypt(input, args, true, encrypt),
        DesMode::Cbc => des_block_crypt(input, args, false, encrypt),
        DesMode::Cfb => cfb_crypt(input, args, des_from_args(args)?, encrypt),
        DesMode::Ofb => ofb_crypt(input, args, des_from_args(args)?),
        DesMode::Ctr => ctr_crypt(input, args, des_from_args(args)?),
    }
}

fn des_block_crypt(
    input: &[u8],
    args: &HashMap<String, String>,
    ecb: bool,
    encrypt: bool,
) -> anyhow::Result<Vec<u8>> {
    let mut s = BufBlockStream::new(args, des_from_args(args)?, ecb, encrypt)?;
    let mut out = s.write(input)?;
    out.extend(s.finish()?);
    Ok(out)
}

fn make_des_enc(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    make_des(args, true)
}

fn make_des_dec(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    make_des(args, false)
}

fn make_des(args: &HashMap<String, String>, encrypt: bool) -> anyhow::Result<Box<dyn StreamingOp>> {
    match parse_des_mode(args)? {
        DesMode::Ecb => Ok(Box::new(BufBlockStream::new(
            args,
            des_from_args(args)?,
            true,
            encrypt,
        )?)),
        DesMode::Cbc => Ok(Box::new(BufBlockStream::new(
            args,
            des_from_args(args)?,
            false,
            encrypt,
        )?)),
        DesMode::Cfb => Ok(Box::new(CfbStream::new(
            args,
            des_from_args(args)?,
            encrypt,
        )?)),
        DesMode::Ofb => Ok(Box::new(OfbStream::new(args, des_from_args(args)?)?)),
        DesMode::Ctr => Ok(Box::new(CtrStream::new(args, des_from_args(args)?)?)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn sm4_ecb_known_vector() {
        // GB/T 32907-2016 Annex A: key=0123456789abcdeffedcba9876543210,
        // plaintext=0123456789abcdeffedcba9876543210 => ciphertext=681edf34d206965e86b3e94f536e4246
        // dpa ECB uses PKCS#7: 16 bytes of plaintext produce 32 bytes of
        // ciphertext (one extra padding block); the first block must match the vector.
        let a = args(&[
            ("key", "0x0123456789abcdeffedcba9876543210"),
            ("mode", "ecb"),
        ]);
        let plain = hex::decode("0123456789abcdeffedcba9876543210").unwrap();
        let enc = sm4_encrypt(&plain, &a).unwrap();
        assert_eq!(enc.len(), 32);
        assert_eq!(hex::encode(&enc[..16]), "681edf34d206965e86b3e94f536e4246");
        assert_eq!(sm4_decrypt(&enc, &a).unwrap(), plain);
    }

    #[test]
    fn sm4_cbc_roundtrip_and_defaults() {
        let a = args(&[("key", "0x0123456789abcdeffedcba9876543210")]);
        let b = args(&[
            ("key", "0x0123456789abcdeffedcba9876543210"),
            ("mode", "cbc"),
            ("iv", "0x00000000000000000000000000000000"),
        ]);
        let data = b"SM4 default-args payload data";
        assert_eq!(
            sm4_encrypt(data, &a).unwrap(),
            sm4_encrypt(data, &b).unwrap()
        );
        let enc = sm4_encrypt(data, &a).unwrap();
        assert_eq!(sm4_decrypt(&enc, &a).unwrap(), data);
    }

    #[test]
    fn sm4_ctr_roundtrip_and_stream_matches_memory() {
        let a = args(&[
            ("key", "0x0123456789abcdeffedcba9876543210"),
            ("mode", "ctr"),
            ("iv", "0xf0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
        ]);
        let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let enc = sm4_encrypt(&data, &a).unwrap();
        assert_eq!(sm4_decrypt(&enc, &a).unwrap(), data);
        let mut h = make_sm4_enc(&a).unwrap();
        let mut acc = Vec::new();
        for c in data.chunks(7) {
            acc.extend(h.write(c).unwrap());
        }
        acc.extend(h.finish().unwrap());
        assert_eq!(acc, enc);
        let mut hd = make_sm4_dec(&a).unwrap();
        let mut acc2 = Vec::new();
        for c in enc.chunks(9) {
            acc2.extend(hd.write(c).unwrap());
        }
        acc2.extend(hd.finish().unwrap());
        assert_eq!(acc2, data);
    }

    #[test]
    fn sm4_block_stream_matches_memory() {
        let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        for (mode, extra) in [
            ("ecb", vec![]),
            ("cbc", vec![("iv", "0xf0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")]),
        ] {
            let mut pairs = vec![
                ("key", "0x0123456789abcdeffedcba9876543210"),
                ("mode", mode),
            ];
            pairs.extend(extra.iter().copied());
            let a = args(&pairs);
            let run = sm4_encrypt(&data, &a).unwrap();
            let mut h = make_sm4_enc(&a).unwrap();
            let mut acc = Vec::new();
            for c in data.chunks(11) {
                acc.extend(h.write(c).unwrap());
            }
            acc.extend(h.finish().unwrap());
            assert_eq!(acc, run, "sm4 {} stream mismatch", mode);
            let mut hd = make_sm4_dec(&a).unwrap();
            let mut acc2 = Vec::new();
            for c in run.chunks(13) {
                acc2.extend(hd.write(c).unwrap());
            }
            acc2.extend(hd.finish().unwrap());
            assert_eq!(acc2, data, "sm4 {} decrypt mismatch", mode);
        }
    }

    #[test]
    fn sm4_rejects_bad_key_len_and_mode() {
        let a = args(&[("key", "0123456789abcdef0123456789abcdef"), ("mode", "ecb")]);
        assert!(sm4_encrypt(b"data", &a).is_err()); // key must be 16 bytes
        let b = args(&[
            ("key", "0x0123456789abcdeffedcba9876543210"),
            ("mode", "xts"),
        ]);
        assert!(sm4_encrypt(b"data", &b).is_err());
    }

    #[test]
    fn des_cbc_roundtrip_and_differs_from_ecb() {
        // A single CBC block under a non-zero IV differs from ECB; with
        // iv=0123456789abcdef the output must differ from the ECB result.
        let a = args(&[
            ("key", "0x133457799bbcdff1"),
            ("mode", "cbc"),
            ("iv", "0x0123456789abcdef"),
        ]);
        let plain = hex::decode("0123456789abcdef").unwrap();
        let enc = des_encrypt(&plain, &a).unwrap();
        assert_eq!(des_decrypt(&enc, &a).unwrap(), plain);
        let e_ecb = args(&[("key", "0x133457799bbcdff1"), ("mode", "ecb")]);
        assert_ne!(
            hex::encode(&enc[..8]),
            hex::encode(&des_encrypt(&plain, &e_ecb).unwrap()[..8])
        );
    }

    #[test]
    fn des_default_mode_cbc_zero_iv() {
        let a = args(&[("key", "0x133457799bbcdff1")]);
        let b = args(&[
            ("key", "0x133457799bbcdff1"),
            ("mode", "cbc"),
            ("iv", "0x0000000000000000"),
        ]);
        let data = b"DES defaults payload";
        assert_eq!(
            des_encrypt(data, &a).unwrap(),
            des_encrypt(data, &b).unwrap()
        );
        assert_eq!(
            des_decrypt(&des_encrypt(data, &a).unwrap(), &a).unwrap(),
            data
        );
    }

    #[test]
    fn des_ecb_known_vector_and_stream_matches_memory() {
        // FIPS 81 teaching vector (single ECB block): key=133457799bbcdff1,
        // PT=0123456789abcdef => CT=85e813540f0ab405
        let a = args(&[("key", "0x133457799bbcdff1"), ("mode", "ecb")]);
        let plain = hex::decode("0123456789abcdef").unwrap();
        let enc = des_encrypt(&plain, &a).unwrap();
        assert_eq!(hex::encode(&enc[..8]), "85e813540f0ab405");
        let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let run = des_encrypt(&data, &a).unwrap();
        assert_eq!(des_decrypt(&run, &a).unwrap(), data);
        let mut h = make_des_enc(&a).unwrap();
        let mut acc = Vec::new();
        for c in data.chunks(9) {
            acc.extend(h.write(c).unwrap());
        }
        acc.extend(h.finish().unwrap());
        assert_eq!(acc, run);
        let mut hd = make_des_dec(&a).unwrap();
        let mut acc2 = Vec::new();
        for c in run.chunks(5) {
            acc2.extend(hd.write(c).unwrap());
        }
        acc2.extend(hd.finish().unwrap());
        assert_eq!(acc2, data);
    }

    #[test]
    fn des_rejects_bad_key_len_and_mode() {
        let a = args(&[("key", "tooLongKeyString")]);
        assert!(des_encrypt(b"data", &a).is_err());
        let b = args(&[("key", "0x133457799bbcdff1"), ("mode", "xts")]);
        assert!(des_encrypt(b"data", &b).is_err());
    }

    #[test]
    fn sm4_cfb_known_vector() {
        // Standard CFB-128: OpenSSL 3.x `openssl enc -sm4-cfb` cross-check over
        // 8 blocks (review fix 3.1: multi-block output must match CFB-128).
        let a = args(&[
            ("key", "0x0123456789abcdeffedcba9876543210"),
            ("mode", "cfb"),
            ("iv", "0x000102030405060708090a0b0c0d0e0f"),
        ]);
        let plain = b"0123456789abcdef".repeat(8);
        let expect = hex::decode("36a9ae5209935e9a12b496e082cc9c0ca855e2ee337579deb1df61738b758ed2198e65264a414c96f60e7074b69669be121066334d592c091390baca897fffc2b69ced4b4502ed7ad4cdd71fca1049faa2d2fbbd8edf470cab1e59a3d5cee56202a4253701849395e8fa4794be0f6a437e10f1c6b36433f73ffb7aea93f46dad").unwrap();
        let enc = sm4_encrypt(&plain, &a).unwrap();
        assert_eq!(enc, expect);
        assert_eq!(sm4_decrypt(&enc, &a).unwrap(), plain);
        // Unaligned tail must match the block-aligned prefix byte-for-byte.
        assert_eq!(sm4_encrypt(&plain[..20], &a).unwrap(), expect[..20]);
        assert_eq!(sm4_decrypt(&expect[..20], &a).unwrap(), plain[..20]);
    }

    #[test]
    fn des_cfb_known_vector() {
        // Standard CFB-64: pycryptodome DES MODE_CFB segment_size=64 cross-check
        // over 16 blocks (review fix 3.1: multi-block output must match CFB-64).
        let a = args(&[
            ("key", "0x133457799bbcdff1"),
            ("mode", "cfb"),
            ("iv", "0x1234567890abcdef"),
        ]);
        let plain = b"abcdefgh".repeat(16);
        let expect = hex::decode("68fbdcf68e10dd66d22e52f10719d40f353787548e4410a53f625214148107434b1eeab755ab21ddd0c3fa44530a406eed2341ee1ec28f9503a9d7cd2a6084f36a32fd2ef4f1cd024c94771ca4235383604f6863c2c8d209d534f7c480102dedb42332076577216f949b1af0f2c02e012911c6a7dff98169360a27e7875a4351").unwrap();
        let enc = des_encrypt(&plain, &a).unwrap();
        assert_eq!(enc, expect);
        assert_eq!(des_decrypt(&enc, &a).unwrap(), plain);
        assert_eq!(des_encrypt(&plain[..13], &a).unwrap(), expect[..13]);
        assert_eq!(des_decrypt(&expect[..13], &a).unwrap(), plain[..13]);
    }

    #[test]
    fn sm4_cfb_ofb_roundtrip_and_stream_matches_memory() {
        for mode in ["cfb", "ofb"] {
            let a = args(&[
                ("key", "0x0123456789abcdeffedcba9876543210"),
                ("mode", mode),
                ("iv", "0xf0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
            ]);
            let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
            let enc = sm4_encrypt(&data, &a).unwrap();
            assert_eq!(
                sm4_decrypt(&enc, &a).unwrap(),
                data,
                "sm4 {} roundtrip",
                mode
            );
            // one-shot stream must match the in-memory run
            let mut h = make_sm4_enc(&a).unwrap();
            let mut acc = Vec::new();
            for c in data.chunks(3) {
                acc.extend(h.write(c).unwrap());
            }
            acc.extend(h.finish().unwrap());
            assert_eq!(acc, enc, "sm4 {} stream mismatch", mode);
            let mut hd = make_sm4_dec(&a).unwrap();
            let mut acc2 = Vec::new();
            for c in enc.chunks(7) {
                acc2.extend(hd.write(c).unwrap());
            }
            acc2.extend(hd.finish().unwrap());
            assert_eq!(acc2, data, "sm4 {} decrypt stream mismatch", mode);
        }
    }

    #[test]
    fn sm4_nopadding_block_modes() {
        // padding=none: aligned input is encrypted/decrypted without padding.
        for mode in ["ecb", "cbc"] {
            let a = args(&[
                ("key", "0x0123456789abcdeffedcba9876543210"),
                ("mode", mode),
                ("padding", "none"),
            ]);
            let plain = hex::decode("0123456789abcdeffedcba9876543210").unwrap();
            let enc = sm4_encrypt(&plain, &a).unwrap();
            assert_eq!(
                enc.len(),
                16,
                "sm4 {} no-padding must not add a block",
                mode
            );
            assert_eq!(sm4_decrypt(&enc, &a).unwrap(), plain);
            // unaligned plaintext must be rejected
            assert!(sm4_encrypt(&plain[..15], &a).is_err());
        }
    }

    #[test]
    fn des_cfb_ofb_ctr_roundtrip_and_stream_matches_memory() {
        for mode in ["cfb", "ofb", "ctr"] {
            let a = args(&[
                ("key", "0x133457799bbcdff1"),
                ("mode", mode),
                ("iv", "0x0123456789abcdef"),
            ]);
            let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
            let enc = des_encrypt(&data, &a).unwrap();
            assert_eq!(
                des_decrypt(&enc, &a).unwrap(),
                data,
                "des {} roundtrip",
                mode
            );
            let mut h = make_des_enc(&a).unwrap();
            let mut acc = Vec::new();
            for c in data.chunks(11) {
                acc.extend(h.write(c).unwrap());
            }
            acc.extend(h.finish().unwrap());
            assert_eq!(acc, enc, "des {} stream mismatch", mode);
            let mut hd = make_des_dec(&a).unwrap();
            let mut acc2 = Vec::new();
            for c in enc.chunks(5) {
                acc2.extend(hd.write(c).unwrap());
            }
            acc2.extend(hd.finish().unwrap());
            assert_eq!(acc2, data, "des {} decrypt stream mismatch", mode);
        }
    }

    #[test]
    fn des_nopadding_block_modes() {
        for mode in ["ecb", "cbc"] {
            let a = args(&[
                ("key", "0x133457799bbcdff1"),
                ("mode", mode),
                ("padding", "none"),
            ]);
            let plain = hex::decode("0123456789abcdef").unwrap();
            let enc = des_encrypt(&plain, &a).unwrap();
            assert_eq!(enc.len(), 8, "des {} no-padding must not add a block", mode);
            assert_eq!(des_decrypt(&enc, &a).unwrap(), plain);
            assert!(des_encrypt(&plain[..7], &a).is_err());
        }
    }
}
