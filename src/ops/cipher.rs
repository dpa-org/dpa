//! Symmetric block ciphers: SM4 / DES.
//!
//! Same "direction split, mode parameterized" convention as AES (see crypto.rs):
//! one encrypt op + one decrypt op; the mode is an optional parameter with a
//! default (cbc); the iv is optional and defaults to the all-zero block.
//! Block modes (ecb/cbc) use PKCS#7 padding; ctr needs no padding.

use std::collections::HashMap;

use super::crypto::aes::{gcm_encrypt_iv, gcm_split_decrypt_input, opt_aad};
use super::crypto::{implicit_zero_iv_warning, opt_arg, parse_key, require_key};
use super::gcm::{self, GcmBlock};
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
                ArgSpec {
                    name: "aad",
                    required: false,
                    description: "op.sm4.encrypt.arg.aad",
                    format: crate::ops::ArgFormat::HexOrUtf8,
                },
                ArgSpec {
                    name: "zero-iv-ok",
                    required: false,
                    description: "op.sm4.encrypt.arg.zero_iv_ok",
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
                ArgSpec {
                    name: "aad",
                    required: false,
                    description: "op.sm4.decrypt.arg.aad",
                    format: crate::ops::ArgFormat::HexOrUtf8,
                },
                ArgSpec {
                    name: "tag",
                    required: false,
                    description: "op.sm4.decrypt.arg.tag",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "zero-iv-ok",
                    required: false,
                    description: "op.sm4.decrypt.arg.zero_iv_ok",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            sm4_decrypt,
            make_sm4_dec
        ),
        op!(
            "dpa:sm4:mac",
            "crypto",
            "op.sm4.mac.desc",
            &[
                ArgSpec {
                    name: "key",
                    required: true,
                    description: "op.sm4.mac.arg.key",
                    format: crate::ops::ArgFormat::HexOrUtf8,
                },
                ArgSpec {
                    name: "iv",
                    required: false,
                    description: "op.sm4.mac.arg.iv",
                    format: crate::ops::ArgFormat::HexOrUtf8,
                },
                ArgSpec {
                    name: "padding",
                    required: false,
                    description: "op.sm4.mac.arg.padding",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            sm4_mac
        ),
        op!(
            "dpa:sm4:cmac",
            "crypto",
            "op.sm4.cmac.desc",
            &[ArgSpec {
                name: "key",
                required: true,
                description: "op.sm4.cmac.arg.key",
                format: crate::ops::ArgFormat::HexOrUtf8,
            },],
            sm4_cmac
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
    if data.is_empty() || !data.len().is_multiple_of(block) {
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

impl GcmBlock for Sm4 {
    fn encrypt_block(&self, blk: &mut [u8; 16]) {
        let mut b = Sm4Block::<Sm4>::clone_from_slice(blk);
        Sm4BlockEncrypt::encrypt_block(self, &mut b);
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
// a feedback shift; the previous byte-wise sliding window was
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
    Gcm,
}

impl Sm4Mode {
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

fn parse_sm4_mode(args: &HashMap<String, String>) -> anyhow::Result<Sm4Mode> {
    match opt_arg(args, "mode", "cbc") {
        "ecb" => Ok(Sm4Mode::Ecb),
        "cbc" => Ok(Sm4Mode::Cbc),
        "cfb" => Ok(Sm4Mode::Cfb),
        "ofb" => Ok(Sm4Mode::Ofb),
        "ctr" => Ok(Sm4Mode::Ctr),
        "gcm" => Ok(Sm4Mode::Gcm),
        other => anyhow::bail!(
            "{}",
            i18n::tf("err.unknown_mode", &[other, "ecb/cbc/cfb/ofb/ctr/gcm"])
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
    let mode = parse_sm4_mode(args)?;
    if let Some(w) = implicit_zero_iv_warning(args, mode.name(), encrypt) {
        eprintln!("{}", w);
    }
    match mode {
        Sm4Mode::Ecb => sm4_block_crypt(input, args, true, encrypt),
        Sm4Mode::Cbc => sm4_block_crypt(input, args, false, encrypt),
        Sm4Mode::Cfb => cfb_crypt(input, args, sm4_from_args(args)?, encrypt),
        Sm4Mode::Ofb => ofb_crypt(input, args, sm4_from_args(args)?),
        Sm4Mode::Ctr => ctr_crypt(input, args, sm4_from_args(args)?),
        Sm4Mode::Gcm => sm4_gcm_run(input, args, encrypt),
    }
}

/// `dpa:sm4:mac` - SM4-CBC-MAC (GM/T 0002-2012) over the input message.
/// Accepts a 16-byte key and an optional 16-byte iv (all-zero default) and
/// returns the 16-byte MAC. With `padding=pkcs7` (default) the message is
/// PKCS#7-padded before MACing; `padding=none` requires a block-aligned input.
fn sm4_mac(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let key = require_key(args)?;
    if key.len() != 16 {
        anyhow::bail!(
            "{}",
            i18n::tf("err.sm4_key_len", &[key.len().to_string().as_str()])
        );
    }
    let cipher = Sm4::new_from_slice(&key)
        .map_err(|_| anyhow::anyhow!("{}", i18n::tf("err.sm4_init", &["invalid key material"])))?;
    let padding = parse_padding(args)?;
    let iv = opt_iv(args, Sm4::BLOCK)?;

    let data = match padding {
        Padding::Pkcs7 => pkcs7_pad(input, Sm4::BLOCK),
        Padding::None => {
            if !input.len().is_multiple_of(Sm4::BLOCK) {
                anyhow::bail!(
                    "{}",
                    i18n::tf("err.sm4_mac_align", &[Sm4::BLOCK.to_string().as_str()])
                );
            }
            input.to_vec()
        }
    };

    // CBC chain over the full padded message; the final block is the MAC.
    let mut acc = iv;
    for chunk in data.chunks(Sm4::BLOCK) {
        for (a, b) in acc.iter_mut().zip(chunk) {
            *a ^= b;
        }
        cipher.encrypt(&mut acc);
    }
    Ok(acc)
}

/// `dpa:sm4:cmac` - SM4-CMAC (GM/T 0005-2021; the RFC 4493 construction with
/// SM4 as the underlying 128-bit block cipher). Accepts a 16-byte key and
/// returns the 16-byte MAC. Unlike `sm4:mac`, CMAC fixes the length-extension
/// weakness of CBC-MAC: the final block is masked with K1/K2, so there is no
/// padding ambiguity and no length-extension attack.
fn sm4_cmac(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let key = require_key(args)?;
    if key.len() != 16 {
        anyhow::bail!(
            "{}",
            i18n::tf("err.sm4_key_len", &[key.len().to_string().as_str()])
        );
    }
    let cipher = Sm4::new_from_slice(&key)
        .map_err(|_| anyhow::anyhow!("{}", i18n::tf("err.sm4_init", &["invalid key material"])))?;
    let mut enc = |b: &mut [u8; 16]| {
        cipher.encrypt(Sm4Block::<Sm4>::from_mut_slice(b));
    };
    Ok(cmac_128(&mut enc, input).to_vec())
}

/// CMAC over a 128-bit block cipher, parameterized by a block-encryption
/// closure so the same logic can be validated against the RFC 4493 AES-CMAC
/// test vectors with any 128-bit cipher.
fn cmac_128(enc: &mut impl FnMut(&mut [u8; 16]), input: &[u8]) -> [u8; 16] {
    let block = 16usize;
    // Subkey generation: L = E(K, 0^128), K1 = dbl(L), K2 = dbl(K1).
    let mut l = [0u8; 16];
    enc(&mut l);
    let k1 = cmac_dbl(&l);
    let k2 = cmac_dbl(&k1);

    let mut x = [0u8; 16];
    let n_blocks = input.len().div_ceil(block);
    if n_blocks == 0 {
        // Empty message (RFC 4493): flagged as not-complete-block, padded
        // with 10* and masked with K2.
        let mut last = [0u8; 16];
        last[0] = 0x80;
        for i in 0..block {
            last[i] ^= k2[i];
        }
        for i in 0..block {
            x[i] ^= last[i];
        }
        enc(&mut x);
        return x;
    }

    // All complete blocks except the last pass through the CBC chain.
    let full = input.len().is_multiple_of(block);
    let last_start = input.len() - (if full { block } else { input.len() % block });
    for chunk in input[..last_start].chunks(block) {
        for i in 0..block {
            x[i] ^= chunk[i];
        }
        enc(&mut x);
    }

    // Final block: complete -> mask with K1; incomplete -> pad 10* and mask K2.
    let mut last = [0u8; 16];
    let rem = input.len() % block;
    if full {
        for i in 0..block {
            last[i] = input[last_start + i] ^ k1[i];
        }
    } else {
        last[..rem].copy_from_slice(&input[last_start..last_start + rem]);
        last[rem] = 0x80;
        for i in 0..block {
            last[i] ^= k2[i];
        }
    }
    for i in 0..block {
        x[i] ^= last[i];
    }
    enc(&mut x);
    x
}

/// Doubling in GF(2^128) with the NIST/CMAC polynomial Rb = 0x87 (x^128 + x^7
/// + x^2 + x + 1).
fn cmac_dbl(x: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let msb = x[0] >> 7;
    for i in 0..15 {
        out[i] = (x[i] << 1) | (x[i + 1] >> 7);
    }
    out[15] = x[15] << 1;
    if msb == 1 {
        out[15] ^= 0x87;
    }
    out
}

// ---------------------------------------------------------------------------
// SM4-GCM (NIST SP 800-38D): authenticated encryption with associated data.
// The GHASH/GCTR/J0 machinery is shared with AES-GCM via `super::gcm`
// (generic over [`GcmBlock`]); SM4 only provides the block primitive below.
// Memory-only for now - the streaming factory buffers the whole input and
// runs the one-shot path.
// ---------------------------------------------------------------------------

fn sm4_gcm_run(
    input: &[u8],
    args: &HashMap<String, String>,
    encrypt: bool,
) -> anyhow::Result<Vec<u8>> {
    let cipher = sm4_from_args(args)?;
    let aad = opt_aad(args)?;
    if encrypt {
        let (iv, prefix) = gcm_encrypt_iv(args)?;
        let (mut ct, tag) = gcm::encrypt(&cipher, &iv, &aad, input);
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
        gcm::decrypt(&cipher, &iv, &aad, &ct, &tag)
    }
}

/// GCM is memory-only (no cross-chunk state); buffer the whole input and run
/// the one-shot SM4-GCM path at finish so the CLI can use GCM too.
struct Sm4GcmBufferStream {
    buf: Vec<u8>,
    args: HashMap<String, String>,
    encrypt: bool,
}

impl StreamingOp for Sm4GcmBufferStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.buf.extend_from_slice(chunk);
        Ok(Vec::new())
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        sm4_gcm_run(&self.buf, &self.args, self.encrypt)
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
    let mode = parse_sm4_mode(args)?;
    if let Some(w) = implicit_zero_iv_warning(args, mode.name(), encrypt) {
        eprintln!("{}", w);
    }
    match mode {
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
        Sm4Mode::Gcm => Ok(Box::new(Sm4GcmBufferStream {
            buf: Vec::new(),
            args: args.clone(),
            encrypt,
        })),
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

impl DesMode {
    fn name(&self) -> &'static str {
        match self {
            Self::Ecb => "ecb",
            Self::Cbc => "cbc",
            Self::Cfb => "cfb",
            Self::Ofb => "ofb",
            Self::Ctr => "ctr",
        }
    }
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
    let mode = parse_des_mode(args)?;
    if let Some(w) = implicit_zero_iv_warning(args, mode.name(), encrypt) {
        eprintln!("{}", w);
    }
    match mode {
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
    let mode = parse_des_mode(args)?;
    if let Some(w) = implicit_zero_iv_warning(args, mode.name(), encrypt) {
        eprintln!("{}", w);
    }
    match mode {
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
    fn sm4_mac_known_vectors() {
        // GM/T 0002-2012 SM4 CBC-MAC. References generated with an
        // independent GMSSL-based implementation (16-byte MAC output).
        let key = "0x0123456789abcdeffedcba9876543210";
        let a = args(&[("key", key)]);
        assert_eq!(
            hex::encode(sm4_mac(b"hello sm4 cbc-mac", &a).unwrap()),
            "99b803c3303d2a8b3e5ae1e4c4cccde8"
        );
        assert_eq!(
            hex::encode(sm4_mac(b"A".repeat(16).as_slice(), &a).unwrap()),
            "09479d6d57ba6cf2c47f3cfa19a89911"
        );
        let iv = args(&[("key", key), ("iv", "0x000102030405060708090a0b0c0d0e0f")]);
        assert_eq!(
            hex::encode(sm4_mac(b"hello sm4 cbc-mac", &iv).unwrap()),
            "84f1bf349075d3975de3ec92ebc546f4"
        );
    }

    #[test]
    fn cmac_128_matches_rfc4493_aes_vectors() {
        // Validate the generic CMAC construction against the published RFC
        // 4493 §4 AES-CMAC test vectors (AES-128 as the block cipher).
        use aes::Aes128;
        use aes::cipher::generic_array::GenericArray;
        use aes::cipher::{BlockEncrypt as _, KeyInit as _};

        let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
        let aes = Aes128::new_from_slice(&key).unwrap();
        let mut enc = |b: &mut [u8; 16]| {
            aes.encrypt_block(GenericArray::from_mut_slice(b));
        };
        let vectors: &[(&str, &str)] = &[
            ("", "bb1d6929e95937287fa37d129b756746"),
            (
                "6bc1bee22e409f96e93d7e117393172a",
                "070a16b46b4d4144f79bdd9dd04a287c",
            ),
            (
                "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411",
                "dfa66747de9ae63030ca32611497c827",
            ),
            (
                "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
                "51f0bebf7e3b9d92fc49741779363cfe",
            ),
        ];
        for (i, (msg, tag)) in vectors.iter().enumerate() {
            let mac = cmac_128(&mut enc, &hex::decode(msg).unwrap());
            assert_eq!(hex::encode(mac), *tag, "RFC 4493 vector {}", i);
        }
    }

    #[test]
    fn sm4_cmac_behaviour() {
        // SM4-CMAC runs through the same RFC 4493 construction validated
        // above, with SM4 as the underlying block cipher: deterministic
        // 16-byte tag, distinct for distinct messages, wrong key rejected.
        let key = "0x0123456789abcdeffedcba9876543210";
        let a = args(&[("key", key)]);
        let m1 = sm4_cmac(b"hello sm4 cmac", &a).unwrap();
        let m1b = sm4_cmac(b"hello sm4 cmac", &a).unwrap();
        let m2 = sm4_cmac(b"hello sm4 cmac!", &a).unwrap();
        assert_eq!(m1, m1b, "CMAC must be deterministic");
        assert_ne!(m1, m2, "CMAC must change with the message");
        assert_eq!(m1.len(), 16);
        // Empty message produces a full padded block tag.
        assert_eq!(sm4_cmac(b"", &a).unwrap().len(), 16);
        // Key length is enforced like sm4:mac.
        let bad = args(&[("key", "0x00112233")]);
        assert!(sm4_cmac(b"x", &bad).is_err());
        // CMAC differs from the pkcs7 CBC-MAC of the same message (the whole
        // point of the #14 fix: no length-extension ambiguity).
        let mac = sm4_mac(b"hello sm4 cmac", &a).unwrap();
        assert_ne!(m1, mac);
    }

    #[test]
    fn sm4_mac_no_padding_single_block() {
        // padding=none over an exactly 16-byte message: MAC is the encryption
        // of (iv XOR block). Reference from an independent GMSSL implementation.
        let a = args(&[
            ("key", "0x0123456789abcdeffedcba9876543210"),
            ("padding", "none"),
        ]);
        assert_eq!(
            hex::encode(sm4_mac(b"A".repeat(16).as_slice(), &a).unwrap()),
            "99ce75c0ca2949d3eb87bd2d831f3510"
        );
        // Non-block-aligned input with padding=none must be rejected.
        let b = args(&[
            ("key", "0x0123456789abcdeffedcba9876543210"),
            ("padding", "none"),
        ]);
        assert!(sm4_mac(b"short", &b).is_err());
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
        // 8 blocks; multi-block output must match CFB-128.
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
        // over 16 blocks; multi-block output must match CFB-64.
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

    fn sm4_gcm_args<'a>(
        iv: &'a str,
        aad: &'a str,
        tag: Option<&'a str>,
    ) -> Vec<(&'a str, &'a str)> {
        let mut v = vec![
            ("key", "0x0123456789abcdeffedcba9876543210"),
            ("mode", "gcm"),
            ("iv", iv),
            ("aad", aad),
        ];
        if let Some(t) = tag {
            v.push(("tag", t));
        }
        v
    }

    #[test]
    fn sm4_gcm_known_vectors() {
        // Independent reference implementation (Python gmssl SM4 single block + NIST SP 800-38D GHASH/GCTR).
        // Precomputed fixed vectors: key=0123456789abcdeffedcba9876543210, iv=000102..0b, aad="aad-data".
        let iv = "0x000102030405060708090a0b";
        let aad = "aad-data"; // UTF-8 bytes, matching the reference vector b"aad-data"
        let pt64 = "58".repeat(64);
        let ct64 = "0d7940c9e9e9f1473cd8dbf383043e0dd0a171f51809e6e71eecf177c8b54b23115d95027c51654d5fe907684cc9d3c842d77cfb632754239c12cdd74b23a7f5";
        let pt48 = (0..48u8).map(|i| format!("{:02x}", i)).collect::<String>();
        let vectors = [
            ("", "", "0b15cecd575c44d1f06624104552d1af"),
            (
                "68656c6c6f20736d342067636d21",
                "3d4474fdde91da7250a0e4c8b67d",
                "9a8b4be80f24db2d303958b1ad265af1",
            ),
            (pt64.as_str(), ct64, "a4d4eb5beb516187510ace38df7de6d2"),
            (
                pt48.as_str(),
                "55201a92b5b4af186c8989a0d751685a98e83bbe5444a8a85eadb3348cf00d646924ef79002c1b322f98751b38bca5bf",
                "b8bf8664b72ec884a690ca09ffac3abb",
            ),
        ];
        for (i, (pt_hex, ct_hex, tag_hex)) in vectors.iter().enumerate() {
            let pt = hex::decode(pt_hex).unwrap();
            let a = args(&sm4_gcm_args(iv, aad, None));
            let out = sm4_encrypt(&pt, &a).unwrap();
            let (ct, tag) = out.split_at(out.len() - 16);
            assert_eq!(hex::encode(ct), *ct_hex, "sm4-gcm vector {} ct", i);
            assert_eq!(hex::encode(tag), *tag_hex, "sm4-gcm vector {} tag", i);
            // The correct tag and aad must decrypt back to the plaintext.
            let d = args(&sm4_gcm_args(iv, aad, Some(&format!("0x{tag_hex}"))));
            assert_eq!(
                sm4_decrypt(&out[..out.len() - 16], &d).unwrap(),
                pt,
                "sm4-gcm vector {} decrypt",
                i
            );
        }
    }

    #[test]
    fn sm4_gcm_roundtrip() {
        let iv = "0x000102030405060708090a0b";
        let aad = "aad-data";
        let data: Vec<u8> = (0..=255u8).cycle().take(1024).collect();
        let enc = args(&sm4_gcm_args(iv, aad, None));
        let out = sm4_encrypt(&data, &enc).unwrap();
        assert_eq!(out.len(), data.len() + 16);
        let dec = args(&sm4_gcm_args(
            iv,
            aad,
            Some(&format!("0x{}", hex::encode(&out[data.len()..]))),
        ));
        assert_eq!(sm4_decrypt(&out[..data.len()], &dec).unwrap(), data);
        // Empty plaintext with empty aad must also round-trip.
        let enc0 = args(&sm4_gcm_args(iv, "", None));
        let out0 = sm4_encrypt(b"", &enc0).unwrap();
        assert_eq!(out0.len(), 16);
        let dec0 = args(&sm4_gcm_args(
            iv,
            "",
            Some(&format!("0x{}", hex::encode(&out0))),
        ));
        assert_eq!(sm4_decrypt(&out0[..0], &dec0).unwrap(), b"");
    }

    #[test]
    fn sm4_gcm_tag_failure() {
        let iv = "0x000102030405060708090a0b";
        let aad = "aad-data";
        let enc = args(&sm4_gcm_args(iv, aad, None));
        let out = sm4_encrypt(b"attack at dawn", &enc).unwrap();
        let good = hex::encode(&out[out.len() - 16..]);
        // Flipping any byte of the tag must fail authentication.
        let bad = format!(
            "0x{:02x}{}",
            u8::from_str_radix(&good[..2], 16).unwrap() ^ 1,
            &good[2..]
        );
        let dec = args(&sm4_gcm_args(iv, aad, Some(&bad)));
        let err = sm4_decrypt(&out[..out.len() - 16], &dec).unwrap_err();
        assert!(
            err.to_string().contains("authentication"),
            "unexpected err: {err}"
        );
        // Tampering with the ciphertext must also fail authentication.
        let mut tampered = out.clone();
        tampered[0] ^= 1;
        let dec2 = args(&sm4_gcm_args(iv, aad, Some(&format!("0x{good}"))));
        assert!(sm4_decrypt(&tampered[..tampered.len() - 16], &dec2).is_err());
    }

    #[test]
    fn sm4_gcm_aad_mismatch() {
        let iv = "0x000102030405060708090a0b";
        let enc = args(&sm4_gcm_args(iv, "aad-data", None));
        let out = sm4_encrypt(b"payload-payload-payload", &enc).unwrap();
        let tag = hex::encode(&out[out.len() - 16..]);
        // Decrypting with a different aad must fail authentication.
        let wrong = args(&sm4_gcm_args(iv, "other-aad", Some(&format!("0x{tag}"))));
        assert!(sm4_decrypt(&out[..out.len() - 16], &wrong).is_err());
        // The correct aad must succeed.
        let right = args(&sm4_gcm_args(iv, "aad-data", Some(&format!("0x{tag}"))));
        assert_eq!(
            sm4_decrypt(&out[..out.len() - 16], &right).unwrap(),
            b"payload-payload-payload"
        );
    }

    #[test]
    fn sm4_gcm_iv_length() {
        // Non-12-byte IVs are accepted too (J0 derived via GHASH) and round-trip consistently.
        for ivlen in [8usize, 13, 16, 20] {
            let iv_hex = format!(
                "0x{}",
                (0..ivlen as u8)
                    .map(|i| format!("{:02x}", i))
                    .collect::<String>()
            );
            let enc = args(&sm4_gcm_args(&iv_hex, "", None));
            let out = sm4_encrypt(b"abc", &enc).unwrap();
            let tag = hex::encode(&out[out.len() - 16..]);
            let dec = args(&sm4_gcm_args(&iv_hex, "", Some(&format!("0x{tag}"))));
            assert_eq!(
                sm4_decrypt(&out[..out.len() - 16], &dec).unwrap(),
                b"abc",
                "ivlen={ivlen}"
            );
        }
        // With no iv argument: a random 12-byte IV is prepended as iv||ct||tag and decrypt splits it automatically.
        let no_iv = args(&[
            ("key", "0x0123456789abcdeffedcba9876543210"),
            ("mode", "gcm"),
        ]);
        let out = sm4_encrypt(b"abc", &no_iv).unwrap();
        assert_eq!(out.len(), 12 + 3 + 16);
        // Two consecutive encryptions must not reuse the same IV (random prefix).
        let out2 = sm4_encrypt(b"abc", &no_iv).unwrap();
        assert_ne!(&out[..12], &out2[..12]);
        // Decrypt auto-splits iv||ct||tag, so no tag argument is needed.
        assert_eq!(sm4_decrypt(&out, &no_iv).unwrap(), b"abc");
        // zero-iv-ok escape hatch: 12-byte zero IV, ct||tag layout.
        let zo = args(&[
            ("key", "0x0123456789abcdeffedcba9876543210"),
            ("mode", "gcm"),
            ("zero-iv-ok", "true"),
        ]);
        let outz = sm4_encrypt(b"abc", &zo).unwrap();
        assert_eq!(outz.len(), 3 + 16);
        let zd = args(&[
            ("key", "0x0123456789abcdeffedcba9876543210"),
            ("mode", "gcm"),
            ("zero-iv-ok", "true"),
        ]);
        assert_eq!(sm4_decrypt(&outz, &zd).unwrap(), b"abc");
        // An empty iv must be rejected.
        let empty_iv = args(&sm4_gcm_args("", "", None));
        assert!(sm4_encrypt(b"abc", &empty_iv).is_err());
    }

    #[test]
    fn sm4_gcm_stream_matches_memory() {
        let a = args(&sm4_gcm_args(
            "0x000102030405060708090a0b",
            "aad-data",
            None,
        ));
        let data: Vec<u8> = (0..=255u8).cycle().take(257).collect();
        let enc = sm4_encrypt(&data, &a).unwrap();
        let mut h = make_sm4_enc(&a).unwrap();
        let mut acc = Vec::new();
        for c in data.chunks(3) {
            acc.extend(h.write(c).unwrap());
        }
        acc.extend(h.finish().unwrap());
        assert_eq!(acc, enc, "sm4-gcm stream mismatch");
        let mut da = a.clone();
        da.insert(
            "tag".to_string(),
            format!("0x{}", hex::encode(&enc[data.len()..])),
        );
        let mut hd = make_sm4_dec(&da).unwrap();
        let mut acc2 = Vec::new();
        for c in enc[..data.len()].chunks(7) {
            acc2.extend(hd.write(c).unwrap());
        }
        acc2.extend(hd.finish().unwrap());
        assert_eq!(acc2, data, "sm4-gcm decrypt stream mismatch");
    }
}
