//! classic ops (split from mod.rs).

use super::super::cipher::{
    BlockCipherOps, BufBlockStream, CfbStream, CtrStream, OfbStream, cfb_crypt, ctr_crypt,
    ofb_crypt,
};
use super::super::{ArgSpec, Op, StreamingOp};
use super::*;
use crate::i18n;
use ::aes::cipher::KeyInit;
use blowfish::Blowfish;
use blowfish::cipher::{BlockDecrypt as BfBlockDecrypt, BlockEncrypt as BfBlockEncrypt};
use byteorder::BE;
use des::TdesEde3;
use des::cipher::{BlockDecrypt as DesBlockDecrypt, BlockEncrypt as DesBlockEncrypt};
use std::collections::HashMap;
pub fn ops() -> Vec<Op> {
    vec![
        stream_op!(
            "dpa:rc4",
            "crypto",
            "op.rc4.desc",
            &[ArgSpec {
                name: "key",
                required: true,
                description: "op.rc4.arg.key",
                format: crate::ops::ArgFormat::HexOrUtf8,
            },],
            rc4,
            make_rc4
        ),
        op!(
            "dpa:rc4:decrypt",
            "crypto",
            "op.rc4.decrypt.desc",
            &[ArgSpec {
                name: "key",
                required: true,
                description: "op.rc4.arg.key",
                format: crate::ops::ArgFormat::HexOrUtf8,
            },],
            rc4_decrypt
        ),
        stream_op!(
            "dpa:des3:encrypt",
            "crypto",
            "op.des3.encrypt.desc",
            &[
                ArgSpec {
                    name: "key",
                    required: true,
                    description: "op.des3.encrypt.arg.key",
                    format: crate::ops::ArgFormat::HexOrUtf8,
                },
                ArgSpec {
                    name: "mode",
                    required: false,
                    description: "op.des3.encrypt.arg.mode",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "iv",
                    required: false,
                    description: "op.des3.encrypt.arg.iv",
                    format: crate::ops::ArgFormat::HexOrUtf8,
                },
                ArgSpec {
                    name: "padding",
                    required: false,
                    description: "op.des3.encrypt.arg.padding",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            des3_encrypt,
            make_des3_enc
        ),
        stream_op!(
            "dpa:des3:decrypt",
            "crypto",
            "op.des3.decrypt.desc",
            &[
                ArgSpec {
                    name: "key",
                    required: true,
                    description: "op.des3.decrypt.arg.key",
                    format: crate::ops::ArgFormat::HexOrUtf8,
                },
                ArgSpec {
                    name: "mode",
                    required: false,
                    description: "op.des3.decrypt.arg.mode",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "iv",
                    required: false,
                    description: "op.des3.decrypt.arg.iv",
                    format: crate::ops::ArgFormat::HexOrUtf8,
                },
                ArgSpec {
                    name: "padding",
                    required: false,
                    description: "op.des3.decrypt.arg.padding",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            des3_decrypt,
            make_des3_dec
        ),
        stream_op!(
            "dpa:blowfish:encrypt",
            "crypto",
            "op.blowfish.encrypt.desc",
            &[
                ArgSpec {
                    name: "key",
                    required: true,
                    description: "op.blowfish.encrypt.arg.key",
                    format: crate::ops::ArgFormat::HexOrUtf8,
                },
                ArgSpec {
                    name: "mode",
                    required: false,
                    description: "op.blowfish.encrypt.arg.mode",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "iv",
                    required: false,
                    description: "op.blowfish.encrypt.arg.iv",
                    format: crate::ops::ArgFormat::HexOrUtf8,
                },
                ArgSpec {
                    name: "padding",
                    required: false,
                    description: "op.blowfish.encrypt.arg.padding",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            blowfish_encrypt,
            make_blowfish_enc
        ),
        stream_op!(
            "dpa:blowfish:decrypt",
            "crypto",
            "op.blowfish.decrypt.desc",
            &[
                ArgSpec {
                    name: "key",
                    required: true,
                    description: "op.blowfish.decrypt.arg.key",
                    format: crate::ops::ArgFormat::HexOrUtf8,
                },
                ArgSpec {
                    name: "mode",
                    required: false,
                    description: "op.blowfish.decrypt.arg.mode",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "iv",
                    required: false,
                    description: "op.blowfish.decrypt.arg.iv",
                    format: crate::ops::ArgFormat::HexOrUtf8,
                },
                ArgSpec {
                    name: "padding",
                    required: false,
                    description: "op.blowfish.decrypt.arg.padding",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            blowfish_decrypt,
            make_blowfish_dec
        ),
        op!(
            "dpa:tea:encode",
            "crypto",
            "op.tea.encode.desc",
            &[
                ArgSpec {
                    name: "key",
                    required: true,
                    description: "op.tea.encode.arg.key",
                    format: crate::ops::ArgFormat::HexOrUtf8,
                },
                ArgSpec {
                    name: "padding",
                    required: false,
                    description: "op.tea.arg.padding",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            tea_encode
        ),
        op!(
            "dpa:tea:decode",
            "crypto",
            "op.tea.decode.desc",
            &[
                ArgSpec {
                    name: "key",
                    required: true,
                    description: "op.tea.decode.arg.key",
                    format: crate::ops::ArgFormat::HexOrUtf8,
                },
                ArgSpec {
                    name: "padding",
                    required: false,
                    description: "op.tea.arg.padding",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            tea_decode
        ),
        op!(
            "dpa:tea:encrypt",
            "crypto",
            "op.tea.encrypt.desc",
            &[
                ArgSpec {
                    name: "key",
                    required: true,
                    description: "op.tea.encrypt.arg.key",
                    format: crate::ops::ArgFormat::HexOrUtf8,
                },
                ArgSpec {
                    name: "padding",
                    required: false,
                    description: "op.tea.arg.padding",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            tea_encode
        ),
        op!(
            "dpa:tea:decrypt",
            "crypto",
            "op.tea.decrypt.desc",
            &[
                ArgSpec {
                    name: "key",
                    required: true,
                    description: "op.tea.decrypt.arg.key",
                    format: crate::ops::ArgFormat::HexOrUtf8,
                },
                ArgSpec {
                    name: "padding",
                    required: false,
                    description: "op.tea.arg.padding",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            tea_decode
        ),
        op!(
            "dpa:xtea:encode",
            "crypto",
            "op.xtea.encode.desc",
            &[
                ArgSpec {
                    name: "key",
                    required: true,
                    description: "op.xtea.encode.arg.key",
                    format: crate::ops::ArgFormat::HexOrUtf8,
                },
                ArgSpec {
                    name: "padding",
                    required: false,
                    description: "op.tea.arg.padding",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            xtea_encode
        ),
        op!(
            "dpa:xtea:decode",
            "crypto",
            "op.xtea.decode.desc",
            &[
                ArgSpec {
                    name: "key",
                    required: true,
                    description: "op.xtea.decode.arg.key",
                    format: crate::ops::ArgFormat::HexOrUtf8,
                },
                ArgSpec {
                    name: "padding",
                    required: false,
                    description: "op.tea.arg.padding",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            xtea_decode
        ),
        op!(
            "dpa:xtea:encrypt",
            "crypto",
            "op.xtea.encrypt.desc",
            &[
                ArgSpec {
                    name: "key",
                    required: true,
                    description: "op.xtea.encrypt.arg.key",
                    format: crate::ops::ArgFormat::HexOrUtf8,
                },
                ArgSpec {
                    name: "padding",
                    required: false,
                    description: "op.tea.arg.padding",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            xtea_encode
        ),
        op!(
            "dpa:xtea:decrypt",
            "crypto",
            "op.xtea.decrypt.desc",
            &[
                ArgSpec {
                    name: "key",
                    required: true,
                    description: "op.xtea.decrypt.arg.key",
                    format: crate::ops::ArgFormat::HexOrUtf8,
                },
                ArgSpec {
                    name: "padding",
                    required: false,
                    description: "op.tea.arg.padding",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            xtea_decode
        ),
        op!(
            "dpa:xxtea:encode",
            "crypto",
            "op.xxtea.encode.desc",
            &[
                ArgSpec {
                    name: "key",
                    required: true,
                    description: "op.xxtea.encode.arg.key",
                    format: crate::ops::ArgFormat::HexOrUtf8,
                },
                ArgSpec {
                    name: "padding",
                    required: false,
                    description: "op.tea.arg.padding",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            xxtea_encode
        ),
        op!(
            "dpa:xxtea:decode",
            "crypto",
            "op.xxtea.decode.desc",
            &[
                ArgSpec {
                    name: "key",
                    required: true,
                    description: "op.xxtea.decode.arg.key",
                    format: crate::ops::ArgFormat::HexOrUtf8,
                },
                ArgSpec {
                    name: "padding",
                    required: false,
                    description: "op.tea.arg.padding",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            xxtea_decode
        ),
        op!(
            "dpa:xxtea:encrypt",
            "crypto",
            "op.xxtea.encrypt.desc",
            &[
                ArgSpec {
                    name: "key",
                    required: true,
                    description: "op.xxtea.encrypt.arg.key",
                    format: crate::ops::ArgFormat::HexOrUtf8,
                },
                ArgSpec {
                    name: "padding",
                    required: false,
                    description: "op.tea.arg.padding",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            xxtea_encode
        ),
        op!(
            "dpa:xxtea:decrypt",
            "crypto",
            "op.xxtea.decrypt.desc",
            &[
                ArgSpec {
                    name: "key",
                    required: true,
                    description: "op.xxtea.decrypt.arg.key",
                    format: crate::ops::ArgFormat::HexOrUtf8,
                },
                ArgSpec {
                    name: "padding",
                    required: false,
                    description: "op.tea.arg.padding",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            xxtea_decode
        ),
    ]
}

/// Streaming RC4: KSA runs at construction; PRGA i/j state persists across chunks.
struct Rc4Stream {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4Stream {
    fn new(key: &[u8]) -> Self {
        let mut s: [u8; 256] = core::array::from_fn(|i| i as u8);
        let mut j: u8 = 0;
        for i in 0..256usize {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }
        Self { s, i: 0, j: 0 }
    }
}

impl StreamingOp for Rc4Stream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(chunk.len());
        for _ in chunk {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let k =
                self.s[(self.s[self.i as usize].wrapping_add(self.s[self.j as usize])) as usize];
            out.push(k);
        }
        // Same as the in-memory byte-wise XOR: mix by position with the output stream.
        for (o, &b) in out.iter_mut().zip(chunk) {
            *o ^= b;
        }
        Ok(out)
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        Ok(Vec::new())
    }
}

/// Mode for legacy 8-byte block ciphers (3DES / Blowfish): ecb/cbc/cfb/ofb/ctr.
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum LegacyMode {
    Ecb,
    Cbc,
    Cfb,
    Ofb,
    Ctr,
}

/// Adapter: 3DES block ops for the generic cipher helpers in cipher.rs.
impl BlockCipherOps for TdesEde3 {
    const BLOCK: usize = 8;

    fn encrypt(&self, blk: &mut [u8]) {
        let mut b = des::cipher::Block::<TdesEde3>::clone_from_slice(blk);
        DesBlockEncrypt::encrypt_block(self, &mut b);
        blk.copy_from_slice(&b);
    }

    fn decrypt(&self, blk: &mut [u8]) {
        let mut b = des::cipher::Block::<TdesEde3>::clone_from_slice(blk);
        DesBlockDecrypt::decrypt_block(self, &mut b);
        blk.copy_from_slice(&b);
    }
}

/// Adapter: Blowfish (big-endian) block ops for the generic helpers.
impl BlockCipherOps for Blowfish<BE> {
    const BLOCK: usize = 8;

    fn encrypt(&self, blk: &mut [u8]) {
        let mut b = blowfish::cipher::Block::<Blowfish<BE>>::clone_from_slice(blk);
        BfBlockEncrypt::encrypt_block(self, &mut b);
        blk.copy_from_slice(&b);
    }

    fn decrypt(&self, blk: &mut [u8]) {
        let mut b = blowfish::cipher::Block::<Blowfish<BE>>::clone_from_slice(blk);
        BfBlockDecrypt::decrypt_block(self, &mut b);
        blk.copy_from_slice(&b);
    }
}

const TEA_DELTA: u32 = 0x9E37_79B9;

pub(crate) fn make_rc4(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    let key = require_key(args)?;
    if key.len() > 256 {
        anyhow::bail!(
            "{}",
            i18n::tf("err.rc4_key_len", &[key.len().to_string().as_str()])
        );
    }
    Ok(Box::new(Rc4Stream::new(&key)))
}

pub(crate) fn rc4(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let key = require_key(args)?;
    if key.len() > 256 {
        anyhow::bail!(
            "{}",
            i18n::tf("err.rc4_key_len", &[key.len().to_string().as_str()])
        );
    }
    // KSA
    let mut s: [u8; 256] = core::array::from_fn(|i| i as u8);
    let mut j: u8 = 0;
    for i in 0..256usize {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }
    // PRGA
    let mut out = input.to_vec();
    let (mut i, mut j) = (0u8, 0u8);
    for b in out.iter_mut() {
        i = i.wrapping_add(1);
        j = j.wrapping_add(s[i as usize]);
        s.swap(i as usize, j as usize);
        let k = s[(s[i as usize].wrapping_add(s[j as usize])) as usize];
        *b ^= k;
    }
    Ok(out)
}

/// `dpa:rc4:decrypt` - RC4 is a stream cipher: encrypting twice recovers the
/// plaintext. This alias runs the same keystream XOR as `dpa:rc4`, so
/// `encrypt` then `decrypt` round-trips.
pub(crate) fn rc4_decrypt(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    rc4(input, args)
}

pub(crate) fn parse_legacy_mode(args: &HashMap<String, String>) -> anyhow::Result<LegacyMode> {
    match opt_arg(args, "mode", "cbc") {
        "ecb" => Ok(LegacyMode::Ecb),
        "cbc" => Ok(LegacyMode::Cbc),
        "cfb" => Ok(LegacyMode::Cfb),
        "ofb" => Ok(LegacyMode::Ofb),
        "ctr" => Ok(LegacyMode::Ctr),
        other => anyhow::bail!(
            "{}",
            i18n::tf("err.unknown_mode", &[other, "ecb/cbc/cfb/ofb/ctr"])
        ),
    }
}

pub(crate) fn des3_encrypt(
    input: &[u8],
    args: &HashMap<String, String>,
) -> anyhow::Result<Vec<u8>> {
    des3_run(input, args, true)
}

pub(crate) fn des3_decrypt(
    input: &[u8],
    args: &HashMap<String, String>,
) -> anyhow::Result<Vec<u8>> {
    des3_run(input, args, false)
}

pub(crate) fn des3_from_args(args: &HashMap<String, String>) -> anyhow::Result<TdesEde3> {
    let key = require_key(args)?;
    if key.len() != 24 {
        anyhow::bail!(
            "{}",
            i18n::tf("err.des3_key_len", &[key.len().to_string().as_str()])
        );
    }
    TdesEde3::new_from_slice(&key)
        .map_err(|e| anyhow::anyhow!("{}", i18n::tf("err.cipher_init", &[e.to_string().as_str()])))
}

pub(crate) fn des3_run(
    input: &[u8],
    args: &HashMap<String, String>,
    encrypt: bool,
) -> anyhow::Result<Vec<u8>> {
    let cipher = des3_from_args(args)?;
    match parse_legacy_mode(args)? {
        LegacyMode::Ecb => des3_block_crypt(input, args, cipher, true, encrypt),
        LegacyMode::Cbc => des3_block_crypt(input, args, cipher, false, encrypt),
        LegacyMode::Cfb => cfb_crypt(input, args, cipher, encrypt),
        LegacyMode::Ofb => ofb_crypt(input, args, cipher),
        LegacyMode::Ctr => ctr_crypt(input, args, cipher),
    }
}

/// In-memory ECB/CBC for 3DES, sharing the generic buffered block-mode stream
/// (BufBlockStream): one-shot write + finish. 8-byte blocks, PKCS#7 (or
/// padding=none), iv defaults to the all-zero block.
pub(crate) fn des3_block_crypt(
    input: &[u8],
    args: &HashMap<String, String>,
    cipher: TdesEde3,
    ecb: bool,
    encrypt: bool,
) -> anyhow::Result<Vec<u8>> {
    let mut s = BufBlockStream::new(args, cipher, ecb, encrypt)?;
    let mut out = s.write(input)?;
    out.extend(s.finish()?);
    Ok(out)
}

pub(crate) fn blowfish_encrypt(
    input: &[u8],
    args: &HashMap<String, String>,
) -> anyhow::Result<Vec<u8>> {
    blowfish_run(input, args, true)
}

pub(crate) fn blowfish_decrypt(
    input: &[u8],
    args: &HashMap<String, String>,
) -> anyhow::Result<Vec<u8>> {
    blowfish_run(input, args, false)
}

pub(crate) fn blowfish_from_args(args: &HashMap<String, String>) -> anyhow::Result<Blowfish<BE>> {
    let key = require_key(args)?;
    if !(4..=56).contains(&key.len()) {
        anyhow::bail!(
            "{}",
            i18n::tf("err.blowfish_key_len", &[key.len().to_string().as_str()])
        );
    }
    Blowfish::<BE>::new_from_slice(&key)
        .map_err(|e| anyhow::anyhow!("{}", i18n::tf("err.cipher_init", &[e.to_string().as_str()])))
}

pub(crate) fn blowfish_run(
    input: &[u8],
    args: &HashMap<String, String>,
    encrypt: bool,
) -> anyhow::Result<Vec<u8>> {
    let cipher = blowfish_from_args(args)?;
    match parse_legacy_mode(args)? {
        LegacyMode::Ecb => blowfish_block_crypt(input, args, cipher, true, encrypt),
        LegacyMode::Cbc => blowfish_block_crypt(input, args, cipher, false, encrypt),
        LegacyMode::Cfb => cfb_crypt(input, args, cipher, encrypt),
        LegacyMode::Ofb => ofb_crypt(input, args, cipher),
        LegacyMode::Ctr => ctr_crypt(input, args, cipher),
    }
}

/// In-memory ECB/CBC for Blowfish, sharing the generic buffered block-mode
/// stream (BufBlockStream): one-shot write + finish. 8-byte blocks, PKCS#7 (or
/// padding=none), iv defaults to the all-zero block.
pub(crate) fn blowfish_block_crypt(
    input: &[u8],
    args: &HashMap<String, String>,
    cipher: Blowfish<BE>,
    ecb: bool,
    encrypt: bool,
) -> anyhow::Result<Vec<u8>> {
    let mut s = BufBlockStream::new(args, cipher, ecb, encrypt)?;
    let mut out = s.write(input)?;
    out.extend(s.finish()?);
    Ok(out)
}

pub(crate) fn make_des3_enc(
    args: &HashMap<String, String>,
) -> anyhow::Result<Box<dyn StreamingOp>> {
    make_des3(args, true)
}

pub(crate) fn make_des3_dec(
    args: &HashMap<String, String>,
) -> anyhow::Result<Box<dyn StreamingOp>> {
    make_des3(args, false)
}

pub(crate) fn make_des3(
    args: &HashMap<String, String>,
    encrypt: bool,
) -> anyhow::Result<Box<dyn StreamingOp>> {
    let cipher = des3_from_args(args)?;
    match parse_legacy_mode(args)? {
        LegacyMode::Ecb => Ok(Box::new(BufBlockStream::new(args, cipher, true, encrypt)?)),
        LegacyMode::Cbc => Ok(Box::new(BufBlockStream::new(args, cipher, false, encrypt)?)),
        LegacyMode::Cfb => Ok(Box::new(CfbStream::new(args, cipher, encrypt)?)),
        LegacyMode::Ofb => Ok(Box::new(OfbStream::new(args, cipher)?)),
        LegacyMode::Ctr => Ok(Box::new(CtrStream::new(args, cipher)?)),
    }
}

pub(crate) fn make_blowfish_enc(
    args: &HashMap<String, String>,
) -> anyhow::Result<Box<dyn StreamingOp>> {
    make_blowfish(args, true)
}

pub(crate) fn make_blowfish_dec(
    args: &HashMap<String, String>,
) -> anyhow::Result<Box<dyn StreamingOp>> {
    make_blowfish(args, false)
}

pub(crate) fn make_blowfish(
    args: &HashMap<String, String>,
    encrypt: bool,
) -> anyhow::Result<Box<dyn StreamingOp>> {
    let cipher = blowfish_from_args(args)?;
    match parse_legacy_mode(args)? {
        LegacyMode::Ecb => Ok(Box::new(BufBlockStream::new(args, cipher, true, encrypt)?)),
        LegacyMode::Cbc => Ok(Box::new(BufBlockStream::new(args, cipher, false, encrypt)?)),
        LegacyMode::Cfb => Ok(Box::new(CfbStream::new(args, cipher, encrypt)?)),
        LegacyMode::Ofb => Ok(Box::new(OfbStream::new(args, cipher)?)),
        LegacyMode::Ctr => Ok(Box::new(CtrStream::new(args, cipher)?)),
    }
}

pub(crate) fn tea_key(args: &HashMap<String, String>) -> anyhow::Result<[u32; 4]> {
    let key = require_key(args)?;
    if key.len() != 16 {
        anyhow::bail!(
            "{}",
            i18n::tf("err.tea_key_len", &[key.len().to_string().as_str()])
        );
    }
    let mut k = [0u32; 4];
    for i in 0..4 {
        k[i] = u32::from_be_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    }
    Ok(k)
}

pub(crate) fn pad_to_8(input: &[u8]) -> Vec<u8> {
    let rem = input.len() % 8;
    if rem == 0 {
        return input.to_vec();
    }
    let mut v = input.to_vec();
    v.extend(std::iter::repeat_n(0u8, 8 - rem));
    v
}

/// Strip zero padding on decode. A fully-zero block is kept as one 8-byte
/// block, since zero padding cannot distinguish it from padded data.
pub(crate) fn unpad_zero(mut v: Vec<u8>) -> Vec<u8> {
    while v.last() == Some(&0) {
        v.pop();
    }
    if v.is_empty() {
        v.resize(8, 0);
    }
    v
}

/// TEA-family padding: zero (legacy default), pkcs7 or none (strict, errors on
/// misaligned input). Returns the block-aligned payload.
pub(crate) fn pad_tea_block(input: &[u8], mode: &str) -> anyhow::Result<Vec<u8>> {
    match mode {
        "none" => {
            if !input.len().is_multiple_of(8) {
                anyhow::bail!("{}", i18n::t("err.tea_block_misaligned"));
            }
            Ok(input.to_vec())
        }
        "pkcs7" => {
            let pad = 8 - (input.len() % 8);
            let mut v = input.to_vec();
            v.extend(std::iter::repeat_n(pad as u8, pad));
            Ok(v)
        }
        _ => Ok(pad_to_8(input)),
    }
}

/// Reverse of `pad_tea_block`: strips pkcs7 (validated), keeps zero padding
/// legacy semantics, or verifies alignment for none mode.
pub(crate) fn unpad_tea_block(mut v: Vec<u8>, mode: &str) -> anyhow::Result<Vec<u8>> {
    match mode {
        "none" => {
            if !v.len().is_multiple_of(8) {
                anyhow::bail!("{}", i18n::t("err.tea_block_misaligned"));
            }
            Ok(v)
        }
        "pkcs7" => {
            let &last = v
                .last()
                .ok_or_else(|| anyhow::anyhow!("{}", i18n::t("err.tea_bad_padding")))?;
            let pad = last as usize;
            if pad == 0 || pad > 8 || v.len() < pad {
                anyhow::bail!("{}", i18n::t("err.tea_bad_padding"));
            }
            if v[v.len() - pad..].iter().any(|&b| b != last) {
                anyhow::bail!("{}", i18n::t("err.tea_bad_padding"));
            }
            v.truncate(v.len() - pad);
            Ok(v)
        }
        _ => Ok(unpad_zero(v)),
    }
}

pub(crate) fn tea_padding(args: &HashMap<String, String>) -> String {
    args.get("padding")
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_else(|| "zero".to_string())
}

pub(crate) fn tea_encode_block(v: &mut [u32; 2], k: &[u32; 4]) {
    let (mut v0, mut v1) = (v[0], v[1]);
    let mut sum = 0u32;
    for _ in 0..32 {
        sum = sum.wrapping_add(TEA_DELTA);
        v0 = v0.wrapping_add(
            (v1 << 4).wrapping_add(k[0]) ^ v1.wrapping_add(sum) ^ (v1 >> 5).wrapping_add(k[1]),
        );
        v1 = v1.wrapping_add(
            (v0 << 4).wrapping_add(k[2]) ^ v0.wrapping_add(sum) ^ (v0 >> 5).wrapping_add(k[3]),
        );
    }
    v[0] = v0;
    v[1] = v1;
}

pub(crate) fn tea_decode_block(v: &mut [u32; 2], k: &[u32; 4]) {
    let (mut v0, mut v1) = (v[0], v[1]);
    let mut sum = TEA_DELTA.wrapping_mul(32);
    for _ in 0..32 {
        v1 = v1.wrapping_sub(
            (v0 << 4).wrapping_add(k[2]) ^ v0.wrapping_add(sum) ^ (v0 >> 5).wrapping_add(k[3]),
        );
        v0 = v0.wrapping_sub(
            (v1 << 4).wrapping_add(k[0]) ^ v1.wrapping_add(sum) ^ (v1 >> 5).wrapping_add(k[1]),
        );
        sum = sum.wrapping_sub(TEA_DELTA);
    }
    v[0] = v0;
    v[1] = v1;
}

pub(crate) fn tea_run(
    input: &[u8],
    args: &HashMap<String, String>,
    encode: bool,
) -> anyhow::Result<Vec<u8>> {
    let k = tea_key(args)?;
    if input.is_empty() {
        return Ok(Vec::new());
    }
    let padding = tea_padding(args);
    let data = if encode {
        pad_tea_block(input, &padding)?
    } else {
        if !input.len().is_multiple_of(8) {
            anyhow::bail!("{}", i18n::t("err.tea_block_misaligned"));
        }
        input.to_vec()
    };
    let mut out = Vec::with_capacity(data.len());
    for blk in data.as_chunks::<8>().0 {
        let mut v = [0u32; 2];
        v[0] = u32::from_be_bytes([blk[0], blk[1], blk[2], blk[3]]);
        v[1] = u32::from_be_bytes([blk[4], blk[5], blk[6], blk[7]]);
        if encode {
            tea_encode_block(&mut v, &k);
        } else {
            tea_decode_block(&mut v, &k);
        }
        out.extend_from_slice(&v[0].to_be_bytes());
        out.extend_from_slice(&v[1].to_be_bytes());
    }
    if encode {
        Ok(out)
    } else {
        unpad_tea_block(out, &padding)
    }
}

pub(crate) fn tea_encode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    tea_run(input, args, true)
}

pub(crate) fn tea_decode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    tea_run(input, args, false)
}

pub(crate) fn xtea_encode_block(v: &mut [u32; 2], k: &[u32; 4]) {
    let (mut v0, mut v1) = (v[0], v[1]);
    let mut sum = 0u32;
    for _ in 0..32 {
        v0 = v0.wrapping_add(
            (((v1 << 4) ^ (v1 >> 5)).wrapping_add(v1)) ^ sum.wrapping_add(k[(sum & 3) as usize]),
        );
        sum = sum.wrapping_add(TEA_DELTA);
        v1 = v1.wrapping_add(
            (((v0 << 4) ^ (v0 >> 5)).wrapping_add(v0))
                ^ sum.wrapping_add(k[((sum >> 11) & 3) as usize]),
        );
    }
    v[0] = v0;
    v[1] = v1;
}

pub(crate) fn xtea_decode_block(v: &mut [u32; 2], k: &[u32; 4]) {
    let (mut v0, mut v1) = (v[0], v[1]);
    let mut sum = TEA_DELTA.wrapping_mul(32);
    for _ in 0..32 {
        v1 = v1.wrapping_sub(
            (((v0 << 4) ^ (v0 >> 5)).wrapping_add(v0))
                ^ sum.wrapping_add(k[((sum >> 11) & 3) as usize]),
        );
        sum = sum.wrapping_sub(TEA_DELTA);
        v0 = v0.wrapping_sub(
            (((v1 << 4) ^ (v1 >> 5)).wrapping_add(v1)) ^ sum.wrapping_add(k[(sum & 3) as usize]),
        );
    }
    v[0] = v0;
    v[1] = v1;
}

pub(crate) fn xtea_run(
    input: &[u8],
    args: &HashMap<String, String>,
    encode: bool,
) -> anyhow::Result<Vec<u8>> {
    let k = tea_key(args)?;
    if input.is_empty() {
        return Ok(Vec::new());
    }
    let padding = tea_padding(args);
    let data = if encode {
        pad_tea_block(input, &padding)?
    } else {
        if !input.len().is_multiple_of(8) {
            anyhow::bail!("{}", i18n::t("err.tea_block_misaligned"));
        }
        input.to_vec()
    };
    let mut out = Vec::with_capacity(data.len());
    for blk in data.as_chunks::<8>().0 {
        let mut v = [0u32; 2];
        v[0] = u32::from_be_bytes([blk[0], blk[1], blk[2], blk[3]]);
        v[1] = u32::from_be_bytes([blk[4], blk[5], blk[6], blk[7]]);
        if encode {
            xtea_encode_block(&mut v, &k);
        } else {
            xtea_decode_block(&mut v, &k);
        }
        out.extend_from_slice(&v[0].to_be_bytes());
        out.extend_from_slice(&v[1].to_be_bytes());
    }
    if encode {
        Ok(out)
    } else {
        unpad_tea_block(out, &padding)
    }
}

pub(crate) fn xtea_encode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    xtea_run(input, args, true)
}

pub(crate) fn xtea_decode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    xtea_run(input, args, false)
}

pub(crate) fn xxtea_encrypt_block(v: &mut [u32], k: &[u32; 4]) {
    let n = v.len();
    if n < 2 {
        return;
    }
    let q = 6 + 52 / n as u32;
    let mut sum = 0u32;
    let mut z = v[n - 1];
    for _ in 0..q {
        sum = sum.wrapping_add(TEA_DELTA);
        let e = (sum >> 2) & 3;
        for p in 0..n - 1 {
            let y = v[p + 1];
            let mx = (((z >> 5) ^ (y << 2)).wrapping_add((y >> 3) ^ (z << 4)))
                ^ ((sum ^ y).wrapping_add(k[(p & 3) ^ e as usize] ^ z));
            v[p] = v[p].wrapping_add(mx);
            z = v[p];
        }
        let y = v[0];
        let p = n - 1;
        let mx = (((z >> 5) ^ (y << 2)).wrapping_add((y >> 3) ^ (z << 4)))
            ^ ((sum ^ y).wrapping_add(k[(p & 3) ^ e as usize] ^ z));
        v[n - 1] = v[n - 1].wrapping_add(mx);
        z = v[n - 1];
    }
}

pub(crate) fn xxtea_decrypt_block(v: &mut [u32], k: &[u32; 4]) {
    let n = v.len();
    if n < 2 {
        return;
    }
    let q = 6 + 52 / n as u32;
    let mut sum = TEA_DELTA.wrapping_mul(q);
    let mut y = v[0];
    for _ in 0..q {
        let e = (sum >> 2) & 3;
        for p in (1..n).rev() {
            let z = v[p - 1];
            let mx = (((z >> 5) ^ (y << 2)).wrapping_add((y >> 3) ^ (z << 4)))
                ^ ((sum ^ y).wrapping_add(k[(p & 3) ^ e as usize] ^ z));
            v[p] = v[p].wrapping_sub(mx);
            y = v[p];
        }
        let z = v[n - 1];
        let p = 0usize;
        let mx = (((z >> 5) ^ (y << 2)).wrapping_add((y >> 3) ^ (z << 4)))
            ^ ((sum ^ y).wrapping_add(k[(p & 3) ^ e as usize] ^ z));
        v[0] = v[0].wrapping_sub(mx);
        y = v[0];
        sum = sum.wrapping_sub(TEA_DELTA);
    }
}

pub(crate) fn xxtea_run(
    input: &[u8],
    args: &HashMap<String, String>,
    encode: bool,
) -> anyhow::Result<Vec<u8>> {
    let k = tea_key(args)?;
    if input.is_empty() {
        return Ok(Vec::new());
    }
    let padding = tea_padding(args);
    let data = if encode {
        pad_tea_block(input, &padding)?
    } else {
        if !input.len().is_multiple_of(8) {
            anyhow::bail!("{}", i18n::t("err.tea_block_misaligned"));
        }
        input.to_vec()
    };
    let mut v: Vec<u32> = data
        .as_chunks::<4>()
        .0
        .iter()
        .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
        .collect();
    if encode {
        xxtea_encrypt_block(&mut v, &k);
    } else {
        xxtea_decrypt_block(&mut v, &k);
    }
    let mut out = Vec::with_capacity(v.len() * 4);
    for w in v {
        out.extend_from_slice(&w.to_be_bytes());
    }
    if encode {
        Ok(out)
    } else {
        unpad_tea_block(out, &padding)
    }
}

pub(crate) fn xxtea_encode(
    input: &[u8],
    args: &HashMap<String, String>,
) -> anyhow::Result<Vec<u8>> {
    xxtea_run(input, args, true)
}

pub(crate) fn xxtea_decode(
    input: &[u8],
    args: &HashMap<String, String>,
) -> anyhow::Result<Vec<u8>> {
    xxtea_run(input, args, false)
}
