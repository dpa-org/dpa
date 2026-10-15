//! Crypto ops: XOR / AES / ChaCha20 / RC4 / HMAC.
//!
//! AES follows the "direction split, mode parameterized" convention (aligned
//! with CyberChef): one encrypt op and one decrypt op; the block-cipher mode
//! (ecb/cbc/cfb/ofb/ctr) is an optional parameter (default cbc), and the key
//! length (16/24/32 bytes) selects AES-128/192/256. Block modes (ecb/cbc) use
//! PKCS#7 padding; stream modes (cfb/ofb/ctr) need no padding.

use std::collections::HashMap;

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256, Block};
use blowfish::Blowfish;
use blowfish::cipher::{BlockDecrypt as BfBlockDecrypt, BlockEncrypt as BfBlockEncrypt};
use byteorder::BE;
use des::TdesEde3;
use des::cipher::{BlockDecrypt as DesBlockDecrypt, BlockEncrypt as DesBlockEncrypt};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use super::cipher::{
    BlockCipherOps, BufBlockStream, CfbStream, CtrStream, OfbStream, cfb_crypt, ctr_crypt,
    ofb_crypt,
};
use super::{ArgSpec, Op, StreamingOp};
use crate::i18n;

pub fn ops() -> Vec<Op> {
    vec![
        stream_op!(
            "dpa:xor",
            "crypto",
            "op.xor.desc",
            &[
                ArgSpec {
                    name: "key",
                    required: true,
                    description: "op.xor.arg.key",
                    format: crate::ops::ArgFormat::HexOrUtf8,
                },
                ArgSpec {
                    name: "scheme",
                    required: false,
                    description: "op.xor.arg.scheme",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "null_preserving",
                    required: false,
                    description: "op.xor.arg.null_preserving",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            xor,
            make_xor
        ),
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
            ],
            aes_decrypt,
            make_aes_dec
        ),
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
        stream_op!(
            "dpa:chacha20",
            "crypto",
            "op.chacha20.desc",
            &[
                ArgSpec {
                    name: "key",
                    required: true,
                    description: "op.chacha20.arg.key",
                    format: crate::ops::ArgFormat::HexOrUtf8,
                },
                ArgSpec {
                    name: "nonce",
                    required: true,
                    description: "op.chacha20.arg.nonce",
                    format: crate::ops::ArgFormat::HexOrUtf8,
                },
            ],
            chacha20_crypt,
            make_chacha20
        ),
        // XOR brute force
        op!(
            "dpa:xor:bruteforce",
            "crypto",
            "op.xor.bruteforce.desc",
            &[
                ArgSpec {
                    name: "top",
                    required: false,
                    description: "op.xor.bruteforce.arg.top",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "sample",
                    required: false,
                    description: "op.xor.bruteforce.arg.sample",
                    format: crate::ops::ArgFormat::HexOrUtf8,
                },
                ArgSpec {
                    name: "key_length",
                    required: false,
                    description: "op.xor.bruteforce.arg.key_length",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "scheme",
                    required: false,
                    description: "op.xor.bruteforce.arg.scheme",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "null_preserving",
                    required: false,
                    description: "op.xor.bruteforce.arg.null_preserving",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "sample_offset",
                    required: false,
                    description: "op.xor.bruteforce.arg.sample_offset",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "print_key",
                    required: false,
                    description: "op.xor.bruteforce.arg.print_key",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "hex_output",
                    required: false,
                    description: "op.xor.bruteforce.arg.hex_output",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            xor_bruteforce
        ),
        // legacy block ciphers
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
        // TEA family (64-bit blocks, zero padding)
        op!(
            "dpa:tea:encode",
            "crypto",
            "op.tea.encode.desc",
            &[ArgSpec {
                name: "key",
                required: true,
                description: "op.tea.encode.arg.key",
                format: crate::ops::ArgFormat::HexOrUtf8,
            },],
            tea_encode
        ),
        op!(
            "dpa:tea:decode",
            "crypto",
            "op.tea.decode.desc",
            &[ArgSpec {
                name: "key",
                required: true,
                description: "op.tea.decode.arg.key",
                format: crate::ops::ArgFormat::HexOrUtf8,
            },],
            tea_decode
        ),
        op!(
            "dpa:xtea:encode",
            "crypto",
            "op.xtea.encode.desc",
            &[ArgSpec {
                name: "key",
                required: true,
                description: "op.xtea.encode.arg.key",
                format: crate::ops::ArgFormat::HexOrUtf8,
            },],
            xtea_encode
        ),
        op!(
            "dpa:xtea:decode",
            "crypto",
            "op.xtea.decode.desc",
            &[ArgSpec {
                name: "key",
                required: true,
                description: "op.xtea.decode.arg.key",
                format: crate::ops::ArgFormat::HexOrUtf8,
            },],
            xtea_decode
        ),
        op!(
            "dpa:xxtea:encode",
            "crypto",
            "op.xxtea.encode.desc",
            &[ArgSpec {
                name: "key",
                required: true,
                description: "op.xxtea.encode.arg.key",
                format: crate::ops::ArgFormat::HexOrUtf8,
            },],
            xxtea_encode
        ),
        op!(
            "dpa:xxtea:decode",
            "crypto",
            "op.xxtea.decode.desc",
            &[ArgSpec {
                name: "key",
                required: true,
                description: "op.xxtea.decode.arg.key",
                format: crate::ops::ArgFormat::HexOrUtf8,
            },],
            xxtea_decode
        ),
        // key derivation (PBKDF2 / HKDF)
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

// ---------------------------------------------------------------------------
// Streaming implementation
// ---------------------------------------------------------------------------

/// XOR scheme (mirrors CyberChef's XOR bit-op schemes):
/// `standard` cycles a single key over the whole input;
/// `input-delimited` splits both key and input on whitespace, so token i is
/// XORed with key i (keys cycle), and whitespace separators pass through;
/// `input-differential` rekeys with the previous *input* byte;
/// `output-differential` rekeys with the previous *output* byte;
/// `cascade` keys each byte with the following input byte (last uses 0).
#[derive(Clone, Copy, PartialEq)]
enum XorScheme {
    Standard,
    InputDelimited,
    InputDifferential,
    OutputDifferential,
    Cascade,
}

/// Streaming XOR. For `standard` only the key cursor persists; for
/// `input-delimited` token/segment state must survive chunk boundaries;
/// differential schemes mutate the single key in place; `cascade` delays the
/// last byte of every chunk until the next chunk (or finish) is seen.
struct XorStream {
    key: Vec<u8>,
    keys: Vec<Vec<u8>>,
    scheme: XorScheme,
    pos: usize,
    null_preserving: bool,
    pending: Option<u8>,
    in_token: bool,
    key_idx: usize,
    byte_idx: usize,
    token_count: usize,
}

fn parse_xor_scheme(args: &HashMap<String, String>) -> anyhow::Result<XorScheme> {
    match opt_arg(args, "scheme", "standard") {
        "standard" => Ok(XorScheme::Standard),
        "input-delimited" | "input_delimited" => Ok(XorScheme::InputDelimited),
        "input-differential" | "input_differential" => Ok(XorScheme::InputDifferential),
        "output-differential" | "output_differential" => Ok(XorScheme::OutputDifferential),
        "cascade" => Ok(XorScheme::Cascade),
        other => anyhow::bail!(
            "{}",
            i18n::tf(
                "err.xor.scheme",
                &[
                    other,
                    "standard/input-delimited/input-differential/output-differential/cascade"
                ]
            )
        ),
    }
}

/// Parse the optional `null_preserving` boolean (skip 0x00 bytes and bytes
/// equal to the current key byte, leaving them unchanged).
fn parse_null_preserving(args: &HashMap<String, String>) -> anyhow::Result<bool> {
    match opt_arg(args, "null_preserving", "false") {
        "false" | "0" => Ok(false),
        "true" | "1" => Ok(true),
        other => anyhow::bail!("{}", i18n::tf("err.bool_invalid", &[other])),
    }
}

fn make_xor(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    let scheme = parse_xor_scheme(args)?;
    let null_preserving = parse_null_preserving(args)?;
    let (key, keys) = match scheme {
        XorScheme::InputDelimited => {
            let key_str = args
                .get("key")
                .ok_or_else(|| anyhow::anyhow!("{}", i18n::t("err.missing_key")))?;
            let parts: Vec<&str> = key_str.split_whitespace().collect();
            if parts.is_empty() {
                anyhow::bail!("{}", i18n::t("err.empty_key"));
            }
            let keys: Vec<Vec<u8>> = parts
                .iter()
                .map(|p| parse_key(p))
                .collect::<anyhow::Result<_>>()?;
            if keys.iter().any(|k| k.is_empty()) {
                anyhow::bail!("{}", i18n::t("err.empty_key"));
            }
            (Vec::new(), keys)
        }
        _ => (require_key(args)?, Vec::new()),
    };
    Ok(Box::new(XorStream {
        key,
        keys,
        scheme,
        pos: 0,
        null_preserving,
        pending: None,
        in_token: false,
        key_idx: 0,
        byte_idx: 0,
        token_count: 0,
    }))
}

impl StreamingOp for XorStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        match self.scheme {
            XorScheme::Standard | XorScheme::InputDifferential | XorScheme::OutputDifferential => {
                let mut out = Vec::with_capacity(chunk.len());
                for &o in chunk {
                    let k = self.key[self.pos % self.key.len()];
                    let x = if self.null_preserving && (o == 0 || o == k) {
                        o
                    } else {
                        o ^ k
                    };
                    out.push(x);
                    if !(self.null_preserving && (o == 0 || o == k)) {
                        match self.scheme {
                            XorScheme::InputDifferential => {
                                let idx = self.pos % self.key.len();
                                self.key[idx] = o;
                            }
                            XorScheme::OutputDifferential => {
                                let idx = self.pos % self.key.len();
                                self.key[idx] = x;
                            }
                            _ => {}
                        }
                    }
                    self.pos += 1;
                }
                Ok(out)
            }
            XorScheme::Cascade => {
                let mut out = Vec::with_capacity(chunk.len() + 1);
                if let Some(p) = self.pending.take() {
                    let next = chunk.first().copied().unwrap_or(0);
                    let x = if self.null_preserving && (p == 0 || p == next) {
                        p
                    } else {
                        p ^ next
                    };
                    out.push(x);
                }
                for i in 0..chunk.len().saturating_sub(1) {
                    let o = chunk[i];
                    let next = chunk[i + 1];
                    let x = if self.null_preserving && (o == 0 || o == next) {
                        o
                    } else {
                        o ^ next
                    };
                    out.push(x);
                }
                if let Some(&last) = chunk.last() {
                    self.pending = Some(last);
                }
                Ok(out)
            }
            XorScheme::InputDelimited => {
                let mut out = Vec::with_capacity(chunk.len());
                let n = self.keys.len();
                for &b in chunk {
                    if self.in_token {
                        if b.is_ascii_whitespace() {
                            self.in_token = false;
                            out.push(b);
                        } else {
                            let key = &self.keys[self.key_idx % n];
                            out.push(b ^ key[self.byte_idx % key.len()]);
                            self.byte_idx += 1;
                        }
                    } else if b.is_ascii_whitespace() {
                        out.push(b);
                    } else {
                        self.in_token = true;
                        self.byte_idx = 0;
                        if self.token_count > 0 {
                            self.key_idx += 1;
                        }
                        self.token_count += 1;
                        let key = &self.keys[self.key_idx % n];
                        out.push(b ^ key[0]);
                        self.byte_idx = 1;
                    }
                }
                Ok(out)
            }
        }
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        if self.scheme == XorScheme::Cascade {
            if let Some(p) = self.pending.take() {
                // Cascade keys the last byte with 0, so it always passes through.
                return Ok(vec![p]);
            }
        }
        Ok(Vec::new())
    }
}

/// Streaming RC4: KSA runs at construction; PRGA i/j state persists across chunks.
struct Rc4Stream {
    s: [u8; 256],
    i: u8,
    j: u8,
}

fn make_rc4(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    let key = require_key(args)?;
    if key.len() > 256 {
        anyhow::bail!(
            "{}",
            i18n::tf("err.rc4_key_len", &[key.len().to_string().as_str()])
        );
    }
    Ok(Box::new(Rc4Stream::new(&key)))
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

fn make_hmac(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
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
        other => anyhow::bail!("{}", i18n::tf("err.unknown_algo", &[other])),
    };
    Ok(Box::new(HmacStream { mac }))
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

/// Parse a key/IV: `0x` prefix means hex, otherwise UTF-8 bytes.
pub fn parse_key(key: &str) -> anyhow::Result<Vec<u8>> {
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

fn xor(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let scheme = parse_xor_scheme(args)?;
    let null_preserving = parse_null_preserving(args)?;
    match scheme {
        XorScheme::Standard | XorScheme::InputDifferential | XorScheme::OutputDifferential => {
            let mut key = require_key(args)?;
            let mut out = Vec::with_capacity(input.len());
            for (i, &o) in input.iter().enumerate() {
                let k = key[i % key.len()];
                let x = if null_preserving && (o == 0 || o == k) {
                    o
                } else {
                    o ^ k
                };
                out.push(x);
                if !(null_preserving && (o == 0 || o == k)) {
                    match scheme {
                        XorScheme::InputDifferential => {
                            let idx = i % key.len();
                            key[idx] = o;
                        }
                        XorScheme::OutputDifferential => {
                            let idx = i % key.len();
                            key[idx] = x;
                        }
                        _ => {}
                    }
                }
            }
            Ok(out)
        }
        XorScheme::Cascade => {
            let mut out = Vec::with_capacity(input.len());
            for (i, &o) in input.iter().enumerate() {
                let k = if i + 1 < input.len() { input[i + 1] } else { 0 };
                let x = if null_preserving && (o == 0 || o == k) {
                    o
                } else {
                    o ^ k
                };
                out.push(x);
            }
            Ok(out)
        }
        XorScheme::InputDelimited => {
            let key_str = args
                .get("key")
                .ok_or_else(|| anyhow::anyhow!("{}", i18n::t("err.missing_key")))?;
            let parts: Vec<&str> = key_str.split_whitespace().collect();
            if parts.is_empty() {
                anyhow::bail!("{}", i18n::t("err.empty_key"));
            }
            let keys: Vec<Vec<u8>> = parts
                .iter()
                .map(|p| parse_key(p))
                .collect::<anyhow::Result<_>>()?;
            if keys.iter().any(|k| k.is_empty()) {
                anyhow::bail!("{}", i18n::t("err.empty_key"));
            }
            let mut out = Vec::with_capacity(input.len());
            let mut in_token = false;
            let mut key_idx = 0usize;
            let mut byte_idx = 0usize;
            let mut token_count = 0usize;
            for &b in input {
                if in_token {
                    if b.is_ascii_whitespace() {
                        in_token = false;
                        out.push(b);
                    } else {
                        let key = &keys[key_idx % keys.len()];
                        out.push(b ^ key[byte_idx % key.len()]);
                        byte_idx += 1;
                    }
                } else if b.is_ascii_whitespace() {
                    out.push(b);
                } else {
                    in_token = true;
                    if token_count > 0 {
                        key_idx += 1;
                    }
                    token_count += 1;
                    let key = &keys[key_idx % keys.len()];
                    out.push(b ^ key[0]);
                    byte_idx = 1;
                }
            }
            Ok(out)
        }
    }
}

/// Read the required `key` argument, parse it, and reject empty keys.
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

/// Read an optional argument with a default value.
fn opt_arg<'a>(args: &'a HashMap<String, String>, name: &str, default: &'a str) -> &'a str {
    args.get(name).map(String::as_str).unwrap_or(default)
}

// ---------------------------------------------------------------------------
// ChaCha20 (RFC 8439): 32-byte key, 12-byte nonce, 32-bit block counter,
// 64-byte keystream blocks. Symmetric stream: running twice decrypts.
//
// Counter limit: the 32-bit block counter wraps after 2^32 blocks, i.e.
// 256 GiB of keystream per (key, nonce) pair; past that the keystream
// repeats, which is a confidentiality break. We intentionally keep 32-bit
// (RFC 8439) and refuse nothing at build time: consumers MUST re-key (or
// change the nonce) before 256 GiB. Note the in-memory run path can never
// reach the limit in practice, but a streamed run fed a giant file can.
// ---------------------------------------------------------------------------

fn qr(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(16);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(12);
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(8);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(7);
}

struct ChaCha20 {
    key: [u8; 32],
    nonce: [u8; 12],
    counter: u32,
}

impl ChaCha20 {
    fn new(key: &[u8], nonce: &[u8]) -> Self {
        let mut k = [0u8; 32];
        k.copy_from_slice(key);
        let mut n = [0u8; 12];
        n.copy_from_slice(nonce);
        Self {
            key: k,
            nonce: n,
            counter: 0,
        }
    }

    fn next_block(&mut self, out: &mut [u8; 64]) {
        let mut st = [0u32; 16];
        st[0] = 0x6170_7865;
        st[1] = 0x3320_646e;
        st[2] = 0x7962_2d32;
        st[3] = 0x6b20_6574;
        for i in 0..8 {
            let off = i * 4;
            st[4 + i] = u32::from_le_bytes([
                self.key[off],
                self.key[off + 1],
                self.key[off + 2],
                self.key[off + 3],
            ]);
        }
        st[12] = self.counter;
        st[13] = u32::from_le_bytes([self.nonce[0], self.nonce[1], self.nonce[2], self.nonce[3]]);
        st[14] = u32::from_le_bytes([self.nonce[4], self.nonce[5], self.nonce[6], self.nonce[7]]);
        st[15] = u32::from_le_bytes([self.nonce[8], self.nonce[9], self.nonce[10], self.nonce[11]]);

        let mut x = st;
        for _ in 0..10 {
            qr(&mut x, 0, 4, 8, 12);
            qr(&mut x, 1, 5, 9, 13);
            qr(&mut x, 2, 6, 10, 14);
            qr(&mut x, 3, 7, 11, 15);
            qr(&mut x, 0, 5, 10, 15);
            qr(&mut x, 1, 6, 11, 12);
            qr(&mut x, 2, 7, 8, 13);
            qr(&mut x, 3, 4, 9, 14);
        }
        for i in 0..16 {
            x[i] = x[i].wrapping_add(st[i]);
        }
        for i in 0..16 {
            out[i * 4..i * 4 + 4].copy_from_slice(&x[i].to_le_bytes());
        }
        self.counter = self.counter.wrapping_add(1);
    }
}

fn chacha20_from_args(args: &HashMap<String, String>) -> anyhow::Result<ChaCha20> {
    let key = require_key(args)?;
    if key.len() != 32 {
        anyhow::bail!(
            "{}",
            i18n::tf("err.bad_chacha_key_len", &[key.len().to_string().as_str()])
        );
    }
    let nonce_str = args
        .get("nonce")
        .ok_or_else(|| anyhow::anyhow!("{}", i18n::t("err.missing_nonce")))?;
    let nonce = parse_key(nonce_str)?;
    if nonce.len() != 12 {
        anyhow::bail!(
            "{}",
            i18n::tf("err.bad_nonce_len", &[nonce.len().to_string().as_str()])
        );
    }
    Ok(ChaCha20::new(&key, &nonce))
}

fn chacha20_crypt(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let mut chacha = chacha20_from_args(args)?;
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        let mut ks = [0u8; 64];
        chacha.next_block(&mut ks);
        let n = (input.len() - i).min(64);
        for (j, &b) in input[i..i + n].iter().enumerate() {
            out.push(b ^ ks[j]);
        }
        i += n;
    }
    Ok(out)
}

struct ChaCha20Stream {
    chacha: ChaCha20,
    cur: [u8; 64],
    pos: usize,
}

fn make_chacha20(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    let chacha = chacha20_from_args(args)?;
    Ok(Box::new(ChaCha20Stream {
        chacha,
        cur: [0u8; 64],
        pos: 64,
    }))
}

impl StreamingOp for ChaCha20Stream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(chunk.len());
        let mut i = 0;
        while i < chunk.len() {
            if self.pos == 64 {
                self.chacha.next_block(&mut self.cur);
                self.pos = 0;
            }
            let n = (chunk.len() - i).min(64 - self.pos);
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
// AES: "direction split, mode parameterized". One encrypt op + one decrypt op;
// mode (ecb/cbc/cfb/ofb/ctr) defaults to cbc; iv defaults to the all-zero block.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
enum AesMode {
    Ecb,
    Cbc,
    Cfb,
    Ofb,
    Ctr,
    Gcm,
}

fn parse_aes_mode(args: &HashMap<String, String>) -> anyhow::Result<AesMode> {
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

enum AesBlock {
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

fn aes_block_from_args(args: &HashMap<String, String>) -> anyhow::Result<AesBlock> {
    let key = require_key(args)?;
    let mk = |e: aes::cipher::InvalidLength| {
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

fn aes_encrypt(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    aes_run(input, args, true)
}

fn aes_decrypt(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    aes_run(input, args, false)
}

fn aes_run(input: &[u8], args: &HashMap<String, String>, encrypt: bool) -> anyhow::Result<Vec<u8>> {
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
fn aes_block_crypt(
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

// --- GCM (NIST SP 800-38D): authenticated encryption with associated data.
// Memory-only for now: the streaming factory rejects gcm with an explicit
// "not streamable" error. GHASH/GHASH field arithmetic is implemented over
// GF(2^128) with the irreducible polynomial x^128 + x^7 + x^2 + x + 1
// (reduction constant 0xe1 in the top byte).

/// Reduction constant for GF(2^128): x^128 + x^7 + x^2 + x + 1.
const GCM_R: u128 = 0xe1u128 << 120;

/// Carry-less multiplication in GF(2^128), then reduction modulo GCM_R.
fn gf_mul(x: u128, y: u128) -> u128 {
    let mut z: u128 = 0;
    let mut v: u128 = y;
    let mut xb: u128 = x;
    for _ in 0..128 {
        if xb & (1u128 << 127) != 0 {
            z ^= v;
        }
        let lsb = v & 1;
        v >>= 1;
        if lsb != 0 {
            v ^= GCM_R;
        }
        xb <<= 1;
    }
    z
}

/// GHASH: accumulate AAD blocks, ciphertext blocks (both zero-padded), then
/// the 64-bit bit-lengths of AAD and ciphertext.
fn ghash(h: u128, aad: &[u8], ct: &[u8]) -> u128 {
    let mut x: u128 = 0;
    for chunk in aad.chunks(16) {
        let mut blk = [0u8; 16];
        blk[..chunk.len()].copy_from_slice(chunk);
        x = gf_mul(x ^ u128::from_be_bytes(blk), h);
    }
    for chunk in ct.chunks(16) {
        let mut blk = [0u8; 16];
        blk[..chunk.len()].copy_from_slice(chunk);
        x = gf_mul(x ^ u128::from_be_bytes(blk), h);
    }
    let mut len_blk = [0u8; 16];
    len_blk[..8].copy_from_slice(&(aad.len() as u64 * 8).to_be_bytes());
    len_blk[8..].copy_from_slice(&(ct.len() as u64 * 8).to_be_bytes());
    x = gf_mul(x ^ u128::from_be_bytes(len_blk), h);
    x
}

/// Increments the low 32 bits of the 128-bit counter block (SP 800-38D inc32).
fn inc32(blk: &mut [u8; 16]) {
    for i in (12..16).rev() {
        blk[i] = blk[i].wrapping_add(1);
        if blk[i] != 0 {
            break;
        }
    }
}

/// GCTR keystream: counter starts at `icb` and is inc32-ed per block.
fn gctr(block: &AesBlock, icb: [u8; 16], input: &[u8], out: &mut Vec<u8>) {
    let mut cb = icb;
    let mut i = 0;
    while i < input.len() {
        let mut ks = [0u8; 16];
        ks.copy_from_slice(&cb);
        block.encrypt_block(&mut ks);
        inc32(&mut cb);
        let n = (input.len() - i).min(16);
        for (j, &b) in input[i..i + n].iter().enumerate() {
            out.push(b ^ ks[j]);
        }
        i += n;
    }
}

/// Builds J0: IV || 0^31 || 1 for 96-bit IVs, otherwise GHASH_H(IV padded).
fn gcm_j0(iv: &[u8], h: u128) -> [u8; 16] {
    if iv.len() == 12 {
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(iv);
        j0[15] = 1;
        j0
    } else {
        let mut x: u128 = 0;
        for chunk in iv.chunks(16) {
            let mut blk = [0u8; 16];
            blk[..chunk.len()].copy_from_slice(chunk);
            x = gf_mul(x ^ u128::from_be_bytes(blk), h);
        }
        let mut len_blk = [0u8; 16];
        len_blk[8..].copy_from_slice(&(iv.len() as u64 * 8).to_be_bytes());
        x = gf_mul(x ^ u128::from_be_bytes(len_blk), h);
        x.to_be_bytes()
    }
}

/// AES-GCM encryption: returns (ciphertext, 16-byte tag).
fn gcm_encrypt(block: &AesBlock, iv: &[u8], aad: &[u8], plain: &[u8]) -> (Vec<u8>, [u8; 16]) {
    let mut hb = [0u8; 16];
    block.encrypt_block(&mut hb);
    let h = u128::from_be_bytes(hb);
    let j0 = gcm_j0(iv, h);
    let mut ctr0 = j0;
    inc32(&mut ctr0);
    let mut ct = Vec::with_capacity(plain.len());
    gctr(block, ctr0, plain, &mut ct);
    let s = ghash(h, aad, &ct);
    let mut ek0 = [0u8; 16];
    ek0.copy_from_slice(&j0);
    block.encrypt_block(&mut ek0);
    (ct, (s ^ u128::from_be_bytes(ek0)).to_be_bytes())
}

/// AES-GCM decryption: authenticates ciphertext + tag, then decrypts in place.
fn gcm_decrypt(
    block: &AesBlock,
    iv: &[u8],
    aad: &[u8],
    ct: &[u8],
    tag: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let mut hb = [0u8; 16];
    block.encrypt_block(&mut hb);
    let h = u128::from_be_bytes(hb);
    let s = ghash(h, aad, ct);
    let j0 = gcm_j0(iv, h);
    let mut ek0 = [0u8; 16];
    ek0.copy_from_slice(&j0);
    block.encrypt_block(&mut ek0);
    let t = (s ^ u128::from_be_bytes(ek0)).to_be_bytes();
    let mut diff = 0u8;
    for (a, b) in t.iter().zip(tag.iter()) {
        diff |= a ^ b;
    }
    if diff != 0 {
        anyhow::bail!("{}", i18n::t("err.gcm_auth_failed"));
    }
    let mut ctr0 = j0;
    inc32(&mut ctr0);
    let mut plain = Vec::with_capacity(ct.len());
    gctr(block, ctr0, ct, &mut plain);
    Ok(plain)
}

/// GCM iv: defaults to 12 zero bytes; any non-empty length is accepted.
fn opt_gcm_iv(args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    match args.get("iv") {
        None => Ok(vec![0u8; 12]),
        Some(s) => {
            let v = parse_key(s)?;
            if v.is_empty() {
                anyhow::bail!("{}", i18n::t("err.empty_iv"));
            }
            Ok(v)
        }
    }
}

/// GCM additional authenticated data: hex or UTF-8 bytes, default empty.
fn opt_aad(args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    match args.get("aad") {
        None => Ok(Vec::new()),
        Some(s) => parse_key(s),
    }
}

fn aes_gcm_run(
    input: &[u8],
    args: &HashMap<String, String>,
    encrypt: bool,
) -> anyhow::Result<Vec<u8>> {
    let block = aes_block_from_args(args)?;
    let iv = opt_gcm_iv(args)?;
    let aad = opt_aad(args)?;
    if encrypt {
        let (mut ct, tag) = gcm_encrypt(&block, &iv, &aad, input);
        ct.extend_from_slice(&tag);
        Ok(ct)
    } else {
        let tag_str = args
            .get("tag")
            .ok_or_else(|| anyhow::anyhow!("{}", i18n::t("err.missing_gcm_tag")))?;
        let tag = parse_key(tag_str)?;
        if tag.len() != 16 {
            anyhow::bail!(
                "{}",
                i18n::tf("err.gcm_tag_len", &[tag.len().to_string().as_str()])
            );
        }
        gcm_decrypt(&block, &iv, &aad, input, &tag)
    }
}

// --- Streaming factory for the aes:encrypt / aes:decrypt ops. Block modes
// (ecb/cbc) buffer to full blocks and flush padding at finish; stream modes
// carry their native cross-chunk state.

fn make_aes_enc(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    make_aes(args, true)
}

fn make_aes_dec(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    make_aes(args, false)
}

fn make_aes(args: &HashMap<String, String>, encrypt: bool) -> anyhow::Result<Box<dyn StreamingOp>> {
    let block = aes_block_from_args(args)?;
    match parse_aes_mode(args)? {
        AesMode::Ecb => Ok(Box::new(BufBlockStream::new(args, block, true, encrypt)?)),
        AesMode::Cbc => Ok(Box::new(BufBlockStream::new(args, block, false, encrypt)?)),
        AesMode::Cfb => Ok(Box::new(CfbStream::new(args, block, encrypt)?)),
        AesMode::Ofb => Ok(Box::new(OfbStream::new(args, block)?)),
        AesMode::Ctr => Ok(Box::new(CtrStream::new(args, block)?)),
        AesMode::Gcm => anyhow::bail!("{}", i18n::t("err.gcm_not_streamable")),
    }
}

fn rc4(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
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

fn hmac(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
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
        other => anyhow::bail!("{}", i18n::tf("err.unknown_algo", &[other])),
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

    fn hex(data: impl AsRef<[u8]>) -> String {
        data.as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }

    // ------------------------------------------------------------------
    // PBKDF2 / HKDF (RFC 6070 / RFC 5869 vectors)
    // ------------------------------------------------------------------

    #[test]
    fn pbkdf2_sha1_rfc6070() {
        let a = args(&[
            ("key", "password"),
            ("salt", "salt"),
            ("hash", "sha1"),
            ("iterations", "1"),
            ("length", "20"),
        ]);
        assert_eq!(
            hex(pbkdf2(b"", &a).unwrap()),
            "0c60c80f961f0e71f3a9b524af6012062fe037a6"
        );
        let a = args(&[
            ("key", "password"),
            ("salt", "salt"),
            ("hash", "sha1"),
            ("iterations", "2"),
            ("length", "20"),
        ]);
        assert_eq!(
            hex(pbkdf2(b"", &a).unwrap()),
            "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"
        );
        let a = args(&[
            ("key", "password"),
            ("salt", "salt"),
            ("hash", "sha1"),
            ("iterations", "4096"),
            ("length", "20"),
        ]);
        assert_eq!(
            hex(pbkdf2(b"", &a).unwrap()),
            "4b007901b765489abead49d926f721d065a429c1"
        );
    }

    #[test]
    fn pbkdf2_sha256_vectors() {
        let a = args(&[
            ("key", "password"),
            ("salt", "salt"),
            ("iterations", "1"),
            ("length", "32"),
        ]);
        assert_eq!(
            hex(pbkdf2(b"", &a).unwrap()),
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        );
        let a = args(&[
            ("key", "password"),
            ("salt", "salt"),
            ("iterations", "10000"),
            ("length", "32"),
        ]);
        assert_eq!(
            hex(pbkdf2(b"", &a).unwrap()),
            "5ec02b91a4b59c6f59dd5fbe4ca649ece4fa8568cdb8ba36cf41426e8805522b"
        );
    }

    #[test]
    fn pbkdf2_sha512_uses_input_password() {
        // No 'key' arg: op input is the password.
        let a = args(&[
            ("salt", "salt"),
            ("hash", "sha512"),
            ("iterations", "2"),
            ("length", "64"),
        ]);
        assert_eq!(
            hex(pbkdf2(b"pass", &a).unwrap()),
            "b38deb857ea637081cfe61e4965722c36ee58dc40f53b80e42a4315795c39470480bf86c81e90a4f1c142aabc7273ee0c5a095fbab225ddea60a3d328c15cf03"
        );
    }

    #[test]
    fn pbkdf2_hex_salt() {
        let a = args(&[
            ("key", "password"),
            ("salt", "0x73616c74"),
            ("iterations", "1"),
            ("length", "20"),
            ("hash", "sha1"),
        ]);
        assert_eq!(
            hex(pbkdf2(b"", &a).unwrap()),
            "0c60c80f961f0e71f3a9b524af6012062fe037a6"
        );
    }

    #[test]
    fn pbkdf2_unknown_hash() {
        let a = args(&[("key", "x"), ("hash", "md5")]);
        assert!(pbkdf2(b"", &a).is_err());
    }

    #[test]
    fn hkdf_sha256_rfc5869_tc1() {
        // IKM = 0x0b*22, salt = 0x000102..0c (13 bytes), info = 0xf0..f9, L = 42
        let ikm = format!("0x{}", "0b".repeat(22));
        let salt = format!(
            "0x{}",
            (0..13u8).map(|b| format!("{b:02x}")).collect::<String>()
        );
        let a = args(&[
            ("key", &ikm),
            ("salt", &salt),
            ("info", "0xf0f1f2f3f4f5f6f7f8f9"),
            ("length", "42"),
            ("hash", "sha256"),
        ]);
        assert_eq!(
            hex(hkdf(b"", &a).unwrap()),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn hkdf_sha1_rfc5869_tc4() {
        let ikm = format!("0x{}", "0b".repeat(11));
        let salt = format!(
            "0x{}",
            (0..9u8).map(|b| format!("{b:02x}")).collect::<String>()
        );
        let a = args(&[
            ("key", &ikm),
            ("salt", &salt),
            ("info", "0xf0f1f2f3f4f5f6f7"),
            ("length", "42"),
            ("hash", "sha1"),
        ]);
        assert_eq!(
            hex(hkdf(b"", &a).unwrap()),
            "319e5088afa610a19ba8764fc85abee06cd3afc4e8438d1680e900ae284908095644cdead5f7dd4dc5c7"
        );
    }

    #[test]
    fn hkdf_empty_salt_uses_hashlen_zeros() {
        let a = args(&[
            ("key", "ikm"),
            ("info", "info"),
            ("length", "32"),
            ("hash", "sha256"),
        ]);
        assert_eq!(
            hex(hkdf(b"", &a).unwrap()),
            "253471d1d21137fd9a4016868ba773216954d4cc5ecb925eeacadfd7eeb208c3"
        );
    }

    #[test]
    fn hkdf_uses_input_ikm_when_no_key() {
        let a = args(&[
            ("salt", "salt"),
            ("info", "info"),
            ("length", "32"),
            ("hash", "sha256"),
        ]);
        let out = hkdf(b"ikm", &a).unwrap();
        assert_eq!(out.len(), 32);
    }

    #[test]
    fn hkdf_unknown_hash() {
        let a = args(&[("key", "x"), ("hash", "md5")]);
        assert!(hkdf(b"", &a).is_err());
    }

    #[test]
    fn xor_hex_key() {
        let a = args(&[("key", "0x2A")]);
        // 'H' (0x48) ^ 0x2A = 0x62 = 'b'
        assert_eq!(xor(b"H", &a).unwrap(), b"b");
    }

    #[test]
    fn xor_roundtrip() {
        let a = args(&[("key", "secret")]);
        let data = b"payload data";
        let enc = xor(data, &a).unwrap();
        let dec = xor(&enc, &a).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn parse_key_forms() {
        assert_eq!(parse_key("0x2A").unwrap(), vec![0x2a]);
        assert_eq!(parse_key("0X0102").unwrap(), vec![0x01, 0x02]);
        assert_eq!(parse_key("ab").unwrap(), b"ab");
    }

    #[test]
    fn aes_cbc_roundtrip_known_vector() {
        // NIST SP 800-38A F.2.1：AES-128-CBC，key=2b7e151628aed2a6abf7158809cf4f3c，
        // iv=000102030405060708090a0b0c0d0e0f, plaintext 6bc1bee22e409f96e93d7e117393172a.
        let a = args(&[
            ("key", "0x2b7e151628aed2a6abf7158809cf4f3c"),
            ("mode", "cbc"),
            ("iv", "0x000102030405060708090a0b0c0d0e0f"),
        ]);
        let plain = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
        let enc = aes_encrypt(&plain, &a).unwrap();
        // Single-block plaintext + PKCS#7 padding -> two-block NIST first-block ciphertext
        assert_eq!(hex::encode(&enc[..16]), "7649abac8119b246cee98e9b12e9197d");
        let dec = aes_decrypt(&enc, &a).unwrap();
        assert_eq!(dec, plain);
    }

    #[test]
    fn aes_ecb_roundtrip() {
        let a = args(&[("key", "0123456789abcdef0123456789abcdef"), ("mode", "ecb")]);
        let data = b"block aligned data!!";
        let enc = aes_encrypt(data, &a).unwrap();
        let dec = aes_decrypt(&enc, &a).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn aes_default_mode_is_cbc_and_iv_is_zero() {
        // Same key but no mode/iv: must behave as cbc with all-zero IV.
        let a = args(&[("key", "0123456789abcdef0123456789abcdef")]);
        let b = args(&[
            ("key", "0123456789abcdef0123456789abcdef"),
            ("mode", "cbc"),
            ("iv", "0x00000000000000000000000000000000"),
        ]);
        let data = b"default-args payload";
        assert_eq!(
            aes_encrypt(data, &a).unwrap(),
            aes_encrypt(data, &b).unwrap()
        );
        let enc = aes_encrypt(data, &a).unwrap();
        assert_eq!(aes_decrypt(&enc, &a).unwrap(), data);
    }

    #[test]
    fn aes_rejects_bad_key_len_and_unknown_mode() {
        let a = args(&[("key", "short"), ("mode", "cbc")]);
        assert!(aes_encrypt(b"data", &a).is_err());
        let b = args(&[("key", "0123456789abcdef0123456789abcdef"), ("mode", "xts")]);
        assert!(aes_encrypt(b"data", &b).is_err());
    }

    #[test]
    fn aes_cfb_known_vector() {
        // Standard CFB-128: NIST SP 800-38A F.3.7 block 1 + OpenSSL 3.x
        // cross-check for all 4 blocks (review fix 3.1: multi-block feedback
        // must match CFB-128, not a byte-wise sliding window).
        let a = args(&[
            ("key", "0x2b7e151628aed2a6abf7158809cf4f3c"),
            ("mode", "cfb"),
            ("iv", "0x000102030405060708090a0b0c0d0e0f"),
        ]);
        let plain = hex::decode("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710").unwrap();
        let expect = hex::decode("3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6").unwrap();
        let enc = aes_encrypt(&plain, &a).unwrap();
        assert_eq!(enc, expect);
        assert_eq!(aes_decrypt(&enc, &a).unwrap(), plain);
        // Partial tail (non-block-aligned input) must also match block-aligned output.
        let tail = &plain[..20];
        let enc_tail = aes_encrypt(tail, &a).unwrap();
        assert_eq!(enc_tail, expect[..20]);
        assert_eq!(aes_decrypt(&enc_tail, &a).unwrap(), tail);
        // Streaming path must agree with the in-memory path for multi-block data.
        let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let mem = aes_encrypt(&data, &a).unwrap();
        let mut s = CfbStream::new(&a, aes_block_from_args(&a).unwrap(), true).unwrap();
        let mut st = Vec::new();
        for c in data.chunks(3) {
            st.extend(s.write(c).unwrap());
        }
        st.extend(s.finish().unwrap());
        assert_eq!(st, mem);
    }

    #[test]
    fn aes_ofb_known_vector() {
        // NIST SP 800-38A F.4.1 (OFB-AES128): same first block as CFB128.
        let a = args(&[
            ("key", "0x2b7e151628aed2a6abf7158809cf4f3c"),
            ("mode", "ofb"),
            ("iv", "0x000102030405060708090a0b0c0d0e0f"),
        ]);
        let plain = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
        let enc = aes_encrypt(&plain, &a).unwrap();
        assert_eq!(hex::encode(&enc[..16]), "3b3fd92eb72dad20333449f8e83cfb4a");
        assert_eq!(aes_decrypt(&enc, &a).unwrap(), plain);
    }

    #[test]
    fn aes_ctr_known_vector_and_roundtrip() {
        // NIST SP 800-38A F.5.1: AES-128-CTR.
        let a = args(&[
            ("key", "0x2b7e151628aed2a6abf7158809cf4f3c"),
            ("mode", "ctr"),
            ("iv", "0xf0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
        ]);
        let plain = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
        let enc = aes_encrypt(&plain, &a).unwrap();
        assert_eq!(hex::encode(&enc[..16]), "874d6191b620e3261bef6864990db6ce");
        let dec = aes_decrypt(&enc, &a).unwrap();
        assert_eq!(dec, plain);
    }

    #[test]
    fn aes_stream_matches_memory_all_modes() {
        let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let cases = [
            (
                "ecb",
                args(&[("key", "0123456789abcdef0123456789abcdef"), ("mode", "ecb")]),
            ),
            (
                "cbc",
                args(&[
                    ("key", "0123456789abcdef0123456789abcdef"),
                    ("mode", "cbc"),
                    ("iv", "0xf0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
                ]),
            ),
            (
                "cfb",
                args(&[
                    ("key", "0123456789abcdef0123456789abcdef"),
                    ("mode", "cfb"),
                    ("iv", "0xf0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
                ]),
            ),
            (
                "ofb",
                args(&[
                    ("key", "0123456789abcdef0123456789abcdef"),
                    ("mode", "ofb"),
                    ("iv", "0xf0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
                ]),
            ),
            (
                "ctr",
                args(&[
                    ("key", "0123456789abcdef0123456789abcdef"),
                    ("mode", "ctr"),
                    ("iv", "0xf0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
                ]),
            ),
        ];
        for (mode, a) in cases {
            let run = if mode == "ecb" || mode == "cbc" {
                let enc = aes_encrypt(&data, &a).unwrap();
                let dec = aes_decrypt(&enc, &a).unwrap();
                assert_eq!(dec, data, "roundtrip failed for mode {}", mode);
                enc
            } else {
                aes_encrypt(&data, &a).unwrap()
            };
            let mut h = make_aes_enc(&a).unwrap();
            let mut acc = Vec::new();
            for c in data.chunks(7) {
                acc.extend(h.write(c).unwrap());
            }
            acc.extend(h.finish().unwrap());
            assert_eq!(acc, run, "stream != memory for mode {}", mode);
            // decrypt stream
            let mut hd = make_aes_dec(&a).unwrap();
            let mut acc2 = Vec::new();
            for c in run.chunks(9) {
                acc2.extend(hd.write(c).unwrap());
            }
            acc2.extend(hd.finish().unwrap());
            assert_eq!(acc2, data, "decrypt stream != plaintext for mode {}", mode);
        }
    }

    #[test]
    fn rc4_known_vector() {
        // RFC 6229: key="Key", plaintext "Plaintext" (9B) outputs bbf316e8d940af0ad3
        let a = args(&[("key", "Key")]);
        let enc = rc4(b"Plaintext", &a).unwrap();
        assert_eq!(hex::encode(enc), "bbf316e8d940af0ad3");
    }

    #[test]
    fn hmac_known_vector() {
        let a = args(&[("key", "key"), ("algo", "sha256")]);
        let out = hmac(b"The quick brown fox jumps over the lazy dog", &a).unwrap();
        assert_eq!(
            hex::encode(out),
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
    }

    #[test]
    fn chacha20_known_keystream_and_roundtrip() {
        // RFC 8439 §2.3.2: key=000102...1f, nonce=000000000000004a00000000, counter=1.
        let a = args(&[
            (
                "key",
                "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            ),
            ("nonce", "0x000000000000004a00000000"),
        ]);
        let mut chacha = chacha20_from_args(&a).unwrap();
        let mut ks = [0u8; 64];
        chacha.next_block(&mut ks); // block 0 (counter=0)
        chacha.next_block(&mut ks); // block 1 (counter=1) -> RFC 8439 2.3.2 vector
        assert_eq!(hex::encode(&ks[..16]), "224f51f3401bd9e12fde276fb8631ded");
        let plain = b"ChaCha20 round trip works over any bytes";
        let enc = chacha20_crypt(plain, &a).unwrap();
        assert_eq!(chacha20_crypt(&enc, &a).unwrap(), plain);
    }

    #[test]
    fn stream_ciphers_stream_matches_memory() {
        let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let a = args(&[
            (
                "key",
                "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            ),
            ("nonce", "0x000000000000004a00000000"),
        ]);
        let mut h = make_chacha20(&a).unwrap();
        let mut acc = Vec::new();
        for c in data.chunks(5) {
            acc.extend(h.write(c).unwrap());
        }
        acc.extend(h.finish().unwrap());
        assert_eq!(acc, chacha20_crypt(&data, &a).unwrap());

        let b = args(&[
            ("key", "0123456789abcdef"),
            ("iv", "0xf0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
            ("mode", "ctr"),
        ]);
        let mut h2 = make_aes_enc(&b).unwrap();
        let mut acc2 = Vec::new();
        for c in data.chunks(9) {
            acc2.extend(h2.write(c).unwrap());
        }
        acc2.extend(h2.finish().unwrap());
        assert_eq!(
            acc2,
            ctr_crypt(&data, &b, aes_block_from_args(&b).unwrap()).unwrap()
        );
    }

    #[test]
    fn xor_bruteforce_finds_known_key() {
        let plain = b"Hello, world! This is a known plaintext for XOR testing.";
        let cipher: Vec<u8> = plain.iter().map(|b| b ^ 0x2a).collect();
        let out = xor_bruteforce(&cipher, &HashMap::new()).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.starts_with("0x2a: "), "got: {}", s);
        assert!(s.contains("Hello, world!"), "got: {}", s);
        assert_eq!(s.lines().count(), 5); // default top=5
    }

    #[test]
    fn xor_bruteforce_top_limits_output() {
        let cipher: Vec<u8> = b"abc".iter().map(|b| b ^ 0x01).collect();
        let out = xor_bruteforce(&cipher, &args(&[("top", "2")])).unwrap();
        assert_eq!(String::from_utf8(out).unwrap().lines().count(), 2);
        assert!(xor_bruteforce(&cipher, &args(&[("top", "0")])).is_err());
    }

    #[test]
    fn xor_input_delimited_memory() {
        // "foo" token uses key 0x01, "bar" token uses key 0x02; space passes through.
        let out = xor(
            b"foo bar",
            &args(&[("key", "0x01 0x02"), ("scheme", "input-delimited")]),
        )
        .unwrap();
        assert_eq!(out, b"gnn `cp");
        // key list cycles when input has more tokens than keys.
        let out2 = xor(
            b"foo bar baz",
            &args(&[("key", "0x01 0x02"), ("scheme", "input_delimited")]),
        )
        .unwrap();
        // "baz" cycles back to key 0x01: b->c, a->`, z->{
        assert_eq!(out2, b"gnn `cp c`{");
    }

    #[test]
    fn xor_input_delimited_streaming_matches_memory() {
        let a = args(&[("key", "0x01 0x02"), ("scheme", "input-delimited")]);
        let mut st = make_xor(&a).unwrap();
        let mut acc = Vec::new();
        for chunk in [&b"fo"[..], b"o b", b"ar", b" qux"] {
            acc.extend_from_slice(&st.write(chunk).unwrap());
        }
        acc.extend_from_slice(&st.finish().unwrap());
        assert_eq!(acc, xor(b"foo bar qux", &a).unwrap());
    }

    #[test]
    fn xor_scheme_rejects_unknown() {
        assert!(xor(b"abc", &args(&[("key", "0x01"), ("scheme", "bogus")])).is_err());
        assert!(make_xor(&args(&[("key", "0x01"), ("scheme", "bogus")])).is_err());
    }

    #[test]
    fn xor_bruteforce_sample_filters_to_known_key() {
        let plain = b"Hello, world! This is a known plaintext for XOR testing.";
        let cipher: Vec<u8> = plain.iter().map(|b| b ^ 0x2a).collect();
        let out = xor_bruteforce(&cipher, &args(&[("sample", "Hello")])).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert_eq!(s.lines().count(), 1, "got: {}", s);
        assert!(s.starts_with("0x2a: "), "got: {}", s);
        assert!(s.contains("Hello, world!"), "got: {}", s);
    }

    #[test]
    fn xor_bruteforce_double_byte_key_with_sample() {
        let plain = b"attack at dawn (double-byte key test)";
        let key = [0x12u8, 0x34];
        let cipher: Vec<u8> = plain
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % key.len()])
            .collect();
        let out =
            xor_bruteforce(&cipher, &args(&[("key_length", "2"), ("sample", "attack")])).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.starts_with("0x1234: "), "got: {}", s);
        assert!(s.contains("attack at dawn"), "got: {}", s);
    }

    #[test]
    fn xor_bruteforce_rejects_bad_key_length() {
        let cipher: Vec<u8> = b"abc".iter().map(|b| b ^ 0x01).collect();
        assert!(xor_bruteforce(&cipher, &args(&[("key_length", "3")])).is_err());
        assert!(xor_bruteforce(&cipher, &args(&[("key_length", "0")])).is_err());
    }

    #[test]
    fn xor_differential_schemes_memory() {
        // Input differential: key byte is replaced by each input byte.
        let out = xor(
            b"ABC",
            &args(&[("key", "0x01"), ("scheme", "input-differential")]),
        )
        .unwrap();
        assert_eq!(out, b"@\x03\x01");
        // Output differential: key byte is replaced by each output byte.
        let out2 = xor(
            b"ABC",
            &args(&[("key", "0x01"), ("scheme", "output-differential")]),
        )
        .unwrap();
        assert_eq!(out2, b"@\x02A");
    }

    #[test]
    fn xor_differential_streaming_matches_memory() {
        for scheme in ["input-differential", "output-differential"] {
            let a = args(&[("key", "0x0102"), ("scheme", scheme)]);
            let mem = xor(b"the quick brown fox", &a).unwrap();
            let mut st = make_xor(&a).unwrap();
            let mut acc = Vec::new();
            for chunk in [&b"the q"[..], b"uick ", b"brown ", b"fox"] {
                acc.extend_from_slice(&st.write(chunk).unwrap());
            }
            acc.extend_from_slice(&st.finish().unwrap());
            assert_eq!(acc, mem, "scheme={}", scheme);
        }
    }

    #[test]
    fn xor_cascade_memory_and_streaming() {
        let a = args(&[("key", "0x01"), ("scheme", "cascade")]);
        let mem = xor(b"\x01\x02\x03", &a).unwrap();
        assert_eq!(mem, b"\x03\x01\x03");
        let mut st = make_xor(&a).unwrap();
        let mut acc = Vec::new();
        for chunk in [&b"\x01\x02"[..], b"\x03"] {
            acc.extend_from_slice(&st.write(chunk).unwrap());
        }
        acc.extend_from_slice(&st.finish().unwrap());
        assert_eq!(acc, mem);
    }

    #[test]
    fn xor_null_preserving_standard() {
        let out = xor(
            b"\x00\x01A",
            &args(&[("key", "0x01"), ("null_preserving", "true")]),
        )
        .unwrap();
        assert_eq!(out, b"\x00\x01@");
    }

    #[test]
    fn xor_bruteforce_differential_with_sample() {
        // Input-differential "encryption" is inverted by output-differential
        // decoding (the key byte is fed back from the decoded output).
        let plain = b"Known plaintext under input-differential XOR.";
        let a = args(&[("key", "0x05"), ("scheme", "input-differential")]);
        let cipher = xor(plain, &a).unwrap();
        let out = xor_bruteforce(
            &cipher,
            &args(&[("sample", "Known"), ("scheme", "output-differential")]),
        )
        .unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.starts_with("0x05: "), "got: {}", s);
        assert!(s.contains("Known plaintext"), "got: {}", s);
        // And the mirror direction: output-differential ciphertext is
        // recovered with input-differential decoding.
        let a2 = args(&[("key", "0x07"), ("scheme", "output-differential")]);
        let cipher2 = xor(plain, &a2).unwrap();
        let out2 = xor_bruteforce(
            &cipher2,
            &args(&[("sample", "Known"), ("scheme", "input-differential")]),
        )
        .unwrap();
        let s2 = String::from_utf8(out2).unwrap();
        assert!(s2.starts_with("0x07: "), "got: {}", s2);
        assert!(s2.contains("Known plaintext"), "got: {}", s2);
    }

    #[test]
    fn xor_bruteforce_sample_offset_and_print_options() {
        let plain = b"prefix data of interest here";
        let key = 0x11u8;
        let mut cipher = b"junkjunkjunk".to_vec();
        cipher.extend(plain.iter().map(|b| b ^ key));
        // sample_offset skips the junk prefix; known plaintext matches at offset.
        let out = xor_bruteforce(
            &cipher,
            &args(&[
                ("sample", "prefix"),
                ("sample_offset", "12"),
                ("print_key", "false"),
            ]),
        )
        .unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(!s.starts_with("0x"), "got: {}", s);
        assert!(s.contains("prefix data"), "got: {}", s);
        // hex_output renders candidates as hex.
        let out2 = xor_bruteforce(
            &cipher,
            &args(&[
                ("sample", "prefix"),
                ("sample_offset", "12"),
                ("hex_output", "true"),
            ]),
        )
        .unwrap();
        let s2 = String::from_utf8(out2).unwrap();
        assert!(
            s2.starts_with("0x11: 707265666978206461746120"),
            "got: {}",
            s2
        );
    }

    #[test]
    fn xor_bruteforce_rejects_delimited_and_cascade_schemes() {
        let cipher: Vec<u8> = b"abc".iter().map(|b| b ^ 0x01).collect();
        assert!(xor_bruteforce(&cipher, &args(&[("scheme", "cascade")])).is_err());
        assert!(xor_bruteforce(&cipher, &args(&[("scheme", "input-delimited")])).is_err());
    }

    #[test]
    fn xor_bruteforce_rejects_bad_booleans_and_offset() {
        let cipher: Vec<u8> = b"abc".iter().map(|b| b ^ 0x01).collect();
        assert!(xor_bruteforce(&cipher, &args(&[("print_key", "maybe")])).is_err());
        assert!(xor_bruteforce(&cipher, &args(&[("sample_offset", "abc")])).is_err());
    }

    #[test]
    fn des3_known_vector_ecb() {
        // 3DES-EDE with K1=K2=K3=0123456789ABCDEF reduces to single DES,
        // so the FIPS 81 vector "Now is t" -> 3FA40E8A984D4815 applies.
        // PKCS#7 pads the 8-byte input to 16 bytes; first block matches.
        let key = "0x0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
        let a = args(&[("key", key), ("mode", "ecb")]);
        let enc = des3_encrypt(b"Now is t", &a).unwrap();
        assert_eq!(enc.len(), 16);
        assert_eq!(&enc[..8], hex::decode("3FA40E8A984D4815").unwrap());
        assert_eq!(des3_decrypt(&enc, &a).unwrap(), b"Now is t");
        assert!(des3_encrypt(b"x", &args(&[("key", "0x00"), ("mode", "ecb")])).is_err());
    }

    #[test]
    fn des3_cbc_roundtrip() {
        let a = args(&[("key", "0x0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")]);
        let enc = des3_encrypt(b"attack at dawn", &a).unwrap();
        assert!(enc.len() % 8 == 0);
        assert_eq!(des3_decrypt(&enc, &a).unwrap(), b"attack at dawn");
    }

    #[test]
    fn blowfish_known_vector_ecb() {
        // Classic Blowfish vector: all-zero key, all-zero plaintext block.
        // PKCS#7 pads to 16 bytes; first block matches the known vector.
        let a = args(&[("key", "0x0000000000000000"), ("mode", "ecb")]);
        let enc = blowfish_encrypt(b"\0\0\0\0\0\0\0\0", &a).unwrap();
        assert_eq!(enc.len(), 16);
        assert_eq!(&enc[..8], hex::decode("4EF997456198DD78").unwrap());
        assert_eq!(blowfish_decrypt(&enc, &a).unwrap(), b"\0\0\0\0\0\0\0\0");
    }

    #[test]
    fn blowfish_cbc_roundtrip() {
        let a = args(&[("key", "my blowfish key")]);
        let enc = blowfish_encrypt(b"hello blowfish world", &a).unwrap();
        assert_eq!(blowfish_decrypt(&enc, &a).unwrap(), b"hello blowfish world");
    }

    #[test]
    fn tea_known_vector() {
        let a = args(&[("key", "0x00000000000000000000000000000000")]);
        let enc = tea_encode(b"\0\0\0\0\0\0\0\0", &a).unwrap();
        assert_eq!(enc, hex::decode("41EA3A0A94BAA940").unwrap());
        assert_eq!(tea_decode(&enc, &a).unwrap(), b"\0\0\0\0\0\0\0\0");
        assert!(tea_encode(b"x", &args(&[("key", "short")])).is_err());
    }

    #[test]
    fn xtea_known_vector() {
        let a = args(&[("key", "0x00000000000000000000000000000000")]);
        let enc = xtea_encode(b"\0\0\0\0\0\0\0\0", &a).unwrap();
        assert_eq!(enc, hex::decode("DEE9D4D8F7131ED9").unwrap());
        assert_eq!(xtea_decode(&enc, &a).unwrap(), b"\0\0\0\0\0\0\0\0");
    }

    #[test]
    fn tea_family_padding_and_roundtrip() {
        let a = args(&[("key", "0x000102030405060708090a0b0c0d0e0f")]);
        for plain in [
            b"".as_slice(),
            b"a",
            b"hello tea!",
            b"0123456789abcdef01234567",
        ] {
            let e = tea_encode(plain, &a).unwrap();
            assert_eq!(tea_decode(&e, &a).unwrap(), plain);
            let xe = xtea_encode(plain, &a).unwrap();
            assert_eq!(xtea_decode(&xe, &a).unwrap(), plain);
            let xx = xxtea_encode(plain, &a).unwrap();
            assert_eq!(xxtea_decode(&xx, &a).unwrap(), plain);
        }
    }

    #[test]
    fn xxtea_known_short_vector() {
        // 8-byte input, two words: deterministic, decode must invert.
        let a = args(&[("key", "0x000102030405060708090a0b0c0d0e0f")]);
        let enc = xxtea_encode(b"12345678", &a).unwrap();
        assert_eq!(enc.len(), 8);
        assert_eq!(xxtea_decode(&enc, &a).unwrap(), b"12345678");
    }

    #[test]
    fn aes_gcm_nist_vectors() {
        // NIST SP 800-38D Appendix B (AES-128-GCM), values cross-checked
        // against OpenSSL. encrypt output is ct||tag.
        // TC1: empty plaintext, empty AAD, zero 12-byte IV.
        let tc1 = args(&[
            ("key", "0x00000000000000000000000000000000"),
            ("mode", "gcm"),
            ("iv", "0x000000000000000000000000"),
        ]);
        let out = aes_encrypt(b"", &tc1).unwrap();
        assert_eq!(hex::encode(out), "58e2fccefa7e3061367f1d57a4e7455a");

        // TC2: 16-byte zero plaintext, empty AAD -> ct||tag.
        let tc2 = args(&[
            ("key", "0x00000000000000000000000000000000"),
            ("mode", "gcm"),
            ("iv", "0x000000000000000000000000"),
        ]);
        let out = aes_encrypt(&[0u8; 16], &tc2).unwrap();
        assert_eq!(
            hex::encode(out),
            "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf"
        );

        // Extra: empty plaintext + 64-byte AAD exercises a long GHASH chain
        // (value recomputed independently via OpenSSL, not an official NIST case).
        let tc3 = args(&[
            ("key", "0xfeffe9928665731c6d6a8f9467308308"),
            ("mode", "gcm"),
            ("iv", "0xcafebabefacedbaddecaf888"),
            (
                "aad",
                "0x03522522523a7835f915bdf0781d64d2e0fd50a52f26b9de809e9a1dccbf1eec7d42f1fd5eb9e3bcc9a4246b07125d19c714e0a5afce4de475f01e5fa25d6b9f",
            ),
        ]);
        let out = aes_encrypt(b"", &tc3).unwrap();
        assert_eq!(hex::encode(out), "748581dd629f74038d5ff80323860829");

        // TC4: 64-byte plaintext, empty AAD.
        let tc4 = args(&[
            ("key", "0xfeffe9928665731c6d6a8f9467308308"),
            ("mode", "gcm"),
            ("iv", "0xcafebabefacedbaddecaf888"),
        ]);
        let plain64 = hex::decode(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        )
        .unwrap();
        let out = aes_encrypt(&plain64, &tc4).unwrap();
        assert_eq!(
            hex::encode(out),
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
             21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985\
             4d5c2af327cd64a62cf35abd2ba6fab4"
        );

        // TC5: 60-byte plaintext plus AAD.
        let tc5 = args(&[
            ("key", "0xfeffe9928665731c6d6a8f9467308308"),
            ("mode", "gcm"),
            ("iv", "0xcafebabefacedbaddecaf888"),
            ("aad", "0xfeedfacedeadbeeffeedfacedeadbeefabaddad2"),
        ]);
        let plain60 = hex::decode(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        )
        .unwrap();
        let out = aes_encrypt(&plain60, &tc5).unwrap();
        assert_eq!(
            hex::encode(out),
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
             21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091\
             5bc94fbc3221a5db94fae95ae7121a47"
        );
    }

    #[test]
    fn aes_gcm_roundtrip_and_errors() {
        // roundtrip: encrypt emits ct||tag; decrypt takes ct body + tag param.
        let a = args(&[
            ("key", "0xfeffe9928665731c6d6a8f9467308308"),
            ("mode", "gcm"),
            ("iv", "0xcafebabefacedbaddecaf888"),
            ("aad", "0xfeedfacedeadbeeffeedfacedeadbeefabaddad2"),
        ]);
        let plain = b"authenticated payload with padding-free GCM";
        let enc = aes_encrypt(plain, &a).unwrap();
        assert_eq!(enc.len(), plain.len() + 16);
        let (ct, tag) = enc.split_at(enc.len() - 16);
        let dec = aes_decrypt(
            ct,
            &args(&[
                ("key", "0xfeffe9928665731c6d6a8f9467308308"),
                ("mode", "gcm"),
                ("iv", "0xcafebabefacedbaddecaf888"),
                ("aad", "0xfeedfacedeadbeeffeedfacedeadbeefabaddad2"),
                ("tag", &format!("0x{}", hex::encode(tag))),
            ]),
        )
        .unwrap();
        assert_eq!(dec, plain);

        // wrong tag must fail authentication
        let mut bad = tag.to_vec();
        bad[0] ^= 1;
        let err_args = args(&[
            ("key", "0xfeffe9928665731c6d6a8f9467308308"),
            ("mode", "gcm"),
            ("iv", "0xcafebabefacedbaddecaf888"),
            ("aad", "0xfeedfacedeadbeeffeedfacedeadbeefabaddad2"),
            ("tag", &format!("0x{}", hex::encode(bad))),
        ]);
        assert!(aes_decrypt(ct, &err_args).is_err());

        // missing tag / wrong tag length must fail
        assert!(
            aes_decrypt(
                ct,
                &args(&[
                    ("key", "0xfeffe9928665731c6d6a8f9467308308"),
                    ("mode", "gcm"),
                    ("iv", "0xcafebabefacedbaddecaf888"),
                ])
            )
            .is_err()
        );
        assert!(
            aes_decrypt(
                ct,
                &args(&[
                    ("key", "0xfeffe9928665731c6d6a8f9467308308"),
                    ("mode", "gcm"),
                    ("iv", "0xcafebabefacedbaddecaf888"),
                    ("tag", "0x00ff"),
                ])
            )
            .is_err()
        );

        // gcm is memory-only: the streaming factory must reject it.
        assert!(make_aes_enc(&a).is_err());
        assert!(make_aes_dec(&a).is_err());
    }
}

// ---------------------------------------------------------------------------
// XOR brute force (single-byte key)
// ---------------------------------------------------------------------------

/// Decode `data` with a candidate key under one of the brute-force schemes.
fn xor_decode_with(key: &[u8], data: &[u8], scheme: XorScheme, null_preserving: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let skip = |o: u8, k: u8| null_preserving && (o == 0 || o == k);
    match scheme {
        XorScheme::Standard => {
            for (i, &o) in data.iter().enumerate() {
                let k = key[i % key.len()];
                out.push(if skip(o, k) { o } else { o ^ k });
            }
        }
        XorScheme::InputDifferential => {
            let mut kk = key.to_vec();
            for (i, &o) in data.iter().enumerate() {
                let k = kk[i % kk.len()];
                let x = if skip(o, k) { o } else { o ^ k };
                out.push(x);
                if !skip(o, k) {
                    let idx = i % kk.len();
                    kk[idx] = o;
                }
            }
        }
        XorScheme::OutputDifferential => {
            let mut kk = key.to_vec();
            for (i, &o) in data.iter().enumerate() {
                let k = kk[i % kk.len()];
                let x = if skip(o, k) { o } else { o ^ k };
                out.push(x);
                if !skip(o, k) {
                    let idx = i % kk.len();
                    kk[idx] = x;
                }
            }
        }
        XorScheme::InputDelimited | XorScheme::Cascade => unreachable!(),
    }
    out
}

fn parse_bool_arg(
    args: &HashMap<String, String>,
    name: &str,
    default: &str,
) -> anyhow::Result<bool> {
    match opt_arg(args, name, default) {
        "false" | "0" => Ok(false),
        "true" | "1" => Ok(true),
        other => anyhow::bail!("{}", i18n::tf("err.bool_invalid", &[other])),
    }
}

fn xor_bruteforce(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    use crate::ops::analyze::{parse_top, score_text};
    let top = parse_top(args)?;
    let key_len = match opt_arg(args, "key_length", "1") {
        "1" => 1usize,
        "2" => 2usize,
        other => anyhow::bail!("{}", i18n::tf("err.xor.key_length", &[other])),
    };
    let scheme = parse_xor_scheme(args)?;
    if matches!(scheme, XorScheme::InputDelimited | XorScheme::Cascade) {
        anyhow::bail!("{}", i18n::t("err.xor.bruteforce_scheme"));
    }
    let null_preserving = parse_null_preserving(args)?;
    let print_key = parse_bool_arg(args, "print_key", "true")?;
    let hex_output = parse_bool_arg(args, "hex_output", "false")?;
    let sample_offset = match opt_arg(args, "sample_offset", "0").parse::<usize>() {
        Ok(v) => v,
        Err(_) => anyhow::bail!("{}", i18n::t("err.int_invalid")),
    };
    let sample: Option<Vec<u8>> = match args.get("sample") {
        Some(s) if !s.trim().is_empty() => Some(parse_key(s)?),
        _ => None,
    };
    if input.is_empty() || sample_offset >= input.len() {
        return Ok(Vec::new());
    }
    let body = &input[sample_offset..];
    // Candidate keys: all single bytes, or all 16-bit words when key_length=2.
    let keys: Vec<Vec<u8>> = if key_len == 1 {
        (0..=255u8).map(|k| vec![k]).collect()
    } else {
        (0..=65535u16)
            .map(|k| vec![(k >> 8) as u8, (k & 0xff) as u8])
            .collect()
    };
    // Score on a bounded window after the sample offset for speed.
    let window_len = body.len().min(256);
    let window = &body[..window_len];
    let mut cands: Vec<(f64, Vec<u8>)> = Vec::new();
    for key in keys {
        if let Some(sample) = &sample {
            if window_len < sample.len() {
                continue;
            }
            let dec = xor_decode_with(&key, window, scheme, null_preserving);
            let hit = dec.iter().zip(sample.iter()).all(|(&c, &s)| c == s);
            if !hit {
                continue;
            }
        }
        let dec = xor_decode_with(&key, window, scheme, null_preserving);
        cands.push((score_text(&dec), key));
    }
    cands.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    let mut out = Vec::new();
    for (_, key) in cands.into_iter().take(top) {
        let dec = xor_decode_with(&key, body, scheme, null_preserving);
        let hexkey = if key.len() == 1 {
            format!("0x{:02x}", key[0])
        } else {
            format!("0x{:04x}", ((key[0] as u16) << 8) | key[1] as u16)
        };
        if print_key {
            out.extend_from_slice(hexkey.as_bytes());
            out.extend_from_slice(b": ");
        }
        if hex_output {
            for b in &dec {
                out.extend_from_slice(format!("{:02x}", b).as_bytes());
            }
        } else {
            out.extend_from_slice(String::from_utf8_lossy(&dec).as_bytes());
        }
        out.push(b'\n');
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// legacy block ciphers (3DES / Blowfish) and TEA family
// ---------------------------------------------------------------------------

/// Mode for legacy 8-byte block ciphers (3DES / Blowfish): ecb/cbc/cfb/ofb/ctr.
#[derive(Clone, Copy, PartialEq)]
enum LegacyMode {
    Ecb,
    Cbc,
    Cfb,
    Ofb,
    Ctr,
}

fn parse_legacy_mode(args: &HashMap<String, String>) -> anyhow::Result<LegacyMode> {
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

fn des3_encrypt(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    des3_run(input, args, true)
}

fn des3_decrypt(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    des3_run(input, args, false)
}

fn des3_from_args(args: &HashMap<String, String>) -> anyhow::Result<TdesEde3> {
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

fn des3_run(
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
fn des3_block_crypt(
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

fn blowfish_encrypt(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    blowfish_run(input, args, true)
}

fn blowfish_decrypt(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    blowfish_run(input, args, false)
}

fn blowfish_from_args(args: &HashMap<String, String>) -> anyhow::Result<Blowfish<BE>> {
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

fn blowfish_run(
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
fn blowfish_block_crypt(
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

fn make_des3_enc(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    make_des3(args, true)
}

fn make_des3_dec(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    make_des3(args, false)
}

fn make_des3(
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

fn make_blowfish_enc(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    make_blowfish(args, true)
}

fn make_blowfish_dec(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    make_blowfish(args, false)
}

fn make_blowfish(
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

// ---------------------------------------------------------------------------
// TEA family: 64-bit blocks, big-endian words, zero padding to 8 bytes.
// ---------------------------------------------------------------------------

const TEA_DELTA: u32 = 0x9E37_79B9;

fn tea_key(args: &HashMap<String, String>) -> anyhow::Result<[u32; 4]> {
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

fn pad_to_8(input: &[u8]) -> Vec<u8> {
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
fn unpad_zero(mut v: Vec<u8>) -> Vec<u8> {
    while v.last() == Some(&0) {
        v.pop();
    }
    if v.is_empty() {
        v.resize(8, 0);
    }
    v
}

fn tea_encode_block(v: &mut [u32; 2], k: &[u32; 4]) {
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

fn tea_decode_block(v: &mut [u32; 2], k: &[u32; 4]) {
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

fn tea_run(input: &[u8], args: &HashMap<String, String>, encode: bool) -> anyhow::Result<Vec<u8>> {
    let k = tea_key(args)?;
    if input.is_empty() {
        return Ok(Vec::new());
    }
    let data = pad_to_8(input);
    let mut out = Vec::with_capacity(data.len());
    for blk in data.chunks_exact(8) {
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
    if encode { Ok(out) } else { Ok(unpad_zero(out)) }
}

fn tea_encode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    tea_run(input, args, true)
}

fn tea_decode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    tea_run(input, args, false)
}

fn xtea_encode_block(v: &mut [u32; 2], k: &[u32; 4]) {
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

fn xtea_decode_block(v: &mut [u32; 2], k: &[u32; 4]) {
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

fn xtea_run(input: &[u8], args: &HashMap<String, String>, encode: bool) -> anyhow::Result<Vec<u8>> {
    let k = tea_key(args)?;
    if input.is_empty() {
        return Ok(Vec::new());
    }
    let data = pad_to_8(input);
    let mut out = Vec::with_capacity(data.len());
    for blk in data.chunks_exact(8) {
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
    if encode { Ok(out) } else { Ok(unpad_zero(out)) }
}

fn xtea_encode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    xtea_run(input, args, true)
}

fn xtea_decode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    xtea_run(input, args, false)
}

fn xxtea_encrypt_block(v: &mut [u32], k: &[u32; 4]) {
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

fn xxtea_decrypt_block(v: &mut [u32], k: &[u32; 4]) {
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

fn xxtea_run(
    input: &[u8],
    args: &HashMap<String, String>,
    encode: bool,
) -> anyhow::Result<Vec<u8>> {
    let k = tea_key(args)?;
    if input.is_empty() {
        return Ok(Vec::new());
    }
    let data = pad_to_8(input);
    let mut v: Vec<u32> = data
        .chunks_exact(4)
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
    if encode { Ok(out) } else { Ok(unpad_zero(out)) }
}

fn xxtea_encode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    xxtea_run(input, args, true)
}

fn xxtea_decode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    xxtea_run(input, args, false)
}

// ---------------------------------------------------------------------------
// key derivation (PBKDF2 / HKDF, RFC 2898 / RFC 5869)
// ---------------------------------------------------------------------------

/// One-shot HMAC over `data` with `key` (SHA-1 / SHA-256 / SHA-512).
fn hmac_bytes(hash: &str, key: &[u8], data: &[u8]) -> anyhow::Result<Vec<u8>> {
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
        other => anyhow::bail!(
            "{}",
            i18n::tf(
                "err.unknown_hash_variant",
                &[other, "sha1 / sha256 / sha512"]
            )
        ),
    }
}

fn parse_derivation_args(args: &HashMap<String, String>) -> anyhow::Result<(Vec<u8>, String)> {
    let key = match args.get("key") {
        None => Vec::new(),
        Some(s) => parse_key(s)?,
    };
    let hash = opt_arg(args, "hash", "sha256").to_string();
    Ok((key, hash))
}

fn parse_u64_arg(args: &HashMap<String, String>, name: &str, default: u64) -> anyhow::Result<u64> {
    match args.get(name) {
        None => Ok(default),
        Some(s) => s
            .trim()
            .parse::<u64>()
            .map_err(|_| anyhow::anyhow!("{}", i18n::tf("err.invalid_number", &[s.as_str()]))),
    }
}

fn pbkdf2(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
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
    let iterations = parse_u64_arg(args, "iterations", 10_000)? as u32;
    let length = parse_u64_arg(args, "length", 32)? as usize;
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

fn hkdf(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
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
    let length = parse_u64_arg(args, "length", 32)? as usize;
    let h_len = match hash.as_str() {
        "sha1" => 20usize,
        "sha256" => 32,
        "sha512" => 64,
        _ => anyhow::bail!(
            "{}",
            i18n::tf(
                "err.unknown_hash_variant",
                &[hash.as_str(), "sha1 / sha256 / sha512"]
            )
        ),
    };
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
    let mut counter: u8 = 1;
    while out.len() < length {
        let mut input = t.clone();
        input.extend_from_slice(&info);
        input.push(counter);
        t = hmac_bytes(&hash, &prk, &input)?;
        out.extend_from_slice(&t);
        counter += 1;
    }
    out.truncate(length);
    Ok(out)
}
