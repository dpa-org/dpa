//! chacha ops (split from mod.rs).

use super::super::{ArgSpec, Op, StreamingOp};
use super::xor::qr;
use super::*;
use crate::i18n;
use std::collections::HashMap;
pub fn ops() -> Vec<Op> {
    vec![
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
        op!(
            "dpa:chacha20:decrypt",
            "crypto",
            "op.chacha20.decrypt.desc",
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
            chacha20_decrypt
        ),
    ]
}

pub(crate) struct ChaCha20 {
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

    pub(crate) fn next_block(&mut self, out: &mut [u8; 64]) {
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

struct ChaCha20Stream {
    chacha: ChaCha20,
    cur: [u8; 64],
    pos: usize,
    // Bytes processed so far; guards the RFC 8439 32-bit counter limit
    // (2^32 blocks = 256 GiB per key/nonce pair).
    total: u64,
}

impl StreamingOp for ChaCha20Stream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.total = self.total.saturating_add(chunk.len() as u64);
        // Past 256 GiB the 32-bit block counter wraps and the keystream
        // repeats (confidentiality break); refuse instead of silently reusing.
        if self.total > (1u64 << 38) {
            anyhow::bail!("{}", i18n::t("err.chacha_counter_limit"));
        }
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

pub(crate) fn chacha20_from_args(args: &HashMap<String, String>) -> anyhow::Result<ChaCha20> {
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

pub(crate) fn chacha20_crypt(
    input: &[u8],
    args: &HashMap<String, String>,
) -> anyhow::Result<Vec<u8>> {
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

/// `dpa:chacha20:decrypt` - ChaCha20 is a stream cipher: encrypting twice
/// recovers the plaintext. This alias runs the same keystream XOR as
/// `dpa:chacha20`, so `encrypt` then `decrypt` round-trips.
pub(crate) fn chacha20_decrypt(
    input: &[u8],
    args: &HashMap<String, String>,
) -> anyhow::Result<Vec<u8>> {
    chacha20_crypt(input, args)
}

pub(crate) fn make_chacha20(
    args: &HashMap<String, String>,
) -> anyhow::Result<Box<dyn StreamingOp>> {
    let chacha = chacha20_from_args(args)?;
    Ok(Box::new(ChaCha20Stream {
        chacha,
        cur: [0u8; 64],
        pos: 64,
        total: 0,
    }))
}
