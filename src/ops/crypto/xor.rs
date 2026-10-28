//! xor ops (split from mod.rs).

use super::super::{ArgSpec, Op, StreamingOp};
use super::*;
use crate::i18n;
use std::collections::HashMap;
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
                    format: crate::ops::ArgFormat::Bool,
                },
                ArgSpec {
                    name: "hex_output",
                    required: false,
                    description: "op.xor.bruteforce.arg.hex_output",
                    format: crate::ops::ArgFormat::Bool,
                },
            ],
            xor_bruteforce
        ),
    ]
}

/// XOR scheme (mirrors CyberChef's XOR bit-op schemes):
/// `standard` cycles a single key over the whole input;
/// `input-delimited` splits both key and input on whitespace, so token i is
/// XORed with key i (keys cycle), and whitespace separators pass through;
/// `input-differential` rekeys with the previous *input* byte;
/// `output-differential` rekeys with the previous *output* byte;
/// `cascade` keys each byte with the following input byte (last uses 0).
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum XorScheme {
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
        if self.scheme == XorScheme::Cascade
            && let Some(p) = self.pending.take()
        {
            // Cascade keys the last byte with 0, so it always passes through.
            return Ok(vec![p]);
        }
        Ok(Vec::new())
    }
}

pub(crate) fn parse_xor_scheme(args: &HashMap<String, String>) -> anyhow::Result<XorScheme> {
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
pub(crate) fn parse_null_preserving(args: &HashMap<String, String>) -> anyhow::Result<bool> {
    match opt_arg(args, "null_preserving", "false") {
        "false" | "0" => Ok(false),
        "true" | "1" => Ok(true),
        other => anyhow::bail!("{}", i18n::tf("err.bool_invalid", &[other])),
    }
}

pub(crate) fn make_xor(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
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

pub(crate) fn xor(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
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

pub(crate) fn qr(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(16);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(12);
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(8);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(7);
}

/// Decode `data` with a candidate key under one of the brute-force schemes.
pub(crate) fn xor_decode_with(
    key: &[u8],
    data: &[u8],
    scheme: XorScheme,
    null_preserving: bool,
) -> Vec<u8> {
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

pub(crate) fn parse_bool_arg(
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

pub(crate) fn xor_bruteforce(
    input: &[u8],
    args: &HashMap<String, String>,
) -> anyhow::Result<Vec<u8>> {
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
