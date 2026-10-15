//! Official dpa plugin: Adobe ascii85 (base85) encode/decode.
//!
//! Build: `cargo build -p dpa-plugin-ascii85` (or `cargo build --workspace`),
//! then load the produced `dpa_plugin_ascii85.dll` / `.so` / `.dylib` with
//! `dpa --plugins <dir>`. Nothing is discovered implicitly; `--discover-plugins`
//! is the opt-in for the conventional plugin directories.

use std::collections::HashMap;

use dpa::dpa_plugin;
use dpa::ops::{ArgSpec, StreamingOp};

const WRAP_ARGS: &[ArgSpec] = &[ArgSpec::new(
    "wrap",
    false,
    "wrap output with <~ ~> (default true)",
)];

/// Encode one 1..=4 byte block to its ascii85 representation (n+1 chars).
fn encode_block(bytes: &[u8]) -> Vec<u8> {
    let mut buf = [0u8; 4];
    buf[..bytes.len()].copy_from_slice(bytes);
    let n = u32::from_be_bytes(buf);
    let mut out = [0u8; 5];
    let mut rem = n;
    for i in (0..5).rev() {
        out[i] = (rem % 85) as u8 + 33;
        rem /= 85;
    }
    out[..bytes.len() + 1].to_vec()
}

fn encode_all(input: &[u8], wrap: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() / 4 * 5 + 8);
    if wrap {
        out.extend_from_slice(b"<~");
    }
    let mut i = 0;
    while i + 4 <= input.len() {
        let block = &input[i..i + 4];
        if block == [0, 0, 0, 0] {
            out.push(b'z');
        } else {
            out.extend_from_slice(&encode_block(block));
        }
        i += 4;
    }
    if i < input.len() {
        out.extend_from_slice(&encode_block(&input[i..]));
    }
    if wrap {
        out.extend_from_slice(b"~>");
    }
    out
}

fn decode_all(input: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut cleaned: Vec<u8> = Vec::with_capacity(input.len());
    for &b in input {
        if b.is_ascii_whitespace() {
            continue;
        }
        cleaned.push(b);
    }
    // Strip the optional <~ ~> wrapper.
    if cleaned.len() >= 2 && cleaned[0] == b'<' && cleaned[1] == b'~' {
        cleaned.drain(0..2);
    }
    if cleaned.len() >= 2
        && cleaned[cleaned.len() - 2] == b'~'
        && cleaned[cleaned.len() - 1] == b'>'
    {
        cleaned.truncate(cleaned.len() - 2);
    }

    let mut out = Vec::with_capacity(cleaned.len() / 5 * 4 + 4);
    let mut i = 0;
    while i < cleaned.len() {
        if cleaned[i] == b'z' {
            out.extend_from_slice(&[0, 0, 0, 0]);
            i += 1;
            continue;
        }
        let group_end = (i + 5).min(cleaned.len());
        let mut group = [b'u'; 5]; // pad the final partial group with 'u' (84)
        let mut cnt = 0usize;
        for (j, &c) in cleaned[i..group_end].iter().enumerate() {
            if !(33..=117).contains(&c) {
                anyhow::bail!("invalid ascii85 character 0x{:02X} at offset {}", c, i + j);
            }
            group[j] = c;
            cnt += 1;
        }
        let mut n: u64 = 0;
        for &c in &group {
            n = n * 85 + u64::from(c - 33);
        }
        if n > u64::from(u32::MAX) {
            anyhow::bail!("ascii85 group exceeds 32-bit range");
        }
        let bytes = (n as u32).to_be_bytes();
        // Full group of 5 chars -> 4 bytes; partial group -> cnt-1 bytes.
        out.extend_from_slice(&bytes[..cnt.saturating_sub(1)]);
        i = group_end;
    }
    Ok(out)
}

fn encode_run(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let wrap = args
        .get("wrap")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(true);
    Ok(encode_all(input, wrap))
}

fn decode_run(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    decode_all(input)
}

struct A85DecodeStream {
    buf: Vec<u8>,
}

impl StreamingOp for A85DecodeStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.buf.extend_from_slice(chunk);
        Ok(Vec::new())
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        let out = decode_all(&self.buf)?;
        self.buf.clear();
        Ok(out)
    }
}

fn decode_stream(_args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    Ok(Box::new(A85DecodeStream { buf: Vec::new() }))
}

struct A85EncodeStream {
    buf: Vec<u8>,
    wrap: bool,
    first: bool,
}

impl StreamingOp for A85EncodeStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut out = Vec::new();
        if self.first {
            if self.wrap {
                out.extend_from_slice(b"<~");
            }
            self.first = false;
        }
        self.buf.extend_from_slice(chunk);
        let mut i = 0;
        while i + 4 <= self.buf.len() {
            let block = &self.buf[i..i + 4];
            if block == [0, 0, 0, 0] {
                out.push(b'z');
            } else {
                out.extend_from_slice(&encode_block(block));
            }
            i += 4;
        }
        self.buf.drain(0..i);
        Ok(out)
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        let mut out = Vec::new();
        if self.first {
            if self.wrap {
                out.extend_from_slice(b"<~");
            }
            self.first = false;
        }
        if !self.buf.is_empty() {
            out.extend_from_slice(&encode_block(&self.buf));
            self.buf.clear();
        }
        if self.wrap {
            out.extend_from_slice(b"~>");
        }
        Ok(out)
    }
}

fn encode_stream(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    let wrap = args
        .get("wrap")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(true);
    Ok(Box::new(A85EncodeStream {
        buf: Vec::new(),
        wrap,
        first: true,
    }))
}

dpa_plugin! {
    version: 2,
    ops: [
        {
            name: "dpa:codec:ascii85:encode",
            category: "codec",
            description: "Encode data as Adobe ascii85 (base85)",
            args: WRAP_ARGS,
            run: encode_run,
            stream: encode_stream,
        },
        {
            name: "dpa:codec:ascii85:decode",
            category: "codec",
            description: "Decode Adobe ascii85 (base85) data",
            args: &[],
            run: decode_run,
            stream: decode_stream,
        },
    ],
}
