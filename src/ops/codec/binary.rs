//! Codec family: binary/octal/decimal/charcode/utf16/utf8:escape/ebcdic/hexdump.

use std::collections::HashMap;

use super::{
    HexDelimiter, StreamingOp, hex_delim_bytes, hex_digit, hex_val, parse_bool, parse_hex_args,
    parse_hex_delimiter, parse_hex_ignore,
};
use crate::i18n;

// ---------------------------------------------------------------------------
// UTF-8 percent escaping: byte-wise escape of non-printable bytes.
// `escape` is an element-wise stateless map -> chunk-parallel safe.
// `unescape` buffers a partial `%XX` tail across chunks -> stateful.
// ---------------------------------------------------------------------------

/// Byte-wise percent escape of non-printable bytes. With `encode_all` every
/// byte (including printable ASCII) is percent-encoded (CyberChef-style).
/// `uppercase` selects upper (default) or lower-case hex digits.
pub(crate) fn utf8_escape(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let encode_all = match args
        .get("encode_all")
        .map(|v| v.to_ascii_lowercase())
        .as_deref()
    {
        None | Some("false") | Some("0") | Some("no") => false,
        Some("true") | Some("1") | Some("yes") => true,
        Some(other) => anyhow::bail!("{}", i18n::tf("err.utf8_encode_all_invalid", &[other])),
    };
    let upper = match args.get("uppercase") {
        None => true,
        Some(v) => parse_bool(Some(v))?,
    };
    let mut out = Vec::with_capacity(input.len());
    for &b in input {
        if b == b'%' {
            out.extend_from_slice(b"%25");
        } else if !encode_all && (0x20..=0x7e).contains(&b) {
            out.push(b);
        } else {
            out.push(b'%');
            out.push(hex_digit_opt(b >> 4, upper));
            out.push(hex_digit_opt(b & 0x0f, upper));
        }
    }
    Ok(out)
}

/// Hex digit with configurable case (upper when `upper` is true).
fn hex_digit_opt(v: u8, upper: bool) -> u8 {
    if upper {
        hex_digit(v)
    } else {
        match v {
            0..=9 => b'0' + v,
            10..=15 => b'a' + (v - 10),
            _ => b'?',
        }
    }
}

struct Utf8EscapeStream {
    encode_all: bool,
    upper: bool,
}

pub(crate) fn make_utf8_escape(
    args: &HashMap<String, String>,
) -> anyhow::Result<Box<dyn StreamingOp>> {
    let encode_all = match args
        .get("encode_all")
        .map(|v| v.to_ascii_lowercase())
        .as_deref()
    {
        None | Some("false") | Some("0") | Some("no") => false,
        Some("true") | Some("1") | Some("yes") => true,
        Some(other) => anyhow::bail!("{}", i18n::tf("err.utf8_encode_all_invalid", &[other])),
    };
    let upper = match args.get("uppercase") {
        None => true,
        Some(v) => parse_bool(Some(v))?,
    };
    Ok(Box::new(Utf8EscapeStream { encode_all, upper }))
}

impl StreamingOp for Utf8EscapeStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut args = HashMap::new();
        if self.encode_all {
            args.insert("encode_all".to_string(), "true".to_string());
        }
        if !self.upper {
            args.insert("uppercase".to_string(), "false".to_string());
        }
        utf8_escape(chunk, &args)
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        Ok(Vec::new())
    }
}

pub(crate) fn utf8_unescape(
    input: &[u8],
    _args: &HashMap<String, String>,
) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'%' {
            if i + 2 >= input.len() {
                anyhow::bail!(
                    "{}",
                    i18n::tf(
                        "err.bad_escape",
                        &[String::from_utf8_lossy(&input[i..]).as_ref()]
                    )
                );
            }
            let hi = hex_val(input[i + 1]).ok_or_else(|| {
                anyhow::anyhow!(
                    "{}",
                    i18n::tf(
                        "err.bad_escape",
                        &[String::from_utf8_lossy(&input[i..i + 3]).as_ref()]
                    )
                )
            })?;
            let lo = hex_val(input[i + 2]).ok_or_else(|| {
                anyhow::anyhow!(
                    "{}",
                    i18n::tf(
                        "err.bad_escape",
                        &[String::from_utf8_lossy(&input[i..i + 3]).as_ref()]
                    )
                )
            })?;
            out.push(hi << 4 | lo);
            i += 3;
        } else {
            out.push(input[i]);
            i += 1;
        }
    }
    Ok(out)
}

struct Utf8UnescapeStream {
    pending: Vec<u8>,
}

pub(crate) fn make_utf8_unescape(
    _args: &HashMap<String, String>,
) -> anyhow::Result<Box<dyn StreamingOp>> {
    Ok(Box::new(Utf8UnescapeStream {
        pending: Vec::new(),
    }))
}

impl StreamingOp for Utf8UnescapeStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.pending.extend_from_slice(chunk);
        // Keep a possible truncated `%` / `%X` tail for the next chunk.
        let split = if !self.pending.is_empty() && self.pending[self.pending.len() - 1] == b'%' {
            self.pending.len() - 1
        } else if self.pending.len() >= 2 && self.pending[self.pending.len() - 2] == b'%' {
            self.pending.len() - 2
        } else {
            self.pending.len()
        };
        let head: Vec<u8> = self.pending.drain(..split).collect();
        utf8_unescape(&head, &HashMap::new())
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        let tail = std::mem::take(&mut self.pending);
        utf8_unescape(&tail, &HashMap::new())
    }
}

// ---------------------------------------------------------------------------
// binary / octal / decimal / charcode / html entity / base58
// Each has an in-memory run fn plus a streaming factory; decode keeps partial
// digit/entity state across chunks; encode is element-wise.
// ---------------------------------------------------------------------------

pub(crate) fn binary_encode(
    input: &[u8],
    args: &HashMap<String, String>,
) -> anyhow::Result<Vec<u8>> {
    let (delim, _) = parse_hex_args(args)?;
    Ok(binary_encode_with(input, delim))
}

fn binary_encode_with(input: &[u8], delim: HexDelimiter) -> Vec<u8> {
    let dbytes = hex_delim_bytes(delim);
    let mut out = Vec::with_capacity(input.len() * (8 + dbytes.len()));
    for (i, &b) in input.iter().enumerate() {
        if i > 0 {
            out.extend_from_slice(dbytes);
        }
        for bit in (0..8).rev() {
            out.push(if (b >> bit) & 1 == 1 { b'1' } else { b'0' });
        }
    }
    out
}

pub(crate) fn binary_decode(
    input: &[u8],
    args: &HashMap<String, String>,
) -> anyhow::Result<Vec<u8>> {
    let (delim, _) = parse_hex_args(args)?;
    let ignore = parse_hex_ignore(args)?;
    let dbytes = hex_delim_bytes(delim);
    let cleaned: Vec<u8> = input
        .iter()
        .copied()
        .filter(|b| {
            !b.is_ascii_whitespace()
                && (dbytes.is_empty() || !dbytes.contains(b))
                && (!ignore || matches!(b, b'0' | b'1'))
        })
        .collect();
    if !cleaned.len().is_multiple_of(8) {
        anyhow::bail!("{}", i18n::t("err.binary_odd"));
    }
    let mut out = Vec::with_capacity(cleaned.len() / 8);
    for group in cleaned.as_chunks::<8>().0 {
        let mut v = 0u8;
        for &c in group {
            v <<= 1;
            v |= match c {
                b'0' => 0,
                b'1' => 1,
                _ => anyhow::bail!("{}", i18n::t("err.binary_invalid")),
            };
        }
        out.push(v);
    }
    Ok(out)
}

struct BinaryEncodeStream {
    delim: HexDelimiter,
    started: bool,
}

pub(crate) fn make_binary_encode(
    args: &HashMap<String, String>,
) -> anyhow::Result<Box<dyn StreamingOp>> {
    let (delim, _) = parse_hex_args(args)?;
    Ok(Box::new(BinaryEncodeStream {
        delim,
        started: false,
    }))
}

impl StreamingOp for BinaryEncodeStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        if chunk.is_empty() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        if self.started {
            out.extend_from_slice(hex_delim_bytes(self.delim));
        }
        out.extend_from_slice(&binary_encode_with(chunk, self.delim));
        self.started = true;
        Ok(out)
    }
    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        Ok(Vec::new())
    }
}

/// Streaming binary decode: keep a partial bit group (0..8 digits) across chunks.
struct BinaryDecodeStream {
    bits: Vec<u8>,
    delim: HexDelimiter,
    ignore: bool,
}

pub(crate) fn make_binary_decode(
    args: &HashMap<String, String>,
) -> anyhow::Result<Box<dyn StreamingOp>> {
    let (delim, _) = parse_hex_args(args)?;
    Ok(Box::new(BinaryDecodeStream {
        bits: Vec::new(),
        delim,
        ignore: parse_hex_ignore(args)?,
    }))
}

impl StreamingOp for BinaryDecodeStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        let dbytes = hex_delim_bytes(self.delim);
        if self.ignore {
            self.bits
                .extend(chunk.iter().copied().filter(|b| matches!(b, b'0' | b'1')));
        } else {
            self.bits.extend_from_slice(chunk);
        }
        let mut out = Vec::new();
        let mut idx = 0usize;
        while idx < self.bits.len() {
            let c = self.bits[idx];
            if c.is_ascii_whitespace() || (!dbytes.is_empty() && dbytes.contains(&c)) {
                idx += 1;
                continue;
            }
            if self.bits.len() - idx < 8 {
                break;
            }
            let mut v = 0u8;
            for j in 0..8 {
                v <<= 1;
                v |= match self.bits[idx + j] {
                    b'0' => 0,
                    b'1' => 1,
                    _ => anyhow::bail!("{}", i18n::t("err.binary_invalid")),
                };
            }
            out.push(v);
            idx += 8;
        }
        self.bits.drain(..idx);
        Ok(out)
    }
    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        let dbytes = hex_delim_bytes(self.delim);
        let remaining: Vec<u8> = self
            .bits
            .iter()
            .copied()
            .filter(|b| {
                !b.is_ascii_whitespace()
                    && (dbytes.is_empty() || !dbytes.contains(b))
                    && (!self.ignore || matches!(b, b'0' | b'1'))
            })
            .collect();
        if !remaining.is_empty() {
            anyhow::bail!("{}", i18n::t("err.binary_odd"));
        }
        Ok(Vec::new())
    }
}

pub(crate) fn octal_encode(
    input: &[u8],
    args: &HashMap<String, String>,
) -> anyhow::Result<Vec<u8>> {
    let (delim, _) = parse_hex_args(args)?;
    Ok(octal_encode_with(input, delim))
}

fn octal_encode_with(input: &[u8], delim: HexDelimiter) -> Vec<u8> {
    let dbytes = hex_delim_bytes(delim);
    let mut out = Vec::with_capacity(input.len() * (3 + dbytes.len()));
    for (i, &b) in input.iter().enumerate() {
        if i > 0 {
            out.extend_from_slice(dbytes);
        }
        out.push(b'0' + (b >> 6));
        out.push(b'0' + ((b >> 3) & 0x07));
        out.push(b'0' + (b & 0x07));
    }
    out
}

pub(crate) fn octal_decode(
    input: &[u8],
    args: &HashMap<String, String>,
) -> anyhow::Result<Vec<u8>> {
    let (delim, _) = parse_hex_args(args)?;
    let ignore = parse_hex_ignore(args)?;
    let dbytes = hex_delim_bytes(delim);
    let cleaned: Vec<u8> = input
        .iter()
        .copied()
        .filter(|b| {
            !b.is_ascii_whitespace()
                && (dbytes.is_empty() || !dbytes.contains(b))
                && (!ignore || matches!(b, b'0'..=b'7'))
        })
        .collect();
    if !cleaned.len().is_multiple_of(3) {
        anyhow::bail!("{}", i18n::t("err.octal_odd"));
    }
    let mut out = Vec::with_capacity(cleaned.len() / 3);
    for group in cleaned.as_chunks::<3>().0 {
        let mut v = 0u8;
        for &c in group {
            let d = match c {
                b'0'..=b'7' => c - b'0',
                _ => anyhow::bail!("{}", i18n::t("err.octal_invalid")),
            };
            v = (v << 3) | d;
        }
        out.push(v);
    }
    Ok(out)
}

struct OctalEncodeStream {
    delim: HexDelimiter,
    started: bool,
}

pub(crate) fn make_octal_encode(
    args: &HashMap<String, String>,
) -> anyhow::Result<Box<dyn StreamingOp>> {
    let (delim, _) = parse_hex_args(args)?;
    Ok(Box::new(OctalEncodeStream {
        delim,
        started: false,
    }))
}

impl StreamingOp for OctalEncodeStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        if chunk.is_empty() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        if self.started {
            out.extend_from_slice(hex_delim_bytes(self.delim));
        }
        out.extend_from_slice(&octal_encode_with(chunk, self.delim));
        self.started = true;
        Ok(out)
    }
    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        Ok(Vec::new())
    }
}

struct OctalDecodeStream {
    digits: Vec<u8>,
    delim: HexDelimiter,
    ignore: bool,
}

pub(crate) fn make_octal_decode(
    args: &HashMap<String, String>,
) -> anyhow::Result<Box<dyn StreamingOp>> {
    let (delim, _) = parse_hex_args(args)?;
    Ok(Box::new(OctalDecodeStream {
        digits: Vec::new(),
        delim,
        ignore: parse_hex_ignore(args)?,
    }))
}

impl StreamingOp for OctalDecodeStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        let dbytes = hex_delim_bytes(self.delim);
        if self.ignore {
            self.digits
                .extend(chunk.iter().copied().filter(|b| matches!(b, b'0'..=b'7')));
        } else {
            self.digits.extend_from_slice(chunk);
        }
        let mut out = Vec::new();
        let mut idx = 0usize;
        while idx < self.digits.len() {
            let c = self.digits[idx];
            if c.is_ascii_whitespace() || (!dbytes.is_empty() && dbytes.contains(&c)) {
                idx += 1;
                continue;
            }
            if self.digits.len() - idx < 3 {
                break;
            }
            let mut v = 0u8;
            for j in 0..3 {
                let d = match self.digits[idx + j] {
                    b'0'..=b'7' => self.digits[idx + j] - b'0',
                    _ => anyhow::bail!("{}", i18n::t("err.octal_invalid")),
                };
                v = (v << 3) | d;
            }
            out.push(v);
            idx += 3;
        }
        self.digits.drain(..idx);
        Ok(out)
    }
    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        let dbytes = hex_delim_bytes(self.delim);
        let remaining: Vec<u8> = self
            .digits
            .iter()
            .copied()
            .filter(|b| {
                !b.is_ascii_whitespace()
                    && (dbytes.is_empty() || !dbytes.contains(b))
                    && (!self.ignore || matches!(b, b'0'..=b'7'))
            })
            .collect();
        if !remaining.is_empty() {
            anyhow::bail!("{}", i18n::t("err.octal_odd"));
        }
        Ok(Vec::new())
    }
}

pub(crate) fn decimal_encode(
    input: &[u8],
    args: &HashMap<String, String>,
) -> anyhow::Result<Vec<u8>> {
    let delim = parse_decimal_delim(args)?;
    Ok(decimal_encode_with(input, delim))
}

fn parse_decimal_delim(args: &HashMap<String, String>) -> anyhow::Result<HexDelimiter> {
    match args.get("delimiter") {
        None => Ok(HexDelimiter::Space),
        Some(s) => parse_hex_delimiter(s),
    }
}

fn decimal_encode_with(input: &[u8], delim: HexDelimiter) -> Vec<u8> {
    let dbytes = hex_delim_bytes(delim);
    let mut out = Vec::with_capacity(input.len() * (4 + dbytes.len()));
    for (i, &b) in input.iter().enumerate() {
        if i > 0 {
            out.extend_from_slice(dbytes);
        }
        out.extend_from_slice(b.to_string().as_bytes());
    }
    out
}

pub(crate) fn decimal_decode(
    input: &[u8],
    args: &HashMap<String, String>,
) -> anyhow::Result<Vec<u8>> {
    use std::borrow::Cow;
    let delim = parse_decimal_delim(args)?;
    let ignore = parse_hex_ignore(args)?;
    let dbytes = hex_delim_bytes(delim);
    let cleaned: Cow<'_, [u8]> = if ignore {
        Cow::Owned(
            input
                .iter()
                .copied()
                .filter(|b| {
                    b.is_ascii_digit()
                        || b.is_ascii_whitespace()
                        || *b == b','
                        || (!dbytes.is_empty() && dbytes.contains(b))
                })
                .collect(),
        )
    } else {
        Cow::Borrowed(input)
    };
    let s = std::str::from_utf8(&cleaned)?;
    let mut out = Vec::new();
    for token in s.split(|c: char| {
        c.is_whitespace() || c == ',' || (!dbytes.is_empty() && dbytes.contains(&(c as u8)))
    }) {
        if token.is_empty() {
            continue;
        }
        let v: u16 = token
            .trim()
            .parse()
            .map_err(|_| anyhow::anyhow!("{}", i18n::tf("err.decimal_invalid", &[token])))?;
        if v > 255 {
            anyhow::bail!("{}", i18n::tf("err.decimal_range", &[token]));
        }
        out.push(v as u8);
    }
    Ok(out)
}

struct DecimalEncodeStream {
    delim: HexDelimiter,
    started: bool,
}

pub(crate) fn make_decimal_encode(
    args: &HashMap<String, String>,
) -> anyhow::Result<Box<dyn StreamingOp>> {
    let delim = parse_decimal_delim(args)?;
    Ok(Box::new(DecimalEncodeStream {
        delim,
        started: false,
    }))
}

impl StreamingOp for DecimalEncodeStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        if chunk.is_empty() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        if self.started {
            out.extend_from_slice(hex_delim_bytes(self.delim));
        }
        out.extend_from_slice(&decimal_encode_with(chunk, self.delim));
        self.started = true;
        Ok(out)
    }
    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        Ok(Vec::new())
    }
}

/// Streaming decimal decode: buffer tokens that may be split across chunks.
struct DecimalDecodeStream {
    pending: Vec<u8>,
    delim: HexDelimiter,
    ignore: bool,
}

pub(crate) fn make_decimal_decode(
    args: &HashMap<String, String>,
) -> anyhow::Result<Box<dyn StreamingOp>> {
    let delim = parse_decimal_delim(args)?;
    Ok(Box::new(DecimalDecodeStream {
        pending: Vec::new(),
        delim,
        ignore: parse_hex_ignore(args)?,
    }))
}

impl StreamingOp for DecimalDecodeStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        let dbytes = hex_delim_bytes(self.delim);
        if self.ignore {
            self.pending.extend(chunk.iter().copied().filter(|b| {
                b.is_ascii_digit()
                    || b.is_ascii_whitespace()
                    || *b == b','
                    || (!dbytes.is_empty() && dbytes.contains(b))
            }));
        } else {
            self.pending.extend_from_slice(chunk);
        }
        // Only parse complete tokens; keep the trailing partial token buffered.
        let split = match self.pending.iter().rposition(|&c| {
            c.is_ascii_whitespace() || c == b',' || (!dbytes.is_empty() && dbytes.contains(&c))
        }) {
            Some(p) => p + 1,
            None => 0,
        };
        let head: Vec<u8> = self.pending.drain(..split).collect();
        let mut args = HashMap::new();
        if !dbytes.is_empty() {
            let name = match self.delim {
                HexDelimiter::Space => "space",
                HexDelimiter::Comma => "comma",
                HexDelimiter::SemiColon => "semicolon",
                HexDelimiter::Colon => "colon",
                HexDelimiter::Newline => "newline",
                HexDelimiter::Crlf => "crlf",
                HexDelimiter::None => "none",
            };
            args.insert("delimiter".to_string(), name.to_string());
        }
        decimal_decode(&head, &args)
    }
    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        let tail = std::mem::take(&mut self.pending);
        decimal_decode(&tail, &HashMap::new())
    }
}

/// Encode each UTF-8 character as its Unicode code point with a configurable
/// delimiter (default space) and base (decimal or 0x-prefixed hex).
pub(crate) fn charcode_encode(
    input: &[u8],
    args: &HashMap<String, String>,
) -> anyhow::Result<Vec<u8>> {
    let (delim, base) = parse_charcode_args(args)?;
    Ok(charcode_encode_with(input, delim, base))
}

fn charcode_encode_with(input: &[u8], delim: HexDelimiter, base: CharcodeBase) -> Vec<u8> {
    let s = std::str::from_utf8(input).expect("valid utf8 upstream");
    let dbytes = hex_delim_bytes(delim);
    let mut out = Vec::new();
    for (i, ch) in s.chars().enumerate() {
        if i > 0 {
            out.extend_from_slice(dbytes);
        }
        match base {
            CharcodeBase::Decimal => out.extend_from_slice((ch as u32).to_string().as_bytes()),
            CharcodeBase::Hex => out.extend_from_slice(format!("0x{:X}", ch as u32).as_bytes()),
            CharcodeBase::Octal => out.extend_from_slice(format!("{:o}", ch as u32).as_bytes()),
            CharcodeBase::Binary => out.extend_from_slice(format!("{:b}", ch as u32).as_bytes()),
        }
    }
    out
}

/// Decode code points (decimal or 0x hex, space/comma separated) back to UTF-8.
/// The delimiter argument controls token separation; whitespace is always
/// tolerated and the default keeps the legacy space/comma behaviour.
pub(crate) fn charcode_decode(
    input: &[u8],
    args: &HashMap<String, String>,
) -> anyhow::Result<Vec<u8>> {
    let delim = match args.get("delimiter") {
        None => HexDelimiter::Space,
        Some(s) => parse_hex_delimiter(s)?,
    };
    let base = parse_charcode_base(args)?;
    charcode_decode_with(input, delim, base)
}

fn charcode_decode_with(
    input: &[u8],
    delim: HexDelimiter,
    base: CharcodeBase,
) -> anyhow::Result<Vec<u8>> {
    let dbytes = hex_delim_bytes(delim);
    let s = std::str::from_utf8(input)?;
    let mut out = Vec::new();
    for token in s.split(|c: char| {
        c.is_whitespace() || c == ',' || (!dbytes.is_empty() && dbytes.contains(&(c as u8)))
    }) {
        if token.is_empty() {
            continue;
        }
        let t = token.trim();
        let cp: u32 = match base {
            CharcodeBase::Decimal => {
                // Backward compatible: auto-detect a 0x/0X prefixed token as hex,
                // otherwise parse as decimal (this matches the pre-parameterized
                // behaviour and the original CyberChef-style convenience).
                if let Some(hexpart) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                    u32::from_str_radix(hexpart, 16).map_err(|_| {
                        anyhow::anyhow!("{}", i18n::tf("err.charcode_invalid", &[t]))
                    })?
                } else {
                    t.parse().map_err(|_| {
                        anyhow::anyhow!("{}", i18n::tf("err.charcode_invalid", &[t]))
                    })?
                }
            }
            CharcodeBase::Hex => {
                let h = t
                    .strip_prefix("0x")
                    .or_else(|| t.strip_prefix("0X"))
                    .unwrap_or(t);
                u32::from_str_radix(h, 16)
                    .map_err(|_| anyhow::anyhow!("{}", i18n::tf("err.charcode_invalid", &[t])))?
            }
            CharcodeBase::Octal => u32::from_str_radix(t, 8)
                .map_err(|_| anyhow::anyhow!("{}", i18n::tf("err.charcode_invalid", &[t])))?,
            CharcodeBase::Binary => u32::from_str_radix(t, 2)
                .map_err(|_| anyhow::anyhow!("{}", i18n::tf("err.charcode_invalid", &[t])))?,
        };
        let ch = char::from_u32(cp)
            .ok_or_else(|| anyhow::anyhow!("{}", i18n::tf("err.charcode_invalid", &[t])))?;
        let mut buf = [0u8; 4];
        out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
    }
    Ok(out)
}

#[derive(Clone, Copy, PartialEq, Eq)]

enum CharcodeBase {
    Decimal,
    Hex,
    Octal,
    Binary,
}

fn parse_charcode_args(
    args: &HashMap<String, String>,
) -> anyhow::Result<(HexDelimiter, CharcodeBase)> {
    let delim = match args.get("delimiter") {
        None => HexDelimiter::Space,
        Some(s) => parse_hex_delimiter(s)?,
    };
    let base = parse_charcode_base(args)?;
    Ok((delim, base))
}

fn parse_charcode_base(args: &HashMap<String, String>) -> anyhow::Result<CharcodeBase> {
    match args.get("base").map(|v| v.to_ascii_lowercase()).as_deref() {
        None | Some("decimal") | Some("dec") => Ok(CharcodeBase::Decimal),
        Some("hex") => Ok(CharcodeBase::Hex),
        Some("octal") | Some("oct") => Ok(CharcodeBase::Octal),
        Some("binary") | Some("bin") => Ok(CharcodeBase::Binary),
        Some(other) => anyhow::bail!("{}", i18n::tf("err.charcode_base_invalid", &[other])),
    }
}

/// Streaming charcode encode: buffer input so partial UTF-8 sequences are never split.
struct CharcodeEncodeStream {
    buf: Vec<u8>,
    emitted: bool,
    delim: HexDelimiter,
    base: CharcodeBase,
}

pub(crate) fn make_charcode_encode(
    args: &HashMap<String, String>,
) -> anyhow::Result<Box<dyn StreamingOp>> {
    let (delim, base) = parse_charcode_args(args)?;
    Ok(Box::new(CharcodeEncodeStream {
        buf: Vec::new(),
        emitted: false,
        delim,
        base,
    }))
}

impl StreamingOp for CharcodeEncodeStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.buf.extend_from_slice(chunk);
        // Emit only complete UTF-8 characters; keep a partial tail for the next write.
        let valid = std::str::from_utf8(&self.buf)
            .map(|_| self.buf.len())
            .unwrap_or_else(|e| e.valid_up_to());
        let head: Vec<u8> = self.buf.drain(..valid).collect();
        if head.is_empty() {
            return Ok(Vec::new());
        }
        let mut out = charcode_encode_with(&head, self.delim, self.base);
        if self.emitted {
            out.splice(0..0, hex_delim_bytes(self.delim).iter().copied());
        }
        self.emitted = true;
        Ok(out)
    }
    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        let tail = std::mem::take(&mut self.buf);
        if !tail.is_empty() {
            anyhow::bail!("{}", i18n::t("err.utf8_invalid"));
        }
        Ok(Vec::new())
    }
}

// ---------------------------------------------------------------------------
// UTF-16 (LE/BE with optional BOM): encode UTF-8 -> UTF-16 bytes, decode
// UTF-16 bytes -> UTF-8. Streaming mirrors the in-memory path across chunk
// boundaries (partial UTF-8 tails for encode; odd trailing bytes, split BOM
// and surrogate pairs for decode).
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]

enum Utf16Endian {
    Le,
    Be,
}

fn parse_utf16_endian(args: &HashMap<String, String>) -> anyhow::Result<Utf16Endian> {
    match args
        .get("endian")
        .map(|v| v.to_ascii_lowercase())
        .as_deref()
    {
        None | Some("le") | Some("little") => Ok(Utf16Endian::Le),
        Some("be") | Some("big") => Ok(Utf16Endian::Be),
        Some(other) => anyhow::bail!("{}", i18n::tf("err.utf16_endian_invalid", &[other])),
    }
}

pub(crate) fn utf16_encode(
    input: &[u8],
    args: &HashMap<String, String>,
) -> anyhow::Result<Vec<u8>> {
    let endian = parse_utf16_endian(args)?;
    let bom = match args.get("bom").map(|v| v.to_ascii_lowercase()).as_deref() {
        None | Some("false") | Some("0") | Some("no") => false,
        Some("true") | Some("1") | Some("yes") => true,
        Some(other) => anyhow::bail!("{}", i18n::tf("err.bool_invalid", &[other])),
    };
    let mut out = Vec::with_capacity(input.len() * 2);
    utf16_encode_with(input, endian, bom, &mut out)?;
    Ok(out)
}

fn utf16_encode_with(
    input: &[u8],
    endian: Utf16Endian,
    bom: bool,
    out: &mut Vec<u8>,
) -> anyhow::Result<()> {
    let s = std::str::from_utf8(input)
        .map_err(|_| anyhow::anyhow!("{}", i18n::t("err.utf8_invalid")))?;
    if bom {
        out.extend_from_slice(match endian {
            Utf16Endian::Le => &[0xFF, 0xFE],
            Utf16Endian::Be => &[0xFE, 0xFF],
        });
    }
    for u in s.encode_utf16() {
        let bytes = if endian == Utf16Endian::Le {
            u.to_le_bytes()
        } else {
            u.to_be_bytes()
        };
        out.extend_from_slice(&bytes);
    }
    Ok(())
}

pub(crate) fn utf16_decode(
    input: &[u8],
    args: &HashMap<String, String>,
) -> anyhow::Result<Vec<u8>> {
    let endian = parse_utf16_endian(args)?;
    let bom = match args.get("bom").map(|v| v.to_ascii_lowercase()).as_deref() {
        None | Some("true") | Some("1") | Some("yes") => true,
        Some("false") | Some("0") | Some("no") => false,
        Some(other) => anyhow::bail!("{}", i18n::tf("err.bool_invalid", &[other])),
    };
    utf16_decode_with(input, endian, bom)
}

fn utf16_decode_with(input: &[u8], endian: Utf16Endian, bom: bool) -> anyhow::Result<Vec<u8>> {
    let mut data = input;
    let mut eff = endian;
    if bom && data.len() >= 2 {
        if data[..2] == [0xFF, 0xFE] {
            eff = Utf16Endian::Le;
            data = &data[2..];
        } else if data[..2] == [0xFE, 0xFF] {
            eff = Utf16Endian::Be;
            data = &data[2..];
        }
    }
    if !data.len().is_multiple_of(2) {
        anyhow::bail!("{}", i18n::t("err.utf16_odd_length"));
    }
    let mut out = Vec::with_capacity(data.len() / 2);
    let mut i = 0usize;
    let units: Vec<u16> = data
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| match eff {
            Utf16Endian::Le => u16::from_le_bytes([c[0], c[1]]),
            Utf16Endian::Be => u16::from_be_bytes([c[0], c[1]]),
        })
        .collect();
    while i < units.len() {
        let u = units[i];
        if (0xD800..=0xDBFF).contains(&u) {
            if i + 1 < units.len() && (0xDC00..=0xDFFF).contains(&units[i + 1]) {
                let c = 0x10000 + (((u as u32 - 0xD800) << 10) | (units[i + 1] as u32 - 0xDC00));
                let ch = char::from_u32(c).ok_or_else(|| {
                    anyhow::anyhow!(
                        "{}",
                        i18n::tf(
                            "err.utf16_invalid_code_point",
                            &[format!("{:04X}", c).as_str()]
                        )
                    )
                })?;
                out.extend_from_slice(ch.to_string().as_bytes());
                i += 2;
                continue;
            }
            anyhow::bail!(
                "{}",
                i18n::tf("err.utf16_lone_surrogate", &[format!("{:04x}", u).as_str()])
            );
        }
        if (0xDC00..=0xDFFF).contains(&u) {
            anyhow::bail!(
                "{}",
                i18n::tf("err.utf16_lone_surrogate", &[format!("{:04x}", u).as_str()])
            );
        }
        let ch = char::from_u32(u as u32).ok_or_else(|| {
            anyhow::anyhow!(
                "{}",
                i18n::tf(
                    "err.utf16_invalid_code_point",
                    &[format!("{:04X}", u as u32).as_str()]
                )
            )
        })?;
        out.extend_from_slice(ch.to_string().as_bytes());
        i += 1;
    }
    Ok(out)
}

/// Streaming UTF-16 encode: buffers a partial UTF-8 tail so multi-byte
/// characters split across chunks encode as whole code points; the BOM is
/// emitted once, at the first output (or at finish for empty input).
struct Utf16EncodeStream {
    buf: Vec<u8>,
    endian: Utf16Endian,
    bom: bool,
    bom_emitted: bool,
    total: usize,
}

pub(crate) fn make_utf16_encode(
    args: &HashMap<String, String>,
) -> anyhow::Result<Box<dyn StreamingOp>> {
    let endian = parse_utf16_endian(args)?;
    let bom = match args.get("bom").map(|v| v.to_ascii_lowercase()).as_deref() {
        None | Some("false") | Some("0") | Some("no") => false,
        Some("true") | Some("1") | Some("yes") => true,
        Some(other) => anyhow::bail!("{}", i18n::tf("err.bool_invalid", &[other])),
    };
    Ok(Box::new(Utf16EncodeStream {
        buf: Vec::new(),
        endian,
        bom,
        bom_emitted: false,
        total: 0,
    }))
}

impl StreamingOp for Utf16EncodeStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.buf.extend_from_slice(chunk);
        let valid = std::str::from_utf8(&self.buf)
            .map(|_| self.buf.len())
            .unwrap_or_else(|e| e.valid_up_to());
        let head: Vec<u8> = self.buf.drain(..valid).collect();
        if head.is_empty() {
            return Ok(Vec::new());
        }
        self.total += head.len();
        let mut out = Vec::with_capacity(head.len() * 2);
        if self.bom && !self.bom_emitted {
            out.extend_from_slice(match self.endian {
                Utf16Endian::Le => &[0xFF, 0xFE],
                Utf16Endian::Be => &[0xFE, 0xFF],
            });
            self.bom_emitted = true;
        }
        utf16_encode_with(&head, self.endian, false, &mut out)?;
        Ok(out)
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        if !self.buf.is_empty() {
            anyhow::bail!("{}", i18n::t("err.utf8_invalid"));
        }
        if self.bom && !self.bom_emitted && self.total == 0 {
            self.bom_emitted = true;
            return Ok(match self.endian {
                Utf16Endian::Le => vec![0xFF, 0xFE],
                Utf16Endian::Be => vec![0xFE, 0xFF],
            });
        }
        Ok(Vec::new())
    }
}

/// Streaming UTF-16 decode: keeps at most one trailing byte plus an unpaired
/// high surrogate across chunks; a BOM split between chunks is still detected.
struct Utf16DecodeStream {
    pending: Vec<u8>,
    endian: Utf16Endian,
    bom: bool,
    bom_checked: bool,
}

pub(crate) fn make_utf16_decode(
    args: &HashMap<String, String>,
) -> anyhow::Result<Box<dyn StreamingOp>> {
    let endian = parse_utf16_endian(args)?;
    let bom = match args.get("bom").map(|v| v.to_ascii_lowercase()).as_deref() {
        None | Some("true") | Some("1") | Some("yes") => true,
        Some("false") | Some("0") | Some("no") => false,
        Some(other) => anyhow::bail!("{}", i18n::tf("err.bool_invalid", &[other])),
    };
    Ok(Box::new(Utf16DecodeStream {
        pending: Vec::new(),
        endian,
        bom,
        bom_checked: false,
    }))
}

impl Utf16DecodeStream {
    /// Consume complete units from `pending`, decoding to UTF-8; leave an odd
    /// trailing byte or an unpaired high surrogate in place.
    fn drain_units(&mut self, out: &mut Vec<u8>) -> anyhow::Result<()> {
        loop {
            if self.pending.len() < 2 {
                return Ok(());
            }
            let u = match self.endian {
                Utf16Endian::Le => u16::from_le_bytes([self.pending[0], self.pending[1]]),
                Utf16Endian::Be => u16::from_be_bytes([self.pending[0], self.pending[1]]),
            };
            if (0xD800..=0xDBFF).contains(&u) {
                if self.pending.len() < 4 {
                    // Wait for the low surrogate in the next chunk.
                    return Ok(());
                }
                let lo = match self.endian {
                    Utf16Endian::Le => u16::from_le_bytes([self.pending[2], self.pending[3]]),
                    Utf16Endian::Be => u16::from_be_bytes([self.pending[2], self.pending[3]]),
                };
                if !(0xDC00..=0xDFFF).contains(&lo) {
                    anyhow::bail!(
                        "{}",
                        i18n::tf("err.utf16_lone_surrogate", &[format!("{:04x}", u).as_str()])
                    );
                }
                let c = 0x10000 + (((u as u32 - 0xD800) << 10) | (lo as u32 - 0xDC00));
                let ch = char::from_u32(c).ok_or_else(|| {
                    anyhow::anyhow!(
                        "{}",
                        i18n::tf(
                            "err.utf16_invalid_code_point",
                            &[format!("{:04X}", c).as_str()]
                        )
                    )
                })?;
                out.extend_from_slice(ch.to_string().as_bytes());
                self.pending.drain(..4);
                continue;
            }
            if (0xDC00..=0xDFFF).contains(&u) {
                anyhow::bail!(
                    "{}",
                    i18n::tf("err.utf16_lone_surrogate", &[format!("{:04x}", u).as_str()])
                );
            }
            let ch = char::from_u32(u as u32).ok_or_else(|| {
                anyhow::anyhow!(
                    "{}",
                    i18n::tf(
                        "err.utf16_invalid_code_point",
                        &[format!("{:04X}", u as u32).as_str()]
                    )
                )
            })?;
            out.extend_from_slice(ch.to_string().as_bytes());
            self.pending.drain(..2);
        }
    }
}

impl StreamingOp for Utf16DecodeStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.pending.extend_from_slice(chunk);
        if self.bom && !self.bom_checked && self.pending.len() >= 2 {
            self.bom_checked = true;
            if self.pending[..2] == [0xFF, 0xFE] {
                self.endian = Utf16Endian::Le;
                self.pending.drain(..2);
            } else if self.pending[..2] == [0xFE, 0xFF] {
                self.endian = Utf16Endian::Be;
                self.pending.drain(..2);
            }
        }
        let mut out = Vec::new();
        self.drain_units(&mut out)?;
        Ok(out)
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        if self.bom && !self.bom_checked && self.pending.len() >= 2 {
            self.bom_checked = true;
            if self.pending[..2] == [0xFF, 0xFE] {
                self.endian = Utf16Endian::Le;
                self.pending.drain(..2);
            } else if self.pending[..2] == [0xFE, 0xFF] {
                self.endian = Utf16Endian::Be;
                self.pending.drain(..2);
            }
        }
        let mut out = Vec::new();
        self.drain_units(&mut out)?;
        if self.pending.len() == 1 {
            anyhow::bail!("{}", i18n::t("err.utf16_odd_length"));
        }
        self.pending.clear();
        Ok(out)
    }
}

/// Streaming charcode decode: buffer partial tokens across chunks.
struct CharcodeDecodeStream {
    pending: Vec<u8>,
    delim: HexDelimiter,
    base: CharcodeBase,
}

pub(crate) fn make_charcode_decode(
    args: &HashMap<String, String>,
) -> anyhow::Result<Box<dyn StreamingOp>> {
    let delim = match args.get("delimiter") {
        None => HexDelimiter::Space,
        Some(s) => parse_hex_delimiter(s)?,
    };
    let base = parse_charcode_base(args)?;
    Ok(Box::new(CharcodeDecodeStream {
        pending: Vec::new(),
        delim,
        base,
    }))
}

impl StreamingOp for CharcodeDecodeStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.pending.extend_from_slice(chunk);
        let dbytes = hex_delim_bytes(self.delim);
        let split = match self.pending.iter().rposition(|&c| {
            c.is_ascii_whitespace() || c == b',' || (!dbytes.is_empty() && dbytes.contains(&c))
        }) {
            Some(p) => p + 1,
            None => 0,
        };
        let head: Vec<u8> = self.pending.drain(..split).collect();
        charcode_decode_with(&head, self.delim, self.base)
    }
    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        let tail = std::mem::take(&mut self.pending);
        charcode_decode_with(&tail, self.delim, self.base)
    }
}

// ---------------------------------------------------------------------------
// EBCDIC (IBM cp037). Tables generated from Python's cp037 codec so
// the byte mapping exactly matches IBM 037 (CyberChef's default EBCDIC codec).
// ---------------------------------------------------------------------------

/// EBCDIC (cp037) byte -> ASCII/Latin-1 byte, indexed by EBCDIC value.
const EBCDIC_TO_ASCII: [u8; 256] = [
    0x00, 0x01, 0x02, 0x03, 0x9C, 0x09, 0x86, 0x7F, 0x97, 0x8D, 0x8E, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x9D, 0x85, 0x08, 0x87, 0x18, 0x19, 0x92, 0x8F, 0x1C, 0x1D, 0x1E, 0x1F,
    0x80, 0x81, 0x82, 0x83, 0x84, 0x0A, 0x17, 0x1B, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x05, 0x06, 0x07,
    0x90, 0x91, 0x16, 0x93, 0x94, 0x95, 0x96, 0x04, 0x98, 0x99, 0x9A, 0x9B, 0x14, 0x15, 0x9E, 0x1A,
    0x20, 0xA0, 0xE2, 0xE4, 0xE0, 0xE1, 0xE3, 0xE5, 0xE7, 0xF1, 0xA2, 0x2E, 0x3C, 0x28, 0x2B, 0x7C,
    0x26, 0xE9, 0xEA, 0xEB, 0xE8, 0xED, 0xEE, 0xEF, 0xEC, 0xDF, 0x21, 0x24, 0x2A, 0x29, 0x3B, 0xAC,
    0x2D, 0x2F, 0xC2, 0xC4, 0xC0, 0xC1, 0xC3, 0xC5, 0xC7, 0xD1, 0xA6, 0x2C, 0x25, 0x5F, 0x3E, 0x3F,
    0xF8, 0xC9, 0xCA, 0xCB, 0xC8, 0xCD, 0xCE, 0xCF, 0xCC, 0x60, 0x3A, 0x23, 0x40, 0x27, 0x3D, 0x22,
    0xD8, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0xAB, 0xBB, 0xF0, 0xFD, 0xFE, 0xB1,
    0xB0, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0xAA, 0xBA, 0xE6, 0xB8, 0xC6, 0xA4,
    0xB5, 0x7E, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0xA1, 0xBF, 0xD0, 0xDD, 0xDE, 0xAE,
    0x5E, 0xA3, 0xA5, 0xB7, 0xA9, 0xA7, 0xB6, 0xBC, 0xBD, 0xBE, 0x5B, 0x5D, 0xAF, 0xA8, 0xB4, 0xD7,
    0x7B, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0xAD, 0xF4, 0xF6, 0xF2, 0xF3, 0xF5,
    0x7D, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0xB9, 0xFB, 0xFC, 0xF9, 0xFA, 0xFF,
    0x5C, 0xF7, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0xB2, 0xD4, 0xD6, 0xD2, 0xD3, 0xD5,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0xB3, 0xDB, 0xDC, 0xD9, 0xDA, 0x9F,
];

/// ASCII/Latin-1 byte -> EBCDIC (cp037) byte, indexed by ASCII value.
const ASCII_TO_EBCDIC: [u8; 256] = [
    0x00, 0x01, 0x02, 0x03, 0x37, 0x2D, 0x2E, 0x2F, 0x16, 0x05, 0x25, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x3C, 0x3D, 0x32, 0x26, 0x18, 0x19, 0x3F, 0x27, 0x1C, 0x1D, 0x1E, 0x1F,
    0x40, 0x5A, 0x7F, 0x7B, 0x5B, 0x6C, 0x50, 0x7D, 0x4D, 0x5D, 0x5C, 0x4E, 0x6B, 0x60, 0x4B, 0x61,
    0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0x7A, 0x5E, 0x4C, 0x7E, 0x6E, 0x6F,
    0x7C, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6,
    0xD7, 0xD8, 0xD9, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xBA, 0xE0, 0xBB, 0xB0, 0x6D,
    0x79, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96,
    0x97, 0x98, 0x99, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xC0, 0x4F, 0xD0, 0xA1, 0x07,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x15, 0x06, 0x17, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x09, 0x0A, 0x1B,
    0x30, 0x31, 0x1A, 0x33, 0x34, 0x35, 0x36, 0x08, 0x38, 0x39, 0x3A, 0x3B, 0x04, 0x14, 0x3E, 0xFF,
    0x41, 0xAA, 0x4A, 0xB1, 0x9F, 0xB2, 0x6A, 0xB5, 0xBD, 0xB4, 0x9A, 0x8A, 0x5F, 0xCA, 0xAF, 0xBC,
    0x90, 0x8F, 0xEA, 0xFA, 0xBE, 0xA0, 0xB6, 0xB3, 0x9D, 0xDA, 0x9B, 0x8B, 0xB7, 0xB8, 0xB9, 0xAB,
    0x64, 0x65, 0x62, 0x66, 0x63, 0x67, 0x9E, 0x68, 0x74, 0x71, 0x72, 0x73, 0x78, 0x75, 0x76, 0x77,
    0xAC, 0x69, 0xED, 0xEE, 0xEB, 0xEF, 0xEC, 0xBF, 0x80, 0xFD, 0xFE, 0xFB, 0xFC, 0xAD, 0xAE, 0x59,
    0x44, 0x45, 0x42, 0x46, 0x43, 0x47, 0x9C, 0x48, 0x54, 0x51, 0x52, 0x53, 0x58, 0x55, 0x56, 0x57,
    0x8C, 0x49, 0xCD, 0xCE, 0xCB, 0xCF, 0xCC, 0xE1, 0x70, 0xDD, 0xDE, 0xDB, 0xDC, 0x8D, 0x8E, 0xDF,
];

pub(crate) fn ebcdic_encode(
    data: &[u8],
    _args: &HashMap<String, String>,
) -> anyhow::Result<Vec<u8>> {
    Ok(data.iter().map(|&b| ASCII_TO_EBCDIC[b as usize]).collect())
}

pub(crate) fn ebcdic_decode(
    data: &[u8],
    _args: &HashMap<String, String>,
) -> anyhow::Result<Vec<u8>> {
    Ok(data.iter().map(|&b| EBCDIC_TO_ASCII[b as usize]).collect())
}

// ---------------------------------------------------------------------------
// hexdump (hexdump -C style)
// ---------------------------------------------------------------------------

pub(crate) fn hexdump_encode(
    input: &[u8],
    args: &HashMap<String, String>,
) -> anyhow::Result<Vec<u8>> {
    let bpl = parse_hexdump_bpl(args)?;
    Ok(hexdump_encode_with(input, bpl))
}

fn hexdump_encode_with(input: &[u8], bpl: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() * 4 + 16);
    let mut offset = 0usize;
    for chunk in input.chunks(bpl) {
        out.extend_from_slice(format!("{:08x}  ", offset).as_bytes());
        let n = chunk.len();
        for (i, &by) in chunk.iter().enumerate() {
            out.extend_from_slice(format!("{:02x} ", by).as_bytes());
            if i == bpl / 2 - 1 {
                out.push(b' ');
            }
        }
        for i in chunk.len()..bpl {
            out.extend_from_slice(b"   ");
            if i == bpl / 2 - 1 {
                out.push(b' ');
            }
        }
        out.push(b'|');
        for &b in chunk {
            out.push(if b.is_ascii_graphic() || b == b' ' {
                b
            } else {
                b'.'
            });
        }
        out.extend_from_slice(b"|\n");
        offset += n;
    }
    out
}

#[derive(Clone, Copy, PartialEq, Eq)]

enum HexdumpDelimiter {
    /// Full `hexdump -C` rows: offset + space-separated hex bytes + ASCII pane.
    Space,
    /// Comma-separated hex bytes, optionally 0x-prefixed.
    Comma,
    /// Bare hex stream decoded two digits per byte.
    None,
}

fn parse_hexdump_delim(args: &HashMap<String, String>) -> anyhow::Result<HexdumpDelimiter> {
    match args
        .get("delimiter")
        .map(|v| v.to_ascii_lowercase())
        .as_deref()
    {
        None | Some("space") | Some("hexdump") | Some("auto") => Ok(HexdumpDelimiter::Space),
        Some("comma") => Ok(HexdumpDelimiter::Comma),
        Some("none") => Ok(HexdumpDelimiter::None),
        Some(other) => anyhow::bail!("{}", i18n::tf("err.hexdump_delim_invalid", &[other])),
    }
}

pub(crate) fn hexdump_decode(
    input: &[u8],
    args: &HashMap<String, String>,
) -> anyhow::Result<Vec<u8>> {
    let delim = parse_hexdump_delim(args)?;
    Ok(hexdump_decode_with(input, delim))
}

fn hexdump_decode_with(input: &[u8], delim: HexdumpDelimiter) -> Vec<u8> {
    match delim {
        HexdumpDelimiter::Space => {
            let mut out = Vec::new();
            for line in input.split(|&b| b == b'\n') {
                hexdump_decode_line(line, &mut out);
            }
            out
        }
        HexdumpDelimiter::Comma => {
            let mut out = Vec::new();
            for tok in input.split(|&b| b == b',') {
                let t: Vec<u8> = tok
                    .iter()
                    .copied()
                    .filter(|b| !b.is_ascii_whitespace())
                    .collect();
                if t.is_empty() {
                    continue;
                }
                let t = if t.len() >= 2 && t[0] == b'0' && (t[1] == b'x' || t[1] == b'X') {
                    &t[2..]
                } else {
                    &t[..]
                };
                if t.len() == 2 && t.iter().all(|b| b.is_ascii_hexdigit()) {
                    out.push((hex_nibble(t[0]) << 4) | hex_nibble(t[1]));
                }
            }
            out
        }
        HexdumpDelimiter::None => {
            let mut out = Vec::new();
            let digits: Vec<u8> = input
                .iter()
                .copied()
                .filter(|b| b.is_ascii_hexdigit())
                .collect();
            for pair in digits.chunks(2) {
                if pair.len() == 2 {
                    out.push((hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]));
                }
            }
            out
        }
    }
}

fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

/// Decode one hexdump line (without trailing '\n'): hex pane only, from the
/// offset through the first '|' (the ASCII pane is dropped).
fn hexdump_decode_line(line: &[u8], out: &mut Vec<u8>) {
    let line = match line.iter().position(|&b| b == b'|') {
        Some(pos) => &line[..pos],
        None => line,
    };
    for tok in line.split(|&b| b.is_ascii_whitespace()) {
        if tok.len() == 2 && tok.iter().all(|b| b.is_ascii_hexdigit()) {
            let hi = (tok[0] as char).to_digit(16).expect("hex digit") as u8;
            let lo = (tok[1] as char).to_digit(16).expect("hex digit") as u8;
            out.push(hi << 4 | lo);
        }
    }
}

/// Streaming hexdump encoder: accumulates a line buffer and flushes one
/// fully-formatted `hexdump -C` row per `bytes_per_line` bytes, carrying the
/// running offset across chunk boundaries so concatenated output is identical
/// to the in-memory path.
struct HexdumpEncodeStream {
    bpl: usize,
    offset: usize,
    buf: Vec<u8>,
}

pub(crate) fn make_hexdump_encode(
    args: &HashMap<String, String>,
) -> anyhow::Result<Box<dyn StreamingOp>> {
    let bpl = parse_hexdump_bpl(args)?;
    Ok(Box::new(HexdumpEncodeStream {
        bpl,
        offset: 0,
        buf: Vec::with_capacity(bpl),
    }))
}

fn parse_hexdump_bpl(args: &HashMap<String, String>) -> anyhow::Result<usize> {
    match args.get("bytes_per_line") {
        None => Ok(16usize),
        Some(v) => {
            let n: usize = v
                .parse()
                .map_err(|_| anyhow::anyhow!("{}", i18n::tf("err.hexdump_bpl_invalid", &["?"])))?;
            if n == 0 || !n.is_multiple_of(8) || n > 64 {
                anyhow::bail!(
                    "{}",
                    i18n::tf("err.hexdump_bpl_invalid", &[n.to_string().as_str()])
                );
            }
            Ok(n)
        }
    }
}

fn hexdump_row(buf: &[u8], bpl: usize, offset: usize, out: &mut Vec<u8>) {
    out.extend_from_slice(format!("{:08x}  ", offset).as_bytes());
    for (i, &by) in buf.iter().enumerate() {
        out.extend_from_slice(format!("{:02x} ", by).as_bytes());
        if i == bpl / 2 - 1 {
            out.push(b' ');
        }
    }
    for i in buf.len()..bpl {
        out.extend_from_slice(b"   ");
        if i == bpl / 2 - 1 {
            out.push(b' ');
        }
    }
    out.push(b'|');
    for &b in buf {
        out.push(if b.is_ascii_graphic() || b == b' ' {
            b
        } else {
            b'.'
        });
    }
    out.extend_from_slice(b"|\n");
}

impl StreamingOp for HexdumpEncodeStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(chunk.len() * 4 + 16);
        for &b in chunk {
            self.buf.push(b);
            if self.buf.len() == self.bpl {
                hexdump_row(&self.buf, self.bpl, self.offset, &mut out);
                self.offset += self.bpl;
                self.buf.clear();
            }
        }
        Ok(out)
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        let mut out = Vec::new();
        if !self.buf.is_empty() {
            hexdump_row(&self.buf, self.bpl, self.offset, &mut out);
            self.buf.clear();
        }
        Ok(out)
    }
}

/// Streaming hexdump decoder: buffers across '\n' boundaries so a line split
/// between chunks still parses identically to the in-memory path.
struct HexdumpDecodeStream {
    pending: Vec<u8>,
    delim: HexdumpDelimiter,
}

pub(crate) fn make_hexdump_decode(
    args: &HashMap<String, String>,
) -> anyhow::Result<Box<dyn StreamingOp>> {
    let delim = parse_hexdump_delim(args)?;
    Ok(Box::new(HexdumpDecodeStream {
        pending: Vec::new(),
        delim,
    }))
}

impl StreamingOp for HexdumpDecodeStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.pending.extend_from_slice(chunk);
        let mut out = Vec::new();
        match self.delim {
            HexdumpDelimiter::Space => {
                let mut start = 0usize;
                for i in 0..self.pending.len() {
                    if self.pending[i] == b'\n' {
                        hexdump_decode_line(&self.pending[start..i], &mut out);
                        start = i + 1;
                    }
                }
                if start > 0 {
                    self.pending.drain(..start);
                }
            }
            HexdumpDelimiter::Comma => {
                // Flush complete comma-separated tokens; keep the tail after the
                // last comma (a byte may span the chunk boundary).
                let split = match self.pending.iter().rposition(|&c| c == b',') {
                    Some(p) => p + 1,
                    None => 0,
                };
                if split > 0 {
                    let head: Vec<u8> = self.pending.drain(..split).collect();
                    out.extend(hexdump_decode_with(&head, HexdumpDelimiter::Comma));
                }
            }
            HexdumpDelimiter::None => {
                // Flush complete byte pairs (even number of hex digits); keep an
                // odd trailing digit for the next chunk.
                let mut consumed = 0usize;
                let mut hex_seen = 0usize;
                for (idx, &b) in self.pending.iter().enumerate() {
                    if b.is_ascii_hexdigit() {
                        hex_seen += 1;
                        if hex_seen.is_multiple_of(2) {
                            consumed = idx + 1;
                        }
                    }
                }
                if consumed > 0 {
                    let head: Vec<u8> = self.pending.drain(..consumed).collect();
                    out.extend(hexdump_decode_with(&head, HexdumpDelimiter::None));
                }
            }
        }
        Ok(out)
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        let tail = std::mem::take(&mut self.pending);
        Ok(hexdump_decode_with(&tail, self.delim))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf8_escape_roundtrip() {
        let data = "中文 a%20b\n".as_bytes();
        let esc = utf8_escape(data, &HashMap::new()).unwrap();
        let s = String::from_utf8(esc.clone()).unwrap();
        assert!(s.contains("%E4") && s.contains("%25") && s.contains("%0A"));
        let dec = utf8_unescape(&esc, &HashMap::new()).unwrap();
        assert_eq!(dec, data);
        // encode_all: printable ASCII is percent-encoded too and roundtrips.
        let mut args = HashMap::new();
        args.insert("encode_all".to_string(), "true".to_string());
        let all = utf8_escape(b"Ab 1", &args).unwrap();
        assert_eq!(all, b"%41%62%20%31");
        assert_eq!(utf8_unescape(&all, &HashMap::new()).unwrap(), b"Ab 1");
        // Stream matches memory under encode_all.
        let mut s = make_utf8_escape(&args).unwrap();
        let mut acc = Vec::new();
        acc.extend_from_slice(&s.write(b"Ab ").unwrap());
        acc.extend_from_slice(&s.write(b"1").unwrap());
        acc.extend_from_slice(&s.finish().unwrap());
        assert_eq!(acc, b"%41%62%20%31");
        // Invalid value rejected.
        let mut bad = HashMap::new();
        bad.insert("encode_all".to_string(), "yesplease".to_string());
        assert!(utf8_escape(b"x", &bad).is_err());
    }

    #[test]
    fn utf8_escape_uppercase_case() {
        // Upper-case hex by default.
        assert_eq!(
            utf8_escape(b"\xff\x01", &HashMap::new()).unwrap(),
            b"%FF%01".to_vec()
        );
        // uppercase=false emits lower-case hex digits.
        let mut lower = HashMap::new();
        lower.insert("uppercase".to_string(), "false".to_string());
        assert_eq!(
            utf8_escape(b"\xff\x01", &lower).unwrap(),
            b"%ff%01".to_vec()
        );
        // Lower-case escapes still unescape to the original bytes.
        let esc = utf8_escape(b"a\xfe", &lower).unwrap();
        assert_eq!(utf8_unescape(&esc, &HashMap::new()).unwrap(), b"a\xfe");
        // Stream matches memory under lowercase.
        let mut s = make_utf8_escape(&lower).unwrap();
        let mut acc = Vec::new();
        acc.extend_from_slice(&s.write(b"\xff").unwrap());
        acc.extend_from_slice(&s.write(b"\x01").unwrap());
        acc.extend_from_slice(&s.finish().unwrap());
        assert_eq!(acc, b"%ff%01".to_vec());
        // Invalid boolean rejected at both entry points.
        let mut bad = HashMap::new();
        bad.insert("uppercase".to_string(), "nope".to_string());
        assert!(utf8_escape(b"x", &bad).is_err());
        assert!(make_utf8_escape(&bad).is_err());
    }

    #[test]
    fn utf8_unescape_stream_matches_memory() {
        let input = b"plain%20text%2Fwith%25escapes%01%ff".to_vec();
        let mut h = make_utf8_unescape(&HashMap::new()).unwrap();
        let mut acc = Vec::new();
        for c in input.chunks(3) {
            acc.extend(h.write(c).unwrap());
        }
        acc.extend(h.finish().unwrap());
        assert_eq!(acc, utf8_unescape(&input, &HashMap::new()).unwrap());
    }

    #[test]
    fn utf8_unescape_rejects_bad_escape() {
        assert!(utf8_unescape(b"%zz", &HashMap::new()).is_err());
        assert!(utf8_unescape(b"ab%2", &HashMap::new()).is_err());
    }

    #[test]
    fn binary_delimiter_parameter() {
        let mut args = HashMap::new();
        args.insert("delimiter".to_string(), "comma".to_string());
        let enc = binary_encode(b"\x01\x02", &args).unwrap();
        assert_eq!(enc, b"00000001,00000010");
        let dec = binary_decode(&enc, &args).unwrap();
        assert_eq!(dec, b"\x01\x02");
        // Default stays delimiter-free (backward compatible).
        assert_eq!(
            binary_encode(b"\x01", &HashMap::new()).unwrap(),
            b"00000001"
        );
        // Stream matches memory path with delimiter.
        let mut stream = make_binary_encode(&args).unwrap();
        let mut acc = Vec::new();
        for part in [&b"\x01"[..], b"\x02".as_slice()] {
            acc.extend_from_slice(&stream.write(part).unwrap());
        }
        acc.extend_from_slice(&stream.finish().unwrap());
        assert_eq!(acc, b"00000001,00000010");
    }

    #[test]
    fn octal_delimiter_parameter() {
        let mut args = HashMap::new();
        args.insert("delimiter".to_string(), "colon".to_string());
        let enc = octal_encode(b"\x0f\x10", &args).unwrap();
        assert_eq!(enc, b"017:020");
        let dec = octal_decode(&enc, &args).unwrap();
        assert_eq!(dec, b"\x0f\x10");
        // Default delimiter-free.
        assert_eq!(octal_encode(b"\x0f", &HashMap::new()).unwrap(), b"017");
        // Stream matches.
        let mut stream = make_octal_encode(&args).unwrap();
        let mut acc = Vec::new();
        for part in [&b"\x0f"[..], b"\x10".as_slice()] {
            acc.extend_from_slice(&stream.write(part).unwrap());
        }
        acc.extend_from_slice(&stream.finish().unwrap());
        assert_eq!(acc, b"017:020");
    }

    #[test]
    fn decimal_delimiter_parameter() {
        // Default is space-separated (backward compatible).
        assert_eq!(
            decimal_encode(b"\x01\xff", &HashMap::new()).unwrap(),
            b"1 255"
        );
        let mut args = HashMap::new();
        args.insert("delimiter".to_string(), "comma".to_string());
        let enc = decimal_encode(b"\x01\xff", &args).unwrap();
        assert_eq!(enc, b"1,255");
        let dec = decimal_decode(&enc, &args).unwrap();
        assert_eq!(dec, b"\x01\xff");
        // Stream encode matches.
        let mut stream = make_decimal_encode(&args).unwrap();
        let mut acc = Vec::new();
        for part in [&b"\x01"[..], b"\xff".as_slice()] {
            acc.extend_from_slice(&stream.write(part).unwrap());
        }
        acc.extend_from_slice(&stream.finish().unwrap());
        assert_eq!(acc, b"1,255");
        // Stream decode across chunk boundary.
        let mut ds = make_decimal_decode(&args).unwrap();
        let mut dacc = Vec::new();
        dacc.extend_from_slice(&ds.write(b"1,").unwrap());
        dacc.extend_from_slice(&ds.write(b"255").unwrap());
        dacc.extend_from_slice(&ds.finish().unwrap());
        assert_eq!(dacc, b"\x01\xff");
    }

    #[test]
    fn binary_known_vector() {
        let enc = binary_encode(b"\x01\x02", &HashMap::new()).unwrap();
        assert_eq!(enc, b"0000000100000010");
        let dec = binary_decode(&enc, &HashMap::new()).unwrap();
        assert_eq!(dec, b"\x01\x02");
        let dec2 = binary_decode(b"0000 0001\n0000 0010", &HashMap::new()).unwrap();
        assert_eq!(dec2, b"\x01\x02");
    }

    #[test]
    fn binary_rejects_bad_input() {
        assert!(binary_decode(b"0000000", &HashMap::new()).is_err());
        assert!(binary_decode(b"00000002", &HashMap::new()).is_err());
    }

    #[test]
    fn binary_ignore_non_alphabet() {
        let mut args = HashMap::new();
        // '2' is not a binary digit: default fails.
        assert!(binary_decode(b"00000002", &args).is_err());
        // With ignore, non-0/1 characters are dropped; "0x0000010z" keeps
        // exactly the 8 bits 00000010 -> 0x02.
        args.insert("ignore_non_alphabet".to_string(), "true".to_string());
        assert_eq!(binary_decode(b"0x0000010z", &args).unwrap(), b"\x02");
        // Trailing garbage that would leave a partial group now succeeds.
        assert_eq!(binary_decode(b"00000001qq", &args).unwrap(), b"\x01");
        // Stream honours the same setting across chunks.
        let mut d = make_binary_decode(&args).unwrap();
        let mut dec = Vec::new();
        for c in [&b"0x000"[..], b"0010z".as_slice()] {
            dec.extend(d.write(c).unwrap());
        }
        dec.extend(d.finish().unwrap());
        assert_eq!(dec, b"\x02");
        // Invalid boolean rejected.
        let mut bad = HashMap::new();
        bad.insert("ignore_non_alphabet".to_string(), "maybe".to_string());
        assert!(binary_decode(b"01", &bad).is_err());
        assert!(make_binary_decode(&bad).is_err());
    }

    #[test]
    fn octal_ignore_non_alphabet() {
        let mut args = HashMap::new();
        assert!(octal_decode(b"077 378", &args).is_err());
        args.insert("ignore_non_alphabet".to_string(), "true".to_string());
        // "07x7 3x77" keeps 077 377 -> 0x3f 0xff.
        assert_eq!(octal_decode(b"07x7 3x77", &args).unwrap(), b"\x3f\xff");
        let mut d = make_octal_decode(&args).unwrap();
        let mut dec = Vec::new();
        for c in [&b"07x"[..], b"7 3x77".as_slice()] {
            dec.extend(d.write(c).unwrap());
        }
        dec.extend(d.finish().unwrap());
        assert_eq!(dec, b"\x3f\xff");
        let mut bad = HashMap::new();
        bad.insert("ignore_non_alphabet".to_string(), "maybe".to_string());
        assert!(octal_decode(b"077", &bad).is_err());
    }

    #[test]
    fn decimal_ignore_non_alphabet() {
        let mut args = HashMap::new();
        assert!(decimal_decode(b"10a", &args).is_err());
        args.insert("ignore_non_alphabet".to_string(), "true".to_string());
        assert_eq!(decimal_decode(b"10a 5x", &args).unwrap(), b"\x0a\x05");
        let mut d = make_decimal_decode(&args).unwrap();
        let mut dec = Vec::new();
        for c in [&b"10a "[..], b"5x".as_slice()] {
            dec.extend(d.write(c).unwrap());
        }
        dec.extend(d.finish().unwrap());
        assert_eq!(dec, b"\x0a\x05");
        let mut bad = HashMap::new();
        bad.insert("ignore_non_alphabet".to_string(), "maybe".to_string());
        assert!(decimal_decode(b"1", &bad).is_err());
    }

    #[test]
    fn binary_stream_matches_memory() {
        let input: Vec<u8> = (0u8..=255).collect();
        let enc_mem = binary_encode(&input, &HashMap::new()).unwrap();
        let mut h = make_binary_encode(&HashMap::new()).unwrap();
        let mut acc = Vec::new();
        for c in input.chunks(7) {
            acc.extend(h.write(c).unwrap());
        }
        acc.extend(h.finish().unwrap());
        assert_eq!(acc, enc_mem);

        let mut d = make_binary_decode(&HashMap::new()).unwrap();
        let mut dec = Vec::new();
        for c in enc_mem.chunks(11) {
            dec.extend(d.write(c).unwrap());
        }
        dec.extend(d.finish().unwrap());
        assert_eq!(dec, input);
    }

    #[test]
    fn octal_known_vector() {
        let enc = octal_encode(b"\x3f\xff", &HashMap::new()).unwrap();
        assert_eq!(enc, b"077377");
        let dec = octal_decode(&enc, &HashMap::new()).unwrap();
        assert_eq!(dec, b"\x3f\xff");
        let dec2 = octal_decode(b"077 377", &HashMap::new()).unwrap();
        assert_eq!(dec2, b"\x3f\xff");
    }

    #[test]
    fn octal_stream_matches_memory() {
        let input: Vec<u8> = (0u8..=200).collect();
        let enc_mem = octal_encode(&input, &HashMap::new()).unwrap();
        let mut d = make_octal_decode(&HashMap::new()).unwrap();
        let mut dec = Vec::new();
        for c in enc_mem.chunks(5) {
            dec.extend(d.write(c).unwrap());
        }
        dec.extend(d.finish().unwrap());
        assert_eq!(dec, input);
    }

    #[test]
    fn decimal_known_vector() {
        let enc = decimal_encode(b"hi", &HashMap::new()).unwrap();
        assert_eq!(enc, b"104 105");
        let dec = decimal_decode(&enc, &HashMap::new()).unwrap();
        assert_eq!(dec, b"hi");
        let dec2 = decimal_decode(b"104,105", &HashMap::new()).unwrap();
        assert_eq!(dec2, b"hi");
    }

    #[test]
    fn decimal_rejects_range() {
        assert!(decimal_decode(b"256", &HashMap::new()).is_err());
        assert!(decimal_decode(b"abc", &HashMap::new()).is_err());
    }

    #[test]
    fn decimal_stream_matches_memory() {
        let input = b"aaa bbb ccc ddd".to_vec();
        let enc_mem = decimal_encode(&input, &HashMap::new()).unwrap();
        let mut d = make_decimal_decode(&HashMap::new()).unwrap();
        let mut dec = Vec::new();
        for c in enc_mem.chunks(6) {
            dec.extend(d.write(c).unwrap());
        }
        dec.extend(d.finish().unwrap());
        assert_eq!(dec, input);
    }

    #[test]
    fn charcode_delimiter_and_base_parameter() {
        // Default stays space-separated decimal (backward compatible).
        assert_eq!(
            charcode_encode("A中".as_bytes(), &HashMap::new()).unwrap(),
            b"65 20013"
        );
        let mut args = HashMap::new();
        args.insert("delimiter".to_string(), "comma".to_string());
        args.insert("base".to_string(), "hex".to_string());
        let enc = charcode_encode("A中".as_bytes(), &args).unwrap();
        assert_eq!(enc, b"0x41,0x4E2D");
        let dec = charcode_decode(&enc, &args).unwrap();
        assert_eq!(dec, "A中".as_bytes());
        // Stream encode matches memory with comma/hex.
        let mut s = make_charcode_encode(&args).unwrap();
        let mut acc = Vec::new();
        for part in ["A".as_bytes(), "中".as_bytes()] {
            acc.extend_from_slice(&s.write(part).unwrap());
        }
        acc.extend_from_slice(&s.finish().unwrap());
        assert_eq!(acc, b"0x41,0x4E2D");
        // Stream decode across a chunk boundary.
        let mut d = make_charcode_decode(&args).unwrap();
        let mut dacc = Vec::new();
        dacc.extend_from_slice(&d.write(b"0x41,").unwrap());
        dacc.extend_from_slice(&d.write(b"0x4E2D").unwrap());
        dacc.extend_from_slice(&d.finish().unwrap());
        assert_eq!(dacc, "A中".as_bytes());
        // Invalid base rejected.
        let mut bad = HashMap::new();
        bad.insert("base".to_string(), "trinary".to_string());
        assert!(charcode_encode(b"A", &bad).is_err());
        assert!(charcode_decode(b"65", &bad).is_err());
    }

    #[test]
    fn charcode_octal_binary_parameter() {
        // Octal roundtrip (space separated, no prefix, like CyberChef).
        let mut oct = HashMap::new();
        oct.insert("base".to_string(), "octal".to_string());
        let enc = charcode_encode("A中".as_bytes(), &oct).unwrap();
        assert_eq!(enc, b"101 47055");
        let dec = charcode_decode(&enc, &oct).unwrap();
        assert_eq!(dec, "A中".as_bytes());
        // Stream decode with octal across a chunk boundary.
        let mut d = make_charcode_decode(&oct).unwrap();
        let mut dacc = Vec::new();
        dacc.extend_from_slice(&d.write(b"101 ").unwrap());
        dacc.extend_from_slice(&d.write(b"47055").unwrap());
        dacc.extend_from_slice(&d.finish().unwrap());
        assert_eq!(dacc, "A中".as_bytes());
        // Binary roundtrip.
        let mut bin = HashMap::new();
        bin.insert("base".to_string(), "bin".to_string());
        let benc = charcode_encode("AB".as_bytes(), &bin).unwrap();
        assert_eq!(benc, b"1000001 1000010");
        let bdec = charcode_decode(&benc, &bin).unwrap();
        assert_eq!(bdec, "AB".as_bytes());
        // Hex base accepts bare hex tokens without the 0x prefix.
        let mut hx = HashMap::new();
        hx.insert("base".to_string(), "hex".to_string());
        assert_eq!(charcode_decode(b"41 4E2D", &hx).unwrap(), "A中".as_bytes());
    }

    #[test]
    fn charcode_known_vector() {
        let enc = charcode_encode("A中".as_bytes(), &HashMap::new()).unwrap();
        assert_eq!(enc, b"65 20013");
        let dec = charcode_decode(&enc, &HashMap::new()).unwrap();
        assert_eq!(dec, "A中".as_bytes());
        let dec2 = charcode_decode(b"0x41 20013", &HashMap::new()).unwrap();
        assert_eq!(dec2, "A中".as_bytes());
    }

    #[test]
    fn charcode_rejects_invalid() {
        assert!(charcode_decode(b"99999999", &HashMap::new()).is_err());
        assert!(charcode_decode(b"zz", &HashMap::new()).is_err());
    }

    #[test]
    fn charcode_stream_matches_memory() {
        let input = "hello 中文 mixed".as_bytes().to_vec();
        let enc_mem = charcode_encode(&input, &HashMap::new()).unwrap();
        let mut h = make_charcode_encode(&HashMap::new()).unwrap();
        let mut acc = Vec::new();
        for c in input.chunks(3) {
            acc.extend(h.write(c).unwrap());
        }
        acc.extend(h.finish().unwrap());
        assert_eq!(acc, enc_mem);

        let mut d = make_charcode_decode(&HashMap::new()).unwrap();
        let mut dec = Vec::new();
        for c in enc_mem.chunks(5) {
            dec.extend(d.write(c).unwrap());
        }
        dec.extend(d.finish().unwrap());
        assert_eq!(dec, input);
    }

    #[test]
    fn hexdump_roundtrip() {
        let data = b"Hello\x00\xff\x10world!";
        let enc = hexdump_encode(data, &HashMap::new()).unwrap();
        let s = String::from_utf8(enc.clone()).unwrap();
        assert!(
            s.starts_with("00000000  48 65 6c 6c 6f 00 ff 10  77 6f 72 6c 64 21"),
            "got: {}",
            s
        );
        let dec = hexdump_decode(&enc, &HashMap::new()).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn hexdump_decode_tolerates_offset_and_ascii() {
        let s = b"00000000  61 62 63  |abc|\n00000010  64 65 66  |def|";
        assert_eq!(hexdump_decode(s, &HashMap::new()).unwrap(), b"abcdef");
    }

    #[test]
    fn hexdump_decode_delimiter_parameter() {
        // Comma-separated bytes, optionally 0x-prefixed.
        let mut comma = HashMap::new();
        comma.insert("delimiter".to_string(), "comma".to_string());
        assert_eq!(hexdump_decode(b"61,62,63", &comma).unwrap(), b"abc");
        assert_eq!(hexdump_decode(b"0x61, 0x62, 0x63", &comma).unwrap(), b"abc");
        // Bare hex stream, two digits per byte.
        let mut none = HashMap::new();
        none.insert("delimiter".to_string(), "none".to_string());
        assert_eq!(hexdump_decode(b"616263", &none).unwrap(), b"abc");
        // Odd trailing digit is dropped (incomplete byte).
        assert_eq!(hexdump_decode(b"616263a", &none).unwrap(), b"abc");
        // Default space mode still parses hexdump -C rows (backward compatible).
        assert_eq!(
            hexdump_decode(b"00000000  61 62 63  |abc|", &HashMap::new()).unwrap(),
            b"abc"
        );
        // Invalid delimiter rejected in both memory and streaming paths.
        let mut bad = HashMap::new();
        bad.insert("delimiter".to_string(), "tab".to_string());
        assert!(hexdump_decode(b"61", &bad).is_err());
        assert!(make_hexdump_decode(&bad).is_err());
        // Streaming comma decode across chunk boundaries.
        let mut d = make_hexdump_decode(&comma).unwrap();
        let mut acc = Vec::new();
        acc.extend_from_slice(&d.write(b"61,6").unwrap());
        acc.extend_from_slice(&d.write(b"2,63").unwrap());
        acc.extend_from_slice(&d.finish().unwrap());
        assert_eq!(acc, b"abc");
        // Streaming bare-hex decode across an odd-digit boundary.
        let mut n = make_hexdump_decode(&none).unwrap();
        let mut nacc = Vec::new();
        nacc.extend_from_slice(&n.write(b"616").unwrap());
        nacc.extend_from_slice(&n.write(b"263").unwrap());
        nacc.extend_from_slice(&n.finish().unwrap());
        assert_eq!(nacc, b"abc");
    }

    #[test]
    fn utf16_encode_decode_roundtrip() {
        let cases: &[(&str, &str)] = &[
            ("", ""),
            ("hello", "hello"),
            ("A", "A"),
            ("dpa", "dpa"),
            ("你好", "你好"),
            ("a😀b", "a😀b"),
            ("𝕏𝔸", "𝕏𝔸"),
        ];
        for &(src, want) in cases {
            for endian in ["le", "be"] {
                let mut args = HashMap::new();
                args.insert("endian".to_string(), endian.to_string());
                let enc = utf16_encode(src.as_bytes(), &args).unwrap();
                let dec = utf16_decode(&enc, &args).unwrap();
                assert_eq!(
                    String::from_utf8(dec).unwrap(),
                    want,
                    "roundtrip {endian} {src}"
                );
            }
        }
    }

    #[test]
    fn utf16_bom_detection_and_emit() {
        let mut args = HashMap::new();
        args.insert("bom".to_string(), "true".to_string());
        args.insert("endian".to_string(), "be".to_string());
        let enc = utf16_encode("hi".as_bytes(), &args).unwrap();
        assert_eq!(&enc[..2], &[0xFE, 0xFF]);
        // Decode with default LE + BOM detection: BE BOM must override endian.
        let dec_args = HashMap::new();
        let dec = utf16_decode(&enc, &dec_args).unwrap();
        assert_eq!(String::from_utf8(dec).unwrap(), "hi");
        // BOM not stripped: default LE reads FE FF as U+FFFE (UTF-8 EF BF BE).
        let mut no_bom = HashMap::new();
        no_bom.insert("bom".to_string(), "false".to_string());
        let raw = utf16_decode(&enc, &no_bom).unwrap();
        assert_eq!(&raw[..3], &[0xEF, 0xBF, 0xBE]);
    }

    #[test]
    fn utf16_decode_errors() {
        // Odd length.
        let args = HashMap::new();
        let mut odd = HashMap::new();
        odd.insert("bom".to_string(), "false".to_string());
        assert!(utf16_decode(&[0x41, 0x00, 0x42], &odd).is_err());
        // Lone high surrogate (BE 0xD800 followed by 0x0000).
        let lone_hi = vec![0xD8u8, 0x00, 0x00, 0x00];
        let mut lone_args = HashMap::new();
        lone_args.insert("endian".to_string(), "be".to_string());
        lone_args.insert("bom".to_string(), "false".to_string());
        assert!(utf16_decode(&lone_hi, &lone_args).is_err());
        // Lone low surrogate (BE 0xDC00 followed by 0x0000).
        let lone_lo = vec![0xDCu8, 0x00, 0x00, 0x00];
        assert!(utf16_decode(&lone_lo, &lone_args).is_err());
        // Invalid UTF-8 on encode.
        let bad = vec![0xC3, 0x28];
        assert!(utf16_encode(&bad, &args).is_err());
        // Invalid endian.
        let mut bad_endian = HashMap::new();
        bad_endian.insert("endian".to_string(), "weird".to_string());
        assert!(utf16_encode(b"x", &bad_endian).is_err());
    }

    #[test]
    fn utf16_encode_stream_matches_memory() {
        let text = "Hello 你好 😀 𝕏𝔸 tail";
        let data = text.as_bytes();
        let mut args = HashMap::new();
        args.insert("endian".to_string(), "be".to_string());
        args.insert("bom".to_string(), "true".to_string());
        let mem = utf16_encode(data, &args).unwrap();
        let mut s = make_utf16_encode(&args).unwrap();
        let mut got = Vec::new();
        for i in (0..data.len()).step_by(3) {
            let end = (i + 3).min(data.len());
            got.extend_from_slice(&s.write(&data[i..end]).unwrap());
        }
        got.extend_from_slice(&s.finish().unwrap());
        assert_eq!(got, mem);
    }

    #[test]
    fn utf16_decode_stream_matches_memory() {
        let text = "Hello 你好 😀 𝕏𝔸 tail";
        let mut enc_args = HashMap::new();
        enc_args.insert("endian".to_string(), "be".to_string());
        enc_args.insert("bom".to_string(), "true".to_string());
        let data = utf16_encode(text.as_bytes(), &enc_args).unwrap();
        // Default decode args: LE + BOM auto-detect.
        let mem = utf16_decode(&data, &HashMap::new()).unwrap();
        let mut s = make_utf16_decode(&HashMap::new()).unwrap();
        let mut got = Vec::new();
        for i in (0..data.len()).step_by(2) {
            let end = (i + 2).min(data.len());
            got.extend_from_slice(&s.write(&data[i..end]).unwrap());
        }
        got.extend_from_slice(&s.finish().unwrap());
        assert_eq!(got, mem);
        assert_eq!(String::from_utf8(got).unwrap(), text);
    }

    #[test]
    fn utf16_decode_stream_split_surrogate_and_bom() {
        // Feed a BE BOM one byte at a time, then a surrogate pair split mid-way.
        let mut enc_args = HashMap::new();
        enc_args.insert("endian".to_string(), "be".to_string());
        enc_args.insert("bom".to_string(), "true".to_string());
        let data = utf16_encode("😀".as_bytes(), &enc_args).unwrap(); // BOM + D83D DE00
        let mut s = make_utf16_decode(&HashMap::new()).unwrap();
        let mut got = Vec::new();
        for b in &data {
            got.extend_from_slice(&s.write(&[*b]).unwrap());
        }
        got.extend_from_slice(&s.finish().unwrap());
        assert_eq!(String::from_utf8(got).unwrap(), "😀");
    }

    #[test]
    fn utf16_empty_input_bom() {
        let mut args = HashMap::new();
        args.insert("bom".to_string(), "true".to_string());
        args.insert("endian".to_string(), "le".to_string());
        let enc = utf16_encode(b"", &args).unwrap();
        assert_eq!(enc, vec![0xFF, 0xFE]);
        let mut s = make_utf16_encode(&args).unwrap();
        let mut got = Vec::new();
        got.extend_from_slice(&s.write(b"").unwrap());
        got.extend_from_slice(&s.finish().unwrap());
        assert_eq!(got, vec![0xFF, 0xFE]);
    }

    #[test]
    fn hexdump_encode_stream_matches_memory() {
        let data: Vec<u8> = (0u32..97).map(|i| (i * 7 + 3) as u8).collect();
        let mut args = HashMap::new();
        args.insert("bytes_per_line".to_string(), "16".to_string());
        let mem = hexdump_encode(&data, &args).unwrap();
        // Split at every possible boundary to exercise cross-chunk rows.
        for split in [1usize, 7, 15, 16, 17, 31, 63, 96, 97] {
            let mut s = make_hexdump_encode(&args).unwrap();
            let mut out = Vec::new();
            out.extend(s.write(&data[..split]).unwrap());
            out.extend(s.write(&data[split..]).unwrap());
            out.extend(s.finish().unwrap());
            assert_eq!(out, mem, "split={}", split);
        }
        // Non-default bytes_per_line (32): empty tail row still matches.
        let mut args32 = HashMap::new();
        args32.insert("bytes_per_line".to_string(), "32".to_string());
        let mem32 = hexdump_encode(&data, &args32).unwrap();
        let mut s = make_hexdump_encode(&args32).unwrap();
        let mut out = Vec::new();
        for c in data.chunks(13) {
            out.extend(s.write(c).unwrap());
        }
        out.extend(s.finish().unwrap());
        assert_eq!(out, mem32);
        // Invalid bytes_per_line rejected at stream construction too.
        let mut bad = HashMap::new();
        bad.insert("bytes_per_line".to_string(), "10".to_string());
        assert!(make_hexdump_encode(&bad).is_err());
        bad.insert("bytes_per_line".to_string(), "abc".to_string());
        assert!(make_hexdump_encode(&bad).is_err());
    }

    #[test]
    fn hexdump_decode_stream_matches_memory() {
        let data: Vec<u8> = (0u32..129).map(|i| (i * 11 + 1) as u8).collect();
        let mut args = HashMap::new();
        args.insert("bytes_per_line".to_string(), "16".to_string());
        let enc = hexdump_encode(&data, &args).unwrap();
        let mem = hexdump_decode(&enc, &HashMap::new()).unwrap();
        assert_eq!(mem, data);
        // Chunks that split mid-line still decode identically.
        for split in [1usize, 5, 16, 33, 60, 61, 120, 200, 500] {
            let split = split.min(enc.len());
            let mut s = make_hexdump_decode(&HashMap::new()).unwrap();
            let mut out = Vec::new();
            out.extend(s.write(&enc[..split]).unwrap());
            out.extend(s.write(&enc[split..]).unwrap());
            out.extend(s.finish().unwrap());
            assert_eq!(out, data, "split={}", split);
        }
        // Multiple lines arriving in one chunk produce the same result.
        let mut s = make_hexdump_decode(&HashMap::new()).unwrap();
        let mut out = s.write(&enc).unwrap();
        out.extend(s.finish().unwrap());
        assert_eq!(out, data);
    }

    #[test]
    fn hexdump_bytes_per_line_parameter() {
        let data = b"0123456789abcdef";
        // Default 16 -> single line.
        let enc16 = hexdump_encode(data, &HashMap::new()).unwrap();
        let newlines = enc16.iter().filter(|&&b| b == b'\n').count();
        assert_eq!(newlines, 1);
        // bytes_per_line=8 -> two lines; offset advances by 8.
        let mut args = HashMap::new();
        args.insert("bytes_per_line".to_string(), "8".to_string());
        let enc8 = hexdump_encode(data, &args).unwrap();
        let lines: Vec<&[u8]> = enc8
            .split(|&b| b == b'\n')
            .filter(|l| !l.is_empty())
            .collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with(b"00000000"));
        assert!(lines[1].starts_with(b"00000008"));
        // Decode is bpl-agnostic.
        assert_eq!(hexdump_decode(&enc8, &HashMap::new()).unwrap(), data);
        // Invalid values rejected.
        let mut bad = HashMap::new();
        bad.insert("bytes_per_line".to_string(), "7".to_string());
        assert!(hexdump_encode(data, &bad).is_err());
        let mut bad2 = HashMap::new();
        bad2.insert("bytes_per_line".to_string(), "128".to_string());
        assert!(hexdump_encode(data, &bad2).is_err());
        let mut bad3 = HashMap::new();
        bad3.insert("bytes_per_line".to_string(), "abc".to_string());
        assert!(hexdump_encode(data, &bad3).is_err());
    }

    #[test]
    fn hexdump_empty() {
        assert_eq!(hexdump_encode(b"", &HashMap::new()).unwrap(), b"");
        assert_eq!(hexdump_decode(b"", &HashMap::new()).unwrap(), b"");
    }

    #[test]
    fn ebcdic_known_vectors() {
        // cp037: A->0xC1, B->0xC2, C->0xC3, a->0x81, 0->0xF0, space->0x40.
        assert_eq!(
            ebcdic_encode(b"ABC", &HashMap::new()).unwrap(),
            [0xC1, 0xC2, 0xC3]
        );
        assert_eq!(
            ebcdic_encode(b"abc012 ", &HashMap::new()).unwrap(),
            [0x81, 0x82, 0x83, 0xF0, 0xF1, 0xF2, 0x40]
        );
        assert_eq!(
            ebcdic_decode(&[0xC1, 0xC2, 0xC3], &HashMap::new()).unwrap(),
            b"ABC"
        );
        // Round-trip both directions.
        let data = b"Hello, EBCDIC 123!";
        assert_eq!(
            ebcdic_decode(
                &ebcdic_encode(data, &HashMap::new()).unwrap(),
                &HashMap::new()
            )
            .unwrap(),
            data
        );
        assert_eq!(
            ebcdic_encode(
                &ebcdic_decode(data, &HashMap::new()).unwrap(),
                &HashMap::new()
            )
            .unwrap(),
            data
        );
    }
}
