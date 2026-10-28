//! Codec family: base encodings (base16/hex, base32, base45, base58, base62, base64, base85).

use std::collections::HashMap;

use super::{
    HexDelimiter, StreamingOp, hex_delim_bytes, hex_digit_lower, hex_digit_upper, hex_val,
    parse_bool, parse_hex_args, parse_hex_bpl, parse_hex_ignore,
};
use crate::i18n;

// ---------------------------------------------------------------------------
// Streaming implementation: block-wise incremental processing; cross-chunk state lives inside each struct.
// Correctness: for the same input, write+finish total output == in-memory run output.
// ---------------------------------------------------------------------------

/// Base64 alphabet presets, kept as CyberChef-style range strings so the same
/// expander handles both presets and custom alphabets. Each entry expands to
/// 64 chars (payload only; padding defaults to '=') or 65 chars (payload + the
/// 65th char is the padding char, e.g. y64 pads with '-' and Atom128 with 'C').
/// Names match CyberChef's ALPHABET_OPTIONS semantics; matching is case-insensitive.
const B64_PRESETS: &[(&str, &str)] = &[
    ("standard", "A-Za-z0-9+/="),
    ("url", "A-Za-z0-9-_="),
    ("url-safe", "A-Za-z0-9-_="),
    ("filename-safe", "A-Za-z0-9+\\-="),
    ("itoa64", "./0-9A-Za-z="),
    ("xml", "A-Za-z0-9_."),
    ("y64", "A-Za-z0-9._-"),
    ("z64", "0-9a-zA-Z+/="),
    ("radix64", "0-9A-Za-z+/="),
    ("uuencode", " -_"),
    ("xxencode", "+\\-0-9A-Za-z"),
    ("binhex", "!-,-0-689@A-NP-VX-Z[`a-fh-mp-r"),
    ("rot13", "N-ZA-Mn-za-m0-9+/="),
    ("crypt", "./0-9A-Za-z"),
    (
        "atom128",
        "/128GhIoPQROSTeUbADfgHijKLM+n0pFWXY456xyzB7=39VaqrstJklmNuZvwcdEC",
    ),
    (
        "megan35",
        "3GHIJKLMNOPQRSTUb=cdefghijklmnopWXYZ/12+406789VaqrstuvwxyzABCDEF5",
    ),
    (
        "zong22",
        "ZKj9n+yf0wDVX1s/5YbdxSo=ILaUpPBCHg8uvNO4klm6iJGhQ7eFrWczAMEq3RTt2",
    ),
    (
        "hazz15",
        "HNO4klm6ij9n+J2hyf0gzA8uvwDEq3X1Q7ZKeFrWcVTts/MRGYbdxSo=ILaUpPBC5",
    ),
];

/// A Base64 alphabet: 64 payload chars, a padding char, whether the alphabet
/// explicitly carries a padding char (65-char alphabets), and a 256-entry
/// reverse table (0..=63 value, -1 invalid, -2 padding).
#[derive(Clone)]

struct B64Alphabet {
    chars: Vec<u8>,
    pad: u8,
    has_pad: bool,
    rev: Vec<i8>,
}

impl B64Alphabet {
    fn from_plain(chars: &[u8], pad: u8, has_pad: bool) -> B64Alphabet {
        let mut rev = vec![-1i8; 256];
        for (i, &c) in chars.iter().enumerate() {
            rev[c as usize] = i as i8;
        }
        if has_pad {
            rev[pad as usize] = -2;
        }
        B64Alphabet {
            chars: chars.to_vec(),
            pad,
            has_pad,
            rev,
        }
    }

    /// Parse the `alphabet` argument: a preset name (see B64_PRESETS) or a
    /// custom 64/65-char alphabet. Range expressions (A-Z, a-z, 0-9, !-, ...)
    /// and `\-` escapes are expanded first, mirroring CyberChef's expandAlphRange.
    /// 65 chars => the 65th char is the pad; 64 chars => `pad_opt` or '='.
    fn parse(alphabet: &str, pad_opt: Option<u8>) -> anyhow::Result<B64Alphabet> {
        let lower = alphabet.to_ascii_lowercase();
        let raw = B64_PRESETS
            .iter()
            .find(|(n, _)| *n == lower)
            .map(|(_, s)| *s)
            .unwrap_or(alphabet);
        let expanded = expand_alph_range(raw)?;
        let (chars, pad, has_pad) = match expanded.len() {
            64 => {
                let has_pad = pad_opt.is_some();
                (expanded, pad_opt.unwrap_or(b'='), has_pad)
            }
            65 => (expanded[..64].to_vec(), expanded[64], true),
            n => anyhow::bail!(
                "{}",
                i18n::tf("err.base64_alphabet_len", &[n.to_string().as_str()])
            ),
        };
        // Payload chars must be unique so the reverse table is unambiguous.
        let mut seen = [false; 256];
        for &c in &chars {
            if seen[c as usize] {
                anyhow::bail!("{}", i18n::t("err.base64_dup_char"));
            }
            seen[c as usize] = true;
        }
        Ok(B64Alphabet::from_plain(&chars, pad, has_pad))
    }

    fn is_pad(&self, c: u8) -> bool {
        self.rev[c as usize] == -2
    }
}

/// Expand range expressions like `A-Za-z0-9+/=`, `!-,` or ` -_` into the full
/// character run, and `\-` escapes into a literal dash. A range is any ASCII
/// byte pair `X-Y` (X not `\`) with X <= Y (ascending code points); anything
/// else is kept literally. Mirrors CyberChef's expandAlphRange, but descending
/// ranges are a hard error instead of silently producing nothing.
fn expand_alph_range(s: &str) -> anyhow::Result<Vec<u8>> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0usize;
    while i < b.len() {
        let c = b[i];
        if c == b'\\' && i + 1 < b.len() && b[i + 1] == b'-' {
            out.push(b'-');
            i += 2;
            continue;
        }
        if i + 2 < b.len() && b[i + 1] == b'-' && c != b'\\' && b[i + 2] != b'\\' {
            if c > b[i + 2] {
                anyhow::bail!("{}", i18n::t("err.base64_bad_range"));
            }
            for v in c..=b[i + 2] {
                out.push(v);
            }
            i += 3;
            continue;
        }
        out.push(c);
        i += 1;
    }
    Ok(out)
}

/// Streaming Base64 encode: emits 4 chars per 3 bytes; the tail is padded in finish.
struct B64EncodeStream {
    alphabet: B64Alphabet,
    pending: Vec<u8>,
}

fn parse_b64_alphabet(args: &HashMap<String, String>) -> anyhow::Result<B64Alphabet> {
    let alph = args
        .get("alphabet")
        .map(String::as_str)
        .unwrap_or("standard");
    let pad = args.get("pad").and_then(|p| p.as_bytes().first().copied());
    B64Alphabet::parse(alph, pad)
}

pub(crate) fn make_base64_encode(
    args: &HashMap<String, String>,
) -> anyhow::Result<Box<dyn StreamingOp>> {
    Ok(Box::new(B64EncodeStream {
        alphabet: parse_b64_alphabet(args)?,
        pending: Vec::new(),
    }))
}

pub(crate) fn make_base64url_encode(
    _args: &HashMap<String, String>,
) -> anyhow::Result<Box<dyn StreamingOp>> {
    Ok(Box::new(B64EncodeStream {
        alphabet: B64Alphabet::parse("url", None)?,
        pending: Vec::new(),
    }))
}

impl StreamingOp for B64EncodeStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.pending.extend_from_slice(chunk);
        let groups = self.pending.len() / 3 * 3;
        let mut out = Vec::with_capacity(groups / 3 * 4);
        for g in self
            .pending
            .drain(..groups)
            .collect::<Vec<_>>()
            .as_chunks::<3>()
            .0
        {
            let b0 = g[0];
            let b1 = g[1];
            let b2 = g[2];
            out.push(self.alphabet.chars[(b0 >> 2) as usize]);
            out.push(self.alphabet.chars[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize]);
            out.push(self.alphabet.chars[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize]);
            out.push(self.alphabet.chars[(b2 & 0x3f) as usize]);
        }
        Ok(out)
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(4);
        match self.pending.len() {
            0 => {}
            1 => {
                let b0 = self.pending[0];
                out.push(self.alphabet.chars[(b0 >> 2) as usize]);
                out.push(self.alphabet.chars[((b0 & 0x03) << 4) as usize]);
                if self.alphabet.has_pad {
                    out.push(self.alphabet.pad);
                    out.push(self.alphabet.pad);
                }
            }
            2 => {
                let b0 = self.pending[0];
                let b1 = self.pending[1];
                out.push(self.alphabet.chars[(b0 >> 2) as usize]);
                out.push(self.alphabet.chars[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize]);
                out.push(self.alphabet.chars[((b1 & 0x0f) << 2) as usize]);
                if self.alphabet.has_pad {
                    out.push(self.alphabet.pad);
                }
            }
            _ => unreachable!("pending length is at most 2"),
        }
        self.pending.clear();
        Ok(out)
    }
}

/// Streaming Base64 decode: decodes 3 bytes per 4 chars; the tail is handled in finish
/// (whitespace and missing padding tolerated; `ignore_non_alphabet` drops other stray chars).
struct B64DecodeStream {
    alphabet: B64Alphabet,
    ignore_non_alph: bool,
    strict: bool,
    pending: Vec<u8>,
    /// Total bytes fed so far; lets error messages report offsets into the
    /// original input even when the offending char only surfaces in finish()
    /// (offsets are still byte-exact for ASCII alphabets).
    total_in: usize,
}

pub(crate) fn make_base64_decode(
    args: &HashMap<String, String>,
) -> anyhow::Result<Box<dyn StreamingOp>> {
    let ignore = parse_bool(args.get("ignore_non_alphabet"))?;
    // Strict by default: padding, when present, must sit at the
    // very end and complete a group; set strict_mode=false for lenient input.
    let strict = match args.get("strict_mode") {
        Some(v) => parse_bool(Some(v))?,
        None => true,
    };
    Ok(Box::new(B64DecodeStream {
        alphabet: parse_b64_alphabet(args)?,
        ignore_non_alph: ignore,
        strict,
        pending: Vec::new(),
        total_in: 0,
    }))
}

pub(crate) fn make_base64url_decode(
    args: &HashMap<String, String>,
) -> anyhow::Result<Box<dyn StreamingOp>> {
    let alph = match args.get("alphabet") {
        Some(a) => B64Alphabet::parse(a, None)?,
        None => B64Alphabet::parse("url", None)?,
    };
    let ignore = parse_bool(args.get("ignore_non_alphabet"))?;
    // Strict by default: padding, when present, must sit at the
    // very end and complete a group; set strict_mode=false for lenient input.
    let strict = match args.get("strict_mode") {
        Some(v) => parse_bool(Some(v))?,
        None => true,
    };
    Ok(Box::new(B64DecodeStream {
        alphabet: alph,
        ignore_non_alph: ignore,
        strict,
        pending: Vec::new(),
        total_in: 0,
    }))
}

impl StreamingOp for B64DecodeStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        // `chunk_start` is the pending-buffer length before this chunk is
        // appended; buffered tail bytes were already counted in previous
        // writes, so `base` is the input offset of this chunk's first byte.
        let chunk_start = self.pending.len();
        self.pending.extend_from_slice(chunk);
        let base = self.total_in - chunk_start;
        let mut out = Vec::new();
        let mut idx = 0usize;
        // (byte, input offset): offsets are carried along so decode errors
        // can report the exact position ("at offset N").
        let mut chars: Vec<(u8, usize)> = Vec::with_capacity(4);
        let n = self.pending.len();
        // Index in `pending` just past the last fully decoded 4-char group.
        // Skipped whitespace/ignored chars before it are dropped too; anything
        // after it stays buffered for the next write / finish. Relying on
        // `idx - chars.len()` here would over-drain whenever a whitespace or
        // ignored char sits before the incomplete tail; the tail
        // char was silently lost and finish() could no longer reject it).
        let mut last_decoded_end = 0usize;
        while idx < n {
            let c = self.pending[idx];
            if c.is_ascii_whitespace()
                && !(self.alphabet.is_pad(c) || self.alphabet.rev[c as usize] >= 0)
            {
                idx += 1;
                continue;
            }
            if !self.alphabet.is_pad(c) && self.alphabet.rev[c as usize] < 0 {
                if self.ignore_non_alph {
                    idx += 1;
                    continue;
                }
                return Err(anyhow::anyhow!(
                    "{}",
                    i18n::tf("err.base64_invalid", &[(base + idx).to_string().as_str()])
                ));
            }
            chars.push((c, base + idx));
            if chars.len() == 4 {
                decode_group(&chars, &self.alphabet, &mut out)?;
                chars.clear();
                last_decoded_end = idx + 1;
            }
            idx += 1;
        }
        // Consume only complete groups; keep an incomplete tail for the next write / finish.
        self.pending.drain(..last_decoded_end);
        self.total_in += chunk.len();
        Ok(out)
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        // `pending_start`: input offset of the first buffered byte.
        let pending_start = self.total_in - self.pending.len();
        let cleaned: Vec<(u8, usize)> = self
            .pending
            .iter()
            .enumerate()
            .filter(|&(_, c)| {
                if c.is_ascii_whitespace() {
                    // Keep whitespace that is part of the alphabet (uuencode's space).
                    return self.alphabet.is_pad(*c) || self.alphabet.rev[*c as usize] >= 0;
                }
                if !self.alphabet.is_pad(*c) && self.alphabet.rev[*c as usize] < 0 {
                    // ignore=true drops the char; ignore=false keeps it so the decoder reports it.
                    return !self.ignore_non_alph;
                }
                true
            })
            .map(|(i, c)| (*c, pending_start + i))
            .collect();
        let mut out = Vec::new();
        if self.strict {
            check_b64_strict(&cleaned, &self.alphabet)?;
        }
        match cleaned.len() % 4 {
            0 => {}
            1 => {
                let off = cleaned.last().map(|&(_, o)| o).unwrap_or(pending_start);
                anyhow::bail!(
                    "{}",
                    i18n::tf("err.base64_tail", &[off.to_string().as_str()])
                )
            }
            n => decode_tail(&cleaned[..n], &self.alphabet, &mut out)?,
        }
        self.pending.clear();
        Ok(out)
    }
}

/// CyberChef strictMode checks, applied to the cleaned input (whitespace and
/// ignore-flagged chars already removed): a 4n+1 length is always rejected;
/// alphabets carrying an explicit pad additionally require padding to be at the
/// very end (last 1-2 chars, all pads) and the length to be a multiple of 4.
fn check_b64_strict(cleaned: &[(u8, usize)], alphabet: &B64Alphabet) -> anyhow::Result<()> {
    if cleaned.len() % 4 == 1 {
        let off = cleaned.last().map(|&(_, o)| o).unwrap_or(0);
        anyhow::bail!(
            "{}",
            i18n::tf("err.base64_strict_len", &[off.to_string().as_str()])
        );
    }
    // Padding checks apply only when padding is actually present (aligns with
    // CyberChef: `padPos >= 0` gates both the position and the length checks).
    if alphabet.has_pad
        && let Some((p, poff)) = cleaned
            .iter()
            .enumerate()
            .find(|&(_, &(c, _))| alphabet.is_pad(c))
            .map(|(i, &(_, o))| (i, o))
    {
        if p + 2 < cleaned.len() || cleaned.last().map(|&(c, _)| c) != Some(alphabet.pad) {
            anyhow::bail!(
                "{}",
                i18n::tf("err.base64_strict_pad_pos", &[poff.to_string().as_str()])
            );
        }
        if !cleaned.len().is_multiple_of(4) {
            anyhow::bail!(
                "{}",
                i18n::tf("err.base64_strict_pad_len", &[poff.to_string().as_str()])
            );
        }
    }
    Ok(())
}

/// Decode a final tail of 2 or 3 Base64 chars (padding inside the tail is an error).
fn decode_tail(
    chars: &[(u8, usize)],
    alphabet: &B64Alphabet,
    out: &mut Vec<u8>,
) -> anyhow::Result<()> {
    let mut vals = [0u8; 4];
    let mut n = 0usize;
    for &(c, off) in chars {
        if alphabet.is_pad(c) {
            return Err(anyhow::anyhow!(
                "{}",
                i18n::tf("err.base64_padding", &[off.to_string().as_str()])
            ));
        }
        let v = alphabet.rev[c as usize];
        if v < 0 {
            return Err(anyhow::anyhow!(
                "{}",
                i18n::tf("err.base64_invalid", &[off.to_string().as_str()])
            ));
        }
        vals[n] = v as u8;
        n += 1;
    }
    match n {
        2 => out.push((vals[0] << 2) | (vals[1] >> 4)),
        3 => {
            out.push((vals[0] << 2) | (vals[1] >> 4));
            out.push((vals[1] << 4) | (vals[2] >> 2));
        }
        _ => unreachable!(),
    }
    Ok(())
}

/// Decode a group of 4 Base64 chars (trailing pad allowed).
fn decode_group(
    chars: &[(u8, usize)],
    alphabet: &B64Alphabet,
    out: &mut Vec<u8>,
) -> anyhow::Result<()> {
    debug_assert_eq!(chars.len(), 4);
    // Count valid chars (before any pad). Once a pad appears, only further
    // pads may follow inside the group; any non-pad char after a pad is
    // invalid and would otherwise be silently dropped by the streaming
    // writer (e.g. "ab=c" -> 'i').
    let mut vals = [0u8; 4];
    let mut n = 0usize;
    for (i, &(c, off)) in chars.iter().enumerate() {
        if alphabet.is_pad(c) {
            if chars[i + 1..].iter().any(|&(x, _)| !alphabet.is_pad(x)) {
                let bad = chars[i + 1..]
                    .iter()
                    .find(|&&(x, _)| !alphabet.is_pad(x))
                    .map(|&(_, o)| o)
                    .unwrap_or(off);
                return Err(anyhow::anyhow!(
                    "{}",
                    i18n::tf("err.base64_padding", &[bad.to_string().as_str()])
                ));
            }
            break;
        }
        let v = alphabet.rev[c as usize];
        if v < 0 {
            return Err(anyhow::anyhow!(
                "{}",
                i18n::tf("err.base64_invalid", &[off.to_string().as_str()])
            ));
        }
        vals[n] = v as u8;
        n += 1;
    }
    if n == 0 {
        let off = chars[0].1;
        return Err(anyhow::anyhow!(
            "{}",
            i18n::tf("err.base64_empty_group", &[off.to_string().as_str()])
        ));
    }
    match n {
        2 => {
            out.push((vals[0] << 2) | (vals[1] >> 4));
        }
        3 => {
            out.push((vals[0] << 2) | (vals[1] >> 4));
            out.push((vals[1] << 4) | (vals[2] >> 2));
        }
        4 => {
            out.push((vals[0] << 2) | (vals[1] >> 4));
            out.push((vals[1] << 4) | (vals[2] >> 2));
            out.push((vals[2] << 6) | vals[3]);
        }
        _ => {
            let off = chars[0].1;
            return Err(anyhow::anyhow!(
                "{}",
                i18n::tf("err.base64_padding", &[off.to_string().as_str()])
            ));
        }
    }
    Ok(())
}

fn hex_encode_with(input: &[u8], delim: HexDelimiter, upper: bool, bpl: usize) -> Vec<u8> {
    let per = 2 + hex_delim_bytes(delim).len();
    let mut out = Vec::with_capacity(input.len() * per + input.len() / bpl.max(1));
    for (i, &b) in input.iter().enumerate() {
        if i > 0 {
            if bpl > 0 && i % bpl == 0 {
                out.push(b'\n');
            } else {
                out.extend_from_slice(hex_delim_bytes(delim));
            }
        }
        let (hi, lo) = (b >> 4, b & 0x0f);
        let (a, b2) = if upper {
            (hex_digit_upper(hi), hex_digit_upper(lo))
        } else {
            (hex_digit_lower(hi), hex_digit_lower(lo))
        };
        out.push(a);
        out.push(b2);
    }
    out
}

/// Streaming hex encode: two chars per byte, no cross-block state.
struct HexEncodeBuf {
    buf: Vec<u8>,
    delim: HexDelimiter,
    upper: bool,
    bpl: usize,
}

pub(crate) fn make_hex_encode(
    args: &HashMap<String, String>,
) -> anyhow::Result<Box<dyn StreamingOp>> {
    let (delim, upper) = parse_hex_args(args)?;
    let bpl = parse_hex_bpl(args)?;
    Ok(Box::new(HexEncodeBuf {
        buf: Vec::new(),
        delim,
        upper,
        bpl,
    }))
}

impl StreamingOp for HexEncodeBuf {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.buf.extend_from_slice(chunk);
        Ok(Vec::new())
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        let input = std::mem::take(&mut self.buf);
        Ok(hex_encode_with(&input, self.delim, self.upper, self.bpl))
    }
}

/// Streaming hex decode: filters whitespace, optional delimiter and (when
/// ignore is set) any non-hex character; keeps nibble state, validates even
/// length in finish.
struct HexDecodeStream {
    high: Option<u8>,
    dbytes: Vec<u8>,
    ignore: bool,
}

pub(crate) fn make_hex_decode(
    args: &HashMap<String, String>,
) -> anyhow::Result<Box<dyn StreamingOp>> {
    let (delim, _upper) = parse_hex_args(args)?;
    Ok(Box::new(HexDecodeStream {
        high: None,
        dbytes: hex_delim_bytes(delim).to_vec(),
        ignore: parse_hex_ignore(args)?,
    }))
}

impl StreamingOp for HexDecodeStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(chunk.len() / 2 + 1);
        for &c in chunk {
            if c.is_ascii_whitespace()
                || (!self.dbytes.is_empty() && self.dbytes.contains(&c))
                || (self.ignore && !c.is_ascii_hexdigit())
            {
                continue;
            }
            let v = hex_val(c).ok_or_else(|| anyhow::anyhow!("{}", i18n::t("err.hex_invalid")))?;
            match self.high.take() {
                Some(h) => out.push((h << 4) | v),
                None => self.high = Some(v),
            }
        }
        Ok(out)
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        if self.high.is_some() {
            anyhow::bail!("{}", i18n::t("err.hex_odd"));
        }
        Ok(Vec::new())
    }
}

pub(crate) fn base64_encode(
    input: &[u8],
    args: &HashMap<String, String>,
) -> anyhow::Result<Vec<u8>> {
    let alphabet = parse_b64_alphabet(args)?;
    Ok(base64_encode_with(input, &alphabet))
}

/// Core Base64 encode against a given alphabet (payload chars + pad char).
fn base64_encode_with(input: &[u8], alphabet: &B64Alphabet) -> Vec<u8> {
    let full = input.len() - input.len() % 3;
    let mut out = Vec::with_capacity(full / 3 * 4 + 4);
    for g in input[..full].as_chunks::<3>().0 {
        let b0 = g[0];
        let b1 = g[1];
        let b2 = g[2];
        out.push(alphabet.chars[(b0 >> 2) as usize]);
        out.push(alphabet.chars[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize]);
        out.push(alphabet.chars[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize]);
        out.push(alphabet.chars[(b2 & 0x3f) as usize]);
    }
    match input.len() % 3 {
        0 => {}
        1 => {
            let b0 = input[full];
            out.push(alphabet.chars[(b0 >> 2) as usize]);
            out.push(alphabet.chars[((b0 & 0x03) << 4) as usize]);
            if alphabet.has_pad {
                out.push(alphabet.pad);
                out.push(alphabet.pad);
            }
        }
        2 => {
            let b0 = input[full];
            let b1 = input[full + 1];
            out.push(alphabet.chars[(b0 >> 2) as usize]);
            out.push(alphabet.chars[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize]);
            out.push(alphabet.chars[((b1 & 0x0f) << 2) as usize]);
            if alphabet.has_pad {
                out.push(alphabet.pad);
            }
        }
        _ => unreachable!(),
    }
    out
}

pub(crate) fn base64_decode(
    input: &[u8],
    args: &HashMap<String, String>,
) -> anyhow::Result<Vec<u8>> {
    let alphabet = parse_b64_alphabet(args)?;
    let ignore = parse_bool(args.get("ignore_non_alphabet"))?;
    // Strict by default: padding, when present, must sit at the
    // very end and complete a group; set strict_mode=false for lenient input.
    let strict = match args.get("strict_mode") {
        Some(v) => parse_bool(Some(v))?,
        None => true,
    };
    base64_decode_with(input, &alphabet, ignore, strict)
}

/// Core Base64 decode against a given alphabet; whitespace is always dropped,
/// other non-alphabet chars are dropped only when `ignore` is set. `strict`
/// enables CyberChef-style strictMode checks on the cleaned input.
fn base64_decode_with(
    input: &[u8],
    alphabet: &B64Alphabet,
    ignore: bool,
    strict: bool,
) -> anyhow::Result<Vec<u8>> {
    // Keep (byte, input offset) pairs so both strict checks and group/tail
    // decoders can report "at offset N".
    let cleaned: Vec<(u8, usize)> = input
        .iter()
        .enumerate()
        .filter(|&(_, &c)| {
            if c.is_ascii_whitespace() {
                // Whitespace that is part of the alphabet (e.g. uuencode's
                // leading space) must be kept; other whitespace is always dropped.
                return alphabet.is_pad(c) || alphabet.rev[c as usize] >= 0;
            }
            if !alphabet.is_pad(c) && alphabet.rev[c as usize] < 0 {
                // ignore=true drops the char; ignore=false keeps it so the decoder reports it.
                return !ignore;
            }
            true
        })
        .map(|(i, &c)| (c, i))
        .collect();
    if strict {
        check_b64_strict(&cleaned, alphabet)?;
    }
    let mut out = Vec::with_capacity(cleaned.len() / 4 * 3 + 3);
    let mut chars: Vec<(u8, usize)> = Vec::with_capacity(4);
    for &(c, off) in &cleaned {
        chars.push((c, off));
        if chars.len() == 4 {
            decode_group(&chars, alphabet, &mut out)?;
            chars.clear();
        }
    }
    match chars.len() {
        0 => {}
        1 => {
            let off = chars[0].1;
            anyhow::bail!(
                "{}",
                i18n::tf("err.base64_tail", &[off.to_string().as_str()])
            )
        }
        n => decode_tail(&chars[..n], alphabet, &mut out)?,
    }
    Ok(out)
}

pub(crate) fn base64url_encode(
    input: &[u8],
    _args: &HashMap<String, String>,
) -> anyhow::Result<Vec<u8>> {
    Ok(base64_encode_with(input, &B64Alphabet::parse("url", None)?))
}

pub(crate) fn base64url_decode(
    input: &[u8],
    args: &HashMap<String, String>,
) -> anyhow::Result<Vec<u8>> {
    let alph = match args.get("alphabet") {
        Some(a) => B64Alphabet::parse(a, None)?,
        None => B64Alphabet::parse("url", None)?,
    };
    let ignore = parse_bool(args.get("ignore_non_alphabet"))?;
    // Strict by default: padding, when present, must sit at the
    // very end and complete a group; set strict_mode=false for lenient input.
    let strict = match args.get("strict_mode") {
        Some(v) => parse_bool(Some(v))?,
        None => true,
    };
    base64_decode_with(input, &alph, ignore, strict)
}

/// Base32 alphabet presets. Ranges are expanded by `expand_alph_range`
/// (same engine as Base64). Standard and extended-hex carry an explicit
/// padding char as their 33rd character; Crockford's base32 uses a 32-char
/// alphabet with no mandatory padding (encode emits no '=' unless requested,
/// decode still tolerates '=').
const B32_PRESETS: &[(&str, &str)] = &[
    ("standard", "A-Z2-7="),
    ("extended-hex", "0-9A-V="),
    ("crockford", "0123456789ABCDEFGHJKMNPQRSTVWXYZ"),
];

/// A Base32 alphabet: 32 payload chars, a padding char, whether padding is
/// accepted on decode, whether the encoder should emit padding, and a 256-entry
/// reverse table (0..=31 value, -1 invalid, -2 padding).
#[derive(Clone)]

struct B32Alphabet {
    chars: Vec<u8>,
    pad: u8,
    encode_pad: bool,
    rev: Vec<i8>,
}

impl B32Alphabet {
    fn from_plain(chars: &[u8], pad: u8, pad_allowed: bool, encode_pad: bool) -> B32Alphabet {
        let mut rev = vec![-1i8; 256];
        for (i, &c) in chars.iter().enumerate() {
            rev[c as usize] = i as i8;
        }
        if pad_allowed {
            rev[pad as usize] = -2;
        }
        B32Alphabet {
            chars: chars.to_vec(),
            pad,
            encode_pad,
            rev,
        }
    }

    /// Parse the `alphabet` argument: a preset name (see B32_PRESETS) or a
    /// custom 32/33-char alphabet. 33 chars => the 33rd char is the pad;
    /// 32 chars => `pad_opt` (or '=') is used and padding is emitted only when
    /// `pad_opt` is given, mirroring Base64's 64/65-char rule. Crockford's
    /// lenient decode aliases (i/I/l/L -> 1, o/O -> 0) are wired into rev.
    fn parse(alphabet: &str, pad_opt: Option<u8>) -> anyhow::Result<B32Alphabet> {
        let lower = alphabet.to_ascii_lowercase();
        let raw = B32_PRESETS
            .iter()
            .find(|(n, _)| *n == lower)
            .map(|(_, s)| *s)
            .unwrap_or(alphabet);
        let expanded = expand_alph_range(raw)?;
        let (chars, pad, pad_allowed, encode_pad, lenient) = match expanded.len() {
            32 => (
                expanded,
                pad_opt.unwrap_or(b'='),
                pad_opt.is_some(),
                pad_opt.is_some(),
                lower == "crockford",
            ),
            33 => (
                expanded[..32].to_vec(),
                expanded[32],
                true,
                true,
                lower == "crockford",
            ),
            n => anyhow::bail!(
                "{}",
                i18n::tf("err.base32_alphabet_len", &[n.to_string().as_str()])
            ),
        };
        let mut seen = [false; 256];
        for &c in &chars {
            if seen[c as usize] {
                anyhow::bail!("{}", i18n::t("err.base32_dup_char"));
            }
            seen[c as usize] = true;
        }
        if pad_allowed && seen[pad as usize] {
            // The padding char must not collide with a payload char.
            anyhow::bail!("{}", i18n::t("err.base32_dup_char"));
        }
        let mut alph = B32Alphabet::from_plain(&chars, pad, pad_allowed, encode_pad);
        if lenient {
            // Crockford decode leniency: I/L are aliases for 1, O for 0.
            for c in *b"iIlL" {
                alph.rev[c as usize] = 1;
            }
            for c in *b"oO" {
                alph.rev[c as usize] = 0;
            }
        }
        Ok(alph)
    }
}

fn parse_b32_alphabet(args: &HashMap<String, String>) -> anyhow::Result<B32Alphabet> {
    let alph = args
        .get("alphabet")
        .map(String::as_str)
        .unwrap_or("standard");
    let pad = args.get("pad").and_then(|p| p.as_bytes().first().copied());
    B32Alphabet::parse(alph, pad)
}

/// RFC 4648 Base32 encode (5 bits per char, MSB-first bit stream). Tail bits
/// are zero-padded; '=' padding is emitted up to a multiple of 8 only when the
/// alphabet requests it (standard/extended-hex, or a custom alphabet with a
/// pad argument; Crockford by default emits none).
fn b32_encode_with(input: &[u8], alph: &B32Alphabet) -> Vec<u8> {
    let mut out = Vec::with_capacity((input.len() * 8).div_ceil(5) + 8);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for &b in input {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(alph.chars[((buf >> bits) & 0x1f) as usize]);
        }
    }
    if bits > 0 {
        out.push(alph.chars[((buf << (5 - bits)) & 0x1f) as usize]);
    }
    if alph.encode_pad {
        while out.len() % 8 != 0 {
            out.push(alph.pad);
        }
    }
    out
}

/// RFC 4648 Base32 decode. Whitespace is always ignored; characters outside
/// the alphabet either fail (`ignore=false`) or are skipped (`ignore=true`).
/// Invalid trailing lengths (1/3/6 chars mod 8) always fail; padding must sit
/// at the very end and its count must complete a group of 8. `strict_mode`
/// additionally rejects non-zero trailing bits (CyberChef does not check this;
/// dpa is deliberately stricter).
fn b32_decode_with(
    input: &[u8],
    alph: &B32Alphabet,
    ignore: bool,
    strict: bool,
) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 5 / 8 + 8);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    let mut data_chars = 0usize;
    let mut pad_chars = 0usize;
    let mut seen_pad = false;
    // Offsets of the last meaningful data char / last pad char, for errors
    // that only surface after the whole input has been scanned.
    let mut last_data_idx = 0usize;
    let mut last_pad_idx = 0usize;
    for (i, &c) in input.iter().enumerate() {
        if c.is_ascii_whitespace() {
            continue;
        }
        let v = alph.rev[c as usize];
        if v == -2 {
            // Padding marks the end of meaningful data: anything after it is
            // invalid regardless of strictness, and so is all-padding input.
            seen_pad = true;
            pad_chars += 1;
            last_pad_idx = i;
            if data_chars == 0 {
                anyhow::bail!(
                    "{}",
                    i18n::tf("err.base32_padding", &[i.to_string().as_str()])
                );
            }
            continue;
        }
        if v >= 0 {
            if seen_pad {
                anyhow::bail!(
                    "{}",
                    i18n::tf("err.base32_padding", &[i.to_string().as_str()])
                );
            }
            buf = (buf << 5) | v as u32;
            bits += 5;
            data_chars += 1;
            last_data_idx = i;
            while bits >= 8 {
                bits -= 8;
                out.push((buf >> bits) as u8);
            }
        } else if !ignore {
            anyhow::bail!(
                "{}",
                i18n::tf("err.base32_invalid", &[i.to_string().as_str()])
            );
        }
    }
    if seen_pad && !(data_chars + pad_chars).is_multiple_of(8) {
        anyhow::bail!(
            "{}",
            i18n::tf("err.base32_padding", &[last_pad_idx.to_string().as_str()])
        );
    }
    if !seen_pad && matches!(data_chars % 8, 1 | 3 | 6) {
        anyhow::bail!(
            "{}",
            i18n::tf("err.base32_tail", &[last_data_idx.to_string().as_str()])
        );
    }
    if strict && bits > 0 && (buf & ((1u32 << bits) - 1)) != 0 {
        anyhow::bail!(
            "{}",
            i18n::tf(
                "err.base32_strict_tail",
                &[last_data_idx.to_string().as_str()]
            )
        );
    }
    Ok(out)
}

pub(crate) fn base32_encode(
    input: &[u8],
    args: &HashMap<String, String>,
) -> anyhow::Result<Vec<u8>> {
    Ok(b32_encode_with(input, &parse_b32_alphabet(args)?))
}

pub(crate) fn base32_decode(
    input: &[u8],
    args: &HashMap<String, String>,
) -> anyhow::Result<Vec<u8>> {
    let alph = parse_b32_alphabet(args)?;
    let ignore = args
        .get("ignore_non_alphabet")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let strict = args
        .get("strict_mode")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    b32_decode_with(input, &alph, ignore, strict)
}

struct B32EncodeBuf {
    buf: Vec<u8>,
    args: HashMap<String, String>,
}

pub(crate) fn make_b32_encode_stream(
    args: &HashMap<String, String>,
) -> anyhow::Result<Box<dyn StreamingOp>> {
    // Validate arguments up front so a bad alphabet fails on creation.
    let _ = parse_b32_alphabet(args)?;
    Ok(Box::new(B32EncodeBuf {
        buf: Vec::new(),
        args: args.clone(),
    }))
}

impl StreamingOp for B32EncodeBuf {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.buf.extend_from_slice(chunk);
        Ok(Vec::new())
    }
    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        base32_encode(&std::mem::take(&mut self.buf), &self.args)
    }
}

struct B32DecodeBuf {
    buf: Vec<u8>,
    args: HashMap<String, String>,
}

pub(crate) fn make_b32_decode_stream(
    args: &HashMap<String, String>,
) -> anyhow::Result<Box<dyn StreamingOp>> {
    let _ = parse_b32_alphabet(args)?;
    Ok(Box::new(B32DecodeBuf {
        buf: Vec::new(),
        args: args.clone(),
    }))
}

impl StreamingOp for B32DecodeBuf {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.buf.extend_from_slice(chunk);
        Ok(Vec::new())
    }
    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        base32_decode(&std::mem::take(&mut self.buf), &self.args)
    }
}

pub(crate) fn hex_encode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let (delim, upper) = parse_hex_args(args)?;
    let bpl = parse_hex_bpl(args)?;
    Ok(hex_encode_with(input, delim, upper, bpl))
}

pub(crate) fn hex_decode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let (delim, _upper) = parse_hex_args(args)?;
    let ignore = parse_hex_ignore(args)?;
    let dbytes = hex_delim_bytes(delim);
    let cleaned: Vec<u8> = input
        .iter()
        .copied()
        .filter(|b| {
            let is_delim = !dbytes.is_empty() && dbytes.contains(b);
            let is_nonhex = ignore && !b.is_ascii_hexdigit();
            !(b.is_ascii_whitespace() || is_delim || is_nonhex)
        })
        .collect();
    let s = std::str::from_utf8(&cleaned)?;
    hex::decode(s)
        .map_err(|e| anyhow::anyhow!("{}", i18n::tf("err.hex_decode", &[e.to_string().as_str()])))
}

/// Base58 alphabet presets (mirror CyberChef's ALPHABET_OPTIONS).
const B58_PRESETS: &[(&str, &str)] = &[
    (
        "bitcoin",
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
    ),
    (
        "ripple",
        "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz",
    ),
];

/// A Base58 alphabet: 58 payload chars plus a 256-entry reverse table
/// (0..=57 value, -1 invalid). Base58 has no padding semantics, so this is
/// simpler than the Base32/Base64 alphabets.
#[derive(Clone)]

struct B58Alphabet {
    chars: Vec<u8>,
    rev: Vec<i8>,
}

impl B58Alphabet {
    fn from_plain(chars: &[u8]) -> B58Alphabet {
        let mut rev = vec![-1i8; 256];
        for (i, &c) in chars.iter().enumerate() {
            rev[c as usize] = i as i8;
        }
        B58Alphabet {
            chars: chars.to_vec(),
            rev,
        }
    }

    /// Parse the `alphabet` argument: a preset name (bitcoin/ripple) or a
    /// custom 58-char alphabet. Ranges are expanded by `expand_alph_range`
    /// (same engine as Base64/Base32); length and uniqueness checks mirror
    /// CyberChef's To/From Base58 (58 unique chars required).
    fn parse(alphabet: &str) -> anyhow::Result<B58Alphabet> {
        let lower = alphabet.to_ascii_lowercase();
        let raw = B58_PRESETS
            .iter()
            .find(|(n, _)| *n == lower)
            .map(|(_, s)| *s)
            .unwrap_or(alphabet);
        let expanded = expand_alph_range(raw)?;
        if expanded.len() != 58 {
            anyhow::bail!(
                "{}",
                i18n::tf(
                    "err.base58_alphabet_len",
                    &[expanded.len().to_string().as_str()]
                )
            );
        }
        let mut seen = [false; 256];
        for &c in &expanded {
            if seen[c as usize] {
                anyhow::bail!("{}", i18n::t("err.base58_dup_char"));
            }
            seen[c as usize] = true;
        }
        Ok(B58Alphabet::from_plain(&expanded))
    }
}

fn parse_b58_alphabet(args: &HashMap<String, String>) -> anyhow::Result<B58Alphabet> {
    let alph = args
        .get("alphabet")
        .map(String::as_str)
        .unwrap_or("bitcoin");
    B58Alphabet::parse(alph)
}

/// Base58 encode with a dynamic alphabet: leading zero bytes become the
/// alphabet's first char (mirroring CyberChef's To Base58). No checksum is
/// added; the conversion is the classic per-byte carry into base 58.
fn base58_encode_with(input: &[u8], alph: &B58Alphabet) -> Vec<u8> {
    let zeros = input.iter().take_while(|&&b| b == 0).count();
    let mut digits: Vec<u8> = Vec::new(); // little-endian base-58 digits
    for &b in &input[zeros..] {
        let mut carry = b as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = Vec::with_capacity(zeros + digits.len());
    out.extend(std::iter::repeat_n(alph.chars[0], zeros));
    for &d in digits.iter().rev() {
        out.push(alph.chars[d as usize]);
    }
    out
}

/// Base58 decode with a dynamic alphabet. Whitespace is always ignored;
/// characters outside the alphabet either fail with a position-tagged error
/// (`ignore=false`) or are skipped (`ignore=true`). Leading chars equal to
/// the alphabet's first char decode to zero bytes.
fn base58_decode_with(input: &[u8], alph: &B58Alphabet, ignore: bool) -> anyhow::Result<Vec<u8>> {
    // Count leading alphabet[0] chars (skipping whitespace) -> leading zeros.
    let mut zeros = 0usize;
    let mut idx = 0usize;
    while idx < input.len() {
        let c = input[idx];
        if c.is_ascii_whitespace() {
            idx += 1;
            continue;
        }
        if alph.rev[c as usize] == 0 {
            zeros += 1;
            idx += 1;
            continue;
        }
        break;
    }
    let mut digits: Vec<u8> = Vec::new(); // little-endian base-256 digits
    let mut pos = idx;
    while idx < input.len() {
        let c = input[idx];
        if c.is_ascii_whitespace() {
            idx += 1;
            continue;
        }
        let v = alph.rev[c as usize];
        if v < 0 {
            if ignore {
                idx += 1;
                continue;
            }
            anyhow::bail!(
                "{}",
                i18n::tf(
                    "err.base58_invalid_at",
                    &[&(c as char).to_string(), &pos.to_string()]
                )
            );
        }
        let mut carry = v as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) * 58;
            *d = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            digits.push((carry & 0xff) as u8);
            carry >>= 8;
        }
        idx += 1;
        pos += 1;
    }
    let mut out = Vec::with_capacity(zeros + digits.len());
    out.extend(std::iter::repeat_n(0u8, zeros));
    out.extend(digits.iter().rev().copied());
    Ok(out)
}

/// Memory-path Base58 encode (parses alphabet argument).
pub(crate) fn base58_encode(
    input: &[u8],
    args: &HashMap<String, String>,
) -> anyhow::Result<Vec<u8>> {
    let alph = parse_b58_alphabet(args)?;
    Ok(base58_encode_with(input, &alph))
}

/// Memory-path Base58 decode (parses alphabet / ignore_non_alphabet).
pub(crate) fn base58_decode(
    input: &[u8],
    args: &HashMap<String, String>,
) -> anyhow::Result<Vec<u8>> {
    let alph = parse_b58_alphabet(args)?;
    let ignore = parse_bool(args.get("ignore_non_alphabet"))?;
    base58_decode_with(input, &alph, ignore)
}

/// Streaming base58 encode buffers whole input: emit on finish (big-int conversion is whole-input).
struct Base58EncodeBuf {
    buf: Vec<u8>,
    alph: B58Alphabet,
}

pub(crate) fn make_base58_encode_stream(
    args: &HashMap<String, String>,
) -> anyhow::Result<Box<dyn StreamingOp>> {
    Ok(Box::new(Base58EncodeBuf {
        buf: Vec::new(),
        alph: parse_b58_alphabet(args)?,
    }))
}

impl StreamingOp for Base58EncodeBuf {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.buf.extend_from_slice(chunk);
        Ok(Vec::new())
    }
    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        let input = std::mem::take(&mut self.buf);
        Ok(base58_encode_with(&input, &self.alph))
    }
}

/// Streaming base58 decode: buffer until finish (conversion is inherently whole-input).
struct Base58DecodeStream {
    buf: Vec<u8>,
    alph: B58Alphabet,
    ignore: bool,
}

pub(crate) fn make_base58_decode(
    args: &HashMap<String, String>,
) -> anyhow::Result<Box<dyn StreamingOp>> {
    Ok(Box::new(Base58DecodeStream {
        buf: Vec::new(),
        alph: parse_b58_alphabet(args)?,
        ignore: parse_bool(args.get("ignore_non_alphabet"))?,
    }))
}

impl StreamingOp for Base58DecodeStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.buf.extend_from_slice(chunk);
        Ok(Vec::new())
    }
    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        let input = std::mem::take(&mut self.buf);
        base58_decode_with(&input, &self.alph, self.ignore)
    }
}

// ---------------------------------------------------------------------------
// Base62 (P1, deep): dynamic alphabet (preset or 62 chars with range expansion),
// big-endian big-int conversion like Base58. Leading zero bytes become the
// alphabet's first char; decode honours ignore_non_alphabet and always skips
// whitespace.
// ---------------------------------------------------------------------------

const B62_PRESETS: &[(&str, &str)] = &[(
    "standard",
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
)];

/// A Base62 alphabet: 62 payload chars plus a 256-entry reverse table
/// (0..=61 value, -1 invalid). No padding semantics, like Base58.
#[derive(Clone)]

struct B62Alphabet {
    chars: Vec<u8>,
    rev: Vec<i8>,
}

impl B62Alphabet {
    fn from_plain(chars: &[u8]) -> B62Alphabet {
        let mut rev = vec![-1i8; 256];
        for (i, &c) in chars.iter().enumerate() {
            rev[c as usize] = i as i8;
        }
        B62Alphabet {
            chars: chars.to_vec(),
            rev,
        }
    }

    /// Parse the `alphabet` argument: a preset name (standard) or a custom
    /// 62-char alphabet. Ranges are expanded by `expand_alph_range`; length
    /// and uniqueness checks mirror CyberChef's To/From Base62.
    fn parse(alphabet: &str) -> anyhow::Result<B62Alphabet> {
        let lower = alphabet.to_ascii_lowercase();
        let raw = B62_PRESETS
            .iter()
            .find(|(n, _)| *n == lower)
            .map(|(_, s)| *s)
            .unwrap_or(alphabet);
        let expanded = expand_alph_range(raw)?;
        if expanded.len() != 62 {
            anyhow::bail!(
                "{}",
                i18n::tf(
                    "err.base62_alphabet_len",
                    &[expanded.len().to_string().as_str()]
                )
            );
        }
        let mut seen = [false; 256];
        for &c in &expanded {
            if seen[c as usize] {
                anyhow::bail!("{}", i18n::t("err.base62_dup_char"));
            }
            seen[c as usize] = true;
        }
        Ok(B62Alphabet::from_plain(&expanded))
    }
}

fn parse_b62_alphabet(args: &HashMap<String, String>) -> anyhow::Result<B62Alphabet> {
    let alph = args
        .get("alphabet")
        .map(String::as_str)
        .unwrap_or("standard");
    B62Alphabet::parse(alph)
}

fn base62_encode_with(input: &[u8], alph: &B62Alphabet) -> Vec<u8> {
    let zeros = input.iter().take_while(|&&b| b == 0).count();
    let mut digits: Vec<u8> = Vec::new(); // little-endian base-62 digits
    for &b in &input[zeros..] {
        let mut carry = b as u64;
        for d in digits.iter_mut() {
            carry += (*d as u64) << 8;
            *d = (carry % 62) as u8;
            carry /= 62;
        }
        while carry > 0 {
            digits.push((carry % 62) as u8);
            carry /= 62;
        }
    }
    let mut out = Vec::with_capacity(zeros + digits.len());
    out.extend(std::iter::repeat_n(alph.chars[0], zeros));
    for &d in digits.iter().rev() {
        out.push(alph.chars[d as usize]);
    }
    out
}

fn base62_decode_with(input: &[u8], alph: &B62Alphabet, ignore: bool) -> anyhow::Result<Vec<u8>> {
    // Count leading alphabet[0] chars (skipping whitespace) -> leading zeros.
    let mut zeros = 0usize;
    let mut idx = 0usize;
    while idx < input.len() {
        let c = input[idx];
        if c.is_ascii_whitespace() {
            idx += 1;
            continue;
        }
        if alph.rev[c as usize] == 0 {
            zeros += 1;
            idx += 1;
            continue;
        }
        break;
    }
    let mut digits: Vec<u8> = Vec::new(); // little-endian base-256 digits
    let mut pos = idx;
    while idx < input.len() {
        let c = input[idx];
        if c.is_ascii_whitespace() {
            idx += 1;
            continue;
        }
        let v = alph.rev[c as usize];
        if v < 0 {
            if ignore {
                idx += 1;
                continue;
            }
            anyhow::bail!(
                "{}",
                i18n::tf(
                    "err.base62_invalid_at",
                    &[&(c as char).to_string(), &pos.to_string()]
                )
            );
        }
        let mut carry = v as u64;
        for d in digits.iter_mut() {
            carry += (*d as u64) * 62;
            *d = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            digits.push((carry & 0xff) as u8);
            carry >>= 8;
        }
        idx += 1;
        pos += 1;
    }
    let mut out = Vec::with_capacity(zeros + digits.len());
    out.extend(std::iter::repeat_n(0u8, zeros));
    out.extend(digits.iter().rev().copied());
    Ok(out)
}

/// Memory-path Base62 encode (parses alphabet argument).
pub(crate) fn base62_encode(
    input: &[u8],
    args: &HashMap<String, String>,
) -> anyhow::Result<Vec<u8>> {
    let alph = parse_b62_alphabet(args)?;
    Ok(base62_encode_with(input, &alph))
}

/// Memory-path Base62 decode (parses alphabet / ignore_non_alphabet).
pub(crate) fn base62_decode(
    input: &[u8],
    args: &HashMap<String, String>,
) -> anyhow::Result<Vec<u8>> {
    let alph = parse_b62_alphabet(args)?;
    let ignore = parse_bool(args.get("ignore_non_alphabet"))?;
    base62_decode_with(input, &alph, ignore)
}

/// Streaming base62 encode buffers whole input: emit on finish (big-int conversion is whole-input).
struct Base62EncodeBuf {
    buf: Vec<u8>,
    alph: B62Alphabet,
}

pub(crate) fn make_base62_encode_stream(
    args: &HashMap<String, String>,
) -> anyhow::Result<Box<dyn StreamingOp>> {
    Ok(Box::new(Base62EncodeBuf {
        buf: Vec::new(),
        alph: parse_b62_alphabet(args)?,
    }))
}

impl StreamingOp for Base62EncodeBuf {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.buf.extend_from_slice(chunk);
        Ok(Vec::new())
    }
    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        let input = std::mem::take(&mut self.buf);
        Ok(base62_encode_with(&input, &self.alph))
    }
}

/// Streaming base62 decode: buffer until finish (conversion is inherently whole-input).
struct Base62DecodeBuf {
    buf: Vec<u8>,
    alph: B62Alphabet,
    ignore: bool,
}

pub(crate) fn make_base62_decode_stream(
    args: &HashMap<String, String>,
) -> anyhow::Result<Box<dyn StreamingOp>> {
    Ok(Box::new(Base62DecodeBuf {
        buf: Vec::new(),
        alph: parse_b62_alphabet(args)?,
        ignore: parse_bool(args.get("ignore_non_alphabet"))?,
    }))
}

impl StreamingOp for Base62DecodeBuf {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.buf.extend_from_slice(chunk);
        Ok(Vec::new())
    }
    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        let input = std::mem::take(&mut self.buf);
        base62_decode_with(&input, &self.alph, self.ignore)
    }
}

// ---------------------------------------------------------------------------
// Base85 (P1, deep): dynamic alphabet with presets (ascii85/z85/rfc1924) or a
// custom 85-char alphabet. The ascii85 preset enables Adobe's 'z' compression
// for all-zero groups; other presets treat 'z' as an ordinary char. Decode
// honours ignore_non_alphabet and always skips whitespace.
// ---------------------------------------------------------------------------

const B85_PRESETS: &[(&str, &str)] = &[
    (
        "ascii85",
        "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstu",
    ),
    (
        "z85",
        "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#",
    ),
    (
        "rfc1924",
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~",
    ),
];

/// A Base85 alphabet: 85 payload chars plus a 256-entry reverse table
/// (0..=84 value, -1 invalid). `z_compress` enables Adobe Ascii85's 'z' rule.
#[derive(Clone)]

struct B85Alphabet {
    chars: Vec<u8>,
    rev: Vec<i8>,
    z_compress: bool,
    remove_zeros: bool,
}

impl B85Alphabet {
    fn from_plain(chars: &[u8], z_compress: bool) -> B85Alphabet {
        let mut rev = vec![-1i8; 256];
        for (i, &c) in chars.iter().enumerate() {
            rev[c as usize] = i as i8;
        }
        B85Alphabet {
            chars: chars.to_vec(),
            rev,
            z_compress,
            remove_zeros: true,
        }
    }

    /// Parse the `alphabet` argument: a preset name (ascii85/z85/rfc1924) or a
    /// custom 85-char alphabet. Ranges are expanded by `expand_alph_range`;
    /// length and uniqueness checks mirror CyberChef's To/From Base85.
    fn parse(alphabet: &str) -> anyhow::Result<B85Alphabet> {
        let lower = alphabet.to_ascii_lowercase();
        if let Some((n, s)) = B85_PRESETS.iter().find(|(n, _)| *n == lower) {
            // Preset tables are written fully expanded; never run them through
            // expand_alph_range (their '-' would be misread as a range).
            return Ok(B85Alphabet::from_plain(s.as_bytes(), *n == "ascii85"));
        }
        let expanded = expand_alph_range(alphabet)?;
        if expanded.len() != 85 {
            anyhow::bail!(
                "{}",
                i18n::tf(
                    "err.base85_alphabet_len",
                    &[expanded.len().to_string().as_str()]
                )
            );
        }
        let mut seen = [false; 256];
        for &c in &expanded {
            if seen[c as usize] {
                anyhow::bail!("{}", i18n::t("err.base85_dup_char"));
            }
            seen[c as usize] = true;
        }
        Ok(B85Alphabet::from_plain(&expanded, false))
    }
}

fn parse_b85_alphabet(args: &HashMap<String, String>) -> anyhow::Result<B85Alphabet> {
    let alph = args
        .get("alphabet")
        .map(String::as_str)
        .unwrap_or("ascii85");
    let mut a = B85Alphabet::parse(alph)?;
    // CyberChef's Ascii85 Encode exposes "Remove Zeros" (default on): zero
    // groups collapse to 'z'. Turning it off emits the literal 5-char group.
    match args.get("remove_zeros").map(|s| s.as_str()) {
        None | Some("true") | Some("1") | Some("yes") => {}
        Some("false") | Some("0") | Some("no") => a.remove_zeros = false,
        Some(other) => anyhow::bail!("{}", i18n::tf("err.bool_invalid", &[other])),
    }
    Ok(a)
}

fn base85_encode_with(input: &[u8], alph: &B85Alphabet) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() + input.len() / 4 + 1);
    let (chunks, rem) = input.as_chunks::<4>();
    for c in chunks {
        let val =
            ((c[0] as u32) << 24) | ((c[1] as u32) << 16) | ((c[2] as u32) << 8) | (c[3] as u32);
        if alph.z_compress && alph.remove_zeros && val == 0 {
            out.push(b'z');
            continue;
        }
        let mut tmp = val;
        let mut group = [0u8; 5];
        for g in group.iter_mut().rev() {
            *g = alph.chars[(tmp % 85) as usize];
            tmp /= 85;
        }
        out.extend_from_slice(&group);
    }
    if !rem.is_empty() {
        let n = rem.len();
        let mut padded = [0u8; 4];
        padded[..n].copy_from_slice(rem);
        let val = ((padded[0] as u32) << 24)
            | ((padded[1] as u32) << 16)
            | ((padded[2] as u32) << 8)
            | (padded[3] as u32);
        let mut tmp = val;
        let mut group = [0u8; 5];
        for g in group.iter_mut().rev() {
            *g = alph.chars[(tmp % 85) as usize];
            tmp /= 85;
        }
        out.extend_from_slice(&group[..n + 1]);
    }
    out
}

fn base85_decode_with(input: &[u8], alph: &B85Alphabet, ignore: bool) -> anyhow::Result<Vec<u8>> {
    let cleaned: Vec<u8> = input
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    let mut out = Vec::with_capacity(cleaned.len());
    let mut i = 0usize;
    while i < cleaned.len() {
        if alph.z_compress && alph.remove_zeros && cleaned[i] == b'z' {
            out.extend_from_slice(&[0, 0, 0, 0]);
            i += 1;
            continue;
        }
        // Collect a group of up to 5 chars; fewer allowed only at the end.
        let mut vals = [0u32; 5];
        let mut n = 0usize;
        while i < cleaned.len() && n < 5 {
            let c = cleaned[i];
            let v = alph.rev[c as usize];
            if v < 0 {
                if ignore {
                    i += 1;
                    continue;
                }
                if alph.z_compress && alph.remove_zeros && c == b'z' {
                    anyhow::bail!("{}", i18n::t("err.base85_z_mid_group"));
                }
                let ch = c as char;
                let s = ch.to_string();
                anyhow::bail!(
                    "{}",
                    i18n::tf("err.base85_invalid_at", &[s.as_str(), &i.to_string()])
                );
            }
            vals[n] = v as u32;
            n += 1;
            i += 1;
        }
        if n == 0 {
            continue;
        }
        if n == 1 {
            anyhow::bail!("{}", i18n::t("err.base85_incomplete"));
        }
        // Pad with the alphabet's last char value (84) for the tail group.
        let pad = 5 - n;
        for v in vals.iter_mut().skip(n) {
            *v = 84;
        }
        let mut val = 0u32;
        for v in vals.iter() {
            val = val * 85 + *v;
        }
        // n chars encode n-1 bytes; the known digits are the most significant.
        let nbytes = n - 1;
        let bytes = val.to_be_bytes();
        out.extend_from_slice(&bytes[..nbytes]);
        // The 'pad' unused digits only make sense for the final group.
        if pad > 0 && i < cleaned.len() {
            anyhow::bail!("{}", i18n::t("err.base85_incomplete"));
        }
    }
    Ok(out)
}

/// Memory-path Base85 encode (parses alphabet argument).
pub(crate) fn base85_encode(
    input: &[u8],
    args: &HashMap<String, String>,
) -> anyhow::Result<Vec<u8>> {
    let alph = parse_b85_alphabet(args)?;
    Ok(base85_encode_with(input, &alph))
}

/// Memory-path Base85 decode (parses alphabet / ignore_non_alphabet).
pub(crate) fn base85_decode(
    input: &[u8],
    args: &HashMap<String, String>,
) -> anyhow::Result<Vec<u8>> {
    let alph = parse_b85_alphabet(args)?;
    let ignore = parse_bool(args.get("ignore_non_alphabet"))?;
    base85_decode_with(input, &alph, ignore)
}

struct Base85EncodeBuf {
    buf: Vec<u8>,
    alph: B85Alphabet,
}

pub(crate) fn make_base85_encode_stream(
    args: &HashMap<String, String>,
) -> anyhow::Result<Box<dyn StreamingOp>> {
    Ok(Box::new(Base85EncodeBuf {
        buf: Vec::new(),
        alph: parse_b85_alphabet(args)?,
    }))
}

impl StreamingOp for Base85EncodeBuf {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.buf.extend_from_slice(chunk);
        Ok(Vec::new())
    }
    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        let input = std::mem::take(&mut self.buf);
        Ok(base85_encode_with(&input, &self.alph))
    }
}

struct Base85DecodeBuf {
    buf: Vec<u8>,
    alph: B85Alphabet,
    ignore: bool,
}

pub(crate) fn make_base85_decode_stream(
    args: &HashMap<String, String>,
) -> anyhow::Result<Box<dyn StreamingOp>> {
    Ok(Box::new(Base85DecodeBuf {
        buf: Vec::new(),
        alph: parse_b85_alphabet(args)?,
        ignore: parse_bool(args.get("ignore_non_alphabet"))?,
    }))
}

impl StreamingOp for Base85DecodeBuf {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.buf.extend_from_slice(chunk);
        Ok(Vec::new())
    }
    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        let input = std::mem::take(&mut self.buf);
        base85_decode_with(&input, &self.alph, self.ignore)
    }
}

// ---------------------------------------------------------------------------
// Base45 (RFC 9285) - QR Code / DCC credential encoding.
// 2 bytes -> 3 chars (value < 45^3), 1 trailing byte -> 2 chars (value < 45^2).
// ---------------------------------------------------------------------------

const BASE45_ALPHABET: &[u8; 45] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

pub(crate) fn base45_encode(
    data: &[u8],
    _args: &HashMap<String, String>,
) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::with_capacity((data.len() * 3).div_ceil(2));
    let mut i = 0;
    while i < data.len() {
        if i + 1 < data.len() {
            let x = (data[i] as u32) * 256 + data[i + 1] as u32;
            let v0 = x / 2025;
            let rem = x % 2025;
            let v1 = rem / 45;
            let v2 = rem % 45;
            out.push(BASE45_ALPHABET[v0 as usize]);
            out.push(BASE45_ALPHABET[v1 as usize]);
            out.push(BASE45_ALPHABET[v2 as usize]);
            i += 2;
        } else {
            let x = data[i] as u32;
            out.push(BASE45_ALPHABET[(x / 45) as usize]);
            out.push(BASE45_ALPHABET[(x % 45) as usize]);
            i += 1;
        }
    }
    Ok(out)
}

pub(crate) fn base45_decode(
    data: &[u8],
    args: &HashMap<String, String>,
) -> anyhow::Result<Vec<u8>> {
    let ignore = args
        .get("ignore_non_alphabet")
        .map(|s| s.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let mut vals: Vec<u32> = Vec::with_capacity(data.len());
    for &b in data {
        if (b == b'\r' || b == b'\n' || b == b'\t') && ignore {
            continue;
        }
        if let Some(pos) = BASE45_ALPHABET.iter().position(|&c| c == b) {
            vals.push(pos as u32);
        } else if ignore {
            continue;
        } else {
            anyhow::bail!(
                "invalid base45 character {:?} (enable ignore_non_alphabet to skip)",
                b as char
            );
        }
    }
    let mut out = Vec::with_capacity((vals.len() * 2) / 3);
    let mut i = 0;
    while i < vals.len() {
        let rem = vals.len() - i;
        if rem >= 3 {
            let x = vals[i] * 2025 + vals[i + 1] * 45 + vals[i + 2];
            if x > 0xFFFF {
                anyhow::bail!("base45 group value {x} exceeds 2 bytes");
            }
            out.push((x >> 8) as u8);
            out.push((x & 0xFF) as u8);
            i += 3;
        } else {
            let x = vals[i] * 45 + vals[i + 1];
            if x > 0xFF {
                anyhow::bail!("base45 trailing group value {x} exceeds 1 byte");
            }
            out.push(x as u8);
            i += 2;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_roundtrip() {
        let data = b"Hello, dpa!";
        let enc = base64_encode(data, &HashMap::new()).unwrap();
        assert_eq!(enc, b"SGVsbG8sIGRwYSE=");
        let dec = base64_decode(&enc, &HashMap::new()).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn base64_decode_tolerates_whitespace() {
        let enc = b"SGVs bG8s\nIGRwYSE=";
        let dec = base64_decode(enc, &HashMap::new()).unwrap();
        assert_eq!(dec, b"Hello, dpa!");
    }

    #[test]
    fn base64url_uses_safe_alphabet() {
        // Standard Base64 of 0xfb 0xef 0xbe contains '+'; the URL-safe variant must use '-'.
        let data = [0xfbu8, 0xef, 0xbe];
        let enc = base64url_encode(&data, &HashMap::new()).unwrap();
        let s = String::from_utf8(enc).unwrap();
        assert!(
            !s.contains('+') && !s.contains('/'),
            "URL-safe encoding contains standard characters: {}",
            s
        );
        let dec = base64url_decode(s.as_bytes(), &HashMap::new()).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn base64url_decode_params() {
        let data = [0xfbu8, 0xef, 0xbe];
        let enc = base64url_encode(&data, &HashMap::new()).unwrap();
        assert_eq!(enc, b"----");
        // Default alphabet is url-safe.
        assert_eq!(base64url_decode(b"----", &HashMap::new()).unwrap(), data);
        // Explicit alphabet override to standard: '-' is invalid there...
        let mut std = HashMap::new();
        std.insert("alphabet".to_string(), "standard".to_string());
        assert!(base64url_decode(b"----", &std).is_err());
        // ...and with ignore_non_alphabet every '-' is dropped, yielding empty output.
        let mut ignore = HashMap::new();
        ignore.insert("alphabet".to_string(), "standard".to_string());
        ignore.insert("ignore_non_alphabet".to_string(), "true".to_string());
        assert_eq!(base64url_decode(b"----", &ignore).unwrap(), b"");
        // A '-' injected into standard-encoded data: rejected without ignore, fine with ignore.
        let polluted = b"SGVsbG8s-IGRwYSE=";
        assert!(base64url_decode(polluted, &std).is_err());
        assert_eq!(base64url_decode(polluted, &ignore).unwrap(), b"Hello, dpa!");
        // strict_mode enforces padding position under the pad-carrying standard alphabet.
        let mut strict = HashMap::new();
        strict.insert("alphabet".to_string(), "standard".to_string());
        strict.insert("strict_mode".to_string(), "true".to_string());
        assert_eq!(base64url_decode(b"SGVsbG8=", &strict).unwrap(), b"Hello");
        assert!(base64url_decode(b"SGVsbG8=Q", &strict).is_err()); // pad not at end
        // Stream path honours the same parameters and matches the memory path.
        let mut s = make_base64url_decode(&ignore).unwrap();
        let mut acc = Vec::new();
        acc.extend_from_slice(&s.write(b"SGVs").unwrap());
        acc.extend_from_slice(&s.write(b"bG8s-IGRwYSE=").unwrap());
        acc.extend_from_slice(&s.finish().unwrap());
        assert_eq!(acc, b"Hello, dpa!");
        let mut s2 = make_base64url_decode(&strict).unwrap();
        assert!(s2.write(b"SGVsbG8=Q").is_ok()); // write stage buffers; rejection surfaces at finish
        assert!(s2.finish().is_err());
    }

    #[test]
    fn base64_preset_url_matches_alias() {
        // The `url` alphabet argument must produce identical output to the dpa:base64:url alias.
        let data = [0xfbu8, 0xef, 0xbe];
        let args = HashMap::from([("alphabet".to_string(), "url".to_string())]);
        assert_eq!(
            base64_encode(&data, &args).unwrap(),
            base64url_encode(&data, &HashMap::new()).unwrap()
        );
        let enc = base64_encode(&data, &args).unwrap();
        let dec = base64_decode(&enc, &args).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn base64_range_expansion_equals_standard() {
        // The range expression A-Za-z0-9+/= must expand to the RFC 4648 standard alphabet.
        let args = HashMap::from([("alphabet".to_string(), "A-Za-z0-9+/=".to_string())]);
        let data = b"Hello, dpa! The quick brown fox jumps over the lazy dog.";
        let std_enc = base64_encode(data, &HashMap::new()).unwrap();
        let exp_enc = base64_encode(data, &args).unwrap();
        assert_eq!(exp_enc, std_enc);
        let dec = base64_decode(&exp_enc, &args).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn base64_custom_alphabet_known_vector() {
        // Custom alphabet with a different character order: "a-zA-Z0-9+/=" expands to
        // a-z, A-Z, 0-9, '+', '/', '=' (65 chars => '=' is the pad). Hand-computed vector:
        // b"Hi" => idx 18, 6, 36 + pad => "sgK=".
        let args = HashMap::from([("alphabet".to_string(), "a-zA-Z0-9+/=".to_string())]);
        let enc = base64_encode(b"Hi", &args).unwrap();
        assert_eq!(enc, b"sgK=");
        let dec = base64_decode(b"sgK=", &args).unwrap();
        assert_eq!(dec, b"Hi");
    }

    #[test]
    fn base64_custom_pad_char() {
        // A 64-char alphabet with an explicit pad argument: encode must use the custom pad.
        let args = HashMap::from([
            ("alphabet".to_string(), "A-Za-z0-9+/".to_string()),
            ("pad".to_string(), "~".to_string()),
        ]);
        let enc = base64_encode(b"Hi", &args).unwrap();
        assert_eq!(enc, b"SGk~");
        let dec = base64_decode(b"SGk~", &args).unwrap();
        assert_eq!(dec, b"Hi");
    }

    #[test]
    fn base64_invalid_alphabet_errors() {
        // Wrong length (62 after expansion).
        let args = HashMap::from([("alphabet".to_string(), "A-Za-z0-9".to_string())]);
        assert!(base64_encode(b"x", &args).is_err());
        // Descending range expression.
        let args = HashMap::from([("alphabet".to_string(), "a-A0-9+/=".to_string())]);
        assert!(base64_encode(b"x", &args).is_err());
        // Duplicate characters in the alphabet.
        let args = HashMap::from([("alphabet".to_string(), "A".repeat(65))]);
        assert!(base64_encode(b"x", &args).is_err());
    }

    #[test]
    fn base64_ignore_non_alphabet() {
        let dirty = b"SGVs*bG8s IGRwYSE!"; // '*' and '!' are outside the standard alphabet.
        let args = HashMap::from([("ignore_non_alphabet".to_string(), "true".to_string())]);
        let dec = base64_decode(dirty, &args).unwrap();
        assert_eq!(dec, b"Hello, dpa!");
        assert!(base64_decode(dirty, &HashMap::new()).is_err());
    }

    #[test]
    fn base64_custom_stream_matches_memory() {
        let args = HashMap::from([("alphabet".to_string(), "a-zA-Z0-9+/=".to_string())]);
        let input: Vec<u8> = (0u8..=255).collect();
        let enc_mem = base64_encode(&input, &args).unwrap();
        let mut h = make_base64_encode(&args).unwrap();
        let mut acc = Vec::new();
        for c in input.chunks(7) {
            acc.extend(h.write(c).unwrap());
        }
        acc.extend(h.finish().unwrap());
        assert_eq!(acc, enc_mem);
        let mut d = make_base64_decode(&args).unwrap();
        let mut dec = Vec::new();
        for c in enc_mem.chunks(11) {
            dec.extend(d.write(c).unwrap());
        }
        dec.extend(d.finish().unwrap());
        assert_eq!(dec, input);
    }

    #[test]
    fn base64_stream_uuencode_roundtrip() {
        // uuencode's alphabet contains a leading space; the streaming decoder
        // must keep it (not treat it as ignorable whitespace).
        let args = HashMap::from([("alphabet".to_string(), "uuencode".to_string())]);
        let input: Vec<u8> = (0u8..=255).collect();
        let mut h = make_base64_encode(&args).unwrap();
        let mut acc = Vec::new();
        for c in input.chunks(5) {
            acc.extend(h.write(c).unwrap());
        }
        acc.extend(h.finish().unwrap());
        assert!(acc.contains(&b' '), "uuencode output must contain spaces");
        let mut d = make_base64_decode(&args).unwrap();
        let mut dec = Vec::new();
        for c in acc.chunks(7) {
            dec.extend(d.write(c).unwrap());
        }
        dec.extend(d.finish().unwrap());
        assert_eq!(dec, input);
    }

    #[test]
    fn base64_all_presets_roundtrip() {
        // Every preset alphabet must round-trip encode -> decode for all tail
        // lengths (0..=257 covers every modulo-3 remainder, plus 0-byte input).
        let inputs: Vec<Vec<u8>> = (0..=257)
            .map(|n| (0..n).map(|i| (i * 31 + 7) as u8).collect())
            .chain(std::iter::once(Vec::new()))
            .collect();
        for &(name, _) in B64_PRESETS {
            for input in &inputs {
                let args = HashMap::from([("alphabet".to_string(), name.to_string())]);
                let enc = base64_encode(input, &args).unwrap();
                let dec = base64_decode(&enc, &args).unwrap();
                assert_eq!(&dec, input, "preset {name} length {}", input.len());
            }
        }
    }

    #[test]
    fn base64_presets_known_vectors() {
        // Hand-computed with an independent reference encoder over
        // "Hello, dpa!" (see presets in B64_PRESETS).
        let data = b"Hello, dpa!";
        let cases = [
            ("standard", "SGVsbG8sIGRwYSE="),
            ("url", "SGVsbG8sIGRwYSE="),
            ("url-safe", "SGVsbG8sIGRwYSE="),
            ("filename-safe", "SGVsbG8sIGRwYSE="),
            ("itoa64", "G4JgP4wg64FkMG2="),
            ("xml", "SGVsbG8sIGRwYSE"),
            ("y64", "SGVsbG8sIGRwYSE-"),
            ("z64", "i6lIr6YI86hMoi4="),
            ("radix64", "I6LiR6yi86HmOI4="),
            ("uuencode", "2&5L;&\\L(&1P82$"),
            ("xxencode", "G4JgP4wg64FkMG2"),
            ("binhex", "5'9XE'mX)'4`B5%"),
            ("rot13", "FTIfoT8fVTEjLFR="),
            ("crypt", "G4JgP4wg64FkMG2"),
            ("atom128", "DIH3+Iw3PIAqKDGC"),
            ("megan35", "cLf8lLC8NL=qicJ5"),
            ("zong22", "bySiUy3i0yYQIbn2"),
            ("hazz15", "0mAsEmpsimfGv0k5"),
        ];
        for (name, expected) in cases {
            let args = HashMap::from([("alphabet".to_string(), name.to_string())]);
            let enc = base64_encode(data, &args).unwrap();
            assert_eq!(enc, expected.as_bytes(), "preset {name} encode");
            let dec = base64_decode(expected.as_bytes(), &args).unwrap();
            assert_eq!(dec, data, "preset {name} decode");
        }
    }

    #[test]
    fn base64_strict_mode_errors() {
        let strict = HashMap::from([("strict_mode".to_string(), "true".to_string())]);
        // 4n+1 length is always rejected (lenient and strict alike; CyberChef
        // throws the same "cannot be represented" error in both modes).
        let s4n1 = b"SGVsb"; // 5 chars
        assert!(base64_decode(s4n1, &HashMap::new()).is_err());
        assert!(base64_decode(s4n1, &strict).is_err());
        // Misplaced padding: '=' before the end.
        let misplaced = b"SGVs=bG8=";
        assert!(base64_decode(misplaced, &strict).is_err());
        // Strict is the default, so misplaced padding is
        // rejected even without an explicit strict_mode argument.
        assert!(base64_decode(misplaced, &HashMap::new()).is_err());
        // Strict-mode failures must point users to the lenient
        // escape hatch (`--loose`) instead of leaving them stranded.
        let hint = base64_decode(misplaced, &HashMap::new())
            .unwrap_err()
            .to_string();
        assert!(hint.contains("--loose"), "{}", hint);
        // Extra padding: two '=' but length not a multiple of 4.
        let extra = b"SGVsbG8=="; // 10 chars
        assert!(base64_decode(extra, &strict).is_err());
        // Valid padded input still passes strict.
        let ok = b"SGVsbG8sIGRwYSE=";
        assert_eq!(base64_decode(ok, &strict).unwrap(), b"Hello, dpa!");
        // Unpadded input of 4n+3 length passes strict too (no padding present,
        // so the pad checks are skipped, exactly like CyberChef).
        let ok_unpadded = b"SGVsbG8"; // 7 chars -> "Hello"
        assert_eq!(base64_decode(ok_unpadded, &strict).unwrap(), b"Hello");
        // strict + ignore: 4n+1 after cleaning non-alphabet chars is fine.
        let mixed = HashMap::from([
            ("strict_mode".to_string(), "true".to_string()),
            ("ignore_non_alphabet".to_string(), "true".to_string()),
        ]);
        assert_eq!(
            base64_decode(b"SGVs*bG8s IGRwYSE=", &mixed).unwrap(),
            b"Hello, dpa!"
        );
    }

    #[test]
    fn base64_stream_rejects_mid_group_padding() {
        // The streaming decoder must not silently drop the chars
        // that follow a pad inside a 4-char group ("ab=c" used to decode as
        // 'i'). The default (no strict_mode arg) is strict.
        let mut s = make_base64_decode(&HashMap::new()).unwrap();
        assert!(s.write(b"abcd=fgh\n").is_err());
        // 'Q' after a full valid group leaves a 1-char tail: the mid-group pad
        // is legal here, but strict mode rejects the 4n+1 tail at finish().
        let mut s2 = make_base64_decode(&HashMap::new()).unwrap();
        assert!(s2.write(b"SGVsbG8=Q\n").is_ok());
        assert!(s2.finish().is_err());
        // Explicit lenient mode keeps rejecting chars after a pad inside a
        // group: they are structurally invalid, not a strictness choice.
        let lenient = HashMap::from([("strict_mode".to_string(), "false".to_string())]);
        let mut s3 = make_base64_decode(&lenient).unwrap();
        assert!(s3.write(b"abcd=fgh\n").is_err());
        // Trailing pads inside the final group still decode fine (including
        // the double-pad 2-char tail).
        let mut ok = make_base64_decode(&HashMap::new()).unwrap();
        let mut acc = ok.write(b"SGVsbG8=\n").unwrap();
        acc.extend(ok.finish().unwrap());
        assert_eq!(acc, b"Hello");
        let mut ok2 = make_base64_decode(&HashMap::new()).unwrap();
        let mut acc2 = ok2.write(b"SGk=\n").unwrap();
        acc2.extend(ok2.finish().unwrap());
        assert_eq!(acc2, b"Hi");
    }

    #[test]
    fn base64_errors_report_input_offsets() {
        // Every decode failure must name the exact input
        // byte offset ("at offset N") so users can locate bad input in large
        // buffers. Both the memory path and the streaming path are covered.
        let err_of_mem = |input: &[u8], args: &HashMap<String, String>| -> String {
            base64_decode(input, args).unwrap_err().to_string()
        };

        // 1) Invalid character: '!' sits at input offset 4.
        let e = err_of_mem(b"SGVs!G8=", &HashMap::new());
        assert!(e.contains("invalid character at offset 4"), "{}", e);
        // 2) Padding error: lenient mode flags the byte right after a
        // mid-group pad ('b' at offset 5).
        let loose = HashMap::from([("strict_mode".to_string(), "false".to_string())]);
        let e = err_of_mem(b"SGVs=bG8=", &loose);
        assert!(e.contains("invalid padding at offset 5"), "{}", e);
        // 3) Trailing group: a 4n+1 input is rejected at its final byte.
        let e = err_of_mem(b"SGVsb", &loose);
        assert!(e.contains("at offset 4"), "{}", e);
        // 4) Padded length not a multiple of 4: the pad lands at offset 10.
        let e = err_of_mem(b"SGVsbG8sIG=", &HashMap::new());
        assert!(e.contains("at offset 10"), "{}", e);

        // Streaming path reports the same offsets via B64DecodeStream.
        let mut s = make_base64_decode(&HashMap::new()).unwrap();
        assert!(s.write(b"SGVs!G8=\n").is_err());
        // The final group is buffered, so the error surfaces at finish() for
        // the tail case; the streaming error must still carry an offset.
        let mut s2 = make_base64_decode(&loose).unwrap();
        s2.write(b"SGVsb\n").unwrap();
        let e = s2.finish().unwrap_err().to_string();
        assert!(e.contains("at offset"), "stream tail: {}", e);

        // base64:url shares the same implementation and messages.
        let mut u = make_base64url_decode(&HashMap::new()).unwrap();
        assert!(u.write(b"SGVs!G8=\n").is_err());
    }

    #[test]
    fn base32_known_vector() {
        // Cross-checked against Python's stdlib base64.b32encode and an
        // independent 5-bit reference encoder.
        let cases: &[(&str, &[u8], &[u8])] = &[
            ("standard", b"foo", b"MZXW6==="),
            ("standard", b"Hello, dpa!", b"JBSWY3DPFQQGI4DBEE======"),
            ("extended-hex", b"foo", b"CPNMU==="),
            ("extended-hex", b"Hello, dpa!", b"91IMOR3F5GG68S3144======"),
            ("crockford", b"foo", b"CSQPY"),
            ("crockford", b"Hello, dpa!", b"91JPRV3F5GG68W3144"),
        ];
        for &(name, data, expected) in cases {
            let args = HashMap::from([("alphabet".to_string(), name.to_string())]);
            let enc = base32_encode(data, &args).unwrap();
            assert_eq!(&enc[..], expected, "preset {name} encode");
            let dec = base32_decode(expected, &args).unwrap();
            assert_eq!(&dec[..], data, "preset {name} decode");
        }
    }

    #[test]
    fn base32_presets_roundtrip_all_lengths() {
        for &(name, _) in B32_PRESETS {
            let args = HashMap::from([("alphabet".to_string(), name.to_string())]);
            for len in 0..=64usize {
                let data: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
                let enc = base32_encode(&data, &args).unwrap();
                let dec = base32_decode(&enc, &args).unwrap();
                assert_eq!(dec, data, "preset {name} len {len}");
            }
        }
    }

    #[test]
    fn base32_crockford_lenient_decode() {
        let args = HashMap::from([("alphabet".to_string(), "crockford".to_string())]);
        // I/L are aliases for 1, O for 0 on decode.
        assert_eq!(
            base32_decode(b"CSIPY", &args).unwrap(),
            base32_decode(b"CS1PY", &args).unwrap()
        );
        assert_eq!(
            base32_decode(b"COQPY", &args).unwrap(),
            base32_decode(b"C0QPY", &args).unwrap()
        );
        // Encoding always emits canonical Crockford chars (no I/L/O/U).
        let enc = base32_encode(b"foo", &args).unwrap();
        assert_eq!(enc, b"CSQPY");
        // Crockford tolerates '=' padding on decode even though encode omits it.
        let padded = HashMap::from([
            ("alphabet".to_string(), "crockford".to_string()),
            ("pad".to_string(), "=".to_string()),
        ]);
        assert_eq!(base32_decode(b"CSQPY===", &padded).unwrap(), b"foo");
    }

    #[test]
    fn base32_custom_alphabet_and_pad() {
        // 32-char custom alphabet without a pad arg: no padding emitted.
        let nopad = HashMap::from([("alphabet".to_string(), "A-Z2-7".to_string())]);
        assert_eq!(base32_encode(b"foo", &nopad).unwrap(), b"MZXW6");
        assert_eq!(base32_decode(b"MZXW6", &nopad).unwrap(), b"foo");
        // Same alphabet with a pad arg: padding emitted and enforced.
        let pad = HashMap::from([
            ("alphabet".to_string(), "A-Z2-7".to_string()),
            ("pad".to_string(), "-".to_string()),
        ]);
        assert_eq!(base32_encode(b"foo", &pad).unwrap(), b"MZXW6---");
        assert_eq!(base32_decode(b"MZXW6---", &pad).unwrap(), b"foo");
        // 33-char alphabet: 33rd char is the pad.
        let hex33 = HashMap::from([("alphabet".to_string(), "0-9A-V=".to_string())]);
        assert_eq!(base32_encode(b"foo", &hex33).unwrap(), b"CPNMU===");
        // Range expansion and \- escaping reuse the Base64 engine: here the
        // escaped dash becomes the 33rd char, i.e. the padding char.
        let custom = HashMap::from([("alphabet".to_string(), "A-Z2-7\\-".to_string())]);
        assert_eq!(base32_encode(b"foo", &custom).unwrap(), b"MZXW6---");
        assert_eq!(base32_decode(b"MZXW6---", &custom).unwrap(), b"foo");
        // Length validation: 3 chars is not 32/33.
        let bad = HashMap::from([("alphabet".to_string(), "ABC".to_string())]);
        assert!(base32_encode(b"x", &bad).is_err());
        // Duplicate char detection.
        let dup = HashMap::from([("alphabet".to_string(), "A-Z2-7A".to_string())]);
        assert!(base32_encode(b"x", &dup).is_err());
    }

    #[test]
    fn base32_ignore_and_strict() {
        let std = HashMap::new();
        // Whitespace is always ignored.
        assert_eq!(base32_decode(b"MZXW6 ===\n", &std).unwrap(), b"foo");
        // Invalid char fails by default, skipped with ignore=true.
        assert!(base32_decode(b"MZXW6*===", &std).is_err());
        let ignore = HashMap::from([("ignore_non_alphabet".to_string(), "true".to_string())]);
        assert_eq!(base32_decode(b"MZXW6*===", &ignore).unwrap(), b"foo");
        // Invalid trailing lengths (1/3/6 mod 8) always fail.
        assert!(base32_decode(b"M", &std).is_err()); // 1 mod 8
        assert!(base32_decode(b"MZXW6===", &std).is_ok());
        assert!(base32_decode(b"MZXW6===A", &std).is_err()); // 9 chars -> 1 mod 8
        // Padding must terminate the data.
        assert!(base32_decode(b"MZX=W6===", &std).is_err());
        // All-padding input is rejected.
        assert!(base32_decode(b"========", &std).is_err());
        // Unpadded valid input decodes fine.
        assert_eq!(base32_decode(b"MZXW6", &std).unwrap(), b"foo");
        // strict checks the unused pad bits are zero (RFC 4648 §3.5).
        let strict = HashMap::from([("strict_mode".to_string(), "true".to_string())]);
        assert_eq!(base32_decode(b"MZXW6===", &strict).unwrap(), b"foo");
        // Tampered trailing char with non-zero pad bits is rejected by strict.
        assert!(base32_decode(b"MZXW7", &strict).is_err());
        // ...but tolerated in lenient mode (same data, pad bit ignored).
        assert_eq!(base32_decode(b"MZXW7", &std).unwrap(), b"foo");
        // strict + ignore: cleaned input must still satisfy length rules.
        let mixed = HashMap::from([
            ("strict_mode".to_string(), "true".to_string()),
            ("ignore_non_alphabet".to_string(), "true".to_string()),
        ]);
        assert_eq!(base32_decode(b"MZXW6*===", &mixed).unwrap(), b"foo");
    }

    #[test]
    fn hex_roundtrip() {
        let data = [0x00u8, 0x2a, 0xff, 0x10];
        let enc = hex_encode(&data, &HashMap::new()).unwrap();
        assert_eq!(enc, b"002aff10");
        let dec = hex_decode(&enc, &HashMap::new()).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn hex_delimiter_and_uppercase() {
        let data = [0x00u8, 0x2a, 0xff];
        let mut args = HashMap::new();
        args.insert("delimiter".to_string(), "space".to_string());
        assert_eq!(hex_encode(&data, &args).unwrap(), b"00 2a ff");
        args.insert("delimiter".to_string(), "colon".to_string());
        assert_eq!(hex_encode(&data, &args).unwrap(), b"00:2a:ff");
        args.insert("delimiter".to_string(), "comma".to_string());
        assert_eq!(hex_encode(&data, &args).unwrap(), b"00,2a,ff");
        args.insert("delimiter".to_string(), "semicolon".to_string());
        assert_eq!(hex_encode(&data, &args).unwrap(), b"00;2a;ff");
        args.insert("delimiter".to_string(), "newline".to_string());
        assert_eq!(hex_encode(&data, &args).unwrap(), b"00\n2a\nff");
        args.insert("delimiter".to_string(), "crlf".to_string());
        assert_eq!(hex_encode(&data, &args).unwrap(), b"00\r\n2a\r\nff");
        // Uppercase.
        args.clear();
        args.insert("uppercase".to_string(), "true".to_string());
        assert_eq!(hex_encode(&data, &args).unwrap(), b"002AFF");
        args.insert("delimiter".to_string(), "space".to_string());
        assert_eq!(hex_encode(&data, &args).unwrap(), b"00 2A FF");
        // Unknown delimiter rejected.
        args.clear();
        args.insert("delimiter".to_string(), "bang".to_string());
        assert!(hex_encode(&data, &args).is_err());
        // Decode of delimited/uppercase output roundtrips.
        args.clear();
        args.insert("delimiter".to_string(), "space".to_string());
        args.insert("uppercase".to_string(), "true".to_string());
        let enc = hex_encode(&data, &args).unwrap();
        assert_eq!(hex_decode(&enc, &HashMap::new()).unwrap(), data);
    }

    #[test]
    fn hex_wrap_parameter() {
        let data: Vec<u8> = (0..10).collect();
        // Default: no wrapping.
        assert_eq!(
            hex_encode(&data, &HashMap::new()).unwrap(),
            b"00010203040506070809"
        );
        // bpl=8: newline after every 8 bytes, delimiter only within a line.
        let mut args = HashMap::new();
        args.insert("bytes_per_line".to_string(), "8".to_string());
        assert_eq!(hex_encode(&data, &args).unwrap(), b"0001020304050607\n0809");
        // bpl=8 with delimiter: line break replaces the delimiter.
        args.insert("delimiter".to_string(), "space".to_string());
        assert_eq!(
            hex_encode(&data, &args).unwrap(),
            b"00 01 02 03 04 05 06 07\n08 09"
        );
        // bpl=0 explicitly disables wrapping.
        args.clear();
        args.insert("bytes_per_line".to_string(), "0".to_string());
        assert_eq!(hex_encode(&data, &args).unwrap(), b"00010203040506070809");
        // Wrapped output still decodes to the original bytes.
        args.clear();
        args.insert("bytes_per_line".to_string(), "8".to_string());
        args.insert("delimiter".to_string(), "space".to_string());
        let enc = hex_encode(&data, &args).unwrap();
        assert_eq!(hex_decode(&enc, &HashMap::new()).unwrap(), data);
        // Invalid values rejected.
        for bad in ["4", "65", "abc", "-1"] {
            args.clear();
            args.insert("bytes_per_line".to_string(), bad.to_string());
            assert!(hex_encode(&data, &args).is_err(), "bpl={bad} should fail");
        }
        // Streaming path matches the in-memory path.
        args.clear();
        args.insert("bytes_per_line".to_string(), "8".to_string());
        args.insert("delimiter".to_string(), "space".to_string());
        let mut s = make_hex_encode(&args).unwrap();
        s.write(&data[..3]).unwrap();
        s.write(&data[3..7]).unwrap();
        s.write(&data[7..]).unwrap();
        assert_eq!(s.finish().unwrap(), hex_encode(&data, &args).unwrap());
    }

    #[test]
    fn hex_decode_delimiter() {
        let data = [0x00u8, 0x2a, 0xff, 0x10];
        let mut args = HashMap::new();
        args.insert("delimiter".to_string(), "space".to_string());
        assert_eq!(hex_decode(b"00 2a ff 10", &args).unwrap(), data);
        args.insert("delimiter".to_string(), "colon".to_string());
        assert_eq!(hex_decode(b"00:2a:ff:10", &args).unwrap(), data);
        args.insert("delimiter".to_string(), "comma".to_string());
        assert_eq!(hex_decode(b"00,2a,ff,10", &args).unwrap(), data);
        args.insert("delimiter".to_string(), "semicolon".to_string());
        assert_eq!(hex_decode(b"00;2a;ff;10", &args).unwrap(), data);
        args.insert("delimiter".to_string(), "newline".to_string());
        assert_eq!(hex_decode(b"00\n2a\nff\n10", &args).unwrap(), data);
        args.insert("delimiter".to_string(), "crlf".to_string());
        assert_eq!(hex_decode(b"00\r\n2a\r\nff\r\n10", &args).unwrap(), data);
        // Whitespace is still tolerated alongside a delimiter.
        args.clear();
        args.insert("delimiter".to_string(), "comma".to_string());
        assert_eq!(
            hex_decode(b"00, 2a, ff", &args).unwrap(),
            [0x00u8, 0x2a, 0xff]
        );
        // Without a delimiter, stray delimiter chars are rejected.
        assert!(hex_decode(b"00:2a", &HashMap::new()).is_err());
        // Invalid delimiter value still rejected.
        args.insert("delimiter".to_string(), "bang".to_string());
        assert!(hex_decode(b"00 2a", &args).is_err());
    }

    #[test]
    fn hex_ignore_non_alphabet() {
        let data = [0x00u8, 0x2a, 0xff, 0x10];
        // Without ignore, junk chars fail.
        assert!(hex_decode(b"00Z2a", &HashMap::new()).is_err());
        // With ignore, every non-hex char is dropped.
        let mut args = HashMap::new();
        args.insert("ignore_non_alphabet".to_string(), "true".to_string());
        assert_eq!(hex_decode(b"00Z2a;ff x10", &args).unwrap(), data);
        // Combined with a delimiter.
        args.insert("delimiter".to_string(), "comma".to_string());
        assert_eq!(hex_decode(b"00,,2aZff,10", &args).unwrap(), data);
        // Stream matches memory under ignore.
        let mut s = make_hex_decode(&args).unwrap();
        let mut acc = Vec::new();
        acc.extend_from_slice(&s.write(b"00,,2a").unwrap());
        acc.extend_from_slice(&s.write(b"Zff,1").unwrap());
        acc.extend_from_slice(&s.write(b"0").unwrap());
        acc.extend_from_slice(&s.finish().unwrap());
        assert_eq!(acc, data);
        // Invalid boolean rejected.
        let mut bad = HashMap::new();
        bad.insert("ignore_non_alphabet".to_string(), "maybe".to_string());
        assert!(hex_decode(b"00", &bad).is_err());
        assert!(make_hex_decode(&bad).is_err());
    }

    #[test]
    fn base58_known_vector() {
        // Bitcoin genesis block hash (hex), known Base58Check: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
        let raw = hex::decode("00010966776006953d5567439e5e39f86a0d273beed61967f6").unwrap();
        let enc = base58_encode(&raw, &HashMap::new()).unwrap();
        // Without the 4-byte checksum, prefix should match the well-known string minus last 6 chars.
        assert_eq!(
            String::from_utf8(enc.clone()).unwrap(),
            "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM"
        );
        let dec = base58_decode(&enc, &HashMap::new()).unwrap();
        assert_eq!(dec, raw);
    }

    #[test]
    fn base58_leading_zero_bytes() {
        let data = [0u8, 0, 1, 2, 3];
        let enc = base58_encode(&data, &HashMap::new()).unwrap();
        let s = String::from_utf8(enc.clone()).unwrap();
        assert!(s.starts_with("11"));
        let dec = base58_decode(&enc, &HashMap::new()).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn base58_rejects_invalid() {
        assert!(base58_decode(b"0OIl", &HashMap::new()).is_err());
    }

    #[test]
    fn base58_stream_matches_memory() {
        let input = b"Base58 streaming test payload \x00\xff\x10".to_vec();
        let enc_mem = base58_encode(&input, &HashMap::new()).unwrap();
        let mut h = make_base58_encode_stream(&HashMap::new()).unwrap();
        let mut acc = Vec::new();
        for c in input.chunks(9) {
            acc.extend(h.write(c).unwrap());
        }
        acc.extend(h.finish().unwrap());
        assert_eq!(acc, enc_mem);

        let mut d = make_base58_decode(&HashMap::new()).unwrap();
        let mut dec = Vec::new();
        for c in enc_mem.chunks(8) {
            dec.extend(d.write(c).unwrap());
        }
        dec.extend(d.finish().unwrap());
        assert_eq!(dec, input);
    }

    #[test]
    fn base58_ripple_known_vector() {
        // Cross-validated with a Python reference implementation.
        let raw = b"hello world";
        let mut args = HashMap::new();
        args.insert("alphabet".to_string(), "ripple".to_string());
        let enc = base58_encode(raw, &args).unwrap();
        assert_eq!(String::from_utf8(enc.clone()).unwrap(), "StVrDLaUATiyKyV");
        assert_eq!(base58_decode(&enc, &args).unwrap(), raw);

        let g = hex::decode("00010966776006953d5567439e5e39f86a0d273beed61967f6").unwrap();
        let enc2 = base58_encode(&g, &args).unwrap();
        assert_eq!(
            String::from_utf8(enc2.clone()).unwrap(),
            "ra7ALL9R51csQCPqB7vKoCHmBQfAMtjvM"
        );
        assert_eq!(base58_decode(&enc2, &args).unwrap(), g);
    }

    #[test]
    fn base58_custom_alphabet_range() {
        // The canonical Bitcoin alphabet spelled as ranges expands identically.
        let mut args = HashMap::new();
        args.insert("alphabet".to_string(), "1-9A-HJ-NP-Za-km-z".to_string());
        let enc = base58_encode(b"hello world", &args).unwrap();
        assert_eq!(String::from_utf8(enc).unwrap(), "StV1DL6CwTryKyV");
    }

    #[test]
    fn base58_ignore_non_alphabet() {
        let mut args = HashMap::new();
        let clean = b"StV1DL6CwTryKyV".to_vec();
        let mut dirty = Vec::new();
        for (i, &c) in clean.iter().enumerate() {
            if i % 3 == 1 {
                dirty.push(b'!');
            }
            dirty.push(c);
        }
        // Default is strict: out-of-alphabet chars are rejected.
        assert!(base58_decode(&dirty, &HashMap::new()).is_err());
        // ignore=true skips them (whitespace is always skipped).
        args.insert("ignore_non_alphabet".to_string(), "true".to_string());
        let dec = base58_decode(&dirty, &args).unwrap();
        assert_eq!(dec, b"hello world");
    }

    #[test]
    fn base58_invalid_position_message() {
        // '0' is not in the Bitcoin alphabet; the error must tag its position.
        let err = base58_decode(b"abc0def", &HashMap::new())
            .unwrap_err()
            .to_string();
        assert!(err.contains("'0'"), "err = {err}");
        assert!(err.contains("3"), "err = {err}");
    }

    #[test]
    fn base58_alphabet_validation() {
        // 36 chars -> length error.
        let mut a1 = HashMap::new();
        a1.insert("alphabet".to_string(), "A-Z0-9".to_string());
        assert!(base58_encode(b"x", &a1).is_err());
        // 58 chars with a duplicate -> duplicate error.
        let mut a2 = HashMap::new();
        a2.insert("alphabet".to_string(), "A".repeat(58));
        assert!(base58_encode(b"x", &a2).is_err());
    }

    #[test]
    fn base58_ripple_stream_matches_memory() {
        let input = b"\x00streaming ripple payload \xff\x00\x12".to_vec();
        let mut args = HashMap::new();
        args.insert("alphabet".to_string(), "ripple".to_string());
        let enc_mem = base58_encode(&input, &args).unwrap();
        let mut h = make_base58_encode_stream(&args).unwrap();
        let mut acc = Vec::new();
        for c in input.chunks(9) {
            acc.extend(h.write(c).unwrap());
        }
        acc.extend(h.finish().unwrap());
        assert_eq!(acc, enc_mem);

        let mut d = make_base58_decode(&args).unwrap();
        let mut dec = Vec::new();
        for c in enc_mem.chunks(7) {
            dec.extend(d.write(c).unwrap());
        }
        dec.extend(d.finish().unwrap());
        assert_eq!(dec, input);
    }

    #[test]
    fn base62_roundtrip() {
        let enc = base62_encode(b"Hello", &HashMap::new()).unwrap();
        assert_eq!(enc, b"5TP3P3v");
        assert_eq!(base62_decode(&enc, &HashMap::new()).unwrap(), b"Hello");
        // leading zeros are preserved
        assert_eq!(base62_encode(b"\x00\x01", &HashMap::new()).unwrap(), b"01");
        assert_eq!(base62_decode(b"01", &HashMap::new()).unwrap(), b"\x00\x01");
        // empty
        assert_eq!(base62_encode(b"", &HashMap::new()).unwrap(), b"");
        assert_eq!(base62_decode(b"", &HashMap::new()).unwrap(), b"");
    }

    #[test]
    fn base62_rejects_invalid() {
        assert!(base62_decode(b"hello!", &HashMap::new()).is_err());
        assert!(base62_decode(b"AB*C", &HashMap::new()).is_err());
    }

    #[test]
    fn base62_custom_alphabet_and_ignore() {
        // Custom 62-char alphabet (digits + letters swapped order) via range expansion.
        let mut args = HashMap::new();
        args.insert("alphabet".to_string(), "0-9A-Za-z".to_string());
        assert_eq!(base62_encode(b"Hello", &args).unwrap(), b"5TP3P3v");
        assert_eq!(base62_decode(b"5TP3P3v", &args).unwrap(), b"Hello");
        // Reversed alphabet keeps round-trip consistent.
        let mut rev = HashMap::new();
        rev.insert(
            "alphabet".to_string(),
            "zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA9876543210".to_string(),
        );
        let enc = base62_encode(b"abc123", &rev).unwrap();
        assert_eq!(base62_decode(&enc, &rev).unwrap(), b"abc123");
        // Wrong-length alphabet rejected.
        let mut short = HashMap::new();
        short.insert("alphabet".to_string(), "0-9A-Za".to_string());
        assert!(base62_encode(b"x", &short).is_err());
        // Duplicate chars rejected.
        let mut dup = HashMap::new();
        dup.insert("alphabet".to_string(), "0-9A-Za-".to_string());
        assert!(base62_encode(b"x", &dup).is_err());
        // ignore_non_alphabet drops stray chars.
        let mut ig = HashMap::new();
        ig.insert("ignore_non_alphabet".to_string(), "true".to_string());
        assert_eq!(base62_decode(b"5T P3P3v!", &ig).unwrap(), b"Hello");
        let mut ig2 = HashMap::new();
        ig2.insert("ignore_non_alphabet".to_string(), "false".to_string());
        assert!(base62_decode(b"5T P3P3v!", &ig2).is_err());
    }

    #[test]
    fn base85_custom_alphabet_presets_and_ignore() {
        // ascii85 preset keeps z compression and Adobe vectors.
        let mut a85 = HashMap::new();
        a85.insert("alphabet".to_string(), "ascii85".to_string());
        assert_eq!(base85_encode(b"\x00\x00\x00\x00", &a85).unwrap(), b"z");
        // z85 preset: z is an ordinary char (not compression).
        let mut z85 = HashMap::new();
        z85.insert("alphabet".to_string(), "z85".to_string());
        let enc = base85_encode(b"Hello", &z85).unwrap();
        assert_eq!(base85_decode(&enc, &z85).unwrap(), b"Hello");
        assert_ne!(base85_encode(b"\x00\x00\x00\x00", &z85).unwrap(), b"z");
        // rfc1924 preset round-trip.
        let mut rfc = HashMap::new();
        rfc.insert("alphabet".to_string(), "rfc1924".to_string());
        let enc2 = base85_encode(b"dpa test 123", &rfc).unwrap();
        assert_eq!(base85_decode(&enc2, &rfc).unwrap(), b"dpa test 123");
        // Custom alphabet via range expansion (33..117 == ascii85 chars).
        let mut cust = HashMap::new();
        cust.insert("alphabet".to_string(), "!-u".to_string());
        assert_eq!(base85_encode(b"Man ", &cust).unwrap(), b"9jqo^");
        assert_eq!(base85_decode(b"9jqo^", &cust).unwrap(), b"Man ");
        // Wrong length / duplicate alphabet rejected.
        let mut short = HashMap::new();
        short.insert("alphabet".to_string(), "!-t".to_string());
        assert!(base85_encode(b"x", &short).is_err());
        let mut dup = HashMap::new();
        dup.insert("alphabet".to_string(), "!-u!".to_string());
        assert!(base85_encode(b"x", &dup).is_err());
        // ignore_non_alphabet drops stray chars (whitespace always tolerated).
        let mut ig = HashMap::new();
        ig.insert("ignore_non_alphabet".to_string(), "true".to_string());
        assert_eq!(base85_decode(b"9j qo^|", &ig).unwrap(), b"Man ");
        let mut ig2 = HashMap::new();
        ig2.insert("ignore_non_alphabet".to_string(), "false".to_string());
        assert!(base85_decode(b"9j qo^|", &ig2).is_err());
    }

    #[test]
    fn base85_remove_zeros_parameter() {
        // Default: all-zero 4-byte group collapses to 'z' (Adobe ascii85).
        let def = HashMap::new();
        assert_eq!(base85_encode(b"\x00\x00\x00\x00", &def).unwrap(), b"z");
        // remove_zeros=false: literal 5-char group ('!!!!!' in ascii85).
        let mut off = HashMap::new();
        off.insert("remove_zeros".to_string(), "false".to_string());
        assert_eq!(base85_encode(b"\x00\x00\x00\x00", &off).unwrap(), b"!!!!!");
        // Symmetric decode: literal group round-trips; 'z' is now rejected as
        // out-of-alphabet unless ignore is set.
        assert_eq!(base85_decode(b"!!!!!", &off).unwrap(), b"\x00\x00\x00\x00");
        assert!(base85_decode(b"z", &off).is_err());
        // With ignore_non_alphabet, a stray 'z' is skipped entirely.
        let mut off_ig = HashMap::new();
        off_ig.insert("remove_zeros".to_string(), "false".to_string());
        off_ig.insert("ignore_non_alphabet".to_string(), "true".to_string());
        assert_eq!(
            base85_decode(b"z!!!!!", &off_ig).unwrap(),
            b"\x00\x00\x00\x00"
        );
        // Explicit true keeps the default behaviour; invalid bool rejected.
        let mut on = HashMap::new();
        on.insert("remove_zeros".to_string(), "true".to_string());
        assert_eq!(base85_encode(b"\x00\x00\x00\x00", &on).unwrap(), b"z");
        let mut bad = HashMap::new();
        bad.insert("remove_zeros".to_string(), "maybe".to_string());
        assert!(base85_encode(b"x", &bad).is_err());
        assert!(make_base85_encode_stream(&bad).is_err());
        // Streaming path honours remove_zeros.
        let mut s = make_base85_encode_stream(&off).unwrap();
        let mut acc = Vec::new();
        acc.extend_from_slice(&s.write(b"\x00\x00\x00\x00").unwrap());
        acc.extend_from_slice(&s.finish().unwrap());
        assert_eq!(acc, b"!!!!!");
    }

    #[test]
    fn base85_roundtrip() {
        // Adobe Ascii85 known vectors
        assert_eq!(base85_encode(b"Man ", &HashMap::new()).unwrap(), b"9jqo^");
        assert_eq!(
            base85_encode(b"Hello", &HashMap::new()).unwrap(),
            b"87cURDZ"
        );
        // z compression for zero group
        assert_eq!(
            base85_encode(b"\x00\x00\x00\x00", &HashMap::new()).unwrap(),
            b"z"
        );
        assert_eq!(base85_decode(b"9jqo^", &HashMap::new()).unwrap(), b"Man ");
        assert_eq!(
            base85_decode(b"87cURDZ", &HashMap::new()).unwrap(),
            b"Hello"
        );
        assert_eq!(
            base85_decode(b"z", &HashMap::new()).unwrap(),
            b"\x00\x00\x00\x00"
        );
        // whitespace tolerated
        assert_eq!(base85_decode(b"9jqo\n^", &HashMap::new()).unwrap(), b"Man ");
        // roundtrip
        let data = b"The quick brown fox jumps over the lazy dog";
        let enc = base85_encode(data, &HashMap::new()).unwrap();
        assert_eq!(base85_decode(&enc, &HashMap::new()).unwrap(), data);
    }

    #[test]
    fn base85_rejects_invalid() {
        assert!(base85_decode(b"abc~", &HashMap::new()).is_err());
        assert!(base85_decode(b"~", &HashMap::new()).is_err());
        // tail group shorter than 2 chars is incomplete
        assert!(base85_decode(b"9jqo^!", &HashMap::new()).is_err());
    }

    #[test]
    fn base45_vectors() {
        // Hand-computed RFC 9285 vectors: 1 byte -> 2 chars, 2 bytes -> 3 chars.
        let a = base45_encode(b"A", &HashMap::new()).unwrap();
        assert_eq!(a, b"1K");
        let ab = base45_encode(b"AB", &HashMap::new()).unwrap();
        assert_eq!(ab, b"8BB");
        let hello = base45_encode(b"Hello!!", &HashMap::new()).unwrap();
        // space (index 36) is a legitimate alphabet character
        assert_eq!(hello, b"96%DV E290X");
    }

    #[test]
    fn base45_roundtrip() {
        for len in 0..=20usize {
            let data: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let enc = base45_encode(&data, &HashMap::new()).unwrap();
            let dec = base45_decode(&enc, &HashMap::new()).unwrap();
            assert_eq!(dec, data, "roundtrip failed at len {len}");
        }
    }

    #[test]
    fn base45_decode_ignore_and_strict() {
        // Space is a valid alphabet char; CR/LF skipped when ignore=true.
        let enc = base45_encode(b"AB", &HashMap::new()).unwrap();
        let with_nl = format!("{}\r\n", String::from_utf8_lossy(&enc));
        let dec = base45_decode(
            with_nl.as_bytes(),
            &HashMap::from([("ignore_non_alphabet".to_string(), "true".to_string())]),
        )
        .unwrap();
        assert_eq!(dec, b"AB");
        // Strict mode fails on CR.
        assert!(base45_decode(with_nl.as_bytes(), &HashMap::new()).is_err());
    }
}
