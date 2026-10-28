//! Codec family: url/html/quoted-printable/punycode.

use std::collections::HashMap;

use super::base::base64_decode;
use super::{StreamingOp, hex_digit, hex_val, parse_bool};
use crate::i18n;

/// Streaming URL percent-encode: byte by byte (RFC 3986: alphanumerics and
/// `-._~` kept when preserve_unreserved, others %XX), no cross-block state.
struct UrlEncodeStream {
    preserve_unreserved: bool,
    use_plus: bool,
}

pub(crate) fn make_url_encode(
    args: &HashMap<String, String>,
) -> anyhow::Result<Box<dyn StreamingOp>> {
    let preserve = match args.get("preserve_unreserved") {
        None => true,
        Some(v) => parse_bool(Some(v))?,
    };
    let use_plus = parse_bool(args.get("use_plus"))?;
    Ok(Box::new(UrlEncodeStream {
        preserve_unreserved: preserve,
        use_plus,
    }))
}

impl StreamingOp for UrlEncodeStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(chunk.len() * 3);
        for &b in chunk {
            if b == b' ' && self.use_plus {
                out.push(b'+');
            } else if b.is_ascii_alphanumeric()
                || (self.preserve_unreserved && matches!(b, b'-' | b'.' | b'_' | b'~'))
            {
                out.push(b);
            } else {
                out.extend_from_slice(format!("%{:02X}", b).as_bytes());
            }
        }
        Ok(out)
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        Ok(Vec::new())
    }
}

pub(crate) fn url_encode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let preserve = match args.get("preserve_unreserved") {
        None => true,
        Some(v) => parse_bool(Some(v))?,
    };
    let use_plus = parse_bool(args.get("use_plus"))?;
    Ok(url_encode_with(input, preserve, use_plus))
}

/// RFC 3986 percent-encode: alphanumerics always kept; `-._~` kept when
/// preserve_unreserved is true (standard), otherwise also percent-encoded.
/// With `use_plus`, the space byte is emitted as `+` (form encoding); it is
/// still decoded back to a space by `url_decode` when use_plus is set there.
fn url_encode_with(input: &[u8], preserve_unreserved: bool, use_plus: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() * 3);
    for &b in input {
        if b == b' ' && use_plus {
            out.push(b'+');
        } else if b.is_ascii_alphanumeric()
            || (preserve_unreserved && matches!(b, b'-' | b'.' | b'_' | b'~'))
        {
            out.push(b);
        } else {
            out.extend_from_slice(format!("%{:02X}", b).as_bytes());
        }
    }
    out
}

/// RFC 3986 percent-decode: `%XX` sequences decoded byte-wise; invalid
/// sequences and all other bytes pass through unchanged (raw byte output,
/// no UTF-8 lossy replacement). With `use_plus`, `+` decodes to a space
/// (application/x-www-form-urlencoded form semantics).
pub(crate) fn url_decode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let use_plus = match args
        .get("use_plus")
        .map(|v| v.to_ascii_lowercase())
        .as_deref()
    {
        None | Some("false") | Some("0") | Some("no") => false,
        Some("true") | Some("1") | Some("yes") => true,
        Some(other) => anyhow::bail!("{}", i18n::tf("err.url_use_plus_invalid", &[other])),
    };
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        let b = input[i];
        if b == b'+' && use_plus {
            out.push(b' ');
            i += 1;
            continue;
        }
        if b == b'%' && i + 2 < input.len() {
            let hi = hex_val(input[i + 1]);
            let lo = hex_val(input[i + 2]);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(b);
        i += 1;
    }
    Ok(out)
}

/// Streaming URL percent-decode: keeps a pending `%` (and its first hex
/// nibble) across chunk boundaries so `%XX` split mid-sequence still decodes;
/// incomplete sequences are flushed verbatim in finish.
struct UrlDecodeStream {
    use_plus: bool,
    pending: Option<u8>, // Some(b'%') or Some(first-nibble char)
}

pub(crate) fn make_url_decode(
    args: &HashMap<String, String>,
) -> anyhow::Result<Box<dyn StreamingOp>> {
    let use_plus = match args
        .get("use_plus")
        .map(|v| v.to_ascii_lowercase())
        .as_deref()
    {
        None | Some("false") | Some("0") | Some("no") => false,
        Some("true") | Some("1") | Some("yes") => true,
        Some(other) => anyhow::bail!("{}", i18n::tf("err.url_use_plus_invalid", &[other])),
    };
    Ok(Box::new(UrlDecodeStream {
        use_plus,
        pending: None,
    }))
}

impl StreamingOp for UrlDecodeStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(chunk.len());
        for &c in chunk {
            match self.pending {
                None => {
                    if c == b'%' {
                        self.pending = Some(b'%');
                    } else if c == b'+' && self.use_plus {
                        out.push(b' ');
                    } else {
                        out.push(c);
                    }
                }
                Some(b'%') => {
                    if hex_val(c).is_some() {
                        self.pending = Some(c);
                    } else {
                        out.push(b'%');
                        out.push(c);
                        self.pending = None;
                    }
                }
                Some(hi) => {
                    if let Some(l) = hex_val(c) {
                        let h = hex_val(hi).unwrap();
                        out.push((h << 4) | l);
                        self.pending = None;
                    } else {
                        out.push(b'%');
                        out.push(hi);
                        out.push(c);
                        self.pending = None;
                    }
                }
            }
        }
        Ok(out)
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(2);
        if let Some(p) = self.pending.take() {
            out.push(b'%');
            if p != b'%' {
                out.push(p);
            }
        }
        Ok(out)
    }
}

/// Common named HTML entities beyond the five mandatory ones.
const HTML_NAMED_ENTITIES: &[(&str, &str)] = &[
    ("nbsp", "\u{a0}"),
    ("iexcl", "\u{a1}"),
    ("cent", "\u{a2}"),
    ("pound", "\u{a3}"),
    ("curren", "\u{a4}"),
    ("yen", "\u{a5}"),
    ("brvbar", "\u{a6}"),
    ("sect", "\u{a7}"),
    ("uml", "\u{a8}"),
    ("copy", "\u{a9}"),
    ("ordf", "\u{aa}"),
    ("laquo", "\u{ab}"),
    ("not", "\u{ac}"),
    ("shy", "\u{ad}"),
    ("reg", "\u{ae}"),
    ("macr", "\u{af}"),
    ("deg", "\u{b0}"),
    ("plusmn", "\u{b1}"),
    ("sup2", "\u{b2}"),
    ("sup3", "\u{b3}"),
    ("acute", "\u{b4}"),
    ("micro", "\u{b5}"),
    ("para", "\u{b6}"),
    ("middot", "\u{b7}"),
    ("cedil", "\u{b8}"),
    ("sup1", "\u{b9}"),
    ("ordm", "\u{ba}"),
    ("raquo", "\u{bb}"),
    ("frac14", "\u{bc}"),
    ("frac12", "\u{bd}"),
    ("frac34", "\u{be}"),
    ("iquest", "\u{bf}"),
    ("Agrave", "\u{c0}"),
    ("Aacute", "\u{c1}"),
    ("Acirc", "\u{c2}"),
    ("Atilde", "\u{c3}"),
    ("Auml", "\u{c4}"),
    ("Aring", "\u{c5}"),
    ("AElig", "\u{c6}"),
    ("Ccedil", "\u{c7}"),
    ("Egrave", "\u{c8}"),
    ("Eacute", "\u{c9}"),
    ("Ecirc", "\u{ca}"),
    ("Euml", "\u{cb}"),
    ("Igrave", "\u{cc}"),
    ("Iacute", "\u{cd}"),
    ("Icirc", "\u{ce}"),
    ("Iuml", "\u{cf}"),
    ("ETH", "\u{d0}"),
    ("Ntilde", "\u{d1}"),
    ("Ograve", "\u{d2}"),
    ("Oacute", "\u{d3}"),
    ("Ocirc", "\u{d4}"),
    ("Otilde", "\u{d5}"),
    ("Ouml", "\u{d6}"),
    ("times", "\u{d7}"),
    ("Oslash", "\u{d8}"),
    ("Ugrave", "\u{d9}"),
    ("Uacute", "\u{da}"),
    ("Ucirc", "\u{db}"),
    ("Uuml", "\u{dc}"),
    ("Yacute", "\u{dd}"),
    ("THORN", "\u{de}"),
    ("szlig", "\u{df}"),
    ("agrave", "\u{e0}"),
    ("aacute", "\u{e1}"),
    ("acirc", "\u{e2}"),
    ("atilde", "\u{e3}"),
    ("auml", "\u{e4}"),
    ("aring", "\u{e5}"),
    ("aelig", "\u{e6}"),
    ("ccedil", "\u{e7}"),
    ("egrave", "\u{e8}"),
    ("eacute", "\u{e9}"),
    ("ecirc", "\u{ea}"),
    ("euml", "\u{eb}"),
    ("igrave", "\u{ec}"),
    ("iacute", "\u{ed}"),
    ("icirc", "\u{ee}"),
    ("iuml", "\u{ef}"),
    ("eth", "\u{f0}"),
    ("ntilde", "\u{f1}"),
    ("ograve", "\u{f2}"),
    ("oacute", "\u{f3}"),
    ("ocirc", "\u{f4}"),
    ("otilde", "\u{f5}"),
    ("ouml", "\u{f6}"),
    ("divide", "\u{f7}"),
    ("oslash", "\u{f8}"),
    ("ugrave", "\u{f9}"),
    ("uacute", "\u{fa}"),
    ("ucirc", "\u{fb}"),
    ("uuml", "\u{fc}"),
    ("yacute", "\u{fd}"),
    ("thorn", "\u{fe}"),
    ("yuml", "\u{ff}"),
    ("OElig", "\u{152}"),
    ("oelig", "\u{153}"),
    ("Scaron", "\u{160}"),
    ("scaron", "\u{161}"),
    ("Yuml", "\u{178}"),
    ("fnof", "\u{192}"),
    ("circ", "\u{2c6}"),
    ("tilde", "\u{2dc}"),
    ("Alpha", "\u{391}"),
    ("Beta", "\u{392}"),
    ("Gamma", "\u{393}"),
    ("Delta", "\u{394}"),
    ("epsilon", "\u{3b5}"),
    ("theta", "\u{3b8}"),
    ("lambda", "\u{3bb}"),
    ("pi", "\u{3c0}"),
    ("sigma", "\u{3c3}"),
    ("phi", "\u{3c6}"),
    ("omega", "\u{3c9}"),
    ("hellip", "\u{2026}"),
    ("prime", "\u{2032}"),
    ("Prime", "\u{2033}"),
    ("lsaquo", "\u{2039}"),
    ("rsaquo", "\u{203a}"),
    ("oline", "\u{203e}"),
    ("frasl", "\u{2044}"),
    ("euro", "\u{20ac}"),
    ("trade", "\u{2122}"),
    ("larr", "\u{2190}"),
    ("uarr", "\u{2191}"),
    ("rarr", "\u{2192}"),
    ("darr", "\u{2193}"),
    ("harr", "\u{2194}"),
    ("forall", "\u{2200}"),
    ("part", "\u{2202}"),
    ("exist", "\u{2203}"),
    ("empty", "\u{2205}"),
    ("nabla", "\u{2207}"),
    ("isin", "\u{2208}"),
    ("notin", "\u{2209}"),
    ("ni", "\u{220b}"),
    ("prod", "\u{220f}"),
    ("sum", "\u{2211}"),
    ("minus", "\u{2212}"),
    ("lowast", "\u{2217}"),
    ("radic", "\u{221a}"),
    ("prop", "\u{221d}"),
    ("infin", "\u{221e}"),
    ("ang", "\u{2220}"),
    ("and", "\u{2227}"),
    ("or", "\u{2228}"),
    ("cap", "\u{2229}"),
    ("cup", "\u{222a}"),
    ("int", "\u{222b}"),
    ("there4", "\u{2234}"),
    ("sim", "\u{223c}"),
    ("cong", "\u{2245}"),
    ("asymp", "\u{2248}"),
    ("ne", "\u{2260}"),
    ("equiv", "\u{2261}"),
    ("le", "\u{2264}"),
    ("ge", "\u{2265}"),
    ("sub", "\u{2282}"),
    ("sup", "\u{2283}"),
    ("nsub", "\u{2284}"),
    ("sube", "\u{2286}"),
    ("supe", "\u{2287}"),
    ("oplus", "\u{2295}"),
    ("otimes", "\u{2297}"),
    ("perp", "\u{22a5}"),
    ("sdot", "\u{22c5}"),
    ("lceil", "\u{2308}"),
    ("rceil", "\u{2309}"),
    ("lfloor", "\u{230a}"),
    ("rfloor", "\u{230b}"),
    ("lang", "\u{2329}"),
    ("rang", "\u{232a}"),
    ("loz", "\u{25ca}"),
    ("spades", "\u{2660}"),
    ("clubs", "\u{2663}"),
    ("hearts", "\u{2665}"),
    ("diams", "\u{2666}"),
];

fn lookup_html_entity(name: &str) -> Option<&'static str> {
    match name {
        "amp" => Some("&"),
        "lt" => Some("<"),
        "gt" => Some(">"),
        "quot" => Some("\""),
        "apos" => Some("'"),
        other => HTML_NAMED_ENTITIES
            .iter()
            .find(|(k, _)| *k == other)
            .map(|(_, v)| *v),
    }
}

/// Entity format for HTML encoding (mirrors CyberChef To HTMLEntity "Encode
/// everything" + entity type options). `Auto` keeps the historical behaviour:
/// five specials become named entities unless `encode_all` switches to decimal
/// numeric entities.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]

enum HtmlEncodeFormat {
    Auto,
    Named,
    Numeric,
    Hex,
}

fn parse_html_encode_format(args: &HashMap<String, String>) -> anyhow::Result<HtmlEncodeFormat> {
    match args
        .get("format")
        .map(|v| v.to_ascii_lowercase())
        .as_deref()
    {
        None | Some("auto") => Ok(HtmlEncodeFormat::Auto),
        Some("named") => Ok(HtmlEncodeFormat::Named),
        Some("numeric") => Ok(HtmlEncodeFormat::Numeric),
        Some("hex") => Ok(HtmlEncodeFormat::Hex),
        Some(other) => anyhow::bail!(
            "{}",
            i18n::tf(
                "err.html_encode_format_invalid",
                &[other, "auto / named / numeric / hex"]
            )
        ),
    }
}

/// Reverse lookup of the shared Latin-1 named-entity table: char -> entity name.
fn char_to_entity_name(c: char) -> Option<&'static str> {
    HTML_NAMED_ENTITIES
        .iter()
        .find(|(_, v)| v.starts_with(c))
        .map(|(k, _)| *k)
}

/// Append one character as an entity in the requested explicit format.
fn emit_html_entity(out: &mut Vec<u8>, c: char, format: HtmlEncodeFormat) {
    match format {
        HtmlEncodeFormat::Named => {
            if let Some(name) = char_to_entity_name(c) {
                out.push(b'&');
                out.extend_from_slice(name.as_bytes());
                out.push(b';');
            } else {
                out.extend_from_slice(format!("&#{};", c as u32).as_bytes());
            }
        }
        HtmlEncodeFormat::Numeric => out.extend_from_slice(format!("&#{};", c as u32).as_bytes()),
        HtmlEncodeFormat::Hex => out.extend_from_slice(format!("&#x{:X};", c as u32).as_bytes()),
        HtmlEncodeFormat::Auto => {
            // Unreachable for explicit-format callers; kept for exhaustiveness.
            out.extend_from_slice(format!("&#{};", c as u32).as_bytes());
        }
    }
}

/// The five HTML specials, for the non-encode_all path.
fn emit_html_special(out: &mut Vec<u8>, b: u8, format: HtmlEncodeFormat) {
    let c = b as char;
    match format {
        HtmlEncodeFormat::Named => match b {
            b'&' => out.extend_from_slice(b"&amp;"),
            b'<' => out.extend_from_slice(b"&lt;"),
            b'>' => out.extend_from_slice(b"&gt;"),
            b'"' => out.extend_from_slice(b"&quot;"),
            _ => out.extend_from_slice(b"&apos;"),
        },
        _ => emit_html_entity(out, c, format),
    }
}

/// Encode HTML special characters; with `encode_all` every non-ASCII byte and
/// the five specials become a decimal numeric entity (CyberChef-style).
pub(crate) fn html_encode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let encode_all = match args
        .get("encode_all")
        .map(|v| v.to_ascii_lowercase())
        .as_deref()
    {
        None | Some("false") | Some("0") | Some("no") => false,
        Some("true") | Some("1") | Some("yes") => true,
        Some(other) => anyhow::bail!("{}", i18n::tf("err.html_encode_all_invalid", &[other])),
    };
    let format = parse_html_encode_format(args)?;
    let mut out = Vec::with_capacity(input.len());

    // Auto keeps the historical output byte-for-byte.
    if format == HtmlEncodeFormat::Auto {
        if !encode_all {
            for &b in input {
                match b {
                    b'&' => out.extend_from_slice(b"&amp;"),
                    b'<' => out.extend_from_slice(b"&lt;"),
                    b'>' => out.extend_from_slice(b"&gt;"),
                    b'"' => out.extend_from_slice(b"&quot;"),
                    b'\'' => out.extend_from_slice(b"&#39;"),
                    _ => out.push(b),
                }
            }
            return Ok(out);
        }
        // encode_all: every non-ASCII character and the five specials become a
        // decimal numeric entity; printable ASCII passes through.
        if let Ok(s) = std::str::from_utf8(input) {
            for ch in s.chars() {
                match ch {
                    '&' => out.extend_from_slice(b"&#38;"),
                    '<' => out.extend_from_slice(b"&#60;"),
                    '>' => out.extend_from_slice(b"&#62;"),
                    '"' => out.extend_from_slice(b"&#34;"),
                    '\'' => out.extend_from_slice(b"&#39;"),
                    c if c.is_ascii() && !c.is_control() => out.push(c as u8),
                    c => out.extend_from_slice(format!("&#{};", c as u32).as_bytes()),
                }
            }
            return Ok(out);
        }
        // Binary fallback: encode every byte outside printable ASCII.
        for &b in input {
            match b {
                b'&' => out.extend_from_slice(b"&#38;"),
                b'<' => out.extend_from_slice(b"&#60;"),
                b'>' => out.extend_from_slice(b"&#62;"),
                b'"' => out.extend_from_slice(b"&#34;"),
                b'\'' => out.extend_from_slice(b"&#39;"),
                0x20..=0x7e => out.push(b),
                _ => out.extend_from_slice(format!("&#{};", b).as_bytes()),
            }
        }
        return Ok(out);
    }

    // Explicit format: the five specials always become entities; non-ASCII
    // characters become entities only when encode_all is set.
    if !encode_all {
        for &b in input {
            match b {
                b'&' | b'<' | b'>' | b'"' | b'\'' => emit_html_special(&mut out, b, format),
                _ => out.push(b),
            }
        }
        return Ok(out);
    }
    if let Ok(s) = std::str::from_utf8(input) {
        for ch in s.chars() {
            match ch {
                '&' | '<' | '>' | '"' | '\'' => emit_html_special(&mut out, ch as u8, format),
                c if c.is_ascii() && !c.is_control() => out.push(c as u8),
                c => emit_html_entity(&mut out, c, format),
            }
        }
        return Ok(out);
    }
    for &b in input {
        match b {
            b'&' | b'<' | b'>' | b'"' | b'\'' => emit_html_special(&mut out, b, format),
            0x20..=0x7e => out.push(b),
            _ => emit_html_entity(&mut out, b as char, format),
        }
    }
    Ok(out)
}

/// Decode named entities (common HTML4/HTML5 set) and numeric entities
/// (&amp; &lt; &gt; &quot; &#39; &#NN; &#xHH;).
#[derive(Clone, Copy, PartialEq, Eq)]

enum HtmlDecodeMode {
    /// Both named and numeric entities (backward-compatible default).
    Both,
    /// Named entities only (&amp; &lt; ...); numeric entities are left as-is.
    Named,
    /// Numeric entities only (&#NN; &#xHH;); named entities are left as-is.
    Numeric,
}

fn parse_html_decode_mode(args: &HashMap<String, String>) -> anyhow::Result<HtmlDecodeMode> {
    match args.get("mode").map(|v| v.to_ascii_lowercase()).as_deref() {
        None | Some("both") | Some("all") => Ok(HtmlDecodeMode::Both),
        Some("html") | Some("named") => Ok(HtmlDecodeMode::Named),
        Some("numeric") | Some("num") => Ok(HtmlDecodeMode::Numeric),
        Some(other) => anyhow::bail!("{}", i18n::tf("err.html_mode_invalid", &[other])),
    }
}

pub(crate) fn html_decode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let mode = parse_html_decode_mode(args)?;
    html_decode_with(input, mode)
}

fn html_decode_with(input: &[u8], mode: HtmlDecodeMode) -> anyhow::Result<Vec<u8>> {
    let s = std::str::from_utf8(input)?;
    let mut out = Vec::with_capacity(input.len());
    let bytes = s.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] != b'&' {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        // Find terminating ';' within a reasonable window (<= 12 chars).
        let end = bytes[i..].iter().position(|&c| c == b';').map(|p| i + p);
        let Some(semi) = end else {
            out.push(bytes[i]);
            i += 1;
            continue;
        };
        if semi - i > 12 {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        let ent = &s[i + 1..semi];
        let is_numeric = ent.starts_with('#');
        let decoded: Option<Vec<u8>> = match mode {
            HtmlDecodeMode::Numeric => {
                if !is_numeric {
                    None
                } else {
                    parse_numeric_html_entity(ent)
                }
            }
            HtmlDecodeMode::Named => {
                if is_numeric {
                    None
                } else {
                    lookup_html_entity(ent).map(|v| v.as_bytes().to_vec())
                }
            }
            HtmlDecodeMode::Both => {
                if is_numeric {
                    parse_numeric_html_entity(ent)
                } else {
                    lookup_html_entity(ent).map(|v| v.as_bytes().to_vec())
                }
            }
        };
        match decoded {
            Some(d) => {
                out.extend_from_slice(&d);
                i = semi + 1;
            }
            None => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }
    Ok(out)
}

/// Parse a numeric HTML entity body (already stripped of the leading `&` and
/// trailing `;`): `#xHH...` hex or `#NNN` decimal. Returns the decoded UTF-8
/// bytes, or None when the entity is not numeric or the code point is invalid.
fn parse_numeric_html_entity(ent: &str) -> Option<Vec<u8>> {
    let decode = |cp: u32| -> Option<Vec<u8>> {
        // WHATWG-style handling of code point 0: `&#0;` must not inject
        // a NUL byte into the output stream, replace it with U+FFFD instead.
        // Out-of-range (>= 0xD800 surrogate / > 0x10FFFF) code points are
        // rejected by char::from_u32 and left verbatim by the caller.
        if cp == 0 {
            return Some("\u{FFFD}".to_string().into_bytes());
        }
        char::from_u32(cp).map(|c| c.to_string().into_bytes())
    };
    if let Some(num) = ent.strip_prefix("#x").or_else(|| ent.strip_prefix("#X")) {
        u32::from_str_radix(num, 16).ok().and_then(decode)
    } else if let Some(num) = ent.strip_prefix('#') {
        num.parse::<u32>().ok().and_then(decode)
    } else {
        None
    }
}

struct HtmlEncodeStream {
    encode_all: bool,
    format: HtmlEncodeFormat,
}

pub(crate) fn make_html_encode(
    args: &HashMap<String, String>,
) -> anyhow::Result<Box<dyn StreamingOp>> {
    let encode_all = match args
        .get("encode_all")
        .map(|v| v.to_ascii_lowercase())
        .as_deref()
    {
        None | Some("false") | Some("0") | Some("no") => false,
        Some("true") | Some("1") | Some("yes") => true,
        Some(other) => anyhow::bail!("{}", i18n::tf("err.html_encode_all_invalid", &[other])),
    };
    let format = parse_html_encode_format(args)?;
    Ok(Box::new(HtmlEncodeStream { encode_all, format }))
}

impl StreamingOp for HtmlEncodeStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut args = HashMap::new();
        if self.encode_all {
            args.insert("encode_all".to_string(), "true".to_string());
        }
        match self.format {
            HtmlEncodeFormat::Auto => {}
            HtmlEncodeFormat::Named => {
                args.insert("format".to_string(), "named".to_string());
            }
            HtmlEncodeFormat::Numeric => {
                args.insert("format".to_string(), "numeric".to_string());
            }
            HtmlEncodeFormat::Hex => {
                args.insert("format".to_string(), "hex".to_string());
            }
        }
        html_encode(chunk, &args)
    }
    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        Ok(Vec::new())
    }
}

/// Streaming html decode: keep a possible partial '&...' tail across chunks.
struct HtmlDecodeStream {
    pending: Vec<u8>,
    mode: HtmlDecodeMode,
}

pub(crate) fn make_html_decode(
    args: &HashMap<String, String>,
) -> anyhow::Result<Box<dyn StreamingOp>> {
    let mode = parse_html_decode_mode(args)?;
    Ok(Box::new(HtmlDecodeStream {
        pending: Vec::new(),
        mode,
    }))
}

impl StreamingOp for HtmlDecodeStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.pending.extend_from_slice(chunk);
        // Keep the tail starting from the last '&' (it may continue into the next chunk).
        let split = match self.pending.iter().rposition(|&c| c == b'&') {
            Some(p) => p,
            None => self.pending.len(),
        };
        let head: Vec<u8> = self.pending.drain(..split).collect();
        html_decode_with(&head, self.mode)
    }
    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        let tail = std::mem::take(&mut self.pending);
        html_decode_with(&tail, self.mode)
    }
}

// ---------------------------------------------------------------------------
// Quoted-printable (P1, deep): RFC 2045, '=' -> =3D, non-printable -> =XX,
// soft breaks. Encode honours a configurable line width (`wrap`); wrap=0
// disables soft line breaking entirely (mirrors CyberChef's line length).
// ---------------------------------------------------------------------------

fn parse_qp_wrap(args: &HashMap<String, String>) -> anyhow::Result<usize> {
    match args.get("wrap") {
        None => Ok(76),
        Some(s) => {
            let v: usize = s.parse().map_err(|_| {
                anyhow::anyhow!("{}", i18n::tf("err.qp_wrap_invalid", &[s.as_str()]))
            })?;
            Ok(v)
        }
    }
}

/// RFC 2047 §4.2 Q-encoding safe characters (besides '=').
fn qp_q_safe(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'!' | b'*' | b'+' | b'-' | b'/')
}

/// Encode Quoted-Printable. `header_mode` switches to RFC 2047 Q-encoding
/// (space becomes '_', only Q-safe characters pass through); `encode_all`
/// hex-escapes every printable ASCII byte even when it would not strictly
/// need it (mirrors CyberChef's "Encode all" toggle).
fn qp_encode_with(input: &[u8], wrap: usize, header_mode: bool, encode_all: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len() + input.len() / 3 + 8);
    let mut col = 0usize;
    let mut i = 0usize;
    while i < input.len() {
        let b = input[i];
        // Hard line break: pass CRLF / LF through and reset column.
        if b == b'\r' {
            out.push(b'\r');
            i += 1;
            if i < input.len() && input[i] == b'\n' {
                out.push(b'\n');
                i += 1;
            }
            col = 0;
            continue;
        }
        if b == b'\n' {
            out.push(b'\n');
            i += 1;
            col = 0;
            continue;
        }
        let enc: &[u8] = if b == b'=' {
            b"=3D"
        } else if header_mode {
            if b == b' ' {
                b"_"
            } else if qp_q_safe(b) {
                &[b]
            } else {
                &[b'=', hex_digit(b >> 4), hex_digit(b & 0x0f)]
            }
        } else if encode_all && (b.is_ascii_graphic() || b == b' ' || b == b'\t') {
            // Encode all: even printable ASCII is hex-escaped.
            &[b'=', hex_digit(b >> 4), hex_digit(b & 0x0f)]
        } else if b.is_ascii_graphic() || b == b' ' || b == b'\t' {
            // printable ASCII (33-126); '=' handled above; space/tab allowed.
            &[b]
        } else {
            &[b'=', hex_digit(b >> 4), hex_digit(b & 0x0f)]
        };
        // Enforce the configured line limit with a soft break "=\r\n".
        if wrap > 0 && col + enc.len() > wrap {
            out.extend_from_slice(b"=\r\n");
            col = 0;
        }
        out.extend_from_slice(enc);
        col += enc.len();
        i += 1;
    }
    out
}

pub(crate) fn qp_encode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let wrap = parse_qp_wrap(args)?;
    let header_mode = parse_bool(args.get("header_mode"))?;
    let encode_all = parse_bool(args.get("encode_all"))?;
    Ok(qp_encode_with(input, wrap, header_mode, encode_all))
}

pub(crate) fn qp_decode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let header_mode = match args
        .get("header_mode")
        .map(|v| v.to_ascii_lowercase())
        .as_deref()
    {
        None | Some("false") | Some("0") | Some("no") => false,
        Some("true") | Some("1") | Some("yes") => true,
        Some(other) => anyhow::bail!("{}", i18n::tf("err.qp_header_mode_invalid", &[other])),
    };
    Ok(qp_decode_with(input, header_mode))
}

/// Decode Quoted-Printable. In `header_mode` (RFC 2047), `=?charset?Q?..?=`
/// and `=?charset?B?..?=` encoded-words are decoded (Q uses '_' for space);
/// all other text passes through unchanged.
fn qp_decode_with(input: &[u8], header_mode: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0usize;
    while i < input.len() {
        if header_mode
            && input[i] == b'='
            && i + 1 < input.len()
            && input[i + 1] == b'?'
            && let Some((bytes, next)) = decode_rfc2047_word(input, i)
        {
            out.extend_from_slice(&bytes);
            i = next;
            continue;
        }
        let b = input[i];
        if b == b'=' {
            if i + 2 < input.len() && input[i + 1] == b'\r' && input[i + 2] == b'\n' {
                i += 3; // soft break: drop
                continue;
            }
            if i + 1 < input.len() && input[i + 1] == b'\n' {
                i += 2; // soft break (bare LF): drop
                continue;
            }
            if i + 2 < input.len()
                && let (Some(h), Some(l)) = (hex_val(input[i + 1]), hex_val(input[i + 2]))
            {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
            // Not a valid escape: keep '=' verbatim.
            out.push(b'=');
            i += 1;
            continue;
        }
        out.push(b);
        i += 1;
    }
    out
}

/// Try to decode an RFC 2047 encoded-word starting at `start` (which points
/// at '='). Returns the decoded bytes and the index just past the trailing
/// `?=`; `None` if the region is not a well-formed encoded-word.
fn decode_rfc2047_word(input: &[u8], start: usize) -> Option<(Vec<u8>, usize)> {
    // =?charset?X?payload?=  (X is 'Q' or 'B'; payload may contain '?')
    let mut p = start + 2;
    let charset_start = p;
    while p < input.len() && input[p] != b'?' {
        p += 1;
    }
    if p >= input.len() || p == charset_start {
        return None;
    }
    p += 1; // past charset '?'
    if p >= input.len() {
        return None;
    }
    let enc = input[p];
    if enc != b'Q' && enc != b'q' && enc != b'B' && enc != b'b' {
        return None;
    }
    p += 1;
    if p >= input.len() || input[p] != b'?' {
        return None;
    }
    p += 1; // past encoding '?'
    let payload_start = p;
    // Find trailing '?=' (first occurrence).
    let mut q = p;
    while q + 1 < input.len() && !(input[q] == b'?' && input[q + 1] == b'=') {
        q += 1;
    }
    if q + 1 >= input.len() {
        return None;
    }
    let payload = &input[payload_start..q];
    let mut bytes = Vec::with_capacity(payload.len());
    match enc.to_ascii_uppercase() {
        b'Q' => {
            let mut k = 0usize;
            while k < payload.len() {
                let b = payload[k];
                if b == b'_' {
                    bytes.push(b' ');
                    k += 1;
                } else if b == b'=' && k + 2 < payload.len() {
                    if let (Some(h), Some(l)) = (hex_val(payload[k + 1]), hex_val(payload[k + 2])) {
                        bytes.push((h << 4) | l);
                        k += 3;
                    } else {
                        bytes.push(b'=');
                        k += 1;
                    }
                } else {
                    bytes.push(b);
                    k += 1;
                }
            }
        }
        _ => {
            // B: base64 (whitespace tolerated by our decoder).
            bytes = match base64_decode(payload, &HashMap::new()) {
                Ok(v) => v,
                Err(_) => return None,
            };
        }
    }
    Some((bytes, q + 2))
}

struct QpEncodeBuf {
    buf: Vec<u8>,
    wrap: usize,
    header_mode: bool,
    encode_all: bool,
}

pub(crate) fn make_qp_encode_stream(
    args: &HashMap<String, String>,
) -> anyhow::Result<Box<dyn StreamingOp>> {
    Ok(Box::new(QpEncodeBuf {
        buf: Vec::new(),
        wrap: parse_qp_wrap(args)?,
        header_mode: parse_bool(args.get("header_mode"))?,
        encode_all: parse_bool(args.get("encode_all"))?,
    }))
}

impl StreamingOp for QpEncodeBuf {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.buf.extend_from_slice(chunk);
        Ok(Vec::new())
    }
    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        let input = std::mem::take(&mut self.buf);
        Ok(qp_encode_with(
            &input,
            self.wrap,
            self.header_mode,
            self.encode_all,
        ))
    }
}

struct QpDecodeBuf {
    buf: Vec<u8>,
    args: HashMap<String, String>,
}

pub(crate) fn make_qp_decode_stream(
    args: &HashMap<String, String>,
) -> anyhow::Result<Box<dyn StreamingOp>> {
    // Validate header_mode up front.
    let _ = qp_decode(b"", args)?;
    Ok(Box::new(QpDecodeBuf {
        buf: Vec::new(),
        args: args.clone(),
    }))
}

impl StreamingOp for QpDecodeBuf {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.buf.extend_from_slice(chunk);
        Ok(Vec::new())
    }
    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        qp_decode(&std::mem::take(&mut self.buf), &self.args)
    }
}

// ---------------------------------------------------------------------------
// Punycode (P1): RFC 3492 bootstring (no IDNA mapping; UTF-8 in, ASCII out).
// ---------------------------------------------------------------------------

const PUNY_BASE: u32 = 36;

const PUNY_TMIN: u32 = 1;

const PUNY_TMAX: u32 = 26;

const PUNY_SKEW: u32 = 38;

const PUNY_DAMP: u32 = 700;

const PUNY_INITIAL_BIAS: u32 = 72;

const PUNY_INITIAL_N: u32 = 128;

fn puny_adapt(mut delta: u32, numpoints: u32, firsttime: bool) -> u32 {
    delta = if firsttime {
        delta / PUNY_DAMP
    } else {
        delta / 2
    };
    delta += delta / numpoints;
    let mut k = 0u32;
    while delta > ((PUNY_BASE - PUNY_TMIN) * PUNY_TMAX) / 2 {
        delta /= PUNY_BASE - PUNY_TMIN;
        k += PUNY_BASE;
    }
    k + (((PUNY_BASE - PUNY_TMIN + 1) * delta) / (delta + PUNY_SKEW))
}

fn puny_encode_digit(d: u32) -> u8 {
    if d < 26 {
        b'a' + d as u8
    } else {
        b'0' + (d - 26) as u8
    }
}

fn puny_decode_digit(c: u8) -> Option<u32> {
    match c {
        b'a'..=b'z' => Some((c - b'a') as u32),
        b'A'..=b'Z' => Some((c - b'A') as u32),
        b'0'..=b'9' => Some((c - b'0') as u32 + 26),
        _ => None,
    }
}

pub(crate) fn punycode_encode(
    input: &[u8],
    args: &HashMap<String, String>,
) -> anyhow::Result<Vec<u8>> {
    let text = std::str::from_utf8(input)
        .map_err(|_| anyhow::anyhow!("{}", i18n::t("err.punycode_utf8")))?;
    let cps: Vec<u32> = text.chars().map(|c| c as u32).collect();
    let mut out: Vec<u8> = Vec::new();
    let mut basic: Vec<u8> = Vec::new();
    for &cp in &cps {
        if cp < 0x80 {
            basic.push(cp as u8);
        }
    }
    let basic_count = basic.len();
    let mut basic_pos = 0usize;
    for &cp in &cps {
        if cp < 0x80 {
            out.push(basic[basic_pos]);
            basic_pos += 1;
        }
    }
    let mut handled = basic_count;
    let mut n = PUNY_INITIAL_N;
    let mut delta = 0u32;
    let mut bias = PUNY_INITIAL_BIAS;
    // RFC 3492: emit the '-' separator whenever basic code points exist.
    if handled > 0 {
        out.push(b'-');
    }
    while handled < cps.len() {
        let mut m = u32::MAX;
        for &cp in &cps {
            if cp >= n && cp < m {
                m = cp;
            }
        }
        delta = delta
            .checked_add(
                (m - n)
                    .checked_mul(handled as u32 + 1)
                    .ok_or_else(|| anyhow::anyhow!("{}", i18n::t("err.punycode_overflow")))?,
            )
            .ok_or_else(|| anyhow::anyhow!("{}", i18n::t("err.punycode_overflow")))?;
        n = m;
        for &cp in &cps {
            if cp < n {
                delta = delta
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("{}", i18n::t("err.punycode_overflow")))?;
            }
            if cp == n {
                let mut q = delta;
                let mut k = PUNY_BASE;
                loop {
                    let t = if k <= bias {
                        PUNY_TMIN
                    } else if k >= bias + PUNY_TMAX {
                        PUNY_TMAX
                    } else {
                        k - bias
                    };
                    if q < t {
                        break;
                    }
                    out.push(puny_encode_digit(t + ((q - t) % (PUNY_BASE - t))));
                    q = (q - t) / (PUNY_BASE - t);
                    k += PUNY_BASE;
                }
                out.push(puny_encode_digit(q));
                bias = puny_adapt(delta, handled as u32 + 1, handled == basic_count);
                delta = 0;
                handled += 1;
            }
        }
        delta = delta
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("{}", i18n::t("err.punycode_overflow")))?;
        n = n
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("{}", i18n::t("err.punycode_overflow")))?;
    }
    if args.get("use_prefix").map(|v| v == "true").unwrap_or(false) {
        let mut with_prefix = b"xn--".to_vec();
        with_prefix.extend_from_slice(&out);
        Ok(with_prefix)
    } else {
        Ok(out)
    }
}

fn parse_puny_prefix_required(args: &HashMap<String, String>) -> bool {
    args.get("use_prefix").map(|v| v == "true").unwrap_or(false)
}

pub(crate) fn punycode_decode(
    input: &[u8],
    args: &HashMap<String, String>,
) -> anyhow::Result<Vec<u8>> {
    let mut s: &[u8] = input;
    let has_prefix = s.starts_with(b"xn--");
    if parse_puny_prefix_required(args) {
        // Strict mode: the xn-- prefix is mandatory.
        if !has_prefix {
            anyhow::bail!(
                "{}",
                i18n::tf(
                    "err.punycode_prefix_missing",
                    &[String::from_utf8_lossy(input).as_ref()]
                )
            );
        }
        s = &s[4..];
    } else if has_prefix {
        // Lenient mode (default): tolerate and strip the prefix.
        s = &s[4..];
    }
    let mut cps: Vec<u32> = Vec::new();
    // Split at the last '-' which separates basic code points from the encoded part.
    let last_dash = s.iter().rposition(|&c| c == b'-');
    let (basic_part, enc_part) = match last_dash {
        Some(p) => (&s[..p], &s[p + 1..]),
        // Without a delimiter everything is the encoded part (no basic code points).
        None => (&s[..0], s),
    };
    if basic_part.is_empty() && enc_part.is_empty() {
        anyhow::bail!("{}", i18n::t("err.punycode_invalid"));
    }
    for &c in basic_part {
        if !c.is_ascii() {
            anyhow::bail!("{}", i18n::t("err.punycode_invalid_basic"));
        }
        cps.push(c as u32);
    }
    let mut n = PUNY_INITIAL_N;
    let mut i_delta = 0u32;
    let mut bias = PUNY_INITIAL_BIAS;
    let mut pos = 0usize;
    while pos < enc_part.len() {
        let old_i = i_delta;
        let mut w = 1u32;
        let mut k = PUNY_BASE;
        loop {
            if pos >= enc_part.len() {
                anyhow::bail!("{}", i18n::t("err.punycode_invalid"));
            }
            let digit = puny_decode_digit(enc_part[pos])
                .ok_or_else(|| anyhow::anyhow!("{}", i18n::t("err.punycode_invalid")))?;
            pos += 1;
            i_delta = i_delta
                .checked_add(
                    digit
                        .checked_mul(w)
                        .ok_or_else(|| anyhow::anyhow!("{}", i18n::t("err.punycode_invalid")))?,
                )
                .ok_or_else(|| anyhow::anyhow!("{}", i18n::t("err.punycode_invalid")))?;
            let t = if k <= bias {
                PUNY_TMIN
            } else if k >= bias + PUNY_TMAX {
                PUNY_TMAX
            } else {
                k - bias
            };
            if digit < t {
                break;
            }
            w = w
                .checked_mul(PUNY_BASE - t)
                .ok_or_else(|| anyhow::anyhow!("{}", i18n::t("err.punycode_invalid")))?;
            k += PUNY_BASE;
        }
        let out_len = cps.len() as u32 + 1;
        bias = puny_adapt(i_delta - old_i, out_len, old_i == 0);
        n = n
            .checked_add(i_delta / out_len)
            .ok_or_else(|| anyhow::anyhow!("{}", i18n::t("err.punycode_invalid")))?;
        i_delta %= out_len;
        if !(0x80..=0x10ffff).contains(&n) || (0xd800..=0xdfff).contains(&n) {
            anyhow::bail!("{}", i18n::t("err.punycode_invalid"));
        }
        cps.insert(i_delta as usize, n);
        i_delta += 1;
    }
    // Re-encode to UTF-8.
    let mut out = Vec::new();
    for cp in cps {
        let c = char::from_u32(cp)
            .ok_or_else(|| anyhow::anyhow!("{}", i18n::t("err.punycode_invalid")))?;
        let mut buf = [0u8; 4];
        out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
    }
    Ok(out)
}

pub(crate) fn make_punycode_encode_stream(
    args: &HashMap<String, String>,
) -> anyhow::Result<Box<dyn StreamingOp>> {
    Ok(Box::new(PunycodeEncodeBuf {
        buf: Vec::new(),
        args: args.clone(),
    }))
}

impl StreamingOp for PunycodeEncodeBuf {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.buf.extend_from_slice(chunk);
        Ok(Vec::new())
    }
    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        punycode_encode(&std::mem::take(&mut self.buf), &self.args)
    }
}

struct PunycodeEncodeBuf {
    buf: Vec<u8>,
    args: HashMap<String, String>,
}

struct PunycodeDecodeBuf {
    buf: Vec<u8>,
    args: HashMap<String, String>,
}

pub(crate) fn make_punycode_decode_stream(
    args: &HashMap<String, String>,
) -> anyhow::Result<Box<dyn StreamingOp>> {
    Ok(Box::new(PunycodeDecodeBuf {
        buf: Vec::new(),
        args: args.clone(),
    }))
}

impl StreamingOp for PunycodeDecodeBuf {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.buf.extend_from_slice(chunk);
        Ok(Vec::new())
    }
    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        punycode_decode(&std::mem::take(&mut self.buf), &self.args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_roundtrip() {
        let data = b"a b+c/d?e=f";
        let enc = url_encode(data, &HashMap::new()).unwrap();
        assert_eq!(enc, b"a%20b%2Bc%2Fd%3Fe%3Df");
        let dec = url_decode(&enc, &HashMap::new()).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn url_preserve_unreserved() {
        // RFC 3986 unreserved chars stay unencoded by default.
        let enc = url_encode(b"a-b.c_d~e", &HashMap::new()).unwrap();
        assert_eq!(enc, b"a-b.c_d~e");
        // preserve_unreserved=false percent-encodes them.
        let mut args = HashMap::new();
        args.insert("preserve_unreserved".to_string(), "false".to_string());
        let enc2 = url_encode(b"a-b.c_d~e", &args).unwrap();
        assert_eq!(enc2, b"a%2Db%2Ec%5Fd%7Ee");
        // Stream matches memory path for both settings.
        let mut stream = make_url_encode(&HashMap::new()).unwrap();
        let mut acc = Vec::new();
        for part in [&b"a-b"[..], b".c_d~e".as_slice()] {
            acc.extend_from_slice(&stream.write(part).unwrap());
        }
        acc.extend_from_slice(&stream.finish().unwrap());
        assert_eq!(acc, b"a-b.c_d~e");
        let mut stream2 = make_url_encode(&args).unwrap();
        let mut acc2 = Vec::new();
        for part in [&b"a-b"[..], b".c_d~e".as_slice()] {
            acc2.extend_from_slice(&stream2.write(part).unwrap());
        }
        acc2.extend_from_slice(&stream2.finish().unwrap());
        assert_eq!(acc2, b"a%2Db%2Ec%5Fd%7Ee");
    }

    #[test]
    fn url_encode_use_plus() {
        // Space becomes '+' with use_plus, %20 otherwise.
        let mut plus = HashMap::new();
        plus.insert("use_plus".to_string(), "true".to_string());
        assert_eq!(url_encode(b"a b", &plus).unwrap(), b"a+b".to_vec());
        assert_eq!(
            url_encode(b"a b", &HashMap::new()).unwrap(),
            b"a%20b".to_vec()
        );
        // Other characters unaffected by use_plus.
        assert_eq!(url_encode(b"a b/c", &plus).unwrap(), b"a+b%2Fc".to_vec());
        // Round-trip with decode use_plus is symmetric.
        let enc = url_encode(b"hello world foo", &plus).unwrap();
        let dec = url_decode(&enc, &plus).unwrap();
        assert_eq!(dec, b"hello world foo");
        // Stream matches memory.
        let mut s = make_url_encode(&plus).unwrap();
        let mut acc = Vec::new();
        acc.extend_from_slice(&s.write(b"a ").unwrap());
        acc.extend_from_slice(&s.write(b"b").unwrap());
        acc.extend_from_slice(&s.finish().unwrap());
        assert_eq!(acc, b"a+b".to_vec());
        // Invalid boolean rejected.
        let mut bad = HashMap::new();
        bad.insert("use_plus".to_string(), "maybe".to_string());
        assert!(url_encode(b"a b", &bad).is_err());
        assert!(make_url_encode(&bad).is_err());
    }

    #[test]
    fn url_use_plus_with_preserve_unreserved() {
        // Combination semantics: use_plus only rewrites the space byte; it must
        // not change how unreserved chars are treated by preserve_unreserved.
        let both = || {
            let mut m = HashMap::new();
            m.insert("use_plus".to_string(), "true".to_string());
            m.insert("preserve_unreserved".to_string(), "false".to_string());
            m
        };
        // preserve_unreserved=false + use_plus=true: unreserved chars are
        // percent-encoded while the space becomes '+'.
        assert_eq!(
            url_encode(b"a-b.c_d~e x", &both()).unwrap(),
            b"a%2Db%2Ec%5Fd%7Ee+x".to_vec()
        );
        // use_plus=true alone keeps unreserved chars verbatim.
        let plus = || {
            let mut m = HashMap::new();
            m.insert("use_plus".to_string(), "true".to_string());
            m
        };
        assert_eq!(
            url_encode(b"a-b.c_d~e x", &plus()).unwrap(),
            b"a-b.c_d~e+x".to_vec()
        );
        // preserve_unreserved=false alone keeps %20 for the space.
        let mut no_res = HashMap::new();
        no_res.insert("preserve_unreserved".to_string(), "false".to_string());
        assert_eq!(
            url_encode(b"a-b.c_d~e x", &no_res).unwrap(),
            b"a%2Db%2Ec%5Fd%7Ee%20x".to_vec()
        );
        // Form round-trip with both flags stays symmetric.
        let src = b"a-b.c_d~e x/y z";
        let enc = url_encode(src, &both()).unwrap();
        assert_eq!(url_decode(&enc, &plus()).unwrap(), src);
        // Stream path honours the combination as well.
        let mut s = make_url_encode(&both()).unwrap();
        let mut acc = Vec::new();
        acc.extend_from_slice(&s.write(b"a-b.c").unwrap());
        acc.extend_from_slice(&s.write(b"_d~e x/y").unwrap());
        acc.extend_from_slice(&s.finish().unwrap());
        assert_eq!(acc, b"a%2Db%2Ec%5Fd%7Ee+x%2Fy".to_vec());
    }

    #[test]
    fn url_decode_raw_bytes_and_invalid() {
        // Decoded output is raw bytes, no UTF-8 lossy replacement.
        let dec = url_decode(b"%FF", &HashMap::new()).unwrap();
        assert_eq!(dec, [0xffu8]);
        // Invalid % sequence passes through unchanged.
        assert_eq!(
            url_decode(b"100%zz%2", &HashMap::new()).unwrap(),
            b"100%zz%2"
        );
        // Truncated % at end passes through.
        assert_eq!(url_decode(b"abc%", &HashMap::new()).unwrap(), b"abc%");
        // '+' is untouched by default (RFC 3986)...
        assert_eq!(url_decode(b"a+b", &HashMap::new()).unwrap(), b"a+b");
        // ...but decodes to a space with use_plus (form semantics).
        let mut args = HashMap::new();
        args.insert("use_plus".to_string(), "true".to_string());
        assert_eq!(url_decode(b"a+b%20c", &args).unwrap(), b"a b c");
        // Invalid boolean value rejected.
        let mut bad = HashMap::new();
        bad.insert("use_plus".to_string(), "maybe".to_string());
        assert!(url_decode(b"a+b", &bad).is_err());
    }

    #[test]
    fn url_decode_use_plus_specific() {
        let plus = || {
            let mut m = HashMap::new();
            m.insert("use_plus".to_string(), "true".to_string());
            m
        };
        // Repeated '+' yields repeated spaces.
        assert_eq!(url_decode(b"a++b", &plus()).unwrap(), b"a  b");
        // A single '+' is a single space.
        assert_eq!(url_decode(b"+", &plus()).unwrap(), b" ");
        // '+' mixes with %XX escapes and UTF-8 bytes.
        assert_eq!(
            url_decode(b"%E4%B8%AD+ok", &plus()).unwrap(),
            "中 ok".as_bytes()
        );
        // '+' after an escaped byte inside a query segment.
        assert_eq!(url_decode(b"a%2Bb+c", &plus()).unwrap(), b"a+b c");
        // '%2B' is always a literal plus regardless of use_plus.
        assert_eq!(url_decode(b"a%2Bb", &plus()).unwrap(), b"a+b");
        assert_eq!(url_decode(b"a%2Bb", &HashMap::new()).unwrap(), b"a+b");
        // Default (RFC 3986) keeps '+' verbatim even next to escapes.
        assert_eq!(url_decode(b"a+b%20c", &HashMap::new()).unwrap(), b"a+b c");
        // Form round-trip symmetry: encode use_plus -> decode use_plus.
        let src = b"a b/c d?e=f&g h";
        let enc = url_encode(src, &plus()).unwrap();
        assert_eq!(url_decode(&enc, &plus()).unwrap(), src);
        // Stream factory: '+' sitting across a chunk boundary.
        let mut s = make_url_decode(&plus()).unwrap();
        let mut acc = Vec::new();
        acc.extend_from_slice(&s.write(b"a+").unwrap());
        acc.extend_from_slice(&s.write(b"+b").unwrap());
        acc.extend_from_slice(&s.finish().unwrap());
        assert_eq!(acc, b"a  b");
    }

    #[test]
    fn url_decode_stream_matches_memory() {
        // %XX split across chunk boundaries still decodes; incomplete and
        // invalid sequences flush verbatim exactly like the memory path.
        let data = b"a%20b+c%2Fd%3Fe%3Df%41x%YZ%4g";
        let args = HashMap::new();
        let expect = url_decode(data, &args).unwrap();
        let mut s = make_url_decode(&args).unwrap();
        let mut acc = Vec::new();
        acc.extend_from_slice(&s.write(b"a%20b+c%2").unwrap());
        acc.extend_from_slice(&s.write(b"Fd%3Fe%3Df%41x%Y").unwrap());
        acc.extend_from_slice(&s.write(b"Z%4g").unwrap());
        acc.extend_from_slice(&s.finish().unwrap());
        assert_eq!(acc, expect);
        // use_plus flows through the stream factory.
        let mut args2 = HashMap::new();
        args2.insert("use_plus".to_string(), "true".to_string());
        let expect2 = url_decode(b"a+b%20c", &args2).unwrap();
        let mut s2 = make_url_decode(&args2).unwrap();
        let mut acc2 = Vec::new();
        acc2.extend_from_slice(&s2.write(b"a+b%").unwrap());
        acc2.extend_from_slice(&s2.write(b"20c").unwrap());
        acc2.extend_from_slice(&s2.finish().unwrap());
        assert_eq!(acc2, expect2);
        // Invalid boolean rejected at factory too.
        let mut bad = HashMap::new();
        bad.insert("use_plus".to_string(), "maybe".to_string());
        assert!(make_url_decode(&bad).is_err());
    }

    #[test]
    fn html_named_table_and_encode_all() {
        // Extended named entity table decodes common HTML4 entities.
        let dec = html_decode(b"&copy;&nbsp;&euro;&hellip;", &HashMap::new()).unwrap();
        assert_eq!(dec, "\u{a9}\u{a0}\u{20ac}\u{2026}".as_bytes());
        // Unknown entity left alone.
        let dec2 = html_decode(b"&bogus;", &HashMap::new()).unwrap();
        assert_eq!(dec2, b"&bogus;");
        // encode_all turns non-ASCII into a single numeric entity (roundtrips).
        let mut args = HashMap::new();
        args.insert("encode_all".to_string(), "true".to_string());
        let enc = html_encode("a<b&中".as_bytes(), &args).unwrap();
        assert_eq!(enc, "a&#60;b&#38;&#20013;".as_bytes());
        let round = html_decode(&enc, &HashMap::new()).unwrap();
        assert_eq!(round, "a<b&中".as_bytes());
        // encode_all stream matches memory.
        let mut s = make_html_encode(&args).unwrap();
        let mut acc = Vec::new();
        acc.extend_from_slice(&s.write("中".as_bytes()).unwrap());
        acc.extend_from_slice(&s.finish().unwrap());
        assert_eq!(acc, "&#20013;".as_bytes());
        // Default still only escapes the five specials.
        assert_eq!(
            html_encode("a<b&中".as_bytes(), &HashMap::new()).unwrap(),
            "a&lt;b&amp;中".as_bytes()
        );
        // Invalid encode_all rejected.
        let mut bad = HashMap::new();
        bad.insert("encode_all".to_string(), "maybe".to_string());
        assert!(html_encode(b"x", &bad).is_err());
    }

    #[test]
    fn html_encode_explicit_formats() {
        // named: specials use names, Latin-1 supplement uses the table,
        // out-of-table characters fall back to decimal numeric.
        let mut a = HashMap::new();
        a.insert("format".to_string(), "named".to_string());
        a.insert("encode_all".to_string(), "true".to_string());
        let enc = html_encode("a<b&caf\u{e9}\u{4e2d}".as_bytes(), &a).unwrap();
        assert_eq!(enc, "a&lt;b&amp;caf&eacute;&#20013;".as_bytes());
        // named without encode_all only touches the five specials.
        let mut b = HashMap::new();
        b.insert("format".to_string(), "named".to_string());
        assert_eq!(
            html_encode("'x'\"y\"".as_bytes(), &b).unwrap(),
            "&apos;x&apos;&quot;y&quot;".as_bytes()
        );
        // numeric: everything becomes decimal entities.
        let mut c = HashMap::new();
        c.insert("format".to_string(), "numeric".to_string());
        c.insert("encode_all".to_string(), "true".to_string());
        assert_eq!(
            html_encode("a<b&caf\u{e9}".as_bytes(), &c).unwrap(),
            "a&#60;b&#38;caf&#233;".as_bytes()
        );
        // hex: uppercase hex digits with &#x..; form.
        let mut d = HashMap::new();
        d.insert("format".to_string(), "hex".to_string());
        d.insert("encode_all".to_string(), "true".to_string());
        assert_eq!(
            html_encode("a<b>".as_bytes(), &d).unwrap(),
            "a&#x3C;b&#x3E;".as_bytes()
        );
        // Invalid format rejected.
        let mut e = HashMap::new();
        e.insert("format".to_string(), "bogus".to_string());
        assert!(html_encode(b"x", &e).is_err());
        // Stream with explicit format matches memory.
        let mut s = make_html_encode(&d).unwrap();
        let mut acc = Vec::new();
        acc.extend_from_slice(&s.write(b"a<b>").unwrap());
        acc.extend_from_slice(&s.finish().unwrap());
        assert_eq!(acc, "a&#x3C;b&#x3E;".as_bytes());
    }

    #[test]
    fn html_known_vector() {
        let enc = html_encode(b"<a href=\"x\">A&B'C</a>", &HashMap::new()).unwrap();
        assert_eq!(enc, b"&lt;a href=&quot;x&quot;&gt;A&amp;B&#39;C&lt;/a&gt;");
        let dec = html_decode(&enc, &HashMap::new()).unwrap();
        assert_eq!(dec, b"<a href=\"x\">A&B'C</a>");
        let dec2 = html_decode(b"&#65;&#x42;&amp;", &HashMap::new()).unwrap();
        assert_eq!(dec2, b"AB&");
    }

    #[test]
    fn html_leaves_unknown_entity_alone() {
        let dec = html_decode(b"&unknown;rest", &HashMap::new()).unwrap();
        assert_eq!(dec, b"&unknown;rest");
    }

    #[test]
    fn html_decode_mode_parameter() {
        // Default both decodes named and numeric entities (backward compatible).
        assert_eq!(
            html_decode(b"&amp; &#65; &#x42;", &HashMap::new()).unwrap(),
            b"& A B"
        );
        // Named mode keeps numeric entities untouched.
        let mut named = HashMap::new();
        named.insert("mode".to_string(), "named".to_string());
        assert_eq!(
            html_decode(b"&amp; &#65; &#x42;", &named).unwrap(),
            b"& &#65; &#x42;"
        );
        // Numeric mode keeps named entities untouched (accepts "num" alias).
        let mut num = HashMap::new();
        num.insert("mode".to_string(), "num".to_string());
        assert_eq!(
            html_decode(b"&amp; &#65; &#x42;", &num).unwrap(),
            b"&amp; A B"
        );
        // Invalid mode rejected in both memory and streaming paths.
        let mut bad = HashMap::new();
        bad.insert("mode".to_string(), "latin1".to_string());
        assert!(html_decode(b"&amp;", &bad).is_err());
        assert!(make_html_decode(&bad).is_err());
        // Streaming decode honours mode across chunk boundaries.
        let mut d = make_html_decode(&named).unwrap();
        let mut acc = Vec::new();
        acc.extend_from_slice(&d.write(b"&am").unwrap());
        acc.extend_from_slice(&d.write(b"p; &#65; tail").unwrap());
        acc.extend_from_slice(&d.finish().unwrap());
        assert_eq!(acc, b"& &#65; tail");
    }

    /// `&#0;` must not inject a NUL byte; out-of-range code points are
    /// left verbatim (not silently dropped).
    #[test]
    fn html_decode_replaces_null_entity() {
        let out = html_decode(b"A&#0;B", &HashMap::new()).unwrap();
        assert!(!out.contains(&0u8), "NUL leaked into output: {out:?}");
        assert_eq!(out, "A\u{FFFD}B".as_bytes());
        // Hex form too.
        let out2 = html_decode(b"&#x0;X", &HashMap::new()).unwrap();
        assert!(!out2.contains(&0u8));
        assert_eq!(out2, "\u{FFFD}X".as_bytes());
        // Out-of-range code points stay verbatim.
        let out3 = html_decode(b"&#x110000;Y", &HashMap::new()).unwrap();
        assert_eq!(out3, "&#x110000;Y".as_bytes());
    }

    #[test]
    fn html_stream_matches_memory() {
        let input = b"<tag attr=\"&quot;&#39;\">a&b</tag> tail &amp; more".to_vec();
        let enc_mem = html_encode(&input, &HashMap::new()).unwrap();
        let mut d = make_html_decode(&HashMap::new()).unwrap();
        let mut dec = Vec::new();
        for c in enc_mem.chunks(7) {
            dec.extend(d.write(c).unwrap());
        }
        dec.extend(d.finish().unwrap());
        assert_eq!(dec, input);
    }

    #[test]
    fn qp_roundtrip() {
        assert_eq!(
            qp_encode(b"Hello=World", &HashMap::new()).unwrap(),
            b"Hello=3DWorld"
        );
        assert_eq!(
            qp_decode(b"Hello=3DWorld", &HashMap::new()).unwrap(),
            b"Hello=World"
        );
        // soft line breaks removed on decode
        assert_eq!(
            qp_decode(b"soft=\r\nbreak", &HashMap::new()).unwrap(),
            b"softbreak"
        );
        // non-ASCII bytes become =XX
        assert_eq!(
            qp_encode(b"\xe4\xb8\xad", &HashMap::new()).unwrap(),
            b"=E4=B8=AD"
        );
        assert_eq!(
            qp_decode(b"=E4=B8=AD", &HashMap::new()).unwrap(),
            b"\xe4\xb8\xad"
        );
        // roundtrip
        let data = b"some data with spaces and \x01\xff\x00";
        let enc = qp_encode(data, &HashMap::new()).unwrap();
        assert_eq!(qp_decode(&enc, &HashMap::new()).unwrap(), data);
    }

    #[test]
    fn qp_wrap_parameter() {
        // Default wrap is 76: a long run of 'a' gets soft breaks.
        let data: Vec<u8> = vec![b'a'; 100];
        let enc = qp_encode(&data, &HashMap::new()).unwrap();
        let s = String::from_utf8(enc.clone()).unwrap();
        assert!(s.contains("=\r\n"), "expected soft break, got: {}", s);
        // wrap=0 disables soft breaks entirely.
        let mut no_wrap = HashMap::new();
        no_wrap.insert("wrap".to_string(), "0".to_string());
        let enc0 = qp_encode(&data, &no_wrap).unwrap();
        assert!(!enc0.contains(&b'='), "wrap=0 must not emit soft breaks");
        assert_eq!(enc0.len(), 100);
        // Custom narrow wrap respects the configured width.
        let mut narrow = HashMap::new();
        narrow.insert("wrap".to_string(), "8".to_string());
        let enc8 = qp_encode(b"abcdefghijkl", &narrow).unwrap();
        let s8 = String::from_utf8(enc8.clone()).unwrap();
        let breaks: Vec<&str> = s8.split("=\r\n").collect();
        assert!(breaks.len() >= 2, "got: {}", s8);
        for part in &breaks {
            assert!(part.len() <= 8, "line too long: {:?}", part);
        }
        // Decode still removes soft breaks from wrapped output.
        assert_eq!(qp_decode(&enc8, &HashMap::new()).unwrap(), b"abcdefghijkl");
        // Invalid wrap rejected.
        let mut bad = HashMap::new();
        bad.insert("wrap".to_string(), "abc".to_string());
        assert!(qp_encode(b"x", &bad).is_err());
        let mut neg = HashMap::new();
        neg.insert("wrap".to_string(), "-5".to_string());
        assert!(qp_encode(b"x", &neg).is_err());
    }

    #[test]
    fn qp_header_mode_rfc2047() {
        // Q encoded-word: CJK text with '_' as space.
        let mut q = HashMap::new();
        q.insert("header_mode".to_string(), "true".to_string());
        let input = b"=?utf-8?Q?=E4=B8=AD=E6=96=87_hello?=";
        assert_eq!(qp_decode(input, &q).unwrap(), "中文 hello".as_bytes());
        // B encoded-word: base64-encoded CJK text.
        let input_b = b"Subject: =?utf-8?B?5Lit5paH?=";
        assert_eq!(qp_decode(input_b, &q).unwrap(), "Subject: 中文".as_bytes());
        // Off by default: encoded-word structure is preserved and '_' stays
        // literal (only QP escapes are decoded, no RFC 2047 semantics).
        assert_eq!(
            qp_decode(input, &HashMap::new()).unwrap(),
            "=?utf-8?Q?中文_hello?=".as_bytes()
        );
        // Non-encoded-word QP still works alongside.
        let mixed = b"a=20b =?utf-8?Q?hi?=";
        assert_eq!(qp_decode(mixed, &q).unwrap(), b"a b hi");
        // Malformed encoded-word passes through unchanged.
        let mal = b"=?utf-8?Z?bad?= =?utf-8?Q?unterminated";
        assert_eq!(qp_decode(mal, &q).unwrap(), mal);
        // Stream matches memory under header_mode.
        let mut s = make_qp_decode_stream(&q).unwrap();
        let mut acc = Vec::new();
        acc.extend_from_slice(&s.write(&input_b[..8]).unwrap());
        acc.extend_from_slice(&s.write(&input_b[8..]).unwrap());
        acc.extend_from_slice(&s.finish().unwrap());
        assert_eq!(acc, "Subject: 中文".as_bytes());
        // Invalid boolean value rejected.
        let mut bad = HashMap::new();
        bad.insert("header_mode".to_string(), "yeah".to_string());
        assert!(qp_decode(b"x", &bad).is_err());
        assert!(make_qp_decode_stream(&bad).is_err());
    }

    #[test]
    fn qp_encode_header_mode() {
        // RFC 2047 Q-encoding: space -> '_', only Q-safe chars pass through.
        let mut q = HashMap::new();
        q.insert("header_mode".to_string(), "true".to_string());
        q.insert("wrap".to_string(), "0".to_string());
        assert_eq!(
            qp_encode(b"hello world", &q).unwrap(),
            b"hello_world".to_vec()
        );
        // Chinese bytes are hex-escaped; '-' '/' '+' '*' '!' are Q-safe.
        let enc = qp_encode("中文".as_bytes(), &q).unwrap();
        assert_eq!(enc, b"=E4=B8=AD=E6=96=87".to_vec());
        assert_eq!(
            qp_encode(b"a!b*c+d/e f", &q).unwrap(),
            b"a!b*c+d/e_f".to_vec()
        );
        // '=' always becomes =3D even in header mode.
        assert_eq!(qp_encode(b"a=b", &q).unwrap(), b"a=3Db".to_vec());
        // Stream matches memory under header_mode.
        let mut s = make_qp_encode_stream(&q).unwrap();
        let mut acc = Vec::new();
        acc.extend_from_slice(&s.write(b"hello ").unwrap());
        acc.extend_from_slice(&s.write(b"world").unwrap());
        acc.extend_from_slice(&s.finish().unwrap());
        assert_eq!(acc, b"hello_world".to_vec());
        // Invalid boolean rejected.
        let mut bad = HashMap::new();
        bad.insert("encode_all".to_string(), "yes!".to_string());
        assert!(qp_encode(b"x", &bad).is_err());
        assert!(make_qp_encode_stream(&bad).is_err());
    }

    #[test]
    fn qp_encode_all() {
        // encode_all hex-escapes printable ASCII too.
        let mut all = HashMap::new();
        all.insert("encode_all".to_string(), "true".to_string());
        all.insert("wrap".to_string(), "0".to_string());
        assert_eq!(qp_encode(b"ab", &all).unwrap(), b"=61=62".to_vec());
        assert_eq!(qp_encode(b"a b", &all).unwrap(), b"=61=20=62".to_vec());
        assert_eq!(qp_encode(b"a=b", &all).unwrap(), b"=61=3D=62".to_vec());
        // Non-printable bytes are hex-escaped as before.
        assert_eq!(qp_encode(b"a\xff", &all).unwrap(), b"=61=FF".to_vec());
        // CRLF structure is preserved even with encode_all.
        assert_eq!(qp_encode(b"a\r\nb", &all).unwrap(), b"=61\r\n=62".to_vec());
        // Round-trip: encode_all output decodes back to the original bytes.
        let data = b"Hello, World! \xff\x00";
        let enc = qp_encode(data, &all).unwrap();
        assert_eq!(qp_decode(&enc, &HashMap::new()).unwrap(), data);
        // Off by default.
        assert_eq!(qp_encode(b"ab", &HashMap::new()).unwrap(), b"ab".to_vec());
    }

    #[test]
    fn punycode_known_vectors() {
        assert_eq!(
            punycode_encode(b"m\xc3\xbcnchen", &HashMap::new()).unwrap(),
            b"mnchen-3ya"
        );
        assert_eq!(
            punycode_encode(b"b\xc3\xbccher", &HashMap::new()).unwrap(),
            b"bcher-kva"
        );
        assert_eq!(
            punycode_encode(b"\xe4\xb8\xad\xe5\x9b\xbd", &HashMap::new()).unwrap(),
            b"fiqs8s"
        );
        assert_eq!(punycode_encode(b"abc", &HashMap::new()).unwrap(), b"abc-");
        // xn-- prefix option
        let mut args = HashMap::new();
        args.insert("use_prefix".to_string(), "true".to_string());
        assert_eq!(
            punycode_encode(b"\xe4\xb8\xad\xe5\x9b\xbd", &args).unwrap(),
            b"xn--fiqs8s"
        );
        // decode
        assert_eq!(
            punycode_decode(b"mnchen-3ya", &HashMap::new()).unwrap(),
            b"m\xc3\xbcnchen"
        );
        assert_eq!(
            punycode_decode(b"fiqs8s", &HashMap::new()).unwrap(),
            b"\xe4\xb8\xad\xe5\x9b\xbd"
        );
        assert_eq!(
            punycode_decode(b"xn--fiqs8s", &HashMap::new()).unwrap(),
            b"\xe4\xb8\xad\xe5\x9b\xbd"
        );
        // roundtrip
        for s in [
            b"m\xc3\xbcnchen".as_slice(),
            b"b\xc3\xbccher".as_slice(),
            b"\xe4\xb8\xad\xe5\x9b\xbd".as_slice(),
            b"abc".as_slice(),
        ] {
            let enc = punycode_encode(s, &HashMap::new()).unwrap();
            assert_eq!(punycode_decode(&enc, &HashMap::new()).unwrap(), s);
        }
    }

    #[test]
    fn punycode_rejects_invalid() {
        assert!(punycode_decode(b"xn--", &HashMap::new()).is_err());
        assert!(punycode_decode(b"\xff", &HashMap::new()).is_err());
    }

    #[test]
    fn punycode_decode_use_prefix_strict() {
        let mut strict = HashMap::new();
        strict.insert("use_prefix".to_string(), "true".to_string());
        // Strict mode decodes prefixed input fine.
        assert_eq!(
            punycode_decode(b"xn--fiqs8s", &strict).unwrap(),
            "\u{4e2d}\u{56fd}".as_bytes()
        );
        // Strict mode rejects input without the prefix.
        assert!(punycode_decode(b"fiqs8s", &strict).is_err());
        // Lenient mode (default) still decodes without the prefix.
        assert_eq!(
            punycode_decode(b"fiqs8s", &HashMap::new()).unwrap(),
            "\u{4e2d}\u{56fd}".as_bytes()
        );
    }
}
