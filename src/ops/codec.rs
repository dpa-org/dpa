//! Codec ops: Base64 / Base32 / Hex / URL.

use std::collections::HashMap;

use super::{ArgSpec, Op, StreamingOp};
use crate::i18n;

pub fn ops() -> Vec<Op> {
    vec![
        stream_op!(
            "dpa:base64:encode",
            "codec",
            "op.base64.encode.desc",
            &[
                ArgSpec {
                    name: "alphabet",
                    required: false,
                    description: "op.base64.encode.arg.alphabet",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "pad",
                    required: false,
                    description: "op.base64.encode.arg.pad",
                    format: crate::ops::ArgFormat::Utf8,
                }
            ],
            base64_encode,
            make_base64_encode
        ),
        stream_op!(
            "dpa:base64:decode",
            "codec",
            "op.base64.decode.desc",
            &[
                ArgSpec {
                    name: "alphabet",
                    required: false,
                    description: "op.base64.decode.arg.alphabet",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "ignore_non_alphabet",
                    required: false,
                    description: "op.base64.decode.arg.ignore_non_alphabet",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "strict_mode",
                    required: false,
                    description: "op.base64.decode.arg.strict_mode",
                    format: crate::ops::ArgFormat::Utf8,
                }
            ],
            base64_decode,
            make_base64_decode
        ),
        stream_op!(
            "dpa:base64:url:encode",
            "codec",
            "op.base64.url.encode.desc",
            &[],
            base64url_encode,
            make_base64url_encode
        ),
        stream_op!(
            "dpa:base64:url:decode",
            "codec",
            "op.base64.url.decode.desc",
            &[
                ArgSpec {
                    name: "alphabet",
                    required: false,
                    description: "op.base64.url.decode.arg.alphabet",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "ignore_non_alphabet",
                    required: false,
                    description: "op.base64.url.decode.arg.ignore_non_alphabet",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "strict_mode",
                    required: false,
                    description: "op.base64.url.decode.arg.strict_mode",
                    format: crate::ops::ArgFormat::Utf8,
                }
            ],
            base64url_decode,
            make_base64url_decode
        ),
        stream_op!(
            "dpa:base32:encode",
            "codec",
            "op.base32.encode.desc",
            &[
                ArgSpec {
                    name: "alphabet",
                    required: false,
                    description: "op.base32.encode.arg.alphabet",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "pad",
                    required: false,
                    description: "op.base32.encode.arg.pad",
                    format: crate::ops::ArgFormat::Utf8,
                }
            ],
            base32_encode,
            make_b32_encode_stream
        ),
        stream_op!(
            "dpa:base32:decode",
            "codec",
            "op.base32.decode.desc",
            &[
                ArgSpec {
                    name: "alphabet",
                    required: false,
                    description: "op.base32.decode.arg.alphabet",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "ignore_non_alphabet",
                    required: false,
                    description: "op.base32.decode.arg.ignore_non_alphabet",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "strict_mode",
                    required: false,
                    description: "op.base32.decode.arg.strict_mode",
                    format: crate::ops::ArgFormat::Utf8,
                }
            ],
            base32_decode,
            make_b32_decode_stream
        ),
        stream_op!(
            "dpa:hex:encode",
            "codec",
            "op.hex.encode.desc",
            &[
                ArgSpec {
                    name: "delimiter",
                    required: false,
                    description: "op.hex.encode.arg.delimiter",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "uppercase",
                    required: false,
                    description: "op.hex.encode.arg.uppercase",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "bytes_per_line",
                    required: false,
                    description: "op.hex.encode.arg.bytes_per_line",
                    format: crate::ops::ArgFormat::Utf8,
                }
            ],
            hex_encode,
            make_hex_encode
        ),
        stream_op!(
            "dpa:hex:decode",
            "codec",
            "op.hex.decode.desc",
            &[
                ArgSpec {
                    name: "delimiter",
                    required: false,
                    description: "op.hex.decode.arg.delimiter",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "ignore_non_alphabet",
                    required: false,
                    description: "op.hex.decode.arg.ignore_non_alphabet",
                    format: crate::ops::ArgFormat::Utf8,
                }
            ],
            hex_decode,
            make_hex_decode
        ),
        stream_op!(
            "dpa:url:encode",
            "codec",
            "op.url.encode.desc",
            &[
                ArgSpec {
                    name: "preserve_unreserved",
                    required: false,
                    description: "op.url.encode.arg.preserve_unreserved",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "use_plus",
                    required: false,
                    description: "op.url.encode.arg.use_plus",
                    format: crate::ops::ArgFormat::Utf8,
                }
            ],
            url_encode,
            make_url_encode
        ),
        stream_op!(
            "dpa:url:decode",
            "codec",
            "op.url.decode.desc",
            &[ArgSpec {
                name: "use_plus",
                required: false,
                description: "op.url.decode.arg.use_plus",
                format: crate::ops::ArgFormat::Utf8,
            }],
            url_decode,
            make_url_decode
        ),
        stream_op!(
            "dpa:utf8:escape",
            "codec",
            "op.utf8.escape.desc",
            &[
                ArgSpec {
                    name: "encode_all",
                    required: false,
                    description: "op.utf8.escape.arg.encode_all",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "uppercase",
                    required: false,
                    description: "op.utf8.escape.arg.uppercase",
                    format: crate::ops::ArgFormat::Utf8,
                }
            ],
            utf8_escape,
            make_utf8_escape
        ),
        stream_op!(
            "dpa:utf8:unescape",
            "codec",
            "op.utf8.unescape.desc",
            &[],
            utf8_unescape,
            make_utf8_unescape
        ),
        // binary / octal / decimal / charcode / html entity / base58
        stream_op!(
            "dpa:binary:encode",
            "codec",
            "op.binary.encode.desc",
            &[ArgSpec {
                name: "delimiter",
                required: false,
                description: "op.binary.encode.arg.delimiter",
                format: crate::ops::ArgFormat::Utf8,
            }],
            binary_encode,
            make_binary_encode
        ),
        stream_op!(
            "dpa:binary:decode",
            "codec",
            "op.binary.decode.desc",
            &[
                ArgSpec {
                    name: "delimiter",
                    required: false,
                    description: "op.binary.decode.arg.delimiter",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "ignore_non_alphabet",
                    required: false,
                    description: "op.binary.decode.arg.ignore_non_alphabet",
                    format: crate::ops::ArgFormat::Utf8,
                }
            ],
            binary_decode,
            make_binary_decode
        ),
        stream_op!(
            "dpa:octal:encode",
            "codec",
            "op.octal.encode.desc",
            &[ArgSpec {
                name: "delimiter",
                required: false,
                description: "op.octal.encode.arg.delimiter",
                format: crate::ops::ArgFormat::Utf8,
            }],
            octal_encode,
            make_octal_encode
        ),
        stream_op!(
            "dpa:octal:decode",
            "codec",
            "op.octal.decode.desc",
            &[
                ArgSpec {
                    name: "delimiter",
                    required: false,
                    description: "op.octal.decode.arg.delimiter",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "ignore_non_alphabet",
                    required: false,
                    description: "op.octal.decode.arg.ignore_non_alphabet",
                    format: crate::ops::ArgFormat::Utf8,
                }
            ],
            octal_decode,
            make_octal_decode
        ),
        stream_op!(
            "dpa:decimal:encode",
            "codec",
            "op.decimal.encode.desc",
            &[ArgSpec {
                name: "delimiter",
                required: false,
                description: "op.decimal.encode.arg.delimiter",
                format: crate::ops::ArgFormat::Utf8,
            }],
            decimal_encode,
            make_decimal_encode
        ),
        stream_op!(
            "dpa:decimal:decode",
            "codec",
            "op.decimal.decode.desc",
            &[
                ArgSpec {
                    name: "delimiter",
                    required: false,
                    description: "op.decimal.decode.arg.delimiter",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "ignore_non_alphabet",
                    required: false,
                    description: "op.decimal.decode.arg.ignore_non_alphabet",
                    format: crate::ops::ArgFormat::Utf8,
                }
            ],
            decimal_decode,
            make_decimal_decode
        ),
        stream_op!(
            "dpa:charcode:encode",
            "codec",
            "op.charcode.encode.desc",
            &[
                ArgSpec {
                    name: "delimiter",
                    required: false,
                    description: "op.charcode.encode.arg.delimiter",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "base",
                    required: false,
                    description: "op.charcode.encode.arg.base",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            charcode_encode,
            make_charcode_encode
        ),
        stream_op!(
            "dpa:charcode:decode",
            "codec",
            "op.charcode.decode.desc",
            &[
                ArgSpec {
                    name: "delimiter",
                    required: false,
                    description: "op.charcode.decode.arg.delimiter",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "base",
                    required: false,
                    description: "op.charcode.decode.arg.base",
                    format: crate::ops::ArgFormat::Utf8,
                }
            ],
            charcode_decode,
            make_charcode_decode
        ),
        stream_op!(
            "dpa:html:encode",
            "codec",
            "op.html.encode.desc",
            &[
                ArgSpec {
                    name: "encode_all",
                    required: false,
                    description: "op.html.encode.arg.encode_all",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "format",
                    required: false,
                    description: "op.html.encode.arg.format",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            html_encode,
            make_html_encode
        ),
        stream_op!(
            "dpa:html:decode",
            "codec",
            "op.html.decode.desc",
            &[ArgSpec {
                name: "mode",
                required: false,
                description: "op.html.decode.arg.mode",
                format: crate::ops::ArgFormat::Utf8,
            }],
            html_decode,
            make_html_decode
        ),
        stream_op!(
            "dpa:base58:encode",
            "codec",
            "op.base58.encode.desc",
            &[ArgSpec {
                name: "alphabet",
                required: false,
                description: "op.base58.encode.arg.alphabet",
                format: crate::ops::ArgFormat::Utf8,
            }],
            base58_encode,
            make_base58_encode_stream
        ),
        stream_op!(
            "dpa:base58:decode",
            "codec",
            "op.base58.decode.desc",
            &[
                ArgSpec {
                    name: "alphabet",
                    required: false,
                    description: "op.base58.decode.arg.alphabet",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "ignore_non_alphabet",
                    required: false,
                    description: "op.base58.decode.arg.ignore_non_alphabet",
                    format: crate::ops::ArgFormat::Utf8,
                }
            ],
            base58_decode,
            make_base58_decode
        ),
        // base62 / base85 / quoted-printable / punycode
        stream_op!(
            "dpa:base62:encode",
            "codec",
            "op.base62.encode.desc",
            &[ArgSpec {
                name: "alphabet",
                required: false,
                description: "op.base62.encode.arg.alphabet",
                format: crate::ops::ArgFormat::Utf8,
            }],
            base62_encode,
            make_base62_encode_stream
        ),
        stream_op!(
            "dpa:base62:decode",
            "codec",
            "op.base62.decode.desc",
            &[
                ArgSpec {
                    name: "alphabet",
                    required: false,
                    description: "op.base62.decode.arg.alphabet",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "ignore_non_alphabet",
                    required: false,
                    description: "op.base62.decode.arg.ignore_non_alphabet",
                    format: crate::ops::ArgFormat::Utf8,
                }
            ],
            base62_decode,
            make_base62_decode_stream
        ),
        stream_op!(
            "dpa:base85:encode",
            "codec",
            "op.base85.encode.desc",
            &[
                ArgSpec {
                    name: "alphabet",
                    required: false,
                    description: "op.base85.encode.arg.alphabet",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "remove_zeros",
                    required: false,
                    description: "op.base85.encode.arg.remove_zeros",
                    format: crate::ops::ArgFormat::Utf8,
                }
            ],
            base85_encode,
            make_base85_encode_stream
        ),
        stream_op!(
            "dpa:base85:decode",
            "codec",
            "op.base85.decode.desc",
            &[
                ArgSpec {
                    name: "alphabet",
                    required: false,
                    description: "op.base85.decode.arg.alphabet",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "ignore_non_alphabet",
                    required: false,
                    description: "op.base85.decode.arg.ignore_non_alphabet",
                    format: crate::ops::ArgFormat::Utf8,
                }
            ],
            base85_decode,
            make_base85_decode_stream
        ),
        stream_op!(
            "dpa:qp:encode",
            "codec",
            "op.qp.encode.desc",
            &[
                ArgSpec {
                    name: "wrap",
                    required: false,
                    description: "op.qp.encode.arg.wrap",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "header_mode",
                    required: false,
                    description: "op.qp.encode.arg.header_mode",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "encode_all",
                    required: false,
                    description: "op.qp.encode.arg.encode_all",
                    format: crate::ops::ArgFormat::Utf8,
                }
            ],
            qp_encode,
            make_qp_encode_stream
        ),
        stream_op!(
            "dpa:qp:decode",
            "codec",
            "op.qp.decode.desc",
            &[ArgSpec {
                name: "header_mode",
                required: false,
                description: "op.qp.decode.arg.header_mode",
                format: crate::ops::ArgFormat::Utf8,
            }],
            qp_decode,
            make_qp_decode_stream
        ),
        stream_op!(
            "dpa:punycode:encode",
            "codec",
            "op.punycode.encode.desc",
            &[ArgSpec {
                name: "use_prefix",
                required: false,
                description: "op.punycode.encode.arg.use_prefix",
                format: crate::ops::ArgFormat::Utf8,
            }],
            punycode_encode,
            make_punycode_encode_stream
        ),
        stream_op!(
            "dpa:punycode:decode",
            "codec",
            "op.punycode.decode.desc",
            &[ArgSpec {
                name: "use_prefix",
                required: false,
                description: "op.punycode.decode.arg.use_prefix",
                format: crate::ops::ArgFormat::Utf8,
            }],
            punycode_decode,
            make_punycode_decode_stream
        ),
        stream_op!(
            "dpa:utf16:encode",
            "codec",
            "op.utf16.encode.desc",
            &[
                ArgSpec {
                    name: "endian",
                    required: false,
                    description: "op.utf16.encode.arg.endian",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "bom",
                    required: false,
                    description: "op.utf16.encode.arg.bom",
                    format: crate::ops::ArgFormat::Utf8,
                }
            ],
            utf16_encode,
            make_utf16_encode
        ),
        stream_op!(
            "dpa:utf16:decode",
            "codec",
            "op.utf16.decode.desc",
            &[
                ArgSpec {
                    name: "endian",
                    required: false,
                    description: "op.utf16.decode.arg.endian",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "bom",
                    required: false,
                    description: "op.utf16.decode.arg.bom",
                    format: crate::ops::ArgFormat::Utf8,
                }
            ],
            utf16_decode,
            make_utf16_decode
        ),
        // hexdump
        stream_op!(
            "dpa:hexdump:encode",
            "codec",
            "op.hexdump.encode.desc",
            &[ArgSpec {
                name: "bytes_per_line",
                required: false,
                description: "op.hexdump.encode.arg.bytes_per_line",
                format: crate::ops::ArgFormat::Utf8,
            }],
            hexdump_encode,
            make_hexdump_encode
        ),
        stream_op!(
            "dpa:hexdump:decode",
            "codec",
            "op.hexdump.decode.desc",
            &[ArgSpec {
                name: "delimiter",
                required: false,
                description: "op.hexdump.decode.arg.delimiter",
                format: crate::ops::ArgFormat::Utf8,
            }],
            hexdump_decode,
            make_hexdump_decode
        ),
        // YAML / XML <-> JSON
        op!(
            "dpa:yaml:to-json",
            "codec",
            "op.yaml.to-json.desc",
            &[],
            yaml_to_json
        ),
        op!(
            "dpa:json:to-yaml",
            "codec",
            "op.json.to-yaml.desc",
            &[],
            json_to_yaml
        ),
        op!(
            "dpa:xml:to-json",
            "codec",
            "op.xml.to-json.desc",
            &[],
            xml_to_json
        ),
        op!(
            "dpa:json:to-xml",
            "codec",
            "op.json.to-xml.desc",
            &[],
            json_to_xml
        ),
        // Base45 (RFC 9285), used by QR codes / DCC
        op!(
            "dpa:base45:encode",
            "codec",
            "op.base45.encode.desc",
            &[],
            base45_encode
        ),
        op!(
            "dpa:base45:decode",
            "codec",
            "op.base45.decode.desc",
            &[ArgSpec {
                name: "ignore_non_alphabet",
                required: false,
                description: "op.base45.decode.arg.ignore_non_alphabet",
                format: crate::ops::ArgFormat::Utf8,
            }],
            base45_decode
        ),
        // EBCDIC (IBM cp037), matching CyberChef's EBCDIC codec
        op!(
            "dpa:ebcdic:encode",
            "codec",
            "op.ebcdic.encode.desc",
            &[],
            ebcdic_encode
        ),
        op!(
            "dpa:ebcdic:decode",
            "codec",
            "op.ebcdic.decode.desc",
            &[],
            ebcdic_decode
        ),
    ]
}

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

fn make_base64_encode(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    Ok(Box::new(B64EncodeStream {
        alphabet: parse_b64_alphabet(args)?,
        pending: Vec::new(),
    }))
}

fn make_base64url_encode(_args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
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
            .chunks_exact(3)
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
}

fn make_base64_decode(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    let ignore = parse_bool(args.get("ignore_non_alphabet"))?;
    let strict = parse_bool(args.get("strict_mode"))?;
    Ok(Box::new(B64DecodeStream {
        alphabet: parse_b64_alphabet(args)?,
        ignore_non_alph: ignore,
        strict,
        pending: Vec::new(),
    }))
}

fn make_base64url_decode(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    let alph = match args.get("alphabet") {
        Some(a) => B64Alphabet::parse(a, None)?,
        None => B64Alphabet::parse("url", None)?,
    };
    let ignore = parse_bool(args.get("ignore_non_alphabet"))?;
    let strict = parse_bool(args.get("strict_mode"))?;
    Ok(Box::new(B64DecodeStream {
        alphabet: alph,
        ignore_non_alph: ignore,
        strict,
        pending: Vec::new(),
    }))
}

fn parse_bool(v: Option<&String>) -> anyhow::Result<bool> {
    match v.map(|s| s.as_str()) {
        None | Some("false") | Some("0") => Ok(false),
        Some("true") | Some("1") => Ok(true),
        Some(other) => anyhow::bail!("{}", i18n::tf("err.bool_invalid", &[other])),
    }
}

impl StreamingOp for B64DecodeStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.pending.extend_from_slice(chunk);
        let mut out = Vec::new();
        let mut idx = 0usize;
        let mut chars = Vec::with_capacity(4);
        let n = self.pending.len();
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
                return Err(anyhow::anyhow!("{}", i18n::t("err.base64_invalid")));
            }
            chars.push(c);
            if chars.len() == 4 {
                decode_group(&chars, &self.alphabet, &mut out)?;
                chars.clear();
            }
            idx += 1;
        }
        // Consume only complete groups; keep an incomplete tail for the next write / finish.
        let consumed = idx - chars.len();
        self.pending.drain(..consumed);
        Ok(out)
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        let cleaned: Vec<u8> = self
            .pending
            .iter()
            .copied()
            .filter(|c| {
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
            .collect();
        let mut out = Vec::new();
        if self.strict {
            check_b64_strict(&cleaned, &self.alphabet)?;
        }
        match cleaned.len() % 4 {
            0 => {}
            1 => anyhow::bail!("{}", i18n::t("err.base64_tail")),
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
fn check_b64_strict(cleaned: &[u8], alphabet: &B64Alphabet) -> anyhow::Result<()> {
    if cleaned.len() % 4 == 1 {
        anyhow::bail!("{}", i18n::t("err.base64_strict_len"));
    }
    // Padding checks apply only when padding is actually present (aligns with
    // CyberChef: `padPos >= 0` gates both the position and the length checks).
    if alphabet.has_pad {
        if let Some(p) = cleaned.iter().position(|&c| alphabet.is_pad(c)) {
            if p + 2 < cleaned.len() || cleaned.last() != Some(&alphabet.pad) {
                anyhow::bail!("{}", i18n::t("err.base64_strict_pad_pos"));
            }
            if cleaned.len() % 4 != 0 {
                anyhow::bail!("{}", i18n::t("err.base64_strict_pad_len"));
            }
        }
    }
    Ok(())
}

/// Decode a final tail of 2 or 3 Base64 chars (padding inside the tail is an error).
fn decode_tail(chars: &[u8], alphabet: &B64Alphabet, out: &mut Vec<u8>) -> anyhow::Result<()> {
    let mut vals = [0u8; 4];
    let mut n = 0usize;
    for &c in chars {
        if alphabet.is_pad(c) {
            return Err(anyhow::anyhow!("{}", i18n::t("err.base64_padding")));
        }
        let v = alphabet.rev[c as usize];
        if v < 0 {
            return Err(anyhow::anyhow!("{}", i18n::t("err.base64_invalid")));
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
fn decode_group(chars: &[u8], alphabet: &B64Alphabet, out: &mut Vec<u8>) -> anyhow::Result<()> {
    debug_assert_eq!(chars.len(), 4);
    // Count valid chars (before any pad).
    let mut vals = [0u8; 4];
    let mut n = 0usize;
    for &c in chars {
        if alphabet.is_pad(c) {
            break;
        }
        let v = alphabet.rev[c as usize];
        if v < 0 {
            return Err(anyhow::anyhow!("{}", i18n::t("err.base64_invalid")));
        }
        vals[n] = v as u8;
        n += 1;
    }
    if n == 0 {
        return Err(anyhow::anyhow!("{}", i18n::t("err.base64_empty_group")));
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
        _ => return Err(anyhow::anyhow!("{}", i18n::t("err.base64_padding"))),
    }
    Ok(())
}

/// Streaming hex encode: two chars per byte, no cross-block state.
/// When a delimiter or uppercase is requested the op degrades to buffered
/// mode so separators and case apply consistently across the whole input.
#[derive(Clone, Copy, PartialEq, Eq)]
enum HexDelimiter {
    None,
    Space,
    Comma,
    SemiColon,
    Colon,
    Newline,
    Crlf,
}

fn parse_hex_delimiter(s: &str) -> anyhow::Result<HexDelimiter> {
    match s.to_ascii_lowercase().as_str() {
        "none" => Ok(HexDelimiter::None),
        "space" => Ok(HexDelimiter::Space),
        "comma" => Ok(HexDelimiter::Comma),
        "semicolon" => Ok(HexDelimiter::SemiColon),
        "colon" => Ok(HexDelimiter::Colon),
        "newline" => Ok(HexDelimiter::Newline),
        "crlf" => Ok(HexDelimiter::Crlf),
        _ => Err(anyhow::anyhow!(
            "{}",
            i18n::tf("err.hex_delimiter_invalid", &[s])
        )),
    }
}

fn parse_hex_args(args: &HashMap<String, String>) -> anyhow::Result<(HexDelimiter, bool)> {
    let delim = match args.get("delimiter") {
        None => HexDelimiter::None,
        Some(s) => parse_hex_delimiter(s)?,
    };
    let upper = args
        .get("uppercase")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    Ok((delim, upper))
}

fn parse_hex_bpl(args: &HashMap<String, String>) -> anyhow::Result<usize> {
    match args.get("bytes_per_line") {
        None => Ok(0),
        Some(s) => {
            let v: i64 = s
                .trim()
                .parse()
                .map_err(|_| anyhow::anyhow!("{}", i18n::tf("err.hex_bpl_invalid", &[s])))?;
            if v == 0 || (8..=64).contains(&v) {
                Ok(v as usize)
            } else {
                Err(anyhow::anyhow!("{}", i18n::tf("err.hex_bpl_invalid", &[s])))
            }
        }
    }
}

fn hex_delim_bytes(d: HexDelimiter) -> &'static [u8] {
    match d {
        HexDelimiter::None => b"",
        HexDelimiter::Space => b" ",
        HexDelimiter::Comma => b",",
        HexDelimiter::SemiColon => b";",
        HexDelimiter::Colon => b":",
        HexDelimiter::Newline => b"\n",
        HexDelimiter::Crlf => b"\r\n",
    }
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

fn hex_digit_upper(v: u8) -> u8 {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    HEX[(v & 0x0f) as usize]
}

fn hex_digit_lower(v: u8) -> u8 {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    HEX[(v & 0x0f) as usize]
}

/// Streaming hex encode: two chars per byte, no cross-block state.
struct HexEncodeBuf {
    buf: Vec<u8>,
    delim: HexDelimiter,
    upper: bool,
    bpl: usize,
}

fn make_hex_encode(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
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

fn make_hex_decode(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
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

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn hex_digit(v: u8) -> u8 {
    match v {
        0..=9 => b'0' + v,
        _ => b'A' + v - 10,
    }
}

/// Streaming URL percent-encode: byte by byte (RFC 3986: alphanumerics and
/// `-._~` kept when preserve_unreserved, others %XX), no cross-block state.
struct UrlEncodeStream {
    preserve_unreserved: bool,
    use_plus: bool,
}

fn make_url_encode(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
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

fn base64_encode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let alphabet = parse_b64_alphabet(args)?;
    Ok(base64_encode_with(input, &alphabet))
}

/// Core Base64 encode against a given alphabet (payload chars + pad char).
fn base64_encode_with(input: &[u8], alphabet: &B64Alphabet) -> Vec<u8> {
    let full = input.len() - input.len() % 3;
    let mut out = Vec::with_capacity(full / 3 * 4 + 4);
    for g in input[..full].chunks_exact(3) {
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

fn base64_decode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let alphabet = parse_b64_alphabet(args)?;
    let ignore = parse_bool(args.get("ignore_non_alphabet"))?;
    let strict = parse_bool(args.get("strict_mode"))?;
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
    let cleaned: Vec<u8> = input
        .iter()
        .copied()
        .filter(|&c| {
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
        .collect();
    if strict {
        check_b64_strict(&cleaned, alphabet)?;
    }
    let mut out = Vec::with_capacity(cleaned.len() / 4 * 3 + 3);
    let mut chars = Vec::with_capacity(4);
    for &c in &cleaned {
        chars.push(c);
        if chars.len() == 4 {
            decode_group(&chars, alphabet, &mut out)?;
            chars.clear();
        }
    }
    match chars.len() {
        0 => {}
        1 => anyhow::bail!("{}", i18n::t("err.base64_tail")),
        n => decode_tail(&chars[..n], alphabet, &mut out)?,
    }
    Ok(out)
}

fn base64url_encode(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    Ok(base64_encode_with(input, &B64Alphabet::parse("url", None)?))
}

fn base64url_decode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let alph = match args.get("alphabet") {
        Some(a) => B64Alphabet::parse(a, None)?,
        None => B64Alphabet::parse("url", None)?,
    };
    let ignore = parse_bool(args.get("ignore_non_alphabet"))?;
    let strict = parse_bool(args.get("strict_mode"))?;
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
    for &c in input {
        if c.is_ascii_whitespace() {
            continue;
        }
        let v = alph.rev[c as usize];
        if v == -2 {
            // Padding marks the end of meaningful data: anything after it is
            // invalid regardless of strictness, and so is all-padding input.
            seen_pad = true;
            pad_chars += 1;
            if data_chars == 0 {
                anyhow::bail!("{}", i18n::t("err.base32_padding"));
            }
            continue;
        }
        if v >= 0 {
            if seen_pad {
                anyhow::bail!("{}", i18n::t("err.base32_padding"));
            }
            buf = (buf << 5) | v as u32;
            bits += 5;
            data_chars += 1;
            while bits >= 8 {
                bits -= 8;
                out.push((buf >> bits) as u8);
            }
        } else if !ignore {
            anyhow::bail!("{}", i18n::t("err.base32_invalid"));
        }
    }
    if seen_pad && (data_chars + pad_chars) % 8 != 0 {
        anyhow::bail!("{}", i18n::t("err.base32_padding"));
    }
    if !seen_pad && matches!(data_chars % 8, 1 | 3 | 6) {
        anyhow::bail!("{}", i18n::t("err.base32_tail"));
    }
    if strict && bits > 0 && (buf & ((1u32 << bits) - 1)) != 0 {
        anyhow::bail!("{}", i18n::t("err.base32_strict_tail"));
    }
    Ok(out)
}

fn base32_encode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    Ok(b32_encode_with(input, &parse_b32_alphabet(args)?))
}

fn base32_decode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
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
fn make_b32_encode_stream(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
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
fn make_b32_decode_stream(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
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

fn hex_encode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let (delim, upper) = parse_hex_args(args)?;
    let bpl = parse_hex_bpl(args)?;
    Ok(hex_encode_with(input, delim, upper, bpl))
}

fn hex_decode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
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

fn parse_hex_ignore(args: &HashMap<String, String>) -> anyhow::Result<bool> {
    match args
        .get("ignore_non_alphabet")
        .map(|v| v.to_ascii_lowercase())
        .as_deref()
    {
        None | Some("false") | Some("0") | Some("no") => Ok(false),
        Some("true") | Some("1") | Some("yes") => Ok(true),
        Some(other) => anyhow::bail!("{}", i18n::tf("err.hex_ignore_invalid", &[other])),
    }
}

fn url_encode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
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
fn url_decode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
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

fn make_url_decode(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
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

// ---------------------------------------------------------------------------
// UTF-8 percent escaping: byte-wise escape of non-printable bytes.
// `escape` is an element-wise stateless map -> chunk-parallel safe.
// `unescape` buffers a partial `%XX` tail across chunks -> stateful.
// ---------------------------------------------------------------------------

/// Byte-wise percent escape of non-printable bytes. With `encode_all` every
/// byte (including printable ASCII) is percent-encoded (CyberChef-style).
/// `uppercase` selects upper (default) or lower-case hex digits.
fn utf8_escape(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
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

fn make_utf8_escape(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
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

fn utf8_unescape(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
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

fn make_utf8_unescape(_args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
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

fn binary_encode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
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

fn binary_decode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
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
    if cleaned.len() % 8 != 0 {
        anyhow::bail!("{}", i18n::t("err.binary_odd"));
    }
    let mut out = Vec::with_capacity(cleaned.len() / 8);
    for group in cleaned.chunks_exact(8) {
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

fn make_binary_encode(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
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

fn make_binary_decode(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
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

fn octal_encode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
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

fn octal_decode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
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
    if cleaned.len() % 3 != 0 {
        anyhow::bail!("{}", i18n::t("err.octal_odd"));
    }
    let mut out = Vec::with_capacity(cleaned.len() / 3);
    for group in cleaned.chunks_exact(3) {
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

fn make_octal_encode(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
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

fn make_octal_decode(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
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

fn decimal_encode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
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

fn decimal_decode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
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

fn make_decimal_encode(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
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

fn make_decimal_decode(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
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
fn charcode_encode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
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
fn charcode_decode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
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

fn make_charcode_encode(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
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

fn utf16_encode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
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

fn utf16_decode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
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
    if data.len() % 2 != 0 {
        anyhow::bail!("{}", i18n::t("err.utf16_odd_length"));
    }
    let mut out = Vec::with_capacity(data.len() / 2);
    let mut i = 0usize;
    let units: Vec<u16> = data
        .chunks_exact(2)
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

fn make_utf16_encode(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
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

fn make_utf16_decode(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
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

fn make_charcode_decode(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
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
fn html_encode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
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

fn html_decode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
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
    if let Some(num) = ent.strip_prefix("#x").or_else(|| ent.strip_prefix("#X")) {
        u32::from_str_radix(num, 16)
            .ok()
            .and_then(char::from_u32)
            .map(|c| c.to_string().into_bytes())
    } else if let Some(num) = ent.strip_prefix('#') {
        num.parse::<u32>()
            .ok()
            .and_then(char::from_u32)
            .map(|c| c.to_string().into_bytes())
    } else {
        None
    }
}

struct HtmlEncodeStream {
    encode_all: bool,
    format: HtmlEncodeFormat,
}

fn make_html_encode(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
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

fn make_html_decode(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
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
fn base58_encode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let alph = parse_b58_alphabet(args)?;
    Ok(base58_encode_with(input, &alph))
}

/// Memory-path Base58 decode (parses alphabet / ignore_non_alphabet).
fn base58_decode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let alph = parse_b58_alphabet(args)?;
    let ignore = parse_bool(args.get("ignore_non_alphabet"))?;
    base58_decode_with(input, &alph, ignore)
}

/// Streaming base58 encode buffers whole input: emit on finish (big-int conversion is whole-input).
struct Base58EncodeBuf {
    buf: Vec<u8>,
    alph: B58Alphabet,
}

fn make_base58_encode_stream(
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

fn make_base58_decode(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
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
fn base62_encode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let alph = parse_b62_alphabet(args)?;
    Ok(base62_encode_with(input, &alph))
}

/// Memory-path Base62 decode (parses alphabet / ignore_non_alphabet).
fn base62_decode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let alph = parse_b62_alphabet(args)?;
    let ignore = parse_bool(args.get("ignore_non_alphabet"))?;
    base62_decode_with(input, &alph, ignore)
}

/// Streaming base62 encode buffers whole input: emit on finish (big-int conversion is whole-input).
struct Base62EncodeBuf {
    buf: Vec<u8>,
    alph: B62Alphabet,
}

fn make_base62_encode_stream(
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

fn make_base62_decode_stream(
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
    let mut chunks = input.chunks_exact(4);
    for c in &mut chunks {
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
    let rem = chunks.remainder();
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
fn base85_encode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let alph = parse_b85_alphabet(args)?;
    Ok(base85_encode_with(input, &alph))
}

/// Memory-path Base85 decode (parses alphabet / ignore_non_alphabet).
fn base85_decode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let alph = parse_b85_alphabet(args)?;
    let ignore = parse_bool(args.get("ignore_non_alphabet"))?;
    base85_decode_with(input, &alph, ignore)
}

struct Base85EncodeBuf {
    buf: Vec<u8>,
    alph: B85Alphabet,
}
fn make_base85_encode_stream(
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
fn make_base85_decode_stream(
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

fn qp_encode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let wrap = parse_qp_wrap(args)?;
    let header_mode = parse_bool(args.get("header_mode"))?;
    let encode_all = parse_bool(args.get("encode_all"))?;
    Ok(qp_encode_with(input, wrap, header_mode, encode_all))
}

fn qp_decode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
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
        if header_mode && input[i] == b'=' && i + 1 < input.len() && input[i + 1] == b'?' {
            if let Some((bytes, next)) = decode_rfc2047_word(input, i) {
                out.extend_from_slice(&bytes);
                i = next;
                continue;
            }
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
            if i + 2 < input.len() {
                if let (Some(h), Some(l)) = (hex_val(input[i + 1]), hex_val(input[i + 2])) {
                    out.push((h << 4) | l);
                    i += 3;
                    continue;
                }
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
fn make_qp_encode_stream(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
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
fn make_qp_decode_stream(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
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

fn punycode_encode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
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

fn punycode_decode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
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

fn make_punycode_encode_stream(
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
fn make_punycode_decode_stream(
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

// ---------------------------------------------------------------------------
// YAML / XML <-> JSON
// ---------------------------------------------------------------------------

fn yaml_to_json(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let s = String::from_utf8_lossy(input);
    let v: serde_json::Value = serde_yaml::from_str(&s).map_err(|e| anyhow::anyhow!("{}", e))?;
    Ok(serde_json::to_vec(&v)?)
}

fn json_to_yaml(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let v: serde_json::Value = serde_json::from_slice(input)?;
    let s = serde_yaml::to_string(&v).map_err(|e| anyhow::anyhow!("{}", e))?;
    Ok(s.into_bytes())
}

fn xml_to_json(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    use quick_xml::Reader;
    use quick_xml::events::Event;
    use serde_json::{Map, Value};

    let mut reader = Reader::from_reader(std::io::Cursor::new(input));
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut stack: Vec<(String, Map<String, Value>)> = Vec::new();
    let mut root: Option<Value> = None;

    loop {
        match reader.read_event_into(&mut buf) {
            Err(e) => anyhow::bail!("{}", e),
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                let mut m = Map::new();
                for a in e.attributes() {
                    let a = a.map_err(|e| anyhow::anyhow!("{}", e))?;
                    let key = format!("@{}", String::from_utf8_lossy(a.key.as_ref()));
                    let val = String::from_utf8_lossy(&a.value).to_string();
                    m.insert(key, Value::String(val));
                }
                stack.push((name, m));
            }
            Ok(Event::End(_)) => {
                let (name, m) = stack
                    .pop()
                    .ok_or_else(|| anyhow::anyhow!("unbalanced XML"))?;
                // Fold a text-only leaf into a plain string.
                let node = if m.len() == 1 {
                    if let Some(Value::String(s)) = m.get("#text") {
                        Value::String(s.clone())
                    } else {
                        Value::Object(m)
                    }
                } else {
                    Value::Object(m)
                };
                if let Some((_, parent)) = stack.last_mut() {
                    match parent.get_mut(&name) {
                        Some(Value::Array(arr)) => arr.push(node),
                        Some(Value::Object(o)) => {
                            let old = Value::Object(std::mem::take(o));
                            parent.insert(name.clone(), Value::Array(vec![old, node]));
                        }
                        Some(old) => {
                            let old = std::mem::replace(old, Value::Null);
                            parent.insert(name.clone(), Value::Array(vec![old, node]));
                        }
                        _ => {
                            parent.insert(name.clone(), node);
                        }
                    }
                } else {
                    let mut m = Map::new();
                    m.insert(name, node);
                    root = Some(Value::Object(m));
                }
            }
            Ok(Event::Text(e)) => {
                let txt = e
                    .unescape()
                    .map_err(|e| anyhow::anyhow!("{}", e))?
                    .into_owned();
                if let Some((_, m)) = stack.last_mut() {
                    if !txt.is_empty() {
                        match m.get_mut("#text") {
                            Some(Value::String(s)) => s.push_str(&txt),
                            _ => {
                                m.insert("#text".to_string(), Value::String(txt));
                            }
                        }
                    }
                }
            }
            Ok(Event::CData(e)) => {
                if let Some((_, m)) = stack.last_mut() {
                    let txt = String::from_utf8_lossy(&e).to_string();
                    if !txt.is_empty() {
                        match m.get_mut("#text") {
                            Some(Value::String(s)) => s.push_str(&txt),
                            _ => {
                                m.insert("#text".to_string(), Value::String(txt));
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        buf.clear();
    }
    let root = root.ok_or_else(|| anyhow::anyhow!("empty XML input"))?;
    Ok(serde_json::to_vec(&root)?)
}

fn json_to_xml(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    use serde_json::Value;
    let v: Value = serde_json::from_slice(input)?;
    let mut out = Vec::new();
    match &v {
        // Single-key root object: expand that key directly as the root element.
        Value::Object(m) if m.len() == 1 => {
            let (name, val) = m.iter().next().expect("len 1");
            json_value_to_xml(val, name, &mut out)?;
        }
        _ => json_value_to_xml(&v, "root", &mut out)?,
    }
    Ok(out)
}

fn json_value_to_xml(v: &serde_json::Value, name: &str, out: &mut Vec<u8>) -> anyhow::Result<()> {
    use serde_json::Value;
    match v {
        Value::Object(m) => {
            let mut attrs = String::new();
            let mut text = String::new();
            let mut children: Vec<(&String, &Value)> = Vec::new();
            for (k, val) in m {
                if let Some(a) = k.strip_prefix('@') {
                    attrs.push_str(&format!(
                        " {}=\"{}\"",
                        xml_escape_attr(a),
                        xml_escape_attr(&json_scalar_to_string(val))
                    ));
                } else if k == "#text" {
                    text = json_scalar_to_string(val);
                } else {
                    children.push((k, val));
                }
            }
            out.extend_from_slice(format!("<{}{}>", name, attrs).as_bytes());
            out.extend_from_slice(xml_escape_text(&text).as_bytes());
            for (k, val) in children {
                json_value_to_xml(val, k, out)?;
            }
            out.extend_from_slice(format!("</{}>", name).as_bytes());
        }
        Value::Array(a) => {
            for item in a {
                json_value_to_xml(item, name, out)?;
            }
        }
        _ => {
            out.extend_from_slice(format!("<{}>", name).as_bytes());
            out.extend_from_slice(xml_escape_text(&json_scalar_to_string(v)).as_bytes());
            out.extend_from_slice(format!("</{}>", name).as_bytes());
        }
    }
    Ok(())
}

fn json_scalar_to_string(v: &serde_json::Value) -> String {
    use serde_json::Value;
    match v {
        Value::String(s) => s.clone(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        _ => String::new(),
    }
}

fn xml_escape_text(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn xml_escape_attr(s: &str) -> String {
    xml_escape_text(s).replace('"', "&quot;")
}

// ---------------------------------------------------------------------------
// Base45 (RFC 9285) — QR Code / DCC credential encoding.
// 2 bytes -> 3 chars (value < 45^3), 1 trailing byte -> 2 chars (value < 45^2).
// ---------------------------------------------------------------------------

const BASE45_ALPHABET: &[u8; 45] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

fn base45_encode(data: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
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

fn base45_decode(data: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
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

fn ebcdic_encode(data: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    Ok(data.iter().map(|&b| ASCII_TO_EBCDIC[b as usize]).collect())
}

fn ebcdic_decode(data: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    Ok(data.iter().map(|&b| EBCDIC_TO_ASCII[b as usize]).collect())
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
        // Q encoded-word: "中文 hello" with '_' as space.
        let mut q = HashMap::new();
        q.insert("header_mode".to_string(), "true".to_string());
        let input = b"=?utf-8?Q?=E4=B8=AD=E6=96=87_hello?=";
        assert_eq!(qp_decode(input, &q).unwrap(), "中文 hello".as_bytes());
        // B encoded-word: base64 "中文".
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

// ---------------------------------------------------------------------------
// hexdump (hexdump -C style)
// ---------------------------------------------------------------------------

fn hexdump_encode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
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

fn hexdump_decode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
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

fn make_hexdump_encode(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
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
            if n == 0 || n % 8 != 0 || n > 64 {
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

fn make_hexdump_decode(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
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
                        if hex_seen % 2 == 0 {
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
mod tests_p1_3 {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn yaml_to_json_basic() {
        let y = b"name: Alice\nage: 30\nskills:\n  - rust\n  - crypto\n";
        let v = String::from_utf8(yaml_to_json(y, &HashMap::new()).unwrap()).unwrap();
        let j: serde_json::Value = serde_json::from_str(&v).unwrap();
        assert_eq!(j["name"], "Alice");
        assert_eq!(j["age"], 30);
        assert_eq!(j["skills"][0], "rust");
        assert_eq!(j["skills"][1], "crypto");
    }

    #[test]
    fn json_to_yaml_roundtrip() {
        let j = br#"{"a":1,"b":[true,null,"x"]}"#;
        let y = String::from_utf8(json_to_yaml(j, &HashMap::new()).unwrap()).unwrap();
        assert!(y.contains("a: 1"));
        let back: serde_json::Value = serde_yaml::from_str(&y).unwrap();
        assert_eq!(back["b"][2], "x");
    }

    #[test]
    fn xml_to_json_basic() {
        let x = b"<note id=\"1\"><to>Bob</to><to>Eve</to><body>hi</body></note>";
        let v = String::from_utf8(xml_to_json(x, &HashMap::new()).unwrap()).unwrap();
        let j: serde_json::Value = serde_json::from_str(&v).unwrap();
        assert_eq!(j["note"]["@id"], "1");
        assert_eq!(j["note"]["to"][0], "Bob");
        assert_eq!(j["note"]["to"][1], "Eve");
        assert_eq!(j["note"]["body"], "hi");
    }

    #[test]
    fn json_to_xml_basic() {
        let j = "{\"root\":{\"@id\":\"7\",\"#text\":\"hi\",\"item\":[\"a\",\"b\"]}}";
        let x = String::from_utf8(json_to_xml(j.as_bytes(), &HashMap::new()).unwrap()).unwrap();
        assert_eq!(x, r#"<root id="7">hi<item>a</item><item>b</item></root>"#);
    }

    #[test]
    fn xml_json_roundtrip() {
        let x = b"<a x=\"1\"><b>text</b><c>2</c></a>";
        let j = xml_to_json(x, &HashMap::new()).unwrap();
        let back = json_to_xml(&j, &HashMap::new()).unwrap();
        let s = String::from_utf8(back).unwrap();
        assert!(s.contains("<a x=\"1\">"));
        assert!(s.contains("<b>text</b>"));
        assert!(s.contains("<c>2</c>"));
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
