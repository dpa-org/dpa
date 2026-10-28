//! Codec ops: Base64 / Base32 / Hex / URL.
//! Split into family submodules: base, binary, url_html, format.

use std::collections::HashMap;

use super::{ArgSpec, Op, StreamingOp};
use crate::i18n;

mod base;
mod binary;
mod format;
mod url_html;

use base::*;
use binary::*;
use format::*;
use url_html::*;

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
                    format: crate::ops::ArgFormat::Bool,
                },
                ArgSpec {
                    name: "strict_mode",
                    required: false,
                    description: "op.base64.decode.arg.strict_mode",
                    format: crate::ops::ArgFormat::Bool,
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
                    format: crate::ops::ArgFormat::Bool,
                },
                ArgSpec {
                    name: "strict_mode",
                    required: false,
                    description: "op.base64.url.decode.arg.strict_mode",
                    format: crate::ops::ArgFormat::Bool,
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
                    format: crate::ops::ArgFormat::Bool,
                },
                ArgSpec {
                    name: "strict_mode",
                    required: false,
                    description: "op.base32.decode.arg.strict_mode",
                    format: crate::ops::ArgFormat::Bool,
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
                    format: crate::ops::ArgFormat::Bool,
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
                    format: crate::ops::ArgFormat::Bool,
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
                    format: crate::ops::ArgFormat::Bool,
                },
                ArgSpec {
                    name: "use_plus",
                    required: false,
                    description: "op.url.encode.arg.use_plus",
                    format: crate::ops::ArgFormat::Bool,
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
                format: crate::ops::ArgFormat::Bool,
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
                    format: crate::ops::ArgFormat::Bool,
                },
                ArgSpec {
                    name: "uppercase",
                    required: false,
                    description: "op.utf8.escape.arg.uppercase",
                    format: crate::ops::ArgFormat::Bool,
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
                    format: crate::ops::ArgFormat::Bool,
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
                    format: crate::ops::ArgFormat::Bool,
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
                    format: crate::ops::ArgFormat::Bool,
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
                    format: crate::ops::ArgFormat::Bool,
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
                    format: crate::ops::ArgFormat::Bool,
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
                    format: crate::ops::ArgFormat::Bool,
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
                    format: crate::ops::ArgFormat::Bool,
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
                    format: crate::ops::ArgFormat::Bool,
                },
                ArgSpec {
                    name: "encode_all",
                    required: false,
                    description: "op.qp.encode.arg.encode_all",
                    format: crate::ops::ArgFormat::Bool,
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
                format: crate::ops::ArgFormat::Bool,
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
                format: crate::ops::ArgFormat::Bool,
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

pub(crate) fn parse_bool(v: Option<&String>) -> anyhow::Result<bool> {
    match v.map(|s| s.as_str()) {
        None | Some("false") | Some("0") => Ok(false),
        Some("true") | Some("1") => Ok(true),
        Some(other) => anyhow::bail!("{}", i18n::tf("err.bool_invalid", &[other])),
    }
}

/// Streaming hex encode: two chars per byte, no cross-block state.
/// When a delimiter or uppercase is requested the op degrades to buffered
/// mode so separators and case apply consistently across the whole input.
#[derive(Clone, Copy, PartialEq, Eq)]

pub(crate) enum HexDelimiter {
    None,
    Space,
    Comma,
    SemiColon,
    Colon,
    Newline,
    Crlf,
}

pub(crate) fn parse_hex_delimiter(s: &str) -> anyhow::Result<HexDelimiter> {
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

pub(crate) fn parse_hex_args(
    args: &HashMap<String, String>,
) -> anyhow::Result<(HexDelimiter, bool)> {
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

pub(crate) fn parse_hex_bpl(args: &HashMap<String, String>) -> anyhow::Result<usize> {
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

pub(crate) fn hex_delim_bytes(d: HexDelimiter) -> &'static [u8] {
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

pub(crate) fn hex_digit_upper(v: u8) -> u8 {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    HEX[(v & 0x0f) as usize]
}

pub(crate) fn hex_digit_lower(v: u8) -> u8 {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    HEX[(v & 0x0f) as usize]
}

pub(crate) fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

pub(crate) fn hex_digit(v: u8) -> u8 {
    match v {
        0..=9 => b'0' + v,
        _ => b'A' + v - 10,
    }
}

pub(crate) fn parse_hex_ignore(args: &HashMap<String, String>) -> anyhow::Result<bool> {
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
