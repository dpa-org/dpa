//! Transform ops: reverse / case / whitespace / replace / byte-level transforms.

use std::collections::HashMap;

use super::{ArgSpec, Op, StreamingOp};
use crate::i18n;

pub fn ops() -> Vec<Op> {
    vec![
        op!(
            "dpa:reverse",
            "transform",
            "op.reverse.desc",
            &[ArgSpec {
                name: "mode",
                required: false,
                description: "op.reverse.arg.mode",
                format: crate::ops::ArgFormat::Utf8,
            },],
            reverse
        ),
        op!(
            "dpa:upper",
            "transform",
            "op.upper.desc",
            &[ArgSpec {
                name: "mode",
                required: false,
                description: "op.upper.arg.mode",
                format: crate::ops::ArgFormat::Utf8,
            },],
            upper
        ),
        op!("dpa:lower", "transform", "op.lower.desc", &[], lower),
        op!(
            "dpa:swapcase",
            "transform",
            "op.swapcase.desc",
            &[],
            swapcase
        ),
        op!("dpa:trim", "transform", "op.trim.desc", &[], trim),
        op!(
            "dpa:replace",
            "transform",
            "op.replace.desc",
            &[
                ArgSpec {
                    name: "from",
                    required: true,
                    description: "op.replace.arg.from",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "to",
                    required: true,
                    description: "op.replace.arg.to",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            replace
        ),
        op!(
            "dpa:rot13",
            "transform",
            "op.rot13.desc",
            &[
                ArgSpec {
                    name: "amount",
                    required: false,
                    description: "op.rot13.arg.amount",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "rot_lower",
                    required: false,
                    description: "op.rot13.arg.rot_lower",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "rot_upper",
                    required: false,
                    description: "op.rot13.arg.rot_upper",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "rot_numeric",
                    required: false,
                    description: "op.rot13.arg.rot_numeric",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            rot13
        ),
        stream_op!(
            "dpa:not",
            "transform",
            "op.not.desc",
            &[],
            bitwise_not,
            make_bitwise_not
        ),
        stream_op!(
            "dpa:byteswap",
            "transform",
            "op.byteswap.desc",
            &[ArgSpec {
                name: "width",
                required: false,
                description: "op.byteswap.arg.width",
                format: crate::ops::ArgFormat::Utf8,
            },],
            byteswap,
            make_byteswap
        ),
        stream_op!(
            "dpa:dedup",
            "transform",
            "op.dedup.desc",
            &[],
            dedup,
            make_dedup
        ),
        // ROT13 brute force (all Caesar shifts)
        op!(
            "dpa:rot13:bruteforce",
            "transform",
            "op.rot13.bruteforce.desc",
            &[
                ArgSpec {
                    name: "top",
                    required: false,
                    description: "op.rot13.bruteforce.arg.top",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "sample_length",
                    required: false,
                    description: "op.rot13.bruteforce.arg.sample_length",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "sample_offset",
                    required: false,
                    description: "op.rot13.bruteforce.arg.sample_offset",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "known_plaintext",
                    required: false,
                    description: "op.rot13.bruteforce.arg.known_plaintext",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            rot13_bruteforce
        ),
        // classical / text batch ops
        op!(
            "dpa:rot47",
            "transform",
            "op.rot47.desc",
            &[ArgSpec {
                name: "amount",
                required: false,
                description: "op.rot47.arg.amount",
                format: crate::ops::ArgFormat::Utf8,
            },],
            rot47
        ),
        op!(
            "dpa:vigenere:encode",
            "transform",
            "op.vigenere.encode.desc",
            &[ArgSpec {
                name: "key",
                required: true,
                description: "op.vigenere.encode.arg.key",
                format: crate::ops::ArgFormat::Utf8,
            },],
            vigenere_encode
        ),
        op!(
            "dpa:vigenere:decode",
            "transform",
            "op.vigenere.decode.desc",
            &[ArgSpec {
                name: "key",
                required: true,
                description: "op.vigenere.decode.arg.key",
                format: crate::ops::ArgFormat::Utf8,
            },],
            vigenere_decode
        ),
        op!(
            "dpa:sort",
            "transform",
            "op.sort.desc",
            &[ArgSpec {
                name: "type",
                required: false,
                description: "op.sort.arg.type",
                format: crate::ops::ArgFormat::Utf8,
            },],
            sort_bytes
        ),
        op!(
            "dpa:unique",
            "transform",
            "op.unique.desc",
            &[
                ArgSpec {
                    name: "separator",
                    required: false,
                    description: "op.unique.arg.separator",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "display_count",
                    required: false,
                    description: "op.unique.arg.display_count",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            unique_bytes
        ),
        op!(
            "dpa:count",
            "transform",
            "op.count.desc",
            &[ArgSpec {
                name: "sub",
                required: true,
                description: "op.count.arg.sub",
                format: crate::ops::ArgFormat::Utf8,
            },],
            count_sub
        ),
        op!(
            "dpa:take:bytes",
            "transform",
            "op.take.bytes.desc",
            &[
                ArgSpec {
                    name: "n",
                    required: true,
                    description: "op.take.bytes.arg.n",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "start",
                    required: false,
                    description: "op.take.bytes.arg.start",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "per_line",
                    required: false,
                    description: "op.take.bytes.arg.per_line",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            take_bytes
        ),
        op!(
            "dpa:drop:bytes",
            "transform",
            "op.drop.bytes.desc",
            &[
                ArgSpec {
                    name: "n",
                    required: true,
                    description: "op.drop.bytes.arg.n",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "offset",
                    required: false,
                    description: "op.drop.bytes.arg.offset",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "per_line",
                    required: false,
                    description: "op.drop.bytes.arg.per_line",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            drop_bytes
        ),
        // line/text ops + defang
        op!(
            "dpa:split",
            "transform",
            "op.split.desc",
            &[
                ArgSpec {
                    name: "delimiter",
                    required: true,
                    description: "op.split.arg.delimiter",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "join",
                    required: false,
                    description: "op.split.arg.join",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            split_by_delim
        ),
        op!(
            "dpa:filter",
            "transform",
            "op.filter.desc",
            &[
                ArgSpec {
                    name: "sub",
                    required: true,
                    description: "op.filter.arg.sub",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "regex",
                    required: false,
                    description: "op.filter.arg.regex",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "invert",
                    required: false,
                    description: "op.filter.arg.invert",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            filter_lines
        ),
        op!(
            "dpa:head",
            "transform",
            "op.head.desc",
            &[ArgSpec {
                name: "n",
                required: true,
                description: "op.head.arg.n",
                format: crate::ops::ArgFormat::Utf8,
            },],
            head_lines
        ),
        op!(
            "dpa:tail",
            "transform",
            "op.tail.desc",
            &[ArgSpec {
                name: "n",
                required: true,
                description: "op.tail.arg.n",
                format: crate::ops::ArgFormat::Utf8,
            },],
            tail_lines
        ),
        op!(
            "dpa:defang:ip",
            "transform",
            "op.defang.ip.desc",
            &[],
            defang_ip
        ),
        op!(
            "dpa:defang:ipv6",
            "transform",
            "op.defang.ipv6.desc",
            &[],
            defang_ipv6
        ),
        op!(
            "dpa:defang:url",
            "transform",
            "op.defang.url.desc",
            &[
                ArgSpec {
                    name: "escape_dots",
                    required: false,
                    description: "op.defang.url.arg.escape_dots",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "escape_http",
                    required: false,
                    description: "op.defang.url.arg.escape_http",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "escape_scheme",
                    required: false,
                    description: "op.defang.url.arg.escape_scheme",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "process",
                    required: false,
                    description: "op.defang.url.arg.process",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            defang_url
        ),
        // Fork — flow control. The engine intercepts this op
        // (see crate::engine): remaining steps run independently on each segment.
        op!(
            "dpa:fork",
            "transform",
            "op.fork.desc",
            &[ArgSpec {
                name: "separator",
                required: false,
                description: "op.fork.arg.separator",
                format: crate::ops::ArgFormat::Utf8,
            },],
            fork_identity
        ),
        // bitwise family (AND/OR use a cyclic key; NOT and XOR already exist)
        stream_op!(
            "dpa:bitwise:and",
            "transform",
            "op.bitwise.and.desc",
            &[ArgSpec {
                name: "key",
                required: true,
                description: "op.bitwise.and.arg.key",
                format: crate::ops::ArgFormat::Utf8,
            },],
            bitwise_and,
            make_bitwise_and_stream
        ),
        stream_op!(
            "dpa:bitwise:or",
            "transform",
            "op.bitwise.or.desc",
            &[ArgSpec {
                name: "key",
                required: true,
                description: "op.bitwise.or.arg.key",
                format: crate::ops::ArgFormat::Utf8,
            },],
            bitwise_or,
            make_bitwise_or_stream
        ),
        stream_op!(
            "dpa:bitwise:shift-left",
            "transform",
            "op.bitwise.shift-left.desc",
            &[ArgSpec {
                name: "bits",
                required: true,
                description: "op.bitwise.shift-left.arg.bits",
                format: crate::ops::ArgFormat::Utf8,
            },],
            bitwise_shift_left,
            make_shift_left_stream
        ),
        stream_op!(
            "dpa:bitwise:shift-right",
            "transform",
            "op.bitwise.shift-right.desc",
            &[
                ArgSpec {
                    name: "bits",
                    required: true,
                    description: "op.bitwise.shift-right.arg.bits",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "mode",
                    required: false,
                    description: "op.bitwise.shift-right.arg.mode",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            bitwise_shift_right,
            make_shift_right_stream
        ),
        stream_op!(
            "dpa:bitwise:rotate-left",
            "transform",
            "op.bitwise.rotate-left.desc",
            &[
                ArgSpec {
                    name: "bits",
                    required: true,
                    description: "op.bitwise.rotate-left.arg.bits",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "carry",
                    required: false,
                    description: "op.bitwise.rotate-left.arg.carry",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            bitwise_rotate_left,
            make_rotate_left_stream
        ),
        stream_op!(
            "dpa:bitwise:rotate-right",
            "transform",
            "op.bitwise.rotate-right.desc",
            &[
                ArgSpec {
                    name: "bits",
                    required: true,
                    description: "op.bitwise.rotate-right.arg.bits",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "carry",
                    required: false,
                    description: "op.bitwise.rotate-right.arg.carry",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            bitwise_rotate_right,
            make_rotate_right_stream
        ),
        // set operations (line-based; input A<sep>B)
        op!(
            "dpa:sets:union",
            "transform",
            "op.sets.union.desc",
            &[
                ArgSpec {
                    name: "separator",
                    required: false,
                    description: "op.sets.union.arg.separator",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "item_separator",
                    required: false,
                    description: "op.sets.union.arg.item_separator",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            sets_union
        ),
        op!(
            "dpa:sets:intersection",
            "transform",
            "op.sets.intersection.desc",
            &[
                ArgSpec {
                    name: "separator",
                    required: false,
                    description: "op.sets.intersection.arg.separator",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "item_separator",
                    required: false,
                    description: "op.sets.intersection.arg.item_separator",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            sets_intersection
        ),
        op!(
            "dpa:sets:difference",
            "transform",
            "op.sets.difference.desc",
            &[
                ArgSpec {
                    name: "separator",
                    required: false,
                    description: "op.sets.difference.arg.separator",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "item_separator",
                    required: false,
                    description: "op.sets.difference.arg.item_separator",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            sets_difference
        ),
        // CC-common operations not yet covered (transform family)
        op!(
            "dpa:case:convert",
            "transform",
            "op.case.convert.desc",
            &[ArgSpec {
                name: "style",
                required: false,
                description: "op.case.convert.arg.style",
                format: crate::ops::ArgFormat::Utf8,
            },],
            case_convert
        ),
        op!("dpa:atbash", "transform", "op.atbash.desc", &[], atbash),
        op!(
            "dpa:remove:null",
            "transform",
            "op.remove.null.desc",
            &[],
            remove_null
        ),
        op!(
            "dpa:add:line-numbers",
            "transform",
            "op.add.line_numbers.desc",
            &[
                ArgSpec {
                    name: "offset",
                    required: false,
                    description: "op.add.line_numbers.arg.offset",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "separator",
                    required: false,
                    description: "op.add.line_numbers.arg.separator",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            add_line_numbers
        ),
        op!(
            "dpa:substitute",
            "transform",
            "op.substitute.desc",
            &[
                ArgSpec {
                    name: "from",
                    required: true,
                    description: "op.substitute.arg.from",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "to",
                    required: true,
                    description: "op.substitute.arg.to",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "ignore_case",
                    required: false,
                    description: "op.substitute.arg.ignore_case",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            substitute
        ),
        // Rail Fence cipher (with configurable rails and offset)
        op!(
            "dpa:rail-fence:encode",
            "transform",
            "op.rail_fence.encode.desc",
            &[
                ArgSpec {
                    name: "rails",
                    required: false,
                    description: "op.rail_fence.arg.rails",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "offset",
                    required: false,
                    description: "op.rail_fence.arg.offset",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            rail_fence_encode
        ),
        op!(
            "dpa:rail-fence:decode",
            "transform",
            "op.rail_fence.decode.desc",
            &[
                ArgSpec {
                    name: "rails",
                    required: false,
                    description: "op.rail_fence.arg.rails",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "offset",
                    required: false,
                    description: "op.rail_fence.arg.offset",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            rail_fence_decode
        ),
    ]
}

fn reverse(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let mode = args.get("mode").map(|s| s.as_str()).unwrap_or("bytes");
    match mode {
        "bytes" => {
            let mut v = input.to_vec();
            v.reverse();
            Ok(v)
        }
        "chars" => {
            let text = String::from_utf8_lossy(input);
            Ok(text.chars().rev().collect::<String>().into_bytes())
        }
        "lines" => {
            let text = String::from_utf8_lossy(input);
            let mut out = Vec::with_capacity(input.len());
            for line in text.lines().rev() {
                out.extend_from_slice(line.as_bytes());
                out.push(b'\n');
            }
            Ok(out)
        }
        other => anyhow::bail!("invalid reverse mode: {other} (bytes|chars|lines)"),
    }
}

fn upper(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let mode = args.get("mode").map(|s| s.as_str()).unwrap_or("all");
    match mode {
        "all" => Ok(input.iter().map(|b| b.to_ascii_uppercase()).collect()),
        "words" => {
            let text = String::from_utf8_lossy(input);
            let mut out = Vec::with_capacity(input.len());
            let mut in_word = false;
            for &b in text.as_bytes() {
                if b.is_ascii_alphabetic() {
                    if !in_word {
                        out.push(b.to_ascii_uppercase());
                        in_word = true;
                    } else {
                        out.push(b);
                    }
                } else {
                    out.push(b);
                    in_word = false;
                }
            }
            Ok(out)
        }
        "sentences" => {
            let text = String::from_utf8_lossy(input);
            let mut out = Vec::with_capacity(input.len());
            let mut at_start = true;
            for &b in text.as_bytes() {
                if at_start && b.is_ascii_alphabetic() {
                    out.push(b.to_ascii_uppercase());
                    at_start = false;
                } else {
                    out.push(b);
                    if matches!(b, b'.' | b'!' | b'?' | b'\n') {
                        at_start = true;
                    } else if !b.is_ascii_whitespace() {
                        at_start = false;
                    }
                }
            }
            Ok(out)
        }
        "paragraphs" => {
            let text = String::from_utf8_lossy(input);
            let mut out = Vec::with_capacity(input.len());
            let mut para_start = true;
            for &b in text.as_bytes() {
                if para_start && b.is_ascii_alphabetic() {
                    out.push(b.to_ascii_uppercase());
                    para_start = false;
                } else {
                    out.push(b);
                    if b == b'\n' {
                        para_start = true;
                    }
                }
            }
            Ok(out)
        }
        other => anyhow::bail!("invalid upper mode: {other} (all|words|sentences|paragraphs)"),
    }
}

fn lower(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    Ok(input.iter().map(|b| b.to_ascii_lowercase()).collect())
}

fn swapcase(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    Ok(input
        .iter()
        .map(|&b| {
            if b.is_ascii_lowercase() {
                b.to_ascii_uppercase()
            } else if b.is_ascii_uppercase() {
                b.to_ascii_lowercase()
            } else {
                b
            }
        })
        .collect())
}

fn trim(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let start = input
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(input.len());
    let end = input
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map(|i| i + 1)
        .unwrap_or(start);
    Ok(input[start..end].to_vec())
}

// ---------------------------------------------------------------------------
// CC-common transforms (case conversion, atbash, null removal,
// line numbering, byte substitution).
// ---------------------------------------------------------------------------

fn case_convert(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let style = args.get("style").map(|s| s.as_str()).unwrap_or("camel");
    let text = String::from_utf8_lossy(input);
    let mut words: Vec<String> = Vec::new();
    let mut cur = String::new();
    for ch in text.chars() {
        if ch.is_alphanumeric() {
            cur.push(ch);
        } else if !cur.is_empty() {
            words.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        words.push(cur);
    }
    if words.is_empty() {
        return Ok(Vec::new());
    }
    let lower_all: Vec<String> = words.iter().map(|w| w.to_lowercase()).collect();
    let mut out = String::new();
    match style {
        "camel" => {
            out.push_str(&lower_all[0]);
            for w in &lower_all[1..] {
                let mut c = w.chars();
                if let Some(first) = c.next() {
                    out.push_str(&first.to_uppercase().collect::<String>());
                    out.push_str(&c.collect::<String>());
                }
            }
        }
        "snake" => out.push_str(&lower_all.join("_")),
        "kebab" => out.push_str(&lower_all.join("-")),
        "pascal" => {
            for w in &lower_all {
                let mut c = w.chars();
                if let Some(first) = c.next() {
                    out.push_str(&first.to_uppercase().collect::<String>());
                    out.push_str(&c.collect::<String>());
                }
            }
        }
        "title" => {
            for (i, w) in lower_all.iter().enumerate() {
                if i > 0 {
                    out.push(' ');
                }
                let mut c = w.chars();
                if let Some(first) = c.next() {
                    out.push_str(&first.to_uppercase().collect::<String>());
                    out.push_str(&c.collect::<String>());
                }
            }
        }
        "constant" => out.push_str(&lower_all.join("_").to_uppercase()),
        other => {
            anyhow::bail!("invalid case style: {other} (camel|snake|kebab|pascal|title|constant)")
        }
    }
    Ok(out.into_bytes())
}

fn atbash(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    Ok(input
        .iter()
        .map(|&b| match b {
            b'A'..=b'Z' => b'Z' - (b - b'A'),
            b'a'..=b'z' => b'z' - (b - b'a'),
            _ => b,
        })
        .collect())
}

fn remove_null(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    Ok(input.iter().copied().filter(|&b| b != 0).collect())
}

fn add_line_numbers(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let offset: i64 = match args.get("offset") {
        Some(s) => s
            .trim()
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid offset: {e}"))?,
        None => 0,
    };
    let separator = args
        .get("separator")
        .cloned()
        .unwrap_or_else(|| " ".to_string());
    let text = String::from_utf8_lossy(input);
    let lines: Vec<&str> = text.split('\n').collect();
    let width = lines.len().to_string().len();
    let mut out = String::new();
    for (i, line) in lines.iter().enumerate() {
        let n = i as i64 + 1 + offset;
        if n > 0 {
            out.push_str(&format!("{n:>width$}{separator}{line}\n", width = width));
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    Ok(out.into_bytes())
}

fn parse_substitute_spec(s: &str) -> anyhow::Result<Vec<u8>> {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                if i + 1 >= bytes.len() {
                    anyhow::bail!("dangling escape in substitution spec");
                }
                match bytes[i + 1] {
                    b'n' => {
                        out.push(b'\n');
                        i += 2;
                    }
                    b't' => {
                        out.push(b'\t');
                        i += 2;
                    }
                    b'\\' => {
                        out.push(b'\\');
                        i += 2;
                    }
                    b'x' => {
                        if i + 3 >= bytes.len() {
                            anyhow::bail!("invalid \\xHH escape in substitution spec");
                        }
                        let hi = (bytes[i + 2] as char)
                            .to_digit(16)
                            .ok_or_else(|| anyhow::anyhow!("invalid \\xHH escape"))?;
                        let lo = (bytes[i + 3] as char)
                            .to_digit(16)
                            .ok_or_else(|| anyhow::anyhow!("invalid \\xHH escape"))?;
                        out.push((hi * 16 + lo) as u8);
                        i += 4;
                    }
                    other => anyhow::bail!("unsupported escape: \\{}", other as char),
                }
            }
            lo => {
                if lo.is_ascii_alphanumeric() && i + 2 < bytes.len() && bytes[i + 1] == b'-' {
                    let hi = bytes[i + 2];
                    if hi.is_ascii_alphanumeric() && hi >= lo {
                        for b in lo..=hi {
                            out.push(b);
                        }
                        i += 3;
                        continue;
                    }
                }
                out.push(lo);
                i += 1;
            }
        }
    }
    Ok(out)
}

fn substitute(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let from = args
        .get("from")
        .ok_or_else(|| anyhow::anyhow!("missing from"))?;
    let to = args
        .get("to")
        .ok_or_else(|| anyhow::anyhow!("missing to"))?;
    let ignore_case = match args.get("ignore_case") {
        Some(s) => crate::ops::parse_bool(s)?,
        None => false,
    };
    let from_bytes = parse_substitute_spec(from)?;
    let to_bytes = parse_substitute_spec(to)?;
    let mut dict: HashMap<u8, u8> = HashMap::new();
    for (i, &f) in from_bytes.iter().enumerate() {
        let t = *to_bytes.get(i).unwrap_or(&f);
        dict.insert(f, t);
    }
    Ok(input
        .iter()
        .map(|&b| {
            if let Some(&t) = dict.get(&b) {
                return t;
            }
            if ignore_case {
                let folded = if b.is_ascii_uppercase() {
                    b.to_ascii_lowercase()
                } else {
                    b.to_ascii_uppercase()
                };
                if let Some(&t) = dict.get(&folded) {
                    if b.is_ascii_uppercase() {
                        return t.to_ascii_uppercase();
                    }
                    return t.to_ascii_lowercase();
                }
            }
            b
        })
        .collect())
}

fn replace(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let from = args
        .get("from")
        .ok_or_else(|| anyhow::anyhow!("{}", i18n::t("err.missing_from")))?;
    let to = args
        .get("to")
        .ok_or_else(|| anyhow::anyhow!("{}", i18n::t("err.missing_to")))?;
    if from.is_empty() {
        anyhow::bail!("{}", i18n::t("err.empty_from"));
    }
    let hay = String::from_utf8_lossy(input);
    Ok(hay.replace(from.as_str(), to.as_str()).into_bytes())
}

fn rot13(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let amount: u8 = match args.get("amount") {
        Some(s) => s
            .trim()
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid amount: {e}"))?,
        None => 13,
    };
    let rot_lower = match args.get("rot_lower") {
        Some(s) => crate::ops::parse_bool(s)?,
        None => true,
    };
    let rot_upper = match args.get("rot_upper") {
        Some(s) => crate::ops::parse_bool(s)?,
        None => true,
    };
    let rot_numeric = match args.get("rot_numeric") {
        Some(s) => crate::ops::parse_bool(s)?,
        None => false,
    };
    Ok(input
        .iter()
        .map(|b| match b {
            b'A'..=b'Z' if rot_upper => rotate_ascii(*b, b'A', amount),
            b'a'..=b'z' if rot_lower => rotate_ascii(*b, b'a', amount),
            b'0'..=b'9' if rot_numeric => rotate_ascii(*b, b'0', amount),
            _ => *b,
        })
        .collect())
}

fn rotate_ascii(b: u8, base: u8, amount: u8) -> u8 {
    let range = match base {
        b'A' | b'a' => 26,
        b'0' => 10,
        _ => 26,
    };
    base + ((b - base + amount) % range)
}

// ---------------------------------------------------------------------------
// Byte-level transforms: bitwise NOT, byte-order swap, run-length dedup.
// `not` is element-wise and stateless, so it is chunk-parallel safe.
// ---------------------------------------------------------------------------

fn bitwise_not(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    Ok(input.iter().map(|b| !b).collect())
}

struct NotStream;

fn make_bitwise_not(_args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    Ok(Box::new(NotStream))
}

impl StreamingOp for NotStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        Ok(chunk.iter().map(|b| !b).collect())
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        Ok(Vec::new())
    }
}

fn byteswap_width(args: &HashMap<String, String>) -> anyhow::Result<usize> {
    match args.get("width").map(|s| s.as_str()).unwrap_or("4") {
        "2" => Ok(2),
        "4" => Ok(4),
        "8" => Ok(8),
        w => anyhow::bail!("{}", i18n::tf("err.bad_byteswap_width", &[w])),
    }
}

fn byteswap(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let width = byteswap_width(args)?;
    let mut out = input.to_vec();
    for g in out.chunks_exact_mut(width) {
        g.reverse();
    }
    Ok(out)
}

struct ByteswapStream {
    width: usize,
    pending: Vec<u8>,
}

fn make_byteswap(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    let width = byteswap_width(args)?;
    Ok(Box::new(ByteswapStream {
        width,
        pending: Vec::new(),
    }))
}

impl StreamingOp for ByteswapStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.pending.extend_from_slice(chunk);
        let groups = self.pending.len() / self.width * self.width;
        let mut out = Vec::with_capacity(groups);
        if groups > 0 {
            let head: Vec<u8> = self.pending.drain(..groups).collect();
            for g in head.chunks_exact(self.width) {
                let mut v = g.to_vec();
                v.reverse();
                out.extend(v);
            }
        }
        Ok(out)
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        // Trailing bytes that do not fill a group are emitted as-is.
        Ok(std::mem::take(&mut self.pending))
    }
}

fn dedup(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    let mut last: Option<u8> = None;
    for &b in input {
        if last != Some(b) {
            out.push(b);
            last = Some(b);
        }
    }
    Ok(out)
}

struct DedupStream {
    last: Option<u8>,
}

fn make_dedup(_args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    Ok(Box::new(DedupStream { last: None }))
}

impl StreamingOp for DedupStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(chunk.len());
        for &b in chunk {
            if self.last != Some(b) {
                out.push(b);
                self.last = Some(b);
            }
        }
        Ok(out)
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        Ok(Vec::new())
    }
}

// ---------------------------------------------------------------------------
// Rail Fence cipher (zig-zag transposition).
// rails defaults to 3; offset rotates the plaintext window before laying out.
// ---------------------------------------------------------------------------

fn parse_rails_offset(args: &HashMap<String, String>) -> anyhow::Result<(usize, usize)> {
    let rails = match args.get("rails") {
        Some(s) => s
            .parse::<usize>()
            .map_err(|_| anyhow::anyhow!("rails must be a positive integer"))?,
        None => 3,
    };
    if rails == 0 {
        anyhow::bail!("rails must be at least 1");
    }
    let offset = match args.get("offset") {
        Some(s) => s.parse::<usize>().unwrap_or(0),
        None => 0,
    };
    Ok((rails, offset))
}

fn rail_row_for(j: usize, rails: usize) -> usize {
    let period = 2 * (rails - 1);
    let pos = j % period;
    if pos < rails { pos } else { period - pos }
}

fn rail_fence_encode(data: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let (rails, offset) = parse_rails_offset(args)?;
    let n = data.len();
    if rails <= 1 || n <= 1 {
        return Ok(data.to_vec());
    }
    let mut rows: Vec<Vec<u8>> = vec![Vec::new(); rails];
    for (i, &b) in data.iter().enumerate() {
        let j = (i + offset) % n;
        rows[rail_row_for(j, rails)].push(b);
    }
    Ok(rows.into_iter().flatten().collect())
}

fn rail_fence_decode(data: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let (rails, offset) = parse_rails_offset(args)?;
    let n = data.len();
    if rails <= 1 || n <= 1 {
        return Ok(data.to_vec());
    }
    let mut row_lens = vec![0usize; rails];
    for (i, _) in data.iter().enumerate() {
        let j = (i + offset) % n;
        row_lens[rail_row_for(j, rails)] += 1;
    }
    let mut start = 0usize;
    let mut row_slices = Vec::with_capacity(rails);
    for &len in &row_lens {
        row_slices.push(&data[start..start + len]);
        start += len;
    }
    let mut iters: Vec<std::slice::Iter<'_, u8>> = row_slices.iter().map(|r| r.iter()).collect();
    let mut out = vec![0u8; n];
    for (i, o) in out.iter_mut().enumerate() {
        let j = (i + offset) % n;
        let row = rail_row_for(j, rails);
        *o = *iters[row].next().expect("rail-fence row underflow");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::type_complexity)]
    use super::*;

    #[test]
    fn reverse_bytes() {
        assert_eq!(reverse(b"abc", &HashMap::new()).unwrap(), b"cba");
    }

    #[test]
    fn rail_fence_classic_vector() {
        let pt = b"WEAREDISCOVEREDFLEEATONCE";
        let ct = rail_fence_encode(pt, &HashMap::new()).unwrap();
        assert_eq!(ct, b"WECRLTEERDSOEEFEAOCAIVDEN");
        let back = rail_fence_decode(&ct, &HashMap::new()).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn rail_fence_rails2_offset() {
        let pt = b"123456";
        let args0 = HashMap::from([("rails".to_string(), "2".to_string())]);
        assert_eq!(rail_fence_encode(pt, &args0).unwrap(), b"135246");
        let args1 = HashMap::from([
            ("rails".to_string(), "2".to_string()),
            ("offset".to_string(), "1".to_string()),
        ]);
        let ct = rail_fence_encode(pt, &args1).unwrap();
        assert_eq!(ct, b"246135");
        assert_eq!(rail_fence_decode(&ct, &args1).unwrap(), pt);
    }

    #[test]
    fn rail_fence_rails1_and_roundtrip() {
        let pt = b"abracadabra";
        let args1 = HashMap::from([("rails".to_string(), "1".to_string())]);
        assert_eq!(rail_fence_encode(pt, &args1).unwrap(), pt);
        for rails in [2usize, 3, 4, 7] {
            let args = HashMap::from([("rails".to_string(), rails.to_string())]);
            let ct = rail_fence_encode(pt, &args).unwrap();
            assert_eq!(rail_fence_decode(&ct, &args).unwrap(), pt, "rails={rails}");
        }
    }

    #[test]
    fn ascii_case() {
        assert_eq!(upper(b"aB3c", &HashMap::new()).unwrap(), b"AB3C");
        assert_eq!(lower(b"aB3C", &HashMap::new()).unwrap(), b"ab3c");
    }

    #[test]
    fn swapcase_ascii() {
        assert_eq!(
            swapcase(b"HeLLo 123!", &HashMap::new()).unwrap(),
            b"hEllO 123!"
        );
        assert_eq!(swapcase(b"abc", &HashMap::new()).unwrap(), b"ABC");
        assert_eq!(swapcase(b"ABC", &HashMap::new()).unwrap(), b"abc");
        assert_eq!(
            swapcase(b"123 \x00\xff", &HashMap::new()).unwrap(),
            b"123 \x00\xff"
        );
    }

    #[test]
    fn trim_edges() {
        assert_eq!(
            trim(b" \t\r\n hello \n", &HashMap::new()).unwrap(),
            b"hello"
        );
        assert_eq!(trim(b"   ", &HashMap::new()).unwrap(), b"");
    }

    #[test]
    fn replace_substring() {
        let mut args = HashMap::new();
        args.insert("from".into(), "foo".into());
        args.insert("to".into(), "bar".into());
        assert_eq!(replace(b"foo and foo", &args).unwrap(), b"bar and bar");
    }

    #[test]
    fn rot13_known() {
        assert_eq!(
            rot13(b"Hello, World!", &HashMap::new()).unwrap(),
            b"Uryyb, Jbeyq!"
        );
        // ROT13 is self-inverse
        let once = rot13(b"nopqrstuvwxyz", &HashMap::new()).unwrap();
        assert_eq!(rot13(&once, &HashMap::new()).unwrap(), b"nopqrstuvwxyz");
    }

    #[test]
    fn not_inverts_and_is_self_inverse() {
        assert_eq!(
            bitwise_not(b"\x00\x0f\xff", &HashMap::new()).unwrap(),
            b"\xff\xf0\x00"
        );
        let once = bitwise_not(b"abc", &HashMap::new()).unwrap();
        assert_eq!(bitwise_not(&once, &HashMap::new()).unwrap(), b"abc");
    }

    #[test]
    fn byteswap_groups() {
        assert_eq!(
            byteswap(b"\x01\x02\x03\x04\x05\x06", &HashMap::new()).unwrap(),
            b"\x04\x03\x02\x01\x05\x06"
        );
        let mut args = HashMap::new();
        args.insert("width".into(), "2".into());
        assert_eq!(
            byteswap(b"\x01\x02\x03\x04", &args).unwrap(),
            b"\x02\x01\x04\x03"
        );
        args.insert("width".into(), "8".into());
        assert_eq!(
            byteswap(b"\x01\x02\x03\x04\x05\x06\x07\x08", &args).unwrap(),
            b"\x08\x07\x06\x05\x04\x03\x02\x01"
        );
        // Trailing bytes that do not fill a group are kept as-is.
        assert_eq!(byteswap(b"\x01\x02", &args).unwrap(), b"\x01\x02");
        args.insert("width".into(), "3".into());
        assert!(byteswap(b"x", &args).is_err());
    }

    #[test]
    fn dedup_collapses_runs() {
        assert_eq!(dedup(b"aaabbbcc", &HashMap::new()).unwrap(), b"abc");
        assert_eq!(dedup(b"", &HashMap::new()).unwrap(), b"");
        assert_eq!(dedup(b"aabbcc", &HashMap::new()).unwrap(), b"abc");
    }

    /// Streaming path must produce identical output to the in-memory path, even on awkward chunk splits.
    fn stream_equals_memory(
        make: fn(&HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>>,
        run: fn(&[u8], &HashMap<String, String>) -> anyhow::Result<Vec<u8>>,
        input: &[u8],
        args: &HashMap<String, String>,
    ) {
        let mut h = make(args).unwrap();
        let mut acc = Vec::new();
        for c in input.chunks(3) {
            acc.extend(h.write(c).unwrap());
        }
        acc.extend(h.finish().unwrap());
        assert_eq!(acc, run(input, args).unwrap());
    }

    #[test]
    fn stream_matches_memory_for_byte_transforms() {
        let data: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
        let empty = HashMap::new();
        stream_equals_memory(make_bitwise_not, bitwise_not, &data, &empty);
        stream_equals_memory(make_dedup, dedup, &data, &empty);
        let mut args = HashMap::new();
        args.insert("width".into(), "2".into());
        stream_equals_memory(make_byteswap, byteswap, &data, &args);
    }

    #[test]
    fn rot13_bruteforce_finds_shift() {
        let plain = b"attack at dawn tomorrow";
        let cipher: Vec<u8> = plain.iter().map(|b| caesar_shift(*b, 3)).collect();
        let out = rot13_bruteforce(&cipher, &HashMap::new()).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.starts_with("shift 23: "), "got: {}", s);
        assert!(s.contains("attack at dawn"), "got: {}", s);
        assert_eq!(s.lines().count(), 5);
    }

    #[test]
    fn rot13_bruteforce_empty_input() {
        assert_eq!(rot13_bruteforce(b"", &HashMap::new()).unwrap(), b"");
    }

    #[test]
    fn rot47_known() {
        let enc = rot47(b"Hello!", &HashMap::new()).unwrap();
        assert_eq!(enc, b"w6==@P");
        assert_eq!(rot47(&enc, &HashMap::new()).unwrap(), b"Hello!");
    }

    #[test]
    fn vigenere_known_vector() {
        let mut a = HashMap::new();
        a.insert("key".to_string(), "LEMON".to_string());
        let plain = b"ATTACKATDAWN";
        let enc = vigenere_encode(plain, &a).unwrap();
        assert_eq!(enc, b"LXFOPVEFRNHR");
        assert_eq!(vigenere_decode(&enc, &a).unwrap(), plain);
        // Non-letters pass through and do not consume key positions.
        let mut a2 = HashMap::new();
        a2.insert("key".to_string(), "A".to_string());
        assert_eq!(vigenere_encode(b"a b!", &a2).unwrap(), b"a b!");
        assert!(vigenere_encode(b"x", &HashMap::new()).is_err());
    }

    #[test]
    fn sort_unique_bytes() {
        assert_eq!(sort_bytes(b"caba", &HashMap::new()).unwrap(), b"aabc");
        assert_eq!(sort_bytes(b"", &HashMap::new()).unwrap(), b"");
        assert_eq!(unique_bytes(b"caba", &HashMap::new()).unwrap(), b"cab");
        assert_eq!(unique_bytes(b"", &HashMap::new()).unwrap(), b"");
    }

    #[test]
    fn count_take_drop_bytes() {
        let mut a = HashMap::new();
        a.insert("sub".to_string(), "ab".to_string());
        assert_eq!(count_sub(b"ababxab", &a).unwrap(), b"3");
        assert_eq!(count_sub(b"aaa", &a).unwrap(), b"0");
        assert!(count_sub(b"x", &HashMap::new()).is_err());

        let mut n = HashMap::new();
        n.insert("n".to_string(), "3".to_string());
        assert_eq!(take_bytes(b"abcdef", &n).unwrap(), b"abc");
        assert_eq!(drop_bytes(b"abcdef", &n).unwrap(), b"def");
        n.insert("n".to_string(), "99".to_string());
        assert_eq!(take_bytes(b"abcdef", &n).unwrap(), b"abcdef");
        assert_eq!(drop_bytes(b"abcdef", &n).unwrap(), b"");
        assert!(take_bytes(b"x", &HashMap::new()).is_err());
    }

    #[test]
    fn split_by_delim_segments() {
        let mut a = HashMap::new();
        a.insert("delimiter".to_string(), ",".to_string());
        assert_eq!(split_by_delim(b"a,b,c", &a).unwrap(), b"a\nb\nc\n");
        assert_eq!(split_by_delim(b"", &a).unwrap(), b"");
        assert!(split_by_delim(b"x", &HashMap::new()).is_err());
        a.insert("delimiter".to_string(), "".to_string());
        assert!(split_by_delim(b"x", &a).is_err());
    }

    #[test]
    fn filter_lines_substring() {
        let mut a = HashMap::new();
        a.insert("sub".to_string(), "err".to_string());
        assert_eq!(
            filter_lines(b"ok line\nsome error here\nanother\nERROR\n", &a).unwrap(),
            b"some error here\n"
        );
        assert_eq!(filter_lines(b"no match", &a).unwrap(), b"");
        assert!(filter_lines(b"x", &HashMap::new()).is_err());
    }

    #[test]
    fn head_tail_lines() {
        let mut a = HashMap::new();
        a.insert("n".to_string(), "2".to_string());
        assert_eq!(head_lines(b"1\n2\n3\n4\n", &a).unwrap(), b"1\n2\n");
        assert_eq!(tail_lines(b"1\n2\n3\n4\n", &a).unwrap(), b"3\n4\n");
        a.insert("n".to_string(), "99".to_string());
        assert_eq!(head_lines(b"1\n2\n", &a).unwrap(), b"1\n2\n");
        assert_eq!(tail_lines(b"1\n2\n", &a).unwrap(), b"1\n2\n");
        a.insert("n".to_string(), "0".to_string());
        assert_eq!(head_lines(b"1\n2\n", &a).unwrap(), b"");
        assert_eq!(tail_lines(b"1\n2\n", &a).unwrap(), b"");
        a.insert("n".to_string(), "x".to_string());
        assert!(head_lines(b"1\n", &a).is_err());
        assert!(tail_lines(b"1\n", &a).is_err());
    }

    #[test]
    fn defang_ipv4() {
        assert_eq!(
            defang_ip(b"host 1.2.3.4 alive", &HashMap::new()).unwrap(),
            b"host 1[.]2[.]3[.]4 alive"
        );
        // Only dotted-quad tokens are defanged; a bare dotted word is untouched.
        assert_eq!(defang_ip(b"v1.2.3", &HashMap::new()).unwrap(), b"v1.2.3");
    }

    #[test]
    fn defang_ipv6_and_url() {
        assert_eq!(
            defang_ipv6(b"2001:db8::1", &HashMap::new()).unwrap(),
            b"2001[:]db8[:][:]1"
        );
        assert_eq!(defang_ipv6(b"::1", &HashMap::new()).unwrap(), b"[:][:]1");
        assert_eq!(
            defang_url(b"visit https://example.com/a?b=c", &HashMap::new()).unwrap(),
            b"visit hxxps://example[.]com/a?b=c"
        );
        assert_eq!(
            defang_url(b"http://x.y", &HashMap::new()).unwrap(),
            b"hxxp://x[.]y"
        );
    }

    #[test]
    fn defang_url_options() {
        // scheme escape adds [://] on top of the http rule
        assert_eq!(
            defang_url(
                b"visit https://example.com",
                &HashMap::from([("escape_scheme".to_string(), "true".to_string())])
            )
            .unwrap(),
            b"visit hxxps[://]example[.]com"
        );
        // disabling dots keeps the dot intact
        assert_eq!(
            defang_url(
                b"http://x.y",
                &HashMap::from([("escape_dots".to_string(), "false".to_string())])
            )
            .unwrap(),
            b"hxxp://x.y"
        );
        // disabling http keeps the scheme untouched
        assert_eq!(
            defang_url(
                b"http://x.y",
                &HashMap::from([("escape_http".to_string(), "false".to_string())])
            )
            .unwrap(),
            b"http://x[.]y"
        );
        // urls mode only rewrites URL spans, leaving surrounding text alone
        assert_eq!(
            defang_url(
                b"check https://example.com/a now",
                &HashMap::from([("process".to_string(), "urls".to_string())])
            )
            .unwrap(),
            b"check hxxps://example[.]com/a now"
        );
        // domains mode handles standalone domains after URLs
        assert_eq!(
            defang_url(
                b"see https://example.com and evil.org:8080",
                &HashMap::from([("process".to_string(), "domains".to_string())])
            )
            .unwrap(),
            b"see hxxps://example[.]com and evil[.]org:8080"
        );
        // everything mode applies to the whole input
        assert_eq!(
            defang_url(
                b"https://example.com plain",
                &HashMap::from([("process".to_string(), "everything".to_string())])
            )
            .unwrap(),
            b"hxxps://example[.]com plain"
        );
        // invalid flag / mode values are rejected
        assert!(
            defang_url(
                b"x",
                &HashMap::from([("escape_dots".to_string(), "maybe".to_string())])
            )
            .is_err()
        );
        assert!(
            defang_url(
                b"x",
                &HashMap::from([("process".to_string(), "bogus".to_string())])
            )
            .is_err()
        );
    }
}

// ---------------------------------------------------------------------------
// ROT13 brute force (all Caesar shifts)
// ---------------------------------------------------------------------------

fn caesar_shift(b: u8, shift: u8) -> u8 {
    match b {
        b'A'..=b'Z' => (b - b'A' + shift) % 26 + b'A',
        b'a'..=b'z' => (b - b'a' + shift) % 26 + b'a',
        _ => b,
    }
}

fn rot13_bruteforce(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    use crate::ops::analyze::{parse_top, score_text};
    let top = parse_top(args)?;
    if input.is_empty() {
        return Ok(Vec::new());
    }
    // Optional sample window (CyberChef sample length / sample offset).
    let sample_len = args
        .get("sample_length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(input.len());
    let sample_off = args
        .get("sample_offset")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    let start = sample_off.min(input.len());
    let end = input.len().min(start.saturating_add(sample_len));
    let sample = &input[start..end];
    if sample.is_empty() {
        return Ok(Vec::new());
    }
    // Optional known-plaintext filter (case-insensitive substring).
    let known = args
        .get("known_plaintext")
        .map(|s| s.as_str())
        .unwrap_or("");
    let mut cands: Vec<(f64, u8, Vec<u8>)> = (0..=25u8)
        .map(|shift| {
            let dec: Vec<u8> = sample.iter().map(|b| caesar_shift(*b, shift)).collect();
            let score = score_text(&dec);
            (score, shift, dec)
        })
        .collect();
    if !known.is_empty() {
        let needle = known.to_lowercase();
        cands.retain(|(_, _, dec)| {
            String::from_utf8_lossy(dec)
                .to_lowercase()
                .contains(&needle)
        });
    }
    cands.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    let mut out = Vec::new();
    for (_, shift, dec) in cands.into_iter().take(top) {
        out.extend_from_slice(format!("shift {:02}: ", shift).as_bytes());
        out.extend_from_slice(String::from_utf8_lossy(&dec).as_bytes());
        out.push(b'\n');
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// classical / text batch ops
// ---------------------------------------------------------------------------

fn rot47(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let amount: u8 = match args.get("amount") {
        Some(s) => s
            .trim()
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid amount: {e}"))?,
        None => 47,
    };
    Ok(input
        .iter()
        .map(|&b| match b {
            33..=126 => 33 + ((b - 33 + amount) % 94),
            _ => b,
        })
        .collect())
}

fn vigenere_shift(
    input: &[u8],
    args: &HashMap<String, String>,
    encode: bool,
) -> anyhow::Result<Vec<u8>> {
    let key = args
        .get("key")
        .ok_or_else(|| anyhow::anyhow!("{}", i18n::tf("err.missing_key", &[])))?;
    let key_bytes: Vec<u8> = key.bytes().filter(|b| b.is_ascii_alphabetic()).collect();
    if key_bytes.is_empty() {
        anyhow::bail!("{}", i18n::tf("err.empty_key", &[]));
    }
    let mut out = Vec::with_capacity(input.len());
    for (ki, &b) in input.iter().enumerate() {
        let shift = key_bytes[ki % key_bytes.len()].to_ascii_lowercase() - b'a';
        let shifted = |off: u8| -> u8 {
            if encode {
                (off + shift) % 26
            } else {
                (off + 26 - shift % 26) % 26
            }
        };
        match b {
            b'A'..=b'Z' => out.push(shifted(b - b'A') + b'A'),
            b'a'..=b'z' => out.push(shifted(b - b'a') + b'a'),
            _ => out.push(b),
        }
    }
    Ok(out)
}

fn vigenere_encode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    vigenere_shift(input, args, true)
}

fn vigenere_decode(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    vigenere_shift(input, args, false)
}

fn sort_bytes(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let sort_type = args.get("type").map(|s| s.as_str()).unwrap_or("alpha");
    match sort_type {
        "alpha" => {
            let mut v = input.to_vec();
            v.sort_unstable();
            Ok(v)
        }
        "ip" | "numeric" | "length" => {
            let text = String::from_utf8_lossy(input);
            let mut lines: Vec<&str> = text.lines().collect();
            match sort_type {
                "ip" => lines.sort_by_key(|a| ip_key(a)),
                "numeric" => lines.sort_by(|a, b| {
                    let an = a.trim().parse::<f64>().unwrap_or(f64::NEG_INFINITY);
                    let bn = b.trim().parse::<f64>().unwrap_or(f64::NEG_INFINITY);
                    an.partial_cmp(&bn).unwrap_or(std::cmp::Ordering::Equal)
                }),
                "length" => lines.sort_by_key(|a| a.len()),
                _ => unreachable!(),
            }
            let mut out = Vec::with_capacity(input.len());
            for l in lines {
                out.extend_from_slice(l.as_bytes());
                out.push(b'\n');
            }
            Ok(out)
        }
        other => anyhow::bail!("invalid sort type: {other} (alpha|ip|numeric|length)"),
    }
}

fn ip_key(s: &str) -> (u32, u32, u32, u32) {
    let mut parts = s.trim().split('.');
    let a: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let b: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let c: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let d: u32 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    (a, b, c, d)
}

fn unique_bytes(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let separator = args.get("separator").map(|s| s.as_str());
    let display_count = match args.get("display_count") {
        Some(s) => crate::ops::parse_bool(s)?,
        None => false,
    };
    match separator {
        None => {
            let mut seen = [false; 256];
            let mut out = Vec::new();
            for &b in input {
                if !seen[b as usize] {
                    seen[b as usize] = true;
                    out.push(b);
                }
            }
            Ok(out)
        }
        Some(sep) => {
            let text = String::from_utf8_lossy(input);
            let items: Vec<&str> = if sep == "\n" {
                text.lines().collect()
            } else {
                text.split(sep).collect()
            };
            let mut seen = std::collections::BTreeSet::new();
            let mut out: Vec<String> = Vec::new();
            for it in &items {
                if seen.insert(it.to_string()) {
                    if display_count {
                        let n = items.iter().filter(|x| ***x == **it).count();
                        out.push(format!("{n} {it}"));
                    } else {
                        out.push(it.to_string());
                    }
                }
            }
            Ok(out.join("\n").into_bytes())
        }
    }
}

fn count_sub(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let sub = args
        .get("sub")
        .ok_or_else(|| anyhow::anyhow!("{}", i18n::tf("err.missing_sub", &[])))?
        .as_bytes()
        .to_vec();
    if sub.is_empty() {
        anyhow::bail!("{}", i18n::tf("err.empty_sub", &[]));
    }
    let mut count = 0usize;
    let mut i = 0usize;
    while i + sub.len() <= input.len() {
        if &input[i..i + sub.len()] == sub.as_slice() {
            count += 1;
            i += sub.len();
        } else {
            i += 1;
        }
    }
    Ok(count.to_string().into_bytes())
}

fn parse_n(args: &HashMap<String, String>) -> anyhow::Result<usize> {
    args.get("n")
        .ok_or_else(|| anyhow::anyhow!("{}", i18n::tf("err.missing_n", &[])))?
        .parse::<usize>()
        .map_err(|e| anyhow::anyhow!("{}", i18n::tf("err.n_not_num", &[e.to_string().as_str()])))
}

fn take_bytes(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let n = parse_n(args)?;
    let start = match args.get("start") {
        Some(s) => s.trim().parse::<usize>().map_err(|e| {
            anyhow::anyhow!("{}", i18n::tf("err.n_not_num", &[e.to_string().as_str()]))
        })?,
        None => 0,
    };
    let per_line = match args.get("per_line") {
        Some(s) => crate::ops::parse_bool(s)?,
        None => false,
    };
    if per_line {
        let text = String::from_utf8_lossy(input);
        let mut out = Vec::with_capacity(input.len());
        for line in text.lines() {
            let bytes = line.as_bytes();
            let end = (start + n).min(bytes.len());
            out.extend_from_slice(&bytes[start.min(bytes.len())..end]);
            out.push(b'\n');
        }
        Ok(out)
    } else {
        let end = (start + n).min(input.len());
        Ok(input[start.min(input.len())..end].to_vec())
    }
}

fn drop_bytes(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let n = parse_n(args)?;
    let offset = match args.get("offset") {
        Some(s) => s.trim().parse::<usize>().map_err(|e| {
            anyhow::anyhow!("{}", i18n::tf("err.n_not_num", &[e.to_string().as_str()]))
        })?,
        None => 0,
    };
    let per_line = match args.get("per_line") {
        Some(s) => crate::ops::parse_bool(s)?,
        None => false,
    };
    if per_line {
        let text = String::from_utf8_lossy(input);
        let mut out = Vec::with_capacity(input.len());
        for line in text.lines() {
            let bytes = line.as_bytes();
            let start = offset.min(bytes.len());
            let end = (start + n).min(bytes.len());
            out.extend_from_slice(&bytes[..start]);
            out.extend_from_slice(&bytes[end..]);
            out.push(b'\n');
        }
        Ok(out)
    } else {
        let start = offset.min(input.len());
        let end = (start + n).min(input.len());
        let mut out = input.to_vec();
        out.drain(start..end);
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// line/text ops (split / filter / head / tail) + defang.
// All are whole-input transforms (line-oriented), so they are in-memory only.
// ---------------------------------------------------------------------------

fn split_by_delim(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let delim = args
        .get("delimiter")
        .ok_or_else(|| anyhow::anyhow!("{}", i18n::t("err.missing_delimiter")))?;
    if delim.is_empty() {
        anyhow::bail!("{}", i18n::t("err.empty_delimiter"));
    }
    if input.is_empty() {
        return Ok(Vec::new());
    }
    let join = args
        .get("join")
        .cloned()
        .unwrap_or_else(|| "\n".to_string());
    let text = String::from_utf8_lossy(input);
    let mut out = Vec::with_capacity(text.len() + text.matches(delim.as_str()).count() + 1);
    for seg in text.split(delim.as_str()) {
        out.extend_from_slice(seg.as_bytes());
        out.extend_from_slice(join.as_bytes());
    }
    Ok(out)
}

fn filter_lines(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let sub = args
        .get("sub")
        .ok_or_else(|| anyhow::anyhow!("{}", i18n::t("err.missing_sub")))?;
    if sub.is_empty() {
        anyhow::bail!("{}", i18n::t("err.empty_sub"));
    }
    let use_regex = match args.get("regex") {
        Some(s) => crate::ops::parse_bool(s)?,
        None => false,
    };
    let invert = match args.get("invert") {
        Some(s) => crate::ops::parse_bool(s)?,
        None => false,
    };
    let re = if use_regex {
        Some(regex::Regex::new(sub.as_str()).map_err(|e| anyhow::anyhow!("invalid regex: {e}"))?)
    } else {
        None
    };
    let text = String::from_utf8_lossy(input);
    let mut out = Vec::with_capacity(input.len());
    for line in text.lines() {
        let matched = match &re {
            Some(r) => r.is_match(line),
            None => line.contains(sub.as_str()),
        };
        if matched != invert {
            out.extend_from_slice(line.as_bytes());
            out.push(b'\n');
        }
    }
    Ok(out)
}

fn head_lines(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let n = parse_n(args)?;
    let text = String::from_utf8_lossy(input);
    let mut out = Vec::with_capacity(input.len());
    for line in text.lines().take(n) {
        out.extend_from_slice(line.as_bytes());
        out.push(b'\n');
    }
    Ok(out)
}

fn tail_lines(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let n = parse_n(args)?;
    let text = String::from_utf8_lossy(input);
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(n);
    let mut out = Vec::with_capacity(input.len());
    for line in &lines[start..] {
        out.extend_from_slice(line.as_bytes());
        out.push(b'\n');
    }
    Ok(out)
}

fn defang_ip(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let text = String::from_utf8_lossy(input);
    let re = regex::Regex::new(r"\b\d{1,3}(?:\.\d{1,3}){3}\b").map_err(|e| {
        anyhow::anyhow!(
            "{}",
            i18n::tf("err.regex_compile", &[e.to_string().as_str()])
        )
    })?;
    let out = re.replace_all(&text, |caps: &regex::Captures| caps[0].replace('.', "[.]"));
    Ok(out.as_bytes().to_vec())
}

fn defang_ipv6(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let text = String::from_utf8_lossy(input);
    // Match IPv6-like tokens: hex groups separated by colons, or a leading "::".
    // Not a full RFC 4291 grammar; may also match colon-separated hex tokens in text.
    let re = regex::Regex::new(r"(?i)(?:[0-9a-f]{1,4}:){1,7}[0-9a-f]{0,4}|:{1,2}[0-9a-f]{1,4}")
        .map_err(|e| {
            anyhow::anyhow!(
                "{}",
                i18n::tf("err.regex_compile", &[e.to_string().as_str()])
            )
        })?;
    let mut out = String::with_capacity(text.len());
    let mut last = 0usize;
    for m in re.find_iter(&text) {
        out.push_str(&text[last..m.start()]);
        out.push_str(&m.as_str().replace(':', "[:]"));
        last = m.end();
    }
    out.push_str(&text[last..]);
    Ok(out.into_bytes())
}

fn defang_url(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let dots = defang_flag(args, "escape_dots", true)?;
    let http = defang_flag(args, "escape_http", true)?;
    let scheme = defang_flag(args, "escape_scheme", false)?;
    let process = match args.get("process").map(|s| s.as_str()) {
        None | Some("everything") => DefangMode::Everything,
        Some("urls") => DefangMode::Urls,
        Some("domains") => DefangMode::Domains,
        Some(other) => {
            anyhow::bail!(
                "{}",
                i18n::t("err.defang.process_invalid").replace("{v}", other)
            )
        }
    };
    let text = String::from_utf8_lossy(input);
    let out = match process {
        DefangMode::Everything => defang_text(&text, dots, http, scheme),
        DefangMode::Urls => {
            let re = regex::Regex::new("https?://[^\\s<>\"']+").unwrap();
            re.replace_all(&text, |caps: &regex::Captures<'_>| {
                defang_text(&caps[0], dots, http, scheme)
            })
            .into_owned()
        }
        DefangMode::Domains => {
            // Mirrors CyberChef "Valid domains and full URLs": URLs first, then
            // standalone domains (already-defanged URLs no longer match the
            // domain pattern because dots became "[.]").
            let url_re = regex::Regex::new("https?://[^\\s<>\"']+").unwrap();
            let staged = url_re
                .replace_all(&text, |caps: &regex::Captures<'_>| {
                    defang_text(&caps[0], dots, http, scheme)
                })
                .into_owned();
            let dom_re = regex::Regex::new(
                r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?::\d+)?",
            )
            .unwrap();
            dom_re
                .replace_all(&staged, |caps: &regex::Captures<'_>| {
                    defang_text(&caps[0], dots, http, scheme)
                })
                .into_owned()
        }
    };
    Ok(out.into_bytes())
}

#[derive(Clone, Copy)]
enum DefangMode {
    Everything,
    Urls,
    Domains,
}

fn defang_flag(args: &HashMap<String, String>, name: &str, default: bool) -> anyhow::Result<bool> {
    match args.get(name).map(|s| s.as_str()) {
        None => Ok(default),
        Some("true") => Ok(true),
        Some("false") => Ok(false),
        Some(v) => anyhow::bail!(
            "{}",
            i18n::t("err.defang.flag_invalid")
                .replace("{name}", name)
                .replace("{v}", v)
        ),
    }
}

fn defang_text(s: &str, dots: bool, http: bool, scheme: bool) -> String {
    let mut out = s.to_string();
    // https first so "https://" is not turned into "hxxps://" via the http rule.
    if http {
        out = out.replace("https://", "hxxps://");
        out = out.replace("http://", "hxxp://");
    }
    if dots {
        out = out.replace('.', "[.]");
    }
    if scheme {
        out = out.replace("://", "[://]");
    }
    out
}

/// Fork is an engine-level flow-control op (see `crate::engine::process_bytes`);
/// the engine intercepts it and re-runs the remaining steps on each segment.
/// This in-memory stub exists for registration/listing only and is never reached
/// through the engine paths.
fn fork_identity(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    Ok(input.to_vec())
}

// ---------------------------------------------------------------------------
// bitwise family
// ---------------------------------------------------------------------------

fn bitwise_and(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let key = args.get("key").map(|s| s.as_bytes()).unwrap_or(&[]);
    if key.is_empty() {
        anyhow::bail!("key must not be empty");
    }
    Ok(input
        .iter()
        .enumerate()
        .map(|(i, b)| b & key[i % key.len()])
        .collect())
}

fn bitwise_or(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let key = args.get("key").map(|s| s.as_bytes()).unwrap_or(&[]);
    if key.is_empty() {
        anyhow::bail!("key must not be empty");
    }
    Ok(input
        .iter()
        .enumerate()
        .map(|(i, b)| b | key[i % key.len()])
        .collect())
}

/// Shared streaming constructor for AND/OR: holds the key and current index.
struct AndStream {
    key: Vec<u8>,
    idx: usize,
}
struct OrStream {
    key: Vec<u8>,
    idx: usize,
}

fn make_bitwise_and_stream(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    let key = args
        .get("key")
        .map(|s| s.as_bytes().to_vec())
        .unwrap_or_default();
    if key.is_empty() {
        anyhow::bail!("key must not be empty");
    }
    Ok(Box::new(AndStream { key, idx: 0 }))
}

fn make_bitwise_or_stream(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    let key = args
        .get("key")
        .map(|s| s.as_bytes().to_vec())
        .unwrap_or_default();
    if key.is_empty() {
        anyhow::bail!("key must not be empty");
    }
    Ok(Box::new(OrStream { key, idx: 0 }))
}

impl StreamingOp for AndStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        let out: Vec<u8> = chunk
            .iter()
            .enumerate()
            .map(|(i, b)| b & self.key[(self.idx + i) % self.key.len()])
            .collect();
        self.idx = (self.idx + chunk.len()) % self.key.len();
        Ok(out)
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        Ok(Vec::new())
    }
}

impl StreamingOp for OrStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        let out: Vec<u8> = chunk
            .iter()
            .enumerate()
            .map(|(i, b)| b | self.key[(self.idx + i) % self.key.len()])
            .collect();
        self.idx = (self.idx + chunk.len()) % self.key.len();
        Ok(out)
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        Ok(Vec::new())
    }
}

fn bitwise_shift_left(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let n = parse_bits(args)?;
    Ok(input.iter().map(|b| b << n).collect())
}

fn bitwise_shift_right(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let n = parse_bits(args)?;
    let mode = args.get("mode").map(|s| s.as_str()).unwrap_or("logical");
    match mode {
        "logical" => Ok(input.iter().map(|b| b >> n).collect()),
        "arithmetic" => Ok(input.iter().map(|b| ((*b as i8) >> n) as u8).collect()),
        other => anyhow::bail!("invalid shift-right mode: {other} (logical|arithmetic)"),
    }
}

fn bitwise_rotate_left(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let n = parse_bits(args)?;
    let carry = match args.get("carry") {
        Some(s) => crate::ops::parse_bool(s)?,
        None => false,
    };
    if carry {
        Ok(input.iter().map(|b| rotate_left_carry(*b, n)).collect())
    } else {
        Ok(input.iter().map(|b| b.rotate_left(n)).collect())
    }
}

fn bitwise_rotate_right(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let n = parse_bits(args)?;
    let carry = match args.get("carry") {
        Some(s) => crate::ops::parse_bool(s)?,
        None => false,
    };
    if carry {
        Ok(input.iter().map(|b| rotate_right_carry(*b, n)).collect())
    } else {
        Ok(input.iter().map(|b| b.rotate_right(n)).collect())
    }
}

/// Rotate left through carry (9-bit rotate): the bit shifted out of the top
/// feeds into the bottom, cycling through a virtual carry flag.
fn rotate_left_carry(b: u8, n: u32) -> u8 {
    let mut val = b as u16;
    for _ in 0..n {
        let top = (val >> 8) & 1;
        val = ((val << 1) & 0x1FF) | top;
    }
    (val & 0xFF) as u8
}

/// Rotate right through carry (9-bit rotate), mirroring the left variant.
fn rotate_right_carry(b: u8, n: u32) -> u8 {
    let mut val = (b as u16) << 1; // 9-bit value with carry bit at position 8
    for _ in 0..n {
        let bottom = val & 1;
        val = (val >> 1) | (bottom << 8);
    }
    (val >> 1) as u8
}

fn parse_bits(args: &HashMap<String, String>) -> anyhow::Result<u32> {
    let raw = args
        .get("bits")
        .ok_or_else(|| anyhow::anyhow!("bits argument required"))?;
    let n: u32 = raw
        .parse()
        .map_err(|_| anyhow::anyhow!("bits must be an integer"))?;
    if !(1..=7).contains(&n) {
        anyhow::bail!("bits must be in 1..=7");
    }
    Ok(n)
}

struct ShiftLeftStream {
    n: u32,
}
struct ShiftRightStream {
    n: u32,
    arithmetic: bool,
}
struct RotateLeftStream {
    n: u32,
    carry: bool,
}
struct RotateRightStream {
    n: u32,
    carry: bool,
}

fn make_shift_left_stream(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    Ok(Box::new(ShiftLeftStream {
        n: parse_bits(args)?,
    }))
}
fn make_shift_right_stream(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    let arithmetic = match args.get("mode").map(|s| s.as_str()) {
        Some("arithmetic") => true,
        Some("logical") | None => false,
        Some(other) => anyhow::bail!("invalid shift-right mode: {other} (logical|arithmetic)"),
    };
    Ok(Box::new(ShiftRightStream {
        n: parse_bits(args)?,
        arithmetic,
    }))
}
fn make_rotate_left_stream(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    let carry = match args.get("carry") {
        Some(s) => crate::ops::parse_bool(s)?,
        None => false,
    };
    Ok(Box::new(RotateLeftStream {
        n: parse_bits(args)?,
        carry,
    }))
}
fn make_rotate_right_stream(
    args: &HashMap<String, String>,
) -> anyhow::Result<Box<dyn StreamingOp>> {
    let carry = match args.get("carry") {
        Some(s) => crate::ops::parse_bool(s)?,
        None => false,
    };
    Ok(Box::new(RotateRightStream {
        n: parse_bits(args)?,
        carry,
    }))
}

impl StreamingOp for ShiftLeftStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        Ok(chunk.iter().map(|b| b << self.n).collect())
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        Ok(Vec::new())
    }
}
impl StreamingOp for ShiftRightStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        Ok(chunk
            .iter()
            .map(|b| {
                if self.arithmetic {
                    ((*b as i8) >> self.n) as u8
                } else {
                    b >> self.n
                }
            })
            .collect())
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        Ok(Vec::new())
    }
}
impl StreamingOp for RotateLeftStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        Ok(chunk
            .iter()
            .map(|b| {
                if self.carry {
                    rotate_left_carry(*b, self.n)
                } else {
                    b.rotate_left(self.n)
                }
            })
            .collect())
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        Ok(Vec::new())
    }
}
impl StreamingOp for RotateRightStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        Ok(chunk
            .iter()
            .map(|b| {
                if self.carry {
                    rotate_right_carry(*b, self.n)
                } else {
                    b.rotate_right(self.n)
                }
            })
            .collect())
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        Ok(Vec::new())
    }
}

// ---------------------------------------------------------------------------
// set operations (line-based)
// ---------------------------------------------------------------------------

fn sets_union(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let sep = args.get("separator").map(|s| s.as_str()).unwrap_or("\n\n");
    let item_sep = args
        .get("item_separator")
        .map(|s| s.as_str())
        .unwrap_or("\n");
    let (a, b) = split_two_sets(input, sep, item_sep)?;
    let mut seen = std::collections::BTreeSet::new();
    let mut out: Vec<String> = Vec::new();
    for l in a.into_iter().chain(b) {
        if seen.insert(l.clone()) {
            out.push(l);
        }
    }
    Ok(out.join("\n").into_bytes())
}

fn sets_intersection(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let sep = args.get("separator").map(|s| s.as_str()).unwrap_or("\n\n");
    let item_sep = args
        .get("item_separator")
        .map(|s| s.as_str())
        .unwrap_or("\n");
    let (a, b) = split_two_sets(input, sep, item_sep)?;
    let bset: std::collections::BTreeSet<&String> = b.iter().collect();
    let mut out: Vec<String> = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for l in a {
        if bset.contains(&l) && seen.insert(l.clone()) {
            out.push(l);
        }
    }
    Ok(out.join("\n").into_bytes())
}

fn sets_difference(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let sep = args.get("separator").map(|s| s.as_str()).unwrap_or("\n\n");
    let item_sep = args
        .get("item_separator")
        .map(|s| s.as_str())
        .unwrap_or("\n");
    let (a, b) = split_two_sets(input, sep, item_sep)?;
    let bset: std::collections::BTreeSet<&String> = b.iter().collect();
    let mut out: Vec<String> = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for l in a {
        if !bset.contains(&l) && seen.insert(l.clone()) {
            out.push(l);
        }
    }
    Ok(out.join("\n").into_bytes())
}

/// Split input into two sets at the first occurrence of `sep`,
/// then split each side into items by `item_sep`.
fn split_two_sets(
    input: &[u8],
    sep: &str,
    item_sep: &str,
) -> anyhow::Result<(Vec<String>, Vec<String>)> {
    let s = String::from_utf8_lossy(input);
    let Some((left, right)) = s.split_once(sep) else {
        anyhow::bail!("{}", i18n::t("err.missing_separator"));
    };
    let split = |part: &str| -> Vec<String> {
        if item_sep == "\n" {
            part.lines()
                .map(|l| l.trim_end().to_string())
                .filter(|l| !l.is_empty())
                .collect()
        } else {
            part.split(item_sep)
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect()
        }
    };
    Ok((split(left), split(right)))
}

#[cfg(test)]
mod tests_bitwise_and_sets {
    #![allow(clippy::type_complexity)]
    use super::*;

    fn run(
        f: fn(&[u8], &HashMap<String, String>) -> anyhow::Result<Vec<u8>>,
        input: &str,
        args: &[(&str, &str)],
    ) -> String {
        let m: HashMap<String, String> = args
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let out = f(input.as_bytes(), &m).expect("op failed");
        String::from_utf8_lossy(&out).into_owned()
    }

    #[test]
    fn bitwise_and_cyclic() {
        // key "A" = 0x41; input "abc" -> 0x61&0x41=0x41 'A', 0x62&0x41=0x40 '@', 0x63&0x41=0x41 'A'
        assert_eq!(run(bitwise_and, "abc", &[("key", "A")]), "A@A");
    }

    #[test]
    fn bitwise_or_cyclic() {
        // 0x61|0x41='a', 0x62|0x41='c', 0x63|0x41='c'
        assert_eq!(run(bitwise_or, "abc", &[("key", "A")]), "acc");
    }

    #[test]
    fn shift_left_right() {
        // 0x01 << 3 = 0x08
        assert_eq!(
            run(bitwise_shift_left, "\u{1}\u{2}", &[("bits", "3")]),
            "\u{8}\u{10}"
        );
        assert_eq!(
            run(bitwise_shift_right, "\u{8}\u{10}", &[("bits", "3")]),
            "\u{1}\u{2}"
        );
    }

    #[test]
    fn rotate_left_right() {
        // 0x81 rotl 1 = 0x03, 0x02 rotl 1 = 0x04
        let m: HashMap<String, String> = HashMap::from([("bits".to_string(), "1".to_string())]);
        assert_eq!(bitwise_rotate_left(b"\x81\x02", &m).unwrap(), b"\x03\x04");
        // 0x03 rotr 1 = 0x81, 0x04 rotr 1 = 0x02
        assert_eq!(bitwise_rotate_right(b"\x03\x04", &m).unwrap(), b"\x81\x02");
    }

    #[test]
    fn bits_out_of_range() {
        assert!(
            bitwise_shift_left(
                b"x",
                &HashMap::from([("bits".to_string(), "8".to_string())])
            )
            .is_err()
        );
    }

    #[test]
    fn sets_union_intersection_difference() {
        let input = "a\nb\n\nb\nc\n";
        assert_eq!(run(sets_union, input, &[]), "a\nb\nc");
        assert_eq!(run(sets_intersection, input, &[]), "b");
        assert_eq!(run(sets_difference, input, &[]), "a");
    }

    #[test]
    fn stream_equals_memory_p1_4() {
        type Mk = fn(&HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>>;
        type Mem = fn(&[u8], &HashMap<String, String>) -> anyhow::Result<Vec<u8>>;
        let cases: [(Mk, Mem, &[(&str, &str)]); 6] = [
            (make_bitwise_and_stream, bitwise_and, &[("key", "secret")]),
            (make_bitwise_or_stream, bitwise_or, &[("key", "key")]),
            (make_shift_left_stream, bitwise_shift_left, &[("bits", "2")]),
            (
                make_shift_right_stream,
                bitwise_shift_right,
                &[("bits", "3")],
            ),
            (
                make_rotate_left_stream,
                bitwise_rotate_left,
                &[("bits", "1")],
            ),
            (
                make_rotate_right_stream,
                bitwise_rotate_right,
                &[("bits", "1")],
            ),
        ];
        let data = b"Hello, dpa! \x00\xff\x80 bitwise ops 1234567890";
        for (mk, mem, args) in cases {
            let m: HashMap<String, String> = args
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            let mut st = mk(&m).unwrap();
            let mut got = Vec::new();
            for c in data.chunks(5) {
                got.extend(st.write(c).unwrap());
            }
            got.extend(st.finish().unwrap());
            assert_eq!(
                got,
                mem(data, &m).unwrap(),
                "stream vs memory mismatch for args {:?}",
                args
            );
        }
    }

    #[test]
    fn reverse_modes() {
        assert_eq!(run(reverse, "abc", &[]), "cba");
        assert_eq!(run(reverse, "a中b", &[("mode", "chars")]), "b中a");
        assert_eq!(run(reverse, "ab\ncd\n", &[("mode", "lines")]), "cd\nab\n");
        assert!(
            reverse(
                b"x",
                &HashMap::from([("mode".to_string(), "bad".to_string())])
            )
            .is_err()
        );
    }

    #[test]
    fn upper_modes() {
        assert_eq!(run(upper, "hello world", &[]), "HELLO WORLD");
        assert_eq!(
            run(upper, "hello world", &[("mode", "words")]),
            "Hello World"
        );
        assert_eq!(run(upper, "hi. bye!", &[("mode", "sentences")]), "Hi. Bye!");
        assert_eq!(run(upper, "a\nb", &[("mode", "paragraphs")]), "A\nB");
        assert!(
            upper(
                b"x",
                &HashMap::from([("mode".to_string(), "bad".to_string())])
            )
            .is_err()
        );
    }

    #[test]
    fn rot13_params() {
        // default amount 13 keeps classic behaviour
        assert_eq!(run(rot13, "Hello, World!", &[]), "Uryyb, Jbeyq!");
        // amount 1 is a plain Caesar shift
        assert_eq!(run(rot13, "abc", &[("amount", "1")]), "bcd");
        // disabling uppercase keeps letters untouched
        assert_eq!(run(rot13, "ABC", &[("rot_upper", "false")]), "ABC");
        // numeric rotation on
        assert_eq!(run(rot13, "123", &[("rot_numeric", "true")]), "456");
    }

    #[test]
    fn rot47_amount() {
        assert_eq!(run(rot47, "ABC", &[]), "pqr");
        assert_eq!(run(rot47, "ABC", &[("amount", "0")]), "ABC");
    }

    #[test]
    fn sort_types() {
        assert_eq!(run(sort_bytes, "cab", &[]), "abc");
        assert_eq!(
            run(sort_bytes, "10\n2\n1\n", &[("type", "numeric")]),
            "1\n2\n10\n"
        );
        assert_eq!(run(sort_bytes, "bb\na\n", &[("type", "length")]), "a\nbb\n");
        assert_eq!(
            run(sort_bytes, "192.168.1.2\n10.0.0.1\n", &[("type", "ip")]),
            "10.0.0.1\n192.168.1.2\n"
        );
        assert!(
            sort_bytes(
                b"x",
                &HashMap::from([("type".to_string(), "bad".to_string())])
            )
            .is_err()
        );
    }

    #[test]
    fn unique_params() {
        assert_eq!(run(unique_bytes, "abac", &[]), "abc");
        assert_eq!(
            run(unique_bytes, "a\nb\na\nb\nc\n", &[("separator", "\n")]),
            "a\nb\nc"
        );
        assert_eq!(
            run(
                unique_bytes,
                "a\na\nb\n",
                &[("separator", "\n"), ("display_count", "true")]
            ),
            "2 a\n1 b"
        );
    }

    #[test]
    fn take_drop_params() {
        assert_eq!(run(take_bytes, "abcdef", &[("n", "2")]), "ab");
        assert_eq!(
            run(take_bytes, "abcdef", &[("n", "2"), ("start", "3")]),
            "de"
        );
        assert_eq!(
            run(
                take_bytes,
                "abcd\nabcd\n",
                &[("n", "2"), ("per_line", "true")]
            ),
            "ab\nab\n"
        );
        assert_eq!(run(drop_bytes, "abcdef", &[("n", "2")]), "cdef");
        assert_eq!(
            run(drop_bytes, "abcdef", &[("n", "2"), ("offset", "3")]),
            "abcf"
        );
        assert_eq!(
            run(
                drop_bytes,
                "abcd\nabcd\n",
                &[("n", "2"), ("per_line", "true")]
            ),
            "cd\ncd\n"
        );
    }

    #[test]
    fn split_join() {
        assert_eq!(
            run(split_by_delim, "a,b,c", &[("delimiter", ",")]),
            "a\nb\nc\n"
        );
        assert_eq!(
            run(
                split_by_delim,
                "a,b,c",
                &[("delimiter", ","), ("join", "|")]
            ),
            "a|b|c|"
        );
    }

    #[test]
    fn filter_regex_invert() {
        assert_eq!(run(filter_lines, "ab\ncd\nef\n", &[("sub", "c")]), "cd\n");
        assert_eq!(
            run(
                filter_lines,
                "ab\ncd\nef\n",
                &[("sub", "c"), ("invert", "true")]
            ),
            "ab\nef\n"
        );
        assert_eq!(
            run(
                filter_lines,
                "a1\nbb\n",
                &[("sub", "^a\\d$"), ("regex", "true")]
            ),
            "a1\n"
        );
    }

    #[test]
    fn shift_right_arithmetic() {
        let m: HashMap<String, String> = HashMap::from([("bits".to_string(), "3".to_string())]);
        // logical: 0x80 >> 3 = 0x10
        assert_eq!(bitwise_shift_right(b"\x80", &m).unwrap(), b"\x10");
        // arithmetic: 0x80 >> 3 = 0xF0 (sign fill)
        let mut am = m.clone();
        am.insert("mode".to_string(), "arithmetic".to_string());
        assert_eq!(bitwise_shift_right(b"\x80", &am).unwrap(), b"\xF0");
    }

    #[test]
    fn rotate_carry() {
        let m: HashMap<String, String> = HashMap::from([("bits".to_string(), "1".to_string())]);
        // no carry: 0x81 rotl 1 = 0x03
        assert_eq!(bitwise_rotate_left(b"\x81", &m).unwrap(), b"\x03");
        // carry left (RCL): CF=0, 0x80 -> 0x00 with carry out
        let mut cm = m.clone();
        cm.insert("carry".to_string(), "true".to_string());
        assert_eq!(bitwise_rotate_left(b"\x80", &cm).unwrap(), b"\x00");
        // carry right (RCR): CF=0, 0x01 -> 0x00
        assert_eq!(bitwise_rotate_right(b"\x01", &cm).unwrap(), b"\x00");
    }

    #[test]
    fn sets_item_separator() {
        assert_eq!(
            run(sets_union, "a,b\n\nb,c\n", &[("item_separator", ",")]),
            "a\nb\nc"
        );
        assert_eq!(
            run(
                sets_intersection,
                "a,b\n\nb,c\n",
                &[("item_separator", ",")]
            ),
            "b"
        );
        assert_eq!(
            run(sets_difference, "a,b\n\nb,c\n", &[("item_separator", ",")]),
            "a"
        );
    }

    #[test]
    fn rot13_bruteforce_sample_and_known() {
        // "Uryyb Jbeyq" is "Hello World" rot13'd; shift 13 is the only plausible candidate.
        // known_plaintext keeps only shifts whose output contains the substring.
        let out = run(
            rot13_bruteforce,
            "Uryyb Jbeyq\n",
            &[("known_plaintext", "Hello")],
        );
        assert_eq!(out.trim_end(), "shift 13: Hello World");
        // top limits the number of candidates.
        let out = run(rot13_bruteforce, "Uryyb Jbeyq\n", &[("top", "2")]);
        assert_eq!(out.lines().filter(|l| !l.is_empty()).count(), 2);
        // sample_length scores only the first N bytes.
        let out = run(rot13_bruteforce, "Uryyb Jbeyq\n", &[("sample_length", "5")]);
        assert!(out.contains("shift 13: Hello"), "{out}");
        // sample_offset skips leading bytes (score changes but still runs).
        let out = run(rot13_bruteforce, "Uryyb Jbeyq\n", &[("sample_offset", "6")]);
        assert!(!out.is_empty(), "{out}");
        assert!(out.contains("shift "), "{out}");
    }
}

#[cfg(test)]
mod tests_cc_transforms {
    #![allow(clippy::type_complexity)]
    use super::*;

    #[allow(clippy::type_complexity)]
    fn run(
        f: fn(&[u8], &HashMap<String, String>) -> anyhow::Result<Vec<u8>>,
        input: &str,
        args: &[(&str, &str)],
    ) -> String {
        let m: HashMap<String, String> = args
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let out = f(input.as_bytes(), &m).expect("op failed");
        String::from_utf8_lossy(&out).into_owned()
    }

    #[test]
    fn case_convert_styles() {
        // camel default
        assert_eq!(run(case_convert, "hello world", &[]), "helloWorld");
        assert_eq!(
            run(case_convert, "Hello World foo-bar", &[]),
            "helloWorldFooBar"
        );
        assert_eq!(
            run(case_convert, "hello world", &[("style", "snake")]),
            "hello_world"
        );
        assert_eq!(
            run(case_convert, "hello world", &[("style", "kebab")]),
            "hello-world"
        );
        assert_eq!(
            run(case_convert, "hello world", &[("style", "pascal")]),
            "HelloWorld"
        );
        assert_eq!(
            run(case_convert, "hello world", &[("style", "title")]),
            "Hello World"
        );
        assert_eq!(
            run(case_convert, "hello world", &[("style", "constant")]),
            "HELLO_WORLD"
        );
        // digits stay attached to words; separators dropped
        assert_eq!(
            run(case_convert, "version 2 beta", &[("style", "camel")]),
            "version2Beta"
        );
        // empty input -> empty output
        assert_eq!(run(case_convert, "", &[]), "");
    }

    #[test]
    fn atbash_ascii_known() {
        // classic: Hello -> Svool
        assert_eq!(run(atbash, "Hello", &[]), "Svool");
        assert_eq!(run(atbash, "ABC", &[]), "ZYX");
        assert_eq!(run(atbash, "abc123", &[]), "zyx123");
    }

    #[test]
    fn remove_null_bytes() {
        assert_eq!(run(remove_null, "a\u{0}b\u{0}\u{0}c", &[]), "abc");
        assert_eq!(run(remove_null, "\u{0}\u{0}", &[]), "");
        assert_eq!(run(remove_null, "no nulls", &[]), "no nulls");
    }

    #[test]
    fn add_line_numbers_format() {
        assert_eq!(
            run(add_line_numbers, "a\nbb\nccc", &[]),
            "1 a\n2 bb\n3 ccc\n"
        );
        // width grows with line count
        assert_eq!(
            run(add_line_numbers, "1\n2\n3\n4\n5\n6\n7\n8\n9\n10", &[]),
            " 1 1\n 2 2\n 3 3\n 4 4\n 5 5\n 6 6\n 7 7\n 8 8\n 9 9\n10 10\n"
        );
        // custom separator
        assert_eq!(
            run(add_line_numbers, "a\nb", &[("separator", ": ")]),
            "1: a\n2: b\n"
        );
        // offset shifts numbering
        assert_eq!(
            run(add_line_numbers, "a\nb", &[("offset", "9")]),
            "10 a\n11 b\n"
        );
    }

    #[test]
    fn substitute_known_rot_and_range() {
        // ROT13 style via alphabet mapping (CC default-like)
        let rot13_from = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        let rot13_to = "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm";
        assert_eq!(
            run(
                substitute,
                "HELLO world",
                &[("from", rot13_from), ("to", rot13_to)]
            ),
            "URYYB jbeyq"
        );
        // digit range expansion 0-9 -> 9-0 reverse
        assert_eq!(
            run(
                substitute,
                "0123456789",
                &[("from", "0-9"), ("to", "9876543210")]
            ),
            "9876543210"
        );
        // a-z range -> reversed alphabet (atbash via substitute)
        assert_eq!(
            run(
                substitute,
                "abcxyz",
                &[("from", "a-z"), ("to", "zyxwvutsrqponmlkjihgfedcba")]
            ),
            "zyxcba"
        );
        // unmatched bytes are kept
        assert_eq!(
            run(substitute, "a1b", &[("from", "ab"), ("to", "XY")]),
            "X1Y"
        );
        // escapes: from "a\\nb" parses as [a, \n, b]; a->X, \n->Y, b kept (no mapping)
        assert_eq!(
            run(substitute, "a\nb", &[("from", "a\\nb"), ("to", "XY")]),
            "XYb"
        );
    }

    #[test]
    fn substitute_ignore_case_preserves_case() {
        // from lowercase only; ignore_case maps upper input and preserves case
        assert_eq!(
            run(
                substitute,
                "AbC",
                &[("from", "a"), ("to", "x"), ("ignore_case", "true")]
            ),
            "XbC"
        );
        // without ignore_case, only exact bytes match
        assert_eq!(
            run(
                substitute,
                "AbC",
                &[("from", "a"), ("to", "x"), ("ignore_case", "false")]
            ),
            "AbC"
        );
    }
}
