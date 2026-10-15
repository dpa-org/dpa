//! Analyze ops: extractors (strings / URLs / emails / IPs / hashes)
//! and byte-level statistics (Shannon entropy / frequency distribution / IC).
//!
//! All ops here are whole-buffer transforms (extraction and statistics are
//! global by nature), so they register with `op!` and run on the in-memory path.

use std::collections::HashMap;

use regex::Regex;

use super::{ArgSpec, Op};
use crate::i18n;

pub fn ops() -> Vec<Op> {
    vec![
        op!(
            "dpa:extract:strings",
            "extract",
            "op.extract.strings.desc",
            &[
                ArgSpec {
                    name: "min",
                    required: false,
                    description: "op.extract.strings.arg.min",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "display_total",
                    required: false,
                    description: "op.extract.strings.arg.display_total",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "sort",
                    required: false,
                    description: "op.extract.strings.arg.sort",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "unique",
                    required: false,
                    description: "op.extract.strings.arg.unique",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            extract_strings
        ),
        op!(
            "dpa:extract:urls",
            "extract",
            "op.extract.urls.desc",
            &[
                ArgSpec {
                    name: "display_total",
                    required: false,
                    description: "op.extract.urls.arg.display_total",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "sort",
                    required: false,
                    description: "op.extract.urls.arg.sort",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "unique",
                    required: false,
                    description: "op.extract.urls.arg.unique",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            extract_urls
        ),
        op!(
            "dpa:extract:emails",
            "extract",
            "op.extract.emails.desc",
            &[
                ArgSpec {
                    name: "display_total",
                    required: false,
                    description: "op.extract.emails.arg.display_total",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "sort",
                    required: false,
                    description: "op.extract.emails.arg.sort",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "unique",
                    required: false,
                    description: "op.extract.emails.arg.unique",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            extract_emails
        ),
        op!(
            "dpa:extract:ips",
            "extract",
            "op.extract.ips.desc",
            &[
                ArgSpec {
                    name: "ipv6",
                    required: false,
                    description: "op.extract.ips.arg.ipv6",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "remove_local",
                    required: false,
                    description: "op.extract.ips.arg.remove_local",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "display_total",
                    required: false,
                    description: "op.extract.ips.arg.display_total",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "sort",
                    required: false,
                    description: "op.extract.ips.arg.sort",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "unique",
                    required: false,
                    description: "op.extract.ips.arg.unique",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            extract_ips
        ),
        op!(
            "dpa:extract:hashes",
            "extract",
            "op.extract.hashes.desc",
            &[
                ArgSpec {
                    name: "length",
                    required: false,
                    description: "op.extract.hashes.arg.length",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "display_total",
                    required: false,
                    description: "op.extract.hashes.arg.display_total",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "sort",
                    required: false,
                    description: "op.extract.hashes.arg.sort",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "unique",
                    required: false,
                    description: "op.extract.hashes.arg.unique",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            extract_hashes
        ),
        op!(
            "dpa:extract:domains",
            "extract",
            "op.extract.domains.desc",
            &[
                ArgSpec {
                    name: "display_total",
                    required: false,
                    description: "op.extract.domains.arg.display_total",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "sort",
                    required: false,
                    description: "op.extract.domains.arg.sort",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "unique",
                    required: false,
                    description: "op.extract.domains.arg.unique",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "underscore",
                    required: false,
                    description: "op.extract.domains.arg.underscore",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            extract_domains
        ),
        op!(
            "dpa:extract:mac",
            "extract",
            "op.extract.mac.desc",
            &[
                ArgSpec {
                    name: "display_total",
                    required: false,
                    description: "op.extract.mac.arg.display_total",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "sort",
                    required: false,
                    description: "op.extract.mac.arg.sort",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "unique",
                    required: false,
                    description: "op.extract.mac.arg.unique",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            extract_macs
        ),
        op!(
            "dpa:extract:dates",
            "extract",
            "op.extract.dates.desc",
            &[
                ArgSpec {
                    name: "display_total",
                    required: false,
                    description: "op.extract.dates.arg.display_total",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "sort",
                    required: false,
                    description: "op.extract.dates.arg.sort",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "unique",
                    required: false,
                    description: "op.extract.dates.arg.unique",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            extract_dates
        ),
        op!(
            "dpa:analyze:file:type",
            "analyze",
            "op.analyze.file.type.desc",
            &[],
            detect_file_type
        ),
        op!(
            "dpa:analyze:hash",
            "analyze",
            "op.analyze.hash.desc",
            &[],
            analyze_hash
        ),
        op!(
            "dpa:entropy",
            "analyze",
            "op.entropy.desc",
            &[ArgSpec {
                name: "scale",
                required: false,
                description: "op.entropy.arg.scale",
                format: crate::ops::ArgFormat::Utf8,
            },],
            entropy
        ),
        op!(
            "dpa:freq:distribution",
            "analyze",
            "op.freq.distribution.desc",
            &[
                ArgSpec {
                    name: "show_zero",
                    required: false,
                    description: "op.freq.distribution.arg.show_zero",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "show_ascii",
                    required: false,
                    description: "op.freq.distribution.arg.show_ascii",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            freq_distribution
        ),
        op!("dpa:ic", "analyze", "op.ic.desc", &[], coincidence_index),
        // distance / similarity statistics
        op!(
            "dpa:distance:hamming",
            "analyze",
            "op.distance.hamming.desc",
            &[
                ArgSpec {
                    name: "separator",
                    required: false,
                    description: "op.distance.hamming.arg.separator",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "mode",
                    required: false,
                    description: "op.distance.hamming.arg.mode",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            distance_hamming
        ),
        op!(
            "dpa:distance:levenshtein",
            "analyze",
            "op.distance.levenshtein.desc",
            &[
                ArgSpec {
                    name: "separator",
                    required: false,
                    description: "op.distance.levenshtein.arg.separator",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "algorithm",
                    required: false,
                    description: "op.distance.levenshtein.arg.algorithm",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "insert_cost",
                    required: false,
                    description: "op.distance.levenshtein.arg.insert_cost",
                    format: crate::ops::ArgFormat::Number,
                },
                ArgSpec {
                    name: "delete_cost",
                    required: false,
                    description: "op.distance.levenshtein.arg.delete_cost",
                    format: crate::ops::ArgFormat::Number,
                },
                ArgSpec {
                    name: "substitute_cost",
                    required: false,
                    description: "op.distance.levenshtein.arg.substitute_cost",
                    format: crate::ops::ArgFormat::Number,
                },
            ],
            distance_levenshtein
        ),
        op!(
            "dpa:similarity:jaccard",
            "analyze",
            "op.similarity.jaccard.desc",
            &[ArgSpec {
                name: "separator",
                required: false,
                description: "op.similarity.jaccard.arg.separator",
                format: crate::ops::ArgFormat::Utf8,
            },],
            similarity_jaccard
        ),
    ]
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Heuristic text score for brute-force ranking: printable ratio, whitespace
/// bonus, and English letter-frequency weighting. Higher is more "readable".
pub(crate) fn score_text(b: &[u8]) -> f64 {
    if b.is_empty() {
        return 0.0;
    }
    // English letter frequency (%) by byte index 0..25 (a-z).
    const FREQ: [f64; 26] = [
        8.17, 1.49, 2.78, 4.25, 12.70, 2.23, 2.02, 6.09, 6.97, 0.15, 0.77, 4.03, 2.41, 6.75, 7.51,
        1.93, 0.10, 5.99, 6.33, 9.06, 2.76, 0.98, 2.36, 0.15, 1.97, 0.07,
    ];
    let mut printable = 0usize;
    let mut spaces = 0usize;
    let mut freq_score = 0f64;
    for &x in b {
        if (0x20..=0x7e).contains(&x) || x == b'\n' || x == b'\r' || x == b'\t' {
            printable += 1;
        }
        if x == b' ' {
            spaces += 1;
        }
        if x.is_ascii_alphabetic() {
            let i = (x.to_ascii_lowercase() - b'a') as usize;
            freq_score += FREQ[i];
        }
    }
    let n = b.len() as f64;
    (printable as f64 / n) * 100.0 + (spaces as f64 / n) * 40.0 + (freq_score / n) * 10.0
}

pub(crate) fn parse_top(args: &HashMap<String, String>) -> anyhow::Result<usize> {
    let top = args
        .get("top")
        .map(|s| s.parse::<usize>())
        .transpose()
        .map_err(|e| anyhow::anyhow!("{}", i18n::tf("err.top_not_num", &[e.to_string().as_str()])))?
        .unwrap_or(5);
    if top == 0 || top > 256 {
        anyhow::bail!("{}", i18n::tf("err.top_range", &[top.to_string().as_str()]));
    }
    Ok(top)
}

fn parse_min(args: &HashMap<String, String>) -> anyhow::Result<usize> {
    let min = args
        .get("min")
        .map(|s| s.parse::<usize>())
        .transpose()
        .map_err(|e| anyhow::anyhow!("{}", i18n::tf("err.min_not_num", &[e.to_string().as_str()])))?
        .unwrap_or(4);
    if min == 0 || min > 100_000 {
        anyhow::bail!("{}", i18n::tf("err.min_range", &[min.to_string().as_str()]));
    }
    Ok(min)
}

fn parse_bool(v: Option<&String>) -> anyhow::Result<bool> {
    match v.map(|s| s.as_str()) {
        None | Some("false") | Some("0") => Ok(false),
        Some("true") | Some("1") => Ok(true),
        Some(other) => anyhow::bail!("{}", i18n::tf("err.bool_invalid", &[other])),
    }
}

/// Trim trailing punctuation that commonly glues onto extracted tokens.
fn trim_tail(tok: &str) -> &str {
    tok.trim_end_matches(['.', ',', ';', ':', '!', '?', ')', ']', '}'])
}

/// RFC1918 private ranges plus loopback and link-local (for remove_local).
fn is_local_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    let a: u16 = parts[0].parse().unwrap_or(0);
    let b: u16 = parts[1].parse().unwrap_or(0);
    a == 10
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || a == 127
        || (a == 169 && b == 254)
}

/// Hash length selector: 0 (default) means all lengths; otherwise 32/40/64/128.
fn parse_hash_length(args: &HashMap<String, String>) -> anyhow::Result<Option<usize>> {
    let Some(v) = args.get("length") else {
        return Ok(None);
    };
    let n = v.parse::<usize>().map_err(|e| {
        anyhow::anyhow!("{}", i18n::tf("err.min_not_num", &[e.to_string().as_str()]))
    })?;
    if !matches!(n, 0 | 32 | 40 | 64 | 128) {
        anyhow::bail!("{}", i18n::tf("err.min_range", &[v.as_str()]));
    }
    if n == 0 { Ok(None) } else { Ok(Some(n)) }
}

/// Shared post-processing for extractors: optional sort / unique / display total.
fn finish_hits(hits: Vec<String>, args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let sort = parse_bool(args.get("sort"))?;
    let unique = parse_bool(args.get("unique"))?;
    let total = parse_bool(args.get("display_total"))?;
    let mut lines = hits;
    if sort {
        lines.sort();
    }
    if unique {
        let mut seen = std::collections::HashSet::new();
        lines.retain(|l| seen.insert(l.clone()));
    }
    let mut out = Vec::new();
    if total {
        out.extend_from_slice(format!("Total found: {}\n", lines.len()).as_bytes());
    }
    for l in lines {
        out.extend_from_slice(l.as_bytes());
        out.push(b'\n');
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Extractors
// ---------------------------------------------------------------------------

fn extract_strings(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let min = parse_min(args)?;
    let mut hits = Vec::new();
    let mut cur = Vec::new();
    for &b in input {
        if (0x20..=0x7e).contains(&b) {
            cur.push(b);
        } else {
            if cur.len() >= min {
                hits.push(String::from_utf8_lossy(&cur).into_owned());
            }
            cur.clear();
        }
    }
    if cur.len() >= min {
        hits.push(String::from_utf8_lossy(&cur).into_owned());
    }
    finish_hits(hits, args)
}

fn extract_urls(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let re = Regex::new(r#"(?i)\b(?:[a-z][a-z0-9+.\-]*://|www\.)[^\s<>"']+"#).unwrap();
    let s = String::from_utf8_lossy(input);
    let mut hits = Vec::new();
    for m in re.find_iter(&s) {
        hits.push(trim_tail(m.as_str()).to_string());
    }
    finish_hits(hits, args)
}

fn extract_emails(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let re = Regex::new(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}").unwrap();
    let s = String::from_utf8_lossy(input);
    let mut hits = Vec::new();
    for m in re.find_iter(&s) {
        hits.push(trim_tail(m.as_str()).to_string());
    }
    finish_hits(hits, args)
}

fn is_valid_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| {
        !p.is_empty()
            && p.len() <= 3
            && p.bytes().all(|b| b.is_ascii_digit())
            && p.parse::<u16>().map(|v| v <= 255).unwrap_or(false)
    })
}

fn is_valid_ipv6(s: &str) -> bool {
    // Loose validation: at least two colons, no dots, segments are 1-4 hex digits
    // (empty segments allowed for `::` compression, but not leading/trailing single
    // colons beyond the `::` pattern).
    if s.is_empty() || s.contains('.') || s.matches(':').count() < 2 {
        return false;
    }
    s.split(':')
        .all(|seg| seg.is_empty() || (seg.len() <= 4 && seg.bytes().all(|b| b.is_ascii_hexdigit())))
}

fn extract_ips(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let want_v6 = parse_bool(args.get("ipv6"))?;
    let remove_local = parse_bool(args.get("remove_local"))?;
    let s = String::from_utf8_lossy(input);
    let mut hits = Vec::new();

    let v4 = Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap();
    for m in v4.find_iter(&s) {
        let t = m.as_str();
        if is_valid_ipv4(t) && !(remove_local && is_local_ipv4(t)) {
            hits.push(t.to_string());
        }
    }

    if want_v6 {
        let v6 = Regex::new(r"(?i)\b[0-9a-f:]{3,39}\b").unwrap();
        for m in v6.find_iter(&s) {
            let t = m.as_str();
            if is_valid_ipv6(t) {
                hits.push(t.to_string());
            }
        }
    }
    finish_hits(hits, args)
}

fn extract_hashes(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let len = parse_hash_length(args)?;
    let re = match len {
        Some(n) => Regex::new(&format!(r"\b[0-9a-fA-F]{{{}}}\b", n)).unwrap(),
        // Longest digest first so a SHA-512 blob is not chopped into MD5 pieces.
        None => Regex::new(
            r"\b[0-9a-fA-F]{128}\b|\b[0-9a-fA-F]{64}\b|\b[0-9a-fA-F]{40}\b|\b[0-9a-fA-F]{32}\b",
        )
        .unwrap(),
    };
    let s = String::from_utf8_lossy(input);
    let mut hits = Vec::new();
    for m in re.find_iter(&s) {
        hits.push(m.as_str().to_string());
    }
    finish_hits(hits, args)
}

/// A registered DNS label: alphanumeric plus hyphen, no leading/trailing hyphen.
fn is_valid_label_opt(s: &str, underscore: bool) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || (underscore && b == b'_'))
        && !s.starts_with('-')
        && !s.ends_with('-')
        && (underscore || (!s.starts_with('_') && !s.ends_with('_')))
}

fn extract_domains(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    // Candidate FQDN: labels separated by dots, TLD 2+ alpha; excludes bare IPv4
    // (all-numeric labels) and trailing punctuation. `underscore` mirrors
    // CyberChef's option for DMARC/DKIM records (_dmarc.example.com).
    let underscore = crate::ops::parse_bool(
        args.get("underscore")
            .map(String::as_str)
            .unwrap_or("false"),
    )?;
    let label = if underscore {
        r"[a-z0-9_-]+"
    } else {
        r"[a-z0-9-]+"
    };
    let re = Regex::new(&format!(r"(?i)\b(?:{label}\.)+[a-z]{{2,63}}\b")).unwrap();
    let s = String::from_utf8_lossy(input);
    let mut hits = Vec::new();
    for m in re.find_iter(&s) {
        // Reject substring matches chopped off a longer token (e.g.
        // "_dmarc.example.com" must not yield "example.com" when underscore
        // is disabled): the match must not start right after '.', '-' or '_'.
        if !underscore && m.start() > 0 && matches!(s.as_bytes()[m.start() - 1], b'.' | b'-' | b'_')
        {
            continue;
        }
        let tok = trim_tail(m.as_str());
        if tok.bytes().any(|b| b.is_ascii_alphabetic())
            && tok.split('.').all(|l| is_valid_label_opt(l, underscore))
        {
            hits.push(tok.to_string());
        }
    }
    finish_hits(hits, args)
}

fn extract_macs(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    // Colon / dash / Cisco dotted notations; hex digits only.
    let re = Regex::new(
        r"(?i)\b(?:[0-9a-f]{2}(?::[0-9a-f]{2}){5}|[0-9a-f]{2}(?:-[0-9a-f]{2}){5}|[0-9a-f]{4}(?:\.[0-9a-f]{4}){2})\b",
    )
    .unwrap();
    let s = String::from_utf8_lossy(input);
    let mut hits = Vec::new();
    for m in re.find_iter(&s) {
        let tok = trim_tail(m.as_str());
        // Reject all-zero / all-ff placeholder MACs (common in logs) and validate grouping.
        let compact: String = tok.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        let all_same = compact.bytes().all(|b| b == compact.as_bytes()[0]);
        if !all_same && compact.len() == 12 {
            hits.push(tok.to_string());
        }
    }
    finish_hits(hits, args)
}

fn is_valid_date(y: i32, m: u32, d: u32) -> bool {
    if !(1..=12).contains(&m) || d == 0 {
        return false;
    }
    let days = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) {
                29
            } else {
                28
            }
        }
        _ => return false,
    };
    d <= days
}

fn extract_dates(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    // ISO YYYY-MM-DD plus common D/M/Y, M/D/Y variants (4-digit years).
    let re =
        Regex::new(r"\b(?:\d{4}-\d{1,2}-\d{1,2}|\d{1,2}/\d{1,2}/\d{4}|\d{1,2}\.\d{1,2}\.\d{4})\b")
            .unwrap();
    let s = String::from_utf8_lossy(input);
    let mut hits = Vec::new();
    for m in re.find_iter(&s) {
        let tok = trim_tail(m.as_str());
        let parts: Vec<&str> = tok.split(['-', '/', '.']).collect();
        let (y, mo, d) = if parts[0].len() == 4 {
            (parts[0], parts[1], parts[2])
        } else {
            // D/M/Y -> parts are d, m, y; treat as day-first like the regex intent.
            (parts[2], parts[1], parts[0])
        };
        if let (Ok(yy), Ok(mm), Ok(dd)) = (y.parse::<i32>(), mo.parse::<u32>(), d.parse::<u32>()) {
            if is_valid_date(yy, mm, dd) {
                hits.push(tok.to_string());
            }
        }
    }
    finish_hits(hits, args)
}

// ---------------------------------------------------------------------------
// Detect file type (magic bytes)
// ---------------------------------------------------------------------------

/// Magic-byte matchers in priority order: (name, matcher closure).
/// Longer / more specific signatures come first so e.g. ZIP matches before OLE2.
#[allow(clippy::type_complexity)]
fn detect_file_type(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    if input.is_empty() {
        return Ok(b"Unknown (empty input)".to_vec());
    }
    let matches: &[(&str, fn(&[u8]) -> bool)] = &[
        ("ELF executable", |b| b.starts_with(b"\x7fELF")),
        ("PE executable (MZ)", |b| b.starts_with(b"MZ")),
        ("Mach-O 32-bit", |b| b.starts_with(b"\xfe\xed\xfa\xce")),
        ("Mach-O 64-bit", |b| b.starts_with(b"\xfe\xed\xfa\xcf")),
        ("Mach-O fat binary", |b| b.starts_with(b"\xca\xfe\xba\xbe")),
        ("Java class", |b| {
            b.starts_with(b"\xca\xfe\xba\xbe") && b.len() >= 8
        }),
        ("PNG image", |b| b.starts_with(b"\x89PNG\r\n\x1a\n")),
        ("JPEG image", |b| b.starts_with(b"\xff\xd8\xff")),
        ("GIF image", |b| {
            b.starts_with(b"GIF87a") || b.starts_with(b"GIF89a")
        }),
        ("BMP image", |b| b.starts_with(b"BM")),
        ("TIFF image (LE)", |b| b.starts_with(b"II*\x00")),
        ("TIFF image (BE)", |b| b.starts_with(b"MM\x00*")),
        ("WebP image", |b| {
            b.len() >= 12 && &b[0..4] == b"RIFF" && &b[8..12] == b"WEBP"
        }),
        ("WAV audio", |b| {
            b.len() >= 12 && &b[0..4] == b"RIFF" && &b[8..12] == b"WAVE"
        }),
        ("AVI video", |b| {
            b.len() >= 12 && &b[0..4] == b"RIFF" && &b[8..12] == b"AVI "
        }),
        ("MP3 audio", |b| {
            b.starts_with(b"ID3") || (b.len() >= 2 && (b[0] == 0xff && (b[1] & 0xe0) == 0xe0))
        }),
        ("Ogg container", |b| b.starts_with(b"OggS")),
        ("FLAC audio", |b| b.starts_with(b"fLaC")),
        ("MIDI", |b| b.starts_with(b"MThd")),
        ("PDF document", |b| b.starts_with(b"%PDF-")),
        ("ZIP archive", |b| {
            b.starts_with(b"PK\x03\x04")
                || b.starts_with(b"PK\x05\x06")
                || b.starts_with(b"PK\x07\x08")
        }),
        ("GZIP archive", |b| b.starts_with(b"\x1f\x8b")),
        ("BZIP2 archive", |b| b.starts_with(b"BZh")),
        ("XZ archive", |b| b.starts_with(b"\xfd7zXZ\x00")),
        ("Zstandard archive", |b| b.starts_with(b"\x28\xb5\x2f\xfd")),
        ("7-Zip archive", |b| b.starts_with(b"7z\xbc\xaf\x27\x1c")),
        ("RAR archive", |b| b.starts_with(b"Rar!\x1a\x07")),
        ("SQLite database", |b| b.starts_with(b"SQLite format 3\x00")),
        ("OLE2 compound document", |b| {
            b.starts_with(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")
        }),
        ("Android DEX", |b| b.starts_with(b"dex\n") && b.len() >= 8),
        ("WebAssembly binary", |b| b.starts_with(b"\x00asm")),
        ("UTF-8 BOM", |b| b.starts_with(b"\xef\xbb\xbf")),
        ("UTF-16 LE BOM", |b| b.starts_with(b"\xff\xfe")),
        ("UTF-16 BE BOM", |b| b.starts_with(b"\xfe\xff")),
    ];
    let mut out = Vec::new();
    for (name, f) in matches {
        if f(input) {
            out.extend_from_slice(name.as_bytes());
            out.push(b'\n');
        }
    }
    if out.is_empty() {
        out.extend_from_slice(b"Unknown file type");
        out.push(b'\n');
    }
    Ok(out)
}

/// Candidate hash algorithms grouped by digest bit-length (hex string length).
fn analyze_hash(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let s = String::from_utf8_lossy(input);
    let trimmed = s.trim();
    // Accept optional 0x prefix and tolerate whitespace.
    let hex = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    let clean: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.is_empty() {
        anyhow::bail!("{}", crate::i18n::tf("err.analyze_hash_empty", &[]));
    }
    let n = clean.len();
    let candidates: &[&str] = match n {
        8 => &["CRC-32", "Adler-32", "FNV-1a 32"],
        16 => &["MD5", "MD4", "CRC-64"],
        32 => &["MD5", "MD4", "RIPEMD-128"],
        40 => &["SHA-1", "RIPEMD-160"],
        48 => &["RIPEMD-192"],
        56 => &["SHA-224", "SHA3-224", "BLAKE2s-224"],
        64 => &[
            "SHA-256",
            "SHA3-256",
            "BLAKE2s-256",
            "BLAKE2b-256",
            "SM3",
            "Keccak-256",
        ],
        96 => &["SHA-384", "SHA3-384", "BLAKE2b-384"],
        128 => &[
            "SHA-512",
            "SHA3-512",
            "BLAKE2b-512",
            "Keccak-512",
            "Whirlpool",
        ],
        _ => &[],
    };
    // Only hex digest characters are valid; otherwise say so.
    let all_hex = clean.bytes().all(|b| b.is_ascii_hexdigit());
    let mut out = String::new();
    out.push_str(&format!("Length: {} hex characters ({} bytes)\n", n, n / 2));
    if candidates.is_empty() {
        if !all_hex {
            out.push_str("Not a hexadecimal digest; provide a hex-encoded hash.\n");
        } else {
            out.push_str(&format!(
                "No known hash algorithm matches {} hex chars.\n",
                n
            ));
        }
    } else {
        out.push_str("Possible algorithms: ");
        out.push_str(&candidates.join(", "));
        out.push('\n');
    }
    Ok(out.into_bytes())
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

fn entropy(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    if input.is_empty() {
        return Ok(b"0".to_vec());
    }
    let scale = args.get("scale").map(|s| s.as_str()).unwrap_or("shannon");
    let mut freq = [0u64; 256];
    for &b in input {
        freq[b as usize] += 1;
    }
    let n = input.len() as f64;
    let mut h = 0.0f64;
    for &c in freq.iter() {
        if c > 0 {
            let p = c as f64 / n;
            h -= p * p.log2();
        }
    }
    let (value, unit) = match scale {
        "base10" => (h / std::f64::consts::LOG2_10, "decimal digits per byte"),
        "base256" => (h / 8.0, "bytes per byte"),
        // "shannon" (default) or any unknown value: bits per byte.
        _ => (h, "bits per byte"),
    };
    Ok(format!("{:.6} {}", value, unit).into_bytes())
}

fn freq_distribution(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let show_zero = match args.get("show_zero") {
        Some(s) => crate::ops::parse_bool(s)?,
        None => false,
    };
    let show_ascii = match args.get("show_ascii") {
        Some(s) => crate::ops::parse_bool(s)?,
        None => true,
    };
    let mut freq = [0u64; 256];
    for &b in input {
        freq[b as usize] += 1;
    }
    let n = input.len() as f64;
    let mut items: Vec<(u8, u64)> = freq
        .iter()
        .enumerate()
        .filter(|(_, c)| show_zero || **c > 0)
        .map(|(i, c)| (i as u8, *c))
        .collect();
    items.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let mut out = String::new();
    for (b, c) in items {
        let mut line = format!("0x{:02x}  {:>6}  {:>6.2}%", b, c, c as f64 / n * 100.0);
        if show_ascii {
            let ch = match b {
                0x20 => "sp".to_string(),
                0x21..=0x7e => (b as char).to_string(),
                _ => "..".to_string(),
            };
            line = format!(
                "0x{:02x}  {:<3}  {:>6}  {:>6.2}%",
                b,
                ch,
                c,
                c as f64 / n * 100.0
            );
        }
        out.push_str(&line);
        out.push('\n');
    }
    Ok(out.into_bytes())
}

fn coincidence_index(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let n = input.len();
    if n < 2 {
        return Ok(b"0.000000".to_vec());
    }
    let mut freq = [0u64; 256];
    for &b in input {
        freq[b as usize] += 1;
    }
    let num: u64 = freq.iter().map(|&c| c * c.saturating_sub(1)).sum();
    let den = (n as u64) * (n as u64 - 1);
    Ok(format!("{:.6}", num as f64 / den as f64).into_bytes())
}

// ---------------------------------------------------------------------------
// distance / similarity statistics
// ---------------------------------------------------------------------------

fn split_two(input: &[u8], sep: &str) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let s = String::from_utf8_lossy(input);
    let parts: Vec<&str> = s.split(sep).collect();
    if parts.len() != 2 {
        anyhow::bail!(
            "expected exactly two parts separated by {:?}, got {}",
            sep,
            parts.len()
        );
    }
    Ok((parts[0].as_bytes().to_vec(), parts[1].as_bytes().to_vec()))
}

fn distance_hamming(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let sep = args.get("separator").map(|s| s.as_str()).unwrap_or("\n\n");
    let mode = args.get("mode").map(|s| s.as_str()).unwrap_or("bytes");
    let (a, b) = split_two(input, sep)?;
    if a.len() != b.len() {
        anyhow::bail!(
            "Hamming distance requires equal lengths ({} vs {})",
            a.len(),
            b.len()
        );
    }
    let d = match mode {
        "bits" => a
            .iter()
            .zip(b.iter())
            .map(|(x, y)| (x ^ y).count_ones() as usize)
            .sum(),
        // "bytes" (default) or any unknown value: byte-wise comparison.
        _ => a.iter().zip(b.iter()).filter(|(x, y)| x != y).count(),
    };
    Ok(d.to_string().into_bytes())
}

fn distance_levenshtein(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let sep = args.get("separator").map(|s| s.as_str()).unwrap_or("\n\n");
    let (a, b) = split_two(input, sep)?;
    let a: Vec<char> = String::from_utf8_lossy(&a).chars().collect();
    let b: Vec<char> = String::from_utf8_lossy(&b).chars().collect();
    let algorithm = args
        .get("algorithm")
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_else(|| "levenshtein".to_string());
    match algorithm.as_str() {
        "levenshtein" => {
            let (ins, del, sub) = parse_edit_costs(args)?;
            Ok(levenshtein_dp(&a, &b, ins, del, sub)
                .to_string()
                .into_bytes())
        }
        "damerau" => {
            let (ins, del, sub) = parse_edit_costs(args)?;
            Ok(damerau_dp(&a, &b, ins, del, sub).to_string().into_bytes())
        }
        "lcs" => Ok(lcs_distance(&a, &b).to_string().into_bytes()),
        other => anyhow::bail!(
            "{}",
            i18n::tf("err.distance.levenshtein.algorithm_invalid", &[other])
        ),
    }
}

/// Parse the optional insert/delete/substitute costs (non-negative integers,
/// default 1). LCS mode ignores costs because its distance is structural.
fn parse_edit_costs(args: &HashMap<String, String>) -> anyhow::Result<(u64, u64, u64)> {
    let one = |k: &str| -> anyhow::Result<u64> {
        match args.get(k) {
            None => Ok(1),
            Some(v) => v.trim().parse::<u64>().map_err(|_| {
                anyhow::anyhow!(
                    "{}",
                    i18n::tf("err.distance.levenshtein.cost_invalid", &[k, v])
                )
            }),
        }
    };
    Ok((
        one("insert_cost")?,
        one("delete_cost")?,
        one("substitute_cost")?,
    ))
}

/// Weighted Levenshtein DP over Unicode scalar values (chars).
fn levenshtein_dp(a: &[char], b: &[char], ins: u64, del: u64, sub: u64) -> u64 {
    let (n, m) = (a.len(), b.len());
    let mut prev: Vec<u64> = (0..=m as u64).map(|j| j * ins).collect();
    for i in 1..=n {
        let mut cur = vec![0u64; m + 1];
        cur[0] = i as u64 * del;
        for j in 1..=m {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { sub };
            cur[j] = (prev[j] + del)
                .min(cur[j - 1] + ins)
                .min(prev[j - 1] + cost);
        }
        prev = cur;
    }
    prev[m]
}

/// Damerau-Levenshtein DP with adjacent transposition (transposition cost 1).
/// Insertion / deletion / substitution costs are configurable like
/// Levenshtein; transposition is a fixed single operation.
fn damerau_dp(a: &[char], b: &[char], ins: u64, del: u64, sub: u64) -> u64 {
    let (n, m) = (a.len(), b.len());
    let mut prev2: Vec<u64> = (0..=m as u64).map(|j| j * ins).collect();
    let mut prev1: Vec<u64> = (0..=m as u64).map(|j| j * ins).collect();
    for i in 1..=n {
        let mut cur = vec![0u64; m + 1];
        cur[0] = i as u64 * del;
        for j in 1..=m {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { sub };
            let mut v = (prev1[j] + del)
                .min(cur[j - 1] + ins)
                .min(prev1[j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                v = v.min(prev2[j - 2] + 1);
            }
            cur[j] = v;
        }
        prev2 = prev1;
        prev1 = cur;
    }
    prev1[m]
}

/// Longest common subsequence distance: n + m - 2 * LCS(a, b).
fn lcs_distance(a: &[char], b: &[char]) -> u64 {
    let (n, m) = (a.len(), b.len());
    let mut prev = vec![0usize; m + 1];
    for i in 1..=n {
        let mut cur = vec![0usize; m + 1];
        for j in 1..=m {
            cur[j] = if a[i - 1] == b[j - 1] {
                prev[j - 1] + 1
            } else {
                prev[j].max(cur[j - 1])
            };
        }
        prev = cur;
    }
    (n + m - 2 * prev[m]) as u64
}

fn similarity_jaccard(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let sep = args.get("separator").map(|s| s.as_str()).unwrap_or("\n\n");
    let (a, b) = split_two(input, sep)?;
    let sa: std::collections::BTreeSet<String> = String::from_utf8_lossy(&a)
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    let sb: std::collections::BTreeSet<String> = String::from_utf8_lossy(&b)
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    if sa.is_empty() && sb.is_empty() {
        return Ok(b"1.000000".to_vec());
    }
    let inter = sa.intersection(&sb).count();
    let union = sa.union(&sb).count();
    Ok(format!("{:.6}", inter as f64 / union as f64).into_bytes())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::type_complexity)]
    use super::*;

    fn run(op: &str, input: &[u8], args: &[(&str, &str)]) -> Vec<u8> {
        let mut m = HashMap::new();
        for (k, v) in args {
            m.insert(k.to_string(), v.to_string());
        }
        let o = crate::ops::find_op(op).expect("op exists");
        (o.run)(input, &m).expect("run ok")
    }

    fn text(v: &[u8]) -> String {
        String::from_utf8_lossy(v).to_string()
    }

    #[test]
    fn strings_basic() {
        let input = b"abc\x00defgh\x00ijklmno\xffpq";
        let out = text(&run("dpa:extract:strings", input, &[]));
        assert_eq!(out, "defgh\nijklmno\n");
    }

    #[test]
    fn strings_min_length() {
        let out = text(&run("dpa:extract:strings", b"ab cd efg", &[("min", "3")]));
        assert_eq!(out, "ab cd efg\n");
        let out = text(&run("dpa:extract:strings", b"ab cd efg", &[("min", "10")]));
        assert_eq!(out, "");
    }

    #[test]
    fn urls_extracted() {
        let input = "visit https://example.com/a?b=1 now, or www.test.org/x and http://xn--pssq.no"
            .as_bytes();
        let out = text(&run("dpa:extract:urls", input, &[]));
        assert!(out.contains("https://example.com/a?b=1"), "got: {}", out);
        assert!(out.contains("www.test.org/x"), "got: {}", out);
    }

    #[test]
    fn emails_extracted() {
        let input = b"contact a.b+c@mail.example.org or bad@@x";
        let out = text(&run("dpa:extract:emails", input, &[]));
        assert_eq!(out, "a.b+c@mail.example.org\n");
    }

    #[test]
    fn ipv4_extracted_and_validated() {
        let input = b"ip 192.168.1.1 and 999.1.2.3 and 10.0.0.1.";
        let out = text(&run("dpa:extract:ips", input, &[]));
        assert!(out.contains("192.168.1.1"));
        assert!(out.contains("10.0.0.1"));
        assert!(!out.contains("999.1.2.3"), "got: {}", out);
    }

    #[test]
    fn ipv6_extracted_when_requested() {
        let input = b"v6 2001:db8::1 and 2001:0db8:85a3:0000:0000:8a2e:0370:7334";
        let out = run("dpa:extract:ips", input, &[("ipv6", "true")]);
        let out = text(&out);
        assert!(out.contains("2001:db8::1"), "got: {}", out);
        assert!(
            out.contains("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
            "got: {}",
            out
        );
    }

    #[test]
    fn hashes_extracted_longest_first() {
        let sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let md5 = "d41d8cd98f00b204e9800998ecf8427e";
        let input = format!("{} {}", sha256, md5);
        let out = text(&run("dpa:extract:hashes", input.as_bytes(), &[]));
        assert!(out.contains(sha256));
        assert!(out.contains(md5));
        assert_eq!(out.lines().count(), 2);
    }

    #[test]
    fn entropy_known() {
        // 4 x 'A': p=1 => entropy 0
        assert_eq!(
            text(&run("dpa:entropy", b"AAAA", &[])),
            "0.000000 bits per byte"
        );
        // two distinct bytes, 50/50 => 1 bit
        assert_eq!(
            text(&run("dpa:entropy", b"ABAB", &[])),
            "1.000000 bits per byte"
        );
        // base10 scale: 1 bit == log10(2) decimal digits per byte
        assert_eq!(
            text(&run("dpa:entropy", b"ABAB", &[("scale", "base10")])),
            "0.301030 decimal digits per byte"
        );
        // base256 scale: 1 bit == 0.125 bytes per byte
        assert_eq!(
            text(&run("dpa:entropy", b"ABAB", &[("scale", "base256")])),
            "0.125000 bytes per byte"
        );
    }

    #[test]
    fn freq_distribution_options() {
        // show_zero=false (default): only present bytes
        let out = text(&run("dpa:freq:distribution", b"aabbb", &[]));
        assert!(out.starts_with("0x62"), "got: {}", out);
        assert!(!out.contains("0x00"), "got: {}", out);
        // show_zero=true: zero-count bytes appear (0x00 is absent from input)
        let out = text(&run(
            "dpa:freq:distribution",
            b"aabbb",
            &[("show_zero", "true")],
        ));
        assert!(out.contains("0x00"), "got: {}", out);
        // show_ascii=false: no character column (line has no printable-char field)
        let out = text(&run(
            "dpa:freq:distribution",
            b"aabbb",
            &[("show_ascii", "false")],
        ));
        assert!(out.lines().all(|l| !l.contains("  b  ")), "got: {}", out);
        assert!(out.contains("0x62"), "got: {}", out);
    }

    #[test]
    fn freq_distribution_sorted() {
        let out = text(&run("dpa:freq:distribution", b"aabbb", &[]));
        assert!(out.starts_with("0x62"), "got: {}", out);
        assert!(out.contains("40.00%"), "got: {}", out);
    }

    #[test]
    fn ic_known() {
        // single byte class: IC ~ 1.0 (n=4 => 4*3/(4*3))
        assert_eq!(text(&run("dpa:ic", b"AAAA", &[])), "1.000000");
        // uniform 2 classes n=4 => IC = (2*1 + 2*1)/(4*3) = 0.333333
        assert_eq!(text(&run("dpa:ic", b"AABB", &[])), "0.333333");
    }

    #[test]
    fn domains_extracted() {
        let input = b"c2 example.com and sub.test.org and 192.168.1.1 and bad-host..x";
        let out = text(&run("dpa:extract:domains", input, &[]));
        assert!(out.contains("example.com"), "got: {}", out);
        assert!(out.contains("sub.test.org"), "got: {}", out);
        assert!(!out.contains("192.168.1.1"), "got: {}", out);
        assert!(!out.contains("bad-host"), "got: {}", out);
    }

    #[test]
    fn macs_extracted_three_notations() {
        let input = b"a:b 00:1A:2B:3C:4D:5E dash 66-77-88-99-AA-BB cisco 0011.2233.4455 bad 00:00:00:00:00:00";
        let out = text(&run("dpa:extract:mac", input, &[]));
        assert!(out.contains("00:1A:2B:3C:4D:5E"), "got: {}", out);
        assert!(out.contains("66-77-88-99-AA-BB"), "got: {}", out);
        assert!(out.contains("0011.2233.4455"), "got: {}", out);
        assert!(!out.contains("00:00:00:00:00:00"), "got: {}", out);
    }

    #[test]
    fn dates_extracted_and_validated() {
        let input =
            b"iso 2024-02-29 ok, bad 2023-02-29, slash 31/12/2024, dot 01.01.2025, junk 99/99/9999";
        let out = text(&run("dpa:extract:dates", input, &[]));
        assert!(out.contains("2024-02-29"), "got: {}", out);
        assert!(out.contains("31/12/2024"), "got: {}", out);
        assert!(out.contains("01.01.2025"), "got: {}", out);
        assert!(!out.contains("2023-02-29"), "got: {}", out);
        assert!(!out.contains("99/99/9999"), "got: {}", out);
    }

    #[test]
    fn file_type_magic_bytes() {
        let png: &[u8] = b"\x89PNG\r\n\x1a\nrest";
        let out = text(&run("dpa:analyze:file:type", png, &[]));
        assert!(out.contains("PNG image"), "got: {}", out);
        let pdf = b"%PDF-1.7 ...";
        let out = text(&run("dpa:analyze:file:type", pdf, &[]));
        assert!(out.contains("PDF document"), "got: {}", out);
        let zip: &[u8] = b"PK\x03\x04...";
        let out = text(&run("dpa:analyze:file:type", zip, &[]));
        assert!(out.contains("ZIP archive"), "got: {}", out);
        let unknown = b"just some text";
        let out = text(&run("dpa:analyze:file:type", unknown, &[]));
        assert!(out.contains("Unknown file type"), "got: {}", out);
    }

    #[test]
    fn hash_analysis_by_length() {
        let md5 = text(&run(
            "dpa:analyze:hash",
            b"d41d8cd98f00b204e9800998ecf8427e",
            &[],
        ));
        assert!(md5.contains("32 hex characters"), "got: {}", md5);
        assert!(md5.contains("MD5"), "got: {}", md5);
        let sha256 = text(&run(
            "dpa:analyze:hash",
            b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            &[],
        ));
        assert!(sha256.contains("64 hex characters"), "got: {}", sha256);
        assert!(sha256.contains("SHA-256"), "got: {}", sha256);
        let weird = text(&run("dpa:analyze:hash", b"zzz", &[]));
        assert!(weird.contains("Not a hexadecimal digest"), "got: {}", weird);
        let short_hex = text(&run("dpa:analyze:hash", b"abc", &[]));
        assert!(short_hex.contains("No known hash"), "got: {}", short_hex);
    }

    #[test]
    fn extract_display_total_sort_unique() {
        // urls: sort + unique + total
        let input = b"b.example.com a.example.com b.example.com";
        let out = text(&run(
            "dpa:extract:domains",
            input,
            &[
                ("display_total", "true"),
                ("sort", "true"),
                ("unique", "true"),
            ],
        ));
        assert_eq!(out, "Total found: 2\na.example.com\nb.example.com\n");
        // default: no total, order preserved
        let out = text(&run("dpa:extract:domains", input, &[]));
        assert_eq!(out, "b.example.com\na.example.com\nb.example.com\n");
        // underscore option captures DMARC/DKIM labels.
        let out = text(&run(
            "dpa:extract:domains",
            b"_dmarc.example.com mail._domainkey.example.net",
            &[("underscore", "true")],
        ));
        assert_eq!(out, "_dmarc.example.com\nmail._domainkey.example.net\n");
        let out = text(&run("dpa:extract:domains", b"_dmarc.example.com", &[]));
        assert_eq!(out, "");
    }

    #[test]
    fn extract_strings_min_and_total() {
        let input = b"ab\x00cde\x00fg\x00hijkl";
        let out = text(&run(
            "dpa:extract:strings",
            input,
            &[("min", "3"), ("display_total", "true")],
        ));
        assert_eq!(out, "Total found: 2\ncde\nhijkl\n");
    }

    #[test]
    fn ips_remove_local() {
        let input = b"8.8.8.8 192.168.1.1 10.0.0.5 127.0.0.1 172.16.0.1 169.254.1.1";
        let out = text(&run("dpa:extract:ips", input, &[("remove_local", "true")]));
        assert_eq!(out, "8.8.8.8\n");
        let out = text(&run("dpa:extract:ips", input, &[]));
        assert!(out.contains("8.8.8.8"), "got: {}", out);
        assert!(out.contains("192.168.1.1"), "got: {}", out);
        assert!(out.contains("169.254.1.1"), "got: {}", out);
    }

    #[test]
    fn hashes_length_filter() {
        let sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let md5 = "d41d8cd98f00b204e9800998ecf8427e";
        let input = format!("{} {}", sha256, md5);
        // only MD5-length digests
        let out = text(&run(
            "dpa:extract:hashes",
            input.as_bytes(),
            &[("length", "32")],
        ));
        assert!(out.contains(md5), "got: {}", out);
        assert!(!out.contains(sha256), "got: {}", out);
        // invalid length rejected
        assert!(
            (crate::ops::find_op("dpa:extract:hashes").unwrap().run)(
                input.as_bytes(),
                &HashMap::from([("length".into(), "33".into())])
            )
            .is_err()
        );
    }

    #[test]
    fn emails_sort_unique_total() {
        let input = b"b@x.com a@y.com b@x.com";
        let out = text(&run(
            "dpa:extract:emails",
            input,
            &[
                ("display_total", "true"),
                ("sort", "true"),
                ("unique", "true"),
            ],
        ));
        assert_eq!(out, "Total found: 2\na@y.com\nb@x.com\n");
    }
}

#[cfg(test)]
mod tests_p1_4 {
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
    fn hamming_distance_known() {
        // "karolin" vs "kathrin": positions differ: a/e? karolin k-a-r-o-l-i-n; kathrin k-a-t-h-r-i-n; differ at r? compute: r vs t, o vs h, l vs r -> 3
        assert_eq!(run(distance_hamming, "karolin\n\nkathrin", &[]), "3");
        // equal-length mismatch error
        assert!(distance_hamming(b"abc\n\nab", &HashMap::new()).is_err());
        // bits mode: 'k' (0x6b) vs 'k' = 0; 'a'(0x61) vs 'a' = 0; 'r'(0x72) vs 't'(0x74) = 2 bits
        // 'o'(0x6f) vs 'h'(0x68) = 3; 'l'(0x6c) vs 'r'(0x72) = 4; 'i'(0x69) vs 'i' = 0; 'n' vs 'n' = 0
        // total = 0+0+2+3+4+0+0 = 9
        assert_eq!(
            run(distance_hamming, "karolin\n\nkathrin", &[("mode", "bits")]),
            "9"
        );
    }

    #[test]
    fn levenshtein_distance_known() {
        // "kitten" -> "sitting": 3
        assert_eq!(run(distance_levenshtein, "kitten\n\nsitting", &[]), "3");
        // "flaw" -> "lawn": 2
        assert_eq!(run(distance_levenshtein, "flaw\n\nlawn", &[]), "2");
    }

    #[test]
    fn levenshtein_algorithms_and_costs() {
        // default remains plain Levenshtein
        assert_eq!(run(distance_levenshtein, "kitten\n\nsitting", &[]), "3");
        // adjacent transposition: Damerau cost 1, plain Levenshtein cost 2
        assert_eq!(
            run(
                distance_levenshtein,
                "ab\n\nba",
                &[("algorithm", "damerau")]
            ),
            "1"
        );
        assert_eq!(
            run(
                distance_levenshtein,
                "ab\n\nba",
                &[("algorithm", "levenshtein")]
            ),
            "2"
        );
        // LCS: AGGTAB / GXTXAYB -> LCS "GTAB" len 4 -> 6 + 7 - 8 = 5
        assert_eq!(
            run(
                distance_levenshtein,
                "AGGTAB\n\nGXTXAYB",
                &[("algorithm", "lcs")]
            ),
            "5"
        );
        // weighted insert cost: kitten -> sitting = 1 sub + 1 sub + 1 ins = 3,
        // with insert_cost=2 -> 1 + 1 + 2 = 4
        assert_eq!(
            run(
                distance_levenshtein,
                "kitten\n\nsitting",
                &[("insert_cost", "2")]
            ),
            "4"
        );
        // invalid algorithm and invalid cost are rejected
        let mut bad_algo = HashMap::new();
        bad_algo.insert("algorithm".to_string(), "xx".to_string());
        assert!(distance_levenshtein(b"a\n\nb", &bad_algo).is_err());
        let mut bad_cost = HashMap::new();
        bad_cost.insert("insert_cost".to_string(), "x".to_string());
        assert!(distance_levenshtein(b"a\n\nb", &bad_cost).is_err());
    }

    #[test]
    fn jaccard_similarity() {
        // A={a,b,c} B={b,c,d}: inter 2, union 4 -> 0.5
        assert_eq!(
            run(similarity_jaccard, "a\nb\nc\n\nb\nc\nd\n", &[]),
            "0.500000"
        );
        // identical sets -> 1
        assert_eq!(run(similarity_jaccard, "x\ny\n\nx\ny\n", &[]), "1.000000");
        // disjoint -> 0
        assert_eq!(run(similarity_jaccard, "a\n\nb\n", &[]), "0.000000");
    }

    #[test]
    fn two_part_separator_validation() {
        assert!(distance_hamming(b"a\n\nb\n\nc", &HashMap::new()).is_err());
    }
}
