//! Regex ops: match / replace.

use std::collections::HashMap;

use regex::Regex;

use super::{ArgSpec, Op};
use crate::i18n;

pub fn ops() -> Vec<Op> {
    vec![
        op!(
            "dpa:regex:match",
            "transform",
            "op.regex.match.desc",
            &[
                ArgSpec {
                    name: "pattern",
                    required: false,
                    description: "op.regex.match.arg.pattern",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "builtin",
                    required: false,
                    description: "op.regex.match.arg.builtin",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            regex_match
        ),
        op!(
            "dpa:regex:replace",
            "transform",
            "op.regex.replace.desc",
            &[
                ArgSpec {
                    name: "pattern",
                    required: true,
                    description: "op.regex.replace.arg.pattern",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "replacement",
                    required: true,
                    description: "op.regex.replace.arg.replacement",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "builtin",
                    required: false,
                    description: "op.regex.replace.arg.builtin",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            regex_replace
        ),
    ]
}

/// Built-in regex templates mirroring CyberChef's "Regular expression"
/// preset selector. When `pattern` is given it always wins; otherwise
/// `builtin` picks one of these templates.
fn builtin_pattern(name: &str) -> Option<&'static str> {
    let t: &[(&str, &str)] = &[
        (
            "ipv4",
            r"\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
        ),
        (
            "ipv6",
            r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:|\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{0,4}\b",
        ),
        ("email", r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
        ("url", r"\b(?:https?|ftp)://[\w\-./?%&=#~+]+"),
        (
            "domain",
            r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b",
        ),
        (
            "windows_path",
            r#"(?:[A-Za-z]:[\\/][^\s<>"|?*]+|\\\\[^\\\s<>"|?*]+\\[^\s<>"|?*]+)"#,
        ),
        ("unix_path", r"(?:/[^\s/]+)+"),
        ("mac", r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"),
        (
            "uuid",
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
        ),
        (
            "date_ymd",
            r"\b(?:19|20)\d{2}[-/](?:0[1-9]|1[0-2])[-/](?:0[1-9]|[12]\d|3[01])\b",
        ),
        (
            "date_dmy",
            r"\b(?:0[1-9]|[12]\d|3[01])[-/](?:0[1-9]|1[0-2])[-/](?:19|20)\d{2}\b",
        ),
        (
            "date_mdy",
            r"\b(?:0[1-9]|1[0-2])[-/](?:0[1-9]|[12]\d|3[01])[-/](?:19|20)\d{2}\b",
        ),
        ("strings", r"[\x20-\x7E]{4,}"),
    ];
    t.iter().find(|(n, _)| *n == name).map(|(_, p)| *p)
}

fn resolve_pattern(
    args: &HashMap<String, String>,
) -> anyhow::Result<std::borrow::Cow<'static, str>> {
    if let Some(p) = args.get("pattern")
        && !p.trim().is_empty()
    {
        return Ok(std::borrow::Cow::Owned(p.clone()));
    }
    if let Some(b) = args.get("builtin") {
        if let Some(t) = builtin_pattern(b.trim()) {
            return Ok(std::borrow::Cow::Borrowed(t));
        }
        return Err(anyhow::anyhow!(
            "{}",
            i18n::tf("err.bad_builtin_regex", &[b.trim()])
        ));
    }
    Err(anyhow::anyhow!("{}", i18n::t("err.missing_pattern")))
}

fn regex_match(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let pattern = resolve_pattern(args)?;
    let re = Regex::new(&pattern).map_err(|e| {
        anyhow::anyhow!(
            "{}",
            i18n::tf("err.regex_compile", &[e.to_string().as_str()])
        )
    })?;
    let text = std::str::from_utf8(input)
        .map_err(|_| anyhow::anyhow!("{}", i18n::t("err.not_utf8_match")))?;
    let mut out = Vec::new();
    for m in re.find_iter(text) {
        out.extend_from_slice(m.as_str().as_bytes());
        out.push(b'\n');
    }
    Ok(out)
}

fn regex_replace(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let pattern = resolve_pattern(args)?;
    let replacement = args
        .get("replacement")
        .ok_or_else(|| anyhow::anyhow!("{}", i18n::t("err.missing_replacement")))?;
    let re = Regex::new(&pattern).map_err(|e| {
        anyhow::anyhow!(
            "{}",
            i18n::tf("err.regex_compile", &[e.to_string().as_str()])
        )
    })?;
    let text = std::str::from_utf8(input)
        .map_err(|_| anyhow::anyhow!("{}", i18n::t("err.not_utf8_replace")))?;
    Ok(re
        .replace_all(text, replacement.as_str())
        .as_bytes()
        .to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn regex_match_extracts() {
        let a = args(&[("pattern", r"https?://\S+")]);
        let out = regex_match(b"visit https://example.com/a and http://x.io", &a).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "https://example.com/a\nhttp://x.io\n"
        );
    }

    #[test]
    fn regex_replace_groups() {
        let a = args(&[
            ("pattern", r"(\d{4})-(\d{2})-(\d{2})"),
            ("replacement", "$3/$2/$1"),
        ]);
        let out = regex_replace(b"date: 2026-10-07 ok", &a).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "date: 07/10/2026 ok");
    }

    #[test]
    fn regex_rejects_invalid_pattern() {
        let a = args(&[("pattern", "(")]);
        assert!(regex_match(b"x", &a).is_err());
    }

    #[test]
    fn regex_match_no_hit_is_empty() {
        let a = args(&[("pattern", r"\d+")]);
        assert_eq!(regex_match(b"abc def", &a).unwrap(), b"");
        assert_eq!(regex_match(b"", &a).unwrap(), b"");
    }

    #[test]
    fn regex_match_missing_pattern_rejected() {
        assert!(regex_match(b"x", &HashMap::new()).is_err());
        let a = args(&[("replacement", "y")]);
        assert!(regex_match(b"x", &a).is_err());
    }

    #[test]
    fn regex_replace_no_hit_passthrough() {
        let a = args(&[("pattern", r"\d+"), ("replacement", "#")]);
        assert_eq!(regex_replace(b"abc def", &a).unwrap(), b"abc def");
        assert_eq!(regex_replace(b"", &a).unwrap(), b"");
    }

    #[test]
    fn regex_replace_all_hits() {
        let a = args(&[("pattern", r"cat"), ("replacement", "dog")]);
        assert_eq!(
            regex_replace(b"cat and cat, cat!", &a).unwrap(),
            b"dog and dog, dog!"
        );
        // Adjacent hits are each replaced independently.
        let a2 = args(&[("pattern", r"a+"), ("replacement", "x")]);
        assert_eq!(regex_replace(b"aaa aaa", &a2).unwrap(), b"x x");
    }

    #[test]
    fn regex_missing_required_args() {
        assert!(regex_replace(b"x", &HashMap::new()).is_err());
        assert!(regex_replace(b"x", &args(&[("pattern", r"\d+")])).is_err());
        assert!(regex_replace(b"x", &args(&[("replacement", "y")])).is_err());
    }

    #[test]
    fn regex_rejects_non_utf8_input() {
        let a = args(&[("pattern", r".")]);
        assert!(regex_match(&[0xff, 0xfe], &a).is_err());
        let r = args(&[("pattern", r"."), ("replacement", "x")]);
        assert!(regex_replace(&[0xff, 0xfe], &r).is_err());
    }

    #[test]
    fn regex_multiline_match() {
        // Without (?m) the anchors match the whole text only; with (?m) they
        // match per line. find_iter spans the whole text including newlines.
        let a = args(&[("pattern", r"^line \d+$")]);
        assert_eq!(regex_match(b"line 1\nskip\nline 2", &a).unwrap(), b"");
        let m = args(&[("pattern", r"(?m)^line \d+$")]);
        let out = regex_match(b"line 1\nskip\nline 2", &m).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "line 1\nline 2\n");
    }

    #[test]
    fn regex_builtin_templates_extract() {
        let ip = args(&[("builtin", "ipv4")]);
        let out = regex_match(b"host 192.168.1.10 and 10.0.0.1 done", &ip).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "192.168.1.10\n10.0.0.1\n");
        let em = args(&[("builtin", "email")]);
        let out = regex_match(b"mail me at a.b+tag@example.com now", &em).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "a.b+tag@example.com\n");
        let uuid = args(&[("builtin", "uuid")]);
        let out = regex_match(b"id 123e4567-e89b-12d3-a456-426614174000 end", &uuid).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "123e4567-e89b-12d3-a456-426614174000\n"
        );
        let mac = args(&[("builtin", "mac")]);
        let out = regex_match(b"nic AA:BB:CC:DD:EE:FF and 00-11-22-33-44-55", &mac).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "AA:BB:CC:DD:EE:FF\n00-11-22-33-44-55\n"
        );
        let dom = args(&[("builtin", "domain")]);
        let out = regex_match(b"see www.example.co.uk today", &dom).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "www.example.co.uk\n");
        let d = args(&[("builtin", "date_ymd")]);
        let out = regex_match(b"on 2026-10-12 and 1999/01/31 ok", &d).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "2026-10-12\n1999/01/31\n");
        let s = args(&[("builtin", "strings")]);
        let out = regex_match(b"abc123 def!!\tzz", &s).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "abc123 def!!\n");
    }

    #[test]
    fn regex_builtin_pattern_precedence_and_errors() {
        let a = args(&[("builtin", "email"), ("pattern", r"cat")]);
        let out = regex_match(b"cat@x", &a).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "cat\n");
        assert!(regex_match(b"x", &args(&[("builtin", "nope")])).is_err());
        assert!(regex_match(b"x", &HashMap::new()).is_err());
        let b = args(&[("pattern", ""), ("builtin", "ipv4")]);
        let out = regex_match(b"1.2.3.4", &b).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "1.2.3.4\n");
    }

    #[test]
    fn regex_builtin_replace_uses_template() {
        let a = args(&[("builtin", "mac"), ("replacement", "X")]);
        let out = regex_replace(b"AA:BB:CC:DD:EE:FF ok", &a).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "X ok");
    }
}
