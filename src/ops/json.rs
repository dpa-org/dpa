//! JSON ops: pretty-print / minify / field extraction.

use std::collections::HashMap;

use serde_json::Value;

use super::{ArgSpec, Op};
use crate::i18n;

pub fn ops() -> Vec<Op> {
    vec![
        op!(
            "dpa:json:pretty",
            "transform",
            "op.json.pretty.desc",
            &[ArgSpec {
                name: "indent",
                required: false,
                description: "op.json.pretty.arg.indent",
                format: crate::ops::ArgFormat::Utf8,
            },],
            json_pretty
        ),
        op!(
            "dpa:json:minify",
            "transform",
            "op.json.minify.desc",
            &[],
            json_minify
        ),
        op!(
            "dpa:json:get",
            "transform",
            "op.json.get.desc",
            &[ArgSpec {
                name: "path",
                required: true,
                description: "op.json.get.arg.path",
                format: crate::ops::ArgFormat::Utf8,
            },],
            json_get
        ),
        // CSV <-> JSON
        op!(
            "dpa:csv:to-json",
            "codec",
            "op.csv.to-json.desc",
            &[
                ArgSpec {
                    name: "delimiter",
                    required: false,
                    description: "op.csv.to-json.arg.delimiter",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "format",
                    required: false,
                    description: "op.csv.to-json.arg.format",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "row_delimiter",
                    required: false,
                    description: "op.csv.to-json.arg.row-delimiter",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            csv_to_json
        ),
        op!(
            "dpa:json:to-csv",
            "codec",
            "op.json.to-csv.desc",
            &[
                ArgSpec {
                    name: "delimiter",
                    required: false,
                    description: "op.json.to-csv.arg.delimiter",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "row_delimiter",
                    required: false,
                    description: "op.json.to-csv.arg.row-delimiter",
                    format: crate::ops::ArgFormat::Utf8,
                },
                ArgSpec {
                    name: "flatten",
                    required: false,
                    description: "op.json.to-csv.arg.flatten",
                    format: crate::ops::ArgFormat::Utf8,
                },
            ],
            json_to_csv
        ),
    ]
}

fn parse(input: &[u8]) -> anyhow::Result<Value> {
    serde_json::from_slice(input)
        .map_err(|e| anyhow::anyhow!("{}", i18n::tf("err.json_parse", &[e.to_string().as_str()])))
}

/// Parse the `delimiter` argument: a single byte (the CSV cell separator).
fn parse_csv_delimiter(args: &HashMap<String, String>) -> anyhow::Result<u8> {
    match args.get("delimiter") {
        None => Ok(b','),
        Some(v) => {
            let bytes = v.as_bytes();
            if bytes.len() != 1 {
                anyhow::bail!("{}", i18n::t("err.csv_delimiter_invalid"));
            }
            Ok(bytes[0])
        }
    }
}

/// Row delimiter selection for CSV reading/writing (mirrors CyberChef's Row
/// delimiters option): `auto` (CRLF or LF, default), `lf`, or `crlf`.
/// Reading is lenient: `auto`/`crlf` accept `\r`, `\n` and `\r\n`; `lf` is
/// strict LF. Writing is strict: `auto`/`lf` emit LF, `crlf` emits CRLF.
fn parse_csv_row_delimiter(
    args: &HashMap<String, String>,
    writing: bool,
) -> anyhow::Result<csv::Terminator> {
    let mode = args
        .get("row_delimiter")
        .map(|v| v.to_ascii_lowercase())
        .unwrap_or_else(|| "auto".to_string());
    match mode.as_str() {
        "crlf" | "\\r\\n" => Ok(csv::Terminator::CRLF),
        "lf" | "\\n" => Ok(csv::Terminator::Any(b'\n')),
        "auto" => Ok(if writing {
            csv::Terminator::Any(b'\n')
        } else {
            csv::Terminator::CRLF
        }),
        other => anyhow::bail!(
            "{}",
            i18n::tf(
                "err.csv_row_delimiter_invalid",
                &[other, "auto / lf / crlf"]
            )
        ),
    }
}

/// Output shape for `dpa:csv:to-json` (mirrors CyberChef's CSVToJSON).
#[derive(Clone, Copy, PartialEq, Eq)]
enum CsvJsonFormat {
    Dict,
    Array,
}

fn parse_csv_format(args: &HashMap<String, String>) -> anyhow::Result<CsvJsonFormat> {
    match args
        .get("format")
        .map(|v| v.to_ascii_lowercase())
        .as_deref()
    {
        None | Some("dict") => Ok(CsvJsonFormat::Dict),
        Some("array") => Ok(CsvJsonFormat::Array),
        Some(other) => anyhow::bail!(
            "{}",
            i18n::tf("err.csv_format_invalid", &[other, "dict / array"])
        ),
    }
}

/// Parse the `indent` argument for pretty printing: a literal string, `tab`,
/// `\t`, or a number of spaces (0..=32). Defaults to two spaces.
fn parse_indent(args: &HashMap<String, String>) -> anyhow::Result<String> {
    match args.get("indent") {
        None => Ok("  ".to_string()),
        Some(v) if v == "tab" || v == "\\t" || v == "\t" => Ok("\t".to_string()),
        Some(v) => {
            if let Ok(n) = v.parse::<usize>() {
                if n > 32 {
                    anyhow::bail!("{}", i18n::t("err.json_indent_invalid"));
                }
                Ok(" ".repeat(n))
            } else {
                Ok(v.clone())
            }
        }
    }
}

fn json_pretty(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let v = parse(input)?;
    let indent = parse_indent(args)?;
    let s = serde_json::to_string_pretty(&v)?;
    if indent == "  " {
        return Ok(s.into_bytes());
    }
    // serde_json uses two spaces per level; re-indent line by line. JSON
    // string values never span lines, so leading-space counting is safe.
    let mut out = String::with_capacity(s.len());
    for (idx, line) in s.lines().enumerate() {
        if idx > 0 {
            out.push('\n');
        }
        let lead = line.len() - line.trim_start_matches(' ').len();
        for _ in 0..(lead / 2) {
            out.push_str(&indent);
        }
        out.push_str(&line[lead..]);
    }
    Ok(out.into_bytes())
}

fn json_minify(input: &[u8], _args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let v = parse(input)?;
    let s = serde_json::to_string(&v)?;
    Ok(s.into_bytes())
}

fn json_get(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let path = args
        .get("path")
        .ok_or_else(|| anyhow::anyhow!("{}", i18n::t("err.missing_path")))?;
    let v = parse(input)?;
    let cur = walk(&v, path)?;
    let s = if cur.is_string() {
        cur.as_str().unwrap().to_string()
    } else {
        serde_json::to_string(cur)?
    };
    Ok(s.into_bytes())
}

/// Navigate a `a.b[0].c`-style path; only object keys and array indexes are supported.
fn walk<'a>(mut cur: &'a Value, path: &str) -> anyhow::Result<&'a Value> {
    let mut seg = String::new();
    let mut chars = path.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '.' | '[' => {
                if !seg.is_empty() {
                    cur = step(cur, &seg)?;
                    seg.clear();
                }
                if c == '[' {
                    // Read 'N]'
                    let mut idx = String::new();
                    for c2 in chars.by_ref() {
                        if c2 == ']' {
                            break;
                        }
                        idx.push(c2);
                    }
                    let n: usize = idx.trim().parse().map_err(|_| {
                        anyhow::anyhow!("{}", i18n::tf("err.path_index", &[idx.as_str()]))
                    })?;
                    cur = cur.get(n).ok_or_else(|| {
                        anyhow::anyhow!("{}", i18n::tf("err.path_not_found_idx", &[idx.as_str()]))
                    })?;
                }
            }
            _ => seg.push(c),
        }
    }
    if !seg.is_empty() {
        cur = step(cur, &seg)?;
    }
    Ok(cur)
}

fn step<'a>(cur: &'a Value, key: &str) -> anyhow::Result<&'a Value> {
    cur.get(key)
        .ok_or_else(|| anyhow::anyhow!("{}", i18n::tf("err.path_not_found_key", &[key])))
}

// ---------------------------------------------------------------------------
// CSV <-> JSON: compact JSON array of objects from CSV, and the
// reverse with a union of keys as headers. Both are in-memory whole-input ops.
// ---------------------------------------------------------------------------

fn csv_to_json(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let delimiter = parse_csv_delimiter(args)?;
    let format = parse_csv_format(args)?;
    let terminator = parse_csv_row_delimiter(args, false)?;
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(true)
        .delimiter(delimiter)
        .terminator(terminator)
        .from_reader(input);
    let headers: Vec<String> = rdr.headers()?.iter().map(String::from).collect();
    let mut out = Vec::with_capacity(input.len() + 2);
    match format {
        CsvJsonFormat::Dict => {
            out.push(b'[');
            let mut first = true;
            for rec in rdr.records() {
                let rec = rec?;
                let mut obj = serde_json::Map::new();
                for (i, h) in headers.iter().enumerate() {
                    obj.insert(
                        h.clone(),
                        Value::String(rec.get(i).unwrap_or("").to_string()),
                    );
                }
                if !first {
                    out.push(b',');
                }
                first = false;
                out.extend_from_slice(&serde_json::to_vec(&Value::Object(obj))?);
            }
            out.push(b']');
        }
        CsvJsonFormat::Array => {
            out.push(b'[');
            // The header row is the first data row, mirroring CyberChef.
            out.extend_from_slice(&serde_json::to_vec(&Value::Array(
                headers.iter().map(|h| Value::String(h.clone())).collect(),
            ))?);
            for rec in rdr.records() {
                let rec = rec?;
                out.push(b',');
                let row: Vec<Value> = (0..headers.len())
                    .map(|i| Value::String(rec.get(i).unwrap_or("").to_string()))
                    .collect();
                out.extend_from_slice(&serde_json::to_vec(&Value::Array(row))?);
            }
            out.push(b']');
        }
    }
    Ok(out)
}

fn json_to_csv(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let delimiter = parse_csv_delimiter(args)?;
    let row_delimiter = parse_csv_row_delimiter(args, true)?;
    let flatten = match args
        .get("flatten")
        .map(|v| v.to_ascii_lowercase())
        .as_deref()
    {
        None | Some("false") | Some("0") | Some("no") => false,
        Some("true") | Some("1") | Some("yes") => true,
        Some(other) => anyhow::bail!("{}", i18n::tf("err.json_flatten_invalid", &[other])),
    };
    let v = parse(input)?;
    // Non-array inputs (single object / scalar) are wrapped into a one-row
    // array, mirroring CyberChef's JSONToCSV.
    let arr: Vec<Value> = match v.as_array() {
        Some(a) => a.clone(),
        None => vec![v],
    };
    // Union of keys (plain keys or flattened dotted paths) in first-seen order.
    let mut keys: Vec<String> = Vec::new();
    let mut leaves: Vec<Vec<(String, Value)>> = Vec::with_capacity(arr.len());
    for e in &arr {
        let mut row_leaves: Vec<(String, Value)> = Vec::new();
        if flatten {
            flatten_value("", e, &mut row_leaves);
        } else if let Some(obj) = e.as_object() {
            for (k, val) in obj {
                row_leaves.push((k.clone(), val.clone()));
            }
        }
        for (k, _) in &row_leaves {
            if !keys.iter().any(|x| x == k) {
                keys.push(k.clone());
            }
        }
        leaves.push(row_leaves);
    }
    let mut wtr = csv::WriterBuilder::new()
        .delimiter(delimiter)
        .terminator(row_delimiter)
        .from_writer(Vec::new());
    wtr.write_record(&keys)?;
    for row_leaves in &leaves {
        let row: Vec<String> = keys
            .iter()
            .map(
                |k| match row_leaves.iter().find(|(p, _)| p == k).map(|(_, v)| v) {
                    None | Some(Value::Null) => String::new(),
                    Some(Value::String(s)) => s.clone(),
                    Some(other) => serde_json::to_string(other).unwrap_or_default(),
                },
            )
            .collect();
        wtr.write_record(&row)?;
    }
    Ok(wtr.into_inner()?)
}

/// Flatten a JSON value into dotted-path leaves (`a.b`, `a.0`), mirroring the
/// nested-object expansion CyberChef applies through the `flat` library when
/// direct conversion would lose data. Empty objects/arrays are kept as leaves
/// so their paths still appear in the header.
fn flatten_value(prefix: &str, v: &Value, out: &mut Vec<(String, Value)>) {
    match v {
        Value::Object(map) if !map.is_empty() => {
            for (k, val) in map {
                let key = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{}.{}", prefix, k)
                };
                flatten_value(&key, val, out);
            }
        }
        Value::Array(items) if !items.is_empty() => {
            for (i, val) in items.iter().enumerate() {
                let key = if prefix.is_empty() {
                    i.to_string()
                } else {
                    format!("{}.{}", prefix, i)
                };
                flatten_value(&key, val, out);
            }
        }
        leaf => out.push((prefix.to_string(), leaf.clone())),
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pretty_roundtrip() {
        let input = br#"{"b":1,"a":[true,null]}"#;
        let out = json_pretty(input, &HashMap::new()).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(
            s.contains('\n'),
            "pretty output should contain a newline: {}",
            s
        );
        let back = json_minify(s.as_bytes(), &HashMap::new()).unwrap();
        // serde_json sorts object keys; compare semantically, not byte-wise
        let v1: Value = serde_json::from_slice(input).unwrap();
        let v2: Value = serde_json::from_slice(&back).unwrap();
        assert_eq!(v1, v2);
    }

    #[test]
    fn get_by_path() {
        let input = br#"{"user":{"name":"alice","tags":["dev","rust"]}}"#;
        let mut a = HashMap::new();
        a.insert("path".into(), "user.name".into());
        assert_eq!(json_get(input, &a).unwrap(), b"alice");
        a.insert("path".into(), "user.tags[1]".into());
        assert_eq!(json_get(input, &a).unwrap(), b"rust");
    }

    #[test]
    fn get_missing_path_fails() {
        let mut a = HashMap::new();
        a.insert("path".into(), "nope".into());
        assert!(json_get(b"{}", &a).is_err());
    }

    #[test]
    fn csv_to_json_objects() {
        let input = b"name,age\nalice,30\nbob,25\n";
        let out = csv_to_json(input, &HashMap::new()).unwrap();
        let v: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(
            v,
            serde_json::json!([
                {"name": "alice", "age": "30"},
                {"name": "bob", "age": "25"}
            ])
        );
        // Headers-only CSV yields an empty array.
        assert_eq!(csv_to_json(b"a,b\n", &HashMap::new()).unwrap(), b"[]");
    }

    #[test]
    fn json_to_csv_union_keys() {
        let input = br#"[{"a":1,"b":"x"},{"a":2,"c":true},{"d":null}]"#;
        let out = json_to_csv(input, &HashMap::new()).unwrap();
        let s = String::from_utf8(out).unwrap();
        let rows: Vec<&str> = s.trim_end().split('\n').collect();
        assert_eq!(rows[0], "a,b,c,d");
        assert_eq!(rows[1], "1,x,,");
        assert_eq!(rows[2], "2,,true,");
        assert_eq!(rows[3], ",,,null".replace("null", ""));
    }

    #[test]
    fn json_to_csv_single_object() {
        // Non-array inputs are wrapped into a one-row array (CyberChef parity).
        let out = json_to_csv(b"{\"a\":1,\"b\":\"x\"}", &HashMap::new()).unwrap();
        let s = String::from_utf8(out).unwrap();
        let rows: Vec<&str> = s.trim_end().split('\n').collect();
        assert_eq!(rows[0], "a,b");
        assert_eq!(rows[1].trim_end(), "1,x");
    }

    #[test]
    fn csv_to_json_custom_delimiter_and_array() {
        // Custom single-byte delimiter.
        let mut a = HashMap::new();
        a.insert("delimiter".to_string(), "|".to_string());
        let out = csv_to_json(b"name|age\nalice|30\n", &a).unwrap();
        let v: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v, serde_json::json!([{"name": "alice", "age": "30"}]));
        // Array-of-arrays format keeps the header row as the first row.
        let mut b = HashMap::new();
        b.insert("format".to_string(), "array".to_string());
        let out2 = csv_to_json(b"name,age\nalice,30\n", &b).unwrap();
        let v2: Value = serde_json::from_slice(&out2).unwrap();
        assert_eq!(v2, serde_json::json!([["name", "age"], ["alice", "30"]]));
        // Multi-byte delimiter rejected.
        let mut c = HashMap::new();
        c.insert("delimiter".to_string(), "::".to_string());
        assert!(csv_to_json(b"a::b\n", &c).is_err());
        // Invalid format rejected.
        let mut d = HashMap::new();
        d.insert("format".to_string(), "bogus".to_string());
        assert!(csv_to_json(b"a,b\n", &d).is_err());
    }

    #[test]
    fn json_to_csv_custom_delimiter() {
        let input = br#"[{"a":1,"b":2},{"a":3,"b":4}]"#;
        let mut a = HashMap::new();
        a.insert("delimiter".to_string(), ";".to_string());
        let out = json_to_csv(input, &a).unwrap();
        let s = String::from_utf8(out).unwrap();
        let rows: Vec<&str> = s.trim_end().split('\n').collect();
        assert_eq!(rows[0], "a;b");
        assert_eq!(rows[1], "1;2");
        assert_eq!(rows[2], "3;4");
    }

    #[test]
    fn json_pretty_custom_indent() {
        let input = br#"{"a":[1,2]}"#;
        // Tab indent.
        let mut t = HashMap::new();
        t.insert("indent".to_string(), "tab".to_string());
        let out = json_pretty(input, &t).unwrap();
        assert!(
            String::from_utf8(out).unwrap().contains("\n\t\""),
            "tab indent"
        );
        // Numeric spaces.
        let mut n = HashMap::new();
        n.insert("indent".to_string(), "4".to_string());
        let out2 = json_pretty(input, &n).unwrap();
        assert!(
            String::from_utf8(out2).unwrap().contains("\n    \""),
            "4-space indent"
        );
        // Literal string.
        let mut s = HashMap::new();
        s.insert("indent".to_string(), "--".to_string());
        let out3 = json_pretty(input, &s).unwrap();
        assert!(
            String::from_utf8(out3).unwrap().contains("\n--\""),
            "literal indent"
        );
        // Out-of-range number rejected.
        let mut bad = HashMap::new();
        bad.insert("indent".to_string(), "99".to_string());
        assert!(json_pretty(input, &bad).is_err());
    }

    #[test]
    fn minify_single_line_and_roundtrip() {
        let input = b"{\n  \"b\": 1,\n  \"a\": [true, null]\n}\n";
        let out = json_minify(input, &HashMap::new()).unwrap();
        let s = String::from_utf8(out.clone()).unwrap();
        assert!(!s.contains('\n'), "minified output must be one line: {}", s);
        // Pretty -> minify -> pretty stays semantically equal.
        let v1: Value = serde_json::from_slice(input).unwrap();
        let v2: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v1, v2);
    }

    #[test]
    fn pretty_rejects_invalid_json() {
        assert!(json_pretty(b"not json", &HashMap::new()).is_err());
        assert!(json_minify(b"", &HashMap::new()).is_err());
    }

    #[test]
    fn get_returns_serialized_non_string() {
        let mut a = HashMap::new();
        a.insert("path".into(), "n".into());
        assert_eq!(json_get(br#"{"n":42}"#, &a).unwrap(), b"42");
        a.insert("path".into(), "f".into());
        assert_eq!(json_get(br#"{"f":false}"#, &a).unwrap(), b"false");
        a.insert("path".into(), "obj".into());
        assert_eq!(json_get(br#"{"obj":{"k":1}}"#, &a).unwrap(), br#"{"k":1}"#);
        a.insert("path".into(), "arr".into());
        assert_eq!(json_get(br#"{"arr":[1,2]}"#, &a).unwrap(), b"[1,2]");
    }

    #[test]
    fn get_missing_path_param_rejected() {
        // No "path" argument at all must fail with a missing-param error.
        assert!(json_get(b"{}", &HashMap::new()).is_err());
    }

    #[test]
    fn get_path_index_missing_fails() {
        let mut a = HashMap::new();
        a.insert("path".into(), "a[9]".into());
        assert!(json_get(br#"{"a":[1]}"#, &a).is_err());
        a.insert("path".into(), "a.b".into());
        assert!(json_get(br#"{"a":1}"#, &a).is_err());
    }

    #[test]
    fn get_nested_array_indexing() {
        let mut a = HashMap::new();
        a.insert("path".into(), "[0][1]".into());
        assert_eq!(json_get(br#"[[1,2],[3]]"#, &a).unwrap(), b"2");
        a.insert("path".into(), "rows[0].name".into());
        assert_eq!(json_get(br#"{"rows":[{"name":"x"}]}"#, &a).unwrap(), b"x");
    }

    #[test]
    fn get_array_root_by_index() {
        let mut a = HashMap::new();
        a.insert("path".into(), "[1]".into());
        assert_eq!(json_get(br#"["a","b"]"#, &a).unwrap(), b"b");
    }

    #[test]
    fn csv_to_json_short_row_rejected() {
        // Row with fewer fields than headers is an error (column-count
        // mismatch, same strictness as CyberChef's CSV conversion).
        let input = b"a,b,c\n1,2\n";
        assert!(csv_to_json(input, &HashMap::new()).is_err());
    }

    #[test]
    fn json_to_csv_empty_array_is_ok() {
        // Empty array: no union keys, so a single empty record is emitted
        // (csv crate writes an empty field as `""`).
        let out = json_to_csv(b"[]", &HashMap::new()).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert_eq!(s.trim_end(), "\"\"");
    }

    #[test]
    fn json_to_csv_nested_values_serialized() {
        let input = br#"[{"a":{"k":1},"b":[1,2]}]"#;
        let out = json_to_csv(input, &HashMap::new()).unwrap();
        let s = String::from_utf8(out).unwrap();
        let rows: Vec<&str> = s.trim_end().split('\n').collect();
        assert_eq!(rows[0], "a,b");
        // csv crate writes CRLF terminators; strip before comparing. A field
        // containing quote chars is quoted with doubled quotes (CSV standard).
        assert_eq!(rows[1].trim_end(), "\"{\"\"k\"\":1}\",\"[1,2]\"");
    }

    #[test]
    fn csv_to_json_crlf_rows_auto() {
        // Auto row delimiter accepts CRLF input (mirrors CyberChef Row delimiters).
        let out = csv_to_json(b"name,age\r\nalice,30\r\n", &HashMap::new()).unwrap();
        let v: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v, serde_json::json!([{"name": "alice", "age": "30"}]));
        // lf mode also works for LF input and rejects nothing extra.
        let mut a = HashMap::new();
        a.insert("row_delimiter".to_string(), "lf".to_string());
        let out2 = csv_to_json(b"name,age\nalice,30\n", &a).unwrap();
        let v2: Value = serde_json::from_slice(&out2).unwrap();
        assert_eq!(v2, serde_json::json!([{"name": "alice", "age": "30"}]));
        // Invalid row delimiter rejected.
        let mut b = HashMap::new();
        b.insert("row_delimiter".to_string(), "bogus".to_string());
        assert!(csv_to_json(b"a,b\n", &b).is_err());
    }

    #[test]
    fn json_to_csv_row_delimiter_lf() {
        let input = br#"[{"a":1,"b":2}]"#;
        let mut a = HashMap::new();
        a.insert("row_delimiter".to_string(), "lf".to_string());
        let out = json_to_csv(input, &a).unwrap();
        let s = String::from_utf8(out).unwrap();
        // LF terminator: header and data rows separated by bare newlines.
        assert_eq!(s, "a,b\n1,2\n");
        // crlf mode emits CRLF terminators.
        let mut b = HashMap::new();
        b.insert("row_delimiter".to_string(), "crlf".to_string());
        let out2 = json_to_csv(input, &b).unwrap();
        let s2 = String::from_utf8(out2).unwrap();
        assert_eq!(s2, "a,b\r\n1,2\r\n");
        // Invalid value rejected.
        let mut c = HashMap::new();
        c.insert("row_delimiter".to_string(), "weird".to_string());
        assert!(json_to_csv(input, &c).is_err());
    }

    #[test]
    fn json_to_csv_flatten_nested() {
        let input = br#"[{"a":{"k":1},"b":[10,20],"c":"x"}]"#;
        let mut a = HashMap::new();
        a.insert("flatten".to_string(), "true".to_string());
        let out = json_to_csv(input, &a).unwrap();
        let s = String::from_utf8(out).unwrap();
        let rows: Vec<&str> = s.trim_end().split('\n').collect();
        // Nested objects/arrays expand into dotted-path columns.
        assert_eq!(rows[0], "a.k,b.0,b.1,c");
        assert_eq!(rows[1].trim_end(), "1,10,20,x");
        // flatten=false keeps JSON-string serialization for nested values.
        let out2 = json_to_csv(input, &HashMap::new()).unwrap();
        let s2 = String::from_utf8(out2).unwrap();
        let rows2: Vec<&str> = s2.trim_end().split('\n').collect();
        assert_eq!(rows2[0], "a,b,c");
        // Invalid flatten value rejected.
        let mut b = HashMap::new();
        b.insert("flatten".to_string(), "maybe".to_string());
        assert!(json_to_csv(input, &b).is_err());
    }
}
