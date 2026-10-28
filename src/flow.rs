//! Flow model and YAML parsing.
//!
//! Flows as code: a flow is a versionable YAML file - Git-friendly, reviewable, reusable.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::i18n;
use serde_json::Value;

/// dpa-wide YAML parse options, aligned with the pre-migration
/// `serde_yaml_ng` semantics:
/// - `strict_booleans: true` keeps YAML 1.1 `yes`/`no`/`on`/`off` as strings
///   (serde_yaml_ng never inferred booleans from these);
/// - `merge_keys: AsOrdinary` keeps a literal `<<` merge key instead of
///   expanding it (matches ng's literal handling on the Value DOM path);
/// - `duplicate_keys: Error` rejects duplicate mapping keys at the parser
///   layer (ng rejected them at the serde layer; both keep the key name).
pub fn yaml_parse_options() -> serde_saphyr::Options {
    serde_saphyr::options! {
        strict_booleans: true,
        merge_keys: serde_saphyr::MergeKeyPolicy::AsOrdinary,
        duplicate_keys: serde_saphyr::DuplicateKeyPolicy::Error,
    }
}

/// Parse a YAML document with the dpa-wide options (typed deserialization).
///
/// The YAML parser migrated from `serde_yaml_ng` (unsafe-libyaml,
/// RUSTSEC-2024-0449, unmaintained) to `serde-saphyr` (safe Rust + serde
/// integration). Error messages may differ in wording but keep the affected
/// key name; the FTL i18n wrappers are unchanged.
pub fn from_yaml<T>(s: &str) -> Result<T, serde_saphyr::DeserializeError>
where
    T: serde::de::DeserializeOwned,
{
    serde_saphyr::from_str_with_options(s, yaml_parse_options())
}

/// Flow file structure.
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Flow {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Output format: raw | hex; overridable via the `--output-format` CLI flag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
    #[serde(default)]
    pub steps: Vec<Step>,
    /// Optional flow manifest (flow market prototype).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<FlowMeta>,
}

/// Current flow file schema version supported by this build.
///
/// Schema versions are additive and only bumped when older dpa builds can no
/// longer read the file. Files without `meta.schema_version` are treated as
/// v1 (backward compatible); dpa always serializes the current version.
pub const SUPPORTED_SCHEMA_VERSION: u64 = 1;

/// Flow manifest: discovery metadata attached to a flow (flow market prototype).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FlowMeta {
    /// Flow file schema version; absent means v1. Newer-than-supported
    /// versions are rejected at parse time (migration: upgrade dpa or
    /// convert the flow to a supported schema).
    #[serde(
        default = "default_schema_version",
        deserialize_with = "de_schema_version"
    )]
    pub schema_version: u64,
    /// Namespaced flow identifier, e.g. `dpa:flow:base64-decode`.
    ///
    /// `name` is accepted as an input alias: flows written by
    /// humans often call the identifier "name". Serialization keeps `id`, so
    /// the alias is purely backward-compatible.
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "name")]
    pub id: Option<String>,
    /// Flow version (semver), e.g. `1.0.0`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Author / maintainer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    /// Free-form tags for discovery.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// SPDX license id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    /// Homepage / source URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub homepage: Option<String>,
}

impl Default for FlowMeta {
    fn default() -> Self {
        Self {
            schema_version: SUPPORTED_SCHEMA_VERSION,
            id: None,
            version: None,
            author: None,
            tags: Vec::new(),
            license: None,
            homepage: None,
        }
    }
}

/// Schema version used when `meta.schema_version` is absent (v1).
fn default_schema_version() -> u64 {
    SUPPORTED_SCHEMA_VERSION
}

/// Parse `meta.schema_version`; reject unknown newer versions so old dpa
/// builds never misread a file written by a newer schema.
fn de_schema_version<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v = u64::deserialize(deserializer)?;
    if v > SUPPORTED_SCHEMA_VERSION {
        let ver = v.to_string();
        let cur = SUPPORTED_SCHEMA_VERSION.to_string();
        return Err(serde::de::Error::custom(i18n::tf(
            "err.flow_schema_unsupported",
            &[ver.as_str(), cur.as_str()],
        )));
    }
    Ok(v)
}

/// A single flow step.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    /// Op identifier, e.g. `dpa:base64:decode`.
    pub op: String,
    #[serde(
        default,
        deserialize_with = "de_string_map",
        skip_serializing_if = "HashMap::is_empty"
    )]
    pub args: HashMap<String, String>,
}

/// Output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Raw,
    Hex,
}

impl OutputFormat {
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "raw" => Ok(Self::Raw),
            "hex" => Ok(Self::Hex),
            _ => anyhow::bail!("{}", i18n::tf("err.unknown_output_format", &[s])),
        }
    }
}

/// Normalize a YAML map to string key-values.
///
/// Unquoted YAML numbers are silently converted by the YAML 1.2 core
/// schema (serde_yaml_ng turns `0x2A` into `Number(42)`), so the `0x`/`0o`/`0b`
/// literal is lost before any op sees it. To keep hex-like arguments
/// byte-exact, only quoted strings are accepted; numbers/booleans must be
/// quoted explicitly. The quoting also makes the radix intent unambiguous
/// (quoted `"0x10"` reaches the op as-is and numeric ops parse the prefix).
///
/// The raw `serde_yaml_ng::Mapping` deserializer rejects duplicate keys,
/// but `HashMap::deserialize` silently keeps the last value. We deserialize
/// through a map visitor so duplicate keys become a first-class i18n error
/// (with the key name) instead of a silent override, regardless of the
/// parser in use.
fn de_string_map<'de, D>(deserializer: D) -> Result<HashMap<String, String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct StringMapVisitor;

    impl<'de> serde::de::Visitor<'de> for StringMapVisitor {
        type Value = HashMap<String, String>;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a map of string arguments")
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::MapAccess<'de>,
        {
            let mut out = HashMap::new();
            let mut seen = std::collections::HashSet::new();
            while let Some((k, v)) = map.next_entry::<String, Value>()? {
                if !seen.insert(k.clone()) {
                    return Err(serde::de::Error::custom(i18n::tf(
                        "err.flow_dup_arg",
                        &[k.as_str()],
                    )));
                }
                match v {
                    Value::String(s) => {
                        out.insert(k, s);
                    }
                    Value::Number(_) | Value::Bool(_) => {
                        // Reject implicit scalar conversion; require quoting.
                        return Err(serde::de::Error::custom(i18n::tf(
                            "err.arg_type",
                            &[k.as_str()],
                        )));
                    }
                    Value::Null => {}
                    _ => {
                        return Err(serde::de::Error::custom(i18n::tf(
                            "err.arg_type",
                            &[k.as_str()],
                        )));
                    }
                }
            }
            Ok(out)
        }
    }

    deserializer.deserialize_map(StringMapVisitor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_flow_yaml() {
        let yaml = r#"
name: demo
description: test
output: hex
steps:
  - op: dpa:base64:decode
  - op: dpa:xor
    args:
      key: "0x2A"
      rounds: "3"
"#;
        let flow: Flow = from_yaml(yaml).unwrap();
        assert_eq!(flow.steps.len(), 2);
        assert_eq!(flow.steps[1].op, "dpa:xor");
        assert_eq!(flow.steps[1].args.get("key").unwrap(), "0x2A");
        assert_eq!(flow.steps[1].args.get("rounds").unwrap(), "3");
    }

    #[test]
    fn reject_nested_args() {
        let yaml = r#"
steps:
  - op: dpa:xor
    args:
      key:
        nested: value
"#;
        assert!(from_yaml::<Flow>(yaml).is_err());
    }

    #[test]
    fn output_format_parse() {
        assert_eq!(OutputFormat::parse("hex").unwrap(), OutputFormat::Hex);
        assert_eq!(OutputFormat::parse("RAW").unwrap(), OutputFormat::Raw);
        assert!(OutputFormat::parse("base64").is_err());
    }

    #[test]
    fn meta_name_aliases_id() {
        // `name` is accepted as an alias of `meta.id` (a pure
        // backward-compatible addition); serialization keeps emitting `id`.
        let yaml = r#"
meta:
  name: dpa:flow:demo
  version: "1.0.0"
steps:
  - op: dpa:base64:encode
"#;
        let flow: Flow = from_yaml(yaml).unwrap();
        assert_eq!(
            flow.meta.as_ref().and_then(|m| m.id.as_deref()),
            Some("dpa:flow:demo")
        );
    }

    #[test]
    fn meta_unknown_field_still_rejected() {
        // `deny_unknown_fields` stays intact: a typo like `nmae` must fail.
        let yaml = r#"
meta:
  nmae: demo
steps: []
"#;
        assert!(from_yaml::<Flow>(yaml).is_err());
    }

    #[test]
    fn parse_flow_yaml_bool_args() {
        // YAML booleans must be quoted inside args so the literal is
        // preserved (unquoted `true` is a YAML core-schema bool and cannot be
        // distinguished from a hex literal at parse time). Quoted "true"/"false"
        // normalize to those exact strings so ops that parse bool args work
        // unchanged inside flows.
        let rejected = r#"
name: bools
description: test
steps:
  - op: dpa:extract:domains
    args:
      unique: true
      sort: true
"#;
        let err = from_yaml::<Flow>(rejected).unwrap_err().to_string();
        assert!(err.contains("unique"), "got: {err}");

        let yaml = r#"
name: bools
description: test
steps:
  - op: dpa:extract:domains
    args:
      unique: "true"
      sort: "true"
      display_total: "false"
      extra_tld_blacklist: internal,corp
"#;
        let flow: Flow = from_yaml(yaml).unwrap();
        let args = &flow.steps[0].args;
        assert_eq!(args.get("unique").map(String::as_str), Some("true"));
        assert_eq!(args.get("sort").map(String::as_str), Some("true"));
        assert_eq!(args.get("display_total").map(String::as_str), Some("false"));
        assert_eq!(
            args.get("extra_tld_blacklist").map(String::as_str),
            Some("internal,corp")
        );
    }

    #[test]
    fn reject_unknown_flow_fields() {
        // YAML entry points deny unknown fields so typos fail
        // loudly instead of being silently ignored.
        let flow_typo = r#"
name: demo
desciption: oops
steps:
  - op: dpa:base64:encode
"#;
        assert!(from_yaml::<Flow>(flow_typo).is_err());

        let meta_typo = r#"
name: demo
meta:
  id: demo
  versoin: 1.0.0
steps:
  - op: dpa:base64:encode
"#;
        assert!(from_yaml::<Flow>(meta_typo).is_err());

        let step_typo = r#"
steps:
  - op: dpa:base64:encode
    arg: nope
"#;
        assert!(from_yaml::<Flow>(step_typo).is_err());

        // Sanity: the same documents without typos still parse.
        let ok = r#"
name: demo
meta:
  id: demo
  version: 1.0.0
steps:
  - op: dpa:base64:encode
"#;
        assert!(from_yaml::<Flow>(ok).is_ok());
    }

    #[test]
    fn flow_meta_schema_version_absent_defaults_to_v1() {
        // Files without meta.schema_version parse as v1 (backward compatible).
        let yaml = r#"
name: demo
meta:
  id: demo
steps:
  - op: dpa:base64:encode
"#;
        let flow: Flow = from_yaml(yaml).unwrap();
        assert_eq!(flow.meta.unwrap().schema_version, SUPPORTED_SCHEMA_VERSION);
    }

    #[test]
    fn flow_meta_schema_version_explicit_v1_ok() {
        let yaml = r#"
meta:
  schema_version: 1
  id: demo
steps:
  - op: dpa:base64:encode
"#;
        let flow: Flow = from_yaml(yaml).unwrap();
        assert_eq!(flow.meta.unwrap().schema_version, 1);
    }

    #[test]
    fn flow_meta_schema_version_unknown_newer_rejected() {
        for v in [2u64, 3, 99] {
            let yaml = format!(
                "meta:\n  schema_version: {v}\n  id: demo\nsteps:\n  - op: dpa:base64:encode\n"
            );
            let err = from_yaml::<Flow>(&yaml).unwrap_err();
            let msg = err.to_string();
            assert!(msg.contains("schema_version"), "v={v} msg: {msg}");
            assert!(msg.contains(v.to_string().as_str()), "v={v} msg: {msg}");
        }
    }

    #[test]
    fn flow_meta_schema_version_roundtrip_serializes_current() {
        let yaml = r#"
meta:
  id: demo
steps:
  - op: dpa:base64:encode
"#;
        let flow: Flow = from_yaml(yaml).unwrap();
        let out = serde_saphyr::to_string(&flow).unwrap();
        // Serialization must emit the current schema version field.
        assert!(out.contains("schema_version:"), "out: {out}");
        assert!(
            out.contains(&format!("schema_version: {SUPPORTED_SCHEMA_VERSION}")),
            "out: {out}"
        );
        // Round-trip: the emitted file parses back to the same version.
        let back: Flow = from_yaml(&out).unwrap();
        assert_eq!(back.meta.unwrap().schema_version, SUPPORTED_SCHEMA_VERSION);
    }

    #[test]
    fn flow_args_reject_unquoted_numbers_and_bools() {
        // Unquoted `0x2A` is silently converted by YAML core schema
        // (Number(42)); the literal must be preserved, so only quoted strings
        // are accepted for args. Numbers/booleans must be quoted explicitly.
        for yaml in [
            "steps:\n  - op: dpa:probe\n    args:\n      k: 0x2A\n",
            "steps:\n  - op: dpa:probe\n    args:\n      k: 0o17\n",
            "steps:\n  - op: dpa:probe\n    args:\n      k: 0b101\n",
            "steps:\n  - op: dpa:probe\n    args:\n      k: 42\n",
            "steps:\n  - op: dpa:probe\n    args:\n      k: true\n",
        ] {
            let err = from_yaml::<Flow>(yaml).unwrap_err().to_string();
            assert!(
                err.contains("k"),
                "expected key name in error for {yaml:?}, got: {err}"
            );
        }
        // Quoted literals round-trip untouched (hex-like args keep byte-exact
        // semantics; numeric ops see the prefix and can parse it).
        let yaml = "steps:\n  - op: dpa:probe\n    args:\n      k: \"0x2A\"\n      n: \"0x10\"\n";
        let flow: Flow = from_yaml(yaml).unwrap();
        assert_eq!(
            flow.steps[0].args.get("k").map(String::as_str),
            Some("0x2A")
        );
        assert_eq!(
            flow.steps[0].args.get("n").map(String::as_str),
            Some("0x10")
        );
    }

    #[test]
    fn flow_args_reject_duplicate_keys() {
        // Duplicate args keys must be a hard error (with the key name),
        // not a silent last-wins override.
        let yaml = "steps:\n  - op: dpa:probe\n    args:\n      k: \"1\"\n      k: \"2\"\n";
        let err = from_yaml::<Flow>(yaml).unwrap_err().to_string();
        assert!(err.contains("k"), "expected key name in error, got: {err}");
        // Same for the meta map.
        let yaml = "meta:\n  id: dup\n  id: other\nsteps:\n  - op: dpa:probe\n";
        assert!(
            from_yaml::<Flow>(yaml).is_err(),
            "duplicate meta keys must be rejected"
        );
    }
}
