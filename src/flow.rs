//! Flow model and YAML parsing.
//!
//! Flows as code: a flow is a versionable YAML file — Git-friendly, reviewable, reusable.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::i18n;
use serde_yaml::Value;

/// Flow file structure.
#[derive(Debug, Default, Deserialize, Serialize)]
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

/// Flow manifest: discovery metadata attached to a flow (flow market prototype).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct FlowMeta {
    /// Namespaced flow identifier, e.g. `dpa:flow:base64-decode`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
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

/// A single flow step.
#[derive(Debug, Clone, Deserialize, Serialize)]
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

/// Normalize a YAML map to string key-values: strings as-is, numbers/booleans converted to strings.
fn de_string_map<'de, D>(deserializer: D) -> Result<HashMap<String, String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let map: HashMap<String, Value> = HashMap::deserialize(deserializer)?;
    let mut out = HashMap::new();
    for (k, v) in map {
        match v {
            Value::String(s) => {
                out.insert(k, s);
            }
            Value::Number(n) => {
                out.insert(k, n.to_string());
            }
            Value::Bool(b) => {
                out.insert(k, b.to_string());
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
      rounds: 3
"#;
        let flow: Flow = serde_yaml::from_str(yaml).unwrap();
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
        assert!(serde_yaml::from_str::<Flow>(yaml).is_err());
    }

    #[test]
    fn output_format_parse() {
        assert_eq!(OutputFormat::parse("hex").unwrap(), OutputFormat::Hex);
        assert_eq!(OutputFormat::parse("RAW").unwrap(), OutputFormat::Raw);
        assert!(OutputFormat::parse("base64").is_err());
    }
}
