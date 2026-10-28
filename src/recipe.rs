//! CyberChef recipe converter: interconverts URL / CHEF(pretty) / JSON formats;
//! operation names support both Chinese and English.
//!
//! Format notes (mirrors CyberChef_zh-cn `src/core/Utils.mjs` `parseRecipeConfig`
//! and the web URL convention):
//! - JSON: `[{"op":"To Base64","args":["A-Za-z0-9+/="]}, ...]` (may carry `disabled` / `breakpoint` fields)
//! - CHEF: `To_Base64('A-Za-z0-9+/=')To_Hex('Space')` (pretty format, `.chef` file content; underscores stand in for spaces in op names)
//! - URL: `https://gchq.github.io/CyberChef/#recipe=<URL-encoded CHEF or JSON>&input=<URL-encoded Base64>`
//!
//! Bilingual support: op names are translated both ways through [`crate::recipe_map`];
//! names not in the map are kept as-is without guessing.

use anyhow::{Context, Result, bail};
use serde_json::Value;

use crate::i18n;
use crate::recipe_map;

/// The official CyberChef homepage, used to build share URLs.
pub const RECIPE_BASE_URL: &str = "https://gchq.github.io/CyberChef/";

/// A single operation within a recipe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipeOp {
    /// Operation name (English or Chinese, kept as written).
    pub op: String,
    /// Argument array (strings / numbers / booleans / null).
    pub args: Vec<Value>,
    pub disabled: bool,
    pub breakpoint: bool,
}

impl RecipeOp {
    pub fn new(op: &str, args: Vec<Value>) -> Self {
        RecipeOp {
            op: op.to_string(),
            args,
            disabled: false,
            breakpoint: false,
        }
    }
}

/// The three recipe formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Url,
    Chef,
    Json,
}

impl Format {
    pub fn parse(s: &str) -> Option<Format> {
        match s.trim().to_ascii_lowercase().as_str() {
            "url" => Some(Format::Url),
            "chef" | "pretty" => Some(Format::Chef),
            "json" => Some(Format::Json),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Format::Url => "url",
            Format::Chef => "chef",
            Format::Json => "json",
        }
    }
}

/// Auto-detect a recipe format from input text. A UTF-8 BOM
/// (`\u{FEFF}`) and leading whitespace are stripped before deciding, so a
/// BOM-prefixed JSON recipe is no longer misclassified as Chef.
pub fn detect_format(input: &str) -> Format {
    let s = input
        .trim_start()
        .trim_start_matches('\u{feff}')
        .trim_start();
    if s.starts_with("http://") || s.starts_with("https://") {
        Format::Url
    } else if s.starts_with('[') {
        Format::Json
    } else {
        Format::Chef
    }
}

/// Output language for operation names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    Zh,
    En,
}

impl Lang {
    pub fn parse(s: &str) -> Option<Lang> {
        match s.trim().to_ascii_lowercase().as_str() {
            "zh" | "zh-cn" | "zh_cn" | "cn" => Some(Lang::Zh),
            "en" | "en-us" | "en_us" => Some(Lang::En),
            _ => None,
        }
    }
}

// ============================ JSON ============================

/// Serialize a recipe op list to a JSON string (CyberChef recipeConfig format).
pub fn to_json(ops: &[RecipeOp]) -> String {
    let arr: Vec<Value> = ops.iter().map(op_to_json).collect();
    serde_json::to_string(&arr).unwrap_or_else(|_| "[]".to_string())
}

fn op_to_json(op: &RecipeOp) -> Value {
    let mut m = serde_json::Map::new();
    m.insert("op".into(), Value::String(op.op.clone()));
    m.insert("args".into(), Value::Array(op.args.clone()));
    if op.disabled {
        m.insert("disabled".into(), Value::Bool(true));
    }
    if op.breakpoint {
        m.insert("breakpoint".into(), Value::Bool(true));
    }
    Value::Object(m)
}

/// Parse a recipe op list from a JSON string.
pub fn from_json(s: &str) -> Result<Vec<RecipeOp>> {
    let v: Value = serde_json::from_str(s.trim()).context(i18n::t_str("err.recipe_json_parse"))?;
    let arr = v
        .as_array()
        .context(i18n::t_str("err.recipe_json_top_array"))?;
    let mut ops = Vec::with_capacity(arr.len());
    for item in arr {
        let obj = item
            .as_object()
            .context(i18n::t_str("err.recipe_element_object"))?;
        let op = obj
            .get("op")
            .and_then(Value::as_str)
            .context(i18n::t_str("err.recipe_missing_op"))?
            .to_string();
        let args = obj.get("args").cloned().unwrap_or(Value::Array(vec![]));
        let args = args
            .as_array()
            .context(i18n::t_str("err.recipe_args_array"))?
            .clone();
        let disabled = obj
            .get("disabled")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let breakpoint = obj
            .get("breakpoint")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        ops.push(RecipeOp {
            op,
            args,
            disabled,
            breakpoint,
        });
    }
    Ok(ops)
}

// ============================ CHEF (pretty) ============================

/// Serialize a recipe op list to a CHEF / pretty string.
pub fn to_chef(ops: &[RecipeOp]) -> String {
    ops.iter()
        .map(|op| {
            let mut s = format!(
                "{}({})",
                op.op.replace(' ', "_"),
                op.args
                    .iter()
                    .map(arg_to_chef)
                    .collect::<Vec<_>>()
                    .join(",")
            );
            if op.breakpoint {
                s.push_str("/breakpoint");
            }
            if op.disabled {
                s.push_str("/disabled");
            }
            s
        })
        .collect()
}

fn arg_to_chef(v: &Value) -> String {
    match v {
        Value::String(s) => format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'")),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".to_string(),
        // Object / array arguments are emitted as JSON literals in pretty format (CyberChef does the same).
        other => other.to_string(),
    }
}

/// Parse a recipe op list from a CHEF / pretty string.
///
/// Syntax: `Op_Name('arg1',123,true)/disabled/breakpoint`; string arguments are
/// single-quoted with `\'` escapes; underscores in op names are restored to spaces.
pub fn from_chef(s: &str) -> Result<Vec<RecipeOp>> {
    let b = s.as_bytes();
    let mut i = 0usize;
    let mut ops = Vec::new();

    while i < b.len() {
        // Skip whitespace
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= b.len() {
            break;
        }
        // Stray parenthesised groups (leftover `(...)` fragments): match official behaviour, skip silently
        if b[i] == b'(' {
            while i < b.len() && b[i] != b')' {
                i += 1;
            }
            if i < b.len() {
                i += 1;
            }
            continue;
        }
        let op_start = i;
        while i < b.len() && b[i] != b'(' {
            if b[i] == b'\n' || b[i] == b'\r' {
                bail!(
                    "{}",
                    i18n::tf("err.recipe_missing_paren", &[op_start.to_string().as_str()])
                );
            }
            i += 1;
        }
        if i >= b.len() || i == op_start {
            bail!(
                "{}",
                i18n::tf("err.recipe_missing_paren", &[op_start.to_string().as_str()])
            );
        }
        let op_name = s[op_start..i].trim().replace('_', " ");
        i += 1; // consume '('

        let mut args: Vec<Value> = Vec::new();
        let mut token: Vec<u8> = Vec::new();
        let mut in_str = false;
        let disabled = false;
        let breakpoint = false;

        loop {
            if i >= b.len() {
                bail!(
                    "{}",
                    i18n::tf("err.recipe_unclosed_paren", &[op_name.as_str()])
                );
            }
            let c = b[i];
            if in_str {
                match c {
                    b'\\' => {
                        i += 1;
                        if i >= b.len() {
                            bail!("{}", i18n::t_str("err.recipe_unfinished_escape"));
                        }
                        token.push(b[i]);
                        i += 1;
                    }
                    b'\'' => {
                        let s = String::from_utf8(std::mem::take(&mut token))
                            .context(i18n::t_str("err.recipe_arg_utf8"))?;
                        args.push(Value::String(s));
                        in_str = false;
                        i += 1;
                    }
                    _ => {
                        token.push(c);
                        i += 1;
                    }
                }
            } else {
                match c {
                    b'\'' => {
                        token.clear();
                        in_str = true;
                        i += 1;
                    }
                    b',' => {
                        push_bare_token(&mut args, &mut token)?;
                        i += 1;
                    }
                    b')' => {
                        push_bare_token(&mut args, &mut token)?;
                        i += 1;
                        break;
                    }
                    _ => {
                        token.push(c);
                        i += 1;
                    }
                }
            }
        }

        ops.push(RecipeOp {
            op: op_name,
            args,
            disabled,
            breakpoint,
        });

        // After an op, handle the trailing /disabled /breakpoint flags (aligned
        // with official prefix-match semantics: a hit sets the flag, leftover
        // characters belong to the next op name; unknown suffixes are ignored).
        loop {
            while i < b.len() && b[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < b.len() && b[i] == b'/' {
                i += 1;
                let mut consumed = 0usize;
                for candidate in ["breakpoint", "disabled"] {
                    if s[i..].starts_with(candidate) {
                        let is_bp = candidate == "breakpoint";
                        if let Some(last) = ops.last_mut() {
                            if is_bp {
                                last.breakpoint = true;
                            } else {
                                last.disabled = true;
                            }
                        }
                        consumed = candidate.len();
                        break;
                    }
                }
                i += consumed;
                if consumed == 0 {
                    // Not a flag. Official CyberChef separates ops with '/':
                    // if a parenthesised group follows, this is the start of
                    // the next op and must be parsed normally. A bare suffix
                    // (no parens) stays ignored to match official behaviour.
                    let token_start = i;
                    while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                        i += 1;
                    }
                    let mut j = i;
                    while j < b.len() && b[j].is_ascii_whitespace() {
                        j += 1;
                    }
                    if j < b.len() && b[j] == b'(' {
                        i = token_start;
                        break;
                    }
                }
            } else {
                break;
            }
        }
    }
    Ok(ops)
}

fn push_bare_token(args: &mut Vec<Value>, token: &mut Vec<u8>) -> Result<()> {
    let raw =
        String::from_utf8(std::mem::take(token)).context(i18n::t_str("err.recipe_param_utf8"))?;
    let t = raw.trim().to_string();
    if t.is_empty() {
        return Ok(());
    }
    let v = if t == "true" {
        Value::Bool(true)
    } else if t == "false" {
        Value::Bool(false)
    } else if t == "null" {
        Value::Null
    } else if let Ok(n) = t.parse::<i64>() {
        Value::Number(n.into())
    } else if let Ok(n) = t.parse::<u64>() {
        Value::Number(n.into())
    } else if let Ok(n) = t.parse::<f64>() {
        Value::Number(serde_json::Number::from_f64(n).unwrap_or_else(|| 0.into()))
    } else {
        Value::String(t)
    };
    args.push(v);
    Ok(())
}

// ============================ URL ============================

/// URL recipe parse result: op list + input data (Base64-decoded).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlRecipe {
    pub ops: Vec<RecipeOp>,
    pub input: Option<Vec<u8>>,
}

/// Parse a recipe from a CyberChef share URL.
///
/// Supports `https://gchq.github.io/CyberChef/#recipe=<encoded>&input=<encoded>`.
/// After decoding, a recipe value starting with `[` is parsed as JSON, otherwise
/// as CHEF (pretty).
pub fn from_url(s: &str) -> Result<UrlRecipe> {
    let hash = s.find('#').map(|p| &s[p + 1..]).unwrap_or(s);
    let mut recipe_part: Option<String> = None;
    let mut input_part: Option<String> = None;

    for pair in hash.split('&') {
        let Some(eq) = pair.find('=') else { continue };
        let (k, v) = (&pair[..eq], &pair[eq + 1..]);
        if k == "recipe" {
            recipe_part = Some(v.to_string());
        } else if k == "input" {
            input_part = Some(v.to_string());
        }
    }

    let recipe_enc = recipe_part.context(i18n::t_str("err.url_missing_recipe"))?;
    let recipe_str = percent_decode(&recipe_enc).context(i18n::t_str("err.url_recipe_decode"))?;
    let ops = if recipe_str.trim_start().starts_with('[') {
        from_json(&recipe_str)?
    } else {
        from_chef(&recipe_str)?
    };

    let input = match input_part {
        Some(enc) => {
            let b64 = percent_decode(&enc).context(i18n::t_str("err.url_input_decode"))?;
            Some(
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64.as_bytes())
                    .context(i18n::t_str("err.url_input_base64"))?,
            )
        }
        None => None,
    };

    Ok(UrlRecipe { ops, input })
}

/// Serialize a recipe op list to a CyberChef share URL.
///
/// `input` is optional input data, Base64-encoded into the `&input=` parameter.
pub fn to_url(ops: &[RecipeOp], input: Option<&[u8]>) -> String {
    let chef = to_chef(ops);
    let mut url = format!("{}#recipe={}", RECIPE_BASE_URL, percent_encode(&chef));
    if let Some(data) = input {
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, data);
        url.push_str("&input=");
        url.push_str(&percent_encode(&b64));
    }
    url
}

// ============================ Translation ============================

/// Translate recipe op names to the target language (zh→en / en→zh); names not in the map are kept as-is.
pub fn translate(ops: &[RecipeOp], lang: Lang) -> Vec<RecipeOp> {
    ops.iter()
        .map(|op| {
            let translated = match lang {
                Lang::Zh => recipe_map::en_to_zh(&op.op),
                Lang::En => recipe_map::zh_to_en(&op.op),
            };
            RecipeOp {
                op: translated.unwrap_or(&op.op).to_string(),
                args: op.args.clone(),
                disabled: op.disabled,
                breakpoint: op.breakpoint,
            }
        })
        .collect()
}

// ============================ Top-level conversion ============================

/// Top-level conversion entry: parse → (optional) translate → serialize.
///
/// URL inputs carry their input data automatically; URL outputs pass the input
/// data through (when the input has input data and the target format is URL).
pub fn convert(input: &str, from: Format, to: Format, lang: Option<Lang>) -> Result<String> {
    let mut url_input: Option<Vec<u8>> = None;

    let ops = match from {
        Format::Url => {
            let u = from_url(input)?;
            url_input = u.input.clone();
            u.ops
        }
        Format::Chef => from_chef(input)?,
        Format::Json => from_json(input)?,
    };

    let ops = match lang {
        Some(l) => translate(&ops, l),
        None => ops,
    };

    match to {
        Format::Url => Ok(to_url(&ops, url_input.as_deref())),
        Format::Chef => Ok(to_chef(&ops)),
        Format::Json => Ok(to_json(&ops)),
    }
}

// ============================ URL percent codec ============================

/// encodeURIComponent style: keep unreserved chars plus `'` `(` `)`; other UTF-8 bytes are %XX-encoded.
pub fn percent_encode(s: &str) -> String {
    const UNRESERVED: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.!~*'()";
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if UNRESERVED.contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// URL percent-decoding (`+` stays a literal `+`, no form-space conversion).
pub fn percent_decode(s: &str) -> Result<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0usize;
    while i < b.len() {
        if b[i] == b'%' {
            if i + 2 >= b.len() {
                bail!(
                    "{}",
                    i18n::tf("err.url_percent_incomplete", &[i.to_string().as_str()])
                );
            }
            let hex_s = &s[i + 1..i + 3];
            let byte = u8::from_str_radix(hex_s, 16)
                .with_context(|| i18n::tf("err.url_percent_invalid", &[hex_s]))?;
            out.push(byte);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).context(i18n::t_str("err.url_decode_utf8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_ops() -> Vec<RecipeOp> {
        vec![
            RecipeOp::new("To Base64", vec![Value::String("A-Za-z0-9+/=".into())]),
            RecipeOp::new("To Hex", vec![Value::String("Space".into())]),
        ]
    }

    #[test]
    fn chef_roundtrip() {
        let ops = sample_ops();
        let chef = to_chef(&ops);
        assert_eq!(chef, "To_Base64('A-Za-z0-9+/=')To_Hex('Space')");
        assert_eq!(from_chef(&chef).unwrap(), ops);
    }

    #[test]
    fn chef_flags_roundtrip() {
        let mut a = RecipeOp::new(
            "Fork",
            vec![Value::String("\\n".into()), Value::Bool(false)],
        );
        a.breakpoint = true;
        let mut b = RecipeOp::new("Label", vec![Value::String("base64".into())]);
        b.disabled = true;
        let ops = vec![a, b];
        let chef = to_chef(&ops);
        assert_eq!(
            chef,
            "Fork('\\\\n',false)/breakpointLabel('base64')/disabled"
        );
        assert_eq!(from_chef(&chef).unwrap(), ops);
    }

    #[test]
    fn chef_escapes_quotes_and_backslashes() {
        let ops = vec![RecipeOp::new("X", vec![Value::String("it's \\ ok".into())])];
        let chef = to_chef(&ops);
        assert_eq!(chef, "X('it\\'s \\\\ ok')");
        assert_eq!(from_chef(&chef).unwrap(), ops);
    }

    #[test]
    fn chef_numbers_bools_null() {
        let ops = vec![
            RecipeOp::new("A", vec![Value::from(123), Value::Bool(true), Value::Null]),
            RecipeOp::new("B", vec![Value::from(1.5)]),
        ];
        let chef = to_chef(&ops);
        assert_eq!(chef, "A(123,true,null)B(1.5)");
        assert_eq!(from_chef(&chef).unwrap(), ops);
    }

    #[test]
    fn chef_invalid_raises() {
        assert!(from_chef("To_Base64('x'").is_err());
        assert!(from_chef("NoParen").is_err());
    }

    #[test]
    fn chef_unknown_suffix_ignored() {
        // Aligned with official behaviour: unknown suffixes are ignored silently
        let ops = from_chef("A('x')/wat").unwrap();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].op, "A");
    }

    #[test]
    fn chef_official_slash_separated_ops() {
        // Official CyberChef exports separate ops with '/'. A parenthesised
        // group after '/' is the next op, not an unknown suffix.
        let ops = from_chef("To_Base64('A-Za-z0-9+/=')/Fork('\\\\n',false)").unwrap();
        assert_eq!(ops.len(), 2);
        assert_eq!(ops[0].op, "To Base64");
        assert_eq!(ops[0].args, vec![Value::String("A-Za-z0-9+/=".into())]);
        assert_eq!(ops[1].op, "Fork");
        assert_eq!(
            ops[1].args,
            vec![Value::String("\\n".into()), Value::Bool(false)]
        );
        // flags still work when followed by another op
        let ops = from_chef("Fork('\\\\n',false)/breakpointLabel('base64')/disabled").unwrap();
        assert_eq!(ops.len(), 2);
        assert!(ops[0].breakpoint);
        assert!(ops[1].disabled);
    }

    #[test]
    fn chef_flag_followed_by_op_name() {
        // /breakpointLabel → breakpoint flag + op "Label"
        let ops = from_chef("Fork('\\\\n',false)/breakpointLabel('base64')/disabled").unwrap();
        assert_eq!(ops.len(), 2);
        assert_eq!(ops[0].op, "Fork");
        assert!(ops[0].breakpoint);
        assert!(!ops[0].disabled);
        assert_eq!(ops[1].op, "Label");
        assert!(ops[1].disabled);
        assert!(!ops[1].breakpoint);
    }

    #[test]
    fn json_roundtrip() {
        let ops = sample_ops();
        let json = to_json(&ops);
        assert!(json.contains("\"op\":\"To Base64\""));
        assert!(json.contains("\"op\":\"To Hex\""));
        assert!(json.contains("\"args\":[\"A-Za-z0-9+/=\"]"));
        assert_eq!(from_json(&json).unwrap(), ops);
    }

    #[test]
    fn json_flags_roundtrip() {
        let mut a = RecipeOp::new("Fork", vec![Value::from(10)]);
        a.breakpoint = true;
        a.disabled = true;
        let ops = vec![a];
        let json = to_json(&ops);
        assert!(json.contains("\"disabled\":true"));
        assert!(json.contains("\"breakpoint\":true"));
        assert_eq!(from_json(&json).unwrap(), ops);
    }

    #[test]
    fn json_invalid_raises() {
        assert!(from_json("{}").is_err());
        assert!(from_json("[{\"args\":[]}]").is_err());
    }

    #[test]
    fn url_roundtrip() {
        let ops = sample_ops();
        let input = b"hello world";
        let url = to_url(&ops, Some(input));
        assert!(url.starts_with(RECIPE_BASE_URL));
        assert!(url.contains("#recipe="));
        assert!(url.contains("&input="));
        let parsed = from_url(&url).unwrap();
        assert_eq!(parsed.ops, ops);
        assert_eq!(parsed.input, Some(input.to_vec()));
    }

    #[test]
    fn url_json_recipe_param() {
        let ops = sample_ops();
        let json = to_json(&ops);
        let url = format!("{}#recipe={}", RECIPE_BASE_URL, percent_encode(&json));
        let parsed = from_url(&url).unwrap();
        assert_eq!(parsed.ops, ops);
        assert_eq!(parsed.input, None);
    }

    #[test]
    fn url_no_input_ok() {
        let ops = sample_ops();
        let url = to_url(&ops, None);
        let parsed = from_url(&url).unwrap();
        assert_eq!(parsed.ops, ops);
        assert_eq!(parsed.input, None);
    }

    #[test]
    fn percent_codec_roundtrip() {
        for s in [
            "To_Base64('A-Za-z0-9+/=')",
            "Fork('%5C%5Cn',false)",
            "中文 操作 \"引号\" '单引号' & 等号= 百分号%",
        ] {
            assert_eq!(percent_decode(&percent_encode(s)).unwrap(), s);
        }
        assert_eq!(percent_decode("%E4%B8%AD%E6%96%87").unwrap(), "中文");
        assert_eq!(percent_decode("a+b").unwrap(), "a+b");
    }

    #[test]
    fn percent_decode_invalid() {
        assert!(percent_decode("%ZZ").is_err());
        assert!(percent_decode("%E4%B8").is_err());
    }

    #[test]
    fn translate_zh_to_en_and_back() {
        let zh_ops = vec![
            RecipeOp::new("AES 加密", vec![Value::String("key".into())]),
            RecipeOp::new("转为 Hex", vec![Value::String("Space".into())]),
        ];
        let en = translate(&zh_ops, Lang::En);
        assert_eq!(en[0].op, "AES Encrypt");
        assert_eq!(en[1].op, "To Hex");
        let back = translate(&en, Lang::Zh);
        assert_eq!(back, zh_ops);
    }

    #[test]
    fn translate_unknown_keeps_name() {
        let ops = vec![RecipeOp::new("No Such Op", vec![])];
        let en = translate(&ops, Lang::En);
        assert_eq!(en[0].op, "No Such Op");
    }

    #[test]
    fn convert_chef_to_json_with_translation() {
        let out = convert(
            "AES_Encrypt('key')To_Hex('Space')",
            Format::Chef,
            Format::Json,
            Some(Lang::Zh),
        )
        .unwrap();
        assert!(out.contains("AES 加密"));
        assert!(out.contains("转为 Hex"));
        let back = convert(&out, Format::Json, Format::Chef, Some(Lang::En)).unwrap();
        assert_eq!(back, "AES_Encrypt('key')To_Hex('Space')");
    }

    #[test]
    fn convert_url_to_chef() {
        let url = to_url(&sample_ops(), Some(b"data"));
        let out = convert(&url, Format::Url, Format::Chef, None).unwrap();
        assert_eq!(out, "To_Base64('A-Za-z0-9+/=')To_Hex('Space')");
    }
}
