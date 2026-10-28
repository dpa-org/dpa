//! Codec family: yaml/json/xml format conversions.

use std::collections::HashMap;

use crate::flow::from_yaml;

// ---------------------------------------------------------------------------
// YAML / XML <-> JSON
// ---------------------------------------------------------------------------

pub(crate) fn yaml_to_json(
    input: &[u8],
    _args: &HashMap<String, String>,
) -> anyhow::Result<Vec<u8>> {
    let s = String::from_utf8_lossy(input);
    let v: serde_json::Value = from_yaml(&s).map_err(|e| anyhow::anyhow!("{}", e))?;
    Ok(serde_json::to_vec(&v)?)
}

pub(crate) fn json_to_yaml(
    input: &[u8],
    _args: &HashMap<String, String>,
) -> anyhow::Result<Vec<u8>> {
    let v: serde_json::Value = serde_json::from_slice(input)?;
    let s = serde_saphyr::to_string(&v).map_err(|e| anyhow::anyhow!("{}", e))?;
    Ok(s.into_bytes())
}

pub(crate) fn xml_to_json(
    input: &[u8],
    _args: &HashMap<String, String>,
) -> anyhow::Result<Vec<u8>> {
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
                let txt = quick_xml::escape::unescape(
                    std::str::from_utf8(&e).map_err(|err| anyhow::anyhow!("{err}"))?,
                )
                .map_err(|err| anyhow::anyhow!("{err}"))?
                .into_owned();
                if let Some((_, m)) = stack.last_mut()
                    && !txt.is_empty()
                {
                    match m.get_mut("#text") {
                        Some(Value::String(s)) => s.push_str(&txt),
                        _ => {
                            m.insert("#text".to_string(), Value::String(txt));
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

pub(crate) fn json_to_xml(
    input: &[u8],
    _args: &HashMap<String, String>,
) -> anyhow::Result<Vec<u8>> {
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

#[cfg(test)]
mod tests {
    use super::*;

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
        let back: serde_json::Value = from_yaml(&y).unwrap();
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
}
