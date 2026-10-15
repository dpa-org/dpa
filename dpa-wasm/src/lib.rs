//! dpa Web/WASM engine binding: reuses the Rust core engine on wasm32.
//!
//! This is the *engine-layer* binding only — no GUI. It mirrors the pyo3 binding
//! (`src/python.rs`): flow YAML in, bytes in, rendered bytes out, all through
//! `engine::process_bytes_stream`. Callers can build a Web UI on top later
//! (v1.0+, separate repo).

use wasm_bindgen::prelude::*;

use dpa::flow::{Flow, OutputFormat};
use dpa::{engine, i18n, ops};

fn js_err(e: anyhow::Error) -> JsValue {
    JsValue::from_str(&format!("{:#}", e))
}

fn parse_flow(yaml_text: &str) -> Result<Flow, JsValue> {
    let flow: Flow = serde_yaml::from_str(yaml_text).map_err(|e| {
        JsValue::from_str(&i18n::tf(
            "err.parse_flow_failed",
            &[e.to_string().as_str()],
        ))
    })?;
    if flow.steps.is_empty() {
        return Err(JsValue::from_str(i18n::t("err.empty_steps")));
    }
    Ok(flow)
}

fn resolve_fmt(flow: &Flow, output_format: Option<String>) -> Result<OutputFormat, JsValue> {
    match output_format {
        Some(s) => OutputFormat::parse(&s).map_err(js_err),
        None => match flow.output.as_deref() {
            Some(s) => OutputFormat::parse(s).map_err(js_err),
            None => Ok(OutputFormat::Raw),
        },
    }
}

/// Run a flow in memory: `dpa_wasm.run(flow_yaml, data, output_format?) -> Uint8Array`.
#[wasm_bindgen]
pub fn run(
    flow_yaml: &str,
    data: &[u8],
    output_format: Option<String>,
) -> Result<Vec<u8>, JsValue> {
    let flow = parse_flow(flow_yaml)?;
    let fmt = resolve_fmt(&flow, output_format)?;
    engine::process_bytes_stream(&flow, data, fmt).map_err(js_err)
}

/// Run flows in memory in batch: `dpa_wasm.run_batch(flow_yaml, items: Array<Uint8Array>, output_format?) -> Array<Uint8Array>`.
#[wasm_bindgen]
pub fn run_batch(
    flow_yaml: &str,
    items: js_sys::Array,
    output_format: Option<String>,
) -> Result<js_sys::Array, JsValue> {
    let flow = parse_flow(flow_yaml)?;
    let fmt = resolve_fmt(&flow, output_format)?;

    let out = js_sys::Array::new();
    for item in items.iter() {
        let bytes = js_sys::Uint8Array::new(&item).to_vec();
        let rendered = engine::process_bytes_stream(&flow, &bytes, fmt).map_err(js_err)?;
        out.push(&js_sys::Uint8Array::from(&rendered[..]));
    }
    Ok(out)
}

/// List built-in ops: `dpa_wasm.list_ops(category?) -> JSON string`.
#[wasm_bindgen]
pub fn list_ops(category: Option<String>) -> String {
    let mut all: Vec<&ops::Op> = ops::all_ops().iter().collect();
    if let Some(c) = category {
        all.retain(|o| o.category == c);
    }
    all.sort_by(|a, b| a.name.cmp(&b.name));

    let arr: Vec<serde_json::Value> = all
        .into_iter()
        .map(|o| {
            serde_json::json!({
                "name": &o.name,
                "category": &o.category,
                "description": i18n::t_str(&o.description),
                "args": o.args.iter().map(|a| serde_json::json!({
                    "name": &a.name,
                    "required": a.required,
                    "description": i18n::t_str(a.description),
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    serde_json::to_string(&arr).unwrap_or_else(|_| "[]".to_string())
}

/// Describe a single op: `dpa_wasm.op(name) -> JSON string or null`.
#[wasm_bindgen]
pub fn op(name: &str) -> Option<String> {
    let o = ops::find_op(name)?;
    Some(
        serde_json::json!({
            "name": &o.name,
            "category": &o.category,
            "description": i18n::t_str(&o.description),
            "args": o.args.iter().map(|a| serde_json::json!({
                "name": &a.name,
                "required": a.required,
                "description": i18n::t_str(a.description),
            })).collect::<Vec<_>>(),
        })
        .to_string(),
    )
}

/// Library version: `dpa_wasm.version() -> String`.
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
