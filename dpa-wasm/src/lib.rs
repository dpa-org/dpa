//! dpa Web/WASM engine binding: reuses the Rust core engine on wasm32.
//!
//! This is the *engine-layer* binding only - no GUI. It mirrors the pyo3 binding
//! (`src/python.rs`): flow YAML in, bytes in, rendered bytes out, all through
//! `engine::process_bytes_stream`. Callers can build a Web UI on top later
//! (v1.0+, separate repo).

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;

use dpa::api::{self, Structured};
use dpa::engine::EngineConfig;
use dpa::flow::{Flow, OutputFormat};
use dpa::ops::OutputKind;
use dpa::{engine, i18n, ops};

/// WASM hosts configure the engine through the exported setters; values are
/// stored per-wasm-instance (single-threaded) and passed by value into each
/// `run` call (the engine core keeps no process-wide state).
static WASM_CFG: LazyLock<Mutex<EngineConfig>> =
    LazyLock::new(|| Mutex::new(EngineConfig::default()));

fn current_cfg() -> EngineConfig {
    WASM_CFG.lock().unwrap().clone()
}

fn js_err(e: anyhow::Error) -> JsValue {
    // Structured error contract: hosts receive `{code, category, message}`
    // as JSON text in the thrown Error's `message`, so callers can branch on
    // `code` without parsing human text.
    JsValue::from_str(&dpa::error::to_json(&e).to_string())
}

fn parse_flow(yaml_text: &str) -> Result<Flow, JsValue> {
    let flow: Flow = dpa::flow::from_yaml(yaml_text).map_err(|e| {
        js_err(dpa::error::coded(
            dpa::error::ErrorCode::ParseFlowFailed,
            i18n::tf("err.parse_flow_failed", &[e.to_string().as_str()]),
        ))
    })?;
    if flow.steps.is_empty() {
        return Err(js_err(dpa::error::coded(
            dpa::error::ErrorCode::EmptySteps,
            i18n::t("err.empty_steps"),
        )));
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

/// Convert a JS object (or null/undefined) into an op-arg map. Values must be
/// strings, matching the CLI/Python arg contract (`HashMap<String, String>`).
fn js_args_to_map(args: &JsValue) -> Result<HashMap<String, String>, JsValue> {
    if args.is_null() || args.is_undefined() {
        return Ok(HashMap::new());
    }
    let obj = args
        .dyn_ref::<js_sys::Object>()
        .ok_or_else(|| JsValue::from_str("op args must be a plain object"))?;
    let entries = js_sys::Object::entries(obj);
    let mut map = HashMap::new();
    for entry in entries.iter() {
        let pair = entry.unchecked_into::<js_sys::Array>();
        let key = pair
            .get(0)
            .as_string()
            .ok_or_else(|| JsValue::from_str("op args keys must be strings"))?;
        let val = pair
            .get(1)
            .as_string()
            .ok_or_else(|| JsValue::from_str("op args values must be strings"))?;
        map.insert(key, val);
    }
    Ok(map)
}

/// Convert the shared JSON DOM into a JS value.
fn json_to_js(v: &serde_json::Value) -> JsValue {
    match v {
        serde_json::Value::Null => JsValue::NULL,
        serde_json::Value::Bool(b) => JsValue::from_bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                JsValue::from_f64(i as f64)
            } else if let Some(f) = n.as_f64() {
                JsValue::from_f64(f)
            } else {
                JsValue::from_str(&n.to_string())
            }
        }
        serde_json::Value::String(s) => JsValue::from_str(s),
        serde_json::Value::Array(a) => {
            let arr = js_sys::Array::new();
            for item in a {
                arr.push(&json_to_js(item));
            }
            arr.into()
        }
        serde_json::Value::Object(o) => {
            let obj = js_sys::Object::new();
            for (k, val) in o {
                js_sys::Reflect::set(&obj, &JsValue::from_str(k), &json_to_js(val))
                    .expect("reflect set cannot fail on a plain object");
            }
            obj.into()
        }
    }
}

/// Serialize a structured view result to a JS value (mirrors the Python
/// binding's `structured_to_py`): Bytes -> Uint8Array, Utf8/Hex -> string,
/// Json/Yaml -> JS object.
fn structured_to_js(s: Structured) -> JsValue {
    match s {
        Structured::Bytes(b) => js_sys::Uint8Array::from(&b[..]).into(),
        Structured::Utf8(t) | Structured::Hex(t) => JsValue::from_str(&t),
        Structured::Json(v) | Structured::Yaml(v) => json_to_js(&v),
    }
}

/// Full schema-level JSON for a single op (aligned with CLI `show_op`).
fn op_to_json(o: &ops::Op) -> serde_json::Value {
    serde_json::json!({
        "name": &o.name,
        "category": &o.category,
        "family": &o.family,
        "kind": &o.kind,
        "level": o.level.display(),
        "input": o.input.display(),
        "output": o.output.display(),
        "output_kind": o.output_kind.display(),
        "description": i18n::t_str(&o.description),
        "example": o.example.map(i18n::t_str),
        "args": o.args.iter().map(|a| serde_json::json!({
            "name": a.name,
            "required": a.required,
            "description": i18n::t_str(a.description),
            "format": a.format.display(),
        })).collect::<Vec<_>>(),
    })
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
    let cfg = current_cfg();
    engine::process_bytes_stream(&flow, data, fmt, &cfg).map_err(js_err)
}

/// Run flows in memory in batch: `dpa_wasm.run_batch(flow_yaml, items: Array<Uint8Array>, output_format?, jobs?) -> Array<Uint8Array>`.
///
/// Returns one rendered item per input in input order. A failing item is
/// returned as an **error string** in the same array slot (failure isolation,
/// mirroring the host `api::run_batch` contract): the slot value is
/// `Uint8Array` on success and `String` (the structured `{code, category,
/// message}` JSON) on failure. On wasm there is no rayon, so execution is
/// serial; the `jobs` hint is accepted for API compatibility and ignored.
#[wasm_bindgen]
pub fn run_batch(
    flow_yaml: &str,
    items: js_sys::Array,
    output_format: Option<String>,
    jobs: Option<usize>,
) -> Result<js_sys::Array, JsValue> {
    let _ = jobs; // serial fallback ignores the parallel hint
    let flow = parse_flow(flow_yaml)?;
    let fmt = resolve_fmt(&flow, output_format)?;

    let cfg = current_cfg();
    let out = js_sys::Array::new();
    for item in items.iter() {
        let bytes = js_sys::Uint8Array::new(&item).to_vec();
        match engine::process_bytes_stream(&flow, &bytes, fmt, &cfg) {
            Ok(rendered) => out.push(&js_sys::Uint8Array::from(&rendered[..])),
            Err(e) => out.push(&JsValue::from_str(&dpa::error::to_json(&e).to_string())),
        };
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

    let arr: Vec<serde_json::Value> = all.into_iter().map(op_to_json).collect();
    serde_json::to_string(&arr).unwrap_or_else(|_| "[]".to_string())
}

/// Describe a single op: `dpa_wasm.op(name) -> JSON string or null`.
#[wasm_bindgen]
pub fn op(name: &str) -> Option<String> {
    let o = ops::find_op(name)?;
    Some(op_to_json(o).to_string())
}

/// Library version: `dpa_wasm.version() -> String`.
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Configure the whole-input byte cap (bytes; 0 = unlimited).
/// WASM hosts could not previously adjust the 256 MiB default
/// for browser memory-constrained environments.
#[wasm_bindgen]
pub fn set_max_input_bytes(n: usize) {
    let mut g = WASM_CFG.lock().unwrap();
    *g = g.clone().with_max_input_bytes(n);
}

/// Configure the per-step streaming output cap (bytes; 0 = unlimited).
#[wasm_bindgen]
pub fn set_max_step_output_bytes(n: usize) {
    let mut g = WASM_CFG.lock().unwrap();
    *g = g.clone().with_max_step_output_bytes(n);
}

/// Enable/disable per-step timing / byte accounting on stderr (`--verbose`).
#[wasm_bindgen]
pub fn set_verbose(on: bool) {
    let mut g = WASM_CFG.lock().unwrap();
    *g = g.clone().with_verbose(on);
}

/// Execute a single op by name:
/// `dpa_wasm.run_op(name, args: object|null, data: Uint8Array) -> Uint8Array`.
/// Mirrors the Python binding's `run_op` through `api::run_op` (registry
/// validation + single-step flow on the same engine pipeline).
#[wasm_bindgen]
pub fn run_op(name: &str, args: JsValue, data: &[u8]) -> Result<Vec<u8>, JsValue> {
    let args = js_args_to_map(&args)?;
    let cfg = current_cfg();
    api::run_op(name, args, data, &cfg).map_err(js_err)
}

/// Run a flow and return a structured view of the final result:
/// `dpa_wasm.inspect(flow_yaml, data, output_kind?) -> Uint8Array | string | object`.
/// Mirrors the Python binding's `inspect`: without `output_kind` the flow's
/// final op declaration is used; undeclared ops fall back to raw bytes.
#[wasm_bindgen]
pub fn inspect(
    flow_yaml: &str,
    data: &[u8],
    output_kind: Option<String>,
) -> Result<JsValue, JsValue> {
    let flow = parse_flow(flow_yaml)?;
    let kind = match output_kind {
        Some(s) => Some(OutputKind::parse(&s).ok_or_else(|| {
            js_err(dpa::error::coded(
                dpa::error::ErrorCode::InvalidOutputFormat,
                format!("unknown output_kind: {s}"),
            ))
        })?),
        None => None,
    };
    let cfg = current_cfg();
    let out = api::inspect(&flow, data, kind, &cfg).map_err(js_err)?;
    Ok(structured_to_js(out))
}

/// Schema contract version: bumped whenever `list_ops` / `op` field layouts
/// change, so desktop hosts can decide when to refresh their op catalog.
const SCHEMA_VERSION: &str = "1";

/// Engine metadata / capability probe:
/// `dpa_wasm.meta() -> {version, schema_version, ops_total, categories}`.
#[wasm_bindgen]
pub fn meta() -> String {
    let mut categories: Vec<String> = ops::all_ops().iter().map(|o| o.category.clone()).collect();
    categories.sort();
    categories.dedup();
    serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "schema_version": SCHEMA_VERSION,
        "ops_total": ops::all_ops().len(),
        "categories": categories,
    })
    .to_string()
}

/// Read side for the whole-input byte cap (0 = unlimited).
#[wasm_bindgen]
pub fn get_max_input_bytes() -> usize {
    current_cfg().max_input_bytes()
}

/// Read side for the per-step output cap (0 = unlimited).
#[wasm_bindgen]
pub fn get_max_step_output_bytes() -> usize {
    current_cfg().max_step_output_bytes()
}

/// Read side for the verbose flag.
#[wasm_bindgen]
pub fn get_verbose() -> bool {
    current_cfg().verbose()
}
