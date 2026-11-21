//! Structured execution-result outlet: single-op execution and
//! declaration-driven structured views.
//!
//! This module is the v1.0+ "structured outlet" minimal prototype. It adds
//! two new entry points on top of the existing engine pipeline without
//! touching the execution path itself:
//!
//! * [`run_op`]  -  execute exactly one op by name (an engine-side single-step
//!   flow), returning the raw pipeline bytes.
//! * [`inspect`]  -  run an arbitrary flow through the existing bytes pipeline
//!   and then convert the final result to a structured value according to the
//!   op's declared `output_kind` (or an explicit override).

use std::collections::HashMap;

use anyhow::Result;

use crate::engine::EngineConfig;
use crate::error::{ErrorCode, coded};
use crate::flow::{Flow, OutputFormat, Step, from_yaml};
use crate::ops::{OutputKind, find_op, parse_hex};

/// Maximum input size accepted by [`run_op`], kept in sync with the Python
/// binding's `MAX_INPUT_BYTES`.
const MAX_INPUT_BYTES: usize = 64 * 1024 * 1024;

/// Structured representation of an op result after the bytes pipeline.
///
/// `Bytes` mirrors the historical outlet and is returned whenever the op does
/// not declare a structured `output_kind` (or when `Bytes` is requested
/// explicitly).
#[derive(Debug, Clone, PartialEq)]
pub enum Structured {
    /// Raw pipeline bytes (unchanged historical outlet).
    Bytes(Vec<u8>),
    /// UTF-8 text.
    Utf8(String),
    /// JSON document (parsed to the shared JSON-compatible DOM).
    Json(serde_json::Value),
    /// YAML document (parsed to the shared JSON-compatible DOM, matching
    /// `dpa:yaml:to-json`).
    Yaml(serde_json::Value),
    /// Hex-encoded text (validated by the shared codec hex parser).
    Hex(String),
}

/// Execute a single op by name against `data`, returning the raw pipeline
/// bytes. This is the engine-side equivalent of the CLI's `dpa op <name>`
/// single-op path: it builds a one-step flow `[{op: name, args: args}]` and
/// runs it through [`crate::engine::process_bytes_stream`] with `Raw` output,
/// so the execution track stays byte-for-byte identical to a flow run.
pub fn run_op(
    name: &str,
    args: HashMap<String, String>,
    data: &[u8],
    cfg: &EngineConfig,
) -> Result<Vec<u8>> {
    // Fail fast on unknown ops with a registry-backed message; execution
    // itself still goes through the engine (single execution path).
    find_op(name).ok_or_else(|| coded(ErrorCode::UnknownOp, format!("unknown op: {name}")))?;
    if data.len() > MAX_INPUT_BYTES {
        return Err(coded(
            ErrorCode::InputTooLarge,
            crate::i18n::tf(
                "err.input_too_large",
                &[
                    data.len().to_string().as_str(),
                    MAX_INPUT_BYTES.to_string().as_str(),
                ],
            ),
        ));
    }
    let flow = Flow {
        steps: vec![Step {
            op: name.to_string(),
            args,
        }],
        ..Flow::default()
    };
    crate::engine::process_bytes_stream(&flow, data, OutputFormat::Raw, cfg)
}

/// Run `flow` through the existing bytes pipeline, then convert the final
/// result to a structured value.
///
/// The conversion target is resolved in this order:
///
/// 1. `output_kind` when given explicitly (overrides any declaration);
/// 2. otherwise the `output_kind` declared by the flow's final op
///    (see [`crate::ops::OutputKind`]);
/// 3. `Bytes` as the universal fallback for undeclared ops.
pub fn inspect(
    flow: &Flow,
    data: &[u8],
    output_kind: Option<OutputKind>,
    cfg: &EngineConfig,
) -> Result<Structured> {
    let out = crate::engine::process_bytes_stream(flow, data, OutputFormat::Raw, cfg)?;
    let kind = match output_kind {
        Some(k) => k,
        None => flow
            .steps
            .last()
            .and_then(|s| find_op(&s.op))
            .map(|o| o.output_kind)
            .unwrap_or_default(),
    };
    to_structured(out, kind)
}

/// Convert raw pipeline bytes to the requested structured form.
pub fn to_structured(out: Vec<u8>, kind: OutputKind) -> Result<Structured> {
    match kind {
        OutputKind::Bytes => Ok(Structured::Bytes(out)),
        OutputKind::Utf8 => match String::from_utf8(out) {
            Ok(s) => Ok(Structured::Utf8(s)),
            Err(_) => Err(coded(
                ErrorCode::OutputNotUtf8,
                crate::i18n::t("err.output_not_utf8"),
            )),
        },
        OutputKind::Json => {
            let s = utf8_view(out)?;
            let v: serde_json::Value = serde_json::from_str(&s).map_err(|e| {
                coded(
                    ErrorCode::JsonParseFailed,
                    crate::i18n::tf("err.json_parse", &[&e.to_string()]),
                )
            })?;
            Ok(Structured::Json(v))
        }
        OutputKind::Yaml => {
            let s = utf8_view(out)?;
            let v: serde_json::Value = from_yaml(&s).map_err(|e| {
                coded(
                    ErrorCode::YamlParseFailed,
                    crate::i18n::tf("err.yaml_parse", &[&e.to_string()]),
                )
            })?;
            Ok(Structured::Yaml(v))
        }
        OutputKind::Hex => {
            let s = utf8_view(out)?;
            // Validate through the shared codec hex parser so inspect never
            // hands back text that `dpa:hex:decode` would reject.
            parse_hex(&s)?;
            Ok(Structured::Hex(s))
        }
    }
}

fn utf8_view(out: Vec<u8>) -> Result<String> {
    String::from_utf8(out).map_err(|_| {
        coded(
            ErrorCode::OutputNotUtf8,
            crate::i18n::t("err.output_not_utf8"),
        )
    })
}

/// Hard ceiling for batch worker threads: a hostile `jobs` value must not
/// make rayon spawn unbounded threads. 64 workers is far beyond any batch
/// need and keeps pool allocation bounded.
const MAX_BATCH_JOBS: usize = 64;

/// # Stability contract (1.x)
///
/// `api::run_batch` is a **stable 1.x API contract** of the dpa engine: its
/// signature, input-order semantics, per-item failure isolation and structured
/// `{code, category, message}` error payload are relied upon by downstream
/// consumers (notably the dpa-desktop shell through the `desktop` feature).
/// Any breaking change to this function therefore requires a **major**
/// version bump.
///
/// Batch execution outlet: run `flow` against every input item, returning one
/// `Result` per item in **input order**. A failing item does not abort the
/// batch (failure isolation), mirroring the CLI batch path's semantics; the
/// error payload keeps the same `{code, category, message}` contract as the
/// single-op [`run_op`].
///
/// Parallelism: non-wasm builds use rayon with `jobs` worker threads
/// (`0` = `available_parallelism`, matching the CLI `--jobs` default); wasm
/// builds fall back to serial order-preserving execution. The per-item
/// engine limits (input / step-output caps, timeout / cancellation) come from
/// `cfg`, so batch hosts configure one `EngineConfig` for the whole run.
///
/// `jobs` is clamped to [`MAX_BATCH_JOBS`] so a hostile host value cannot
/// make rayon spawn unbounded threads.
#[cfg(not(target_arch = "wasm32"))]
pub fn run_batch(
    flow: &Flow,
    items: &[Vec<u8>],
    fmt: OutputFormat,
    jobs: usize,
    cfg: &EngineConfig,
) -> Vec<Result<Vec<u8>, anyhow::Error>> {
    let threads = if jobs > 0 {
        jobs.min(MAX_BATCH_JOBS)
    } else {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
    };
    match rayon::ThreadPoolBuilder::new().num_threads(threads).build() {
        Ok(pool) => pool.install(|| {
            use rayon::prelude::*;
            items
                .par_iter()
                .map(|item| crate::engine::process_bytes_stream(flow, item, fmt, cfg))
                .collect()
        }),
        Err(_) => items
            .iter()
            .map(|item| crate::engine::process_bytes_stream(flow, item, fmt, cfg))
            .collect(),
    }
}

/// wasm builds have no rayon; execution is serial but keeps the same
/// order-preserving, failure-isolated contract as the host path.
#[cfg(target_arch = "wasm32")]
pub fn run_batch(
    flow: &Flow,
    items: &[Vec<u8>],
    fmt: OutputFormat,
    jobs: usize,
    cfg: &EngineConfig,
) -> Vec<Result<Vec<u8>, anyhow::Error>> {
    let _ = jobs; // serial fallback ignores the parallel hint
    items
        .iter()
        .map(|item| crate::engine::process_bytes_stream(flow, item, fmt, cfg))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn cfg() -> EngineConfig {
        EngineConfig::default()
    }

    fn flow1(op: &str, args: HashMap<String, String>) -> Flow {
        Flow {
            steps: vec![Step {
                op: op.to_string(),
                args,
            }],
            ..Flow::default()
        }
    }

    #[test]
    fn run_op_yaml_to_json() {
        let out = run_op(
            "dpa:yaml:to-json",
            HashMap::new(),
            b"a: 1\nb:\n  - x\n  - y\n".as_slice(),
            &cfg(),
        )
        .unwrap();
        let s = String::from_utf8(out).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["a"], 1);
        assert_eq!(v["b"][1], "y");
    }

    #[test]
    fn run_op_hex_encode() {
        let out = run_op(
            "dpa:hex:encode",
            HashMap::new(),
            &[0xde, 0xad, 0xbe, 0xef],
            &cfg(),
        )
        .unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "deadbeef");
    }

    #[test]
    fn run_op_unknown_fails() {
        assert!(run_op("dpa:no:such:op", HashMap::new(), b"x", &cfg()).is_err());
    }

    #[test]
    fn inspect_json_declared() {
        // Final op declares output_kind=yaml (dpa:json:to-yaml), no explicit
        // kind: inspect should parse the pipeline bytes as YAML.
        let out = inspect(
            &flow1("dpa:json:to-yaml", HashMap::new()),
            br#"{"a":1,"b":[1,2]}"#,
            None,
            &cfg(),
        )
        .unwrap();
        let Structured::Yaml(v) = out else {
            panic!("expected yaml view");
        };
        assert_eq!(v["a"], 1);
        assert_eq!(v["b"][1], 2);
    }

    #[test]
    fn inspect_yaml_declared() {
        let out = inspect(
            &flow1("dpa:yaml:to-json", HashMap::new()),
            b"a: 1\nb: 2\n",
            None,
            &cfg(),
        )
        .unwrap();
        let Structured::Json(v) = out else {
            panic!("expected json view");
        };
        assert_eq!(v["a"], 1);
    }

    #[test]
    fn inspect_hex_declared() {
        let out = inspect(
            &flow1("dpa:hex:encode", HashMap::new()),
            &[0x01, 0x02],
            None,
            &cfg(),
        )
        .unwrap();
        let Structured::Hex(s) = out else {
            panic!("expected hex view");
        };
        assert_eq!(s, "0102");
    }

    #[test]
    fn inspect_undeclared_returns_bytes() {
        let out = inspect(&flow1("dpa:reverse", HashMap::new()), b"abc", None, &cfg()).unwrap();
        let Structured::Bytes(b) = out else {
            panic!("expected bytes view");
        };
        assert_eq!(b, b"cba");
    }

    #[test]
    fn inspect_explicit_kind_overrides() {
        let out = inspect(
            &flow1("dpa:hex:encode", HashMap::new()),
            &[0x0a],
            Some(OutputKind::Utf8),
            &cfg(),
        )
        .unwrap();
        let Structured::Utf8(s) = out else {
            panic!("expected utf8 view");
        };
        assert_eq!(s, "0a");
    }

    #[test]
    fn run_batch_parallel_orders_and_isolates() {
        let flow = flow1("dpa:hex:encode", HashMap::new());
        let items: Vec<Vec<u8>> = vec![vec![0x01, 0x02], vec![0xff, 0xee], vec![0x10, 0x20]];
        let res = run_batch(&flow, &items, OutputFormat::Raw, 2, &cfg());
        assert_eq!(res.len(), 3);
        assert!(res[0].as_ref().unwrap().as_slice() == b"0102");
        assert!(res[1].as_ref().unwrap().as_slice() == b"ffee");
        assert!(res[2].as_ref().unwrap().as_slice() == b"1020");

        // Failure isolation: an unknown op fails every item independently
        // instead of aborting the whole batch.
        let bad = flow1("dpa:no:such:op", HashMap::new());
        let res2 = run_batch(&bad, &items, OutputFormat::Raw, 2, &cfg());
        assert_eq!(res2.len(), 3);
        assert!(res2.iter().all(|r| r.is_err()));
    }

    #[test]
    fn run_batch_respects_config_limits() {
        // A per-item engine cap rejects oversized items while shorter ones
        // still succeed in the same batch (per-item isolation).
        let flow = flow1("dpa:reverse", HashMap::new());
        let tight = EngineConfig::default().with_max_input_bytes(2);
        let items: Vec<Vec<u8>> = vec![b"abcd".to_vec(), b"xy".to_vec(), b"efgh".to_vec()];
        let res = run_batch(&flow, &items, OutputFormat::Raw, 0, &tight);
        assert_eq!(res.len(), 3);
        assert!(res[0].is_err());
        assert_eq!(res[1].as_ref().unwrap().as_slice(), b"yx");
        assert!(res[2].is_err());
    }

    #[test]
    fn engine_config_timeout_fails_with_timeout_code() {
        use std::time::Duration;
        let zero = EngineConfig::default().with_timeout(Some(Duration::ZERO));
        let err = run_op("dpa:reverse", HashMap::new(), b"abc", &zero).unwrap_err();
        let payload = crate::error::to_json(&err);
        assert_eq!(payload["code"], "TIMEOUT");
        assert_eq!(payload["category"], "run");
    }

    #[test]
    fn engine_config_cancel_fails_with_cancelled_code() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        let flag = Arc::new(AtomicBool::new(true));
        let cfg = EngineConfig::default().with_cancel(Some(flag.clone()));
        let err = run_op("dpa:reverse", HashMap::new(), b"abc", &cfg).unwrap_err();
        let payload = crate::error::to_json(&err);
        assert_eq!(payload["code"], "CANCELLED");
        assert_eq!(payload["category"], "run");

        // Unset flag = run proceeds normally.
        flag.store(false, Ordering::Relaxed);
        let out = run_op("dpa:reverse", HashMap::new(), b"abc", &cfg).unwrap();
        assert_eq!(out, b"cba");
    }
}
