//! Python bindings (pyo3): run flows in memory after `import dpa`.
//!
//! Compiled only with the `python` feature. Usage example: examples/python_demo.py.

use pyo3::exceptions::{PyRuntimeError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PyString};

use crate::api::{self, Structured};
use crate::engine;
use crate::flow::{Flow, OutputFormat, from_yaml};
use crate::i18n;
use crate::ops;
use crate::ops::OutputKind;

/// Upper bound for a flow YAML document passed through the Python bindings
/// (8 MiB). Mirrors the CLI-side `MAX_FLOW_YAML_BYTES` in engine.rs so the
/// Python in-memory parse cannot bypass the engine cap.
const MAX_FLOW_YAML_BYTES: usize = 8 * 1024 * 1024;
/// Upper bound for an input file read by `run_file` (1 GiB). Mirrors the
/// engine's derived-key material bound so the in-memory whole-file path can
/// never silently exhaust memory.
const MAX_INPUT_BYTES: u64 = 1 << 30;

fn py_err(e: anyhow::Error) -> PyErr {
    PyRuntimeError::new_err(format!("{:#}", e))
}

fn parse_flow(yaml_text: &str) -> PyResult<Flow> {
    if yaml_text.len() > MAX_FLOW_YAML_BYTES {
        return Err(PyValueError::new_err(i18n::tf(
            "err.flow_too_large",
            &[
                yaml_text.len().to_string().as_str(),
                MAX_FLOW_YAML_BYTES.to_string().as_str(),
            ],
        )));
    }
    let flow: Flow = from_yaml(yaml_text).map_err(|e| {
        PyValueError::new_err(i18n::tf("err.parse_flow_failed", &[e.to_string().as_str()]))
    })?;
    if flow.steps.is_empty() {
        return Err(PyValueError::new_err(i18n::t("err.empty_steps")));
    }
    Ok(flow)
}

fn resolve_fmt(flow: &Flow, output_format: Option<&str>) -> PyResult<OutputFormat> {
    match output_format {
        Some(s) => OutputFormat::parse(s).map_err(py_err),
        None => match flow.output.as_deref() {
            Some(s) => OutputFormat::parse(s).map_err(py_err),
            None => Ok(OutputFormat::Raw),
        },
    }
}

/// Run a flow in memory: `dpa.run(flow_yaml, data, output_format=None) -> bytes`.
#[pyfunction]
#[pyo3(signature = (flow_yaml, data, output_format=None))]
fn run(flow_yaml: &str, data: &[u8], output_format: Option<&str>) -> PyResult<Py<PyBytes>> {
    let flow = parse_flow(flow_yaml)?;
    let fmt = resolve_fmt(&flow, output_format)?;
    let out = engine::process_bytes_stream(&flow, data, fmt, &engine::EngineConfig::default())
        .map_err(py_err)?;
    Ok(Python::with_gil(|py| PyBytes::new(py, &out).into()))
}

/// Run flows in memory in batch: `dpa.run_batch(flow_yaml, items, output_format=None) -> list[bytes]`.
/// Items are processed **sequentially** in input order; parallel execution is
/// intentionally deferred until the EngineConfig migration lands, so no
/// ordering or thread-affinity guarantee exists beyond FIFO completion today.
#[pyfunction]
#[pyo3(signature = (flow_yaml, items, output_format=None))]
fn run_batch(
    flow_yaml: &str,
    items: Vec<Vec<u8>>,
    output_format: Option<&str>,
) -> PyResult<Vec<Py<PyBytes>>> {
    let flow = parse_flow(flow_yaml)?;
    let fmt = resolve_fmt(&flow, output_format)?;
    // Release the GIL while the engine runs so other Python threads can make
    // progress; the GIL is only re-acquired to wrap each result in PyBytes.
    let mut outs = Vec::with_capacity(items.len());
    let mut failed = 0usize;
    let mut first_err: Option<PyErr> = None;
    for item in items {
        let res = Python::with_gil(|py| {
            py.allow_threads(|| {
                engine::process_bytes_stream(&flow, &item, fmt, &engine::EngineConfig::default())
                    .map_err(py_err)
            })
        });
        match res {
            Ok(out) => outs.push(Python::with_gil(|py| PyBytes::new(py, &out).into())),
            Err(e) => {
                failed += 1;
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }
    }
    if failed > 0 {
        let n_ok = outs.len();
        let detail = first_err.map(|e| format!("{:?}", e)).unwrap_or_default();
        return Err(PyRuntimeError::new_err(i18n::tf(
            "err.batch_partial_failure",
            &[
                n_ok.to_string().as_str(),
                failed.to_string().as_str(),
                detail.as_str(),
            ],
        )));
    }
    Ok(outs)
}

/// Run a flow file: `dpa.run_file(flow_path, input_path, output_path=None, output_format=None)`.
#[pyfunction]
#[pyo3(signature = (flow_path, input_path, output_path=None, output_format=None))]
fn run_file(
    flow_path: &str,
    input_path: &str,
    output_path: Option<&str>,
    output_format: Option<&str>,
) -> PyResult<Option<Py<PyBytes>>> {
    let yaml_text = std::fs::read_to_string(flow_path).map_err(|e| {
        PyRuntimeError::new_err(i18n::tf(
            "err.read_flow_failed",
            &[flow_path, i18n::os_error(&e).as_str()],
        ))
    })?;
    let flow = parse_flow(&yaml_text)?;
    let fmt = resolve_fmt(&flow, output_format)?;
    let input_len = std::fs::metadata(input_path).map(|m| m.len()).unwrap_or(0);
    if input_len > MAX_INPUT_BYTES {
        return Err(PyRuntimeError::new_err(i18n::tf(
            "err.input_too_large",
            &[
                input_len.to_string().as_str(),
                MAX_INPUT_BYTES.to_string().as_str(),
            ],
        )));
    }
    let data = std::fs::read(input_path).map_err(|e| {
        PyRuntimeError::new_err(i18n::tf(
            "err.read_input_failed",
            &[input_path, i18n::os_error(&e).as_str()],
        ))
    })?;
    let out = engine::process_bytes_stream(&flow, &data, fmt, &engine::EngineConfig::default())
        .map_err(py_err)?;
    match output_path {
        Some(p) => {
            // Atomic output: reuse the engine's tmp+commit path so an
            // interrupted run never leaves a half-written file at `p`
            // (see the engine's atomic-write contract).
            let mut of = engine::open_file_writer(p).map_err(py_err)?;
            of.writer_mut().write_all(&out).map_err(|e| {
                PyRuntimeError::new_err(i18n::tf(
                    "err.write_outfile_failed",
                    &[i18n::os_error(&e).as_str()],
                ))
            })?;
            of.commit().map_err(|e| {
                PyRuntimeError::new_err(i18n::tf(
                    "err.write_outfile_failed",
                    &[i18n::os_error(&e).as_str()],
                ))
            })?;
            Ok(None)
        }
        None => Ok(Some(Python::with_gil(|py| PyBytes::new(py, &out).into()))),
    }
}

/// Convert an optional Python dict into op args (`str -> str`). Non-string
/// scalar values are stringified the same way the YAML flow parser would
/// normalize them, so `args={'offset': 1}` behaves like `offset: 1`.
fn py_args(
    args: Option<&Bound<'_, PyDict>>,
) -> PyResult<std::collections::HashMap<String, String>> {
    let mut out = std::collections::HashMap::new();
    if let Some(d) = args {
        for (k, v) in d.iter() {
            let key: String = k.extract()?;
            let val = match v.extract::<String>() {
                Ok(s) => s,
                Err(_) => py_scalar_to_string(&v)?,
            };
            out.insert(key, val);
        }
    }
    Ok(out)
}

/// Stringify a Python scalar (int/float/bool/None) for op args.
fn py_scalar_to_string(v: &Bound<'_, PyAny>) -> PyResult<String> {
    if v.is_none() {
        return Ok("null".to_string());
    }
    if let Ok(b) = v.extract::<bool>() {
        return Ok(if b {
            "true".to_string()
        } else {
            "false".to_string()
        });
    }
    if let Ok(i) = v.extract::<i64>() {
        return Ok(i.to_string());
    }
    if let Ok(f) = v.extract::<f64>() {
        return Ok(f.to_string());
    }
    Err(PyValueError::new_err(
        "unsupported arg value type for key (expected str/int/float/bool/None)",
    ))
}

/// Convert a Python object to the shared JSON DOM for flow construction.
fn py_to_json(v: &Bound<'_, PyAny>) -> PyResult<serde_json::Value> {
    if v.is_none() {
        return Ok(serde_json::Value::Null);
    }
    if let Ok(b) = v.extract::<bool>() {
        return Ok(serde_json::Value::Bool(b));
    }
    if let Ok(i) = v.extract::<i64>() {
        return Ok(serde_json::Value::from(i));
    }
    if let Ok(f) = v.extract::<f64>() {
        return Ok(serde_json::Value::from(f));
    }
    if let Ok(s) = v.extract::<String>() {
        return Ok(serde_json::Value::String(s));
    }
    if let Ok(list) = v.downcast::<PyList>() {
        let mut arr = Vec::with_capacity(list.len());
        for item in list.iter() {
            arr.push(py_to_json(&item)?);
        }
        return Ok(serde_json::Value::Array(arr));
    }
    if let Ok(dict) = v.downcast::<PyDict>() {
        let mut map = serde_json::Map::new();
        for (k, val) in dict.iter() {
            let key: String = k.extract()?;
            map.insert(key, py_to_json(&val)?);
        }
        return Ok(serde_json::Value::Object(map));
    }
    Err(PyValueError::new_err("unsupported Python value for flow"))
}

/// Build a [`Flow`] from a Python `str` (YAML) or `dict` (`{steps: [...]}`).
fn py_flow(flow: &Bound<'_, PyAny>) -> PyResult<Flow> {
    if let Ok(s) = flow.extract::<String>() {
        return parse_flow(&s);
    }
    let v = py_to_json(flow)?;
    serde_json::from_value(v).map_err(|e| {
        PyValueError::new_err(i18n::tf("err.parse_flow_failed", &[e.to_string().as_str()]))
    })
}

/// Convert a structured view result to its Python counterpart.
fn structured_to_py(py: Python<'_>, s: Structured) -> PyResult<PyObject> {
    match s {
        Structured::Bytes(b) => Ok(PyBytes::new(py, &b).into()),
        Structured::Utf8(t) => Ok(PyString::new(py, &t).into()),
        Structured::Hex(t) => Ok(PyString::new(py, &t).into()),
        Structured::Json(v) | Structured::Yaml(v) => json_to_py(py, &v),
    }
}

/// Convert the shared JSON DOM to Python builtins.
fn json_to_py(py: Python<'_>, v: &serde_json::Value) -> PyResult<PyObject> {
    Ok(match v {
        serde_json::Value::Null => py.None(),
        serde_json::Value::Bool(b) => pyo3::types::PyBool::new(py, *b)
            .to_owned()
            .into_any()
            .unbind(),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i.into_pyobject(py)?.into_any().unbind()
            } else if let Some(f) = n.as_f64() {
                f.into_pyobject(py)?.into_any().unbind()
            } else {
                n.to_string().into_pyobject(py)?.into_any().unbind()
            }
        }
        serde_json::Value::String(s) => s.as_str().into_pyobject(py)?.into_any().unbind(),
        serde_json::Value::Array(a) => {
            let list = PyList::empty(py);
            for item in a {
                list.append(json_to_py(py, item)?)?;
            }
            list.into_any().unbind()
        }
        serde_json::Value::Object(o) => {
            let d = PyDict::new(py);
            for (k, val) in o {
                d.set_item(k, json_to_py(py, val)?)?;
            }
            d.into_any().unbind()
        }
    })
}

/// Convert the optional `data` argument (str | bytes) into raw input bytes.
/// Text ops (JSON/YAML/hex text in) accept a plain Python `str`, encoded as
/// UTF-8; binary ops accept `bytes`; anything else is rejected up front.
fn py_data_bytes(data: Option<&Bound<'_, PyAny>>) -> PyResult<Vec<u8>> {
    match data {
        None => Ok(Vec::new()),
        Some(v) => {
            if let Ok(s) = v.extract::<String>() {
                return Ok(s.into_bytes());
            }
            if let Ok(b) = v.downcast::<PyBytes>() {
                return Ok(b.as_bytes().to_vec());
            }
            Err(PyTypeError::new_err("data must be str or bytes"))
        }
    }
}

/// Execute a single op in memory: `dpa.run_op(name, args=None, data=b'') ->
/// bytes`. Mirrors the CLI's `dpa op <name>` single-op path through the
/// engine's single-step flow runner.
#[pyfunction]
#[pyo3(signature = (name, args=None, data=None))]
fn run_op(
    name: &str,
    args: Option<&Bound<'_, PyDict>>,
    data: Option<&Bound<'_, PyAny>>,
) -> PyResult<Py<PyBytes>> {
    let args = py_args(args)?;
    let data = py_data_bytes(data)?;
    let out = api::run_op(name, args, &data, &engine::EngineConfig::default()).map_err(py_err)?;
    Python::with_gil(|py| Ok(PyBytes::new(py, &out).into()))
}

/// Run a flow and return a structured view of the final result:
/// `dpa.inspect(flow, data=b'', output_kind=None) -> bytes | str | dict |
/// list | None`. `flow` may be a YAML string or a `{steps: [...]}` dict.
/// Without `output_kind` the flow's final op declaration is used; undeclared
/// ops fall back to raw `bytes`.
#[pyfunction]
#[pyo3(signature = (flow, data=None, output_kind=None))]
fn inspect(
    flow: &Bound<'_, PyAny>,
    data: Option<&Bound<'_, PyAny>>,
    output_kind: Option<&str>,
) -> PyResult<PyObject> {
    let flow = py_flow(flow)?;
    let data = py_data_bytes(data)?;
    let kind = match output_kind {
        Some(s) => Some(
            OutputKind::parse(s)
                .ok_or_else(|| PyValueError::new_err(format!("unknown output_kind: {s}")))?,
        ),
        None => None,
    };
    let out = api::inspect(&flow, &data, kind, &engine::EngineConfig::default()).map_err(py_err)?;
    Python::with_gil(|py| structured_to_py(py, out))
}

/// List built-in ops: `dpa.list_ops(category=None) -> list[dict]`.
#[pyfunction]
#[pyo3(signature = (category=None))]
fn list_ops(category: Option<&str>) -> PyResult<Vec<Py<PyDict>>> {
    let all = ops::all_ops();
    let mut filtered: Vec<&ops::Op> = all.iter().collect();
    if let Some(c) = category {
        filtered.retain(|o| o.category == c);
    }
    filtered.sort_by(|a, b| a.name.cmp(&b.name));

    Python::with_gil(|py| {
        let mut out = Vec::with_capacity(filtered.len());
        for o in filtered {
            let d = PyDict::new(py);
            d.set_item("name", o.name.as_str())?;
            d.set_item("category", o.category.as_str())?;
            d.set_item("family", o.family.as_str())?;
            d.set_item("kind", o.kind.as_str())?;
            d.set_item("level", o.level.display())?;
            d.set_item("input", o.input.display())?;
            d.set_item("output", o.output.display())?;
            d.set_item("description", i18n::t_str(&o.description))?;
            d.set_item("output_kind", o.output_kind.display())?;
            match o.example {
                Some(ek) => d.set_item("example", i18n::t_str(ek))?,
                None => d.set_item("example", py.None())?,
            }
            let args = PyList::empty(py);
            for a in o.args {
                let ad = PyDict::new(py);
                ad.set_item("name", a.name)?;
                ad.set_item("required", a.required)?;
                ad.set_item("description", i18n::t_str(a.description))?;
                ad.set_item("format", a.format.display())?;
                args.append(ad)?;
            }
            d.set_item("args", args)?;
            out.push(d.into());
        }
        Ok(out)
    })
}

/// Query a single op: `dpa.op(name) -> dict | None`.
#[pyfunction]
fn op(name: &str) -> PyResult<Option<Py<PyDict>>> {
    match ops::find_op(name) {
        Some(o) => Python::with_gil(|py| {
            let d = PyDict::new(py);
            d.set_item("name", o.name.as_str())?;
            d.set_item("category", o.category.as_str())?;
            d.set_item("family", o.family.as_str())?;
            d.set_item("kind", o.kind.as_str())?;
            d.set_item("level", o.level.display())?;
            d.set_item("input", o.input.display())?;
            d.set_item("output", o.output.display())?;
            d.set_item("description", i18n::t_str(&o.description))?;
            d.set_item("output_kind", o.output_kind.display())?;
            match o.example {
                Some(ek) => d.set_item("example", i18n::t_str(ek))?,
                None => d.set_item("example", py.None())?,
            }
            let args = PyList::empty(py);
            for a in o.args {
                let ad = PyDict::new(py);
                ad.set_item("name", a.name)?;
                ad.set_item("required", a.required)?;
                ad.set_item("description", i18n::t_str(a.description))?;
                ad.set_item("format", a.format.display())?;
                args.append(ad)?;
            }
            d.set_item("args", args)?;
            Ok(Some(d.into()))
        }),
        None => Ok(None),
    }
}

/// pyo3 module entry: `import dpa`.
#[pymodule]
fn dpa(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(run, m)?)?;
    m.add_function(wrap_pyfunction!(run_batch, m)?)?;
    m.add_function(wrap_pyfunction!(run_file, m)?)?;
    m.add_function(wrap_pyfunction!(run_op, m)?)?;
    m.add_function(wrap_pyfunction!(inspect, m)?)?;
    m.add_function(wrap_pyfunction!(list_ops, m)?)?;
    m.add_function(wrap_pyfunction!(op, m)?)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
