//! Python bindings (pyo3): run flows in memory after `import dpa`.
//!
//! Compiled only with the `python` feature. Usage example: examples/python_demo.py.

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};

use crate::engine;
use crate::flow::{Flow, OutputFormat};
use crate::i18n;
use crate::ops;

fn py_err(e: anyhow::Error) -> PyErr {
    PyRuntimeError::new_err(format!("{:#}", e))
}

fn parse_flow(yaml_text: &str) -> PyResult<Flow> {
    let flow: Flow = serde_yaml::from_str(yaml_text).map_err(|e| {
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
    let out = engine::process_bytes_stream(&flow, data, fmt).map_err(py_err)?;
    Ok(Python::with_gil(|py| PyBytes::new(py, &out).into()))
}

/// Run flows in memory in batch: `dpa.run_batch(flow_yaml, items, output_format=None) -> list[bytes]`.
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
            py.detach()
                .allow_threads(|| engine::process_bytes_stream(&flow, &item, fmt).map_err(py_err))
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
        PyRuntimeError::new_err(i18n::tf("err.read_flow_failed", &[e.to_string().as_str()]))
    })?;
    let flow = parse_flow(&yaml_text)?;
    let fmt = resolve_fmt(&flow, output_format)?;
    let data = std::fs::read(input_path).map_err(|e| {
        PyRuntimeError::new_err(i18n::tf("err.read_input_failed", &[e.to_string().as_str()]))
    })?;
    let out = engine::process_bytes_stream(&flow, &data, fmt).map_err(py_err)?;
    match output_path {
        Some(p) => {
            std::fs::write(p, &out).map_err(|e| {
                PyRuntimeError::new_err(i18n::tf(
                    "err.write_outfile_failed",
                    &[e.to_string().as_str()],
                ))
            })?;
            Ok(None)
        }
        None => Ok(Some(Python::with_gil(|py| PyBytes::new(py, &out).into()))),
    }
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
            d.set_item("description", i18n::t_str(&o.description))?;
            let args = PyList::empty(py);
            for a in o.args {
                let ad = PyDict::new(py);
                ad.set_item("name", a.name.as_str())?;
                ad.set_item("required", a.required)?;
                ad.set_item("description", i18n::t_str(&a.description))?;
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
            d.set_item("description", i18n::t_str(&o.description))?;
            let args = PyList::empty(py);
            for a in o.args {
                let ad = PyDict::new(py);
                ad.set_item("name", a.name.as_str())?;
                ad.set_item("required", a.required)?;
                ad.set_item("description", i18n::t_str(&a.description))?;
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
    m.add_function(wrap_pyfunction!(list_ops, m)?)?;
    m.add_function(wrap_pyfunction!(op, m)?)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
