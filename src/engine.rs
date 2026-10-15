//! Execution engine: read a flow -> expand inputs -> run every step (optionally in parallel) -> output.
//!
//! Batch support: multiple input files, directory expansion (recursive optional), file-level parallelism.

use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[cfg(not(target_arch = "wasm32"))]
use rayon::prelude::*;

use crate::flow::{Flow, OutputFormat};
use crate::i18n;
use crate::ops;

/// IO buffer size: 1 MiB, balancing throughput and memory.
const IO_BUF: usize = 1 << 20;

/// Default cap for whole-buffer input and Fork output accumulation (256 MiB).
/// Guards the [`BarrierStream`] buffer and the Fork join against
/// memory-exhaustion inputs (review §3-F).
pub const DEFAULT_MAX_INPUT_BYTES: usize = 256 << 20;

/// Process-wide input/output byte cap, overridable via `--max-input-bytes`.
static MAX_INPUT_BYTES: AtomicUsize = AtomicUsize::new(DEFAULT_MAX_INPUT_BYTES);

/// Configure the input/output byte cap (CLI `--max-input-bytes`).
pub fn set_max_input_bytes(n: usize) {
    MAX_INPUT_BYTES.store(n.max(1), Ordering::Relaxed);
}

/// Current input/output byte cap.
pub fn max_input_bytes() -> usize {
    MAX_INPUT_BYTES.load(Ordering::Relaxed)
}

/// Per-step observability switch (review G11, `--verbose`).
static VERBOSE: AtomicBool = AtomicBool::new(false);

/// Enable per-step timing / byte accounting on stderr (`--verbose`).
pub fn set_verbose(on: bool) {
    VERBOSE.store(on, Ordering::Relaxed);
}

/// Whether per-step observability is enabled.
pub fn is_verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

/// Flow-control op: Fork. The engine intercepts it in
/// [`process_bytes`]: all remaining steps run independently on each segment
/// and the results are joined with the same separator (CyberChef Fork semantics).
const FORK_OP: &str = "dpa:fork";

/// Split bytes on a separator; empty segments are kept so that
/// `join_segments(split_segments(d), sep) == d` (lossless round-trip).
fn split_segments(data: &[u8], sep: &[u8]) -> Vec<Vec<u8>> {
    if sep.is_empty() {
        return vec![data.to_vec()];
    }
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;
    while i + sep.len() <= data.len() {
        if &data[i..i + sep.len()] == sep {
            out.push(data[start..i].to_vec());
            i += sep.len();
            start = i;
        } else {
            i += 1;
        }
    }
    out.push(data[start..].to_vec());
    out
}

/// Join segments with the separator; inverse of [`split_segments`].
fn join_segments(segs: &[Vec<u8>], sep: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, s) in segs.iter().enumerate() {
        if i > 0 {
            out.extend_from_slice(sep);
        }
        out.extend_from_slice(s);
    }
    out
}

/// True when the flow contains a Fork step: the streaming pipeline falls back
/// to the whole-buffer path because Fork needs the full input in memory.
fn flow_has_fork(flow: &Flow) -> bool {
    flow.steps.iter().any(|s| s.op == FORK_OP)
}

/// A single input source.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone)]
enum InputSpec {
    Stdin,
    /// File path + relative path for batch output (basename for standalone files; path relative to the directory root for files inside directories).
    File {
        path: PathBuf,
        out_rel: PathBuf,
    },
}

#[cfg(not(target_arch = "wasm32"))]
impl InputSpec {
    /// Label used for prompts and stdout batch output.
    fn label(&self) -> String {
        match self {
            InputSpec::Stdin => "<stdin>".to_string(),
            InputSpec::File { path, .. } => path.display().to_string(),
        }
    }

    /// Output relative path in batch `-o` directory mode.
    fn out_rel(&self) -> Option<&Path> {
        match self {
            InputSpec::Stdin => None,
            InputSpec::File { out_rel, .. } => Some(out_rel),
        }
    }
}

/// Run a flow file.
#[cfg(not(target_arch = "wasm32"))]
pub fn run_flow(
    flow_path: &str,
    inputs: &[String],
    output_path: Option<&str>,
    cli_format: Option<String>,
    recursive: bool,
    jobs: usize,
) -> anyhow::Result<()> {
    // `-` reads the flow YAML from stdin (`dpa run - < flow.yaml` / pipe).
    let yaml_text = if flow_path == "-" {
        let mut s = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin().lock(), &mut s).map_err(|e| {
            anyhow::anyhow!(
                "{}",
                i18n::tf("err.read_flow_failed", &[e.to_string().as_str()])
            )
        })?;
        s
    } else {
        std::fs::read_to_string(flow_path).map_err(|e| {
            anyhow::anyhow!(
                "{}",
                i18n::tf("err.read_flow_failed", &[e.to_string().as_str()])
            )
        })?
    };
    run_flow_yaml(&yaml_text, inputs, output_path, cli_format, recursive, jobs)
}

/// Run an inline flow (YAML text already in memory). Used by `dpa run -e`.
#[cfg(not(target_arch = "wasm32"))]
pub fn run_flow_yaml(
    yaml_text: &str,
    inputs: &[String],
    output_path: Option<&str>,
    cli_format: Option<String>,
    recursive: bool,
    jobs: usize,
) -> anyhow::Result<()> {
    let flow: Flow = serde_yaml::from_str(yaml_text).map_err(|e| {
        anyhow::anyhow!(
            "{}",
            i18n::tf("err.parse_flow_failed", &[e.to_string().as_str()])
        )
    })?;

    if flow.steps.is_empty() {
        anyhow::bail!("{}", i18n::t("err.empty_steps"));
    }

    // Flow metadata goes to stderr so it never pollutes the stdout data stream.
    match (&flow.name, &flow.description) {
        (Some(n), Some(d)) => eprintln!("{}", i18n::tf("msg.flow_meta", &[n.as_str(), d.as_str()])),
        (Some(n), None) => eprintln!("{}", i18n::tf("msg.flow_name", &[n.as_str()])),
        (None, Some(d)) => eprintln!("{}", i18n::tf("msg.flow_desc", &[d.as_str()])),
        (None, None) => {}
    }

    let fmt = match cli_format {
        Some(s) => OutputFormat::parse(&s)?,
        None => match flow.output.as_deref() {
            Some(s) => OutputFormat::parse(s)?,
            None => OutputFormat::Raw,
        },
    };

    let expanded = expand_inputs(inputs, recursive)?;

    match expanded.len() {
        0 => {
            // No input arguments: read stdin.
            run_single(&flow, fmt, InputSpec::Stdin, output_path)
        }
        1 => run_single(&flow, fmt, expanded[0].clone(), output_path),
        _ => run_batch(&flow, fmt, &expanded, output_path, jobs),
    }
}

/// Single-input execution: `-o` writes to a file. The
/// operation-coverage pipeline makes every flow streamable, so this is always the
/// incremental path; at most one IO_BUF chunk plus barrier buffers stay resident.
#[cfg(not(target_arch = "wasm32"))]
fn run_single(
    flow: &Flow,
    fmt: OutputFormat,
    input: InputSpec,
    output_path: Option<&str>,
) -> anyhow::Result<()> {
    match output_path {
        Some(p) => {
            let mut w = open_file_writer(p)?;
            process_stream_to(flow, &input, fmt, &mut w)
        }
        None => {
            let stdout = std::io::stdout();
            let mut lock = stdout.lock();
            process_stream_to(flow, &input, fmt, &mut lock)
        }
    }
}

/// Batch execution: file-level parallelism. With `-o` as a directory, mirror the input
/// relative structure and write each output directly; otherwise stream every input through
/// the (always-on) incremental pipeline, hold the rendered outputs and print
/// them sequentially in input order (deterministic stdout, race-free).
///
/// Threads: `jobs` on the CLI, falling back to `available_parallelism` when 0 (default).
/// Memory: `-o` mode never accumulates results; stdout mode holds only rendered outputs
/// while each input is streamed chunk by chunk (see [`process_stream_collect`]).
#[cfg(not(target_arch = "wasm32"))]
fn run_batch(
    flow: &Flow,
    fmt: OutputFormat,
    expanded: &[InputSpec],
    output_path: Option<&str>,
    jobs: usize,
) -> anyhow::Result<()> {
    let threads = if jobs > 0 {
        jobs
    } else {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
    };
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .map_err(|e| {
            anyhow::anyhow!("{}", i18n::tf("err.thread_pool", &[e.to_string().as_str()]))
        })?;
    pool.install(|| run_batch_inner(flow, fmt, expanded, output_path))
}

#[cfg(not(target_arch = "wasm32"))]
fn run_batch_inner(
    flow: &Flow,
    fmt: OutputFormat,
    expanded: &[InputSpec],
    output_path: Option<&str>,
) -> anyhow::Result<()> {
    match output_path {
        // Execute in parallel and write files directly (no results held in memory; good for large batches).
        Some(dir) => {
            let results: Vec<(String, anyhow::Result<()>)> = expanded
                .par_iter()
                .map(|input| {
                    let label = input.label();
                    let res = (|| {
                        let rel = input.out_rel().ok_or_else(|| {
                            anyhow::anyhow!("{}", i18n::t("err.stdin_no_dir_out"))
                        })?;
                        let out_path = Path::new(dir).join(rel);
                        // Streaming batch: block-level read/write,
                        // only one chunk plus barrier buffers stay in memory.
                        // On failure, clean up already-created leftover files (release the
                        // write handle first; Windows locks block deletion).
                        let write_res = {
                            let mut w = open_file_writer(out_path.to_str().unwrap())?;
                            process_stream_to(flow, input, fmt, &mut w)
                        };
                        if let Err(e) = write_res {
                            let _ = std::fs::remove_file(&out_path);
                            return Err(e);
                        }
                        Ok(())
                    })();
                    (label, res)
                })
                .collect();
            summarize(results)
        }
        // Compute in parallel, print in order: keeps stdout deterministic and race-free.
        None => {
            let results: Vec<(String, anyhow::Result<Vec<u8>>)> = expanded
                .par_iter()
                .map(|input| {
                    let label = input.label();
                    let res = process_stream_collect(flow, input, fmt);
                    (label, res)
                })
                .collect();
            let mut failed = Vec::new();
            for (label, res) in results {
                match res {
                    Ok(data) => write_stdout(&data, fmt, Some(&label)).map_err(|e| {
                        anyhow::anyhow!(
                            "{}",
                            i18n::tf("err.write_stdout", &[e.to_string().as_str()])
                        )
                    })?,
                    Err(e) => failed.push(format!("{}: {}", label, e)),
                }
            }
            if failed.is_empty() {
                Ok(())
            } else {
                anyhow::bail!(
                    "{}",
                    i18n::tf(
                        "err.n_inputs_failed",
                        &[
                            failed.len().to_string().as_str(),
                            failed.join("\n").as_str()
                        ]
                    )
                )
            }
        }
    }
}

/// Aggregate parallel results: failures go to stderr; return Ok only when all succeed.
#[cfg(not(target_arch = "wasm32"))]
fn summarize(results: Vec<(String, anyhow::Result<()>)>) -> anyhow::Result<()> {
    let mut failed = Vec::new();
    for (label, res) in results {
        if let Err(e) = res {
            failed.push(format!("{}: {}", label, e));
        }
    }
    if failed.is_empty() {
        Ok(())
    } else {
        anyhow::bail!(
            "{}",
            i18n::tf(
                "err.n_inputs_failed",
                &[
                    failed.len().to_string().as_str(),
                    failed.join("\n").as_str()
                ]
            )
        )
    }
}

/// Run a single input through the streaming pipeline and return the rendered output bytes.
/// The input is read chunk by chunk (never whole-file resident); only the (typically
/// smaller) rendered output is accumulated for deterministic in-order stdout printing.
#[cfg(not(target_arch = "wasm32"))]
fn process_stream_collect(
    flow: &Flow,
    input: &InputSpec,
    fmt: OutputFormat,
) -> anyhow::Result<Vec<u8>> {
    let mut buf = Vec::new();
    process_stream_to(flow, input, fmt, &mut buf)?;
    Ok(buf)
}

/// Review fix §3-P7 (P2): secret-class argument sources. A step argument whose
/// string value starts with `env:` is resolved from the process environment at
/// execution time, so key material never has to appear in shell history, the
/// command line, or a recipe URL. Unknown variables are a hard error (better to
/// fail loudly than to run with a missing key); `env:` alone resolves the empty
/// variable. All other values pass through untouched.
fn expand_env_args(
    args: &std::collections::HashMap<String, String>,
) -> anyhow::Result<std::collections::HashMap<String, String>> {
    const PREFIX: &str = "env:";
    let mut out = std::collections::HashMap::with_capacity(args.len());
    for (k, v) in args {
        if let Some(name) = v.strip_prefix(PREFIX) {
            match std::env::var(name) {
                Ok(val) => {
                    out.insert(k.clone(), val);
                }
                Err(_) => {
                    return Err(anyhow::anyhow!(
                        "{}",
                        i18n::tf("err.env_var_missing", &[k.as_str(), name])
                    ));
                }
            }
        } else {
            out.insert(k.clone(), v.clone());
        }
    }
    Ok(out)
}

/// §4: static type check over the step chain. Only *strong* shapes
/// participate: an op declaring `input: Raw` accepts any upstream bytes and never
/// constrains the chain; `Unspecified` shapes (the default for most ops) also skip
/// the check, so existing flows never break. When the upstream `output` and the
/// current step's `input` are both strong shapes and differ, we report a mismatch
/// hint instead of silently feeding wrong-shaped data downstream.
fn check_io_chain(flow: &Flow) -> anyhow::Result<()> {
    use ops::OpIO;
    let mut prev_output: Option<ops::OpIO> = None;
    for (idx, step) in flow.steps.iter().enumerate() {
        if step.op == FORK_OP {
            // Fork is a control step; the remaining steps are re-checked on each
            // segment inside `process_bytes` (recursive rest flow), so skip here.
            prev_output = None;
            continue;
        }
        let op = ops::find_op(&step.op).ok_or_else(|| {
            anyhow::anyhow!(
                "{}",
                i18n::tf(
                    "err.unknown_op",
                    &[(idx + 1).to_string().as_str(), step.op.as_str()]
                )
            )
        })?;
        if let Some(prev) = prev_output {
            let strong_input = op.input != OpIO::Unspecified && op.input != OpIO::Raw;
            if strong_input && prev != OpIO::Unspecified && prev != op.input {
                anyhow::bail!(
                    "{}",
                    i18n::tf(
                        "err.type_mismatch",
                        &[
                            (idx + 1).to_string().as_str(),
                            prev.display(),
                            step.op.as_str(),
                            op.input.display()
                        ]
                    )
                );
            }
        }
        prev_output = Some(op.output);
    }
    Ok(())
}

/// Run the full flow over bytes in memory (entry point for the Python binding and library calls).
pub fn process_bytes(flow: &Flow, data: &[u8], fmt: OutputFormat) -> anyhow::Result<Vec<u8>> {
    check_io_chain(flow)?;
    process_bytes_depth(flow, data, fmt, 0)
}

/// Maximum Fork nesting depth. Guard against malicious or accidental flows that
/// would otherwise recurse without bound (review P2: fork recursion has no guard).
const FORK_MAX_DEPTH: usize = 16;

fn process_bytes_depth(
    flow: &Flow,
    data: &[u8],
    fmt: OutputFormat,
    depth: usize,
) -> anyhow::Result<Vec<u8>> {
    if depth > FORK_MAX_DEPTH {
        anyhow::bail!(
            "{}",
            i18n::tf("err.fork_depth", &[FORK_MAX_DEPTH.to_string().as_str()])
        );
    }
    let mut current = data.to_vec();

    let mut idx = 0;
    while idx < flow.steps.len() {
        let step = &flow.steps[idx];
        if step.op == FORK_OP {
            // Fork: split on the separator, run every remaining step on each
            // segment independently (recursion also handles nested Forks), then
            // join the per-segment results with the same separator.
            let sep = step
                .args
                .get("separator")
                .cloned()
                .unwrap_or_else(|| "\n".to_string())
                .into_bytes();
            let segments = split_segments(&current, &sep);
            let rest = Flow {
                steps: flow.steps[idx + 1..].to_vec(),
                ..Default::default()
            };
            let mut outs = Vec::with_capacity(segments.len());
            // Review §3-F: bound the Fork join so N segments cannot amplify
            // output into memory exhaustion (each segment output is bounded
            // individually by its own barrier cap; the sum must also be).
            let mut joined_bytes = 0usize;
            for seg in segments {
                let out = process_bytes_depth(&rest, &seg, OutputFormat::Raw, depth + 1)?;
                joined_bytes = joined_bytes.saturating_add(out.len());
                if joined_bytes > max_input_bytes() {
                    anyhow::bail!(
                        "{}",
                        i18n::tf(
                            "err.input_too_large",
                            &[max_input_bytes().to_string().as_str()]
                        )
                    );
                }
                outs.push(out);
            }
            current = join_segments(&outs, &sep);
            return Ok(render(current, fmt));
        }
        let op = ops::find_op(&step.op).ok_or_else(|| {
            anyhow::anyhow!(
                "{}",
                i18n::tf(
                    "err.unknown_op",
                    &[(idx + 1).to_string().as_str(), step.op.as_str()]
                )
            )
        })?;
        // Review fix §3-P7: resolve `env:`-sourced arguments before the op runs.
        let args = expand_env_args(&step.args)?;
        // Review G11: per-step observability (bytes in/out + wall time).
        let step_start = std::time::Instant::now();
        let in_len = current.len();
        current = (op.run)(&current, &args).map_err(|e| {
            anyhow::anyhow!(
                "{}",
                i18n::tf(
                    "err.step_failed",
                    &[
                        (idx + 1).to_string().as_str(),
                        step.op.as_str(),
                        e.to_string().as_str()
                    ]
                )
            )
        })?;
        if is_verbose() {
            eprintln!(
                "[dpa] step {} {}: {}B -> {}B in {:?}",
                idx + 1,
                step.op,
                in_len,
                current.len(),
                step_start.elapsed()
            );
        }
        idx += 1;
    }

    Ok(render(current, fmt))
}

/// Open an input reader (shared by the streaming path).
#[cfg(not(target_arch = "wasm32"))]
fn open_reader(input: &InputSpec) -> anyhow::Result<Box<dyn Read>> {
    match input {
        InputSpec::Stdin => Ok(Box::new(BufReader::with_capacity(
            IO_BUF,
            std::io::stdin().lock(),
        ))),
        InputSpec::File { path, .. } => {
            let f = std::fs::File::open(path).map_err(|e| {
                anyhow::anyhow!(
                    "{}",
                    i18n::tf("err.read_input_failed", &[e.to_string().as_str()])
                )
            })?;
            Ok(Box::new(BufReader::with_capacity(IO_BUF, f)))
        }
    }
}

/// Open an output writer (creates parent directories; shared by the streaming path).
#[cfg(not(target_arch = "wasm32"))]
fn open_file_writer(path: &str) -> anyhow::Result<BufWriter<std::fs::File>> {
    let p = Path::new(path);
    if let Some(parent) = p.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                anyhow::anyhow!(
                    "{}",
                    i18n::tf("err.create_outdir_failed", &[e.to_string().as_str()])
                )
            })?;
        }
    }
    let f = std::fs::File::create(p).map_err(|e| {
        anyhow::anyhow!(
            "{}",
            i18n::tf("err.create_outfile_failed", &[e.to_string().as_str()])
        )
    })?;
    Ok(BufWriter::with_capacity(IO_BUF, f))
}

/// Hybrid pipeline barrier (chunk-level pipeline):
/// wraps a non-streamable op so a partially-streamable flow still runs incrementally.
/// `write` buffers every incoming chunk and emits nothing; `finish` runs the op's in-memory
/// path once on the whole buffer. Steps before/after the barrier keep streaming chunk by chunk.
struct BarrierStream {
    op: &'static ops::Op,
    args: std::collections::HashMap<String, String>,
    buf: Vec<u8>,
}

impl ops::StreamingOp for BarrierStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        // Review §3-F: cap the unbounded whole-buffer accumulation so a huge
        // input cannot exhaust memory behind a non-streamable op.
        if self.buf.len().saturating_add(chunk.len()) > max_input_bytes() {
            anyhow::bail!(
                "{}",
                i18n::tf(
                    "err.input_too_large",
                    &[max_input_bytes().to_string().as_str()]
                )
            );
        }
        self.buf.extend_from_slice(chunk);
        Ok(Vec::new())
    }
    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        (self.op.run)(&self.buf, &self.args)
    }
}

/// Write rendered output; hex is encoded chunk by chunk, equivalent to whole-buffer encoding.
#[cfg(not(target_arch = "wasm32"))]
fn write_render(out: &mut dyn Write, data: &[u8], fmt: OutputFormat) -> std::io::Result<()> {
    match fmt {
        OutputFormat::Raw => out.write_all(data),
        // Hex is rendered as a text line with a trailing newline so that the
        // streaming path is byte-identical to write_stdout (review P2: hex
        // trailing newline was inconsistent between the two). Empty data
        // renders nothing (no stray blank line in streaming chunks).
        OutputFormat::Hex => {
            if data.is_empty() {
                return Ok(());
            }
            let mut s = hex::encode(data).into_bytes();
            s.push(b'\n');
            out.write_all(&s)
        }
    }
}

/// End-to-end streaming: read input in chunks -> push each chunk through the streaming op chain -> render -> write to out.
/// Only invoked when every step supports streaming; at most one chunk (IO_BUF) is resident.
/// Build the streaming handler chain for a flow.
/// Every step yields a handler: streamable steps use their
/// native factory, non-streamable steps are wrapped in a [`BarrierStream`] buffer.
fn build_handlers(flow: &Flow) -> anyhow::Result<Vec<Box<dyn ops::StreamingOp>>> {
    check_io_chain(flow)?;
    let mut handlers: Vec<Box<dyn ops::StreamingOp>> = Vec::new();
    for (idx, step) in flow.steps.iter().enumerate() {
        let op = ops::find_op(&step.op).ok_or_else(|| {
            anyhow::anyhow!(
                "{}",
                i18n::tf(
                    "err.unknown_op",
                    &[(idx + 1).to_string().as_str(), step.op.as_str()]
                )
            )
        })?;
        match &op.stream {
            Some(factory) => handlers.push(factory(&step.args).map_err(|e| {
                anyhow::anyhow!(
                    "{}",
                    i18n::tf(
                        "err.init_stream_failed",
                        &[
                            (idx + 1).to_string().as_str(),
                            step.op.as_str(),
                            e.to_string().as_str()
                        ]
                    )
                )
            })?),
            None => handlers.push(Box::new(BarrierStream {
                op,
                args: step.args.clone(),
                buf: Vec::new(),
            })),
        }
    }
    Ok(handlers)
}

/// In-memory processing through the unified streaming interface (pyo3 path):
/// every step yields a streaming handler (non-streamable steps are wrapped in a
/// [`BarrierStream`]), so the input is always fed through the chain in chunks.
/// Output is identical to [`process_bytes`].
pub fn process_bytes_stream(
    flow: &Flow,
    data: &[u8],
    fmt: OutputFormat,
) -> anyhow::Result<Vec<u8>> {
    if flow_has_fork(flow) {
        // Fork needs the whole buffer (segments are re-run through the remaining
        // steps); fall back to the in-memory path, which is the canonical one.
        return process_bytes(flow, data, fmt);
    }
    let mut handlers = build_handlers(flow)?;
    let mut acc = Vec::new();
    for chunk in data.chunks(IO_BUF) {
        let mut cur: &[u8] = chunk;
        let mut produced;
        for h in handlers.iter_mut() {
            produced = h.write(cur).map_err(|e| {
                anyhow::anyhow!(
                    "{}",
                    i18n::tf("err.stream_failed", &[e.to_string().as_str()])
                )
            })?;
            cur = &produced;
        }
        acc.extend_from_slice(cur);
    }
    let tail = finish_tail(&mut handlers, 0)?;
    acc.extend_from_slice(&tail);
    Ok(render(acc, fmt))
}

/// Stream from an input to an output through the handler chain (CLI single/batch and
/// stdout-collect paths). The input is read in IO_BUF chunks; at most one chunk plus
/// barrier buffers stay resident.
#[cfg(not(target_arch = "wasm32"))]
fn process_stream_to(
    flow: &Flow,
    input: &InputSpec,
    fmt: OutputFormat,
    out: &mut dyn Write,
) -> anyhow::Result<()> {
    if flow_has_fork(flow) {
        // Fork segments are re-run through the remaining steps, which requires
        // the whole input; fall back to the in-memory path for exact semantics.
        let mut all = Vec::new();
        open_reader(input)?.read_to_end(&mut all).map_err(|e| {
            anyhow::anyhow!(
                "{}",
                i18n::tf("err.stream_read_failed", &[e.to_string().as_str()])
            )
        })?;
        let out_bytes = process_bytes(flow, &all, OutputFormat::Raw)?;
        write_render(out, &out_bytes, fmt)?;
        return out.flush().map_err(|e| {
            anyhow::anyhow!(
                "{}",
                i18n::tf("err.flush_out_failed", &[e.to_string().as_str()])
            )
        });
    }
    let mut handlers = build_handlers(flow)?;

    let mut reader = open_reader(input)?;
    let mut buf = vec![0u8; IO_BUF];
    loop {
        let n = reader.read(&mut buf).map_err(|e| {
            anyhow::anyhow!(
                "{}",
                i18n::tf("err.stream_read_failed", &[e.to_string().as_str()])
            )
        })?;
        if n == 0 {
            break;
        }
        let mut chunk: &[u8] = &buf[..n];
        let mut produced;
        for h in handlers.iter_mut() {
            produced = h.write(chunk).map_err(|e| {
                anyhow::anyhow!(
                    "{}",
                    i18n::tf("err.stream_failed", &[e.to_string().as_str()])
                )
            })?;
            chunk = &produced;
        }
        write_render(out, chunk, fmt)?;
    }
    let tail = finish_tail(&mut handlers, 0)?;
    write_render(out, &tail, fmt)?;
    out.flush().map_err(|e| {
        anyhow::anyhow!(
            "{}",
            i18n::tf("err.flush_out_failed", &[e.to_string().as_str()])
        )
    })
}

/// Finish the streaming chain: finish each level in turn, feed its output into the next level, and return all tail bytes.
fn finish_tail(handlers: &mut [Box<dyn ops::StreamingOp>], idx: usize) -> anyhow::Result<Vec<u8>> {
    if idx == handlers.len() {
        return Ok(Vec::new());
    }
    let mut acc = handlers[idx].finish()?;
    for h in handlers[idx + 1..].iter_mut() {
        acc = h.write(&acc)?;
    }
    let rest = finish_tail(handlers, idx + 1)?;
    acc.extend(rest);
    Ok(acc)
}

/// Apply the output format; raw is returned as-is to avoid an extra copy.
fn render(data: Vec<u8>, fmt: OutputFormat) -> Vec<u8> {
    match fmt {
        OutputFormat::Raw => data,
        OutputFormat::Hex => hex::encode(&data).into_bytes(),
    }
}

/// Write to stdout; batch mode prints a `=== label ===` header so per-file results stay distinguishable.
#[cfg(not(target_arch = "wasm32"))]
fn write_stdout(data: &[u8], fmt: OutputFormat, label: Option<&str>) -> std::io::Result<()> {
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    if let Some(label) = label {
        writeln!(lock, "=== {} ===", label)?;
    }
    match fmt {
        OutputFormat::Raw => lock.write_all(data)?,
        // Match write_render: hex is a text line with a trailing newline, and
        // empty data renders nothing (no stray blank line).
        OutputFormat::Hex => {
            if !data.is_empty() {
                writeln!(lock, "{}", hex::encode(data))?;
            }
        }
    }
    Ok(())
}

/// Expand input arguments: files as-is, directories expanded to contained files (recursive optional), `-` means stdin.
#[cfg(not(target_arch = "wasm32"))]
fn expand_inputs(inputs: &[String], recursive: bool) -> anyhow::Result<Vec<InputSpec>> {
    let mut out = Vec::new();
    for s in inputs {
        if s == "-" {
            out.push(InputSpec::Stdin);
            continue;
        }
        let p = Path::new(s);
        if p.is_dir() {
            let max_depth = if recursive { usize::MAX } else { 1 };
            for entry in walkdir::WalkDir::new(p).max_depth(max_depth) {
                let e = entry.map_err(|err| {
                    anyhow::anyhow!(
                        "{}",
                        i18n::tf("err.walk_dir_failed", &[err.to_string().as_str()])
                    )
                })?;
                if e.file_type().is_file() {
                    let path = e.path().to_path_buf();
                    let out_rel = path.strip_prefix(p).unwrap_or(&path).to_path_buf();
                    out.push(InputSpec::File { path, out_rel });
                }
            }
        } else {
            let out_rel = p
                .file_name()
                .map(PathBuf::from)
                .unwrap_or_else(|| p.to_path_buf());
            out.push(InputSpec::File {
                path: p.to_path_buf(),
                out_rel,
            });
        }
    }
    // Deterministic order + dedup keeps parallel batch output stable.
    out.sort_by_key(|a| a.label());
    out.dedup_by(|a, b| a.label() == b.label());
    // Review fix A-1: distinct inputs that map to the same output relative path
    // would race when writing the same file under -o directory mode. Reject
    // explicitly instead of silently overwriting/competing.
    let mut seen_rel: std::collections::HashMap<PathBuf, String> = std::collections::HashMap::new();
    for spec in &out {
        if let Some(rel) = spec.out_rel() {
            if let Some(prev) = seen_rel.get(rel) {
                anyhow::bail!(
                    "{}",
                    i18n::tf(
                        "err.out_rel_conflict",
                        &[
                            rel.display().to_string().as_str(),
                            prev.as_str(),
                            spec.label().as_str(),
                        ]
                    )
                );
            }
            seen_rel.insert(rel.to_path_buf(), spec.label());
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Review fix §3-P7: `env:`-prefixed args resolve from the environment;
    /// plain values pass through; a missing variable is a hard error.
    #[test]
    fn expand_env_args_resolves_and_errors() {
        let mut args = std::collections::HashMap::new();
        args.insert("key".to_string(), "env:DPA_TEST_KEY".to_string());
        args.insert("algo".to_string(), "sha256".to_string());
        // SAFETY: variable name is unique to this test; edition-2024 marks set_var unsafe.
        unsafe { std::env::set_var("DPA_TEST_KEY", "s3cret") };
        let out = expand_env_args(&args).unwrap();
        assert_eq!(out.get("key").map(String::as_str), Some("s3cret"));
        assert_eq!(out.get("algo").map(String::as_str), Some("sha256"));

        let mut missing = std::collections::HashMap::new();
        missing.insert("key".to_string(), "env:DPA_TEST_KEY_ABSENT".to_string());
        let err = expand_env_args(&missing).unwrap_err();
        assert!(err.to_string().contains("DPA_TEST_KEY_ABSENT"));
    }

    fn write_flow(path: &Path, yaml: &str) {
        std::fs::write(path, yaml).unwrap();
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("dpa_engine_test_{}_{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn expand_dir_and_files() {
        let d = tmpdir("expand");
        std::fs::write(d.join("a.bin"), b"a").unwrap();
        std::fs::write(d.join("b.bin"), b"bb").unwrap();
        std::fs::create_dir_all(d.join("sub")).unwrap();
        std::fs::write(d.join("sub").join("c.bin"), b"ccc").unwrap();

        let expanded = expand_inputs(&[d.to_str().unwrap().to_string()], false).unwrap();
        assert_eq!(expanded.len(), 2); // non-recursive: only a.bin / b.bin
        let expanded_r = expand_inputs(&[d.to_str().unwrap().to_string()], true).unwrap();
        assert_eq!(expanded_r.len(), 3); // recursive: + sub/c.bin
    }

    /// §4 type chain check: only explicitly declared, non-Raw shapes constrain
    /// the step chain; Raw inputs accept any upstream bytes.
    #[test]
    fn io_type_chain_check() {
        let flow = |yaml: &str| -> Flow { serde_yaml::from_str(yaml).unwrap() };
        let err_of = |yaml: &str| -> String {
            process_bytes(&flow(yaml), b"", OutputFormat::Raw)
                .unwrap_err()
                .to_string()
        };

        // random (raw) -> hex:decode (hex): mismatch, hints at inserting hex:encode.
        let e = err_of("steps:\n  - op: dpa:random\n  - op: dpa:hex:decode\n");
        assert!(e.contains("type mismatch"), "{}", e);

        // base64:encode (base64) -> hex:decode (hex): mismatch.
        let e = err_of("steps:\n  - op: dpa:base64:encode\n  - op: dpa:hex:decode\n");
        assert!(e.contains("type mismatch"), "{}", e);

        // random:hex (hex) -> hex:decode (hex): passes.
        let ok = process_bytes(
            &flow("steps:\n  - op: dpa:random:hex\n  - op: dpa:hex:decode\n"),
            b"",
            OutputFormat::Raw,
        );
        assert!(ok.is_ok(), "{}", ok.unwrap_err());

        // base64:encode -> base64:decode: passes and round-trips.
        let out = process_bytes(
            &flow("steps:\n  - op: dpa:base64:encode\n  - op: dpa:base64:decode\n"),
            b"hello",
            OutputFormat::Raw,
        )
        .unwrap();
        assert_eq!(out, b"hello");

        // Raw input ops do not constrain upstream (hex:encode accepts any bytes).
        let ok = process_bytes(
            &flow("steps:\n  - op: dpa:base64:encode\n  - op: dpa:hex:encode\n"),
            b"abc",
            OutputFormat::Raw,
        );
        assert!(ok.is_ok(), "{}", ok.unwrap_err());
    }

    #[test]
    fn expand_inputs_detects_out_rel_conflict() {
        // Review fix A-1: dir1/a.bin and dir2/a.bin both expand to out_rel a.bin;
        // -o directory mode would race two parallel writers on the same file.
        let d = tmpdir("conflict");
        let dir1 = d.join("dir1");
        let dir2 = d.join("dir2");
        std::fs::create_dir_all(&dir1).unwrap();
        std::fs::create_dir_all(&dir2).unwrap();
        std::fs::write(dir1.join("a.bin"), b"one").unwrap();
        std::fs::write(dir2.join("a.bin"), b"two").unwrap();

        let err = expand_inputs(
            &[
                dir1.to_str().unwrap().to_string(),
                dir2.to_str().unwrap().to_string(),
            ],
            false,
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("a.bin"),
            "conflict message mentions path: {}",
            msg
        );

        // Same file passed twice via the same directory is deduped, not a conflict.
        let ok = expand_inputs(&[dir1.to_str().unwrap().to_string()], false).unwrap();
        assert_eq!(ok.len(), 1);
    }

    #[test]
    fn run_single_file_to_stdout_bytes() {
        let d = tmpdir("single");
        let flow = d.join("f.yaml");
        write_flow(&flow, "steps:\n  - op: dpa:base64:encode\n");
        let input = d.join("in.bin");
        std::fs::write(&input, b"hello").unwrap();

        let expanded = expand_inputs(&[input.to_str().unwrap().to_string()], false).unwrap();
        let flow: Flow = serde_yaml::from_str(&std::fs::read_to_string(&flow).unwrap()).unwrap();
        let out = process_mem(&flow, &expanded[0], OutputFormat::Raw);
        assert_eq!(out, b"aGVsbG8=");
    }

    #[test]
    fn run_batch_to_output_dir() {
        let d = tmpdir("batch");
        let flow = d.join("f.yaml");
        write_flow(
            &flow,
            "steps:\n  - op: dpa:xor\n    args:\n      key: \"0x2A\"\n",
        );
        let indir = d.join("in");
        std::fs::create_dir_all(&indir).unwrap();
        std::fs::write(indir.join("a.bin"), b"abcd").unwrap();
        std::fs::write(indir.join("b.bin"), b"xyzw").unwrap();
        let outdir = d.join("out");

        let expanded = expand_inputs(&[indir.to_str().unwrap().to_string()], false).unwrap();
        let flow: Flow = serde_yaml::from_str(&std::fs::read_to_string(&flow).unwrap()).unwrap();
        run_batch(
            &flow,
            OutputFormat::Raw,
            &expanded,
            Some(outdir.to_str().unwrap()),
            2,
        )
        .unwrap();

        let a = std::fs::read(outdir.join("a.bin")).unwrap();
        let b = std::fs::read(outdir.join("b.bin")).unwrap();
        // 'a'^0x2A='K'、'b'^0x2A='H'、'c'^0x2A='I'、'd'^0x2A='N'
        assert_eq!(a, b"KHIN");
        assert_eq!(b.len(), 4);
    }

    #[test]
    fn process_hex_render() {
        let d = tmpdir("stdout");
        let flow = d.join("f.yaml");
        write_flow(&flow, "output: hex\nsteps:\n  - op: dpa:base64:encode\n");
        std::fs::write(d.join("x.bin"), b"a").unwrap();

        let expanded =
            expand_inputs(&[d.join("x.bin").to_str().unwrap().to_string()], false).unwrap();
        let flow: Flow = serde_yaml::from_str(&std::fs::read_to_string(&flow).unwrap()).unwrap();
        let out = process_mem(&flow, &expanded[0], OutputFormat::Hex);
        // hex of "YQ=="
        assert_eq!(out, b"59513d3d");
    }

    #[test]
    fn error_does_not_abort_batch() {
        let d = tmpdir("err");
        let flow = d.join("f.yaml");
        write_flow(&flow, "steps:\n  - op: dpa:base64:decode\n");
        std::fs::write(d.join("ok.bin"), b"aGk=").unwrap();
        std::fs::write(d.join("bad.bin"), b"!!!").unwrap();
        let outdir = d.join("out");

        let expanded = expand_inputs(&[d.to_str().unwrap().to_string()], false).unwrap();
        let flow: Flow = serde_yaml::from_str(&std::fs::read_to_string(&flow).unwrap()).unwrap();
        let res = run_batch(
            &flow,
            OutputFormat::Raw,
            &expanded,
            Some(outdir.to_str().unwrap()),
            2,
        );
        assert!(res.is_err()); // aggregate error
        assert!(outdir.join("ok.bin").exists()); // but the successful file is already written
        assert!(!outdir.join("bad.bin").exists());
    }

    #[test]
    fn stream_read_large_input() {
        let d = tmpdir("large");
        let p = d.join("big.bin");
        let mut f = std::fs::File::create(&p).unwrap();
        let chunk = vec![0xABu8; 1 << 16];
        for _ in 0..64 {
            std::io::Write::write_all(&mut f, &chunk).unwrap();
        }
        std::io::Write::flush(&mut f).unwrap();

        let input = InputSpec::File {
            path: p.clone(),
            out_rel: PathBuf::from("big.bin"),
        };
        let mut data = Vec::new();
        open_reader(&input).unwrap().read_to_end(&mut data).unwrap();
        assert_eq!(data.len(), 64 * (1 << 16));
        assert_eq!(data[0], 0xAB);
    }

    /// In-memory reference path (whole-buffer): used by tests to compare streaming output
    /// against the non-streaming implementation (replaces the removed `process` helper).
    fn process_mem(flow: &Flow, input: &InputSpec, fmt: OutputFormat) -> Vec<u8> {
        let data = {
            let mut buf = Vec::new();
            open_reader(input).unwrap().read_to_end(&mut buf).unwrap();
            buf
        };
        process_bytes(flow, &data, fmt).unwrap()
    }

    // ---- streaming path tests: streaming output must match the in-memory path byte for byte ----

    /// Produce one streaming execution (simulating a single-input `-o` file write).
    fn run_stream_to_file(flow: &Flow, input: &InputSpec, out_path: &Path) -> anyhow::Result<()> {
        let mut w = open_file_writer(out_path.to_str().unwrap()).unwrap();
        process_stream_to(flow, input, OutputFormat::Raw, &mut w)
    }

    #[test]
    fn stream_matches_memory_for_codec() {
        let d = tmpdir("stream_codec");
        let flow = d.join("f.yaml");
        // Multi-step streaming chain: base64 encode -> base64 decode -> hex encode.
        // (The historical `base64:encode -> hex:encode -> base64:decode` chain is
        // rejected by the §4 type check: hex text is not valid base64 input.)
        write_flow(
            &flow,
            "steps:\n  - op: dpa:base64:encode\n  - op: dpa:base64:decode\n  - op: dpa:hex:encode\n",
        );
        // Input exceeds 3x IO_BUF (1 MiB) to force multiple chunks
        let input = d.join("in.bin");
        let data: Vec<u8> = (0..(3 * 1024 * 1024 + 7))
            .map(|i| (i % 251) as u8)
            .collect();
        std::fs::write(&input, &data).unwrap();
        let out_mem = d.join("out_mem.bin");
        let out_str = d.join("out_str.bin");

        let flow: Flow = serde_yaml::from_str(&std::fs::read_to_string(&flow).unwrap()).unwrap();
        let expanded = expand_inputs(&[input.to_str().unwrap().to_string()], false).unwrap();
        // in-memory path
        let mem = process_mem(&flow, &expanded[0], OutputFormat::Raw);
        std::fs::write(&out_mem, &mem).unwrap();
        // streaming path
        run_stream_to_file(&flow, &expanded[0], &out_str).unwrap();

        assert_eq!(
            std::fs::read(&out_mem).unwrap(),
            std::fs::read(&out_str).unwrap(),
            "streaming output differs from in-memory output"
        );
    }

    #[test]
    fn stream_hash_matches_memory() {
        let d = tmpdir("stream_hash");
        let flow = d.join("f.yaml");
        write_flow(&flow, "steps:\n  - op: dpa:sha256\n");
        // 5 MiB input
        let input = d.join("in.bin");
        let data: Vec<u8> = (0..(5 * 1024 * 1024 + 11)).map(|i| (i % 7) as u8).collect();
        std::fs::write(&input, &data).unwrap();
        let out_mem = d.join("out_mem.bin");
        let out_str = d.join("out_str.bin");

        let flow: Flow = serde_yaml::from_str(&std::fs::read_to_string(&flow).unwrap()).unwrap();
        let expanded = expand_inputs(&[input.to_str().unwrap().to_string()], false).unwrap();
        let mem = process_mem(&flow, &expanded[0], OutputFormat::Raw);
        std::fs::write(&out_mem, &mem).unwrap();
        run_stream_to_file(&flow, &expanded[0], &out_str).unwrap();
        assert_eq!(
            std::fs::read(&out_mem).unwrap(),
            std::fs::read(&out_str).unwrap()
        );
    }

    #[test]
    fn stream_compress_roundtrip_matches_memory() {
        let d = tmpdir("stream_compress");
        let input = d.join("in.bin");
        // Highly compressible repeating data + above IO_BUF
        let data: Vec<u8> = (0..(3 * 1024 * 1024 + 3))
            .map(|i| if i % 4 == 0 { b'a' } else { b'b' })
            .collect();
        std::fs::write(&input, &data).unwrap();

        // gzip/zlib compress: streaming and in-memory results must match
        for (steps, name) in [
            ("steps:\n  - op: dpa:gzip:compress\n", "gzip_c"),
            ("steps:\n  - op: dpa:zlib:compress\n", "zlib_c"),
        ] {
            let flow_path = d.join(format!("{}.yaml", name));
            write_flow(&flow_path, steps);
            let flow: Flow =
                serde_yaml::from_str(&std::fs::read_to_string(&flow_path).unwrap()).unwrap();
            let expanded = expand_inputs(&[input.to_str().unwrap().to_string()], false).unwrap();

            let mem = process_mem(&flow, &expanded[0], OutputFormat::Raw);
            let out_mem = d.join(format!("{}_mem.bin", name));
            let out_str = d.join(format!("{}_str.bin", name));
            std::fs::write(&out_mem, &mem).unwrap();
            run_stream_to_file(&flow, &expanded[0], &out_str).unwrap();
            assert_eq!(
                std::fs::read(&out_mem).unwrap(),
                std::fs::read(&out_str).unwrap(),
                "{} streaming output differs from in-memory output",
                name
            );
        }

        // gzip/zlib decompress: input is the in-memory compressed output; streaming and in-memory results must match
        for (steps, name, comp_op) in [
            (
                "steps:\n  - op: dpa:gzip:decompress\n",
                "gzip_d",
                "dpa:gzip:compress",
            ),
            (
                "steps:\n  - op: dpa:zlib:decompress\n",
                "zlib_d",
                "dpa:zlib:compress",
            ),
        ] {
            let comp_flow: Flow =
                serde_yaml::from_str(&format!("steps:\n  - op: {}\n", comp_op)).unwrap();
            let expanded_in = expand_inputs(&[input.to_str().unwrap().to_string()], false).unwrap();
            let compressed = process_mem(&comp_flow, &expanded_in[0], OutputFormat::Raw);
            let comp_in = d.join(format!("{}_in.bin", name));
            std::fs::write(&comp_in, &compressed).unwrap();

            let flow_path = d.join(format!("{}.yaml", name));
            write_flow(&flow_path, steps);
            let flow: Flow =
                serde_yaml::from_str(&std::fs::read_to_string(&flow_path).unwrap()).unwrap();
            let expanded = expand_inputs(&[comp_in.to_str().unwrap().to_string()], false).unwrap();

            let mem = process_mem(&flow, &expanded[0], OutputFormat::Raw);
            let out_mem = d.join(format!("{}_mem.bin", name));
            let out_str = d.join(format!("{}_str.bin", name));
            std::fs::write(&out_mem, &mem).unwrap();
            run_stream_to_file(&flow, &expanded[0], &out_str).unwrap();
            assert_eq!(
                std::fs::read(&out_mem).unwrap(),
                std::fs::read(&out_str).unwrap(),
                "{} streaming output differs from in-memory output",
                name
            );
        }

        // End-to-end gzip compress streaming -> decompress streaming (verifies data integrity across files)
        let gz = d.join("c.bin");
        let flow_c = d.join("gzip_c.yaml");
        write_flow(&flow_c, "steps:\n  - op: dpa:gzip:compress\n");
        let flow_c: Flow =
            serde_yaml::from_str(&std::fs::read_to_string(&flow_c).unwrap()).unwrap();
        let expanded = expand_inputs(&[input.to_str().unwrap().to_string()], false).unwrap();
        run_stream_to_file(&flow_c, &expanded[0], &gz).unwrap();

        let flow_d = d.join("gzip_d.yaml");
        write_flow(&flow_d, "steps:\n  - op: dpa:gzip:decompress\n");
        let flow_d: Flow =
            serde_yaml::from_str(&std::fs::read_to_string(&flow_d).unwrap()).unwrap();
        let expanded = expand_inputs(&[gz.to_str().unwrap().to_string()], false).unwrap();
        let back = process_mem(&flow_d, &expanded[0], OutputFormat::Raw);
        assert_eq!(
            back, data,
            "gzip streaming compress then decompress must restore the original data"
        );
    }

    #[test]
    fn stream_hex_render_consistent() {
        let d = tmpdir("stream_hex");
        let flow = d.join("f.yaml");
        write_flow(&flow, "output: hex\nsteps:\n  - op: dpa:sha256\n");
        let input = d.join("in.bin");
        std::fs::write(&input, b"stream hex render").unwrap();
        let flow: Flow = serde_yaml::from_str(&std::fs::read_to_string(&flow).unwrap()).unwrap();
        let expanded = expand_inputs(&[input.to_str().unwrap().to_string()], false).unwrap();

        let mut out = Vec::new();
        process_stream_to(&flow, &expanded[0], OutputFormat::Hex, &mut out).unwrap();
        // Hex is rendered as a text line (trailing newline), matching write_stdout.
        let expected = format!(
            "{}\n",
            hex::encode(process_mem(&flow, &expanded[0], OutputFormat::Raw))
        );
        assert_eq!(String::from_utf8(out).unwrap(), expected);
    }

    #[test]
    fn stream_rc4_xor_consistent() {
        let d = tmpdir("stream_crypto");
        let flow = d.join("f.yaml");
        // xor + rc4 + hmac chain (streaming) compared against the in-memory path
        write_flow(
            &flow,
            "steps:\n  - op: dpa:xor\n    args:\n      key: \"0x2A\"\n  - op: dpa:rc4\n    args:\n      key: \"secret-key\"\n  - op: dpa:hmac\n    args:\n      key: \"mac-key\"\n      algo: sha256\n",
        );
        let input = d.join("in.bin");
        let data: Vec<u8> = (0..(2 * 1024 * 1024 + 5)).map(|i| (i % 97) as u8).collect();
        std::fs::write(&input, &data).unwrap();
        let flow: Flow = serde_yaml::from_str(&std::fs::read_to_string(&flow).unwrap()).unwrap();
        let expanded = expand_inputs(&[input.to_str().unwrap().to_string()], false).unwrap();
        let mem = process_mem(&flow, &expanded[0], OutputFormat::Raw);
        let out_mem = d.join("out_mem.bin");
        let out_str = d.join("out_str.bin");
        std::fs::write(&out_mem, &mem).unwrap();
        run_stream_to_file(&flow, &expanded[0], &out_str).unwrap();
        assert_eq!(
            std::fs::read(&out_mem).unwrap(),
            std::fs::read(&out_str).unwrap()
        );
    }

    // ---- chunk-level pipeline tests: hybrid chains with barriers ----

    /// Streaming execution must equal the in-memory path even when the flow contains
    /// non-streamable steps (they become chunk-pipeline barriers).
    fn assert_hybrid_matches_memory(steps: &str, data: &[u8], tag: &str) {
        let d = tmpdir(&format!("hybrid_{}", tag));
        let flow = d.join("f.yaml");
        write_flow(&flow, steps);
        let input = d.join("in.bin");
        std::fs::write(&input, data).unwrap();

        let flow: Flow = serde_yaml::from_str(&std::fs::read_to_string(&flow).unwrap()).unwrap();
        let expanded = expand_inputs(&[input.to_str().unwrap().to_string()], false).unwrap();
        let mem = process_mem(&flow, &expanded[0], OutputFormat::Raw);
        let out_mem = d.join("out_mem.bin");
        let out_str = d.join("out_str.bin");
        std::fs::write(&out_mem, &mem).unwrap();
        run_stream_to_file(&flow, &expanded[0], &out_str).unwrap();
        assert_eq!(
            std::fs::read(&out_mem).unwrap(),
            std::fs::read(&out_str).unwrap(),
            "{}: hybrid streaming differs from in-memory",
            tag
        );
    }

    #[test]
    fn stream_hybrid_one_barrier_matches_memory() {
        // streamable -> barrier (base32:encode) -> streamable; input spans multiple chunks.
        let data: Vec<u8> = (0..(3 * 1024 * 1024 + 13))
            .map(|i| (i % 251) as u8)
            .collect();
        assert_hybrid_matches_memory(
            "steps:\n  - op: dpa:base64:encode\n  - op: dpa:base32:encode\n  - op: dpa:hex:encode\n",
            &data,
            "one_barrier",
        );
    }

    #[test]
    fn stream_hybrid_two_barriers_matches_memory() {
        // barrier -> barrier -> streamable: base32:encode (whole-buffer) then reverse (whole-buffer).
        let data: Vec<u8> = (0..(2 * 1024 * 1024 + 5)).map(|i| (i % 97) as u8).collect();
        assert_hybrid_matches_memory(
            "steps:\n  - op: dpa:base32:encode\n  - op: dpa:reverse\n  - op: dpa:hex:encode\n",
            &data,
            "two_barriers",
        );
    }

    #[test]
    fn stream_hybrid_empty_and_small_inputs() {
        // Empty input through a barrier chain; small input through barrier + streamable.
        assert_hybrid_matches_memory(
            "steps:\n  - op: dpa:base32:encode\n  - op: dpa:reverse\n  - op: dpa:hex:encode\n",
            &[],
            "empty",
        );
        assert_hybrid_matches_memory(
            "steps:\n  - op: dpa:base32:encode\n  - op: dpa:base32:decode\n  - op: dpa:hex:encode\n",
            b"hello world, dpa hybrid pipeline",
            "small",
        );
    }

    // ---- Fork (flow control) ----

    #[test]
    fn fork_runs_remaining_steps_per_segment() {
        let d = tmpdir("fork");
        // Two base64 lines decoded independently.
        let flow = d.join("f.yaml");
        write_flow(
            &flow,
            "steps:\n  - op: dpa:fork\n  - op: dpa:base64:decode\n",
        );
        std::fs::write(d.join("in.bin"), b"aGk=\nYQ==").unwrap();
        let expanded =
            expand_inputs(&[d.join("in.bin").to_str().unwrap().to_string()], false).unwrap();
        let flow: Flow = serde_yaml::from_str(&std::fs::read_to_string(&flow).unwrap()).unwrap();
        let out = process_mem(&flow, &expanded[0], OutputFormat::Raw);
        assert_eq!(out, b"hi\na");
    }

    #[test]
    fn fork_custom_separator_and_empty_segments() {
        let d = tmpdir("fork_sep");
        // "aGk=,YQ==," splits into ["aGk=", "YQ==", ""]; each is decoded
        // independently, joined back with "," -> "hi,a,".
        let flow = d.join("f.yaml");
        write_flow(
            &flow,
            "steps:\n  - op: dpa:fork\n    args:\n      separator: \",\"\n  - op: dpa:base64:decode\n",
        );
        std::fs::write(d.join("in.bin"), b"aGk=,YQ==,").unwrap();
        let expanded =
            expand_inputs(&[d.join("in.bin").to_str().unwrap().to_string()], false).unwrap();
        let flow: Flow = serde_yaml::from_str(&std::fs::read_to_string(&flow).unwrap()).unwrap();
        let out = process_mem(&flow, &expanded[0], OutputFormat::Raw);
        assert_eq!(out, b"hi,a,");
    }

    #[test]
    fn fork_as_last_step_is_identity() {
        let d = tmpdir("fork_last");
        let flow = d.join("f.yaml");
        write_flow(&flow, "steps:\n  - op: dpa:fork\n");
        let input = d.join("in.bin");
        std::fs::write(&input, b"a\nb\n\nc").unwrap();
        let expanded = expand_inputs(&[input.to_str().unwrap().to_string()], false).unwrap();
        let flow: Flow = serde_yaml::from_str(&std::fs::read_to_string(&flow).unwrap()).unwrap();
        let out = process_mem(&flow, &expanded[0], OutputFormat::Raw);
        assert_eq!(out, b"a\nb\n\nc");
    }

    #[test]
    fn fork_stream_path_matches_memory() {
        let d = tmpdir("fork_stream");
        let flow = d.join("f.yaml");
        // Fork falls back to the whole-buffer path; output must still equal the
        // in-memory result byte for byte.
        write_flow(
            &flow,
            "steps:\n  - op: dpa:fork\n  - op: dpa:base64:decode\n  - op: dpa:hex:encode\n",
        );
        let input = d.join("in.bin");
        let line = b"aGk=\n";
        let mut data = Vec::new();
        while data.len() < 2 * 1024 * 1024 {
            data.extend_from_slice(line);
        }
        std::fs::write(&input, &data).unwrap();
        let flow: Flow = serde_yaml::from_str(&std::fs::read_to_string(&flow).unwrap()).unwrap();
        let expanded = expand_inputs(&[input.to_str().unwrap().to_string()], false).unwrap();
        let mem = process_mem(&flow, &expanded[0], OutputFormat::Raw);
        let out_mem = d.join("out_mem.bin");
        let out_str = d.join("out_str.bin");
        std::fs::write(&out_mem, &mem).unwrap();
        run_stream_to_file(&flow, &expanded[0], &out_str).unwrap();
        assert_eq!(
            std::fs::read(&out_mem).unwrap(),
            std::fs::read(&out_str).unwrap(),
            "fork streaming path differs from in-memory path"
        );
    }
}
