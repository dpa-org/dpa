//! Execution engine: read a flow -> expand inputs -> run every step (optionally in parallel) -> output.
//!
//! Batch support: multiple input files, directory expansion (recursive optional), file-level parallelism.

#[cfg(not(target_arch = "wasm32"))]
use std::io::IsTerminal;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

#[cfg(not(target_arch = "wasm32"))]
use rayon::prelude::*;

use crate::estimate;
use crate::flow::{Flow, OutputFormat, from_yaml};
use crate::i18n;
use crate::ops;

/// IO buffer size: 1 MiB, balancing throughput and memory.
const IO_BUF: usize = 1 << 20;

/// Hard cap for flow/recipe YAML text (8 MiB). Flows are small, hand-written
/// documents; this bounds the parser's input before serde-saphyr touches it
/// (a size-limit mitigation for the YAML parser).
const MAX_FLOW_YAML_BYTES: usize = 8 << 20;

/// Default cap for whole-buffer input and Fork output accumulation (256 MiB).
/// Guards the [`BarrierStream`] buffer and the Fork join against
/// memory-exhaustion inputs.
pub const DEFAULT_MAX_INPUT_BYTES: usize = 256 << 20;

/// Default per-step streaming output cap (64 MiB). A single pipeline step
/// that inflates beyond this is almost always a runaway transform (e.g. a
/// repeated base64 chain); set `--max-step-output-bytes=0` to disable
/// the per-step cap.
pub const DEFAULT_MAX_STEP_OUTPUT_BYTES: usize = 64 << 20;

/// Engine-wide execution settings, carried by value through the execution
/// pipeline. Replaces the process-wide globals (`set_max_input_bytes` /
/// `set_max_step_output_bytes` / `set_verbose`) so every entry point (CLI,
/// pyo3, wasm, cdylib, tests) configures its own context without hidden
/// cross-call state; default behaviour is identical to the old globals'
/// initial values. Multiple engines with different settings can now run
/// side by side (multi-instance / wasm / cdylib paths unaffected).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineConfig {
    max_input_bytes: usize,
    max_step_output_bytes: usize,
    verbose: bool,
    /// Optional separator emitted between batch stdout
    /// outputs. `None` (default) streams every file's raw bytes with no
    /// forced framing so binary chains stay byte-exact; a text-scene caller
    /// can opt into explicit framing via `--batch-separator`.
    batch_separator: Option<String>,
    /// Optional per-output label line (`==> <input>`) before
    /// each batch stdout output. `false` (default) keeps the stream byte-exact
    /// with no injected framing; text-scene callers can opt into readable
    /// attribution via `--batch-label`.
    batch_label: bool,
    /// Optional `env:` variable whitelist. `None` (default)
    /// preserves the legacy behavior where any environment variable may be
    /// read; `Some(names)` restricts `env:`-sourced arguments to that exact
    /// set, so a malicious flow cannot exfiltrate arbitrary variables.
    allow_env: Option<std::collections::HashSet<String>>,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            max_input_bytes: DEFAULT_MAX_INPUT_BYTES,
            max_step_output_bytes: DEFAULT_MAX_STEP_OUTPUT_BYTES,
            verbose: false,
            batch_separator: None,
            batch_label: false,
            allow_env: None,
        }
    }
}

impl EngineConfig {
    /// Current input/output byte cap.
    pub fn max_input_bytes(&self) -> usize {
        self.max_input_bytes
    }

    /// Current per-step streaming output cap (0 = unlimited).
    pub fn max_step_output_bytes(&self) -> usize {
        self.max_step_output_bytes
    }

    /// Whether per-step observability is enabled.
    pub fn verbose(&self) -> bool {
        self.verbose
    }

    /// Builder: override the input/output byte cap (1 = minimum).
    pub fn with_max_input_bytes(mut self, n: usize) -> Self {
        self.max_input_bytes = n.max(1);
        self
    }

    /// Builder: override the per-step streaming output cap (0 = unlimited).
    pub fn with_max_step_output_bytes(mut self, n: usize) -> Self {
        self.max_step_output_bytes = n;
        self
    }

    /// Builder: toggle per-step observability.
    pub fn with_verbose(mut self, on: bool) -> Self {
        self.verbose = on;
        self
    }

    /// Builder that sets the `env:` variable whitelist.
    /// Replaces any previously configured set.
    pub fn with_allow_env(mut self, names: std::collections::HashSet<String>) -> Self {
        self.allow_env = if names.is_empty() { None } else { Some(names) };
        self
    }

    /// Effective `env:` whitelist (`None` = any variable may be
    /// read, legacy behavior).
    pub fn allow_env(&self) -> Option<&std::collections::HashSet<String>> {
        self.allow_env.as_ref()
    }

    /// Batch stdout separator. `None` = no forced framing.
    pub fn batch_separator(&self) -> Option<&str> {
        self.batch_separator.as_deref()
    }

    /// Builder: set the optional separator emitted between batch stdout
    /// outputs. `None` restores the default (binary-integrity-first: no
    /// framing at all); a non-empty string opts into explicit framing for
    /// text scenes.
    pub fn with_batch_separator(mut self, sep: Option<String>) -> Self {
        self.batch_separator = sep.filter(|s| !s.is_empty());
        self
    }

    /// Batch per-output label. `false` (default) = no
    /// injected label line; stdout stays byte-exact for binary chains.
    pub fn batch_label(&self) -> bool {
        self.batch_label
    }

    /// Builder: toggle the optional `==> <input>` label line emitted before
    /// each batch stdout output. `false` (default) restores byte-exact
    /// streaming; text scenes can opt in for readable attribution.
    pub fn with_batch_label(mut self, on: bool) -> Self {
        self.batch_label = on;
        self
    }
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

    /// Progress-line label for batch stdout. Uses the relative
    /// path (basename for standalone files; path relative to the input
    /// directory root for files inside directories) so `==> <input>` stays
    /// readable and copy-paste friendly. The absolute path from `label()` is
    /// still what ordering/dedup/conflict checks use.
    fn display_label(&self) -> String {
        match self {
            InputSpec::Stdin => "<stdin>".to_string(),
            InputSpec::File { out_rel, .. } => out_rel.display().to_string(),
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

/// serde-saphyr error strings leak Rust API concepts to
/// terminal users (`Depth { depth: N }` debug formatting, `set
/// DuplicateKeyPolicy in Options`). Rewrite those into user-friendly wording
/// while keeping the line/column prefix and the offending key name.
#[cfg(not(target_arch = "wasm32"))]
fn polish_yaml_error(raw: &str) -> String {
    const DEPTH_MARK: &str = "budget breached: Depth { depth: ";
    let mut s = raw.to_string();
    if let Some(pos) = s.find(DEPTH_MARK) {
        let n_start = pos + DEPTH_MARK.len();
        if let Some(close) = s[n_start..].find('}') {
            let depth = s[n_start..n_start + close].trim();
            s = format!(
                "{}maximum YAML nesting depth ({}) exceeded{}",
                &s[..pos],
                depth,
                &s[n_start + close + 1..]
            );
        }
    }
    const DUP_TAIL: &str = ", set DuplicateKeyPolicy in Options if acceptable";
    if let Some(pos) = s.find(DUP_TAIL) {
        s = format!("{}; remove or rename one of the keys", &s[..pos]);
    }
    s
}

/// Run a flow file end to end. `cfg` carries the engine limits and verbosity;
/// several knobs are threaded here by design so the public entry
/// points stay explicit, hence the arg count.
#[cfg(not(target_arch = "wasm32"))]
#[allow(clippy::too_many_arguments)]
pub fn run_flow(
    flow_path: &str,
    inputs: &[String],
    output_path: Option<&str>,
    cli_format: Option<String>,
    recursive: bool,
    jobs: usize,
    to_step: Option<usize>,
    explain: bool,
    cfg: &EngineConfig,
) -> anyhow::Result<()> {
    // `-` reads the flow YAML from stdin (`dpa run - < flow.yaml` / pipe).
    let yaml_text = if flow_path == "-" {
        let mut s = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin().lock(), &mut s).map_err(|e| {
            anyhow::anyhow!(
                "{}",
                i18n::tf(
                    "err.read_flow_failed",
                    &["stdin", i18n::os_error(&e).as_str()]
                )
            )
        })?;
        s
    } else {
        std::fs::read_to_string(flow_path).map_err(|e| {
            anyhow::anyhow!(
                "{}",
                i18n::tf(
                    "err.read_flow_failed",
                    &[flow_path, i18n::os_error(&e).as_str()]
                )
            )
        })?
    };
    run_flow_yaml(
        &yaml_text,
        inputs,
        output_path,
        cli_format,
        recursive,
        jobs,
        to_step,
        explain,
        cfg,
    )
}

/// Run an inline flow (YAML text already in memory). Used by `dpa run -e`.
/// `cfg` carries the engine limits and verbosity; the arg count is
/// explicit by design for the CLI entry points.
#[cfg(not(target_arch = "wasm32"))]
#[allow(clippy::too_many_arguments)]
pub fn run_flow_yaml(
    yaml_text: &str,
    inputs: &[String],
    output_path: Option<&str>,
    cli_format: Option<String>,
    recursive: bool,
    jobs: usize,
    to_step: Option<usize>,
    explain: bool,
    cfg: &EngineConfig,
) -> anyhow::Result<()> {
    // Strip a single leading UTF-8 BOM that Windows editors
    // (e.g. Notepad "Save as UTF-8") commonly prepend; serde-saphyr would
    // otherwise treat \u{FEFF} as an extra document and fail with
    // "YAML containing more than one document".
    let yaml_text = yaml_text.strip_prefix('\u{FEFF}').unwrap_or(yaml_text);
    // Reject oversized flow YAML before the parser
    // runs, so hostile input never reaches serde-saphyr unbounded.
    if yaml_text.len() > MAX_FLOW_YAML_BYTES {
        let cap = MAX_FLOW_YAML_BYTES.to_string();
        anyhow::bail!("{}", i18n::tf("err.flow_too_large", &[&cap]));
    }
    let mut flow: Flow = from_yaml(yaml_text).map_err(|e| {
        anyhow::anyhow!(
            "{}\n\n{}",
            i18n::tf(
                "err.parse_flow_failed",
                &[polish_yaml_error(&e.to_string()).as_str()]
            ),
            i18n::t("hint.flow_shape")
        )
    })?;

    // `--to-step N` runs only the first N steps. Truncating here
    // keeps every downstream path (in-memory / streaming / batch / fork) on the
    // exact same semantics as a shorter flow file.
    if let Some(n) = to_step {
        if n == 0 {
            anyhow::bail!("{}", i18n::t("err.to_step_zero"));
        }
        if n > flow.steps.len() {
            anyhow::bail!(
                "{}",
                i18n::tf(
                    "err.to_step_exceeds",
                    &[
                        n.to_string().as_str(),
                        flow.steps.len().to_string().as_str()
                    ]
                )
            );
        }
        flow.steps.truncate(n);
    }

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

    // `--explain` prints a static per-step input→output estimate before
    // execution (advisory only; never changes behaviour or the dynamic cap).
    if explain {
        print_flow_explain(&flow, input_size_hint(&expanded))?;
    }

    match expanded.len() {
        0 => {
            // No input arguments: read stdin.
            // When stdin is an interactive terminal, tell the user the
            // process is waiting for input instead of appearing to hang.
            if std::io::stdin().is_terminal() {
                eprintln!("{}", i18n::t("msg.reading_stdin"));
            }
            run_single(&flow, fmt, InputSpec::Stdin, output_path, cfg)
        }
        1 => run_single(&flow, fmt, expanded[0].clone(), output_path, cfg),
        _ => run_batch(&flow, fmt, &expanded, output_path, jobs, cfg),
    }
}

/// Best-effort input size for `--explain`: exact only for a single file
/// input; stdin and multi-input batches stay unknown ("?").
#[cfg(not(target_arch = "wasm32"))]
fn input_size_hint(expanded: &[InputSpec]) -> Option<usize> {
    match expanded {
        [InputSpec::File { path, .. }] => std::fs::metadata(path).ok().map(|m| m.len() as usize),
        _ => None,
    }
}

/// `--explain`: print a static per-step input→output estimate before
/// execution. Goes to stderr so the stdout data stream stays clean.
fn print_flow_explain(flow: &Flow, input_len: Option<usize>) -> anyhow::Result<()> {
    for line in render_flow_explain(flow, input_len)?.lines() {
        eprintln!("{line}");
    }
    Ok(())
}

/// Render the `--explain` table body (one localized line per step). Kept
/// separate from `print_flow_explain` so tests can assert the exact text.
fn render_flow_explain(flow: &Flow, input_len: Option<usize>) -> anyhow::Result<String> {
    use std::fmt::Write as _;
    let mut buf = String::new();
    writeln!(
        buf,
        "{}",
        i18n::tf(
            "explain.heading",
            &[estimate::render_size(input_len).as_str()]
        )
    )
    .ok();
    let mut cur = input_len;
    for (i, step) in flow.steps.iter().enumerate() {
        let op = ops::find_op(&step.op).ok_or_else(|| {
            anyhow::anyhow!("{}", i18n::tf("err.op_not_found", &[step.op.as_str()]))
        })?;
        let est = estimate::estimate_for_op(op, &step.args, cur);
        let out = estimate::render_estimate(&est, cur);
        writeln!(
            buf,
            "{}",
            i18n::tf(
                "explain.step",
                &[
                    (i + 1).to_string().as_str(),
                    step.op.as_str(),
                    estimate::render_size(cur).as_str(),
                    out.as_str(),
                ]
            )
        )
        .ok();
        cur = estimate::next_input(&est, cur);
    }
    Ok(buf)
}

/// Terminal-ness pair for overwrite prompts. On wasm there is no real
/// terminal, but `run_single` is host-only; this helper exists so the
/// condition stays testable with injected flags.
#[cfg(not(target_arch = "wasm32"))]
fn tty_pair() -> (bool, bool) {
    (
        std::io::stdin().is_terminal(),
        std::io::stdout().is_terminal(),
    )
}

/// Warning text for silently clobbering an existing output
/// file in a non-interactive context (piped/redirected single runs and
/// parallel batch runs never prompt).
fn overwrite_warning(path: &str) -> String {
    i18n::tf("warn.overwrite_existing", &[path])
}

/// Whether an interactive overwrite confirmation applies:
/// only when the input is a file (a stdin-fed terminal cannot answer a prompt
/// without swallowing flow data) and both stdin/stdout are real terminals.
#[cfg(not(target_arch = "wasm32"))]
fn overwrite_prompt_needed(input: &InputSpec, stdin_tty: bool, stdout_tty: bool) -> bool {
    matches!(input, InputSpec::File { .. }) && stdin_tty && stdout_tty
}

/// Parse one line of the [y/N] overwrite prompt; only an explicit y/yes
/// (case-insensitive) overwrites, anything else - including EOF - cancels.
#[cfg(not(target_arch = "wasm32"))]
fn parse_overwrite_answer(line: &str) -> bool {
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// Ask [y/N] on stderr and read one answer from stdin.
#[cfg(not(target_arch = "wasm32"))]
fn confirm_overwrite(path: &str) -> anyhow::Result<bool> {
    eprint!("{}", i18n::tf("msg.overwrite_confirm", &[path]));
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    let n = std::io::stdin().read_line(&mut line)?;
    if n == 0 {
        return Ok(false);
    }
    Ok(parse_overwrite_answer(&line))
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
    cfg: &EngineConfig,
) -> anyhow::Result<()> {
    match output_path {
        Some(p) => {
            // Interactive overwrite guard. Only a real terminal
            // with a file input gets a [y/N] prompt; piped/redirected (non-TTY)
            // callers keep the silent overwrite so scripts are unaffected, and
            // stdin-fed runs are never prompted (the terminal is busy feeding
            // data and cannot answer).
            let (stdin_tty, stdout_tty) = tty_pair();
            if Path::new(p).exists()
                && overwrite_prompt_needed(&input, stdin_tty, stdout_tty)
                && !confirm_overwrite(p)?
            {
                return Err(anyhow::anyhow!(
                    "{}",
                    i18n::tf("err.overwrite_cancelled", &[p])
                ));
            }
            // Non-interactive (piped/redirected) callers skip
            // the [y/N] prompt by design, but silently clobbering an existing
            // file is surprising; emit a one-line warning on stderr so the
            // overwrite is at least observable. Interactive runs already got
            // an explicit prompt, so they stay quiet here.
            if Path::new(p).exists() && !overwrite_prompt_needed(&input, stdin_tty, stdout_tty) {
                eprintln!("{}", overwrite_warning(p));
            }
            let mut out = open_file_writer(p)?;
            let res = process_stream_to(flow, &input, fmt, out.writer_mut(), false, cfg);
            match res {
                Ok(()) => out.commit().map_err(|e| {
                    anyhow::anyhow!(
                        "{}",
                        i18n::tf("err.flush_out_failed", &[i18n::os_error(&e).as_str()])
                    )
                })?,
                Err(e) => {
                    let tmp = out.tmp.clone();
                    drop(out);
                    let _ = std::fs::remove_file(&tmp);
                    return Err(e);
                }
            }
            Ok(())
        }
        None => {
            let stdout = std::io::stdout();
            let mut lock = stdout.lock();
            process_stream_to(flow, &input, fmt, &mut lock, flow_ends_with_text(flow), cfg)
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
    cfg: &EngineConfig,
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
    pool.install(|| run_batch_inner(flow, fmt, expanded, output_path, cfg))
}

#[cfg(not(target_arch = "wasm32"))]
fn run_batch_inner(
    flow: &Flow,
    fmt: OutputFormat,
    expanded: &[InputSpec],
    output_path: Option<&str>,
    cfg: &EngineConfig,
) -> anyhow::Result<()> {
    match output_path {
        // Execute in parallel and write files directly (no results held in memory; good for large batches).
        Some(dir) => {
            let results: Vec<(String, anyhow::Result<()>)> = expanded
                .par_iter()
                .map(|input| {
                    let label = input.display_label();
                    let res = (|| {
                        let rel = input.out_rel().ok_or_else(|| {
                            anyhow::anyhow!("{}", i18n::t("err.stdin_no_dir_out"))
                        })?;
                        let out_path = Path::new(dir).join(rel);
                        // Remember whether the target pre-existed
                        // so a failure never deletes a file this session did
                        // not create (e.g. a stale output from a previous run).
                        let target_pre_existed = out_path.exists();
                        // Batch mode never prompts (parallel
                        // workers), so an overwrite of an existing output is
                        // announced on stderr for observability.
                        if target_pre_existed {
                            eprintln!("{}", overwrite_warning(&out_path.display().to_string()));
                        }
                        // Streaming batch: block-level read/write,
                        // only one chunk plus barrier buffers stay in memory.
                        // On failure, clean up already-created leftover files (release the
                        // write handle first; Windows locks block deletion).
                        let write_res = {
                            // A user-supplied output directory may contain
                            // non-UTF-8 segments (Windows paths); surface the
                            // error instead of panicking.
                            let out_str = out_path.to_str().ok_or_else(|| {
                                anyhow::anyhow!(
                                    "{}",
                                    i18n::tf(
                                        "err.output_path_utf8",
                                        &[out_path.display().to_string().as_str()]
                                    )
                                )
                            })?;
                            let mut w = open_file_writer(out_str)?;
                            let step_res =
                                process_stream_to(flow, input, fmt, w.writer_mut(), false, cfg);
                            match step_res {
                                Ok(()) => w.commit().map_err(|e| {
                                    anyhow::anyhow!(
                                        "{}",
                                        i18n::tf(
                                            "err.flush_out_failed",
                                            &[i18n::os_error(&e).as_str()]
                                        )
                                    )
                                }),
                                Err(e) => {
                                    let tmp = w.tmp.clone();
                                    drop(w);
                                    if let Err(ce) = std::fs::remove_file(&tmp) {
                                        return Err(e.context(format!(
                                            "failed to remove temp file {}: {ce}",
                                            tmp.display()
                                        )));
                                    }
                                    Err(e)
                                }
                            }
                        };
                        // On failure, clean up only a target this session
                        // created (commit never ran, so a pre-existing target
                        // is untouched and must be preserved).
                        if let Err(e) = write_res {
                            if !target_pre_existed {
                                let _ = std::fs::remove_file(&out_path);
                            }
                            return Err(e);
                        }
                        Ok(())
                    })();
                    (label, res)
                })
                .collect();
            summarize(results)?;
            // A successful batch run reports the processed count on
            // stderr so the user knows the run finished (failures already
            // surface through the summarize error above).
            eprintln!(
                "{}",
                i18n::tf(
                    "msg.batch_summary",
                    &[
                        expanded.len().to_string().as_str(),
                        output_path.unwrap_or("-")
                    ]
                )
            );
            Ok(())
        }
        // Compute in parallel, print in order: keeps stdout deterministic and race-free.
        None => {
            let results: Vec<(String, anyhow::Result<Vec<u8>>)> = expanded
                .par_iter()
                .map(|input| {
                    let label = input.display_label();
                    // Collect the raw bytes and let write_stdout apply the
                    // output format exactly once. Passing `fmt` here caused the
                    // batch path to pre-render each file and then hex-encode the
                    // already rendered text again (double encoding).
                    let res = process_stream_collect(flow, input, OutputFormat::Raw, cfg);
                    (label, res)
                })
                .collect();
            let mut failed = Vec::new();
            let total = results.len();
            // By default batch stdout streams every file's
            // bytes with no forced framing (binary chains stay byte-exact).
            // A caller that wants readable text output can opt into explicit
            // framing with --batch-separator, emitted between outputs.
            let sep = cfg.batch_separator();
            for (i, (label, res)) in results.into_iter().enumerate() {
                match res {
                    Ok(data) => {
                        let sep_before = sep_before(i, sep);
                        // `--batch-label` opts into a readable
                        // `==> <input>` line per output (default off, so the
                        // stream stays byte-exact). The label is metadata on
                        // stdout, never part of the payload.
                        let label_before = batch_label_before(cfg, label.as_str());
                        write_stdout(
                            &data,
                            fmt,
                            sep_before,
                            flow_ends_with_text(flow),
                            label_before.as_deref(),
                        )
                        .map_err(|e| {
                            anyhow::anyhow!(
                                "{}",
                                i18n::tf("err.write_stdout", &[i18n::os_error(&e).as_str()])
                            )
                        })?;
                    }
                    Err(e) => failed.push(format!("{}: {}", label, e)),
                }
            }
            let succeeded = total - failed.len();
            if failed.is_empty() {
                Ok(())
            } else {
                anyhow::bail!(
                    "{}",
                    i18n::tf(
                        "err.n_inputs_failed",
                        &[
                            total.to_string().as_str(),
                            succeeded.to_string().as_str(),
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
    let total = results.len();
    let mut failed = Vec::new();
    for (label, res) in results {
        if let Err(e) = res {
            failed.push(format!("{}: {}", label, e));
        }
    }
    if failed.is_empty() {
        Ok(())
    } else {
        let succeeded = total - failed.len();
        anyhow::bail!(
            "{}",
            i18n::tf(
                "err.n_inputs_failed",
                &[
                    total.to_string().as_str(),
                    succeeded.to_string().as_str(),
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
    cfg: &EngineConfig,
) -> anyhow::Result<Vec<u8>> {
    let mut buf = Vec::new();
    process_stream_to(flow, input, fmt, &mut buf, false, cfg)?;
    Ok(buf)
}

/// Secret-class argument sources. A step argument whose
/// string value starts with `env:` is resolved from the process environment at
/// execution time, so key material never has to appear in shell history, the
/// command line, or a recipe URL. Unknown variables are a hard error (better to
/// fail loudly than to run with a missing key); `env:` alone resolves the empty
/// variable. All other values pass through untouched.
///
/// When `allow_env` is `Some`, only variables listed in that
/// whitelist may be resolved; a flow that tries to read any other variable is
/// rejected with a descriptive error. `None` preserves the legacy behavior.
fn expand_env_args(
    args: &std::collections::HashMap<String, String>,
    allow_env: Option<&std::collections::HashSet<String>>,
) -> anyhow::Result<std::collections::HashMap<String, String>> {
    const PREFIX: &str = "env:";
    let mut out = std::collections::HashMap::with_capacity(args.len());
    for (k, v) in args {
        if let Some(name) = v.strip_prefix(PREFIX) {
            if let Some(allowed) = allow_env
                && !allowed.contains(name)
            {
                return Err(anyhow::anyhow!(
                    "{}",
                    i18n::tf("err.env_not_allowed", &[name, k.as_str()])
                ));
            }
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

/// Static type check over the step chain. Only *strong* shapes
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
pub fn process_bytes(
    flow: &Flow,
    data: &[u8],
    fmt: OutputFormat,
    cfg: &EngineConfig,
) -> anyhow::Result<Vec<u8>> {
    check_io_chain(flow)?;
    process_bytes_depth(flow, data, fmt, 0, cfg)
}

/// Maximum Fork nesting depth. Guard against malicious or accidental flows that
/// would otherwise recurse without bound.
const FORK_MAX_DEPTH: usize = 16;

fn process_bytes_depth(
    flow: &Flow,
    data: &[u8],
    fmt: OutputFormat,
    depth: usize,
    cfg: &EngineConfig,
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
            // Bound the Fork join so N segments cannot amplify
            // output into memory exhaustion (each segment output is bounded
            // individually by its own barrier cap; the sum must also be).
            let mut joined_bytes = 0usize;
            for seg in segments {
                let out = process_bytes_depth(&rest, &seg, OutputFormat::Raw, depth + 1, cfg)?;
                joined_bytes = joined_bytes.saturating_add(out.len());
                if joined_bytes > cfg.max_input_bytes() {
                    anyhow::bail!(
                        "{}",
                        i18n::tf(
                            "err.input_too_large",
                            &[cfg.max_input_bytes().to_string().as_str()]
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
        // Resolve `env:`-sourced arguments before the op runs.
        let args = expand_env_args(&step.args, cfg.allow_env())?;
        // Per-step observability (bytes in/out + wall time).
        let step_start = std::time::Instant::now();
        let in_len = current.len();
        let in_head = if cfg.verbose() {
            current[..current.len().min(16)].to_vec()
        } else {
            Vec::new()
        };
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
        if cfg.verbose() {
            eprintln!(
                "[dpa] step {} {}: {}B -> {}B in {:?}  in[..16]={}  out[..16]={}",
                idx + 1,
                step.op,
                in_len,
                current.len(),
                step_start.elapsed(),
                hex_head(&in_head, 16),
                hex_head(&current, 16),
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
                    i18n::tf(
                        "err.read_input_failed",
                        &[
                            path.display().to_string().as_str(),
                            i18n::os_error(&e).as_str()
                        ]
                    )
                )
            })?;
            Ok(Box::new(BufReader::with_capacity(IO_BUF, f)))
        }
    }
}

/// Output file written to a `<path>.tmp` sibling and atomically renamed on
/// success, so an interrupted run never leaves a half-written file at the
/// requested path. Callers must call [`OutFile::commit`] on
/// success and drop + remove `tmp` on failure; a hard kill may leave the
/// `.tmp` sibling behind, which is intentionally recognizable as partial.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) struct OutFile {
    tmp: PathBuf,
    final_path: PathBuf,
    writer: BufWriter<std::fs::File>,
}

#[cfg(not(target_arch = "wasm32"))]
impl OutFile {
    pub(crate) fn writer_mut(&mut self) -> &mut dyn Write {
        &mut self.writer
    }

    pub(crate) fn commit(mut self) -> std::io::Result<()> {
        self.writer.flush()?;
        drop(self.writer);
        // Windows cannot rename over an existing file. Instead
        // of deleting the old file first (non-atomic; a failed rename would
        // leave the target missing), move the old file aside, install the new
        // one, then remove the backup. If the rename-in fails, roll the old
        // file back so the target is never lost.
        if self.final_path.exists() {
            let backup = self.tmp.with_extension("bak");
            // A stale backup from a previous crash would block the rename.
            let _ = std::fs::remove_file(&backup);
            std::fs::rename(&self.final_path, &backup)?;
            if let Err(e) = std::fs::rename(&self.tmp, &self.final_path) {
                let _ = std::fs::rename(&backup, &self.final_path);
                return Err(e);
            }
            std::fs::remove_file(&backup)
        } else {
            std::fs::rename(&self.tmp, &self.final_path)
        }
    }
}

/// Open an output writer (creates parent directories; shared by the streaming path).
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn open_file_writer(path: &str) -> anyhow::Result<OutFile> {
    let p = Path::new(path);
    if let Some(parent) = p.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|e| {
            anyhow::anyhow!(
                "{}",
                i18n::tf("err.create_outdir_failed", &[i18n::os_error(&e).as_str()])
            )
        })?;
    }
    // Use a per-process unique tmp name (PID + monotonic counter) so
    // concurrent runs or a stale sibling from a previous crash can never
    // collide with an in-flight writer; the `.dpa-*.tmp` suffix stays
    // recognizable as partial output. create_new (instead of create) refuses
    // to follow a pre-existing symlink or truncate a stale file: on EEXIST we
    // bump the counter and retry with a fresh name.
    static TMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let tmp = loop {
        let seq = TMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let candidate = PathBuf::from(format!("{path}.dpa-{}-{seq}.tmp", std::process::id()));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(f) => break (candidate, f),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "{}",
                    i18n::tf("err.create_outfile_failed", &[i18n::os_error(&e).as_str()])
                ));
            }
        }
    };
    let f = tmp.1;
    Ok(OutFile {
        tmp: tmp.0,
        final_path: p.to_path_buf(),
        writer: BufWriter::with_capacity(IO_BUF, f),
    })
}

/// Hybrid pipeline barrier (chunk-level pipeline):
/// wraps a non-streamable op so a partially-streamable flow still runs incrementally.
/// `write` buffers every incoming chunk and emits nothing; `finish` runs the op's in-memory
/// path once on the whole buffer. Steps before/after the barrier keep streaming chunk by chunk.
struct BarrierStream {
    op: &'static ops::Op,
    args: std::collections::HashMap<String, String>,
    buf: Vec<u8>,
    max_input: usize,
}

impl ops::StreamingOp for BarrierStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        // Cap the unbounded whole-buffer accumulation so a huge
        // input cannot exhaust memory behind a non-streamable op.
        if self.buf.len().saturating_add(chunk.len()) > self.max_input {
            anyhow::bail!(
                "{}",
                i18n::tf(
                    "err.input_too_large",
                    &[self.max_input.to_string().as_str()]
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

/// True when the flow's final step is a text-shaped op (UTF-8 / hex / base64 /
/// JSON): its raw output should end with a newline. Byte-shaped ops
/// (`random`, decode outputs) are left untouched.
#[cfg(not(target_arch = "wasm32"))]
fn flow_ends_with_text(flow: &Flow) -> bool {
    let Some(last) = flow.steps.last() else {
        return false;
    };
    match ops::find_op(&last.op) {
        Some(op) => matches!(
            op.output,
            ops::OpIO::Utf8 | ops::OpIO::Hex | ops::OpIO::Base64 | ops::OpIO::Json
        ),
        None => false,
    }
}

/// Write rendered output; hex is encoded chunk by chunk, equivalent to whole-buffer encoding.
/// `hex_final` marks the last chunk of a hex stream so the newline is emitted
/// exactly once at the end; intermediate chunks must not break
/// the hex line, otherwise downstream line-oriented consumers see fragments.
#[cfg(not(target_arch = "wasm32"))]
fn write_render(
    out: &mut dyn Write,
    data: &[u8],
    fmt: OutputFormat,
    hex_final: bool,
) -> std::io::Result<()> {
    match fmt {
        // Raw: write the exact byte stream. The trailing newline for text
        // chains is the caller's job (stdout only, once at the very end);
        // never per chunk and never for file outputs, so streaming stays
        // byte-identical to the in-memory path.
        OutputFormat::Raw => out.write_all(data),
        // Hex is rendered as a single text line with one trailing newline so
        // that the streaming path is byte-identical to write_stdout; the
        // whole-buffer path renders hex the same way. Empty
        // data renders nothing (no stray blank line in streaming chunks).
        OutputFormat::Hex => {
            if data.is_empty() {
                return Ok(());
            }
            let mut s = hex::encode(data).into_bytes();
            if hex_final {
                s.push(b'\n');
            }
            out.write_all(&s)
        }
    }
}

/// End-to-end streaming: read input in chunks -> push each chunk through the streaming op chain -> render -> write to out.
/// Only invoked when every step supports streaming; at most one chunk (IO_BUF) is resident.
/// Build the streaming handler chain for a flow.
/// Every step yields a handler: streamable steps use their
/// native factory, non-streamable steps are wrapped in a [`BarrierStream`] buffer.
fn build_handlers(
    flow: &Flow,
    cfg: &EngineConfig,
) -> anyhow::Result<Vec<Box<dyn ops::StreamingOp>>> {
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
        // Resolve `env:`-sourced arguments in the streaming path too.
        let args = expand_env_args(&step.args, cfg.allow_env())?;
        match &op.stream {
            Some(factory) => handlers.push(factory(&args).map_err(|e| {
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
                args: args.clone(),
                buf: Vec::new(),
                max_input: cfg.max_input_bytes(),
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
    cfg: &EngineConfig,
) -> anyhow::Result<Vec<u8>> {
    if flow_has_fork(flow) {
        // Fork needs the whole buffer (segments are re-run through the remaining
        // steps); fall back to the in-memory path, which is the canonical one.
        return process_bytes(flow, data, fmt, cfg);
    }
    let mut handlers = build_handlers(flow, cfg)?;
    let mut stats: Vec<StepStat> = (0..handlers.len()).map(|_| StepStat::new()).collect();
    let mut acc = Vec::new();
    for chunk in data.chunks(IO_BUF) {
        let mut cur: &[u8] = chunk;
        let mut produced;
        for (hi, h) in handlers.iter_mut().enumerate() {
            let in_n = cur.len();
            produced = h.write(cur).map_err(|e| {
                anyhow::anyhow!(
                    "{}",
                    i18n::tf(
                        "err.step_failed",
                        &[
                            (hi + 1).to_string().as_str(),
                            flow.steps[hi].op.as_str(),
                            e.to_string().as_str()
                        ]
                    )
                )
            })?;
            stats[hi].in_total += in_n;
            stats[hi].out_total += produced.len();
            if stats[hi].out_head.is_empty() && !produced.is_empty() {
                stats[hi].out_head = produced[..produced.len().min(16)].to_vec();
            }
            cur = &produced;
        }
        acc.extend_from_slice(cur);
    }
    let tail = finish_tail(&mut handlers, 0, &mut stats, flow, cfg)?;
    acc.extend_from_slice(&tail);
    report_stream_stats(flow, &stats, cfg);
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
    text_tail: bool,
    cfg: &EngineConfig,
) -> anyhow::Result<()> {
    if flow_has_fork(flow) {
        // Fork segments are re-run through the remaining steps, which requires
        // the whole input; fall back to the in-memory path for exact semantics.
        let mut all = Vec::new();
        open_reader(input)?.read_to_end(&mut all).map_err(|e| {
            anyhow::anyhow!(
                "{}",
                i18n::tf("err.stream_read_failed", &[i18n::os_error(&e).as_str()])
            )
        })?;
        // The whole-buffer fallback must respect --max-input-bytes just
        // like the streaming path (BarrierStream / fork join) does.
        if all.len() > cfg.max_input_bytes() {
            anyhow::bail!(
                "{}",
                i18n::tf(
                    "err.input_too_large",
                    &[cfg.max_input_bytes().to_string().as_str()]
                )
            );
        }
        let out_bytes = process_bytes(flow, &all, OutputFormat::Raw, cfg)?;
        // The fork fallback path must enforce --max-step-output-bytes too,
        // otherwise a runaway transform behind a Fork step bypasses the cap that
        // the streaming write path enforces per step.
        if out_bytes.len() > cfg.max_step_output_bytes() {
            let last_op = flow.steps.last().map(|s| s.op.as_str()).unwrap_or("?");
            anyhow::bail!(
                "{}",
                i18n::tf(
                    "err.step_output_too_large",
                    &[
                        flow.steps.len().to_string().as_str(),
                        last_op,
                        out_bytes.len().to_string().as_str(),
                        cfg.max_step_output_bytes().to_string().as_str()
                    ]
                )
            );
        }
        write_render(out, &out_bytes, fmt, true)?;
        if text_tail && fmt != OutputFormat::Hex && !out_bytes.is_empty() {
            out.write_all(b"\n")?;
        }
        return out.flush().map_err(|e| {
            anyhow::anyhow!(
                "{}",
                i18n::tf("err.flush_out_failed", &[i18n::os_error(&e).as_str()])
            )
        });
    }
    let mut handlers = build_handlers(flow, cfg)?;
    let mut stats: Vec<StepStat> = (0..handlers.len()).map(|_| StepStat::new()).collect();

    let mut reader = open_reader(input)?;
    let mut buf = vec![0u8; IO_BUF];
    let mut wrote_any = false;
    // Remember the last byte actually written so the final trailing
    // newline is added only when the rendered chain does not end with one.
    let mut last_byte: Option<u8> = None;
    loop {
        let n = reader.read(&mut buf).map_err(|e| {
            anyhow::anyhow!(
                "{}",
                i18n::tf("err.stream_read_failed", &[i18n::os_error(&e).as_str()])
            )
        })?;
        if n == 0 {
            break;
        }
        let mut chunk: &[u8] = &buf[..n];
        let mut produced;
        for (hi, h) in handlers.iter_mut().enumerate() {
            let in_n = chunk.len();
            produced = h.write(chunk).map_err(|e| {
                anyhow::anyhow!(
                    "{}",
                    i18n::tf(
                        "err.step_failed",
                        &[
                            (hi + 1).to_string().as_str(),
                            flow.steps[hi].op.as_str(),
                            e.to_string().as_str()
                        ]
                    )
                )
            })?;
            stats[hi].in_total += in_n;
            stats[hi].out_total += produced.len();
            check_step_output_cap(hi, flow, &stats, cfg)?;
            if stats[hi].out_head.is_empty() && !produced.is_empty() {
                stats[hi].out_head = produced[..produced.len().min(16)].to_vec();
            }
            chunk = &produced;
        }
        if !chunk.is_empty() {
            wrote_any = true;
            last_byte = chunk.last().copied();
        }
        write_render(out, chunk, fmt, false)?;
    }
    let tail = finish_tail(&mut handlers, 0, &mut stats, flow, cfg)?;
    if !tail.is_empty() {
        wrote_any = true;
        last_byte = tail.last().copied();
    }
    if !tail.is_empty() {
        write_render(out, &tail, fmt, true)?;
    } else if fmt == OutputFormat::Hex && wrote_any {
        // Hex stream with no tail chunk: the newline still has to be emitted
        // exactly once so the single-line promise holds.
        out.write_all(b"\n")?;
    }
    // Text-shaped chains get exactly one trailing newline on
    // stdout so shell output / `>> file` appends never glue to the prompt or
    // prior content; byte chains and file outputs stay byte-identical to
    // in-memory. Hex already got its single newline from write_render.
    // Line-shaped ops (head/tail/filter) already end their output with
    // a newline, so the extra one is added only when the last byte differs.
    if text_tail && fmt != OutputFormat::Hex && wrote_any && last_byte != Some(b'\n') {
        out.write_all(b"\n")?;
    }
    report_stream_stats(flow, &stats, cfg);
    out.flush().map_err(|e| {
        anyhow::anyhow!(
            "{}",
            i18n::tf("err.flush_out_failed", &[i18n::os_error(&e).as_str()])
        )
    })
}

/// Enforce the per-step streaming output cap. `0` disables the
/// check; a single step inflating beyond the cap is treated as a runaway
/// transform so the pipeline bails instead of grinding on for minutes.
fn check_step_output_cap(
    hi: usize,
    flow: &Flow,
    stats: &[StepStat],
    cfg: &EngineConfig,
) -> anyhow::Result<()> {
    let lim = cfg.max_step_output_bytes();
    if lim > 0 && stats[hi].out_total > lim {
        anyhow::bail!(
            "{}",
            i18n::tf(
                "err.step_output_too_large",
                &[
                    (hi + 1).to_string().as_str(),
                    flow.steps[hi].op.as_str(),
                    stats[hi].out_total.to_string().as_str(),
                    lim.to_string().as_str(),
                ]
            )
        );
    }
    Ok(())
}

/// Finish the streaming chain: finish each level in turn, feed its output into the next level, and return all tail bytes.
fn finish_tail(
    handlers: &mut [Box<dyn ops::StreamingOp>],
    idx: usize,
    stats: &mut [StepStat],
    flow: &Flow,
    cfg: &EngineConfig,
) -> anyhow::Result<Vec<u8>> {
    if idx == handlers.len() {
        return Ok(Vec::new());
    }
    let mut acc = handlers[idx].finish()?;
    if stats.len() > idx {
        stats[idx].out_total += acc.len();
        check_step_output_cap(idx, flow, stats, cfg)?;
        if stats[idx].out_head.is_empty() && !acc.is_empty() {
            stats[idx].out_head = acc[..acc.len().min(16)].to_vec();
        }
    }
    for (j, h) in handlers[idx + 1..].iter_mut().enumerate() {
        let hj = idx + 1 + j;
        let produced = h.write(&acc)?;
        stats[hj].out_total += produced.len();
        check_step_output_cap(hj, flow, stats, cfg)?;
        if stats[hj].out_head.is_empty() && !produced.is_empty() {
            stats[hj].out_head = produced[..produced.len().min(16)].to_vec();
        }
        acc = produced;
    }
    let rest = finish_tail(handlers, idx + 1, stats, flow, cfg)?;
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

/// First `n` bytes as a lowercase hex string for verbose previews; `(empty)`
/// for empty data, trailing `...` when truncated.
fn hex_head(data: &[u8], n: usize) -> String {
    if data.is_empty() {
        return "(empty)".to_string();
    }
    let shown = &data[..data.len().min(n)];
    let mut s = hex::encode(shown);
    if data.len() > n {
        s.push_str("...");
    }
    s
}

/// Per-step counters for streaming-path verbose output. The streaming pipeline
/// cannot know a step's final size while chunks are still flowing, so it keeps
/// running totals plus the first non-empty output head for a preview.
struct StepStat {
    in_total: usize,
    out_total: usize,
    out_head: Vec<u8>,
}

impl StepStat {
    fn new() -> Self {
        StepStat {
            in_total: 0,
            out_total: 0,
            out_head: Vec::new(),
        }
    }
}

/// Print streaming-path per-step stats when `--verbose` is on. Steps are
/// reported by flow order; handler count equals step count on this path
/// (fork flows fall back to the in-memory path before reaching here).
fn report_stream_stats(flow: &Flow, stats: &[StepStat], cfg: &EngineConfig) {
    if !cfg.verbose() {
        return;
    }
    for (i, s) in stats.iter().enumerate() {
        let op = flow.steps.get(i).map(|s| s.op.as_str()).unwrap_or("?");
        eprintln!(
            "[dpa] step {} {}: {}B -> {}B (streamed)  out[..16]={}",
            i + 1,
            op,
            s.in_total,
            s.out_total,
            hex_head(&s.out_head, 16),
        );
    }
}

/// Batch framing is emitted only between outputs, never
/// before the first one.
fn sep_before(i: usize, sep: Option<&str>) -> Option<&str> {
    if i > 0 { sep } else { None }
}

/// The label line emitted before each batch stdout output
/// when `--batch-label` is on (default off). It is metadata on stdout, never
/// part of the payload, and stays outside the separator framing.
fn batch_label_line(label: &str) -> String {
    format!("==> {label}\n")
}

/// `Some(label_line)` when the batch-label switch is on,
/// `None` otherwise (default behaviour: byte-exact stream, no injected text).
fn batch_label_before(cfg: &EngineConfig, label: &str) -> Option<String> {
    if cfg.batch_label() {
        Some(batch_label_line(label))
    } else {
        None
    }
}

/// Write to stdout. `label_before` is an optional `==> <input>` metadata line
/// emitted first (only when --batch-label is on).
/// `sep_before` is an optional separator emitted just before the payload; the
/// batch path passes it only between outputs; no forced
/// `=== label ===` framing by default.
#[cfg(not(target_arch = "wasm32"))]
fn write_stdout(
    data: &[u8],
    fmt: OutputFormat,
    sep_before: Option<&str>,
    text_tail: bool,
    label_before: Option<&str>,
) -> std::io::Result<()> {
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    if let Some(lb) = label_before {
        lock.write_all(lb.as_bytes())?;
    }
    if let Some(sep) = sep_before {
        lock.write_all(sep.as_bytes())?;
    }
    match fmt {
        // Same text-tail rule as write_render so batch mode and
        // single-input mode agree byte-for-byte.
        OutputFormat::Raw => {
            if text_tail && !data.is_empty() {
                lock.write_all(data)?;
                lock.write_all(b"\n")?;
            } else {
                lock.write_all(data)?;
            }
        }
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
    // Distinct inputs that map to the same output relative path
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

    /// RAII guard so a test-scoped environment variable is always
    /// removed on drop (including on panic), preventing cross-test pollution
    /// in the parallel test harness.
    struct EnvVarGuard(&'static str);
    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            // SAFETY: guarded by Drop below; variable name is unique per test.
            unsafe { std::env::set_var(key, value) };
            EnvVarGuard(key)
        }
    }
    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            // SAFETY: removing a variable set by this same guard.
            unsafe { std::env::remove_var(self.0) };
        }
    }

    /// Overwrite prompts apply only to file inputs on real
    /// terminals; piped (non-TTY) runs and stdin-fed runs stay silent.
    #[test]
    fn overwrite_prompt_needed_conditions() {
        let file = InputSpec::File {
            path: PathBuf::from("in.bin"),
            out_rel: PathBuf::from("in.bin"),
        };
        let stdin = InputSpec::Stdin;
        assert!(overwrite_prompt_needed(&file, true, true));
        assert!(!overwrite_prompt_needed(&file, true, false));
        assert!(!overwrite_prompt_needed(&file, false, true));
        assert!(!overwrite_prompt_needed(&stdin, true, true));
    }

    /// Progress-line labels must be relative (basename for
    /// standalone files, path relative to the input directory for files
    /// inside directories); the absolute path stays in `label()` for
    /// ordering/dedup/conflict checks.
    #[test]
    fn display_label_uses_relative_path() {
        let standalone = InputSpec::File {
            path: PathBuf::from(r"C:\data\in\a.txt"),
            out_rel: PathBuf::from("a.txt"),
        };
        assert_eq!(standalone.display_label(), "a.txt");
        assert_eq!(standalone.label(), r"C:\data\in\a.txt");
        let nested = InputSpec::File {
            path: PathBuf::from(r"C:\data\in\sub\b.txt"),
            out_rel: PathBuf::from("sub/b.txt"),
        };
        assert_eq!(nested.display_label(), "sub/b.txt");
        assert_eq!(InputSpec::Stdin.display_label(), "<stdin>");
    }

    /// Parser error strings must not leak Rust API
    /// concepts; the line/column prefix and the offending key name survive.
    #[test]
    fn polish_yaml_error_hides_api_terms() {
        let deep =
            polish_yaml_error("error: line 65 column 129: budget breached: Depth { depth: 65 }");
        assert_eq!(
            deep,
            "error: line 65 column 129: maximum YAML nesting depth (65) exceeded"
        );
        let dup = polish_yaml_error(
            "error: line 6 column 7: duplicate mapping key: k, set DuplicateKeyPolicy in Options if acceptable",
        );
        assert_eq!(
            dup,
            "error: line 6 column 7: duplicate mapping key: k; remove or rename one of the keys"
        );
        let other = polish_yaml_error("error: line 2 column 3: unknown step");
        assert_eq!(other, "error: line 2 column 3: unknown step");
    }

    /// Hash ops are Raw outputs, so stdout rendering never
    /// appends a trailing newline to the raw digest (Hex was wrong: it made
    /// flow_ends_with_text treat the digest as text and pollute the stream).
    #[test]
    fn hash_ops_raw_output_byte_exact() {
        assert_eq!(ops::find_op("dpa:sha256").unwrap().output, ops::OpIO::Raw);
        assert_eq!(ops::find_op("dpa:md5").unwrap().output, ops::OpIO::Raw);
        let flow: Flow = from_yaml("steps: [{op: dpa:sha256}]").unwrap();
        assert!(!flow_ends_with_text(&flow));
        // Streaming path yields the exact 32-byte digest, no newline tail.
        let out =
            process_bytes_stream(&flow, b"hello", OutputFormat::Raw, &EngineConfig::default())
                .unwrap();
        let expected = [
            0x2c, 0xf2, 0x4d, 0xba, 0x5f, 0xb0, 0xa3, 0x0e, 0x26, 0xe8, 0x3b, 0x2a, 0xc5, 0xb9,
            0xe2, 0x9e, 0x1b, 0x16, 0x1e, 0x5c, 0x1f, 0xa7, 0x42, 0x5e, 0x73, 0x04, 0x33, 0x62,
            0x93, 0x8b, 0x98, 0x24,
        ];
        assert_eq!(out.len(), 32, "digest must be 32 bytes, got {}", out.len());
        assert_eq!(out, expected);
    }

    /// The non-interactive overwrite warning carries the path.
    #[test]
    fn overwrite_warning_carries_path() {
        let w = overwrite_warning("out.bin");
        assert!(w.contains("out.bin"), "{w}");
        let w_zh = i18n::tf("warn.overwrite_existing", &["x.bin"]);
        assert!(w_zh.contains("x.bin"), "{w_zh}");
    }

    /// Only an explicit y/yes overwrites; n, empty, EOF-like and
    /// partial words all cancel.
    #[test]
    fn parse_overwrite_answer_accepts_only_y_yes() {
        assert!(parse_overwrite_answer("y"));
        assert!(parse_overwrite_answer("Y\n"));
        assert!(parse_overwrite_answer("yes"));
        assert!(!parse_overwrite_answer("n"));
        assert!(!parse_overwrite_answer(""));
        assert!(!parse_overwrite_answer("yep"));
        assert!(!parse_overwrite_answer("maybe"));
    }

    /// `env:`-prefixed args resolve from the environment;
    /// plain values pass through; a missing variable is a hard error.
    #[test]
    fn expand_env_args_resolves_and_errors() {
        let mut args = std::collections::HashMap::new();
        args.insert("key".to_string(), "env:DPA_TEST_KEY".to_string());
        args.insert("algo".to_string(), "sha256".to_string());
        let _guard = EnvVarGuard::set("DPA_TEST_KEY", "s3cret");
        let out = expand_env_args(&args, None).unwrap();
        assert_eq!(out.get("key").map(String::as_str), Some("s3cret"));
        assert_eq!(out.get("algo").map(String::as_str), Some("sha256"));

        let mut missing = std::collections::HashMap::new();
        missing.insert("key".to_string(), "env:DPA_TEST_KEY_ABSENT".to_string());
        let err = expand_env_args(&missing, None).unwrap_err();
        assert!(err.to_string().contains("DPA_TEST_KEY_ABSENT"));
    }

    /// With a whitelist configured, `env:` can only resolve
    /// listed variables; anything else is rejected before lookup.
    #[test]
    fn expand_env_args_whitelist_rejects_unlisted() {
        let mut allowed = std::collections::HashSet::new();
        allowed.insert("DPA_ALLOWED".to_string());
        let mut args = std::collections::HashMap::new();
        args.insert("a".to_string(), "env:DPA_ALLOWED".to_string());
        args.insert("b".to_string(), "env:DPA_SNEAKY".to_string());
        let _guard = EnvVarGuard::set("DPA_ALLOWED", "yes");
        let _guard2 = EnvVarGuard::set("DPA_SNEAKY", "no");

        // Whitelisted variable resolves.
        let mut only = std::collections::HashMap::new();
        only.insert("a".to_string(), "env:DPA_ALLOWED".to_string());
        let out = expand_env_args(&only, Some(&allowed)).unwrap();
        assert_eq!(out.get("a").map(String::as_str), Some("yes"));

        // Unlisted variable is rejected even though it exists.
        let err = expand_env_args(&args, Some(&allowed)).unwrap_err();
        assert!(err.to_string().contains("DPA_SNEAKY"), "got: {err}");
        assert!(err.to_string().contains("--allow-env"), "got: {err}");
    }

    /// The streaming path (build_handlers) must also expand
    /// `env:`-sourced arguments; otherwise `dpa run` falls back to treating
    /// the literal prefix as key material.
    #[test]
    fn stream_path_expands_env_args() {
        // Default EngineConfig is used throughout; cap-specific tests build
        // their own config value so no process-wide state can leak between
        // tests.
        let d = tmpdir("stream_env");
        let _guard = EnvVarGuard::set("DPA_TEST_STREAM_KEY", "0123456789abcdef");
        let ok_flow: Flow = from_yaml(
            "steps:\n  - op: dpa:aes:encrypt\n    args: {key: 'env:DPA_TEST_STREAM_KEY', mode: ecb}\n",
        )
        .unwrap();
        let input = d.join("in.bin");
        std::fs::write(&input, b"hello dpa env stream").unwrap();
        let expanded = expand_inputs(&[input.to_str().unwrap().to_string()], false).unwrap();
        let out = d.join("out.bin");
        run_stream_to_file(&ok_flow, &expanded[0], &out).unwrap();

        let bad_flow: Flow = from_yaml(
            "steps:\n  - op: dpa:aes:encrypt\n    args: {key: 'env:DPA_TEST_STREAM_KEY_ABSENT', mode: ecb}\n",
        )
        .unwrap();
        let err = run_stream_to_file(&bad_flow, &expanded[0], &out).unwrap_err();
        assert!(err.to_string().contains("DPA_TEST_STREAM_KEY_ABSENT"));
    }

    /// Oversized flow YAML is rejected before the
    /// parser runs (size-limit mitigation for the YAML parser).
    #[test]
    fn flow_yaml_size_cap_rejected() {
        let mut big = String::with_capacity(MAX_FLOW_YAML_BYTES + 1);
        big.push_str("name: big\nsteps:\n  - op: dpa:base64:decode\n");
        while big.len() < MAX_FLOW_YAML_BYTES + 1 {
            big.push('#');
        }
        let err = run_flow_yaml(
            &big,
            &[],
            None,
            None,
            false,
            1,
            None,
            false,
            &EngineConfig::default(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("size limit"), "{}", err);
    }

    /// A leading UTF-8 BOM must not break flow parsing.
    #[test]
    fn flow_with_bom_parses() {
        let yaml = "\u{FEFF}steps:\n  - op: dpa:base64:decode\n";
        // No panic/error: BOM is stripped before serde-saphyr runs.
        run_flow_yaml(
            yaml,
            &[],
            None,
            None,
            false,
            1,
            None,
            false,
            &EngineConfig::default(),
        )
        .unwrap();
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

    /// Type chain check: only explicitly declared, non-Raw shapes constrain
    /// the step chain; Raw inputs accept any upstream bytes.
    #[test]
    fn io_type_chain_check() {
        let flow = |yaml: &str| -> Flow { from_yaml(yaml).unwrap() };
        let err_of = |yaml: &str| -> String {
            process_bytes(
                &flow(yaml),
                b"",
                OutputFormat::Raw,
                &EngineConfig::default(),
            )
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
            &EngineConfig::default(),
        );
        assert!(ok.is_ok(), "{}", ok.unwrap_err());

        // base64:encode -> base64:decode: passes and round-trips.
        let out = process_bytes(
            &flow("steps:\n  - op: dpa:base64:encode\n  - op: dpa:base64:decode\n"),
            b"hello",
            OutputFormat::Raw,
            &EngineConfig::default(),
        )
        .unwrap();
        assert_eq!(out, b"hello");

        // Raw input ops do not constrain upstream (hex:encode accepts any bytes).
        let ok = process_bytes(
            &flow("steps:\n  - op: dpa:base64:encode\n  - op: dpa:hex:encode\n"),
            b"abc",
            OutputFormat::Raw,
            &EngineConfig::default(),
        );
        assert!(ok.is_ok(), "{}", ok.unwrap_err());
    }

    #[test]
    fn expand_inputs_detects_out_rel_conflict() {
        // dir1/a.bin and dir2/a.bin both expand to out_rel a.bin;
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
        let flow: Flow = from_yaml(&std::fs::read_to_string(&flow).unwrap()).unwrap();
        let out = process_mem(&flow, &expanded[0], OutputFormat::Raw);
        assert_eq!(out, b"aGVsbG8=");
    }

    #[test]
    fn stream_line_op_ends_with_single_newline() {
        let d = tmpdir("p2_1");
        let flow = d.join("f.yaml");
        write_flow(
            &flow,
            "steps:\n  - op: dpa:head\n    args:\n      n: \"2\"\n",
        );
        let input = d.join("in.txt");
        std::fs::write(&input, b"1\n2\n3\n4\n5\n").unwrap();

        let expanded = expand_inputs(&[input.to_str().unwrap().to_string()], false).unwrap();
        let flow: Flow = from_yaml(&std::fs::read_to_string(&flow).unwrap()).unwrap();
        let mut out = Vec::new();
        process_stream_to(
            &flow,
            &expanded[0],
            OutputFormat::Raw,
            &mut out,
            true,
            &EngineConfig::default(),
        )
        .unwrap();
        // The streaming stdout path must end with exactly one newline
        // (it used to append a second one after a line-shaped op).
        assert_eq!(out, b"1\n2\n");
        let mut out2 = Vec::new();
        process_stream_to(
            &flow,
            &expanded[0],
            OutputFormat::Raw,
            &mut out2,
            false,
            &EngineConfig::default(),
        )
        .unwrap();
        // File-to-file path stays byte-identical to the op output.
        assert_eq!(out2, b"1\n2\n");
    }

    #[test]
    fn summarize_reports_failed_inputs_with_details() {
        // The summary must carry total/succeeded/failed counts and the
        // per-input error detail (the old two-argument call produced an i18n
        // template mismatch instead).
        let res = summarize(vec![
            ("ok.txt".to_string(), Ok(())),
            ("bad.txt".to_string(), Err(anyhow::anyhow!("boom"))),
        ]);
        let err = res.unwrap_err().to_string();
        assert!(err.contains("2"), "total missing: {err}");
        assert!(err.contains("1"), "succeeded missing: {err}");
        assert!(err.contains("bad.txt: boom"), "detail missing: {err}");
        // All-ok summary returns Ok.
        assert!(summarize(vec![("a".to_string(), Ok(()))]).is_ok());
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
        let flow: Flow = from_yaml(&std::fs::read_to_string(&flow).unwrap()).unwrap();
        run_batch(
            &flow,
            OutputFormat::Raw,
            &expanded,
            Some(outdir.to_str().unwrap()),
            2,
            &EngineConfig::default(),
        )
        .unwrap();

        let a = std::fs::read(outdir.join("a.bin")).unwrap();
        let b = std::fs::read(outdir.join("b.bin")).unwrap();
        // 'a'^0x2A='K'; 'b'^0x2A='H'; 'c'^0x2A='I'; 'd'^0x2A='N'
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
        let flow: Flow = from_yaml(&std::fs::read_to_string(&flow).unwrap()).unwrap();
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
        let flow: Flow = from_yaml(&std::fs::read_to_string(&flow).unwrap()).unwrap();
        let res = run_batch(
            &flow,
            OutputFormat::Raw,
            &expanded,
            Some(outdir.to_str().unwrap()),
            2,
            &EngineConfig::default(),
        );
        assert!(res.is_err()); // aggregate error
        assert!(outdir.join("ok.bin").exists()); // but the successful file is already written
        assert!(!outdir.join("bad.bin").exists());
    }

    #[test]
    fn batch_separator_framing_rules() {
        // Default is no framing (binary integrity first);
        // with an explicit separator it is emitted only between outputs.
        assert_eq!(sep_before(0, Some("--")), None);
        assert_eq!(sep_before(1, Some("--")), Some("--"));
        assert_eq!(sep_before(2, Some("--")), Some("--"));
        assert_eq!(sep_before(3, None), None);
        assert_eq!(EngineConfig::default().batch_separator(), None);
        assert_eq!(
            EngineConfig::default()
                .with_batch_separator(Some("---".to_string()))
                .batch_separator(),
            Some("---")
        );
        // Empty separators are normalized away.
        assert_eq!(
            EngineConfig::default()
                .with_batch_separator(Some(String::new()))
                .batch_separator(),
            None
        );
    }

    #[test]
    fn batch_label_default_off_and_builder() {
        // `--batch-label` is opt-in; the default must keep
        // batch stdout byte-exact (no injected label lines).
        assert!(!EngineConfig::default().batch_label());
        assert!(EngineConfig::default().with_batch_label(true).batch_label());
        assert!(
            !EngineConfig::default()
                .with_batch_label(false)
                .batch_label()
        );
    }

    #[test]
    fn batch_label_line_and_switch_behavior() {
        // The label line is `==> <input>\n` and only enters
        // the stream when the switch is on. Default (off) emits nothing.
        assert_eq!(batch_label_line("<stdin>"), "==> <stdin>\n");
        assert_eq!(batch_label_line("dir/a.bin"), "==> dir/a.bin\n");
        let cfg_off = EngineConfig::default();
        assert_eq!(batch_label_before(&cfg_off, "a.bin"), None);
        let cfg_on = EngineConfig::default().with_batch_label(true);
        assert_eq!(
            batch_label_before(&cfg_on, "a.bin"),
            Some("==> a.bin\n".to_string())
        );
        // First output also gets the label when enabled (not only between).
        assert_eq!(
            batch_label_before(&cfg_on, "<stdin>"),
            Some("==> <stdin>\n".to_string())
        );
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
        process_bytes(flow, &data, fmt, &EngineConfig::default()).unwrap()
    }

    // ---- streaming path tests: streaming output must match the in-memory path byte for byte ----

    /// Produce one streaming execution (simulating a single-input `-o` file write).
    fn run_stream_to_file(flow: &Flow, input: &InputSpec, out_path: &Path) -> anyhow::Result<()> {
        let mut w = open_file_writer(out_path.to_str().unwrap()).unwrap();
        let res = process_stream_to(
            flow,
            input,
            OutputFormat::Raw,
            w.writer_mut(),
            false,
            &EngineConfig::default(),
        );
        match res {
            Ok(()) => w.commit().map_err(|e| anyhow::anyhow!("commit: {e}")),
            Err(e) => {
                let tmp = w.tmp.clone();
                drop(w);
                let _ = std::fs::remove_file(&tmp);
                Err(e)
            }
        }
    }

    #[test]
    fn outfile_failure_leaves_no_partial_target() {
        // An interrupted/failed stream must not leave a
        // half-written file at the requested output path (nor a tmp sibling).
        let d = tmpdir("outfile_fail");
        let flow = d.join("f.yaml");
        write_flow(&flow, "steps:\n  - op: dpa:base64:decode\n");
        let flow: Flow = from_yaml(&std::fs::read_to_string(&flow).unwrap()).unwrap();
        let input_file = d.join("in.bin");
        std::fs::write(&input_file, b"!!! not base64 !!!").unwrap();
        let expanded = expand_inputs(&[input_file.to_str().unwrap().to_string()], false).unwrap();
        let out_path = d.join("out.bin");
        // Strict decode rejects this payload, so the stream errors early.
        let res = run_stream_to_file(&flow, &expanded[0], &out_path);
        assert!(res.is_err());
        assert!(!out_path.exists(), "partial target must not exist");
        // Tmp sibling names are unique per writer, so assert by suffix
        // instead of a fixed `<path>.tmp` literal.
        let leftover: Vec<_> = std::fs::read_dir(&d)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .is_some_and(|x| x == std::ffi::OsStr::new("tmp"))
            })
            .collect();
        assert!(
            leftover.is_empty(),
            "tmp sibling must be cleaned: {leftover:?}"
        );
    }

    #[test]
    fn step_output_cap_aborts_runaway_stream() {
        // A step inflating beyond the per-step cap must abort the
        // pipeline instead of grinding on (32 x 'a' -> 44 base64 chars > 16).
        let d = tmpdir("step_cap");
        let flow = d.join("f.yaml");
        write_flow(&flow, "steps:\n  - op: dpa:base64:encode\n");
        let flow: Flow = from_yaml(&std::fs::read_to_string(&flow).unwrap()).unwrap();
        let input_file = d.join("in.bin");
        std::fs::write(&input_file, vec![b'a'; 32]).unwrap();
        let expanded = expand_inputs(&[input_file.to_str().unwrap().to_string()], false).unwrap();
        let mut out = Vec::new();
        let cfg_small = EngineConfig::default().with_max_step_output_bytes(16);
        let res = process_stream_to(
            &flow,
            &expanded[0],
            OutputFormat::Raw,
            &mut out,
            false,
            &cfg_small,
        );
        assert!(res.is_err(), "runaway step must be capped");
        // A lenient cap still lets the same flow succeed.
        let cfg_ok = EngineConfig::default().with_max_step_output_bytes(64);
        let res = process_stream_to(
            &flow,
            &expanded[0],
            OutputFormat::Raw,
            &mut out,
            false,
            &cfg_ok,
        );
        assert!(res.is_ok(), "capped within limit must pass");
    }

    #[test]
    fn batch_workers_observe_step_output_cap() {
        // The per-step cap must be observed by rayon workers in
        // batch mode (the old thread_local leaked the default 64 MiB to workers).
        let d = tmpdir("batch_cap");
        let flow = d.join("f.yaml");
        write_flow(&flow, "steps:\n  - op: dpa:base64:encode\n");
        let flow: Flow = from_yaml(&std::fs::read_to_string(&flow).unwrap()).unwrap();
        let a = d.join("a.bin");
        let b = d.join("b.bin");
        std::fs::write(&a, vec![b'a'; 32]).unwrap();
        std::fs::write(&b, vec![b'b'; 32]).unwrap();
        let expanded = expand_inputs(
            &[
                a.to_str().unwrap().to_string(),
                b.to_str().unwrap().to_string(),
            ],
            false,
        )
        .unwrap();
        let cfg = EngineConfig::default().with_max_step_output_bytes(16);
        let res = run_batch(&flow, OutputFormat::Raw, &expanded, None, 2, &cfg);
        assert!(
            res.is_err(),
            "batch workers must observe the step output cap"
        );
    }

    #[test]
    fn stream_matches_memory_for_codec() {
        let d = tmpdir("stream_codec");
        let flow = d.join("f.yaml");
        // Multi-step streaming chain: base64 encode -> base64 decode -> hex encode.
        // (The `base64:encode -> hex:encode -> base64:decode` chain is
        // rejected by the type check: hex text is not valid base64 input.)
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

        let flow: Flow = from_yaml(&std::fs::read_to_string(&flow).unwrap()).unwrap();
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

        let flow: Flow = from_yaml(&std::fs::read_to_string(&flow).unwrap()).unwrap();
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
            let flow: Flow = from_yaml(&std::fs::read_to_string(&flow_path).unwrap()).unwrap();
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
            let comp_flow: Flow = from_yaml(&format!("steps:\n  - op: {}\n", comp_op)).unwrap();
            let expanded_in = expand_inputs(&[input.to_str().unwrap().to_string()], false).unwrap();
            let compressed = process_mem(&comp_flow, &expanded_in[0], OutputFormat::Raw);
            let comp_in = d.join(format!("{}_in.bin", name));
            std::fs::write(&comp_in, &compressed).unwrap();

            let flow_path = d.join(format!("{}.yaml", name));
            write_flow(&flow_path, steps);
            let flow: Flow = from_yaml(&std::fs::read_to_string(&flow_path).unwrap()).unwrap();
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
        let flow_c: Flow = from_yaml(&std::fs::read_to_string(&flow_c).unwrap()).unwrap();
        let expanded = expand_inputs(&[input.to_str().unwrap().to_string()], false).unwrap();
        run_stream_to_file(&flow_c, &expanded[0], &gz).unwrap();

        let flow_d = d.join("gzip_d.yaml");
        write_flow(&flow_d, "steps:\n  - op: dpa:gzip:decompress\n");
        let flow_d: Flow = from_yaml(&std::fs::read_to_string(&flow_d).unwrap()).unwrap();
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
        let flow: Flow = from_yaml(&std::fs::read_to_string(&flow).unwrap()).unwrap();
        let expanded = expand_inputs(&[input.to_str().unwrap().to_string()], false).unwrap();

        let mut out = Vec::new();
        process_stream_to(
            &flow,
            &expanded[0],
            OutputFormat::Hex,
            &mut out,
            false,
            &EngineConfig::default(),
        )
        .unwrap();
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
        let flow: Flow = from_yaml(&std::fs::read_to_string(&flow).unwrap()).unwrap();
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

        let flow: Flow = from_yaml(&std::fs::read_to_string(&flow).unwrap()).unwrap();
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
        let flow: Flow = from_yaml(&std::fs::read_to_string(&flow).unwrap()).unwrap();
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
        let flow: Flow = from_yaml(&std::fs::read_to_string(&flow).unwrap()).unwrap();
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
        let flow: Flow = from_yaml(&std::fs::read_to_string(&flow).unwrap()).unwrap();
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
        let flow: Flow = from_yaml(&std::fs::read_to_string(&flow).unwrap()).unwrap();
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

    /// `--explain` renders one localized heading plus a per-step
    /// input→output estimate; content-dependent steps are marked unknown and
    /// are never fabricated into a number.
    #[test]
    fn explain_renders_step_estimates() {
        let flow: Flow = from_yaml(
            "steps:\n  - op: dpa:hex:encode\n  - op: dpa:base64:encode\n  - op: dpa:json:pretty\n",
        )
        .unwrap();
        let text = render_flow_explain(&flow, Some(4)).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        // Heading carries the input size.
        assert!(lines[0].contains("4"), "heading: {}", lines[0]);
        // Step 1: hex:encode doubles (4 -> 8).
        assert!(lines[1].contains("dpa:hex:encode"), "{}", lines[1]);
        assert!(lines[1].contains("4"), "{}", lines[1]);
        assert!(lines[1].contains("8"), "step1 estimate: {}", lines[1]);
        // Step 2: base64:encode scales 4/3 (8 -> 10).
        assert!(lines[2].contains("dpa:base64:encode"), "{}", lines[2]);
        assert!(lines[2].contains("8"), "{}", lines[2]);
        assert!(lines[2].contains("10"), "step2 estimate: {}", lines[2]);
        // Step 3: content-dependent op is honestly marked unknown, and the
        // running estimate stops propagating.
        assert!(lines[3].contains("dpa:json:pretty"), "{}", lines[3]);
        let unknown = i18n::t("explain.out_unknown");
        assert!(
            lines[3].contains(unknown),
            "step3 must say unknown: {}",
            lines[3]
        );
    }

    /// Fixed-length generators (random / hash) estimate a constant
    /// output regardless of the input size.
    #[test]
    fn explain_fixed_length_steps() {
        let flow: Flow = from_yaml(
            "steps:\n  - op: dpa:random\n    args: {length: \"16\"}\n  - op: dpa:hex:encode\n",
        )
        .unwrap();
        let text = render_flow_explain(&flow, None).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert!(
            lines[1].contains("16"),
            "random bytes estimate: {}",
            lines[1]
        );
        // hex:encode of 16 bytes -> 32 chars.
        assert!(lines[2].contains("32"), "hex after random: {}", lines[2]);
    }

    #[test]
    fn batch_hex_output_not_double_encoded() {
        // The batch path previously hex-encoded each chunk while collecting
        // and then rendered the collected bytes again (double encoding). The
        // output must now be the single hex rendering.
        let d = tmpdir("batch_hex");
        let flow = d.join("f.yaml");
        write_flow(&flow, "steps:\n  - op: dpa:base64:decode\n");
        std::fs::write(d.join("in.bin"), b"aGk=").unwrap(); // base64("hi")
        let expanded =
            expand_inputs(&[d.join("in.bin").to_str().unwrap().to_string()], false).unwrap();
        let flow: Flow = from_yaml(&std::fs::read_to_string(&flow).unwrap()).unwrap();
        let outdir = d.join("out");
        run_batch(
            &flow,
            OutputFormat::Hex,
            &expanded,
            Some(outdir.to_str().unwrap()),
            2,
            &EngineConfig::default(),
        )
        .unwrap();
        let rendered = std::fs::read(outdir.join("in.bin")).unwrap();
        assert_eq!(
            rendered,
            b"6869\n",
            "expected single hex rendering (one line, trailing newline), got double-encoded output: {}",
            String::from_utf8_lossy(&rendered)
        );
    }

    #[test]
    fn batch_stdout_collect_keeps_raw_bytes() {
        // The batch collector must return raw bytes so
        // write_stdout renders the output format exactly once. Previously the
        // collector pre-rendered with Hex and write_stdout hex-encoded the
        // already-rendered text again (double encoding).
        let d = tmpdir("batch_stdout");
        let flow = d.join("f.yaml");
        write_flow(&flow, "steps:\n  - op: dpa:base64:decode\n");
        std::fs::write(d.join("in.bin"), b"aGk=").unwrap(); // base64("hi")
        let expanded =
            expand_inputs(&[d.join("in.bin").to_str().unwrap().to_string()], false).unwrap();
        let flow: Flow = from_yaml(&std::fs::read_to_string(&flow).unwrap()).unwrap();
        let cfg = EngineConfig::default();
        // Collector stays raw; hex rendering happens once at write_stdout.
        let raw = process_stream_collect(&flow, &expanded[0], OutputFormat::Raw, &cfg).unwrap();
        assert_eq!(
            raw, b"hi",
            "collector must return raw decoded bytes, got {:?}",
            raw
        );
        assert_eq!(
            hex::encode(&raw),
            "6869",
            "single hex rendering of raw bytes must be 6869, got {}",
            hex::encode(&raw)
        );
        // Raw text chain gets exactly one trailing newline (write_stdout text_tail).
        let mut rendered = raw.clone();
        if !rendered.is_empty() {
            rendered.push(b'\n');
        }
        assert_eq!(rendered, b"hi\n", "raw batch stdout render mismatch");
    }

    #[test]
    fn fork_fallback_enforces_input_cap() {
        // The fork whole-buffer fallback must observe --max-input-bytes
        // just like the streaming path does.
        let d = tmpdir("fork_in_cap");
        let flow = d.join("f.yaml");
        write_flow(
            &flow,
            "steps:\n  - op: dpa:fork\n  - op: dpa:base64:decode\n",
        );
        std::fs::write(d.join("in.bin"), b"aGk=").unwrap();
        let expanded =
            expand_inputs(&[d.join("in.bin").to_str().unwrap().to_string()], false).unwrap();
        let flow: Flow = from_yaml(&std::fs::read_to_string(&flow).unwrap()).unwrap();
        let cfg = EngineConfig::default().with_max_input_bytes(1);
        let mut out = Vec::new();
        let res = process_stream_to(
            &flow,
            &expanded[0],
            OutputFormat::Raw,
            &mut out,
            false,
            &cfg,
        );
        assert!(res.is_err(), "fork fallback must respect --max-input-bytes");
        let msg = format!("{}", res.unwrap_err());
        assert!(msg.contains("max-input-bytes"), "got: {}", msg);
    }

    #[test]
    fn fork_fallback_enforces_step_output_cap() {
        // The fork whole-buffer fallback must enforce the per-step output
        // cap, otherwise a runaway transform behind a Fork step bypasses the cap
        // that the streaming write path enforces.
        let d = tmpdir("fork_out_cap");
        let flow = d.join("f.yaml");
        write_flow(
            &flow,
            "steps:\n  - op: dpa:fork\n  - op: dpa:base64:encode\n",
        );
        std::fs::write(d.join("in.bin"), vec![b'a'; 32]).unwrap();
        let expanded =
            expand_inputs(&[d.join("in.bin").to_str().unwrap().to_string()], false).unwrap();
        let flow: Flow = from_yaml(&std::fs::read_to_string(&flow).unwrap()).unwrap();
        let cfg = EngineConfig::default().with_max_step_output_bytes(16);
        let mut out = Vec::new();
        let res = process_stream_to(
            &flow,
            &expanded[0],
            OutputFormat::Raw,
            &mut out,
            false,
            &cfg,
        );
        assert!(
            res.is_err(),
            "fork fallback must enforce the step output cap"
        );
        let msg = format!("{}", res.unwrap_err());
        assert!(msg.contains("--max-step-output-bytes"), "got: {}", msg);
    }

    #[test]
    fn stream_error_reports_step_number() {
        // Streaming write errors must name the failing step instead of a
        // generic "Streaming failed: ...".
        let d = tmpdir("step_err");
        let flow = d.join("f.yaml");
        write_flow(&flow, "steps:\n  - op: dpa:base64:decode\n");
        std::fs::write(d.join("in.bin"), b"!!!").unwrap();
        let expanded =
            expand_inputs(&[d.join("in.bin").to_str().unwrap().to_string()], false).unwrap();
        let flow: Flow = from_yaml(&std::fs::read_to_string(&flow).unwrap()).unwrap();
        let mut out = Vec::new();
        let res = process_stream_to(
            &flow,
            &expanded[0],
            OutputFormat::Raw,
            &mut out,
            false,
            &EngineConfig::default(),
        );
        assert!(res.is_err(), "invalid base64 must fail the stream");
        let msg = format!("{}", res.unwrap_err());
        assert!(
            msg.contains("Step 1") && msg.contains("dpa:base64:decode"),
            "stream error must name the failing step, got: {}",
            msg
        );
    }

    #[test]
    fn open_file_writer_retries_on_tmp_collision() {
        // create_new must refuse a pre-existing tmp sibling and
        // bump the counter instead of truncating it.
        #[cfg(not(target_arch = "wasm32"))]
        {
            let d = tmpdir("outfile_tmp_collision");
            let target = d.join("out.bin").to_str().unwrap().to_string();
            // Pre-create the first candidate the writer would pick
            // (pid + seq 0) to force an AlreadyExists retry.
            let first = format!("{target}.dpa-{}-0.tmp", std::process::id());
            std::fs::write(&first, b"stale").unwrap();
            let mut w = open_file_writer(&target).unwrap();
            w.writer_mut().write_all(b"fresh").unwrap();
            w.commit().unwrap();
            let body = std::fs::read(&target).unwrap();
            assert_eq!(body, b"fresh", "writer must skip the stale tmp file");
            assert!(
                std::fs::metadata(&first).is_ok(),
                "stale tmp must be left untouched"
            );
        }
    }
}
