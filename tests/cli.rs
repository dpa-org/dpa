//! End-to-end tests for the command line: run the built binary and check its
//! exit status and output. These cover the surfaces the library tests cannot
//! reach - argument parsing, `dpa op`, and inline flows.

#![cfg(feature = "cli")]

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_dpa");

/// A scratch directory removed when the test ends.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("dpa_{}_{}", tag, std::process::id()));
        std::fs::create_dir_all(&dir).expect("create the temp dir");
        TempDir(dir)
    }

    fn file(&self, name: &str, contents: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, contents).expect("write the temp file");
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run(args: &[&str]) -> Output {
    Command::new(BIN).args(args).output().expect("run dpa")
}

fn run_with_stdin(args: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(BIN)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn dpa");
    child
        .stdin
        .as_mut()
        .expect("child stdin")
        .write_all(input)
        .expect("write to child stdin");
    child.wait_with_output().expect("wait for dpa")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn op_runs_one_operation_on_a_file() {
    let dir = TempDir::new("op_file");
    let input = dir.file("in.txt", b"Hello");
    let out = run(&["op", "hex:encode", input.to_str().unwrap()]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    // Text-shaped op output ends with a newline.
    assert_eq!(stdout(&out), "48656c6c6f\n");
}

#[test]
fn op_name_may_omit_the_dpa_prefix() {
    let dir = TempDir::new("op_prefix");
    let input = dir.file("in.txt", b"Hello");
    let full = run(&["op", "dpa:hex:encode", input.to_str().unwrap()]);
    let short = run(&["op", "hex:encode", input.to_str().unwrap()]);
    assert!(full.status.success(), "stderr: {}", stderr(&full));
    assert!(short.status.success(), "stderr: {}", stderr(&short));
    assert_eq!(stdout(&full), stdout(&short));
}

#[test]
fn op_takes_arguments_and_the_output_format() {
    let dir = TempDir::new("op_args");
    let input = dir.file("in.txt", b"Hello");
    let out = run(&[
        "op",
        "xor",
        "--key",
        "0x2A",
        "--output-format",
        "hex",
        input.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    // "Hello" XOR 0x2A == "bOFFE", which is 624f464645 in hex. Unlike an op
    // that emits hex text itself (`hex:encode`), the `--output-format hex`
    // rendering ends with a newline.
    assert_eq!(stdout(&out).trim_end(), "624f464645");
}

#[test]
fn op_reports_a_missing_required_argument() {
    let dir = TempDir::new("op_missing");
    let input = dir.file("in.txt", b"Hello");
    let out = run(&["op", "xor", input.to_str().unwrap()]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("--key"), "stderr: {}", stderr(&out));
}

#[test]
fn op_reports_an_unknown_name() {
    let out = run(&["op", "nosuchop"]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("nosuchop"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn op_help_lists_that_operations_arguments() {
    let out = run(&["op", "xor", "--help"]);
    let text = format!("{}{}", stdout(&out), stderr(&out));
    assert!(text.contains("--key"), "help was: {text}");
    assert!(text.contains("--scheme"), "help was: {text}");
}

#[test]
fn zh_cn_op_help_headings_are_valid_utf8() {
    // The zh-CN dynamic op help headings must be real UTF-8
    // (the usage/options/arguments headings) - a GBK double-encoded literal previously rendered
    // Garbled CJK glyphs that corrupt the heading.
    let out = run(&["--lang", "zh-CN", "op", "sha256", "--help"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("用法:"), "help was: {text}");
    assert!(text.contains("选项:"), "help was: {text}");
    assert!(text.contains("参数:"), "help was: {text}");
    for ch in ['\u{3126}', '\u{9422}'] {
        assert!(!text.contains(ch), "mojibake char {ch:?} in help: {text}");
    }
}

#[test]
fn single_value_op_error_truncates_huge_input() {
    // A huge / multi-line input must not be echoed back in
    // full by single-value ops - the error shows a bounded prefix instead.
    let big = "1\n".repeat(2000);
    let out = run_with_stdin(&["op", "dpa:timestamp:to:date"], big.as_bytes());
    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(!err.contains(&big), "full input echoed in stderr");
    assert!(err.contains("bytes total"), "stderr: {err}");
}

#[test]
fn op_reads_stdin_when_no_input_is_given() {
    let out = run_with_stdin(&["op", "hex:encode"], b"Hello");
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    // Text-shaped op output ends with a newline.
    assert_eq!(stdout(&out), "48656c6c6f\n");
}

#[test]
fn inline_flow_takes_the_positional_as_input() {
    // Regression: with `-e` the first positional was consumed by the flow
    // argument, so the run silently fell back to (empty) stdin.
    let dir = TempDir::new("eval_input");
    let input = dir.file("in.hex", b"48656C6C6F");
    let out = run(&[
        "run",
        "-e",
        "steps: [{op: hex:decode}, {op: base64:encode}]",
        input.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    // Text-shaped op output ends with a newline.
    assert_eq!(stdout(&out), "SGVsbG8=\n");
}

#[test]
fn flow_step_accepts_a_name_without_the_prefix() {
    let dir = TempDir::new("flow_prefix");
    let input = dir.file("in.hex", b"48656C6C6F");
    let out = run(&[
        "run",
        "-e",
        "steps: [{op: hex:decode}]",
        input.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "Hello");
}

#[test]
fn inline_flow_reads_stdin_when_no_input_is_given() {
    let out = run_with_stdin(&["run", "-e", "steps: [{op: base64:encode}]"], b"Hello");
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    // Text-shaped op output ends with a newline.
    assert_eq!(stdout(&out), "SGVsbG8=\n");
}

#[test]
fn jobs_rejects_non_numeric_value() {
    // A non-numeric --jobs must fail fast instead of silently
    // falling back to the auto thread count.
    let out = run(&["run", "-e", "steps: [{op: base64:encode}]", "--jobs", "abc"]);
    assert!(!out.status.success(), "non-numeric --jobs must be rejected");
    let err = stderr(&out);
    assert!(err.contains("invalid --jobs"), "stderr: {err}");
}

#[test]
fn base64_loose_alias_matches_strict_mode_false() {
    // `--loose` is a short alias for `strict_mode=false` on the
    // base64 decoders. Both accept a 4n+1 input and fail with the same
    // lenient tail error carrying the same input offset.
    let dir = TempDir::new("loose_eq");
    let input = dir.file("in.txt", b"SGVsb");
    let loose = run(&["op", "base64:decode", "--loose", input.to_str().unwrap()]);
    let lenient = run(&[
        "op",
        "base64:decode",
        "--strict_mode",
        "false",
        input.to_str().unwrap(),
    ]);
    assert!(!loose.status.success());
    assert!(!lenient.status.success());
    assert_eq!(stderr(&loose), stderr(&lenient));
    assert!(
        stderr(&loose).contains("offset 4"),
        "stderr: {}",
        stderr(&loose)
    );
}

#[test]
fn explicit_strict_mode_wins_over_loose_alias() {
    // `--loose --strict_mode true` behaves exactly like an explicit strict
    // decode: the long form overrides the alias, so the 4n+1 input is
    // rejected by the strict length check (not the lenient tail check).
    let dir = TempDir::new("loose_strict");
    let input = dir.file("in.txt", b"SGVsb");
    let out = run(&[
        "op",
        "base64:decode",
        "--loose",
        "--strict_mode",
        "true",
        input.to_str().unwrap(),
    ]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("strict"), "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains("offset 4"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn base64_decode_error_reports_the_input_offset() {
    // Decode errors carry the offending input offset, e.g. the
    // invalid character '!' inside "ab!c" is reported at offset 2.
    let dir = TempDir::new("b64_offset");
    let input = dir.file("in.txt", b"ab!c");
    let out = run(&["op", "base64:decode", input.to_str().unwrap()]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("offset 2"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn explain_prints_step_estimates_before_running() {
    // `--explain` prints the static per-step input->output
    // estimate before the actual run; the text-shaped output still follows.
    let dir = TempDir::new("explain_cli");
    let input = dir.file("in.txt", b"Hello");
    let out = run(&["op", "base64:encode", "--explain", input.to_str().unwrap()]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let text = format!("{}{}", stdout(&out), stderr(&out));
    assert!(text.contains("Flow estimate"), "output: {text}");
    assert!(text.contains("Step 1"), "output: {text}");
}

#[test]
fn head_tail_n_lines_aliases() {
    // `-n` (short flag) and `--lines` (long alias) both resolve to the
    // canonical `--n` argument on dpa:head/dpa:tail (GNU coreutils
    // convention); the default behavior is unchanged.
    let input = b"a\nb\nc\nd\ne\n";
    // head: -n short flag == --n.
    let a = run_with_stdin(&["op", "head", "-n", "2"], input);
    assert_eq!(stdout(&a), "a\nb\n", "head -n 2");
    // head: --lines long alias == --n.
    let b = run_with_stdin(&["op", "head", "--lines", "2"], input);
    assert_eq!(stdout(&b), "a\nb\n", "head --lines 2");
    // tail: --n canonical form still works.
    let c = run_with_stdin(&["op", "tail", "--n", "2"], input);
    assert_eq!(stdout(&c), "d\ne\n", "tail --n 2");
    // tail: -n short flag == --n.
    let d = run_with_stdin(&["op", "tail", "-n", "2"], input);
    assert_eq!(stdout(&d), "d\ne\n", "tail -n 2");
    // tail: --lines long alias == --n.
    let e = run_with_stdin(&["op", "tail", "--lines", "3"], input);
    assert_eq!(stdout(&e), "c\nd\ne\n", "tail --lines 3");
}

#[test]
fn flow_with_utf8_bom_preamble_runs() {
    // A UTF-8 BOM at the start of a flow file (PowerShell
    // 5.1's `Set-Content -Encoding UTF8` / old Notepad default) must parse
    // and run instead of surfacing a misleading "more than one document"
    // error. The YAML loader treats the BOM as preamble; keep that behavior
    // locked with a regression test.
    let dir = TempDir::new("flow_bom");
    let flow = b"\xEF\xBB\xBFsteps:\n  - op: dpa:base64:encode\n";
    let flow_path = dir.file("flow_bom.yaml", flow);
    let out = run_with_stdin(&["run", flow_path.to_str().unwrap()], b"Hello");
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "SGVsbG8=\n");
}

#[test]
fn to_step_renders_intermediate_output() {
    // `--to-step N` lets the user inspect the
    // intermediate output of step N. The truncated flow runs through the
    // normal pipeline, so step N's output must land on stdout (or in the
    // `-o` file), not vanish.
    let dir = TempDir::new("to_step_out");
    let flow = b"steps:\n  - op: dpa:base64:encode\n  - op: dpa:upper\n";
    let flow_path = dir.file("ok2.yaml", flow);

    let out = run_with_stdin(
        &["run", flow_path.to_str().unwrap(), "--to-step", "1"],
        b"Hello",
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "SGVsbG8=\n");

    let out_file = dir.0.join("mid.hex");
    let out = run_with_stdin(
        &[
            "run",
            flow_path.to_str().unwrap(),
            "--to-step",
            "1",
            "-o",
            out_file.to_str().unwrap(),
        ],
        b"Hello",
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    // Files receive the step's raw bytes; the stdout renderer adds the
    // trailing newline for text-shaped output.
    assert_eq!(std::fs::read(&out_file).expect("read -o file"), b"SGVsbG8=");
}

#[test]
fn op_hex_flag_switches_output_to_hex() {
    // The explicit `--hex` flag renders the op output as hex;
    // without it the raw stream is unchanged.
    let dir = TempDir::new("op_hex");
    let input = dir.file("in.txt", b"Hello");
    let raw = run(&["op", "upper", input.to_str().unwrap()]);
    assert!(raw.status.success(), "stderr: {}", stderr(&raw));
    assert_eq!(stdout(&raw), "HELLO\n");

    let hexed = run(&["op", "upper", "--hex", input.to_str().unwrap()]);
    assert!(hexed.status.success(), "stderr: {}", stderr(&hexed));
    assert_eq!(stdout(&hexed), "48454c4c4f\n");
}

#[test]
fn list_full_flag_prints_uncut_descriptions() {
    // `--full` keeps every description and op; the default list
    // still renders (interactive truncation is a TTY-only concern).
    let normal = run(&["list"]);
    assert!(normal.status.success(), "stderr: {}", stderr(&normal));
    let full = run(&["list", "--full"]);
    assert!(full.status.success(), "stderr: {}", stderr(&full));
    assert!(
        stdout(&full).contains("base64:encode"),
        "list --full misses ops"
    );
    assert!(
        stdout(&full).len() >= stdout(&normal).len(),
        "--full list shorter than default list"
    );
}

#[test]
fn non_tty_overwrite_stays_silent() {
    // With no console (piped stdio, as in scripts), writing
    // over an existing `-o` target proceeds without any prompt. The TTY
    // confirmation path is covered by unit tests (prompt parsing + gating).
    let dir = TempDir::new("overwrite_nontty");
    let flow = dir.file("f.yaml", b"steps:\n  - op: dpa:base64:encode\n");
    let out_file = dir.0.join("out.bin");
    std::fs::write(&out_file, b"old").expect("seed the output file");

    let out = run_with_stdin(
        &[
            "run",
            flow.to_str().unwrap(),
            "-o",
            out_file.to_str().unwrap(),
        ],
        b"Hello",
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(std::fs::read(&out_file).expect("read -o file"), b"SGVsbG8=");
}

#[test]
fn version_prints_one_clean_line() {
    // `--version` stays a single line starting with the crate
    // version; when built from a git checkout it additionally carries
    // the embedded commit hash/date, never a trailing blank line.
    let out = run(&["--version"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    assert!(text.starts_with("dpa "), "version: {text}");
    assert_eq!(text.lines().count(), 1, "version: {text:?}");
    assert!(text.trim_end().ends_with(text.trim()), "version: {text:?}");
}
