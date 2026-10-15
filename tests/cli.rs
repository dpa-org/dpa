//! End-to-end tests for the command line: run the built binary and check its
//! exit status and output. These cover the surfaces the library tests cannot
//! reach — argument parsing, `dpa op`, and inline flows.

#![cfg(feature = "cli")]

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_dpa-cli");

/// A scratch directory removed when the test ends.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("dpa_cli_{}_{}", tag, std::process::id()));
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
    assert_eq!(stdout(&out), "48656c6c6f");
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
fn op_reads_stdin_when_no_input_is_given() {
    let out = run_with_stdin(&["op", "hex:encode"], b"Hello");
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "48656c6c6f");
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
    assert_eq!(stdout(&out), "SGVsbG8=");
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
    assert_eq!(stdout(&out), "SGVsbG8=");
}
