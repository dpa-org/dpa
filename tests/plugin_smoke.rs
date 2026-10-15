//! Smoke test for the plugin ABI: load the demo plugin and run its op through
//! both the in-memory path (`process_bytes`) and the streaming path
//! (`process_bytes_stream`), verifying identical output.
//!
//! `cargo test` does not build the plugin cdylib, so this test needs
//! `cargo build -p dpa-plugin-demo` first — CI runs that before the test step.
//! Without the artifact the test is skipped locally (with a notice) and fails
//! when `CI` is set, so a missing build step cannot pass silently in CI.

use std::collections::HashMap;
use std::path::PathBuf;

use dpa::{engine, flow, ops, plugin};

/// The demo plugin's cdylib in the build output directory (`target/<profile>/`),
/// which is two levels up from the test binary in `target/<profile>/deps/`.
fn demo_plugin_artifact() -> Option<PathBuf> {
    let dir = std::env::current_exe()
        .ok()?
        .parent()?
        .parent()?
        .to_path_buf();
    let name = if cfg!(windows) {
        "dpa_plugin_demo.dll"
    } else if cfg!(target_os = "macos") {
        "libdpa_plugin_demo.dylib"
    } else {
        "libdpa_plugin_demo.so"
    };
    let path = dir.join(name);
    path.is_file().then_some(path)
}

/// Copy the plugin into a scratch directory and load it from there, so the test
/// never depends on (or writes into) the `plugins/` directory in the repo.
/// Returns false when the artifact is missing and the test should be skipped.
fn load_demo_plugin() -> bool {
    let Some(source) = demo_plugin_artifact() else {
        assert!(
            std::env::var_os("CI").is_none(),
            "demo plugin artifact not found; build it with `cargo build -p dpa-plugin-demo` \
             before running the tests"
        );
        eprintln!("skipped: run `cargo build -p dpa-plugin-demo` to exercise the plugin ABI");
        return false;
    };
    let dir = std::env::temp_dir().join(format!("dpa_plugin_smoke_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create the scratch plugin dir");
    let dest = dir.join(source.file_name().expect("plugin file name"));
    std::fs::copy(&source, &dest).expect("copy the plugin into the scratch dir");
    let n = plugin::load_plugins(&dir).expect("load the demo plugin");
    assert_eq!(n, 1, "expected exactly one plugin op to be loaded");
    // The scratch directory is left in place: the library stays mapped while the
    // process runs, and deleting it under a live mapping fails on Windows.
    true
}

fn rot_flow() -> flow::Flow {
    let mut args = HashMap::new();
    args.insert("n".to_string(), "13".to_string());
    flow::Flow {
        name: Some("rot-test".to_string()),
        description: None,
        output: None,
        steps: vec![flow::Step {
            op: "dpa:plugin:rot".to_string(),
            args,
        }],
        meta: None,
    }
}

#[test]
fn plugin_registration_and_execution() {
    if !load_demo_plugin() {
        return;
    }

    let rot = ops::find_op("dpa:plugin:rot").expect("rot op should be registered");
    assert!(
        rot.stream.is_some(),
        "rot should expose a streaming handler"
    );

    let f = rot_flow();
    let expect: Vec<u8> = b"HELLO".iter().map(|b| b.wrapping_add(13)).collect();

    // In-memory path (calls the plugin's run bridge).
    let mem = engine::process_bytes(&f, b"HELLO", flow::OutputFormat::Raw).expect("memory path ok");
    assert_eq!(mem, expect, "memory run should wrap-add 13 to 'HELLO'");

    // Streaming path (calls the plugin's stream init/write/finish bridges).
    let st = engine::process_bytes_stream(&f, b"HELLO", flow::OutputFormat::Raw)
        .expect("stream path ok");
    assert_eq!(st, expect, "stream run should wrap-add 13 to 'HELLO'");

    // Chunked streaming: 1 MiB forces several internal chunks.
    let big: Vec<u8> = (0..(1 << 20)).map(|i| (i % 251) as u8).collect();
    let st_big =
        engine::process_bytes_stream(&f, &big, flow::OutputFormat::Raw).expect("big stream ok");
    assert_eq!(
        st_big.len(),
        big.len(),
        "big stream length must match input"
    );
    assert_eq!(
        st_big,
        big.iter().map(|b| b.wrapping_add(13)).collect::<Vec<u8>>(),
        "big stream output must equal per-byte wrap-add"
    );
}
