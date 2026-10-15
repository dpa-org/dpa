//! Official sample plugin for the dpa plugin ABI (see docs/PLUGIN.md).
//!
//! Build: `cargo build -p dpa-plugin-demo` (or `cargo build --workspace`), then
//! load the produced `dpa_plugin_demo.dll` / `.so` / `.dylib` with
//! `dpa --plugins <dir>`.

use std::collections::HashMap;

use dpa::dpa_plugin;
use dpa::ops::{ArgSpec, StreamingOp};

/// Static args spec for the demo op.
const ROT_ARGS: &[ArgSpec] = &[ArgSpec::new("n", false, "rotation amount (default 13)")];

/// Whole-buffer run: rotate every byte by `n` (wrapping).
fn rot_run(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
    let n = args
        .get("n")
        .and_then(|v| v.parse::<u8>().ok())
        .unwrap_or(13);
    Ok(input.iter().map(|b| b.wrapping_add(n)).collect())
}

/// Streaming run: same transform, applied chunk by chunk.
struct RotStream {
    n: u8,
}

fn rot_stream(args: &HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> {
    let n = args
        .get("n")
        .and_then(|v| v.parse::<u8>().ok())
        .unwrap_or(13);
    Ok(Box::new(RotStream { n }))
}

impl StreamingOp for RotStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        Ok(chunk.iter().map(|b| b.wrapping_add(self.n)).collect())
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        Ok(Vec::new())
    }
}

dpa_plugin! {
    version: 2,
    ops: [
        {
            name: "dpa:plugin:rot",
            category: "plugin",
            description: "Rotate every byte by n (default 13)",
            args: ROT_ARGS,
            run: rot_run,
            stream: rot_stream,
        },
    ],
}
