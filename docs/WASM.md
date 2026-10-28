# dpa WebAssembly binding

[简体中文](WASM.zh-CN.md) | English

`dpa-wasm` compiles the same engine (flow parsing, operations, i18n) to wasm32.
It is an engine binding, not a browser UI: you pass a flow and input bytes, and
it returns output bytes. Any interface on top is yours to build.

## Build

Requires Rust 1.89+ and the wasm32 target:

```bash
rustup target add wasm32-unknown-unknown
```

With wasm-bindgen tooling (produces JS glue plus the `.wasm` file):

```bash
wasm-pack build dpa-wasm --target web
```

Without wasm-pack, build the module and generate the bindings yourself:

```bash
cargo build -p dpa-wasm --target wasm32-unknown-unknown
wasm-bindgen --target web --out-dir pkg \
  target/wasm32-unknown-unknown/debug/dpa_wasm.wasm
```

## API

| Function | Signature | Notes |
| --- | --- | --- |
| `run` | `run(flowYaml, data, outputFormat?) -> Uint8Array` | one input |
| `run_batch` | `run_batch(flowYaml, items, outputFormat?) -> Uint8Array[]` | one output per input, in order |
| `list_ops` | `list_ops(category?) -> string` | JSON array |
| `op` | `op(name) -> string \| null` | JSON object, or null |
| `version` | `version() -> string` | package version |
| `set_max_input_bytes` | `set_max_input_bytes(n) -> void` | `0` disables the cap |
| `set_max_step_output_bytes` | `set_max_step_output_bytes(n) -> void` | `0` disables the cap |
| `set_verbose` | `set_verbose(on) -> void` | per-step byte accounting |

`outputFormat` is `"raw"` or `"hex"`. When omitted, the flow's `output:` field
applies; when neither is set, the output is raw bytes.

## Example

```js
import init, { run } from "./pkg/dpa_wasm.js";

await init();

const flow = `steps:
  - op: dpa:base64:decode
  - op: dpa:hex:encode`;
const out = run(flow, new TextEncoder().encode("aGVsbG8="));
console.log(new TextDecoder().decode(out)); // 68656c6c6f
```

## Limits

- Whole-input cap: 256 MiB by default; `set_max_input_bytes(0)` disables it.
- Per-step output cap: 64 MiB by default; `set_max_step_output_bytes(0)`
  disables it.
- No network and no filesystem access: the binding only sees the bytes you pass
  in. The surrounding page still owns its UI and any input/output handling.
