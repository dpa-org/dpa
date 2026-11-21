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
| `run_op` | `run_op(name, args?, data) -> Uint8Array` | single op by name; `args` is a plain object |
| `inspect` | `inspect(flowYaml, data, outputKind?) -> Uint8Array \| string \| object` | structured view of the final result |
| `list_ops` | `list_ops(category?) -> string` | JSON array with full schema metadata |
| `op` | `op(name) -> string \| null` | JSON object with full schema metadata, or null |
| `version` | `version() -> string` | package version |
| `meta` | `meta() -> string` | `{version, schema_version, ops_total, categories}` |
| `set_max_input_bytes` | `set_max_input_bytes(n) -> void` | `0` disables the cap |
| `set_max_step_output_bytes` | `set_max_step_output_bytes(n) -> void` | `0` disables the cap |
| `set_verbose` | `set_verbose(on) -> void` | per-step byte accounting |
| `get_max_input_bytes` | `get_max_input_bytes() -> number` | read side for the input cap |
| `get_max_step_output_bytes` | `get_max_step_output_bytes() -> number` | read side for the step cap |
| `get_verbose` | `get_verbose() -> boolean` | read side for the verbose flag |

`outputFormat` is `"raw"` or `"hex"`. When omitted, the flow's `output:` field
applies; when neither is set, the output is raw bytes.

### `run_op`

Executes one op by name through the same engine pipeline as `dpa op <name>`
(registry validation included). `args` must be a plain object whose values are
strings; `data` is a `Uint8Array`.

```js
const out = run_op("dpa:hex:encode", {}, new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
```

### `inspect`

Runs a flow and converts the final result to a structured value. Without
`outputKind` the flow's final op declaration is used; undeclared ops fall back
to raw bytes. Explicit `outputKind` overrides the declaration. Mapping:

| Structured variant | JS value |
| --- | --- |
| `Bytes` | `Uint8Array` |
| `Utf8` | `string` |
| `Json` | parsed object (JSON DOM) |
| `Yaml` | parsed object (YAML normalized to JSON DOM) |
| `Hex` | validated hex string |

```js
const view = inspect("steps:\n  - op: dpa:json:to-yaml", data); // object view
const txt  = inspect("steps:\n  - op: dpa:hex:encode", data, "Utf8"); // string
```

### Schema metadata contract

`list_ops` and `op` return full schema-level metadata aligned with the CLI
`show_op` fields. Field names stay snake_case and stable; `meta()` exposes
`schema_version`, which is bumped whenever the field layout changes. Hosts
should refresh their op catalog when `meta().schema_version` changes.

`op(name)` object shape:

```json
{
  "name": "dpa:hex:encode",
  "category": "codec",
  "family": "codec",
  "kind": "encode",
  "level": "basic",
  "input": "bytes",
  "output": "bytes",
  "output_kind": "hex",
  "description": "Encode bytes as hexadecimal.",
  "example": "deadbeef",
  "args": [
    {"name": "uppercase", "required": false, "description": "...", "format": "bool"}
  ]
}
```

### Structured errors

All thrown errors follow the `{code, category, message}` contract: the thrown
`Error.message` is JSON text, so hosts can branch programmatically:

```js
try {
  run_op("dpa:no:such:op", {}, data);
} catch (e) {
  const { code, category, message } = JSON.parse(e.message);
  // code: UNKNOWN_OP | INPUT_TOO_LARGE | PARSE_FLOW_FAILED | EMPTY_STEPS
  //     | INVALID_OUTPUT_FORMAT | OUTPUT_NOT_UTF8 | JSON_PARSE_FAILED
  //     | YAML_PARSE_FAILED | INVALID_ARG | RUN_FAILED | INTERNAL
  // category: input | limit | flow | output | run | internal
}
```

This is a contract change from the pre-1.x plain-text `message`: hosts should
treat a message that fails `JSON.parse` as an untagged engine error
(`RUN_FAILED` fallback) during migration.

## Example

```js
import init, { run, run_op, inspect, meta } from "./pkg/dpa_wasm.js";

await init();

const flow = `steps:
  - op: dpa:base64:decode
  - op: dpa:hex:encode`;
const out = run(flow, new TextEncoder().encode("aGVsbG8="));
console.log(new TextDecoder().decode(out)); // 68656c6c6f

// single op + structured view + capability probe
const h = run_op("dpa:hex:encode", {}, new Uint8Array([0x01, 0x02]));
console.log(h); // Uint8Array [49, 50, 48, 50] ("0102")
console.log(meta()); // {"version":"...","schema_version":1,"ops_total":233,"categories":[...]}
```

## Limits

- Whole-input cap: 256 MiB by default; `set_max_input_bytes(0)` disables it.
- Per-step output cap: 64 MiB by default; `set_max_step_output_bytes(0)`
  disables it.
- No network and no filesystem access: the binding only sees the bytes you pass
  in. The surrounding page still owns its UI and any input/output handling.
