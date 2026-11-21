# dpa WebAssembly 绑定

[English](WASM.md) | 简体中文

`dpa-wasm` 把同一套引擎（流程解析、操作、i18n）编译到 wasm32。它是**引擎绑定**，
不是浏览器界面：你传入流程与输入字节，它返回输出字节；界面由你自己构建。

## 构建

需要 Rust 1.89+ 与 wasm32 target：

```bash
rustup target add wasm32-unknown-unknown
```

用 wasm-bindgen 工具链（产出 JS 胶水与 `.wasm`）：

```bash
wasm-pack build dpa-wasm --target web
```

不用 wasm-pack 时，自行构建模块并生成绑定：

```bash
cargo build -p dpa-wasm --target wasm32-unknown-unknown
wasm-bindgen --target web --out-dir pkg \
  target/wasm32-unknown-unknown/debug/dpa_wasm.wasm
```

## API

| 函数 | 签名 | 说明 |
| --- | --- | --- |
| `run` | `run(flowYaml, data, outputFormat?) -> Uint8Array` | 单个输入 |
| `run_batch` | `run_batch(flowYaml, items, outputFormat?) -> Uint8Array[]` | 每个输入一个输出，按顺序 |
| `run_op` | `run_op(name, args?, data) -> Uint8Array` | 按名称执行单个 op；`args` 为普通对象 |
| `inspect` | `inspect(flowYaml, data, outputKind?) -> Uint8Array \| string \| object` | 最终结果的结构化视图 |
| `list_ops` | `list_ops(category?) -> string` | JSON 数组，含完整 schema 元数据 |
| `op` | `op(name) -> string \| null` | JSON 对象（含完整 schema 元数据）或 null |
| `version` | `version() -> string` | 包版本 |
| `meta` | `meta() -> string` | `{version, schema_version, ops_total, categories}` |
| `set_max_input_bytes` | `set_max_input_bytes(n) -> void` | `0` 表示不限制 |
| `set_max_step_output_bytes` | `set_max_step_output_bytes(n) -> void` | `0` 表示不限制 |
| `set_verbose` | `set_verbose(on) -> void` | 每步字节统计 |
| `get_max_input_bytes` | `get_max_input_bytes() -> number` | 读取输入上限 |
| `get_max_step_output_bytes` | `get_max_step_output_bytes() -> number` | 读取每步上限 |
| `get_verbose` | `get_verbose() -> boolean` | 读取 verbose 标志 |

`outputFormat` 取 `"raw"` 或 `"hex"`；省略时使用流程里的 `output:` 字段；两者都没有
则输出原始字节。

### `run_op`

按名称执行单个 op，走与 CLI `dpa op <name>` 相同的引擎管线（含注册表校验）。
`args` 必须是普通对象、值为字符串；`data` 为 `Uint8Array`。

```js
const out = run_op("dpa:hex:encode", {}, new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
```

### `inspect`

运行流程并把最终结果转为结构化值。不传 `outputKind` 时使用流程最终 op 的声明；
未声明的 op 回退为原始字节；显式传入的 `outputKind` 覆盖声明。映射：

| 结构化变体 | JS 值 |
| --- | --- |
| `Bytes` | `Uint8Array` |
| `Utf8` | `string` |
| `Json` | 解析后的对象（JSON DOM） |
| `Yaml` | 解析后的对象（YAML 归一化为 JSON DOM） |
| `Hex` | 校验过的十六进制字符串 |

```js
const view = inspect("steps:\n  - op: dpa:json:to-yaml", data); // 对象视图
const txt  = inspect("steps:\n  - op: dpa:hex:encode", data, "Utf8"); // 字符串
```

### Schema 元数据契约

`list_ops` 与 `op` 返回与 CLI `show_op` 字段一致的完整 schema 元数据。字段名保持
snake_case 且稳定；`meta()` 暴露 `schema_version`，字段布局变更时递增。宿主应在
`meta().schema_version` 变化时刷新 op 目录。

`op(name)` 对象结构：

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

### 结构化错误

所有抛出的错误遵循 `{code, category, message}` 契约：抛出的 `Error.message` 是
JSON 文本，宿主可按分支编程：

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

这是相对 1.x 之前纯文本 `message` 的契约变更：迁移期内宿主应将 `JSON.parse`
失败的 message 视为未标记的引擎错误（回退 `RUN_FAILED`）。

## 示例

```js
import init, { run, run_op, inspect, meta } from "./pkg/dpa_wasm.js";

await init();

const flow = `steps:
  - op: dpa:base64:decode
  - op: dpa:hex:encode`;
const out = run(flow, new TextEncoder().encode("aGVsbG8="));
console.log(new TextDecoder().decode(out)); // 68656c6c6f

// 单 op + 结构化视图 + 能力探测
const h = run_op("dpa:hex:encode", {}, new Uint8Array([0x01, 0x02]));
console.log(h); // Uint8Array [49, 50, 48, 50] ("0102")
console.log(meta()); // {"version":"...","schema_version":1,"ops_total":233,"categories":[...]}
```

## 限制

- 整块输入上限：默认 256 MiB；`set_max_input_bytes(0)` 关闭限制。
- 每步输出上限：默认 64 MiB；`set_max_step_output_bytes(0)` 关闭限制。
- 无网络、无文件系统：绑定只能看到你传入的字节；界面与输入输出处理由外层页面负责。

---
