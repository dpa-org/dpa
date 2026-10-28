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
| `list_ops` | `list_ops(category?) -> string` | JSON 数组 |
| `op` | `op(name) -> string \| null` | JSON 对象或 null |
| `version` | `version() -> string` | 包版本 |
| `set_max_input_bytes` | `set_max_input_bytes(n) -> void` | `0` 表示不限制 |
| `set_max_step_output_bytes` | `set_max_step_output_bytes(n) -> void` | `0` 表示不限制 |
| `set_verbose` | `set_verbose(on) -> void` | 每步字节统计 |

`outputFormat` 取 `"raw"` 或 `"hex"`；省略时使用流程里的 `output:` 字段；两者都没有
则输出原始字节。

## 示例

```js
import init, { run } from "./pkg/dpa_wasm.js";

await init();

const flow = `steps:
  - op: dpa:base64:decode
  - op: dpa:hex:encode`;
const out = run(flow, new TextEncoder().encode("aGVsbG8="));
console.log(new TextDecoder().decode(out)); // 68656c6c6f
```

## 限制

- 整块输入上限：默认 256 MiB；`set_max_input_bytes(0)` 关闭限制。
- 每步输出上限：默认 64 MiB；`set_max_step_output_bytes(0)` 关闭限制。
- 无网络、无文件系统：绑定只能看到你传入的字节；界面与输入输出处理由外层页面负责。
