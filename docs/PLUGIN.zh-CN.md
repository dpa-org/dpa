# dpa 插件 ABI

[English](PLUGIN.md) | 简体中文

插件可以在不改动主程序的前提下为 dpa 增加操作。插件是一个动态库（`.dll`、`.so`、
`.dylib`），针对 `dpa_plugin!` 宏导出的 C ABI 构建。

## 安全模型

插件在 dpa 进程内运行原生代码。加载插件等同于以你的权限运行一个本地程序，
因此只应加载你信任的插件。

dpa 不会自行查找插件：

- 加载插件的方式是给出目录：`dpa --plugins <dir>`；
- 启动时不读取任何目录。`dpa --discover-plugins` 才是主动读取两个约定位置的
  选项——二进制旁边的 `<dpa 目录>/plugins/`，以及用户级目录（Windows 为
  `%APPDATA%\dpa\plugins`，其他平台为 `~/.dpa/plugins`）。它会先打印警告并列出
  即将读取的目录：把动态库放进用户可写的目录，是已知的代码执行手法；
- dpa 自身不发起网络请求。插件是原生代码，仍可自行做任何事——这正是上面两点存在
  的原因。

`plugins/demo` 是示例插件。用 `cargo build -p dpa-plugin-demo` 构建，再用
`dpa --plugins <dir> list` 加载生成的动态库。

## 编写插件

1. 创建一个 `cdylib` crate，依赖 dpa（`default-features = false` 即可）：

   ```toml
   [lib]
   crate-type = ["cdylib"]

   [dependencies]
   dpa = { path = "../..", default-features = false }
   anyhow = "1"
   ```

2. 定义整块处理函数；若该操作可增量处理，再定义一个流式工厂函数。用 `dpa_plugin!`
   宏导出：

   ```rust
   use std::collections::HashMap;
   use dpa::dpa_plugin;
   use dpa::ops::{ArgSpec, StreamingOp};

   fn my_run(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
       Ok(input.to_vec())
   }

   dpa_plugin! {
       version: 2,                    // 必须等于 DPA_PLUGIN_ABI_VERSION
       ops: [
           {
               name: "demo:identity",  // 前缀任意
               category: "transform",
               description: "复制输入到输出",
               args: [],
               run: my_run,
           },
       ],
   }
   ```

   `stream` 字段填流式工厂函数；一次性处理整个输入的操作直接省略该字段
   （不接受 `stream: None`）。`plugins/demo` 展示了两种路径。

3. 构建该 crate，然后用 `dpa --plugins <dir>` 加载生成的动态库。

## ABI 面

导出的符号刻意保持精简且 C ABI 稳定；完整签名见 `src/plugin.rs` 的模块文档。

- `dpa_plugin_version()`——ABI 版本握手；
- `dpa_plugin_op_count()` 与
  `dpa_plugin_op_name/_category/_description/_args_json(i)`——静态操作元数据；
- `dpa_plugin_op_run(name, in, in_len, args_json, out, out_len)`——整块处理；
- `dpa_plugin_op_stream_init/_write/_finish/_free`——流式处理；
- `dpa_plugin_last_error()` 与 `dpa_plugin_buf_free(ptr, len)`——错误通道与缓冲区
  归属。分配与释放都在插件内部完成。

返回约定：`0` 表示成功，任何非零值表示处理出错。

## 命名

操作名形如 `prefix:family:kind`。内置操作使用 `dpa:` 前缀；插件可以使用其他任意
前缀。以 `dpa:` 开头的名字保留给随 dpa 一同发布的插件。

列表展示会去掉第一段，因此名为 `my:foo` 的插件操作显示为 `foo`。

## 适用范围

这套 ABI 面向适合放在主 crate 之外的操作：少见的格式、对大型库的封装，以及第三方
贡献的操作。随 dpa 发布的操作留在主 crate 中；把某个操作移出去需要逐个评估。
