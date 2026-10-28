# dpa Plugin ABI

[简体中文](PLUGIN.zh-CN.md) | English

Plugins add operations to dpa without changing the main binary. A plugin is a
shared library (`.dll`, `.so`, `.dylib`) built against the C ABI exported by the
`dpa_plugin!` macro.

## Security model

A plugin runs native code inside the dpa process. Loading one is equivalent to
running a local program with your privileges, so only load plugins you trust.

dpa does not look for plugins on its own:

- a plugin is loaded by naming its directory: `dpa --plugins <dir>`;
- nothing is read at startup. `dpa --discover-plugins` opts in to reading the two
  conventional locations — `<dpa dir>/plugins/` next to the binary, and the
  per-user directory (`%APPDATA%\dpa\plugins` on Windows, `~/.dpa/plugins`
  elsewhere). It prints a warning and lists the directories it is about to read,
  because a library placed in a user-writable directory is a known way to get
  code executed;
- dpa makes no network requests. A plugin is native code and can still do
  anything on its own — which is the reason for the two points above.

`plugins/demo` is the sample plugin. Build it with
`cargo build -p dpa-plugin-demo`, then load the produced library with
`dpa --plugins <dir> list`.

## Writing a plugin

1. Create a `cdylib` crate that depends on dpa (`default-features = false` is
   enough):

   ```toml
   [lib]
   crate-type = ["cdylib"]

   [dependencies]
   dpa = { path = "../..", default-features = false }
   anyhow = "1"
   ```

2. Define a whole-buffer run function and, if the operation can work
   incrementally, a streaming factory. Export them with the `dpa_plugin!` macro:

   ```rust
   use std::collections::HashMap;
   use dpa::dpa_plugin;
   use dpa::ops::{ArgSpec, StreamingOp};

   fn my_run(input: &[u8], args: &HashMap<String, String>) -> anyhow::Result<Vec<u8>> {
       Ok(input.to_vec())
   }

   dpa_plugin! {
       version: 2,                    // must equal DPA_PLUGIN_ABI_VERSION
       ops: [
           {
               name: "demo:identity",  // any prefix is allowed
               category: "transform",
               description: "copy input to output",
               args: [],
               run: my_run,
           },
       ],
   }
   ```

   The `stream` field holds a streaming factory function; an operation that
   processes the whole input at once simply omits the field (`stream: None` is
   not accepted). `plugins/demo` shows both paths.

3. Build the crate, then load the resulting library with `dpa --plugins <dir>`.

## ABI surface

The exported symbols are deliberately small and C-stable; the module
documentation in `src/plugin.rs` has the full signatures.

- `dpa_plugin_version()` — ABI version handshake;
- `dpa_plugin_op_count()` and
  `dpa_plugin_op_name/_category/_description/_args_json(i)` — static operation
  metadata;
- `dpa_plugin_op_run(name, in, in_len, args_json, out, out_len)` — whole-buffer
  run;
- `dpa_plugin_op_stream_init/_write/_finish/_free` — streaming run;
- `dpa_plugin_last_error()` and `dpa_plugin_buf_free(ptr, len)` — error channel
  and buffer ownership. Allocation and freeing both happen inside the plugin.

Return convention: `0` means success; any non-zero value is a processing error.

## Naming

Operation names have the form `prefix:family:kind`. Built-in operations use the
`dpa:` prefix; a plugin may use any other prefix. Names beginning with `dpa:` are
reserved for plugins shipped with dpa itself.

The listing strips the first segment, so a plugin operation named `my:foo`
appears as `foo`.

## Scope

The ABI is for operations that make sense outside the main crate: uncommon
formats, wrappers around large libraries, and operations contributed by third
parties. Operations that ship with dpa stay in the main crate; moving one out is
decided case by case.
