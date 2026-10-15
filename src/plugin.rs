//! Plugin ABI: load third-party ops from `cdylib` plugins.
//!
//! A plugin is a shared library (`.dll` / `.so` / `.dylib`) compiled with the
//! [`dpa_plugin!`] export macro. The ABI is deliberately small and C-stable:
//!
//! ```text
//! dpa_plugin_version() -> u32                    // must equal DPA_PLUGIN_ABI_VERSION
//! dpa_plugin_op_count() -> usize
//! dpa_plugin_op_name(i) / _category(i) / _description(i) / _args_json(i) -> *const c_char
//! dpa_plugin_op_run(name, in, in_len, args_json, &mut *mut u8, &mut usize) -> i32
//! dpa_plugin_op_stream_init(name, args_json) -> *mut c_void
//! dpa_plugin_op_stream_write(handle, in, in_len, &mut *mut u8, &mut usize) -> i32
//! dpa_plugin_op_stream_finish(handle, &mut *mut u8, &mut usize) -> i32
//! dpa_plugin_op_stream_free(handle)
//! dpa_plugin_last_error() -> *const c_char   // most recent error description (null if none)
//! dpa_plugin_buf_free(ptr, len)
//! ```
//!
//! Return convention: `0` = success, any non-zero value = processing error.
//! On error the plugin stores a human-readable description (entry point, op
//! name and underlying error) that the host reads back through
//! `dpa_plugin_last_error`. On success the plugin allocates the output buffer
//! and the host copies it out, then calls `dpa_plugin_buf_free` (allocation
//! and freeing stay inside the plugin).
//!
//! Error channel (ABI v2): best-effort and per-thread on the plugin side; the
//! host reads it immediately after a failing call returns. All entry points
//! guard null pointers and report them through the same channel.
//!
//! Security: a plugin runs arbitrary native code inside the dpa process. Only
//! load plugins you trust. Plugins are loaded from the default plugin
//! directories at startup (the `plugins/` directory next to the executable,
//! then the per-user plugin directory), plus any directory explicitly passed
//! via `--plugins`. Loading is opt-out by simply not placing plugin binaries
//! in those locations; the security responsibility stays with whoever put a
//! plugin there (local by design, see docs/PLUGIN.md).

use std::collections::HashMap;
use std::ffi::{CStr, CString, c_char, c_void};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use libloading::Library;

use crate::i18n;
use crate::ops::{ArgFormat, ArgSpec, Op, StreamFactory, StreamingOp};

/// ABI version negotiated between host and plugin. Bump on breaking ABI changes.
pub const DPA_PLUGIN_ABI_VERSION: u32 = 2;

// ---------------------------------------------------------------------------
// Plugin-side contract (used by the `dpa_plugin!` export macro)
// ---------------------------------------------------------------------------

/// One op registered by a plugin. The export macro builds these via
/// [`PluginOpEntry::new`] and dispatches all ABI calls against the entry table.
#[allow(clippy::type_complexity)]
pub struct PluginOpEntry {
    /// Unique op identifier, namespaced: `dpa:<category>:<name>`.
    pub name: &'static str,
    pub category: &'static str,
    pub description: &'static str,
    pub args: &'static [ArgSpec],
    /// In-memory run function (whole-buffer path).
    pub run: fn(&[u8], &HashMap<String, String>) -> anyhow::Result<Vec<u8>>,
    /// Optional streaming factory; `None` restricts the op to whole-buffer input.
    pub stream: Option<fn(&HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>>>,
    /// NUL-terminated C views (leaked for the plugin lifetime; the host reads them via CStr).
    /// Read by the `dpa_plugin!` export bridges; `#[allow]` because the macro
    /// expands in plugin crates, so the lib target reports them as unused.
    #[allow(dead_code)]
    pub name_ptr: *const c_char,
    #[allow(dead_code)]
    pub category_ptr: *const c_char,
    #[allow(dead_code)]
    pub description_ptr: *const c_char,
}

// Raw pointers inside; PluginOpEntry is only used behind & in the plugin-side
// static table, never sent across threads. Safe enough for the export macro.
unsafe impl Send for PluginOpEntry {}
unsafe impl Sync for PluginOpEntry {}

#[allow(clippy::type_complexity)]
impl PluginOpEntry {
    /// Build an entry; C views are derived from the static strings and leaked
    /// once (tiny, and the plugin stays loaded for the whole process lifetime).
    pub fn new(
        name: &'static str,
        category: &'static str,
        description: &'static str,
        args: &'static [ArgSpec],
        run: fn(&[u8], &HashMap<String, String>) -> anyhow::Result<Vec<u8>>,
        stream: Option<fn(&HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>>>,
    ) -> Self {
        let leak_c = |s: &str| -> *const c_char {
            Box::leak(format!("{}\0", s).into_boxed_str()).as_ptr() as *const c_char
        };
        Self {
            name,
            category,
            description,
            args,
            run,
            stream,
            name_ptr: leak_c(name),
            category_ptr: leak_c(category),
            description_ptr: leak_c(description),
        }
    }
}

/// Serialize an `ArgSpec` slice into the plugin `args_json` spec format:
/// `{"<name>":{"required":bool,"description":"..."}}`.
pub fn args_spec_to_json(args: &[ArgSpec]) -> String {
    // Serialize through serde_json so every string field (names, descriptions,
    // formats) is escaped exactly like the parser expects (review §3-G: the
    // previous hand-rolled builder only escaped `"` and could emit invalid
    // JSON for backslashes/newlines).
    let mut map = serde_json::Map::new();
    for a in args {
        map.insert(
            a.name.to_string(),
            serde_json::json!({
                "required": a.required,
                "description": a.description,
                "format": a.format.display(),
            }),
        );
    }
    serde_json::Value::Object(map).to_string()
}

/// Parse the plugin `args_json` spec format into `ArgSpec`s (used by the host
/// registry so plugin ops show up in `dpa list` / `dpa ops`).
///
/// Returns an error instead of silently swallowing malformed JSON (review
/// §3-G: the previous version returned an empty `Vec` on failure, which hid
/// broken plugin metadata).
pub fn parse_args_spec_json(s: &str) -> anyhow::Result<Vec<ArgSpec>> {
    let v = serde_json::from_str::<serde_json::Value>(s)
        .map_err(|e| anyhow::anyhow!("invalid plugin args spec JSON: {e}"))?;
    let Some(obj) = v.as_object() else {
        return Ok(Vec::new());
    };
    let mut out = Vec::with_capacity(obj.len());
    for (name, spec) in obj {
        let required = spec
            .get("required")
            .and_then(|r| r.as_bool())
            .unwrap_or(false);
        let description = spec
            .get("description")
            .and_then(|d| d.as_str())
            .unwrap_or("")
            .to_string();
        let format = spec
            .get("format")
            .and_then(|f| f.as_str())
            .and_then(ArgFormat::parse)
            .unwrap_or(ArgFormat::Utf8);
        out.push(ArgSpec {
            name: Box::leak(name.clone().into_boxed_str()),
            required,
            description: Box::leak(description.into_boxed_str()),
            format,
        });
    }
    Ok(out)
}

/// Parse runtime user args (a JSON object of string -> string) for ABI calls.
pub fn parse_args_json(s: &str) -> anyhow::Result<HashMap<String, String>> {
    let v: serde_json::Value = serde_json::from_str(s).map_err(|e| {
        anyhow::anyhow!(
            "{}",
            i18n::tf("err.plugin_args_json", &[e.to_string().as_str()])
        )
    })?;
    let obj = v
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("{}", i18n::t("err.plugin_args_json_obj")))?;
    let mut map = HashMap::new();
    for (k, val) in obj {
        let sv = match val {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Bool(b) => b.to_string(),
            serde_json::Value::Number(n) => n.to_string(),
            _ => continue,
        };
        map.insert(k.clone(), sv);
    }
    Ok(map)
}

// ---------------------------------------------------------------------------
// Host side: plugin discovery, loading and op bridging
// ---------------------------------------------------------------------------

/// A loaded plugin. The `Library` is kept alive for the whole process so the
/// op metadata strings (leaked into `Op`) never dangle.
struct LoadedPlugin {
    _lib: Library,
    ops: Vec<PluginLoadedOp>,
}

/// Host-side mirror of a plugin op with the resolved ABI function pointers.
/// All ABI pointers are `unsafe extern "C" fn` (calling plugin code is unsafe).
struct PluginLoadedOp {
    name: String,
    category: String,
    description: String,
    args: &'static [ArgSpec],
    run: unsafe extern "C" fn(
        *const c_char,
        *const u8,
        usize,
        *const c_char,
        *mut *mut u8,
        *mut usize,
    ) -> i32,
    stream_init: Option<unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_void>,
    stream_write: Option<
        unsafe extern "C" fn(*mut c_void, *const u8, usize, *mut *mut u8, *mut usize) -> i32,
    >,
    stream_finish: Option<unsafe extern "C" fn(*mut c_void, *mut *mut u8, *mut usize) -> i32>,
    stream_free: Option<unsafe extern "C" fn(*mut c_void)>,
    last_error: Option<unsafe extern "C" fn() -> *const c_char>,
    buf_free: unsafe extern "C" fn(*mut u8, usize),
}

/// Process-wide registry of loaded plugins (populated by [`load_plugins`]).
static REGISTRY: OnceLock<Mutex<Vec<LoadedPlugin>>> = OnceLock::new();

fn registry() -> &'static Mutex<Vec<LoadedPlugin>> {
    REGISTRY.get_or_init(|| Mutex::new(Vec::new()))
}

/// File name of the per-directory plugin hash manifest (review §3-P8).
const PLUGIN_HASH_MANIFEST: &str = ".dpa-plugin-hashes.json";

/// SHA-256 of a file in hex, streamed to avoid loading large binaries.
fn file_sha256(path: &Path) -> anyhow::Result<String> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    let mut f = std::fs::File::open(path)?;
    let mut buf = [0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Load every shared library in `dir` as a dpa plugin. A failing plugin is
/// skipped with a warning on stderr; returns the number of successfully loaded
/// plugins. Missing directories are treated as "nothing to load" (no error).
///
/// Review §3-P8 (plugin hash manifest): on first use the directory's SHA-256
/// manifest is generated; afterwards only plugins whose hash matches the
/// manifest are loaded. Deleting `.dpa-plugin-hashes.json` regenerates it.
pub fn load_plugins(dir: &Path) -> anyhow::Result<usize> {
    if !dir.is_dir() {
        return Ok(0);
    }
    let mut paths: Vec<PathBuf> = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if matches!(ext, "dll" | "so" | "dylib") {
            paths.push(path);
        }
    }
    paths.sort_by(|a, b| a.file_name().cmp(&b.file_name()));

    let manifest_path = dir.join(PLUGIN_HASH_MANIFEST);
    let known: std::collections::HashMap<String, String> = if manifest_path.is_file() {
        std::fs::read_to_string(&manifest_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    } else {
        std::collections::HashMap::new()
    };
    let hash_enforced = !known.is_empty();

    let mut loaded = 0;
    let mut reg = registry().lock().unwrap();
    for path in &paths {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        if hash_enforced {
            let Some(recorded) = known.get(&name) else {
                eprintln!(
                    "{}",
                    i18n::tf(
                        "err.plugin_hash_missing",
                        &[name.as_str(), manifest_path.display().to_string().as_str()]
                    )
                );
                continue;
            };
            match file_sha256(path) {
                Ok(h) if h == *recorded => {}
                Ok(_) => {
                    eprintln!(
                        "{}",
                        i18n::tf(
                            "err.plugin_hash_mismatch",
                            &[name.as_str(), manifest_path.display().to_string().as_str()]
                        )
                    );
                    continue;
                }
                Err(e) => {
                    eprintln!(
                        "{}",
                        i18n::tf(
                            "err.plugin_load_failed",
                            &[name.as_str(), e.to_string().as_str()]
                        )
                    );
                    continue;
                }
            }
        }
        match load_one(path) {
            Ok(p) => {
                loaded += p.ops.len();
                reg.push(p);
            }
            Err(e) => {
                eprintln!(
                    "{}",
                    i18n::tf(
                        "err.plugin_load_failed",
                        &[path.display().to_string().as_str(), e.to_string().as_str()]
                    )
                );
            }
        }
    }

    // First use: record hashes so later runs can enforce them.
    if !hash_enforced && !paths.is_empty() {
        let mut map = serde_json::Map::new();
        for path in &paths {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            if let Ok(h) = file_sha256(path) {
                map.insert(name.to_string(), serde_json::Value::String(h));
            }
        }
        if let Ok(s) = serde_json::to_string_pretty(&serde_json::Value::Object(map)) {
            if std::fs::write(&manifest_path, s).is_ok() {
                eprintln!(
                    "{}",
                    i18n::tf(
                        "msg.plugin_hash_generated",
                        &[manifest_path.display().to_string().as_str()]
                    )
                );
            }
        }
    }

    Ok(loaded)
}

/// Candidate default plugin directories, in load order: the `plugins/`
/// directory next to the current executable (ships with the program, e.g.
/// official plugins), then the per-user plugin directory
/// (`%APPDATA%\dpa\plugins` on Windows, `~/.dpa/plugins` elsewhere). Only
/// directories that actually exist are returned.
pub fn default_plugin_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let bundled = parent.join("plugins");
            if bundled.is_dir() {
                dirs.push(bundled);
            }
        }
    }
    let user_dir = if cfg!(windows) {
        std::env::var_os("APPDATA").map(PathBuf::from)
    } else {
        std::env::var_os("HOME").map(PathBuf::from)
    }
    .map(|base| {
        if cfg!(windows) {
            base.join("dpa").join("plugins")
        } else {
            base.join(".dpa").join("plugins")
        }
    });
    if let Some(dir) = user_dir {
        if dir.is_dir() {
            dirs.push(dir);
        }
    }
    dirs
}

/// Load plugins from every existing default plugin directory. Missing
/// directories are skipped silently; a failing plugin inside an existing
/// directory is already handled by [`load_plugins`] (warn + skip). Returns the
/// total number of ops loaded.
pub fn load_default_plugins() -> anyhow::Result<usize> {
    let mut total = 0;
    for dir in default_plugin_dirs() {
        total += load_plugins(&dir)?;
    }
    Ok(total)
}

/// Load a single plugin library and mirror its ops.
fn load_one(path: &Path) -> anyhow::Result<LoadedPlugin> {
    unsafe {
        let lib = Library::new(path)?;
        let version: libloading::Symbol<unsafe extern "C" fn() -> u32> =
            lib.get(b"dpa_plugin_version")?;
        if version() != DPA_PLUGIN_ABI_VERSION {
            anyhow::bail!(
                "{}",
                i18n::tf(
                    "err.plugin_abi_version",
                    &[
                        DPA_PLUGIN_ABI_VERSION.to_string().as_str(),
                        version().to_string().as_str()
                    ]
                )
            );
        }
        let count: libloading::Symbol<unsafe extern "C" fn() -> usize> =
            lib.get(b"dpa_plugin_op_count")?;
        let get_name: libloading::Symbol<unsafe extern "C" fn(usize) -> *const c_char> =
            lib.get(b"dpa_plugin_op_name")?;
        let get_category: libloading::Symbol<unsafe extern "C" fn(usize) -> *const c_char> =
            lib.get(b"dpa_plugin_op_category")?;
        let get_description: libloading::Symbol<unsafe extern "C" fn(usize) -> *const c_char> =
            lib.get(b"dpa_plugin_op_description")?;
        let get_args_json: libloading::Symbol<unsafe extern "C" fn(usize) -> *const c_char> =
            lib.get(b"dpa_plugin_op_args_json")?;
        let run: libloading::Symbol<
            unsafe extern "C" fn(
                *const c_char,
                *const u8,
                usize,
                *const c_char,
                *mut *mut u8,
                *mut usize,
            ) -> i32,
        > = lib.get(b"dpa_plugin_op_run")?;
        let buf_free: libloading::Symbol<unsafe extern "C" fn(*mut u8, usize)> =
            lib.get(b"dpa_plugin_buf_free")?;
        let stream_init: Option<
            libloading::Symbol<unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_void>,
        > = lib.get(b"dpa_plugin_op_stream_init").ok();
        let stream_write: Option<
            libloading::Symbol<
                unsafe extern "C" fn(
                    *mut c_void,
                    *const u8,
                    usize,
                    *mut *mut u8,
                    *mut usize,
                ) -> i32,
            >,
        > = lib.get(b"dpa_plugin_op_stream_write").ok();
        let stream_finish: Option<
            libloading::Symbol<unsafe extern "C" fn(*mut c_void, *mut *mut u8, *mut usize) -> i32>,
        > = lib.get(b"dpa_plugin_op_stream_finish").ok();
        let stream_free: Option<libloading::Symbol<unsafe extern "C" fn(*mut c_void)>> =
            lib.get(b"dpa_plugin_op_stream_free").ok();
        // ABI v2 error channel: optional, so v1-era plugins still load (their
        // failures just carry no description).
        let last_error: Option<libloading::Symbol<unsafe extern "C" fn() -> *const c_char>> =
            lib.get(b"dpa_plugin_last_error").ok();

        let stream = match (&stream_init, &stream_write, &stream_finish, &stream_free) {
            (Some(a), Some(b), Some(c), Some(d)) => Some((**a, **b, **c, **d)),
            (None, None, None, None) => None,
            _ => anyhow::bail!("{}", i18n::t("err.plugin_partial_stream")),
        };

        let n = count();
        let mut ops = Vec::new();
        for i in 0..n {
            let name_ptr = get_name(i);
            let category_ptr = get_category(i);
            let description_ptr = get_description(i);
            let args_ptr = get_args_json(i);
            if name_ptr.is_null() {
                continue;
            }
            let name = CStr::from_ptr(name_ptr).to_string_lossy().into_owned();
            let category = CStr::from_ptr(category_ptr).to_string_lossy().into_owned();
            let description = CStr::from_ptr(description_ptr)
                .to_string_lossy()
                .into_owned();
            let args_json = CStr::from_ptr(args_ptr).to_string_lossy().into_owned();
            let args = match parse_args_spec_json(&args_json) {
                Ok(v) => Box::leak(v.into_boxed_slice()),
                Err(e) => {
                    // Review §3-G: surface malformed plugin metadata instead of
                    // silently registering the op with an empty arg spec.
                    eprintln!(
                        "{}",
                        i18n::tf(
                            "err.plugin_bad_args",
                            &[name.as_str(), e.to_string().as_str()]
                        )
                    );
                    Box::leak(Vec::new().into_boxed_slice())
                }
            };
            ops.push(PluginLoadedOp {
                name,
                category,
                description,
                args,
                run: *run,
                stream_init: stream.map(|(a, _, _, _)| a),
                stream_write: stream.map(|(_, b, _, _)| b),
                stream_finish: stream.map(|(_, _, c, _)| c),
                stream_free: stream.map(|(_, _, _, d)| d),
                last_error: last_error.as_ref().map(|s| **s),
                buf_free: *buf_free,
            });
        }
        if ops.is_empty() {
            anyhow::bail!("{}", i18n::t("err.plugin_no_ops"));
        }
        Ok(LoadedPlugin { _lib: lib, ops })
    }
}

/// Build dpa `Op`s for every loaded plugin op. Called exactly once by the
/// process-wide registry in `ops::mod` (review fix 3.2/3.4): the plugin
/// registry is immutable after [`load_plugins`], so the returned table is
/// materialized once and owned by the registry — no per-call `Box::leak` of
/// `&'static str` metadata. Op metadata is owned (`String`).
pub(crate) fn plugin_ops_vec() -> Vec<Op> {
    build_plugin_ops()
}

fn build_plugin_ops() -> Vec<Op> {
    let reg = registry().lock().unwrap();
    let mut out = Vec::new();
    for plugin in reg.iter() {
        for op in &plugin.ops {
            let name = op.name.clone();
            let category = op.category.clone();
            let description = op.description.clone();
            let run_ptr = op.run;
            let buf_free = op.buf_free;
            let last_error = op.last_error;
            let name_c = CString::new(op.name.clone()).unwrap_or_default();
            let run = Box::new(move |input: &[u8], args: &HashMap<String, String>| {
                call_plugin_run(name_c.as_ptr(), run_ptr, buf_free, last_error, input, args)
            });
            let stream = op.stream_init.map(|init| {
                // ABI guarantees all-or-nothing: if stream_init exists, the
                // three companion functions are present too.
                let write = op.stream_write.unwrap();
                let finish = op.stream_finish.unwrap();
                let free = op.stream_free.unwrap();
                let last_error = op.last_error;
                let name_c = CString::new(op.name.clone()).unwrap_or_default();
                let factory: StreamFactory = Box::new(move |args: &HashMap<String, String>| {
                    let args_json = serde_json::to_string(args)?;
                    let c_args = CString::new(args_json)?;
                    let h = unsafe { init(name_c.as_ptr(), c_args.as_ptr()) };
                    if h.is_null() {
                        let detail = last_error_msg(last_error);
                        if detail.is_empty() {
                            anyhow::bail!("{}", i18n::t("err.plugin_stream_init_failed"));
                        }
                        anyhow::bail!("{}: {}", i18n::t("err.plugin_stream_init_failed"), detail);
                    }
                    Ok(Box::new(PluginStream {
                        h,
                        write,
                        finish,
                        free,
                        last_error,
                        buf_free,
                    }))
                });
                factory
            });
            let (family, kind) = crate::ops::derive_family_kind(&name, &category);
            let level = crate::ops::derive_level(&name, &category, &family, &kind);
            out.push(Op {
                name,
                category,
                family,
                kind,
                level,
                input: crate::ops::OpIO::Unspecified,
                output: crate::ops::OpIO::Unspecified,
                description,
                args: op.args,
                run,
                stream,
            });
        }
    }
    out
}

/// Invoke a plugin's in-memory run function: serialize args, call the ABI,
/// copy the plugin-allocated output out and free it via the plugin.
/// Read the plugin's most recent error description through the ABI v2 channel.
fn last_error_msg(f: Option<unsafe extern "C" fn() -> *const c_char>) -> String {
    match f {
        Some(f) => {
            let p = unsafe { f() };
            if p.is_null() {
                String::new()
            } else {
                unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
            }
        }
        None => String::new(),
    }
}

fn call_plugin_run(
    name: *const c_char,
    run: unsafe extern "C" fn(
        *const c_char,
        *const u8,
        usize,
        *const c_char,
        *mut *mut u8,
        *mut usize,
    ) -> i32,
    buf_free: unsafe extern "C" fn(*mut u8, usize),
    last_error: Option<unsafe extern "C" fn() -> *const c_char>,
    input: &[u8],
    args: &HashMap<String, String>,
) -> anyhow::Result<Vec<u8>> {
    let args_json = serde_json::to_string(args)?;
    let c_args = CString::new(args_json)?;
    let mut out_ptr: *mut u8 = std::ptr::null_mut();
    let mut out_len: usize = 0;
    let rc = unsafe {
        run(
            name,
            input.as_ptr(),
            input.len(),
            c_args.as_ptr(),
            &mut out_ptr,
            &mut out_len,
        )
    };
    if rc != 0 {
        let detail = last_error_msg(last_error);
        if detail.is_empty() {
            anyhow::bail!("{}", i18n::t("err.plugin_run_failed"));
        }
        anyhow::bail!("{}: {}", i18n::t("err.plugin_run_failed"), detail);
    }
    let out = if out_len == 0 {
        Vec::new()
    } else {
        let slice = unsafe { std::slice::from_raw_parts(out_ptr, out_len) };
        let v = slice.to_vec();
        unsafe { buf_free(out_ptr, out_len) };
        v
    };
    Ok(out)
}

/// Host-side `StreamingOp` bridging a plugin streaming handle through the ABI.
struct PluginStream {
    h: *mut c_void,
    write: unsafe extern "C" fn(*mut c_void, *const u8, usize, *mut *mut u8, *mut usize) -> i32,
    finish: unsafe extern "C" fn(*mut c_void, *mut *mut u8, *mut usize) -> i32,
    free: unsafe extern "C" fn(*mut c_void),
    last_error: Option<unsafe extern "C" fn() -> *const c_char>,
    buf_free: unsafe extern "C" fn(*mut u8, usize),
}

impl PluginStream {
    fn collect(&self, rc: i32, out_ptr: *mut u8, out_len: usize) -> anyhow::Result<Vec<u8>> {
        if rc != 0 {
            let detail = last_error_msg(self.last_error);
            if detail.is_empty() {
                anyhow::bail!("{}", i18n::t("err.plugin_stream_failed"));
            }
            anyhow::bail!("{}: {}", i18n::t("err.plugin_stream_failed"), detail);
        }
        let out = if out_len == 0 {
            Vec::new()
        } else {
            let slice = unsafe { std::slice::from_raw_parts(out_ptr, out_len) };
            let v = slice.to_vec();
            unsafe { (self.buf_free)(out_ptr, out_len) };
            v
        };
        Ok(out)
    }
}

impl StreamingOp for PluginStream {
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut out_ptr: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let rc = unsafe {
            (self.write)(
                self.h,
                chunk.as_ptr(),
                chunk.len(),
                &mut out_ptr,
                &mut out_len,
            )
        };
        self.collect(rc, out_ptr, out_len)
    }

    fn finish(&mut self) -> anyhow::Result<Vec<u8>> {
        let mut out_ptr: *mut u8 = std::ptr::null_mut();
        let mut out_len: usize = 0;
        let rc = unsafe { (self.finish)(self.h, &mut out_ptr, &mut out_len) };
        self.collect(rc, out_ptr, out_len)
    }
}

impl Drop for PluginStream {
    fn drop(&mut self) {
        unsafe { (self.free)(self.h) };
    }
}

// ---------------------------------------------------------------------------
// Export macro: turn a table of plain Rust ops into a dpa plugin library
// ---------------------------------------------------------------------------

/// Export the current crate as a dpa plugin.
///
/// ```ignore
/// dpa::dpa_plugin! {
///     version: 2,
///     ops: [
///         {
///             name: "dpa:plugin:rot13",
///             category: "plugin",
///             description: "Rotate every byte by 13",
///             args: [],
///             run: rot13_run,                // fn(&[u8], &HashMap<String,String>) -> anyhow::Result<Vec<u8>>
///             stream: Some(rot13_stream),    // optional; fn(&HashMap) -> anyhow::Result<Box<dyn dpa::ops::StreamingOp>>
///         },
///     ],
/// }
/// ```
///
/// `name` / `category` / `description` / `args` must be static expressions.
/// The macro generates the full C ABI surface (version/count/metadata/run/
/// stream/buf_free) shared by every op, dispatching on the op name.
#[macro_export]
macro_rules! dpa_plugin {
    // Op entry WITH an explicit streaming factory.
    (
        version: $ver:expr,
        ops: [ $( { name: $name:expr, category: $cat:expr, description: $desc:expr, args: $args:expr, run: $run:expr, stream: $stream:expr $(,)* } ),* $(,)? ] $(,)?
    ) => {
        $crate::_dpa_plugin_body!($ver; $($name, $cat, $desc, $args, $run, Some($stream as fn(&::std::collections::HashMap<::std::string::String, ::std::string::String>) -> ::anyhow::Result<::std::boxed::Box<dyn $crate::ops::StreamingOp>>);)*);
    };
    // Op entry WITHOUT a streaming factory (whole-buffer only).
    (
        version: $ver:expr,
        ops: [ $( { name: $name:expr, category: $cat:expr, description: $desc:expr, args: $args:expr, run: $run:expr $(,)* } ),* $(,)? ] $(,)?
    ) => {
        $crate::_dpa_plugin_body!($ver; $($name, $cat, $desc, $args, $run, None;)*);
    };
}

/// Shared body of the `dpa_plugin!` export macro. `$stream` is an
/// `Option<StreamFactory>` per op.
#[macro_export]
macro_rules! _dpa_plugin_body {
    ($ver:expr; $( $name:expr, $cat:expr, $desc:expr, $args:expr, $run:expr, $stream:expr ; )*) => {
        const _DPA_PLUGIN_ABI_VERSION: u32 = $ver;

        // ABI v2 error channel: the most recent error description, kept per
        // thread so concurrent host calls on different threads do not clobber
        // each other. The host reads it right after a failing call returns.
        ::std::thread_local! {
            static _DPA_PLUGIN_LAST_ERROR: ::std::cell::RefCell<::std::option::Option<::std::ffi::CString>> =
                ::std::cell::RefCell::new(::std::option::Option::None);
        }

        fn _dpa_plugin_set_error(msg: ::std::string::String) {
            _DPA_PLUGIN_LAST_ERROR.with(|e| {
                *e.borrow_mut() = ::std::option::Option::Some(::std::ffi::CString::new(msg).unwrap_or_default());
            });
        }

        fn _dpa_plugin_clear_error() {
            _DPA_PLUGIN_LAST_ERROR.with(|e| {
                *e.borrow_mut() = ::std::option::Option::None;
            });
        }

        #[unsafe(no_mangle)]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        pub extern "C" fn dpa_plugin_last_error() -> *const ::std::ffi::c_char {
            _DPA_PLUGIN_LAST_ERROR.with(|e| {
                e.borrow().as_ref().map_or(::std::ptr::null(), |s| s.as_ptr())
            })
        }

        static _DPA_PLUGIN_OPS: ::std::sync::OnceLock<::std::vec::Vec<$crate::plugin::PluginOpEntry>> =
            ::std::sync::OnceLock::new();

        fn _dpa_plugin_ops() -> &'static ::std::vec::Vec<$crate::plugin::PluginOpEntry> {
            _DPA_PLUGIN_OPS.get_or_init(|| {
                ::std::vec![
                    $(
                        $crate::plugin::PluginOpEntry::new(
                            $name,
                            $cat,
                            $desc,
                            $args,
                            $run,
                            $stream
                        ),
                    )*
                ]
            })
        }

        #[unsafe(no_mangle)]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        pub extern "C" fn dpa_plugin_version() -> u32 {
            _DPA_PLUGIN_ABI_VERSION
        }

        #[unsafe(no_mangle)]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        pub extern "C" fn dpa_plugin_op_count() -> usize {
            _dpa_plugin_ops().len()
        }

        #[unsafe(no_mangle)]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        pub extern "C" fn dpa_plugin_op_name(i: usize) -> *const ::std::ffi::c_char {
            _dpa_plugin_ops().get(i).map_or(::std::ptr::null(), |e| e.name_ptr)
        }

        #[unsafe(no_mangle)]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        pub extern "C" fn dpa_plugin_op_category(i: usize) -> *const ::std::ffi::c_char {
            _dpa_plugin_ops().get(i).map_or(::std::ptr::null(), |e| e.category_ptr)
        }

        #[unsafe(no_mangle)]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        pub extern "C" fn dpa_plugin_op_description(i: usize) -> *const ::std::ffi::c_char {
            _dpa_plugin_ops().get(i).map_or(::std::ptr::null(), |e| e.description_ptr)
        }

        #[unsafe(no_mangle)]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        pub extern "C" fn dpa_plugin_op_args_json(i: usize) -> *const ::std::ffi::c_char {
            _dpa_plugin_ops()
                .get(i)
                .map_or(::std::ptr::null(), |e| {
                    // NUL-terminate like every other C view (name/category/
                    // description); a plain `into_boxed_str()` pointer has no
                    // terminator and the host CStr::from_ptr would read past
                    // the JSON and reject it with "trailing characters".
                    ::std::boxed::Box::leak(
                        ::std::ffi::CString::new($crate::plugin::args_spec_to_json(e.args))
                            .unwrap_or_default()
                            .into_boxed_c_str()
                    ).as_ptr() as *const ::std::ffi::c_char
                })
        }

        /// Shared in-memory run bridge: dispatch on the op name.
        #[unsafe(no_mangle)]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        pub extern "C" fn dpa_plugin_op_run(
            name: *const ::std::ffi::c_char,
            in_p: *const u8,
            in_len: usize,
            args_json: *const ::std::ffi::c_char,
            out_ptr: *mut *mut u8,
            out_len: *mut usize,
        ) -> i32 {
            if name.is_null() || in_p.is_null() || args_json.is_null() || out_ptr.is_null() || out_len.is_null() {
                _dpa_plugin_set_error("dpa_plugin_op_run: null argument".into());
                return -1;
            }
            let Some(entry) = _dpa_plugin_ops().iter().find(|e| {
                let n = unsafe { ::std::ffi::CStr::from_ptr(name) }.to_string_lossy();
                n == e.name
            }) else {
                _dpa_plugin_set_error(::std::format!("dpa_plugin_op_run: unknown op {}", unsafe { ::std::ffi::CStr::from_ptr(name) }.to_string_lossy()));
                return -1;
            };
            let input = unsafe { ::std::slice::from_raw_parts(in_p, in_len) };
            let args = unsafe { ::std::ffi::CStr::from_ptr(args_json) }.to_string_lossy();
            let Ok(args) = $crate::plugin::parse_args_json(&args) else {
                _dpa_plugin_set_error("dpa_plugin_op_run: invalid args_json".into());
                return -1;
            };
            match (entry.run)(input, &args) {
                Ok(v) => {
                    _dpa_plugin_clear_error();
                    let len = v.len();
                    let boxed = v.into_boxed_slice();
                    unsafe {
                        *out_ptr = ::std::boxed::Box::into_raw(boxed) as *mut u8;
                        *out_len = len;
                    }
                    0
                }
                Err(e) => {
                    _dpa_plugin_set_error(::std::format!("dpa_plugin_op_run: {}", e));
                    -1
                }
            }
        }

        #[unsafe(no_mangle)]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        pub extern "C" fn dpa_plugin_op_stream_init(
            name: *const ::std::ffi::c_char,
            args_json: *const ::std::ffi::c_char,
        ) -> *mut ::std::ffi::c_void {
            if name.is_null() || args_json.is_null() {
                _dpa_plugin_set_error("dpa_plugin_op_stream_init: null argument".into());
                return ::std::ptr::null_mut();
            }
            let Some(entry) = _dpa_plugin_ops().iter().find(|e| {
                let n = unsafe { ::std::ffi::CStr::from_ptr(name) }.to_string_lossy();
                n == e.name
            }) else {
                _dpa_plugin_set_error(::std::format!("dpa_plugin_op_stream_init: unknown op {}", unsafe { ::std::ffi::CStr::from_ptr(name) }.to_string_lossy()));
                return ::std::ptr::null_mut();
            };
            let Some(make) = entry.stream else {
                _dpa_plugin_set_error(::std::format!("dpa_plugin_op_stream_init: op {} has no streaming factory", unsafe { ::std::ffi::CStr::from_ptr(name) }.to_string_lossy()));
                return ::std::ptr::null_mut();
            };
            let args = unsafe { ::std::ffi::CStr::from_ptr(args_json) }.to_string_lossy();
            let Ok(args) = $crate::plugin::parse_args_json(&args) else {
                _dpa_plugin_set_error("dpa_plugin_op_stream_init: invalid args_json".into());
                return ::std::ptr::null_mut();
            };
            match make(&args) {
                Ok(op) => {
                    _dpa_plugin_clear_error();
                    // Double-box to a thin pointer: the trait object's fat pointer
                    // (data + vtable) cannot survive a cast to *mut c_void, so we
                    // heap-allocate a Box<Box<dyn StreamingOp>> and pass its thin
                    // pointer across the ABI. The companion bridge functions
                    // (stream_write/finish/free) expect exactly this layout.
                    let double: ::std::boxed::Box<::std::boxed::Box<dyn $crate::ops::StreamingOp>> =
                        ::std::boxed::Box::new(op);
                    ::std::boxed::Box::into_raw(double) as *mut ::std::ffi::c_void
                }
                Err(e) => {
                    _dpa_plugin_set_error(::std::format!("dpa_plugin_op_stream_init: {}", e));
                    ::std::ptr::null_mut()
                }
            }
        }

        #[unsafe(no_mangle)]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        pub extern "C" fn dpa_plugin_op_stream_write(
            h: *mut ::std::ffi::c_void,
            in_p: *const u8,
            in_len: usize,
            out_ptr: *mut *mut u8,
            out_len: *mut usize,
        ) -> i32 {
            if h.is_null() {
                _dpa_plugin_set_error("dpa_plugin_op_stream_write: null handle".into());
                return -1;
            }
            if in_p.is_null() && in_len > 0 {
                _dpa_plugin_set_error("dpa_plugin_op_stream_write: null input".into());
                return -1;
            }
            let b: &mut ::std::boxed::Box<dyn $crate::ops::StreamingOp> =
                unsafe { &mut *(h as *mut ::std::boxed::Box<dyn $crate::ops::StreamingOp>) };
            let input = unsafe { ::std::slice::from_raw_parts(in_p, in_len) };
            match b.write(input) {
                Ok(v) => {
                    _dpa_plugin_clear_error();
                    let len = v.len();
                    let boxed = v.into_boxed_slice();
                    unsafe {
                        *out_ptr = ::std::boxed::Box::into_raw(boxed) as *mut u8;
                        *out_len = len;
                    }
                    0
                }
                Err(e) => {
                    _dpa_plugin_set_error(::std::format!("dpa_plugin_op_stream_write: {}", e));
                    -1
                }
            }
        }

        #[unsafe(no_mangle)]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        pub extern "C" fn dpa_plugin_op_stream_finish(
            h: *mut ::std::ffi::c_void,
            out_ptr: *mut *mut u8,
            out_len: *mut usize,
        ) -> i32 {
            if h.is_null() {
                _dpa_plugin_set_error("dpa_plugin_op_stream_finish: null handle".into());
                return -1;
            }
            let b: &mut ::std::boxed::Box<dyn $crate::ops::StreamingOp> =
                unsafe { &mut *(h as *mut ::std::boxed::Box<dyn $crate::ops::StreamingOp>) };
            match b.finish() {
                Ok(v) => {
                    _dpa_plugin_clear_error();
                    let len = v.len();
                    let boxed = v.into_boxed_slice();
                    unsafe {
                        *out_ptr = ::std::boxed::Box::into_raw(boxed) as *mut u8;
                        *out_len = len;
                    }
                    0
                }
                Err(e) => {
                    _dpa_plugin_set_error(::std::format!("dpa_plugin_op_stream_finish: {}", e));
                    -1
                }
            }
        }

        #[unsafe(no_mangle)]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        pub extern "C" fn dpa_plugin_op_stream_free(h: *mut ::std::ffi::c_void) {
            if !h.is_null() {
                // Dropping the double-box also drops the inner `Box<dyn StreamingOp>`.
                unsafe {
                    let _ = ::std::boxed::Box::from_raw(h as *mut ::std::boxed::Box<dyn $crate::ops::StreamingOp>);
                }
            }
        }

        #[unsafe(no_mangle)]
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        pub extern "C" fn dpa_plugin_buf_free(ptr: *mut u8, len: usize) {
            if !ptr.is_null() {
                unsafe {
                    let _ = ::std::boxed::Box::from_raw(::std::ptr::slice_from_raw_parts_mut(ptr, len));
                }
            }
        }
    };
}
