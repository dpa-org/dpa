//! Op definitions and registration macros.
//!
//! Low-friction contribution: adding an op = one run function in the right submodule + one `op!` line,
//! then append that module's `ops()` to [`builtin_ops`].

/// Registration macro: declare an op in one line. Op submodules import it via `use crate::op;`.
/// Declares ops without a streaming implementation (`stream: None`); they run on the in-memory
/// whole-buffer path. In the streaming pipeline such steps are wrapped by the engine's
/// [`crate::engine::BarrierStream`], so a flow mixing streamable and non-streamable steps
/// still runs incrementally between barriers.
///
/// Two forms: the explicit 7-arg form passes `family`/`kind` directly; the 5-arg form derives
/// them from the op name (e.g. `dpa:gzip:compress` -> family `gzip`, kind `compress`; a bare
/// two-part name such as `dpa:md5` falls back to the category as family and the name as kind).
#[macro_export]
macro_rules! op {
    ($name:expr, $category:expr, $family:expr, $kind:expr, $desc:expr, $args:expr, $run:expr) => {
        $crate::ops::Op {
            name: $name.to_string(),
            category: $category.to_string(),
            family: $family.to_string(),
            kind: $kind.to_string(),
            level: $crate::ops::derive_level($name, &$category, &$family, &$kind),
            input: $crate::ops::OpIO::Unspecified,
            output: $crate::ops::OpIO::Unspecified,
            description: $desc.to_string(),
            args: $args,
            run: Box::new($run),
            stream: None,
        }
    };
    ($name:expr, $category:expr, $desc:expr, $args:expr, $run:expr) => {
        $crate::ops::Op {
            name: $name.to_string(),
            category: $category.to_string(),
            family: $crate::ops::derive_family_kind(&$name, &$category).0,
            kind: $crate::ops::derive_family_kind(&$name, &$category).1,
            level: $crate::ops::derive_level(
                &$name,
                &$category,
                &$crate::ops::derive_family_kind(&$name, &$category).0,
                &$crate::ops::derive_family_kind(&$name, &$category).1,
            ),
            input: $crate::ops::OpIO::Unspecified,
            output: $crate::ops::OpIO::Unspecified,
            description: $desc.to_string(),
            args: $args,
            run: Box::new($run),
            stream: None,
        }
    };
}

/// Registration macro (streaming variant): besides the in-memory run function, declares a streaming handler factory.
/// Streaming ops use the incremental pipeline for batch/large-file writes, keeping whole files out of memory.
/// Same dual form as [`op!`]: the 8-arg form sets `family`/`kind` explicitly, the 6-arg form derives them.
#[macro_export]
macro_rules! stream_op {
    ($name:expr, $category:expr, $family:expr, $kind:expr, $desc:expr, $args:expr, $run:expr, $make:expr) => {
        $crate::ops::Op {
            name: $name.to_string(),
            category: $category.to_string(),
            family: $family.to_string(),
            kind: $kind.to_string(),
            level: $crate::ops::derive_level($name, &$category, &$family, &$kind),
            input: $crate::ops::OpIO::Unspecified,
            output: $crate::ops::OpIO::Unspecified,
            description: $desc.to_string(),
            args: $args,
            run: Box::new($run),
            stream: Some(Box::new($make)),
        }
    };
    ($name:expr, $category:expr, $desc:expr, $args:expr, $run:expr, $make:expr) => {
        $crate::ops::Op {
            name: $name.to_string(),
            category: $category.to_string(),
            family: $crate::ops::derive_family_kind(&$name, &$category).0,
            kind: $crate::ops::derive_family_kind(&$name, &$category).1,
            level: $crate::ops::derive_level(
                &$name,
                &$category,
                &$crate::ops::derive_family_kind(&$name, &$category).0,
                &$crate::ops::derive_family_kind(&$name, &$category).1,
            ),
            input: $crate::ops::OpIO::Unspecified,
            output: $crate::ops::OpIO::Unspecified,
            description: $desc.to_string(),
            args: $args,
            run: Box::new($run),
            stream: Some(Box::new($make)),
        }
    };
}

pub mod analyze;
pub mod cipher;
pub mod codec;
pub mod compress;
pub mod crypto;
pub mod datetime;
pub mod hash;
pub mod json;
pub mod protocol;
#[cfg(not(target_arch = "wasm32"))]
pub mod pubkey;
pub mod random;
pub mod regex;
pub mod transform;

use std::collections::HashMap;

/// Parameter value format: explicit replacement for the implicit
/// `'0x..'` magic prefix. `Utf8` is the default and matches historical
/// behavior; `Hex` / `Base64` / `Number` / `Bool` make the parsing contract
/// explicit. See OPERATION_CONTRACT.md §4.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum ArgFormat {
    /// UTF-8 bytes (historical default).
    #[default]
    Utf8,
    /// Hex string; an optional `0x` / `0X` prefix is accepted and stripped,
    /// inner whitespace is tolerated.
    Hex,
    /// Historical dual-mode: hex when an `0x` / `0X` prefix is present,
    /// otherwise the raw UTF-8 bytes. Replaces the old `'0x..'` magic prefix
    /// convention for key/iv/nonce/tag/salt arguments without changing behavior.
    HexOrUtf8,
    /// Base64 string (standard alphabet with padding).
    Base64,
    /// Integer literal.
    Number,
    /// `true` / `false` (ASCII case-insensitive).
    Bool,
}

impl ArgFormat {
    /// Short display token used by `dpa ops <name>` (code-level, not localized).
    pub fn display(self) -> &'static str {
        match self {
            ArgFormat::Utf8 => "utf8",
            ArgFormat::Hex => "hex",
            ArgFormat::HexOrUtf8 => "hex-or-utf8",
            ArgFormat::Base64 => "base64",
            ArgFormat::Number => "number",
            ArgFormat::Bool => "bool",
        }
    }

    /// Inverse of [`ArgFormat::display`]; unknown tokens yield `None` so the
    /// caller can fall back to the `Utf8` default (used by the plugin ABI spec).
    pub fn parse(token: &str) -> Option<ArgFormat> {
        Some(match token {
            "utf8" => ArgFormat::Utf8,
            "hex" => ArgFormat::Hex,
            "hex-or-utf8" => ArgFormat::HexOrUtf8,
            "base64" => ArgFormat::Base64,
            "number" => ArgFormat::Number,
            "bool" => ArgFormat::Bool,
            _ => return None,
        })
    }
}

/// Hex-decode a string, stripping an optional `0x` / `0X` prefix and tolerating
/// inner whitespace (the canonical hex-arg parser for `ArgFormat::Hex`).
pub fn parse_hex(s: &str) -> anyhow::Result<Vec<u8>> {
    let t = s.trim();
    let hex_part = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    let cleaned: String = hex_part.chars().filter(|c| !c.is_whitespace()).collect();
    hex::decode(&cleaned).map_err(|e| anyhow::anyhow!("invalid hex value: {e}"))
}

/// Parse `true` / `false` (ASCII case-insensitive, plus `1`/`0` aliases).
pub fn parse_bool(s: &str) -> anyhow::Result<bool> {
    match s.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        other => anyhow::bail!("invalid bool value: {other}"),
    }
}

/// Parse a signed integer literal.
pub fn parse_number(s: &str) -> anyhow::Result<i64> {
    s.trim()
        .parse::<i64>()
        .map_err(|e| anyhow::anyhow!("invalid number value: {e}"))
}

/// Base64-decode a string (standard alphabet, padding required).
pub fn parse_base64(s: &str) -> anyhow::Result<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|e| anyhow::anyhow!("invalid base64 value: {e}"))
}

/// Op argument spec (used by `dpa ops <name>` display and flow validation).
pub struct ArgSpec {
    pub name: &'static str,
    pub required: bool,
    pub description: &'static str,
    /// How the argument value is parsed; `Utf8` by default.
    pub format: ArgFormat,
}

impl Default for ArgSpec {
    fn default() -> Self {
        ArgSpec {
            name: "",
            required: false,
            description: "",
            format: ArgFormat::Utf8,
        }
    }
}

impl ArgSpec {
    /// Const constructor with the default `Utf8` format. The recommended way to
    /// declare args (plugin ABI included): callers do not need to spell every
    /// field, and future field additions to `ArgSpec` will not break call sites.
    pub const fn new(name: &'static str, required: bool, description: &'static str) -> Self {
        ArgSpec {
            name,
            required,
            description,
            format: ArgFormat::Utf8,
        }
    }

    /// Const constructor with an explicit [`ArgFormat`].
    pub const fn with_format(
        name: &'static str,
        required: bool,
        description: &'static str,
        format: ArgFormat,
    ) -> Self {
        ArgSpec {
            name,
            required,
            description,
            format,
        }
    }
}

/// Streaming handler factory: builds an incremental handler from op args (unified streaming interface).
/// Boxed (not a bare fn) so plugin ops can capture their loaded FFI pointers.
pub type StreamFactory =
    Box<dyn Fn(&HashMap<String, String>) -> anyhow::Result<Box<dyn StreamingOp>> + Send + Sync>;

/// Streaming op interface (core abstraction).
///
/// Batch streaming, pyo3 bindings and the plugin ABI share this interface:
/// input is fed into [`StreamingOp::write`] in chunks and per-chunk output is returned immediately
/// (can be written straight to disk; only one chunk stays in memory); after all input is fed,
/// [`StreamingOp::finish`] is called to flush internal buffers, emit trailing data and validate integrity.
///
/// Implementation constraints:
/// - `write` must handle arbitrary chunk splits on its own (cross-chunk state is kept inside);
/// - `finish` is called exactly once and returns all remaining output;
/// - for the same input, the streaming path and the `Op::run` in-memory path must produce identical output.
pub trait StreamingOp {
    /// Feed one chunk of input and return the output bytes produced by this chunk.
    fn write(&mut self, chunk: &[u8]) -> anyhow::Result<Vec<u8>>;
    /// Finish: process trailing buffered data and return the remaining output.
    fn finish(&mut self) -> anyhow::Result<Vec<u8>>;
}

/// Full definition of a single op.
#[allow(clippy::type_complexity)]
pub struct Op {
    /// Unique identifier, namespaced: `dpa:<category>:<name>`.
    pub name: String,
    /// Category: analyze / codec / crypto / extract / generate / hash / transform.
    pub category: String,
    /// Family: the technical family an op belongs to, e.g. gzip / base64 / sm4 / parse / timestamp.
    /// Derives from the second name segment unless the registration macro receives an explicit value.
    pub family: String,
    /// Kind: the verb of the operation, e.g. encode / decode / compress / encrypt / parse.
    /// Derives from the remaining name segments unless the registration macro receives an explicit value.
    pub kind: String,
    /// Granularity level: Primary (independent transform) / Variant (sub-path form of a
    /// family, e.g. `base64:url:decode`) / Shortcut (composite convenience, e.g.
    /// `random:hex` = `random` -> `hex:encode`). Defaults to Primary; used for the
    /// statistical dimension ("M families / N ops, including K shortcuts").
    pub level: OpLevel,
    /// Declared input data shape for the engine's step-chain type check (§4).
    /// `Unspecified` (default) opts out of the check; explicit declarations are
    /// validated between adjacent steps (engine reports a hint when they clash).
    pub input: OpIO,
    /// Declared output data shape; see [`Op::input`].
    pub output: OpIO,
    pub description: String,
    pub args: &'static [ArgSpec],
    /// Run function: input bytes + args -> output bytes (in-memory whole-buffer path).
    /// Boxed (not a bare fn) so plugin ops can capture their loaded FFI pointers.
    pub run: Box<dyn Fn(&[u8], &HashMap<String, String>) -> anyhow::Result<Vec<u8>> + Send + Sync>,
    /// Streaming handler factory; `None` means the op has no streaming support (needs whole-buffer input).
    pub stream: Option<StreamFactory>,
}

/// Granularity level of an op: the "statistical dimension" of §3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OpLevel {
    /// Independent transform (`aes:encrypt`, `base64:decode`).
    #[default]
    Primary,
    /// Same-family sub-path form that cannot be reduced further (`base64:url:encode`).
    Variant,
    /// Composite shortcut (`random:hex` = `random` -> `hex:encode`); counted into
    /// its family but not as a standalone op in statistics.
    Shortcut,
}

impl OpLevel {
    pub fn display(&self) -> &'static str {
        match self {
            OpLevel::Primary => "primary",
            OpLevel::Variant => "variant",
            OpLevel::Shortcut => "shortcut",
        }
    }
}

/// Declared data shape of an op's input / output (§4). The engine checks
/// the step chain only between *explicitly declared* neighbours: if both the
/// upstream `output` and the current step's `input` are declared (non-Unspecified)
/// and differ, it reports a mismatch hint (e.g. `random(raw) -> hex:decode(hex)`
/// suggests inserting `hex:encode` first). `Unspecified` opts out of the check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OpIO {
    /// No declaration: shape unknown / not checked.
    #[default]
    Unspecified,
    /// Raw bytes (default pipeline shape; e.g. `random`, decode outputs).
    Raw,
    /// UTF-8 text (e.g. `uuid4`, `timestamp`, JSON/CSV text).
    Utf8,
    /// Hex-encoded text (`hex:encode` output, `hex:decode` input).
    Hex,
    /// Standard Base64 text (`base64:encode` output, `base64:decode` input).
    Base64,
    /// JSON document (text shape, but structurally meaningful; e.g. `json:get`).
    Json,
}

impl OpIO {
    pub fn display(&self) -> &'static str {
        match self {
            OpIO::Unspecified => "unspecified",
            OpIO::Raw => "raw",
            OpIO::Utf8 => "utf8",
            OpIO::Hex => "hex",
            OpIO::Base64 => "base64",
            OpIO::Json => "json",
        }
    }
}

/// Derive the granularity level from an op id when a registration macro is used
/// without an explicit level. Rule: a kind containing a `:` sub-path (such as
/// `base64:url:decode`'s `url:decode`, `timestamp:to:date`'s `to:date`) is a
/// Variant; everything else defaults to Primary. Shortcuts are composite by
/// design and are marked explicitly at registration (e.g. `random:hex`).
pub fn derive_level(name: &str, _category: &str, _family: &str, kind: &str) -> OpLevel {
    let _ = name;
    if kind.contains(':') {
        OpLevel::Variant
    } else {
        OpLevel::Primary
    }
}

/// Derive `(family, kind)` from an op id and its category when a registration
/// macro is used without explicit values. Rules:
/// - `dpa:gzip:compress` -> (`gzip`, `compress`)
/// - `dpa:parse:ethernet` -> (`parse`, `ethernet`)
/// - `dpa:timestamp:to:date` -> (`timestamp`, `to:date`)
/// - a two-part id such as `dpa:md5` (no family segment) -> (category, name),
///   e.g. (`hash`, `md5`); `dpa:reverse` -> (`transform`, `reverse`).
pub fn derive_family_kind(name: &str, category: &str) -> (String, String) {
    let stripped = name.strip_prefix("dpa:").unwrap_or(name);
    let mut parts = stripped.split(':');
    let first = parts.next().unwrap_or("");
    let rest: Vec<&str> = parts.collect();
    if rest.is_empty() {
        (category.to_string(), first.to_string())
    } else {
        (first.to_string(), rest.join(":"))
    }
}

/// All built-in ops. Append a line here when adding an op module.
pub fn builtin_ops() -> Vec<Op> {
    let mut ops = Vec::new();
    ops.extend(analyze::ops());
    ops.extend(codec::ops());
    ops.extend(transform::ops());
    ops.extend(crypto::ops());
    ops.extend(cipher::ops());
    ops.extend(hash::ops());
    ops.extend(compress::ops());
    ops.extend(datetime::ops());
    ops.extend(json::ops());
    #[cfg(not(target_arch = "wasm32"))]
    ops.extend(pubkey::ops());
    ops.extend(protocol::ops());
    ops.extend(random::ops());
    ops.extend(regex::ops());
    apply_io_declarations(&mut ops);
    apply_shortcut_marks(&mut ops);
    ops
}

/// Central shortcut marks: op chains composed of two or more primitives get
/// promoted to `OpLevel::Shortcut` here (single source of truth), instead of
/// scattering `o.level = Shortcut` across modules. The name-based derivation
/// cannot infer these, so they must be explicit. Keep in sync with the §4
/// declaration table where the composite also declares its IO shape.
fn apply_shortcut_marks(ops: &mut [Op]) {
    for op in ops.iter_mut() {
        if matches!(
            op.name.as_str(),
            // codec composites: base64 -> url transform.
            "dpa:base64:url:encode"
                | "dpa:base64:url:decode"
                // datetime composites: epoch/ticks -> human date.
                | "dpa:timestamp:to:date"
                | "dpa:filetime:to:date"
                // pubkey format composites.
                | "dpa:pem:to:hex"
                | "dpa:pem:to:jwk"
                | "dpa:jwk:to:pem"
                | "dpa:hex:to:pem"
                | "dpa:pkcs1:to:pkcs8"
                | "dpa:pkcs8:to:pkcs1"
        ) {
            op.level = OpLevel::Shortcut;
        }
    }
    // `random:hex` stays a shortcut as well; its mark previously lived in
    // random.rs, now unified here.
    for op in ops.iter_mut() {
        if op.name == "dpa:random:hex" {
            op.level = OpLevel::Shortcut;
        }
    }
}

/// Central §4 type declarations: mark the data shape of every built-in op so
/// the engine can type-check step chains. Ops left `Unspecified` opt out of the
/// check; coverage is additive and never changes runtime behaviour. Keep the
/// table grouped by module and in sync with `apply_shortcut_marks`.
fn apply_io_declarations(ops: &mut [Op]) {
    use OpIO::*;
    let set = |ops: &mut [Op], name: &str, input: OpIO, output: OpIO| {
        for op in ops.iter_mut() {
            if op.name == name {
                op.input = input;
                op.output = output;
            }
        }
    };
    // ── random / generators ───────────────────────────────────────────────
    set(ops, "dpa:random", Unspecified, Raw);
    set(ops, "dpa:random:hex", Unspecified, Hex);
    set(ops, "dpa:uuid4", Unspecified, Utf8);
    set(ops, "dpa:timestamp", Unspecified, Utf8);
    set(ops, "dpa:timestamp:to:date", Utf8, Utf8);
    set(ops, "dpa:filetime", Unspecified, Utf8);
    set(ops, "dpa:filetime:to:date", Utf8, Utf8);
    set(ops, "dpa:de:bruijn", Unspecified, Utf8);
    set(ops, "dpa:hotp", Unspecified, Utf8);
    set(ops, "dpa:totp", Unspecified, Utf8);
    set(ops, "dpa:lorem:ipsum", Unspecified, Utf8);
    set(ops, "dpa:prime", Unspecified, Utf8);
    // ── hex / base64 boundary (text encodings) ────────────────────────────
    set(ops, "dpa:hex:encode", Raw, Hex);
    set(ops, "dpa:hex:decode", Hex, Raw);
    set(ops, "dpa:base64:encode", Raw, Base64);
    set(ops, "dpa:base64:decode", Base64, Raw);
    set(ops, "dpa:base64:url:encode", Raw, Base64);
    set(ops, "dpa:base64:url:decode", Base64, Raw);
    // ── codec: text encodings of arbitrary bytes ──────────────────────────
    set(ops, "dpa:base32:encode", Raw, Utf8);
    set(ops, "dpa:base32:decode", Utf8, Raw);
    set(ops, "dpa:base45:encode", Raw, Utf8);
    set(ops, "dpa:base45:decode", Utf8, Raw);
    set(ops, "dpa:base58:encode", Raw, Utf8);
    set(ops, "dpa:base58:decode", Utf8, Raw);
    set(ops, "dpa:base62:encode", Raw, Utf8);
    set(ops, "dpa:base62:decode", Utf8, Raw);
    set(ops, "dpa:base85:encode", Raw, Utf8);
    set(ops, "dpa:base85:decode", Utf8, Raw);
    set(ops, "dpa:binary:encode", Raw, Utf8);
    set(ops, "dpa:binary:decode", Utf8, Raw);
    set(ops, "dpa:octal:encode", Raw, Utf8);
    set(ops, "dpa:octal:decode", Utf8, Raw);
    set(ops, "dpa:decimal:encode", Raw, Utf8);
    set(ops, "dpa:decimal:decode", Utf8, Raw);
    set(ops, "dpa:charcode:encode", Raw, Utf8);
    set(ops, "dpa:charcode:decode", Utf8, Raw);
    set(ops, "dpa:ebcdic:encode", Raw, Utf8);
    set(ops, "dpa:ebcdic:decode", Utf8, Raw);
    set(ops, "dpa:hexdump:encode", Raw, Utf8);
    set(ops, "dpa:hexdump:decode", Utf8, Raw);
    set(ops, "dpa:qp:encode", Raw, Utf8);
    set(ops, "dpa:qp:decode", Utf8, Raw);
    // utf16 emits raw wide-char bytes, not text.
    set(ops, "dpa:utf16:encode", Utf8, Raw);
    set(ops, "dpa:utf16:decode", Raw, Utf8);
    // ── codec: text <-> text transforms ───────────────────────────────────
    set(ops, "dpa:url:encode", Utf8, Utf8);
    set(ops, "dpa:url:decode", Utf8, Utf8);
    set(ops, "dpa:html:encode", Utf8, Utf8);
    set(ops, "dpa:html:decode", Utf8, Utf8);
    set(ops, "dpa:punycode:encode", Utf8, Utf8);
    set(ops, "dpa:punycode:decode", Utf8, Utf8);
    set(ops, "dpa:utf8:escape", Utf8, Utf8);
    set(ops, "dpa:utf8:unescape", Utf8, Utf8);
    // ── codec: structured <-> text ────────────────────────────────────────
    set(ops, "dpa:json:to-xml", Json, Utf8);
    set(ops, "dpa:json:to-yaml", Json, Utf8);
    set(ops, "dpa:xml:to-json", Utf8, Json);
    set(ops, "dpa:yaml:to-json", Utf8, Json);
    // ── json boundary ─────────────────────────────────────────────────────
    set(ops, "dpa:json:pretty", Json, Json);
    set(ops, "dpa:json:minify", Json, Json);
    set(ops, "dpa:json:get", Json, Utf8);
    set(ops, "dpa:json:to-csv", Json, Utf8);
    set(ops, "dpa:csv:to-json", Utf8, Json);
    // ── hash: raw bytes in, hex digest out ────────────────────────────────
    for h in [
        "adler32",
        "blake2b:256",
        "blake2b:384",
        "blake2b:512",
        "blake2s:256",
        "crc16",
        "crc32",
        "crc32c",
        "fletcher16",
        "fletcher32",
        "fletcher64",
        "fletcher8",
        "keccak",
        "lm-hash",
        "md4",
        "md5",
        "nt-hash",
        "ripemd160",
        "sha1",
        "sha224",
        "sha256",
        "sha384",
        "sha3:256",
        "sha3:512",
        "sha512",
        "shake",
        "sm3",
        "whirlpool",
        "xxhash32",
        "xxhash64",
    ] {
        set(ops, &format!("dpa:{h}"), Raw, Hex);
    }
    // fuzzy hashes emit text; luhn works on digit text.
    set(ops, "dpa:ssdeep", Raw, Utf8);
    set(ops, "dpa:ssdeep:compare", Utf8, Utf8);
    set(ops, "dpa:luhn", Utf8, Utf8);
    // ── compress ──────────────────────────────────────────────────────────
    for c in ["brotli", "bzip2", "deflate", "gzip", "lzma", "zlib"] {
        set(ops, &format!("dpa:{c}:compress"), Raw, Raw);
        set(ops, &format!("dpa:{c}:decompress"), Raw, Raw);
    }
    // ── crypto / cipher: raw in, raw out ──────────────────────────────────
    for c in [
        "aes:encrypt",
        "aes:decrypt",
        "blowfish:encrypt",
        "blowfish:decrypt",
        "chacha20",
        "des:encrypt",
        "des:decrypt",
        "des3:encrypt",
        "des3:decrypt",
        "sm4:encrypt",
        "sm4:decrypt",
        "rc4",
        "tea:encode",
        "tea:decode",
        "xtea:encode",
        "xtea:decode",
        "xxtea:encode",
        "xxtea:decode",
        "xor",
        "xor:bruteforce",
        "hkdf",
        "hmac",
        "pbkdf2",
    ] {
        set(ops, &format!("dpa:{c}"), Raw, Raw);
    }
    // ── analyze / extract: text in, text out ──────────────────────────────
    set(ops, "dpa:entropy", Raw, Utf8);
    set(ops, "dpa:analyze:file:type", Raw, Utf8);
    set(ops, "dpa:analyze:hash", Raw, Utf8);
    for a in [
        "distance:hamming",
        "distance:levenshtein",
        "similarity:jaccard",
        "ic",
        "freq:distribution",
        "extract:dates",
        "extract:domains",
        "extract:emails",
        "extract:hashes",
        "extract:ips",
        "extract:mac",
        "extract:strings",
        "extract:urls",
    ] {
        set(ops, &format!("dpa:{a}"), Utf8, Utf8);
    }
    // ── transform: text transforms ────────────────────────────────────────
    for t in [
        "add:line-numbers",
        "atbash",
        "case:convert",
        "count",
        "dedup",
        "defang:ip",
        "defang:ipv6",
        "defang:url",
        "filter",
        "head",
        "lower",
        "rail-fence:encode",
        "rail-fence:decode",
        "replace",
        "rot13",
        "rot13:bruteforce",
        "rot47",
        "sets:difference",
        "sets:intersection",
        "sets:union",
        "sort",
        "split",
        "substitute",
        "swapcase",
        "tail",
        "trim",
        "unique",
        "upper",
        "vigenere:encode",
        "vigenere:decode",
    ] {
        set(ops, &format!("dpa:{t}"), Utf8, Utf8);
    }
    // ── transform: byte-level ops ─────────────────────────────────────────
    for t in [
        "bitwise:and",
        "bitwise:or",
        "bitwise:rotate-left",
        "bitwise:rotate-right",
        "bitwise:shift-left",
        "bitwise:shift-right",
        "byteswap",
        "drop:bytes",
        "remove:null",
        "not",
        "reverse",
        "take:bytes",
    ] {
        set(ops, &format!("dpa:{t}"), Raw, Raw);
    }
    // ── datetime ──────────────────────────────────────────────────────────
    set(ops, "dpa:datetime:parse", Utf8, Utf8);
    set(ops, "dpa:datetime:delta", Utf8, Utf8);
    set(ops, "dpa:datetime:translate", Utf8, Utf8);
    // ── pubkey: textual key formats ───────────────────────────────────────
    for k in [
        "pem",
        "pem:to:hex",
        "pem:to:jwk",
        "jwk:to:pem",
        "hex:to:pem",
        "pkcs1:to:pkcs8",
        "pkcs8:to:pkcs1",
        "asn1:parse",
        "csr:parse",
        "pubkey:extract",
        "ssh:parse",
        "x509",
        "ecdsa:verify",
        "rsa:verify",
    ] {
        set(ops, &format!("dpa:{k}"), Utf8, Utf8);
    }
    // ── protocol: hex text in, json text out; strips keep raw payloads ────
    for p in ["ethernet", "ipv4", "ipv6", "tcp", "tls", "udp"] {
        set(ops, &format!("dpa:parse:{p}"), Utf8, Utf8);
        set(ops, &format!("dpa:strip:{p}"), Raw, Raw);
    }
    // ── regex ─────────────────────────────────────────────────────────────
    set(ops, "dpa:regex:match", Utf8, Utf8);
    set(ops, "dpa:regex:replace", Utf8, Utf8);
    // `fork` is a control step (engine skips it) and stays Unspecified.
}

/// Process-wide op registry (review fix 3.2/3.4): built-ins plus loaded plugin
/// ops are materialized exactly once, then served by reference. `find_op` uses a
/// name index (O(1)); no per-step reallocation, no per-call `Box::leak`.
struct Registry {
    ops: Vec<Op>,
    index: HashMap<String, usize>,
}

static REGISTRY: std::sync::OnceLock<Registry> = std::sync::OnceLock::new();

fn registry() -> &'static Registry {
    REGISTRY.get_or_init(|| {
        let mut ops = builtin_ops();
        // Plugin ops must never silently shadow a built-in (nor one another):
        // a name collision is skipped with a stderr warning instead of being
        // overwritten into the registry index.
        #[cfg(not(target_arch = "wasm32"))]
        {
            use std::collections::HashSet;
            // Owned names so the sets never borrow `ops` (which is mutated by push).
            let builtin: HashSet<String> = ops.iter().map(|o| o.name.to_string()).collect();
            let mut seen = HashSet::new();
            for op in crate::plugin::plugin_ops_vec() {
                let name = op.name.clone();
                if builtin.contains(&name) || !seen.insert(name) {
                    eprintln!(
                        "{}",
                        crate::i18n::tf("msg.plugin_op_skipped", &[op.name.as_str()])
                    );
                    continue;
                }
                ops.push(op);
            }
        }
        let mut index = HashMap::with_capacity(ops.len());
        for (i, op) in ops.iter().enumerate() {
            index.insert(op.name.clone(), i);
        }
        Registry { ops, index }
    })
}

/// All visible ops: built-ins followed by loaded plugin ops (plugin ABI).
pub fn all_ops() -> &'static [Op] {
    &registry().ops
}

/// Find an op by name: built-ins first, then loaded plugin ops.
///
/// Review fix A-7: accepts both the full namespaced ID (`dpa:aes:encrypt`) and
/// the display-layer short name (`aes:encrypt`, as printed by `dpa list`); a
/// name without the `dpa:` prefix is auto-completed before lookup, so CLI
/// output can be fed straight back into `dpa ops <name>` or flow references.
pub fn find_op(name: &str) -> Option<&'static Op> {
    let reg = registry();
    if let Some(&i) = reg.index.get(name) {
        return Some(&reg.ops[i]);
    }
    if !name.starts_with("dpa:") {
        let full = format!("dpa:{}", name);
        if let Some(&i) = reg.index.get(&full) {
            return Some(&reg.ops[i]);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Review fix A-7: `dpa list` shows `aes:encrypt`-style short names; feeding
    /// them back into `dpa ops <name>` / flow references must resolve to the
    /// same op as the full `dpa:` namespaced id.
    #[test]
    fn find_op_auto_completes_missing_prefix() {
        // Full name still resolves unchanged.
        let full = find_op("dpa:base64:encode").expect("full name resolves");
        assert_eq!(full.name, "dpa:base64:encode");

        // Short name auto-completes to the same op (same registry entry).
        let short = find_op("base64:encode").expect("short name resolves");
        assert_eq!(short.name, full.name);
        assert!(std::ptr::eq(short, full));

        // Plugin-style nested short ids also complete.
        let hex_full = find_op("dpa:hex:encode").expect("full hex op");
        let hex_short = find_op("hex:encode").expect("short hex op");
        assert_eq!(hex_short.name, hex_full.name);

        // Truly unknown names still return None (both short and full forms).
        assert!(find_op("no:such:op").is_none());
        assert!(find_op("dpa:no:such:op").is_none());
    }

    /// §3 statistical dimension: level derivation rule and the explicit
    /// shortcut marker on `random:hex`.
    #[test]
    fn derive_level_rules() {
        // Primary: no `:` sub-path in kind.
        assert_eq!(
            derive_level("dpa:aes:encrypt", "crypto", "aes", "encrypt"),
            OpLevel::Primary
        );
        assert_eq!(
            derive_level("dpa:base64:decode", "codec", "base64", "decode"),
            OpLevel::Primary
        );
        // Two-part id (no family segment) is also Primary.
        assert_eq!(
            derive_level("dpa:md5", "hash", "hash", "md5"),
            OpLevel::Primary
        );

        // Variant: kind contains a `:` sub-path.
        assert_eq!(
            derive_level("dpa:base64:url:decode", "codec", "base64", "url:decode"),
            OpLevel::Variant
        );
        assert_eq!(
            derive_level("dpa:timestamp:to:date", "generate", "timestamp", "to:date"),
            OpLevel::Variant
        );

        // Shortcut: marked explicitly at registration, not by derivation.
        assert_eq!(
            derive_level("dpa:random:hex", "generate", "random", "hex"),
            OpLevel::Primary
        );
        let ops = crate::ops::builtin_ops();
        let rhex = ops.iter().find(|o| o.name == "dpa:random:hex").unwrap();
        assert_eq!(rhex.level, OpLevel::Shortcut);
        assert_eq!(rhex.level.display(), "shortcut");
    }
}
