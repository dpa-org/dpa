//! Minimal zero-dependency i18n for user-facing strings.
//!
//! All user-facing strings move out of source into FTL-style
//! resource files (`i18n/en/*.ftl`, `i18n/zh-CN/*.ftl`) embedded at compile time
//! via [`include_str!`]. This file keeps only the loading + lookup logic.
//! A new language = a new resource directory + one registration list in
//! [`zh_table`]/[`en_table`] (and the domain coverage test).
//! Op/arg descriptions are keyized - the registry stores structured keys
//! (`op.<name>.desc`, `op.<name>.arg.<argname>`) instead of English text, and
//! both `en` and `zh` tables carry translations for them.
//!
//! Resource format (see `i18n/*/*.ftl`): one `key = value` per line, grouped by
//! file per key family (common / ops-<category>).
//! Only two escapes are honored when decoding a value: `\\` -> `\`, `\n` ->
//! newline (enough for single-line values with embedded line breaks).
//!
//! Two kinds of keys are supported:
//! - Short keys (e.g. `err.read_flow_failed`) used by error messages, CLI help
//!   and list output. Both `en` and `zh` tables provide translations, and the
//!   coverage test fails when the key sets diverge.
//! - Structured op/arg keys (`op.*.desc`, `op.*.arg.*`): the registry stores
//!   these keys; `en` maps them to the English original, `zh` maps them to
//!   Simplified Chinese (falling back to English when untranslated).
//!
//! Language selection (first match wins):
//!   1. `--lang` CLI flag (via [`set_lang`]; main scans argv before clap)
//!   2. `DPA_LANG` env var (`en` / `zh` / `zh-CN`)
//!   3. system `LANG` env var (any `zh*` prefix)
//!   4. default: English

use std::collections::HashMap;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU8, Ordering};

/// Language id: English.
pub const LANG_EN: u8 = 0;
/// Language id: Simplified Chinese.
pub const LANG_ZH: u8 = 1;

static LANG: AtomicU8 = AtomicU8::new(LANG_EN);

/// Set the active language explicitly (e.g. from the `--lang` CLI flag).
pub fn set_lang(lang: u8) {
    LANG.store(lang, Ordering::Relaxed);
}

/// Detect language from environment (`DPA_LANG`, then `LANG`), defaulting to English.
pub fn detect_lang() -> u8 {
    if let Ok(v) = std::env::var("DPA_LANG") {
        let v = v.trim().to_ascii_lowercase();
        // Any `zh*` variant (zh, zh-cn, zh-tw, zh-hk, zh-my, zh_sg, ...) maps to
        // Simplified Chinese. Traditional variants (zh-TW/zh-HK) intentionally
        // fall back to Simplified until a separate Traditional resource exists.
        if v.starts_with("zh") {
            return LANG_ZH;
        }
        if v.starts_with("en") {
            return LANG_EN;
        }
    }
    if let Ok(v) = std::env::var("LANG")
        && v.to_ascii_lowercase().starts_with("zh")
    {
        return LANG_ZH;
    }
    LANG_EN
}

/// Current active language.
pub fn lang() -> u8 {
    LANG.load(Ordering::Relaxed)
}

/// i18n domains: keys are classified by prefix so each domain
/// can be audited independently. Resource files are grouped by the same domains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Domain {
    /// Error/status messages (`err.*` / `msg.*`).
    Errors,
    /// CLI help/about strings (`cli.*`).
    Cli,
    /// Op/arg descriptions (English original used as key).
    OpDescs,
}

/// Classify a lookup key into an i18n domain by prefix.
pub fn domain(key: &str) -> Domain {
    if key.starts_with("cli.") {
        Domain::Cli
    } else if key.starts_with("err.") || key.starts_with("msg.") {
        Domain::Errors
    } else if key.starts_with("op.") {
        Domain::OpDescs
    } else {
        // Fallback (legacy English-original rows kept as translation assets).
        Domain::OpDescs
    }
}

// ---------------------------------------------------------------------------
// Resource loading (include_str! directory merge, zero dependencies)
// ---------------------------------------------------------------------------
// Resources live in `i18n/en/*.ftl` and `i18n/zh-CN/*.ftl`, one file per key
// family (common.ftl for err/msg/cli keys, ops-<category>.ftl for op/arg
// keys). The loader merges all files of the active language into one table.
// Keep the lists below in sync with the directory contents - the CI script
// `scripts/check_i18n_keys.py` asserts the exact same file set.

/// English resource files (embedded at compile time, merged in order).
const EN_FILES: &[&str] = &[
    include_str!("../i18n/en/common.ftl"),
    include_str!("../i18n/en/ops-analyze.ftl"),
    include_str!("../i18n/en/ops-codec.ftl"),
    include_str!("../i18n/en/ops-crypto.ftl"),
    include_str!("../i18n/en/ops-extract.ftl"),
    include_str!("../i18n/en/ops-generate.ftl"),
    include_str!("../i18n/en/ops-hash.ftl"),
    include_str!("../i18n/en/ops-misc.ftl"),
    include_str!("../i18n/en/ops-transform.ftl"),
];

/// Simplified Chinese resource files (embedded at compile time, merged in order).
const ZH_FILES: &[&str] = &[
    include_str!("../i18n/zh-CN/common.ftl"),
    include_str!("../i18n/zh-CN/ops-analyze.ftl"),
    include_str!("../i18n/zh-CN/ops-codec.ftl"),
    include_str!("../i18n/zh-CN/ops-crypto.ftl"),
    include_str!("../i18n/zh-CN/ops-extract.ftl"),
    include_str!("../i18n/zh-CN/ops-generate.ftl"),
    include_str!("../i18n/zh-CN/ops-hash.ftl"),
    include_str!("../i18n/zh-CN/ops-misc.ftl"),
    include_str!("../i18n/zh-CN/ops-transform.ftl"),
];

/// Decode the two escapes used in `.ftl` values: `\\` and `\n`.
fn decode_value(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('\\') => out.push('\\'),
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Merge several resource files into one lookup table.
fn build_table(files: &'static [&'static str]) -> HashMap<&'static str, &'static str> {
    let mut table = HashMap::new();
    for src in files {
        for line in src.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // Separator is the first " = " (space-equals-space): keys such as
            // op descriptions may legitimately contain '=' (e.g. "a <=> b"),
            // so a bare '=' split would truncate them. Values may contain " = ".
            let Some((key, val)) = line.split_once(" = ") else {
                continue;
            };
            let key = key.trim();
            if key.is_empty() {
                continue;
            }
            // Values are decoded once at first use and leaked as 'static strings
            // (one-time process startup cost; keeps t() returning &'static str).
            let decoded = decode_value(val.trim());
            let leaked: &'static str = Box::leak(decoded.into_boxed_str());
            table.insert(key, leaked);
        }
    }
    table
}

/// English lookup table (built lazily, once).
fn en_table() -> &'static HashMap<&'static str, &'static str> {
    static TABLE: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();
    TABLE.get_or_init(|| build_table(EN_FILES))
}

/// Simplified Chinese lookup table (built lazily, once).
fn zh_table() -> &'static HashMap<&'static str, &'static str> {
    static TABLE: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();
    TABLE.get_or_init(|| build_table(ZH_FILES))
}

/// English lookup.
fn en(key: &str) -> Option<&'static str> {
    en_table().get(key).copied()
}

/// Simplified Chinese lookup.
fn zh(key: &str) -> Option<&'static str> {
    zh_table().get(key).copied()
}

// ---------------------------------------------------------------------------
// Public lookup API
// ---------------------------------------------------------------------------

/// Look up a localized string.
///
/// Resolution order:
/// - `zh`: `zh(key)` -> `en(key)` -> key itself
/// - `en`: `en(key)` -> key itself
///
/// Missing keys fall back to the key itself (English original), so op
/// descriptions written in English need no `en` entry.
pub fn t(key: &'static str) -> &'static str {
    if lang() == LANG_ZH {
        if let Some(s) = zh(key) {
            return s;
        }
        if let Some(s) = en(key) {
            return s;
        }
    } else if let Some(s) = en(key) {
        return s;
    }
    key
}

/// Look up a localized string for a runtime-owned key (e.g. op metadata stored
/// as `String` after the registry rework). Falls back to the key itself
/// (English original) when missing, mirroring `t`.
pub fn t_str(key: &str) -> String {
    if lang() == LANG_ZH {
        if let Some(s) = zh(key) {
            return s.to_string();
        }
        if let Some(s) = en(key) {
            return s.to_string();
        }
    } else if let Some(s) = en(key) {
        return s.to_string();
    }
    key.to_string()
}

/// Look up a localized string and fill `{}` placeholders in order.
///
/// If the number of `{}` placeholders does not match the number of arguments,
/// returns an explicit error text instead of silently truncating/leaving
/// placeholders (tf() never swallows i18n argument mismatches).
pub fn tf(key: &'static str, args: &[&str]) -> String {
    let template = t(key);
    let placeholders = template.matches("{}").count();
    if placeholders != args.len() {
        return format!(
            "[i18n:{}] argument mismatch: template has {} placeholder(s), {} arg(s) given",
            key,
            placeholders,
            args.len()
        );
    }
    let mut out = String::with_capacity(template.len() + 16);
    let mut rest = template;
    for arg in args {
        match rest.split_once("{}") {
            Some((head, tail)) => {
                out.push_str(head);
                out.push_str(arg);
                rest = tail;
            }
            None => {
                out.push_str(rest);
                rest = "";
                break;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Localize an OS error without leaking the system-locale message.
/// The error *kind* is mapped to dpa's own en/zh-CN i18n text and the numeric
/// OS code is appended, so error output no longer depends on the machine's
/// locale: a Chinese and an English machine produce the same text
/// (stable for scripts/screenshots).
pub fn os_error(e: &std::io::Error) -> String {
    let code = e
        .raw_os_error()
        .map(|c| c.to_string())
        .unwrap_or_else(|| "?".to_string());
    let key = match e.kind() {
        std::io::ErrorKind::NotFound => "err.os.file_not_found",
        std::io::ErrorKind::PermissionDenied => "err.os.permission_denied",
        std::io::ErrorKind::AlreadyExists => "err.os.already_exists",
        std::io::ErrorKind::InvalidInput => "err.os.invalid_input",
        std::io::ErrorKind::UnexpectedEof => "err.os.unexpected_eof",
        _ => "err.os.other",
    };
    tf(key, &[code.as_str()])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops;

    /// All short keys (errors + cli domains) that must exist in BOTH resource
    /// files. Kept as an explicit regression list in addition to the
    /// full-set assertions below.
    const EN_SHORT_KEYS: &[&str] = &[
        "err.read_flow_failed",
        "err.parse_flow_failed",
        "err.flow_too_large",
        "err.flow_schema_unsupported",
        "err.empty_steps",
        "msg.flow_meta",
        "msg.flow_name",
        "msg.flow_desc",
        "err.thread_pool",
        "err.stdin_no_dir_out",
        "err.write_stdout",
        "err.n_inputs_failed",
        "err.unknown_op",
        "err.step_failed",
        "msg.col_family",
        "msg.col_kind",
        "msg.op_family",
        "msg.op_kind",
        "err.read_input_failed",
        "err.create_outdir_failed",
        "err.create_outfile_failed",
        "err.bad_lang",
        "err.init_stream_failed",
        "err.stream_read_failed",
        "err.stream_failed",
        "err.flush_out_failed",
        "err.write_outfile_failed",
        "err.flush_outfile_failed",
        "err.walk_dir_failed",
        "err.unknown_output_format",
        "err.arg_type",
        "msg.no_match",
        "msg.op_count",
        "err.op_not_found",
        "err.plugin_load_failed",
        "err.plugin_abi_version",
        "err.plugin_no_ops",
        "err.plugin_partial_stream",
        "err.plugin_args_json",
        "err.plugin_args_json_obj",
        "err.plugin_run_failed",
        "err.plugin_stream_failed",
        "err.plugin_stream_init_failed",
        "msg.plugins_loaded",
        "msg.op_name",
        "msg.op_category",
        "msg.flow_id",
        "msg.flow_version",
        "msg.flow_author",
        "msg.flow_license",
        "msg.flow_tags_none",
        "msg.flow_tags",
        "msg.flow_homepage",
        "msg.flow_steps",
        "msg.step_ok",
        "msg.step_missing",
        "msg.flow_exported",
        "msg.flow_imported",
        "err.read_pkg_failed",
        "err.pkg_parse",
        "err.pkg_serialize",
        "err.pkg_format",
        "err.pkg_version",
        "err.pkg_unknown_op",
        "msg.op_description",
        "msg.no_args",
        "msg.args_header",
        "msg.req",
        "msg.opt",
        "err.base64_tail",
        "err.base64_invalid",
        "err.base64_empty_group",
        "err.base64_padding",
        "err.hex_invalid",
        "err.hex_odd",
        "err.hex_bpl_invalid",
        "err.base64_decode",
        "err.base64url_decode",
        "err.base32_decode",
        "err.hex_decode",
        "err.bad_escape",
        "err.binary_odd",
        "err.binary_invalid",
        "err.octal_odd",
        "err.octal_invalid",
        "err.decimal_invalid",
        "err.decimal_range",
        "err.charcode_invalid",
        "err.utf8_invalid",
        "err.base58_alphabet_len",
        "err.base58_dup_char",
        "err.base58_invalid_at",
        "err.base62_alphabet_len",
        "err.base62_dup_char",
        "err.base62_invalid_at",
        "err.base85_alphabet_len",
        "err.base85_dup_char",
        "err.base85_invalid_at",
        "err.qp_wrap_invalid",
        "err.punycode_prefix_missing",
        "err.hex_delimiter_invalid",
        "err.gzip_compress",
        "err.gzip_decompress",
        "err.zlib_compress",
        "err.zlib_decompress",
        "err.compress_failed",
        "err.compressor_stuck",
        "err.gzip_bad_header",
        "err.decompressor_stuck",
        "err.gzip_crc",
        "err.gzip_len",
        "err.gzip_incomplete_trailer",
        "err.gzip_incomplete",
        "err.zlib_incomplete",
        "err.rc4_key_len",
        "err.hmac_sha1_init",
        "err.hmac_sha256_init",
        "err.hmac_sha512_init",
        "err.unknown_algo",
        "err.key_not_hex",
        "err.missing_key",
        "err.missing_nonce",
        "err.empty_key",
        "err.aes_key_len",
        "err.bad_nonce_len",
        "err.bad_chacha_key_len",
        "err.bad_byteswap_width",
        "err.iv_len",
        "err.sm4_key_len",
        "err.des_key_len",
        "err.ciphertext_len",
        "err.unknown_mode",
        "err.unknown_crc",
        "err.unknown_hash_variant",
        "err.invalid_length",
        "err.invalid_number",
        "err.aes_init",
        "err.aes_decrypt",
        "err.sm4_init",
        "err.sm4_decrypt",
        "err.des_init",
        "err.des_decrypt",
        "err.unpad",
        "err.stream_finished",
        "err.bad_padding",
        "err.block_alignment",
        "err.gcm_not_streamable",
        "err.missing_tag",
        "err.missing_gcm_tag",
        "err.gcm_tag_len",
        "err.gcm_tag_mismatch",
        "err.gcm_auth_failed",
        "err.empty_iv",
        "err.des3_key_len",
        "err.blowfish_key_len",
        "err.cipher_init",
        "err.tea_key_len",
        "err.json_parse",
        "err.missing_path",
        "err.path_index",
        "err.path_not_found_idx",
        "err.path_not_found_key",
        "err.system_time",
        "err.bytes_not_num",
        "err.bytes_range",
        "err.unknown_unit",
        "err.number_invalid",
        "err.flow_dup_arg",
        "err.not_unix_time",
        "err.not_filetime",
        "err.missing_pattern",
        "err.regex_compile",
        "err.not_utf8_match",
        "err.missing_replacement",
        "err.not_utf8_replace",
        "err.missing_from",
        "err.missing_to",
        "err.empty_from",
        "err.top_not_num",
        "err.top_range",
        "err.min_not_num",
        "err.min_range",
        "err.bool_invalid",
        "err.missing_sub",
        "err.empty_sub",
        "err.missing_n",
        "err.n_not_num",
        "err.recipe_json_parse",
        "err.recipe_json_top_array",
        "err.recipe_element_object",
        "err.recipe_missing_op",
        "err.recipe_args_array",
        "err.recipe_missing_paren",
        "err.recipe_unclosed_paren",
        "err.recipe_unfinished_escape",
        "err.recipe_arg_utf8",
        "err.recipe_param_utf8",
        "err.url_missing_recipe",
        "err.url_recipe_decode",
        "err.url_input_decode",
        "err.url_input_base64",
        "err.url_percent_incomplete",
        "err.url_percent_invalid",
        "err.url_decode_utf8",
        "cli.about_short",
        "cli.about_long",
        "cli.run_about",
        "cli.run_flow_help",
        "cli.input_help",
        "cli.output_help",
        "cli.output_format_help",
        "cli.recursive_help",
        "cli.jobs_help",
        "cli.batch_separator_help",
        "cli.batch_label_help",
        "cli.list_about",
        "cli.category_help_prefix",
        "cli.op_about",
        "cli.op_name_help",
        "cli.flow_about",
        "cli.flow_manifest_about",
        "cli.flow_export_about",
        "cli.flow_import_about",
        "cli.pkg_help",
        "cli.recipe_about",
        "cli.recipe_convert_about",
        "cli.recipe_input_help",
        "cli.recipe_from_help",
        "cli.recipe_to_help",
        "cli.recipe_lang_help",
        "cli.recipe_from_default",
        "cli.lang_help",
        "cli.plugins_help",
        "cli.max_input_bytes_help",
        "cli.verbose_help",
        "msg.col_category",
        "msg.col_op",
        "msg.col_desc",
        "err.plugin_bad_args",
        "err.plugin_hash_missing",
        "err.plugin_hash_mismatch",
        "msg.plugin_hash_generated",
        "err.input_too_large",
    ];

    #[test]
    fn domain_classification() {
        assert_eq!(domain("err.foo"), Domain::Errors);
        assert_eq!(domain("msg.bar"), Domain::Errors);
        assert_eq!(domain("cli.help"), Domain::Cli);
        assert_eq!(domain("op.base64.encode.desc"), Domain::OpDescs);
        assert_eq!(domain("op.base64.encode.arg.alphabet"), Domain::OpDescs);
    }

    /// Resource coverage: the zh-CN file must carry EXACTLY the same
    /// short-key set (err./msg./cli.) as en.ftl - no missing keys, no extras -
    /// otherwise a missing translation would silently fall back to English.
    #[test]
    fn zh_short_key_set_matches_en() {
        let en_keys: Vec<&str> = en_table()
            .keys()
            .copied()
            .filter(|k| matches!(domain(k), Domain::Errors | Domain::Cli))
            .collect();
        let zh_keys: Vec<&str> = zh_table()
            .keys()
            .copied()
            .filter(|k| matches!(domain(k), Domain::Errors | Domain::Cli))
            .collect();
        let mut missing: Vec<&str> = en_keys
            .iter()
            .copied()
            .filter(|k| !zh_table().contains_key(*k))
            .collect();
        missing.sort_unstable();
        assert!(
            missing.is_empty(),
            "zh-CN.ftl misses en.ftl short keys: {:?}",
            missing
        );
        let mut extra: Vec<&str> = zh_keys
            .iter()
            .copied()
            .filter(|k| !en_table().contains_key(*k))
            .collect();
        extra.sort_unstable();
        assert!(
            extra.is_empty(),
            "zh-CN.ftl has short keys absent from en.ftl: {:?}",
            extra
        );
        // Explicit regression list must be a subset of the real resource keys.
        let missing_regression: Vec<&str> = EN_SHORT_KEYS
            .iter()
            .copied()
            .filter(|k| !en_table().contains_key(*k) || !zh_table().contains_key(*k))
            .collect();
        assert!(
            missing_regression.is_empty(),
            "EN_SHORT_KEYS regression list misses resource keys: {:?}",
            missing_regression
        );
    }

    /// Resource coverage: every op/arg description registered by ops::all_ops()
    /// must have a zh translation in zh-CN.ftl (no silent English fallback for
    /// a newly added op).
    #[test]
    fn zh_covers_all_op_descriptions() {
        let mut missing = Vec::new();
        for op in ops::all_ops() {
            if zh_table().get(op.description.as_str()).is_none() {
                missing.push(format!("op desc: {}", op.description));
            }
            for a in op.args {
                if zh_table().get(a.description).is_none() {
                    missing.push(format!("arg desc: {}", a.description));
                }
            }
        }
        assert!(
            missing.is_empty(),
            "zh-CN.ftl misses op/arg descriptions: {:?}",
            missing
        );
    }

    #[test]
    fn op_description_uniqueness() {
        // Identical op descriptions would make it impossible to
        // tell which translation context a key belongs to, so they must stay unique.
        let mut seen: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        for op in ops::all_ops() {
            *seen.entry(&op.description).or_insert(0) += 1;
        }
        let dup: Vec<&&str> = seen
            .iter()
            .filter(|(_, n)| **n > 1)
            .map(|(k, _)| k)
            .collect();
        assert!(dup.is_empty(), "duplicate op descriptions: {:?}", dup);
    }

    #[test]
    fn tf_reports_arg_mismatch() {
        // Missing args must surface an explicit i18n error text, not a silent truncation.
        let short = tf("err.step_failed", &["1"]);
        assert!(short.contains("argument mismatch"), "got: {}", short);
        assert!(short.contains("err.step_failed"), "got: {}", short);
        // Matching args still format normally.
        let ok = tf("err.step_failed", &["1", "dpa:base64:decode", "boom"]);
        assert!(!ok.contains("argument mismatch"), "got: {}", ok);
        assert_eq!(ok, "Step 1 (dpa:base64:decode) failed: boom");
        // Excess args also mismatch.
        let extra = tf("err.step_failed", &["1", "op", "boom", "surplus"]);
        assert!(extra.contains("argument mismatch"), "got: {}", extra);
    }
}
