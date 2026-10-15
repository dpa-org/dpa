//! API contract tests (review P3 §3-P9 / G8).
//!
//! dpa exposes a library surface (`lib.rs`) shared by the CLI, the WASM crate
//! and the Python binding. These tests pin the *public contract* so a refactor
//! that silently renames a public symbol, drops an op from the registry, or
//! changes an ArgSpec shape fails loudly in CI instead of at runtime.
//!
//! They are deliberately conservative: they assert existence and shape, not
//! exact op counts, so adding ops never breaks the contract suite.

use dpa::engine;
use dpa::flow::{Flow, FlowMeta, OutputFormat};
use dpa::ops::{self, ArgFormat, ArgSpec, OpLevel};
use dpa::recipe::{self, Format};

#[test]
fn engine_public_surface_is_stable() {
    // Compile-level pin: these must exist with the same shapes.
    let _: fn(&Flow, &[u8], OutputFormat) -> anyhow::Result<Vec<u8>> = engine::process_bytes;
    let _: fn(&Flow, &[u8], OutputFormat) -> anyhow::Result<Vec<u8>> = engine::process_bytes_stream;
    let _: fn(usize) = engine::set_max_input_bytes;
    let _: fn() -> usize = engine::max_input_bytes;
    let _: fn(bool) = engine::set_verbose;
    let _: fn() -> bool = engine::is_verbose;
}

#[test]
fn registry_contract_is_stable() {
    let all = ops::all_ops();
    // Registry must never silently shrink (1.0 ships 218 op entries).
    assert!(all.len() > 100, "registry dropped ops: {}", all.len());

    // Namespaced names and a non-empty category for every entry.
    for op in all {
        assert!(op.name.starts_with("dpa:"), "bad name {}", op.name);
        assert!(!op.category.is_empty(), "empty category for {}", op.name);
    }

    // Well-known ops must stay discoverable by name.
    for known in ["dpa:base64:encode", "dpa:sha256", "dpa:xor", "dpa:upper"] {
        assert!(
            ops::find_op(known).is_some(),
            "known op missing from registry: {known}"
        );
    }
}

#[test]
fn argspec_contract_is_stable() {
    // ArgSpec construction + field readability is part of the public contract.
    let a = ArgSpec::new("input", true, "input text");
    assert_eq!(a.name, "input");
    assert!(a.required);
    assert_eq!(a.format, ArgFormat::Utf8);

    let b = ArgSpec::with_format("hex", false, "hex string", ArgFormat::Hex);
    assert_eq!(b.format, ArgFormat::Hex);

    let d = ArgSpec::default();
    assert_eq!(d.name, "");
    assert!(!d.required);
    assert_eq!(d.format, ArgFormat::Utf8);
}

#[test]
fn op_shape_contract_is_stable() {
    // Op metadata fields (family / kind / level) feed statistics and the
    // type-check; they must stay readable on every registered op.
    let sample = ops::find_op("dpa:base64:encode").expect("base64 encode op");
    assert!(!sample.family.is_empty());
    assert!(!sample.kind.is_empty());
    assert!(matches!(
        sample.level,
        OpLevel::Primary | OpLevel::Variant | OpLevel::Shortcut
    ));

    let _ = &sample.run;
}

#[test]
fn recipe_format_contract_is_stable() {
    let _: fn(&str) -> Option<Format> = Format::parse;
    let _: fn(&str) -> Format = recipe::detect_format;
    // Auto-detection (review P3 §3-N) must tolerate BOM / leading whitespace.
    assert_eq!(
        recipe::detect_format("\u{feff}https://example.com/x.txt"),
        Format::Url
    );
    assert_eq!(recipe::detect_format("  [\n{\"a\":1}\n]\n"), Format::Json);
}

#[test]
fn i18n_contract_is_stable() {
    // Runtime pin: language switching and P2/P3 keys resolve in both languages.
    for lang in [dpa::i18n::LANG_EN, dpa::i18n::LANG_ZH] {
        dpa::i18n::set_lang(lang);
        assert!(!dpa::i18n::t("cli.verbose_help").is_empty());
        assert!(!dpa::i18n::t("err.input_too_large").is_empty());
        assert!(!dpa::i18n::t("cli.max_input_bytes_help").is_empty());
        assert!(!dpa::i18n::t("err.plugin_bad_args").is_empty());
        let s = dpa::i18n::tf("cli.verbose_help", &[]);
        assert!(!s.is_empty());
    }
}

#[test]
fn flow_struct_contract_is_stable() {
    // Flow / FlowMeta stay publicly constructible (size + default pin shape).
    let _ = FlowMeta::default();
    let _ = std::mem::size_of::<Flow>();
    let _ = std::mem::size_of::<OutputFormat>();
}
