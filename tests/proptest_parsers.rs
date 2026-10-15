//! N3: property tests for parser surfaces.
//!
//! The v1.0 hardening pass adds proptest coverage over the encoding / parsing
//! ops that consume untrusted bytes: round-trip laws for the codec layer and a
//! strict "never panics on arbitrary input" law for the ASN.1 / X.509 / JSON
//! parsers. cargo-fuzz harnesses are deferred to post-v1.0 CI (see CHANGELOG).

use std::collections::HashMap;

use dpa::ops;
use proptest::prelude::*;

/// Run an op by name with args, panicking on unexpected runtime failure.
fn must_run(name: &str, input: &[u8], args: &[(&str, &str)]) -> Vec<u8> {
    let op = ops::find_op(name).unwrap_or_else(|| panic!("op `{name}` missing from registry"));
    let m: HashMap<String, String> = args
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    (op.run)(input, &m).unwrap_or_else(|e| panic!("`{name}` failed on property input: {e}"))
}

/// Run an op by name; any error is acceptable, panics are not.
fn no_panic(name: &str, input: &[u8], args: &[(&str, &str)]) {
    let op = ops::find_op(name).unwrap_or_else(|| panic!("op `{name}` missing from registry"));
    let m: HashMap<String, String> = args
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let _ = (op.run)(input, &m);
}

proptest! {
    // ---- codec round-trips (encode -> decode == identity) ----

    #[test]
    fn hex_roundtrip(data in any::<Vec<u8>>()) {
        let enc = must_run("dpa:hex:encode", &data, &[]);
        let dec = must_run("dpa:hex:decode", &enc, &[]);
        prop_assert_eq!(dec, data);
    }

    #[test]
    fn base64_roundtrip(data in any::<Vec<u8>>()) {
        let enc = must_run("dpa:base64:encode", &data, &[]);
        let dec = must_run("dpa:base64:decode", &enc, &[]);
        prop_assert_eq!(dec, data);
    }

    #[test]
    fn pem_roundtrip(data in any::<Vec<u8>>()) {
        let enc = must_run("dpa:pem", &data, &[("action", "encode"), ("label", "TEST KEY")]);
        let dec = must_run("dpa:pem", &enc, &[("action", "decode")]);
        prop_assert_eq!(dec, data);
    }

    // ---- parser surfaces: arbitrary bytes must never panic ----

    #[test]
    fn asn1_parse_no_panic(data in any::<Vec<u8>>()) {
        no_panic("dpa:asn1:parse", &data, &[]);
    }

    #[test]
    fn x509_no_panic(data in any::<Vec<u8>>()) {
        no_panic("dpa:x509", &data, &[]);
    }

    #[test]
    fn json_pretty_no_panic(data in any::<Vec<u8>>()) {
        no_panic("dpa:json:pretty", &data, &[]);
    }

    #[test]
    fn pem_to_hex_no_panic(data in any::<Vec<u8>>()) {
        // PEM -> hex and hex -> PEM consume arbitrary input through pem::parse.
        no_panic("dpa:pem:to:hex", &data, &[]);
        let h = must_run("dpa:hex:encode", &data, &[]);
        no_panic("dpa:hex:to:pem", &h, &[("label", "TEST KEY")]);
    }

    #[test]
    fn pkcs_convert_no_panic(data in any::<Vec<u8>>()) {
        no_panic("dpa:pkcs1:to:pkcs8", &data, &[]);
        no_panic("dpa:pkcs8:to:pkcs1", &data, &[]);
    }

    #[test]
    fn regex_no_panic(data in any::<Vec<u8>>()) {
        no_panic("dpa:regex:match", &data, &[]);
    }
}
