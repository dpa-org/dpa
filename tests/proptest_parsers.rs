//! Property tests for parser surfaces.
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
    fn pkcs_convert_no_panic(data in any::<Vec<u8>>()) {
        no_panic("dpa:pkcs1:to:pkcs8", &data, &[]);
        no_panic("dpa:pkcs8:to:pkcs1", &data, &[]);
    }

    #[test]
    fn regex_no_panic(data in any::<Vec<u8>>()) {
        no_panic("dpa:regex:match", &data, &[]);
    }

    // ---- More codec round-trips ----

    #[test]
    fn base32_roundtrip(data in any::<Vec<u8>>()) {
        let enc = must_run("dpa:base32:encode", &data, &[]);
        let dec = must_run("dpa:base32:decode", &enc, &[]);
        prop_assert_eq!(dec, data);
    }

    #[test]
    fn base45_roundtrip(data in any::<Vec<u8>>()) {
        let enc = must_run("dpa:base45:encode", &data, &[]);
        let dec = must_run("dpa:base45:decode", &enc, &[]);
        prop_assert_eq!(dec, data);
    }

    #[test]
    fn base62_roundtrip(data in any::<Vec<u8>>()) {
        let enc = must_run("dpa:base62:encode", &data, &[]);
        let dec = must_run("dpa:base62:decode", &enc, &[]);
        prop_assert_eq!(dec, data);
    }

    #[test]
    fn base85_roundtrip(data in any::<Vec<u8>>()) {
        let enc = must_run("dpa:base85:encode", &data, &[]);
        let dec = must_run("dpa:base85:decode", &enc, &[]);
        prop_assert_eq!(dec, data);
    }

    #[test]
    fn base64url_roundtrip(data in any::<Vec<u8>>()) {
        let enc = must_run("dpa:base64:url:encode", &data, &[]);
        let dec = must_run("dpa:base64:url:decode", &enc, &[]);
        prop_assert_eq!(dec, data);
    }

    #[test]
    fn qp_roundtrip(data in any::<Vec<u8>>()) {
        let enc = must_run("dpa:qp:encode", &data, &[]);
        let dec = must_run("dpa:qp:decode", &enc, &[]);
        prop_assert_eq!(dec, data);
    }

    #[test]
    fn url_roundtrip(data in any::<Vec<u8>>()) {
        let enc = must_run("dpa:url:encode", &data, &[]);
        let dec = must_run("dpa:url:decode", &enc, &[]);
        prop_assert_eq!(dec, data);
    }

    // ---- Crypto invariants ----

    #[test]
    fn xor_is_involution(data in any::<Vec<u8>>()) {
        let once = must_run("dpa:xor", &data, &[("key", "0xdeadbeef")]);
        let twice = must_run("dpa:xor", &once, &[("key", "0xdeadbeef")]);
        prop_assert_eq!(twice, data);
    }

    #[test]
    fn aes_ctr_roundtrip(data in any::<Vec<u8>>()) {
        let ct = must_run(
            "dpa:aes:encrypt",
            &data,
            &[
                ("key", "0x00112233445566778899aabbccddeeff"),
                ("mode", "ctr"),
                ("iv", "0x00000000000000000000000000000000"),
            ],
        );
        let pt = must_run(
            "dpa:aes:decrypt",
            &ct,
            &[
                ("key", "0x00112233445566778899aabbccddeeff"),
                ("mode", "ctr"),
                ("iv", "0x00000000000000000000000000000000"),
            ],
        );
        prop_assert_eq!(pt, data);
    }

    #[test]
    fn chacha20_roundtrip(data in any::<Vec<u8>>()) {
        let ct = must_run(
            "dpa:chacha20",
            &data,
            &[
                ("key", "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
                ("nonce", "0x000000000000000000000000"),
            ],
        );
        let pt = must_run(
            "dpa:chacha20:decrypt",
            &ct,
            &[
                ("key", "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
                ("nonce", "0x000000000000000000000000"),
            ],
        );
        prop_assert_eq!(pt, data);
    }

    #[test]
    fn rc4_roundtrip(data in any::<Vec<u8>>()) {
        let ct = must_run("dpa:rc4", &data, &[("key", "0x0102030405")]);
        let pt = must_run("dpa:rc4:decrypt", &ct, &[("key", "0x0102030405")]);
        prop_assert_eq!(pt, data);
    }

    #[test]
    fn hash_length_invariants(data in any::<Vec<u8>>()) {
        prop_assert_eq!(must_run("dpa:sha256", &data, &[]).len(), 32);
        prop_assert_eq!(must_run("dpa:sha1", &data, &[]).len(), 20);
        prop_assert_eq!(must_run("dpa:md5", &data, &[]).len(), 16);
        prop_assert_eq!(must_run("dpa:sha512", &data, &[]).len(), 64);
    }

    #[test]
    fn hmac_is_deterministic(data in any::<Vec<u8>>()) {
        let a = must_run("dpa:hmac", &data, &[("key", "0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")]);
        let b = must_run("dpa:hmac", &data, &[("key", "0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")]);
        prop_assert_eq!(a, b);
    }
}

// ---- Fixed known vectors (NIST / RFC 4231) ----

fn hex_vec(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut hi = None;
    for c in s.bytes() {
        let v = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => continue,
        };
        match hi.take() {
            None => hi = Some(v),
            Some(h) => out.push((h << 4) | v),
        }
    }
    out
}

#[test]
fn sha256_known_vectors() {
    // FIPS 180-4 test vectors.
    let empty = must_run("dpa:sha256", b"", &[]);
    assert_eq!(
        empty,
        hex_vec("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    );
    let abc = must_run("dpa:sha256", b"abc", &[]);
    assert_eq!(
        abc,
        hex_vec("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
}

#[test]
fn hmac_sha256_known_vector() {
    // RFC 4231 test case 1: key = 0x0b * 20, data = "Hi There".
    let mac = must_run(
        "dpa:hmac",
        b"Hi There",
        &[("key", "0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")],
    );
    assert_eq!(
        mac,
        hex_vec("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
    );
}

#[test]
fn aes_ctr_known_vector() {
    // NIST SP 800-38A F.5.1 CTR-AES128.Encrypt: key = 2b7e151628aed2a6abf7158809cf4f3c,
    // initial counter = f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff, plaintext = 6bc1bee2... first block.
    let pt = hex_vec("6bc1bee22e409f96e93d7e117393172a");
    let ct = must_run(
        "dpa:aes:encrypt",
        &pt,
        &[
            ("key", "0x2b7e151628aed2a6abf7158809cf4f3c"),
            ("mode", "ctr"),
            ("iv", "0xf0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
        ],
    );
    assert_eq!(ct, hex_vec("874d6191b620e3261bef6864990db6ce"));
}
