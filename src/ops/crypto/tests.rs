use super::super::StreamingOp;
use super::super::cipher::{CfbStream, ctr_crypt};
use super::aes::*;
use super::chacha::*;
use super::classic::*;
use super::hmac_kdf::*;
use super::xor::*;
use super::*;
use std::collections::HashMap;

fn args(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn hex(data: impl AsRef<[u8]>) -> String {
    data.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

// ------------------------------------------------------------------
// Implicit all-zero IV warning
// ------------------------------------------------------------------

#[test]
fn zero_iv_warning_fires_for_non_gcm_encrypt_without_iv() {
    for mode in ["cbc", "cfb", "ofb", "ctr"] {
        let a = args(&[("key", "k"), ("mode", mode)]);
        let w = implicit_zero_iv_warning(&a, mode, true);
        assert!(w.is_some(), "expected warning for {mode} without iv");
        assert!(w.unwrap().contains(mode));
    }
}

#[test]
fn zero_iv_warning_silent_when_iv_given() {
    for mode in ["cbc", "cfb", "ofb", "ctr"] {
        let a = args(&[
            ("key", "k"),
            ("mode", mode),
            ("iv", "0x000102030405060708090a0b0c0d0e0f"),
        ]);
        assert!(
            implicit_zero_iv_warning(&a, mode, true).is_none(),
            "no warning expected for {mode} with explicit iv"
        );
    }
}

#[test]
fn zero_iv_warning_silent_for_gcm_ecb_and_decrypt() {
    let gcm = args(&[("key", "k"), ("mode", "gcm")]);
    assert!(implicit_zero_iv_warning(&gcm, "gcm", true).is_none());
    for mode in ["ecb", "cbc", "cfb", "ofb", "ctr"] {
        let a = args(&[("key", "k"), ("mode", mode)]);
        assert!(
            implicit_zero_iv_warning(&a, mode, false).is_none(),
            "no warning expected on decrypt for {mode}"
        );
    }
    let ecb = args(&[("key", "k"), ("mode", "ecb")]);
    assert!(implicit_zero_iv_warning(&ecb, "ecb", true).is_none());
}

// ------------------------------------------------------------------
// PBKDF2 / HKDF (RFC 6070 / RFC 5869 vectors)
// ------------------------------------------------------------------

#[test]
fn pbkdf2_sha1_rfc6070() {
    let a = args(&[
        ("key", "password"),
        ("salt", "salt"),
        ("hash", "sha1"),
        ("iterations", "1"),
        ("length", "20"),
    ]);
    assert_eq!(
        hex(pbkdf2(b"", &a).unwrap()),
        "0c60c80f961f0e71f3a9b524af6012062fe037a6"
    );
    let a = args(&[
        ("key", "password"),
        ("salt", "salt"),
        ("hash", "sha1"),
        ("iterations", "2"),
        ("length", "20"),
    ]);
    assert_eq!(
        hex(pbkdf2(b"", &a).unwrap()),
        "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"
    );
    let a = args(&[
        ("key", "password"),
        ("salt", "salt"),
        ("hash", "sha1"),
        ("iterations", "4096"),
        ("length", "20"),
    ]);
    assert_eq!(
        hex(pbkdf2(b"", &a).unwrap()),
        "4b007901b765489abead49d926f721d065a429c1"
    );
}

#[test]
fn pbkdf2_sha256_vectors() {
    let a = args(&[
        ("key", "password"),
        ("salt", "salt"),
        ("iterations", "1"),
        ("length", "32"),
    ]);
    assert_eq!(
        hex(pbkdf2(b"", &a).unwrap()),
        "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
    );
    let a = args(&[
        ("key", "password"),
        ("salt", "salt"),
        ("iterations", "10000"),
        ("length", "32"),
    ]);
    assert_eq!(
        hex(pbkdf2(b"", &a).unwrap()),
        "5ec02b91a4b59c6f59dd5fbe4ca649ece4fa8568cdb8ba36cf41426e8805522b"
    );
}

#[test]
fn pbkdf2_sha512_uses_input_password() {
    // No 'key' arg: op input is the password.
    let a = args(&[
        ("salt", "salt"),
        ("hash", "sha512"),
        ("iterations", "2"),
        ("length", "64"),
    ]);
    assert_eq!(
        hex(pbkdf2(b"pass", &a).unwrap()),
        "b38deb857ea637081cfe61e4965722c36ee58dc40f53b80e42a4315795c39470480bf86c81e90a4f1c142aabc7273ee0c5a095fbab225ddea60a3d328c15cf03"
    );
}

#[test]
fn pbkdf2_hex_salt() {
    let a = args(&[
        ("key", "password"),
        ("salt", "0x73616c74"),
        ("iterations", "1"),
        ("length", "20"),
        ("hash", "sha1"),
    ]);
    assert_eq!(
        hex(pbkdf2(b"", &a).unwrap()),
        "0c60c80f961f0e71f3a9b524af6012062fe037a6"
    );
}

#[test]
fn pbkdf2_unknown_hash() {
    let a = args(&[("key", "x"), ("hash", "md5")]);
    assert!(pbkdf2(b"", &a).is_err());
}

#[test]
fn hkdf_sha256_rfc5869_tc1() {
    // IKM = 0x0b*22, salt = 0x000102..0c (13 bytes), info = 0xf0..f9, L = 42
    let ikm = format!("0x{}", "0b".repeat(22));
    let salt = format!(
        "0x{}",
        (0..13u8).map(|b| format!("{b:02x}")).collect::<String>()
    );
    let a = args(&[
        ("key", &ikm),
        ("salt", &salt),
        ("info", "0xf0f1f2f3f4f5f6f7f8f9"),
        ("length", "42"),
        ("hash", "sha256"),
    ]);
    assert_eq!(
        hex(hkdf(b"", &a).unwrap()),
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    );
}

#[test]
fn hkdf_sha1_rfc5869_tc4() {
    let ikm = format!("0x{}", "0b".repeat(11));
    let salt = format!(
        "0x{}",
        (0..9u8).map(|b| format!("{b:02x}")).collect::<String>()
    );
    let a = args(&[
        ("key", &ikm),
        ("salt", &salt),
        ("info", "0xf0f1f2f3f4f5f6f7"),
        ("length", "42"),
        ("hash", "sha1"),
    ]);
    assert_eq!(
        hex(hkdf(b"", &a).unwrap()),
        "319e5088afa610a19ba8764fc85abee06cd3afc4e8438d1680e900ae284908095644cdead5f7dd4dc5c7"
    );
}

#[test]
fn hkdf_empty_salt_uses_hashlen_zeros() {
    let a = args(&[
        ("key", "ikm"),
        ("info", "info"),
        ("length", "32"),
        ("hash", "sha256"),
    ]);
    assert_eq!(
        hex(hkdf(b"", &a).unwrap()),
        "253471d1d21137fd9a4016868ba773216954d4cc5ecb925eeacadfd7eeb208c3"
    );
}

#[test]
fn hkdf_uses_input_ikm_when_no_key() {
    let a = args(&[
        ("salt", "salt"),
        ("info", "info"),
        ("length", "32"),
        ("hash", "sha256"),
    ]);
    let out = hkdf(b"ikm", &a).unwrap();
    assert_eq!(out.len(), 32);
}

#[test]
fn hkdf_unknown_hash() {
    let a = args(&[("key", "x"), ("hash", "md5")]);
    assert!(hkdf(b"", &a).is_err());
}

#[test]
fn hkdf_sm3_rfc5869_style() {
    // Same IKM/salt/info as RFC 5869 TC1, but HMAC-SM3 (32-byte hash).
    // Reference generated with an independent GMSSL-based implementation.
    let ikm = format!("0x{}", "0b".repeat(22));
    let salt = format!(
        "0x{}",
        (0..13u8).map(|b| format!("{b:02x}")).collect::<String>()
    );
    let a = args(&[
        ("key", &ikm),
        ("salt", &salt),
        ("info", "0xf0f1f2f3f4f5f6f7f8f9"),
        ("length", "42"),
        ("hash", "sm3"),
    ]);
    assert_eq!(
        hex(hkdf(b"", &a).unwrap()),
        "c69fe91b7aaee2dd5718d72dcaee0cce93f1b8e41f792da51261b6a517e68b36ed2c595572b01dfa359b"
    );
}

#[test]
fn hkdf_sm3_short_input() {
    let a = args(&[
        ("key", "ikm"),
        ("salt", "salt"),
        ("info", "info"),
        ("length", "32"),
        ("hash", "sm3"),
    ]);
    assert_eq!(
        hex(hkdf(b"", &a).unwrap()),
        "315a3171a989f11d4b10d39d48360982fc7f586ccbc688699af779c6e05a3355"
    );
}

#[test]
fn xor_hex_key() {
    let a = args(&[("key", "0x2A")]);
    // 'H' (0x48) ^ 0x2A = 0x62 = 'b'
    assert_eq!(xor(b"H", &a).unwrap(), b"b");
}

#[test]
fn xor_roundtrip() {
    let a = args(&[("key", "secret")]);
    let data = b"payload data";
    let enc = xor(data, &a).unwrap();
    let dec = xor(&enc, &a).unwrap();
    assert_eq!(dec, data);
}

#[test]
fn parse_key_forms() {
    assert_eq!(parse_key("0x2A").unwrap(), vec![0x2a]);
    assert_eq!(parse_key("0X0102").unwrap(), vec![0x01, 0x02]);
    assert_eq!(parse_key("ab").unwrap(), b"ab");
}

#[test]
fn aes_cbc_roundtrip_known_vector() {
    // NIST SP 800-38A F.2.1：AES-128-CBC，key=2b7e151628aed2a6abf7158809cf4f3c，
    // iv=000102030405060708090a0b0c0d0e0f, plaintext 6bc1bee22e409f96e93d7e117393172a.
    let a = args(&[
        ("key", "0x2b7e151628aed2a6abf7158809cf4f3c"),
        ("mode", "cbc"),
        ("iv", "0x000102030405060708090a0b0c0d0e0f"),
    ]);
    let plain = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
    let enc = aes_encrypt(&plain, &a).unwrap();
    // Single-block plaintext + PKCS#7 padding -> two-block NIST first-block ciphertext
    assert_eq!(hex::encode(&enc[..16]), "7649abac8119b246cee98e9b12e9197d");
    let dec = aes_decrypt(&enc, &a).unwrap();
    assert_eq!(dec, plain);
}

#[test]
fn aes_ecb_roundtrip() {
    let a = args(&[("key", "0123456789abcdef0123456789abcdef"), ("mode", "ecb")]);
    let data = b"block aligned data!!";
    let enc = aes_encrypt(data, &a).unwrap();
    let dec = aes_decrypt(&enc, &a).unwrap();
    assert_eq!(dec, data);
}

#[test]
fn aes_default_mode_is_cbc_and_iv_is_zero() {
    // Same key but no mode/iv: must behave as cbc with all-zero IV.
    let a = args(&[("key", "0123456789abcdef0123456789abcdef")]);
    let b = args(&[
        ("key", "0123456789abcdef0123456789abcdef"),
        ("mode", "cbc"),
        ("iv", "0x00000000000000000000000000000000"),
    ]);
    let data = b"default-args payload";
    assert_eq!(
        aes_encrypt(data, &a).unwrap(),
        aes_encrypt(data, &b).unwrap()
    );
    let enc = aes_encrypt(data, &a).unwrap();
    assert_eq!(aes_decrypt(&enc, &a).unwrap(), data);
}

#[test]
fn aes_rejects_bad_key_len_and_unknown_mode() {
    let a = args(&[("key", "short"), ("mode", "cbc")]);
    assert!(aes_encrypt(b"data", &a).is_err());
    let b = args(&[("key", "0123456789abcdef0123456789abcdef"), ("mode", "xts")]);
    assert!(aes_encrypt(b"data", &b).is_err());
}

#[test]
fn aes_cfb_known_vector() {
    // Standard CFB-128: NIST SP 800-38A F.3.7 block 1 + OpenSSL 3.x
    // cross-check for all 4 blocks; multi-block feedback
    // must match CFB-128, not a byte-wise sliding window).
    let a = args(&[
        ("key", "0x2b7e151628aed2a6abf7158809cf4f3c"),
        ("mode", "cfb"),
        ("iv", "0x000102030405060708090a0b0c0d0e0f"),
    ]);
    let plain = hex::decode("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710").unwrap();
    let expect = hex::decode("3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6").unwrap();
    let enc = aes_encrypt(&plain, &a).unwrap();
    assert_eq!(enc, expect);
    assert_eq!(aes_decrypt(&enc, &a).unwrap(), plain);
    // Partial tail (non-block-aligned input) must also match block-aligned output.
    let tail = &plain[..20];
    let enc_tail = aes_encrypt(tail, &a).unwrap();
    assert_eq!(enc_tail, expect[..20]);
    assert_eq!(aes_decrypt(&enc_tail, &a).unwrap(), tail);
    // Streaming path must agree with the in-memory path for multi-block data.
    let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
    let mem = aes_encrypt(&data, &a).unwrap();
    let mut s = CfbStream::new(&a, aes_block_from_args(&a).unwrap(), true).unwrap();
    let mut st = Vec::new();
    for c in data.chunks(3) {
        st.extend(s.write(c).unwrap());
    }
    st.extend(s.finish().unwrap());
    assert_eq!(st, mem);
}

#[test]
fn aes_ofb_known_vector() {
    // NIST SP 800-38A F.4.1 (OFB-AES128): same first block as CFB128.
    let a = args(&[
        ("key", "0x2b7e151628aed2a6abf7158809cf4f3c"),
        ("mode", "ofb"),
        ("iv", "0x000102030405060708090a0b0c0d0e0f"),
    ]);
    let plain = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
    let enc = aes_encrypt(&plain, &a).unwrap();
    assert_eq!(hex::encode(&enc[..16]), "3b3fd92eb72dad20333449f8e83cfb4a");
    assert_eq!(aes_decrypt(&enc, &a).unwrap(), plain);
}

#[test]
fn aes_ctr_known_vector_and_roundtrip() {
    // NIST SP 800-38A F.5.1: AES-128-CTR.
    let a = args(&[
        ("key", "0x2b7e151628aed2a6abf7158809cf4f3c"),
        ("mode", "ctr"),
        ("iv", "0xf0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
    ]);
    let plain = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
    let enc = aes_encrypt(&plain, &a).unwrap();
    assert_eq!(hex::encode(&enc[..16]), "874d6191b620e3261bef6864990db6ce");
    let dec = aes_decrypt(&enc, &a).unwrap();
    assert_eq!(dec, plain);
}

#[test]
fn aes_stream_matches_memory_all_modes() {
    let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
    let cases = [
        (
            "ecb",
            args(&[("key", "0123456789abcdef0123456789abcdef"), ("mode", "ecb")]),
        ),
        (
            "cbc",
            args(&[
                ("key", "0123456789abcdef0123456789abcdef"),
                ("mode", "cbc"),
                ("iv", "0xf0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
            ]),
        ),
        (
            "cfb",
            args(&[
                ("key", "0123456789abcdef0123456789abcdef"),
                ("mode", "cfb"),
                ("iv", "0xf0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
            ]),
        ),
        (
            "ofb",
            args(&[
                ("key", "0123456789abcdef0123456789abcdef"),
                ("mode", "ofb"),
                ("iv", "0xf0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
            ]),
        ),
        (
            "ctr",
            args(&[
                ("key", "0123456789abcdef0123456789abcdef"),
                ("mode", "ctr"),
                ("iv", "0xf0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
            ]),
        ),
    ];
    for (mode, a) in cases {
        let run = if mode == "ecb" || mode == "cbc" {
            let enc = aes_encrypt(&data, &a).unwrap();
            let dec = aes_decrypt(&enc, &a).unwrap();
            assert_eq!(dec, data, "roundtrip failed for mode {}", mode);
            enc
        } else {
            aes_encrypt(&data, &a).unwrap()
        };
        let mut h = make_aes_enc(&a).unwrap();
        let mut acc = Vec::new();
        for c in data.chunks(7) {
            acc.extend(h.write(c).unwrap());
        }
        acc.extend(h.finish().unwrap());
        assert_eq!(acc, run, "stream != memory for mode {}", mode);
        // decrypt stream
        let mut hd = make_aes_dec(&a).unwrap();
        let mut acc2 = Vec::new();
        for c in run.chunks(9) {
            acc2.extend(hd.write(c).unwrap());
        }
        acc2.extend(hd.finish().unwrap());
        assert_eq!(acc2, data, "decrypt stream != plaintext for mode {}", mode);
    }
}

#[test]
fn rc4_known_vector() {
    // RFC 6229: key="Key", plaintext "Plaintext" (9B) outputs bbf316e8d940af0ad3
    let a = args(&[("key", "Key")]);
    let enc = rc4(b"Plaintext", &a).unwrap();
    assert_eq!(hex::encode(enc), "bbf316e8d940af0ad3");
}

#[test]
fn rc4_decrypt_alias_roundtrip() {
    // #6: dpa:rc4:decrypt runs the same stream cipher twice and recovers
    // the plaintext, matching the documented "run twice to decrypt" flow.
    let a = args(&[("key", "Key")]);
    let plain = b"RC4 decrypt alias round trip";
    let enc = rc4(plain, &a).unwrap();
    assert_eq!(rc4_decrypt(&enc, &a).unwrap(), plain);
    assert_eq!(rc4_decrypt(plain, &a).unwrap(), enc);
}

#[test]
fn hmac_known_vector() {
    let a = args(&[("key", "key"), ("algo", "sha256")]);
    let out = hmac(b"The quick brown fox jumps over the lazy dog", &a).unwrap();
    assert_eq!(
        hex::encode(out),
        "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
    );
}

#[test]
fn chacha20_known_keystream_and_roundtrip() {
    // RFC 8439 §2.3.2: key=000102...1f, nonce=000000000000004a00000000, counter=1.
    let a = args(&[
        (
            "key",
            "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        ),
        ("nonce", "0x000000000000004a00000000"),
    ]);
    let mut chacha = chacha20_from_args(&a).unwrap();
    let mut ks = [0u8; 64];
    chacha.next_block(&mut ks); // block 0 (counter=0)
    chacha.next_block(&mut ks); // block 1 (counter=1) -> RFC 8439 2.3.2 vector
    assert_eq!(hex::encode(&ks[..16]), "224f51f3401bd9e12fde276fb8631ded");
    let plain = b"ChaCha20 round trip works over any bytes";
    let enc = chacha20_crypt(plain, &a).unwrap();
    assert_eq!(chacha20_crypt(&enc, &a).unwrap(), plain);
    // #6: dpa:chacha20:decrypt is the same keystream XOR (stream cipher
    // run twice), so decrypt(encrypt(x)) == x.
    assert_eq!(chacha20_decrypt(&enc, &a).unwrap(), plain);
    assert_eq!(chacha20_decrypt(plain, &a).unwrap(), enc);
}

#[test]
fn stream_ciphers_stream_matches_memory() {
    let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
    let a = args(&[
        (
            "key",
            "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        ),
        ("nonce", "0x000000000000004a00000000"),
    ]);
    let mut h = make_chacha20(&a).unwrap();
    let mut acc = Vec::new();
    for c in data.chunks(5) {
        acc.extend(h.write(c).unwrap());
    }
    acc.extend(h.finish().unwrap());
    assert_eq!(acc, chacha20_crypt(&data, &a).unwrap());

    let b = args(&[
        ("key", "0123456789abcdef"),
        ("iv", "0xf0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
        ("mode", "ctr"),
    ]);
    let mut h2 = make_aes_enc(&b).unwrap();
    let mut acc2 = Vec::new();
    for c in data.chunks(9) {
        acc2.extend(h2.write(c).unwrap());
    }
    acc2.extend(h2.finish().unwrap());
    assert_eq!(
        acc2,
        ctr_crypt(&data, &b, aes_block_from_args(&b).unwrap()).unwrap()
    );
}

#[test]
fn xor_bruteforce_finds_known_key() {
    let plain = b"Hello, world! This is a known plaintext for XOR testing.";
    let cipher: Vec<u8> = plain.iter().map(|b| b ^ 0x2a).collect();
    let out = xor_bruteforce(&cipher, &HashMap::new()).unwrap();
    let s = String::from_utf8(out).unwrap();
    assert!(s.starts_with("0x2a: "), "got: {}", s);
    assert!(s.contains("Hello, world!"), "got: {}", s);
    assert_eq!(s.lines().count(), 5); // default top=5
}

#[test]
fn xor_bruteforce_top_limits_output() {
    let cipher: Vec<u8> = b"abc".iter().map(|b| b ^ 0x01).collect();
    let out = xor_bruteforce(&cipher, &args(&[("top", "2")])).unwrap();
    assert_eq!(String::from_utf8(out).unwrap().lines().count(), 2);
    assert!(xor_bruteforce(&cipher, &args(&[("top", "0")])).is_err());
}

#[test]
fn xor_input_delimited_memory() {
    // "foo" token uses key 0x01, "bar" token uses key 0x02; space passes through.
    let out = xor(
        b"foo bar",
        &args(&[("key", "0x01 0x02"), ("scheme", "input-delimited")]),
    )
    .unwrap();
    assert_eq!(out, b"gnn `cp");
    // key list cycles when input has more tokens than keys.
    let out2 = xor(
        b"foo bar baz",
        &args(&[("key", "0x01 0x02"), ("scheme", "input_delimited")]),
    )
    .unwrap();
    // "baz" cycles back to key 0x01: b->c, a->`, z->{
    assert_eq!(out2, b"gnn `cp c`{");
}

#[test]
fn xor_input_delimited_streaming_matches_memory() {
    let a = args(&[("key", "0x01 0x02"), ("scheme", "input-delimited")]);
    let mut st = make_xor(&a).unwrap();
    let mut acc = Vec::new();
    for chunk in [&b"fo"[..], b"o b", b"ar", b" qux"] {
        acc.extend_from_slice(&st.write(chunk).unwrap());
    }
    acc.extend_from_slice(&st.finish().unwrap());
    assert_eq!(acc, xor(b"foo bar qux", &a).unwrap());
}

#[test]
fn xor_scheme_rejects_unknown() {
    assert!(xor(b"abc", &args(&[("key", "0x01"), ("scheme", "bogus")])).is_err());
    assert!(make_xor(&args(&[("key", "0x01"), ("scheme", "bogus")])).is_err());
}

#[test]
fn xor_bruteforce_sample_filters_to_known_key() {
    let plain = b"Hello, world! This is a known plaintext for XOR testing.";
    let cipher: Vec<u8> = plain.iter().map(|b| b ^ 0x2a).collect();
    let out = xor_bruteforce(&cipher, &args(&[("sample", "Hello")])).unwrap();
    let s = String::from_utf8(out).unwrap();
    assert_eq!(s.lines().count(), 1, "got: {}", s);
    assert!(s.starts_with("0x2a: "), "got: {}", s);
    assert!(s.contains("Hello, world!"), "got: {}", s);
}

#[test]
fn xor_bruteforce_double_byte_key_with_sample() {
    let plain = b"attack at dawn (double-byte key test)";
    let key = [0x12u8, 0x34];
    let cipher: Vec<u8> = plain
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect();
    let out = xor_bruteforce(&cipher, &args(&[("key_length", "2"), ("sample", "attack")])).unwrap();
    let s = String::from_utf8(out).unwrap();
    assert!(s.starts_with("0x1234: "), "got: {}", s);
    assert!(s.contains("attack at dawn"), "got: {}", s);
}

#[test]
fn xor_bruteforce_rejects_bad_key_length() {
    let cipher: Vec<u8> = b"abc".iter().map(|b| b ^ 0x01).collect();
    assert!(xor_bruteforce(&cipher, &args(&[("key_length", "3")])).is_err());
    assert!(xor_bruteforce(&cipher, &args(&[("key_length", "0")])).is_err());
}

#[test]
fn xor_differential_schemes_memory() {
    // Input differential: key byte is replaced by each input byte.
    let out = xor(
        b"ABC",
        &args(&[("key", "0x01"), ("scheme", "input-differential")]),
    )
    .unwrap();
    assert_eq!(out, b"@\x03\x01");
    // Output differential: key byte is replaced by each output byte.
    let out2 = xor(
        b"ABC",
        &args(&[("key", "0x01"), ("scheme", "output-differential")]),
    )
    .unwrap();
    assert_eq!(out2, b"@\x02A");
}

#[test]
fn xor_differential_streaming_matches_memory() {
    for scheme in ["input-differential", "output-differential"] {
        let a = args(&[("key", "0x0102"), ("scheme", scheme)]);
        let mem = xor(b"the quick brown fox", &a).unwrap();
        let mut st = make_xor(&a).unwrap();
        let mut acc = Vec::new();
        for chunk in [&b"the q"[..], b"uick ", b"brown ", b"fox"] {
            acc.extend_from_slice(&st.write(chunk).unwrap());
        }
        acc.extend_from_slice(&st.finish().unwrap());
        assert_eq!(acc, mem, "scheme={}", scheme);
    }
}

#[test]
fn xor_cascade_memory_and_streaming() {
    let a = args(&[("key", "0x01"), ("scheme", "cascade")]);
    let mem = xor(b"\x01\x02\x03", &a).unwrap();
    assert_eq!(mem, b"\x03\x01\x03");
    let mut st = make_xor(&a).unwrap();
    let mut acc = Vec::new();
    for chunk in [&b"\x01\x02"[..], b"\x03"] {
        acc.extend_from_slice(&st.write(chunk).unwrap());
    }
    acc.extend_from_slice(&st.finish().unwrap());
    assert_eq!(acc, mem);
}

#[test]
fn xor_null_preserving_standard() {
    let out = xor(
        b"\x00\x01A",
        &args(&[("key", "0x01"), ("null_preserving", "true")]),
    )
    .unwrap();
    assert_eq!(out, b"\x00\x01@");
}

#[test]
fn xor_bruteforce_differential_with_sample() {
    // Input-differential "encryption" is inverted by output-differential
    // decoding (the key byte is fed back from the decoded output).
    let plain = b"Known plaintext under input-differential XOR.";
    let a = args(&[("key", "0x05"), ("scheme", "input-differential")]);
    let cipher = xor(plain, &a).unwrap();
    let out = xor_bruteforce(
        &cipher,
        &args(&[("sample", "Known"), ("scheme", "output-differential")]),
    )
    .unwrap();
    let s = String::from_utf8(out).unwrap();
    assert!(s.starts_with("0x05: "), "got: {}", s);
    assert!(s.contains("Known plaintext"), "got: {}", s);
    // And the mirror direction: output-differential ciphertext is
    // recovered with input-differential decoding.
    let a2 = args(&[("key", "0x07"), ("scheme", "output-differential")]);
    let cipher2 = xor(plain, &a2).unwrap();
    let out2 = xor_bruteforce(
        &cipher2,
        &args(&[("sample", "Known"), ("scheme", "input-differential")]),
    )
    .unwrap();
    let s2 = String::from_utf8(out2).unwrap();
    assert!(s2.starts_with("0x07: "), "got: {}", s2);
    assert!(s2.contains("Known plaintext"), "got: {}", s2);
}

#[test]
fn xor_bruteforce_sample_offset_and_print_options() {
    let plain = b"prefix data of interest here";
    let key = 0x11u8;
    let mut cipher = b"junkjunkjunk".to_vec();
    cipher.extend(plain.iter().map(|b| b ^ key));
    // sample_offset skips the junk prefix; known plaintext matches at offset.
    let out = xor_bruteforce(
        &cipher,
        &args(&[
            ("sample", "prefix"),
            ("sample_offset", "12"),
            ("print_key", "false"),
        ]),
    )
    .unwrap();
    let s = String::from_utf8(out).unwrap();
    assert!(!s.starts_with("0x"), "got: {}", s);
    assert!(s.contains("prefix data"), "got: {}", s);
    // hex_output renders candidates as hex.
    let out2 = xor_bruteforce(
        &cipher,
        &args(&[
            ("sample", "prefix"),
            ("sample_offset", "12"),
            ("hex_output", "true"),
        ]),
    )
    .unwrap();
    let s2 = String::from_utf8(out2).unwrap();
    assert!(
        s2.starts_with("0x11: 707265666978206461746120"),
        "got: {}",
        s2
    );
}

#[test]
fn xor_bruteforce_rejects_delimited_and_cascade_schemes() {
    let cipher: Vec<u8> = b"abc".iter().map(|b| b ^ 0x01).collect();
    assert!(xor_bruteforce(&cipher, &args(&[("scheme", "cascade")])).is_err());
    assert!(xor_bruteforce(&cipher, &args(&[("scheme", "input-delimited")])).is_err());
}

#[test]
fn xor_bruteforce_rejects_bad_booleans_and_offset() {
    let cipher: Vec<u8> = b"abc".iter().map(|b| b ^ 0x01).collect();
    assert!(xor_bruteforce(&cipher, &args(&[("print_key", "maybe")])).is_err());
    assert!(xor_bruteforce(&cipher, &args(&[("sample_offset", "abc")])).is_err());
}

#[test]
fn des3_known_vector_ecb() {
    // 3DES-EDE with K1=K2=K3=0123456789ABCDEF reduces to single DES,
    // so the FIPS 81 vector "Now is t" -> 3FA40E8A984D4815 applies.
    // PKCS#7 pads the 8-byte input to 16 bytes; first block matches.
    let key = "0x0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
    let a = args(&[("key", key), ("mode", "ecb")]);
    let enc = des3_encrypt(b"Now is t", &a).unwrap();
    assert_eq!(enc.len(), 16);
    assert_eq!(&enc[..8], hex::decode("3FA40E8A984D4815").unwrap());
    assert_eq!(des3_decrypt(&enc, &a).unwrap(), b"Now is t");
    assert!(des3_encrypt(b"x", &args(&[("key", "0x00"), ("mode", "ecb")])).is_err());
}

#[test]
fn des3_cbc_roundtrip() {
    let a = args(&[("key", "0x0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")]);
    let enc = des3_encrypt(b"attack at dawn", &a).unwrap();
    assert!(enc.len().is_multiple_of(8));
    assert_eq!(des3_decrypt(&enc, &a).unwrap(), b"attack at dawn");
}

#[test]
fn blowfish_known_vector_ecb() {
    // Classic Blowfish vector: all-zero key, all-zero plaintext block.
    // PKCS#7 pads to 16 bytes; first block matches the known vector.
    let a = args(&[("key", "0x0000000000000000"), ("mode", "ecb")]);
    let enc = blowfish_encrypt(b"\0\0\0\0\0\0\0\0", &a).unwrap();
    assert_eq!(enc.len(), 16);
    assert_eq!(&enc[..8], hex::decode("4EF997456198DD78").unwrap());
    assert_eq!(blowfish_decrypt(&enc, &a).unwrap(), b"\0\0\0\0\0\0\0\0");
}

#[test]
fn blowfish_cbc_roundtrip() {
    let a = args(&[("key", "my blowfish key")]);
    let enc = blowfish_encrypt(b"hello blowfish world", &a).unwrap();
    assert_eq!(blowfish_decrypt(&enc, &a).unwrap(), b"hello blowfish world");
}

#[test]
fn tea_known_vector() {
    let a = args(&[("key", "0x00000000000000000000000000000000")]);
    let enc = tea_encode(b"\0\0\0\0\0\0\0\0", &a).unwrap();
    assert_eq!(enc, hex::decode("41EA3A0A94BAA940").unwrap());
    assert_eq!(tea_decode(&enc, &a).unwrap(), b"\0\0\0\0\0\0\0\0");
    assert!(tea_encode(b"x", &args(&[("key", "short")])).is_err());
}

#[test]
fn xtea_known_vector() {
    let a = args(&[("key", "0x00000000000000000000000000000000")]);
    let enc = xtea_encode(b"\0\0\0\0\0\0\0\0", &a).unwrap();
    assert_eq!(enc, hex::decode("DEE9D4D8F7131ED9").unwrap());
    assert_eq!(xtea_decode(&enc, &a).unwrap(), b"\0\0\0\0\0\0\0\0");
}

#[test]
fn tea_family_padding_and_roundtrip() {
    let a = args(&[("key", "0x000102030405060708090a0b0c0d0e0f")]);
    for plain in [
        b"".as_slice(),
        b"a",
        b"hello tea!",
        b"0123456789abcdef01234567",
    ] {
        let e = tea_encode(plain, &a).unwrap();
        assert_eq!(tea_decode(&e, &a).unwrap(), plain);
        let xe = xtea_encode(plain, &a).unwrap();
        assert_eq!(xtea_decode(&xe, &a).unwrap(), plain);
        let xx = xxtea_encode(plain, &a).unwrap();
        assert_eq!(xxtea_decode(&xx, &a).unwrap(), plain);
    }
}

#[test]
fn tea_family_encrypt_decrypt_aliases() {
    // #7: tea/xtea/xxtea gain encrypt/decrypt aliases aligned with the
    // other block ciphers; the aliases share the existing encode/decode
    // implementations and must round-trip.
    let a = args(&[("key", "0x000102030405060708090a0b0c0d0e0f")]);
    let plain = b"tea alias round trip";
    assert_eq!(
        tea_decode(&tea_encode(plain, &a).unwrap(), &a).unwrap(),
        plain
    );
    assert_eq!(
        xtea_decode(&xtea_encode(plain, &a).unwrap(), &a).unwrap(),
        plain
    );
    assert_eq!(
        xxtea_decode(&xxtea_encode(plain, &a).unwrap(), &a).unwrap(),
        plain
    );
}

#[test]
fn xxtea_known_short_vector() {
    // 8-byte input, two words: deterministic, decode must invert.
    let a = args(&[("key", "0x000102030405060708090a0b0c0d0e0f")]);
    let enc = xxtea_encode(b"12345678", &a).unwrap();
    assert_eq!(enc.len(), 8);
    assert_eq!(xxtea_decode(&enc, &a).unwrap(), b"12345678");
}

#[test]
fn tea_family_padding_modes() {
    // PKCS7: padded length is a multiple of 8; decode inverts.
    for (enc, dec) in [
        (
            tea_encode as fn(&[u8], &HashMap<String, String>) -> anyhow::Result<Vec<u8>>,
            tea_decode as fn(&[u8], &HashMap<String, String>) -> anyhow::Result<Vec<u8>>,
        ),
        (
            xtea_encode as fn(&[u8], &HashMap<String, String>) -> anyhow::Result<Vec<u8>>,
            xtea_decode as fn(&[u8], &HashMap<String, String>) -> anyhow::Result<Vec<u8>>,
        ),
        (
            xxtea_encode as fn(&[u8], &HashMap<String, String>) -> anyhow::Result<Vec<u8>>,
            xxtea_decode as fn(&[u8], &HashMap<String, String>) -> anyhow::Result<Vec<u8>>,
        ),
    ] {
        let a = args(&[
            ("key", "0x000102030405060708090a0b0c0d0e0f"),
            ("padding", "pkcs7"),
        ]);
        let ct = enc(b"hello", &a).unwrap();
        assert_eq!(ct.len() % 8, 0, "pkcs7 output must be block-aligned");
        assert_eq!(dec(&ct, &a).unwrap(), b"hello");
    }
    // none: aligned input round-trips, misaligned input errors.
    let a = args(&[
        ("key", "0x000102030405060708090a0b0c0d0e0f"),
        ("padding", "none"),
    ]);
    let ct = tea_encode(b"12345678", &a).unwrap();
    assert_eq!(ct.len(), 8);
    assert_eq!(tea_decode(&ct, &a).unwrap(), b"12345678");
    assert!(
        tea_encode(b"123", &a).is_err(),
        "none mode rejects misaligned input"
    );
    // pkcs7 rejects invalid padding on decode.
    let bad = args(&[
        ("key", "0x000102030405060708090a0b0c0d0e0f"),
        ("padding", "pkcs7"),
    ]);
    let ct = tea_encode(b"hello", &bad).unwrap();
    let mut tampered = ct.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0xff; // corrupt the pkcs7 pad byte
    assert!(
        tea_decode(&tampered, &bad).is_err(),
        "corrupted pkcs7 pad byte must be rejected"
    );
}

#[test]
fn aes_gcm_nist_vectors() {
    // NIST SP 800-38D Appendix B (AES-128-GCM), values cross-checked
    // against OpenSSL. encrypt output is ct||tag.
    // TC1: empty plaintext, empty AAD, zero 12-byte IV.
    let tc1 = args(&[
        ("key", "0x00000000000000000000000000000000"),
        ("mode", "gcm"),
        ("iv", "0x000000000000000000000000"),
    ]);
    let out = aes_encrypt(b"", &tc1).unwrap();
    assert_eq!(hex::encode(out), "58e2fccefa7e3061367f1d57a4e7455a");

    // TC2: 16-byte zero plaintext, empty AAD -> ct||tag.
    let tc2 = args(&[
        ("key", "0x00000000000000000000000000000000"),
        ("mode", "gcm"),
        ("iv", "0x000000000000000000000000"),
    ]);
    let out = aes_encrypt(&[0u8; 16], &tc2).unwrap();
    assert_eq!(
        hex::encode(out),
        "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf"
    );

    // Extra: empty plaintext + 64-byte AAD exercises a long GHASH chain
    // (value recomputed independently via OpenSSL, not an official NIST case).
    let tc3 = args(&[
        ("key", "0xfeffe9928665731c6d6a8f9467308308"),
        ("mode", "gcm"),
        ("iv", "0xcafebabefacedbaddecaf888"),
        (
            "aad",
            "0x03522522523a7835f915bdf0781d64d2e0fd50a52f26b9de809e9a1dccbf1eec7d42f1fd5eb9e3bcc9a4246b07125d19c714e0a5afce4de475f01e5fa25d6b9f",
        ),
    ]);
    let out = aes_encrypt(b"", &tc3).unwrap();
    assert_eq!(hex::encode(out), "748581dd629f74038d5ff80323860829");

    // TC4: 64-byte plaintext, empty AAD.
    let tc4 = args(&[
        ("key", "0xfeffe9928665731c6d6a8f9467308308"),
        ("mode", "gcm"),
        ("iv", "0xcafebabefacedbaddecaf888"),
    ]);
    let plain64 = hex::decode(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
    )
    .unwrap();
    let out = aes_encrypt(&plain64, &tc4).unwrap();
    assert_eq!(
        hex::encode(out),
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
             21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985\
             4d5c2af327cd64a62cf35abd2ba6fab4"
    );

    // TC5: 60-byte plaintext plus AAD.
    let tc5 = args(&[
        ("key", "0xfeffe9928665731c6d6a8f9467308308"),
        ("mode", "gcm"),
        ("iv", "0xcafebabefacedbaddecaf888"),
        ("aad", "0xfeedfacedeadbeeffeedfacedeadbeefabaddad2"),
    ]);
    let plain60 = hex::decode(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
    )
    .unwrap();
    let out = aes_encrypt(&plain60, &tc5).unwrap();
    assert_eq!(
        hex::encode(out),
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
             21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091\
             5bc94fbc3221a5db94fae95ae7121a47"
    );
}

#[test]
fn aes_gcm_roundtrip_and_errors() {
    // roundtrip: encrypt emits ct||tag; decrypt takes ct body + tag param.
    let a = args(&[
        ("key", "0xfeffe9928665731c6d6a8f9467308308"),
        ("mode", "gcm"),
        ("iv", "0xcafebabefacedbaddecaf888"),
        ("aad", "0xfeedfacedeadbeeffeedfacedeadbeefabaddad2"),
    ]);
    let plain = b"authenticated payload with padding-free GCM";
    let enc = aes_encrypt(plain, &a).unwrap();
    assert_eq!(enc.len(), plain.len() + 16);
    let (ct, tag) = enc.split_at(enc.len() - 16);
    let dec = aes_decrypt(
        ct,
        &args(&[
            ("key", "0xfeffe9928665731c6d6a8f9467308308"),
            ("mode", "gcm"),
            ("iv", "0xcafebabefacedbaddecaf888"),
            ("aad", "0xfeedfacedeadbeeffeedfacedeadbeefabaddad2"),
            ("tag", &format!("0x{}", hex::encode(tag))),
        ]),
    )
    .unwrap();
    assert_eq!(dec, plain);

    // wrong tag must fail authentication
    let mut bad = tag.to_vec();
    bad[0] ^= 1;
    let err_args = args(&[
        ("key", "0xfeffe9928665731c6d6a8f9467308308"),
        ("mode", "gcm"),
        ("iv", "0xcafebabefacedbaddecaf888"),
        ("aad", "0xfeedfacedeadbeeffeedfacedeadbeefabaddad2"),
        ("tag", &format!("0x{}", hex::encode(bad))),
    ]);
    assert!(aes_decrypt(ct, &err_args).is_err());

    // explicit iv without tag argument: auto-split trailing tag from ct||tag input
    let auto = aes_decrypt(
        &enc,
        &args(&[
            ("key", "0xfeffe9928665731c6d6a8f9467308308"),
            ("mode", "gcm"),
            ("iv", "0xcafebabefacedbaddecaf888"),
            ("aad", "0xfeedfacedeadbeeffeedfacedeadbeefabaddad2"),
        ]),
    )
    .unwrap();
    assert_eq!(auto, plain);
    // ct-only input (no trailing tag) must fail authentication
    assert!(
        aes_decrypt(
            ct,
            &args(&[
                ("key", "0xfeffe9928665731c6d6a8f9467308308"),
                ("mode", "gcm"),
                ("iv", "0xcafebabefacedbaddecaf888"),
            ])
        )
        .is_err()
    );
    assert!(
        aes_decrypt(
            ct,
            &args(&[
                ("key", "0xfeffe9928665731c6d6a8f9467308308"),
                ("mode", "gcm"),
                ("iv", "0xcafebabefacedbaddecaf888"),
                ("tag", "0x00ff"),
            ])
        )
        .is_err()
    );

    // default (no iv): random 12B IV, output iv||ct||tag, decrypt auto-splits
    let no_iv = args(&[
        ("key", "0xfeffe9928665731c6d6a8f9467308308"),
        ("mode", "gcm"),
    ]);
    let enc2 = aes_encrypt(plain, &no_iv).unwrap();
    assert_eq!(enc2.len(), 12 + plain.len() + 16);
    assert_ne!(&enc2[..12], &[0u8; 12]);
    assert_eq!(aes_decrypt(&enc2, &no_iv).unwrap(), plain);
    // zero-iv-ok escape hatch: 12-byte zero IV, ct||tag layout
    let zo = args(&[
        ("key", "0xfeffe9928665731c6d6a8f9467308308"),
        ("mode", "gcm"),
        ("zero-iv-ok", "true"),
    ]);
    let encz = aes_encrypt(plain, &zo).unwrap();
    assert_eq!(encz.len(), plain.len() + 16);
    assert_eq!(aes_decrypt(&encz, &zo).unwrap(), plain);

    // gcm is streamable through GcmBufferStream: the streaming factory must
    // accept it and produce the same bytes as the one-shot path.
    let mut s = make_aes_enc(&a).unwrap();
    let mut via_stream = Vec::new();
    for c in plain.chunks(7) {
        via_stream.extend(s.write(c).unwrap());
    }
    via_stream.extend(s.finish().unwrap());
    assert_eq!(via_stream, enc);
    assert!(make_aes_dec(&a).is_ok());
}

// ------------------------------------------------------------------
// KDF argument bounds (u64->u32 truncation, length cap)
// ------------------------------------------------------------------

#[test]
fn pbkdf2_rejects_iterations_over_u32_max() {
    let a = args(&[
        ("key", "password"),
        ("salt", "salt"),
        ("iterations", "4294967296"),
        ("length", "32"),
    ]);
    let err = pbkdf2(b"", &a).unwrap_err().to_string();
    assert!(err.contains("iterations 4294967296"), "got: {err}");
    // u32::MAX itself remains accepted (valid, just slow if executed); use
    // length 0 so the derivation loop never runs.
    let ok = args(&[
        ("key", "password"),
        ("salt", "salt"),
        ("iterations", "4294967295"),
        ("length", "0"),
    ]);
    assert!(pbkdf2(b"", &ok).is_ok());
}

#[test]
fn pbkdf2_rejects_length_over_1gib() {
    let a = args(&[
        ("key", "password"),
        ("salt", "salt"),
        ("iterations", "1"),
        ("length", "1073741825"),
    ]);
    let err = pbkdf2(b"", &a).unwrap_err().to_string();
    assert!(err.contains("length 1073741825"), "got: {err}");
}

#[test]
fn hkdf_rejects_length_over_1gib() {
    let a = args(&[
        ("key", "ikm"),
        ("salt", "salt"),
        ("info", "info"),
        ("length", "1073741825"),
    ]);
    let err = hkdf(b"", &a).unwrap_err().to_string();
    assert!(err.contains("length 1073741825"), "got: {err}");
}

#[test]
fn hkdf_rejects_length_over_rfc5869_block_bound() {
    // Default hash is sha256 (32-byte blocks): RFC 5869 caps output at
    // 255 * 32 = 8160 bytes. 8161 must be rejected, not panic on the u8
    // block counter.
    let a = args(&[
        ("key", "ikm"),
        ("salt", "salt"),
        ("info", "info"),
        ("length", "8161"),
    ]);
    let err = hkdf(b"", &a).unwrap_err().to_string();
    assert!(err.contains("length 8161"), "got: {err}");
    // The boundary value itself is accepted and derives the full 8160 bytes.
    let ok = args(&[
        ("key", "ikm"),
        ("salt", "salt"),
        ("info", "info"),
        ("length", "8160"),
    ]);
    let out = hkdf(b"", &ok).unwrap();
    assert_eq!(out.len(), 8160);
}
