# Fuzzing Roadmap

> Property tests ship in-tree. A continuous fuzz pipeline is planned, using
> only the stable Rust toolchain.

## Context

`dpa` consumes untrusted bytes in several places: YAML flow files, codec
decode paths, ASN.1 / X.509 / JSON / regex parsers, and crypto primitives.
The classic fuzzing route (`cargo-fuzz` + libFuzzer) requires a **nightly**
Rust toolchain. The build, test, and release gates are stable-only, so no
nightly dependency is introduced.

## Current coverage

| Surface | Tool | What is asserted |
| --- | --- | --- |
| codec encode/decode | `proptest` (`tests/proptest_parsers.rs`) | `decode(encode(x)) == x` for hex, base32/45/58/62/64/64url/85, pem, qp, url |
| crypto | `proptest` (`tests/proptest_parsers.rs`) | xor involution, AES-CTR / ChaCha20 / RC4 round-trips, hash length invariants, HMAC determinism |
| parsers | `proptest` (`tests/proptest_parsers.rs`) | "never panics on arbitrary bytes" for ASN.1, X.509, JSON, PKCS#1<->PKCS#8, regex |
| known vectors | plain tests (`tests/proptest_parsers.rs`) | FIPS 180-4 SHA-256, RFC 4231 HMAC-SHA256, NIST SP 800-38A CTR-AES128 |

## Phases

### Phase 1 — stable harness

Introduce a `fuzz/` crate (stable, no nightly) with random-bytes drivers:

- corpus seeds: real flow files, malformed YAML, truncated codec output;
- invariant: `run(op, input, args)` must not panic / must not hang
  (bounded input size, op-specific timeout budget);
- runner options: `cargo afl` (AFL++) and/or an in-house deterministic
  pseudo-random driver so CI can replay a fixed seed set;
- targets: `yaml parse flow`, `asn1:parse`, `x509`, `json:pretty`,
  `regex:match`, every codec `*:decode`, `hexdump:decode`.

### Phase 2 — libFuzzer via cargo-fuzz

Once a dedicated nightly CI runner exists:

- add `cargo-fuzz` targets mirroring the Phase 1 target list;
- wire `cargo fuzz build` into a nightly-only workflow;
- keep the stable gate untouched — nightly is never required to build/test/ship.

### Phase 3 — corpus & regression hygiene

- commit a small corpus of interesting inputs (edge-case YAML, truncated
  DER/JSON, pathological base85) under `fuzz/corpus/`;
- every crash found upstream gets reduced and added as a unit test in
  `tests/` before the fix lands;
- optional OSS-Fuzz integration once Phase 2 is proven stable.

## Explicit non-goals

- No nightly toolchain in the build, test, clippy or fmt gates.
- No fuzz loop inside the library: harnesses live in `fuzz/`, never in `src/`.
