# Changelog

All notable changes to dpa are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-10-15

First public release.

### Added

- **Flows as code**: a flow is a YAML file executed by a single static binary
  (`dpa run flow.yaml input`); it can be reviewed, versioned, and run again.
- **Single operation calls**: `dpa op <name> [--arg value]... [INPUT]...` runs
  one operation without a flow file, taking its arguments from that operation's
  own definition.
- **218 built-in ops** across 7 categories (`codec` / `transform` / `hash` /
  `crypto` / `analyze` / `generate` / `extract`):
  - codecs: Base64 (std/URL/custom alphabet), Base32/58/62/85, Hex, binary,
    octal, decimal, charcode, URL, HTML, quoted-printable, punycode, UTF-8/16,
    hexdump, CSV/JSON, YAML/JSON, XML/JSON;
  - compression: gzip, zlib, raw deflate, Brotli, LZMA/XZ, bzip2;
  - symmetric crypto: AES-128/192/256 (ECB/CBC/CFB/OFB/CTR/GCM), SM4, DES,
    3DES, Blowfish, ChaCha20, RC4, XOR;
  - KDF/MAC: HMAC (SHA-1/256/512), PBKDF2, HKDF;
  - hashes: MD5, SHA-1, SHA-2, SHA-3, Keccak, SHAKE, BLAKE2, RIPEMD,
    Whirlpool, SM3, CRC16/32/32C, Adler-32, Fletcher, NT/LM, ssdeep;
  - analysis: entropy, byte frequency, hash identification, file-type
    detection (magic bytes), IoC extraction, TCP/UDP/IPv4/IPv6/TLS/Ethernet
    header parsing, X.509 / CSR / SSH / ASN.1 parsing and verify-only
    signature checks;
  - text/structural transforms, plus data generation (timestamps, UUID, primes,
    HOTP/TOTP).
- **Streaming pipeline**: chunked, incremental execution for large files and
  directories; only one chunk is held in memory.
- **Batch mode**: directory inputs (recursive with `-r`), file-level
  parallelism (`-j N`), and per-file error isolation that never aborts the run.
- **Introspection and interop**: `dpa list`, `dpa ops <name>`, and
  `dpa recipe convert` for URL / CHEF / JSON recipes (506-name zh/en map).
- **Plugin ABI**: out-of-tree ops in shared libraries, loaded only via an
  explicit `dpa --plugins <dir>`. Nothing is discovered implicitly; the
  `--discover-plugins` flag opts in to the conventional plugin directories and
  warns first. The ABI has no network surface.
- **Multi-target**: optional Python bindings (`--features python`) and a
  `dpa-wasm` crate for wasm32, both reusing the same engine.
- **Built-in i18n**: English (default) and Simplified Chinese
  (`--lang zh-CN` or `DPA_LANG=zh`).

### Notes

- dpa is strictly local: no remote registry and no network calls. The
  `.dpaflow` package format and manifest APIs ship as extension points; the
  corresponding CLI surface is disabled in 1.0.
- Secret-class arguments can come from the environment (`env:NAME`) instead of
  flow files, shell history, or process listings.
- ChaCha20 keystream is limited to 256 GiB per key/nonce pair (RFC 8439
  32-bit counter); re-key before that.

[1.0.0]: https://github.com/dpa-org/dpa/releases/tag/v1.0.0
