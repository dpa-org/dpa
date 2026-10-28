# Changelog

All notable changes to dpa are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Updated `base64` to 0.23, `ecb` to 0.2, and `libloading` to 0.9 after
  workspace-wide compatibility checks.

### Security

- Updated `crypto-bigint` to 0.7.10 and `ctutils` to 0.4.6 for
  RUSTSEC-2026-0387 and RUSTSEC-2026-0385. CI now checks advisories through
  the audited `deny.toml` policy.

## [1.0.0-rc2] - 2026-10-28

### Added

- **SM4-GCM (AEAD, NIST SP 800-38D)**: `sm4:encrypt` / `sm4:decrypt` now
  accept `--mode gcm` with `--iv` / `--aad` / `--tag`, mirroring AES-GCM:
  encryption outputs `ciphertext||tag`, decryption verifies the 16-byte tag
  before releasing plaintext. Unit tests cover known vectors, round-trips,
  tag tampering, AAD mismatch, and non-12-byte IVs; the differential suite
  cross-checks against an independent Python reference (pysm4 + GCM).
- **Perfect-pick list additions (CLI parity)**:
  - `sha3:224` / `sha3:384` join the existing 256/512 variants.
  - `hmac` and `pbkdf2` accept `--algo`/`--hash` values `sm3`, `sha3-256`,
    `sha3-512` in addition to sha1/sha256/sha512.
  - `totp` / `hotp` gain `--algo sha1|sha256|sha512` (RFC 4226/6238).
  - `xxhash32` / `xxhash64` gain `--seed` (default 0 preserves prior output).
  - New `bitwise:xor` (keyed XOR alongside and/or/rotate/shift/not).
  - `timestamp:to:date` accepts `--unit s|ms|us|ns` matching
    `generate:timestamp`.
  - `count` accepts `--mode lines` (wc -l equivalent) alongside substring.
  - Empty-key `totp` / `hotp` now prints the generated random secret and an
    `otpauth://` URI plus a demo-only note instead of outputting an
    unverifiable code.
- **Perfect-pick decisions (14-item review)**:
  - **`sm4:cmac`** joins `sm4:mac`: SM4-CMAC (GM/T 0005-2012, RFC 4493
    construction) fixes the length-extension weakness of CBC-MAC; key required.
  - **`extract:hashes` length classes**: candidates now also cover 56/96/128
    hex digits (SHA-224 / SHA3-384 / SHA-512 groups etc.) alongside the
    existing 32/40/64 classes.
  - **`--hex` shorthand** for `--output-format hex` on `dpa op`; an explicit
    `--output-format` still wins when both are given.
  - **Boolean arguments accept bare flags**: semantic booleans (e.g.
    `filter --regex`, `--invert`, `analyze:entropy --show-zero`, `compress
    --fhcrc`, `sm2 --raw`) can be used as bare `--flag` (implies `true`) or
    with an explicit `--flag true|false`; invalid values report
    `expected true|false`. Flow files keep the string form.
  - **zh-CN clap error localization**: under `--lang zh`, the four high
    frequency clap error classes (invalid value, missing required value,
    unknown argument, unknown subcommand) are wrapped with localized text
    instead of raw English.
  - **`--batch-separator` for `dpa run`**: batch stdout carries no separator
    by default so binary chains stay byte-exact; text scenarios can opt into a
    visible delimiter between outputs (`--batch-separator "---"`). Empty value
    is normalized to no separator. See README for the binary-chain semantics.
- **`--explain`**: `dpa run --explain` prints a static per-step input/output
  estimate to stderr before executing, as a pre-run guard for long flows.
- **`--generate-completion <shell>`**: emit a completion script for bash, zsh,
  fish, or PowerShell.
- **Non-UTF-8 console hint**: when stdout is a real console whose codepage is
  not 65001, dpa prints a one-time `chcp 65001` hint to stderr; piped and
  scripted runs stay silent.

### Changed

- **YAML parser migrated to `serde-saphyr`**: flow/recipe/package YAML
  parsing and serialization moved from `serde_yaml_ng` (unsafe-libyaml,
  RUSTSEC-2024-0449, unmaintained) to `serde-saphyr` 1.3.x (safe Rust + serde
  integration). All entry points use the dpa-wide options
  (`strict_booleans: true`, `MergeKeyPolicy::AsOrdinary`,
  `DuplicateKeyPolicy::Error`) so YAML 1.1 `yes`/`no` stay strings, `<<` merge
  keys stay literal, and duplicate keys remain a hard error carrying the key
  name (now raised by the parser layer instead of the serde map visitor).
  MSRV raised 1.85 → 1.89. Verified: build + full test suite green, release
  build + `release_smoke.ps1` pass, `cargo deny check advisories` clean.
- **Flow args reject unquoted scalars**: YAML argument values must be
  quoted strings; unquoted numbers/booleans are rejected with a key-named i18n
  error because YAML 1.2 core-schema conversion silently drops `0x`/`0o`/`0b`
  prefixes. Quoted `"0x2A"` reaches numeric ops as-is and hex codec ops never
  strip prefixes.
- **Duplicate YAML flow keys are an error**: duplicate `args` keys now
  fail parsing with the key name (i18n bilingual) instead of silently keeping
  the last value; detection is implemented at the serde map-visitor level,
  independent of the parser migration.
- **Non-GCM implicit zero IV now warns**: aes/sm4/des encryption
  (CBC/CFB/OFB/CTR) without an explicit `iv` prints a one-line stderr
  warning (i18n en/zh-CN) that the all-zero IV can reuse the keystream under
  a repeated key; pass a random `iv` or use `gcm` mode. Defaults and output
  formats are unchanged — decryption and legacy ciphertexts are unaffected.
- **cap-0 semantics documented**: README (en/zh-CN) now states
  explicitly that `--max-step-output-bytes 0` disables the per-step cap
  (no limit); runtime behavior is unchanged.
- **Differential suite aligned with CLI conventions**: `scripts/difftest.py`
  round-trip and quoted-printable comparisons now fetch exact encoding bytes
  through the hex output channel instead of the raw channel, so the CLI's
  text-op trailing LF (`text_tail`) no longer pollutes decode inputs or QP
  baselines; html `encode_all` round-trips accept the WHATWG U+FFFD
  substitution for numeric entity U+0000 (see the `61eb32f` codec fix), and
  the script's Python syntax/comments were corrected. Full run (all cases,
  6996 differential checks) is green again.

- **datetime parse / translate tolerance**: `dpa:datetime:parse` /
  `dpa:datetime:translate` accept minute precision (`2024-01-02 03:04`),
  slash-separated dates (`2026/10/02 14:05`), and fractional seconds
  (truncated to whole seconds). New `on_error=skip` argument drops invalid
  lines instead of failing the whole batch and appends a
  `# [dpa] skipped N invalid line(s)` summary (default remains `fail`).
- **extract:domains false positives**: common file extensions are no longer
  reported as TLDs (`app.js`, `style.css` filtered by default); new
  `filter_ext_tlds` (default `true`) and `extra_tld_blacklist` arguments
  control the behavior.
- **analyze:file:type text fallback**: inputs with no magic signature now fall
  back to a text sniff (ASCII / UTF-8 / UTF-16 LE/BE) with newline-style
  annotation (`LF` / `CRLF` / `None`) instead of reporting `Unknown file type`
  for readable text.
- **Binary renamed to `dpa`**: the CLI binary now carries the same name as the
  library crate (`dpa`), matching the conventional app+library layout.
  `cargo install dpa` installs the command as `dpa`, and release archives ship
  `dpa.exe` directly (no install-time rename). On Windows MSVC, cargo emits a
  known `dpa.pdb` output-name collision warning (cargo #6313) which does not
  affect build output.
- **sort alpha is now line-oriented**: default `--type alpha` sorts whole lines
  lexically (newline-terminated), matching numeric/ip/length; the previous
  whole-buffer byte ordering is preserved as explicit `--type bytes`.
  Help and list descriptions are aligned with the new behavior.
- **i18n list descriptions corrected**: `utf8:escape` no longer claims `'%%'`
  for `%` (it emits standard `%25`) and now documents the escape-range
  difference from `url:encode`; the damaged `ssh:parse` list entry was
  rewritten in both locales (residual sentence duplication removed).
- **`uuid4` renamed to `uuid`**: the op is now `dpa:uuid` with
  `--version 1|3|4|5` (default 4), `--namespace`, and `--name`;
  `uuid4` remains as a deprecated alias (`[deprecated alias] Same as dpa:uuid`).
- **Deprecated aliases for symmetric decrypts**: `chacha20:decrypt` and
  `rc4:decrypt` are now explicit ops (deprecation note, engine unchanged);
  `tea:encode` / `tea:decode` and `xtea:encode` / `xtea:decode` /
  `xxtea:encode` / `xxtea:decode` are marked `[deprecated alias]` pointing at
  the canonical `encrypt` / `decrypt` forms.
- **`add:line-numbers` family corrected to `transform`**: the op (id
  `dpa:add:line-numbers`) now lists under family `transform` (kind
  `line-numbers`) instead of a `add` family, aligning with its sibling line
  transforms.
- **Common options folded**: `dpa op` help groups shared flags (`--output`,
  `--output-format`, `--hex`, `--recursive`, `--jobs`, `--max-input-bytes`)
  under a single `Common options` section instead of inline per-op.
- **`fork` hidden from `dpa list`**: the op is no longer advertised in list
  output (engine kept for backward compatibility; explicitly usable via flow).
- **`sm4:mac` help warns about CBC-MAC**: the op's help now carries a SECURITY
  note (both locales) about length-extension forgery on variable-length
  messages with pkcs7 padding, recommending `sm4:cmac` for new designs.
- **User-facing polish**: zh-CN `dpa op --help` headings were
  mojibake and are now UTF-8 (smoke-tested); single-value op failures no
  longer echo the entire (potentially huge) input (truncated to 64 bytes with
  a total-length note); README drops the nonexistent `--input-file` promise
  and the PowerShell `--batch-separator` example uses double quotes
  (backtick-n escapes only inside double-quoted strings); YAML parser errors
  hide Rust API concepts (`Depth { depth: N }`, `set DuplicateKeyPolicy in
  Options`) while keeping line/column and a user action; `err.arg_type` shows
  the fix (`rounds: "3"`); `datetime:delta` human text agrees in number
  (`1 hour`, not `1 hours`); `datetime:parse` / `datetime:translate` strict
  errors name the failing line and strftime errors/help list common
  directives; `--batch-label` progress labels use relative paths instead of
  full absolute paths.
- **`-o` overwrite confirmation**: writing to an existing file now asks
  `[y/N]` on an interactive terminal and aborts on "no"; piped or redirected
  runs keep the previous silent-overwrite behavior.
- **SM4 help lists GCM**: `dpa ops sm4:encrypt` / `sm4:decrypt` now include
  `gcm` in their mode list (the mode already worked; the help omitted it).

### Fixed

- **Release workflow validation**: release builds now compare the embedded
  12-character commit with the triggering tag SHA, Windows smoke tests parse
  the final operation count without treating a trailing blank line as zero and
  check every native command's exit status, and the Linux cross-toolchain
  download fails closed with retries before the build starts. The differential
  suite is now a required release job with pinned reference dependencies.
- **Leading UTF-8 BOM in flow YAML**: a BOM is stripped before parsing instead
  of producing a YAML error.
- **Plugin panics no longer abort the host**: panics crossing the plugin ABI
  bridge are caught and reported as plugin errors.
- **HTML numeric entity `&#0;`**: decoded as U+FFFD per WHATWG instead of
  producing a NUL byte.
- **Batch and stream error reporting**: batch hex output is rendered once per
  file, fork fallback respects the output cap, and stream errors name the
  failing step.

### Security

- **KDF bounds**: `pbkdf2` iterations above `u32::MAX` are now
  rejected instead of being silently truncated to zero (an overflow previously
  collapsed the iteration count, degrading derived-key strength to a single
  hash); derived length is capped at 1 GiB; `hkdf` honors the RFC 5869 255-block
  limit. Each violation fails with a descriptive i18n error (`err.kdf_iterations_exceeded` /
  `err.kdf_length_exceeded`).
- **PEM error redaction**: `dpa:pem` decode failures no longer
  echo the first 120 bytes of the input (which could leak private-key / secret
  material into stderr, logs, or CI output); the message now reports the error
  and the input length only.
- **Python binding caps**: `python` feature enforces the same
  defenses as the CLI path — flow YAML capped at 8 MiB (`err.flow_too_large`),
  `run_file` input capped at 1 GiB (`err.input_too_large`), and file output goes
  through the engine's atomic tmp+commit writer (no half-written target file).
- **`env:` whitelist**: `dpa run` gains `--allow-env NAME,...`
  to restrict which environment variables `env:` arguments may resolve; unlisted
  variables are rejected with `err.env_not_allowed`. Without the flag, legacy
  behavior is preserved so existing flows keep working unchanged.
- **Hex stream partial-output disclosure**: `hex:decode` error
  messages now state that bytes already emitted before the failure are partial
  and must not be used (`err.hex_odd` / `err.hex_invalid`), closing the
  silent-half-output integrity gap for scripts that ignore the exit code.
- **Output temp file hardening**: engine output writers open
  temp files with `create_new` and retry with an incremented sequence on
  `AlreadyExists`, instead of `File::create` (which truncated a pre-existing
  file and followed symlinks).
- **Release version-metadata gate**: `scripts/release.ps1` now
  runs the release smoke gate against the freshly built binary and hard-fails
  the packaging if the embedded commit in `dpa --version` does not match HEAD.
  A stale `--version` (e.g. from a missing post-commit hook or an incremental
  build that skipped `build.rs`) can no longer be packaged silently.
- **CI feature matrix**: the `feature-matrix` job now checks
  the lib with `--no-default-features` and on `wasm32-unknown-unknown`
  (`--lib --no-default-features`), covering combinations that were previously
  untested.

### Removed

- **`serde_yaml_ng` / `unsafe-libyaml` dependency removed**: the migration
  to `serde-saphyr` eliminates the unsafe-libyaml C surface and closes
  RUSTSEC-2024-0449.
- **`hex:to:pem` / `pem:to:hex` removed**: the PEM-wrapper ops are gone from
  the registry and docs (no safe X.509 encoding guarantee; see README
  equivalence note below).
- **`lorem:ipsum` removed**: the placeholder generator op was dropped from the
  registry and docs.

## [1.0.0] - 2026-10-15

First public release.

### Added

- **Flows as code**: a flow is a YAML file executed by a single static binary
  (`dpa run flow.yaml input`); it can be reviewed, versioned, and run again.
- **Single operation calls**: `dpa op <name> [--arg value]... [INPUT]...` runs
  one operation without a flow file, taking its arguments from that operation's
  own definition.
- **233 built-in ops** across 7 categories (`codec` / `transform` / `hash` /
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
- **`--to-step N`**: run only the first N steps of a flow, for debugging and
  previewing long flows.
- **`--verbose` / `-v`**: print each step's byte count and a 16-byte hex
  preview while running; data output stays clean for piping.
- **Recipe conversion boundaries**: `dpa recipe convert` interchange rules
  for URL / CHEF / JSON formats are documented in `docs/RECIPE_CONVERT.md`.

### Fixed

- **xxh64**: the four-byte branch read the block in the wrong byte order and
  produced incorrect digests for certain inputs; output now matches the
  reference implementation.
- **gzip**: an empty input produced a malformed stream header; it now emits a
  valid gzip stream with an empty payload.
- **AES-GCM (streaming)**: the streaming path computed the authentication tag
  differently from the in-memory path; both paths now produce identical
  ciphertext and tag.
- **from_chef**: the official `/` multi-operation separator was swallowed by
  the conversion; URL / CHEF / JSON recipes now preserve every operation
  (regression test added).

### Notes

- dpa is strictly local: no remote registry and no network calls. The
  `.dpaflow` package format and manifest APIs ship as extension points; the
  corresponding CLI surface is disabled in 1.0.
- Secret-class arguments can come from the environment (`env:NAME`) instead of
  flow files, shell history, or process listings.
- ChaCha20 keystream is limited to 256 GiB per key/nonce pair (RFC 8439
  32-bit counter); re-key before that.

[1.0.0]: https://github.com/dpa-org/dpa/releases/tag/v1.0.0
