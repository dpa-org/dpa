# dpa — Data Processing & Analysis

[![CI](https://github.com/dpa-org/dpa/actions/workflows/ci.yml/badge.svg)](https://github.com/dpa-org/dpa/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/dpa-org/dpa?include_prereleases&sort=semver)](https://github.com/dpa-org/dpa/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.89%2B-orange.svg)](Cargo.toml)

[简体中文](README.zh-CN.md) | English

dpa runs multi-step data transformation and analysis workflows from the command
line. A workflow is a YAML file: an ordered list of operations and their
arguments, so it can be reviewed, versioned, and rerun instead of being retyped.

It is built for work that repeats: decoding samples, hashing artifacts, parsing
headers and certificates, extracting indicators, and running those steps over
one file or a whole directory.

## Install

- **Prebuilt binaries**: download the archive for your platform from
  [Releases](https://github.com/dpa-org/dpa/releases). Archives cover Windows
  x86_64 / arm64, Linux x86_64 (glibc and static musl) / arm64, and a macOS
  universal binary.
- **From source**: `cargo build --release` with Rust 1.89 or newer; the binary
  is `target/release/dpa`.
- **crates.io**: this project owns the `dpa` crate name (currently a 0.0.0
  placeholder); `cargo install dpa` will install the command once 1.0.0 is
  published.

## Quick start

One operation, without writing a flow file:

```console
$ cat input.txt
aGVsbG8=
$ dpa op base64:decode input.txt
hello
```

The same kind of work as a flow you can keep — `flow.yaml`:

```yaml
steps:
  - op: dpa:hex:decode
  - op: dpa:sha256
  - op: dpa:hex:encode
```

```console
$ printf '48656C6C6F' > input.hex
$ dpa run flow.yaml input.hex
185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969
```

`dpa list` shows all operations; `dpa op <name> --help` shows the arguments of
one of them. The full per-operation behavior, including deliberate divergences,
is in [docs/op-semantics.md](docs/op-semantics.md).

## Features

- **Flows as code**: `dpa run flow.yaml input` executes the steps of a flow in
  order. The same flow runs on a file, on stdin, or across a directory.
- **Single operation**: `dpa op <name>` runs one operation directly, without a
  flow file. Its arguments come from the operation itself, so
  `dpa op aes:decrypt --help` lists them.
- **Streaming execution**: a chunked pipeline keeps one chunk (plus any
  buffering steps) in memory, so inputs are not limited by available RAM.
- **Batch mode**: a directory expands to the files it contains (`-r` to
  recurse), files are processed in parallel (`-j N`), and one failing file does
  not abort the run.
- **233 built-in operations** in 7 categories — run `dpa list` for the full set:

  | Category | What is in it |
  | --- | --- |
  | `codec` | Base64/32/58/62/85, hex, binary/octal/decimal, charcode, URL, HTML, quoted-printable, punycode, UTF-8/16, hexdump; gzip, zlib, deflate, Brotli, LZMA/XZ, bzip2 |
  | `crypto` | XOR, RC4, ChaCha20, AES-128/192/256 (ECB/CBC/CFB/OFB/CTR/GCM), SM4 (same modes plus CMAC), DES/3DES, Blowfish, HMAC, PBKDF2, HKDF |
  | `hash` | MD5, SHA-1/2/3, Keccak, SHAKE, BLAKE2, RIPEMD, Whirlpool, SM3, CRC, Adler-32, Fletcher, NT/LM, ssdeep |
  | `transform` | reverse, case, trim, replace, ROT13, Atbash, sort/unique/split/filter/head/tail, JSON/YAML/XML/CSV conversion, regex |
  | `analyze` | entropy, frequency, hash identification, file-type detection, IoC extraction, datetime, TCP/UDP/IP/TLS/Ethernet headers, X.509/CSR/SSH/ASN.1, verify-only signatures |
  | `generate` | timestamps, UUID v1/v3/v4/v5, random bytes, primes, HOTP, TOTP |
  | `extract` | dates, domains, emails, hashes, IPs, MACs, strings, URLs |
- **Reproducible output**: the same input and explicit arguments produce the
  same bytes on every run. Compressed output pins the gzip header time and OS
  fields, time conversions use UTC, and parallel batch output is written in
  input order.
- **Independently checked**: the core codec, hash, compression and crypto
  operations are compared against separate implementations (Python's standard
  library, PyCryptodome, OpenSSL) by a differential suite that runs in CI.
- **Chinese cryptography (SM2 / SM3 / SM4)**: SM2 key parsing, public-key
  extraction and signature verification; SM3 hashing; SM4 in
  ECB/CBC/CFB/OFB/CTR/GCM plus CMAC; HMAC-SM3 and PBKDF2-SM3.
- **Local and explicit**: no network calls, no telemetry, no remote registry.
  Plugins load only from a directory you name; the conventional plugin
  locations need an explicit, warned opt-in.
- **Web/WASM**: the `dpa-wasm` crate runs the same engine on wasm32 (see
  [docs/WASM.md](docs/WASM.md)).
- **Plugin ABI**: operations can be added from a shared library. No directory is
  scanned implicitly; `dpa --plugins <dir>` loads a directory you name, and
  `--discover-plugins` is a warned opt-in for the conventional plugin locations
  (see [docs/PLUGIN.md](docs/PLUGIN.md)).
- **Recipe conversion**: `dpa recipe convert` reads and writes CyberChef recipe
  formats (URL, CHEF, JSON), so an existing recipe can be moved into a flow.
- **Python bindings** (optional `python` feature): `import dpa` and run flows in
  memory.
- **Localized messages**: user-facing text (errors, CLI help, listing output) is
  available in English (default) and Simplified Chinese (`--lang zh-CN`, or
  `DPA_LANG=zh`).
- **Single binary**, no runtime dependencies.

## Build

```bash
cargo build --release
# binary: target/release/dpa.exe
# with Python bindings:
cargo build --features python
```

## Usage

```bash
# One operation, no flow file
dpa op base64:decode input.txt
dpa op xor --key 0x2A input.bin --output-format hex

# Chain operations with a shell pipe
dpa op base64:decode data.txt | dpa op hex:encode -

# Show the arguments of one operation
dpa op xor --help
dpa ops xor

# Run a flow from a file
dpa run flow.yaml input.bin

# Run only the first N steps, then stop (inspect intermediate output)
dpa run flow.yaml input.bin --to-step 2

# Per-step observability: byte counts, first 16 bytes (hex preview), timing on stderr
dpa run -v flow.yaml input.bin

# Batch: directory input, recursive, 4 parallel jobs, output to a directory
dpa run flow.yaml input_dir -o out_dir -r -j 4

# Multiple inputs (output must be a directory)
dpa run flow.yaml a.bin b.bin c.bin -o out_dir

# Batch stdout carries no separator by default (binary chains stay byte-exact);
# add --batch-separator to delimit text outputs explicitly. The separator is
# inserted byte-for-byte between outputs with no added newline, so for readable
# text scenes include the line breaks yourself: PowerShell "`n---`n" (double
# quotes; backtick-n escapes only inside double-quoted strings), bash
# $'\n---\n'. Results are written in input order (parallel workers,
# deterministic output; with -r recursion the order follows the directory walk,
# not alphabetical sorting). For readable attribution in text scenes, add
# --batch-label to print a "==> <input>" line before each output (also off by
# default, so binary chains are unaffected)
dpa run flow.yaml a.bin b.bin --batch-separator $'\n---\n' --batch-label

# Read from stdin ('-' or no input argument)
echo "48656C6C6F" | dpa run flow.yaml

# Write to a file, rendered as hex
dpa run flow.yaml input.bin -o out.txt --output-format hex

# List operations
dpa list
dpa list -c codec        # by category
dpa list -s hash         # by keyword
dpa list --full          # never truncate descriptions (interactive default: 60 chars)

# Switch the language of messages
dpa --lang zh-CN list
DPA_LANG=zh dpa list

# Print a per-step input-to-output estimate before running (advisory, stderr)
dpa run flow.yaml input.bin --explain

# Generate a shell completion script
dpa --generate-completion powershell > dpa-completion.ps1
```

Shell pipes are the shortest route for two or three operations on Unix-like
systems. On Windows, a PowerShell pipeline does not preserve raw bytes; see
[Pipes on Windows](#pipes-on-windows) below before using one.

## Flow file format

```yaml
name: demo
description: example flow
output: hex            # raw | hex; --output-format overrides it
steps:
  - op: dpa:base64:decode
  - op: dpa:xor
    args:
      key: "0x2A"      # arg values must be quoted strings; unquoted numbers/booleans are rejected because they lose 0x/0o/0b prefixes
  - op: dpa:sha256
  - op: dpa:hex:encode
```

Arguments whose values are secret (keys, passwords) can be read from the
environment instead of the flow file or the command line, by using an
`env:NAME` value. This keeps the material out of shell history, process
listings, and recipe URLs. A missing variable is an error.

```yaml
  - op: dpa:hmac
    args:
      key: "env:DPA_HMAC_KEY"
      algo: sha256
```

The engine resolves `env:` values itself, so this works the same way under
`dpa run`, `--eval`, and the Python bindings.

`dpa run` also accepts `--allow-env NAME1,NAME2,...` to
restrict which environment variables may be read this way. A flow that tries to
read any variable not listed on the whitelist fails with a descriptive error.
Without `--allow-env`, the legacy behavior is preserved (any variable can be
resolved), so existing flows keep working unchanged; use the whitelist in
shared or untrusted flow scenarios to prevent `env:` from exfiltrating
unexpected values.

### Flow schema version

Flow files can carry an optional manifest (`meta:`). Its `schema_version`
field tracks the flow file schema used by dpa:

```yaml
name: demo
meta:
  schema_version: 1        # optional; absent means v1
  id: dpa:flow:demo
  version: 1.0.0
steps:
  - op: dpa:base64:decode
```

- Files without `meta.schema_version` are treated as **v1** (backward
  compatible: existing flows keep working unchanged).
- dpa always serializes the current schema version (`1`) when writing a flow
  that carries a manifest.
- A file whose `schema_version` is **newer than the current dpa supports** is
  rejected with a clear error: upgrade dpa, or convert the flow back to a
  supported schema (the migration channel).

Evolution strategy: schema versions are additive. `schema_version` is bumped
only when older dpa builds could no longer read the file; readers should
default a missing version to `1`.

### Flow manifest fields

A flow manifest (`meta:`) accepts the following fields:

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | integer | Flow-file schema version; absent means 1 (see above) |
| `id` | string | Stable identifier, e.g. `dpa:flow:demo` |
| `name` | string | Alias of `id`, accepted on input (backward compatible; never emitted) |
| `version` | string | Human-facing flow version, e.g. `1.0.0` |
| `author` | string | Author name or contact |
| `tags` | string list | Searchable tags |
| `license` | string | License identifier |
| `homepage` | string | Project / readme URL |

Unknown fields are rejected (the manifest is strict). The flow's display name
lives at the top level (`name:`), not inside `meta:`; use `id` as the machine
identifier. `meta.name` is accepted as a backward-compatible alias of `meta.id`
(older manifests that wrote `name` keep loading; serialization always emits
`id`).

## Hex: render layer vs data layer

There are two independent places where “hex” appears, and mixing them up
double-encodes:

| Where | What it does | Example |
|------|------|----|
| Data-layer op `dpa:hex:encode` / `dpa:hex:decode` | A flow step that turns bytes into hex text (or back) | `steps: [- op: dpa:hex:encode]` |
| End-of-pipeline render `output: hex` / `--output-format hex` | Affects only how the flow's **final output bytes** are displayed; does not apply per step | `dpa run flow.yaml in -o out --output-format hex` |

Applying `--output-format hex` on top of a `dpa:hex:encode` step re-encodes
text that is already hex (hex of hex). To inspect the intermediate result of a
step, truncate the flow with `--to-step N`, or add `-v` to preview the first 16
bytes of each step's output.

The `--hex` flag is a shorthand for `--output-format hex`: it affects only the
final render of the pipeline and never changes the data layer, so
`dpa op xor --key 0x2A in.bin --hex` is equivalent to the `--output-format hex`
form above. Use `--hex` for human-readable interactive display of binary results.

When the last step produces binary output, stdout carries the exact bytes, so
`dpa op sha256 in.bin | ...` is byte-exact. When the last step's declared output
is text (`Utf8`, `Hex`, `Base64`, or `Json`), one trailing newline is added to
stdout so interactive output ends on its own line; `-o <file>` never adds it.
For the exact bytes of a text-producing op, write with `-o` or strip that final
newline.

## Python bindings

```python
import dpa

out = dpa.run("""
name: demo
steps:
  - op: dpa:base64:decode
  - op: dpa:hex:encode
""", b"aGVsbG8=")
print(out)  # b"68656c6c6f"
```

The module exports `run`, `run_batch`, `run_file`, `list_ops`, and `op`. See
[examples/python_demo.py](examples/python_demo.py) for the batch and file-based
entry points.

## Documentation

- [PLAN.md](PLAN.md) - scope, architecture, and roadmap
- [OPERATION_CONTRACT.md](OPERATION_CONTRACT.md) - operation naming, arguments, and type rules
- [docs/op-semantics.md](docs/op-semantics.md) - normative operator semantics, alignments, and intentional divergences
- [docs/WASM.md](docs/WASM.md) - WebAssembly binding API, build steps, and limits
- [docs/PLUGIN.md](docs/PLUGIN.md) - plugin ABI
- [docs/RECIPE_CONVERT.md](docs/RECIPE_CONVERT.md) - CyberChef recipe conversion boundaries
- [docs/FUZZ_ROADMAP.md](docs/FUZZ_ROADMAP.md) - fuzzing plan for the parsers
- [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), [CHANGELOG.md](CHANGELOG.md)

Every document above except the changelog also has a Simplified Chinese
counterpart (`*.zh-CN.md`).

## Notes

- Operation identifiers are namespaced `dpa:<category>:<name>`, for example
  `dpa:base64:decode` and `dpa:sha256`.
- Hash operations emit the raw digest bytes; add a `dpa:hex:encode` step to
  display them.
- Decompression outputs are subject to the per-step cap
  (`--max-step-output-bytes`, default 64 MiB): a payload that decompresses
  beyond the cap fails with a clear error instead of unbounded memory growth.
  Raise the cap for larger outputs, or set it to `0` — `0` disables the cap
  entirely (no limit); decompression itself streams.
- Block-cipher encryption without an explicit `iv` (aes/sm4/des in
  CBC/CFB/OFB/CTR mode) uses the all-zero IV for backward compatibility and
  prints a one-line stderr warning: the fixed IV can reuse the
  keystream across messages under the same key. Pass a random `iv` or use
  `gcm` mode, which randomizes by default. Decryption keeps the all-zero
  default so legacy ciphertexts still read back.
- The text-transform family (`dpa:transform:*` — reverse, chars, upper, lower,
  trim, case, etc.) interprets input as UTF-8: invalid bytes are replaced with
  U+FFFD and are not reversible. Keep text transforms out of byte-exact binary
  chains; validate or transcode input first.
- For a given input, the streaming and in-memory execution paths are required to
  produce identical output. Tests enforce this.
- ChaCha20 is limited to 256 GiB of keystream per key/nonce pair (RFC 8439 uses
  a 32-bit counter); re-key before that.
- Streaming `dpa:hex:decode` cannot know the full input length until the end, so
  an error (for example an odd number of digits) is only detected in the finish
  phase: bytes already written to stdout before the error are partial and must
  not be used. Scripts that consume `hex:decode` output must check the exit
  code.
- KDF bounds: `pbkdf2` iterations above `u32::MAX` are
  rejected instead of being silently truncated (an overflow could collapse the
  iteration count to zero); derived length is capped at 1 GiB; `hkdf` honors
  the RFC 5869 255-block limit. Exceeding any bound fails with a clear error.
- The `.dpaflow` package format and its manifest API exist in the library as
  groundwork for sharing flows. The corresponding CLI surface is disabled in
  1.0, and nothing is fetched over the network.
- `dpa run -e <YAML>` runs a flow supplied inline. It is there for scripts and
  CI that generate YAML, rather than for typing flows by hand.
- Unix pipes are a first-class input source and output sink: stdout/stderr stay
  clean (no progress bars, no color escapes), plain byte output can be fed
  straight into the next command, and the exit code is 0 on success and non-zero
  on failure. The shell-pipe form works (`dpa op base64:decode x | dpa op hex:encode -`);
  a single-command pipe-string form (`dpa "op1|op2"`) is not supported — chain
  multiple ops with a flow file or `dpa run -e` instead.
- Writing to an existing `-o` target asks for confirmation on an interactive
  terminal (`[y/N]`, answering no aborts); with piped/redirected stdio (scripts,
  CI) it overwrites silently.
- `dpa recipe convert` converts CyberChef recipes between URL / CHEF / JSON
  formats. It is an interop tool, not a “CyberChef → dpa flow” converter;
  conversion does not validate op availability or expand control-flow ops.
  See [docs/RECIPE_CONVERT.md](docs/RECIPE_CONVERT.md) for the exact boundary.

### Pipes on Windows

- PowerShell 5.1 attaches a UTF-8 BOM and a CRLF to pipeline output, which
  corrupts raw bytes and surprises consumers that count bytes (e.g.
  `dpa op sha256`). Set
  `$OutputEncoding = [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)`
  (BOM-less UTF-8) before piping, use `cmd /c` with `chcp 65001` redirection,
  or avoid the pipeline entirely: pass a file positionally
  (`dpa run flow.yaml in.bin`).
- cmd.exe uses the legacy ANSI/OEM code page (GBK on Chinese Windows) by
  default; run `chcp 65001` first so dpa's UTF-8 output is not mis-rendered.
  When dpa detects a console codepage other than 65001 (and stdout is a real
  console, not a pipe or redirection), it prints this hint once to stderr;
  scripted and piped runs stay silent.
- The examples in `dpa op <name> --help` use bash syntax; translate quoting and
  line continuations to your shell.

## Release

- License: Apache-2.0 (see [LICENSE](LICENSE) and [NOTICE](NOTICE)).
- Local packaging (Windows): `powershell -ExecutionPolicy Bypass -File scripts\release.ps1`
  builds the release binary, assembles `dist\dpa-<ver>-x86_64-pc-windows-msvc\`,
  and writes a zip plus a `SHA256` checksum.
- Release smoke gate (Windows): `powershell -ExecutionPolicy Bypass -File scripts\release_smoke.ps1`
  asserts `--version`, `--help`, one op conversion, one flow run, and error exit
  codes against a built binary. It is a pure development-side gate: it never
  tags, packages, or publishes.
- Releases are cut by pushing a tag `v*` (for example `git tag v1.0.0 &&
  git push origin v1.0.0`), which triggers
  [.github/workflows/release.yml](.github/workflows/release.yml) and attaches
  prebuilt archives with checksums to a GitHub Release, named after their Rust
  target:

  | Platform | Archive |
  | --- | --- |
  | Windows x86_64 | `-x86_64-pc-windows-msvc.zip` |
  | Windows arm64 | `-aarch64-pc-windows-msvc.zip` |
  | Linux x86_64, glibc | `-x86_64-unknown-linux-gnu.tar.gz` |
  | Linux x86_64, static (musl) | `-x86_64-unknown-linux-musl.tar.gz` |
  | Linux arm64, static (musl) | `-aarch64-unknown-linux-musl.tar.gz` |
  | macOS universal (arm64 + x86_64) | `-universal-apple-darwin.tar.gz` |

### Version metadata

When built from a git checkout, `dpa --version` prints the package version, the
commit it was built from, and the commit date:

```
dpa 1.0.0 (commit 66d05b838b01, 2026-10-25)
```

- Sources without a `.git` directory (release tarballs) fall back to the bare
  version line.
- Builds from a dirty tree append `-dirty`, so `--version` never claims a clean
  commit it was not built from. The release script refuses to package a dirty
  tree.
- `build.rs` reads the commit at build time. Cargo does not reliably rerun it
  for changes under `.git/`, so the repository ships a post-commit hook that
  touches `build.rs` after every commit. Install it once per clone:

  ```powershell
  powershell -ExecutionPolicy Bypass -File scripts\setup-git-hooks.ps1
  # or, on any platform:
  git config core.hooksPath .githooks
  ```

  `scripts\release.ps1` also touches `build.rs` before packaging, and CI checks
  that the embedded commit matches the tagged commit.

## Roadmap

`1.0.0` is the first public release. The flow format, operation identifiers, and
CLI surface are treated as stable from here on; see
[OPERATION_CONTRACT.md](OPERATION_CONTRACT.md).

- **1.x**: additive changes — new operations, new optional arguments, new output
  forms, and performance work. Changing the meaning of a flow file or an
  operation name would require `2.0`.
- **Later**: more first-party plugins, a crates.io release, and the deferred
  flow-sharing surface.

The direction and open questions are recorded in [PLAN.md](PLAN.md); released
changes are in [CHANGELOG.md](CHANGELOG.md).
