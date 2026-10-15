# dpa — Data Processing & Analysis

[简体中文](README.zh-CN.md) | English

dpa runs multi-step data transformation and analysis workflows from the command
line. A workflow is a YAML file: an ordered list of operations and their
arguments. Because the workflow is a file, it can be reviewed, versioned, and
rerun instead of being retyped each time.

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
- **218 built-in operations** in 7 categories (`codec` / `transform` / `hash` /
  `crypto` / `analyze` / `generate` / `extract`):
  - `codec`: Base64 (standard, URL-safe, or a custom alphabet), Base32, Base58,
    Base62, Base85, Hex, binary, octal, decimal, charcode, URL, HTML,
    quoted-printable, punycode, UTF-8, UTF-16, hexdump; gzip, zlib, raw
    deflate, Brotli, LZMA/XZ, bzip2
  - `crypto`: XOR, RC4, ChaCha20, AES-128/192/256 (ECB, CBC, CFB, OFB, CTR,
    GCM), SM4, DES, 3DES, Blowfish, HMAC (SHA-1/256/512), PBKDF2, HKDF
  - `hash`: MD5, SHA-1, SHA-2, SHA-3, Keccak, SHAKE, BLAKE2, RIPEMD, Whirlpool,
    SM3, CRC-16/32/32C, Adler-32, Fletcher, NT, LM, ssdeep
  - `transform`: reverse, case conversion, trim, replace, ROT13, Atbash,
    substitution, sort, unique, split, filter, head, tail, JSON pretty-print,
    JSON minify, JSON path extraction, regex match, regex replace, CSV to/from
    JSON, YAML to/from JSON, XML to/from JSON
  - `analyze`: entropy, byte frequency, hash identification, file-type detection
    from magic bytes, IoC extraction, datetime parsing, TCP/UDP/IPv4/IPv6/TLS/
    Ethernet header parsing, X.509 / CSR / SSH / ASN.1 parsing, and verify-only
    signature checks
  - `generate`: timestamps, UUID v4, random bytes, primes, HOTP, TOTP
- **Web/WASM**: the `dpa-wasm` crate runs the same engine on wasm32.
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
# binary: target/release/dpa-cli.exe (installed as dpa.exe)
# with Python bindings:
cargo build --features python
```

The binary is named `dpa-cli`, so `cargo install dpa` installs the command as
`dpa-cli`. The prebuilt archives below rename it to `dpa`.

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

# Batch: directory input, recursive, 4 parallel jobs, output to a directory
dpa run flow.yaml input_dir -o out_dir -r -j 4

# Multiple inputs (output must be a directory)
dpa run flow.yaml a.bin b.bin c.bin -o out_dir

# Read from stdin ('-' or no input argument)
echo "48656C6C6F" | dpa run flow.yaml

# Write to a file, rendered as hex
dpa run flow.yaml input.bin -o out.txt --output-format hex

# List operations
dpa list
dpa list -c codec        # by category
dpa list -s hash         # by keyword

# Switch the language of messages
dpa --lang zh-CN list
DPA_LANG=zh dpa list
```

For two or three operations, a shell pipe is the shortest route on Unix-like
systems. On Windows, where binary data does not survive a PowerShell pipeline
intact, a small flow file is more reliable.

## Flow file format

```yaml
name: demo
description: example flow
output: hex            # raw | hex; --output-format overrides it
steps:
  - op: dpa:base64:decode
  - op: dpa:xor
    args:
      key: "0x2A"      # argument values: string / number / boolean
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

See [examples/python_demo.py](examples/python_demo.py) for the batch and
file-based entry points.

## Notes

- Operation identifiers are namespaced `dpa:<category>:<name>`, for example
  `dpa:base64:decode` and `dpa:sha256`.
- Hash operations emit the raw digest bytes; add a `dpa:hex:encode` step to
  display them.
- For a given input, the streaming and in-memory execution paths are required to
  produce identical output. Tests enforce this.
- ChaCha20 is limited to 256 GiB of keystream per key/nonce pair (RFC 8439 uses
  a 32-bit counter); re-key before that.
- The `.dpaflow` package format and its manifest API exist in the library as
  groundwork for sharing flows. The corresponding CLI surface is disabled in
  1.0, and nothing is fetched over the network.
- `dpa run -e <YAML>` runs a flow supplied inline. It is there for scripts and
  CI that generate YAML, rather than for typing flows by hand.

## Release

- License: Apache-2.0 (see [LICENSE](LICENSE) and [NOTICE](NOTICE)).
- Local packaging (Windows): `powershell -ExecutionPolicy Bypass -File scripts\release.ps1`
  builds the release binary, assembles `dist\dpa-<ver>-x86_64-pc-windows-msvc\`,
  and writes a zip plus a `SHA256` checksum.
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
  | Linux arm64, glibc | `-aarch64-unknown-linux-gnu.tar.gz` |
  | macOS universal (arm64 + x86_64) | `-universal-apple-darwin.tar.gz` |

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
