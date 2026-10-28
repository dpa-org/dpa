
# dpa Op Semantics

This document is the normative reference for how dpa operators behave: where they
align with mainstream tools (CyberChef / Python / OpenSSL / RFCs), and where dpa
deliberately keeps its own behavior. The implementation and this file stay in
sync.

## 1. General principles

- **Raw bytes everywhere.** Operators consume and produce byte arrays. Text
  rendering is a presentation-layer concern; use `dpa:hex:encode` for hex, or
  `--output-format hex` for CLI rendering.
- **Deterministic defaults.** A recipe with the same input and the same explicit
  args must produce the same bytes on every run and every platform.
- **UTC for all time conversions.** No local-timezone dependence anywhere.
- **Streaming where possible.** Operators document streamable / whole-buffer
  behavior in the engine; semantics are identical in both paths.
- **Fail loudly.** Invalid input, bad padding, or malformed encodings produce an
  error instead of silent best-effort output, unless an explicit
  `ignore_non_alphabet` / `strict_mode=false` argument opts out.

## 2. Alignments with mainstream tools

These behaviors were changed to match mainstream references and are covered by
differential tests (`scripts/difftest.py`):

> **Coverage.** The differential suite targets the codec, hash, compression and
> symmetric-crypto families, where an independent reference implementation
> exists. It does not exercise every one of the 233 operations: transform,
> analyze, generate and extract operations are covered by unit tests and
> documented vectors instead. The suite prints its own `TOTAL` / `FAIL` /
> `SKIP` counts, and CI runs it with `--strict`, so a missing reference fails
> the job instead of being skipped silently.

| Operator | Semantics | Reference |
| --- | --- | --- |
| `dpa:filetime` | Windows FILETIME = 100ns ticks since 1601-01-01, little-endian hex. `dpa:filetime:from:unix` converts Unix s/ms/us to FILETIME; `dpa:filetime:to:date` renders UTC date. | CyberChef "Filetime" |
| `dpa:xxhash32` / `dpa:xxhash64` | Digest bytes are emitted **big-endian** (matches the xxHash reference and CyberChef output). | xxHash spec / CyberChef |
| `dpa:split` | Splits on a delimiter and joins segments with `\n`; a trailing delimiter does **not** produce a trailing empty segment. | CyberChef "Split" |
| `dpa:tea:encode` / `dpa:tea:decode` (`dpa:xtea:*`, `dpa:xxtea:*`) | 64-bit block cipher family with selectable padding: `zero` (legacy default), `pkcs7`, `none` (strict; errors on non-aligned input). Decode validates pkcs7 and errors on bad padding. | CyberChef TEA/XTea/XXTEA + PKCS#7 |

## 3. Intentional divergences (kept on purpose)

These differ from some mainstream tools by design. They are documented here so
the choice is explicit, not accidental.

| Operator | dpa behavior | Why |
| --- | --- | --- |
| `dpa:gzip` | Header `MTIME = 0` and `OS = 0xff` unless overridden with `timestamp` / `os` args. | Byte-stable, reproducible output; no wall-clock leakage. CyberChef embeds current time/OS by default. |
| `dpa:timestamp` / `dpa:filetime:*` / date ops | All conversions use **UTC** and render `YYYY-MM-DD HH:MM:SS`. | Deterministic across timezones; recipes do not depend on the machine's locale. |
| `dpa:utf16:encode` / `dpa:utf16:decode` | No BOM is emitted by default; `bom=true` opts in. | Matches raw byte expectations; BOM is optional by design in UTF-16. |
| `dpa:base32:decode` (and base64/hex/binary family) | Strict by default: non-alphabet bytes fail unless `ignore_non_alphabet=true`; `strict_mode` controls padding validation. | Fail loudly instead of silently dropping corrupt data. |
| Hash family (`dpa:md5`, `dpa:sha256`, ...) | Operators emit **raw digest bytes**. `dpa:hex:encode` (or `--output-format hex`) renders hex. | Single data-layer contract; avoids double-encoding confusion. |

## 4. Divergence index (quick lookup)

| Topic | Mainstream default | dpa default | Where |
| --- | --- | --- | --- |
| gzip header time | current Unix time | `0` | `dpa:gzip` |
| gzip header OS | host OS | `0xff` | `dpa:gzip` |
| xxhash32/64 output endian | little-endian bytes in some libs | big-endian | `dpa:xxhash32`, `dpa:xxhash64` |
| split trailing delimiter | some tools keep empty tail | dropped | `dpa:split` |
| TEA/XTea/XXTEA padding | zero-fill only | `zero` / `pkcs7` / `none` | tea family |
| time/date rendering | local time | UTC | `dpa:timestamp`, `dpa:filetime` |
| UTF-16 BOM | varies | none (opt-in) | `dpa:utf16:*` |
| base32/base64 decode strictness | varies, often lenient | strict (opt-out) | codec family |
| hash output | sometimes hex | raw bytes | hash family |

## 5. Edge cases and bounds

- **FILETIME range**: values are `u64`; negative Unix times are rejected.
  `filetime:from:unix` accepts `s` (default) / `ms` / `us` and emits
  little-endian hex or decimal (`format=dec`).
- **XXTEA**: input shorter than one block is padded to a full block; `none`
  padding errors on non-aligned input.
- **gzip FHCRC**: dpa emits the optional CRC16 header field only when the
  corresponding flags are requested; the streaming and whole-buffer paths emit
  byte-identical headers for identical options.
- **base32 strict mode**: trailing bits (non-zero remainder in the final
  quantum) are rejected in strict mode; set `strict_mode=false` to accept them.
- **UTF-16 decode**: odd trailing byte, split surrogate pairs, and a split BOM
  are handled per-stream; decode of malformed input errors.
- **hash family**: all digests are raw bytes; there is no operator-level hex
  option — pipe through `dpa:hex:encode` instead.
- **datetime parse / translate**: strict by default — one invalid line fails
  the whole batch. Set `on_error=skip` to drop invalid lines and append a
  trailing `# [dpa] skipped N invalid line(s)` summary comment. Accepted forms
  include minute precision (`2024-01-02 03:04`), slash-separated dates
  (`2026/10/02 14:05`), and fractional seconds (truncated to whole seconds).
- **extract:domains**: by default filters pseudo-TLDs that are common file
  extensions (`app.js`, `style.css`) so path fragments are not reported as
  domains; set `filter_ext_tlds=false` to keep the old permissive behavior.
  `extra_tld_blacklist` adds a comma-separated, case-insensitive TLD
  blacklist.
- **analyze:file:type**: when no magic signature matches, falls back to a text
  sniff (ASCII / UTF-8 / UTF-16 LE/BE) and annotates the newline style
  (`LF` / `CRLF` / `None`); truly opaque buffers still report
  `Unknown file type`.

## 6. Removed ops and equivalent flows

These ops were removed from the registry; use the equivalent flow composition
instead.

| Removed op | Equivalent flow |
| --- | --- |
| `dpa:hex:to:pem` | `dpa:hex:decode` → `dpa:pem` (action=encode, label=...) |
| `dpa:pem:to:hex` | `dpa:pem` (action=decode) → `dpa:hex:encode` |
| `dpa:lorem:ipsum` | No built-in equivalent. Use an external text source or a flow that builds the sample text from `dpa:generate:random` / literal input. |

