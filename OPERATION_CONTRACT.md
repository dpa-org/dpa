# Operation Contract

[简体中文](OPERATION_CONTRACT.zh-CN.md) | English

This document defines how operations in dpa are named, parameterized, and typed.
It is the reference to consult before adding an operation, adding an argument, or
changing a data format, so that the operation set stays consistent as it grows.

## 1. Operations versus arguments

The question that decides it: **does this choice change what a downstream step
can do with the value?** If yes, it is a separate operation. If no, it is an
argument.

| Kind | Criterion | Example |
| --- | --- | --- |
| Operation | Inverse directions of the same transform | encrypt / decrypt, encode / decode, compress / decompress |
| Operation | Different algorithm family | AES vs SM4 vs DES; Base64 vs Base32 |
| Operation | Output shape changes the type of downstream input | a hex string can be fed to `hex:decode`; raw bytes cannot |
| Argument | Quantitative configuration of one transform | length, count, unit, language, character set |
| Argument | Internal strategy of one transform | mode (ecb/cbc/ctr), padding, endianness, compression level, delimiter |
| Argument or display layer | Affects only how a human reads the output | hex / UTF-8 / binary rendering — not an operation |

Before adding an argument, confirm it does not change the downstream input type.
If it does, split the operation, or give it `Variant` / `Shortcut` level (§3).

## 2. Naming

- Full name, used in storage and flows: `dpa:<category>:<family>:<action>`, for
  example `dpa:gzip:compress`.
- The display layer drops the `dpa:` prefix: `gzip:compress`,
  `base64:url:decode`.
- The prefix is optional wherever an operation is *referenced* — a flow step, a
  `dpa op` call, or `dpa ops` — so `xor` and `dpa:xor` mean the same thing.
  Names are always stored and printed in the full form.
- There are seven top-level categories: `analyze`, `codec`, `crypto`, `extract`,
  `generate`, `hash`, `transform`. Internal modules that do not match a category
  name (`cipher`, `compress`, `datetime`, `json`, `protocol`, `pubkey`, `random`,
  `regex`) are filed under the closest one — for example `compress` under
  `codec`, `datetime` under `analyze`.
- Actions use a small, lowercase, fixed vocabulary: `encode`, `decode`,
  `compress`, `decompress`, `encrypt`, `decrypt`, `parse`, `extract`,
  `generate`, `hash`, `transform`, `format`, `minify`, `pretty`, `get`,
  `replace`, `match`, `translate`, `delta`. A colon marks a sub-path
  (`to:json`, `to:date`); hyphens are used only where a compound cannot be
  avoided.
- Different alphabets of the same family are an argument (`alphabet`), not
  separate operations. Convenience aliases, where they are justified, get
  `Variant` or `Shortcut` level.

## 3. The `family`, `kind`, and `level` fields

Every `Op` carries three derived dimensions. The registration macros accept them
explicitly, or derive them from the name:

- **`family`** — the technical family, such as `gzip`, `base64`, `sm4`, `parse`,
  `timestamp`. Operations in one family share an algorithm core and its presets.
- **`kind`** — the action, such as `encode`, `decode`, `compress`, `encrypt`,
  `parse`, `ethernet`, `to:date`. Used for filtering and for CLI grouping.
- **`level`** — `Primary`, `Variant`, or `Shortcut`:
  - `Primary`: an independent transform (`aes:encrypt`, `base64:decode`);
  - `Variant`: a different direction or shape within a family that cannot be
    reduced further (`base64:url:encode`);
  - `Shortcut`: a combination exposed for convenience (`random:hex` is `random`
    followed by `hex:encode`). Shortcuts count toward their family rather than
    as separate operations.

Derivation, when the macros are not given the values:

| Name | `family` | `kind` |
| --- | --- | --- |
| `dpa:gzip:compress` | `gzip` | `compress` |
| `dpa:base64:url:decode` | `base64` | `url:decode` |
| `dpa:parse:ethernet` | `parse` | `ethernet` |
| `dpa:timestamp:to:date` | `timestamp` | `to:date` |
| `dpa:md5` (no family segment) | the category (`hash`) | `md5` |

A `kind` containing a sub-path (`url:decode`, `to:date`, `to:pem`) yields
`Variant`; everything else defaults to `Primary`. `Shortcut` is always marked
explicitly at the registration site.

`Op` is `{ name, category, family, kind, level, description, args,
run, stream }`. `dpa list` prints Category / Family / Kind / Op / Description;
`dpa ops <name>` prints the family, kind, and level. Run `dpa list` for the
current counts.

## 4. Data format contract

- Values between steps are **raw bytes**. The format of an argument is declared
  explicitly through `ArgSpec.format`:
  - `utf8` (the default): the argument is taken as UTF-8 text;
  - `hex`: a hex string; an optional `0x` / `0X` prefix is stripped and interior
    whitespace is tolerated;
  - `hex-or-utf8`: a `0x` / `0X` prefix means hex, anything else means UTF-8
    text. Key, IV, nonce, tag, and salt arguments use this form;
  - `base64`: standard Base64 with padding;
  - `number`, `bool`: integer and boolean literals.
- `utf8` is the default, so it is not written out at construction sites.
  `dpa ops <name>` shows `(format: ...)` only for non-default formats.
- Decoding operations emit raw bytes and never substitute invalid sequences with
  a replacement character.
- Operations declare the shape of their input and output through `OpIO`, whose
  values are `Unspecified`, `Raw`, `Utf8`, `Hex`, `Base64`, and `Json`:
  - the engine checks the chain statically (`check_io_chain`, called from both
    the whole-buffer and streaming entry points). Only adjacent *strong* types
    take part: `Raw` accepts any bytes and constrains nothing upstream, and
    `Unspecified` is skipped. A mismatch raises `err.type_mismatch` and suggests
    an explicit conversion step — for example `random` followed by `hex:decode`
    reports that a `hex:encode` step is missing. `fork` is a control step and is
    skipped;
  - `dpa ops <name>` shows `input:` / `output:` for anything other than
    `Unspecified`.

## 5. Codec parameters

| Operation | Arguments |
| --- | --- |
| base64:encode / decode | encode: `alphabet` (18 presets, custom, or range expansion), `pad`; decode: `alphabet`, `ignore_non_alphabet`, `strict_mode` |
| base64:url:encode / decode | encode: fixed URL-safe alphabet; decode: `alphabet` (URL-safe by default, overridable), `ignore_non_alphabet`, `strict_mode` |
| base32 / base58 / base62 / base85 | encode: `alphabet` (preset, custom, or range expansion), plus `pad` or `remove_zeros` where applicable; decode: `alphabet`, `ignore_non_alphabet`, and `strict_mode` where applicable |
| hex / binary / octal / decimal | encode: `delimiter` (hex also `uppercase`, `bytes_per_line`); decode: `delimiter`, `ignore_non_alphabet` |
| charcode | encode / decode: `delimiter`, `base` (decimal, octal, binary; `0x` prefixes are recognized automatically) |
| html | decode: `mode` (named, numeric, both); encode: no arguments |
| hexdump | encode: `bytes_per_line` (8 to 64, a multiple of 8; 16 by default); decode: `delimiter` (space, comma, none) |
| url | encode: `preserve_unreserved`, `use_plus`; decode: `use_plus` (`+` as space) |
| qp | encode: `wrap`, `header_mode`, `encode_all`; decode: `header_mode` |
| utf8 | escape: `encode_all`, `uppercase`; unescape: no arguments |
| punycode | encode / decode: `use_prefix` (bare output by default; `true` adds `xn--`; decode rejects input without the prefix) |
| utf16 | encode / decode: `endian`, `bom` |
| yaml:to-json / json:to-yaml / xml:to-json / json:to-xml | no arguments |

## 6. Coverage policy

How much depth an operation gets is decided per operation, not by comparison with
any other tool, and it is recorded when the operation is added:

| Tier | Applies to | Depth expected |
| --- | --- | --- |
| Core | Operations that appear in typical flows (encoding, common hashes, symmetric encryption, text transforms) | Argument set and edge-case behavior are worked out in full |
| Supporting | Narrower operations that still need to work, such as `de:bruijn`, `prime`, `hotp`, `totp` | Correct and usable; parameter depth is not pursued |
| Out of scope | Operations unrelated to the tool's purpose | Not implemented, and not promised in the docs |

Operations are tiered so that effort goes to the operations that carry flows
rather than to surface coverage.

## 7. Adding an argument

1. Parse arguments in the run function (`args`), validating booleans through an
   explicit true/false mapping, checking integer ranges, and using dedicated
   `parse_*` helpers for enumerated values.
2. Extract a pure `*_with(input, params)` function that does the computation.
3. In the streaming struct, hold the parsed parameters, parse them once in the
   `make_*` constructor, and pass them through `write` and `finish`, so chunked
   input and whole-buffer input agree.
4. Declare the argument in the registration site's `ArgSpec` array, including
   its default and allowed values.
5. Add the description to both `i18n/en.ftl` and `i18n/zh-CN.ftl`, along with any
   new `err.*` keys, and register new short keys in the `EN_SHORT_KEYS` list.
6. Add tests: default behavior, each option, a round trip where one applies,
   agreement between the streaming and in-memory paths, and rejection of invalid
   values.

## 8. Quality contract

- `cargo test --lib` passes before anything is merged, and the streaming and
  in-memory paths produce identical output for the same input.
- Every operation and argument description has a Simplified Chinese translation;
  the `zh_covers_all_op_descriptions` test fails otherwise, and every key in
  `EN_SHORT_KEYS` must exist in both resource files.
- After a change to the binary, rebuild and check the CLI end to end: `dpa list`,
  `dpa ops <name>`, and a `dpa run` round trip, including rejection of invalid
  arguments.
- A new argument must leave existing behavior unchanged: an input that does not
  use the new argument produces the same result as before.

## 9. Argument model

`ArgSpec` is a stable four-field structure: `name`, `required`, `description`,
`format`.

- **Fields are frozen.** `ArgSpec` is built as a struct literal in more than 330
  places, so a new required field would silently break all of them. Any field
  must be added through a constructor (`ArgSpec::new`, `ArgSpec::with_format`) or
  given a `Default`.
- **Defaults, allowed values, and validation** remain the responsibility of each
  operation's argument parsing rather than becoming `ArgSpec` fields. Adding such
  a field would first require converting the existing literals to the constructor
  family.
- **Required-ness** is checked inside each operation, which returns a localized
  error; the engine does not enforce it.
- `tests/api_contract.rs` pins the public shapes of the engine, registry,
  `ArgSpec`, `Op`, recipe handling, i18n, and `Flow`, so an accidental change
  fails in CI.
