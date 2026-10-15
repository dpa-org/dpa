# dpa — Project Plan

[简体中文](PLAN.zh-CN.md) | English

This document records what dpa is, what it deliberately leaves out, and where it
is going. It is a working document: the direction can change as the tool is
used. Implementation rules live in [OPERATION_CONTRACT.md](OPERATION_CONTRACT.md),
the plugin interface in [docs/PLUGIN.md](docs/PLUGIN.md), and released changes in
[CHANGELOG.md](CHANGELOG.md).

## 1. What dpa is

dpa is a command-line tool for multi-step data transformation and analysis. Its
unit of work is a **flow**: a YAML file listing operations and their arguments.

A flow is a file rather than a one-off command for a simple reason: a
transformation that matters tends to be repeated, shared, or needed again
months later, and a file can be reviewed, versioned, and rerun.

The built-in operation set is broad because the steps that make up this kind of
work span several areas — decoding, hashing, symmetric crypto, parsing, and
extraction — and a flow usually crosses more than one of them.

## 2. Scope

In scope:

- transformations and analyses over bytes and text: codecs, compression,
  hashes, symmetric crypto, key derivation, text and structured-data
  transforms, data generation, and parsing of common formats;
- running those steps over a single input, a batch of files, or a directory
  tree, with output that can be piped or written to files;
- describing all of the above in a flow file that is meant to be kept.

Out of scope:

- **Key management and signing.** Public-key support is limited to parsing and
  to verifying existing signatures. Generating keys or producing signatures is
  left to dedicated tools.
- **Network features.** There is no remote registry and no network access at
  run time. The `.dpaflow` package format and manifest API exist in the library
  as groundwork, but the corresponding CLI surface is disabled.
- **A graphical interface.** The WebAssembly target is an engine binding, not a
  user interface.

## 3. Design principles

- **Local by default.** No network calls, no telemetry, no remote registry.
  Plugins load only from a directory named on the command line; the conventional
  plugin locations are read only when explicitly requested.
- **Composable in a shell.** Output is raw bytes by default, so a flow can be
  piped into another program without an adapter.
- **Two execution paths, one result.** For the same input, the streaming path
  and the in-memory path must produce identical output. This is checked by
  tests rather than assumed.
- **Formatting follows a written contract.** Operation naming, arguments, and
  the data shape between steps are specified in
  [OPERATION_CONTRACT.md](OPERATION_CONTRACT.md) so the set stays consistent as
  it grows.
- **Adding an operation should be cheap.** One run function plus one registration
  line, with no build-system or interface work.

## 4. Architecture

- **Core engine** (the `dpa` crate): a registry of operations behind a common
  interface. Each operation provides a whole-buffer path and, where it is
  meaningful, a streaming path. The engine handles flow parsing, input
  expansion, parallelism, message localization, and the type check between
  consecutive steps.
- **CLI** (the `dpa-cli` binary, installed as `dpa`): `run`, `list`, `ops`, and
  `recipe convert`.
- **Bindings**: the `dpa-wasm` crate for wasm32 and optional pyo3 bindings for
  Python. Both call the same engine, so behavior cannot drift between targets.
- **Plugins**: a small C ABI for operations built outside the main crate.

## 5. Related work

Several established tools solve adjacent problems, and it is worth being clear
about the overlap:

- `jq` and similar tools query and transform structured data with a terse
  expression language;
- Miller and CSV-oriented toolkits work on record streams in tabular formats;
- CyberChef provides an interactive, browser-based recipe builder;
- Pandoc, FFmpeg, and ImageMagick convert between formats in their own domains;
- binwalk and radare2 operate on binaries and firmware.

dpa does not set out to replace any of them. It targets the case where a
transformation is a *chain* of steps that should be stored as a file and run
again — including over many files at once — and where the steps cross the
boundaries between those tools.

Writing this as a flow file is also the main cost: for a single step, a direct
command is usually shorter.

## 6. Status and limitations

- The operation set and the flow format are still new. `1.0.0` declares them
  stable for the purpose of compatibility, not as a claim about maturity.
- Operation coverage is uneven. Common steps are covered in depth; some areas
  contain a few operations that are correct but shallow.
- Discovery is manual. There is no site that documents every operation; `dpa
  list`, `dpa list -s <keyword>`, and `dpa ops <name>` are the interface.
- Performance has not been benchmarked publicly. The streaming design bounds
  memory use, but throughput numbers are not published.

The long-term aim is a tool that is broadly useful for this kind of work. It is
not that yet.

## 7. Roadmap

- **1.x**: additive changes only — new operations, new optional arguments, new
  output forms, and performance work. Changing the meaning of a flow file or an
  operation name would require `2.0`.
- **Later**: more first-party plugins, a crates.io release, and the postponed
  flow-sharing surface, once there is a concrete reason to move past
  strictly-local operation.

## 8. License and contributing

dpa is licensed under [Apache-2.0](LICENSE). Attribution for material derived
from CyberChef is recorded in [NOTICE](NOTICE). See
[CONTRIBUTING.md](CONTRIBUTING.md) for how to build, test, and add an operation.
