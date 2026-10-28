# Contributing to dpa

[简体中文](CONTRIBUTING.zh-CN.md) | English

Issues and pull requests are welcome.

## Before you start

- Read [OPERATION_CONTRACT.md](OPERATION_CONTRACT.md). Operation naming,
  arguments, and data formats follow it, and a change that does not is usually
  sent back.
- Before adding an operation, check whether one already exists: `dpa list`,
  `dpa list -s <keyword>`, `dpa ops <name>`.
- For anything larger than a bug fix or a single operation, open an issue first
  so the shape of the change can be agreed on.

## Build and test

```bash
cargo build --release          # binary: target/release/dpa(.exe)
cargo test --workspace
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
```

CI runs these four commands on every push and pull request.

## Adding an operation

1. Write the run function in the relevant `src/ops/*.rs` module. Keep it a pure
   `input + args -> output` function and declare its arguments with `ArgSpec`.
2. If the operation can work incrementally, implement the `StreamingOp` path too,
   and make sure both paths produce identical output for the same input.
3. Register it with one `op!` (or `stream_op!`) line, with `family`, `kind`, and
   a description.
4. Add the Simplified Chinese translation for any new user-facing string; the
   `zh_covers_all_op_descriptions` test fails if it is missing.
5. Add tests: default behavior, each option, a round trip where one applies, and
   agreement between the streaming and in-memory paths.

Section 7 of [OPERATION_CONTRACT.md](OPERATION_CONTRACT.md) covers this in detail.

## Pull requests

- Keep the change scoped: one operation, one fix, or one refactor.
- Existing behavior stays as it is. New behavior goes behind a new argument with
  a backwards-compatible default.
- If the change touches the public surface (`engine`, `registry`, `ArgSpec`,
  `Op`, `recipe`, `i18n`, `Flow`), say so in the description. Those shapes are
  pinned by `tests/api_contract.rs`.
- Documentation is part of the change. If a claim in the docs no longer matches
  the code, fix it in the same pull request.

## License

Contributions are accepted under the [Apache-2.0](LICENSE) license.
