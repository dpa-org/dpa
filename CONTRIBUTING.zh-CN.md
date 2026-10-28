# 为 dpa 贡献

[English](CONTRIBUTING.md) | 简体中文

欢迎提交 issue 与 pull request。

## 开始之前

- 先读 [OPERATION_CONTRACT.md](OPERATION_CONTRACT.zh-CN.md)。操作命名、参数与数据
  格式都以它为准，不符合的改动通常会被退回。
- 新增操作前先确认没有重复：`dpa list`、`dpa list -s <关键字>`、`dpa ops <名字>`。
- 超出修 bug 或单个操作范围的改动，请先开 issue，把改动形态谈清楚。

## 构建与测试

```bash
cargo build --release          # 产物：target/release/dpa(.exe)
cargo test --workspace
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
```

CI 会在每次 push 与 pull request 上运行这四条命令。

## 新增操作

1. 在对应的 `src/ops/*.rs` 模块中写执行函数。保持它是纯粹的
   `input + args -> output` 函数，并用 `ArgSpec` 声明参数。
2. 若该操作可增量处理，同时实现 `StreamingOp` 路径，并保证两条路径对同一输入产出
   相同结果。
3. 用一行 `op!`（或 `stream_op!`）注册，带上 `family`、`kind` 与描述。
4. 任何新增的面向用户文本都要补简体中文翻译，否则
   `zh_covers_all_op_descriptions` 测试会失败。
5. 补测试：默认行为、每个选项、适用时的往返、以及流式与内存路径一致。

详细做法见 [OPERATION_CONTRACT.md](OPERATION_CONTRACT.zh-CN.md) 第 7 节。

## Pull request

- 控制改动范围：一个操作、一处修复或一次重构。
- 既有行为保持不变。新行为放在新参数后面，并给出向后兼容的默认值。
- 若改动触及公共面（`engine`、`registry`、`ArgSpec`、`Op`、`recipe`、`i18n`、
  `Flow`），请在描述中说明。这些形状由 `tests/api_contract.rs` 钉住。
- 文档属于改动的一部分。若文档中的说法与代码不再一致，请在同一处 pull request 内
  修正。

## 许可

贡献按 [Apache-2.0](LICENSE) 许可接受。
