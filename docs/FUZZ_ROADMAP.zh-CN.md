# 模糊测试路线图

> 属性测试已随源码落地；持续模糊测试管道正在规划，且只依赖 stable 工具链。

## 背景

`dpa` 在多个位置消费不可信字节：YAML flow 文件、codec 解码路径、ASN.1 / X.509 /
JSON / regex 解析器以及密码学原语。经典模糊测试路线（`cargo-fuzz` + libFuzzer）
要求 **nightly** Rust 工具链。构建、测试与发布门禁刻意只允许 stable，因此不引入 nightly 依赖。

## 现有覆盖

| 面 | 工具 | 断言内容 |
| --- | --- | --- |
| codec 编解码 | `proptest`（`tests/proptest_parsers.rs`） | hex、base32/45/58/62/64/64url/85、pem、qp、url 满足 `decode(encode(x)) == x` |
| crypto | `proptest`（`tests/proptest_parsers.rs`） | xor 对合、AES-CTR / ChaCha20 / RC4 往返、hash 长度不变量、HMAC 确定性 |
| 解析器 | `proptest`（`tests/proptest_parsers.rs`） | ASN.1、X.509、JSON、PKCS#1<->PKCS#8、regex 对任意字节"绝不 panic" |
| 已知向量 | 普通测试（`tests/proptest_parsers.rs`） | FIPS 180-4 SHA-256、RFC 4231 HMAC-SHA256、NIST SP 800-38A CTR-AES128 |

## 阶段

### 阶段 1 — stable harness

新增 `fuzz/` crate（stable、不依赖 nightly），提供随机字节驱动：

- 语料种子：真实 flow 文件、畸形 YAML、截断的 codec 输出；
- 不变量：`run(op, input, args)` 不得 panic、不得挂起（限制输入大小 + op 级超时预算）；
- 运行器选项：`cargo afl`（AFL++）和/或内置确定性伪随机驱动，使 CI 可复放固定种子集；
- 目标：`yaml parse flow`、`asn1:parse`、`x509`、`json:pretty`、`regex:match`、
  全部 codec `*:decode`、`hexdump:decode`。

### 阶段 2 — 经 cargo-fuzz 接入 libFuzzer

在引入独立 nightly CI runner 后：

- 新增与阶段 1 目标清单一致的 `cargo-fuzz` targets；
- 将 `cargo fuzz build` 接入 nightly-only 工作流；
- stable 门禁保持不动——构建/测试/发布永不要求 nightly。

### 阶段 3 — 语料与回归卫生

- 提交少量有价值语料（edge-case YAML、截断 DER/JSON、病态 base85）到 `fuzz/corpus/`；
- 上游发现的每个崩溃先最小化，再作为 `tests/` 中的单元测试加入，然后才修；
- 阶段 2 稳定后可选接入 OSS-Fuzz。

## 明确不做的事

- build / test / clippy / fmt 门禁不引入 nightly 工具链。
- 库内不放模糊循环：harness 一律放 `fuzz/`，绝不进入 `src/`。
