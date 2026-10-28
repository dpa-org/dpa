# dpa — 数据处理与分析

[![CI](https://github.com/dpa-org/dpa/actions/workflows/ci.yml/badge.svg)](https://github.com/dpa-org/dpa/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/dpa-org/dpa?include_prereleases&sort=semver)](https://github.com/dpa-org/dpa/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.89%2B-orange.svg)](Cargo.toml)

[English](README.md) | 简体中文

dpa 在命令行上运行多步的数据变换与分析流程。流程是一份 YAML 文件：一串带参数的操作，
因此可以被审阅、纳入版本管理、反复运行，而不必每次重敲。

它面向会反复做同一类工作的人：解码样本、计算哈希、解析头部与证书、提取指标，并把
这些步骤跑在一个文件或整个目录上。

## 安装

- **预编译二进制**：从 [Releases](https://github.com/dpa-org/dpa/releases) 下载对应
  平台的归档。覆盖 Windows x86_64 / arm64、Linux x86_64（glibc 与静态 musl）/ arm64，
  以及 macOS 通用二进制。
- **从源码构建**：Rust 1.89 或更新版本，`cargo build --release`，产物为
  `target/release/dpa`。
- **crates.io**：`dpa` crate 名由本项目持有（当前是 0.0.0 占位）；1.0.0 发布后
  `cargo install dpa` 即可安装命令。

## 快速上手

单个操作，不写流程文件：

```console
$ cat input.txt
aGVsbG8=
$ dpa op base64:decode input.txt
hello
```

把同样的工作写成一份可保留的流程 —— `flow.yaml`：

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

`dpa list` 列出全部操作；`dpa op <名字> --help` 查看某个操作的参数。每个操作的行为
（包括有意保留的差异）见 [docs/op-semantics.md](docs/op-semantics.zh-CN.md)。

## 功能

- **流程即代码**：`dpa run flow.yaml input` 按顺序执行流程中的步骤。同一份流程可用于
  文件、标准输入或整个目录。
- **单个操作**：`dpa op <名字>` 直接运行一个操作，无需流程文件。参数取自操作自身，
  因此 `dpa op aes:decrypt --help` 会列出它的参数。
- **流式执行**：分块管道在内存中只保留一个数据块（以及必要的缓冲步骤），因此输入大小
  不受可用内存限制。
- **批量模式**：目录会展开为其中的文件（`-r` 递归），文件并行处理（`-j N`），单个
  文件失败不会中止整批。
- **233 个内置操作**，分 7 类 —— `dpa list` 查看完整列表：

  | 分类 | 内容 |
  | --- | --- |
  | `codec` | Base64/32/58/62/85、Hex、二进制/八进制/十进制、字符码、URL、HTML、quoted-printable、punycode、UTF-8/16、hexdump；gzip、zlib、deflate、Brotli、LZMA/XZ、bzip2 |
  | `crypto` | XOR、RC4、ChaCha20、AES-128/192/256（ECB/CBC/CFB/OFB/CTR/GCM）、SM4（同模式 + CMAC）、DES/3DES、Blowfish、HMAC、PBKDF2、HKDF |
  | `hash` | MD5、SHA-1/2/3、Keccak、SHAKE、BLAKE2、RIPEMD、Whirlpool、SM3、CRC、Adler-32、Fletcher、NT/LM、ssdeep |
  | `transform` | 反转、大小写、去空白、替换、ROT13、Atbash、排序/去重/拆分/筛选/取头尾、JSON/YAML/XML/CSV 互转、正则 |
  | `analyze` | 熵、频率、哈希识别、文件类型识别、IoC 提取、日期时间、TCP/UDP/IP/TLS/Ethernet 头部、X.509/CSR/SSH/ASN.1、仅验签 |
  | `generate` | 时间戳、UUID v1/v3/v4/v5、随机字节、素数、HOTP、TOTP |
  | `extract` | 日期、域名、邮箱、哈希、IP、MAC、字符串、URL |
- **可复现输出**：相同输入与显式参数在每次运行都产出相同字节。压缩输出的 gzip 头部
  固定时间与 OS 字段，时间转换统一 UTC，并行批量的输出按输入顺序写出。
- **独立交叉验证**：核心编解码 / 哈希 / 压缩 / 加密操作都与独立实现（Python 标准库、
  PyCryptodome、OpenSSL）逐条比对，差分测试在 CI 中运行。
- **国密（SM2 / SM3 / SM4）**：SM2 密钥解析、公钥提取与验签；SM3 摘要；SM4 的
  ECB/CBC/CFB/OFB/CTR/GCM 与 CMAC；HMAC-SM3、PBKDF2-SM3。
- **本地且显式**：不发起网络请求、不做遥测、无远程注册表；插件只从你指定的目录加载，
  约定目录需要显式且带警告的 opt-in。
- **Web/WASM**：`dpa-wasm` crate 在 wasm32 上运行同一引擎（见
  [docs/WASM.md](docs/WASM.zh-CN.md)）。
- **插件 ABI**：可从动态库添加操作。默认不扫描任何目录；`dpa --plugins <dir>` 加载你
  指定的目录，`--discover-plugins` 才是带警告的主动扫描选项，用于约定目录
  （见 [docs/PLUGIN.md](docs/PLUGIN.md)）。
- **Recipe 转换**：`dpa recipe convert` 读写 CyberChef 的 recipe 格式（URL、CHEF、
  JSON），便于把已有 recipe 转成流程。
- **Python 绑定**（可选 `python` feature）：`import dpa` 后在内存中运行流程。
- **消息本地化**：面向用户的文本（错误、CLI 帮助、列表输出）提供英文（默认）与
  简体中文（`--lang zh-CN` 或 `DPA_LANG=zh`）。
- **单一二进制**，无运行时依赖。

## 构建

```bash
cargo build --release
# 产物：target/release/dpa.exe
# 启用 Python 绑定：
cargo build --features python
```

## 用法

```bash
# 单个操作，不需要流程文件
dpa op base64:decode input.txt
dpa op xor --key 0x2A input.bin --output-format hex

# 用 shell 管道串起多个操作
dpa op base64:decode data.txt | dpa op hex:encode -

# 查看某个操作的参数
dpa op xor --help
dpa ops xor

# 运行流程文件
dpa run flow.yaml input.bin

# 只运行前 N 步后停止（用于检查中间输出）
dpa run flow.yaml input.bin --to-step 2

# 每步可观测：字节数、前 16 字节（hex 预览）、耗时输出到 stderr
dpa run -v flow.yaml input.bin

# 批量：目录输入，递归，4 个并行任务，输出到目录
dpa run flow.yaml input_dir -o out_dir -r -j 4

# 多个输入（输出必须是目录）
dpa run flow.yaml a.bin b.bin c.bin -o out_dir

# 批量输出到 stdout 时默认不加分隔符（保证二进制链逐字节完整）；
# 需要显式分隔文本输出时用 --batch-separator。分隔符按原样插入在两次输出之间，
# 不附带额外换行，所以文本场景请自行包含换行：PowerShell "`n---`n"
# （双引号内反引号-n 才生效）、bash $'\n---\n'。结果按输入顺序写出
# （并行工作线程，输出确定；-r 递归时顺序跟随目录遍历序，非字典序）。
# 文本场景如需可读归属，可加 --batch-label，在每段输出前打印 "==> <输入>" 行
# （同样默认关闭，不影响二进制链）
dpa run flow.yaml a.bin b.bin --batch-separator $'\n---\n' --batch-label

# 从标准输入读取（'-' 或省略输入参数）
echo "48656C6C6F" | dpa run flow.yaml

# 写入文件，以 hex 渲染
dpa run flow.yaml input.bin -o out.txt --output-format hex

# 查看操作
dpa list
dpa list -c codec        # 按分类
dpa list -s hash         # 按关键字
dpa list --full          # 不截断描述（交互默认截断为 60 字符）

# 切换消息语言
dpa --lang zh-CN list
DPA_LANG=zh dpa list

# 运行前打印每步的输入→输出估算（仅提示，输出到 stderr）
dpa run flow.yaml input.bin --explain

# 生成 shell 补全脚本
dpa --generate-completion powershell > dpa-completion.ps1
```

两三个操作时，类 Unix 系统上直接用 shell 管道最短。Windows 上 PowerShell 管道无法
原样传递二进制数据，使用前请看下面的 [Windows 管道](#windows-管道) 一节。

## 流程文件格式

```yaml
name: demo
description: 示例流程
output: hex            # raw | hex；--output-format 可覆盖
steps:
  - op: dpa:base64:decode
  - op: dpa:xor
    args:
      key: "0x2A"      # 参数值必须用引号包裹；未加引号的数字/布尔会被拒绝（会丢失 0x/0o/0b 前缀）
  - op: dpa:sha256
  - op: dpa:hex:encode
```

取值属于机密（密钥、口令）的参数，可以用 `env:NAME` 从环境变量读取，而不写进流程
文件或命令行。这样密钥材料不会出现在 shell 历史、进程列表与 recipe URL 中。
变量缺失会报错。

```yaml
  - op: dpa:hmac
    args:
      key: "env:DPA_HMAC_KEY"
      algo: sha256
```

`env:` 值由引擎本身解析，因此在 `dpa run`、`--eval` 与 Python 绑定下行为一致。

`dpa run` 还支持 `--allow-env NAME1,NAME2,...` 限制可通过
这种方式读取的环境变量白名单。流程若尝试读取白名单之外的变量，会报描述性错误。
不传 `--allow-env` 时保持旧行为（任意变量均可解析），现有流程无需改动即可继续运行；
在共享或不可信流程场景中建议使用白名单，防止 `env:` 外带意外变量。

### 流程 schema 版本

流程文件可携带可选清单（`meta:`）。其 `schema_version` 字段记录 dpa 使用的流程文件 schema 版本：

```yaml
name: demo
meta:
  schema_version: 1        # 可选；缺省视为 v1
  id: dpa:flow:demo
  version: 1.0.0
steps:
  - op: dpa:base64:decode
```

- 没有 `meta.schema_version` 的文件按 **v1** 处理（向后兼容：现有流程无需改动即可继续运行）。
- dpa 序列化带清单的流程时，总是输出当前 schema 版本（`1`）。
- 当文件的 `schema_version` **高于当前 dpa 支持的版本**时，解析会直接报错：请升级 dpa，或将流程转换回受支持的 schema（迁移通道）。

演进策略：schema 版本只增不减。仅在旧版 dpa 无法再读取文件时才提升 `schema_version`；读取流程的工具对缺失版本默认按 `1` 处理。

### 流程清单字段

流程清单（`meta:`）接受以下字段：

| 字段 | 类型 | 含义 |
|---|---|---|
| `schema_version` | 整数 | 流程文件 schema 版本；缺省视为 1（见上文） |
| `id` | 字符串 | 稳定标识，如 `dpa:flow:demo` |
| `name` | 字符串 | `id` 的别名，输入时接受（向后兼容；序列化时不输出） |
| `version` | 字符串 | 面向人的流程版本，如 `1.0.0` |
| `author` | 字符串 | 作者名或联系方式 |
| `tags` | 字符串列表 | 可检索标签 |
| `license` | 字符串 | 许可证标识 |
| `homepage` | 字符串 | 项目 / 说明页 URL |

未知字段会被拒绝（清单是严格的）。流程的显示名在顶层（`name:`），不在 `meta:`
内部；机器标识请使用 `id`。`meta.name` 作为 `meta.id` 的向后兼容别名被接受
（旧清单里写 `name` 的仍可加载；序列化时总是输出 `id`）。

## Hex：渲染层与数据层

“hex”出现在两个彼此独立的位置，混用会导致二次编码：

| 位置 | 作用 | 示例 |
|---|---|---|
| 数据层操作 `dpa:hex:encode` / `dpa:hex:decode` | 流程中的一步，把字节转成 hex 文本（或转回） | `steps: [- op: dpa:hex:encode]` |
| 管道末端渲染 `output: hex` / `--output-format hex` | 只影响流程**最终输出字节**的显示方式，不作用于每一步 | `dpa run flow.yaml in -o out --output-format hex` |

在 `dpa:hex:encode` 之上再叠加 `--output-format hex`，会把已经是 hex 文本的结果
再编码一次（hex 的 hex）。要看某一步的中间结果，用 `--to-step N` 截断流程，
或加 `-v` 预览每步输出的前 16 字节。

`--hex` 是 `--output-format hex` 的快捷开关：它只影响管道的最终渲染，绝不改变数据层，
因此 `dpa op xor --key 0x2A in.bin --hex` 与上面的 `--output-format hex` 形式等价。
交互式查看二进制结果时用 `--hex`。

最后一步产生二进制输出时，stdout 携带精确字节，`dpa op sha256 in.bin | ...`
可安全入管道。最后一步声明的输出是文本（`Utf8`、`Hex`、`Base64` 或 `Json`）时，
stdout 末尾会补一个换行，方便交互阅读；`-o <file>` 从不补换行。需要文本类操作的
精确字节时，请用 `-o` 写文件，或自行去掉末尾换行。

## Python 绑定

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

模块导出 `run`、`run_batch`、`run_file`、`list_ops` 与 `op`。批量与文件入口见
[examples/python_demo.py](examples/python_demo.py)。

## 文档

- [PLAN.md](PLAN.zh-CN.md) - 范围、架构与路线图
- [OPERATION_CONTRACT.md](OPERATION_CONTRACT.zh-CN.md) - 操作命名、参数与类型规则
- [docs/op-semantics.md](docs/op-semantics.zh-CN.md) - 算子语义规范、与主流工具的对齐项及有意差异
- [docs/WASM.md](docs/WASM.zh-CN.md) - WebAssembly 绑定的 API、构建步骤与限制
- [docs/PLUGIN.md](docs/PLUGIN.zh-CN.md) - 插件 ABI
- [docs/RECIPE_CONVERT.md](docs/RECIPE_CONVERT.zh-CN.md) - CyberChef recipe 转换边界
- [docs/FUZZ_ROADMAP.md](docs/FUZZ_ROADMAP.zh-CN.md) - 解析器模糊测试计划
- [CONTRIBUTING.md](CONTRIBUTING.zh-CN.md)、[SECURITY.md](SECURITY.zh-CN.md)、[CHANGELOG.md](CHANGELOG.md)

除变更日志外，以上每份文档都有英文原件（`*.md`）。

## 说明

- 操作标识使用命名空间 `dpa:<分类>:<名字>`，例如 `dpa:base64:decode`、`dpa:sha256`。
- 哈希操作输出原始摘要字节；需要展示时加一步 `dpa:hex:encode`。
- 解压输出受每步上限（`--max-step-output-bytes`，默认 64 MiB）约束：解压超出上限
  时报错退出，避免无界内存增长。需要更大输出时可调高上限，或设为 `0` —— `0`
  表示不限制（关闭每步上限）；解压本身是流式的。
- 未显式指定 `iv` 的分组加密（aes/sm4/des 的 CBC/CFB/OFB/CTR 模式）为兼容旧数据
  默认使用全零 IV，并在 stderr 打印一行警告：固定 IV 在同一密钥下
  多次加密可能重用密钥流。请传入随机 `iv` 或改用默认随机 IV 的 `gcm` 模式。
  解密仍保留全零默认，以便读取旧密文。
- 文本变换家族（`dpa:transform:*` —— 反转、字符操作、大小写、去空白、大小写折叠等）
  把输入当作 UTF-8 处理：非法字节会被替换为 U+FFFD 且不可逆。请勿把文本变换放进
  逐字节精确的二进制链；先校验或转码输入。
- 对同一输入，流式路径与内存路径必须产出相同结果，并有测试保证。
- ChaCha20 每对 key/nonce 的密钥流上限为 256 GiB（RFC 8439 使用 32 位计数器），
  超出前须更换 key/nonce。
- 流式 `dpa:hex:decode` 在输入结束前无法预知总长度，错误（例如奇数位）只在 finish
  阶段发现：报错前已写入 stdout 的字节属于半截输出，不可使用。消费 `hex:decode`
  输出的脚本必须检查退出码。
- KDF 边界：`pbkdf2` 的 iterations 超过 `u32::MAX` 时直接拒绝，
  不再静默截断（溢出可能把迭代次数归零）；派生长度上限 1 GiB；`hkdf` 遵守 RFC 5869
  的 255 块限制。超出任一上限都会报清晰错误。
- `.dpaflow` 包格式及其 manifest API 作为流程分享的基础保留在库中；对应的 CLI 面在
  1.0 中禁用，且不做任何网络请求。
- `dpa run -e <YAML>` 用于内联传入流程，是给生成 YAML 的脚本与 CI 用的，不适合手敲。
- Unix 管道是一等输入源与输出汇：stdout/stderr 保持干净（无进度条、无颜色转义），
  纯字节输出可直接喂给下一条命令，退出码成功为 0、失败非 0。管道形式可用
  （`dpa op base64:decode x | dpa op hex:encode -`）；不支持单命令管道串形式
  （`dpa "op1|op2"`）——需要串联多个操作时用流程文件或 `dpa run -e`。
- 用 `-o` 写文件时，若目标已存在：交互式终端会提示 `[y/N]` 确认；stdin/stdout
  被管道或重定向（脚本、CI）时静默覆盖，不打断管道。
- `dpa recipe convert` 在 URL / CHEF / JSON 三种 CyberChef recipe 格式之间转换。
  它是互操作工具，不是「CyberChef → dpa 流程」转换器；转换不校验操作是否可用，
  也不展开控制流操作。边界细节见 [docs/RECIPE_CONVERT.md](docs/RECIPE_CONVERT.md)。

### Windows 管道

- PowerShell 5.1 会给管道输出附加 UTF-8 BOM 与 CRLF，这会破坏原始字节，并让按字节计
  数的消费者意外（如 `dpa op sha256`）。管道前先设置
  `$OutputEncoding = [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)`
  （无 BOM 的 UTF-8），或用 `cmd /c` 配合 `chcp 65001` 重定向，或干脆不走管道：以
  位置参数传入文件（`dpa run flow.yaml in.bin`）。
- cmd.exe 默认使用传统 ANSI/OEM 代码页（中文 Windows 为 GBK）；先运行 `chcp 65001`
  以免 dpa 的 UTF-8 输出被错误渲染。dpa 检测到控制台代码页不是 65001（且 stdout 是
  真实控制台，不是管道或重定向）时，会向 stderr 打印一次该提示；脚本与管道场景保持
  静默。
- `dpa op <name> --help` 中的示例使用 bash 语法；请按你的 shell 调整引号与续行。

## 发布

- 许可证：Apache-2.0（见 [LICENSE](LICENSE) 与 [NOTICE](NOTICE)）。
- 本地打包（Windows）：`powershell -ExecutionPolicy Bypass -File scripts\release.ps1`
  构建 release 二进制，组装 `dist\dpa-<版本>-x86_64-pc-windows-msvc\`，并写出 zip
  与 `SHA256` 校验文件。
- 发布冒烟门禁（Windows）：`powershell -ExecutionPolicy Bypass -File scripts\release_smoke.ps1`
  对已构建的二进制断言 `--version`、`--help`、一个基本 op、一个流程运行与错误退出码；
  纯开发侧脚本，不执行 tag、打包或发布。
- 推送 `v*` tag（如 `git tag v1.0.0 && git push origin v1.0.0`）触发
  [.github/workflows/release.yml](.github/workflows/release.yml)，把带校验文件的
  预编译归档附加到 GitHub Release，文件名即目标平台三元组：

  | 平台 | 归档 |
  | --- | --- |
  | Windows x86_64 | `-x86_64-pc-windows-msvc.zip` |
  | Windows arm64 | `-aarch64-pc-windows-msvc.zip` |
  | Linux x86_64，glibc | `-x86_64-unknown-linux-gnu.tar.gz` |
  | Linux x86_64，静态（musl） | `-x86_64-unknown-linux-musl.tar.gz` |
  | Linux arm64，静态（musl） | `-aarch64-unknown-linux-musl.tar.gz` |
  | macOS 通用（arm64 + x86_64） | `-universal-apple-darwin.tar.gz` |

### 版本元数据

从 git 检出构建时，`dpa --version` 会输出包版本、构建所用的 git 提交与提交日期：

```
dpa 1.0.0 (commit 66d05b838b01, 2026-10-25)
```

- 没有 `.git` 目录的源码（如发布 tarball）退化为仅显示版本号。
- 从 dirty 工作树构建的临时二进制会在提交后追加 `-dirty`，使 `--version` 不会谎称
  构建自某个干净的提交；发布脚本会拒绝打包 dirty 工作树。
- 提交哈希由 `build.rs` 在构建时读取。cargo 的 `rerun-if-changed` 无法可靠跟踪
  `.git/` 下的文件，因此仓库内置了 post-commit 钩子：每次提交后 touch `build.rs`。
  每个 clone 安装一次：

  ```powershell
  powershell -ExecutionPolicy Bypass -File scripts\setup-git-hooks.ps1
  # 或任意平台：
  git config core.hooksPath .githooks
  ```

  `scripts\release.ps1` 在打包构建前也会 touch `build.rs`；CI 还会校验嵌入提交与打
  tag 的提交一致。

## 路线图

`1.0.0` 是首个公开发布。从此 flow 格式、操作标识与 CLI 面视为稳定；见
[OPERATION_CONTRACT.md](OPERATION_CONTRACT.md)。

- **1.x**：只做加法——新增操作、新增可选参数、新增输出形态与性能优化。改变流程文件
  或操作名的含义需要 `2.0`。
- **后续**：更多一方插件、发布到 crates.io，以及延后的流程分享面。

方向与待定问题记录在 [PLAN.md](PLAN.md)；已发布的变化记录在 [CHANGELOG.md](CHANGELOG.md)。
