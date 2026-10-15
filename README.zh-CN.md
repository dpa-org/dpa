# dpa — 数据处理与分析

[English](README.md) | 简体中文

dpa 在命令行上运行多步的数据变换与分析流程。流程是一份 YAML 文件：一串带参数的操作。
因为流程是文件，它就可以被审阅、纳入版本管理、反复运行，而不必每次重敲。

## 功能

- **流程即代码**：`dpa run flow.yaml input` 按顺序执行流程中的步骤。同一份流程可用于
  文件、标准输入或整个目录。
- **单个操作**：`dpa op <名字>` 直接运行一个操作，无需流程文件。参数取自操作自身，
  因此 `dpa op aes:decrypt --help` 会列出它的参数。
- **流式执行**：分块管道在内存中只保留一个数据块（以及必要的缓冲步骤），因此输入大小
  不受可用内存限制。
- **批量模式**：目录会展开为其中的文件（`-r` 递归），文件并行处理（`-j N`），单个
  文件失败不会中止整批。
- **218 个内置操作**，分 7 类（`codec` / `transform` / `hash` / `crypto` / `analyze` /
  `generate` / `extract`）：
  - `codec`：Base64（标准、URL 安全或自定义字母表）、Base32、Base58、Base62、Base85、
    Hex、二进制、八进制、十进制、字符码、URL、HTML、quoted-printable、punycode、
    UTF-8、UTF-16、hexdump；gzip、zlib、原始 deflate、Brotli、LZMA/XZ、bzip2
  - `crypto`：XOR、RC4、ChaCha20、AES-128/192/256（ECB、CBC、CFB、OFB、CTR、GCM）、
    SM4、DES、3DES、Blowfish、HMAC（SHA-1/256/512）、PBKDF2、HKDF
  - `hash`：MD5、SHA-1、SHA-2、SHA-3、Keccak、SHAKE、BLAKE2、RIPEMD、Whirlpool、SM3、
    CRC-16/32/32C、Adler-32、Fletcher、NT、LM、ssdeep
  - `transform`：反转、大小写、去空白、替换、ROT13、Atbash、替换表、排序、去重、拆分、
    筛选、取头尾、JSON 美化、JSON 压缩、JSON 路径提取、正则匹配、正则替换、CSV 与
    JSON 互转、YAML 与 JSON 互转、XML 与 JSON 互转
  - `analyze`：熵、字节频率、哈希识别、按魔数识别文件类型、IoC 提取、日期时间解析、
    TCP/UDP/IPv4/IPv6/TLS/Ethernet 头部解析、X.509 / CSR / SSH / ASN.1 解析，以及仅验签
  - `generate`：时间戳、UUID v4、随机字节、素数、HOTP、TOTP
- **Web/WASM**：`dpa-wasm` crate 在 wasm32 上运行同一引擎。
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
# 产物：target/release/dpa-cli.exe（安装后命名为 dpa.exe）
# 启用 Python 绑定：
cargo build --features python
```

二进制名为 `dpa-cli`，所以 `cargo install dpa` 装出来的命令是 `dpa-cli`；
下面的预编译归档会将其重命名为 `dpa`。

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

# 批量：目录输入，递归，4 个并行任务，输出到目录
dpa run flow.yaml input_dir -o out_dir -r -j 4

# 多个输入（输出必须是目录）
dpa run flow.yaml a.bin b.bin c.bin -o out_dir

# 从标准输入读取（'-' 或省略输入参数）
echo "48656C6C6F" | dpa run flow.yaml

# 写入文件，以 hex 渲染
dpa run flow.yaml input.bin -o out.txt --output-format hex

# 查看操作
dpa list
dpa list -c codec        # 按分类
dpa list -s hash         # 按关键字

# 切换消息语言
dpa --lang zh-CN list
DPA_LANG=zh dpa list
```

两三个操作时，类 Unix 系统上直接用 shell 管道最短。Windows 上 PowerShell 管道无法
原样传递二进制数据，用一份小流程文件更可靠。

## 流程文件格式

```yaml
name: demo
description: 示例流程
output: hex            # raw | hex；--output-format 可覆盖
steps:
  - op: dpa:base64:decode
  - op: dpa:xor
    args:
      key: "0x2A"      # 参数值：字符串 / 数字 / 布尔
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

批量与文件入口见 [examples/python_demo.py](examples/python_demo.py)。

## 说明

- 操作标识使用命名空间 `dpa:<分类>:<名字>`，例如 `dpa:base64:decode`、`dpa:sha256`。
- 哈希操作输出原始摘要字节；需要展示时加一步 `dpa:hex:encode`。
- 对同一输入，流式路径与内存路径必须产出相同结果，并有测试保证。
- ChaCha20 每对 key/nonce 的密钥流上限为 256 GiB（RFC 8439 使用 32 位计数器），
  超出前须更换 key/nonce。
- `.dpaflow` 包格式及其 manifest API 作为流程分享的基础保留在库中；对应的 CLI 面在
  1.0 中禁用，且不做任何网络请求。
- `dpa run -e <YAML>` 用于内联传入流程，是给生成 YAML 的脚本与 CI 用的，不适合手敲。

## 发布

- 许可证：Apache-2.0（见 [LICENSE](LICENSE) 与 [NOTICE](NOTICE)）。
- 本地打包（Windows）：`powershell -ExecutionPolicy Bypass -File scripts\release.ps1`
  构建 release 二进制，组装 `dist\dpa-<版本>-x86_64-pc-windows-msvc\`，并写出 zip
  与 `SHA256` 校验文件。
- 推送 `v*` tag（如 `git tag v1.0.0 && git push origin v1.0.0`）触发
  [.github/workflows/release.yml](.github/workflows/release.yml)，把带校验文件的
  预编译归档附加到 GitHub Release，文件名即目标平台三元组：

  | 平台 | 归档 |
  | --- | --- |
  | Windows x86_64 | `-x86_64-pc-windows-msvc.zip` |
  | Windows arm64 | `-aarch64-pc-windows-msvc.zip` |
  | Linux x86_64，glibc | `-x86_64-unknown-linux-gnu.tar.gz` |
  | Linux x86_64，静态（musl） | `-x86_64-unknown-linux-musl.tar.gz` |
  | Linux arm64，glibc | `-aarch64-unknown-linux-gnu.tar.gz` |
  | macOS 通用（arm64 + x86_64） | `-universal-apple-darwin.tar.gz` |

## 路线图

`1.0.0` 是首个公开发布。从此 flow 格式、操作标识与 CLI 面视为稳定；见
[OPERATION_CONTRACT.md](OPERATION_CONTRACT.md)。

- **1.x**：只做加法——新增操作、新增可选参数、新增输出形态与性能优化。改变流程文件
  或操作名的含义需要 `2.0`。
- **后续**：更多一方插件、发布到 crates.io，以及延后的流程分享面。

方向与待定问题记录在 [PLAN.md](PLAN.md)；已发布的变化记录在 [CHANGELOG.md](CHANGELOG.md)。
