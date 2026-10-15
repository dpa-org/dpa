# 操作契约

[English](OPERATION_CONTRACT.md) | 简体中文

本文档规定 dpa 中操作（op）的命名、参数与类型。新增操作、给操作加参数、改动数据格式
之前，应先对照本文档，使操作集在扩张过程中保持一致。

## 1. 操作与参数的划分

判据是一句话：**这个选择会不会改变下游步骤能用它做什么？** 会，就拆成独立操作；
不会，就是参数。

| 类型 | 判据 | 例子 |
| --- | --- | --- |
| 操作 | 同一变换的互逆方向 | encrypt / decrypt、encode / decode、compress / decompress |
| 操作 | 算法族不同 | AES 与 SM4 与 DES；Base64 与 Base32 |
| 操作 | 输出形态改变下游输入的类型 | hex 字符串可交给 `hex:decode`，原始字节不行 |
| 参数 | 同一变换的量化配置 | 长度、数量、单位、语言、字符集 |
| 参数 | 同一变换的内部策略 | mode（ecb/cbc/ctr）、padding、端序、压缩级别、分隔符 |
| 参数或显示层 | 只影响人怎么看输出 | hex / UTF-8 / binary 渲染，不作为操作 |

加参数之前先确认它不改变下游输入类型；若会改变，就拆操作，或定级为
`Variant` / `Shortcut`（见 §3）。

## 2. 命名

- 全名（用于存储与流程引用）：`dpa:<分类>:<家族>:<动作>`，例如 `dpa:gzip:compress`。
- 展示层去掉 `dpa:` 前缀：`gzip:compress`、`base64:url:decode`。
- 凡是在**引用**操作的地方——流程步骤、`dpa op` 调用、`dpa ops`——前缀都可以省略，
  即 `xor` 与 `dpa:xor` 等价。存储与打印时一律使用全名。
- 顶层分类固定为七个：`analyze`、`codec`、`crypto`、`extract`、`generate`、
  `hash`、`transform`。与分类名不一致的内部模块（`cipher`、`compress`、
  `datetime`、`json`、`protocol`、`pubkey`、`random`、`regex`）按语义归入最接近的
  分类——例如 `compress` 归 `codec`、`datetime` 归 `analyze`。
- 动作取自一份小而固定的词表，全部小写：`encode`、`decode`、`compress`、
  `decompress`、`encrypt`、`decrypt`、`parse`、`extract`、`generate`、`hash`、
  `transform`、`format`、`minify`、`pretty`、`get`、`replace`、`match`、
  `translate`、`delta`。冒号表示子路径（`to:json`、`to:date`）；只有在复合词无法
  回避时才用连字符。
- 同一家族的不同字母表是参数（`alphabet`），不是独立操作。确有必要的便捷别名，
  定级为 `Variant` 或 `Shortcut`。

## 3. `family`、`kind`、`level` 字段

每个 `Op` 携带三个派生维度。注册宏可以显式传入，也可以从名称推导：

- **`family`**——技术家族，如 `gzip`、`base64`、`sm4`、`parse`、`timestamp`。
  同一家族的操作共享算法内核及其预设。
- **`kind`**——动作，如 `encode`、`decode`、`compress`、`encrypt`、`parse`、
  `ethernet`、`to:date`。用于筛选与 CLI 分组。
- **`level`**——`Primary`、`Variant` 或 `Shortcut`：
  - `Primary`：独立的变换（`aes:encrypt`、`base64:decode`）；
  - `Variant`：同家族内不同方向或形态、且无法再简（`base64:url:encode`）；
  - `Shortcut`：为便捷而暴露的组合（`random:hex` 即 `random` 接 `hex:encode`）。
    Shortcut 计入所属家族，不单独算作一个操作。

未显式传入时的推导规则：

| 名称 | `family` | `kind` |
| --- | --- | --- |
| `dpa:gzip:compress` | `gzip` | `compress` |
| `dpa:base64:url:decode` | `base64` | `url:decode` |
| `dpa:parse:ethernet` | `parse` | `ethernet` |
| `dpa:timestamp:to:date` | `timestamp` | `to:date` |
| `dpa:md5`（无家族段） | 取分类（`hash`） | `md5` |

`kind` 含子路径（`url:decode`、`to:date`、`to:pem`）即为 `Variant`，其余默认
`Primary`。`Shortcut` 一律在注册处显式标注。

`Op` 目前是 `{ name, category, family, kind, level, description, args, run,
stream }`。`dpa list` 展示 Category / Family / Kind / Op / Description 五列；
`dpa ops <名字>` 展示 family、kind 与 level。当前数量以 `dpa list` 为准。

## 4. 数据格式契约

- 步骤之间传递的值一律是**原始字节**。参数的格式由 `ArgSpec.format` 显式声明：
  - `utf8`（默认）：参数按 UTF-8 文本处理；
  - `hex`：hex 字符串，可带 `0x` / `0X` 前缀（会被剥离），中间空白容忍；
  - `hex-or-utf8`：带 `0x` / `0X` 前缀按 hex 解析，否则按 UTF-8 文本。key、IV、
    nonce、tag、salt 等参数使用这种形式；
  - `base64`：带填充的标准 Base64；
  - `number`、`bool`：整数与布尔字面量。
- `utf8` 是默认值，构造处无需写出。只有非默认格式才会在 `dpa ops <名字>` 中显示
  `(format: ...)`。
- 解码类操作输出原始字节，绝不用替换字符顶替非法序列。
- 操作通过 `OpIO` 声明其输入与输出的形态，取值为 `Unspecified`、`Raw`、`Utf8`、
  `Hex`、`Base64`、`Json`：
  - 引擎对步骤链做静态检查（`check_io_chain`，整块路径与流式路径入口都会调用）。
    只有相邻的**强类型**参与判定：`Raw` 表示接受任意字节、不约束上游，
    `Unspecified` 直接跳过。类型不一致时报 `err.type_mismatch` 并建议插入显式转换
    步骤——例如 `random` 后接 `hex:decode` 会提示缺少一步 `hex:encode`。`fork`
    是控制步骤，跳过检查；
  - `dpa ops <名字>` 对非 `Unspecified` 的项显示 `input:` / `output:`。

## 5. codec 参数

| 操作 | 参数 |
| --- | --- |
| base64:encode / decode | encode：`alphabet`（18 个预设、自定义或范围展开）、`pad`；decode：`alphabet`、`ignore_non_alphabet`、`strict_mode` |
| base64:url:encode / decode | encode：固定的 URL 安全字母表；decode：`alphabet`（默认 URL 安全字母表，可覆盖）、`ignore_non_alphabet`、`strict_mode` |
| base32 / base58 / base62 / base85 | encode：`alphabet`（预设、自定义或范围展开），按需附 `pad` 或 `remove_zeros`；decode：`alphabet`、`ignore_non_alphabet`，按需附 `strict_mode` |
| hex / binary / octal / decimal | encode：`delimiter`（hex 另有 `uppercase`、`bytes_per_line`）；decode：`delimiter`、`ignore_non_alphabet` |
| charcode | encode / decode：`delimiter`、`base`（decimal、octal、binary；自动识别 `0x` 前缀） |
| html | decode：`mode`（named、numeric、both）；encode：无参数 |
| hexdump | encode：`bytes_per_line`（8 到 64，且为 8 的倍数，默认 16）；decode：`delimiter`（space、comma、none） |
| url | encode：`preserve_unreserved`、`use_plus`；decode：`use_plus`（`+` 视为空格） |
| qp | encode：`wrap`、`header_mode`、`encode_all`；decode：`header_mode` |
| utf8 | escape：`encode_all`、`uppercase`；unescape：无参数 |
| punycode | encode / decode：`use_prefix`（默认裸输出；`true` 加 `xn--`；decode 拒绝无前缀输入） |
| utf16 | encode / decode：`endian`、`bom` |
| yaml:to-json / json:to-yaml / xml:to-json / json:to-xml | 无参数 |

## 6. 覆盖策略

每个操作做到多深，按它自身的用途决定，不与其他工具做对比，并在新增时记录归属：

| 层级 | 适用 | 深度要求 |
| --- | --- | --- |
| 核心 | 典型流程里会出现的操作（编解码、常用哈希、对称加密、文本变换） | 参数集与边界行为做完整 |
| 支撑 | 较窄但仍需可用的操作，如 `de:bruijn`、`prime`、`hotp`、`totp` | 结果正确、接口可用，不追求参数深度 |
| 不做 | 与本工具目的无关的操作 | 不实现，文档中也不承诺 |

新增操作先定归属再实现，让投入落在承载流程的操作上，而不是表面覆盖。

## 7. 新增参数的做法

1. 在执行函数（`args`）中解析参数：布尔走显式的 true/false 映射，整数做范围校验，
   枚举用专门的 `parse_*` 辅助函数。
2. 抽出只做计算的纯函数 `*_with(input, params)`。
3. 流式结构体持有解析后的参数，在 `make_*` 构造时解析一次，并在 `write` 与
   `finish` 中透传，使分块输入与整块输入结果一致。
4. 在注册处的 `ArgSpec` 数组中声明该参数，含默认值与允许取值。
5. 在 `i18n/en.ftl` 与 `i18n/zh-CN.ftl` 中补上描述与新增的 `err.*` 键，新增的短键
   同步进 `EN_SHORT_KEYS` 清单。
6. 补测试：默认行为、每个选项、适用时的往返、流式与内存路径一致、非法值被拒绝。

## 8. 质量契约

- 合入前 `cargo test --lib` 必须通过；同一输入在流式路径与内存路径下的输出必须一致。
- 每个操作与参数的描述都有简体中文翻译，否则 `zh_covers_all_op_descriptions`
  测试会失败；`EN_SHORT_KEYS` 中的键必须在两份资源文件中都存在。
- 二进制改动后重新构建并端到端验证：`dpa list`、`dpa ops <名字>`、一次 `dpa run`
  往返，含非法参数被拒绝。
- 新增参数不得改变既有行为：不使用新参数的输入，结果与之前一致。

## 9. 参数模型

`ArgSpec` 是稳定的四字段结构：`name`、`required`、`description`、`format`。

- **字段冻结。** `ArgSpec` 以结构体字面量形式在 330 多处构造，新增必填字段会无声
  破坏全部调用点。任何字段扩展都必须经由构造器（`ArgSpec::new`、
  `ArgSpec::with_format`）或提供 `Default`。
- **默认值、允许取值与校验**仍由各操作自己的参数解析负责，不升格为 `ArgSpec`
  字段。真要加这类字段，得先把现有字面量改成构造器形式。
- **必填校验**由各操作内部完成并返回本地化错误，引擎层不做强制。
- `tests/api_contract.rs` 钉住 engine、registry、`ArgSpec`、`Op`、recipe、i18n 与
  `Flow` 的公共形状，意外改动会在 CI 中直接失败。
