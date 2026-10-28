
# dpa 算子语义（Op Semantics）

本文档是 dpa 各算子行为的规范性参考：说明算子与主流工具（CyberChef / Python /
OpenSSL / RFC）对齐之处，以及 dpa 有意保留自身行为之处。实现与本文档保持同步。

## 1. 总则

- **处处是原始字节。** 算子只消费和产出字节数组。文本渲染属于表现层；需要 hex 时用
  `dpa:hex:encode`，或 CLI 用 `--output-format hex`。
- **默认确定性。** 相同输入、相同显式参数下，配方在任何运行环境、任何平台必须产出
  相同字节。
- **所有时间转换一律 UTC。** 任何地方都不依赖本地时区。
- **尽量流式。** 算子的流式 / 整块缓冲行为由引擎标注；两条路径语义完全一致。
- **失败要响亮。** 非法输入、坏填充、畸形编码一律报错，不做静默的尽力而为输出；
  除非显式传入 `ignore_non_alphabet` / `strict_mode=false` 等参数主动放宽。

## 2. 与主流工具的对齐项

以下行为已按主流参考修正，并有差分测试覆盖（`scripts/difftest.py`）：

> **覆盖范围。** 差分测试面向 codec、hash、压缩与对称加密这几类——因为它们
> 存在独立参考实现。它并**不**覆盖全部 233 个操作：transform、analyze、
> generate、extract 的操作由单元测试与文档化向量覆盖。脚本会打印自己的
> `TOTAL` / `FAIL` / `SKIP` 计数，CI 以 `--strict` 运行，因此缺少参考实现会
> 让任务失败，而不是被静默跳过。

| 算子 | 语义 | 参考 |
| --- | --- | --- |
| `dpa:filetime` | Windows FILETIME = 自 1601-01-01 起 100ns 计数，小端 hex。`dpa:filetime:from:unix` 将 Unix s/ms/us 转为 FILETIME；`dpa:filetime:to:date` 输出 UTC 日期。 | CyberChef "Filetime" |
| `dpa:xxhash32` / `dpa:xxhash64` | 摘要字节按**大端**输出（与 xxHash 参考实现及 CyberChef 输出一致）。 | xxHash spec / CyberChef |
| `dpa:split` | 按分隔符拆分并以 `\n` 连接各段；末尾分隔符**不再**产生空尾段。 | CyberChef "Split" |
| `dpa:tea:encode` / `dpa:tea:decode`（含 `dpa:xtea:*`、`dpa:xxtea:*`） | 64 位块分组密码族，可选填充：`zero`（历史默认）、`pkcs7`、`none`（严格模式，非对齐输入报错）。解码时校验 pkcs7，坏填充报错。 | CyberChef TEA/XTea/XXTEA + PKCS#7 |

## 3. 有意坚持的差异项

以下行为是设计上的选择，与部分主流工具不同。记录在此，使选择显式化而非偶然。

| 算子 | dpa 行为 | 原因 |
| --- | --- | --- |
| `dpa:gzip` | 头部 `MTIME = 0`、`OS = 0xff`，除非用 `timestamp` / `os` 参数覆盖。 | 字节稳定、可复现；不泄露墙钟时间。CyberChef 默认嵌入当前时间与操作系统。 |
| `dpa:timestamp` / `dpa:filetime:*` 及日期类算子 | 所有转换使用 **UTC**，渲染 `YYYY-MM-DD HH:MM:SS`。 | 跨时区确定；配方不依赖机器区域设置。 |
| `dpa:utf16:encode` / `dpa:utf16:decode` | 默认**不输出 BOM**；`bom=true` 才写入。 | 贴合原始字节预期；UTF-16 的 BOM 本来就是可选的。 |
| `dpa:base32:decode`（及 base64/hex/binary 族） | 默认严格：非字母表字节报错，除非 `ignore_non_alphabet=true`；`strict_mode` 控制填充校验。 | 失败要响亮，不静默丢弃损坏数据。 |
| 哈希族（`dpa:md5`、`dpa:sha256`、…） | 算子输出**原始摘要字节**；`dpa:hex:encode`（或 `--output-format hex`）负责 hex 渲染。 | 单一数据层契约，避免双重编码混淆。 |

## 4. 差异索引（速查）

| 主题 | 主流默认 | dpa 默认 | 位置 |
| --- | --- | --- | --- |
| gzip 头时间 | 当前 Unix 时间 | `0` | `dpa:gzip` |
| gzip 头 OS | 宿主机 OS | `0xff` | `dpa:gzip` |
| xxhash32/64 输出端序 | 部分库输出小端 | 大端 | `dpa:xxhash32`、`dpa:xxhash64` |
| split 末尾分隔符 | 部分工具保留空尾段 | 丢弃 | `dpa:split` |
| TEA/XTeA/XXTEA 填充 | 仅零填充 | `zero` / `pkcs7` / `none` | tea 族 |
| 时间 / 日期渲染 | 本地时间 | UTC | `dpa:timestamp`、`dpa:filetime` |
| UTF-16 BOM | 各不相同 | 无（可选开启） | `dpa:utf16:*` |
| base32/base64 解码严格度 | 各不相同，常宽松 | 严格（可选放宽） | codec 族 |
| 哈希输出 | 部分工具输出 hex | 原始字节 | 哈希族 |

## 5. 边界清单

- **FILETIME 范围**：值为 `u64`；负 Unix 时间被拒绝。`filetime:from:unix` 接受
  `s`（默认）/ `ms` / `us`，输出小端 hex 或十进制（`format=dec`）。
- **XXTEA**：输入不足一块时补足整块；`none` 填充对非对齐输入报错。
- **gzip FHCRC**：仅当请求对应标志位时才输出可选的 CRC16 头字段；相同参数下流式与
  整块路径产出逐字节一致的头。
- **base32 严格模式**：末量子残留非零尾位在严格模式下报错；`strict_mode=false` 可接受。
- **UTF-16 解码**：奇数尾字节、拆分的代理对、拆分的 BOM 均按流处理；畸形输入报错。
- **哈希族**：所有摘要均为原始字节，算子层无 hex 选项——请经 `dpa:hex:encode` 管道。
- **datetime parse / translate**：默认严格——任一行无效即整批失败；设 `on_error=skip`
  可跳过无效行并在末尾追加 `# [dpa] skipped N invalid line(s)` 摘要注释。支持分钟精度
  （`2024-01-02 03:04`）、斜杠分隔日期（`2026/10/02 14:05`）与小数秒（截断为整秒）。
- **extract:domains**：默认过滤常见文件扩展名伪 TLD（`app.js`、`style.css`），避免路径
  片段被误报为域名；设 `filter_ext_tlds=false` 恢复旧宽松行为。`extra_tld_blacklist`
  提供逗号分隔、忽略大小写的附加 TLD 黑名单。
- **analyze:file:type**：无 magic 签名匹配时回退文本嗅探（ASCII / UTF-8 / UTF-16
  LE/BE），并标注换行风格（`LF` / `CRLF` / `None`）；确实不透明的缓冲区仍报
  `Unknown file type`。

## 6. 已删除算子与等价 flow 组合

以下算子已从注册表移除，请改用等价 flow 组合：

| 已删除算子 | 等价 flow 组合 |
| --- | --- |
| `dpa:hex:to:pem` | `dpa:hex:decode` → `dpa:pem`（action=encode，label=...） |
| `dpa:pem:to:hex` | `dpa:pem`（action=decode）→ `dpa:hex:encode` |
| `dpa:lorem:ipsum` | 无内置等价。请使用外部文本源，或由 `dpa:generate:random` / 字面输入在 flow 中拼装示例文本。 |

