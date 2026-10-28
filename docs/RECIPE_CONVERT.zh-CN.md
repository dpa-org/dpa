# CyberChef Recipe 转换边界（dpa recipe convert）

[English](RECIPE_CONVERT.md) | 简体中文


`dpa recipe convert` 是 **CyberChef recipe 三格式之间的互转工具**，不是
“CyberChef recipe → dpa flow 一键转换器”。本文写清它做什么、不做什么，
以及把转换产物拿到 dpa 上执行时的边界。

## 支持的转换

| 格式 | 说明 | 示例 |
|------|------|------|
| `url` | CyberChef 分享链接（`https://gchq.github.io/CyberChef/#recipe=...&input=...`），`input` 为 Base64 | `dpa recipe convert <链接> --to chef` |
| `chef` | `.chef` 明文配方（pretty 格式），下划线代表空格：`To_Base64('A-Za-z0-9+/=')`；多个操作以 `/` 分隔（官方导出格式） | `dpa recipe convert recipe.chef --to url` |
| `json` | `recipeConfig` JSON 数组：`[{"op":"To Base64","args":["A-Za-z0-9+/="]}]` | `dpa recipe convert recipe.json --to chef` |

- 三种格式**双向**互转，输入格式缺省为 `auto` 自动识别（URL 前缀 / `[` 开头 / 其余按 chef）。
- chef 多操作解析兼容官方 `/` 分隔（`OpA(...)/OpB(...)`），也兼容 dpa 自身的
  `/breakpoint`、`/disabled` 修饰前缀；转换输出统一为 dpa 规范 chef（操作间无分隔符）。
- 操作名支持中英文双向翻译（内置 506 条 CyberChef 操作名映射表）。
- `disabled` / `breakpoint` 标志转换时保留。
- 不在映射表中的操作名**原样透传，不做猜测**。

## 边界（转换层明确不负责的）

1. **不做能力校验**：转换层把操作名和参数当成“字符串 + JSON 数组”搬运，
   不校验某个操作是否存在、参数是否合法。CyberChef 有而 dpa 没有的操作，转换不会报错，
   但产物拿给 dpa 执行时会因未知 op 失败。
2. **流程控制类操作原样透传**：CyberChef 的流程控制（`Fork`、`Merge`、`Jump`、
   `Register`、`Subsection` 等）在转换层只是普通操作名，不做语义展开。
   dpa flow 目前只实现 `fork` 这一种控制步骤；其余需手工改写后才能执行。
3. **参数语义不翻译**：CyberChef 参数是位置数组（字符串 / 数字 / 布尔 / null），
   dpa 参数是键值 map。convert 不负责把“CyberChef 参数数组”映射为“dpa 参数名”，
   这一步必须手工完成。chef 文本里的对象参数（`{'option':'Hex',...}`）会被
   扁平化为裸 token 序列搬运，不还原成结构，需要时请用 json 格式承载。
4. **产物仍是 CyberChef 生态格式**：url / chef / json 的产物只有在 CyberChef 生态内
   才有语义；要在 dpa 上执行，需要改写为 dpa flow YAML（见 `dpa run` / `dpa list`）。
5. **不保证可直接运行**：转换不会让 dpa 直接执行这份 recipe；dpa 自己的格式是
   flow YAML，与 CyberChef recipe 是两套东西。转换用于查看操作、翻译名称，之后需要
   手动改写成 flow。

## 把 CyberChef 操作搬到 dpa 的可行路径

1. `dpa recipe convert recipe.chef --to json` 查看操作列表。
2. 对照 `dpa list` 找出 dpa 中对应的操作（多数编解码 / 哈希 / 加解密操作可直接对应）。
3. 按 dpa 参数名改写为 flow YAML：
   ```yaml
   steps:
     - op: dpa:base64:decode
     - op: dpa:xor
       args:
         key: "0x2A"
   ```
4. 流程控制 / dpa 没有的操作，需要手工拆分或寻找替代实现。

## 用法

```bash
# chef -> url
dpa recipe convert recipe.chef --to url

# url -> json，并把操作名翻译为中文
dpa recipe convert 'https://gchq.github.io/CyberChef/#recipe=...' --to json --lang zh

# json -> chef
dpa recipe convert recipe.json --to chef
```
