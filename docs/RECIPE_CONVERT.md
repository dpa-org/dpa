# CyberChef Recipe Conversion Boundaries (`dpa recipe convert`)

[简体中文](RECIPE_CONVERT.zh-CN.md) | English

`dpa recipe convert` is an interchange tool between the three CyberChef recipe
formats. It is **not** a "CyberChef recipe → dpa flow" one-click converter.
This document states what it does, what it does not do, and the boundaries that
apply when the converted output is executed with dpa.

## Supported conversions

| Format | Description | Example |
| --- | --- | --- |
| `url` | CyberChef share link (`https://gchq.github.io/CyberChef/#recipe=...&input=...`); `input` is Base64 | `dpa recipe convert <link> --to chef` |
| `chef` | `.chef` plain recipe (pretty format); underscores stand for spaces: `To_Base64('A-Za-z0-9+/=')`; multiple operations are separated by `/` (official export format) | `dpa recipe convert recipe.chef --to url` |
| `json` | `recipeConfig` JSON array: `[{"op":"To Base64","args":["A-Za-z0-9+/="]}]` | `dpa recipe convert recipe.json --to chef` |

- All three formats convert in **both** directions; the input format defaults to
  `auto` detection (URL prefix / leading `[` / otherwise chef).
- Chef parsing accepts the official `/` separator (`OpA(...)/OpB(...)`) as well
  as dpa's own `/breakpoint` and `/disabled` modifier prefixes; conversion output
  is always canonical dpa chef (no separators between operations).
- Operation names are translated bidirectionally between English and Chinese
  (built-in map of 506 CyberChef operation names).
- `disabled` / `breakpoint` flags are preserved during conversion.
- Operation names not in the map are passed through verbatim, never guessed.

## Boundaries (explicitly out of scope for the conversion layer)

1. **No capability validation.** The conversion layer carries operation names
   and arguments as "string + JSON array" payloads. It does not validate whether
   an operation exists or whether its arguments are legal. Operations that exist
   in CyberChef but not in dpa do not fail conversion, but the converted output
   fails at run time with an unknown-op error.
2. **Flow-control operations are passed through verbatim.** CyberChef flow
   control (`Fork`, `Merge`, `Jump`, `Register`, `Subsection`, etc.) is just an
   ordinary operation name to the conversion layer; no semantic expansion is
   performed. dpa flows currently implement only the `fork` control step; the
   rest must be rewritten by hand before they can run.
3. **Argument semantics are not translated.** CyberChef arguments are positional
   arrays (string / number / boolean / null); dpa arguments are key-value maps.
   `convert` does not map "CyberChef argument arrays" to "dpa argument names";
   that step must be done by hand. Object arguments in chef text
   (`{'option':'Hex',...}`) are flattened into bare token sequences and not
   restored to structure; use the json format when structure matters.
4. **The output is still a CyberChef-ecosystem format.** url / chef / json
   output only has meaning inside the CyberChef ecosystem. To run it with dpa,
   rewrite it as a dpa flow YAML (see `dpa run` / `dpa list`).
5. **No compatibility guarantee.** Converting a recipe does not make dpa able to
   run it; dpa's own format is flow YAML, which is separate from CyberChef
   recipes. Use the conversion to inspect operations and translate names, then
   rewrite the flow by hand.

## A practical path from a CyberChef operation to dpa

1. `dpa recipe convert recipe.chef --to json` to inspect the operation list.
2. Find the corresponding dpa operation with `dpa list` (most codec / hash /
   crypto operations map directly).
3. Rewrite it as flow YAML with dpa argument names:
   ```yaml
   steps:
     - op: dpa:base64:decode
     - op: dpa:xor
       args:
         key: "0x2A"
   ```
4. Flow control and operations dpa does not have must be split by hand or
   replaced with an alternative.

## Usage

```bash
# chef -> url
dpa recipe convert recipe.chef --to url

# url -> json, translating operation names to Chinese
dpa recipe convert 'https://gchq.github.io/CyberChef/#recipe=...' --to json --lang zh

# json -> chef
dpa recipe convert recipe.json --to chef
```
