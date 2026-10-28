# Security Policy

[简体中文](SECURITY.zh-CN.md) | English

## Supported versions

The latest release in the `1.x` line receives security fixes.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on this repository, under
**Security** then **Report a vulnerability**, rather than a public issue. Include
the affected version, the impact, and a minimal reproduction if you have one. You
will receive an acknowledgement, and credit in the release notes unless you
prefer otherwise.

## Scope

The following are deliberate design decisions, not vulnerabilities:

- **Plugins are native code.** Loading a plugin with `dpa --plugins <dir>` runs
  it with your privileges. Nothing is discovered implicitly: no directory is read
  at startup, and `dpa --discover-plugins` — which reads the conventional
  locations and warns first — is a deliberate opt-in. Only pass directories you
  trust.
- **No network access.** dpa makes no network requests and has no remote
  registry. A flow file is data, not code, and cannot cause network access on its
  own.
- **Cryptography is not a security boundary here.** The cipher and hash
  operations are implemented for analysis and interoperability. They are not
  constant-time, and dpa does not manage keys. It is not a substitute for a key
  management or signing system.
- **Untrusted input.** The engine is written in Rust so that hostile input can be
  parsed safely. Memory-safety bugs, and panics reachable from parsing input, are
  in scope — particularly in the public-key, ASN.1, and codec parsers.

## Security design

The engine applies the following controls when processing untrusted input:

- **YAML size cap.** Flow and recipe YAML is rejected above 8 MiB before parsing
  (`MAX_FLOW_YAML_BYTES`), which bounds both input and parser work. YAML entry
  points are strict by default: unknown fields are denied, duplicate keys are
  rejected, and unquoted booleans follow the YAML 1.2 core schema.
- **Python binding limits.** When the `python` feature is enabled, flow YAML is
  capped at 8 MiB and `run_file` input at 1 GiB; output is written through the
  engine's atomic writer.
- **KDF parameter validation.** `pbkdf2` iteration counts above `u32::MAX` are
  rejected, derived lengths are capped at 1 GiB, and `hkdf` honors the RFC 5869
  255-block bound.
- **Secret-material redaction.** `dpa:pem` decode errors never echo input
  samples, so secret material cannot leak into stderr or logs.
- **Environment whitelist.** `env:`-sourced step arguments are resolved only
  from variables explicitly listed with `--allow-env NAME,...`; without the
  flag the engine preserves its legacy behavior and does not read the
  environment.
- **Atomic output writes.** Engine writers create output files with
  `create_new` and retry on `AlreadyExists`; existing files are never truncated
  and symlinks are not followed.
- **Partial-output disclosure.** When a streamed `hex:decode` (or similar)
  operation fails part-way, error messages state that bytes already emitted are
  partial and must not be used.
- **Non-GCM default IV warning.** A non-GCM encryption operation that omits an
  explicit `iv` emits a one-line stderr warning, because a fixed all-zero IV can
  reuse the keystream across runs. Defaults and output formats are unchanged.
- **Plugin trust model.** Plugins are accepted on a hash-list trust-on-first-use
  (TOFU) basis without signatures; a signature or permission model is not part
  of the current release. Only load plugins from directories you control.

## Known dependency advisories

Two upstream advisories affect crates in the dependency tree. They are tracked
here for visibility.

| Advisory | Crate / version | Issue | Impact on dpa | Status |
|---|---|---|---|---|
| RUSTSEC-2023-0071 | rsa 0.9.10 | Marvin's attack: RSA timing side channel; no patched release available | **Audited, not reachable**: dpa's public-key ops only *verify* signatures — `pubkey.rs` never performs private-key operations (sign/decrypt); private key material is parsed for format inspection only, so the RSA private-key timing oracle this advisory describes cannot be triggered by dpa | Tracked, not fixed; registered in the cargo-deny ignore list with a decision reference |
| RUSTSEC-2024-0449 | unsafe-libyaml 0.2.11 via serde_yaml 0.9.34+ (deprecated) | YAML parser issue; upstream archived without a fix | **Closed**: flow/recipe YAML parsing and serialization migrated to `serde-saphyr` 1.3.x (safe Rust with serde integration) through the single entry point `flow::from_yaml` (strict booleans, ordinary merge keys, duplicate keys rejected); `serde_yaml_ng` and `unsafe-libyaml` are removed from the dependency tree, so the advisory no longer applies | Resolved by migration |

The `rsa` advisory remains open because no patched upstream release exists; the
boundary audit above is re-evaluated on each release, and a fix is adopted as
soon as the ecosystem provides one.
