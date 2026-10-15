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
