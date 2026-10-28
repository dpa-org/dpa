# dpa git hook installer (Windows)
# Usage:
#   .\scripts\setup-git-hooks.ps1
#
# Points git at the repository-local hook directory (.githooks) so the
# post-commit hook touches build.rs after every commit. That touch forces
# cargo to rerun build.rs on the next incremental build, which re-embeds the
# current commit hash into `dpa --version`.
#
# Without this hook, `dpa --version` can keep showing the hash of an older
# commit: cargo's rerun-if-changed does not reliably track files under .git/,
# so committing does not by itself trigger a build.rs rerun.
#
# The hook directory is committed to the repository (unlike .git/hooks), so
# setup is one git-config command; run this script (or the equivalent
# `git config core.hooksPath .githooks`) once per clone.

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

if (-not (Test-Path ".githooks\post-commit")) {
  throw ".githooks\post-commit not found; are you at the repository root?"
}

git config core.hooksPath .githooks
if ($LASTEXITCODE -ne 0) { throw "git config core.hooksPath failed" }

Write-Host "core.hooksPath = $(git config --get core.hooksPath)"
Write-Host "post-commit hook installed: .githooks\post-commit (touches build.rs after each commit)"
Write-Host "Next `cargo build` after a commit will rerun build.rs and embed the new commit hash."
