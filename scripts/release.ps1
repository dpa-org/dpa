# dpa release script (Windows)
# Usage:
#   .\scripts\release.ps1                # build release, package dist/, print sha256
#   .\scripts\release.ps1 -Version 1.0.0 # override version (default: read Cargo.toml)
#
# Produces:
#   dist\dpa-<ver>-x86_64-pc-windows-msvc\dpa.exe        (install-time name; copied from dpa-cli.exe)
#   dist\dpa-<ver>-x86_64-pc-windows-msvc.zip
#   dist\dpa-<ver>-x86_64-pc-windows-msvc.zip.sha256
#
# Note: version tags are applied by the maintainer (git tag v<ver>); this script
# only packages binaries locally. Tagging triggers the GitHub Actions release
# workflow (.github/workflows/release.yml).

param(
  [string]$Version = ""
)

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

# --- resolve version -------------------------------------------------------
if (-not $Version) {
  $toml = Get-Content "Cargo.toml" -Raw
  $m = [regex]::Match($toml, '(?m)^version\s*=\s*"([^"]+)"')
  if ($m.Success) { $Version = $m.Groups[1].Value }
}
if (-not $Version) { throw "Cannot resolve version from Cargo.toml; pass -Version explicitly." }
$ver = $Version.TrimStart("v")

# --- sanity checks ---------------------------------------------------------
$dirty = git status --porcelain
if ($dirty) {
  Write-Host "WARN: working tree is not clean; packaging anyway:" -ForegroundColor Yellow
  $dirty | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
}

# --- build release ---------------------------------------------------------
Write-Host "Building release (features: cli)..." -ForegroundColor Cyan
cargo build --release --features cli
if ($LASTEXITCODE -ne 0) { throw "cargo build --release failed" }

# --- assemble dist dir -----------------------------------------------------
$triple = "x86_64-pc-windows-msvc"
$dirName = "dpa-$ver-$triple"
$distRoot = Join-Path (Get-Location) "dist"
$distDir = Join-Path $distRoot $dirName
$binSrc = Join-Path (Get-Location) "target\release\dpa-cli.exe"
if (-not (Test-Path $binSrc)) { throw "release binary not found: $binSrc" }

if (Test-Path $distDir) { Remove-Item $distDir -Recurse -Force }
New-Item -ItemType Directory -Path $distDir -Force | Out-Null

# install-time name: dpa.exe (users type `dpa`; the Cargo bin is dpa-cli)
Copy-Item $binSrc (Join-Path $distDir "dpa.exe")
Copy-Item "LICENSE" (Join-Path $distDir "LICENSE")
if (Test-Path "NOTICE") { Copy-Item "NOTICE" (Join-Path $distDir "NOTICE") }
if (Test-Path "README.md") { Copy-Item "README.md" (Join-Path $distDir "README.md") }
if (Test-Path "README.zh-CN.md") { Copy-Item "README.zh-CN.md" (Join-Path $distDir "README.zh-CN.md") }

# --- archive + checksum ----------------------------------------------------
$zipPath = Join-Path $distRoot "$dirName.zip"
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
Compress-Archive -Path $distDir -DestinationPath $zipPath -CompressionLevel Optimal

$hash = (Get-FileHash $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
$shaPath = "$zipPath.sha256"
Set-Content -Path $shaPath -Value "$hash  $dirName.zip" -Encoding Ascii

# --- report ----------------------------------------------------------------
Write-Host ""
Write-Host "Package ready:" -ForegroundColor Green
Write-Host "  $zipPath"
Write-Host "  SHA256: $hash"
Write-Host ""
Write-Host "Next steps (maintainer):" -ForegroundColor Cyan
Write-Host "  git add -A && git commit -m 'release $ver'"
Write-Host "  git tag v$ver && git push origin v$ver   # triggers GitHub Actions release workflow"
