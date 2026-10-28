# dpa release smoke gate (Windows)
# Usage:
#   .\scripts\release_smoke.ps1                # run against target\release\dpa.exe
#   .\scripts\release_smoke.ps1 -Exe path\to\dpa.exe
#
# Asserts, on a built binary:
#   - `--version` prints one clean "dpa ..." line and exits 0
#   - `--help` exits 0
#   - a basic op conversion (`dpa op hex:encode`) returns the exact bytes
#   - a basic flow run (`dpa run -e 'steps: [{op: base64:encode}]'`) works
#   - an unknown op exits non-zero (error propagation)
#
# Pure development-side gate: it never tags, packages or publishes anything.
# The gate exits non-zero on the first failed assertion.

param(
  [string]$Exe = ""
)

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

if (-not $Exe) { $Exe = Join-Path (Get-Location) "target\release\dpa.exe" }
if (-not (Test-Path $Exe)) {
  throw "Binary not found at $Exe; build first: cargo build --release --features cli"
}
$bin = (Resolve-Path $Exe).Path

function Assert-Exit([string]$What, [int]$Expected) {
  if ($LASTEXITCODE -ne $Expected) {
    throw "exit code $LASTEXITCODE != $Expected for: $What"
  }
}

# --- 1. version ------------------------------------------------------------
$ver = & $bin --version
Assert-Exit "dpa --version" 0
if ($ver -notmatch '^dpa ') { throw "--version output: $ver" }
if (($ver -join "`n") -match "`n") { throw "--version must be one line: $ver" }

# The embedded commit must match the current HEAD (a dirty
# tree is allowed on ad-hoc local builds, hence the optional -dirty suffix).
$head = git rev-parse --short=12 HEAD
$m = [regex]::Match(($ver -join " "), 'commit ([0-9a-f]{12}(-dirty)?),')
if (-not $m.Success) { throw "--version carries no embedded commit hash: $ver" }
$verCommit = $m.Groups[1].Value
if ($verCommit -ne $head -and $verCommit -ne "$head-dirty") {
  throw "--version commit '$verCommit' != HEAD '$head'"
}

# A clean working tree must never advertise `-dirty` (the marker
# is only valid for ad-hoc builds made from a dirty tree; the release script
# refuses to package those anyway). Also catches a stale build.rs rerun that
# embeds an old hash while the tree has since been cleaned.
if ($verCommit -like "*-dirty") {
  $tree = git status --porcelain
  if (-not $tree) {
    throw "--version claims '-dirty' but the working tree is clean: $ver"
  }
}

# --- 2. help ---------------------------------------------------------------
& $bin --help | Out-Null
Assert-Exit "dpa --help" 0

# --- 3. basic op ------------------------------------------------------------
$in = Join-Path $env:TEMP "dpa_smoke_in_$PID.txt"
[System.IO.File]::WriteAllText($in, "Hello")
try {
  $hex = (& $bin op hex:encode $in) -join "`n"
  Assert-Exit "dpa op hex:encode" 0
  if ($hex.Trim() -ne "48656c6c6f") { throw "op hex:encode expected '48656c6c6f', got: $hex" }

  # --- 4. basic flow ---------------------------------------------------------
  $b64 = (& $bin run -e "steps: [{op: base64:encode}]" $in) -join "`n"
  Assert-Exit "dpa run -e base64:encode" 0
  if ($b64.Trim() -ne "SGVsbG8=") { throw "flow base64 expected 'SGVsbG8=', got: $b64" }
} finally {
  Remove-Item $in -ErrorAction SilentlyContinue
}

# --- 5. error propagation ---------------------------------------------------
# Run through cmd so the child's stderr cannot be rethrown as a native
# command error under $ErrorActionPreference = "Stop" (PowerShell 5.1).
& cmd /c "`"$bin`" op nosuchop >nul 2>&1"
if ($LASTEXITCODE -eq 0) { throw "unknown op must exit non-zero" }

Write-Host "release smoke OK: $bin"
