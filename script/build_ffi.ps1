#!/usr/bin/env pwsh
# Build the Rust FFI cdylib for the host platform and copy it into
# dart/lib/src/native/<os>/, where the autocipher_dart loader finds it.
# Requires cargo on PATH.
#
# Usage:
#   pwsh script/build_ffi.ps1            # release
#   pwsh script/build_ffi.ps1 -Profile debug
param(
    [ValidateSet("dev", "release")]
    [string]$Profile = "release"
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$natives = Join-Path $root "dart" "lib" "src" "native"
$profileDir = if ($Profile -eq "release") { "release" } else { "debug" }

cargo build --profile $Profile -p autocipher-ffi
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# Rust names Windows cdylibs without the `lib` prefix; keep the same name in
# the bundle so the loader's plain-name fallback also matches.
$os = if ($IsWindows) { "win" } elseif ($IsLinux) { "linux" } else { "macos" }
$name = if ($IsWindows) { "autocipher_ffi.dll" } elseif ($IsLinux) { "libautocipher_ffi.so" } else { "libautocipher_ffi.dylib" }

$src = Join-Path $root "target" $profileDir $name
$dstDir = Join-Path $natives $os
New-Item -ItemType Directory -Force -Path $dstDir | Out-Null
Copy-Item -LiteralPath $src -Destination (Join-Path $dstDir $name) -Force
Write-Host "copied $src -> $(Join-Path $dstDir $name)"