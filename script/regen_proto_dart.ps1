#!/usr/bin/env pwsh
# Regenerate the Dart protobuf types (dart/lib/src/gen) from
# proto/autocipher.v1.proto.
#
# Resolves `protoc` and the `protoc-gen-dart` plugin without requiring them on
# PATH:
#   - protoc: $env:PROTOC if set, else protoc on PATH, else the protoc binary
#             vendored by the Rust build (crate protoc-bin-vendored, unpacked
#             under ~/.cargo/registry/src).
#   - plugin: protoc-gen-dart on PATH, else the one installed via
#             `dart pub global activate protoc_plugin`
#             (%LOCALAPPDATA%\Pub\Cache\bin\protoc-gen-dart.bat).
#
# Usage:
#   pwsh script/regen_proto_dart.ps1
$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot

# --- protoc -----------------------------------------------------------------
$protoc = $null
if ($env:PROTOC -and (Test-Path -LiteralPath $env:PROTOC)) {
    $protoc = $env:PROTOC
} elseif (Get-Command protoc -ErrorAction SilentlyContinue) {
    $protoc = (Get-Command protoc).Source
} else {
    # protoc-bin-vendored ships per-platform crates; the Rust build pulls the
    # one for the host. Pick the newest win32 binary present in the registry.
    $candidates = Get-ChildItem "$HOME\.cargo\registry\src\*\protoc-bin-vendored-win32-*\bin\protoc.exe" -ErrorAction SilentlyContinue
    $protoc = $candidates | Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName
}
if (-not $protoc) {
    Write-Error "protoc not found. Run `cargo fetch` / `cargo build` in the Rust workspace to pull the vendored protoc (crate protoc-bin-vendored), install protoc on PATH, or set PROTOC."
    exit 1
}

# --- plugin -----------------------------------------------------------------
$plugin = $null
if (Get-Command protoc-gen-dart -ErrorAction SilentlyContinue) {
    $plugin = (Get-Command protoc-gen-dart).Source
} else {
    $candidate = Join-Path $env:LOCALAPPDATA "Pub\Cache\bin\protoc-gen-dart.bat"
    if (Test-Path -LiteralPath $candidate) {
        $plugin = $candidate
    }
}
if (-not $plugin) {
    Write-Error "protoc-gen-dart not found. Run `dart pub global activate protoc_plugin`, or add its bin dir to PATH."
    exit 1
}

# --- regenerate -------------------------------------------------------------
$protoDir = Join-Path $root "proto"
$outDir = Join-Path $root "dart" "lib" "src" "gen"

& $protoc --plugin="protoc-gen-dart=$plugin" --dart_out="$outDir" --proto_path="$protoDir" (Join-Path $protoDir "autocipher.v1.proto")
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "regenerated Dart protobuf types in dart/lib/src/gen (protoc: $protoc, plugin: $plugin)"