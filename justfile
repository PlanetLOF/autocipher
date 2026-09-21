# just — dev commands for the autocipher monorepo.
# Shell is selected per-platform: PowerShell (pwsh) on Windows, bash on
# macOS/Linux (a superset of zsh's compatible subset; recipes are POSIX-safe).
[unix]
set shell := ["bash", "-uc"]

[windows]
set shell := ["pwsh", "-Command"]
#
# Recipes:
#   just build            cargo build the whole rust/ workspace
#   just test             cargo test (workspace) + dart test (package)
#   just test-dart        dart test (set AUTOCIPHER_FFI_LIB for the live test)
#   just build-ffi        build + stage the native lib into dart/lib/src/native/
#   just build-ffi-debug  same, debug profile
#   just generate-c       regenerate include/autocipher_capi.h
#   just generate-dart    regenerate dart/lib/src/generated/Native.dart
#   just check-generated  verify both generated files are up to date
#   just regen-proto-dart regenerate the Dart protobuf types (dart/lib/src/gen)
#   just fmt              cargo fmt + dart format

build:
    cargo build --workspace

test:
    cargo test --workspace
    cd dart && dart test

test-dart:
    cd dart && dart test

# Resolve the per-OS build script up front.
ffi_script := if os() == "windows" {
    "pwsh script/build_ffi.ps1"
} else {
    "./script/build_ffi.sh"
}

build-ffi:
    {{ffi_script}}

build-ffi-debug:
    {{if os() == "windows" { "pwsh script/build_ffi.ps1 -Profile debug" } else { "./script/build_ffi.sh dev" }}}

generate-c:
    cargo run -q -p autocipher-bridge-codegen-c --bin native_c -- --out include

generate-dart:
    cargo run -q -p autocipher-bridge-codegen-dart --bin native_dart -- --out dart/lib/src/generated

check-generated:
    cargo run -q -p autocipher-bridge-codegen-c --bin native_c -- --out include --verify
    cargo run -q -p autocipher-bridge-codegen-dart --bin native_dart -- --out dart/lib/src/generated --verify
    cargo test -p autocipher-proto
    cd dart && dart test test/golden_test.dart

# Needs `protoc` and `protoc-gen-dart` on PATH (Rust builds use the vendored
# protoc; `dart pub global activate protoc_plugin` provides the plugin, put its
# bin dir on PATH — %LOCALAPPDATA%\Pub\Cache\bin on Windows, ~/.pub-cache/bin
# on macOS/Linux). `--plugin` is omitted so protoc finds it from PATH on any OS.
regen-proto-dart:
    protoc --dart_out=dart/lib/src/gen --proto_path=proto proto/autocipher.v1.proto

fmt:
    cargo fmt --all
    dart format dart/lib dart/test