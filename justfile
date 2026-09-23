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

# Regenerate the Dart protobuf types (dart/lib/src/gen). No PATH setup needed:
# the per-OS script resolves `protoc` (PATH entry, $PROTOC, or the binary
# vendored by the Rust build via protoc-bin-vendored) and `protoc-gen-dart`
# (PATH or the pub global install from `dart pub global activate protoc_plugin`).
regen_proto_dart_script := if os() == "windows" {
    "pwsh script/regen_proto_dart.ps1"
} else {
    "./script/regen_proto_dart.sh"
}

regen-proto-dart:
    {{regen_proto_dart_script}}

fmt:
    cargo fmt --all
    dart format dart/lib dart/test