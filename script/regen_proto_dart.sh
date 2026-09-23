#!/usr/bin/env bash
# Regenerate the Dart protobuf types (dart/lib/src/gen) from
# proto/autocipher.v1.proto.
#
# Resolves `protoc` and the `protoc-gen-dart` plugin without requiring them on
# PATH:
#   - protoc: $PROTOC if set, else protoc on PATH, else the protoc binary
#             vendored by the Rust build (crate protoc-bin-vendored, unpacked
#             under ~/.cargo/registry/src, matched to the host OS/arch).
#   - plugin: protoc-gen-dart on PATH, else the one installed via
#             `dart pub global activate protoc_plugin` (~/.pub-cache/bin).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# --- protoc -----------------------------------------------------------------
protoc="${PROTOC:-}"
if [ -z "$protoc" ] && command -v protoc >/dev/null 2>&1; then
  protoc="$(command -v protoc)"
fi
if [ -z "$protoc" ]; then
  # protoc-bin-vendored ships per-platform crates; map the host to the crate
  # suffix the Rust build would have fetched.
  case "$(uname -s)" in
    Darwin) os="macos" ;;
    Linux)  os="linux" ;;
    *) echo "unsupported host OS: $(uname -s) (install protoc or set PROTOC)" >&2; exit 1 ;;
  esac
  case "$(uname -m)" in
    x86_64)             arch="x86_64" ;;
    aarch64|arm64)      arch="aarch_64" ;;
    i386|i686)          arch="x86_32" ;;
    ppc64le)            arch="ppcle_64" ;;
    s390x)              arch="s390_64" ;;
    *) echo "unsupported host arch: $(uname -m) (install protoc or set PROTOC)" >&2; exit 1 ;;
  esac
  protoc="$(ls -t "$HOME"/.cargo/registry/src/*/protoc-bin-vendored-${os}-${arch}-*/bin/protoc 2>/dev/null | head -n 1 || true)"
  if [ -z "$protoc" ]; then
    echo "protoc not found: run \`cargo fetch\`/\`cargo build\` in the Rust workspace to pull the vendored protoc (protoc-bin-vendored), install protoc on PATH, or set PROTOC." >&2
    exit 1
  fi
fi

# --- plugin -----------------------------------------------------------------
plugin=""
if command -v protoc-gen-dart >/dev/null 2>&1; then
  plugin="$(command -v protoc-gen-dart)"
else
  candidate="$HOME/.pub-cache/bin/protoc-gen-dart"
  if [ -f "$candidate" ]; then
    plugin="$candidate"
  fi
fi
if [ -z "$plugin" ]; then
  echo "protoc-gen-dart not found: run \`dart pub global activate protoc_plugin\`, or add its bin dir to PATH." >&2
  exit 1
fi

# --- regenerate -------------------------------------------------------------
"$protoc" --plugin="protoc-gen-dart=$plugin" \
  --dart_out="$root/dart/lib/src/gen" \
  --proto_path="$root/proto" \
  "$root/proto/autocipher.v1.proto"

echo "regenerated Dart protobuf types in dart/lib/src/gen (protoc: $protoc, plugin: $plugin)"