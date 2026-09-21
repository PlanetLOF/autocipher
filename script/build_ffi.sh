#!/usr/bin/env bash
# Build the Rust FFI cdylib for the host platform and copy it into
# dart/lib/src/native/<os>/, where the autocipher_dart loader finds it.
# Requires cargo on PATH.
#
# Usage:
#   script/build_ffi.sh            # release
#   script/build_ffi.sh dev        # debug profile
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
profile="${1:-release}"
profile_dir="$([ "$profile" = "release" ] && echo release || echo debug)"

cargo build --profile "$profile" -p autocipher-ffi

case "$(uname -s)" in
  Darwin) os="macos";  src="libautocipher_ffi.dylib" ;;
  Linux)  os="linux";  src="libautocipher_ffi.so" ;;
  *) echo "unsupported host OS: $(uname -s)" >&2; exit 1 ;;
esac

src_path="$root/target/$profile_dir/$src"
if [ ! -f "$src_path" ]; then
  echo "native library not found at $src_path (build failed?)" >&2
  exit 1
fi

dst_dir="$root/dart/lib/src/native/$os"
mkdir -p "$dst_dir"
cp "$src_path" "$dst_dir/$src"
echo "copied $src_path -> $dst_dir/$src"