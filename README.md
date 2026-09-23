# autocipher

Encrypted single-file vaults (`.ac`): Argon2id-derived keys, AES-256-GCM-SIV content encryption, and a crash-safe container format.

**License:** GPL-3.0-only · **Version:** 0.1.0

---

## Features

- Argon2id key derivation (128/256/512 MiB, tunable time + parallelism)
- AES-256-GCM-SIV content + filename encryption (deterministic name encryption)
- Fixed 64 KiB chunked AEAD streaming
- Header + metadata mirrors for crash-safe recovery
- One **C ABI** (`autocipher_ffi` cdylib) drives every language wrapper:
  Dart (`autocipher_dart`), JVM (`java/`), Swift (`swift/`), Node (`node/`)
- CLI (`rust/cli`): create, unlock, list, add, extract, change-password, info, compact, remirror

---

## Building

```bash
cargo build --release
```

The workspace root tames every crate; the binary is at `target/release/autocipher`.

```bash
# Whole workspace (engine + bridge + codegen bins)
cargo build --workspace

# The FFI cdylib that every wrapper loads
cargo build --release -p autocipher-ffi
# → target/release/autocipher_ffi.dll     (Windows)
# → target/release/libautocipher_ffi.dylib (macOS)
# → target/release/libautocipher_ffi.so    (Linux)
```

---

## The bridge: one ABI, five languages

The engine is exposed as a minimal, opaque-handle C ABI — **one exported symbol
per operation** (`autocipher_vault_create`, `autocipher_vault_list`, …) plus a
handshake (`ac_version`) and diagnostics (`autocipher_error_message`). Byte
payloads cross the ABI as protobuf (`proto/autocipher.v1.proto`); no pointers
to Rust internals leak out.

- `#[ac_fn]` attributes on the engine methods in `rust/bridge/shared/src`
  are the **single definition set**.
- Codegen bins render `include/autocipher_capi.h` (C) and `Native.dart`
  (`dart:ffi`); the JVM/Swift/Node generators (`native_kt`/`native_ts`) are in
  progress.
- `rust/bridge/shared/types` + `shared/macros` compile that list into the
  exported code (`linkme` metadata), served by `rust/bridge/ffi`.

Regenerate anything with:

```bash
just generate-c      # include/autocipher_capi.h
just generate-dart   # dart/lib/src/generated/Native.dart
just check-generated # verify both are up to date (= CI gate)
```

## The Dart package (`dart/`)

`autocipher_dart` is a pure-Dart wrapper (no Flutter dependency) that binds the
engine over `dart:ffi`:

- `lib/src/generated/Native.dart` — raw generated bindings (committed).
- `lib/src/gen/` — Dart protobuf types (committed).
- `lib/src/native/library.dart` — loader: `AUTOCIPHER_FFI_LIB` env override →
  bundled asset `lib/src/native/<os>/` → plain library name.
- `lib/src/vault/vault.dart` — the `Vault` API. Heavy ops (Argon2id create /
  open / changePassword, folder imports, compaction) run **per-call on worker
  isolates**; light ops run on the calling isolate.

### Build and test

```powershell
# Windows: build the release DLL and stage it
pwsh script/build_ffi.ps1       # → dart/lib/src/native/win/autocipher_ffi.dll
```

```bash
# macOS / Linux
script/build_ffi.sh             # → dart/lib/src/native/{macos,linux}/libautocipher_ffi.*
```

```bash
cd dart
dart pub get
dart analyze && dart test       # wire-format parity + live lifecycle (needs the DLL)
```

The live lifecycle test uses the staged (or `AUTOCIPHER_FFI_LIB`-pointed)
library automatically; against a **release** build it takes a few seconds.

### Regenerating the Dart protobuf (only when the contract changes)

`dart/lib/src/gen/` is committed, so normal builds need no `protoc`. To
regenerate: `just regen-proto-dart`, then update the golden vectors in `rust/proto/src/lib.rs`
and `dart/test/golden_test.dart` together.

## Other wrappers

- `java/` — Gradle module (`org.autocipher`), FFM/JNI binding pending the
  `native_kt` generator; loads via the same env/bundled/system search order.
- `swift/` — SPM package + CocoaPods podspec; the umbrella header imports the
  checked-in `autocipher_capi.h`.
- `node/` — ESM + TS package; `native_ts` binding pending.

---

## CLI Usage

All commands require the `AUTOCIPHER_PASSWORD` environment variable or an interactive password prompt (no echo).

### Create a vault

```bash
autocipher create <path.ac>

# With custom KDF parameters (memory in MiB: 128, 256, or 512)
autocipher create <path.ac> --memory 512 --t 4 --p 4

# Generate a random password instead of prompting
autocipher create <path.ac> --generate-password
```

`--generate-password` (also available on `change-password`) prints a random
password in the grouped format `XXXXX-XXXXX-XXXXX-XXXXX-XXXXX` (5 groups of 5
characters, guaranteed to include uppercase, lowercase, digits, and symbols);
the hyphens are part of the password.

### Unlock and inspect

```bash
autocipher unlock <path.ac>
autocipher info <path.ac>
```

`info` prints:

```
path:            vault.ac
version:         1
kdf:             256 MiB, t=4, p=4
generation:      12
files:           3
size:            4194304 bytes
garbage:         0 bytes (0.0%)
header mirror:   true
metadata mirror: true
```

### List files

```bash
autocipher list <path.ac>
```

### Add a file or folder

Encrypt and store a file, or import a whole folder tree recursively. Folder contents keep their relative subpaths as stored names (e.g. `photos/beach/1.jpg`); symlinks are skipped. A folder import is committed in a single atomic batch — the whole tree lands or nothing does — and re-importing an already-present file overwrites it in place instead of duplicating it.

```bash
autocipher add <path.ac> <plaintext-file-or-directory>
```

### Extract a file

```bash
autocipher extract <path.ac> <stored-name> -o <output-path>
```

### Change password

Re-wraps the master key under a new password (no re-encryption of data).

```bash
AUTOCIPHER_NEW_PASSWORD=newpass autocipher change-password <path.ac>

# With new KDF parameters
autocipher change-password <path.ac> --memory 512 --t 4 --p 4
```

### Compact

Rewrites the archive, dropping stale/freed data.

```bash
autocipher compact <path.ac>
```

### Regenerate mirrors

Recreates the sidecar mirror files (`vault.ac.mirror.header`, `vault.ac.mirror.metadata`) from the primary container. Use this if the mirrors were deleted or not copied along with the vault — the vault keeps working without them, but this restores the crash-recovery safety net.

```bash
autocipher remirror <path.ac>
```

---

## Environment Variables

| Variable | Purpose |
|---|---|
| `AUTOCIPHER_PASSWORD` | Vault password (all commands) |
| `AUTOCIPHER_NEW_PASSWORD` | New password for `change-password` |
| `AUTOCIPHER_FFI_LIB` | Absolute path to the native CDLL (all wrapper libraries) |

If unset, passwords are read interactively from the terminal.

---

## Container Format (`.ac`)

```
Offset        Region
──────────────────────────────────────────────
 0 .. 8192    Header (8 KiB, HMAC-SHA512 authenticated)
8192 .. off   Metadata (sealed manifest + integrity store)
off ..        File data (64 KiB chunked AEAD)
```

Sidecar mirrors (`vault.ac.mirror.header`, `vault.ac.mirror.metadata`) provide crash-safe recovery when the primary container is damaged; they are refreshed atomically with every mutation. The metadata region is bounded by a 64 MiB ceiling (roughly tens of thousands of files). If the mirrors are missing or deleted, regenerate them from the primary with `autocipher remirror <path.ac>`.

---

## Security

Key hierarchy:

```
password ──Argon2id(salt)──▶ KEK
KEK ──AES-256-GCM-SIV unwrap──▶ Master Key
Master Key ──HKDF-SHA256──▶ Subkeys
    ├── "header-mac"  → HMAC-SHA512 key
    ├── "manifest"    → manifest AEAD key
    ├── "integrity"   → integrity HMAC key
    ├── "filename"    → NameKey (SIV + HMAC)
    └── "content"     → per-chunk AEAD key (file_id + chunk_idx)
```

- Deterministic filename encryption (same name → same ciphertext, lookup via HMAC index)
- Monotonic generation counter prevents rollback
- Constant-time passphrase comparison

---

## Workspace Layout

```
rust/
  bridge/
    shared/types/         ABI vocabulary, AcOutBuffer, error mapping, linkme lists
    shared/macros/        the #[ac_fn] attribute macro
    shared/src/           the #[ac_fn] engine method list (single source of truth)
    ffi/                  C ABI cdylib (autocipher_ffi) + ABI integration tests
    codegen/
      core/               shared codegen machinery (#[ac_fn] → bindings)
      native_c/           native_c bin → include/autocipher_capi.h
      native_dart/        native_dart bin → dart/lib/src/generated/Native.dart
      jni/native_kt/      native_kt bin (JVM bindings, stub)
      node/native_ts/     native_ts bin (TS bindings, stub)
  core/                   Pure crypto (KDF, AEAD, keywrap, subkeys)
  format/                 .ac container (header, manifest, chunking, integrity, mirrors)
  cli/                    CLI binary (clap)
  proto/                  prost-build codegen; Rust protobuf types (shared contract)

proto/                    autocipher.v1.proto — single source of truth
include/                  autocipher_capi.h — generated C header (committed)
dart/                     autocipher_dart package (FFI bindings + loader + Vault API + tests)
java/                     JVM wrapper (scaffold)
swift/                    Swift wrapper (scaffold, SPM + podspec)
node/                     Node.js wrapper (scaffold)
script/                   build_ffi.ps1 / build_ffi.sh — build + stage native libs
justfile                  dev recipes: build, test, generate-*, check-generated
```

---

## License

GPL-3.0-only