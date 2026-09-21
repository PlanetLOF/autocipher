# java/ — JVM wrapper (scaffold)

Planned layout:

- `lib/` — Gradle module, package `org.autocipher`, JAR with the C ABI
  bindings (FFI via FFM or the JNI shim in `rust/bridge/codegen/jni`).
- `native/` — staged `libautocipher_ffi.so` / `.dll` / `.dylib` resources.

Status: **scaffold only**. The binding is stubbed pending the `native_kt`
codegen bin; the C contract is authoritative and lives in
`include/autocipher_capi.h`.

Build (when present): `./gradlew :lib:build`