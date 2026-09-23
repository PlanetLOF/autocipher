// ABI handshake, typed error mapping, and the per-isolate library load/cache
// helpers shared by every op. Statics are isolate-local, so each worker
// isolate re-resolves the library handle exactly once (same process — the OS
// reference count keeps the file loaded) before its first op.

import 'dart:convert';
import 'dart:ffi';

import 'package:ffi/ffi.dart';

import '../generated/Native.dart';
import 'library.dart';

/// Ensure the native library is loaded on this isolate (idempotent).
Future<void> ensureNative() async {
  if (!Native.isLoaded) {
    Native.use(await openAutocipher());
  }
}

/// The native ABI version triple `(major, minor, patch)` from `ac_version`.
Future<(int, int, int)> nativeVersion() async {
  await ensureNative();
  final major = calloc<Int32>();
  final minor = calloc<Int32>();
  final patch = calloc<Int32>();
  try {
    Native.acVersion(major, minor, patch);
    return (major.value, minor.value, patch.value);
  } finally {
    calloc.free(major);
    calloc.free(minor);
    calloc.free(patch);
  }
}

/// Throws when the native library reports an ABI major that differs from the
/// one this package was generated for.
Future<void> ensureAbiCompatible() async {
  final (major, minor, _) = await nativeVersion();
  if (major != kAbiMajor) {
    throw AutocipherLibraryException(
      'ABI major mismatch: native reports $major.$minor, Dart expects '
      '$kAbiMajor.$kAbiMinor — rebuild both sides.',
    );
  }
}

/// Diagnostic text recorded by the most recent failed op, or `null` if the
/// ABI reported no message. The message persists until the next failure.
String? lastError() {
  final out = calloc<AcOutBuffer>();
  try {
    out.ref.base = nullptr;
    out.ref.len = 0;
    if (Native.autocipherErrorMessage(out) != 0) return null;
    final need = out.ref.len;
    if (need == 0) return null;
    final p = calloc<Uint8>(need);
    try {
      out.ref.base = p;
      out.ref.len = need;
      if (Native.autocipherErrorMessage(out) != 0) return null;
      return utf8.decode(p.asTypedList(out.ref.len));
    } finally {
      calloc.free(p);
    }
  } finally {
    calloc.free(out);
  }
}
