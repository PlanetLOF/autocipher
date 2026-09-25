// ABI handshake, typed error mapping, and the per-isolate library load/cache
// helpers shared by every op. Statics are isolate-local, so each worker
// isolate re-resolves the library handle exactly once (same process — the OS
// reference count keeps the file loaded) before its first op.

import 'dart:convert';
import 'dart:ffi';

import 'package:ffi/ffi.dart';

import '../generated/Native.dart';
import 'library.dart';

bool _abiChecked = false;

Future<void> _loadNative() async {
  if (!Native.isLoaded) {
    Native.use(await openAutocipher());
  }
}

(int, int, int) _readNativeVersion() {
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

/// Ensure the native library is loaded and its ABI is compatible on this
/// isolate. The check is performed once per isolate and applies to every
/// operation that calls this helper.
Future<void> ensureNative() async {
  await _loadNative();
  if (_abiChecked) return;
  final (major, minor, _) = _readNativeVersion();
  if (major != kAbiMajor || minor < kAbiMinor) {
    throw AutocipherLibraryException(
      'ABI version mismatch: native reports $major.$minor, Dart expects '
      '$kAbiMajor.$kAbiMinor or newer within the same major — rebuild both '
      'sides.',
    );
  }
  _abiChecked = true;
}

/// The native ABI version triple `(major, minor, patch)` from `ac_version`.
///
/// This diagnostic helper loads the library but does not apply the
/// compatibility check; callers that need the check should await
/// [ensureAbiCompatible] or use [ensureNative].
Future<(int, int, int)> nativeVersion() async {
  await _loadNative();
  return _readNativeVersion();
}

/// Throws when the native library is older than the ABI this package was
/// generated for. A newer same-major native library remains compatible.
Future<void> ensureAbiCompatible() async {
  await ensureNative();
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
