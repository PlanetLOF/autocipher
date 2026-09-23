// Resolves and loads the native `autocipher_ffi` library in-process.
//
// Resolution order:
//   1. `AUTOCIPHER_FFI_LIB` environment variable (absolute path) — the dev /
//      test override (e.g. `target\debug\autocipher_ffi.dll`).
//   2. The bundled asset inside this package
//      (`package:autocipher_dart/lib/src/native/<os>/<file>`), which is where
//      the build scripts drop fresh builds so the wrapper is self-contained.
//      On desktop Flutter this resolves on disk under the app's
//      `data/flutter_assets/packages/autocipher_dart/...`;
//   3. The plain library name (lets the OS search path find it).
//
// The open handle is cached per isolate (Dart isolates do not share statics),
// so every worker isolate re-resolves the library exactly once — the same
// process, no re-loading of the file.

import 'dart:ffi';
import 'dart:io';
import 'dart:isolate';

/// Thrown when the native library cannot be located or opened.
class AutocipherLibraryException implements Exception {
  AutocipherLibraryException(this.message);
  final String message;

  @override
  String toString() => 'AutocipherLibraryException: $message';
}

/// The library file name on this platform.
String nativeLibraryFileName() {
  if (Platform.isWindows) return 'autocipher_ffi.dll';
  if (Platform.isMacOS) return 'libautocipher_ffi.dylib';
  return 'libautocipher_ffi.so';
}

String _osDir() {
  if (Platform.isWindows) return 'win';
  if (Platform.isMacOS) return 'macos';
  return 'linux';
}

/// Candidate absolute paths for the library under the package asset layout.
Future<List<String>> bundledCandidates() async {
  final candidates = <String>{};
  final os = _osDir();
  final name = nativeLibraryFileName();
  try {
    final uri = await Isolate.resolvePackageUri(
      Uri.parse('package:autocipher_dart/lib/src/native/$os/$name'),
    );
    if (uri != null && uri.isScheme('file')) {
      candidates.add(Uri.decodeComponent(uri.toFilePath()));
    }
  } on UnsupportedError {
    // Not running inside a package context (e.g. a bare script); fall through.
  }

  // Desktop Flutter bundles declared package assets on disk under
  // `data/flutter_assets/packages/<pkg>/...` next to the app binary.
  // Isolate.resolvePackageUri can return null in a running app, so also walk
  // the filesystem from the script/exe locations.
  final baseDirs = <Uri>{};
  if (Platform.script.isScheme('file')) {
    baseDirs.add(Uri.file(File.fromUri(Platform.script).path).resolve('./'));
  }
  final exe = Platform.resolvedExecutable;
  if (exe.isNotEmpty) {
    baseDirs.add(Uri.file(exe).resolve('./'));
  }
  final rel =
      'data/flutter_assets/packages/autocipher_dart/lib/src/native/$os/$name';
  final rel2 =
      'flutter_assets/packages/autocipher_dart/lib/src/native/$os/$name';
  for (final base in baseDirs) {
    for (final r in [rel, rel2]) {
      candidates.add(base.resolve(r).toFilePath());
    }
  }
  return candidates.toList(growable: false);
}

/// Open the native library, or throw [AutocipherLibraryException].
Future<DynamicLibrary> openAutocipher() async {
  final override = Platform.environment['AUTOCIPHER_FFI_LIB'];
  if (override != null && override.isNotEmpty) {
    final f = File(override);
    if (!f.existsSync()) {
      throw AutocipherLibraryException(
        'AUTOCIPHER_FFI_LIB points at a missing file: $override',
      );
    }
    return DynamicLibrary.open(override);
  }

  for (final path in await bundledCandidates()) {
    if (File(path).existsSync()) {
      return DynamicLibrary.open(path);
    }
  }

  // Let the OS library search path find it (exe dir on Windows / rpath).
  final plain = nativeLibraryFileName();
  try {
    return DynamicLibrary.open(plain);
  } on ArgumentError {
    // Fall through to the friendly error below.
  }

  throw AutocipherLibraryException(
    'Could not locate $plain. Build it with `just build-ffi` (or '
    '`script/build_ffi.ps1`/`script/build_ffi.sh`) or point AUTOCIPHER_FFI_LIB '
    'at the built library.',
  );
}
