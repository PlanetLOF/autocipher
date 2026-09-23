// `Vault` — the Dart client's mirror of the Rust `autocipher-format` `Vault`
// API, driven over the per-op C ABI (see `src/generated/Native.dart`).
//
// Every op marshals through the opaque handle (a process-wide `Box<Vault>` on
// the Rust side). Long-running ops — Argon2id KDF in create/open/
// changePassword, folder imports in addPaths, and rewrite passes in compact —
// run on a *fresh* worker isolate so the caller's isolate never janks; light
// ops (list/info/size/readRange/put/delete/rename/extract/remirror/close) run
// inline on the calling isolate. Workers and owner each re-resolve the native
// library once (isolate-local statics, same process).
//
// Concurrency: a single `Vault` must not be shared across Dart isolates at
// the same time — the engine takes `&mut Vault` for every op and is not
// internally synchronized. Drive it from one isolate (the UI isolate, with
// heavy ops delegated internally to throwaway workers), which is how the
// Flutter app uses it.

import 'dart:ffi';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../gen/autocipher.v1.pb.dart';
import '../generated/Native.dart';
import '../native/abi.dart';
import 'exceptions.dart';
import 'models.dart';

/// A handle to one open vault on the Rust side.
///
/// The caller owns the vault: call [close] (or the app's lock button) to
/// scrub the in-memory master key.
class Vault {
  Vault._(this._handleAddress);

  /// The opaque handle's address in the native process.
  final int _handleAddress;

  bool _closed = false;

  Pointer<Void> get _handle => Pointer<Void>.fromAddress(_handleAddress);

  /// A failed worker op read a diagnostic from its own isolate thread-local.
  AutocipherException _error(int code, String? workerMessage) {
    if (code == 0) {
      throw StateError('_error with success code');
    }
    final msg = workerMessage ?? lastError() ?? 'op failed with code $code';
    return exceptionFromCode(code, msg);
  }

  void _ensureOpen() {
    if (_closed) {
      throw StateError('vault is closed');
    }
  }

  // ---- lifecycle ------------------------------------------------------------

  /// Create a new vault at `path` with `password` and the given [KdfPreset].
  /// The KDF run happens on a worker isolate.
  static Future<Vault> create(
    String path,
    String password,
    KdfPreset preset,
  ) async {
    final (code, message, address) = await Isolate.run(
      () => _workerCreate(path, password, preset.toWire().writeToBuffer()),
    );
    if (code != 0) {
      throw _errorFromWorker(code, message);
    }
    // The heavy create ran on a worker isolate, so this isolate has not loaded
    // the library yet — every subsequent inline op (list/info/read/…) needs it.
    await ensureNative();
    return Vault._(address);
  }

  /// Open an existing vault at `path`.
  ///
  /// Throws [WrongPasswordException] when `password` fails the header HMAC or
  /// the master-key unwrap.
  static Future<Vault> open(String path, String password) async {
    final (code, message, address) = await Isolate.run(
      () => _workerOpen(path, password),
    );
    if (code != 0) {
      throw _errorFromWorker(code, message);
    }
    // Same as create: the KDF ran on a worker, load the library here for the
    // inline ops that follow on this isolate.
    await ensureNative();
    return Vault._(address);
  }

  /// Close the vault, releasing the handle and scrubbing key material.
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    // Cheap (a drop) — safe on the calling isolate.
    Native.VaultDestroy(_handle);
  }

  // ---- reading --------------------------------------------------------------

  /// List the vault's plaintext entries (name + size), sorted by name.
  Uint8List _listRaw() {
    _ensureOpen();
    final (code, data) = Native.bufferCall((out) => Native.list(_handle, out));
    if (code != 0) throw _error(code, null);
    return data;
  }

  Future<List<VaultFileInfo>> listFiles() async {
    final files = FileInfoList.fromBuffer(_listRaw()).files;
    return [for (final f in files) VaultFileInfo(f.name, f.size.toInt())];
  }

  /// Aggregated engine + container statistics.
  Future<VaultInfoModel> info() async {
    _ensureOpen();
    final (code, data) = Native.bufferCall((out) => Native.info(_handle, out));
    if (code != 0) throw _error(code, null);
    return _fromInfo(VaultInfo.fromBuffer(data));
  }

  /// Exact plaintext byte length of `name` (fast, no decryption).
  int size(String name) => Native.withUtf8(name, (np, nl) {
    final out = calloc<Uint64>();
    try {
      final code = Native.size(_handle, np, nl, out);
      if (code != 0) throw _error(code, null);
      return out.value;
    } finally {
      calloc.free(out);
    }
  });

  /// Read a raw [len]-byte window starting at `offset`. Returns fewer bytes
  /// (possibly zero) when the window runs past EOF. Prefer [readFile] for
  /// whole-file pulls with progress.
  Future<Uint8List> readRange(
    String name, {
    required int offset,
    required int len,
  }) async {
    _ensureOpen();
    return Native.withUtf8(name, (np, nl) {
      final (code, data) = Native.bufferCall(
        (out) => Native.readRange(_handle, np, nl, offset, len, out),
      );
      if (code != 0) throw _error(code, null);
      return data;
    });
  }

  /// Stream `name` into memory in fixed-size chunks, reporting progress.
  ///
  /// [chunkSize] is the rectified window per call; the native side still
  /// decrypts only the (at most two) 64 KiB content chunks overlapping each
  /// window, so memory stays bounded by `chunkSize`, not the file size.
  /// [onProgress] receives `(bytesSoFar, totalBytes)` after every chunk.
  Future<Uint8List> readFile(
    String name, {
    int chunkSize = 1 << 20, // 1 MiB
    void Function(int done, int total)? onProgress,
  }) async {
    final files = await listFiles();
    final total = files
        .firstWhere(
          (f) => f.name == name,
          orElse: () =>
              throw NotFoundInVaultException(2, 'no such file: $name'),
        )
        .size;

    final out = BytesBuilder(copy: false);
    var offset = 0;
    while (offset < total) {
      final take = chunkSize < total - offset ? chunkSize : total - offset;
      final chunk = await readRange(name, offset: offset, len: take);
      if (chunk.isEmpty) break; // safety net against a silently truncated read
      out.add(chunk);
      offset += chunk.length;
      onProgress?.call(offset, total);
      if (offset == total) break;
    }
    return out.takeBytes();
  }

  // ---- writing --------------------------------------------------------------

  /// Import host paths into the vault (atomic, recursive folder import).
  ///
  /// [items] maps each host path to its stored name; see the engine docs for
  /// stored-name semantics. Runs on a worker isolate.
  Future<int> addPaths(List<({String src, String storedName})> items) async {
    final wire = AddPaths(
      items: [
        for (final it in items)
          PathItem(src: it.src, storedName: it.storedName),
      ],
    ).writeToBuffer();
    final (code, message, count) = await Isolate.run(
      () => _workerAddPaths(_handleAddress, wire),
    );
    if (code != 0) throw _errorFromWorker(code, message);
    return count;
  }

  /// Write [data] to `name`, creating it if absent or overwriting in place.
  Future<void> put(String name, Uint8List data) async {
    _ensureOpen();
    Native.withUtf8(
      name,
      (np, nl) => Native.withSlice(data, (dp, dl) {
        final code = Native.put(_handle, np, nl, dp, dl);
        if (code != 0) throw _error(code, null);
        return code;
      }),
    );
  }

  /// Decrypt `name` to the host path `dest` (chunk-streamed in Rust).
  Future<void> extract(String name, String dest) async {
    _ensureOpen();
    Native.withUtf8(
      name,
      (np, nl) => Native.withUtf8(dest, (dp, dl) {
        final code = Native.extract(_handle, np, nl, dp, dl);
        if (code != 0) throw _error(code, null);
        return code;
      }),
    );
  }

  /// Remove `name` from the vault.
  Future<void> delete(String name) async {
    _ensureOpen();
    Native.withUtf8(name, (np, nl) {
      final code = Native.delete(_handle, np, nl);
      if (code != 0) throw _error(code, null);
    });
  }

  /// Rename the entry `old` → `new` (preserves the file id / chunk bindings).
  Future<void> rename(String old, String newName) async {
    _ensureOpen();
    Native.withUtf8(
      old,
      (op, ol) => Native.withUtf8(newName, (np, nl) {
        final code = Native.rename(_handle, op, ol, np, nl);
        if (code != 0) throw _error(code, null);
        return code;
      }),
    );
  }

  // ---- maintenance ----------------------------------------------------------

  /// Re-wrap the vault under `newPassword` (with new KDF costs). Content is
  /// not re-encrypted. Runs on a worker isolate (argon2id + atomic rewrite).
  Future<void> changePassword(String newPassword, KdfPreset preset) async {
    final (code, message) = await Isolate.run(
      () => _workerChangePassword(
        _handleAddress,
        newPassword,
        preset.toWire().writeToBuffer(),
      ),
    );
    if (code != 0) throw _errorFromWorker(code, message);
  }

  /// Garbage-collect the container. Blocking for large vaults — runs on a
  /// worker isolate.
  Future<void> compact() async {
    final (code, message) = await Isolate.run(
      () => _workerCompact(_handleAddress),
    );
    if (code != 0) throw _errorFromWorker(code, message);
  }

  /// Regenerate the sidecar mirror files for crash recovery.
  Future<void> remirror() async {
    _ensureOpen();
    final code = Native.remirror(_handle);
    if (code != 0) throw _error(code, null);
  }

  // ---- helpers --------------------------------------------------------------

  static VaultInfoModel _fromInfo(VaultInfo v) {
    final kdf = v.kdf;
    return VaultInfoModel(
      path: v.path,
      generation: v.generation.toInt(),
      files: v.files,
      sizeBytes: v.sizeBytes.toInt(),
      garbageBytes: v.garbageBytes.toInt(),
      garbageRatio: v.garbageRatio,
      headerMirror: v.headerMirror,
      metadataMirror: v.metadataMirror,
      kdf: describeKdf(kdf),
    );
  }
}

/// Reconstruct an error record produced outside the calling isolate.
AutocipherException _errorFromWorker(int code, String? message) {
  return exceptionFromCode(code, message ?? 'op failed with code $code');
}

// ---- worker-isolate entry points -------------------------------------------
//
// Each takes only sendable values (primitives, Uint8List) and returns only
// sendable values; errors surface as `(code, message)` pairs so the caller
// isolate can build the typed exception itself (exceptions do not cross
// isolates as typed values).

Future<(int, String?, int)> _workerCreate(
  String path,
  String password,
  Uint8List kdfParams,
) async {
  await ensureNative();
  final handle = calloc<Pointer<Void>>();
  try {
    final code = Native.withUtf8(
      path,
      (pp, pl) => Native.withUtf8(
        password,
        (wp, wl) => Native.withSlice(
          kdfParams,
          (kp, kl) => Native.createVault(pp, pl, wp, wl, kp, kl, handle),
        ),
      ),
    );
    final address = code == 0 ? handle.value.address : 0;
    return (code, code == 0 ? null : lastError(), address);
  } finally {
    calloc.free(handle);
  }
}

Future<(int, String?, int)> _workerOpen(String path, String password) async {
  await ensureNative();
  final handle = calloc<Pointer<Void>>();
  try {
    final code = Native.withUtf8(
      path,
      (pp, pl) => Native.withUtf8(
        password,
        (wp, wl) => Native.openVault(pp, pl, wp, wl, handle),
      ),
    );
    final address = code == 0 ? handle.value.address : 0;
    return (code, code == 0 ? null : lastError(), address);
  } finally {
    calloc.free(handle);
  }
}

Future<(int, String?)> _workerChangePassword(
  int address,
  String newPassword,
  Uint8List kdfParams,
) async {
  await ensureNative();
  final me = Pointer<Void>.fromAddress(address);
  return Native.withUtf8(
    newPassword,
    (np, nl) => Native.withSlice(kdfParams, (kp, kl) {
      final code = Native.changePassword(me, np, nl, kp, kl);
      return (code, code == 0 ? null : lastError());
    }),
  );
}

Future<(int, String?, int)> _workerAddPaths(int address, Uint8List wire) async {
  await ensureNative();
  final me = Pointer<Void>.fromAddress(address);
  final count = calloc<Uint32>();
  try {
    final code = Native.withSlice(wire, (ip, il) {
      final ret = Native.addPaths(me, ip, il, count);
      return ret;
    });
    return (code, code == 0 ? null : lastError(), count.value);
  } finally {
    calloc.free(count);
  }
}

Future<(int, String?)> _workerCompact(int address) async {
  await ensureNative();
  final me = Pointer<Void>.fromAddress(address);
  final code = Native.compact(me);
  return (code, code == 0 ? null : lastError());
}
