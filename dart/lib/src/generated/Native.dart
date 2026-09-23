// GENERATED CODE — DO NOT EDIT. Run: just generate-dart
// The authoritative definition set is in rust/bridge/shared/src (the #[ac_fn] list).

// ignore_for_file: public_member_api_docs, constant_identifier_names

import 'dart:convert';
import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

const int kAbiMajor = 1;
const int kAbiMinor = 1;

/// Caller-owned I/O buffer for byte payloads crossing the ABI.
/// Double-call protocol: pass a buffer; if too small the op returns
/// len = required size and base = null, call again with the size.
final class AcOutBuffer extends Struct {
  external Pointer<Uint8> base;
  @IntPtr()
  external int len;
}

/// Raw, generated bindings for the autocipher C ABI.
/// Load the library with [use] before calling any op.
final class Native {
  Native._();

  static DynamicLibrary? _lib;
  static bool get isLoaded => _lib != null;
  static void use(DynamicLibrary lib) => _lib = lib;

  /// ABI handshake. Fills 0 on any null output pointer.
  static int acVersion(
    Pointer<Int32> outMajor,
    Pointer<Int32> outMinor,
    Pointer<Int32> outPatch,
  ) =>
      _lib!.lookupFunction<
        Int32 Function(Pointer<Int32>, Pointer<Int32>, Pointer<Int32>),
        int Function(Pointer<Int32>, Pointer<Int32>, Pointer<Int32>)
      >('ac_version')(outMajor, outMinor, outPatch);

  /// Diagnostic text from the most recent failed call.
  static int autocipherErrorMessage(Pointer<AcOutBuffer> out) =>
      _lib!.lookupFunction<
        Int32 Function(Pointer<AcOutBuffer>),
        int Function(Pointer<AcOutBuffer>)
      >('autocipher_error_message')(out);

  /// Releases an opaque Vault handle (NULL is a no-op).
  static void VaultDestroy(Pointer<Void> me) =>
      _lib!.lookupFunction<
        Void Function(Pointer<Void>),
        void Function(Pointer<Void>)
      >('autocipher_vault_destroy')(me);

  /// Generate a cryptographically secure random password as UTF-8 bytes in the grouped XXXXX-XXXXX-XXXXX-XXXXX-XXXXX format.
  static int generatePassword(Pointer<AcOutBuffer> out) =>
      _lib!.lookupFunction<
        Int32 Function(Pointer<AcOutBuffer>),
        int Function(Pointer<AcOutBuffer> out)
      >('autocipher_generate_password')(out);

  /// Import files/trees; `items` is an encoded AddPaths protobuf. Returns the number of files added.
  static int addPaths(
    Pointer<Void> me,
    Pointer<Uint8> items,
    int itemsLen,
    Pointer<Uint32> count,
  ) =>
      _lib!.lookupFunction<
        Int32 Function(Pointer<Void>, Pointer<Uint8>, IntPtr, Pointer<Uint32>),
        int Function(
          Pointer<Void> me,
          Pointer<Uint8> items,
          int itemsLen,
          Pointer<Uint32> count,
        )
      >('autocipher_vault_add_paths')(me, items, itemsLen, count);

  /// Re-wrap the master key under a new password and KDF parameters; `params` is encoded KdfParams.
  static int changePassword(
    Pointer<Void> me,
    Pointer<Uint8> new_password,
    int new_passwordLen,
    Pointer<Uint8> params,
    int paramsLen,
  ) =>
      _lib!.lookupFunction<
        Int32 Function(
          Pointer<Void>,
          Pointer<Uint8>,
          IntPtr,
          Pointer<Uint8>,
          IntPtr,
        ),
        int Function(
          Pointer<Void> me,
          Pointer<Uint8> new_password,
          int new_passwordLen,
          Pointer<Uint8> params,
          int paramsLen,
        )
      >('autocipher_vault_change_password')(
        me,
        new_password,
        new_passwordLen,
        params,
        paramsLen,
      );

  /// Rewrite the vault file to drop garbage space.
  static int compact(Pointer<Void> me) =>
      _lib!.lookupFunction<
        Int32 Function(Pointer<Void>),
        int Function(Pointer<Void> me)
      >('autocipher_vault_compact')(me);

  /// Create a new empty vault at `path` with the given KDF parameters and password.
  static int createVault(
    Pointer<Uint8> path,
    int pathLen,
    Pointer<Uint8> password,
    int passwordLen,
    Pointer<Uint8> params,
    int paramsLen,
    Pointer<Pointer<Void>> outHandle,
  ) =>
      _lib!.lookupFunction<
        Int32 Function(
          Pointer<Uint8>,
          IntPtr,
          Pointer<Uint8>,
          IntPtr,
          Pointer<Uint8>,
          IntPtr,
          Pointer<Pointer<Void>>,
        ),
        int Function(
          Pointer<Uint8> path,
          int pathLen,
          Pointer<Uint8> password,
          int passwordLen,
          Pointer<Uint8> params,
          int paramsLen,
          Pointer<Pointer<Void>> outHandle,
        )
      >('autocipher_vault_create')(
        path,
        pathLen,
        password,
        passwordLen,
        params,
        paramsLen,
        outHandle,
      );

  /// Delete the named stored file.
  static int delete(Pointer<Void> me, Pointer<Uint8> name, int nameLen) =>
      _lib!.lookupFunction<
        Int32 Function(Pointer<Void>, Pointer<Uint8>, IntPtr),
        int Function(Pointer<Void> me, Pointer<Uint8> name, int nameLen)
      >('autocipher_vault_delete')(me, name, nameLen);

  /// Extract the named stored file to `dest` on the filesystem.
  static int extract(
    Pointer<Void> me,
    Pointer<Uint8> name,
    int nameLen,
    Pointer<Uint8> dest,
    int destLen,
  ) =>
      _lib!.lookupFunction<
        Int32 Function(
          Pointer<Void>,
          Pointer<Uint8>,
          IntPtr,
          Pointer<Uint8>,
          IntPtr,
        ),
        int Function(
          Pointer<Void> me,
          Pointer<Uint8> name,
          int nameLen,
          Pointer<Uint8> dest,
          int destLen,
        )
      >('autocipher_vault_extract')(me, name, nameLen, dest, destLen);

  /// Aggregate vault metadata as an encoded VaultInfo protobuf.
  static int info(Pointer<Void> me, Pointer<AcOutBuffer> out) =>
      _lib!.lookupFunction<
        Int32 Function(Pointer<Void>, Pointer<AcOutBuffer>),
        int Function(Pointer<Void> me, Pointer<AcOutBuffer> out)
      >('autocipher_vault_info')(me, out);

  /// List the files in the vault as an encoded FileInfoList protobuf.
  static int list(Pointer<Void> me, Pointer<AcOutBuffer> out) =>
      _lib!.lookupFunction<
        Int32 Function(Pointer<Void>, Pointer<AcOutBuffer>),
        int Function(Pointer<Void> me, Pointer<AcOutBuffer> out)
      >('autocipher_vault_list')(me, out);

  /// Open the vault at `path` with the given password.
  static int openVault(
    Pointer<Uint8> path,
    int pathLen,
    Pointer<Uint8> password,
    int passwordLen,
    Pointer<Pointer<Void>> outHandle,
  ) =>
      _lib!.lookupFunction<
        Int32 Function(
          Pointer<Uint8>,
          IntPtr,
          Pointer<Uint8>,
          IntPtr,
          Pointer<Pointer<Void>>,
        ),
        int Function(
          Pointer<Uint8> path,
          int pathLen,
          Pointer<Uint8> password,
          int passwordLen,
          Pointer<Pointer<Void>> outHandle,
        )
      >('autocipher_vault_open')(
        path,
        pathLen,
        password,
        passwordLen,
        outHandle,
      );

  /// Write `data` to the named stored file, creating or overwriting it.
  static int put(
    Pointer<Void> me,
    Pointer<Uint8> name,
    int nameLen,
    Pointer<Uint8> data,
    int dataLen,
  ) =>
      _lib!.lookupFunction<
        Int32 Function(
          Pointer<Void>,
          Pointer<Uint8>,
          IntPtr,
          Pointer<Uint8>,
          IntPtr,
        ),
        int Function(
          Pointer<Void> me,
          Pointer<Uint8> name,
          int nameLen,
          Pointer<Uint8> data,
          int dataLen,
        )
      >('autocipher_vault_put')(me, name, nameLen, data, dataLen);

  /// Read `len` bytes starting at `offset` from the named stored file.
  static int readRange(
    Pointer<Void> me,
    Pointer<Uint8> name,
    int nameLen,
    int offset,
    int len,
    Pointer<AcOutBuffer> out,
  ) =>
      _lib!.lookupFunction<
        Int32 Function(
          Pointer<Void>,
          Pointer<Uint8>,
          IntPtr,
          Int64,
          Int64,
          Pointer<AcOutBuffer>,
        ),
        int Function(
          Pointer<Void> me,
          Pointer<Uint8> name,
          int nameLen,
          int offset,
          int len,
          Pointer<AcOutBuffer> out,
        )
      >('autocipher_vault_read_range')(me, name, nameLen, offset, len, out);

  /// Rewrite the sidecar mirrors from the primary vault file.
  static int remirror(Pointer<Void> me) =>
      _lib!.lookupFunction<
        Int32 Function(Pointer<Void>),
        int Function(Pointer<Void> me)
      >('autocipher_vault_remirror')(me);

  /// Rename the stored file `old` to `new`.
  static int rename(
    Pointer<Void> me,
    Pointer<Uint8> old,
    int oldLen,
    Pointer<Uint8> new_name,
    int new_nameLen,
  ) =>
      _lib!.lookupFunction<
        Int32 Function(
          Pointer<Void>,
          Pointer<Uint8>,
          IntPtr,
          Pointer<Uint8>,
          IntPtr,
        ),
        int Function(
          Pointer<Void> me,
          Pointer<Uint8> old,
          int oldLen,
          Pointer<Uint8> new_name,
          int new_nameLen,
        )
      >('autocipher_vault_rename')(me, old, oldLen, new_name, new_nameLen);

  /// Return the uncompressed size in bytes of the named stored file.
  static int size(
    Pointer<Void> me,
    Pointer<Uint8> name,
    int nameLen,
    Pointer<Uint64> out,
  ) =>
      _lib!.lookupFunction<
        Int32 Function(Pointer<Void>, Pointer<Uint8>, IntPtr, Pointer<Uint64>),
        int Function(
          Pointer<Void> me,
          Pointer<Uint8> name,
          int nameLen,
          Pointer<Uint64> out,
        )
      >('autocipher_vault_size')(me, name, nameLen, out);

  /// Measure/fill dance for a buffer-returning op.
  /// Returns (code, bytes); code == 0 means success.
  static (int, Uint8List) bufferCall(int Function(Pointer<AcOutBuffer>) call) {
    final out = calloc<AcOutBuffer>();
    try {
      out.ref.base = nullptr;
      out.ref.len = 0;
      var code = call(out);
      if (code != 0) return (code, Uint8List(0));
      final need = out.ref.len;
      if (need == 0) return (0, Uint8List(0));
      final p = calloc<Uint8>(need);
      try {
        out.ref.base = p;
        out.ref.len = need;
        code = call(out);
        if (code != 0) return (code, Uint8List(0));
        final len = out.ref.len;
        return (
          0,
          len == 0 ? Uint8List(0) : Uint8List.fromList(p.asTypedList(len)),
        );
      } finally {
        calloc.free(p);
      }
    } finally {
      calloc.free(out);
    }
  }

  /// Run [body] with a NUL-free UTF-8 encoding of [s]; frees after.
  static T withUtf8<T>(String s, T Function(Pointer<Uint8> ptr, int len) body) {
    final bytes = utf8.encode(s);
    if (bytes.isEmpty) return body(nullptr, 0);
    final p = calloc<Uint8>(bytes.length);
    try {
      p.asTypedList(bytes.length).setAll(0, bytes);
      return body(p, bytes.length);
    } finally {
      calloc.free(p);
    }
  }

  /// Run [body] with a copy of [data]; frees after.
  static T withSlice<T>(
    Uint8List data,
    T Function(Pointer<Uint8> ptr, int len) body,
  ) {
    if (data.isEmpty) return body(nullptr, 0);
    final p = calloc<Uint8>(data.length);
    try {
      p.asTypedList(data.length).setAll(0, data);
      return body(p, data.length);
    } finally {
      calloc.free(p);
    }
  }
}
