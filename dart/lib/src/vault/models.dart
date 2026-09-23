// Domain models returned by `Vault`, mapped from the generated protobuf
// messages.

import '../gen/autocipher.v1.pb.dart';
import 'exceptions.dart';

/// Argon2id cost preset handed to create / change-password.
class KdfPreset {
  const KdfPreset(this.memoryMiB, this.t, this.p);

  /// Memory cost in MiB — one of 128, 256, 512.
  final int memoryMiB;
  final int t;
  final int p;

  static const kdf128 = KdfPreset(128, 3, 2);
  static const kdf256 = KdfPreset(256, 4, 4);
  static const kdf512 = KdfPreset(512, 4, 4);

  KdfParams toWire() => KdfParams(
    memory: switch (memoryMiB) {
      128 => KdfParams_Memory.M128,
      256 => KdfParams_Memory.M256,
      512 => KdfParams_Memory.M512,
      _ => throw InvalidArgumentAutocipherException(
        8,
        'unsupported KDF memory preset: $memoryMiB MiB',
      ),
    },
    t: t,
    p: p,
  );

  @override
  String toString() => '$memoryMiB MiB, t=$t, p=$p';
}

/// A plaintext file entry inside the vault.
class VaultFileInfo {
  const VaultFileInfo(this.name, this.size);
  final String name;
  final int size;

  @override
  bool operator ==(Object other) =>
      other is VaultFileInfo && other.name == name && other.size == size;

  @override
  int get hashCode => Object.hash(name, size);

  @override
  String toString() => 'VaultFileInfo($name, $size bytes)';
}

/// Aggregated `VaultInfo` from the engine.
class VaultInfoModel {
  const VaultInfoModel({
    required this.path,
    required this.generation,
    required this.files,
    required this.sizeBytes,
    required this.garbageBytes,
    required this.garbageRatio,
    required this.headerMirror,
    required this.metadataMirror,
    required this.kdf,
  });

  final String path;
  final int generation;
  final int files;
  final int sizeBytes;
  final int garbageBytes;
  final double garbageRatio;
  final bool headerMirror;
  final bool metadataMirror;
  final String kdf;
}

String describeKdf(KdfParams kdf) {
  final mem = switch (kdf.memory) {
    KdfParams_Memory.M128 => '128 MiB',
    KdfParams_Memory.M256 => '256 MiB',
    KdfParams_Memory.M512 => '512 MiB',
    _ => '?',
  };
  return 'Argon2id $mem t=${kdf.t} p=${kdf.p}';
}
