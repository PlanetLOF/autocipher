/// autocipher_dart — pure-Dart bindings for the autocipher vault engine.
///
/// ```dart
/// final vault = await Vault.create(path, password, KdfPreset.kdf128);
/// await vault.addPaths([(src: '~/Photos', storedName: 'photos')]);
/// final files = await vault.listFiles();
/// await vault.close();
/// ```
library;

export 'src/generated/Native.dart';
export 'src/native/abi.dart';
export 'src/native/library.dart';
export 'src/password.dart';
export 'src/vault/exceptions.dart';
export 'src/vault/models.dart';
export 'src/vault/vault.dart';
