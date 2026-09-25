// End-to-end lifecycle through the real native library.
//
// Skipped (with a message) when no library can be found. Point
// AUTOCIPHER_FFI_LIB at the built DLL to force a specific build, e.g.:
//   $env:AUTOCIPHER_FFI_LIB = '..\target\release\autocipher_ffi.dll'
// Run against a release build — the debug DLL makes Argon2id prohibitive.

import 'dart:io';
import 'dart:typed_data';

import 'package:autocipher_dart/src/native/abi.dart';
import 'package:autocipher_dart/src/vault/exceptions.dart';
import 'package:autocipher_dart/src/vault/models.dart';
import 'package:autocipher_dart/src/vault/vault.dart';
import 'package:test/test.dart';

final _libOverride = Platform.environment['AUTOCIPHER_FFI_LIB'];
bool _isSkipped() => _libOverride == null || !File(_libOverride!).existsSync();

void main() {
  setUpAll(() async {
    if (_isSkipped()) {
      markTestSkipped(
        'No native library configured; set AUTOCIPHER_FFI_LIB to the built '
        'autocipher_ffi.dll (release) to run the live lifecycle test.',
      );
    } else {
      await ensureAbiCompatible();
    }
  });

  Directory? tempDir;
  late String vaultPath;

  setUp(() async {
    tempDir = await Directory.systemTemp.createTemp('ac_vault_');
    vaultPath = '${tempDir!.path}${Platform.pathSeparator}test.vlt';
  });

  tearDown(() {
    tempDir?.deleteSync(recursive: true);
  });

  test('full lifecycle over the FFI ABI', () async {
    final kdf = KdfPreset.kdf128;

    // create
    final vault = await Vault.create(vaultPath, 'hunter2', kdf);
    addTearDown(() => vault.close());

    // import a host file
    final src = File('${tempDir!.path}${Platform.pathSeparator}src.txt')
      ..writeAsStringSync('hello autocipher\n');
    final added = await vault.addPaths([
      (src: src.path, storedName: 'stuff/notes.txt'),
    ]);
    expect(added, greaterThanOrEqualTo(1));

    // list + size
    var files = await vault.listFiles();
    expect(files.any((f) => f.name == 'stuff/notes.txt'), isTrue);
    final imported = files.singleWhere((f) => f.name == 'stuff/notes.txt');
    expect(imported.createdAt, greaterThan(0));
    expect(imported.modifiedAt, imported.createdAt);
    expect(imported.storageUsed, greaterThan(imported.size));

    // put + readRange round-trip
    final blob = Uint8List.fromList(List.generate(1000, (i) => i % 251));
    await vault.put('data.bin', blob);
    expect(vault.size('data.bin'), 1000);
    final got = await vault.readRange('data.bin', offset: 0, len: 1000);
    expect(got, equals(blob));

    // rename
    await vault.rename('data.bin', 'renamed.bin');
    files = await vault.listFiles();
    expect(files.any((f) => f.name == 'renamed.bin'), isTrue);
    expect(files.any((f) => f.name == 'data.bin'), isFalse);

    // extract back to host
    final dest = File('${tempDir!.path}${Platform.pathSeparator}out.txt');
    await vault.extract('stuff/notes.txt', dest.path);
    expect(dest.readAsStringSync(), 'hello autocipher\n');

    // info
    final info = await vault.info();
    expect(info.path, vaultPath);
    expect(info.generation, greaterThanOrEqualTo(1));
    expect(info.files, greaterThanOrEqualTo(2));
    expect(info.sizeBytes, greaterThan(0));
    expect(info.kdf, contains('Argon2id'));

    // change password (re-wraps master key)
    await vault.changePassword('newpw', KdfPreset.kdf256);

    // compact + remirror
    await vault.compact();
    await vault.remirror();

    // reopen under the new password
    await vault.close();
    await expectLater(
      Vault.open(vaultPath, 'wrong'),
      throwsA(isA<WrongPasswordException>()),
    );
    final reopened = await Vault.open(vaultPath, 'newpw');
    addTearDown(() => reopened.close());
    final back = await reopened.readRange('renamed.bin', offset: 0, len: 1000);
    expect(back, equals(blob));
    final reopenedEntry = (await reopened.listFiles()).singleWhere(
      (f) => f.name == 'renamed.bin',
    );
    expect(reopenedEntry.createdAt, greaterThan(0));
    expect(
      reopenedEntry.modifiedAt,
      greaterThanOrEqualTo(reopenedEntry.createdAt),
    );
    expect(reopenedEntry.storageUsed, greaterThan(reopenedEntry.size));

    // delete
    await reopened.delete('renamed.bin');
    files = await reopened.listFiles();
    expect(files.any((f) => f.name == 'renamed.bin'), isFalse);
    await expectLater(
      reopened.readRange('renamed.bin', offset: 0, len: 16),
      throwsA(isA<NotFoundInVaultException>()),
    );
  });
}
