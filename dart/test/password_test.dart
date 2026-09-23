// Live test of the grouped password generation over the real native library.
//
// Skipped (with a message) when no library can be found; see
// `vault_lifecycle_test.dart` for the AUTOCIPHER_FFI_LIB override pattern.

import 'dart:io';

import 'package:autocipher_dart/autocipher_dart.dart';
import 'package:test/test.dart';

final _libOverride = Platform.environment['AUTOCIPHER_FFI_LIB'];
bool _isSkipped() => _libOverride == null || !File(_libOverride!).existsSync();

void main() {
  setUpAll(() {
    if (_isSkipped()) {
      markTestSkipped(
        'No native library configured; set AUTOCIPHER_FFI_LIB to the built '
        'autocipher_ffi.dll (release) to run the live password test.',
      );
    } else {
      ensureAbiCompatible();
    }
  });

  test(
    'generatePassword returns the grouped XXXXX-XXXXX-XXXXX-XXXXX-XXXXX shape',
    () async {
      final pwd = await generatePassword();
      expect(
        pwd.length,
        29,
        reason: '5 groups of 5 chars plus 4 hyphens: $pwd',
      );
      for (var i = 0; i < pwd.length; i++) {
        final isHyphen = pwd.codeUnitAt(i) == 0x2d;
        expect(
          isHyphen,
          i == 5 || i == 11 || i == 17 || i == 23,
          reason: 'unexpected character at index $i: $pwd',
        );
      }
    },
  );

  test('generatePassword produces distinct outputs', () async {
    final a = await generatePassword();
    final b = await generatePassword();
    expect(a, isNot(b));
  });
}
