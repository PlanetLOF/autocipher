// Password generation over the native ABI.
//
// Generation runs on the Rust side (the same CSPRNG-backed engine as the CLI),
// so every frontend gets byte-identical output. The result crosses as UTF-8
// bytes through the standard measure/fill buffer protocol.

import 'dart:convert';

import 'generated/Native.dart';
import 'native/abi.dart';
import 'vault/exceptions.dart';

/// Generate a cryptographically secure random password.
///
/// The password uses the grouped `XXXXX-XXXXX-XXXXX-XXXXX-XXXXX` format (5
/// hyphen-separated groups of 5 characters) and is guaranteed to contain at
/// least one uppercase letter, one lowercase letter, one digit, and one
/// symbol. The hyphens are part of the password.
///
/// Throws [AutocipherException] when the native side reports a failure.
Future<String> generatePassword() async {
  await ensureNative();
  final (code, data) = Native.bufferCall(Native.generatePassword);
  if (code != 0) {
    throw exceptionFromCode(code, lastError() ?? 'failed to generate password');
  }
  return utf8.decode(data);
}
