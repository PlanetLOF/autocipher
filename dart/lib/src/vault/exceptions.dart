// Typed exceptions mirroring the wire `ErrorCode`s, so callers can catch
// specific failures (e.g. a wrong password) instead of parsing messages.

/// Base class for every error surfaced by the vault engine over the FFI ABI.
sealed class AutocipherException implements Exception {
  AutocipherException(this.code, this.message);
  final int code;
  final String message;

  @override
  String toString() => '$runtimeType(code=$code): $message';
}

class WrongPasswordException extends AutocipherException {
  WrongPasswordException(super.code, super.message);
}

class NotFoundInVaultException extends AutocipherException {
  NotFoundInVaultException(super.code, super.message);
}

class AlreadyExistsException extends AutocipherException {
  AlreadyExistsException(super.code, super.message);
}

class CryptoException extends AutocipherException {
  CryptoException(super.code, super.message);
}

class IoException extends AutocipherException {
  IoException(super.code, super.message);
}

class KdfException extends AutocipherException {
  KdfException(super.code, super.message);
}

class MetadataTooLargeException extends AutocipherException {
  MetadataTooLargeException(super.code, super.message);
}

class InvalidArgumentAutocipherException extends AutocipherException {
  InvalidArgumentAutocipherException(super.code, super.message);
}

class InternalAutocipherException extends AutocipherException {
  InternalAutocipherException(super.code, super.message);
}

/// Build the typed exception for a wire `ErrorCode` value.
AutocipherException exceptionFromCode(int code, String message) {
  switch (code) {
    case 1:
      return WrongPasswordException(code, message);
    case 2:
      return NotFoundInVaultException(code, message);
    case 3:
      return AlreadyExistsException(code, message);
    case 4:
      return CryptoException(code, message);
    case 5:
      return IoException(code, message);
    case 6:
      return KdfException(code, message);
    case 7:
      return MetadataTooLargeException(code, message);
    case 8:
      return InvalidArgumentAutocipherException(code, message);
    case 9:
      return InternalAutocipherException(code, message);
    default:
      return InternalAutocipherException(
        code,
        'unknown error code $code: $message',
      );
  }
}