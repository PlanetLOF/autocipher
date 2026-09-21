// This is a generated file - do not edit.
//
// Generated from autocipher.v1.proto.

// @dart = 3.3

// ignore_for_file: annotate_overrides, camel_case_types, comment_references
// ignore_for_file: constant_identifier_names
// ignore_for_file: curly_braces_in_flow_control_structures
// ignore_for_file: deprecated_member_use_from_same_package, library_prefixes
// ignore_for_file: non_constant_identifier_names, prefer_relative_imports

import 'dart:core' as $core;

import 'package:protobuf/protobuf.dart' as $pb;

class ErrorCode extends $pb.ProtobufEnum {
  static const ErrorCode ERROR_CODE_UNSPECIFIED =
      ErrorCode._(0, _omitEnumNames ? '' : 'ERROR_CODE_UNSPECIFIED');
  static const ErrorCode WRONG_PASSWORD =
      ErrorCode._(1, _omitEnumNames ? '' : 'WRONG_PASSWORD');
  static const ErrorCode NOT_FOUND =
      ErrorCode._(2, _omitEnumNames ? '' : 'NOT_FOUND');
  static const ErrorCode ALREADY_EXISTS =
      ErrorCode._(3, _omitEnumNames ? '' : 'ALREADY_EXISTS');
  static const ErrorCode CRYPTO =
      ErrorCode._(4, _omitEnumNames ? '' : 'CRYPTO');
  static const ErrorCode IO = ErrorCode._(5, _omitEnumNames ? '' : 'IO');
  static const ErrorCode KDF = ErrorCode._(6, _omitEnumNames ? '' : 'KDF');
  static const ErrorCode METADATA_TOO_LARGE =
      ErrorCode._(7, _omitEnumNames ? '' : 'METADATA_TOO_LARGE');
  static const ErrorCode INVALID_ARGUMENT =
      ErrorCode._(8, _omitEnumNames ? '' : 'INVALID_ARGUMENT');
  static const ErrorCode INTERNAL =
      ErrorCode._(9, _omitEnumNames ? '' : 'INTERNAL');

  static const $core.List<ErrorCode> values = <ErrorCode>[
    ERROR_CODE_UNSPECIFIED,
    WRONG_PASSWORD,
    NOT_FOUND,
    ALREADY_EXISTS,
    CRYPTO,
    IO,
    KDF,
    METADATA_TOO_LARGE,
    INVALID_ARGUMENT,
    INTERNAL,
  ];

  static final $core.List<ErrorCode?> _byValue =
      $pb.ProtobufEnum.$_initByValueList(values, 9);
  static ErrorCode? valueOf($core.int value) =>
      value < 0 || value >= _byValue.length ? null : _byValue[value];

  const ErrorCode._(super.value, super.name);
}

class KdfParams_Memory extends $pb.ProtobufEnum {
  static const KdfParams_Memory M128 =
      KdfParams_Memory._(0, _omitEnumNames ? '' : 'M128');
  static const KdfParams_Memory M256 =
      KdfParams_Memory._(1, _omitEnumNames ? '' : 'M256');
  static const KdfParams_Memory M512 =
      KdfParams_Memory._(2, _omitEnumNames ? '' : 'M512');

  static const $core.List<KdfParams_Memory> values = <KdfParams_Memory>[
    M128,
    M256,
    M512,
  ];

  static final $core.List<KdfParams_Memory?> _byValue =
      $pb.ProtobufEnum.$_initByValueList(values, 2);
  static KdfParams_Memory? valueOf($core.int value) =>
      value < 0 || value >= _byValue.length ? null : _byValue[value];

  const KdfParams_Memory._(super.value, super.name);
}

const $core.bool _omitEnumNames =
    $core.bool.fromEnvironment('protobuf.omit_enum_names');
