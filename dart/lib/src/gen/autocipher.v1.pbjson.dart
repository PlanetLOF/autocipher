// This is a generated file - do not edit.
//
// Generated from autocipher.v1.proto.

// @dart = 3.3

// ignore_for_file: annotate_overrides, camel_case_types, comment_references
// ignore_for_file: constant_identifier_names
// ignore_for_file: curly_braces_in_flow_control_structures
// ignore_for_file: deprecated_member_use_from_same_package, library_prefixes
// ignore_for_file: non_constant_identifier_names, prefer_relative_imports
// ignore_for_file: unused_import

import 'dart:convert' as $convert;
import 'dart:core' as $core;
import 'dart:typed_data' as $typed_data;

@$core.Deprecated('Use errorCodeDescriptor instead')
const ErrorCode$json = {
  '1': 'ErrorCode',
  '2': [
    {'1': 'ERROR_CODE_UNSPECIFIED', '2': 0},
    {'1': 'WRONG_PASSWORD', '2': 1},
    {'1': 'NOT_FOUND', '2': 2},
    {'1': 'ALREADY_EXISTS', '2': 3},
    {'1': 'CRYPTO', '2': 4},
    {'1': 'IO', '2': 5},
    {'1': 'KDF', '2': 6},
    {'1': 'METADATA_TOO_LARGE', '2': 7},
    {'1': 'INVALID_ARGUMENT', '2': 8},
    {'1': 'INTERNAL', '2': 9},
  ],
};

/// Descriptor for `ErrorCode`. Decode as a `google.protobuf.EnumDescriptorProto`.
final $typed_data.Uint8List errorCodeDescriptor = $convert.base64Decode(
    'CglFcnJvckNvZGUSGgoWRVJST1JfQ09ERV9VTlNQRUNJRklFRBAAEhIKDldST05HX1BBU1NXT1'
    'JEEAESDQoJTk9UX0ZPVU5EEAISEgoOQUxSRUFEWV9FWElTVFMQAxIKCgZDUllQVE8QBBIGCgJJ'
    'TxAFEgcKA0tERhAGEhYKEk1FVEFEQVRBX1RPT19MQVJHRRAHEhQKEElOVkFMSURfQVJHVU1FTl'
    'QQCBIMCghJTlRFUk5BTBAJ');

@$core.Deprecated('Use kdfParamsDescriptor instead')
const KdfParams$json = {
  '1': 'KdfParams',
  '2': [
    {
      '1': 'memory',
      '3': 1,
      '4': 1,
      '5': 14,
      '6': '.autocipher.v1.KdfParams.Memory',
      '10': 'memory'
    },
    {'1': 't', '3': 2, '4': 1, '5': 13, '10': 't'},
    {'1': 'p', '3': 3, '4': 1, '5': 13, '10': 'p'},
  ],
  '4': [KdfParams_Memory$json],
};

@$core.Deprecated('Use kdfParamsDescriptor instead')
const KdfParams_Memory$json = {
  '1': 'Memory',
  '2': [
    {'1': 'M128', '2': 0},
    {'1': 'M256', '2': 1},
    {'1': 'M512', '2': 2},
  ],
};

/// Descriptor for `KdfParams`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List kdfParamsDescriptor = $convert.base64Decode(
    'CglLZGZQYXJhbXMSNwoGbWVtb3J5GAEgASgOMh8uYXV0b2NpcGhlci52MS5LZGZQYXJhbXMuTW'
    'Vtb3J5UgZtZW1vcnkSDAoBdBgCIAEoDVIBdBIMCgFwGAMgASgNUgFwIiYKBk1lbW9yeRIICgRN'
    'MTI4EAASCAoETTI1NhABEggKBE01MTIQAg==');

@$core.Deprecated('Use fileInfoDescriptor instead')
const FileInfo$json = {
  '1': 'FileInfo',
  '2': [
    {'1': 'name', '3': 1, '4': 1, '5': 9, '10': 'name'},
    {'1': 'size', '3': 2, '4': 1, '5': 4, '10': 'size'},
  ],
};

/// Descriptor for `FileInfo`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List fileInfoDescriptor = $convert.base64Decode(
    'CghGaWxlSW5mbxISCgRuYW1lGAEgASgJUgRuYW1lEhIKBHNpemUYAiABKARSBHNpemU=');

@$core.Deprecated('Use pathItemDescriptor instead')
const PathItem$json = {
  '1': 'PathItem',
  '2': [
    {'1': 'src', '3': 1, '4': 1, '5': 9, '10': 'src'},
    {'1': 'stored_name', '3': 2, '4': 1, '5': 9, '10': 'storedName'},
  ],
};

/// Descriptor for `PathItem`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List pathItemDescriptor = $convert.base64Decode(
    'CghQYXRoSXRlbRIQCgNzcmMYASABKAlSA3NyYxIfCgtzdG9yZWRfbmFtZRgCIAEoCVIKc3Rvcm'
    'VkTmFtZQ==');

@$core.Deprecated('Use vaultInfoDescriptor instead')
const VaultInfo$json = {
  '1': 'VaultInfo',
  '2': [
    {'1': 'path', '3': 1, '4': 1, '5': 9, '10': 'path'},
    {'1': 'generation', '3': 2, '4': 1, '5': 4, '10': 'generation'},
    {
      '1': 'kdf',
      '3': 3,
      '4': 1,
      '5': 11,
      '6': '.autocipher.v1.KdfParams',
      '10': 'kdf'
    },
    {'1': 'files', '3': 4, '4': 1, '5': 13, '10': 'files'},
    {'1': 'size_bytes', '3': 5, '4': 1, '5': 4, '10': 'sizeBytes'},
    {'1': 'garbage_bytes', '3': 6, '4': 1, '5': 4, '10': 'garbageBytes'},
    {'1': 'garbage_ratio', '3': 7, '4': 1, '5': 1, '10': 'garbageRatio'},
    {'1': 'header_mirror', '3': 8, '4': 1, '5': 8, '10': 'headerMirror'},
    {'1': 'metadata_mirror', '3': 9, '4': 1, '5': 8, '10': 'metadataMirror'},
  ],
};

/// Descriptor for `VaultInfo`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List vaultInfoDescriptor = $convert.base64Decode(
    'CglWYXVsdEluZm8SEgoEcGF0aBgBIAEoCVIEcGF0aBIeCgpnZW5lcmF0aW9uGAIgASgEUgpnZW'
    '5lcmF0aW9uEioKA2tkZhgDIAEoCzIYLmF1dG9jaXBoZXIudjEuS2RmUGFyYW1zUgNrZGYSFAoF'
    'ZmlsZXMYBCABKA1SBWZpbGVzEh0KCnNpemVfYnl0ZXMYBSABKARSCXNpemVCeXRlcxIjCg1nYX'
    'JiYWdlX2J5dGVzGAYgASgEUgxnYXJiYWdlQnl0ZXMSIwoNZ2FyYmFnZV9yYXRpbxgHIAEoAVIM'
    'Z2FyYmFnZVJhdGlvEiMKDWhlYWRlcl9taXJyb3IYCCABKAhSDGhlYWRlck1pcnJvchInCg9tZX'
    'RhZGF0YV9taXJyb3IYCSABKAhSDm1ldGFkYXRhTWlycm9y');

@$core.Deprecated('Use addPathsDescriptor instead')
const AddPaths$json = {
  '1': 'AddPaths',
  '2': [
    {
      '1': 'items',
      '3': 1,
      '4': 3,
      '5': 11,
      '6': '.autocipher.v1.PathItem',
      '10': 'items'
    },
  ],
};

/// Descriptor for `AddPaths`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List addPathsDescriptor = $convert.base64Decode(
    'CghBZGRQYXRocxItCgVpdGVtcxgBIAMoCzIXLmF1dG9jaXBoZXIudjEuUGF0aEl0ZW1SBWl0ZW'
    '1z');

@$core.Deprecated('Use fileInfoListDescriptor instead')
const FileInfoList$json = {
  '1': 'FileInfoList',
  '2': [
    {
      '1': 'files',
      '3': 1,
      '4': 3,
      '5': 11,
      '6': '.autocipher.v1.FileInfo',
      '10': 'files'
    },
  ],
};

/// Descriptor for `FileInfoList`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List fileInfoListDescriptor = $convert.base64Decode(
    'CgxGaWxlSW5mb0xpc3QSLQoFZmlsZXMYASADKAsyFy5hdXRvY2lwaGVyLnYxLkZpbGVJbmZvUg'
    'VmaWxlcw==');
