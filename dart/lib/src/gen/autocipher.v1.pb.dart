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

import 'package:fixnum/fixnum.dart' as $fixnum;
import 'package:protobuf/protobuf.dart' as $pb;

import 'autocipher.v1.pbenum.dart';

export 'package:protobuf/protobuf.dart' show GeneratedMessageGenericExtensions;

export 'autocipher.v1.pbenum.dart';

class KdfParams extends $pb.GeneratedMessage {
  factory KdfParams({
    KdfParams_Memory? memory,
    $core.int? t,
    $core.int? p,
  }) {
    final result = KdfParams._();
    if (memory != null) result.memory = memory;
    if (t != null) result.t = t;
    if (p != null) result.p = p;
    return result;
  }

  KdfParams._();

  factory KdfParams.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      KdfParams()..mergeFromBuffer(data, registry);
  factory KdfParams.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      KdfParams()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'KdfParams',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'autocipher.v1'),
      createEmptyInstance: KdfParams.$_createMessage)
    ..aE<KdfParams_Memory>(1, _omitFieldNames ? '' : 'memory',
        enumValues: KdfParams_Memory.values)
    ..aI(2, _omitFieldNames ? '' : 't', fieldType: $pb.PbFieldType.OU3)
    ..aI(3, _omitFieldNames ? '' : 'p', fieldType: $pb.PbFieldType.OU3)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  KdfParams clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  KdfParams copyWith(void Function(KdfParams) updates) =>
      super.copyWith((message) => updates(message as KdfParams)) as KdfParams;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated('Use KdfParams() / KdfParams.new instead')
  static KdfParams create() => KdfParams._();
  static $pb.GeneratedMessage $_createMessage() => KdfParams._();
  @$core.override
  KdfParams createEmptyInstance() => KdfParams._();
  @$core.pragma('dart2js:noInline')
  static KdfParams getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<KdfParams>(KdfParams.$_createMessage);
  static KdfParams? _defaultInstance;

  @$pb.TagNumber(1)
  KdfParams_Memory get memory => $_getN(0);
  @$pb.TagNumber(1)
  set memory(KdfParams_Memory value) => $_setField(1, value);
  @$pb.TagNumber(1)
  $core.bool hasMemory() => $_has(0);
  @$pb.TagNumber(1)
  void clearMemory() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.int get t => $_getIZ(1);
  @$pb.TagNumber(2)
  set t($core.int value) => $_setUnsignedInt32(1, value);
  @$pb.TagNumber(2)
  $core.bool hasT() => $_has(1);
  @$pb.TagNumber(2)
  void clearT() => $_clearField(2);

  @$pb.TagNumber(3)
  $core.int get p => $_getIZ(2);
  @$pb.TagNumber(3)
  set p($core.int value) => $_setUnsignedInt32(2, value);
  @$pb.TagNumber(3)
  $core.bool hasP() => $_has(2);
  @$pb.TagNumber(3)
  void clearP() => $_clearField(3);
}

class FileInfo extends $pb.GeneratedMessage {
  factory FileInfo({
    $core.String? name,
    $fixnum.Int64? size,
    $fixnum.Int64? createdAt,
    $fixnum.Int64? modifiedAt,
    $fixnum.Int64? storageUsed,
  }) {
    final result = FileInfo._();
    if (name != null) result.name = name;
    if (size != null) result.size = size;
    if (createdAt != null) result.createdAt = createdAt;
    if (modifiedAt != null) result.modifiedAt = modifiedAt;
    if (storageUsed != null) result.storageUsed = storageUsed;
    return result;
  }

  FileInfo._();

  factory FileInfo.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      FileInfo()..mergeFromBuffer(data, registry);
  factory FileInfo.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      FileInfo()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'FileInfo',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'autocipher.v1'),
      createEmptyInstance: FileInfo.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'name')
    ..a<$fixnum.Int64>(2, _omitFieldNames ? '' : 'size', $pb.PbFieldType.OU6,
        defaultOrMaker: $fixnum.Int64.ZERO)
    ..a<$fixnum.Int64>(
        3, _omitFieldNames ? '' : 'createdAt', $pb.PbFieldType.OU6,
        defaultOrMaker: $fixnum.Int64.ZERO)
    ..a<$fixnum.Int64>(
        4, _omitFieldNames ? '' : 'modifiedAt', $pb.PbFieldType.OU6,
        defaultOrMaker: $fixnum.Int64.ZERO)
    ..a<$fixnum.Int64>(
        5, _omitFieldNames ? '' : 'storageUsed', $pb.PbFieldType.OU6,
        defaultOrMaker: $fixnum.Int64.ZERO)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  FileInfo clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  FileInfo copyWith(void Function(FileInfo) updates) =>
      super.copyWith((message) => updates(message as FileInfo)) as FileInfo;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated('Use FileInfo() / FileInfo.new instead')
  static FileInfo create() => FileInfo._();
  static $pb.GeneratedMessage $_createMessage() => FileInfo._();
  @$core.override
  FileInfo createEmptyInstance() => FileInfo._();
  @$core.pragma('dart2js:noInline')
  static FileInfo getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<FileInfo>(FileInfo.$_createMessage);
  static FileInfo? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get name => $_getSZ(0);
  @$pb.TagNumber(1)
  set name($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasName() => $_has(0);
  @$pb.TagNumber(1)
  void clearName() => $_clearField(1);

  @$pb.TagNumber(2)
  $fixnum.Int64 get size => $_getI64(1);
  @$pb.TagNumber(2)
  set size($fixnum.Int64 value) => $_setInt64(1, value);
  @$pb.TagNumber(2)
  $core.bool hasSize() => $_has(1);
  @$pb.TagNumber(2)
  void clearSize() => $_clearField(2);

  /// Vault-operation Unix timestamps in seconds; zero means unknown. These do
  /// not mirror source-filesystem timestamps.
  @$pb.TagNumber(3)
  $fixnum.Int64 get createdAt => $_getI64(2);
  @$pb.TagNumber(3)
  set createdAt($fixnum.Int64 value) => $_setInt64(2, value);
  @$pb.TagNumber(3)
  $core.bool hasCreatedAt() => $_has(2);
  @$pb.TagNumber(3)
  void clearCreatedAt() => $_clearField(3);

  @$pb.TagNumber(4)
  $fixnum.Int64 get modifiedAt => $_getI64(3);
  @$pb.TagNumber(4)
  set modifiedAt($fixnum.Int64 value) => $_setInt64(3, value);
  @$pb.TagNumber(4)
  $core.bool hasModifiedAt() => $_has(3);
  @$pb.TagNumber(4)
  void clearModifiedAt() => $_clearField(4);

  /// Sum of encrypted chunk lengths referenced by this file. This is logical
  /// storage accounting and can survive structural recovery of metadata.
  @$pb.TagNumber(5)
  $fixnum.Int64 get storageUsed => $_getI64(4);
  @$pb.TagNumber(5)
  set storageUsed($fixnum.Int64 value) => $_setInt64(4, value);
  @$pb.TagNumber(5)
  $core.bool hasStorageUsed() => $_has(4);
  @$pb.TagNumber(5)
  void clearStorageUsed() => $_clearField(5);
}

class PathItem extends $pb.GeneratedMessage {
  factory PathItem({
    $core.String? src,
    $core.String? storedName,
  }) {
    final result = PathItem._();
    if (src != null) result.src = src;
    if (storedName != null) result.storedName = storedName;
    return result;
  }

  PathItem._();

  factory PathItem.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      PathItem()..mergeFromBuffer(data, registry);
  factory PathItem.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      PathItem()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'PathItem',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'autocipher.v1'),
      createEmptyInstance: PathItem.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'src')
    ..aOS(2, _omitFieldNames ? '' : 'storedName')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  PathItem clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  PathItem copyWith(void Function(PathItem) updates) =>
      super.copyWith((message) => updates(message as PathItem)) as PathItem;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated('Use PathItem() / PathItem.new instead')
  static PathItem create() => PathItem._();
  static $pb.GeneratedMessage $_createMessage() => PathItem._();
  @$core.override
  PathItem createEmptyInstance() => PathItem._();
  @$core.pragma('dart2js:noInline')
  static PathItem getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<PathItem>(PathItem.$_createMessage);
  static PathItem? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get src => $_getSZ(0);
  @$pb.TagNumber(1)
  set src($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasSrc() => $_has(0);
  @$pb.TagNumber(1)
  void clearSrc() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.String get storedName => $_getSZ(1);
  @$pb.TagNumber(2)
  set storedName($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasStoredName() => $_has(1);
  @$pb.TagNumber(2)
  void clearStoredName() => $_clearField(2);
}

class VaultInfo extends $pb.GeneratedMessage {
  factory VaultInfo({
    $core.String? path,
    $fixnum.Int64? generation,
    KdfParams? kdf,
    $core.int? files,
    $fixnum.Int64? sizeBytes,
    $fixnum.Int64? garbageBytes,
    $core.double? garbageRatio,
    $core.bool? headerMirror,
    $core.bool? metadataMirror,
  }) {
    final result = VaultInfo._();
    if (path != null) result.path = path;
    if (generation != null) result.generation = generation;
    if (kdf != null) result.kdf = kdf;
    if (files != null) result.files = files;
    if (sizeBytes != null) result.sizeBytes = sizeBytes;
    if (garbageBytes != null) result.garbageBytes = garbageBytes;
    if (garbageRatio != null) result.garbageRatio = garbageRatio;
    if (headerMirror != null) result.headerMirror = headerMirror;
    if (metadataMirror != null) result.metadataMirror = metadataMirror;
    return result;
  }

  VaultInfo._();

  factory VaultInfo.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      VaultInfo()..mergeFromBuffer(data, registry);
  factory VaultInfo.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      VaultInfo()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'VaultInfo',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'autocipher.v1'),
      createEmptyInstance: VaultInfo.$_createMessage)
    ..aOS(1, _omitFieldNames ? '' : 'path')
    ..a<$fixnum.Int64>(
        2, _omitFieldNames ? '' : 'generation', $pb.PbFieldType.OU6,
        defaultOrMaker: $fixnum.Int64.ZERO)
    ..aOM<KdfParams>(3, _omitFieldNames ? '' : 'kdf',
        subBuilder: KdfParams.$_createMessage)
    ..aI(4, _omitFieldNames ? '' : 'files', fieldType: $pb.PbFieldType.OU3)
    ..a<$fixnum.Int64>(
        5, _omitFieldNames ? '' : 'sizeBytes', $pb.PbFieldType.OU6,
        defaultOrMaker: $fixnum.Int64.ZERO)
    ..a<$fixnum.Int64>(
        6, _omitFieldNames ? '' : 'garbageBytes', $pb.PbFieldType.OU6,
        defaultOrMaker: $fixnum.Int64.ZERO)
    ..aD(7, _omitFieldNames ? '' : 'garbageRatio')
    ..aOB(8, _omitFieldNames ? '' : 'headerMirror')
    ..aOB(9, _omitFieldNames ? '' : 'metadataMirror')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  VaultInfo clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  VaultInfo copyWith(void Function(VaultInfo) updates) =>
      super.copyWith((message) => updates(message as VaultInfo)) as VaultInfo;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated('Use VaultInfo() / VaultInfo.new instead')
  static VaultInfo create() => VaultInfo._();
  static $pb.GeneratedMessage $_createMessage() => VaultInfo._();
  @$core.override
  VaultInfo createEmptyInstance() => VaultInfo._();
  @$core.pragma('dart2js:noInline')
  static VaultInfo getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<VaultInfo>(VaultInfo.$_createMessage);
  static VaultInfo? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get path => $_getSZ(0);
  @$pb.TagNumber(1)
  set path($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasPath() => $_has(0);
  @$pb.TagNumber(1)
  void clearPath() => $_clearField(1);

  @$pb.TagNumber(2)
  $fixnum.Int64 get generation => $_getI64(1);
  @$pb.TagNumber(2)
  set generation($fixnum.Int64 value) => $_setInt64(1, value);
  @$pb.TagNumber(2)
  $core.bool hasGeneration() => $_has(1);
  @$pb.TagNumber(2)
  void clearGeneration() => $_clearField(2);

  @$pb.TagNumber(3)
  KdfParams get kdf => $_getN(2);
  @$pb.TagNumber(3)
  set kdf(KdfParams value) => $_setField(3, value);
  @$pb.TagNumber(3)
  $core.bool hasKdf() => $_has(2);
  @$pb.TagNumber(3)
  void clearKdf() => $_clearField(3);
  @$pb.TagNumber(3)
  KdfParams ensureKdf() => $_ensure(2);

  @$pb.TagNumber(4)
  $core.int get files => $_getIZ(3);
  @$pb.TagNumber(4)
  set files($core.int value) => $_setUnsignedInt32(3, value);
  @$pb.TagNumber(4)
  $core.bool hasFiles() => $_has(3);
  @$pb.TagNumber(4)
  void clearFiles() => $_clearField(4);

  @$pb.TagNumber(5)
  $fixnum.Int64 get sizeBytes => $_getI64(4);
  @$pb.TagNumber(5)
  set sizeBytes($fixnum.Int64 value) => $_setInt64(4, value);
  @$pb.TagNumber(5)
  $core.bool hasSizeBytes() => $_has(4);
  @$pb.TagNumber(5)
  void clearSizeBytes() => $_clearField(5);

  @$pb.TagNumber(6)
  $fixnum.Int64 get garbageBytes => $_getI64(5);
  @$pb.TagNumber(6)
  set garbageBytes($fixnum.Int64 value) => $_setInt64(5, value);
  @$pb.TagNumber(6)
  $core.bool hasGarbageBytes() => $_has(5);
  @$pb.TagNumber(6)
  void clearGarbageBytes() => $_clearField(6);

  @$pb.TagNumber(7)
  $core.double get garbageRatio => $_getN(6);
  @$pb.TagNumber(7)
  set garbageRatio($core.double value) => $_setDouble(6, value);
  @$pb.TagNumber(7)
  $core.bool hasGarbageRatio() => $_has(6);
  @$pb.TagNumber(7)
  void clearGarbageRatio() => $_clearField(7);

  @$pb.TagNumber(8)
  $core.bool get headerMirror => $_getBF(7);
  @$pb.TagNumber(8)
  set headerMirror($core.bool value) => $_setBool(7, value);
  @$pb.TagNumber(8)
  $core.bool hasHeaderMirror() => $_has(7);
  @$pb.TagNumber(8)
  void clearHeaderMirror() => $_clearField(8);

  @$pb.TagNumber(9)
  $core.bool get metadataMirror => $_getBF(8);
  @$pb.TagNumber(9)
  set metadataMirror($core.bool value) => $_setBool(8, value);
  @$pb.TagNumber(9)
  $core.bool hasMetadataMirror() => $_has(8);
  @$pb.TagNumber(9)
  void clearMetadataMirror() => $_clearField(9);
}

class AddPaths extends $pb.GeneratedMessage {
  factory AddPaths({
    $core.Iterable<PathItem>? items,
  }) {
    final result = AddPaths._();
    if (items != null) result.items.addAll(items);
    return result;
  }

  AddPaths._();

  factory AddPaths.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      AddPaths()..mergeFromBuffer(data, registry);
  factory AddPaths.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      AddPaths()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'AddPaths',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'autocipher.v1'),
      createEmptyInstance: AddPaths.$_createMessage)
    ..pPM<PathItem>(1, _omitFieldNames ? '' : 'items',
        subBuilder: PathItem.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  AddPaths clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  AddPaths copyWith(void Function(AddPaths) updates) =>
      super.copyWith((message) => updates(message as AddPaths)) as AddPaths;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated('Use AddPaths() / AddPaths.new instead')
  static AddPaths create() => AddPaths._();
  static $pb.GeneratedMessage $_createMessage() => AddPaths._();
  @$core.override
  AddPaths createEmptyInstance() => AddPaths._();
  @$core.pragma('dart2js:noInline')
  static AddPaths getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<AddPaths>(AddPaths.$_createMessage);
  static AddPaths? _defaultInstance;

  @$pb.TagNumber(1)
  $pb.PbList<PathItem> get items => $_getList(0);
}

class FileInfoList extends $pb.GeneratedMessage {
  factory FileInfoList({
    $core.Iterable<FileInfo>? files,
  }) {
    final result = FileInfoList._();
    if (files != null) result.files.addAll(files);
    return result;
  }

  FileInfoList._();

  factory FileInfoList.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      FileInfoList()..mergeFromBuffer(data, registry);
  factory FileInfoList.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      FileInfoList()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'FileInfoList',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'autocipher.v1'),
      createEmptyInstance: FileInfoList.$_createMessage)
    ..pPM<FileInfo>(1, _omitFieldNames ? '' : 'files',
        subBuilder: FileInfo.$_createMessage)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  FileInfoList clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  FileInfoList copyWith(void Function(FileInfoList) updates) =>
      super.copyWith((message) => updates(message as FileInfoList))
          as FileInfoList;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  @$core.Deprecated('Use FileInfoList() / FileInfoList.new instead')
  static FileInfoList create() => FileInfoList._();
  static $pb.GeneratedMessage $_createMessage() => FileInfoList._();
  @$core.override
  FileInfoList createEmptyInstance() => FileInfoList._();
  @$core.pragma('dart2js:noInline')
  static FileInfoList getDefault() =>
      _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<FileInfoList>(
          FileInfoList.$_createMessage);
  static FileInfoList? _defaultInstance;

  @$pb.TagNumber(1)
  $pb.PbList<FileInfo> get files => $_getList(0);
}

const $core.bool _omitFieldNames =
    $core.bool.fromEnvironment('protobuf.omit_field_names');
const $core.bool _omitMessageNames =
    $core.bool.fromEnvironment('protobuf.omit_message_names');
