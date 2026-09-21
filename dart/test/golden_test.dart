// Wire-format parity tests: the byte payloads this Dart package produces for
// the FFI ops must match the golden vectors asserted by the Rust side
// (`rust/proto/src/lib.rs`). Both sides compile the same autocipher.v1.proto.

import 'dart:typed_data';

import 'package:fixnum/fixnum.dart';
import 'package:autocipher_dart/src/gen/autocipher.v1.pb.dart';
import 'package:test/test.dart';

String hex(Uint8List b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

void main() {
  test('kdf params golden bytes', () {
    final m = KdfParams(memory: KdfParams_Memory.M256, t: 4, p: 4);
    expect(hex(m.writeToBuffer()), '080110041804');
  });

  test('add_paths golden bytes', () {
    final a = AddPaths(
      items: [
        PathItem(
          src: r'C:\Users\me\DSC0001.jpg',
          storedName: 'photos/DSC0001.jpg',
        ),
        PathItem(src: '/home/me/doc.txt', storedName: 'doc.txt'),
      ],
    );
    expect(
      hex(a.writeToBuffer()),
      '0a2d0a17433a5c55736572735c6d655c445343303030312e6a7067'
      '121270686f746f732f445343303030312e6a7067'
      '0a1b0a102f686f6d652f6d652f646f632e7478741207646f632e747874',
    );
  });

  test('file_list golden bytes', () {
    final l = FileInfoList(
      files: [
        FileInfo(name: 'photos/DSC0001.jpg', size: Int64(1048576)),
        FileInfo(name: 'doc.txt', size: Int64(42)),
      ],
    );
    expect(
      hex(l.writeToBuffer()),
      '0a180a1270686f746f732f445343303030312e6a7067'
      '10808040'
      '0a0b0a07646f632e747874102a',
    );
  });

  test('add_paths round-trips stable', () {
    final a = AddPaths(
      items: [
        PathItem(src: 'a.txt', storedName: 'a.txt'),
        PathItem(src: 'b/c.txt', storedName: 'c.txt'),
      ],
    );
    final back = AddPaths.fromBuffer(a.writeToBuffer());
    expect(back.items.length, 2);
    expect(back.items.first.src, 'a.txt');
    expect(back.items.last.storedName, 'c.txt');
  });
}