//! Renders `dart/lib/src/generated/Native.dart` from the `#[ac_fn]`
//! definitions. Pure `dart:ffi` bindings — the nice async API and the
//! loader live in hand-written Dart files beside this file.
//!
//! Usage: `native_dart --out <dir> [--verify]`

use autocipher_bridge_codegen::{
    ABI_MAJOR, ABI_MINOR, fn_specs, handle_specs, parse_args, verify, write_if_changed,
};

/// Map an ArgSpec/ret tag to (native type, dart type).
fn types(tag: &str) -> (&'static str, &'static str) {
    match tag {
        "Handle" => ("Pointer<Void>", "Pointer<Void>"),
        "String" | "BytesIn" => ("Pointer<Uint8>", "Pointer<Uint8>"),
        "U64" => ("Int64", "int"),
        "U32" => ("Uint32", "int"),
        "Buffer" => ("Pointer<AcOutBuffer>", "Pointer<AcOutBuffer>"),
        other => panic!("unexpected tag {other:?}"),
    }
}

/// Native ABI type for the `{name}_len` companion of a borrowed arg.
fn len_native(_tag: &str) -> &'static str {
    "IntPtr"
}

fn render() -> String {
    let mut s = String::new();
    s.push_str("// GENERATED CODE — DO NOT EDIT. Run: just generate-dart\n");
    s.push_str(
        "// The authoritative definition set is in rust/bridge/shared/src (the #[ac_fn] list).\n\n",
    );
    s.push_str("// ignore_for_file: public_member_api_docs, constant_identifier_names\n\n");
    s.push_str("import 'dart:convert';\n");
    s.push_str("import 'dart:ffi';\n");
    s.push_str("import 'dart:typed_data';\n");
    s.push_str("import 'package:ffi/ffi.dart';\n\n");

    s.push_str(&format!("const int kAbiMajor = {ABI_MAJOR};\n"));
    s.push_str(&format!("const int kAbiMinor = {ABI_MINOR};\n\n"));

    s.push_str("/// Caller-owned I/O buffer for byte payloads crossing the ABI.\n");
    s.push_str("/// Double-call protocol: pass a buffer; if too small the op returns\n");
    s.push_str("/// len = required size and base = null, call again with the size.\n");
    s.push_str("final class AcOutBuffer extends Struct {\n");
    s.push_str("  external Pointer<Uint8> base;\n");
    s.push_str("  @IntPtr()\n");
    s.push_str("  external int len;\n");
    s.push_str("}\n\n");

    s.push_str("/// Raw, generated bindings for the autocipher C ABI.\n");
    s.push_str("/// Load the library with [use] before calling any op.\n");
    s.push_str("final class Native {\n");
    s.push_str("  Native._();\n\n");
    s.push_str("  static DynamicLibrary? _lib;\n");
    s.push_str("  static bool get isLoaded => _lib != null;\n");
    s.push_str("  static void use(DynamicLibrary lib) => _lib = lib;\n\n");

    // Hand-written handshake and diagnostics.
    s.push_str("  /// ABI handshake. Fills 0 on any null output pointer.\n");
    s.push_str("  static int acVersion(Pointer<Int32> outMajor, Pointer<Int32> outMinor, Pointer<Int32> outPatch) =>\n");
    s.push_str("      _lib!.lookupFunction<Int32 Function(Pointer<Int32>, Pointer<Int32>, Pointer<Int32>), int Function(Pointer<Int32>, Pointer<Int32>, Pointer<Int32>)>(\n");
    s.push_str("          'ac_version')(outMajor, outMinor, outPatch);\n\n");
    s.push_str("  /// Diagnostic text from the most recent failed call.\n");
    s.push_str("  static int autocipherErrorMessage(Pointer<AcOutBuffer> out) =>\n");
    s.push_str("      _lib!.lookupFunction<Int32 Function(Pointer<AcOutBuffer>), int Function(Pointer<AcOutBuffer>)>(\n");
    s.push_str("          'autocipher_error_message')(out);\n\n");

    // Handles.
    for h in handle_specs() {
        s.push_str(&format!(
            "  /// Releases an opaque {name} handle (NULL is a no-op).\n",
            name = h.nice
        ));
        s.push_str(&format!(
            "  static void {}Destroy(Pointer<Void> me) =>\n",
            h.nice
        ));
        s.push_str(&format!(
            "      _lib!.lookupFunction<Void Function(Pointer<Void>), void Function(Pointer<Void>)>(\n          '{}')(me);\n\n",
            h.destroy
        ));
    }

    // One op per FnSpec.
    for spec in fn_specs() {
        let ret_tag = spec.ret;
        let mut native_params = Vec::new();
        let mut dart_params = Vec::new();
        if spec.is_handle {
            native_params.push("Pointer<Void>".to_string());
            dart_params.push("Pointer<Void> me".to_string());
        }
        for arg in spec.args {
            let (nt, dt) = types(arg.tag);
            native_params.push(nt.to_string());
            dart_params.push(format!("{dt} {}", arg.name));
            let _ = dt;
            if matches!(arg.tag, "String" | "BytesIn") {
                native_params.push(len_native(arg.tag).to_string());
                dart_params.push(format!("int {}Len", arg.name));
            }
        }
        let (nat_out, dart_out) = match ret_tag {
            "Unit" => (None, None),
            "U32" => (Some("Pointer<Uint32>"), Some("Pointer<Uint32> count")),
            "U64" => (Some("Pointer<Uint64>"), Some("Pointer<Uint64> out")),
            "Buffer" => (
                Some("Pointer<AcOutBuffer>"),
                Some("Pointer<AcOutBuffer> out"),
            ),
            "Handle" => (
                Some("Pointer<Pointer<Void>>"),
                Some("Pointer<Pointer<Void>> outHandle"),
            ),
            other => panic!("unexpected ret {other:?}"),
        };
        if let (Some(n), Some(d)) = (nat_out, dart_out) {
            native_params.push(n.to_string());
            dart_params.push(d.to_string());
        }
        let native_sig = native_params.join(", ");
        let dart_sig = dart_params.join(", ");

        for line in spec.doc.lines() {
            s.push_str(&format!("  /// {line}\n"));
        }
        s.push_str(&format!(
            "  static int {symbol}({dart_sig}) =>\n",
            symbol = spec.nice
        ));
        s.push_str(&format!(
            "      _lib!.lookupFunction<Int32 Function({native_sig}), int Function({dart_sig})>(\n          '{}')({});\n\n",
            spec.symbol,
            dart_params
                .iter()
                .map(|p| p.split_whitespace().last().unwrap_or(p))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    // Helpers.
    s.push_str("  /// Measure/fill dance for a buffer-returning op.\n");
    s.push_str("  /// Returns (code, bytes); code == 0 means success.\n");
    s.push_str("  static (int, Uint8List) bufferCall(int Function(Pointer<AcOutBuffer>) call) {\n");
    s.push_str("    final out = calloc<AcOutBuffer>();\n");
    s.push_str("    try {\n");
    s.push_str("      out.ref.base = nullptr;\n");
    s.push_str("      out.ref.len = 0;\n");
    s.push_str("      var code = call(out);\n");
    s.push_str("      if (code != 0) return (code, Uint8List(0));\n");
    s.push_str("      final need = out.ref.len;\n");
    s.push_str("      if (need == 0) return (0, Uint8List(0));\n");
    s.push_str("      final p = calloc<Uint8>(need);\n");
    s.push_str("      try {\n");
    s.push_str("        out.ref.base = p;\n");
    s.push_str("        out.ref.len = need;\n");
    s.push_str("        code = call(out);\n");
    s.push_str("        if (code != 0) return (code, Uint8List(0));\n");
    s.push_str("        final len = out.ref.len;\n");
    s.push_str(
        "        return (0, len == 0 ? Uint8List(0) : Uint8List.fromList(p.asTypedList(len)));\n",
    );
    s.push_str("      } finally {\n");
    s.push_str("        calloc.free(p);\n");
    s.push_str("      }\n");
    s.push_str("    } finally {\n");
    s.push_str("      calloc.free(out);\n");
    s.push_str("    }\n");
    s.push_str("  }\n\n");

    s.push_str("  /// Run [body] with a NUL-free UTF-8 encoding of [s]; frees after.\n");
    s.push_str(
        "  static T withUtf8<T>(String s, T Function(Pointer<Uint8> ptr, int len) body) {\n",
    );
    s.push_str("    final bytes = utf8.encode(s);\n");
    s.push_str("    if (bytes.isEmpty) return body(nullptr, 0);\n");
    s.push_str("    final p = calloc<Uint8>(bytes.length);\n");
    s.push_str("    try {\n");
    s.push_str("      p.asTypedList(bytes.length).setAll(0, bytes);\n");
    s.push_str("      return body(p, bytes.length);\n");
    s.push_str("    } finally {\n");
    s.push_str("      calloc.free(p);\n");
    s.push_str("    }\n");
    s.push_str("  }\n\n");

    s.push_str("  /// Run [body] with a copy of [data]; frees after.\n");
    s.push_str(
        "  static T withSlice<T>(Uint8List data, T Function(Pointer<Uint8> ptr, int len) body) {\n",
    );
    s.push_str("    if (data.isEmpty) return body(nullptr, 0);\n");
    s.push_str("    final p = calloc<Uint8>(data.length);\n");
    s.push_str("    try {\n");
    s.push_str("      p.asTypedList(data.length).setAll(0, data);\n");
    s.push_str("      return body(p, data.length);\n");
    s.push_str("    } finally {\n");
    s.push_str("      calloc.free(p);\n");
    s.push_str("    }\n");
    s.push_str("  }\n");
    s.push_str("}\n");
    s
}

fn main() {
    let args = parse_args();
    let out_dir = args.out.unwrap_or_else(|| std::env::current_dir().unwrap());
    let path = out_dir.join("Native.dart");
    let content = render();

    if args.verify {
        verify(&path, &content).unwrap_or_else(|e| {
            eprintln!("{e}");
            std::process::exit(1)
        });
        eprintln!("ok: {} is up to date", path.display());
    } else {
        match write_if_changed(&path, &content).unwrap() {
            true => eprintln!("wrote {}", path.display()),
            false => eprintln!("unchanged: {}", path.display()),
        }
    }
}
