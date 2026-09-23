//! Renders the C ABI header from the `#[ac_fn]` definitions.
//!
//! Output mirrors the generated Rust wrappers exactly: one
//! `autocipher_{id}(...)` declaration per op, plus the hand-written handshake
//! and diagnostic symbols. The header is committed to the repo so Swift and
//! any C consumer can bind without running codegen.
//!
//! Usage: `native_c --out <dir> [--verify]`

use autocipher_bridge_codegen::{
    ABI_MAJOR, ABI_MINOR, c_params, fn_specs, handle_specs, parse_args, verify, write_if_changed,
};

fn render() -> String {
    let mut s = String::new();
    s.push_str("/*\n");
    s.push_str(" * GENERATED CODE — DO NOT EDIT. Run: just generate-c\n");
    s.push_str(
        " * The authoritative definition set is in rust/bridge/shared/src (the #[ac_fn] list).\n",
    );
    s.push_str(" */\n");
    s.push_str("#pragma once\n");
    s.push_str("#include <stdbool.h>\n#include <stddef.h>\n#include <stdint.h>\n\n");
    s.push_str("#ifdef __cplusplus\nextern \"C\" {\n#endif\n\n");

    s.push_str("/* Opaque handle to an open .ac vault. */\n");
    s.push_str("typedef void autocipher_vault;\n\n");

    s.push_str("/* Caller-owned I/O buffer for byte payloads.\n");
    s.push_str(" * Protocol: on entry the caller may set base to a buffer of len\n");
    s.push_str(" * capacity. An op that returns n bytes copies them in when\n");
    s.push_str(" * capacity >= n and sets len = n; otherwise it sets base = NULL and\n");
    s.push_str(" * len = n so the caller can allocate exactly the reported size and\n");
    s.push_str(" * call again. len == 0 means no payload. */\n");
    s.push_str("typedef struct autocipher_out_buffer {\n");
    s.push_str("  uint8_t* base;\n");
    s.push_str("  size_t len;\n");
    s.push_str("} autocipher_out_buffer;\n\n");

    s.push_str(&format!("#define AUTOCIPHER_ABI_MAJOR {ABI_MAJOR}\n"));
    s.push_str(&format!("#define AUTOCIPHER_ABI_MINOR {ABI_MINOR}\n\n"));

    s.push_str("/* ABI handshake. */\n");
    s.push_str("int32_t ac_version(int32_t* out_major, int32_t* out_minor, int32_t* out_patch);\n");
    s.push_str("/* Diagnostic text from the most recent failed call. */\n");
    s.push_str("int32_t autocipher_error_message(autocipher_out_buffer* out);\n\n");

    s.push_str("/* Opaque handle lifecycle. */\n");
    for h in handle_specs() {
        s.push_str(&format!("void {}(autocipher_vault* v);\n", h.destroy));
    }
    s.push_str("\n");

    for spec in fn_specs() {
        let kind = if spec.ret == "Handle" {
            "constructor: writes an opaque handle into out_handle (NULL handles are never written)."
        } else if spec.is_handle {
            "op"
        } else {
            "free function"
        };
        for line in spec.doc.lines() {
            s.push_str(&format!("/* {line} */\n"));
        }
        s.push_str(&format!("/* {kind} */\n"));
        s.push_str(&format!("int32_t {}({});\n", spec.symbol, c_params(spec)));
    }
    s.push_str("\n#ifdef __cplusplus\n}\n#endif\n");
    s
}

fn main() {
    let args = parse_args();
    let out_dir = args.out.unwrap_or_else(|| std::env::current_dir().unwrap());
    let path = out_dir.join("autocipher_capi.h");
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
