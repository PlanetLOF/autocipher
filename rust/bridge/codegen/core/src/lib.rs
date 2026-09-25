//! Shared helpers for the autocipher bridge codegen runners.
//!
//! The runners (`native_c`, `native_dart`, and the later `native_kt` /
//! `native_ts`) enumerate the `linkme` metadata populated by the `#[ac_fn]`
//! definitions and render deterministic outputs that are committed to the
//! repository. `--verify` re-renders and fails when the committed output has
//! drifted from the Rust definitions.

pub use autocipher_bridge_types::{ArgSpec, FnSpec, HandleSpec};

/// Force the bridge crate to be linked into every codegen binary so its
/// `linkme` distributed-slice items (`AC_FN_ITEMS`, `AC_HANDLE_ITEMS`) are
/// present when the runners enumerate them.
#[allow(unused_imports)]
use autocipher_bridge as _;

/// ABI version, kept in step with `autocipher-ffi::ABI_MAJOR` / `ABI_MINOR`.
pub const ABI_MAJOR: i32 = 1;
pub const ABI_MINOR: i32 = 2;

/// All `#[ac_fn]` definitions, sorted by symbol.
pub fn fn_specs() -> Vec<&'static FnSpec> {
    autocipher_bridge_types::fn_specs()
}

/// All handle declarations, sorted by rust type name.
pub fn handle_specs() -> Vec<&'static HandleSpec> {
    autocipher_bridge_types::handle_specs()
}

/// Render the C parameter list for a `FnSpec`, mirroring the `#[ac_fn]` wrapper
/// exactly: handle first, then `*const u8` + `size_t` pairs for borrowed
/// strings/bytes, then by-value integers, then the output parameter.
pub fn c_params(spec: &FnSpec) -> String {
    let mut out = Vec::new();
    if spec.is_handle {
        out.push("autocipher_vault* me".to_string());
    }
    for arg in spec.args {
        match arg.tag {
            "String" | "BytesIn" => {
                out.push(format!("const uint8_t* {}", arg.name));
                out.push(format!("size_t {}_len", arg.name));
            }
            "U64" => out.push(format!("uint64_t {}", arg.name)),
            "U32" => out.push(format!("uint32_t {}", arg.name)),
            other => panic!("unexpected arg tag {other:?}"),
        }
    }
    match spec.ret {
        "Unit" => {}
        "U32" => out.push("uint32_t* count".to_string()),
        "U64" => out.push("uint64_t* out".to_string()),
        "Buffer" => out.push("autocipher_out_buffer* out".to_string()),
        "Handle" => out.push("void** out_handle".to_string()),
        other => panic!("unexpected ret tag {other:?}"),
    }
    out.join(", ")
}

/// Load a file, if present.
pub fn read_if_exists(path: &std::path::Path) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

/// Atomically write `content` to `path`; returns whether it changed.
pub fn write_if_changed(path: &std::path::Path, content: &str) -> std::io::Result<bool> {
    match read_if_exists(path) {
        Some(existing) if existing == content => return Ok(false),
        _ => {}
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, content)?;
    Ok(true)
}

/// Verify that `path` holds exactly `content`; `Err` describes the drift.
pub fn verify(path: &std::path::Path, content: &str) -> Result<(), String> {
    match read_if_exists(path) {
        Some(existing) if existing == content => Ok(()),
        Some(_) => Err(format!(
            "{} is out of date — regenerate with the codegen runner",
            path.display()
        )),
        None => Err(format!(
            "{} is missing — run the codegen runner",
            path.display()
        )),
    }
}

/// Simple `--out <dir/file>` / `--verify` argument parser.
pub struct Args {
    pub out: Option<std::path::PathBuf>,
    pub verify: bool,
}

pub fn parse_args() -> Args {
    let mut out = None;
    let mut verify = false;
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--verify" => verify = true,
            "--out" => out = Some(it.next().expect("--out requires a path").into()),
            other => panic!("unknown argument: {other}"),
        }
    }
    Args { out, verify }
}
