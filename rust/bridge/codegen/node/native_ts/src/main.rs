//! Placeholder for the future Node (N-API) codegen runner.
//!
//! The plan exposes the canonical C ABI to Node via an N-API addon once the
//! TypeScript wrapper package is built out. Today this binary exists so the
//! workspace layout and `just generate-all` are stable. It exits 0 and writes
//! nothing.

fn main() {
    eprintln!(
        "native_ts: not implemented yet — Node/N-API bindings land in a later round \
         (the canonical schema lives in rust/bridge/codegen/core)."
    );
}
