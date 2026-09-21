//! Placeholder for the future JNI codegen runner.
//!
//! The plan wraps `java/corg/signal/...`-style native methods around the
//! canonical C ABI via JNI once the Java wrapper package is built out. Today
//! this binary exists so the workspace layout and `just generate-all` are
//! stable. It exits 0 and writes nothing.

fn main() {
    eprintln!(
        "native_kt: not implemented yet — Java/JNI bindings land in a later round \
         (the canonical schema lives in rust/bridge/codegen/core)."
    );
}