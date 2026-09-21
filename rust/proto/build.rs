//! Build script: compile `proto/autocipher.v1.proto` into Rust types with
//! prost-build. Uses the `protoc-bin-vendored` binary when `protoc` is not on
//! PATH, so the Rust side never needs a system protoc install.

use std::env;
use std::path::PathBuf;

fn main() {
    let proto_root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("../../proto");
    let proto_file = proto_root.join("autocipher.v1.proto");

    println!("cargo:rerun-if-changed={}", proto_file.display());

    if env::var_os("PROTOC").is_none() {
        let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc");
        // Rust 2024 edition: set_var is unsafe.
        unsafe {
            env::set_var("PROTOC", protoc);
        }
    }

    prost_build::Config::new()
        .compile_protos(&[proto_file], &[proto_root])
        .expect("prost-build failed to compile proto/autocipher.v1.proto");
}
