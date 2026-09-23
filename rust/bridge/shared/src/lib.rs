//! The hub of the autocipher bridge.
//!
//! Every vault operation an application can call is declared here as a plain
//! Rust function annotated with `#[ac_fn]`. The macro emits the `extern "C"`
//! export, the panic containment, the error mapping, and the metadata entry
//! ([`autocipher_bridge_types::AC_FN_ITEMS`]) that drives the codegen runners.
//!
//! # The boundary
//!
//! - The opaque handle for an open vault is `*const c_void` (a
//!   `Box<Vault>`), created inside `autocipher_vault_create` /
//!   `autocipher_vault_open` and released with
//!   [`autocipher_vault_destroy`].
//! - String and byte parameters cross as borrowed `base` + `len` pairs.
//! - Byte payloads *returned* by an op cross through an
//!   [`autocipher_bridge_types::AcOutBuffer`] using the double-call
//!   "measure then fill" protocol.
//! - Every export returns an `i32` [`ErrorCode`] number; 0 means success.
//!   After a failed call [`autocipher_error_message`] in the cdylib surfaces
//!   the diagnostic text.
//!
//! # Target features
//!
//! Like libsignal's `libsignal-bridge`, exactly one target feature may be
//! active. The C ABI is the canonical substrate consumed by every language
//! (Dart and Swift today; JNI/Node forward), so only `ffi` gates anything for
//! now — the other features are declared for symmetry and future codegen.
//!
//! [`ErrorCode`]: autocipher_proto::v1::ErrorCode

use std::path::PathBuf;

use autocipher_bridge_macros::ac_fn;
use autocipher_core::kdf::{KdfParams, Memory};
use autocipher_core::password::generate_grouped_password;
use autocipher_format::{FormatError, mirror};
use autocipher_proto::v1 as proto;
use prost::Message;

#[cfg(not(any(feature = "ffi", feature = "dart", feature = "jni", feature = "node")))]
compile_error!("autocipher-bridge requires exactly one target feature: ffi, dart, jni, or node");

#[cfg(any(
    all(
        feature = "ffi",
        any(feature = "dart", feature = "jni", feature = "node")
    ),
    all(feature = "dart", any(feature = "jni", feature = "node")),
    all(feature = "jni", feature = "node")
))]
compile_error!("autocipher-bridge requires exactly one target feature: ffi, dart, jni, or node");

pub use autocipher_format::Vault;

// ---- shared helpers ---------------------------------------------------------

fn io_err(message: &str) -> FormatError {
    FormatError::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message,
    ))
}

/// Decode wire `KdfParams` bytes into engine params; rejects unknown memory
/// presets and zero t/p (which Argon2 rejects anyway).
fn parse_kdf(params: &[u8]) -> Result<KdfParams, FormatError> {
    let wire = proto::KdfParams::decode(params).map_err(|_| io_err("invalid KDF parameters"))?;
    let memory = match proto::kdf_params::Memory::try_from(wire.memory) {
        Ok(proto::kdf_params::Memory::M128) => Memory::M128,
        Ok(proto::kdf_params::Memory::M256) => Memory::M256,
        Ok(proto::kdf_params::Memory::M512) => Memory::M512,
        Err(_) => return Err(io_err("invalid KDF memory preset")),
    };
    if wire.t == 0 || wire.p == 0 {
        return Err(io_err("invalid KDF t/p parameters"));
    }
    Ok(KdfParams {
        memory,
        t: wire.t,
        p: wire.p,
    })
}

/// Convert engine [`Memory`] to the wire enum value.
fn to_wire_memory(m: Memory) -> proto::kdf_params::Memory {
    match m {
        Memory::M128 => proto::kdf_params::Memory::M128,
        Memory::M256 => proto::kdf_params::Memory::M256,
        Memory::M512 => proto::kdf_params::Memory::M512,
    }
}

/// Aggregate the `VaultInfo` structure for an open vault.
fn build_vault_info(v: &Vault) -> Result<proto::VaultInfo, FormatError> {
    let files = v.list()?.len() as u32;
    let size_bytes = std::fs::metadata(v.path())?.len();
    let garbage_bytes = v.garbage_bytes()?;
    let garbage_ratio = v.garbage_ratio()?;
    let kdf = v.kdf_params();
    let header_mirror = mirror::header_mirror_path(v.path()).exists();
    let metadata_mirror = mirror::metadata_mirror_path(v.path()).exists();
    Ok(proto::VaultInfo {
        path: v.path().display().to_string(),
        generation: v.generation(),
        kdf: Some(proto::KdfParams {
            memory: to_wire_memory(kdf.memory) as i32,
            t: kdf.t,
            p: kdf.p,
        }),
        files,
        size_bytes,
        garbage_bytes,
        garbage_ratio,
        header_mirror,
        metadata_mirror,
    })
}

// ---- the opaque vault handle --------------------------------------------------

/// Opaque-handle metadata the codegen runners use for bindings.
#[linkme::distributed_slice(autocipher_bridge_types::AC_HANDLE_ITEMS)]
#[allow(non_upper_case_globals)]
#[doc(hidden)]
pub static __AC_HANDLE_Vault: autocipher_bridge_types::HandleSpec =
    autocipher_bridge_types::HandleSpec {
        destroy: "autocipher_vault_destroy",
        rust_type: "Vault",
        nice: "Vault",
        doc: "Opaque handle to an open `.ac` vault. Created by `createVault`/`openVault`.",
    };

/// Free an opaque vault handle. Safe with NULL; dropping the `Vault` scrubs
/// the in-memory master key via the engine's `Zeroizing` wrapping.
///
/// # Safety
///
/// `v` must be NULL or a value previously handed out by `autocipher_vault_create`
/// or `autocipher_vault_open` that has not already been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn autocipher_vault_destroy(v: *mut std::ffi::c_void) {
    if !v.is_null() {
        unsafe {
            drop(Box::from_raw(v as *mut Vault));
        }
    }
}

// ---- constructors --------------------------------------------------------------

/// Create a new empty vault at `path`.
#[ac_fn(
    nice = "createVault",
    doc = "Create a new empty vault at `path` with the given KDF parameters and password."
)]
pub fn vault_create(path: &str, password: &[u8], params: &[u8]) -> Result<Vault, FormatError> {
    let params = parse_kdf(params)?;
    Vault::create(path, password, params)
}

/// Open (or auto-recover, from mirrors) the vault at `path`.
#[ac_fn(
    nice = "openVault",
    opening,
    doc = "Open the vault at `path` with the given password."
)]
pub fn vault_open(path: &str, password: &[u8]) -> Result<Vault, FormatError> {
    Vault::open(path, password)
}

// ---- queries -------------------------------------------------------------------

/// List stored files. Returns the encoded `FileInfoList` protobuf.
#[ac_fn(
    nice = "list",
    doc = "List the files in the vault as an encoded FileInfoList protobuf."
)]
pub fn vault_list(me: &mut Vault) -> Result<Vec<u8>, FormatError> {
    let names = me.list()?;
    let mut files = Vec::with_capacity(names.len());
    for name in names {
        let size = me.size(&name)?;
        files.push(proto::FileInfo { name, size });
    }
    Ok(proto::FileInfoList { files }.encode_to_vec())
}

/// Aggregate vault metadata. Returns the encoded `VaultInfo` protobuf.
#[ac_fn(
    nice = "info",
    doc = "Aggregate vault metadata as an encoded VaultInfo protobuf."
)]
pub fn vault_info(me: &mut Vault) -> Result<Vec<u8>, FormatError> {
    Ok(build_vault_info(me)?.encode_to_vec())
}

/// Uncompressed size of one stored file in bytes.
#[ac_fn(
    nice = "size",
    doc = "Return the uncompressed size in bytes of the named stored file."
)]
pub fn vault_size(me: &mut Vault, name: &str) -> Result<u64, FormatError> {
    me.size(name)
}

// ---- mutations -------------------------------------------------------------------

/// Import files (or whole trees). `items` is an encoded `AddPaths` message of
/// `PathItem { src, stored_name }`. Returns the number of files imported, all
/// in a single atomic batch.
#[ac_fn(
    nice = "addPaths",
    doc = "Import files/trees; `items` is an encoded AddPaths protobuf. Returns the number of files added."
)]
pub fn vault_add_paths(me: &mut Vault, items: &[u8]) -> Result<u32, FormatError> {
    let wire = proto::AddPaths::decode(items).map_err(|_| io_err("invalid add_paths payload"))?;
    let items: Vec<(PathBuf, String)> = wire
        .items
        .into_iter()
        .map(|i| (PathBuf::from(&i.src), i.stored_name))
        .collect();
    let count = me.add_paths(&items)?;
    Ok(count as u32)
}

/// Extract one stored file out to the filesystem.
#[ac_fn(
    nice = "extract",
    doc = "Extract the named stored file to `dest` on the filesystem."
)]
pub fn vault_extract(me: &mut Vault, name: &str, dest: &str) -> Result<(), FormatError> {
    me.extract(name, dest)
}

/// Read a byte range of one stored file; returns the plaintext bytes in a
/// caller-sized buffer.
#[ac_fn(
    nice = "readRange",
    doc = "Read `len` bytes starting at `offset` from the named stored file."
)]
pub fn vault_read_range(
    me: &mut Vault,
    name: &str,
    offset: u64,
    len: u64,
) -> Result<Vec<u8>, FormatError> {
    let (data, _end) = me.read_range(name, offset, len)?;
    Ok(data)
}

/// Write (creating or overwriting) one stored file.
#[ac_fn(
    nice = "put",
    doc = "Write `data` to the named stored file, creating or overwriting it."
)]
pub fn vault_put(me: &mut Vault, name: &str, data: &[u8]) -> Result<(), FormatError> {
    me.put(name, data)
}

/// Delete one stored file.
#[ac_fn(nice = "delete", doc = "Delete the named stored file.")]
pub fn vault_delete(me: &mut Vault, name: &str) -> Result<(), FormatError> {
    me.delete(name)
}

/// Rename one stored file.
#[ac_fn(nice = "rename", doc = "Rename the stored file `old` to `new`.")]
pub fn vault_rename(me: &mut Vault, old: &str, new_name: &str) -> Result<(), FormatError> {
    me.rename(old, new_name)
}

/// Rewrite the vault to drop garbage (delta-encoded deleted chunks).
#[ac_fn(
    nice = "compact",
    doc = "Rewrite the vault file to drop garbage space."
)]
pub fn vault_compact(me: &mut Vault) -> Result<(), FormatError> {
    me.compact()
}

/// Re-wrap the master key under a new password (no data re-encryption).
#[ac_fn(
    nice = "changePassword",
    doc = "Re-wrap the master key under a new password and KDF parameters; `params` is encoded KdfParams."
)]
pub fn vault_change_password(
    me: &mut Vault,
    new_password: &[u8],
    params: &[u8],
) -> Result<(), FormatError> {
    let params = parse_kdf(params)?;
    me.change_password(new_password, params)
}

/// Rewrite the sidecar mirrors from the primary vault file.
#[ac_fn(
    nice = "remirror",
    doc = "Rewrite the sidecar mirrors from the primary vault file."
)]
pub fn vault_remirror(me: &mut Vault) -> Result<(), FormatError> {
    me.remirror()
}

/// Generate a random password in the grouped `XXXXX-XXXXX-XXXXX-XXXXX-XXXXX`
/// format (5 groups of 5 characters joined by '-'), guaranteed to contain at
/// least one uppercase letter, one lowercase letter, one digit, and one symbol.
#[ac_fn(
    nice = "generatePassword",
    doc = "Generate a cryptographically secure random password as UTF-8 bytes in the grouped XXXXX-XXXXX-XXXXX-XXXXX-XXXXX format."
)]
pub fn generate_password() -> Result<Vec<u8>, FormatError> {
    Ok(generate_grouped_password().into_bytes())
}
