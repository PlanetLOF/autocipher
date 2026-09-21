//! Shared infrastructure for the autocipher C bridge.
//!
//! This crate plays the role libsignal's `libsignal-bridge-types` plays for
//! the Signal bridge: it owns
//!
//! - the **type protocol** the ABI uses to move values across the boundary
//!   (pointer-based buffers, opaque handles, `i32` error codes),
//! - the **error mapping table** that translates vault-engine errors into the
//!   stable [`autocipher_proto::v1::ErrorCode`] numbers,
//! - the **thread-local diagnostic message** that a caller can fetch after a
//!   failed call,
//! - the **linker metadata slices** ([`AC_FN_ITEMS`], [`AC_HANDLE_ITEMS`])
//!   that the codegen runners enumerate to emit the C header and the per
//!   language bindings.
//!
//! The metadata is gathered through `linkme` distributed slices: every
//! `#[ac_fn]` definition in `autocipher-bridge` pushes a [`FnSpec`] into
//! [`AC_FN_ITEMS`], and handle declarations push a [`HandleSpec`]. Because the
//! slices are real linker symbols, the codegen binaries can walk exactly the
//! API that is compiled into the library — nothing more, nothing less.

pub use autocipher_format::FormatError;

/// Error code for a request rejected at the ABI edge (bad UTF-8, invalid KDF
/// params, …) — mirrors `ErrorCode::INVALID_ARGUMENT`.
pub const ERR_INVALID_ARGUMENT: i32 = autocipher_proto::v1::ErrorCode::InvalidArgument as i32;

/// Error code for an internal panic contained at the ABI edge.
pub const ERR_INTERNAL: i32 = autocipher_proto::v1::ErrorCode::Internal as i32;

/// A wrapper-level error: either an already-mapped ABI code or an engine
/// error that still has to run through [`map_error`].
pub enum AcErr {
    /// A short-circuit from the wrapper itself (conversion failure, …); the
    /// code is final and needs no further mapping.
    Code(i32),
    /// An engine error, to be translated with [`map_error`].
    Engine(FormatError),
}

/// Caller-owned I/O buffer used for byte payloads that cross the boundary.
///
/// Protocol: on entry whichever side allocates sets `base != NULL` and
/// `len` = capacity. A function that needs to return `n` bytes writes them
/// when `base` is a valid buffer of capacity ≥ `n` and then sets `len = n`;
/// otherwise it sets `base = NULL`, `len = n` and returns success so the
/// caller can allocate and call again. `len == 0` after a call means "no
/// payload".
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct AcOutBuffer {
    pub base: *mut u8,
    pub len: usize,
}

impl AcOutBuffer {
    /// An empty, read-only buffer (base null, len 0) for the size-measuring
    /// pass of the double-call protocol.
    pub const fn empty() -> Self {
        Self {
            base: core::ptr::null_mut(),
            len: 0,
        }
    }
}

// ---- thread-local diagnostics -------------------------------------------------

thread_local! {
    /// The most recent ABI-level failure message (cleared on success).
    static LAST_ERROR: core::cell::RefCell<String> = const { core::cell::RefCell::new(String::new()) };
}

/// Record the message for the most recent failed call.
pub fn set_last_error(message: String) {
    LAST_ERROR.with(|cell| cell.replace(message));
}

/// Fetch the message for the most recent failed call without clearing it.
///
/// Failure messages persist until the next failure (matching `strerror`-style
/// diagnostics) so a caller can sample them repeatedly — in particular the
/// measure/fill buffer protocol calls the export twice.
pub fn peek_last_error() -> String {
    LAST_ERROR.with(|cell| cell.borrow().clone())
}

/// Fetch and clear the message for the most recent failed call.
pub fn take_last_error() -> String {
    LAST_ERROR.with(|cell| cell.replace(String::new()))
}

// ---- error mapping --------------------------------------------------------------

/// Translate a vault-engine error to a stable wire `ErrorCode`.
///
/// `opening` switches AEAD-unwrap failures to `WRONG_PASSWORD`: while opening
/// a vault the only authenticated decryptions are the header HMAC and the
/// master-key unwrap, so an AEAD failure there means a wrong password.
pub fn map_error(e: &FormatError, opening: bool) -> i32 {
    use autocipher_format::FormatError as E;
    use autocipher_proto::v1::ErrorCode as C;
    (match e {
        E::Crypto(c) => match c {
            autocipher_core::error::CryptoError::Kdf(_) => C::Kdf,
            autocipher_core::error::CryptoError::Aead(_) if opening => C::WrongPassword,
            autocipher_core::error::CryptoError::Aead(_) => C::Crypto,
            autocipher_core::error::CryptoError::InvalidLength { .. }
            | autocipher_core::error::CryptoError::InvalidCiphertextLength { .. } => C::Crypto,
        },
        E::Io(e) if e.kind() == std::io::ErrorKind::NotFound => C::NotFound,
        E::Io(e) if e.kind() == std::io::ErrorKind::InvalidInput => C::InvalidArgument,
        E::Io(e) if e.kind() == std::io::ErrorKind::AlreadyExists => C::AlreadyExists,
        E::Io(_) => C::Io,
        E::NotFound(_) => C::NotFound,
        // The header HMAC is only verified while opening a vault.
        E::Hmac => C::WrongPassword,
        E::Rollback { .. } => C::Crypto,
        E::InvalidKeyLength { .. } | E::InvalidLength { .. } => C::Crypto,
        E::MetadataTooLarge { .. } => C::MetadataTooLarge,
        E::ChunkLimitExceeded { .. } => C::MetadataTooLarge,
        E::Internal(_) => C::Internal,
    }) as i32
}

// ---- metadata shapes --------------------------------------------------------------

/// One parameter of an `#[ac_fn]` definition, as seen by the ABI.
///
/// `tag` is one of:
/// - `"Handle"` — the opaque vault handle (first parameter only);
/// - `"String"` — a borrowed UTF-8 string (`base` + `len`);
/// - `"BytesIn"` — borrowed raw bytes (`base` + `len`);
/// - `"U64"` / `"U32"` — an integer passed by value.
#[derive(Clone, Copy)]
pub struct ArgSpec {
    pub name: &'static str,
    pub tag: &'static str,
}

impl ArgSpec {
    pub const fn new(name: &'static str, tag: &'static str) -> Self {
        Self { name, tag }
    }
}

/// One `#[ac_fn]` definition, as seen by the ABI and the codegen runners.
#[derive(Clone, Copy)]
pub struct FnSpec {
    /// Rust id of the definition (e.g. `vault_add_paths`).
    pub id: &'static str,
    /// Exported C symbol (e.g. `autocipher_vault_add_paths`).
    pub symbol: &'static str,
    /// User-facing name in generated bindings (e.g. `addPaths`).
    pub nice: &'static str,
    /// Whether the first argument is the opaque handle (`true` for ops).
    pub is_handle: bool,
    /// Parameters, excluding the optional handle.
    pub args: &'static [ArgSpec],
    /// Return kind: `"Unit"`, `"U32"`, `"U64"`, `"Buffer"`, or `"Handle"`.
    pub ret: &'static str,
    /// Documentation for the generated binding.
    pub doc: &'static str,
}

/// One opaque handle type (currently just the vault), for codegen.
#[derive(Clone, Copy)]
pub struct HandleSpec {
    /// C symbol for the handle's destroy function.
    pub destroy: &'static str,
    /// Rust type name (e.g. `Vault`).
    pub rust_type: &'static str,
    /// User-facing name in generated bindings (e.g. `Vault`).
    pub nice: &'static str,
    /// Doc comment for the generated binding.
    pub doc: &'static str,
}

/// Every `#[ac_fn]` definition, collected at link time.
#[linkme::distributed_slice]
pub static AC_FN_ITEMS: [FnSpec] = [..];

/// Every opaque handle declaration, collected at link time.
#[linkme::distributed_slice]
pub static AC_HANDLE_ITEMS: [HandleSpec] = [..];

/// All current [`FnSpec`]s, sorted by symbol, for deterministic codegen.
pub fn fn_specs() -> Vec<&'static FnSpec> {
    let mut all: Vec<&'static FnSpec> = AC_FN_ITEMS.iter().collect();
    all.sort_by(|a, b| a.symbol.cmp(b.symbol));
    all
}

/// All current [`HandleSpec`]s, sorted by rust type name.
pub fn handle_specs() -> Vec<&'static HandleSpec> {
    let mut all: Vec<&'static HandleSpec> = AC_HANDLE_ITEMS.iter().collect();
    all.sort_by(|a, b| a.rust_type.cmp(b.rust_type));
    all
}