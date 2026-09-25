//! The autocipher C ABI cdylib.
//!
//! Every `#[ac_fn]` export lives in [`autocipher-bridge`] (the macro emits the
//! `#[no_mangle] extern "C"` wrapper next to the Rust definition). This crate
//! is the concrete `libautocipher_ffi.{dll,dylib,so}` that applications load.
//! `pub use autocipher_bridge::*` keeps every symbol linked and re-exported.
//!
//! Beyond the per-op exports, this crate owns two hand-written symbols:
//!
//! - [`ac_version`] — the ABI handshake (major/minor/patch);
//! - [`autocipher_error_message`] — fetch the diagnostic text recorded by the
//!   most recent failed call (cleared on success).
//!
//! # ABI contract
//!
//! Every op export returns an `i32` [`ErrorCode`] number; `0` means success.
//! Handle-returning ops ([`autocipher_vault_create`], [`autocipher_vault_open`])
//! write the opaque handle into a `*mut *const c_void` out-param; byte payloads
//! use the double-call measure/fill protocol over
//! [`autocipher_bridge_types::AcOutBuffer`].
//!
//! [`ErrorCode`]: autocipher_proto::v1::ErrorCode

#![allow(unexpected_cfgs)]
// Keep every #[ac_fn] symbol linked into this cdylib and re-export it for the
// integration tests, which link the rlib.
#[doc(hidden)]
pub use autocipher_bridge::*;

/// ABI major version; bump on breaking wire/symbol changes.
pub const ABI_MAJOR: i32 = 1;
/// ABI minor version; bump on additive, backward-compatible changes.
pub const ABI_MINOR: i32 = 2;

/// `int32 ac_version(int32* out_major, int32* out_minor, int32* out_patch)`
///
/// Fills the ABI version components into the (optional) outputs and returns 0.
///
/// # Safety
///
/// Each non-NULL output pointer must be writable for one `i32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ac_version(
    out_major: *mut i32,
    out_minor: *mut i32,
    out_patch: *mut i32,
) -> i32 {
    unsafe {
        if !out_major.is_null() {
            *out_major = ABI_MAJOR;
        }
        if !out_minor.is_null() {
            *out_minor = ABI_MINOR;
        }
        if !out_patch.is_null() {
            *out_patch = 0;
        }
    }
    0
}

/// `int32 autocipher_error_message(autocipher_out_buffer* out)`
///
/// Fetches the diagnostic text recorded by the most recent failed call using
/// the measure/fill buffer protocol: when the caller-provided buffer is large
/// enough the message is copied in and `len` is set to its length; otherwise
/// the buffer is reset to NULL and `len` holds the required size. `len == 0`
/// means there is no recent diagnostic to report. The message persists (peek,
/// not clear) until the next failed call.
///
/// # Safety
///
/// `out` must point to a writable [`autocipher_bridge_types::AcOutBuffer`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn autocipher_error_message(
    out: *mut autocipher_bridge_types::AcOutBuffer,
) -> i32 {
    let msg = autocipher_bridge_types::peek_last_error();
    let need = msg.len();
    unsafe {
        let ob = &mut *out;
        if !ob.base.is_null() && ob.len >= need {
            if need != 0 {
                std::ptr::copy_nonoverlapping(msg.as_ptr(), ob.base, need);
            }
            ob.len = need;
        } else {
            ob.base = std::ptr::null_mut();
            ob.len = need;
        }
    }
    0
}
