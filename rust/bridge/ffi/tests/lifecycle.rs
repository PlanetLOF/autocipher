//! Integration tests for the autocipher C ABI, linking the rlib directly.
//!
//! These exercise the whole vault lifecycle through the per-op exported
//! symbols — createVault → addPaths → list → readRange → put → rename →
//! delete → size → info → compact → changePassword → openVault → destroy —
//! plus the error paths (wrong password, not-found, invalid KDF params) and
//! the buffer measure/fill protocol.

use std::alloc::{Layout, alloc, dealloc};
use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use autocipher_bridge_types::AcOutBuffer;
use autocipher_ffi::{
    ac_version, autocipher_error_message, autocipher_generate_password, autocipher_vault_add_paths,
    autocipher_vault_change_password, autocipher_vault_compact, autocipher_vault_create,
    autocipher_vault_delete, autocipher_vault_destroy, autocipher_vault_extract,
    autocipher_vault_info, autocipher_vault_list, autocipher_vault_open, autocipher_vault_put,
    autocipher_vault_read_range, autocipher_vault_remirror, autocipher_vault_rename,
    autocipher_vault_size,
};
use autocipher_proto::v1 as proto;
use prost::Message;

type Handle = *mut c_void;

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn temp_dir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "autocipher-ffi-{}-{}-{}",
        tag,
        std::process::id(),
        n
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn params() -> Vec<u8> {
    proto::KdfParams {
        memory: proto::kdf_params::Memory::M128 as i32,
        t: 1,
        p: 1,
    }
    .encode_to_vec()
}

/// Borrowed-slice helper: (base, len) for a value that must stay alive for the
/// duration of the call.
fn parts(s: &str) -> (*const u8, usize) {
    (s.as_ptr(), s.len())
}

fn path_parts(p: &Path) -> (*const u8, usize) {
    let s = p.display().to_string();
    parts(&s)
}

/// Empty stored-name generation for error tests.
fn empty_stored(src: &Path) -> Vec<u8> {
    proto::AddPaths {
        items: vec![proto::PathItem {
            src: src.display().to_string(),
            stored_name: String::new(),
        }],
    }
    .encode_to_vec()
}

/// Call a byte-payload op with the measure/fill dance and return the bytes.
fn with_buffer(call: impl Fn(*mut AcOutBuffer) -> i32) -> (i32, Vec<u8>) {
    let mut out = AcOutBuffer::empty();
    let code = call(&mut out);
    if out.base.is_null() {
        if out.len == 0 {
            return (code, Vec::new());
        }
        unsafe {
            let layout = Layout::from_size_align(out.len, std::mem::align_of::<u8>()).unwrap();
            let ptr = alloc(layout) as *mut u8;
            out.base = ptr;
            out.len = layout.size();
            let code = call(&mut out);
            let data = std::slice::from_raw_parts(out.base, out.len).to_vec();
            dealloc(ptr, layout);
            return (code, data);
        }
    }
    unsafe { (code, std::slice::from_raw_parts(out.base, out.len).to_vec()) }
}

fn create_vault(path: &Path, password: &str, params: &[u8]) -> (i32, Handle) {
    let (pp, pl) = path_parts(path);
    let (pw, wl) = parts(password);
    let (kp, kl) = (params.as_ptr(), params.len());
    let mut handle: Handle = std::ptr::null_mut();
    let code = unsafe { autocipher_vault_create(pp, pl, pw, wl, kp, kl, &mut handle) };
    (code, handle)
}

fn open_vault(path: &Path, password: &str) -> (i32, Handle) {
    let (pp, pl) = path_parts(path);
    let (pw, wl) = parts(password);
    let mut handle: Handle = std::ptr::null_mut();
    let code = unsafe { autocipher_vault_open(pp, pl, pw, wl, &mut handle) };
    (code, handle)
}

fn add_paths(v: Handle, items: &[u8]) -> (i32, u32) {
    let (ip, il) = (items.as_ptr(), items.len());
    let mut count: u32 = 0;
    let code = unsafe { autocipher_vault_add_paths(v, ip, il, &mut count) };
    (code, count)
}

fn read_range(v: Handle, name: &str, offset: u64, len: u64) -> (i32, Vec<u8>) {
    let (np, nl) = parts(name);
    with_buffer(|out| unsafe { autocipher_vault_read_range(v, np, nl, offset, len, out) })
}

fn list(v: Handle) -> (i32, Vec<u8>) {
    with_buffer(|out| unsafe { autocipher_vault_list(v, out) })
}

fn info(v: Handle) -> (i32, Vec<u8>) {
    with_buffer(|out| unsafe { autocipher_vault_info(v, out) })
}

fn recent_error() -> String {
    let (_, bytes) = with_buffer(|out| unsafe { autocipher_error_message(out) });
    String::from_utf8(bytes).unwrap_or_default()
}

fn put(v: Handle, name: &str, data: &[u8]) -> i32 {
    let (np, nl) = parts(name);
    let (dp, dl) = (data.as_ptr(), data.len());
    unsafe { autocipher_vault_put(v, np, nl, dp, dl) }
}

#[test]
fn version_handshake_reports_components() {
    let (mut major, mut minor, mut patch) = (-1i32, -1i32, -1i32);
    let status = unsafe { ac_version(&mut major, &mut minor, &mut patch) };
    assert_eq!(status, 0);
    assert_eq!(major, autocipher_ffi::ABI_MAJOR);
    assert_eq!(minor, autocipher_ffi::ABI_MINOR);
    assert_eq!(patch, 0);
}

#[test]
fn full_lifecycle_create_add_list_read_put_rename_delete_size_info_compact_changepwd() {
    let dir = temp_dir("lifecycle");
    let vault_path = dir.join("vault.ac");
    let src = dir.join("hello.txt");
    std::fs::write(&src, b"hello world").unwrap();
    let password = "correct horse battery staple";
    let items = proto::AddPaths {
        items: vec![proto::PathItem {
            src: src.display().to_string(),
            stored_name: "docs/hello.txt".to_string(),
        }],
    };

    // 1. version handshake.
    let (mut major, mut minor, mut patch) = (0, 0, 0);
    let status = unsafe { ac_version(&mut major, &mut minor, &mut patch) };
    assert_eq!(status, 0);
    assert!(major >= 1);

    // 2. create → opaque handle.
    let (code, handle) = create_vault(&vault_path, password, &params());
    assert_eq!(code, 0);
    assert!(!handle.is_null());

    // 3. list on a fresh vault is empty.
    let (code, bytes) = list(handle);
    assert_eq!(code, 0);
    let files = proto::FileInfoList::decode(bytes.as_slice()).unwrap();
    assert!(files.files.is_empty());

    // 4. add_paths imports the source file under a stored name (one batch).
    let (code, count) = add_paths(handle, &items.encode_to_vec());
    assert_eq!(code, 0);
    assert_eq!(count, 1);

    // 5. list shows the imported file with its plaintext size.
    let (code, bytes) = list(handle);
    assert_eq!(code, 0);
    let files = proto::FileInfoList::decode(bytes.as_slice()).unwrap();
    assert_eq!(files.files.len(), 1);
    assert_eq!(&files.files[0].name, "docs/hello.txt");
    assert_eq!(files.files[0].size, 11);
    assert!(files.files[0].created_at > 0);
    assert_eq!(files.files[0].created_at, files.files[0].modified_at);
    assert!(files.files[0].storage_used > files.files[0].size);

    // 6. read_range of the whole file returns the plaintext.
    let (code, data) = read_range(handle, "docs/hello.txt", 0, 100);
    assert_eq!(code, 0);
    assert_eq!(data, b"hello world");

    // 7. put overwrites in place; a range read sees the new contents.
    assert_eq!(put(handle, "docs/hello.txt", b"hello vault, again"), 0);
    let (code, data) = read_range(handle, "docs/hello.txt", 6, 5);
    assert_eq!(code, 0);
    assert_eq!(data, b"vault");

    // 8. rename moves the stored name.
    let (op, op_len) = parts("docs/hello.txt");
    let (np, nl) = parts("docs/renamed.txt");
    assert_eq!(
        unsafe { autocipher_vault_rename(handle, op, op_len, np, nl) },
        0
    );

    // 9. reading works under the new name, and size reflects it.
    let (code, data) = read_range(handle, "docs/renamed.txt", 0, 100);
    assert_eq!(code, 0);
    assert_eq!(data, b"hello vault, again");
    let mut size: u64 = 0;
    let (np, nl) = parts("docs/renamed.txt");
    assert_eq!(
        unsafe { autocipher_vault_size(handle, np, nl, &mut size) },
        0
    );
    assert_eq!(size, b"hello vault, again".len() as u64);

    // 10. delete removes it.
    let (np, nl) = parts("docs/renamed.txt");
    assert_eq!(unsafe { autocipher_vault_delete(handle, np, nl) }, 0);
    let (code, bytes) = list(handle);
    assert_eq!(code, 0);
    let files = proto::FileInfoList::decode(bytes.as_slice()).unwrap();
    assert!(files.files.is_empty());

    // 11. vault info aggregates generation / sizes / mirrors.
    let (code, bytes) = info(handle);
    assert_eq!(code, 0);
    let info = proto::VaultInfo::decode(bytes.as_slice()).unwrap();
    assert_eq!(info.path, vault_path.display().to_string());
    assert!(info.generation >= 1);
    assert!(info.header_mirror);
    assert!(info.metadata_mirror);

    // 12. put again so compact has something to rewrite, then compact + remirror.
    assert_eq!(put(handle, "a.txt", &vec![7u8; 64_000]), 0);
    assert_eq!(unsafe { autocipher_vault_compact(handle) }, 0);
    assert_eq!(unsafe { autocipher_vault_remirror(handle) }, 0);
    let (code, data) = read_range(handle, "a.txt", 0, 64_000);
    assert_eq!(code, 0);
    assert_eq!(data, vec![7u8; 64_000]);

    // 13. change password re-wraps the master key.
    let (np_, nl_) = parts("brand new password");
    let pbytes = params();
    let (pp, pl) = (pbytes.as_ptr(), pbytes.len());
    assert_eq!(
        unsafe { autocipher_vault_change_password(handle, np_, nl_, pp, pl) },
        0
    );

    // 14. extract still works after the password change.
    let (named, named_len) = parts("a.txt");
    let out_path = dir.join("out.bin").display().to_string();
    let (dest, dest_len) = parts(&out_path);
    assert_eq!(
        unsafe { autocipher_vault_extract(handle, named, named_len, dest, dest_len) },
        0
    );
    assert_eq!(
        std::fs::read(dir.join("out.bin")).unwrap(),
        vec![7u8; 64_000]
    );

    // 15. destroy scrubs the vault.
    unsafe { autocipher_vault_destroy(handle) };

    // 16. reopen with the new password and verify a read.
    let (code, handle2) = open_vault(&vault_path, "brand new password");
    assert_eq!(code, 0);
    assert!(!handle2.is_null());
    let (code, data) = read_range(handle2, "a.txt", 0, 256);
    assert_eq!(code, 0);
    assert_eq!(data, vec![7u8; 256]);
    unsafe { autocipher_vault_destroy(handle2) };

    // 17. destroy with NULL is a no-op.
    unsafe { autocipher_vault_destroy(std::ptr::null_mut()) };

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn open_reopen_and_error_paths() {
    let dir = temp_dir("open");
    let vault_path = dir.join("vault.ac");
    let password = "open password";

    let (code, handle) = create_vault(&vault_path, password, &params());
    assert_eq!(code, 0);
    unsafe { autocipher_vault_destroy(handle) };

    // Reopen with the same password.
    let (code, handle) = open_vault(&vault_path, password);
    assert_eq!(code, 0);

    // Reading a missing file → NOT_FOUND, and the diagnostic is non-empty.
    let (code, data) = read_range(handle, "ghost.bin", 0, 10);
    assert_eq!(code, proto::ErrorCode::NotFound as i32);
    assert!(data.is_empty());
    let diag = recent_error();
    assert!(
        !diag.is_empty(),
        "engine error produced no diagnostic: {diag:?}"
    );

    // add_paths with an empty stored name → INVALID_ARGUMENT.
    let (code, _count) = add_paths(handle, &empty_stored(&vault_path));
    assert_eq!(code, proto::ErrorCode::InvalidArgument as i32);

    unsafe { autocipher_vault_destroy(handle) };

    // Wrong password on open → WRONG_PASSWORD.
    let (code, handle) = open_vault(&vault_path, "wrong password");
    assert_eq!(code, proto::ErrorCode::WrongPassword as i32);
    assert!(handle.is_null());

    // Opening a missing file → NOT_FOUND.
    let (code, handle) = open_vault(&dir.join("nope.ac"), "whatever");
    assert_eq!(code, proto::ErrorCode::NotFound as i32);
    assert!(handle.is_null());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn invalid_kdf_params_rejected() {
    let dir = temp_dir("badkdf");
    let bad = proto::KdfParams {
        memory: proto::kdf_params::Memory::M128 as i32,
        t: 0, // Argon2 rejects t = 0
        p: 1,
    };
    let (code, handle) = create_vault(&dir.join("v.ac"), "pw", &bad.encode_to_vec());
    assert_eq!(code, proto::ErrorCode::InvalidArgument as i32);
    assert!(handle.is_null());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn buffer_protocol_respects_capacity() {
    let dir = temp_dir("buf");
    let vault_path = dir.join("vault.ac");
    let password = "buffer protocol";
    let (code, handle) = create_vault(&vault_path, password, &params());
    assert_eq!(code, 0);

    // A caller-provided buffer that is large enough receives data in one pass.
    assert_eq!(put(handle, "f.txt", b"hello"), 0);
    let (np, nl) = parts("f.txt");
    let mut out = AcOutBuffer {
        base: std::ptr::null_mut(),
        len: 0,
    };
    let code = unsafe { autocipher_vault_read_range(handle, np, nl, 0, 100, &mut out) };
    assert_eq!(code, 0);
    assert!(out.base.is_null());
    assert_eq!(out.len, 5);

    unsafe {
        let layout = Layout::from_size_align(8, std::mem::align_of::<u8>()).unwrap();
        let ptr = alloc(layout) as *mut u8;
        out.base = ptr;
        out.len = 8;
        let code = autocipher_vault_read_range(handle, np, nl, 0, 100, &mut out);
        assert_eq!(code, 0);
        assert_eq!(out.len, 5);
        assert_eq!(std::slice::from_raw_parts(out.base, out.len), b"hello");
        dealloc(ptr, layout);
    }

    unsafe { autocipher_vault_destroy(handle) };
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn generate_password_returns_grouped_format() {
    // Free function: no handle, bytes out through the buffer protocol.
    let (code, data) = with_buffer(|out| unsafe { autocipher_generate_password(out) });
    assert_eq!(code, 0);
    let s = String::from_utf8(data).expect("password is UTF-8");
    assert_eq!(s.len(), 29, "5 groups of 5 chars plus 4 hyphens: {s}");
    let mut hyphens = 0;
    for (i, ch) in s.char_indices() {
        let expected_hyphen = matches!(i, 5 | 11 | 17 | 23);
        assert_eq!(
            ch == '-',
            expected_hyphen,
            "unexpected char at index {i}: {s}"
        );
        if ch == '-' {
            hyphens += 1;
        }
    }
    assert_eq!(hyphens, 4);

    // A second call produces a different password.
    let (_, data2) = with_buffer(|out| unsafe { autocipher_generate_password(out) });
    assert_ne!(s, String::from_utf8(data2).unwrap());
}
