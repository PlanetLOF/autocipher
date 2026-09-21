//! Per-purpose key separation via HKDF-SHA256.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Length of a derived subkey in bytes.
pub const SUBKEY_LEN: usize = 32;

/// Derive a 32-byte subkey from `master`.
///
/// The HKDF `info` is `purpose | file_id | chunk_idx` (little-endian), binding
/// each derived key to its use.
pub fn derive_subkey(
    master: &[u8],
    purpose: &[u8],
    file_id: &[u8],
    chunk_idx: u64,
) -> Zeroizing<[u8; SUBKEY_LEN]> {
    let hk = Hkdf::<Sha256>::new(None, master);
    let mut info = Vec::with_capacity(purpose.len() + file_id.len() + std::mem::size_of::<u64>());
    info.extend_from_slice(purpose);
    info.extend_from_slice(file_id);
    info.extend_from_slice(&chunk_idx.to_le_bytes());
    let mut subkey = Zeroizing::new([0u8; SUBKEY_LEN]);
    hk.expand(&info, subkey.as_mut())
        .expect("32-byte HKDF-SHA256 output is always valid");
    subkey
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASTER: &[u8] = b"0123456789abcdef0123456789abcdef";

    #[test]
    fn same_inputs_reproducible() {
        let a = derive_subkey(MASTER, b"header-mac", b"file", 3);
        let b = derive_subkey(MASTER, b"header-mac", b"file", 3);
        assert_eq!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn different_purpose_different_subkey() {
        let a = derive_subkey(MASTER, b"content", b"file", 0);
        let b = derive_subkey(MASTER, b"filename", b"file", 0);
        assert_ne!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn different_file_id_different_subkey() {
        let a = derive_subkey(MASTER, b"content", b"file-a", 0);
        let b = derive_subkey(MASTER, b"content", b"file-b", 0);
        assert_ne!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn different_chunk_idx_different_subkey() {
        let a = derive_subkey(MASTER, b"content", b"file", 0);
        let b = derive_subkey(MASTER, b"content", b"file", 1);
        assert_ne!(a.as_ref(), b.as_ref());
    }
}
