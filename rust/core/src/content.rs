//! Per-chunk authenticated encryption (AES-256-GCM-SIV, 64 KiB fixed chunks).
//!
//! Each chunk is sealed with a caller-provided 32-byte subkey (derived via
//! [`crate::subkeys::derive_subkey`]). The AAD binds the ciphertext to its
//! position and context: `file_id | chunk_idx | generation`.

use aes_gcm_siv::{
    Aes256GcmSiv, Key, Nonce,
    aead::{Aead, KeyInit},
};
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};

/// Fixed chunk size in bytes (64 KiB).
pub const CHUNK_SIZE: usize = 64 * 1024;

/// AES-256-GCM-SIV nonce length in bytes.
pub const NONCE_LEN: usize = 12;

/// AEAD authentication tag length in bytes.
pub const TAG_LEN: usize = 16;

/// Length of a content subkey in bytes.
pub const SUBKEY_LEN: usize = 32;

/// Seal (encrypt + authenticate) `plaintext` for `(file_id, chunk_idx, generation)`.
///
/// `plaintext` must not exceed [`CHUNK_SIZE`]. Returns `nonce(12) || ciphertext || tag`.
pub fn seal_chunk(
    subkey: &[u8; SUBKEY_LEN],
    generation: &[u8],
    file_id: &[u8],
    chunk_idx: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    if plaintext.len() > CHUNK_SIZE {
        return Err(CryptoError::invalid_length(
            "chunk plaintext",
            CHUNK_SIZE,
            plaintext.len(),
        ));
    }
    let cipher = cipher_from_subkey(subkey)?;
    let mut aad = Vec::with_capacity(file_id.len() + std::mem::size_of::<u64>() + generation.len());
    aad.extend_from_slice(file_id);
    aad.extend_from_slice(&chunk_idx.to_le_bytes());
    aad.extend_from_slice(generation);
    let nonce = zero_nonce();
    let ciphertext = cipher.encrypt(
        nonce,
        Payload {
            msg: plaintext,
            aad: &aad,
        },
    )?;

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&[0u8; NONCE_LEN]); // zero nonce is fixed for all chunks
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Open (decrypt + verify) a chunk as produced by [`seal_chunk`].
pub fn open_chunk(
    subkey: &[u8; SUBKEY_LEN],
    generation: &[u8],
    file_id: &[u8],
    chunk_idx: u64,
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if ciphertext.len() < NONCE_LEN + TAG_LEN {
        return Err(CryptoError::invalid_ciphertext_length(
            NONCE_LEN + TAG_LEN,
            ciphertext.len(),
        ));
    }
    let cipher = cipher_from_subkey(subkey)?;
    let nonce = zero_nonce();
    let mut aad = Vec::with_capacity(file_id.len() + std::mem::size_of::<u64>() + generation.len());
    aad.extend_from_slice(file_id);
    aad.extend_from_slice(&chunk_idx.to_le_bytes());
    aad.extend_from_slice(generation);

    // The stored payload is `zero_nonce || ciphertext || tag`; drop the fixed
    // nonce bytes before decrypting.
    let body = &ciphertext[NONCE_LEN..];
    let plaintext = cipher.decrypt(
        nonce,
        Payload {
            msg: body,
            aad: &aad,
        },
    )?;
    Ok(Zeroizing::new(plaintext))
}

fn cipher_from_subkey(subkey: &[u8; SUBKEY_LEN]) -> Result<Aes256GcmSiv> {
    let key: &Key<Aes256GcmSiv> = subkey
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::invalid_length("content subkey", SUBKEY_LEN, subkey.len()))?;
    Ok(Aes256GcmSiv::new(key))
}

/// A fixed zero nonce. In SIV modes (AES-GCM-SIV) the nonce is a hint, and the
/// synthetic IV is derived from the AAD/plaintext, so a constant nonce is safe
/// and gives deterministic ciphertext per identical (message, AAD).
fn zero_nonce() -> &'static Nonce {
    static NONCE: [u8; NONCE_LEN] = [0u8; NONCE_LEN];
    <&Nonce>::try_from(&NONCE[..]).expect("12-byte nonce slice")
}

use aes_gcm_siv::aead::Payload;

#[cfg(test)]
mod tests {
    use super::*;

    const SUBKEY: [u8; SUBKEY_LEN] = [7u8; 32];
    const FILE_ID: &[u8] = b"file-123";
    const GENERATION: &[u8] = b"gen-0";

    fn seal(generation: &[u8], file_id: &[u8], idx: u64, data: &[u8]) -> Vec<u8> {
        seal_chunk(&SUBKEY, generation, file_id, idx, data).unwrap()
    }

    #[test]
    fn chunk_roundtrip() {
        let data = vec![0xAB; CHUNK_SIZE / 2];
        let sealed = seal(GENERATION, FILE_ID, 3, &data);
        let opened = open_chunk(&SUBKEY, GENERATION, FILE_ID, 3, &sealed).unwrap();
        assert_eq!(opened.as_slice(), data.as_slice());
    }

    #[test]
    fn roundtrip_empty_chunk() {
        let sealed = seal(GENERATION, FILE_ID, 0, b"");
        let opened = open_chunk(&SUBKEY, GENERATION, FILE_ID, 0, &sealed).unwrap();
        assert!(opened.is_empty());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let data = vec![0xAB; 100];
        let mut sealed = seal(GENERATION, FILE_ID, 1, &data);
        let last = sealed.last_mut().unwrap();
        *last ^= 0x01;
        assert!(open_chunk(&SUBKEY, GENERATION, FILE_ID, 1, &sealed).is_err());
    }

    #[test]
    fn wrong_generation_fails() {
        let data = b"hello chunk";
        let sealed = seal(GENERATION, FILE_ID, 1, data);
        assert!(open_chunk(&SUBKEY, b"gen-1", FILE_ID, 1, &sealed).is_err());
    }

    #[test]
    fn wrong_file_id_fails() {
        let data = b"hello chunk";
        let sealed = seal(GENERATION, FILE_ID, 1, data);
        assert!(open_chunk(&SUBKEY, GENERATION, b"file-999", 1, &sealed).is_err());
    }

    #[test]
    fn wrong_chunk_idx_fails() {
        let data = b"hello chunk";
        let sealed = seal(GENERATION, FILE_ID, 1, data);
        assert!(open_chunk(&SUBKEY, GENERATION, FILE_ID, 2, &sealed).is_err());
    }

    #[test]
    fn wrong_subkey_fails() {
        let data = b"hello chunk";
        let sealed = seal(GENERATION, FILE_ID, 1, data);
        let other = [9u8; 32];
        assert!(open_chunk(&other, GENERATION, FILE_ID, 1, &sealed).is_err());
    }

    #[test]
    fn overlarge_plaintext_rejected() {
        let big = vec![0u8; CHUNK_SIZE + 1];
        assert!(seal_chunk(&SUBKEY, GENERATION, FILE_ID, 0, &big).is_err());
    }

    #[test]
    fn short_ciphertext_rejected() {
        assert!(open_chunk(&SUBKEY, GENERATION, FILE_ID, 0, &[0u8; 11]).is_err());
        assert!(matches!(
            open_chunk(&SUBKEY, GENERATION, FILE_ID, 0, &[0u8; 11]),
            Err(CryptoError::InvalidCiphertextLength { .. })
        ));
    }

    #[test]
    fn output_layout() {
        let data = b"abc";
        let sealed = seal(GENERATION, FILE_ID, 0, data);
        assert_eq!(sealed.len(), NONCE_LEN + data.len() + TAG_LEN);
    }
}
