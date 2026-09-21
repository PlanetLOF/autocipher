//! Deterministic filename encryption via a cached [`NameKey`].
//!
//! The [`NameKey`] is expanded **once** at vault init from a 32-byte filename
//! subkey (see [`crate::subkeys::derive_subkey`]) with a single HKDF-SHA256
//! call yielding 96 bytes:
//!
//! ```text
//! okm[0..64]  -> siv_key  ( [0..32] AES-256-GCM-SIV key , [32..64] AAD key )
//! okm[64..96] -> hmac_key ( search-index lookup key )
//! ```
//!
//! After construction, [`encrypt_name`], [`decrypt_name`] and [`compute_lookup`]
//! only slice the cached keys — there is no per-file HKDF overhead.

use aes_gcm_siv::{
    Aes256GcmSiv, Key, Nonce,
    aead::{Aead, KeyInit},
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};
use crate::subkeys::{SUBKEY_LEN, derive_subkey};

/// AES-256-GCM-SIV nonce length in bytes.
pub const NONCE_LEN: usize = 12;

/// AEAD authentication tag length in bytes.
pub const TAG_LEN: usize = 16;

/// Minimum byte length of an encrypted name payload: `nonce + plaintext + tag`.
pub const MIN_ENCRYPTED_NAME_LEN: usize = NONCE_LEN + TAG_LEN;

/// Length of the computed lookup digest in bytes.
const LOOKUP_LEN: usize = 32;

type HmacSha256 = Hmac<Sha256>;

/// An encrypted filename payload: `nonce(12) || ciphertext || tag(16)`.
pub type EncryptedName = Vec<u8>;

/// Cached per-vault key set for deterministic filename encryption/decryption
/// and search-index lookup.
#[derive(Clone)]
pub struct NameKey {
    siv_key: Zeroizing<[u8; 64]>,
    hmac_key: Zeroizing<[u8; 32]>,
}

impl NameKey {
    /// Build a [`NameKey`] from a 32-byte filename subkey via a single
    /// HKDF-SHA256 expansion (96 bytes). The subkey is consumed and zeroized.
    pub fn from_subkey(name_subkey: &[u8; SUBKEY_LEN]) -> Self {
        let hk = Hkdf::<Sha256>::new(None, name_subkey.as_slice());
        let mut okm = Zeroizing::new([0u8; 96]);
        hk.expand(&[], okm.as_mut())
            .expect("96-byte HKDF-SHA256 output is always valid");

        let mut siv_key = Zeroizing::new([0u8; 64]);
        siv_key.copy_from_slice(&okm[0..64]);
        let mut hmac_key = Zeroizing::new([0u8; 32]);
        hmac_key.copy_from_slice(&okm[64..96]);

        Self { siv_key, hmac_key }
    }

    /// Convenience constructor: derive the 32-byte filename subkey from `master`
    /// (purpose `"filename"`, fixed `chunk_idx = 0`) and expand it into a [`NameKey`].
    pub fn from_master(master: &[u8], file_id: &[u8]) -> Self {
        let subkey = derive_subkey(master, b"filename", file_id, 0);
        Self::from_subkey(
            subkey
                .as_ref()
                .try_into()
                .expect("derive_subkey always returns a 32-byte subkey"),
        )
    }

    /// Deterministically encrypt `name`, binding the ciphertext to `aad_ctx`
    /// (a context known before decryption, e.g. `file_id` or a fixed domain
    /// string). Returns `nonce(12) || ciphertext || tag`.
    ///
    /// Same `(name, aad_ctx)` always produces the same output.
    pub fn encrypt_name(&self, name: &[u8], aad_ctx: &[u8]) -> Result<EncryptedName> {
        let cipher = self.siv_cipher()?;

        // Deterministic nonce from the data-hiding half of siv_key.
        let mut mac = HmacSha256::new_from_slice(&self.siv_key[0..32]).expect("32-byte HMAC key");
        mac.update(name);
        let digest = mac.finalize().into_bytes();
        let nonce: &Nonce = digest[0..NONCE_LEN].try_into().unwrap();

        // AAD keyed by the second half of siv_key over known context (not plaintext).
        let mut amac = HmacSha256::new_from_slice(&self.siv_key[32..64]).expect("32-byte HMAC key");
        amac.update(aad_ctx);
        let aad = amac.finalize().into_bytes();

        let ciphertext = cipher.encrypt(
            nonce,
            aes_gcm_siv::aead::Payload {
                msg: name,
                aad: aad.as_slice(),
            },
        )?;

        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&digest[0..NONCE_LEN]);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypt and verify an encrypted name as produced by [`NameKey::encrypt_name`].
    ///
    /// The same `aad_ctx` used during encryption must be supplied. Before any
    /// slicing, the payload length is validated to be at least
    /// [`MIN_ENCRYPTED_NAME_LEN`].
    pub fn decrypt_name(&self, enc: &EncryptedName, aad_ctx: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if enc.len() < MIN_ENCRYPTED_NAME_LEN {
            return Err(CryptoError::invalid_ciphertext_length(
                MIN_ENCRYPTED_NAME_LEN,
                enc.len(),
            ));
        }
        let cipher = self.siv_cipher()?;
        let (nonce_bytes, body) = enc.split_at(NONCE_LEN);
        let nonce: &Nonce = nonce_bytes.try_into().unwrap();

        let mut amac = HmacSha256::new_from_slice(&self.siv_key[32..64]).expect("32-byte HMAC key");
        amac.update(aad_ctx);
        let aad = amac.finalize().into_bytes();

        let plaintext = cipher.decrypt(
            nonce,
            aes_gcm_siv::aead::Payload {
                msg: body,
                aad: aad.as_slice(),
            },
        )?;
        Ok(Zeroizing::new(plaintext))
    }

    /// Compute the 32-byte search-index lookup digest for `name` using the cached
    /// `hmac_key`, independent of the encryption path.
    pub fn compute_lookup(&self, name: &[u8]) -> [u8; LOOKUP_LEN] {
        let mut mac = HmacSha256::new_from_slice(self.hmac_key.as_ref()).expect("32-byte HMAC key");
        mac.update(name);
        let digest = mac.finalize().into_bytes();
        let mut out = [0u8; LOOKUP_LEN];
        out.copy_from_slice(&digest);
        out
    }

    fn siv_cipher(&self) -> Result<Aes256GcmSiv> {
        let key: &Key<Aes256GcmSiv> = self.siv_key[0..32]
            .try_into()
            .map_err(|_| CryptoError::invalid_length("filename aes key", 32usize, 32usize))?;
        Ok(Aes256GcmSiv::new(key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASTER: &[u8] = b"0123456789abcdef0123456789abcdef";
    const FILE_ID: &[u8] = b"file-abc";
    const AAD_CTX: &[u8] = b"autocipher:filename:v1";

    fn key() -> NameKey {
        NameKey::from_master(MASTER, FILE_ID)
    }

    #[test]
    fn subkey_expands_to_distinct_halves() {
        let subkey = derive_subkey(MASTER, b"filename", FILE_ID, 0);
        let nk = NameKey::from_subkey(subkey.as_ref().try_into().unwrap());
        assert_ne!(nk.siv_key[0..32], nk.siv_key[32..64]);
        // hmac_key should differ from both siv halves (independent key material).
        assert_ne!(nk.hmac_key.as_ref(), &nk.siv_key[0..32]);
        assert_ne!(nk.hmac_key.as_ref(), &nk.siv_key[32..64]);
    }

    #[test]
    fn roundtrip() {
        let nk = key();
        let enc = nk.encrypt_name(b"report.pdf", AAD_CTX).unwrap();
        let dec = nk.decrypt_name(&enc, AAD_CTX).unwrap();
        assert_eq!(dec.as_slice(), b"report.pdf");
    }

    #[test]
    fn roundtrip_empty_name() {
        let nk = key();
        let enc = nk.encrypt_name(b"", AAD_CTX).unwrap();
        assert_eq!(enc.len(), MIN_ENCRYPTED_NAME_LEN);
        let dec = nk.decrypt_name(&enc, AAD_CTX).unwrap();
        assert!(dec.is_empty());
    }

    #[test]
    fn deterministic_encryption() {
        let nk = key();
        let a = nk.encrypt_name(b"photo.jpg", AAD_CTX).unwrap();
        let b = nk.encrypt_name(b"photo.jpg", AAD_CTX).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_name_different_ciphertext() {
        let nk = key();
        let a = nk.encrypt_name(b"a.txt", AAD_CTX).unwrap();
        let b = nk.encrypt_name(b"b.txt", AAD_CTX).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn wrong_aad_ctx_fails() {
        let nk = key();
        let enc = nk.encrypt_name(b"notes.md", AAD_CTX).unwrap();
        assert!(nk.decrypt_name(&enc, b"autocipher:filename:v2").is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let nk = key();
        let mut enc = nk.encrypt_name(b"secret.txt", AAD_CTX).unwrap();
        let last = enc.last_mut().unwrap();
        *last ^= 0x01;
        assert!(nk.decrypt_name(&enc, AAD_CTX).is_err());
    }

    #[test]
    fn short_payload_rejected_without_panic() {
        let nk = key();
        for len in [0usize, 12, 27] {
            let enc = vec![0u8; len];
            assert!(matches!(
                nk.decrypt_name(&enc, AAD_CTX),
                Err(CryptoError::InvalidCiphertextLength { expected_min, got })
                    if expected_min == MIN_ENCRYPTED_NAME_LEN && got == len
            ));
        }
    }

    #[test]
    fn lookup_deterministic() {
        let nk = key();
        assert_eq!(
            nk.compute_lookup(b"star.png"),
            nk.compute_lookup(b"star.png")
        );
        assert_ne!(
            nk.compute_lookup(b"star.png"),
            nk.compute_lookup(b"star.gif")
        );
    }

    #[test]
    fn lookup_distinct_from_ciphertext() {
        let nk = key();
        let lookup = nk.compute_lookup(b"star.png");
        let enc = nk.encrypt_name(b"star.png", AAD_CTX).unwrap();
        assert_ne!(lookup.as_slice(), enc.as_slice());
    }

    #[test]
    fn from_master_reproducible() {
        let a = NameKey::from_master(MASTER, FILE_ID);
        let b = NameKey::from_master(MASTER, FILE_ID);
        assert_eq!(a.siv_key.as_ref(), b.siv_key.as_ref());
        assert_eq!(a.hmac_key.as_ref(), b.hmac_key.as_ref());
    }

    #[test]
    fn different_master_isolation() {
        let other_master = format!("{}x", String::from_utf8(MASTER.to_vec()).unwrap());
        let a = key();
        let b = NameKey::from_master(other_master.as_bytes(), FILE_ID);
        let ea = a.encrypt_name(b"same.txt", AAD_CTX).unwrap();
        let eb = b.encrypt_name(b"same.txt", AAD_CTX).unwrap();
        assert_ne!(ea, eb);
        assert_ne!(a.compute_lookup(b"same.txt"), b.compute_lookup(b"same.txt"));
    }
}
