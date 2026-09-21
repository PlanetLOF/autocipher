//! Master-key wrapping using AES-256-GCM-SIV.

use aes_gcm_siv::{Aes256GcmSiv, Key, KeyInit, Nonce, aead::Aead};
use rand::Rng;
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};

/// Length of the wrapping key (KEK) in bytes.
pub const KEK_LEN: usize = 32;

/// Length of the generated master key in bytes.
pub const MASTER_KEY_LEN: usize = 32;

/// AES-GCM-SIV nonce length in bytes.
const NONCE_LEN: usize = 12;

/// Generate a fresh 32-byte master key from a cryptographically secure RNG.
pub fn generate_master_key() -> Zeroizing<[u8; MASTER_KEY_LEN]> {
    let mut master = Zeroizing::new([0u8; MASTER_KEY_LEN]);
    rand::rng().fill_bytes(master.as_mut());
    master
}

/// Wrap `master` with `kek`, returning `nonce(12) || ciphertext`.
pub fn wrap(kek: &[u8], master: &[u8]) -> Result<Vec<u8>> {
    let cipher = cipher_from_kek(kek)?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce: &Nonce = nonce_bytes
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::invalid_length("nonce", NONCE_LEN, NONCE_LEN))?;
    let ciphertext = cipher.encrypt(nonce, master)?;
    let mut wrapped = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    wrapped.extend_from_slice(&nonce_bytes);
    wrapped.extend_from_slice(&ciphertext);
    Ok(wrapped)
}

/// Unwrap `wrapped` — as produced by [`wrap`] — back to the 32-byte master key.
pub fn unwrap(kek: &[u8], wrapped: &[u8]) -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>> {
    let cipher = cipher_from_kek(kek)?;
    if wrapped.len() < NONCE_LEN {
        return Err(CryptoError::invalid_length(
            "wrapped key",
            NONCE_LEN,
            wrapped.len(),
        ));
    }
    let (nonce_bytes, ciphertext) = wrapped.split_at(NONCE_LEN);
    let nonce: &Nonce = nonce_bytes
        .try_into()
        .map_err(|_| CryptoError::invalid_length("nonce", NONCE_LEN, nonce_bytes.len()))?;
    let plaintext = cipher.decrypt(nonce, ciphertext)?;
    if plaintext.len() != MASTER_KEY_LEN {
        return Err(CryptoError::invalid_length(
            "master key",
            MASTER_KEY_LEN,
            plaintext.len(),
        ));
    }
    let mut master = Zeroizing::new([0u8; MASTER_KEY_LEN]);
    master.copy_from_slice(&plaintext);
    Ok(master)
}

/// Build the AES-256-GCM-SIV cipher from a 32-byte KEK.
fn cipher_from_kek(kek: &[u8]) -> Result<Aes256GcmSiv> {
    let key: &Key<Aes256GcmSiv> = kek
        .try_into()
        .map_err(|_| CryptoError::invalid_length("KEK", KEK_LEN, kek.len()))?;
    Ok(Aes256GcmSiv::new(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap_roundtrip() {
        let kek = Zeroizing::new([7u8; 32]);
        let master = generate_master_key();
        let wrapped = wrap(kek.as_ref(), master.as_ref()).unwrap();
        assert_eq!(wrapped.len(), NONCE_LEN + MASTER_KEY_LEN + 16);
        let unwrapped = unwrap(kek.as_ref(), &wrapped).unwrap();
        assert_eq!(unwrapped.as_ref(), master.as_ref());
    }

    #[test]
    fn tampered_wrapped_fails_unwrap() {
        let kek = Zeroizing::new([7u8; 32]);
        let master = generate_master_key();
        let mut wrapped = wrap(kek.as_ref(), master.as_ref()).unwrap();
        *wrapped.last_mut().unwrap() ^= 0x01;
        assert!(unwrap(kek.as_ref(), &wrapped).is_err());
    }

    #[test]
    fn wrong_kek_fails_unwrap() {
        let kek_a = Zeroizing::new([1u8; 32]);
        let kek_b = Zeroizing::new([2u8; 32]);
        let master = generate_master_key();
        let wrapped = wrap(kek_a.as_ref(), master.as_ref()).unwrap();
        assert!(unwrap(kek_b.as_ref(), &wrapped).is_err());
    }

    #[test]
    fn invalid_kek_length_rejected() {
        let master = generate_master_key();
        let short = [0u8; 31];
        assert!(matches!(
            wrap(&short, master.as_ref()),
            Err(CryptoError::InvalidLength { .. })
        ));
    }
}
