//! autocipher-core
//!
//! Pure cryptographic core: error handling, Argon2id key derivation, KEK
//! master-key wrapping, HKDF key separation, chunk/file content crypto, and
//! deterministic filename encryption — assembled behind a single
//! [`Vault::from_password`] entry point.

pub mod constant_time;
pub mod content;
pub mod error;
pub mod filename;
pub mod kdf;
pub mod keywrap;
pub mod password;
pub mod subkeys;

use zeroize::{Zeroize, Zeroizing};

use crate::error::Result;
use crate::filename::NameKey;
use crate::kdf::KdfParams;

/// Length of the unwrapped master key in bytes.
pub const MASTER_KEY_LEN: usize = keywrap::MASTER_KEY_LEN;

/// Entry point for unlocking a vault.
///
/// Stateless: `from_password` derives the KEK, unwraps the stored master key,
/// and returns the cached per-vault [`Keys`]. Intermediate key material (the
/// KEK and unwrapped master) lives in [`Zeroizing`] buffers and is scrubbed on
/// drop.
pub struct Vault;

impl Vault {
    /// Unlock a vault from `password`, `salt`, and Argon2 [`KdfParams`].
    ///
    /// `wrapped` must be the output of [`keywrap::wrap`], i.e.
    /// `nonce(12) || AEAD ciphertext` of the 32-byte master key. A wrong
    /// password derives a different KEK and the authenticated unwrap fails.
    pub fn from_password(
        password: &[u8],
        salt: &[u8],
        params: &KdfParams,
        wrapped: &[u8],
    ) -> Result<Keys> {
        // Zeroized intermediate material: the KEK, then the unwrapped master.
        let mut kek = Zeroizing::new([0u8; kdf::KEK_LEN]);
        kek.copy_from_slice(
            kdf::derive_kek(password, salt, params.memory, params.t, params.p)?.as_ref(),
        );

        let master = keywrap::unwrap(kek.as_ref(), wrapped)?;
        kek.zeroize();

        // Vault-level NameKey: derive the filename subkey from the master with a
        // fixed domain context (no per-file binding at init).
        let name_subkey = subkeys::derive_subkey(master.as_ref(), b"filename", b"", 0);
        let name = NameKey::from_subkey(
            name_subkey
                .as_ref()
                .try_into()
                .expect("derive_subkey always returns a 32-byte subkey"),
        );

        Ok(Keys { name })
    }
}

/// Key container: the cached per-vault key sets derived at unlock.
pub struct Keys {
    name: NameKey,
}

impl Keys {
    /// Derive the cached key sets from `master` for `file_id`.
    pub fn from_master(master: &[u8], file_id: &[u8]) -> Self {
        Self {
            name: NameKey::from_master(master, file_id),
        }
    }

    /// Access the cached filename [`NameKey`].
    pub fn name(&self) -> &NameKey {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::Memory;

    const SALT: &[u8] = b"Nhf562T6TFOJKXpx";
    const FILE_ID: &[u8] = b"";

    fn params() -> KdfParams {
        KdfParams {
            memory: Memory::M128,
            t: 1,
            p: 1,
        }
    }

    #[test]
    fn from_password_unlocks_with_correct_password() {
        let master = keywrap::generate_master_key();
        let kek =
            kdf::derive_kek(b"correct horse battery staple", SALT, Memory::M128, 1, 1).unwrap();
        let wrapped = keywrap::wrap(kek.as_ref(), master.as_ref()).unwrap();

        let keys = Vault::from_password(b"correct horse battery staple", SALT, &params(), &wrapped)
            .expect("correct password should unlock");

        // The NameKey derived at unlock must match one derived directly from the
        // same master, proving the unwrapped master is correct.
        let expected = NameKey::from_master(master.as_ref(), FILE_ID);
        assert_eq!(
            keys.name().compute_lookup(b"same.txt"),
            expected.compute_lookup(b"same.txt")
        );
        let ea = keys.name().encrypt_name(b"same.txt", b"ctx").unwrap();
        let eb = expected.encrypt_name(b"same.txt", b"ctx").unwrap();
        assert_eq!(ea, eb);
    }

    #[test]
    fn from_password_fails_with_wrong_password() {
        let master = keywrap::generate_master_key();
        let kek =
            kdf::derive_kek(b"correct horse battery staple", SALT, Memory::M128, 1, 1).unwrap();
        let wrapped = keywrap::wrap(kek.as_ref(), master.as_ref()).unwrap();

        let result = Vault::from_password(b"wrong horse battery staple", SALT, &params(), &wrapped);
        assert!(result.is_err());
    }

    #[test]
    fn from_password_rejects_corrupt_wrapped_key() {
        let master = keywrap::generate_master_key();
        let kek = kdf::derive_kek(b"pass", SALT, Memory::M128, 1, 1).unwrap();
        let mut wrapped = keywrap::wrap(kek.as_ref(), master.as_ref()).unwrap();
        *wrapped.last_mut().unwrap() ^= 0x01;

        assert!(Vault::from_password(b"pass", SALT, &params(), &wrapped).is_err());
    }
}
