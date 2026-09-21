//! Argon2id password-based key derivation.

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

use crate::error::Result;

/// Length of the derived KEK in bytes.
pub const KEK_LEN: usize = 32;

/// Argon2id memory cost preset, in MiB.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Memory {
    M128,
    #[default]
    M256,
    M512,
}

impl Memory {
    /// Memory cost in 1 KiB blocks for the preset.
    pub const fn kib(self) -> u32 {
        match self {
            Self::M128 => 128 * 1024,
            Self::M256 => 256 * 1024,
            Self::M512 => 512 * 1024,
        }
    }
}

/// Default Argon2id cost parameters: 256 MiB memory, `t=4`, `p=4`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KdfParams {
    /// Memory cost preset.
    pub memory: Memory,
    /// Iteration (time) cost.
    pub t: u32,
    /// Parallelism (lanes).
    pub p: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            memory: Memory::M256,
            t: 4,
            p: 4,
        }
    }
}

impl KdfParams {
    /// Build the Argon2 [`Params`] for this preset and the 32-byte KEK output.
    pub fn params(&self) -> Result<Params> {
        Params::new(self.memory.kib(), self.t, self.p, Some(KEK_LEN)).map_err(Into::into)
    }
}

/// Derive a 32-byte KEK from `password` using Argon2id.
///
/// `memory` selects the memory cost preset, defaulting to [`Memory::M256`];
/// `t` and `p` are caller-provided.
pub fn derive_kek(
    password: &[u8],
    salt: &[u8],
    memory: Memory,
    t: u32,
    p: u32,
) -> Result<Zeroizing<[u8; KEK_LEN]>> {
    let params = KdfParams { memory, t, p }.params()?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut kek = Zeroizing::new([0u8; KEK_LEN]);
    argon2.hash_password_into(password, salt, kek.as_mut())?;
    Ok(kek)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: &[u8] = b"Nhf562T6TFOJKXpx";

    #[test]
    fn same_password_and_params_reproducible() {
        let a = derive_kek(b"correct horse battery staple", SALT, Memory::M256, 4, 4).unwrap();
        let b = derive_kek(b"correct horse battery staple", SALT, Memory::M256, 4, 4).unwrap();
        assert_eq!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn different_password_different_kek() {
        let a = derive_kek(b"password one", SALT, Memory::M256, 4, 4).unwrap();
        let b = derive_kek(b"password two", SALT, Memory::M256, 4, 4).unwrap();
        assert_ne!(a.as_ref(), b.as_ref());
    }

    #[test]
    fn different_memory_different_kek() {
        let mem128 = derive_kek(b"password", SALT, Memory::M128, 4, 4).unwrap();
        let mem512 = derive_kek(b"password", SALT, Memory::M512, 4, 4).unwrap();
        assert_ne!(mem128.as_ref(), mem512.as_ref());
    }

    #[test]
    fn different_t_or_p_different_kek() {
        let base = derive_kek(b"password", SALT, Memory::M256, 4, 4).unwrap();
        let higher_t = derive_kek(b"password", SALT, Memory::M256, 8, 4).unwrap();
        let higher_p = derive_kek(b"password", SALT, Memory::M256, 4, 8).unwrap();
        assert_ne!(base.as_ref(), higher_t.as_ref());
        assert_ne!(base.as_ref(), higher_p.as_ref());
    }
}
