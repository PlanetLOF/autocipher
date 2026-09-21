//! Central error type for autocipher-core.

use thiserror::Error;

/// Result alias using [`CryptoError`].
pub type Result<T> = std::result::Result<T, CryptoError>;

/// Errors produced by the cryptographic core.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Key derivation failed.
    #[error("argon2 key derivation failed: {0}")]
    Kdf(#[from] argon2::Error),
    /// Authenticated encryption failed (e.g. authentication tag mismatch).
    #[error("AES-256-GCM-SIV operation failed: {0}")]
    Aead(#[from] aes_gcm_siv::aead::Error),
    /// A fixed-size value had an unexpected byte length.
    #[error("invalid length for {what}: expected {expected}, got {got}")]
    InvalidLength {
        /// What the length constrained.
        what: &'static str,
        /// The expected byte length.
        expected: usize,
        /// The byte length that was supplied.
        got: usize,
    },
    /// An encrypted payload (e.g. filename) was too short to contain its
    /// nonce/header and tag.
    #[error("invalid ciphertext length: expected at least {expected_min}, got {got}")]
    InvalidCiphertextLength {
        /// Minimum accepted length (nonce + tag).
        expected_min: usize,
        /// The byte length actually supplied.
        got: usize,
    },
}

impl CryptoError {
    /// Construct an [`CryptoError::InvalidLength`] for `what`.
    pub(crate) fn invalid_length(what: &'static str, expected: usize, got: usize) -> Self {
        Self::InvalidLength {
            what,
            expected,
            got,
        }
    }

    /// Construct an [`CryptoError::InvalidCiphertextLength`] for `got`.
    pub(crate) fn invalid_ciphertext_length(expected_min: usize, got: usize) -> Self {
        Self::InvalidCiphertextLength { expected_min, got }
    }
}
