//! Error types for autocipher-format.

use thiserror::Error;

/// Result alias using [`FormatError`].
pub type Result<T> = std::result::Result<T, FormatError>;

/// Errors produced by the `.ac` container layer.
#[derive(Debug, Error)]
pub enum FormatError {
    /// An underlying [`autocipher_core`] cryptographic operation failed.
    #[error("cryptographic core error: {0}")]
    Crypto(#[from] autocipher_core::error::CryptoError),
    /// An underlying I/O operation failed.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// A required file (e.g. a mirror) was not found.
    #[error("required file not found: {0}")]
    NotFound(String),
    /// A monotonic generation/anchor regressed, indicating a rollback or a
    /// torn/old store that must not be trusted.
    #[error("generation rollback detected: got {got}, expected at least {expected}")]
    Rollback { got: u64, expected: u64 },
    /// HMAC computation or verification failed.
    #[error("header HMAC verification failed")]
    Hmac,
    /// The header-MAC subkey had an unexpected byte length.
    #[error("invalid header-MAC key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },
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
    /// A forged or corrupt container advertised a metadata region larger than
    /// the DoS ceiling.
    #[error(
        "metadata too large: {size} bytes exceeds limit {limit}; split the import into smaller batches"
    )]
    MetadataTooLarge {
        /// The size of the metadata region found.
        size: usize,
        /// The enforced ceiling.
        limit: usize,
    },
    /// An internal invariant was violated (e.g. the regenerated chunk layout
    /// diverged from the layout used to write the metadata). Indicates a bug,
    /// not a corrupt container.
    #[error("internal inconsistency: {0}")]
    Internal(&'static str),
    /// A forged or corrupt container advertised more files/chunks than the DoS
    /// ceiling allows.
    #[error("{what} count {count} exceeds limit {limit}")]
    ChunkLimitExceeded {
        /// What was bounded (a file or a chunk count).
        what: &'static str,
        /// The count found in the metadata.
        count: usize,
        /// The enforced ceiling.
        limit: usize,
    },
}
