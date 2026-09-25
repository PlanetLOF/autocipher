//! Format constants for the `.ac` container: magic, header geometry, and
//! default Argon2id cost parameters.

use autocipher_core::kdf::KdfParams;

/// Four-byte magic identifying an `.ac` container.
pub const MAGIC: &[u8; 4] = b"ACPH";

/// Current container/header format version.
///
/// The fixed-size header layout is unchanged by per-file metadata, so the
/// container version remains 1. The manifest has its own version below.
pub const VERSION: u16 = 1;

/// Current sealed-manifest format version.
///
/// Version 2 adds optional per-file creation/modification timestamps. Version
/// 1 manifests remain readable and expose zero (unknown) timestamps.
pub const MANIFEST_VERSION: u16 = 2;

/// The legacy manifest version without per-file timestamps.
pub const LEGACY_MANIFEST_VERSION: u16 = 1;

/// Total size of each header slot in bytes (8 KiB).
pub const HEADER_SIZE: usize = 8192;

/// Number of header slots in the container.
///
/// Two slots enable atomic header flips: a mutation appends new metadata + data
/// to the end of the file, then atomically writes the inactive header slot to
/// activate the new generation. The old slot remains valid until overwritten.
pub const HEADER_SLOTS: usize = 2;

/// Total size of the header region (all slots).
pub const HEADER_REGION_SIZE: usize = HEADER_SIZE * HEADER_SLOTS;

/// Length of the header salt in bytes.
pub const SALT_LEN: usize = 32;

/// Length of the HMAC-SHA512 trailer in bytes.
pub const HMAC_LEN: usize = 64;

/// HKDF purpose tag used to derive the header-MAC subkey.
pub const HEADER_MAC_PURPOSE: &[u8] = b"header-mac";

/// Default Argon2id cost parameters (256 MiB, t=4, p=4).
pub const DEFAULT_KDF_PARAMS: KdfParams = KdfParams {
    memory: autocipher_core::kdf::Memory::M256,
    t: 4,
    p: 4,
};

/// Default garbage ratio above which a mutation triggers automatic compaction.
///
/// `garbage / container_size` is measured after every mutation; when it exceeds
/// this threshold the container is rebuilt to reclaim the space. See
/// [`Vault::set_auto_compact_ratio`](crate::Vault::set_auto_compact_ratio).
pub const DEFAULT_AUTO_COMPACT_RATIO: f64 = 0.5;
