//! The `.ac` metadata region: the sealed manifest plus the integrity store,
//! framed with length prefixes and bounded by DoS ceilings.
//!
//! The metadata region begins immediately after the 8 KiB header
//! (`[HEADER_SIZE .. data_off]`) and stores two authenticated payloads:
//!
//! ```text
//! u64 LE  manifest_len || sealed manifest (AEAD via the manifest subkey)
//! u64 LE  store_len    || serialized IntegrityBlockStore (HMAC-SHA512 trailer)
//! ```
//!
//! [`serialize_metadata`] produces this region; [`parse_metadata`] reads it back
//! and enforces hard ceilings on the metadata size and on the per-file chunk
//! counts it may contain, so a forged oversized container cannot exhaust memory
//! or CPU on open.

use crate::constants::HEADER_SIZE;
use crate::error::{FormatError, Result};
use crate::integrity::IntegrityBlockStore;
use crate::manifest::{FileMeta, VaultManifest, decrypt_manifest, encrypt_manifest};

/// Hard ceiling on the total size of a serialized metadata region, in bytes.
///
/// This bounds the maximum vault/manifest size a container may advertise, so a
/// maliciously crafted `.ac` cannot force an unlimited allocation on open.
///
/// 64 MiB keeps the bound meaningful as a DoS ceiling while leaving room for
/// vaults whose manifest + integrity store exceed the old 4 MiB cap (roughly
/// tens of thousands of files). Each mutation re-seals the whole region, so
/// values far beyond this make every add/delete quadratically expensive.
pub const MAX_METADATA_SIZE: usize = 64 * 1024 * 1024;

/// Hard ceiling on the number of files permitted in a vault manifest.
pub const MAX_FILES: usize = 1_000_000;

/// Hard ceiling on the number of sealed chunks any single file may reference.
pub const MAX_CHUNKS_PER_FILE: usize = 1 << 24;

/// Byte length of the little-endian length prefix framing each metadata field.
const LEN_FIELD: usize = 8;

/// Serialize `manifest` and `store` into a single length-prefixed metadata
/// region that can be persisted in the container or mirrored.
pub fn serialize_metadata(
    master: &[u8],
    manifest: &VaultManifest,
    store: &IntegrityBlockStore,
) -> Result<Vec<u8>> {
    let manifest_sealed = encrypt_manifest(master, manifest)?;
    let store_bytes = store.serialize(master)?;

    let mut out = Vec::with_capacity(LEN_FIELD * 2 + manifest_sealed.len() + store_bytes.len());
    out.extend_from_slice(&(manifest_sealed.len() as u64).to_le_bytes());
    out.extend_from_slice(&manifest_sealed);
    out.extend_from_slice(&(store_bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(&store_bytes);

    if out.len() > MAX_METADATA_SIZE {
        return Err(FormatError::MetadataTooLarge {
            size: out.len(),
            limit: MAX_METADATA_SIZE,
        });
    }
    Ok(out)
}

/// Parse and authenticate a metadata region produced by
/// [`serialize_metadata`], enforcing the DoS ceilings on metadata size and
/// per-file chunk counts.
///
/// `min_generation` is the rollback anchor: a metadata region whose integrity
/// store carries a lower generation is rejected as a replayed/old snapshot.
/// Returns the manifest and store, plus the byte length of the metadata region
/// itself. The absolute offset of the file-data area is recorded in the active
/// header's `data_offset` (which the new layout keeps strictly increasing
/// across appends), so the caller resolves it there rather than from this
/// region's position.
pub fn parse_metadata(
    master: &[u8],
    bytes: &[u8],
    min_generation: u64,
) -> Result<(VaultManifest, IntegrityBlockStore, u64)> {
    if bytes.len() > MAX_METADATA_SIZE {
        return Err(FormatError::MetadataTooLarge {
            size: bytes.len(),
            limit: MAX_METADATA_SIZE,
        });
    }

    let mut rest = bytes;
    let manifest_len = take_len(&mut rest)?;
    if manifest_len > rest.len() {
        return Err(FormatError::InvalidLength {
            what: "manifest field",
            expected: rest.len(),
            got: manifest_len,
        });
    }
    let (manifest_sealed, after_manifest) = rest.split_at(manifest_len);
    let manifest = decrypt_manifest(master, manifest_sealed)?;
    enforce_manifest_ceilings(&manifest)?;

    let mut rest = after_manifest;
    let store_len = take_len(&mut rest)?;
    if store_len > rest.len() {
        return Err(FormatError::InvalidLength {
            what: "integrity store field",
            expected: rest.len(),
            got: store_len,
        });
    }
    let (store_bytes, _) = rest.split_at(store_len);
    let store = IntegrityBlockStore::parse_verified(master, store_bytes, min_generation)?;

    let meta_len = (bytes.len() - rest.len()) as u64;
    Ok((manifest, store, meta_len))
}

/// Read an 8-byte little-endian length prefix from the front of `rest`.
fn take_len(rest: &mut &[u8]) -> Result<usize> {
    if rest.len() < LEN_FIELD {
        return Err(FormatError::InvalidLength {
            what: "metadata length prefix",
            expected: LEN_FIELD,
            got: rest.len(),
        });
    }
    let v = u64::from_le_bytes(rest[..LEN_FIELD].try_into().unwrap()) as usize;
    *rest = &rest[LEN_FIELD..];
    Ok(v)
}

/// Enforce the DoS ceilings on the parsed manifest's file and chunk counts.
fn enforce_manifest_ceilings(manifest: &VaultManifest) -> Result<()> {
    if manifest.files.len() > MAX_FILES {
        return Err(FormatError::ChunkLimitExceeded {
            what: "files",
            count: manifest.files.len(),
            limit: MAX_FILES,
        });
    }
    for file in &manifest.files {
        if file.chunks.len() > MAX_CHUNKS_PER_FILE {
            return Err(FormatError::ChunkLimitExceeded {
                what: "chunks",
                count: file.chunks.len(),
                limit: MAX_CHUNKS_PER_FILE,
            });
        }
    }
    Ok(())
}

/// The absolute offset at which the file-data area begins for a fresh container
/// with an empty metadata region.
pub const fn metadata_start() -> u64 {
    HEADER_SIZE as u64
}

/// Sanity helper used by callers to sum the chunk count of a manifest.
pub fn file_chunk_count(file: &FileMeta) -> usize {
    file.chunks.len()
}
