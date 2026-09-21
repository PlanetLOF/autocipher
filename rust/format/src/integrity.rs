//! HMAC-SHA512 integrity block store with rollback protection.
//!
//! [`IntegrityBlockStore`] records, per `file_id`, the block references and a
//! per-file version that describe where that file's sealed chunks live, the
//! counter to the content AEAD AAD ("generation") used to write them. The whole
//! store is shielded by an HMAC-SHA512 trailer computed with the integrity
//! subkey, and carries a monotonic `generation` anchor. Any replayed or torn
//! (older-generation) store is rejected so a rolled-back vault is never
//! trusted.
//!
//! Serialization uses the same binary layout style as the [`crate::header`]:
//! the authenticated body is serialized field-by-field (little-endian) and the
//! final 64 bytes are the HMAC-SHA512 computed over that body with the
//! integrity subkey (`derive_subkey(master, b"integrity", b"", 0)`).

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha512;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::constants::HMAC_LEN;
use crate::error::{FormatError, Result};
use crate::manifest::ChunkRef;

/// Type alias for HMAC-SHA512.
type HmacSha512 = Hmac<Sha512>;

/// HKDF purpose tag for the integrity subkey.
pub const INTEGRITY_PURPOSE: &[u8] = b"integrity";

/// Length of the HMAC-SHA512 trailer appended to a serialized store.
pub const INTEGRITY_HMAC_LEN: usize = HMAC_LEN;

/// Per-file block record: the content-AEAD version and the sealed-chunk
/// references for one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockVersion {
    /// The generation value bound into every chunk's AAD for this file.
    pub version: u64,
    /// Sealed-chunk references in storage order; `chunk_idx` maps 1:1 to the
    /// position.
    pub refs: Vec<ChunkRef>,
}

/// The integrity store: a monotonic generation anchor plus the per-file block
/// versions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityBlockStore {
    /// Monotonic rollback anchor; strictly increases on every committed write.
    generation: u64,
    /// `file_id` -> per-file block version, in deterministic insertion order.
    blocks: Vec<(String, BlockVersion)>,
}

impl IntegrityBlockStore {
    /// Create an empty store carrying `generation`.
    pub fn new(generation: u64) -> Self {
        Self {
            generation,
            blocks: Vec::new(),
        }
    }

    /// The current generation anchor.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Set the generation anchor, refusing to regress it (monotonic).
    ///
    /// This is the write-side hardening: a caller may only ever move the
    /// generation forward. A lower-or-equal candidate is rejected as a
    /// rollback.
    pub fn ensure_can_advance(&mut self, generation: u64) -> Result<()> {
        if generation <= self.generation {
            return Err(FormatError::Rollback {
                got: generation,
                expected: self.generation + 1,
            });
        }
        self.generation = generation;
        Ok(())
    }

    /// Record `version` + `refs` for `file_id`, inserting or replacing the
    /// existing entry.
    pub fn record(&mut self, file_id: &str, version: u64, refs: Vec<ChunkRef>) -> Result<()> {
        let entry = BlockVersion { version, refs };
        match self.blocks.iter_mut().find(|(id, _)| id == file_id) {
            Some((_, v)) => *v = entry,
            None => self.blocks.push((file_id.to_string(), entry)),
        }
        Ok(())
    }

    /// Look up the recorded block version for `file_id`.
    pub fn get(&self, file_id: &str) -> Option<&BlockVersion> {
        self.blocks
            .iter()
            .find(|(id, _)| id == file_id)
            .map(|(_, v)| v)
    }

    /// Iterate over `(file_id, block_version)` pairs.
    pub fn blocks(&self) -> impl Iterator<Item = (&str, &BlockVersion)> {
        self.blocks.iter().map(|(id, v)| (id.as_str(), v))
    }

    /// Compute the HMAC-SHA512 over `body` with the integrity subkey for
    /// `master`.
    fn compute_mac(body: &[u8], master: &[u8]) -> Result<[u8; HMAC_LEN]> {
        let subkey = integrity_subkey(master);
        let mut mac = HmacSha512::new_from_slice(subkey.as_ref()).map_err(|_| FormatError::Hmac)?;
        mac.update(body);
        let tag = mac.finalize().into_bytes();
        let mut out = [0u8; HMAC_LEN];
        out.copy_from_slice(&tag);
        Ok(out)
    }

    /// Serialize the store as `body || HMAC-SHA512(body)`.
    pub fn serialize(&self, master: &[u8]) -> Result<Vec<u8>> {
        let body = self.serialize_body();
        let mac = Self::compute_mac(&body, master)?;
        let mut out = Vec::with_capacity(body.len() + HMAC_LEN);
        out.extend_from_slice(&body);
        out.extend_from_slice(&mac);
        Ok(out)
    }

    /// Serialize only the authenticated body (no trailer).
    fn serialize_body(&self) -> Vec<u8> {
        let capacity = 8
            + 8
            + self
                .blocks
                .iter()
                .map(|(id, bv)| 8 + id.len() + 8 + 8 + bv.refs.len() * (8 + 4))
                .sum::<usize>();
        let mut buf = Vec::with_capacity(capacity);
        buf.extend_from_slice(&self.generation.to_le_bytes());
        buf.extend_from_slice(&(self.blocks.len() as u64).to_le_bytes());
        for (id, bv) in &self.blocks {
            buf.extend_from_slice(&(id.len() as u64).to_le_bytes());
            buf.extend_from_slice(id.as_bytes());
            buf.extend_from_slice(&bv.version.to_le_bytes());
            buf.extend_from_slice(&(bv.refs.len() as u64).to_le_bytes());
            for r in &bv.refs {
                buf.extend_from_slice(&r.offset.to_le_bytes());
                buf.extend_from_slice(&r.len.to_le_bytes());
            }
        }
        buf
    }

    /// Parse and authenticate an integrity store as produced by
    /// [`IntegrityBlockStore::serialize`].
    pub fn parse(master: &[u8], bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HMAC_LEN {
            return Err(FormatError::InvalidLength {
                what: "integrity store",
                expected: HMAC_LEN,
                got: bytes.len(),
            });
        }
        let (body, trailer) = bytes.split_at(bytes.len() - HMAC_LEN);
        let expected = Self::compute_mac(body, master)?;
        if !bool::from(expected.ct_eq(trailer)) {
            return Err(FormatError::Hmac);
        }
        Self::parse_body(body)
    }

    /// Parse and authenticate the store, then enforce the rollback anchor: the
    /// parsed generation must be at least `min_generation`, or the store is
    /// rejected as a replayed/old snapshot.
    pub fn parse_verified(master: &[u8], bytes: &[u8], min_generation: u64) -> Result<Self> {
        let store = Self::parse(master, bytes)?;
        if store.generation < min_generation {
            return Err(FormatError::Rollback {
                got: store.generation,
                expected: min_generation,
            });
        }
        Ok(store)
    }

    /// Decode the authenticated body into a store.
    fn parse_body(mut body: &[u8]) -> Result<Self> {
        let read_u64 = |b: &mut &[u8]| -> Result<u64> {
            if b.len() < 8 {
                return Err(FormatError::InvalidLength {
                    what: "integrity store body",
                    expected: 8,
                    got: b.len(),
                });
            }
            let v = u64::from_le_bytes(b[..8].try_into().unwrap());
            *b = &b[8..];
            Ok(v)
        };

        let generation = read_u64(&mut body)?;
        let file_count = read_u64(&mut body)?;
        let mut blocks = Vec::with_capacity(file_count.min(4096) as usize);
        for _ in 0..file_count {
            let id_len = read_u64(&mut body)? as usize;
            if body.len() < id_len {
                return Err(FormatError::InvalidLength {
                    what: "file id",
                    expected: id_len,
                    got: body.len(),
                });
            }
            let id = String::from_utf8_lossy(&body[..id_len]).into_owned();
            body = &body[id_len..];

            let version = read_u64(&mut body)?;
            let ref_count = read_u64(&mut body)?;
            let mut refs = Vec::with_capacity(ref_count.min(1_000_000) as usize);
            for _ in 0..ref_count {
                if body.len() < 12 {
                    return Err(FormatError::InvalidLength {
                        what: "chunk ref",
                        expected: 12,
                        got: body.len(),
                    });
                }
                let offset = u64::from_le_bytes(body[..8].try_into().unwrap());
                let len = u32::from_le_bytes(body[8..12].try_into().unwrap());
                body = &body[12..];
                refs.push(ChunkRef { offset, len });
            }
            blocks.push((id, BlockVersion { version, refs }));
        }

        Ok(Self { generation, blocks })
    }
}

/// Derive the 32-byte integrity subkey from `master`.
fn integrity_subkey(master: &[u8]) -> Zeroizing<[u8; 32]> {
    autocipher_core::subkeys::derive_subkey(master, INTEGRITY_PURPOSE, b"", 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASTER: &[u8] = b"0123456789abcdef0123456789abcdef";

    fn refs(offsets: &[u64]) -> Vec<ChunkRef> {
        offsets
            .iter()
            .map(|&o| ChunkRef {
                offset: o,
                len: 1024,
            })
            .collect()
    }

    fn sample_store() -> IntegrityBlockStore {
        let mut store = IntegrityBlockStore::new(7);
        store.record("file-a", 5, refs(&[8192, 9216])).unwrap();
        store.record("file-b", 5, refs(&[10240])).unwrap();
        store
    }

    #[test]
    fn integrity_binary_roundtrip() {
        let store = sample_store();
        let bytes = store.serialize(MASTER).unwrap();
        let parsed = IntegrityBlockStore::parse(MASTER, &bytes).unwrap();
        assert_eq!(parsed, store);
    }

    #[test]
    fn integrity_empty_roundtrip() {
        let store = IntegrityBlockStore::new(0);
        let bytes = store.serialize(MASTER).unwrap();
        let parsed = IntegrityBlockStore::parse(MASTER, &bytes).unwrap();
        assert_eq!(parsed, store);
        assert_eq!(parsed.generation(), 0);
    }

    #[test]
    fn integrity_get_and_record_versions() {
        let store = sample_store();
        assert_eq!(store.get("file-a").unwrap().version, 5);
        assert_eq!(store.get("file-a").unwrap().refs, refs(&[8192, 9216]));
        assert_eq!(store.get("file-b").unwrap().refs, refs(&[10240]));
        assert!(store.get("missing").is_none());

        // Re-recording updates the version and refs for the same file.
        let mut updated = store.clone();
        updated.record("file-a", 6, refs(&[12000, 13000])).unwrap();
        assert_eq!(updated.get("file-a").unwrap().version, 6);
        assert_eq!(updated.get("file-a").unwrap().refs, refs(&[12000, 13000]));
        assert_eq!(updated.blocks().count(), 2);
    }

    #[test]
    fn integrity_tamper_fails() {
        let store = sample_store();
        let mut bytes = store.serialize(MASTER).unwrap();
        // Flip a byte in the body (before the trailer).
        bytes[4] ^= 0x01;
        assert!(matches!(
            IntegrityBlockStore::parse(MASTER, &bytes),
            Err(FormatError::Hmac)
        ));
    }

    #[test]
    fn integrity_tamper_in_trailer_fails() {
        let store = sample_store();
        let mut bytes = store.serialize(MASTER).unwrap();
        let last = bytes.last_mut().unwrap();
        *last ^= 0x01;
        assert!(IntegrityBlockStore::parse(MASTER, &bytes).is_err());
    }

    #[test]
    fn integrity_wrong_key_fails() {
        let store = sample_store();
        let bytes = store.serialize(MASTER).unwrap();
        let other = b"ffffffffffffffffffffffffffffffff";
        assert!(IntegrityBlockStore::parse(other, &bytes).is_err());
    }

    #[test]
    fn integrity_short_buffer_rejected() {
        assert!(matches!(
            IntegrityBlockStore::parse(MASTER, &[0u8; 4]),
            Err(FormatError::InvalidLength { .. })
        ));
    }

    #[test]
    fn integrity_rollback_detected_via_anchor() {
        // Store written at generation 7.
        let store = sample_store();
        let bytes = store.serialize(MASTER).unwrap();

        // Reading with a higher expected anchor => replayed/old generation.
        let replayed = IntegrityBlockStore::parse_verified(MASTER, &bytes, 7 + 1).unwrap_err();
        assert!(matches!(replayed, FormatError::Rollback { got: 7, .. }));

        // Reading with an anchor <= stored generation is fine.
        let ok = IntegrityBlockStore::parse_verified(MASTER, &bytes, 7).unwrap();
        assert_eq!(ok.generation(), 7);
        let ok = IntegrityBlockStore::parse_verified(MASTER, &bytes, 3).unwrap();
        assert_eq!(ok.generation(), 7);
    }

    #[test]
    fn integrity_non_monotonic_advance_rejected() {
        let mut store = sample_store(); // generation 7
        assert!(store.ensure_can_advance(8).is_ok());
        assert_eq!(store.generation(), 8);
        // Regression is rejected.
        assert!(matches!(
            store.ensure_can_advance(8),
            Err(FormatError::Rollback { .. })
        ));
        assert!(matches!(
            store.ensure_can_advance(7),
            Err(FormatError::Rollback { .. })
        ));
        assert_eq!(store.generation(), 8);
    }
}
