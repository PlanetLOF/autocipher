//! autocipher-format
//!
//! On-disk `.ac` container I/O: format constants, the 8 KiB authenticated
//! header (magic, version, KDF params, salt, wrapped key, HMAC-SHA512 trailer),
//! the sealed vault manifest, fixed 64 KiB streaming chunk I/O, an
//! HMAC-integrity block store with rollback anchors, mirroring, auto-restore,
//! and the public [`Vault`] API.
//!
//! # On-disk layout
//!
//! ```text
//! [ 0 .. 16384       ]  Header region (two 8 KiB slots; one active)
//! [ 16384 .. meta_off]  File-data area (64 KiB chunked AEAD, append-only)
//! [ meta_off .. EOF  ]  Active metadata region: sealed manifest + integrity store
//! ```
//!
//! Mutating operations run under a serial append-only model: files that are not
//! touched keep their sealed chunks byte-for-byte at their original offsets and
//! with their original per-file generation; only new/overwritten data is
//! appended after the existing data area. A fresh *unified* metadata region
//! (old + new file refs) is appended at EOF and the inactive header slot is
//! atomically flipped to point at it. Older metadata regions become
//! unreferenced garbage. When the garbage ratio exceeds the configured
//! threshold (default [`DEFAULT_AUTO_COMPACT_RATIO`], settable per vault with
//! [`Vault::set_auto_compact_ratio`]), a mutation automatically rebuilds the
//! container via [`Vault::compact`] to reclaim the space.

use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rand::Rng;
use zeroize::Zeroizing;

use autocipher_core::filename::NameKey;
use autocipher_core::kdf::{self, KdfParams};
use autocipher_core::keywrap;
use autocipher_core::subkeys::derive_subkey;

use crate::metadata::{parse_metadata, serialize_metadata};

pub mod chunking;
pub mod constants;
pub mod error;
pub mod header;
pub mod integrity;
pub mod manifest;
pub mod metadata;
pub mod mirror;
pub mod recover;

pub use chunking::{ChunkReader, ChunkWriter, read_stream, write_stream};
pub use constants::*;
pub use error::{FormatError, Result};
pub use header::{Header, derive_header_key};
pub use integrity::{BlockVersion, IntegrityBlockStore};
pub use manifest::{ChunkRef, FileMeta, VaultManifest, decrypt_manifest, encrypt_manifest};
pub use metadata::{MAX_CHUNKS_PER_FILE, MAX_FILES, MAX_METADATA_SIZE};
pub use mirror::{read_mirrors, write_mirrors};
pub use recover::restore_if_needed;

/// The minimum vault generation anchor accepted on open. Fresh containers start
/// at this generation; anything older is rejected as a replayed rollback.
const MIN_VAULT_GENERATION: u64 = 1;

/// HKDF purpose tag for the filename subkey (matches autocipher-core).
const FILENAME_PURPOSE: &[u8] = b"filename";

/// Domain tag bound into encrypted file names (also used by autocipher-core).
const NAME_AAD: &[u8] = b"autocipher:filename:v1";

/// Plaintext metadata for one file in a vault listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredFileInfo {
    /// Decrypted stored name, including any folder prefixes.
    pub name: String,
    /// Plaintext file size in bytes.
    pub size: u64,
    /// Vault-operation creation timestamp in seconds; `0` means unknown.
    pub created_at: u64,
    /// Vault-operation modification timestamp in seconds; `0` means unknown.
    pub modified_at: u64,
    /// Sum of the sealed chunk lengths referenced by this file.
    ///
    /// This is logical encrypted-storage accounting. A structural recovery can
    /// retain these references even when the primary content bytes are not
    /// available for extraction.
    pub storage_used: u64,
}

/// The public `.ac` vault handle.
///
/// [`Vault::create`] builds a new container; [`Vault::open`] unlocks and loads
/// one (auto-restoring from mirrors if the primary is lost). Mutating operations
/// rebuild the container in a single streaming pass (append new data, then
/// atomically flip the inactive header slot) and update the sidecar mirrors.
/// The rebuild never buffers the whole vault in memory, so peak memory stays
/// bounded regardless of vault size.
pub struct Vault {
    path: PathBuf,
    header_bytes: Vec<u8>,
    active_slot: u8,
    inactive_header_bytes: Vec<u8>,
    kdf_params: KdfParams,
    master: Zeroizing<[u8; 32]>,
    name_key: NameKey,
    manifest: VaultManifest,
    store: IntegrityBlockStore,
    data_off: u64,
    compact_ratio: Option<f64>,
}

impl Vault {
    /// Create a new empty vault at `path`, unlocked with `password` using the
    /// given Argon2id cost `params`.
    ///
    /// Generates a fresh salt and master key, wraps the master under the KEK
    /// derived from `password`, writes the authenticated header and an empty
    /// metadata region, and writes the sidecar mirrors. The primary and mirrors
    /// are written atomically (fsync + rename).
    pub fn create(path: impl AsRef<Path>, password: &[u8], params: KdfParams) -> Result<Vault> {
        let path = path.as_ref().to_path_buf();

        let mut salt = [0u8; SALT_LEN];
        rand::rng().fill_bytes(&mut salt);
        let master = keywrap::generate_master_key();

        let kek = kdf::derive_kek(password, &salt, params.memory, params.t, params.p)?;
        let wrapped_key = keywrap::wrap(kek.as_ref(), master.as_ref())?;

        let header = Header {
            magic: *MAGIC,
            version: VERSION,
            kdf_params: params,
            salt,
            wrapped_key: wrapped_key.clone(),
            active_slot: 0,
            metadata_offset: HEADER_REGION_SIZE as u64,
            data_offset: HEADER_REGION_SIZE as u64,
            hmac: [0u8; 64],
        };
        let header_key = derive_header_key(master.as_ref());
        let header_bytes = header.serialize(header_key.as_ref())?.to_vec();

        // The inactive slot is zeroed with the magic set, so it is distinguishable
        // from the active slot but never mistaken for valid.
        let mut inactive = [0u8; HEADER_SIZE];
        inactive[..MAGIC.len()].copy_from_slice(MAGIC);
        let inactive_header_bytes = inactive.to_vec();

        let store = IntegrityBlockStore::new(MIN_VAULT_GENERATION);
        let manifest = VaultManifest::default();
        let metadata = serialize_metadata(master.as_ref(), &manifest, &store)?;
        let data_off = header.data_offset + metadata.len() as u64;

        atomic_write_to(&path, |f| {
            f.write_all(&header_bytes)?;
            f.write_all(&inactive)?;
            f.write_all(&metadata)?;
            Ok(())
        })?;
        write_mirrors(&path, &header_bytes, &metadata)?;

        let name_key = name_key_from_master(master.as_ref());

        Ok(Vault {
            path,
            header_bytes,
            active_slot: 0,
            inactive_header_bytes,
            kdf_params: params,
            master,
            name_key,
            manifest,
            store,
            data_off,
            compact_ratio: Some(DEFAULT_AUTO_COMPACT_RATIO),
        })
    }

    /// Open and unlock an existing vault at `path` with `password`.
    ///
    /// Auto-restores the primary from its mirrors if it is missing or unusable
    /// ([`restore_if_needed`]). A wrong password or a tampered header fails the
    /// header HMAC / key unwrap. Enforces the DoS ceilings on metadata size and
    /// chunk counts, and the minimum generation (rollback) anchor.
    pub fn open(path: impl AsRef<Path>, password: &[u8]) -> Result<Vault> {
        let path = path.as_ref().to_path_buf();

        restore_if_needed(&path)?;

        let file_len = std::fs::metadata(&path)?.len();
        if file_len < HEADER_REGION_SIZE as u64 {
            return Err(FormatError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "container shorter than the two-slot header region",
            )));
        }

        // Read both header slots.
        let region = read_range_file(&path, 0, HEADER_REGION_SIZE)?;
        let (slot0, slot1) = region.split_at(HEADER_SIZE);

        // Parse both raw (unverified) to find the master/key. An invalidated
        // (stale) slot is magic + zeros, so its offsets read as 0 and it is
        // excluded here; the unwrap candidate must have a plausible layout.
        let raw0 = Header::parse_raw(slot0).ok();
        let raw1 = Header::parse_raw(slot1).ok();
        let usable = |h: &Header| {
            h.magic == *MAGIC
                && h.metadata_offset >= HEADER_REGION_SIZE as u64
                && h.data_offset >= HEADER_REGION_SIZE as u64
        };

        // Pick a candidate to unwrap the master.
        let raw = match (raw0.as_ref(), raw1.as_ref()) {
            (Some(a), _) if usable(a) => a.clone(),
            (_, Some(b)) if usable(b) => b.clone(),
            (Some(a), _) if &a.magic == MAGIC => a.clone(),
            (_, Some(b)) if &b.magic == MAGIC => b.clone(),
            _ => {
                return Err(FormatError::InvalidLength {
                    what: "magic",
                    expected: MAGIC.len(),
                    got: 0,
                });
            }
        };

        // Derive the KEK and unwrap the master. A wrong password fails here.
        let kek = kdf::derive_kek(
            password,
            &raw.salt,
            raw.kdf_params.memory,
            raw.kdf_params.t,
            raw.kdf_params.p,
        )?;
        let master = keywrap::unwrap(kek.as_ref(), &raw.wrapped_key)?;

        // Now that the master is known, authenticate both slots.
        let header_key = derive_header_key(master.as_ref());
        let verified0 = Header::parse(slot0, header_key.as_ref());
        let verified1 = Header::parse(slot1, header_key.as_ref());

        // Pick the valid slot with the highest data offset (most recent layout).
        let (active_slot, header_bytes) = match (verified0, verified1) {
            (Ok(h0), Ok(h1)) => {
                if h0.data_offset >= h1.data_offset {
                    (h0.active_slot, slot0.to_vec())
                } else {
                    (h1.active_slot, slot1.to_vec())
                }
            }
            (Ok(h0), Err(_)) => (h0.active_slot, slot0.to_vec()),
            (Err(_), Ok(h1)) => (h1.active_slot, slot1.to_vec()),
            (Err(_), Err(_)) => {
                return Err(FormatError::Hmac);
            }
        };

        let active_header = Header::parse(&header_bytes, header_key.as_ref())?;

        // Read metadata at the active header's recorded offset, bounded by the
        // DoS ceiling on metadata size.
        let meta_off = active_header.metadata_offset;
        if meta_off < HEADER_REGION_SIZE as u64 || meta_off >= file_len {
            return Err(FormatError::InvalidLength {
                what: "metadata offset",
                expected: HEADER_REGION_SIZE,
                got: meta_off as usize,
            });
        }
        let read_len = ((file_len - meta_off).min(MAX_METADATA_SIZE as u64)) as usize;
        let raw_meta = read_range_file(&path, meta_off, read_len)?;
        let (manifest, store, _meta_len) =
            parse_metadata(master.as_ref(), &raw_meta, MIN_VAULT_GENERATION)?;

        let name_key = name_key_from_master(master.as_ref());

        // Remember the inactive slot contents for the next header flip.
        let inactive_header_bytes = match active_slot {
            0 => slot1.to_vec(),
            _ => slot0.to_vec(),
        };

        Ok(Vault {
            path,
            header_bytes,
            active_slot,
            inactive_header_bytes,
            kdf_params: active_header.kdf_params,
            master,
            name_key,
            manifest,
            store,
            data_off: active_header.data_offset,
            compact_ratio: Some(DEFAULT_AUTO_COMPACT_RATIO),
        })
    }

    /// The raw path of the primary container.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Re-write the mirror files beside the primary, copying the current active
    /// header and metadata regions verbatim. Useful when the mirrors were
    /// deleted or not copied together with the container: the vault keeps
    /// working from the primary either way, but this restores the crash-recovery
    /// safety net provided by [`crate::recover::restore_if_needed`]. The metadata
    /// is read from the primary at the offset recorded in the active header, so
    /// this never relies on the old mirrors' content.
    pub fn remirror(&self) -> Result<()> {
        let header = Header::parse_raw(&self.header_bytes)?;
        let meta_off = header.metadata_offset;
        let file_len = std::fs::metadata(&self.path)?.len();
        let read_len = file_len.saturating_sub(meta_off) as usize;
        let metadata = read_range_file(&self.path, meta_off, read_len)?;
        write_mirrors(&self.path, &self.header_bytes, &metadata)?;
        Ok(())
    }

    /// The kdf parameters recorded in the header.
    pub fn kdf_params(&self) -> KdfParams {
        self.kdf_params
    }

    /// The current vault-level generation anchor.
    pub fn generation(&self) -> u64 {
        self.store.generation()
    }

    /// Decrypt and list the plaintext file names currently stored in the vault.
    pub fn list(&self) -> Result<Vec<String>> {
        Ok(self
            .list_file_info()?
            .into_iter()
            .map(|info| info.name)
            .collect())
    }

    /// List file metadata, including native vault-operation timestamps and
    /// encrypted storage use.
    ///
    /// `storage_used` is the sum of the sealed chunk lengths referenced by the
    /// file; it excludes the manifest and integrity-store overhead. It remains
    /// a logical metadata value after structural recovery when the original
    /// content bytes are unavailable. Timestamps are Unix seconds and remain
    /// `0` for entries loaded from legacy manifests.
    pub fn list_file_info(&self) -> Result<Vec<StoredFileInfo>> {
        self.manifest
            .files
            .iter()
            .map(|meta| {
                let dec = self
                    .name_key
                    .decrypt_name(&meta.name_enc, NAME_AAD)
                    .map_err(FormatError::Crypto)?;
                let name = String::from_utf8(dec.to_vec()).map_err(|e| {
                    FormatError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
                })?;
                Ok(StoredFileInfo {
                    name,
                    size: meta.size,
                    created_at: meta.created_at,
                    modified_at: meta.modified_at,
                    storage_used: meta.chunks.iter().map(|chunk| u64::from(chunk.len)).sum(),
                })
            })
            .collect()
    }

    /// Encrypt and add the plaintext file at `src` to the vault under its base
    /// filename, then durably persist the updated container.
    ///
    /// The container is rebuilt in a single streaming pass (never buffering the
    /// whole vault in memory), so peak memory stays bounded regardless of vault
    /// size.
    pub fn add_file(&mut self, src: impl AsRef<Path>) -> Result<String> {
        let src = src.as_ref();
        let name = src
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| {
                FormatError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "file has no valid name",
                ))
            })?
            .to_string();
        self.add_file_as(src, &name)?;
        Ok(name)
    }

    /// Encrypt and add the plaintext file at `src` to the vault under the
    /// explicit stored name `name` (which may be a relative subpath like
    /// `photos/beach/1.jpg`), then durably persist the updated container.
    ///
    /// Identical to [`Vault::add_file`] except the stored name is caller-chosen
    /// rather than the file's basename; this is what allows a directory import
    /// to preserve folder structure. The plaintext is streamed from disk in a
    /// single pass, so peak memory stays bounded regardless of file size.
    pub fn add_file_as(&mut self, src: impl AsRef<Path>, name: &str) -> Result<()> {
        if name.is_empty() {
            return Err(FormatError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "stored name cannot be empty",
            )));
        }
        let src = src.as_ref().to_path_buf();

        let size = std::fs::metadata(&src)?.len();
        let now = now_unix_seconds();
        let id = new_file_id();
        let name_enc = self
            .name_key
            .encrypt_name(name.as_bytes(), NAME_AAD)
            .map_err(FormatError::Crypto)?;

        let mut plan = self.surviving_plan();
        plan.push(PlannedFile {
            id,
            name_enc,
            size,
            created_at: now,
            modified_at: now,
            src: FileSource::Path(src),
        });
        self.commit_plan(plan)
    }

    /// Encrypt and add many files in a single commit, each under its explicit
    /// stored name (which may be a relative subpath like `photos/beach/1.jpg`).
    ///
    /// This is the batch counterpart of [`Vault::add_file_as`] used by folder
    /// imports: all `items` are planned and committed together, so the metadata
    /// region is serialized exactly once instead of once per file (folder import
    /// of `n` files is then one metadata rewrite, not `n`). Walks are atomic: the
    /// layout pass runs before any bytes are written, so a failure — including a
    /// [`FormatError::MetadataTooLarge`] — aborts with the container completely
    /// untouched and no partially-imported files. A stored name that already
    /// exists is overwritten in place (preserving its file id), mirroring
    /// [`Vault::put`], so re-importing a folder is idempotent rather than
    /// duplicating entries. Returns the number of items added or overwritten.
    pub fn add_paths(&mut self, items: &[(std::path::PathBuf, String)]) -> Result<usize> {
        let mut plan = self.surviving_plan();
        let now = now_unix_seconds();
        let mut added = 0usize;
        for (src, name) in items {
            if name.is_empty() {
                return Err(FormatError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "stored name cannot be empty",
                )));
            }
            let size = std::fs::metadata(src)?.len();
            match plan
                .iter_mut()
                .find(|p| self.name_equals(&p.name_enc, name))
            {
                Some(p) => {
                    p.size = size;
                    p.modified_at = now;
                    p.src = FileSource::Path(src.clone());
                }
                None => {
                    let id = new_file_id();
                    let name_enc = self
                        .name_key
                        .encrypt_name(name.as_bytes(), NAME_AAD)
                        .map_err(FormatError::Crypto)?;
                    plan.push(PlannedFile {
                        id,
                        name_enc,
                        size,
                        created_at: now,
                        modified_at: now,
                        src: FileSource::Path(src.clone()),
                    });
                }
            }
            added += 1;
        }
        if added == 0 {
            return Ok(0);
        }
        self.commit_plan(plan)?;
        Ok(added)
    }

    /// Extract the file named `name` to the destination path `dest`.
    ///
    /// Fails cleanly if the file is not present or if any chunk fails to
    /// authenticate (e.g. a corrupt chunk).
    pub fn extract(&self, name: &str, dest: impl AsRef<Path>) -> Result<()> {
        let meta = self.find_by_name(name)?;
        let generation = self.generation_for(&meta.id).to_le_bytes();

        let mut primary = open_primary(&self.path)?;
        let mut reader = ChunkReader::new(
            &mut primary,
            self.master.as_ref(),
            meta.id.as_bytes(),
            &generation,
        );
        let mut out = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(dest.as_ref())?;
        read_stream(&mut reader, &meta.chunks, &mut out)?;
        out.sync_all()?;
        Ok(())
    }

    /// Read the file named `name` into memory.
    ///
    /// Fails cleanly if the file is not present or any chunk fails to
    /// authenticate.
    pub fn get(&self, name: &str) -> Result<Vec<u8>> {
        let meta = self.find_by_name(name)?;
        let generation = self.generation_for(&meta.id).to_le_bytes();

        let mut primary = open_primary(&self.path)?;
        let mut reader = ChunkReader::new(
            &mut primary,
            self.master.as_ref(),
            meta.id.as_bytes(),
            &generation,
        );
        let mut buf = Vec::with_capacity(meta.size as usize);
        read_stream(&mut reader, &meta.chunks, &mut buf)?;
        Ok(buf)
    }

    /// The plaintext size in bytes of the file named `name`.
    pub fn size(&self, name: &str) -> Result<u64> {
        Ok(self.find_by_name(name)?.size)
    }

    /// Read `len` bytes of the file named `name` starting at `offset`, decrypting
    /// only the chunks that intersect the requested range.
    ///
    /// This is the chunk-level primitive behind streaming VFS reads: it never
    /// decrypts the whole file, so reading a small window of a huge stored file
    /// touches only the (at most two) 64 KiB chunks that overlap it. A range that
    /// lies wholly past EOF returns an empty slice. Each returned byte is
    /// authenticated by the chunk AEAD before it is handed out.
    ///
    /// Returns `(bytes, absolute_end_offset)`; `bytes` is exactly the requested
    /// window (clamped to EOF), and `absolute_end_offset` is the plaintext offset
    /// just past the last byte returned, which lets callers detect truncation.
    pub fn read_range(&self, name: &str, offset: u64, len: u64) -> Result<(Vec<u8>, u64)> {
        let meta = self.find_by_name(name)?;
        if offset >= meta.size {
            return Ok((Vec::new(), meta.size));
        }
        let end = (offset.saturating_add(len)).min(meta.size);
        let n = (end - offset) as usize;

        let generation = self.generation_for(&meta.id).to_le_bytes();
        let mut primary = open_primary(&self.path)?;
        let mut reader = ChunkReader::new(
            &mut primary,
            self.master.as_ref(),
            meta.id.as_bytes(),
            &generation,
        );

        let first_chunk = (offset / autocipher_core::content::CHUNK_SIZE as u64) as usize;
        let last_chunk = ((end - 1) / autocipher_core::content::CHUNK_SIZE as u64) as usize;

        let mut out = Vec::with_capacity(n);
        for (idx, chunk) in meta.chunks.iter().enumerate().take(last_chunk + 1) {
            if idx < first_chunk {
                continue;
            }
            let mut plain = Vec::new();
            reader.read_chunk(chunk, idx as u64, &mut plain)?;
            let chunk_start = (idx as u64) * autocipher_core::content::CHUNK_SIZE as u64;
            let chunk_end = (chunk_start + plain.len() as u64).min(meta.size);
            if offset < chunk_end && end > chunk_start {
                let rel_start = offset.saturating_sub(chunk_start) as usize;
                let take = (end - chunk_start).min(plain.len() as u64) as usize;
                out.extend_from_slice(&plain[rel_start..take]);
            }
        }
        Ok((out, end))
    }

    /// Write `data` to the file named `name`, creating it if absent or
    /// overwriting its contents in place (preserving the file id), then
    /// durably persist the container.
    pub fn put(&mut self, name: &str, data: &[u8]) -> Result<()> {
        let mut plan = self.surviving_plan();
        let now = now_unix_seconds();
        match plan
            .iter_mut()
            .find(|p| self.name_equals(&p.name_enc, name))
        {
            Some(p) => {
                p.size = data.len() as u64;
                p.modified_at = now;
                p.src = FileSource::Bytes(data.to_vec());
            }
            None => {
                let id = new_file_id();
                let name_enc = self
                    .name_key
                    .encrypt_name(name.as_bytes(), NAME_AAD)
                    .map_err(FormatError::Crypto)?;
                plan.push(PlannedFile {
                    id,
                    name_enc,
                    size: data.len() as u64,
                    created_at: now,
                    modified_at: now,
                    src: FileSource::Bytes(data.to_vec()),
                });
            }
        }
        self.commit_plan(plan)
    }

    /// Delete the file named `name`, then durably persist the container.
    pub fn delete(&mut self, name: &str) -> Result<()> {
        let before = self.manifest.files.len();
        let plan: Vec<PlannedFile> = self
            .manifest
            .files
            .iter()
            .filter(|meta| !self.name_equals(&meta.name_enc, name))
            .map(|meta| PlannedFile {
                id: meta.id.clone(),
                name_enc: meta.name_enc.clone(),
                size: meta.size,
                created_at: meta.created_at,
                modified_at: meta.modified_at,
                src: FileSource::Container {
                    chunks: meta.chunks.clone(),
                },
            })
            .collect();
        if plan.len() == before {
            return Err(FormatError::NotFound(name.to_string()));
        }
        self.commit_plan(plan)
    }

    /// Rename the file `old` to `new`, then durably persist the container.
    ///
    /// The file id (and thus its chunk encryption bindings) is preserved; only
    /// the encrypted name is replaced.
    pub fn rename(&mut self, old: &str, new: &str) -> Result<()> {
        let name_enc = self
            .name_key
            .encrypt_name(new.as_bytes(), NAME_AAD)
            .map_err(FormatError::Crypto)?;

        let now = now_unix_seconds();
        let mut plan = self.surviving_plan();
        let mut found = false;
        for p in plan.iter_mut() {
            if self.name_equals(&p.name_enc, old) {
                p.name_enc = name_enc.clone();
                p.modified_at = now;
                found = true;
                break;
            }
        }
        if !found {
            return Err(FormatError::NotFound(old.to_string()));
        }
        self.commit_plan(plan)
    }

    /// Rewrite the whole container from the current manifest, garbage-collecting
    /// any stale/freed data and re-sealing all content under a fresh generation.
    ///
    /// Unlike the in-place mutations, compaction rebuilds into a sibling temp
    /// file and atomically renames it over the primary. This is the only way to
    /// physically reclaim the space freed by deleted/overwritten data while
    /// staying crash-safe (a shrink can never overwrite live data in place).
    /// The rebuild streams one 64 KiB chunk at a time, so peak memory stays
    /// bounded regardless of vault size.
    pub fn compact(&mut self) -> Result<()> {
        let files = self.surviving_plan();

        let generation = self.store.generation() + 1;
        self.store.ensure_can_advance(generation)?;
        let gen_le = generation.to_le_bytes();

        // Pass 1 — layout only (no I/O), with the compacted container starting
        // immediately after the header region.
        let (metadata, new_manifest, new_store, data_off) = plan_layout(
            self.master.as_ref(),
            &files,
            generation,
            HEADER_REGION_SIZE as u64,
        )?;

        // Build a fresh header (slot 0) pointing at the compacted layout,
        // reusing the active header's salt + wrapped key + KDF params.
        let header_bytes =
            self.build_header_bytes_for_slot(0, HEADER_REGION_SIZE as u64, data_off)?;

        // Pass 2 — stream the data area into a sibling temp file.
        let mut tmp = self.path.as_os_str().to_owned();
        tmp.push(".compact.tmp");
        let tmp = PathBuf::from(tmp);
        let write_result = (|| -> Result<()> {
            let mut src = open_primary(&self.path)?;
            let mut out = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&tmp)?;
            out.write_all(&header_bytes)?;
            let pad = HEADER_REGION_SIZE - header_bytes.len();
            out.write_all(&vec![0u8; pad])?;
            out.write_all(&metadata)?;

            let mut offset = data_off;
            for (fi, f) in files.iter().enumerate() {
                let planned = new_manifest.files[fi].chunks.clone();
                let mut writer = ChunkWriter::new(
                    &mut out,
                    self.master.as_ref(),
                    f.id.as_bytes(),
                    &gen_le,
                    offset,
                );
                let refs = match &f.src {
                    FileSource::Path(p) => {
                        let mut r = std::io::BufReader::new(std::fs::File::open(p)?);
                        write_stream(&mut writer, &mut r)?
                    }
                    FileSource::Bytes(bytes) => {
                        let mut c = std::io::Cursor::new(bytes.as_slice());
                        write_stream(&mut writer, &mut c)?
                    }
                    FileSource::Container { chunks, .. } => {
                        let read_gen = self.generation_for(&f.id).to_le_bytes();
                        let mut reader = ChunkReader::new(
                            &mut src,
                            self.master.as_ref(),
                            f.id.as_bytes(),
                            &read_gen,
                        );
                        reseal_stream(&mut reader, chunks, &mut writer, f.size)?
                    }
                };
                if refs != planned {
                    return Err(FormatError::Internal(
                        "regenerated chunk layout diverged from the metadata layout",
                    ));
                }
                offset = writer.offset();
            }
            out.sync_all()?;
            Ok(())
        })();
        if let Err(e) = write_result {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        std::fs::rename(&tmp, &self.path)?;

        // Re-mirror the fresh header + metadata.
        write_mirrors(&self.path, &header_bytes, &metadata)?;

        // Invalidate the (now stale) other slot by writing slot-magic garbage.
        pwrite_inactive_slot(&self.path, 0, &header_bytes)?;

        self.header_bytes = header_bytes;
        self.active_slot = 0;
        self.inactive_header_bytes = stale_slot_bytes();
        self.manifest = new_manifest;
        self.store = new_store;
        self.data_off = data_off;
        Ok(())
    }

    /// Re-wrap the master key under `new_password` and KDF `params`.
    ///
    /// Rebuilds the authenticated header with a fresh salt, the master key
    /// re-wrapped under a new KEK, and the header HMAC recomputed from the
    /// master key (which is unchanged). Only the 8 KiB active header slot is
    /// rewritten in place; the metadata region and all file data are preserved
    /// byte-for-byte with unchanged offsets, so the operation touches exactly
    /// one header slot and never buffers the vault. After this, the old
    /// password no longer unlocks the vault.
    pub fn change_password(&mut self, new_password: &[u8], params: KdfParams) -> Result<()> {
        let mut salt = [0u8; SALT_LEN];
        rand::rng().fill_bytes(&mut salt);
        let kek = kdf::derive_kek(new_password, &salt, params.memory, params.t, params.p)?;
        let wrapped_key = keywrap::wrap(kek.as_ref(), self.master.as_ref())?;

        let header = Header {
            magic: *MAGIC,
            version: VERSION,
            kdf_params: params,
            salt,
            wrapped_key,
            active_slot: self.active_slot,
            metadata_offset: self
                .current_metadata_offset()
                .unwrap_or(HEADER_REGION_SIZE as u64),
            data_offset: self.data_off,
            hmac: [0u8; HMAC_LEN],
        };
        let header_key = derive_header_key(self.master.as_ref());
        let new_header = header.serialize(header_key.as_ref())?.to_vec();

        // Overwrite the active slot in place with an 8 KiB pwrite.
        let active_off = Header::slot_offset(self.active_slot);
        pwrite_block(&self.path, active_off, &new_header)?;

        // Invalidate the inactive slot so the old password no longer unlocks the
        // vault and recovery never falls back to a stale pre-change header.
        pwrite_inactive_slot(&self.path, self.active_slot, &new_header)?;

        // The metadata region is unchanged; re-write its mirror using the
        // recorded metadata offset. The region is self-describing (two u64
        // length prefixes), so its exact extent is read from the framing rather
        // than derived from file geometry — the region sits at EOF in the
        // append-only layout but is followed by data in the legacy layout.
        let file_len = current_file_len(&self.path)?;
        let meta_off = header.metadata_offset;
        if meta_off >= file_len {
            return Err(FormatError::InvalidLength {
                what: "metadata offset",
                expected: HEADER_REGION_SIZE,
                got: meta_off as usize,
            });
        }
        let read_len = ((file_len - meta_off).min(MAX_METADATA_SIZE as u64)) as usize;
        let region = read_range_file(&self.path, meta_off, read_len)?;
        let meta_len = metadata_region_len(&region)?;
        let raw_meta = region[..meta_len].to_vec();
        write_mirrors(&self.path, &new_header, &raw_meta)?;

        self.header_bytes = new_header;
        self.kdf_params = params;
        Ok(())
    }

    // ---- internal helpers ----

    /// Build a rewrite plan holding every currently-manifested file, each
    /// sourced by streaming its existing chunks from the current container.
    fn surviving_plan(&self) -> Vec<PlannedFile> {
        self.manifest
            .files
            .iter()
            .map(|meta| PlannedFile {
                id: meta.id.clone(),
                name_enc: meta.name_enc.clone(),
                size: meta.size,
                created_at: meta.created_at,
                modified_at: meta.modified_at,
                src: FileSource::Container {
                    chunks: meta.chunks.clone(),
                },
            })
            .collect()
    }

    /// In-place mutation: append a unified metadata region + the *new* file data
    /// to the end of the container and atomically flip the inactive header slot.
    /// No temp file is used and the old header remains authoritative until the
    /// flip, so a crash mid-commit leaves the vault intact (the appended bytes
    /// become unreferenced garbage).
    ///
    /// Serial append-only model: files that survive the mutation unchanged
    /// (`FileSource::Container`) keep their existing sealed chunks byte-for-byte
    /// at their original offsets with their original per-file AEAD generation,
    /// so they are never re-read or re-written. Only new/overwritten files
    /// (`Path`/`Bytes`) are streamed, one 64 KiB chunk at a time, into the data
    /// area appended after the existing data. The metadata region is appended at
    /// EOF containing the *unified* manifest (old + new chunk refs) and a
    /// freshly sealed integrity store. Peak memory stays bounded by a few chunks
    /// plus the (small) manifest, regardless of vault size.
    ///
    /// After the commit, the garbage ratio is measured and, if it exceeds the
    /// configured [`set_auto_compact_ratio`](Vault::set_auto_compact_ratio)
    /// threshold, the container is automatically compacted. Compaction is
    /// best-effort: a failure leaves the mutation committed (the container is
    /// still valid, just with unreclaimed garbage) and is not surfaced as an
    /// error here.
    fn commit_plan(&mut self, files: Vec<PlannedFile>) -> Result<()> {
        // Snapshot the pre-mutation store so survivor files can keep their
        // original per-file AEAD generations (the `generation` anchor bumps for
        // rollback protection, but untouched bytes stay sealed under the old
        // generation and must be read with it).
        let previous = self.store.clone();
        let generation = previous.generation() + 1;
        self.store.ensure_can_advance(generation)?;
        let gen_le = generation.to_le_bytes();

        // The append position: the new data area starts right after everything
        // currently in the container, so the existing (survivor) bytes are never
        // disturbed.
        let append_off = current_file_len(&self.path)?;

        // Pass 1 — layout only, no I/O. The sealed-chunk length is deterministic
        // (nonce + plaintext + tag), so new-file chunk offsets depend only on
        // plaintext sizes; survivor refs are reused verbatim from the old
        // manifest. The unified metadata is appended after the new data, so its
        // length does not feed back into any chunk offset: no fixed-point loop.
        // A normal mutation upgrades a legacy v1 manifest to the current v2
        // shape so new and changed entries can carry timestamps. Operations
        // that leave metadata bytes untouched (for example password changes)
        // preserve the original manifest version.
        let mut new_manifest = VaultManifest::default();
        let mut new_store = IntegrityBlockStore::new(generation);
        let mut offset = append_off;
        for f in &files {
            let (refs, version) = match &f.src {
                FileSource::Container { chunks } => {
                    // Survivor: keep the exact refs and the original per-file
                    // AEAD generation the bytes were sealed under.
                    let version = previous
                        .get(&f.id)
                        .map(|b| b.version)
                        .unwrap_or(previous.generation());
                    (chunks.clone(), version)
                }
                FileSource::Path(_) | FileSource::Bytes(_) => {
                    let (refs, next) = layout_new_file_refs(offset, f.size);
                    offset = next;
                    (refs, generation)
                }
            };
            new_store.record(&f.id, version, refs.clone())?;
            new_manifest.files.push(FileMeta {
                id: f.id.clone(),
                name_enc: f.name_enc.clone(),
                size: f.size,
                created_at: f.created_at,
                modified_at: f.modified_at,
                chunks: refs,
            });
        }
        let metadata = serialize_metadata(self.master.as_ref(), &new_manifest, &new_store)?;
        // The unified metadata region is appended at EOF, directly after the new
        // data. `data_off` = start of the new data area; it strictly increases
        // across appends, so the "higher data_offset wins" slot selection on open
        // keeps resolving to the most recent layout.
        let meta_off = offset;
        let data_off = append_off;

        // Pass 2 — stream only the new/overwritten file data into the data area,
        // then append the unified metadata.
        let mut out = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        for (fi, f) in files.iter().enumerate() {
            let planned = new_manifest.files[fi].chunks.clone();
            if planned.is_empty() {
                // Zero-size file: no sealed chunks, nothing to stream.
                continue;
            }
            let start = planned[0].offset;
            let actual = match &f.src {
                FileSource::Path(p) => {
                    let mut writer = ChunkWriter::new(
                        &mut out,
                        self.master.as_ref(),
                        f.id.as_bytes(),
                        &gen_le,
                        start,
                    );
                    let mut r = std::io::BufReader::new(std::fs::File::open(p)?);
                    write_stream(&mut writer, &mut r)?
                }
                FileSource::Bytes(bytes) => {
                    let mut writer = ChunkWriter::new(
                        &mut out,
                        self.master.as_ref(),
                        f.id.as_bytes(),
                        &gen_le,
                        start,
                    );
                    let mut c = std::io::Cursor::new(bytes.as_slice());
                    write_stream(&mut writer, &mut c)?
                }
                FileSource::Container { .. } => {
                    // Survivor data is already in place; nothing is written here.
                    continue;
                }
            };
            // The streaming write must reproduce the planned refs exactly
            // (an internal invariant; sealed-chunk lengths are deterministic).
            if actual != planned {
                return Err(FormatError::Internal(
                    "streamed chunk layout diverged from the metadata layout",
                ));
            }
        }
        out.write_all(&metadata)?;
        out.sync_all()?;
        drop(out);

        // Write the position into the header: metadata_offset = meta_off,
        // data_offset = data_off.
        let inactive_slot = Header::inactive_slot(self.active_slot);
        let new_header_bytes =
            self.build_header_bytes_for_slot(inactive_slot, meta_off, data_off)?;

        // Atomically flip: overwrite the inactive slot with the new header.
        let slot_off = Header::slot_offset(inactive_slot);
        pwrite_block(&self.path, slot_off, &new_header_bytes)?;

        // Re-mirror the new header + metadata region.
        write_mirrors(&self.path, &new_header_bytes, &metadata)?;

        self.header_bytes = new_header_bytes;
        self.active_slot = inactive_slot;
        self.inactive_header_bytes = stale_slot_bytes();
        self.manifest = new_manifest;
        self.store = new_store;
        self.data_off = data_off;
        // Reclaim space when the mutation pushed the garbage ratio past the
        // configured threshold (best-effort; see auto_compact_if_needed).
        self.auto_compact_if_needed();
        Ok(())
    }

    /// Set the garbage-ratio threshold that triggers automatic compaction after
    /// each mutation. `None` disables auto-compaction; `Some(r)` compacts after
    /// a mutation whenever `garbage / container_size > r`. Values outside
    /// `(0, 1)` effectively disable the trigger, since the ratio is always
    /// below 1. The default is [`DEFAULT_AUTO_COMPACT_RATIO`].
    pub fn set_auto_compact_ratio(&mut self, ratio: Option<f64>) {
        self.compact_ratio = ratio;
    }

    /// The currently configured auto-compaction garbage-ratio threshold.
    /// `None` means auto-compaction is disabled; `Some(r)` compacts after a
    /// mutation whenever `garbage / container_size > r`. The default is
    /// [`DEFAULT_AUTO_COMPACT_RATIO`].
    pub fn auto_compact_ratio(&self) -> Option<f64> {
        self.compact_ratio
    }

    /// Bytes physically present in the container that are no longer referenced:
    /// stale metadata regions and freed/overwritten chunk data. These are
    /// reclaimed by [`Vault::compact`] (or automatically, see
    /// [`set_auto_compact_ratio`](Vault::set_auto_compact_ratio)).
    pub fn garbage_bytes(&self) -> Result<u64> {
        let file_len = current_file_len(&self.path)?;
        let overhead = HEADER_REGION_SIZE as u64;
        if file_len <= overhead {
            return Ok(0);
        }
        let live: u64 = self
            .manifest
            .files
            .iter()
            .map(|f| f.chunks.iter().map(|c| c.len as u64).sum::<u64>())
            .sum();
        Ok(file_len.saturating_sub(overhead + live + self.active_metadata_len()?))
    }

    /// The fraction of the container that is unreferenced garbage: `0.0` for a
    /// freshly created/compacted vault, approaching `1.0` as mutations pile up
    /// while data is deleted or overwritten.
    pub fn garbage_ratio(&self) -> Result<f64> {
        let file_len = current_file_len(&self.path)?;
        if file_len == 0 {
            return Ok(0.0);
        }
        Ok(self.garbage_bytes()? as f64 / file_len as f64)
    }

    /// Best-effort compaction after a successful mutation: when the garbage
    /// ratio exceeds the configured threshold, rebuild and reclaim the space.
    /// A rebuild failure is swallowed — the mutation already committed durably
    /// and the container stays valid (garbage collection is merely postponed).
    fn auto_compact_if_needed(&mut self) {
        let Some(threshold) = self.compact_ratio else {
            return;
        };
        let Ok(ratio) = self.garbage_ratio() else {
            return;
        };
        if ratio > threshold {
            let _ = self.compact();
        }
    }

    /// Byte length of the active metadata region, read from its self-describing
    /// framing at the header's metadata offset (bounded by `MAX_METADATA_SIZE`,
    /// so it works for both the append-only layout with metadata at EOF and the
    /// legacy layout with trailing data after the metadata).
    fn active_metadata_len(&self) -> Result<u64> {
        let Some(meta_off) = self.current_metadata_offset() else {
            return Ok(0);
        };
        let file_len = current_file_len(&self.path)?;
        if meta_off >= file_len {
            return Ok(0);
        }
        let read_len = ((file_len - meta_off).min(MAX_METADATA_SIZE as u64)) as usize;
        let region = read_range_file(&self.path, meta_off, read_len)?;
        Ok(metadata_region_len(&region).unwrap_or(0) as u64)
    }

    /// Decrypt the plaintext name of `enc` and compare it to `name`.
    fn name_equals(&self, enc: &Vec<u8>, name: &str) -> bool {
        self.name_key
            .decrypt_name(enc, NAME_AAD)
            .map(|d| d.as_slice() == name.as_bytes())
            .unwrap_or(false)
    }

    /// Find the [`FileMeta`] whose plaintext name is `name`.
    fn find_by_name(&self, name: &str) -> Result<&FileMeta> {
        for meta in &self.manifest.files {
            if self.name_equals(&meta.name_enc, name) {
                return Ok(meta);
            }
        }
        Err(FormatError::NotFound(name.to_string()))
    }

    /// The recorded content generation for `file_id` (defaults to the anchor).
    fn generation_for(&self, file_id: &str) -> u64 {
        self.store
            .get(file_id)
            .map(|b| b.version)
            .unwrap_or(self.store.generation())
    }

    /// The metadata offset recorded in the currently-active header.
    fn current_metadata_offset(&self) -> Option<u64> {
        Header::parse_raw(&self.header_bytes)
            .ok()
            .map(|h| h.metadata_offset)
    }

    /// Build a header for `slot` that references the given metadata/data
    /// offsets, reusing the active header's salt, wrapped key, and KDF params
    /// (the master is unchanged). The HMAC is recomputed from the master.
    fn build_header_bytes_for_slot(
        &self,
        slot: u8,
        metadata_offset: u64,
        data_offset: u64,
    ) -> Result<Vec<u8>> {
        let cur = Header::parse_raw(&self.header_bytes)?;

        let header = Header {
            magic: *MAGIC,
            version: VERSION,
            kdf_params: cur.kdf_params,
            salt: cur.salt,
            wrapped_key: cur.wrapped_key.clone(),
            active_slot: slot,
            metadata_offset,
            data_offset,
            hmac: [0u8; HMAC_LEN],
        };
        let header_key = derive_header_key(self.master.as_ref());
        Ok(header.serialize(header_key.as_ref())?.to_vec())
    }
}

/// One file in a rewrite plan: identity plus a streaming source for its
/// plaintext. The plaintext is never held whole in memory; it is streamed in
/// 64 KiB chunks during the rebuild.
struct PlannedFile {
    id: String,
    name_enc: Vec<u8>,
    size: u64,
    created_at: u64,
    modified_at: u64,
    src: FileSource,
}

/// Where a planned file's plaintext comes from during the streamed rebuild.
enum FileSource {
    /// Read the file's existing sealed chunks from the current container and
    /// re-seal them under the fresh generation.
    Container { chunks: Vec<ChunkRef> },
    /// Stream plaintext from a file on disk (used by add).
    Path(PathBuf),
    /// Stream plaintext from an in-memory byte slice (used by put).
    Bytes(Vec<u8>),
}

/// Derive the cached [`NameKey`] for the vault from the master key.
fn name_key_from_master(master: &[u8]) -> NameKey {
    let subkey = derive_subkey(master, FILENAME_PURPOSE, b"", 0);
    NameKey::from_subkey(
        subkey
            .as_ref()
            .try_into()
            .expect("derive_subkey always returns a 32-byte subkey"),
    )
}

/// Current Unix timestamp in seconds, with `0` used when the system clock is
/// before the Unix epoch.
fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// Generate a fresh random file id, hex-encoded.
fn new_file_id() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    let mut s = String::with_capacity(32);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Open the primary container for reading/seek.
fn open_primary(path: &Path) -> Result<std::fs::File> {
    OpenOptions::new().read(true).open(path).map_err(Into::into)
}

/// Atomically call `write_into` on a sibling temp file, fsync, then rename it
/// over `path`.
fn atomic_write_to(
    path: &Path,
    write_into: impl FnOnce(&mut std::fs::File) -> Result<()>,
) -> Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".auto.tmp");
    let tmp = std::path::PathBuf::from(tmp);

    {
        let mut f = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp)?;
        write_into(&mut f)?;
        f.sync_all()?;
    }
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(FormatError::Io(e))
        }
    }
}

/// The current length of the file at `path` in bytes.
fn current_file_len(path: &Path) -> Result<u64> {
    Ok(std::fs::metadata(path)?.len())
}

/// Read exactly `len` bytes of `path` starting at `off` (bounds-checked).
fn read_range_file(path: &Path, off: u64, len: usize) -> Result<Vec<u8>> {
    let mut f = open_primary(path)?;
    f.seek(SeekFrom::Start(off))?;
    let mut buf = vec![0u8; len];
    f.read_exact(&mut buf)?;
    Ok(buf)
}

/// Positioned write of `data` at `off` within `path`, followed by fsync.
///
/// Used for the atomic 8 KiB header-slot flip. An 8 KiB write aligned to a
/// logical-block boundary is atomic on practically all filesystems, so a
/// reader observes either the old slot or the new slot, never a mix.
fn pwrite_block(path: &Path, off: u64, data: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new().create(true).write(true).open(path)?;
    f.seek(SeekFrom::Start(off))?;
    f.write_all(data)?;
    f.sync_all()?;
    Ok(())
}

/// Zero-magic bytes for an inactive/stale header slot, so it is never mistaken
/// for a valid header but is still readable enough for recovery.
fn stale_slot_bytes() -> Vec<u8> {
    let mut slot = [0u8; HEADER_SIZE];
    slot[..MAGIC.len()].copy_from_slice(MAGIC);
    slot.to_vec()
}

/// Overwrite the inactive header slot with garbage (invalidating it) after a
/// full compact rebuild, so recovery/rollback never falls back to a stale slot.
fn pwrite_inactive_slot(path: &Path, active_slot: u8, active_header: &[u8]) -> Result<()> {
    let inactive = Header::inactive_slot(active_slot);
    let off = Header::slot_offset(inactive);
    let _ = active_header;
    pwrite_block(path, off, &stale_slot_bytes())
}

/// Compute the byte length of a serialized metadata region from its
/// self-describing framing: `u64 manifest_len || manifest || u64 store_len ||
/// store`. `buf` must begin at the region start and may extend past it (e.g.
/// into the legacy trailing data area); only the region's exact extent is
/// returned.
fn metadata_region_len(buf: &[u8]) -> Result<usize> {
    let read_len = |rest: &mut &[u8]| -> Result<usize> {
        if rest.len() < 8 {
            return Err(FormatError::InvalidLength {
                what: "metadata length prefix",
                expected: 8,
                got: rest.len(),
            });
        }
        let v = u64::from_le_bytes(rest[..8].try_into().unwrap()) as usize;
        *rest = &rest[8..];
        Ok(v)
    };

    let mut rest = buf;
    let manifest_len = read_len(&mut rest)?;
    if manifest_len > rest.len() {
        return Err(FormatError::InvalidLength {
            what: "metadata manifest field",
            expected: rest.len(),
            got: manifest_len,
        });
    }
    rest = &rest[manifest_len..];
    let store_len = read_len(&mut rest)?;
    if store_len > rest.len() {
        return Err(FormatError::InvalidLength {
            what: "metadata store field",
            expected: rest.len(),
            got: store_len,
        });
    }
    Ok(buf.len() - rest.len() + store_len)
}

/// Fixed byte overhead added to each plaintext chunk by sealing:
/// `nonce(12) || ciphertext || tag(16)` (ciphertext is the same length as the
/// plaintext for the AEAD used). Because sealing is deterministic, the sealed
/// length depends only on the plaintext size, so chunk offsets can be computed
/// from sizes alone before any data is written.
const SEAL_OVERHEAD: u64 =
    autocipher_core::content::NONCE_LEN as u64 + autocipher_core::content::TAG_LEN as u64;

/// Plaintext byte length of chunk `idx` of a file of `size` bytes.
///
/// All but the final chunk are full [`CHUNK_SIZE`]; the final chunk holds the
/// remainder (an empty file has no chunks).
fn chunk_plaintext_len(size: u64, idx: u64) -> usize {
    let chunk = autocipher_core::content::CHUNK_SIZE as u64;
    let remaining = size - idx * chunk;
    remaining.min(chunk) as usize
}

/// Number of sealed chunks a file of `size` bytes will occupy (0 for empty).
fn file_chunk_count(size: u64) -> usize {
    let chunk = autocipher_core::content::CHUNK_SIZE as u64;
    if size == 0 {
        0
    } else {
        size.div_ceil(chunk) as usize
    }
}

/// Total sealed byte length of chunk `idx` of a file of `size` bytes.
fn sealed_chunk_len(size: u64, idx: u64) -> u32 {
    (chunk_plaintext_len(size, idx) as u64 + SEAL_OVERHEAD) as u32
}

/// Lay out the sealed chunks of one new/overwritten file whose data area begins
/// at `base_off`, from its plaintext size alone.
///
/// The sealed-chunk length is deterministic (`nonce 12 + plaintext + tag 16`),
/// so the returned [`ChunkRef`]s depend only on `size`, never on content. This
/// is how the serial append-only pass plans new-file offsets up front (no I/O)
/// and later proves the streamed write reproduced them exactly.
fn layout_new_file_refs(base_off: u64, size: u64) -> (Vec<ChunkRef>, u64) {
    let mut refs = Vec::with_capacity(file_chunk_count(size));
    let mut offset = base_off;
    for idx in 0..file_chunk_count(size) {
        let len = sealed_chunk_len(size, idx as u64);
        refs.push(ChunkRef { offset, len });
        offset += u64::from(len);
    }
    (refs, offset)
}

/// Compute the metadata region (manifest + integrity store) and the file-data
/// offset for a full-rebuild plan, from plaintext sizes alone — no file data is
/// read or buffered here.
///
/// Used only by [`Vault::compact`], which rebuilds the whole container starting
/// at the header region: every file is re-sealed under a fresh generation and
/// laid out in one contiguous data area. `base_off` is the byte offset at which
/// the metadata region begins. The metadata length depends on the chunk
/// offsets, which depend on the data offset, which depends on the metadata
/// length. This is resolved by a short fixed-point loop; the sealed chunk
/// lengths are deterministic, so each iteration is cheap.
#[allow(clippy::type_complexity)]
fn plan_layout(
    master: &[u8],
    files: &[PlannedFile],
    generation: u64,
    base_off: u64,
) -> Result<(Vec<u8>, VaultManifest, IntegrityBlockStore, u64)> {
    let mut data_off = base_off;
    // Compaction is a metadata rewrite, so it intentionally upgrades a legacy
    // v1 manifest to the current timestamp-bearing format.
    let mut manifest = VaultManifest::default();
    let mut store = IntegrityBlockStore::new(generation);
    let mut metadata = Vec::new();
    for _ in 0..16 {
        manifest = VaultManifest::default();
        store = IntegrityBlockStore::new(generation);
        let mut offset = data_off;
        for f in files {
            let mut refs = Vec::with_capacity(file_chunk_count(f.size));
            for idx in 0..file_chunk_count(f.size) {
                let len = sealed_chunk_len(f.size, idx as u64);
                refs.push(ChunkRef { offset, len });
                offset += u64::from(len);
            }
            let refs_for_id = refs.clone();
            store.record(&f.id, generation, refs_for_id)?;
            manifest.files.push(FileMeta {
                id: f.id.clone(),
                name_enc: f.name_enc.clone(),
                size: f.size,
                created_at: f.created_at,
                modified_at: f.modified_at,
                chunks: refs,
            });
        }
        metadata = serialize_metadata(master, &manifest, &store)?;
        let new_data_off = base_off + metadata.len() as u64;
        if new_data_off == data_off {
            break;
        }
        data_off = new_data_off;
    }
    let final_data_off = base_off + metadata.len() as u64;
    Ok((metadata, manifest, store, final_data_off))
}

/// Stream the plaintext of one existing file from the old container's sealed
/// chunks and re-seal copies of them (under the fresh generation) into `dst`.
///
/// Reads and rewrites one 64 KiB chunk at a time, so a single file is never
/// held whole in memory. `plain_size` is the file's plaintext size; the source
/// chunk count and per-chunk plaintext lengths are identical to the target's.
fn reseal_stream(
    src: &mut ChunkReader,
    refs: &[ChunkRef],
    dst: &mut ChunkWriter,
    plain_size: u64,
) -> Result<Vec<ChunkRef>> {
    let mut buf = vec![0u8; autocipher_core::content::CHUNK_SIZE];
    let mut out = Vec::with_capacity(refs.len());
    for (idx, reference) in refs.iter().enumerate() {
        let pt_len = chunk_plaintext_len(plain_size, idx as u64);
        let mut sink = std::io::Cursor::new(&mut buf[..pt_len]);
        src.read_chunk(reference, idx as u64, &mut sink)?;
        out.push(dst.write_chunk(&buf[..pt_len])?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Seek, SeekFrom};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use autocipher_core::kdf::Memory;
    use autocipher_core::keywrap;

    use super::*;

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    const PASSWORD: &[u8] = b"correct horse battery staple";

    fn params() -> KdfParams {
        KdfParams {
            memory: Memory::M128,
            t: 1,
            p: 1,
        }
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "autocipher-vault-{}-{}-{}",
            tag,
            std::process::id(),
            n
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_plain(path: &Path, data: &[u8]) {
        std::fs::write(path, data).unwrap();
    }

    /// Build a container with an EMPTY manifest but an arbitrary store generation,
    /// letting tests exercise rollback/anchoring through `Vault::open`.
    fn craft_container(
        path: &Path,
        password: &[u8],
        params: KdfParams,
        master: &[u8],
        store_gen: u64,
    ) -> Result<()> {
        let salt = [0x42u8; SALT_LEN];
        let kek = kdf::derive_kek(password, &salt, params.memory, params.t, params.p)?;
        let wrapped = keywrap::wrap(kek.as_ref(), master)?;
        let header = Header {
            magic: *MAGIC,
            version: VERSION,
            kdf_params: params,
            salt,
            wrapped_key: wrapped,
            active_slot: 0,
            metadata_offset: HEADER_REGION_SIZE as u64,
            data_offset: HEADER_REGION_SIZE as u64,
            hmac: [0u8; 64],
        };
        let header_key = derive_header_key(master);
        let header_bytes = header.serialize(header_key.as_ref())?.to_vec();
        let store = IntegrityBlockStore::new(store_gen);
        let metadata = serialize_metadata(master, &VaultManifest::default(), &store)?;
        let mut container = Vec::with_capacity(HEADER_REGION_SIZE + metadata.len());
        container.extend_from_slice(&header_bytes);
        container.resize(HEADER_REGION_SIZE, 0);
        container.extend_from_slice(&metadata);
        std::fs::write(path, container)?;
        Ok(())
    }

    #[test]
    fn e2e_create_list_empty() {
        let dir = temp_dir("create");
        let vault_path = dir.join("vault.ac");
        let v = Vault::create(&vault_path, PASSWORD, params()).unwrap();
        assert!(v.list().unwrap().is_empty());
        assert_eq!(v.generation(), MIN_VAULT_GENERATION);
        assert!(vault_path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn e2e_create_open_roundtrip_rejects_wrong_password() {
        let dir = temp_dir("open");
        let vault_path = dir.join("vault.ac");
        Vault::create(&vault_path, PASSWORD, params()).unwrap();

        let v = Vault::open(&vault_path, PASSWORD).unwrap();
        assert!(v.list().unwrap().is_empty());

        assert!(Vault::open(&vault_path, b"wrong password").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn change_password_old_fails_new_works() {
        let dir = temp_dir("chpwd");
        let vault_path = dir.join("vault.ac");
        let src = dir.join("doc.txt");
        write_plain(&src, b"secrets");

        let new_params = KdfParams {
            memory: Memory::M256,
            t: 2,
            p: 1,
        };

        let mut v = Vault::create(&vault_path, b"old pass", params()).unwrap();
        v.add_file(&src).unwrap();
        v.change_password(b"new pass", new_params).unwrap();
        drop(v);

        // The old password no longer works.
        assert!(Vault::open(&vault_path, b"old pass").is_err());

        // The new password unlocks with the new KDF params and intact contents.
        let v2 = Vault::open(&vault_path, b"new pass").unwrap();
        assert_eq!(v2.kdf_params(), new_params);
        assert_eq!(v2.list().unwrap(), vec!["doc.txt".to_string()]);
        let out = dir.join("out.txt");
        v2.extract("doc.txt", &out).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), b"secrets");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn get_put_size_name_access_roundtrip() {
        let dir = temp_dir("getput");
        let vault_path = dir.join("vault.ac");

        let mut v = Vault::create(&vault_path, PASSWORD, params()).unwrap();
        // A new name is created; nested path separators are opaque to the store.
        v.put("docs/report.txt", b"hello vfs").unwrap();
        assert_eq!(v.size("docs/report.txt").unwrap(), 9);
        assert_eq!(v.list().unwrap(), vec!["docs/report.txt".to_string()]);

        // Overwriting the same name replaces contents in place.
        v.put("docs/report.txt", b"hello vfs, again").unwrap();
        assert_eq!(v.get("docs/report.txt").unwrap(), b"hello vfs, again");
        assert_eq!(v.size("docs/report.txt").unwrap(), 16);
        assert_eq!(v.list().unwrap().len(), 1);

        // Mutating accessors are visible after a reopen.
        drop(v);
        let v2 = Vault::open(&vault_path, PASSWORD).unwrap();
        assert_eq!(v2.get("docs/report.txt").unwrap(), b"hello vfs, again");

        // Missing names fail cleanly.
        assert!(v2.get("nope.txt").is_err());
        assert!(v2.size("nope.txt").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn metadata_survives_overwrite_rename_reopen_and_compaction() {
        let dir = temp_dir("metadata");
        let vault_path = dir.join("vault.ac");
        let initial_size = autocipher_core::content::CHUNK_SIZE as usize + 1;
        let initial = vec![0x5a; initial_size];

        let mut v = Vault::create(&vault_path, PASSWORD, params()).unwrap();
        v.set_auto_compact_ratio(None);
        v.put("docs/blob.bin", &initial).unwrap();

        let first = v
            .list_file_info()
            .unwrap()
            .into_iter()
            .next()
            .expect("new entry should be listed");
        assert_eq!(first.name, "docs/blob.bin");
        assert_eq!(first.size, initial_size as u64);
        assert!(first.created_at > 0);
        assert_eq!(first.created_at, first.modified_at);
        assert_eq!(
            first.storage_used,
            u64::from(sealed_chunk_len(initial_size as u64, 0))
                + u64::from(sealed_chunk_len(initial_size as u64, 1)),
        );

        drop(v);
        let mut v = Vault::open(&vault_path, PASSWORD).unwrap();
        v.set_auto_compact_ratio(None);
        let reopened = v.list_file_info().unwrap().pop().unwrap();
        assert_eq!(reopened, first);

        // Overwriting keeps the creation timestamp and refreshes modification.
        v.put("docs/blob.bin", b"small").unwrap();
        let overwritten = v
            .list_file_info()
            .unwrap()
            .into_iter()
            .find(|info| info.name == "docs/blob.bin")
            .unwrap();
        assert_eq!(overwritten.created_at, first.created_at);
        assert!(overwritten.modified_at >= first.modified_at);
        assert_eq!(overwritten.size, 5);
        assert_eq!(overwritten.storage_used, u64::from(sealed_chunk_len(5, 0)),);

        // A rename keeps the creation timestamp and advances modification again.
        v.rename("docs/blob.bin", "docs/renamed.bin").unwrap();
        let renamed = v
            .list_file_info()
            .unwrap()
            .into_iter()
            .find(|info| info.name == "docs/renamed.bin")
            .unwrap();
        assert_eq!(renamed.created_at, first.created_at);
        assert!(renamed.modified_at >= overwritten.modified_at);
        assert_eq!(renamed.size, overwritten.size);
        assert_eq!(renamed.storage_used, overwritten.storage_used);

        v.compact().unwrap();
        drop(v);
        let after_compact = Vault::open(&vault_path, PASSWORD)
            .unwrap()
            .list_file_info()
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(after_compact, renamed);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn add_file_as_stores_under_explicit_subpath() {
        let dir = temp_dir("addfileas");
        let vault_path = dir.join("vault.ac");
        let src = dir.join("photo.jpg");
        let payload: Vec<u8> = (0u32..200_000).map(|i| (i % 251) as u8).collect();
        write_plain(&src, &payload);

        let mut v = Vault::create(&vault_path, PASSWORD, params()).unwrap();
        // The stored name is a relative subpath; the format treats it opaquely.
        v.add_file_as(&src, "photos/beach/1.jpg").unwrap();
        assert_eq!(v.list().unwrap(), vec!["photos/beach/1.jpg".to_string()]);
        assert_eq!(v.get("photos/beach/1.jpg").unwrap(), payload);

        // Survives a reopen and compaction.
        drop(v);
        let mut v2 = Vault::open(&vault_path, PASSWORD).unwrap();
        assert_eq!(v2.get("photos/beach/1.jpg").unwrap(), payload);
        v2.compact().unwrap();
        let out = dir.join("out.jpg");
        v2.extract("photos/beach/1.jpg", &out).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), payload);

        // Empty stored names are rejected.
        assert!(v2.add_file_as(&src, "").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn add_file_uses_basename_compat_with_add_file_as() {
        let dir = temp_dir("addfilebase");
        let vault_path = dir.join("vault.ac");
        let src = dir.join("deep").join("nested").join("leaf.txt");
        std::fs::create_dir_all(src.parent().unwrap()).unwrap();
        write_plain(&src, b"hello");

        let mut v = Vault::create(&vault_path, PASSWORD, params()).unwrap();
        // add_file stores the basename; add_file_as stores the explicit name.
        assert_eq!(v.add_file(&src).unwrap(), "leaf.txt");
        v.add_file_as(&src, "deep/nested/leaf.txt").unwrap();
        assert_eq!(
            v.list().unwrap(),
            vec!["leaf.txt".to_string(), "deep/nested/leaf.txt".to_string()]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn add_paths_batches_many_files_in_one_commit() {
        let dir = temp_dir("batch");
        let vault_path = dir.join("vault.ac");
        let tree = dir.join("tree");
        std::fs::create_dir_all(tree.join("photos/beach")).unwrap();
        std::fs::create_dir_all(tree.join("docs")).unwrap();
        write_plain(&tree.join("photos/beach/1.jpg"), b"jpeg");
        write_plain(&tree.join("photos/beach/2.jpg"), b"jpeg2");
        write_plain(&tree.join("docs/readme.md"), b"# hi");
        write_plain(&tree.join("top.txt"), b"top");

        let mut v = Vault::create(&vault_path, PASSWORD, params()).unwrap();
        let items: Vec<(std::path::PathBuf, String)> = vec![
            (tree.join("photos/beach/1.jpg"), "photos/beach/1.jpg".into()),
            (tree.join("photos/beach/2.jpg"), "photos/beach/2.jpg".into()),
            (tree.join("docs/readme.md"), "docs/readme.md".into()),
            (tree.join("top.txt"), "top.txt".into()),
        ];
        let added = v.add_paths(&items).unwrap();
        assert_eq!(added, 4);

        let mut names = v.list().unwrap();
        names.sort();
        assert_eq!(
            names,
            vec![
                "docs/readme.md".to_string(),
                "photos/beach/1.jpg".to_string(),
                "photos/beach/2.jpg".to_string(),
                "top.txt".to_string(),
            ]
        );
        assert_eq!(v.get("photos/beach/1.jpg").unwrap(), b"jpeg");
        assert_eq!(v.get("top.txt").unwrap(), b"top");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn add_paths_overwrites_existing_names_in_place() {
        let dir = temp_dir("batchoverwrite");
        let vault_path = dir.join("vault.ac");
        let a = dir.join("a.txt");
        let b = dir.join("b.txt");
        write_plain(&a, b"old");
        write_plain(&b, b"new");

        let mut v = Vault::create(&vault_path, PASSWORD, params()).unwrap();
        v.add_file_as(&a, "photos/1.jpg").unwrap();
        assert_eq!(v.list().unwrap(), vec!["photos/1.jpg".to_string()]);

        // Re-importing the same stored name replaces it instead of duplicating.
        let added = v
            .add_paths(&[(b.to_path_buf(), "photos/1.jpg".to_string())])
            .unwrap();
        assert_eq!(added, 1);
        assert_eq!(v.list().unwrap(), vec!["photos/1.jpg".to_string()]);
        assert_eq!(v.get("photos/1.jpg").unwrap(), b"new");

        // A batch containing the same name twice collapses to one entry.
        let added = v
            .add_paths(&[
                (a.to_path_buf(), "photos/1.jpg".to_string()),
                (b.to_path_buf(), "photos/1.jpg".to_string()),
            ])
            .unwrap();
        assert_eq!(added, 2);
        assert_eq!(v.list().unwrap(), vec!["photos/1.jpg".to_string()]);
        assert_eq!(v.get("photos/1.jpg").unwrap(), b"new");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn add_paths_failure_leaves_vault_untouched() {
        let dir = temp_dir("batchatomic");
        let vault_path = dir.join("vault.ac");
        let good = dir.join("good.txt");
        let missing = dir.join("missing.txt");
        write_plain(&good, b"survivor");

        let mut v = Vault::create(&vault_path, PASSWORD, params()).unwrap();
        v.add_file(&good).unwrap();
        let gen_before = v.generation();
        let len_before = std::fs::metadata(&vault_path).unwrap().len();

        // One of the batch items has no source on disk: the whole commit aborts.
        let items: Vec<(std::path::PathBuf, String)> = vec![
            (good.to_path_buf(), "top.txt".to_string()),
            (missing, "also.txt".to_string()),
        ];
        assert!(v.add_paths(&items).is_err());

        assert_eq!(v.list().unwrap(), vec!["good.txt".to_string()]);
        assert_eq!(v.generation(), gen_before);
        assert_eq!(std::fs::metadata(&vault_path).unwrap().len(), len_before);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn metadata_above_old_4mib_limit_roundtrips() {
        // Regression for folder imports whose unified metadata exceeded the
        // legacy 4 MiB ceiling (e.g. ~6.7 MB for a large import). Such a region
        // must now serialize and parse cleanly under the raised bound.
        let master = keywrap::generate_master_key();
        let mut manifest = VaultManifest::default();
        let mut store = IntegrityBlockStore::new(MIN_VAULT_GENERATION);
        for i in 0..40_000u32 {
            let id = format!("file-{i:06}");
            let file = FileMeta {
                id: id.clone(),
                name_enc: vec![(i % 251) as u8; 40],
                size: 1 << 20,
                created_at: i as u64 + 1_000,
                modified_at: i as u64 + 2_000,
                chunks: vec![ChunkRef {
                    offset: i as u64 * 70_000,
                    len: 70_004,
                }],
            };
            manifest.files.push(file);
            store
                .record(
                    &id,
                    MIN_VAULT_GENERATION,
                    vec![ChunkRef {
                        offset: i as u64 * 70_000,
                        len: 70_004,
                    }],
                )
                .unwrap();
        }

        let metadata = serialize_metadata(master.as_ref(), &manifest, &store).unwrap();
        assert!(
            metadata.len() > 4 * 1024 * 1024,
            "metadata ({}) must exceed the legacy 4 MiB ceiling",
            metadata.len()
        );
        assert!(metadata.len() <= MAX_METADATA_SIZE);

        let (parsed_manifest, parsed_store, _) =
            parse_metadata(master.as_ref(), &metadata, MIN_VAULT_GENERATION).unwrap();
        assert_eq!(parsed_manifest, manifest);
        assert_eq!(parsed_store, store);
    }

    #[test]
    fn remirror_recreates_mirrors_from_primary() {
        let dir = temp_dir("remirror");
        let vault_path = dir.join("vault.ac");
        let a = dir.join("a.txt");
        write_plain(&a, b"hello world");

        let mut v = Vault::create(&vault_path, PASSWORD, params()).unwrap();
        v.add_file(&a).unwrap();
        let expected_header =
            std::fs::read(crate::mirror::header_mirror_path(&vault_path)).unwrap();
        let expected_meta =
            std::fs::read(crate::mirror::metadata_mirror_path(&vault_path)).unwrap();

        // Simulate lost mirrors, then regenerate them purely from the primary.
        std::fs::remove_file(crate::mirror::header_mirror_path(&vault_path)).unwrap();
        std::fs::remove_file(crate::mirror::metadata_mirror_path(&vault_path)).unwrap();
        assert!(crate::mirror::read_mirrors(&vault_path).is_err());

        v.remirror().unwrap();

        let (header, meta) = crate::mirror::read_mirrors(&vault_path).unwrap();
        assert_eq!(header, expected_header);
        assert_eq!(meta, expected_meta);

        // The regenerated mirrors describe a vault that still opens and reads.
        let reopened = Vault::open(&vault_path, PASSWORD).unwrap();
        assert!(matches!(reopened.get("a.txt"), Ok(data) if data == b"hello world"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_range_window_across_chunks() {
        let dir = temp_dir("ranger");
        let vault_path = dir.join("vault.ac");
        let src = dir.join("big.bin");

        // ~0.9 MiB: 15 chunks (64 KiB each) plus a partial final chunk.
        let payload: Vec<u8> = (0u32..900_000).map(|i| (i % 251) as u8).collect();
        write_plain(&src, &payload);
        let size = payload.len() as u64;
        let chunk = autocipher_core::content::CHUNK_SIZE as u64;

        let mut v = Vault::create(&vault_path, PASSWORD, params()).unwrap();
        v.add_file(&src).unwrap();

        // Whole-file window must equal the full plaintext.
        let (all, end) = v.read_range("big.bin", 0, size).unwrap();
        assert_eq!(end, size);
        assert_eq!(all, payload);

        // Mid-file window that straddles a chunk boundary.
        let (mid, mid_end) = v.read_range("big.bin", chunk - 10, 20).unwrap();
        assert_eq!(mid_end, chunk + 10);
        assert_eq!(mid, payload[(chunk as usize - 10)..(chunk as usize + 10)]);

        // Head and tail reads.
        let (head, _) = v.read_range("big.bin", 0, 5).unwrap();
        assert_eq!(head, &payload[..5]);
        let (tail, tail_end) = v.read_range("big.bin", size - 3, 1000).unwrap();
        assert_eq!(tail_end, size);
        assert_eq!(tail, &payload[(size as usize - 3)..]);

        // Past-EOF read returns empty and clamps the end to size.
        let (past, past_end) = v.read_range("big.bin", size + 5, 10).unwrap();
        assert!(past.is_empty());
        assert_eq!(past_end, size);

        // A large len is clamped to EOF.
        let (clamped, clamped_end) = v.read_range("big.bin", 10, u64::MAX - 1).unwrap();
        assert_eq!(clamped_end, size);
        assert_eq!(clamped, &payload[10..]);

        // Missing name fails cleanly.
        assert!(v.read_range("nope", 0, 10).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn e2e_add_list_extract_roundtrip() {
        let dir = temp_dir("add");
        let vault_path = dir.join("vault.ac");
        let src = dir.join("report.txt");
        let dest = dir.join("out.txt");
        let payload: Vec<u8> = (0u32..300_000).map(|i| (i % 251) as u8).collect();
        write_plain(&src, &payload);

        let mut v = Vault::create(&vault_path, PASSWORD, params()).unwrap();
        let name = v.add_file(&src).unwrap();
        assert_eq!(name, "report.txt");
        assert_eq!(v.list().unwrap(), vec!["report.txt".to_string()]);

        // Rename, verify listing changes but data stays intact.
        v.rename("report.txt", "renamed.bin").unwrap();
        assert_eq!(v.list().unwrap(), vec!["renamed.bin".to_string()]);

        v.extract("renamed.bin", &dest).unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), payload);

        // Delete, verify the vault is empty again.
        v.delete("renamed.bin").unwrap();
        assert!(v.list().unwrap().is_empty());

        // A freshly opened vault sees the same empty state.
        let v2 = Vault::open(&vault_path, PASSWORD).unwrap();
        assert!(v2.list().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn e2e_multiple_files_survive_reopen_and_compact() {
        let dir = temp_dir("multi");
        let vault_path = dir.join("vault.ac");
        let f1 = dir.join("a.txt");
        let f2 = dir.join("b.bin");
        write_plain(&f1, b"hello world");
        write_plain(&f2, &vec![7u8; 200_000]);

        let mut v = Vault::create(&vault_path, PASSWORD, params()).unwrap();
        v.add_file(&f1).unwrap();
        v.add_file(&f2).unwrap();
        v.compact().unwrap();

        let v2 = Vault::open(&vault_path, PASSWORD).unwrap();
        let mut names = v2.list().unwrap();
        names.sort();
        assert_eq!(names, vec!["a.txt".to_string(), "b.bin".to_string()]);

        let out = dir.join("out.bin");
        v2.extract("b.bin", &out).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), vec![7u8; 200_000]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_chunk_fails_cleanly_on_extract() {
        let dir = temp_dir("corrupt");
        let vault_path = dir.join("vault.ac");
        let src = dir.join("data.bin");
        write_plain(&src, &vec![0xABu8; 200_000]);

        let mut v = Vault::create(&vault_path, PASSWORD, params()).unwrap();
        v.add_file(&src).unwrap();
        let data_off = v.data_off;
        drop(v);

        // Corrupt a byte in the data area (before the end) of the primary.
        {
            let path = vault_path.clone();
            let mut f = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            f.seek(SeekFrom::Start(data_off + 50)).unwrap();
            let mut byte = [0u8];
            f.read_exact(&mut byte).unwrap();
            byte[0] ^= 0x01;
            f.seek(SeekFrom::Start(data_off + 50)).unwrap();
            f.write_all(&byte).unwrap();
        }

        // Open still succeeds (header + metadata intact)...
        let v = Vault::open(&vault_path, PASSWORD).unwrap();
        // ...but extracting the corrupted chunk fails cleanly.
        let out = dir.join("out.bin");
        assert!(v.extract("data.bin", &out).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn serial_append_survivor_chunks_untouched() {
        let dir = temp_dir("appendonly");
        let vault_path = dir.join("vault.ac");
        let f1 = dir.join("a.bin");
        write_plain(&f1, &vec![1u8; 300_000]);

        let mut v = Vault::create(&vault_path, PASSWORD, params()).unwrap();
        v.add_file(&f1).unwrap();

        // Snapshot A's chunk layout, its per-file generation, and the raw sealed
        // bytes at those offsets before the mutation.
        let refs_a = v.manifest.files[0].chunks.clone();
        let id_a = v.manifest.files[0].id.clone();
        let version_a = v.store.get(&id_a).unwrap().version;
        let before: Vec<u8> = {
            let bytes = std::fs::read(&vault_path).unwrap();
            refs_a
                .iter()
                .flat_map(|r| bytes[r.offset as usize..][..r.len as usize].to_vec())
                .collect()
        };
        drop(v);

        // The second mutation touches only B's data.
        let mut v = Vault::open(&vault_path, PASSWORD).unwrap();
        v.put("b.bin", &vec![2u8; 64_000]).unwrap();

        // A keeps its exact refs and its original generation in the unified
        // metadata (neither is re-sealed, so the generation did not advance).
        let a_meta = v.manifest.files.iter().find(|m| m.id == id_a).unwrap();
        assert_eq!(a_meta.chunks, refs_a);
        assert_eq!(v.store.get(&id_a).unwrap().version, version_a);

        // A's bytes on disk are bit-for-bit unchanged at the same offsets.
        let after = std::fs::read(&vault_path).unwrap();
        let after_bytes: Vec<u8> = refs_a
            .iter()
            .flat_map(|r| after[r.offset as usize..][..r.len as usize].to_vec())
            .collect();
        assert_eq!(after_bytes, before, "survivor data must not be rewritten");

        // Both files still decrypt correctly (mixed generations).
        assert_eq!(v.get("a.bin").unwrap(), vec![1u8; 300_000]);
        assert_eq!(v.get("b.bin").unwrap(), vec![2u8; 64_000]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn serial_append_mixed_generation_reopen() {
        let dir = temp_dir("mixedgen");
        let vault_path = dir.join("vault.ac");
        let mut v = Vault::create(&vault_path, PASSWORD, params()).unwrap();
        v.put("one.txt", b"first file").unwrap();
        let (id_one, gen_one) = {
            let m = v.manifest.files.first().unwrap();
            (m.id.clone(), v.store.get(&m.id).unwrap().version)
        };

        v.put("two.txt", &vec![9u8; 200_000]).unwrap();
        assert_eq!(v.generation(), 3);
        let id_two = v
            .manifest
            .files
            .iter()
            .find(|m| m.size == 200_000)
            .unwrap()
            .id
            .clone();
        let gen_two = v.store.get(&id_two).unwrap().version;

        // one.txt survived untouched: it must be recorded at its old generation
        // while the store anchor advanced to the next generation.
        assert_eq!(v.store.get(&id_one).unwrap().version, gen_one);
        assert_ne!(gen_one, gen_two);
        drop(v);

        // A reopened vault resolves each file under its own recorded generation.
        let v = Vault::open(&vault_path, PASSWORD).unwrap();
        assert_eq!(v.generation(), 3);
        assert_eq!(v.get("one.txt").unwrap(), b"first file");
        assert_eq!(v.get("two.txt").unwrap(), vec![9u8; 200_000]);
        assert_eq!(v.store.get(&id_one).unwrap().version, gen_one);
        assert_eq!(v.store.get(&id_two).unwrap().version, gen_two);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn garbage_ratio_tracks_unreferenced_bytes() {
        let dir = temp_dir("garbageratio");
        let vault_path = dir.join("vault.ac");

        let mut v = Vault::create(&vault_path, PASSWORD, params()).unwrap();
        // Fresh containers default to auto-compaction enabled.
        assert_eq!(v.compact_ratio, Some(DEFAULT_AUTO_COMPACT_RATIO));
        v.set_auto_compact_ratio(None);
        assert_eq!(v.compact_ratio, None);

        v.put("keep.bin", &vec![1u8; 64_000]).unwrap();
        v.put("drop.bin", &vec![2u8; 256_000]).unwrap();
        // Two appends leave only tiny stale metadata regions.
        assert!(v.garbage_ratio().unwrap() < 0.1);

        // Deleting a third of the container turns its sealed data into garbage.
        v.delete("drop.bin").unwrap();
        let ratio = v.garbage_ratio().unwrap();
        assert!(ratio > 0.5, "deleted data must be counted as garbage");
        // With compaction disabled the stale bytes remain on disk.
        let len = std::fs::metadata(&vault_path).unwrap().len();
        assert!(
            len > (HEADER_REGION_SIZE as u64) + 256_000,
            "no reclaim when disabled"
        );
        assert_eq!(v.garbage_bytes().unwrap() as f64 / len as f64, ratio);
        assert_eq!(v.get("keep.bin").unwrap(), vec![1u8; 64_000]);

        // The garbage survives a reopen unchanged.
        let v2 = Vault::open(&vault_path, PASSWORD).unwrap();
        let reopened = v2.garbage_ratio().unwrap();
        assert!((reopened - ratio).abs() < 0.01);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn auto_compact_triggers_on_ratio_threshold() {
        let dir = temp_dir("autocompact");
        let vault_path = dir.join("vault.ac");

        let mut v = Vault::create(&vault_path, PASSWORD, params()).unwrap();
        v.set_auto_compact_ratio(Some(0.25));

        v.put("keep.bin", &vec![1u8; 64_000]).unwrap();
        v.put("drop.bin", &vec![2u8; 256_000]).unwrap();

        // Deleting drop.bin would leave ~76% garbage with compaction disabled;
        // the low threshold forces an automatic reclaim on this very mutation.
        v.delete("drop.bin").unwrap();
        assert!(
            v.garbage_ratio().unwrap() < 0.1,
            "auto-compaction should reclaim deleted data"
        );
        assert_eq!(v.get("keep.bin").unwrap(), vec![1u8; 64_000]);

        // Overwriting a chunked file also builds garbage; each overwrite here
        // crosses the threshold and compacts, keeping the ratio near zero.
        for i in 0..6 {
            let data = vec![(i + 3) as u8; 128_000];
            v.put("keep.bin", &data).unwrap();
        }
        assert!(
            v.garbage_ratio().unwrap() < 0.1,
            "auto-compaction should reclaim overwritten data"
        );
        assert_eq!(v.get("keep.bin").unwrap(), vec![8u8; 128_000]);

        // The compacted container reopens with all contents intact.
        let v2 = Vault::open(&vault_path, PASSWORD).unwrap();
        assert_eq!(v2.list().unwrap(), vec!["keep.bin".to_string()]);
        assert_eq!(v2.get("keep.bin").unwrap(), vec![8u8; 128_000]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn auto_compact_disabled_allows_garbage_accumulation() {
        let dir = temp_dir("autocompactoff");
        let vault_path = dir.join("vault.ac");

        let mut v = Vault::create(&vault_path, PASSWORD, params()).unwrap();
        v.set_auto_compact_ratio(None);
        v.put("keep.bin", &vec![1u8; 64_000]).unwrap();
        v.put("drop.bin", &vec![2u8; 256_000]).unwrap();

        let before = v.garbage_ratio().unwrap();
        assert!(before < 0.1);

        // Repeated overwrites accumulate garbage far past the default threshold
        // with auto-compaction disabled; the ratio only grows.
        v.delete("drop.bin").unwrap();
        let after = v.garbage_ratio().unwrap();
        assert!(after > 0.5);
        assert!(after > before);
        assert_eq!(v.get("keep.bin").unwrap(), vec![1u8; 64_000]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mirror_restore_after_primary_loss() {
        let dir = temp_dir("mirrorrestore");
        let vault_path = dir.join("vault.ac");
        let src = dir.join("docs.txt");
        write_plain(&src, b"persistent payload");

        let mut v = Vault::create(&vault_path, PASSWORD, params()).unwrap();
        v.add_file(&src).unwrap();
        drop(v);

        // Lose the primary container.
        std::fs::remove_file(&vault_path).unwrap();

        // Open auto-restores the vault identity/structure (header + metadata)
        // from the sidecar mirrors, so the vault stays unlockable with its file
        // listing intact. Encrypted file *data* lives only in the primary and is
        // not mirrored, so recovery preserves structure, not the file bytes.
        let v = Vault::open(&vault_path, PASSWORD).unwrap();
        assert_eq!(v.list().unwrap(), vec!["docs.txt".to_string()]);
        assert!(vault_path.exists(), "primary should be rebuilt");
        // `extract` fails cleanly for the pre-existing file whose data was lost.
        assert!(v.extract("docs.txt", dir.join("ghost.out")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rollback_anchor_rejected_on_open() {
        let dir = temp_dir("rollback");
        let vault_path = dir.join("vault.ac");
        let master = keywrap::generate_master_key();

        // A valid container at the minimum generation opens fine.
        craft_container(
            &vault_path,
            PASSWORD,
            params(),
            master.as_ref(),
            MIN_VAULT_GENERATION,
        )
        .unwrap();
        let v = Vault::open(&vault_path, PASSWORD).unwrap();
        assert_eq!(v.generation(), MIN_VAULT_GENERATION);

        // A container whose integrity store carries a stale (pre-minimum)
        // generation is rejected as a rollback.
        let bad = dir.join("stale.ac");
        craft_container(
            &bad,
            PASSWORD,
            params(),
            master.as_ref(),
            MIN_VAULT_GENERATION - 1,
        )
        .unwrap();
        let err = Vault::open(&bad, PASSWORD).map(|_| ()).unwrap_err();
        assert!(matches!(
            err,
            FormatError::Rollback {
                got: 0,
                expected: 1
            }
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn oversized_metadata_rejected_dos_ceiling() {
        let dir = temp_dir("dos");
        let master = keywrap::generate_master_key();
        // A metadata buffer larger than the ceiling must be rejected up front.
        let oversized = vec![0u8; MAX_METADATA_SIZE + 1];
        let err = parse_metadata(master.as_ref(), &oversized, MIN_VAULT_GENERATION).unwrap_err();
        assert!(matches!(err, FormatError::MetadataTooLarge { .. }));

        // A forged manifest length prefix pointing past the available data must
        // be rejected cleanly (not panic / OOM).
        let mut forged = Vec::new();
        forged.extend_from_slice(&(u64::MAX).to_le_bytes()); // absurd manifest length
        let forged = forged;
        assert!(parse_metadata(master.as_ref(), &forged, MIN_VAULT_GENERATION).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_vault_open_reports_not_found() {
        let dir = temp_dir("missing");
        let vault_path = dir.join("nope.ac");
        assert!(Vault::open(&vault_path, PASSWORD).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
