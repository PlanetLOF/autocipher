//! Encrypted vault manifest.
//!
//! The vault metadata — the file list with per-file encrypted names and chunk
//! locations — is serialized to a compact binary format and sealed as a single
//! AEAD payload under a manifest subkey (HKDF purpose `b"manifest"`, empty file
//! id, index 0), reusing the tested per-chunk AEAD from
//! [`autocipher_core::content`].

use autocipher_core::content;
use autocipher_core::subkeys::derive_subkey;

use crate::constants::{LEGACY_MANIFEST_VERSION, MANIFEST_VERSION};
use crate::error::{FormatError, Result};
use crate::metadata::{MAX_CHUNKS_PER_FILE, MAX_FILES};

/// HKDF purpose tag for the manifest subkey.
pub const MANIFEST_PURPOSE: &[u8] = b"manifest";

/// Generation bound into the manifest AEAD AAD. The manifest is a single
/// vault-wide blob, so the AAD uses an empty file id, index 0, and this fixed
/// generation until per-vault generations arrive with the integrity phase.
pub const MANIFEST_GENERATION: &[u8] = b"";

/// u32 marker prefixing a multi-chunk manifest payload.
///
/// A single-chunk sealed manifest starts with the 12-byte zero nonce, so its
/// first four bytes are always `0x00000000`; any non-zero marker is therefore
/// unambiguous. Chunked payloads are produced only when the serialized manifest
/// exceeds the single-chunk plaintext limit.
const CHUNKED: u32 = 0x54484E43; // "CNHT" (little-endian)

/// A reference to one sealed chunk in the container's data area.
///
/// `offset` is the absolute byte position of the sealed chunk
/// (`nonce(12) || ciphertext || tag`) within the `.ac` file; `len` is its total
/// byte length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkRef {
    /// Absolute offset of the sealed chunk in the container file.
    pub offset: u64,
    /// Total byte length of the sealed chunk.
    pub len: u32,
}

/// Per-file vault metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMeta {
    /// Plaintext file id (an opaque identifier within this vault).
    pub id: String,
    /// Deterministically encrypted filename (`nonce(12) || ciphertext || tag`).
    pub name_enc: Vec<u8>,
    /// Plaintext file size in bytes.
    pub size: u64,
    /// Unix timestamp (seconds) when this entry was first stored, or `0` when
    /// the entry came from a legacy manifest.
    pub created_at: u64,
    /// Unix timestamp (seconds) when this entry was last stored, renamed, or
    /// overwritten, or `0` when unknown.
    pub modified_at: u64,
    /// Sealed chunks in storage order; `chunk_idx` maps 1:1 to the position.
    pub chunks: Vec<ChunkRef>,
}

/// The vault manifest: a versioned list of encrypted file metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultManifest {
    /// On-disk format version of the manifest.
    pub version: u16,
    /// Per-file entries.
    pub files: Vec<FileMeta>,
}

impl Default for VaultManifest {
    fn default() -> Self {
        Self {
            version: MANIFEST_VERSION,
            files: Vec::new(),
        }
    }
}

/// Encrypt `manifest` into a sealed AEAD payload using the manifest subkey.
///
/// The binary representation ([`serialize_binary`]) is encrypted directly. When
/// the serialized manifest fits in a single chunk the payload is exactly
/// `nonce(12) || ciphertext || tag`; larger manifests use the chunked framing:
///
/// ```text
/// u32 LE  CHUNKED || u32 LE chunk_count || (u32 LE len || sealed_chunk) × n
/// ```
///
/// Each sealed chunk is bound to `(manifest subkey, empty file id, chunk_idx)`,
/// with `chunk_idx` starting at 0, so the AAD chain is index-ordered.
pub fn encrypt_manifest(master: &[u8], manifest: &VaultManifest) -> Result<Vec<u8>> {
    let bin = serialize_binary(manifest);
    if bin.len() <= content::CHUNK_SIZE {
        return seal_manifest_chunk(master, 0, &bin);
    }
    let subkey = manifest_subkey(master);
    let mut payload = Vec::with_capacity(4 + 4);
    payload.extend_from_slice(&CHUNKED.to_le_bytes());
    let chunks = seal_large_payload(&subkey, &bin)?;
    payload.extend_from_slice(&(chunks.len() as u32).to_le_bytes());
    for sealed in chunks {
        payload.extend_from_slice(&(sealed.len() as u32).to_le_bytes());
        payload.extend_from_slice(&sealed);
    }
    Ok(payload)
}

/// Seal a plaintext larger than one chunk into multiple sealed chunks.
///
/// `plaintext` is split into [`content::CHUNK_SIZE`] slices, each sealed under
/// the manifest subkey with a monotonically increasing `chunk_idx` starting at 0.
fn seal_large_payload(subkey: &[u8; 32], plaintext: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut chunks = Vec::new();
    let mut idx = 0u64;
    let mut offset = 0usize;
    while offset < plaintext.len() {
        let end = (offset + content::CHUNK_SIZE).min(plaintext.len());
        let sealed = content::seal_chunk(
            subkey,
            MANIFEST_GENERATION,
            b"",
            idx,
            &plaintext[offset..end],
        )?;
        chunks.push(sealed);
        offset = end;
        idx += 1;
    }
    Ok(chunks)
}

/// Decrypt and deserialize a manifest as produced by [`encrypt_manifest`].
///
/// A tampered payload or a wrong master key (and thus wrong subkey) fails the
/// AEAD verification before any field is trusted.
pub fn decrypt_manifest(master: &[u8], payload: &[u8]) -> Result<VaultManifest> {
    if payload.len() < 4 {
        let plaintext = content::open_chunk(
            &manifest_subkey(master),
            MANIFEST_GENERATION,
            b"",
            0,
            payload,
        )?;
        return parse_binary(plaintext.as_ref());
    }
    let marker = u32::from_le_bytes(payload[..4].try_into().expect("4-byte slice"));
    if marker == CHUNKED {
        let mut rest = &payload[4..];
        let count = take_u32(&mut rest)?;
        if count == 0 {
            return Err(FormatError::Crypto(
                autocipher_core::error::CryptoError::InvalidCiphertextLength {
                    expected_min: content::NONCE_LEN + content::TAG_LEN,
                    got: payload.len(),
                },
            ));
        }
        let subkey = manifest_subkey(master);
        let mut plaintext = Vec::new();
        for idx in 0..count {
            let len = take_u32(&mut rest)? as usize;
            if len > rest.len() {
                return Err(FormatError::Crypto(
                    autocipher_core::error::CryptoError::InvalidCiphertextLength {
                        expected_min: content::NONCE_LEN + content::TAG_LEN,
                        got: len,
                    },
                ));
            }
            let (chunk, after) = rest.split_at(len);
            rest = after;
            let pt = content::open_chunk(&subkey, MANIFEST_GENERATION, b"", u64::from(idx), chunk)?;
            plaintext.extend_from_slice(pt.as_ref());
        }
        return parse_binary(&plaintext);
    }

    let plaintext = content::open_chunk(
        &manifest_subkey(master),
        MANIFEST_GENERATION,
        b"",
        0,
        payload,
    )?;
    parse_binary(plaintext.as_ref())
}

/// Seal one manifest plaintext slice under the manifest subkey with `chunk_idx`.
fn seal_manifest_chunk(master: &[u8], chunk_idx: u64, plaintext: &[u8]) -> Result<Vec<u8>> {
    content::seal_chunk(
        &manifest_subkey(master),
        MANIFEST_GENERATION,
        b"",
        chunk_idx,
        plaintext,
    )
    .map_err(Into::into)
}

/// Read a 4-byte little-endian length/count from the front of `rest`.
fn take_u32(rest: &mut &[u8]) -> Result<u32> {
    if rest.len() < 4 {
        return Err(FormatError::Crypto(
            autocipher_core::error::CryptoError::InvalidCiphertextLength {
                expected_min: content::NONCE_LEN + content::TAG_LEN,
                got: rest.len(),
            },
        ));
    }
    let v = u32::from_le_bytes(rest[..4].try_into().expect("4-byte slice"));
    *rest = &rest[4..];
    Ok(v)
}

/// Derive the 32-byte manifest subkey from `master`.
fn manifest_subkey(master: &[u8]) -> [u8; 32] {
    let subkey = derive_subkey(master, MANIFEST_PURPOSE, b"", 0);
    *subkey
}

/// Serialize the manifest into the current compact binary format.
///
/// Layout (all little-endian, version 2):
/// ```text
/// u16 LE    version
/// u64 LE    file_count
/// For each file:
///   u64 LE  id_len
///   [N]     file_id (UTF-8)
///   u64 LE  name_enc_len
///   [N]     name_enc
///   u64 LE  size
///   u64 LE  created_at (Unix seconds; 0 = unknown)
///   u64 LE  modified_at (Unix seconds; 0 = unknown)
///   u64 LE  chunk_count
///   For each ChunkRef:
///     u64 LE  offset
///     u32 LE  len
/// ```
///
/// Version 1 had no timestamp fields. It is decoded and encoded by
/// [`serialize_binary`] when `manifest.version` is explicitly
/// [`LEGACY_MANIFEST_VERSION`], preserving the legacy shape for callers that
/// need to rewrite an old manifest in place. Newly-created manifests use
/// version 2.
pub fn serialize_binary(manifest: &VaultManifest) -> Vec<u8> {
    let version = if manifest.version == LEGACY_MANIFEST_VERSION {
        LEGACY_MANIFEST_VERSION
    } else {
        MANIFEST_VERSION
    };
    let timestamp_bytes = if version == MANIFEST_VERSION { 16 } else { 0 };
    let capacity = 2
        + 8
        + manifest
            .files
            .iter()
            .map(|f| {
                8 + f.id.len()
                    + 8
                    + f.name_enc.len()
                    + 8
                    + timestamp_bytes
                    + 8
                    + f.chunks.len() * 12
            })
            .sum::<usize>();
    let mut buf = Vec::with_capacity(capacity);
    buf.extend_from_slice(&version.to_le_bytes());
    buf.extend_from_slice(&(manifest.files.len() as u64).to_le_bytes());
    for file in &manifest.files {
        buf.extend_from_slice(&(file.id.len() as u64).to_le_bytes());
        buf.extend_from_slice(file.id.as_bytes());
        buf.extend_from_slice(&(file.name_enc.len() as u64).to_le_bytes());
        buf.extend_from_slice(&file.name_enc);
        buf.extend_from_slice(&file.size.to_le_bytes());
        if version == MANIFEST_VERSION {
            buf.extend_from_slice(&file.created_at.to_le_bytes());
            buf.extend_from_slice(&file.modified_at.to_le_bytes());
        }
        buf.extend_from_slice(&(file.chunks.len() as u64).to_le_bytes());
        for chunk in &file.chunks {
            buf.extend_from_slice(&chunk.offset.to_le_bytes());
            buf.extend_from_slice(&chunk.len.to_le_bytes());
        }
    }
    buf
}

/// Parse a manifest from compact binary format.
///
/// The caller must ensure `bytes` was produced by [`serialize_binary`].
/// Trailing bytes after the manifest are rejected.
pub fn parse_binary(bytes: &[u8]) -> Result<VaultManifest> {
    parse_binary_inner(bytes)
}

fn parse_binary_inner(mut bytes: &[u8]) -> Result<VaultManifest> {
    let read_u64 = |b: &mut &[u8]| -> Result<u64> {
        if b.len() < 8 {
            return Err(FormatError::InvalidLength {
                what: "manifest binary body",
                expected: 8,
                got: b.len(),
            });
        }
        let v = u64::from_le_bytes(b[..8].try_into().unwrap());
        *b = &b[8..];
        Ok(v)
    };

    if bytes.len() < 2 {
        return Err(FormatError::InvalidLength {
            what: "manifest version",
            expected: 2,
            got: bytes.len(),
        });
    }
    let version = u16::from_le_bytes(bytes[..2].try_into().unwrap());
    if version != LEGACY_MANIFEST_VERSION && version != MANIFEST_VERSION {
        return Err(FormatError::InvalidLength {
            what: "manifest version",
            expected: usize::from(MANIFEST_VERSION),
            got: usize::from(version),
        });
    }
    bytes = &bytes[2..];

    let file_count = read_u64(&mut bytes)?;
    let mut files = Vec::with_capacity(file_count.min(MAX_FILES as u64) as usize);
    for _ in 0..file_count {
        let id_len = read_u64(&mut bytes)? as usize;
        if bytes.len() < id_len {
            return Err(FormatError::InvalidLength {
                what: "file id",
                expected: id_len,
                got: bytes.len(),
            });
        }
        let id = String::from_utf8_lossy(&bytes[..id_len]).into_owned();
        bytes = &bytes[id_len..];

        let name_enc_len = read_u64(&mut bytes)? as usize;
        if bytes.len() < name_enc_len {
            return Err(FormatError::InvalidLength {
                what: "encrypted filename",
                expected: name_enc_len,
                got: bytes.len(),
            });
        }
        let name_enc = bytes[..name_enc_len].to_vec();
        bytes = &bytes[name_enc_len..];

        let size = read_u64(&mut bytes)?;
        let (created_at, modified_at) = if version == MANIFEST_VERSION {
            (read_u64(&mut bytes)?, read_u64(&mut bytes)?)
        } else {
            (0, 0)
        };
        let chunk_count = read_u64(&mut bytes)?;
        if chunk_count > MAX_CHUNKS_PER_FILE as u64 {
            return Err(FormatError::ChunkLimitExceeded {
                what: "chunks",
                count: chunk_count as usize,
                limit: MAX_CHUNKS_PER_FILE,
            });
        }
        let mut chunks = Vec::with_capacity(chunk_count.min(1_000_000) as usize);
        for _ in 0..chunk_count {
            if bytes.len() < 12 {
                return Err(FormatError::InvalidLength {
                    what: "chunk ref",
                    expected: 12,
                    got: bytes.len(),
                });
            }
            let offset = u64::from_le_bytes(bytes[..8].try_into().unwrap());
            let len = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
            bytes = &bytes[12..];
            chunks.push(ChunkRef { offset, len });
        }
        files.push(FileMeta {
            id,
            name_enc,
            size,
            created_at,
            modified_at,
            chunks,
        });
    }

    if !bytes.is_empty() {
        return Err(FormatError::InvalidLength {
            what: "manifest trailing bytes",
            expected: 0,
            got: bytes.len(),
        });
    }

    Ok(VaultManifest { version, files })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASTER: &[u8] = b"0123456789abcdef0123456789abcdef";

    fn sample_manifest() -> VaultManifest {
        VaultManifest {
            version: MANIFEST_VERSION,
            files: vec![
                FileMeta {
                    id: "file-1".into(),
                    name_enc: vec![1u8; 28],
                    size: 0,
                    created_at: 100,
                    modified_at: 101,
                    chunks: vec![],
                },
                FileMeta {
                    id: "file-2".into(),
                    name_enc: vec![2u8; 28],
                    size: 131_072,
                    created_at: 200,
                    modified_at: 202,
                    chunks: vec![
                        ChunkRef {
                            offset: 8192,
                            len: 1024,
                        },
                        ChunkRef {
                            offset: 9216,
                            len: 512,
                        },
                    ],
                },
            ],
        }
    }

    #[test]
    fn manifest_binary_roundtrip() {
        let m = sample_manifest();
        let bin = serialize_binary(&m);
        let parsed = parse_binary(&bin).unwrap();
        assert_eq!(parsed, m);
    }

    #[test]
    fn manifest_binary_legacy_v1_defaults_timestamps() {
        // Version 1 had no timestamps between `size` and `chunk_count`.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&LEGACY_MANIFEST_VERSION.to_le_bytes());
        bytes.extend_from_slice(&1u64.to_le_bytes());
        bytes.extend_from_slice(&6u64.to_le_bytes());
        bytes.extend_from_slice(b"file-1");
        bytes.extend_from_slice(&3u64.to_le_bytes());
        bytes.extend_from_slice(&[1, 2, 3]);
        bytes.extend_from_slice(&42u64.to_le_bytes());
        bytes.extend_from_slice(&1u64.to_le_bytes());
        bytes.extend_from_slice(&8192u64.to_le_bytes());
        bytes.extend_from_slice(&70u32.to_le_bytes());

        let parsed = parse_binary(&bytes).unwrap();
        assert_eq!(parsed.version, LEGACY_MANIFEST_VERSION);
        assert_eq!(parsed.files[0].created_at, 0);
        assert_eq!(parsed.files[0].modified_at, 0);

        // A caller may hold a legacy manifest in memory while adding metadata.
        // Explicitly retaining its v1 shape must not accidentally emit v2
        // timestamp fields, and a round-trip must remain byte-for-byte stable.
        let mut legacy = parsed.clone();
        legacy.files[0].created_at = 7;
        legacy.files[0].modified_at = 9;
        assert_eq!(serialize_binary(&legacy), bytes);
    }

    #[test]
    fn manifest_binary_empty() {
        let m = VaultManifest::default();
        let bin = serialize_binary(&m);
        let parsed = parse_binary(&bin).unwrap();
        assert_eq!(parsed, m);
    }

    #[test]
    fn manifest_binary_large_roundtrip() {
        let m = VaultManifest {
            version: MANIFEST_VERSION,
            files: (0..80_000)
                .map(|i| FileMeta {
                    id: format!("file-{i:06}"),
                    name_enc: vec![(i % 251) as u8; 28],
                    size: 1 << 20,
                    created_at: i as u64 + 1_000,
                    modified_at: i as u64 + 2_000,
                    chunks: vec![
                        ChunkRef {
                            offset: i as u64 * 65564,
                            len: 65564,
                        },
                        ChunkRef {
                            offset: i as u64 * 65564 + 65564,
                            len: 4096,
                        },
                    ],
                })
                .collect(),
        };
        let bin = serialize_binary(&m);
        let parsed = parse_binary(&bin).unwrap();
        assert_eq!(parsed, m);
    }

    #[test]
    fn manifest_binary_tamper_fails() {
        let m = sample_manifest();
        let mut bin = serialize_binary(&m);
        let mid = bin.len() / 2;
        bin[mid] ^= 0x01;
        assert!(parse_binary(&bin).is_err());
    }

    #[test]
    fn manifest_encrypt_decrypt() {
        let m = sample_manifest();
        let sealed = encrypt_manifest(MASTER, &m).unwrap();
        let dec = decrypt_manifest(MASTER, &sealed).unwrap();
        assert_eq!(dec, m);
    }

    #[test]
    fn manifest_large_chunked_roundtrip() {
        let m = VaultManifest {
            version: MANIFEST_VERSION,
            files: (0..500_000)
                .map(|i| FileMeta {
                    id: format!("file-{i:06}"),
                    name_enc: vec![(i % 251) as u8; 28],
                    size: 1 << 20,
                    created_at: i as u64 + 1_000,
                    modified_at: i as u64 + 2_000,
                    chunks: vec![ChunkRef {
                        offset: i as u64 * 70_000,
                        len: 70_004,
                    }],
                })
                .collect(),
        };
        let sealed = encrypt_manifest(MASTER, &m).unwrap();
        assert_eq!(u32::from_le_bytes(sealed[..4].try_into().unwrap()), CHUNKED);
        let dec = decrypt_manifest(MASTER, &sealed).unwrap();
        assert_eq!(dec, m);
    }

    #[test]
    fn manifest_tamper_fails() {
        let m = sample_manifest();
        let mut sealed = encrypt_manifest(MASTER, &m).unwrap();
        let last = sealed.last_mut().unwrap();
        *last ^= 0x01;
        assert!(decrypt_manifest(MASTER, &sealed).is_err());

        let cut = sealed.len() / 2;
        let truncated = sealed[..cut].to_vec();
        assert!(decrypt_manifest(MASTER, &truncated).is_err());
    }
}
