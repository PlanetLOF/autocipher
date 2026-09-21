//! The 8 KiB `.ac` header: magic, version, KDF params, salt, wrapped key, and
//! an HMAC-SHA512 trailer that authenticates the whole header.
//!
//! The header uses a fixed binary layout. When serialized, the first
//! `HEADER_SIZE - HMAC_LEN` bytes are the plaintext header fields (zero-padded
//! to that boundary), and the final `HMAC_LEN` bytes are the HMAC-SHA512
//! computed over those bytes with the header-MAC subkey. Parsing re-derives and
//! verifies the MAC before trusting any field.

use autocipher_core::kdf::KdfParams;
use autocipher_core::kdf::Memory;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::constants::{HEADER_MAC_PURPOSE, HEADER_SIZE, HMAC_LEN, MAGIC, SALT_LEN, VERSION};
use crate::error::{FormatError, Result};

/// Type alias for HMAC-SHA512.
type HmacSha512 = Hmac<Sha512>;

/// Size in bytes of the serialized wrapped-key length prefix.
const WRAPPED_KEY_LEN_FIELD: usize = 4;
/// Size of the fixed header suffix after the wrapped key (active_slot + offsets).
const HEADER_SUFFIX_LEN: usize = 1 + 8 + 8;
/// Size in bytes of the fixed serialized header prefix (all fields before the
/// variable-length wrapped key).
const FIXED_HEADER_LEN: usize = MAGIC.len() + 2 + 1 + 4 + 4 + SALT_LEN + WRAPPED_KEY_LEN_FIELD;
/// Maximum wrapped-key length representable within the header.
const MAX_WRAPPED_KEY_LEN: usize = HEADER_SIZE - HMAC_LEN - FIXED_HEADER_LEN - HEADER_SUFFIX_LEN;

/// Decode the serialized `Memory` preset.
fn memory_from_u8(v: u8) -> Option<Memory> {
    match v {
        0 => Some(Memory::M128),
        1 => Some(Memory::M256),
        2 => Some(Memory::M512),
        _ => None,
    }
}

/// Encode the `Memory` preset as a single byte.
fn memory_to_u8(m: Memory) -> u8 {
    match m {
        Memory::M128 => 0,
        Memory::M256 => 1,
        Memory::M512 => 2,
    }
}

/// The `.ac` header fields, before authentication by the HMAC trailer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Four-byte magic identifying the container.
    pub magic: [u8; 4],
    /// On-disk format version.
    pub version: u16,
    /// Argon2id cost parameters used to derive the KEK.
    pub kdf_params: KdfParams,
    /// KDF salt.
    pub salt: [u8; SALT_LEN],
    /// The wrapped master key (`nonce(12) || AEAD ciphertext`).
    pub wrapped_key: Vec<u8>,
    /// Which header slot (0 or 1) holds this valid header.
    pub active_slot: u8,
    /// Absolute offset to the metadata region (sealed manifest + integrity store).
    pub metadata_offset: u64,
    /// Absolute offset to the file-data area.
    pub data_offset: u64,
    /// HMAC-SHA512 trailer authenticating the serialized header.
    pub hmac: [u8; HMAC_LEN],
}

impl Default for Header {
    fn default() -> Self {
        Self {
            magic: *MAGIC,
            version: VERSION,
            kdf_params: crate::constants::DEFAULT_KDF_PARAMS,
            salt: [0u8; SALT_LEN],
            wrapped_key: Vec::new(),
            active_slot: 0,
            metadata_offset: crate::constants::HEADER_REGION_SIZE as u64,
            data_offset: crate::constants::HEADER_REGION_SIZE as u64,
            hmac: [0u8; HMAC_LEN],
        }
    }
}

impl Header {
    /// Serialize the header's authenticated prefix (all bytes before the HMAC
    /// trailer) into a zero-padded `HEADER_SIZE` buffer.
    fn serialize_authenticated(&self) -> Result<[u8; HEADER_SIZE]> {
        let mut buf = [0u8; HEADER_SIZE];
        let mut pos = 0usize;

        buf[pos..][..MAGIC.len()].copy_from_slice(&self.magic);
        pos += MAGIC.len();

        buf[pos..][..2].copy_from_slice(&self.version.to_le_bytes());
        pos += 2;

        buf[pos] = memory_to_u8(self.kdf_params.memory);
        pos += 1;

        buf[pos..][..4].copy_from_slice(&self.kdf_params.t.to_le_bytes());
        pos += 4;

        buf[pos..][..4].copy_from_slice(&self.kdf_params.p.to_le_bytes());
        pos += 4;

        buf[pos..][..SALT_LEN].copy_from_slice(&self.salt);
        pos += SALT_LEN;

        if self.wrapped_key.len() > MAX_WRAPPED_KEY_LEN {
            return Err(FormatError::InvalidLength {
                what: "wrapped key",
                expected: MAX_WRAPPED_KEY_LEN,
                got: self.wrapped_key.len(),
            });
        }
        buf[pos..][..WRAPPED_KEY_LEN_FIELD]
            .copy_from_slice(&(self.wrapped_key.len() as u32).to_le_bytes());
        pos += WRAPPED_KEY_LEN_FIELD;
        buf[pos..][..self.wrapped_key.len()].copy_from_slice(&self.wrapped_key);
        pos += self.wrapped_key.len();

        buf[pos] = self.active_slot;
        pos += 1;

        buf[pos..][..8].copy_from_slice(&self.metadata_offset.to_le_bytes());
        pos += 8;

        buf[pos..][..8].copy_from_slice(&self.data_offset.to_le_bytes());

        // `pos` is not tracked further; `Ok(buf)` returns the zero-padded buffer
        // directly, and the HMAC covers `buf[..HEADER_SIZE - HMAC_LEN]`.
        Ok(buf)
    }

    /// Compute the raw HMAC-SHA512 over the pre-trailer bytes of `buf`.
    fn compute_mac(buf: &[u8; HEADER_SIZE], header_key: &[u8]) -> Result<[u8; HMAC_LEN]> {
        let mut mac = HmacSha512::new_from_slice(header_key).map_err(|_| FormatError::Hmac)?;
        mac.update(&buf[..HEADER_SIZE - HMAC_LEN]);
        let tag = mac.finalize().into_bytes();
        let mut out = [0u8; HMAC_LEN];
        out.copy_from_slice(&tag);
        Ok(out)
    }

    /// Serialize the header into the 8 KiB region, computing and embedding the
    /// HMAC-SHA512 trailer keyed by `header_key`.
    ///
    /// `header_key` is the header-MAC subkey, i.e.
    /// `subkeys::derive_subkey(master, b"header-mac", b"", 0)`.
    pub fn serialize(&self, header_key: &[u8]) -> Result<[u8; HEADER_SIZE]> {
        let mut buf = self.serialize_authenticated()?;
        let hmac = Self::compute_mac(&buf, header_key)?;
        buf[HEADER_SIZE - HMAC_LEN..].copy_from_slice(&hmac);
        Ok(buf)
    }

    /// Parse an 8 KiB header region **without** verifying the HMAC trailer.
    ///
    /// This is used when the master key (and therefore the header-MAC subkey)
    /// is not yet known — e.g. to read the salt and wrapped key so a vault can
    /// be unlocked. Always re-verify with [`Header::parse`]/[`Header::parse_verified`]
    /// once the master key is available.
    ///
    /// Returns an error if the buffer is not `HEADER_SIZE` bytes.
    pub fn parse_raw(buf: &[u8]) -> Result<Header> {
        if buf.len() != HEADER_SIZE {
            return Err(FormatError::InvalidLength {
                what: "header buffer",
                expected: HEADER_SIZE,
                got: buf.len(),
            });
        }
        let arr: [u8; HEADER_SIZE] = buf.try_into().map_err(|_| FormatError::InvalidLength {
            what: "header buffer",
            expected: HEADER_SIZE,
            got: buf.len(),
        })?;

        let mut pos = 0usize;
        let mut magic = [0u8; 4];
        magic.copy_from_slice(&arr[pos..][..MAGIC.len()]);
        pos += MAGIC.len();

        let version = u16::from_le_bytes(arr[pos..][..2].try_into().unwrap());
        pos += 2;

        let memory = memory_from_u8(arr[pos]).ok_or(FormatError::InvalidLength {
            what: "kdf memory",
            expected: 1,
            got: 1,
        })?;
        pos += 1;

        let t = u32::from_le_bytes(arr[pos..][..4].try_into().unwrap());
        pos += 4;

        let p = u32::from_le_bytes(arr[pos..][..4].try_into().unwrap());
        pos += 4;

        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&arr[pos..][..SALT_LEN]);
        pos += SALT_LEN;

        let wrapped_len =
            u32::from_le_bytes(arr[pos..][..WRAPPED_KEY_LEN_FIELD].try_into().unwrap()) as usize;
        pos += WRAPPED_KEY_LEN_FIELD;

        if wrapped_len > MAX_WRAPPED_KEY_LEN || pos + wrapped_len > HEADER_SIZE - HMAC_LEN {
            return Err(FormatError::InvalidLength {
                what: "wrapped key",
                expected: MAX_WRAPPED_KEY_LEN,
                got: wrapped_len,
            });
        }
        let wrapped_key = arr[pos..][..wrapped_len].to_vec();
        pos += wrapped_len;

        let active_slot = arr[pos];
        pos += 1;

        let metadata_offset = u64::from_le_bytes(arr[pos..][..8].try_into().unwrap());
        pos += 8;

        let data_offset = u64::from_le_bytes(arr[pos..][..8].try_into().unwrap());

        Ok(Header {
            magic,
            version,
            kdf_params: KdfParams { memory, t, p },
            salt,
            wrapped_key,
            active_slot,
            metadata_offset,
            data_offset,
            hmac: arr[HEADER_SIZE - HMAC_LEN..].try_into().unwrap(),
        })
    }

    /// Parse and authenticate an 8 KiB header region.
    ///
    /// Returns an error if the buffer is not `HEADER_SIZE` bytes or if the
    /// HMAC-SHA512 trailer does not match, so a tampered header is never
    /// trusted.
    pub fn parse(buf: &[u8], header_key: &[u8]) -> Result<Header> {
        let header = Self::parse_raw(buf)?;
        let arr: [u8; HEADER_SIZE] = buf.try_into().unwrap();
        if !constant_time_eq(
            &Self::compute_mac(&arr, header_key)?,
            &arr[HEADER_SIZE - HMAC_LEN..],
        ) {
            return Err(FormatError::Hmac);
        }
        Ok(header)
    }

    /// Parse and authenticate the header, then verify the magic and version.
    pub fn parse_verified(buf: &[u8], header_key: &[u8]) -> Result<Header> {
        let header = Self::parse(buf, header_key)?;
        if &header.magic != MAGIC {
            return Err(FormatError::InvalidLength {
                what: "magic",
                expected: MAGIC.len(),
                got: header.magic.len(),
            });
        }
        if header.version != VERSION {
            return Err(FormatError::InvalidLength {
                what: "version",
                expected: VERSION as usize,
                got: header.version as usize,
            });
        }
        Ok(header)
    }

    /// Recompute the HMAC trailer for this header and return it, matching what
    /// [`Header::serialize`] would have written.
    pub fn compute_hmac(&self, header_key: &[u8]) -> Result<[u8; HMAC_LEN]> {
        let buf = self.serialize_authenticated()?;
        Self::compute_mac(&buf, header_key)
    }

    /// The byte offset of the header slot identified by `slot` (0 or 1).
    pub fn slot_offset(slot: u8) -> u64 {
        (slot as u64) * crate::constants::HEADER_SIZE as u64
    }

    /// The index of the inactive slot relative to `active_slot`.
    pub fn inactive_slot(active_slot: u8) -> u8 {
        1 - active_slot
    }
}

/// Constant-time byte comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

/// Derive the header-MAC subkey from a master key.
///
/// The header-MAC subkey is an HKDF-SHA256 subkey (purpose `b"header-mac"`)
/// derived from the unwrapped master key, using an empty file id and index.
pub fn derive_header_key(master: &[u8]) -> Zeroizing<[u8; 32]> {
    autocipher_core::subkeys::derive_subkey(master, HEADER_MAC_PURPOSE, b"", 0)
}

#[cfg(test)]
mod tests {
    use autocipher_core::kdf::Memory;
    use autocipher_core::keywrap;

    use super::*;

    fn master() -> [u8; 32] {
        *keywrap::generate_master_key()
    }

    fn header_with(m: Memory, t: u32, p: u32, wrapped: Vec<u8>) -> (Header, Zeroizing<[u8; 32]>) {
        let master = Zeroizing::new(master());
        let key = derive_header_key(master.as_ref());
        let mut header = Header::default();
        header.salt = *b"01234567890123456789012345678901";
        header.kdf_params = KdfParams { memory: m, t, p };
        header.wrapped_key = wrapped;
        (header, key)
    }

    #[test]
    fn header_roundtrip_serialize_parse() {
        let (header, key) = header_with(Memory::M256, 4, 4, vec![7u8; 64]);
        let bytes = header.serialize(key.as_ref()).unwrap();
        assert_eq!(bytes.len(), HEADER_SIZE);

        let parsed = Header::parse(&bytes, key.as_ref()).unwrap();
        assert_eq!(&parsed.magic, MAGIC);
        assert_eq!(parsed.version, VERSION);
        assert_eq!(parsed.kdf_params, header.kdf_params);
        assert_eq!(parsed.salt, header.salt);
        assert_eq!(parsed.wrapped_key, header.wrapped_key);
        assert_eq!(parsed.active_slot, header.active_slot);
        assert_eq!(parsed.metadata_offset, header.metadata_offset);
        assert_eq!(parsed.data_offset, header.data_offset);
        // The parsed trailer must match what serialize computed, not the default
        // zeroed `hmac` on the in-memory header.
        assert_eq!(parsed.hmac, bytes[HEADER_SIZE - HMAC_LEN..]);
    }

    #[test]
    fn header_tamper_fails_hmac() {
        let (header, key) = header_with(Memory::M256, 4, 4, vec![7u8; 64]);
        let mut bytes = header.serialize(key.as_ref()).unwrap();

        // Flip a byte in the authenticated prefix region (not the trailer).
        let idx = 16usize;
        bytes[idx] ^= 0x01;

        assert!(matches!(
            Header::parse(&bytes, key.as_ref()),
            Err(FormatError::Hmac)
        ));
    }

    #[test]
    fn header_tamper_in_wrapped_key_fails_hmac() {
        let (header, key) = header_with(Memory::M512, 2, 1, vec![0xAA; 32]);
        let mut bytes = header.serialize(key.as_ref()).unwrap();

        // Locate where the wrapped key begins: FIXED_HEADER_LEN is private, but
        // we can find it by scanning; simplest is to tamper inside the region
        // just before the trailer which is guaranteed to be covered.
        bytes[HEADER_SIZE - HMAC_LEN - 1] ^= 0x01;

        assert!(matches!(
            Header::parse(&bytes, key.as_ref()),
            Err(FormatError::Hmac)
        ));
    }

    #[test]
    fn header_short_buffer_rejected() {
        let (header, key) = header_with(Memory::M256, 4, 4, vec![7u8; 64]);
        let bytes = header.serialize(key.as_ref()).unwrap();
        assert!(matches!(
            Header::parse(&bytes[..HEADER_SIZE - 1], key.as_ref()),
            Err(FormatError::InvalidLength { .. })
        ));
    }

    #[test]
    fn header_wrong_key_fails_hmac() {
        let (header, key) = header_with(Memory::M256, 4, 4, vec![7u8; 64]);
        let bytes = header.serialize(key.as_ref()).unwrap();

        let other_master = Zeroizing::new(master());
        let other_key = derive_header_key(other_master.as_ref());
        assert!(matches!(
            Header::parse(&bytes, other_key.as_ref()),
            Err(FormatError::Hmac)
        ));
    }

    #[test]
    fn header_serialized_size_and_zero_padding() {
        // The authenticated prefix must be zero-padded to HEADER_SIZE - HMAC_LEN.
        let (header, key) = header_with(Memory::M128, 1, 1, vec![9u8; 8]);
        let bytes = header.serialize(key.as_ref()).unwrap();
        assert_eq!(bytes.len(), HEADER_SIZE);

        // The HMAC region must equal the recomputed trailer.
        let recomputed = header.compute_hmac(key.as_ref()).unwrap();
        assert_eq!(&bytes[HEADER_SIZE - HMAC_LEN..], &recomputed[..]);

        // Verify the padding between the wrapped key and the trailer is zero.
        let wrapped_len = header.wrapped_key.len();
        // wrapped key + suffix ends at FIXED_HEADER_LEN + wrapped_len + HEADER_SUFFIX_LEN
        let end =
            4 + 2 + 1 + 4 + 4 + SALT_LEN + WRAPPED_KEY_LEN_FIELD + wrapped_len + HEADER_SUFFIX_LEN;
        for b in &bytes[end..HEADER_SIZE - HMAC_LEN] {
            assert_eq!(*b, 0u8);
        }
    }

    #[test]
    fn header_verify_rejects_bad_magic_or_version() {
        let (header, key) = header_with(Memory::M256, 4, 4, vec![3u8; 16]);

        let mut bytes = header.serialize(key.as_ref()).unwrap();
        bytes[0] = b'X';
        assert!(Header::parse_verified(&bytes, key.as_ref()).is_err());

        let (header2, key2) = header_with(Memory::M256, 4, 4, vec![3u8; 16]);
        let mut bytes2 = header2.serialize(key2.as_ref()).unwrap();
        bytes2[5] = 99u8; // bump version bytes
        assert!(Header::parse_verified(&bytes2, key2.as_ref()).is_err());
    }

    #[test]
    fn header_mac_subkey_reproducible() {
        let master = Zeroizing::new(master());
        let a = derive_header_key(master.as_ref());
        let b = derive_header_key(master.as_ref());
        assert_eq!(a.as_ref(), b.as_ref());
    }
}
