//! Auto-restore of a lost or corrupt primary container from its mirrors.
//!
//! The `.ac` container keeps a durable sidecar metadata mirror written
//! atomically by [`crate::mirror`]. If the primary container is missing,
//! truncated, or fails to authenticate, [`restore_if_needed`] rebuilds it from
//! that mirror plus the header mirror so an open can proceed.
//!
//! Recovery restores the container's *structure* (the two-slot header region and
//! the sealed metadata region), preserving the header's recorded metadata/data
//! offsets via zero-padding. Encrypted file *data* lives only in the primary and
//! is never mirrored, so data contents are not recovered — `extract` on a
//! pre-existing file fails cleanly after a restore.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use crate::constants::{HEADER_REGION_SIZE, HEADER_SIZE, HMAC_LEN, MAGIC};
use crate::error::{FormatError, Result};
use crate::header::Header;
use crate::mirror::{header_mirror_path, read_mirrors};

/// If the primary `.ac` container at `base` is missing or unusable, restore it
/// from the header + metadata mirrors written by [`crate::mirror::write_mirrors`].
///
/// A primary is considered unusable when it does not start with the four-byte
/// [`MAGIC`]. In that case, if both mirrors exist, the primary is reconstructed
/// with the mirrored header in slot 0, a zeroed slot 1, and the mirrored
/// metadata placed at the header's recorded offset (padded with zeros). This is
/// done via an atomic temp-write + rename so a crash never leaves a torn
/// primary. When the primary is healthy (magic present) this is a no-op.
///
/// Errors with [`FormatError::NotFound`] when the primary is unusable and no
/// (complete) mirror set is available.
pub fn restore_if_needed(base: &Path) -> Result<()> {
    if primary_usable(base) {
        return Ok(());
    }

    let (header, metadata) = read_mirrors(base)?;

    if header.len() != HEADER_SIZE {
        return Err(FormatError::InvalidLength {
            what: "header mirror",
            expected: HEADER_SIZE,
            got: header.len(),
        });
    }
    if &header[..MAGIC.len()] != MAGIC {
        return Err(FormatError::NotFound(
            header_mirror_path(base).display().to_string(),
        ));
    }
    if metadata.len() < HMAC_LEN {
        return Err(FormatError::InvalidLength {
            what: "metadata mirror",
            expected: HMAC_LEN,
            got: metadata.len(),
        });
    }

    let meta_off = Header::parse_raw(&header)
        .map(|h| h.metadata_offset)
        .unwrap_or(HEADER_REGION_SIZE as u64);

    // Place slot 0 = mirrored header, slot 1 = zeros, then zero-pad to the
    // recorded metadata offset, then the metadata region itself. The data area
    // is intentionally absent (recovery does not recover file contents).
    let end = (meta_off as usize).saturating_add(metadata.len());
    let mut data = vec![0u8; end.max(HEADER_REGION_SIZE)];
    data[..HEADER_SIZE].copy_from_slice(&header);
    let meta_start = meta_off as usize;
    data[meta_start..meta_start + metadata.len()].copy_from_slice(&metadata);

    atomic_write_primary(base, &data)
}

/// Whether the primary container currently looks usable (starts with the magic).
fn primary_usable(base: &Path) -> bool {
    let mut f = match std::fs::File::open(base) {
        Ok(f) => f,
        Err(_) => return false,
    };
    use std::io::Read;
    let mut magic = [0u8; MAGIC.len()];
    if f.read_exact(&mut magic).is_err() {
        return false;
    }
    &magic == MAGIC
}

/// Atomically write `data` over the primary container via temp file + rename.
fn atomic_write_primary(base: &Path, data: &[u8]) -> Result<()> {
    let mut tmp = base.as_os_str().to_owned();
    tmp.push(".restore.tmp");
    let tmp = std::path::PathBuf::from(tmp);

    {
        let mut f = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    match std::fs::rename(&tmp, base) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(FormatError::Io(e))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::constants::HEADER_REGION_SIZE;
    use crate::mirror::write_mirrors;

    use super::*;

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "autocipher-recover-{}-{}-{}",
            tag,
            std::process::id(),
            n
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn restore_noop_when_primary_healthy() {
        let dir = temp_dir("healthy");
        let base = dir.join("vault.ac");
        let mut f = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&base)
            .unwrap();
        f.write_all(MAGIC).unwrap();
        f.write_all(&[0u8; 100]).unwrap();
        drop(f);

        let before = std::fs::read(&base).unwrap();
        restore_if_needed(&base).unwrap();
        let after = std::fs::read(&base).unwrap();
        assert_eq!(before, after);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn restore_rebuilds_primary_from_mirrors() {
        let dir = temp_dir("rebuild");
        let base = dir.join("vault.ac");

        // Build a real header whose metadata_offset defaults after the region.
        let h = crate::header::Header::default();
        let header_key = vec![0u8; 32];
        let header = h.serialize(&header_key).unwrap().to_vec();
        let metadata: Vec<u8> = (0u8..200).collect();

        // Write mirrors, leave primary absent.
        write_mirrors(&base, &header, &metadata).unwrap();

        restore_if_needed(&base).unwrap();
        let restored = std::fs::read(&base).unwrap();
        assert!(restored.len() >= HEADER_REGION_SIZE);
        assert_eq!(&restored[..HEADER_SIZE], &header[..]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn restore_noop_if_primary_has_magic() {
        let dir = temp_dir("hasmagic");
        let base = dir.join("vault.ac");
        let mut f = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&base)
            .unwrap();
        f.write_all(MAGIC).unwrap();
        f.write_all(&[0xAB; 64]).unwrap();
        drop(f);
        let before = std::fs::read(&base).unwrap();
        restore_if_needed(&base).unwrap();
        assert_eq!(std::fs::read(&base).unwrap(), before);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn restore_missing_mirrors_reports_not_found() {
        let dir = temp_dir("nomirror");
        let base = dir.join("vault.ac");
        // Primary absent and mirrors absent.
        let err = restore_if_needed(&base).unwrap_err();
        assert!(matches!(err, FormatError::NotFound(_)));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
