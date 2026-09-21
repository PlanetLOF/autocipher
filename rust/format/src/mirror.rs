//! Atomic header and metadata mirrors.
//!
//! The `.ac` container keeps two recoverable artifacts: the 8 KiB authenticated
//! [`crate::header`] and the sealed metadata (encrypted JSON manifest) payload.
//! [`write_mirrors`] durably mirrors both beside the container via a
//! write-temp-then-rename sequence, so a crash or torn write never leaves a
//! partially-written mirror. [`read_mirrors`] reads those mirrors back so a lost
//! primary can be restored.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::error::{FormatError, Result};

/// Suffix appended to the container path for the header mirror file.
pub const HEADER_MIRROR_SUFFIX: &str = ".mirror.header";
/// Suffix appended to the container path for the metadata mirror file.
pub const METADATA_MIRROR_SUFFIX: &str = ".mirror.metadata";
/// Suffix for the temporary file used during atomic rotation.
const TEMP_SUFFIX: &str = ".tmp";

/// Mirror path for the header of the container at `base`.
pub fn header_mirror_path(base: &Path) -> PathBuf {
    let mut p = base.as_os_str().to_owned();
    p.push(HEADER_MIRROR_SUFFIX);
    PathBuf::from(p)
}

/// Mirror path for the metadata of the container at `base`.
pub fn metadata_mirror_path(base: &Path) -> PathBuf {
    let mut p = base.as_os_str().to_owned();
    p.push(METADATA_MIRROR_SUFFIX);
    PathBuf::from(p)
}

/// Atomically write `data` to `path` via a temp file + rename.
///
/// The data is written to a sibling temp file derived from `path`, fsynced, then
/// renamed over `path`. Rename is atomic on the same filesystem, so a reader
/// never observes a torn/partial file: they see either the previous complete
/// contents or the new complete contents.
fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(TEMP_SUFFIX);
    let tmp = PathBuf::from(tmp);

    {
        let mut f = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp)?;
        f.write_all(data)?;
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

/// Duably write the header and metadata mirrors beside the container at `base`.
///
/// `header` is the serialized 8 KiB header region (its own HMAC trailer
/// authenticates it); `metadata` is the sealed metadata payload. Both are copied
/// verbatim.
pub fn write_mirrors(base: &Path, header: &[u8], metadata: &[u8]) -> Result<()> {
    atomic_write(&header_mirror_path(base), header)?;
    atomic_write(&metadata_mirror_path(base), metadata)?;
    Ok(())
}

/// Read the header and metadata mirrors back, returning `(header, metadata)`.
///
/// Errors with [`FormatError::NotFound`] if either mirror is missing.
pub fn read_mirrors(base: &Path) -> Result<(Vec<u8>, Vec<u8>)> {
    let header = std::fs::read(header_mirror_path(base)).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            FormatError::NotFound(HEADER_MIRROR_SUFFIX.into())
        } else {
            FormatError::Io(e)
        }
    })?;
    let metadata = std::fs::read(metadata_mirror_path(base)).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            FormatError::NotFound(METADATA_MIRROR_SUFFIX.into())
        } else {
            FormatError::Io(e)
        }
    })?;
    Ok((header, metadata))
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn temp_dir(tag: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "autocipher-mirror-{}-{}-{}",
            tag,
            std::process::id(),
            n
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn mirror_write_read_roundtrip() {
        let dir = temp_dir("roundtrip");
        let base = dir.join("vault.ac");
        let header = vec![0xAAu8; 8192];
        let metadata = vec![0xBBu8; 100];

        write_mirrors(&base, &header, &metadata).unwrap();
        let (h, m) = read_mirrors(&base).unwrap();
        assert_eq!(h, header);
        assert_eq!(m, metadata);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mirror_rotation_is_atomic_old_or_new() {
        let dir = temp_dir("atomic");
        let base = dir.join("vault.ac");

        let header_a = vec![0x11u8; 8192];
        let header_b = vec![0x22u8; 8192];
        let meta_a = vec![0x33u8; 64];
        let meta_b = vec![0x44u8; 128];

        write_mirrors(&base, &header_a, &meta_a).unwrap();
        write_mirrors(&base, &header_b, &meta_b).unwrap();

        // After the rotation completes, the mirror holds exactly the new data,
        // and never a partial mixture of the two writes.
        let (h, m) = read_mirrors(&base).unwrap();
        assert!(h == header_a || h == header_b);
        assert!(m == meta_a || m == meta_b);
        assert_eq!(h, header_b);
        assert_eq!(m, meta_b);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mirror_leftover_temp_does_not_corrupt_read() {
        let dir = temp_dir("temp");
        let base = dir.join("vault.ac");
        let header = vec![0x77u8; 8192];
        let metadata = vec![0x88u8; 32];

        write_mirrors(&base, &header, &metadata).unwrap();

        // Simulate an aborted write: a stale temp file with partial garbage that
        // never got renamed over the real mirror.
        let mut stale = header_mirror_path(&base).as_os_str().to_owned();
        stale.push(TEMP_SUFFIX);
        File::create(PathBuf::from(stale))
            .unwrap()
            .write_all(b"garbage")
            .unwrap();

        // Reads still return the committed mirror, not the stale temp.
        let (h, m) = read_mirrors(&base).unwrap();
        assert_eq!(h, header);
        assert_eq!(m, metadata);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mirror_restore_after_primary_loss() {
        let dir = temp_dir("restore");
        let base = dir.join("vault.ac");
        let header = vec![0x01u8; 8192];
        let metadata: Vec<u8> = (0u8..64).collect();

        // Write the mirrors, then "lose" the primary container.
        write_mirrors(&base, &header, &metadata).unwrap();

        // Restore the primary from the mirrors (this is what recover.rs will do).
        let (h, m) = read_mirrors(&base).unwrap();
        let mut primary = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&base)
            .unwrap();
        primary.write_all(&h).unwrap();
        primary.write_all(&m).unwrap();
        primary.sync_all().unwrap();
        drop(primary);

        let restored = std::fs::read(&base).unwrap();
        assert_eq!(restored[..8192], header[..]);
        assert_eq!(restored[8192..], metadata[..]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mirror_read_missing_reports_not_found() {
        let dir = temp_dir("missing");
        let base = dir.join("vault.ac");
        let err = read_mirrors(&base).unwrap_err();
        assert!(matches!(err, FormatError::NotFound(_)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mirror_write_no_temp_left() {
        let dir = temp_dir("notmp");
        let base = dir.join("vault.ac");
        write_mirrors(&base, &[1u8; 64], &[2u8; 64]).unwrap();
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp file should be cleaned up: {leftovers:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
