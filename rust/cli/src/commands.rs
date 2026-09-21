//! Command implementations for the autocipher CLI.
//!
//! Thin wrappers over the `autocipher-format` [`Vault`] API, kept separate from
//! the clap parsing in `main.rs` so they stay unit-testable without spawning a
//! binary.

use std::path::{Path, PathBuf};

use autocipher_core::kdf::{KdfParams, Memory};
use autocipher_format::mirror::{header_mirror_path, metadata_mirror_path};
use autocipher_format::{FormatError, Result, VERSION, Vault};

/// Default reference for `--memory`: 256 MiB (matches the format default).
pub const DEFAULT_MEMORY_MIB: u32 = 256;

/// Create a new empty vault at `path`.
pub fn create(path: &Path, password: &[u8], memory: Memory, t: u32, p: u32) -> Result<Vault> {
    let params = KdfParams { memory, t, p };
    Vault::create(path, password, params)
}

/// Unlock an existing vault at `path`, returning an open handle.
pub fn unlock(path: &Path, password: &[u8]) -> Result<Vault> {
    Vault::open(path, password)
}

/// List the plaintext file names stored in `vault`, sorted.
pub fn list(vault: &Vault) -> Result<Vec<String>> {
    let mut names = vault.list()?;
    names.sort();
    Ok(names)
}

/// Encrypt `src` and add it to `vault`, returning the stored plaintext name.
pub fn add(vault: &mut Vault, src: &Path) -> Result<String> {
    vault.add_file(src)
}

/// Encrypt and add `src` to `vault`: a regular file is stored under its base
/// filename, while a directory is walked recursively and every file inside is
/// stored under its path relative to the chosen directory (so folder structure
/// is preserved in the stored names). Symlinks are skipped. The whole tree is
/// added in a single commit, so an oversize/metadata failure is atomic rather
/// than leaving a partial import. Returns the number of files added.
pub fn add_path(vault: &mut Vault, src: &Path) -> Result<usize> {
    if src.is_dir() {
        let mut items: Vec<(PathBuf, String)> = Vec::new();
        walk_dir(src, &mut |file, relative| {
            items.push((file.to_path_buf(), relative.to_string()));
            Ok(())
        })?;
        vault.add_paths(&items)
    } else {
        vault.add_file(src)?;
        Ok(1)
    }
}

/// Depth-first walk of `root`, invoking `visit(file, relative)` for every
/// regular file (skipping directories and symlinks). `relative` uses `/` as the
/// separator so stored names are portable regardless of the host OS.
fn walk_dir(root: &Path, visit: &mut dyn FnMut(&Path, &str) -> Result<()>) -> Result<()> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                stack.push(path);
            } else if file_type.is_file() {
                let relative = path
                    .strip_prefix(root)
                    .map_err(|_| {
                        FormatError::Io(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "walk escaped the selected directory",
                        ))
                    })?
                    .to_string_lossy()
                    .replace('\\', "/");
                visit(&path, &relative)?;
            }
        }
    }
    Ok(())
}

/// Extract the file named `name` from `vault` to `dest`.
pub fn extract(vault: &Vault, name: &str, dest: &Path) -> Result<()> {
    vault.extract(name, dest)
}

/// Re-wrap the vault's master key under `new_password` with the given KDF cost.
pub fn change_password(
    vault: &mut Vault,
    new_password: &[u8],
    memory: Memory,
    t: u32,
    p: u32,
) -> Result<()> {
    let params = KdfParams { memory, t, p };
    vault.change_password(new_password, params)
}

/// Rewrite the whole container, dropping stale/freed data.
pub fn compact(vault: &mut Vault) -> Result<()> {
    vault.compact()
}

/// Regenerate the mirror files beside the primary container.
pub fn remirror(vault: &Vault) -> Result<()> {
    vault.remirror()
}

/// A read-only snapshot of a vault's header and integrity state.
pub struct VaultInfo {
    /// On-disk format version.
    pub version: u16,
    /// Container path.
    pub path: String,
    /// Argon2id memory cost in MiB.
    pub memory_mib: u32,
    /// Argon2id iteration cost.
    pub t: u32,
    /// Argon2id parallelism.
    pub p: u32,
    /// Current generation (integrity/anchor).
    pub generation: u64,
    /// Number of stored files.
    pub files: usize,
    /// Whether the header mirror exists.
    pub header_mirror: bool,
    /// Whether the metadata mirror exists.
    pub metadata_mirror: bool,
    /// Size of the primary container in bytes.
    pub size_bytes: u64,
    /// Unreferenced garbage bytes in the container (stale metadata + freed data).
    pub garbage_bytes: u64,
    /// Fraction of the container that is unreferenced garbage.
    pub garbage_ratio: f64,
}

/// Collect header and integrity state for `vault`.
pub fn info(vault: &Vault) -> Result<VaultInfo> {
    let kdf = vault.kdf_params();
    let memory_mib = match kdf.memory {
        Memory::M128 => 128,
        Memory::M256 => 256,
        Memory::M512 => 512,
    };
    Ok(VaultInfo {
        version: VERSION,
        path: vault.path().display().to_string(),
        memory_mib,
        t: kdf.t,
        p: kdf.p,
        generation: vault.generation(),
        files: vault.list()?.len(),
        header_mirror: header_mirror_path(vault.path()).exists(),
        metadata_mirror: metadata_mirror_path(vault.path()).exists(),
        size_bytes: std::fs::metadata(vault.path())?.len(),
        garbage_bytes: vault.garbage_bytes()?,
        garbage_ratio: vault.garbage_ratio()?,
    })
}

/// Map a `--memory` value in MiB to the matching [`Memory`] preset.
pub fn parse_memory(mib: &str) -> std::result::Result<Memory, String> {
    match mib {
        "128" => Ok(Memory::M128),
        "256" => Ok(Memory::M256),
        "512" => Ok(Memory::M512),
        other => Err(format!(
            "invalid memory cost `{other}` MiB; choose 128, 256, or 512"
        )),
    }
}

/// Resolve the password: `AUTOCIPHER_PASSWORD` env var when set (for scripting
/// and tests), otherwise prompt on the controlling terminal.
pub fn resolve_password(prompt: &str) -> Result<Vec<u8>> {
    if let Ok(p) = std::env::var("AUTOCIPHER_PASSWORD") {
        return Ok(p.into_bytes());
    }
    eprint!("{prompt}");
    rpassword::read_password()
        .map(|s| s.into_bytes())
        .map_err(FormatError::Io)
}

/// Resolve a new password for `change-password`: `AUTOCIPHER_NEW_PASSWORD` env
/// var when set, otherwise prompt on the controlling terminal.
pub fn resolve_new_password(prompt: &str) -> Result<Vec<u8>> {
    if let Ok(p) = std::env::var("AUTOCIPHER_NEW_PASSWORD") {
        return Ok(p.into_bytes());
    }
    eprint!("{prompt}");
    rpassword::read_password()
        .map(|s| s.into_bytes())
        .map_err(FormatError::Io)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    const PASSWORD: &[u8] = b"correct horse battery staple";

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "autocipher-cli-{}-{}-{}",
            tag,
            std::process::id(),
            n
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn create_and_list_empty_roundtrip() {
        let dir = temp_dir("create");
        let vault_path = dir.join("vault.ac");
        let v = create(&vault_path, PASSWORD, Memory::M128, 1, 1).unwrap();
        assert!(list(&v).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unlock_wrong_password_rejected() {
        let dir = temp_dir("unlock");
        let vault_path = dir.join("vault.ac");
        create(&vault_path, PASSWORD, Memory::M128, 1, 1).unwrap();

        assert!(unlock(&vault_path, PASSWORD).is_ok());
        assert!(unlock(&vault_path, b"wrong password").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_returns_sorted_names() {
        let dir = temp_dir("list");
        let vault_path = dir.join("vault.ac");
        let mut v = create(&vault_path, PASSWORD, Memory::M128, 1, 1).unwrap();
        let _ = std::fs::write(dir.join("zebra.txt"), b"hi");
        let _ = std::fs::write(dir.join("apple.txt"), b"hi");
        v.add_file(dir.join("zebra.txt").to_str().unwrap()).unwrap();
        v.add_file(dir.join("apple.txt").to_str().unwrap()).unwrap();

        assert_eq!(
            list(&v).unwrap(),
            vec!["apple.txt".to_string(), "zebra.txt".to_string()]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_memory_accepts_presets() {
        assert_eq!(parse_memory("128"), Ok(Memory::M128));
        assert_eq!(parse_memory("256"), Ok(Memory::M256));
        assert_eq!(parse_memory("512"), Ok(Memory::M512));
        assert!(parse_memory("42").is_err());
    }

    #[test]
    fn add_extract_roundtrip() {
        let dir = temp_dir("add_extract");
        let vault_path = dir.join("vault.ac");
        let src = dir.join("report.txt");
        let dest = dir.join("out.bin");
        let payload: Vec<u8> = (0u32..300_000).map(|i| (i % 251) as u8).collect();
        std::fs::write(&src, &payload).unwrap();

        let mut v = create(&vault_path, PASSWORD, Memory::M128, 1, 1).unwrap();
        let added = add(&mut v, &src).unwrap();
        assert_eq!(added, "report.txt");
        assert_eq!(list(&v).unwrap(), vec!["report.txt".to_string()]);

        extract(&v, "report.txt", &dest).unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), payload);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn add_path_walks_directory_keeping_relative_subpaths() {
        let dir = temp_dir("add_path");
        let vault_path = dir.join("vault.ac");
        let tree = dir.join("tree");
        std::fs::create_dir_all(tree.join("photos/beach")).unwrap();
        std::fs::create_dir_all(tree.join("docs")).unwrap();
        std::fs::write(tree.join("photos/beach/1.jpg"), b"jpeg").unwrap();
        std::fs::write(tree.join("photos/beach/2.jpg"), b"jpeg2").unwrap();
        std::fs::write(tree.join("docs/readme.md"), b"# hi").unwrap();
        std::fs::write(tree.join("top.txt"), b"top").unwrap();

        let mut v = create(&vault_path, PASSWORD, Memory::M128, 1, 1).unwrap();
        let count = add_path(&mut v, &tree).unwrap();
        assert_eq!(count, 4);

        // Stored names preserve the folder structure with `/` separators.
        assert_eq!(
            list(&v).unwrap(),
            vec![
                "docs/readme.md".to_string(),
                "photos/beach/1.jpg".to_string(),
                "photos/beach/2.jpg".to_string(),
                "top.txt".to_string(),
            ]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn add_path_stores_a_single_file_by_basename() {
        let dir = temp_dir("add_path_file");
        let vault_path = dir.join("vault.ac");
        let src = dir.join("single.bin");
        std::fs::write(&src, b"data").unwrap();

        let mut v = create(&vault_path, PASSWORD, Memory::M128, 1, 1).unwrap();
        let count = add_path(&mut v, &src).unwrap();
        assert_eq!(count, 1);
        assert_eq!(list(&v).unwrap(), vec!["single.bin".to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn add_extract_reopens_and_matches() {
        let dir = temp_dir("reopen");
        let vault_path = dir.join("vault.ac");
        let src = dir.join("blob.bin");
        let dest = dir.join("out.bin");
        let payload = vec![7u8; 200_000];

        std::fs::write(&src, &payload).unwrap();

        {
            let mut v = create(&vault_path, PASSWORD, Memory::M128, 1, 1).unwrap();
            add(&mut v, &src).unwrap();
        }
        // A fresh session must be able to extract identical bytes.
        let v = unlock(&vault_path, PASSWORD).unwrap();
        extract(&v, "blob.bin", &dest).unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), payload);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn extract_missing_file_fails_cleanly() {
        let dir = temp_dir("extract_missing");
        let vault_path = dir.join("vault.ac");
        let v = create(&vault_path, PASSWORD, Memory::M128, 1, 1).unwrap();
        let err = extract(&v, "ghost.txt", &dir.join("out.bin")).unwrap_err();
        assert!(err.to_string().contains("not found"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn change_password_old_fails_new_works() {
        let dir = temp_dir("chpwd");
        let vault_path = dir.join("vault.ac");
        let src = dir.join("doc.txt");
        std::fs::write(&src, b"secrets").unwrap();

        let mut v = create(&vault_path, b"old pass", Memory::M128, 1, 1).unwrap();
        add(&mut v, &src).unwrap();
        change_password(&mut v, b"new pass", Memory::M256, 1, 1).unwrap();
        drop(v);

        assert!(unlock(&vault_path, b"old pass").is_err());
        let v = unlock(&vault_path, b"new pass").unwrap();
        assert_eq!(list(&v).unwrap(), vec!["doc.txt".to_string()]);
        let out = dir.join("out.txt");
        extract(&v, "doc.txt", &out).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), b"secrets".to_vec());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn generated_password_create_and_change_roundtrip() {
        use autocipher_core::password::{DEFAULT_PASSWORD_LEN, generate_password};

        let dir = temp_dir("genpwd");
        let vault_path = dir.join("vault.ac");

        let generated = generate_password(DEFAULT_PASSWORD_LEN);
        assert!(generated.len() == DEFAULT_PASSWORD_LEN);

        let v = create(&vault_path, generated.as_bytes(), Memory::M128, 1, 1).unwrap();
        drop(v);

        // The generated password unlocks the vault.
        let v = unlock(&vault_path, generated.as_bytes()).unwrap();
        assert!(list(&v).unwrap().is_empty());
        drop(v);

        // Generate a new one for a change-password roundtrip.
        let new_gen = generate_password(DEFAULT_PASSWORD_LEN);
        let mut v = unlock(&vault_path, generated.as_bytes()).unwrap();
        change_password(&mut v, new_gen.as_bytes(), Memory::M128, 1, 1).unwrap();
        drop(v);

        assert!(unlock(&vault_path, generated.as_bytes()).is_err());
        assert!(unlock(&vault_path, new_gen.as_bytes()).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn info_reports_header_state() {
        let dir = temp_dir("info");
        let vault_path = dir.join("vault.ac");
        let src = dir.join("f.txt");
        std::fs::write(&src, b"data").unwrap();

        let mut v = create(&vault_path, PASSWORD, Memory::M128, 1, 1).unwrap();
        add(&mut v, &src).unwrap();

        let i = info(&v).unwrap();
        assert_eq!(i.version, autocipher_format::constants::VERSION);
        assert_eq!(i.memory_mib, 128);
        assert_eq!(i.t, 1);
        assert_eq!(i.p, 1);
        assert_eq!(i.generation, 2);
        assert_eq!(i.files, 1);
        assert!(i.header_mirror);
        assert!(i.metadata_mirror);
        assert!(i.size_bytes > 0);
        assert!(i.garbage_bytes < i.size_bytes);
        assert!(i.garbage_ratio >= 0.0 && i.garbage_ratio < 0.5);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn compact_preserves_contents() {
        let dir = temp_dir("compact");
        let vault_path = dir.join("vault.ac");
        let src = dir.join("keep.txt");
        std::fs::write(&src, b"keep me").unwrap();

        let mut v = create(&vault_path, PASSWORD, Memory::M128, 1, 1).unwrap();
        add(&mut v, &src).unwrap();
        compact(&mut v).unwrap();

        let v = unlock(&vault_path, PASSWORD).unwrap();
        assert_eq!(list(&v).unwrap(), vec!["keep.txt".to_string()]);
        let out = dir.join("out.txt");
        extract(&v, "keep.txt", &out).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), b"keep me".to_vec());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
