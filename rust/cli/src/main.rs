//! autocipher command-line entry point.

use std::path::PathBuf;
use std::process::ExitCode;

use autocipher_core::kdf::Memory;
use autocipher_core::password::{DEFAULT_PASSWORD_LEN, generate_password};
use clap::{Parser, Subcommand};

use autocipher_cli::commands;

#[derive(Parser)]
#[command(
    name = "autocipher",
    version,
    about = "Manage encrypted .ac vaults",
    long_about = "Encrypted single-file vaults (.ac): Argon2id-derived keys, \
                  AES-256-GCM-SIV content, and a FUSE/cloud-ready container."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new empty vault.
    Create {
        /// Path of the new .ac container to create.
        path: PathBuf,
        /// Argon2id memory cost in MiB: 128, 256, or 512 (default 256).
        #[arg(long, default_value = "256", value_parser = parse_memory_arg)]
        memory: Memory,
        /// Argon2id iteration (time) cost (default 4).
        #[arg(long, default_value_t = 4)]
        t: u32,
        /// Argon2id parallelism (lanes) (default 4).
        #[arg(long, default_value_t = 4)]
        p: u32,
        /// Generate a random password instead of prompting; printed to stdout.
        #[arg(long)]
        generate_password: bool,
    },
    /// Unlock a vault and print a summary.
    Unlock {
        /// Path of the .ac container to unlock.
        path: PathBuf,
    },
    /// List the file names stored in a vault.
    List {
        /// Path of the .ac container to list.
        path: PathBuf,
    },
    /// Encrypt and add a file or a whole folder tree to a vault.
    Add {
        /// Path of the .ac container.
        path: PathBuf,
        /// Plaintext file or directory to encrypt and store. A directory is
        /// walked recursively; each file is stored under its relative subpath.
        file: PathBuf,
    },
    /// Extract a file from a vault to disk.
    Extract {
        /// Path of the .ac container.
        path: PathBuf,
        /// Plaintext name of the stored file to extract.
        name: String,
        /// Destination path for the decrypted output.
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Re-wrap the master key under a new password.
    ChangePassword {
        /// Path of the .ac container.
        path: PathBuf,
        /// Argon2id memory cost in MiB for the new KEK (default 256).
        #[arg(long, default_value = "256", value_parser = parse_memory_arg)]
        memory: Memory,
        /// Argon2id iteration (time) cost (default 4).
        #[arg(long, default_value_t = 4)]
        t: u32,
        /// Argon2id parallelism (lanes) (default 4).
        #[arg(long, default_value_t = 4)]
        p: u32,
        /// Generate a random new password instead of prompting; printed to stdout.
        #[arg(long)]
        generate_password: bool,
    },
    /// Print header, KDF, and integrity/anchor state.
    Info {
        /// Path of the .ac container.
        path: PathBuf,
    },
    /// Rewrite the archive, dropping stale/freed data.
    Compact {
        /// Path of the .ac container.
        path: PathBuf,
    },
    /// Regenerate the header/metadata mirror files beside a vault.
    Remirror {
        /// Path of the .ac container.
        path: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("autocipher: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(command: Command) -> autocipher_format::Result<()> {
    match command {
        Command::Create {
            path,
            memory,
            t,
            p,
            generate_password: generated,
        } => {
            let password = if generated {
                let pw = generate_password(DEFAULT_PASSWORD_LEN);
                println!("generated password: {pw}");
                pw.into_bytes()
            } else {
                commands::resolve_password("Password: ")?
            };
            let vault = commands::create(&path, &password, memory, t, p)?;
            println!(
                "created {} (generation {}, kdf {} MiB, t={}, p={})",
                path.display(),
                vault.generation(),
                mib(memory),
                t,
                p
            );
        }
        Command::Unlock { path } => {
            let password = commands::resolve_password("Password: ")?;
            let vault = commands::unlock(&path, &password)?;
            let files = vault.list()?.len();
            println!(
                "unlocked {} (generation {}, kdf {} MiB, {} file(s))",
                path.display(),
                vault.generation(),
                mib(vault.kdf_params().memory),
                files
            );
        }
        Command::List { path } => {
            let password = commands::resolve_password("Password: ")?;
            let vault = commands::unlock(&path, &password)?;
            for name in commands::list(&vault)? {
                println!("{name}");
            }
        }
        Command::Add { path, file } => {
            let password = commands::resolve_password("Password: ")?;
            let mut vault = commands::unlock(&path, &password)?;
            let count = commands::add_path(&mut vault, &file)?;
            println!(
                "added {count} file(s) from {} in {}",
                file.display(),
                path.display()
            );
        }
        Command::Extract { path, name, output } => {
            let password = commands::resolve_password("Password: ")?;
            let vault = commands::unlock(&path, &password)?;
            commands::extract(&vault, &name, &output)?;
            println!(
                "extracted {name} -> {} ({} bytes)",
                output.display(),
                file_size(&output)?
            );
        }
        Command::ChangePassword {
            path,
            memory,
            t,
            p,
            generate_password: generated,
        } => {
            let password = commands::resolve_password("Current password: ")?;
            let mut vault = commands::unlock(&path, &password)?;
            let new_password = if generated {
                let pw = generate_password(DEFAULT_PASSWORD_LEN);
                println!("generated password: {pw}");
                pw.into_bytes()
            } else {
                commands::resolve_new_password("New password: ")?
            };
            commands::change_password(&mut vault, &new_password, memory, t, p)?;
            println!("changed password for {}", path.display());
        }
        Command::Info { path } => {
            let password = commands::resolve_password("Password: ")?;
            let vault = commands::unlock(&path, &password)?;
            let i = commands::info(&vault)?;
            println!("path:            {}", i.path);
            println!("version:         {}", i.version);
            println!(
                "kdf:             {} MiB, t={}, p={}",
                i.memory_mib, i.t, i.p
            );
            println!("generation:      {}", i.generation);
            println!("files:           {}", i.files);
            println!("size:            {} bytes", i.size_bytes);
            println!(
                "garbage:         {} bytes ({:.1}%)",
                i.garbage_bytes,
                i.garbage_ratio * 100.0
            );
            println!("header mirror:   {}", i.header_mirror);
            println!("metadata mirror: {}", i.metadata_mirror);
        }
        Command::Compact { path } => {
            let password = commands::resolve_password("Password: ")?;
            let mut vault = commands::unlock(&path, &password)?;
            commands::compact(&mut vault)?;
            println!(
                "compacted {} (generation {}, {} file(s))",
                path.display(),
                vault.generation(),
                vault.list()?.len()
            );
        }
        Command::Remirror { path } => {
            let password = commands::resolve_password("Password: ")?;
            let vault = commands::unlock(&path, &password)?;
            commands::remirror(&vault)?;
            println!(
                "regenerated mirrors for {} ({} and {})",
                path.display(),
                autocipher_format::mirror::header_mirror_path(&path).display(),
                autocipher_format::mirror::metadata_mirror_path(&path).display()
            );
        }
    }
    Ok(())
}

/// clap value parser for the `--memory` flag.
fn parse_memory_arg(s: &str) -> Result<Memory, String> {
    commands::parse_memory(s)
}

/// Memory preset name in MiB for display.
fn mib(memory: Memory) -> u32 {
    match memory {
        Memory::M128 => 128,
        Memory::M256 => 256,
        Memory::M512 => 512,
    }
}

/// Length of the file at `path` in bytes.
fn file_size(path: &std::path::Path) -> autocipher_format::Result<u64> {
    Ok(std::fs::metadata(path)?.len())
}
