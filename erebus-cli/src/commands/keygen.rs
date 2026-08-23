use anyhow::{Context, Result};
use clap::Args;
use ed25519_dalek::SigningKey;
use erebus_core::paths::default_key_dir;
use rand::rngs::OsRng;
use std::path::PathBuf;
use zeroize::Zeroizing;

#[derive(Args)]
pub struct KeygenArgs {
    /// Directory to write keys to
    #[arg(long, default_value = ".")]
    pub key_dir: PathBuf,

    /// Quiet output
    #[arg(short, long)]
    pub quiet: bool,

    /// Force overwrite existing keys
    #[arg(short, long)]
    pub force: bool,

    /// Output result as JSON
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: KeygenArgs) -> Result<()> {
    let key_dir = if args.key_dir == PathBuf::from(".") {
        default_key_dir()
    } else {
        args.key_dir.clone()
    };

    std::fs::create_dir_all(&key_dir)
        .with_context(|| format!("failed to create key directory {}", key_dir.display()))?;

    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let fingerprint = hex::encode(verifying_key.as_bytes());

    let key_path = key_dir.join(format!("{fingerprint}.key"));
    let pub_path = key_dir.join(format!("{fingerprint}.pub"));

    if key_path.exists() || pub_path.exists() {
        if args.force {
            std::fs::remove_file(&key_path).ok();
            std::fs::remove_file(&pub_path).ok();
        } else {
            anyhow::bail!(
                "key pair already exists at {}. Use --force to overwrite",
                key_dir.display()
            );
        }
    }

    let key_bytes = Zeroizing::new(signing_key.to_bytes());
    write_private_key(&key_path, &*key_bytes)
        .with_context(|| format!("failed to write private key to {}", key_path.display()))?;
    std::fs::write(&pub_path, verifying_key.as_bytes())
        .with_context(|| format!("failed to write public key to {}", pub_path.display()))?;

    #[cfg(unix)]
    debug_assert_private_mode(&key_path)?;

    if args.json {
        let info = serde_json::json!({
            "fingerprint": fingerprint,
            "private_key": key_path.display().to_string(),
            "public_key": pub_path.display().to_string(),
        });
        println!("{}", serde_json::to_string_pretty(&info)?);
    } else if !args.quiet {
        eprintln!("Generated Ed25519 keypair");
        eprintln!("  fingerprint: {fingerprint}");
        eprintln!("  private key: {}", key_path.display());
        eprintln!("  public key:  {}", pub_path.display());
    }

    Ok(())
}

/// Write a private key with owner-only permissions from the moment of
/// creation — never a default-mode file chmodded after the fact (TOCTOU).
///
/// `create_new` also refuses to clobber or follow an existing symlink at the
/// key path; callers handle the already-exists case before calling.
#[cfg(unix)]
fn write_private_key(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?
        .write_all(bytes)
}

#[cfg(not(unix))]
fn write_private_key(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)
}

/// Fail loudly if the OS did not honor the private key mode.
#[cfg(unix)]
fn debug_assert_private_mode(path: &std::path::Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
    if mode != 0o600 {
        anyhow::bail!(
            "private key written with permissive mode {:o} at {}",
            mode,
            path.display()
        );
    }
    Ok(())
}
