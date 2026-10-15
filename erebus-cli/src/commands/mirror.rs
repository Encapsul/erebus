use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{Context, Result};
use clap::Args;
use erebus_core::encrypt::generate_salt;
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use std::fs::{self, File};
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use tar::Builder;
use zeroize::Zeroizing;

#[derive(Args)]
pub struct MirrorArgs {
    #[command(subcommand)]
    pub command: MirrorCommand,
}

#[derive(clap::Subcommand)]
pub enum MirrorCommand {
    /// Export registry data to an encrypted archive
    Export {
        /// Registry data directory
        #[arg(long)]
        dir: PathBuf,

        /// Output archive path
        #[arg(short, long)]
        output: PathBuf,

        /// File containing the encryption password
        #[arg(long)]
        password_file: PathBuf,
    },
    /// Import registry data from an encrypted archive
    Import {
        /// Input archive path
        #[arg(short, long)]
        input: PathBuf,

        /// Registry data directory
        #[arg(long)]
        dir: PathBuf,

        /// File containing the decryption password
        #[arg(long)]
        password_file: PathBuf,
    },
}

pub fn run(args: MirrorArgs) -> Result<()> {
    match args.command {
        MirrorCommand::Export {
            dir,
            output,
            password_file,
        } => export(&dir, &output, &read_secret(&password_file)?),
        MirrorCommand::Import {
            input,
            dir,
            password_file,
        } => import(&input, &dir, &read_secret(&password_file)?),
    }
}

fn read_secret(path: &Path) -> Result<String> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    Ok(raw.trim().to_string())
}

fn derive_key(password: &str, salt: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    let hk = Hkdf::<Sha256>::new(Some(salt), password.as_bytes());
    hk.expand(b"erebus-mirror-key", &mut key[..])
        .expect("HKDF expand failed");
    key
}

fn export(dir: &Path, output: &PathBuf, password: &str) -> Result<()> {
    let salt = generate_salt();
    let key = derive_key(password, &salt);

    let tar_data = {
        let mut buf = Vec::new();
        let mut builder = Builder::new(&mut buf);
        for entry in walkdir::WalkDir::new(dir) {
            let entry = entry?;
            let path = entry.path();
            let rel = path.strip_prefix(dir)?;
            if rel.as_os_str().is_empty() {
                continue;
            }
            if path.is_file() {
                builder.append_path_with_name(path, rel)?;
            }
        }
        builder.into_inner()?;
        buf
    };

    let mut rng = OsRng;
    let nonce = {
        let mut n = [0u8; 12];
        rng.fill_bytes(&mut n);
        n
    };
    let ciphertext = {
        let key_bytes: [u8; 32] = *key;
        let cipher = Aes256Gcm::new_from_slice(&key_bytes).context("aes key init")?;
        let nonce_bytes = Nonce::from_slice(&nonce);
        cipher
            .encrypt(nonce_bytes, tar_data.as_ref())
            .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))?
    };

    let mut out = File::create(output).context("failed to create output file")?;
    out.write_all(&salt)?;
    out.write_all(&nonce)?;
    let tag = &ciphertext[ciphertext.len() - 16..];
    out.write_all(tag)?;
    out.write_all(&ciphertext[..ciphertext.len() - 16])?;
    out.flush()?;

    println!(
        "Mirror exported to {} ({} bytes)",
        output.display(),
        out.metadata()?.len()
    );
    Ok(())
}

fn import(input: &PathBuf, dir: &Path, password: &str) -> Result<()> {
    let mut f = File::open(input).context("failed to open input file")?;
    let mut salt = [0u8; 32];
    f.read_exact(&mut salt)?;
    let mut nonce = [0u8; 12];
    f.read_exact(&mut nonce)?;
    let mut tag = [0u8; 16];
    f.read_exact(&mut tag)?;
    let mut ciphertext = Vec::new();
    f.read_to_end(&mut ciphertext)?;
    ciphertext.extend_from_slice(&tag);

    let key = derive_key(password, &salt);
    let plaintext = {
        let key_bytes: [u8; 32] = *key;
        let cipher = Aes256Gcm::new_from_slice(&key_bytes).context("aes key init")?;
        let nonce_bytes = Nonce::from_slice(&nonce);
        cipher
            .decrypt(nonce_bytes, ciphertext.as_ref())
            .map_err(|e| anyhow::anyhow!("decryption failed: {e}"))?
    };

    fs::create_dir_all(dir)?;
    let mut archive = tar::Archive::new(Cursor::new(plaintext));
    archive.unpack(dir)?;

    println!("Mirror imported to {}", dir.display());
    Ok(())
}
