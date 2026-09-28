use anyhow::{Context, Result};
use clap::Args;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const GITHUB_API: &str = "https://api.github.com/repos/Tednoob17/erebus/releases/latest";

#[derive(Args)]
pub struct UpgradeArgs {
    /// Skip confirmation prompt
    #[arg(short, long)]
    pub force: bool,

    /// Do not use sudo; fail if binary is not writable
    #[arg(long)]
    pub no_sudo: bool,

    /// Show what would be done without doing it
    #[arg(long)]
    pub dry_run: bool,

    /// Run in non-interactive mode (no prompts, fail if input required)
    #[arg(long)]
    pub no_input: bool,

    /// Output result as JSON
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: UpgradeArgs) -> Result<()> {
    let current = env!("CARGO_PKG_VERSION");
    if verbose() {
        eprintln!("[erebus] current version: {current}");
    }

    let latest = fetch_latest_version().context("failed to fetch latest version")?;

    if verbose() {
        eprintln!("[erebus] latest version:  {latest}");
    }

    if current == latest {
        eprintln!("[erebus] already up to date");
        return Ok(());
    }

    let platform = detect_platform()?;
    if verbose() {
        eprintln!("[erebus] platform: {platform}");
    }

    // Naming contract of .github/workflows/release.yml (shared with install.sh).
    let tag = format!("v{latest}");
    let asset = format!("erebus_{latest}_{platform}.tar.gz");
    let url = format!("https://github.com/Tednoob17/erebus/releases/download/{tag}/{asset}");

    if args.dry_run {
        eprintln!("Would upgrade from {current} to {latest}");
        eprintln!("  platform: {platform}");
        eprintln!("  url:      {url}");
        return Ok(());
    }

    let tmp = tempfile::tempdir().context("failed to create temp dir")?;
    let tarball = tmp.path().join(&asset);

    // Fetch the expected checksum BEFORE downloading and fail closed: a
    // release whose integrity cannot be verified is never installed.
    let checksum_url = format!("{url}.sha256");
    let expected = fetch_checksum(&checksum_url)
        .context("failed to fetch release checksum; refusing an unverified upgrade")?;
    if verbose() {
        eprintln!("[erebus] expected checksum {expected}");
    }

    // Download
    if verbose() {
        eprintln!("[erebus] downloading {asset}...");
    }
    download_file(&url, &tarball).context("download failed")?;

    // Verify checksum — mismatch aborts before anything is extracted or copied.
    let got = sha256_file(&tarball)?;
    if expected != got {
        anyhow::bail!("checksum mismatch: expected {expected}, got {got}");
    }
    if verbose() {
        eprintln!("[erebus] checksum verified");
    }

    // Extract
    let status = std::process::Command::new("tar")
        .args([
            "xzf",
            &tarball.to_string_lossy(),
            "-C",
            &tmp.path().to_string_lossy(),
        ])
        .status()
        .context("failed to run tar")?;
    if !status.success() {
        anyhow::bail!("tar extraction failed");
    }

    // Find extracted directory
    let bin_dir = find_binaries_dir(tmp.path())?;

    // Find install location
    let erebus_path = find_erebus_binary()?;
    let install_dir = erebus_path
        .parent()
        .context("cannot determine install directory")?;

    if verbose() {
        eprintln!("[erebus] installing to {}...", install_dir.display());
    }

    let needs_sudo = !is_writable(install_dir);
    if needs_sudo && args.no_sudo {
        anyhow::bail!(
            "install directory {} is not writable and --no-sudo is set",
            install_dir.display()
        );
    }
    if needs_sudo && !args.force && !args.no_input {
        if !is_interactive() {
            anyhow::bail!(
                "sudo required for {}; pass --force for non-interactive use",
                install_dir.display()
            );
        }
        eprint!(
            "[erebus] install to {} requires sudo. Continue? [y/N] ",
            install_dir.display()
        );
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            eprintln!("Aborted");
            return Ok(());
        }
    }

    for entry in std::fs::read_dir(&bin_dir).context("failed to read archive directory")? {
        let entry = entry?;
        if !entry.path().is_file() {
            continue;
        }
        let dest = install_dir.join(entry.file_name());
        if is_writable(&dest) {
            std::fs::copy(entry.path(), &dest)
                .with_context(|| format!("failed to copy to {}", dest.display()))?;
        } else if needs_sudo {
            let status = std::process::Command::new("sudo")
                .args([
                    "cp",
                    &entry.path().to_string_lossy(),
                    &dest.to_string_lossy(),
                ])
                .status()
                .context("failed to run sudo cp")?;
            if !status.success() {
                anyhow::bail!("failed to install to {}", dest.display());
            }
        } else {
            anyhow::bail!("{} is not writable and sudo was not used", dest.display());
        }
    }

    eprintln!("[erebus] upgraded to {latest}");
    if args.json {
        let info = serde_json::json!({
            "previous": current,
            "upgraded_to": latest,
            "platform": platform,
        });
        println!("{}", serde_json::to_string_pretty(&info)?);
    }
    Ok(())
}

/// Locate the directory holding the binaries inside an extracted release
/// archive: `erebus_<ver>_<os>_<arch>/` with the binaries at its root
/// (current layout), or a legacy `erebus-*/bin/`.
fn find_binaries_dir(tmp: &Path) -> Result<PathBuf> {
    let extracted = std::fs::read_dir(tmp)
        .context("failed to read temp dir")?
        .flatten()
        .map(|e| e.path())
        .find(|p| {
            p.is_dir()
                && p.file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with("erebus"))
        })
        .context("unexpected archive structure")?;
    let legacy_bin = extracted.join("bin");
    if legacy_bin.is_dir() {
        return Ok(legacy_bin);
    }
    if !extracted.join("erebus").is_file() && !extracted.join("erebus.exe").is_file() {
        anyhow::bail!("no erebus binary in archive");
    }
    Ok(extracted)
}

/// `<os>_<arch>` exactly as the release archives are named
/// (`erebus_<ver>_<os>_<arch>.tar.gz`, see .github/workflows/release.yml).
fn detect_platform() -> Result<String> {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;

    let os_str = match os {
        "linux" => "linux",
        "macos" => "darwin",
        "windows" => "windows",
        _ => anyhow::bail!("unsupported OS: {os}"),
    };

    let arch_str = match arch {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "x86" => "i386",
        "arm" => "armv7",
        _ => anyhow::bail!("unsupported architecture: {arch}"),
    };

    Ok(format!("{os_str}_{arch_str}"))
}

fn fetch_latest_version() -> Result<String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .context("failed to create HTTP client")?;

    let resp = client
        .get(GITHUB_API)
        .header("Accept", "application/vnd.github.v3+json")
        .send()
        .context("failed to fetch latest release")?;

    let data: serde_json::Value = resp.json().context("failed to parse GitHub API response")?;
    let tag = data
        .get("tag_name")
        .and_then(|v: &serde_json::Value| v.as_str())
        .context("missing tag_name in response")?;

    Ok(tag.trim_start_matches('v').to_string())
}

const MAX_DOWNLOAD_BYTES: u64 = 500 * 1024 * 1024;

fn download_file(url: &str, dest: &PathBuf) -> Result<()> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_mins(5))
        .build()
        .context("failed to create HTTP client")?;

    let resp = client.get(url).send().context("failed to download")?;
    if let Some(len) = resp.content_length() {
        if len > MAX_DOWNLOAD_BYTES {
            anyhow::bail!(
                "download aborted: content length {len} exceeds limit {MAX_DOWNLOAD_BYTES}"
            );
        }
    }
    let bytes = resp.bytes().context("failed to read response")?;
    if bytes.len() > MAX_DOWNLOAD_BYTES as usize {
        anyhow::bail!(
            "download aborted: {} bytes exceeds limit {MAX_DOWNLOAD_BYTES}",
            bytes.len()
        );
    }
    std::fs::write(dest, &bytes).context("failed to write file")?;
    Ok(())
}

fn fetch_checksum(url: &str) -> Result<String> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .context("failed to create HTTP client")?;

    let resp = client.get(url).send().context("failed to fetch checksum")?;
    let text = resp.text().context("failed to read checksum")?;
    let hash = text
        .split_whitespace()
        .next()
        .context("empty checksum")?
        .to_string();
    Ok(hash)
}

fn sha256_file(path: &PathBuf) -> Result<String> {
    let bytes = std::fs::read(path).context("failed to read file for checksum")?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let result = hasher.finalize();
    Ok(hex::encode(result))
}

fn find_erebus_binary() -> Result<PathBuf> {
    // Try /proc/self/exe (Linux)
    let proc = PathBuf::from("/proc/self/exe");
    if proc.exists() {
        let target = std::fs::read_link(&proc).context("failed to read /proc/self/exe")?;
        return Ok(target);
    }

    // Try which
    if let Ok(p) = which::which("erebus") {
        return Ok(p);
    }

    anyhow::bail!("cannot locate erebus binary for self-update")
}

/// Whether a path is actually writable, probed rather than inferred.
///
/// The POSIX readonly bit is only advisory and does not reflect real
/// writability (e.g. vfat, root-owned dirs). For directories — or files that
/// do not exist yet — a temp file is created and removed in the directory; a
/// file that already exists is opened for writing.
fn is_writable(path: &Path) -> bool {
    if path.exists() && !path.is_dir() {
        return std::fs::OpenOptions::new().write(true).open(path).is_ok();
    }
    let dir = if path.is_dir() {
        path
    } else {
        path.parent().unwrap_or(path)
    };
    let probe = dir.join(format!(".erebus-probe-{}", std::process::id()));
    let created = std::fs::File::create(&probe).is_ok();
    if created {
        let _ = std::fs::remove_file(&probe);
    }
    created
}

fn is_interactive() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal()
}

fn verbose() -> bool {
    std::env::var("ERE_VERBOSE").map_or(false, |v| !v.is_empty() && v != "0")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_platform_matches_release_naming() {
        // Runs on the current platform: the value must be a valid
        // `<os>_<arch>` suffix of a release archive name.
        let p = detect_platform().unwrap();
        let (os, arch) = p.split_once('_').unwrap();
        assert!(["linux", "darwin", "windows"].contains(&os));
        assert!(["amd64", "arm64", "i386", "armv7"].contains(&arch));
        if std::env::consts::OS == "macos" {
            assert_eq!(os, "darwin");
        }
    }

    #[test]
    fn test_find_binaries_dir_current_and_legacy_layouts() {
        let tmp = tempfile::tempdir().unwrap();
        let cur = tmp.path().join("erebus_0.6.0_linux_amd64");
        std::fs::create_dir(&cur).unwrap();
        std::fs::write(cur.join("erebus"), b"bin").unwrap();
        assert_eq!(find_binaries_dir(tmp.path()).unwrap(), cur);

        let tmp = tempfile::tempdir().unwrap();
        let legacy = tmp.path().join("erebus-0.5.0-linux-x64");
        std::fs::create_dir_all(legacy.join("bin")).unwrap();
        assert_eq!(find_binaries_dir(tmp.path()).unwrap(), legacy.join("bin"));

        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("erebus_empty")).unwrap();
        assert!(find_binaries_dir(tmp.path()).is_err());
    }

    #[test]
    fn test_sha256_file() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("test.txt");
        std::fs::write(&file, b"hello world").unwrap();
        let hash = sha256_file(&file).unwrap();
        // SHA-256 of "hello world"
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_is_writable_existing_file() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("test.txt");
        std::fs::write(&file, b"test").unwrap();
        assert!(is_writable(&file));
    }

    #[test]
    fn test_is_writable_dir_probes_real_perms() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(is_writable(tmp.path()));
        assert!(is_writable(&tmp.path().join("missing-file")));
    }
}
