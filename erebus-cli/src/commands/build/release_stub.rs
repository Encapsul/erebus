//! `cargo install` ships the CLI only. The matching `erebus-stub` is fetched
//! from the GitHub release (the same archives as `scripts/install.sh`),
//! SHA-256 checked against `checksums.txt`, and cached. A checksum miss
//! never writes the binary.

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

const ASSET_BASE: &str = "https://github.com/Tednoob17/erebus/releases/download";
const MAX_ASSET_BYTES: u64 = 80 * 1024 * 1024;

/// `<os>_<arch>` tag of the release archive that contains this stub, when
/// the release pipeline actually builds one. GNU and stub-less targets
/// (riscv64, ppc64le) return `None` — those archives have no launcher.
pub(crate) fn release_tag(arch_suffix: &str) -> Option<&'static str> {
    Some(match arch_suffix {
        "x86_64-unknown-linux-musl" => "linux_amd64",
        "aarch64-unknown-linux-musl" => "linux_arm64",
        "i686-unknown-linux-musl" | "i386-unknown-linux-musl" | "x86-unknown-linux-musl" => {
            "linux_i386"
        }
        "armv7-unknown-linux-musl" | "armv7-unknown-linux-musleabihf" => "linux_armv7",
        "arm-unknown-linux-musl" | "arm-unknown-linux-musleabihf" => "linux_arm",
        "x86_64-apple-darwin" => "darwin_amd64",
        "aarch64-apple-darwin" => "darwin_arm64",
        "x86_64-pc-windows-gnu" => "windows_amd64",
        _ => return None,
    })
}

fn asset_name(version: &str, tag: &str) -> String {
    format!("erebus_{version}_{tag}.tar.gz")
}

fn cache_path(version: &str, arch_suffix: &str, stub_name: &str) -> PathBuf {
    erebus_core::paths::cache_dir()
        .join("stubs")
        .join(version)
        .join(arch_suffix)
        .join(stub_name)
}

/// Download the stub for `arch_suffix` when no local candidate exists.
pub(crate) fn fetch_release_stub(arch_suffix: &str, stub_name: &str) -> Result<PathBuf> {
    let tag = release_tag(arch_suffix)
        .with_context(|| format!("no published erebus-stub for {arch_suffix}"))?;
    let version = env!("CARGO_PKG_VERSION");
    let dest = cache_path(version, arch_suffix, stub_name);
    if dest.is_file() {
        return Ok(dest);
    }
    let asset = asset_name(version, tag);
    let base = format!("{ASSET_BASE}/v{version}");
    eprintln!("[erebus] downloading {stub_name} {version} ({tag})");
    let expected = checksum_for(&fetch_text(&format!("{base}/checksums.txt"))?, &asset)
        .with_context(|| format!("no checksum for {asset}"))?;
    let archive = download_verified(&format!("{base}/{asset}"), &expected)?;
    let stub = extract_named(&archive, stub_name)?;
    write_executable(&dest, &stub)?;
    Ok(dest)
}

/// SHA-256 field for `asset` inside a `sha256sum` `checksums.txt`.
fn checksum_for(text: &str, asset: &str) -> Option<String> {
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let Some(hash) = fields.next() else {
            continue;
        };
        if fields.any(|f| f.trim_start_matches('*') == asset) {
            return Some(hash.to_string());
        }
    }
    None
}

fn http() -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .user_agent(concat!("erebus/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("failed to build HTTP client")
}

fn fetch_text(url: &str) -> Result<String> {
    http()?
        .get(url)
        .send()
        .with_context(|| format!("failed to fetch {url}"))?
        .error_for_status()
        .with_context(|| format!("failed to fetch {url}"))?
        .text()
        .context("failed to read response")
}

fn download_verified(url: &str, expected: &str) -> Result<Vec<u8>> {
    let response = http()?
        .get(url)
        .send()
        .with_context(|| format!("failed to download {url}"))?
        .error_for_status()
        .with_context(|| format!("failed to download {url}"))?;
    if let Some(len) = response.content_length() {
        if len > MAX_ASSET_BYTES {
            anyhow::bail!("release asset too large: {len} bytes");
        }
    }
    let bytes = response.bytes().context("failed to read release asset")?;
    if bytes.len() as u64 > MAX_ASSET_BYTES {
        anyhow::bail!("release asset too large: {} bytes", bytes.len());
    }
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let got = hex::encode(hasher.finalize());
    if got != expected {
        anyhow::bail!("checksum mismatch for {url}: expected {expected}, got {got}");
    }
    Ok(bytes.to_vec())
}

fn extract_named(archive: &[u8], stub_name: &str) -> Result<Vec<u8>> {
    let decoder = flate2::read::GzDecoder::new(Cursor::new(archive));
    let mut tar = tar::Archive::new(decoder);
    for entry in tar.entries().context("failed to read release archive")? {
        let mut entry = entry.context("failed to read archive entry")?;
        let path = entry.path().context("failed to read archive entry path")?;
        if path.ends_with(stub_name) {
            let mut bytes = Vec::new();
            entry
                .read_to_end(&mut bytes)
                .context("failed to read stub from archive")?;
            if bytes.is_empty() {
                anyhow::bail!("{stub_name} in the release archive is empty");
            }
            return Ok(bytes);
        }
    }
    anyhow::bail!("{stub_name} is not in the release archive")
}

fn write_executable(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("stub cache path has no parent")?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("failed to create {}", parent.display()))?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .context("stub cache path has no file name")?;
    let tmp = parent.join(format!(".{name}.partial"));
    std::fs::write(&tmp, bytes).with_context(|| format!("failed to write {}", tmp.display()))?;
    set_executable(&tmp)?;
    std::fs::rename(&tmp, path).with_context(|| format!("failed to install {}", path.display()))?;
    Ok(())
}

fn set_executable(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = std::fs::metadata(path)
            .with_context(|| format!("failed to stat {}", path.display()))?
            .permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(path, perm)
            .with_context(|| format!("failed to chmod {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_tag_matches_published_archives() {
        assert_eq!(
            release_tag("x86_64-unknown-linux-musl"),
            Some("linux_amd64")
        );
        assert_eq!(release_tag("aarch64-apple-darwin"), Some("darwin_arm64"));
        assert_eq!(release_tag("x86_64-pc-windows-gnu"), Some("windows_amd64"));
        assert_eq!(release_tag("i686-unknown-linux-musl"), Some("linux_i386"));
        assert_eq!(
            release_tag("armv7-unknown-linux-musleabihf"),
            Some("linux_armv7")
        );
    }

    #[test]
    fn release_tag_refuses_archives_without_a_stub() {
        assert_eq!(release_tag("riscv64gc-unknown-linux-musl"), None);
        assert_eq!(release_tag("powerpc64le-unknown-linux-musl"), None);
        assert_eq!(release_tag("x86_64-unknown-linux-gnu"), None);
        assert_eq!(release_tag("aarch64-pc-windows-gnu"), None);
    }

    #[test]
    fn checksum_for_reads_sha256sum_lines() {
        let text =
            "\nabc  erebus_0.6.1_linux_amd64.tar.gz\ndef *erebus_0.6.1_darwin_arm64.tar.gz\n";
        assert_eq!(
            checksum_for(text, "erebus_0.6.1_linux_amd64.tar.gz").as_deref(),
            Some("abc")
        );
        assert_eq!(
            checksum_for(text, "erebus_0.6.1_darwin_arm64.tar.gz").as_deref(),
            Some("def")
        );
        assert_eq!(checksum_for(text, "missing.tar.gz"), None);
    }

    #[test]
    fn extract_named_reads_the_stub_out_of_the_archive() {
        let raw = tar_gz("erebus_0.6.1_linux_amd64/erebus-stub", b"stub-bytes");
        let got = extract_named(&raw, "erebus-stub").unwrap();
        assert_eq!(got, b"stub-bytes");
    }

    #[test]
    fn extract_named_errors_when_the_stub_is_absent() {
        let raw = tar_gz("erebus_0.6.1_linux_amd64/erebus", b"cli");
        let err = extract_named(&raw, "erebus-stub").unwrap_err();
        assert!(err.to_string().contains("not in the release archive"));
    }

    fn tar_gz(name: &str, bytes: &[u8]) -> Vec<u8> {
        let mut raw = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut raw);
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(bytes.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            builder.append_data(&mut header, name, bytes).unwrap();
            builder.finish().unwrap();
        }
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut enc, &raw).unwrap();
        enc.finish().unwrap()
    }
}
