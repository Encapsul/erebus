use anyhow::{Context, Result};
use clap::Args;
use erebus_core::audit::generate_sbom;
use erebus_core::format::Footer;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, Write};
use std::path::PathBuf;

#[derive(Args)]
pub struct SbomArgs {
    /// Path to the .erebus file
    pub file: PathBuf,

    /// Output file path (defaults to <file>.sbom.json)
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Embed SBOM in the .erebus binary metadata
    #[arg(long)]
    pub embed: bool,

    /// Quiet output
    #[arg(short, long)]
    pub quiet: bool,
}

fn read_metadata(path: &PathBuf) -> Result<Value> {
    let mut f = std::fs::File::open(path).context("failed to open file")?;
    let footer = Footer::read_from(&mut f)?;
    let meta_offset = footer.meta_offset as u64;
    let meta_size = footer.meta_size as usize;
    let mut meta_bytes = vec![0u8; meta_size];
    f.seek(std::io::SeekFrom::Start(meta_offset))?;
    f.read_exact(&mut meta_bytes)?;
    let meta: Value =
        serde_json::from_slice(&meta_bytes).context("failed to parse metadata JSON")?;
    Ok(meta)
}

fn write_metadata(path: &PathBuf, meta: &Value, output: Option<&PathBuf>) -> Result<()> {
    let mut f =
        std::fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let footer = Footer::read_from(&mut f)?;

    if footer.is_signed() {
        anyhow::bail!(
            "cannot embed SBOM in a signed .erebus: metadata is covered by the signature. \
             Rebuild with `erebus build` or re-sign after embedding."
        );
    }
    if footer.has_sisr() {
        anyhow::bail!(
            "cannot embed SBOM in a SISR binary: the delta manifest is signed and would be truncated"
        );
    }

    let json_bytes = serde_json::to_vec_pretty(meta).context("failed to serialize metadata")?;
    let tmp = path.with_extension("erebus.sbom-tmp");
    {
        let mut out = std::fs::File::create(&tmp)
            .with_context(|| format!("failed to create temp file {}", tmp.display()))?;
        let mut src = std::fs::File::open(path)?;
        let mut leading = Vec::new();
        src.seek(std::io::SeekFrom::Start(0))?;
        src.read_to_end(&mut leading)
            .context("failed to read source file")?;
        let meta_offset = footer.meta_offset as usize;
        out.write_all(&leading[..meta_offset])
            .context("failed to copy payload")?;
        out.write_all(&json_bytes)
            .context("failed to write metadata")?;
        let mut hasher = Sha256::new();
        hasher.update(&leading[..meta_offset]);
        hasher.update(&json_bytes);
        let new_hash: [u8; 32] = hasher.finalize().into();
        let new_footer = Footer {
            format_version: footer.format_version,
            arch: footer.arch,
            flags: footer.flags,
            payload_offset: footer.payload_offset,
            payload_csize: footer.payload_csize,
            payload_usize: footer.payload_usize,
            payload_sha256: new_hash,
            meta_offset: footer.meta_offset,
            meta_size: json_bytes.len() as u64,
            sig_offset: footer.sig_offset,
        };
        let footer_bytes: Vec<u8> = if new_footer.format_version >= 3 {
            new_footer.pack_full().to_vec()
        } else {
            new_footer.pack().to_vec()
        };
        out.write_all(&footer_bytes)
            .context("failed to write footer")?;
    }
    let dest = output.unwrap_or(path);
    std::fs::rename(&tmp, dest).context("failed to rename temp file")?;
    Ok(())
}

pub fn run(args: SbomArgs) -> Result<()> {
    if !args.file.exists() {
        anyhow::bail!("file not found: {}", args.file.display());
    }

    let meta = read_metadata(&args.file)?;
    let sbom = generate_sbom(&meta);

    if args.embed {
        let mut new_meta = meta;
        new_meta["sbom"] = serde_json::to_value(sbom)?;
        write_metadata(&args.file, &new_meta, args.output.as_ref())?;
        if !args.quiet {
            println!("SBOM embedded in {}", args.file.display());
        }
    } else {
        let output_path = args
            .output
            .unwrap_or_else(|| args.file.with_extension("erebus.sbom.json"));
        let json_bytes = serde_json::to_vec_pretty(&sbom).context("failed to serialize SBOM")?;
        std::fs::write(&output_path, &json_bytes)
            .with_context(|| format!("failed to write {}", output_path.display()))?;
        if !args.quiet {
            println!("SBOM written to {}", output_path.display());
        }
    }

    Ok(())
}
