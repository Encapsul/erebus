use anyhow::{Context, Result};
use clap::Args;
use erebus_core::format::{Footer, ARCH_AARCH64, ARCH_RISCV64, ARCH_X86_64, FLAG_ENCRYPTED};
use erebus_core::paths::format_size;
use std::io::Seek;
use std::path::PathBuf;

#[derive(Args)]
pub struct InspectArgs {
    /// Path to the .erebus file
    pub file: PathBuf,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,

    /// Write JSON output to file (requires --json)
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Dry run — show what would be done without doing it
    #[arg(long)]
    pub dry_run: bool,
}

pub fn run(args: InspectArgs) -> Result<()> {
    if args.dry_run {
        eprintln!("Would inspect: {}", args.file.display());
        return Ok(());
    }

    let mut f = std::fs::File::open(&args.file)
        .with_context(|| format!("failed to open {}", args.file.display()))?;

    // Universal polyglot files are not plain .erebus artifacts; show the
    // slice table instead of failing on footer magic.
    if let Ok(header) = erebus_core::polyglot::read_polyglot_header(&mut f) {
        return inspect_polyglot(&args, &mut f, &header);
    }
    f.rewind()?;

    let footer = Footer::read_from(&mut f).context("failed to read erebus footer")?;

    let arch_name = match footer.arch {
        ARCH_X86_64 => "x86_64",
        ARCH_AARCH64 => "aarch64",
        ARCH_RISCV64 => "riscv64",
        _ => "unknown",
    };

    let payload =
        erebus_core::format::read_at(&mut f, footer.meta_offset, footer.meta_size as usize)
            .context("failed to read metadata payload")?;
    let meta: serde_json::Value =
        serde_json::from_slice(&payload).context("failed to parse metadata JSON")?;

    if args.json {
        let info = serde_json::json!({
            "file": args.file.display().to_string(),
            "format_version": footer.format_version,
            "arch": arch_name,
            "signed": footer.is_signed(),
            "encrypted": footer.flags & FLAG_ENCRYPTED != 0,
            "payload_offset": footer.payload_offset,
            "payload_compressed_size": footer.payload_csize,
            "payload_uncompressed_size": footer.payload_usize,
            "payload_sha256": footer.sha256_hex(),
            "meta": meta,
        });
        let json_str = serde_json::to_string_pretty(&info)?;
        if let Some(ref path) = args.output {
            std::fs::write(path, &json_str)
                .with_context(|| format!("failed to write to {}", path.display()))?;
            eprintln!("Wrote JSON to {}", path.display());
        } else {
            println!("{json_str}");
        }
    } else {
        eprintln!("File:        {}", args.file.display());
        eprintln!("Format:      v{}", footer.format_version);
        eprintln!("Arch:        {arch_name}");
        eprintln!("Signed:      {}", footer.is_signed());
        eprintln!("Encrypted:   {}", footer.flags & FLAG_ENCRYPTED != 0);
        if let Some(st) = meta.get("artifact_state").and_then(|v| v.as_str()) {
            eprintln!("State:       {st}");
        }
        eprintln!(
            "Payload:     {} -> {}",
            format_size(footer.payload_csize),
            format_size(footer.payload_usize)
        );
        eprintln!("SHA-256:     {}", &footer.sha256_hex()[..16]);

        // Signature info
        if footer.is_signed() {
            let sig_block_offset = footer.payload_offset + footer.payload_csize;
            eprintln!("Sig offset:  0x{sig_block_offset:X}");
            eprintln!("Sig size:    64 bytes (ed25519)");
        }

        if let Some(name) = meta.get("name").and_then(|v| v.as_str()) {
            eprintln!("Name:        {name}");
        }
        if let Some(rt) = meta.get("runtime").and_then(|v| v.as_str()) {
            eprintln!("Runtime:     {rt}");
        }
        if let Some(v) = meta.get("version").and_then(|v| v.as_str()) {
            eprintln!("Version:     {v}");
        }
        if let Some(a) = meta.get("author").and_then(|v| v.as_str()) {
            eprintln!("Author:      {a}");
        }
        if let Some(d) = meta.get("description").and_then(|v| v.as_str()) {
            eprintln!("Description: {d}");
        }
        if let Some(l) = meta.get("license").and_then(|v| v.as_str()) {
            eprintln!("License:     {l}");
        }

        // Isolation level
        if let Some(iso) = meta.get("isolation").and_then(|v| v.as_u64()) {
            eprintln!("Isolation:   level {iso}");
        }

        // Entrypoint
        if let Some(ep) = meta.get("entrypoint").and_then(|v| v.as_array()) {
            let parts: Vec<&str> = ep.iter().filter_map(|v| v.as_str()).collect();
            eprintln!("Entrypoint:  {}", parts.join(" "));
        }

        // Created timestamp
        if let Some(created) = meta.get("created").and_then(|v| v.as_str()) {
            eprintln!("Created:     {created}");
        }

        // Env vars
        if let Some(env) = meta.get("env").and_then(|v| v.as_object()) {
            if !env.is_empty() {
                eprintln!("Env vars:    {} var(s)", env.len());
                for (k, v) in env {
                    let val = v.as_str().unwrap_or("...");
                    eprintln!("  {k}={val}");
                }
            }
        }

        // Layers
        if let Some(layers) = meta.get("layers").and_then(|v| v.as_array()) {
            eprintln!("Layers:      {}", layers.len());
            for (i, layer) in layers.iter().enumerate() {
                let name = layer.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                let usize = layer.get("usize").and_then(|v| v.as_u64()).unwrap_or(0);
                eprintln!("  [{i}] {name} ({})", format_size(usize));
            }
        }

        // App/runtime hashes
        if let Some(app_hash) = meta.get("app_hash").and_then(|v| v.as_str()) {
            eprintln!("App hash:    {}...", &app_hash[..16.min(app_hash.len())]);
        }
        if let Some(rt_hash) = meta.get("rt_deps_hash").and_then(|v| v.as_str()) {
            eprintln!("RT hash:     {}...", &rt_hash[..16.min(rt_hash.len())]);
        }
    }

    Ok(())
}

/// Inspect a universal polyglot file: loader info + slice table.
fn inspect_polyglot(
    args: &InspectArgs,
    f: &mut std::fs::File,
    header: &erebus_core::polyglot::PolyglotHeader,
) -> Result<()> {
    use erebus_core::polyglot::{read_slice_table, PolyglotOS, LOADER_REGION_SIZE};

    let os_name = |v: u8| match v {
        v if v == PolyglotOS::Linux as u8 => "linux",
        v if v == PolyglotOS::MacOS as u8 => "macos",
        v if v == PolyglotOS::Windows as u8 => "windows",
        _ => "unknown",
    };
    let arch_name = |v: u8| match v {
        ARCH_X86_64 => "x86_64",
        ARCH_AARCH64 => "aarch64",
        ARCH_RISCV64 => "riscv64",
        _ => "unknown",
    };

    let entries = read_slice_table(f, header)?;
    let rows: Vec<(String, String, u64, u64)> = entries
        .iter()
        .map(|e| {
            let (off, size) = (e.offset, e.size);
            (
                os_name(e.target_os).to_string(),
                arch_name(e.target_arch).to_string(),
                off,
                size,
            )
        })
        .collect();
    let total = header.total_size;
    if args.json {
        let info = serde_json::json!({
            "file": args.file.display().to_string(),
            "kind": "universal-polyglot",
            "format_version": header.version,
            "total_size": total,
            "slices": rows.iter().map(|(os, arch, off, size)| serde_json::json!({
                "os": os,
                "arch": arch,
                "offset": off,
                "size": size,
            })).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&info)?);
        return Ok(());
    }

    eprintln!("File:        {}", args.file.display());
    eprintln!("Kind:        universal polyglot (v{})", header.version);
    eprintln!("Loader:      /bin/sh ({} byte region)", LOADER_REGION_SIZE);
    eprintln!(
        "Total size:  {} ({:.1} MB)",
        format_size(total),
        total as f64 / 1_048_576.0
    );
    eprintln!("Slices:      {}", rows.len());
    for (os, arch, off, size) in &rows {
        eprintln!(
            "  {os:<8} {arch:<8} offset={off:<12} size={}",
            format_size(*size)
        );
    }
    Ok(())
}
