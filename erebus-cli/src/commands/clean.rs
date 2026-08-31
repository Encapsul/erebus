use anyhow::{Context, Result};
use clap::Args;
use erebus_core::paths::{cache_dir, format_size, BuildCache};

#[derive(Args)]
pub struct CleanArgs {
    /// Remove all cached data
    #[arg(long)]
    pub all: bool,

    /// Garbage-collect expired cache entries (TTL-based)
    #[arg(long)]
    pub gc: bool,

    /// Skip confirmation
    #[arg(short, long)]
    pub force: bool,

    /// Run in non-interactive mode (no prompts, fail if input required)
    #[arg(long)]
    pub no_input: bool,

    /// Output result as JSON
    #[arg(long)]
    pub json: bool,

    /// Garbage-collect orphaned content-addressed blobs in a registry
    ///
    /// Requires --blob-dir and --manifest-dir to be set
    #[arg(long)]
    pub gc_blobs: bool,

    /// Registry blob directory (used with --gc-blobs)
    #[arg(long)]
    pub blob_dir: Option<std::path::PathBuf>,

    /// Registry manifest directory (used with --gc-blobs)
    #[arg(long)]
    pub manifest_dir: Option<std::path::PathBuf>,

    /// Trash directory for reclaimed blobs (defaults to <blob-dir>/trash)
    #[arg(long)]
    pub trash_dir: Option<std::path::PathBuf>,
}

pub fn run(args: CleanArgs) -> Result<()> {
    if args.gc_blobs {
        let blob = args
            .blob_dir
            .context("--blob-dir required with --gc-blobs")?;
        let manifest = args
            .manifest_dir
            .context("--manifest-dir required with --gc-blobs")?;
        let trash = args.trash_dir.unwrap_or_else(|| blob.join("trash"));
        let res = erebus_core::gc::collect_garbage(&blob, &manifest, &trash)?;
        if args.json {
            let info = serde_json::json!({
                "reclaimed": res.reclaimed,
                "bytes_reclaimed": res.bytes_reclaimed,
                "live_count": res.live_count,
            });
            println!("{}", serde_json::to_string_pretty(&info)?);
        } else {
            eprintln!("GC complete:");
            eprintln!("  Orphans reclaimed: {}", res.reclaimed.len());
            eprintln!(
                "  Bytes freed:      {}",
                erebus_core::paths::format_size(res.bytes_reclaimed)
            );
            eprintln!("  Live blobs:       {}", res.live_count);
            if !res.reclaimed.is_empty() {
                eprintln!("  Moved to: {}", trash.display());
            }
        }
        return Ok(());
    }

    if args.gc {
        let cache = BuildCache::new(std::path::Path::new("."), 50);
        cache.gc();
        eprintln!("Cache garbage-collected (expired entries removed)");
        return Ok(());
    }

    let cache_dir = cache_dir();

    if !cache_dir.exists() {
        eprintln!("Nothing to clean");
        return Ok(());
    }

    let size = dir_size(&cache_dir)?;

    if !args.force && !args.no_input && is_interactive() {
        eprintln!(
            "This will remove {} ({})",
            cache_dir.display(),
            format_size(size)
        );
        eprint!("Continue? [y/N] ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            eprintln!("Aborted");
            return Ok(());
        }
    }

    std::fs::remove_dir_all(&cache_dir)
        .with_context(|| format!("failed to remove cache directory {}", cache_dir.display()))?;
    if args.json {
        let info = serde_json::json!({
            "cleaned": cache_dir.display().to_string(),
            "size_bytes": size,
            "size_human": format_size(size),
        });
        println!("{}", serde_json::to_string_pretty(&info)?);
    } else {
        eprintln!("Cleaned {} ({})", cache_dir.display(), format_size(size));
    }

    Ok(())
}

fn dir_size(path: &std::path::Path) -> Result<u64> {
    let mut total = 0;
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let meta = entry.metadata()?;
        if meta.is_dir() {
            total += dir_size(&entry.path())?;
        } else {
            total += meta.len();
        }
    }
    Ok(total)
}

fn is_interactive() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal()
}
