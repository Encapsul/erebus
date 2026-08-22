use anyhow::{bail, Context, Result};
use clap::Args;
use erebus_core::layer::LayerKind;
use erebus_core::registry::LayerRegistry;
use std::path::{Path, PathBuf};

#[derive(Args)]
pub struct LayerArgs {
    #[command(subcommand)]
    pub command: LayerCommand,
}

#[derive(clap::Subcommand)]
pub enum LayerCommand {
    /// Store a file in the shared layer registry
    Push {
        /// File to store
        file: PathBuf,
        /// Registry name for the layer
        #[arg(long)]
        name: String,
        /// Layer kind
        #[arg(long, value_enum, default_value_t = KindArg::Runtime)]
        kind: KindArg,
    },
    /// List layers in the local registry
    List,
    /// Materialize a registry layer to a file
    Pull {
        /// Layer name in the registry
        name: String,
        /// Destination path
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Remove a layer entry from the registry
    Remove { name: String },
}

#[derive(Clone, Copy, clap::ValueEnum)]
pub enum KindArg {
    Runtime,
    Model,
    Tool,
    Config,
}

impl From<KindArg> for LayerKind {
    fn from(k: KindArg) -> Self {
        match k {
            KindArg::Runtime => LayerKind::Runtime,
            KindArg::Model => LayerKind::Model,
            KindArg::Tool => LayerKind::Tool,
            KindArg::Config => LayerKind::Config,
        }
    }
}

/// `erebus layer` — manage the local shared-layer registry.
///
/// Publish heavyweight blobs once (runtime packs, llama.cpp, base models) and
/// reuse them across agent builds without re-embedding.
pub fn run(args: LayerArgs) -> Result<()> {
    let root =
        LayerRegistry::default_dir().context("no usable directory for the layer registry")?;
    let mut reg =
        LayerRegistry::open(&root).with_context(|| format!("opening {}", root.display()))?;
    match args.command {
        LayerCommand::Push { file, name, kind } => push(&mut reg, &file, &name, kind.into()),
        LayerCommand::List => list(&reg),
        LayerCommand::Pull { name, output } => pull(&reg, &name, &output),
        LayerCommand::Remove { name } => remove(&mut reg, &name),
    }
}

fn push(reg: &mut LayerRegistry, file: &PathBuf, name: &str, kind: LayerKind) -> Result<()> {
    let data = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    let entry = reg.push(name, kind, &data)?;
    eprintln!(
        "Pushed {} ({}, {} bytes) as sha256:{}",
        name,
        format_kind(entry.kind),
        entry.size,
        entry.sha256
    );
    Ok(())
}

fn list(reg: &LayerRegistry) -> Result<()> {
    let entries = reg.list()?;
    if entries.is_empty() {
        eprintln!("Registry is empty. Push one with: erebus layer push <file> --name <name>");
        return Ok(());
    }
    println!("{:<24} {:<8} {:>12}  SHA-256", "NAME", "KIND", "SIZE");
    for e in entries {
        println!(
            "{:<24} {:<8} {:>12}  {}",
            e.name,
            format_kind(e.kind),
            human_size(e.size),
            e.sha256
        );
    }
    Ok(())
}

fn pull(reg: &LayerRegistry, name: &str, output: &Path) -> Result<()> {
    match reg.materialize(name, output)? {
        Some(bytes) => eprintln!("Wrote {} ({} bytes)", output.display(), bytes),
        None => bail!("layer '{name}' not found in registry"),
    }
    Ok(())
}

fn remove(reg: &mut LayerRegistry, name: &str) -> Result<()> {
    if reg.remove(name)? {
        eprintln!("Removed {name}");
    } else {
        bail!("layer '{name}' not found in registry");
    }
    Ok(())
}

fn format_kind(k: LayerKind) -> &'static str {
    match k {
        LayerKind::Runtime => "runtime",
        LayerKind::Model => "model",
        LayerKind::Tool => "tool",
        LayerKind::Config => "config",
        LayerKind::Custom => "custom",
    }
}

fn human_size(bytes: u64) -> String {
    let mb = bytes as f64 / 1_048_576.0;
    if mb >= 1.0 {
        format!("{mb:.1}MB")
    } else {
        format!("{bytes}B")
    }
}
