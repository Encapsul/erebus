//! `erebus demo` — offline activation in one command: build a tiny agent,
//! produce a signed receipt, verify it, and leave every path on disk so the
//! user can replay the steps. No account, no network, no hosted link.

use anyhow::{Context, Result};
use clap::Args;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

const AGENT: &str = "print('erebus demo: hello from a verified run')\n";

#[derive(Args)]
pub struct DemoArgs {
    /// Create the demo in this directory instead of a fresh temporary one
    #[arg(long, value_name = "DIR")]
    pub output_dir: Option<PathBuf>,
}

pub fn run(args: DemoArgs) -> Result<()> {
    let started = Instant::now();
    let bin = std::env::current_exe().context("cannot locate the erebus binary")?;
    let base = workspace(args.output_dir)?;

    let app = base.join("app");
    fs::create_dir_all(&app).with_context(|| format!("cannot create {}", app.display()))?;
    fs::write(app.join("app.py"), AGENT)
        .with_context(|| format!("cannot write {}", app.display()))?;
    let keys = base.join("keys");
    fs::create_dir_all(&keys).with_context(|| format!("cannot create {}", keys.display()))?;

    step(
        &bin,
        "keygen",
        [s("keygen"), s("--key-dir"), os(&keys), s("--quiet")],
        &[],
    )?;
    let key = find_key(&keys)?;
    let bundle = base.join("demo.erebus");
    let receipt = base.join("demo.erebus.attest");

    step(
        &bin,
        "build",
        [
            s("build"),
            os(&app),
            s("-o"),
            os(&bundle),
            s("--key"),
            os(&key),
            s("--isolation"),
            s("none"),
            s("--no-install"),
            s("--quiet"),
        ],
        &[],
    )?;

    run_bundle(&bin, &bundle, &receipt, &key, &keys)?;
    anyhow::ensure!(
        receipt.is_file(),
        "no receipt at {} — the launcher could not sign it",
        receipt.display()
    );
    step(
        &bin,
        "verify-attest",
        [
            s("verify-attest"),
            os(&receipt),
            s("--trusted-dir"),
            os(&keys),
            s("--bundle"),
            os(&bundle),
        ],
        &[],
    )?;

    println!("Agent:   {}", app.join("app.py").display());
    println!("Bundle:  {}", bundle.display());
    println!("Receipt: {}", receipt.display());
    println!("Key:     {}", key.display());
    println!();
    println!("Verify it yourself:");
    println!(
        "  erebus verify-attest {} --trusted-dir {} --bundle {}",
        shell_quote(&receipt),
        shell_quote(&keys),
        shell_quote(&bundle),
    );
    println!();
    println!(
        "OK: first receipt verified ({:.1}s)",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

fn run_bundle(bin: &Path, bundle: &Path, receipt: &Path, key: &Path, keys: &Path) -> Result<()> {
    step(
        bin,
        "run",
        [s("run"), os(bundle)],
        &[
            ("ERE_ATTEST_KEY", os(key)),
            ("ERE_ATTEST_OUT", os(receipt)),
            ("ERE_ATTEST_LOG", s("none")),
            ("ERE_TRUSTED_DIR", os(keys)),
        ],
    )
}

fn workspace(dir: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(dir) = dir {
        fs::create_dir_all(&dir).with_context(|| format!("cannot create {}", dir.display()))?;
        return Ok(dir);
    }
    Ok(tempfile::Builder::new()
        .prefix("erebus-demo-")
        .tempdir()
        .context("cannot create a temporary demo directory")?
        .keep())
}

fn find_key(dir: &Path) -> Result<PathBuf> {
    fs::read_dir(dir)
        .with_context(|| format!("cannot read {}", dir.display()))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.extension().is_some_and(|ext| ext == "key"))
        .context("keygen did not produce a .key file")
}

fn step<I, S>(bin: &Path, label: &str, args: I, envs: &[(&str, OsString)]) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut cmd = Command::new(bin);
    cmd.args(args);
    for (name, value) in envs {
        cmd.env(name, value);
    }
    let status = cmd
        .status()
        .with_context(|| format!("failed to start erebus {label}"))?;
    anyhow::ensure!(status.success(), "erebus {label} failed with {status}");
    Ok(())
}

fn s(value: &str) -> OsString {
    OsString::from(value)
}

fn os(path: &Path) -> OsString {
    path.as_os_str().to_os_string()
}

fn shell_quote(path: &Path) -> String {
    let text = path.to_string_lossy();
    if text
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '-' | '.'))
    {
        text.into_owned()
    } else {
        format!("'{}'", text.replace('\'', "'\\''"))
    }
}
