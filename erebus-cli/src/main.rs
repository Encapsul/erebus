//! erebus CLI - package any app into a single self-extracting binary

#![allow(dead_code)]

pub mod commands;
mod error;
mod pager;
mod remote_cache;

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{
    generate,
    shells::{Bash, Elvish, Fish, PowerShell, Zsh},
};
use std::io;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "erebus",
    version,
    about = "Package any app into a single self-extracting binary",
    long_about = "erebus packages any application into a single self-extracting ELF binary.\n\nSupported runtimes: Python, Node.js, Go, and static binaries.\nBuild, sign, attest, and serve AI agent bundles from one file.\n\nExamples:\n  erebus build ./myapp -o myapp.erebus\n  erebus run myapp.erebus\n  erebus inspect myapp.erebus\n  erebus keygen\n  erebus sign myapp.erebus --key ~/.erebus/keys/*.key\n  erebus verify myapp.erebus\n  erebus attest myapp.erebus --key ~/.erebus/keys/*.key\n  erebus audit myapp.erebus\n  erebus doctor\n  erebus scan .\n  erebus serve agent.erebus --port 8080\n  erebus chat agent.erebus\n  erebus completion bash >> ~/.bashrc\n  erebus completion zsh >> ~/.zshrc\n  erebus completion fish > ~/.config/fish/completions/erebus.fish\n\nDocumentation: https://github.com/Tednoob17/erebus\nReport bugs: https://github.com/Tednoob17/erebus/issues\n\nUninstall: rm $(which erebus) && rm -rf ~/.cache/erebus ~/.local/share/erebus"
)]
struct Cli {
    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Disable colored output (also respects `NO_COLOR` env)
    #[arg(long, global = true)]
    no_color: bool,

    /// Suppress non-error output
    #[arg(short, long, global = true)]
    quiet: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Build a .erebus binary from an app directory
    ///
    /// Examples:
    ///   erebus build ./myapp -o myapp.erebus
    ///   erebus build ./myapp --target aarch64 --squashfs
    ///   erebus build ./myapp --sign --key ~/.erebus/keys/*.key
    ///   erebus build ./myapp --encrypt --key ~/.erebus/keys/*.key
    ///     (--encrypt is obfuscation-only: the decryption key is embedded in
    ///      the metadata, so a determined attacker can always extract the app)
    ///   erebus build ./myapp --health-port 8081
    ///   erebus build ./myapp --persist --env-file .env
    Build(Box<commands::build::BuildArgs>),

    /// Execute a .erebus file
    Run(commands::run::RunArgs),

    /// Inspect a .erebus file's metadata
    Inspect(commands::inspect::InspectArgs),

    /// Generate Ed25519 signing keys
    Keygen(commands::keygen::KeygenArgs),

    /// Sign a .erebus file
    Sign(commands::sign::SignArgs),

    /// Generate a detached attestation proving what executed
    ///
    /// Produces a signed .erebus.attest JSON file containing artifact hashes,
    /// provenance, and execution context. The hostname is never stored in
    /// plaintext — only a SHA-256 hash is recorded.
    Attest(commands::attest::AttestArgs),

    /// Generate or verify a signed compliance audit report
    ///
    /// Aggregates attestations, SBOM, and integrity info into a single
    /// signed JSON document suitable for regulators and auditors.
    Audit(commands::audit::AuditArgs),

    /// Generate or embed a Software Bill of Materials (SBOM)
    ///
    /// Produces a `CycloneDX` SBOM from the .erebus metadata, or embeds it
    /// in the binary for supply-chain transparency.
    ///
    /// Examples:
    ///   erebus sbom myapp.erebus
    ///   erebus sbom myapp.erebus --embed --key ~/.erebus/keys/*.key
    Sbom(commands::sbom::SbomArgs),

    /// Download the registry's monthly audit trail (JSONL)
    ///
    /// Examples:
    ///   erebus audit-log --registry <https://registry.erebus.io> --month 2026-08
    ///   erebus audit-log --registry <https://registry.erebus.io> --month 2026-08 --org acme -o audit.jsonl
    AuditLog(commands::audit_log::AuditLogArgs),

    /// Manage billing: check tier or start a Stripe Checkout
    ///
    /// Examples:
    ///   erebus billing status --registry <https://registry.erebus.io> --token <token>
    ///   erebus billing checkout --registry <https://registry.erebus.io> --plan pro --token <token>
    Billing(commands::billing::BillingArgs),

    /// Manage artifact lifecycle state (quarantine / promote / revoke)
    ///
    /// Enforces the closed trust state machine: acquired -> quarantined ->
    /// trusted -> revoked -> deleted. Only Trusted (or Acquired, if policy
    /// allows) artifacts may be served.
    ///
    /// Examples:
    ///   erebus lifecycle agent.erebus --action quarantine
    ///   erebus lifecycle agent.erebus --action promote
    ///   erebus lifecycle agent.erebus --action revoke
    Lifecycle(commands::lifecycle::LifecycleArgs),

    /// Export or import registry data for air-gapped sync
    ///
    /// Examples:
    ///   erebus mirror export --dir /var/lib/erebus-registry -o backup.mirror.enc --password <secret>
    ///   erebus mirror import --input backup.mirror.enc --dir /var/lib/erebus-registry --password <secret>
    Mirror(commands::mirror::MirrorArgs),

    /// Verify a .erebus file's signature
    Verify(commands::verify::VerifyArgs),

    /// Trust a public key
    Trust(commands::trust::TrustArgs),

    /// Scan directories for .erebus files
    Scan(commands::scan::ScanArgs),

    /// Check system prerequisites
    Doctor(commands::doctor::DoctorArgs),

    /// Clean erebus cache
    Clean(commands::clean::CleanArgs),

    /// Interactive TUI dashboard showing SISR benchmark & cache status
    Dashboard(commands::dashboard::DashboardArgs),

    /// Interactive chat with a bundled model (TUI, or browser with --web)
    ///
    /// Examples:
    ///   erebus chat agent.erebus
    ///   erebus chat agent.erebus --web --port 8080
    Chat(commands::chat::ChatArgs),

    /// Test a .erebus file in an ephemeral sandbox
    Selftest(commands::selftest::SelftestArgs),

    /// Upgrade erebus to the latest release
    Upgrade(commands::upgrade::UpgradeArgs),

    /// Migrate a legacy .erebus (v1) to the SISR-enabled v2 format
    Migrate(commands::upgrade_binary::MigrateArgs),

    /// Download a bundle from a registry (integrity-checked)
    Pull(commands::pull::PullArgs),

    /// Serve a bundle model as an OpenAI-compatible API
    ///
    /// Examples:
    ///   erebus serve agent.erebus --port 8080
    ///   erebus serve agent.erebus --ngl auto --ctx 4096
    Serve(commands::serve::ServeArgs),

    /// Publish a .erebus file to a registry
    Publish(commands::publish::PublishArgs),

    /// Replace a file inside an existing .erebus binary without rebuilding
    ///
    /// Examples:
    ///   erebus swap agent.erebus app/models/agent.gguf --from ./new.gguf
    Swap(commands::swap::SwapArgs),

    /// Manage the local shared-layer registry (runtime packs, models, tools)
    ///
    /// Examples:
    ///   erebus layer push llama.cpp --name llama-cpp --kind tool
    ///   erebus layer list
    Layer(commands::layer::LayerArgs),

    /// Show erebus environment info
    Env(commands::env::EnvArgs),

    /// Generate shell completion scripts
    Completion {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: Shell,
    },

    /// Generate man pages (to a directory)
    Man {
        /// Output directory for man pages
        #[arg(default_value = ".")]
        dir: std::path::PathBuf,
    },
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum Shell {
    Bash,
    Zsh,
    Fish,
    Elvish,
    PowerShell,
}

fn main() -> ExitCode {
    // Hide source locations in panic messages for security (no file/line info leakage)
    human_panic::setup_panic!();

    // clig.dev: "When `myapp` requires arguments to function and is run
    // with no arguments, display concise help text."
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 1 {
        eprintln!("erebus — package any app into a single self-extracting binary");
        eprintln!();
        eprintln!("Usage: erebus <COMMAND> [OPTIONS]");
        eprintln!();
        eprintln!("Most used commands:");
        eprintln!("  build       Build a .erebus binary from an app directory");
        eprintln!("  run         Execute a .erebus file");
        eprintln!("  inspect     Inspect a .erebus file's metadata");
        eprintln!("  serve       Serve a bundle model as an OpenAI-compatible API");
        eprintln!("  chat        Interactive chat with a bundled model");
        eprintln!("  attest      Generate a detached attestation proving what executed");
        eprintln!("  audit       Generate or verify a signed compliance audit report");
        eprintln!();
        eprintln!("Use 'erebus --help' for the full listing of commands and options.");
        return ExitCode::SUCCESS;
    }

    let cli = Cli::parse();

    // Respect --no-color flag and NO_COLOR env var
    if cli.no_color || std::env::var("NO_COLOR").is_ok() {
        std::env::set_var("NO_COLOR", "1");
    }

    let effective_verbose = cli.verbose && !cli.quiet;

    let result = match cli.command {
        Commands::Build(args) => commands::build::run(*args, effective_verbose),
        Commands::Run(mut args) => {
            if cli.verbose {
                args.verbose = true;
            }
            commands::run::run(args)
        }
        Commands::Inspect(args) => commands::inspect::run(args),
        Commands::Keygen(mut args) => {
            if cli.quiet {
                args.quiet = true;
            }
            commands::keygen::run(args)
        }
        Commands::Sign(mut args) => {
            if cli.quiet {
                args.quiet = true;
            }
            commands::sign::run(args)
        }
        Commands::Attest(mut args) => {
            if cli.quiet {
                args.quiet = true;
            }
            commands::attest::run(args)
        }
        Commands::Audit(mut args) => {
            if cli.quiet {
                args.quiet = true;
            }
            commands::audit::run(args)
        }
        Commands::Sbom(args) => commands::sbom::run(args),
        Commands::AuditLog(args) => commands::audit_log::run(args),
        Commands::Billing(args) => commands::billing::run(args),
        Commands::Verify(mut args) => {
            if cli.quiet {
                args.quiet = true;
            }
            commands::verify::run(args)
        }
        Commands::Lifecycle(mut args) => {
            if cli.quiet {
                args.quiet = true;
            }
            commands::lifecycle::run(args)
        }
        Commands::Mirror(args) => commands::mirror::run(args),
        Commands::Trust(mut args) => {
            if cli.quiet {
                args.quiet = true;
            }
            commands::trust::run(args)
        }
        Commands::Scan(args) => commands::scan::run(args),
        Commands::Doctor(mut args) => {
            if cli.quiet {
                args.quiet = true;
            }
            commands::doctor::run(args)
        }
        Commands::Clean(args) => commands::clean::run(args),
        Commands::Dashboard(args) => commands::dashboard::run(&args),
        Commands::Selftest(args) => match commands::selftest::run(args) {
            Ok(code) => return code,
            Err(e) => return error::exit_code_for_error(&e),
        },
        Commands::Upgrade(args) => commands::upgrade::run(args),
        Commands::Migrate(args) => commands::upgrade_binary::run(args),
        Commands::Publish(mut args) => {
            if cli.verbose {
                args.verbose = true;
            }
            if cli.quiet {
                args.verbose = false;
            }
            commands::publish::run(args)
        }
        Commands::Pull(mut args) => {
            if cli.verbose {
                args.verbose = true;
            }
            if cli.quiet {
                args.verbose = false;
            }
            commands::pull::run(args)
        }
        Commands::Chat(args) => commands::chat::run(args),
        Commands::Serve(args) => commands::serve::run(args),
        Commands::Swap(args) => commands::swap::run(args),
        Commands::Layer(args) => commands::layer::run(args),
        Commands::Env(args) => commands::env::run(args),
        Commands::Completion { shell } => {
            let mut cmd = Cli::command();
            let bin_name = "erebus";
            match shell {
                Shell::Bash => generate(Bash, &mut cmd, bin_name, &mut io::stdout()),
                Shell::Zsh => generate(Zsh, &mut cmd, bin_name, &mut io::stdout()),
                Shell::Fish => generate(Fish, &mut cmd, bin_name, &mut io::stdout()),
                Shell::Elvish => generate(Elvish, &mut cmd, bin_name, &mut io::stdout()),
                Shell::PowerShell => generate(PowerShell, &mut cmd, bin_name, &mut io::stdout()),
            }
            Ok(())
        }
        Commands::Man { dir } => generate_man_pages(&dir),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("Error: {err:#}");
            error::exit_code_for_error(&err)
        }
    }
}

fn generate_man_pages(dir: &std::path::Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)?;

    let cmd = Cli::command();
    let version = env!("CARGO_PKG_VERSION");
    let author = "Ted Kouhouenou <ted.sig42@tutamail.com>";
    let manual = format!("erebus {version}");

    // ── Main man page (erebus.1) ────────────────────────────────────────
    let man = clap_mangen::Man::new(cmd.clone())
        .section("1")
        .manual(&manual)
        .source(author);
    let mut buffer = Vec::new();
    man.render(&mut buffer)?;

    let extra = format!(
        r"
EXIT STATUS
       0      Success.

       1      General error (invalid arguments, build failure, I/O error).

       2      Lint or verification error (signature mismatch, corrupt file).

       3      Data error (parse failure, invalid format).

       4      Permission error (insufficient privileges, file not writable).

       5      Not found (file, directory, or dependency missing).

ENVIRONMENT
       ERE_CACHE_DIR
              Override the cache directory (default: ~/.cache/erebus).

       ERE_VERBOSE
              If set, enable verbose output (equivalent to -v).

       XDG_DATA_HOME
              Base directory for erebus keys and trusted keys.

FILES
       ~/.cache/erebus/<hash>/rootfs/
              Extracted rootfs for each built binary, keyed by SHA-256 hash.

       ~/.erebus/trusted-keys/
              Directory of trusted public keys for signature verification.

       ~/.local/share/erebus/keys/
              Default directory for generated signing keys.

SEE ALSO
       erebus-build(1), erebus-sign(1), erebus-verify(1), erebus-keygen(1),
       erebus-inspect(1), erebus-doctor(1)

AUTHORS
       Written by {author}.

HISTORY
       erebus was started in 2025 to solve the problem of
       packaging complex multi-dependency applications into a single
       portable binary.  The Rust CLI (v0.1.0) replaced the legacy
       Python CLI in 2026.

BUGS
        Report bugs at: https://github.com/Tednoob17/erebus/issues

UNINSTALL
        rm $(which erebus) && rm -rf ~/.cache/erebus ~/.local/share/erebus
"
    );
    buffer.extend_from_slice(extra.as_bytes());
    std::fs::write(dir.join("erebus.1"), &buffer)?;

    // ── Subcommand man pages ──────────────────────────────────────────
    let sub_extras: &[(&str, &str)] = &[
        ("build", "ENVIRONMENT\n       ERE_CACHE_DIR\n              Override the cache directory.\n"),
        ("run", ""),
        ("sign", "ENVIRONMENT\n       XDG_DATA_HOME\n              Base directory for key lookup.\n"),
        ("verify", "ENVIRONMENT\n       XDG_DATA_HOME\n              Base directory for trusted key lookup.\n"),
        ("keygen", "ENVIRONMENT\n       XDG_DATA_HOME\n              Base directory for key storage.\n"),
        ("doctor", ""),
        ("selftest", ""),
        ("upgrade", ""),
        ("upgrade-binary", "ENVIRONMENT\n       XDG_DATA_HOME\n              Base directory for key lookup.\n"),
        ("inspect", ""),
        ("scan", ""),
        ("clean", "FILES\n       ~/.cache/erebus/\n              The cache directory cleaned by this command.\n"),
        ("dashboard", ""),
        ("env", ""),
        ("trust", "ENVIRONMENT\n       XDG_DATA_HOME\n              Base directory for trusted key storage.\n"),
        ("completion", ""),
        ("man", ""),
    ];

    for sub in cmd.get_subcommands() {
        let sub_name = sub.get_name().to_owned();
        let sub = sub.clone();

        let man = clap_mangen::Man::new(sub)
            .section("1")
            .manual(&manual)
            .source(author);
        let mut buffer = Vec::new();
        man.render(&mut buffer)?;

        let extra_footer = sub_extras
            .iter()
            .find(|(name, _)| *name == sub_name)
            .map(|(_, e)| *e)
            .unwrap_or("");

        let shared = format!(
            r"
EXIT STATUS
       0      Success.

       1      General error.

       2      Verification error.

       3      Data error.

       4      Permission error.

       5      Not found.

SEE ALSO
       erebus(1)

AUTHORS
       Written by {author}.

HISTORY
       Part of erebus since v0.1.0.
{extra_footer}"
        );
        buffer.extend_from_slice(shared.as_bytes());
        std::fs::write(dir.join(format!("erebus-{sub_name}.1")), &buffer)?;
    }

    eprintln!("Generated man pages in {}", dir.display());
    Ok(())
}
