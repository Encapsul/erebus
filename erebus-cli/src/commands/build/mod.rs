mod args;
pub(crate) mod deps;
pub(crate) mod payload;
mod pipeline;
mod release_stub;
mod sign;
mod sisr;
mod stub;
mod universal;

pub(crate) use args::{load_config, BuildArgs, BuildPlan, NglPolicy};
use payload::{count_files, print_tree};
use pipeline::{build_single_target, warn_sandbox_noops};

use anyhow::{Context, Result};
use erebus_core::detect;
use std::path::Path;

pub fn run(args: BuildArgs, verbose: bool) -> Result<()> {
    // Quiet mode overrides verbose
    let verbose = verbose && !args.quiet;

    let app_dir = args
        .app
        .canonicalize()
        .context("failed to canonicalize app path")?;
    if !app_dir.is_dir() {
        anyhow::bail!("{} is not a directory", app_dir.display());
    }

    // Load .erebus.toml config if present
    let config = load_config(&app_dir);

    // Agentfile/.erebus.toml agent fields (model, env, entrypoint, ngl...)
    // merged onto args — explicit CLI flags keep precedence.
    let mut args = args;
    args::apply_config_overrides(&mut args, &config);

    // Apply config defaults (CLI flags override). Clone the args fields so
    // `&args` stays borrowable for the per-target loop below.
    let isolation = if args.isolation != "sandbox" {
        args.isolation.clone()
    } else {
        config.build.isolation.unwrap_or_else(|| "sandbox".into())
    };
    let isolation_num = args::parse_isolation(&isolation)
        .with_context(|| format!("invalid --isolation value: '{isolation}'"))?;

    // Detect runtime
    let runtime = detect::detect_runtime(&app_dir)
        .context("could not detect runtime — supported: python, binary")?;
    let runtime_name = runtime.name().to_string();

    eprintln!("Detected runtime: {runtime_name}");

    let targets = args::resolve_targets(&args, config.build.target.as_deref());
    let outputs = args::output_paths(&args, &targets);
    let plan = BuildPlan {
        verbose,
        app_dir,
        runtime,
        runtime_name,
        isolation,
        isolation_num,
        no_install: args.no_install || config.build.no_install.unwrap_or(false),
        seccomp: args.seccomp || config.build.seccomp.unwrap_or(false),
        landlock: args.landlock || config.build.landlock.unwrap_or(false),
        gui: args.gui || config.build.gui.unwrap_or(false),
        encrypt: args.encrypt || config.build.encrypt.unwrap_or(false),
        squashfs: args.squashfs || config.build.squashfs.unwrap_or(false),
        version_info: args.version_info.clone().or(config.package.version),
        author: args.author.clone().or(config.package.author),
        description: args.description.clone().or(config.package.description),
        license: args.license.clone().or(config.package.license),
        env_file: args
            .env_file
            .clone()
            .or(config.build.env_file.map(std::path::PathBuf::from)),
        targets,
        outputs,
    };

    if args.dry_run && args.universal {
        let matrix = match &args.target {
            Some(t) => t
                .split(',')
                .map(|s| s.trim().to_string())
                .collect::<Vec<_>>(),
            None => erebus_core::polyglot::DEFAULT_UNIVERSAL_TARGETS
                .iter()
                .map(|(triple, _, _, _)| (*triple).to_string())
                .collect(),
        };
        eprintln!("Dry run — would build universal binary:");
        eprintln!("  App:       {}", plan.app_dir.display());
        eprintln!("  Output:    {}", args.output.display());
        for t in &matrix {
            eprintln!("  Slice:     {t}");
        }
        return Ok(());
    }

    if args.dry_run {
        for (target, output) in plan.targets.iter().zip(&plan.outputs) {
            print_dry_run(&args, &plan, target.as_deref(), output);
        }
        return Ok(());
    }

    // clig.dev: destructive overwrite requires explicit consent. Refuse to
    // clobber an existing artifact unless `--force` was given; `--update` is
    // the sanctioned in-place path (it reads the existing file's hashes).
    if !args.force && !args.update {
        if let Some(existing) = plan.outputs.iter().find(|p| p.exists()) {
            anyhow::bail!(
                "output {} already exists (pass --force to overwrite, or --update \
                 for an incremental rebuild)",
                existing.display()
            );
        }
    }

    // Universal mode replaces the per-target artifact loop: one polyglot
    // file containing a slice per matrix entry.
    if args.universal {
        return universal::run(&args, &plan, verbose);
    }

    // Build one artifact per target; each gets its own output path.
    let mut json_results: Vec<serde_json::Value> = Vec::new();
    for (target, output) in plan.targets.iter().zip(&plan.outputs) {
        if let Some(result) = build_single_target(&args, &plan, target.clone(), output)? {
            json_results.push(result);
        }
    }
    if args.json {
        let doc = if json_results.len() == 1 {
            json_results.remove(0)
        } else {
            serde_json::Value::Array(json_results)
        };
        println!("{}", serde_json::to_string_pretty(&doc)?);
    }
    Ok(())
}

fn print_dry_run(args: &BuildArgs, plan: &BuildPlan, target: Option<&str>, output: &Path) {
    eprintln!("Dry run — would build:");
    eprintln!("  App:       {}", plan.app_dir.display());
    eprintln!("  Output:    {}", output.display());
    eprintln!("  Runtime:   {}", plan.runtime_name);
    eprintln!("  Isolation: {}", plan.isolation);
    eprintln!("  Seccomp:   {}", plan.seccomp);
    eprintln!("  Landlock:  {}", plan.landlock);
    eprintln!("  GUI:       {}", plan.gui);
    warn_sandbox_noops(plan.isolation_num, plan.seccomp, plan.landlock);
    eprintln!("  Encrypt:   {}", plan.encrypt);
    eprintln!("  SquashFS:  {}", plan.squashfs);
    if args.enable_sisr {
        eprintln!("  SISR:      enabled (delta-indexed, <output>.manifest)");
        match &args.update_url {
            Some(url) => eprintln!("  Update URL: {url}"),
            None => {
                eprintln!("  Update URL: (none — updates must pass a URL or set ERE_UPDATE_URL)");
            }
        }
    }
    if let Some(ref v) = plan.version_info {
        eprintln!("  Version:   {v}");
    }
    if let Some(ref a) = plan.author {
        eprintln!("  Author:    {a}");
    }
    if let Some(ref d) = plan.description {
        eprintln!("  Desc:      {d}");
    }
    if let Some(ref l) = plan.license {
        eprintln!("  License:   {l}");
    }
    if let Some(t) = target {
        eprintln!("  Target:    {t}");
    }
    if let Some(ref e) = plan.env_file {
        eprintln!("  Env file:  {}", e.display());
    }
    if plan.no_install {
        eprintln!("  No install: yes");
    }
    if args.update {
        eprintln!("  Update:    yes (incremental)");
    }
    if args.persist {
        eprintln!("  Persist:   yes");
    }
    if let Some(port) = args.health_port {
        eprintln!("  Health:    port {port}");
    }
    if let Some(otel) = args.otel_endpoint.as_deref() {
        eprintln!("  OTel:      {otel}");
    }
    if !args.cron.is_empty() {
        eprintln!("  Cron:      {} task(s)", args.cron.len());
    }
    if !args.include.is_empty() {
        for inc in &args.include {
            eprintln!("  Include:   {}", inc.display());
        }
    }

    // Detect package managers
    let all_mgrs = erebus_core::pkgmgr::detect_all_pkgmgrs(&plan.app_dir, &plan.runtime_name);
    if all_mgrs.is_empty() {
        eprintln!("  Pkg mgr:   (none)");
    } else {
        for mgr in &all_mgrs {
            eprintln!("  Pkg mgr:   {}", mgr.name());
            if !plan.no_install {
                let cmd = mgr.install_cmd();
                eprintln!("  Install:   {}", cmd.join(" "));
            }
        }
    }

    // Estimate sizes
    let file_count = count_files(&plan.app_dir);
    eprintln!("  Files:     {file_count}");

    if plan.verbose {
        eprintln!("\nFile tree:");
        print_tree(&plan.app_dir, 2);
    }
}
