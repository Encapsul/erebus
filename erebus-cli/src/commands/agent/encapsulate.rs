//! Package task config into a `.erebus` so receipts can name the bundle hash.
//!
//! MVP: write a temp Python app that embeds the run descriptor, `erebus build`
//! it (isolation=none, `no_install`), and use `AttestationTemplate::from_bundle`
//! as the receipt subject. The HTTP agent loop still runs in this CLI process.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::{json, Value};

use crate::commands::build::{self, BuildArgs};

/// Build a `.erebus` whose payload is the agent task descriptor.
pub fn build_task_bundle(descriptor: &Value, output: &Path, force: bool) -> Result<PathBuf> {
    let tmp = tempfile::tempdir().context("temp app dir for agent encapsulate")?;
    let app = tmp.path();
    let task_path = app.join("task.json");
    std::fs::write(
        &task_path,
        serde_json::to_vec_pretty(descriptor).context("serialize task.json")?,
    )?;
    std::fs::write(app.join("app.py"), APP_PY)?;
    // Keep the temp dir alive until build finishes by leaking into a path we
    // own under the output's parent when possible — build reads the app tree.
    let staged = output
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!(".erebus-agent-build-{}", std::process::id()));
    if staged.exists() {
        let _ = std::fs::remove_dir_all(&staged);
    }
    copy_dir(app, &staged)?;
    drop(tmp);

    let args = BuildArgs {
        app: staged.clone(),
        output: output.to_path_buf(),
        force,
        isolation: "none".into(),
        no_install: true,
        quiet: true,
        description: Some("erebus agent task bundle".into()),
        ..build_args_defaults()
    };
    build::run(args, false).with_context(|| {
        format!(
            "erebus build failed for encapsulated agent at {}",
            output.display()
        )
    })?;
    let _ = std::fs::remove_dir_all(&staged);
    Ok(output.to_path_buf())
}

/// Descriptor stored in the bundle and hashed when `--bundle` is unset before
/// encapsulate fills it.
pub fn task_descriptor(
    provider: &str,
    model: &str,
    base_host: &str,
    task: &str,
    tools: &[String],
) -> Value {
    json!({
        "kind": "agent-task",
        "provider": provider,
        "model": model,
        "base_host": base_host,
        "task": task,
        "tools": tools,
    })
}

fn copy_dir(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let to = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&entry.path(), &to)?;
        } else {
            std::fs::copy(entry.path(), &to)?;
        }
    }
    Ok(())
}

fn build_args_defaults() -> BuildArgs {
    BuildArgs {
        app: PathBuf::from("."),
        output: PathBuf::from("app.erebus"),
        force: false,
        target: None,
        universal: false,
        isolation: "sandbox".into(),
        policy: None,
        seccomp: false,
        gui: false,
        landlock: false,
        encrypt: false,
        squashfs: false,
        key: None,
        enable_sisr: false,
        update_url: None,
        no_install: false,
        env_file: None,
        env: Vec::new(),
        define: Vec::new(),
        version_info: None,
        author: None,
        description: None,
        license: None,
        dry_run: false,
        update: false,
        include: Vec::new(),
        persist: false,
        health_port: None,
        otel_endpoint: None,
        otel_protocol: "grpc".into(),
        cron: Vec::new(),
        redetect: false,
        embed_interpreter: None,
        interpreter_path: None,
        cross_compile: None,
        use_cache: false,
        clear_cache: false,
        remote_cache_url: None,
        remote_cache_max_entries: None,
        compression_level: 3,
        health_endpoint: None,
        json: false,
        quiet: false,
        embed_model: None,
        entrypoint: Vec::new(),
        engine: None,
        ngl: None,
    }
}

const APP_PY: &str = r#"#!/usr/bin/env python3
"""erebus agent task bundle — identity payload for receipt subjects.

Running this binary prints the embedded task.json. The attested HTTP agent
loop still runs via `erebus agent run`; this file exists so the bundle hash
commits the task config.
"""
import json
import pathlib
import sys

def main() -> int:
    path = pathlib.Path(__file__).with_name("task.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    print(json.dumps(data, sort_keys=True))
    return 0

if __name__ == "__main__":
    sys.exit(main())
"#;
