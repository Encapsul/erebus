//! Runtime detection — identifies which runtime an app directory uses.
//!
//! AI-agent focus: only Python and native Binary (e.g. llama.cpp) are
//! supported. Other runtimes were removed from the product scope.

use std::io::Read;
use std::path::Path;

/// Detected runtime type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Runtime {
    Python,
    Binary,
}

impl Runtime {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Python => "python",
            Self::Binary => "binary",
        }
    }

    /// Parse a runtime name as written in the binary metadata. Returns `None`
    /// for unknown names so callers can reject crafted metadata instead of
    /// silently falling back to a default interpreter.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "python" => Some(Self::Python),
            "binary" => Some(Self::Binary),
            _ => None,
        }
    }
}

/// Detect the runtime for an app directory by checking marker files.
/// Returns the first match in priority order, preferring runtimes with entry files.
pub fn detect_runtime(app_dir: &Path) -> Option<Runtime> {
    let detected = detect_runtime_candidates(app_dir);

    // Prefer a runtime that has an identifiable entry file.
    for (runtime, _) in &detected {
        let has_entry = match runtime {
            Runtime::Python => {
                find_first_file(app_dir, &["app.py", "main.py", "__main__.py", "server.py"])
                    .is_some()
            }
            Runtime::Binary => false,
        };
        if has_entry {
            return Some(*runtime);
        }
    }

    detected.into_iter().next().map(|(r, _)| r)
}

/// Detect all runtime candidates, returning (runtime, `has_marker`) pairs.
fn detect_runtime_candidates(dir: &Path) -> Vec<(Runtime, bool)> {
    let mut candidates = Vec::new();

    if detect_python(dir) {
        candidates.push((Runtime::Python, true));
    }
    if detect_binary(dir) {
        candidates.push((Runtime::Binary, true));
    }

    candidates
}

fn detect_python(dir: &Path) -> bool {
    ["app.py", "main.py", "__main__.py", "server.py"]
        .iter()
        .any(|f| dir.join(f).is_file())
        || dir.join("pyproject.toml").is_file()
        || dir.join("setup.py").is_file()
        || dir.join("requirements.txt").is_file()
}

fn has_python_dep(dir: &Path, dep: &str) -> bool {
    if let Ok(content) = std::fs::read_to_string(dir.join("requirements.txt")) {
        return content.lines().any(|line| {
            let name = line.split_whitespace().next().unwrap_or("");
            let name = name
                .split(['>', '<', '=', '!'])
                .next()
                .unwrap_or(name)
                .to_lowercase()
                .replace('-', "_");
            name == dep.replace('-', "_")
        });
    }
    if let Ok(content) = std::fs::read_to_string(dir.join("pyproject.toml")) {
        return content.contains(dep);
    }
    false
}

fn detect_binary(dir: &Path) -> bool {
    let mut native_count = 0;
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return false,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if is_native_binary(&path) {
            native_count += 1;
            if native_count > 1 {
                return false;
            }
        }
    }
    native_count == 1
}

/// True if `path` is an ELF or PE (`.exe`) executable by magic bytes.
fn is_native_binary(path: &Path) -> bool {
    let mut magic = [0u8; 4];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut magic))
        .map(|()| &magic[..] == b"\x7fELF" || (magic[0] == b'M' && magic[1] == b'Z'))
        .unwrap_or(false)
}

/// Resolve the entrypoint argv for a detected runtime.
///
/// Returns `None` if the entry file cannot be determined.
/// Interpreter names are bare (e.g. `python3`) — the stub uses
/// `execvp` which resolves them via PATH. App paths use `/app/` prefix.
///
/// NOTE: intentionally >100 lines because this is the central dispatch for
/// all supported runtimes (Python, Binary).
#[allow(clippy::too_many_lines)]
pub fn resolve_entrypoint(app_dir: &Path, runtime: Runtime) -> Option<Vec<String>> {
    match runtime {
        Runtime::Python => {
            // 0. Django manage.py
            if app_dir.join("manage.py").is_file() {
                return Some(vec![
                    "python3".into(),
                    "/app/manage.py".into(),
                    "runserver".into(),
                    "0.0.0.0:8000".into(),
                ]);
            }
            // 0b. Streamlit
            if has_python_dep(app_dir, "streamlit") {
                if let Some(entry) = find_first_file(app_dir, &["app.py", "main.py", "server.py"]) {
                    return Some(vec![
                        "streamlit".into(),
                        "run".into(),
                        format!("/app/{}", entry),
                        "--server.port".into(),
                        "8501".into(),
                        "--server.address".into(),
                        "0.0.0.0".into(),
                    ]);
                }
            }
            // 1. FastAPI / ASGI: uvicorn or gunicorn with uvicorn worker
            if let Some(asgi) = detect_asgi_entrypoint(app_dir) {
                return Some(asgi);
            }
            // 2. PEP 621 pyproject.toml [project.scripts]
            if let Some(script) = detect_pyproject_scripts(app_dir) {
                return Some(script);
            }
            // 3. python -m module
            if let Some(module) = detect_python_module(app_dir) {
                return Some(vec!["python3".into(), "-m".into(), module]);
            }
            // 4. Script fallback
            let entry =
                find_first_file(app_dir, &["app.py", "main.py", "__main__.py", "server.py"])?;
            Some(vec!["python3".into(), format!("/app/{}", entry)])
        }
        Runtime::Binary => {
            let bin = find_native_binary(app_dir)?;
            Some(vec![format!("/app/{}", bin)])
        }
    }
}

/// Detect Python `-m` module entrypoint from `pyproject.toml` or package layout.
/// Returns `Some(module)` if the app should be launched with `python3 -m <module>`.
fn detect_python_module(app_dir: &Path) -> Option<String> {
    if let Ok(content) = std::fs::read_to_string(app_dir.join("pyproject.toml")) {
        if let Ok(pyproject) = content.parse::<toml::Value>() {
            if let Some(tool) = pyproject.get("tool") {
                let has_fastapi = tool.get("fastapi").is_some();
                let entrypoint = tool.get("entrypoint").and_then(|v| v.as_str()).or_else(|| {
                    tool.as_table().and_then(|table| {
                        table
                            .values()
                            .find_map(|v| v.get("entrypoint").and_then(|v| v.as_str()))
                    })
                });
                if has_fastapi || entrypoint.is_some() {
                    if let Some(ep) = entrypoint {
                        let module = ep.split(':').next()?.to_string();
                        if !module.is_empty() {
                            return Some(module);
                        }
                    }
                }
            }
        }
    }
    if app_dir.join("__main__.py").is_file() {
        if let Ok(entries) = std::fs::read_dir(app_dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_dir()
                    && p.join("__init__.py").is_file()
                    && !p.file_name()?.to_str()?.starts_with('.')
                {
                    return p.file_name()?.to_str().map(String::from);
                }
            }
        }
    }
    None
}

/// Detect ASGI entrypoint (uvicorn / gunicorn with uvicorn worker) from
/// `pyproject.toml`, `requirements.txt`, or installed package layout.
/// Returns `Some(argv)` with the full server command.
fn detect_asgi_entrypoint(app_dir: &Path) -> Option<Vec<String>> {
    // Check pyproject.toml for [tool.uvicorn] or gunicorn config
    if let Ok(content) = std::fs::read_to_string(app_dir.join("pyproject.toml")) {
        if let Ok(pyproject) = content.parse::<toml::Value>() {
            if let Some(tool) = pyproject.get("tool") {
                if tool.get("uvicorn").is_some() || tool.get("gunicorn").is_some() {
                    let app = tool.get("app").and_then(|v| v.as_str()).or_else(|| {
                        tool.as_table().and_then(|table| {
                            table
                                .values()
                                .find_map(|v| v.get("app").and_then(|v| v.as_str()))
                        })
                    });
                    if let Some(app_str) = app {
                        let app = app_str.trim().trim_matches('"').to_string();
                        if !app.is_empty() {
                            return Some(vec![
                                "uvicorn".into(),
                                app,
                                "--host".into(),
                                "0.0.0.0".into(),
                                "--port".into(),
                                "8000".into(),
                            ]);
                        }
                    }
                }
            }
        }
    }
    // Check requirements.txt for uvicorn/gunicorn presence
    if let Ok(content) = std::fs::read_to_string(app_dir.join("requirements.txt")) {
        if content.contains("uvicorn") || content.contains("gunicorn") {
            // Find the app module: look for main.py, app.py, or package __main__.py
            let app_module = find_first_file(app_dir, &["main.py", "app.py"])
                .or_else(|| detect_python_module(app_dir).map(|m| format!("{m}:app")))?;
            let module = app_module.strip_suffix(".py").unwrap_or(&app_module);
            return Some(vec![
                "uvicorn".into(),
                format!("{module}:app"),
                "--host".into(),
                "0.0.0.0".into(),
                "--port".into(),
                "8000".into(),
            ]);
        }
    }
    None
}

/// Detect PEP 621 `[project.scripts]` entrypoints from `pyproject.toml`.
/// Returns `Some(argv)` if a `start` or run script is defined.
fn detect_pyproject_scripts(app_dir: &Path) -> Option<Vec<String>> {
    let content = std::fs::read_to_string(app_dir.join("pyproject.toml")).ok()?;
    let mut in_scripts = false;
    let mut start_cmd = None;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("[project.scripts]") {
            in_scripts = true;
            continue;
        }
        if in_scripts && trimmed.starts_with('[') {
            break;
        }
        if in_scripts && trimmed.starts_with("start") {
            if let Some((_, cmd)) = trimmed.split_once('=') {
                start_cmd = Some(cmd.trim().trim_matches('"').to_string());
                break;
            }
        }
    }
    start_cmd.map(|cmd| {
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        parts.into_iter().map(|s| s.into()).collect()
    })
}

/// Find the first existing file from a list of candidates.
/// Returns the filename (not full path).
fn find_first_file(dir: &Path, candidates: &[&str]) -> Option<String> {
    for name in candidates {
        if dir.join(name).is_file() {
            return Some((*name).to_string());
        }
    }
    None
}

/// Find the single native entry binary (ELF or PE `.exe`) in `dir`.
fn find_native_binary(dir: &Path) -> Option<String> {
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_file() && is_native_binary(&p) {
            return p.file_name()?.to_str().map(String::from);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn detect_python_app() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("app.py"), "print('hi')").unwrap();
        assert_eq!(detect_runtime(dir.path()), Some(Runtime::Python));
    }

    #[test]
    fn detect_python_pyproject_only() {
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("pyproject.toml"),
            "[project]\nname = \"myapp\"",
        )
        .unwrap();
        assert_eq!(detect_runtime(dir.path()), Some(Runtime::Python));
    }

    #[test]
    fn detect_python_setup_py() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("setup.py"), "").unwrap();
        assert_eq!(detect_runtime(dir.path()), Some(Runtime::Python));
    }

    // A package.json alone is no longer a runtime marker: Node support was
    // removed from the product scope.
    #[test]
    fn package_json_alone_is_not_a_runtime() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("package.json"), "{}").unwrap();
        assert_eq!(detect_runtime(dir.path()), None);
    }

    #[test]
    fn no_runtime_returns_none() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("README.md"), "hi").unwrap();
        assert_eq!(detect_runtime(dir.path()), None);
    }

    #[test]
    fn detect_pe_exe_as_binary() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("app.exe"), b"MZ\x90\x00").unwrap();
        assert_eq!(detect_runtime(dir.path()), Some(Runtime::Binary));
        assert_eq!(
            resolve_entrypoint(dir.path(), Runtime::Binary),
            Some(vec!["/app/app.exe".into()])
        );
    }

    #[test]
    fn pe_and_elf_is_not_binary() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("a.exe"), b"MZ\x90\x00").unwrap();
        std::fs::write(dir.path().join("b.elf"), b"\x7fELF").unwrap();
        assert_eq!(detect_runtime(dir.path()), None);
    }

    #[test]
    fn python_elf_combo_prefers_python_entry() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("app.py"), "print('hi')").unwrap();
        std::fs::write(dir.path().join("model-runner"), b"\x7fELF").unwrap();
        assert_eq!(detect_runtime(dir.path()), Some(Runtime::Python));
        let ep = resolve_entrypoint(dir.path(), Runtime::Python);
        assert_eq!(ep, Some(vec!["python3".into(), "/app/app.py".into()]));
    }

    #[test]
    fn detect_elf_binary_entrypoint() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("llama-server"), b"\x7fELF").unwrap();
        assert_eq!(detect_runtime(dir.path()), Some(Runtime::Binary));
        assert_eq!(
            resolve_entrypoint(dir.path(), Runtime::Binary),
            Some(vec!["/app/llama-server".into()])
        );
    }

    #[test]
    fn detect_python_fastapi_module_entrypoint() {
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("pyproject.toml"),
            r#"[tool.fastapi]
entrypoint = "app.main:app"
"#,
        )
        .unwrap();
        std::fs::create_dir(dir.path().join("app")).unwrap();
        std::fs::write(dir.path().join("app").join("__init__.py"), "").unwrap();
        std::fs::write(dir.path().join("app").join("main.py"), "").unwrap();
        assert_eq!(detect_runtime(dir.path()), Some(Runtime::Python));
        let ep = resolve_entrypoint(dir.path(), Runtime::Python);
        assert_eq!(
            ep,
            Some(vec!["python3".into(), "-m".into(), "app.main".into()])
        );
    }

    #[test]
    fn detect_python_package_main_entrypoint() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("__main__.py"), "print('hi')").unwrap();
        std::fs::create_dir(dir.path().join("mypackage")).unwrap();
        std::fs::write(dir.path().join("mypackage").join("__init__.py"), "").unwrap();
        let ep = resolve_entrypoint(dir.path(), Runtime::Python);
        assert_eq!(
            ep,
            Some(vec!["python3".into(), "-m".into(), "mypackage".into()])
        );
    }

    #[test]
    fn detect_python_script_fallback() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("app.py"), "print('hi')").unwrap();
        let ep = resolve_entrypoint(dir.path(), Runtime::Python);
        assert_eq!(ep, Some(vec!["python3".into(), "/app/app.py".into()]));
    }

    #[test]
    fn detect_django_manage_py() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("manage.py"), "#!/usr/bin/env python\n").unwrap();
        std::fs::write(dir.path().join("requirements.txt"), "Django\n").unwrap();
        let ep = resolve_entrypoint(dir.path(), Runtime::Python);
        assert_eq!(
            ep,
            Some(vec![
                "python3".into(),
                "/app/manage.py".into(),
                "runserver".into(),
                "0.0.0.0:8000".into(),
            ])
        );
    }

    #[test]
    fn detect_fastapi_uvicorn_entrypoint() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("requirements.txt"), "fastapi\nuvicorn\n").unwrap();
        std::fs::write(dir.path().join("main.py"), "app = FastAPI()\n").unwrap();
        let ep = resolve_entrypoint(dir.path(), Runtime::Python);
        assert_eq!(
            ep,
            Some(vec![
                "uvicorn".into(),
                "main:app".into(),
                "--host".into(),
                "0.0.0.0".into(),
                "--port".into(),
                "8000".into(),
            ])
        );
    }

    #[test]
    fn detect_python_pyproject_scripts() {
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("pyproject.toml"),
            r#"[project.scripts]
start = "uvicorn main:app"
"#,
        )
        .unwrap();
        std::fs::write(dir.path().join("main.py"), "").unwrap();
        let ep = resolve_entrypoint(dir.path(), Runtime::Python);
        assert_eq!(ep, Some(vec!["uvicorn".into(), "main:app".into()]));
    }

    #[test]
    fn python_streamlit_entrypoint() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("app.py"), "").unwrap();
        std::fs::write(dir.path().join("requirements.txt"), "streamlit==1.37.0\n").unwrap();
        let ep = resolve_entrypoint(dir.path(), Runtime::Python);
        assert_eq!(
            ep,
            Some(vec![
                "streamlit".into(),
                "run".into(),
                "/app/app.py".into(),
                "--server.port".into(),
                "8501".into(),
                "--server.address".into(),
                "0.0.0.0".into(),
            ])
        );
    }

    #[test]
    fn python_streamlit_with_hyphen() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("main.py"), "").unwrap();
        std::fs::write(
            dir.path().join("requirements.txt"),
            "streamlit>=1.0\nfastapi\n",
        )
        .unwrap();
        let ep = resolve_entrypoint(dir.path(), Runtime::Python);
        assert!(ep.unwrap().contains(&"streamlit".to_string()));
    }

    #[test]
    fn from_name_roundtrips_all_runtimes() {
        for runtime in [Runtime::Python, Runtime::Binary] {
            let name = runtime.name();
            assert_eq!(Runtime::from_name(name), Some(runtime), "name: {name}");
        }
        // Removed runtimes must not parse back — crafted metadata cannot
        // resurrect them.
        assert_eq!(Runtime::from_name("node"), None);
        assert_eq!(Runtime::from_name("cobol"), None);
        assert_eq!(Runtime::from_name(""), None);
    }
}
