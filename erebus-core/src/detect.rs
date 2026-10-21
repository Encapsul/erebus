//! Runtime detection — identifies which runtime an app directory uses.
//!
//! AI-agent focus: only Python and native Binary (e.g. llama.cpp) are
//! supported. Other runtimes were removed from the product scope.

use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};

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

/// Why runtime detection failed (for actionable CLI errors).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetectFailure {
    /// No Python marker and no single native binary.
    NoRuntime,
    /// More than one ELF/PE/Mach-O file at the app root.
    AmbiguousNative { binaries: Vec<String> },
    /// `PyInstaller` onefile, `.pyz` zipapp, or similar unsupported bundle.
    UnsupportedBundle { kind: &'static str, detail: String },
    /// A `.venv`/`venv` exists but there is no entrypoint or requirements.txt.
    VenvWithoutEntrypoint,
}

impl fmt::Display for DetectFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRuntime => write!(
                f,
                "could not detect runtime — supported: python \
                 (app.py/main.py/shebang script), binary (single ELF/PE/Mach-O)"
            ),
            Self::AmbiguousNative { binaries } => write!(
                f,
                "ambiguous native binary: found {} executables at app root ({}); \
                 keep a single ELF, PE, or Mach-O entry binary, or add a Python \
                 entrypoint (app.py / main.py / shebang script)",
                binaries.len(),
                binaries.join(", ")
            ),
            Self::UnsupportedBundle { kind, detail } => write!(
                f,
                "unsupported {kind}: {detail}. erebus packages source apps or a \
                 single native binary — not PyInstaller onefile or zipapp (.pyz). \
                 Build from the Python sources (or a plain ELF) instead"
            ),
            Self::VenvWithoutEntrypoint => write!(
                f,
                "found a virtualenv (.venv/ or venv/) but no Python entrypoint \
                 and no requirements.txt — add app.py/main.py (or a python \
                 shebang script), or requirements.txt plus an entry module"
            ),
        }
    }
}

/// Detect the runtime for an app directory.
///
/// Returns a structured failure when the directory is ambiguous or contains
/// an unsupported bundle so the CLI can print an actionable message.
pub fn detect_runtime(app_dir: &Path) -> Result<Runtime, DetectFailure> {
    if let Some(failure) = detect_unsupported_bundle(app_dir) {
        return Err(failure);
    }

    let detected = detect_runtime_candidates(app_dir);

    // Prefer a runtime that has an identifiable entry file.
    for (runtime, _) in &detected {
        let has_entry = match runtime {
            Runtime::Python => python_entry_name(app_dir).is_some(),
            Runtime::Binary => false,
        };
        if has_entry {
            return Ok(*runtime);
        }
    }

    if let Some((runtime, _)) = detected.into_iter().next() {
        return Ok(runtime);
    }

    let natives = list_native_binaries(app_dir);
    if natives.len() > 1 {
        return Err(DetectFailure::AmbiguousNative { binaries: natives });
    }

    if find_venv_site_packages(app_dir).is_some() && !has_python_dep_marker(app_dir) {
        return Err(DetectFailure::VenvWithoutEntrypoint);
    }

    Err(DetectFailure::NoRuntime)
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
    python_named_entry(dir).is_some()
        || dir.join("pyproject.toml").is_file()
        || dir.join("setup.py").is_file()
        || dir.join("requirements.txt").is_file()
        || dir.join("manage.py").is_file()
        || !list_python_shebang_scripts(dir).is_empty()
}

fn has_python_dep_marker(dir: &Path) -> bool {
    python_named_entry(dir).is_some()
        || dir.join("pyproject.toml").is_file()
        || dir.join("setup.py").is_file()
        || dir.join("requirements.txt").is_file()
        || dir.join("manage.py").is_file()
        || !list_python_shebang_scripts(dir).is_empty()
}

fn python_named_entry(dir: &Path) -> Option<String> {
    find_first_file(dir, &["app.py", "main.py", "__main__.py", "server.py"])
}

fn python_entry_name(dir: &Path) -> Option<String> {
    python_named_entry(dir).or_else(|| find_python_shebang_entry(dir))
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
    list_native_binaries(dir).len() == 1
}

fn list_native_binaries(dir: &Path) -> Vec<String> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    let mut names = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() && is_native_binary(&path) {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                names.push(name.to_string());
            }
        }
    }
    names.sort();
    names
}

/// True if `path` is an ELF, PE (`.exe`) or Mach-O executable by magic bytes.
fn is_native_binary(path: &Path) -> bool {
    let mut buf = Vec::with_capacity(8);
    let Ok(n) = std::fs::File::open(path).and_then(|f| f.take(8).read_to_end(&mut buf)) else {
        return false;
    };
    let mut head = [0u8; 8];
    head[..n].copy_from_slice(&buf);
    n >= 4 && is_native_magic(&head)
}

fn is_native_magic(head: &[u8; 8]) -> bool {
    let magic = &head[..4];
    // A Java class shares the fat Mach-O magic; its next word is a class
    // file version (≥ 45), a fat header's is an arch count — file(1) splits at 20.
    let fat_arches = u32::from_be_bytes([head[4], head[5], head[6], head[7]]);
    magic == b"\x7fELF"
        || magic[..2] == *b"MZ"
        || magic == [0xcf, 0xfa, 0xed, 0xfe]
        || (magic == [0xca, 0xfe, 0xba, 0xbe] && (1..20).contains(&fat_arches))
}

/// Refuse `PyInstaller` onefile and `.pyz` zipapps — packaging them as a bare
/// Binary or copying them into the rootfs collides with erebus's own stub.
fn detect_unsupported_bundle(dir: &Path) -> Option<DetectFailure> {
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = path.file_name()?.to_str()?;
        if name.ends_with(".pyz") || looks_like_zipapp(&path) {
            return Some(DetectFailure::UnsupportedBundle {
                kind: "zipapp",
                detail: format!("found '{name}'"),
            });
        }
        if is_native_binary(&path) && contains_marker(&path, b"PyInstaller") {
            return Some(DetectFailure::UnsupportedBundle {
                kind: "PyInstaller onefile",
                detail: format!("'{name}' contains a PyInstaller marker"),
            });
        }
    }
    None
}

fn looks_like_zipapp(path: &Path) -> bool {
    let mut head = [0u8; 4];
    let Ok(n) = std::fs::File::open(path).and_then(|mut f| f.read(&mut head)) else {
        return false;
    };
    n >= 4 && &head == b"PK\x03\x04" && path.extension().and_then(|e| e.to_str()) == Some("pyz")
}

fn contains_marker(path: &Path, marker: &[u8]) -> bool {
    const WINDOW: usize = 256 * 1024;
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    let mut buf = vec![0u8; WINDOW];
    let Ok(n) = file.read(&mut buf) else {
        return false;
    };
    if buf[..n].windows(marker.len()).any(|w| w == marker) {
        return true;
    }
    // PyInstaller appends the archive near EOF — also scan the tail.
    let Ok(meta) = file.metadata() else {
        return false;
    };
    let len = meta.len() as usize;
    if len <= WINDOW {
        return false;
    }
    use std::io::Seek;
    let start = len.saturating_sub(WINDOW) as u64;
    if file.seek(std::io::SeekFrom::Start(start)).is_err() {
        return false;
    }
    let Ok(n) = file.read(&mut buf) else {
        return false;
    };
    buf[..n].windows(marker.len()).any(|w| w == marker)
}

/// Locate `site-packages` under `.venv/` or `venv/` (POSIX or Windows layout).
///
/// The venv directory itself is excluded from the payload walk; builders call
/// this to copy only the install tree into `/app/site-packages`.
pub fn find_venv_site_packages(app_dir: &Path) -> Option<PathBuf> {
    for venv_name in [".venv", "venv"] {
        let venv = app_dir.join(venv_name);
        if !venv.is_dir() {
            continue;
        }
        if let Some(sp) = site_packages_under_venv(&venv) {
            return Some(sp);
        }
    }
    None
}

fn site_packages_under_venv(venv: &Path) -> Option<PathBuf> {
    for lib in ["lib", "lib64"] {
        let lib_dir = venv.join(lib);
        let Ok(entries) = std::fs::read_dir(&lib_dir) else {
            continue;
        };
        let mut py_dirs: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.is_dir()
                    && p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with("python"))
            })
            .collect();
        py_dirs.sort();
        for py in py_dirs {
            let sp = py.join("site-packages");
            if sp.is_dir() {
                return Some(sp);
            }
        }
    }
    let win = venv.join("Lib").join("site-packages");
    win.is_dir().then_some(win)
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
            // 4. Named .py script, then extensionless python shebang script
            let entry = python_entry_name(app_dir)?;
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
    list_native_binaries(dir).into_iter().next()
}

fn list_python_shebang_scripts(dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        // Named *.py entries are handled separately; shebang path is for
        // extensionless (or non-.py) scripts like `#!/usr/bin/env python3`.
        if name.ends_with(".py") || name.starts_with('.') {
            continue;
        }
        if has_python_shebang(&path) {
            names.push(name.to_string());
        }
    }
    names.sort();
    names
}

fn find_python_shebang_entry(dir: &Path) -> Option<String> {
    let scripts = list_python_shebang_scripts(dir);
    if scripts.is_empty() {
        return None;
    }
    for preferred in ["app", "main", "run", "serve", "server"] {
        if scripts.iter().any(|s| s == preferred) {
            return Some((*preferred).to_string());
        }
    }
    if scripts.len() == 1 {
        return Some(scripts[0].clone());
    }
    None
}

fn has_python_shebang(path: &Path) -> bool {
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut buf = [0u8; 256];
    let Ok(n) = file.read(&mut buf) else {
        return false;
    };
    if n < 2 || buf[0] != b'#' || buf[1] != b'!' {
        return false;
    }
    let line_end = buf[..n].iter().position(|&b| b == b'\n').unwrap_or(n);
    let line = String::from_utf8_lossy(&buf[..line_end]);
    let line = line.trim();
    // #!/usr/bin/env python3  |  #!/usr/bin/python  |  #!/usr/bin/python3.12
    let after_bang = line.trim_start_matches("#!").trim();
    let token = after_bang.split_whitespace().next().unwrap_or("");
    if token.ends_with("env") {
        let prog = after_bang.split_whitespace().nth(1).unwrap_or("");
        return prog.starts_with("python");
    }
    Path::new(token)
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.starts_with("python"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn detect_python_app() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("app.py"), "print('hi')").unwrap();
        assert_eq!(detect_runtime(dir.path()), Ok(Runtime::Python));
    }

    #[test]
    fn detect_python_pyproject_only() {
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("pyproject.toml"),
            "[project]\nname = \"myapp\"",
        )
        .unwrap();
        assert_eq!(detect_runtime(dir.path()), Ok(Runtime::Python));
    }

    #[test]
    fn detect_python_setup_py() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("setup.py"), "").unwrap();
        assert_eq!(detect_runtime(dir.path()), Ok(Runtime::Python));
    }

    // A package.json alone is no longer a runtime marker: Node support was
    // removed from the product scope.
    #[test]
    fn package_json_alone_is_not_a_runtime() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("package.json"), "{}").unwrap();
        assert_eq!(detect_runtime(dir.path()), Err(DetectFailure::NoRuntime));
    }

    #[test]
    fn no_runtime_returns_none() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("README.md"), "hi").unwrap();
        assert_eq!(detect_runtime(dir.path()), Err(DetectFailure::NoRuntime));
    }

    #[test]
    fn detect_pe_exe_as_binary() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("app.exe"), b"MZ\x90\x00").unwrap();
        assert_eq!(detect_runtime(dir.path()), Ok(Runtime::Binary));
        assert_eq!(
            resolve_entrypoint(dir.path(), Runtime::Binary),
            Some(vec!["/app/app.exe".into()])
        );
    }

    #[test]
    fn pe_and_elf_is_ambiguous() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("a.exe"), b"MZ\x90\x00").unwrap();
        std::fs::write(dir.path().join("b.elf"), b"\x7fELF").unwrap();
        match detect_runtime(dir.path()) {
            Err(DetectFailure::AmbiguousNative { binaries }) => {
                assert_eq!(binaries, vec!["a.exe".to_string(), "b.elf".to_string()]);
            }
            other => panic!("expected AmbiguousNative, got {other:?}"),
        }
    }

    #[test]
    fn python_elf_combo_prefers_python_entry() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("app.py"), "print('hi')").unwrap();
        std::fs::write(dir.path().join("model-runner"), b"\x7fELF").unwrap();
        assert_eq!(detect_runtime(dir.path()), Ok(Runtime::Python));
        let ep = resolve_entrypoint(dir.path(), Runtime::Python);
        assert_eq!(ep, Some(vec!["python3".into(), "/app/app.py".into()]));
    }

    #[test]
    fn detect_macho_binaries_but_not_java_classes() {
        let thin = TempDir::new().unwrap();
        std::fs::write(
            thin.path().join("agent"),
            b"\xcf\xfa\xed\xfe\x0c\x00\x00\x01",
        )
        .unwrap();
        assert_eq!(detect_runtime(thin.path()), Ok(Runtime::Binary));
        assert_eq!(
            resolve_entrypoint(thin.path(), Runtime::Binary),
            Some(vec!["/app/agent".to_string()])
        );
        let fat = TempDir::new().unwrap();
        std::fs::write(
            fat.path().join("agent"),
            b"\xca\xfe\xba\xbe\x00\x00\x00\x02",
        )
        .unwrap();
        assert_eq!(detect_runtime(fat.path()), Ok(Runtime::Binary));
        let class = TempDir::new().unwrap();
        std::fs::write(
            class.path().join("Main.class"),
            b"\xca\xfe\xba\xbe\x00\x00\x00\x41",
        )
        .unwrap();
        assert_eq!(detect_runtime(class.path()), Err(DetectFailure::NoRuntime));
    }

    #[test]
    fn detect_elf_binary_entrypoint() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("llama-server"), b"\x7fELF").unwrap();
        assert_eq!(detect_runtime(dir.path()), Ok(Runtime::Binary));
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
        assert_eq!(detect_runtime(dir.path()), Ok(Runtime::Python));
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

    #[test]
    fn shebang_script_without_py_is_python() {
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("run"),
            "#!/usr/bin/env python3\nprint('hi')\n",
        )
        .unwrap();
        assert_eq!(detect_runtime(dir.path()), Ok(Runtime::Python));
        assert_eq!(
            resolve_entrypoint(dir.path(), Runtime::Python),
            Some(vec!["python3".into(), "/app/run".into()])
        );
    }

    #[test]
    fn shebang_direct_python_path() {
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("serve"),
            "#!/usr/bin/python3\nprint('ok')\n",
        )
        .unwrap();
        assert_eq!(detect_runtime(dir.path()), Ok(Runtime::Python));
        assert_eq!(
            resolve_entrypoint(dir.path(), Runtime::Python),
            Some(vec!["python3".into(), "/app/serve".into()])
        );
    }

    #[test]
    fn shell_shebang_is_not_python() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("run"), "#!/bin/sh\necho hi\n").unwrap();
        assert_eq!(detect_runtime(dir.path()), Err(DetectFailure::NoRuntime));
    }

    #[test]
    fn pyinstaller_onefile_is_rejected() {
        let dir = TempDir::new().unwrap();
        let mut blob = b"MZ\x90\x00".to_vec();
        blob.extend(std::iter::repeat_n(0u8, 64));
        blob.extend_from_slice(b"PyInstaller");
        std::fs::write(dir.path().join("dist-app"), &blob).unwrap();
        match detect_runtime(dir.path()) {
            Err(DetectFailure::UnsupportedBundle { kind, .. }) => {
                assert!(kind.contains("PyInstaller"));
            }
            other => panic!("expected UnsupportedBundle, got {other:?}"),
        }
    }

    #[test]
    fn pyz_zipapp_is_rejected() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("app.pyz"), b"PK\x03\x04rest").unwrap();
        match detect_runtime(dir.path()) {
            Err(DetectFailure::UnsupportedBundle { kind, .. }) => assert_eq!(kind, "zipapp"),
            other => panic!("expected UnsupportedBundle, got {other:?}"),
        }
    }

    #[test]
    fn find_venv_site_packages_posix_layout() {
        let dir = TempDir::new().unwrap();
        let sp = dir.path().join(".venv/lib/python3.12/site-packages");
        std::fs::create_dir_all(&sp).unwrap();
        std::fs::write(sp.join("bottle.py"), "x").unwrap();
        assert_eq!(find_venv_site_packages(dir.path()), Some(sp));
    }

    #[test]
    fn venv_alone_without_entrypoint_errors_clearly() {
        let dir = TempDir::new().unwrap();
        let sp = dir.path().join("venv/lib/python3.11/site-packages");
        std::fs::create_dir_all(&sp).unwrap();
        std::fs::write(sp.join("x.py"), "").unwrap();
        assert_eq!(
            detect_runtime(dir.path()),
            Err(DetectFailure::VenvWithoutEntrypoint)
        );
    }
}
