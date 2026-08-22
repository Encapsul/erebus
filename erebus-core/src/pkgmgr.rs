//! Package manager detection — identifies which package manager a Python app uses.
//!
//! Priority is speed-based: uv > poetry > pipenv > pip.

use std::path::Path;

/// Detected package manager type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkgMgr {
    Uv,
    Poetry,
    Pipenv,
    Pip,
}

impl PkgMgr {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Uv => "uv",
            Self::Poetry => "poetry",
            Self::Pipenv => "pipenv",
            Self::Pip => "pip",
        }
    }

    pub fn install_cmd(&self) -> Vec<&'static str> {
        match self {
            Self::Uv => vec!["uv", "sync"],
            Self::Poetry => vec!["poetry", "install", "--no-interaction"],
            Self::Pipenv => vec!["pipenv", "install", "--deploy"],
            Self::Pip => vec![
                "pip",
                "install",
                "--default-timeout",
                "120",
                "--retries",
                "5",
                "-r",
                "requirements.txt",
            ],
        }
    }
}

/// Detect the Python package manager by checking lock files.
pub fn detect_python_pkgmgr(dir: &Path) -> Option<PkgMgr> {
    if dir.join("uv.lock").is_file() {
        return Some(PkgMgr::Uv);
    }
    if dir.join("poetry.lock").is_file() {
        return Some(PkgMgr::Poetry);
    }
    if dir.join("Pipfile.lock").is_file() {
        return Some(PkgMgr::Pipenv);
    }
    let req = dir.join("requirements.txt");
    if req.is_file() && std::fs::metadata(&req).is_ok_and(|m| m.len() > 0) {
        return Some(PkgMgr::Pip);
    }
    None
}

/// Detect the package manager for a given runtime.
pub fn detect_pkgmgr(dir: &Path, runtime: &str) -> Option<PkgMgr> {
    if runtime == "python" {
        detect_python_pkgmgr(dir)
    } else {
        None
    }
}

/// Detect all package managers relevant to the runtime.
/// Kept as a list so callers can iterate uniformly; Python apps have at most one.
pub fn detect_all_pkgmgrs(dir: &Path, runtime: &str) -> Vec<PkgMgr> {
    detect_pkgmgr(dir, runtime).into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn uv_lock() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("uv.lock"), "# uv").unwrap();
        assert_eq!(detect_python_pkgmgr(dir.path()), Some(PkgMgr::Uv));
    }

    #[test]
    fn uv_beats_poetry() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("uv.lock"), "# uv").unwrap();
        std::fs::write(dir.path().join("poetry.lock"), "# poetry").unwrap();
        assert_eq!(detect_python_pkgmgr(dir.path()), Some(PkgMgr::Uv));
    }

    #[test]
    fn poetry_beats_pipenv() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("poetry.lock"), "# poetry").unwrap();
        std::fs::write(dir.path().join("Pipfile.lock"), "{}").unwrap();
        assert_eq!(detect_python_pkgmgr(dir.path()), Some(PkgMgr::Poetry));
    }

    #[test]
    fn pipenv_lock() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("Pipfile.lock"), "{}").unwrap();
        assert_eq!(detect_python_pkgmgr(dir.path()), Some(PkgMgr::Pipenv));
    }

    #[test]
    fn requirements_txt_is_pip() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("requirements.txt"), "flask\n").unwrap();
        assert_eq!(detect_python_pkgmgr(dir.path()), Some(PkgMgr::Pip));
    }

    #[test]
    fn empty_requirements_is_not_pip() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("requirements.txt"), "").unwrap();
        assert_eq!(detect_python_pkgmgr(dir.path()), None);
    }

    #[test]
    fn no_manifest_no_mgr() {
        let dir = TempDir::new().unwrap();
        assert_eq!(detect_python_pkgmgr(dir.path()), None);
    }

    #[test]
    fn detect_for_runtime() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("uv.lock"), "# uv").unwrap();
        assert_eq!(detect_pkgmgr(dir.path(), "python"), Some(PkgMgr::Uv));
        assert_eq!(detect_pkgmgr(dir.path(), "binary"), None);
        assert_eq!(detect_pkgmgr(dir.path(), "cobol"), None);
    }

    #[test]
    fn detect_all_returns_single_entry() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("requirements.txt"), "flask\n").unwrap();
        let mgrs = detect_all_pkgmgrs(dir.path(), "python");
        assert_eq!(mgrs.len(), 1);
        assert_eq!(mgrs[0], PkgMgr::Pip);
    }

    #[test]
    fn binary_runtime_has_no_managers() {
        let dir = TempDir::new().unwrap();
        assert!(detect_all_pkgmgrs(dir.path(), "binary").is_empty());
    }
}
