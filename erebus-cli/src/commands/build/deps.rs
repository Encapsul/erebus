use std::process::Command;

/// Check if a command is available on PATH.
pub(crate) fn is_command_available(name: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {name}")])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sh_is_available() {
        assert!(is_command_available("sh"));
    }

    #[test]
    fn nonexistent_command_is_not_available() {
        assert!(!is_command_available("definitely-not-a-real-command-xyz"));
    }
}
