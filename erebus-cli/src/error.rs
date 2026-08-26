use std::process::ExitCode;

/// Exit codes per clig.dev conventions.
///
/// - `0`: Success
/// - `1`: General error
/// - `2`: Usage / lint / verification error
/// - `3`: Data error (parse failure, invalid format)
/// - `4`: Permission error
/// - `5`: Not found
pub fn exit_code_for_error(err: &anyhow::Error) -> ExitCode {
    // First: check the structured error chain (most reliable)
    for cause in err.chain() {
        if let Some(io_err) = cause.downcast_ref::<std::io::Error>() {
            return match io_err.kind() {
                std::io::ErrorKind::NotFound => ExitCode::from(5),
                std::io::ErrorKind::PermissionDenied => ExitCode::from(4),
                std::io::ErrorKind::InvalidData
                | std::io::ErrorKind::InvalidInput
                | std::io::ErrorKind::UnexpectedEof => ExitCode::from(3),
                _ => ExitCode::from(1),
            };
        }
        if cause.downcast_ref::<serde_json::Error>().is_some() {
            return ExitCode::from(3);
        }
        if cause
            .downcast_ref::<ed25519_dalek::SignatureError>()
            .is_some()
        {
            return ExitCode::from(2);
        }
    }

    // Second: pattern-match the top-level message for known categories.
    // This catches anyhow::bail!("signature does not match...") etc.
    let msg = format!("{err}");
    let lower = msg.to_lowercase();

    if lower.contains("not found")
        || lower.contains("no such file")
        || lower.contains("not a file")
        || lower.contains("not a directory")
    {
        return ExitCode::from(5);
    }
    if lower.contains("permission denied")
        || lower.contains("not writable")
        || lower.contains("read-only")
    {
        return ExitCode::from(4);
    }
    if lower.contains("signature")
        || lower.contains("lint")
        || lower.contains("already signed")
        || lower.contains("verification")
        || lower.contains("mismatch")
    {
        return ExitCode::from(2);
    }
    if lower.contains("parse")
        || lower.contains("invalid")
        || lower.contains("corrupt")
        || lower.contains("truncated")
    {
        return ExitCode::from(3);
    }

    ExitCode::from(1)
}
