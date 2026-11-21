//! Update URL resolution for the erebus launcher stub.
//!
//! Provides `resolve_update_url` (precedence: `--erebus-update=<URL>` CLI arg >
//! env > embedded meta) and `normalize_base_url` (strip trailing slashes,
//! reject non-http(s)). Plain HTTP is loopback-only unless
//! `ERE_ALLOW_PLAIN_HTTP_UPDATES=1` is set explicitly.

use std::ffi::OsString;
use std::io;

use crate::Metadata;

/// Resolves the update channel base URL:
/// `--erebus-update=<URL>` argument > `$ERE_UPDATE_URL` > embedded `meta.update_url`.
///
/// Only the `=` form is accepted as a CLI override — the next positional argv
/// is never guessed as the URL, so the app's first argument can't be swallowed.
pub fn resolve_update_url(args: &[OsString], idx: usize, meta: &Metadata) -> io::Result<String> {
    if let Some(arg) = args.get(idx) {
        if let Some(url) = arg.to_string_lossy().strip_prefix("--erebus-update=") {
            if !url.is_empty() {
                return normalize_base_url(url);
            }
        }
    }
    if let Some(url) = std::env::var_os("ERE_UPDATE_URL") {
        return normalize_base_url(&url.to_string_lossy());
    }
    if let Some(ref url) = meta.update_url {
        return normalize_base_url(url);
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "no update URL — pass --erebus-update=<URL>, set $ERE_UPDATE_URL, \
         or rebuild with erebus build --update-url",
    ))
}

/// Strips trailing slashes and rejects non-http(s) schemes. Plain HTTP is
/// limited to loopback: an on-path attacker could otherwise swap the update
/// manifest in flight. HTTPS has transport authentication and stays allowed.
///
/// Controlled deployments with their own transport protection can opt out of
/// the loopback restriction with `ERE_ALLOW_PLAIN_HTTP_UPDATES=1`. The update
/// manifest still requires a trusted Ed25519 signature and a v2 identity
/// match, so this only relaxes transport authentication, not publisher trust.
pub fn normalize_base_url(url: &str) -> io::Result<String> {
    let allow_plain_http = plain_http_opted_in(std::env::var_os("ERE_ALLOW_PLAIN_HTTP_UPDATES"));
    normalize_base_url_with_policy(url, allow_plain_http)
}

fn plain_http_opted_in(value: Option<std::ffi::OsString>) -> bool {
    matches!(value, Some(v) if v == "1")
}

fn normalize_base_url_with_policy(url: &str, allow_plain_http: bool) -> io::Result<String> {
    let base = url.trim().trim_end_matches('/').to_string();
    if base.is_empty() || !(base.starts_with("http://") || base.starts_with("https://")) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "update URL must be http(s)://<host>/<path>",
        ));
    }
    if base.starts_with("http://") && !allow_plain_http && !is_loopback_authority(&base[7..]) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "plain HTTP update URLs are allowed only for loopback; use HTTPS or set \
             ERE_ALLOW_PLAIN_HTTP_UPDATES=1",
        ));
    }
    Ok(base)
}

fn is_loopback_authority(rest: &str) -> bool {
    let authority = rest.split('/').next().unwrap_or("");
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    let host = if let Some(end) = host_port.find(']') {
        &host_port[..=end]
    } else {
        host_port.split(':').next().unwrap_or("")
    };
    matches!(host, "localhost" | "127.0.0.1" | "[::1]")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_base_url_accepts_http_and_https() {
        assert_eq!(
            normalize_base_url("https://updates.example.com/app").unwrap(),
            "https://updates.example.com/app"
        );
        assert_eq!(
            normalize_base_url("http://localhost:8080/updates/").unwrap(),
            "http://localhost:8080/updates"
        );
        assert_eq!(
            normalize_base_url("  https://x.example  ").unwrap(),
            "https://x.example"
        );
    }

    #[test]
    fn normalize_base_url_rejects_plain_http_off_loopback() {
        assert!(normalize_base_url("http://updates.example.com/app").is_err());
        assert!(normalize_base_url("http://192.168.1.10:8080/app").is_err());
        assert!(normalize_base_url("http://localhost.evil/app").is_err());
        assert_eq!(
            normalize_base_url("http://127.0.0.1:8080/app").unwrap(),
            "http://127.0.0.1:8080/app"
        );
        assert_eq!(
            normalize_base_url("http://[::1]:8080/app").unwrap(),
            "http://[::1]:8080/app"
        );
    }

    #[test]
    fn plain_http_opt_in_allows_non_loopback_only_when_exactly_one() {
        let url = "http://updates.example.com/app";
        assert!(normalize_base_url_with_policy(url, false).is_err());
        assert_eq!(normalize_base_url_with_policy(url, true).unwrap(), url);
        // A value other than "1" must not silently relax the restriction.
        let one = Some(std::ffi::OsString::from("1"));
        let zero = Some(std::ffi::OsString::from("0"));
        assert!(plain_http_opted_in(one));
        assert!(!plain_http_opted_in(zero));
        assert!(!plain_http_opted_in(None));
    }

    #[test]
    fn normalize_base_url_rejects_unsupported_schemes() {
        assert!(normalize_base_url("ftp://updates.example.com").is_err());
        assert!(normalize_base_url("file:///tmp/updates").is_err());
        assert!(normalize_base_url("").is_err());
        assert!(normalize_base_url("updates.example.com/app").is_err());
    }

    #[test]
    fn resolve_update_url_prefers_the_equals_argument() {
        let args = vec![
            OsString::from("--erebus-update=https://arg.example/app"),
            OsString::from("--flag-for-app"),
        ];
        let meta = Metadata {
            update_url: Some("https://embedded.example".into()),
            ..Metadata {
                name: "test".into(),
                version: None,
                runtime: String::new(),
                entrypoint: Vec::new(),
                env: std::collections::BTreeMap::new(),
                cwd: None,
                isolation: 0,
                seccomp: false,
                gui: false,
                landlock: false,
                services: Vec::new(),
                crypto: None,
                payload_format: String::new(),
                health_check: None,
                update_url: None,
                layers: Vec::new(),
                entrypoint_layer: None,
                artifact_state: None,
                artifact_policy: None,
            }
        };
        let base = resolve_update_url(&args, 0, &meta).unwrap();
        assert_eq!(base, "https://arg.example/app");
    }

    #[test]
    fn resolve_update_url_does_not_swallow_app_positional_arg() {
        // `--erebus-update serve` must NOT treat `serve` as the URL — the next
        // positional argv belongs to the app and is never consumed.
        let args = vec![OsString::from("--erebus-update"), OsString::from("serve")];
        let meta = Metadata {
            update_url: Some("https://meta.example/app/".into()),
            ..Metadata {
                name: "test".into(),
                version: None,
                runtime: String::new(),
                entrypoint: Vec::new(),
                env: std::collections::BTreeMap::new(),
                cwd: None,
                isolation: 0,
                seccomp: false,
                gui: false,
                landlock: false,
                services: Vec::new(),
                crypto: None,
                payload_format: String::new(),
                health_check: None,
                update_url: None,
                layers: Vec::new(),
                entrypoint_layer: None,
                artifact_state: None,
                artifact_policy: None,
            }
        };
        let base = resolve_update_url(&args, 0, &meta).unwrap();
        assert_eq!(base, "https://meta.example/app");
    }

    #[test]
    fn resolve_update_url_falls_back_to_embedded_metadata() {
        let args = vec![OsString::from("--erebus-update")];
        let meta = Metadata {
            update_url: Some("https://meta.example/app/".into()),
            ..Metadata {
                name: "test".into(),
                version: None,
                runtime: String::new(),
                entrypoint: Vec::new(),
                env: std::collections::BTreeMap::new(),
                cwd: None,
                isolation: 0,
                seccomp: false,
                gui: false,
                landlock: false,
                services: Vec::new(),
                crypto: None,
                payload_format: String::new(),
                health_check: None,
                update_url: None,
                layers: Vec::new(),
                entrypoint_layer: None,
                artifact_state: None,
                artifact_policy: None,
            }
        };
        let base = resolve_update_url(&args, 0, &meta).unwrap();
        assert_eq!(base, "https://meta.example/app");
    }

    #[test]
    fn resolve_update_url_errors_without_any_source() {
        let args = vec![OsString::from("--erebus-update")];
        let meta = Metadata {
            update_url: None,
            ..Metadata {
                name: "test".into(),
                version: None,
                runtime: String::new(),
                entrypoint: Vec::new(),
                env: std::collections::BTreeMap::new(),
                cwd: None,
                isolation: 0,
                seccomp: false,
                gui: false,
                landlock: false,
                services: Vec::new(),
                crypto: None,
                payload_format: String::new(),
                health_check: None,
                update_url: None,
                layers: Vec::new(),
                entrypoint_layer: None,
                artifact_state: None,
                artifact_policy: None,
            }
        };
        let err = resolve_update_url(&args, 0, &meta).unwrap_err();
        assert!(err.to_string().contains("no update URL"));
    }

    #[test]
    fn resolve_update_url_handles_equals_syntax() {
        let args = vec![OsString::from("--erebus-update=https://arg.example/app")];
        let meta = Metadata {
            update_url: None,
            ..Metadata {
                name: "test".into(),
                version: None,
                runtime: String::new(),
                entrypoint: Vec::new(),
                env: std::collections::BTreeMap::new(),
                cwd: None,
                isolation: 0,
                seccomp: false,
                gui: false,
                landlock: false,
                services: Vec::new(),
                crypto: None,
                payload_format: String::new(),
                health_check: None,
                update_url: Some("https://meta.example/app".into()),
                entrypoint_layer: None,
                artifact_state: None,
                artifact_policy: None,
                layers: Vec::new(),
            }
        };
        let base = resolve_update_url(&args, 0, &meta).unwrap();
        assert_eq!(base, "https://arg.example/app");
    }
}
