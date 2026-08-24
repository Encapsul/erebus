//! Embedded browser chat for `erebus chat --web`.
//!
//! A std-only TCP server: serves the single-file UI on `/` and transparently
//! proxies every other request to the engine port, so any OpenAI-compatible client can
//! point at the same URL the humans use.

use anyhow::Result;
use std::net::TcpListener;
use std::process::Child;

const HTML: &str = include_str!("webchat.html");

/// Serve `listen_port` until interrupted; engine keeps running as a child.
pub fn serve(
    host: &str,
    listen_port: u16,
    engine_port: u16,
    _engine_child: &mut Child,
    model_label: &str,
) -> Result<()> {
    let bind = if host == "0.0.0.0" { "0.0.0.0" } else { host };
    let listener = TcpListener::bind((bind, listen_port))
        .map_err(|e| anyhow::anyhow!("cannot bind {bind}:{listen_port}: {e}"))?;
    eprintln!("[erebus] chat UI ready — Ctrl+C stops everything");
    let upstream = format!("http://127.0.0.1:{engine_port}");
    let label = model_label.to_string();
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let upstream = upstream.clone();
        let label = label.clone();
        std::thread::spawn(move || {
            let Ok((method, path, body)) = super::chat::read_request(&mut stream) else {
                return;
            };
            if (method == "GET" || method == "HEAD") && (path == "/" || path == "/ui") {
                let page = HTML
                    .replace("__MODEL__", &label)
                    .replace("__PORT__", &engine_port.to_string());
                let _ = super::chat::respond(
                    &mut stream,
                    "200 OK",
                    "text/html; charset=utf-8",
                    page.as_bytes(),
                );
                return;
            }
            // Proxy everything else to the engine.
            let client = match reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(600))
                .build()
            {
                Ok(c) => c,
                Err(_) => {
                    let _ = super::chat::respond(
                        &mut stream,
                        "502 Bad Gateway",
                        "application/json",
                        br#"{"error":"proxy build failed"}"#,
                    );
                    return;
                }
            };
            let url = format!("{upstream}{}", sanitize_path(&path));
            let mut req = match method.as_str() {
                "GET" => client.get(&url),
                "POST" => client.post(&url),
                _ => client.request(
                    reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::GET),
                    &url,
                ),
            };
            if !body.is_empty() {
                req = req.header("Content-Type", "application/json").body(body);
            }
            match req.send() {
                Ok(resp) => {
                    let status = format!(
                        "{} {}",
                        resp.status().as_u16(),
                        resp.status().canonical_reason().unwrap_or("")
                    );
                    let ctype = resp
                        .headers()
                        .get("content-type")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("application/json")
                        .to_string();
                    let bytes: Vec<u8> = resp.bytes().map(|b| b.to_vec()).unwrap_or_default();
                    let _ = super::chat::respond(&mut stream, &status, &ctype, &bytes);
                }
                Err(e) => {
                    let msg = format!("{{\"error\":\"upstream unreachable: {e}\"}}");
                    let _ = super::chat::respond(
                        &mut stream,
                        "502 Bad Gateway",
                        "application/json",
                        msg.as_bytes(),
                    );
                }
            }
        });
    }
    Ok(())
}

/// Reject anything that is not a clean absolute path before proxying.
fn sanitize_path(path: &str) -> String {
    if path.starts_with('/') && !path.contains("..") {
        path.to_string()
    } else {
        "/".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::chat::read_request;
    use std::net::TcpStream;

    #[test]
    fn embedded_html_targets_the_proxy_endpoint() {
        assert!(HTML.contains("/v1/chat/completions"));
        assert!(HTML.contains("__MODEL__"));
    }

    #[test]
    fn sanitizer_blocks_traversal_and_keeps_clean_paths() {
        assert_eq!(sanitize_path("/v1/models"), "/v1/models");
        assert_eq!(sanitize_path("/../etc/passwd"), "/");
        assert_eq!(sanitize_path("/v1/../secret"), "/");
    }

    #[test]
    fn request_reader_parses_head_and_body() {
        use std::io::Write;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut c, _) = listener.accept().unwrap();
            c.write_all(b"POST /v1/chat/completions HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}")
                .unwrap();
        });
        let mut s = TcpStream::connect(addr).unwrap();
        let (method, path, body) = read_request(&mut s).unwrap();
        assert_eq!(method, "POST");
        assert_eq!(path, "/v1/chat/completions");
        assert_eq!(body, b"{}");
    }
}
