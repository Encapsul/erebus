//! `erebus chat` — zero-config terminal chat with a bundled model.
//!
//! Launches the bundle's inference engine exactly like `erebus serve`, then
//! opens a ratatui/crossterm TUI over the standard `/v1/chat/completions`
//! contract. `--web` swaps the TUI for an embedded browser page served by a
//! tiny std-only HTTP wrapper that proxies `/v1/*` to the engine.

use anyhow::{bail, Context, Result};
use clap::Args;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::mpsc;

use crate::commands::build::NglPolicy;
use crate::commands::serve;

#[derive(Args)]
pub struct ChatArgs {
    /// Path to the .erebus bundle embedding a GGUF model
    pub file: PathBuf,

    /// Bind address for the engine (and the web wrapper in --web mode)
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,

    /// Engine port; in --web mode the chat page moves here and the engine
    /// takes this value +1
    #[arg(long, default_value_t = 8123)]
    pub port: u16,

    /// Serve the embedded browser chat instead of the terminal TUI
    #[arg(long)]
    pub web: bool,

    /// GPU offload policy: auto | off | <layer count>
    #[arg(long)]
    pub ngl: Option<String>,

    /// Context window (-c)
    #[arg(long, default_value_t = 2048)]
    pub ctx_size: u32,

    /// CPU threads (-t)
    #[arg(long)]
    pub threads: Option<u32>,

    /// Substring filter when several models are embedded
    #[arg(long)]
    pub model: Option<String>,

    /// Force a specific engine binary (llama-server path)
    #[arg(long, env = "ERE_LLAMA_SERVER")]
    pub llama_server: Option<PathBuf>,
}

pub fn run(args: ChatArgs) -> Result<()> {
    let file = args.file.canonicalize().context("failed to open bundle")?;
    let verbose = std::env::var_os("ERE_VERBOSE").is_some();

    let (ui_port, engine_port) = if args.web {
        (args.port, args.port.saturating_add(1))
    } else {
        (args.port, args.port)
    };

    let mut eng = serve::start_engine(
        &file,
        &args.host,
        engine_port,
        args.ngl.as_deref(),
        args.ctx_size,
        args.threads,
        args.model.as_deref(),
        args.llama_server.as_deref(),
        verbose,
    )?;
    serve::wait_healthy_pub(&eng.base_url, &mut eng.child)?;

    let result = if args.web {
        eprintln!(
            "[erebus] chat: open http://{}:{ui_port}  (engine on :{engine_port})",
            args.host
        );
        super::webchat::serve(
            &args.host,
            ui_port,
            engine_port,
            &mut eng.child,
            &eng.model_label,
        )
    } else {
        eprintln!("[erebus] chat: talking to {}", eng.base_url);
        let out = tui_main(&eng.base_url, &eng.model_label);
        // TUI exits intentionally: take the engine down with us.
        let _ = eng.child.kill();
        let _ = eng.child.wait();
        out
    };
    result
}

// ---------------------------------------------------------------------------
// Terminal TUI
// ---------------------------------------------------------------------------

struct Msg {
    role: &'static str,
    text: String,
}

fn tui_main(base_url: &str, model_label: &str) -> Result<()> {
    use std::io::stdout;

    crossterm::terminal::enable_raw_mode()?;
    let mut stdout = stdout();
    crossterm::execute!(
        stdout,
        crossterm::terminal::EnterAlternateScreen,
        crossterm::event::EnableMouseCapture
    )?;
    let backend = ratatui::backend::CrosstermBackend::new(stdout);
    let mut terminal = ratatui::Terminal::new(backend)?;
    terminal.hide_cursor()?;

    let res = tui_loop(&mut terminal, base_url, model_label);

    crossterm::execute!(
        terminal.backend_mut(),
        crossterm::event::DisableMouseCapture,
        crossterm::terminal::LeaveAlternateScreen
    )?;
    crossterm::terminal::disable_raw_mode()?;
    terminal.show_cursor()?;
    res
}

fn tui_loop(
    terminal: &mut ratatui::Terminal<ratatui::backend::CrosstermBackend<std::io::Stdout>>,
    base_url: &str,
    model_label: &str,
) -> Result<()> {
    let mut history: Vec<Msg> = vec![Msg {
        role: "system",
        text: format!("Model: {model_label} — Enter to send, Ctrl+C to quit"),
    }];
    let mut input = String::new();
    let (tx, rx) = mpsc::channel::<String>();
    let mut busy = false;

    loop {
        // Drain finished completions.
        while let Ok(reply) = rx.try_recv() {
            history.push(Msg {
                role: "assistant",
                text: reply,
            });
            busy = false;
        }

        terminal.draw(|f| {
            let chunks = ratatui::layout::Layout::default()
                .direction(ratatui::layout::Direction::Vertical)
                .constraints([
                    ratatui::layout::Constraint::Min(3),
                    ratatui::layout::Constraint::Length(3),
                ])
                .split(f.area());
            let lines: Vec<ratatui::text::Line<'_>> = history
                .iter()
                .map(|m| {
                    use ratatui::style::{Modifier, Style};
                    let (arrow, style) = match m.role {
                        "you" => ("▸", Style::new().add_modifier(Modifier::BOLD)),
                        "assistant" => ("◂", Style::new().cyan()),
                        _ => ("·", Style::new().dim()),
                    };
                    ratatui::text::Line::styled(format!("{arrow} {}", m.text), style)
                })
                .collect();
            let msgs = ratatui::widgets::Paragraph::new(lines)
                .wrap(ratatui::widgets::Wrap { trim: false })
                .block(
                    ratatui::widgets::Block::bordered()
                        .title(" erebus chat ")
                        .title_bottom(ratatui::text::Line::from("↑↓ scroll · Ctrl+C quit"))
                        .title_alignment(ratatui::layout::Alignment::Right),
                );
            f.render_widget(msgs, chunks[0]);
            let style = if busy {
                ratatui::style::Style::new().yellow()
            } else {
                ratatui::style::Style::new()
            };
            let placeholder = if busy { " …thinking" } else { "" };
            let input_w = ratatui::widgets::Paragraph::new(format!("you ▸ {input}{placeholder}"))
                .style(style)
                .block(ratatui::widgets::Block::bordered());
            f.render_widget(input_w, chunks[1]);
        })?;

        if crossterm::event::poll(std::time::Duration::from_millis(120))? {
            if let crossterm::event::Event::Key(key) = crossterm::event::read()? {
                if key.kind == crossterm::event::KeyEventKind::Press {
                    match key.code {
                        crossterm::event::KeyCode::Char('c')
                            if key
                                .modifiers
                                .contains(crossterm::event::KeyModifiers::CONTROL) =>
                        {
                            return Ok(());
                        }
                        crossterm::event::KeyCode::Esc => return Ok(()),
                        crossterm::event::KeyCode::Enter if !busy && !input.trim().is_empty() => {
                            let prompt = input.trim().to_string();
                            input.clear();
                            history.push(Msg {
                                role: "you",
                                text: prompt.clone(),
                            });
                            busy = true;
                            spawn_completion(tx.clone(), base_url.to_string(), prompt);
                        }
                        crossterm::event::KeyCode::Backspace => {
                            input.pop();
                        }
                        crossterm::event::KeyCode::Char(c) => input.push(c),
                        _ => {}
                    }
                }
            }
        }
    }
}

/// Blocking completion call on a worker thread; the reply lands on `tx`.
fn spawn_completion(tx: mpsc::Sender<String>, base_url: String, prompt: String) {
    std::thread::spawn(move || {
        let payload = serde_json::json!({
            "model": "local",
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 512,
        });
        let reply = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(300))
            .build()
            .and_then(|c| {
                c.post(format!("{base_url}/v1/chat/completions"))
                    .json(&payload)
                    .send()
            })
            .and_then(|r| r.error_for_status())
            .and_then(|r| r.json::<serde_json::Value>())
            .ok()
            .and_then(|v| {
                v["choices"][0]["message"]["content"]
                    .as_str()
                    .map(str::to_string)
            })
            .unwrap_or_else(|| "⚠ engine error (see its output)".into());
        let _ = tx.send(reply);
    });
}

// ---------------------------------------------------------------------------
// Web wrapper (shared helpers used by webchat.rs)
// ---------------------------------------------------------------------------

/// Read one HTTP request head + body from `stream` (Content-Length bodies,
/// capped). Returns (method, path, body).
pub(crate) fn read_request(stream: &mut TcpStream) -> std::io::Result<(String, String, Vec<u8>)> {
    let mut buf = [0u8; 8192];
    let mut data = Vec::new();
    let head_end;
    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "client closed",
            ));
        }
        data.extend_from_slice(&buf[..n]);
        if let Some(pos) = find_subslice(&data, b"\r\n\r\n") {
            head_end = pos;
            break;
        }
        if data.len() > 64 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "headers too large",
            ));
        }
    }
    let head = String::from_utf8_lossy(&data[..head_end]).into_owned();
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    let path = parts.next().unwrap_or("/").to_string();
    let content_length = head
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case("content-length")
                .then(|| v.trim().parse::<usize>().ok())?
        })
        .unwrap_or(0);
    let mut body = data[head_end + 4..].to_vec();
    let cap = 16 * 1024 * 1024;
    if content_length > cap {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "body too large",
        ));
    }
    while body.len() < content_length {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&buf[..n]);
    }
    body.truncate(content_length);
    Ok((method, path, body))
}

pub(crate) fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Minimal response writer shared by the webchat wrapper.
pub(crate) fn respond(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

/// Validate that a port pair makes sense before launching engines.
pub(crate) fn validate_ports(port: u16, web: bool) -> Result<()> {
    if web && port == u16::MAX {
        bail!("--port too high for --web mode (engine needs port+1)");
    }
    let _ = NglPolicy::parse("auto"); // touch import parity with serve
    Ok(())
}
