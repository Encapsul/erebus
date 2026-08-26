//! Pager support for long output (clig.dev: "Use a pager if outputting a lot of text").
//!
//! Checks `PAGER` / `LESS` env vars, falls back to `less -R`, and only pages
//! when stdout is a TTY. Returns a handle that pages on drop.

use std::io::{self, Write};
use std::process::{Child, Command, Stdio};

pub struct Pager {
    child: Option<Child>,
}

impl Pager {
    /// Start a pager if stdout is a terminal and the content is long enough.
    pub fn start(min_lines: usize, line_hint: usize) -> Self {
        if !is_terminal() || line_hint < min_lines {
            return Pager { child: None };
        }
        let pager_cmd = std::env::var("PAGER")
            .or_else(|_| std::env::var("LESS"))
            .unwrap_or_else(|_| "less -R".to_string());
        let mut parts = pager_cmd.split_whitespace();
        let bin = parts.next().unwrap_or("less");
        let args: Vec<&str> = parts.collect();
        match Command::new(bin).args(&args).stdin(Stdio::piped()).spawn() {
            Ok(child) => Pager { child: Some(child) },
            Err(_) => Pager { child: None },
        }
    }

    pub fn is_active(&self) -> bool {
        self.child.is_some()
    }

    pub fn writer(&mut self) -> Box<dyn Write> {
        if let Some(ref mut child) = self.child {
            if child.stdin.is_some() {
                // Can't get a owned ref, so we return a pipe writer
                // that writes to the child's stdin.
                Box::new(PagerWriter {
                    stdin: child.stdin.take().unwrap(),
                })
            } else {
                Box::new(io::stdout())
            }
        } else {
            Box::new(io::stdout())
        }
    }
}

struct PagerWriter {
    stdin: std::process::ChildStdin,
}

impl Write for PagerWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stdin.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.stdin.flush()
    }
}

impl Drop for Pager {
    fn drop(&mut self) {
        if let Some(ref mut child) = self.child {
            let _ = child.stdin.take();
            let _ = child.wait();
        }
    }
}

fn is_terminal() -> bool {
    use std::io::IsTerminal;
    io::stdout().is_terminal()
}
