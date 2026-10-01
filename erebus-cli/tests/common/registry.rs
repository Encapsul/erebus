//! Start the real Python registry for an e2e test, race-free.
//!
//! The registry binds `--port 0` and announces the port it got on stdout,
//! so no other process can grab a pre-picked free port in between. Its
//! stderr is drained in the background (a full pipe would block its access
//! log) and shown when the registry dies or never announces itself.

use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

pub struct RegistryProcess {
    pub child: Child,
    pub base: String,
}

impl Drop for RegistryProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// `None` when `python3` cannot be spawned; panics with the registry's
/// stderr when it exits or stays silent for 60 s.
pub fn spawn_registry(root: &Path, origin: &str) -> Option<RegistryProcess> {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../scripts/registry_server.py");
    let mut child = Command::new("python3")
        .arg(script)
        .args(["--dir", root.to_str().unwrap(), "--port", "0"])
        .args(["--log-origin", origin, "--anchor-every", "0"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let stderr = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&stderr);
    let mut err = child.stderr.take().unwrap();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n @ 1..) = err.read(&mut buf) {
            sink.lock().unwrap().extend_from_slice(&buf[..n]);
        }
    });
    let (tx, rx) = mpsc::channel();
    let out = child.stdout.take().unwrap();
    std::thread::spawn(move || {
        for line in BufReader::new(out).lines().map_while(Result::ok) {
            if let Some(base) = announced_base(&line) {
                let _ = tx.send(base);
            }
        }
    });
    match rx.recv_timeout(Duration::from_secs(60)) {
        Ok(base) => Some(RegistryProcess { child, base }),
        Err(_) => {
            let status = child.try_wait().ok().flatten();
            let _ = child.kill();
            let log = String::from_utf8_lossy(&stderr.lock().unwrap()).into_owned();
            panic!("registry never announced its port (exit: {status:?}); stderr:\n{log}");
        }
    }
}

/// `http://127.0.0.1:PORT` from `erebus registry v2 on http://127.0.0.1:PORT dir=…`.
fn announced_base(line: &str) -> Option<String> {
    let rest = line.strip_prefix("erebus registry v2 on ")?;
    let base = rest.split_whitespace().next()?;
    base.rsplit(':')
        .next()
        .is_some_and(|p| p.parse::<u16>().is_ok_and(|p| p != 0))
        .then(|| base.to_string())
}
