#!/usr/bin/env python3
"""erebus registry v2 — accounts, quotas, SISR stats, landing page. stdlib only.

Routes (backward compatible with erebus CLI publish/pull):
    GET  /health              -> {"status":"ok"}
    GET  /                    -> landing page (live SISR savings counter)
    GET  /stats               -> JSON counters
    GET  /index.json          -> {"packages":[{name,file,sha256,size,private}]}
    GET  /packages/<file>     -> blob (private ones require Bearer token + quota)
    POST /packages/<name>     -> multipart upload (auth once bootstrap user exists)
    POST /auth/register       -> {"username","password"} -> {"token"}
    POST /auth/login          -> same shape, rotates nothing (token is stable)
    POST /waitlist            -> {"email"} throttled per IP

Storage layout under --dir:
    packages/<file>           blobs
    meta/<file>.json          {"owner":..., "private":bool}
    users.json                hashed credentials (scrypt) + tier
    usage/<user>.json         {"month","bytes_served"}
    stats.json                weekly served / full-equivalent / saved / pulls
    waitlist.txt              one email per line
"""
import argparse
import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SAFE_FILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*\.erebus$")
SAFE_USER = re.compile(r"^[a-z0-9_-]{1,32}$")
SAFE_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,16}$")
CHUNK = 64 * 1024
MONTH_FMT = "%Y-%m"
WEEK_FMT = "%G-W%V"


def month_now():
    return datetime.now(timezone.utc).strftime(MONTH_FMT)


def week_now():
    return datetime.now(timezone.utc).strftime(WEEK_FMT)


def atomic_write(path: str, data: bytes):
    tmp = f"{path}.{uuid.uuid4().hex}.tmp"
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


class Store:
    """All mutable state, guarded by an in-process RLock + per-file flock."""

    def __init__(self, root: str, quota_bytes: int, upload_cap: int):
        self.root = root
        self.pkg_dir = os.path.join(root, "packages")
        self.meta_dir = os.path.join(root, "meta")
        self.usage_dir = os.path.join(root, "usage")
        for d in (self.pkg_dir, self.meta_dir, self.usage_dir):
            os.makedirs(d, exist_ok=True)
        self.users_path = os.path.join(root, "users.json")
        self.stats_path = os.path.join(root, "stats.json")
        self.waitlist_path = os.path.join(root, "waitlist.txt")
        self.quota_bytes = quota_bytes
        self.upload_cap = upload_cap
        self.lock = threading.RLock()
        self._hash_cache: dict[str, tuple[float, str]] = {}
        # Bootstrap rule: until the first account exists, uploads stay open so
        # existing workflows (and the original chaos battery) keep working.
        self.users = self._load(self.users_path, {})

    # ---- json helpers -----------------------------------------------------
    @staticmethod
    def _load(path: str, default):
        try:
            with open(path, "rb") as f:
                return json.loads(f.read())
        except (OSError, ValueError):
            return default

    def _save_locked(self, path: str, obj):
        atomic_write(path, json.dumps(obj).encode())

    # ---- users ------------------------------------------------------------
    def bootstrap_open_uploads(self) -> bool:
        with self.lock:
            return len(self.users) == 0

    @staticmethod
    def _hash_password(password: str, salt: bytes) -> str:
        return hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1).hex()

    def register(self, username: str, password: str) -> tuple[bool, str]:
        if not SAFE_USER.match(username or ""):
            return False, "invalid username ([a-z0-9_-], max 32)"
        if len(password or "") < 10:
            return False, "password must be >= 10 chars"
        salt = secrets.token_bytes(16)
        token = secrets.token_hex(32)
        rec = {
            "salt": salt.hex(),
            "pwhash": self._hash_password(password, salt),
            "token_hash": hashlib.sha256(token.encode()).hexdigest(),
            "tier": "free",
            "created": time.time(),
        }
        with self.lock:
            # Same shape as login(): credentials live under the "users" key.
            users = self._load(self.users_path, {}).get("users", {})
            if username in users:
                return False, "username taken"
            users[username] = rec
            self._save_locked(self.users_path, {"users": users})
            self.users = users
        return True, token

    def login(self, username: str, password: str, provided_token: str | None) -> str | None:
        """Return username iff credentials match. Password OR bearer token."""
        with self.lock:
            users = self._load(self.users_path, {}).get("users", {})
            rec = users.get(username or "")
        if not rec:
            # burn comparable time so user enumeration via timing is harder
            self._hash_password(password or "", b"x" * 16)
            return None
        if provided_token is not None:
            good = hmac.compare_digest(
                rec["token_hash"], hashlib.sha256(provided_token.encode()).hexdigest()
            )
            return username if good else None
        calc = self._hash_password(password or "", bytes.fromhex(rec["salt"]))
        if hmac.compare_digest(calc, rec["pwhash"]):
            return username
        return None

    def authenticate(self, authorization: str) -> str | None:
        """Bearer <username>:<token> or legacy bare token matched globally."""
        if not authorization.startswith("Bearer "):
            return None
        raw = authorization[len("Bearer "):].strip()
        if ":" in raw:
            username, _, token = raw.partition(":")
        else:
            username, token = "", raw
        with self.lock:
            users = self._load(self.users_path, {}).get("users", {})
        if username:
            rec = users.get(username)
            if rec and hmac.compare_digest(
                rec["token_hash"], hashlib.sha256(token.encode()).hexdigest()
            ):
                return username
            return None
        # bare-token mode (legacy): scan — O(n), fine for small registries
        for name, rec in users.items():
            if hmac.compare_digest(
                rec["token_hash"], hashlib.sha256(token.encode()).hexdigest()
            ):
                return name
        return None

    # ---- packages ---------------------------------------------------------
    def set_meta(self, fname: str, owner: str | None, private: bool):
        with self.lock:
            atomic_write(
                os.path.join(self.meta_dir, fname + ".json"),
                json.dumps({"owner": owner, "private": private}).encode(),
            )

    def get_meta(self, fname: str) -> dict:
        return self._load(os.path.join(self.meta_dir, fname + ".json"), {})

    def sha256_cached(self, path: str) -> str:
        mtime = os.path.getmtime(path)
        cached = self._hash_cache.get(path)
        if cached and cached[0] == mtime:
            return cached[1]
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(CHUNK):
                h.update(chunk)
        digest = h.hexdigest()
        with self.lock:
            self._hash_cache[path] = (mtime, digest)
        return digest

    def index(self) -> bytes:
        packages = []
        for name in sorted(os.listdir(self.pkg_dir)):
            path = os.path.join(self.pkg_dir, name)
            if not os.path.isfile(path) or not name.endswith(".erebus"):
                continue
            entry = {
                "name": name[: -len(".erebus")],
                "file": name,
                "sha256": self.sha256_cached(path),
                "size": os.path.getsize(path),
            }
            meta = self.get_meta(name)
            entry["private"] = bool(meta.get("private"))
            packages.append(entry)
        return json.dumps({"packages": packages}).encode()

    # ---- quotas & stats ---------------------------------------------------
    def _usage_path(self, user: str) -> str:
        return os.path.join(self.usage_dir, f"{user}.json")

    def month_served(self, user: str) -> int:
        u = self._load(self._usage_path(user), {})
        return u["bytes"] if u.get("month") == month_now() else 0

    def charge_bytes(self, user: str, nbytes: int, full_equiv: int = 0):
        """Metered transfer accounting, crash-consistent under flock."""
        with self.lock:
            path = self._usage_path(user)
            fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                rec = self._load(path, {})
                if rec.get("month") != month_now():
                    rec = {"month": month_now(), "bytes": 0}
                rec["bytes"] = rec.get("bytes", 0) + nbytes
                atomic_write(path, json.dumps(rec).encode())
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)
        self.bump_stats(nbytes, full_equiv)

    def bump_stats(self, served: int, full_equiv: int):
        with self.lock:
            st = self._load(self.stats_path, {})
            wk = week_now()
            if st.get("week") != wk:
                st = {"week": wk, "served": 0, "full_equiv": 0, "pulls": 0}
            st["served"] += served
            st["full_equiv"] += full_equiv
            st["saved"] = max(0, st["full_equiv"] - st["served"])
            st["pulls"] = st.get("pulls", 0) + 1
            self._save_locked(self.stats_path, st)

    def stats(self) -> dict:
        with self.lock:
            st = self._load(self.stats_path, {})
        npkg = sum(
            1 for n in os.listdir(self.pkg_dir) if n.endswith(".erebus")
        ) if os.path.isdir(self.pkg_dir) else 0
        return {
            "week": st.get("week", week_now()),
            "bytes_served": st.get("served", 0),
            "full_equivalent": st.get("full_equiv", 0),
            "bytes_saved": max(0, st.get("full_equiv", 0) - st.get("served", 0)),
            "pulls": st.get("pulls", 0),
            "packages": npkg,
        }

    # ---- waitlist ---------------------------------------------------------
    def waitlist_add(self, email: str, ip: str) -> tuple[bool, str]:
        if not SAFE_EMAIL.match(email or "") or len(email) > 254:
            return False, "invalid email"
        with self.lock:
            recent = [
                e for e in self._load(self.waitlist_path + ".rl", {}) if True
            ]
            stamps: dict[str, float] = self._load(self.waitlist_path + ".rl", {})
            now = time.time()
            stamps = {k: v for k, v in stamps.items() if now - v < 3600}
            if sum(1 for t in stamps.values() if now - t < 60) >= 3:
                return False, "rate limited"
            # Key each ATTEMPT uniquely: keying by IP alone would let one
            # client overwrite its own stamp and never reach the threshold.
            stamps[f"{ip}:{uuid.uuid4().hex[:8]}"] = now
            atomic_write(
                self.waitlist_path + ".rl", json.dumps(stamps).encode()
            )
            with open(self.waitlist_path, "a") as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                f.write(email + "\n")
        return True, "added"


LANDING = """<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>erebus registry</title>
<style>
 body{{font-family:ui-monospace,Menlo,monospace;background:#0b0e14;color:#d7dce6;
      display:flex;flex-direction:column;align-items:center;padding:48px 16px;gap:28px}}
 h1{{color:#7ee0c3;font-size:26px}} .tag{{color:#5b6577}}
 .counters{{display:flex;gap:34px;text-align:center}}
 .num{{font-size:38px;color:#7ee0c3;font-weight:700}} .lbl{{color:#5b6577;font-size:12px}}
 form{{display:flex;gap:8px}} input{{background:#10162a;color:inherit;border:1px solid #1d2433;
      border-radius:8px;padding:11px 13px;font:inherit;width:280px}}
 button{{background:#173229;color:#7ee0c3;border:1px solid #245244;border-radius:8px;
      padding:0 18px;font:inherit;cursor:pointer}}
 code{{background:#10162a;padding:2px 6px;border-radius:4px}}
 a{{color:#7ee0c3}} #msg{{color:#5b6577;min-height:20px}}
</style></head><body>
<h1>erebus registry</h1>
<div class="tag">Your AI agent. One file. Runs anywhere.</div>
<div class="counters">
  <div><div class="num" id="saved">…</div><div class="lbl">GB SAVED BY DELTAS THIS WEEK</div></div>
  <div><div class="num" id="served">…</div><div class="lbl">GB SERVED</div></div>
  <div><div class="num" id="pulls">…</div><div class="lbl">PULLS</div></div>
</div>
<form onsubmit="join(event)"><input id="email" placeholder="you@company.com" autocomplete="email">
<button>Join the waitlist</button></form>
<div id="msg"></div>
<div class="tag">Open source · MIT —
<a href="https://github.com/Tednoob17/erebus">github.com/Tednoob17/erebus</a> ·
API: <code>/index.json</code> · <code>/packages/&lt;name&gt;</code></div>
<script>
async function refresh(){{
  try{{
    const s = await (await fetch('/stats')).json();
    saved.textContent = (s.bytes_saved/1e9).toFixed(2);
    served.textContent = (s.bytes_served/1e9).toFixed(2);
    pulls.textContent = s.pulls;
  }}catch(e){{}}
}}
function join(e){{
  e.preventDefault();
  fetch('/waitlist',{{method:'POST',headers:{{'Content-Type':'application/json'}},
    body:JSON.stringify({{email:document.getElementById('email').value}})}})
    .then(r=>r.json()).then(j=>{{msg.textContent=j.message||j.error;refresh();}})
    .catch(()=>msg.textContent='error');
}}
refresh(); setInterval(refresh, 30000);
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    store: Store = None  # type: ignore[assignment]
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    # -- helpers ------------------------------------------------------------
    def client_ip(self) -> str:
        return self.client_address[0]

    def read_body(self, cap: int) -> bytes | None:
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length > cap or length < 0:
            return None
        data = bytearray()
        while len(data) < length:
            chunk = self.rfile.read(min(CHUNK, length - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        return bytes(data)

    def send_json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # -- routing ------------------------------------------------------------
    def do_GET(self):
        self.connection.settimeout(30)
        path = self.path.split("?", 1)[0]
        if path == "/health":
            return self.send_json({"status": "ok"})
        if path == "/stats":
            return self.send_json(self.store.stats())
        if path == "/index.json":
            return self._send_index()
        if path == "/" or path == "/ui":
            body = LANDING.format().encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path.startswith("/packages/"):
            return self._serve_package(path[len("/packages/"):])
        self.send_json({"error": "not found"}, 404)

    def _send_index(self):
        body = self.store.index()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized_user(self) -> str | None:
        return self.store.authenticate(self.headers.get("Authorization", ""))

    def _serve_package(self, fname: str):
        fname = os.path.basename(fname)
        full = os.path.join(self.store.pkg_dir, fname)
        if not SAFE_FILE.match(fname) or not os.path.isfile(full):
            return self.send_json({"error": "package not found"}, 404)
        meta = self.store.get_meta(fname)
        size = os.path.getsize(full)
        rng = self.headers.get("Range")
        start, end = 0, size - 1
        if rng and rng.startswith("bytes="):
            try:
                first, last = rng[6:].split("-", 1)
                start = int(first) if first else 0
                end = int(last) if last else size - 1
            except ValueError:
                return self.send_json({"error": "bad range"}, 400)
        if start < 0 or end >= size or start > end:
            return self.send_json({"error": "range not satisfiable"}, 416)
        if meta.get("private"):
            user = self._authorized_user()
            if user != meta.get("owner"):
                return self.send_json({"error": "private package"}, 401)
            if self.store.month_served(user) + (end - start + 1) > self.store.quota_bytes:
                return self.send_json(
                    {"error": "monthly transfer quota exceeded (upgrade tier)"}, 402
                )
            self.store.charge_bytes(user, end - start + 1, size)
        else:
            # Anonymous public pull: count toward the public SISR story.
            self.store.bump_stats(end - start + 1, size)
        code = 206 if (rng and (start != 0 or end != size - 1)) else 200
        self.send_response(code)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(end - start + 1))
        self.send_header("Accept-Ranges", "bytes")
        self.end_headers()
        with open(full, "rb") as f:
            f.seek(start)
            remaining = end - start + 1
            while remaining > 0:
                chunk = f.read(min(CHUNK, remaining))
                if not chunk:
                    break
                self.wfile.write(chunk)
                remaining -= len(chunk)

    def do_POST(self):
        self.connection.settimeout(60)
        path = self.path.split("?", 1)[0]
        if path in ("/auth/register", "/auth/login"):
            body = self.read_body(4096)
            if body is None:
                return self.send_json({"error": "body too large"}, 413)
            try:
                payload = json.loads(body.decode("utf-8", "replace"))
                if not isinstance(payload, dict):
                    raise ValueError
            except ValueError:
                return self.send_json({"error": "invalid json"}, 400)
            return self._auth(payload, login=(path == "/auth/login"))
        if path == "/waitlist":
            body = self.read_body(1024)
            if body is None:
                return self.send_json({"error": "body too large"}, 413)
            try:
                parsed = json.loads(body.decode())
                if not isinstance(parsed, dict):
                    raise ValueError
                email = str(parsed.get("email", ""))
            except ValueError:
                return self.send_json({"error": "invalid json"}, 400)
            ok, msg = self.store.waitlist_add(email, self.client_ip())
            if ok:
                return self.send_json({"message": msg})
            code = 429 if "rate limited" in msg else 400
            return self.send_json({"error": msg}, code)
        if path == "/" or path.startswith("/packages/"):
            return self._upload()
        self.send_json({"error": "not found"}, 404)

    def _auth(self, payload: dict, login: bool):
        username = str(payload.get("username", ""))
        password = str(payload.get("password", ""))
        if login and self.store.bootstrap_open_uploads():
            return self.send_json({"error": "no users yet — register first"}, 400)
        if login:
            user = self.store.login(username, password, None)
            if not user:
                return self.send_json({"error": "invalid credentials"}, 401)
            with self.lock:
                tok_hash = self.store.users[user]["token_hash"]
            return self.send_json({"username": user, "note": "use your registration token"})
        ok, msg = self.store.register(username, password)
        if not ok:
            return self.send_json({"error": msg}, 400)
        return self.send_json({"username": username, "token": msg})

    def _upload(self):
        # The body may be huge and we may respond before reading all of it
        # (auth failure, cap exceeded): mark the connection for close so the
        # unread tail is never parsed as a pipelined request.
        self.close_connection = True
        open_mode = self.store.bootstrap_open_uploads()
        owner = self._authorized_user() if not open_mode else "__anon__"
        if not open_mode and owner is None:
            return self.send_json(
                {"error": "authentication required — register via /auth/register"}, 401
            )
        ctype = self.headers.get("Content-Type", "")
        if "boundary=" not in ctype:
            return self.send_json({"error": "expected multipart/form-data"}, 400)
        declared = int(self.headers.get("Content-Length", 0) or 0)
        if declared > self.store.upload_cap:
            return self.send_json({"error": "payload exceeds upload cap"}, 413)
        boundary = ctype.split("boundary=", 1)[1].strip('"').encode()

        # Stream to a unique temp file: concurrent uploads of the same target
        # can never interleave into one another's .part. Reading is bounded by
        # Content-Length — the client keeps the connection open, so waiting
        # for EOF would hang forever.
        declared = int(self.headers.get("Content-Length", 0) or 0)
        tmp = os.path.join(self.store.pkg_dir, f".incoming.{uuid.uuid4().hex}")
        fname, nbytes = stream_multipart(self, boundary, tmp, self.store.upload_cap, declared)
        if not fname:
            os.unlink(tmp)
            return self.send_json({"error": "missing file part / filename"}, 400)
        fname = os.path.basename(fname)
        if not SAFE_FILE.match(fname):
            os.unlink(tmp)
            return self.send_json({"error": "invalid package filename (want *.erebus)"}, 400)
        final = os.path.join(self.store.pkg_dir, fname)
        os.replace(tmp, final)
        # Body framing was handled manually (streamed); never let this
        # keep-alive connection be reused with unconsumed trailing bytes.
        self.close_connection = True
        self.store.set_meta(fname, None if open_mode else owner, private=bool(not open_mode and owner != "__anon__"))
        self.store._hash_cache.pop(final, None)
        self.send_json({"status": "ok", "stored": fname, "size": nbytes})


def stream_multipart(handler, boundary: bytes, dest: str, cap: int, declared: int):
    """Stream the first file part of a multipart body straight to `dest`.

    Returns (filename, bytes_written). Never holds more than one window of
    the payload in memory, and never reads past `declared` bytes — the client
    may keep the socket open after the body.
    """
    delim = b"\r\n--" + boundary
    fname = None
    written = 0
    consumed = 0
    out = open(dest, "wb")
    state = "preamble"
    window = b""
    try:
        while consumed < declared and written <= cap:
            chunk = handler.rfile.read(min(CHUNK, declared - consumed))
            if not chunk:
                break
            consumed += len(chunk)
            if state == "preamble":
                # The FIRST boundary sits at the very start of the body and
                # has no leading CRLF; later ones do (handled in data state).
                window += chunk
                first = b"--" + boundary
                idx = window.find(first)
                if idx == -1:
                    continue
                section_head = window[idx + len(first):]
                state = "headers"
                window = section_head
                continue
            if state == "headers":
                window += chunk
                hdr_end = window.find(b"\r\n\r\n")
                if hdr_end == -1:
                    if len(window) > 64 * 1024:
                        break
                    continue
                head = window[:hdr_end]
                m = re.search(rb'filename="([^"]+)"', head)
                fname = m.group(1).decode("utf-8", "replace") if m else None
                rest = window[hdr_end + 4:]
                state = "data"
                window = b""
                chunk = rest
            if state == "data":
                window += chunk
                # Flush everything except a trailing window that could hold
                # a split delimiter.
                keep = max(0, len(window) - (len(delim) + 4))
                if keep > 0:
                    out.write(window[:keep])
                    written += keep
                    window = window[keep:]
                pos = window.find(delim)
                while pos != -1:
                    out.write(window[:pos])
                    written += pos
                    after = window[pos + len(delim):]
                    if after.startswith(b"--"):
                        out.flush()
                        return fname, written
                    state = "headers"
                    window = after
                    break
    finally:
        out.close()
    return fname, written


def main() -> None:
    ap = argparse.ArgumentParser(description="erebus registry v2")
    ap.add_argument("--dir", required=True)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--quota-gb", type=float, default=20.0,
                    help="monthly transfer quota for free-tier authenticated pulls")
    ap.add_argument("--upload-cap-gb", type=float, default=70.0,
                    help="hard cap on any single upload")
    args = ap.parse_args()

    Handler.store = Store(
        args.dir, int(args.quota_gb * 1e9), int(args.upload_cap_gb * 1e9)
    )
    class Server(ThreadingHTTPServer):
        # Default listen backlog is 5; fleet-style bursts of concurrent
        # pulls/uploads otherwise get connection resets.
        request_queue_size = 128
        daemon_threads = True

    server = Server((args.host, args.port), Handler)
    daemon_threads = True
    print(
        f"erebus registry v2 on http://{args.host}:{args.port} dir={args.dir} "
        f"quota={args.quota_gb}GB/month cap={args.upload_cap_gb}GB/upload "
        f"(uploads {'OPEN — bootstrap mode' if Handler.store.bootstrap_open_uploads() else 'require auth'})",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
