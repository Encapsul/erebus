#!/usr/bin/env python3
"""Minimal erebus registry server — stdlib only, VPS-friendly.

Contract (matches the erebus CLI):
    GET  /health                  -> {"status":"ok"}
    GET  /index.json              -> {"packages":[{name,file,sha256,size,version}]}
    GET  /packages/<file>         -> raw bytes (range requests supported)
    POST /                        -> multipart upload ("file" part), .erebus only

The index is generated on the fly from the packages directory, so uploads are
immediately pullable — no manual index editing. sha256 is cached per file
mtime in memory to keep large-model listings cheap.

Run on your VPS:
    python3 scripts/registry_server.py --dir /srv/erebus --port 8787

Put nginx in front for TLS; set ERE_REGISTRY_TOKEN on both sides to require a
bearer token on uploads.
"""
import argparse
import hashlib
import io
import json
import os
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SAFE_FILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*\.erebus$")
CHUNK = 64 * 1024


class Registry:
    def __init__(self, root: str, token: str | None):
        self.root = root
        self.token = token
        self._hash_cache: dict[str, tuple[float, str]] = {}

    def pkg_dir(self) -> str:
        return os.path.join(self.root, "packages")

    def _sha256(self, path: str) -> str:
        mtime = os.path.getmtime(path)
        cached = self._hash_cache.get(path)
        if cached and cached[0] == mtime:
            return cached[1]
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(CHUNK):
                h.update(chunk)
        digest = h.hexdigest()
        self._hash_cache[path] = (mtime, digest)
        return digest

    def index(self) -> bytes:
        packages = []
        pkg_dir = self.pkg_dir()
        if os.path.isdir(pkg_dir):
            for name in sorted(os.listdir(pkg_dir)):
                path = os.path.join(pkg_dir, name)
                if not os.path.isfile(path) or not name.endswith(".erebus"):
                    continue
                packages.append({
                    "name": name[: -len(".erebus")],
                    "file": name,
                    "sha256": self._sha256(path),
                    "size": os.path.getsize(path),
                })
        body = json.dumps({"packages": packages}).encode()
        return body


def parse_multipart(handler, boundary: bytes) -> tuple[str | None, bytes | None]:
    """Return (filename, file-bytes) from the first file part of the body."""
    length = int(handler.headers.get("Content-Length", 0))
    if length <= 0 or length > 32 * 1024 * 1024 * 1024:
        return None, None
    body = handler.rfile.read(length)
    delim = b"--" + boundary
    for section in body.split(delim):
        if b"filename=" not in section or section in (b"--", b"--\r\n"):
            continue
        headers_blob, _, payload = section.partition(b"\r\n\r\n")
        m = re.search(rb'filename="([^"]+)"', headers_blob)
        fname = m.group(1).decode("utf-8", "replace") if m else None
        if payload.endswith(b"\r\n"):
            payload = payload[:-2]
        return fname, payload
    return None, None


class Handler(BaseHTTPRequestHandler):
    registry: Registry = None  # type: ignore[assignment]
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # quieter default logs
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _authorized(self) -> bool:
        expected = self.registry.token
        if not expected:
            return True
        got = self.headers.get("Authorization", "")
        return got == f"Bearer {expected}"

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/health":
            return self._send_json({"status": "ok"})
        if path == "/index.json":
            return self._send_json_bytes(self.registry.index())
        if path.startswith("/packages/"):
            fname = os.path.basename(path[len("/packages/"):])
            full = os.path.join(self.registry.pkg_dir(), fname)
            if SAFE_FILE.match(fname) and os.path.isfile(full):
                return self._send_file(full)
            return self._error(404, "package not found")
        self._error(404, "not found")

    def do_POST(self):
        if not self._authorized():
            return self._error(401, "unauthorized")
        ctype = self.headers.get("Content-Type", "")
        if "boundary=" not in ctype:
            return self._error(400, "expected multipart/form-data")
        boundary = ctype.split("boundary=", 1)[1].strip('"').encode()
        fname, data = parse_multipart(self, boundary)
        if data is None or not fname:
            return self._error(400, "missing file part / filename")
        fname = os.path.basename(fname)
        if not SAFE_FILE.match(fname):
            return self._error(400, "invalid package filename (want *.erebus)")

        pkg_dir = self.registry.pkg_dir()
        os.makedirs(pkg_dir, exist_ok=True)
        dest = os.path.join(pkg_dir, fname)
        with open(dest + ".part", "wb") as f:
            f.write(data)
        os.replace(dest + ".part", dest)
        self.registry._hash_cache.pop(dest, None)
        self._send_json({"status": "ok", "stored": fname, "size": len(data)})

    # -- responders ---------------------------------------------------------
    def _send_json(self, obj, code=200):
        self._send_json_bytes(json.dumps(obj).encode(), code)

    def _send_json_bytes(self, body: bytes, code=200):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path: str):
        size = os.path.getsize(path)
        rng = self.headers.get("Range")
        start, end = 0, size - 1
        code = 200
        if rng and rng.startswith("bytes="):
            first, last = rng[6:].split("-", 1)
            start = int(first) if first else 0
            end = int(last) if last else size - 1
            code = 206
        length = end - start + 1
        self.send_response(code)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(length))
        self.send_header("Accept-Ranges", "bytes")
        self.end_headers()
        with open(path, "rb") as f:
            f.seek(start)
            remaining = length
            while remaining > 0:
                chunk = f.read(min(CHUNK, remaining))
                if not chunk:
                    break
                self.wfile.write(chunk)
                remaining -= len(chunk)

    def _error(self, code: int, message: str):
        self._send_json({"error": message}, code)


def main() -> None:
    ap = argparse.ArgumentParser(description="minimal erebus registry")
    ap.add_argument("--dir", required=True, help="registry root directory")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8787)
    args = ap.parse_args()

    token = os.environ.get("ERE_REGISTRY_TOKEN")
    Handler.registry = Registry(args.dir, token)
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"erebus registry on http://{args.host}:{args.port} dir={args.dir}"
          + (" (token auth)" if token else " (OPEN UPLOADS)"), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
