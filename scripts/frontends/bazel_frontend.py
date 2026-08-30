#!/usr/bin/env python3
"""erebus Bazel HTTP remote cache frontend.

Implements the Bazel HTTP remote cache protocol v2:
    GET  /ac/<hash>/<size>   -> get action cache entry
    PUT  /ac/<hash>/<size>   -> put action cache entry
    GET  /cas/<hash>         -> get content-addressable store blob
    PUT  /cas/<hash>         -> put in CAS (size in body determines digest check)

Maps to erebus registry:
    /cas/<sha256>  -> GET/POST /packages/<name>.erebus where sha256 matches
    /ac/<hash>     -> 200 OK with empty body (hit) or 404 (miss)
                      Bazel's AC is derived from CAS, so we just proxy CAS.

Authentication: Bearer <token> forwarded to erebus registry.

Stdlib only.
"""
import argparse
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

CHUNK = 64 * 1024
SAFE_DIGEST = re.compile(r"^[a-f0-9]{64}$")


def parse_bearer(headers: dict) -> str | None:
    auth = headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:].strip()
    return None


def erebus_request(base: str, method: str, path: str, token: str | None,
                   data: bytes | None = None, content_type: str = "") -> tuple[int, bytes, dict]:
    url = urllib.parse.urljoin(base, path)
    headers = {"User-Agent": "erebus-bazel-frontend/0.5"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if data is not None and content_type:
        headers["Content-Type"] = content_type
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            return resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)
    except urllib.error.URLError:
        return 503, b"", {}


def bazel_find_package_by_sha(base: str, token: str | None, hex_digest: str) -> tuple[str, bytes] | None:
    code, body, _ = erebus_request(base, "GET", "/index.json", token)
    if code != 200:
        return None
    try:
        packages = json.loads(body).get("packages", [])
    except ValueError:
        return None
    for pkg in packages:
        if pkg.get("sha256", "") == hex_digest:
            return pkg.get("name", ""), body
    return None


def bazel_cas_get(base: str, token: str | None, hex_digest: str) -> tuple[int, bytes]:
    if not SAFE_DIGEST.match(hex_digest):
        return 400, b'{"message":"invalid digest"}'
    result = bazel_find_package_by_sha(base, token, hex_digest)
    if not result:
        return 404, b""
    pkg_name = result[0]
    path = f"/packages/{urllib.parse.quote(pkg_name)}.erebus"
    code, blob, _ = erebus_request(base, "GET", path, token)
    if code != 200:
        return code, b""
    actual = hashlib.sha256(blob).hexdigest()
    if actual != hex_digest:
        return 404, b""
    return 200, blob


def bazel_cas_put(base: str, token: str | None, hex_digest: str, data: bytes) -> tuple[int, bytes]:
    if not SAFE_DIGEST.match(hex_digest):
        return 400, b'{"message":"invalid digest"}'
    actual = hashlib.sha256(data).hexdigest()
    if actual != hex_digest:
        return 400, b'{"message":"checksum mismatch"}'
    # Find if a package with this sha already exists to reuse the name
    existing = bazel_find_package_by_sha(base, token, hex_digest)
    if existing:
        pkg_name = existing[0]
    else:
        pkg_name = f"bazel-{hex_digest[:16]}"
    expected = f"{pkg_name}.erebus"
    boundary = "boundary_erebus"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{expected}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + data + f"\r\n--{boundary}--\r\n".encode()
    path = f"/packages/{urllib.parse.quote(expected)}"
    code, _, _ = erebus_request(base, "POST", path, token, data=body,
                                content_type=f"multipart/form-data; boundary={boundary}")
    if code in (200, 201):
        return 200, b""
    return code, b'{"message":"upload failed"}'


class BazelHandler(BaseHTTPRequestHandler):
    server_version = "erebus-bazel-frontend/0.5"
    erebus_base: str = "http://127.0.0.1:8080"
    token: str | None = None

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _auth_token(self) -> str | None:
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:].strip()
        return None

    def do_GET(self):
        token = self._auth_token()
        path = urllib.parse.urlparse(self.path).path
        m = re.match(r"^/cas/([a-f0-9]{64})$", path)
        if m:
            hex_digest = m.group(1)
            code, body = bazel_cas_get(self.erebus_base, token, hex_digest)
            self.send_response(code)
            if code == 200:
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("X-Checksum-Sha256", hex_digest)
            self.end_headers()
            self.wfile.write(body)
            return
        # AC passthrough: Bazel action cache hits return empty 200.
        m = re.match(r"^/ac/([a-f0-9]{64})/(\d+)$", path)
        if m:
            hex_digest = m.group(1)
            code, body = bazel_cas_get(self.erebus_base, token, hex_digest)
            if code == 200:
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
            return
        self.send_response(404)
        self.end_headers()

    def do_PUT(self):
        token = self._auth_token()
        path = urllib.parse.urlparse(self.path).path
        length = int(self.headers.get("Content-Length", 0))
        data = self.rfile.read(min(length, 1 << 30))
        # CAS put
        m = re.match(r"^/cas/([a-f0-9]{64})$", path)
        if m:
            hex_digest = m.group(1)
            code, resp = bazel_cas_put(self.erebus_base, token, hex_digest, data)
            self.send_response(code)
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
            return
        # AC put (empty body, derived from CAS)
        m = re.match(r"^/ac/([a-f0-9]{64})/(\d+)$", path)
        if m:
            hex_digest = m.group(1)
            actual = hashlib.sha256(data).hexdigest()
            if actual != hex_digest:
                self.send_response(400)
                self.end_headers()
                return
            # AC is derived from CAS — store marker in registry or just return 200
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(404)
        self.end_headers()


def main():
    ap = argparse.ArgumentParser(description="erebus Bazel HTTP remote cache frontend")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8083)
    ap.add_argument("--registry", default="http://127.0.0.1:8080")
    ap.add_argument("--token", default=None)
    args = ap.parse_args()
    BazelHandler.erebus_base = args.registry.rstrip("/")
    BazelHandler.token = args.token
    server = HTTPServer((args.host, args.port), BazelHandler)
    print(f"Bazel HTTP cache frontend listening on {args.host}:{args.port} -> {args.registry}", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
