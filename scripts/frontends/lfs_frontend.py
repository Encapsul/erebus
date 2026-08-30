#!/usr/bin/env python3
"""erebus Git LFS compatible frontend.

Implements the Git LFS batch API:
    POST /objects/batch  -> batch download/upload/verify

The LFS object id (oid) is the SHA-256 hex digest of the .erebus blob.
Maps to erebus registry:
    oid sha256:<hex> -> erebus package whose sha256 == <hex>

Authentication: Basic auth or Bearer token forwarded to erebus registry.

Stdlib only. No git-lfs dependency.
"""
import argparse
import base64
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


def parse_auth(headers: dict) -> str | None:
    auth = headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:].strip()
    if auth.startswith("Basic "):
        try:
            decoded = base64.b64decode(auth[6:]).decode()
            if ":" in decoded:
                return decoded.split(":", 1)[1]
        except Exception:
            pass
    return None


def erebus_request(base: str, method: str, path: str, token: str | None,
                   data: bytes | None = None, content_type: str = "") -> tuple[int, bytes, dict]:
    url = urllib.parse.urljoin(base, path)
    headers = {"User-Agent": "erebus-lfs-frontend/0.5"}
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


def lfs_batch(base: str, token: str | None, body: bytes) -> tuple[int, bytes, dict]:
    try:
        req = json.loads(body)
    except ValueError:
        return 400, json.dumps({"message": "Invalid JSON body"}).encode(), {}
    objects = req.get("objects", [])
    operation = req.get("operation", "download")
    if not isinstance(objects, list):
        return 400, json.dumps({"message": "objects must be an array"}).encode(), {}
    # Build sha256 set from index
    code, index_body, _ = erebus_request(base, "GET", "/index.json", token)
    if code != 200:
        return code, json.dumps({"message": "upstream error", "status": code}).encode(), {}
    try:
        packages = json.loads(index_body).get("packages", [])
    except ValueError:
        packages = []
    sha_to_name = {}
    for pkg in packages:
        sha_to_name[pkg.get("sha256", "")] = pkg.get("name", "")
    results = []
    for obj in objects:
        oid = obj.get("oid", "")
        size = obj.get("size", 0)
        if not oid.startswith("sha256:"):
            results.append({"oid": oid, "size": size, "error": {"code": 404, "message": "invalid oid"}})
            continue
        hex_digest = oid[7:]
        if not SAFE_DIGEST.match(hex_digest):
            results.append({"oid": oid, "size": size, "error": {"code": 404, "message": "invalid sha256"}})
            continue
        pkg_name = sha_to_name.get(hex_digest)
        if not pkg_name:
            results.append({"oid": oid, "size": size, "error": {"code": 404, "message": "object not found"}})
            continue
        if operation == "download":
            pkg_path = f"/packages/{urllib.parse.quote(pkg_name)}.erebus"
            blob_code, blob, _ = erebus_request(base, "GET", pkg_path, token)
            if blob_code == 200:
                actual_digest = hashlib.sha256(blob).hexdigest()
                if actual_digest != hex_digest:
                    results.append({"oid": oid, "size": size, "error": {"code": 422, "message": "checksum mismatch"}})
                else:
                    results.append({
                        "oid": oid,
                        "size": size,
                        "actions": {
                            "download": {
                                "href": f"lfs://erebus/{pkg_name}",
                                "header": {},
                            }
                        },
                    })
            else:
                results.append({"oid": oid, "size": size, "error": {"code": 404, "message": "blob fetch failed"}})
        elif operation == "upload":
            results.append({"oid": oid, "size": size})
        else:
            results.append({"oid": oid, "size": size, "error": {"code": 400, "message": f"unknown operation {operation}"}})
    return 200, json.dumps({"transfer": ["basic"], "objects": results}).encode(), {}


def lfs_upload_object(base: str, token: str | None, oid: str, data: bytes) -> tuple[int, bytes, dict]:
    if not oid.startswith("sha256:"):
        return 400, json.dumps({"message": "invalid oid"}).encode(), {}
    hex_digest = oid[7:]
    actual = hashlib.sha256(data).hexdigest()
    if actual != hex_digest:
        return 422, json.dumps({"message": "checksum mismatch", "oid": oid}).encode(), {}
    # Use first package slot or create a deterministic name
    pkg_name = f"lfs-{hex_digest[:16]}"
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
        return 201, json.dumps({"oid": oid, "size": len(data)}).encode(), {}
    return code, json.dumps({"message": "upload failed", "status": code}).encode(), {}


class LFSHandler(BaseHTTPRequestHandler):
    server_version = "erebus-lfs-frontend/0.5"
    erebus_base: str = "http://127.0.0.1:8080"
    token: str | None = None

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _auth_token(self) -> str | None:
        return parse_auth(dict(self.headers))

    def _send_json(self, code: int, body: bytes):
        self.send_response(code)
        self.send_header("Content-Type", "application/vnd.git-lfs+json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        token = self._auth_token()
        path = urllib.parse.urlparse(self.path).path
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(min(length, 10 << 20))
        if path == "/objects/batch":
            code, resp, _ = lfs_batch(self.erebus_base, token, body)
            return self._send_json(code, resp)
        # Single object upload endpoint some clients use
        m = re.match(r"^/objects/([^/]+)$", path)
        if m:
            oid = urllib.parse.unquote(m.group(1))
            code, resp, _ = lfs_upload_object(self.erebus_base, token, oid, body)
            return self._send_json(code, resp)
        self.send_response(404)
        self.end_headers()

    def do_GET(self):
        token = self._auth_token()
        path = urllib.parse.urlparse(self.path).path
        m = re.match(r"^/objects/([^/]+)$", path)
        if m:
            oid = urllib.parse.unquote(m.group(1))
            if not oid.startswith("sha256:"):
                return self._send_json(400, json.dumps({"message": "invalid oid"}).encode())
            hex_digest = oid[7:]
            code, index_body, _ = erebus_request(self.erebus_base, "GET", "/index.json", token)
            if code != 200:
                return self._send_json(code, json.dumps({"message": "upstream error"}).encode())
            try:
                packages = json.loads(index_body).get("packages", [])
            except ValueError:
                packages = []
            match = None
            for pkg in packages:
                if pkg.get("sha256", "") == hex_digest:
                    match = pkg
                    break
            if not match:
                return self._send_json(404, json.dumps({"message": "object not found", "oid": oid}).encode())
            pkg_path = f"/packages/{urllib.parse.quote(match.get('name', ''))}.erebus"
            blob_code, blob, _ = erebus_request(self.erebus_base, "GET", pkg_path, token)
            if blob_code != 200:
                return self._send_json(blob_code, json.dumps({"message": "blob not found", "oid": oid}).encode())
            actual = hashlib.sha256(blob).hexdigest()
            if actual != hex_digest:
                return self._send_json(422, json.dumps({"message": "checksum mismatch", "oid": oid}).encode())
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(blob)))
            self.send_header("X-Checksum-Sha256", actual)
            self.end_headers()
            self.wfile.write(blob)
            return
        self.send_response(404)
        self.end_headers()


def main():
    ap = argparse.ArgumentParser(description="erebus Git LFS frontend")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8082)
    ap.add_argument("--registry", default="http://127.0.0.1:8080")
    ap.add_argument("--token", default=None)
    args = ap.parse_args()
    LFSHandler.erebus_base = args.registry.rstrip("/")
    LFSHandler.token = args.token
    server = HTTPServer((args.host, args.port), LFSHandler)
    print(f"LFS frontend listening on {args.host}:{args.port} -> {args.registry}", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
