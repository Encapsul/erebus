#!/usr/bin/env python3
"""erebus HuggingFace Hub API compatible frontend.

Implements a minimal subset of the HF Hub API backed by an erebus registry:
    GET /api/models                        -> list packages (as HF repos)
    GET /api/models/{repo_id}              -> package metadata
    GET /api/models/{repo_id}/tree/{rev}   -> file listing
    GET /api/models/{repo_id}/resolve/{rev}/{filename} -> download
    POST /api/models/{repo_id}/commit/{branch} -> upload (multipart)

The mapping is:
    HF repo_id   -> erebus package name (dots/slashes normalized)
    HF revision  -> erebus package file (the blob itself is the artifact)
    HF filename  -> the erebus .erebus blob

Authentication: Bearer <token> forwarded to the erebus registry.

Stdlib only. No huggingface_hub dependency.
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

EREBUS_MAGIC = b"ERE\x01\x00"
CHUNK = 64 * 1024

SAFE_REPO = re.compile(r"^[A-Za-z0-9\-\.]+/[A-Za-z0-9\-\.]+$")

HF_DATE_FMT = "%Y-%m-%dT%H:%M:%S.%fZ"


def hf_error(code: int, message: str, **kwargs) -> bytes:
    obj = {"error": message}
    obj.update(kwargs)
    return json.dumps(obj).encode()


def hf_normalize_repo(repo_id: str) -> str:
    return repo_id.replace("/", "-").replace(".", "-")


def hf_denormalize_name(name: str) -> str:
    return name.replace("-", ".", 1)


def erebus_request(base: str, method: str, path: str, token: str | None,
                   data: bytes | None = None, content_type: str = "") -> tuple[int, bytes, dict]:
    url = urllib.parse.urljoin(base, path)
    headers = {"User-Agent": "erebus-hf-frontend/0.5"}
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


def hf_list_models(base: str, token: str | None) -> tuple[int, bytes]:
    code, body, _ = erebus_request(base, "GET", "/index.json", token)
    if code != 200:
        return code, hf_error(code, "upstream_error", upstream_status=code)
    try:
        packages = json.loads(body).get("packages", [])
    except ValueError:
        packages = []
    result = []
    for pkg in packages:
        repo_id = hf_denormalize_name(pkg.get("name", ""))
        result.append({
            "id": repo_id,
            "sha": pkg.get("sha256", ""),
            "lastModified": pkg.get("lastModified", ""),
            "private": pkg.get("private", False),
        })
    return 200, json.dumps(result).encode()


def hf_model_info(base: str, token: str | None, repo_id: str) -> tuple[int, bytes]:
    normalized = hf_normalize_repo(repo_id)
    code, body, _ = erebus_request(base, "GET", "/index.json", token)
    if code != 200:
        return code, hf_error(code, "upstream_error")
    try:
        packages = json.loads(body).get("packages", [])
    except ValueError:
        packages = []
    match = None
    for pkg in packages:
        if pkg.get("name") == normalized:
            match = pkg
            break
    if not match:
        return 404, hf_error(404, "RepoNotFound", repository=repo_id)
    info = {
        "id": repo_id,
        "sha": match.get("sha256", ""),
        "private": match.get("private", False),
        "cardData": {},
        "siblings": [
            {
                "rfilename": f"{normalized}.erebus",
                "size": match.get("size", 0),
                "blobId": f"blob:{match.get('sha256', '')}",
            }
        ],
    }
    return 200, json.dumps(info).encode()


def hf_tree(base: str, token: str | None, repo_id: str, rev: str) -> tuple[int, bytes]:
    normalized = hf_normalize_repo(repo_id)
    code, body, _ = erebus_request(base, "GET", "/index.json", token)
    if code != 200:
        return code, hf_error(code, "upstream_error")
    try:
        packages = json.loads(body).get("packages", [])
    except ValueError:
        packages = []
    match = None
    for pkg in packages:
        if pkg.get("name") == normalized:
            match = pkg
            break
    if not match:
        return 404, hf_error(404, "RepoNotFound", repository=repo_id)
    tree = [
        {
            "path": f"{normalized}.erebus",
            "size": match.get("size", 0),
            "blobId": f"blob:{match.get('sha256', '')}",
            "type": "file",
        }
    ]
    return 200, json.dumps(tree).encode()


def hf_resolve(base: str, token: str | None, repo_id: str, rev: str, filename: str) -> tuple[int, bytes, dict]:
    normalized = hf_normalize_repo(repo_id)
    expected = f"{normalized}.erebus"
    if filename != expected:
        return 404, hf_error(404, "FileNotFoundError", path=filename), {}
    path = f"/packages/{urllib.parse.quote(expected)}"
    code, body, headers = erebus_request(base, "GET", path, token)
    if code != 200:
        return code, hf_error(code, "upstream_error"), {}
    hdrs = {
        "Content-Type": "application/octet-stream",
        "ETag": '"' + hashlib.sha256(body).hexdigest()[:32] + '"',
        "Content-Disposition": f'attachment; filename="{expected}"',
        "X-Linked-ETag": '"' + hashlib.sha256(body).hexdigest()[:32] + '"',
    }
    return 200, body, hdrs


def hf_upload(base: str, token: str | None, repo_id: str, branch: str,
              data: bytes, content_type: str) -> tuple[int, bytes]:
    if not token:
        return 401, hf_error(401, "unauthorized")
    normalized = hf_normalize_repo(repo_id)
    expected_name = f"{normalized}.erebus"
    boundary = None
    if content_type.startswith("multipart/form-data"):
        boundary = content_type.split("boundary=")[-1]
        if boundary:
            boundary = boundary.strip('"')
    if boundary:
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{expected_name}"\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n"
        ).encode() + data + f"\r\n--{boundary}--\r\n".encode()
    else:
        body = data
    path = f"/packages/{urllib.parse.quote(expected_name)}"
    code, resp_body, _ = erebus_request(base, "POST", path, token, data=body,
                                        content_type=content_type or "application/octet-stream")
    if code in (200, 201):
        return 201, json.dumps({
            "commitUrl": f"https://huggingface.co/{repo_id}/commit/abc123",
            "commit": {
                "title": "Upload via erebus HF frontend",
                "summary": "",
                "date": __import__("datetime").datetime.utcnow().strftime(HF_DATE_FMT),
            },
        }).encode()
    return code, hf_error(code, "upstream_error")


class HFHandler(BaseHTTPRequestHandler):
    server_version = "erebus-hf-frontend/0.5"
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
        # /api/models
        if path == "/api/models" or path == "/api/models/":
            code, body = hf_list_models(self.erebus_base, token)
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        # /api/models/{repo_id}
        m = re.match(r"^/api/models/([^/]+)/?$", path)
        if m:
            repo_id = urllib.parse.unquote(m.group(1))
            code, body = hf_model_info(self.erebus_base, token, repo_id)
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        # /api/models/{repo_id}/tree/{rev}
        m = re.match(r"^/api/models/([^/]+)/tree/([^/]+)/?$", path)
        if m:
            repo_id = urllib.parse.unquote(m.group(1))
            rev = urllib.parse.unquote(m.group(2))
            code, body = hf_tree(self.erebus_base, token, repo_id, rev)
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        # /api/models/{repo_id}/resolve/{rev}/{filename}
        m = re.match(r"^/api/models/([^/]+)/resolve/([^/]+)/(.+)$", path)
        if m:
            repo_id = urllib.parse.unquote(m.group(1))
            rev = urllib.parse.unquote(m.group(2))
            filename = urllib.parse.unquote(m.group(3))
            code, body, hdrs = hf_resolve(self.erebus_base, token, repo_id, rev, filename)
            self.send_response(code)
            self.send_header("Content-Type", "application/octet-stream")
            for k, v in hdrs.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        token = self._auth_token()
        path = urllib.parse.urlparse(self.path).path
        # /api/models/{repo_id}/commit/{branch}
        m = re.match(r"^/api/models/([^/]+)/commit/([^/]+)/?$", path)
        if m:
            repo_id = urllib.parse.unquote(m.group(1))
            branch = urllib.parse.unquote(m.group(2))
            length = int(self.headers.get("Content-Length", 0))
            data = self.rfile.read(min(length, 1 << 30))
            content_type = self.headers.get("Content-Type", "")
            code, body = hf_upload(self.erebus_base, token, repo_id, branch, data, content_type)
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()


def main():
    ap = argparse.ArgumentParser(description="erebus HuggingFace Hub API frontend")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8081)
    ap.add_argument("--registry", default="http://127.0.0.1:8080")
    ap.add_argument("--token", default=None)
    args = ap.parse_args()
    HFHandler.erebus_base = args.registry.rstrip("/")
    HFHandler.token = args.token
    server = HTTPServer((args.host, args.port), HFHandler)
    print(f"HF Hub frontend listening on {args.host}:{args.port} -> {args.registry}", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
