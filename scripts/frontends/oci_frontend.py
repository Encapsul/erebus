#!/usr/bin/env python3
"""erebus OCI Distribution (Docker Registry) v2 compatible frontend.

Implements a minimal subset of the OCI Distribution Spec:
    GET  /v2/                              -> API version
    GET  /v2/{name}/tags/list              -> list versions
    GET  /v2/{name}/manifests/{ref}       -> get manifest (application/vnd.oci.image.manifest.v1+json)
    PUT  /v2/{name}/manifests/{ref}       -> push manifest
    GET  /v2/{name}/blobs/{digest}        -> get blob
    POST /v2/{name}/blobs/uploads/        -> start blob upload (returns 202 + location)
    PUT  /v2/{name}/blobs/{digest}        -> monolithic blob push

Mapping to erebus registry:
    OCI name    -> erebus package name (dots/slashes normalized)
    OCI tag     -> erebus package version (stored in metadata)
    OCI manifest -> erebus package metadata JSON + SHA-256 digest
    OCI blob     -> the .erebus binary payload

Authentication: Bearer <token> forwarded to erebus registry.

Stdlib only. No docker / oci SDK dependency.
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
OCI_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
OCI_LAYER_MEDIA = "application/vnd.erebus.binary.v1"
DEFAULT_TAG = "latest"

SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-/]*$")
SAFE_DIGEST = re.compile(r"^[a-f0-9]{64}$")


def parse_bearer(headers: dict) -> str | None:
    auth = headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:].strip()
    return None


def oci_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def oci_blob_digest_path(digest: str) -> str:
    if not SAFE_DIGEST.match(digest.split(":", 1)[-1] if ":" in digest else digest):
        raise ValueError("bad digest")
    return digest.replace(":", "/")


def erebus_request(base: str, method: str, path: str, token: str | None,
                   data: bytes | None = None, content_type: str = "",
                   headers: dict | None = None) -> tuple[int, bytes, dict]:
    url = urllib.parse.urljoin(base, path)
    hdrs = {"User-Agent": "erebus-oci-frontend/0.5"}
    if headers:
        hdrs.update(headers)
    if token:
        hdrs["Authorization"] = f"Bearer {token}"
    if data is not None and content_type and "Content-Type" not in hdrs:
        hdrs["Content-Type"] = content_type
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            return resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as e:
        body = e.read()
        return e.code, body, dict(e.headers)


def oci_manifest_from_package(name: str, pkg: dict, token: str | None, base: str) -> dict:
    digest_hex = pkg.get("sha256", "")
    config_digest = oci_digest(json.dumps({"name": name, "tag": pkg.get("tag", DEFAULT_TAG)}).encode())
    return {
        "schemaVersion": 2,
        "mediaType": OCI_MEDIA_TYPE,
        "config": {
            "mediaType": "application/vnd.erebus.config.v1+json",
            "size": len(json.dumps({"name": name, "tag": pkg.get("tag", DEFAULT_TAG)})),
            "digest": config_digest,
        },
        "layers": [
            {
                "mediaType": OCI_LAYER_MEDIA,
                "size": pkg.get("size", 0),
                "digest": f"sha256:{digest_hex}",
            }
        ],
    }


def oci_list_tags(base: str, token: str | None, name: str) -> tuple[int, bytes]:
    normalized = name.replace("/", "-").replace(".", "-")
    code, body, _ = erebus_request(base, "GET", "/index.json", token)
    if code != 200:
        return code, b'{"errors":[{"code":"SERVICE_UNAVAILABLE"}]}'
    try:
        packages = json.loads(body).get("packages", [])
    except ValueError:
        packages = []
    tags = []
    for pkg in packages:
        if pkg.get("name") == normalized:
            tags.append(pkg.get("tag", DEFAULT_TAG))
    return 200, json.dumps({"name": name, "tags": tags}).encode()


def oci_get_manifest(base: str, token: str | None, name: str, ref: str) -> tuple[int, bytes, dict]:
    normalized = name.replace("/", "-").replace(".", "-")
    code, body, _ = erebus_request(base, "GET", "/index.json", token)
    if code != 200:
        return code, b'{"errors":[{"code":"SERVICE_UNAVAILABLE"}]}', {}
    try:
        packages = json.loads(body).get("packages", [])
    except ValueError:
        packages = []
    match = None
    tag = ref
    if ":" not in ref and ref != "latest":
        tag = ref
    elif ":" in ref:
        tag = ref.split(":", 1)[-1]
    for pkg in packages:
        if pkg.get("name") == normalized and pkg.get("tag", DEFAULT_TAG) == tag:
            match = pkg
            break
    if not match:
        # Fallback: latest tag by name
        for pkg in packages:
            if pkg.get("name") == normalized:
                match = pkg
                break
    if not match:
        return 404, b'{"errors":[{"code":"NAME_UNKNOWN"}]}', {}
    match["tag"] = tag
    manifest = oci_manifest_from_package(name, match, token, base)
    body = json.dumps(manifest).encode()
    hdrs = {
        "Content-Type": OCI_MEDIA_TYPE,
        "Docker-Content-Digest": oci_digest(body),
    }
    return 200, body, hdrs


def oci_head_manifest(base: str, token: str | None, name: str, ref: str) -> tuple[int, dict]:
    normalized = name.replace("/", "-").replace(".", "-")
    code, body, _ = erebus_request(base, "GET", "/index.json", token)
    if code != 200:
        return 503, {}
    try:
        packages = json.loads(body).get("packages", [])
    except ValueError:
        packages = []
    tag = ref.split(":", 1)[-1] if ":" in ref else ref
    match = None
    for pkg in packages:
        if pkg.get("name") == normalized and pkg.get("tag", DEFAULT_TAG) == tag:
            match = pkg
            break
    if not match:
        for pkg in packages:
            if pkg.get("name") == normalized:
                match = pkg
                break
    if not match:
        return 404, {}
    manifest = oci_manifest_from_package(name, match, token, base)
    body = json.dumps(manifest).encode()
    hdrs = {
        "Content-Type": OCI_MEDIA_TYPE,
        "Docker-Content-Digest": oci_digest(body),
        "Content-Length": str(len(body)),
    }
    return 200, hdrs


def oci_get_blob(base: str, token: str | None, name: str, digest: str) -> tuple[int, bytes, dict]:
    normalized = name.replace("/", "-").replace(".", "-")
    hex_digest = digest.split(":", 1)[-1] if ":" in digest else digest
    if not SAFE_DIGEST.match(hex_digest):
        return 400, b'{"errors":[{"code":"DIGEST_INVALID"}]}', {}
    code, body, _ = erebus_request(base, "GET", "/index.json", token)
    if code != 200:
        return code, b'{"errors":[{"code":"SERVICE_UNAVAILABLE"}]}', {}
    try:
        packages = json.loads(body).get("packages", [])
    except ValueError:
        packages = []
    match = None
    for pkg in packages:
        if pkg.get("name") == normalized and pkg.get("sha256", "") == hex_digest:
            match = pkg
            break
    if not match:
        return 404, b'{"errors":[{"code":"BLOB_UNKNOWN"}]}', {}
    path = f"/packages/{urllib.parse.quote(normalized)}.erebus"
    code, blob, hdrs = erebus_request(base, "GET", path, token)
    if code != 200:
        return code, b'{"errors":[{"code":"BLOB_UNKNOWN"}]}', {}
    actual_digest = oci_digest(blob)
    if actual_digest != f"sha256:{hex_digest}":
        return 404, b'{"errors":[{"code":"BLOB_UNKNOWN"}]}', {}
    resp_hdrs = {
        "Content-Type": OCI_LAYER_MEDIA,
        "Content-Length": str(len(blob)),
        "Docker-Content-Digest": actual_digest,
    }
    return 200, blob, resp_hdrs


def oci_start_upload(base: str, token: str | None, name: str) -> tuple[int, bytes, dict]:
    if not token:
        return 401, b'{"errors":[{"code":"UNAUTHORIZED"}]}', {}
    normalized = name.replace("/", "-").replace(".", "-")
    location = f"/v2/{urllib.parse.quote(name)}/blobs/uploads/?uuid=erebus"
    hdrs = {
        "Location": urllib.parse.urljoin(base, location),
        "Docker-Upload-UUID": "erebus",
    }
    return 202, b"", hdrs


def oci_monolithic_upload(base: str, token: str | None, name: str,
                          digest: str, data: bytes) -> tuple[int, bytes]:
    if not token:
        return 401, b'{"errors":[{"code":"UNAUTHORIZED"}]}'
    hex_digest = digest.split(":", 1)[-1] if ":" in digest else digest
    if not SAFE_DIGEST.match(hex_digest):
        return 400, b'{"errors":[{"code":"DIGEST_INVALID"}]}'
    actual = oci_digest(data)
    if actual != f"sha256:{hex_digest}":
        return 400, b'{"errors":[{"code":"DIGEST_INVALID"}]}'
    normalized = name.replace("/", "-").replace(".", "-")
    boundary = "boundary_erebus"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{normalized}.erebus"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + data + f"\r\n--{boundary}--\r\n".encode()
    path = f"/packages/{urllib.parse.quote(normalized)}.erebus"
    code, _, _ = erebus_request(base, "POST", path, token, data=body,
                                content_type=f"multipart/form-data; boundary={boundary}")
    if code in (200, 201):
        return 201, b""
    return code, b'{"errors":[{"code":"BLOB_UPLOAD_INVALID"}]}'


class OCIHandler(BaseHTTPRequestHandler):
    server_version = "erebus-oci-frontend/0.5"
    erebus_base: str = "http://127.0.0.1:8080"
    token: str | None = None

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _auth_token(self) -> str | None:
        return parse_bearer(dict(self.headers))

    def _send_json(self, code: int, body: bytes, hdrs: dict | None = None):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if hdrs:
            for k, v in hdrs.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        token = self._auth_token()
        path = urllib.parse.urlparse(self.path).path
        if path == "/v2/":
            return self._send_json(200, b'{"apiVersion":"v2"}')
        m = re.match(r"^/v2/([^/]+)/tags/list$", path)
        if m:
            name = urllib.parse.unquote(m.group(1))
            code, body = oci_list_tags(self.erebus_base, token, name)
            return self._send_json(code, body)
        m = re.match(r"^/v2/([^/]+)/blobs/([^/]+)$", path)
        if m:
            name = urllib.parse.unquote(m.group(1))
            digest = urllib.parse.unquote(m.group(2))
            code, body, hdrs = oci_get_blob(self.erebus_base, token, name, digest)
            self.send_response(code)
            self.send_header("Content-Type", OCI_LAYER_MEDIA)
            self.send_header("Content-Length", str(len(body)))
            for k, v in hdrs.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()

    def do_HEAD(self):
        token = self._auth_token()
        path = urllib.parse.urlparse(self.path).path
        m = re.match(r"^/v2/([^/]+)/manifests/([^/]+)$", path)
        if m:
            name = urllib.parse.unquote(m.group(1))
            ref = urllib.parse.unquote(m.group(2))
            code, hdrs = oci_head_manifest(self.erebus_base, token, name, ref)
            self.send_response(code)
            self.send_header("Content-Type", OCI_MEDIA_TYPE)
            for k, v in hdrs.items():
                self.send_header(k, v)
            self.end_headers()
            return
        m = re.match(r"^/v2/([^/]+)/blobs/([^/]+)$", path)
        if m:
            name = urllib.parse.unquote(m.group(1))
            digest = urllib.parse.unquote(m.group(2))
            code, body, hdrs = oci_get_blob(self.erebus_base, token, name, digest)
            self.send_response(code)
            for k, v in hdrs.items():
                self.send_header(k, v)
            self.end_headers()
            return
        self.send_response(404)
        self.end_headers()

    def do_PUT(self):
        token = self._auth_token()
        path = urllib.parse.urlparse(self.path).path
        length = int(self.headers.get("Content-Length", 0))
        data = self.rfile.read(min(length, 1 << 30))
        # Manifest push
        m = re.match(r"^/v2/([^/]+)/manifests/([^/]+)$", path)
        if m:
            name = urllib.parse.unquote(m.group(1))
            ref = urllib.parse.unquote(m.group(2))
            # Normalize tag from ref
            tag = ref.split(":", 1)[-1] if ":" in ref else ref
            normalized = name.replace("/", "-").replace(".", "-")
            expected = f"{normalized}.erebus"
            boundary = "boundary_erebus"
            body = (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="file"; filename="{expected}"\r\n'
                f"Content-Type: application/octet-stream\r\n\r\n"
            ).encode() + data + f"\r\n--{boundary}--\r\n".encode()
            path2 = f"/packages/{urllib.parse.quote(expected)}"
            code, _, _ = erebus_request(self.erebus_base, "POST", path2, token,
                                        data=body, content_type=f"multipart/form-data; boundary={boundary}")
            if code in (200, 201):
                digest = oci_digest(data)
                hdrs = {
                    "Docker-Content-Digest": digest,
                }
                return self._send_json(201, b"", hdrs)
            return self._send_json(code, b'{"errors":[{"code":"BLOB_UPLOAD_INVALID"}]}')
        # Blob push (monolithic)
        m = re.match(r"^/v2/([^/]+)/blobs/([^/]+)$", path)
        if m:
            name = urllib.parse.unquote(m.group(1))
            digest = urllib.parse.unquote(m.group(2))
            code, body = oci_monolithic_upload(self.erebus_base, token, name, digest, data)
            return self._send_json(code, body)
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        token = self._auth_token()
        path = urllib.parse.urlparse(self.path).path
        m = re.match(r"^/v2/([^/]+)/blobs/uploads/?$", path)
        if m:
            name = urllib.parse.unquote(m.group(1))
            code, body, hdrs = oci_start_upload(self.erebus_base, token, name)
            self.send_response(code)
            self.send_header("Content-Length", "0")
            for k, v in hdrs.items():
                self.send_header(k, v)
            self.end_headers()
            return
        self.send_response(404)
        self.end_headers()


def main():
    ap = argparse.ArgumentParser(description="erebus OCI Distribution frontend")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--registry", default="http://127.0.0.1:8080")
    ap.add_argument("--token", default=None)
    args = ap.parse_args()
    OCIHandler.erebus_base = args.registry.rstrip("/")
    OCIHandler.token = args.token
    server = HTTPServer((args.host, args.port), OCIHandler)
    print(f"OCI frontend listening on {args.host}:{args.port} -> {args.registry}", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
