#!/usr/bin/env python3
"""erebus S3-compatible frontend.

Translates a subset of the S3 REST API to erebus registry calls:
    GET  /{key}                  -> GET  /packages/{file}
    PUT  /{key}                  -> POST /packages/{name} (multipart)
    HEAD /{key}                  -> HEAD /packages/{file}
    GET  /?list-type=2&prefix=   -> GET  /index.json
    DELETE /{key}                -> 501 Not Implemented

Authentication:
    Authorization: AWS <key>:<secret> or Bearer <token>
    The secret is ignored; key is matched as a bearer token against
    the erebus registry auth.

Stdlib only. No boto3 or botocore.
"""
import argparse
import hashlib
import hmac
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from xml.etree.ElementTree import Element, SubElement, tostring

EREBUS_MAGIC = b"ERE\x01\x00"
CHUNK = 64 * 1024

SAFE_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-/]*$")


def parse_s3_auth(headers: dict) -> str | None:
    auth = headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:].strip()
    if auth.startswith("AWS "):
        parts = auth[4:].split(":", 1)
        if parts:
            return parts[0].strip()
    return None


def erebus_request(base: str, method: str, path: str, token: str | None,
                   data: bytes | None = None, content_type: str = "") -> tuple[int, bytes, dict]:
    url = urllib.parse.urljoin(base, path)
    headers = {"User-Agent": "erebus-s3-frontend/0.5"}
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


def s3_list_buckets(base: str, token: str | None) -> tuple[int, bytes]:
    # erebus has no bucket concept; return the public package index as a
    # single bucket named "packages".
    code, body, _ = erebus_request(base, "GET", "/index.json", token)
    if code != 200:
        return code, b'<?xml version="1.0"?><Error><Code>ServiceUnavailable</Code></Error>'
    import json
    try:
        packages = json.loads(body).get("packages", [])
    except ValueError:
        packages = []
    root = Element("ListAllMyBucketsResult")
    owner = SubElement(root, "Owner")
    SubElement(owner, "ID").text = "erebus"
    SubElement(owner, "DisplayName").text = "erebus"
    buckets = SubElement(root, "Buckets")
    bucket = SubElement(buckets, "Bucket")
    SubElement(bucket, "Name").text = "packages"
    SubElement(bucket, "CreationDate").text = "2026-01-01T00:00:00Z"
    return 200, tostring(root, encoding="unicode").encode("utf-8")


def s3_list_objects(base: str, token: str | None, prefix: str = "") -> tuple[int, bytes]:
    code, body, _ = erebus_request(base, "GET", "/index.json", token)
    if code != 200:
        return code, b'<?xml version="1.0"?><Error><Code>ServiceUnavailable</Code></Error>'
    import json
    try:
        packages = json.loads(body).get("packages", [])
    except ValueError:
        packages = []
    root = Element("ListBucketResult")
    SubElement(root, "Name").text = "packages"
    SubElement(root, "Prefix").text = prefix or ""
    SubElement(root, "KeyCount").text = str(len(packages))
    SubElement(root, "MaxKeys").text = "1000"
    SubElement(root, "IsTruncated").text = "false"
    contents = SubElement(root, "Contents")
    for pkg in packages:
        obj = SubElement(contents, "Contents")
        SubElement(obj, "Key").text = pkg.get("name", "")
        SubElement(obj, "Size").text = str(pkg.get("size", 0))
        SubElement(obj, "ETag").text = '"' + (pkg.get("sha256", "")[:32]) + '"'
    return 200, tostring(root, encoding="unicode").encode("utf-8")


def s3_get_object(base: str, token: str | None, key: str) -> tuple[int, bytes, dict]:
    path = f"/packages/{urllib.parse.quote(key)}"
    code, body, headers = erebus_request(base, "GET", path, token)
    if code != 200:
        return code, b'', headers
    resp_headers = {
        "Content-Type": "application/octet-stream",
        "ETag": '"' + hashlib.sha256(body).hexdigest()[:32] + '"',
        "Content-Length": str(len(body)),
    }
    return 200, body, resp_headers


def s3_put_object(base: str, token: str | None, key: str, data: bytes) -> tuple[int, bytes]:
    if not SAFE_KEY.match(key or ""):
        return 400, b'<?xml version="1.0"?><Error><Code>InvalidRequest</Code></Error>'
    boundary = "boundary_erebus"
    headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{urllib.parse.quote(key)}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + data + f"\r\n--{boundary}--\r\n".encode()
    path = f"/packages/{urllib.parse.quote(key)}"
    code, resp_body, _ = erebus_request(base, "POST", path, token, data=body,
                                        content_type=f"multipart/form-data; boundary={boundary}")
    if code in (200, 201):
        return 200, b'<?xml version="1.0"?><PutObjectResult><ETag>"' + hashlib.sha256(data).hexdigest()[:32].encode() + b'"</ETag></PutObjectResult>'
    return code, b'<?xml version="1.0"?><Error><Code>UploadFailed</Code></Error>'


class S3Handler(BaseHTTPRequestHandler):
    server_version = "erebus-s3-frontend/0.5"
    erebus_base: str = "http://127.0.0.1:8080"
    token: str | None = None

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _auth_token(self) -> str | None:
        return parse_s3_auth(dict(self.headers))

    def _send_xml(self, code: int, body: bytes):
        self.send_response(code)
        self.send_header("Content-Type", "application/xml")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        token = self._auth_token()
        qs = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(qs)
        key = urllib.parse.unquote(urllib.parse.urlparse(self.path).path.lstrip("/"))

        if "list-type" in params:
            prefix = params.get("prefix", [""])[0]
            code, body = s3_list_objects(self.erebus_base, token, prefix)
            return self._send_xml(code, body)

        if key:
            code, body, hdrs = s3_get_object(self.erebus_base, token, key)
            self.send_response(code)
            for k, v in hdrs.items():
                if k.lower() in ("content-type", "content-length", "etag"):
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        code, body = s3_list_buckets(self.erebus_base, token)
        self._send_xml(code, body)

    def do_PUT(self):
        token = self._auth_token()
        key = urllib.parse.unquote(urllib.parse.urlparse(self.path).path.lstrip("/"))
        if not key:
            return self._send_xml(400, b'<?xml version="1.0"?><Error><Code>InvalidRequest</Code></Error>')
        length = int(self.headers.get("Content-Length", 0))
        data = self.rfile.read(min(length, 1 << 30))
        code, body = s3_put_object(self.erebus_base, token, key, data)
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):
        token = self._auth_token()
        key = urllib.parse.unquote(urllib.parse.urlparse(self.path).path.lstrip("/"))
        if not key:
            return self._send_xml(404, b'<?xml version="1.0"?><Error><Code>NotFound</Code></Error>')
        path = f"/packages/{urllib.parse.quote(key)}"
        code, _, hdrs = erebus_request(self.erebus_base, "HEAD", path, token)
        self.send_response(code)
        for k, v in hdrs.items():
            if k.lower() in ("content-length", "etag", "last-modified", "content-type"):
                self.send_header(k, v)
        self.end_headers()

    def do_DELETE(self):
        self._send_xml(501, b'<?xml version="1.0"?><Error><Code>NotImplemented</Code><Message>DeleteObject not implemented in erebus registry</Message></Error>')


def main():
    ap = argparse.ArgumentParser(description="erebus S3-compatible frontend")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("--registry", default="http://127.0.0.1:8080",
                    help="erebus registry base URL")
    ap.add_argument("--token", default=None)
    args = ap.parse_args()
    S3Handler.erebus_base = args.registry.rstrip("/")
    S3Handler.token = args.token
    server = HTTPServer((args.host, args.port), S3Handler)
    print(f"S3 frontend listening on {args.host}:{args.port} -> {args.registry}", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
