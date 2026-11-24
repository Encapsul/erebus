#!/usr/bin/env python3
"""Self-hosted trust center acceptance: 1,000 receipts, share link, export, restore.

Run with: python3 scripts/test_trust_center.py
stdlib only — receipts are signed with the registry's own Ed25519 helpers.
"""

import base64
import hashlib
import io
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER = os.path.join(HERE, "registry_server.py")
SEED = b"trust-center-e2e-seed-32-bytes!!"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_V2 = "https://erebus.dev/attestation/execution/v2"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
FAILS = []


def check(label, condition):
    print(("PASS " if condition else "FAIL ") + label)
    if not condition:
        FAILS.append(label)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode()


def pae(payload_type, payload):
    kind = payload_type.encode()
    return (b"DSSEv1 " + str(len(kind)).encode() + b" " + kind
            + b" " + str(len(payload)).encode() + b" " + payload)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def spawn(root, log_key=None, origin="trust-center-e2e"):
    cmd = [sys.executable, SERVER, "--dir", root, "--host", "127.0.0.1",
           "--port", "0", "--anchor-every", "0", "--log-origin", origin]
    if log_key:
        cmd += ["--log-key", log_key]
    env = dict(os.environ, ERE_ADMIN_USERS="admin")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, env=env)
    line = proc.stdout.readline()
    match = re.search(r"127\.0\.0\.1:(\d+)", line)
    if not match:
        proc.terminate()
        raise RuntimeError("registry did not start: " + line)
    return proc, "http://127.0.0.1:" + match.group(1)


def request(method, url, token=None, body=None):
    req = urllib.request.Request(url, method=method)
    if token:
        req.add_header("Authorization", "Bearer " + token)
    data = None
    if body is not None:
        data = body if isinstance(body, bytes) else canonical(body)
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, data=data, timeout=120) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def json_request(method, url, token=None, body=None):
    status, raw = request(method, url, token, body)
    return status, json.loads(raw or b"{}")


def register(base, username):
    status, body = json_request("POST", base + "/auth/register", body={
        "username": username, "password": "pw12345678"})
    if status != 200:
        raise RuntimeError(f"register {username}: {status} {body}")
    return body["token"]


def make_receipt(seed, public, index, previous):
    sys.path.insert(0, HERE)
    from erebus_registry.ed25519 import _ed25519_sign_fast

    fingerprint = "sha256:" + hashlib.sha256(public).hexdigest()
    descriptor = canonical({"kind": "agent", "name": "bulk"})
    subject = hashlib.sha256(descriptor).hexdigest()
    when = datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=index)
    execution = {
        "attested_at": when.isoformat().replace("+00:00", "Z"),
        "machine_id_hash": "sha256:" + "ab" * 32,
        "os": "linux", "arch": "x86_64",
        "input_hash": "sha256:" + hashlib.sha256(f"in{index}".encode()).hexdigest(),
        "output_hash": "sha256:" + hashlib.sha256(f"out{index}".encode()).hexdigest(),
        "exit_code": None, "prev_attestation_hash": previous,
        "request": None, "rootfs_root": None, "machine_id": None,
    }
    artifact = {
        "bundle_hash": "sha256:" + subject, "payload_hash": "sha256:" + subject,
        "metadata_hash": "sha256:" + hashlib.sha256(descriptor).hexdigest(),
        "format_version": 0, "flags": ["agent"],
    }
    statement = {
        "_type": STATEMENT_TYPE, "predicateType": PREDICATE_V2,
        "subject": [
            {"name": "bundle", "digest": {"sha256": subject}},
            {"name": "payload", "digest": {"sha256": subject}},
        ],
        "predicate": {
            "builder": "trust-center-test", "author": None, "license": None,
            "layers": [], "execution": execution,
            "artifact": {"metadata_hash": artifact["metadata_hash"],
                         "format_version": 0, "flags": ["agent"]},
        },
    }
    payload = canonical(statement)
    signature = _ed25519_sign_fast(seed, pae(PAYLOAD_TYPE, payload))
    attestation = {
        "spec_version": "2.0", "attestation_type": "erebus-execution",
        "artifact": artifact, "provenance": statement["predicate"],
        "execution": execution, "statement": statement,
        "signature": {"algorithm": "ed25519", "key_fingerprint": fingerprint,
                      "signature_hex": signature.hex()},
        "envelope": {
            "payloadType": PAYLOAD_TYPE,
            "payload": base64.b64encode(payload).decode(),
            "signatures": [{"keyid": fingerprint,
                            "sig": base64.b64encode(signature).decode()}],
        },
        "machine": None,
    }
    raw = canonical(attestation)
    receipt_id = hashlib.sha256(raw).hexdigest()[:16]
    return receipt_id, raw, artifact["bundle_hash"]


def main():
    root = tempfile.mkdtemp(prefix="erebus-trust-center-")
    restore_root = tempfile.mkdtemp(prefix="erebus-trust-restore-")
    first = second = None
    try:
        first, base = spawn(root)
        alice = register(base, "alice")
        admin_token = register(base, "admin")
        sys.path.insert(0, HERE)
        from erebus_registry.ed25519 import _ed25519_public_key, _ed25519_verify_fast
        public = _ed25519_public_key(SEED)

        status, body = json_request("POST", base + "/trust/projects", alice, {
            "name": "pilot", "trusted_keys": [public.hex()]})
        check("create project -> 201", status == 201 and body["id"] == "alice/pilot")

        status, body = json_request(
            "POST", base + "/trust/projects/alice/pilot/keys", alice, {"label": "agent"})
        check("create API key -> 201", status == 201 and body["token"])
        api_key = body["token"]

        head = None
        last_id = ""
        started = time.time()
        for index in range(1000):
            last_id, raw, bundle = make_receipt(SEED, public, index, head)
            status, payload = json_request(
                "POST", base + "/trust/receipts", "tc:" + api_key, raw)
            if status != 201:
                check(f"ingest receipt {index}", status == 201)
                break
            last_id = payload["id"]
            head = "sha256:" + hashlib.sha256(raw).hexdigest()
        check("1,000 receipts ingested", time.time() - started < 180)

        status, body = json_request("GET", base + "/trust/status")
        check("public status page", status == 200 and body["counts"]["verified"] == 1000)

        status, body = json_request(
            "GET", base + "/trust/receipts?project=alice%2Fpilot&status=verified&limit=5",
            alice)
        check("search by status", status == 200 and body["total"] == 1000
              and len(body["receipts"]) == 5)

        status, body = json_request(
            "GET", base + "/trust/receipts?bundle=" + bundle, "tc:" + api_key)
        check("search by bundle with API key", status == 200 and body["total"] == 1000)

        forged_id, forged, _ = make_receipt(b"other-seed-32-bytes!!!!!!!!!!", public, 1000, head)
        status, _ = json_request("POST", base + "/trust/receipts", "tc:" + api_key, forged)
        check("unsigned key rejected", status == 400 and forged_id != last_id)

        status, body = json_request(
            "POST", base + f"/trust/receipts/{last_id}/share", alice)
        check("share link created", status == 201 and "token=" in body["url"])
        link = body["url"]

        status, body = json_request("GET", link.replace(base, base) + "&format=json")
        check("no-account JSON verification", status == 200 and body["status"] == "verified"
              and body["log_origin"] == "trust-center-e2e")

        status, html_body = request("GET", link)
        check("no-account HTML verification", status == 200
              and b"erebus receipt verification" in html_body)

        status, _ = json_request("GET", base + f"/verify/{last_id}")
        check("link without token -> 404", status == 404)

        status, payload = request("GET", base + "/trust/evidence?project=alice%2Fpilot", alice)
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            names = archive.namelist()
            manifest = json.loads(archive.read("manifest.json"))
        check("project evidence export", status == 200 and manifest["receipts"] == 1000
              and len([n for n in names if n.startswith("receipts/")]) == 1000
              and len([n for n in names if n.startswith("proofs/")]) == 1000)

        status, payload = request("GET", link.split("?")[0].replace("/verify/", "/public/evidence/")
                                  + "?" + link.split("?", 1)[1])
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            names = archive.namelist()
        check("public evidence pack", status == 200
              and len([n for n in names if n.startswith("receipts/")]) == 1)

        status, backup = json_request("GET", base + "/admin/backup", admin_token)
        check("backup includes trust center", status == 200
              and backup["trust_center"]["kind"] == "erebus-trust-center-backup/1"
              and len(backup["trust_center"]["receipts"]) == 1000)

        shutil.copyfile(os.path.join(root, "log.key"), os.path.join(restore_root, "log.key"))
        second, restore_base = spawn(restore_root)
        restore_admin = register(restore_base, "admin")
        status, body = json_request("POST", restore_base + "/admin/restore",
                                    restore_admin, backup)
        check("restore from backup", status == 200 and body["trust_center"]["restored"] == 1000)
        status, body = json_request("GET", restore_base + "/trust/status")
        check("restored receipts verify", status == 200
              and body["counts"]["verified"] == 1000 and body["projects"] == 1)
        status, body = json_request("GET", link.replace(base, restore_base) + "&format=json")
        check("restored share link works", status == 200 and body["status"] == "verified")

        check("fast verifier rejects tampering",
              not _ed25519_verify_fast(public, b"other", b"\x00" * 64))
    finally:
        for proc in (first, second):
            if proc:
                proc.terminate()
                proc.wait()
                rest = proc.stdout.read()
                if "Traceback" in rest:
                    print("SERVER ERRORS:\n" + rest)
        print("ALL PASS" if not FAILS else f"{len(FAILS)} FAILED")
    return 0 if not FAILS else 1


if __name__ == "__main__":
    sys.exit(main())
