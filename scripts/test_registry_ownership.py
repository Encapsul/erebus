#!/usr/bin/env python3
"""Regression tests for registry ownership + admin gating (E6/E7).

Run with: python3 scripts/test_registry_ownership.py
"""

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER = os.path.join(HERE, "registry_server.py")


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def req(method, url, token=None, body=None, ctype="application/json"):
    r = urllib.request.Request(url, method=method)
    if token:
        r.add_header("Authorization", f"Bearer {token}")
    if body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        r.add_header("Content-Type", ctype)
    else:
        data = None
    try:
        with urllib.request.urlopen(r, data=data, timeout=10) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def upload(base, token, filename, payload=b"EREP\x01x"):
    boundary = "XBOUND"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + payload + f"\r\n--{boundary}--\r\n".encode()
    return req(
        "POST", base + f"/packages/{filename}", token=token,
        body=body, ctype=f"multipart/form-data; boundary={boundary}",
    )


def spawn(root, extra_args=(), env_extra=None):
    port = str(free_port())
    env = dict(os.environ)
    for key in ("STRIPE_SECRET_KEY", "STRIPE_WEBHOOK_SECRET"):
        env.pop(key, None)
    if env_extra:
        env.update(env_extra)
    proc = subprocess.Popen(
        [sys.executable, SERVER, "--dir", root, "--port", port, *extra_args],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env,
    )
    base = f"http://127.0.0.1:{port}"
    for _ in range(50):
        try:
            req("GET", base + "/health")
            return proc, base
        except OSError:
            time.sleep(0.1)
    proc.terminate()
    proc.wait()
    raise RuntimeError("registry did not start")


def register(base, username):
    status, body = req(
        "POST", base + "/auth/register",
        body={"username": username, "password": "longpassword123"},
    )
    if status != 200:
        raise RuntimeError(f"register {username}: {status} {body!r}")
    return json.loads(body)["token"]


def main():
    fails = 0

    def check(name, cond):
        nonlocal fails
        print(f"[{'PASS' if cond else 'FAIL'}] {name}")
        if not cond:
            fails += 1

    # E6: a published package belongs to its uploader.
    root = tempfile.mkdtemp(prefix="erebus-own-")
    proc, base = spawn(root)
    try:
        alice = register(base, "alice")
        bob = register(base, "bob")
        check("owner upload -> 200", upload(base, alice, "app.erebus")[0] == 200)
        check("cross-user overwrite -> 403", upload(base, bob, "app.erebus")[0] == 403)
        check("owner re-upload -> 200", upload(base, alice, "app.erebus")[0] == 200)
    finally:
        proc.terminate()
        proc.wait()

    # E6: anon bootstrap closes once the first user registers.
    root = tempfile.mkdtemp(prefix="erebus-anon-")
    proc, base = spawn(root, extra_args=["--allow-anon-uploads"])
    try:
        check("bootstrap anon upload -> 200", upload(base, None, "anon.erebus")[0] == 200)
        register(base, "alice")
        check("anon upload after first user -> 401",
              upload(base, None, "later.erebus")[0] == 401)
    finally:
        proc.terminate()
        proc.wait()

    # E7: admin endpoints are not available to ordinary users.
    root = tempfile.mkdtemp(prefix="erebus-admin-")
    proc, base = spawn(root)
    try:
        alice = register(base, "alice")
        for endpoint in ("/admin/gc", "/admin/scan", "/admin/backup"):
            status, _ = req("GET", base + endpoint, token=alice)
            check(f"non-admin GET {endpoint} -> 403", status == 403)
    finally:
        proc.terminate()
        proc.wait()

    # E7: GC keeps packages whose `<fname>.json` meta exists.
    root = tempfile.mkdtemp(prefix="erebus-gc-")
    proc, base = spawn(root, env_extra={"ERE_ADMIN_USERS": "admin"})
    try:
        admin = register(base, "admin")
        check("admin upload -> 200", upload(base, admin, "app.erebus")[0] == 200)
        status, body = req("GET", base + "/admin/gc", token=admin)
        report = json.loads(body)
        check("admin GET /admin/gc -> 200", status == 200)
        check("GC keeps app.erebus reachable", "app.erebus" not in report["unreachable"])
        status, body = req("GET", base + "/admin/gc?execute=1", token=admin)
        report = json.loads(body)
        check("GC quarantine is empty", status == 200 and not report["quarantined"])
        check("app.erebus still on disk",
              os.path.isfile(os.path.join(root, "packages", "app.erebus")))
    finally:
        proc.terminate()
        proc.wait()

    print("ALL PASS" if fails == 0 else f"{fails} FAILED")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
