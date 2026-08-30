#!/usr/bin/env python3
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER = os.path.join(HERE, "registry_server.py")


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


def upload(url, token=None):
    boundary = "XBOUND"
    body = (f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="artifact.erebus"\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n"
            f"EREP\x01x\r\n"
            f"--{boundary}--\r\n").encode()
    ctype = f"multipart/form-data; boundary={boundary}"
    return req("POST", url + "/packages/artifact.erebus", token=token, body=body, ctype=ctype)


def spawn(extra):
    root = tempfile.mkdtemp(prefix="flc-")
    port = str(9000 + (int(time.time()) % 1000))
    env = dict(os.environ)
    env.pop("STRIPE_SECRET_KEY", None)
    env.pop("STRIPE_WEBHOOK_SECRET", None)
    proc = subprocess.Popen(
        [sys.executable, SERVER, "--dir", root, "--port", port, *extra],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env,
    )
    base = f"http://127.0.0.1:{port}"
    for _ in range(50):
        try:
            req("GET", base + "/health")
            break
        except OSError:
            time.sleep(0.1)
    return proc, base


def main():
    fails = 0
    label = "test_tier3_fail_closed"

    def check(name, cond):
        nonlocal fails
        print(f"[{'PASS' if cond else 'FAIL'}] {label}: {name}")
        if not cond:
            fails += 1

    # 1) DEFAULT = fail-closed: mutation with no token -> 401, zero users
    p, b = spawn([])
    try:
        st, _ = upload(b)
        check("default: anon upload -> 401", st == 401)
        # register still works (first-user bootstrap)
        st, body = req("POST", b + "/auth/register",
                       body={"username": "alice", "password": "alicepass123"})
        check("default: first register -> 200", st == 200 and "token" in json.loads(body))
    finally:
        p.terminate(); p.wait()

    # 2) OPT-IN open: anon upload succeeds
    p, b = spawn(["--allow-anon-uploads"])
    try:
        st, _ = upload(b)
        check("opt-in: anon upload -> 200", st == 200)
    finally:
        p.terminate(); p.wait()

    # 3) require-auth forces closed even with allow-anon
    p, b = spawn(["--require-auth", "--allow-anon-uploads"])
    try:
        st, _ = upload(b)
        check("require-auth overrides allow-anon: 401", st == 401)
    finally:
        p.terminate(); p.wait()

    print(f"{label}: {'ALL PASS' if fails == 0 else str(fails)+' FAILED'}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
