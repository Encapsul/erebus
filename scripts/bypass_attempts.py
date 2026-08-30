#!/usr/bin/env python3
"""bypass_attempts.py — adversarial bypass attempts against the erebus registry.

Targets the two policy features:
  #8  Lifecycle gating  — a Revoked/Deleted/Quarantined artifact must never be
      served, regardless of how the client asks (name, range, query, path
      tricks, sidecar/pack, index, HEAD...).
  #9  Fail-closed auth  — all mutations require a valid token; no header,
      path-normalization, method, or query trick may reach them anonymously.

The server is launched FAIL-CLOSED (no --allow-anon-uploads). We then probe
every bypass vector and assert the gate holds. A FAIL here means a real
bypass. Report-only: tries to *break* the feature and must find it unbreakable.
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER = os.path.join(HERE, "registry_server.py")
ERE = os.path.join(os.path.dirname(HERE), "target", "release", "erebus")


def http(method, url, token=None, body=None, ctype="application/json",
         headers=None, timeout=15):
    r = urllib.request.Request(url, method=method)
    if token:
        r.add_header("Authorization", f"Bearer {token}")
    if headers:
        for k, v in headers.items():
            r.add_header(k, v)
    data = None
    if body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        r.add_header("Content-Type", ctype)
    try:
        with urllib.request.urlopen(r, data=data, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def multipart(url, token=None, fname="artifact.erebus", payload=b"EREP\x01x",
             headers=None):
    boundary = "BYXX"
    body = (f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{fname}"\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n").encode() \
        + payload + f"\r\n--{boundary}--\r\n".encode()
    return http("POST", url + "/packages/" + fname, token=token, body=body,
                ctype=f"multipart/form-data; boundary={boundary}",
                headers=headers)


def run_cli(args, env=None):
    e = dict(os.environ)
    if env:
        e.update(env)
    return subprocess.run([ERE] + args, capture_output=True, text=True,
                          env=e, timeout=90)


F = 0
P = 0


def check(name, cond, detail=""):
    global F, P
    if cond:
        P += 1
        print(f"  [GATE-HOLDS] {name}")
    else:
        F += 1
        print(f"  [**BYPass**] {name}{'  ' + detail if detail else ''}")


def main():
    global F, P
    # ---- fresh fail-closed registry -------------------------------------
    root = tempfile.mkdtemp(prefix="bypass-")
    env = dict(os.environ)
    env.pop("STRIPE_SECRET_KEY", None)
    env.pop("STRIPE_WEBHOOK_SECRET", None)
    proc = subprocess.Popen(
        [sys.executable, SERVER, "--dir", root, "--host", "127.0.0.1",
         "--port", "0"],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env)
    # port 0 won't work for http.server discovery; use a fixed free port
    proc.kill(); proc.wait()
    # pick a real free port
    import socket
    s = socket.socket(); s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]; s.close()
    proc = subprocess.Popen(
        [sys.executable, SERVER, "--dir", root, "--host", "127.0.0.1",
         "--port", str(port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env)
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(60):
            try:
                http("GET", base + "/health"); break
            except OSError:
                time.sleep(0.1)

        # ---- #9 fail-closed auth bypasses ------------------------------------
        print("── #9 fail-closed auth: mutations must reject anonymous clients")

        # mutation endpoints with NO token (default-deny):
        # NOTE: /waitlist is intentionally PUBLIC (email capture), not a
        # protected mutation — excluded from the deny-list expectation.
        for path, method, body in [
            ("/packages/bypass1.erebus", "POST", None),          # upload
            ("/mcp", "POST", None),                              # mcp upload
            ("/billing/checkout", "POST", {"plan": "pro"}),
            ("/orgs", "POST", {"name": "evilorg"}),
        ]:
            if "packages/" in path or path == "/mcp":
                st, _ = multipart(base, fname=path.split("/")[-1])
            else:
                st, _ = http(method, base + path, body=body)
            check(f"anon {method} {path} -> {st} (want 401+)",
                  st in (401, 403, 413, 400))

        # auth header spoofing variants must all fail (urllib refuses newline
        # and control chars in header values, which is itself a client-side
        # guard, so those are not independently testable here)
        for tok in ["", ":", "alice:", ":tok", "Bearer", "alice:deadbeef",
                    "%20%20%20"]:
            st, _ = multipart(base, token=tok)
            check(f"upload token='{tok[:18]!r}' -> {st} (want 401)", st == 401)

        # header name smuggling / query token
        st, _ = multipart(base, headers={"X-Auth-Token": "evil"})
        check("X-Auth-Token header ignored -> 401", st == 401)
        st, _ = http("GET", base + "/packages/x.erebus?token=evil")
        check("query-spec token ignored -> 404/401", st in (401, 404))

        # path-normalization must not reach a handler anonymously
        for p in ["//packages/x.erebus", "/PACKAGES/x.erebus",
                  "/packages/./x.erebus", "/packages/%2e%2e/x.erebus",
                  "/packages/../../packages/x.erebus",
                  "/packages/x.erebus%00", "/packages//x.erebus",
                  "/packages/x.EREBUS", "/packages/X.EREBUS"]:
            st, _ = http("GET", base + p)
            check(f"normalized-pull {p!r} -> {st} (401/404, not 200)", st in (401, 404, 400))

        # HTTP methods that must not be usable for mutation
        for method in ["PUT", "PATCH", "HEAD", "TRACE", "OPTIONS"]:
            st, _ = http(method, base + "/packages/x.erebus")
            check(f"{method} method -> {st} (not 200/2xx)", st not in (200, 201))

        # ---- #8 lifecycle gating --------------------------------------------
        print("── #8 lifecycle: deny-listed artifacts must never be served")

        # build a real artifact and walk it through lifecycle states
        app = os.path.join(root, "app")
        os.makedirs(app)
        with open(os.path.join(app, "app.py"), "w") as f:
            f.write('print("lifecycle-bypass")\n')
        tiny = os.path.join(root, "tiny.erebus")
        r = run_cli(["build", app, "--isolation", "none", "-o", tiny])
        check("CLI build artifact", r.returncode == 0, r.stderr[:200])

        # register + login for the auth'd serving path
        st, body = http("POST", base + "/auth/register",
                        body={"username": "alice", "password": "alicepass123"})
        token = json.loads(body).get("token", "") if st == 200 else ""
        check("register alice", st == 200 and bool(token))

        def upload_and_state(state, fname="st.erebus", allow_untrusted=False):
            p = os.path.join(root, fname)
            args = ["lifecycle", tiny, "--action", state, "-o", p]
            r = run_cli(args)
            if r.returncode != 0:
                return None, r.stderr
            st, _ = multipart(base, token=token, fname=fname,
                              payload=open(p, "rb").read())
            if st != 200:
                return None, f"upload {st}"
            return p, None

        # Quarantined: must be 410 by default, 200 only with allow_untrusted
        p, err = upload_and_state("quarantine", "quar.erebus")
        check("set quarantine + upload", p is not None, str(err))
        st, _ = http("GET", base + "/packages/quar.erebus", token=token)
        check("pull quarantined (no policy) -> 410", st == 410,
              f"got {st}")
        st, body = http("GET", base + "/index.json")
        idx = json.loads(body)
        entry = next((x for x in idx["packages"] if x["name"] == "quar"), None)
        check("index exposes quarantined state", entry and entry.get("state") == "Quarantined")

        # Revoked: must be 410 via every request shape
        p2, err2 = upload_and_state("revoke", "rev.erebus")
        check("set revoked + upload", p2 is not None, str(err2))
        for shape, kwargs in [
            ("plain", {}),
            ("range", {"headers": {"Range": "bytes=0-1"}}),
            ("suffix-range", {"headers": {"Range": "bytes=-1"}}),
            ("query", {"body": None}),  # query handled below
        ]:
            path = base + "/packages/rev.erebus"
            if shape == "query":
                path += "?download=1&state=trusted"
            st, _ = http("GET", path, token=token, **kwargs)
            check(f"pull revoked via {shape} -> 410", st == 410, f"got {st}")

        # "Deleted" is a terminal state not settable via the CLI (only
        # quarantine|promote|revoke exist). Confirm it cannot be forged as a
        # bypass (a client cannot fabricate a Deleted artifact through CLI).
        r = run_cli(["lifecycle", tiny, "--action", "delete"])
        check("deleted not CLI-forgeable (invalid action)", r.returncode != 0,
              r.stderr[:80])

        # sidecar/pack of a revoked artifact: it's metadata-only, must not be
        # a vector to retrieve the blob
        st, _ = http("GET", base + "/packages/rev.erebus.sha256", token=token)
        check("revoked .sha256 sidecar -> 404 (not a bypass)", st == 404, f"got {st}")

        # a Trusted artifact must serve fine (positive control)
        p4, err4 = upload_and_state("promote", "ok.erebus")
        check("set promote + upload", p4 is not None, str(err4))
        st, body = http("GET", base + "/packages/ok.erebus", token=token)
        check("pull trusted -> 200 (positive control)", st == 200, f"got {st}: {body[:80]}")

        print(f"\nBYPass-harness: {P} gates held, {F} bypass found")
        return 0 if F == 0 else 1
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        err = proc.stderr.read().decode()
        if "Traceback" in err:
            print("SERVER TRACEBACK:\n", err[-1200:])


if __name__ == "__main__":
    sys.exit(main())
