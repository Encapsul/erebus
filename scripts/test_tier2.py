#!/usr/bin/env python3
"""Tier 2 chaos battery: billing, orgs/RBAC, audit trail.

Runs a throwaway registry with a local webhook secret and exercises the
whole entitlement chain — no network calls to Stripe itself (checkout is
asserted to fail closed at 501 without keys; webhooks are simulated with
correctly-signed payloads, which is exactly what Stripe would send).

Usage: python3 scripts/test_tier2.py
"""
import hashlib
import hmac as hmac_mod
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

PORT = int(os.environ.get("TIER2_PORT", "18990"))
BASE = f"http://127.0.0.1:{PORT}"
WHSEC = "whsec_test_local_only"
PASS = []
FAIL = []


def req(method: str, path: str, token: str | None = None,
        body: dict | None = None, headers: dict | None = None):
    r = urllib.request.Request(BASE + path, method=method)
    if token:
        r.add_header("Authorization", f"Bearer {token}")
    for k, v in (headers or {}).items():
        r.add_header(k, v)
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        r.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(r, data=data, timeout=10) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def jbody(raw: bytes) -> dict:
    try:
        return json.loads(raw)
    except ValueError:
        return {}


def check(name: str, cond: bool, detail: str = ""):
    (PASS if cond else FAIL).append(name)
    mark = "PASS" if cond else "FAIL"
    print(f"[{mark}] {name}" + (f"  ({detail})" if detail and not cond else ""))


def signed_webhook(event: dict) -> tuple[int, bytes]:
    ts = str(int(time.time()))
    raw = json.dumps(event).encode()
    sig = hmac_mod.new(WHSEC.encode(), ts.encode() + b"." + raw,
                       hashlib.sha256).hexdigest()
    r = urllib.request.Request(BASE + "/billing/webhook", method="POST",
                               data=raw)
    r.add_header("Content-Type", "application/json")
    r.add_header("Stripe-Signature", f"t={ts},v1={sig}")
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def main() -> int:
    root = tempfile.mkdtemp(prefix="tier2-")
    env = dict(os.environ)
    env.pop("STRIPE_SECRET_KEY", None)  # force 501 path determinism
    proc = subprocess.Popen(
        [sys.executable, os.path.join(os.path.dirname(__file__),
                                      "registry_server.py"),
         "--dir", root, "--port", str(PORT),
         "--stripe-webhook-secret", WHSEC],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env,
    )
    try:
        for _ in range(50):
            try:
                req("GET", "/health")
                break
            except OSError:
                time.sleep(0.1)

        # -- accounts ------------------------------------------------------
        _, raw = req("POST", "/auth/register",
                     body={"username": "alice", "password": "alicepass123"})
        alice = jbody(raw).get("token", "")
        req("POST", "/auth/register",
            body={"username": "bob", "password": "bobpassword123"})
        _, raw = req("POST", "/auth/login",
                     body={"username": "bob", "password": "bobpassword123"})
        bob_tok = ""
        # login returns no token; use register-time shape instead
        _, raw2 = req("POST", "/auth/register",
                      body={"username": "bobb", "password": "bobbpass12345"})
        bob = jbody(raw2).get("token", "")
        _ = bob_tok
        _, raw = req("POST", "/auth/register",
                     body={"username": "carol", "password": "carolpass123"})
        carol = jbody(raw).get("token", "")
        check("accounts created", bool(alice and bob and carol))

        # -- billing status / checkout gating ------------------------------
        code, raw = req("GET", "/billing/status", alice)
        check("status free by default",
              code == 200 and jbody(raw).get("tier") == "free", raw[:120])
        code, raw = req("POST", "/billing/checkout", alice,
                        body={"plan": "pro"})
        check("checkout 501 without stripe key", code == 501, raw[:120])
        code, _ = req("POST", "/billing/checkout", None, body={"plan": "pro"})
        check("checkout requires auth", code == 401)

        # -- webhook signature enforcement ---------------------------------
        code, _ = req("POST", "/billing/webhook", body={"type": "x"})
        check("webhook rejects unsigned body", code == 400)
        ev = {"type": "checkout.session.completed",
              "data": {"object": {"payment_status": "paid",
                                  "metadata": {"user": "alice", "plan": "pro"}}}}
        ts_bad = str(int(time.time()))
        raw_ev = json.dumps(ev).encode()
        bad_sig = "0" * 64
        r = urllib.request.Request(BASE + "/billing/webhook", method="POST",
                                   data=raw_ev)
        r.add_header("Stripe-Signature", f"t={ts_bad},v1={bad_sig}")
        try:
            with urllib.request.urlopen(r, timeout=10) as resp:
                code = resp.status
        except urllib.error.HTTPError as e:
            code = e.code
        check("webhook rejects forged signature", code == 400)

        # -- tier upgrade via correctly-signed event ------------------------
        code, raw = signed_webhook(ev)
        check("signed checkout.completed accepted", code == 200, raw[:120])
        code, raw = req("GET", "/billing/status", alice)
        check("alice upgraded to pro",
              code == 200 and jbody(raw).get("tier") == "pro", raw[:120])

        # -- orgs gated on Team ---------------------------------------------
        code, raw = req("POST", "/orgs", alice, body={"name": "acme-pro"})
        check("org creation refused on pro", code == 400, raw[:120])
        ev_team = {"type": "checkout.session.completed",
                   "data": {"object": {"payment_status": "paid",
                                       "metadata": {"user": "alice",
                                                    "plan": "team"}}}}
        signed_webhook(ev_team)
        code, raw = req("GET", "/billing/status", alice)
        check("alice upgraded to team",
              jbody(raw).get("tier") == "team", raw[:120])
        code, raw = req("POST", "/orgs", alice, body={"name": "acme"})
        check("org created on team", code == 200, raw[:120])

        # -- RBAC -------------------------------------------------------------
        code, raw = req("POST", "/orgs/acme/members", alice,
                        body={"username": "bobb", "role": "developer"})
        check("owner adds developer", code == 200, raw[:120])
        code, raw = req("POST", "/orgs/acme/members", bob,
                        body={"username": "carol", "role": "viewer"})
        check("developer cannot add member", code == 403, raw[:120])
        code, raw = req("DELETE", "/orgs/acme/members/bobb", carol)
        check("outsider cannot remove member", code == 401 or code == 403,
              str(code))
        code, raw = req("DELETE", "/orgs/acme/members/alice", alice)
        check("owner cannot be removed", code == 400, raw[:120])
        code, raw = req("GET", "/orgs/acme", carol)
        check("non-member cannot see org", code == 404, raw[:120])
        code, raw = req("GET", "/orgs/acme", bob)
        check("member sees org",
              code == 200 and jbody(raw).get("your_role") == "developer",
              raw[:120])

        # -- org publish / private pull ---------------------------------------
        blob = b"\x00erebus-fake-payload" * 100
        files = {"file": ("orgpkg.erebus", blob)}
        boundary = "XxTier2BoundaryxX"
        mp = (f"--{boundary}\r\n"
              f'Content-Disposition: form-data; name="file"; '
              f'filename="orgpkg.erebus"\r\n'
              f"Content-Type: application/octet-stream\r\n\r\n"
              ).encode() + blob + f"\r\n--{boundary}--\r\n".encode()
        r = urllib.request.Request(BASE + "/packages/orgpkg.erebus",
                                   method="POST", data=mp)
        r.add_header("Authorization", f"Bearer {bob}")
        r.add_header("Content-Type",
                     f'multipart/form-data; boundary={boundary}')
        r.add_header("X-Erebus-Org", "acme")
        try:
            with urllib.request.urlopen(r, timeout=10) as resp:
                code = resp.status
        except urllib.error.HTTPError as e:
            code = e.code
        check("developer publishes to org", code == 200, str(code))

        code, _ = req("GET", "/packages/orgpkg.erebus", carol)
        check("outsider denied private org package", code == 401, str(code))
        code, raw = req("GET", "/packages/orgpkg.erebus", bob)
        check("org member pulls private package", code == 200, str(code))
        code, raw = req("GET", "/packages/orgpkg.erebus", alice)
        check("owner pulls private org package", code == 200, str(code))

        # viewer role can read but not publish
        req("POST", "/orgs/acme/members", alice,
            body={"username": "carol", "role": "viewer"})
        code, _ = req("GET", "/packages/orgpkg.erebus", carol)
        check("viewer can now pull", code == 200, str(code))

        # -- audit download ------------------------------------------------------
        month = time.strftime("%Y-%m")
        code, raw = req("GET", f"/audit/download?month={month}", carol)
        check("audit download gated on team", code == 402, str(code))
        code, raw = req("GET", f"/audit/download?month={month}", alice)
        lines = [json.loads(x) for x in raw.decode().splitlines() if x.strip()]
        actions = {l.get("action") for l in lines}
        check("personal audit has own actions", code == 200
              and all(l.get("actor") == "alice" and "org" not in l
                      for l in lines), str(actions))
        check("personal audit excludes org-tagged lines",
              not any(l.get("action") == "publish" for l in lines), "")
        code, raw = req("GET", f"/audit/download?month={month}&org=acme", bob)
        check("developer cannot pull org trail", code == 403, str(code))
        code, raw = req("GET", f"/audit/download?month={month}&org=acme", alice)
        olines = [json.loads(x) for x in raw.decode().splitlines()
                  if x.strip()]
        check("org trail shows org events",
              code == 200 and any(l.get("action") == "publish" for l in olines)
              and any(l.get("action") == "private_download" for l in olines),
              str({l.get("action") for l in olines}))
        code, _ = req("GET", "/audit/download?month=../../etc", alice)
        check("month traversal rejected", code == 400, str(code))

        # -- downgrade via subscription deletion ---------------------------------
        ev_del = {"type": "customer.subscription.deleted",
                  "data": {"object": {"metadata": {"user": "alice"}}}}
        signed_webhook(ev_del)
        code, raw = req("GET", "/billing/status", alice)
        check("downgrade to free on subscription.deleted",
              jbody(raw).get("tier") == "free", raw[:120])
    finally:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    print(f"\n{'=' * 50}\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("FAILED:", ", ".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
