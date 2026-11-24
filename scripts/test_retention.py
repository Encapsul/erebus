#!/usr/bin/env python3
"""Logical retention acceptance for the self-hosted trust center.

Run with: python3 scripts/test_retention.py
stdlib only — proves expiry hides receipts without deleting proof bytes.
"""

import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import test_trust_center as tc

SEED = b"trust-center-e2e-seed-32-bytes!!"
PROJECT = "alice/pilot"
FAILS = []


def check(label, condition):
    print(("PASS " if condition else "FAIL ") + label)
    if not condition:
        FAILS.append(label)


def set_policy(base, admin, payload):
    return tc.json_request("POST", base + "/admin/retention", admin, payload)


def ingest_chain(base, api_key, public, count):
    ids, heads = [], []
    head = None
    for index in range(count):
        _, raw, _ = tc.make_receipt(SEED, public, index, head)
        status, body = tc.json_request(
            "POST", base + "/trust/receipts", "tc:" + api_key, raw)
        check(f"ingest receipt {index}", status == 201)
        ids.append(body.get("id", ""))
        head = "sha256:" + hashlib.sha256(raw).hexdigest()
        heads.append(head)
    return ids, heads


def default_and_gating(base, admin, alice):
    status, policy = tc.json_request("GET", base + "/admin/retention", admin)
    check("default policy is no-op", status == 200
          and policy["default_days"] is None and policy["rules"] == []
          and policy["legal_hold"]["receipts"] == [])
    for token, expected in ((alice, 403), (None, 401)):
        status, _ = tc.json_request("GET", base + "/admin/retention", token)
        check(f"GET retention gated ({expected})", status == expected)
    status, _ = set_policy(base, alice, {"default_days": 0})
    check("POST retention requires admin", status == 403)


def expiry_checks(base, admin, alice, api_key, ids, heads, public, link):
    status, policy = set_policy(base, admin, {"default_days": 0})
    check("set zero-day policy", status == 200 and policy["updated_by"] == "admin")
    status, page = tc.json_request("GET", base + "/trust/status")
    check("status hides expired", status == 200 and page["receipts"] == 0
          and page["retention_hidden"] == 4 and page["counts"]["verified"] == 0)
    status, body = tc.json_request(
        "GET", base + "/trust/receipts?project=alice%2Fpilot", alice)
    check("search hides expired", status == 200 and body["total"] == 0)
    status, _ = tc.json_request(
        "GET", base + f"/trust/receipts/{ids[0]}?project=alice%2Fpilot", alice)
    check("direct get hides expired", status == 404)
    status, _ = tc.json_request("GET", link + "&format=json")
    check("share link hides expired", status == 404)
    status, payload = tc.request("GET", link.replace("/verify/", "/public/evidence/"))
    check("public pack hides expired", status == 404)
    status, payload = tc.request(
        "GET", base + "/trust/evidence?project=alice%2Fpilot", alice)
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        names = archive.namelist()
        manifest = json.loads(archive.read("manifest.json"))
    check("export hides expired", status == 200 and manifest["receipts"] == 0
          and not any(n.startswith("receipts/") for n in names))
    status, body = tc.json_request(
        "POST", base + "/trust/receipts", "tc:" + api_key,
        tc.make_receipt(SEED, public, 4, heads[-1])[1])
    check("hidden HEAD keeps chain", status == 201)
    ids.append(body.get("id", ""))
    status, bad = set_policy(base, admin, {"default_days": -1})
    check("invalid policy rejected", status == 400 and "error" in bad)


def hold_checks(base, admin, alice, ids, link):
    payload = {
        "rules": [{"project": PROJECT, "days": 0}],
        "legal_hold": {"receipts": [ids[0]]},
    }
    status, _ = set_policy(base, admin, payload)
    check("receipt legal hold set", status == 200)
    status, body = tc.json_request(
        "GET", base + "/trust/receipts?project=alice%2Fpilot", alice)
    check("hold overrides expiry", status == 200 and body["total"] == 1)
    status, _ = tc.json_request("GET", link + "&format=json")
    check("held share link works", status == 200)
    payload["legal_hold"] = {"projects": [PROJECT]}
    status, _ = set_policy(base, admin, payload)
    check("project legal hold set", status == 200)
    status, body = tc.json_request(
        "GET", base + "/trust/receipts?project=alice%2Fpilot", alice)
    status, page = tc.json_request("GET", base + "/trust/status")
    check("project hold restores all", status == 200 and body["total"] == 5
          and page["receipts"] == 5 and page["retention_hidden"] == 0)


def restore_checks(root, backup, restore_root):
    shutil.copyfile(os.path.join(root, "log.key"),
                    os.path.join(restore_root, "log.key"))
    second, restore_base = tc.spawn(restore_root)
    restore_admin = tc.register(restore_base, "admin")
    status, body = tc.json_request(
        "POST", restore_base + "/admin/restore", restore_admin, backup)
    check("restore with policy", status == 200
          and body["trust_center"]["restored"] == 5
          and body["trust_center"]["retention"] is True)
    status, page = tc.json_request("GET", restore_base + "/trust/status")
    check("restored policy still hides", status == 200
          and page["retention_hidden"] == 5 and page["receipts"] == 0)
    return second


def setup_project(base, alice, public):
    status, body = tc.json_request("POST", base + "/trust/projects", alice, {
        "name": "pilot", "trusted_keys": [public.hex()]})
    check("create project", status == 201 and body["id"] == PROJECT)
    status, body = tc.json_request(
        "POST", base + f"/trust/projects/{PROJECT}/keys", alice,
        {"label": "agent"})
    api_key = body.get("token", "")
    check("create API key", status == 201 and bool(api_key))
    return api_key


def main():
    from erebus_registry.ed25519 import _ed25519_public_key

    root = tempfile.mkdtemp(prefix="erebus-retention-")
    restore_root = tempfile.mkdtemp(prefix="erebus-retention-restore-")
    first = second = None
    public = _ed25519_public_key(SEED)
    try:
        first, base = tc.spawn(root)
        alice = tc.register(base, "alice")
        admin = tc.register(base, "admin")
        api_key = setup_project(base, alice, public)
        ids, heads = ingest_chain(base, api_key, public, 4)
        status, share = tc.json_request(
            "POST", base + f"/trust/receipts/{ids[0]}/share", alice)
        check("share link created", status == 201 and "token=" in share["url"])
        link = share["url"]
        default_and_gating(base, admin, alice)
        expiry_checks(base, admin, alice, api_key, ids, heads, public, link)
        status, backup = tc.json_request("GET", base + "/admin/backup", admin)
        check("backup keeps all bytes", status == 200
              and backup["trust_center"]["kind"] == "erebus-trust-center-backup/1"
              and len(backup["trust_center"]["receipts"]) == 5
              and backup["trust_center"]["retention"]["default_days"] == 0)
        hold_checks(base, admin, alice, ids, link)
        second = restore_checks(root, backup, restore_root)
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
