#!/usr/bin/env python3
"""Offline auditor kit for an erebus evidence pack.

Inputs: the zip, the bundle (unless embedded), and the operator / log public
keys obtained out of band. No account, no network, no trust in pack contents.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile

PREDICATE = "https://erebus.dev/attestation/execution/v2"


class KitError(Exception):
    pass


def run(cmd, env=None):
    return subprocess.run(cmd, capture_output=True, text=True, env=env, check=False)


def expect(ok, message):
    if not ok:
        raise KitError(message)


def verify_report(erebus, pack, bundle, operator, log):
    cmd = [erebus, "verify-evidence", str(pack), "--json",
           "--operator-key", operator, "--log-key", log]
    if bundle:
        cmd += ["--bundle", str(bundle)]
    out = run(cmd)
    expect(out.returncode == 0, "verify-evidence failed: " + (out.stderr.strip() or out.stdout.strip()))
    try:
        report = json.loads(out.stdout)
    except json.JSONDecodeError as exc:
        raise KitError("verifier did not print JSON: " + str(exc)) from exc
    expect(report.get("verified") is True, "verifier did not report verified=true")
    keys = report.get("keys", {})
    expect(keys.get("operator_pinned") is True, "operator key is not pinned")
    expect(keys.get("registry_pinned") is True, "registry key is not pinned")
    for role in ("operator", "registry"):
        expect(bool(keys.get(role)), f"pack carries no {role} key")
    receipts = report.get("receipts", 0)
    expect(isinstance(receipts, int) and receipts > 0, "pack has no receipts")
    expect(report.get("log_proofs") == receipts,
           f"only {report.get('log_proofs')}/{receipts} log proofs")
    expect(report.get("bundle", {}).get("file_checked") is True,
           "bundle file not checked; pass --bundle or export with --include-bundle")
    return report


def cosign_check(pack, bundle):
    tool = shutil.which("cosign")
    if not tool:
        return "SKIP (cosign not installed)"
    with tempfile.TemporaryDirectory() as tmp:
        with zipfile.ZipFile(pack) as z:
            names = z.namelist()
            envelopes = sorted(n for n in names if n.startswith("dsse/") and n.endswith(".json"))
            pems = sorted(n for n in names if n.startswith("keys/operator/") and n.endswith(".pem"))
            embedded = sorted(n for n in names if n.startswith("bundle/") and not n.endswith("/"))
            if not envelopes or not pems:
                return "SKIP (no DSSE envelope / operator PEM in pack)"
            if bundle:
                blob = str(bundle)
            elif embedded:
                z.extract(embedded[0], tmp)
                blob = os.path.join(tmp, embedded[0])
            else:
                return "SKIP (no bundle file; pass --bundle)"
            for name in [envelopes[0]] + pems:
                z.extract(name, tmp)
            env = dict(os.environ, COSIGN_MAX_ATTACHMENT_SIZE="16GiB")
            detail = "cosign produced no output"
            for pem in pems:
                out = run([tool, "verify-blob-attestation", "--key", os.path.join(tmp, pem),
                           "--signature", os.path.join(tmp, envelopes[0]),
                           "--type", PREDICATE, "--insecure-ignore-tlog", blob], env)
                detail = (out.stdout + out.stderr).strip()
                if out.returncode == 0 and "Verified OK" in detail:
                    return "Verified OK (" + envelopes[0] + ")"
            raise KitError("cosign refused the DSSE envelope: " + detail)


def tsa_check(pack, ca):
    if not ca:
        return "SKIP (pass --tsa-ca to check the TSA CMS signature)"
    tool = shutil.which("openssl")
    if not tool:
        return "SKIP (openssl not installed)"
    with tempfile.TemporaryDirectory() as tmp:
        with zipfile.ZipFile(pack) as z:
            tokens = sorted(n for n in z.namelist()
                            if n.startswith("anchors/") and n.endswith(".tsr"))
            if not tokens:
                return "SKIP (no RFC 3161 anchor in pack)"
            for token in tokens:
                z.extract(token, tmp)
                checkpoint = token[:-4] + ".checkpoint"
                z.extract(checkpoint, tmp)
                out = run([tool, "ts", "-verify", "-in", os.path.join(tmp, token),
                           "-data", os.path.join(tmp, checkpoint), "-CAfile", str(ca)])
                expect(out.returncode == 0,
                       f"TSA verification failed for {token}: {out.stderr.strip()}")
        return f"OK ({len(tokens)} token(s))"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("pack")
    ap.add_argument("--bundle")
    ap.add_argument("--operator-key", required=True)
    ap.add_argument("--log-key", required=True)
    ap.add_argument("--tsa-ca")
    ap.add_argument("--erebus", default=os.environ.get("EREBUS", "erebus"))
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    try:
        report = verify_report(args.erebus, args.pack, args.bundle,
                               args.operator_key, args.log_key)
        cosign = cosign_check(args.pack, args.bundle)
        tsa = tsa_check(args.pack, args.tsa_ca)
    except (KitError, OSError, zipfile.BadZipFile) as exc:
        print(f"AUDIT FAILED: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps({"ok": True, "report": report, "cosign": cosign, "tsa": tsa}, indent=2))
    else:
        print("EREBUS AUDITOR KIT — offline, no account")
        print(f"  pack:      {args.pack}")
        print(f"  receipts:  {report['receipts']}, log proofs: "
              f"{report['log_proofs']}/{report['receipts']}")
        print("  bundle:    file checked")
        print(f"  cosign:    {cosign}")
        print(f"  TSA:       {tsa}")
        print("EVIDENCE PACK OK — confirm the pinned keys out of band")
    return 0


if __name__ == "__main__":
    sys.exit(main())
