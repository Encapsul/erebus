#!/usr/bin/env python3
"""Measure the T2 pilot from evidence, never from self-reported counters."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
import re
import subprocess
import urllib.request
from typing import Any


def load_json(path: pathlib.Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def api(url: str, token: str) -> dict[str, Any]:
    req = urllib.request.Request(
        url, headers={"Authorization": f"Bearer {token}"}
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        return json.load(response)


def receipts(trail: pathlib.Path) -> list[pathlib.Path]:
    return sorted(
        path
        for path in trail.glob("*.json")
        if not path.name.endswith(".proof.json")
    )


def verify_receipt(
    erebus: str,
    receipt: pathlib.Path,
    bundle: pathlib.Path,
    trusted: pathlib.Path,
    log_key: str,
) -> bool:
    cmd = [
        erebus,
        "verify-attest",
        str(receipt),
        "--bundle",
        str(bundle),
        "--trusted-dir",
        str(trusted),
        "--strict",
        "--proof",
        "--log-key",
        log_key,
    ]
    return subprocess.run(cmd, capture_output=True, check=False).returncode == 0


def verify_chain(
    erebus: str, trail: pathlib.Path, bundle: pathlib.Path, trusted: pathlib.Path
) -> bool:
    cmd = [
        erebus,
        "verify-attest",
        "--chain",
        str(trail),
        "--bundle",
        str(bundle),
        "--trusted-dir",
        str(trusted),
    ]
    return subprocess.run(cmd, capture_output=True, check=False).returncode == 0


def timestamp(receipt: pathlib.Path) -> dt.datetime:
    raw = load_json(receipt)["execution"]["attested_at"].replace("Z", "+00:00")
    # Receipts carry nanoseconds; Python < 3.11 parses at most microseconds.
    raw = re.sub(r"(\.\d{6})\d+", r"\1", raw)
    return dt.datetime.fromisoformat(raw)


def build_report(state: pathlib.Path, erebus: str) -> dict[str, Any]:
    trail = state / "receipts"
    items = receipts(trail)
    registry = (state / "registry.url").read_text().strip()
    token = (state / "registry.token").read_text().strip()
    log_key = load_json(state / "registry-key.json")["public_key_hex"]
    machines = api(f"{registry}/machines", token).get("machines", [])
    history = api(f"{registry}/attestations?limit=10000", token)
    proofs = [path.with_name(path.name + ".proof.json") for path in items]
    anchored = sum(
        1 for path in proofs if path.is_file() and load_json(path).get("anchor")
    )
    verified = [
        verify_receipt(
            erebus, path, state / "baguettotron.erebus", state / "trusted", log_key
        )
        for path in items
    ]
    first = min((timestamp(path) for path in items), default=None)
    now = dt.datetime.now(dt.timezone.utc)
    evidence_bytes = sum(
        path.stat().st_size + (proof.stat().st_size if proof.is_file() else 0)
        for path, proof in zip(items, proofs, strict=True)
    )
    return {
        "generated_at": now.isoformat(),
        "pilot_started_at": first.isoformat() if first else None,
        "elapsed_days": (now - first).days if first else 0,
        "enrolled_machines": len(machines),
        "local_receipts": len(items),
        "registry_receipts": history.get("total", 0),
        "verified_receipts": sum(verified),
        "verification_failures": len(verified) - sum(verified),
        "chain_verified": verify_chain(
            erebus, trail, state / "baguettotron.erebus", state / "trusted"
        )
        if items
        else False,
        "proofs_present": sum(path.is_file() for path in proofs),
        "tsa_anchors_present": anchored,
        "evidence_bytes_total": evidence_bytes,
        "evidence_bytes_per_call": round(evidence_bytes / len(items)) if items else 0,
        "t2_complete": len(machines) >= 3
        and bool(first)
        and (now - first).days >= 28
        and len(items) > 0
        and all(verified),
    }


def print_report(report: dict[str, Any]) -> None:
    print("erebus T2 pilot")
    print(f"  machines enrolled:      {report['enrolled_machines']} / 3")
    print(f"  elapsed:                {report['elapsed_days']} / 28 days")
    print(f"  receipts local/registry:{report['local_receipts']} / {report['registry_receipts']}")
    print(f"  strict+proof failures:  {report['verification_failures']}")
    print(f"  TSA-anchored proofs:    {report['tsa_anchors_present']}")
    print(f"  evidence per call:      {report['evidence_bytes_per_call']} bytes")
    print(f"  chain verified:         {report['chain_verified']}")
    print(f"  T2 complete:            {report['t2_complete']}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--state",
        type=pathlib.Path,
        default=pathlib.Path.home() / ".local/share/erebus/pilot",
    )
    parser.add_argument("--erebus", default=os.environ.get("ERE_BIN", "erebus"))
    args = parser.parse_args()
    report = build_report(args.state, args.erebus)
    output = args.state / "pilot-report.json"
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print_report(report)
    print(f"  JSON:                   {output}")


if __name__ == "__main__":
    main()
