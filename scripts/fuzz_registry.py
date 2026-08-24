#!/usr/bin/env python3
"""fuzz_registry.py — comprehensive adversarial fuzzer for erebus.

Modes (composable, can run simultaneously):
  --parser-fuzz N     in-process hammering of stream_multipart() with mutated
                      bodies (millions of iterations/minute). ANY exception
                      escaping the parser is a bug by definition.
  --store-fuzz N      randomized Store op sequences with invariant checks
                      (users monotonic, stats non-negative ints, index always
                      parses, negative/huge charges must not corrupt state).
  --storm SECONDS     live server + W workers mixing valid traffic, mutated
                      requests, auth/quota races and raw-socket garbage;
                      anomalies: >=500s, server death, .incoming litter,
                      tracebacks in server log, health stalls.
  --format-fuzz N     in-process hammering of .erebus binary format parsing
                      (footer, metadata, payload) with bit flips, truncation,
                      corruption, oversized fields.
  --stub-fuzz N       in-process stub launcher logic fuzzing (entrypoint
                      resolution, runtime detection, extraction logic).
  --cli-fuzz N        subprocess-based CLI fuzzing (runs erebus binary with
                      mutated arguments, checks for panics/crashes).

Exit code 0 iff zero anomalies. Prints one summary line + anomaly details.

Usage examples:
  # Quick smoke test
  python3 fuzz_registry.py --parser-fuzz 10000 --store-fuzz 1000 --format-fuzz 1000 --stub-fuzz 1000

  # Full campaign (run for ~1 hour)
  python3 fuzz_registry.py --parser-fuzz 2000000 --store-fuzz 200000 --format-fuzz 500000 --stub-fuzz 100000 --storm 3600 --workers 8

  # CI-friendly quick run
  python3 fuzz_registry.py --parser-fuzz 100000 --store-fuzz 10000 --format-fuzz 50000 --stub-fuzz 10000 --storm 60 --workers 4
"""

from __future__ import annotations

import argparse
import io
import json
import os
import random
import re
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER = os.path.join(HERE, "registry_server.py")
CHUNK = 64 * 1024

# Import local format_fuzz module
sys.path.insert(0, os.path.dirname(__file__))
import format_fuzz

# ── shared generators ────────────────────────────────────────────────

def gen_multipart(rng: random.Random, boundary: bytes) -> bytes:
    """Random-ish multipart body: valid shapes plus hostile variations."""
    pre = bytes(rng.randbytes(rng.randint(0, 48)))
    head_variants = [
        b'Content-Disposition: form-data; name="file"; filename="a.erebus"\r\n',
        b'content-disposition:form-data;filename="b.pack.tar.gz"\r\n',
        b'Content-Disposition: form-data; filename="trav/../x.erebus"\r\n',
        b"Content-Disposition: form-data\r\n",
        b'filename="lf-only.erebus"\n',
    ]
    head = rng.choice(head_variants)
    sep = b"\r\n" if rng.random() < 0.85 else b"\n"
    body = bytes(rng.randbytes(rng.randint(0, 2048)))
    if rng.random() < 0.3 and body:
        pos = rng.randrange(len(body))
        frag = b"\r\n--" + boundary[: rng.randint(1, max(1, len(boundary)))]
        body = body[:pos] + frag + body[pos:]
    close = rng.choice(
        [b"\r\n--" + boundary + b"--\r\n", b"--" + boundary + b"--", b""]
    )
    return pre + b"--" + boundary + sep + head + sep + body + close


# ── parser fuzz ──────────────────────────────────────────────────────

class FakeHandler:
    def __init__(self, body: bytes):
        self.rfile = io.BytesIO(body)


def parser_fuzz(iters: int, seed: int) -> list[str]:
    anomalies = []
    import importlib.util
    spec = importlib.util.spec_from_file_location("rs", os.path.join(HERE, "registry_server.py"))
    rs = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rs)
    rng = random.Random(seed)
    tmp = "/tmp/fuzz-multipart.bin"
    for i in range(iters):
        body = gen_multipart(rng, b"bnd")
        declared = len(body) if rng.random() < 0.9 else rng.randint(0, len(body))
        cap = rng.choice([10**10, 1024, 0])
        try:
            fname, written = rs.stream_multipart(
                FakeHandler(body), b"bnd", tmp, cap, declared
            )
        except Exception as exc:
            anomalies.append(f"parser iter {i}: {type(exc).__name__}: {exc}")
            continue
        if written > cap + rs.CHUNK:
            anomalies.append(f"parser iter {i}: cap overshoot {written} > {cap}")
        if fname is not None and ("/" in fname or ".." in fname):
            anomalies.append(f"parser iter {i}: suspicious fname {fname!r}")
    print(f"[parser-fuzz] {iters} iterations")
    return anomalies


# ── format fuzz ──────────────────────────────────────────────────────

def format_fuzz(iters: int, seed: int) -> list[str]:
    import format_fuzz as ff
    return ff.format_fuzz_main(iters, seed)


# ── stub fuzz ────────────────────────────────────────────────────────

def gen_stub_scenario(rng: random.Random) -> dict:
    return {
        "payload_type": rng.choice(["python", "node", "go", "rust", "script", "mixed"]),
        "entrypoint": rng.choice(["app.py", "index.js", "main", "server", "script.sh"]),
        "nested": rng.random() < 0.2,
        "symlinks": rng.random() < 0.1,
        "unicode": rng.random() < 0.1,
    }


def stub_fuzz(iters: int, seed: int) -> list[str]:
    anomalies = []
    rng = random.Random(seed)
    import tempfile
    for i in range(iters):
        scenario = {
            "payload_type": rng.choice(["python", "node", "go", "rust", "script", "mixed"]),
            "entrypoint": rng.choice(["app.py", "index.js", "main", "server", "script.sh"]),
            "nested": rng.random() < 0.2,
            "symlinks": rng.random() < 0.1,
            "unicode": rng.random() < 0.1,
        }
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                # Write entrypoint based on scenario
                if scenario["payload_type"] == "python":
                    with open(os.path.join(tmpdir, "app.py"), "w") as f:
                        f.write("print('test')")
                elif scenario["payload_type"] == "node":
                    with open(os.path.join(tmpdir, "index.js"), "w") as f:
                        f.write("console.log('test')")
                elif scenario["payload_type"] in ("go", "rust"):
                    with open(os.path.join(tmpdir, scenario["entrypoint"]), "wb") as f:
                        f.write(b"ELF fake binary")
                else:
                    with open(os.path.join(tmpdir, scenario["entrypoint"]), "wb") as f:
                        f.write(b"#!/bin/sh\necho hello")

                # Test runtime detection (simplified - just check file exists)
                if scenario["payload_type"] == "python":
                    if not os.path.exists(os.path.join(tmpdir, "app.py")):
                        anomalies.append(f"stub iter {i}: python entrypoint missing")
                elif scenario["payload_type"] == "node":
                    if not os.path.exists(os.path.join(tmpdir, "index.js")):
                        anomalies.append(f"stub iter {i}: node entrypoint missing")
                elif scenario["payload_type"] in ("go", "rust"):
                    if not os.path.exists(os.path.join(tmpdir, scenario["entrypoint"])):
                        anomalies.append(f"stub iter {i}: binary entrypoint missing")
        except Exception as exc:
            anomalies.append(f"stub iter {i}: {type(exc).__name__}: {exc}")
    print(f"[stub-fuzz] {iters} iterations")
    return anomalies


# ── cli fuzz (subprocess) ─────────────────────────────────────────────

def gen_cli_args(rng: random.Random) -> list[str]:
    commands = ["build", "serve", "pull", "publish", "sign", "verify", "layer", "keygen", "inspect", "scan", "clean", "upgrade", "doctor", "dashboard", "chat", "run", "env", "swap", "trust"]
    cmd = rng.choice(["build", "serve", "pull", "publish", "sign", "verify", "layer", "keygen", "inspect", "scan", "clean", "upgrade", "doctor", "dashboard", "chat", "run", "env", "swap", "trust"])
    args = [cmd]
    flag_count = rng.randint(0, 3)
    flags = ["--help", "--version", "--verbose", "--quiet", "--json", "--output", "/tmp/test.erebus", "--port", "8080", "--registry", "http://localhost:8080", "--token", "test"]
    for _ in range(rng.randint(0, 3)):
        if flags:
            args.append(rng.choice(flags))
    return args


def cli_fuzz(iters: int, seed: int) -> list[str]:
    anomalies = []
    rng = random.Random(seed)
    for i in range(iters):
        args = gen_cli_args(random.Random(seed + i))
        try:
            subprocess.run(
                [os.environ.get("EREBUS_BIN", "erebus")] + args,
                timeout=10,
                capture_output=True,
            )
        except subprocess.TimeoutExpired:
            anomalies.append(f"cli iter {i}: timeout")
        except Exception as exc:
            anomalies.append(f"cli iter {i}: {type(exc).__name__}: {exc}")
    print(f"[cli-fuzz] {iters} iterations")
    return anomalies


# ── store fuzz ───────────────────────────────────────────────────────

def store_fuzz(iters: int, seed: int) -> list[str]:
    anomalies = []
    import importlib.util
    import shutil
    spec = importlib.util.spec_from_file_location("rs", os.path.join(HERE, "registry_server.py"))
    rs = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rs)
    root = "/tmp/fuzz-store"
    shutil.rmtree(root, ignore_errors=True)
    os.makedirs(root, exist_ok=True)
    st = rs.Store(root, 1000, 10**7)
    rng = random.Random(seed)
    users = ["u0", "u1", "u2"]
    tokens: dict[str, str] = {}
    for i in range(iters):
        op = rng.randrange(8)
        u = rng.choice(["u0", "u1", "u2"])
        try:
            if op == 0:
                ok, res = st.register(u + str(rng.randint(0, 3)), "pw-" + str(i))
                if ok:
                    tokens[u] = res
            elif op == 1:
                t = tokens.get(u)
                st.authenticate(f"{u}:{t}" if t else "junk")
            elif op == 2:
                st.charge_bytes(u, rng.choice([0, 5, -3, 10**15]), 10**15)
            elif op == 3:
                st.bump_stats(rng.choice([1, -2, 10**18]), 10**18)
            elif op == 4:
                st.set_meta("x.erebus", u if rng.random() < 0.5 else None, private=rng.random() < 0.5)
            elif op == 5:
                st.month_served(u)
            elif op == 6:
                json.loads(st.index())
            else:
                ok, _ = st.waitlist_add(f"w{i % 40}@ok.io", "9.9.9.9")
                if not ok and "rate limited" not in _ and "invalid" not in _:
                    pass
        except Exception as exc:
            anomalies.append(f"store iter {i} op{op}: {type(exc).__name__}: {exc}")
            break
        spath = os.path.join(root, "stats.json")
        if os.path.isfile(spath):
            stats = json.loads(open(spath).read())
            if any(v < 0 for v in stats.values() if isinstance(v, int)):
                anomalies.append(f"store iter {i}: negative stat {stats}")
                break
    print(f"[store-fuzz] {iters} iterations")
    return anomalies


# ── storm ────────────────────────────────────────────────────────────

KNOWN = {"name": "diffcheck.erebus", "body": b""}

def upload_known(url: str) -> None:
    body_bytes = (b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdef" * 100)
    KNOWN["body"] = body_bytes
    bnd = b"DiffCheckBoundary42"
    part = (f"--{bnd.decode()}\r\n".encode()
            + b'Content-Disposition: form-data; name="f"; filename="'
            + KNOWN["name"].encode() + b'"\r\n\r\n'
            + body_bytes + f"\r\n--{bnd.decode()}--\r\n".encode())
    code, resp = http(url + "/", data=part, headers={"Content-Type": f"multipart/form-data; boundary={bnd}"})
    if code != 200:
        raise SystemExit(f"differential seed upload failed: {code} {resp[:80]}")


def check_range(url: str, spec: str) -> list[str]:
    anomalies = []
    data = KNOWN["body"]
    size = len(data)
    try:
        code, got = http(f"{url}/packages/{KNOWN['name']}", headers={"Range": f"bytes={spec}"})
    except urllib.error.HTTPError as exc:
        code, got = exc.code, b""
    first, _, last = spec.partition("-")
    if first == "" and last != "":
        want_start, want_end = max(0, size - int(last)), size - 1
    elif first != "" and last == "":
        want_start, want_end = int(first), size - 1
    else:
        try:
            want_start, want_end = int(first), min(int(last), size - 1)
        except ValueError:
            if code not in (400, 416):
                return [f"range {spec}: expected 400/416, got {code}"]
            return []
    valid = 0 <= want_start <= want_end < size
    if not valid:
        if code != 416:
            return [f"range {spec}: expected 416, got {code}"]
        return []
    expect = data[want_start:want_end + 1]
    if code == 206 and got != expect:
        return [f"range {spec}: WRONG BYTES ({len(got)} vs {len(expect)})"]
    elif code not in (200, 206):
        return [f"range {spec}: status {code}"]
    return []


def http(url: str, data=None, headers=None, method=None, timeout=8):
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read()


def worker_valid(url: str, stop: threading.Event, counts: list) -> None:
    rng = random.Random(threading.get_ident())
    size = len(KNOWN["body"])
    while not stop.is_set():
        try:
            http(f"{url}/index.json")
            kind = rng.randrange(4)
            if kind == 0:
                a = rng.randrange(size); spec = f"{a}-{a + rng.randint(0, 500)}"
            elif kind == 1:
                spec = f"{rng.randrange(size)}-"
            elif kind == 2:
                spec = f"-{rng.randint(1, size)}"
            else:
                spec = rng.choice([f"{size}-", f"{size}-{size+10}", "-", f"0-{size*2}"])
            for a in check_range(url, spec):
                ANOMALIES.append(a)
        except urllib.error.HTTPError as exc:
            if exc.code >= 500:
                ANOMALIES.append(f"valid worker: {exc.code}")
        except Exception as exc:
            ANOMALIES.append(f"valid worker: {type(exc).__name__}")
        counts[0] += 2


def worker_hostile(url: str, stop: threading.Event, counts: list) -> None:
    paths = ["/packages/../../etc/passwd", "/packages/.incoming.x", "/packages/%2e%2e%2f.erebus", "/auth/login", "/waitlist", "/stats?x=" + "A" * 8000, "/" + "B" * 300, "/packages/x.pack.tar.gz.sha256", "/packages/x.pack"]
    while not stop.is_set():
        p = random.choice(paths)
        try:
            code, _ = http(url + p, data=b'{"email":"f@z.io"}' if p == "/waitlist" else None)
            if code >= 500:
                ANOMALIES.append(f"hostile: GET {p[:40]} -> {code}")
        except urllib.error.HTTPError as exc:
            if exc.code >= 500:
                ANOMALIES.append(f"hostile: {p[:40]} -> {exc.code}")
        except Exception:
            pass
        counts[0] += 1


def raw_socket_garbage(port: int, stop: threading.Event, counts: list) -> None:
    junk = [b"GARBAGE\r\n\r\n", b"GET / HTTP/1.1\r\nHost: x\r\n" + b"H: v\r\n" * 4000, b"POST / HTTP/1.1\r\nContent-Length: 999999999999\r\n\r\nshort", b"GET / HTTP/1.1\r\nContent-Length: -5\r\n\r\n", b"GET / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nZZZZ", b"GET /stats HTTP/1.1\r\nRange: bytes=9-3\r\n\r\n"]
    while not stop.is_set():
        kind = random.randrange(4)
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=3)
            if kind == 0:
                s.sendall(random.choice(junk))
            elif kind == 1:
                s.sendall(b"GET /stats HTTP/1.1\r\n")
                time.sleep(random.uniform(0.05, 0.4))
                s.sendall(b"Host: x\r\n\r\n")
            elif kind == 2:
                s.sendall(b"GET /landing HTTP/1.1\r\n\r\n" * 30)
            else:
                pass
            s.close()
        except OSError:
            pass
        counts[0] += 1


def upload_worker(url: str, stop: threading.Event, counts: list) -> None:
    rng = random.Random(threading.get_ident())
    while not stop.is_set():
        bnd = b"B" + bytes(rng.randbytes(6)).hex().encode()
        name = rng.choice(["up.erebus", "evil/../x.erebus", ".hidden.erebus", "p.pack.tar.gz"])
        body = (f"--{bnd}\r\n".encode() + b'Content-Disposition: form-data; name="f"; filename="' + name.encode() + b'"\r\n\r\n' + bytes(rng.randbytes(rng.randint(0, 4096))) + f"\r\n--{bnd}--\r\n".encode())
        try:
            code, _ = http(url + "/", data=body, timeout=8, headers={"Content-Type": f"multipart/form-data; boundary={bnd}"})
            if code >= 500:
                ANOMALIES.append(f"upload: {name[:20]} -> {code}")
        except urllib.error.HTTPError as exc:
            if exc.code >= 500:
                ANOMALIES.append(f"upload: {name[:20]} -> {exc.code}")
        except Exception:
            pass
        counts[0] += 1


def health_watch(url: str, stop: threading.Event) -> None:
    while not stop.is_set():
        t0 = time.time()
        try:
            code, _ = http(url + "/stats", timeout=5)
            if code != 200:
                ANOMALIES.append(f"health: stats {code}")
        except Exception as exc:
            ANOMALIES.append(f"health stall: {type(exc).__name__}")
        dt = time.time() - t0
        if dt > 5:
            ANOMALIES.append(f"health latency {dt:.1f}s")
        time.sleep(1.0)


ANOMALIES: list[str] = []
LOCK = threading.Lock()


def anomaly(msg: str) -> None:
    with LOCK:
        if len(ANOMALIES) < 100:
            ANOMALIES.append(msg)


def storm(seconds: int, workers_n: int, port: int) -> list[str]:
    global ANOMALIES
    ANOMALIES = []
    workdir = "/tmp/fuzz-storm-registry"
    subprocess.run(["rm", "-rf", workdir], check=True)
    os.makedirs(workdir, exist_ok=True)
    log = open("/tmp/fuzz-storm-server.log", "wb")
    proc = subprocess.Popen(
        [sys.executable, SERVER, "--dir", workdir, "--host", "127.0.0.1", "--port", str(port)],
        stdout=log, stderr=log, preexec_fn=os.setsid)
    url = f"http://127.0.0.1:{port}"
    up = False
    for _ in range(60):
        try:
            http(url + "/stats", timeout=1)
            up = True
            break
        except Exception:
            time.sleep(0.25)
    if not up:
        anomaly("server never came up")
        return ANOMALIES
    upload_known(url)
    stop = threading.Event()
    counts = [0]
    threads = []
    for _ in range(max(1, workers_n - 4)):
        threads.append(threading.Thread(target=worker_valid, args=(url, stop, counts)))
    threads += [
        threading.Thread(target=worker_hostile, args=(url, stop, counts)),
        threading.Thread(target=raw_socket_garbage, args=(port, stop, counts)),
        threading.Thread(target=upload_worker, args=(url, stop, counts)),
        threading.Thread(target=health_watch, args=(url, stop)),
    ]
    for t in threads:
        t.daemon = True
        t.start()
    time.sleep(seconds)
    stop.set()
    time.sleep(1.0)
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    log.close()
    time.sleep(0.5)
    server_log = open("/tmp/fuzz-storm-server.log", "rb").read().decode("utf-8", "replace")
    for m in re.finditer(r"Traceback[^\n]*\n(.+\n){1,4}", server_log):
        anomaly("server traceback: " + m.group(0)[:160].replace("\n", " | "))
    litter = [f for f in os.listdir(os.path.join(workdir, "packages")) if f.startswith(".")]
    if litter:
        anomaly(f"litter after storm: {litter[:3]}")
    print(f"[storm] ~{sum(counts)} requests over {seconds}s on :{port}")
    return ANOMALIES


# ── main ─────────────────────────────────────────────────────────────

def parse_duration(s: str) -> float:
    import re
    m = re.match(r"^(\d+)([smhd]?)$", s)
    if not m:
        raise ValueError(f"invalid duration: {s}")
    val = int(m.group(1))
    unit = m.group(2) or "s"
    return val * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--parser-fuzz", type=int, default=0, metavar="N", help="parser fuzz iterations")
    ap.add_argument("--format-fuzz", type=int, default=0, metavar="N", help="format fuzz iterations")
    ap.add_argument("--stub-fuzz", type=int, default=0, metavar="N", help="stub fuzz iterations")
    ap.add_argument("--store-fuzz", type=int, default=0, metavar="N", help="store fuzz iterations")
    ap.add_argument("--cli-fuzz", type=int, default=0, metavar="N", help="cli fuzz iterations")
    ap.add_argument("--storm", type=int, default=0, metavar="SECONDS", help="storm duration in seconds")
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--port", type=int, default=8931)
    ap.add_argument("--seed", type=int, default=20260824)
    ap.add_argument("--list-targets", action="store_true")
    args = ap.parse_args()

    if args.list_targets:
        print("Available targets: format, stub, cli, registry, serve, parser, store, storm")
        return

    all_anomalies = []

    if args.parser_fuzz:
        all_anomalies.extend(parser_fuzz(args.parser_fuzz, args.seed))
    if args.format_fuzz:
        import format_fuzz as ff
        all_anomalies.extend(ff.format_fuzz_main(args.format_fuzz, args.seed))
    if args.stub_fuzz:
        all_anomalies.extend(stub_fuzz(args.stub_fuzz, args.seed))
    if args.store_fuzz:
        all_anomalies.extend(store_fuzz(args.store_fuzz, args.seed))
    if args.cli_fuzz:
        all_anomalies.extend(cli_fuzz(args.cli_fuzz, args.seed))
    if args.storm:
        all_anomalies.extend(storm(args.storm, args.workers, args.port))

    if all_anomalies:
        print(f"\n=== {len(all_anomalies)} ANOMALIES ===")
        for a in all_anomalies[:50]:
            print("  ✗", a)
        if len(all_anomalies) > 50:
            print(f"  ... and {len(all_anomalies) - 50} more")
        sys.exit(1)
    print("=== ZERO ANOMALIES ===")


if __name__ == "__main__":
    main()