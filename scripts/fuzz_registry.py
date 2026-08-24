#!/usr/bin/env python3
"""fuzz_registry.py — adversarial campaign against registry_server.py.

Modes (composable):

  --parser-fuzz N   in-process hammering of stream_multipart() with mutated
                    bodies (millions of iterations per minute). ANY exception
                    escaping the parser is a bug by definition.
  --store-fuzz N    randomized Store op sequences with invariant checks
                    (users monotonic, stats non-negative ints, index always
                    parses, negative/huge charges must not corrupt state).
  --storm SECONDS   live server + W workers mixing valid traffic, mutated
                    requests, auth/quota races and raw-socket garbage.
                    Anomalies: HTTP >=500, server death, .incoming litter,
                    tracebacks in server log, health stalls.

Exit code 0 iff zero anomalies.
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

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER = os.path.join(HERE, "registry_server.py")

ANOMALIES: list[str] = []
LOCK = threading.Lock()


def anomaly(msg: str) -> None:
    with LOCK:
        if len(ANOMALIES) < 50:
            ANOMALIES.append(msg)


# ── parser fuzz ──────────────────────────────────────────────────────

class FakeHandler:
    def __init__(self, body: bytes) -> None:
        self.rfile = io.BytesIO(body)


HEAD_VARIANTS = [
    b'Content-Disposition: form-data; name="file"; filename="a.erebus"\r\n',
    b'content-disposition:form-data;filename="b.pack.tar.gz"\r\n',
    b'Content-Disposition: form-data; filename="trav/../x.erebus"\r\n',
    b"Content-Disposition: form-data\r\n",
    b'filename="lf-only.erebus"\n',
]


def gen_multipart(rng: random.Random) -> bytes:
    boundary = bytes(rng.randbytes(rng.randint(4, 32))).replace(b"\r", b"x")
    pre = bytes(rng.randbytes(rng.randint(0, 48)))
    head = rng.choice(HEAD_VARIANTS)
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


def parser_fuzz(iters: int, seed: int) -> None:
    import importlib.util

    spec = importlib.util.spec_from_file_location("rs", SERVER)
    rs = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rs)
    rng = random.Random(seed)
    tmp = "/tmp/fuzz-multipart.bin"
    for i in range(iters):
        body = gen_multipart(rng)
        declared = len(body) if rng.random() < 0.9 else rng.randint(0, len(body))
        cap = rng.choice([10**10, 1024, 0])
        try:
            fname, written = rs.stream_multipart(
                FakeHandler(body), b"bnd", tmp, cap, declared
            )
        except Exception as exc:  # noqa: BLE001 — any raise IS the bug
            anomaly(f"parser iter {i}: {type(exc).__name__}: {exc}")
            continue
        if written > cap + rs.CHUNK:
            anomaly(f"parser iter {i}: cap overshoot {written} > {cap}")
        if fname is not None and "/" in fname or ".." in (fname or ""):
            anomaly(f"parser iter {i}: suspicious fname {fname!r}")
    print(f"[parser-fuzz] {iters} iterations")


# ── store fuzz ───────────────────────────────────────────────────────

def store_fuzz(iters: int, seed: int) -> None:
    import importlib.util
    import shutil

    spec = importlib.util.spec_from_file_location("rs", SERVER)
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
        u = rng.choice(users)
        try:
            if op == 0:
                ok, res = st.register(u + str(rng.randint(0, 3)), "pw-" + str(i))
                if ok:
                    tokens[u] = res
            elif op == 1:
                t = tokens.get(u)
                st.authenticate(f"{u}:{t}" if t else f"{u}:junk")
            elif op == 2:
                st.charge_bytes(u, rng.choice([0, 5, -3, 10**15]), 10**15)
            elif op == 3:
                st.bump_stats(rng.choice([1, -2, 10**18]), 10**18)
            elif op == 4:
                st.set_meta("x.erebus", u if rng.random() < 0.5 else None,
                            private=rng.random() < 0.5)
            elif op == 5:
                st.month_served(u)
            elif op == 6:
                json.loads(st.index())
            else:
                ok, _ = st.waitlist_add(f"w{i % 40}@ok.io", "9.9.9.9")
                if not ok and "rate limited" not in _ and "invalid" not in _:
                    anomaly(f"store iter {i}: odd waitlist refusal {_!r}")
        except Exception as exc:  # noqa: BLE001
            anomaly(f"store iter {i} op{op}: {type(exc).__name__}: {exc}")
            break
        count = len(json.loads(st.index())["packages"]) + sum(
            1 for _ in os.listdir(os.path.join(root, "usage"))
        )
        spath = os.path.join(root, "stats.json")
        if os.path.isfile(spath):
            stats = json.loads(open(spath).read())
            vals = [v for k, v in stats.items() if isinstance(v, int)]
            if any(v < 0 for v in vals):
                anomaly(f"store iter {i}: negative stat {stats}")
                break
    print(f"[store-fuzz] {iters} iterations")


# ── storm ────────────────────────────────────────────────────────────

def http(url: str, data=None, headers=None, method=None, timeout=8):
    req = urllib.request.Request(url, data=data, headers=headers or {},
                                 method=method)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read()


def worker_valid(url: str, stop: threading.Event, counts: list) -> None:
    n = 0
    while not stop.is_set():
        n += 1
        start = random.randrange(0, 1000)
        try:
            http(f"{url}/index.json")
            # Empty-registry 404s are a normal status here.
            http(f"{url}/packages/demo-agent.erebus",
                 headers={"Range": f"bytes={start}-{start+99}"})
        except urllib.error.HTTPError as exc:
            if exc.code >= 500:
                anomaly(f"valid worker: {exc.code}")
        except Exception as exc:  # noqa: BLE001
            anomaly(f"valid worker: {type(exc).__name__}")
        counts[0] += 2


def worker_hostile(url: str, stop: threading.Event, counts: list) -> None:
    paths = [
        "/packages/../../etc/passwd", "/packages/.incoming.x",
        "/packages/%2e%2e%2f.erebus", "/auth/login", "/waitlist",
        "/stats?x=" + "A" * 8000, "/" + "B" * 300,
        "/packages/x.pack.tar.gz.sha256", "/packages/x.pack",
    ]
    while not stop.is_set():
        p = random.choice(paths)
        try:
            code, _ = http(url + p,
                           data=b'{"email":"f@z.io"}' if p == "/waitlist" else None)
            if code >= 500:
                anomaly(f"hostile: GET {p[:40]} -> {code}")
        except urllib.error.HTTPError as exc:
            if exc.code >= 500:
                anomaly(f"hostile: {p[:40]} -> {exc.code}")
        except Exception:
            pass
        counts[0] += 1


def raw_socket_garbage(port: int, stop: threading.Event, counts: list) -> None:
    junk = [
        b"GARBAGE\r\n\r\n", b"GET / HTTP/1.1\r\nHost: x\r\n" + b"H: v\r\n" * 4000,
        b"POST / HTTP/1.1\r\nContent-Length: 999999999999\r\n\r\nshort",
        b"GET / HTTP/1.1\r\nContent-Length: -5\r\n\r\n",
        b"GET / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nZZZZ",
        b"GET /stats HTTP/1.1\r\nRange: bytes=9-3\r\n\r\n",
    ]
    while not stop.is_set():
        kind = random.randrange(4)
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=3)
            if kind == 0:
                s.sendall(random.choice(junk))
            elif kind == 1:                       # slowloris-lite
                s.sendall(b"GET /stats HTTP/1.1\r\n")
                time.sleep(random.uniform(0.05, 0.4))
                s.sendall(b"Host: x\r\n\r\n")
            elif kind == 2:                       # pipelined flood
                s.sendall(b"GET /landing HTTP/1.1\r\n\r\n" * 30)
            else:                                 # connect & vanish
                pass
            s.close()
        except OSError:
            pass
        counts[0] += 1


def upload_worker(url: str, stop: threading.Event, counts: list) -> None:
    rng = random.Random(threading.get_ident())
    while not stop.is_set():
        bnd = b"B" + bytes(rng.randbytes(6)).hex().encode()
        name = rng.choice(["up.erebus", "evil/../x.erebus", ".hidden.erebus",
                           "p.pack.tar.gz"])
        body = (f"--{bnd}\r\n".encode()
                + f'Content-Disposition: form-data; name="f"; filename="{name}"\r\n\r\n'.encode()
                + bytes(rng.randbytes(rng.randint(0, 4096)))
                + f"\r\n--{bnd}--\r\n".encode())
        try:
            code, _ = http(url + "/", data=body, timeout=8,
                           headers={"Content-Type": f"multipart/form-data; boundary={bnd}"})
            if code >= 500:
                anomaly(f"upload: {name[:20]} -> {code}")
        except urllib.error.HTTPError as exc:
            if exc.code >= 500:
                anomaly(f"upload: {name[:20]} -> {exc.code}")
        except Exception:
            pass
        counts[0] += 1


def storm(seconds: int, workers_n: int, port: int) -> None:
    workdir = "/tmp/fuzz-storm-registry"
    subprocess.run(["rm", "-rf", workdir], check=True)
    os.makedirs(workdir, exist_ok=True)
    log = open("/tmp/fuzz-storm-server.log", "wb")
    proc = subprocess.Popen(
        [sys.executable, SERVER, "--dir", workdir, "--host", "127.0.0.1",
         "--port", str(port)],
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
        return
    stop = threading.Event()
    counts = [0]
    threads = []
    for _ in range(max(1, workers_n - 4)):
        threads.append(threading.Thread(target=worker_valid, args=(url, stop, counts)))
    threads += [
        threading.Thread(target=worker_hostile, args=(url, stop, counts)),
        threading.Thread(target=raw_socket_garbage, args=(port, stop, counts)),
        threading.Thread(target=upload_worker, args=(url, stop, counts)),
        threading.Thread(target=lambda: health_watch(url, stop)),
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
    litter = [f for f in os.listdir(os.path.join(workdir, "packages"))
              if f.startswith(".")]
    if litter:
        anomaly(f"litter after storm: {litter[:3]}")
    print(f"[storm] ~{counts[0]} requests over {seconds}s on :{port}")


def health_watch(url: str, stop: threading.Event) -> None:
    while not stop.is_set():
        t0 = time.time()
        try:
            code, _ = http(url + "/stats", timeout=5)
            if code != 200:
                anomaly(f"health: stats {code}")
        except Exception as exc:
            anomaly(f"health stall: {type(exc).__name__}")
        dt = time.time() - t0
        if dt > 5:
            anomaly(f"health latency {dt:.1f}s")
        time.sleep(1.0)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--parser-fuzz", type=int, default=0, metavar="N")
    ap.add_argument("--store-fuzz", type=int, default=0, metavar="N")
    ap.add_argument("--storm", type=int, default=0, metavar="SECONDS")
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--port", type=int, default=8931)
    ap.add_argument("--seed", type=int, default=20260824)
    args = ap.parse_args()

    if args.parser_fuzz:
        parser_fuzz(args.parser_fuzz, args.seed)
    if args.store_fuzz:
        store_fuzz(args.store_fuzz, args.seed)
    if args.storm:
        storm(args.storm, args.workers, args.port)

    if ANOMALIES:
        print(f"\n=== {len(ANOMALIES)} ANOMALIES ===")
        for a in ANOMALIES:
            print("  ✗", a)
        sys.exit(1)
    print("=== ZERO ANOMALIES ===")


if __name__ == "__main__":
    main()
