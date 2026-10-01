#!/usr/bin/env python3
"""Transparency-log battery for registry_server.py (ROADMAP P0-5).

Pure stdlib. Starts a throwaway registry, publishes receipts and checks:
  * Merkle primitives against the RFC 9162 test vectors (byte-compatible
    with erebus-core/src/merkle.rs),
  * Ed25519 checkpoint signatures (pure-Python signer ↔ pure-Python verifier),
  * inclusion + consistency proofs served over HTTP, idempotent re-posts,
  * RFC 3161 anchoring against a local fake TSA,
  * crash consistency: SIGKILL during concurrent publishes → restart → every
    stored leaf still has a valid inclusion proof under the new head.

Usage: python3 scripts/test_transparency_log.py
"""
import hashlib
import importlib.util
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER = os.path.join(HERE, "registry_server.py")
PASS: list[str] = []
FAIL: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    (PASS if cond else FAIL).append(name)
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail and not cond else ""))


def load_module():
    spec = importlib.util.spec_from_file_location("registry_server", SERVER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def req(base: str, method: str, path: str, token: str | None = None,
        body: bytes | dict | None = None):
    r = urllib.request.Request(base + path, method=method)
    if token:
        r.add_header("Authorization", f"Bearer {token}")
    data = None
    if body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        r.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(r, data=data, timeout=10) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except ValueError:
            return e.code, {}


def wait_up(base: str, proc: subprocess.Popen, timeout: float = 15.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            raise SystemExit(f"registry exited early with {proc.returncode}")
        try:
            status, _ = req(base, "GET", "/health")
            if status == 200:
                return
        except (urllib.error.URLError, ConnectionError, socket.timeout):
            pass
        time.sleep(0.1)
    raise SystemExit("registry never became healthy")


def fake_receipt(n: int) -> bytes:
    """Minimal document shaped like an erebus receipt (server validates shape)."""
    doc = {
        "spec_version": "1.2",
        "attestation_type": "erebus-execution",
        "artifact": {"bundle_hash": "sha256:" + "ab" * 32, "payload_hash": "sha256:" + "cd" * 32},
        "execution": {"machine_id_hash": "sha256:" + "ef" * 32, "os": "linux",
                      "arch": "x86_64", "attested_at": f"2026-09-17T10:00:{n:02d}Z"},
        "signature": {"algorithm": "ed25519", "key_fingerprint": "sha256:" + "01" * 32,
                      "signature_hex": f"{n:02x}" * 64},
        "statement": {"_type": "https://in-toto.io/Statement/v1", "subject": []},
    }
    return json.dumps(doc, indent=2).encode()


# --------------------------------------------------------------------------
# 1. Primitives
# --------------------------------------------------------------------------
def test_primitives(mod) -> None:
    raw = [b"", b"\x00", b"\x10", b"\x20\x21", b"\x30\x31", b"\x40\x41\x42\x43",
           b"\x50\x51\x52\x53\x54\x55\x56\x57",
           bytes(range(0x60, 0x70))]
    leaves = [mod._mt_leaf(d) for d in raw]
    roots = [
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
        "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
        "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
        "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
        "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
        "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
    ]
    check("merkle: RFC 9162 roots", all(mod._mt_root(leaves[:n]).hex() == roots[n] for n in range(9)))
    check("merkle: PATH(0, D[8]) vector",
          [p.hex() for p in mod._mt_inclusion(leaves, 0)] == [
              "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
              "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
              "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4"])
    check("merkle: PROOF(6, D[8]) vector",
          [p.hex() for p in mod._mt_consistency(leaves, 6)] == [
              "0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
              "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
              "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7"])
    ok = True
    for size in range(1, 9):
        root = mod._mt_root(leaves[:size])
        for i in range(size):
            ok &= mod._mt_verify_inclusion(leaves[i], i, size, mod._mt_inclusion(leaves[:size], i), root)
            ok &= not mod._mt_verify_inclusion(leaves[i], i, size, mod._mt_inclusion(leaves[:size], i), b"\x42" * 32)
    check("merkle: inclusion verifies for every leaf/size", ok)

    seed = hashlib.sha256(b"test seed").digest()
    pub = mod._ed25519_public_key(seed)
    msg = b"erebus-log-checkpoint/v1\norigin\n3\nabc\n2026\n"
    sig = mod._ed25519_sign(seed, msg)
    check("ed25519: sign→verify", mod._ed25519_verify(pub, msg, sig))
    check("ed25519: tampered message rejected", not mod._ed25519_verify(pub, msg + b"x", sig))
    # RFC 8032 §7.1 test 1: empty message.
    seed1 = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    pub1 = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    sig1 = ("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    check("ed25519: RFC 8032 vector 1", mod._ed25519_public_key(seed1).hex() == pub1
          and mod._ed25519_sign(seed1, b"").hex() == sig1)

    digest = hashlib.sha256(b"checkpoint").digest()
    tsq = mod.tsa_build_request(digest, nonce=0x1234)
    check("tsa: request is DER with imprint", tsq[0] == 0x30 and digest in tsq and tsq.endswith(b"\x01\x01\xff"))


# --------------------------------------------------------------------------
# 2. Fake RFC 3161 TSA
# --------------------------------------------------------------------------
class FakeTsa(BaseHTTPRequestHandler):
    """Answers every query with a structurally valid TimeStampResp whose
    TSTInfo echoes the imprint. Not cryptographically signed — the registry
    only checks structure; full CMS validation is `openssl ts -verify`."""
    mod = None
    seen: list[bytes] = []

    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        query = self.rfile.read(n)
        FakeTsa.seen.append(query)
        m = self.mod
        # imprint OCTET STRING sits right after the AlgorithmIdentifier
        pos = query.find(m._TSA_SHA256_ALGID) + len(m._TSA_SHA256_ALGID)
        digest = query[pos + 2:pos + 34]
        gen_time = m._der(0x18, b"20260917120000Z")
        tst_info = m._der(0x30, m._der_int(1) + m._der(0x06, b"\x2a\x03\x04")
                          + m._der(0x30, m._TSA_SHA256_ALGID + m._der(0x04, digest))
                          + m._der_int(42) + gen_time)
        content = m._der(0x30, m._der(0x06, bytes.fromhex("2a864886f70d010702"))
                         + m._der(0xA0, m._der(0x30, m._der(0x04, tst_info))))
        status = m._der(0x30, m._der_int(0))
        resp = m._der(0x30, status + content)
        self.send_response(200)
        self.send_header("Content-Type", "application/timestamp-reply")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)


def start_fake_tsa(mod) -> str:
    FakeTsa.mod = mod
    srv = HTTPServer(("127.0.0.1", 0), FakeTsa)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{srv.server_address[1]}/tsr"


# --------------------------------------------------------------------------
# 3. HTTP battery
# --------------------------------------------------------------------------
def start_registry(root: str, port: int, tsa_url: str, extra: list[str] | None = None):
    cmd = [sys.executable, SERVER, "--dir", root, "--port", str(port), "--tsa-url", tsa_url,
           "--anchor-every", "0", "--log-origin", "test-origin"] + (extra or [])
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def test_http(mod, root: str, tsa_url: str) -> str:
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    proc = start_registry(root, port, tsa_url)
    try:
        wait_up(base, proc)
        status, body = req(base, "POST", "/auth/register", body={"username": "alice", "password": "pw12345678"})
        check("auth: register", status == 200, str(body))
        token = body.get("token", "")

        status, key = req(base, "GET", "/log/key")
        check("log: /log/key public", status == 200 and len(key.get("public_key_hex", "")) == 64)
        pub = bytes.fromhex(key["public_key_hex"])

        receipts = [fake_receipt(i) for i in range(3)]
        positions = []
        for i, body_bytes in enumerate(receipts):
            status, body = req(base, "POST", "/attestations", token, body_bytes)
            check(f"log: publish #{i} → 201", status == 201, str(body))
            pos = body.get("log") or {}
            positions.append(pos)
            leaf = mod._mt_leaf(body_bytes)
            check(f"log: leaf #{i} = sha256(0x00‖body)", pos.get("leaf_hash") == "sha256:" + leaf.hex())
            check(f"log: leaf #{i} index/size", pos.get("leaf_index") == i and pos.get("tree_size") == i + 1)
            root = bytes.fromhex(pos["root"].removeprefix("sha256:"))
            proof = [bytes.fromhex(p) for p in pos["inclusion_proof"]]
            check(f"log: inclusion #{i} verifies", mod._mt_verify_inclusion(leaf, i, i + 1, proof, root))
            cp = pos["checkpoint"]
            msg = (f"erebus-log-checkpoint/v1\n{cp['origin']}\n{cp['size']}\n"
                   f"{root.hex()}\n{cp['timestamp']}\n").encode()
            check(f"log: checkpoint #{i} signed by log key",
                  cp["origin"] == "test-origin" and cp["root"] == pos["root"]
                  and mod._ed25519_verify(pub, msg, bytes.fromhex(cp["signature_hex"])))

        # Idempotent re-post: same leaf, 200, fresh checkpoint of size 3.
        status, body = req(base, "POST", "/attestations", token, receipts[1])
        check("log: re-post is idempotent", status == 200 and body.get("recorded") is False
              and body["log"]["leaf_index"] == 1 and body["log"]["tree_size"] == 3)

        # Proof for an old size + consistency to head.
        leaf0 = positions[0]["leaf_hash"]
        status, body = req(base, "GET", f"/log/proof?leaf={leaf0}&size=1")
        check("log: historical proof carries consistency_to_head",
              status == 200 and body.get("checkpoint") is None
              and body["consistency_to_head"]["first"] == 1 and body["consistency_to_head"]["second"] == 3)
        status, body = req(base, "GET", f"/log/proof?leaf={leaf0}")
        check("log: current proof against signed head", status == 200 and body["checkpoint"]["size"] == 3)
        status, body = req(base, "GET", "/log/proof?leaf=" + "00" * 32)
        check("log: unknown leaf → 404", status == 404)
        status, body = req(base, "GET", "/log/consistency?from=2&to=3")
        check("log: consistency endpoint", status == 200 and len(body["consistency_proof"]) >= 1)
        status, body = req(base, "GET", "/log/consistency?from=0&to=3")
        check("log: consistency rejects from=0", status == 400)

        # Anchoring at the fake TSA.
        status, body = req(base, "POST", "/log/anchor")
        check("log: anchor requires auth", status == 401)
        status, body = req(base, "POST", "/log/anchor", token)
        check("log: anchor → 201 with token", status == 201 and body["anchor"]["size"] == 3
              and body["anchor"]["gen_time"] == "20260917120000Z", str(body))
        check("tsa: registry sent a DER query", len(FakeTsa.seen) >= 1 and FakeTsa.seen[-1][0] == 0x30)
        status, body = req(base, "GET", "/log/checkpoint")
        check("log: checkpoint exposes anchor", status == 200 and body["anchor"]["size"] == 3
              and body["checkpoint"]["size"] == 3)
        status, body = req(base, "GET", f"/log/proof?leaf={leaf0}")
        check("log: proof at anchored size carries the anchor", body.get("anchor", {}) and body["anchor"]["size"] == 3)

        # Personal trail still works, now from SQLite.
        status, body = req(base, "GET", "/attestations", token)
        check("attestations: query from sqlite", status == 200 and body["total"] == 3
              and body["records"][0]["leaf_index"] == 0)

        # Machine enrollment: certificate signed by the log key, canonical
        # bytes identical to erebus-core/src/machine.rs.
        seed = b"\x05" * 32
        mpub = mod._ed25519_public_key(seed).hex()
        status, body = req(base, "POST", "/machines/enroll", body={"public_key_hex": mpub})
        check("enroll: requires auth", status == 401)
        status, body = req(base, "POST", "/machines/enroll", token,
                           body={"public_key_hex": mpub, "os": "linux", "arch": "x86_64"})
        cert = body.get("certificate", {})
        check("enroll: 201 with certificate", status == 201 and cert.get("owner") == "alice", str(body))
        mid = "sha256:" + hashlib.sha256(bytes.fromhex(mpub)).hexdigest()
        cbytes = (f"erebus-machine-cert/v1\n{mid}\n{mpub}\nalice\n{cert.get('registry')}\n"
                  f"{cert.get('issued_at')}\n").encode()
        check("enroll: machine_id = sha256(pubkey)", cert.get("machine_id") == mid)
        check("enroll: certificate signed by log key",
              cert.get("registry_key_id") == key["key_id"]
              and mod._ed25519_verify(pub, cbytes, bytes.fromhex(cert.get("signature_hex", "00"))))
        status, body2 = req(base, "POST", "/machines/enroll", token, body={"public_key_hex": mpub})
        check("enroll: re-enroll is idempotent (200, same cert)",
              status == 200 and body2.get("certificate") == cert)
        status, body = req(base, "POST", "/machines/enroll", token, body={"public_key_hex": "zz"})
        check("enroll: garbage key → 400", status == 400)
        status, body = req(base, "POST", "/auth/register", body={"username": "bob", "password": "pw12345678"})
        bob = body.get("token", "")
        status, body = req(base, "POST", "/machines/enroll", bob, body={"public_key_hex": mpub})
        check("enroll: another user cannot claim the key → 409", status == 409)
        status, body = req(base, "GET", "/machines", token)
        check("enroll: owner lists the machine",
              status == 200 and [m["machine_id"] for m in body.get("machines", [])] == [mid])
        return token
    finally:
        proc.kill()
        proc.wait()


# --------------------------------------------------------------------------
# 4. Chaos: SIGKILL mid-publish
# --------------------------------------------------------------------------
def test_crash_consistency(mod, root: str, tsa_url: str, token: str) -> None:
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    proc = start_registry(root, port, tsa_url)
    wait_up(base, proc)

    accepted: list[bytes] = []
    lock = threading.Lock()
    stop = threading.Event()

    def publisher(worker: int):
        n = 0
        while not stop.is_set():
            doc = fake_receipt(10 + worker * 100 + n)
            try:
                status, body = req(base, "POST", "/attestations", token, doc)
                if status in (200, 201):
                    with lock:
                        accepted.append(doc)
            except Exception:
                break
            n += 1

    threads = [threading.Thread(target=publisher, args=(w,)) for w in range(4)]
    for t in threads:
        t.start()
    # Kill once at least one publish is acknowledged — a fixed sleep races
    # with machine load and can fire before any publish lands.
    deadline = time.monotonic() + 10
    while not accepted and time.monotonic() < deadline:
        time.sleep(0.02)
    os.kill(proc.pid, signal.SIGKILL)
    proc.wait()
    stop.set()
    for t in threads:
        t.join()
    check("chaos: some publishes landed before SIGKILL", len(accepted) > 0, str(len(accepted)))

    # Restart on the same directory: the log must contain every acknowledged
    # leaf (durability) and every stored leaf must prove into the new head.
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    proc = start_registry(root, port, tsa_url)
    try:
        wait_up(base, proc)
        status, head = req(base, "GET", "/log/checkpoint")
        size = head["checkpoint"]["size"]
        root_hash = bytes.fromhex(head["checkpoint"]["root"].removeprefix("sha256:"))
        check("chaos: restart yields a checkpoint ≥ 3 + acknowledged", size >= 3 + len(accepted), f"size={size}")
        ok = True
        for doc in accepted:
            leaf = mod._mt_leaf(doc)
            status, body = req(base, "GET", f"/log/proof?leaf={leaf.hex()}")
            if status != 200:
                ok = False
                continue
            proof = [bytes.fromhex(p) for p in body["inclusion_proof"]]
            ok &= mod._mt_verify_inclusion(leaf, body["leaf_index"], size, proof, root_hash)
        check("chaos: every acknowledged leaf proves into the new head", ok)
        status, body = req(base, "GET", f"/log/consistency?from=3&to={size}")
        check("chaos: old head (size 3) consistent with new head", status == 200
              and body["second_root"] == head["checkpoint"]["root"])
    finally:
        proc.kill()
        proc.wait()


def test_cached_tree(mod) -> None:
    """The O(log n) tree must emit the reference functions' bytes exactly."""
    leaves = [mod._mt_leaf(i.to_bytes(4, "big")) for i in range(300)]
    tree = mod._MerkleTree([])
    same_root = same_path = same_cons = True
    for n in range(1, len(leaves) + 1):
        tree.append(leaves[n - 1])
        same_root &= tree.root() == mod._mt_root(leaves[:n])
        for i in {0, n // 3, n // 2, n - 1}:
            same_path &= tree.inclusion(i, 0, n) == mod._mt_inclusion(leaves[:n], i)
        for m in {1, n // 4 or 1, n // 2 or 1, n - 1 or 1, n}:
            same_cons &= tree.consistency(m, 0, n) == mod._mt_consistency(leaves[:n], m)
    check("merkle cache: roots equal reference for sizes 1..300", same_root)
    check("merkle cache: inclusion proofs equal reference", same_path)
    check("merkle cache: consistency proofs equal reference", same_cons)
    check("merkle cache: leaf index lookup", tree.index[leaves[257]] == 257)

    big = mod._MerkleTree([hashlib.sha256(i.to_bytes(8, "big")).digest() for i in range(200_000)])
    big.root()  # warm-up, O(n) once at startup
    t0 = time.perf_counter()
    for i in range(100):
        big.append(hashlib.sha256(b"new%d" % i).digest())
        big.root()
        big.inclusion(len(big) // 2, 0, len(big))
    per_op_ms = (time.perf_counter() - t0) * 10
    check("merkle cache: append+root+proof at 200k leaves < 20 ms",
          per_op_ms < 20, f"{per_op_ms:.2f} ms")


def main() -> int:
    mod = load_module()
    test_primitives(mod)
    test_cached_tree(mod)
    tsa_url = start_fake_tsa(mod)
    with tempfile.TemporaryDirectory() as root:
        token = test_http(mod, root, tsa_url)
        test_crash_consistency(mod, root, tsa_url, token)
    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("FAILED: " + ", ".join(FAIL))
        return 1
    print("VERDICT: SURVIVED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
