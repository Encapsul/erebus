"""SQLite-backed append-only transparency log: leaves, signed checkpoints,
inclusion and consistency proofs, RFC 3161 anchors, machine enrollment."""
import base64
import hashlib
import json
import os
import secrets
import sys
import threading
import urllib.error
import urllib.request
from datetime import datetime, timezone

from .ed25519 import _ed25519_public_key, _ed25519_sign, _ed_point_decode
from .merkle import _MerkleTree, _mt_leaf
from .tsa import tsa_build_request, tsa_parse_response


class TransparencyLog:
    """Append-only Merkle log of execution receipts (ROADMAP P0-5).

    Storage is a single SQLite file (stdlib `sqlite3`, WAL mode): one row per
    receipt with the exact bytes the client posted, so the leaf hash
    `SHA-256(0x00 ‖ body)` is reproducible offline from the receipt file.
    Leaf hashes are mirrored in memory; the tree head is recomputed on demand
    and signed with the registry's Ed25519 log key. Checkpoints can be
    anchored at an RFC 3161 TSA so the registry operator cannot backdate.
    """

    CHECKPOINT_PREFIX = "erebus-log-checkpoint/v1"

    def __init__(self, db_path: str, seed: bytes, origin: str,
                 tsa_url: str | None = None, anchor_every: int = 0):
        import sqlite3
        self.lock = threading.RLock()
        self.seed = seed
        self.public_key = _ed25519_public_key(seed)
        self.key_id = "sha256:" + hashlib.sha256(self.public_key).hexdigest()
        self.origin = origin
        self.tsa_url = tsa_url
        self.anchor_every = anchor_every
        self.conn = sqlite3.connect(db_path, check_same_thread=False, isolation_level=None)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=FULL")
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS attestations ("
            " seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE NOT NULL,"
            " owner TEXT NOT NULL, bundle TEXT NOT NULL, machine TEXT NOT NULL,"
            " os TEXT, arch TEXT, attested_at TEXT, key_fp TEXT, ts TEXT NOT NULL,"
            " leaf_hash TEXT UNIQUE NOT NULL, body BLOB NOT NULL)"
        )
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS att_owner_time ON attestations(owner, attested_at)"
        )
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS anchors ("
            " id INTEGER PRIMARY KEY AUTOINCREMENT, size INTEGER NOT NULL,"
            " root TEXT NOT NULL, ts TEXT NOT NULL, tsa_url TEXT NOT NULL,"
            " gen_time TEXT, token BLOB NOT NULL)"
        )
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS machines ("
            " machine_id TEXT PRIMARY KEY, public_key_hex TEXT UNIQUE NOT NULL,"
            " owner TEXT NOT NULL, os TEXT, arch TEXT, enrolled_at TEXT NOT NULL,"
            " certificate TEXT NOT NULL)"
        )
        rows = self.conn.execute("SELECT leaf_hash FROM attestations ORDER BY seq").fetchall()
        self.tree = _MerkleTree([bytes.fromhex(r[0]) for r in rows])
        # seq is AUTOINCREMENT: gaps would break seq-1 == leaf index, so the
        # in-memory list is the authority and seq is only a display id.

    # -- writes -----------------------------------------------------------
    def append(self, rec: dict, body: bytes) -> tuple[int, str, bool]:
        """Insert one receipt. Returns (leaf_index, leaf_hash_hex, already)."""
        leaf = _mt_leaf(body)
        leaf_hex = leaf.hex()
        with self.lock:
            row = self.conn.execute(
                "SELECT seq, leaf_hash FROM attestations WHERE id = ? OR leaf_hash = ?",
                (rec["id"], leaf_hex),
            ).fetchone()
            if row:
                return self.tree.index[bytes.fromhex(row[1])], row[1], True
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                self.conn.execute(
                    "INSERT INTO attestations (id, owner, bundle, machine, os, arch,"
                    " attested_at, key_fp, ts, leaf_hash, body)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (rec["id"], rec["owner"], rec["bundle"], rec["machine"], rec["os"],
                     rec["arch"], rec["attested_at"], rec["key_fp"], rec["ts"],
                     leaf_hex, body),
                )
                self.conn.execute("COMMIT")
            except Exception:
                self.conn.execute("ROLLBACK")
                raise
            index = self.tree.append(leaf)
        if self.tsa_url and self.anchor_every and (index + 1) % self.anchor_every == 0:
            try:
                self.anchor()
            except Exception as e:  # never fail a publish because the TSA is down
                print(f"[registry] TSA anchoring failed: {e}", file=sys.stderr)
        return index, leaf_hex, False

    def exists(self, att_id: str) -> bool:
        with self.lock:
            return self.conn.execute(
                "SELECT 1 FROM attestations WHERE id = ?", (att_id,)
            ).fetchone() is not None

    def query(self, owner: str, filters: dict, limit: int, skip: int) -> tuple[int, list[dict]]:
        clauses, params = ["owner = ?"], [owner]
        if filters.get("bundle"):
            clauses.append("bundle = ?")
            params.append(filters["bundle"])
        if filters.get("machine"):
            clauses.append("machine = ?")
            params.append(filters["machine"])
        if filters.get("since"):
            clauses.append("attested_at >= ?")
            params.append(filters["since"])
        if filters.get("until"):
            clauses.append("attested_at <= ?")
            params.append(filters["until"])
        where = " AND ".join(clauses)
        with self.lock:
            total = self.conn.execute(
                f"SELECT COUNT(*) FROM attestations WHERE {where}", params
            ).fetchone()[0]
            rows = self.conn.execute(
                f"SELECT seq, id, owner, ts, bundle, machine, os, arch, attested_at,"
                f" key_fp, leaf_hash, body FROM attestations WHERE {where}"
                f" ORDER BY seq LIMIT ? OFFSET ?",
                params + [limit, skip],
            ).fetchall()
        page = []
        for r in rows:
            try:
                att = json.loads(r[11])
            except ValueError:
                att = None
            page.append({
                "id": r[1], "owner": r[2], "ts": r[3], "bundle": r[4], "machine": r[5],
                "os": r[6], "arch": r[7], "attested_at": r[8], "key_fp": r[9],
                "leaf_index": r[0] - 1, "leaf_hash": "sha256:" + r[10], "attestation": att,
            })
        return total, page

    # -- tree heads ---------------------------------------------------------
    def size(self) -> int:
        with self.lock:
            return len(self.tree)

    def root(self, size: int | None = None) -> bytes:
        with self.lock:
            n = len(self.tree)
            return self.tree.root(0, n if size is None else min(size, n))

    def checkpoint_bytes(self, size: int, root: bytes, ts: str) -> bytes:
        return (f"{self.CHECKPOINT_PREFIX}\n{self.origin}\n{size}\n{root.hex()}\n{ts}\n").encode()

    def checkpoint(self) -> dict:
        """Signed tree head over the current size."""
        with self.lock:
            size = len(self.tree)
            root = self.tree.root()
        ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
        sig = _ed25519_sign(self.seed, self.checkpoint_bytes(size, root, ts))
        return {
            "origin": self.origin,
            "size": size,
            "root": "sha256:" + root.hex(),
            "timestamp": ts,
            "key_id": self.key_id,
            "public_key_hex": self.public_key.hex(),
            "signature_hex": sig.hex(),
        }

    def inclusion(self, leaf_hex: str, size: int | None = None) -> dict | None:
        with self.lock:
            index = self.tree.index.get(bytes.fromhex(leaf_hex))
            if index is None:
                return None
            n = len(self.tree) if size is None else size
            if index >= n or n > len(self.tree):
                return None
            path = self.tree.inclusion(index, 0, n)
            root = self.tree.root(0, n)
        return {
            "leaf_index": index,
            "leaf_hash": "sha256:" + leaf_hex,
            "tree_size": n,
            "root": "sha256:" + root.hex(),
            "inclusion_proof": [p.hex() for p in path],
        }

    def consistency(self, first: int, second: int) -> dict | None:
        with self.lock:
            if not (0 < first <= second <= len(self.tree)):
                return None
            proof = self.tree.consistency(first, 0, second)
            return {
                "first": first,
                "second": second,
                "first_root": "sha256:" + self.tree.root(0, first).hex(),
                "second_root": "sha256:" + self.tree.root(0, second).hex(),
                "consistency_proof": [p.hex() for p in proof],
            }

    # -- anchoring ----------------------------------------------------------
    def anchor(self, tsa_url: str | None = None) -> dict:
        """Timestamp the current checkpoint at an RFC 3161 TSA and store it.

        The imprint is SHA-256 over the canonical checkpoint bytes *without*
        the timestamp line (the TSA's genTime is the authoritative time).
        """
        url = tsa_url or self.tsa_url
        if not url:
            raise RuntimeError("no TSA configured (--tsa-url)")
        with self.lock:
            size = len(self.tree)
            root = self.tree.root()
        digest = hashlib.sha256(self.anchor_bytes(size, root)).digest()
        req = urllib.request.Request(
            url, data=tsa_build_request(digest), method="POST",
            headers={"Content-Type": "application/timestamp-query",
                     "Accept": "application/timestamp-reply"},
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            body = resp.read()
        parsed = tsa_parse_response(body, digest)
        if not parsed["ok"]:
            raise RuntimeError(f"TSA rejected the request: {parsed['error']}")
        ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self.lock:
            self.conn.execute(
                "INSERT INTO anchors (size, root, ts, tsa_url, gen_time, token)"
                " VALUES (?,?,?,?,?,?)",
                (size, "sha256:" + root.hex(), ts, url, parsed["gen_time"], body),
            )
        return self._anchor_dict(size, "sha256:" + root.hex(), ts, url, parsed["gen_time"], body)

    def anchor_bytes(self, size: int, root: bytes) -> bytes:
        return f"{self.CHECKPOINT_PREFIX}\n{self.origin}\n{size}\n{root.hex()}\n".encode()

    @staticmethod
    def _anchor_dict(size, root, ts, url, gen_time, token) -> dict:
        return {
            "size": size, "root": root, "requested_at": ts, "tsa_url": url,
            "gen_time": gen_time, "token_b64": base64.b64encode(token).decode(),
        }

    def latest_anchor(self) -> dict | None:
        with self.lock:
            row = self.conn.execute(
                "SELECT size, root, ts, tsa_url, gen_time, token FROM anchors"
                " ORDER BY id DESC LIMIT 1"
            ).fetchone()
        return self._anchor_dict(*row) if row else None

    def key_info(self) -> dict:
        return {"algorithm": "ed25519", "key_id": self.key_id,
                "public_key_hex": self.public_key.hex(), "origin": self.origin}

    # -- machine identity (spec 2.0, `erebus enroll`) ----------------------
    # The registry certifies "this Ed25519 key belongs to a host enrolled by
    # <owner>". Canonical bytes are shared with erebus-core/src/machine.rs;
    # the log key doubles as the certificate key so verifiers trust one key.
    CERT_PREFIX = b"erebus-machine-cert/v1\n"

    def cert_bytes(self, machine_id: str, pub_hex: str, owner: str, registry: str,
                   issued_at: str) -> bytes:
        return self.CERT_PREFIX + "\n".join(
            [machine_id, pub_hex, owner, registry, issued_at]).encode() + b"\n"

    def enroll(self, owner: str, pub_hex: str, registry: str, os_name: str,
               arch: str) -> tuple[dict, bool]:
        """Certify a machine key. Re-enrolling the same key returns the
        existing certificate (idempotent) so a retried CLI call is harmless."""
        if len(pub_hex) != 64 or any(c not in "0123456789abcdef" for c in pub_hex):
            raise ValueError("public_key_hex must be 64 lowercase hex chars")
        pub = bytes.fromhex(pub_hex)
        if _ed_point_decode(pub) is None:
            raise ValueError("public_key_hex is not a valid Ed25519 point")
        machine_id = "sha256:" + hashlib.sha256(pub).hexdigest()
        with self.lock:
            row = self.conn.execute(
                "SELECT owner, certificate FROM machines WHERE machine_id = ?", (machine_id,)
            ).fetchone()
            if row:
                if row[0] != owner:
                    raise PermissionError("machine key already enrolled by another user")
                return json.loads(row[1]), True
            issued_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
            sig = _ed25519_sign(
                self.seed, self.cert_bytes(machine_id, pub_hex, owner, registry, issued_at))
            cert = {
                "machine_id": machine_id, "public_key_hex": pub_hex, "owner": owner,
                "registry": registry, "issued_at": issued_at,
                "registry_key_id": self.key_id, "registry_key_hex": self.public_key.hex(),
                "signature_hex": sig.hex(),
            }
            self.conn.execute(
                "INSERT INTO machines (machine_id, public_key_hex, owner, os, arch,"
                " enrolled_at, certificate) VALUES (?,?,?,?,?,?,?)",
                (machine_id, pub_hex, owner, os_name, arch, issued_at, json.dumps(cert)),
            )
        return cert, False

    def machines_of(self, owner: str) -> list[dict]:
        with self.lock:
            rows = self.conn.execute(
                "SELECT machine_id, public_key_hex, os, arch, enrolled_at FROM machines"
                " WHERE owner = ? ORDER BY enrolled_at", (owner,)
            ).fetchall()
        return [{"machine_id": r[0], "public_key_hex": r[1], "os": r[2], "arch": r[3],
                 "enrolled_at": r[4]} for r in rows]


def load_or_create_log_key(path: str) -> bytes:
    """32-byte Ed25519 seed, `erebus keygen` format, created 0600 if absent."""
    try:
        with open(path, "rb") as f:
            seed = f.read()
        if len(seed) != 32:
            raise SystemExit(f"log key {path} must be exactly 32 bytes")
        return seed
    except FileNotFoundError:
        seed = secrets.token_bytes(32)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(seed)
        return seed
