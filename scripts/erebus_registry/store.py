"""Mutable registry state (packages, users, attestations, quotas)."""
from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from typing import Any

from erebus_registry.artifacts import (
    artifact_lifecycle,
    verify_gguf_integrity,
    verify_integrity,
)
from erebus_registry.ed25519 import _ed25519_verify
from erebus_registry.tlog import TransparencyLog, load_or_create_log_key
from erebus_registry.util import (
    CHUNK,
    EREBUS_MAGIC,
    ROLE_ORDER,
    SAFE_EMAIL,
    SAFE_ORG,
    SAFE_USER,
    TIER_QUOTAS,
    atomic_write,
    base64url_decode,
    month_now,
    week_now,
)

class Store:
    """All mutable state, guarded by an in-process RLock + per-file flock."""

    def __init__(self, root: str, quota_bytes: int, upload_cap: int,
                 require_auth: bool = False, allow_anon_uploads: bool = False,
                 log_key: str | None = None, log_origin: str | None = None,
                 tsa_url: str | None = None, anchor_every: int = 0):
        self.root = root
        self.pkg_dir = os.path.join(root, "packages")
        self.meta_dir = os.path.join(root, "meta")
        self.webhooks_path = os.path.join(root, "webhooks.json")
        self.usage_dir = os.path.join(root, "usage")
        self.mcp_dir = os.path.join(root, "mcp")
        self.attest_dir = os.path.join(root, "attestations")
        for d in (self.pkg_dir, self.meta_dir, self.usage_dir, self.mcp_dir, self.attest_dir):
            os.makedirs(d, exist_ok=True)
        self.attest_path = os.path.join(self.attest_dir, "attestations.jsonl")
        self.log = TransparencyLog(
            os.path.join(self.attest_dir, "log.sqlite"),
            load_or_create_log_key(log_key or os.path.join(root, "log.key")),
            log_origin or "erebus-registry",
            tsa_url=tsa_url,
            anchor_every=anchor_every,
        )
        self._migrate_attestation_jsonl()
        self.users_path = os.path.join(root, "users.json")
        self.stats_path = os.path.join(root, "stats.json")
        self.waitlist_path = os.path.join(root, "waitlist.txt")
        self.orgs_path = os.path.join(root, "orgs.json")
        self.audit_dir = os.path.join(root, "audit")
        os.makedirs(self.audit_dir, exist_ok=True)
        self.quota_bytes = quota_bytes
        self.upload_cap = upload_cap
        self.require_auth = require_auth
        # Fail-closed (default-deny): anonymous uploads are NEVER implicit.
        # They only happen when the operator explicitly opts in with
        # --allow-anon-uploads (development/bootstrap). Mutation endpoints
        # require a valid token in every other case.
        self.allow_anon_uploads = allow_anon_uploads
        self.lock = threading.RLock()
        self._hash_cache: dict[str, tuple[float, str]] = {}
        # Roadmap #13 integrity state: {fname: {"ok": bool, "detail": str,
        # "ts": iso}}. Maintained by the periodic `scan_integrity_locked` pass
        # and read by `index()`/`/integrity`, so the public index never
        # re-hashes every blob on each hit. Corrupt blobs are excluded from
        # serving regardless of their embedded (possibly rewritten) state.
        self.integrity_path = os.path.join(root, "integrity.json")
        self.integrity = self._load(self.integrity_path, {})
        self.users = self._load(self.users_path, {})

    # ---- json helpers -----------------------------------------------------
    @staticmethod
    def _load(path: str, default):
        try:
            with open(path, "rb") as f:
                return json.loads(f.read())
        except (OSError, ValueError):
            return default

    def _save_locked(self, path: str, obj):
        atomic_write(path, json.dumps(obj).encode())

    # ---- users ------------------------------------------------------------
    def bootstrap_open_uploads(self) -> bool:
        with self.lock:
            # Fail-closed (default-deny): anonymous uploads require an
            # explicit opt-in flag. `require_auth` forces closure regardless.
            if self.require_auth:
                return False
            return self.allow_anon_uploads

    @staticmethod
    def _hash_password(password: str, salt: bytes) -> str:
        return hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1).hex()

    def register(self, username: str, password: str,
                 ed25519_pub: str | None = None) -> tuple[bool, str]:
        if not SAFE_USER.match(username or ""):
            return False, "invalid username ([a-z0-9_-], max 32)"
        if len(password or "") < 10:
            return False, "password must be >= 10 chars"
        salt = secrets.token_bytes(16)
        token = secrets.token_hex(32)
        rec = {
            "salt": salt.hex(),
            "pwhash": self._hash_password(password, salt),
            "token_hash": hashlib.sha256(token.encode()).hexdigest(),
            "tier": "free",
            "created": time.time(),
        }
        if ed25519_pub:
            # Optional native Ed25519 sign-in: 32-byte public key, hex-encoded.
            try:
                pub_bytes = bytes.fromhex(ed25519_pub)
            except ValueError:
                return False, "ed25519_pub must be hex"
            if len(pub_bytes) != 32:
                return False, "ed25519_pub must be 32 bytes"
            rec["ed25519_pub"] = ed25519_pub
        with self.lock:
            # Same shape as login(): credentials live under the "users" key.
            users = self._load(self.users_path, {}).get("users", {})
            if username in users:
                return False, "username taken"
            users[username] = rec
            self._save_locked(self.users_path, {"users": users})
            self.users = users
        # Replication event for new user
        self.record_replication_event(
            "upsert_user",
            username,
            {
                "sha256": "",
                "size": 0,
                "at": datetime.now(timezone.utc).isoformat(),
                "private": False,
                "deleted": False,
                "meta": {"tier": "free"},
            },
        )
        return True, token

    def login(self, username: str, password: str, provided_token: str | None) -> str | None:
        """Return username iff credentials match. Password OR bearer token."""
        with self.lock:
            users = self._load(self.users_path, {}).get("users", {})
            rec = users.get(username or "")
        if not rec:
            # burn comparable time so user enumeration via timing is harder
            self._hash_password(password or "", b"x" * 16)
            return None
        if provided_token is not None:
            good = hmac.compare_digest(
                rec["token_hash"], hashlib.sha256(provided_token.encode()).hexdigest()
            )
            return username if good else None
        calc = self._hash_password(password or "", bytes.fromhex(rec["salt"]))
        if hmac.compare_digest(calc, rec["pwhash"]):
            return username
        return None

    def authenticate(self, authorization: str) -> str | None:
        """Bearer <scheme>:<payload> or legacy Bearer <token>."""
        if not authorization.startswith("Bearer "):
            return None
        raw = authorization[len("Bearer "):].strip()
        if ":" in raw:
            scheme, _, payload = raw.partition(":")
        else:
            scheme, payload = "token", raw
        with self.lock:
            users = self._load(self.users_path, {}).get("users", {})
        if scheme == "token":
            if ":" in payload:
                username, _, token = payload.partition(":")
            else:
                username, token = "", payload
            if username:
                rec = users.get(username)
                if rec and hmac.compare_digest(
                    rec["token_hash"], hashlib.sha256(token.encode()).hexdigest()
                ):
                    return username
                return None
            for name, rec in users.items():
                if hmac.compare_digest(
                    rec["token_hash"], hashlib.sha256(token.encode()).hexdigest()
                ):
                    return name
            return None
        if scheme == "hmac":
            return self._auth_hmac(payload, users)
        if scheme == "ed25519":
            return self._auth_ed25519(payload, users)
        return None

    def _auth_ed25519(self, payload: str, users: dict) -> str | None:
        """Verify Ed25519 bearer token: `bundle_id:base64url(sig)`.

        Matches the Rust `Ed25519Authenticator` (erebus-core/src/auth.rs): the
        signature is Ed25519 over the subject (bundle_id) bytes, verified
        against a per-user stored Ed25519 public key.
        """
        try:
            bundle_id, sig_b64url = payload.split(":", 1)
        except ValueError:
            return None
        try:
            sig_bytes = base64url_decode(sig_b64url)
        except Exception:
            return None
        if len(sig_bytes) != 64:
            return None
        for username, rec in users.items():
            pub_hex = rec.get("ed25519_pub")
            if not pub_hex:
                continue
            try:
                pub_bytes = bytes.fromhex(pub_hex)
                if len(pub_bytes) == 32 and _ed25519_verify(
                    pub_bytes, bundle_id.encode(), sig_bytes
                ):
                    return username
            except (ValueError, OSError):
                continue
        return None

    def _auth_hmac(self, payload: str, users: dict) -> str | None:
        try:
            username, signature = payload.split(":", 1)
        except ValueError:
            return None
        rec = users.get(username)
        if not rec or "secret" not in rec:
            return None
        expected = hmac.new(
            rec["secret"].encode(), username.encode(), hashlib.sha256
        ).hexdigest()
        if hmac.compare_digest(expected, signature):
            return username
        return None

    # ---- tiers / billing --------------------------------------------------
    def user_tier(self, username: str) -> str:
        with self.lock:
            rec = self.users.get(username or "")
        tier = (rec or {}).get("tier", "free")
        return tier if tier in TIER_QUOTAS else "free"

    def set_tier(self, username: str, tier: str) -> bool:
        if tier not in TIER_QUOTAS:
            return False
        with self.lock:
            if username not in self.users:
                return False
            users = self._load(self.users_path, {}).get("users", {})
            if username not in users:
                return False
            users[username]["tier"] = tier
            self._save_locked(self.users_path, {"users": users})
            self.users = users
        self.record_audit(username, "billing_tier", tier)
        # Replication event
        self.record_replication_event(
            "tier_change",
            username,
            {
                "sha256": "",
                "size": 0,
                "at": datetime.now(timezone.utc).isoformat(),
                "private": False,
                "deleted": False,
                "meta": {"tier": tier},
            },
        )
        return True

    def quota_for(self, username: str) -> int:
        tier = self.user_tier(username)
        # `--quota-gb` overrides the free-tier ceiling (operator-set and
        # used by chaos/quotas tests). Paid tiers always use their table.
        if tier == "free":
            return self.quota_bytes
        return TIER_QUOTAS[tier]

    # ---- orgs / RBAC ------------------------------------------------------
    def create_org(self, name: str, owner: str) -> tuple[bool, str]:
        if not SAFE_ORG.match(name or ""):
            return False, "invalid org name ([a-z0-9][a-z0-9_-], max 39)"
        if self.user_tier(owner) != "team":
            return False, "orgs require the Team plan"
        with self.lock:
            orgs = self._load(self.orgs_path, {}).get("orgs", {})
            if name in orgs:
                return False, "org name taken"
            orgs[name] = {
                "owner": owner,
                "members": {owner: "owner"},
                "created": time.time(),
            }
            self._save_locked(self.orgs_path, {"orgs": orgs})
        self.record_audit(owner, "org_create", f"org:{name}", org=name)
        return True, "created"

    def get_org(self, name: str) -> dict | None:
        with self.lock:
            return self._load(self.orgs_path, {}).get("orgs", {}).get(name)

    def org_role(self, name: str, username: str) -> str | None:
        org = self.get_org(name)
        if not org:
            return None
        role = org.get("members", {}).get(username or "")
        return role if role in ROLE_ORDER else None

    def add_member(self, org: str, actor: str, member: str, role: str) -> tuple[bool, str]:
        if role not in ("viewer", "developer", "admin"):
            return False, "role must be viewer|developer|admin"
        if not SAFE_USER.match(member or ""):
            return False, "invalid username"
        if actor not in self.users:
            return False, "no such user"
        with self.lock:
            orgs = self._load(self.orgs_path, {}).get("orgs", {})
            o = orgs.get(org)
            if not o:
                return False, "no such org"
            actor_role = ROLE_ORDER.get(o["members"].get(actor, ""), -1)
            if actor_role < ROLE_ORDER["admin"]:
                return False, "admin role required"
            if member == o["owner"]:
                return False, "owner role cannot be reassigned"
            o.setdefault("members", {})[member] = role
            self._save_locked(self.orgs_path, {"orgs": orgs})
        self.record_audit(actor, "org_member_add", f"org:{org}:{member}:{role}", org=org)
        return True, "added"

    def remove_member(self, org: str, actor: str, member: str) -> tuple[bool, str]:
        with self.lock:
            orgs = self._load(self.orgs_path, {}).get("orgs", {})
            o = orgs.get(org)
            if not o:
                return False, "no such org"
            if member == o["owner"]:
                return False, "the org owner cannot be removed"
            actor_role = ROLE_ORDER.get(o["members"].get(actor, ""), -1)
            if actor_role < ROLE_ORDER["admin"]:
                return False, "admin role required"
            target_role = ROLE_ORDER.get(o["members"].get(member, ""), -1)
            if target_role < 0:
                return False, "not a member"
            # Admins may only remove viewers/developers — protects admin pool.
            if actor_role == ROLE_ORDER["admin"] and target_role >= ROLE_ORDER["admin"]:
                return False, "admins can only remove viewers and developers"
            del o["members"][member]
            self._save_locked(self.orgs_path, {"orgs": orgs})
        self.record_audit(actor, "org_member_remove", f"org:{org}:{member}", org=org)
        return True, "removed"

    def user_orgs(self, username: str) -> dict[str, str]:
        """Map of org name -> role for all memberships of a user."""
        result: dict[str, str] = {}
        for name, o in self._load(self.orgs_path, {}).get("orgs", {}).items():
            role = o.get("members", {}).get(username or "")
            if role in ROLE_ORDER:
                result[name] = role
        return result

    # ---- audit log --------------------------------------------------------
    def record_audit(self, actor: str, action: str, target: str = "",
                     org: str | None = None):
        line = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "actor": actor,
            "action": action,
            "target": target,
            "ip": None,
        }
        if org:
            line["org"] = org
        path = os.path.join(self.audit_dir, month_now() + ".jsonl")
        data = json.dumps(line).encode() + b"\n"
        with open(path, "ab") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                f.write(data)
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        self._dispatch_webhook(line)

    def _dispatch_webhook(self, event: dict):
        """Send event to configured webhook URLs."""
        webhooks = self._load(self.webhooks_path, [])
        if not webhooks:
            return
        payload = json.dumps(event).encode()
        for url in webhooks:
            try:
                req = urllib.request.Request(url, data=payload, headers={
                    "Content-Type": "application/json",
                    "User-Agent": "erebus-registry-webhook/0.5",
                }, method="POST")
                urllib.request.urlopen(req, timeout=10)
            except (OSError, urllib.error.URLError):
                pass  # fire-and-forget

    def read_audit(self, month: str, actor: str | None = None,
                   org: str | None = None) -> list[dict]:
        """Lines filtered by actor (personal) XOR by org tag (org trail)."""
        out: list[dict] = []
        try:
            with open(os.path.join(self.audit_dir, month + ".jsonl"), "rb") as f:
                raw = f.read()
        except OSError:
            return out
        for line in raw.splitlines():
            try:
                rec = json.loads(line)
            except ValueError:
                continue  # torn tail write from a crashed process
            if actor is not None and rec.get("actor") == actor and "org" not in rec:
                out.append(rec)
            elif org is not None and rec.get("org") == org:
                out.append(rec)
        return out

    def add_webhook(self, url: str) -> None:
        with self.lock:
            webhooks = self._load(self.webhooks_path, [])
            if url not in webhooks:
                webhooks.append(url)
                atomic_write(self.webhooks_path, json.dumps(webhooks).encode())

    def remove_webhook(self, url: str) -> None:
        with self.lock:
            webhooks = self._load(self.webhooks_path, [])
            webhooks = [w for w in webhooks if w != url]
            atomic_write(self.webhooks_path, json.dumps(webhooks).encode())

    def list_webhooks(self) -> list[str]:
        with self.lock:
            return self._load(self.webhooks_path, [])

    # ---- attestations -----------------------------------------------------
    def _migrate_attestation_jsonl(self) -> None:
        """One-shot import of the pre-P0-5 JSONL journal into the Merkle log.

        The old journal stored re-serialized JSON, so imported leaves hash the
        canonical form (`sort_keys`) — older receipts get an inclusion proof
        but cannot be re-derived from the client file byte-for-byte. The file
        is renamed, not deleted.
        """
        if not os.path.isfile(self.attest_path) or self.log.size() > 0:
            return
        imported = 0
        with open(self.attest_path, "rb") as f:
            for line in f.read().splitlines():
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue  # torn tail write from a crashed process
                body = json.dumps(rec.get("attestation"), sort_keys=True).encode()
                try:
                    self.log.append(rec, body)
                    imported += 1
                except (KeyError, TypeError):
                    continue
        os.replace(self.attest_path, self.attest_path + ".migrated")
        if imported:
            print(f"[registry] migrated {imported} attestations into the Merkle log",
                  file=sys.stderr)

    def record_attestation(self, owner: str, att: dict,
                           raw: bytes | None = None) -> tuple[bool, str, bool]:
        """Append one execution attestation to the Merkle transparency log.

        Validate the in-toto shape fail-closed, derive a content id, and write
        idempotently (a re-post of the same attestation returns the same id).
        `raw` is the exact body the client sent — it becomes the leaf preimage
        so the client can recompute the leaf hash from its receipt file.
        Returns (ok, id_or_err, already_recorded); the log position is
        available afterwards via `log_position(id)`.
        """
        if not isinstance(att, dict):
            return False, "attestation must be a JSON object", False
        sig = att.get("signature")
        art = att.get("artifact")
        exe = att.get("execution")
        if not (isinstance(sig, dict) and isinstance(art, dict) and isinstance(exe, dict)):
            return False, "attestation missing signature/artifact/execution object", False
        if not (sig.get("signature_hex") and sig.get("key_fingerprint")):
            return False, "signature.signature_hex and key_fingerprint are required", False
        att_id = att.get("attestation_id") or att.get("id") or ""
        bundle = str(art.get("bundle_hash") or "")
        machine = str(exe.get("machine_id_hash") or "")
        if not bundle:
            return False, "artifact.bundle_hash is required", False
        if not machine:
            return False, "execution.machine_id_hash is required", False
        if not att_id:
            att_id = hashlib.sha256(json.dumps(att, sort_keys=True).encode()).hexdigest()[:16]
        rec = {
            "id": att_id,
            "owner": owner,
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "bundle": bundle,
            "machine": machine,
            "os": str(exe.get("os") or ""),
            "arch": str(exe.get("arch") or ""),
            "attested_at": str(exe.get("attested_at") or ""),
            "key_fp": str(sig.get("key_fingerprint") or ""),
            "attestation": att,
        }
        body = raw if raw is not None else json.dumps(att, sort_keys=True).encode()
        _index, _leaf, already = self.log.append(rec, body)
        if already:
            return True, att_id, True
        self.record_audit(owner, "attestation_published", att_id)
        self.record_replication_event("upsert_attestation", att_id, {
            "bundle": bundle,
            "machine": machine,
            "attested_at": rec["attested_at"],
            "owner": owner,
        })
        return True, att_id, False

    def _attestation_exists(self, att_id: str) -> bool:
        return self.log.exists(att_id)

    def log_position(self, att_id: str) -> dict | None:
        """Inclusion proof + signed checkpoint for a stored receipt."""
        with self.log.lock:
            row = self.log.conn.execute(
                "SELECT leaf_hash FROM attestations WHERE id = ?", (att_id,)
            ).fetchone()
            if not row:
                return None
            proof = self.log.inclusion(row[0])
            checkpoint = self.log.checkpoint()
        if proof is None:
            return None
        anchor = self.log.latest_anchor()
        proof["checkpoint"] = checkpoint
        proof["anchor"] = anchor if anchor and anchor["size"] == checkpoint["size"] else None
        return proof

    def query_attestations(self, owner: str, filters: dict, limit: int, skip: int) -> tuple[int, list[dict]]:
        """Chronological page of <owner>'s attestations matching AND-ed filters.

        Filters are bundle, machine, since, until. Only the caller's own
        records are ever returned — fail-closed personal trail. Attested-at
        ISO timestamps compare lexicographically as long as every producer
        emits the same timezone-aware format (the stub/CLI do).
        """
        return self.log.query(owner, filters, limit, skip)

    # ---- packages ---------------------------------------------------------
    def set_meta(self, fname: str, owner: str | None, private: bool, deleted: bool = False, deleted_at: str | None = None):
        with self.lock:
            atomic_write(
                os.path.join(self.meta_dir, fname + ".json"),
                json.dumps({"owner": owner, "private": private, "deleted": deleted, "deleted_at": deleted_at}).encode(),
            )
            # Replication event. The package file may be missing (meta-only or
            # half-created upload); tolerate it rather than leaking an OSError.
            pkg_path = os.path.join(self.pkg_dir, fname)
            if os.path.isfile(pkg_path):
                pkg_sha = self.sha256_cached(pkg_path)
                pkg_size = os.path.getsize(pkg_path)
            else:
                pkg_sha, pkg_size = "", 0
            meta = self.get_meta(fname)
            self.record_replication_event(
                "upsert_artifact",
                fname,
                {
                    "sha256": pkg_sha,
                    "size": pkg_size,
                    "at": datetime.now(timezone.utc).isoformat(),
                    "private": private,
                    "deleted": deleted,
                    "meta": meta,
                },
            )

    def soft_delete(self, fname: str, user: str) -> None:
        with self.lock:
            meta = self.get_meta(fname)
            meta["deleted"] = True
            meta["deleted_at"] = datetime.now(timezone.utc).isoformat()
            meta["deleted_by"] = user
            atomic_write(
                os.path.join(self.meta_dir, fname + ".json"),
                json.dumps(meta).encode(),
            )
            self.store.record_audit(user, "artifact_deleted", fname)
            # Replication event
            self.record_replication_event(
                "delete_artifact",
                fname,
                {
                    "sha256": self.sha256_cached(os.path.join(self.pkg_dir, fname)),
                    "size": 0,
                    "at": datetime.now(timezone.utc).isoformat(),
                    "private": meta.get("private", False),
                    "deleted": True,
                    "meta": meta,
                },
            )


    def get_meta(self, fname: str) -> dict:
        return self._load(os.path.join(self.meta_dir, fname + ".json"), {})

    def read_erebus_meta(self, path: str) -> dict:
        if not path.endswith(".erebus"):
            return {}
        try:
            size = os.path.getsize(path)
            if size < 84:
                return {}
            with open(path, "rb") as f:
                if size >= 92:
                    f.seek(size - 92)
                    core = f.read(92)
                    if core[8:13] == EREBUS_MAGIC and core[13] >= 3:
                        meta_off = int.from_bytes(core[72:80], "little")
                        meta_len = int.from_bytes(core[80:88], "little")
                    else:
                        core = core[8:]
                        meta_off = int.from_bytes(core[64:72], "little")
                        meta_len = int.from_bytes(core[72:80], "little")
                else:
                    f.seek(size - 84)
                    core = f.read(84)
                    if core[0:5] != EREBUS_MAGIC:
                        return {}
                    meta_off = int.from_bytes(core[64:72], "little")
                    meta_len = int.from_bytes(core[72:80], "little")
                if meta_len <= 0 or meta_len > 64 * 1024 * 1024:
                    return {}
                f.seek(meta_off)
                meta_bytes = f.read(meta_len)
                return json.loads(meta_bytes)
        except (OSError, ValueError):
            return {}

    def artifact_format(self, path: str) -> str:
        if not path.endswith(".erebus"):
            return "unknown"
        try:
            size = os.path.getsize(path)
            if size < 84:
                return "legacy"
            with open(path, "rb") as f:
                if size >= 92:
                    f.seek(size - 92)
                    core = f.read(92)
                    if core[8:13] == EREBUS_MAGIC and core[13] >= 3:
                        payload_csz = int.from_bytes(core[16:24], "little")
                        flags = core[15]
                    else:
                        core = core[8:]
                        payload_csz = int.from_bytes(core[16:24], "little")
                        flags = core[14]
                else:
                    f.seek(size - 84)
                    core = f.read(84)
                    if core[0:5] != EREBUS_MAGIC:
                        return "legacy"
                    payload_csz = int.from_bytes(core[16:24], "little")
                    flags = core[14]
                if flags & 0x01:
                    return "encrypted-v4"
                if flags & 0x02:
                    return "signed-v3"
                if flags & 0x04:
                    return "sisr-v2"
                return "plain-v2"
        except (OSError, ValueError):
            return "unknown"

    def sha256_cached(self, path: str) -> str:
        mtime = os.path.getmtime(path)
        cached = self._hash_cache.get(path)
        if cached and cached[0] == mtime:
            return cached[1]
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(CHUNK):
                h.update(chunk)
        digest = h.hexdigest()
        with self.lock:
            self._hash_cache[path] = (mtime, digest)
        return digest

    def scan_integrity_locked(self):
        """Re-verify every stored .erebus blob; update the persisted state.

        Called by the periodic daemon thread and/or the /integrity?scan=1
        request. Only touches .erebus blobs (runtime packs/sidecars are out of
        scope and reported ok). Temp `.incoming.*`/`.tmp` uploads are skipped.
        Never mutates the blob itself — a corrupt artifact is excluded from
        serving via the integrity state, not rewritten (rewriting would break
        its signature/footer hash).
        """
        snapshot = {}
        for name in sorted(os.listdir(self.pkg_dir)):
            if name.startswith(".incoming.") or ".tmp" in name:
                continue
            path = os.path.join(self.pkg_dir, name)
            if not os.path.isfile(path):
                continue
            ok, detail = verify_integrity(path)
            if ok and path.endswith(".gguf"):
                manifest_path = path + ".manifest.json"
                if os.path.isfile(manifest_path):
                    gguf_ok, gguf_detail = verify_gguf_integrity(path)
                    if not gguf_ok:
                        ok = False
                        detail = f"gguf:{gguf_detail}"
            snapshot[name] = {
                "ok": bool(ok),
                "detail": detail,
                "ts": datetime.now(timezone.utc).isoformat(),
            }
        with self.lock:
            self.integrity = snapshot
            self._save_locked(self.integrity_path, snapshot)
        return snapshot

    def garbage_collect_locked(self, dry_run: bool = True) -> dict:
        """Find and optionally reclaim unreachable or corrupt blobs.

        Returns a report dict with:
          - dry_run: boolean
          - corrupt: list of corrupt blob filenames
          - unreachable: list of blob filenames not in the current index
          - quarantined: list of blobs moved to quarantine (empty if dry_run)
        """
        index_names = set()
        for name in os.listdir(self.pkg_dir):
            if name.endswith(".erebus") and os.path.isfile(os.path.join(self.pkg_dir, name)):
                index_names.add(name)

        integrity = self.integrity if hasattr(self, 'integrity') else {}
        corrupt = [name for name, info in integrity.items() if not info.get("ok") and name in index_names]
        referenced = set()
        meta_names = set(os.listdir(self.meta_dir)) if os.path.isdir(self.meta_dir) else set()
        for meta_name in meta_names:
            if meta_name.endswith(".json"):
                pkg_name = meta_name[:-5]
                if pkg_name + ".erebus" in index_names:
                    referenced.add(pkg_name + ".erebus")
        unreachable = sorted(index_names - referenced)
        quarantined = []
        if not dry_run:
            quarantine_dir = os.path.join(self.root, "quarantine")
            os.makedirs(quarantine_dir, exist_ok=True)
            for name in corrupt + unreachable:
                src = os.path.join(self.pkg_dir, name)
                if os.path.isfile(src):
                    dst = os.path.join(quarantine_dir, name)
                    try:
                        atomic_write(dst, open(src, "rb").read())
                        os.remove(src)
                        quarantined.append(name)
                    except OSError:
                        pass
        return {
            "dry_run": dry_run,
            "corrupt": corrupt,
            "unreachable": unreachable,
            "quarantined": quarantined,
        }

    # ---- Replication journal -----------------------------------------
    def _replication_path(self) -> str:
        return os.path.join(self.root, "replication.jsonl")

    def record_replication_event(self, op: str, name: str, payload: dict) -> int:
        """Append an event to the replication journal. Returns the sequence number."""
        with self.lock:
            # Read current max seq
            max_seq = 0
            if os.path.exists(self._replication_path()):
                with open(self._replication_path(), "r") as f:
                    for line in f:
                        try:
                            rec = json.loads(line)
                            if rec.get("seq", 0) > max_seq:
                                max_seq = rec["seq"]
                        except (json.JSONDecodeError, KeyError):
                            continue
            next_seq = max_seq + 1
            entry = {
                "seq": next_seq,
                "op": op,
                "name": name,
                "payload": payload,
                "at": datetime.now(timezone.utc).isoformat(),
            }
            with open(self._replication_path(), "a") as f:
                f.write(json.dumps(entry) + "\n")
            return next_seq

    def replication_journal(self, after: int = 0) -> tuple[list[dict], int]:
        """Return journal entries with seq > after, and the next_seq."""
        entries = []
        max_seq = 0
        if os.path.exists(self._replication_path()):
            with open(self._replication_path(), "r") as f:
                for line in f:
                    try:
                        rec = json.loads(line)
                        if rec.get("seq", 0) > after:
                            entries.append(rec)
                        if rec.get("seq", 0) > max_seq:
                            max_seq = rec["seq"]
                    except (json.JSONDecodeError, KeyError):
                        continue
        next_seq = max_seq + 1
        return entries, next_seq

    def index(self) -> bytes:
        packages = []
        for name in sorted(os.listdir(self.pkg_dir)):
            path = os.path.join(self.pkg_dir, name)
            if not os.path.isfile(path) or not name.endswith(".erebus"):
                continue
            erebus_meta = self.read_erebus_meta(path)
            sidecar_meta = self.get_meta(name)
            entry = {
                "name": name[: -len(".erebus")],
                "file": name,
                "sha256": self.sha256_cached(path),
                "size": os.path.getsize(path),
                "format": self.artifact_format(path),
                "state": artifact_lifecycle(path)[0],
                "integrity": "ok" if self.integrity.get(name, {}).get("ok", True) else "corrupt",
            }
            if erebus_meta.get("author"):
                entry["author"] = erebus_meta["author"]
            if erebus_meta.get("description"):
                entry["description"] = erebus_meta["description"]
            if erebus_meta.get("license"):
                entry["license"] = erebus_meta["license"]
            if erebus_meta.get("payload_format"):
                entry["payload_format"] = erebus_meta["payload_format"]
            entry["private"] = bool(sidecar_meta.get("private"))
            if sidecar_meta.get("deleted"):
                continue
            packages.append(entry)
        return json.dumps({"packages": packages}).encode()

    # ---- quotas & stats ---------------------------------------------------
    def _usage_path(self, user: str) -> str:
        return os.path.join(self.usage_dir, f"{user}.json")

    def month_served(self, user: str) -> int:
        u = self._load(self._usage_path(user), {})
        return u["bytes"] if u.get("month") == month_now() else 0

    def charge_bytes(self, user: str, nbytes: int, full_equiv: int = 0):
        """Metered transfer accounting, crash-consistent under flock."""
        with self.lock:
            path = self._usage_path(user)
            fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                rec = self._load(path, {})
                if rec.get("month") != month_now():
                    rec = {"month": month_now(), "bytes": 0}
                rec["bytes"] = rec.get("bytes", 0) + nbytes
                atomic_write(path, json.dumps(rec).encode())
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)
        self.bump_stats(nbytes, full_equiv)

    def bump_stats(self, served: int, full_equiv: int):
        with self.lock:
            st = self._load(self.stats_path, {})
            wk = week_now()
            if st.get("week") != wk:
                st = {"week": wk, "served": 0, "full_equiv": 0, "pulls": 0}
            st["served"] += served
            st["full_equiv"] += full_equiv
            st["saved"] = max(0, st["full_equiv"] - st["served"])
            st["pulls"] = st.get("pulls", 0) + 1
            self._save_locked(self.stats_path, st)

    def stats(self) -> dict:
        with self.lock:
            st = self._load(self.stats_path, {})
        npkg = sum(
            1 for n in os.listdir(self.pkg_dir) if n.endswith(".erebus")
        ) if os.path.isdir(self.pkg_dir) else 0
        return {
            "week": st.get("week", week_now()),
            "bytes_served": st.get("served", 0),
            "full_equivalent": st.get("full_equiv", 0),
            "bytes_saved": max(0, st.get("full_equiv", 0) - st.get("served", 0)),
            "pulls": st.get("pulls", 0),
            "packages": npkg,
        }

    # ---- MCP servers ------------------------------------------------------
    def mcp_index(self) -> list[dict]:
        """List all MCP servers with their metadata."""
        servers = []
        for name in sorted(os.listdir(self.mcp_dir)):
            if not name.endswith(".mcp.json"):
                continue
            path = os.path.join(self.mcp_dir, name)
            meta = self._load(path, {})
            servers.append(meta)
        return servers

    def get_mcp(self, name: str) -> dict | None:
        path = os.path.join(self.mcp_dir, f"{name}.mcp.json")
        if not os.path.isfile(path):
            return None
        return self._load(path, None)

    def set_mcp(self, name: str, meta: dict):
        atomic_write(
            os.path.join(self.mcp_dir, f"{name}.mcp.json"),
            json.dumps(meta).encode(),
        )

    # ---- waitlist ---------------------------------------------------------
    def waitlist_add(self, email: str, ip: str) -> tuple[bool, str]:
        if not SAFE_EMAIL.match(email or "") or len(email) > 254:
            return False, "invalid email"
        rl_path = self.waitlist_path + ".rl"
        with self.lock:
            # Hold self.lock for the entire read-check-write to prevent TOCTOU
            # races where concurrent requests from the same IP both pass the
            # threshold check. The file lock is redundant here but provides
            # defense-in-depth for multi-process deployments.
            stamps: dict[str, float] = self._load(rl_path, {})
            now = time.time()
            stamps = {k: v for k, v in stamps.items() if now - v < 3600}
            if sum(1 for t in stamps.values() if now - t < 60) >= 3:
                return False, "rate limited"
            stamps[f"{ip}:{uuid.uuid4().hex[:8]}"] = now
            atomic_write(rl_path, json.dumps(stamps).encode())
            with open(self.waitlist_path, "a") as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                f.write(email + "\n")
        return True, "added"

    # ---- SSO config -------------------------------------------------------
    def set_sso_config(
        self, issuer: str, client_id: str, client_secret: str, provider_name: str = "OIDC"
    ) -> None:
        """Persist SSO config to sso.json in the registry root."""
        config = {
            "issuer": issuer,
            "client_id": client_id,
            "client_secret": client_secret,
            "provider_name": provider_name,
        }
        atomic_write(os.path.join(self.root, "sso.json"), json.dumps(config).encode())

    def get_sso_config(self) -> dict | None:
        """Read sso.json, or None if SSO not configured."""
        return self._load(os.path.join(self.root, "sso.json"), None)

    def sso_enabled(self) -> bool:
        return self.get_sso_config() is not None

