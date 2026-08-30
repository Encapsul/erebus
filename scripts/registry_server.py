#!/usr/bin/env python3
"""erebus registry v2 — accounts, quotas, SISR stats, landing page. stdlib only.

Routes (backward compatible with erebus CLI publish/pull):
    GET  /health              -> {"status":"ok"}
    GET  /                    -> landing page (live SISR savings counter)
    GET  /stats               -> JSON counters
    GET  /index.json          -> {"packages":[{name,file,sha256,size,private}]}
    GET  /packages/<file>     -> blob (private ones require Bearer token + quota)
    POST /packages/<name>     -> multipart upload (auth once bootstrap user exists)
    POST /auth/register       -> {"username","password"} -> {"token"}
    POST /auth/login          -> same shape, rotates nothing (token is stable)
    POST /waitlist            -> {"email"} throttled per IP
    GET  /mcp                 -> list MCP servers
    GET  /mcp/<name>          -> MCP server details
    POST /mcp                 -> upload MCP server (multipart, auth required)
    GET  /mcp/<name>/install  -> 1-line install script
    POST /billing/checkout    -> {"url"} Stripe Checkout session (auth)
    POST /billing/webhook     -> Stripe-signed events -> tier updates
    GET  /billing/status      -> {"tier": ...} (auth)
    POST /orgs                -> create org (Team tier)
    GET  /orgs/<name>         -> members list (members only)
    POST /orgs/<n>/members    -> add member {username, role} (owner/admin)
    DELETE /orgs/<n>/members/<u> -> remove member (owner/admin)
    GET  /audit/download?month=YYYY-MM[&org=n] -> JSONL audit trail (Team)

Storage layout under --dir:
    packages/<file>           blobs
    meta/<file>.json          {"owner":..., "private":bool}
    users.json                hashed credentials (scrypt) + tier
    usage/<user>.json         {"month","bytes_served"}
    stats.json                weekly served / full-equivalent / saved / pulls
    waitlist.txt              one email per line
    orgs.json                 {"orgs": {name: {owner, members:{user:role}}}}
    audit/YYYY-MM.jsonl       append-only action log
"""
import argparse
import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SAFE_FILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*\.erebus$")
# Runtime packs: raw engine binaries (llama-server etc.) published next to
# packages. Their .sha256 sidecar is always public — it leaks nothing.
SAFE_PACK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*\.pack(\.tar\.gz)?$")
SAFE_SIDECAR = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*\.pack(\.tar\.gz)?\.sha256$")
SAFE_USER = re.compile(r"^[a-z0-9_-]{1,32}$")
SAFE_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,16}$")
SAFE_ORG = re.compile(r"^[a-z0-9][a-z0-9_-]{1,38}$")
SAFE_MONTH = re.compile(r"^\d{4}-\d{2}$")
CHUNK = 64 * 1024
MONTH_FMT = "%Y-%m"
WEEK_FMT = "%G-W%V"

# BUSINESS.md tiers. Quotas are monthly private-transfer bytes.
TIER_QUOTAS = {"free": 20 * 10**9, "pro": 1000 * 10**9, "team": 5000 * 10**9}
PAID_TIERS = ("pro", "team")
ROLE_ORDER = {"viewer": 0, "developer": 1, "admin": 2, "owner": 3}


def month_now():
    return datetime.now(timezone.utc).strftime(MONTH_FMT)


def week_now():
    return datetime.now(timezone.utc).strftime(WEEK_FMT)


def atomic_write(path: str, data: bytes):
    tmp = f"{path}.{uuid.uuid4().hex}.tmp"
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


# .erebus footer layout (see erebus-core/src/format.rs):
#   v3+: full 92-byte footer = 8-byte sig_offset prefix + 84-byte core
#   v2:  84-byte core only
# Core (84 bytes): MAGIC[0:5] ver[5] arch[6] flags[7]
#   payload_offset[8:16] payload_csize[16:24] payload_usize[24:32]
#   payload_sha256[32:64] meta_offset[64:72] meta_size[72:80] footer_magic[80:84]
EREBUS_MAGIC = b"ERE\x01\x00"


def artifact_lifecycle(path: str) -> tuple[str, bool]:
    """Read the embedded lifecycle state of a stored .erebus blob.

    Returns (state_name, allow_untrusted). The state is embedded in the
    artifact's own metadata JSON (set by `erebus lifecycle`), and this is the
    registry's fail-safe enforcement point: a Revoked/Deleted artifact must
    never be served even if a client asks by name.

    Any file that predates lifecycle metadata, or whose footer cannot be
    parsed, is treated as the default `Acquired` state with an untrusted-
     deny policy — i.e. servable. This matches the Rust stub's treatment of a
    missing `artifact_state` as `Acquired`, so legacy/public artifacts keep
    working while deny-listed ones fail closed.
    """
    try:
        size = os.path.getsize(path)
        if size < 84:
            return "Acquired", False
        with open(path, "rb") as f:
            if size >= 92:
                f.seek(size - 92)
                core = f.read(92)
                # v3+: MAGIC lives at index 8 (after the sig_offset prefix).
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
                    return "Acquired", False
                meta_off = int.from_bytes(core[64:72], "little")
                meta_len = int.from_bytes(core[72:80], "little")
            if meta_len <= 0 or meta_len > 64 * 1024 * 1024:
                return "Acquired", False
            f.seek(meta_off)
            meta = json.loads(f.read(meta_len).decode("utf-8", "replace"))
    except (OSError, ValueError, TypeError):
        return "Acquired", False
    state = str(meta.get("artifact_state") or "Acquired")
    allow = bool((meta.get("artifact_policy") or {}).get("allow_untrusted", False))
    return state, allow


def verify_integrity(path: str) -> tuple[bool, str]:
    """Verify a stored .erebus blob's payload integrity against its footer.

    Reproduces the Rust stub's runtime check (erebus-stub/src/main.rs): the
    footer embeds `payload_sha256 = SHA-256(payload || meta_bytes)` and a
    tamper that changes the payload OR the embedded lifecycle metadata breaks
    the digest. Because the lifecycle state lives inside the blob, a corrupted
    blob would otherwise "forget" its Trusted/Revoked/Quarantined state and
    be served as Acquired — a hole in roadmap #8. `verify_integrity` closes it:
    it is independent of the embedded state and fails closed on any mismatch.

    Returns (ok, detail). `ok=False` means the blob is corrupt (bit-rot or
    tampering) and must not be served. Non-.erebus files (runtime packs,
    sidecars) are out of scope and always report ok=True.
    """
    if not path.endswith(".erebus"):
        return True, "not-an-erebus-blob"
    try:
        size = os.path.getsize(path)
        if size < 84:
            return True, "too-small (pre-lifecycle)"
        with open(path, "rb") as f:
            if size >= 92:
                f.seek(size - 92)
                core = f.read(92)
                if core[8:13] == EREBUS_MAGIC and core[13] >= 3:
                    payload_off = int.from_bytes(core[8:16], "little")
                    payload_csz = int.from_bytes(core[16:24], "little")
                    expected = core[32:64]
                    meta_off = int.from_bytes(core[72:80], "little")
                    meta_len = int.from_bytes(core[80:88], "little")
                else:
                    core = core[8:]
                    payload_off = int.from_bytes(core[8:16], "little")
                    payload_csz = int.from_bytes(core[16:24], "little")
                    expected = core[32:64]
                    meta_off = int.from_bytes(core[64:72], "little")
                    meta_len = int.from_bytes(core[72:80], "little")
            else:
                f.seek(size - 84)
                core = f.read(84)
                if core[0:5] != EREBUS_MAGIC:
                    return True, "no-footer (legacy)"
                payload_off = int.from_bytes(core[8:16], "little")
                payload_csz = int.from_bytes(core[16:24], "little")
                expected = core[32:64]
                meta_off = int.from_bytes(core[64:72], "little")
                meta_len = int.from_bytes(core[72:80], "little")
            if meta_len <= 0 or meta_len > 64 * 1024 * 1024:
                return True, "meta-out-of-range (legacy)"
            f.seek(payload_off)
            h = hashlib.sha256()
            remaining = payload_csz
            while remaining > 0:
                chunk = f.read(min(CHUNK, remaining))
                if not chunk:
                    break
                h.update(chunk)
                remaining -= len(chunk)
            f.seek(meta_off)
            remaining = meta_len
            while remaining > 0:
                chunk = f.read(min(CHUNK, remaining))
                if not chunk:
                    break
                h.update(chunk)
                remaining -= len(chunk)
            if remaining != 0 or payload_csz <= 0:
                return False, "truncated"
            got = h.digest()
    except (OSError, ValueError):
        return False, "unreadable"
    return got == expected, "corrupt" if got != expected else "ok"


class Store:
    """All mutable state, guarded by an in-process RLock + per-file flock."""

    def __init__(self, root: str, quota_bytes: int, upload_cap: int,
                 require_auth: bool = False, allow_anon_uploads: bool = False):
        self.root = root
        self.pkg_dir = os.path.join(root, "packages")
        self.meta_dir = os.path.join(root, "meta")
        self.usage_dir = os.path.join(root, "usage")
        self.mcp_dir = os.path.join(root, "mcp")
        for d in (self.pkg_dir, self.meta_dir, self.usage_dir, self.mcp_dir):
            os.makedirs(d, exist_ok=True)
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

    def register(self, username: str, password: str) -> tuple[bool, str]:
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
        with self.lock:
            # Same shape as login(): credentials live under the "users" key.
            users = self._load(self.users_path, {}).get("users", {})
            if username in users:
                return False, "username taken"
            users[username] = rec
            self._save_locked(self.users_path, {"users": users})
            self.users = users
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
        """Bearer <username>:<token> or legacy bare token matched globally."""
        if not authorization.startswith("Bearer "):
            return None
        raw = authorization[len("Bearer "):].strip()
        if ":" in raw:
            username, _, token = raw.partition(":")
        else:
            username, token = "", raw
        with self.lock:
            users = self._load(self.users_path, {}).get("users", {})
        if username:
            rec = users.get(username)
            if rec and hmac.compare_digest(
                rec["token_hash"], hashlib.sha256(token.encode()).hexdigest()
            ):
                return username
            return None
        # bare-token mode (legacy): scan — O(n), fine for small registries
        for name, rec in users.items():
            if hmac.compare_digest(
                rec["token_hash"], hashlib.sha256(token.encode()).hexdigest()
            ):
                return name
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

    # ---- packages ---------------------------------------------------------
    def set_meta(self, fname: str, owner: str | None, private: bool, deleted: bool = False, deleted_at: str | None = None):
        with self.lock:
            atomic_write(
                os.path.join(self.meta_dir, fname + ".json"),
                json.dumps({"owner": owner, "private": private, "deleted": deleted, "deleted_at": deleted_at}).encode(),
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


# ---- Stripe (stdlib REST, no SDK) -----------------------------------------
# Keys come from CLI flags or env; never logged, never stored on disk here.

def stripe_api(endpoint: str, params: dict, key: str) -> dict:
    """POST form-encoded params to the Stripe REST API. Raises on HTTP errors."""
    data = urllib.parse.urlencode(params).encode()
    req = urllib.request.Request(
        f"https://api.stripe.com/v1/{endpoint}",
        data=data,
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read())


def verify_stripe_signature(payload: bytes, header: str, secret: str,
                            tolerance: int = 300) -> bool:
    """Stripe-Signature: t=<ts>,v1=<hmac>. Constant-time compare, replay guard."""
    parts = {}
    for piece in header.split(","):
        if "=" in piece:
            k, _, v = piece.partition("=")
            parts[k.strip()] = v.strip()
    ts, v1 = parts.get("t"), parts.get("v1")
    if not ts or not v1 or not ts.isdigit():
        return False
    if abs(time.time() - int(ts)) > tolerance:
        return False
    signed = ts.encode() + b"." + payload
    expected = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, v1)


LANDING = """<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>erebus registry</title>
<style>
 body{{font-family:ui-monospace,Menlo,monospace;background:#0b0e14;color:#d7dce6;
      display:flex;flex-direction:column;align-items:center;padding:48px 16px;gap:28px}}
 h1{{color:#7ee0c3;font-size:26px}} .tag{{color:#5b6577}}
 .counters{{display:flex;gap:34px;text-align:center}}
 .num{{font-size:38px;color:#7ee0c3;font-weight:700}} .lbl{{color:#5b6577;font-size:12px}}
 form{{display:flex;gap:8px}} input{{background:#10162a;color:inherit;border:1px solid #1d2433;
      border-radius:8px;padding:11px 13px;font:inherit;width:280px}}
 button{{background:#173229;color:#7ee0c3;border:1px solid #245244;border-radius:8px;
      padding:0 18px;font:inherit;cursor:pointer}}
 code{{background:#10162a;padding:2px 6px;border-radius:4px}}
 a{{color:#7ee0c3}} #msg{{color:#5b6577;min-height:20px}}
</style></head><body>
<h1>erebus registry</h1>
<div class="tag">Your AI agent. One file. Runs anywhere.</div>
<div class="counters">
  <div><div class="num" id="saved">…</div><div class="lbl">GB SAVED BY DELTAS THIS WEEK</div></div>
  <div><div class="num" id="served">…</div><div class="lbl">GB SERVED</div></div>
  <div><div class="num" id="pulls">…</div><div class="lbl">PULLS</div></div>
</div>
<form onsubmit="join(event)"><input id="email" placeholder="you@company.com" autocomplete="email">
<button>Join the waitlist</button></form>
<div id="msg"></div>
<div class="tag">Open source · MIT —
<a href="https://github.com/Tednoob17/erebus">github.com/Tednoob17/erebus</a> ·
API: <code>/index.json</code> · <code>/packages/&lt;name&gt;</code></div>
<script>
async function refresh(){{
  try{{
    const s = await (await fetch('/stats')).json();
    saved.textContent = (s.bytes_saved/1e9).toFixed(2);
    served.textContent = (s.bytes_served/1e9).toFixed(2);
    pulls.textContent = s.pulls;
  }}catch(e){{}}
}}
function join(e){{
  e.preventDefault();
  fetch('/waitlist',{{method:'POST',headers:{{'Content-Type':'application/json'}},
    body:JSON.stringify({{email:document.getElementById('email').value}})}})
    .then(r=>r.json()).then(j=>{{msg.textContent=j.message||j.error;refresh();}})
    .catch(()=>msg.textContent='error');
}}
refresh(); setInterval(refresh, 30000);
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    # Hostile clients routinely vanish mid-response; the resulting
    # BrokenPipe/Reset tracebacks are noise, not errors — swallow them.
    def handle_one_request(self):
        try:
            super().handle_one_request()
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True

    store: Store = None  # type: ignore[assignment]
    billing: dict = {}  # stripe config, set in main(); empty -> billing off
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    # -- helpers ------------------------------------------------------------
    def client_ip(self) -> str:
        return self.client_address[0]

    def read_body(self, cap: int) -> bytes | None:
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length > cap or length < 0:
            return None
        data = bytearray()
        while len(data) < length:
            chunk = self.rfile.read(min(CHUNK, length - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        return bytes(data)

    def send_json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # -- routing ------------------------------------------------------------
    def do_GET(self):
        self.connection.settimeout(30)
        path = self.path.split("?", 1)[0]
        if path == "/health":
            return self.send_json({"status": "ok"})
        if path == "/stats":
            return self.send_json(self.store.stats())
        if path == "/index.json":
            return self._send_index()
        if path == "/admin/gc":
            return self._admin_gc()
        if path == "/" or path == "/ui":
            body = LANDING.format().encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path.startswith("/packages/"):
            return self._serve_package(path[len("/packages/"):])
        if path == "/mcp":
            return self._mcp_list()
        if re.match(r"^/mcp/[^/]+/install$", path):
            return self._mcp_install(path.split("/")[2])
        if re.match(r"^/mcp/[^/]+$", path):
            return self._mcp_detail(path.split("/")[2])
        if path == "/billing/status":
            user = self._authorized_user()
            if not user:
                return self.send_json({"error": "authentication required"}, 401)
            tier = self.store.user_tier(user)
            return self.send_json({
                "user": user,
                "tier": tier,
                "quota_bytes": TIER_QUOTAS[tier],
                "orgs": self.store.user_orgs(user),
            })
        m = re.match(r"^/orgs/([^/]+)$", path)
        if m:
            return self._org_detail(urllib.parse.unquote(m.group(1)))
        if path == "/audit/download":
            return self._audit_download(self.path.split("?", 1)[1] if "?" in self.path else "")
        self.send_json({"error": "not found"}, 404)

    def _admin_gc(self):
        user = self._authorized_user()
        if not user:
            return self.send_json({"error": "authentication required"}, 401)
        dry_run = not any("execute=1" in q for q in self.path.split("?")[1].split("&") if "?" in self.path)
        report = self.store.garbage_collect_locked(dry_run=dry_run)
        self.send_json(report)

    def _send_index(self):
        body = self.store.index()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized_user(self) -> str | None:
        return self.store.authenticate(self.headers.get("Authorization", ""))

    def _package_delete(self, fname: str):
        user = self._authorized_user()
        if not user:
            return self.send_json({"error": "authentication required"}, 401)
        path = os.path.join(self.store.pkg_dir, fname)
        if not os.path.isfile(path):
            return self.send_json({"error": "package not found"}, 404)
        meta = self.store.get_meta(fname)
        if meta.get("owner") and meta["owner"] != user:
            return self.send_json({"error": "forbidden"}, 403)
        self.store.soft_delete(fname, user)
        self.send_json({"ok": True, "file": fname})

    def _serve_package(self, fname: str):
        fname = os.path.basename(fname)
        full = os.path.join(self.store.pkg_dir, fname)
        is_sidecar = bool(SAFE_SIDECAR.match(fname))
        is_pack = bool(SAFE_PACK.match(fname))
        if not (SAFE_FILE.match(fname) or is_pack or is_sidecar) or not os.path.isfile(full):
            return self.send_json({"error": "package not found"}, 404)
        # Policy-gated promotion (roadmap #8): a deny-listed artifact must not
        # be served even when requested by name. Revoked/Deleted always fail
        # closed; Quarantined is served only under an allow_untrusted policy.
        if SAFE_FILE.match(fname) and not is_pack and not is_sidecar:
            # Integrity gate (roadmap #13), checked BEFORE the embedded state:
            # corruption rewrites the blob's own lifecycle footer, so a bit-
            # rotted or tampered artifact must be refused regardless of what
            # state its (possibly rewritten) footer claims. Auto-quarantine:
            # corrupt => 410, served only when integrity holds AND the state
            # permits.
            ok, _detail = verify_integrity(full)
            if not ok:
                return self.send_json(
                    {"error": "artifact integrity check failed (corrupt)"}, 410
                )
            state, allow = artifact_lifecycle(full)
            if state in ("Revoked", "Deleted"):
                return self.send_json(
                    {"error": f"artifact is {state} and unavailable for download"}, 410
                )
            if state == "Quarantined" and not allow:
                return self.send_json(
                    {"error": "artifact is quarantined and not allowed for download"}, 410
                )
        meta = self.store.get_meta(fname)
        size = os.path.getsize(full)
        rng = self.headers.get("Range")
        start, end = 0, size - 1
        if rng and rng.startswith("bytes="):
            try:
                first, last = rng[6:].split("-", 1)
                if first == "" and last != "":
                    # RFC 7233 suffix range: final <last> bytes of the body.
                    start = max(0, size - min(int(last), size))
                elif first != "":
                    start = int(first)
                    # Open-ended "N-" runs to EOF.
                    end = size - 1 if last == "" else int(last)
                else:
                    raise ValueError("bytes=- is not a valid range")
            except ValueError:
                return self.send_json({"error": "bad range"}, 400)
        # RFC 7233: a last-byte-pos past EOF means "clamp to final byte",
        # not an error — resumable clients legitimately overshoot.
        end = min(end, size - 1)
        if start < 0 or start > end:
            return self.send_json({"error": "range not satisfiable"}, 416)
        if meta.get("private") and not is_sidecar:
            user = self._authorized_user()
            owner = meta.get("owner", "")
            allowed = user == owner
            if not allowed and owner.startswith("org:") and user:
                allowed = self.store.org_role(owner[4:], user) is not None
            if not allowed:
                return self.send_json({"error": "private package"}, 401)
            if self.store.month_served(user) + (end - start + 1) > self.store.quota_for(user):
                return self.send_json(
                    {"error": "monthly transfer quota exceeded (upgrade tier)"}, 402
                )
            self.store.charge_bytes(user, end - start + 1, size)
            self.store.record_audit(
                user, "private_download", fname,
                org=owner[4:] if owner.startswith("org:") else None,
            )
        elif not is_pack and not is_sidecar:
            # Anonymous public pull: count toward the public SISR story.
            # Runtime packs stay out of the savings narrative on purpose.
            self.store.bump_stats(end - start + 1, size)
        code = 206 if (rng and (start != 0 or end != size - 1)) else 200
        self.send_response(code)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(end - start + 1))
        self.send_header("Accept-Ranges", "bytes")
        self.end_headers()
        with open(full, "rb") as f:
            f.seek(start)
            remaining = end - start + 1
            while remaining > 0:
                chunk = f.read(min(CHUNK, remaining))
                if not chunk:
                    break
                self.wfile.write(chunk)
                remaining -= len(chunk)

    def do_POST(self):
        self.connection.settimeout(60)
        path = self.path.split("?", 1)[0]
        if path in ("/auth/register", "/auth/login"):
            body = self.read_body(4096)
            if body is None:
                return self.send_json({"error": "body too large"}, 413)
            try:
                payload = json.loads(body.decode("utf-8", "replace"))
                if not isinstance(payload, dict):
                    raise ValueError
            except (ValueError, RecursionError):
                # Deeply nested arrays raise RecursionError, not ValueError.
                return self.send_json({"error": "invalid json"}, 400)
            return self._auth(payload, login=(path == "/auth/login"))
        if path == "/waitlist":
            body = self.read_body(1024)
            if body is None:
                return self.send_json({"error": "body too large"}, 413)
            try:
                parsed = json.loads(body.decode())
                if not isinstance(parsed, dict):
                    raise ValueError
                email = str(parsed.get("email", ""))
            except (ValueError, RecursionError):
                return self.send_json({"error": "invalid json"}, 400)
            ok, msg = self.store.waitlist_add(email, self.client_ip())
            if ok:
                return self.send_json({"message": msg})
            code = 429 if "rate limited" in msg else 400
            return self.send_json({"error": msg}, code)
        if path == "/mcp":
            return self._mcp_upload()
        if path == "/billing/webhook":
            return self._billing_webhook()
        if path == "/billing/checkout":
            body = self.read_body(2048)
            return self._billing_checkout(body)
        if path == "/orgs":
            body = self.read_body(2048)
            return self._org_create(body)
        m = re.match(r"^/orgs/([^/]+)/members$", path)
        if m:
            body = self.read_body(2048)
            return self._org_member_add(urllib.parse.unquote(m.group(1)), body)
        if path == "/" or path.startswith("/packages/"):
            return self._upload()
        self.send_json({"error": "not found"}, 404)

    def do_DELETE(self):
        self.connection.settimeout(30)
        path = self.path.split("?", 1)[0]
        m = re.match(r"^/orgs/([^/]+)/members/([^/]+)$", path)
        if m:
            return self._org_member_remove(
                urllib.parse.unquote(m.group(1)), urllib.parse.unquote(m.group(2))
            )
        m = re.match(r"^/packages/([^/]+)$", path)
        if m:
            return self._package_delete(urllib.parse.unquote(m.group(1)))
        self.send_json({"error": "not found"}, 404)

    def _auth(self, payload: dict, login: bool):
        username = str(payload.get("username", ""))
        password = str(payload.get("password", ""))
        if login and self.store.bootstrap_open_uploads():
            return self.send_json({"error": "no users yet — register first"}, 400)
        if login:
            user = self.store.login(username, password, None)
            if not user:
                return self.send_json({"error": "invalid credentials"}, 401)
            return self.send_json({"username": user, "note": "use your registration token"})
        ok, msg = self.store.register(username, password)
        if not ok:
            return self.send_json({"error": msg}, 400)
        self.store.record_audit(username, "register")
        return self.send_json({"username": username, "token": msg})

    # ---- json body helper ---------------------------------------------------
    def _read_json(self, raw: bytes | None) -> dict | None:
        if raw is None:
            return None
        try:
            parsed = json.loads(raw.decode("utf-8", "replace"))
            return parsed if isinstance(parsed, dict) else None
        except (ValueError, RecursionError):
            return None

    # ---- billing -------------------------------------------------------------
    def _billing_checkout(self, raw: bytes | None):
        user = self._authorized_user()
        if not user:
            return self.send_json({"error": "authentication required"}, 401)
        cfg = self.billing
        if not cfg.get("secret_key") or not cfg.get("webhook_secret"):
            return self.send_json(
                {"error": "billing not configured on this registry "
                          "(--stripe-secret-key / --stripe-webhook-secret)"}, 501
            )
        payload = self._read_json(raw)
        if payload is None:
            return self.send_json({"error": "invalid json"}, 400)
        plan = str(payload.get("plan", ""))
        price = cfg.get(f"price_{plan}")
        if plan not in PAID_TIERS or not price:
            return self.send_json({"error": f"plan must be one of {list(PAID_TIERS)}"}, 400)
        params = {
            "mode": "subscription",
            "line_items[0][price]": price,
            "line_items[0][quantity]": 1,
            "success_url": cfg["success_url"],
            "cancel_url": cfg["cancel_url"],
            "client_reference_id": user,
            "metadata[user]": user,
            "metadata[plan]": plan,
            "subscription_data[metadata][user]": user,
            "subscription_data[metadata][plan]": plan,
        }
        try:
            session = stripe_api("checkout/sessions", params, cfg["secret_key"])
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")[:200]
            return self.send_json({"error": f"stripe error: {detail}"}, 502)
        except (urllib.error.URLError, TimeoutError, OSError):
            return self.send_json({"error": "stripe unreachable"}, 502)
        self.store.record_audit(user, "billing_checkout_started", plan)
        return self.send_json({"url": session.get("url"), "id": session.get("id")})

    def _billing_webhook(self):
        """Stripe events. Signature-verified; unconfigured secret -> 503."""
        cfg = self.billing
        secret = cfg.get("webhook_secret")
        if not secret:
            return self.send_json({"error": "webhooks not configured"}, 503)
        declared = int(self.headers.get("Content-Length", 0) or 0)
        if declared <= 0 or declared > 1 << 20:
            return self.send_json({"error": "bad body size"}, 400)
        raw = self.rfile.read(declared)
        sig = self.headers.get("Stripe-Signature", "")
        if not verify_stripe_signature(raw, sig, secret):
            self.store.record_audit("__stripe__", "billing_webhook_bad_signature")
            return self.send_json({"error": "invalid signature"}, 400)
        try:
            event = json.loads(raw.decode("utf-8", "replace"))
        except ValueError:
            return self.send_json({"error": "invalid event"}, 400)
        etype = str(event.get("type", ""))
        obj = event.get("data", {}).get("object", {})
        meta = obj.get("metadata", {}) or {}
        user = str(meta.get("user", ""))
        if not SAFE_USER.match(user):
            return self.send_json({"received": True})  # not ours; ack silently
        if etype == "checkout.session.completed":
            plan = str(meta.get("plan", ""))
            if plan in PAID_TIERS and obj.get("payment_status") == "paid":
                self.store.set_tier(user, plan)
                return self.send_json({"applied": f"{user}->{plan}"})
        elif etype == "customer.subscription.deleted":
            self.store.set_tier(user, "free")
            return self.send_json({"applied": f"{user}->free"})
        return self.send_json({"received": True})

    # ---- orgs ----------------------------------------------------------------
    def _org_create(self, raw: bytes | None):
        user = self._authorized_user()
        if not user:
            return self.send_json({"error": "authentication required"}, 401)
        payload = self._read_json(raw)
        if payload is None:
            return self.send_json({"error": "invalid json"}, 400)
        ok, msg = self.store.create_org(str(payload.get("name", "")), user)
        return self.send_json(
            {"status": msg} if ok else {"error": msg},
            200 if ok else 400,
        )

    def _org_detail(self, name: str):
        user = self._authorized_user()
        if not user:
            return self.send_json({"error": "authentication required"}, 401)
        org = self.store.get_org(name)
        if not org:
            return self.send_json({"error": "no such org"}, 404)
        role = self.store.org_role(name, user)
        if role is None:
            # Existence probe denied without membership.
            return self.send_json({"error": "no such org"}, 404)
        return self.send_json({
            "name": name,
            "your_role": role,
            "owner": org["owner"],
            "members": org.get("members", {}),
            "created": org.get("created"),
        })

    def _org_member_add(self, org: str, raw: bytes | None):
        user = self._authorized_user()
        if not user:
            return self.send_json({"error": "authentication required"}, 401)
        payload = self._read_json(raw)
        if payload is None:
            return self.send_json({"error": "invalid json"}, 400)
        ok, msg = self.store.add_member(
            org, user, str(payload.get("username", "")), str(payload.get("role", ""))
        )
        return self.send_json(
            {"status": msg} if ok else {"error": msg},
            200 if ok else (404 if "no such" in msg else 400 if "role must" in msg or "invalid" in msg else 403),
        )

    def _org_member_remove(self, org: str, member: str):
        user = self._authorized_user()
        if not user:
            return self.send_json({"error": "authentication required"}, 401)
        ok, msg = self.store.remove_member(org, user, member)
        return self.send_json(
            {"status": msg} if ok else {"error": msg},
            200 if ok else (404 if "no such" in msg else 400 if "cannot be removed" in msg else 403),
        )

    # ---- audit trail -----------------------------------------------------------
    def _audit_download(self, query: str):
        user = self._authorized_user()
        if not user:
            return self.send_json({"error": "authentication required"}, 401)
        qs = urllib.parse.parse_qs(query)
        month = (qs.get("month") or [""])[0]
        org = (qs.get("org") or [None])[0]
        if not SAFE_MONTH.match(month):
            return self.send_json({"error": "month must be YYYY-MM"}, 400)
        if org is not None:
            # Org trail entitlement follows the ORG OWNER's plan — admins
            # without their own Team seat still serve the org they manage.
            role = self.store.org_role(org, user)
            if role not in ("owner", "admin"):
                return self.send_json({"error": "owner/admin role required"}, 403)
            owner_tier = self.store.user_tier(self.store.get_org(org)["owner"])
            if owner_tier != "team":
                return self.send_json(
                    {"error": "org audit log requires the org owner to be on Team"}, 402
                )
            records = self.store.read_audit(month, org=org)
        else:
            if self.store.user_tier(user) != "team":
                return self.send_json(
                    {"error": "audit log download requires the Team plan"}, 402
                )
            records = self.store.read_audit(month, actor=user)
        records.sort(key=lambda r: r.get("ts", ""))
        records.sort(key=lambda r: r.get("ts", ""))
        body = ("\n".join(json.dumps(r) for r in records) + "\n").encode() \
            if records else b""
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson")
        self.send_header("Content-Disposition",
                         f'attachment; filename="erebus-audit-{month}.jsonl"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _mcp_list(self):
        servers = self.store.mcp_index()
        self.send_json({"mcp_servers": servers, "count": len(servers)})

    def _mcp_detail(self, name: str):
        meta = self.store.get_mcp(name)
        if meta is None:
            return self.send_json({"error": "MCP server not found"}, 404)
        self.send_json(meta)

    def _mcp_install(self, name: str):
        meta = self.store.get_mcp(name)
        if meta is None:
            return self.send_json({"error": "MCP server not found"}, 404)
        runtime = meta.get("runtime", "python")
        pkg_file = meta.get("file", "")
        install_cmd = f'erebus pull {pkg_file} && erebus run {pkg_file}'
        body = f"""# Install {name}
# {meta.get('description', '')}
# Runtime: {runtime}
# Tools: {', '.join(meta.get('tools', []))}
{install_cmd}
""".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _mcp_upload(self):
        self.close_connection = True
        open_mode = self.store.bootstrap_open_uploads()
        owner = self._authorized_user() if not open_mode else "__anon__"
        if not open_mode and owner is None:
            return self.send_json(
                {"error": "authentication required — register via /auth/register"}, 401
            )
        ctype = self.headers.get("Content-Type", "")
        if "boundary=" not in ctype:
            return self.send_json({"error": "expected multipart/form-data"}, 400)
        declared = int(self.headers.get("Content-Length", 0) or 0)
        if declared > self.store.upload_cap:
            return self.send_json({"error": "payload exceeds upload cap"}, 413)
        boundary = ctype.split("boundary=", 1)[1].strip('"').encode()

        tmp = os.path.join(self.store.pkg_dir, f".incoming.{uuid.uuid4().hex}")
        fname, nbytes = stream_multipart(self, boundary, tmp, self.store.upload_cap, declared)
        if not fname:
            os.unlink(tmp)
            return self.send_json({"error": "missing file part / filename"}, 400)
        if nbytes > self.store.upload_cap:
            os.unlink(tmp)
            return self.send_json({"error": "upload exceeds --upload-cap"}, 413)
        fname = os.path.basename(fname)
        if not SAFE_FILE.match(fname):
            os.unlink(tmp)
            return self.send_json(
                {"error": "invalid upload filename (want *.erebus)"}, 400
            )
        final = os.path.join(self.store.pkg_dir, fname)
        os.replace(tmp, final)
        self.close_connection = True
        self.store.set_meta(fname, None if open_mode else owner, private=bool(not open_mode and owner != "__anon__"))

        # Extract MCP metadata from JSON body fields or use defaults
        mcp_name = fname[: -len(".erebus")]
        mcp_meta = {
            "name": mcp_name,
            "version": "1.0.0",
            "description": f"MCP server: {mcp_name}",
            "tools": [],
            "transport": "stdio",
            "runtime": "python",
            "tags": [],
            "file": fname,
            "sha256": self.store.sha256_cached(final),
            "size": nbytes,
            "owner": owner,
        }
        self.store.set_mcp(mcp_name, mcp_meta)
        self.store._hash_cache.pop(final, None)
        self.send_json({"status": "ok", "stored": fname, "mcp": mcp_name, "size": nbytes})

    def _upload(self):
        # The body may be huge and we may respond before reading all of it
        # (auth failure, cap exceeded): mark the connection for close so the
        # unread tail is never parsed as a pipelined request.
        self.close_connection = True
        open_mode = self.store.bootstrap_open_uploads()
        owner = self._authorized_user() if not open_mode else "__anon__"
        if not open_mode and owner is None:
            return self.send_json(
                {"error": "authentication required — register via /auth/register"}, 401
            )
        # Optional org publish: X-Erebus-Org header keeps the streamed
        # multipart parser untouched. Developer role required.
        audit_org = None
        if not open_mode:
            org_name = (self.headers.get("X-Erebus-Org") or "").strip()
            if org_name:
                if not SAFE_ORG.match(org_name):
                    return self.send_json({"error": "invalid org name"}, 400)
                if ROLE_ORDER.get(self.store.org_role(org_name, owner), -1) \
                        < ROLE_ORDER["developer"]:
                    return self.send_json(
                        {"error": "developer role required in this org"}, 403
                    )
                owner = f"org:{org_name}"
                audit_org = org_name
        ctype = self.headers.get("Content-Type", "")
        if "boundary=" not in ctype:
            return self.send_json({"error": "expected multipart/form-data"}, 400)
        declared = int(self.headers.get("Content-Length", 0) or 0)
        if declared > self.store.upload_cap:
            return self.send_json({"error": "payload exceeds upload cap"}, 413)
        boundary = ctype.split("boundary=", 1)[1].strip('"').encode()

        # Stream to a unique temp file: concurrent uploads of the same target
        # can never interleave into one another's .part. Reading is bounded by
        # Content-Length — the client keeps the connection open, so waiting
        # for EOF would hang forever.
        declared = int(self.headers.get("Content-Length", 0) or 0)
        tmp = os.path.join(self.store.pkg_dir, f".incoming.{uuid.uuid4().hex}")
        fname, nbytes = stream_multipart(self, boundary, tmp, self.store.upload_cap, declared)
        if not fname:
            os.unlink(tmp)
            return self.send_json({"error": "missing file part / filename"}, 400)
        if nbytes > self.store.upload_cap:
            # The streaming window stops at the cap; storing the head would
            # poison the index with a truncated blob that looks valid.
            os.unlink(tmp)
            return self.send_json({"error": "upload exceeds --upload-cap"}, 413)
        fname = os.path.basename(fname)
        if not (SAFE_FILE.match(fname) or SAFE_PACK.match(fname) or SAFE_SIDECAR.match(fname)):
            os.unlink(tmp)
            return self.send_json(
                {"error": "invalid upload filename (want *.erebus or *.pack[.sha256])"}, 400
            )
        final = os.path.join(self.store.pkg_dir, fname)
        os.replace(tmp, final)
        # Body framing was handled manually (streamed); never let this
        # keep-alive connection be reused with unconsumed trailing bytes.
        self.close_connection = True
        self.store.set_meta(fname, None if open_mode else owner, private=bool(not open_mode and owner != "__anon__"))
        self.store._hash_cache.pop(final, None)
        self.store.record_audit(
            owner if not open_mode else "__anon__", "publish", fname, org=audit_org
        )
        self.send_json({"status": "ok", "stored": fname, "size": nbytes})


def stream_multipart(handler, boundary: bytes, dest: str, cap: int, declared: int):
    """Stream the first file part of a multipart body straight to `dest`.

    Returns (filename, bytes_written). Never holds more than one window of
    the payload in memory, and never reads past `declared` bytes — the
    client may keep the socket open after the body.
    """
    delim = b"\r\n--" + boundary
    first_tok = b"--" + boundary
    fname = None
    written = 0
    consumed = 0
    out = open(dest, "wb")
    state = "preamble"
    window = b""
    try:
        while consumed < declared and written <= cap:
            chunk = handler.rfile.read(min(CHUNK, declared - consumed))
            consumed += len(chunk)
            window += chunk
            # Drain every state transition the current window allows:
            # a single read can carry the boundary AND headers AND data,
            # and the final read may arrive with no trailing chunk.
            progressed = True
            while progressed:
                progressed = False
                if state == "preamble":
                    idx = window.find(first_tok)
                    if idx != -1:
                        window = window[idx + len(first_tok):]
                        state = "headers"
                        progressed = True
                elif state == "headers":
                    hdr_end = window.find(b"\r\n\r\n")
                    if hdr_end != -1:
                        m = re.search(rb'filename="([^"]+)"', window[:hdr_end])
                        fname = (
                            m.group(1).decode("utf-8", "replace") if m else None
                        )
                        window = window[hdr_end + 4:]
                        state = "data"
                        progressed = True
                    elif len(window) > 64 * 1024:
                        return fname, written
                elif state == "data":
                    keep = max(0, len(window) - (len(delim) + 4))
                    if keep > 0:
                        out.write(window[:keep])
                        written += keep
                        window = window[keep:]
                    pos = window.find(delim)
                    if pos != -1:
                        out.write(window[:pos])
                        written += pos
                        after = window[pos + len(delim):]
                        if after.startswith(b"--"):
                            return fname, written
                        state = "headers"
                        window = after
                        progressed = True
            if not chunk:
                break
    finally:
        out.close()
    return fname, written


def main() -> None:
    ap = argparse.ArgumentParser(description="erebus registry v2")
    ap.add_argument("--dir", required=True)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--quota-gb", type=float, default=20.0,
                    help="monthly transfer quota for free-tier authenticated pulls")
    ap.add_argument("--upload-cap-gb", type=float, default=70.0,
                    help="hard cap on any single upload")
    ap.add_argument("--require-auth", action="store_true",
                    help="force strict auth: all uploads require a token, "
                         "even with --allow-anon-uploads")
    ap.add_argument("--allow-anon-uploads", action="store_true",
                    help="OPT-IN fail-open: permit anonymous uploads before the "
                         "first user registers. Off by default — the registry is "
                         "fail-closed, so mutations require auth unless this is set")
    ap.add_argument("--verify", action="store_true",
                    help="Run a one-shot integrity scan of all stored blobs and exit")
    ap.add_argument("--tls-cert",
                    help="path to TLS certificate file (PEM)")
    ap.add_argument("--tls-key",
                    help="path to TLS private key file (PEM)")
    ap.add_argument("--stripe-secret-key",
                    default=os.environ.get("STRIPE_SECRET_KEY"),
                    help="Stripe secret key (or STRIPE_SECRET_KEY env)")
    ap.add_argument("--stripe-webhook-secret",
                    default=os.environ.get("STRIPE_WEBHOOK_SECRET"),
                    help="Stripe webhook signing secret (or env)")
    ap.add_argument("--stripe-price-pro",
                    default=os.environ.get("STRIPE_PRICE_PRO"),
                    help="Stripe price ID for the Pro plan")
    ap.add_argument("--stripe-price-team",
                    default=os.environ.get("STRIPE_PRICE_TEAM"),
                    help="Stripe price ID for the Team plan")
    ap.add_argument("--billing-success-url",
                    default="https://registry.erebus.dev/billing/success",
                    help="redirect target after Stripe Checkout payment")
    ap.add_argument("--billing-cancel-url",
                    default="https://registry.erebus.dev/billing/cancelled",
                    help="redirect target after Checkout cancellation")
    args = ap.parse_args()

    if bool(args.tls_cert) != bool(args.tls_key):
        ap.error("--tls-cert and --tls-key must be used together")

    Handler.store = Store(
        args.dir, int(args.quota_gb * 1e9), int(args.upload_cap_gb * 1e9),
        require_auth=args.require_auth,
        allow_anon_uploads=args.allow_anon_uploads,
    )
    Handler.billing = {
        "secret_key": args.stripe_secret_key,
        "webhook_secret": args.stripe_webhook_secret,
        "price_pro": args.stripe_price_pro,
        "price_team": args.stripe_price_team,
        "success_url": args.billing_success_url,
        "cancel_url": args.billing_cancel_url,
    }
    class Server(ThreadingHTTPServer):
        # Default listen backlog is 5; fleet-style bursts of concurrent
        # pulls/uploads otherwise get connection resets.
        request_queue_size = 128
        daemon_threads = True

    server = Server((args.host, args.port), Handler)

    if args.tls_cert and args.tls_key:
        import ssl
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(args.tls_cert, args.tls_key)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        scheme = "https"
    elif args.host != "127.0.0.1":
        print(
            "WARNING: Serving on non-localhost without TLS. Tokens traverse "
            "plaintext. Use --tls-cert/--tls-key or a reverse proxy.",
            flush=True,
        )
        scheme = "http"
    else:
        scheme = "http"

    if args.verify:
        store = Handler.store
        print("Running integrity scan...", flush=True)
        snapshot = store.scan_integrity_locked()
        ok_count = sum(1 for v in snapshot.values() if v.get("ok"))
        bad_count = len(snapshot) - ok_count
        print(f"Scanned {len(snapshot)} blobs: {ok_count} ok, {bad_count} corrupt", flush=True)
        if bad_count > 0:
            print("Corrupt blobs:", flush=True)
            for name, info in snapshot.items():
                if not info.get("ok"):
                    print(f"  {name}: {info.get('detail')}", flush=True)
            raise SystemExit(1)
        raise SystemExit(0)

    bootstrap = Handler.store.bootstrap_open_uploads()
    billing_state = ("on" if Handler.billing.get("secret_key")
                     and Handler.billing.get("webhook_secret") else "off")
    print(
        f"erebus registry v2 on {scheme}://{args.host}:{args.port} dir={args.dir} "
        f"quota={args.quota_gb}GB/month cap={args.upload_cap_gb}GB/upload "
        f"auth={'required (strict, --require-auth)' if args.require_auth else 'OPEN — anonymous uploads (opt-in --allow-anon-uploads)' if bootstrap else 'required (fail-closed by default)'} "
        f"billing={billing_state}",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
