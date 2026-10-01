"""HTTP Handler for the erebus registry (stdlib only)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler

from erebus_registry.artifacts import parse_gguf
from erebus_registry.auth import (
    _get_cached_discovery,
    _jwt_verify_id_token,
    stripe_api,
    verify_stripe_signature,
)
from erebus_registry.util import (
    CHUNK,
    PAID_TIERS,
    REGISTRY_VERSION,
    SAFE_EMAIL,
    SAFE_FILE,
    SAFE_MONTH,
    SAFE_ORG,
    SAFE_PACK,
    SAFE_SIDECAR,
    SAFE_USER,
    TIER_QUOTAS,
    atomic_write,
    month_now,
)

# Populated by registry_server.main before serving.
STARTED_AT: str | None = None
START_TS: float = 0.0

# Landing / dashboard HTML are defined in registry_server and injected.
LANDING = ""
DASHBOARD = ""

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
        if path == "/sla":
            return self._sla()
        if path == "/auth/sso/config":
            return self._sso_config()
        if path == "/auth/sso/start":
            return self._sso_start()
        if path == "/auth/sso/callback":
            return self._sso_callback()
        if path == "/replicate/index":
            return self._replicate_index()
        if path.startswith("/replicate/blob/"):
            return self._replicate_blob(path[len("/replicate/blob/"):])
        if path == "/attestations":
            return self._attest_query()
        if path == "/log/checkpoint":
            return self._log_checkpoint()
        if path == "/log/key":
            return self._log_key()
        if path == "/log/proof":
            return self._log_proof()
        if path == "/log/consistency":
            return self._log_consistency()
        if path == "/machines":
            return self._machine_list()
        if path == "/stats":
            return self.send_json(self.store.stats())
        if path == "/index.json":
            return self._send_index()
        if path == "/admin/gc":
            return self._admin_gc()
        if path == "/admin/scan":
            return self._admin_scan()
        if path == "/webhooks" and self.command == "GET":
            return self._webhook_list()
        if path == "/webhooks" and self.command == "POST":
            body = self.read_body(2048)
            return self._webhook_add(body)
        if path.startswith("/webhooks/") and self.command == "DELETE":
            return self._webhook_remove(urllib.parse.unquote(path[len("/webhooks/"):]))
        if path == "/admin/backup":
            return self._admin_backup()
        if path == "/admin/restore" and self.command == "POST":
            return self._admin_restore(self.read_body())
        if path == "/" or path == "/ui":
            body = LANDING.format().encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/ui/dashboard":
            body = DASHBOARD.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path.startswith("/packages/"):
            return self._package_delete(path[len("/packages/"):])
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

    def _admin_backup(self):
        user = self._authorized_user()
        if not user:
            return self.send_json({"error": "authentication required"}, 401)
        manifest = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "packages": [],
        }
        for name in sorted(os.listdir(self.store.pkg_dir)):
            if not name.endswith(".erebus"):
                continue
            path = os.path.join(self.store.pkg_dir, name)
            if not os.path.isfile(path):
                continue
            meta = self.store.get_meta(name)
            entry = {
                "file": name,
                "sha256": self.store.sha256_cached(path),
                "size": os.path.getsize(path),
                "meta": meta,
                "integrity": self.store.integrity.get(name, {}),
            }
            manifest["packages"].append(entry)
        self.send_json(manifest)

    def _admin_restore(self, raw: bytes | None):
        user = self._authorized_user()
        if not user:
            return self.send_json({"error": "authentication required"}, 401)
        payload = self._read_json(raw)
        if payload is None:
            return self.send_json({"error": "invalid json"}, 400)
        packages = payload.get("packages", [])
        restored = []
        for entry in packages:
            fname = entry.get("file")
            if not fname or not fname.endswith(".erebus"):
                continue
            src = os.path.join(self.store.pkg_dir, fname)
            if os.path.isfile(src):
                continue
            meta = entry.get("meta", {})
            self.store.set_meta(fname, meta.get("owner"), bool(meta.get("private")), bool(meta.get("deleted")), meta.get("deleted_at"))
            restored.append(fname)
        self.store.record_audit(user, "backup_restore", f"{len(restored)} packages")
        return self.send_json({"restored": restored})

    def _send_index(self):
        body = self.store.index()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorized_user(self) -> str | None:
        return self.store.authenticate(self.headers.get("Authorization", ""))

    # ---- SSO handlers ---------------------------------------------------
    def _sla(self):
        uptime = int(time.time() - START_TS) if START_TS else 0
        stats = self.store.stats()
        integrity = self.store.integrity
        ok_count = sum(1 for v in integrity.values() if v.get("ok"))
        bad_count = len(integrity) - ok_count
        self.send_json({
            "status": "operational",
            "uptime_seconds": uptime,
            "started_at": STARTED_AT,
            "packages": stats.get("packages", 0),
            "integrity": {"ok": ok_count, "corrupt": bad_count},
            "sso_enabled": self.store.sso_enabled(),
            "version": REGISTRY_VERSION,
        })

    def _sso_config(self):
        cfg = self.store.get_sso_config()
        if not cfg:
            self.send_json({"enabled": False})
            return
        # Never expose client_secret
        self.send_json({
            "enabled": True,
            "provider": cfg.get("provider_name", "OIDC"),
            "issuer": cfg.get("issuer"),
            "client_id": cfg.get("client_id"),
        })

    def _sso_start(self):
        cfg = self.store.get_sso_config()
        if not cfg:
            self.send_json({"error": "SSO not configured"}, 400)
            return
        issuer = cfg["issuer"]
        client_id = cfg["client_id"]
        disc = _get_cached_discovery(issuer)
        if not disc:
            self.send_json({"error": "SSO discovery failed"}, 502)
            return
        auth_endpoint = disc.get("authorization_endpoint")
        if not auth_endpoint:
            self.send_json({"error": "SSO provider missing authorization_endpoint"}, 502)
            return
        state = secrets.token_urlsafe(24)
        redirect_uri = self._sso_redirect_uri()
        params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "openid email profile",
            "state": state,
        }
        auth_url = auth_endpoint + "?" + urllib.parse.urlencode(params)
        self.send_json({"auth_url": auth_url})

    def _sso_callback(self):
        cfg = self.store.get_sso_config()
        if not cfg:
            self.send_json({"error": "SSO not configured"}, 400)
            return
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        code = qs.get("code", [None])[0]
        state = qs.get("state", [None])[0]
        if not code:
            self.send_json({"error": "missing code"}, 400)
            return
        issuer = cfg["issuer"]
        client_id = cfg["client_id"]
        client_secret = cfg["client_secret"]
        disc = _get_cached_discovery(issuer)
        if not disc:
            self.send_json({"error": "SSO discovery failed"}, 502)
            return
        token_endpoint = disc.get("token_endpoint")
        if not token_endpoint:
            self.send_json({"error": "SSO provider missing token_endpoint"}, 502)
            return
        redirect_uri = self._sso_redirect_uri()
        data = urllib.parse.urlencode({
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "client_secret": client_secret,
        }).encode("ascii")
        try:
            req = urllib.request.Request(
                token_endpoint,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                token_resp = json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            self.send_json({"error": f"token exchange failed: {e}"}, 502)
            return
        id_token = token_resp.get("id_token")
        if not id_token:
            self.send_json({"error": "no id_token in response"}, 502)
            return
        jwks = disc.get("_jwks")
        if not jwks:
            self.send_json({"error": "no JWKS available"}, 502)
            return
        claims = _jwt_verify_id_token(id_token, client_id, issuer, jwks)
        if not claims:
            self.send_json({"error": "ID token verification failed"}, 401)
            return
        # Map claims to local user
        email = claims.get("email")
        sub = claims.get("sub")
        if not email and not sub:
            self.send_json({"error": "ID token missing email/sub"}, 401)
            return
        # Username from email local-part, sanitized
        username = None
        if email:
            local = email.split("@")[0]
            username = re.sub(r"[^a-z0-9_-]", "", local.lower())
            if not username or not SAFE_USER.match(username):
                username = None
        if not username and sub:
            username = f"sso_{sub[:16]}"
        # Find existing user by email or create
        users = self.store._load(self.store.users_path, {}).get("users", {})
        target_user = None
        if email:
            for u, rec in users.items():
                if rec.get("email") == email:
                    target_user = u
                    break
        if target_user:
            user = target_user
        elif username and username not in users:
            user = username
            # Auto-provision with no password (SSO-only)
            salt = secrets.token_bytes(16)
            token = secrets.token_hex(32)
            rec = {
                "salt": salt.hex(),
                "pwhash": "",
                "token_hash": hashlib.sha256(token.encode()).hexdigest(),
                "tier": "free",
                "created": time.time(),
                "email": email,
            }
            with self.store.lock:
                users[user] = rec
                self.store._save_locked(self.store.users_path, {"users": users})
            self.store.record_audit(user, "sso_provision", f"email={email}")
        elif username:
            user = username
        else:
            self.send_json({"error": "could not determine username"}, 500)
            return
        # Generate bearer token for this session
        token = secrets.token_hex(32)
        with self.store.lock:
            users = self.store._load(self.store.users_path, {}).get("users", {})
            users[user]["token_hash"] = hashlib.sha256(token.encode()).hexdigest()
            self.store._save_locked(self.store.users_path, {"users": users})
        self.store.record_audit(user, "sso_login", f"provider={cfg.get('provider_name','OIDC')}")
        self.send_json({"username": user, "token": token})

    def _sso_redirect_uri(self) -> str:
        # Build redirect URI from Host header or configured base_url
        host = self.headers.get("Host", "")
        # If we have a configured base_url, use it; otherwise infer from Host
        cfg = self.store.get_sso_config()
        if cfg and cfg.get("base_url"):
            base = cfg["base_url"].rstrip("/")
            return f"{base}/auth/sso/callback"
        # Fallback: infer from Host header
        scheme = "https" if self.headers.get("X-Forwarded-Proto") == "https" else "http"
        return f"{scheme}://{host}/auth/sso/callback"

    # ---- Replication handlers -----------------------------------------
    def _replicate_index(self):
        # Optional: require replication token if configured
        cfg = self.store.get_sso_config()
        # Replication token can be stored in sso.json as "replicate_token"
        replicate_token = cfg.get("replicate_token") if cfg else None
        if replicate_token:
            auth = self.headers.get("Authorization", "")
            token_header = self.headers.get("X-Replicate-Token", "")
            token = None
            if auth.startswith("Bearer replicate:"):
                token = auth[len("Bearer replicate:"):].strip()
            elif token_header:
                token = token_header
            if token != replicate_token:
                self.send_json({"error": "replication token required"}, 403)
                return

        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        after = int(qs.get("after", ["0"])[0]) if qs.get("after") else 0
        entries, next_seq = self.store.replication_journal(after)
        self.send_json({
            "leader": socket.gethostname(),
            "journal": entries,
            "next_seq": next_seq,
        })

    def _replicate_blob(self, fname: str):
        fname = os.path.basename(fname)
        full = os.path.join(self.store.pkg_dir, fname)
        if not SAFE_FILE.match(fname) or not os.path.isfile(full):
            self.send_json({"error": "blob not found"}, 404)
            return
        # Same token check as _replicate_index
        cfg = self.store.get_sso_config()
        replicate_token = cfg.get("replicate_token") if cfg else None
        if replicate_token:
            auth = self.headers.get("Authorization", "")
            token_header = self.headers.get("X-Replicate-Token", "")
            token = None
            if auth.startswith("Bearer replicate:"):
                token = auth[len("Bearer replicate:"):].strip()
            elif token_header:
                token = token_header
            if token != replicate_token:
                self.send_json({"error": "replication token required"}, 403)
                return
        # Stream the blob
        try:
            stat = os.stat(full)
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(stat.st_size))
            self.end_headers()
            with open(full, "rb") as f:
                while chunk := f.read(CHUNK):
                    self.wfile.write(chunk)
        except Exception:
            self.send_json({"error": "blob read failed"}, 500)

    def _package_delete(self, fname: str):
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
        if path == "/webhooks/github":
            body = self.read_body(65536)
            return self._provider_webhook("github", body)
        if path == "/webhooks/gitlab":
            body = self.read_body(65536)
            return self._provider_webhook("gitlab", body)
        if path == "/webhooks/gitea":
            body = self.read_body(65536)
            return self._provider_webhook("gitea", body)
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
        if path == "/attestations":
            body = self.read_body(1_000_000)
            return self._attest_publish(body)
        if path == "/log/anchor":
            return self._log_anchor()
        if path == "/machines/enroll":
            body = self.read_body(4096)
            return self._machine_enroll(body)
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
        m = re.match(r"^/webhooks/(.+)$", path)
        if m:
            return self._webhook_remove(urllib.parse.unquote(m.group(1)))
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
        ok, msg = self.store.register(
            username, password, ed25519_pub=str(payload.get("ed25519_pub") or "").strip() or None
        )
        if not ok:
            return self.send_json({"error": msg}, 400)
        self.store.record_audit(username, "register")
        return self.send_json({"username": username, "token": msg})

    # ---- attestations echo ------------------------------------------------
    def _attest_publish(self, raw: bytes | None):
        # Fail-closed: attestation uploads require a valid token and a well-
        # formed in-toto document. Idempotent re-posts return the same id.
        user = self._authorized_user()
        if not user:
            return self.send_json({"error": "authentication required"}, 401)
        att = self._read_json(raw)
        if att is None:
            return self.send_json({"error": "invalid json"}, 400)
        ok, id_or_err, already = self.store.record_attestation(user, att, raw)
        if not ok:
            return self.send_json({"error": id_or_err}, 400)
        # The leaf position, a signed checkpoint and (when the tree head is
        # anchored) the TSA token: everything `verify-attest --proof` needs
        # offline. Idempotent re-posts get a fresh checkpoint, same leaf.
        position = self.store.log_position(id_or_err)
        return self.send_json(
            {"id": id_or_err, "recorded": not already, "log": position},
            200 if already else 201,
        )

    # ---- transparency log (public: proofs leak no receipt content) --------
    def _log_checkpoint(self):
        checkpoint = self.store.log.checkpoint()
        anchor = self.store.log.latest_anchor()
        return self.send_json({"checkpoint": checkpoint, "anchor": anchor,
                               "key": self.store.log.key_info()})

    def _log_key(self):
        return self.send_json(self.store.log.key_info())

    def _log_proof(self):
        qs = urllib.parse.parse_qs(self.path.split("?", 1)[1] if "?" in self.path else "")
        leaf = (qs.get("leaf") or [""])[0].strip().removeprefix("sha256:")
        if len(leaf) != 64 or any(c not in "0123456789abcdef" for c in leaf.lower()):
            return self.send_json({"error": "leaf must be a sha256 hex digest"}, 400)
        size = None
        if qs.get("size"):
            try:
                size = int(qs["size"][0])
            except ValueError:
                return self.send_json({"error": "size must be an integer"}, 400)
        proof = self.store.log.inclusion(leaf.lower(), size)
        if proof is None:
            return self.send_json({"error": "leaf not in log (or size out of range)"}, 404)
        checkpoint = self.store.log.checkpoint()
        proof["checkpoint"] = checkpoint if checkpoint["size"] == proof["tree_size"] else None
        # Historical size: hand out a consistency proof to the signed head.
        if proof["checkpoint"] is None:
            proof["consistency_to_head"] = self.store.log.consistency(
                proof["tree_size"], checkpoint["size"])
            proof["head"] = checkpoint
        anchor = self.store.log.latest_anchor()
        proof["anchor"] = anchor if anchor and anchor["size"] == proof["tree_size"] else None
        return self.send_json(proof)

    def _log_consistency(self):
        qs = urllib.parse.parse_qs(self.path.split("?", 1)[1] if "?" in self.path else "")
        try:
            first = int((qs.get("from") or ["0"])[0])
            second = int((qs.get("to") or [str(self.store.log.size())])[0])
        except ValueError:
            return self.send_json({"error": "from/to must be integers"}, 400)
        proof = self.store.log.consistency(first, second)
        if proof is None:
            return self.send_json({"error": "need 0 < from <= to <= log size"}, 400)
        return self.send_json(proof)

    # ---- machine identity --------------------------------------------------
    def _machine_enroll(self, raw: bytes | None):
        user = self._authorized_user()
        if not user:
            return self.send_json({"error": "authentication required"}, 401)
        try:
            payload = json.loads(raw or b"{}")
            pub_hex = str(payload.get("public_key_hex", "")).strip().lower()
            registry = self._public_base_url()
            cert, already = self.store.log.enroll(
                user, pub_hex, registry,
                str(payload.get("os", ""))[:32], str(payload.get("arch", ""))[:32])
        except PermissionError as e:
            return self.send_json({"error": str(e)}, 409)
        except (ValueError, TypeError) as e:
            return self.send_json({"error": f"invalid enrollment: {e}"}, 400)
        if not already:
            self.store.record_audit(user, "machine_enroll", cert["machine_id"])
        return self.send_json({"certificate": cert}, 200 if already else 201)

    def _machine_list(self):
        user = self._authorized_user()
        if not user:
            return self.send_json({"error": "authentication required"}, 401)
        return self.send_json({"machines": self.store.log.machines_of(user)})

    def _public_base_url(self) -> str:
        # Certificates name the registry so a verifier can tell which
        # registry vouched for the host; honour reverse-proxy headers.
        host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host") or "registry"
        scheme = self.headers.get("X-Forwarded-Proto") or "http"
        return f"{scheme}://{host}"

    def _log_anchor(self):
        # Anchoring costs a TSA round-trip: authenticated users only.
        if not self._authorized_user():
            return self.send_json({"error": "authentication required"}, 401)
        qs = urllib.parse.parse_qs(self.path.split("?", 1)[1] if "?" in self.path else "")
        tsa = (qs.get("tsa") or [None])[0]
        try:
            anchor = self.store.log.anchor(tsa)
        except Exception as e:
            return self.send_json({"error": f"anchoring failed: {e}"}, 502)
        return self.send_json({"anchor": anchor}, 201)

    def _attest_query(self):
        user = self._authorized_user()
        if not user:
            return self.send_json({"error": "authentication required"}, 401)
        qs = urllib.parse.parse_qs(self.path.split("?", 1)[1] if "?" in self.path else "")
        try:
            limit = min(int((qs.get("limit") or ["100"])[0]), 1000)
            skip = max(0, int((qs.get("skip") or ["0"])[0]))
        except ValueError:
            return self.send_json({"error": "limit/skip must be integers"}, 400)
        filters = {}
        for key in ("bundle", "machine", "since", "until"):
            vals = qs.get(key)
            if vals:
                filters[key] = vals[0]
        # Personal trail: a caller may only read back what they published.
        # Other accounts' trails stay invisible (default-deny compliance trail).
        total, page = self.store.query_attestations(user, filters, limit, skip)
        return self.send_json({"owner": user, "total": total, "records": page})

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

    def _provider_webhook(self, provider: str, raw: bytes | None):
        if raw is None:
            return self.send_json({"error": "empty body"}, 400)
        cfg = self.billing
        secret = cfg.get(f"{provider}_webhook_secret")
        if not secret:
            return self.send_json({"error": f"{provider} webhook not configured"}, 503)
        declared = int(self.headers.get("Content-Length", 0) or 0)
        if declared <= 0 or declared > 1 << 20:
            return self.send_json({"error": "bad body size"}, 400)
        if provider == "github":
            sig = self.headers.get("X-Hub-Signature-256", "")
            expected = "sha256=" + hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, sig):
                self.store.record_audit("__github__", "webhook_bad_signature")
                return self.send_json({"error": "invalid signature"}, 400)
        elif provider == "gitlab":
            token = self.headers.get("X-Gitlab-Token", "")
            if not hmac.compare_digest(secret, token):
                self.store.record_audit("__gitlab__", "webhook_bad_token")
                return self.send_json({"error": "invalid token"}, 400)
        elif provider == "gitea":
            sig = self.headers.get("X-Gitea-Signature", "")
            expected = hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, sig):
                self.store.record_audit("__gitea__", "webhook_bad_signature")
                return self.send_json({"error": "invalid signature"}, 400)
        else:
            return self.send_json({"error": "unknown provider"}, 400)
        try:
            event = json.loads(raw.decode("utf-8", "replace"))
        except ValueError:
            return self.send_json({"error": "invalid json"}, 400)
        etype = event.get("action", "")
        if etype in ("member", "added", "invited"):
            sender = event.get("sender", {}) or {}
            member_user = event.get("member", {}).get("username", "") or event.get("user", {}).get("username", "")
            repo = event.get("repository", {}).get("full_name", "") or event.get("project", {}).get("path_with_namespace", "")
            if member_user and repo:
                token = secrets.token_hex(32)
                with self.lock:
                    users = self._load(self.users_path, {}).get("users", {})
                    rec = users.get(member_user)
                    if rec is None:
                        users[member_user] = {
                            "token_hash": hashlib.sha256(token.encode()).hexdigest(),
                            "tier": "free",
                            "created_at": datetime.now(timezone.utc).isoformat(),
                            f"{provider}_repos": [repo],
                        }
                    else:
                        repos = rec.get(f"{provider}_repos", [])
                        if repo not in repos:
                            repos.append(repo)
                            rec[f"{provider}_repos"] = repos
                            rec["token_hash"] = hashlib.sha256(token.encode()).hexdigest()
                    atomic_write(self.users_path, json.dumps({"users": users}).encode())
                self.store.record_audit(member_user, f"{provider}_webhook_token", repo)
                return self.send_json({"issued": True, "user": member_user, "repo": repo, "token": token})
        return self.send_json({"received": True})

    # ---- cve scanning -------------------------------------------------------
    def _scan_cve(self, path: str) -> list[dict]:
        """Scan a model artifact for known CVEs.

        Uses a local CVE database if available, otherwise returns empty list.
        The database is a JSON file mapping file hashes to CVE entries.
        """
        cve_db_path = os.path.join(self.root, "cve_db.json")
        if not os.path.isfile(cve_db_path):
            return []
        try:
            with open(cve_db_path, "r") as f:
                cve_db = json.load(f)
        except (OSError, ValueError):
            return []
        file_hash = self.store.sha256_cached(path)
        return cve_db.get(file_hash, [])

    def _admin_scan(self):
        user = self._authorized_user()
        if not user:
            return self.send_json({"error": "authentication required"}, 401)
        results = []
        for name in sorted(os.listdir(self.store.pkg_dir)):
            if not name.endswith(".erebus") and not name.endswith(".gguf"):
                continue
            path = os.path.join(self.store.pkg_dir, name)
            if not os.path.isfile(path):
                continue
            cves = self._scan_cve(path)
            if cves:
                results.append({
                    "file": name,
                    "sha256": self.store.sha256_cached(path),
                    "cves": cves,
                })
        return self.send_json({"scanned": len(results), "vulnerable": len([r for r in results if r["cves"]]), "results": results})

    # ---- webhooks ------------------------------------------------------------
    def _webhook_list(self):
        user = self._authorized_user()
        if not user:
            return self.send_json({"error": "authentication required"}, 401)
        return self.send_json({"webhooks": self.store.list_webhooks()})

    def _webhook_add(self, raw: bytes | None):
        user = self._authorized_user()
        if not user:
            return self.send_json({"error": "authentication required"}, 401)
        payload = self._read_json(raw)
        if payload is None:
            return self.send_json({"error": "invalid json"}, 400)
        url = str(payload.get("url", "")).strip()
        if not url.startswith("http://") and not url.startswith("https://"):
            return self.send_json({"error": "url must start with http(s)"}, 400)
        self.store.add_webhook(url)
        self.store.record_audit(user, "webhook_add", url)
        return self.send_json({"added": url})

    def _webhook_remove(self, url: str):
        user = self._authorized_user()
        if not user:
            return self.send_json({"error": "authentication required"}, 401)
        self.store.remove_webhook(url)
        self.store.record_audit(user, "webhook_remove", url)
        return self.send_json({"removed": url})

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
        # Generate GGUF per-tensor manifest if applicable
        if fname.endswith(".gguf"):
            manifest = parse_gguf(final)
            if manifest:
                manifest_path = final + ".manifest.json"
                atomic_write(manifest_path, json.dumps(manifest).encode())
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



