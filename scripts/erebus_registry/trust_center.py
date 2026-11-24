"""Self-hosted trust center MVP on top of the registry transparency log.

Projects pin operator public keys and own API keys. Receipts are checked
against those keys, chained per project, then anchored in the existing Merkle
log. Status `verified` means: signature under a pinned key, chain link and
inclusion under a checkpoint signed by the registry log key. It does not mean
"every execution was captured" — see docs/src/concepts/proof.md.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import html
import io
import json
import re
import secrets
import zipfile
from datetime import datetime, timezone
from typing import Any

from erebus_registry.ed25519 import _ED_P, _ed25519_verify_fast
from erebus_registry.merkle import _mt_verify_inclusion
from erebus_registry.util import SAFE_ORG, atomic_write

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_V2 = "https://erebus.dev/attestation/execution/v2"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
PROOF_SPEC = "erebus-log-proof/v1"
CHECKPOINT_PREFIX = "erebus-log-checkpoint/v1"
SAFE_PROJECT = re.compile(r"^[a-z0-9][a-z0-9_-]{1,38}$")
CHAIN_FIELDS = (
    "attested_at", "machine_id_hash", "input_hash", "output_hash",
    "prev_attestation_hash",
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _fingerprint(public: bytes) -> str:
    return _sha(public)


def _normalize_key(value: Any) -> bytes:
    raw = bytes.fromhex(str(value).strip().removeprefix("sha256:"))
    # CVE-2023-48022: reject non-canonical encodings where y >= 2^255 - 19.
    if len(raw) != 32 or int.from_bytes(raw, "little") & ((1 << 255) - 1) >= _ED_P:
        raise ValueError("trusted key must be a canonical 32-byte Ed25519 public key")
    return raw


def _pae(payload_type: str, payload: bytes) -> bytes:
    kind = payload_type.encode()
    return (
        b"DSSEv1 " + str(len(kind)).encode() + b" " + kind
        + b" " + str(len(payload)).encode() + b" " + payload
    )


def _subject_digests(statement: dict) -> dict[str, str]:
    return {
        str(s.get("name")): str((s.get("digest") or {}).get("sha256") or "")
        for s in statement.get("subject", [])
        if isinstance(s, dict)
    }


def _statement_consistent(att: dict, statement: dict) -> bool:
    """Only the fields the Rust verifier re-derives are compared here."""
    if statement.get("_type") != STATEMENT_TYPE:
        return False
    if statement.get("predicateType") != PREDICATE_V2:
        return False
    signed_execution = ((statement.get("predicate") or {}).get("execution") or {})
    display_execution = att.get("execution") or {}
    if any(signed_execution.get(k) != display_execution.get(k) for k in CHAIN_FIELDS):
        return False
    digests = _subject_digests(statement)
    artifact = att.get("artifact") or {}
    for name in ("bundle", "payload"):
        expected = str(artifact.get(f"{name}_hash") or "").removeprefix("sha256:")
        if digests.get(name) != expected:
            return False
    return True


def verify_signature(att: dict, trusted_keys: list[str]) -> tuple[str | None, str | None]:
    """Return (key fingerprint, error). Only DSSE/JCS spec 2.x is accepted."""
    envelope = att.get("envelope")
    if not isinstance(envelope, dict) or envelope.get("payloadType") != PAYLOAD_TYPE:
        return None, "only DSSE spec 2.x receipts are accepted"
    try:
        payload = base64.b64decode(str(envelope.get("payload") or ""), validate=True)
        statement = json.loads(payload)
        if not isinstance(statement, dict) or not _statement_consistent(att, statement):
            return None, "signed statement does not match the receipt fields"
        message = _pae(PAYLOAD_TYPE, payload)
        entries = envelope.get("signatures") or []
        claimed = str((att.get("signature") or {}).get("key_fingerprint") or "")
        for entry in entries:
            sig = base64.b64decode(str(entry.get("sig") or ""), validate=True)
            for raw_key in trusted_keys:
                public = _normalize_key(raw_key)
                if not _ed25519_verify_fast(public, message, sig):
                    continue
                fingerprint = _fingerprint(public)
                if fingerprint.removeprefix("sha256:") not in claimed:
                    return None, "signature key does not match receipt key_fingerprint"
                return fingerprint, None
    except (ValueError, TypeError, KeyError, UnicodeError):
        return None, "malformed DSSE envelope or trusted key"
    return None, "no envelope signature verifies under a project key"


def checkpoint_bytes(checkpoint: dict) -> bytes:
    root = str(checkpoint.get("root") or "").removeprefix("sha256:")
    return (
        f"{CHECKPOINT_PREFIX}\n{checkpoint.get('origin')}\n{checkpoint.get('size')}"
        f"\n{root}\n{checkpoint.get('timestamp')}\n"
    ).encode()


def proof_ok(proof: dict) -> bool:
    """Inclusion path plus the log key signature over the signed tree head."""
    if proof.get("checkpoint") is None:
        return False
    checkpoint = proof["checkpoint"]
    if checkpoint.get("root") != proof.get("root"):
        return False
    try:
        leaf = bytes.fromhex(str(proof["leaf_hash"]).removeprefix("sha256:"))
        path = [bytes.fromhex(p) for p in proof["inclusion_proof"]]
        root = bytes.fromhex(str(proof["root"]).removeprefix("sha256:"))
        if not _mt_verify_inclusion(
            leaf, int(proof["leaf_index"]), int(proof["tree_size"]), path, root
        ):
            return False
        public = bytes.fromhex(checkpoint["public_key_hex"])
        if _fingerprint(public) != checkpoint.get("key_id"):
            return False
        signature = bytes.fromhex(checkpoint["signature_hex"])
        return _ed25519_verify_fast(public, checkpoint_bytes(checkpoint), signature)
    except (KeyError, TypeError, ValueError):
        return False


class TrustCenter:
    """Project/API-key state, backed by `Store` for users, audit and the tlog."""

    def __init__(self, store: Any):
        self.store = store
        self.path = store.trust_path
        self.lock = store.lock
        self.state = self._load()

    def _load(self) -> dict:
        try:
            with open(self.path, "rb") as handle:
                return json.loads(handle.read())
        except (OSError, ValueError):
            return {"projects": {}, "receipts": {}, "shares": {}}

    def _save(self) -> None:
        atomic_write(self.path, json.dumps(self.state, indent=2, sort_keys=True).encode())

    def project(self, project_id: str) -> dict | None:
        return self.state["projects"].get(project_id)

    def role(self, actor: str | None, project_id: str) -> str | None:
        project = self.project(project_id)
        if not project or not actor:
            return None
        if project["owner"] == actor:
            return "owner"
        role = self.store.org_role(project["org"], actor)
        return role if role in ("owner", "admin") else None

    def create_project(self, actor: str, org: str | None, name: str,
                       trusted_keys: list[str]) -> tuple[bool, str, dict | None]:
        org = org or actor
        if not SAFE_ORG.match(org) or not SAFE_PROJECT.match(name):
            return False, "invalid org/project name", None
        if org != actor and self.store.org_role(org, actor) not in ("owner", "admin"):
            return False, "org owner/admin role required", None
        try:
            keys = [_normalize_key(k).hex() for k in trusted_keys]
        except (ValueError, TypeError) as exc:
            return False, str(exc), None
        if not keys:
            return False, "at least one trusted operator key is required", None
        project_id = f"{org}/{name}"
        with self.lock:
            if project_id in self.state["projects"]:
                return False, "project already exists", None
            project = {
                "id": project_id, "org": org, "name": name, "owner": actor,
                "created": _now(), "log_origin": self.store.log.origin,
                "trusted_keys": keys, "keys": {},
            }
            self.state["projects"][project_id] = project
            self._save()
        self.store.record_audit(actor, "trust_project_create", project_id, org=org)
        return True, project_id, project

    def create_api_key(self, actor: str, project_id: str,
                       label: str) -> tuple[bool, str, str | None]:
        if self.role(actor, project_id) not in ("owner", "admin"):
            return False, "project owner/admin role required", None
        token = secrets.token_urlsafe(24)
        key_id = secrets.token_hex(8)
        with self.lock:
            project = self.state["projects"][project_id]
            project["keys"][key_id] = {
                "hash": hashlib.sha256(token.encode()).hexdigest(),
                "label": label[:64], "created": _now(),
                "last_used": None, "revoked": False,
            }
            self._save()
        self.store.record_audit(actor, "trust_key_create", f"{project_id}:{key_id}")
        return True, token, key_id

    def authenticate_api_key(self, authorization: str) -> tuple[str, str] | None:
        prefix = "Bearer tc:"
        if not authorization.startswith(prefix):
            return None
        token = authorization[len(prefix):].strip()
        digest = hashlib.sha256(token.encode()).hexdigest()
        with self.lock:
            for project_id, project in self.state["projects"].items():
                for record in project["keys"].values():
                    if record["revoked"]:
                        continue
                    if hmac.compare_digest(record["hash"], digest):
                        return project["owner"], project_id
        return None

    def revoke_api_key(self, actor: str, project_id: str, key_id: str) -> bool:
        if self.role(actor, project_id) not in ("owner", "admin"):
            return False
        with self.lock:
            record = self.state["projects"][project_id]["keys"].get(key_id)
            if not record or record["revoked"]:
                return False
            record["revoked"] = True
            self._save()
        self.store.record_audit(actor, "trust_key_revoke", f"{project_id}:{key_id}")
        return True

    def projects_of(self, actor: str) -> list[dict]:
        return [
            dict(project, keys=len(project["keys"]))
            for project in self.state["projects"].values()
            if self.role(actor, project["id"])
        ]

    def ingest(self, actor: str, project_id: str, raw: bytes,
               base_url: str) -> tuple[int, dict]:
        """Verify, chain and anchor one receipt. Returns (HTTP code, body)."""
        project = self.project(project_id)
        if not project or self.role(actor, project_id) not in ("owner", "admin"):
            return 403, {"error": "project owner/admin role required"}
        try:
            att = json.loads(raw.decode("utf-8", "replace"))
        except (ValueError, UnicodeError):
            return 400, {"error": "invalid json"}
        if not isinstance(att, dict):
            return 400, {"error": "receipt must be a JSON object"}
        fingerprint, error = verify_signature(att, project["trusted_keys"])
        if error:
            return 400, {"error": error}
        rid = self.receipt_id(att)
        body_sha = _sha(raw)
        with self.lock:
            existing = self.state["receipts"].get(rid)
            if existing and existing["sha256"] == body_sha and self.store.log.exists(rid):
                return 200, self.receipt_response(rid, base_url)
            if existing:
                return 409, {"error": "receipt id already recorded with different bytes"}
            head = self._head(project_id)
            previous = str((att.get("execution") or {}).get("prev_attestation_hash") or "")
            if previous != (head or ""):
                return 409, {"error": "chain conflict: missing predecessor or wrong order"}
            ok, detail, _ = self.store.record_attestation(project["owner"], att, raw)
            if not ok:
                return 400, {"error": detail}
            self.state["receipts"][rid] = {
                "id": rid, "project": project_id, "seq": len(self.state["receipts"]) + 1,
                "sha256": body_sha, "key_fp": fingerprint, "chain_ok": True,
                "ingested_at": _now(), "attested_at": str(
                    (att.get("execution") or {}).get("attested_at") or ""),
                "bundle": str((att.get("artifact") or {}).get("bundle_hash") or ""),
                "machine": str((att.get("execution") or {}).get("machine_id_hash") or ""),
            }
            self._save()
        self.store.record_audit(actor, "trust_receipt_ingest", f"{project_id}:{rid}")
        return 201, self.receipt_response(rid, base_url)

    @staticmethod
    def receipt_id(att: dict) -> str:
        explicit = att.get("attestation_id") or att.get("id")
        if explicit:
            return str(explicit)[:128]
        # Match Store.record_attestation()'s derived id so log_position() and
        # attestation_body() can find the exact bytes we just anchored.
        return hashlib.sha256(
            json.dumps(att, sort_keys=True).encode()
        ).hexdigest()[:16]

    def _head(self, project_id: str) -> str | None:
        rows = [
            r for r in self.state["receipts"].values() if r["project"] == project_id
        ]
        if not rows:
            return None
        return max(rows, key=lambda r: r["seq"])["sha256"]

    def receipt_response(self, receipt_id: str, base_url: str) -> dict:
        meta = self.state["receipts"].get(receipt_id)
        if not meta:
            return {"error": "receipt not found"}
        return {
            "id": receipt_id, "project": meta["project"], "status": self.status(receipt_id),
            "sha256": meta["sha256"], "key_fp": meta["key_fp"],
            "attested_at": meta["attested_at"], "log": self.store.log_position(receipt_id),
            "verify_url": f"{base_url}/verify/{receipt_id}",
        }

    def status(self, receipt_id: str) -> str:
        meta = self.state["receipts"].get(receipt_id)
        if not meta:
            return "missing"
        raw = self.store.attestation_body(receipt_id)
        if raw is None:
            return "missing"
        proof = self.store.log_position(receipt_id)
        checkpoint = (proof or {}).get("checkpoint") or {}
        log_key = self.store.log.key_info()
        if (not proof or not proof_ok(proof) or not meta["chain_ok"]
                or checkpoint.get("origin") != log_key["origin"]
                or checkpoint.get("key_id") != log_key["key_id"]
                or checkpoint.get("public_key_hex") != log_key["public_key_hex"]):
            return "failed"
        project = self.project(meta["project"])
        if not project:
            return "failed"
        att = json.loads(raw)
        fingerprint, error = verify_signature(att, project["trusted_keys"])
        return "verified" if not error and fingerprint == meta["key_fp"] else "failed"

    def get(self, actor: str | None, project_id: str, receipt_id: str,
            base_url: str) -> tuple[int, dict]:
        if self.role(actor, project_id) is None:
            return 403, {"error": "project access denied"}
        meta = self.state["receipts"].get(receipt_id)
        if not meta or meta["project"] != project_id:
            return 404, {"error": "receipt not found"}
        if self.store.retention.expired(meta):
            return 404, {"error": "receipt not found"}
        return 200, self.receipt_response(receipt_id, base_url)

    def query(self, project_id: str, filters: dict, limit: int,
              skip: int) -> tuple[int, list[dict]]:
        if not self.project(project_id):
            return 0, []
        rows = [
            r for r in self.state["receipts"].values()
            if r["project"] == project_id and not self.store.retention.expired(r)
        ]
        if filters.get("id"):
            rows = [r for r in rows if r["id"] == filters["id"]]
        for key in ("bundle", "machine"):
            if filters.get(key):
                rows = [r for r in rows if r[key] == filters[key]]
        if filters.get("status"):
            rows = [r for r in rows if self.status(r["id"]) == filters["status"]]
        if filters.get("since"):
            rows = [r for r in rows if r["attested_at"] >= filters["since"]]
        if filters.get("until"):
            rows = [r for r in rows if r["attested_at"] <= filters["until"]]
        rows.sort(key=lambda r: r["seq"])
        return len(rows), [
            {
                "id": r["id"], "status": self.status(r["id"]),
                "attested_at": r["attested_at"], "bundle": r["bundle"],
                "machine": r["machine"], "sha256": r["sha256"],
            }
            for r in rows[skip:skip + limit]
        ]

    def create_share(self, actor: str, receipt_id: str, base_url: str) -> tuple[int, dict]:
        meta = self.state["receipts"].get(receipt_id)
        if not meta or self.role(actor, meta["project"]) is None:
            return 403, {"error": "project access denied"}
        if self.store.retention.expired(meta):
            return 404, {"error": "receipt not found"}
        token = secrets.token_urlsafe(24)
        with self.lock:
            self.state["shares"][receipt_id] = {
                "hash": hashlib.sha256(token.encode()).hexdigest(),
                "project": meta["project"], "created": _now(),
            }
            self._save()
        self.store.record_audit(actor, "trust_share_create", receipt_id)
        return 201, {"url": f"{base_url}/verify/{receipt_id}?token={token}"}

    def shared(self, receipt_id: str, token: str | None) -> bool:
        record = self.state["shares"].get(receipt_id)
        if not record or not token:
            return False
        return hmac.compare_digest(
            record["hash"], hashlib.sha256(token.encode()).hexdigest()
        )

    def public_view(self, receipt_id: str, token: str | None) -> dict | None:
        meta = self.state["receipts"].get(receipt_id)
        if not meta or self.store.retention.expired(meta):
            return None
        if not self.shared(receipt_id, token):
            return None
        response = self.receipt_response(receipt_id, "")
        project = self.project(meta["project"])
        response.update({
            "project": meta["project"], "status": self.status(receipt_id),
            "log_origin": project["log_origin"],
            "trusted_key_fingerprints": [_fingerprint(bytes.fromhex(k))
                                         for k in project["trusted_keys"]],
            "log_key": self.store.log.key_info(),
        })
        return response

    def public_html(self, receipt_id: str, view: dict, token: str, base_url: str) -> bytes:
        esc = html.escape
        proof = view.get("log") or {}
        checkpoint = proof.get("checkpoint") or {}
        lines = [
            "<!doctype html><meta charset=utf-8><title>erebus verification</title>",
            "<style>body{font:15px ui-monospace,monospace;background:#0b0e14;color:#d7dce6;"
            "padding:32px;line-height:1.6}h1{color:#7ee0c3}code{color:#7ee0c3}</style>",
            "<h1>erebus receipt verification</h1>",
            f"<p>Receipt <code>{esc(str(receipt_id))}</code> — "
            f"status <strong>{esc(str(view['status']))}</strong></p>",
            f"<p>Project <code>{esc(str(view['project']))}</code> · "
            f"log origin <code>{esc(str(view['log_origin']))}</code></p>",
            f"<p>Attested at <code>{esc(str(view['attested_at']))}</code> · "
            f"Merkle leaf <code>{esc(str(proof.get('leaf_index', '?')))}</code> "
            f"of <code>{esc(str(proof.get('tree_size', '?')))}</code></p>",
            f"<p>Signed checkpoint key <code>{esc(str(checkpoint.get('key_id', '?')))}</code></p>",
            f"<p><a href='/public/evidence/{esc(str(receipt_id))}?token={esc(token)}'>"
            "Download evidence pack</a></p>",
            "<p>Verified here from the pinned operator key and the registry log key. "
            "For offline verification, extract the pack and run "
            "<code>erebus verify-attest receipt.json --proof-file receipt.proof.json "
            "--log-key &lt;log public key hex&gt;</code>.</p>",
        ]
        return "\n".join(lines).encode()

    def export(self, project_id: str, base_url: str, filters: dict) -> tuple[int, bytes]:
        if not self.project(project_id):
            return 404, b""
        total, rows = self.query(project_id, filters, 100_000, 0)
        output = io.BytesIO()
        project = self.project(project_id)
        manifest = {
            "kind": "erebus-trust-center-evidence/1",
            "generated_at": _now(), "project": project_id,
            "log_origin": project["log_origin"], "registry": base_url,
            "receipts": total,
            "trusted_key_fingerprints": [
                _fingerprint(bytes.fromhex(k)) for k in project["trusted_keys"]
            ],
            "log_key": self.store.log.key_info(),
            "verify_command": (
                "erebus verify-attest receipts/<id>.json "
                "--proof-file proofs/<id>.proof.json --log-key <log public key hex>"
            ),
            "items": [
                {"id": r["id"], "status": r["status"], "sha256": r["sha256"]}
                for r in rows
            ],
        }
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("manifest.json", json.dumps(manifest, indent=2))
            for row in rows:
                rid = row["id"]
                raw = self.store.attestation_body(rid)
                if raw is None:
                    continue
                archive.writestr(f"receipts/{rid}.json", raw)
                proof = self.store.log_position(rid)
                if proof:
                    archive.writestr(
                        f"proofs/{rid}.proof.json",
                        json.dumps(dict(proof, spec=PROOF_SPEC, registry=base_url), indent=2),
                    )
        return total, output.getvalue()

    def status_page(self) -> dict:
        counts = {"verified": 0, "missing": 0, "failed": 0}
        with self.lock:
            visible = [
                r for r in self.state["receipts"].values()
                if not self.store.retention.expired(r)
            ]
            for meta in visible:
                counts[self.status(meta["id"])] += 1
            return {
                "status": "operational", "products": "self-hosted trust center MVP",
                "projects": len(self.state["projects"]),
                "receipts": len(visible),
                "retention_hidden": len(self.state["receipts"]) - len(visible),
                "log_size": self.store.log.size(), "log_origin": self.store.log.origin,
                "counts": counts, "generated_at": _now(),
            }

    def backup(self) -> dict:
        receipts = []
        with self.lock:
            for rid, meta in self.state["receipts"].items():
                raw = self.store.attestation_body(rid)
                if raw is None:
                    continue
                receipts.append({
                    "id": rid, "meta": meta, "body_b64": base64.b64encode(raw).decode(),
                })
            return {
                "kind": "erebus-trust-center-backup/1",
                "generated_at": _now(), "state": self.state, "receipts": receipts,
                "retention": self.store.retention.as_dict(),
                "note": "Keep the registry log.key and users.json outside this export.",
            }

    def restore(self, payload: dict) -> tuple[int, dict]:
        if payload.get("kind") != "erebus-trust-center-backup/1":
            return 400, {"error": "unsupported backup kind"}
        state = payload.get("state") or {}
        if not all(k in state for k in ("projects", "receipts", "shares")):
            return 400, {"error": "backup state is incomplete"}
        policy = payload.get("retention")
        policy_data = None
        if policy is not None:
            try:
                policy_data = self.store.retention.validate(policy)
            except ValueError as exc:
                return 400, {"error": f"invalid retention policy: {exc}"}
        entries = payload.get("receipts") or []
        restored = 0
        for entry in entries:
            rid = entry.get("id")
            meta = (state["receipts"] or {}).get(rid)
            if not rid or not meta:
                continue
            raw = base64.b64decode(str(entry.get("body_b64") or ""))
            att = json.loads(raw)
            owner = state["projects"][meta["project"]]["owner"]
            ok, _, _ = self.store.record_attestation(owner, att, raw)
            if ok:
                restored += 1
        with self.lock:
            self.state = state
            self._save()
            if policy_data is not None:
                self.store.retention.save(policy_data)
        self.store.record_audit("admin", "trust_restore", f"{restored} receipts")
        if policy_data is not None:
            self.store.record_audit(
                "admin", "retention_policy_restore", f"version={policy_data['version']}")
        return 200, {
            "restored": restored, "projects": len(state["projects"]),
            "retention": policy_data is not None,
        }
