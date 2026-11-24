"""Spec 2.0 receipt writer for the erebus Python SDK.

The bytes produced here are the same bytes the Rust verifier re-derives:
a JCS in-toto statement inside a DSSE envelope, signed with the raw Ed25519
seed written by `erebus keygen`. No `.erebus` bundle and no `erebus build`
are involved — the subject is the instrumented function descriptor.
"""

from __future__ import annotations

import base64
import functools
import hashlib
import json
import os
import platform
import socket
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, TypeVar

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

__version__ = "0.1.0"

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://erebus.dev/attestation/execution/v2"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
ATTESTATION_TYPE = "erebus-execution"

F = TypeVar("F", bound=Callable[..., Any])


class ErebusError(RuntimeError):
    """Configuration or receipt-writing failure. Never silently ignored."""


def jcs(value: Any) -> bytes:
    """RFC 8785 canonical bytes; floats are refused like the Rust writer."""
    out: list[str] = []
    _write(value, out)
    return "".join(out).encode("utf-8")


def _write(value: Any, out: list[str]) -> None:
    if value is None:
        out.append("null")
    elif isinstance(value, bool):
        out.append("true" if value else "false")
    elif isinstance(value, int):
        out.append(str(value))
    elif isinstance(value, float):
        raise ErebusError("JCS refuses floating-point values in receipts")
    elif isinstance(value, str):
        out.append(json.dumps(value, ensure_ascii=False, separators=(",", ":")))
    elif isinstance(value, (list, tuple)):
        out.append("[")
        out.append(",".join(_item(item) for item in value))
        out.append("]")
    elif isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise ErebusError("JCS object keys must be strings")
        out.append("{")
        members = sorted(value.items(), key=lambda pair: pair[0].encode("utf-16-be"))
        out.append(",".join(f"{_item(key)}:{_item(item)}" for key, item in members))
        out.append("}")
    else:
        raise ErebusError(f"value of type {type(value).__name__} is not canonicalizable")


def _item(value: Any) -> str:
    out: list[str] = []
    _write(value, out)
    return "".join(out)


def digest(data: bytes) -> str:
    """Prefixed SHA-256 digest, the same spelling Rust receipts use."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _machine_hash() -> str:
    try:
        host = socket.gethostname()
    except OSError:
        host = "unknown"
    material = host.encode() + platform.system().lower().encode() + platform.machine().encode()
    return digest(material)


def _load_key(path: Path) -> Ed25519PrivateKey:
    raw = path.read_bytes()
    if len(raw) != 32:
        raise ErebusError(f"attestation key {path} must be 32 bytes, got {len(raw)}")
    return Ed25519PrivateKey.from_private_bytes(raw)


def _fingerprint(key: Ed25519PrivateKey) -> str:
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return digest(public)


def _pae(payload_type: str, payload: bytes) -> bytes:
    kind = payload_type.encode()
    return (
        b"DSSEv1 "
        + str(len(kind)).encode() + b" " + kind
        + b" " + str(len(payload)).encode() + b" " + payload
    )


def _head(trail: Path) -> str | None:
    path = trail / "HEAD"
    if not path.is_file():
        return None
    return path.read_text().strip() or None


def _compact(iso: str) -> str:
    chars: list[str] = []
    for char in iso:
        if char in ".+":
            break
        if char.isascii() and char.isalnum():
            chars.append(char)
    return "".join(chars) or "unknown"


def _next_seq(trail: Path) -> int:
    files = [p for p in trail.glob("*.json") if not p.name.endswith((".proof.json", ".witness.json"))]
    return len(files) + 1


def _write_atomic(path: Path, data: bytes) -> None:
    tmp = path.with_name(f"{path.name}.tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


def _descriptor(name: str, version: str) -> dict[str, Any]:
    return {"kind": "agent", "name": name, "sdk": f"erebus-python-sdk {version}"}


def _artifact(descriptor: dict[str, Any]) -> dict[str, Any]:
    meta = jcs(descriptor)
    subject = digest(meta)
    return {
        "bundle_hash": subject,
        "payload_hash": subject,
        "metadata_hash": digest(meta),
        "format_version": 0,
        "flags": ["agent"],
    }


def _provenance(version: str) -> dict[str, Any]:
    return {"builder": f"erebus python-sdk {version}", "author": None, "license": None, "layers": []}


def _execution(input_bytes: bytes, output_bytes: bytes, previous: str | None, now: str) -> dict:
    return {
        "attested_at": now,
        "machine_id_hash": _machine_hash(),
        "os": platform.system().lower(),
        "arch": platform.machine(),
        "input_hash": digest(input_bytes),
        "output_hash": digest(output_bytes),
        "exit_code": None,
        "prev_attestation_hash": previous,
        "request": None,
        "rootfs_root": None,
        "machine_id": None,
    }


def _statement(artifact: dict, provenance: dict, execution: dict) -> dict[str, Any]:
    return {
        "_type": STATEMENT_TYPE,
        "subject": [
            {"name": "bundle", "digest": {"sha256": artifact["bundle_hash"][7:]}},
            {"name": "payload", "digest": {"sha256": artifact["payload_hash"][7:]}},
        ],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "builder": provenance["builder"],
            "author": provenance["author"],
            "license": provenance["license"],
            "layers": provenance["layers"],
            "execution": execution,
            "artifact": {
                "metadata_hash": artifact["metadata_hash"],
                "format_version": artifact["format_version"],
                "flags": artifact["flags"],
            },
        },
    }


def _envelope(canonical: bytes, key: Ed25519PrivateKey, key_id: str):
    signature = key.sign(_pae(PAYLOAD_TYPE, canonical))
    return {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(canonical).decode(),
        "signatures": [{"keyid": key_id, "sig": base64.b64encode(signature).decode()}],
    }, signature


def _attestation(canonical: bytes, artifact: dict, provenance: dict, execution: dict,
                 statement: dict, key: Ed25519PrivateKey) -> dict[str, Any]:
    key_id = _fingerprint(key)
    envelope, signature = _envelope(canonical, key, key_id)
    return {
        "spec_version": "2.0",
        "attestation_type": ATTESTATION_TYPE,
        "artifact": artifact,
        "provenance": provenance,
        "execution": execution,
        "statement": statement,
        "signature": {
            "algorithm": "ed25519",
            "key_fingerprint": key_id,
            "signature_hex": signature.hex(),
        },
        "envelope": envelope,
        "machine": None,
    }


class Erebus:
    """Append signed receipts to a hash-chained directory.

    Key and trail default to `ERE_ATTEST_KEY` and `ERE_ATTEST_LOG`, so an
    instrumented function needs no configuration in its own source.
    """

    def __init__(self, key: str | os.PathLike | None = None,
                 trail: str | os.PathLike | None = None, *, name: str = "agent",
                 version: str = __version__) -> None:
        configured = key or os.environ.get("ERE_ATTEST_KEY")
        if not configured:
            raise ErebusError("set ERE_ATTEST_KEY or pass key= to Erebus/attest")
        self.key_path = Path(configured)
        if not self.key_path.is_file():
            raise ErebusError(f"attestation key {self.key_path} does not exist")
        self.trail = Path(trail or os.environ.get("ERE_ATTEST_LOG") or "agent.run.attest.d")
        self.name = name
        self.version = version
        self._key = _load_key(self.key_path)
        self._lock = threading.Lock()

    def record(self, name: str | None, arguments: Any, result: Any) -> Path:
        """Sign one JSON-serializable call; digests only, never plaintext."""
        return self.record_bytes(name, jcs(arguments), jcs(result))

    def record_bytes(self, name: str | None, input_bytes: bytes,
                     output_bytes: bytes) -> Path:
        """Append a receipt whose signed digests are already canonical bytes."""
        with self._lock:
            self.trail.mkdir(parents=True, exist_ok=True)
            previous = _head(self.trail)
            now = _utc_now()
            label = name or self.name
            artifact = _artifact(_descriptor(label, self.version))
            provenance = _provenance(self.version)
            execution = _execution(input_bytes, output_bytes, previous, now)
            statement = _statement(artifact, provenance, execution)
            attestation = _attestation(jcs(statement), artifact, provenance, execution,
                                       statement, self._key)
            return self._append(attestation, now)

    def _append(self, attestation: dict[str, Any], now: str) -> Path:
        data = json.dumps(attestation, indent=2, ensure_ascii=False).encode("utf-8")
        hash_value = digest(data)
        label = f"{_next_seq(self.trail):06}-{_compact(now)}-{hash_value[7:15]}.json"
        path = self.trail / label
        _write_atomic(path, data)
        _write_atomic(self.trail / "HEAD", f"{hash_value}\n".encode())
        return path


def attest(func: F | None = None, *, key: str | os.PathLike | None = None,
           trail: str | os.PathLike | None = None, name: str | None = None,
           version: str = __version__):
    """Decorate a function so each call appends a receipt.

    Receipt-writing failure raises after the call: evidence is not optional.
    """
    def decorate(target: F) -> F:
        client = Erebus(key=key, trail=trail, version=version)
        label = name or target.__qualname__

        @functools.wraps(target)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            input_bytes = jcs({"args": list(args), "kwargs": kwargs})
            result = target(*args, **kwargs)
            client.record_bytes(label, input_bytes, jcs(result))
            return result

        return wrapped  # type: ignore[return-value]

    return decorate if func is None else decorate(func)
