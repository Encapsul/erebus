"""Shared helpers and constants for the erebus registry (stdlib only)."""
from __future__ import annotations

import os
import re
import uuid
from datetime import datetime, timezone

SAFE_FILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*\.erebus$")
SAFE_PACK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*\.pack(\.tar\.gz)?$")
SAFE_SIDECAR = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*\.pack(\.tar\.gz)?\.sha256$")
SAFE_USER = re.compile(r"^[a-z0-9_-]{1,32}$")
SAFE_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,16}$")
SAFE_ORG = re.compile(r"^[a-z0-9][a-z0-9_-]{1,38}$")
SAFE_MONTH = re.compile(r"^\d{4}-\d{2}$")
CHUNK = 64 * 1024
MONTH_FMT = "%Y-%m"
WEEK_FMT = "%G-W%V"
SSO_CACHE_TTL = 300
REGISTRY_VERSION = "0.5.0"
TIER_QUOTAS = {"free": 20 * 10**9, "pro": 1000 * 10**9, "team": 5000 * 10**9}
PAID_TIERS = ("pro", "team")
ROLE_ORDER = {"viewer": 0, "developer": 1, "admin": 2, "owner": 3}
EREBUS_MAGIC = b"ERE\x01\x00"


def month_now() -> str:
    return datetime.now(timezone.utc).strftime(MONTH_FMT)


def week_now() -> str:
    return datetime.now(timezone.utc).strftime(WEEK_FMT)


def atomic_write(path: str, data: bytes) -> None:
    tmp = f"{path}.{uuid.uuid4().hex}.tmp"
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def base64url_decode(s: str) -> bytes:
    """Decode unpadded (or padded) base64url without raising on garbage."""
    import base64

    s = s.rstrip("=")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
