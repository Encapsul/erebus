"""Logical retention policy for the self-hosted trust center.

The policy hides receipts from trust-center views after a retention window. It
never deletes receipt bytes, changes proof bytes or rewrites the Merkle log.
The clock is the server-side `ingested_at` recorded when a receipt is accepted.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from erebus_registry.util import SAFE_ORG, atomic_write

POLICY_VERSION = 1
MAX_DAYS = 36500
SAFE_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{1,38}$")


def default_policy() -> dict:
    """Return the no-op policy used when no config file exists."""
    return {
        "version": POLICY_VERSION,
        "default_days": None,
        "rules": [],
        "legal_hold": {"projects": [], "receipts": []},
        "updated_at": None,
        "updated_by": None,
    }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _parse_ts(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _days(value: Any, label: str, allow_none: bool = False) -> int | None:
    if value is None and allow_none:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{label} must be an integer")
    if not 0 <= value <= MAX_DAYS:
        raise ValueError(f"{label} must be between 0 and {MAX_DAYS}")
    return value


def _project_ok(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    parts = value.split("/", 1)
    if len(parts) != 2:
        return False
    return bool(SAFE_ORG.fullmatch(parts[0]) and SAFE_NAME.fullmatch(parts[1]))


def _string_list(value: Any, label: str, valid: Any = None) -> list[str]:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be a list")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item or len(item) > 128:
            raise ValueError(f"{label} contains an invalid entry")
        if valid is not None and not valid(item):
            raise ValueError(f"{label} contains an invalid entry")
        if item not in result:
            result.append(item)
    return result


class RetentionPolicy:
    """JSON-backed policy with admin replacement and logical visibility checks."""

    def __init__(self, path: str):
        self.path = path
        self.data = self.load()

    @staticmethod
    def _rule(entry: Any) -> tuple[str, int]:
        if not isinstance(entry, dict):
            raise ValueError("rules entries must be objects")
        project = entry.get("project")
        if not _project_ok(project):
            raise ValueError("rule project must be an org/name identifier")
        days = _days(entry.get("days"), f"rule {project} days")
        return str(project), int(days)

    @staticmethod
    def validate(payload: Any) -> dict:
        """Normalize an admin payload; raise ValueError on invalid policy."""
        if not isinstance(payload, dict):
            raise ValueError("retention policy must be a JSON object")
        if payload.get("version", POLICY_VERSION) != POLICY_VERSION:
            raise ValueError("unsupported retention policy version")
        raw_rules = payload.get("rules", [])
        if not isinstance(raw_rules, list):
            raise ValueError("rules must be a list")
        rules: list[dict] = []
        seen: set[str] = set()
        for entry in raw_rules:
            project, days = RetentionPolicy._rule(entry)
            if project in seen:
                raise ValueError(f"duplicate rule for {project}")
            seen.add(project)
            rules.append({"project": project, "days": days})
        hold = payload.get("legal_hold", {})
        if not isinstance(hold, dict):
            raise ValueError("legal_hold must be an object")
        return {
            "version": POLICY_VERSION,
            "default_days": _days(
                payload.get("default_days"), "default_days", allow_none=True),
            "rules": rules,
            "legal_hold": {
                "projects": _string_list(
                    hold.get("projects", []), "legal_hold.projects", _project_ok),
                "receipts": _string_list(hold.get("receipts", []), "legal_hold.receipts"),
            },
            "updated_at": str(payload.get("updated_at") or "") or None,
            "updated_by": str(payload.get("updated_by") or "") or None,
        }

    def load(self) -> dict:
        try:
            with open(self.path, "rb") as handle:
                payload = json.loads(handle.read())
        except (OSError, ValueError, RecursionError):
            return default_policy()
        try:
            return self.validate(payload)
        except ValueError:
            return default_policy()

    def save(self, data: dict) -> None:
        atomic_write(
            self.path, json.dumps(data, indent=2, sort_keys=True).encode()
        )
        self.data = data

    def update(self, payload: Any, actor: str, lock: Any) -> dict:
        data = self.validate(payload)
        data["updated_at"] = _now()
        data["updated_by"] = actor
        with lock:
            self.save(data)
        return data

    def as_dict(self) -> dict:
        return json.loads(json.dumps(self.data))

    def days_for(self, project: str) -> int | None:
        for rule in self.data["rules"]:
            if rule["project"] == project:
                return int(rule["days"])
        value = self.data["default_days"]
        return None if value is None else int(value)

    def is_held(self, meta: dict) -> bool:
        hold = self.data["legal_hold"]
        return (meta.get("project") in hold["projects"]
                or meta.get("id") in hold["receipts"])

    def expired(self, meta: dict, now: datetime | None = None) -> bool:
        days = self.days_for(str(meta.get("project") or ""))
        if days is None or self.is_held(meta):
            return False
        ingested = _parse_ts(meta.get("ingested_at"))
        if ingested is None:
            return False
        current = now or datetime.now(timezone.utc)
        try:
            return current >= ingested + timedelta(days=days)
        except OverflowError:
            return False
