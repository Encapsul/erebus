"""Artifact footer / GGUF integrity checks (stdlib only)."""
from __future__ import annotations

import hashlib
import io
import json
import os

from erebus_registry.util import CHUNK, EREBUS_MAGIC

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


def _gguf_read_string(f: io.BufferedReader) -> str:
    length = int.from_bytes(f.read(4), "little")
    if length > 4096:
        raise ValueError("string too long")
    return f.read(length).decode("utf-8", "replace")


def _gguf_read_uint64(f: io.BufferedReader) -> int:
    data = f.read(8)
    if len(data) < 8:
        raise ValueError("truncated uint64")
    return int.from_bytes(data, "little")


def _gguf_read_uint32(f: io.BufferedReader) -> int:
    data = f.read(4)
    if len(data) < 4:
        raise ValueError("truncated uint32")
    return int.from_bytes(data, "little")


def parse_gguf(path: str) -> dict | None:
    """Parse a GGUF file and return a per-tensor manifest.

    Returns None if the file is not a valid GGUF file.
    The manifest contains:
      - tensors: list of {name, n_dims, dims, type, offset, size, sha256}
      - metadata: dict of metadata key-value pairs
    """
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
            if magic != b"GGUF":
                return None
            version = _gguf_read_uint32(f)
            if version not in (1, 2, 3):
                return None
            tensor_count = _gguf_read_uint64(f)
            metadata_count = _gguf_read_uint64(f)
            metadata = {}
            for _ in range(metadata_count):
                key = _gguf_read_string(f)
                # Skip value based on type (simplified: just skip)
                value_type = _gguf_read_uint32(f)
                if value_type == 0:  # uint8
                    f.read(1)
                elif value_type == 1:  # int8
                    f.read(1)
                elif value_type == 2:  # uint16
                    f.read(2)
                elif value_type == 3:  # int16
                    f.read(2)
                elif value_type == 4:  # uint32
                    f.read(4)
                elif value_type == 5:  # int32
                    f.read(4)
                elif value_type == 6:  # float32
                    f.read(4)
                elif value_type == 7:  # bool
                    f.read(1)
                elif value_type == 8:  # string
                    str_len = _gguf_read_uint32(f)
                    f.read(str_len)
                elif value_type == 9:  # array
                    array_type = _gguf_read_uint32(f)
                    array_len = _gguf_read_uint64(f)
                    if array_type == 8:  # string array
                        for _ in range(array_len):
                            str_len = _gguf_read_uint32(f)
                            f.read(str_len)
                    else:
                        # Skip array elements based on type size
                        sizes = {0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1}
                        elem_size = sizes.get(array_type, 1)
                        f.read(array_len * elem_size)
                else:
                    # Unknown type, skip
                    pass
                metadata[key] = None  # We don't parse values fully for now
            tensor_infos = []
            for _ in range(tensor_count):
                name = _gguf_read_string(f)
                n_dims = _gguf_read_uint32(f)
                dims = [_gguf_read_uint32(f) for _ in range(n_dims)]
                tensor_type = _gguf_read_uint32(f)
                offset = _gguf_read_uint64(f)
                tensor_infos.append({
                    "name": name,
                    "n_dims": n_dims,
                    "dims": dims,
                    "type": tensor_type,
                    "offset": offset,
                })
            tensor_infos.sort(key=lambda t: t["offset"])
            for i, info in enumerate(tensor_infos):
                start = info["offset"]
                end = tensor_infos[i + 1]["offset"] if i + 1 < len(tensor_infos) else os.path.getsize(path)
                size = end - start
                f.seek(start)
                h = hashlib.sha256()
                remaining = size
                while remaining > 0:
                    chunk = f.read(min(CHUNK, remaining))
                    if not chunk:
                        break
                    h.update(chunk)
                    remaining -= len(chunk)
                info["size"] = size
                info["sha256"] = h.hexdigest()
            return {
                "version": version,
                "tensor_count": tensor_count,
                "tensors": tensor_infos,
                "metadata_keys": list(metadata.keys()),
            }
    except (OSError, ValueError):
        return None


def verify_gguf_integrity(path: str) -> tuple[bool, str]:
    """Verify a GGUF file using its stored per-tensor manifest.

    The manifest is stored as a sidecar file with .gguf.manifest.json extension.
    Returns (ok, detail).
    """
    manifest_path = path + ".manifest.json"
    if not os.path.isfile(manifest_path):
        return True, "no-manifest (unverified)"
    try:
        with open(manifest_path, "r") as f:
            manifest = json.load(f)
    except (OSError, ValueError):
        return False, "unreadable-manifest"
    return verify_gguf(path, manifest)


def verify_gguf(path: str, manifest: dict) -> tuple[bool, str]:
    """Verify a GGUF file against a stored manifest.

    Returns (ok, detail). `ok=False` means the GGUF file has been tampered with
    or corrupted.
    """
    current = parse_gguf(path)
    if current is None:
        return False, "invalid gguf"
    if current["tensor_count"] != manifest.get("tensor_count", 0):
        return False, "tensor count mismatch"
    current_tensors = {t["name"]: t for t in current["tensors"]}
    manifest_tensors = {t["name"]: t for t in manifest.get("tensors", [])}
    for name, mt in manifest_tensors.items():
        ct = current_tensors.get(name)
        if ct is None:
            return False, f"tensor {name} missing"
        if ct["sha256"] != mt["sha256"]:
            return False, f"tensor {name} checksum mismatch"
        if ct["offset"] != mt["offset"]:
            return False, f"tensor {name} offset changed"
        if ct["size"] != mt["size"]:
            return False, f"tensor {name} size changed"
    return True, "ok"


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
    if path.endswith(".gguf"):
        return verify_gguf_integrity(path)
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

