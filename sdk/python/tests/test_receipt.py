"""SDK unit tests: chain bytes and DSSE/JCS shape, independent of the CLI."""

import hashlib
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from erebus import Erebus, ErebusError, attest
from erebus.receipt import jcs


def make_key(tmp_path, keys_dir):
    key = Ed25519PrivateKey.generate()
    seed = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    key_path = tmp_path / "ops.key"
    key_path.write_bytes(seed)
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    keys_dir.mkdir(exist_ok=True)
    fingerprint = hashlib.sha256(public).hexdigest()
    (keys_dir / f"{fingerprint}.pub").write_bytes(public)
    return key_path


def test_jcs_sorts_and_refuses_floats():
    assert jcs({"b": 1, "a": 2}) == b'{"a":2,"b":1}'
    assert jcs([1, "é", None]) == '[1,"é",null]'.encode()
    with pytest.raises(ErebusError):
        jcs({"x": 1.5})


def test_missing_key_fails_closed(tmp_path, monkeypatch):
    monkeypatch.delenv("ERE_ATTEST_KEY", raising=False)
    with pytest.raises(ErebusError, match="ERE_ATTEST_KEY"):
        Erebus()


def test_decorator_writes_a_chained_pair(tmp_path, monkeypatch):
    key = make_key(tmp_path, tmp_path / "keys")
    trail = tmp_path / "trail"
    monkeypatch.setenv("ERE_ATTEST_KEY", str(key))
    monkeypatch.setenv("ERE_ATTEST_LOG", str(trail))

    @attest
    def answer(question):
        return {"answer": question.upper()}

    assert answer("hi") == {"answer": "HI"}
    answer("there")

    files = sorted(trail.glob("*.json"))
    assert len(files) == 2
    first = json.loads(files[0].read_text())
    second = json.loads(files[1].read_text())
    head = "sha256:" + hashlib.sha256(files[0].read_bytes()).hexdigest()
    assert first["execution"]["prev_attestation_hash"] is None
    assert second["execution"]["prev_attestation_hash"] == head
    assert (trail / "HEAD").read_text().strip().startswith("sha256:")
    assert second["envelope"]["payloadType"] == "application/vnd.in-toto+json"
    assert second["spec_version"] == "2.0"
