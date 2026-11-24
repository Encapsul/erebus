"""The Node SDK uses the same canonical bytes as the shipped Python SDK."""

import json
from pathlib import Path

import pytest

from erebus.receipt import _pae, jcs

VECTORS = json.loads(
    (Path(__file__).parents[2] / "node" / "test-vectors" / "v1.json").read_text()
)


@pytest.mark.parametrize("vector", VECTORS["jcs"], ids=lambda v: v["name"])
def test_jcs_shared_vectors(vector):
    assert jcs(vector["value"]) == vector["canonical"].encode()


@pytest.mark.parametrize("vector", VECTORS["pae"])
def test_pae_shared_vector(vector):
    assert _pae(vector["payloadType"], vector["payload"].encode()) == vector["expected"].encode()
