"""OIDC/JWT and Stripe helpers for the erebus registry (stdlib only)."""
from __future__ import annotations

import hashlib
import hmac
import json
import time
import urllib.parse
import urllib.request

from erebus_registry.util import SSO_CACHE_TTL, base64url_decode

# ---- SSO (OIDC) ------------------------------------------------------------
# Pure-stdlib OIDC authorization-code flow with JWT RS256 verification.
# Caches discovery doc + JWKS. Fail-closed on any verification error.

_SSO_CACHE: dict[str, tuple[float, dict]] = {}


def _fetch_json(url: str) -> dict | None:
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "erebus-registry-sso/0.1"}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None


def _get_cached_discovery(issuer: str) -> dict | None:
    now = time.time()
    cached = _SSO_CACHE.get(issuer)
    if cached and now - cached[0] < SSO_CACHE_TTL:
        return cached[1]
    # Discovery document at {issuer}/.well-known/openid-configuration
    disc = _fetch_json(issuer.rstrip("/") + "/.well-known/openid-configuration")
    if not disc:
        return None
    # Fetch JWKS and attach
    jwks_uri = disc.get("jwks_uri")
    if jwks_uri:
        jwks = _fetch_json(jwks_uri)
        if jwks:
            disc["_jwks"] = jwks
    _SSO_CACHE[issuer] = (now, disc)
    return disc


def _jwt_verify_rs256(token: str, jwks: dict) -> dict | None:
    """Verify a JWT RS256 signature using the JWKS. Returns payload dict on success."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header_b64, payload_b64, sig_b64 = parts
        # Decode header
        header = json.loads(base64url_decode(header_b64).decode("utf-8"))
        if header.get("alg") != "RS256":
            return None
        # Find matching JWK by kid
        kid = header.get("kid")
        jwk = None
        if kid:
            for key in jwks.get("keys", []):
                if key.get("kid") == kid and key.get("kty") == "RSA":
                    jwk = key
                    break
        if not jwk:
            # No kid or not found; try first RSA key
            for key in jwks.get("keys", []):
                if key.get("kty") == "RSA":
                    jwk = key
                    break
        if not jwk:
            return None
        n = int.from_bytes(base64url_decode(jwk["n"]), "big")
        e = int.from_bytes(base64url_decode(jwk["e"]), "big")
        # Reconstruct signing input and signature
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        sig = int.from_bytes(base64url_decode(sig_b64), "big")
        # RSASSA-PKCS1-v1_5 verification: m = sig^e mod n
        m = pow(sig, e, n)
        # Convert m to bytes (size = ceil(n.bit_length()/8))
        em = m.to_bytes((n.bit_length() + 7) // 8, "big")
        # PKCS1 v1.5: 00 01 FF...FF 00 || DER(SHA-256) || digest
        # DER for SHA-256: 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20
        der_prefix = bytes.fromhex(
            "3031300d060960864801650304020105000420"
        )
        if not em.startswith(b"\x00\x01"):
            return None
        # Find the 00 separator after FF padding
        try:
            sep = em.index(b"\x00", 2)
        except ValueError:
            return None
        if sep < 10:  # at least 8 FF bytes
            return None
        if not em[2:sep] == b"\xff" * (sep - 2):
            return None
        body = em[sep + 1 :]
        if not body.startswith(der_prefix):
            return None
        digest = body[len(der_prefix) :]
        if len(digest) != 32:
            return None
        # Compute expected digest of signing_input
        expected = hashlib.sha256(signing_input).digest()
        if not hmac.compare_digest(digest, expected):
            return None
        # Signature verified; parse payload
        payload = json.loads(base64url_decode(payload_b64).decode("utf-8"))
        return payload
    except Exception:
        return None


def _jwt_verify_id_token(id_token: str, client_id: str, issuer: str, jwks: dict) -> dict | None:
    """Verify ID token signature + standard claims (iss, aud, exp)."""
    payload = _jwt_verify_rs256(id_token, jwks)
    if not payload:
        return None
    if payload.get("iss") != issuer:
        return None
    aud = payload.get("aud")
    if isinstance(aud, list):
        if client_id not in aud:
            return None
    elif aud != client_id:
        return None
    exp = payload.get("exp")
    if exp is None or int(exp) < int(time.time()):
        return None
    return payload


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

