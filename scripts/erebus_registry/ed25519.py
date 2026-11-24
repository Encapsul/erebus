"""Ed25519 (RFC 8032) in pure Python: sign, verify, public key. stdlib only."""
import hashlib

# ---- Ed25519 pure-Python verification (RFC 8032 §5.1.7, stdlib only) -----
# The Rust `Ed25519Authenticator` (erebus-core/src/auth.rs) signs the subject
# bytes with Ed25519 and emits `subject:base64url(sig)`. Ed25519 is not in the
# Python stdlib, so verification is re-implemented here with field arithmetic
# over GF(2^255 - 19). This is verify-only — no secret material is handled.
_ED_P = 2 ** 255 - 19
_ED_L = 2 ** 252 + 27742317777372353535851937790883648493
_ED_D = -121665 * pow(121666, _ED_P - 2, _ED_P) % _ED_P
_ED_I = pow(2, (_ED_P - 1) // 4, _ED_P)
_ED_B = (
    15112221349535400772501151409588531511454012693041857206046113283949847762202,
    46316835694926478169428394003475163141307993866256225615783033603165251855960,
)


def _ed_add(p, q):
    """Unified Edwards point addition (twisted Edwards, a = -1)."""
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    x1y1x2y2 = x1 * y1 * x2 * y2 % _ED_P
    den_x = (1 + _ED_D * x1y1x2y2) % _ED_P
    den_y = (1 - _ED_D * x1y1x2y2) % _ED_P
    inv_x = pow(den_x, _ED_P - 2, _ED_P)
    inv_y = pow(den_y, _ED_P - 2, _ED_P)
    return (
        (x1 * y2 + y1 * x2) * inv_x % _ED_P,
        (y1 * y2 + x1 * x2) * inv_y % _ED_P,
    )


def _ed_scalarmult(p, s):
    """Double-and-add scalar multiplication; `None` is the point at infinity."""
    acc = None
    while s:
        if s & 1:
            acc = _ed_add(acc, p)
        p = _ed_add(p, p)
        s >>= 1
    return acc


def _ed_point_decode(data):
    """Decode a 32-byte compressed Edwards point, or None if invalid."""
    if len(data) != 32:
        return None
    raw = int.from_bytes(data, "little")
    sign = (raw >> 255) & 1
    y = raw & ((1 << 255) - 1)
    if y >= _ED_P:
        return None
    y2 = y * y % _ED_P
    x2 = (y2 - 1) * pow(_ED_D * y2 + 1, _ED_P - 2, _ED_P) % _ED_P
    x = pow(x2, (_ED_P + 3) // 8, _ED_P)
    if x * x % _ED_P != x2:
        x = x * _ED_I % _ED_P
    if x * x % _ED_P != x2:
        return None
    if (x & 1) != sign:
        x = _ED_P - x
    return x, y


def _ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 signature (RFC 8032 §5.1.7). Pure-Python, stdlib only.

    Uses the cofactorless group equation [S]B = R + [k]A, which RFC 8032
    explicitly permits. Compatible with `ed25519_dalek::verify_strict`.
    """
    if len(public_key) != 32 or len(signature) != 64:
        return False
    r_bytes = signature[:32]
    s = int.from_bytes(signature[32:], "little")
    if s >= _ED_L:
        return False
    a = _ed_point_decode(public_key)
    r = _ed_point_decode(r_bytes)
    if a is None or r is None:
        return False
    k = int.from_bytes(
        hashlib.sha512(r_bytes + public_key + message).digest(), "little"
    )
    k %= _ED_L
    return _ed_scalarmult(_ED_B, s) == _ed_add(r, _ed_scalarmult(a, k))


def _ed_extended(point):
    x, y = point
    return x, y, 1, x * y % _ED_P


def _ed_add_ext(p, q):
    """Extended Edwards addition (a = -1); no inversion per addition."""
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    aa = (y1 - x1) * (y2 - x2) % _ED_P
    bb = (y1 + x1) * (y2 + x2) % _ED_P
    cc = t1 * 2 * _ED_D * t2 % _ED_P
    dd = z1 * 2 * z2 % _ED_P
    e, f = (bb - aa) % _ED_P, (dd - cc) % _ED_P
    g, h = (dd + cc) % _ED_P, (bb + aa) % _ED_P
    return e * f % _ED_P, g * h % _ED_P, f * g % _ED_P, e * h % _ED_P


def _ed_mul_ext(point, scalar):
    acc = (0, 1, 1, 0)
    while scalar:
        if scalar & 1:
            acc = _ed_add_ext(acc, point)
        point = _ed_add_ext(point, point)
        scalar >>= 1
    return acc


def _ed_equal_ext(p, q) -> bool:
    return (p[0] * q[2] % _ED_P == q[0] * p[2] % _ED_P
            and p[1] * q[2] % _ED_P == q[1] * p[2] % _ED_P)


def _ed_encode_ext(p) -> bytes:
    x, y, z, _ = p
    inv = pow(z, _ED_P - 2, _ED_P)
    return _ed_point_encode((x * inv % _ED_P, y * inv % _ED_P))


def _ed25519_verify_fast(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Same check as `_ed25519_verify`, using extended coordinates.

    No inversion per point addition, so a 1,000-receipt ingest stays
    interactive. Trust-center tests assert equivalence with the slow verifier
    and with a tampered signature; do not use it without those tests.
    """
    if len(public_key) != 32 or len(signature) != 64:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _ED_L:
        return False
    a = _ed_point_decode(public_key)
    r = _ed_point_decode(signature[:32])
    if a is None or r is None:
        return False
    k = int.from_bytes(
        hashlib.sha512(signature[:32] + public_key + message).digest(), "little"
    ) % _ED_L
    return _ed_equal_ext(
        _ed_mul_ext(_ed_extended(_ED_B), s),
        _ed_add_ext(_ed_extended(r), _ed_mul_ext(_ed_extended(a), k)),
    )


def _ed25519_sign_fast(seed: bytes, message: bytes) -> bytes:
    """Deterministic Ed25519 signature identical to `_ed25519_sign`, but fast."""
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little") & ((1 << 254) - 8) | (1 << 254)
    r = int.from_bytes(hashlib.sha512(h[32:] + message).digest(), "little") % _ED_L
    r_enc = _ed_encode_ext(_ed_mul_ext(_ed_extended(_ED_B), r))
    pub = _ed_encode_ext(_ed_mul_ext(_ed_extended(_ED_B), a))
    k = int.from_bytes(hashlib.sha512(r_enc + pub + message).digest(), "little") % _ED_L
    return r_enc + ((r + k * a) % _ED_L).to_bytes(32, "little")


def _ed_point_encode(p) -> bytes:
    """Compress an Edwards point to 32 bytes (RFC 8032 §5.1.2)."""
    x, y = p
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _ed25519_public_key(seed: bytes) -> bytes:
    """Public half of a 32-byte seed (RFC 8032 §5.1.5)."""
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return _ed_point_encode(_ed_scalarmult(_ED_B, a))


def _ed25519_sign(seed: bytes, message: bytes) -> bytes:
    """Ed25519 signature (RFC 8032 §5.1.6). Pure Python, stdlib only.

    Only the transparency-log checkpoint is signed with this (a few times a
    minute at most), so the naive big-int arithmetic is fast enough. The
    output verifies under `ed25519_dalek::verify_strict` on the CLI side.
    """
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    prefix = h[32:]
    pub = _ed_point_encode(_ed_scalarmult(_ED_B, a))
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % _ED_L
    r_enc = _ed_point_encode(_ed_scalarmult(_ED_B, r))
    k = int.from_bytes(hashlib.sha512(r_enc + pub + message).digest(), "little") % _ED_L
    s = (r + k * a) % _ED_L
    return r_enc + s.to_bytes(32, "little")
