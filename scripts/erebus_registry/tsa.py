"""RFC 3161 time-stamp requests and structural response checks (DER by hand)."""
import re
import secrets

# ---- RFC 3161 time-stamp requests (DER by hand, stdlib only) ----------------
_TSA_SHA256_ALGID = bytes.fromhex("300d06096086480165030402010500")


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _der(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(body)) + body


def _der_int(n: int) -> bytes:
    body = n.to_bytes(max(1, (n.bit_length() + 8) // 8), "big")
    return _der(0x02, body)


def tsa_build_request(digest: bytes, nonce: int | None = None) -> bytes:
    """TimeStampReq over a SHA-256 imprint with certReq=TRUE (RFC 3161 §2.4.1)."""
    imprint = _der(0x30, _TSA_SHA256_ALGID + _der(0x04, digest))
    body = _der_int(1) + imprint
    if nonce is None:
        nonce = int.from_bytes(secrets.token_bytes(8), "big")
    body += _der_int(nonce) + _der(0x01, b"\xff")
    return _der(0x30, body)


def _der_read(buf: bytes, pos: int) -> tuple[int, int, int]:
    """(tag, content_start, content_end) of the TLV at `pos`."""
    tag = buf[pos]
    length = buf[pos + 1]
    pos += 2
    if length & 0x80:
        nbytes = length & 0x7F
        length = int.from_bytes(buf[pos:pos + nbytes], "big")
        pos += nbytes
    return tag, pos, pos + length


def tsa_parse_response(resp: bytes, digest: bytes) -> dict:
    """Structural check of a TimeStampResp: status granted, imprint present.

    Cryptographic validation of the CMS signature needs the TSA chain and is
    delegated to `openssl ts -verify` on the verifier side; here we only make
    sure the TSA answered *this* digest and expose genTime for display.
    """
    try:
        tag, start, end = _der_read(resp, 0)
        if tag != 0x30:
            return {"ok": False, "error": "not a SEQUENCE"}
        stag, sstart, send = _der_read(resp, start)
        itag, istart, iend = _der_read(resp, sstart)
        if stag != 0x30 or itag != 0x02:
            return {"ok": False, "error": "malformed PKIStatusInfo"}
        status = int.from_bytes(resp[istart:iend], "big")
    except (IndexError, ValueError):
        return {"ok": False, "error": "truncated response"}
    if status not in (0, 1):
        return {"ok": False, "error": f"TSA status {status}"}
    token = resp[send:end]
    if digest not in token:
        return {"ok": False, "error": "token does not cover the requested digest"}
    gen_time = None
    m = re.search(rb"\x18[\x0f-\x18]((?:19|20)\d{12}(?:\.\d+)?Z)", token)
    if m:
        gen_time = m.group(1).decode()
    return {"ok": True, "gen_time": gen_time, "token": token}
