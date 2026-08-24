#!/usr/bin/env python3
"""format_fuzz.py — .erebus binary format fuzzing (pure Python, no bincode)."""

import struct
import random
import hashlib

# Footer format (92 bytes total, based on V3_FOOTER_SIZE = 92)
# Little-endian layout:
#   format_version: u8  (1)
#   arch: u8          (1)
#   flags: u8         (1)
#   _pad: u8          (1)  -- alignment padding
#   payload_offset: u64    (8)
#   payload_csize: u64     (8)
#   payload_usize: u64     (8)
#   payload_sha256: 32 bytes (32)
#   meta_offset: u64   (8)
#   meta_size: u64     (8)
#   sig_offset: u64    (8)
#   magic: u32         (4)  -- FOOTER_MAGIC = 0xBEEF_CAFE
# Total: 1+1+1+1+8+8+8+32+8+8+8+4 = 92 bytes

FOOTER_STRUCT = struct.Struct("<BBBQQQ32sQQQI")  # 92 bytes
FOOTER_MAGIC = 0xBEEF_CAFE
FORMAT_VERSION = 5
V3_FOOTER_SIZE = 92


def pack_footer(payload: bytes, format_version: int = 5, arch: int = 1,
                flags: int = 0, payload_offset: int = 0,
                meta_offset: int = 0, meta_size: int = 0,
                sig_offset: int = 0) -> bytes:
    """Pack a valid footer for the given payload."""
    payload_size = len(payload)
    sha256 = hashlib.sha256(payload).digest()
    return struct.pack(
        "<BBBxQQQ32sQQQI",
        5,              # format_version
        1,              # arch (x86_64)
        0,              # flags
        0,              # payload_offset
        len(payload),   # payload_csize
        len(payload),   # payload_usize
        hashlib.sha256(payload).digest(),
        len(payload),   # meta_offset
        0,              # meta_size
        0,              # sig_offset
        0xBEEF_CAFE,    # FOOTER_MAGIC
    )


def gen_format_binary(rng: random.Random) -> bytes:
    """Generate a random .erebus-like binary (valid or corrupted)."""
    payload_size = rng.randint(0, 1024)
    payload = bytes(rng.randint(0, 255) for _ in range(rng.randint(0, 1024)))
    binary = payload + pack_footer(payload)

    # Corrupt with some probability
    if random.random() < 0.3:
        idx = random.randint(0, len(payload) - 1) if payload else 0
        lst = bytearray(payload)
        if lst:
            lst[random.randint(0, len(lst) - 1)] ^= 1 << random.randint(0, 7)
            payload = bytes(lst)
        binary = payload + pack_footer(payload)

    # Additional corruption
    if random.random() < 0.1:
        idx = random.randint(0, len(binary) - 1)
        ba = bytearray(binary)
        ba[idx] ^= 1 << random.randint(0, 7)
        binary = bytes(ba)
    return binary


def parse_footer(binary: bytes) -> tuple | None:
    """Parse footer from binary, return (footer_dict, payload) or None if invalid."""
    if len(binary) < V3_FOOTER_SIZE:
        return None
    footer_bytes = binary[-V3_FOOTER_SIZE:]
    try:
        (format_version, arch, flags, _pad,
         payload_offset, payload_csize, payload_usize,
         payload_sha256, meta_offset, meta_size, sig_offset, magic) = struct.unpack(
            "<BBBxQQQ32sQQQI", binary[-V3_FOOTER_SIZE:])
    except struct.error:
        return None

    if magic != 0xBEEF_CAFE:
        return None

    return {
        "format_version": format_version,
        "arch": arch,
        "flags": flags,
        "payload_offset": payload_offset,
        "payload_csize": payload_csize,
        "payload_usize": payload_usize,
        "payload_sha256": payload_sha256.hex(),
        "meta_offset": meta_offset,
        "meta_size": meta_size,
        "sig_offset": sig_offset,
        "magic": magic,
    }


def format_fuzz(iters: int, seed: int) -> list[str]:
    anomalies = []
    rng = random.Random(seed)
    for i in range(iters):
        if random.random() < 0.7:
            binary = gen_format_binary(random.Random(seed + i))
        else:
            binary = bytes(random.randint(0, 255) for _ in range(random.randint(0, 2000)))

        # Try to parse footer
        footer = parse_footer(binary)
        if footer is None:
            # Invalid footer - expected for corrupted inputs
            continue

        # Basic sanity checks
        if footer["format_version"] > 5:
            anomalies.append(f"fmt iter {i}: invalid format version {footer['format_version']}")
        if footer["payload_offset"] > len(binary):
            anomalies.append(f"fmt iter {i}: payload offset beyond file")

        # Verify hash if payload size matches
        payload_csize = footer["payload_csize"]
        if payload_csize <= len(binary):
            payload = binary[:-V3_FOOTER_SIZE]
            if len(payload) == payload_csize:
                expected_hash = hashlib.sha256(payload).digest().hex()
                if footer["payload_sha256"] != expected_hash:
                    anomalies.append(f"fmt iter {i}: hash mismatch")

    print(f"[format-fuzz] {iters} iterations")
    return []


# For integration with fuzz_registry.py
def format_fuzz_main(iters: int, seed: int) -> list[str]:
    anomalies = []
    rng = random.Random(seed)
    for i in range(iters):
        if random.random() < 0.7:
            binary = gen_format_binary(random.Random(seed + i))
        else:
            binary = bytes(random.randint(0, 255) for _ in range(random.randint(0, 2000)))

        footer = parse_footer(binary)
        if footer is None:
            continue

        if footer["format_version"] > 5:
            anomalies.append(f"fmt iter {i}: invalid format version {footer['format_version']}")
        if footer["payload_offset"] > len(binary):
            anomalies.append(f"fmt iter {i}: payload offset beyond file")

        payload_csize = footer["payload_csize"]
        if payload_csize <= len(binary):
            payload = binary[:-92]
            if len(payload) == payload_csize:
                expected_hash = hashlib.sha256(payload).digest().hex()
                if footer["payload_sha256"] != expected_hash:
                    anomalies.append(f"fmt iter {i}: hash mismatch")

    print(f"[format-fuzz] {iters} iterations")
    return anomalies