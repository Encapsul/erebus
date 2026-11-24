"""Deterministic mutation helpers for scripts/chaos_monkey.sh.

The shell script owns the build/run lifecycle; this module owns the mutation
strategies and the invariant checks applied to every mutated bundle.
"""

import hashlib
import os
import random
import re
import struct
import subprocess

FOOTER_SIZE = 92
# Absolute offsets inside the v3 footer (see erebus-core/src/format.rs).
SIG_OFFSET, VERSION, FLAGS, PAYLOAD_OFF, PAYLOAD_SIZE = 0, 13, 15, 16, 24
PAYLOAD_USIZE, META_OFF, META_SIZE, FOOTER_MAGIC = 32, 72, 80, 88
INT_FIELDS = (
    SIG_OFFSET, VERSION, FLAGS, PAYLOAD_OFF, PAYLOAD_SIZE,
    PAYLOAD_USIZE, META_OFF, META_SIZE, FOOTER_MAGIC,
)
PANIC_RE = re.compile(
    r'panicked|SIGSEGV|segmentation fault|core dumped|AddressSanitizer', re.I
)


def fields(blob):
    """Return the on-disk layout used to scope mutations."""
    footer = blob[-FOOTER_SIZE:]
    return {
        "start": len(blob) - FOOTER_SIZE,
        "signed_start": struct.unpack_from("<Q", footer, PAYLOAD_OFF)[0],
        "meta_start": struct.unpack_from("<Q", footer, META_OFF)[0],
        "meta_size": struct.unpack_from("<Q", footer, META_SIZE)[0],
    }


def report(ctx, phase, i, data, reason, detail=""):
    """Persist a violating input and print a machine-checkable marker."""
    digest = hashlib.sha256(data).hexdigest()[:16]
    path = os.path.join(ctx["findings"], f"{phase}-case{i}-{digest}.bin")
    with open(path, "wb") as handle:
        handle.write(data)
    os.chmod(path, 0o755)  # findings must be directly re-runnable
    line = (
        f"{reason} phase={phase} case={i} seed={hex(ctx['seed'])} "
        f"sha256={digest} path={path}"
    )
    if detail:
        line += f" detail={detail}"
    print(line)


def write_case(ctx, phase, i, data):
    """Give every case a run-unique path so parallel runs cannot collide."""
    path = os.path.join(ctx["cases"], f"{phase}-{i}")
    with open(path, "wb") as handle:
        handle.write(data)
    os.chmod(path, 0o755)
    return path


def run_case(path, data, ctx, phase, i, key_hex=None, timeout=30):
    """Execute one bundle; report hangs, panics and secret leaks."""
    try:
        result = subprocess.run([path], capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        report(ctx, phase, i, data, "TIMEOUT-VIOLATION")
        return None
    except OSError:
        # Garbage that is not an ELF is rejected by execve itself.
        return None
    stderr = result.stderr or ""
    if PANIC_RE.search(stderr):
        report(ctx, phase, i, data, "PANIC-VIOLATION")
    if key_hex and key_hex.lower() in stderr.lower():
        report(ctx, phase, i, data, "KEY-LEAK")
    return result


def interesting(data, layout, i):
    """Write an interesting integer into a footer field (AFL deterministic)."""
    off = INT_FIELDS[i % len(INT_FIELDS)]
    width = 1 if off in (VERSION, FLAGS) else 4 if off == FOOTER_MAGIC else 8
    values = [0, 1, 2, 0xFF, 0xFFFF, len(data), len(data) + 1]
    value = values[(i // len(INT_FIELDS)) % len(values)]
    absolute = layout["start"] + off
    data[absolute:absolute + width] = (
        value & ((1 << (width * 8)) - 1)
    ).to_bytes(width, "little")
    return f"interesting@{off}={value}"


def mutate(blob, layout, kind, i, n, rng):
    """Return (bytes, description) for one AFL-style mutant."""
    data = bytearray(blob)
    lo, hi = layout["signed_start"], len(data)
    rand_off = lambda: rng.randrange(lo, hi)
    if kind == "walk":
        off = layout["start"] + (i * FOOTER_SIZE // max(1, n)) % FOOTER_SIZE
        data[off] ^= 1 << (i % 8)
    elif kind == "flip":
        for _ in range(rng.randint(1, 8)):
            data[rand_off()] ^= 1 << rng.randrange(8)
    elif kind == "interesting":
        # The mutation must run before bytes(data) snapshots the buffer.
        detail = interesting(data, layout, i)
        return bytes(data), detail
    elif kind == "arith":
        off = layout["start"] + rng.choice(
            [SIG_OFFSET, PAYLOAD_OFF, PAYLOAD_SIZE, META_OFF, META_SIZE]
        )
        value = struct.unpack_from("<Q", data, off)[0]
        delta = 1 if i % 2 == 0 else -1
        struct.pack_into("<Q", data, off, (value + delta) & 0xFFFFFFFFFFFFFFFF)
    elif kind == "magic":
        data[layout["start"] + FOOTER_MAGIC + (i % 4)] ^= 0xFF
    elif kind == "meta":
        start, size = layout["meta_start"], layout["meta_size"]
        if size > 32:
            off = rng.randrange(start, start + size - 32)
            length = rng.randint(4, 64)
        else:
            off, length = start, max(1, size)
        garbage = b'{"tampered": true, " garbage'
        data[off:off + length] = garbage[:length]
    elif kind == "block-del":
        off = rand_off()
        del data[off:off + min(rng.randint(16, 4096), hi - off - 1)]
    elif kind == "block-dup":
        off = rand_off()
        chunk = data[off:off + min(rng.randint(16, 4096), hi - off - 1)]
        data[off:off] = chunk
    elif kind == "zero":
        off = rand_off()
        length = min(rng.randint(16, 4096), hi - off - 1)
        data[off:off + length] = b"\x00" * length
    elif kind == "nibble":
        for _ in range(rng.randint(1, 4)):
            idx = rand_off()
            data[idx] = (
                ((data[idx] >> 4) ^ 0xF & 0xF) << 4 | ((data[idx] & 0xF) ^ 0xF)
            )
    else:  # truncate
        data = data[:rng.randrange(1, hi)]
    return bytes(data), kind


def check_corrupt(ctx, phase, blob, n, kinds, key_hex=None, seed_offset=0):
    """Run n mutants through the stub and report fail-closed violations."""
    layout = fields(blob)
    rng = random.Random(ctx["seed"] + seed_offset)
    closed = 0
    for i in range(n):
        kind = kinds[i % len(kinds)]
        data, detail = mutate(blob, layout, kind, i, n, rng)
        if data == blob:
            # A no-op mutant cannot test fail-closed; treat it as a harness bug.
            print(f"NOOP-MUTANT phase={phase} case={i} kind={kind}")
        path = write_case(ctx, phase, i, data)
        result = run_case(path, data, ctx, phase, i, key_hex)
        if result is not None and result.returncode == 0:
            report(ctx, phase, i, data, "FAIL-CLOSED-VIOLATION", f"{kind}:{detail}")
            closed += 1
        os.unlink(path)
    print(f"SUMMARY phase={phase} runs={n} exit0_on_corrupt={closed}")
