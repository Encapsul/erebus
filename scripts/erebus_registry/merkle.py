"""RFC 6962 / RFC 9162 Merkle tree over SHA-256: leaves, roots, proofs."""
import hashlib


# ---- Merkle hash tree (RFC 6962 / RFC 9162, SHA-256) ------------------------
# Mirrors `erebus-core/src/merkle.rs` byte for byte; both are pinned to the
# RFC 9162 test vectors so a proof produced here verifies in the CLI offline.
def _mt_leaf(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def _mt_node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _mt_split(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _mt_root(leaves) -> bytes:
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaves[0]
    k = _mt_split(n)
    return _mt_node(_mt_root(leaves[:k]), _mt_root(leaves[k:]))


def _mt_inclusion(leaves, index: int) -> list[bytes]:
    """Audit path for leaves[index], leaf-to-root (RFC 6962 §2.1.1)."""
    n = len(leaves)
    if n <= 1:
        return []
    k = _mt_split(n)
    if index < k:
        return _mt_inclusion(leaves[:k], index) + [_mt_root(leaves[k:])]
    return _mt_inclusion(leaves[k:], index - k) + [_mt_root(leaves[:k])]


def _mt_consistency(leaves, first: int, complete: bool = True) -> list[bytes]:
    """Consistency proof from the first `first` leaves (RFC 6962 §2.1.2)."""
    n = len(leaves)
    if first == n:
        return [] if complete else [_mt_root(leaves)]
    k = _mt_split(n)
    if first <= k:
        return _mt_consistency(leaves[:k], first, complete) + [_mt_root(leaves[k:])]
    return _mt_consistency(leaves[k:], first - k, False) + [_mt_root(leaves[:k])]


class _MerkleTree:
    """Append-only RFC 6962 tree over leaf hashes, O(log n) per query.

    Same bytes as `_mt_root` / `_mt_inclusion` / `_mt_consistency` (the
    reference, kept for the self-test), but over index ranges instead of
    list slices, and with the roots of complete power-of-two subtrees cached:
    in an append-only log those never change. Subtrees under `MIN_CACHED`
    leaves are recomputed, which keeps the cache at ~n/32 entries.
    """

    MIN_CACHED = 64

    def __init__(self, leaves: list[bytes]) -> None:
        self.leaves: list[bytes] = []
        self.index: dict[bytes, int] = {}
        self._cache: dict[tuple[int, int], bytes] = {}
        for leaf in leaves:
            self.append(leaf)

    def __len__(self) -> int:
        return len(self.leaves)

    def append(self, leaf: bytes) -> int:
        self.leaves.append(leaf)
        self.index.setdefault(leaf, len(self.leaves) - 1)
        return len(self.leaves) - 1

    def root(self, lo: int = 0, hi: int | None = None) -> bytes:
        hi = len(self.leaves) if hi is None else hi
        n = hi - lo
        if n == 0:
            return hashlib.sha256(b"").digest()
        if n == 1:
            return self.leaves[lo]
        complete = n & (n - 1) == 0 and n >= self.MIN_CACHED
        if complete and (lo, n) in self._cache:
            return self._cache[(lo, n)]
        k = _mt_split(n)
        r = _mt_node(self.root(lo, lo + k), self.root(lo + k, hi))
        if complete:
            self._cache[(lo, n)] = r
        return r

    def inclusion(self, index: int, lo: int, hi: int) -> list[bytes]:
        n = hi - lo
        if n <= 1:
            return []
        k = _mt_split(n)
        if index < lo + k:
            return self.inclusion(index, lo, lo + k) + [self.root(lo + k, hi)]
        return self.inclusion(index, lo + k, hi) + [self.root(lo, lo + k)]

    def consistency(
        self, first: int, lo: int, hi: int, complete: bool = True
    ) -> list[bytes]:
        n = hi - lo
        if first == n:
            return [] if complete else [self.root(lo, hi)]
        k = _mt_split(n)
        if first <= k:
            left = self.consistency(first, lo, lo + k, complete)
            return left + [self.root(lo + k, hi)]
        right = self.consistency(first - k, lo + k, hi, False)
        return right + [self.root(lo, lo + k)]


def _mt_verify_inclusion(leaf: bytes, index: int, size: int, proof, root: bytes) -> bool:
    """RFC 9162 §2.1.3.2 — used by the self-test and the chaos battery."""
    if index >= size:
        return False
    fn, sn, r = index, size - 1, leaf
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = _mt_node(p, r)
            while not (fn & 1) and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            r = _mt_node(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root
