//! RFC 6962 / RFC 9162 Merkle hash tree over SHA-256.
//!
//! Used twice: the rootfs manifest root (P0-4) and the registry transparency
//! log (P0-5). The registry (`scripts/registry_server.py`) implements the same
//! algorithms; both sides are pinned to the RFC 9162 test vectors so a proof
//! produced by one is always accepted by the other.
//!
//! Domain separation: `leaf = SHA-256(0x00 ‖ data)`, `node = SHA-256(0x01 ‖ l ‖ r)`.

use sha2::{Digest, Sha256};

/// A 32-byte SHA-256 digest.
pub type Hash = [u8; 32];

/// `SHA-256(0x00 ‖ data)`.
pub fn leaf_hash(data: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(data);
    h.finalize().into()
}

/// `SHA-256(0x01 ‖ left ‖ right)`.
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Largest power of two strictly less than `n` (`n >= 2`).
fn split_point(n: usize) -> usize {
    let mut k = 1usize;
    while k.saturating_mul(2) < n {
        k = k.saturating_mul(2);
    }
    k
}

/// Merkle tree head over already-hashed leaves (`MTH` in RFC 6962 §2.1).
/// The empty tree hashes to `SHA-256("")`.
pub fn root(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => Sha256::digest([]).into(),
        1 => leaves[0],
        n => {
            let k = split_point(n);
            node_hash(&root(&leaves[..k]), &root(&leaves[k..]))
        }
    }
}

/// Audit path for `leaves[index]` (RFC 6962 §2.1.1), leaf-to-root order.
pub fn inclusion_proof(leaves: &[Hash], index: usize) -> Option<Vec<Hash>> {
    if index >= leaves.len() {
        return None;
    }
    let mut path = Vec::new();
    path_rec(leaves, index, &mut path);
    Some(path)
}

fn path_rec(leaves: &[Hash], m: usize, out: &mut Vec<Hash>) {
    let n = leaves.len();
    if n <= 1 {
        return;
    }
    let k = split_point(n);
    if m < k {
        path_rec(&leaves[..k], m, out);
        out.push(root(&leaves[k..]));
    } else {
        path_rec(&leaves[k..], m - k, out);
        out.push(root(&leaves[..k]));
    }
}

/// RFC 9162 §2.1.3.2 — does `proof` bind `leaf` at `index` into a tree of
/// `size` leaves with head `expected_root`?
pub fn verify_inclusion(
    leaf: &Hash,
    index: u64,
    size: u64,
    proof: &[Hash],
    expected_root: &Hash,
) -> bool {
    if index >= size {
        return false;
    }
    let (mut fn_, mut sn) = (index, size - 1);
    let mut r = *leaf;
    for p in proof {
        if sn == 0 {
            return false;
        }
        if fn_ & 1 == 1 || fn_ == sn {
            r = node_hash(p, &r);
            while fn_ & 1 == 0 && fn_ != 0 {
                fn_ >>= 1;
                sn >>= 1;
            }
        } else {
            r = node_hash(&r, p);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    sn == 0 && r == *expected_root
}

/// Consistency proof between the tree of the first `first` leaves and the
/// full tree (RFC 6962 §2.1.2). `None` unless `0 < first <= leaves.len()`.
pub fn consistency_proof(leaves: &[Hash], first: usize) -> Option<Vec<Hash>> {
    if first == 0 || first > leaves.len() {
        return None;
    }
    let mut out = Vec::new();
    subproof(leaves, first, true, &mut out);
    Some(out)
}

fn subproof(leaves: &[Hash], m: usize, complete: bool, out: &mut Vec<Hash>) {
    let n = leaves.len();
    if m == n {
        if !complete {
            out.push(root(leaves));
        }
        return;
    }
    let k = split_point(n);
    if m <= k {
        subproof(&leaves[..k], m, complete, out);
        out.push(root(&leaves[k..]));
    } else {
        subproof(&leaves[k..], m - k, false, out);
        out.push(root(&leaves[..k]));
    }
}

/// RFC 9162 §2.1.4.2 — is the tree with head `second_root` (size `second`)
/// an append-only extension of the tree with head `first_root` (size `first`)?
pub fn verify_consistency(
    first: u64,
    second: u64,
    first_root: &Hash,
    second_root: &Hash,
    proof: &[Hash],
) -> bool {
    if first == second {
        return proof.is_empty() && first_root == second_root;
    }
    if first == 0 || first > second {
        return false;
    }
    let mut path: Vec<Hash> = Vec::with_capacity(proof.len() + 1);
    if first.is_power_of_two() {
        path.push(*first_root);
    }
    path.extend_from_slice(proof);
    let Some((&head, rest)) = path.split_first() else {
        return false;
    };
    let (mut fn_, mut sn) = (first - 1, second - 1);
    while fn_ & 1 == 1 {
        fn_ >>= 1;
        sn >>= 1;
    }
    let (mut fr, mut sr) = (head, head);
    for c in rest {
        if sn == 0 {
            return false;
        }
        if fn_ & 1 == 1 || fn_ == sn {
            fr = node_hash(c, &fr);
            sr = node_hash(c, &sr);
            while fn_ & 1 == 0 && fn_ != 0 {
                fn_ >>= 1;
                sn >>= 1;
            }
        } else {
            sr = node_hash(&sr, c);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    fr == *first_root && sr == *second_root && sn == 0
}

/// Parse a `sha256:<hex>` or bare hex digest.
pub fn parse_hash(s: &str) -> Option<Hash> {
    let hex_part = s.strip_prefix("sha256:").unwrap_or(s);
    let bytes = hex::decode(hex_part).ok()?;
    bytes.try_into().ok()
}

/// `sha256:<hex>` rendering used in receipts and proofs.
pub fn display(h: &Hash) -> String {
    format!("sha256:{}", hex::encode(h))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 9162 Appendix (also Trillian/CT test vectors).
    fn vector_leaves() -> Vec<Hash> {
        let raw: [&[u8]; 8] = [
            b"",
            b"\x00",
            b"\x10",
            b"\x20\x21",
            b"\x30\x31",
            b"\x40\x41\x42\x43",
            b"\x50\x51\x52\x53\x54\x55\x56\x57",
            b"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f",
        ];
        raw.iter().map(|d| leaf_hash(d)).collect()
    }

    const ROOTS: [&str; 9] = [
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
        "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
        "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
        "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
        "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
        "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
    ];

    #[test]
    fn roots_match_rfc_vectors() {
        let leaves = vector_leaves();
        for (n, expected) in ROOTS.iter().enumerate() {
            assert_eq!(hex::encode(root(&leaves[..n])), *expected, "size {n}");
        }
    }

    #[test]
    fn inclusion_proofs_verify_for_every_leaf_and_size() {
        let leaves = vector_leaves();
        for size in 1..=leaves.len() {
            let tree = &leaves[..size];
            let r = root(tree);
            for i in 0..size {
                let proof = inclusion_proof(tree, i).unwrap();
                assert!(verify_inclusion(
                    &tree[i],
                    i as u64,
                    size as u64,
                    &proof,
                    &r
                ));
                // Wrong leaf, wrong index and wrong root are all rejected.
                assert!(!verify_inclusion(
                    &leaf_hash(b"x"),
                    i as u64,
                    size as u64,
                    &proof,
                    &r
                ));
                if size > 1 {
                    let other = (i + 1) % size;
                    assert!(!verify_inclusion(
                        &tree[i],
                        other as u64,
                        size as u64,
                        &proof,
                        &r
                    ));
                }
                assert!(!verify_inclusion(
                    &tree[i],
                    i as u64,
                    size as u64,
                    &proof,
                    &leaf_hash(b"y")
                ));
            }
        }
    }

    #[test]
    fn rfc_inclusion_vector() {
        // RFC 9162: PATH(0, D[8]) for the vector leaves.
        let leaves = vector_leaves();
        let proof = inclusion_proof(&leaves, 0).unwrap();
        let hex_proof: Vec<String> = proof.iter().map(hex::encode).collect();
        assert_eq!(
            hex_proof,
            vec![
                "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
                "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
                "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
            ]
        );
    }

    #[test]
    fn consistency_proofs_verify_for_every_prefix() {
        let leaves = vector_leaves();
        for second in 1..=leaves.len() {
            let tree = &leaves[..second];
            let second_root = root(tree);
            for first in 1..=second {
                let first_root = root(&tree[..first]);
                let proof = consistency_proof(tree, first).unwrap();
                assert!(
                    verify_consistency(
                        first as u64,
                        second as u64,
                        &first_root,
                        &second_root,
                        &proof
                    ),
                    "first={first} second={second}"
                );
                // A fork (different first root) is rejected.
                let forged = leaf_hash(b"fork");
                assert!(
                    !verify_consistency(first as u64, second as u64, &forged, &second_root, &proof)
                        || first_root == forged
                );
            }
        }
    }

    #[test]
    fn rfc_consistency_vectors() {
        let leaves = vector_leaves();
        let hexes = |v: Vec<Hash>| v.iter().map(hex::encode).collect::<Vec<_>>();
        // PROOF(1, D[1]) is empty; PROOF(2, D[8]) = [MTH(D[2:4]), MTH(D[4:8])].
        assert!(consistency_proof(&leaves[..1], 1).unwrap().is_empty());
        assert_eq!(
            hexes(consistency_proof(&leaves, 2).unwrap()),
            vec![
                "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
                "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
            ]
        );
        // PROOF(6, D[8]).
        assert_eq!(
            hexes(consistency_proof(&leaves, 6).unwrap()),
            vec![
                "0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
                "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
                "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
            ]
        );
    }

    #[test]
    fn parse_and_display_roundtrip() {
        let h = leaf_hash(b"abc");
        assert_eq!(parse_hash(&display(&h)), Some(h));
        assert_eq!(parse_hash(&hex::encode(h)), Some(h));
        assert_eq!(parse_hash("sha256:zz"), None);
    }
}
