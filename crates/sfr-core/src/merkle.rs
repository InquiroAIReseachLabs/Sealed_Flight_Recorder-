//! Domain-separated SHA-256 Merkle tree (SPEC B1.7): leaf hash = SHA-256(0x00 || leaf), node
//! hash = SHA-256(0x01 || left || right), and the tree shape of RFC 6962 section 2.1: the left
//! subtree holds the largest power of two strictly below the leaf count, so an odd node is
//! never duplicated.

use crate::crypto::CryptoBackend;
use crate::{MERKLE_LEAF_PREFIX, MERKLE_NODE_PREFIX};

/// Record spelling of the algorithm.
pub const ALGORITHM: &str = "sha256-rfc6962";

/// SHA-256(0x00 || leaf).
pub fn leaf_hash(crypto: &dyn CryptoBackend, leaf: &[u8]) -> [u8; 32] {
    crypto.sha256_concat(&[&[MERKLE_LEAF_PREFIX], leaf])
}

/// SHA-256(0x00 || tag || leaf): a leaf of a schema 3 record, bound to its section by the tag
/// byte (see [`crate::seal::Section`]), so a leaf cannot be moved to another section and still
/// give the same root.
pub fn tagged_leaf_hash(crypto: &dyn CryptoBackend, tag: u8, leaf: &[u8]) -> [u8; 32] {
    crypto.sha256_concat(&[&[MERKLE_LEAF_PREFIX, tag], leaf])
}

fn node_hash(crypto: &dyn CryptoBackend, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 65];
    buf[0] = MERKLE_NODE_PREFIX;
    buf[1..33].copy_from_slice(left);
    buf[33..].copy_from_slice(right);
    crypto.sha256(&buf)
}

/// Tagged leaf hashes ([`tagged_leaf_hash`]) of many leaves of one section, reusing one buffer
/// for the prefixed input.
pub fn tagged_leaf_hashes<'a>(
    crypto: &dyn CryptoBackend,
    tag: u8,
    leaves: impl Iterator<Item = &'a [u8]>,
) -> Vec<[u8; 32]> {
    let mut buf = Vec::new();
    leaves
        .map(|leaf| {
            buf.clear();
            buf.push(MERKLE_LEAF_PREFIX);
            buf.push(tag);
            buf.extend_from_slice(leaf);
            crypto.sha256(&buf)
        })
        .collect()
}

/// The Merkle tree hash of already-hashed leaves (RFC 6962 MTH). `None` for no leaves: a
/// record always has at least five.
pub fn root(crypto: &dyn CryptoBackend, leaves: &[[u8; 32]]) -> Option<[u8; 32]> {
    match leaves {
        [] => None,
        [one] => Some(*one),
        _ => {
            let mut k = 1usize;
            while k * 2 < leaves.len() {
                k *= 2;
            }
            let (l, r) = leaves.split_at(k);
            Some(node_hash(crypto, &root(crypto, l)?, &root(crypto, r)?))
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::crypto::test_backend::TestBackend;
    use crate::hex;

    #[test]
    fn roots_match_an_independent_rfc6962_computation() {
        // Python hashlib, leaves are the single bytes 0..n.
        let expected = [
            (
                1,
                "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
            ),
            (
                2,
                "a20bf9a7cc2dc8a08f5f415a71b19f6ac427bab54d24eec868b5d3103449953a",
            ),
            (
                3,
                "3b6cccd7e3e023ff393006f030315ee7ad9eb111b022b41fba7e5b7a3973f688",
            ),
            (
                4,
                "9bcd51240af4005168f033121ba85be5a6ed4f0e6a5fac262066729b8fbfdecb",
            ),
            (
                5,
                "b855b42d6c30f5b087e05266783fbd6e394f7b926013ccaa67700a8b0c5a596f",
            ),
            (
                6,
                "bb36e7d3d4cee5720cbd323d02fab15962e2ba1dadf5f8fc6eeef4fd6ad056a8",
            ),
            (
                7,
                "3560191803028444b232018ac047fdb561c09c23a7a6876c85e08b5e4d48e9f3",
            ),
        ];
        for (n, root_hex) in expected {
            let leaves: Vec<[u8; 32]> = (0..n)
                .map(|i| leaf_hash(&TestBackend, &[i as u8]))
                .collect();
            assert_eq!(
                hex(&root(&TestBackend, &leaves).unwrap()),
                root_hex,
                "n = {n}"
            );
        }
        assert_eq!(root(&TestBackend, &[]), None);
    }
}
