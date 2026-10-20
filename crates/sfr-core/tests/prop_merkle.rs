//! Property tests of the Merkle tree and of the leaf encoding (SPEC B1.7 "Hashing" and "Leaves",
//! `docs/RECORD_FORMAT.md` "Merkle leaves", `crates/sfr-core/src/merkle.rs`, and the leaf
//! construction in `crates/sfr-core/src/seal.rs`).
//!
//! Every expected value is computed here, independently of the code under test: SHA-256 through
//! the `sha2` crate directly (not through the backend of `sfr-core`), the tree of the document
//! (leaf hash SHA-256(0x00 || tag || leaf), node hash SHA-256(0x01 || left || right), the left
//! subtree holding the first `k` leaves, `k` the largest power of two strictly below the count),
//! and a second writer of the canonical JSON the document describes. Each property says in its
//! comment what it holds and where the statement comes from.
//!
//! The default run is deterministic and cheap (a fixed seed, 64 cases). A deep run:
//! `PROPTEST_CASES=100000 PROPTEST_RNG_SEED=1 cargo test -p sfr-core --test prop_merkle`.
// A panicking test is a failing test, so tests may use expect, unwrap and panic.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use proptest::collection::{btree_map, vec};
use proptest::prelude::*;
use proptest::test_runner::RngSeed;
use sfr_core::crypto::rustcrypto::RustCrypto;
use sfr_core::crypto::{CrateVersion, CryptoBackend, Sha256Stream};
use sfr_core::json::{MAX_SAFE_INTEGER, Obj, Value, canonical, parse, scan_canonical};
use sfr_core::seal::{self, LeafKind, RECORD_FIELDS, Section, TreeShape, signed_payload};
use sfr_core::{MERKLE_LEAF_PREFIX, MERKLE_NODE_PREFIX, SIGNED_PAYLOAD_PREFIX, merkle};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashSet};
use std::rc::Rc;

type Hash = [u8; 32];

/// The seed of the default run: the bytes of `merkle_1`. Any constant would do.
const SEED: u64 = 0x6d65_726b_6c65_5f31;

/// Cases per property in the default run, small enough that the whole file runs in seconds in a
/// debug build, also under emulation on a 32-bit ARM target.
const DEFAULT_CASES: u32 = 64;

/// The configuration of every property. It starts from `ProptestConfig::default()`, which reads
/// `PROPTEST_CASES` and `PROPTEST_RNG_SEED`; the fixed seed and the case count apply only when
/// the variable is not set. No regression file is written into the source tree: a failure prints
/// its seed and its minimal input, and the seed reproduces it.
fn config() -> ProptestConfig {
    let mut config = ProptestConfig::default();
    if std::env::var_os("PROPTEST_RNG_SEED").is_none() {
        config.rng_seed = RngSeed::Fixed(SEED);
    }
    if std::env::var_os("PROPTEST_CASES").is_none() {
        config.cases = DEFAULT_CASES;
    }
    config.failure_persistence = None;
    config
}

// ---------------------------------------------------------------------------------------------
// The reference tree, written from docs/RECORD_FORMAT.md "Merkle leaves" with `sha2` only.
// ---------------------------------------------------------------------------------------------

/// SHA-256 of the concatenation of `parts`.
fn sha(parts: &[&[u8]]) -> Hash {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// RECORD_FORMAT: a leaf's hash is SHA-256(`0x00` || tag || JCS(leaf)); without a tag (the
/// untagged `leaf_hash` of `merkle.rs`) it is SHA-256(`0x00` || leaf).
fn ref_leaf(leaf: &[u8]) -> Hash {
    sha(&[&[0x00], leaf])
}

/// SHA-256(`0x00` || tag || leaf).
fn ref_tagged_leaf(tag: u8, leaf: &[u8]) -> Hash {
    sha(&[&[0x00, tag], leaf])
}

/// RECORD_FORMAT: an interior node's hash is SHA-256(`0x01` || left || right).
fn ref_node(left: &Hash, right: &Hash) -> Hash {
    sha(&[&[0x01], left, right])
}

/// RECORD_FORMAT: "k the largest power of two strictly below n" (for n above one).
fn split_point(n: usize) -> usize {
    1usize << (n - 1).ilog2()
}

/// RECORD_FORMAT: for `n` leaves, `n` above one, the left subtree holds the first `k` leaves and
/// the right subtree the rest, recursively; a single leaf's tree hash is its leaf hash; nothing
/// is duplicated. The document gives no value for the empty tree (`None` here, as in the code,
/// whose comment says a record always has at least five leaves).
fn ref_root(hashes: &[Hash]) -> Option<Hash> {
    match hashes {
        [] => None,
        [one] => Some(*one),
        _ => {
            let (left, right) = hashes.split_at(split_point(hashes.len()));
            Some(ref_node(&ref_root(left)?, &ref_root(right)?))
        }
    }
}

/// The same tree built bottom up, as a check on `ref_root` itself: equal-sized subtrees merge as
/// leaves arrive, and the remaining perfect subtrees (the binary digits of the count, largest
/// first) join from the right. For the shape the document states, it gives the same hash.
fn ref_root_bottom_up(hashes: &[Hash]) -> Option<Hash> {
    let mut stack: Vec<(Hash, usize)> = Vec::new();
    for h in hashes {
        let mut current = (*h, 1usize);
        while let Some(&(top, size)) = stack.last() {
            if size != current.1 {
                break;
            }
            stack.pop();
            current = (ref_node(&top, &current.0), size * 2);
        }
        stack.push(current);
    }
    let mut from_right = stack.into_iter().rev();
    let (mut acc, _) = from_right.next()?;
    for (h, _) in from_right {
        acc = ref_node(&h, &acc);
    }
    Some(acc)
}

/// The preimages of the node hashes of the reference tree, appended to `out` (left subtree
/// first), and the tree hash.
fn ref_node_preimages(hashes: &[Hash], out: &mut Vec<Vec<u8>>) -> Option<Hash> {
    match hashes {
        [] => None,
        [one] => Some(*one),
        _ => {
            let (left, right) = hashes.split_at(split_point(hashes.len()));
            let l = ref_node_preimages(left, out)?;
            let r = ref_node_preimages(right, out)?;
            let mut preimage = vec![0x01u8];
            preimage.extend_from_slice(&l);
            preimage.extend_from_slice(&r);
            out.push(preimage);
            Some(ref_node(&l, &r))
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The code under test, driven through its public functions.
// ---------------------------------------------------------------------------------------------

/// The tagged leaf hashes of `leaves`, through `merkle::tagged_leaf_hashes`.
fn tagged_hashes(tag: u8, leaves: &[Vec<u8>]) -> Vec<Hash> {
    merkle::tagged_leaf_hashes(&RustCrypto, tag, leaves.iter().map(|l| l.as_slice()))
}

/// The root over `leaves` hashed with `tag`, through the public functions.
fn tree_root(tag: u8, leaves: &[Vec<u8>]) -> Option<Hash> {
    merkle::root(&RustCrypto, &tagged_hashes(tag, leaves))
}

type Preimages = Rc<RefCell<Vec<Vec<u8>>>>;

/// A backend that implements only the streaming primitive, so every default method of
/// `CryptoBackend` routes through it, and that records the exact bytes of every SHA-256 it
/// computes. The hashes it returns are real SHA-256 values, so the code under test behaves as it
/// does with `RustCrypto`; the record shows what was hashed.
struct Recorder(Preimages);

struct RecordingStream {
    buf: Vec<u8>,
    log: Preimages,
}

impl Recorder {
    fn new() -> Recorder {
        Recorder(Rc::new(RefCell::new(Vec::new())))
    }

    /// The preimages recorded since the last call.
    fn take(&self) -> Vec<Vec<u8>> {
        std::mem::take(&mut *self.0.borrow_mut())
    }
}

impl Sha256Stream for RecordingStream {
    fn update(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    fn finish(self: Box<Self>) -> Hash {
        let this = *self;
        let digest = sha(&[&this.buf]);
        this.log.borrow_mut().push(this.buf);
        digest
    }
}

impl CryptoBackend for Recorder {
    fn crates(&self) -> &'static [CrateVersion] {
        &[]
    }

    fn sha256_stream(&self) -> Box<dyn Sha256Stream> {
        Box::new(RecordingStream {
            buf: Vec::new(),
            log: Rc::clone(&self.0),
        })
    }

    fn ed25519_verify(&self, _: &[u8; 32], _: &[u8], _: &[u8; 64]) -> bool {
        false
    }
}

fn sorted(mut v: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    v.sort();
    v
}

// ---------------------------------------------------------------------------------------------
// Generators.
// ---------------------------------------------------------------------------------------------

/// A list of `min..=max` items. One time in four the items are drawn from a pool of at most
/// three, so lists with repeated items (equal leaves, equal subtrees) are common.
fn list_of<S>(item: S, min: usize, max: usize) -> BoxedStrategy<Vec<S::Value>>
where
    S: Strategy + Clone + 'static,
    S::Value: Clone + 'static,
{
    prop_oneof![
        3 => vec(item.clone(), min..=max),
        1 => (vec(item, 1..=3), vec(0usize..3, min..=max)).prop_map(|(pool, picks)| {
            picks.into_iter().map(|i| pool[i % pool.len()].clone()).collect()
        }),
    ]
    .boxed()
}

/// Leaf bytes: arbitrary bytes, one repeated byte, runs of the two prefix bytes 0x00 and 0x01,
/// and 65 bytes that start with a prefix byte (the length of a node preimage).
fn leaf_bytes() -> BoxedStrategy<Vec<u8>> {
    prop_oneof![
        4 => vec(any::<u8>(), 0..48),
        1 => (any::<u8>(), 0usize..70).prop_map(|(b, n)| vec![b; n]),
        1 => vec(prop_oneof![Just(0x00u8), Just(0x01u8)], 0..70),
        1 => (0u8..2, vec(any::<u8>(), 64)).prop_map(|(prefix, mut v)| {
            v.insert(0, prefix);
            v
        }),
    ]
    .boxed()
}

fn hash() -> BoxedStrategy<Hash> {
    prop::array::uniform32(any::<u8>()).boxed()
}

// ---------------------------------------------------------------------------------------------
// 1. Reference equality, and what the document says about the empty and the single-leaf tree.
// ---------------------------------------------------------------------------------------------

#[test]
fn the_prefix_constants_and_the_algorithm_name_are_the_documented_ones() {
    // RECORD_FORMAT "Merkle leaves": leaves are prefixed 0x00, interior nodes 0x01; "Signed
    // payload": the domain separation prefix is ASCII SFR-RECORD-V1; "merkle" member: the
    // algorithm is sha256-rfc6962.
    assert_eq!(MERKLE_LEAF_PREFIX, 0x00);
    assert_eq!(MERKLE_NODE_PREFIX, 0x01);
    assert_eq!(SIGNED_PAYLOAD_PREFIX, b"SFR-RECORD-V1");
    assert_eq!(merkle::ALGORITHM, "sha256-rfc6962");
}

#[test]
fn the_reference_reproduces_the_independent_python_roots() {
    // The roots that the unit test `roots_match_an_independent_rfc6962_computation` in merkle.rs
    // took from Python hashlib (leaves are the single bytes 0..n, untagged), checked against
    // this file's reference and against the code, so a mistake in the reference shows here and
    // not as a false failure of a property.
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
            5,
            "b855b42d6c30f5b087e05266783fbd6e394f7b926013ccaa67700a8b0c5a596f",
        ),
        (
            7,
            "3560191803028444b232018ac047fdb561c09c23a7a6876c85e08b5e4d48e9f3",
        ),
    ];
    for (n, root_hex) in expected {
        let reference: Vec<Hash> = (0..n).map(|i| ref_leaf(&[i as u8])).collect();
        let code: Vec<Hash> = (0..n)
            .map(|i| merkle::leaf_hash(&RustCrypto, &[i as u8]))
            .collect();
        assert_eq!(reference, code, "n = {n}");
        for root in [
            ref_root(&reference),
            ref_root_bottom_up(&reference),
            merkle::root(&RustCrypto, &code),
        ] {
            assert_eq!(sfr_core::hex(&root.unwrap()), root_hex, "n = {n}");
        }
    }
}

#[test]
fn the_split_point_is_the_largest_power_of_two_strictly_below_the_count() {
    // RECORD_FORMAT: "k the largest power of two strictly below n". Holds the reference's own
    // formula to that sentence, for every count up to 5000 and around 2^16 and 2^20.
    for n in (2..=5000usize).chain([65_535, 65_536, 65_537, 1 << 20, (1 << 20) + 1]) {
        let k = split_point(n);
        assert!(k.is_power_of_two(), "n = {n}");
        assert!(k < n, "n = {n}");
        assert!(k * 2 >= n, "n = {n}: the next power of two is not below n");
    }
}

#[test]
fn the_empty_tree_has_no_root_and_a_single_leaf_is_its_own_root() {
    // The document gives no value for the empty tree, and merkle.rs says `None`: "a record
    // always has at least five" leaves. Nothing from RFC 6962's empty-tree hash is assumed.
    assert_eq!(merkle::root(&RustCrypto, &[]), None);
    assert_eq!(ref_root(&[]), None);
    assert_eq!(tree_root(0x06, &[]), None);
    assert!(tagged_hashes(0x06, &[]).is_empty());
    // RECORD_FORMAT: "a single leaf's tree hash is its leaf hash".
    let leaf = b"{\"id\":\"R1\"}".to_vec();
    assert_eq!(
        tree_root(0x06, std::slice::from_ref(&leaf)),
        Some(ref_tagged_leaf(0x06, &leaf))
    );
}

#[test]
fn every_leaf_count_matches_the_reference_up_to_the_boundaries_of_powers_of_two() {
    // RECORD_FORMAT tree shape, checked for every count from 0 to 70 and around each power of
    // two up to 4096, where an off-by-one in the split would first show. Leaves are the
    // big-endian bytes of their index.
    let counts = (0..=70usize).chain([
        127, 128, 129, 255, 256, 257, 511, 512, 513, 1023, 1024, 1025, 2047, 2048, 2049, 4095,
        4096, 4097,
    ]);
    for n in counts {
        let leaves: Vec<Vec<u8>> = (0..n as u32).map(|i| i.to_be_bytes().to_vec()).collect();
        let hashes = tagged_hashes(0x08, &leaves);
        let expected: Vec<Hash> = leaves.iter().map(|l| ref_tagged_leaf(0x08, l)).collect();
        assert_eq!(hashes, expected, "n = {n}");
        let root = merkle::root(&RustCrypto, &hashes);
        assert_eq!(root, ref_root(&expected), "n = {n}");
        assert_eq!(root, ref_root_bottom_up(&expected), "n = {n}");
    }
}

#[test]
fn an_odd_node_is_never_duplicated() {
    // RECORD_FORMAT: "nothing is duplicated". The trees of 3, 5, 6 and 7 leaves, written out
    // by hand from the document's rule (k = 2, 4, 4, 4).
    let h: Vec<Hash> = (0..7u8).map(|i| ref_leaf(&[i])).collect();
    let n = ref_node;
    let root = |count: usize| merkle::root(&RustCrypto, &h[..count]).unwrap();
    assert_eq!(root(3), n(&n(&h[0], &h[1]), &h[2]));
    let four = n(&n(&h[0], &h[1]), &n(&h[2], &h[3]));
    assert_eq!(root(4), four);
    assert_eq!(root(5), n(&four, &h[4]));
    assert_eq!(root(6), n(&four, &n(&h[4], &h[5])));
    assert_eq!(root(7), n(&four, &n(&n(&h[4], &h[5]), &h[6])));
    // The shape that duplicates an odd node would make [a, b, c] and [a, b, c, c] one root.
    for count in 1..=6 {
        let mut doubled = h[..count].to_vec();
        doubled.push(h[count - 1]);
        assert_ne!(
            merkle::root(&RustCrypto, &h[..count]),
            merkle::root(&RustCrypto, &doubled),
            "count = {count}"
        );
    }
}

proptest! {
    #![proptest_config(config())]

    /// RECORD_FORMAT "Merkle leaves" and `merkle::tagged_leaf_hashes`, `merkle::root`: for 0 to
    /// 40 arbitrary leaves under any tag, the leaf hashes are SHA-256(0x00 || tag || leaf) and
    /// the root is the reference tree over them (built two ways).
    #[test]
    fn the_root_of_tagged_leaves_equals_the_reference_tree(
        tag in any::<u8>(),
        leaves in list_of(leaf_bytes(), 0, 40),
    ) {
        let hashes = tagged_hashes(tag, &leaves);
        let expected: Vec<Hash> = leaves.iter().map(|l| ref_tagged_leaf(tag, l)).collect();
        prop_assert_eq!(&hashes, &expected);
        let root = merkle::root(&RustCrypto, &hashes);
        prop_assert_eq!(root, ref_root(&expected));
        prop_assert_eq!(root, ref_root_bottom_up(&expected));
        prop_assert_eq!(root.is_none(), leaves.is_empty());
    }

    /// RECORD_FORMAT "Merkle leaves" with no tag (`merkle::leaf_hash`, SHA-256(0x00 || leaf)):
    /// for 0 to 40 arbitrary leaves the root is the reference tree.
    #[test]
    fn the_root_of_untagged_leaves_equals_the_reference_tree(
        leaves in list_of(leaf_bytes(), 0, 40),
    ) {
        let hashes: Vec<Hash> =
            leaves.iter().map(|l| merkle::leaf_hash(&RustCrypto, l)).collect();
        let expected: Vec<Hash> = leaves.iter().map(|l| ref_leaf(l)).collect();
        prop_assert_eq!(&hashes, &expected);
        prop_assert_eq!(merkle::root(&RustCrypto, &hashes), ref_root(&expected));
    }

    /// RECORD_FORMAT tree shape, with no leaf hashing in the way: `merkle::root` over 0 to 40
    /// arbitrary 32-byte values equals the reference tree. A single value is its own root.
    #[test]
    fn the_root_of_arbitrary_hashes_equals_the_reference_tree(
        hashes in list_of(hash(), 0, 40),
    ) {
        let expected = ref_root(&hashes);
        prop_assert_eq!(merkle::root(&RustCrypto, &hashes), expected);
        prop_assert_eq!(expected, ref_root_bottom_up(&hashes));
        if let [one] = hashes.as_slice() {
            prop_assert_eq!(expected, Some(*one));
        }
    }

    /// RECORD_FORMAT: for `n` above one the root is SHA-256(0x01 || left || right) over the
    /// roots of the first `k` leaves and of the rest, `k` the largest power of two strictly
    /// below `n`. Checked at the top node with the code's own `root` on both halves.
    #[test]
    fn the_root_joins_the_first_k_leaves_and_the_rest(hashes in list_of(hash(), 2, 40)) {
        let k = split_point(hashes.len());
        let (left, right) = hashes.split_at(k);
        let l = merkle::root(&RustCrypto, left).unwrap();
        let r = merkle::root(&RustCrypto, right).unwrap();
        prop_assert_eq!(
            merkle::root(&RustCrypto, &hashes),
            Some(ref_node(&l, &r))
        );
    }

    /// RECORD_FORMAT: a leaf's hash is over `0x00 || tag || bytes` and a node's over
    /// `0x01 || left || right` (65 bytes), and nothing else is hashed. The preimages the code
    /// hands to the backend are exactly the reference's: one per leaf, and one per interior node
    /// (`n - 1`). This checks what is hashed, not the hash function.
    #[test]
    fn the_tree_hashes_exactly_the_documented_preimages(
        tag in any::<u8>(),
        leaves in list_of(leaf_bytes(), 0, 40),
    ) {
        let recorder = Recorder::new();
        let hashes = merkle::tagged_leaf_hashes(&recorder, tag, leaves.iter().map(|l| l.as_slice()));
        let leaf_preimages: Vec<Vec<u8>> = leaves
            .iter()
            .map(|l| [&[0x00, tag][..], l.as_slice()].concat())
            .collect();
        prop_assert_eq!(recorder.take(), leaf_preimages);

        let root = merkle::root(&recorder, &hashes);
        let mut node_preimages = Vec::new();
        let expected = ref_node_preimages(&hashes, &mut node_preimages);
        prop_assert_eq!(root, expected);
        let seen = recorder.take();
        prop_assert_eq!(seen.len(), hashes.len().saturating_sub(1));
        prop_assert!(seen.iter().all(|p| p.len() == 65 && p[0] == 0x01));
        prop_assert_eq!(sorted(seen), sorted(node_preimages));
        // The same tree through the real backend.
        prop_assert_eq!(root, merkle::root(&RustCrypto, &hashes));
    }

    /// The untagged and the single-leaf forms: `leaf_hash` hashes `0x00 || leaf` and
    /// `tagged_leaf_hash` hashes `0x00 || tag || leaf`, one SHA-256 each, nothing before or
    /// after (RECORD_FORMAT "Merkle leaves").
    #[test]
    fn a_leaf_hash_covers_exactly_the_prefix_the_tag_and_the_bytes(
        tag in any::<u8>(),
        leaf in leaf_bytes(),
    ) {
        let recorder = Recorder::new();
        let plain = merkle::leaf_hash(&recorder, &leaf);
        prop_assert_eq!(recorder.take(), vec![[&[0x00][..], leaf.as_slice()].concat()]);
        let tagged = merkle::tagged_leaf_hash(&recorder, tag, &leaf);
        prop_assert_eq!(recorder.take(), vec![[&[0x00, tag][..], leaf.as_slice()].concat()]);
        prop_assert_eq!(plain, ref_leaf(&leaf));
        prop_assert_eq!(tagged, ref_tagged_leaf(tag, &leaf));
    }

    /// RECORD_FORMAT: a single leaf's tree hash is its leaf hash, so the root of one value is
    /// that value, whatever it is.
    #[test]
    fn a_single_value_is_its_own_root(one in hash()) {
        prop_assert_eq!(merkle::root(&RustCrypto, &[one]), Some(one));
    }
}

// ---------------------------------------------------------------------------------------------
// 2. Determinism and sensitivity.
// ---------------------------------------------------------------------------------------------

#[test]
fn all_single_edits_of_small_trees_give_distinct_roots() {
    // For counts 0 to 17 and 31 to 33 (the powers of two from 1 to 32 and their neighbours): the
    // tree, and every tree got from it by dropping a leaf, inserting a new leaf anywhere,
    // duplicating a leaf in place, duplicating the last leaf, swapping two leaves, or flipping
    // one bit of one leaf (every bit up to 17 leaves, the lowest and the highest bit of each
    // byte above), are pairwise different lists of leaves, so (SHA-256 having no collision
    // here) pairwise different roots. This is the exhaustive form of the sensitivity
    // properties below.
    for n in (0..=17usize).chain(31..=33) {
        let base: Vec<Vec<u8>> = (0..n).map(|i| vec![i as u8; i % 4 + 1]).collect();
        let mut lists: HashSet<Vec<Vec<u8>>> = HashSet::new();
        lists.insert(base.clone());
        for i in 0..=n {
            let mut v = base.clone();
            v.insert(i, vec![0xee, 0xee]);
            lists.insert(v);
        }
        for (i, leaf) in base.iter().enumerate() {
            let mut dropped = base.clone();
            dropped.remove(i);
            lists.insert(dropped);
            let mut doubled = base.clone();
            doubled.insert(i, leaf.clone());
            lists.insert(doubled);
            for (j, other) in base.iter().enumerate().skip(i + 1) {
                let mut swapped = base.clone();
                swapped.swap(i, j);
                assert_ne!(leaf, other);
                lists.insert(swapped);
            }
            let bits: &[u32] = if n <= 17 {
                &[0, 1, 2, 3, 4, 5, 6, 7]
            } else {
                &[0, 7]
            };
            for p in 0..leaf.len() {
                for bit in bits {
                    let mut flipped = base.clone();
                    flipped[i][p] ^= 1 << bit;
                    lists.insert(flipped);
                }
            }
        }
        if let Some(last) = base.last() {
            let mut doubled = base.clone();
            doubled.push(last.clone());
            lists.insert(doubled);
        }
        let roots: HashSet<Option<Hash>> = lists.iter().map(|l| tree_root(0x08, l)).collect();
        assert_eq!(roots.len(), lists.len(), "n = {n}");
    }
}

#[test]
fn a_tree_of_equal_leaves_has_a_different_root_for_every_count() {
    // A tree that duplicated an odd node would hash [a, b, c] as it hashes [a, b, c, c]; this
    // tree does not (RECORD_FORMAT: "nothing is duplicated"). With every leaf equal, the root is
    // different for each count from 0 (no root) to 130.
    let leaf = vec![0xabu8; 5];
    let roots: HashSet<Option<Hash>> = (0..=130usize)
        .map(|n| tree_root(0x08, &vec![leaf.clone(); n]))
        .collect();
    assert_eq!(roots.len(), 131);
}

proptest! {
    #![proptest_config(config())]

    /// SPEC B1.10 "Deterministic": the root is a function of the leaves. Two computations, with
    /// separate backend values, give the same hashes and root, and a backend that implements
    /// only the streaming primitive (so the trait's default methods run) gives the same too.
    #[test]
    fn the_root_does_not_change_between_calls_or_backends(
        tag in any::<u8>(),
        leaves in list_of(leaf_bytes(), 0, 40),
    ) {
        let first = tree_root(tag, &leaves);
        prop_assert_eq!(first, tree_root(tag, &leaves));
        let recorder = Recorder::new();
        let hashes = merkle::tagged_leaf_hashes(&recorder, tag, leaves.iter().map(|l| l.as_slice()));
        prop_assert_eq!(merkle::root(&recorder, &hashes), first);
    }

    /// Changing any one byte of any leaf changes the root (SPEC B1.10 "Tamper property" for the
    /// tree). A leaf that is empty, which has no byte to change, gets one byte instead.
    #[test]
    fn changing_one_byte_of_one_leaf_changes_the_root(
        tag in any::<u8>(),
        leaves in list_of(leaf_bytes(), 1, 40),
        which in any::<prop::sample::Index>(),
        at in any::<prop::sample::Index>(),
        mask in 1u8..=255,
    ) {
        let i = which.index(leaves.len());
        let mut changed = leaves.clone();
        if changed[i].is_empty() {
            changed[i].push(mask);
        } else {
            let p = at.index(changed[i].len());
            changed[i][p] ^= mask;
        }
        prop_assert_ne!(tree_root(tag, &leaves), tree_root(tag, &changed));
    }

    /// Changing any one bit of any 32-byte value changes the root, with no leaf hashing in the
    /// way: every byte of every hash reaches the root.
    #[test]
    fn changing_one_bit_of_one_hash_changes_the_root(
        hashes in list_of(hash(), 1, 40),
        which in any::<prop::sample::Index>(),
        bit in 0usize..256,
    ) {
        let i = which.index(hashes.len());
        let mut changed = hashes.clone();
        changed[i][bit / 8] ^= 1 << (bit % 8);
        prop_assert_ne!(
            merkle::root(&RustCrypto, &hashes),
            merkle::root(&RustCrypto, &changed)
        );
    }

    /// Dropping any one leaf changes the root, the last leaf and the only leaf included (the
    /// tree of no leaves has no root, which differs from any root).
    #[test]
    fn dropping_a_leaf_changes_the_root(
        tag in any::<u8>(),
        leaves in list_of(leaf_bytes(), 1, 40),
        which in any::<prop::sample::Index>(),
    ) {
        let mut dropped = leaves.clone();
        dropped.remove(which.index(leaves.len()));
        prop_assert_ne!(tree_root(tag, &leaves), tree_root(tag, &dropped));
    }

    /// Appending a leaf, or inserting one anywhere, changes the root, also when the new leaf
    /// equals a leaf already there.
    #[test]
    fn adding_a_leaf_anywhere_changes_the_root(
        tag in any::<u8>(),
        leaves in list_of(leaf_bytes(), 0, 40),
        fresh in leaf_bytes(),
        copy_of in any::<prop::sample::Index>(),
        copy in any::<bool>(),
        position in any::<prop::sample::Index>(),
    ) {
        let extra = if copy && !leaves.is_empty() {
            leaves[copy_of.index(leaves.len())].clone()
        } else {
            fresh
        };
        let mut appended = leaves.clone();
        appended.push(extra.clone());
        prop_assert_ne!(tree_root(tag, &leaves), tree_root(tag, &appended));
        let mut inserted = leaves.clone();
        inserted.insert(position.index(leaves.len() + 1), extra);
        prop_assert_ne!(tree_root(tag, &leaves), tree_root(tag, &inserted));
    }

    /// Duplicating a leaf changes the root, in place and at the end. The duplicate of the last
    /// leaf is the case where a tree that duplicates an odd node would keep the root
    /// (RECORD_FORMAT: "nothing is duplicated").
    #[test]
    fn duplicating_a_leaf_changes_the_root(
        tag in any::<u8>(),
        leaves in list_of(leaf_bytes(), 1, 40),
        which in any::<prop::sample::Index>(),
    ) {
        let i = which.index(leaves.len());
        let mut in_place = leaves.clone();
        in_place.insert(i, leaves[i].clone());
        prop_assert_ne!(tree_root(tag, &leaves), tree_root(tag, &in_place));
        let mut at_end = leaves.clone();
        at_end.push(leaves[leaves.len() - 1].clone());
        prop_assert_ne!(tree_root(tag, &leaves), tree_root(tag, &at_end));
    }

    /// Swapping two leaves changes the root exactly when they differ: the order of the leaves is
    /// part of the root (RECORD_FORMAT: "The leaves, in this order"), and swapping equal leaves
    /// is no change at all.
    #[test]
    fn swapping_two_leaves_changes_the_root_exactly_when_they_differ(
        tag in any::<u8>(),
        leaves in list_of(leaf_bytes(), 2, 40),
        a in any::<prop::sample::Index>(),
        b in any::<prop::sample::Index>(),
    ) {
        let (i, j) = (a.index(leaves.len()), b.index(leaves.len()));
        let mut swapped = leaves.clone();
        swapped.swap(i, j);
        if leaves[i] == leaves[j] {
            prop_assert_eq!(tree_root(tag, &leaves), tree_root(tag, &swapped));
        } else {
            prop_assert_ne!(tree_root(tag, &leaves), tree_root(tag, &swapped));
        }
    }

    /// Swapping two different 32-byte values changes the root, and reversing a list of values
    /// that are not a palindrome changes it: the position of a value is part of the root.
    #[test]
    fn swapping_or_reversing_hashes_changes_the_root_unless_they_are_equal(
        hashes in list_of(hash(), 2, 40),
        a in any::<prop::sample::Index>(),
        b in any::<prop::sample::Index>(),
    ) {
        let (i, j) = (a.index(hashes.len()), b.index(hashes.len()));
        let mut swapped = hashes.clone();
        swapped.swap(i, j);
        let before = merkle::root(&RustCrypto, &hashes);
        let after = merkle::root(&RustCrypto, &swapped);
        if hashes[i] == hashes[j] {
            prop_assert_eq!(before, after);
        } else {
            prop_assert_ne!(before, after);
        }
        let mut reversed = hashes.clone();
        reversed.reverse();
        let reversed_root = merkle::root(&RustCrypto, &reversed);
        if reversed == hashes {
            prop_assert_eq!(before, reversed_root);
        } else {
            prop_assert_ne!(before, reversed_root);
        }
    }

    /// The tag of one leaf is part of the root: the same bytes under another tag in one
    /// position give another root (RECORD_FORMAT: the tag binds a leaf to its section).
    #[test]
    fn changing_the_tag_of_one_leaf_changes_the_root(
        tags in vec(0u8..=9, 1..=40),
        leaves in vec(leaf_bytes(), 40),
        which in any::<prop::sample::Index>(),
        delta in 1u8..=255,
    ) {
        let leaves = &leaves[..tags.len()];
        let root = |tags: &[u8]| {
            let hashes: Vec<Hash> = tags
                .iter()
                .zip(leaves)
                .map(|(t, l)| merkle::tagged_leaf_hash(&RustCrypto, *t, l))
                .collect();
            merkle::root(&RustCrypto, &hashes)
        };
        let mut other = tags.clone();
        let i = which.index(tags.len());
        other[i] ^= delta;
        prop_assert_ne!(root(&tags), root(&other));
    }

    /// Distinct lists of leaves have distinct roots: for two independently drawn lists (often
    /// short, often with repeated leaves) the roots are equal only if the lists are.
    #[test]
    fn different_lists_of_leaves_have_different_roots(
        tag in any::<u8>(),
        a in list_of(leaf_bytes(), 0, 12),
        b in list_of(leaf_bytes(), 0, 12),
    ) {
        prop_assert_eq!(a == b, tree_root(tag, &a) == tree_root(tag, &b));
    }
}

#[test]
fn every_bit_of_every_leaf_matters() {
    // The exhaustive form of "changing one byte of a leaf changes the root", for 7 leaves of
    // 1 to 70 bytes (the 70-byte leaf spans one SHA-256 block boundary): each of the bits flips.
    let leaves: Vec<Vec<u8>> = [1usize, 2, 3, 31, 32, 64, 70]
        .iter()
        .enumerate()
        .map(|(i, len)| (0..*len).map(|p| (i * 31 + p * 7) as u8).collect())
        .collect();
    let root = tree_root(0x08, &leaves);
    let mut seen = HashSet::new();
    seen.insert(root);
    let mut flips = 0;
    for (i, leaf) in leaves.iter().enumerate() {
        for p in 0..leaf.len() {
            for bit in 0..8 {
                let mut changed = leaves.clone();
                changed[i][p] ^= 1 << bit;
                assert!(
                    seen.insert(tree_root(0x08, &changed)),
                    "leaf {i} byte {p} bit {bit}"
                );
                flips += 1;
            }
        }
    }
    assert_eq!(flips, 8 * (1 + 2 + 3 + 31 + 32 + 64 + 70));
}

// ---------------------------------------------------------------------------------------------
// 3. Domain separation.
// ---------------------------------------------------------------------------------------------

/// The 64 bytes of two hashes side by side.
fn concat64(x: &Hash, y: &Hash) -> Vec<u8> {
    [&x[..], &y[..]].concat()
}

proptest! {
    #![proptest_config(config())]

    /// RECORD_FORMAT: leaves are hashed with prefix 0x00, nodes with 0x01 (SPEC B1.7 domain
    /// separation). The root of two leaves a and b is never the hash of a leaf made from the
    /// concatenation of the two leaf hashes: not the plain leaf hash, not the tagged one under
    /// any of ten tags, and not the leaf hash of the same bytes written with the node prefix
    /// first. As a tree: the tree of one such leaf has another root than the tree of a and b.
    #[test]
    fn the_root_of_two_leaves_is_not_the_hash_of_a_leaf_made_from_their_hashes(
        tag in any::<u8>(),
        a in leaf_bytes(),
        b in leaf_bytes(),
    ) {
        let ha = merkle::tagged_leaf_hash(&RustCrypto, tag, &a);
        let hb = merkle::tagged_leaf_hash(&RustCrypto, tag, &b);
        let node = merkle::root(&RustCrypto, &[ha, hb]).unwrap();
        prop_assert_eq!(node, ref_node(&ha, &hb));
        let forged = concat64(&ha, &hb);
        prop_assert_ne!(node, merkle::leaf_hash(&RustCrypto, &forged));
        for t in [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, tag] {
            prop_assert_ne!(node, merkle::tagged_leaf_hash(&RustCrypto, t, &forged));
        }
        let with_node_prefix = [&[MERKLE_NODE_PREFIX][..], forged.as_slice()].concat();
        prop_assert_ne!(node, merkle::leaf_hash(&RustCrypto, &with_node_prefix));
        // As trees: one leaf holding the forged bytes is not the tree of the two leaves.
        prop_assert_ne!(Some(node), tree_root(tag, &[forged]));
    }

    /// The same shape inside a larger tree: the top node of any tree of two or more leaves is
    /// not the leaf hash of its two child hashes written side by side, so a subtree cannot be
    /// presented as one leaf (the second-preimage shape of an interior node).
    #[test]
    fn the_top_node_of_a_tree_is_not_a_leaf_over_its_two_children(
        tag in any::<u8>(),
        leaves in list_of(leaf_bytes(), 2, 40),
    ) {
        let hashes = tagged_hashes(tag, &leaves);
        let (left, right) = hashes.split_at(split_point(hashes.len()));
        let l = merkle::root(&RustCrypto, left).unwrap();
        let r = merkle::root(&RustCrypto, right).unwrap();
        let top = merkle::root(&RustCrypto, &hashes).unwrap();
        let forged = concat64(&l, &r);
        prop_assert_ne!(top, merkle::leaf_hash(&RustCrypto, &forged));
        prop_assert_ne!(top, merkle::tagged_leaf_hash(&RustCrypto, tag, &forged));
    }

    /// A leaf hash never equals a node hash for the same bytes: for any two 32-byte values x
    /// and y, `leaf_hash(x || y)` and `tagged_leaf_hash(t, x || y)` differ from the node hash
    /// of x and y (the preimages differ in their first byte), and the node hash is the
    /// reference's.
    #[test]
    fn a_leaf_hash_never_equals_a_node_hash_over_the_same_bytes(
        x in hash(),
        y in hash(),
        tag in any::<u8>(),
    ) {
        let node = merkle::root(&RustCrypto, &[x, y]).unwrap();
        prop_assert_eq!(node, sha(&[&[0x01], &x, &y]));
        let bytes = concat64(&x, &y);
        prop_assert_eq!(merkle::leaf_hash(&RustCrypto, &bytes), sha(&[&[0x00], &x, &y]));
        prop_assert_ne!(node, merkle::leaf_hash(&RustCrypto, &bytes));
        prop_assert_ne!(node, merkle::tagged_leaf_hash(&RustCrypto, tag, &bytes));
        // A 65-byte leaf that starts with the node prefix is still a leaf.
        let looks_like_a_node = [&[0x01][..], bytes.as_slice()].concat();
        prop_assert_ne!(node, merkle::leaf_hash(&RustCrypto, &looks_like_a_node));
    }
}

#[test]
fn no_tag_makes_a_leaf_hash_equal_a_node_hash_or_another_tag_s_hash() {
    // The exhaustive form over all 256 tags, for fixed bytes: the node hash of x and y differs
    // from the tagged leaf hash of x || y under every tag, and the 256 tagged hashes and the
    // untagged one are pairwise different.
    let x = ref_leaf(b"x");
    let y = ref_leaf(b"y");
    let node = ref_node(&x, &y);
    let bytes = concat64(&x, &y);
    let mut seen = HashSet::new();
    assert!(seen.insert(merkle::leaf_hash(&RustCrypto, &bytes)));
    for tag in 0..=255u8 {
        let h = merkle::tagged_leaf_hash(&RustCrypto, tag, &bytes);
        assert_ne!(h, node, "tag {tag}");
        assert!(seen.insert(h), "tag {tag}");
    }
    assert_eq!(seen.len(), 257);
}

// ---------------------------------------------------------------------------------------------
// 4. tagged_leaf_hash and tagged_leaf_hashes.
// ---------------------------------------------------------------------------------------------

#[test]
fn the_buffer_of_tagged_leaf_hashes_leaves_no_stale_bytes() {
    // `tagged_leaf_hashes` reuses one buffer for the prefixed input; a longer leaf followed by
    // a shorter or an empty one must not leave its bytes in the next preimage.
    let leaves: Vec<&[u8]> = vec![
        &[7u8; 100][..],
        &[8u8; 3][..],
        &[][..],
        &[9u8; 64][..],
        &[][..],
    ];
    let recorder = Recorder::new();
    let hashes = merkle::tagged_leaf_hashes(&recorder, 0x07, leaves.iter().copied());
    let expected: Vec<Vec<u8>> = leaves
        .iter()
        .map(|l| [&[0x00, 0x07][..], *l].concat())
        .collect();
    assert_eq!(recorder.take(), expected);
    let reference: Vec<Hash> = leaves.iter().map(|l| ref_tagged_leaf(0x07, l)).collect();
    assert_eq!(hashes, reference);
}

proptest! {
    #![proptest_config(config())]

    /// `merkle::tagged_leaf_hash` is SHA-256(0x00 || tag || leaf) (RECORD_FORMAT), and
    /// `merkle::tagged_leaf_hashes` gives the same hash for each leaf of a list, in order, as
    /// the single function and as the reference; leaves of any length follow each other (the
    /// shared buffer is cleared between them).
    #[test]
    fn tagged_leaf_hash_and_tagged_leaf_hashes_agree_with_the_reference(
        tag in any::<u8>(),
        leaves in list_of(leaf_bytes(), 0, 40),
    ) {
        let many = tagged_hashes(tag, &leaves);
        prop_assert_eq!(many.len(), leaves.len());
        for (leaf, h) in leaves.iter().zip(&many) {
            prop_assert_eq!(*h, ref_tagged_leaf(tag, leaf));
            prop_assert_eq!(*h, merkle::tagged_leaf_hash(&RustCrypto, tag, leaf));
        }
    }

    /// The tag changes the hash (RECORD_FORMAT: the tag binds a leaf to its section): the same
    /// bytes under two tags give two hashes, and a tagged hash is never the untagged hash. The
    /// pair (tag, bytes) is recoverable from the preimage, so two pairs give the same hash only
    /// when they are the same pair.
    #[test]
    fn the_tag_changes_the_hash(
        t1 in any::<u8>(),
        t2 in any::<u8>(),
        a in leaf_bytes(),
        b in leaf_bytes(),
    ) {
        let h1 = merkle::tagged_leaf_hash(&RustCrypto, t1, &a);
        let h2 = merkle::tagged_leaf_hash(&RustCrypto, t2, &b);
        prop_assert_eq!(h1 == h2, t1 == t2 && a == b);
        prop_assert_ne!(h1, merkle::leaf_hash(&RustCrypto, &a));
    }

    /// The same leaves under two tags give two roots (the whole section moves): a tree is not
    /// the tree of the same leaves under another tag.
    #[test]
    fn the_same_leaves_under_another_tag_give_another_root(
        t1 in any::<u8>(),
        delta in 1u8..=255,
        leaves in list_of(leaf_bytes(), 1, 40),
    ) {
        prop_assert_ne!(tree_root(t1, &leaves), tree_root(t1 ^ delta, &leaves));
    }
}

// ---------------------------------------------------------------------------------------------
// 5. The leaves of a record: canonical JSON, section tags, order.
// ---------------------------------------------------------------------------------------------

/// A character from a small pool that stresses the string rules of RECORD_FORMAT "Canonical
/// JSON": lowercase letters, the quote and the backslash, the slash, controls with and without a
/// short escape, DEL, characters outside ASCII, the line separators, and, for the UTF-16 key
/// order, characters above U+FFFF next to characters in U+E000 to U+FFFF.
fn text_char() -> BoxedStrategy<char> {
    prop_oneof![
        6 => prop::char::range('a', 'z'),
        2 => prop::sample::select(vec![
            '"', '\\', '/', ' ', '\u{0}', '\u{8}', '\t', '\n', '\u{c}', '\r', '\u{1f}', '\u{7f}',
            '\u{e9}', '\u{20ac}', '\u{2028}', '\u{e000}', '\u{fb33}', '\u{ffff}', '\u{10000}',
            '\u{1f600}', '\u{10ffff}',
        ]),
    ]
    .boxed()
}

fn text() -> BoxedStrategy<String> {
    vec(text_char(), 0..6)
        .prop_map(|cs| cs.into_iter().collect())
        .boxed()
}

/// An object key: any short text, or, one time in three, one or two characters from a pool
/// where the order of UTF-16 code units differs from the order of code points (U+E000 and
/// U+FFFF sort after the surrogates that spell U+10000 and above), so keys of one object often
/// differ exactly there.
fn key() -> BoxedStrategy<String> {
    prop_oneof![
        2 => vec(text_char(), 0..4).prop_map(|cs| cs.into_iter().collect::<String>()),
        1 => vec(
            prop::sample::select(vec!['a', '\u{e000}', '\u{ffff}', '\u{10000}', '\u{1f600}', '\u{10ffff}']),
            1..=2,
        )
        .prop_map(|cs| cs.into_iter().collect::<String>()),
    ]
    .boxed()
}

/// A JSON value of the record's subset (no floats; integers within +-(2^53 - 1), extremes
/// included), up to three levels deep.
fn json_value() -> BoxedStrategy<Value> {
    let scalar = prop_oneof![
        2 => Just(Value::Null),
        2 => any::<bool>().prop_map(Value::Bool),
        3 => prop_oneof![
            (-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).prop_map(Value::Int),
            (-20i64..20).prop_map(Value::Int),
            Just(Value::Int(MAX_SAFE_INTEGER)),
            Just(Value::Int(-MAX_SAFE_INTEGER)),
        ],
        4 => text().prop_map(Value::Str),
    ];
    scalar
        .prop_recursive(3, 20, 4, |inner| {
            prop_oneof![
                vec(inner.clone(), 0..4).prop_map(Value::Array),
                btree_map(key(), inner, 0..4).prop_map(Value::Object),
            ]
        })
        .boxed()
}

fn object() -> BoxedStrategy<Value> {
    btree_map(key(), json_value(), 0..5)
        .prop_map(Value::Object)
        .boxed()
}

/// An object with one fixed member (`id`, `topic` and `multi_id`, or `seq`) and some others, or
/// any value at all: `seal::leaves` reads such members only to name a leaf, and takes any value
/// as a leaf.
fn element(fixed: BoxedStrategy<Vec<(&'static str, Value)>>) -> BoxedStrategy<Value> {
    prop_oneof![
        4 => (fixed, btree_map(key(), json_value(), 0..3)).prop_map(|(fixed, mut m)| {
            for (k, v) in fixed {
                m.insert(k.to_string(), v);
            }
            Value::Object(m)
        }),
        1 => json_value(),
    ]
    .boxed()
}

/// A record object with the thirteen fields of `RECORD_FIELDS`, 0 to 10 results, 0 to 6 sealed
/// topics and 0 to 40 events.
fn record() -> BoxedStrategy<BTreeMap<String, Value>> {
    let result = element(
        prop::sample::select(vec!["R1", "R2", "R10", "X1"])
            .prop_map(|id| vec![("id", Value::str(id))])
            .boxed(),
    );
    let topic = element(
        (text(), 0i64..3)
            .prop_map(|(t, i)| vec![("topic", Value::Str(t)), ("multi_id", Value::Int(i))])
            .boxed(),
    );
    let event = element(Just(Vec::new()).boxed());
    (
        (
            prop_oneof![Just(4i64), Just(5i64)],
            object(),
            object(),
            object(),
        ),
        (object(), object(), object()),
        (vec(result, 0..=10), vec(topic, 0..=6), vec(event, 0..=40)),
        (text(), object(), object()),
    )
        .prop_map(
            |(
                (schema, tool_member, seal_member, log_member),
                (config_member, baseline_member, rules_member),
                (results, sealed_topics, events),
                (status, merkle_member, signature_member),
            )| {
                let mut m = BTreeMap::new();
                m.insert("schema_version".to_string(), Value::Int(schema));
                m.insert("tool".to_string(), tool_member);
                m.insert("seal".to_string(), seal_member);
                m.insert("log".to_string(), log_member);
                m.insert("config".to_string(), config_member);
                m.insert("baseline".to_string(), baseline_member);
                m.insert("rules".to_string(), rules_member);
                m.insert("results".to_string(), Value::Array(results));
                m.insert("sealed_topics".to_string(), Value::Array(sealed_topics));
                m.insert("events".to_string(), Value::Array(events));
                m.insert("status".to_string(), Value::Str(status));
                m.insert("merkle".to_string(), merkle_member);
                m.insert("signature".to_string(), signature_member);
                m
            },
        )
        .boxed()
}

/// RECORD_FORMAT "Strings": `"` and `\` as `\"` and `\\`; U+0008, U+0009, U+000A, U+000C and
/// U+000D as `\b`, `\t`, `\n`, `\f`, `\r`; every other code point below U+0020 as `\u` and four
/// lowercase hex digits; everything else as itself.
fn ref_string(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if u32::from(c) < 0x20 => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// RECORD_FORMAT "Canonical JSON": no whitespace, integers in decimal, object members sorted by
/// key comparing the keys as sequences of UTF-16 code units.
fn ref_canonical(v: &Value) -> String {
    match v {
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Int(n) => n.to_string(),
        Value::Str(s) => ref_string(s),
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(ref_canonical).collect();
            format!("[{}]", parts.join(","))
        }
        Value::Object(map) => {
            let mut members: Vec<(&String, &Value)> = map.iter().collect();
            members.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));
            let parts: Vec<String> = members
                .iter()
                .map(|(k, v)| format!("{}:{}", ref_string(k), ref_canonical(v)))
                .collect();
            format!("{{{}}}", parts.join(","))
        }
    }
}

fn array_of<'a>(rec: &'a BTreeMap<String, Value>, field: &str) -> &'a [Value] {
    match &rec[field] {
        Value::Array(items) => items,
        other => panic!("{field} is not an array: {other:?}"),
    }
}

/// RECORD_FORMAT "Merkle leaves": the seal context `{"schema_version": ..., "seal": ...,
/// "tool": ...}`, then `log`, `config`, `baseline`, `rules`, each element of `results`, of
/// `sealed_topics` and of `events`; the tag bytes are 0x01 to 0x08 in that order. Returns each
/// leaf's tag and canonical bytes.
fn ref_leaves(rec: &BTreeMap<String, Value>) -> Vec<(u8, Vec<u8>)> {
    let context = format!(
        "{{\"schema_version\":{},\"seal\":{},\"tool\":{}}}",
        ref_canonical(&rec["schema_version"]),
        ref_canonical(&rec["seal"]),
        ref_canonical(&rec["tool"]),
    );
    let mut out = vec![(0x01, context.into_bytes())];
    for (tag, field) in [
        (0x02, "log"),
        (0x03, "config"),
        (0x04, "baseline"),
        (0x05, "rules"),
    ] {
        out.push((tag, ref_canonical(&rec[field]).into_bytes()));
    }
    for (tag, field) in [(0x06, "results"), (0x07, "sealed_topics"), (0x08, "events")] {
        for element in array_of(rec, field) {
            out.push((tag, ref_canonical(element).into_bytes()));
        }
    }
    out
}

/// The reference root of a record and its per-section leaf counts.
fn ref_record_root(rec: &BTreeMap<String, Value>) -> (Option<Hash>, [u64; 8]) {
    let leaves = ref_leaves(rec);
    let mut counts = [0u64; 8];
    for (tag, _) in &leaves {
        counts[usize::from(*tag) - 1] += 1;
    }
    let hashes: Vec<Hash> = leaves.iter().map(|(t, b)| ref_tagged_leaf(*t, b)).collect();
    (ref_root(&hashes), counts)
}

/// The Merkle root and leaf counts the way `verify` gets them (`standalone` in verify.rs,
/// "Leaves straight from the canonical bytes"): from the byte ranges of the members of the
/// canonical file, with the seal context spliced together from the three member ranges.
fn root_from_file_bytes(bytes: &[u8]) -> Result<(Hash, [u64; 8]), String> {
    let spans = scan_canonical(bytes).map_err(|e| e.to_string())?;
    let find = |k: &str| {
        spans
            .iter()
            .find(|m| m.key == k)
            .ok_or_else(|| format!("no member {k}"))
    };
    let slice = |k: &str| -> Result<&[u8], String> { Ok(&bytes[find(k)?.value.clone()]) };
    let mut context = b"{\"schema_version\":".to_vec();
    context.extend_from_slice(slice("schema_version")?);
    context.extend_from_slice(b",\"seal\":");
    context.extend_from_slice(slice("seal")?);
    context.extend_from_slice(b",\"tool\":");
    context.extend_from_slice(slice("tool")?);
    context.push(b'}');
    let single =
        |section: Section, leaf: &[u8]| merkle::tagged_leaf_hash(&RustCrypto, section.tag(), leaf);
    let mut hashes = vec![
        single(Section::SealContext, &context),
        single(Section::Log, slice("log")?),
        single(Section::Config, slice("config")?),
        single(Section::Baseline, slice("baseline")?),
        single(Section::Rules, slice("rules")?),
    ];
    let mut counts = [1, 1, 1, 1, 1, 0, 0, 0];
    for (slot, (field, section)) in [
        ("results", Section::Result),
        ("sealed_topics", Section::SealedTopic),
        ("events", Section::Event),
    ]
    .into_iter()
    .enumerate()
    {
        let member = find(field)?;
        counts[5 + slot] = member.elements.len() as u64;
        hashes.extend(merkle::tagged_leaf_hashes(
            &RustCrypto,
            section.tag(),
            member.elements.iter().map(|e| &bytes[e.clone()]),
        ));
    }
    let root = merkle::root(&RustCrypto, &hashes).ok_or("no leaves")?;
    Ok((root, counts))
}

/// A small deterministic generator (xorshift64*) for the order and the spelling of a text.
struct Shuffler(u64);

impl Shuffler {
    fn new(seed: u64) -> Shuffler {
        Shuffler(seed | 1)
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// A number in `0..n`, for `n` above zero.
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            let j = self.below(i + 1);
            items.swap(i, j);
        }
    }
}

fn write_space(out: &mut String, s: &mut Shuffler) {
    out.push_str(["", "", " ", "\n", "\t", " \r\n "][s.below(6)]);
}

/// `\u` and four hex digits (upper or lower case) per UTF-16 code unit of `c`.
fn unicode_escape(c: char, s: &mut Shuffler) -> String {
    let upper = s.below(2) == 0;
    let mut units = [0u16; 2];
    c.encode_utf16(&mut units)
        .iter()
        .map(|u| {
            if upper {
                format!("\\u{u:04X}")
            } else {
                format!("\\u{u:04x}")
            }
        })
        .collect()
}

/// A JSON string for `text` in a spelling that is valid but not canonical: random escapes for
/// ordinary characters, `\/`, long escapes for controls that have a short one, upper case hex.
fn write_loose_string(out: &mut String, text: &str, s: &mut Shuffler) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '/' if s.below(2) == 0 => out.push_str("\\/"),
            c if u32::from(c) < 0x20 => {
                let short = match c {
                    '\u{8}' => Some('b'),
                    '\t' => Some('t'),
                    '\n' => Some('n'),
                    '\u{c}' => Some('f'),
                    '\r' => Some('r'),
                    _ => None,
                };
                match short {
                    Some(letter) if s.below(2) == 0 => {
                        out.push('\\');
                        out.push(letter);
                    }
                    _ => out.push_str(&unicode_escape(c, s)),
                }
            }
            c if s.below(4) == 0 => out.push_str(&unicode_escape(c, s)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// JSON text of `v` with the members of every object in a random order, random whitespace
/// between tokens and loose string spellings: the same logical value, as many different texts.
fn write_loose(out: &mut String, v: &Value, s: &mut Shuffler) {
    match v {
        Value::Str(text) => write_loose_string(out, text, s),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    write_space(out, s);
                    out.push(',');
                }
                write_space(out, s);
                write_loose(out, item, s);
            }
            write_space(out, s);
            out.push(']');
        }
        Value::Object(map) => {
            let mut members: Vec<(&String, &Value)> = map.iter().collect();
            s.shuffle(&mut members);
            out.push('{');
            for (i, (k, item)) in members.into_iter().enumerate() {
                if i > 0 {
                    write_space(out, s);
                    out.push(',');
                }
                write_space(out, s);
                write_loose_string(out, k, s);
                write_space(out, s);
                out.push(':');
                write_space(out, s);
                write_loose(out, item, s);
            }
            write_space(out, s);
            out.push('}');
        }
        other => out.push_str(&ref_canonical(other)),
    }
}

/// `v` rebuilt with `Obj::field` calls in a random insertion order at every level.
fn rebuilt(v: &Value, s: &mut Shuffler) -> Value {
    match v {
        Value::Array(items) => Value::Array(items.iter().map(|i| rebuilt(i, s)).collect()),
        Value::Object(map) => {
            let mut members: Vec<(&String, &Value)> = map.iter().collect();
            s.shuffle(&mut members);
            let mut o = Obj::new();
            for (k, item) in members {
                o = o.field(k, rebuilt(item, s));
            }
            o.build()
        }
        other => other.clone(),
    }
}

fn record_root(rec: &BTreeMap<String, Value>) -> Result<(Hash, TreeShape), TestCaseError> {
    seal::merkle_root(&RustCrypto, rec).map_err(TestCaseError::fail)
}

fn flat_leaves(rec: &BTreeMap<String, Value>) -> Vec<String> {
    seal::leaves(rec)
        .unwrap()
        .iter()
        .map(|(_, v)| canonical(v))
        .collect()
}

/// The record with its three variable sections replaced.
fn with_sections(
    rec: &BTreeMap<String, Value>,
    results: &[Value],
    sealed: &[Value],
    events: &[Value],
) -> BTreeMap<String, Value> {
    let mut m = rec.clone();
    m.insert("results".to_string(), Value::Array(results.to_vec()));
    m.insert("sealed_topics".to_string(), Value::Array(sealed.to_vec()));
    m.insert("events".to_string(), Value::Array(events.to_vec()));
    m
}

/// Two records whose leaves have the same bytes in the same order, but with one leaf in
/// another section: the root, the shape and the signed payload must all differ, and without the
/// tag the roots would be equal (so the tag alone tells them apart).
fn check_a_moved_leaf(
    a: &BTreeMap<String, Value>,
    b: &BTreeMap<String, Value>,
) -> Result<(), TestCaseError> {
    prop_assert_eq!(flat_leaves(a), flat_leaves(b));
    let (root_a, shape_a) = record_root(a)?;
    let (root_b, shape_b) = record_root(b)?;
    prop_assert_eq!(shape_a.leaf_count(), shape_b.leaf_count());
    prop_assert_ne!(shape_a, shape_b);
    prop_assert_ne!(root_a, root_b);
    prop_assert_ne!(
        signed_payload(4, &shape_a, &root_a),
        signed_payload(4, &shape_b, &root_b)
    );
    let untagged = |rec: &BTreeMap<String, Value>| {
        let hashes: Vec<Hash> = flat_leaves(rec)
            .iter()
            .map(|l| merkle::leaf_hash(&RustCrypto, l.as_bytes()))
            .collect();
        merkle::root(&RustCrypto, &hashes)
    };
    prop_assert_eq!(untagged(a), untagged(b));
    Ok(())
}

proptest! {
    #![proptest_config(config())]

    /// RECORD_FORMAT "Merkle leaves": the leaves of a record are the seal context, `log`,
    /// `config`, `baseline`, `rules`, then each result, sealed topic digest and event, each
    /// hashed as SHA-256(0x00 || tag || JCS(leaf)) with the tags 0x01 to 0x08, and the root is
    /// the reference tree over them. `seal::merkle_root` (leaf values, canonical bytes, tagged
    /// hashes, tree) equals the reference computed from the document with this file's own
    /// canonical writer, and its shape is the per-section count of leaves.
    #[test]
    fn the_root_of_a_record_equals_the_reference_computed_from_the_document(rec in record()) {
        let (root, shape) = record_root(&rec)?;
        let (expected_root, expected_counts) = ref_record_root(&rec);
        prop_assert_eq!(Some(root), expected_root);
        prop_assert_eq!(shape, TreeShape::new(expected_counts));
        // The leaf bytes themselves are the document's canonical bytes.
        let leaves: Vec<String> = flat_leaves(&rec);
        let expected: Vec<String> = ref_leaves(&rec)
            .into_iter()
            .map(|(_, b)| String::from_utf8(b).unwrap())
            .collect();
        prop_assert_eq!(leaves, expected);
    }

    /// RECORD_FORMAT: "`merkle.leaf_count` is five plus the lengths of the three arrays", and
    /// `merkle.sections` gives the number of leaves in each section, the first five always 1.
    /// The leaves come in the fixed order, so event `i` is the leaf `LeafKind::Event(i)`.
    #[test]
    fn the_shape_of_a_record_is_five_plus_the_lengths_of_the_three_arrays(rec in record()) {
        let (results, sealed, events) = (
            array_of(&rec, "results").len(),
            array_of(&rec, "sealed_topics").len(),
            array_of(&rec, "events").len(),
        );
        let (_, shape) = record_root(&rec)?;
        prop_assert_eq!(shape, TreeShape::of_counts(results, sealed, events));
        prop_assert_eq!(shape.leaf_count(), (5 + results + sealed + events) as u64);
        for (section, n) in [
            (Section::SealContext, 1),
            (Section::Log, 1),
            (Section::Config, 1),
            (Section::Baseline, 1),
            (Section::Rules, 1),
            (Section::Result, results as u64),
            (Section::SealedTopic, sealed as u64),
            (Section::Event, events as u64),
        ] {
            prop_assert_eq!(shape.count(section), n);
        }
        let mut expected = Obj::new();
        for (name, n) in [
            ("seal_context", 1),
            ("log", 1),
            ("config", 1),
            ("baseline", 1),
            ("rules", 1),
            ("results", results as u64),
            ("sealed_topics", sealed as u64),
            ("events", events as u64),
        ] {
            expected = expected.field(name, Value::count(n));
        }
        prop_assert_eq!(shape.to_json(), expected.build());
        // The leaves are in the fixed order, one `Section` run after the other.
        let kinds: Vec<Section> = seal::leaves(&rec).unwrap().iter().map(|(k, _)| k.section()).collect();
        let mut order = vec![Section::SealContext, Section::Log, Section::Config, Section::Baseline, Section::Rules];
        order.extend(vec![Section::Result; results]);
        order.extend(vec![Section::SealedTopic; sealed]);
        order.extend(vec![Section::Event; events]);
        prop_assert_eq!(kinds, order);
        let event_kinds: Vec<LeafKind> = seal::leaves(&rec)
            .unwrap()
            .into_iter()
            .map(|(k, _)| k)
            .filter(|k| matches!(k, LeafKind::Event(_)))
            .collect();
        prop_assert_eq!(event_kinds, (0..events as u64).map(LeafKind::Event).collect::<Vec<_>>());
    }

    /// RECORD_FORMAT "Because the file is canonical, each member value's bytes in the file are
    /// that value's canonical form, so a verifier can hash leaves straight from the file or
    /// from a parse." The root and the leaf counts hashed from the byte ranges of the
    /// canonical file (the way `verify` does) equal those of `seal::merkle_root` over the
    /// values (the way `seal` does).
    #[test]
    fn hashing_the_leaves_from_the_file_bytes_gives_the_root_of_the_values(rec in record()) {
        let bytes = canonical(&Value::Object(rec.clone())).into_bytes();
        let (file_root, file_counts) = root_from_file_bytes(&bytes).map_err(TestCaseError::fail)?;
        let (root, shape) = record_root(&rec)?;
        prop_assert_eq!(file_root, root);
        prop_assert_eq!(TreeShape::new(file_counts), shape);
        // And through a parse of those bytes.
        let Value::Object(parsed) = parse(&bytes).map_err(|e| TestCaseError::fail(e.to_string()))? else {
            return Err(TestCaseError::fail("the record did not parse as an object"));
        };
        prop_assert_eq!(&parsed, &rec);
        prop_assert_eq!(record_root(&parsed)?.0, root);
    }

    /// The leaf bytes are canonical JSON, so the same logical members give the same leaves and
    /// the same root in any order: a record built with its members inserted in any order
    /// (`Obj::field`), and a record read from text whose members are in any order, with any
    /// whitespace and any valid spelling of its strings, have the leaves and the root of the
    /// original.
    #[test]
    fn the_order_and_spelling_of_the_members_do_not_change_the_leaves_or_the_root(
        rec in record(),
        seed in any::<u64>(),
    ) {
        let mut shuffler = Shuffler::new(seed);
        let (root, shape) = record_root(&rec)?;

        let Value::Object(rebuilt_rec) = rebuilt(&Value::Object(rec.clone()), &mut shuffler) else {
            return Err(TestCaseError::fail("not an object"));
        };
        prop_assert_eq!(&rebuilt_rec, &rec);
        prop_assert_eq!(flat_leaves(&rebuilt_rec), flat_leaves(&rec));
        prop_assert_eq!(record_root(&rebuilt_rec)?, (root, shape));

        let mut text = String::new();
        write_space(&mut text, &mut shuffler);
        write_loose(&mut text, &Value::Object(rec.clone()), &mut shuffler);
        write_space(&mut text, &mut shuffler);
        let parsed = parse(text.as_bytes()).map_err(|e| TestCaseError::fail(format!("{e}: {text}")))?;
        let Value::Object(parsed) = parsed else {
            return Err(TestCaseError::fail("the text did not parse as an object"));
        };
        prop_assert_eq!(&parsed, &rec);
        prop_assert_eq!(flat_leaves(&parsed), flat_leaves(&rec));
        prop_assert_eq!(record_root(&parsed)?, (root, shape));
    }

    /// RECORD_FORMAT: "`status`, `merkle` and `signature` are not leaves." Replacing any of the
    /// three leaves the leaves, the shape and the root as they were.
    #[test]
    fn status_merkle_and_signature_are_not_leaves(
        rec in record(),
        status in text(),
        merkle_member in json_value(),
        signature_member in json_value(),
    ) {
        let mut other = rec.clone();
        other.insert("status".to_string(), Value::Str(status));
        other.insert("merkle".to_string(), merkle_member);
        other.insert("signature".to_string(), signature_member);
        prop_assert_eq!(flat_leaves(&other), flat_leaves(&rec));
        prop_assert_eq!(record_root(&other)?, record_root(&rec)?);
        let mut without = rec.clone();
        for field in ["status", "merkle", "signature"] {
            without.remove(field);
        }
        prop_assert_eq!(record_root(&without)?, record_root(&rec)?);
    }

    /// Every one of the ten members that make leaves is covered by the root: changing the value
    /// of `schema_version`, `tool`, `seal`, `log`, `config`, `baseline` or `rules`, or adding an
    /// element to, or nesting the first element of, `results`, `sealed_topics` or `events`,
    /// changes the root. (The generator cannot produce the key `Z!`, so adding it is a change.)
    #[test]
    fn every_member_that_makes_a_leaf_is_covered_by_the_root(rec in record()) {
        let (root, _) = record_root(&rec)?;
        let mut changed_records = Vec::new();
        let mut toggled = rec.clone();
        let schema = if rec["schema_version"] == Value::Int(4) { 5 } else { 4 };
        toggled.insert("schema_version".to_string(), Value::Int(schema));
        changed_records.push(("schema_version", toggled));
        for field in ["tool", "seal", "log", "config", "baseline", "rules"] {
            let mut m = rec.clone();
            let Value::Object(inner) = &rec[field] else {
                return Err(TestCaseError::fail("a section is not an object"));
            };
            let mut inner = inner.clone();
            inner.insert("Z!".to_string(), Value::Null);
            m.insert(field.to_string(), Value::Object(inner));
            changed_records.push((field, m));
        }
        for field in ["results", "sealed_topics", "events"] {
            let items = array_of(&rec, field);
            let mut appended = items.to_vec();
            appended.push(Value::Null);
            let mut m = rec.clone();
            m.insert(field.to_string(), Value::Array(appended));
            changed_records.push((field, m));
            if let Some(first) = items.first() {
                let mut nested = items.to_vec();
                nested[0] = Value::Array(vec![first.clone()]);
                let mut m = rec.clone();
                m.insert(field.to_string(), Value::Array(nested));
                changed_records.push((field, m));
            }
        }
        for (field, changed) in changed_records {
            let (changed_root, _) = record_root(&changed)?;
            prop_assert_ne!(changed_root, root, "changing {} left the root", field);
        }
    }

    /// RECORD_FORMAT: a leaf's tag binds it to its section ("a result moved into
    /// `sealed_topics`, or an event into `results`, hashes differently and changes the root").
    /// An element placed as the last of one array or as the first of the next array keeps the
    /// order and the bytes of all leaves, and changes the shape, the root and the signed
    /// payload; so does moving it across an empty `sealed_topics`. Without the tag the two
    /// records would have one root, which `check_a_moved_leaf` also shows.
    #[test]
    fn a_leaf_moved_to_the_next_section_changes_the_root_and_the_shape(
        rec in record(),
        x in json_value(),
    ) {
        let results = array_of(&rec, "results").to_vec();
        let sealed = array_of(&rec, "sealed_topics").to_vec();
        let events = array_of(&rec, "events").to_vec();
        let with = |mut list: Vec<Value>, front: bool, x: &Value| {
            if front { list.insert(0, x.clone()) } else { list.push(x.clone()) }
            list
        };
        // results | sealed_topics
        check_a_moved_leaf(
            &with_sections(&rec, &with(results.clone(), false, &x), &sealed, &events),
            &with_sections(&rec, &results, &with(sealed.clone(), true, &x), &events),
        )?;
        // sealed_topics | events
        check_a_moved_leaf(
            &with_sections(&rec, &results, &with(sealed.clone(), false, &x), &events),
            &with_sections(&rec, &results, &sealed, &with(events.clone(), true, &x)),
        )?;
        // results | (empty sealed_topics) | events
        check_a_moved_leaf(
            &with_sections(&rec, &with(results.clone(), false, &x), &[], &events),
            &with_sections(&rec, &results, &[], &with(events.clone(), true, &x)),
        )?;
    }

    /// RECORD_FORMAT "Signed payload": the shape is signed with the root. Given only the
    /// canonical bytes of the leaves in order and the per-section counts of the shape, the root
    /// is determined (each leaf takes the tag of the section its position falls in), and it is
    /// the root of the record. The counts add up to the number of leaves.
    #[test]
    fn the_shape_and_the_leaf_bytes_determine_the_root(rec in record()) {
        let (root, shape) = record_root(&rec)?;
        let flat = flat_leaves(&rec);
        prop_assert_eq!(shape.leaf_count(), flat.len() as u64);
        let mut hashes = Vec::new();
        let mut start = 0usize;
        for section in Section::ALL {
            let n = usize::try_from(shape.count(section)).unwrap();
            let range = &flat[start..start + n];
            hashes.extend(merkle::tagged_leaf_hashes(
                &RustCrypto,
                section.tag(),
                range.iter().map(|l| l.as_bytes()),
            ));
            start += n;
        }
        prop_assert_eq!(start, flat.len());
        prop_assert_eq!(merkle::root(&RustCrypto, &hashes), Some(root));
    }

    /// RECORD_FORMAT "Signed payload", byte for byte: ASCII `SFR-RECORD-V1`, 0x00, the schema
    /// version as 4 bytes, the tree size as 8 bytes, the eight section counts as 8 bytes each
    /// (big-endian), then the root's raw bytes: 122 bytes.
    #[test]
    fn the_signed_payload_has_the_documented_layout(
        schema in any::<u32>(),
        counts in prop::array::uniform8(0u64..(1 << 50)),
        root in hash(),
    ) {
        let shape = TreeShape::new(counts);
        prop_assert_eq!(shape.leaf_count(), counts.iter().sum::<u64>());
        let mut expected = b"SFR-RECORD-V1".to_vec();
        expected.push(0x00);
        expected.extend_from_slice(&schema.to_be_bytes());
        expected.extend_from_slice(&counts.iter().sum::<u64>().to_be_bytes());
        for c in counts {
            expected.extend_from_slice(&c.to_be_bytes());
        }
        expected.extend_from_slice(&root);
        let payload = signed_payload(schema, &shape, &root);
        prop_assert_eq!(payload.len(), 122);
        prop_assert_eq!(payload, expected);
    }

    /// The shape is signed as well as the root: two shapes with the same total (a leaf moved
    /// from one section to another) give two payloads for one root and one schema version.
    #[test]
    fn two_shapes_with_the_same_total_sign_differently(
        counts in prop::array::uniform8(1u64..1000),
        from in 0usize..8,
        step in 1usize..8,
        root in hash(),
    ) {
        let to = (from + step) % 8;
        let mut moved = counts;
        moved[from] -= 1;
        moved[to] += 1;
        let (a, b) = (TreeShape::new(counts), TreeShape::new(moved));
        prop_assert_eq!(a.leaf_count(), b.leaf_count());
        prop_assert_ne!(signed_payload(4, &a, &root), signed_payload(4, &b, &root));
    }
}

#[test]
fn sections_have_the_documented_tags_names_and_order() {
    // RECORD_FORMAT: 0x01 seal context, 0x02 `log`, 0x03 `config`, 0x04 `baseline`, 0x05
    // `rules`, 0x06 each result, 0x07 each sealed topic digest, 0x08 each event; the names of
    // `merkle.sections` in the order of the signed payload.
    let documented = [
        ("seal_context", 0x01),
        ("log", 0x02),
        ("config", 0x03),
        ("baseline", 0x04),
        ("rules", 0x05),
        ("results", 0x06),
        ("sealed_topics", 0x07),
        ("events", 0x08),
    ];
    let actual: Vec<(&str, u8)> = Section::ALL.iter().map(|s| (s.name(), s.tag())).collect();
    assert_eq!(actual, documented);
    // Three different counts show each count in its own slot of the shape.
    let shape = TreeShape::of_counts(3, 5, 7);
    assert_eq!(shape, TreeShape::new([1, 1, 1, 1, 1, 3, 5, 7]));
    assert_eq!(shape.leaf_count(), 5 + 3 + 5 + 7);
    assert_eq!(shape.count(Section::Result), 3);
    assert_eq!(shape.count(Section::SealedTopic), 5);
    assert_eq!(shape.count(Section::Event), 7);
}

#[test]
fn a_record_without_its_leaf_members_has_no_root_and_never_panics() {
    // A record needs the ten members that make leaves; without one, or with a variable section
    // that is not an array, `seal::merkle_root` returns an error (SPEC B1.10: no panics on any
    // input). Without `status`, `merkle` and `signature` it still has its root.
    let leaf_members = [
        "schema_version",
        "tool",
        "seal",
        "log",
        "config",
        "baseline",
        "rules",
        "results",
        "sealed_topics",
        "events",
    ];
    let mut rec = BTreeMap::new();
    for field in leaf_members {
        let value = match field {
            "results" | "sealed_topics" | "events" => Value::Array(Vec::new()),
            "schema_version" => Value::Int(4),
            _ => Value::Object(BTreeMap::new()),
        };
        rec.insert(field.to_string(), value);
    }
    let (root, shape) = seal::merkle_root(&RustCrypto, &rec).unwrap();
    assert_eq!(shape, TreeShape::of_counts(0, 0, 0));
    assert_eq!(shape.leaf_count(), 5);
    assert_eq!(Some(root), ref_record_root(&rec).0);
    for field in leaf_members {
        let mut missing = rec.clone();
        missing.remove(field);
        assert!(seal::merkle_root(&RustCrypto, &missing).is_err(), "{field}");
        assert!(seal::leaves(&missing).is_err(), "{field}");
    }
    for field in ["results", "sealed_topics", "events"] {
        for not_an_array in [
            Value::Null,
            Value::Object(BTreeMap::new()),
            Value::str("[]"),
        ] {
            let mut bad = rec.clone();
            bad.insert(field.to_string(), not_an_array);
            assert!(seal::merkle_root(&RustCrypto, &bad).is_err(), "{field}");
        }
    }
    assert_eq!(RECORD_FIELDS.len(), 13);
    for field in RECORD_FIELDS {
        assert!(
            leaf_members.contains(&field) || ["status", "merkle", "signature"].contains(&field),
            "{field}"
        );
    }
}
