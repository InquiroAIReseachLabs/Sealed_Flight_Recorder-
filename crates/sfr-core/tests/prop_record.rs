//! Property tests of the standalone record verifier (`sfr_core::verify::verify`, the checks of
//! docs/RECORD_FORMAT.md "What a verifier checks"). The inputs are the real signed records of
//! `fuzz/seeds/sfr_verify/` and their public key, damaged in random ways; the one oracle is that
//! a byte string verifies only if it is byte for byte one of the seeds.
// A panicking test is a failing test, so tests may use expect, unwrap and panic.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use proptest::prelude::*;
use proptest::test_runner::{Config as ProptestConfig, RngSeed};
use sfr_core::crypto::rustcrypto::{FileKey, RustCrypto};
use sfr_core::crypto::{CryptoBackend, Custody, Signer};
use sfr_core::json::{Value, canonical, parse, scan_canonical};
use sfr_core::keys::{fingerprint, hex_decode};
use sfr_core::merkle;
use sfr_core::seal::{Section, TreeShape, merkle_root, signed_payload};
use sfr_core::verify::{OVERALL_STATUSES, Verified, VerifyError, verify};
use std::sync::LazyLock;

/// The signed seed records of the fuzz target `sfr_verify`.
static SEEDS: [&[u8]; 5] = [
    include_bytes!("../../../fuzz/seeds/sfr_verify/pyulog_sample_first_65516.sfr"),
    include_bytes!("../../../fuzz/seeds/sfr_verify/sitl_v1.17.0_failsafe_gps_loss_shrunk.sfr"),
    include_bytes!("../../../fuzz/seeds/sfr_verify/sitl_v1.17.0_vtol_transition_abort_shrunk.sfr"),
    include_bytes!("../../../fuzz/seeds/sfr_verify/sitl_v1.17.0_gz_x500_vision_hover_shrunk.sfr"),
    include_bytes!("../../../fuzz/seeds/sfr_verify/synthetic_custom_detection.sfr"),
];

/// The raw key inside the seed key file.
static KEY: LazyLock<[u8; 32]> = LazyLock::new(|| {
    sfr_core::keys::parse_public_key_pem(include_str!("../../../fuzz/seeds/sfr_verify_key.pub"))
        .expect("the seed public key parses")
});

/// A fixed seed, so the default run is deterministic.
const FIXED_SEED: u64 = 0x5f12_a7c3_9e41_0b6d;

/// The default is 64 cases and a fixed seed; PROPTEST_CASES and PROPTEST_RNG_SEED override them.
fn config() -> ProptestConfig {
    let mut c = ProptestConfig::default();
    if std::env::var_os("PROPTEST_RNG_SEED").is_none() {
        c.rng_seed = RngSeed::Fixed(FIXED_SEED);
    }
    if std::env::var_os("PROPTEST_CASES").is_none() {
        c.cases = 64;
    }
    c
}

fn run(bytes: &[u8], key: &[u8; 32]) -> Result<Verified, VerifyError> {
    verify(bytes, None, &RustCrypto, key)
}

/// Asserts the oracle: `bytes` verifies under the seed key only when it is a seed.
fn assert_only_seeds_verify(bytes: &[u8], what: &str) {
    if run(bytes, &KEY).is_ok() {
        assert!(
            SEEDS.contains(&bytes),
            "a record that is not a seed verified ({what}); bytes as hex: {}",
            hex(bytes)
        );
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// An index into a seed and a position fraction, kept 32-bit safe by using u32 and reducing.
fn at(n: usize, r: u32) -> usize {
    (r as usize) % n.max(1)
}

/// Control property: RECORD_FORMAT "What a verifier checks" accepts a genuine record.
#[test]
fn every_seed_record_verifies_against_the_seed_key() {
    for (i, s) in SEEDS.iter().enumerate() {
        let v = run(s, &KEY);
        assert!(v.is_ok(), "seed {i} does not verify: {v:?}");
    }
}

proptest! {
    #![proptest_config(config())]

    // Property: flipping any bits of any one byte of a signed record (the signature covers the
    // Merkle root over the content, check 5 and 9) never verifies and never panics.
    #[test]
    fn a_byte_xor_never_verifies(s in 0..SEEDS.len(), p in any::<u32>(), m in 1u8..=255) {
        let mut b = SEEDS[s].to_vec();
        let i = at(b.len(), p);
        b[i] ^= m;
        prop_assert!(run(&b, &KEY).is_err(), "xor {m:#x} at {i} of seed {s} verified");
    }

    // Property: deleting one byte never verifies (the record is canonical and signed).
    #[test]
    fn deleting_a_byte_never_verifies(s in 0..SEEDS.len(), p in any::<u32>()) {
        let mut b = SEEDS[s].to_vec();
        b.remove(at(b.len(), p));
        prop_assert!(run(&b, &KEY).is_err());
    }

    // Property: inserting one byte anywhere (including the end) never verifies.
    #[test]
    fn inserting_a_byte_never_verifies(s in 0..SEEDS.len(), p in any::<u32>(), v in any::<u8>()) {
        let mut b = SEEDS[s].to_vec();
        let i = at(b.len() + 1, p);
        b.insert(i, v);
        prop_assert!(run(&b, &KEY).is_err(), "insert {v:#x} at {i} of seed {s} verified");
    }

    // Property: a proper prefix of a record (truncation at a random length) never verifies.
    #[test]
    fn truncation_never_verifies(s in 0..SEEDS.len(), p in any::<u32>()) {
        let n = at(SEEDS[s].len(), p);
        prop_assert!(run(&SEEDS[s][..n], &KEY).is_err(), "prefix {n} of seed {s} verified");
    }

    // Property: duplicating a non-empty range in place never verifies.
    #[test]
    fn duplicating_a_range_never_verifies(
        s in 0..SEEDS.len(), p in any::<u32>(), l in 1usize..512,
    ) {
        let src = SEEDS[s];
        let a = at(src.len(), p);
        let z = (a + l).min(src.len());
        let mut b = src[..z].to_vec();
        b.extend_from_slice(&src[a..]);
        prop_assert!(run(&b, &KEY).is_err(), "duplicate {a}..{z} of seed {s} verified");
    }

    // Property: swapping two non-overlapping ranges with different content never verifies.
    #[test]
    fn swapping_two_ranges_never_verifies(
        s in 0..SEEDS.len(), p in any::<u32>(), q in any::<u32>(), l in 1usize..256,
    ) {
        let src = SEEDS[s];
        let mut a = at(src.len(), p);
        let mut c = at(src.len(), q);
        if a > c { std::mem::swap(&mut a, &mut c); }
        let l = l.min(c - a).min(src.len() - c);
        prop_assume!(l > 0 && src[a..a + l] != src[c..c + l]);
        let mut b = src.to_vec();
        b[a..a + l].copy_from_slice(&src[c..c + l]);
        b[c..c + l].copy_from_slice(&src[a..a + l]);
        prop_assert!(run(&b, &KEY).is_err(), "swap {a} and {c}, length {l}, of seed {s} verified");
    }

    // Property: replacing a range of one record by the range at the same place in another seed
    // (or one of any length from another seed) gives a record that verifies only if unchanged.
    #[test]
    fn splicing_in_another_records_range_never_verifies(
        s in 0..SEEDS.len(), t in 0..SEEDS.len(), p in any::<u32>(), q in any::<u32>(),
        l in 1usize..2048,
    ) {
        let (x, y) = (SEEDS[s], SEEDS[t]);
        let a = at(x.len(), p);
        let c = at(y.len(), q);
        let la = l.min(x.len() - a);
        let lc = l.min(y.len() - c);
        let mut b = x[..a].to_vec();
        b.extend_from_slice(&y[c..c + lc]);
        b.extend_from_slice(&x[a + la..]);
        if b != x {
            prop_assert!(run(&b, &KEY).is_err(), "splice of seed {t} into seed {s} verified");
        }
    }

    // Property: several byte edits at once (flips and deletions) never verify.
    #[test]
    fn several_edits_never_verify(
        s in 0..SEEDS.len(),
        edits in proptest::collection::vec((any::<u32>(), 0u8..3, any::<u8>()), 1..6),
    ) {
        let mut b = SEEDS[s].to_vec();
        for (p, kind, v) in edits {
            let i = at(b.len(), p);
            match kind {
                0 => b[i] = v,
                1 => { b.remove(i); }
                _ => b.insert(i, v),
            }
        }
        assert_only_seeds_verify(&b, "several edits");
    }

    // Property: arbitrary bytes never verify and never panic (the call returns).
    #[test]
    fn arbitrary_bytes_never_verify(b in proptest::collection::vec(any::<u8>(), 0..2048)) {
        prop_assert!(run(&b, &KEY).is_err());
    }

    // Property: well-formed structure with random garbage after a valid record opening, so that
    // the checks after the parser run on damaged content, never verifies.
    #[test]
    fn a_seed_head_with_random_tail_never_verifies(
        s in 0..SEEDS.len(), p in any::<u32>(),
        tail in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        let n = at(SEEDS[s].len(), p);
        let mut b = SEEDS[s][..n].to_vec();
        b.extend_from_slice(&tail);
        assert_only_seeds_verify(&b, "head and random tail");
    }

    // Property: changing member values in place (digits to other digits, hex characters to other
    // hex characters, true and false swapped) keeps the JSON well formed and canonical-looking,
    // so the schema, Merkle and signature checks run; the result never verifies.
    #[test]
    fn changed_member_values_never_verify(
        s in 0..SEEDS.len(),
        picks in proptest::collection::vec((any::<u32>(), 1u8..16, 0u8..3), 1..4),
    ) {
        let src = SEEDS[s];
        let mut b = src.to_vec();
        let mut changed = false;
        for (p, d, kind) in picks {
            let start = at(b.len(), p);
            // The next suitable character at or after the pick, wrapping once.
            let found = (0..b.len()).map(|k| (start + k) % b.len()).find(|&i| match kind {
                0 => b[i].is_ascii_digit(),
                1 => b[i].is_ascii_hexdigit() && !b[i].is_ascii_uppercase(),
                _ => b[i..].starts_with(b"true") || b[i..].starts_with(b"false"),
            });
            let Some(i) = found else { continue };
            match kind {
                0 => b[i] = b'0' + (b[i] - b'0' + d) % 10,
                1 => {
                    let h = b"0123456789abcdef";
                    let cur = h.iter().position(|&c| c == b[i]).unwrap();
                    b[i] = h[(cur + d as usize) % 16];
                }
                _ => {
                    let n = if b[i..].starts_with(b"true") { 4 } else { 5 };
                    let rep: &[u8] = if n == 4 { b"false" } else { b"true" };
                    b.splice(i..i + n, rep.iter().copied());
                }
            }
            changed = true;
        }
        prop_assume!(changed && b != src);
        prop_assert!(run(&b, &KEY).is_err());
    }

    // Property: verification is deterministic: the same bytes and key give the same result,
    // for a seed, a damaged seed and arbitrary bytes.
    #[test]
    fn verification_is_deterministic(
        s in 0..SEEDS.len(), p in any::<u32>(), m in 0u8..=255,
        junk in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let mut damaged = SEEDS[s].to_vec();
        let i = at(damaged.len(), p);
        damaged[i] ^= m;
        for input in [SEEDS[s], &damaged[..], &junk[..]] {
            prop_assert_eq!(run(input, &KEY), run(input, &KEY));
        }
    }

    // Property: a different public key never verifies a seed (check 8: `seal.key_fingerprint`
    // is the fingerprint of the given key, and check 9: the signature verifies under it).
    #[test]
    fn a_different_public_key_never_verifies(
        s in 0..SEEDS.len(), key in proptest::array::uniform32(any::<u8>()),
    ) {
        prop_assume!(key != *KEY);
        prop_assert!(run(SEEDS[s], &key).is_err());
    }

    // Property: one bit of the key flipped never verifies (a key that is near the real one).
    #[test]
    fn a_key_with_one_bit_flipped_never_verifies(
        s in 0..SEEDS.len(), byte in 0usize..32, bit in 0u32..8,
    ) {
        let mut key = *KEY;
        key[byte] ^= 1 << bit;
        prop_assert!(run(SEEDS[s], &key).is_err());
    }
}

/// Property: a successful result states what the document's list establishes, as far as the
/// public `Verified` type shows it: the key fingerprint is the given key's (check 8), the root
/// is 64 lowercase hex digits (check 9), the status is one of the four sealed statuses and agrees
/// with the failed and warned rule lists (check 7, `OVERALL_STATUSES`), the rule id lists are
/// strictly increasing (check 4), and a standalone verify does not claim a deep check.
#[test]
fn a_successful_result_reports_consistent_facts() {
    for (i, s) in SEEDS.iter().enumerate() {
        let v = run(s, &KEY).unwrap();
        assert_eq!(v.merkle_root.len(), 64, "seed {i}");
        assert!(
            v.merkle_root
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
            "seed {i}: root is not lowercase hex"
        );
        assert!(
            OVERALL_STATUSES.contains(&v.status.as_str()),
            "seed {i}: {}",
            v.status
        );
        if v.status == "PASS" || v.status == "NO ARMED FLIGHT" {
            assert!(v.failed_rules.is_empty(), "seed {i}");
        }
        if v.status == "FAIL" {
            assert!(!v.failed_rules.is_empty(), "seed {i}");
        }
        for list in [&v.failed_rules, &v.warned_rules] {
            assert!(
                list.windows(2).all(|w| w[0] < w[1]),
                "seed {i}: rule ids not increasing"
            );
        }
        assert!(v.leaf_count >= 1 || v.events == 0, "seed {i}");
        assert!(!v.deep, "seed {i}: standalone verify claims a deep check");
        assert!(!v.fingerprint.is_empty(), "seed {i}");
    }
}

proptest! {
    #![proptest_config(config())]

    // Property: whenever the result is Ok, the bytes are a seed and the result equals the
    // seed's own result (no mismatch hides behind a success); whenever it is Err, a Mismatch
    // names its first problem (a non-empty text) or the error is an Io error. Checked on
    // damaged seeds so that both outcomes of the match are exercised.
    #[test]
    fn an_error_always_carries_a_reason(s in 0..SEEDS.len(), p in any::<u32>(), m in 0u8..=255) {
        let mut b = SEEDS[s].to_vec();
        let i = at(b.len(), p);
        b[i] ^= m;
        match run(&b, &KEY) {
            Ok(v) => {
                prop_assert!(m == 0, "a damaged record verified");
                prop_assert_eq!(Ok(v), run(SEEDS[s], &KEY));
            }
            Err(VerifyError::Mismatch(mm)) => prop_assert!(!mm.first.is_empty()),
            Err(VerifyError::Io(e)) => prop_assert!(!e.is_empty()),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Targeted tests. A random byte edit nearly always breaks the Merkle root or the signature, so
// it cannot show that each of the other checks of the verifier is made: a verifier that skipped
// the signature, the fingerprint, the status, the sections, the leaf count, the order of the
// results, events and sealed topics, the rules digest or the member types would pass the
// random tests above. The tests below damage exactly one thing at a time. Where the damage
// would otherwise be caught by the root or the signature, the record is signed again with a
// key made here (the signed parts are rebuilt with the public `seal` functions), so that the
// one check under test is the only one that can fire.
// ---------------------------------------------------------------------------------------------

type Map = std::collections::BTreeMap<String, Value>;

fn record_of(bytes: &[u8]) -> Map {
    match parse(bytes).expect("a seed is JSON") {
        Value::Object(m) => m,
        _ => panic!("a seed is an object"),
    }
}

fn obj_mut<'a>(r: &'a mut Map, k: &str) -> &'a mut Map {
    match r.get_mut(k) {
        Some(Value::Object(m)) => m,
        _ => panic!("`{k}` is not an object"),
    }
}

fn arr_mut<'a>(r: &'a mut Map, k: &str) -> &'a mut Vec<Value> {
    match r.get_mut(k) {
        Some(Value::Array(a)) => a,
        _ => panic!("`{k}` is not an array"),
    }
}

fn string_of(r: &Map, section: &str, k: &str) -> String {
    match r.get(section) {
        Some(Value::Object(m)) => match m.get(k) {
            Some(Value::Str(s)) => s.clone(),
            other => panic!("`{section}.{k}` is {other:?}"),
        },
        other => panic!("`{section}` is {other:?}"),
    }
}

fn key_n(n: u8) -> FileKey {
    FileKey::from_seed(&[n; 32], "audit")
}

fn same(s: String) -> String {
    s
}

/// The text with its first character changed to another hex digit.
fn flip_first(s: String) -> String {
    let mut c: Vec<char> = s.chars().collect();
    c[0] = if c[0] == '0' { '1' } else { '0' };
    c.into_iter().collect()
}

/// The text with its last character changed to another hex digit.
fn flip_last(s: String) -> String {
    let mut c: Vec<char> = s.chars().collect();
    let n = c.len() - 1;
    c[n] = if c[n] == '0' { '1' } else { '0' };
    c.into_iter().collect()
}

/// An edit of a decoded record; false when the seed has nothing to apply it to.
type Edit = fn(&mut Map) -> bool;

/// How a record is signed again.
#[derive(Clone, Copy)]
struct Resign {
    /// The key that signs (a seed byte).
    signer: u8,
    /// The key whose fingerprint `seal.key_fingerprint` claims.
    claimed: u8,
    /// Applied to the hex of the true root before it is recorded and signed.
    root: fn(String) -> String,
    /// Applied to the claimed fingerprint before it is recorded.
    fingerprint: fn(String) -> String,
}

const HONEST: Resign = Resign {
    signer: 7,
    claimed: 7,
    root: same,
    fingerprint: same,
};

/// Decodes `seed`, applies `edit`, and signs the result again as `how` says. None when `edit`
/// found nothing to change.
fn resign(seed: &[u8], how: Resign, edit: Edit) -> Option<Vec<u8>> {
    let mut r = record_of(seed);
    if !edit(&mut r) {
        return None;
    }
    let claimed = fingerprint(&RustCrypto, &key_n(how.claimed).public_key());
    obj_mut(&mut r, "seal").insert(
        "key_fingerprint".into(),
        Value::str((how.fingerprint)(claimed)),
    );
    let schema = match r.get("schema_version") {
        Some(Value::Int(v)) => u32::try_from(*v).unwrap_or(u32::MAX),
        _ => 0,
    };
    let (root, shape) = merkle_root(&RustCrypto, &r).expect("the edited record has leaves");
    let root_hex = (how.root)(hex(&root));
    let signed_root = hex_decode::<32>(&root_hex).expect("the recorded root stays hex");
    let sig = key_n(how.signer)
        .sign(&signed_payload(schema, &shape, &signed_root))
        .expect("signing");
    let mut merkle = Map::new();
    merkle.insert("algorithm".into(), Value::str("sha256-rfc6962"));
    merkle.insert("leaf_count".into(), Value::count(shape.leaf_count()));
    merkle.insert("root".into(), Value::str(root_hex));
    merkle.insert("sections".into(), shape.to_json());
    r.insert("merkle".into(), Value::Object(merkle));
    let mut signature = Map::new();
    signature.insert("algorithm".into(), Value::str("ed25519"));
    signature.insert("value".into(), Value::str(hex(&sig)));
    r.insert("signature".into(), Value::Object(signature));
    Some(canonical(&Value::Object(r)).into_bytes())
}

/// Decodes `seed`, applies `edit` and writes it back as it is, with no new signature.
fn edited(seed: &[u8], edit: Edit) -> Option<Vec<u8>> {
    let mut r = record_of(seed);
    edit(&mut r).then(|| canonical(&Value::Object(r)).into_bytes())
}

/// Controls for the helpers: decoding and encoding a seed gives the seed back, and a seed signed
/// again by the helper's key verifies under that key and under no other.
#[test]
fn the_helpers_reproduce_a_verifying_record() {
    let own = key_n(7).public_key();
    for (i, s) in SEEDS.iter().enumerate() {
        assert_eq!(
            edited(s, |_| true).as_deref(),
            Some(*s),
            "seed {i} is canonical"
        );
        let again = resign(s, HONEST, |_| true).unwrap();
        let v = run(&again, &own);
        assert!(v.is_ok(), "seed {i} signed again does not verify: {v:?}");
        assert!(
            run(&again, &KEY).is_err(),
            "seed {i}: the seed key accepted another key's record"
        );
    }
}

fn status_of(r: &Map) -> String {
    match r.get("status") {
        Some(Value::Str(s)) => s.clone(),
        other => panic!("status is {other:?}"),
    }
}

/// Edits of members the signature does not cover, or covers only through the recorded root:
/// each must be refused by the check of that member, and only that one can fire.
#[test]
fn damage_to_unsigned_members_is_refused() {
    let cases: Vec<(&str, Edit)> = vec![
        ("status PASS->other", |r| {
            let s = status_of(r);
            let other = OVERALL_STATUSES.iter().find(|o| **o != s).unwrap();
            r.insert("status".into(), Value::str(*other));
            true
        }),
        ("status not a status", |r| {
            r.insert("status".into(), Value::str("OK"));
            true
        }),
        ("status not a string", |r| {
            r.insert("status".into(), Value::Int(1));
            true
        }),
        ("leaf_count + 1", |r| {
            let m = obj_mut(r, "merkle");
            let Some(Value::Int(n)) = m.get("leaf_count").cloned() else {
                return false;
            };
            m.insert("leaf_count".into(), Value::Int(n + 1));
            true
        }),
        ("leaf_count - 1", |r| {
            let m = obj_mut(r, "merkle");
            let Some(Value::Int(n)) = m.get("leaf_count").cloned() else {
                return false;
            };
            m.insert("leaf_count".into(), Value::Int(n - 1));
            true
        }),
        ("sections one count up", |r| {
            let Some(Value::Object(s)) = obj_mut(r, "merkle").get_mut("sections") else {
                return false;
            };
            let Some(Value::Int(n)) = s.values_mut().last() else {
                return false;
            };
            *n += 1;
            true
        }),
        ("sections first count up", |r| {
            let Some(Value::Object(s)) = obj_mut(r, "merkle").get_mut("sections") else {
                return false;
            };
            let Some(Value::Int(n)) = s.values_mut().next() else {
                return false;
            };
            *n += 1;
            true
        }),
        ("sections removed", |r| {
            obj_mut(r, "merkle").remove("sections").is_some()
        }),
        ("merkle algorithm", |r| {
            obj_mut(r, "merkle").insert("algorithm".into(), Value::str("sha256-rfc6962x"));
            true
        }),
        ("merkle extra member", |r| {
            obj_mut(r, "merkle").insert("zzz".into(), Value::Null);
            true
        }),
        ("merkle root first digit", |r| {
            let m = obj_mut(r, "merkle");
            let Some(Value::Str(s)) = m.get("root").cloned() else {
                return false;
            };
            m.insert("root".into(), Value::str(flip_first(s)));
            true
        }),
        ("merkle root last digit", |r| {
            let m = obj_mut(r, "merkle");
            let Some(Value::Str(s)) = m.get("root").cloned() else {
                return false;
            };
            m.insert("root".into(), Value::str(flip_last(s)));
            true
        }),
        ("signature algorithm", |r| {
            obj_mut(r, "signature").insert("algorithm".into(), Value::str("ed448"));
            true
        }),
        ("signature extra member", |r| {
            obj_mut(r, "signature").insert("zzz".into(), Value::Null);
            true
        }),
        ("signature first digit", |r| {
            let m = obj_mut(r, "signature");
            let Some(Value::Str(s)) = m.get("value").cloned() else {
                return false;
            };
            m.insert("value".into(), Value::str(flip_first(s)));
            true
        }),
        ("signature last digit", |r| {
            let m = obj_mut(r, "signature");
            let Some(Value::Str(s)) = m.get("value").cloned() else {
                return false;
            };
            m.insert("value".into(), Value::str(flip_last(s)));
            true
        }),
        ("signature value upper case", |r| {
            let m = obj_mut(r, "signature");
            let Some(Value::Str(s)) = m.get("value").cloned() else {
                return false;
            };
            m.insert("value".into(), Value::str(s.to_uppercase()));
            true
        }),
        ("signature value one digit short", |r| {
            let m = obj_mut(r, "signature");
            let Some(Value::Str(mut s)) = m.get("value").cloned() else {
                return false;
            };
            s.pop();
            m.insert("value".into(), Value::str(s));
            true
        }),
        ("signature value zeros", |r| {
            obj_mut(r, "signature").insert("value".into(), Value::str("0".repeat(128)));
            true
        }),
    ];
    for (name, edit) in cases {
        let mut applied = 0;
        for (i, s) in SEEDS.iter().enumerate() {
            let Some(b) = edited(s, edit) else { continue };
            applied += 1;
            assert!(run(&b, &KEY).is_err(), "seed {i}: `{name}` verified");
        }
        assert!(applied > 0, "`{name}` applied to no seed");
    }
}

/// Edits that leave a validly signed record (right root, right shape, own key) whose content
/// breaks a rule of the format: the signature cannot be what refuses them.
#[test]
fn signed_records_that_break_a_rule_of_the_format_are_refused() {
    let own = key_n(7).public_key();
    let cases: Vec<(&str, Edit)> = vec![
        ("rules sha256 differs", |r| {
            let m = obj_mut(r, "rules");
            let Some(Value::Str(s)) = m.get("sha256").cloned() else {
                return false;
            };
            m.insert("sha256".into(), Value::str(flip_last(s)));
            true
        }),
        ("rules text is not a rules file", |r| {
            let m = obj_mut(r, "rules");
            let text = "this is not [[ a rules file";
            m.insert("text".into(), Value::str(text));
            m.insert(
                "sha256".into(),
                Value::str(hex(&RustCrypto.sha256(text.as_bytes()))),
            );
            true
        }),
        ("results swapped", |r| {
            let a = arr_mut(r, "results");
            if a.len() < 2 {
                return false;
            }
            a.swap(0, 1);
            true
        }),
        ("results first and last swapped", |r| {
            let a = arr_mut(r, "results");
            if a.len() < 2 {
                return false;
            }
            let n = a.len() - 1;
            a.swap(0, n);
            true
        }),
        ("result id repeated", |r| {
            let a = arr_mut(r, "results");
            if a.len() < 2 {
                return false;
            }
            a[1] = a[0].clone();
            true
        }),
        ("result removed", |r| {
            let a = arr_mut(r, "results");
            if a.is_empty() {
                return false;
            }
            a.remove(0);
            true
        }),
        ("last core result removed", |r| {
            // R7 is the last core rule; X1 to X5 are optional and may be absent.
            let a = arr_mut(r, "results");
            let at = a.iter().position(
                |x| matches!(x, Value::Object(m) if m.get("id") == Some(&Value::str("R7"))),
            );
            at.map(|i| a.remove(i)).is_some()
        }),
        ("result of an unknown rule", |r| {
            let a = arr_mut(r, "results");
            let Some(Value::Object(last)) = a.last().cloned() else {
                return false;
            };
            let mut last = last;
            last.insert("id".into(), Value::str("Z9"));
            a.push(Value::Object(last));
            true
        }),
        ("result id not a rule id", |r| {
            let a = arr_mut(r, "results");
            let Some(Value::Object(m)) = a.last_mut() else {
                return false;
            };
            m.insert("id".into(), Value::str("R07"));
            true
        }),
        ("result without an id", |r| {
            let a = arr_mut(r, "results");
            let Some(Value::Object(m)) = a.last_mut() else {
                return false;
            };
            m.remove("id").is_some()
        }),
        ("result status invalid", |r| {
            let a = arr_mut(r, "results");
            let Some(Value::Object(m)) = a.first_mut() else {
                return false;
            };
            m.insert("status".into(), Value::str("MAYBE"));
            true
        }),
        ("result without a status", |r| {
            let a = arr_mut(r, "results");
            let Some(Value::Object(m)) = a.first_mut() else {
                return false;
            };
            m.remove("status").is_some()
        }),
        ("result not an object", |r| {
            let a = arr_mut(r, "results");
            if a.is_empty() {
                return false;
            }
            a[0] = Value::Null;
            true
        }),
        ("events first seq wrong", |r| {
            let a = arr_mut(r, "events");
            let Some(Value::Object(m)) = a.first_mut() else {
                return false;
            };
            m.insert("seq".into(), Value::Int(1));
            true
        }),
        ("events last seq wrong", |r| {
            let a = arr_mut(r, "events");
            let n = a.len();
            let Some(Value::Object(m)) = a.last_mut() else {
                return false;
            };
            m.insert("seq".into(), Value::count(n as u64));
            true
        }),
        ("events swapped", |r| {
            let a = arr_mut(r, "events");
            if a.len() < 2 {
                return false;
            }
            a.swap(0, 1);
            true
        }),
        ("events seq as text", |r| {
            let a = arr_mut(r, "events");
            let Some(Value::Object(m)) = a.first_mut() else {
                return false;
            };
            m.insert("seq".into(), Value::str("0"));
            true
        }),
        ("sealed topics swapped", |r| {
            let a = arr_mut(r, "sealed_topics");
            if a.len() < 2 {
                return false;
            }
            a.swap(0, 1);
            true
        }),
        ("sealed topic repeated", |r| {
            let a = arr_mut(r, "sealed_topics");
            if a.len() < 2 {
                return false;
            }
            a[1] = a[0].clone();
            true
        }),
        ("sealed topic without multi_id", |r| {
            let a = arr_mut(r, "sealed_topics");
            let Some(Value::Object(m)) = a.first_mut() else {
                return false;
            };
            m.remove("multi_id").is_some()
        }),
        ("sealed topic without topic", |r| {
            let a = arr_mut(r, "sealed_topics");
            let Some(Value::Object(m)) = a.first_mut() else {
                return false;
            };
            m.remove("topic").is_some()
        }),
        ("allow_ignore_all flipped", |r| {
            let m = obj_mut(r, "seal");
            let Some(Value::Bool(b)) = m.get("allow_ignore_all").cloned() else {
                return false;
            };
            m.insert("allow_ignore_all".into(), Value::Bool(!b));
            true
        }),
        ("allow_ignore_all missing", |r| {
            obj_mut(r, "seal").remove("allow_ignore_all").is_some()
        }),
        ("allow_ignore_all as text", |r| {
            obj_mut(r, "seal").insert("allow_ignore_all".into(), Value::str("false"));
            true
        }),
        ("allow_untested_version as text", |r| {
            obj_mut(r, "seal").insert("allow_untested_version".into(), Value::str("false"));
            true
        }),
        ("allow_untested_version missing", |r| {
            obj_mut(r, "seal")
                .remove("allow_untested_version")
                .is_some()
        }),
        ("key_custody unknown", |r| {
            obj_mut(r, "seal").insert("key_custody".into(), Value::str("hsm-magic"));
            true
        }),
        ("signer certificate not base64", |r| {
            obj_mut(r, "seal").insert("signer_certificate".into(), Value::str("!!!!"));
            true
        }),
        ("signer certificate empty", |r| {
            obj_mut(r, "seal").insert("signer_certificate".into(), Value::str(""));
            true
        }),
        ("signer certificate a number", |r| {
            obj_mut(r, "seal").insert("signer_certificate".into(), Value::Int(1));
            true
        }),
        ("chain without a signer certificate", |r| {
            let m = obj_mut(r, "seal");
            m.insert("signer_certificate".into(), Value::Null);
            m.insert(
                "certificate_chain".into(),
                Value::Array(vec![Value::str("AAAA")]),
            );
            true
        }),
        ("chain empty beside a signer certificate", |r| {
            let m = obj_mut(r, "seal");
            m.insert("signer_certificate".into(), Value::str("AAAA"));
            m.insert("certificate_chain".into(), Value::Array(Vec::new()));
            true
        }),
        ("chain element not base64", |r| {
            let m = obj_mut(r, "seal");
            m.insert("signer_certificate".into(), Value::str("AAAA"));
            m.insert(
                "certificate_chain".into(),
                Value::Array(vec![Value::str("AAAA"), Value::str("!!!!")]),
            );
            true
        }),
        ("chain element empty", |r| {
            let m = obj_mut(r, "seal");
            m.insert("signer_certificate".into(), Value::str("AAAA"));
            m.insert(
                "certificate_chain".into(),
                Value::Array(vec![Value::str("")]),
            );
            true
        }),
        ("chain not an array", |r| {
            let m = obj_mut(r, "seal");
            m.insert("signer_certificate".into(), Value::str("AAAA"));
            m.insert("certificate_chain".into(), Value::str("AAAA"));
            true
        }),
        ("crypto crate not an object", |r| {
            let Some(Value::Array(a)) = obj_mut(r, "seal").get_mut("crypto_crates") else {
                return false;
            };
            if a.is_empty() {
                return false;
            }
            a[0] = Value::str("x");
            true
        }),
        ("crypto crate without a version", |r| {
            let Some(Value::Array(a)) = obj_mut(r, "seal").get_mut("crypto_crates") else {
                return false;
            };
            let Some(Value::Object(m)) = a.first_mut() else {
                return false;
            };
            m.remove("version").is_some()
        }),
        ("unknown top-level member", |r| {
            r.insert("zzz".into(), Value::Null);
            true
        }),
        ("unknown schema_version", |r| {
            r.insert("schema_version".into(), Value::Int(999));
            true
        }),
        ("schema_version as text", |r| {
            r.insert("schema_version".into(), Value::str("5"));
            true
        }),
    ];
    for (name, edit) in cases {
        let mut applied = 0;
        for (i, s) in SEEDS.iter().enumerate() {
            let Some(b) = resign(s, HONEST, edit) else {
                continue;
            };
            applied += 1;
            let v = run(&b, &own);
            assert!(
                v.is_err(),
                "seed {i}: signed record with `{name}` verified: {v:?}"
            );
        }
        assert!(applied > 0, "`{name}` applied to no seed");
    }
}

/// Records that differ from a verifying one in exactly one of the Merkle root, the claimed
/// fingerprint and the signing key.
#[test]
fn a_wrong_root_fingerprint_or_signer_alone_is_refused() {
    let own = key_n(7).public_key();
    let cases: [(&str, Resign); 7] = [
        (
            "signed by another key",
            Resign {
                signer: 9,
                ..HONEST
            },
        ),
        (
            "claims another key's fingerprint",
            Resign {
                claimed: 9,
                ..HONEST
            },
        ),
        (
            "fingerprint first digit",
            Resign {
                fingerprint: flip_first_fp,
                ..HONEST
            },
        ),
        (
            "fingerprint last digit",
            Resign {
                fingerprint: flip_last,
                ..HONEST
            },
        ),
        (
            "root first digit, signed",
            Resign {
                root: flip_first,
                ..HONEST
            },
        ),
        (
            "root last digit, signed",
            Resign {
                root: flip_last,
                ..HONEST
            },
        ),
        (
            "root all zero, signed",
            Resign {
                root: |_| "0".repeat(64),
                ..HONEST
            },
        ),
    ];
    for (name, how) in cases {
        for (i, s) in SEEDS.iter().enumerate() {
            let b = resign(s, how, |_| true).unwrap();
            let v = run(&b, &own);
            assert!(v.is_err(), "seed {i}: `{name}` verified: {v:?}");
        }
    }
}

/// The first digit after `sha256:`.
fn flip_first_fp(s: String) -> String {
    let (head, tail) = s.split_at("sha256:".len());
    format!("{head}{}", flip_first(tail.to_string()))
}

/// Everything a `Verified` reports is what the record says, read here from the JSON itself.
#[test]
fn a_verified_result_agrees_with_the_record_it_describes() {
    for (i, s) in SEEDS.iter().enumerate() {
        let r = record_of(s);
        let v = run(s, &KEY).unwrap();
        let ids_with = |wanted: &str| -> Vec<String> {
            match r.get("results") {
                Some(Value::Array(a)) => a
                    .iter()
                    .filter_map(|x| match x {
                        Value::Object(m) if m.get("status") == Some(&Value::str(wanted)) => {
                            match m.get("id") {
                                Some(Value::Str(id)) => Some(id.clone()),
                                _ => None,
                            }
                        }
                        _ => None,
                    })
                    .collect(),
                _ => panic!("results"),
            }
        };
        assert_eq!(v.failed_rules, ids_with("FAIL"), "seed {i}");
        assert_eq!(v.warned_rules, ids_with("WARN"), "seed {i}");
        let len = |k: &str| match r.get(k) {
            Some(Value::Array(a)) => a.len(),
            _ => panic!("{k}"),
        };
        assert_eq!(v.events, len("events"), "seed {i}");
        assert_eq!(
            v.leaf_count,
            5 + len("results") + len("sealed_topics") + len("events"),
            "seed {i}"
        );
        let m = match r.get("merkle") {
            Some(Value::Object(m)) => m,
            _ => panic!("merkle"),
        };
        assert_eq!(
            m.get("leaf_count"),
            Some(&Value::count(v.leaf_count as u64)),
            "seed {i}"
        );
        assert_eq!(v.merkle_root, string_of(&r, "merkle", "root"), "seed {i}");
        assert_eq!(
            v.fingerprint,
            string_of(&r, "seal", "key_fingerprint"),
            "seed {i}"
        );
        assert_eq!(v.fingerprint, fingerprint(&RustCrypto, &KEY), "seed {i}");
        assert_eq!(v.status, status_of(&r), "seed {i}");
        assert_eq!(
            v.log_file_name,
            string_of(&r, "log", "file_name"),
            "seed {i}"
        );
        assert_eq!(
            v.claimed_time_utc,
            string_of(&r, "seal", "time_utc"),
            "seed {i}"
        );
        assert_eq!(
            Some(v.custody),
            Custody::parse(&string_of(&r, "seal", "key_custody")),
            "seed {i}"
        );
        let crates = match r.get("seal") {
            Some(Value::Object(m)) => match m.get("crypto_crates") {
                Some(Value::Array(a)) => a
                    .iter()
                    .map(|c| match c {
                        Value::Object(c) => match (c.get("name"), c.get("version")) {
                            (Some(Value::Str(n)), Some(Value::Str(ver))) => format!("{n} {ver}"),
                            _ => panic!("crate"),
                        },
                        _ => panic!("crate"),
                    })
                    .collect::<Vec<_>>()
                    .join(", "),
                _ => panic!("crates"),
            },
            _ => panic!("seal"),
        };
        assert_eq!(v.crypto_crates, crates, "seed {i}");
    }
}

/// Every 7th byte of the smallest seed, and every 509th byte of the others, changed and deleted:
/// not one verifies. The positions are fixed, so the run is deterministic and covers the whole length of every seed.
#[test]
fn a_sweep_over_every_position_of_a_seed_never_verifies() {
    for (i, s) in SEEDS.iter().enumerate() {
        let step = if s.len() < 10_000 { 7 } else { 509 };
        for p in (0..s.len()).step_by(step) {
            let mut b = s.to_vec();
            b[p] ^= 0x01;
            assert!(run(&b, &KEY).is_err(), "seed {i}: xor at {p} verified");
            let mut b = s.to_vec();
            b.remove(p);
            assert!(
                run(&b, &KEY).is_err(),
                "seed {i}: deleting byte {p} verified"
            );
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Records that are intact in every byte the Merkle tree and the signature cover, and are not in
// canonical form (RFC 8785) in a part nothing hashes: only the canonical scan can refuse these.
// ---------------------------------------------------------------------------------------------

/// A member of the top-level object of a seed: its key, the start of `"key":` and the value range.
fn members_of(seed: &[u8]) -> Vec<(String, usize, std::ops::Range<usize>)> {
    scan_canonical(seed)
        .expect("a seed is canonical")
        .into_iter()
        .map(|m| {
            let start = m.value.start - (m.key.len() + 3);
            (m.key, start, m.value)
        })
        .collect()
}

/// The seed with the bytes of the value of the top-level member `key` rewritten.
fn rewrite_value(seed: &[u8], key: &str, f: impl FnOnce(&[u8]) -> Vec<u8>) -> Vec<u8> {
    let (_, _, v) = members_of(seed).into_iter().find(|m| m.0 == key).unwrap();
    let mut out = seed[..v.start].to_vec();
    out.extend(f(&seed[v.clone()]));
    out.extend_from_slice(&seed[v.end..]);
    out
}

/// The seed with its top-level members, each as `"key":value` text, put together by `order`.
fn rebuilt(seed: &[u8], order: impl FnOnce(Vec<Vec<u8>>) -> Vec<Vec<u8>>) -> Vec<u8> {
    let texts = members_of(seed)
        .into_iter()
        .map(|(_, s, v)| seed[s..v.end].to_vec())
        .collect();
    let mut out = b"{".to_vec();
    out.extend(order(texts).join(&b","[..]));
    out.push(b'}');
    out
}

fn insert_at(seed: &[u8], at: usize, with: &[u8]) -> Vec<u8> {
    let mut b = seed[..at].to_vec();
    b.extend_from_slice(with);
    b.extend_from_slice(&seed[at..]);
    b
}

/// `rebuilt` with nothing changed is the seed itself, so the cases below differ from it by
/// exactly what they name.
#[test]
fn noncanonical_forms_of_a_record_are_refused() {
    type Case = (&'static str, fn(&[u8]) -> Vec<u8>);
    let cases: Vec<Case> = vec![
        ("space after the opening brace", |s| insert_at(s, 1, b" ")),
        ("space before the closing brace", |s| {
            insert_at(s, s.len() - 1, b" ")
        }),
        ("newline after the record", |s| insert_at(s, s.len(), b"\n")),
        ("byte order mark", |s| insert_at(s, 0, b"\xef\xbb\xbf")),
        ("space after a top-level colon", |s| {
            insert_at(s, members_of(s)[0].2.start, b" ")
        }),
        ("space after a top-level comma", |s| {
            insert_at(s, members_of(s)[0].2.end + 1, b" ")
        }),
        ("first two top-level members swapped", |s| {
            rebuilt(s, |mut t| {
                t.swap(0, 1);
                t
            })
        }),
        ("last two top-level members swapped", |s| {
            rebuilt(s, |mut t| {
                let n = t.len();
                t.swap(n - 2, n - 1);
                t
            })
        }),
        ("top-level members in reverse", |s| {
            rebuilt(s, |mut t| {
                t.reverse();
                t
            })
        }),
        ("a top-level member twice", |s| {
            rebuilt(s, |mut t| {
                let n = t.len();
                let copy = t[n - 2].clone();
                t.insert(n - 2, copy);
                t
            })
        }),
        ("the first top-level member twice", |s| {
            rebuilt(s, |mut t| {
                let copy = t[0].clone();
                t.insert(0, copy);
                t
            })
        }),
        ("status with an escaped letter", |s| {
            rewrite_value(s, "status", |v| {
                // "PASS" -> "\u0050ASS": the same text, not the canonical spelling.
                let mut o = vec![b'"'];
                o.extend_from_slice(format!("\\u{:04x}", v[1]).as_bytes());
                o.extend_from_slice(&v[2..]);
                o
            })
        }),
        ("leaf_count with a leading zero", |s| {
            rewrite_value(s, "merkle", |v| {
                let at = v.windows(13).position(|w| w == b"\"leaf_count\":").unwrap() + 13;
                insert_at(v, at, b"0")
            })
        }),
        ("leaf_count with a plus sign", |s| {
            rewrite_value(s, "merkle", |v| {
                let at = v.windows(13).position(|w| w == b"\"leaf_count\":").unwrap() + 13;
                insert_at(v, at, b"+")
            })
        }),
        ("leaf_count with a fraction", |s| {
            rewrite_value(s, "merkle", |v| {
                let at = v.windows(13).position(|w| w == b"\"leaf_count\":").unwrap() + 13;
                let end = at + v[at..].iter().position(|c| !c.is_ascii_digit()).unwrap();
                insert_at(v, end, b".0")
            })
        }),
        ("leaf_count with an exponent", |s| {
            rewrite_value(s, "merkle", |v| {
                let at = v.windows(13).position(|w| w == b"\"leaf_count\":").unwrap() + 13;
                let end = at + v[at..].iter().position(|c| !c.is_ascii_digit()).unwrap();
                insert_at(v, end, b"e0")
            })
        }),
        ("merkle with a space after a colon", |s| {
            rewrite_value(s, "merkle", |v| insert_at(v, 13, b" "))
        }),
        ("signature with a space after a comma", |s| {
            rewrite_value(s, "signature", |v| {
                let at = v.iter().position(|c| *c == b',').unwrap() + 1;
                insert_at(v, at, b" ")
            })
        }),
        ("signature members swapped", |s| {
            rewrite_value(s, "signature", |v| {
                let text = String::from_utf8(v.to_vec()).unwrap();
                let inner = &text[1..text.len() - 1];
                let (a, b) = inner.split_once(',').unwrap();
                format!("{{{b},{a}}}").into_bytes()
            })
        }),
        ("status with invalid UTF-8", |s| {
            rewrite_value(s, "status", |v| {
                let mut o = v[..v.len() - 1].to_vec();
                o.extend_from_slice(b"\xff\"");
                o
            })
        }),
    ];
    assert_eq!(
        rebuilt(SEEDS[4], |t| t),
        SEEDS[4],
        "rebuilding keeps the seed"
    );
    for (name, make) in cases {
        for (i, s) in SEEDS.iter().enumerate() {
            let b = make(s);
            assert_ne!(&b[..], *s, "`{name}` changed nothing");
            let v = run(&b, &KEY);
            assert!(v.is_err(), "seed {i}: `{name}` verified: {v:?}");
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Records signed again over bytes of the author's choosing. The tree and the signature are built
// here the way the format says (docs/RECORD_FORMAT.md): a leaf is the bytes of the member as
// written, so a record can be given a valid root and signature whatever its bytes are. That
// leaves the canonical scan, and the checks for missing members, as the only checks that can
// refuse it.
// ---------------------------------------------------------------------------------------------

/// A member of a record as text: one value, or the elements of an array that are leaves.
#[derive(Clone)]
enum Part {
    One(Vec<u8>),
    List(Vec<Vec<u8>>),
}

/// The top-level members of a seed in order, with the key fingerprint changed to the own key's.
fn parts_of(seed: &[u8]) -> Vec<(String, Part)> {
    let old = fingerprint(&RustCrypto, &KEY).into_bytes();
    let new = fingerprint(&RustCrypto, &key_n(7).public_key()).into_bytes();
    scan_canonical(seed)
        .expect("a seed is canonical")
        .into_iter()
        .map(|m| {
            let part = if matches!(m.key.as_str(), "results" | "sealed_topics" | "events") {
                Part::List(
                    m.elements
                        .iter()
                        .map(|e| seed[e.clone()].to_vec())
                        .collect(),
                )
            } else {
                let mut v = seed[m.value.clone()].to_vec();
                if m.key == "seal" {
                    let at = v.windows(old.len()).position(|w| w == &old[..]).unwrap();
                    v.splice(at..at + old.len(), new.iter().copied());
                }
                Part::One(v)
            };
            (m.key, part)
        })
        .collect()
}

fn part<'a>(parts: &'a mut [(String, Part)], key: &str) -> &'a mut Part {
    &mut parts.iter_mut().find(|p| p.0 == key).unwrap().1
}

fn one(parts: &[(String, Part)], key: &str) -> Vec<u8> {
    match &parts.iter().find(|p| p.0 == key).unwrap().1 {
        Part::One(v) => v.clone(),
        Part::List(_) => panic!("{key} is a list"),
    }
}

/// The record these parts make, with its own key's root and signature. Members `merkle` and
/// `signature` of `parts` are replaced; a part that is missing is hashed as no bytes, the way a
/// verifier that does not insist on it would.
fn assemble(mut parts: Vec<(String, Part)>) -> Vec<u8> {
    parts.retain(|p| p.0 != "merkle" && p.0 != "signature");
    let get = |k: &str| -> Vec<u8> {
        parts
            .iter()
            .find(|p| p.0 == k)
            .map_or(Vec::new(), |p| match &p.1 {
                Part::One(v) => v.clone(),
                Part::List(_) => Vec::new(),
            })
    };
    let list = |k: &str| -> Vec<Vec<u8>> {
        parts
            .iter()
            .find(|p| p.0 == k)
            .map_or(Vec::new(), |p| match &p.1 {
                Part::List(v) => v.clone(),
                Part::One(_) => Vec::new(),
            })
    };
    let schema_text = get("schema_version");
    let mut context = b"{\"schema_version\":".to_vec();
    context.extend_from_slice(&schema_text);
    context.extend_from_slice(b",\"seal\":");
    context.extend_from_slice(&get("seal"));
    context.extend_from_slice(b",\"tool\":");
    context.extend_from_slice(&get("tool"));
    context.push(b'}');
    let leaf = |s: Section, b: &[u8]| merkle::tagged_leaf_hash(&RustCrypto, s.tag(), b);
    let mut hashes = vec![
        leaf(Section::SealContext, &context),
        leaf(Section::Log, &get("log")),
        leaf(Section::Config, &get("config")),
        leaf(Section::Baseline, &get("baseline")),
        leaf(Section::Rules, &get("rules")),
    ];
    let (results, topics, events) = (list("results"), list("sealed_topics"), list("events"));
    for (s, items) in [
        (Section::Result, &results),
        (Section::SealedTopic, &topics),
        (Section::Event, &events),
    ] {
        hashes.extend(items.iter().map(|e| leaf(s, e)));
    }
    let shape = TreeShape::of_counts(results.len(), topics.len(), events.len());
    let root = merkle::root(&RustCrypto, &hashes).unwrap();
    let schema = std::str::from_utf8(&schema_text)
        .unwrap()
        .parse::<u32>()
        .unwrap_or(0);
    let sig = key_n(7)
        .sign(&signed_payload(schema, &shape, &root))
        .unwrap();
    let mut m = Map::new();
    m.insert("algorithm".into(), Value::str(merkle::ALGORITHM));
    m.insert("leaf_count".into(), Value::count(hashes.len() as u64));
    m.insert("root".into(), Value::str(hex(&root)));
    m.insert("sections".into(), shape.to_json());
    let mut sg = Map::new();
    sg.insert("algorithm".into(), Value::str("ed25519"));
    sg.insert("value".into(), Value::str(hex(&sig)));
    parts.push((
        "merkle".into(),
        Part::One(canonical(&Value::Object(m)).into_bytes()),
    ));
    parts.push((
        "signature".into(),
        Part::One(canonical(&Value::Object(sg)).into_bytes()),
    ));
    parts.sort_by(|a, b| a.0.cmp(&b.0));
    let mut out = b"{".to_vec();
    for (i, (k, p)) in parts.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        out.extend_from_slice(format!("\"{k}\":").as_bytes());
        match p {
            Part::One(v) => out.extend_from_slice(v),
            Part::List(items) => {
                out.push(b'[');
                out.extend_from_slice(&items.join(&b","[..]));
                out.push(b']');
            }
        }
    }
    out.push(b'}');
    out
}

/// `{...}` text with the members of its top level as `"key":value` texts.
fn object_members(object: &[u8]) -> Vec<Vec<u8>> {
    scan_canonical(object)
        .expect("an element is a canonical object")
        .into_iter()
        .map(|m| object[m.value.start - (m.key.len() + 3)..m.value.end].to_vec())
        .collect()
}

fn object_of(members: &[Vec<u8>]) -> Vec<u8> {
    let mut o = b"{".to_vec();
    o.extend(members.join(&b","[..]));
    o.push(b'}');
    o
}

/// Control: reassembling a seed over its own bytes gives a record that verifies under the own
/// key, and the members that make it can be taken apart and put together again.
#[test]
fn a_reassembled_record_verifies() {
    let own = key_n(7).public_key();
    for (i, s) in SEEDS.iter().enumerate() {
        let b = assemble(parts_of(s));
        let v = run(&b, &own);
        assert!(
            v.is_ok(),
            "seed {i}: reassembled record does not verify: {v:?}"
        );
        let again = object_of(&object_members(&one(&parts_of(s), "tool")));
        assert_eq!(again, one(&parts_of(s), "tool"));
    }
}

/// Members that are missing from a record that is signed again over what is left.
#[test]
fn a_record_without_a_required_member_is_refused() {
    let own = key_n(7).public_key();
    for member in [
        "baseline",
        "config",
        "events",
        "log",
        "results",
        "rules",
        "schema_version",
        "seal",
        "sealed_topics",
        "status",
        "tool",
    ] {
        for (i, s) in SEEDS.iter().enumerate() {
            let mut p = parts_of(s);
            p.retain(|x| x.0 != member);
            let v = run(&assemble(p), &own);
            assert!(
                v.is_err(),
                "seed {i}: a record without `{member}` verified: {v:?}"
            );
        }
    }
}

/// A seed signed again with the text of one event replaced by `make(event)`.
fn with_event(seed: &[u8], make: impl FnOnce(&[u8]) -> Vec<u8>) -> Vec<u8> {
    let mut p = parts_of(seed);
    let Part::List(events) = part(&mut p, "events") else {
        panic!("events")
    };
    let e = events[0].clone();
    events[0] = make(&e);
    assemble(p)
}

/// Inside a leaf, nothing but the canonical scan sees the bytes of an event: the record is
/// signed over them as written. Forms that are not canonical must be refused, and the canonical
/// forms next to them must not.
#[test]
fn noncanonical_bytes_inside_a_signed_leaf_are_refused() {
    let own = key_n(7).public_key();
    // Before the first digit of the member's value, and inside the first string value.
    let after_key = |e: &[u8], key: &str| {
        let pat = format!("\"{key}\":");
        e.windows(pat.len())
            .position(|w| w == pat.as_bytes())
            .map(|at| at + pat.len())
    };
    type Case = (&'static str, fn(&[u8]) -> Option<Vec<u8>>);
    let bad: Vec<Case> = vec![
        ("an object member twice", |e| {
            let mut m = object_members(e);
            let first = m[0].clone();
            m.insert(0, first);
            Some(object_of(&m))
        }),
        ("an object member twice, last", |e| {
            let mut m = object_members(e);
            let last = m[m.len() - 1].clone();
            m.push(last);
            Some(object_of(&m))
        }),
        ("members out of order", |e| {
            let mut m = object_members(e);
            m.swap(0, 1);
            Some(object_of(&m))
        }),
        ("members in reverse", |e| {
            let mut m = object_members(e);
            m.reverse();
            Some(object_of(&m))
        }),
        ("non-ASCII keys in UTF-8 order, not UTF-16 order", |e| {
            let mut m = object_members(e);
            m.push("\"\u{ff5e}\":1".as_bytes().to_vec());
            m.push("\"\u{10000}\":1".as_bytes().to_vec());
            Some(object_of(&m))
        }),
        ("the same non-ASCII key twice", |e| {
            let mut m = object_members(e);
            m.push("\"\u{ff5e}\":1".as_bytes().to_vec());
            m.push("\"\u{ff5e}\":1".as_bytes().to_vec());
            Some(object_of(&m))
        }),
        ("an escaped key out of order", |e| {
            let mut m = object_members(e);
            m.push("\"\\u0001\":1".as_bytes().to_vec());
            m.push("\"\\u0001\":1".as_bytes().to_vec());
            Some(object_of(&m))
        }),
        ("whitespace inside the event", |e| {
            let mut o = e.to_vec();
            o.insert(1, b' ');
            Some(o)
        }),
        ("whitespace after a comma inside the event", |e| {
            let mut o = e.to_vec();
            let at = o.iter().position(|c| *c == b',')? + 1;
            o.insert(at, b' ');
            Some(o)
        }),
    ];
    let with_int: Vec<(&'static str, &'static [u8])> = vec![
        ("an integer with a leading zero", b"0"),
        ("an integer with a plus sign", b"+"),
        ("an integer with a minus zero prefix", b"-0"),
    ];
    let with_string: Vec<(&'static str, &'static [u8])> = vec![
        ("a raw control character in a string", b"\x09"),
        ("a raw newline in a string", b"\n"),
        ("invalid UTF-8 in a string", b"\xff"),
        ("a truncated UTF-8 sequence in a string", b"\xe3\x81"),
        ("an escape of a printable character", b"\\u0041"),
        ("an upper-case hex escape", b"\\u001F"),
        ("a long escape of a character with a short one", b"\\u000a"),
        ("a long escape of backspace", b"\\u0008"),
        ("an escape that is not one", b"\\x"),
        ("an escaped solidus", b"\\/"),
        ("a short hex escape", b"\\u00"),
        ("a bare backslash", b"\\"),
    ];
    let mut applied = 0;
    for (i, s) in SEEDS.iter().enumerate() {
        for (name, make) in &bad {
            let mut made = false;
            let b = with_event(s, |e| match make(e) {
                Some(x) => {
                    made = true;
                    x
                }
                None => e.to_vec(),
            });
            if made {
                applied += 1;
                let v = run(&b, &own);
                assert!(v.is_err(), "seed {i}: `{name}` verified: {v:?}");
            }
        }
        // Negative zero in place of the index, and a fraction or exponent after it.
        for (name, rest) in [
            ("negative zero", &b"-0"[..]),
            ("a fraction", b"0.0"),
            ("an exponent", b"0e0"),
            ("a number beyond the safe range", b"9007199254740992"),
        ] {
            let mut made = false;
            let b = with_event(s, |e| {
                let Some(at) = after_key(e, "index") else {
                    return e.to_vec();
                };
                made = true;
                let end = at + e[at..].iter().position(|c| !c.is_ascii_digit()).unwrap();
                let mut o = e[..at].to_vec();
                o.extend_from_slice(rest);
                o.extend_from_slice(&e[end..]);
                o
            });
            if made {
                applied += 1;
                let v = run(&b, &own);
                assert!(v.is_err(), "seed {i}: `{name}` verified: {v:?}");
            }
        }
        for (name, ins) in &with_int {
            let mut made = false;
            let b = with_event(s, |e| {
                let Some(at) = after_key(e, "index") else {
                    return e.to_vec();
                };
                made = true;
                insert_at(e, at, ins)
            });
            if made {
                applied += 1;
                let v = run(&b, &own);
                assert!(v.is_err(), "seed {i}: `{name}` verified: {v:?}");
            }
        }
        for (name, ins) in &with_string {
            let mut made = false;
            let b = with_event(s, |e| {
                let Some(at) = after_key(e, "kind") else {
                    return e.to_vec();
                };
                made = true;
                insert_at(e, at + 2, ins)
            });
            if made {
                applied += 1;
                let v = run(&b, &own);
                assert!(v.is_err(), "seed {i}: `{name}` verified: {v:?}");
            }
        }
        // The canonical neighbours of the forms above verify: this is what the cases differ by.
        let ok = with_event(s, |e| {
            let mut m = object_members(e);
            m.push(b"\"\x7f\":\"a\\u001fb\\n\\b\\t\"".to_vec());
            m.push("\"\u{10000}\":1".as_bytes().to_vec());
            m.push("\"\u{ff5e}\":1".as_bytes().to_vec());
            object_of(&m)
        });
        assert!(
            run(&ok, &own).is_ok(),
            "seed {i}: canonical non-ASCII keys and escapes are refused"
        );
    }
    assert!(applied > 40, "only {applied} cases were applied");
}
