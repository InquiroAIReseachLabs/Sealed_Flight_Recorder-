//! The signed structure of a record (SPEC B1.7, schema 3): every Merkle leaf is hashed with the
//! tag of its section, and the signature covers the tree size and the number of leaves in each
//! section. Before schema 3, a leaf moved between sections left the root and the signature valid;
//! only the structural checks of the sections noticed.
// A panicking test is a failing test, so tests may use expect and unwrap.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use sfr_core::json::{Value, canonical, parse};
use sfr_core::seal::{Section, TreeShape};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

mod forge;

const LOG: &str = "testdata/synthetic/custom_detection.ulg";
const RULES: &str = "testdata/rules/synthetic_custom_detection.toml";
const BASELINE: &str = "testdata/baselines/synthetic_custom_detection.params";

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn sfr(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sfr"))
        .current_dir(root())
        .args(args)
        .output()
        .expect("sfr binary runs")
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn scratch() -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "sfr-structure-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A sealed record of the synthetic log (7 rule results, 3 sealed topic digests, 3 events), the
/// private key's seed file path, and the public key file.
fn sealed(dir: &Path) -> (Vec<u8>, PathBuf, PathBuf) {
    let o = sfr(&[
        "keygen",
        "--evaluation-only",
        "--out",
        dir.join("k").to_str().unwrap(),
    ]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let (key, public) = (dir.join("k/sfr.key"), dir.join("k/sfr.pub"));
    let o = sfr(&[
        "seal",
        LOG,
        "--rules",
        RULES,
        "--baseline",
        BASELINE,
        "--key",
        key.to_str().unwrap(),
        "--evaluation-only",
        "--seal-time",
        "2026-10-18T15:00:00Z",
        "--out",
        dir.join("out").to_str().unwrap(),
    ]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let record = std::fs::read(dir.join("out/custom_detection.sfr")).unwrap();
    (record, key, public)
}

/// `sfr verify` of `record` against `public`, without the report (it is not under test).
fn verify(dir: &Path, name: &str, record: &[u8], public: &Path) -> Output {
    let path = dir.join(name);
    std::fs::write(&path, record).unwrap();
    sfr(&[
        "verify",
        path.to_str().unwrap(),
        "--pubkey",
        public.to_str().unwrap(),
        "--allow-evaluation-key",
        "--no-report",
    ])
}

fn object(record: &[u8]) -> std::collections::BTreeMap<String, Value> {
    match parse(record).unwrap() {
        Value::Object(m) => m,
        other => panic!("a record is an object, not {other:?}"),
    }
}

fn array<'a>(r: &'a mut std::collections::BTreeMap<String, Value>, k: &str) -> &'a mut Vec<Value> {
    match r.get_mut(k) {
        Some(Value::Array(a)) => a,
        other => panic!("{k} is an array, not {other:?}"),
    }
}

#[test]
fn a_leaf_moved_to_another_section_changes_the_root_and_fails_the_signature() {
    let dir = scratch();
    let (record, _, public) = sealed(&dir);
    assert_eq!(
        verify(&dir, "good.sfr", &record, &public).status.code(),
        Some(0)
    );

    // The red team's move (Issue #24, F5): the last result becomes the first sealed topic. The
    // order of the leaves is unchanged, so without section tags the root, and with it the
    // signature, stayed valid.
    let mut r = object(&record);
    let moved = array(&mut r, "results").pop().unwrap();
    array(&mut r, "sealed_topics").insert(0, moved);
    let forged = canonical(&Value::Object(r)).into_bytes();
    let o = verify(&dir, "moved.sfr", &forged, &public);
    let out = text(&o);
    assert_eq!(o.status.code(), Some(1), "{out}");
    assert!(
        out.contains("Merkle root mismatch: a leaf changed after sealing"),
        "{out}"
    );
    assert!(out.contains("Merkle sections: recorded"), "{out}");
    assert!(!out.contains("Integrity: VERIFIED"), "{out}");

    // The same in the other direction: the first event becomes the last result.
    let mut r = object(&record);
    let moved = array(&mut r, "events").remove(0);
    array(&mut r, "results").push(moved);
    let forged = canonical(&Value::Object(r)).into_bytes();
    let o = verify(&dir, "moved2.sfr", &forged, &public);
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));
    assert!(
        text(&o).contains("Merkle root mismatch: a leaf changed after sealing"),
        "{}",
        text(&o)
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn the_signature_covers_the_shape_of_the_tree() {
    let dir = scratch();
    let (record, key, public) = sealed(&dir);
    let key = forge::key_from_file(&key);

    // The key holder signs the right root over another shape: one leaf fewer in `results` and
    // one more in `events`, the same total. The record is internally consistent, but the
    // signature covers a payload the verifier does not rebuild from the record.
    let r = object(&record);
    let count = |k: &str| match r.get(k) {
        Some(Value::Array(a)) => a.len(),
        other => panic!("{k}: {other:?}"),
    };
    let (results, topics, events) = (count("results"), count("sealed_topics"), count("events"));
    let other = TreeShape::of_counts(results - 1, topics, events + 1);
    assert_eq!(
        other.leaf_count(),
        TreeShape::of_counts(results, topics, events).leaf_count(),
        "the same tree size"
    );
    let forged = forge::resign_over_shape(&record, &key, other);
    let o = verify(&dir, "shape.sfr", &forged, &public);
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));
    assert!(
        text(&o).contains("signature does not verify"),
        "{}",
        text(&o)
    );

    // Signed over the true shape, the same record verifies: the check above is about the shape.
    let honest =
        forge::resign_over_shape(&record, &key, TreeShape::of_counts(results, topics, events));
    let o = verify(&dir, "honest.sfr", &honest, &public);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_wrong_sections_count_is_named() {
    let dir = scratch();
    let (record, _, public) = sealed(&dir);
    let mut r = object(&record);
    let Some(Value::Object(merkle)) = r.get_mut("merkle") else {
        panic!("merkle is an object");
    };
    let Some(Value::Object(sections)) = merkle.get_mut("sections") else {
        panic!("merkle.sections is an object");
    };
    sections.insert("events".into(), Value::count(99));
    let forged = canonical(&Value::Object(r)).into_bytes();
    let o = verify(&dir, "sections.sfr", &forged, &public);
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));
    assert!(
        text(&o).contains("Merkle sections: recorded"),
        "{}",
        text(&o)
    );

    // `merkle` holds exactly its four members.
    let mut r = object(&record);
    let Some(Value::Object(merkle)) = r.get_mut("merkle") else {
        panic!("merkle is an object");
    };
    merkle.remove("sections");
    let forged = canonical(&Value::Object(r)).into_bytes();
    let o = verify(&dir, "nosections.sfr", &forged, &public);
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));
    assert!(
        text(&o).contains("must hold exactly algorithm, leaf_count, root, sections"),
        "{}",
        text(&o)
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_record_names_its_sections_and_carries_no_token_certification_field() {
    let dir = scratch();
    let (record, _, _) = sealed(&dir);
    let text = String::from_utf8(record.clone()).unwrap();
    assert!(
        !text.contains("token_cmvp_certificate"),
        "a record says nothing about a token's certification"
    );
    assert!(text.contains("\"schema_version\":3"), "schema 3");
    let r = object(&record);
    let Some(Value::Object(merkle)) = r.get("merkle") else {
        panic!("merkle is an object");
    };
    let Some(Value::Object(sections)) = merkle.get("sections") else {
        panic!("merkle.sections is an object");
    };
    let names: Vec<&str> = sections.keys().map(String::as_str).collect();
    let mut expected: Vec<&str> = Section::ALL.iter().map(|s| s.name()).collect();
    expected.sort_unstable();
    assert_eq!(names, expected, "one count for each section");
    std::fs::remove_dir_all(dir).unwrap();
}
