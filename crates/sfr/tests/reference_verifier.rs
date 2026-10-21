//! Differential test: `sfr verify` and the standalone reference verifier
//! (tools/reference_verifier/sfr_ref_verify.py, which shares no code with sfr) give the verdicts
//! tools/reference_verifier/vectors/expected.json lists for each test vector, among them the
//! adversarial JSON cases (a boolean where an integer belongs, unpaired surrogates, integers at
//! and over 2^53, the nesting limit), and both accept every committed record.
// A panicking test is a failing test, so tests may use expect and unwrap.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use sfr_core::json::{Value, parse};
use std::path::{Path, PathBuf};
use std::process::Command;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn sfr_accepts(record: &Path, public: &Path) -> bool {
    let o = Command::new(env!("CARGO_BIN_EXE_sfr"))
        .arg("verify")
        .arg(record)
        .arg("--pubkey")
        .arg(public)
        .args(["--allow-evaluation-key", "--no-report"])
        .output()
        .unwrap();
    o.status.code() == Some(0)
}

fn reference_accepts(record: &Path, public: &Path) -> bool {
    let o = Command::new("python3")
        .arg("-I")
        .arg(root().join("tools/reference_verifier/sfr_ref_verify.py"))
        .arg(record)
        .arg(public)
        .output()
        .expect("python3 runs");
    let out = String::from_utf8_lossy(&o.stdout).into_owned();
    assert!(
        out.starts_with("VERIFIED") || out.starts_with("FAILED: "),
        "{record:?}: {out}{}",
        String::from_utf8_lossy(&o.stderr)
    );
    o.status.code() == Some(0)
}

fn text(v: &Value) -> &str {
    match v {
        Value::Str(s) => s,
        other => panic!("not a string: {other:?}"),
    }
}

#[test]
fn sfr_and_the_reference_verifier_give_every_vector_its_expected_verdict() {
    let dir = root().join("tools/reference_verifier/vectors");
    let public = dir.join("vectors.pub");
    let Value::Object(expected) =
        parse(&std::fs::read(dir.join("expected.json")).unwrap()).unwrap()
    else {
        panic!("expected.json is an object");
    };
    assert!(expected.len() >= 35, "every vector is listed");
    let mut problems = Vec::new();
    for (name, want) in &expected {
        let (sfr_want, ref_want) = match want {
            Value::Str(v) => (v.as_str(), v.as_str()),
            Value::Object(m) => {
                assert!(!text(&m["why"]).is_empty(), "{name}: a difference says why");
                (text(&m["sfr"]), text(&m["reference"]))
            }
            other => panic!("{name}: {other:?}"),
        };
        let path = dir.join(name);
        let (s, r) = (
            sfr_accepts(&path, &public),
            reference_accepts(&path, &public),
        );
        if s != (sfr_want == "accept") {
            problems.push(format!("{name}: sfr accepts {s}, expected {sfr_want}"));
        }
        if r != (ref_want == "accept") {
            problems.push(format!(
                "{name}: reference accepts {r}, expected {ref_want}"
            ));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[test]
fn both_verifiers_accept_every_committed_record() {
    for (dir, key) in [
        ("examples/reports", "examples/reports/sfr.pub"),
        ("fuzz/seeds/sfr_verify", "fuzz/seeds/sfr_verify_key.pub"),
    ] {
        for e in std::fs::read_dir(root().join(dir)).unwrap() {
            let path = e.unwrap().path();
            if path.extension().is_some_and(|x| x == "sfr") {
                let key = root().join(key);
                assert!(sfr_accepts(&path, &key), "sfr: {path:?}");
                assert!(reference_accepts(&path, &key), "reference: {path:?}");
            }
        }
    }
}

#[test]
fn the_vectors_are_what_their_generator_writes() {
    let o = Command::new("python3")
        .current_dir(root())
        .args(["-I", "tools/reference_verifier/make_vectors.py", "--check"])
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stdout));
    let o = Command::new("python3")
        .current_dir(root())
        .args([
            "-I",
            "tools/reference_verifier/sfr_ref_verify.py",
            "--self-test",
        ])
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stdout));
}

/// Step 3 of docs/RECORD_FORMAT.md builds the signed payload from the recorded tree shape with
/// shell. A count that is not a number must not read as 0: on a record whose `sealed_topics` count
/// is `false` (its signature otherwise good), the documented commands must not report a good
/// signature. The test runs the doc's own block, so it cannot drift from the page.
#[test]
fn the_documented_signature_step_refuses_a_tree_shape_that_is_not_a_number() {
    let doc = std::fs::read_to_string(root().join("docs/RECORD_FORMAT.md")).unwrap();
    let step = doc
        .split("### 3. The signature over the recorded Merkle root and tree shape")
        .nth(1)
        .expect("the page has step 3");
    let block = step
        .split("```sh doc-test\n")
        .nth(1)
        .expect("step 3 has a command block")
        .split("\n```")
        .next()
        .unwrap();
    let dir = root().join("tools/reference_verifier/vectors");
    let work = std::env::temp_dir().join(format!("sfr-doc-step3-{}", std::process::id()));
    std::fs::create_dir_all(&work).unwrap();
    let verifies = |vector: &str| -> bool {
        let script = block
            .replace(
                "examples/reports/vtol_transition.sfr",
                dir.join(vector).to_str().unwrap(),
            )
            .replace(
                "examples/reports/sfr.pub",
                dir.join("vectors.pub").to_str().unwrap(),
            );
        Command::new("bash")
            .current_dir(&work)
            .args(["-c", &script])
            .output()
            .expect("bash runs")
            .status
            .success()
    };
    let (good, bad) = (verifies("valid.sfr"), verifies("merkle_sections_bool.sfr"));
    std::fs::remove_dir_all(&work).ok();
    assert!(good, "the documented commands verify the valid vector");
    assert!(
        !bad,
        "the documented commands must not verify a record whose sealed_topics count is `false`"
    );
}
