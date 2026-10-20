//! `verify` judges the results a record holds, not only their signature: standalone, the
//! results must be R1 to R7 exactly once each with known statuses and the overall status must
//! be the one they give; with the log, the rules run again and every result and the status must
//! be what they give. Each record here is edited and signed again with the sealing key, as its
//! key holder could, so the signature is good and only these checks can catch it.
// A panicking test is a failing test, so tests may use expect and unwrap.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use sfr_core::json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

mod forge;

const LOG: &str = "testdata/sitl/v1.17.0/failsafe_gps_loss.ulg";
const BASELINE: &str = "testdata/baselines/v1.17.0_failsafe_gps_loss.params";

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

/// A record of the GPS-loss flight (R4 FAIL), sealed with a new evaluation key.
fn sealed(dir: &Path) -> (Vec<u8>, PathBuf, PathBuf) {
    std::fs::create_dir_all(dir).unwrap();
    let o = sfr(&[
        "keygen",
        "--evaluation-only",
        "--out",
        dir.join("k").to_str().unwrap(),
    ]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let o = sfr(&[
        "seal",
        LOG,
        "--rules",
        "examples/rules.default.toml",
        "--baseline",
        BASELINE,
        "--key",
        dir.join("k/sfr.key").to_str().unwrap(),
        "--evaluation-only",
        "--seal-time",
        "2026-10-18T15:00:00Z",
        "--out",
        dir.join("out").to_str().unwrap(),
    ]);
    assert_eq!(o.status.code(), Some(1), "R4 fails: {}", text(&o));
    let record = std::fs::read(dir.join("out/failsafe_gps_loss.sfr")).unwrap();
    (record, dir.join("k/sfr.key"), dir.join("k/sfr.pub"))
}

fn verify(dir: &Path, name: &str, record: &[u8], public: &Path, log: bool) -> Output {
    let path = dir.join(name);
    std::fs::write(&path, record).unwrap();
    let mut args = vec![
        "verify",
        path.to_str().unwrap(),
        "--pubkey",
        public.to_str().unwrap(),
        "--allow-evaluation-key",
        "--no-report",
    ];
    if log {
        args.extend(["--ulog", LOG]);
    }
    sfr(&args)
}

/// An edit of a record before it is signed again.
type Edit = Box<dyn Fn(&mut forge::Record)>;

fn results(r: &mut forge::Record) -> &mut Vec<Value> {
    match r.get_mut("results") {
        Some(Value::Array(a)) => a,
        _ => panic!("results"),
    }
}

fn set(v: &mut Value, key: &str, to: Value) {
    match v {
        Value::Object(m) => {
            m.insert(key.into(), to);
        }
        _ => panic!("not an object"),
    }
}

#[test]
fn standalone_verify_refuses_results_that_are_not_a_complete_known_set() {
    let dir = std::env::temp_dir().join(format!("sfr-results-{}", std::process::id()));
    let (record, key, public) = sealed(&dir);
    let key = forge::key_from_file(&key);
    let o = verify(&dir, "good.sfr", &record, &public, false);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));

    let cases: Vec<(&str, Edit, &str)> = vec![
        (
            "no results, status PASS",
            Box::new(|r| {
                results(r).clear();
                r.insert("status".into(), Value::str("PASS"));
            }),
            "results lack R1, R2, R3, R4, R5, R6, R7",
        ),
        (
            "a result status FAILED",
            Box::new(|r| {
                set(&mut results(r)[3], "status", Value::str("FAILED"));
                r.insert("status".into(), Value::str("PASS"));
            }),
            "result R4 has status \"FAILED\", not PASS, WARN, FAIL or N/A",
        ),
        (
            "an object as a result status",
            Box::new(|r| {
                set(
                    &mut results(r)[3],
                    "status",
                    Value::Object(Default::default()),
                )
            }),
            "result R4 has status {}, not PASS, WARN, FAIL or N/A",
        ),
        (
            "R4 removed, status PASS",
            Box::new(|r| {
                results(r).remove(3);
                r.insert("status".into(), Value::str("PASS"));
            }),
            "results lack R4",
        ),
        (
            "an overall status the results do not give",
            Box::new(|r| {
                r.insert("status".into(), Value::str("PASS"));
            }),
            "status is PASS but the results say FAIL",
        ),
        (
            "an overall status outside the four",
            Box::new(|r| {
                r.insert("status".into(), Value::str("FAILED"));
            }),
            "status is \"FAILED\", not PASS, WARN, FAIL or NO ARMED FLIGHT",
        ),
    ];
    for (what, edit, want) in cases {
        let forged = forge::resign(&record, &key, |r| edit(r));
        let o = verify(&dir, "forged.sfr", &forged, &public, false);
        assert_eq!(o.status.code(), Some(1), "{what}: {}", text(&o));
        assert!(
            text(&o).contains(want),
            "{what}: want `{want}` in {}",
            text(&o)
        );
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn deep_verify_runs_the_rules_again_and_names_the_rule_whose_result_was_changed() {
    let dir = std::env::temp_dir().join(format!("sfr-rerun-{}", std::process::id()));
    let (record, key, public) = sealed(&dir);
    let key = forge::key_from_file(&key);
    // R4 FAIL turned into PASS, the overall status with it: consistent, signed, and standalone
    // verify has nothing to object to.
    let forged = forge::resign(&record, &key, |r| {
        let r4 = &mut results(r)[3];
        set(r4, "status", Value::str("PASS"));
        set(r4, "found", Value::str("never true in flight"));
        set(r4, "detail", Value::Array(vec![]));
        r.insert("status".into(), Value::str("PASS"));
    });
    let o = verify(&dir, "forged.sfr", &forged, &public, false);
    assert_eq!(o.status.code(), Some(0), "standalone: {}", text(&o));
    let o = verify(&dir, "forged.sfr", &forged, &public, true);
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));
    let out = text(&o);
    assert!(
        out.contains("Integrity: FAILED: result R4 field `detail`")
            || out.contains("Integrity: FAILED: result R4 field `found`"),
        "{out}"
    );
    assert!(
        out.contains("status: sealed PASS, found FAIL when the rules run again on the log"),
        "{out}"
    );
    std::fs::remove_dir_all(dir).unwrap();
}
