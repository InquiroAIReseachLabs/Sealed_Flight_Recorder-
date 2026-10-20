//! The false-pass corpus (testdata/falsepass, written by scripts/testdata/make_falsepass.py):
//! logs built to pass a reader that trusts what a log declares about its own structure, each
//! beside a positive control. Every case must give the result cases.json expects.
// A panicking test is a failing test, so tests may use expect and unwrap.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use sfr_core::json::{Value, parse};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn obj(v: &Value) -> &BTreeMap<String, Value> {
    match v {
        Value::Object(m) => m,
        other => panic!("not an object: {other:?}"),
    }
}

fn arr(v: &Value) -> &[Value] {
    match v {
        Value::Array(a) => a,
        other => panic!("not an array: {other:?}"),
    }
}

fn text(v: &Value) -> String {
    match v {
        Value::Str(s) => s.clone(),
        Value::Int(i) => i.to_string(),
        Value::Null => "null".into(),
        other => panic!("not a scalar: {other:?}"),
    }
}

fn int(v: &Value) -> i64 {
    match v {
        Value::Int(i) => *i,
        Value::Str(s) => s.parse().expect("a number"),
        other => panic!("not a number: {other:?}"),
    }
}

#[test]
fn every_false_pass_case_and_control_gives_its_expected_result() {
    let dir = root().join("testdata/falsepass");
    let cases = parse(&std::fs::read(dir.join("cases.json")).expect("cases.json")).unwrap();
    let mut problems = Vec::new();
    let cases = arr(&cases);
    assert!(
        cases.len() >= 30,
        "the corpus holds every case and its control"
    );
    for case in cases {
        let c = obj(case);
        let name = text(&c["case"]);
        let mut args: Vec<String> = vec![
            "seal".into(),
            dir.join(text(&c["log"])).display().to_string(),
            "--rules".into(),
            dir.join(text(&c["rules"])).display().to_string(),
            "--baseline".into(),
            dir.join(text(&c["baseline"])).display().to_string(),
            "--dry-run".into(),
            "--json".into(),
        ];
        args.extend(arr(&c["options"]).iter().map(text));
        let out = Command::new(env!("CARGO_BIN_EXE_sfr"))
            .args(&args)
            .output()
            .expect("sfr runs");
        let expect = obj(&c["expect"]);
        let code = out.status.code().unwrap_or(-1);
        if i64::from(code) != int(&expect["exit"]) {
            problems.push(format!(
                "{name}: exit {code}, expected {}: {}",
                int(&expect["exit"]),
                String::from_utf8_lossy(&out.stderr)
            ));
            continue;
        }
        if expect["status"] == Value::Null {
            continue;
        }
        let doc = parse(&out.stdout).unwrap();
        let doc = obj(&doc);
        if text(&doc["status"]) != text(&expect["status"]) {
            problems.push(format!(
                "{name}: status {}, expected {}",
                text(&doc["status"]),
                text(&expect["status"])
            ));
        }
        let results: BTreeMap<String, &BTreeMap<String, Value>> = arr(&doc["results"])
            .iter()
            .map(|r| (text(&obj(r)["id"]), obj(r)))
            .collect();
        for (id, status) in obj(&expect["results"]) {
            let got = text(&results[id]["status"]);
            if got != text(status) {
                problems.push(format!("{name}: {id} {got}, expected {}", text(status)));
            }
        }
        if let Some(found) = expect.get("found") {
            for (id, want) in obj(found) {
                let got = text(&results[id]["found"]);
                if !got.contains(&text(want)) {
                    problems.push(format!("{name}: {id} found `{got}` lacks `{}`", text(want)));
                }
            }
        }
        let log = obj(&doc["log"]);
        if let Some(n) = expect.get("instances") {
            assert_eq!(int(&log["vehicle_status_instances"]), int(n), "{name}");
        }
        if let Some(n) = expect.get("skipped") {
            let s = obj(&log["skipped"]);
            let total =
                int(&s["unknown_records"]) + int(&s["orphan_data_records"]) + int(&s["regions"]);
            assert_eq!(total, int(n), "{name}: skipped messages");
        }
        if let Some(events) = expect.get("events") {
            for (kind, n) in obj(events) {
                let got = arr(&doc["events"])
                    .iter()
                    .filter(|e| text(&obj(e)["kind"]) == *kind)
                    .count() as i64;
                assert_eq!(got, int(n), "{name}: {kind} events");
            }
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[test]
fn the_corpus_is_what_its_generator_writes() {
    let out = Command::new("python3")
        .current_dir(root())
        .args([
            "-I",
            "scripts/testdata/make_falsepass.py",
            "--check",
            "testdata/falsepass",
        ])
        .output()
        .expect("python3 runs");
    assert!(
        out.status.success(),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
