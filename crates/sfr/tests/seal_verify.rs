//! Chunk 3 gate tests: keygen, sealed records, standalone and deep verify (SPEC B1.3, B1.7,
//! B1.10 Deterministic, Replay, Tamper property).
// A panicking test is a failing test, so tests may use expect and unwrap.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use sfr_core::crypto::fips::Fips;
use sfr_core::keys::parse_public_key_pem;
use sfr_core::verify::{VerifyError, verify};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

const RULES: &str = "examples/rules.default.toml";
const SEAL_TIME: &str = "2026-10-18T15:00:00Z";

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
        "sfr-c3-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A fresh evaluation key pair in `dir`.
fn keygen(dir: &Path) -> (String, String) {
    let out = sfr(&[
        "keygen",
        "--evaluation-only",
        "--out",
        dir.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    (
        dir.join("sfr.key").to_str().unwrap().to_string(),
        dir.join("sfr.pub").to_str().unwrap().to_string(),
    )
}

/// Seals `log` into `out` and returns the record path and the exit code.
fn seal(log: &str, baseline: &str, key: &str, out: &Path) -> (String, i32) {
    let o = sfr(&[
        "seal",
        log,
        "--rules",
        RULES,
        "--baseline",
        baseline,
        "--key",
        key,
        "--evaluation-only",
        "--out",
        out.to_str().unwrap(),
        "--seal-time",
        SEAL_TIME,
    ]);
    let stem = Path::new(log).file_stem().unwrap().to_str().unwrap();
    let path = out.join(format!("{stem}.sfr"));
    assert!(path.exists(), "record written: {}", text(&o));
    (path.to_str().unwrap().to_string(), o.status.code().unwrap())
}

fn pubkey(path: &str) -> [u8; 32] {
    parse_public_key_pem(&std::fs::read_to_string(path).unwrap()).unwrap()
}

const GOLDEN: &[(&str, &str, i32)] = &[
    ("pyulog_sample", "testdata/pyulog/sample.ulg", 2),
    (
        "v1.14.4_mc_flight",
        "testdata/sitl/v1.14.4/mc_flight.ulg",
        0,
    ),
    (
        "v1.17.0_failsafe_battery_empty",
        "testdata/sitl/v1.17.0/failsafe_battery_empty.ulg",
        1,
    ),
    (
        "v1.17.0_failsafe_gps_loss",
        "testdata/sitl/v1.17.0/failsafe_gps_loss.ulg",
        1,
    ),
    (
        "v1.17.0_mc_flight_1",
        "testdata/sitl/v1.17.0/mc_flight_1.ulg",
        0,
    ),
    (
        "v1.17.0_mc_flight_2",
        "testdata/sitl/v1.17.0/mc_flight_2.ulg",
        0,
    ),
    (
        "v1.17.0_vtol_transition",
        "testdata/sitl/v1.17.0/vtol_transition.ulg",
        0,
    ),
    (
        "v1.17.0_vtol_quadchute",
        "testdata/sitl/v1.17.0/vtol_quadchute.ulg",
        1,
    ),
    (
        "v1.17.0_vtol_transition_abort",
        "testdata/sitl/v1.17.0/vtol_transition_abort.ulg",
        1,
    ),
    (
        "synthetic_r4_quadchute_on_disarm",
        "testdata/synthetic/r4_quadchute_on_disarm.ulg",
        1,
    ),
];

#[test]
fn keygen_writes_a_private_key_only_its_owner_can_read_and_never_overwrites() {
    let dir = scratch();
    let (key, _) = keygen(&dir);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    let again = sfr(&[
        "keygen",
        "--evaluation-only",
        "--out",
        dir.to_str().unwrap(),
    ]);
    assert_eq!(again.status.code(), Some(4));
    assert!(
        text(&again).contains("never overwrites"),
        "{}",
        text(&again)
    );
    let no_flag = sfr(&["keygen", "--out", scratch().to_str().unwrap()]);
    assert_eq!(no_flag.status.code(), Some(4));
    assert!(text(&no_flag).contains("pkcs11-token") && text(&no_flag).contains("--tpm-sealed"));
    let first = String::from_utf8_lossy(
        &sfr(&[
            "keygen",
            "--evaluation-only",
            "--out",
            scratch().to_str().unwrap(),
        ])
        .stdout,
    )
    .into_owned();
    assert!(
        first.starts_with("EVALUATION KEY") && first.contains("fingerprint  sha256:"),
        "{first}"
    );
}

#[test]
fn sealing_twice_is_byte_identical_and_failing_rules_still_write() {
    let dir = scratch();
    let (key, _) = keygen(&dir.join("k"));
    let log = "testdata/sitl/v1.17.0/failsafe_battery_empty.ulg";
    let bl = "testdata/baselines/v1.17.0_failsafe_battery_empty.params";
    let (a, code_a) = seal(log, bl, &key, &dir.join("a"));
    let (b, code_b) = seal(log, bl, &key, &dir.join("b"));
    assert_eq!(
        (code_a, code_b),
        (1, 1),
        "R4 fails, the record is still written, exit 1"
    );
    assert_eq!(std::fs::read(&a).unwrap(), std::fs::read(&b).unwrap());
    // Never overwrite a record.
    let o = sfr(&[
        "seal",
        log,
        "--rules",
        RULES,
        "--baseline",
        bl,
        "--key",
        &key,
        "--evaluation-only",
        "--out",
        dir.join("a").to_str().unwrap(),
    ]);
    assert_eq!(o.status.code(), Some(4));
    assert!(text(&o).contains("never overwrites"), "{}", text(&o));
}

#[test]
fn verify_with_ulog_replays_every_golden_log() {
    let dir = scratch();
    let (key, public) = keygen(&dir.join("k"));
    for (name, log, code) in GOLDEN {
        let (record, sealed_code) = seal(
            log,
            &format!("testdata/baselines/{name}.params"),
            &key,
            &dir.join(name),
        );
        assert_eq!(sealed_code, *code, "{log}");
        let o = sfr(&["verify", &record, "--pubkey", &public, "--ulog", log]);
        assert_eq!(o.status.code(), Some(0), "{log}: {}", text(&o));
        let t = text(&o);
        assert!(
            t.starts_with("EVALUATION KEY: not for operational use\nVERIFIED (record and log)"),
            "{t}"
        );
        let o = sfr(&["verify", &record, "--pubkey", &public]);
        assert_eq!(o.status.code(), Some(0), "{log}: {}", text(&o));
    }
}

/// xorshift64*, so the flips are the same on every run.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
}

#[test]
fn every_single_byte_flip_in_a_record_fails_verification() {
    let dir = scratch();
    let (key, public) = keygen(&dir.join("k"));
    let (record, _) = seal(
        "testdata/sitl/v1.17.0/vtol_transition_abort.ulg",
        "testdata/baselines/v1.17.0_vtol_transition_abort.params",
        &key,
        &dir,
    );
    let bytes = std::fs::read(&record).unwrap();
    let pk = pubkey(&public);
    let crypto = Fips::new().unwrap();
    assert!(verify(&bytes, None, &crypto, &pk, false).is_ok());
    let mut rng = Rng(0x5eed_0001);
    for i in 0..1000 {
        let mut t = bytes.clone();
        let at = (rng.next() % t.len() as u64) as usize;
        let x = (rng.next() % 255 + 1) as u8;
        t[at] ^= x;
        match verify(&t, None, &crypto, &pk, false) {
            Err(VerifyError::Mismatch(_)) => {}
            other => panic!("flip {i} at byte {at} (xor {x:#04x}) was not detected: {other:?}"),
        }
    }
}

#[test]
fn every_single_byte_flip_in_a_log_fails_verification() {
    let dir = scratch();
    let (key, public) = keygen(&dir.join("k"));
    // A complete log small enough to re-read 1,000 times (the shrunk fuzz seed).
    let log = "fuzz/seeds/ulog_ingest/sitl_v1.17.0_failsafe_gps_loss_shrunk.ulg";
    let (record, _) = seal(
        log,
        "testdata/baselines/v1.17.0_failsafe_gps_loss.params",
        &key,
        &dir,
    );
    let rec = std::fs::read(&record).unwrap();
    let ulg = std::fs::read(root().join(log)).unwrap();
    let pk = pubkey(&public);
    let crypto = Fips::new().unwrap();
    assert!(verify(&rec, Some(&mut &ulg[..]), &crypto, &pk, false).is_ok());
    let mut rng = Rng(0x5eed_0002);
    for i in 0..1000 {
        let mut t = ulg.clone();
        let at = (rng.next() % t.len() as u64) as usize;
        let x = (rng.next() % 255 + 1) as u8;
        t[at] ^= x;
        match verify(&rec, Some(&mut &t[..]), &crypto, &pk, false) {
            Err(VerifyError::Mismatch(_)) => {}
            other => panic!("flip {i} at byte {at} (xor {x:#04x}) was not detected: {other:?}"),
        }
    }
}

/// Offsets of the data payloads of every 'D' record, with their topic names.
fn data_records(log: &[u8]) -> Vec<(usize, usize, String)> {
    let mut topics = std::collections::BTreeMap::new();
    let mut out = Vec::new();
    let mut pos = 16;
    while pos + 3 <= log.len() {
        let size = u16::from_le_bytes([log[pos], log[pos + 1]]) as usize;
        let ty = log[pos + 2];
        let body = &log[pos + 3..pos + 3 + size];
        if ty == b'A' {
            topics.insert(
                u16::from_le_bytes([body[1], body[2]]),
                String::from_utf8_lossy(&body[3..]).into_owned(),
            );
        } else if ty == b'D' {
            let id = u16::from_le_bytes([body[0], body[1]]);
            out.push((
                pos + 5,
                size - 2,
                topics.get(&id).cloned().unwrap_or_default(),
            ));
        }
        pos += 3 + size;
    }
    out
}

#[test]
fn mismatches_are_named_precisely() {
    let dir = scratch();
    let (key, public) = keygen(&dir.join("k"));
    let log = "testdata/sitl/v1.17.0/mc_flight_1.ulg";
    let (record, _) = seal(
        log,
        "testdata/baselines/v1.17.0_mc_flight_1.params",
        &key,
        &dir,
    );
    let rec = std::fs::read_to_string(&record).unwrap();

    // 1. One byte of an event in the record: deep verify names the sequence number and field.
    let at = rec.find("\"result\":\"ACCEPTED\"").unwrap() + "\"result\":\"ACCEPTE".len();
    let mut flipped = rec.clone().into_bytes();
    flipped[at] = b'E';
    let bad = dir.join("event.sfr");
    std::fs::write(&bad, &flipped).unwrap();
    let o = sfr(&[
        "verify",
        bad.to_str().unwrap(),
        "--pubkey",
        &public,
        "--ulog",
        log,
    ]);
    assert_eq!(o.status.code(), Some(1));
    let t = text(&o);
    assert!(
        t.contains(
            "FAILED: event seq 2 (COMMAND) field `result`: sealed \"ACCEPTEE\", found \"ACCEPTED\""
        ),
        "{t}"
    );
    let o = sfr(&["verify", bad.to_str().unwrap(), "--pubkey", &public]);
    assert_eq!(o.status.code(), Some(1));
    // The record declares an evaluation key: the warning comes first even when it fails.
    assert!(
        String::from_utf8_lossy(&o.stdout)
            .starts_with("EVALUATION KEY: not for operational use\nFAILED: Merkle root mismatch"),
        "{}",
        text(&o)
    );
    let j = sfr(&[
        "verify",
        bad.to_str().unwrap(),
        "--pubkey",
        &public,
        "--json",
    ]);
    assert!(
        String::from_utf8_lossy(&j.stdout).contains("\"key_custody\": \"file-evaluation\""),
        "{}",
        text(&j)
    );
    assert!(
        text(&o).contains("FAILED: Merkle root mismatch"),
        "{}",
        text(&o)
    );

    // 2. One parameter value in the log: names the parameter with sealed and found values.
    let mut ulg = std::fs::read(root().join(log)).unwrap();
    let needle = b"float MPC_XY_VEL_MAX";
    let p = ulg.windows(needle.len()).position(|w| w == needle).unwrap() + needle.len();
    ulg[p..p + 4].copy_from_slice(&9.5f32.to_le_bytes());
    let edited = dir.join("param.ulg");
    std::fs::write(&edited, &ulg).unwrap();
    let o = sfr(&[
        "verify",
        &record,
        "--pubkey",
        &public,
        "--ulog",
        edited.to_str().unwrap(),
    ]);
    assert_eq!(o.status.code(), Some(1));
    assert!(
        text(&o).contains("FAILED: parameter MPC_XY_VEL_MAX: sealed f32:12, found f32:9.5"),
        "{}",
        text(&o)
    );

    // 3. One byte elsewhere (a data field of a topic sfr does not read): log digest mismatch.
    let mut ulg = std::fs::read(root().join(log)).unwrap();
    let (off, len, topic) = data_records(&ulg)
        .into_iter()
        .find(|(_, len, t)| t == "sensor_combined" && *len > 12)
        .unwrap();
    ulg[off + len - 1] ^= 0x01;
    let edited = dir.join("elsewhere.ulg");
    std::fs::write(&edited, &ulg).unwrap();
    let o = sfr(&[
        "verify",
        &record,
        "--pubkey",
        &public,
        "--ulog",
        edited.to_str().unwrap(),
    ]);
    assert_eq!(o.status.code(), Some(1), "{topic}");
    assert!(
        text(&o).contains("FAILED: log digest mismatch: sha256 sealed"),
        "{}",
        text(&o)
    );
}

#[test]
fn unknown_schema_version_wrong_key_and_evaluation_custody_are_refused() {
    let dir = scratch();
    let (key, public) = keygen(&dir.join("k"));
    let (other_key, other_pub) = keygen(&dir.join("k2"));
    let _ = other_key;
    let (record, _) = seal(
        "testdata/sitl/v1.17.0/mc_flight_2.ulg",
        "testdata/baselines/v1.17.0_mc_flight_2.params",
        &key,
        &dir,
    );
    let rec = std::fs::read_to_string(&record).unwrap();
    let v2 = rec.replacen("\"schema_version\":1", "\"schema_version\":2", 1);
    let bad = dir.join("v2.sfr");
    std::fs::write(&bad, v2).unwrap();
    let o = sfr(&["verify", bad.to_str().unwrap(), "--pubkey", &public]);
    assert_eq!(o.status.code(), Some(1));
    assert!(
        text(&o).contains("unknown schema_version 2; this verifier knows only 1"),
        "{}",
        text(&o)
    );

    let o = sfr(&["verify", &record, "--pubkey", &other_pub]);
    assert_eq!(o.status.code(), Some(1));
    assert!(
        text(&o).contains("not by the given public key"),
        "{}",
        text(&o)
    );

    let o = sfr(&[
        "verify",
        &record,
        "--pubkey",
        &public,
        "--require-hardware-key",
    ]);
    assert_eq!(o.status.code(), Some(1));
    assert!(text(&o).contains("evaluation key"), "{}", text(&o));

    let o = sfr(&[
        "verify",
        &record,
        "--pubkey",
        &public,
        "--trust-anchor",
        "ca.pem",
    ]);
    assert_eq!(o.status.code(), Some(4));
}

#[test]
fn seal_key_sources_and_seal_time_are_checked() {
    let dir = scratch();
    let (key, _) = keygen(&dir.join("k"));
    let base = [
        "seal",
        "testdata/sitl/v1.17.0/mc_flight_1.ulg",
        "--rules",
        RULES,
        "--baseline",
        "testdata/baselines/v1.17.0_mc_flight_1.params",
    ];
    let with = |extra: &[&str]| {
        let mut a: Vec<&str> = base.to_vec();
        a.extend_from_slice(extra);
        sfr(&a)
    };
    let o = with(&["--key", &key]);
    assert_eq!(o.status.code(), Some(4));
    assert!(text(&o).contains("evaluation only"), "{}", text(&o));
    let o = with(&["--key-uri", "pkcs11:token=x"]);
    assert_eq!(o.status.code(), Some(4));
    let out = dir.join("t");
    let o = with(&[
        "--key",
        &key,
        "--evaluation-only",
        "--out",
        out.to_str().unwrap(),
        "--seal-time",
        "2026-10-18 15:00",
    ]);
    assert_eq!(o.status.code(), Some(4));
    assert!(text(&o).contains("RFC 3339"), "{}", text(&o));
    let o = with(&[
        "--key",
        &key,
        "--evaluation-only",
        "--out",
        out.to_str().unwrap(),
        "--seal-time",
        "2026-10-18T17:00:00+02:00",
    ]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let rec = std::fs::read_to_string(out.join("mc_flight_1.sfr")).unwrap();
    assert!(rec.contains("\"time_utc\":\"2026-10-18T15:00:00Z\""));
    assert!(rec.contains("\"key_custody\":\"file-evaluation\""));
}
