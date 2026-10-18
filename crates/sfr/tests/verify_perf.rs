//! SPEC B1.10 Performance: standalone verify under 10 ms for a record of 10,000 events.
//!
//! Run in release, where the gate applies:
//! `cargo test --release -p sfr --test verify_perf -- --ignored --nocapture`
// A panicking test is a failing test, so tests may use expect and unwrap.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::print_stdout)]

use sfr_core::crypto::rustcrypto::RustCrypto;
use sfr_core::keys::parse_public_key_pem;
use sfr_core::verify::verify;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

fn rec(out: &mut Vec<u8>, ty: u8, body: &[u8]) {
    out.extend_from_slice(&(body.len() as u16).to_le_bytes());
    out.push(ty);
    out.extend_from_slice(body);
}

/// A ULog with one vehicle_status row and `n` warning messages: `n` LOG_MESSAGE events.
fn synthetic_log(n: usize) -> Vec<u8> {
    let mut b = b"ULog\x01\x12\x35\x01".to_vec();
    b.extend_from_slice(&0u64.to_le_bytes());
    rec(&mut b, b'B', &[0u8; 40]);
    rec(
        &mut b,
        b'F',
        b"vehicle_status:uint64_t timestamp;uint8_t arming_state;uint8_t nav_state;",
    );
    rec(&mut b, b'A', b"\x00\x00\x00vehicle_status");
    let mut row = 0u16.to_le_bytes().to_vec();
    row.extend_from_slice(&1u64.to_le_bytes());
    row.extend_from_slice(&[1, 4]);
    rec(&mut b, b'D', &row);
    for i in 0..n {
        let mut l = vec![b'4'];
        l.extend_from_slice(&(1000 + i as u64).to_le_bytes());
        l.extend_from_slice(format!("[perf] synthetic warning number {i}").as_bytes());
        rec(&mut b, b'L', &l);
    }
    b
}

#[test]
#[ignore = "timing gate; run in release with --ignored"]
fn standalone_verify_of_10000_events_is_under_10_ms() {
    let dir = std::env::temp_dir().join(format!("sfr-perf-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let log = dir.join("perf.ulg");
    // 9,999 messages plus the first NAV_STATE_CHANGE: 10,000 events.
    std::fs::write(&log, synthetic_log(9_999)).unwrap();
    let baseline = dir.join("perf.params");
    std::fs::write(&baseline, "# Firmware: 1.17.0\n").unwrap();
    let bin = env!("CARGO_BIN_EXE_sfr");
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let k = Command::new(bin)
        .args(["keygen", "--evaluation-only", "--out"])
        .arg(dir.join("k"))
        .output()
        .unwrap();
    assert!(k.status.success());
    let s = Command::new(bin)
        .current_dir(&root)
        .args(["seal"])
        .arg(&log)
        .args(["--rules", "examples/rules.default.toml", "--baseline"])
        .arg(&baseline)
        .args(["--key"])
        .arg(dir.join("k/sfr.key"))
        .args([
            "--evaluation-only",
            "--seal-time",
            "2026-10-18T15:00:00Z",
            "--out",
        ])
        .arg(&dir)
        .output()
        .unwrap();
    assert!(
        dir.join("perf.sfr").exists(),
        "{}",
        String::from_utf8_lossy(&s.stderr)
    );
    let record = std::fs::read(dir.join("perf.sfr")).unwrap();
    let pk =
        parse_public_key_pem(&std::fs::read_to_string(dir.join("k/sfr.pub")).unwrap()).unwrap();
    let crypto = RustCrypto;
    // SPEC B1.10: the gate is in-process verification, the median of RUNS runs.
    const RUNS: usize = 101;
    let mut times: Vec<Duration> = Vec::new();
    for _ in 0..RUNS {
        let t0 = Instant::now();
        let v = verify(&record, None, &crypto, &pk, false).unwrap();
        times.push(t0.elapsed());
        assert_eq!(v.events, 10_000);
    }
    times.sort();
    let median = times[times.len() / 2];
    // Reported beside it, not gated: the whole `sfr verify` command, which adds process start
    // and reading the record and the public key.
    let mut cli: Vec<Duration> = Vec::new();
    for _ in 0..RUNS {
        let t0 = Instant::now();
        let o = Command::new(bin)
            .arg("verify")
            .arg(dir.join("perf.sfr"))
            .arg("--pubkey")
            .arg(dir.join("k/sfr.pub"))
            .output()
            .unwrap();
        cli.push(t0.elapsed());
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stdout));
    }
    cli.sort();
    let ms = |d: Duration| format!("{:.2} ms", d.as_secs_f64() * 1000.0);
    println!(
        "perf: in-process verify (gated, under 10 ms): 10,000 events, {} byte record, median {}, min {}, max {}, {} runs",
        record.len(),
        ms(median),
        ms(times[0]),
        ms(times[times.len() - 1]),
        times.len()
    );
    println!(
        "perf: end-to-end sfr verify (not gated): same record, median {}, min {}, max {}, {} runs",
        ms(cli[cli.len() / 2]),
        ms(cli[0]),
        ms(cli[cli.len() - 1]),
        cli.len()
    );
    if cfg!(debug_assertions) {
        println!("debug build: the 10 ms gate applies to release builds only");
    } else {
        assert!(
            median < Duration::from_millis(10),
            "median {median:?} is not under 10 ms"
        );
    }
}
