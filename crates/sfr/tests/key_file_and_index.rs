//! Two small things a reader could take the wrong way (the key-file mode and the BLAKE3 index):
//! `seal` warns about a key file other users can read, and the BLAKE3 digest of a log is an index
//! that comes second, after the SHA-256 the seal rests on.
// A panicking test is a failing test, so tests may use expect and unwrap.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

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
        "sfr-keyfile-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn keygen(dir: &Path) -> (PathBuf, PathBuf) {
    let o = sfr(&[
        "keygen",
        "--evaluation-only",
        "--out",
        dir.to_str().unwrap(),
    ]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    (dir.join("sfr.key"), dir.join("sfr.pub"))
}

fn seal(key: &Path, out: &Path) -> Output {
    sfr(&[
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
        out.to_str().unwrap(),
    ])
}

#[cfg(unix)]
#[test]
fn a_key_file_that_group_or_other_can_access_is_warned_about() {
    use std::os::unix::fs::PermissionsExt;
    let dir = scratch();
    let (key, _) = keygen(&dir.join("k"));
    let set =
        |mode: u32| std::fs::set_permissions(&key, std::fs::Permissions::from_mode(mode)).unwrap();

    // As keygen writes it (0600) there is nothing to say; 0400 is stricter and has nothing to say.
    for (i, mode) in [0o600, 0o400].into_iter().enumerate() {
        set(mode);
        let o = seal(&key, &dir.join(format!("ok{i}")));
        assert_eq!(o.status.code(), Some(0), "{}", text(&o));
        assert!(
            !text(&o).contains("key file"),
            "mode {mode:o}: {}",
            text(&o)
        );
    }
    // Any access for group or other is a warning, naming the file and its mode. It still seals:
    // the warning is for the person to act on, and a refusal would not make the key private again.
    for (i, mode) in [0o644, 0o640, 0o604, 0o666, 0o755].into_iter().enumerate() {
        set(mode);
        let o = seal(&key, &dir.join(format!("warn{i}")));
        assert_eq!(o.status.code(), Some(0), "{}", text(&o));
        let err = String::from_utf8_lossy(&o.stderr).into_owned();
        assert!(
            err.contains("sfr: warning: key file")
                && err.contains(&format!("has mode {mode:04o}"))
                && err.contains("chmod 600"),
            "mode {mode:o}: {err}"
        );
        assert!(dir.join(format!("warn{i}/custom_detection.sfr")).exists());
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn blake3_is_an_index_the_sha256_is_checked_first_and_the_output_says_so() {
    let dir = scratch();
    let (key, public) = keygen(&dir.join("k"));
    let out = dir.join("out");
    let o = seal(&key, &out);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    // Where sfr prints the BLAKE3 digest it says what it is; the report does too.
    assert!(
        text(&o).contains("(index only, adds no security)"),
        "{}",
        text(&o)
    );
    let report = std::fs::read_to_string(out.join("custom_detection.sfr.md")).unwrap();
    assert!(
        report.contains("BLAKE3 (index only, adds no security)"),
        "{report}"
    );
    assert!(!report.contains("supplementary"), "{report}");

    // The log changes by one byte: the failure names SHA-256, the digest the seal rests on, and
    // not the BLAKE3 index (both differ, SHA-256 is checked first).
    let mut log = std::fs::read(root().join(LOG)).unwrap();
    let last = log.len() - 1;
    log[last] ^= 1;
    let changed = dir.join("changed.ulg");
    std::fs::write(&changed, &log).unwrap();
    let o = sfr(&[
        "verify",
        out.join("custom_detection.sfr").to_str().unwrap(),
        "--pubkey",
        public.to_str().unwrap(),
        "--allow-evaluation-key",
        "--ulog",
        changed.to_str().unwrap(),
    ]);
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));
    assert!(
        text(&o).contains("log digest mismatch: sha256 sealed"),
        "{}",
        text(&o)
    );
    assert!(!text(&o).contains("blake3 sealed"), "{}", text(&o));

    // A record whose BLAKE3 index is wrong but whose SHA-256 is right (a sealer's mistake, or a
    // key holder's choice) is still refused, as an inconsistent record: the index is checked, but
    // it is the SHA-256 that says which log this is.
    let record = std::fs::read(out.join("custom_detection.sfr")).unwrap();
    let wrong = forge::resign(&record, &forge::key_from_file(&key), |r| {
        let Some(sfr_core::json::Value::Object(log)) = r.get_mut("log") else {
            panic!("log is an object");
        };
        log.insert("blake3".into(), sfr_core::json::Value::str("0".repeat(64)));
    });
    let path = dir.join("wrong_index.sfr");
    std::fs::write(&path, wrong).unwrap();
    let o = sfr(&[
        "verify",
        path.to_str().unwrap(),
        "--pubkey",
        public.to_str().unwrap(),
        "--allow-evaluation-key",
        "--no-report",
        "--ulog",
        root().join(LOG).to_str().unwrap(),
    ]);
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));
    assert!(
        text(&o).contains("log digest mismatch: blake3 sealed"),
        "{}",
        text(&o)
    );
    std::fs::remove_dir_all(dir).unwrap();
}
