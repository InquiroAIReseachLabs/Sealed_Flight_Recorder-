//! Property tests of the ULog reader and of the ingest path (SPEC B1.4 "Input limits", B1.5 "What
//! is extracted from the log"; `docs/LIMITS.md`; `docs/RECORD_FORMAT.md` "Sealed topic digests";
//! `crates/sfr-core/src/ulog.rs`, `ingest.rs`).
//!
//! Every expectation is computed in this file, not by the code under test: SHA-256 through the
//! `sha2` crate and BLAKE3 through `blake3::hash` (the ingestor streams both through its own
//! wrapper), a record scanner that knows only the framing (a 3-byte header of a little-endian
//! `u16` size and a type byte, then the payload), and a model of a log (formats with scalar,
//! array, nested and padding fields, subscriptions, data rows, parameters, information
//! messages, logged strings, dropouts) whose writer is checked byte for byte against the logs
//! that `scripts/testdata/make_synthetic_logs.py` writes (`testdata/synthetic/`). The
//! properties:
//!
//! 1. No panic, exact accounting. For arbitrary bytes, for a valid header followed by arbitrary
//!    records, and for a structured log with local damage (sizes that lie, wrong types, flipped
//!    bytes, dropped, repeated and swapped records, a cut), `Px4Ingestor` returns `Ok` or `Err`;
//!    on `Ok` the byte count is the input length, both digests are those of the whole input, and
//!    the counts of records, unknown records, orphan data records, data records per topic,
//!    parameters, logged strings and dropouts are those of the scanner.
//! 2. Truncation (SPEC B1.5, "A log that ends in the middle of a record"; B1.4 exit 3): for real
//!    logs cut anywhere, a cut inside the header, or before the first data record, is refused; any
//!    other cut is read up to the unfinished record, which is reported with its offset and
//!    trailing bytes, and a cut at a record boundary is a log that is not truncated.
//! 3. Determinism: the same bytes give equal results (the `Ingested` value and the
//!    `seal --dry-run` document), whatever the sizes of the reads that deliver them, with
//!    interrupted reads retried; a read error is an `Io` error, never a panic or a success.
//! 4. Round trip: a log written from the model reads back as the model says (the reader's calls
//!    one by one, the flattened layouts, the parameters at log start and in flight, the
//!    information values, the counts, the vehicle status rows, the sealed topic digests).
//! 5. Limits (docs/LIMITS.md): input over a limit is refused with an error that names it, input
//!    at the limit is read, and the call returns. Format nesting, one flattened format, name
//!    lengths, subscriptions, flattened fields across subscriptions, flattened name bytes,
//!    parameter names and parameters at log start. The 1,000,000 field definitions are not
//!    reached here: a million definitions cost seconds in a debug build, and the unit test in
//!    `ulog.rs` holds that limit exactly.
//! 6. Appended data (SPEC B1.5): a record that crosses an announced offset is dropped and reading
//!    resumes at the offset; a file that ends before the offset is refused.
//!
//! The default run is deterministic and cheap (a fixed seed, 64 cases per property). A deep run:
//! `PROPTEST_CASES=100000 PROPTEST_RNG_SEED=1 cargo test -p sfr-core --test prop_ulog`.
// A panicking test is a failing test, so tests may use expect, unwrap and panic.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read};
use std::rc::Rc;

use proptest::collection::vec;
use proptest::prelude::*;
use proptest::test_runner::RngSeed;
use sfr_core::crypto::rustcrypto::RustCrypto;
use sfr_core::evaluate::evaluate;
use sfr_core::ingest::{FlightLogIngestor, IngestError, Ingested, Px4Ingestor};
use sfr_core::json::canonical;
use sfr_core::params::{Baseline, parse_baseline};
use sfr_core::record::dry_run_json;
use sfr_core::rules::{Rules, parse_rules};
use sfr_core::ulog::{self, Header, Layout, ParamValue, Section, UlogError, Visitor};
use sha2::{Digest, Sha256};

/// The seed of a default run: any constant makes the run repeat exactly.
const SEED: u64 = 0x756c_6f67_5f70_7270;

/// The configuration of every property: `ProptestConfig::default()` reads `PROPTEST_CASES` and
/// `PROPTEST_RNG_SEED`; when they are unset the run uses a fixed seed and 64 cases. No failure
/// file is written next to the sources: the fixed seed already repeats a failure.
fn config() -> ProptestConfig {
    let mut config = ProptestConfig::default();
    if std::env::var_os("PROPTEST_RNG_SEED").is_none() {
        config.rng_seed = RngSeed::Fixed(SEED);
    }
    if std::env::var_os("PROPTEST_CASES").is_none() {
        config.cases = 64;
    }
    config.failure_persistence = None;
    config
}

fn fail<T>(message: String) -> Result<T, TestCaseError> {
    Err(TestCaseError::fail(message))
}

// ---------------------------------------------------------------------------------------------
// Independent references: digests, the file format's framing, a writer.
// ---------------------------------------------------------------------------------------------

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn blake3_digest(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

/// The file magic, as `scripts/testdata/make_synthetic_logs.py` `MAGIC` writes it.
const MAGIC: [u8; 7] = *b"ULog\x01\x12\x35";

/// The record types the reader knows (`ulog.rs` `read`, the arms of the match on the type byte).
const KNOWN_TYPES: &[u8] = b"BFIMPQARDLCSO";

/// A parameter value as the model holds it: an int32, or a float32 by its bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Pv {
    I(i32),
    F(u32),
}

impl Pv {
    /// Every NaN is one value (the reader's `same_as` and its text treat all NaNs alike, and a
    /// 32-bit target may quiet a signalling NaN it moves through a float register).
    fn norm(self) -> Pv {
        match self {
            Pv::F(b) if f32::from_bits(b).is_nan() => Pv::F(0x7fc0_0000),
            other => other,
        }
    }

    fn of(v: ParamValue) -> Pv {
        match v {
            ParamValue::I32(i) => Pv::I(i),
            ParamValue::F32(f) => Pv::F(f.to_bits()).norm(),
        }
    }
}

/// The 16-byte file header: magic, version byte, start timestamp.
fn file_header(version: u8, ts: u64) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    out.push(version);
    out.extend_from_slice(&ts.to_le_bytes());
    out
}

/// One record: 3-byte header (size as a little-endian `u16`, then the type) and the body.
fn rec(ty: u8, body: &[u8]) -> Vec<u8> {
    let size = u16::try_from(body.len()).expect("a record body fits the 16-bit size");
    let mut out = size.to_le_bytes().to_vec();
    out.push(ty);
    out.extend_from_slice(body);
    out
}

/// 'B': 8 bytes of compatibility flags, 8 of incompatible flags (the first byte is `incompat0`)
/// and three 8-byte appended-data offsets (`ulog.rs` `read`, the `b'B'` arm; the Python writer
/// writes 16 zero bytes and three zero offsets).
fn flags_rec(incompat0: u8, offsets: [u64; 3]) -> Vec<u8> {
    let mut body = vec![0u8; 8];
    body.push(incompat0);
    body.extend_from_slice(&[0u8; 7]);
    for o in offsets {
        body.extend_from_slice(&o.to_le_bytes());
    }
    rec(b'B', &body)
}

/// 'I': a key length byte, the key (`<type> <name>`), then the value.
fn info_rec(key: &str, value: &[u8]) -> Vec<u8> {
    let mut body = vec![u8::try_from(key.len()).expect("key length")];
    body.extend_from_slice(key.as_bytes());
    body.extend_from_slice(value);
    rec(b'I', &body)
}

/// 'M': a continuation flag, a key length byte, the key, then the value (read and skipped).
fn multi_info_rec(continued: u8, key: &str, value: &[u8]) -> Vec<u8> {
    let mut body = vec![continued, u8::try_from(key.len()).expect("key length")];
    body.extend_from_slice(key.as_bytes());
    body.extend_from_slice(value);
    rec(b'M', &body)
}

/// 'Q': the default types byte, a key length byte, the key (read and skipped).
fn default_param_rec(types: u8, key: &str) -> Vec<u8> {
    let mut body = vec![types, u8::try_from(key.len()).expect("key length")];
    body.extend_from_slice(key.as_bytes());
    rec(b'Q', &body)
}

/// 'P': a key length byte, the key (`int32_t NAME` or `float NAME`), then 4 value bytes.
fn param_rec(name: &str, v: Pv) -> Vec<u8> {
    let (ty, raw) = match v {
        Pv::I(i) => ("int32_t", i.to_le_bytes()),
        Pv::F(b) => ("float", b.to_le_bytes()),
    };
    let key = format!("{ty} {name}");
    let mut body = vec![u8::try_from(key.len()).expect("key length")];
    body.extend_from_slice(key.as_bytes());
    body.extend_from_slice(&raw);
    rec(b'P', &body)
}

/// 'A': multi id, message id (little endian), topic name.
fn sub_rec(multi: u8, id: u16, topic: &str) -> Vec<u8> {
    let mut body = vec![multi];
    body.extend_from_slice(&id.to_le_bytes());
    body.extend_from_slice(topic.as_bytes());
    rec(b'A', &body)
}

/// 'D': message id, then the payload.
fn data_rec(id: u16, payload: &[u8]) -> Vec<u8> {
    let mut body = id.to_le_bytes().to_vec();
    body.extend_from_slice(payload);
    rec(b'D', &body)
}

/// 'L': level byte, timestamp, text.
fn log_rec(level: u8, ts: u64, text: &[u8]) -> Vec<u8> {
    let mut body = vec![level];
    body.extend_from_slice(&ts.to_le_bytes());
    body.extend_from_slice(text);
    rec(b'L', &body)
}

/// 'C': level byte, tag, timestamp, text.
fn tagged_rec(level: u8, tag: u16, ts: u64, text: &[u8]) -> Vec<u8> {
    let mut body = vec![level];
    body.extend_from_slice(&tag.to_le_bytes());
    body.extend_from_slice(&ts.to_le_bytes());
    body.extend_from_slice(text);
    rec(b'C', &body)
}

/// 'O': the dropout duration in milliseconds.
fn dropout_rec(ms: u16) -> Vec<u8> {
    rec(b'O', &ms.to_le_bytes())
}

/// Where the records of a byte string are, by framing alone: `docs/RECORD_FORMAT.md` ("Each record
/// is a 3-byte header (`msg_size` as uint16 little-endian, then `msg_type`) and `msg_size` bytes of
/// payload") and SPEC B1.5 (an unfinished record is not read).
#[derive(Debug)]
struct Frame {
    start: usize,
    size: usize,
    ty: u8,
}

impl Frame {
    fn end(&self) -> usize {
        self.start + 3 + self.size
    }
}

/// The complete frames after the 16-byte header, and where an unfinished one starts (if the
/// bytes end inside a header or a payload).
#[derive(Debug)]
struct Frames {
    frames: Vec<Frame>,
    unfinished: Option<usize>,
}

fn u16_at(b: &[u8], at: usize) -> usize {
    usize::from(u16::from_le_bytes([b[at], b[at + 1]]))
}

fn scan(bytes: &[u8]) -> Frames {
    let mut frames = Vec::new();
    let mut at = 16usize;
    let mut unfinished = None;
    while at < bytes.len() {
        if at + 3 > bytes.len() {
            unfinished = Some(at);
            break;
        }
        let size = u16_at(bytes, at);
        let ty = bytes[at + 2];
        if at + 3 + size > bytes.len() {
            unfinished = Some(at);
            break;
        }
        frames.push(Frame {
            start: at,
            size,
            ty,
        });
        at += 3 + size;
    }
    Frames { frames, unfinished }
}

fn body<'a>(bytes: &'a [u8], f: &Frame) -> &'a [u8] {
    &bytes[f.start + 3..f.end()]
}

/// A 'P' frame body: key length, `<type> <name>`, 4 value bytes. `None` when it is not one the
/// reader accepts.
fn parse_param(b: &[u8]) -> Option<(String, Pv)> {
    let klen = usize::from(*b.first()?);
    let key = std::str::from_utf8(b.get(1..1 + klen)?).ok()?;
    let (ty, name) = key.split_once(' ')?;
    let raw: [u8; 4] = b.get(1 + klen..1 + klen + 4)?.try_into().ok()?;
    let v = match ty {
        "int32_t" => Pv::I(i32::from_le_bytes(raw)),
        "float" => Pv::F(u32::from_le_bytes(raw)).norm(),
        _ => return None,
    };
    Some((name.to_string(), v))
}

/// What the scanner says a log that the reader accepted holds.
#[derive(Debug, Default, PartialEq)]
struct Counts {
    /// All complete frames.
    records: u64,
    /// Frames of a type the reader does not know.
    unknown: u64,
    /// 'D' frames of a message id nobody subscribed.
    orphans: u64,
    /// 'D' frames of a subscribed id, by topic.
    topic_rows: BTreeMap<String, u64>,
    /// Parameters before the first 'A', last value of each name.
    config: BTreeMap<String, Pv>,
    /// 'P' frames after the first 'A', in order.
    param_records: Vec<(String, Pv)>,
    /// 'P' frames in all.
    params: u64,
    /// 'L' and 'C' frames at levels `'0'` to `'4'`, in order (level, text offset not needed).
    kept_logs: Vec<u8>,
    /// 'L' and 'C' frames in all.
    logs: u64,
    dropouts: u64,
}

/// Counts of a log with no appended data, from framing alone. Only meaningful for bytes the
/// reader accepted, whose frames are therefore well formed where the reader looks inside them.
fn count(bytes: &[u8]) -> Counts {
    let f = scan(bytes);
    let mut c = Counts::default();
    let mut subs: BTreeMap<u16, String> = BTreeMap::new();
    let mut in_defs = true;
    for fr in &f.frames {
        c.records += 1;
        let b = body(bytes, fr);
        match fr.ty {
            b'A' => {
                in_defs = false;
                if let (Some(id), Some(name)) = (
                    b.get(1..3).map(|s| u16::from_le_bytes([s[0], s[1]])),
                    b.get(3..).and_then(|s| std::str::from_utf8(s).ok()),
                ) {
                    subs.insert(id, name.to_string());
                }
            }
            b'D' => {
                let id = b.get(..2).map(|s| u16::from_le_bytes([s[0], s[1]]));
                match id.and_then(|id| subs.get(&id)) {
                    Some(topic) => *c.topic_rows.entry(topic.clone()).or_insert(0) += 1,
                    None => c.orphans += 1,
                }
            }
            b'P' => {
                c.params += 1;
                if let Some((name, v)) = parse_param(b) {
                    if in_defs {
                        c.config.insert(name, v);
                    } else {
                        c.param_records.push((name, v));
                    }
                }
            }
            b'L' | b'C' => {
                c.logs += 1;
                if let Some(&level) = b.first()
                    && (b'0'..=b'4').contains(&level)
                {
                    c.kept_logs.push(level - b'0');
                }
            }
            b'O' => c.dropouts += 1,
            t if !KNOWN_TYPES.contains(&t) => c.unknown += 1,
            _ => {}
        }
    }
    c
}

/// Whether the first record is a flag bits record announcing appended data (its incompatible
/// flag bit 0, byte 8 of the body).
fn announces_appended(bytes: &[u8]) -> bool {
    let f = scan(bytes);
    f.frames
        .first()
        .filter(|fr| fr.ty == b'B')
        .and_then(|fr| body(bytes, fr).get(8))
        .is_some_and(|b| b & 1 != 0)
}

/// Ingests `bytes` with the sealed topics `sealed`.
fn ingest_with(bytes: &[u8], sealed: &[String]) -> Result<Ingested, IngestError> {
    let mut input: &[u8] = bytes;
    Px4Ingestor.ingest_sealing("prop.ulg", &mut input, &RustCrypto, sealed)
}

fn ingest(bytes: &[u8]) -> Result<Ingested, IngestError> {
    ingest_with(bytes, &[])
}

// ---------------------------------------------------------------------------------------------
// The writer is held to the Python writer's bytes.
// ---------------------------------------------------------------------------------------------

/// `scripts/testdata/make_synthetic_logs.py` `VS` and `FS`.
const PY_VS: &str = "vehicle_status:uint64_t timestamp;uint8_t arming_state;uint8_t nav_state;bool failsafe;\
    bool is_vtol;bool in_transition_mode;bool in_transition_to_fw;uint8_t vehicle_type;\
    uint8_t system_type;uint8_t latest_arming_reason;uint8_t latest_disarming_reason;";
const PY_FS: &str = "failsafe_flags:uint64_t timestamp;uint32_t mode_req_angular_velocity;\
    uint32_t mode_req_attitude;uint32_t mode_req_local_alt;uint32_t mode_req_local_position;\
    uint32_t mode_req_local_position_relaxed;uint32_t mode_req_global_position;\
    uint32_t mode_req_global_position_relaxed;uint32_t mode_req_mission;\
    uint32_t mode_req_offboard_signal;uint32_t mode_req_home_position;\
    uint32_t mode_req_wind_and_flight_time_compliance;uint32_t mode_req_prevent_arming;\
    uint32_t mode_req_manual_control;uint32_t mode_req_other;bool angular_velocity_invalid;\
    bool attitude_invalid;bool local_altitude_invalid;bool local_position_invalid;\
    bool local_position_invalid_relaxed;bool local_velocity_invalid;\
    bool global_position_invalid;bool global_position_invalid_relaxed;\
    bool auto_mission_missing;bool offboard_control_signal_lost;bool home_position_invalid;\
    bool manual_control_signal_lost;bool gcs_connection_lost;uint8_t battery_warning;\
    bool battery_low_remaining_time;bool battery_unhealthy;bool geofence_breached;\
    bool mission_failure;bool vtol_fixed_wing_system_failure;bool wind_limit_exceeded;\
    bool flight_time_limit_exceeded;bool position_accuracy_low;bool navigator_failure;\
    bool fd_critical_failure;bool fd_esc_arming_failure;bool fd_imbalanced_prop;\
    bool fd_motor_failure;";
/// Bytes of one `failsafe_flags` row (every field 0 but the timestamp).
const PY_FS_LEN: usize = 91;
const PY_BOX: &str = "detection_box:float x;float y;float w;float h;";
const PY_DET: &str =
    "custom_detection:uint64_t timestamp;uint32_t class_id;float confidence;detection_box box;";
const PY_GIT: &[u8] = b"d6f12ad1c4f70ad3230afd7d86e971421e02fef4";

/// The head every Python log shares: header, flag bits, `ver_sw`, `ver_sw_release` 0x011100FF.
fn py_head(version: u8) -> Vec<u8> {
    let mut out = file_header(version, 0);
    out.extend(flags_rec(0, [0; 3]));
    out.extend(info_rec("char[40] ver_sw", PY_GIT));
    out.extend(info_rec(
        "uint32_t ver_sw_release",
        &0x0111_00FFu32.to_le_bytes(),
    ));
    out
}

/// `make_synthetic_logs.py` `vs()` and `mc_vs()`: the `vehicle_status` payload.
#[allow(clippy::too_many_arguments)]
fn py_vs(
    ts: u64,
    arming: u8,
    failsafe: u8,
    is_vtol: u8,
    in_tr: u8,
    to_fw: u8,
    vtype: u8,
    system: u8,
) -> Vec<u8> {
    let mut p = ts.to_le_bytes().to_vec();
    p.extend_from_slice(&[
        arming, 4, failsafe, is_vtol, in_tr, to_fw, vtype, system, 3, 6,
    ]);
    p
}

fn py_mc_flight(version: u8) -> Vec<u8> {
    let mut out = py_head(version);
    out.extend(rec(b'F', PY_VS.as_bytes()));
    out.extend(rec(b'F', PY_FS.as_bytes()));
    out.extend(param_rec("SYS_AUTOSTART", Pv::I(10040)));
    out.extend(param_rec("COM_DISARM_LAND", Pv::I(2)));
    out.extend(sub_rec(0, 0, "vehicle_status"));
    out.extend(sub_rec(0, 1, "failsafe_flags"));
    for i in 1..=8u64 {
        let ts = i * 1_000_000;
        let mut fs = ts.to_le_bytes().to_vec();
        fs.resize(PY_FS_LEN, 0);
        out.extend(data_rec(1, &fs));
        let armed = if (2..=6).contains(&i) { 2 } else { 1 };
        out.extend(data_rec(0, &py_vs(ts, armed, 0, 0, 0, 0, 1, 2)));
    }
    out
}

fn py_r4_quadchute_on_disarm() -> Vec<u8> {
    let mut out = py_head(1);
    out.extend(rec(b'F', PY_VS.as_bytes()));
    out.extend(rec(b'F', PY_FS.as_bytes()));
    out.extend(param_rec("SYS_AUTOSTART", Pv::I(10043)));
    out.extend(param_rec("COM_DISARM_LAND", Pv::I(2)));
    out.extend(sub_rec(0, 0, "vehicle_status"));
    out.extend(sub_rec(0, 1, "failsafe_flags"));
    // (armed, in_transition_mode, in_transition_to_fw, fixed wing), the Python `rows`.
    let rows: [(bool, u8, u8, bool); 12] = [
        (false, 0, 0, false),
        (true, 0, 0, false),
        (true, 1, 1, false),
        (true, 0, 0, true),
        (false, 0, 0, false),
        (false, 0, 0, false),
        (true, 0, 0, false),
        (true, 1, 1, false),
        (true, 0, 0, true),
        (false, 0, 0, true),
        (false, 0, 0, false),
        (false, 0, 0, false),
    ];
    for (k, (armed, in_tr, to_fw, fw)) in rows.into_iter().enumerate() {
        let ts = (k as u64 + 1) * 1_000_000;
        let mut fs = ts.to_le_bytes().to_vec();
        fs.resize(PY_FS_LEN, 0);
        out.extend(data_rec(1, &fs));
        // `vs()`: is_vtol 1, vehicle_type 2 (fixed wing) or 1, system_type 22.
        out.extend(data_rec(
            0,
            &py_vs(
                ts,
                if armed { 2 } else { 1 },
                0,
                1,
                in_tr,
                to_fw,
                if fw { 2 } else { 1 },
                22,
            ),
        ));
    }
    out
}

fn py_custom_detection() -> Vec<u8> {
    let mut out = py_head(1);
    out.extend(rec(b'F', PY_VS.as_bytes()));
    out.extend(rec(b'F', PY_FS.as_bytes()));
    out.extend(rec(b'F', PY_BOX.as_bytes()));
    out.extend(rec(b'F', PY_DET.as_bytes()));
    out.extend(param_rec("SYS_AUTOSTART", Pv::I(10040)));
    out.extend(param_rec("COM_DISARM_LAND", Pv::I(2)));
    out.extend(sub_rec(0, 0, "vehicle_status"));
    out.extend(sub_rec(0, 1, "failsafe_flags"));
    out.extend(sub_rec(0, 2, "custom_detection"));
    out.extend(sub_rec(1, 3, "custom_detection"));
    out.extend(sub_rec(2, 4, "custom_detection"));
    let detection = |ts: u64, class: u32, conf: f32, x: f32, y: f32, w: f32, h: f32| {
        let mut p = ts.to_le_bytes().to_vec();
        p.extend_from_slice(&class.to_le_bytes());
        for v in [conf, x, y, w, h] {
            p.extend_from_slice(&v.to_le_bytes());
        }
        p
    };
    for i in 0..8u64 {
        let ts = (i + 1) * 1_000_000;
        let mut fs = ts.to_le_bytes().to_vec();
        fs.resize(PY_FS_LEN, 0);
        out.extend(data_rec(1, &fs));
        let armed = if (2..=6).contains(&(i + 1)) { 2 } else { 1 };
        out.extend(data_rec(0, &py_vs(ts, armed, 0, 0, 0, 0, 1, 2)));
        if (2..=6).contains(&i) {
            let c = 0.5 + i as f64 / 20.0;
            out.extend(data_rec(
                2,
                &detection(
                    ts + 500,
                    7,
                    c as f32,
                    i as f32,
                    (2.0 * i as f64) as f32,
                    1.5,
                    0.25,
                ),
            ));
        }
        if i == 3 || i == 5 {
            out.extend(data_rec(
                3,
                &detection(ts + 700, 9, 0.75, -1.0, i as f32, 0.5, 0.5),
            ));
        }
    }
    out
}

#[test]
fn the_writer_reproduces_the_bytes_of_the_python_synthetic_logs() {
    // Each record writer above is held to the logs `scripts/testdata/make_synthetic_logs.py`
    // wrote into `testdata/synthetic/`: header, flag bits, information messages, formats,
    // parameters, subscriptions and data records (scalar, nested and array payloads).
    let golden: [(&str, Vec<u8>, &[u8]); 4] = [
        (
            "cut_control",
            py_mc_flight(1),
            include_bytes!("../../../testdata/synthetic/cut_control.ulg"),
        ),
        (
            "ulog_version_2",
            py_mc_flight(2),
            include_bytes!("../../../testdata/synthetic/ulog_version_2.ulg"),
        ),
        (
            "r4_quadchute_on_disarm",
            py_r4_quadchute_on_disarm(),
            include_bytes!("../../../testdata/synthetic/r4_quadchute_on_disarm.ulg"),
        ),
        (
            "custom_detection",
            py_custom_detection(),
            include_bytes!("../../../testdata/synthetic/custom_detection.ulg"),
        ),
    ];
    for (name, mine, theirs) in golden {
        assert_eq!(mine.len(), theirs.len(), "{name}: length");
        assert!(mine == theirs, "{name}: bytes differ");
    }
}

// ---------------------------------------------------------------------------------------------
// The model of a log: formats, subscriptions, rows and the rest, with its own flattening.
// ---------------------------------------------------------------------------------------------

/// The scalar types of a ULog format and their sizes in bytes (`ulog.rs` `Scalar::parse` and
/// `Scalar::size`).
const SCALARS: [(&str, usize); 12] = [
    ("int8_t", 1),
    ("uint8_t", 1),
    ("int16_t", 2),
    ("uint16_t", 2),
    ("int32_t", 4),
    ("uint32_t", 4),
    ("int64_t", 8),
    ("uint64_t", 8),
    ("float", 4),
    ("double", 8),
    ("bool", 1),
    ("char", 1),
];
const S_U8: usize = 1;
const S_U64: usize = 7;

#[derive(Clone, Copy, Debug)]
enum FTy {
    Scalar(usize),
    /// A format by its index in the model's list.
    Nested(usize),
}

#[derive(Clone, Debug)]
struct Field {
    ty: FTy,
    arr: Option<u32>,
    name: String,
}

#[derive(Clone, Debug)]
struct Fmt {
    name: String,
    fields: Vec<Field>,
}

impl Fmt {
    /// The payload of the 'F' record: `<name>:<type> <field>;...`, an array type as `type[n]`.
    fn text(&self, all: &[Fmt]) -> String {
        let mut out = format!("{}:", self.name);
        for f in &self.fields {
            let tok = match f.ty {
                FTy::Scalar(s) => SCALARS[s].0.to_string(),
                FTy::Nested(n) => all[n].name.clone(),
            };
            match f.arr {
                Some(n) => out.push_str(&format!("{tok}[{n}] {};", f.name)),
                None => out.push_str(&format!("{tok} {};", f.name)),
            }
        }
        out
    }
}

/// One flattened scalar: the name `pyulog` prints (`esc[1].esc_rpm`), its byte offset in the
/// payload, and its scalar index.
#[derive(Clone, Debug)]
struct RefField {
    name: String,
    offset: usize,
    scalar: usize,
}

#[derive(Clone, Debug)]
struct RefLayout {
    /// Payload size without the trailing top-level padding.
    size: usize,
    /// Payload size with it.
    padded: usize,
    /// The flattened fields without the trailing top-level padding.
    fields: Vec<RefField>,
}

fn walk(
    fmts: &[Fmt],
    fields: &[Field],
    prefix: &str,
    base: usize,
    out: &mut Vec<RefField>,
) -> usize {
    let mut pos = base;
    for f in fields {
        for i in 0..f.arr.unwrap_or(1) {
            let mut name = format!("{prefix}{}", f.name);
            if f.arr.is_some() {
                name.push_str(&format!("[{i}]"));
            }
            match f.ty {
                FTy::Scalar(s) => {
                    out.push(RefField {
                        name,
                        offset: pos,
                        scalar: s,
                    });
                    pos += SCALARS[s].1;
                }
                FTy::Nested(n) => {
                    pos += walk(fmts, &fmts[n].fields, &format!("{name}."), pos, out);
                }
            }
        }
    }
    pos - base
}

/// The flattened layout of format `idx`, from `ulog.rs`'s documentation of it: fields in order,
/// array elements and nested fields named with `[i]` and `.`, no padding between fields, and
/// the trailing top-level `_padding` fields left out of the data record's size (`Layout::size`)
/// but not of the longest record the reader accepts (`Layout::padded_size`).
fn ref_flatten(fmts: &[Fmt], idx: usize) -> RefLayout {
    let all = &fmts[idx].fields;
    let mut keep = all.len();
    while keep > 0 && all[keep - 1].name.starts_with("_padding") {
        keep -= 1;
    }
    let mut fields = Vec::new();
    let size = walk(fmts, &all[..keep], "", 0, &mut fields);
    let padded = if keep == all.len() {
        size
    } else {
        walk(fmts, all, "", 0, &mut Vec::new())
    };
    RefLayout {
        size,
        padded,
        fields,
    }
}

/// The topics of the PX4 messages the ingestor decodes (`ingest.rs`, `Collector::subscription`).
const PX4_TOPICS: [&str; 11] = [
    "vehicle_status",
    "failsafe_flags",
    "vehicle_command",
    "vehicle_command_ack",
    "vehicle_gps_position",
    "sensor_gps",
    "battery_status",
    "estimator_status",
    "estimator_selector_status",
    "vehicle_imu_status",
    "sensor_selection",
];

/// A format with the fields PX4 gives `topic` at the newest supported release
/// (`sfr_core::px4_tables`, a vocabulary here: nothing is checked against it), array elements
/// `x[0]`, `x[1]` merged back into one array field.
fn px4_format(topic: &str) -> Fmt {
    let release = sfr_core::px4_tables::RELEASES.last().expect("a release");
    let msg = sfr_core::px4::msg(release, topic).expect("a PX4 topic");
    let mut fields: Vec<Field> = Vec::new();
    for (name, scalar) in msg.fields {
        let s = SCALARS
            .iter()
            .position(|(n, _)| *n == scalar.name())
            .expect("a scalar");
        match name.strip_suffix(']').and_then(|n| n.split_once('[')) {
            Some((base, "0")) => fields.push(Field {
                ty: FTy::Scalar(s),
                arr: Some(1),
                name: base.to_string(),
            }),
            Some((base, _)) => {
                let last = fields.last_mut().expect("an array started");
                assert_eq!(last.name, base);
                last.arr = last.arr.map(|n| n + 1);
            }
            None => fields.push(Field {
                ty: FTy::Scalar(s),
                arr: None,
                name: (*name).to_string(),
            }),
        }
    }
    Fmt {
        name: topic.to_string(),
        fields,
    }
}

#[derive(Clone, Debug)]
struct SubSpec {
    /// Index into the model's formats of a top-level format.
    fmt: usize,
    multi: u8,
    id: u16,
}

#[derive(Clone, Debug)]
enum Item {
    /// Subscribe `subs[n % len]` unless it is subscribed.
    Sub(usize),
    /// A data record of `subs[n % len]` (an orphan when it is not subscribed yet): `dt` after the
    /// subscription's previous timestamp, a length from the layout's size to its padded size,
    /// bytes cycled from `fill`.
    Row {
        sub: usize,
        dt: u32,
        len_sel: u8,
        fill: Vec<u8>,
    },
    /// A data record of an id nobody subscribed.
    Orphan {
        id: u16,
        fill: Vec<u8>,
    },
    Param(String, Pv),
    Log {
        tag: Option<u16>,
        level: u8,
        ts: u64,
        text: Vec<u8>,
    },
    Dropout(u16),
    Sync,
    Unsub(u16),
    Multi {
        continued: u8,
        key: String,
    },
    DefaultParam {
        types: u8,
        key: String,
    },
    Unknown(u8, Vec<u8>),
}

#[derive(Clone, Debug)]
struct Model {
    version: u8,
    start_ts: u64,
    flags: bool,
    /// `ver_sw`: the text, and how many NUL bytes follow it in the declared `char[n]`.
    git: Option<(String, usize)>,
    release: Option<u32>,
    /// Other information messages: type, name, value.
    infos: Vec<(String, String, Vec<u8>)>,
    /// Which of the six orders the information, format and parameter records come in.
    def_order: u8,
    fmts: Vec<Fmt>,
    /// How many of `fmts` are nested types: the rest are top-level formats, which start with
    /// `uint64_t timestamp`.
    nested: usize,
    params: Vec<(String, Pv)>,
    subs: Vec<SubSpec>,
    /// How many of `subs` are subscribed right after the definitions.
    initial: usize,
    items: Vec<Item>,
}

/// The reader's calls, in order, as the model says they happen.
#[derive(Clone, Debug, PartialEq)]
enum Ev {
    Header(u8, u64),
    Info(String, String, Vec<u8>),
    Format(String, Vec<u8>),
    Param {
        name: String,
        value: Pv,
        defs: bool,
        last: u64,
    },
    Sub {
        id: u16,
        multi: u8,
        topic: String,
        size: usize,
        padded: usize,
        fields: Vec<(String, usize, &'static str)>,
    },
    Data {
        id: u16,
        ts: u64,
        payload: Vec<u8>,
    },
    Log {
        level: u8,
        tag: Option<u16>,
        ts: u64,
        text: Vec<u8>,
    },
    Dropout {
        ms: u16,
        last: u64,
    },
}

/// What `vehicle_status` decoding must give for a payload.
#[derive(Clone, Debug, PartialEq)]
struct VsExp {
    ts: u64,
    index: u64,
    arming_state: Option<u8>,
    nav_state: Option<u8>,
    failsafe: Option<bool>,
    is_vtol: Option<bool>,
    in_transition_mode: Option<bool>,
    in_transition_to_fw: Option<bool>,
    vehicle_type: Option<u8>,
    system_type: Option<u8>,
    latest_arming_reason: Option<u8>,
    latest_disarming_reason: Option<u8>,
}

#[derive(Clone, Debug, PartialEq)]
struct DigestExp {
    topic: String,
    multi: u8,
    format_sha256: [u8; 32],
    count: u64,
    first: Option<u64>,
    last: Option<u64>,
    data_sha256: [u8; 32],
}

#[derive(Debug, Default)]
struct Expect {
    events: Vec<Ev>,
    records: u64,
    unknown: u64,
    orphans: u64,
    config: BTreeMap<String, Pv>,
    /// Name, value, time, index among all 'P' records.
    param_records: Vec<(String, Pv, u64, u64)>,
    /// Level (0 to 4), time, text, index among all 'L' and 'C' records.
    logs: Vec<(u8, u64, Vec<u8>, u64)>,
    /// Milliseconds, time, index among all 'O' records.
    dropouts: Vec<(u16, u64, u64)>,
    topic_rows: BTreeMap<String, u64>,
    rows: u64,
    /// The `vehicle_status` rows by instance (stable), as the ingestor orders them.
    vs: Vec<(u8, VsExp)>,
    sealed: Vec<DigestExp>,
    release: Option<u32>,
    git: Option<String>,
}

struct Acc {
    format_sha256: [u8; 32],
    count: u64,
    first: Option<u64>,
    last: Option<u64>,
    sha: Sha256,
}

struct Rendered {
    header: Vec<u8>,
    records: Vec<Vec<u8>>,
    exp: Expect,
}

impl Rendered {
    fn bytes(&self) -> Vec<u8> {
        let mut out = self.header.clone();
        for r in &self.records {
            out.extend_from_slice(r);
        }
        out
    }
}

/// The value of the unsigned-like scalar `s` (`uint8_t` to `uint64_t`, `bool`, `char`) at
/// `offset`, little endian; `None` for the other scalars or when the payload is too short.
fn dec_unsigned(s: usize, p: &[u8], offset: usize) -> Option<u64> {
    let n = match SCALARS[s].0 {
        "uint8_t" | "bool" | "char" => 1,
        "uint16_t" => 2,
        "uint32_t" => 4,
        "uint64_t" => 8,
        _ => return None,
    };
    let b = p.get(offset..offset + n)?;
    Some(
        b.iter()
            .rev()
            .fold(0u64, |acc, &x| (acc << 8) | u64::from(x)),
    )
}

/// The value of the signed scalar `s` at `offset`, sign extended.
fn dec_signed(s: usize, p: &[u8], offset: usize) -> Option<i64> {
    let n = match SCALARS[s].0 {
        "int8_t" => 1,
        "int16_t" => 2,
        "int32_t" => 4,
        "int64_t" => 8,
        _ => return None,
    };
    let b = p.get(offset..offset + n)?;
    let raw = b
        .iter()
        .rev()
        .fold(0u64, |acc, &x| (acc << 8) | u64::from(x));
    let shift = 64 - 8 * n as u32;
    Some(((raw << shift) as i64) >> shift)
}

fn vs_expected(layout: &RefLayout, p: &[u8], ts: u64, index: u64) -> VsExp {
    let get = |name: &str| layout.fields.iter().find(|f| f.name == name);
    let int = |name: &str| {
        get(name)
            .and_then(|f| dec_unsigned(f.scalar, p, f.offset))
            .and_then(|v| u8::try_from(v).ok())
    };
    let flag = |name: &str| {
        get(name)
            .filter(|f| SCALARS[f.scalar].0 == "bool")
            .and_then(|f| p.get(f.offset))
            .map(|&b| b != 0)
    };
    VsExp {
        ts,
        index,
        arming_state: int("arming_state"),
        nav_state: int("nav_state"),
        failsafe: flag("failsafe"),
        is_vtol: flag("is_vtol"),
        in_transition_mode: flag("in_transition_mode"),
        in_transition_to_fw: flag("in_transition_to_fw"),
        vehicle_type: int("vehicle_type"),
        system_type: int("system_type"),
        latest_arming_reason: int("latest_arming_reason"),
        latest_disarming_reason: int("latest_disarming_reason"),
    }
}

fn cycle(fill: &[u8], len: usize) -> Vec<u8> {
    if fill.is_empty() {
        vec![0; len]
    } else {
        (0..len).map(|i| fill[i % fill.len()]).collect()
    }
}

/// The ULog record sequence of `m`, and what reading it must give. `sealed` names the topics the
/// rules file would seal.
fn render(m: &Model, sealed: &BTreeSet<String>) -> Rendered {
    let mut records: Vec<Vec<u8>> = Vec::new();
    let mut exp = Expect::default();
    let mut ev: Vec<Ev> = vec![Ev::Header(m.version, m.start_ts)];
    if m.flags {
        records.push(flags_rec(0, [0; 3]));
    }

    // The definitions section: three segments, in one of the six orders.
    let mut infos: Vec<(Vec<u8>, Ev)> = Vec::new();
    if let Some((text, nuls)) = &m.git {
        let mut value = text.as_bytes().to_vec();
        value.extend(std::iter::repeat_n(0u8, *nuls));
        let ty = format!("char[{}]", value.len());
        infos.push((
            info_rec(&format!("{ty} ver_sw"), &value),
            Ev::Info(ty, "ver_sw".into(), value),
        ));
        exp.git = Some(text.clone());
    }
    if let Some(r) = m.release {
        infos.push((
            info_rec("uint32_t ver_sw_release", &r.to_le_bytes()),
            Ev::Info(
                "uint32_t".into(),
                "ver_sw_release".into(),
                r.to_le_bytes().to_vec(),
            ),
        ));
        exp.release = Some(r);
    }
    for (ty, name, value) in &m.infos {
        infos.push((
            info_rec(&format!("{ty} {name}"), value),
            Ev::Info(ty.clone(), name.clone(), value.clone()),
        ));
    }
    let mut formats: Vec<(Vec<u8>, Ev)> = Vec::new();
    for f in &m.fmts {
        let text = f.text(&m.fmts);
        formats.push((
            rec(b'F', text.as_bytes()),
            Ev::Format(f.name.clone(), text.into_bytes()),
        ));
    }
    let mut param_index = 0u64;
    let mut params: Vec<(Vec<u8>, Ev)> = Vec::new();
    for (name, v) in &m.params {
        params.push((
            param_rec(name, *v),
            Ev::Param {
                name: name.clone(),
                value: v.norm(),
                defs: true,
                last: m.start_ts,
            },
        ));
        exp.config.insert(name.clone(), v.norm());
        param_index += 1;
    }
    let order: [usize; 3] = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ][usize::from(m.def_order) % 6];
    let mut segments = [infos, formats, params];
    for which in order {
        for (r, e) in std::mem::take(&mut segments[which]) {
            records.push(r);
            ev.push(e);
        }
    }

    // The data section.
    let layouts: Vec<Option<RefLayout>> = (0..m.fmts.len())
        .map(|i| (i >= m.nested).then(|| ref_flatten(&m.fmts, i)))
        .collect();
    let mut subscribed = vec![false; m.subs.len()];
    let mut in_defs = true;
    let mut last_ts = m.start_ts;
    let mut sub_last: BTreeMap<u16, u64> = BTreeMap::new();
    let mut row_index: BTreeMap<(String, u8), u64> = BTreeMap::new();
    let mut accs: BTreeMap<(String, u8), Acc> = BTreeMap::new();
    let (mut log_index, mut dropout_index) = (0u64, 0u64);
    let mut vs: Vec<(u8, VsExp)> = Vec::new();

    let subscribe = |k: usize,
                     records: &mut Vec<Vec<u8>>,
                     ev: &mut Vec<Ev>,
                     subscribed: &mut Vec<bool>,
                     in_defs: &mut bool,
                     accs: &mut BTreeMap<(String, u8), Acc>| {
        if m.subs.is_empty() {
            return;
        }
        let k = k % m.subs.len();
        if subscribed[k] {
            return;
        }
        subscribed[k] = true;
        *in_defs = false;
        let s = &m.subs[k];
        let name = &m.fmts[s.fmt].name;
        let lay = layouts[s.fmt].as_ref().expect("a top-level format");
        records.push(sub_rec(s.multi, s.id, name));
        ev.push(Ev::Sub {
            id: s.id,
            multi: s.multi,
            topic: name.clone(),
            size: lay.size,
            padded: lay.padded,
            fields: lay
                .fields
                .iter()
                .map(|f| (f.name.clone(), f.offset, SCALARS[f.scalar].0))
                .collect(),
        });
        if sealed.contains(name) {
            accs.entry((name.clone(), s.multi)).or_insert_with(|| Acc {
                format_sha256: sha256(m.fmts[s.fmt].text(&m.fmts).as_bytes()),
                count: 0,
                first: None,
                last: None,
                sha: Sha256::new(),
            });
        }
    };

    for k in 0..m.initial.min(m.subs.len()) {
        subscribe(
            k,
            &mut records,
            &mut ev,
            &mut subscribed,
            &mut in_defs,
            &mut accs,
        );
    }
    for item in &m.items {
        match item {
            Item::Sub(k) => subscribe(
                *k,
                &mut records,
                &mut ev,
                &mut subscribed,
                &mut in_defs,
                &mut accs,
            ),
            Item::Row {
                sub,
                dt,
                len_sel,
                fill,
            } => {
                if m.subs.is_empty() {
                    continue;
                }
                let k = sub % m.subs.len();
                let s = &m.subs[k];
                if !subscribed[k] {
                    records.push(data_rec(s.id, &cycle(fill, 9)));
                    exp.orphans += 1;
                    continue;
                }
                let name = &m.fmts[s.fmt].name;
                let lay = layouts[s.fmt].as_ref().expect("a top-level format");
                let len = lay.size + usize::from(*len_sel) % (lay.padded - lay.size + 1);
                let ts = sub_last
                    .get(&s.id)
                    .copied()
                    .unwrap_or(m.start_ts)
                    .saturating_add(u64::from(*dt));
                sub_last.insert(s.id, ts);
                let mut payload = cycle(fill, len);
                let ts_at = lay
                    .fields
                    .iter()
                    .find(|f| f.name == "timestamp")
                    .map(|f| f.offset)
                    .expect("a timestamp");
                payload[ts_at..ts_at + 8].copy_from_slice(&ts.to_le_bytes());
                records.push(data_rec(s.id, &payload));
                last_ts = last_ts.max(ts);
                exp.rows += 1;
                *exp.topic_rows.entry(name.clone()).or_insert(0) += 1;
                let idx = row_index.entry((name.clone(), s.multi)).or_insert(0);
                if name == "vehicle_status" {
                    vs.push((s.multi, vs_expected(lay, &payload, ts, *idx)));
                }
                *idx += 1;
                if let Some(acc) = accs.get_mut(&(name.clone(), s.multi)) {
                    acc.count += 1;
                    acc.first.get_or_insert(ts);
                    acc.last = Some(ts);
                    acc.sha.update((payload.len() as u64).to_le_bytes());
                    acc.sha.update(&payload);
                }
                ev.push(Ev::Data {
                    id: s.id,
                    ts,
                    payload,
                });
            }
            Item::Orphan { id, fill } => {
                let mut id = *id;
                while m.subs.iter().any(|s| s.id == id) {
                    id = id.wrapping_add(1);
                }
                records.push(data_rec(id, &cycle(fill, 5)));
                exp.orphans += 1;
            }
            Item::Param(name, v) => {
                records.push(param_rec(name, *v));
                ev.push(Ev::Param {
                    name: name.clone(),
                    value: v.norm(),
                    defs: in_defs,
                    last: last_ts,
                });
                if in_defs {
                    exp.config.insert(name.clone(), v.norm());
                } else {
                    exp.param_records
                        .push((name.clone(), v.norm(), last_ts, param_index));
                }
                param_index += 1;
            }
            Item::Log {
                tag,
                level,
                ts,
                text,
            } => {
                records.push(match tag {
                    Some(t) => tagged_rec(*level, *t, *ts, text),
                    None => log_rec(*level, *ts, text),
                });
                ev.push(Ev::Log {
                    level: *level,
                    tag: *tag,
                    ts: *ts,
                    text: text.clone(),
                });
                if (b'0'..=b'4').contains(level) {
                    exp.logs.push((level - b'0', *ts, text.clone(), log_index));
                }
                log_index += 1;
            }
            Item::Dropout(ms) => {
                records.push(dropout_rec(*ms));
                ev.push(Ev::Dropout {
                    ms: *ms,
                    last: last_ts,
                });
                exp.dropouts.push((*ms, last_ts, dropout_index));
                dropout_index += 1;
            }
            Item::Sync => records.push(rec(b'S', &[0u8; 8])),
            Item::Unsub(id) => records.push(rec(b'R', &id.to_le_bytes())),
            Item::Multi { continued, key } => {
                records.push(multi_info_rec(*continued, key, b"value"));
            }
            Item::DefaultParam { types, key } => records.push(default_param_rec(*types, key)),
            Item::Unknown(ty, body) => {
                records.push(rec(*ty, body));
                exp.unknown += 1;
            }
        }
    }

    exp.records = records.len() as u64;
    exp.events = ev;
    // The ingestor orders `vehicle_status` rows by instance, each in file order.
    vs.sort_by_key(|(multi, _)| *multi);
    exp.vs = vs;
    exp.sealed = accs
        .into_iter()
        .map(|((topic, multi), a)| DigestExp {
            topic,
            multi,
            format_sha256: a.format_sha256,
            count: a.count,
            first: a.first,
            last: a.last,
            data_sha256: a.sha.finalize().into(),
        })
        .collect();
    Rendered {
        header: file_header(m.version, m.start_ts),
        records,
        exp,
    }
}

fn field(name: &str, s: usize) -> Field {
    Field {
        ty: FTy::Scalar(s),
        arr: None,
        name: name.to_string(),
    }
}

fn scalar_index(name: &str) -> usize {
    SCALARS
        .iter()
        .position(|(n, _)| *n == name)
        .expect("a scalar")
}

/// `vehicle_status` and `failsafe_flags` as `make_synthetic_logs.py` declares them.
fn py_formats() -> Vec<Fmt> {
    let u8t = scalar_index("uint8_t");
    let b = scalar_index("bool");
    vec![
        Fmt {
            name: "vehicle_status".into(),
            fields: vec![
                field("timestamp", S_U64),
                field("arming_state", u8t),
                field("nav_state", u8t),
                field("failsafe", b),
                field("is_vtol", b),
                field("in_transition_mode", b),
                field("in_transition_to_fw", b),
                field("vehicle_type", u8t),
                field("system_type", u8t),
                field("latest_arming_reason", u8t),
                field("latest_disarming_reason", u8t),
            ],
        },
        Fmt {
            name: "failsafe_flags".into(),
            // The fields of PY_FS, "type name;" each after the name of the message.
            fields: PY_FS
                .strip_prefix("failsafe_flags:")
                .expect("the message name")
                .split_terminator(';')
                .map(|f| {
                    let (ty, name) = f.split_once(' ').expect("type and name");
                    field(name, scalar_index(ty))
                })
                .collect(),
        },
    ]
}

#[test]
fn the_model_renders_the_python_flight_and_flattens_its_nested_format() {
    // `mc_flight()` of `make_synthetic_logs.py`, as a model: the records, their order, the
    // format texts, the timestamps and the payloads must come out as the Python bytes.
    let m = Model {
        version: 1,
        start_ts: 0,
        flags: true,
        git: Some((String::from_utf8(PY_GIT.to_vec()).unwrap(), 0)),
        release: Some(0x0111_00FF),
        infos: vec![],
        def_order: 0,
        fmts: py_formats(),
        nested: 0,
        params: vec![
            ("SYS_AUTOSTART".into(), Pv::I(10040)),
            ("COM_DISARM_LAND".into(), Pv::I(2)),
        ],
        subs: vec![
            SubSpec {
                fmt: 0,
                multi: 0,
                id: 0,
            },
            SubSpec {
                fmt: 1,
                multi: 0,
                id: 1,
            },
        ],
        initial: 2,
        items: (1..=8u64)
            .flat_map(|i| {
                let armed = if (2..=6).contains(&i) { 2 } else { 1 };
                [
                    Item::Row {
                        sub: 1,
                        dt: 1_000_000,
                        len_sel: 0,
                        fill: vec![0; PY_FS_LEN],
                    },
                    Item::Row {
                        sub: 0,
                        dt: 1_000_000,
                        len_sel: 0,
                        fill: vec![0, 0, 0, 0, 0, 0, 0, 0, armed, 4, 0, 0, 0, 0, 1, 2, 3, 6],
                    },
                ]
            })
            .collect(),
    };
    let r = render(&m, &BTreeSet::new());
    assert!(
        r.bytes() == py_mc_flight(1),
        "the model's bytes differ from the Python flight"
    );
    // One flag bits record, two information messages, two formats, two parameters, two
    // subscriptions and sixteen data records.
    assert_eq!(r.exp.records, 1 + 2 + 2 + 2 + 2 + 16);

    // The nested format of `custom_detection` as the Python script declares it.
    let f = scalar_index("float");
    let mut fmts = vec![
        Fmt {
            name: "detection_box".into(),
            fields: vec![field("x", f), field("y", f), field("w", f), field("h", f)],
        },
        Fmt {
            name: "custom_detection".into(),
            fields: vec![
                field("timestamp", S_U64),
                field("class_id", scalar_index("uint32_t")),
                field("confidence", f),
                Field {
                    ty: FTy::Nested(0),
                    arr: None,
                    name: "box".into(),
                },
            ],
        },
    ];
    assert_eq!(fmts[0].text(&fmts), PY_BOX);
    assert_eq!(fmts[1].text(&fmts), PY_DET);
    let lay = ref_flatten(&fmts, 1);
    let names: Vec<(&str, usize)> = lay
        .fields
        .iter()
        .map(|x| (x.name.as_str(), x.offset))
        .collect();
    assert_eq!(
        names,
        [
            ("timestamp", 0),
            ("class_id", 8),
            ("confidence", 12),
            ("box.x", 16),
            ("box.y", 20),
            ("box.w", 24),
            ("box.h", 28)
        ]
    );
    assert_eq!((lay.size, lay.padded), (32, 32));
    // The ULog specification's own example of padding: `_padding0[3]` ends a format, and the
    // data record leaves it out (`ulog.rs`, `Layout::size`).
    fmts[1].fields.push(Field {
        ty: FTy::Scalar(S_U8),
        arr: Some(3),
        name: "_padding0".into(),
    });
    let lay = ref_flatten(&fmts, 1);
    assert_eq!((lay.size, lay.padded, lay.fields.len()), (32, 35, 7));
}

// ---------------------------------------------------------------------------------------------
// A visitor that records every call, and what the reader and the ingestor must give.
// ---------------------------------------------------------------------------------------------

/// Records the reader's calls as `Ev` values, and checks each layout it is given against the
/// scalar accessors of `FlatField` and `Layout::field`.
#[derive(Default)]
struct Cap {
    evs: Vec<Ev>,
    layouts: BTreeMap<u16, Rc<Layout>>,
    problems: Vec<String>,
}

impl Visitor for Cap {
    fn header(&mut self, h: &Header) {
        self.evs.push(Ev::Header(h.version, h.timestamp));
    }
    fn info(&mut self, key_type: &str, key: &str, value: &[u8]) {
        self.evs
            .push(Ev::Info(key_type.into(), key.into(), value.to_vec()));
    }
    fn format_definition(&mut self, name: &str, definition: &[u8]) {
        self.evs.push(Ev::Format(name.into(), definition.to_vec()));
    }
    fn parameter(&mut self, name: &str, value: ParamValue, section: Section, last: u64) {
        self.evs.push(Ev::Param {
            name: name.into(),
            value: Pv::of(value),
            defs: section == Section::Definitions,
            last,
        });
    }
    fn subscription(&mut self, id: u16, multi: u8, topic: &str, layout: &Rc<Layout>) {
        for f in &layout.fields {
            if layout.field(&f.name) != Some(f) {
                self.problems
                    .push(format!("Layout::field({}) is not that field", f.name));
            }
        }
        if layout.field("no such field").is_some() {
            self.problems
                .push("Layout::field found an absent name".into());
        }
        self.layouts.insert(id, Rc::clone(layout));
        self.evs.push(Ev::Sub {
            id,
            multi,
            topic: topic.into(),
            size: layout.size,
            padded: layout.padded_size,
            fields: layout
                .fields
                .iter()
                .map(|f| (f.name.clone(), f.offset, f.scalar.name()))
                .collect(),
        });
    }
    fn data(&mut self, id: u16, ts: u64, payload: &[u8]) {
        if let Some(layout) = self.layouts.get(&id) {
            for f in &layout.fields {
                let s = scalar_index(f.scalar.name());
                let unsigned = dec_unsigned(s, payload, f.offset);
                let signed = dec_signed(s, payload, f.offset);
                let name = &f.name;
                if f.read_u64(payload) != unsigned {
                    self.problems.push(format!("read_u64 of {name}"));
                }
                if f.read_i64(payload) != signed {
                    self.problems.push(format!("read_i64 of {name}"));
                }
                let u32_expected = if SCALARS[s].0 == "uint32_t" {
                    unsigned.and_then(|v| u32::try_from(v).ok())
                } else {
                    None
                };
                if f.read_u32(payload) != u32_expected {
                    self.problems.push(format!("read_u32 of {name}"));
                }
                let bool_expected = if SCALARS[s].0 == "bool" {
                    unsigned.map(|v| v != 0)
                } else {
                    None
                };
                if f.read_bool(payload) != bool_expected {
                    self.problems.push(format!("read_bool of {name}"));
                }
                let float_expected = if SCALARS[s].0 == "float" {
                    dec_unsigned(scalar_index("uint32_t"), payload, f.offset)
                        .and_then(|v| u32::try_from(v).ok())
                } else {
                    None
                };
                match (f.read_f32(payload), float_expected) {
                    (None, None) => {}
                    (Some(x), Some(bits)) if x.to_bits() == bits || x.is_nan() => {}
                    _ => self.problems.push(format!("read_f32 of {name}")),
                }
            }
        }
        self.evs.push(Ev::Data {
            id,
            ts,
            payload: payload.to_vec(),
        });
    }
    fn logging(&mut self, level: u8, tag: Option<u16>, ts: u64, text: &[u8]) {
        self.evs.push(Ev::Log {
            level,
            tag,
            ts,
            text: text.to_vec(),
        });
    }
    fn dropout(&mut self, ms: u16, last: u64) {
        self.evs.push(Ev::Dropout { ms, last });
    }
}

/// Whether a firmware version text is `major.minor.patch` of the release word's big-endian bytes
/// (`Firmware::release` is `0xAABBCCTT`), with a suffix exactly when `TT` is below 255
/// (`Firmware::version`).
fn version_text_ok(release: u32, text: Option<&str>) -> bool {
    if release == 0 {
        return text.is_none();
    }
    let [a, b, c, t] = release.to_be_bytes();
    let base = format!("{a}.{b}.{c}");
    match text {
        None => false,
        Some(s) if t == 255 => s == base,
        Some(s) => ["-rc", "-beta", "-alpha", "-dev"]
            .iter()
            .any(|suffix| s == format!("{base}{suffix}")),
    }
}

/// What every successful ingest of `bytes` holds, whatever the bytes are: the byte count and the
/// digests of the whole input, the reader's summary, the event numbering and order (SPEC B1.5
/// "Event ordering": boot time, then topic name, then instance, then message index), and the
/// sealed topics (sorted, unique, only the listed ones, their counts those of the topic).
fn check_any_ok(bytes: &[u8], ing: &Ingested, sealed: &[String]) -> Result<(), TestCaseError> {
    prop_assert_eq!(ing.identity.size, bytes.len() as u64);
    prop_assert_eq!(ing.identity.sha256, sha256(bytes));
    prop_assert_eq!(ing.identity.blake3, blake3_digest(bytes));
    prop_assert_eq!(ing.flight.summary.bytes, bytes.len() as u64);
    prop_assert_eq!(&ing.identity.skipped, &ing.flight.summary);
    prop_assert_eq!(ing.identity.truncated, ing.flight.summary.truncated);
    prop_assert_eq!(ing.identity.ulog_version, bytes[7]);
    prop_assert_eq!(
        ing.flight.start_timestamp,
        u64::from_le_bytes(bytes[8..16].try_into().unwrap())
    );
    if let Some(t) = ing.flight.summary.truncated {
        prop_assert!(t.trailing_bytes >= 1);
        prop_assert_eq!(t.offset + t.trailing_bytes, bytes.len() as u64);
    }
    for (i, e) in ing.events.iter().enumerate() {
        prop_assert_eq!(e.seq, i as u64);
    }
    for w in ing.events.windows(2) {
        let key = |e: &sfr_core::events::Event| (e.boot_us, e.topic.clone(), e.instance, e.index);
        prop_assert!(key(&w[0]) <= key(&w[1]), "events out of order: {:?}", w);
    }
    let keys: Vec<(&str, u8)> = ing
        .sealed_topics
        .iter()
        .map(|d| (d.topic.as_str(), d.multi_id))
        .collect();
    prop_assert!(keys.windows(2).all(|w| w[0] < w[1]), "sorted and unique");
    prop_assert!(
        ing.sealed_topics.iter().all(|d| sealed.contains(&d.topic)),
        "only listed topics are sealed"
    );
    for d in &ing.sealed_topics {
        prop_assert_eq!(d.first_timestamp_us.is_none(), d.message_count == 0);
        prop_assert_eq!(d.last_timestamp_us.is_none(), d.message_count == 0);
    }
    let topics: BTreeSet<&str> = ing.sealed_topics.iter().map(|d| d.topic.as_str()).collect();
    for topic in topics {
        let total: u64 = ing
            .sealed_topics
            .iter()
            .filter(|d| d.topic == topic)
            .map(|d| d.message_count)
            .sum();
        prop_assert_eq!(
            total,
            ing.flight.topic_rows.get(topic).copied().unwrap_or(0),
            "{}",
            topic
        );
    }
    if let Some(r) = ing.identity.firmware.release {
        prop_assert!(
            version_text_ok(r, ing.identity.firmware.version.as_deref()),
            "{:?}",
            ing.identity.firmware
        );
    } else {
        prop_assert_eq!(&ing.identity.firmware.version, &None);
    }
    prop_assert_eq!(&ing.config.firmware, &ing.identity.firmware.version);
    Ok(())
}

/// The counts the scanner gives for bytes with no appended data, held against the ingested
/// value.
fn check_counts(bytes: &[u8], ing: &Ingested) -> Result<(), TestCaseError> {
    let c = count(bytes);
    let s = &ing.flight.summary;
    prop_assert!(!s.data_appended);
    prop_assert_eq!(s.records, c.records);
    prop_assert_eq!(s.unknown_records, c.unknown);
    prop_assert_eq!(s.orphan_data, c.orphans);
    prop_assert_eq!((s.skipped_regions, s.skipped_bytes), (0, 0));
    let frames = scan(bytes);
    match (frames.unfinished, s.truncated) {
        (None, None) => {}
        (Some(at), Some(t)) => {
            prop_assert_eq!(t.offset, at as u64);
            prop_assert_eq!(t.trailing_bytes, (bytes.len() - at) as u64);
        }
        (a, b) => return fail(format!("unfinished {a:?}, truncated {b:?}")),
    }
    prop_assert_eq!(&ing.flight.topic_rows, &c.topic_rows);
    let config: BTreeMap<String, Pv> = ing
        .config
        .params
        .iter()
        .map(|(k, v)| (k.clone(), Pv::of(*v)))
        .collect();
    prop_assert_eq!(&config, &c.config);
    let records: Vec<(String, Pv)> = ing
        .flight
        .param_records
        .iter()
        .map(|r| (r.name.clone(), Pv::of(r.value)))
        .collect();
    prop_assert_eq!(&records, &c.param_records);
    for (i, r) in ing.flight.param_records.iter().enumerate() {
        if i > 0 {
            let before = &ing.flight.param_records[i - 1];
            prop_assert!(before.index < r.index && before.file_order < r.file_order);
            prop_assert!(
                before.time <= r.time,
                "the time of a record never goes back"
            );
        }
        prop_assert!(r.index < c.params);
    }
    let levels: Vec<u8> = ing.flight.log_records.iter().map(|r| r.level).collect();
    prop_assert_eq!(&levels, &c.kept_logs);
    for w in ing.flight.log_records.windows(2) {
        prop_assert!(w[0].index < w[1].index);
    }
    prop_assert!(ing.flight.log_records.iter().all(|r| r.index < c.logs));
    prop_assert_eq!(ing.flight.dropouts.len() as u64, c.dropouts);
    for (i, d) in ing.flight.dropouts.iter().enumerate() {
        prop_assert_eq!(d.index, i as u64);
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Strategies for the model.
// ---------------------------------------------------------------------------------------------

/// A parameter name the reader accepts: 1 to 16 letters, digits and `_` (SPEC B1.4).
fn param_name() -> impl Strategy<Value = String> {
    "[A-Za-z0-9_]{1,16}"
}

fn pv() -> impl Strategy<Value = Pv> {
    prop_oneof![
        3 => any::<i32>().prop_map(Pv::I),
        3 => any::<u32>().prop_map(Pv::F),
        1 => prop::sample::select(vec![
            0u32, 0x8000_0000, 0x3f80_0000, 0x7f80_0000, 0xff80_0000, 0x7fc0_0000, 0x7fa0_0000,
            0xffc0_1234, 1, 0x7f7f_ffff,
        ]).prop_map(Pv::F),
    ]
}

#[derive(Clone, Debug)]
struct RawField {
    scalar: usize,
    nested: Option<usize>,
    arr: u32,
    pad: bool,
}

fn raw_field() -> impl Strategy<Value = RawField> {
    (
        0..SCALARS.len(),
        proptest::option::weighted(0.25, any::<usize>()),
        prop_oneof![5 => Just(0u32), 2 => 1u32..=3, 1 => 4u32..=5],
        // Often enough that a format ends in two or more padding fields in a few cases of 64.
        proptest::bool::weighted(0.25),
    )
        .prop_map(|(scalar, nested, arr, pad)| RawField {
            scalar,
            nested,
            arr,
            pad,
        })
}

/// The fields of a format from raw choices; `avail` nested formats may be used as field types
/// (an array of one is at most 2 long, so a layout stays far below the 65,535-byte limit).
fn resolve(raw: &[RawField], avail: usize) -> Vec<Field> {
    raw.iter()
        .enumerate()
        .map(|(i, r)| {
            if r.pad {
                return Field {
                    ty: FTy::Scalar(S_U8),
                    arr: Some(r.arr.max(1)),
                    name: format!("_padding{i}"),
                };
            }
            let (ty, arr) = match r.nested {
                Some(n) if avail > 0 => (FTy::Nested(n % avail), r.arr.min(2)),
                _ => (FTy::Scalar(r.scalar), r.arr),
            };
            Field {
                ty,
                arr: (arr > 0).then_some(arr),
                name: format!("f{i}"),
            }
        })
        .collect()
}

/// The formats of a model: nested types `n0`, `n1`, ... (each using only earlier ones), then
/// top-level custom formats `c0`, ... and the PX4 topics selected by `px4` (once each).
fn build_formats(
    nested: &[Vec<RawField>],
    customs: &[Vec<RawField>],
    px4: &[usize],
) -> (Vec<Fmt>, usize) {
    let mut fmts: Vec<Fmt> = nested
        .iter()
        .enumerate()
        .map(|(i, raw)| Fmt {
            name: format!("n{i}"),
            fields: resolve(raw, i),
        })
        .collect();
    let k = fmts.len();
    for (j, raw) in customs.iter().enumerate() {
        let mut fields = vec![field("timestamp", S_U64)];
        fields.extend(resolve(raw, k));
        fmts.push(Fmt {
            name: format!("c{j}"),
            fields,
        });
    }
    let mut seen = BTreeSet::new();
    for &p in px4 {
        let topic = PX4_TOPICS[p % PX4_TOPICS.len()];
        if seen.insert(topic) {
            fmts.push(px4_format(topic));
        }
    }
    (fmts, k)
}

fn item() -> impl Strategy<Value = Item> {
    prop_oneof![
        8 => (
            any::<usize>(),
            prop_oneof![3 => 0u32..1000, 1 => any::<u32>()],
            any::<u8>(),
            vec(any::<u8>(), 0..24),
        )
            .prop_map(|(sub, dt, len_sel, fill)| Item::Row { sub, dt, len_sel, fill }),
        2 => any::<usize>().prop_map(Item::Sub),
        2 => (param_name(), pv()).prop_map(|(n, v)| Item::Param(n, v)),
        1 => (
            proptest::option::of(any::<u16>()),
            prop_oneof![3 => b'0'..=b'7', 1 => any::<u8>()],
            any::<u64>(),
            vec(any::<u8>(), 0..20),
        )
            .prop_map(|(tag, level, ts, text)| Item::Log { tag, level, ts, text }),
        1 => any::<u16>().prop_map(Item::Dropout),
        1 => Just(Item::Sync),
        1 => any::<u16>().prop_map(Item::Unsub),
        1 => (any::<u8>(), "[a-z_]{0,12}")
            .prop_map(|(continued, key)| Item::Multi { continued, key }),
        1 => (any::<u8>(), "[a-z_]{0,12}")
            .prop_map(|(types, key)| Item::DefaultParam { types, key }),
        1 => (any::<u8>(), vec(any::<u8>(), 0..16)).prop_map(|(t, b)| {
            Item::Unknown(if KNOWN_TYPES.contains(&t) { b'X' } else { t }, b)
        }),
        1 => (any::<u16>(), vec(any::<u8>(), 0..8))
            .prop_map(|(id, fill)| Item::Orphan { id, fill }),
    ]
}

fn model() -> impl Strategy<Value = Model> {
    let head = (
        prop_oneof![9 => Just(1u8), 1 => any::<u8>()],
        prop_oneof![3 => 0u64..10_000_000, 1 => any::<u64>()],
        any::<bool>(),
        0u8..6,
    );
    let ident = (
        proptest::option::of(("[0-9a-f]{1,40}", 0usize..6)),
        proptest::option::of(prop_oneof![
            Just(0x0111_00FFu32),
            Just(0x010E_0400),
            Just(0),
            any::<u32>()
        ]),
        vec(
            (
                prop::sample::select(vec!["char[8]", "uint32_t", "int32_t", "float", "uint8_t"]),
                "x_[a-z]{1,10}",
                vec(any::<u8>(), 0..12),
            ),
            0..3,
        ),
    );
    let shapes = (
        vec(vec(raw_field(), 1..=3), 0..=3),
        vec(vec(raw_field(), 0..=4), 1..=3),
        vec(0usize..PX4_TOPICS.len(), 0..=3),
    );
    let data = (
        vec((param_name(), pv()), 0..6),
        vec(
            (any::<usize>(), prop_oneof![4 => 0u8..3, 1 => any::<u8>()]),
            0..6,
        ),
        (any::<u16>(), any::<u16>()),
        0usize..=6,
        vec(item(), 0..40),
    );
    (head, ident, shapes, data).prop_map(
        |(
            (version, start_ts, flags, def_order),
            (git, release, infos),
            (nested, customs, px4),
            (params, subs, (id_base, id_step), initial, items),
        )| {
            let (fmts, k) = build_formats(&nested, &customs, &px4);
            let tops = fmts.len() - k;
            let subs = subs
                .into_iter()
                .enumerate()
                .map(|(i, (sel, multi))| SubSpec {
                    fmt: k + sel % tops,
                    multi,
                    // An odd step: the ids of fewer than 65,536 subscriptions differ.
                    id: id_base.wrapping_add((i as u16).wrapping_mul(id_step | 1)),
                })
                .collect();
            Model {
                version,
                start_ts,
                flags,
                git,
                release,
                infos: infos
                    .into_iter()
                    .map(|(t, n, v)| (t.to_string(), n, v))
                    .collect(),
                def_order,
                fmts,
                nested: k,
                params,
                subs,
                initial,
                items,
            }
        },
    )
}

/// The topics to seal for a case: the top-level formats selected by `mask`, and a topic the log
/// does not have.
fn sealed_names(m: &Model, mask: u8) -> Vec<String> {
    let mut names: Vec<String> = m.fmts[m.nested..]
        .iter()
        .enumerate()
        .filter(|(i, _)| (mask >> (i % 7)) & 1 == 1)
        .map(|(_, f)| f.name.clone())
        .collect();
    if mask & 0x80 != 0 {
        names.push("absent_topic".into());
    }
    names
}

// ---------------------------------------------------------------------------------------------
// Property 4: the round trip.
// ---------------------------------------------------------------------------------------------

fn check_reader(bytes: &[u8], exp: &Expect) -> Result<(), TestCaseError> {
    let mut cap = Cap::default();
    let summary = match ulog::read(bytes, &mut cap) {
        Ok(s) => s,
        Err(e) => return fail(format!("the reader refused a log from the model: {e}")),
    };
    prop_assert_eq!(&cap.evs, &exp.events);
    prop_assert!(cap.problems.is_empty(), "{:?}", cap.problems);
    prop_assert_eq!(summary.bytes, bytes.len() as u64);
    prop_assert_eq!(summary.records, exp.records);
    prop_assert_eq!(summary.unknown_records, exp.unknown);
    prop_assert_eq!(summary.orphan_data, exp.orphans);
    prop_assert_eq!(summary.truncated, None);
    prop_assert!(!summary.data_appended);
    Ok(())
}

fn check_ingest_matches(bytes: &[u8], exp: &Expect, names: &[String]) -> Result<(), TestCaseError> {
    let ing = match ingest_with(bytes, names) {
        Ok(ing) => ing,
        Err(e) => {
            // SPEC B1.4, exit 3: a log with no data record is refused, however it ends.
            prop_assert_eq!(exp.rows, 0, "refused with data records: {}", e);
            prop_assert!(
                matches!(e, IngestError::Malformed(UlogError::Truncated { .. })),
                "{:?}",
                e
            );
            return Ok(());
        }
    };
    prop_assert!(exp.rows > 0, "a log with no data record was accepted");
    check_any_ok(bytes, &ing, names)?;
    check_counts(bytes, &ing)?;

    let config: BTreeMap<String, Pv> = ing
        .config
        .params
        .iter()
        .map(|(k, v)| (k.clone(), Pv::of(*v)))
        .collect();
    prop_assert_eq!(&config, &exp.config);
    prop_assert_eq!(ing.identity.firmware.release, exp.release);
    prop_assert_eq!(&ing.identity.firmware.git, &exp.git);
    prop_assert_eq!(&ing.flight.topic_rows, &exp.topic_rows);

    let records: Vec<(String, Pv, u64, u64)> = ing
        .flight
        .param_records
        .iter()
        .map(|r| (r.name.clone(), Pv::of(r.value), r.time, r.index))
        .collect();
    prop_assert_eq!(&records, &exp.param_records);
    let logs: Vec<(u8, u64, Vec<u8>, u64)> = ing
        .flight
        .log_records
        .iter()
        .map(|r| (r.level, r.time, r.text.clone(), r.index))
        .collect();
    prop_assert_eq!(&logs, &exp.logs);
    let dropouts: Vec<(u16, u64, u64)> = ing
        .flight
        .dropouts
        .iter()
        .map(|d| (d.duration_ms, d.time, d.index))
        .collect();
    prop_assert_eq!(&dropouts, &exp.dropouts);

    let digests: Vec<DigestExp> = ing
        .sealed_topics
        .iter()
        .map(|d| DigestExp {
            topic: d.topic.clone(),
            multi: d.multi_id,
            format_sha256: d.format_sha256,
            count: d.message_count,
            first: d.first_timestamp_us,
            last: d.last_timestamp_us,
            data_sha256: d.data_sha256,
        })
        .collect();
    prop_assert_eq!(&digests, &exp.sealed);

    let rows: Vec<(u8, VsExp)> = ing
        .flight
        .vehicle_status
        .iter()
        .map(|r| {
            (
                r.id.instance,
                VsExp {
                    ts: r.id.ts,
                    index: r.id.index,
                    arming_state: r.arming_state,
                    nav_state: r.nav_state,
                    failsafe: r.failsafe,
                    is_vtol: r.is_vtol,
                    in_transition_mode: r.in_transition_mode,
                    in_transition_to_fw: r.in_transition_to_fw,
                    vehicle_type: r.vehicle_type,
                    system_type: r.system_type,
                    latest_arming_reason: r.latest_arming_reason,
                    latest_disarming_reason: r.latest_disarming_reason,
                },
            )
        })
        .collect();
    prop_assert_eq!(&rows, &exp.vs);
    let instances: BTreeSet<u8> = exp.vs.iter().map(|(i, _)| *i).collect();
    prop_assert_eq!(
        ing.identity.vehicle_status_instances,
        instances.len() as u64
    );
    prop_assert_eq!(
        ing.identity.vehicle.system_type,
        exp.vs.first().and_then(|(_, r)| r.system_type)
    );
    prop_assert_eq!(
        ing.identity.vehicle.is_vtol,
        exp.vs.first().and_then(|(_, r)| r.is_vtol)
    );
    Ok(())
}

proptest! {
    #![proptest_config(config())]

    // Property 4. A log written from the model reads back as the model says. The reader's calls
    // come in the order, with the arguments, the layouts (names, offsets, scalars, sizes with
    // and without trailing padding) and the "last data timestamp" the model computes; the
    // ingested value holds the parameters at log start (the 'P' records before the first
    // subscription, SPEC B1.5 "Configuration"), the data-section parameter records with their
    // time and index, the information values `ver_sw` and `ver_sw_release`, the counts, the
    // decoded `vehicle_status` rows, and the sealed topic digests of SPEC B1.5 / RECORD_FORMAT
    // ("Sealed topic digests": the format record's SHA-256, the count, the first and last
    // timestamp, and SHA-256 over each payload's length as 8 little-endian bytes and the payload).
    #[test]
    fn a_log_written_from_a_model_reads_back_as_the_model_says(m in model(), mask in any::<u8>()) {
        let names = sealed_names(&m, mask);
        let sealed: BTreeSet<String> = names.iter().cloned().collect();
        let r = render(&m, &sealed);
        let bytes = r.bytes();
        check_reader(&bytes, &r.exp)?;
        check_ingest_matches(&bytes, &r.exp, &names)?;
    }
}

// ---------------------------------------------------------------------------------------------
// Properties 1 to 3: damaged input, truncation, determinism.
// ---------------------------------------------------------------------------------------------

/// Formats the structured generator draws from: the first is a nested type only, the other four
/// are top-level (they start with `uint64_t timestamp`) and have the payload size beside them.
const POOL: [(&str, usize); 5] = [
    ("n0:uint8_t a;uint8_t b;", 2),
    ("t0:uint64_t timestamp;uint8_t a;", 9),
    ("t1:uint64_t timestamp;float[3] v;int32_t k;", 24),
    (
        "vehicle_status:uint64_t timestamp;uint8_t arming_state;uint8_t nav_state;bool failsafe;",
        11,
    ),
    ("t3:uint64_t timestamp;n0 inner;uint16_t w;", 12),
];
const POOL_TOPICS: [&str; 4] = ["t0", "t1", "vehicle_status", "t3"];

/// The topics sealed in the damaged-input properties (one of them is not in any log).
fn sealed_list() -> Vec<String> {
    ["t0", "t1", "vehicle_status", "t3", "absent_topic"]
        .iter()
        .map(|s| (*s).to_string())
        .collect()
}

/// One record of the structured generator, before it is damaged.
#[derive(Clone, Debug)]
enum Rs {
    Format(u8),
    Sub {
        fmt: u8,
        id: u8,
        multi: u8,
    },
    /// A data record: the timestamp advances by `dt`; the payload is the subscribed format's size
    /// when `len % 8` is below 6, one byte short when it is 6, two bytes too long when it is 7.
    Data {
        id: u8,
        dt: u8,
        fill: Vec<u8>,
        len: u8,
    },
    Param(String, Pv),
    Raw(u8, Vec<u8>),
    Info(u8, Vec<u8>),
    Multi(u8, u8, Vec<u8>),
    DefaultParam(u8, u8),
    Log(u8, u64, Vec<u8>),
    Tagged(u8, u16, u64, Vec<u8>),
    Dropout(u16),
    /// The last subscription record again, byte for byte (a message id subscribed twice).
    Again,
}

const INFO_KEYS: [&str; 5] = [
    "char[40] ver_sw",
    "uint32_t ver_sw_release",
    "float x_f",
    "char[4] x_c",
    "int32_t x_i",
];

const INFO_SIZES: [usize; 5] = [40, 4, 4, 4, 4];

fn rs() -> impl Strategy<Value = Rs> {
    prop_oneof![
        4 => (0u8..4, 3u8..6, prop_oneof![8 => Just(0u8), 1 => any::<u8>()])
            .prop_map(|(fmt, id, multi)| Rs::Sub { fmt, id, multi }),
        40 => (
            prop_oneof![9 => 0u8..3, 1 => 3u8..6],
            prop_oneof![8 => 0u8..3, 1 => any::<u8>()],
            vec(any::<u8>(), 0..24),
            prop_oneof![30 => 0u8..6, 1 => 6u8..8],
        )
            .prop_map(|(id, dt, fill, len)| Rs::Data { id, dt, fill, len }),
        1 => (0u8..5).prop_map(Rs::Format),
        6 => (param_name(), pv()).prop_map(|(n, v)| Rs::Param(n, v)),
        2 => (any::<u8>(), vec(any::<u8>(), 0..24)).prop_map(|(t, b)| Rs::Raw(t, b)),
        3 => (0u8..5, vec(any::<u8>(), 0..8)).prop_map(|(k, v)| Rs::Info(k, v)),
        2 => (any::<u8>(), 0u8..5, vec(any::<u8>(), 0..8))
            .prop_map(|(c, k, v)| Rs::Multi(c, k, v)),
        2 => (any::<u8>(), 0u8..5).prop_map(|(t, k)| Rs::DefaultParam(t, k)),
        2 => (prop_oneof![3 => b'0'..=b'7', 1 => any::<u8>()], any::<u64>(), vec(any::<u8>(), 0..16))
            .prop_map(|(l, t, x)| Rs::Log(l, t, x)),
        2 => (b'0'..=b'7', any::<u16>(), any::<u64>(), vec(any::<u8>(), 0..16))
            .prop_map(|(l, g, t, x)| Rs::Tagged(l, g, t, x)),
        2 => any::<u16>().prop_map(Rs::Dropout),
        1 => Just(Rs::Again),
    ]
}

/// The records of a list of specs, each as its own byte string.
fn render_specs(specs: &[Rs]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut ts = 0u64;
    let mut subs: BTreeMap<u8, usize> = BTreeMap::new();
    let mut last_sub: Option<Vec<u8>> = None;
    for s in specs {
        match s {
            Rs::Format(i) => out.push(rec(b'F', POOL[usize::from(*i) % 5].0.as_bytes())),
            Rs::Sub { fmt, id, multi } => {
                let f = usize::from(*fmt) % 4;
                subs.insert(*id, f);
                let r = sub_rec(*multi, u16::from(*id), POOL_TOPICS[f]);
                last_sub = Some(r.clone());
                out.push(r);
            }
            Rs::Data { id, dt, fill, len } => {
                ts = ts.saturating_add(u64::from(*dt));
                let base = subs.get(id).map_or(8 + fill.len(), |f| POOL[f + 1].1) - 8;
                let n = match len % 8 {
                    6 => base.saturating_sub(1),
                    7 => base + 2,
                    _ => base,
                };
                let mut payload = ts.to_le_bytes().to_vec();
                payload.extend(cycle(fill, n));
                out.push(data_rec(u16::from(*id), &payload));
            }
            Rs::Param(n, v) => out.push(param_rec(n, *v)),
            Rs::Raw(t, b) => out.push(rec(*t, b)),
            Rs::Info(k, v) => {
                // The value has the declared size, except when the fill is long (a lie).
                let k = usize::from(*k) % 5;
                let n = if v.len() > 6 { v.len() } else { INFO_SIZES[k] };
                out.push(info_rec(INFO_KEYS[k], &cycle(v, n)));
            }
            Rs::Multi(c, k, v) => out.push(multi_info_rec(*c, INFO_KEYS[usize::from(*k) % 5], v)),
            Rs::DefaultParam(t, k) => {
                out.push(default_param_rec(*t, INFO_KEYS[usize::from(*k) % 5]))
            }
            Rs::Log(l, t, x) => out.push(log_rec(*l, *t, x)),
            Rs::Tagged(l, g, t, x) => out.push(tagged_rec(*l, *g, *t, x)),
            Rs::Dropout(ms) => out.push(dropout_rec(*ms)),
            Rs::Again => out.push(last_sub.clone().unwrap_or_else(|| dropout_rec(0))),
        }
    }
    out
}

/// Local damage to a list of records.
#[derive(Clone, Debug)]
enum Dmg {
    /// The declared size moves by a non-zero amount (the record lies about its length).
    Size(usize, i8),
    Ty(usize, u8),
    Flip(usize, usize, u8),
    Drop(usize),
    Dup(usize),
    Swap(usize),
}

fn dmg() -> impl Strategy<Value = Dmg> {
    prop_oneof![
        4 => (any::<usize>(), prop_oneof![(-4i8..0), (1i8..5), Just(i8::MIN), Just(i8::MAX)])
            .prop_map(|(i, d)| Dmg::Size(i, d)),
        2 => (any::<usize>(), any::<u8>()).prop_map(|(i, t)| Dmg::Ty(i, t)),
        3 => (any::<usize>(), any::<usize>(), 1u8..=255).prop_map(|(i, o, m)| Dmg::Flip(i, o, m)),
        1 => any::<usize>().prop_map(Dmg::Drop),
        1 => any::<usize>().prop_map(Dmg::Dup),
        1 => any::<usize>().prop_map(Dmg::Swap),
    ]
}

fn apply(recs: &mut Vec<Vec<u8>>, d: &Dmg) {
    if recs.is_empty() {
        return;
    }
    match d {
        Dmg::Size(i, delta) => {
            let n = recs.len();
            let r = &mut recs[i % n];
            let size = i32::from(u16::from_le_bytes([r[0], r[1]])) + i32::from(*delta);
            let size = u16::try_from(size.clamp(0, 65535)).expect("clamped");
            r[..2].copy_from_slice(&size.to_le_bytes());
        }
        Dmg::Ty(i, t) => {
            let n = recs.len();
            recs[i % n][2] = *t;
        }
        Dmg::Flip(i, o, m) => {
            let n = recs.len();
            let r = &mut recs[i % n];
            let at = o % r.len();
            r[at] ^= m;
        }
        Dmg::Drop(i) => {
            let n = recs.len();
            recs.remove(i % n);
        }
        Dmg::Dup(i) => {
            let r = recs[i % recs.len()].clone();
            recs.push(r);
        }
        Dmg::Swap(i) => {
            let at = i % recs.len();
            if at + 1 < recs.len() {
                recs.swap(at, at + 1);
            }
        }
    }
}

/// A log of the structured generator: a header, an optional flag bits record, the formats, a
/// random sequence of records, then local damage and perhaps a cut.
#[derive(Clone, Debug)]
struct Structured {
    version: u8,
    start: u64,
    /// 0: no flag bits record; 1: one with no appended data; 2: one announcing appended data at
    /// `flag_off`.
    flags: u8,
    flag_off: u64,
    /// Which of the five pool formats the definitions section holds, as a bit mask.
    defs: u8,
    /// Formats subscribed right after the definitions, as ids 0, 1, 2.
    subs: Vec<u8>,
    specs: Vec<Rs>,
    damage: Vec<Dmg>,
    cut: Option<usize>,
    /// A byte of the flag bits record (when there is one) changed before the damage: its
    /// position in the 40-byte body and the mask xored in. The first 16 bytes are the flags.
    flag_junk: Option<(u8, u8)>,
}

fn structured() -> impl Strategy<Value = Structured> {
    (
        prop_oneof![9 => Just(1u8), 1 => any::<u8>()],
        any::<u64>(),
        prop_oneof![4 => Just(0u8), 8 => Just(1u8), 1 => Just(2u8)],
        0u64..200,
        prop_oneof![8 => Just(0b11111u8), 1 => 0u8..32],
        vec(0u8..4, 1..=3),
        vec(rs(), 1..25),
        prop_oneof![5 => Just(Vec::new()), 5 => vec(dmg(), 1..=3)],
        proptest::option::weighted(0.2, any::<usize>()),
        proptest::option::weighted(0.25, (prop_oneof![3 => 0u8..16, 1 => 16u8..40], 1u8..=255)),
    )
        .prop_map(
            |(version, start, flags, flag_off, defs, subs, specs, damage, cut, flag_junk)| {
                Structured {
                    version,
                    start,
                    flags,
                    flag_off,
                    defs,
                    subs,
                    specs,
                    damage,
                    cut,
                    flag_junk,
                }
            },
        )
}

fn build(s: &Structured) -> Vec<u8> {
    let mut recs = Vec::new();
    match s.flags {
        0 => {}
        1 => recs.push(flags_rec(0, [0; 3])),
        _ => recs.push(flags_rec(1, [s.flag_off, 0, 0])),
    }
    if s.flags != 0
        && let (Some((at, mask)), Some(r)) = (s.flag_junk, recs.first_mut())
    {
        r[3 + usize::from(at)] ^= mask;
    }
    let defs: Vec<Rs> = (0..5u8)
        .filter(|i| (s.defs >> i) & 1 == 1)
        .map(Rs::Format)
        .collect();
    recs.extend(render_specs(&defs));
    // Specs are rendered together so the data records know the subscriptions.
    let mut specs: Vec<Rs> = s
        .subs
        .iter()
        .enumerate()
        .map(|(i, f)| Rs::Sub {
            fmt: *f,
            id: u8::try_from(i).expect("at most 3"),
            multi: 0,
        })
        .collect();
    specs.extend(s.specs.iter().cloned());
    recs.extend(render_specs(&specs));
    for d in &s.damage {
        apply(&mut recs, d);
    }
    let mut out = file_header(s.version, s.start);
    for r in &recs {
        out.extend_from_slice(r);
    }
    if let Some(c) = s.cut {
        out.truncate(c % (out.len() + 1));
    }
    out
}

/// What the specification obliges a reader to refuse, read off the framing: a log the reader
/// accepted holds none of these. Flag bits record: only as the first record, and with no
/// incompatible flag bit beyond bit 0 (`INCOMPAT_DATA_APPENDED`) (ULog "Flag Bits Message");
/// each message id subscribed once; no format record after the first subscription or logged
/// string (the definitions section ends there). Logs with appended data are framed by
/// offsets, not by this scan, so only the first record is held to the flags rule there.
fn check_accepted(bytes: &[u8], ing: &Ingested) -> Result<(), TestCaseError> {
    let appended = ing.flight.summary.data_appended;
    let frames = scan(bytes).frames;
    if let Some(first) = frames.first().filter(|f| f.ty == b'B') {
        let b = body(bytes, first);
        prop_assert!(
            b.len() >= 40 && b[8] & !1 == 0 && b[9..16].iter().all(|&x| x == 0),
            "accepted incompatible flag bits {:?}",
            b.get(8..16)
        );
    }
    if appended {
        return Ok(());
    }
    let mut ids = BTreeSet::new();
    let mut ended = false;
    for (i, f) in frames.iter().enumerate() {
        let b = body(bytes, f);
        match f.ty {
            b'B' => prop_assert!(i == 0, "accepted a flag bits record at record {}", i),
            b'A' => {
                ended = true;
                let id = b.get(1..3).map(|s| u16::from_le_bytes([s[0], s[1]]));
                prop_assert!(
                    id.is_some_and(|id| ids.insert(id)),
                    "accepted a message id subscribed twice, or a short subscription"
                );
            }
            b'L' => ended = true,
            b'F' => prop_assert!(!ended, "accepted a format record after the definitions"),
            _ => {}
        }
    }
    Ok(())
}

/// What every outcome of an ingest holds: an error is a refusal of the contents (never an I/O
/// failure, as the input is a slice), and a success is consistent with the bytes.
fn check_outcome(bytes: &[u8]) -> Result<(), TestCaseError> {
    let sealed = sealed_list();
    match ingest_with(bytes, &sealed) {
        Ok(ing) => {
            check_any_ok(bytes, &ing, &sealed)?;
            check_accepted(bytes, &ing)?;
            if !ing.flight.summary.data_appended {
                check_counts(bytes, &ing)?;
            }
        }
        Err(IngestError::Io(m)) => return fail(format!("an I/O error from a slice: {m}")),
        Err(e) => prop_assert!(!e.to_string().is_empty()),
    }
    Ok(())
}

proptest! {
    #![proptest_config(config())]

    // Property 1a. For arbitrary bytes, and for the 16-byte header (magic, version, timestamp)
    // followed by arbitrary bytes, `Px4Ingestor` returns `Ok` or `Err` without panicking; on `Ok`
    // the byte count is the input length, both digests are those of the whole input, and the
    // counts are those of the framing scanner (SPEC B1.5, "What is extracted from the log";
    // `ingest.rs` `Hashing`, which hashes every byte the reader asks for and the drain).
    #[test]
    fn arbitrary_bytes_never_panic_and_are_accounted_exactly(
        raw in vec(any::<u8>(), 0..300),
        version in any::<u8>(),
        start in any::<u64>(),
        tail in vec(any::<u8>(), 0..300),
    ) {
        check_outcome(&raw)?;
        let mut framed = file_header(version, start);
        framed.extend_from_slice(&tail);
        check_outcome(&framed)?;
    }

    // Property 1b. A valid header, then a random sequence of formats, subscriptions, data,
    // parameter, information, logged message, dropout and unknown-type records, with local damage
    // (sizes that lie, wrong types, flipped bytes, dropped, repeated and swapped records, a cut):
    // never a panic, and on success the accounting of property 1a. The sequence is mostly
    // well formed, so the reader gets past its first checks into formats, layouts and rows.
    #[test]
    fn structured_logs_with_local_damage_never_panic_and_are_accounted_exactly(s in structured()) {
        check_outcome(&build(&s))?;
    }
}

// ---------------------------------------------------------------------------------------------
// Property 2: truncation of real logs.
// ---------------------------------------------------------------------------------------------

/// Real logs (small PX4 SITL logs and a pyulog sample, `fuzz/seeds/ulog_ingest/`), none of which
/// announces appended data.
const REAL: [(&str, &[u8]); 3] = [
    (
        "sitl_v1.17.0_mc_flight_1_shrunk",
        include_bytes!("../../../fuzz/seeds/ulog_ingest/sitl_v1.17.0_mc_flight_1_shrunk.ulg"),
    ),
    (
        "sitl_v1.17.0_failsafe_battery_empty_shrunk",
        include_bytes!(
            "../../../fuzz/seeds/ulog_ingest/sitl_v1.17.0_failsafe_battery_empty_shrunk.ulg"
        ),
    ),
    (
        "pyulog_sample_first_65516",
        include_bytes!("../../../fuzz/seeds/ulog_ingest/pyulog_sample_first_65516.ulg"),
    ),
];

/// For each real log: the offsets at which a record ends (16 for the end of the header), and the
/// index in that list of the first data record of a subscribed id.
static BOUNDARIES: std::sync::LazyLock<Vec<(Vec<usize>, usize)>> = std::sync::LazyLock::new(|| {
    REAL.iter()
        .map(|(_, bytes)| {
            let f = scan(bytes);
            let mut ends = vec![16usize];
            ends.extend(f.frames.iter().map(Frame::end));
            let mut subs = BTreeSet::new();
            let mut first_data = ends.len() - 1;
            for (i, fr) in f.frames.iter().enumerate() {
                let b = body(bytes, fr);
                if fr.ty == b'A' && b.len() >= 3 {
                    subs.insert(u16::from_le_bytes([b[1], b[2]]));
                }
                if fr.ty == b'D' && b.len() >= 2 && subs.contains(&u16::from_le_bytes([b[0], b[1]]))
                {
                    first_data = i + 1;
                    break;
                }
            }
            (ends, first_data)
        })
        .collect()
});

#[test]
fn the_real_logs_are_what_the_truncation_properties_assume() {
    for (i, (name, bytes)) in REAL.iter().enumerate() {
        assert!(!announces_appended(bytes), "{name} announces appended data");
        let ing = ingest(bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
        check_any_ok(bytes, &ing, &[]).unwrap();
        check_counts(bytes, &ing).unwrap();
        let (ends, first_data) = &BOUNDARIES[i];
        assert!(*first_data < ends.len() - 1, "{name}: a data record exists");
        // The shrunk SITL logs end at a record boundary; the pyulog sample is a prefix of a
        // larger file and ends where it ends.
        if name.starts_with("sitl") {
            assert_eq!(ing.flight.summary.truncated, None, "{name}");
        }
    }
}

/// A cut of real log `which`, chosen by `kind`: anywhere; inside the header; at a record boundary;
/// a few bytes into the next record; around the end of the first data record.
fn cut_of(which: usize, kind: u8, x: u32) -> usize {
    let bytes = REAL[which].1;
    let (ends, first_data) = &BOUNDARIES[which];
    let x = x as usize;
    match kind % 5 {
        0 => x % (bytes.len() + 1),
        1 => x % 17,
        2 => ends[x % ends.len()],
        3 => (ends[x % ends.len()] + 1 + (x / 7) % 5).min(bytes.len()),
        _ => (ends[*first_data] + x % 9)
            .saturating_sub(4)
            .clamp(16, bytes.len()),
    }
}

/// The documented handling of a log cut at `cut` (SPEC B1.5 "A log that ends in the middle of a
/// record"; SPEC B1.4 exit 3, "including a log with no data records (whether it ends at a record
/// boundary or inside a record)"): a cut inside the 16-byte header is refused; a log with no
/// data record of a subscribed id is refused as truncated; any other cut is read up to its last
/// complete record, with `truncated` set exactly when the bytes end inside a record, and the
/// digests, size and counts are those of the cut input.
fn check_cut(bytes: &[u8]) -> Result<(), TestCaseError> {
    let result = ingest(bytes);
    if bytes.len() < 16 {
        return match result {
            Err(IngestError::Malformed(UlogError::NotUlog | UlogError::Truncated { .. })) => Ok(()),
            other => fail(format!(
                "a cut inside the header gave {:?}",
                other.map(|_| ())
            )),
        };
    }
    let c = count(bytes);
    if c.topic_rows.is_empty() {
        return match result {
            Err(IngestError::Malformed(UlogError::Truncated { offset, .. })) => {
                prop_assert_eq!(offset, bytes.len() as u64);
                Ok(())
            }
            other => fail(format!("no data record gave {:?}", other.map(|_| ()))),
        };
    }
    let ing = match result {
        Ok(ing) => ing,
        Err(e) => return fail(format!("a cut log with data was refused: {e}")),
    };
    check_any_ok(bytes, &ing, &[])?;
    check_counts(bytes, &ing)?;
    let at_boundary = scan(bytes).unfinished.is_none();
    prop_assert_eq!(ing.flight.summary.truncated.is_none(), at_boundary);
    Ok(())
}

proptest! {
    #![proptest_config(config())]

    // Property 2a. A real log cut at a random byte: no panic, the size and digests are those of
    // the cut input, a cut inside the header or before the first data record is refused, a cut
    // at a record boundary is a log that is not truncated, and any other cut reports the
    // unfinished record's offset and trailing bytes (`check_cut`).
    #[test]
    fn a_real_log_cut_anywhere_is_handled_as_the_documentation_says(
        which in 0..REAL.len(),
        kind in any::<u8>(),
        x in any::<u32>(),
    ) {
        let cut = cut_of(which, kind, x);
        check_cut(&REAL[which].1[..cut])?;
    }

    // Property 2b. Bytes of an unfinished record change nothing but the truncation: the log cut at
    // a record boundary and the same log with 1 to (size - 1) more bytes of the next record give
    // the same topics, rows, configuration, parameters, events and sealed digests (SPEC B1.5: "The
    // unfinished message should just be discarded"), and only the second reports `truncated`.
    #[test]
    fn the_bytes_of_an_unfinished_record_are_discarded(
        which in 0..REAL.len(),
        pick in any::<usize>(),
        extra in any::<usize>(),
    ) {
        let bytes = REAL[which].1;
        let (ends, first_data) = &BOUNDARIES[which];
        // A boundary after the first data record that has a record after it.
        let span = ends.len() - 1 - first_data;
        prop_assume!(span > 0);
        let i = first_data + pick % span;
        let (start, end) = (ends[i], ends[i + 1]);
        let k = 1 + extra % (end - start - 1).max(1);
        let k = k.min(end - start - 1);
        prop_assume!(k >= 1);
        let sealed = sealed_list();
        let a = ingest_with(&bytes[..start], &sealed).unwrap();
        let b = ingest_with(&bytes[..start + k], &sealed).unwrap();
        prop_assert_eq!(a.flight.summary.truncated, None);
        let t = b.flight.summary.truncated.expect("an unfinished record is reported");
        prop_assert_eq!((t.offset, t.trailing_bytes), (start as u64, k as u64));
        prop_assert_eq!(&a.flight.topic_rows, &b.flight.topic_rows);
        prop_assert_eq!(&a.config.params, &b.config.params);
        prop_assert_eq!(format!("{:?}", a.flight.param_records), format!("{:?}", b.flight.param_records));
        prop_assert_eq!(format!("{:?}", a.events), format!("{:?}", b.events));
        prop_assert_eq!(format!("{:?}", a.sealed_topics), format!("{:?}", b.sealed_topics));
        prop_assert_eq!(a.flight.summary.records, b.flight.summary.records);
        prop_assert_eq!(&a.identity.firmware, &b.identity.firmware);
        prop_assert_eq!(a.identity.vehicle_status_instances, b.identity.vehicle_status_instances);
        prop_assert_eq!(b.identity.size, (start + k) as u64);
    }
}

// ---------------------------------------------------------------------------------------------
// Property 3: determinism, however the bytes are delivered.
// ---------------------------------------------------------------------------------------------

const RULES_TEXT: &str = concat!(
    include_str!("../../../examples/rules.extended.toml"),
    "\n[sealed_topics]\n",
    "topics = [\"vehicle_status\", \"vehicle_command\", \"battery_status\", \"t0\", \"t1\", \"t3\"]\n",
);
const BASELINE_TEXT: &str = "# Firmware: 1.17.0\n";

static RULES: std::sync::LazyLock<Rules> =
    std::sync::LazyLock::new(|| parse_rules(RULES_TEXT).expect("the rules text must parse"));
static BASELINE: std::sync::LazyLock<Baseline> = std::sync::LazyLock::new(|| {
    parse_baseline(BASELINE_TEXT).expect("the baseline text must parse")
});

/// Delivers `data` in reads of the given sizes, with an `Interrupted` error on every fifth call
/// (`Read` allows the caller to retry it), and, when `fail_at` is set, an error once that many
/// bytes have been delivered.
struct Chunked<'a> {
    data: &'a [u8],
    pos: usize,
    sizes: &'a [u16],
    calls: usize,
    fail_at: Option<usize>,
}

impl Read for Chunked<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.calls += 1;
        if self.calls.checked_rem(5) == Some(0) {
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        let mut n = usize::from(self.sizes[self.calls % self.sizes.len()])
            .max(1)
            .min(buf.len())
            .min(self.data.len() - self.pos);
        if let Some(k) = self.fail_at {
            if self.pos >= k {
                return Err(io::Error::other("injected failure"));
            }
            n = n.min(k - self.pos);
        }
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// The outcome as text: the `Debug` rendering of the whole `Ingested` value and the
/// `seal --dry-run` document (rules evaluated, canonical JSON), or of the error.
fn outcome_text(result: Result<Ingested, IngestError>) -> String {
    match result {
        Ok(ing) => {
            let eval = evaluate(&ing, &RULES, &BASELINE);
            let sha = sha256(RULES_TEXT.as_bytes());
            let doc = dry_run_json(&ing, &eval, &RULES, &BASELINE, &sha);
            format!("{ing:?}\n{}", canonical(&doc))
        }
        Err(e) => format!("{e:?}"),
    }
}

fn ingest_chunked(
    bytes: &[u8],
    sizes: &[u16],
    fail_at: Option<usize>,
) -> Result<Ingested, IngestError> {
    let mut input = Chunked {
        data: bytes,
        pos: 0,
        sizes,
        calls: 0,
        fail_at,
    };
    Px4Ingestor.ingest_sealing("prop.ulg", &mut input, &RustCrypto, &RULES.sealed_topics)
}

fn check_deterministic(bytes: &[u8], sizes: &[u16]) -> Result<(), TestCaseError> {
    let mut input: &[u8] = bytes;
    let first = outcome_text(Px4Ingestor.ingest_sealing(
        "prop.ulg",
        &mut input,
        &RustCrypto,
        &RULES.sealed_topics,
    ));
    let mut input: &[u8] = bytes;
    let second = outcome_text(Px4Ingestor.ingest_sealing(
        "prop.ulg",
        &mut input,
        &RustCrypto,
        &RULES.sealed_topics,
    ));
    prop_assert!(first == second, "two ingests of the same bytes differ");
    let chunked = outcome_text(ingest_chunked(bytes, sizes, None));
    prop_assert!(
        first == chunked,
        "the sizes of the reads change the outcome"
    );
    Ok(())
}

proptest! {
    #![proptest_config(config())]

    // Property 3a. The same bytes ingest to equal results, twice and when delivered in reads of
    // other sizes with interrupted reads retried (`ingest.rs` hashes what the reader consumes;
    // the digests and the decoded values must not depend on how the stream is cut into reads).
    // Equality is that of the `Debug` text of the `Ingested` value plus the dry-run document.
    #[test]
    fn ingesting_the_same_bytes_gives_equal_results(
        s in structured(),
        sizes in vec(1u16..64, 1..6),
    ) {
        check_deterministic(&build(&s), &sizes)?;
    }

    // Property 3b. The same for a real log cut anywhere.
    #[test]
    fn ingesting_a_cut_real_log_gives_equal_results(
        which in 0..REAL.len(),
        kind in any::<u8>(),
        x in any::<u32>(),
        sizes in vec(1u16..4096, 1..6),
    ) {
        let cut = cut_of(which, kind, x);
        check_deterministic(&REAL[which].1[..cut], &sizes)?;
    }

    // Property 3b'. The same for a log with appended data, whose reader skips regions (a
    // separate loop that must retry an interrupted read as well) and whose chunks of 1 to 63
    // bytes cut records, gaps and offsets in every way.
    #[test]
    fn ingesting_an_appended_log_gives_equal_results(
        main_rows in 1usize..4,
        segments in vec(segment(), 1..=3),
        order in any::<u8>(),
        sizes in vec(1u16..64, 1..6),
    ) {
        let log = appended_log(main_rows, &segments, order);
        check_deterministic(&log.bytes, &sizes)?;
        let outcome = ingest_chunked(&log.bytes, &sizes, None);
        prop_assert!(
            outcome.is_ok(),
            "chunked reads refused an appended log: {:?}",
            outcome.err()
        );
    }

    // Property 3c. A read error is an `Io` error, never a panic or a success (SPEC B1.4 exit 4;
    // `IngestError::Io`): the reader must see the end of the stream, so a failure at any byte
    // count up to and including the length is reported.
    #[test]
    fn a_read_error_is_an_io_error(
        s in structured(),
        sizes in vec(1u16..64, 1..6),
        at in any::<usize>(),
    ) {
        let bytes = build(&s);
        let fail_at = at % (bytes.len() + 1);
        let clean = ingest(&bytes);
        match ingest_chunked(&bytes, &sizes, Some(fail_at)) {
            Err(IngestError::Io(m)) => prop_assert!(m.contains("injected failure"), "{}", m),
            // A failure is never reported as a refusal of the contents.
            Err(IngestError::Malformed(UlogError::Io(m))) => {
                return fail(format!("a read error reported as malformed: {m}"));
            }
            // The reader may refuse the bytes it saw before the failure, and then it refuses
            // the whole input too (a refusal rests on records read in full).
            Err(IngestError::Malformed(_) | IngestError::Limit(_)) => {
                prop_assert!(clean.is_err(), "a refusal at a read error of a log that is accepted");
            }
            Ok(_) => return fail(format!("a read error at {fail_at} of {} was not reported", bytes.len())),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Property 5: limits (docs/LIMITS.md, SPEC B1.4).
// ---------------------------------------------------------------------------------------------

/// A reader that ignores everything: only whether the log is accepted matters.
struct Nop;

impl Visitor for Nop {}

/// A log of the given records after a header and a flag bits record.
fn log_of(records: &[Vec<u8>]) -> Vec<u8> {
    let mut out = file_header(1, 0);
    out.extend(flags_rec(0, [0; 3]));
    for r in records {
        out.extend_from_slice(r);
    }
    out
}

fn fmt_rec(definition: &str) -> Vec<u8> {
    rec(b'F', definition.as_bytes())
}

/// Held for a log that either is within a limit (`ok`) or is one step over it: the reader accepts
/// the first and refuses the second with an error that holds `needle`; the whole ingest path
/// refuses the second likewise (it has no data record when accepted, so the first is held at the
/// reader only), and the call returns.
fn check_limit(records: &[Vec<u8>], ok: bool, needle: &str) -> Result<(), TestCaseError> {
    let bytes = log_of(records);
    match (ulog::read(&bytes[..], &mut Nop), ok) {
        (Ok(_), true) => Ok(()),
        (Err(e), false) => {
            prop_assert!(e.to_string().contains(needle), "{}", e);
            match ingest(&bytes) {
                Err(e) => {
                    prop_assert!(e.to_string().contains(needle), "{}", e);
                    Ok(())
                }
                Ok(_) => fail("the ingest path accepted what the reader refused".into()),
            }
        }
        (Ok(_), false) => fail(format!("accepted over the limit ({needle})")),
        (Err(e), true) => fail(format!("refused within the limit: {e}")),
    }
}

const SCALAR_TYPES: [(&str, usize); 4] = [
    ("uint8_t", 1),
    ("uint16_t", 2),
    ("float", 4),
    ("uint64_t", 8),
];

/// A name of `len` bytes, starting with `lead`.
fn name_of(lead: &str, len: usize) -> String {
    let mut s = lead.to_string();
    while s.len() < len {
        s.push('a');
    }
    s
}

// The small domains of the limit properties are walked whole, not sampled: a boundary hit by 64
// random draws out of a few hundred combinations would be missed by a fixed seed more often than
// not, and a defect at one boundary value would pass. (`unwrap` on a `TestCaseError` reports the
// message of the failed check.)

// Property 5a. Format nesting: 8 levels below a subscribed format are read, a ninth is
// refused with "format nesting exceeds the input limit of 8 levels" (docs/LIMITS.md "Format
// nesting", `ulog.rs` `MAX_NESTING`). Chains of 1 to 12 types, each with no extra field, with
// an extra field in every type, and with one in every other type.
#[test]
fn format_nesting_over_8_levels_is_refused() {
    for levels in 1usize..=12 {
        for pattern in 0u8..3 {
            let mut recs = Vec::new();
            for k in 0..levels {
                let inner = if k + 1 < levels {
                    format!("n{} c;", k + 1)
                } else {
                    String::new()
                };
                let with_extra = match pattern {
                    0 => false,
                    1 => true,
                    _ => k % 2 == 0,
                };
                let more = if with_extra { "uint16_t w;" } else { "" };
                recs.push(fmt_rec(&format!("n{k}:uint8_t v;{more}{inner}")));
            }
            recs.push(fmt_rec("t:uint64_t timestamp;n0 c;"));
            recs.push(sub_rec(0, 0, "t"));
            check_limit(
                &recs,
                levels <= 8,
                "format nesting exceeds the input limit of 8 levels",
            )
            .unwrap_or_else(|e| panic!("{levels} levels, pattern {pattern}: {e}"));
        }
    }
}

// Property 5b. One flattened format: 65,535 bytes are read, one more is refused with "a
// flattened format exceeds the input limit of 65535 bytes" (docs/LIMITS.md "One flattened
// format", `ulog.rs` `MAX_LAYOUT_SIZE`), for arrays of each scalar size around the limit.
#[test]
fn a_flattened_format_over_65535_bytes_is_refused() {
    for (ty, size) in SCALAR_TYPES {
        for delta in -2i64..=2 {
            let n = i64::try_from((65_535 - 8) / size).unwrap() + delta;
            let total = 8 + size as i64 * n;
            let recs = vec![
                fmt_rec(&format!("wide:uint64_t timestamp;{ty}[{n}] x;")),
                sub_rec(0, 0, "wide"),
            ];
            check_limit(
                &recs,
                total <= 65_535,
                "a flattened format exceeds the input limit of 65535 bytes",
            )
            .unwrap_or_else(|e| panic!("{ty}[{n}]: {e}"));
        }
    }
}

// Property 5c. Names are at most 255 bytes: a format name, a field name, a field type name, a
// subscription name, and a flattened field name (with the `[i]` index of an array element, or
// the `.` and name of a nested field). Lengths 250 to 260 around the limit, every kind, every
// length and every array size.
#[test]
fn names_over_255_bytes_are_refused() {
    for kind in 0u8..6 {
        for len in 250usize..=260 {
            for arr in 0usize..3 {
                names_case(kind, len, arr)
                    .unwrap_or_else(|e| panic!("kind {kind}, length {len}, array {arr}: {e}"));
            }
        }
    }
}

fn names_case(kind: u8, len: usize, arr: usize) -> Result<(), TestCaseError> {
    let ok = len <= 255;
    let name = name_of("n", len);
    let (recs, needle): (Vec<Vec<u8>>, &str) = match kind {
        0 => (
            vec![fmt_rec(&format!("{name}:uint8_t v;"))],
            "a format name exceeds the input limit of 255 bytes",
        ),
        1 => (
            vec![fmt_rec(&format!("f:uint8_t {name};"))],
            "a field name exceeds the input limit of 255 bytes",
        ),
        2 => (
            vec![fmt_rec(&format!("f:{name} v;"))],
            "a field type name exceeds the input limit of 255 bytes",
        ),
        3 => {
            // Format names are capped, so a longer subscription names a shorter format.
            let format = if ok { name.as_str() } else { "t" };
            (
                vec![
                    fmt_rec(&format!("{format}:uint64_t timestamp;")),
                    sub_rec(0, 0, &name),
                ],
                "a subscription name exceeds the input limit of 255 bytes",
            )
        }
        4 => {
            // The last element is `<name>[<count - 1>]`: `len` bytes in all.
            let count = [1usize, 11, 101][arr];
            let digits = (count - 1).to_string().len();
            let base = name_of("a", len - 2 - digits);
            (
                vec![
                    fmt_rec(&format!("t:uint64_t timestamp;uint8_t[{count}] {base};")),
                    sub_rec(0, 0, "t"),
                ],
                "field name exceeds the input limit of 255 bytes",
            )
        }
        _ => {
            // `<name>.v`: `len` bytes in all.
            let base = name_of("a", len - 2);
            (
                vec![
                    fmt_rec("c:uint8_t v;"),
                    fmt_rec(&format!("t:uint64_t timestamp;c {base};")),
                    sub_rec(0, 0, "t"),
                ],
                "field name exceeds the input limit of 255 bytes",
            )
        }
    };
    check_limit(&recs, ok, needle)
}

// Property 5d. A parameter name is 1 to 16 letters, digits and `_` (docs/LIMITS.md
// "Parameter name", `params.rs` `valid_param_name`): a log with another name is refused with
// "is not a parameter name (1 to 16 letters, digits, `_`; SPEC B1.4)", and one with a valid
// name is read and holds the value. Every length from 1 to 20 is tried, with a valid name and
// with each of the other characters at a random place.
proptest! {
    #![proptest_config(config())]

    #[test]
    fn a_parameter_name_outside_the_rule_is_refused(
        bad in (any::<usize>(), prop::sample::select(vec!['-', '.', '*', '/', ' '])),
        value in pv(),
    ) {
        for len in 1usize..=20 {
            for bad in [None, Some(bad)] {
                let mut name = name_of("p", len);
                if let Some((at, ch)) = bad {
                    name.replace_range(at % len..at % len + 1, &ch.to_string());
                }
                let valid = len <= 16 && bad.is_none();
                let records = [
                    fmt_rec(POOL[1].0),
                    param_rec(&name, value),
                    sub_rec(0, 0, "t0"),
                    data_rec(0, &[0u8; 9]),
                ];
                let bytes = log_of(&records);
                match (ingest(&bytes), valid) {
                    (Ok(ing), true) => {
                        let got = ing.config.params.get(&name).map(|v| Pv::of(*v));
                        prop_assert_eq!(got, Some(value.norm()));
                    }
                    (Err(e), false) => prop_assert!(
                        e.to_string().contains("is not a parameter name (1 to 16 letters, digits, `_`; SPEC B1.4)"),
                        "{}", e
                    ),
                    (Ok(_), false) => return fail(format!("accepted the name {name:?}")),
                    (Err(e), true) => return fail(format!("refused the name {name:?}: {e}")),
                }
            }
        }
    }
}

// Property 5e. Subscriptions: 4,096 are read (through the whole ingest path too), the 4,097th
// is refused with "the number of subscriptions exceeds the input limit of 4096 subscriptions"
// (docs/LIMITS.md "Subscriptions", `ulog.rs` `MAX_SUBSCRIPTIONS`). Counts 4090 to 4100, with
// and without odd instances.
#[test]
fn more_than_4096_subscriptions_are_refused() {
    for n in 4090u32..=4100 {
        for multi in [false, true] {
            let mut recs = vec![fmt_rec(POOL[1].0)];
            for id in 0..n {
                let id = u16::try_from(id).unwrap();
                recs.push(sub_rec(u8::from(multi && id % 2 == 1), id, "t0"));
            }
            recs.push(data_rec(0, &[0u8; 9]));
            let needle =
                "the number of subscriptions exceeds the input limit of 4096 subscriptions";
            if n <= 4096 {
                let ing = ingest(&log_of(&recs))
                    .unwrap_or_else(|e| panic!("refused {n} subscriptions: {e}"));
                assert_eq!(ing.flight.topic_rows.get("t0"), Some(&1), "{n}");
            } else {
                check_limit(&recs, false, needle).unwrap_or_else(|e| panic!("{n}: {e}"));
            }
        }
    }
}

// Property 5f. Flattened fields across all subscriptions are counted per subscription: 20
// subscriptions of a format of 50,000 fields (1,000,000 in all) are read, one field more is
// refused with "across all subscriptions exceeds the input limit of 1000000 fields"
// (docs/LIMITS.md "Flattened fields across all subscriptions", `ulog.rs` `MAX_TOTAL_FIELDS`).
// The 50,000 fields are one shared layout, so the case costs one flattening. All six
// combinations of 19 to 21 subscriptions and the narrow one are run.
#[test]
fn flattened_fields_across_subscriptions_over_a_million_are_refused() {
    for subs in 19u16..=21 {
        for narrow in [false, true] {
            let mut recs = vec![
                fmt_rec("wide:uint64_t timestamp;uint8_t[49999] x;"),
                fmt_rec("narrow:uint64_t timestamp;"),
            ];
            for id in 0..subs {
                recs.push(sub_rec(0, id, "wide"));
            }
            if narrow {
                recs.push(sub_rec(0, 100, "narrow"));
            }
            let total = 50_000 * u32::from(subs) + u32::from(narrow);
            check_limit(
                &recs,
                total <= 1_000_000,
                "across all subscriptions exceeds the input limit of 1000000 fields",
            )
            .unwrap_or_else(|e| panic!("{subs} subscriptions, narrow {narrow}: {e}"));
        }
    }
}

// Property 5g. Parameters at log start: 65,536 distinct names are read, the 65,537th is
// refused with "the number of parameters at log start exceeds the input limit of 65536
// parameters" (docs/LIMITS.md "Parameters at log start", `params.rs` `MAX_PARAMS`, enforced in
// `ingest.rs`). A name set again does not count twice, so repeated records of a few names
// never reach the limit. All ten combinations of 65,534 to 65,538 names, with and without
// repeats.
#[test]
fn more_than_65536_parameters_at_log_start_are_refused() {
    for distinct in 65_534usize..=65_538 {
        for repeat in [false, true] {
            let total = distinct + if repeat { 4 } else { 0 };
            let mut recs = vec![fmt_rec(POOL[1].0)];
            for i in 0..total {
                recs.push(param_rec(&format!("P{}", i % distinct), Pv::I(i as i32)));
            }
            recs.push(sub_rec(0, 0, "t0"));
            recs.push(data_rec(0, &[0u8; 9]));
            let bytes = log_of(&recs);
            match (ingest(&bytes), distinct <= 65_536) {
                (Ok(ing), true) => {
                    assert_eq!(ing.config.params.len(), distinct);
                    // The last record of each name wins: names 0 to 3 are set again when repeating.
                    for j in [0usize, 3, 4, distinct - 1] {
                        let last = if repeat && j < 4 { j + distinct } else { j };
                        let got = ing.config.params.get(&format!("P{j}")).map(|v| Pv::of(*v));
                        assert_eq!(got, Some(Pv::I(last as i32)), "{distinct} {repeat} {j}");
                    }
                }
                (Err(e), false) => assert!(
                    e.to_string().contains(
                        "the number of parameters at log start exceeds the input limit of 65536 parameters"
                    ),
                    "{e}"
                ),
                (Ok(_), false) => panic!("accepted {distinct} parameters"),
                (Err(e), true) => panic!("refused {distinct} parameters: {e}"),
            }
        }
    }
}

// Property 5i. Field definitions across all formats are capped at 1,000,000, and a format with
// no fields counts as one (docs/LIMITS.md "Field definitions across all formats", `ulog.rs`
// `MAX_TOTAL_FIELDS`): 250 formats of 4,000 definitions (exactly 1,000,000) are read, and one
// more format, with no field at all, is refused; so is the seventh empty format after 999,994
// definitions, while six are read. One test and not a property: each log is 11 MB. The reader
// alone is run for a log within the limit, and the ingest path too for one over it.
#[test]
fn field_definitions_over_a_million_are_refused() {
    let wide = |n: usize| -> String { (0..n).map(|k| format!("bool a{k};")).collect() };
    let mut recs = Vec::new();
    for f in 0..249 {
        recs.push(fmt_rec(&format!("f{f}:{}", wide(4000))));
    }
    let needle = "the number of field definitions across all formats exceeds the input limit of 1000000 definitions";
    let mut exact = recs.clone();
    exact.push(fmt_rec(&format!("f249:{}", wide(4000))));
    check_limit(&exact, true, needle).expect("exactly 1,000,000 definitions");
    exact.push(fmt_rec("empty:"));
    check_limit(&exact, false, needle).expect("an empty format is one definition");
    // 996,000 + 3,994 = 999,994 definitions, and each empty format adds one.
    recs.push(fmt_rec(&format!("f249:{}", wide(3994))));
    for empty in 0..6 {
        recs.push(fmt_rec(&format!("e{empty}:")));
    }
    check_limit(&recs, true, needle).expect("six empty formats make exactly 1,000,000");
    recs.push(fmt_rec("e6:"));
    check_limit(&recs, false, needle).expect("the seventh passes the limit");
}

// Property 5h. Flattened field names summed once per distinct subscribed format are capped at 16
// MiB (docs/LIMITS.md, `ulog.rs` `MAX_FLATTENED_NAME_BYTES`): 274 formats of 240 fields with
// 255-byte names and one more, in all exactly 16,777,216 bytes, are read, and one byte more is
// refused. One test and not a property: the log is 17 MB. The reader alone is run (hashing 17 MB in a
// debug build costs seconds), and the message is the one the ingest path passes on.
#[test]
fn flattened_name_bytes_over_16_mib_are_refused() {
    let field = |k: usize, len: usize| {
        let name = name_of(&format!("f{k}_"), len);
        format!("uint8_t {name};")
    };
    let log = |last: usize| {
        let mut recs = Vec::new();
        for f in 0..274 {
            let fields: String = (0..240).map(|k| field(k, 255)).collect();
            recs.push(fmt_rec(&format!("g{f}:uint64_t timestamp;{fields}")));
        }
        let fields: String = (0..23).map(|k| field(k, 255)).collect();
        recs.push(fmt_rec(&format!(
            "g274:uint64_t timestamp;{fields}{}",
            field(23, last)
        )));
        for f in 0..275u16 {
            recs.push(sub_rec(0, f, &format!("g{f}")));
        }
        log_of(&recs)
    };
    ulog::read(&log(76)[..], &mut Nop).expect("exactly 16 MiB of flattened names");
    let e = ulog::read(&log(77)[..], &mut Nop).expect_err("one byte over");
    assert!(
        e.to_string().contains(
            "flattened field names in the subscribed formats exceeds the input limit of 16777216 bytes (SPEC B1.4)"
        ),
        "{e}"
    );
}

// ---------------------------------------------------------------------------------------------
// Property 6: appended data (SPEC B1.5, ULog "appended data": flag bits record with an offset).
// ---------------------------------------------------------------------------------------------

/// One appended section: a gap of `gap` bytes before the announced offset that starts with the
/// header of a record declaring more bytes than the gap holds (`over` more than it has left), and
/// `rows` data records at the offset.
#[derive(Clone, Debug)]
struct Segment {
    gap: usize,
    over: u16,
    ty: u8,
    junk: Vec<u8>,
    rows: usize,
}

/// The log and what reading it must give: the number of records read, the regions skipped and
/// their bytes, the timestamps of the data records in order, and the offsets announced.
struct AppendedLog {
    bytes: Vec<u8>,
    records: u64,
    skipped_regions: u64,
    skipped_bytes: u64,
    stamps: Vec<u64>,
    offsets: Vec<u64>,
    /// Where each unit of the file starts: the header, every record of the main part, and for
    /// each appended section its gap (if any) and its records.
    starts: Vec<usize>,
}

/// The three slots of the flag bits record's offset array in which the offsets are written, for
/// `order % 6`: the six permutations. The reader sorts them and ignores the zero ones, so an
/// offset may stand in any slot.
const SLOTS: [[usize; 3]; 6] = [
    [0, 1, 2],
    [0, 2, 1],
    [1, 0, 2],
    [1, 2, 0],
    [2, 0, 1],
    [2, 1, 0],
];

fn appended_log(main_rows: usize, segments: &[Segment], order: u8) -> AppendedLog {
    let mut rest = vec![fmt_rec(POOL[1].0), sub_rec(0, 0, "t0")];
    let mut stamps = Vec::new();
    let mut next_ts = 0u64;
    let mut row = |rest: &mut Vec<Vec<u8>>| {
        next_ts += 10;
        stamps.push(next_ts);
        let mut payload = next_ts.to_le_bytes().to_vec();
        payload.push(7);
        rest.push(data_rec(0, &payload));
    };
    for _ in 0..main_rows {
        row(&mut rest);
    }
    let mut records = 1 + rest.len() as u64;
    // The flag bits record is 3 + 40 bytes after the 16-byte header.
    let mut at = 16 + 43;
    let mut starts = vec![0usize, 16, at];
    for r in &rest {
        starts.push(at + r.len());
        at += r.len();
    }
    starts.pop();
    let mut tail: Vec<u8> = Vec::new();
    let mut offsets = Vec::new();
    let (mut regions, mut skipped) = (0u64, 0u64);
    for seg in segments {
        let mut gap = vec![0u8; 0];
        if seg.gap >= 3 {
            let declared = seg.gap - 3 + usize::from(seg.over.max(1));
            gap.extend_from_slice(&u16::try_from(declared).unwrap().to_le_bytes());
            gap.push(seg.ty);
            gap.extend(cycle(&seg.junk, seg.gap - 3));
        } else {
            gap.extend(cycle(&seg.junk, seg.gap));
        }
        if seg.gap > 0 {
            regions += 1;
            skipped += seg.gap as u64;
            starts.push(at);
        }
        tail.extend_from_slice(&gap);
        at += seg.gap;
        // Offsets are written in file order (the reader sorts them anyway).
        offsets.push(at as u64);
        let mut part = Vec::new();
        for _ in 0..seg.rows {
            row(&mut part);
        }
        records += part.len() as u64;
        for r in &part {
            starts.push(at);
            tail.extend_from_slice(r);
            at += r.len();
        }
    }
    let mut offs = [0u64; 3];
    for (o, slot) in offsets.iter().zip(SLOTS[usize::from(order) % 6]) {
        offs[slot] = *o;
    }
    let mut bytes = file_header(1, 0);
    bytes.extend(flags_rec(1, offs));
    for r in &rest {
        bytes.extend_from_slice(r);
    }
    bytes.extend_from_slice(&tail);
    AppendedLog {
        bytes,
        records,
        skipped_regions: regions,
        skipped_bytes: skipped,
        stamps,
        offsets,
        starts,
    }
}

fn segment() -> impl Strategy<Value = Segment> {
    (
        prop_oneof![1 => Just(0usize), 1 => 1usize..3, 6 => 3usize..40],
        1u16..300,
        any::<u8>(),
        vec(any::<u8>(), 0..8),
        0usize..4,
    )
        .prop_map(|(gap, over, ty, junk, rows)| Segment {
            gap,
            over,
            ty,
            junk,
            rows,
        })
}

#[derive(Default)]
struct Stamps(Vec<u64>);

impl Visitor for Stamps {
    fn data(&mut self, _id: u16, ts: u64, _payload: &[u8]) {
        self.0.push(ts);
    }
}

proptest! {
    #![proptest_config(config())]

    // Property 6a. A flag bits record with the appended-data bit and up to three offsets: the
    // reader drops a record that crosses an announced offset (and a gap too short to hold a
    // record header), resumes at the offset, counts the dropped region and its bytes in
    // `skipped_regions` and `skipped_bytes` (`log.skipped`, SPEC B1.5 "Skipped messages"), and
    // reads the data records of the main part and of every appended part in file order; no
    // record is counted twice and none is lost; the log is not reported as truncated.
    #[test]
    fn a_record_crossing_an_appended_offset_is_dropped_and_reading_resumes(
        main_rows in 1usize..4,
        segments in vec(segment(), 1..=3),
        order in any::<u8>(),
    ) {
        let log = appended_log(main_rows, &segments, order);
        let mut v = Stamps::default();
        let s = match ulog::read(&log.bytes[..], &mut v) {
            Ok(s) => s,
            Err(e) => return fail(format!("refused: {e}")),
        };
        prop_assert!(s.data_appended);
        prop_assert_eq!(s.bytes, log.bytes.len() as u64);
        prop_assert_eq!(s.records, log.records);
        prop_assert_eq!((s.skipped_regions, s.skipped_bytes), (log.skipped_regions, log.skipped_bytes));
        prop_assert_eq!(s.truncated, None);
        prop_assert_eq!(&v.0, &log.stamps);
        // The whole path: the same rows, and digests of every byte.
        let ing = match ingest(&log.bytes) {
            Ok(ing) => ing,
            Err(e) => return fail(format!("the ingest path refused: {e}")),
        };
        check_any_ok(&log.bytes, &ing, &[])?;
        prop_assert_eq!(ing.flight.topic_rows.get("t0").copied(), Some(log.stamps.len() as u64));
        prop_assert_eq!(&ing.flight.summary, &s);
    }

    // Property 6b. A file that ends before an offset it announced is refused (SPEC B1.5: "so is
    // one that ends inside a record before an appended-data offset it announced, whose appended
    // data is missing"; the reader would otherwise wait for data that is not there): every cut
    // that leaves fewer bytes than the last announced offset is an error, whether it falls in
    // the header, in the main part, at a record boundary or in the gap.
    #[test]
    fn a_file_that_ends_before_an_announced_offset_is_refused(
        main_rows in 1usize..4,
        segments in vec(segment(), 1..=3),
        order in any::<u8>(),
        cut in any::<usize>(),
    ) {
        let log = appended_log(main_rows, &segments, order);
        let last = usize::try_from(*log.offsets.last().unwrap()).unwrap();
        let cut = cut % last;
        let e = match ingest(&log.bytes[..cut]) {
            Err(IngestError::Malformed(e)) => e,
            Err(e) => return fail(format!("another error: {e}")),
            Ok(_) => return fail(format!("accepted {cut} bytes, offset {last}")),
        };
        // Once the flag bits record is whole (it ends at byte 59) the reader knows what was
        // announced and says where the file stops short: at the start of the record, or of the
        // gap, the cut falls in, or at the cut when it falls between two.
        if cut >= 59 {
            let expected = log.starts.iter().copied().filter(|&s| s <= cut).max().unwrap();
            match e {
                UlogError::Truncated { offset, .. } => prop_assert_eq!(
                    offset,
                    expected as u64,
                    "cut at {} of offsets {:?}",
                    cut,
                    log.offsets
                ),
                other => return fail(format!("cut at {cut}: not a truncation: {other}")),
            }
        }
    }
}
