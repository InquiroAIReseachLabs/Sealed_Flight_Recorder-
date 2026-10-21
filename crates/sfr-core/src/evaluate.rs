//! Rule evaluation (SPEC B1.6). Missing or unreadable input data is FAIL, never N/A; N/A means
//! only that a rule does not apply (R6 on a vehicle that is not VTOL, R7 without
//! `[authorized_sources]`, R4 and R5 on a log with no armed flight). WARN means the rule holds
//! but the log shows something the reader should see. No threshold here is presented as correct
//! for any aircraft: the optional rules take every threshold from the rules file.

use crate::events::{
    ArmedInterval, Event, EventKind, VtolState, armed_sample, attribute_failsafe, flag_at,
    flight_armed_intervals, vtol_state,
};
use crate::exit_code;
use crate::ingest::{FailsafeFlags, Firmware, FlightLog, Ingested, VehicleStatusRow};
use crate::json::{Obj, Value};
use crate::params::Baseline;
use crate::rules::{Compare, R7_TOPIC, Rules};
use crate::ulog::{ParamValue, f32_shortest};
use std::collections::{BTreeMap, BTreeSet};

/// A rule outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The rule holds.
    Pass,
    /// The rule holds, with findings the reader should see (named in `found`).
    Warn,
    /// The rule does not hold, or its input data is missing or unreadable.
    Fail,
    /// The rule does not apply to this log.
    NotApplicable,
}

impl Status {
    /// Record spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Warn => "WARN",
            Status::Fail => "FAIL",
            Status::NotApplicable => "N/A",
        }
    }

    /// The status a record spells `s`, if any.
    pub fn parse(s: &str) -> Option<Status> {
        Some(match s {
            "PASS" => Status::Pass,
            "WARN" => Status::Warn,
            "FAIL" => Status::Fail,
            "N/A" => Status::NotApplicable,
            _ => return None,
        })
    }
}

/// The overall status of a record (SPEC B1.7 `status`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Overall {
    /// Every rule PASS or N/A, and the log has an armed flight.
    Pass,
    /// No rule FAIL, at least one WARN, and the log has an armed flight.
    Warn,
    /// At least one rule FAIL.
    Fail,
    /// No rule FAIL, and the log has no ARM and no DISARM (R5 N/A): there is no flight the
    /// rules could check.
    NoArmedFlight,
}

impl Overall {
    /// Record spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Overall::Pass => "PASS",
            Overall::Warn => "WARN",
            Overall::Fail => "FAIL",
            Overall::NoArmedFlight => "NO ARMED FLIGHT",
        }
    }

    /// From `(id, status)` of every result: FAIL if any is FAIL; else NO ARMED FLIGHT if R5 is
    /// N/A; else WARN if any is WARN; else PASS. `verify` computes it the same way from a
    /// record's results.
    pub fn of<'a>(results: impl IntoIterator<Item = (&'a str, Status)>) -> Overall {
        let (mut fail, mut warn, mut no_flight) = (false, false, false);
        for (id, status) in results {
            match status {
                Status::Fail => fail = true,
                Status::Warn => warn = true,
                Status::NotApplicable if id == "R5" => no_flight = true,
                _ => {}
            }
        }
        if fail {
            Overall::Fail
        } else if no_flight {
            Overall::NoArmedFlight
        } else if warn {
            Overall::Warn
        } else {
            Overall::Pass
        }
    }
}

/// The ids of the core rules, each exactly once in every record, in this order.
pub const CORE_RULES: [&str; 7] = ["R1", "R2", "R3", "R4", "R5", "R6", "R7"];

/// One rule result (SPEC B1.7 `results`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleResult {
    /// R1 to R7, X1 to X5.
    pub id: &'static str,
    /// Short name.
    pub name: &'static str,
    /// Outcome.
    pub status: Status,
    /// What the rule expects.
    pub expected: String,
    /// What the log shows.
    pub found: String,
    /// One line per finding.
    pub detail: Vec<String>,
}

impl RuleResult {
    fn new(
        id: &'static str,
        name: &'static str,
        status: Status,
        expected: impl Into<String>,
        found: impl Into<String>,
        detail: Vec<String>,
    ) -> Self {
        RuleResult {
            id,
            name,
            status,
            expected: expected.into(),
            found: found.into(),
            detail,
        }
    }

    /// Record form.
    pub fn to_json(&self) -> Value {
        Obj::new()
            .field("id", Value::str(self.id))
            .field("name", Value::str(self.name))
            .field("status", Value::str(self.status.as_str()))
            .field("expected", Value::str(self.expected.clone()))
            .field("found", Value::str(self.found.clone()))
            .field(
                "detail",
                Value::Array(self.detail.iter().map(|d| Value::str(d.clone())).collect()),
            )
            .build()
    }
}

/// All results plus the overall status and exit code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evaluation {
    /// In rule-id order: R1 to R7, then the enabled X rules.
    pub results: Vec<RuleResult>,
    /// [`Overall::of`] the results.
    pub status: Overall,
    /// SPEC B1.4: 2 if R1 fails, else 1 if any rule fails or the log has no armed flight,
    /// else 0.
    pub exit_code: i32,
}

/// The `vehicle_status` fields the core rules read (R1 checks them).
pub const VEHICLE_STATUS_FIELDS: [&str; 8] = [
    "timestamp",
    "arming_state",
    "nav_state",
    "failsafe",
    "is_vtol",
    "in_transition_mode",
    "in_transition_to_fw",
    "vehicle_type",
];

/// The `failsafe_flags` fields the core rules read at every tag: the timestamp. R1 also requires
/// the flags and `mode_req_*` masks PX4 defines at the log's tag
/// ([`crate::px4::failsafe_flags_fields`], from `msg/FailsafeFlags.msg`), so a format that leaves
/// one out is not a pass for the flag R4 would then never see.
pub const FAILSAFE_FLAGS_FIELDS: [&str; 1] = ["timestamp"];

/// The `vehicle_command` fields R7 reads (R1 checks them when R7 is enabled).
pub const VEHICLE_COMMAND_FIELDS: [&str; 3] = ["command", "source_system", "source_component"];

/// The `vehicle_status.system_type` values PX4 counts as VTOL: 19 to 23. Read from PX4's
/// `src/modules/commander/commander_helper.cpp`, function `is_vtol`, which is true exactly for
/// `VEHICLE_TYPE_VTOL_TAILSITTER_DUOROTOR` (19), `VEHICLE_TYPE_VTOL_TAILSITTER_QUADROTOR` (20),
/// `VEHICLE_TYPE_VTOL_TILTROTOR` (21), `VEHICLE_TYPE_VTOL_FIXEDROTOR` (22) and
/// `VEHICLE_TYPE_VTOL_TAILSITTER` (23), as that file defines them. The function and the defines
/// are the same at every supported tag, v1.14.0 to v1.17.0 (v1.17.0 is commit
/// `d6f12ad1c4f70ad3230afd7d86e971421e02fef4`).
pub const VTOL_MAV_TYPES: std::ops::RangeInclusive<u8> = 19..=23;

/// MAVLink MAV_TYPE values 24 and 25 are VTOL types in MAVLink, but PX4's `is_vtol` does not
/// count them at any supported tag ([`VTOL_MAV_TYPES`]), so `is_vtol` false beside one of them is
/// no contradiction: R6 is N/A and says so.
pub const MAVLINK_ONLY_VTOL_MAV_TYPES: std::ops::RangeInclusive<u8> = 24..=25;

/// The text that says a rule has no armed flight to check.
pub const NO_ARMED_FLIGHT: &str =
    "no armed flight: vehicle_status.arming_state has no ARM and no DISARM";

fn r1(f: &FlightLog, fw: &Firmware, rules: &Rules) -> RuleResult {
    let topics = rules.r1_topics();
    let mut missing = Vec::new();
    for t in &topics {
        if f.topic_rows.get(t).copied().unwrap_or(0) == 0 {
            missing.push(t.clone());
            continue;
        }
        let (fields, have): (Vec<&str>, &[String]) = match t.as_str() {
            "vehicle_status" => (VEHICLE_STATUS_FIELDS.to_vec(), &f.vehicle_status_fields),
            "failsafe_flags" => {
                let mut fields = FAILSAFE_FLAGS_FIELDS.to_vec();
                fields.extend(crate::px4::failsafe_flags_fields(
                    &crate::px4::releases_for(fw),
                ));
                (fields, &f.failsafe_flags_fields)
            }
            R7_TOPIC if rules.authorized_sources.is_some() => {
                (VEHICLE_COMMAND_FIELDS.to_vec(), &f.vehicle_command_fields)
            }
            _ => (Vec::new(), &[]),
        };
        for field in fields {
            if !have.iter().any(|h| h == field) {
                missing.push(format!("{t}.{field}"));
            }
        }
    }
    let readers = if rules.authorized_sources.is_some() {
        "the core rules and R7"
    } else {
        "the core rules"
    };
    let expected = format!(
        "data records for {}, and the fields {readers} read",
        topics.join(", ")
    );
    if missing.is_empty() {
        RuleResult::new(
            "R1",
            "required topics present",
            Status::Pass,
            expected,
            "all present",
            vec![],
        )
    } else {
        let found = format!("missing: {}", missing.join(", "));
        let detail = missing.iter().map(|m| format!("missing {m}")).collect();
        RuleResult::new(
            "R1",
            "required topics present",
            Status::Fail,
            expected,
            found,
            detail,
        )
    }
}

/// How R2 and R3 name the baseline file: its SHA-256, which the operator supplied.
fn baseline_source(baseline: &Baseline) -> String {
    match &baseline.sha256 {
        Some(d) => format!("baseline file sha256 {} (operator-supplied)", crate::hex(d)),
        None => "baseline file sha256 unknown (operator-supplied)".to_string(),
    }
}

fn r2(ing: &Ingested, baseline: &Baseline) -> RuleResult {
    let fw = &ing.identity.firmware;
    let expected = format!(
        "{}, from the baseline's # Firmware: line",
        baseline.firmware
    );
    let stated = match (&fw.version, &fw.git) {
        (Some(v), Some(g)) => format!("PX4 {v} {g}"),
        (Some(v), None) => format!("PX4 {v}"),
        (None, Some(g)) => format!("no ver_sw_release, ver_sw {g}"),
        (None, None) => "no ver_sw_release or ver_sw".into(),
    };
    let found = format!(
        "log states {stated} (self-reported); {}",
        baseline_source(baseline)
    );
    let mut detail = Vec::new();
    match &fw.version {
        None => detail.push("log has no ver_sw_release info message".to_string()),
        Some(v) if *v != baseline.firmware.version => detail.push(format!(
            "version: baseline {}, log {v}",
            baseline.firmware.version
        )),
        Some(_) => {}
    }
    if let Some(prefix) = &baseline.firmware.git_prefix {
        match &fw.git {
            None => detail.push("log has no ver_sw info message".to_string()),
            Some(g) if !g.to_ascii_lowercase().starts_with(prefix) => {
                detail.push(format!("git: baseline {prefix}, log {g}"))
            }
            Some(_) => {}
        }
    }
    let status = if detail.is_empty() {
        Status::Pass
    } else {
        Status::Fail
    };
    RuleResult::new(
        "R2",
        "firmware matches baseline",
        status,
        expected,
        found,
        detail,
    )
}

/// One R3 difference: the flown value, and where it came from when a data-section parameter
/// record set it.
struct Difference {
    baseline: Option<ParamValue>,
    flown: Option<ParamValue>,
    set_at: Option<u64>,
}

/// R3: the parameters in effect at every ARM (the start-of-log values, changed by every
/// data-section parameter record before the arming row in file order) equal the baseline. With
/// no ARM the values at the end of the log are compared. A change in flight is a WARN.
fn r3(ing: &Ingested, rules: &Rules, baseline: &Baseline) -> RuleResult {
    let f = &ing.flight;
    let mut checkpoints: Vec<u64> = flight_armed_intervals(f)
        .iter()
        .map(|a| a.arm_order)
        .collect();
    if checkpoints.is_empty() {
        checkpoints.push(u64::MAX);
    }
    let mut current: BTreeMap<&str, (ParamValue, Option<u64>)> = ing
        .config
        .params
        .iter()
        .map(|(k, v)| (k.as_str(), (*v, None)))
        .collect();
    let mut records = f.param_records.iter().peekable();
    let mut diffs: BTreeMap<String, Difference> = BTreeMap::new();
    let mut ignored: BTreeSet<&str> = BTreeSet::new();
    let mut suppressed: BTreeSet<&str> = BTreeSet::new();
    let mut touched: Option<BTreeSet<&str>> = None;
    for &at in &checkpoints {
        let mut changed: BTreeSet<&str> = BTreeSet::new();
        while let Some(p) = records.next_if(|p| p.file_order < at) {
            current.insert(p.name.as_str(), (p.value, Some(p.time)));
            changed.insert(p.name.as_str());
        }
        // The first checkpoint compares every name; later ones only the names changed since.
        let names: BTreeSet<&str> = match &touched {
            None => {
                let mut n: BTreeSet<&str> = baseline.params.keys().map(String::as_str).collect();
                if rules.compare == Compare::All {
                    n.extend(current.keys().copied());
                }
                n
            }
            Some(_) => changed
                .iter()
                .copied()
                .filter(|n| rules.compare == Compare::All || baseline.params.contains_key(*n))
                .collect(),
        };
        touched = Some(BTreeSet::new());
        for name in names {
            let b = baseline.params.get(name).copied();
            let l = current.get(name).copied();
            let same = matches!((b, l), (Some(b), Some((l, _))) if b.same_as(&l));
            if rules.ignores(name) {
                ignored.insert(name);
                if !same {
                    suppressed.insert(name);
                }
                continue;
            }
            if !same && !diffs.contains_key(name) {
                diffs.insert(
                    name.to_string(),
                    Difference {
                        baseline: b,
                        flown: l.map(|(v, _)| v),
                        set_at: l.and_then(|(_, t)| t),
                    },
                );
            }
        }
    }
    let mut detail = Vec::new();
    let show = |v: Option<ParamValue>| v.map_or("absent".to_string(), |v| v.to_string());
    for (name, d) in &diffs {
        let note = d.set_at.map_or(String::new(), |t| {
            format!(" (set by a parameter record at boot_us {t})")
        });
        detail.push(format!(
            "{name}: baseline {}, flown {}{note}",
            show(d.baseline),
            show(d.flown)
        ));
    }
    // Changes in flight: the PARAM_CHANGED_IN_FLIGHT events.
    let mut in_flight = Lines::new();
    for e in &ing.events {
        if let EventKind::ParamChangedInFlight { name, .. } = &e.kind {
            if rules.ignores(name) {
                suppressed.insert(name.as_str());
                continue;
            }
            in_flight.push(|| {
                format!(
                    "changed in flight: {name} at boot_us {} (event seq {})",
                    e.boot_us, e.seq
                )
            });
        }
    }
    let changed_in_flight = in_flight.total;
    detail.extend(in_flight.finish());
    let scope = match rules.compare {
        Compare::All => "every parameter in the baseline or the log",
        Compare::Baseline => "every parameter in the baseline",
    };
    let expected = format!(
        "{scope} equal to the baseline at every ARM, none changed in flight, {} ignored by pattern",
        ignored.len()
    );
    let patterns: Vec<&str> = rules.ignore.iter().map(|p| p.as_str()).collect();
    let tail = format!(
        "ignore [{}] suppressed {} difference(s){}; {}",
        patterns.join(", "),
        suppressed.len(),
        if rules.ignores_everything() {
            ", and matches every parameter name"
        } else {
            ""
        },
        baseline_source(baseline)
    );
    let (status, head) = match (diffs.len(), changed_in_flight) {
        (0, 0) => (Status::Pass, "no differences".to_string()),
        (0, k) => (
            Status::Warn,
            format!("no differences at ARM; {k} parameter(s) changed in flight"),
        ),
        (n, 0) => (Status::Fail, format!("{n} differ")),
        (n, k) => (
            Status::Fail,
            format!("{n} differ; {k} parameter(s) changed in flight"),
        ),
    };
    RuleResult::new(
        "R3",
        "parameters match baseline",
        status,
        expected,
        format!("{head}; {tail}"),
        detail,
    )
}

fn missing_fields(f: &FlightLog, fields: &[&str]) -> Vec<String> {
    if f.vehicle_status.is_empty() {
        return vec!["vehicle_status".into()];
    }
    fields
        .iter()
        .filter(|x| !f.vehicle_status_fields.iter().any(|h| h == *x))
        .map(|x| format!("vehicle_status.{x}"))
        .collect()
}

fn fail_missing(
    id: &'static str,
    name: &'static str,
    expected: &str,
    missing: Vec<String>,
) -> RuleResult {
    let detail = missing.iter().map(|m| format!("missing {m}")).collect();
    RuleResult::new(
        id,
        name,
        Status::Fail,
        expected,
        format!("cannot evaluate: missing {}", missing.join(", ")),
        detail,
    )
}

/// FAIL for input the log has but that cannot be read as PX4 defines it.
fn fail_unreadable(
    id: &'static str,
    name: &'static str,
    expected: &str,
    problems: Vec<String>,
) -> RuleResult {
    RuleResult::new(
        id,
        name,
        Status::Fail,
        expected,
        format!("cannot evaluate: {}", problems.join("; ")),
        problems,
    )
}

/// The missing and then the mistyped `vehicle_status` fields among `fields`, as a FAIL.
fn check_vehicle_status(
    id: &'static str,
    name: &'static str,
    expected: &str,
    f: &FlightLog,
    fields: &[&str],
) -> Option<RuleResult> {
    let missing = missing_fields(f, fields);
    if !missing.is_empty() {
        return Some(fail_missing(id, name, expected, missing));
    }
    let wrong = f.mismatches("vehicle_status", fields);
    if !wrong.is_empty() {
        return Some(fail_unreadable(id, name, expected, wrong));
    }
    None
}

/// Most detail lines R3, R4, R5, R6, X2, and X3 list. Real logs need a handful; the cap keeps a
/// crafted log from making one result enormous. R3's differences are not capped: SPEC B1.6 has
/// it list every differing parameter, at most the baseline and log-start parameter limits and the data-section parameter record limit together.
pub const MAX_DETAIL_LINES: usize = 1000;

/// Detail lines with a running total, capped at [`MAX_DETAIL_LINES`].
struct Lines {
    lines: Vec<String>,
    total: usize,
    /// Says where the lines past the cap can still be found.
    rest: &'static str,
}

impl Lines {
    /// Lines whose every case is also an event.
    fn new() -> Self {
        Self::with_rest("the events list every one")
    }

    fn with_rest(rest: &'static str) -> Self {
        Lines {
            lines: Vec::new(),
            total: 0,
            rest,
        }
    }

    /// Counts one finding and keeps its text while under the cap.
    fn push(&mut self, line: impl FnOnce() -> String) {
        self.total += 1;
        if self.lines.len() < MAX_DETAIL_LINES {
            self.lines.push(line());
        }
    }

    fn finish(mut self) -> Vec<String> {
        let shown = self.lines.len();
        if self.total > shown {
            self.lines
                .push(format!("and {} more; {}", self.total - shown, self.rest));
        }
        self.lines
    }
}

/// Whether a sample at `t` is in flight: from an ARM through the sample that disarms, both
/// included (R4's window).
fn in_flight_sample(armed: &[ArmedInterval], t: u64) -> bool {
    let n = armed.partition_point(|a| a.arm <= t);
    n.checked_sub(1)
        .and_then(|i| armed.get(i))
        .is_some_and(|a| t >= a.arm && a.disarm.is_none_or(|d| t <= d))
}

/// One failsafe_flags flag that was true in flight.
/// The hazard-class `failsafe_flags` fields: each reports a failure or a limit breach of the
/// vehicle itself, where the other flags report that a mode's input is unavailable or a link is
/// lost. Each name with the PX4 tags whose `msg/FailsafeFlags.msg` declares it as a `bool`, read
/// at every supported tag (v1.14.0 to v1.17.0). One true on every `failsafe_flags` sample of a
/// flight fails R4 whatever the mode requires; true on only some samples, it is a warning when
/// the mode does not require it, as every other flag is.
pub const HAZARD_FLAGS: [(&str, &str); 12] = [
    ("fd_critical_failure", "v1.14.0 to v1.17.0"),
    ("fd_esc_arming_failure", "v1.14.0 to v1.17.0"),
    ("fd_imbalanced_prop", "v1.14.0 to v1.17.0"),
    ("fd_motor_failure", "v1.14.0 to v1.17.0"),
    ("battery_unhealthy", "v1.14.0 to v1.17.0"),
    ("primary_geofence_breached", "v1.14.0 to v1.14.4"),
    ("geofence_breached", "v1.15.0 to v1.17.0"),
    ("mission_failure", "v1.14.0 to v1.17.0"),
    ("navigator_failure", "v1.16.0 to v1.17.0"),
    ("vtol_fixed_wing_system_failure", "v1.14.0 to v1.17.0"),
    ("wind_limit_exceeded", "v1.14.0 to v1.17.0"),
    ("flight_time_limit_exceeded", "v1.14.0 to v1.17.0"),
];

/// The longest gap between two `failsafe_flags` samples in flight before R4 warns, in
/// microseconds. PX4 publishes `failsafe_flags` from
/// `src/modules/commander/HealthAndArmingChecks/HealthAndArmingChecks.cpp` when the results change
/// or `now > _failsafe_flags.timestamp + 500_ms`, and `Commander.cpp` runs those checks at most
/// every 100 ms (`_last_health_and_arming_check + 100_ms`), so a gap reaches 600 ms at most; the
/// logger records every publication (`add_topic("failsafe_flags")`, no interval). The same at every
/// tag v1.14.0 to v1.17.0. The bound adds 400 ms for scheduling on a loaded flight computer; the
/// golden logs' longest gap in flight is 600 ms.
pub const FAILSAFE_FLAGS_MAX_GAP_US: u64 = 1_000_000;

/// Gaps longer than [`FAILSAFE_FLAGS_MAX_GAP_US`] in which R4 could not see the flags of one
/// instance during a flight: (count, longest, its start), over every instance. A gap is the time
/// between two consecutive samples that overlaps a flight, and, where no sample lies on that side
/// of the flight, the stretch from the ARM to the first sample, or from the last sample to the
/// DISARM (the whole flight when no sample falls inside it). A stretch the pairs of consecutive
/// samples already measure (a sample lies before the ARM, or after the disarming sample) is not
/// counted twice. A flight with no DISARM has no end to measure.
fn failsafe_flags_gaps(f: &FlightLog, armed: &[ArmedInterval]) -> Option<(usize, u64, u64)> {
    let mut count = 0usize;
    let mut longest: Option<(u64, u64)> = None;
    let mut note = |gap: u64, start: u64| {
        if gap > FAILSAFE_FLAGS_MAX_GAP_US {
            count += 1;
            if longest.is_none_or(|(g, _)| gap > g) {
                longest = Some((gap, start));
            }
        }
    };
    for fs in std::iter::once(&f.failsafe_flags).chain(&f.failsafe_flags_others) {
        let mut ts: Vec<u64> = fs.rows.iter().map(|r| r.id.ts).collect();
        ts.sort_unstable();
        for w in ts.iter().zip(ts.iter().skip(1)) {
            let (a, b) = (*w.0, *w.1);
            let in_flight = armed
                .iter()
                .any(|i| a < i.disarm.unwrap_or(u64::MAX) && b > i.arm);
            if in_flight {
                note(b - a, a);
            }
        }
        // An instance with no sample at all is a missing input, which R4 fails elsewhere.
        let (Some(&first), Some(&last)) = (ts.first(), ts.last()) else {
            continue;
        };
        for i in armed {
            // No sample at or before the ARM: unseen from the ARM to the first sample, or to the
            // DISARM when that comes first.
            if first > i.arm {
                let end = i.disarm.map_or(first, |d| d.min(first));
                note(end - i.arm, i.arm);
            }
            // No sample at or after the DISARM: unseen from the last sample (or the ARM, if the
            // last sample precedes it) to the DISARM.
            if let Some(d) = i.disarm
                && last < d
            {
                note(d - last.max(i.arm), last.max(i.arm));
            }
        }
    }
    longest.map(|(g, t)| (count, g, t))
}

/// Hazard-class flags ([`HAZARD_FLAGS`]) true on every `failsafe_flags` sample of a flight (an
/// armed interval, through the sample that disarms), on any instance: (name, ARM time, samples).
fn hazard_whole_flight(f: &FlightLog, armed: &[ArmedInterval]) -> Vec<(String, u64, usize)> {
    let mut out = Vec::new();
    let all = std::iter::once(&f.failsafe_flags).chain(&f.failsafe_flags_others);
    for fs in all {
        let rows = crate::events::sorted_by_time(&fs.rows);
        for (i, def) in fs.flags.iter().enumerate() {
            if !HAZARD_FLAGS.iter().any(|(n, _)| *n == def.name) {
                continue;
            }
            for a in armed {
                let samples: Vec<bool> = rows
                    .iter()
                    .filter(|r| r.id.ts >= a.arm && a.disarm.is_none_or(|d| r.id.ts <= d))
                    .map(|r| r.active.get(i).copied().unwrap_or(false))
                    .collect();
                if !samples.is_empty() && samples.iter().all(|&b| b) {
                    out.push((def.name.clone(), a.arm, samples.len()));
                }
            }
        }
    }
    out.sort();
    out.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1);
    out
}

#[derive(Default)]
struct FlagSeen {
    /// Samples where the current mode requires it, the first time, and that mode.
    required: usize,
    first_required: Option<(u64, u8)>,
    /// Samples where the mode does not require it, and the first time.
    other: usize,
    first_other: Option<u64>,
}

/// Every failsafe_flags flag true in flight, on every instance: whether the `nav_state` in
/// effect requires it (its `mode_req_*` bit), as PX4 decides whether a mode can run.
fn flags_in_flight(f: &FlightLog, armed: &[ArmedInterval]) -> BTreeMap<String, FlagSeen> {
    let instances = f.vehicle_status_instances();
    let mut out: BTreeMap<String, FlagSeen> = BTreeMap::new();
    let all: Vec<&FailsafeFlags> = std::iter::once(&f.failsafe_flags)
        .chain(&f.failsafe_flags_others)
        .collect();
    for fs in all {
        // nav_state from the vehicle_status instance of the same number, else the lowest.
        let vs: &[VehicleStatusRow] = instances
            .iter()
            .find(|rows| rows.first().is_some_and(|r| r.id.instance == fs.multi_id))
            .or(instances.first())
            .copied()
            .unwrap_or(&[]);
        let mut nav: Vec<(u64, u8)> = vs
            .iter()
            .filter_map(|r| r.nav_state.map(|n| (r.id.ts, n)))
            .collect();
        nav.sort_by_key(|(t, _)| *t);
        let rows = crate::events::sorted_by_time(&fs.rows);
        for row in rows.iter() {
            let t = row.id.ts;
            if !in_flight_sample(armed, t) {
                continue;
            }
            let k = nav.partition_point(|(ts, _)| *ts <= t);
            let mode = k.checked_sub(1).and_then(|i| nav.get(i)).map(|(_, n)| *n);
            let bit = mode
                .and_then(|n| 1u32.checked_shl(u32::from(n)))
                .unwrap_or(0);
            for (i, def) in fs.flags.iter().enumerate() {
                if !row.active.get(i).copied().unwrap_or(false) {
                    continue;
                }
                let seen = out.entry(def.name.clone()).or_default();
                let required = row.mode_req.get(i).is_some_and(|m| m & bit != 0);
                match (required, mode) {
                    (true, Some(n)) => {
                        seen.required += 1;
                        seen.first_required.get_or_insert((t, n));
                    }
                    _ => {
                        seen.other += 1;
                        seen.first_other.get_or_insert(t);
                    }
                }
            }
        }
    }
    out
}

/// R4 cannot evaluate a flight whose `vehicle_status.nav_state` in flight is at or above
/// `NAVIGATION_STATE_MAX` of every PX4 tag the log's version selects: no mode requirement names
/// such a state, so each flag would be read as not required and a required one demoted to a
/// warning. The highest `NAVIGATION_STATE_MAX` of those tags is the bound.
fn r4_nav_state_out_of_range(f: &FlightLog, fw: &crate::ingest::Firmware) -> Option<RuleResult> {
    let releases = crate::px4::releases_for(fw);
    let max = releases
        .iter()
        .filter_map(|r| crate::px4::constant(r, "VehicleStatus", "NAVIGATION_STATE_MAX"))
        .max()?;
    let armed = flight_armed_intervals(f);
    let row = f.vehicle_status.iter().find(|r| {
        in_flight_sample(&armed, r.id.ts) && r.nav_state.is_some_and(|n| i64::from(n) >= max)
    })?;
    Some(fail_unreadable(
        "R4",
        R4_NAME,
        R4_EXPECTED,
        vec![format!(
            "vehicle_status.nav_state is {} in flight at boot_us {}, at or above NAVIGATION_STATE_MAX ({max}) of PX4 {}",
            row.nav_state.unwrap_or(0),
            row.id.ts,
            crate::px4::tags_label(&releases)
        )],
    ))
}

const R4_NAME: &str = "no failsafe in flight";
const R4_EXPECTED: &str = "vehicle_status.failsafe false in flight (from ARM through the sample that disarms), no quadchute (fixed wing straight to multicopter) in flight, and no failsafe_flags flag that the current nav_state requires true in flight; other failsafe_flags flags true in flight are warnings";

fn r4(f: &FlightLog) -> RuleResult {
    const NAME: &str = R4_NAME;
    let expected = R4_EXPECTED;
    // SPEC B1.6: the quadchute half reads the VTOL state only on a VTOL vehicle (is_vtol true
    // on some sample). No vehicle_status, or no is_vtol field, counts as not VTOL here; R1
    // reports what is missing.
    let is_vtol = f.vehicle_status.iter().any(|r| r.is_vtol == Some(true));
    let mut needed = vec!["arming_state", "nav_state", "failsafe"];
    if is_vtol {
        needed.extend(["in_transition_mode", "in_transition_to_fw", "vehicle_type"]);
    }
    if let Some(r) = check_vehicle_status("R4", NAME, expected, f, &needed) {
        return r;
    }
    if f.failsafe_flags.rows.is_empty() {
        return fail_missing("R4", NAME, expected, vec!["failsafe_flags".into()]);
    }
    let wrong = f.mismatches("failsafe_flags", &[]);
    if !wrong.is_empty() {
        return fail_unreadable("R4", NAME, expected, wrong);
    }
    let armed = flight_armed_intervals(f);
    if armed.is_empty() {
        return RuleResult::new(
            "R4",
            NAME,
            Status::NotApplicable,
            expected,
            NO_ARMED_FLIGHT,
            vec![],
        );
    }
    let mut detail = Lines::new();
    let (mut failsafes, mut quadchutes) = (0usize, 0usize);
    for rows in f.vehicle_status_instances() {
        let Some(instance) = rows.first().map(|r| r.id.instance) else {
            continue;
        };
        let fs = crate::events::flags_for_instance(f, instance);
        let flag_rows = crate::events::sorted_by_time(&fs.rows);
        let mut active = false;
        let mut last_arm = None;
        let mut was_armed = false;
        let mut prev_vtol: Option<VtolState> = None;
        for r in rows {
            let armed = r.arming_state == Some(2);
            if armed && !was_armed {
                last_arm = Some(r.id.ts);
            }
            // The row that disarms still belongs to the flight: a failsafe that disarms the
            // vehicle (or appears together with the disarm) is a failsafe in flight.
            let in_flight = armed || was_armed;
            was_armed = armed;
            let now = in_flight && r.failsafe == Some(true);
            if now && !active {
                failsafes += 1;
                detail.push(|| {
                    let flags = attribute_failsafe(fs, &flag_rows, r.id.ts, r.nav_state, last_arm);
                    format!(
                        "failsafe in flight at boot_us {}{}: {}",
                        r.id.ts,
                        instance_note(instance),
                        flags.join(", ")
                    )
                });
            }
            active = now;
            // SPEC B1.5: a quadchute is not a transition; R4 reports it. PX4 raises the
            // quadchute failsafe only in some modes (failsafe.cpp), so the state change itself
            // is the signal. The disarming row is in flight here too, as for failsafes above.
            let vtol = vtol_state(r);
            if is_vtol
                && in_flight
                && prev_vtol == Some(VtolState::Fw)
                && vtol == Some(VtolState::Mc)
            {
                quadchutes += 1;
                detail.push(|| {
                    let flag = match flag_at(
                        fs,
                        &flag_rows,
                        "vtol_fixed_wing_system_failure",
                        r.id.ts,
                    ) {
                        Some(true) => "true",
                        Some(false) => "false",
                        None => "not logged",
                    };
                    format!(
                        "quadchute in flight at boot_us {}{}: fixed wing straight to multicopter, failsafe_flags.vtol_fixed_wing_system_failure {flag}",
                        r.id.ts,
                        instance_note(instance)
                    )
                });
            }
            if vtol.is_some() {
                prev_vtol = vtol;
            }
        }
    }
    // SPEC B1.6: every failsafe_flags flag true in flight. One the mode in effect requires
    // fails R4 whether or not PX4 raised vehicle_status.failsafe; any other is a warning.
    let flags = flags_in_flight(f, &armed);
    let gaps = failsafe_flags_gaps(f, &armed);
    if let Some((n, g, t)) = gaps {
        detail.push(|| {
            format!(
                "warning: failsafe_flags has {n} gap(s) over {} ms in flight (between samples, or between the ARM or the DISARM and the nearest sample), the longest {} ms from boot_us {t}: R4 did not see the flags in those gaps",
                FAILSAFE_FLAGS_MAX_GAP_US / 1000,
                g / 1000
            )
        });
    }
    let hazards = hazard_whole_flight(f, &armed);
    for (name, arm, n) in &hazards {
        detail.push(|| {
            format!(
                "failsafe_flags.{name} true for the whole flight armed at boot_us {arm} ({n} sample(s)), a hazard flag"
            )
        });
    }
    let mut hazard_names: Vec<&str> = hazards.iter().map(|(n, _, _)| n.as_str()).collect();
    hazard_names.dedup();
    let mut required = Vec::new();
    let mut warned = Vec::new();
    for (name, seen) in &flags {
        if let Some((t, n)) = seen.first_required {
            required.push(name.as_str());
            detail.push(|| {
                format!(
                    "failsafe_flags.{name} true in flight from boot_us {t} ({} sample(s)), required by nav_state {n}",
                    seen.required
                )
            });
        }
        if let Some(t) = seen.first_other {
            warned.push(name.as_str());
            detail.push(|| {
                format!(
                    "warning: failsafe_flags.{name} true in flight from boot_us {t} ({} sample(s)), not required by the nav_state in effect",
                    seen.other
                )
            });
        }
    }
    // Fields of the logged failsafe_flags that no supported PX4 release defines: not read.
    let mut ignored: Vec<&str> = std::iter::once(&f.failsafe_flags)
        .chain(&f.failsafe_flags_others)
        .flat_map(|fs| fs.ignored.iter().map(String::as_str))
        .collect();
    ignored.sort_unstable();
    ignored.dedup();
    for name in ignored {
        detail.push(|| {
            format!("not read: failsafe_flags.{name} is not a field PX4 defines at any supported release")
        });
    }
    let mut warning = if warned.is_empty() {
        String::new()
    } else {
        format!(
            "; warning: failsafe_flags {} true in flight",
            warned.join(", ")
        )
    };
    if let Some((n, g, _)) = gaps {
        warning.push_str(&format!(
            "; warning: failsafe_flags {n} gap(s) over {} ms in flight, longest {} ms",
            FAILSAFE_FLAGS_MAX_GAP_US / 1000,
            g / 1000
        ));
    }
    let failed = failsafes + quadchutes + required.len() + hazard_names.len() > 0;
    let detail = detail.finish();
    if !failed {
        let status = if warned.is_empty() && gaps.is_none() {
            Status::Pass
        } else {
            Status::Warn
        };
        return RuleResult::new(
            "R4",
            NAME,
            status,
            expected,
            format!("never true in flight{warning}"),
            detail,
        );
    }
    // Only what happened, so no part of the line says "0" beside another that failed.
    let mut parts = Vec::new();
    if failsafes > 0 {
        parts.push(format!("true in flight {failsafes} time(s)"));
    }
    if quadchutes > 0 {
        parts.push(format!("quadchute {quadchutes} time(s)"));
    }
    if !required.is_empty() {
        parts.push(format!(
            "required failsafe_flags {} true in flight",
            required.join(", ")
        ));
    }
    if !hazard_names.is_empty() {
        parts.push(format!(
            "hazard failsafe_flags {} true for the whole flight",
            hazard_names.join(", ")
        ));
    }
    let mut found = parts.join(", ");
    found.push_str(&warning);
    RuleResult::new("R4", NAME, Status::Fail, expected, found, detail)
}

/// " (instance N)" for a `vehicle_status` instance other than 0.
fn instance_note(instance: u8) -> String {
    if instance == 0 {
        String::new()
    } else {
        format!(" (vehicle_status instance {instance})")
    }
}

/// `" (log ended mid-record at byte N; K trailing bytes not parsed)"` for a log that ends in
/// the middle of a record, else empty: the end-of-log findings of R5 and R6 say the end is a cut.
fn ends_mid_record(f: &FlightLog) -> String {
    f.summary
        .truncated
        .map_or(String::new(), |t| format!(" ({})", t.line()))
}

fn r5(f: &FlightLog, events: &[Event]) -> RuleResult {
    const NAME: &str = "arm and disarm consistent";
    let expected = "every ARM followed by a DISARM; log does not end armed";
    if let Some(r) = check_vehicle_status("R5", NAME, expected, f, &["arming_state"]) {
        return r;
    }
    let mut detail = Lines::new();
    let mut open: BTreeMap<u8, &Event> = BTreeMap::new();
    let (mut arms, mut disarms) = (0usize, 0usize);
    for e in events {
        match e.kind {
            EventKind::Arm { .. } => {
                if let Some(prev) = open.insert(e.instance, e) {
                    detail.push(|| {
                        format!(
                            "ARM seq {} at boot_us {} has no DISARM",
                            prev.seq, prev.boot_us
                        )
                    });
                }
                arms += 1;
            }
            EventKind::Disarm { .. } => {
                if open.remove(&e.instance).is_none() {
                    detail.push(|| {
                        format!("DISARM seq {} at boot_us {} has no ARM", e.seq, e.boot_us)
                    });
                }
                disarms += 1;
            }
            _ => {}
        }
    }
    // A log cut in the middle of a record ends where its complete records end: armed there is
    // armed at the end, and the missing tail is no DISARM.
    let cut = ends_mid_record(f);
    for prev in open.values() {
        detail.push(|| {
            format!(
                "ARM seq {} at boot_us {} has no DISARM: the log ends armed{cut}",
                prev.seq, prev.boot_us
            )
        });
    }
    if arms == 0 && disarms == 0 {
        // SPEC B1.6: no flight is not a consistent flight; the record's status says so.
        return RuleResult::new(
            "R5",
            NAME,
            Status::NotApplicable,
            expected,
            NO_ARMED_FLIGHT,
            vec![],
        );
    }
    let instances = f.vehicle_status_instances().len();
    let across = if instances > 1 {
        format!(" across {instances} vehicle_status instances")
    } else {
        String::new()
    };
    if detail.total == 0 {
        RuleResult::new(
            "R5",
            NAME,
            Status::Pass,
            expected,
            format!("{arms} ARM, {disarms} DISARM{across}"),
            vec![],
        )
    } else {
        let found = format!("{} unmatched", detail.total);
        let detail = detail.finish();
        RuleResult::new("R5", NAME, Status::Fail, expected, found, detail)
    }
}

/// R6. On a VTOL vehicle its first detail line states the VTOL type.
fn r6(f: &FlightLog, events: &[Event], vtol: Option<&crate::ingest::VtolType>) -> RuleResult {
    const NAME: &str = "VTOL transitions completed";
    let expected = "every VTOL transition START has an END; none aborted";
    if let Some(r) = check_vehicle_status("R6", NAME, expected, f, &["is_vtol"]) {
        return r;
    }
    let wrong = f.mismatches("vehicle_status", &["system_type"]);
    if !wrong.is_empty() {
        return fail_unreadable("R6", NAME, expected, wrong);
    }
    if f.vehicle_status.iter().all(|r| r.is_vtol == Some(false)) {
        // A VTOL MAV_TYPE with is_vtol false on every sample: the two disagree, so whether the
        // vehicle is VTOL cannot be decided from the log.
        if let Some(t) = f
            .vehicle_status
            .iter()
            .filter_map(|r| r.system_type)
            .find(|t| VTOL_MAV_TYPES.contains(t))
        {
            return fail_unreadable(
                "R6",
                NAME,
                expected,
                vec![format!(
                    "vehicle_status.system_type is {t}, a VTOL MAV_TYPE, but is_vtol is false on every sample"
                )],
            );
        }
        let found = match f
            .vehicle_status
            .iter()
            .filter_map(|r| r.system_type)
            .find(|t| MAVLINK_ONLY_VTOL_MAV_TYPES.contains(t))
        {
            Some(t) => format!(
                "vehicle_status.is_vtol false on every sample; system_type {t} is a MAVLink VTOL MAV_TYPE that PX4's is_vtol does not count (v1.14 to v1.17)"
            ),
            None => "vehicle_status.is_vtol false on every sample".to_string(),
        };
        return RuleResult::new("R6", NAME, Status::NotApplicable, expected, found, vec![]);
    }
    if let Some(r) = check_vehicle_status(
        "R6",
        NAME,
        expected,
        f,
        &["in_transition_mode", "in_transition_to_fw", "vehicle_type"],
    ) {
        return with_vtol_type(r, vtol);
    }
    let mut detail = Lines::new();
    let mut open: BTreeMap<u8, &Event> = BTreeMap::new();
    let (mut starts, mut ends) = (0usize, 0usize);
    for e in events {
        match &e.kind {
            EventKind::VtolTransitionStart { .. } => {
                starts += 1;
                open.insert(e.instance, e);
            }
            EventKind::VtolTransitionEnd { .. } => {
                ends += 1;
                open.remove(&e.instance);
            }
            EventKind::VtolTransitionAbort { direction } => {
                detail.push(|| {
                    format!(
                        "VTOL_TRANSITION_ABORT {} seq {} at boot_us {}",
                        direction.as_str(),
                        e.seq,
                        e.boot_us
                    )
                });
                open.remove(&e.instance);
            }
            _ => {}
        }
    }
    let cut = ends_mid_record(f);
    for e in open.values() {
        if let EventKind::VtolTransitionStart { direction } = &e.kind {
            detail.push(|| {
                format!(
                    "VTOL_TRANSITION_START {} seq {} at boot_us {} has no END: the log ends in transition{cut}",
                    direction.as_str(),
                    e.seq,
                    e.boot_us
                )
            });
        }
    }
    let found = format!("{starts} START, {ends} END, {} problem(s)", detail.total);
    let status = if detail.total == 0 {
        Status::Pass
    } else {
        Status::Fail
    };
    let result = RuleResult::new("R6", NAME, status, expected, found, detail.finish());
    with_vtol_type(result, vtol)
}

/// R6's first detail line on a VTOL vehicle: its type, also when the rule fails for a missing
/// field.
fn with_vtol_type(mut r: RuleResult, vtol: Option<&crate::ingest::VtolType>) -> RuleResult {
    if let Some(t) = vtol {
        let value = t.value.map_or(String::new(), |v| format!(" (VT_TYPE {v})"));
        r.detail.insert(0, format!("VTOL type {}{value}", t.name));
    }
    r
}

fn in_armed(armed: &[ArmedInterval], t: u64) -> bool {
    armed_sample(armed, t)
}

/// Index of the armed interval holding a sample at `t`.
fn armed_index(armed: &[ArmedInterval], t: u64) -> Option<usize> {
    let n = armed.partition_point(|a| a.arm <= t);
    let i = n.checked_sub(1)?;
    armed.get(i).filter(|a| a.contains_sample(t)).map(|_| i)
}

/// What an X rule needs before it can look at its own data: a readable `arming_state`, at
/// least one armed interval, and its own fields in the types PX4 defines.
fn need_armed(
    id: &'static str,
    name: &'static str,
    expected: &str,
    f: &FlightLog,
    armed: &[ArmedInterval],
    fields: &[(&str, &[&str])],
) -> Option<RuleResult> {
    if let Some(r) = check_vehicle_status(id, name, expected, f, &["arming_state"]) {
        return Some(r);
    }
    let wrong: Vec<String> = fields
        .iter()
        .flat_map(|(topic, names)| f.mismatches(topic, names))
        .collect();
    if !wrong.is_empty() {
        return Some(fail_unreadable(id, name, expected, wrong));
    }
    if armed.is_empty() {
        return Some(RuleResult::new(
            id,
            name,
            Status::Fail,
            expected,
            "the vehicle never armed, so there is no flight to check",
            vec![],
        ));
    }
    None
}

/// R7, authorized command sources: every COMMAND event (of the configured category, if any)
/// came from a listed MAVLink source. N/A without `[authorized_sources]`; FAIL when the
/// `vehicle_command` data it reads is missing or unreadable (SPEC B1.6: missing input is FAIL).
fn r7(f: &FlightLog, events: &[Event], rules: &Rules) -> RuleResult {
    const NAME: &str = "authorized command sources";
    let Some(auth) = &rules.authorized_sources else {
        return RuleResult::new(
            "R7",
            NAME,
            Status::NotApplicable,
            "every COMMAND event from a source in [authorized_sources]",
            "no [authorized_sources] in the rules file",
            vec![],
        );
    };
    let listed: Vec<String> = auth
        .sources
        .iter()
        .map(|s| format!("{}/{}", s.system, s.component))
        .collect();
    let scope = auth
        .category
        .map_or("every COMMAND event".to_string(), |c| {
            format!("every {} COMMAND event", c.as_str())
        });
    let expected = format!(
        "{scope} from an authorized source (system/component {})",
        listed.join(", ")
    );
    let rows = f.topic_rows.get(R7_TOPIC).copied().unwrap_or(0);
    let missing: Vec<String> = if rows == 0 {
        vec![R7_TOPIC.to_string()]
    } else {
        VEHICLE_COMMAND_FIELDS
            .iter()
            .filter(|x| !f.vehicle_command_fields.iter().any(|h| h == *x))
            .map(|x| format!("{R7_TOPIC}.{x}"))
            .collect()
    };
    if !missing.is_empty() {
        return fail_missing("R7", NAME, &expected, missing);
    }
    let wrong = f.mismatches(R7_TOPIC, &VEHICLE_COMMAND_FIELDS);
    if !wrong.is_empty() {
        return fail_unreadable("R7", NAME, &expected, wrong);
    }
    // The ingest keeps only the samples whose three fields have the types PX4 defines.
    let read = f.commands.len() as u64;
    if read != rows {
        return RuleResult::new(
            "R7",
            NAME,
            Status::Fail,
            expected,
            format!(
                "cannot evaluate: {} of {rows} {R7_TOPIC} record(s) have a command, source_system or source_component that cannot be read",
                rows - read
            ),
            vec![],
        );
    }
    let mut detail = Lines::new();
    let (mut checked, mut excluded) = (0usize, 0usize);
    for e in events {
        let EventKind::Command {
            command,
            source_system,
            source_component,
            ..
        } = &e.kind
        else {
            continue;
        };
        let category = rules.category(*command);
        if auth.category.is_some_and(|c| c != category) {
            excluded += 1;
            continue;
        }
        checked += 1;
        let ok = auth.sources.iter().any(|s| {
            u64::from(s.system) == *source_system && u64::from(s.component) == *source_component
        });
        if !ok {
            detail.push(|| {
                format!(
                    "event seq {}: command {command} ({}) from system {source_system} component {source_component} at boot_us {}",
                    e.seq,
                    category.as_str(),
                    e.boot_us
                )
            });
        }
    }
    let scope_note = format!(
        "scope {}, {excluded} excluded by scope; source ids are self-reported by the sender",
        auth.category
            .map_or("every category".to_string(), |c| format!(
                "{} only",
                c.as_str()
            ))
    );
    let bad = detail.total;
    let (status, found) = if bad == 0 {
        (
            Status::Pass,
            format!("{checked} command(s) checked, all from authorized sources; {scope_note}"),
        )
    } else {
        (
            Status::Fail,
            format!("{bad} of {checked} command(s) from unauthorized sources; {scope_note}"),
        )
    };
    RuleResult::new("R7", NAME, status, expected, found, detail.finish())
}

fn x1(f: &FlightLog, armed: &[ArmedInterval], t: &crate::rules::MinBattery) -> RuleResult {
    let (id, name) = ("X1", "minimum battery");
    let expected = format!(
        "battery_status.remaining >= {} while armed (threshold set by your flight-test lead)",
        t.min_remaining.text
    );
    if let Some(r) = need_armed(
        id,
        name,
        &expected,
        f,
        armed,
        &[("battery_status", &["remaining", "connected"])],
    ) {
        return r;
    }
    let mut min: Option<(f32, u64, u8)> = None;
    for b in &f.battery {
        if !in_armed(armed, b.id.ts) || b.connected == Some(false) {
            continue;
        }
        // PX4 reports -1 when the remaining capacity is unknown (battery_status.msg).
        let Some(rem) = b.remaining.filter(|r| r.is_finite() && *r >= 0.0) else {
            continue;
        };
        if min.is_none_or(|(m, _, _)| rem < m) {
            min = Some((rem, b.id.ts, b.id.instance));
        }
    }
    match min {
        None => fail_missing(
            id,
            name,
            &expected,
            vec!["battery_status.remaining samples while armed".into()],
        ),
        Some((m, ts, inst)) => {
            let shown = f32_shortest(m);
            let found = format!("minimum {shown} (instance {inst}, boot_us {ts})");
            // Compare in float32, the type of the logged value, so the message cannot say a
            // reading shown equal to the threshold is below it.
            let status = if m >= t.min_remaining.value as f32 {
                Status::Pass
            } else {
                Status::Fail
            };
            let detail = if status == Status::Fail {
                vec![format!(
                    "remaining {shown} at boot_us {ts}, below {}",
                    t.min_remaining.text
                )]
            } else {
                vec![]
            };
            RuleResult::new(id, name, status, expected, found, detail)
        }
    }
}

fn x2(
    f: &FlightLog,
    events: &[Event],
    armed: &[ArmedInterval],
    t: &crate::rules::GpsFixAtArm,
) -> RuleResult {
    let (id, name) = ("X2", "GPS fix at arm");
    let expected = format!(
        "at each ARM, vehicle_gps_position fix_type >= {} and satellites_used >= {} (thresholds set by your flight-test lead)",
        t.min_fix_type, t.min_satellites
    );
    if let Some(r) = need_armed(
        id,
        name,
        &expected,
        f,
        armed,
        &[("vehicle_gps_position", &["fix_type", "satellites_used"])],
    ) {
        return r;
    }
    let mut rows = f.vehicle_gps.clone();
    rows.sort_by_key(|g| (g.id.ts, g.id.index));
    let mut detail = Lines::new();
    let mut found = Vec::new();
    let mut arms = 0usize;
    for e in events
        .iter()
        .filter(|e| matches!(e.kind, EventKind::Arm { .. }))
    {
        arms += 1;
        let n = rows.partition_point(|g| g.id.ts <= e.boot_us);
        let sample = n.checked_sub(1).and_then(|i| rows.get(i));
        match sample.map(|g| (g.fix_type, g.satellites_used)) {
            Some((Some(fix), Some(sats))) => {
                let line = || format!("ARM at boot_us {}: fix_type {fix}, satellites_used {sats}", e.boot_us);
                if found.len() < 5 {
                    found.push(line());
                }
                if fix < t.min_fix_type || sats < t.min_satellites {
                    detail.push(line);
                }
            }
            _ => detail.push(|| format!("ARM at boot_us {}: no vehicle_gps_position sample with fix_type and satellites_used at or before it", e.boot_us)),
        }
    }
    let status = if detail.total == 0 {
        Status::Pass
    } else {
        Status::Fail
    };
    let found = match (arms, found.is_empty()) {
        (_, true) => "no GPS sample at any ARM".to_string(),
        (n, false) if n <= 5 => found.join("; "),
        (n, false) => format!("{n} ARMs checked; first: {}", found.join("; ")),
    };
    RuleResult::new(id, name, status, expected, found, detail.finish())
}

fn x3(f: &FlightLog, armed: &[ArmedInterval]) -> RuleResult {
    let (id, name) = ("X3", "estimator fault flags");
    let expected = "estimator_status.filter_fault_flags 0 on the primary estimator while armed";
    if let Some(r) = need_armed(
        id,
        name,
        expected,
        f,
        armed,
        &[
            ("estimator_status", &["filter_fault_flags"]),
            ("estimator_selector_status", &["primary_instance"]),
        ],
    ) {
        return r;
    }
    let mut selector = f.estimator_selector.clone();
    selector.sort_by_key(|s| (s.id.ts, s.id.index));
    let primary_at = |t: u64| -> u8 {
        let n = selector.partition_point(|s| s.id.ts <= t);
        n.checked_sub(1)
            .and_then(|i| selector.get(i))
            .and_then(|s| s.primary_instance)
            .unwrap_or(0)
    };
    let mut checked = 0usize;
    // Estimator samples are not events; the found text counts every one.
    let mut detail = Lines::with_rest("the count above includes every sample");
    for e in &f.estimator {
        if !in_armed(armed, e.id.ts) || e.id.instance != primary_at(e.id.ts) {
            continue;
        }
        let Some(flags) = e.filter_fault_flags else {
            continue;
        };
        checked += 1;
        if flags != 0 {
            detail.push(|| {
                format!(
                    "filter_fault_flags 0x{flags:x} on instance {} at boot_us {}",
                    e.id.instance, e.id.ts
                )
            });
        }
    }
    if checked == 0 {
        return fail_missing(
            id,
            name,
            expected,
            vec![
                "estimator_status.filter_fault_flags samples on the primary estimator while armed"
                    .into(),
            ],
        );
    }
    let status = if detail.total == 0 {
        Status::Pass
    } else {
        Status::Fail
    };
    let found = if detail.total == 0 {
        format!("0 on all {checked} samples")
    } else {
        format!("nonzero on {} of {checked} samples", detail.total)
    };
    RuleResult::new(id, name, status, expected, found, detail.finish())
}

fn x4(f: &FlightLog, armed: &[ArmedInterval], t: &crate::rules::Vibration) -> RuleResult {
    let (id, name) = ("X4", "vibration and clipping");
    let expected = format!(
        "accel_vibration_metric <= {} and accel_clipping increase <= {} on the selected accelerometer while armed (thresholds set by your flight-test lead)",
        t.max_accel_vibration_metric.text, t.max_accel_clipping
    );
    if let Some(r) = need_armed(
        id,
        name,
        &expected,
        f,
        armed,
        &[
            (
                "vehicle_imu_status",
                &[
                    "accel_device_id",
                    "accel_clipping[0]",
                    "accel_clipping[1]",
                    "accel_clipping[2]",
                    "accel_vibration_metric",
                ],
            ),
            ("sensor_selection", &["accel_device_id"]),
        ],
    ) {
        return r;
    }
    let mut sel = f.sensor_selection.clone();
    sel.sort_by_key(|s| (s.id.ts, s.id.index));
    let device_at = |ts: u64| {
        let n = sel.partition_point(|s| s.id.ts <= ts);
        n.checked_sub(1)
            .and_then(|i| sel.get(i))
            .and_then(|s| s.accel_device_id)
    };
    let mut max_vib: Option<(f32, u64)> = None;
    let mut clip_increase: u64 = 0;
    // Last clipping total per IMU instance: (armed interval, total). A delta is counted only
    // between consecutive samples of the selected accelerometer within one armed interval, so
    // clipping while disarmed or while another accelerometer was selected is not counted.
    let mut prev: BTreeMap<u8, (usize, u64)> = BTreeMap::new();
    let mut samples = 0usize;
    for r in &f.imu {
        let Some(interval) = armed_index(armed, r.id.ts) else {
            prev.remove(&r.id.instance);
            continue;
        };
        let selected = device_at(r.id.ts).is_some_and(|dev| r.accel_device_id == Some(dev));
        if !selected {
            prev.remove(&r.id.instance);
            continue;
        }
        samples += 1;
        if let Some(v) = r.accel_vibration_metric.filter(|v| v.is_finite())
            && max_vib.is_none_or(|(m, _)| v > m)
        {
            max_vib = Some((v, r.id.ts));
        }
        if let Some(c) = r.accel_clipping {
            let total = c.iter().fold(0u64, |a, b| a.saturating_add(*b));
            if let Some((k, p)) = prev.insert(r.id.instance, (interval, total))
                && k == interval
            {
                // A counter that went down was reset; everything it now holds is new.
                let delta = if total >= p { total - p } else { total };
                clip_increase = clip_increase.saturating_add(delta);
            }
        } else {
            prev.remove(&r.id.instance);
        }
    }
    let Some((vib, vib_ts)) = max_vib.filter(|_| samples > 0) else {
        return fail_missing(
            id,
            name,
            &expected,
            vec![
                "vehicle_imu_status samples for the accelerometer in sensor_selection while armed"
                    .into(),
            ],
        );
    };
    let shown = f32_shortest(vib);
    let mut detail = Vec::new();
    if vib > t.max_accel_vibration_metric.value as f32 {
        detail.push(format!(
            "accel_vibration_metric {shown} at boot_us {vib_ts}, above {}",
            t.max_accel_vibration_metric.text
        ));
    }
    if clip_increase > t.max_accel_clipping {
        detail.push(format!(
            "accel_clipping increased by {clip_increase}, above {}",
            t.max_accel_clipping
        ));
    }
    let found = format!(
        "max accel_vibration_metric {shown} (boot_us {vib_ts}), accel_clipping increase {clip_increase}"
    );
    let status = if detail.is_empty() {
        Status::Pass
    } else {
        Status::Fail
    };
    RuleResult::new(id, name, status, expected, found, detail)
}

fn x5(f: &FlightLog, t: &crate::rules::Dropouts) -> RuleResult {
    let expected = format!(
        "total dropout time <= {} ms (threshold set by your flight-test lead)",
        t.max_total_ms
    );
    let total = f
        .dropouts
        .iter()
        .fold(0u64, |a, d| a.saturating_add(u64::from(d.duration_ms)));
    let found = format!("{} dropout(s), {total} ms in total", f.dropouts.len());
    let (status, detail) = if total <= t.max_total_ms {
        (Status::Pass, vec![])
    } else {
        (
            Status::Fail,
            vec![format!(
                "{total} ms of dropouts, above {} ms",
                t.max_total_ms
            )],
        )
    };
    RuleResult::new("X5", "total dropout time", status, expected, found, detail)
}

/// Evaluates the core rules and the enabled optional rules.
pub fn evaluate(ing: &Ingested, rules: &Rules, baseline: &Baseline) -> Evaluation {
    let f = &ing.flight;
    let armed = flight_armed_intervals(f);
    let mut results = vec![
        r1(f, &ing.identity.firmware, rules),
        r2(ing, baseline),
        r3(ing, rules, baseline),
        r4_nav_state_out_of_range(f, &ing.identity.firmware).unwrap_or_else(|| r4(f)),
        r5(f, &ing.events),
        r6(f, &ing.events, ing.identity.vehicle.vtol_type.as_ref()),
        r7(f, &ing.events, rules),
    ];
    let x = &rules.extended;
    if let Some(t) = &x.min_battery {
        results.push(x1(f, &armed, t));
    }
    if let Some(t) = &x.gps_fix_at_arm {
        results.push(x2(f, &ing.events, &armed, t));
    }
    if x.estimator_faults {
        results.push(x3(f, &armed));
    }
    if let Some(t) = &x.vibration {
        results.push(x4(f, &armed, t));
    }
    if let Some(t) = &x.dropouts {
        results.push(x5(f, t));
    }
    let status = Overall::of(results.iter().map(|r| (r.id, r.status)));
    let r1_fail = results.first().is_some_and(|r| r.status == Status::Fail);
    let exit_code = match status {
        _ if r1_fail => exit_code::MISSING_TOPIC,
        Overall::Fail | Overall::NoArmedFlight => exit_code::RULE_FAIL,
        Overall::Pass | Overall::Warn => exit_code::OK,
    };
    Evaluation {
        results,
        status,
        exit_code,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::ingest::{FailsafeFlags, FailsafeRow, RowId, VehicleStatusRow};

    /// The flight with one failsafe_flags sample (no flag set) when it has none: R4 needs
    /// failsafe_flags data.
    fn with_flags(mut f: FlightLog) -> FlightLog {
        if f.failsafe_flags.rows.is_empty() {
            f.failsafe_flags = FailsafeFlags {
                rows: vec![FailsafeRow {
                    id: RowId {
                        ts: 0,
                        instance: 0,
                        index: 0,
                    },
                    active: vec![].into(),
                    mode_req: vec![].into(),
                }],
                ..FailsafeFlags::default()
            };
        }
        f
    }

    fn vtol_row(i: u64, arming: u8, trans: bool, to_fw: bool, vtype: u8) -> VehicleStatusRow {
        VehicleStatusRow {
            id: RowId {
                ts: i * 10,
                instance: 0,
                index: i,
            },
            file_order: 0,
            arming_state: Some(arming),
            nav_state: Some(0),
            failsafe: Some(false),
            is_vtol: Some(true),
            in_transition_mode: Some(trans),
            in_transition_to_fw: Some(to_fw),
            vehicle_type: Some(vtype),
            system_type: Some(22),
            latest_arming_reason: None,
            latest_disarming_reason: None,
        }
    }

    #[test]
    fn r4_reports_a_quadchute_even_without_vehicle_status_failsafe() {
        let fields: Vec<String> = VEHICLE_STATUS_FIELDS
            .iter()
            .map(|s| s.to_string())
            .collect();
        // MC, to FW, FW, straight back to MC (quadchute), all armed, failsafe never set.
        let rows = vec![
            vtol_row(0, 2, false, false, 1),
            vtol_row(1, 2, true, true, 1),
            vtol_row(2, 2, false, false, 2),
            vtol_row(3, 2, false, false, 1),
        ];
        let flight = FlightLog {
            vehicle_status: rows,
            vehicle_status_fields: fields.clone(),
            ..FlightLog::default()
        };
        let r = r4(&with_flags(flight.clone()));
        assert_eq!(r.status, Status::Fail);
        assert_eq!(r.found, "quadchute 1 time(s)");
        assert_eq!(
            r.detail,
            [
                "quadchute in flight at boot_us 30: fixed wing straight to multicopter, failsafe_flags.vtol_fixed_wing_system_failure not logged"
            ]
        );
        // A completed back transition (FW, to MC, MC) is not a quadchute, nor is one while disarmed.
        let rows = vec![
            vtol_row(0, 2, false, false, 2),
            vtol_row(1, 2, true, false, 1),
            vtol_row(2, 2, false, false, 1),
            vtol_row(3, 1, false, false, 2),
            vtol_row(4, 1, false, false, 1),
        ];
        let flight = FlightLog {
            vehicle_status: rows,
            vehicle_status_fields: fields,
            ..FlightLog::default()
        };
        assert_eq!(r4(&with_flags(flight.clone())).status, Status::Pass);
    }

    #[test]
    fn r4_counts_a_failsafe_that_disarms_the_vehicle() {
        let fields: Vec<String> = VEHICLE_STATUS_FIELDS
            .iter()
            .map(|s| s.to_string())
            .collect();
        let mut rows = vec![
            vtol_row(0, 2, false, false, 1),
            vtol_row(1, 1, false, false, 1),
        ];
        rows[1].failsafe = Some(true); // failsafe first appears on the row that disarms
        let flight = FlightLog {
            vehicle_status: rows,
            vehicle_status_fields: fields,
            ..FlightLog::default()
        };
        let r = r4(&with_flags(flight.clone()));
        assert_eq!(r.status, Status::Fail);
        assert!(
            r.detail[0].starts_with("failsafe in flight at boot_us 10"),
            "{:?}",
            r.detail
        );
    }

    #[test]
    fn r4_needs_the_vtol_state_only_on_a_vtol_vehicle() {
        let fields = |drop: &str| -> Vec<String> {
            VEHICLE_STATUS_FIELDS
                .iter()
                .filter(|f| **f != drop)
                .map(|s| s.to_string())
                .collect()
        };
        let row = |ts: u64, vtol: bool| {
            let mut r = vtol_row(ts, 2, false, false, 1);
            r.is_vtol = Some(vtol);
            r.vehicle_type = None;
            r
        };
        // Not VTOL and no vehicle_type: R4 does not need it (R1 reports it).
        let flight = FlightLog {
            vehicle_status: vec![row(0, false), row(1, false)],
            vehicle_status_fields: fields("vehicle_type"),
            ..FlightLog::default()
        };
        assert_eq!(r4(&with_flags(flight.clone())).status, Status::Pass);
        // VTOL and no vehicle_type: missing input, FAIL.
        let flight = FlightLog {
            vehicle_status: vec![row(0, true), row(1, true)],
            vehicle_status_fields: fields("vehicle_type"),
            ..FlightLog::default()
        };
        let r = r4(&with_flags(flight.clone()));
        assert_eq!(r.status, Status::Fail);
        assert_eq!(r.detail, ["missing vehicle_status.vehicle_type"]);
        // Not VTOL: a fixed wing to multicopter change in flight is not read as a quadchute.
        let mut rows = vec![
            vtol_row(0, 2, false, false, 1),
            vtol_row(1, 2, false, false, 2),
            vtol_row(2, 2, false, false, 1),
        ];
        for r in &mut rows {
            r.is_vtol = Some(false);
        }
        let flight = FlightLog {
            vehicle_status: rows,
            vehicle_status_fields: fields(""),
            ..FlightLog::default()
        };
        assert_eq!(r4(&with_flags(flight.clone())).status, Status::Pass);
        // No is_vtol field counts as not VTOL.
        let mut rows = vec![row(0, false), row(1, false)];
        for r in &mut rows {
            r.is_vtol = None;
        }
        let flight = FlightLog {
            vehicle_status: rows,
            vehicle_status_fields: fields("is_vtol")
                .into_iter()
                .filter(|f| f != "vehicle_type")
                .collect(),
            ..FlightLog::default()
        };
        assert_eq!(r4(&with_flags(flight.clone())).status, Status::Pass);
    }

    #[test]
    fn r4_counts_a_quadchute_on_the_row_that_disarms() {
        let fields: Vec<String> = VEHICLE_STATUS_FIELDS
            .iter()
            .map(|s| s.to_string())
            .collect();
        // MC, to FW, FW, then disarmed and multicopter on the same row.
        let rows = vec![
            vtol_row(0, 2, false, false, 1),
            vtol_row(1, 2, true, true, 1),
            vtol_row(2, 2, false, false, 2),
            vtol_row(3, 1, false, false, 1),
        ];
        let flight = FlightLog {
            vehicle_status: rows,
            vehicle_status_fields: fields,
            ..FlightLog::default()
        };
        let r = r4(&with_flags(flight.clone()));
        assert_eq!(r.status, Status::Fail);
        assert_eq!(r.found, "quadchute 1 time(s)");
    }

    #[test]
    fn x4_counts_clipping_only_on_the_selected_accelerometer_while_armed() {
        use crate::ingest::{ImuRow, SensorSelectionRow};
        use crate::rules::{Threshold, Vibration};
        let imu = |ts: u64, i: u64, inst: u8, dev: u64, clip: u64| ImuRow {
            id: RowId {
                ts,
                instance: inst,
                index: i,
            },
            accel_device_id: Some(dev),
            accel_clipping: Some([clip, 0, 0]),
            accel_vibration_metric: Some(1.0),
        };
        let armed = [
            ArmedInterval {
                arm: 0,
                arm_order: 0,
                disarm: Some(100),
            },
            ArmedInterval {
                arm: 200,
                arm_order: 0,
                disarm: Some(300),
            },
        ];
        let flight = FlightLog {
            vehicle_status: vec![vtol_row(0, 2, false, false, 1)],
            vehicle_status_fields: VEHICLE_STATUS_FIELDS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            sensor_selection: vec![
                SensorSelectionRow {
                    id: RowId {
                        ts: 0,
                        instance: 0,
                        index: 0,
                    },
                    accel_device_id: Some(7),
                },
                SensorSelectionRow {
                    id: RowId {
                        ts: 250,
                        instance: 0,
                        index: 1,
                    },
                    accel_device_id: Some(8),
                },
            ],
            imu: vec![
                imu(10, 0, 0, 7, 0),
                imu(50, 1, 0, 7, 2),   // +2 while armed and selected
                imu(150, 2, 0, 7, 40), // disarmed: +38 not counted
                imu(210, 3, 0, 7, 41), // new interval: no delta across the gap
                imu(260, 4, 0, 7, 90), // instance 0 no longer selected: not counted
                imu(260, 0, 1, 8, 5),
                imu(280, 1, 1, 8, 6), // +1 on the newly selected accelerometer
            ],
            ..FlightLog::default()
        };
        let t = Vibration {
            max_accel_vibration_metric: Threshold {
                value: 3.0,
                text: "3.0".into(),
            },
            max_accel_clipping: 2,
        };
        let r = x4(&flight, &armed, &t);
        assert!(
            r.found.ends_with("accel_clipping increase 3"),
            "{}",
            r.found
        );
        assert_eq!(r.status, Status::Fail);
    }

    #[test]
    fn r4_lists_at_most_the_detail_cap_and_counts_the_rest() {
        let run = |n: u64| {
            let rows = (0..n)
                .map(|i| VehicleStatusRow {
                    id: RowId {
                        ts: i,
                        instance: 0,
                        index: i,
                    },
                    file_order: 0,
                    arming_state: Some(2),
                    nav_state: Some(4),
                    failsafe: Some(i % 2 == 0),
                    is_vtol: Some(false),
                    in_transition_mode: Some(false),
                    in_transition_to_fw: Some(false),
                    vehicle_type: Some(1),
                    system_type: Some(2),
                    latest_arming_reason: None,
                    latest_disarming_reason: None,
                })
                .collect();
            let fields = VEHICLE_STATUS_FIELDS
                .iter()
                .map(|s| s.to_string())
                .collect();
            let flight = FlightLog {
                vehicle_status: rows,
                vehicle_status_fields: fields,
                ..FlightLog::default()
            };
            r4(&with_flags(flight.clone()))
        };
        // Every second sample is a failsafe: 3000 samples give 1500 cases.
        let r = run(3000);
        assert_eq!(r.status, Status::Fail);
        assert_eq!(r.found, "true in flight 1500 time(s)");
        assert_eq!(r.detail.len(), MAX_DETAIL_LINES + 1);
        assert_eq!(
            r.detail.last().map(String::as_str),
            Some("and 500 more; the events list every one")
        );
        // Exactly at the cap: every case is listed and no line says more follow.
        let r = run(2 * MAX_DETAIL_LINES as u64);
        assert_eq!(r.found, "true in flight 1000 time(s)");
        assert_eq!(r.detail.len(), MAX_DETAIL_LINES);
        assert!(
            !r.detail.iter().any(|l| l.starts_with("and ")),
            "{:?}",
            r.detail.last()
        );
        // One case over: the cap's lines, then one more line.
        let r = run(2 * MAX_DETAIL_LINES as u64 + 1);
        assert_eq!(r.found, "true in flight 1001 time(s)");
        assert_eq!(r.detail.len(), MAX_DETAIL_LINES + 1);
        assert_eq!(
            r.detail.last().map(String::as_str),
            Some("and 1 more; the events list every one")
        );
    }

    #[test]
    fn r7_checks_command_sources_against_the_list_and_its_category() {
        use crate::ingest::{FlightLogIngestor, Px4Ingestor};
        use crate::ulog::tests::Builder;
        let cmd = |ts: u64, id: u32, sys: u8, comp: u16| {
            [
                &ts.to_le_bytes()[..],
                &id.to_le_bytes(),
                &[sys],
                &comp.to_le_bytes(),
            ]
            .concat()
        };
        let log = Builder::new(0)
            .flags(&[])
            .format("vehicle_command:uint64_t timestamp;uint32_t command;uint8_t source_system;uint16_t source_component;")
            .sub(0, 1, "vehicle_command")
            .data(1, &cmd(10, 176, 1, 1))
            .data(1, &cmd(20, 211, 2, 7))
            .data(1, &cmd(30, 187, 255, 190));
        let ing = Px4Ingestor
            .ingest(
                "x.ulg",
                &mut &log.bytes[..],
                &crate::crypto::test_backend::TestBackend,
            )
            .unwrap();
        let rules = |extra: &str| {
            crate::rules::parse_rules(&format!(
                "format = \"sfr-rules/1\"\n[required_topics]\ntopics = []\n[payload_commands]\nids = [187, 211]\n{extra}"
            ))
            .unwrap()
        };
        let na = r7(&ing.flight, &ing.events, &rules(""));
        assert_eq!(na.status, Status::NotApplicable);
        let all = r7(
            &ing.flight,
            &ing.events,
            &rules(
                "[authorized_sources]\nsources = [{ system = 1, component = 1 }, { system = 255, component = 190 }]\n",
            ),
        );
        assert_eq!(all.status, Status::Fail);
        assert_eq!(
            all.found,
            "1 of 3 command(s) from unauthorized sources; scope every category, 0 excluded by scope; source ids are self-reported by the sender"
        );
        assert_eq!(
            all.detail,
            ["event seq 1: command 211 (PAYLOAD) from system 2 component 7 at boot_us 20"]
        );
        // Scoped to GENERAL, the payload commands are not checked.
        let general = r7(
            &ing.flight,
            &ing.events,
            &rules(
                "[authorized_sources]\ncategory = \"GENERAL\"\nsources = [{ system = 1, component = 1 }]\n",
            ),
        );
        assert_eq!(general.status, Status::Pass);
        assert_eq!(
            general.found,
            "1 command(s) checked, all from authorized sources; scope GENERAL only, 2 excluded by scope; source ids are self-reported by the sender"
        );
        let payload = r7(
            &ing.flight,
            &ing.events,
            &rules(
                "[authorized_sources]\ncategory = \"PAYLOAD\"\nsources = [{ system = 2, component = 7 }]\n",
            ),
        );
        assert_eq!(payload.status, Status::Fail);
        assert_eq!(
            payload.found,
            "1 of 2 command(s) from unauthorized sources; scope PAYLOAD only, 1 excluded by scope; source ids are self-reported by the sender"
        );
    }

    #[test]
    fn r7_fails_and_r1_names_the_command_data_when_it_is_missing() {
        use crate::ingest::{FlightLogIngestor, Px4Ingestor};
        use crate::ulog::tests::Builder;
        let ingest = |log: Builder| {
            Px4Ingestor
                .ingest(
                    "x.ulg",
                    &mut &log.bytes[..],
                    &crate::crypto::test_backend::TestBackend,
                )
                .unwrap()
        };
        let rules = |r7: bool| {
            let extra = if r7 {
                "[authorized_sources]\nsources = [{ system = 1, component = 1 }]\n"
            } else {
                ""
            };
            crate::rules::parse_rules(&format!(
                "format = \"sfr-rules/1\"\n[required_topics]\ntopics = []\n{extra}"
            ))
            .unwrap()
        };
        let check = |ing: &Ingested, r1_missing: Option<&str>, r7_found: &str| {
            let r1 = r1(&ing.flight, &ing.identity.firmware, &rules(true));
            // R1 names exactly the vehicle_command item expected to be missing, or none.
            let named: Vec<&String> = r1
                .detail
                .iter()
                .filter(|d| d.contains("vehicle_command"))
                .collect();
            assert_eq!(
                named.iter().map(|d| d.as_str()).collect::<Vec<_>>(),
                r1_missing.map(|m| vec![m]).unwrap_or_default(),
                "{:?}",
                r1.detail
            );
            assert!(
                r1.expected
                    .ends_with("the fields the core rules and R7 read")
            );
            let r7 = r7(&ing.flight, &ing.events, &rules(true));
            assert_eq!(r7.status, Status::Fail);
            assert_eq!(r7.found, r7_found);
        };

        // No vehicle_command at all: no commands is no evidence, so R7 does not pass.
        let none = ingest(
            Builder::new(0)
                .flags(&[])
                .format("other_topic:uint64_t timestamp;")
                .sub(0, 1, "other_topic")
                .data(1, &10u64.to_le_bytes()),
        );
        check(
            &none,
            Some("missing vehicle_command"),
            "cannot evaluate: missing vehicle_command",
        );
        // Without [authorized_sources], R1 does not ask for it and R7 is N/A.
        assert!(
            !r1(&none.flight, &none.identity.firmware, &rules(false))
                .detail
                .iter()
                .any(|d| d.contains("vehicle_command"))
        );
        assert_eq!(
            r7(&none.flight, &none.events, &rules(false)).status,
            Status::NotApplicable
        );

        // A format without source_component.
        let no_field = ingest(
            Builder::new(0)
                .flags(&[])
                .format(
                    "vehicle_command:uint64_t timestamp;uint32_t command;uint8_t source_system;",
                )
                .sub(0, 1, "vehicle_command")
                .data(
                    1,
                    &[&10u64.to_le_bytes()[..], &176u32.to_le_bytes(), &[1]].concat(),
                ),
        );
        check(
            &no_field,
            Some("missing vehicle_command.source_component"),
            "cannot evaluate: missing vehicle_command.source_component",
        );

        // source_component present but not an unsigned integer: R1 sees the name, R7 cannot
        // read the value.
        let float = ingest(
            Builder::new(0)
                .flags(&[])
                .format("vehicle_command:uint64_t timestamp;uint32_t command;uint8_t source_system;float source_component;")
                .sub(0, 1, "vehicle_command")
                .data(
                    1,
                    &[&10u64.to_le_bytes()[..], &176u32.to_le_bytes(), &[1], &1f32.to_le_bytes()].concat(),
                ),
        );
        check(
            &float,
            None,
            "cannot evaluate: vehicle_command.source_component is float in the log; PX4 defines uint8_t or uint16_t (v1.14.0 to v1.17.0)",
        );
    }

    #[test]
    fn r1_reads_vehicle_command_fields_from_the_subscriptions_that_have_data() {
        use crate::ingest::{FlightLogIngestor, Px4Ingestor};
        use crate::ulog::tests::Builder;
        let full = "vehicle_command:uint64_t timestamp;uint32_t command;uint8_t source_system;uint16_t source_component;";
        let short = "vehicle_command:uint64_t timestamp;uint32_t command;uint8_t source_system;";
        let row_full = [
            &10u64.to_le_bytes()[..],
            &176u32.to_le_bytes(),
            &[1],
            &1u16.to_le_bytes(),
        ]
        .concat();
        let row_short = [&20u64.to_le_bytes()[..], &176u32.to_le_bytes(), &[1]].concat();
        let rules = crate::rules::parse_rules(
            "format = \"sfr-rules/1\"\n[required_topics]\ntopics = []\n[authorized_sources]\nsources = [{ system = 1, component = 1 }]\n",
        )
        .unwrap();
        let run = |log: Builder| {
            let ing = Px4Ingestor
                .ingest(
                    "x.ulg",
                    &mut &log.bytes[..],
                    &crate::crypto::test_backend::TestBackend,
                )
                .unwrap();
            let named: Vec<String> = r1(&ing.flight, &ing.identity.firmware, &rules)
                .detail
                .into_iter()
                .filter(|d| d.contains("vehicle_command"))
                .collect();
            (named, r7(&ing.flight, &ing.events, &rules))
        };

        // One subscription with every field and data: nothing is missing, R7 passes.
        let (named, r7) = run(Builder::new(0)
            .flags(&[])
            .format(full)
            .sub(0, 1, "vehicle_command")
            .data(1, &row_full));
        assert!(named.is_empty(), "{named:?}");
        assert_eq!(r7.status, Status::Pass, "{}", r7.found);
        // A format without source_component: R1 names it and R7 cannot evaluate.
        let (named, r7) = run(Builder::new(0)
            .flags(&[])
            .format(short)
            .sub(0, 1, "vehicle_command")
            .data(1, &row_short));
        assert_eq!(named, ["missing vehicle_command.source_component"]);
        assert_eq!(r7.status, Status::Fail);
        assert_eq!(
            r7.found,
            "cannot evaluate: missing vehicle_command.source_component"
        );
        // A format redefined after the first subscription, in either order, is refused: the
        // ULog specification allows format records in the definitions section only.
        for (first, second, row) in [(short, full, &row_full), (full, short, &row_short)] {
            let log = Builder::new(0)
                .flags(&[])
                .format(first)
                .sub(0, 1, "vehicle_command")
                .format(second)
                .sub(1, 2, "vehicle_command")
                .data(2, row);
            let err = Px4Ingestor
                .ingest(
                    "x.ulg",
                    &mut &log.bytes[..],
                    &crate::crypto::test_backend::TestBackend,
                )
                .expect_err("refused");
            assert!(
                err.to_string()
                    .contains("format record for `vehicle_command` after the definitions section"),
                "{err}"
            );
        }
    }

    #[test]
    fn r4_cannot_evaluate_a_nav_state_at_or_above_navigation_state_max() {
        // NAVIGATION_STATE_MAX is 23 at the v1.14 tags and 31 from v1.15.0 (VehicleStatus.msg,
        // scripts/testdata/px4_tables.json). A nav_state at or above it in flight is FAIL
        // (cannot evaluate), never a quiet WARN; at or above it only while disarmed, R4 runs.
        let fields: Vec<String> = VEHICLE_STATUS_FIELDS
            .iter()
            .map(|s| s.to_string())
            .collect();
        let fw = |release: u32| crate::ingest::Firmware {
            release: Some(release),
            version: None,
            git: None,
        };
        // Armed at boot_us 10 and 20, disarmed at 30 (in flight: the disarming sample), and
        // disarmed at 40.
        let flight = |nav: u8, in_flight: bool| {
            let mut rows = vec![
                vtol_row(0, 1, false, false, 1),
                vtol_row(1, 2, false, false, 1),
                vtol_row(2, 2, false, false, 1),
                vtol_row(3, 1, false, false, 1),
                vtol_row(4, 1, false, false, 1),
            ];
            rows[if in_flight { 2 } else { 4 }].nav_state = Some(nav);
            FlightLog {
                vehicle_status: rows,
                vehicle_status_fields: fields.clone(),
                ..FlightLog::default()
            }
        };
        let v1_14_4 = fw(0x010E04FF);
        let v1_17_0 = fw(0x011100FF);
        for (f, nav, max, tags) in [
            (&v1_14_4, 23u8, 23, "v1.14.4"),
            (&v1_14_4, 40, 23, "v1.14.4"),
            (&v1_17_0, 31, 31, "v1.17.0"),
            (&v1_17_0, 200, 31, "v1.17.0"),
        ] {
            let r = r4_nav_state_out_of_range(&flight(nav, true), f).expect("cannot evaluate");
            assert_eq!(r.status, Status::Fail);
            assert_eq!(
                r.found,
                format!(
                    "cannot evaluate: vehicle_status.nav_state is {nav} in flight at boot_us 20, at or above NAVIGATION_STATE_MAX ({max}) of PX4 {tags}"
                )
            );
        }
        assert!(r4_nav_state_out_of_range(&flight(22, true), &v1_14_4).is_none());
        assert!(r4_nav_state_out_of_range(&flight(30, true), &v1_17_0).is_none());
        // Out of range only on a sample after the disarming one: not in flight.
        assert!(r4_nav_state_out_of_range(&flight(31, false), &v1_17_0).is_none());
        // No readable version: every supported tag applies, so the bound is the highest, 31.
        let none = crate::ingest::Firmware {
            release: None,
            version: None,
            git: None,
        };
        assert!(r4_nav_state_out_of_range(&flight(30, true), &none).is_none());
        assert!(r4_nav_state_out_of_range(&flight(31, true), &none).is_some());
    }

    #[test]
    fn every_hazard_flag_is_a_px4_bool_exactly_at_its_stated_tags() {
        use crate::px4_tables::RELEASES;
        for (name, tags) in HAZARD_FLAGS {
            let defining: Vec<&crate::px4_tables::Release> = RELEASES
                .iter()
                .filter(|r| !crate::px4::field_types(&[*r], "failsafe_flags", name).is_empty())
                .collect();
            assert_eq!(crate::px4::tags_label(&defining), tags, "{name}");
            for r in defining {
                assert_eq!(
                    crate::px4::field_types(&[r], "failsafe_flags", name),
                    [crate::ulog::Scalar::Bool],
                    "{name} at {}",
                    r.tag
                );
            }
        }
    }

    #[test]
    fn r4_fails_on_a_hazard_flag_true_for_the_whole_flight() {
        use crate::ingest::{FailsafeFlags, FailsafeRow, RowId};
        let fields: Vec<String> = VEHICLE_STATUS_FIELDS
            .iter()
            .map(|s| s.to_string())
            .collect();
        // Armed at 10 and 20, disarming at 30; failsafe_flags at 0, 10, 20, 30, 40.
        let rows = vec![
            vtol_row(0, 1, false, false, 1),
            vtol_row(1, 2, false, false, 1),
            vtol_row(2, 2, false, false, 1),
            vtol_row(3, 1, false, false, 1),
            vtol_row(4, 1, false, false, 1),
        ];
        let flight = |name: &str, true_at: &[u64]| {
            let fs = FailsafeFlags {
                flags: vec![crate::ingest::FlagDef::for_test(name)],
                rows: (0..5)
                    .map(|i| FailsafeRow {
                        id: RowId {
                            ts: i * 10,
                            instance: 0,
                            index: i,
                        },
                        active: vec![true_at.contains(&(i * 10))].into(),
                        mode_req: vec![0].into(),
                    })
                    .collect(),
                ..FailsafeFlags::default()
            };
            FlightLog {
                vehicle_status: rows.clone(),
                vehicle_status_fields: fields.clone(),
                failsafe_flags: fs,
                ..FlightLog::default()
            }
        };
        // True on every sample from the ARM through the disarming one: FAIL.
        let r = r4(&flight("geofence_breached", &[10, 20, 30]));
        assert_eq!(r.status, Status::Fail, "{}", r.found);
        assert!(
            r.found
                .contains("hazard failsafe_flags geofence_breached true for the whole flight"),
            "{}",
            r.found
        );
        // On only part of the flight: a warning, as before.
        let r = r4(&flight("geofence_breached", &[20]));
        assert_eq!(r.status, Status::Warn, "{}", r.found);
        // A flag outside the hazard list true for the whole flight: a warning.
        let r = r4(&flight("gcs_connection_lost", &[10, 20, 30]));
        assert_eq!(r.status, Status::Warn, "{}", r.found);
        // Before the ARM and after the disarm only: nothing.
        let r = r4(&flight("fd_motor_failure", &[0, 40]));
        assert_eq!(r.status, Status::Pass, "{}", r.found);
    }

    #[test]
    fn r4_warns_on_a_failsafe_flags_gap_in_flight_over_the_bound() {
        use crate::ingest::{FailsafeFlags, FailsafeRow, RowId};
        let fields: Vec<String> = VEHICLE_STATUS_FIELDS
            .iter()
            .map(|s| s.to_string())
            .collect();
        // Armed from 1 s to 10 s; failsafe_flags samples at the given times (us).
        let rows: Vec<_> = (0..12u64)
            .map(|i| {
                let mut r = vtol_row(
                    i,
                    if (1..=10).contains(&i) { 2 } else { 1 },
                    false,
                    false,
                    1,
                );
                r.id.ts = i * 1_000_000;
                r
            })
            .collect();
        let flight = |times: &[u64]| FlightLog {
            vehicle_status: rows.clone(),
            vehicle_status_fields: fields.clone(),
            failsafe_flags: FailsafeFlags {
                flags: vec![crate::ingest::FlagDef::for_test("gcs_connection_lost")],
                rows: times
                    .iter()
                    .enumerate()
                    .map(|(i, &ts)| FailsafeRow {
                        id: RowId {
                            ts,
                            instance: 0,
                            index: i as u64,
                        },
                        active: vec![false].into(),
                        mode_req: vec![0].into(),
                    })
                    .collect(),
                ..FailsafeFlags::default()
            },
            ..FlightLog::default()
        };
        // Every 500 ms, and a gap of exactly the bound: PASS.
        let every = |step: u64| (0..=24u64).map(|i| i * step).collect::<Vec<_>>();
        assert_eq!(r4(&flight(&every(500_000))).status, Status::Pass);
        let mut at_bound = every(500_000);
        at_bound.retain(|&t| t != 4_500_000);
        at_bound.push(4_000_000);
        at_bound.sort_unstable();
        at_bound.dedup();
        assert_eq!(r4(&flight(&at_bound)).status, Status::Pass);
        // Two gaps over the bound in flight, the longer 2.5 s: WARN, with the count and the longest.
        let gaps: Vec<u64> = every(500_000)
            .into_iter()
            .filter(|&t| {
                !(3_100_000..5_400_000).contains(&t) && !(7_100_000..8_400_000).contains(&t)
            })
            .collect();
        let r = r4(&flight(&gaps));
        assert_eq!(r.status, Status::Warn, "{}", r.found);
        assert!(
            r.found.contains(
                "warning: failsafe_flags 2 gap(s) over 1000 ms in flight, longest 2500 ms"
            ),
            "{}",
            r.found
        );
        assert!(
            r.detail
                .iter()
                .any(|d| d.contains("the longest 2500 ms from boot_us 3000000")),
            "{:?}",
            r.detail
        );
        // A gap that starts at the disarming sample (11 s) or later: not in flight, PASS. One
        // that straddles it is in flight, as the window runs through that sample.
        let longer = (0..=28u64).map(|i| i * 500_000).collect::<Vec<_>>();
        let outside: Vec<u64> = longer
            .iter()
            .copied()
            .filter(|&t| !(11_100_000..13_000_000).contains(&t))
            .collect();
        assert_eq!(r4(&flight(&outside)).status, Status::Pass);
        let straddling: Vec<u64> = longer
            .iter()
            .copied()
            .filter(|&t| !(10_600_000..12_000_000).contains(&t))
            .collect();
        assert_eq!(r4(&flight(&straddling)).status, Status::Warn);
    }

    #[test]
    fn r4_warns_when_failsafe_flags_stop_or_start_inside_the_flight() {
        use crate::ingest::{FailsafeFlags, FailsafeRow, RowId};
        let fields: Vec<String> = VEHICLE_STATUS_FIELDS
            .iter()
            .map(|s| s.to_string())
            .collect();
        // Armed at 1 s, disarmed by the sample at 11 s; failsafe_flags samples at the given times.
        let rows: Vec<_> = (0..14u64)
            .map(|i| {
                let mut r = vtol_row(
                    i,
                    if (1..=10).contains(&i) { 2 } else { 1 },
                    false,
                    false,
                    1,
                );
                r.id.ts = i * 1_000_000;
                r
            })
            .collect();
        let flight = |times: &[u64]| FlightLog {
            vehicle_status: rows.clone(),
            vehicle_status_fields: fields.clone(),
            failsafe_flags: FailsafeFlags {
                flags: vec![crate::ingest::FlagDef::for_test("gcs_connection_lost")],
                rows: times
                    .iter()
                    .enumerate()
                    .map(|(i, &ts)| FailsafeRow {
                        id: RowId {
                            ts,
                            instance: 0,
                            index: i as u64,
                        },
                        active: vec![false].into(),
                        mode_req: vec![0].into(),
                    })
                    .collect(),
                ..FailsafeFlags::default()
            },
            ..FlightLog::default()
        };
        let steps = |from: u64, to: u64| (from..=to).step_by(500_000).collect::<Vec<u64>>();
        let warns = |times: &[u64], longest_ms: u64| {
            let r = r4(&flight(times));
            assert_eq!(r.status, Status::Warn, "{times:?}: {}", r.found);
            let want = format!(
                "warning: failsafe_flags 1 gap(s) over 1000 ms in flight, longest {longest_ms} ms"
            );
            assert!(r.found.contains(&want), "{times:?}: {}", r.found);
        };
        // The samples stop at 5 s and none follows the disarming sample: 6 s of flight unseen.
        warns(&steps(0, 5_000_000), 6000);
        // The first sample comes at 3 s and none precedes the ARM: 2 s of flight unseen.
        warns(&steps(3_000_000, 14_000_000), 2000);
        // No sample inside the flight: a sample before the ARM and none after the disarm.
        warns(&[0, 500_000], 10_000);
        // No sample inside the flight: the first comes after the disarming sample.
        warns(&[12_000_000, 12_500_000], 10_000);
        // A sample at the ARM and at the disarming sample, then every 500 ms: PASS.
        assert_eq!(
            r4(&flight(&steps(1_000_000, 11_000_000))).status,
            Status::Pass
        );
        // The first sample 1 s after the ARM, the last 1 s before the disarming sample: the bound
        // is "more than", so PASS; 1 ms more at either end: WARN.
        let mut inside = steps(2_000_000, 10_000_000);
        assert_eq!(r4(&flight(&inside)).status, Status::Pass);
        inside[0] += 1;
        assert_eq!(r4(&flight(&inside)).status, Status::Warn);
        let mut inside = steps(2_000_000, 10_000_000);
        *inside.last_mut().unwrap() -= 1;
        assert_eq!(r4(&flight(&inside)).status, Status::Warn);
        // Samples before the ARM and after the disarm cover the ends as before.
        assert_eq!(r4(&flight(&steps(0, 13_000_000))).status, Status::Pass);
    }

    /// The `failsafe_flags` fields R4 reads at one release, taken straight from the recorded PX4
    /// message (`msg/FailsafeFlags.msg` at the tag): `timestamp`, each flag (a `bool`, and
    /// `battery_warning`, a `uint8`) and the `mode_req_*` mask that PX4 pairs with it.
    fn fields_r4_reads(release: &crate::px4_tables::Release) -> Vec<String> {
        use crate::ulog::Scalar;
        let msg = crate::px4::msg(release, "failsafe_flags").expect("failsafe_flags is defined");
        let mut out = vec!["timestamp".to_string()];
        for (name, ty) in msg.fields {
            let flag = *ty == Scalar::Bool || (*name == "battery_warning" && *ty == Scalar::U8);
            if flag {
                out.push(name.to_string());
                if let Some((_, mask)) = release.mode_requirements.iter().find(|(f, _)| f == name) {
                    out.push(mask.to_string());
                }
            }
        }
        out.sort();
        out.dedup();
        out
    }

    #[test]
    fn r1_requires_the_failsafe_flags_fields_r4_reads_at_the_logs_tag() {
        use crate::ingest::Firmware;
        let rules =
            crate::rules::parse_rules("format = \"sfr-rules/1\"\n[required_topics]\ntopics = []\n")
                .unwrap();
        let tag = |t: &str| {
            crate::px4_tables::RELEASES
                .iter()
                .find(|r| r.tag == t)
                .unwrap()
        };
        let flight = |fields: &[String]| {
            let mut f = FlightLog::default();
            f.topic_rows.insert("vehicle_status".into(), 1);
            f.topic_rows.insert("failsafe_flags".into(), 1);
            f.vehicle_status_fields = VEHICLE_STATUS_FIELDS
                .iter()
                .map(|s| s.to_string())
                .collect();
            f.failsafe_flags_fields = fields.to_vec();
            f
        };
        let release = |r: &crate::px4_tables::Release| Firmware {
            release: Some(u32::from_be_bytes([
                r.version.0,
                r.version.1,
                r.version.2,
                255,
            ])),
            ..Firmware::default()
        };
        let missing = |fw: &Firmware, fields: &[String]| -> Vec<String> {
            let r = r1(&flight(fields), fw, &rules);
            r.detail
                .iter()
                .map(|d| d.trim_start_matches("missing ").to_string())
                .collect()
        };

        let v117 = tag("v1.17.0");
        let all = fields_r4_reads(v117);
        let fw = release(v117);
        // Every field PX4 defines at the log's tag: nothing missing.
        assert!(missing(&fw, &all).is_empty(), "{:?}", missing(&fw, &all));
        assert_eq!(r1(&flight(&all), &fw, &rules).status, Status::Pass);
        // A format with the timestamp only has nothing for R4 to read: R1 fails, naming the flags
        // and the masks.
        let only_ts = vec!["timestamp".to_string()];
        let r = r1(&flight(&only_ts), &fw, &rules);
        assert_eq!(r.status, Status::Fail, "{}", r.found);
        let named = missing(&fw, &only_ts);
        assert!(
            named.contains(&"failsafe_flags.global_position_invalid".to_string()),
            "{named:?}"
        );
        assert!(
            named.contains(&"failsafe_flags.mode_req_global_position".to_string()),
            "{named:?}"
        );
        assert_eq!(named.len(), all.len() - 1, "{named:?}");
        // One mask left out, the flag it pairs with kept: R4 would read the flag as not required.
        let no_mask: Vec<String> = all
            .iter()
            .filter(|n| *n != "mode_req_global_position")
            .cloned()
            .collect();
        assert_eq!(
            missing(&fw, &no_mask),
            vec!["failsafe_flags.mode_req_global_position"]
        );
        assert_eq!(r1(&flight(&no_mask), &fw, &rules).status, Status::Fail);
        // One flag left out, its mask kept.
        let no_flag: Vec<String> = all
            .iter()
            .filter(|n| *n != "global_position_invalid")
            .cloned()
            .collect();
        assert_eq!(
            missing(&fw, &no_flag),
            vec!["failsafe_flags.global_position_invalid"]
        );
        // The fields differ by tag: v1.14.4 has primary_geofence_breached and no navigator_failure.
        let v114 = tag("v1.14.4");
        let old = fields_r4_reads(v114);
        let fw_old = release(v114);
        assert!(old.contains(&"primary_geofence_breached".to_string()));
        assert!(!old.contains(&"navigator_failure".to_string()));
        assert!(
            missing(&fw_old, &old).is_empty(),
            "{:?}",
            missing(&fw_old, &old)
        );
        // Given the v1.17.0 fields instead, it lacks the two its own tag names differently.
        assert_eq!(
            missing(&fw_old, &all),
            vec![
                "failsafe_flags.local_position_accuracy_low",
                "failsafe_flags.primary_geofence_breached"
            ]
        );
        // A log that names no PX4 release is held to the fields every supported tag defines.
        let unknown = Firmware::default();
        let common: Vec<String> = fields_r4_reads(v117)
            .into_iter()
            .filter(|n| {
                crate::px4_tables::RELEASES
                    .iter()
                    .all(|r| fields_r4_reads(r).contains(n))
            })
            .collect();
        assert!(!common.contains(&"navigator_failure".to_string()));
        assert!(common.contains(&"global_position_invalid".to_string()));
        assert!(
            missing(&unknown, &common).is_empty(),
            "{:?}",
            missing(&unknown, &common)
        );
        assert_eq!(r1(&flight(&only_ts), &unknown, &rules).status, Status::Fail);
    }

    #[test]
    fn r6_names_the_vtol_type_when_a_transition_field_is_missing() {
        let rows = vec![
            vtol_row(0, 2, false, false, 1),
            vtol_row(1, 2, false, false, 1),
        ];
        let flight = FlightLog {
            vehicle_status: rows,
            vehicle_status_fields: VEHICLE_STATUS_FIELDS
                .iter()
                .filter(|f| **f != "in_transition_mode")
                .map(|s| s.to_string())
                .collect(),
            ..FlightLog::default()
        };
        let vtol = crate::ingest::VtolType {
            value: Some(2),
            name: "standard".to_string(),
        };
        let r = r6(&flight, &[], Some(&vtol));
        assert_eq!(r.status, Status::Fail);
        assert_eq!(
            r.detail,
            [
                "VTOL type standard (VT_TYPE 2)",
                "missing vehicle_status.in_transition_mode"
            ]
        );
        assert_eq!(
            r6(&flight, &[], None).detail,
            ["missing vehicle_status.in_transition_mode"]
        );
    }

    #[test]
    fn r6_counts_vtol_as_px4_is_vtol_does() {
        // commander_helper.cpp is_vtol, every supported tag: system_type 19 to 23. With is_vtol
        // false on every sample, 19 to 23 contradict it (FAIL); 24 and 25, MAVLink VTOL types
        // PX4 does not count, do not (N/A, named).
        let fields: Vec<String> = VEHICLE_STATUS_FIELDS
            .iter()
            .map(|s| s.to_string())
            .collect();
        let flight = |system_type: u8| {
            let mut rows = vec![
                vtol_row(0, 2, false, false, 1),
                vtol_row(1, 1, false, false, 1),
            ];
            for r in &mut rows {
                r.is_vtol = Some(false);
                r.system_type = Some(system_type);
            }
            FlightLog {
                vehicle_status: rows,
                vehicle_status_fields: fields.clone(),
                ..FlightLog::default()
            }
        };
        for t in 19..=23u8 {
            let r = r6(&flight(t), &[], None);
            assert_eq!(r.status, Status::Fail, "{t}");
            assert!(r.found.contains("cannot evaluate"), "{t}: {}", r.found);
        }
        for t in [24u8, 25] {
            let r = r6(&flight(t), &[], None);
            assert_eq!(r.status, Status::NotApplicable, "{t}: {}", r.found);
            assert_eq!(
                r.found,
                format!(
                    "vehicle_status.is_vtol false on every sample; system_type {t} is a MAVLink VTOL MAV_TYPE that PX4's is_vtol does not count (v1.14 to v1.17)"
                )
            );
        }
        let r = r6(&flight(2), &[], None);
        assert_eq!(r.status, Status::NotApplicable);
        assert_eq!(r.found, "vehicle_status.is_vtol false on every sample");
    }

    #[test]
    fn the_overall_status_follows_the_results() {
        use Status::*;
        let of = |r: &[(&'static str, Status)]| Overall::of(r.iter().copied()).as_str();
        assert_eq!(of(&[("R4", Pass), ("R5", Pass)]), "PASS");
        assert_eq!(of(&[("R4", Warn), ("R5", Pass)]), "WARN");
        assert_eq!(
            of(&[("R4", Warn), ("R5", NotApplicable)]),
            "NO ARMED FLIGHT"
        );
        assert_eq!(of(&[("R4", Fail), ("R5", NotApplicable)]), "FAIL");
        assert_eq!(of(&[("R6", NotApplicable), ("R7", NotApplicable)]), "PASS");
        assert_eq!(Status::parse("WARN"), Some(Warn));
        assert_eq!(Status::parse("FAILED"), None);
    }
}
