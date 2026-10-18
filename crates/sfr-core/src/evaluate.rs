//! Rule evaluation (SPEC B1.6). Missing input data is FAIL, never N/A; N/A means only that a
//! rule does not apply (R6 on a vehicle that is not VTOL). No threshold here is presented as
//! correct for any aircraft: the optional rules take every threshold from the rules file.

use crate::events::{
    ArmedInterval, Event, EventKind, VtolState, armed_intervals, armed_sample, attribute_failsafe,
    flag_at, vtol_state,
};
use crate::exit_code;
use crate::ingest::{FlightLog, Ingested};
use crate::json::{Obj, Value};
use crate::params::Baseline;
use crate::rules::{Compare, R7_TOPIC, Rules};
use crate::ulog::f32_shortest;
use std::collections::BTreeSet;

/// A rule outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The rule holds.
    Pass,
    /// The rule does not hold, or its input data is missing.
    Fail,
    /// The rule does not apply to this log.
    NotApplicable,
}

impl Status {
    /// Record spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Fail => "FAIL",
            Status::NotApplicable => "N/A",
        }
    }
}

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
    /// PASS when no rule is FAIL.
    pub status: Status,
    /// SPEC B1.4: 2 if R1 fails, else 1 if any rule fails, else 0.
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

/// The `failsafe_flags` fields the core rules read.
pub const FAILSAFE_FLAGS_FIELDS: [&str; 1] = ["timestamp"];

/// The `vehicle_command` fields R7 reads (R1 checks them when R7 is enabled).
pub const VEHICLE_COMMAND_FIELDS: [&str; 3] = ["command", "source_system", "source_component"];

fn r1(f: &FlightLog, rules: &Rules) -> RuleResult {
    let topics = rules.r1_topics();
    let mut missing = Vec::new();
    for t in &topics {
        if f.topic_rows.get(t).copied().unwrap_or(0) == 0 {
            missing.push(t.clone());
            continue;
        }
        let (fields, have): (&[&str], &[String]) = match t.as_str() {
            "vehicle_status" => (&VEHICLE_STATUS_FIELDS, &f.vehicle_status_fields),
            "failsafe_flags" => (&FAILSAFE_FLAGS_FIELDS, &f.failsafe_flags_fields),
            R7_TOPIC if rules.authorized_sources.is_some() => {
                (&VEHICLE_COMMAND_FIELDS, &f.vehicle_command_fields)
            }
            _ => (&[], &[]),
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

fn r2(ing: &Ingested, baseline: &Baseline) -> RuleResult {
    let fw = &ing.identity.firmware;
    let expected = baseline.firmware.to_string();
    let found = match (&fw.version, &fw.git) {
        (Some(v), Some(g)) => format!("{v} {g}"),
        (Some(v), None) => v.clone(),
        (None, Some(g)) => format!("no ver_sw_release, ver_sw {g}"),
        (None, None) => "no ver_sw_release or ver_sw".into(),
    };
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

fn r3(ing: &Ingested, rules: &Rules, baseline: &Baseline) -> RuleResult {
    let flown = &ing.config.params;
    let mut names: BTreeSet<&str> = baseline.params.keys().map(String::as_str).collect();
    if rules.compare == Compare::All {
        names.extend(flown.keys().map(String::as_str));
    }
    let mut detail = Vec::new();
    let mut ignored = 0usize;
    for name in names {
        if rules.ignores(name) {
            ignored += 1;
            continue;
        }
        let b = baseline.params.get(name);
        let l = flown.get(name);
        let same = matches!((b, l), (Some(b), Some(l)) if b.same_as(l));
        if !same {
            let show = |v: Option<&crate::ulog::ParamValue>| {
                v.map_or("absent".to_string(), |v| v.to_string())
            };
            detail.push(format!("{name}: baseline {}, flown {}", show(b), show(l)));
        }
    }
    let scope = match rules.compare {
        Compare::All => "every parameter in the baseline or the log",
        Compare::Baseline => "every parameter in the baseline",
    };
    let expected = format!("{scope} equal, {ignored} ignored by pattern");
    if detail.is_empty() {
        RuleResult::new(
            "R3",
            "parameters match baseline",
            Status::Pass,
            expected,
            "no differences",
            detail,
        )
    } else {
        let found = format!("{} differ", detail.len());
        RuleResult::new(
            "R3",
            "parameters match baseline",
            Status::Fail,
            expected,
            found,
            detail,
        )
    }
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

/// Most detail lines R4, R5, R6, X2, and X3 list. Real logs need a handful; the cap keeps a
/// crafted log from making one result enormous. R3 is not capped: SPEC B1.6 has it list every
/// differing parameter, at most the two parameter limits together.
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

fn r4(f: &FlightLog) -> RuleResult {
    let expected = "vehicle_status.failsafe false in flight (from ARM through the sample that disarms), and no quadchute (fixed wing straight to multicopter) in flight";
    // SPEC B1.6: the quadchute half reads the VTOL state only on a VTOL vehicle (is_vtol true
    // on some sample). No vehicle_status, or no is_vtol field, counts as not VTOL here; R1
    // reports what is missing.
    let is_vtol = f.vehicle_status.iter().any(|r| r.is_vtol == Some(true));
    let mut needed = vec!["arming_state", "failsafe"];
    if is_vtol {
        needed.extend(["in_transition_mode", "in_transition_to_fw", "vehicle_type"]);
    }
    let missing = missing_fields(f, &needed);
    if !missing.is_empty() {
        return fail_missing("R4", "no failsafe in flight", expected, missing);
    }
    let fs = &f.failsafe_flags;
    let mut rows = fs.rows.clone();
    rows.sort_by_key(|r| (r.id.ts, r.id.index));
    let mut detail = Lines::new();
    let (mut failsafes, mut quadchutes) = (0usize, 0usize);
    let mut active = false;
    let mut last_arm = None;
    let mut was_armed = false;
    let mut prev_vtol: Option<VtolState> = None;
    for r in &f.vehicle_status {
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
                let flags = attribute_failsafe(fs, &rows, r.id.ts, r.nav_state, last_arm);
                format!(
                    "failsafe in flight at boot_us {}: {}",
                    r.id.ts,
                    flags.join(", ")
                )
            });
        }
        active = now;
        // SPEC B1.5: a quadchute is not a transition; R4 reports it. PX4 raises the quadchute
        // failsafe only in some modes (failsafe.cpp), so the state change itself is the signal.
        // The disarming row is in flight here too, as for failsafes above.
        let vtol = vtol_state(r);
        if is_vtol && in_flight && prev_vtol == Some(VtolState::Fw) && vtol == Some(VtolState::Mc) {
            quadchutes += 1;
            detail.push(|| {
                let flag = match flag_at(fs, &rows, "vtol_fixed_wing_system_failure", r.id.ts) {
                    Some(true) => "true",
                    Some(false) => "false",
                    None => "not logged",
                };
                format!(
                    "quadchute in flight at boot_us {}: fixed wing straight to multicopter, failsafe_flags.vtol_fixed_wing_system_failure {flag}",
                    r.id.ts
                )
            });
        }
        if vtol.is_some() {
            prev_vtol = vtol;
        }
    }
    if detail.total == 0 {
        RuleResult::new(
            "R4",
            "no failsafe in flight",
            Status::Pass,
            expected,
            "never true in flight",
            vec![],
        )
    } else {
        let found = match quadchutes {
            0 => format!("true in flight {failsafes} time(s)"),
            q => format!("true in flight {failsafes} time(s), quadchute {q} time(s)"),
        };
        let detail = detail.finish();
        RuleResult::new(
            "R4",
            "no failsafe in flight",
            Status::Fail,
            expected,
            found,
            detail,
        )
    }
}

fn r5(f: &FlightLog, events: &[Event]) -> RuleResult {
    let expected = "every ARM followed by a DISARM; log does not end armed";
    let missing = missing_fields(f, &["arming_state"]);
    if !missing.is_empty() {
        return fail_missing("R5", "arm and disarm consistent", expected, missing);
    }
    let mut detail = Lines::new();
    let mut open: Option<&Event> = None;
    let mut arms = 0usize;
    for e in events {
        match e.kind {
            EventKind::Arm { .. } => {
                if let Some(prev) = open {
                    detail.push(|| {
                        format!(
                            "ARM seq {} at boot_us {} has no DISARM",
                            prev.seq, prev.boot_us
                        )
                    });
                }
                open = Some(e);
                arms += 1;
            }
            EventKind::Disarm { .. } => {
                if open.is_none() {
                    detail.push(|| {
                        format!("DISARM seq {} at boot_us {} has no ARM", e.seq, e.boot_us)
                    });
                }
                open = None;
            }
            _ => {}
        }
    }
    if let Some(prev) = open {
        detail.push(|| {
            format!(
                "ARM seq {} at boot_us {} has no DISARM: the log ends armed",
                prev.seq, prev.boot_us
            )
        });
    }
    if detail.total == 0 {
        RuleResult::new(
            "R5",
            "arm and disarm consistent",
            Status::Pass,
            expected,
            format!("{arms} ARM, {arms} DISARM"),
            vec![],
        )
    } else {
        let found = format!("{} unmatched", detail.total);
        let detail = detail.finish();
        RuleResult::new(
            "R5",
            "arm and disarm consistent",
            Status::Fail,
            expected,
            found,
            detail,
        )
    }
}

/// R6. On a VTOL vehicle its first detail line states the VTOL type (Change Order 01).
fn r6(f: &FlightLog, events: &[Event], vtol: Option<&crate::ingest::VtolType>) -> RuleResult {
    let expected = "every VTOL transition START has an END; none aborted";
    let missing = missing_fields(f, &["is_vtol"]);
    if !missing.is_empty() {
        return fail_missing("R6", "VTOL transitions completed", expected, missing);
    }
    if f.vehicle_status.iter().all(|r| r.is_vtol == Some(false)) {
        return RuleResult::new(
            "R6",
            "VTOL transitions completed",
            Status::NotApplicable,
            expected,
            "vehicle_status.is_vtol false on every sample",
            vec![],
        );
    }
    let missing = missing_fields(
        f,
        &["in_transition_mode", "in_transition_to_fw", "vehicle_type"],
    );
    if !missing.is_empty() {
        return fail_missing("R6", "VTOL transitions completed", expected, missing);
    }
    let mut detail = Lines::new();
    let mut open: Option<&Event> = None;
    let (mut starts, mut ends) = (0usize, 0usize);
    for e in events {
        match &e.kind {
            EventKind::VtolTransitionStart { .. } => {
                starts += 1;
                open = Some(e);
            }
            EventKind::VtolTransitionEnd { .. } => {
                ends += 1;
                open = None;
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
                open = None;
            }
            _ => {}
        }
    }
    if let Some(e) = open
        && let EventKind::VtolTransitionStart { direction } = &e.kind
    {
        detail.push(|| {
            format!(
                "VTOL_TRANSITION_START {} seq {} at boot_us {} has no END: the log ends in transition",
                direction.as_str(),
                e.seq,
                e.boot_us
            )
        });
    }
    let found = format!("{starts} START, {ends} END, {} problem(s)", detail.total);
    let status = if detail.total == 0 {
        Status::Pass
    } else {
        Status::Fail
    };
    let mut lines = detail.finish();
    if let Some(t) = vtol {
        let value = t.value.map_or(String::new(), |v| format!(" (VT_TYPE {v})"));
        lines.insert(0, format!("VTOL type {}{value}", t.name));
    }
    RuleResult::new(
        "R6",
        "VTOL transitions completed",
        status,
        expected,
        found,
        lines,
    )
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

fn need_armed(
    id: &'static str,
    name: &'static str,
    expected: &str,
    f: &FlightLog,
    armed: &[ArmedInterval],
) -> Option<RuleResult> {
    let missing = missing_fields(f, &["arming_state"]);
    if !missing.is_empty() {
        return Some(fail_missing(id, name, expected, missing));
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
    // The ingest keeps only the samples whose three fields read as unsigned integers.
    let read = f.commands.len() as u64;
    if read != rows {
        return RuleResult::new(
            "R7",
            NAME,
            Status::Fail,
            expected,
            format!(
                "cannot evaluate: {} of {rows} {R7_TOPIC} record(s) have no unsigned integer command, source_system and source_component",
                rows - read
            ),
            vec![],
        );
    }
    let mut detail = Lines::new();
    let mut checked = 0usize;
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
    let bad = detail.total;
    let (status, found) = if bad == 0 {
        (
            Status::Pass,
            format!("{checked} command(s) checked, all from authorized sources"),
        )
    } else {
        (
            Status::Fail,
            format!("{bad} of {checked} command(s) from unauthorized sources"),
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
    if let Some(r) = need_armed(id, name, &expected, f, armed) {
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

fn x2(f: &FlightLog, events: &[Event], t: &crate::rules::GpsFixAtArm) -> RuleResult {
    let (id, name) = ("X2", "GPS fix at arm");
    let expected = format!(
        "at each ARM, vehicle_gps_position fix_type >= {} and satellites_used >= {} (thresholds set by your flight-test lead)",
        t.min_fix_type, t.min_satellites
    );
    let armed = armed_intervals(&f.vehicle_status);
    if let Some(r) = need_armed(id, name, &expected, f, &armed) {
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
    if let Some(r) = need_armed(id, name, expected, f, armed) {
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
    if let Some(r) = need_armed(id, name, &expected, f, armed) {
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
    let mut prev: std::collections::BTreeMap<u8, (usize, u64)> = std::collections::BTreeMap::new();
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
    let armed = armed_intervals(&f.vehicle_status);
    let mut results = vec![
        r1(f, rules),
        r2(ing, baseline),
        r3(ing, rules, baseline),
        r4(f),
        r5(f, &ing.events),
        r6(f, &ing.events, ing.identity.vehicle.vtol_type.as_ref()),
        r7(f, &ing.events, rules),
    ];
    let x = &rules.extended;
    if let Some(t) = &x.min_battery {
        results.push(x1(f, &armed, t));
    }
    if let Some(t) = &x.gps_fix_at_arm {
        results.push(x2(f, &ing.events, t));
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
    let any_fail = results.iter().any(|r| r.status == Status::Fail);
    let r1_fail = results.first().is_some_and(|r| r.status == Status::Fail);
    let exit_code = if r1_fail {
        exit_code::MISSING_TOPIC
    } else if any_fail {
        exit_code::RULE_FAIL
    } else {
        exit_code::OK
    };
    Evaluation {
        results,
        status: if any_fail { Status::Fail } else { Status::Pass },
        exit_code,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::ingest::{RowId, VehicleStatusRow};

    fn vtol_row(i: u64, arming: u8, trans: bool, to_fw: bool, vtype: u8) -> VehicleStatusRow {
        VehicleStatusRow {
            id: RowId {
                ts: i * 10,
                instance: 0,
                index: i,
            },
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
        let r = r4(&flight);
        assert_eq!(r.status, Status::Fail);
        assert_eq!(r.found, "true in flight 0 time(s), quadchute 1 time(s)");
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
        assert_eq!(r4(&flight).status, Status::Pass);
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
        let r = r4(&flight);
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
            let mut r = vtol_row(ts, 1, false, false, 1);
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
        assert_eq!(r4(&flight).status, Status::Pass);
        // VTOL and no vehicle_type: missing input, FAIL.
        let flight = FlightLog {
            vehicle_status: vec![row(0, true), row(1, true)],
            vehicle_status_fields: fields("vehicle_type"),
            ..FlightLog::default()
        };
        let r = r4(&flight);
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
        assert_eq!(r4(&flight).status, Status::Pass);
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
        assert_eq!(r4(&flight).status, Status::Pass);
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
        let r = r4(&flight);
        assert_eq!(r.status, Status::Fail);
        assert_eq!(r.found, "true in flight 0 time(s), quadchute 1 time(s)");
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
                disarm: Some(100),
            },
            ArmedInterval {
                arm: 200,
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
        let rows = (0..3000u64)
            .map(|i| VehicleStatusRow {
                id: RowId {
                    ts: i,
                    instance: 0,
                    index: i,
                },
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
        let r = r4(&flight);
        assert_eq!(r.status, Status::Fail);
        assert_eq!(r.found, "true in flight 1500 time(s)");
        assert_eq!(r.detail.len(), MAX_DETAIL_LINES + 1);
        assert_eq!(
            r.detail.last().map(String::as_str),
            Some("and 500 more; the events list every one")
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
        assert_eq!(all.found, "1 of 3 command(s) from unauthorized sources");
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
            "1 command(s) checked, all from authorized sources"
        );
        let payload = r7(
            &ing.flight,
            &ing.events,
            &rules(
                "[authorized_sources]\ncategory = \"PAYLOAD\"\nsources = [{ system = 2, component = 7 }]\n",
            ),
        );
        assert_eq!(payload.status, Status::Fail);
        assert_eq!(payload.found, "1 of 2 command(s) from unauthorized sources");
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
            let r1 = r1(&ing.flight, &rules(true));
            assert_eq!(
                r1.detail.iter().any(|d| Some(d.as_str()) == r1_missing),
                r1_missing.is_some(),
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
            !r1(&none.flight, &rules(false))
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
            "cannot evaluate: 1 of 1 vehicle_command record(s) have no unsigned integer command, source_system and source_component",
        );
    }
}
