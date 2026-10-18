//! The event timeline (SPEC B1.5).
//!
//! Events are derived from the decoded log, sorted by boot time, then topic name, then
//! instance, then message index, then a fixed order for several events from one source row
//! (ARM or DISARM, NAV_STATE_CHANGE, FAILSAFE_* by flag name, then VTOL END or ABORT before
//! START), and numbered from 0.

use crate::ingest::{
    AckRow, CommandRow, Config, FailsafeFlags, FailsafeRow, Firmware, FlightLog, VehicleStatusRow,
};
use crate::json::{Obj, Value};
use crate::ulog::ParamValue;
use std::collections::BTreeMap;

/// Pseudo-topic of 'L' and 'C' records.
pub const TOPIC_LOGGING: &str = "ulog.logging";
/// Pseudo-topic of data-section 'P' records.
pub const TOPIC_PARAMETER: &str = "ulog.parameter";
/// Pseudo-topic of 'O' records.
pub const TOPIC_DROPOUT: &str = "ulog.dropout";

/// Most events one log may produce. A real flight has hundreds; the cap stops a crafted log
/// (for example a failsafe that toggles on every row, each naming many flags) from building
/// a timeline that exhausts memory.
pub const MAX_EVENTS: usize = 1_000_000;

/// Direction of a VTOL transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Multicopter to fixed wing.
    ToFw,
    /// Fixed wing to multicopter.
    ToMc,
}

impl Direction {
    /// Record spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Direction::ToFw => "to_fw",
            Direction::ToMc => "to_mc",
        }
    }
}

/// Result of a command: the matching acknowledgement, or none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandResult {
    /// `vehicle_command_ack.result`.
    Ack(u8),
    /// No matching acknowledgement in the log.
    NoAck,
}

impl CommandResult {
    /// Record spelling (VEHICLE_CMD_RESULT_* names; unknown values as `RESULT_<n>`).
    pub fn name(self) -> String {
        match self {
            CommandResult::NoAck => "NO_ACK".into(),
            CommandResult::Ack(r) => match r {
                0 => "ACCEPTED".into(),
                1 => "TEMPORARILY_REJECTED".into(),
                2 => "DENIED".into(),
                3 => "UNSUPPORTED".into(),
                4 => "FAILED".into(),
                5 => "IN_PROGRESS".into(),
                6 => "CANCELLED".into(),
                other => format!("RESULT_{other}"),
            },
        }
    }
}

/// What happened.
#[derive(Debug, Clone, PartialEq)]
pub enum EventKind {
    /// `arming_state` became 2.
    Arm {
        /// The log starts armed.
        initial: bool,
        /// `latest_arming_reason`.
        reason: Option<u8>,
    },
    /// `arming_state` left 2.
    Disarm {
        /// `latest_disarming_reason`.
        reason: Option<u8>,
    },
    /// `nav_state` changed, or its first sample (`old` is `None`).
    NavStateChange {
        /// Previous state.
        old: Option<u8>,
        /// New state.
        new: u8,
    },
    /// `vehicle_status.failsafe` became true; one event per named flag.
    FailsafeSet {
        /// The log starts in failsafe: this is the first sample, not an observed edge.
        initial: bool,
        /// Flag name, or `unattributed`.
        flag: String,
    },
    /// `vehicle_status.failsafe` became false.
    FailsafeClear {
        /// Flag name, or `unattributed`.
        flag: String,
    },
    /// A `vehicle_command` and its result.
    Command {
        /// VEHICLE_CMD_* id.
        command: u32,
        /// Source system.
        source_system: u64,
        /// Source component.
        source_component: u64,
        /// Matching ack.
        result: CommandResult,
    },
    /// A transition state was entered.
    VtolTransitionStart {
        /// Direction.
        direction: Direction,
    },
    /// A transition reached its target state.
    VtolTransitionEnd {
        /// Direction.
        direction: Direction,
    },
    /// A transition state was left any other way.
    VtolTransitionAbort {
        /// Direction.
        direction: Direction,
    },
    /// A parameter changed between ARM and DISARM.
    ParamChangedInFlight {
        /// Name.
        name: String,
        /// Last known value, or `None` if the name was not seen before.
        old: Option<ParamValue>,
        /// New value.
        new: ParamValue,
    },
    /// A logged string at warning level or above.
    LogMessage {
        /// 0 emergency to 4 warning.
        level: u8,
        /// Text bytes, verbatim.
        text: Vec<u8>,
    },
    /// Logging lost data.
    LogDropout {
        /// Milliseconds.
        duration_ms: u16,
    },
}

impl EventKind {
    /// Record spelling of the kind.
    pub fn name(&self) -> &'static str {
        match self {
            EventKind::Arm { .. } => "ARM",
            EventKind::Disarm { .. } => "DISARM",
            EventKind::NavStateChange { .. } => "NAV_STATE_CHANGE",
            EventKind::FailsafeSet { .. } => "FAILSAFE_SET",
            EventKind::FailsafeClear { .. } => "FAILSAFE_CLEAR",
            EventKind::Command { .. } => "COMMAND",
            EventKind::VtolTransitionStart { .. } => "VTOL_TRANSITION_START",
            EventKind::VtolTransitionEnd { .. } => "VTOL_TRANSITION_END",
            EventKind::VtolTransitionAbort { .. } => "VTOL_TRANSITION_ABORT",
            EventKind::ParamChangedInFlight { .. } => "PARAM_CHANGED_IN_FLIGHT",
            EventKind::LogMessage { .. } => "LOG_MESSAGE",
            EventKind::LogDropout { .. } => "LOG_DROPOUT",
        }
    }
}

/// One timeline entry.
#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    /// Sequence number from 0.
    pub seq: u64,
    /// Boot-time microseconds.
    pub boot_us: u64,
    /// UTC microseconds from GPS time, when available.
    pub utc_us: Option<u64>,
    /// Source topic or pseudo-topic.
    pub topic: String,
    /// Source instance.
    pub instance: u8,
    /// Source message index within the topic and instance.
    pub index: u64,
    order: u32,
    /// What happened.
    pub kind: EventKind,
}

/// An interval during which the vehicle was armed: `[arm, disarm)` in boot microseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArmedInterval {
    /// ARM time.
    pub arm: u64,
    /// DISARM time, or `None` if the log ends armed.
    pub disarm: Option<u64>,
}

impl ArmedInterval {
    /// Whether a sample at `t` lies in `[arm, disarm)`.
    pub fn contains_sample(&self, t: u64) -> bool {
        t >= self.arm && self.disarm.is_none_or(|d| t < d)
    }

    /// Whether a record timed by "last data timestamp before it" lies in `(arm, disarm]`. At
    /// equal times `ulog.parameter` sorts before `vehicle_status`, so this matches the order
    /// in which the timeline shows them.
    pub fn contains_record(&self, t: u64) -> bool {
        t > self.arm && self.disarm.is_none_or(|d| t <= d)
    }
}

/// Whether a sample at `t` lies in an armed interval. `armed` is sorted and disjoint, so only
/// the last interval that starts at or before `t` can hold it.
pub fn armed_sample(armed: &[ArmedInterval], t: u64) -> bool {
    let n = armed.partition_point(|a| a.arm <= t);
    n.checked_sub(1)
        .and_then(|i| armed.get(i))
        .is_some_and(|a| a.contains_sample(t))
}

/// Whether a record timed by "last data timestamp before it" lies in an armed interval
/// (`(arm, disarm]`, see [`ArmedInterval::contains_record`]).
pub fn in_flight_record(armed: &[ArmedInterval], t: u64) -> bool {
    let n = armed.partition_point(|a| a.arm < t);
    n.checked_sub(1)
        .and_then(|i| armed.get(i))
        .is_some_and(|a| a.contains_record(t))
}

/// Armed intervals from `arming_state == 2` (ARMING_STATE_ARMED in v1.14 through v1.17).
pub fn armed_intervals(rows: &[VehicleStatusRow]) -> Vec<ArmedInterval> {
    let mut out = Vec::new();
    let mut open: Option<u64> = None;
    for r in rows {
        let Some(state) = r.arming_state else {
            continue;
        };
        let armed = state == 2;
        match (armed, open) {
            (true, None) => open = Some(r.id.ts),
            (false, Some(arm)) => {
                out.push(ArmedInterval {
                    arm,
                    disarm: Some(r.id.ts),
                });
                open = None;
            }
            _ => {}
        }
    }
    if let Some(arm) = open {
        out.push(ArmedInterval { arm, disarm: None });
    }
    out
}

/// `arm_disarm_reason_t` from PX4 `src/lib/events/enums.json` (DIAGNOSTIC 4.2).
pub fn reason_name(reason: u8, fw: &Firmware) -> Option<&'static str> {
    let series = supported_series(fw)?;
    Some(match reason {
        0 => "transition_to_standby",
        1 if series < (1, 16) => "rc_stick",
        1 => "stick_gesture",
        2 => "rc_switch",
        3 => "command_internal",
        4 => "command_external",
        5 => "mission_start",
        6 => "auto_disarm_land",
        7 => "auto_disarm_preflight",
        8 => "kill_switch",
        9 => "lockdown",
        10 => "failure_detector",
        11 => "shutdown",
        12 => "unit_test",
        13 => "rc_button",
        14 => "failsafe",
        _ => return None,
    })
}

fn supported_series(fw: &Firmware) -> Option<(u8, u8)> {
    fw.series().filter(|s| (1, 14) <= *s && *s <= (1, 17))
}

/// NAVIGATION_STATE_* names per version (DIAGNOSTIC 4.3). `None` outside v1.14 to v1.17.
pub fn nav_state_name(state: u8, fw: &Firmware) -> Option<&'static str> {
    let series = supported_series(fw)?;
    let v114 = series == (1, 14);
    Some(match state {
        0 => "MANUAL",
        1 => "ALTCTL",
        2 => "POSCTL",
        3 => "AUTO_MISSION",
        4 => "AUTO_LOITER",
        5 => "AUTO_RTL",
        6 if !v114 => "POSITION_SLOW",
        7 if !v114 => "FREE5",
        8 if v114 => "UNUSED3",
        8 if series == (1, 17) => "ALTITUDE_CRUISE",
        8 => "FREE4",
        9 if v114 => "UNUSED",
        9 => "FREE3",
        10 => "ACRO",
        11 if v114 => "UNUSED1",
        11 => "FREE2",
        12 => "DESCEND",
        13 => "TERMINATION",
        14 => "OFFBOARD",
        15 => "STAB",
        16 if v114 => "UNUSED2",
        16 => "FREE1",
        17 => "AUTO_TAKEOFF",
        18 => "AUTO_LAND",
        19 => "AUTO_FOLLOW_TARGET",
        20 => "AUTO_PRECLAND",
        21 => "ORBIT",
        22 => "AUTO_VTOL_TAKEOFF",
        23 if v114 => "MAX",
        23 => "EXTERNAL1",
        24 if !v114 => "EXTERNAL2",
        25 if !v114 => "EXTERNAL3",
        26 if !v114 => "EXTERNAL4",
        27 if !v114 => "EXTERNAL5",
        28 if !v114 => "EXTERNAL6",
        29 if !v114 => "EXTERNAL7",
        30 if !v114 => "EXTERNAL8",
        31 if !v114 => "MAX",
        _ => return None,
    })
}

/// The VTOL state that commander mirrors into `vehicle_status` (DIAGNOSTIC 4.4.1, item 6).
/// PX4 commander sets `vehicle_type`, `in_transition_mode` and `in_transition_to_fw` together
/// from one `vtol_vehicle_status` message (`Commander::vtolStatusUpdate`, v1.14.4 and v1.17.0),
/// so consecutive rows never show a state that the vehicle was not in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VtolState {
    /// In transition to fixed wing.
    TransitionToFw,
    /// In transition to multicopter.
    TransitionToMc,
    /// Multicopter.
    Mc,
    /// Fixed wing.
    Fw,
    /// Neither (a `vehicle_type` other than 1 or 2).
    Other,
}

/// The VTOL state of one `vehicle_status` row, or `None` if a field it needs is not logged.
pub fn vtol_state(r: &VehicleStatusRow) -> Option<VtolState> {
    let in_transition = r.in_transition_mode?;
    Some(if in_transition {
        if r.in_transition_to_fw? {
            VtolState::TransitionToFw
        } else {
            VtolState::TransitionToMc
        }
    } else {
        match r.vehicle_type? {
            1 => VtolState::Mc,
            2 => VtolState::Fw,
            _ => VtolState::Other,
        }
    })
}

/// The latest `failsafe_flags` row with a timestamp at or before `t`.
fn flags_at(rows: &[FailsafeRow], t: u64) -> Option<&FailsafeRow> {
    let n = rows.partition_point(|r| r.id.ts <= t);
    n.checked_sub(1).and_then(|i| rows.get(i))
}

/// The value of the `failsafe_flags` flag `name` at `t`, from rows sorted by time; `None` if
/// the log has no such flag or no row at or before `t`.
pub fn flag_at(fs: &FailsafeFlags, sorted: &[FailsafeRow], name: &str, t: u64) -> Option<bool> {
    let i = fs.flags.iter().position(|d| d.name == name)?;
    flags_at(sorted, t).and_then(|r| r.active.get(i).copied())
}

/// SPEC B1.5 failsafe attribution: flags active at `t` that the current `nav_state` requires
/// or that were not active at the reference row (the most recent ARM, else the first row).
pub fn attribute_failsafe(
    fs: &FailsafeFlags,
    sorted: &[FailsafeRow],
    t: u64,
    nav_state: Option<u8>,
    last_arm: Option<u64>,
) -> Vec<String> {
    let Some(current) = flags_at(sorted, t) else {
        return vec!["unattributed".into()];
    };
    let reference = last_arm
        .and_then(|a| flags_at(sorted, a))
        .or_else(|| sorted.first());
    let bit = nav_state
        .and_then(|n| 1u32.checked_shl(u32::from(n)))
        .unwrap_or(0);
    let mut named = Vec::new();
    for (i, def) in fs.flags.iter().enumerate() {
        let active = current.active.get(i).copied().unwrap_or(false);
        if !active {
            continue;
        }
        let required = current.mode_req.get(i).is_some_and(|m| m & bit != 0);
        let was_active = reference
            .and_then(|r| r.active.get(i).copied())
            .unwrap_or(false);
        if required || !was_active {
            named.push(def.name.clone());
        }
    }
    if named.is_empty() {
        named.push("unattributed".into());
    }
    named
}

fn sorted_flag_rows(fs: &FailsafeFlags) -> Vec<FailsafeRow> {
    let mut rows = fs.rows.clone();
    rows.sort_by_key(|r| (r.id.ts, r.id.index));
    rows
}

struct Builder {
    out: Vec<Event>,
    overflow: bool,
}

impl Builder {
    fn push(
        &mut self,
        boot_us: u64,
        topic: &str,
        instance: u8,
        index: u64,
        order: u32,
        kind: EventKind,
    ) {
        if self.out.len() >= MAX_EVENTS {
            self.overflow = true;
            return;
        }
        self.out.push(Event {
            seq: 0,
            boot_us,
            utc_us: None,
            topic: topic.to_string(),
            instance,
            index,
            order,
            kind,
        });
    }
}

fn vehicle_status_events(b: &mut Builder, flight: &FlightLog) {
    let fs = &flight.failsafe_flags;
    let flag_rows = sorted_flag_rows(fs);
    let mut prev: Option<&VehicleStatusRow> = None;
    let mut last_arm: Option<u64> = None;
    for r in &flight.vehicle_status {
        let (ts, inst, idx) = (r.id.ts, r.id.instance, r.id.index);
        let topic = "vehicle_status";
        // Arming.
        if let Some(state) = r.arming_state {
            let armed = state == 2;
            let was_armed = prev.and_then(|p| p.arming_state).map(|s| s == 2);
            match (was_armed, armed) {
                (None, true) => {
                    b.push(
                        ts,
                        topic,
                        inst,
                        idx,
                        0,
                        EventKind::Arm {
                            initial: prev.is_none(),
                            reason: r.latest_arming_reason,
                        },
                    );
                    last_arm = Some(ts);
                }
                (Some(false), true) => {
                    b.push(
                        ts,
                        topic,
                        inst,
                        idx,
                        0,
                        EventKind::Arm {
                            initial: false,
                            reason: r.latest_arming_reason,
                        },
                    );
                    last_arm = Some(ts);
                }
                (Some(true), false) => b.push(
                    ts,
                    topic,
                    inst,
                    idx,
                    0,
                    EventKind::Disarm {
                        reason: r.latest_disarming_reason,
                    },
                ),
                _ => {}
            }
        }
        // Navigation state.
        if let Some(new) = r.nav_state {
            let old = prev.and_then(|p| p.nav_state);
            if old != Some(new) {
                b.push(
                    ts,
                    topic,
                    inst,
                    idx,
                    1,
                    EventKind::NavStateChange { old, new },
                );
            }
        }
        // Failsafe.
        if let Some(on) = r.failsafe {
            let was_on = prev.and_then(|p| p.failsafe).unwrap_or(false);
            if on != was_on {
                let initial = prev.is_none();
                for flag in attribute_failsafe(fs, &flag_rows, ts, r.nav_state, last_arm) {
                    let kind = if on {
                        EventKind::FailsafeSet { initial, flag }
                    } else {
                        EventKind::FailsafeClear { flag }
                    };
                    b.push(ts, topic, inst, idx, 2, kind);
                }
            }
        }
        // VTOL transitions.
        if let Some(cur) = vtol_state(r) {
            let before = prev.and_then(vtol_state);
            if before != Some(cur) {
                match before {
                    Some(VtolState::TransitionToFw) => {
                        let direction = Direction::ToFw;
                        let kind = if cur == VtolState::Fw {
                            EventKind::VtolTransitionEnd { direction }
                        } else {
                            EventKind::VtolTransitionAbort { direction }
                        };
                        b.push(ts, topic, inst, idx, 3, kind);
                    }
                    Some(VtolState::TransitionToMc) => {
                        let direction = Direction::ToMc;
                        let kind = if cur == VtolState::Mc {
                            EventKind::VtolTransitionEnd { direction }
                        } else {
                            EventKind::VtolTransitionAbort { direction }
                        };
                        b.push(ts, topic, inst, idx, 3, kind);
                    }
                    _ => {}
                }
                match cur {
                    VtolState::TransitionToFw => b.push(
                        ts,
                        topic,
                        inst,
                        idx,
                        4,
                        EventKind::VtolTransitionStart {
                            direction: Direction::ToFw,
                        },
                    ),
                    VtolState::TransitionToMc => b.push(
                        ts,
                        topic,
                        inst,
                        idx,
                        4,
                        EventKind::VtolTransitionStart {
                            direction: Direction::ToMc,
                        },
                    ),
                    _ => {}
                }
            }
        }
        prev = Some(r);
    }
}

/// SPEC B1.5 command pairing. Returns the result for each command, in input order.
///
/// An ack can match a command only if it has the same command id and targets the command's
/// source, so the candidates for a command are the acks of its (command, source) key whose
/// time is in `[command, next identical command)`. Those windows never overlap, so no ack can
/// be claimed twice and each key is paired in one pass: linear in the number of acks after
/// sorting, whatever the log holds.
pub fn pair_commands(commands: &[CommandRow], acks: &[AckRow]) -> Vec<CommandResult> {
    type Key = (u32, u64, u64);
    let mut by_key: BTreeMap<Key, Vec<usize>> = BTreeMap::new();
    for (i, c) in commands.iter().enumerate() {
        by_key
            .entry((c.command, c.source_system, c.source_component))
            .or_default()
            .push(i);
    }
    let mut acks_by_key: BTreeMap<Key, Vec<&AckRow>> = BTreeMap::new();
    for a in acks {
        acks_by_key
            .entry((a.command, a.target_system, a.target_component))
            .or_default()
            .push(a);
    }
    let mut results = vec![CommandResult::NoAck; commands.len()];
    for (key, mut idx) in by_key {
        let Some(mut list) = acks_by_key.remove(&key) else {
            continue;
        };
        list.sort_by_key(|a| (a.id.ts, a.id.instance, a.id.index));
        idx.sort_by_key(|&i| {
            commands
                .get(i)
                .map(|c| (c.id.ts, c.id.instance, c.id.index))
        });
        for (pos, &ci) in idx.iter().enumerate() {
            let Some(c) = commands.get(ci) else { continue };
            let end = idx
                .get(pos + 1)
                .and_then(|&j| commands.get(j))
                .map(|n| n.id.ts);
            let first = list.partition_point(|a| a.id.ts < c.id.ts);
            let mut progress = None;
            let mut chosen = None;
            for a in list.get(first..).unwrap_or(&[]) {
                if end.is_some_and(|e| a.id.ts >= e) {
                    break;
                }
                if a.result == 5 {
                    progress.get_or_insert(a.result);
                } else {
                    chosen = Some(a.result);
                    break;
                }
            }
            if let (Some(r), Some(slot)) = (chosen.or(progress), results.get_mut(ci)) {
                *slot = CommandResult::Ack(r);
            }
        }
    }
    results
}

/// UTC offset from the first GPS sample with fix_type >= 2 and a nonzero `time_utc_usec`
/// (`vehicle_gps_position`, else `sensor_gps` instance 0). Never from `boot_time_utc_us`.
pub fn utc_offset(flight: &FlightLog) -> Option<i128> {
    let first = |rows: &[crate::ingest::GpsRow]| {
        rows.iter()
            .find(|g| g.fix_type.is_some_and(|f| f >= 2) && g.time_utc_usec.is_some_and(|u| u != 0))
            .and_then(|g| g.time_utc_usec.map(|u| i128::from(u) - i128::from(g.id.ts)))
    };
    first(&flight.vehicle_gps).or_else(|| first(&flight.sensor_gps))
}

/// Builds the ordered timeline, or says which limit the log exceeds.
pub fn build(flight: &FlightLog, config: &Config) -> Result<Vec<Event>, String> {
    let mut b = Builder {
        out: Vec::new(),
        overflow: false,
    };
    vehicle_status_events(&mut b, flight);

    let results = pair_commands(&flight.commands, &flight.acks);
    for (c, result) in flight.commands.iter().zip(results) {
        b.push(
            c.id.ts,
            "vehicle_command",
            c.id.instance,
            c.id.index,
            0,
            EventKind::Command {
                command: c.command,
                source_system: c.source_system,
                source_component: c.source_component,
                result,
            },
        );
    }

    let armed = armed_intervals(&flight.vehicle_status);
    let mut last: BTreeMap<&str, ParamValue> = config
        .params
        .iter()
        .map(|(k, v)| (k.as_str(), *v))
        .collect();
    for p in &flight.param_records {
        let old = last.get(p.name.as_str()).copied();
        let changed = old.is_none_or(|o| !o.same_as(&p.value));
        last.insert(p.name.as_str(), p.value);
        if changed && in_flight_record(&armed, p.time) {
            b.push(
                p.time,
                TOPIC_PARAMETER,
                0,
                p.index,
                0,
                EventKind::ParamChangedInFlight {
                    name: p.name.clone(),
                    old,
                    new: p.value,
                },
            );
        }
    }

    for l in &flight.log_records {
        b.push(
            l.time,
            TOPIC_LOGGING,
            0,
            l.index,
            0,
            EventKind::LogMessage {
                level: l.level,
                text: l.text.clone(),
            },
        );
    }
    for d in &flight.dropouts {
        b.push(
            d.time,
            TOPIC_DROPOUT,
            0,
            d.index,
            0,
            EventKind::LogDropout {
                duration_ms: d.duration_ms,
            },
        );
    }

    if b.overflow {
        return Err(format!("more than {MAX_EVENTS} events"));
    }
    let mut events = b.out;
    events.sort_by(|x, y| {
        (x.boot_us, x.topic.as_str(), x.instance, x.index, x.order).cmp(&(
            y.boot_us,
            y.topic.as_str(),
            y.instance,
            y.index,
            y.order,
        ))
    });
    let offset = utc_offset(flight);
    for (seq, e) in events.iter_mut().enumerate() {
        e.seq = seq as u64;
        e.utc_us = offset.and_then(|o| u64::try_from(i128::from(e.boot_us) + o).ok());
    }
    Ok(events)
}

fn opt_u8(v: Option<u8>) -> Value {
    v.map_or(Value::Null, |n| Value::Int(i64::from(n)))
}

/// The record form of one event (SPEC B1.7: no floats, u64 times as strings).
pub fn event_json(e: &Event, fw: &Firmware) -> Value {
    let mut o = Obj::new()
        .field("seq", Value::count(e.seq))
        .field("kind", Value::str(e.kind.name()))
        .field("boot_us", Value::u64_str(e.boot_us))
        .field("utc_us", e.utc_us.map_or(Value::Null, Value::u64_str))
        .field("topic", Value::str(e.topic.clone()))
        .field("instance", Value::Int(i64::from(e.instance)))
        .field("index", Value::count(e.index));
    match &e.kind {
        EventKind::Arm { initial, reason } => {
            o.set("initial", Value::Bool(*initial));
            o.set("reason", opt_u8(*reason));
            o.set(
                "reason_name",
                Value::opt_str(reason.and_then(|r| reason_name(r, fw))),
            );
        }
        EventKind::Disarm { reason } => {
            o.set("reason", opt_u8(*reason));
            o.set(
                "reason_name",
                Value::opt_str(reason.and_then(|r| reason_name(r, fw))),
            );
        }
        EventKind::NavStateChange { old, new } => {
            o.set("old", opt_u8(*old));
            o.set(
                "old_name",
                Value::opt_str(old.and_then(|s| nav_state_name(s, fw))),
            );
            o.set("new", Value::Int(i64::from(*new)));
            o.set("new_name", Value::opt_str(nav_state_name(*new, fw)));
        }
        EventKind::FailsafeSet { initial, flag } => {
            o.set("initial", Value::Bool(*initial));
            o.set("flag", Value::str(flag.clone()));
        }
        EventKind::FailsafeClear { flag } => {
            o.set("flag", Value::str(flag.clone()));
        }
        EventKind::Command {
            command,
            source_system,
            source_component,
            result,
        } => {
            o.set("command", Value::count(u64::from(*command)));
            o.set("source_system", Value::count(*source_system));
            o.set("source_component", Value::count(*source_component));
            o.set("result", Value::str(result.name()));
        }
        EventKind::VtolTransitionStart { direction }
        | EventKind::VtolTransitionEnd { direction }
        | EventKind::VtolTransitionAbort { direction } => {
            o.set("direction", Value::str(direction.as_str()));
        }
        EventKind::ParamChangedInFlight { name, old, new } => {
            o.set("name", Value::str(name.clone()));
            o.set("old", Value::opt_str(old.map(|v| v.to_string())));
            o.set("new", Value::str(new.to_string()));
        }
        EventKind::LogMessage { level, text } => {
            o.set("level", Value::Int(i64::from(*level)));
            match std::str::from_utf8(text) {
                Ok(s) => o.set("text", Value::str(s)),
                Err(_) => {
                    o.set("text", Value::str(String::from_utf8_lossy(text)));
                    o.set("text_hex", Value::str(crate::hex(text)));
                }
            }
        }
        EventKind::LogDropout { duration_ms } => {
            o.set("duration_ms", Value::Int(i64::from(*duration_ms)));
        }
    }
    o.build()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::ingest::{FlagDef, RowId};

    #[allow(clippy::too_many_arguments)]
    fn vs(
        ts: u64,
        index: u64,
        arming: u8,
        nav: u8,
        failsafe: bool,
        trans: bool,
        to_fw: bool,
        vtype: u8,
    ) -> VehicleStatusRow {
        VehicleStatusRow {
            id: RowId {
                ts,
                instance: 0,
                index,
            },
            arming_state: Some(arming),
            nav_state: Some(nav),
            failsafe: Some(failsafe),
            is_vtol: Some(true),
            in_transition_mode: Some(trans),
            in_transition_to_fw: Some(to_fw),
            vehicle_type: Some(vtype),
            system_type: Some(22),
            latest_arming_reason: Some(3),
            latest_disarming_reason: Some(6),
        }
    }

    fn kinds(events: &[Event]) -> Vec<String> {
        events
            .iter()
            .map(|e| match &e.kind {
                EventKind::VtolTransitionStart { direction }
                | EventKind::VtolTransitionEnd { direction }
                | EventKind::VtolTransitionAbort { direction } => {
                    format!("{}:{}", e.kind.name(), direction.as_str())
                }
                k => k.name().to_string(),
            })
            .collect()
    }

    fn fw() -> Firmware {
        Firmware {
            release: Some(0x0111_00FF),
            version: Some("1.17.0".into()),
            git: None,
        }
    }

    #[test]
    fn vtol_states_give_start_end_abort_and_ignore_quadchute() {
        let rows = vec![
            vs(0, 0, 2, 4, false, false, false, 1),
            vs(10, 1, 2, 4, false, true, true, 1), // start to_fw
            vs(20, 2, 2, 4, false, false, false, 2), // end to_fw
            vs(30, 3, 2, 4, false, false, false, 1), // quadchute FW to MC: nothing
            vs(40, 4, 2, 4, false, true, true, 1), // start to_fw
            vs(50, 5, 2, 4, false, true, false, 1), // abort to_fw, start to_mc
            vs(60, 6, 2, 4, false, false, false, 1), // end to_mc
            vs(70, 7, 2, 4, false, true, true, 1), // start to_fw, then log ends
        ];
        let flight = FlightLog {
            vehicle_status: rows,
            ..FlightLog::default()
        };
        let ev = build(&flight, &Config::default()).unwrap();
        let k: Vec<String> = kinds(&ev)
            .into_iter()
            .filter(|k| k.starts_with("VTOL"))
            .collect();
        assert_eq!(
            k,
            [
                "VTOL_TRANSITION_START:to_fw",
                "VTOL_TRANSITION_END:to_fw",
                "VTOL_TRANSITION_START:to_fw",
                "VTOL_TRANSITION_ABORT:to_fw",
                "VTOL_TRANSITION_START:to_mc",
                "VTOL_TRANSITION_END:to_mc",
                "VTOL_TRANSITION_START:to_fw",
            ]
        );
        let seqs: Vec<u64> = ev.iter().map(|e| e.seq).collect();
        assert_eq!(seqs, (0..ev.len() as u64).collect::<Vec<_>>());
    }

    #[test]
    fn initial_arm_and_first_nav_state() {
        let rows = vec![
            vs(5, 0, 2, 4, false, false, false, 1),
            vs(9, 1, 1, 4, false, false, false, 1),
        ];
        let flight = FlightLog {
            vehicle_status: rows,
            ..FlightLog::default()
        };
        let ev = build(&flight, &Config::default()).unwrap();
        assert_eq!(kinds(&ev), ["ARM", "NAV_STATE_CHANGE", "DISARM"]);
        assert_eq!(
            ev.first().map(|e| e.kind.clone()),
            Some(EventKind::Arm {
                initial: true,
                reason: Some(3)
            })
        );
        let nav = event_json(&ev[1], &fw());
        assert_eq!(
            crate::json::canonical(&nav),
            "{\"boot_us\":\"5\",\"index\":0,\"instance\":0,\"kind\":\"NAV_STATE_CHANGE\",\"new\":4,\"new_name\":\"AUTO_LOITER\",\"old\":null,\"old_name\":null,\"seq\":1,\"topic\":\"vehicle_status\",\"utc_us\":null}"
        );
    }

    fn flag(name: &str) -> FlagDef {
        FlagDef::for_test(name)
    }

    #[test]
    fn failsafe_attribution_names_required_or_new_flags() {
        let fs = FailsafeFlags {
            flags: vec![flag("a_always"), flag("b_required"), flag("c_new")],
            rows: vec![
                FailsafeRow {
                    id: RowId {
                        ts: 0,
                        instance: 0,
                        index: 0,
                    },
                    active: vec![true, true, false],
                    mode_req: vec![0, 0, 0],
                },
                FailsafeRow {
                    id: RowId {
                        ts: 100,
                        instance: 0,
                        index: 1,
                    },
                    active: vec![true, true, true],
                    mode_req: vec![0, 1 << 4, 0],
                },
            ],
        };
        let rows = sorted_flag_rows(&fs);
        assert_eq!(
            attribute_failsafe(&fs, &rows, 150, Some(4), Some(10)),
            ["b_required", "c_new"]
        );
        assert_eq!(
            attribute_failsafe(&fs, &rows, 150, Some(5), Some(10)),
            ["c_new"]
        );
        assert_eq!(
            attribute_failsafe(&fs, &rows, 150, Some(5), Some(120)),
            ["unattributed"]
        );
        assert_eq!(
            attribute_failsafe(&fs, &rows, 150, Some(5), None),
            ["c_new"]
        );
        let empty = FailsafeFlags::default();
        assert_eq!(
            attribute_failsafe(&empty, &[], 150, Some(5), None),
            ["unattributed"]
        );
    }

    fn cmd(ts: u64, index: u64, command: u32, comp: u64) -> CommandRow {
        CommandRow {
            id: RowId {
                ts,
                instance: 0,
                index,
            },
            command,
            source_system: 1,
            source_component: comp,
        }
    }

    fn ack(ts: u64, index: u64, command: u32, result: u8, comp: u64) -> AckRow {
        AckRow {
            id: RowId {
                ts,
                instance: 0,
                index,
            },
            command,
            result,
            target_system: 1,
            target_component: comp,
        }
    }

    #[test]
    fn commands_pair_with_the_earliest_final_ack_in_their_window() {
        let commands = vec![
            cmd(10, 0, 400, 1),
            cmd(20, 1, 400, 1),
            cmd(30, 2, 211, 5184),
            cmd(40, 3, 22, 1),
        ];
        let acks = vec![
            ack(12, 0, 400, 0, 1),  // first 400
            ack(25, 1, 400, 2, 1),  // second 400, denied
            ack(31, 2, 211, 0, 64), // wrong component: no match
            ack(41, 3, 22, 5, 1),   // in progress
            ack(42, 4, 22, 0, 1),   // final wins
        ];
        let r: Vec<String> = pair_commands(&commands, &acks)
            .iter()
            .map(|r| r.name())
            .collect();
        assert_eq!(r, ["ACCEPTED", "DENIED", "NO_ACK", "ACCEPTED"]);
        // An ack before the next identical command is not taken by the later one.
        let r: Vec<String> = pair_commands(
            &[cmd(10, 0, 400, 1), cmd(20, 1, 400, 1)],
            &[ack(15, 0, 400, 0, 1)],
        )
        .iter()
        .map(|r| r.name())
        .collect();
        assert_eq!(r, ["ACCEPTED", "NO_ACK"]);
        // In progress only.
        let r = pair_commands(&[cmd(10, 0, 22, 1)], &[ack(11, 0, 22, 5, 1)]);
        assert_eq!(r, [CommandResult::Ack(5)]);
    }

    #[test]
    fn a_timeline_over_the_event_cap_is_refused() {
        // A failsafe that toggles on 8,000 rows while 256 flags are newly active names 256
        // flags per edge: about 2 million events, over the cap.
        let names: Vec<String> = (0..256).map(|i| format!("f{i:03}")).collect();
        let fs = FailsafeFlags {
            flags: names.iter().map(|n| flag(n)).collect(),
            rows: vec![
                FailsafeRow {
                    id: RowId {
                        ts: 0,
                        instance: 0,
                        index: 0,
                    },
                    active: vec![false; 256],
                    mode_req: vec![0; 256],
                },
                FailsafeRow {
                    id: RowId {
                        ts: 11,
                        instance: 0,
                        index: 1,
                    },
                    active: vec![true; 256],
                    mode_req: vec![0; 256],
                },
            ],
        };
        let rows = (0..8000u64)
            .map(|i| vs(10 + i, i, 2, 4, i % 2 == 0, false, false, 1))
            .collect();
        let flight = FlightLog {
            vehicle_status: rows,
            failsafe_flags: fs,
            ..FlightLog::default()
        };
        assert_eq!(
            build(&flight, &Config::default()),
            Err(format!("more than {MAX_EVENTS} events"))
        );
    }

    #[test]
    fn armed_lookups_match_a_linear_scan() {
        let armed = [
            ArmedInterval {
                arm: 5,
                disarm: Some(5),
            },
            ArmedInterval {
                arm: 5,
                disarm: Some(9),
            },
            ArmedInterval {
                arm: 9,
                disarm: Some(12),
            },
            ArmedInterval {
                arm: 20,
                disarm: None,
            },
        ];
        for t in 0..30 {
            assert_eq!(
                armed_sample(&armed, t),
                armed.iter().any(|a| a.contains_sample(t)),
                "sample {t}"
            );
            assert_eq!(
                in_flight_record(&armed, t),
                armed.iter().any(|a| a.contains_record(t)),
                "record {t}"
            );
        }
    }

    #[test]
    fn pairing_is_linear_on_adversarial_input() {
        // 20,000 distinct commands and 20,000 acks for one of them: a scan per command would
        // take 4e8 steps; the keyed pass takes about 40,000.
        let commands: Vec<CommandRow> = (0..20_000u64)
            .map(|i| cmd(i, i, 1000 + (i as u32), 1))
            .collect();
        let acks: Vec<AckRow> = (0..20_000u64).map(|i| ack(i, i, 1000, 5, 1)).collect();
        let started = std::time::Instant::now();
        let r = pair_commands(&commands, &acks);
        assert_eq!(r[0], CommandResult::Ack(5));
        assert!(r[1..].iter().all(|x| *x == CommandResult::NoAck));
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    #[test]
    fn utc_comes_only_from_gps_with_a_fix() {
        use crate::ingest::GpsRow;
        let g = |ts, fix, utc| GpsRow {
            id: RowId {
                ts,
                instance: 0,
                index: 0,
            },
            fix_type: Some(fix),
            satellites_used: None,
            time_utc_usec: Some(utc),
        };
        let flight = FlightLog {
            vehicle_gps: vec![
                g(100, 3, 0),
                g(200, 1, 5_000_000),
                g(300, 3, 1_700_000_000_000_300),
            ],
            sensor_gps: vec![g(50, 3, 9)],
            vehicle_status: vec![vs(1000, 0, 1, 4, false, false, false, 1)],
            ..FlightLog::default()
        };
        assert_eq!(utc_offset(&flight), Some(1_700_000_000_000_000));
        let ev = build(&flight, &Config::default()).unwrap();
        assert_eq!(
            ev.first().and_then(|e| e.utc_us),
            Some(1_700_000_000_001_000)
        );
        let none = FlightLog {
            vehicle_gps: vec![g(100, 3, 0)],
            ..FlightLog::default()
        };
        assert_eq!(utc_offset(&none), None);
    }

    #[test]
    fn nav_state_and_reason_names_depend_on_version() {
        let v = |r: u32| Firmware {
            release: Some(r),
            version: None,
            git: None,
        };
        assert_eq!(nav_state_name(8, &v(0x010E_04FF)), Some("UNUSED3"));
        assert_eq!(nav_state_name(8, &v(0x010F_04FF)), Some("FREE4"));
        assert_eq!(nav_state_name(8, &v(0x0111_00FF)), Some("ALTITUDE_CRUISE"));
        assert_eq!(nav_state_name(23, &v(0x010E_04FF)), Some("MAX"));
        assert_eq!(nav_state_name(30, &v(0x0110_02FF)), Some("EXTERNAL8"));
        assert_eq!(nav_state_name(4, &v(0x010D_00FF)), None);
        assert_eq!(reason_name(1, &v(0x010F_04FF)), Some("rc_stick"));
        assert_eq!(reason_name(1, &v(0x0110_02FF)), Some("stick_gesture"));
        assert_eq!(reason_name(15, &v(0x0111_00FF)), None);
    }
}
