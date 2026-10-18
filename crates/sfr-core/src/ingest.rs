//! Flight log ingestion (SPEC B1.2 `FlightLogIngestor`, B1.5).
//!
//! [`Px4Ingestor`] streams a PX4 ULog once: every byte is hashed (SHA-256 through the caller's
//! [`CryptoBackend`], BLAKE3 alongside) while [`crate::ulog::read`] decodes it, and only the
//! fields that the events and rules need are kept. Topic and field names come from
//! `docs/DIAGNOSTIC.md` item 4; a field that a version does not log stays `None`, and the rule
//! that needs it reports FAIL rather than guessing.

use crate::crypto::{CryptoBackend, Sha256Stream};
use crate::events::{self, Event};
use crate::ulog::{
    self, FlatField, Header, Layout, ParamValue, Scalar, Section, UlogError, Visitor,
};
use std::collections::BTreeMap;
use std::io::{self, BufReader, Read};

/// Why a log could not be ingested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngestError {
    /// The bytes are not a readable log (SPEC B1.4 exit 3).
    Malformed(UlogError),
    /// Reading failed (SPEC B1.4 exit 4).
    Io(String),
    /// The log is readable but exceeds a limit `sfr` sets so that a small crafted file
    /// cannot exhaust memory or time (SPEC B1.4 exit 3).
    Limit(String),
}

/// Most flags (`bool` fields plus `battery_warning`) a `failsafe_flags` format may have. PX4
/// v1.14 to v1.17 log 26 to 28.
pub const MAX_FAILSAFE_FLAGS: usize = 256;

impl std::fmt::Display for IngestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IngestError::Malformed(e) => write!(f, "{e}"),
            IngestError::Io(e) => write!(f, "read error: {e}"),
            IngestError::Limit(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for IngestError {}

/// Firmware identity from the ULog info messages `ver_sw_release` and `ver_sw`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Firmware {
    /// Raw `ver_sw_release` (0xAABBCCTT).
    pub release: Option<u32>,
    /// `major.minor.patch`, with `-rc`, `-beta`, `-alpha` or `-dev` unless TT is 255.
    pub version: Option<String>,
    /// `ver_sw`, the firmware git hash.
    pub git: Option<String>,
}

impl Firmware {
    /// Major and minor version, for per-version enum names.
    pub fn series(&self) -> Option<(u8, u8)> {
        let r = self.release?;
        Some(((r >> 24) as u8, (r >> 16) as u8))
    }
}

/// Formats `ver_sw_release` as `sfr` prints it everywhere (record, baseline, report).
pub fn version_string(release: u32) -> Option<String> {
    if release == 0 {
        return None;
    }
    let [major, minor, patch, ty] = release.to_be_bytes();
    let suffix = match ty {
        255 => "",
        192..=254 => "-rc",
        128..=191 => "-beta",
        64..=127 => "-alpha",
        _ => "-dev",
    };
    Some(format!("{major}.{minor}.{patch}{suffix}"))
}

/// Vehicle identity from the first `vehicle_status` sample.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Vehicle {
    /// `vehicle_status.system_type` (MAVLink MAV_TYPE).
    pub system_type: Option<u8>,
    /// `vehicle_status.is_vtol`.
    pub is_vtol: Option<bool>,
}

/// SPEC B1.5 log identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogIdentity {
    /// File name as given by the caller (no directory).
    pub file_name: String,
    /// Size in bytes.
    pub size: u64,
    /// SHA-256 of the raw bytes, from the FIPS module in the CLI.
    pub sha256: [u8; 32],
    /// BLAKE3 of the raw bytes (supplementary).
    pub blake3: [u8; 32],
    /// Firmware.
    pub firmware: Firmware,
    /// Vehicle type.
    pub vehicle: Vehicle,
}

/// SPEC B1.5 configuration: the parameter set at log start.
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// Firmware version string, if the log has `ver_sw_release`.
    pub firmware: Option<String>,
    /// Parameters from the definitions section, sorted by name.
    pub params: BTreeMap<String, ParamValue>,
}

/// Where a decoded row came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RowId {
    /// Data timestamp, boot microseconds.
    pub ts: u64,
    /// uORB instance (`multi_id`).
    pub instance: u8,
    /// Index of the row among the data records of this topic and instance.
    pub index: u64,
}

/// One `vehicle_status` sample. A field the log does not have is `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct VehicleStatusRow {
    pub id: RowId,
    pub arming_state: Option<u8>,
    pub nav_state: Option<u8>,
    pub failsafe: Option<bool>,
    pub is_vtol: Option<bool>,
    pub in_transition_mode: Option<bool>,
    pub in_transition_to_fw: Option<bool>,
    pub vehicle_type: Option<u8>,
    pub system_type: Option<u8>,
    pub latest_arming_reason: Option<u8>,
    pub latest_disarming_reason: Option<u8>,
}

/// One flag of `failsafe_flags`: every `bool` field, plus `battery_warning` (true above 0).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlagDef {
    /// Field name as logged by this firmware version.
    pub name: String,
    field: FlatField,
    requirement: Option<FlatField>,
}

/// One `failsafe_flags` sample, aligned with [`FailsafeFlags::flags`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailsafeRow {
    /// Source row.
    pub id: RowId,
    /// Whether each flag is active.
    pub active: Vec<bool>,
    /// The flag's `mode_req_*` bitmask (bit `1 << nav_state`), or 0 when it has none.
    pub mode_req: Vec<u32>,
}

/// The `failsafe_flags` topic of one instance.
#[derive(Debug, Clone, Default)]
pub struct FailsafeFlags {
    /// Flag definitions from the logged format.
    pub flags: Vec<FlagDef>,
    /// Samples in file order.
    pub rows: Vec<FailsafeRow>,
}

/// One `vehicle_command` sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct CommandRow {
    pub id: RowId,
    pub command: u32,
    pub source_system: u64,
    pub source_component: u64,
}

/// One `vehicle_command_ack` sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct AckRow {
    pub id: RowId,
    pub command: u32,
    pub result: u8,
    pub target_system: u64,
    pub target_component: u64,
}

/// One GPS sample (`vehicle_gps_position` or `sensor_gps`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct GpsRow {
    pub id: RowId,
    pub fix_type: Option<u8>,
    pub satellites_used: Option<u8>,
    pub time_utc_usec: Option<u64>,
}

/// One `battery_status` sample.
#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(missing_docs)]
pub struct BatteryRow {
    pub id: RowId,
    pub remaining: Option<f32>,
    pub connected: Option<bool>,
}

/// One `estimator_status` sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct EstimatorRow {
    pub id: RowId,
    pub filter_fault_flags: Option<u64>,
}

/// One `estimator_selector_status` sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct SelectorRow {
    pub id: RowId,
    pub primary_instance: Option<u8>,
}

/// One `vehicle_imu_status` sample.
#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(missing_docs)]
pub struct ImuRow {
    pub id: RowId,
    pub accel_device_id: Option<u64>,
    pub accel_clipping: Option<[u64; 3]>,
    pub accel_vibration_metric: Option<f32>,
}

/// One `sensor_selection` sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct SensorSelectionRow {
    pub id: RowId,
    pub accel_device_id: Option<u64>,
}

/// A data-section 'P' record.
#[derive(Debug, Clone)]
pub struct ParamRecord {
    /// Parameter name.
    pub name: String,
    /// New value.
    pub value: ParamValue,
    /// Largest data timestamp before the record (pyulog's rule).
    pub time: u64,
    /// Index among all 'P' records in the file, definitions included.
    pub index: u64,
}

/// An 'L' or 'C' record at warning level or above.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogRecord {
    /// Severity 0 (emergency) to 4 (warning).
    pub level: u8,
    /// The record's own timestamp.
    pub time: u64,
    /// Text bytes, verbatim.
    pub text: Vec<u8>,
    /// Index among all 'L' and 'C' records in the file.
    pub index: u64,
}

/// An 'O' record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DropoutRecord {
    /// Duration in milliseconds.
    pub duration_ms: u16,
    /// Largest data timestamp before the record.
    pub time: u64,
    /// Index among all 'O' records.
    pub index: u64,
}

/// Everything the events and rules read, decoded once.
#[derive(Debug, Clone, Default)]
pub struct FlightLog {
    /// File header timestamp.
    pub start_timestamp: u64,
    /// Data record count per topic, all instances (R1).
    pub topic_rows: BTreeMap<String, u64>,
    /// Flattened field names of the `vehicle_status` instance in use.
    pub vehicle_status_fields: Vec<String>,
    /// Flattened field names of the `failsafe_flags` instance in use.
    pub failsafe_flags_fields: Vec<String>,
    /// `vehicle_status`, lowest instance.
    pub vehicle_status: Vec<VehicleStatusRow>,
    /// `failsafe_flags`, lowest instance.
    pub failsafe_flags: FailsafeFlags,
    /// `vehicle_command`, all instances, file order.
    pub commands: Vec<CommandRow>,
    /// `vehicle_command_ack`, all instances, file order.
    pub acks: Vec<AckRow>,
    /// `vehicle_gps_position` instance 0.
    pub vehicle_gps: Vec<GpsRow>,
    /// `sensor_gps` instance 0.
    pub sensor_gps: Vec<GpsRow>,
    /// `battery_status`, all instances.
    pub battery: Vec<BatteryRow>,
    /// `estimator_status`, all instances.
    pub estimator: Vec<EstimatorRow>,
    /// `estimator_selector_status`.
    pub estimator_selector: Vec<SelectorRow>,
    /// `vehicle_imu_status`, all instances.
    pub imu: Vec<ImuRow>,
    /// `sensor_selection`.
    pub sensor_selection: Vec<SensorSelectionRow>,
    /// Data-section parameter records.
    pub param_records: Vec<ParamRecord>,
    /// Warning-or-above logged strings.
    pub log_records: Vec<LogRecord>,
    /// Dropouts.
    pub dropouts: Vec<DropoutRecord>,
    /// ULog reader counts.
    pub summary: ulog::Summary,
}

/// The result of ingesting one log.
#[derive(Debug, Clone)]
pub struct Ingested {
    /// Log identity.
    pub identity: LogIdentity,
    /// Configuration at log start.
    pub config: Config,
    /// Decoded data.
    pub flight: FlightLog,
    /// The ordered event timeline.
    pub events: Vec<Event>,
}

/// A flight log format `sfr` can read (SPEC B1.2).
pub trait FlightLogIngestor {
    /// Format name for messages.
    fn format(&self) -> &'static str;
    /// Reads and hashes the whole stream.
    fn ingest(
        &self,
        file_name: &str,
        input: &mut dyn Read,
        crypto: &dyn CryptoBackend,
    ) -> Result<Ingested, IngestError>;
}

/// PX4 ULog, v1.14 through v1.17.
#[derive(Debug, Default, Clone, Copy)]
pub struct Px4Ingestor;

struct Hashing<'a> {
    inner: &'a mut dyn Read,
    sha: Box<dyn Sha256Stream>,
    b3: blake3::Hasher,
    size: u64,
}

impl Read for Hashing<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if let Some(chunk) = buf.get(..n) {
            self.sha.update(chunk);
            self.b3.update(chunk);
            self.size = self.size.saturating_add(n as u64);
        }
        Ok(n)
    }
}

impl FlightLogIngestor for Px4Ingestor {
    fn format(&self) -> &'static str {
        "PX4 ULog"
    }

    fn ingest(
        &self,
        file_name: &str,
        input: &mut dyn Read,
        crypto: &dyn CryptoBackend,
    ) -> Result<Ingested, IngestError> {
        let mut hashing = Hashing {
            inner: input,
            sha: crypto.sha256_stream(),
            b3: blake3::Hasher::new(),
            size: 0,
        };
        let mut collector = Collector::default();
        let summary = {
            let mut buffered = BufReader::with_capacity(1 << 16, &mut hashing);
            let summary = ulog::read(&mut buffered, &mut collector).map_err(|e| match e {
                UlogError::Io(m) => IngestError::Io(m),
                other => IngestError::Malformed(other),
            })?;
            // The reader stops only at end of file, but drain anyway so the digests always
            // cover every byte.
            io::copy(&mut buffered, &mut io::sink()).map_err(|e| IngestError::Io(e.to_string()))?;
            summary
        };
        let Hashing { sha, b3, size, .. } = hashing;
        let sha256 = sha.finish();
        let blake3: [u8; 32] = *b3.finalize().as_bytes();
        collector.finish(file_name.to_string(), size, sha256, blake3, summary)
    }
}

// ---------------------------------------------------------------------------------------------
// Collector: a ulog::Visitor that keeps only what is needed.

fn field(layout: &Layout, name: &str) -> Option<FlatField> {
    layout.field(name).cloned()
}

/// A field that PX4 declares as `uint8_t`, `uint16_t` or `uint32_t` (DIAGNOSTIC 4.6). Any other
/// type is not PX4's schema and is treated as absent, so the record's integers stay small.
fn small_uint(layout: &Layout, name: &str) -> Option<FlatField> {
    field(layout, name).filter(|f| matches!(f.scalar, Scalar::U8 | Scalar::U16 | Scalar::U32))
}

fn get_u8(f: &Option<FlatField>, p: &[u8]) -> Option<u8> {
    f.as_ref()
        .and_then(|f| f.read_u64(p))
        .and_then(|v| u8::try_from(v).ok())
}

fn get_u64(f: &Option<FlatField>, p: &[u8]) -> Option<u64> {
    f.as_ref().and_then(|f| f.read_u64(p))
}

fn get_bool(f: &Option<FlatField>, p: &[u8]) -> Option<bool> {
    f.as_ref().and_then(|f| f.read_bool(p))
}

fn get_f32(f: &Option<FlatField>, p: &[u8]) -> Option<f32> {
    f.as_ref().and_then(|f| f.read_f32(p))
}

#[derive(Debug, Clone)]
struct VsDecoder {
    arming_state: Option<FlatField>,
    nav_state: Option<FlatField>,
    failsafe: Option<FlatField>,
    is_vtol: Option<FlatField>,
    in_transition_mode: Option<FlatField>,
    in_transition_to_fw: Option<FlatField>,
    vehicle_type: Option<FlatField>,
    system_type: Option<FlatField>,
    latest_arming_reason: Option<FlatField>,
    latest_disarming_reason: Option<FlatField>,
}

/// `failsafe_flags` flag name to its `mode_req_*` field, as PX4 `FailsafeBase::modeCanRun`
/// (v1.14.4 and v1.17.0 `failsafe/framework.cpp`) and `mode_req_manual_control` pair them.
const MODE_REQUIREMENTS: &[(&str, &str)] = &[
    ("angular_velocity_invalid", "mode_req_angular_velocity"),
    ("attitude_invalid", "mode_req_attitude"),
    ("local_position_invalid", "mode_req_local_position"),
    (
        "local_position_invalid_relaxed",
        "mode_req_local_position_relaxed",
    ),
    ("global_position_invalid", "mode_req_global_position"),
    (
        "global_position_invalid_relaxed",
        "mode_req_global_position_relaxed",
    ),
    ("local_altitude_invalid", "mode_req_local_alt"),
    ("auto_mission_missing", "mode_req_mission"),
    ("offboard_control_signal_lost", "mode_req_offboard_signal"),
    ("home_position_invalid", "mode_req_home_position"),
    ("manual_control_signal_lost", "mode_req_manual_control"),
    // HealthAndArmingChecks modeCheck.cpp clears the can-run bits of
    // mode_req_wind_and_flight_time_compliance when either flag is set.
    (
        "wind_limit_exceeded",
        "mode_req_wind_and_flight_time_compliance",
    ),
    (
        "flight_time_limit_exceeded",
        "mode_req_wind_and_flight_time_compliance",
    ),
];

fn failsafe_schema(layout: &Layout) -> Vec<FlagDef> {
    let mut flags = Vec::new();
    for f in &layout.fields {
        let is_flag =
            f.scalar == Scalar::Bool || (f.name == "battery_warning" && f.scalar == Scalar::U8);
        if !is_flag {
            continue;
        }
        let requirement = MODE_REQUIREMENTS
            .iter()
            .find(|(flag, _)| *flag == f.name)
            .and_then(|(_, req)| layout.field(req))
            .cloned();
        flags.push(FlagDef {
            name: f.name.clone(),
            field: f.clone(),
            requirement,
        });
    }
    flags.sort_by(|a, b| a.name.cmp(&b.name));
    flags
}

#[derive(Debug, Clone)]
enum Decoder {
    VehicleStatus(Box<VsDecoder>),
    Failsafe(Vec<FlagDef>),
    Command {
        command: Option<FlatField>,
        src_sys: Option<FlatField>,
        src_comp: Option<FlatField>,
    },
    Ack {
        command: Option<FlatField>,
        result: Option<FlatField>,
        tgt_sys: Option<FlatField>,
        tgt_comp: Option<FlatField>,
    },
    Gps {
        sensor: bool,
        fix: Option<FlatField>,
        sats: Option<FlatField>,
        utc: Option<FlatField>,
    },
    Battery {
        remaining: Option<FlatField>,
        connected: Option<FlatField>,
    },
    Estimator {
        faults: Option<FlatField>,
    },
    Selector {
        primary: Option<FlatField>,
    },
    Imu {
        dev: Option<FlatField>,
        clip: [Option<FlatField>; 3],
        vib: Option<FlatField>,
    },
    SensorSelection {
        dev: Option<FlatField>,
    },
    Count,
}

#[derive(Debug, Clone)]
struct Sub {
    topic: String,
    multi_id: u8,
    decoder: Decoder,
}

#[derive(Default)]
struct Collector {
    header: Option<Header>,
    ver_sw: Option<String>,
    ver_sw_release: Option<u32>,
    params: BTreeMap<String, ParamValue>,
    param_index: u64,
    log_index: u64,
    dropout_index: u64,
    subs: BTreeMap<u16, Sub>,
    row_index: BTreeMap<(String, u8), u64>,
    vs: BTreeMap<u8, (Vec<String>, Vec<VehicleStatusRow>)>,
    fs: BTreeMap<u8, (Vec<String>, FailsafeFlags)>,
    flight: FlightLog,
    limit: Option<String>,
}

impl Visitor for Collector {
    fn header(&mut self, header: &Header) {
        self.header = Some(*header);
    }

    fn info(&mut self, key_type: &str, key: &str, value: &[u8]) {
        match (key, key_type) {
            ("ver_sw", t) if t.starts_with("char[") => {
                let end = value.iter().position(|&b| b == 0).unwrap_or(value.len());
                let text = String::from_utf8_lossy(value.get(..end).unwrap_or(value))
                    .trim()
                    .to_string();
                self.ver_sw = Some(text);
            }
            ("ver_sw_release", "uint32_t") => {
                if let Ok(raw) = <[u8; 4]>::try_from(value) {
                    self.ver_sw_release = Some(u32::from_le_bytes(raw));
                }
            }
            _ => {}
        }
    }

    fn parameter(&mut self, name: &str, value: ParamValue, section: Section, last_timestamp: u64) {
        let index = self.param_index;
        self.param_index = self.param_index.saturating_add(1);
        match section {
            Section::Definitions => {
                if self.params.len() >= crate::params::MAX_PARAMS && !self.params.contains_key(name)
                {
                    self.limit.get_or_insert_with(|| {
                        crate::limit_exceeded(
                            "the number of parameters at log start",
                            crate::params::MAX_PARAMS,
                            "parameters",
                        )
                    });
                } else {
                    self.params.insert(name.to_string(), value);
                }
            }
            Section::Data => self.flight.param_records.push(ParamRecord {
                name: name.to_string(),
                value,
                time: last_timestamp,
                index,
            }),
        }
    }

    fn subscription(&mut self, msg_id: u16, multi_id: u8, topic: &str, layout: &Layout) {
        let l = layout;
        let decoder = match topic {
            "vehicle_status" => {
                self.vs.entry(multi_id).or_insert_with(|| {
                    (
                        l.fields.iter().map(|f| f.name.clone()).collect(),
                        Vec::new(),
                    )
                });
                Decoder::VehicleStatus(Box::new(VsDecoder {
                    arming_state: field(l, "arming_state"),
                    nav_state: field(l, "nav_state"),
                    failsafe: field(l, "failsafe"),
                    is_vtol: field(l, "is_vtol"),
                    in_transition_mode: field(l, "in_transition_mode"),
                    in_transition_to_fw: field(l, "in_transition_to_fw"),
                    vehicle_type: field(l, "vehicle_type"),
                    system_type: field(l, "system_type"),
                    latest_arming_reason: field(l, "latest_arming_reason"),
                    latest_disarming_reason: field(l, "latest_disarming_reason"),
                }))
            }
            "failsafe_flags" if failsafe_schema(l).len() > MAX_FAILSAFE_FLAGS => {
                self.limit.get_or_insert_with(|| {
                    crate::limit_exceeded(
                        "the number of failsafe_flags flag fields",
                        MAX_FAILSAFE_FLAGS,
                        "fields",
                    )
                });
                Decoder::Count
            }
            "failsafe_flags" => {
                let flags = failsafe_schema(l);
                self.fs.entry(multi_id).or_insert_with(|| {
                    (
                        l.fields.iter().map(|f| f.name.clone()).collect(),
                        FailsafeFlags {
                            flags: flags.clone(),
                            rows: Vec::new(),
                        },
                    )
                });
                Decoder::Failsafe(flags)
            }
            "vehicle_command" => Decoder::Command {
                command: small_uint(l, "command"),
                src_sys: small_uint(l, "source_system"),
                src_comp: small_uint(l, "source_component"),
            },
            "vehicle_command_ack" => Decoder::Ack {
                command: small_uint(l, "command"),
                result: small_uint(l, "result"),
                tgt_sys: small_uint(l, "target_system"),
                tgt_comp: small_uint(l, "target_component"),
            },
            "vehicle_gps_position" | "sensor_gps" => Decoder::Gps {
                sensor: topic == "sensor_gps",
                fix: field(l, "fix_type"),
                sats: field(l, "satellites_used"),
                utc: field(l, "time_utc_usec"),
            },
            "battery_status" => Decoder::Battery {
                remaining: field(l, "remaining"),
                connected: field(l, "connected"),
            },
            "estimator_status" => Decoder::Estimator {
                faults: field(l, "filter_fault_flags"),
            },
            "estimator_selector_status" => Decoder::Selector {
                primary: field(l, "primary_instance"),
            },
            "vehicle_imu_status" => Decoder::Imu {
                dev: field(l, "accel_device_id"),
                clip: [
                    field(l, "accel_clipping[0]"),
                    field(l, "accel_clipping[1]"),
                    field(l, "accel_clipping[2]"),
                ],
                vib: field(l, "accel_vibration_metric"),
            },
            "sensor_selection" => Decoder::SensorSelection {
                dev: field(l, "accel_device_id"),
            },
            _ => Decoder::Count,
        };
        self.subs.insert(
            msg_id,
            Sub {
                topic: topic.to_string(),
                multi_id,
                decoder,
            },
        );
    }

    fn data(&mut self, msg_id: u16, timestamp: u64, p: &[u8]) {
        let Some(sub) = self.subs.get(&msg_id) else {
            return;
        };
        let counter = self
            .row_index
            .entry((sub.topic.clone(), sub.multi_id))
            .or_insert(0);
        let id = RowId {
            ts: timestamp,
            instance: sub.multi_id,
            index: *counter,
        };
        *counter = counter.saturating_add(1);
        let rows = self.flight.topic_rows.entry(sub.topic.clone()).or_insert(0);
        *rows = rows.saturating_add(1);
        match &sub.decoder {
            Decoder::VehicleStatus(d) => {
                let row = VehicleStatusRow {
                    id,
                    arming_state: get_u8(&d.arming_state, p),
                    nav_state: get_u8(&d.nav_state, p),
                    failsafe: get_bool(&d.failsafe, p),
                    is_vtol: get_bool(&d.is_vtol, p),
                    in_transition_mode: get_bool(&d.in_transition_mode, p),
                    in_transition_to_fw: get_bool(&d.in_transition_to_fw, p),
                    vehicle_type: get_u8(&d.vehicle_type, p),
                    system_type: get_u8(&d.system_type, p),
                    latest_arming_reason: get_u8(&d.latest_arming_reason, p),
                    latest_disarming_reason: get_u8(&d.latest_disarming_reason, p),
                };
                if let Some((_, rows)) = self.vs.get_mut(&sub.multi_id) {
                    rows.push(row);
                }
            }
            Decoder::Failsafe(flags) => {
                let active = flags
                    .iter()
                    .map(|f| f.field.read_u64(p).is_some_and(|v| v != 0))
                    .collect();
                let mode_req = flags
                    .iter()
                    .map(|f| {
                        f.requirement
                            .as_ref()
                            .and_then(|r| r.read_u64(p))
                            .map_or(0, |v| v as u32)
                    })
                    .collect();
                if let Some((_, fs)) = self.fs.get_mut(&sub.multi_id) {
                    fs.rows.push(FailsafeRow {
                        id,
                        active,
                        mode_req,
                    });
                }
            }
            Decoder::Command {
                command,
                src_sys,
                src_comp,
            } => {
                if let (Some(c), Some(s), Some(k)) = (
                    get_u64(command, p),
                    get_u64(src_sys, p),
                    get_u64(src_comp, p),
                ) {
                    self.flight.commands.push(CommandRow {
                        id,
                        command: c as u32,
                        source_system: s,
                        source_component: k,
                    });
                }
            }
            Decoder::Ack {
                command,
                result,
                tgt_sys,
                tgt_comp,
            } => {
                if let (Some(c), Some(r), Some(s), Some(k)) = (
                    get_u64(command, p),
                    get_u8(result, p),
                    get_u64(tgt_sys, p),
                    get_u64(tgt_comp, p),
                ) {
                    self.flight.acks.push(AckRow {
                        id,
                        command: c as u32,
                        result: r,
                        target_system: s,
                        target_component: k,
                    });
                }
            }
            Decoder::Gps {
                sensor,
                fix,
                sats,
                utc,
            } => {
                if sub.multi_id == 0 {
                    let row = GpsRow {
                        id,
                        fix_type: get_u8(fix, p),
                        satellites_used: get_u8(sats, p),
                        time_utc_usec: get_u64(utc, p),
                    };
                    if *sensor {
                        self.flight.sensor_gps.push(row);
                    } else {
                        self.flight.vehicle_gps.push(row);
                    }
                }
            }
            Decoder::Battery {
                remaining,
                connected,
            } => self.flight.battery.push(BatteryRow {
                id,
                remaining: get_f32(remaining, p),
                connected: get_bool(connected, p),
            }),
            Decoder::Estimator { faults } => self.flight.estimator.push(EstimatorRow {
                id,
                filter_fault_flags: get_u64(faults, p),
            }),
            Decoder::Selector { primary } => self.flight.estimator_selector.push(SelectorRow {
                id,
                primary_instance: get_u8(primary, p),
            }),
            Decoder::Imu { dev, clip, vib } => {
                let [c0, c1, c2] = clip;
                let clipping = match (get_u64(c0, p), get_u64(c1, p), get_u64(c2, p)) {
                    (Some(a), Some(b), Some(c)) => Some([a, b, c]),
                    _ => None,
                };
                self.flight.imu.push(ImuRow {
                    id,
                    accel_device_id: get_u64(dev, p),
                    accel_clipping: clipping,
                    accel_vibration_metric: get_f32(vib, p),
                });
            }
            Decoder::SensorSelection { dev } => {
                self.flight.sensor_selection.push(SensorSelectionRow {
                    id,
                    accel_device_id: get_u64(dev, p),
                })
            }
            Decoder::Count => {}
        }
    }

    fn logging(&mut self, level: u8, _tag: Option<u16>, timestamp: u64, text: &[u8]) {
        let index = self.log_index;
        self.log_index = self.log_index.saturating_add(1);
        // PX4 writes the level as an ASCII digit, '0' emergency to '7' debug (DIAGNOSTIC 4.7).
        if (b'0'..=b'4').contains(&level) {
            self.flight.log_records.push(LogRecord {
                level: level - b'0',
                time: timestamp,
                text: text.to_vec(),
                index,
            });
        }
    }

    fn dropout(&mut self, duration_ms: u16, last_timestamp: u64) {
        let index = self.dropout_index;
        self.dropout_index = self.dropout_index.saturating_add(1);
        self.flight.dropouts.push(DropoutRecord {
            duration_ms,
            time: last_timestamp,
            index,
        });
    }
}

impl Collector {
    fn finish(
        mut self,
        file_name: String,
        size: u64,
        sha256: [u8; 32],
        blake3: [u8; 32],
        summary: ulog::Summary,
    ) -> Result<Ingested, IngestError> {
        if let Some(limit) = self.limit.take() {
            return Err(IngestError::Limit(limit));
        }
        // A log with no data records (a header, or a definitions section alone) is a file cut
        // short, not a flight with every topic missing.
        if self.flight.topic_rows.is_empty() {
            return Err(IngestError::Malformed(UlogError::Truncated {
                offset: size,
                what: "data section (the log ends before any data record)",
            }));
        }
        let mut flight = std::mem::take(&mut self.flight);
        flight.start_timestamp = self.header.map_or(0, |h| h.timestamp);
        flight.summary = summary;
        // The lowest instance that has rows, else the lowest subscribed one (whose fields R1
        // still reports): R1 counts rows of any instance, so the core rules must read one.
        let mut vs = std::mem::take(&mut self.vs);
        let vs_pick = vs
            .iter()
            .find(|(_, (_, r))| !r.is_empty())
            .or(vs.iter().next())
            .map(|(k, _)| *k);
        if let Some((fields, rows)) = vs_pick.and_then(|k| vs.remove(&k)) {
            flight.vehicle_status_fields = fields;
            flight.vehicle_status = rows;
        }
        let mut fs = std::mem::take(&mut self.fs);
        let fs_pick = fs
            .iter()
            .find(|(_, (_, f))| !f.rows.is_empty())
            .or(fs.iter().next())
            .map(|(k, _)| *k);
        if let Some((fields, flags)) = fs_pick.and_then(|k| fs.remove(&k)) {
            flight.failsafe_flags_fields = fields;
            flight.failsafe_flags = flags;
        }
        let release = self.ver_sw_release;
        let firmware = Firmware {
            release,
            version: release.and_then(version_string),
            git: self.ver_sw.clone(),
        };
        let first = flight.vehicle_status.first();
        let vehicle = Vehicle {
            system_type: first.and_then(|r| r.system_type),
            is_vtol: first.and_then(|r| r.is_vtol),
        };
        let identity = LogIdentity {
            file_name,
            size,
            sha256,
            blake3,
            firmware: firmware.clone(),
            vehicle,
        };
        let config = Config {
            firmware: firmware.version.clone(),
            params: std::mem::take(&mut self.params),
        };
        let events = events::build(&flight, &config).map_err(IngestError::Limit)?;
        Ok(Ingested {
            identity,
            config,
            flight,
            events,
        })
    }
}

#[cfg(test)]
impl FlagDef {
    pub(crate) fn for_test(name: &str) -> FlagDef {
        let field = FlatField {
            name: name.to_string(),
            offset: 0,
            scalar: Scalar::Bool,
        };
        FlagDef {
            name: name.to_string(),
            field,
            requirement: None,
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::crypto::test_backend::TestBackend;

    /// Returns at most `n` bytes per read, to exercise the streaming paths.
    struct Trickle<'a>(&'a [u8], usize);

    impl Read for Trickle<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.0.len().min(self.1).min(buf.len());
            let (head, tail) = self.0.split_at(n);
            buf[..n].copy_from_slice(head);
            self.0 = tail;
            Ok(n)
        }
    }

    #[test]
    fn streaming_digests_match_published_vectors() {
        // BLAKE3 official test vectors (BLAKE3-team/BLAKE3 test_vectors.json): input byte i is
        // i % 251. SHA-256 of "abc" is the FIPS 180-4 example.
        let cases = [
            (
                0usize,
                "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
            ),
            (
                1023,
                "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11",
            ),
            (
                102_400,
                "bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085",
            ),
        ];
        for (len, b3) in cases {
            let input: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let mut src = Trickle(&input, 7);
            let mut h = Hashing {
                inner: &mut src,
                sha: TestBackend.sha256_stream(),
                b3: blake3::Hasher::new(),
                size: 0,
            };
            io::copy(&mut h, &mut io::sink()).unwrap();
            assert_eq!(crate::hex(h.b3.finalize().as_bytes()), b3, "len {len}");
            assert_eq!(h.size, len as u64);
        }
        let mut src = Trickle(b"abc", 1);
        let mut h = Hashing {
            inner: &mut src,
            sha: TestBackend.sha256_stream(),
            b3: blake3::Hasher::new(),
            size: 0,
        };
        io::copy(&mut h, &mut io::sink()).unwrap();
        assert_eq!(
            crate::hex(&h.sha.finish()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn core_rules_read_the_lowest_instance_that_has_rows() {
        use crate::ulog::tests::Builder;
        let row = |ts: u64, arming: u8| {
            let mut p = ts.to_le_bytes().to_vec();
            p.push(arming);
            p
        };
        let log = Builder::new(0)
            .flags(&[])
            .format("vehicle_status:uint64_t timestamp;uint8_t arming_state;")
            .sub(0, 0, "vehicle_status")
            .sub(1, 1, "vehicle_status")
            .data(1, &row(5, 2))
            .data(1, &row(9, 1));
        let ing = Px4Ingestor
            .ingest("x.ulg", &mut &log.bytes[..], &TestBackend)
            .unwrap();
        assert_eq!(ing.flight.vehicle_status.len(), 2);
        assert!(ing.flight.vehicle_status.iter().all(|r| r.id.instance == 1));
        assert_eq!(ing.events.len(), 2, "ARM and DISARM from instance 1");
    }

    #[test]
    fn wind_and_flight_time_flags_carry_their_mode_requirement() {
        use crate::ulog::tests::Builder;
        let log = Builder::new(0).flags(&[]).format(
            "failsafe_flags:uint64_t timestamp;uint32_t mode_req_wind_and_flight_time_compliance;bool wind_limit_exceeded;bool flight_time_limit_exceeded;bool gcs_connection_lost;",
        ).sub(0, 0, "failsafe_flags");
        let mut payload = 7u64.to_le_bytes().to_vec();
        payload.extend_from_slice(&(1u32 << 4).to_le_bytes());
        payload.extend_from_slice(&[1, 0, 1]);
        let log = log.data(0, &payload);
        let ing = Px4Ingestor
            .ingest("x.ulg", &mut &log.bytes[..], &TestBackend)
            .unwrap();
        let fs = &ing.flight.failsafe_flags;
        let names: Vec<&str> = fs.flags.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "flight_time_limit_exceeded",
                "gcs_connection_lost",
                "wind_limit_exceeded"
            ]
        );
        assert_eq!(fs.rows[0].mode_req, [1 << 4, 0, 1 << 4]);
        assert_eq!(fs.rows[0].active, [false, true, true]);
    }

    #[test]
    fn exactly_the_parameter_and_flag_limits_are_accepted() {
        use crate::ulog::tests::Builder;
        let mut log = Builder::new(0).flags(&[]);
        for i in 0..crate::params::MAX_PARAMS {
            log = log.param_f(&format!("P{i}"), 1.0);
        }
        // With no data record the log is truncated; the parameter limit is checked first.
        let err = Px4Ingestor
            .ingest("x.ulg", &mut &log.bytes[..], &TestBackend)
            .unwrap_err();
        assert!(
            matches!(err, IngestError::Malformed(ref m) if m.to_string().contains("ends before any data record")),
            "{err}"
        );
        let mut format = String::from("failsafe_flags:uint64_t timestamp;");
        for i in 0..MAX_FAILSAFE_FLAGS {
            format.push_str(&format!("bool f{i};"));
        }
        let log = Builder::new(0)
            .flags(&[])
            .format(&format)
            .sub(0, 0, "failsafe_flags");
        let err = Px4Ingestor
            .ingest("x.ulg", &mut &log.bytes[..], &TestBackend)
            .unwrap_err();
        assert!(
            matches!(err, IngestError::Malformed(ref m) if m.to_string().contains("ends before any data record")),
            "{err}"
        );
    }

    #[test]
    fn too_many_parameters_at_log_start_are_refused() {
        use crate::ulog::tests::Builder;
        let mut log = Builder::new(0).flags(&[]);
        for i in 0..=crate::params::MAX_PARAMS {
            log = log.param_f(&format!("P{i}"), 1.0);
        }
        let err = Px4Ingestor
            .ingest("x.ulg", &mut &log.bytes[..], &TestBackend)
            .unwrap_err();
        assert_eq!(
            err,
            IngestError::Limit(
                "the number of parameters at log start exceeds the input limit of 65536 parameters (SPEC B1.4)"
                    .to_string()
            )
        );
    }

    #[test]
    fn a_failsafe_flags_format_with_too_many_flags_is_refused() {
        use crate::ulog::tests::Builder;
        let mut format = String::from("failsafe_flags:uint64_t timestamp;");
        for i in 0..=MAX_FAILSAFE_FLAGS {
            format.push_str(&format!("bool f{i};"));
        }
        let log = Builder::new(0)
            .flags(&[])
            .format(&format)
            .sub(0, 0, "failsafe_flags");
        let err = Px4Ingestor
            .ingest("x.ulg", &mut &log.bytes[..], &TestBackend)
            .unwrap_err();
        assert_eq!(
            err,
            IngestError::Limit(
                "the number of failsafe_flags flag fields exceeds the input limit of 256 fields (SPEC B1.4)"
                    .to_string()
            )
        );
        assert!(
            err.to_string()
                .starts_with("the number of failsafe_flags flag fields exceeds")
        );
    }

    #[test]
    fn ingest_hashes_every_byte_of_a_real_log() {
        let bytes = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/sitl/v1.17.0/mc_flight_1.ulg"
        ))
        .unwrap();
        let mut src = Trickle(&bytes, 4093);
        let ing = Px4Ingestor
            .ingest("mc_flight_1.ulg", &mut src, &TestBackend)
            .unwrap();
        // sha256sum testdata/sitl/v1.17.0/mc_flight_1.ulg
        assert_eq!(
            crate::hex(&ing.identity.sha256),
            "6e7b6956c20422aa9f31a13e7f074e80cba85760928fd895eed941e9492823fc"
        );
        assert_eq!(ing.identity.blake3, *blake3::hash(&bytes).as_bytes());
        assert_eq!(ing.identity.size, bytes.len() as u64);
        assert_eq!(ing.flight.summary.bytes, bytes.len() as u64);
        assert_eq!(ing.identity.firmware.version.as_deref(), Some("1.17.0"));
        assert_eq!(
            ing.identity.vehicle,
            Vehicle {
                system_type: Some(2),
                is_vtol: Some(false)
            }
        );
        assert_eq!(ing.events.len(), 22);
    }

    #[test]
    fn version_strings_follow_px4_firmware_type_bands() {
        assert_eq!(version_string(0x0111_00FF).as_deref(), Some("1.17.0"));
        assert_eq!(version_string(0x010E_04FF).as_deref(), Some("1.14.4"));
        assert_eq!(version_string(0x010F_00C0).as_deref(), Some("1.15.0-rc"));
        assert_eq!(version_string(0x010F_0080).as_deref(), Some("1.15.0-beta"));
        assert_eq!(version_string(0x010F_0040).as_deref(), Some("1.15.0-alpha"));
        assert_eq!(version_string(0x010F_0000).as_deref(), Some("1.15.0-dev"));
        assert_eq!(version_string(0), None);
    }
}
