//! Flight log ingestion (SPEC B1.2 `FlightLogIngestor`, B1.5).
//!
//! [`Px4Ingestor`] streams a PX4 ULog once: every byte is hashed (SHA-256 through the caller's
//! [`CryptoBackend`], BLAKE3 alongside) while [`crate::ulog::read`] decodes it, and only the
//! fields that the events and rules need are kept. Topic and field names come from
//! the PX4 message definitions of each supported version; a field that a version does not log stays `None`, and the rule
//! that needs it reports FAIL rather than guessing.

use crate::crypto::{CryptoBackend, Sha256Stream};
use crate::events::{self, Event};
use crate::ulog::{
    self, FlatField, Header, Layout, ParamValue, Scalar, Section, UlogError, Visitor,
};
use std::collections::BTreeMap;
use std::io::{self, BufReader, Read};
use std::rc::Rc;

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

/// Vehicle identity from the first `vehicle_status` sample, and the VTOL subtype.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Vehicle {
    /// `vehicle_status.system_type` (MAVLink MAV_TYPE).
    pub system_type: Option<u8>,
    /// `vehicle_status.is_vtol`.
    pub is_vtol: Option<bool>,
    /// The VTOL subtype from parameter `VT_TYPE`, when `is_vtol` is true on some sample.
    pub vtol_type: Option<VtolType>,
}

/// SPEC B1.5 `vtol_type`: parameter `VT_TYPE` and its PX4 name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VtolType {
    /// The raw integer, or `None` when the log has no int32 `VT_TYPE`.
    pub value: Option<i32>,
    /// `tailsitter`, `tiltrotor`, `standard`, `unknown(<n>)`, or `unknown` without a value.
    pub name: String,
}

impl VtolType {
    /// From the parameter set at log start (PX4's mapping).
    pub fn from_params(params: &BTreeMap<String, ParamValue>) -> VtolType {
        match params.get("VT_TYPE") {
            Some(ParamValue::I32(n)) => VtolType {
                value: Some(*n),
                name: match n {
                    0 => "tailsitter".to_string(),
                    1 => "tiltrotor".to_string(),
                    2 => "standard".to_string(),
                    other => format!("unknown({other})"),
                },
            },
            _ => VtolType {
                value: None,
                name: "unknown".to_string(),
            },
        }
    }
}

/// SPEC B1.5 sealed topic digest: one instance of a topic the rules file seals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedTopicDigest {
    /// Topic name.
    pub topic: String,
    /// uORB instance.
    pub multi_id: u8,
    /// SHA-256 of the topic's 'F' record payload exactly as stored (`<name>:<fields>`).
    pub format_sha256: [u8; 32],
    /// Data records of this instance.
    pub message_count: u64,
    /// The timestamp field of the first data record in file order.
    pub first_timestamp_us: Option<u64>,
    /// The timestamp field of the last data record in file order.
    pub last_timestamp_us: Option<u64>,
    /// SHA-256 over the data records in file order, each as its payload length (8 bytes,
    /// little-endian) followed by the payload without the message id.
    pub data_sha256: [u8; 32],
}

/// SPEC B1.5 log identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogIdentity {
    /// File name as given by the caller (no directory).
    pub file_name: String,
    /// Size in bytes.
    pub size: u64,
    /// SHA-256 of the raw bytes.
    pub sha256: [u8; 32],
    /// BLAKE3 of the raw bytes: an index for finding the file, not part of the seal.
    pub blake3: [u8; 32],
    /// Firmware.
    pub firmware: Firmware,
    /// Vehicle type.
    pub vehicle: Vehicle,
    /// `vehicle_status` instances with data records; the rules read every one.
    pub vehicle_status_instances: u64,
    /// What the reader skipped: unknown record types, data records without a subscription,
    /// regions before an appended-data offset.
    pub skipped: ulog::Summary,
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

/// One `vehicle_status` sample. A field the log does not have, or has with a type other than
/// the one PX4 defines, is `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct VehicleStatusRow {
    pub id: RowId,
    /// Position among the data and parameter records of the file, in file order.
    pub file_order: u64,
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

/// A rule input field logged with a type other than the one the PX4 message definitions of
/// v1.14 to v1.17 give it. The rules that read the field cannot evaluate it (SPEC B1.6).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TypeMismatch {
    /// Topic.
    pub topic: String,
    /// Flattened field name.
    pub field: String,
    /// The type the log declares.
    pub found: &'static str,
    /// The types PX4 defines at the release tags the log's version selects, joined with " or ";
    /// empty when none of them defines the field.
    pub expected: String,
    /// Those release tags ([`crate::px4::tags_label`]).
    pub tags: String,
}

impl std::fmt::Display for TypeMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.expected.is_empty() {
            write!(
                f,
                "{}.{} is {} in the log; PX4 {} does not define it",
                self.topic, self.field, self.found, self.tags
            )
        } else {
            write!(
                f,
                "{}.{} is {} in the log; PX4 defines {} ({})",
                self.topic, self.field, self.found, self.expected, self.tags
            )
        }
    }
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
    /// uORB instance.
    pub multi_id: u8,
    /// Fields of the logged format that no supported PX4 release defines in `failsafe_flags`,
    /// so they are not read.
    pub ignored: Vec<String>,
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
    /// Position among the data and parameter records of the file, in file order.
    pub file_order: u64,
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
    /// Flattened field names every `vehicle_status` subscription with data records has (the
    /// first subscription's when none has data).
    pub vehicle_status_fields: Vec<String>,
    /// The same for `failsafe_flags`.
    pub failsafe_flags_fields: Vec<String>,
    /// Flattened field names that every `vehicle_command` subscription with data records has
    /// (R1 checks the ones R7 reads); empty when no subscription has data.
    pub vehicle_command_fields: Vec<String>,
    /// `vehicle_status`, every instance with data records: grouped by instance in instance
    /// order, each in file order ([`FlightLog::vehicle_status_instances`]).
    pub vehicle_status: Vec<VehicleStatusRow>,
    /// `failsafe_flags`, the lowest instance with data records (else the lowest subscribed).
    pub failsafe_flags: FailsafeFlags,
    /// `failsafe_flags`, every other instance with data records, in instance order.
    pub failsafe_flags_others: Vec<FailsafeFlags>,
    /// Rule input fields logged with a type other than PX4's, sorted.
    pub type_mismatches: Vec<TypeMismatch>,
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

impl FlightLog {
    /// The rows of each `vehicle_status` instance, in instance order.
    pub fn vehicle_status_instances(&self) -> Vec<&[VehicleStatusRow]> {
        self.vehicle_status
            .chunk_by(|a, b| a.id.instance == b.id.instance)
            .collect()
    }

    /// The type mismatches of `topic`, as text, for the fields `fields` (all fields when
    /// empty).
    pub fn mismatches(&self, topic: &str, fields: &[&str]) -> Vec<String> {
        self.type_mismatches
            .iter()
            .filter(|m| {
                m.topic == topic && (fields.is_empty() || fields.contains(&m.field.as_str()))
            })
            .map(|m| m.to_string())
            .collect()
    }
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
    /// Digests of the sealed topics' instances, sorted by topic, then instance.
    pub sealed_topics: Vec<SealedTopicDigest>,
}

/// A flight log format `sfr` can read (SPEC B1.2).
pub trait FlightLogIngestor {
    /// Format name for messages.
    fn format(&self) -> &'static str;
    /// Reads and hashes the whole stream, and digests every instance of `sealed_topics`.
    fn ingest_sealing(
        &self,
        file_name: &str,
        input: &mut dyn Read,
        crypto: &dyn CryptoBackend,
        sealed_topics: &[String],
    ) -> Result<Ingested, IngestError>;
    /// Reads and hashes the whole stream; seals no topic.
    fn ingest(
        &self,
        file_name: &str,
        input: &mut dyn Read,
        crypto: &dyn CryptoBackend,
    ) -> Result<Ingested, IngestError> {
        self.ingest_sealing(file_name, input, crypto, &[])
    }
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

    fn ingest_sealing(
        &self,
        file_name: &str,
        input: &mut dyn Read,
        crypto: &dyn CryptoBackend,
        sealed_topics: &[String],
    ) -> Result<Ingested, IngestError> {
        let mut hashing = Hashing {
            inner: input,
            sha: crypto.sha256_stream(),
            b3: blake3::Hasher::new(),
            size: 0,
        };
        let mut collector = Collector {
            sealing: Sealing {
                crypto: Some(crypto),
                names: sealed_topics.iter().cloned().collect(),
                ..Sealing::default()
            },
            ..Collector::default()
        };
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

/// A field that PX4 declares as `uint8_t`, `uint16_t` or `uint32_t`. Any other
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

/// The fields a rule reads, besides `failsafe_flags`, whose every field PX4 defines is read.
/// Their types come from the PX4 source at each release tag ([`crate::px4`]).
const RULE_FIELDS: &[(&str, &str)] = &[
    ("vehicle_status", "arming_state"),
    ("vehicle_status", "nav_state"),
    ("vehicle_status", "failsafe"),
    ("vehicle_status", "is_vtol"),
    ("vehicle_status", "in_transition_mode"),
    ("vehicle_status", "in_transition_to_fw"),
    ("vehicle_status", "vehicle_type"),
    ("vehicle_status", "system_type"),
    ("vehicle_status", "latest_arming_reason"),
    ("vehicle_status", "latest_disarming_reason"),
    ("vehicle_command", "command"),
    ("vehicle_command", "source_system"),
    ("vehicle_command", "source_component"),
    ("battery_status", "remaining"),
    ("battery_status", "connected"),
    ("vehicle_gps_position", "fix_type"),
    ("vehicle_gps_position", "satellites_used"),
    ("estimator_status", "filter_fault_flags"),
    ("estimator_selector_status", "primary_instance"),
    ("vehicle_imu_status", "accel_device_id"),
    ("vehicle_imu_status", "accel_clipping[0]"),
    ("vehicle_imu_status", "accel_clipping[1]"),
    ("vehicle_imu_status", "accel_clipping[2]"),
    ("vehicle_imu_status", "accel_vibration_metric"),
    ("sensor_selection", "accel_device_id"),
];

/// Whether a rule reads `topic.name`.
fn rule_reads(topic: &str, name: &str) -> bool {
    if topic == "failsafe_flags" {
        return !crate::px4::any_field_types(topic, name).is_empty();
    }
    RULE_FIELDS.iter().any(|(t, f)| *t == topic && *f == name)
}

/// A rule input field, only when the log gives it a type PX4 defines for it at some supported
/// release; whether that is the type at the log's own release is checked when the log ends.
fn pinned(layout: &Layout, topic: &str, name: &str) -> Option<FlatField> {
    let f = layout.field(name)?;
    if rule_reads(topic, name) && !crate::px4::any_field_types(topic, name).contains(&f.scalar) {
        return None;
    }
    Some(f.clone())
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

/// The flags of a `failsafe_flags` format: every field PX4 defines as a `bool` (and
/// `battery_warning`, a `uint8`) at some supported release, each with the `mode_req_*` mask
/// that PX4's mode checks pair with it ([`crate::px4::mode_requirement`]). A field no release
/// defines is not read.
fn failsafe_schema(layout: &Layout) -> Vec<FlagDef> {
    let all: Vec<_> = crate::px4_tables::RELEASES.iter().collect();
    let mut flags = Vec::new();
    for f in &layout.fields {
        let px4 = crate::px4::field_types(&all, "failsafe_flags", &f.name);
        let is_flag = (f.scalar == Scalar::Bool && px4.contains(&Scalar::Bool))
            || (f.name == "battery_warning" && f.scalar == Scalar::U8 && px4.contains(&Scalar::U8));
        if !is_flag {
            continue;
        }
        let requirement = crate::px4::mode_requirement(&all, &f.name)
            .and_then(|req| pinned(layout, "failsafe_flags", req));
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
    Failsafe(Rc<Vec<FlagDef>>),
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
    layout: Rc<Layout>,
    /// Whether a data record of this subscription was read.
    had_data: bool,
    decoder: Decoder,
    /// Index into `Sealing::open` when the rules seal this topic.
    sealed: Option<usize>,
}

/// One sealed topic instance while reading.
struct SealAcc {
    format_sha256: [u8; 32],
    count: u64,
    first: Option<u64>,
    last: Option<u64>,
    sha: Box<dyn Sha256Stream>,
}

/// Sealed topic digests, computed while streaming; no data record is kept.
#[derive(Default)]
struct Sealing<'c> {
    crypto: Option<&'c dyn CryptoBackend>,
    names: std::collections::BTreeSet<String>,
    /// SHA-256 of the latest 'F' record of each sealed topic's format.
    formats: BTreeMap<String, [u8; 32]>,
    index: BTreeMap<(String, u8), usize>,
    open: Vec<SealAcc>,
}

/// One `failsafe_flags` instance while reading: its first subscription's schema.
struct FsInstance {
    flags: Rc<Vec<FlagDef>>,
    rows: Vec<FailsafeRow>,
    ignored: Vec<String>,
}

#[derive(Default)]
struct Collector<'c> {
    sealing: Sealing<'c>,
    header: Option<Header>,
    ver_sw: Option<String>,
    ver_sw_release: Option<u32>,
    params: BTreeMap<String, ParamValue>,
    param_index: u64,
    log_index: u64,
    dropout_index: u64,
    subs: BTreeMap<u16, Sub>,
    row_index: BTreeMap<(String, u8), u64>,
    // Per instance: its rows.
    vs: BTreeMap<u8, Vec<VehicleStatusRow>>,
    fs: BTreeMap<u8, FsInstance>,
    // The flag schema of the last failsafe_flags layout seen, so subscriptions sharing a
    // layout share one schema.
    fs_schema: Option<(Rc<Layout>, Rc<Vec<FlagDef>>)>,
    flight: FlightLog,
    limit: Option<String>,
    // Position of the next data or parameter record, in file order.
    order: u64,
}

impl Visitor for Collector<'_> {
    fn header(&mut self, header: &Header) {
        self.header = Some(*header);
    }

    fn format_definition(&mut self, name: &str, definition: &[u8]) {
        if let (true, Some(crypto)) = (self.sealing.names.contains(name), self.sealing.crypto) {
            self.sealing
                .formats
                .insert(name.to_string(), crypto.sha256(definition));
        }
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
        let file_order = self.order;
        self.order = self.order.saturating_add(1);
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
                file_order,
            }),
        }
    }

    fn subscription(&mut self, msg_id: u16, multi_id: u8, topic: &str, layout: &Rc<Layout>) {
        let l: &Layout = layout;
        let decoder = match topic {
            "vehicle_status" => {
                let vs = |name: &str| pinned(l, "vehicle_status", name);
                Decoder::VehicleStatus(Box::new(VsDecoder {
                    arming_state: vs("arming_state"),
                    nav_state: vs("nav_state"),
                    failsafe: vs("failsafe"),
                    is_vtol: vs("is_vtol"),
                    in_transition_mode: vs("in_transition_mode"),
                    in_transition_to_fw: vs("in_transition_to_fw"),
                    vehicle_type: vs("vehicle_type"),
                    system_type: vs("system_type"),
                    latest_arming_reason: vs("latest_arming_reason"),
                    latest_disarming_reason: vs("latest_disarming_reason"),
                }))
            }
            "failsafe_flags" => {
                let flags = match &self.fs_schema {
                    Some((cached, flags)) if Rc::ptr_eq(cached, layout) => Rc::clone(flags),
                    _ => {
                        let flags = Rc::new(failsafe_schema(l));
                        self.fs_schema = Some((Rc::clone(layout), Rc::clone(&flags)));
                        flags
                    }
                };
                // Only flags PX4 defines are read, so their number is bounded by the PX4
                // tables, not by the log.
                self.fs.entry(multi_id).or_insert_with(|| FsInstance {
                    flags: Rc::clone(&flags),
                    rows: Vec::new(),
                    // Fields no supported PX4 release defines: not read, and named in R4.
                    ignored: l
                        .fields
                        .iter()
                        .filter(|f| crate::px4::any_field_types(topic, &f.name).is_empty())
                        .map(|f| f.name.clone())
                        .collect(),
                });
                Decoder::Failsafe(flags)
            }
            "vehicle_command" => Decoder::Command {
                command: pinned(l, "vehicle_command", "command"),
                src_sys: pinned(l, "vehicle_command", "source_system"),
                src_comp: pinned(l, "vehicle_command", "source_component"),
            },
            "vehicle_command_ack" => Decoder::Ack {
                command: small_uint(l, "command"),
                result: small_uint(l, "result"),
                tgt_sys: small_uint(l, "target_system"),
                tgt_comp: small_uint(l, "target_component"),
            },
            "vehicle_gps_position" | "sensor_gps" => Decoder::Gps {
                sensor: topic == "sensor_gps",
                fix: pinned(l, "vehicle_gps_position", "fix_type"),
                sats: pinned(l, "vehicle_gps_position", "satellites_used"),
                utc: field(l, "time_utc_usec"),
            },
            "battery_status" => Decoder::Battery {
                remaining: pinned(l, topic, "remaining"),
                connected: pinned(l, topic, "connected"),
            },
            "estimator_status" => Decoder::Estimator {
                faults: pinned(l, topic, "filter_fault_flags"),
            },
            "estimator_selector_status" => Decoder::Selector {
                primary: pinned(l, topic, "primary_instance"),
            },
            "vehicle_imu_status" => Decoder::Imu {
                dev: pinned(l, topic, "accel_device_id"),
                clip: [
                    pinned(l, topic, "accel_clipping[0]"),
                    pinned(l, topic, "accel_clipping[1]"),
                    pinned(l, topic, "accel_clipping[2]"),
                ],
                vib: pinned(l, topic, "accel_vibration_metric"),
            },
            "sensor_selection" => Decoder::SensorSelection {
                dev: pinned(l, topic, "accel_device_id"),
            },
            _ => Decoder::Count,
        };
        let sealed = match (self.sealing.names.contains(topic), self.sealing.crypto) {
            (true, Some(crypto)) => {
                let key = (topic.to_string(), multi_id);
                let next = self.sealing.open.len();
                let i = *self.sealing.index.entry(key).or_insert(next);
                if i == next {
                    self.sealing.open.push(SealAcc {
                        format_sha256: self
                            .sealing
                            .formats
                            .get(topic)
                            .copied()
                            .unwrap_or_else(|| crypto.sha256(&[])),
                        count: 0,
                        first: None,
                        last: None,
                        sha: crypto.sha256_stream(),
                    });
                }
                Some(i)
            }
            _ => None,
        };
        self.subs.insert(
            msg_id,
            Sub {
                topic: topic.to_string(),
                multi_id,
                layout: Rc::clone(layout),
                had_data: false,
                decoder,
                sealed,
            },
        );
    }

    fn data(&mut self, msg_id: u16, timestamp: u64, p: &[u8]) {
        let file_order = self.order;
        self.order = self.order.saturating_add(1);
        let Some(sub) = self.subs.get_mut(&msg_id) else {
            return;
        };
        sub.had_data = true;
        let sub = &*sub;
        if let Some(acc) = sub.sealed.and_then(|i| self.sealing.open.get_mut(i)) {
            acc.count = acc.count.saturating_add(1);
            acc.first.get_or_insert(timestamp);
            acc.last = Some(timestamp);
            acc.sha.update(&(p.len() as u64).to_le_bytes());
            acc.sha.update(p);
        }
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
                    file_order,
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
                self.vs.entry(sub.multi_id).or_default().push(row);
            }
            Decoder::Failsafe(flags) => {
                let active = flags
                    .iter()
                    .map(|f| f.field.read_u64(p).is_some_and(|v| v != 0))
                    .collect();
                // A mode_req_* mask is a uint32 at every supported tag; pinned() reads no other.
                let mode_req = flags
                    .iter()
                    .map(|f| {
                        f.requirement
                            .as_ref()
                            .and_then(|r| r.read_u32(p))
                            .unwrap_or(0)
                    })
                    .collect();
                if let Some(inst) = self.fs.get_mut(&sub.multi_id) {
                    inst.rows.push(FailsafeRow {
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
                        command: u32::try_from(c).unwrap_or(u32::MAX),
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
        // PX4 writes the level as an ASCII digit, '0' emergency to '7' debug.
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

impl Collector<'_> {
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
        let release = self.ver_sw_release;
        let firmware = Firmware {
            release,
            version: release.and_then(version_string),
            git: self.ver_sw.clone(),
        };
        // Every vehicle_status instance with rows, in instance order (SPEC B1.6).
        flight.vehicle_status = std::mem::take(&mut self.vs)
            .into_values()
            .flatten()
            .collect();
        // A field counts as present only if every subscription of the topic with data records
        // has it (a later format record may redefine the topic for later subscriptions); a
        // subscription without data records says nothing, unless none has data.
        let common = |topic: &str| -> Vec<String> {
            let of_topic: Vec<&Sub> = self.subs.values().filter(|s| s.topic == topic).collect();
            let with_data: Vec<&Layout> = of_topic
                .iter()
                .filter(|s| s.had_data)
                .map(|s| &*s.layout)
                .collect();
            let layouts: Vec<&Layout> = if with_data.is_empty() {
                of_topic.first().map(|s| &*s.layout).into_iter().collect()
            } else {
                with_data
            };
            let Some((first, rest)) = layouts.split_first() else {
                return Vec::new();
            };
            first
                .fields
                .iter()
                .map(|f| f.name.clone())
                .filter(|n| rest.iter().all(|l| l.field(n).is_some()))
                .collect()
        };
        flight.vehicle_status_fields = common("vehicle_status");
        flight.failsafe_flags_fields = common("failsafe_flags");
        if self
            .subs
            .values()
            .any(|s| s.topic == "vehicle_command" && s.had_data)
        {
            flight.vehicle_command_fields = common("vehicle_command");
        }
        // The lowest failsafe_flags instance that has rows, else the lowest subscribed one; the
        // others with rows are kept for R4.
        let mut fs = std::mem::take(&mut self.fs);
        let fs_pick = fs
            .iter()
            .find(|(_, inst)| !inst.rows.is_empty())
            .or(fs.iter().next())
            .map(|(k, _)| *k);
        let to_flags = |multi_id: u8, inst: FsInstance| FailsafeFlags {
            multi_id,
            ignored: inst.ignored,
            flags: inst.flags.as_ref().clone(),
            rows: inst.rows,
        };
        if let Some(k) = fs_pick
            && let Some(inst) = fs.remove(&k)
        {
            flight.failsafe_flags = to_flags(k, inst);
        }
        flight.failsafe_flags_others = fs
            .into_iter()
            .filter(|(_, i)| !i.rows.is_empty())
            .map(|(k, i)| to_flags(k, i))
            .collect();
        // Rule inputs with a type other than PX4's at the release tags the log's version selects,
        // or that those tags do not define, in the subscriptions that have data records.
        let mut mismatches = std::collections::BTreeSet::new();
        let releases = crate::px4::releases_for(&firmware);
        let tags = crate::px4::tags_label(&releases);
        for sub in self.subs.values().filter(|s| s.had_data) {
            // sensor_gps is read only for the UTC offset, which no rule reads.
            let topic = sub.topic.as_str();
            if topic == "sensor_gps" {
                continue;
            }
            for f in &sub.layout.fields {
                if !rule_reads(topic, &f.name) {
                    continue;
                }
                let allowed = crate::px4::field_types(&releases, topic, &f.name);
                if !allowed.contains(&f.scalar) {
                    mismatches.insert(TypeMismatch {
                        topic: topic.to_string(),
                        field: f.name.clone(),
                        found: f.scalar.name(),
                        expected: allowed
                            .iter()
                            .map(|s| s.name())
                            .collect::<Vec<_>>()
                            .join(" or "),
                        tags: tags.clone(),
                    });
                }
            }
        }
        flight.type_mismatches = mismatches.into_iter().collect();
        let first = flight.vehicle_status.first();
        let vtol = flight
            .vehicle_status
            .iter()
            .any(|r| r.is_vtol == Some(true));
        let vehicle = Vehicle {
            system_type: first.and_then(|r| r.system_type),
            is_vtol: first.and_then(|r| r.is_vtol),
            vtol_type: vtol.then(|| VtolType::from_params(&self.params)),
        };
        let identity = LogIdentity {
            file_name,
            size,
            sha256,
            blake3,
            firmware: firmware.clone(),
            vehicle,
            vehicle_status_instances: flight.vehicle_status_instances().len() as u64,
            skipped: flight.summary.clone(),
        };
        let config = Config {
            firmware: firmware.version.clone(),
            params: std::mem::take(&mut self.params),
        };
        let events = events::build(&flight, &config).map_err(IngestError::Limit)?;
        let Sealing { index, open, .. } = std::mem::take(&mut self.sealing);
        let mut open: Vec<Option<SealAcc>> = open.into_iter().map(Some).collect();
        let sealed_topics = index
            .into_iter()
            .filter_map(|((topic, multi_id), i)| {
                let acc = open.get_mut(i)?.take()?;
                Some(SealedTopicDigest {
                    topic,
                    multi_id,
                    format_sha256: acc.format_sha256,
                    message_count: acc.count,
                    first_timestamp_us: acc.first,
                    last_timestamp_us: acc.last,
                    data_sha256: acc.sha.finish(),
                })
            })
            .collect();
        Ok(Ingested {
            identity,
            config,
            flight,
            events,
            sealed_topics,
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
    fn failsafe_subscriptions_share_one_schema() {
        // The 78 KB subscription-amplification log (scripts/testdata/make_amplification_seed.py).
        let log = include_bytes!("../../../fuzz/seeds/ulog_ingest/subscription_amplification.ulg");
        let mut c = Collector::default();
        crate::ulog::read(&log[..], &mut c).expect("readable");
        let schemas: Vec<&Rc<Vec<FlagDef>>> = c
            .subs
            .values()
            .filter_map(|s| match &s.decoder {
                Decoder::Failsafe(f) => Some(f),
                _ => None,
            })
            .collect();
        assert_eq!(schemas.len(), 3891);
        assert!(
            schemas.iter().all(|f| Rc::ptr_eq(f, schemas[0])),
            "one shared schema"
        );
        // Its 256 bool fields are not PX4 failsafe flags, so none is read.
        assert_eq!(schemas[0].len(), 0);
        assert_eq!(c.fs.len(), 256, "one entry per multi id");
        // R1 reports the missing core topic; nothing else is refused.
        let ing = Px4Ingestor
            .ingest("a.ulg", &mut &log[..], &TestBackend)
            .expect("ingests");
        assert!(ing.flight.vehicle_status.is_empty());
    }

    #[test]
    fn exactly_the_parameter_limit_is_accepted() {
        use crate::ulog::tests::Builder;
        let mut log = Builder::new(0).flags(&[]);
        for i in 0..crate::params::MAX_PARAMS {
            log = log.param_f(&format!("P{i}"), 1.0);
        }
        let log = log
            .format("t:uint64_t timestamp;")
            .sub(0, 0, "t")
            .data(0, &1u64.to_le_bytes());
        let ing = Px4Ingestor
            .ingest("x.ulg", &mut &log.bytes[..], &TestBackend)
            .expect("65,536 parameters are accepted");
        assert_eq!(ing.config.params.len(), crate::params::MAX_PARAMS);
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
                is_vtol: Some(false),
                vtol_type: None
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

    #[test]
    fn sealed_topics_are_digested_per_instance_while_streaming() {
        use crate::ulog::tests::Builder;
        use sha2::Digest;
        let format = "custom_detection:uint64_t timestamp;uint8_t[4] box;";
        let payload = |ts: u64, b: [u8; 4]| [&ts.to_le_bytes()[..], &b[..]].concat();
        let (a, b) = (payload(10, [1, 2, 3, 4]), payload(20, [5, 6, 7, 8]));
        let log = Builder::new(0)
            .flags(&[])
            .format(format)
            .format("other:uint64_t timestamp;")
            .sub(0, 1, "custom_detection")
            .sub(1, 2, "custom_detection")
            .sub(0, 3, "other")
            .data(1, &a)
            .data(3, &5u64.to_le_bytes())
            .data(1, &b);
        let sealed = ["custom_detection".to_string()];
        let ing = Px4Ingestor
            .ingest_sealing("x.ulg", &mut &log.bytes[..], &TestBackend, &sealed)
            .unwrap();
        let mut h = sha2::Sha256::new();
        for p in [&a, &b] {
            h.update((p.len() as u64).to_le_bytes());
            h.update(p);
        }
        let empty: [u8; 32] = sha2::Sha256::digest(b"").into();
        let format_sha256: [u8; 32] = sha2::Sha256::digest(format.as_bytes()).into();
        assert_eq!(
            ing.sealed_topics,
            [
                SealedTopicDigest {
                    topic: "custom_detection".into(),
                    multi_id: 0,
                    format_sha256,
                    message_count: 2,
                    first_timestamp_us: Some(10),
                    last_timestamp_us: Some(20),
                    data_sha256: h.finalize().into(),
                },
                SealedTopicDigest {
                    topic: "custom_detection".into(),
                    multi_id: 1,
                    format_sha256,
                    message_count: 0,
                    first_timestamp_us: None,
                    last_timestamp_us: None,
                    data_sha256: empty,
                },
            ]
        );
        // The values docs/RECORD_FORMAT.md gives for this example.
        assert_eq!(
            crate::hex(&format_sha256),
            "c05f82794614bc08b65ab3dbf5920fb43e7ffbda890061d06e79cfa5364d6143"
        );
        assert_eq!(
            ing.sealed_topics
                .first()
                .map(|d| crate::hex(&d.data_sha256)),
            Some("a933532016ce84d3fa02c2b0e1f09bab760869b1320c9450571b2f62c4eab43c".into())
        );
        assert_eq!(
            (crate::hex(&a), crate::hex(&b)),
            (
                "0a0000000000000001020304".into(),
                "140000000000000005060708".into()
            )
        );
        assert_eq!(
            crate::hex(&empty),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // Without sealing, nothing is digested.
        let plain = Px4Ingestor
            .ingest("x.ulg", &mut &log.bytes[..], &TestBackend)
            .unwrap();
        assert!(plain.sealed_topics.is_empty());
    }

    #[test]
    fn vtol_type_comes_from_vt_type_only_on_a_vtol_vehicle() {
        use crate::ulog::tests::Builder;
        let row = |ts: u64, vtol: u8| [&ts.to_le_bytes()[..], &[vtol][..]].concat();
        let log = |vt: Option<i32>, vtol: u8| {
            let b = Builder::new(0).flags(&[]);
            let b = match vt {
                Some(v) => b.param_i("VT_TYPE", v),
                None => b,
            };
            b.format("vehicle_status:uint64_t timestamp;bool is_vtol;")
                .sub(0, 0, "vehicle_status")
                .data(0, &row(1, 0))
                .data(0, &row(2, vtol))
        };
        let vtol_type = |vt: Option<i32>, vtol: u8| {
            Px4Ingestor
                .ingest("x.ulg", &mut &log(vt, vtol).bytes[..], &TestBackend)
                .unwrap()
                .identity
                .vehicle
                .vtol_type
                .map(|t| (t.value, t.name))
        };
        assert_eq!(vtol_type(Some(0), 1), Some((Some(0), "tailsitter".into())));
        assert_eq!(vtol_type(Some(1), 1), Some((Some(1), "tiltrotor".into())));
        assert_eq!(vtol_type(Some(2), 1), Some((Some(2), "standard".into())));
        assert_eq!(vtol_type(Some(7), 1), Some((Some(7), "unknown(7)".into())));
        assert_eq!(vtol_type(None, 1), Some((None, "unknown".into())));
        // is_vtol true on a later sample is enough; never true means no vtol_type.
        assert_eq!(vtol_type(Some(0), 0), None);
    }

    #[test]
    fn rule_inputs_with_another_type_than_px4_are_named() {
        use crate::ulog::tests::Builder;
        let log = Builder::new(0)
            .flags(&[])
            .format("vehicle_status:uint64_t timestamp;int8_t arming_state;uint8_t failsafe;bool is_vtol;")
            .format("failsafe_flags:uint64_t timestamp;uint64_t mode_req_attitude;uint8_t attitude_invalid;")
            .sub(0, 0, "vehicle_status")
            .sub(0, 1, "failsafe_flags")
            .data(0, &[&5u64.to_le_bytes()[..], &[2, 1, 0]].concat())
            .data(1, &[&5u64.to_le_bytes()[..], &0u64.to_le_bytes(), &[1]].concat());
        let ing = Px4Ingestor
            .ingest("x.ulg", &mut &log.bytes[..], &TestBackend)
            .unwrap();
        let named: Vec<String> = ing
            .flight
            .type_mismatches
            .iter()
            .map(|m| m.to_string())
            .collect();
        assert_eq!(
            named,
            [
                "failsafe_flags.attitude_invalid is uint8_t in the log; PX4 defines bool (v1.14.0 to v1.17.0)",
                "failsafe_flags.mode_req_attitude is uint64_t in the log; PX4 defines uint32_t (v1.14.0 to v1.17.0)",
                "vehicle_status.arming_state is int8_t in the log; PX4 defines uint8_t (v1.14.0 to v1.17.0)",
                "vehicle_status.failsafe is uint8_t in the log; PX4 defines bool (v1.14.0 to v1.17.0)",
            ]
        );
        // A mistyped field reads as absent, never as a guessed value.
        let row = ing.flight.vehicle_status[0];
        assert_eq!((row.arming_state, row.failsafe), (None, None));
        assert_eq!(row.is_vtol, Some(false));
    }

    #[test]
    fn source_component_follows_the_px4_version() {
        let fw = |release: u32| Firmware {
            release: Some(release),
            ..Firmware::default()
        };
        let types = |fw: &Firmware| {
            crate::px4::field_types(
                &crate::px4::releases_for(fw),
                "vehicle_command",
                "source_component",
            )
        };
        assert_eq!(types(&fw(0x010E_04FF)), [Scalar::U8]);
        assert_eq!(types(&fw(0x0111_00FF)), [Scalar::U16]);
        assert_eq!(types(&Firmware::default()), [Scalar::U8, Scalar::U16]);
    }

    // Tests from the ULog specification: docs/en/dev_log/ulog_file_format.md in PX4-Autopilot
    // (commit d28a64240f7b7570d65776b9b6397eddec0dd9ba), "Flag Bits Message" and "Requirements
    // for Parsers". docs/VALIDATION.md lists where sfr does otherwise.

    /// A flight: armed from 2 s to 6 s, failsafe at 4 s; one vehicle_status row per second.
    fn spec_flight_rows() -> Vec<Vec<u8>> {
        (1..=8u64)
            .map(|i| {
                let armed = (2..=6).contains(&i);
                [
                    &(i * 1_000_000).to_le_bytes()[..],
                    &[if armed { 2 } else { 1 }, 4, u8::from(i == 4)],
                ]
                .concat()
            })
            .collect()
    }

    fn spec_definitions(appended: &[u64]) -> crate::ulog::tests::Builder {
        crate::ulog::tests::Builder::new(0)
            .flags(appended)
            .format("vehicle_status:uint64_t timestamp;uint8_t arming_state;uint8_t nav_state;bool failsafe;")
            .sub(0, 0, "vehicle_status")
    }

    fn spec_ingest(bytes: &[u8]) -> Result<Ingested, IngestError> {
        Px4Ingestor.ingest("x.ulg", &mut &bytes[..], &TestBackend)
    }

    /// A log stating `ver_sw_release` with one failsafe_flags format and one row.
    fn flags_log(release: u32, format: &str, row: &[u8]) -> Ingested {
        let key = b"uint32_t ver_sw_release";
        let mut info = vec![key.len() as u8];
        info.extend_from_slice(key);
        info.extend_from_slice(&release.to_le_bytes());
        let log = crate::ulog::tests::Builder::new(0)
            .flags(&[])
            .rec(b'I', &info)
            .format(&format!("failsafe_flags:uint64_t timestamp;{format}"))
            .sub(0, 0, "failsafe_flags")
            .data(0, &[&5u64.to_le_bytes()[..], row].concat());
        Px4Ingestor
            .ingest("x.ulg", &mut &log.bytes[..], &TestBackend)
            .unwrap()
    }

    #[test]
    fn a_failsafe_flags_field_no_px4_release_defines_is_not_read_as_a_flag() {
        // gps_invalid is in no FailsafeFlags.msg from v1.14.0 to v1.17.0.
        let ing = flags_log(
            0x0111_00FF,
            "bool gps_invalid;bool gcs_connection_lost;",
            &[1, 1],
        );
        let fs = &ing.flight.failsafe_flags;
        let names: Vec<&str> = fs.flags.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["gcs_connection_lost"]);
        assert_eq!(fs.ignored, ["gps_invalid"]);
        assert!(ing.flight.type_mismatches.is_empty());
    }

    #[test]
    fn a_failsafe_flags_field_the_logs_release_does_not_define_is_a_mismatch() {
        // navigator_failure is in FailsafeFlags.msg from v1.16.0; a log that states v1.14.4 and
        // has it is not what PX4 v1.14.4 writes.
        let named = |release| -> Vec<String> {
            flags_log(release, "bool navigator_failure;", &[0])
                .flight
                .type_mismatches
                .iter()
                .map(|m| m.to_string())
                .collect()
        };
        assert_eq!(
            named(0x010E_04FF),
            ["failsafe_flags.navigator_failure is bool in the log; PX4 v1.14.4 does not define it"]
        );
        assert!(named(0x0110_00FF).is_empty());
        // global_position_invalid_relaxed and its mask, from v1.17.0 only.
        let ing = flags_log(
            0x010F_04FF,
            "uint32_t mode_req_global_position_relaxed;bool global_position_invalid_relaxed;",
            &[0, 0, 0, 0, 0],
        );
        assert_eq!(ing.flight.type_mismatches.len(), 2);
    }

    #[test]
    fn ulog_spec_every_unknown_incompat_bit_is_refused() {
        // "If a parser finds any of these bits set that isn't specified, it must refuse to parse
        // the log." Bit 0 of incompat_flags[0] (DATA_APPENDED) is the only one specified.
        let base = spec_definitions(&[]).data(0, &spec_flight_rows()[0]).bytes;
        // incompat_flags start after the header (16), the record header (3) and compat_flags (8).
        let at = 16 + 3 + 8;
        for bit in 1..64 {
            let mut b = base.clone();
            b[at + bit / 8] |= 1 << (bit % 8);
            let err = spec_ingest(&b).expect_err("refused");
            assert!(
                err.to_string().contains("unknown incompatible flag bits"),
                "bit {bit}: {err}"
            );
        }
        // Unknown compat_flags bits are for changes any parser can read: ignored.
        let mut b = base.clone();
        b[16 + 3..16 + 3 + 8].copy_from_slice(&[0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        spec_ingest(&b).expect("unknown compat bits are ignored");
    }

    #[test]
    fn ulog_spec_a_longer_flag_bits_message_is_read_and_its_extra_bytes_ignored() {
        // "If the msg_size is bigger than expected (currently 40), any additional bytes must be
        // ignored/discarded."
        let mut flags = vec![0u8; 40];
        flags.extend_from_slice(&[0xAA; 24]);
        let mut b = crate::ulog::tests::Builder::new(0).rec(b'B', &flags);
        b = b
            .format("vehicle_status:uint64_t timestamp;uint8_t arming_state;uint8_t nav_state;bool failsafe;")
            .sub(0, 0, "vehicle_status");
        for row in spec_flight_rows() {
            b = b.data(0, &row);
        }
        let ing = spec_ingest(&b.bytes).expect("read");
        assert_eq!(ing.flight.vehicle_status.len(), 8);
    }

    #[test]
    fn ulog_spec_unknown_message_types_are_skipped_and_counted() {
        // "Must ignore unknown messages (but it can print a warning)." Each type below is not one
        // the specification defines; the flight reads the same with or without them, and the
        // record counts them (log.skipped).
        let mut plain = spec_definitions(&[]);
        let mut noisy = spec_definitions(&[]);
        for (i, row) in spec_flight_rows().iter().enumerate() {
            plain = plain.data(0, row);
            noisy = noisy.data(0, row);
            noisy = noisy.rec(
                [b'Z', b'z', b'X', 0xFF, b'0', b'~', b'H', b'U'][i],
                &[i as u8; 7],
            );
        }
        let (plain, noisy) = (
            spec_ingest(&plain.bytes).unwrap(),
            spec_ingest(&noisy.bytes).unwrap(),
        );
        assert_eq!(noisy.events, plain.events);
        assert_eq!(noisy.flight.vehicle_status, plain.flight.vehicle_status);
        assert_eq!(noisy.flight.summary.unknown_records, 8);
        assert_eq!(plain.flight.summary.unknown_records, 0);
    }

    #[test]
    fn ulog_spec_appended_data_is_read_as_ordinary_data() {
        // "Appended data must be treated as if it was part of the regular Data section." The
        // same flight twice: whole, and cut in the middle of a record after its third row with
        // the other five rows (the failsafe, the disarm) appended at the announced offset.
        let rows = spec_flight_rows();
        let mut whole = spec_definitions(&[]);
        for row in &rows {
            whole = whole.data(0, row);
        }
        let mut main = spec_definitions(&[1]);
        for row in &rows[..3] {
            main = main.data(0, row);
        }
        let mut bytes = main.bytes;
        // A record that announces 100 bytes and stops after 2: a log cut mid-message.
        bytes.extend_from_slice(&[100, 0, b'D', 0, 0]);
        let offset = bytes.len() as u64;
        bytes[16 + 3 + 16..16 + 3 + 24].copy_from_slice(&offset.to_le_bytes());
        let mut tail = crate::ulog::tests::Builder { bytes: Vec::new() };
        for row in &rows[3..] {
            tail = tail.data(0, row);
        }
        bytes.extend_from_slice(&tail.bytes);
        let (whole, appended) = (
            spec_ingest(&whole.bytes).unwrap(),
            spec_ingest(&bytes).unwrap(),
        );
        assert!(appended.flight.summary.data_appended);
        assert_eq!(appended.flight.vehicle_status, whole.flight.vehicle_status);
        assert_eq!(appended.events, whole.events);
        assert!(
            appended
                .events
                .iter()
                .any(|e| matches!(e.kind, crate::events::EventKind::Disarm { .. }))
        );
        // The cut record is the one region skipped, all 5 of its bytes.
        assert_eq!(
            (
                appended.flight.summary.skipped_regions,
                appended.flight.summary.skipped_bytes
            ),
            (1, 5)
        );
    }

    #[test]
    fn ulog_spec_differences_sfr_keeps() {
        // Where sfr does not do what the specification asks, on purpose (docs/VALIDATION.md):
        // a file format version above 1 is refused, not parsed with a warning ...
        let mut b = spec_definitions(&[]).data(0, &spec_flight_rows()[0]).bytes;
        b[7] = 2;
        let err = spec_ingest(&b).expect_err("refused");
        assert!(
            err.to_string()
                .contains("unsupported ULog file format version 2"),
            "{err}"
        );
        // ... and a log that ends in the middle of a record, with no appended data, is refused,
        // not read with the unfinished record discarded.
        let mut b = spec_definitions(&[]).data(0, &spec_flight_rows()[0]).bytes;
        b.extend_from_slice(&[100, 0, b'D', 0, 0]);
        let err = spec_ingest(&b).expect_err("refused");
        assert!(
            matches!(err, IngestError::Malformed(UlogError::Truncated { .. })),
            "{err}"
        );
        // DATA_APPENDED with every offset 0 breaks "at least one of the appended_offsets is
        // non-zero"; sfr reads such a log as one with nothing appended.
        let mut b = spec_definitions(&[0]);
        for row in spec_flight_rows() {
            b = b.data(0, &row);
        }
        let ing = spec_ingest(&b.bytes).expect("read");
        assert_eq!(ing.flight.vehicle_status.len(), 8);
    }

    #[test]
    fn every_vehicle_status_instance_is_kept() {
        use crate::ulog::tests::Builder;
        let row = |ts: u64, arming: u8| [&ts.to_le_bytes()[..], &[arming]].concat();
        let log = Builder::new(0)
            .flags(&[])
            .format("vehicle_status:uint64_t timestamp;uint8_t arming_state;")
            .sub(0, 0, "vehicle_status")
            .sub(1, 1, "vehicle_status")
            .data(1, &row(5, 2))
            .data(0, &row(6, 1))
            .data(1, &row(9, 1));
        let ing = Px4Ingestor
            .ingest("x.ulg", &mut &log.bytes[..], &TestBackend)
            .unwrap();
        let instances: Vec<Vec<u64>> = ing
            .flight
            .vehicle_status_instances()
            .iter()
            .map(|rows| rows.iter().map(|r| r.id.ts).collect())
            .collect();
        assert_eq!(instances, [vec![6], vec![5, 9]]);
        assert_eq!(ing.identity.vehicle_status_instances, 2);
    }
}
