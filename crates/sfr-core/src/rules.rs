//! Rules file (SPEC B1.6): TOML, `format = "sfr-rules/1"`, unknown keys rejected.
//!
//! ```toml
//! format = "sfr-rules/1"
//!
//! [required_topics]
//! topics = ["vehicle_status", "failsafe_flags"]
//!
//! [parameters]
//! compare = "all"          # or "baseline": only parameters listed in the baseline
//! ignore = ["COM_FLIGHT_UUID", "CAL_BARO*_OFF"]
//!
//! # Optional rules, each enabled by the presence of its table.
//! [extended.min_battery]
//! min_remaining = 0.25
//!
//! # Optional sections (Change Order 01).
//! [watched_parameters]
//! names = ["VT_F_TRANS_DUR"]   # shown apart; R3 compares them like any other parameter
//! [sealed_topics]
//! topics = ["vehicle_visual_odometry"]   # required, and digested into the record
//! [payload_commands]
//! ids = [187, 211]             # COMMAND events with these ids are PAYLOAD, others GENERAL
//! [authorized_sources]         # R7; absent means R7 is N/A
//! category = "PAYLOAD"         # optional: check only this category
//! sources = [{ system = 1, component = 1 }]
//! ```

use crate::params::Pattern;
use std::fmt;
use toml::Spanned;
use toml::de::{DeTable, DeValue};

/// The only rules format this version reads.
pub const RULES_FORMAT: &str = "sfr-rules/1";

/// Most entries in `required_topics.topics`, and most in `parameters.ignore`. Real rules files
/// list a handful; the caps keep evaluation time bounded on any file.
pub const MAX_LIST_ENTRIES: usize = 256;

/// Depth at which the toml parser (`toml` 0.9.12, `LIMIT` in `de/parser/mod.rs`) stops nested
/// arrays, inline tables, and dotted keys. Recorded here so the error can name it.
pub const TOML_MAX_DEPTH: usize = 80;

/// Most entries in `[sealed_topics]`; more is a usage error (SPEC B1.4, exit 4).
pub const MAX_SEALED_TOPICS: usize = 64;

/// Topics R1 always requires, because the core rules read them.
pub const CORE_TOPICS: [&str; 2] = ["vehicle_status", "failsafe_flags"];

/// The topic R7 reads; R1 requires it when the rules file has `[authorized_sources]`.
pub const R7_TOPIC: &str = "vehicle_command";

/// Which parameters R3 compares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compare {
    /// Every parameter in the baseline or the log; one present on only one side is a difference.
    All,
    /// Only the parameters in the baseline.
    Baseline,
}

/// A number from the rules file, kept with its source spelling for messages.
#[derive(Debug, Clone, PartialEq)]
pub struct Threshold {
    /// Value.
    pub value: f64,
    /// As written in the file.
    pub text: String,
}

/// X1: minimum `battery_status.remaining` while armed.
#[derive(Debug, Clone, PartialEq)]
pub struct MinBattery {
    /// Fraction 0 to 1.
    pub min_remaining: Threshold,
}

/// X2: GPS fix quality at each ARM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpsFixAtArm {
    /// Minimum `fix_type`.
    pub min_fix_type: u8,
    /// Minimum `satellites_used`.
    pub min_satellites: u8,
}

/// X4: accelerometer vibration and clipping while armed.
#[derive(Debug, Clone, PartialEq)]
pub struct Vibration {
    /// Maximum `accel_vibration_metric`.
    pub max_accel_vibration_metric: Threshold,
    /// Maximum increase of the summed `accel_clipping` counters.
    pub max_accel_clipping: u64,
}

/// X5: total dropout time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dropouts {
    /// Maximum total milliseconds.
    pub max_total_ms: u64,
}

/// The optional rules, off unless their table is present.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Extended {
    /// X1.
    pub min_battery: Option<MinBattery>,
    /// X2.
    pub gps_fix_at_arm: Option<GpsFixAtArm>,
    /// X3: any nonzero `estimator_status.filter_fault_flags` on the primary estimator while armed.
    pub estimator_faults: bool,
    /// X4.
    pub vibration: Option<Vibration>,
    /// X5.
    pub dropouts: Option<Dropouts>,
}

/// A COMMAND event's category (SPEC B1.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Category {
    /// Every command not in `[payload_commands]`.
    General,
    /// A command id listed in `[payload_commands]`.
    Payload,
}

impl Category {
    /// Record spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Category::General => "GENERAL",
            Category::Payload => "PAYLOAD",
        }
    }
}

/// A command source R7 accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Source {
    /// `vehicle_command.source_system` (8 bits).
    pub system: u8,
    /// `vehicle_command.source_component`: 16 bits in PX4 v1.17 (docs/DIAGNOSTIC.md item 12).
    pub component: u16,
}

/// `[authorized_sources]`: R7's configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedSources {
    /// Only commands of this category are checked; `None` checks every command.
    pub category: Option<Category>,
    /// The accepted sources, sorted.
    pub sources: Vec<Source>,
}

/// A parsed rules file.
#[derive(Debug, Clone)]
pub struct Rules {
    /// The file text, embedded in the record.
    pub text: String,
    /// Topics listed in `[required_topics]`, in file order.
    pub required_topics: Vec<String>,
    /// R3 scope.
    pub compare: Compare,
    /// Parameters R3 ignores.
    pub ignore: Vec<Pattern>,
    /// Optional rules.
    pub extended: Extended,
    /// `[watched_parameters]`, sorted.
    pub watched: Vec<String>,
    /// `[sealed_topics]`, sorted.
    pub sealed_topics: Vec<String>,
    /// `[payload_commands]`.
    pub payload_commands: std::collections::BTreeSet<u32>,
    /// `[authorized_sources]` (R7).
    pub authorized_sources: Option<AuthorizedSources>,
}

impl Rules {
    /// The topics R1 checks: the file's list, then the core topics, the sealed topics, and
    /// (with `[authorized_sources]`) the topic R7 reads, each one the list lacks.
    pub fn r1_topics(&self) -> Vec<String> {
        let mut out = self.required_topics.clone();
        let r7 = self.authorized_sources.as_ref().map(|_| R7_TOPIC);
        for t in CORE_TOPICS
            .iter()
            .copied()
            .chain(self.sealed_topics.iter().map(String::as_str))
            .chain(r7)
        {
            if !out.iter().any(|x| x == t) {
                out.push(t.to_string());
            }
        }
        out
    }

    /// A command id's category.
    pub fn category(&self, command: u32) -> Category {
        if self.payload_commands.contains(&command) {
            Category::Payload
        } else {
            Category::General
        }
    }

    /// Whether R3 ignores `name`.
    pub fn ignores(&self, name: &str) -> bool {
        self.ignore.iter().any(|p| p.matches(name))
    }
}

/// A rules file that cannot be used (SPEC B1.4 exit 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RulesError {
    /// 1-based line, or 0 for the file as a whole.
    pub line: usize,
    /// What is wrong.
    pub reason: String,
    /// A usage error (SPEC B1.4 exit 4) rather than an unusable file (exit 3).
    pub usage: bool,
}

impl fmt::Display for RulesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.line == 0 {
            write!(f, "{}", self.reason)
        } else {
            write!(f, "line {}: {}", self.line, self.reason)
        }
    }
}

impl std::error::Error for RulesError {}

struct Ctx<'a> {
    text: &'a str,
}

impl Ctx<'_> {
    fn line(&self, offset: usize) -> usize {
        self.text
            .get(..offset)
            .map_or(0, |s| s.bytes().filter(|&b| b == b'\n').count() + 1)
    }

    fn err(&self, offset: usize, reason: impl Into<String>) -> RulesError {
        RulesError {
            line: self.line(offset),
            reason: reason.into(),
            usage: false,
        }
    }
}

type Table<'i> = DeTable<'i>;

fn check_keys(
    ctx: &Ctx<'_>,
    table: &Table<'_>,
    path: &str,
    allowed: &[&str],
) -> Result<(), RulesError> {
    for key in table.keys() {
        if !allowed.contains(&key.get_ref().as_ref()) {
            let shown = if path.is_empty() {
                key.get_ref().to_string()
            } else {
                format!("{path}.{}", key.get_ref())
            };
            return Err(ctx.err(key.span().start, format!("unknown key `{shown}`")));
        }
    }
    Ok(())
}

fn get<'t, 'i>(table: &'t Table<'i>, key: &str) -> Option<&'t Spanned<DeValue<'i>>> {
    table
        .iter()
        .find(|(k, _)| k.get_ref().as_ref() == key)
        .map(|(_, v)| v)
}

fn as_table<'t, 'i>(
    ctx: &Ctx<'_>,
    v: &'t Spanned<DeValue<'i>>,
    name: &str,
) -> Result<&'t Table<'i>, RulesError> {
    match v.get_ref() {
        DeValue::Table(t) => Ok(t),
        _ => Err(ctx.err(v.span().start, format!("`{name}` must be a table"))),
    }
}

fn as_str<'t>(
    ctx: &Ctx<'_>,
    v: &'t Spanned<DeValue<'_>>,
    name: &str,
) -> Result<&'t str, RulesError> {
    match v.get_ref() {
        DeValue::String(s) => Ok(s.as_ref()),
        _ => Err(ctx.err(v.span().start, format!("`{name}` must be a string"))),
    }
}

fn as_str_list(
    ctx: &Ctx<'_>,
    v: &Spanned<DeValue<'_>>,
    name: &str,
) -> Result<Vec<(String, usize)>, RulesError> {
    let DeValue::Array(items) = v.get_ref() else {
        return Err(ctx.err(
            v.span().start,
            format!("`{name}` must be an array of strings"),
        ));
    };
    items
        .iter()
        .map(|item| as_str(ctx, item, name).map(|s| (s.to_string(), item.span().start)))
        .collect()
}

fn as_uint(
    ctx: &Ctx<'_>,
    v: &Spanned<DeValue<'_>>,
    name: &str,
    max: u64,
) -> Result<u64, RulesError> {
    let DeValue::Integer(i) = v.get_ref() else {
        return Err(ctx.err(v.span().start, format!("`{name}` must be an integer")));
    };
    u64::from_str_radix(i.as_str(), i.radix())
        .ok()
        .filter(|n| *n <= max)
        .ok_or_else(|| {
            ctx.err(
                v.span().start,
                format!("`{name}` must be an integer from 0 to {max}"),
            )
        })
}

fn as_threshold(
    ctx: &Ctx<'_>,
    v: &Spanned<DeValue<'_>>,
    name: &str,
    range: (f64, f64),
) -> Result<Threshold, RulesError> {
    let text = match v.get_ref() {
        DeValue::Float(f) => f.as_str().replace('_', ""),
        DeValue::Integer(i) if i.radix() == 10 => i.as_str().replace('_', ""),
        _ => return Err(ctx.err(v.span().start, format!("`{name}` must be a number"))),
    };
    let value: f64 = text
        .parse()
        .map_err(|_| ctx.err(v.span().start, format!("`{name}` must be a number")))?;
    if !value.is_finite() || value < range.0 || value > range.1 {
        return Err(ctx.err(
            v.span().start,
            format!("`{name}` must be from {} to {}", range.0, range.1),
        ));
    }
    Ok(Threshold { value, text })
}

fn require<'t, 'i>(
    ctx: &Ctx<'_>,
    table: &'t Table<'i>,
    at: usize,
    path: &str,
    key: &str,
) -> Result<&'t Spanned<DeValue<'i>>, RulesError> {
    get(table, key).ok_or_else(|| ctx.err(at, format!("`{path}` needs `{key}`")))
}

fn valid_topic(t: &str) -> bool {
    !t.is_empty()
        && t.len() <= 64
        && t.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Parses and validates a rules file.
pub fn parse_rules(text: &str) -> Result<Rules, RulesError> {
    // The record embeds `text` unchanged; only parsing skips a UTF-8 byte order mark.
    let body = text.strip_prefix('\u{feff}').unwrap_or(text);
    let ctx = Ctx { text: body };
    let doc = DeTable::parse(body).map_err(|e| {
        let line = e.span().map_or(0, |s| ctx.line(s.start));
        let msg = e.message().trim();
        // The toml parser stops nesting and dotted keys at its own depth limit.
        let reason = if msg.contains("recursion") {
            crate::limit_exceeded("TOML nesting or dotted-key depth", TOML_MAX_DEPTH, "levels")
        } else {
            format!("not valid TOML: {msg}")
        };
        RulesError {
            line,
            reason,
            usage: false,
        }
    })?;
    let root = doc.get_ref();
    check_keys(
        &ctx,
        root,
        "",
        &[
            "format",
            "required_topics",
            "parameters",
            "extended",
            "watched_parameters",
            "sealed_topics",
            "payload_commands",
            "authorized_sources",
        ],
    )?;

    let format = get(root, "format").ok_or_else(|| RulesError {
        line: 1,
        reason: format!("missing `format = \"{RULES_FORMAT}\"`"),
        usage: false,
    })?;
    let f = as_str(&ctx, format, "format")?;
    if f != RULES_FORMAT {
        return Err(ctx.err(
            format.span().start,
            format!("format `{f}` is not `{RULES_FORMAT}`"),
        ));
    }
    // SPEC B1.6: the file starts with the format line, so a reader knows the format before
    // anything else; no key or table may come before it.
    let format_at = root
        .keys()
        .find(|k| k.get_ref().as_ref() == "format")
        .map_or(0, |k| k.span().start);
    if let Some(first) = root
        .keys()
        .filter(|k| k.span().start < format_at)
        .min_by_key(|k| k.span().start)
    {
        return Err(ctx.err(
            first.span().start,
            format!(
                "`{}` comes before `format = \"{RULES_FORMAT}\"`, which must come first",
                first.get_ref()
            ),
        ));
    }

    let rt = get(root, "required_topics").ok_or_else(|| RulesError {
        line: body.lines().count() + 1,
        reason: "missing `[required_topics]`".into(),
        usage: false,
    })?;
    let rt_table = as_table(&ctx, rt, "required_topics")?;
    check_keys(&ctx, rt_table, "required_topics", &["topics"])?;
    let topics_v = require(&ctx, rt_table, rt.span().start, "required_topics", "topics")?;
    let mut required_topics = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for (t, at) in as_str_list(&ctx, topics_v, "required_topics.topics")? {
        if !valid_topic(&t) {
            return Err(ctx.err(
                at,
                format!(
                    "`{t}` is not a topic name (1 to 64 lowercase letters, digits, `_`; SPEC B1.4)"
                ),
            ));
        }
        if !seen.insert(t.clone()) {
            return Err(ctx.err(at, format!("topic `{t}` listed twice")));
        }
        if seen.len() > MAX_LIST_ENTRIES {
            return Err(ctx.err(
                at,
                crate::limit_exceeded("`required_topics`", MAX_LIST_ENTRIES, "entries"),
            ));
        }
        required_topics.push(t);
    }

    let mut compare = Compare::All;
    let mut ignore = Vec::new();
    if let Some(p) = get(root, "parameters") {
        let pt = as_table(&ctx, p, "parameters")?;
        check_keys(&ctx, pt, "parameters", &["compare", "ignore"])?;
        if let Some(c) = get(pt, "compare") {
            compare = match as_str(&ctx, c, "parameters.compare")? {
                "all" => Compare::All,
                "baseline" => Compare::Baseline,
                other => {
                    return Err(ctx.err(
                        c.span().start,
                        format!("`parameters.compare` is `{other}`, expected `all` or `baseline`"),
                    ));
                }
            };
        }
        if let Some(list) = get(pt, "ignore") {
            let mut seen = std::collections::BTreeSet::new();
            for (pat, at) in as_str_list(&ctx, list, "parameters.ignore")? {
                if !seen.insert(pat.clone()) {
                    return Err(ctx.err(at, format!("pattern `{pat}` listed twice")));
                }
                if seen.len() > MAX_LIST_ENTRIES {
                    return Err(ctx.err(
                        at,
                        crate::limit_exceeded("`parameters.ignore`", MAX_LIST_ENTRIES, "entries"),
                    ));
                }
                let parsed = Pattern::new(&pat).ok_or_else(|| {
                    ctx.err(
                        at,
                        format!(
                            "`{pat}` is not a parameter name pattern (1 to 64 letters, digits, `_`, `*`, at most {} `*`; SPEC B1.4)",
                            crate::params::MAX_PATTERN_STARS
                        ),
                    )
                })?;
                ignore.push(parsed);
            }
        }
    }

    let mut extended = Extended::default();
    if let Some(x) = get(root, "extended") {
        let xt = as_table(&ctx, x, "extended")?;
        check_keys(
            &ctx,
            xt,
            "extended",
            &[
                "min_battery",
                "gps_fix_at_arm",
                "estimator_faults",
                "vibration",
                "dropouts",
            ],
        )?;
        if let Some(v) = get(xt, "min_battery") {
            let t = as_table(&ctx, v, "extended.min_battery")?;
            check_keys(&ctx, t, "extended.min_battery", &["min_remaining"])?;
            let m = require(
                &ctx,
                t,
                v.span().start,
                "extended.min_battery",
                "min_remaining",
            )?;
            extended.min_battery = Some(MinBattery {
                min_remaining: as_threshold(&ctx, m, "min_remaining", (0.0, 1.0))?,
            });
        }
        if let Some(v) = get(xt, "gps_fix_at_arm") {
            let t = as_table(&ctx, v, "extended.gps_fix_at_arm")?;
            check_keys(
                &ctx,
                t,
                "extended.gps_fix_at_arm",
                &["min_fix_type", "min_satellites"],
            )?;
            let fix = require(
                &ctx,
                t,
                v.span().start,
                "extended.gps_fix_at_arm",
                "min_fix_type",
            )?;
            let sats = require(
                &ctx,
                t,
                v.span().start,
                "extended.gps_fix_at_arm",
                "min_satellites",
            )?;
            extended.gps_fix_at_arm = Some(GpsFixAtArm {
                min_fix_type: as_uint(&ctx, fix, "min_fix_type", 255)? as u8,
                min_satellites: as_uint(&ctx, sats, "min_satellites", 255)? as u8,
            });
        }
        if let Some(v) = get(xt, "estimator_faults") {
            let t = as_table(&ctx, v, "extended.estimator_faults")?;
            check_keys(&ctx, t, "extended.estimator_faults", &[])?;
            extended.estimator_faults = true;
        }
        if let Some(v) = get(xt, "vibration") {
            let t = as_table(&ctx, v, "extended.vibration")?;
            check_keys(
                &ctx,
                t,
                "extended.vibration",
                &["max_accel_vibration_metric", "max_accel_clipping"],
            )?;
            let vib = require(
                &ctx,
                t,
                v.span().start,
                "extended.vibration",
                "max_accel_vibration_metric",
            )?;
            let clip = require(
                &ctx,
                t,
                v.span().start,
                "extended.vibration",
                "max_accel_clipping",
            )?;
            extended.vibration = Some(Vibration {
                max_accel_vibration_metric: as_threshold(
                    &ctx,
                    vib,
                    "max_accel_vibration_metric",
                    (0.0, 1.0e6),
                )?,
                max_accel_clipping: as_uint(&ctx, clip, "max_accel_clipping", u64::from(u32::MAX))?,
            });
        }
        if let Some(v) = get(xt, "dropouts") {
            let t = as_table(&ctx, v, "extended.dropouts")?;
            check_keys(&ctx, t, "extended.dropouts", &["max_total_ms"])?;
            let m = require(&ctx, t, v.span().start, "extended.dropouts", "max_total_ms")?;
            extended.dropouts = Some(Dropouts {
                max_total_ms: as_uint(&ctx, m, "max_total_ms", u64::from(u32::MAX))?,
            });
        }
    }

    let watched = parse_watched(&ctx, root, &ignore)?;
    let sealed_topics = parse_sealed_topics(&ctx, root)?;
    let payload_commands = parse_payload_commands(&ctx, root)?;
    let authorized_sources = parse_authorized_sources(&ctx, root)?;

    Ok(Rules {
        text: text.to_string(),
        required_topics,
        compare,
        ignore,
        extended,
        watched,
        sealed_topics,
        payload_commands,
        authorized_sources,
    })
}

/// A parameter name: 1 to 64 letters, digits, or `_` (SPEC B1.4).
fn valid_param_name(n: &str) -> bool {
    !n.is_empty() && n.len() <= 64 && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// The one-key table `[name] key = [...]` as `(value, offset)` strings, or `None` when absent.
fn single_list<'t, 'i>(
    ctx: &Ctx<'_>,
    root: &'t Table<'i>,
    name: &str,
    key: &str,
) -> Result<Option<&'t Spanned<DeValue<'i>>>, RulesError> {
    let Some(v) = get(root, name) else {
        return Ok(None);
    };
    let t = as_table(ctx, v, name)?;
    check_keys(ctx, t, name, &[key])?;
    require(ctx, t, v.span().start, name, key).map(Some)
}

fn parse_watched(
    ctx: &Ctx<'_>,
    root: &Table<'_>,
    ignore: &[Pattern],
) -> Result<Vec<String>, RulesError> {
    let Some(list) = single_list(ctx, root, "watched_parameters", "names")? else {
        return Ok(Vec::new());
    };
    let mut out = std::collections::BTreeSet::new();
    for (name, at) in as_str_list(ctx, list, "watched_parameters.names")? {
        if !valid_param_name(&name) {
            return Err(ctx.err(
                at,
                format!(
                    "`{name}` is not a parameter name (1 to 64 letters, digits, `_`; SPEC B1.4)"
                ),
            ));
        }
        if let Some(p) = ignore.iter().find(|p| p.matches(&name)) {
            return Err(ctx.err(
                at,
                format!(
                    "watched parameter `{name}` is also ignored by `{}`; R3 compares every watched parameter",
                    p.as_str()
                ),
            ));
        }
        if !out.insert(name.clone()) {
            return Err(ctx.err(at, format!("parameter `{name}` listed twice")));
        }
        if out.len() > MAX_LIST_ENTRIES {
            return Err(ctx.err(
                at,
                crate::limit_exceeded("`watched_parameters`", MAX_LIST_ENTRIES, "entries"),
            ));
        }
    }
    Ok(out.into_iter().collect())
}

fn parse_sealed_topics(ctx: &Ctx<'_>, root: &Table<'_>) -> Result<Vec<String>, RulesError> {
    let Some(list) = single_list(ctx, root, "sealed_topics", "topics")? else {
        return Ok(Vec::new());
    };
    let mut out = std::collections::BTreeSet::new();
    for (t, at) in as_str_list(ctx, list, "sealed_topics.topics")? {
        if !valid_topic(&t) {
            return Err(ctx.err(
                at,
                format!(
                    "`{t}` is not a topic name (1 to 64 lowercase letters, digits, `_`; SPEC B1.4)"
                ),
            ));
        }
        if !out.insert(t.clone()) {
            return Err(ctx.err(at, format!("sealed topic `{t}` listed twice")));
        }
        if out.len() > MAX_SEALED_TOPICS {
            let mut e = ctx.err(
                at,
                crate::limit_exceeded("`sealed_topics`", MAX_SEALED_TOPICS, "topics"),
            );
            e.usage = true;
            return Err(e);
        }
    }
    Ok(out.into_iter().collect())
}

fn parse_payload_commands(
    ctx: &Ctx<'_>,
    root: &Table<'_>,
) -> Result<std::collections::BTreeSet<u32>, RulesError> {
    let mut out = std::collections::BTreeSet::new();
    let Some(list) = single_list(ctx, root, "payload_commands", "ids")? else {
        return Ok(out);
    };
    let DeValue::Array(items) = list.get_ref() else {
        return Err(ctx.err(
            list.span().start,
            "`payload_commands.ids` must be an array of integers",
        ));
    };
    for item in items {
        let id = as_uint(ctx, item, "payload_commands.ids", u64::from(u32::MAX))? as u32;
        if !out.insert(id) {
            return Err(ctx.err(item.span().start, format!("command id {id} listed twice")));
        }
        if out.len() > MAX_LIST_ENTRIES {
            return Err(ctx.err(
                item.span().start,
                crate::limit_exceeded("`payload_commands`", MAX_LIST_ENTRIES, "entries"),
            ));
        }
    }
    Ok(out)
}

fn parse_authorized_sources(
    ctx: &Ctx<'_>,
    root: &Table<'_>,
) -> Result<Option<AuthorizedSources>, RulesError> {
    let Some(v) = get(root, "authorized_sources") else {
        return Ok(None);
    };
    let t = as_table(ctx, v, "authorized_sources")?;
    check_keys(ctx, t, "authorized_sources", &["category", "sources"])?;
    let category = match get(t, "category") {
        None => None,
        Some(c) => Some(match as_str(ctx, c, "authorized_sources.category")? {
            "PAYLOAD" => Category::Payload,
            "GENERAL" => Category::General,
            other => {
                return Err(ctx.err(
                    c.span().start,
                    format!("`authorized_sources.category` is `{other}`, expected `PAYLOAD` or `GENERAL`"),
                ));
            }
        }),
    };
    let list = require(ctx, t, v.span().start, "authorized_sources", "sources")?;
    let DeValue::Array(items) = list.get_ref() else {
        return Err(ctx.err(
            list.span().start,
            "`authorized_sources.sources` must be an array of { system, component } tables",
        ));
    };
    if items.is_empty() {
        return Err(ctx.err(
            list.span().start,
            "`authorized_sources.sources` is empty; list at least one { system, component }",
        ));
    }
    let mut sources = std::collections::BTreeSet::new();
    for item in items {
        let s = as_table(ctx, item, "authorized_sources.sources")?;
        check_keys(
            ctx,
            s,
            "authorized_sources.sources",
            &["system", "component"],
        )?;
        let at = item.span().start;
        let system = require(ctx, s, at, "authorized_sources.sources", "system")?;
        let component = require(ctx, s, at, "authorized_sources.sources", "component")?;
        let src = Source {
            system: as_uint(ctx, system, "system", 255)? as u8,
            component: as_uint(ctx, component, "component", u64::from(u16::MAX))? as u16,
        };
        if !sources.insert(src) {
            return Err(ctx.err(
                at,
                format!(
                    "source system {} component {} listed twice",
                    src.system, src.component
                ),
            ));
        }
        if sources.len() > MAX_LIST_ENTRIES {
            return Err(ctx.err(
                at,
                crate::limit_exceeded("`authorized_sources.sources`", MAX_LIST_ENTRIES, "entries"),
            ));
        }
    }
    Ok(Some(AuthorizedSources {
        category,
        sources: sources.into_iter().collect(),
    }))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
pub(crate) mod tests {
    use super::*;

    const MIN: &str =
        "format = \"sfr-rules/1\"\n[required_topics]\ntopics = [\"vehicle_status\"]\n";

    /// The smallest valid rules file, for tests elsewhere in the crate.
    pub(crate) fn minimal() -> Rules {
        parse_rules(MIN).expect("minimal rules parse")
    }

    #[test]
    fn pattern_length_and_toml_depth_limits_are_named() {
        let pattern = |n: usize| format!("{MIN}[parameters]\nignore = [\"{}\"]\n", "A".repeat(n));
        parse_rules(&pattern(64)).expect("64 characters");
        let e = parse_rules(&pattern(65)).expect_err("65 characters");
        assert!(e.to_string().contains("1 to 64 letters"), "{e}");
        assert_eq!(e.line, 5);

        let deep = format!("{MIN}x = {}{}\n", "[".repeat(81), "]".repeat(81));
        let e = parse_rules(&deep).expect_err("81 nested arrays");
        assert!(
            e.to_string().contains(
                "TOML nesting or dotted-key depth exceeds the input limit of 80 levels (SPEC B1.4)"
            ),
            "{e}"
        );
        assert_eq!(e.line, 4);
        let dotted = format!("{MIN}{} = 1\n", vec!["a"; 100].join("."));
        let e = parse_rules(&dotted).expect_err("100 dotted parts");
        assert!(
            e.to_string()
                .contains("exceeds the input limit of 80 levels"),
            "{e}"
        );
    }

    #[test]
    fn list_and_pattern_limits_are_enforced_and_named() {
        let list =
            |n: usize, f: &dyn Fn(usize) -> String| (0..n).map(f).collect::<Vec<_>>().join(", ");
        let topics = |n| {
            format!(
                "format = \"sfr-rules/1\"\n[required_topics]\ntopics = [{}]\n",
                list(n, &|i| format!("\"t{i}\""))
            )
        };
        parse_rules(&topics(MAX_LIST_ENTRIES)).expect("at the limit");
        let e = parse_rules(&topics(MAX_LIST_ENTRIES + 1)).expect_err("over the limit");
        assert!(
            e.to_string()
                .contains("`required_topics` exceeds the input limit of 256 entries (SPEC B1.4)"),
            "{e}"
        );
        let ignore = |n| {
            format!(
                "{MIN}[parameters]\nignore = [{}]\n",
                list(n, &|i| format!("\"P{i}\""))
            )
        };
        parse_rules(&ignore(MAX_LIST_ENTRIES)).expect("at the limit");
        let e = parse_rules(&ignore(MAX_LIST_ENTRIES + 1)).expect_err("over the limit");
        assert!(
            e.to_string()
                .contains("`parameters.ignore` exceeds the input limit of 256 entries"),
            "{e}"
        );
        let stars = |n| format!("{MIN}[parameters]\nignore = [\"A{}\"]\n", "*".repeat(n));
        parse_rules(&stars(crate::params::MAX_PATTERN_STARS)).expect("at the limit");
        let e = parse_rules(&stars(crate::params::MAX_PATTERN_STARS + 1)).expect_err("9 stars");
        assert!(e.to_string().contains("at most 8 `*`"), "{e}");
        let long_topic = format!(
            "format = \"sfr-rules/1\"\n[required_topics]\ntopics = [\"{}\"]\n",
            "t".repeat(65)
        );
        let e = parse_rules(&long_topic).expect_err("65 bytes");
        assert!(e.to_string().contains("1 to 64 lowercase letters"), "{e}");
    }

    #[test]
    fn comments_and_a_byte_order_mark_may_precede_format() {
        let text = format!("\u{feff}# rules for the test rig\n\n{MIN}");
        let r = parse_rules(&text).expect("valid");
        assert_eq!(r.text, text, "the embedded text keeps the byte order mark");
    }

    #[test]
    fn minimal_file_adds_core_topics() {
        let r = parse_rules(MIN).expect("valid");
        assert_eq!(r.r1_topics(), ["vehicle_status", "failsafe_flags"]);
        assert_eq!(r.compare, Compare::All);
        assert!(r.ignore.is_empty());
        assert_eq!(r.extended, Extended::default());
    }

    #[test]
    fn shipped_examples_parse() {
        let d = parse_rules(include_str!("../../../examples/rules.default.toml"))
            .expect("default rules");
        assert!(
            d.ignores("COM_FLIGHT_UUID")
                && d.ignores("CAL_BARO0_OFF")
                && !d.ignores("CAL_BARO0_ID")
        );
        assert_eq!(d.extended, Extended::default());
        let x = parse_rules(include_str!("../../../examples/rules.extended.toml"))
            .expect("extended rules");
        assert!(x.extended.min_battery.is_some() && x.extended.gps_fix_at_arm.is_some());
        assert!(
            x.extended.estimator_faults
                && x.extended.vibration.is_some()
                && x.extended.dropouts.is_some()
        );
    }

    #[test]
    fn rejects_unknown_keys_and_bad_values_with_lines() {
        let cases: &[(&str, usize, &str)] = &[
            ("format = \"sfr-rules/2\"\n", 1, "is not `sfr-rules/1`"),
            ("[required_topics]\ntopics = []\n", 1, "missing `format"),
            (
                "format = \"sfr-rules/1\"\n",
                2,
                "missing `[required_topics]`",
            ),
            (
                "format = \"sfr-rules/1\"\nthreshold = 3\n[required_topics]\ntopics = []\n",
                2,
                "unknown key `threshold`",
            ),
            (
                "format = \"sfr-rules/1\"\n[required_topics]\ntopics = [\"Bad Topic\"]\n",
                3,
                "not a topic name",
            ),
            (
                "format = \"sfr-rules/1\"\n[required_topics]\ntopics = [\"a\", \"a\"]\n",
                3,
                "twice",
            ),
            (
                "format = \"sfr-rules/1\"\n[required_topics]\ntopic = []\n",
                3,
                "unknown key `required_topics.topic`",
            ),
            (
                "format = \"sfr-rules/1\"\n[required_topics]\ntopics = []\n[parameters]\ncompare = \"some\"\n",
                5,
                "expected `all` or `baseline`",
            ),
            (
                "format = \"sfr-rules/1\"\n[required_topics]\ntopics = []\n[parameters]\nignore = [\"A-B\"]\n",
                5,
                "not a parameter name pattern",
            ),
            (
                "format = \"sfr-rules/1\"\n[required_topics]\ntopics = []\n[extended.min_battery]\nmin_remaining = 1.5\n",
                5,
                "from 0 to 1",
            ),
            (
                "format = \"sfr-rules/1\"\n[required_topics]\ntopics = []\n[extended.min_battery]\n",
                4,
                "needs `min_remaining`",
            ),
            (
                "format = \"sfr-rules/1\"\n[required_topics]\ntopics = []\n[extended.estimator_faults]\nlevel = 1\n",
                5,
                "unknown key `extended.estimator_faults.level`",
            ),
            (
                "format = \"sfr-rules/1\"\n[required_topics]\ntopics = []\n[extended.dropouts]\nmax_total_ms = -1\n",
                5,
                "integer from 0",
            ),
            (
                "format = \"sfr-rules/1\"\n[required_topics]\ntopics = []\n[extended.vibration]\nmax_accel_vibration_metric = nan\nmax_accel_clipping = 0\n",
                5,
                "from 0 to",
            ),
            (
                "format = \"sfr-rules/1\"\n[required_topics\n",
                2,
                "not valid TOML",
            ),
            (
                "[required_topics]\ntopics = []\n[parameters]\nformat = 1\n",
                1,
                "missing `format",
            ),
            (
                "[required_topics]\ntopics = []\n\nformat = \"sfr-rules/1\"\n",
                1,
                "missing `format",
            ),
            (
                "extended.dropouts.max_total_ms = 1\nformat = \"sfr-rules/1\"\n[required_topics]\ntopics = []\n",
                1,
                "comes before `format",
            ),
        ];
        for (text, line, needle) in cases {
            let e = parse_rules(text).expect_err(text);
            assert_eq!(e.line, *line, "{text:?}: {e}");
            assert!(e.reason.contains(needle), "{text:?}: {e}");
        }
    }

    #[test]
    fn change_order_01_sections_parse_and_sort() {
        let text = format!(
            "{MIN}[watched_parameters]\nnames = [\"VT_F_TRANS_DUR\", \"VT_B_TRANS_DUR\"]\n\
             [sealed_topics]\ntopics = [\"vehicle_visual_odometry\", \"custom_detection\"]\n\
             [payload_commands]\nids = [211, 187]\n\
             [authorized_sources]\ncategory = \"PAYLOAD\"\nsources = [{{ system = 255, component = 190 }}, {{ system = 1, component = 1 }}]\n"
        );
        let r = parse_rules(&text).expect("valid");
        assert_eq!(r.watched, ["VT_B_TRANS_DUR", "VT_F_TRANS_DUR"]);
        assert_eq!(
            r.sealed_topics,
            ["custom_detection", "vehicle_visual_odometry"]
        );
        assert_eq!(r.category(211), Category::Payload);
        assert_eq!(r.category(176), Category::General);
        let auth = r.authorized_sources.as_ref().expect("R7 configured");
        assert_eq!(auth.category, Some(Category::Payload));
        assert_eq!(
            auth.sources,
            [
                Source {
                    system: 1,
                    component: 1
                },
                Source {
                    system: 255,
                    component: 190
                }
            ]
        );
        assert_eq!(
            r.r1_topics(),
            [
                "vehicle_status",
                "failsafe_flags",
                "custom_detection",
                "vehicle_visual_odometry",
                "vehicle_command"
            ]
        );
        let none = minimal();
        assert!(none.watched.is_empty() && none.sealed_topics.is_empty());
        assert!(none.payload_commands.is_empty() && none.authorized_sources.is_none());
        assert_eq!(none.category(211), Category::General);
    }

    #[test]
    fn change_order_01_sections_reject_bad_input() {
        let bad = |extra: &str| parse_rules(&format!("{MIN}{extra}")).expect_err(extra);
        // More than 64 sealed topics is a usage error (exit 4); 64 is accepted.
        let topics = |n: usize| {
            let list: Vec<String> = (0..n).map(|i| format!("\"t{i}\"")).collect();
            format!("[sealed_topics]\ntopics = [{}]\n", list.join(", "))
        };
        parse_rules(&format!("{MIN}{}", topics(64))).expect("64 sealed topics");
        let e = bad(&topics(65));
        assert!(e.usage, "{e}");
        assert!(e.reason.contains("input limit of 64 topics"), "{e}");
        // Every other problem is an unusable file (exit 3).
        for (extra, needle) in [
            (
                "[sealed_topics]\ntopics = [\"Bad\"]\n",
                "is not a topic name",
            ),
            ("[sealed_topics]\ntopics = [\"a\", \"a\"]\n", "listed twice"),
            (
                "[watched_parameters]\nnames = [\"A-B\"]\n",
                "is not a parameter name",
            ),
            (
                "[watched_parameters]\nnames = [\"X\", \"X\"]\n",
                "listed twice",
            ),
            (
                "[parameters]\nignore = [\"VT_*\"]\n[watched_parameters]\nnames = [\"VT_TYPE\"]\n",
                "also ignored by `VT_*`",
            ),
            (
                "[payload_commands]\nids = [\"211\"]\n",
                "must be an integer",
            ),
            ("[payload_commands]\nids = [211, 211]\n", "listed twice"),
            (
                "[payload_commands]\nids = [4294967296]\n",
                "from 0 to 4294967295",
            ),
            ("[authorized_sources]\nsources = []\n", "is empty"),
            (
                "[authorized_sources]\ncategory = \"ALL\"\nsources = [{ system = 1, component = 1 }]\n",
                "expected `PAYLOAD` or `GENERAL`",
            ),
            (
                "[authorized_sources]\nsources = [{ system = 256, component = 1 }]\n",
                "from 0 to 255",
            ),
            (
                "[authorized_sources]\nsources = [{ system = 1 }]\n",
                "needs `component`",
            ),
            (
                "[authorized_sources]\nsources = [{ system = 1, component = 1, x = 2 }]\n",
                "unknown key",
            ),
            (
                "[authorized_sources]\nsources = [{ system = 1, component = 1 }, { system = 1, component = 1 }]\n",
                "listed twice",
            ),
            ("[sealed_topics]\ntopic = [\"a\"]\n", "unknown key"),
        ] {
            let e = bad(extra);
            assert!(!e.usage, "{extra}: {e}");
            assert!(e.reason.contains(needle), "{extra}: {e}");
        }
    }
}
