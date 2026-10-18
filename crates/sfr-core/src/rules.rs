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
//! ```

use crate::params::Pattern;
use std::fmt;
use toml::Spanned;
use toml::de::{DeTable, DeValue};

/// The only rules format this version reads.
pub const RULES_FORMAT: &str = "sfr-rules/1";

/// Topics R1 always requires, because the core rules read them.
pub const CORE_TOPICS: [&str; 2] = ["vehicle_status", "failsafe_flags"];

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
}

impl Rules {
    /// The topics R1 checks: the file's list, then the core topics it lacks.
    pub fn r1_topics(&self) -> Vec<String> {
        let mut out = self.required_topics.clone();
        for t in CORE_TOPICS {
            if !out.iter().any(|x| x == t) {
                out.push(t.to_string());
            }
        }
        out
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
    let ctx = Ctx { text };
    let doc = DeTable::parse(text).map_err(|e| {
        let line = e.span().map_or(0, |s| ctx.line(s.start));
        let msg = e.message().trim().to_string();
        RulesError {
            line,
            reason: format!("not valid TOML: {msg}"),
        }
    })?;
    let root = doc.get_ref();
    check_keys(
        &ctx,
        root,
        "",
        &["format", "required_topics", "parameters", "extended"],
    )?;

    let format = get(root, "format").ok_or_else(|| RulesError {
        line: 0,
        reason: format!("missing `format = \"{RULES_FORMAT}\"`"),
    })?;
    let f = as_str(&ctx, format, "format")?;
    if f != RULES_FORMAT {
        return Err(ctx.err(
            format.span().start,
            format!("format `{f}` is not `{RULES_FORMAT}`"),
        ));
    }

    let rt = get(root, "required_topics").ok_or_else(|| RulesError {
        line: 0,
        reason: "missing `[required_topics]`".into(),
    })?;
    let rt_table = as_table(&ctx, rt, "required_topics")?;
    check_keys(&ctx, rt_table, "required_topics", &["topics"])?;
    let topics_v = require(&ctx, rt_table, rt.span().start, "required_topics", "topics")?;
    let mut required_topics = Vec::new();
    for (t, at) in as_str_list(&ctx, topics_v, "required_topics.topics")? {
        if !valid_topic(&t) {
            return Err(ctx.err(at, format!("`{t}` is not a topic name")));
        }
        if required_topics.contains(&t) {
            return Err(ctx.err(at, format!("topic `{t}` listed twice")));
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
            for (pat, at) in as_str_list(&ctx, list, "parameters.ignore")? {
                let parsed = Pattern::new(&pat).ok_or_else(|| {
                    ctx.err(
                        at,
                        format!(
                            "`{pat}` is not a parameter name pattern (letters, digits, `_`, `*`)"
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

    Ok(Rules {
        text: text.to_string(),
        required_topics,
        compare,
        ignore,
        extended,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    const MIN: &str =
        "format = \"sfr-rules/1\"\n[required_topics]\ntopics = [\"vehicle_status\"]\n";

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
            ("[required_topics]\ntopics = []\n", 0, "missing `format"),
            (
                "format = \"sfr-rules/1\"\n",
                0,
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
        ];
        for (text, line, needle) in cases {
            let e = parse_rules(text).expect_err(text);
            assert_eq!(e.line, *line, "{text:?}: {e}");
            assert!(e.reason.contains(needle), "{text:?}: {e}");
        }
    }
}
