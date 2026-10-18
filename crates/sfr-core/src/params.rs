//! Baseline parameter file (SPEC B1.6) and parameter name patterns.
//!
//! The baseline is a QGroundControl `.params` export: tab-separated vehicle id, component id,
//! name, value, and type (6 int32, 9 float32), plus exactly one `# Firmware: <version> [<git
//! hash prefix>]` line. Other `#` lines are comments. Float values are parsed straight to
//! float32 (one correctly rounded conversion), so they compare bitwise with the log's values.

use crate::ulog::ParamValue;
use std::collections::BTreeMap;
use std::fmt;

/// Most parameters a baseline or a log's configuration may hold (PX4 v1.14 to v1.17 logs hold
/// about 900 to 1,200). The cap bounds the R3 comparison time on any input.
pub const MAX_PARAMS: usize = 65_536;

/// Most `*` in one ignore pattern. Real patterns use one or two.
pub const MAX_PATTERN_STARS: usize = 8;

/// Firmware expectation from the baseline's `# Firmware:` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmwareSpec {
    /// Version as `sfr` prints it from `ver_sw_release`, for example `1.17.0`.
    pub version: String,
    /// Optional git hash prefix (7 to 40 lowercase hex digits).
    pub git_prefix: Option<String>,
}

impl fmt::Display for FirmwareSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.git_prefix {
            Some(g) => write!(f, "{} {}", self.version, g),
            None => write!(f, "{}", self.version),
        }
    }
}

/// A parsed baseline.
#[derive(Debug, Clone)]
pub struct Baseline {
    /// Expected firmware.
    pub firmware: FirmwareSpec,
    /// Expected parameter values, sorted by name.
    pub params: BTreeMap<String, ParamValue>,
}

/// A baseline that cannot be used (SPEC B1.4 exit 3), with its 1-based line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineError {
    /// 1-based line number, or 0 for the file as a whole.
    pub line: usize,
    /// What is wrong.
    pub reason: String,
}

impl fmt::Display for BaselineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.line == 0 {
            write!(f, "{}", self.reason)
        } else {
            write!(f, "line {}: {}", self.line, self.reason)
        }
    }
}

impl std::error::Error for BaselineError {}

fn err(line: usize, reason: impl Into<String>) -> BaselineError {
    BaselineError {
        line,
        reason: reason.into(),
    }
}

/// True for a PX4 parameter name: 1 to 16 of `A-Z`, `a-z`, `0-9`, `_`.
pub fn valid_param_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 16
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn parse_firmware(rest: &str, line: usize) -> Result<FirmwareSpec, BaselineError> {
    let mut parts = rest.split_whitespace();
    let version = parts
        .next()
        .ok_or_else(|| err(line, "`# Firmware:` line has no version"))?;
    if !version
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return Err(err(
            line,
            format!("firmware version `{version}` has unexpected characters"),
        ));
    }
    let git_prefix = match parts.next() {
        None => None,
        Some(g) => {
            let g = g.to_ascii_lowercase();
            if !(7..=40).contains(&g.len()) || !g.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(err(
                    line,
                    format!("git hash prefix `{g}` must be 7 to 40 hex digits"),
                ));
            }
            Some(g)
        }
    };
    if parts.next().is_some() {
        return Err(err(
            line,
            "`# Firmware:` line has more than a version and a git hash prefix",
        ));
    }
    Ok(FirmwareSpec {
        version: version.to_string(),
        git_prefix,
    })
}

/// Parses a baseline file.
pub fn parse_baseline(text: &str) -> Result<Baseline, BaselineError> {
    let mut firmware: Option<FirmwareSpec> = None;
    let mut params = BTreeMap::new();
    // A UTF-8 byte order mark, as some editors on Windows write, is not part of line 1.
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    for (i, raw) in text.lines().enumerate() {
        let n = i + 1;
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if line.trim().is_empty() {
            continue;
        }
        if let Some(comment) = line.strip_prefix('#') {
            if let Some(rest) = comment.trim_start().strip_prefix("Firmware:") {
                if firmware.is_some() {
                    return Err(err(n, "second `# Firmware:` line"));
                }
                firmware = Some(parse_firmware(rest, n)?);
            }
            continue;
        }
        let cols: Vec<&str> = line.split('\t').collect();
        let [_vehicle, _component, name, value, ty] = cols.as_slice() else {
            return Err(err(
                n,
                format!("expected 5 tab-separated columns, found {}", cols.len()),
            ));
        };
        if !valid_param_name(name) {
            return Err(err(n, format!("`{name}` is not a parameter name")));
        }
        let value = match *ty {
            "6" => ParamValue::I32(
                value
                    .parse::<i32>()
                    .map_err(|_| err(n, format!("{name}: `{value}` is not an int32")))?,
            ),
            "9" => {
                let v = value
                    .parse::<f32>()
                    .map_err(|_| err(n, format!("{name}: `{value}` is not a number")))?;
                // A logged parameter can be NaN (the record prints it `f32:NaN`), so a baseline
                // may say so too; infinities cannot be set from a ground station and are refused.
                if v.is_infinite() {
                    return Err(err(
                        n,
                        format!("{name}: `{value}` is not a finite float32 or NaN"),
                    ));
                }
                ParamValue::F32(v)
            }
            other => {
                return Err(err(
                    n,
                    format!("{name}: type `{other}` is not 6 (int32) or 9 (float32)"),
                ));
            }
        };
        if params.insert(name.to_string(), value).is_some() {
            return Err(err(n, format!("{name} appears twice")));
        }
        if params.len() > MAX_PARAMS {
            return Err(err(n, format!("more than {MAX_PARAMS} parameters")));
        }
    }
    let firmware =
        firmware.ok_or_else(|| err(0, "no `# Firmware: <version> [<git hash prefix>]` line"))?;
    Ok(Baseline { firmware, params })
}

/// A parameter name pattern: `*` matches any run of characters, everything else literally.
/// The pieces between `*` are split once, when the pattern is made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    text: String,
    parts: Vec<String>,
}

impl Pattern {
    /// Validates a pattern: 1 to 64 of `A-Z`, `a-z`, `0-9`, `_`, `*`, with at most
    /// [`MAX_PATTERN_STARS`] `*`.
    pub fn new(p: &str) -> Option<Pattern> {
        let ok = !p.is_empty()
            && p.len() <= 64
            && p.bytes().filter(|&b| b == b'*').count() <= MAX_PATTERN_STARS
            && p.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'*');
        ok.then(|| Pattern {
            text: p.to_string(),
            parts: p.split('*').map(str::to_string).collect(),
        })
    }

    /// The pattern text.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Whether `name` matches the whole pattern.
    pub fn matches(&self, name: &str) -> bool {
        let Some((first, tail)) = self.parts.split_first() else {
            return false;
        };
        let Some(mut rest) = name.strip_prefix(first.as_str()) else {
            return false;
        };
        let Some((last, middle)) = tail.split_last() else {
            return rest.is_empty();
        };
        for part in middle {
            match rest.find(part.as_str()) {
                Some(at) => rest = rest.get(at + part.len()..).unwrap_or(""),
                None => return false,
            }
        }
        rest.len() >= last.len() && rest.ends_with(last.as_str())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    const GOOD: &str = "# Onboard parameters for Vehicle 1\n#\n# Firmware: 1.17.0 D6F12AD\n#\n# Vehicle-Id Component-Id Name Value Type\n1\t1\tBAT_LOW_THR\t0.150000005960464478\t9\r\n1\t1\tCOM_DISARM_LAND\t2\t9\n1\t1\tNAV_DLL_ACT\t0\t6\n";

    #[test]
    fn parses_qgc_export_with_firmware_line() {
        let b = parse_baseline(GOOD).expect("valid baseline");
        assert_eq!(
            b.firmware,
            FirmwareSpec {
                version: "1.17.0".into(),
                git_prefix: Some("d6f12ad".into())
            }
        );
        assert_eq!(b.params.len(), 3);
        assert_eq!(
            b.params.get("BAT_LOW_THR").map(|v| v.to_string()),
            Some("f32:0.15".into())
        );
        assert_eq!(
            b.params.get("NAV_DLL_ACT").map(|v| v.to_string()),
            Some("i32:0".into())
        );
    }

    #[test]
    fn rejects_bad_baselines_with_line_numbers() {
        let cases: &[(&str, usize, &str)] = &[
            ("1\t1\tA\t1\t6\n", 0, "no `# Firmware"),
            ("# Firmware: 1.17.0\n# Firmware: 1.17.0\n", 2, "second"),
            ("# Firmware: 1.17.0 xyz\n", 1, "7 to 40 hex"),
            ("# Firmware: 1.17.0\n1\t1\tA\t1\n", 2, "5 tab-separated"),
            ("# Firmware: 1.17.0\n1\t1\tA\t1.5\t6\n", 2, "not an int32"),
            ("# Firmware: 1.17.0\n1\t1\tA\tinf\t9\n", 2, "finite"),
            ("# Firmware: 1.17.0\n1\t1\tA\t-infinity\t9\n", 2, "finite"),
            ("# Firmware: 1.17.0\n1\t1\tA\t1\t7\n", 2, "type `7`"),
            (
                "# Firmware: 1.17.0\n1\t1\tA\t1\t6\n1\t1\tA\t2\t6\n",
                3,
                "twice",
            ),
            (
                "# Firmware: 1.17.0\n1\t1\tBAD NAME\t1\t6\n",
                2,
                "not a parameter name",
            ),
        ];
        for (text, line, needle) in cases {
            let e = parse_baseline(text).expect_err(text);
            assert_eq!(e.line, *line, "{text:?}: {e}");
            assert!(e.reason.contains(needle), "{text:?}: {e}");
        }
    }

    #[test]
    fn byte_order_mark_crlf_and_nan_are_accepted() {
        let b =
            parse_baseline("\u{feff}# Firmware: 1.17.0\r\n1\t1\tX\tnan\t9\r\n1\t1\tY\t-0\t9\r\n")
                .expect("valid");
        assert_eq!(
            b.params.get("X").map(|v| v.to_string()),
            Some("f32:NaN".into())
        );
        assert_eq!(
            b.params.get("Y").map(|v| v.to_string()),
            Some("f32:-0".into())
        );
        assert_eq!(b.firmware.version, "1.17.0");
    }

    #[test]
    fn float_values_round_once_to_float32() {
        // 16777217 is not a float32; the nearest is 16777216.
        let b = parse_baseline("# Firmware: 1.17.0\n1\t1\tX\t16777217\t9\n").expect("valid");
        assert_eq!(
            b.params.get("X").map(|v| v.to_string()),
            Some("f32:16777216".into())
        );
    }

    #[test]
    fn patterns_match_whole_names() {
        let p = |s: &str| Pattern::new(s).expect("valid pattern");
        assert!(p("CAL_BARO*_OFF").matches("CAL_BARO0_OFF"));
        assert!(!p("CAL_BARO*_OFF").matches("CAL_BARO0_ID"));
        assert!(p("ASPD_SCALE_*").matches("ASPD_SCALE_"));
        assert!(p("ASPD_SCALE_*").matches("ASPD_SCALE_APPLY"));
        assert!(p("COM_FLIGHT_UUID").matches("COM_FLIGHT_UUID"));
        assert!(!p("COM_FLIGHT_UUID").matches("COM_FLIGHT_UUID2"));
        assert!(!p("A*A").matches("A"));
        assert!(p("A*A").matches("AA"));
        assert!(p("*").matches(""));
        assert!(p("*X*").matches("AXB"));
        assert!(Pattern::new("BAD-NAME").is_none());
        assert!(Pattern::new("").is_none());
        assert!(Pattern::new("A*B*C*D*E*F*G*H*I").is_some());
        assert!(Pattern::new("A*B*C*D*E*F*G*H*I*J").is_none(), "nine stars");
    }
}
