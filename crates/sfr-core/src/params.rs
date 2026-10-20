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
    /// SHA-256 of the baseline file the operator gave, set by the caller that read it
    /// (`baseline.sha256` in the record).
    pub sha256: Option<[u8; 32]>,
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

impl FirmwareSpec {
    /// Parses `<version> [<git hash prefix>]`, the text after `# Firmware:` and the record's
    /// `baseline.firmware`.
    pub fn parse(text: &str) -> Result<FirmwareSpec, String> {
        parse_firmware(text, 0).map_err(|e| e.reason)
    }
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
        let [vehicle, component, name, value, ty] = cols.as_slice() else {
            return Err(err(
                n,
                format!("expected 5 tab-separated columns, found {}", cols.len()),
            ));
        };
        if vehicle.parse::<u8>().is_err() || component.parse::<u8>().is_err() {
            return Err(err(
                n,
                format!(
                    "vehicle id `{vehicle}` and component id `{component}` must be numbers from 0 to 255"
                ),
            ));
        }
        if !valid_param_name(name) {
            return Err(err(
                n,
                format!(
                    "`{name}` is not a parameter name (1 to 16 letters, digits, `_`; SPEC B1.4)"
                ),
            ));
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
                // NaN and infinities parse (`nan`, `inf`, `-inf`, `infinity`), so a baseline can
                // state any value a log can hold; a finite number beyond float32 is refused.
                let lower = value.to_ascii_lowercase();
                let infinite_text =
                    matches!(lower.trim_start_matches(['+', '-']), "inf" | "infinity");
                if v.is_infinite() && !infinite_text {
                    return Err(err(
                        n,
                        format!("{name}: `{value}` is outside the float32 range"),
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
            return Err(err(
                n,
                crate::limit_exceeded(
                    "the number of baseline parameters",
                    MAX_PARAMS,
                    "parameters",
                ),
            ));
        }
    }
    let end = text.lines().count() + 1;
    let firmware = firmware.ok_or_else(|| {
        err(
            end,
            "no `# Firmware: <version> [<git hash prefix>]` line before the end of the file",
        )
    })?;
    Ok(Baseline {
        firmware,
        params,
        sha256: None,
    })
}

/// The most sets of pattern positions [`Pattern::cover_every_name`] keeps for one name length.
pub const MAX_COVER_STATES: usize = 100_000;

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

    /// Whether the patterns together match every parameter name ([`valid_param_name`]: 1 to 16
    /// of `A-Z`, `a-z`, `0-9`, `_`), so R3 would compare nothing. Exact: it looks for a name no
    /// pattern matches, over every length, with each pattern as a set of positions (a glob
    /// automaton). Characters a pattern does not name behave alike, so one stands for them all.
    /// The search keeps at most [`MAX_COVER_STATES`] position sets per length; past that it
    /// answers true, so `seal` asks for `--allow-ignore-all` rather than guess.
    pub fn cover_every_name(patterns: &[Pattern]) -> bool {
        if patterns.is_empty() {
            return false;
        }
        if patterns.iter().any(Pattern::matches_everything) {
            return true;
        }
        // Each pattern as tokens: Some(byte) a literal, None a `*`. At most 64 tokens, so a set
        // of positions 0..=64 fits a u128.
        let toks: Vec<Vec<Option<u8>>> = patterns
            .iter()
            .map(|p| p.text.bytes().map(|b| (b != b'*').then_some(b)).collect())
            .collect();
        let close = |t: &[Option<u8>], mut set: u128| {
            for (i, tok) in t.iter().enumerate() {
                if set & (1u128 << i) != 0 && tok.is_none() {
                    set |= 1u128 << (i + 1);
                }
            }
            set
        };
        let step = |t: &[Option<u8>], set: u128, c: u8| {
            let mut next = 0u128;
            for (i, tok) in t.iter().enumerate() {
                if set & (1u128 << i) == 0 {
                    continue;
                }
                match tok {
                    Some(b) if *b == c => next |= 1u128 << (i + 1),
                    None => next |= 1u128 << i,
                    _ => {}
                }
            }
            close(t, next)
        };
        let accepts = |t: &[Option<u8>], set: u128| set & (1u128 << t.len()) != 0;
        let mut letters: Vec<u8> = toks.iter().flatten().flatten().copied().collect();
        letters.sort_unstable();
        letters.dedup();
        if let Some(other) =
            (0..=127u8).find(|b| (b.is_ascii_alphanumeric() || *b == b'_') && !letters.contains(b))
        {
            letters.push(other);
        }
        let mut frontier: std::collections::BTreeSet<Vec<u128>> =
            std::iter::once(toks.iter().map(|t| close(t, 1)).collect()).collect();
        for _ in 0..16 {
            let mut next = std::collections::BTreeSet::new();
            for state in &frontier {
                for &c in &letters {
                    let s: Vec<u128> = toks
                        .iter()
                        .zip(state)
                        .map(|(t, &set)| step(t, set, c))
                        .collect();
                    if !toks.iter().zip(&s).any(|(t, &set)| accepts(t, set)) {
                        return false;
                    }
                    next.insert(s);
                }
                if next.len() > MAX_COVER_STATES {
                    return true;
                }
            }
            frontier = next;
        }
        true
    }

    /// Whether the pattern matches every name: it is `*` only (one or more).
    pub fn matches_everything(&self) -> bool {
        self.text.bytes().all(|b| b == b'*')
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

    #[test]
    fn patterns_cover_every_name_only_when_no_name_escapes_them_all() {
        let ps =
            |v: &[&str]| -> Vec<Pattern> { v.iter().map(|p| Pattern::new(p).unwrap()).collect() };
        let chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_";
        let prefixes: Vec<String> = chars.chars().map(|c| format!("{c}*")).collect();
        let suffixes: Vec<String> = chars.chars().map(|c| format!("*{c}")).collect();
        let refs =
            |v: &[String]| -> Vec<Pattern> { v.iter().map(|p| Pattern::new(p).unwrap()).collect() };
        assert!(Pattern::cover_every_name(&ps(&["*"])));
        assert!(Pattern::cover_every_name(&ps(&["MPC_*", "**"])));
        assert!(!Pattern::cover_every_name(&ps(&[])));
        assert!(!Pattern::cover_every_name(&ps(&["MPC_*", "*_P"])));
        // One pattern per first character, or per last character: every name, together.
        assert!(Pattern::cover_every_name(&refs(&prefixes)));
        assert!(Pattern::cover_every_name(&refs(&suffixes)));
        // Without one of them, a name starting (or ending) with that character escapes.
        for skip in [0usize, 26, 62] {
            let mut v = prefixes.clone();
            v.remove(skip);
            assert!(!Pattern::cover_every_name(&refs(&v)), "{skip}");
            let mut v = suffixes.clone();
            v.remove(skip);
            assert!(!Pattern::cover_every_name(&refs(&v)), "{skip}");
        }
        // Names with an `_` and names without one: every name.
        assert!(!Pattern::cover_every_name(&ps(&["*_*", "A*"])));
        let mut v = prefixes.clone();
        v.retain(|p| p != "_*");
        v.push("*_*".into());
        assert!(Pattern::cover_every_name(&refs(&v)));
        // What the search says agrees with matching every name of up to two characters.
        let small = ps(&["A*", "*B", "*_*", "C"]);
        let mut escaped = false;
        for a in chars.chars() {
            escaped |= !small.iter().any(|p| p.matches(&a.to_string()));
            for b in chars.chars() {
                escaped |= !small.iter().any(|p| p.matches(&format!("{a}{b}")));
            }
        }
        assert!(escaped);
        assert!(!Pattern::cover_every_name(&small));
    }

    const GOOD: &str = "# Onboard parameters for Vehicle 1\n#\n# Firmware: 1.17.0 D6F12AD\n#\n# Vehicle-Id Component-Id Name Value Type\n1\t1\tBAT_LOW_THR\t0.150000005960464478\t9\r\n1\t1\tCOM_DISARM_LAND\t2\t9\n1\t1\tNAV_DLL_ACT\t0\t6\n";

    #[test]
    fn baseline_parameter_names_follow_the_px4_rule() {
        let text = |name: &str| format!("# Firmware: 1.17.0\n1\t1\t{name}\t1\t6\n");
        parse_baseline(&text(&"P".repeat(16))).expect("16 characters");
        let e = parse_baseline(&text(&"P".repeat(17))).expect_err("17 characters");
        assert!(
            e.to_string()
                .contains("is not a parameter name (1 to 16 letters, digits, `_`; SPEC B1.4)"),
            "{e}"
        );
    }

    #[test]
    fn baseline_parameter_limit_is_enforced_and_named() {
        let baseline = |n: usize| {
            let mut s = String::from("# Firmware: 1.17.0\n");
            for i in 0..n {
                s.push_str(&format!("1\t1\tP{i}\t1\t6\n"));
            }
            s
        };
        assert_eq!(
            parse_baseline(&baseline(MAX_PARAMS)).map(|b| b.params.len()),
            Ok(MAX_PARAMS)
        );
        let e = parse_baseline(&baseline(MAX_PARAMS + 1)).expect_err("over the limit");
        assert!(
            e.to_string().contains(
                "the number of baseline parameters exceeds the input limit of 65536 parameters (SPEC B1.4)"
            ),
            "{e}"
        );
    }

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
            ("1\t1\tA\t1\t6\n", 2, "no `# Firmware"),
            ("# Firmware: 1.17.0\nx\t1\tA\t1\t6\n", 2, "vehicle id"),
            (
                "# Firmware: 1.17.0\n1\t1\tA\t1e39\t9\n",
                2,
                "outside the float32 range",
            ),
            ("# Firmware: 1.17.0\n# Firmware: 1.17.0\n", 2, "second"),
            ("# Firmware: 1.17.0 xyz\n", 1, "7 to 40 hex"),
            ("# Firmware: 1.17.0\n1\t1\tA\t1\n", 2, "5 tab-separated"),
            ("# Firmware: 1.17.0\n1\t1\tA\t1.5\t6\n", 2, "not an int32"),
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
