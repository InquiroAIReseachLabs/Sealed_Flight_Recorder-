//! JSON values and their deterministic text forms (SPEC B1.7).
//!
//! The value model has no floating-point numbers: integers are limited to the I-JSON safe
//! range (|n| <= 2^53 - 1) and every unsigned 64-bit quantity (timestamps) is a decimal string.
//! [`canonical`] writes RFC 8785 (JCS) bytes for that subset: object keys sorted by UTF-16 code
//! units, no whitespace, and strings escaped exactly as ECMAScript `JSON.stringify` does.
//! [`pretty`] writes the same structure with two-space indentation for people and diffs.

use std::collections::BTreeMap;
use std::fmt::Write as _;

/// Largest integer magnitude that survives a round trip through an IEEE 754 double.
pub const MAX_SAFE_INTEGER: i64 = (1 << 53) - 1;

/// A JSON value without floats.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// `null`
    Null,
    /// `true` or `false`
    Bool(bool),
    /// An integer within [`MAX_SAFE_INTEGER`]; construct with [`Value::int`].
    Int(i64),
    /// A string.
    Str(String),
    /// An array.
    Array(Vec<Value>),
    /// An object; keys are unique by construction.
    Object(BTreeMap<String, Value>),
}

impl Value {
    /// An integer, or its decimal string when it is outside the safe range.
    pub fn int(n: i64) -> Value {
        if (-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&n) {
            Value::Int(n)
        } else {
            Value::Str(n.to_string())
        }
    }

    /// A count or index. Counts in a log never approach 2^53; larger values become strings.
    pub fn count(n: u64) -> Value {
        match i64::try_from(n) {
            Ok(v) => Value::int(v),
            Err(_) => Value::Str(n.to_string()),
        }
    }

    /// An unsigned 64-bit quantity, always as a decimal string (SPEC B1.7).
    pub fn u64_str(n: u64) -> Value {
        Value::Str(n.to_string())
    }

    /// A string value.
    pub fn str(s: impl Into<String>) -> Value {
        Value::Str(s.into())
    }

    /// `Some(v)` as a string, `None` as `null`.
    pub fn opt_str(s: Option<impl Into<String>>) -> Value {
        s.map_or(Value::Null, |s| Value::Str(s.into()))
    }
}

/// Builds an object field by field.
#[derive(Debug, Default)]
pub struct Obj(BTreeMap<String, Value>);

impl Obj {
    /// An empty object.
    pub fn new() -> Self {
        Obj(BTreeMap::new())
    }

    /// Adds or replaces a field.
    pub fn field(mut self, key: &str, value: Value) -> Self {
        self.0.insert(key.to_string(), value);
        self
    }

    /// Adds or replaces a field in place.
    pub fn set(&mut self, key: &str, value: Value) {
        self.0.insert(key.to_string(), value);
    }

    /// The finished object.
    pub fn build(self) -> Value {
        Value::Object(self.0)
    }
}

fn sorted_utf16(map: &BTreeMap<String, Value>) -> Vec<(&String, &Value)> {
    let mut entries: Vec<(&String, &Value)> = map.iter().collect();
    // BTreeMap orders by UTF-8 bytes; JCS orders by UTF-16 code units. They differ only when
    // a key holds characters above U+FFFF next to characters in U+E000..U+FFFF.
    entries.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));
    entries
}

/// `s` as a JSON string. `display` is for text a person reads (`pretty`): it also writes the
/// characters that hide or move the reader's view (controls, format characters, line and
/// paragraph separators; `crate::display`) as `\uXXXX`, which is the same string. The canonical
/// form never does: RFC 8785 writes every other character as itself.
fn write_string(out: &mut String, s: &str, display: bool) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c if display && (c.is_control() || crate::display::is_hidden(c)) => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    let _ = write!(out, "\\u{unit:04x}");
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write_canonical(out: &mut String, v: &Value) {
    write_value(out, v, false);
}

fn write_value(out: &mut String, v: &Value, display: bool) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Int(n) => {
            let _ = write!(out, "{n}");
        }
        Value::Str(s) => write_string(out, s, display),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, item, display);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            for (i, (k, item)) in sorted_utf16(map).into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(out, k, display);
                out.push(':');
                write_value(out, item, display);
            }
            out.push('}');
        }
    }
}

fn indent(out: &mut String, depth: usize) {
    out.push('\n');
    for _ in 0..depth {
        out.push_str("  ");
    }
}

fn write_pretty(out: &mut String, v: &Value, depth: usize) {
    match v {
        Value::Array(items) if !items.is_empty() => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                indent(out, depth + 1);
                write_pretty(out, item, depth + 1);
            }
            indent(out, depth);
            out.push(']');
        }
        Value::Object(map) if !map.is_empty() => {
            out.push('{');
            for (i, (k, item)) in sorted_utf16(map).into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                indent(out, depth + 1);
                write_string(out, k, true);
                out.push_str(": ");
                write_pretty(out, item, depth + 1);
            }
            indent(out, depth);
            out.push('}');
        }
        other => write_value(out, other, true),
    }
}

/// RFC 8785 canonical text of `v`.
pub fn canonical(v: &Value) -> String {
    let mut out = String::new();
    write_canonical(&mut out, v);
    out
}

/// Indented text of `v` with the same key order as [`canonical`], ending in a newline. It is for
/// people: a character that hides or moves the reader's view (a control, a format character such
/// as U+202E) is written as a `\uXXXX` escape, so the string is the same and the page shows it.
pub fn pretty(v: &Value) -> String {
    let mut out = String::new();
    write_pretty(&mut out, v, 0);
    out.push('\n');
    out
}

/// Deepest nesting [`parse`] accepts. A record nests about 5 levels.
pub const MAX_DEPTH: usize = 64;

/// Why bytes are not a JSON value of the record's subset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// Byte offset of the problem.
    pub offset: usize,
    /// What is wrong.
    pub reason: String,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "byte offset {}: {}", self.offset, self.reason)
    }
}

impl std::error::Error for ParseError {}

struct Parser<'a> {
    b: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn err<T>(&self, reason: impl Into<String>) -> Result<T, ParseError> {
        Err(ParseError {
            offset: self.pos,
            reason: reason.into(),
        })
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.pos).copied()
    }

    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn expect(&mut self, lit: &[u8]) -> Result<(), ParseError> {
        if self.b.get(self.pos..self.pos + lit.len()) == Some(lit) {
            self.pos += lit.len();
            Ok(())
        } else {
            self.err(format!("expected `{}`", String::from_utf8_lossy(lit)))
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, ParseError> {
        self.ws();
        if matches!(self.peek(), Some(b'[' | b'{')) && depth >= MAX_DEPTH {
            return self.err(crate::limit_exceeded("JSON nesting", MAX_DEPTH, "levels"));
        }
        match self.peek() {
            Some(b'n') => self.expect(b"null").map(|()| Value::Null),
            Some(b't') => self.expect(b"true").map(|()| Value::Bool(true)),
            Some(b'f') => self.expect(b"false").map(|()| Value::Bool(false)),
            Some(b'"') => self.string().map(Value::Str),
            Some(b'[') => {
                self.pos += 1;
                let mut items = Vec::new();
                self.ws();
                if self.peek() == Some(b']') {
                    self.pos += 1;
                    return Ok(Value::Array(items));
                }
                loop {
                    items.push(self.value(depth + 1)?);
                    self.ws();
                    match self.peek() {
                        Some(b',') => self.pos += 1,
                        Some(b']') => {
                            self.pos += 1;
                            return Ok(Value::Array(items));
                        }
                        _ => return self.err("expected `,` or `]`"),
                    }
                }
            }
            Some(b'{') => {
                self.pos += 1;
                let mut map = BTreeMap::new();
                self.ws();
                if self.peek() == Some(b'}') {
                    self.pos += 1;
                    return Ok(Value::Object(map));
                }
                loop {
                    self.ws();
                    let at = self.pos;
                    if self.peek() != Some(b'"') {
                        return self.err("expected a string key");
                    }
                    let key = self.string()?;
                    self.ws();
                    self.expect(b":")?;
                    let v = self.value(depth + 1)?;
                    if map.insert(key.clone(), v).is_some() {
                        return Err(ParseError {
                            offset: at,
                            reason: format!("duplicate key `{key}`"),
                        });
                    }
                    self.ws();
                    match self.peek() {
                        Some(b',') => self.pos += 1,
                        Some(b'}') => {
                            self.pos += 1;
                            return Ok(Value::Object(map));
                        }
                        _ => return self.err("expected `,` or `}`"),
                    }
                }
            }
            Some(b'-' | b'0'..=b'9') => self.integer(),
            Some(_) => self.err("unexpected character"),
            None => self.err("unexpected end of input"),
        }
    }

    fn integer(&mut self) -> Result<Value, ParseError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        let digits = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        let n = self.pos - digits;
        if n == 0 {
            return self.err("expected a digit");
        }
        if n > 1 && self.b.get(digits) == Some(&b'0') {
            return Err(ParseError {
                offset: digits,
                reason: "leading zero".into(),
            });
        }
        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return self.err("the record has no floating-point numbers (SPEC B1.7)");
        }
        let text = std::str::from_utf8(self.b.get(start..self.pos).unwrap_or(b"")).unwrap_or("");
        match text.parse::<i64>() {
            Ok(v) if (-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&v) && text != "-0" => {
                Ok(Value::Int(v))
            }
            _ => Err(ParseError {
                offset: start,
                reason: format!("integer {text} outside the safe range or -0"),
            }),
        }
    }

    fn hex4(&mut self) -> Result<u32, ParseError> {
        let mut v = 0u32;
        for _ in 0..4 {
            let d = match self.peek() {
                Some(c @ b'0'..=b'9') => u32::from(c - b'0'),
                Some(c @ b'a'..=b'f') => u32::from(c - b'a' + 10),
                Some(c @ b'A'..=b'F') => u32::from(c - b'A' + 10),
                _ => return self.err("bad \\u escape"),
            };
            v = (v << 4) | d;
            self.pos += 1;
        }
        Ok(v)
    }

    fn string(&mut self) -> Result<String, ParseError> {
        self.pos += 1; // opening quote
        let mut out = String::new();
        loop {
            let run = self.pos;
            while let Some(c) = self.peek() {
                if c == b'"' || c == b'\\' || c < 0x20 {
                    break;
                }
                self.pos += 1;
            }
            let chunk = self.b.get(run..self.pos).unwrap_or(b"");
            match std::str::from_utf8(chunk) {
                Ok(s) => out.push_str(s),
                Err(e) => {
                    return Err(ParseError {
                        offset: run + e.valid_up_to(),
                        reason: "invalid UTF-8".into(),
                    });
                }
            }
            match self.peek() {
                Some(b'"') => {
                    self.pos += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.pos += 1;
                    let esc = self.peek();
                    self.pos += 1;
                    match esc {
                        Some(b'"') => out.push('"'),
                        Some(b'\\') => out.push('\\'),
                        Some(b'/') => out.push('/'),
                        Some(b'b') => out.push('\u{8}'),
                        Some(b'f') => out.push('\u{c}'),
                        Some(b'n') => out.push('\n'),
                        Some(b'r') => out.push('\r'),
                        Some(b't') => out.push('\t'),
                        Some(b'u') => {
                            let hi = self.hex4()?;
                            let code = if (0xD800..0xDC00).contains(&hi) {
                                self.expect(b"\\u")?;
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return self.err("unpaired surrogate");
                                }
                                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                            } else if (0xDC00..0xE000).contains(&hi) {
                                return self.err("unpaired surrogate");
                            } else {
                                hi
                            };
                            match char::from_u32(code) {
                                Some(c) => out.push(c),
                                None => return self.err("bad \\u escape"),
                            }
                        }
                        _ => {
                            self.pos -= 1;
                            return self.err("bad escape");
                        }
                    }
                }
                Some(_) => return self.err("control character in string"),
                None => return self.err("unterminated string"),
            }
        }
    }
}

/// Parses one JSON value of the record's subset: no floating-point numbers, integers within
/// the safe range, no duplicate keys, nesting at most [`MAX_DEPTH`], nothing after the value.
pub fn parse(bytes: &[u8]) -> Result<Value, ParseError> {
    let mut p = Parser { b: bytes, pos: 0 };
    let v = p.value(0)?;
    p.ws();
    if p.pos != bytes.len() {
        return p.err("data after the JSON value");
    }
    Ok(v)
}

/// One top-level member of a canonical object, as byte ranges of the input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberSpan {
    /// The member's key.
    pub key: String,
    /// The value's bytes.
    pub value: std::ops::Range<usize>,
    /// For an array value, each element's bytes.
    pub elements: Vec<std::ops::Range<usize>>,
    /// For an array value, the bytes of each element's top-level `seq` member, if it is an
    /// object that has one (SPEC B1.7: events are leaves in sequence order).
    pub seqs: Vec<Option<std::ops::Range<usize>>>,
}

/// Checks in one pass, without building values, that `bytes` are an object in exactly the
/// RFC 8785 canonical form of the record's value subset (no whitespace, keys strictly ordered
/// by UTF-16 code units, canonical string escapes, integers in the safe range), and returns
/// the byte ranges of its members. In canonical text each value's bytes are its own canonical
/// form, so a Merkle leaf can be hashed straight from the input.
pub fn scan_canonical(bytes: &[u8]) -> Result<Vec<MemberSpan>, ParseError> {
    let mut sc = Scanner {
        b: bytes,
        pos: 0,
        seq: None,
    };
    if sc.peek() != Some(b'{') {
        return sc.err("expected `{`");
    }
    let members = sc.object(0, true)?;
    if sc.pos != bytes.len() {
        return sc.err("data after the JSON value (or not canonical)");
    }
    Ok(members)
}

/// Where a top-level array's scan puts each element's span and its `seq` member's span.
type ElementSpans<'v> = (
    &'v mut Vec<std::ops::Range<usize>>,
    &'v mut Vec<Option<std::ops::Range<usize>>>,
);

struct Scanner<'a> {
    b: &'a [u8],
    pos: usize,
    /// The value span of the last `seq` key read in an object directly inside a top-level array.
    seq: Option<std::ops::Range<usize>>,
}

impl Scanner<'_> {
    fn err<T>(&self, reason: impl Into<String>) -> Result<T, ParseError> {
        Err(ParseError {
            offset: self.pos,
            reason: reason.into(),
        })
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.pos).copied()
    }

    fn eat(&mut self, c: u8) -> Result<(), ParseError> {
        if self.peek() == Some(c) {
            self.pos += 1;
            Ok(())
        } else {
            self.err(format!("expected `{}` (or not canonical)", char::from(c)))
        }
    }

    fn value(&mut self, depth: usize) -> Result<(), ParseError> {
        if matches!(self.peek(), Some(b'[' | b'{')) && depth >= MAX_DEPTH {
            return self.err(crate::limit_exceeded("JSON nesting", MAX_DEPTH, "levels"));
        }
        match self.peek() {
            Some(b'{') => self.object(depth, false).map(|_| ()),
            Some(b'[') => self.array(depth, None),
            Some(b'"') => self.string().map(|_| ()),
            Some(b'n') => self.literal(b"null"),
            Some(b't') => self.literal(b"true"),
            Some(b'f') => self.literal(b"false"),
            Some(b'-' | b'0'..=b'9') => self.integer(),
            Some(_) => self.err("unexpected character (or not canonical)"),
            None => self.err("unexpected end of input"),
        }
    }

    fn literal(&mut self, lit: &[u8]) -> Result<(), ParseError> {
        if self.b.get(self.pos..self.pos + lit.len()) == Some(lit) {
            self.pos += lit.len();
            Ok(())
        } else {
            self.err(format!("expected `{}`", String::from_utf8_lossy(lit)))
        }
    }

    fn integer(&mut self) -> Result<(), ParseError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        let digits = self.pos;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        let n = self.pos - digits;
        let text = self.b.get(start..self.pos).unwrap_or(b"");
        let ok = n > 0
            && !(n > 1 && self.b.get(digits) == Some(&b'0'))
            && text != b"-0"
            && !matches!(self.peek(), Some(b'.' | b'e' | b'E'))
            && std::str::from_utf8(text)
                .ok()
                .and_then(|t| t.parse::<i64>().ok())
                .is_some_and(|v| (-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&v));
        if ok {
            Ok(())
        } else {
            Err(ParseError {
                offset: start,
                reason: "not a canonical integer in the safe range".into(),
            })
        }
    }

    /// A canonical string; returns its raw bytes between the quotes and whether it has escapes.
    fn string(&mut self) -> Result<(std::ops::Range<usize>, bool), ParseError> {
        self.pos += 1;
        let start = self.pos;
        let mut escaped = false;
        loop {
            let run = self.pos;
            let rest = self.b.get(run..).unwrap_or(b"");
            let n = rest
                .iter()
                .position(|&c| c == b'"' || c == b'\\' || c < 0x20)
                .unwrap_or(rest.len());
            let chunk = rest.get(..n).unwrap_or(b"");
            // ASCII is valid UTF-8; only runs with high bytes need the full check.
            if !chunk.is_ascii()
                && let Err(e) = std::str::from_utf8(chunk)
            {
                return Err(ParseError {
                    offset: run + e.valid_up_to(),
                    reason: "invalid UTF-8".into(),
                });
            }
            self.pos = run + n;
            match self.peek() {
                Some(b'"') => {
                    let r = start..self.pos;
                    self.pos += 1;
                    return Ok((r, escaped));
                }
                Some(b'\\') => {
                    escaped = true;
                    let at = self.pos;
                    let esc = self.b.get(self.pos + 1).copied();
                    match esc {
                        Some(b'"' | b'\\' | b'b' | b'f' | b'n' | b'r' | b't') => self.pos += 2,
                        Some(b'u') => {
                            // Only control characters without a short form are written as
                            // \u00xx, in lowercase hex (RFC 8785 section 3.2.2.2).
                            let hex = self.b.get(self.pos + 2..self.pos + 6).unwrap_or(b"");
                            let v = std::str::from_utf8(hex)
                                .ok()
                                .and_then(|h| u32::from_str_radix(h, 16).ok());
                            let lower = hex
                                .iter()
                                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c));
                            match v {
                                Some(v)
                                    if hex.len() == 4
                                        && lower
                                        && v < 0x20
                                        && ![0x08, 0x09, 0x0a, 0x0c, 0x0d].contains(&v) =>
                                {
                                    self.pos += 6;
                                }
                                _ => {
                                    return Err(ParseError {
                                        offset: at,
                                        reason: "escape not in canonical form".into(),
                                    });
                                }
                            }
                        }
                        _ => {
                            return Err(ParseError {
                                offset: at,
                                reason: "escape not in canonical form".into(),
                            });
                        }
                    }
                }
                Some(_) => return self.err("control character in string"),
                None => return self.err("unterminated string"),
            }
        }
    }

    fn key_text(&self, r: &std::ops::Range<usize>, escaped: bool) -> Result<String, ParseError> {
        let raw = self.b.get(r.clone()).unwrap_or(b"");
        if !escaped {
            return Ok(String::from_utf8_lossy(raw).into_owned());
        }
        let quoted = self.b.get(r.start - 1..r.end + 1).unwrap_or(b"");
        match parse(quoted) {
            Ok(Value::Str(s)) => Ok(s),
            _ => Err(ParseError {
                offset: r.start,
                reason: "bad key".into(),
            }),
        }
    }

    fn array(
        &mut self,
        depth: usize,
        mut spans: Option<ElementSpans<'_>>,
    ) -> Result<(), ParseError> {
        self.eat(b'[')?;
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(());
        }
        loop {
            let start = self.pos;
            self.seq = None;
            self.value(depth + 1)?;
            if let Some((s, q)) = spans.as_mut() {
                s.push(start..self.pos);
                q.push(self.seq.take());
            }
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(());
                }
                _ => return self.err("expected `,` or `]` (or not canonical)"),
            }
        }
    }

    fn object(&mut self, depth: usize, top: bool) -> Result<Vec<MemberSpan>, ParseError> {
        self.eat(b'{')?;
        let mut members = Vec::new();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(members);
        }
        let mut prev: Option<(std::ops::Range<usize>, bool)> = None;
        loop {
            if self.peek() != Some(b'"') {
                return self.err("expected a string key (or not canonical)");
            }
            let key_at = self.pos;
            let (k, escaped) = self.string()?;
            if let Some((p, p_escaped)) = &prev {
                let (a, b) = (
                    self.b.get(p.clone()).unwrap_or(b""),
                    self.b.get(k.clone()).unwrap_or(b""),
                );
                let ascii = !p_escaped && !escaped && a.is_ascii() && b.is_ascii();
                let ordered = if ascii {
                    a < b
                } else {
                    let (x, y) = (self.key_text(p, *p_escaped)?, self.key_text(&k, escaped)?);
                    x.encode_utf16().cmp(y.encode_utf16()) == std::cmp::Ordering::Less
                };
                if !ordered {
                    return Err(ParseError {
                        offset: key_at,
                        reason: "keys not in canonical order, or a duplicate key".into(),
                    });
                }
            }
            self.eat(b':')?;
            let vstart = self.pos;
            let mut elements = Vec::new();
            let mut seqs = Vec::new();
            if top && self.peek() == Some(b'[') {
                self.array(depth + 1, Some((&mut elements, &mut seqs)))?;
            } else {
                self.value(depth + 1)?;
            }
            // An object directly inside a top-level array sits at depth 2.
            if depth == 2 && !escaped && self.b.get(k.clone()) == Some(&b"seq"[..]) {
                self.seq = Some(vstart..self.pos);
            }
            if top {
                members.push(MemberSpan {
                    key: self.key_text(&k, escaped)?,
                    value: vstart..self.pos,
                    elements,
                    seqs,
                });
            }
            prev = Some((k, escaped));
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(members);
                }
                _ => return self.err("expected `,` or `}` (or not canonical)"),
            }
        }
    }
}

/// Checks that `bytes` are exactly the canonical form of `value`; returns the first byte
/// offset where they differ.
pub fn first_non_canonical_offset(bytes: &[u8], value: &Value) -> Option<usize> {
    let c = canonical(value);
    let c = c.as_bytes();
    if c == bytes {
        return None;
    }
    Some(
        c.iter()
            .zip(bytes)
            .position(|(a, b)| a != b)
            .unwrap_or(c.len().min(bytes.len())),
    )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn canonical_matches_jcs_for_the_value_subset() {
        let v = Obj::new()
            .field(
                "b",
                Value::Array(vec![Value::Int(1), Value::Null, Value::Bool(true)]),
            )
            .field(
                "a",
                Value::str("x\"\\\u{8}\u{c}\n\r\t\u{1f}\u{7f}é\u{2028}"),
            )
            .field("", Value::Object(BTreeMap::new()))
            .build();
        assert_eq!(
            canonical(&v),
            "{\"\":{},\"a\":\"x\\\"\\\\\\b\\f\\n\\r\\t\\u001f\u{7f}é\u{2028}\",\"b\":[1,null,true]}"
        );
    }

    #[test]
    fn keys_sort_by_utf16_not_utf8() {
        // U+1F600 sorts after U+FF61 in UTF-8 bytes (F0 > EF) but before it in UTF-16, where
        // it starts with the surrogate 0xD83D.
        let v = Obj::new()
            .field("\u{1f600}", Value::Int(1))
            .field("\u{ff61}", Value::Int(2))
            .build();
        assert_eq!(canonical(&v), "{\"\u{1f600}\":1,\"\u{ff61}\":2}");
    }

    #[test]
    fn unsafe_integers_become_strings() {
        assert_eq!(Value::int(MAX_SAFE_INTEGER), Value::Int(MAX_SAFE_INTEGER));
        assert_eq!(
            Value::int(MAX_SAFE_INTEGER + 1),
            Value::Str("9007199254740992".into())
        );
        assert_eq!(
            Value::count(u64::MAX),
            Value::Str("18446744073709551615".into())
        );
        assert_eq!(Value::u64_str(5), Value::Str("5".into()));
    }

    #[test]
    fn pretty_is_the_same_structure() {
        let v = Obj::new()
            .field("k", Value::Array(vec![Value::Int(1), Value::Array(vec![])]))
            .build();
        assert_eq!(pretty(&v), "{\n  \"k\": [\n    1,\n    []\n  ]\n}\n");
    }

    #[test]
    fn parse_round_trips_canonical_text_and_rejects_the_rest() {
        let text = r#"{"a":[1,-2,null,true,false],"b":{"c":"x\"\\\n\u001f\ud83d\ude00é"}}"#;
        let v = parse(text.as_bytes()).expect("valid");
        assert_eq!(canonical(&v), text.replace("\\ud83d\\ude00", "\u{1f600}"));
        let bad: &[(&str, usize)] = &[
            ("{\"a\":1.5}", 6),
            ("{\"a\":1e3}", 6),
            ("{\"a\":01}", 5),
            ("{\"a\":1,\"a\":2}", 7),
            ("[1,]", 3),
            ("\"\\ud800\"", 7),
            ("\"abc", 4),
            ("[] x", 3),
            ("9007199254740992", 0),
            ("-0", 0),
        ];
        for (b, at) in bad {
            let e = parse(b.as_bytes()).expect_err(b);
            assert_eq!(e.offset, *at, "{b}: {e}");
        }
        // At most 64 nested arrays and objects, whatever the innermost value is.
        for inner in ["", "1"] {
            let at = format!("{}{inner}{}", "[".repeat(MAX_DEPTH), "]".repeat(MAX_DEPTH));
            parse(at.as_bytes()).expect("64 containers");
            let over = format!(
                "{}{inner}{}",
                "[".repeat(MAX_DEPTH + 1),
                "]".repeat(MAX_DEPTH + 1)
            );
            let e = parse(over.as_bytes()).expect_err("65 containers");
            assert!(e.to_string().contains("64 levels"), "{e}");
            let at = format!(
                "{}{}",
                "{\"a\":[".repeat(MAX_DEPTH / 2),
                "]}".repeat(MAX_DEPTH / 2)
            );
            scan_canonical(at.as_bytes()).expect("64 containers");
            let over = format!(
                "{}{inner}{}",
                "{\"a\":[".repeat(MAX_DEPTH / 2).to_string() + "[",
                "]".to_string() + &"]}".repeat(MAX_DEPTH / 2)
            );
            let e = scan_canonical(over.as_bytes()).expect_err("65 containers");
            assert!(e.to_string().contains("64 levels"), "{e}");
        }
        let deep = "[".repeat(MAX_DEPTH + 2);
        let e = parse(deep.as_bytes()).expect_err("too deep");
        assert!(
            e.to_string()
                .contains("JSON nesting exceeds the input limit of 64 levels"),
            "{e}"
        );
        let deep_object = "{\"a\":".repeat(MAX_DEPTH + 2);
        let e = scan_canonical(deep_object.as_bytes()).expect_err("too deep");
        assert!(
            e.to_string()
                .contains("exceeds the input limit of 64 levels"),
            "{e}"
        );
        assert_eq!(
            first_non_canonical_offset(b"{ }", &Value::Object(BTreeMap::new())),
            Some(1)
        );
        assert_eq!(
            first_non_canonical_offset(b"{}", &Value::Object(BTreeMap::new())),
            None
        );
        assert_eq!(
            first_non_canonical_offset(b"\"\\/\"", &Value::str("/")),
            Some(1)
        );
    }

    #[test]
    fn scan_accepts_exactly_the_canonical_form() {
        let v = Obj::new()
            .field(
                "b",
                Value::Array(vec![
                    Value::Int(1),
                    Value::str("x\u{1}\n\u{1f600}"),
                    Value::Null,
                ]),
            )
            .field(
                "a",
                Obj::new()
                    .field("z", Value::Bool(true))
                    .field("\u{1f600}", Value::Int(-5))
                    .field("\u{ff61}", Value::Int(0))
                    .build(),
            )
            .build();
        let text = canonical(&v);
        let spans = scan_canonical(text.as_bytes()).expect("canonical");
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[1].key, "b");
        assert_eq!(spans[1].elements.len(), 3);
        for (span, item) in spans[1].elements.iter().zip(match v {
            Value::Object(ref m) => match m.get("b") {
                Some(Value::Array(a)) => a.clone(),
                _ => vec![],
            },
            _ => vec![],
        }) {
            assert_eq!(&text.as_bytes()[span.clone()], canonical(&item).as_bytes());
        }
        // Every non-canonical spelling of the same value is refused.
        for bad in [
            r#"{"a":1,"a":2}"#,
            r#"{"b":1,"a":2}"#,
            r#"{ "a":1}"#,
            r#"{"a":1.0}"#,
            r#"{"a":01}"#,
            r#"{"a":-0}"#,
            r#"{"a":"\/"}"#,
            r#"{"a":"\u0041"}"#,
            r#"{"a":"\u000A"}"#,
            r#"{"a":"\u000a"}"#,
            r#"{"a":"\u001F"}"#,
            r#"{"a":[1 ,2]}"#,
            r#"{"a":1}"#.trim_end_matches('}'),
            "[1]",
        ] {
            assert!(scan_canonical(bad.as_bytes()).is_err(), "{bad}");
        }
        assert!(scan_canonical(br#"{"a":"\u001f\n"}"#).is_ok());
        // UTF-16 order: U+1F600 sorts before U+FF61.
        assert!(scan_canonical("{\"\u{ff61}\":1,\"\u{1f600}\":2}".as_bytes()).is_err());
    }
}
