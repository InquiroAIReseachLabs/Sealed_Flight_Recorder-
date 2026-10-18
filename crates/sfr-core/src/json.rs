//! JSON values and their deterministic text forms (SPEC B1.7, DIAGNOSTIC item 8).
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

fn write_string(out: &mut String, s: &str) {
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
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write_canonical(out: &mut String, v: &Value) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Int(n) => {
            let _ = write!(out, "{n}");
        }
        Value::Str(s) => write_string(out, s),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(out, item);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            for (i, (k, item)) in sorted_utf16(map).into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(out, k);
                out.push(':');
                write_canonical(out, item);
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
                write_string(out, k);
                out.push_str(": ");
                write_pretty(out, item, depth + 1);
            }
            indent(out, depth);
            out.push('}');
        }
        other => write_canonical(out, other),
    }
}

/// RFC 8785 canonical text of `v`.
pub fn canonical(v: &Value) -> String {
    let mut out = String::new();
    write_canonical(&mut out, v);
    out
}

/// Indented text of `v` with the same key order as [`canonical`], ending in a newline.
pub fn pretty(v: &Value) -> String {
    let mut out = String::new();
    write_pretty(&mut out, v, 0);
    out.push('\n');
    out
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
}
