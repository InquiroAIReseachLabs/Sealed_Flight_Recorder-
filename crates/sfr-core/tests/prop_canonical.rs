//! Property tests of the canonical JSON writer and reader (SPEC B1.7; `docs/RECORD_FORMAT.md`,
//! "Canonical JSON"; `crates/sfr-core/src/json.rs`). `canonical.rs` holds the RFC 8785 examples;
//! this file holds what must be true for every value and for damaged text:
//!
//! - the writer's text is the documented spelling (an independent reference writer in this file
//!   spells strings and sorts keys by UTF-16 code units on its own), and the reader gives the
//!   value back;
//! - bytes the reader accepts are canonical exactly when they equal the writer's text, and the
//!   one-pass scanner (`scan_canonical`) accepts exactly the canonical objects, with member spans
//!   that lie inside the input, in order, and hold each value's own canonical text;
//! - every local damage to a canonical document is either refused, or read as the same value and
//!   then reported as not canonical, as the record format says;
//! - key order does not depend on insertion order, and nesting stops at `MAX_DEPTH` without a
//!   stack overflow;
//! - the integer helpers on `Value`, the object builder and `pretty` round-trip.
//!
//! The default run is deterministic and cheap (a fixed seed, 64 cases per property). A deep run:
//! `PROPTEST_CASES=100000 PROPTEST_RNG_SEED=1 cargo test -p sfr-core --test prop_canonical`.
// A panicking test is a failing test, so tests may use expect, unwrap and panic.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::ops::Range;

use proptest::prelude::*;
use proptest::test_runner::RngSeed;
use sfr_core::display::is_hidden;
use sfr_core::json::{
    MAX_DEPTH, MAX_SAFE_INTEGER, MemberSpan, Obj, Value, canonical, first_non_canonical_offset,
    parse, pretty, scan_canonical,
};

/// The seed of a default run: any constant makes the run repeat exactly.
const SEED: u64 = 0x5f72_6563_6f72_6465;

/// The configuration of every property: `ProptestConfig::default()` reads `PROPTEST_CASES` and
/// `PROPTEST_RNG_SEED`; when they are unset the run uses a fixed seed and 64 cases. No failure
/// file is written next to the sources: the fixed seed already repeats a failure.
fn config() -> ProptestConfig {
    let mut config = ProptestConfig::default();
    if std::env::var_os("PROPTEST_RNG_SEED").is_none() {
        config.rng_seed = RngSeed::Fixed(SEED);
    }
    if std::env::var_os("PROPTEST_CASES").is_none() {
        config.cases = 64;
    }
    config.failure_persistence = None;
    config
}

fn fail<T>(message: String) -> Result<T, TestCaseError> {
    Err(TestCaseError::fail(message))
}

// ---------------------------------------------------------------------------------------------
// The reference: the documented spelling, written without json.rs.
// ---------------------------------------------------------------------------------------------

/// A string as `docs/RECORD_FORMAT.md` ("Strings") spells it: `"` and `\` escaped, U+0008, U+0009,
/// U+000A, U+000C and U+000D as `\b \t \n \f \r`, every other code point below U+0020 as `\u` and
/// four lowercase hex digits, everything else as itself.
fn ref_string(s: &str) -> String {
    let mut out = String::from('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The members of an object in the documented order: keys compared as sequences of UTF-16 code
/// units ("Objects" in `docs/RECORD_FORMAT.md`, RFC 8785 section 3.2.3).
fn ref_sorted(map: &BTreeMap<String, Value>) -> Vec<(&String, &Value)> {
    let mut entries: Vec<(&String, &Value)> = map.iter().collect();
    entries.sort_by_key(|(key, _)| key.encode_utf16().collect::<Vec<u16>>());
    entries
}

/// One member of an object in the reference text: the bytes of `"key":value` and of the key.
struct Member {
    whole: Range<usize>,
    key: Range<usize>,
}

/// Where the tokens of the reference text are, so that damage can be placed on token structure.
#[derive(Default)]
struct Sites {
    /// Every offset between two tokens (outside strings), where whitespace may be written.
    boundaries: Vec<usize>,
    /// Every string literal, quotes included (keys too).
    strings: Vec<Range<usize>>,
    /// Every integer.
    ints: Vec<Range<usize>>,
    /// The members of every object that has any.
    objects: Vec<Vec<Member>>,
}

fn put_token(out: &mut String, sites: &mut Sites, token: &str) -> Range<usize> {
    let start = out.len();
    out.push_str(token);
    sites.boundaries.push(start);
    sites.boundaries.push(out.len());
    start..out.len()
}

fn put(out: &mut String, sites: &mut Sites, v: &Value) {
    match v {
        Value::Null => {
            put_token(out, sites, "null");
        }
        Value::Bool(b) => {
            put_token(out, sites, if *b { "true" } else { "false" });
        }
        Value::Int(n) => {
            let at = put_token(out, sites, &n.to_string());
            sites.ints.push(at);
        }
        Value::Str(s) => {
            let at = put_token(out, sites, &ref_string(s));
            sites.strings.push(at);
        }
        Value::Array(items) => {
            put_token(out, sites, "[");
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    put_token(out, sites, ",");
                }
                put(out, sites, item);
            }
            put_token(out, sites, "]");
        }
        Value::Object(map) => {
            put_token(out, sites, "{");
            let mut members = Vec::new();
            for (i, (key, item)) in ref_sorted(map).into_iter().enumerate() {
                if i > 0 {
                    put_token(out, sites, ",");
                }
                let start = out.len();
                let key_at = put_token(out, sites, &ref_string(key));
                sites.strings.push(key_at.clone());
                put_token(out, sites, ":");
                put(out, sites, item);
                members.push(Member {
                    whole: start..out.len(),
                    key: key_at,
                });
            }
            put_token(out, sites, "}");
            if !members.is_empty() {
                sites.objects.push(members);
            }
        }
    }
}

/// The reference text of `v` and the places in it.
fn render(v: &Value) -> (String, Sites) {
    let mut out = String::new();
    let mut sites = Sites::default();
    put(&mut out, &mut sites, v);
    (out, sites)
}

fn ref_canonical(v: &Value) -> String {
    render(v).0
}

/// The deepest chain of arrays and objects in `v`.
fn nesting(v: &Value) -> usize {
    match v {
        Value::Array(items) => 1 + items.iter().map(nesting).max().unwrap_or(0),
        Value::Object(map) => 1 + map.values().map(nesting).max().unwrap_or(0),
        _ => 0,
    }
}

/// The length of the common prefix of two byte strings, which is the first offset where they
/// differ when they differ.
fn common_prefix(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b).take_while(|(x, y)| x == y).count()
}

fn show(bytes: &[u8]) -> String {
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("{:?} (hex {hex})", String::from_utf8_lossy(bytes))
}

// ---------------------------------------------------------------------------------------------
// Generators.
// ---------------------------------------------------------------------------------------------

/// Characters that matter: controls, NUL, quote, backslash, slash, DEL and the C1 range, the
/// line and paragraph separators, format characters, the characters at the edges of the surrogate
/// range and of the basic multilingual plane, the replacement character and characters outside
/// the plane.
const SPECIAL_CHARS: [char; 28] = [
    '"',
    '\\',
    '/',
    '\u{0}',
    '\u{8}',
    '\u{c}',
    '\u{7f}',
    '\u{80}',
    '\u{9f}',
    '\u{a0}',
    '\u{ad}',
    '\u{7ff}',
    '\u{800}',
    '\u{d7ff}',
    '\u{e000}',
    '\u{2028}',
    '\u{2029}',
    '\u{202e}',
    '\u{200b}',
    '\u{feff}',
    '\u{ff61}',
    '\u{fb33}',
    '\u{fffd}',
    '\u{ffff}',
    '\u{10000}',
    '\u{1f600}',
    '\u{e0001}',
    '\u{10ffff}',
];

/// Characters for keys: few of them, so that keys share prefixes, and several from the range
/// where UTF-16 order and UTF-8 order differ (U+E000 to U+FFFF against characters above U+FFFF).
const KEY_CHARS: [char; 15] = [
    'a',
    'b',
    'c',
    'A',
    '\n',
    '\u{80}',
    '\u{7ff}',
    '\u{800}',
    '\u{d7ff}',
    '\u{e000}',
    '\u{ff61}',
    '\u{ffff}',
    '\u{10000}',
    '\u{1f600}',
    '\u{10ffff}',
];

/// Characters whose order differs between UTF-8 and UTF-16: the last four of the basic
/// multilingual plane (UTF-16 puts them after) and three above it (UTF-16 puts them before).
const ASTRAL_CHARS: [char; 9] = [
    'a',
    '\u{d7ff}',
    '\u{e000}',
    '\u{fb33}',
    '\u{ff61}',
    '\u{ffff}',
    '\u{10000}',
    '\u{1f600}',
    '\u{10ffff}',
];

fn json_char() -> BoxedStrategy<char> {
    prop_oneof![
        6 => (0x20u8..0x7f).prop_map(char::from),
        3 => (0u8..0x20).prop_map(char::from),
        6 => prop::sample::select(SPECIAL_CHARS.to_vec()),
        2 => any::<char>(),
    ]
    .boxed()
}

fn json_string() -> BoxedStrategy<String> {
    prop::collection::vec(json_char(), 0..=10)
        .prop_map(|chars| chars.into_iter().collect())
        .boxed()
}

fn json_key() -> BoxedStrategy<String> {
    prop_oneof![
        2 => prop::sample::select(vec!["", "a", "b", "seq", "z", "zz", "t"]).prop_map(String::from),
        5 => prop::collection::vec(prop::sample::select(KEY_CHARS.to_vec()), 0..=3)
            .prop_map(|chars| chars.into_iter().collect::<String>()),
        2 => json_string(),
    ]
    .boxed()
}

/// An integer of the record's range, with the edges of the range and of 32 bits over-weighted.
fn json_int() -> BoxedStrategy<i64> {
    prop_oneof![
        4 => -20i64..=20,
        2 => -MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER,
        2 => prop::sample::select(vec![
            MAX_SAFE_INTEGER,
            -MAX_SAFE_INTEGER,
            MAX_SAFE_INTEGER - 1,
            1 << 31,
            -(1 << 31),
            (1 << 32) - 1,
            1 << 32,
            255,
            256,
            65_535,
            65_536,
            99,
            100,
            999,
            1000,
        ]),
    ]
    .boxed()
}

fn leaf() -> BoxedStrategy<Value> {
    prop_oneof![
        1 => Just(Value::Null),
        2 => any::<bool>().prop_map(Value::Bool),
        3 => json_int().prop_map(Value::Int),
        4 => json_string().prop_map(Value::Str),
    ]
    .boxed()
}

/// A value of the record's types with at most `depth` levels of arrays and objects.
fn value_of_depth(depth: u32) -> BoxedStrategy<Value> {
    if depth == 0 {
        return leaf();
    }
    let inner = value_of_depth(depth - 1);
    prop_oneof![
        2 => leaf(),
        2 => prop::collection::vec(inner.clone(), 0..=3).prop_map(Value::Array),
        2 => prop::collection::btree_map(json_key(), inner, 0..=3).prop_map(Value::Object),
    ]
    .boxed()
}

/// An arbitrary value of the record's types, nested up to six levels.
fn value() -> BoxedStrategy<Value> {
    value_of_depth(6)
}

/// An object, which is what a record is, with arbitrary values in it.
fn object() -> BoxedStrategy<Value> {
    prop::collection::btree_map(json_key(), value(), 0..=5)
        .prop_map(Value::Object)
        .boxed()
}

/// A value to damage: mostly objects.
fn document() -> BoxedStrategy<Value> {
    prop_oneof![5 => object(), 2 => value()].boxed()
}

/// An event-like object: usually a `seq` member, and other members that may hold arrays.
fn event() -> BoxedStrategy<Value> {
    (
        prop::option::weighted(0.8, 0i64..1000),
        prop::collection::btree_map(json_key(), value(), 0..=3),
    )
        .prop_map(|(seq, mut members)| {
            if let Some(n) = seq {
                members.insert("seq".to_string(), Value::Int(n));
            }
            Value::Object(members)
        })
        .boxed()
}

/// A record-like object whose members include arrays of events.
fn events_document() -> BoxedStrategy<Value> {
    let member = prop_oneof![
        3 => prop::collection::vec(event(), 0..=4).prop_map(Value::Array),
        1 => value(),
    ];
    prop::collection::btree_map(
        prop_oneof![1 => Just("events".to_string()), 1 => json_key()],
        member,
        1..=3,
    )
    .prop_map(Value::Object)
    .boxed()
}

// ---------------------------------------------------------------------------------------------
// The oracle that holds for any bytes.
// ---------------------------------------------------------------------------------------------

fn check_error(bytes: &[u8], e: &sfr_core::json::ParseError) -> Result<(), TestCaseError> {
    prop_assert!(
        e.offset <= bytes.len(),
        "error offset {} past the end of {} bytes: {}",
        e.offset,
        bytes.len(),
        e
    );
    prop_assert!(
        e.to_string()
            .starts_with(&format!("byte offset {}: ", e.offset)),
        "{e}"
    );
    Ok(())
}

/// The member spans of `scan_canonical` against the parsed object (`json.rs`, `MemberSpan` and
/// `scan_canonical`): each value's bytes are its canonical text, spans are inside the input and
/// in order without overlap, and each array's elements tile the array. `seq_complete` also demands
/// a `seq` span for every element that has a `seq` member; the spans given must always be right.
fn check_spans(
    bytes: &[u8],
    map: &BTreeMap<String, Value>,
    spans: &[MemberSpan],
    seq_complete: bool,
) -> Result<(), TestCaseError> {
    let expected = ref_sorted(map);
    prop_assert_eq!(spans.len(), expected.len(), "member count");
    let slice = |r: &Range<usize>| bytes.get(r.clone());
    let mut floor = 0usize;
    for (span, (key, value)) in spans.iter().zip(&expected) {
        prop_assert_eq!(&span.key, *key);
        prop_assert!(
            floor < span.value.start
                && span.value.start < span.value.end
                && span.value.end <= bytes.len(),
            "member `{}`: span {:?} is not inside the input after {}",
            key,
            span.value,
            floor
        );
        let want = ref_canonical(value);
        prop_assert_eq!(
            slice(&span.value),
            Some(want.as_bytes()),
            "member `{}`",
            key
        );
        floor = span.value.end;
        match value {
            Value::Array(items) => {
                prop_assert_eq!(span.elements.len(), items.len(), "member `{}`", key);
                prop_assert_eq!(span.seqs.len(), items.len(), "member `{}`", key);
                // `[`, then the elements separated by one comma each, then `]`.
                let mut at = span.value.start + 1;
                for (i, (element, item)) in span.elements.iter().zip(items).enumerate() {
                    prop_assert_eq!(element.start, at, "element {} of `{}`", i, key);
                    let want = ref_canonical(item);
                    prop_assert_eq!(
                        slice(element),
                        Some(want.as_bytes()),
                        "element {} of `{}`",
                        i,
                        key
                    );
                    at = element.end + 1;
                    match (&span.seqs[i], item) {
                        (Some(seq), Value::Object(members)) => {
                            let Some(member) = members.get("seq") else {
                                return fail(format!(
                                    "element {i} of `{key}` has no seq member but a seq span"
                                ));
                            };
                            prop_assert!(
                                element.start <= seq.start && seq.end <= element.end,
                                "seq span {:?} outside element {:?}",
                                seq,
                                element
                            );
                            let want = ref_canonical(member);
                            prop_assert_eq!(
                                slice(seq),
                                Some(want.as_bytes()),
                                "seq of element {} of `{}`",
                                i,
                                key
                            );
                        }
                        (Some(seq), _) => {
                            return fail(format!(
                                "element {i} of `{key}` is not an object but has seq span {seq:?}"
                            ));
                        }
                        (None, Value::Object(members))
                            if seq_complete && members.contains_key("seq") =>
                        {
                            return fail(format!(
                                "element {i} of `{key}` has a seq member but no seq span"
                            ));
                        }
                        (None, _) => {}
                    }
                }
                if items.is_empty() {
                    prop_assert_eq!(span.value.len(), 2, "empty array `{}`", key);
                } else {
                    prop_assert_eq!(at, span.value.end, "array `{}` ends with `]`", key);
                }
            }
            _ => {
                prop_assert!(
                    span.elements.is_empty() && span.seqs.is_empty(),
                    "`{}`",
                    key
                );
            }
        }
    }
    // The closing brace follows the last member.
    if spans.is_empty() {
        prop_assert_eq!(bytes, b"{}");
    } else {
        prop_assert_eq!(floor + 1, bytes.len());
    }
    Ok(())
}

/// What must hold for any bytes, whatever they are (the identity-or-refusal rule):
///
/// - `parse` and `scan_canonical` return, never panic, and report error offsets inside the input;
/// - when `parse` accepts the bytes as `v`: the bytes are valid UTF-8 and nest at most `MAX_DEPTH`
///   deep, the canonical text of `v` reads back as `v`, and `first_non_canonical_offset` is `None`
///   exactly when the bytes are that text, and otherwise the first offset where they differ;
/// - `scan_canonical` accepts exactly the bytes that are the canonical text of an object, and its
///   spans are then right.
fn check_reader(bytes: &[u8]) -> Result<(), TestCaseError> {
    let parsed = parse(bytes);
    let scanned = scan_canonical(bytes);
    match &parsed {
        Ok(v) => {
            let text = ref_canonical(v);
            prop_assert_eq!(
                canonical(v),
                text.clone(),
                "writer differs from the reference"
            );
            let same = text.as_bytes() == bytes;
            let offset = first_non_canonical_offset(bytes, v);
            prop_assert_eq!(offset.is_none(), same, "{}", show(bytes));
            if !same {
                prop_assert_eq!(offset, Some(common_prefix(text.as_bytes(), bytes)));
            }
            prop_assert!(
                std::str::from_utf8(bytes).is_ok(),
                "accepted bytes are not UTF-8"
            );
            prop_assert!(nesting(v) <= MAX_DEPTH, "nesting {} accepted", nesting(v));
            prop_assert_eq!(parse(text.as_bytes()), Ok(v.clone()));
            prop_assert_eq!(first_non_canonical_offset(text.as_bytes(), v), None);
        }
        Err(e) => check_error(bytes, e)?,
    }
    match &scanned {
        Ok(spans) => {
            let Ok(Value::Object(map)) = &parsed else {
                return fail(format!(
                    "scan accepted bytes that do not parse as an object: {}",
                    show(bytes)
                ));
            };
            let text = ref_canonical(&Value::Object(map.clone()));
            prop_assert_eq!(
                text.as_bytes(),
                bytes,
                "scan accepted bytes that are not canonical"
            );
            check_spans(bytes, map, spans, false)?;
        }
        Err(e) => {
            check_error(bytes, e)?;
            if let Ok(v @ Value::Object(_)) = &parsed {
                prop_assert!(
                    ref_canonical(v).as_bytes() != bytes,
                    "scan refused a canonical object: {e}"
                );
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Damage.
// ---------------------------------------------------------------------------------------------

/// What a damage must do to the reading of the document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    /// The damage changed nothing: the bytes are the canonical text again.
    Canonical,
    /// The bytes spell the same value in a non-canonical way: `parse` gives the value back,
    /// `scan_canonical` refuses, and the first difference from the canonical text is reported.
    SameValue,
    /// The bytes are not in the record's subset: `parse` and `scan_canonical` both refuse.
    Refused,
    /// Anything the identity-or-refusal rule allows.
    Unknown,
}

/// A local damage: a kind and three numbers that choose where and how.
#[derive(Debug, Clone, Copy)]
struct Damage {
    kind: u8,
    a: u32,
    b: u32,
    c: u32,
}

struct Damaged {
    bytes: Vec<u8>,
    expect: Expect,
    /// No error offset may be before this (the damage starts here). Zero: no claim.
    not_before: usize,
    what: String,
}

/// Kinds 0 to 12 are damages with a known outcome; the rest are byte edits.
const DAMAGE_KINDS: u8 = 18;

fn damage() -> impl Strategy<Value = Damage> {
    (0..DAMAGE_KINDS, any::<u32>(), any::<u32>(), any::<u32>()).prop_map(|(kind, a, b, c)| Damage {
        kind,
        a,
        b,
        c,
    })
}

fn small(n: u32, modulus: usize) -> usize {
    usize::try_from(n).unwrap_or(0) % modulus.max(1)
}

fn pick<T>(items: &[T], n: u32) -> Option<&T> {
    if items.is_empty() {
        None
    } else {
        items.get(small(n, items.len()))
    }
}

fn splice(bytes: &[u8], at: Range<usize>, with: &[u8]) -> Vec<u8> {
    let mut out = bytes.get(..at.start).unwrap_or(&[]).to_vec();
    out.extend_from_slice(with);
    out.extend_from_slice(bytes.get(at.end..).unwrap_or(&[]));
    out
}

/// The units of a canonical string literal (quotes included): each escape sequence and each
/// character, as its byte range and its code point.
fn units(text: &str, literal: &Range<usize>) -> Vec<(Range<usize>, u32)> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = literal.start + 1;
    while i < literal.end - 1 {
        if bytes[i] == b'\\' {
            let (len, cp) = match bytes[i + 1] {
                b'"' => (2, 0x22),
                b'\\' => (2, 0x5c),
                b'b' => (2, 0x08),
                b'f' => (2, 0x0c),
                b'n' => (2, 0x0a),
                b'r' => (2, 0x0d),
                b't' => (2, 0x09),
                b'u' => (6, u32::from_str_radix(&text[i + 2..i + 6], 16).unwrap()),
                other => panic!("canonical text holds no escape \\{}", char::from(other)),
            };
            out.push((i..i + len, cp));
            i += len;
        } else {
            let c = text[i..].chars().next().unwrap();
            out.push((i..i + c.len_utf8(), u32::from(c)));
            i += c.len_utf8();
        }
    }
    out
}

/// Offsets inside a string literal where a unit may be inserted: after the opening quote and
/// after each unit.
fn unit_boundaries(text: &str, literal: &Range<usize>) -> Vec<usize> {
    let mut at = vec![literal.start + 1];
    at.extend(units(text, literal).into_iter().map(|(range, _)| range.end));
    at
}

fn damaged(bytes: Vec<u8>, expect: Expect, not_before: usize, what: String) -> Option<Damaged> {
    Some(Damaged {
        bytes,
        expect,
        not_before,
        what,
    })
}

/// Whitespace of the four kinds the reader allows, written between two tokens.
fn extra_whitespace(text: &str, sites: &Sites, d: Damage) -> Option<Damaged> {
    let at = *pick(&sites.boundaries, d.a)?;
    let ws = *b" \t\n\r";
    let inserted: Vec<u8> = (0..(d.b % 3) + 1)
        .map(|i| ws[small(d.c >> (2 * i), ws.len())])
        .collect();
    damaged(
        splice(text.as_bytes(), at..at, &inserted),
        Expect::SameValue,
        at,
        format!("whitespace {inserted:?} inserted at {at}"),
    )
}

/// A comma between two tokens, which no JSON grammar allows.
fn stray_comma(text: &str, sites: &Sites, d: Damage) -> Option<Damaged> {
    let at = *pick(&sites.boundaries, d.a)?;
    damaged(
        splice(text.as_bytes(), at..at, b","),
        Expect::Refused,
        at,
        format!("comma inserted at {at}"),
    )
}

/// A character or escape written in another way that spells the same character: `\u0041` for
/// `A`, `\u002F` or `\/` for `/`, uppercase hex digits, a surrogate pair for a character outside
/// the plane, `\u000a` for `\n`.
fn changed_escape(text: &str, sites: &Sites, d: Damage) -> Option<Damaged> {
    let literal = pick(&sites.strings, d.a)?;
    let all = units(text, literal);
    let (range, cp) = pick(&all, d.b)?.clone();
    let c = char::from_u32(cp)?;
    let spelled = if c == '/' && d.c & 2 != 0 {
        "\\/".to_string()
    } else {
        let mut s = String::new();
        for unit in c.encode_utf16(&mut [0u16; 2]).iter() {
            if d.c & 1 == 1 {
                let _ = write!(s, "\\u{unit:04X}");
            } else {
                let _ = write!(s, "\\u{unit:04x}");
            }
        }
        s
    };
    damaged(
        splice(text.as_bytes(), range.clone(), spelled.as_bytes()),
        Expect::SameValue,
        range.start,
        format!("{c:?} at {range:?} spelled {spelled}"),
    )
}

/// A member moved to another place in its object, which changes the order but not the value.
fn reordered_key(text: &str, sites: &Sites, d: Damage) -> Option<Damaged> {
    let many: Vec<&Vec<Member>> = sites.objects.iter().filter(|o| o.len() >= 2).collect();
    let members = *pick(&many, d.a)?;
    let n = members.len();
    let from = small(d.b, n);
    let mut to = small(d.c, n);
    if to == from {
        to = (from + 1) % n;
    }
    let mut order: Vec<usize> = (0..n).collect();
    let moved = order.remove(from);
    order.insert(to, moved);
    let bytes = text.as_bytes();
    let whole = members[0].whole.start..members[n - 1].whole.end;
    let mut body = Vec::new();
    for (i, &m) in order.iter().enumerate() {
        if i > 0 {
            body.push(b',');
        }
        body.extend_from_slice(bytes.get(members[m].whole.clone())?);
    }
    damaged(
        splice(bytes, whole, &body),
        Expect::SameValue,
        members[from.min(to)].whole.start,
        format!("member {from} moved to place {to} of {n}"),
    )
}

/// A key written twice in one object.
fn duplicated_key(text: &str, sites: &Sites, d: Damage) -> Option<Damaged> {
    let members = pick(&sites.objects, d.a)?;
    let bytes = text.as_bytes();
    let n = members.len();
    if n >= 2 && d.b & 1 == 0 {
        // The key of one member is replaced by the key of the member before it.
        let i = small(d.c, n - 1);
        let key = bytes.get(members[i].key.clone())?;
        let target = members[i + 1].key.clone();
        let at = target.start;
        damaged(
            splice(bytes, target, key),
            Expect::Refused,
            at,
            format!("key of member {} replaced by the key of member {i}", i + 1),
        )
    } else {
        // A whole member is written a second time right after itself.
        let i = small(d.c, n);
        let end = members[i].whole.end;
        let mut copy = vec![b','];
        copy.extend_from_slice(bytes.get(members[i].whole.clone())?);
        damaged(
            splice(bytes, end..end, &copy),
            Expect::Refused,
            end,
            format!("member {i} written twice"),
        )
    }
}

/// An integer that is not in the record's subset: a leading zero, `-0`, a fraction, an exponent,
/// or a magnitude above 2^53 - 1.
fn bad_integer(text: &str, sites: &Sites, d: Damage) -> Option<Damaged> {
    let at = pick(&sites.ints, d.a)?.clone();
    let digits = text.get(at.clone())?;
    let (sign, magnitude) = digits
        .strip_prefix('-')
        .map_or(("", digits), |rest| ("-", rest));
    let (new, what) = match d.b % 6 {
        0 => (format!("{sign}0{magnitude}"), "leading zero"),
        1 => (format!("{digits}.0"), "fraction"),
        2 => (format!("{digits}e2"), "exponent"),
        3 => (format!("{sign}9007199254740992"), "2^53"),
        4 => ("-0".to_string(), "minus zero"),
        _ => (format!("{sign}1{}", "0".repeat(40)), "forty digits"),
    };
    damaged(
        splice(text.as_bytes(), at.clone(), new.as_bytes()),
        Expect::Refused,
        at.start,
        format!("integer {digits} replaced by {new} ({what})"),
    )
}

/// An escape of a surrogate that has no partner, in a string.
fn lone_surrogate(text: &str, sites: &Sites, d: Damage) -> Option<Damaged> {
    let literal = pick(&sites.strings, d.a)?;
    let at = *pick(&unit_boundaries(text, literal), d.b)?;
    let escapes = [
        "\\ud800", "\\udbff", "\\udc00", "\\udfff", "\\uD800", "\\uDBFF", "\\uDC00", "\\uDFFF",
    ];
    let lone = escapes[small(d.c, escapes.len())];
    // What follows must not complete a pair: a character, a escape of another kind, or a second
    // high surrogate.
    let after = ["", "\\u0041", "x", "\\n", "\\ud800"][small(d.c >> 8, 5)];
    let new = format!("{lone}{after}");
    damaged(
        splice(text.as_bytes(), at..at, new.as_bytes()),
        Expect::Refused,
        at,
        format!("{new} inserted at {at}"),
    )
}

/// A control character written as itself in a string.
fn raw_control(text: &str, sites: &Sites, d: Damage) -> Option<Damaged> {
    let literal = pick(&sites.strings, d.a)?;
    let at = *pick(&unit_boundaries(text, literal), d.b)?;
    let byte = u8::try_from(d.c % 0x20).unwrap_or(0);
    damaged(
        splice(text.as_bytes(), at..at, &[byte]),
        Expect::Refused,
        at,
        format!("raw byte {byte:#04x} inserted at {at}"),
    )
}

/// Bytes that are not UTF-8: in a string, or between two tokens.
fn invalid_utf8(text: &str, sites: &Sites, d: Damage) -> Option<Damaged> {
    const BAD: [&[u8]; 8] = [
        &[0x80],
        &[0xc0, 0x80],
        &[0xc1, 0xbf],
        &[0xe2, 0x82],
        &[0xed, 0xa0, 0x80],
        &[0xf4, 0x90, 0x80, 0x80],
        &[0xff],
        &[0xf0, 0x9f, 0x98],
    ];
    let at = if d.a.is_multiple_of(4) {
        *pick(&sites.boundaries, d.b)?
    } else {
        let literal = pick(&sites.strings, d.b)?;
        *pick(&unit_boundaries(text, literal), d.c)?
    };
    let bad = BAD[small(d.c >> 8, BAD.len())];
    damaged(
        splice(text.as_bytes(), at..at, bad),
        Expect::Refused,
        at,
        format!("bytes {bad:02x?} inserted at {at}"),
    )
}

/// A space that JSON does not have (the reader's whitespace is space, tab, line feed and
/// carriage return, `Parser::ws`), between two tokens.
fn other_whitespace(text: &str, sites: &Sites, d: Damage) -> Option<Damaged> {
    let spaces = [
        "\u{a0}", "\u{2003}", "\u{feff}", "\u{3000}", "\u{b}", "\u{c}", "\u{85}", "\u{1c}",
    ];
    let at = *pick(&sites.boundaries, d.a)?;
    let new = spaces[small(d.b, spaces.len())];
    damaged(
        splice(text.as_bytes(), at..at, new.as_bytes()),
        Expect::Refused,
        at,
        format!("{new:?} inserted at {at}"),
    )
}

fn byte_order_mark(text: &str) -> Option<Damaged> {
    damaged(
        splice(text.as_bytes(), 0..0, &[0xef, 0xbb, 0xbf]),
        Expect::Refused,
        0,
        "byte order mark added".to_string(),
    )
}

/// A document cut short: an object or an array is never complete without its last byte.
fn truncated(v: &Value, text: &str, d: Damage) -> Option<Damaged> {
    if !matches!(v, Value::Array(_) | Value::Object(_)) {
        return None;
    }
    let len = small(d.a, text.len());
    damaged(
        text.as_bytes().get(..len)?.to_vec(),
        Expect::Refused,
        0,
        format!("cut to {len} bytes"),
    )
}

/// Text after the value: whitespace is read and not canonical; anything else is refused.
fn appended(text: &str, d: Damage) -> Option<Damaged> {
    let ws = ["\n", " ", "\t", "\r\n", " \n "];
    let junk = ["x", "}", "]", ",", ":", "\"", "{", "[", "\u{0}", "\u{a0}"];
    let (extra, expect) = if d.a.is_multiple_of(2) {
        (ws[small(d.b, ws.len())], Expect::SameValue)
    } else {
        (junk[small(d.b, junk.len())], Expect::Refused)
    };
    let mut bytes = text.as_bytes().to_vec();
    bytes.extend_from_slice(extra.as_bytes());
    damaged(bytes, expect, text.len(), format!("{extra:?} appended"))
}

/// A change of single bytes with no known outcome: a flipped byte, an inserted one, a deleted
/// one, two swapped, a stretch repeated.
fn byte_edit(bytes: &mut Vec<u8>, kind: u8, a: u32, b: u32, c: u32) -> String {
    const STRUCTURE: &[u8] = b"{}[]\",:\\ -0123456789tfnulea.\n\t";
    let len = bytes.len();
    match kind % 5 {
        0 if len > 0 => {
            let i = small(a, len);
            let mask = u8::try_from(b % 255 + 1).unwrap_or(1);
            bytes[i] ^= mask;
            format!("byte {i} xor {mask:#04x}")
        }
        1 => {
            let i = small(a, len + 1);
            let byte = if c & 1 == 0 {
                STRUCTURE[small(b, STRUCTURE.len())]
            } else {
                u8::try_from(b & 0xff).unwrap_or(0)
            };
            bytes.insert(i, byte);
            format!("byte {byte:#04x} inserted at {i}")
        }
        2 if len > 0 => {
            let i = small(a, len);
            let gone = bytes.remove(i);
            format!("byte {i} ({gone:#04x}) deleted")
        }
        3 if len > 1 => {
            let (i, j) = (small(a, len), small(b, len));
            bytes.swap(i, j);
            format!("bytes {i} and {j} swapped")
        }
        4 if len > 0 => {
            let from = small(a, len);
            let to = from + 1 + small(b, len - from);
            let chunk = bytes[from..to.min(len)].to_vec();
            let at = small(c, len + 1);
            bytes.splice(at..at, chunk);
            format!("bytes {from}..{to} repeated at {at}")
        }
        _ => "nothing".to_string(),
    }
}

/// The document `text` of `v` with the damage `d` applied.
fn apply(v: &Value, text: &str, sites: &Sites, d: Damage) -> Damaged {
    let semantic = match d.kind % DAMAGE_KINDS {
        0 => extra_whitespace(text, sites, d),
        1 => stray_comma(text, sites, d),
        2 => changed_escape(text, sites, d),
        3 => reordered_key(text, sites, d),
        4 => duplicated_key(text, sites, d),
        5 => bad_integer(text, sites, d),
        6 => lone_surrogate(text, sites, d),
        7 => raw_control(text, sites, d),
        8 => invalid_utf8(text, sites, d),
        9 => other_whitespace(text, sites, d),
        10 => byte_order_mark(text),
        11 => truncated(v, text, d),
        12 => appended(text, d),
        _ => None,
    };
    let mut out = semantic.unwrap_or_else(|| {
        let mut bytes = text.as_bytes().to_vec();
        let what = byte_edit(&mut bytes, d.kind, d.a, d.b, d.c);
        Damaged {
            bytes,
            expect: Expect::Unknown,
            not_before: 0,
            what,
        }
    });
    if out.bytes == text.as_bytes() {
        out.expect = Expect::Canonical;
    }
    out
}

// ---------------------------------------------------------------------------------------------
// Property 1: the round trip.
// ---------------------------------------------------------------------------------------------

proptest! {
    #![proptest_config(config())]

    /// Holds: for every value, `parse(canonical(v))` is `v`, the canonical text of the parse is
    /// the canonical text again, `first_non_canonical_offset` finds nothing in it, `canonical`
    /// is the documented spelling (the reference writer in this file), and the bytes pass every
    /// check of `check_reader` (the scanner accepts an object, with spans that are right).
    /// Source: SPEC B1.7 ("verify rejects any file that differs from the canonical form of its
    /// own parse") and `docs/RECORD_FORMAT.md`, "Canonical JSON".
    #[test]
    fn a_value_survives_canonical_text_and_back(v in value()) {
        let text = canonical(&v);
        prop_assert_eq!(&text, &ref_canonical(&v));
        let parsed = parse(text.as_bytes());
        prop_assert_eq!(&parsed, &Ok(v.clone()));
        let parsed = parsed.unwrap();
        prop_assert_eq!(canonical(&parsed), text.clone());
        prop_assert_eq!(first_non_canonical_offset(text.as_bytes(), &parsed), None);
        check_reader(text.as_bytes())?;
    }

    /// Holds: the same for an object, which is what a record is, including the scanner: it
    /// accepts the canonical text of every object and returns spans that are right.
    /// Source: `scan_canonical` ("exactly the RFC 8785 canonical form of the record's value
    /// subset") and SPEC B1.7.
    #[test]
    fn the_scanner_accepts_every_canonical_object_with_the_right_spans(v in object()) {
        let text = canonical(&v);
        let Value::Object(map) = &v else { unreachable!() };
        let spans = scan_canonical(text.as_bytes())
            .map_err(|e| TestCaseError::fail(format!("{e} in {}", show(text.as_bytes()))))?;
        check_spans(text.as_bytes(), map, &spans, false)?;
    }
}

// ---------------------------------------------------------------------------------------------
// Property 2: identity or refusal.
// ---------------------------------------------------------------------------------------------

/// A spelling of `v` that JSON allows and the canonical form does not: whitespace of the four
/// kinds between tokens, members in any order, every escape spelling (short escapes, `\u` with
/// either hex case, `\/`, a character written as an escape, a surrogate pair), all chosen from
/// `choices`.
fn loose(v: &Value, choices: &[u8]) -> String {
    struct Pen<'a> {
        choices: &'a [u8],
        at: usize,
        out: String,
    }
    impl Pen<'_> {
        fn next(&mut self) -> usize {
            let byte = self.choices.get(self.at % self.choices.len().max(1));
            self.at += 1;
            usize::from(byte.copied().unwrap_or(0))
        }
        fn space(&mut self) {
            match self.next() % 6 {
                3 => self.out.push(' '),
                4 => self.out.push_str("\t\n"),
                5 => self.out.push_str("\r\n  "),
                _ => {}
            }
        }
        fn token(&mut self, text: &str) {
            self.space();
            self.out.push_str(text);
        }
        fn string(&mut self, s: &str) {
            self.space();
            self.out.push('"');
            for c in s.chars() {
                let pick = self.next();
                let escaped = |c: char, upper: bool| {
                    let mut s = String::new();
                    for unit in c.encode_utf16(&mut [0u16; 2]).iter() {
                        let _ = if upper {
                            write!(s, "\\u{unit:04X}")
                        } else {
                            write!(s, "\\u{unit:04x}")
                        };
                    }
                    s
                };
                match c {
                    '"' if pick % 2 == 0 => self.out.push_str("\\\""),
                    '\\' if pick % 2 == 0 => self.out.push_str("\\\\"),
                    '/' if pick % 4 == 1 => self.out.push_str("\\/"),
                    '\u{8}' if pick % 2 == 0 => self.out.push_str("\\b"),
                    '\t' if pick % 2 == 0 => self.out.push_str("\\t"),
                    '\n' if pick % 2 == 0 => self.out.push_str("\\n"),
                    '\u{c}' if pick % 2 == 0 => self.out.push_str("\\f"),
                    '\r' if pick % 2 == 0 => self.out.push_str("\\r"),
                    '"' | '\\' | '/' | '\u{0}'..='\u{1f}' => {
                        let upper = pick % 3 == 0;
                        self.out.push_str(&escaped(c, upper));
                    }
                    _ if pick % 8 < 5 => self.out.push(c),
                    _ => {
                        let upper = pick % 2 == 0;
                        self.out.push_str(&escaped(c, upper));
                    }
                }
            }
            self.out.push('"');
        }
        fn value(&mut self, v: &Value) {
            match v {
                Value::Null => self.token("null"),
                Value::Bool(b) => self.token(if *b { "true" } else { "false" }),
                Value::Int(n) => self.token(&n.to_string()),
                Value::Str(s) => self.string(s),
                Value::Array(items) => {
                    self.token("[");
                    for (i, item) in items.iter().enumerate() {
                        if i > 0 {
                            self.token(",");
                        }
                        self.value(item);
                    }
                    self.token("]");
                }
                Value::Object(map) => {
                    self.token("{");
                    let mut members = ref_sorted(map);
                    let turn = self.next() % (members.len() + 1);
                    let len = members.len();
                    members.rotate_left(turn.min(len));
                    if self.next() % 3 == 0 {
                        members.reverse();
                    }
                    for (i, (key, item)) in members.into_iter().enumerate() {
                        if i > 0 {
                            self.token(",");
                        }
                        self.string(key);
                        self.token(":");
                        self.value(item);
                    }
                    self.token("}");
                }
            }
        }
    }
    let mut pen = Pen {
        choices,
        at: 0,
        out: String::new(),
    };
    pen.value(v);
    pen.space();
    pen.out
}

proptest! {
    #![proptest_config(config())]

    /// Holds: every spelling of a value that JSON allows is read as that value (whitespace of the
    /// four kinds anywhere between tokens, members in any order, any escape spelling); the text
    /// is reported as not canonical at the first byte where it differs from the canonical text, or
    /// is canonical when it is that text; and the scanner accepts it exactly when it is canonical.
    /// Source: `docs/RECORD_FORMAT.md` ("The file": `not in canonical form` is for whitespace,
    /// key order or escapes, so the reader reads them), `Parser::ws` and `Parser::string`.
    #[test]
    fn every_json_spelling_of_a_value_reads_back_and_is_judged_by_the_canonical_text(
        v in document(),
        choices in prop::collection::vec(any::<u8>(), 1..=64),
    ) {
        let text = loose(&v, &choices);
        let bytes = text.as_bytes();
        prop_assert_eq!(parse(bytes), Ok(v.clone()), "{}", show(bytes));
        let reference = ref_canonical(&v);
        if bytes == reference.as_bytes() {
            prop_assert_eq!(first_non_canonical_offset(bytes, &v), None);
        } else {
            prop_assert_eq!(
                first_non_canonical_offset(bytes, &v),
                Some(common_prefix(reference.as_bytes(), bytes))
            );
        }
        check_reader(bytes)?;
        let canonical_object =
            matches!(v, Value::Object(_)) && bytes == reference.as_bytes();
        prop_assert_eq!(scan_canonical(bytes).is_ok(), canonical_object, "{}", show(bytes));
    }

    /// Holds: a canonical document with one local damage (a changed escape, a moved or duplicated
    /// key, extra whitespace, a leading zero, a lone surrogate escape, a stray comma, a bad byte,
    /// a cut, a byte order mark, a flipped, inserted, deleted or swapped byte) is handled as the
    /// record format says: documents outside the subset are refused by `parse` and by
    /// `scan_canonical` with an offset that is not before the damage; documents that spell the
    /// same value are read as it, refused by the scanner, and reported at the first difference;
    /// and for every outcome `check_reader` (identity or refusal) holds.
    /// Source: `docs/RECORD_FORMAT.md` ("The file", "Canonical JSON": a float, `-0`, a leading
    /// zero, an out-of-range integer, a duplicate key, an unpaired surrogate, bytes that are not
    /// UTF-8, no byte order mark, no whitespace), `json.rs` `Parser::ws` for the whitespace.
    #[test]
    fn a_damaged_canonical_document_is_refused_or_judged_not_canonical(
        v in document(),
        d in damage(),
    ) {
        let (text, sites) = render(&v);
        let out = apply(&v, &text, &sites, d);
        let bytes = out.bytes.as_slice();
        let context = format!("{} on {}: {}", out.what, text, show(bytes));
        check_reader(bytes).map_err(|e| TestCaseError::fail(format!("{e}; {context}")))?;
        let parsed = parse(bytes);
        let scanned = scan_canonical(bytes);
        // The scanner reads objects only: any other root is refused at the first byte.
        let scan_floor = if matches!(v, Value::Object(_)) { out.not_before } else { 0 };
        match out.expect {
            Expect::Canonical => {
                prop_assert_eq!(&parsed, &Ok(v.clone()), "{}", context);
                prop_assert_eq!(first_non_canonical_offset(bytes, &v), None);
                prop_assert_eq!(scanned.is_ok(), matches!(v, Value::Object(_)), "{}", context);
            }
            Expect::SameValue => {
                prop_assert_eq!(&parsed, &Ok(v.clone()), "{}", context);
                let offset = first_non_canonical_offset(bytes, &v);
                prop_assert_eq!(offset, Some(common_prefix(text.as_bytes(), bytes)), "{}", context);
                prop_assert!(offset >= Some(out.not_before), "{}", context);
                match scanned {
                    Ok(_) => return fail(format!("scan accepted non-canonical bytes: {context}")),
                    Err(e) => prop_assert!(e.offset >= scan_floor, "{e}: {}", context),
                }
            }
            Expect::Refused => {
                match parsed {
                    Ok(_) => return fail(format!("parse accepted: {context}")),
                    Err(e) => prop_assert!(e.offset >= out.not_before, "{e}: {}", context),
                }
                match scanned {
                    Ok(_) => return fail(format!("scan accepted: {context}")),
                    Err(e) => prop_assert!(e.offset >= scan_floor, "{e}: {}", context),
                }
            }
            Expect::Unknown => {}
        }
    }

    /// Holds: up to four single-byte edits of a canonical document never make the reader or the
    /// scanner panic, and whatever they give obeys `check_reader`.
    /// Source: SPEC B1.7 ("verify rejects any file that differs from the canonical form of its
    /// own parse"); `first_non_canonical_offset` and `scan_canonical` documentation.
    #[test]
    fn repeated_byte_edits_obey_the_identity_or_refusal_rule(
        v in document(),
        edits in prop::collection::vec((any::<u8>(), any::<u32>(), any::<u32>(), any::<u32>()), 0..=4),
    ) {
        let mut bytes = canonical(&v).into_bytes();
        for (kind, a, b, c) in edits {
            byte_edit(&mut bytes, kind, a, b, c);
        }
        check_reader(&bytes)?;
    }

    /// Holds: arbitrary bytes, and bytes made of JSON-like pieces, never make the reader or the
    /// scanner panic, and whatever they give obeys `check_reader`.
    /// Source: SPEC B1.7; `parse` documentation ("nothing after the value").
    #[test]
    fn arbitrary_bytes_obey_the_identity_or_refusal_rule(bytes in arbitrary_bytes()) {
        check_reader(&bytes)?;
    }

    /// Holds: `first_non_canonical_offset(bytes, v)` is `None` when the bytes are the canonical
    /// text of `v` and otherwise the length of the common prefix of the bytes and that text, for
    /// any bytes and any value, whether or not the bytes are JSON. The semantics relied on: the
    /// function "checks that `bytes` are exactly the canonical form of `value`; returns the first
    /// byte offset where they differ", and the code returns `None` for equal bytes and otherwise
    /// the first position where the two differ, or the length of the shorter when one is a prefix
    /// of the other (a first difference exists at that offset: one has a byte and the other ends).
    /// Source: `first_non_canonical_offset` documentation and code in `json.rs`.
    #[test]
    fn the_first_difference_is_the_common_prefix_length(
        v in value(),
        w in value(),
        edits in prop::collection::vec((any::<u8>(), any::<u32>(), any::<u32>(), any::<u32>()), 0..=2),
        other in any::<bool>(),
    ) {
        let text = canonical(&v);
        let mut bytes = if other { canonical(&w).into_bytes() } else { text.clone().into_bytes() };
        for (kind, a, b, c) in edits {
            byte_edit(&mut bytes, kind, a, b, c);
        }
        let expected = if bytes == text.as_bytes() {
            None
        } else {
            Some(common_prefix(text.as_bytes(), &bytes))
        };
        prop_assert_eq!(first_non_canonical_offset(&bytes, &v), expected);
    }
}

/// Pieces of JSON text, some of them damaged the way the format names: floats, leading zeros,
/// `-0`, a number above 2^53 - 1, a lone surrogate, a bad escape, an escape that is not
/// canonical, a cut literal, a space that is not JSON's.
const SOUP_SCALARS: [&str; 33] = [
    "\"a\"",
    "\"b\"",
    "\"seq\"",
    "\"\"",
    "\"\\n\"",
    "\"\\u00e9\"",
    "\"\\u001f\"",
    "\"\\u001F\"",
    "\"\\ud83d\\ude00\"",
    "\"\\ud83d\"",
    "\"\\ude00\"",
    "\"\\/\"",
    "\"\u{e9}\"",
    "\"\u{1f600}\"",
    "\"\\x\"",
    "\"\\u12\"",
    "\"\\",
    "0",
    "1",
    "-1",
    "12",
    "01",
    "-0",
    "1.5",
    "1e3",
    "9007199254740991",
    "9007199254740992",
    "null",
    "true",
    "false",
    "nul",
    " ",
    "\u{a0}",
];

/// Text built from `SOUP_SCALARS` and brackets: mostly well formed, so that the reader gets past
/// its first checks, with wrong separators and closers now and then.
fn soup() -> BoxedStrategy<Vec<u8>> {
    let scalar = prop_oneof![
        8 => prop::sample::select(SOUP_SCALARS.to_vec()).prop_map(|s| s.as_bytes().to_vec()),
        1 => prop::collection::vec(any::<u8>(), 1..=3),
    ];
    let separator = prop::sample::select(vec![",", ",", ",", ",", ",", ", ", "", ",,", " , "]);
    let key = prop::sample::select(vec![
        "\"a\"",
        "\"b\"",
        "\"seq\"",
        "\"\"",
        "\"\\u00e9\"",
        "\"\u{1f600}\"",
        "\"\u{ff61}\"",
        "\"a",
        "1",
    ]);
    scalar
        .prop_recursive(5, 30, 3, move |inner| {
            let array = (
                prop::collection::vec(inner.clone(), 0..=3),
                separator.clone(),
                prop::sample::select(vec!["]", "]", "]", "]", "]", "}"]),
            )
                .prop_map(|(items, separator, close)| {
                    let mut out = b"[".to_vec();
                    for (i, item) in items.into_iter().enumerate() {
                        if i > 0 {
                            out.extend_from_slice(separator.as_bytes());
                        }
                        out.extend(item);
                    }
                    out.extend_from_slice(close.as_bytes());
                    out
                });
            let object = (
                prop::collection::vec((key.clone(), inner), 0..=3),
                separator.clone(),
                prop::sample::select(vec!["}", "}", "}", "}", "}", "]"]),
            )
                .prop_map(|(members, separator, close)| {
                    let mut out = b"{".to_vec();
                    for (i, (key, item)) in members.into_iter().enumerate() {
                        if i > 0 {
                            out.extend_from_slice(separator.as_bytes());
                        }
                        out.extend_from_slice(key.as_bytes());
                        out.push(b':');
                        out.extend(item);
                    }
                    out.extend_from_slice(close.as_bytes());
                    out
                });
            prop_oneof![array, object]
        })
        .boxed()
}

/// Bytes the reader is mostly going to refuse: raw bytes, or JSON-like text.
fn arbitrary_bytes() -> BoxedStrategy<Vec<u8>> {
    prop_oneof![
        1 => prop::collection::vec(any::<u8>(), 0..=48),
        4 => soup(),
    ]
    .boxed()
}

// ---------------------------------------------------------------------------------------------
// Property 3: the scanner.
// ---------------------------------------------------------------------------------------------

proptest! {
    #![proptest_config(config())]

    /// Holds: for an object whose events carry a `seq` member, the scanner returns a `seq` span
    /// for every element of an array that is an object with a `seq` member, and the span is that
    /// member's canonical text.
    /// Source: `MemberSpan::seqs` ("the bytes of each element's top-level `seq` member, if it is
    /// an object that has one") and SPEC B1.7 (events are leaves in sequence order); `verify`
    /// reads the event sequence from these spans.
    #[test]
    fn the_scanner_finds_the_seq_member_of_every_event(v in events_document()) {
        let text = canonical(&v);
        let Value::Object(map) = &v else { unreachable!() };
        let spans = scan_canonical(text.as_bytes())
            .map_err(|e| TestCaseError::fail(format!("{e} in {}", show(text.as_bytes()))))?;
        check_spans(text.as_bytes(), map, &spans, true)
            .map_err(|e| TestCaseError::fail(format!("{e}; document {text}")))?;
    }

    /// Holds: whatever the scanner accepts or refuses is consistent with the reader and the
    /// writer, and the spans it returns when it accepts are right, for canonical objects that
    /// hold arrays of events (the shape of a record) with the same damage as above.
    /// Source: `scan_canonical` documentation (the byte ranges of its members; in canonical text
    /// each value's bytes are its own canonical form).
    #[test]
    fn the_scanner_agrees_with_the_reader_on_event_documents(
        v in events_document(),
        d in damage(),
    ) {
        let (text, sites) = render(&v);
        let out = apply(&v, &text, &sites, d);
        check_reader(&out.bytes).map_err(|e| TestCaseError::fail(format!("{e}; {}", out.what)))?;
    }
}

// ---------------------------------------------------------------------------------------------
// Property 4: key order.
// ---------------------------------------------------------------------------------------------

/// A token of JSON text, for comparing two texts that differ in whitespace and escapes.
#[derive(Debug, Clone, PartialEq)]
enum Lex {
    Punct(char),
    /// A string literal, quotes included, as written.
    Str(String),
    Word(String),
}

fn lex(text: &str) -> Vec<Lex> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(&c) = chars.get(i) {
        match c {
            ' ' | '\t' | '\n' | '\r' => i += 1,
            '{' | '}' | '[' | ']' | ',' | ':' => {
                out.push(Lex::Punct(c));
                i += 1;
            }
            '"' => {
                let start = i;
                i += 1;
                while let Some(&d) = chars.get(i) {
                    if d == '"' {
                        break;
                    }
                    i += if d == '\\' { 2 } else { 1 };
                }
                out.push(Lex::Str(chars[start..=i].iter().collect()));
                i += 1;
            }
            _ => {
                let start = i;
                while let Some(&d) = chars.get(i) {
                    if matches!(
                        d,
                        ' ' | '\t' | '\n' | '\r' | '{' | '}' | '[' | ']' | ',' | ':' | '"'
                    ) {
                        break;
                    }
                    i += 1;
                }
                out.push(Lex::Word(chars[start..i].iter().collect()));
            }
        }
    }
    out
}

/// The text a string literal stands for.
fn decoded(literal: &str) -> String {
    match parse(literal.as_bytes()) {
        Ok(Value::Str(s)) => s,
        other => panic!("{literal} is not a string: {other:?}"),
    }
}

/// The tokens of `text` with strings decoded: what two spellings of one document share.
fn meaning(text: &str) -> Vec<(char, String)> {
    lex(text)
        .into_iter()
        .map(|token| match token {
            Lex::Punct(c) => ('p', c.to_string()),
            Lex::Str(literal) => ('s', decoded(&literal)),
            Lex::Word(w) => ('w', w),
        })
        .collect()
}

/// The keys of every object in `text`, in the order they are written.
fn keys_in_order(text: &str) -> Vec<String> {
    let tokens = lex(text);
    let mut keys = Vec::new();
    for pair in tokens.windows(2) {
        if let [Lex::Str(literal), Lex::Punct(':')] = pair {
            keys.push(decoded(literal));
        }
    }
    keys
}

/// The keys of every object in `v`, in the order the format puts them: sorted by UTF-16 code
/// units, an object's key before the keys inside its value.
fn ref_keys(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::Array(items) => items.iter().for_each(|item| ref_keys(item, out)),
        Value::Object(map) => {
            for (key, item) in ref_sorted(map) {
                out.push(key.clone());
                ref_keys(item, out);
            }
        }
        _ => {}
    }
}

/// Keys that put UTF-16 order and UTF-8 order apart, in sets of two to five.
fn astral_keys() -> BoxedStrategy<Vec<(String, Value)>> {
    let key = prop::collection::vec(prop::sample::select(ASTRAL_CHARS.to_vec()), 1..=2)
        .prop_map(|chars| chars.into_iter().collect::<String>());
    prop::collection::btree_map(key, json_int().prop_map(Value::Int), 2..=5)
        .prop_map(|map| map.into_iter().collect())
        .boxed()
}

proptest! {
    #![proptest_config(config())]

    /// Holds: an object built from the same pairs in any insertion order, with `field` or with
    /// `set`, is the same value and has the same canonical text.
    /// Source: `Obj` (keys unique, a field added or replaced) and RFC 8785 as written in
    /// `docs/RECORD_FORMAT.md` ("Objects have their members sorted by key").
    #[test]
    fn insertion_order_does_not_change_the_canonical_text(
        pairs in prop::collection::btree_map(json_key(), value(), 0..=8)
            .prop_map(|map| map.into_iter().collect::<Vec<(String, Value)>>()),
        seed in any::<u64>(),
    ) {
        let mut shuffled = pairs.clone();
        // A permutation chosen by the seed: a Fisher-Yates pass with a linear congruence.
        let mut state = seed;
        for i in (1..shuffled.len()).rev() {
            state = state.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
            let j = usize::try_from(state >> 33).unwrap_or(0) % (i + 1);
            shuffled.swap(i, j);
        }
        let in_order = pairs
            .iter()
            .fold(Obj::new(), |o, (k, v)| o.field(k, v.clone()))
            .build();
        let mixed = shuffled
            .iter()
            .fold(Obj::new(), |o, (k, v)| o.field(k, v.clone()))
            .build();
        let mut by_set = Obj::new();
        for (k, v) in shuffled.iter().rev() {
            by_set.set(k, v.clone());
        }
        let by_set = by_set.build();
        prop_assert_eq!(&in_order, &mixed);
        prop_assert_eq!(&in_order, &by_set);
        prop_assert_eq!(canonical(&in_order), canonical(&mixed));
        prop_assert_eq!(canonical(&in_order), canonical(&by_set));
    }

    /// Holds: the canonical text of a value lists the keys of every object sorted by UTF-16 code
    /// units (the reference sort in this file compares `encode_utf16` sequences), and so does the
    /// text of `pretty`.
    /// Source: SPEC B1.7 and `docs/RECORD_FORMAT.md` ("Objects have their members sorted by key,
    /// comparing keys as sequences of UTF-16 code units"); `pretty` documentation ("the same key
    /// order as `canonical`").
    #[test]
    fn keys_are_listed_in_utf16_order(v in value()) {
        let mut expected = Vec::new();
        ref_keys(&v, &mut expected);
        prop_assert_eq!(keys_in_order(&canonical(&v)), expected.clone());
        prop_assert_eq!(keys_in_order(&pretty(&v)), expected);
    }

    /// Holds: an object whose keys are written in UTF-16 order is accepted by the scanner and is
    /// canonical; written in any other order (UTF-8 byte order, which differs when a character
    /// above U+FFFF meets one in U+E000 to U+FFFF, or a shuffle) it is read as the same value,
    /// reported as not canonical, and refused by the scanner.
    /// Source: `scan_canonical` documentation ("keys strictly ordered by UTF-16 code units");
    /// RFC 8785 section 3.2.3 as given in `docs/RECORD_FORMAT.md`.
    #[test]
    fn only_the_utf16_order_of_keys_is_canonical(
        pairs in astral_keys(),
        how in 0u8..3,
        seed in any::<u64>(),
    ) {
        let map: BTreeMap<String, Value> = pairs.iter().cloned().collect();
        let utf16: Vec<(String, Value)> = ref_sorted(&map)
            .into_iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let chosen: Vec<(String, Value)> = match how {
            0 => utf16.clone(),
            // BTreeMap order is the order of the UTF-8 bytes.
            1 => map.clone().into_iter().collect(),
            _ => {
                let mut rest = utf16.clone();
                let n = rest.len();
                rest.rotate_left(1 + usize::try_from(seed % 4).unwrap_or(0) % (n - 1));
                rest
            }
        };
        let body: Vec<String> = chosen
            .iter()
            .map(|(k, v)| format!("{}:{}", ref_string(k), ref_canonical(v)))
            .collect();
        let text = format!("{{{}}}", body.join(","));
        let v = Value::Object(map);
        let in_order = chosen.iter().map(|(k, _)| k).eq(utf16.iter().map(|(k, _)| k));
        prop_assert_eq!(parse(text.as_bytes()), Ok(v.clone()), "{}", text);
        prop_assert_eq!(
            first_non_canonical_offset(text.as_bytes(), &v).is_none(),
            in_order,
            "{}", text
        );
        prop_assert_eq!(scan_canonical(text.as_bytes()).is_ok(), in_order, "{}", text);
        check_reader(text.as_bytes())?;
    }

    /// Holds: building an object by a sequence of writes, each with `field` or `set`, keeps the
    /// last value written for each key, and the object has no other keys.
    /// Source: `Obj::field` and `Obj::set` ("adds or replaces a field").
    #[test]
    fn the_last_write_to_a_key_wins(
        writes in prop::collection::vec((json_key(), value(), any::<bool>()), 0..=10),
    ) {
        let mut model = BTreeMap::new();
        let mut obj = Obj::new();
        for (key, v, by_field) in writes {
            model.insert(key.clone(), v.clone());
            if by_field {
                obj = obj.field(&key, v);
            } else {
                obj.set(&key, v);
            }
        }
        prop_assert_eq!(obj.build(), Value::Object(model));
    }
}

// ---------------------------------------------------------------------------------------------
// Property 5: depth.
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Array,
    Object,
}

/// A chain of nested containers, in canonical form, and where each one opens.
struct Nested {
    opens: String,
    closes: String,
    /// The offset of the opening bracket of each level.
    at: Vec<usize>,
}

impl Nested {
    fn text(&self) -> String {
        format!("{}{}", self.opens, self.closes)
    }
}

/// `kinds.len()` nested containers, each holding the next; `siblings` 0 holds nothing else,
/// 1 puts scalars before the next level, 2 before and after it. The innermost container is empty
/// when `empty_innermost` and holds a scalar otherwise. `pad` is written before each opening
/// bracket; the text is canonical when it is empty (keys `a`, `b`, `c`).
fn nested(kinds: &[Kind], siblings: u8, empty_innermost: bool, pad: &str) -> Nested {
    let mut opens = String::new();
    let mut closes: Vec<&str> = Vec::new();
    let mut at = Vec::new();
    for (i, kind) in kinds.iter().enumerate() {
        opens.push_str(pad);
        at.push(opens.len());
        let last = i + 1 == kinds.len();
        let (open, close) = match (kind, last) {
            (Kind::Array, false) => (
                if siblings >= 1 { "[1,null," } else { "[" },
                if siblings == 2 { ",true]" } else { "]" },
            ),
            (Kind::Array, true) if empty_innermost => ("[", "]"),
            (Kind::Array, true) => ("[7", if siblings == 2 { ",true]" } else { "]" }),
            (Kind::Object, false) => (
                if siblings >= 1 {
                    "{\"a\":1,\"b\":"
                } else {
                    "{\"a\":"
                },
                if siblings == 2 { ",\"c\":2}" } else { "}" },
            ),
            (Kind::Object, true) if empty_innermost => ("{", "}"),
            (Kind::Object, true) => ("{\"a\":7", if siblings == 2 { ",\"c\":2}" } else { "}" }),
        };
        opens.push_str(open);
        closes.push(close);
    }
    closes.reverse();
    Nested {
        opens,
        closes: closes.concat(),
        at,
    }
}

fn kind() -> impl Strategy<Value = Kind> {
    prop_oneof![Just(Kind::Array), Just(Kind::Object)]
}

/// Nesting levels, over-weighted around the limit.
fn levels() -> impl Strategy<Value = usize> {
    prop_oneof![
        3 => MAX_DEPTH - 2..=MAX_DEPTH + 3,
        1 => 1..=MAX_DEPTH + 8,
    ]
}

fn kinds() -> impl Strategy<Value = Vec<Kind>> {
    levels().prop_flat_map(|n| prop::collection::vec(kind(), n))
}

/// The reader's refusal of the level after the last allowed one: an error at the opening bracket
/// of that level, saying which limit it is.
fn check_depth_error(
    what: &str,
    result: Result<(), sfr_core::json::ParseError>,
    nested: &Nested,
) -> Result<(), TestCaseError> {
    match result {
        Ok(()) => fail(format!("{what} accepted {} levels", nested.at.len())),
        Err(e) => {
            prop_assert_eq!(e.offset, nested.at[MAX_DEPTH], "{} {}", what, e);
            prop_assert!(
                e.reason.contains(&format!("{MAX_DEPTH} levels")),
                "{what}: {e}"
            );
            Ok(())
        }
    }
}

proptest! {
    #![proptest_config(config())]

    /// Holds: a document nested `MAX_DEPTH` levels deep (arrays, objects or a mix, with siblings,
    /// whitespace before the brackets, and an empty or a full innermost container) is accepted by
    /// `parse`, read back with exactly that nesting and written back to the canonical text without
    /// the whitespace; one level deeper is refused, at the opening bracket of the 65th level, with
    /// the input-limit message.
    /// Source: `docs/LIMITS.md` ("Record JSON nesting: 64 nested arrays and objects"),
    /// `MAX_DEPTH` in `json.rs`.
    #[test]
    fn the_reader_accepts_the_documented_depth_and_refuses_one_more(
        kinds in kinds(),
        siblings in 0u8..3,
        empty in any::<bool>(),
        pad in prop::sample::select(vec!["", "", " ", "\n\t", "\r\n "]),
    ) {
        let n = nested(&kinds, siblings, empty, pad);
        let text = n.text();
        match parse(text.as_bytes()) {
            Ok(v) => {
                prop_assert!(kinds.len() <= MAX_DEPTH, "{} levels accepted", kinds.len());
                prop_assert_eq!(nesting(&v), kinds.len());
                prop_assert_eq!(canonical(&v), nested(&kinds, siblings, empty, "").text());
            }
            Err(e) => {
                prop_assert!(kinds.len() > MAX_DEPTH, "{} levels refused: {}", kinds.len(), e);
                check_depth_error("parse", Err(e), &n)?;
            }
        }
    }

    /// Holds: the same for the scanner, whose nesting limit is the same: the scanner needs an
    /// object at the top, so the outermost level is an object.
    /// Source: `docs/LIMITS.md` ("Record JSON nesting"), `scan_canonical`.
    #[test]
    fn the_scanner_accepts_the_documented_depth_and_refuses_one_more(
        mut kinds in kinds(),
        siblings in 0u8..3,
        empty in any::<bool>(),
    ) {
        kinds[0] = Kind::Object;
        let n = nested(&kinds, siblings, empty, "");
        let text = n.text();
        match scan_canonical(text.as_bytes()) {
            Ok(_) => {
                prop_assert!(kinds.len() <= MAX_DEPTH, "{} levels accepted", kinds.len());
                check_reader(text.as_bytes())?;
            }
            Err(e) => {
                prop_assert!(kinds.len() > MAX_DEPTH, "{} levels refused: {}", kinds.len(), e);
                check_depth_error("scan", Err(e), &n)?;
            }
        }
    }

    /// Holds: nesting of tens of thousands of brackets, balanced or not, arrays or objects or a
    /// mix, is refused by the reader and by the scanner at the opening bracket of the 65th level,
    /// without overflowing the stack.
    /// Source: `docs/LIMITS.md` ("Record JSON nesting ... Bounds the parser's recursion").
    #[test]
    fn very_deep_nesting_is_refused_without_a_stack_overflow(
        n in 65usize..=40_000,
        pattern in 0u8..3,
        balanced in any::<bool>(),
    ) {
        let kinds: Vec<Kind> = (0..n)
            .map(|i| match pattern {
                0 => Kind::Object,
                1 if i == 0 => Kind::Object,
                1 => Kind::Array,
                _ if i % 2 == 0 => Kind::Object,
                _ => Kind::Array,
            })
            .collect();
        let nested = nested(&kinds, 0, true, "");
        let text = if balanced { nested.text() } else { nested.opens.clone() };
        check_depth_error("parse", parse(text.as_bytes()).map(|_| ()), &nested)?;
        check_depth_error("scan", scan_canonical(text.as_bytes()).map(|_| ()), &nested)?;
    }
}

/// Holds: a million unclosed brackets, of each kind, are refused at the 65th by both entry points.
/// Source: `docs/LIMITS.md` ("Record JSON nesting").
#[test]
fn a_million_brackets_are_refused_without_a_stack_overflow() {
    for text in [
        "[".repeat(1_000_000),
        "{\"a\":".repeat(200_000),
        "{\"a\":[".repeat(200_000),
    ] {
        let e = parse(text.as_bytes()).expect_err("too deep");
        assert!(e.reason.contains(&format!("{MAX_DEPTH} levels")), "{e}");
        let e = scan_canonical(text.as_bytes());
        if text.starts_with('{') {
            let e = e.expect_err("too deep");
            assert!(e.reason.contains(&format!("{MAX_DEPTH} levels")), "{e}");
        } else {
            assert!(e.is_err());
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Property 6: the other inverses in json.rs.
// ---------------------------------------------------------------------------------------------

/// An `i64` from the whole range, with the edges of the record's safe range over-weighted.
fn any_i64() -> BoxedStrategy<i64> {
    prop_oneof![
        3 => any::<i64>(),
        3 => MAX_SAFE_INTEGER - 3..=MAX_SAFE_INTEGER + 3,
        3 => -MAX_SAFE_INTEGER - 3..=-MAX_SAFE_INTEGER + 3,
        1 => prop::sample::select(vec![i64::MIN, i64::MAX, 0, 1, -1]),
    ]
    .boxed()
}

fn any_u64() -> BoxedStrategy<u64> {
    let edge = u64::try_from(MAX_SAFE_INTEGER).unwrap();
    prop_oneof![
        3 => any::<u64>(),
        3 => edge - 3..=edge + 3,
        1 => prop::sample::select(vec![0, 1, u64::MAX, u64::MAX - 1, u64::from(u32::MAX)]),
    ]
    .boxed()
}

proptest! {
    #![proptest_config(config())]

    /// Holds: `Value::int(n)` is the integer itself when it is within the safe range and its
    /// decimal string otherwise; either way the canonical text reads back as the same value, and
    /// the number can be recovered from what was read.
    /// Source: `Value::int` documentation and `MAX_SAFE_INTEGER` (SPEC B1.7: integers below 2^53,
    /// the rest as decimal strings).
    #[test]
    fn value_int_round_trips_through_text(n in any_i64()) {
        let v = Value::int(n);
        let safe = n.unsigned_abs() <= MAX_SAFE_INTEGER.unsigned_abs();
        if safe {
            prop_assert_eq!(&v, &Value::Int(n));
            prop_assert_eq!(canonical(&v), n.to_string());
        } else {
            prop_assert_eq!(&v, &Value::Str(n.to_string()));
            prop_assert_eq!(canonical(&v), format!("\"{n}\""));
        }
        let back = parse(canonical(&v).as_bytes());
        prop_assert_eq!(&back, &Ok(v.clone()));
        let recovered = match back {
            Ok(Value::Int(i)) => Some(i),
            Ok(Value::Str(s)) => s.parse::<i64>().ok(),
            _ => None,
        };
        prop_assert_eq!(recovered, Some(n));
    }

    /// Holds: `Value::count(n)` is an integer up to the safe range and a decimal string above
    /// it; the canonical text reads back as the same value, and `n` can be recovered.
    /// Source: `Value::count` documentation and SPEC B1.7.
    #[test]
    fn value_count_round_trips_through_text(n in any_u64()) {
        let v = Value::count(n);
        let edge = u64::try_from(MAX_SAFE_INTEGER).unwrap();
        prop_assert_eq!(matches!(v, Value::Int(_)), n <= edge);
        let back = parse(canonical(&v).as_bytes());
        prop_assert_eq!(&back, &Ok(v.clone()));
        let recovered = match back {
            Ok(Value::Int(i)) => u64::try_from(i).ok(),
            Ok(Value::Str(s)) => s.parse::<u64>().ok(),
            _ => None,
        };
        prop_assert_eq!(recovered, Some(n));
    }

    /// Holds: `Value::u64_str(n)` is always a string of the decimal digits of `n` with no sign
    /// and no leading zero; its canonical text is that string in quotes and reads back as `n`.
    /// Source: `Value::u64_str` documentation and SPEC B1.7 ("unsigned 64-bit measurements ...
    /// are decimal strings"); `docs/RECORD_FORMAT.md` (`"24295307"`, never `24295307`).
    #[test]
    fn value_u64_str_round_trips_through_text(n in any_u64()) {
        let v = Value::u64_str(n);
        prop_assert_eq!(canonical(&v), format!("\"{n}\""));
        let Ok(Value::Str(s)) = parse(canonical(&v).as_bytes()) else {
            return fail("u64_str did not read back as a string".to_string());
        };
        prop_assert!(s.bytes().all(|b| b.is_ascii_digit()));
        prop_assert!(s == "0" || !s.starts_with('0'));
        prop_assert_eq!(s.parse::<u64>().ok(), Some(n));
    }

    /// Holds: `Value::str` and `Value::opt_str` read back from their canonical text as the
    /// string, or as `null` for `None`.
    /// Source: `Value::str` and `Value::opt_str` documentation ("`None` as `null`").
    #[test]
    fn string_helpers_round_trip_through_text(s in json_string(), some in any::<bool>()) {
        prop_assert_eq!(parse(canonical(&Value::str(s.clone())).as_bytes()), Ok(Value::Str(s.clone())));
        let option = if some { Some(s.clone()) } else { None };
        let v = Value::opt_str(option.clone());
        prop_assert_eq!(parse(canonical(&v).as_bytes()), Ok(v.clone()));
        match option {
            Some(s) => prop_assert_eq!(v, Value::Str(s)),
            None => prop_assert_eq!(v, Value::Null),
        }
    }

    /// Holds: a number written as an optional minus sign and digits is read exactly when it has
    /// no leading zero, is not `-0` and has magnitude at most 2^53 - 1, as that integer; the
    /// scanner accepts it as a member of an object under the same condition. Texts at the edge
    /// of the range and with leading zeros are over-weighted.
    /// Source: `docs/RECORD_FORMAT.md` ("Integers are decimal with magnitude at most 2^53 - 1,
    /// no leading zero, no plus sign, no -0").
    #[test]
    fn integer_text_is_read_exactly_when_it_is_a_safe_canonical_integer(
        negative in any::<bool>(),
        zeros in 0usize..3,
        digits in prop_oneof![
            3 => prop::collection::vec(0u8..10, 1..=24),
            2 => (MAX_SAFE_INTEGER - 4..=MAX_SAFE_INTEGER + 4)
                .prop_map(|n| n.to_string().bytes().map(|b| b - b'0').collect::<Vec<u8>>()),
            1 => Just(vec![0u8]),
        ],
    ) {
        let magnitude: String = "0"
            .repeat(zeros)
            .chars()
            .chain(digits.iter().map(|d| char::from(b'0' + d)))
            .collect();
        let text = format!("{}{magnitude}", if negative { "-" } else { "" });
        let value: i128 = magnitude.parse().unwrap();
        let plain = magnitude.len() == 1 || !magnitude.starts_with('0');
        let accepted = plain
            && !(negative && value == 0)
            && value <= i128::from(MAX_SAFE_INTEGER);
        let signed = if negative { -value } else { value };
        match parse(text.as_bytes()) {
            Ok(v) => {
                prop_assert!(accepted, "{} read as {:?}", text, v);
                prop_assert_eq!(v, Value::Int(i64::try_from(signed).unwrap()));
            }
            Err(e) => prop_assert!(!accepted, "{} refused: {}", text, e),
        }
        let member = format!("{{\"n\":{text}}}");
        prop_assert_eq!(scan_canonical(member.as_bytes()).is_ok(), accepted, "{}", member);
        check_reader(member.as_bytes())?;
    }

    /// Holds: the text of `pretty` is JSON that reads back as the same value, ends in one
    /// newline, has the same tokens in the same order as the canonical text once whitespace and
    /// escapes are set aside, has no control character but the structural newlines, no character
    /// that hides or moves the reader's view, and no newline inside a string.
    /// Source: `pretty` documentation and SPEC B1.8 (`--json` output writes such characters as
    /// `\uXXXX` escapes); `Parser::string` reads those escapes back.
    #[test]
    fn pretty_text_reads_back_and_shows_every_hidden_character(v in value()) {
        let text = pretty(&v);
        prop_assert_eq!(parse(text.as_bytes()), Ok(v.clone()), "{}", text);
        prop_assert!(text.ends_with('\n') && !text.ends_with("\n\n"));
        prop_assert_eq!(meaning(&text), meaning(&canonical(&v)));
        for c in text.chars() {
            prop_assert!(
                !(c.is_control() && c != '\n') && !is_hidden(c),
                "U+{:04X} written as itself in {}", u32::from(c), text
            );
        }
        for token in lex(&text) {
            if let Lex::Str(literal) = token {
                prop_assert!(!literal.contains('\n'), "{}", literal);
            }
        }
    }
}

/// Holds: a document with 20,000 members, each an array of two elements, and a string of 400,000
/// characters is read, scanned and written back unchanged, with one span per member and one per
/// element. A reader whose work grew faster than its input would not finish this in a test run.
/// Source: SPEC B1.7 (a record is read in one pass; `scan_canonical` "in one pass, without
/// building values").
#[test]
fn wide_and_long_documents_are_read_in_one_pass() {
    let mut obj = Obj::new();
    for i in 0..20_000i64 {
        obj.set(
            &format!("k{i:06}"),
            Value::Array(vec![Value::Int(i), Value::str("a\n\u{1f600}")]),
        );
    }
    let long: String = (0..100_000)
        .flat_map(|_| ['a', '"', '\u{1f600}', '\u{1}'])
        .collect();
    obj.set("long", Value::str(long.clone()));
    let v = obj.build();
    let text = canonical(&v);
    assert_eq!(parse(text.as_bytes()), Ok(v.clone()));
    assert_eq!(first_non_canonical_offset(text.as_bytes(), &v), None);
    let spans = scan_canonical(text.as_bytes()).expect("canonical");
    assert_eq!(spans.len(), 20_001);
    // "k000000" to "k019999" come first and "long" sorts after them.
    assert!(spans[..20_000].iter().all(|s| s.elements.len() == 2));
    assert_eq!(spans[20_000].key, "long");
    assert_eq!(
        parse(&text.as_bytes()[spans[20_000].value.clone()]),
        Ok(Value::Str(long))
    );
}

// ---------------------------------------------------------------------------------------------
// Property 7: every spelling of the characters and tokens the damage generators reach only rarely.
// These were added after bugs injected into json.rs went unnoticed by the random damage: the
// scanner accepting uppercase `\u001F`, `\/`, or `\u000a`; the reader accepting a lone low
// surrogate or a form feed as whitespace; `first_non_canonical_offset` on a proper prefix; the
// layout of `pretty`; a stray comma after `[`; a `seq` key nested inside an event.
// ---------------------------------------------------------------------------------------------

/// `Some(c)` for a one-character string `"..."` spelled as the bytes `body`, read by `parse`.
fn read_one(body: &str) -> Result<Value, sfr_core::json::ParseError> {
    parse(format!("\"{body}\"").as_bytes())
}

/// Each way to spell `c` inside a string literal that the reader may accept, and the raw byte.
fn spellings(c: char) -> Vec<String> {
    let mut all = Vec::new();
    let lower: String = c
        .encode_utf16(&mut [0u16; 2])
        .iter()
        .map(|u| format!("\\u{u:04x}"))
        .collect();
    let upper: String = c
        .encode_utf16(&mut [0u16; 2])
        .iter()
        .map(|u| format!("\\u{u:04X}"))
        .collect();
    all.push(lower);
    all.push(upper);
    all.push(c.to_string());
    match c {
        '"' => all.push("\\\"".into()),
        '\\' => all.push("\\\\".into()),
        '/' => all.push("\\/".into()),
        '\u{8}' => all.push("\\b".into()),
        '\t' => all.push("\\t".into()),
        '\n' => all.push("\\n".into()),
        '\u{c}' => all.push("\\f".into()),
        '\r' => all.push("\\r".into()),
        _ => {}
    }
    all
}

/// For every character below U+0020 and the ones with a short escape or a slash, every spelling is
/// judged: a raw control is refused, any escape reads back as the character, and the scanner (as a
/// value and as a key) accepts exactly the spelling the reference writer produces.
#[test]
fn every_spelling_of_every_control_and_special_character_is_judged_exactly() {
    let chars: Vec<char> = (0u8..0x20)
        .map(char::from)
        .chain(['"', '\\', '/', 'A', '\u{7f}', '\u{e9}', '\u{1f600}'])
        .collect();
    for c in chars {
        let want = ref_string(&c.to_string());
        for body in spellings(c) {
            let literal = format!("\"{body}\"");
            let raw_control = u32::from(c) < 0x20 && body == c.to_string();
            let raw_quote = (c == '"' || c == '\\') && body == c.to_string();
            let parsed = read_one(&body);
            if raw_control || raw_quote {
                assert!(parsed.is_err(), "{literal:?} was read as {parsed:?}");
            } else {
                assert_eq!(parsed, Ok(Value::Str(c.to_string())), "{literal:?}");
            }
            let canonical_spelling = literal == want;
            for text in [format!("{{\"k\":{literal}}}"), format!("{{{literal}:1}}")] {
                let scanned = scan_canonical(text.as_bytes());
                let reference = match parse(text.as_bytes()) {
                    Ok(v) => ref_canonical(&v) == text,
                    Err(_) => false,
                };
                assert_eq!(
                    scanned.is_ok(),
                    canonical_spelling,
                    "scan of {text:?}: {scanned:?}"
                );
                assert_eq!(
                    scanned.is_ok(),
                    reference,
                    "scan against the reference for {text:?}"
                );
                if scanned.is_err() && !raw_control && !raw_quote {
                    assert_ne!(
                        first_non_canonical_offset(
                            text.as_bytes(),
                            &parse(text.as_bytes()).unwrap()
                        ),
                        None,
                        "{text:?}"
                    );
                }
            }
        }
    }
}

/// Surrogate escapes: a pair is one character; a high one without a low one after it, a low one
/// alone, and a low one first are refused by the reader and by the scanner, as a value and as a key.
#[test]
fn surrogate_escapes_are_paired_or_refused() {
    let highs = ["d800", "d83d", "dbff", "D800", "DBFF"];
    let lows = ["dc00", "de00", "dfff", "DC00", "DFFF"];
    for high in highs {
        for low in lows {
            let body = format!("\\u{high}\\u{low}");
            let want = char::from_u32(
                0x10000
                    + ((u32::from_str_radix(high, 16).unwrap() - 0xd800) << 10)
                    + (u32::from_str_radix(low, 16).unwrap() - 0xdc00),
            )
            .unwrap();
            assert_eq!(read_one(&body), Ok(Value::Str(want.to_string())), "{body}");
            let text = format!("{{\"k\":\"{body}\"}}");
            assert!(scan_canonical(text.as_bytes()).is_err(), "{text}");
        }
        for after in ["", "x", "\\u0041", "\\n", "\\ud800", "\\uD83D", "\\ue000"] {
            let body = format!("\\u{high}{after}");
            assert!(read_one(&body).is_err(), "{body} was read");
            for text in [format!("{{\"k\":\"{body}\"}}"), format!("{{\"{body}\":1}}")] {
                assert!(parse(text.as_bytes()).is_err(), "{text}");
                assert!(scan_canonical(text.as_bytes()).is_err(), "{text}");
            }
        }
    }
    for low in lows {
        for before in ["", "a", "\\u0041", "\\ud800"] {
            let body = if before == "\\ud800" {
                format!("\\u{low}")
            } else {
                format!("{before}\\u{low}")
            };
            let e = read_one(&body).expect_err(&body);
            assert!(e.reason.contains("surrogate"), "{body}: {e}");
            for text in [format!("{{\"k\":\"{body}\"}}"), format!("{{\"{body}\":1}}")] {
                assert!(parse(text.as_bytes()).is_err(), "{text}");
                assert!(scan_canonical(text.as_bytes()).is_err(), "{text}");
            }
        }
    }
    // The edges of the surrogate range are not surrogates.
    for edge in ["d7ff", "e000"] {
        assert!(read_one(&format!("\\u{edge}")).is_ok(), "{edge}");
    }
}

/// Every byte value, written at every place between tokens: the reader skips exactly space, tab,
/// line feed and carriage return; any other byte is refused. The scanner refuses all of them.
#[test]
fn only_four_bytes_are_whitespace_at_every_place_between_tokens() {
    let v = Obj::new()
        .field(
            "a",
            Value::Array(vec![Value::Int(1), Value::str("x"), Value::Null]),
        )
        .field("b", Obj::new().field("c", Value::Bool(true)).build())
        .build();
    let (text, sites) = render(&v);
    for &at in &sites.boundaries {
        for byte in 0u8..=255 {
            let bytes = splice(text.as_bytes(), at..at, &[byte]);
            let is_ws = matches!(byte, b' ' | b'\t' | b'\n' | b'\r');
            // A byte that is not whitespace either breaks a token or changes one (`-` or a digit
            // next to a number), so the value read, if any, is another one.
            assert_eq!(
                parse(&bytes) == Ok(v.clone()),
                is_ws,
                "byte {byte:#04x} at {at}: {}",
                show(&bytes)
            );
            if is_ws {
                assert!(scan_canonical(&bytes).is_err(), "byte {byte:#04x} at {at}");
                assert_eq!(first_non_canonical_offset(&bytes, &v), Some(at));
            }
        }
    }
}

proptest! {
    #![proptest_config(config())]

    /// Holds: for a proper prefix of the canonical text, and for the text with bytes added, the
    /// first difference is the length of the shorter (`first_non_canonical_offset` documentation).
    /// Source: `first_non_canonical_offset` documentation and code.
    #[test]
    fn a_prefix_or_an_extension_differs_where_the_shorter_one_ends(
        v in value(),
        cut in any::<u32>(),
        extra in prop::collection::vec(any::<u8>(), 1..=3),
    ) {
        let text = canonical(&v).into_bytes();
        let cut = small(cut, text.len());
        prop_assert_eq!(first_non_canonical_offset(&text[..cut], &v), Some(cut));
        let mut longer = text.clone();
        longer.extend_from_slice(&extra);
        prop_assert_eq!(first_non_canonical_offset(&longer, &v), Some(text.len()));
        prop_assert_eq!(first_non_canonical_offset(b"", &v), Some(0));
    }

    /// Holds: a comma written at any place between two tokens of a canonical document is refused
    /// by the reader and by the scanner, whatever the document (arrays at the top level included).
    /// Source: JSON grammar; `scan_canonical` ("exactly the canonical form").
    #[test]
    fn a_comma_at_any_place_is_refused(v in prop_oneof![3 => events_document(), 2 => document()]) {
        let (text, sites) = render(&v);
        for &at in &sites.boundaries {
            let bytes = splice(text.as_bytes(), at..at, b",");
            prop_assert!(parse(&bytes).is_err(), "comma at {}: {}", at, show(&bytes));
            prop_assert!(scan_canonical(&bytes).is_err(), "comma at {}: {}", at, show(&bytes));
        }
    }

    /// Holds: `seq` members nested inside an event (in an object, in an array, deeper) or placed
    /// before and after other members never change which `seq` span an event gets: it is the
    /// event's own top-level `seq`, or none.
    /// Source: `MemberSpan::seqs` ("each element's top-level `seq` member").
    #[test]
    fn nested_seq_members_do_not_become_the_events_seq(
        events in prop::collection::vec(seq_trap(), 0..=4),
    ) {
        let mut top = BTreeMap::new();
        top.insert("events".to_string(), Value::Array(events));
        let v = Value::Object(top);
        let text = canonical(&v);
        let spans = scan_canonical(text.as_bytes())
            .map_err(|e| TestCaseError::fail(format!("{e} in {text}")))?;
        let Value::Object(map) = &v else { unreachable!() };
        check_spans(text.as_bytes(), map, &spans, false)
            .map_err(|e| TestCaseError::fail(format!("{e}; document {text}")))?;
    }

    /// Holds: `pretty` is the documented layout: two spaces per level, one member or element per
    /// line, `key: value` with one space, empty containers as `[]` and `{}`, one final newline;
    /// strings as `canonical` writes them except that controls and hidden characters are `\uXXXX`.
    /// Source: `pretty` documentation ("two-space indentation").
    #[test]
    fn pretty_has_the_documented_layout(v in value()) {
        let mut want = ref_pretty(&v, 0);
        want.push('\n');
        prop_assert_eq!(pretty(&v), want);
    }
}

/// An event whose members hold `seq` keys at other places than its own top level.
fn seq_trap() -> BoxedStrategy<Value> {
    let nested_seq = prop_oneof![
        Just(Obj::new().field("seq", Value::Int(7)).build()),
        Just(Value::Array(vec![
            Obj::new().field("seq", Value::Int(8)).build()
        ])),
        Just(
            Obj::new()
                .field("x", Obj::new().field("seq", Value::Int(9)).build())
                .build()
        ),
        Just(Value::Array(vec![Value::Array(vec![
            Obj::new().field("seq", Value::Int(6)).build()
        ])])),
    ];
    (
        prop::option::of(0i64..100),
        prop::option::of(nested_seq.clone()),
        prop::option::of(nested_seq),
        prop::option::of(Just(Value::Array(vec![]))),
    )
        .prop_map(|(seq, before, after, empty)| {
            let mut m = BTreeMap::new();
            if let Some(n) = seq {
                m.insert("seq".to_string(), Value::Int(n));
            }
            if let Some(v) = before {
                m.insert("a".to_string(), v);
            }
            if let Some(v) = after {
                m.insert("z".to_string(), v);
            }
            if let Some(v) = empty {
                m.insert("m".to_string(), v);
            }
            Value::Object(m)
        })
        .boxed()
}

/// A string in `pretty`: as the reference spells it, and every control or hidden character as the
/// `\u` escapes of its UTF-16 units in lowercase hex.
fn ref_pretty_string(s: &str) -> String {
    let mut out = String::from('"');
    for c in s.chars() {
        let plain = ref_string(&c.to_string());
        if u32::from(c) >= 0x20 && (c.is_control() || is_hidden(c)) {
            for unit in c.encode_utf16(&mut [0u16; 2]).iter() {
                let _ = write!(out, "\\u{unit:04x}");
            }
        } else {
            out.push_str(&plain[1..plain.len() - 1]);
        }
    }
    out.push('"');
    out
}

fn ref_pretty(v: &Value, depth: usize) -> String {
    let pad = |n: usize| "  ".repeat(n);
    match v {
        Value::Array(items) if !items.is_empty() => {
            let body: Vec<String> = items
                .iter()
                .map(|item| format!("{}{}", pad(depth + 1), ref_pretty(item, depth + 1)))
                .collect();
            format!("[\n{}\n{}]", body.join(",\n"), pad(depth))
        }
        Value::Object(map) if !map.is_empty() => {
            let body: Vec<String> = ref_sorted(map)
                .into_iter()
                .map(|(k, item)| {
                    format!(
                        "{}{}: {}",
                        pad(depth + 1),
                        ref_pretty_string(k),
                        ref_pretty(item, depth + 1)
                    )
                })
                .collect();
            format!("{{\n{}\n{}}}", body.join(",\n"), pad(depth))
        }
        Value::Array(_) => "[]".to_string(),
        Value::Object(_) => "{}".to_string(),
        Value::Str(s) => ref_pretty_string(s),
        other => ref_canonical(other),
    }
}

/// A number with a fraction or an exponent is refused with the reader's reason, at the `.` or `e`
/// (the end of the integer part), and by the scanner at the start of the number.
#[test]
fn a_fraction_or_an_exponent_is_refused_where_the_integer_ends() {
    for number in ["1.5", "1.0", "0.5", "-2.5", "10e3", "1E3", "1e-3", "7e+2"] {
        let text = format!("{{\"a\":{number}}}");
        let end = 5 + number.find(['.', 'e', 'E']).unwrap();
        let e = parse(text.as_bytes()).expect_err(&text);
        assert_eq!(e.offset, end, "{text}: {e}");
        assert!(e.reason.contains("floating-point"), "{text}: {e}");
        let e = scan_canonical(text.as_bytes()).expect_err(&text);
        assert_eq!(e.offset, 5, "{text}: {e}");
        let array = format!("[{number}]");
        let e = parse(array.as_bytes()).expect_err(&array);
        assert_eq!(
            e.offset,
            1 + number.find(['.', 'e', 'E']).unwrap(),
            "{array}: {e}"
        );
    }
}
