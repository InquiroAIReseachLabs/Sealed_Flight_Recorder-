//! Canonical JSON and parameter number text (SPEC B1.7), held against independent references:
//! the examples of RFC 8785 (JSON Canonicalization Scheme), ECMAScript `JSON.stringify`, and the
//! shortest round-trip float32 digits of the Rust standard library (a Grisu and Dragon
//! implementation that shares no code with `sfr`).
//!
//! The record has no floating-point numbers, so RFC 8785's number serialization (its section
//! 3.2.2.3 and Appendix B) is not part of the format: a record holding one is not valid. What
//! the record does have is parameter values written as the text ECMAScript `Number::toString`
//! would give for a float32 (`f32:0.15`), and the exhaustive test below holds that text over
//! every float32 bit pattern.
// A panicking test is a failing test, so tests may use expect and unwrap.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use sfr_core::json::{Obj, Value, canonical, first_non_canonical_offset, parse};
use sfr_core::ulog::{ParamValue, f32_shortest};

/// A JSON object from (key, value) pairs.
fn object(pairs: &[(&str, Value)]) -> Value {
    let mut o = Obj::new();
    for (k, v) in pairs {
        o = o.field(k, v.clone());
    }
    o.build()
}

#[test]
fn rfc_8785_section_3_2_3_sorts_properties_by_utf16_code_units() {
    // The example of RFC 8785 section 3.2.3, in the order the RFC lists the input.
    let input = object(&[
        ("\u{20ac}", Value::str("Euro Sign")),
        ("\r", Value::str("Carriage Return")),
        ("\u{fb33}", Value::str("Hebrew Letter Dalet With Dagesh")),
        ("1", Value::str("One")),
        ("\u{1f600}", Value::str("Emoji: Grinning Face")),
        ("\u{80}", Value::str("Control")),
        ("\u{f6}", Value::str("Latin Small Letter O With Diaeresis")),
    ]);
    // The RFC's expected order: CR, "1", U+0080, U+00F6, U+20AC, U+1F600 (surrogate D83D), U+FB33.
    let expected = "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u{80}\":\"Control\",\
        \"\u{f6}\":\"Latin Small Letter O With Diaeresis\",\"\u{20ac}\":\"Euro Sign\",\
        \"\u{1f600}\":\"Emoji: Grinning Face\",\
        \"\u{fb33}\":\"Hebrew Letter Dalet With Dagesh\"}";
    assert_eq!(canonical(&input), expected);
    // And the same bytes parse back to the same value and are canonical.
    let parsed = parse(expected.as_bytes()).unwrap();
    assert_eq!(parsed, input);
    assert_eq!(
        first_non_canonical_offset(expected.as_bytes(), &parsed),
        None
    );
}

#[test]
fn rfc_8785_section_3_2_2_strings_and_literals_as_the_rfc_prints_them() {
    // The string, literals and key order of the RFC's section 3.2.2 example, whose input holds
    // `"\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/"`: Euro, dollar, SI, LF, A, apostrophe, B,
    // quote, backslash, backslash, quote, slash. Its canonical output is
    // `"€$\u000f\nA'B\"\\\\\"/"`. (The example's `numbers` member holds floating-point numbers,
    // which the record's value model does not have; see the next test.)
    let value = object(&[
        (
            "literals",
            Value::Array(vec![Value::Null, Value::Bool(true), Value::Bool(false)]),
        ),
        ("string", Value::str("\u{20ac}$\u{f}\nA'B\"\\\\\"/")),
    ]);
    assert_eq!(
        canonical(&value),
        "{\"literals\":[null,true,false],\"string\":\"\u{20ac}$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"}"
    );
    // The input form with escapes parses to the same value, and is not canonical.
    let input = br#"{"literals":[null,true,false],"string":"\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/"}"#;
    let parsed = parse(input).unwrap();
    assert_eq!(parsed, value);
    assert!(first_non_canonical_offset(input, &parsed).is_some());
}

#[test]
fn strings_are_escaped_exactly_as_json_stringify_does() {
    // ECMAScript JSON.stringify (and so RFC 8785 section 3.2.2.2): `"` `\` and the five short
    // escapes, every other control character as lowercase \u00xx, nothing else escaped. In
    // particular DEL, U+2028, U+2029 and non-BMP characters are written as themselves.
    let mut all: Vec<char> = (0u32..0x20).filter_map(char::from_u32).collect();
    all.extend([
        '"',
        '\\',
        '\u{7f}',
        '\u{2028}',
        '\u{2029}',
        '\u{1f600}',
        '\u{ffff}',
    ]);
    let s: String = all.iter().collect();
    let expected = "\"\\u0000\\u0001\\u0002\\u0003\\u0004\\u0005\\u0006\\u0007\\b\\t\\n\\u000b\\f\\r\
        \\u000e\\u000f\\u0010\\u0011\\u0012\\u0013\\u0014\\u0015\\u0016\\u0017\\u0018\\u0019\\u001a\
        \\u001b\\u001c\\u001d\\u001e\\u001f\\\"\\\\\u{7f}\u{2028}\u{2029}\u{1f600}\u{ffff}\"";
    assert_eq!(canonical(&Value::str(s.clone())), expected);
    assert_eq!(parse(expected.as_bytes()).unwrap(), Value::str(s));
}

#[test]
fn what_the_record_does_not_have_is_refused_not_rewritten() {
    // No floating-point numbers, so RFC 8785's number serialization is never needed: any number
    // with a fraction or exponent, a leading zero or plus, a negative zero, or an integer
    // outside +-(2^53 - 1) is refused when read.
    for bad in [
        "1.0",
        "1e3",
        "1E3",
        "0.5",
        "-0",
        "-0.0",
        "+1",
        "01",
        "00",
        "1.",
        ".5",
        "9007199254740992",
        "-9007199254740992",
        "NaN",
        "Infinity",
        "-Infinity",
        "0x10",
        "1e400",
    ] {
        assert!(parse(bad.as_bytes()).is_err(), "{bad} was accepted");
    }
    // The extremes of the allowed range are written as plain decimal integers.
    for (text, n) in [
        ("9007199254740991", 9_007_199_254_740_991_i64),
        ("-9007199254740991", -9_007_199_254_740_991),
        ("0", 0),
    ] {
        assert_eq!(parse(text.as_bytes()).unwrap(), Value::Int(n));
        assert_eq!(canonical(&Value::Int(n)), text);
    }
}

#[test]
fn a_file_is_canonical_only_in_exactly_one_form() {
    let value = object(&[("a", Value::Int(1)), ("b", Value::str("x"))]);
    let good = br#"{"a":1,"b":"x"}"#;
    assert_eq!(first_non_canonical_offset(good, &value), None);
    for (bad, offset) in [
        (&br#"{"b":"x","a":1}"#[..], 2),                // keys out of order
        (&br#"{"a": 1,"b":"x"}"#[..], 5),               // whitespace
        (&br#" {"a":1,"b":"x"}"#[..], 0),               // leading whitespace
        (&b"{\"a\":1,\"b\":\"x\"}\n"[..], 15),          // trailing newline
        (&b"\xef\xbb\xbf{\"a\":1,\"b\":\"x\"}"[..], 0), // byte order mark
        (&br#"{"a":1,"b":"\u0078"}"#[..], 12),          // an escape for a plain character
        (&br#"{"a":1,"b":"\/"}"#[..], 12),              // an escaped slash
    ] {
        // Some of these do not even parse as the record's subset; those that do differ.
        if let Ok(v) = parse(bad) {
            assert_eq!(
                first_non_canonical_offset(bad, &v),
                Some(offset),
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
    }
    // Duplicate keys are refused, wherever they are.
    for dup in [
        r#"{"a":1,"a":2}"#,
        r#"{"a":1,"b":2,"a":3}"#,
        r#"{"x":{"a":1,"a":1}}"#,
    ] {
        assert!(parse(dup.as_bytes()).is_err(), "{dup}");
    }
}

/// The digits and decimal exponent of `v` as the Rust standard library writes the shortest
/// round-trip form (`{:e}`): `(digits, exponent)` with `v = 0.d1d2.. * 10^(exponent + 1)`, or
/// `d1.d2.. * 10^exponent`.
fn std_shortest(v: f32) -> (String, i32) {
    let sci = format!("{v:e}");
    let (mant, exp) = sci.split_once('e').unwrap();
    let digits: String = mant.chars().filter(char::is_ascii_digit).collect();
    (digits, exp.parse().unwrap())
}

/// The digits (no leading or trailing zeros) and the exponent of `d1.d2.. * 10^exponent` for the
/// positional text `f32_shortest` writes (`-0.00123`, `1200`, `12.5`).
fn digits_of(text: &str) -> (String, i32) {
    let t = text.strip_prefix('-').unwrap_or(text);
    let (int, frac) = t.split_once('.').unwrap_or((t, ""));
    let all = format!("{int}{frac}");
    let first = all.find(|c| c != '0').unwrap();
    let digits = all[first..].trim_end_matches('0').to_string();
    // The first significant digit sits `first` places after the first character of `all`; the
    // decimal point is after `int.len()` characters.
    (digits, int.len() as i32 - 1 - first as i32)
}

/// The exact decimal expansion of `v` as (digits without trailing zeros, exponent of the first
/// digit). Rust prints a float exactly when asked for enough digits; a float32 has at most 112
/// significant decimal digits.
fn exact_digits(v: f32) -> (String, i32) {
    let sci = format!("{v:.150e}");
    let (mant, exp) = sci.split_once('e').unwrap();
    let digits: String = mant.chars().filter(char::is_ascii_digit).collect();
    (
        digits.trim_end_matches('0').to_string(),
        exp.parse().unwrap(),
    )
}

/// When the exact expansion of `v` is one digit longer than `n` digits and ends in 5, the two
/// `n`-digit decimals around it are equally close to `v`: ECMAScript `Number::toString` (and so
/// the record) takes the even one, while the standard library's shortest formatting rounds the
/// tie up. Returns the even candidate's digits, or `None` when `v` is not such a tie.
fn tie_choice(v: f32, n: usize) -> Option<(String, i32)> {
    let (exact, exp) = exact_digits(v);
    if exact.len() != n + 1 || !exact.ends_with('5') {
        return None;
    }
    let low: u64 = exact[..n].parse().ok()?;
    let chosen = if low.is_multiple_of(2) { low } else { low + 1 };
    let text = chosen.to_string();
    // A carry (999 + 1) adds a digit and one to the exponent.
    let exp = exp + i32::from(text.len() > n);
    Some((text.trim_end_matches('0').to_string(), exp))
}

/// How many patterns were exact ties that ECMAScript resolves to the even digit.
static TIES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Checks one float32 against the references; returns a description of the first disagreement.
fn check_one(bits: u32) -> Option<String> {
    let v = f32::from_bits(bits);
    if v.is_nan() || v.is_infinite() {
        return None;
    }
    let ours = f32_shortest(v);
    // 1. It reads back as exactly this float32.
    match ours.parse::<f32>() {
        Ok(back) if back.to_bits() == bits => {}
        other => return Some(format!("{bits:#010x}: {ours} reads back as {other:?}")),
    }
    // 2. Positional notation only: no exponent, no plus sign, no trailing fraction zero.
    if ours.contains(['e', 'E', '+']) || (ours.contains('.') && ours.ends_with('0')) {
        return Some(format!("{bits:#010x}: {ours} is not plain positional"));
    }
    if v == 0.0 {
        let want = if bits == 0 { "0" } else { "-0" };
        return (ours != want).then(|| format!("{bits:#010x}: {ours}, want {want}"));
    }
    // 3. The same digits and exponent as the standard library's shortest round-trip form: no
    //    shorter digit string reads back, and among the shortest it is the closest to v.
    let (std_digits, std_exp) = std_shortest(v);
    let (our_digits, our_exp) = digits_of(&ours);
    let std_digits = std_digits.trim_end_matches('0').to_string();
    if our_digits != std_digits || our_exp != std_exp {
        // The only allowed difference is an exact tie, where ECMAScript takes the even digit.
        if tie_choice(v, std_digits.len()) == Some((our_digits.clone(), our_exp)) {
            TIES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return None;
        }
        return Some(format!(
            "{bits:#010x}: {ours} has digits {our_digits} e{our_exp}, the standard library has {std_digits} e{std_exp}"
        ));
    }
    None
}

/// A float32 bit pattern for every exponent with the mantissas at the edges, where shortest
/// round-trip formatting is hardest (the spacing changes at every power of two), both signs.
fn edge_patterns() -> Vec<u32> {
    let mut out = Vec::new();
    for sign in [0u32, 0x8000_0000] {
        for exp in 0u32..255 {
            for mant in [
                0u32, 1, 2, 3, 0x40_0000, 0x7f_fffe, 0x7f_ffff, 0x12_3456, 0x55_5555,
            ] {
                out.push(sign | (exp << 23) | mant);
            }
        }
    }
    out
}

#[test]
fn float32_text_is_shortest_closest_and_reads_back_for_a_large_sample() {
    // Every 4099th bit pattern (about a million, spread over every exponent), the edges of every
    // exponent, and every pattern of the first and last 100,000 of each sign.
    let mut bad = Vec::new();
    let mut checked = 0u64;
    let mut bits = 0u32;
    loop {
        if let Some(why) = check_one(bits) {
            bad.push(why);
        }
        checked += 1;
        match bits.checked_add(4099) {
            Some(n) => bits = n,
            None => break,
        }
    }
    for b in edge_patterns() {
        checked += 1;
        if let Some(why) = check_one(b) {
            bad.push(why);
        }
    }
    for sign in [0u32, 0x8000_0000] {
        for b in (0..100_000u32).chain(0x7f80_0000 - 100_000..0x7f80_0000) {
            checked += 1;
            if let Some(why) = check_one(sign | b) {
                bad.push(why);
            }
        }
    }
    assert!(checked > 1_000_000, "{checked} patterns");
    assert!(
        bad.is_empty(),
        "{} disagreements, first: {:?}",
        bad.len(),
        &bad[..bad.len().min(5)]
    );
}

/// Every one of the 2^32 float32 bit patterns, on every core: `cargo test --release -p sfr-core
/// --test canonical -- --ignored --nocapture`. Takes under two hours on four cores, so it is not
/// part of `cargo test`; its result for the committed code is stated in `docs/RECORD_FORMAT.md`.
#[test]
#[allow(clippy::print_stdout)] // the count of patterns checked is the evidence; see --nocapture
#[ignore = "exhaustive: 2^32 patterns, under two hours on four cores; run with --release --ignored"]
fn float32_text_is_shortest_closest_and_reads_back_for_every_bit_pattern() {
    let threads = std::thread::available_parallelism().map_or(4, std::num::NonZero::get) as u64;
    let total = 1u64 << 32;
    let per = total / threads + 1;
    let handles: Vec<_> = (0..threads)
        .map(|t| {
            std::thread::spawn(move || {
                let (start, end) = (t * per, ((t + 1) * per).min(total));
                let (mut finite, mut bad) = (0u64, Vec::new());
                for bits in start..end {
                    let bits = bits as u32;
                    if f32::from_bits(bits).is_finite() {
                        finite += 1;
                    }
                    if let Some(why) = check_one(bits)
                        && bad.len() < 20
                    {
                        bad.push(why);
                    }
                }
                (finite, bad)
            })
        })
        .collect();
    let (mut finite, mut bad) = (0u64, Vec::new());
    for h in handles {
        let (f, b) = h.join().unwrap();
        finite += f;
        bad.extend(b);
    }
    println!(
        "float32 bit patterns checked: {total}, finite (including both zeros): {finite}, \
         exact ties resolved to the even digit: {}",
        TIES.load(std::sync::atomic::Ordering::Relaxed)
    );
    assert!(
        bad.is_empty(),
        "disagreements, first: {:?}",
        &bad[..bad.len().min(10)]
    );
}

#[test]
fn every_nan_bit_pattern_is_recorded_as_one_text_and_the_payload_is_not_kept() {
    // A float32 NaN has 2 * (2^23 - 1) = 16,777,214 bit patterns (either sign, any non-zero
    // payload, quiet or signalling). The record writes all of them as `f32:NaN`, so which NaN a
    // log held is not in the record, and all of them read back as a NaN that equals every NaN
    // (`same_as`). This test counts the patterns it ran.
    let mut seen = 0u64;
    for sign in [0u32, 0x8000_0000] {
        for payload in 1u32..0x80_0000 {
            let v = f32::from_bits(sign | 0x7f80_0000 | payload);
            assert!(v.is_nan());
            assert_eq!(ParamValue::F32(v).to_string(), "f32:NaN");
            seen += 1;
        }
    }
    assert_eq!(seen, 16_777_214);
    let back = ParamValue::from_typed("f32:NaN").unwrap();
    for bits in [
        0x7fc0_0000u32,
        0x7f80_0001,
        0xffc0_0000,
        0xffff_ffff,
        0x7fff_ffff,
    ] {
        assert!(
            ParamValue::F32(f32::from_bits(bits)).same_as(&back),
            "{bits:#x}"
        );
    }
    // The two infinities and negative zero are distinct texts; they are not NaN.
    assert_eq!(ParamValue::F32(f32::INFINITY).to_string(), "f32:Infinity");
    assert_eq!(
        ParamValue::F32(f32::NEG_INFINITY).to_string(),
        "f32:-Infinity"
    );
    assert_eq!(ParamValue::F32(-0.0).to_string(), "f32:-0");
}
