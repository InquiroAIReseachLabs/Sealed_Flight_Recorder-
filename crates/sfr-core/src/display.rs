//! Text a person reads (SPEC B1.8): the report, and what `sfr` prints.
//!
//! Values from a log or a record (a file name, a parameter name, a log message) reach a terminal
//! and a Markdown page. Some characters change what the reader sees without showing: the
//! bidirectional controls (U+202A to U+202E and U+2066 to U+2069, the "Trojan Source" class,
//! CVE-2021-42574) reorder text, a zero-width space hides a difference, and a control character
//! such as ESC or CR drives the terminal. This module makes them visible, as `<U+202E>`, so the
//! reader sees that they are there and which they are.
//!
//! The characters are the Unicode general category Format (Cf), the line and paragraph
//! separators (Zl, Zp) and the control characters (Cc). [`FORMAT_CHARACTERS`] is the Cf table;
//! `scripts/check_format_characters.py` holds it to the Unicode database of the Python that runs
//! the checks.

/// The code points of Unicode general category Cf (Format), as inclusive ranges (Unicode 15.1;
/// no later version has added to them). `scripts/check_format_characters.py` checks this table.
pub const FORMAT_CHARACTERS: [(u32, u32); 21] = [
    (0x00AD, 0x00AD),
    (0x0600, 0x0605),
    (0x061C, 0x061C),
    (0x06DD, 0x06DD),
    (0x070F, 0x070F),
    (0x0890, 0x0891),
    (0x08E2, 0x08E2),
    (0x180E, 0x180E),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x2064),
    (0x2066, 0x206F),
    (0xFEFF, 0xFEFF),
    (0xFFF9, 0xFFFB),
    (0x110BD, 0x110BD),
    (0x110CD, 0x110CD),
    (0x13430, 0x1343F),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0001, 0xE0001),
    (0xE0020, 0xE007F),
];

/// Whether `c` is a format character (Unicode general category Cf).
pub fn is_format_character(c: char) -> bool {
    let c = u32::from(c);
    FORMAT_CHARACTERS
        .iter()
        .any(|&(first, last)| (first..=last).contains(&c))
}

/// Whether `c` is hidden or moves the reader's view and so must be shown as a marker: a format
/// character, or the line or paragraph separator (U+2028, U+2029), which break a line in a
/// renderer that honours them. Control characters ([`char::is_control`]) are the other class.
pub fn is_hidden(c: char) -> bool {
    is_format_character(c) || matches!(c, '\u{2028}' | '\u{2029}')
}

/// `c` written out, as `<U+202E>`: at least four hexadecimal digits, in capitals.
pub fn marker(c: char) -> String {
    format!("<U+{:04X}>", u32::from(c))
}

/// `text` with every control character and every [`is_hidden`] character shown as a
/// [`marker`], newlines included: one line of text that cannot move the cursor or reorder.
pub fn visible(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_control() || is_hidden(c) {
                marker(c)
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// Output text for a terminal: `text` as it is, except that every control character other than
/// the newline, and every [`is_hidden`] character, is shown as a [`marker`]. Applied to
/// everything `sfr` prints, since a file name, a parameter name or a log message in it could be
/// built to move the cursor, overwrite a line or reorder what the reader sees.
pub fn terminal_safe(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c != '\n' && (c.is_control() || is_hidden(c)) {
                marker(c)
            } else {
                c.to_string()
            }
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn the_bidirectional_controls_and_other_format_characters_are_shown() {
        // Every bidirectional control: the embeddings and overrides, and the isolates.
        for c in (0x202A..=0x202E).chain(0x2066..=0x2069) {
            let c = char::from_u32(c).unwrap();
            assert!(is_format_character(c), "{c:?}");
            assert_eq!(
                terminal_safe(&format!("a{c}b")),
                format!("a<U+{:04X}>b", u32::from(c))
            );
        }
        for (c, shown) in [
            ('\u{200B}', "<U+200B>"),
            ('\u{200E}', "<U+200E>"),
            ('\u{061C}', "<U+061C>"),
            ('\u{FEFF}', "<U+FEFF>"),
            ('\u{00AD}', "<U+00AD>"),
            ('\u{E0041}', "<U+E0041>"),
            ('\u{2028}', "<U+2028>"),
            ('\u{2029}', "<U+2029>"),
            ('\u{1B}', "<U+001B>"),
            ('\r', "<U+000D>"),
            ('\u{85}', "<U+0085>"),
            ('\u{7F}', "<U+007F>"),
        ] {
            assert_eq!(terminal_safe(&c.to_string()), shown, "{c:?}");
        }
        // Ordinary text, accents, other scripts, emoji and the newline pass unchanged.
        let plain = "PASS \u{e9}t\u{e9} \u{65e5}\u{672c} \u{1f6e9}\u{fe0f}\nR1 \u{a0}ok";
        assert_eq!(terminal_safe(plain), plain);
        // `visible` shows the newline too.
        assert_eq!(visible("a\nb\u{202E}"), "a<U+000A>b<U+202E>");
    }

    #[test]
    fn the_table_is_sorted_and_does_not_overlap() {
        for w in FORMAT_CHARACTERS.windows(2) {
            assert!(w[0].1 < w[1].0, "{w:?}");
        }
        for (first, last) in FORMAT_CHARACTERS {
            assert!(first <= last);
            assert!(char::from_u32(first).is_some() && char::from_u32(last).is_some());
        }
        assert_eq!(
            FORMAT_CHARACTERS
                .iter()
                .map(|(a, b)| b - a + 1)
                .sum::<u32>(),
            170
        );
    }
}
