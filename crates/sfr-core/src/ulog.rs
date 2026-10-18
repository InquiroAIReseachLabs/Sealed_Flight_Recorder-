//! Streaming PX4 ULog reader (file format versions 0 and 1), bounded and panic-free.
//!
//! Design rules from `docs/DIAGNOSTIC.md` item 2.6.4: every read is bounds-checked and errors
//! carry the byte offset; a record whose size exceeds the bytes left is `Truncated`, never padded;
//! formats flatten lazily at subscription time with nesting depth at most 8 and a flattened size
//! of at most 65,535 bytes; unknown incompatible flag bits are rejected; unknown message types
//! are skipped by size; appended sections follow the flag-bits offsets, and a record that
//! crosses an offset is dropped, as pyulog does.
//!
//! The reader is forward-only over any [`Read`]; it never seeks, so the caller can hash every
//! byte as it streams past.
#![deny(clippy::indexing_slicing)]

use std::collections::BTreeMap;
use std::fmt;
use std::io::Read;

/// Maximum nesting depth of message formats (observed maximum in real logs: 2).
pub const MAX_NESTING: usize = 8;
/// A data record payload cannot exceed the 16-bit message size.
pub const MAX_LAYOUT_SIZE: usize = 65_535;
/// Most flattened fields across all subscriptions of one log. Real PX4 logs hold tens of
/// thousands; the cap stops a small crafted file from subscribing thousands of times to a
/// format with 65,535 fields and exhausting memory and time.
pub const MAX_TOTAL_FIELDS: usize = 1_000_000;

const MAGIC: &[u8; 7] = b"ULog\x01\x12\x35";
const INCOMPAT_DATA_APPENDED: u8 = 0x01;

/// Why a log could not be read (SPEC B1.4 exit 3, or exit 4 for an I/O failure).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UlogError {
    /// The file does not start with the ULog magic bytes.
    NotUlog,
    /// The input ended inside a record; `offset` is where that record starts.
    Truncated {
        /// Byte offset of the incomplete record.
        offset: u64,
        /// What was being read.
        what: &'static str,
    },
    /// A record is internally inconsistent.
    Malformed {
        /// Byte offset of the record.
        offset: u64,
        /// What is wrong, naming the field or format.
        reason: String,
    },
    /// The underlying reader failed (not a property of the file's contents).
    Io(String),
}

impl fmt::Display for UlogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UlogError::NotUlog => write!(f, "not a ULog file (bad magic bytes)"),
            UlogError::Truncated { offset, what } => {
                write!(f, "truncated at byte offset {offset}: incomplete {what}")
            }
            UlogError::Malformed { offset, reason } => {
                write!(f, "malformed at byte offset {offset}: {reason}")
            }
            UlogError::Io(e) => write!(f, "read error: {e}"),
        }
    }
}

impl std::error::Error for UlogError {}

fn malformed(offset: u64, reason: impl Into<String>) -> UlogError {
    UlogError::Malformed {
        offset,
        reason: reason.into(),
    }
}

/// A scalar ULog field type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scalar {
    /// `int8_t`
    I8,
    /// `uint8_t`
    U8,
    /// `int16_t`
    I16,
    /// `uint16_t`
    U16,
    /// `int32_t`
    I32,
    /// `uint32_t`
    U32,
    /// `int64_t`
    I64,
    /// `uint64_t`
    U64,
    /// `float`
    F32,
    /// `double`
    F64,
    /// `bool`
    Bool,
    /// `char`
    Char,
}

impl Scalar {
    fn parse(name: &str) -> Option<Scalar> {
        Some(match name {
            "int8_t" => Scalar::I8,
            "uint8_t" => Scalar::U8,
            "int16_t" => Scalar::I16,
            "uint16_t" => Scalar::U16,
            "int32_t" => Scalar::I32,
            "uint32_t" => Scalar::U32,
            "int64_t" => Scalar::I64,
            "uint64_t" => Scalar::U64,
            "float" => Scalar::F32,
            "double" => Scalar::F64,
            "bool" => Scalar::Bool,
            "char" => Scalar::Char,
            _ => return None,
        })
    }

    /// Size in bytes.
    pub fn size(self) -> usize {
        match self {
            Scalar::I8 | Scalar::U8 | Scalar::Bool | Scalar::Char => 1,
            Scalar::I16 | Scalar::U16 => 2,
            Scalar::I32 | Scalar::U32 | Scalar::F32 => 4,
            Scalar::I64 | Scalar::U64 | Scalar::F64 => 8,
        }
    }
}

#[derive(Debug, Clone)]
enum FieldType {
    Scalar(Scalar),
    Nested(String),
}

#[derive(Debug, Clone)]
struct FieldDef {
    ty: FieldType,
    /// `None` for a plain field, `Some(n)` for an array of `n` elements.
    array: Option<usize>,
    name: String,
}

/// One flattened scalar field of a subscribed message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlatField {
    /// Flattened name as pyulog prints it, e.g. `accel_clipping[0]` or `esc[1].esc_rpm`.
    pub name: String,
    /// Byte offset within the data payload (after the 2-byte message id).
    pub offset: usize,
    /// Scalar type.
    pub scalar: Scalar,
}

fn le<const N: usize>(payload: &[u8], offset: usize) -> Option<[u8; N]> {
    payload.get(offset..offset.checked_add(N)?)?.try_into().ok()
}

impl FlatField {
    /// Reads an unsigned integer, bool, or char field, widening to `u64`.
    pub fn read_u64(&self, payload: &[u8]) -> Option<u64> {
        Some(match self.scalar {
            Scalar::U8 | Scalar::Bool | Scalar::Char => {
                u64::from(u8::from_le_bytes(le(payload, self.offset)?))
            }
            Scalar::U16 => u64::from(u16::from_le_bytes(le(payload, self.offset)?)),
            Scalar::U32 => u64::from(u32::from_le_bytes(le(payload, self.offset)?)),
            Scalar::U64 => u64::from_le_bytes(le(payload, self.offset)?),
            _ => return None,
        })
    }

    /// Reads a signed integer field, widening to `i64`.
    pub fn read_i64(&self, payload: &[u8]) -> Option<i64> {
        Some(match self.scalar {
            Scalar::I8 => i64::from(i8::from_le_bytes(le(payload, self.offset)?)),
            Scalar::I16 => i64::from(i16::from_le_bytes(le(payload, self.offset)?)),
            Scalar::I32 => i64::from(i32::from_le_bytes(le(payload, self.offset)?)),
            Scalar::I64 => i64::from_le_bytes(le(payload, self.offset)?),
            _ => return None,
        })
    }

    /// Reads a `float` field.
    pub fn read_f32(&self, payload: &[u8]) -> Option<f32> {
        match self.scalar {
            Scalar::F32 => Some(f32::from_le_bytes(le(payload, self.offset)?)),
            _ => None,
        }
    }

    /// Reads a `bool` (any non-zero byte is true, as in C).
    pub fn read_bool(&self, payload: &[u8]) -> Option<bool> {
        match self.scalar {
            Scalar::Bool => Some(u8::from_le_bytes(le(payload, self.offset)?) != 0),
            _ => None,
        }
    }
}

/// The flattened layout of a subscribed message.
#[derive(Debug, Clone)]
pub struct Layout {
    /// Payload size in bytes (trailing top-level padding excluded, as the logger omits it).
    pub size: usize,
    /// Every flattened scalar field, in layout order.
    pub fields: Vec<FlatField>,
    index: BTreeMap<String, usize>,
}

impl Layout {
    /// Looks up a flattened field by name.
    pub fn field(&self, name: &str) -> Option<&FlatField> {
        self.index.get(name).and_then(|&i| self.fields.get(i))
    }
}

/// A parameter value as ULog stores it (only `int32_t` and `float` exist).
#[derive(Debug, Clone, Copy)]
pub enum ParamValue {
    /// `int32_t`
    I32(i32),
    /// `float`
    F32(f32),
}

impl ParamValue {
    /// Identity of the typed value as the record prints it: the same type and the same float32
    /// bits, except that every NaN equals every other NaN (all print as `f32:NaN`) and -0 does
    /// not equal 0. Used both for change detection and for R3 comparison.
    pub fn same_as(&self, other: &ParamValue) -> bool {
        match (self, other) {
            (ParamValue::I32(a), ParamValue::I32(b)) => a == b,
            (ParamValue::F32(a), ParamValue::F32(b)) => {
                (a.is_nan() && b.is_nan()) || a.to_bits() == b.to_bits()
            }
            _ => false,
        }
    }
}

impl PartialEq for ParamValue {
    fn eq(&self, other: &Self) -> bool {
        self.same_as(other)
    }
}

impl Eq for ParamValue {}

impl fmt::Display for ParamValue {
    /// Typed string form used in the record (SPEC B1.7): `i32:5`, `f32:0.15`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParamValue::I32(v) => write!(f, "i32:{v}"),
            ParamValue::F32(v) if v.is_nan() => write!(f, "f32:NaN"),
            ParamValue::F32(v) if v.is_infinite() => {
                write!(f, "f32:{}Infinity", if *v < 0.0 { "-" } else { "" })
            }
            ParamValue::F32(v) => write!(f, "f32:{}", f32_shortest(*v)),
        }
    }
}

/// The shortest decimal that reads back as `v`, chosen as ECMAScript `Number::toString` chooses
/// digits (fewest digits; then the closest to `v`; an exact tie goes to the even last digit),
/// applied to float32 and written in plain positional notation without an exponent.
///
/// Rust's own `Display` breaks exact ties upward (2.44140625 prints as `2.4414063`); this
/// rule gives `2.4414062`, as Ryu and numpy do, so independent verifiers agree.
pub fn f32_shortest(v: f32) -> String {
    if v == 0.0 {
        return if v.is_sign_negative() {
            "-0".into()
        } else {
            "0".into()
        };
    }
    if !v.is_finite() {
        return format!("{v}");
    }
    for p in 1..=9u32 {
        // Correctly rounded to p significant digits, ties to even.
        let sci = format!("{:.*e}", (p - 1) as usize, v);
        let Some((mant, exp)) = sci.split_once('e') else {
            continue;
        };
        let Ok(exp) = exp.parse::<i32>() else {
            continue;
        };
        let digits: String = mant.chars().filter(char::is_ascii_digit).collect();
        let Ok(m) = digits.parse::<u64>() else {
            continue;
        };
        let (lo, hi) = (10u64.pow(p - 1), 10u64.pow(p));
        let scale = exp - (p as i32 - 1);
        let sign = if v < 0.0 { "-" } else { "" };
        // The closest candidate first; its neighbours can read back as v only next to a power
        // of two, where the spacing of float32 values below v is half the spacing above.
        for c in [Some(m), m.checked_sub(1), m.checked_add(1)]
            .into_iter()
            .flatten()
        {
            if c < lo || c >= hi {
                continue;
            }
            if format!("{sign}{c}e{scale}")
                .parse::<f32>()
                .is_ok_and(|r| r.to_bits() == v.to_bits())
            {
                return positional(sign, c, scale);
            }
        }
    }
    format!("{v}")
}

fn positional(sign: &str, mut c: u64, mut scale: i32) -> String {
    while c != 0 && c.is_multiple_of(10) {
        c /= 10;
        scale += 1;
    }
    let digits = c.to_string();
    if scale >= 0 {
        return format!("{sign}{digits}{}", "0".repeat(scale as usize));
    }
    let frac = (-scale) as usize;
    if digits.len() > frac {
        let (int, rest) = digits.split_at(digits.len() - frac);
        format!("{sign}{int}.{rest}")
    } else {
        format!("{sign}0.{}{digits}", "0".repeat(frac - digits.len()))
    }
}

/// Where a parameter record was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    /// Before the first subscription: the configuration at log start (SPEC B1.5).
    Definitions,
    /// In the data section: a change, or a re-statement of the current value.
    Data,
}

/// The 16-byte file header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// File format version byte (0 or 1).
    pub version: u8,
    /// Logging start timestamp, boot-time microseconds.
    pub timestamp: u64,
}

/// Receives the decoded records in file order.
pub trait Visitor {
    /// The file header was read.
    fn header(&mut self, _header: &Header) {}
    /// An 'I' record; `key_type` is the C type, for example `char[40]` or `uint32_t`.
    fn info(&mut self, _key_type: &str, _key: &str, _value: &[u8]) {}
    /// A 'P' record. `last_timestamp` is the largest data timestamp seen so far (pyulog's rule).
    fn parameter(
        &mut self,
        _name: &str,
        _value: ParamValue,
        _section: Section,
        _last_timestamp: u64,
    ) {
    }
    /// An 'A' record: `msg_id` now carries `topic` instance `multi_id` with this layout.
    fn subscription(&mut self, _msg_id: u16, _multi_id: u8, _topic: &str, _layout: &Layout) {}
    /// A 'D' record for a known subscription.
    fn data(&mut self, _msg_id: u16, _timestamp: u64, _payload: &[u8]) {}
    /// An 'L' (tag `None`) or 'C' record; `level` is the raw ASCII level byte.
    fn logging(&mut self, _level: u8, _tag: Option<u16>, _timestamp: u64, _text: &[u8]) {}
    /// An 'O' record.
    fn dropout(&mut self, _duration_ms: u16, _last_timestamp: u64) {}
}

/// Counts that describe what was read, for the caller's checks and reports.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Summary {
    /// Total bytes consumed (the whole file on success).
    pub bytes: u64,
    /// Number of records, all types.
    pub records: u64,
    /// Data records whose message id had no subscription (skipped).
    pub orphan_data: u64,
    /// Whether the flag bits announced appended data.
    pub data_appended: bool,
}

struct Src<R> {
    inner: R,
    pos: u64,
}

enum Fill {
    Full,
    Eof,
    Partial,
}

impl<R: Read> Src<R> {
    fn fill(&mut self, buf: &mut [u8]) -> Result<Fill, UlogError> {
        let mut got = 0usize;
        while got < buf.len() {
            let rest = buf
                .get_mut(got..)
                .ok_or_else(|| UlogError::Io("buffer".into()))?;
            match self.inner.read(rest) {
                Ok(0) => break,
                Ok(n) => got = got.saturating_add(n),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(UlogError::Io(e.to_string())),
            }
        }
        self.pos = self.pos.saturating_add(got as u64);
        Ok(if got == buf.len() {
            Fill::Full
        } else if got == 0 {
            Fill::Eof
        } else {
            Fill::Partial
        })
    }

    /// Discards bytes up to absolute offset `to` (forward only); stops early at end of input.
    fn skip_to(&mut self, to: u64) -> Result<(), UlogError> {
        let mut scratch = [0u8; 8192];
        while self.pos < to {
            let want =
                usize::try_from((to - self.pos).min(scratch.len() as u64)).unwrap_or(scratch.len());
            let slot = scratch
                .get_mut(..want)
                .ok_or_else(|| UlogError::Io("buffer".into()))?;
            match self.inner.read(slot) {
                Ok(0) => return Ok(()),
                Ok(n) => self.pos = self.pos.saturating_add(n as u64),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(UlogError::Io(e.to_string())),
            }
        }
        Ok(())
    }
}

/// A bounds-checked cursor over one record's body.
struct Cur<'a> {
    buf: &'a [u8],
    at: usize,
    base: u64,
}

impl<'a> Cur<'a> {
    fn new(buf: &'a [u8], base: u64) -> Self {
        Cur { buf, at: 0, base }
    }
    fn take(&mut self, n: usize, what: &str) -> Result<&'a [u8], UlogError> {
        let end = self
            .at
            .checked_add(n)
            .ok_or_else(|| malformed(self.base, format!("{what}: length overflow")))?;
        let s = self
            .buf
            .get(self.at..end)
            .ok_or_else(|| malformed(self.base, format!("{what}: record too short")))?;
        self.at = end;
        Ok(s)
    }
    fn u8(&mut self, what: &str) -> Result<u8, UlogError> {
        let s = self.take(1, what)?;
        s.first()
            .copied()
            .ok_or_else(|| malformed(self.base, format!("{what}: record too short")))
    }
    fn u16(&mut self, what: &str) -> Result<u16, UlogError> {
        let s = self.take(2, what)?;
        Ok(u16::from_le_bytes(
            s.try_into()
                .map_err(|_| malformed(self.base, what.to_string()))?,
        ))
    }
    fn u64(&mut self, what: &str) -> Result<u64, UlogError> {
        let s = self.take(8, what)?;
        Ok(u64::from_le_bytes(
            s.try_into()
                .map_err(|_| malformed(self.base, what.to_string()))?,
        ))
    }
    fn rest(&mut self) -> &'a [u8] {
        let s = self.buf.get(self.at..).unwrap_or(&[]);
        self.at = self.buf.len();
        s
    }
}

fn ascii<'a>(bytes: &'a [u8], offset: u64, what: &str) -> Result<&'a str, UlogError> {
    std::str::from_utf8(bytes).map_err(|_| malformed(offset, format!("{what} is not UTF-8")))
}

/// Parses a type token such as `float`, `float[3]`, or `esc_report[8]`.
fn parse_type(token: &str, offset: u64) -> Result<(FieldType, Option<usize>), UlogError> {
    let (base, array) = match token.split_once('[') {
        Some((b, rest)) => {
            let n = rest
                .strip_suffix(']')
                .ok_or_else(|| malformed(offset, format!("bad array type `{token}`")))?;
            if n.is_empty() || !n.bytes().all(|c| c.is_ascii_digit()) || n.len() > 5 {
                return Err(malformed(offset, format!("bad array length in `{token}`")));
            }
            let len: usize = n
                .parse()
                .map_err(|_| malformed(offset, format!("bad array length in `{token}`")))?;
            if len == 0 || len > MAX_LAYOUT_SIZE {
                return Err(malformed(
                    offset,
                    format!("array length out of range in `{token}`"),
                ));
            }
            (b, Some(len))
        }
        None => (token, None),
    };
    if base.is_empty() {
        return Err(malformed(offset, format!("empty type in `{token}`")));
    }
    let ty = match Scalar::parse(base) {
        Some(s) => FieldType::Scalar(s),
        None => FieldType::Nested(base.to_string()),
    };
    Ok((ty, array))
}

fn parse_format(body: &[u8], offset: u64) -> Result<(String, Vec<FieldDef>), UlogError> {
    let text = ascii(body, offset, "format")?;
    let (name, fields) = text
        .split_once(':')
        .ok_or_else(|| malformed(offset, "format without ':'"))?;
    if name.is_empty() {
        return Err(malformed(offset, "format with empty name"));
    }
    let mut defs = Vec::new();
    for item in fields.split(';').filter(|s| !s.is_empty()) {
        let (ty, fname) = item.split_once(' ').ok_or_else(|| {
            malformed(
                offset,
                format!("format `{name}`: field `{item}` has no name"),
            )
        })?;
        if fname.is_empty() {
            return Err(malformed(
                offset,
                format!("format `{name}`: empty field name"),
            ));
        }
        let (ty, array) = parse_type(ty, offset)?;
        defs.push(FieldDef {
            ty,
            array,
            name: fname.to_string(),
        });
    }
    Ok((name.to_string(), defs))
}

struct Flattener<'a> {
    formats: &'a BTreeMap<String, Vec<FieldDef>>,
    out: Vec<FlatField>,
    offset: u64,
}

impl Flattener<'_> {
    /// Appends the fields of `defs` at byte position `base`; returns the size consumed.
    fn walk(
        &mut self,
        defs: &[FieldDef],
        prefix: &str,
        base: usize,
        depth: usize,
    ) -> Result<usize, UlogError> {
        if depth > MAX_NESTING {
            return Err(malformed(
                self.offset,
                format!("format nesting deeper than {MAX_NESTING}"),
            ));
        }
        let mut pos = base;
        for def in defs {
            let count = def.array.unwrap_or(1);
            for i in 0..count {
                let name = match def.array {
                    Some(_) => format!("{prefix}{}[{i}]", def.name),
                    None => format!("{prefix}{}", def.name),
                };
                match &def.ty {
                    FieldType::Scalar(s) => {
                        self.out.push(FlatField {
                            name,
                            offset: pos,
                            scalar: *s,
                        });
                        pos = pos
                            .checked_add(s.size())
                            .filter(|&p| p <= MAX_LAYOUT_SIZE)
                            .ok_or_else(|| {
                                malformed(self.offset, "flattened format larger than 65535 bytes")
                            })?;
                    }
                    FieldType::Nested(t) => {
                        let inner = self.formats.get(t).ok_or_else(|| {
                            malformed(self.offset, format!("unknown field type `{t}`"))
                        })?;
                        let used = self.walk(inner, &format!("{name}."), pos, depth + 1)?;
                        if used == 0 {
                            return Err(malformed(
                                self.offset,
                                format!("zero-size nested type `{t}`"),
                            ));
                        }
                        pos = pos
                            .checked_add(used)
                            .filter(|&p| p <= MAX_LAYOUT_SIZE)
                            .ok_or_else(|| {
                                malformed(self.offset, "flattened format larger than 65535 bytes")
                            })?;
                    }
                }
                if self.out.len() > MAX_LAYOUT_SIZE {
                    return Err(malformed(self.offset, "more than 65535 flattened fields"));
                }
            }
        }
        Ok(pos - base)
    }
}

fn flatten(
    formats: &BTreeMap<String, Vec<FieldDef>>,
    topic: &str,
    offset: u64,
) -> Result<Layout, UlogError> {
    let defs = formats.get(topic).ok_or_else(|| {
        malformed(
            offset,
            format!("subscription to undefined format `{topic}`"),
        )
    })?;
    // The logger omits trailing top-level padding from data records (ULog spec); nested
    // padding stays because it is part of the nested struct's size.
    let mut top: &[FieldDef] = defs;
    while let Some((last, rest)) = top.split_last() {
        if last.name.starts_with("_padding") {
            top = rest;
        } else {
            break;
        }
    }
    let mut fl = Flattener {
        formats,
        out: Vec::new(),
        offset,
    };
    let size = fl.walk(top, "", 0, 0)?;
    let mut index = BTreeMap::new();
    for (i, f) in fl.out.iter().enumerate() {
        index.entry(f.name.clone()).or_insert(i);
    }
    let layout = Layout {
        size,
        fields: fl.out,
        index,
    };
    match layout.field("timestamp") {
        Some(f) if f.scalar == Scalar::U64 => Ok(layout),
        _ => Err(malformed(
            offset,
            format!("format `{topic}` has no uint64_t timestamp"),
        )),
    }
}

struct Sub {
    layout: Layout,
    ts: FlatField,
}

/// Reads a whole ULog stream, calling `visitor` for each record in file order.
pub fn read<R: Read, V: Visitor>(input: R, visitor: &mut V) -> Result<Summary, UlogError> {
    let mut src = Src {
        inner: input,
        pos: 0,
    };
    let mut hdr = [0u8; 16];
    match src.fill(&mut hdr)? {
        Fill::Full => {}
        Fill::Eof => {
            return Err(UlogError::Truncated {
                offset: 0,
                what: "file header (empty file)",
            });
        }
        Fill::Partial => {
            return Err(UlogError::Truncated {
                offset: 0,
                what: "file header",
            });
        }
    }
    let mut hc = Cur::new(&hdr, 0);
    if hc.take(7, "magic")? != MAGIC {
        return Err(UlogError::NotUlog);
    }
    let header = Header {
        version: hc.u8("version")?,
        timestamp: hc.u64("start timestamp")?,
    };
    visitor.header(&header);

    let mut summary = Summary::default();
    let mut formats: BTreeMap<String, Vec<FieldDef>> = BTreeMap::new();
    let mut subs: BTreeMap<u16, Sub> = BTreeMap::new();
    let mut pending: Vec<u64> = Vec::new();
    let mut first = true;
    let mut in_definitions = true;
    let mut last_ts = header.timestamp;
    let mut body: Vec<u8> = Vec::with_capacity(4096);
    let mut field_budget = MAX_TOTAL_FIELDS;

    loop {
        while pending.first().is_some_and(|&o| src.pos >= o) {
            pending.remove(0);
        }
        let start = src.pos;
        if let Some(&off) = pending.first()
            && start.saturating_add(3) > off
        {
            src.skip_to(off)?;
            continue;
        }
        let mut mh = [0u8; 3];
        match src.fill(&mut mh)? {
            Fill::Full => {}
            Fill::Eof => break,
            Fill::Partial => {
                return Err(UlogError::Truncated {
                    offset: start,
                    what: "record header",
                });
            }
        }
        let [s0, s1, ty] = mh;
        let size = usize::from(u16::from_le_bytes([s0, s1]));
        if let Some(&off) = pending.first()
            && start.saturating_add(3).saturating_add(size as u64) > off
        {
            // A record crossing an appended-data offset is dropped (pyulog behaviour).
            src.skip_to(off)?;
            continue;
        }
        body.resize(size, 0);
        match src.fill(&mut body)? {
            Fill::Full => {}
            Fill::Eof | Fill::Partial => {
                return Err(UlogError::Truncated {
                    offset: start,
                    what: record_name(ty),
                });
            }
        }
        summary.records = summary.records.saturating_add(1);
        let was_first = std::mem::replace(&mut first, false);
        let mut c = Cur::new(&body, start);
        match ty {
            b'B' => {
                if !was_first {
                    return Err(malformed(start, "flag bits record is not the first record"));
                }
                let _compat = c.take(8, "compat flags")?;
                let incompat = c.take(8, "incompat flags")?;
                let (head, tail) = incompat
                    .split_first()
                    .ok_or_else(|| malformed(start, "incompat flags"))?;
                if head & !INCOMPAT_DATA_APPENDED != 0 || tail.iter().any(|&b| b != 0) {
                    return Err(malformed(start, "unknown incompatible flag bits set"));
                }
                let mut offs = Vec::new();
                for _ in 0..3 {
                    offs.push(c.u64("appended offset")?);
                }
                if head & INCOMPAT_DATA_APPENDED != 0 {
                    summary.data_appended = true;
                    pending = offs.into_iter().filter(|&o| o != 0).collect();
                    pending.sort_unstable();
                }
            }
            b'F' => {
                let (name, defs) = parse_format(&body, start)?;
                formats.insert(name, defs);
            }
            b'I' => {
                let klen = usize::from(c.u8("info key length")?);
                let key = ascii(c.take(klen, "info key")?, start, "info key")?;
                let (key_type, key_name) = key.split_once(' ').unwrap_or(("", key));
                visitor.info(key_type, key_name, c.rest());
            }
            b'M' => {
                let _continued = c.u8("multi info flag")?;
                let klen = usize::from(c.u8("multi info key length")?);
                let _key = c.take(klen, "multi info key")?;
            }
            b'P' => {
                let klen = usize::from(c.u8("parameter key length")?);
                let key = ascii(c.take(klen, "parameter key")?, start, "parameter key")?;
                let (ptype, name) = key.split_once(' ').ok_or_else(|| {
                    malformed(start, format!("parameter key `{key}` has no type"))
                })?;
                let raw = c.take(4, "parameter value")?;
                let raw: [u8; 4] = raw
                    .try_into()
                    .map_err(|_| malformed(start, "parameter value"))?;
                let value = match ptype {
                    "int32_t" => ParamValue::I32(i32::from_le_bytes(raw)),
                    "float" => ParamValue::F32(f32::from_le_bytes(raw)),
                    other => {
                        return Err(malformed(
                            start,
                            format!("parameter `{name}` has unsupported type `{other}`"),
                        ));
                    }
                };
                let section = if in_definitions {
                    Section::Definitions
                } else {
                    Section::Data
                };
                visitor.parameter(name, value, section, last_ts);
            }
            b'Q' => {
                let _types = c.u8("default parameter types")?;
                let klen = usize::from(c.u8("default parameter key length")?);
                let _key = c.take(klen, "default parameter key")?;
            }
            b'A' => {
                in_definitions = false;
                let multi_id = c.u8("subscription multi id")?;
                let msg_id = c.u16("subscription message id")?;
                let topic = ascii(c.rest(), start, "subscription name")?.to_string();
                if subs.contains_key(&msg_id) {
                    return Err(malformed(
                        start,
                        format!("message id {msg_id} subscribed twice"),
                    ));
                }
                let layout = flatten(&formats, &topic, start)?;
                field_budget = field_budget.checked_sub(layout.fields.len()).ok_or_else(|| {
                    malformed(
                        start,
                        format!("more than {MAX_TOTAL_FIELDS} flattened fields across all subscriptions"),
                    )
                })?;
                let ts = layout.field("timestamp").cloned().ok_or_else(|| {
                    malformed(start, format!("format `{topic}` has no timestamp"))
                })?;
                visitor.subscription(msg_id, multi_id, &topic, &layout);
                subs.insert(msg_id, Sub { layout, ts });
            }
            b'R' => {}
            b'D' => {
                let msg_id = c.u16("data message id")?;
                let payload = c.rest();
                match subs.get(&msg_id) {
                    Some(sub) => {
                        if payload.len() < sub.layout.size {
                            return Err(malformed(
                                start,
                                format!(
                                    "data record for message id {msg_id} has {} bytes, format needs {}",
                                    payload.len(),
                                    sub.layout.size
                                ),
                            ));
                        }
                        let ts = sub
                            .ts
                            .read_u64(payload)
                            .ok_or_else(|| malformed(start, "data record timestamp"))?;
                        if ts > last_ts {
                            last_ts = ts;
                        }
                        visitor.data(msg_id, ts, payload);
                    }
                    None => summary.orphan_data = summary.orphan_data.saturating_add(1),
                }
            }
            b'L' => {
                let level = c.u8("log level")?;
                let ts = c.u64("log timestamp")?;
                visitor.logging(level, None, ts, c.rest());
            }
            b'C' => {
                let level = c.u8("tagged log level")?;
                let tag = c.u16("tagged log tag")?;
                let ts = c.u64("tagged log timestamp")?;
                visitor.logging(level, Some(tag), ts, c.rest());
            }
            b'S' => {}
            b'O' => {
                let duration = c.u16("dropout duration")?;
                visitor.dropout(duration, last_ts);
            }
            _ => {}
        }
    }
    summary.bytes = src.pos;
    Ok(summary)
}

fn record_name(ty: u8) -> &'static str {
    match ty {
        b'B' => "flag bits record",
        b'F' => "format record",
        b'I' => "info record",
        b'M' => "multi info record",
        b'P' => "parameter record",
        b'Q' => "default parameter record",
        b'A' => "subscription record",
        b'R' => "unsubscription record",
        b'D' => "data record",
        b'L' => "logged string record",
        b'C' => "tagged logged string record",
        b'S' => "sync record",
        b'O' => "dropout record",
        _ => "record",
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
    use super::*;

    /// Builds a minimal ULog byte stream for tests.
    pub(crate) struct Builder {
        pub bytes: Vec<u8>,
    }

    impl Builder {
        pub fn new(ts: u64) -> Self {
            let mut bytes = MAGIC.to_vec();
            bytes.push(1);
            bytes.extend_from_slice(&ts.to_le_bytes());
            Builder { bytes }
        }
        pub fn rec(mut self, ty: u8, body: &[u8]) -> Self {
            self.bytes
                .extend_from_slice(&(body.len() as u16).to_le_bytes());
            self.bytes.push(ty);
            self.bytes.extend_from_slice(body);
            self
        }
        pub fn flags(self, appended: &[u64]) -> Self {
            let mut b = vec![0u8; 8];
            let mut inc = vec![0u8; 8];
            if !appended.is_empty() {
                inc[0] = 1;
            }
            b.extend_from_slice(&inc);
            for i in 0..3 {
                b.extend_from_slice(&appended.get(i).copied().unwrap_or(0).to_le_bytes());
            }
            self.rec(b'B', &b)
        }
        pub fn format(self, f: &str) -> Self {
            self.rec(b'F', f.as_bytes())
        }
        pub fn param_f(self, name: &str, v: f32) -> Self {
            let key = format!("float {name}");
            let mut b = vec![key.len() as u8];
            b.extend_from_slice(key.as_bytes());
            b.extend_from_slice(&v.to_le_bytes());
            self.rec(b'P', &b)
        }
        pub fn sub(self, multi: u8, id: u16, name: &str) -> Self {
            let mut b = vec![multi];
            b.extend_from_slice(&id.to_le_bytes());
            b.extend_from_slice(name.as_bytes());
            self.rec(b'A', &b)
        }
        pub fn data(self, id: u16, payload: &[u8]) -> Self {
            let mut b = id.to_le_bytes().to_vec();
            b.extend_from_slice(payload);
            self.rec(b'D', &b)
        }
    }

    #[derive(Default)]
    struct Collect {
        params: Vec<(String, String, Section, u64)>,
        data: Vec<(u16, u64, usize)>,
        subs: Vec<(u16, String, usize)>,
    }

    impl Visitor for Collect {
        fn parameter(&mut self, name: &str, value: ParamValue, section: Section, last: u64) {
            self.params
                .push((name.into(), value.to_string(), section, last));
        }
        fn subscription(&mut self, msg_id: u16, _m: u8, topic: &str, layout: &Layout) {
            self.subs.push((msg_id, topic.into(), layout.size));
        }
        fn data(&mut self, msg_id: u16, ts: u64, payload: &[u8]) {
            self.data.push((msg_id, ts, payload.len()));
        }
    }

    fn sample() -> Builder {
        Builder::new(1000)
            .flags(&[])
            .format("pos:uint64_t timestamp;float[2] xy;uint8_t _padding0[4];")
            .param_f("MC_ROLL_P", 6.5)
            .sub(0, 7, "pos")
            .data(
                7,
                &[
                    &2000u64.to_le_bytes()[..],
                    &1f32.to_le_bytes(),
                    &2f32.to_le_bytes(),
                ]
                .concat(),
            )
            .param_f("MC_ROLL_P", 7.0)
    }

    #[test]
    fn reads_records_and_drops_trailing_padding() {
        let mut v = Collect::default();
        let s = read(&sample().bytes[..], &mut v).unwrap();
        assert_eq!(
            v.subs,
            vec![(7, "pos".into(), 16)],
            "trailing _padding0 not part of the data size"
        );
        assert_eq!(v.data, vec![(7, 2000, 16)]);
        assert_eq!(
            v.params[0],
            (
                "MC_ROLL_P".into(),
                "f32:6.5".into(),
                Section::Definitions,
                1000
            )
        );
        assert_eq!(
            v.params[1],
            ("MC_ROLL_P".into(), "f32:7".into(), Section::Data, 2000)
        );
        assert_eq!(s.bytes, sample().bytes.len() as u64);
    }

    #[test]
    fn every_truncation_is_an_error_never_a_panic() {
        let full = sample().bytes;
        for cut in 0..full.len() {
            let r = read(&full[..cut], &mut Collect::default());
            // Cutting exactly at a record boundary is indistinguishable from a complete file.
            if let Err(e) = r {
                assert!(
                    matches!(e, UlogError::Truncated { .. } | UlogError::NotUlog),
                    "cut {cut}: {e}"
                );
            }
        }
    }

    #[test]
    fn rejects_unknown_incompat_bits() {
        let mut b = vec![0u8; 8];
        b.extend_from_slice(&[2, 0, 0, 0, 0, 0, 0, 0]);
        b.extend_from_slice(&[0u8; 24]);
        let bytes = Builder::new(0).rec(b'B', &b).bytes;
        let e = read(&bytes[..], &mut Collect::default()).unwrap_err();
        assert!(
            e.to_string().contains("unknown incompatible flag bits"),
            "{e}"
        );
    }

    #[test]
    fn rejects_self_nesting_and_zero_arrays_and_short_data() {
        let nest = Builder::new(0)
            .format("a:uint64_t timestamp;a inner;")
            .sub(0, 1, "a")
            .bytes;
        let e = read(&nest[..], &mut Collect::default()).unwrap_err();
        assert!(e.to_string().contains("nesting deeper"), "{e}");

        let zero = Builder::new(0)
            .format("a:uint64_t timestamp;float[0] x;")
            .bytes;
        let e = read(&zero[..], &mut Collect::default()).unwrap_err();
        assert!(e.to_string().contains("array length out of range"), "{e}");

        let short = Builder::new(0)
            .format("a:uint64_t timestamp;float x;")
            .sub(0, 1, "a")
            .data(1, &5u64.to_le_bytes())
            .bytes;
        let e = read(&short[..], &mut Collect::default()).unwrap_err();
        assert!(e.to_string().contains("format needs 12"), "{e}");
    }

    #[test]
    fn appended_offset_drops_the_crossing_record() {
        // Build the main part, then garbage that a crossing record would swallow, then the
        // appended section starting exactly at the announced offset.
        let main = Builder::new(0)
            .flags(&[0])
            .format("a:uint64_t timestamp;")
            .sub(0, 1, "a");
        let mut bytes = main.data(1, &10u64.to_le_bytes()).bytes;
        let offset_of_append = bytes.len() as u64 + 5;
        // Rewrite the flag bits with the real offset (bytes 16 + 3 + 16 .. + 8).
        bytes[16 + 3 + 8] = 1;
        bytes[16 + 3 + 16..16 + 3 + 24].copy_from_slice(&offset_of_append.to_le_bytes());
        // A record header announcing 100 bytes: it would cross the offset, so it is dropped.
        bytes.extend_from_slice(&[100, 0, b'D', 0, 0]);
        let appended = Builder { bytes: Vec::new() }
            .data(1, &20u64.to_le_bytes())
            .bytes;
        bytes.extend_from_slice(&appended);
        let mut v = Collect::default();
        let s = read(&bytes[..], &mut v).unwrap();
        assert!(s.data_appended);
        assert_eq!(v.data.iter().map(|d| d.1).collect::<Vec<_>>(), vec![10, 20]);
    }

    #[test]
    fn total_flattened_fields_are_capped() {
        // One format with 60,001 fields, subscribed 20 times: 1.2 million fields in all.
        let mut b = Builder::new(0)
            .flags(&[])
            .format("wide:uint64_t timestamp;uint8_t[60000] x;");
        for id in 0..20u16 {
            b = b.sub(0, id, "wide");
        }
        let err = read(&b.bytes[..], &mut Collect::default()).expect_err("over the cap");
        assert!(
            err.to_string()
                .contains("flattened fields across all subscriptions"),
            "{err}"
        );
        // Sixteen subscriptions (960,016 fields) are still accepted.
        let mut b = Builder::new(0)
            .flags(&[])
            .format("wide:uint64_t timestamp;uint8_t[60000] x;");
        for id in 0..16u16 {
            b = b.sub(0, id, "wide");
        }
        read(&b.bytes[..], &mut Collect::default()).expect("under the cap");
    }

    #[test]
    fn param_display_is_typed_and_shortest() {
        assert_eq!(ParamValue::F32(0.15).to_string(), "f32:0.15");
        assert_eq!(ParamValue::F32(625.0 / 256.0).to_string(), "f32:2.4414062");
        assert_eq!(ParamValue::F32(-0.0).to_string(), "f32:-0");
        assert_eq!(ParamValue::F32(1.0e-5).to_string(), "f32:0.00001");
        assert_eq!(
            ParamValue::F32(1.0e30).to_string(),
            "f32:1000000000000000000000000000000"
        );
        assert_eq!(
            ParamValue::F32(f32::from_bits(1)).to_string(),
            "f32:0.000000000000000000000000000000000000000000001"
        );
        assert_eq!(
            ParamValue::F32(f32::MAX).to_string(),
            "f32:340282350000000000000000000000000000000"
        );
        assert_eq!(ParamValue::F32(1.0).to_string(), "f32:1");
        assert_eq!(ParamValue::F32(f32::NAN).to_string(), "f32:NaN");
        assert_eq!(ParamValue::I32(-3).to_string(), "i32:-3");
        assert!(!ParamValue::F32(0.0).same_as(&ParamValue::F32(-0.0)));
        assert!(!ParamValue::F32(1.0).same_as(&ParamValue::I32(1)));
    }
}
