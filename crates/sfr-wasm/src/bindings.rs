//! The functions the sandbox page calls (`site/worker.js`), through `wasm-bindgen`.
//!
//! Each one returns an [`Outcome`] and never throws: a failure is an exit code and the CLI's
//! message. Files reach the engine whole (`Uint8Array`) or, for the log, through a
//! [`ByteSource`] the page reads on demand, so a 100 MiB log is never copied whole into this
//! module's memory. A panic aborts, which the browser reports as a WebAssembly trap; the panic
//! hook keeps its message for [`last_panic`], so the page can say what happened.

use crate::{Input, Key, SealRequest, Stream, VerifyRequest};
use std::io::{self, BufReader, Read};
use std::sync::Mutex;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    /// A file the page reads for the engine, from start to end: `read(buf)` fills the start of
    /// `buf` with the next bytes and returns how many, 0 at the end; it throws a message string
    /// when the browser cannot read the file.
    pub type ByteSource;

    #[wasm_bindgen(method, catch)]
    fn read(this: &ByteSource, buf: &mut [u8]) -> Result<u32, JsValue>;
}

/// [`ByteSource`] as a [`Read`].
struct JsReader<'a>(&'a ByteSource);

impl Read for JsReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.0.read(buf) {
            Ok(n) if n as usize <= buf.len() => Ok(n as usize),
            Ok(n) => Err(io::Error::other(format!(
                "the page returned {n} bytes for a read of {}",
                buf.len()
            ))),
            Err(e) => {
                Err(io::Error::other(e.as_string().unwrap_or_else(|| {
                    "the browser could not read the file".to_string()
                })))
            }
        }
    }
}

/// One call into the page in each mebibyte of the log, not one in each 64 KiB the engine asks.
const READ_CHUNK: usize = 1 << 20;

static LAST_PANIC: Mutex<String> = Mutex::new(String::new());

/// Keeps a panic's message for [`last_panic`]; the panic then aborts (a trap).
#[wasm_bindgen(start)]
fn start() {
    std::panic::set_hook(Box::new(|info| {
        if let Ok(mut last) = LAST_PANIC.lock() {
            *last = info.to_string();
        }
    }));
}

/// The message of the panic that ended the last call in a trap, or empty. A panic is a bug:
/// the engine is built to return an error for every input (CLAUDEME section 5).
#[wasm_bindgen(js_name = lastPanic)]
pub fn last_panic() -> String {
    LAST_PANIC.lock().map(|s| s.clone()).unwrap_or_default()
}

/// The result of a call: an exit code (SPEC B1.4) and what the CLI would print and write.
#[wasm_bindgen]
#[derive(Debug, Default)]
pub struct Outcome {
    code: i32,
    message: String,
    headline: String,
    text: String,
    notes: String,
    record: Vec<u8>,
    record_name: String,
    report: String,
    report_name: String,
}

#[wasm_bindgen]
impl Outcome {
    /// SPEC B1.4 exit code.
    #[wasm_bindgen(getter)]
    pub fn code(&self) -> i32 {
        self.code
    }
    /// The CLI's message for a failure (exit 3 or 4, and 1 from verify); empty otherwise.
    #[wasm_bindgen(getter)]
    pub fn message(&self) -> String {
        self.message.clone()
    }
    /// Verify: `VERIFIED (...)` or `FAILED: <first mismatch>`. Key: the fingerprint.
    #[wasm_bindgen(getter)]
    pub fn headline(&self) -> String {
        self.headline.clone()
    }
    /// What the CLI prints on standard output. Key: the public key PEM. Version: the text.
    #[wasm_bindgen(getter)]
    pub fn text(&self) -> String {
        self.text.clone()
    }
    /// Notes the CLI prints on standard error, one per line.
    #[wasm_bindgen(getter)]
    pub fn notes(&self) -> String {
        self.notes.clone()
    }
    /// Seal: the record's bytes.
    #[wasm_bindgen(getter)]
    pub fn record(&self) -> Vec<u8> {
        self.record.clone()
    }
    /// Seal: `<log stem>.sfr`.
    #[wasm_bindgen(getter, js_name = recordName)]
    pub fn record_name(&self) -> String {
        self.record_name.clone()
    }
    /// Seal: the Markdown report.
    #[wasm_bindgen(getter)]
    pub fn report(&self) -> String {
        self.report.clone()
    }
    /// Seal: `<log stem>.sfr.md`.
    #[wasm_bindgen(getter, js_name = reportName)]
    pub fn report_name(&self) -> String {
        self.report_name.clone()
    }
}

fn failed(f: crate::Failure) -> Outcome {
    Outcome {
        code: f.code,
        message: f.message,
        ..Outcome::default()
    }
}

/// A JavaScript number of bytes as `u64`. A browser reports a file's size as a whole number up
/// to 2^53; anything else counts as over every limit, so it is refused before a read.
fn byte_count(size: f64) -> u64 {
    const MAX_SAFE: f64 = 9_007_199_254_740_992.0;
    if (0.0..=MAX_SAFE).contains(&size) && size.fract() == 0.0 {
        size as u64
    } else {
        u64::MAX
    }
}

/// `sfr --version`.
#[wasm_bindgen]
pub fn version() -> String {
    crate::version_text()
}

/// The sandbox's limit on one log or record, in bytes.
#[wasm_bindgen(js_name = maxFileBytes)]
pub fn max_file_bytes() -> f64 {
    crate::MAX_SANDBOX_FILE_BYTES as f64
}

/// The CLI's limit on a rules file, baseline, key file or public key, in bytes.
#[wasm_bindgen(js_name = maxTextBytes)]
pub fn max_text_bytes() -> f64 {
    crate::MAX_TEXT_BYTES as f64
}

/// The public key (in `text`) and fingerprint (in `headline`) of the in-browser evaluation key
/// with this 32-byte seed.
#[wasm_bindgen(js_name = evaluationKey)]
pub fn evaluation_key(seed: &[u8]) -> Outcome {
    match crate::evaluation_key(seed) {
        Ok(k) => Outcome {
            headline: k.fingerprint,
            text: k.public_key_pem,
            ..Outcome::default()
        },
        Err(f) => failed(f),
    }
}

/// `sfr seal`. The key is the key file when `key_file` is given, else the in-browser key with
/// `seed`. Without a baseline, the sandbox seals with [`crate::NO_BASELINE`].
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn seal(
    log: &ByteSource,
    log_name: &str,
    log_size: f64,
    rules_name: &str,
    rules: &[u8],
    baseline_name: Option<String>,
    baseline: Option<Vec<u8>>,
    key_name: Option<String>,
    key_file: Option<Vec<u8>>,
    seed: Option<Vec<u8>>,
    seal_time: &str,
) -> Outcome {
    let key = match (&key_file, &seed) {
        (Some(bytes), _) => Key::File(Input {
            name: key_name.as_deref().unwrap_or("sfr.key"),
            bytes,
        }),
        (None, Some(seed)) => Key::Seed(seed),
        (None, None) => Key::Seed(&[]),
    };
    let mut reader = BufReader::with_capacity(READ_CHUNK, JsReader(log));
    let request = SealRequest {
        log: Stream {
            name: log_name,
            size: byte_count(log_size),
            reader: &mut reader,
        },
        rules: Input {
            name: rules_name,
            bytes: rules,
        },
        baseline: baseline.as_deref().map(|bytes| Input {
            name: baseline_name.as_deref().unwrap_or("baseline.params"),
            bytes,
        }),
        key,
        seal_time,
    };
    match crate::seal(request) {
        Ok(s) => Outcome {
            code: s.exit_code,
            text: s.text,
            notes: s.notes.join("\n"),
            record: s.record,
            record_name: s.record_name,
            report: s.report,
            report_name: s.report_name,
            ..Outcome::default()
        },
        Err(f) => failed(f),
    }
}

/// `sfr verify --pubkey`, and with `log` also `--ulog`. `record_size` is the record file's size:
/// a record over the sandbox's limit is refused by it, and the page then passes no bytes.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn verify(
    record_name: &str,
    record: &[u8],
    record_size: f64,
    pubkey_name: &str,
    pubkey: &[u8],
    log: Option<ByteSource>,
    log_name: Option<String>,
    log_size: f64,
) -> Outcome {
    if let Err(f) = crate::check_sandbox_size("record", record_name, byte_count(record_size)) {
        return failed(f);
    }
    let mut reader = log
        .as_ref()
        .map(|l| BufReader::with_capacity(READ_CHUNK, JsReader(l)));
    let request = VerifyRequest {
        record: Input {
            name: record_name,
            bytes: record,
        },
        public_key: Input {
            name: pubkey_name,
            bytes: pubkey,
        },
        log: reader.as_mut().map(|r| Stream {
            name: log_name.as_deref().unwrap_or("log"),
            size: byte_count(log_size),
            reader: r,
        }),
    };
    match crate::verify(request) {
        Ok(v) => Outcome {
            code: v.exit_code,
            message: if v.exit_code == 0 {
                String::new()
            } else {
                v.headline.clone()
            },
            headline: v.headline,
            text: v.text,
            ..Outcome::default()
        },
        Err(f) => failed(f),
    }
}
