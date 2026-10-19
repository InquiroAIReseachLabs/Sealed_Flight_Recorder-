//! The functions the engine bundle's worker calls (`crates/sfr-wasm/js/sfr-worker.js`), through
//! `wasm-bindgen`.
//!
//! Each one returns JSON (docs/SANDBOX.md, "JavaScript API"), with a seal's record and report
//! beside it in an [`Outcome`], and never throws: a failure is an exit code and the CLI's
//! message. Files reach the engine whole (`Uint8Array`) or, for the log, through a
//! [`ByteSource`] the page reads on demand, so a 100 MiB log is never copied whole into this
//! module's memory. A panic aborts, which the browser reports as a WebAssembly trap; the panic
//! hook keeps its message for [`last_panic`], so the page can say what happened.

use crate::result::{failure_json, seal_json, verify_json};
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
/// the engine is built to return an error for every input (no silent fallback).
#[wasm_bindgen(js_name = lastPanic)]
pub fn last_panic() -> String {
    LAST_PANIC.lock().map(|s| s.clone()).unwrap_or_default()
}

/// A seal's result: its JSON (docs/SANDBOX.md, "JavaScript API") and, when it sealed, the
/// record's bytes and the report.
#[wasm_bindgen]
#[derive(Debug, Default)]
pub struct Outcome {
    json: String,
    record: Vec<u8>,
    report: String,
}

#[wasm_bindgen]
impl Outcome {
    /// The result as JSON.
    #[wasm_bindgen(getter)]
    pub fn json(&self) -> String {
        self.json.clone()
    }
    /// The record's bytes (`<log stem>.sfr`); empty when nothing was sealed.
    #[wasm_bindgen(getter)]
    pub fn record(&self) -> Vec<u8> {
        self.record.clone()
    }
    /// The Markdown report (`<log stem>.sfr.md`); empty when nothing was sealed.
    #[wasm_bindgen(getter)]
    pub fn report(&self) -> String {
        self.report.clone()
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

/// The public key and fingerprint of the in-browser evaluation key with this 32-byte seed, as
/// JSON: `{"publicKeyPem", "fingerprint"}`, or a failure.
#[wasm_bindgen(js_name = evaluationKey)]
pub fn evaluation_key(seed: &[u8]) -> String {
    match crate::evaluation_key(seed) {
        Ok(k) => sfr_core::json::pretty(
            &sfr_core::json::Obj::new()
                .field("publicKeyPem", sfr_core::json::Value::str(k.public_key_pem))
                .field("fingerprint", sfr_core::json::Value::str(k.fingerprint))
                .build(),
        ),
        Err(f) => failure_json(f.code, &f.message, true),
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
            json: seal_json(&s),
            record: s.record,
            report: s.report,
        },
        Err(f) => Outcome {
            json: failure_json(f.code, &f.message, true),
            ..Outcome::default()
        },
    }
}

/// `sfr verify --pubkey`, and with `log` also `--ulog`, as JSON. `record_size` is the record
/// file's size: a record over the sandbox's limit is refused by it, and the page then passes no
/// bytes.
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
) -> String {
    if let Err(f) = crate::check_sandbox_size("record", record_name, byte_count(record_size)) {
        return failure_json(f.code, &f.message, false);
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
        // The page does not take a report; its verify says the report was not checked.
        report: None,
    };
    match crate::verify(request) {
        Ok(v) => verify_json(&v),
        Err(f) => failure_json(f.code, &f.message, false),
    }
}
