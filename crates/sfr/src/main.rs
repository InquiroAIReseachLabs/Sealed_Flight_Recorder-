//! `sfr` command line (SPEC B1.2, B1.3, `crates/sfr`). Thin wrapper over `sfr-core`.
//!
//! Commands: `keygen --evaluation-only`, `seal` (with `--dry-run`, or writing a signed `.sfr`
//! with an evaluation key file), `verify` (standalone with `--pubkey`, deep with `--ulog`),
//! and `--version`. Hardware key sources and certificate chains are recognised and refused
//! with exit 4 until they are built. Exit codes follow SPEC B1.4.
#![forbid(unsafe_code)]

use sfr_core::crypto::rustcrypto::{FileKey, RustCrypto};
use sfr_core::crypto::{CryptoBackend, Custody, Signer};
use sfr_core::evaluate::{Evaluation, Status, evaluate};
use sfr_core::exit_code;
use sfr_core::ingest::{FlightLogIngestor, IngestError, Ingested, Px4Ingestor};
use sfr_core::json::{self, Obj, Value};
use sfr_core::keys::{
    ed25519_pkcs8_v1_der, fingerprint, parse_public_key_pem, pem_decode, pem_encode, public_key_pem,
};
use sfr_core::params::{Baseline, parse_baseline};
use sfr_core::record::dry_run_json;
use sfr_core::rules::{Rules, parse_rules};
use sfr_core::seal::{
    SealParams, check_seal_time, format_utc, parse_seal_time, parse_seal_time_seconds, seal,
    this_tool,
};
use sfr_core::verify::{
    ClaimedSeal, INTEGRITY_NOT_CHECKED, MAX_RECORD_BYTES, Mismatch, TRUST_PUBKEY, VerifyError,
    check_record_size, claimed_lines, claimed_seal, failed_text, report_line, time_line,
    verified_text, verify,
};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use zeroize::Zeroizing;

mod certs;
mod hardware;

const USAGE: &str = "usage:
  sfr keygen --evaluation-only --out <dir> [--json]
  sfr keygen --tpm-sealed --out <dir> [--tpm-parent <handle>] [--tpm-pcrs <bank:list>] [--json]
  sfr seal <flight.ulg> --rules <rules.toml> --baseline <baseline.params>
           (--key-uri pkcs11:... | --key-uri tpm-sealed:<dir> | --key <sfr.key> --evaluation-only | --dry-run)
           [--out <dir>] [--seal-time <RFC3339>] [--allow-untested-version] [--json]
  sfr verify <record.sfr> (--pubkey <sfr.pub> | --trust-anchor <ca.pem> [--crl <crl>]...)
             [--ulog <flight.ulg>] [--report <name.sfr.md>] [--require-hardware-key]
             [--at <RFC3339>] [--json]
  sfr pubkey --key-uri (pkcs11:... | tpm-sealed:<dir>) [--json]
  sfr --version [--json]";

/// A path as the output shows it. `Path::join` puts the platform's separator after a directory
/// that was typed with `/`, which on Windows gives `try/out\file`; the output uses `/` throughout.
fn shown(path: &Path) -> String {
    with_slashes(&path.display().to_string(), std::path::MAIN_SEPARATOR)
}

/// `text` with every `separator` replaced by `/`.
fn with_slashes(text: &str, separator: char) -> String {
    text.replace(separator, "/")
}

/// Largest rules or baseline file read (real ones are a few kilobytes).
const MAX_TEXT_BYTES: u64 = 16 * 1024 * 1024;

const EVALUATION_LINE: &str = "EVALUATION KEY: not for operational use";

/// A failure that ends the command with a SPEC B1.4 exit code.
struct Failure {
    code: i32,
    message: String,
}

fn fail(code: i32, message: impl Into<String>) -> Failure {
    Failure {
        code,
        message: message.into(),
    }
}

fn usage(message: impl Into<String>) -> Failure {
    fail(exit_code::USAGE, format!("{}\n{USAGE}", message.into()))
}

/// Command-line options: flags and `--name value` pairs, plus positional arguments.
struct Args {
    positional: Vec<String>,
    values: Vec<(String, String)>,
    flags: Vec<String>,
}

impl Args {
    fn parse(args: &[String], with_value: &[&str], flags: &[&str]) -> Result<Args, Failure> {
        let mut out = Args {
            positional: Vec::new(),
            values: Vec::new(),
            flags: Vec::new(),
        };
        let mut it = args.iter();
        while let Some(a) = it.next() {
            if with_value.contains(&a.as_str()) {
                let v = it
                    .next()
                    .ok_or_else(|| usage(format!("{a} needs a value")))?;
                if a != "--crl" && out.values.iter().any(|(k, _)| k == a) {
                    return Err(usage(format!("{a} given twice")));
                }
                out.values.push((a.clone(), v.clone()));
            } else if flags.contains(&a.as_str()) {
                out.flags.push(a.clone());
            } else if a.starts_with('-') {
                return Err(usage(format!("unknown option {a}")));
            } else {
                out.positional.push(a.clone());
            }
        }
        Ok(out)
    }

    fn value(&self, name: &str) -> Option<&str> {
        self.values
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// Every value of an option that may be given more than once (`--crl`).
    fn values(&self, name: &str) -> Vec<&str> {
        self.values
            .iter()
            .filter(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
            .collect()
    }

    fn flag(&self, name: &str) -> bool {
        self.flags.iter().any(|f| f == name)
    }

    fn one_positional(&self, what: &str) -> Result<&str, Failure> {
        match self.positional.as_slice() {
            [one] => Ok(one),
            [] => Err(usage(format!("no {what} given"))),
            _ => Err(usage(format!("more than one {what} given"))),
        }
    }
}

/// Reads at most `cap` bytes, without judging the length.
fn read_capped(path: &str, what: &str, cap: u64) -> Result<Vec<u8>, Failure> {
    let file = File::open(path)
        .map_err(|e| fail(exit_code::USAGE, format!("cannot read {what} {path}: {e}")))?;
    let mut buf = Vec::new();
    file.take(cap)
        .read_to_end(&mut buf)
        .map_err(|e| fail(exit_code::USAGE, format!("cannot read {what} {path}: {e}")))?;
    Ok(buf)
}

/// Reads at most `max` bytes; a longer file fails with exit code `code` and names the limit.
fn read_bytes(path: &str, what: &str, max: u64, code: i32) -> Result<Vec<u8>, Failure> {
    let buf = read_capped(path, what, max + 1)?;
    if buf.len() as u64 > max {
        return Err(fail(
            code,
            format!(
                "{what} {path}: {}",
                sfr_core::limit_exceeded("the file", max, "bytes")
            ),
        ));
    }
    Ok(buf)
}

/// Reads a UTF-8 text file of at most [`MAX_TEXT_BYTES`]; content errors exit with `code`
/// (3 for rules and baseline, 4 for keys).
fn read_text(path: &str, what: &str, code: i32) -> Result<String, Failure> {
    let bytes = read_bytes(path, what, MAX_TEXT_BYTES, code)?;
    String::from_utf8(bytes).map_err(|e| {
        fail(
            code,
            format!(
                "{what} {path}: not UTF-8 at byte offset {}",
                e.utf8_error().valid_up_to()
            ),
        )
    })
}

fn write_out(stdout: &mut dyn Write, text: &str) -> Result<(), Failure> {
    stdout
        .write_all(text.as_bytes())
        .and_then(|()| stdout.flush())
        .map_err(|e| fail(exit_code::USAGE, format!("cannot write output: {e}")))
}

/// The key `--key-uri` names: `pkcs11:...` (custody `pkcs11-token`) or `tpm-sealed:<dir>`
/// (custody `tpm-sealed`). Any failure is a key error, exit 4, before any other work.
fn hardware_key(uri: &str) -> Result<Box<dyn Signer>, Failure> {
    let key: Result<Box<dyn Signer>, String> = if uri.starts_with("pkcs11:") {
        hardware::Pkcs11Key::open(uri).map(|k| Box::new(k) as Box<dyn Signer>)
    } else if let Some(dir) = uri.strip_prefix("tpm-sealed:") {
        if dir.is_empty() {
            Err("tpm-sealed:<dir> needs the key directory `keygen --tpm-sealed` wrote".into())
        } else {
            hardware::tpm_key(Path::new(dir)).map(|k| Box::new(k) as Box<dyn Signer>)
        }
    } else {
        Err(format!(
            "`{uri}` is not a key URI: pkcs11:... (RFC 7512) or tpm-sealed:<dir>"
        ))
    };
    key.map_err(|e| fail(exit_code::USAGE, format!("--key-uri: {e}")))
}

fn file_name(path: &str) -> String {
    Path::new(path)
        .file_name()
        .map_or_else(|| path.to_string(), |n| n.to_string_lossy().into_owned())
}

/// The crypto crates and their crate versions, as `seal.crypto_crates` names them.
fn crates_line(crypto: &dyn CryptoBackend) -> String {
    let names: Vec<String> = crypto
        .crates()
        .iter()
        .map(|c| format!("{} {}", c.name, c.version))
        .collect();
    format!("{} (crate versions)", names.join(", "))
}

// ---------------------------------------------------------------------------------------------
// keygen

fn keygen(args: &[String], crypto: &RustCrypto, stdout: &mut dyn Write) -> Result<i32, Failure> {
    let a = Args::parse(
        args,
        &["--out", "--tpm-parent", "--tpm-pcrs"],
        &["--evaluation-only", "--tpm-sealed", "--json"],
    )?;
    if a.flag("--tpm-sealed") && a.flag("--evaluation-only") {
        return Err(usage(
            "--tpm-sealed and --evaluation-only are two different keys; give one",
        ));
    }
    if !a.flag("--tpm-sealed")
        && (a.value("--tpm-parent").is_some() || a.value("--tpm-pcrs").is_some())
    {
        return Err(usage(
            "--tpm-parent and --tpm-pcrs apply only to --tpm-sealed",
        ));
    }
    if !a.flag("--evaluation-only") && !a.flag("--tpm-sealed") {
        return Err(fail(
            exit_code::USAGE,
            "keygen makes file keys for evaluation only and needs --evaluation-only. Operational keys live in hardware: \
             a PKCS#11 token or HSM key generated with the token's own tools (custody pkcs11-token), or \
             `sfr keygen --tpm-sealed` (custody tpm-sealed)",
        ));
    }
    if !a.positional.is_empty() {
        return Err(usage("keygen takes no positional arguments"));
    }
    let dir = PathBuf::from(
        a.value("--out")
            .ok_or_else(|| usage("--out <dir> is required"))?,
    );
    if a.flag("--tpm-sealed") {
        return keygen_tpm(&a, &dir, crypto, stdout);
    }
    let key_path = dir.join("sfr.key");
    let pub_path = dir.join("sfr.pub");
    for p in [&key_path, &pub_path] {
        if p.exists() {
            return Err(fail(
                exit_code::USAGE,
                format!("{} exists; keygen never overwrites a key", p.display()),
            ));
        }
    }
    std::fs::create_dir_all(&dir).map_err(|e| {
        fail(
            exit_code::USAGE,
            format!("cannot create {}: {e}", dir.display()),
        )
    })?;
    // The only randomness in the tool: a 32-byte Ed25519 seed from the operating system's CSPRNG.
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut seed[..]).map_err(|e| {
        fail(
            exit_code::USAGE,
            format!("the operating system's random number generator failed: {e}"),
        )
    })?;
    let public = FileKey::from_seed(&seed, "sfr.key").public_key();
    let key_pem = Zeroizing::new(pem_encode("PRIVATE KEY", &ed25519_pkcs8_v1_der(&seed)));
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let write = |path: &Path, opts: &OpenOptions, text: &str| {
        opts.open(path)
            .and_then(|mut f| f.write_all(text.as_bytes()).and_then(|()| f.sync_all()))
            .map_err(|e| {
                fail(
                    exit_code::USAGE,
                    format!("cannot write {}: {e}", path.display()),
                )
            })
    };
    write(&key_path, &opts, &key_pem)?;
    let mut pub_opts = OpenOptions::new();
    pub_opts.write(true).create_new(true);
    write(&pub_path, &pub_opts, &public_key_pem(&public))?;
    let fp = fingerprint(crypto, &public);
    let text = if a.flag("--json") {
        json::pretty(
            &Obj::new()
                .field("key_custody", Value::str(Custody::FileEvaluation.as_str()))
                .field("fingerprint", Value::str(fp))
                .field("private_key", Value::str(shown(&key_path)))
                .field("public_key", Value::str(shown(&pub_path)))
                .build(),
        )
    } else {
        format!(
            "{EVALUATION_LINE}\nfingerprint  {fp}\nprivate key  {} (mode 0600)\npublic key   {}\n",
            shown(&key_path),
            shown(&pub_path)
        )
    };
    write_out(stdout, &text)?;
    Ok(exit_code::OK)
}

/// `keygen --tpm-sealed`: a seed from the operating system's CSPRNG, sealed to this machine's
/// TPM 2.0 through a pipe (SPEC B1.3). Only the sealed blobs and the public key reach disk.
fn keygen_tpm(
    a: &Args,
    dir: &Path,
    crypto: &RustCrypto,
    stdout: &mut dyn Write,
) -> Result<i32, Failure> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut seed[..]).map_err(|e| {
        fail(
            exit_code::USAGE,
            format!("the operating system's random number generator failed: {e}"),
        )
    })?;
    let public = FileKey::unsealed_from_tpm(&seed, "").public_key();
    let parent = a
        .value("--tpm-parent")
        .unwrap_or(hardware::DEFAULT_TPM_PARENT);
    let pcrs = a.value("--tpm-pcrs");
    let written = hardware::tpm_keygen(dir, &seed, parent, pcrs, &public)
        .map_err(|e| fail(exit_code::USAGE, format!("keygen --tpm-sealed: {e}")))?;
    let fp = fingerprint(crypto, &public);
    let pub_path = dir.join(hardware::PUBLIC_KEY_FILE);
    let uri = format!("tpm-sealed:{}", shown(dir));
    let text = if a.flag("--json") {
        json::pretty(
            &Obj::new()
                .field("key_custody", Value::str(Custody::TpmSealed.as_str()))
                .field("fingerprint", Value::str(fp))
                .field("key_uri", Value::str(uri))
                .field("tpm_parent", Value::str(parent))
                .field("tpm_pcrs", Value::opt_str(pcrs.map(str::to_string)))
                .field(
                    "files",
                    Value::Array(written.iter().map(|p| Value::str(shown(p))).collect()),
                )
                .field("public_key", Value::str(shown(&pub_path)))
                .build(),
        )
    } else {
        format!(
            "custody      tpm-sealed (parent {parent}{})\nfingerprint  {fp}\nkey uri      {uri}\npublic key   {}\n",
            pcrs.map(|p| format!(", PCR policy {p}"))
                .unwrap_or_default(),
            shown(&pub_path)
        )
    };
    write_out(stdout, &text)?;
    Ok(exit_code::OK)
}

/// `pubkey --key-uri <uri>`: the public half of a hardware key, as the PEM `sfr verify --pubkey`
/// reads, and its fingerprint. For a PKCS#11 key it is read from the token; for a `tpm-sealed`
/// key the seed is unsealed and checked against the directory's `sfr.pub`.
fn pubkey_cmd(
    args: &[String],
    crypto: &RustCrypto,
    stdout: &mut dyn Write,
) -> Result<i32, Failure> {
    let a = Args::parse(args, &["--key-uri"], &["--json"])?;
    if !a.positional.is_empty() {
        return Err(usage("pubkey takes no positional arguments"));
    }
    let uri = a
        .value("--key-uri")
        .ok_or_else(|| usage("--key-uri <pkcs11:... or tpm-sealed:<dir>> is required"))?;
    let key = hardware_key(uri)?;
    let public = key.public_key();
    let pem = public_key_pem(&public);
    let fp = fingerprint(crypto, &public);
    let text = if a.flag("--json") {
        json::pretty(
            &Obj::new()
                .field("key_custody", Value::str(key.custody().as_str()))
                .field("key_label", Value::str(key.label()))
                .field("fingerprint", Value::str(fp))
                .field("public_key_pem", Value::str(pem))
                .build(),
        )
    } else {
        format!(
            "# custody {}, label {}, fingerprint {fp}\n{pem}",
            key.custody().as_str(),
            key.label()
        )
    };
    write_out(stdout, &text)?;
    Ok(exit_code::OK)
}

// ---------------------------------------------------------------------------------------------
// seal

/// The transition tuning section (SPEC B1.8): the VTOL type and each watched parameter with
/// its baseline and flown values. Empty for a vehicle that is not VTOL.
fn transition_tuning(ing: &Ingested, rules: &Rules, baseline: &Baseline) -> String {
    let Some(vtol) = &ing.identity.vehicle.vtol_type else {
        return String::new();
    };
    let mut out = format!("transition tuning (VTOL type {})\n", vtol.name);
    if rules.watched.is_empty() {
        out.push_str("  no [watched_parameters] in the rules file\n");
        return out;
    }
    let show =
        |v: Option<&sfr_core::ulog::ParamValue>| v.map_or("absent".to_string(), |v| v.to_string());
    out.push_str(&format!(
        "  {:<18}{:<16}{:<16}{}\n",
        "PARAMETER", "BASELINE", "FLOWN", "R3"
    ));
    for name in &rules.watched {
        let b = baseline.params.get(name);
        let l = ing.config.params.get(name);
        // As R3 and the report (sfr_core::report::watched_mark): R3 compares a parameter only
        // when the baseline has it, or with compare = "all" when the log has it.
        let mark = match (b, l) {
            (None, None) => "not compared",
            (None, _) if rules.compare == sfr_core::rules::Compare::Baseline => "not compared",
            (Some(b), Some(l)) if b.same_as(l) => "MATCH",
            _ => "DIFF",
        };
        out.push_str(&format!(
            "  {name:<18}{:<16}{:<16}{mark}\n",
            show(b),
            show(l)
        ));
    }
    out
}

fn table(
    ing: &Ingested,
    eval: &Evaluation,
    crypto: &dyn CryptoBackend,
    dry_run: bool,
    rules: &Rules,
    baseline: &Baseline,
) -> String {
    let id = &ing.identity;
    let fw = &id.firmware;
    let mut out = String::new();
    if dry_run {
        out.push_str(
            "sfr seal --dry-run: v1.0 evaluation release; nothing is signed or written\n\n",
        );
    }
    let firmware = match (&fw.version, &fw.git) {
        (Some(v), Some(g)) => format!("{v} ({g})"),
        (Some(v), None) => v.clone(),
        (None, Some(g)) => format!("unknown version ({g})"),
        (None, None) => "unknown".into(),
    };
    for (k, v) in [
        ("log", format!("{} ({} bytes)", id.file_name, id.size)),
        ("sha256", sfr_core::hex(&id.sha256)),
        ("blake3", sfr_core::hex(&id.blake3)),
        ("firmware", firmware),
        ("crypto", crates_line(crypto)),
    ] {
        out.push_str(&format!("{k:<10}{v}\n"));
    }
    out.push('\n');
    out.push_str(&format!(
        "{:<6}{:<8}{:<30}{}\n",
        "RULE", "STATUS", "NAME", "FOUND"
    ));
    for r in &eval.results {
        out.push_str(&format!(
            "{:<6}{:<8}{:<30}{}\n",
            r.id,
            r.status.as_str(),
            r.name,
            r.found
        ));
        if r.status == Status::Fail {
            for d in &r.detail {
                out.push_str(&format!("{:<14}- {d}\n", ""));
            }
        }
    }
    let tuning = transition_tuning(ing, rules, baseline);
    if !tuning.is_empty() {
        out.push('\n');
        out.push_str(&tuning);
    }
    out.push('\n');
    out.push_str(&format!("{:<10}{}\n", "events", ing.events.len()));
    out.push_str(&format!("{:<10}{}\n", "status", eval.status.as_str()));
    out
}

fn seal_cmd(args: &[String], crypto: &RustCrypto, stdout: &mut dyn Write) -> Result<i32, Failure> {
    let a = Args::parse(
        args,
        &[
            "--rules",
            "--baseline",
            "--key",
            "--key-uri",
            "--cert",
            "--chain",
            "--out",
            "--seal-time",
        ],
        &[
            "--dry-run",
            "--json",
            "--evaluation-only",
            "--allow-untested-version",
        ],
    )?;
    let log = a.one_positional("log file")?.to_string();
    let rules_path = a
        .value("--rules")
        .ok_or_else(|| usage("--rules is required"))?;
    let baseline_path = a
        .value("--baseline")
        .ok_or_else(|| usage("--baseline is required"))?;
    let dry_run = a.flag("--dry-run");
    if a.value("--chain").is_some() && a.value("--cert").is_none() {
        return Err(usage("--chain applies only with --cert <signer.pem>"));
    }
    let signer_certificate = match a.value("--cert") {
        None => None,
        Some(path) => {
            let mut certs = certs::read_certificates(path, "signer certificate")
                .map_err(|e| fail(exit_code::USAGE, e))?;
            if certs.len() != 1 {
                return Err(usage(format!(
                    "--cert {path} holds {} certificates; give the signer's alone, intermediates with --chain",
                    certs.len()
                )));
            }
            Some(certs.remove(0))
        }
    };
    let certificate_chain = match a.value("--chain") {
        None => Vec::new(),
        Some(path) => certs::read_certificates(path, "certificate chain")
            .map_err(|e| fail(exit_code::USAGE, e))?,
    };
    // The key source is checked before any work, so a usage error costs nothing.
    if a.value("--key-uri").is_some() && a.value("--key").is_some() {
        return Err(usage("give one key source: --key-uri or --key"));
    }
    let key: Option<Box<dyn Signer>> = if dry_run {
        None
    } else if let Some(uri) = a.value("--key-uri") {
        if a.flag("--evaluation-only") {
            return Err(usage(
                "--evaluation-only applies only to a key file (--key)",
            ));
        }
        Some(hardware_key(uri)?)
    } else if let Some(path) = a.value("--key") {
        if !a.flag("--evaluation-only") {
            return Err(fail(
                exit_code::USAGE,
                "a key file is for evaluation only: add --evaluation-only, or use a hardware key source \
                 (--key-uri pkcs11:... or --key-uri tpm-sealed:<dir>)",
            ));
        }
        let text = Zeroizing::new(read_text(path, "key file", exit_code::USAGE)?);
        let der = Zeroizing::new(
            pem_decode(&text, "PRIVATE KEY")
                .map_err(|e| fail(exit_code::USAGE, format!("key file {path}: {e}")))?,
        );
        Some(Box::new(
            FileKey::from_pkcs8_der(&der, &file_name(path))
                .map_err(|e| fail(exit_code::USAGE, format!("key file {path}: {e}")))?,
        ))
    } else {
        return Err(fail(
            exit_code::USAGE,
            "seal needs a key source: --key-uri pkcs11:..., --key-uri tpm-sealed:<dir>, or --key <sfr.key> \
             --evaluation-only (or --dry-run to sign nothing)",
        ));
    };
    let time_utc = match a.value("--seal-time") {
        Some(t) => parse_seal_time(t).map_err(usage)?,
        None => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| fail(exit_code::USAGE, format!("system clock: {e}")))?;
            format_utc(i64::try_from(now.as_secs()).unwrap_or(i64::MAX))
        }
    };
    let out_dir = PathBuf::from(a.value("--out").unwrap_or("."));
    let stem = Path::new(&log).file_stem().map_or_else(
        || "record".to_string(),
        |s| s.to_string_lossy().into_owned(),
    );
    let out_path = out_dir.join(format!("{stem}.sfr"));
    let report_path = out_dir.join(format!("{stem}.{}", sfr_core::report::REPORT_EXTENSION));
    for path in [&out_path, &report_path] {
        // symlink_metadata: a symbolic link there, even a dangling one, counts as existing.
        if !dry_run && path.symlink_metadata().is_ok() {
            return Err(fail(
                exit_code::USAGE,
                format!(
                    "{} exists; seal never overwrites a record or its report",
                    path.display()
                ),
            ));
        }
    }

    let rules_text = read_text(rules_path, "rules file", exit_code::MALFORMED_INPUT)?;
    let rules: Rules = parse_rules(&rules_text).map_err(|e| {
        let code = if e.usage {
            exit_code::USAGE
        } else {
            exit_code::MALFORMED_INPUT
        };
        fail(code, format!("rules file {rules_path}: {e}"))
    })?;
    let baseline_text = read_text(baseline_path, "baseline", exit_code::MALFORMED_INPUT)?;
    let baseline: Baseline = parse_baseline(&baseline_text).map_err(|e| {
        fail(
            exit_code::MALFORMED_INPUT,
            format!("baseline {baseline_path}: {e}"),
        )
    })?;
    let mut file = File::open(&log)
        .map_err(|e| fail(exit_code::USAGE, format!("cannot open log {log}: {e}")))?;
    let ing = Px4Ingestor
        .ingest_sealing(&file_name(&log), &mut file, crypto, &rules.sealed_topics)
        .map_err(|e| match e {
            IngestError::Malformed(m) => {
                fail(exit_code::MALFORMED_INPUT, format!("log {log}: {m}"))
            }
            IngestError::Io(m) => fail(exit_code::USAGE, format!("log {log}: {m}")),
            limit @ IngestError::Limit(_) => {
                fail(exit_code::MALFORMED_INPUT, format!("log {log}: {limit}"))
            }
        })?;
    let eval = evaluate(&ing, &rules, &baseline);
    // seal.allow_untested_version is true only for a log sealed because of the flag.
    let untested = !sfr_core::events::tested_firmware(&ing.identity.firmware);
    let allow_untested = a.flag("--allow-untested-version") && untested;
    if untested {
        let (refusal, warning) =
            sfr_core::seal::untested_version_messages(&log, &ing.identity.firmware);
        if !a.flag("--allow-untested-version") {
            // SPEC B1.5: sfr is tested on PX4 v1.14 to v1.17 only; anything else needs consent,
            // and the record says it was given.
            return Err(fail(exit_code::USAGE, refusal));
        }
        let _ = writeln!(io::stderr().lock(), "{warning}");
    }

    let Some(key) = key else {
        let text = if a.flag("--json") {
            json::pretty(&dry_run_json(
                &ing,
                &eval,
                &rules,
                &baseline,
                &crypto.sha256(rules_text.as_bytes()),
            ))
        } else {
            table(&ing, &eval, crypto, true, &rules, &baseline)
        };
        write_out(stdout, &text)?;
        return Ok(eval.exit_code);
    };

    // The signer certificate must certify the signing key (SPEC B1.3 --cert).
    if let Some(der) = &signer_certificate {
        let certified = certs::certificate_key(der)
            .map_err(|e| fail(exit_code::USAGE, format!("signer certificate: {e}")))?;
        if certified != key.public_key() {
            return Err(fail(
                exit_code::USAGE,
                format!(
                    "the signer certificate certifies {}, not the signing key {}; nothing written",
                    fingerprint(crypto, &certified),
                    fingerprint(crypto, &key.public_key())
                ),
            ));
        }
    }
    let params = SealParams {
        time_utc,
        signer_certificate,
        certificate_chain,
        allow_untested_version: allow_untested,
    };
    let sealed = seal(
        &ing,
        &eval,
        &rules,
        &baseline,
        &params,
        crypto,
        key.as_ref(),
    )
    .map_err(|e| fail(exit_code::USAGE, e.to_string()))?;
    // A record verify would refuse is never written (SPEC B1.4 input limits).
    check_record_size(sealed.bytes.len()).map_err(|e| {
        fail(
            exit_code::MALFORMED_INPUT,
            format!("log {log}: the record it gives is refused: {e}"),
        )
    })?;
    std::fs::create_dir_all(&out_dir).map_err(|e| {
        fail(
            exit_code::USAGE,
            format!("cannot create {}: {e}", out_dir.display()),
        )
    })?;
    // The report comes from the record alone (SPEC B1.8): the bytes just sealed, parsed back.
    let report = json::parse(&sealed.bytes)
        .map_err(|e| e.to_string())
        .and_then(|v| sfr_core::report::render(&v).map_err(|e| e.to_string()))
        .map_err(|e| fail(exit_code::USAGE, format!("cannot write the report: {e}")))?;
    // A record and its report are written together or not at all: both files are created
    // (never overwriting) before either is written, and a failure removes what this run created.
    let mut created: Vec<&PathBuf> = Vec::new();
    let written = (|| {
        let mut files = Vec::new();
        for (path, bytes) in [
            (&out_path, &sealed.bytes[..]),
            (&report_path, report.as_bytes()),
        ] {
            let f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .map_err(|e| (path, e))?;
            created.push(path);
            files.push((path, f, bytes));
        }
        for (path, f, bytes) in &mut files {
            f.write_all(bytes)
                .and_then(|()| f.sync_all())
                .map_err(|e| (*path, e))?;
        }
        Ok(())
    })();
    if let Err((path, e)) = written {
        for p in created {
            // Best effort: the error below is the one to report.
            let _ = std::fs::remove_file(p);
        }
        return Err(fail(
            exit_code::USAGE,
            format!(
                "cannot write {}: {e}; seal wrote neither the record nor the report",
                path.display()
            ),
        ));
    }
    let custody = key.custody();
    let text = if a.flag("--json") {
        json::pretty(
            &Obj::new()
                .field("record", Value::str(shown(&out_path)))
                .field("report", Value::str(shown(&report_path)))
                .field("key_custody", Value::str(custody.as_str()))
                .field("key_fingerprint", Value::str(sealed.fingerprint.clone()))
                .field("merkle_root", Value::str(sfr_core::hex(&sealed.root)))
                .field("leaf_count", Value::count(sealed.leaf_count as u64))
                .field("event_count", Value::count(ing.events.len() as u64))
                .field("status", Value::str(eval.status.as_str()))
                .build(),
        )
    } else {
        let mut t = String::new();
        if custody == Custody::FileEvaluation {
            t.push_str(EVALUATION_LINE);
            t.push('\n');
        }
        t.push_str(&table(&ing, &eval, crypto, false, &rules, &baseline));
        t.push_str(&format!(
            "\n{:<10}{}\n{:<10}{}\n{:<10}{}\n{:<10}{} ({})\n{:<10}{} (claimed: this machine's clock, or --seal-time)\n",
            "record",
            shown(&out_path),
            "report",
            shown(&report_path),
            "merkle",
            sfr_core::hex(&sealed.root),
            "key",
            sealed.fingerprint,
            custody.as_str(),
            "sealed",
            params.time_utc
        ));
        t
    };
    write_out(stdout, &text)?;
    Ok(eval.exit_code)
}

// ---------------------------------------------------------------------------------------------
// verify

/// What a verification checked the signature against.
enum Trust {
    /// A public key file given with `--pubkey`.
    PublicKey([u8; 32]),
    /// Trust anchors given with `--trust-anchor`, and CRLs given with `--crl`.
    Anchors {
        anchors: Vec<Vec<u8>>,
        crls: Vec<Vec<u8>>,
    },
}

fn verify_cmd(
    args: &[String],
    crypto: &RustCrypto,
    stdout: &mut dyn Write,
) -> Result<i32, Failure> {
    let a = Args::parse(
        args,
        &[
            "--pubkey",
            "--ulog",
            "--trust-anchor",
            "--crl",
            "--report",
            "--at",
        ],
        &["--require-hardware-key", "--json"],
    )?;
    let record_path = a.one_positional("record")?.to_string();
    let json_out = a.flag("--json");
    // The verification time: the verifier's clock, or the time given with --at. Certificate
    // validity is judged at this time and never at the record's claimed seal time, and a claimed
    // seal time later than it is refused.
    let (verification_time, time_source) = match a.value("--at") {
        Some(t) => (
            parse_seal_time_seconds(t).map_err(|e| usage(format!("--at: {e}")))?,
            "--at",
        ),
        None => (
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| fail(exit_code::USAGE, format!("system clock: {e}")))
                .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))?,
            "verifier clock",
        ),
    };
    // The report to check: --report, or <name>.sfr.md beside <name>.sfr when it exists.
    let report_path = match a.value("--report") {
        Some(p) => {
            if !Path::new(p).is_file() {
                return Err(fail(
                    exit_code::USAGE,
                    format!("cannot read report {p}: not a file"),
                ));
            }
            Some(p.to_string())
        }
        None => Some(format!("{record_path}.md"))
            .filter(|p| record_path.ends_with(".sfr") && Path::new(p).is_file()),
    };
    let crl_paths = a.values("--crl");
    let trust = match (a.value("--pubkey"), a.value("--trust-anchor")) {
        (Some(_), Some(_)) => {
            return Err(usage(
                "give one trust source: --pubkey <sfr.pub> or --trust-anchor <ca.pem>",
            ));
        }
        (Some(pub_path), None) => {
            if !crl_paths.is_empty() {
                return Err(usage("--crl applies only to --trust-anchor"));
            }
            Some(Trust::PublicKey(
                parse_public_key_pem(&read_text(pub_path, "public key", exit_code::USAGE)?)
                    .map_err(|e| fail(exit_code::USAGE, format!("public key {pub_path}: {e}")))?,
            ))
        }
        (None, Some(anchor_path)) => {
            let anchors = certs::read_certificates(anchor_path, "trust anchor")
                .map_err(|e| fail(exit_code::USAGE, e))?;
            let crls = crl_paths
                .iter()
                .map(|p| certs::read_crl(p))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| fail(exit_code::USAGE, e))?;
            Some(Trust::Anchors { anchors, crls })
        }
        (None, None) => {
            if !crl_paths.is_empty() {
                return Err(usage("--crl applies only to --trust-anchor"));
            }
            None
        }
    };
    // One byte over the limit is read so that `verify` reports the oversize record as a
    // verification failure (exit 1) naming the limit, the same way for every oversize record.
    let record = read_capped(&record_path, "record", MAX_RECORD_BYTES as u64 + 1)?;
    let claimed = claimed_seal(&record);
    let Some(trust) = trust else {
        return not_checked(&record_path, claimed.as_ref(), json_out, stdout);
    };
    // The key to check the signature with: the given one, or the one the record's signer
    // certificate certifies (the certificate is inside the signed seal leaf, so the signature
    // check below covers it before the chain is judged).
    let public = match &trust {
        Trust::PublicKey(k) => Ok(*k),
        Trust::Anchors { .. } => claimed
            .as_ref()
            .and_then(|c| c.signer_certificate.as_deref())
            .ok_or_else(|| {
                "the record carries no signer certificate, so it cannot chain to a trust anchor; \
                 verify it with --pubkey"
                    .to_string()
            })
            .and_then(|der| {
                certs::certificate_key(der).map_err(|e| format!("signer certificate: {e}"))
            }),
    };
    let mut log_file = match a.value("--ulog") {
        Some(p) => Some(
            File::open(p)
                .map_err(|e| fail(exit_code::USAGE, format!("cannot open log {p}: {e}")))?,
        ),
        None => None,
    };
    let deep = log_file.is_some();
    let outcome = match public {
        Err(e) => Err(VerifyError::Mismatch(Mismatch {
            first: e,
            also: Vec::new(),
            custody: claimed
                .as_ref()
                .and_then(|c| c.custody.as_deref())
                .and_then(Custody::parse),
        })),
        Ok(public) => {
            let log: Option<&mut dyn Read> = log_file.as_mut().map(|f| f as &mut dyn Read);
            verify(
                &record,
                log,
                crypto,
                &public,
                a.flag("--require-hardware-key"),
            )
        }
    };
    // The seal time is the sealer's claim: it may not lie in the verifier's future.
    let outcome = match outcome {
        Ok(v) => match check_seal_time(&v.claimed_time_utc, verification_time) {
            Ok(_) => Ok(v),
            Err(e) => Err(VerifyError::Mismatch(Mismatch {
                first: e,
                also: Vec::new(),
                custody: Some(v.custody),
            })),
        },
        Err(e) => Err(e),
    };
    // With a trust anchor, a record that verified must also chain to it at the verification
    // time (never at the claimed seal time).
    let outcome = match (outcome, &trust) {
        (Ok(v), Trust::Anchors { anchors, crls }) => {
            let chained = claimed
                .as_ref()
                .and_then(|c| c.signer_certificate.as_deref())
                .ok_or_else(|| "the record carries no signer certificate".to_string())
                .and_then(|signer| {
                    let chain = claimed
                        .as_ref()
                        .map_or(&[][..], |c| c.certificate_chain.as_slice());
                    certs::check_chain(signer, chain, anchors, crls, verification_time)
                });
            match chained {
                Ok(ok) => Ok((v, Some(ok))),
                Err(e) => Err(VerifyError::Mismatch(Mismatch {
                    first: format!("certificate chain: {e}"),
                    also: Vec::new(),
                    custody: Some(v.custody),
                })),
            }
        }
        (Ok(v), Trust::PublicKey(_)) => Ok((v, None)),
        (Err(e), _) => Err(e),
    };
    // The report must be, byte for byte, the one the verified record renders (SPEC B1.8).
    let outcome = match (outcome, &report_path) {
        (Ok((v, chain)), Some(path)) => {
            let report = read_capped(path, "report", MAX_RECORD_BYTES as u64)?;
            match sfr_core::report::check(&record, &report) {
                Ok(()) => Ok((v, chain, Some(path.as_str()))),
                Err(e) => Err(VerifyError::Mismatch(Mismatch {
                    first: format!("report {path}: {e}"),
                    also: Vec::new(),
                    custody: Some(v.custody),
                })),
            }
        }
        (Ok((v, chain)), None) => Ok((v, chain, None)),
        (Err(e), _) => Err(e),
    };
    match outcome {
        Err(VerifyError::Io(e)) => Err(fail(exit_code::USAGE, format!("log: {e}"))),
        Ok((v, chain, report)) => {
            let (trust_line, custody_note) = match &chain {
                None => (TRUST_PUBKEY.to_string(), "declared".to_string()),
                Some(ok) => (
                    format!(
                        "certificate chain to the trust anchor {} at the verification time; {} CRL(s) checked",
                        ok.anchor, ok.crls
                    ),
                    format!(
                        "declared; the key's certificate chains to the trust anchor {}",
                        ok.anchor
                    ),
                ),
            };
            let text = if json_out {
                json::pretty(
                    &Obj::new()
                        .field("verified", Value::Bool(true))
                        .field("integrity", Value::str("VERIFIED"))
                        .field("flight_rules", Value::str(v.status.clone()))
                        .field(
                            "failed_rules",
                            Value::Array(
                                v.failed_rules
                                    .iter()
                                    .map(|r| Value::str(r.clone()))
                                    .collect(),
                            ),
                        )
                        .field("record", Value::str(record_path.clone()))
                        .field("report", Value::opt_str(report.map(str::to_string)))
                        .field("deep", Value::Bool(v.deep))
                        .field(
                            "trust",
                            Value::str(if chain.is_some() {
                                "trust-anchor"
                            } else {
                                "pubkey"
                            }),
                        )
                        .field(
                            "trust_anchor",
                            chain
                                .as_ref()
                                .map_or(Value::Null, |c| Value::str(c.anchor.clone())),
                        )
                        .field("key_custody", Value::str(v.custody.as_str()))
                        .field("key_custody_proven", Value::Bool(false))
                        .field("key_fingerprint", Value::str(v.fingerprint.clone()))
                        .field("crypto_crates", Value::str(v.crypto_crates.clone()))
                        .field(
                            "seal_time_claimed_utc",
                            Value::str(v.claimed_time_utc.clone()),
                        )
                        .field(
                            "verification_time_utc",
                            Value::str(format_utc(verification_time)),
                        )
                        .field("verification_time_source", Value::str(time_source))
                        .field("status", Value::str(v.status.clone()))
                        .field("event_count", Value::count(v.events as u64))
                        .build(),
                )
            } else {
                let mut t = String::new();
                if v.custody == Custody::FileEvaluation {
                    t.push_str(EVALUATION_LINE);
                    t.push('\n');
                }
                let time = (chain.is_some() || time_source == "--at")
                    .then(|| time_line(verification_time, time_source, chain.is_some()));
                t.push_str(&verified_text(
                    &record_path,
                    &v,
                    &trust_line,
                    &custody_note,
                    &report_line(report),
                    time.as_deref(),
                ));
                t
            };
            write_out(stdout, &text)?;
            Ok(exit_code::OK)
        }
        Err(VerifyError::Mismatch(m)) => {
            let text = if json_out {
                json::pretty(
                    &Obj::new()
                        .field("verified", Value::Bool(false))
                        .field("integrity", Value::str("FAILED"))
                        .field("flight_rules", Value::str("UNKNOWN"))
                        .field("record", Value::str(record_path.clone()))
                        .field("deep", Value::Bool(deep))
                        .field(
                            "key_custody",
                            m.custody.map_or(Value::Null, |c| Value::str(c.as_str())),
                        )
                        .field(
                            "key_fingerprint",
                            Value::opt_str(claimed.as_ref().and_then(|c| c.fingerprint.clone())),
                        )
                        .field("first_mismatch", Value::str(m.first.clone()))
                        .field(
                            "other_mismatches",
                            Value::Array(
                                m.also
                                    .iter()
                                    .take(20)
                                    .map(|s| Value::str(s.clone()))
                                    .collect(),
                            ),
                        )
                        .build(),
                )
            } else {
                // SPEC B1.3: a record sealed with an evaluation key says so first, verified or
                // not (the custody of a record that fails is only what it claims).
                let mut t = String::new();
                if m.custody == Some(Custody::FileEvaluation) {
                    t.push_str(EVALUATION_LINE);
                    t.push('\n');
                }
                t.push_str(&failed_text(&m, claimed.as_ref()));
                t
            };
            write_out(stdout, &text)?;
            Ok(exit_code::RULE_FAIL)
        }
    }
}

/// `verify` with neither `--pubkey` nor `--trust-anchor`: nothing is checked, because a record
/// signed by anyone verifies against its own key. Says so on standard output, names the key and
/// custody the record claims, says how to check it, and exits 4.
fn not_checked(
    record_path: &str,
    claimed: Option<&ClaimedSeal>,
    json_out: bool,
    stdout: &mut dyn Write,
) -> Result<i32, Failure> {
    let how = "give the signer's public key (--pubkey <sfr.pub>) or a trust anchor its \
               certificate chains to (--trust-anchor <ca.pem>), obtained through a channel you trust";
    let text = if json_out {
        json::pretty(
            &Obj::new()
                .field("verified", Value::Bool(false))
                .field("integrity", Value::str("NOT CHECKED"))
                .field("flight_rules", Value::str("UNKNOWN"))
                .field("record", Value::str(record_path))
                .field(
                    "key_fingerprint",
                    Value::opt_str(claimed.and_then(|c| c.fingerprint.clone())),
                )
                .field(
                    "key_custody",
                    Value::opt_str(claimed.and_then(|c| c.custody.clone())),
                )
                .field("how_to_check", Value::str(how))
                .build(),
        )
    } else {
        let mut t = String::new();
        if claimed.and_then(|c| c.custody.as_deref()) == Some(Custody::FileEvaluation.as_str()) {
            t.push_str(EVALUATION_LINE);
            t.push('\n');
        }
        t.push_str(&format!(
            "{INTEGRITY_NOT_CHECKED}\nFlight rules: UNKNOWN (the record's integrity was not checked)\nrecord    {record_path}\n{}To check it, {how}.\n",
            claimed_lines(claimed)
        ));
        t
    };
    write_out(stdout, &text)?;
    Ok(exit_code::USAGE)
}

// ---------------------------------------------------------------------------------------------

fn version(args: &[String], crypto: &RustCrypto, stdout: &mut dyn Write) -> Result<i32, Failure> {
    let a = Args::parse(args, &[], &["--json"])?;
    let tool = this_tool();
    let text = if a.flag("--json") {
        json::pretty(
            &Obj::new()
                .field("name", Value::str(tool.name))
                .field("version", Value::str(tool.version))
                .field("build_commit", Value::str(tool.build_commit))
                .field(
                    "crypto_crates",
                    sfr_core::seal::crates_json(crypto.crates()),
                )
                .build(),
        )
    } else {
        format!(
            "{} {} (build {})\ncrypto: {}\n",
            tool.name,
            tool.version,
            tool.build_commit,
            crates_line(crypto)
        )
    };
    write_out(stdout, &text)?;
    Ok(exit_code::OK)
}

fn run(args: &[String], stdout: &mut dyn Write) -> Result<i32, Failure> {
    let Some((cmd, rest)) = args.split_first() else {
        return Err(usage("no command given"));
    };
    if matches!(cmd.as_str(), "-h" | "--help" | "help") {
        write_out(stdout, &format!("{USAGE}\n"))?;
        return Ok(exit_code::OK);
    }
    let crypto = RustCrypto;
    match cmd.as_str() {
        "keygen" => keygen(rest, &crypto, stdout),
        "seal" => seal_cmd(rest, &crypto, stdout),
        "verify" => verify_cmd(rest, &crypto, stdout),
        "pubkey" => pubkey_cmd(rest, &crypto, stdout),
        "--version" | "version" => version(rest, &crypto, stdout),
        other => Err(usage(format!("unknown command `{other}`"))),
    }
}

fn main() -> ExitCode {
    // args() panics on an argument that is not valid UTF-8; that is a usage error (exit 4).
    let args: Result<Vec<String>, _> = std::env::args_os()
        .skip(1)
        .map(|a| a.into_string())
        .collect();
    let mut stdout = io::stdout().lock();
    let result = match args {
        Ok(args) => run(&args, &mut stdout),
        Err(bad) => Err(fail(
            exit_code::USAGE,
            format!("argument {} is not valid UTF-8", bad.to_string_lossy()),
        )),
    };
    let code = match result {
        Ok(code) => code,
        Err(f) => {
            // A failed write to stderr changes nothing: the exit code carries the result.
            let _ = writeln!(
                io::stderr().lock(),
                "{}: {}",
                sfr_core::TOOL_NAME,
                f.message
            );
            f.code
        }
    };
    exit_with(code)
}

/// Converts a SPEC B1.4 exit code into the process exit status.
fn exit_with(code: i32) -> ExitCode {
    // Exit codes are 0 to 4, so the conversion cannot truncate.
    ExitCode::from(u8::try_from(code).unwrap_or(u8::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_windows_path_is_shown_with_forward_slashes() {
        // The mixed path Windows gives for `--out try/out`: the typed `/`, then the joined `\`.
        assert_eq!(
            with_slashes("try/out\\vtol_transition.sfr", '\\'),
            "try/out/vtol_transition.sfr"
        );
        assert_eq!(
            with_slashes("C:\\work\\try\\keys\\sfr.key", '\\'),
            "C:/work/try/keys/sfr.key"
        );
    }

    #[test]
    fn a_path_with_the_native_separator_only_is_unchanged() {
        assert_eq!(with_slashes("try/out/a.sfr", '/'), "try/out/a.sfr");
        assert_eq!(
            shown(Path::new("try").join("out").join("a.sfr").as_path())
                .matches('\\')
                .count(),
            0
        );
    }
}
