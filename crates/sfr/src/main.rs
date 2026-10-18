//! `sfr` command line (SPEC B1.2, B1.3, `crates/sfr`). Thin wrapper over `sfr-core`.
//!
//! Commands: `keygen --evaluation-only`, `seal` (with `--dry-run`, or writing a signed `.sfr`
//! with an evaluation key file), `verify` (standalone with `--pubkey`, deep with `--ulog`),
//! and `--version`. Hardware key sources and certificate chains are recognised and refused
//! with exit 4 until they are built. Exit codes follow SPEC B1.4.
#![forbid(unsafe_code)]

use sfr_core::crypto::fips::{FileKey, Fips};
use sfr_core::crypto::{CryptoBackend, Custody, Signer};
use sfr_core::evaluate::{Evaluation, Status, evaluate};
use sfr_core::exit_code;
use sfr_core::ingest::{FlightLogIngestor, IngestError, Ingested, Px4Ingestor};
use sfr_core::json::{self, Obj, Value};
use sfr_core::keys::{fingerprint, parse_public_key_pem, pem_decode, pem_encode, public_key_pem};
use sfr_core::params::{Baseline, parse_baseline};
use sfr_core::record::dry_run_json;
use sfr_core::rules::{Rules, parse_rules};
use sfr_core::seal::{SealParams, format_utc, parse_seal_time, seal, this_tool};
use sfr_core::verify::{MAX_RECORD_BYTES, VerifyError, verify};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use zeroize::Zeroizing;

const USAGE: &str = "usage:
  sfr keygen --evaluation-only --out <dir> [--json]
  sfr seal <flight.ulg> --rules <rules.toml> --baseline <baseline.params>
           (--key <sfr.key> --evaluation-only | --dry-run) [--out <dir>] [--seal-time <RFC3339>] [--json]
  sfr verify <record.sfr> --pubkey <sfr.pub> [--ulog <flight.ulg>] [--require-hardware-key] [--json]
  sfr --version [--json]";

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
                if out.values.iter().any(|(k, _)| k == a) {
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

/// Reads at most `max` bytes; a longer file fails with exit code `code` and names the limit.
fn read_bytes(path: &str, what: &str, max: u64, code: i32) -> Result<Vec<u8>, Failure> {
    let file = File::open(path)
        .map_err(|e| fail(exit_code::USAGE, format!("cannot read {what} {path}: {e}")))?;
    let mut buf = Vec::new();
    file.take(max + 1)
        .read_to_end(&mut buf)
        .map_err(|e| fail(exit_code::USAGE, format!("cannot read {what} {path}: {e}")))?;
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

fn file_name(path: &str) -> String {
    Path::new(path)
        .file_name()
        .map_or_else(|| path.to_string(), |n| n.to_string_lossy().into_owned())
}

fn module_line(crypto: &dyn CryptoBackend) -> String {
    let m = crypto.module_info();
    format!(
        "{} profile, {}, CMVP certificate {}",
        m.profile,
        m.module,
        m.certificate.unwrap_or("none")
    )
}

// ---------------------------------------------------------------------------------------------
// keygen

fn keygen(args: &[String], crypto: &Fips, stdout: &mut dyn Write) -> Result<i32, Failure> {
    let a = Args::parse(
        args,
        &["--out"],
        &["--evaluation-only", "--tpm-sealed", "--json"],
    )?;
    if a.flag("--tpm-sealed") {
        return Err(fail(
            exit_code::USAGE,
            "keygen --tpm-sealed is not available in this build; use --evaluation-only for evaluation keys",
        ));
    }
    if !a.flag("--evaluation-only") {
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
    let (pkcs8, public) = crypto
        .generate_ed25519()
        .map_err(|e| fail(exit_code::USAGE, e.to_string()))?;
    let key_pem = Zeroizing::new(pem_encode("PRIVATE KEY", &pkcs8));
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
                .field("private_key", Value::str(key_path.display().to_string()))
                .field("public_key", Value::str(pub_path.display().to_string()))
                .build(),
        )
    } else {
        format!(
            "{EVALUATION_LINE}\nfingerprint  {fp}\nprivate key  {} (mode 0600)\npublic key   {}\n",
            key_path.display(),
            pub_path.display()
        )
    };
    write_out(stdout, &text)?;
    Ok(exit_code::OK)
}

// ---------------------------------------------------------------------------------------------
// seal

fn table(ing: &Ingested, eval: &Evaluation, crypto: &dyn CryptoBackend, dry_run: bool) -> String {
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
        ("crypto", module_line(crypto)),
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
    out.push('\n');
    out.push_str(&format!("{:<10}{}\n", "events", ing.events.len()));
    out.push_str(&format!("{:<10}{}\n", "status", eval.status.as_str()));
    out
}

fn seal_cmd(args: &[String], crypto: &Fips, stdout: &mut dyn Write) -> Result<i32, Failure> {
    let a = Args::parse(
        args,
        &[
            "--rules",
            "--baseline",
            "--key",
            "--key-uri",
            "--token-cert",
            "--cert",
            "--chain",
            "--out",
            "--seal-time",
        ],
        &["--dry-run", "--json", "--evaluation-only"],
    )?;
    let log = a.one_positional("log file")?.to_string();
    let rules_path = a
        .value("--rules")
        .ok_or_else(|| usage("--rules is required"))?;
    let baseline_path = a
        .value("--baseline")
        .ok_or_else(|| usage("--baseline is required"))?;
    let dry_run = a.flag("--dry-run");
    if a.value("--cert").is_some() || a.value("--chain").is_some() {
        return Err(fail(
            exit_code::USAGE,
            "--cert and --chain (signer certificates) are not available in this build",
        ));
    }
    // The key source is checked before any work, so a usage error costs nothing.
    let key: Option<FileKey> = if dry_run {
        None
    } else if a.value("--key-uri").is_some() {
        return Err(fail(
            exit_code::USAGE,
            "hardware key sources (--key-uri pkcs11:... and --key-uri tpm-sealed:<dir>) are not available in this build; \
             use --key <sfr.key> --evaluation-only for evaluation records",
        ));
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
        Some(
            FileKey::from_pkcs8_der(&der, &file_name(path))
                .map_err(|e| fail(exit_code::USAGE, format!("key file {path}: {e}")))?,
        )
    } else {
        return Err(fail(
            exit_code::USAGE,
            "seal needs a key source: --key-uri pkcs11:..., --key-uri tpm-sealed:<dir>, or --key <sfr.key> \
             --evaluation-only (or --dry-run to sign nothing)",
        ));
    };
    if a.value("--token-cert").is_some() {
        return Err(usage("--token-cert applies only to --key-uri pkcs11:..."));
    }
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
    if !dry_run && out_path.exists() {
        return Err(fail(
            exit_code::USAGE,
            format!(
                "{} exists; seal never overwrites a record",
                out_path.display()
            ),
        ));
    }

    let rules_text = read_text(rules_path, "rules file", exit_code::MALFORMED_INPUT)?;
    let rules: Rules = parse_rules(&rules_text).map_err(|e| {
        fail(
            exit_code::MALFORMED_INPUT,
            format!("rules file {rules_path}: {e}"),
        )
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
        .ingest(&file_name(&log), &mut file, crypto)
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
    let mut stderr = io::stderr().lock();
    if ing
        .identity
        .firmware
        .series()
        .is_none_or(|s| !((1, 14)..=(1, 17)).contains(&s))
    {
        let _ = writeln!(
            stderr,
            "sfr: note: log {log}: firmware {} is outside the supported range PX4 v1.14 to v1.17; \
             version-dependent names are null",
            ing.identity
                .firmware
                .version
                .as_deref()
                .unwrap_or("unknown")
        );
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
            table(&ing, &eval, crypto, true)
        };
        write_out(stdout, &text)?;
        return Ok(eval.exit_code);
    };

    let params = SealParams {
        time_utc,
        token_cmvp_certificate: None,
    };
    let sealed = seal(&ing, &eval, &rules, &baseline, &params, crypto, &key)
        .map_err(|e| fail(exit_code::USAGE, e.to_string()))?;
    std::fs::create_dir_all(&out_dir).map_err(|e| {
        fail(
            exit_code::USAGE,
            format!("cannot create {}: {e}", out_dir.display()),
        )
    })?;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&out_path)
        .and_then(|mut f| f.write_all(&sealed.bytes).and_then(|()| f.sync_all()))
        .map_err(|e| {
            fail(
                exit_code::USAGE,
                format!("cannot write {}: {e}", out_path.display()),
            )
        })?;
    let custody = key.custody();
    let text = if a.flag("--json") {
        json::pretty(
            &Obj::new()
                .field("record", Value::str(out_path.display().to_string()))
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
        t.push_str(&table(&ing, &eval, crypto, false));
        t.push_str(&format!(
            "\n{:<10}{}\n{:<10}{}\n{:<10}{} ({})\n{:<10}{}\n",
            "record",
            out_path.display(),
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

fn verify_cmd(args: &[String], crypto: &Fips, stdout: &mut dyn Write) -> Result<i32, Failure> {
    let a = Args::parse(
        args,
        &["--pubkey", "--ulog", "--trust-anchor", "--crl"],
        &["--require-hardware-key", "--json"],
    )?;
    let record_path = a.one_positional("record")?.to_string();
    if a.value("--trust-anchor").is_some() || a.value("--crl").is_some() {
        return Err(fail(
            exit_code::USAGE,
            "--trust-anchor and --crl (certificate chains) are not available in this build; use --pubkey",
        ));
    }
    let pub_path = a
        .value("--pubkey")
        .ok_or_else(|| usage("--pubkey <sfr.pub> is required"))?;
    let public = parse_public_key_pem(&read_text(pub_path, "public key", exit_code::USAGE)?)
        .map_err(|e| fail(exit_code::USAGE, format!("public key {pub_path}: {e}")))?;
    // One byte over the limit is read so that `verify` reports the oversize record as a
    // verification failure (exit 1) naming the limit.
    let record = read_bytes(
        &record_path,
        "record",
        MAX_RECORD_BYTES as u64 + 1,
        exit_code::RULE_FAIL,
    )?;
    let mut log_file = match a.value("--ulog") {
        Some(p) => Some(
            File::open(p)
                .map_err(|e| fail(exit_code::USAGE, format!("cannot open log {p}: {e}")))?,
        ),
        None => None,
    };
    let log: Option<&mut dyn Read> = log_file.as_mut().map(|f| f as &mut dyn Read);
    let deep = log.is_some();
    let outcome = verify(
        &record,
        log,
        crypto,
        &public,
        a.flag("--require-hardware-key"),
    );
    let json_out = a.flag("--json");
    match outcome {
        Err(VerifyError::Io(e)) => Err(fail(exit_code::USAGE, format!("log: {e}"))),
        Ok(v) => {
            let text = if json_out {
                json::pretty(
                    &Obj::new()
                        .field("verified", Value::Bool(true))
                        .field("record", Value::str(record_path.clone()))
                        .field("deep", Value::Bool(v.deep))
                        .field("key_custody", Value::str(v.custody.as_str()))
                        .field("key_fingerprint", Value::str(v.fingerprint.clone()))
                        .field("crypto_module", Value::str(v.crypto_module.clone()))
                        .field("sealed_utc", Value::str(v.time_utc.clone()))
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
                t.push_str(&format!(
                    "VERIFIED{}\nrecord    {record_path}\ncustody   {}\nkey       {}\ncrypto    {}\nsealed    {}\nstatus    {}\nevents    {}\n",
                    if v.deep { " (record and log)" } else { " (record)" },
                    v.custody.as_str(),
                    v.fingerprint,
                    v.crypto_module,
                    v.time_utc,
                    v.status,
                    v.events
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
                        .field("record", Value::str(record_path.clone()))
                        .field("deep", Value::Bool(deep))
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
                let mut t = format!("FAILED: {}\n", m.first);
                for other in m.also.iter().take(20) {
                    t.push_str(&format!("  also: {other}\n"));
                }
                if m.also.len() > 20 {
                    t.push_str(&format!("  and {} more\n", m.also.len() - 20));
                }
                t
            };
            write_out(stdout, &text)?;
            Ok(exit_code::RULE_FAIL)
        }
    }
}

// ---------------------------------------------------------------------------------------------

fn version(args: &[String], crypto: &Fips, stdout: &mut dyn Write) -> Result<i32, Failure> {
    let a = Args::parse(args, &[], &["--json"])?;
    let tool = this_tool();
    let m = crypto.module_info();
    let text = if a.flag("--json") {
        json::pretty(
            &Obj::new()
                .field("name", Value::str(tool.name))
                .field("version", Value::str(tool.version))
                .field("build_commit", Value::str(tool.build_commit))
                .field("crypto_profile", Value::str(m.profile))
                .field("crypto_module", Value::str(m.module.clone()))
                .field("cmvp_certificate", Value::opt_str(m.certificate))
                .build(),
        )
    } else {
        format!(
            "{} {} (build {})\ncrypto: {}\n",
            tool.name,
            tool.version,
            tool.build_commit,
            module_line(crypto)
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
    // SPEC B1.10 Crypto: check the module's approved mode before any other work.
    let crypto = Fips::new().map_err(|e| fail(exit_code::USAGE, e.to_string()))?;
    match cmd.as_str() {
        "keygen" => keygen(rest, &crypto, stdout),
        "seal" => seal_cmd(rest, &crypto, stdout),
        "verify" => verify_cmd(rest, &crypto, stdout),
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
