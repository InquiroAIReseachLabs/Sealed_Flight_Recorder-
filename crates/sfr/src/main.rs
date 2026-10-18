//! `sfr` command line (SPEC B1.2, B1.3, `crates/sfr`). Thin wrapper over `sfr-core`.
//!
//! This build implements `sfr seal --dry-run`: ingest, events, and rules, with the results
//! table or `--json`. Writing and signing records, `verify`, and `keygen` arrive in later
//! chunks; until then `seal` without `--dry-run` is a usage error (exit 4, SPEC B1.4).
#![forbid(unsafe_code)]

use sfr_core::crypto::CryptoBackend;
use sfr_core::crypto::fips::Fips;
use sfr_core::evaluate::{Evaluation, Status, evaluate};
use sfr_core::exit_code;
use sfr_core::ingest::{FlightLogIngestor, IngestError, Ingested, Px4Ingestor};
use sfr_core::json;
use sfr_core::params::parse_baseline;
use sfr_core::record::dry_run_json;
use sfr_core::rules::parse_rules;
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

const USAGE: &str = "usage: sfr seal <flight.ulg> --rules <rules.toml> --baseline <baseline.params> --dry-run [--json]";

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

struct SealArgs {
    log: String,
    rules: String,
    baseline: String,
    dry_run: bool,
    json: bool,
}

fn parse_seal(args: &[String]) -> Result<SealArgs, Failure> {
    let usage = |m: String| fail(exit_code::USAGE, format!("{m}\n{USAGE}"));
    let mut log = None;
    let mut rules = None;
    let mut baseline = None;
    let mut dry_run = false;
    let mut json = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--rules" | "--baseline" => {
                let v = it
                    .next()
                    .ok_or_else(|| usage(format!("{a} needs a file")))?;
                let slot = if a == "--rules" {
                    &mut rules
                } else {
                    &mut baseline
                };
                if slot.replace(v.clone()).is_some() {
                    return Err(usage(format!("{a} given twice")));
                }
            }
            "--dry-run" => dry_run = true,
            "--json" => json = true,
            other if other.starts_with('-') => {
                return Err(usage(format!("unknown option {other}")));
            }
            other => {
                if log.replace(other.to_string()).is_some() {
                    return Err(usage("more than one log file given".into()));
                }
            }
        }
    }
    Ok(SealArgs {
        log: log.ok_or_else(|| usage("no log file given".into()))?,
        rules: rules.ok_or_else(|| usage("--rules is required".into()))?,
        baseline: baseline.ok_or_else(|| usage("--baseline is required".into()))?,
        dry_run,
        json,
    })
}

fn read_text(path: &str, what: &str) -> Result<String, Failure> {
    let bytes = std::fs::read(path)
        .map_err(|e| fail(exit_code::USAGE, format!("cannot read {what} {path}: {e}")))?;
    String::from_utf8(bytes).map_err(|e| {
        fail(
            exit_code::MALFORMED_INPUT,
            format!(
                "{what} {path}: not UTF-8 at byte {}",
                e.utf8_error().valid_up_to()
            ),
        )
    })
}

fn sha256(crypto: &dyn CryptoBackend, data: &[u8]) -> [u8; 32] {
    let mut s = crypto.sha256_stream();
    s.update(data);
    s.finish()
}

fn table(ing: &Ingested, eval: &Evaluation, module: &str) -> String {
    let id = &ing.identity;
    let fw = &id.firmware;
    let mut out = String::new();
    out.push_str("sfr seal --dry-run: v1.0 evaluation release; nothing is signed or written\n\n");
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
        ("crypto", module.to_string()),
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

fn seal(args: &[String], stdout: &mut dyn Write) -> Result<i32, Failure> {
    let a = parse_seal(args)?;
    // SPEC B1.10 Crypto: check the module's approved mode before any other work.
    let crypto = Fips::new().map_err(|e| fail(exit_code::USAGE, e.to_string()))?;
    if !a.dry_run {
        return Err(fail(
            exit_code::USAGE,
            format!(
                "writing a signed record is not available in this build; run with --dry-run\n{USAGE}"
            ),
        ));
    }
    let rules_text = read_text(&a.rules, "rules file")?;
    let rules = parse_rules(&rules_text).map_err(|e| {
        fail(
            exit_code::MALFORMED_INPUT,
            format!("rules file {}: {e}", a.rules),
        )
    })?;
    let baseline_text = read_text(&a.baseline, "baseline")?;
    let baseline = parse_baseline(&baseline_text).map_err(|e| {
        fail(
            exit_code::MALFORMED_INPUT,
            format!("baseline {}: {e}", a.baseline),
        )
    })?;
    let mut file = File::open(&a.log)
        .map_err(|e| fail(exit_code::USAGE, format!("cannot open log {}: {e}", a.log)))?;
    let name = Path::new(&a.log)
        .file_name()
        .map_or_else(|| a.log.clone(), |n| n.to_string_lossy().into_owned());
    let ing = Px4Ingestor
        .ingest(&name, &mut file, &crypto)
        .map_err(|e| match e {
            IngestError::Malformed(m) => {
                fail(exit_code::MALFORMED_INPUT, format!("log {}: {m}", a.log))
            }
            IngestError::Io(m) => fail(exit_code::USAGE, format!("log {}: {m}", a.log)),
            limit @ IngestError::Limit(_) => fail(
                exit_code::MALFORMED_INPUT,
                format!("log {}: {limit}", a.log),
            ),
        })?;
    let eval = evaluate(&ing, &rules, &baseline);
    let text = if a.json {
        json::pretty(&dry_run_json(
            &ing,
            &eval,
            &rules,
            &baseline,
            &sha256(&crypto, rules_text.as_bytes()),
        ))
    } else {
        table(&ing, &eval, crypto.module_id())
    };
    stdout
        .write_all(text.as_bytes())
        .and_then(|()| stdout.flush())
        .map_err(|e| fail(exit_code::USAGE, format!("cannot write output: {e}")))?;
    Ok(eval.exit_code)
}

fn run(args: &[String], stdout: &mut dyn Write) -> Result<i32, Failure> {
    match args.split_first() {
        None => Err(fail(exit_code::USAGE, format!("no command given\n{USAGE}"))),
        Some((cmd, rest)) => match cmd.as_str() {
            "seal" => seal(rest, stdout),
            "-h" | "--help" | "help" => {
                writeln!(stdout, "{USAGE}")
                    .map_err(|e| fail(exit_code::USAGE, format!("cannot write output: {e}")))?;
                Ok(exit_code::OK)
            }
            "verify" | "keygen" => Err(fail(
                exit_code::USAGE,
                format!("`{cmd}` is not available in this build\n{USAGE}"),
            )),
            other => Err(fail(
                exit_code::USAGE,
                format!("unknown command `{other}`\n{USAGE}"),
            )),
        },
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
