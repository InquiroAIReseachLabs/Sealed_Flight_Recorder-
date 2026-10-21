//! Hardware key sources (SPEC B1.3, B1.7 key custody): `pkcs11-token` and `tpm-sealed`.
//!
//! Both work through child processes over pipes, never sockets (SPEC B1.10 No network):
//! `sfr-pkcs11-helper` for a PKCS#11 token or HSM, and the tpm2-tools commands for a TPM 2.0.
//! A TPM performs no Ed25519 operation: it holds the 32-byte seed sealed at rest, gives it back
//! through a pipe for one signature, and `sfr` signs and drops it (`ed25519-dalek` zeroizes it).
//! `seal` verifies every signature against the key's public half before it writes anything.

use sfr_core::crypto::rustcrypto::FileKey;
use sfr_core::crypto::{Custody, SignError, Signer};
use sfr_core::keys::{parse_public_key_pem, public_key_pem};
use sfr_core::pkcs11_uri::Pkcs11Uri;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use zeroize::Zeroizing;

/// The persistent storage key `keygen --tpm-sealed` seals under unless `--tpm-parent` names
/// another (SPEC B1.3).
pub const DEFAULT_TPM_PARENT: &str = "0x81000001";

/// The files of a `tpm-sealed` key directory.
pub const TPM_PUBLIC_BLOB: &str = "sfr.tpm.pub";
/// The sealed private blob: only the TPM that sealed it can load it.
pub const TPM_PRIVATE_BLOB: &str = "sfr.tpm.priv";
/// The parent handle and PCR selection the seed was sealed with, one `name=value` per line.
pub const TPM_SETTINGS: &str = "sfr.tpm.conf";
/// The public key (`sfr verify --pubkey`).
pub const PUBLIC_KEY_FILE: &str = "sfr.pub";

/// Runs `program` with `args`, writes `input` to its stdin, and returns its stdout. A failure
/// names the program and the end of what it printed on stderr.
fn run(program: &Path, args: &[&str], input: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    let shown = crate::vis(program);
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run {shown}: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(input)
            .map_err(|e| format!("cannot write to {shown}: {e}"))?;
    }
    let mut out = Zeroizing::new(Vec::new());
    if let Some(mut stdout) = child.stdout.take() {
        stdout
            .read_to_end(&mut out)
            .map_err(|e| format!("cannot read from {shown}: {e}"))?;
    }
    let mut err = String::new();
    if let Some(mut stderr) = child.stderr.take() {
        // Best effort: stderr only explains a failure.
        let _ = stderr.read_to_string(&mut err);
    }
    let status = child
        .wait()
        .map_err(|e| format!("{shown} did not finish: {e}"))?;
    if !status.success() {
        let tail: Vec<&str> = err.lines().filter(|l| !l.trim().is_empty()).collect();
        let tail = tail
            .get(tail.len().saturating_sub(3)..)
            .unwrap_or(&[])
            .join("; ");
        return Err(format!(
            "{shown} failed ({status}){}",
            if tail.is_empty() {
                String::new()
            } else {
                format!(": {tail}")
            }
        ));
    }
    Ok(out)
}

fn decode_hex<const N: usize>(text: &[u8], what: &str) -> Result<[u8; N], String> {
    let text = std::str::from_utf8(text)
        .map_err(|_| format!("{what} is not text"))?
        .trim();
    let bytes = sfr_core::keys::hex_decode::<N>(text)
        .ok_or_else(|| format!("{what} is not {N} bytes of lowercase hex"))?;
    Ok(bytes)
}

// ---------------------------------------------------------------------------------------------
// pkcs11-token

/// A key in a PKCS#11 token or HSM, reached through `sfr-pkcs11-helper`.
pub struct Pkcs11Key {
    helper: PathBuf,
    uri: String,
    label: String,
    public: [u8; 32],
}

/// `sfr-pkcs11-helper` in the directory of this `sfr`, by the canonical path of the running
/// binary: the helper signs as the token, so it is never looked up on `PATH` or taken from the
/// environment. Only a test build (the `dev-helper` feature, which a release build refuses) also
/// reads `SFR_PKCS11_HELPER`.
fn helper_path() -> Result<PathBuf, String> {
    #[cfg(feature = "dev-helper")]
    if let Some(p) = std::env::var_os("SFR_PKCS11_HELPER") {
        return Ok(PathBuf::from(p));
    }
    let name = format!("sfr-pkcs11-helper{}", std::env::consts::EXE_SUFFIX);
    let exe = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .map_err(|e| format!("cannot find the directory of this sfr to run {name} from: {e}"))?;
    let dir = exe.parent().ok_or_else(|| {
        format!(
            "cannot find the directory of {} to run {name} from",
            crate::vis(&exe)
        )
    })?;
    let helper = dir.join(&name);
    if !helper.is_file() {
        return Err(format!(
            "{} does not exist: sfr runs {name} only from its own directory, {}",
            crate::vis(helper),
            crate::vis(dir)
        ));
    }
    Ok(helper)
}

impl Pkcs11Key {
    /// Checks the URI and asks the token for the key's public half.
    pub fn open(uri: &str) -> Result<Pkcs11Key, String> {
        let parsed = Pkcs11Uri::parse(uri).map_err(|e| format!("--key-uri: {e}"))?;
        let helper = helper_path()?;
        let out = run(&helper, &["public-key", uri], b"")?;
        Ok(Pkcs11Key {
            public: decode_hex(&out, "the helper's public key")?,
            helper,
            uri: uri.to_string(),
            label: parsed.label(),
        })
    }
}

impl Signer for Pkcs11Key {
    fn public_key(&self) -> [u8; 32] {
        self.public
    }
    fn custody(&self) -> Custody {
        Custody::Pkcs11Token
    }
    fn label(&self) -> String {
        self.label.clone()
    }
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], SignError> {
        let out = run(&self.helper, &["sign", &self.uri], message).map_err(SignError)?;
        decode_hex(&out, "the helper's signature").map_err(SignError)
    }
}

// ---------------------------------------------------------------------------------------------
// tpm-sealed

/// Where the tpm2-tools commands are when `SFR_TPM2_TOOLS_DIR` does not say: the directory
/// Debian, Ubuntu and Fedora install them in.
pub const DEFAULT_TPM2_TOOLS_DIR: &str = "/usr/bin";

/// Whether `path`, once every symlink in it is resolved, and every directory above its real place
/// are owned by root and writable by no one else, so
/// only root can change what runs from there. A directory with the sticky bit set (such as
/// `/tmp`) may be writable by others above the tools, since others cannot rename or remove root's
/// entries in it. `Err` names the first path that fails.
#[cfg(unix)]
fn root_owned_and_closed(path: &std::path::Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    // The real path: a symlink on the way would otherwise hide the parents that matter, those of
    // the directory it leads to.
    let real = std::fs::canonicalize(path).map_err(|e| format!("{}: {e}", crate::vis(path)))?;
    let mut first = true;
    for p in real.ancestors() {
        let m = std::fs::metadata(p).map_err(|e| format!("{}: {e}", crate::vis(p)))?;
        if m.uid() != 0 {
            return Err(format!(
                "{} is owned by uid {}, not root",
                crate::vis(p),
                m.uid()
            ));
        }
        let open = m.mode() & 0o022 != 0;
        let sticky = m.is_dir() && m.mode() & 0o1000 != 0;
        if open && (first || !sticky) {
            return Err(format!(
                "{} is writable by group or others (mode {:04o})",
                crate::vis(p),
                m.mode() & 0o7777
            ));
        }
        first = false;
    }
    Ok(())
}

/// The tpm2-tools command `name`, by an absolute path: in `SFR_TPM2_TOOLS_DIR`, which must be an
/// absolute directory that only root can change (it, every directory above it, and the command
/// owned by root and writable by no one else), else in [`DEFAULT_TPM2_TOOLS_DIR`]. Never looked
/// up on `PATH`: whatever runs here sees the seed. The commands find the TPM through their own
/// configuration (`TPM2TOOLS_TCTI`, else `/dev/tpmrm0`).
fn tpm2(name: &str) -> Result<PathBuf, String> {
    let dir = match std::env::var_os("SFR_TPM2_TOOLS_DIR") {
        Some(d) => {
            let d = PathBuf::from(d);
            if !d.is_absolute() {
                return Err(format!(
                    "SFR_TPM2_TOOLS_DIR is {}, not an absolute directory; sfr runs tpm2-tools only by an absolute path",
                    crate::vis(d)
                ));
            }
            d
        }
        None => PathBuf::from(DEFAULT_TPM2_TOOLS_DIR),
    };
    let tool = dir.join(name);
    if !tool.is_file() {
        return Err(format!(
            "{} does not exist: install tpm2-tools, or set SFR_TPM2_TOOLS_DIR to the absolute directory that holds them (sfr never searches PATH)",
            crate::vis(tool)
        ));
    }
    // A directory named in the environment is trusted only if only root can change it.
    if std::env::var_os("SFR_TPM2_TOOLS_DIR").is_some() {
        #[cfg(unix)]
        root_owned_and_closed(&tool).map_err(|why| {
            format!(
                "SFR_TPM2_TOOLS_DIR {}: {why}; sfr runs tpm2-tools only from a directory only root can change",
                crate::vis(dir)
            )
        })?;
        #[cfg(not(unix))]
        return Err("SFR_TPM2_TOOLS_DIR is read on Unix systems only".into());
    }
    Ok(tool)
}

/// A private scratch directory for TPM object contexts, removed on drop. It never holds key
/// material: the seed only passes through pipes.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Result<Scratch, String> {
        let mut nonce = [0u8; 8];
        getrandom::fill(&mut nonce)
            .map_err(|e| format!("the operating system's random number generator failed: {e}"))?;
        let dir = std::env::temp_dir().join(format!("sfr-tpm-{}", sfr_core::hex(&nonce)));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(&dir)
            .map_err(|e| format!("cannot create {}: {e}", crate::vis(&dir)))?;
        Ok(Scratch(dir))
    }
    fn path(&self, name: &str) -> String {
        self.0.join(name).display().to_string()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // Best effort: only object contexts and a policy digest were here.
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Checks a TPM handle such as `0x81000001`.
fn check_handle(handle: &str) -> Result<(), String> {
    let ok = handle
        .strip_prefix("0x")
        .is_some_and(|h| h.len() == 8 && h.bytes().all(|b| b.is_ascii_hexdigit()));
    if ok {
        Ok(())
    } else {
        Err(format!(
            "TPM handle `{handle}` is not 0x and eight hex digits (for example {DEFAULT_TPM_PARENT})"
        ))
    }
}

/// Checks a PCR selection such as `sha256:0,7` (tpm2-tools syntax, one bank).
fn check_pcrs(pcrs: &str) -> Result<(), String> {
    let ok = pcrs.split_once(':').is_some_and(|(bank, list)| {
        matches!(bank, "sha1" | "sha256" | "sha384" | "sha512")
            && !list.is_empty()
            && list
                .split(',')
                .all(|n| n.parse::<u8>().is_ok_and(|n| n < 24))
    });
    if ok {
        Ok(())
    } else {
        Err(format!(
            "--tpm-pcrs `{pcrs}` is not <bank>:<list> with PCRs 0 to 23 (for example sha256:0,7)"
        ))
    }
}

/// The settings a `tpm-sealed` key was made with.
struct TpmSettings {
    parent: String,
    pcrs: Option<String>,
}

impl TpmSettings {
    fn text(&self) -> String {
        format!(
            "parent={}\npcrs={}\n",
            self.parent,
            self.pcrs.as_deref().unwrap_or("")
        )
    }
    fn parse(text: &str) -> Result<TpmSettings, String> {
        let mut parent = None;
        let mut pcrs = None;
        for line in text.lines().filter(|l| !l.is_empty()) {
            match line.split_once('=') {
                Some(("parent", v)) => parent = Some(v.to_string()),
                Some(("pcrs", v)) => pcrs = Some(v.to_string()).filter(|v| !v.is_empty()),
                _ => return Err(format!("{TPM_SETTINGS}: unknown line `{line}`")),
            }
        }
        let parent = parent.ok_or_else(|| format!("{TPM_SETTINGS} has no parent= line"))?;
        check_handle(&parent)?;
        if let Some(p) = &pcrs {
            check_pcrs(p)?;
        }
        Ok(TpmSettings { parent, pcrs })
    }
}

/// `keygen --tpm-sealed`: seals `seed` to this machine's TPM under `parent` (with a PCR policy
/// when `pcrs` is given) and writes the key directory. Returns the paths written, the public key
/// last.
pub fn tpm_keygen(
    dir: &Path,
    seed: &[u8; 32],
    parent: &str,
    pcrs: Option<&str>,
    public: &[u8; 32],
) -> Result<Vec<PathBuf>, String> {
    check_handle(parent)?;
    if let Some(p) = pcrs {
        check_pcrs(p)?;
    }
    let files: Vec<PathBuf> = [
        TPM_PUBLIC_BLOB,
        TPM_PRIVATE_BLOB,
        TPM_SETTINGS,
        PUBLIC_KEY_FILE,
    ]
    .iter()
    .map(|f| dir.join(f))
    .collect();
    for f in &files {
        if f.symlink_metadata().is_ok() {
            return Err(format!(
                "{} exists; keygen never overwrites a key",
                crate::vis(f)
            ));
        }
    }
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", crate::vis(dir)))?;
    let scratch = Scratch::new()?;
    // Sealed data object: fixedtpm|fixedparent (no other TPM, no other parent can load it).
    // Without a PCR policy it is authorized by its empty password (userwithauth); with one,
    // only by the policy, so the PCRs must match to unseal.
    let mut attributes = String::from("fixedtpm|fixedparent");
    let policy = scratch.path("policy.digest");
    if let Some(p) = pcrs {
        run(
            &tpm2("tpm2_createpolicy")?,
            &["--policy-pcr", "-l", p, "-L", &policy, "-Q"],
            b"",
        )?;
    } else {
        attributes.push_str("|userwithauth");
    }
    let (pub_blob, priv_blob) = (
        scratch.path(TPM_PUBLIC_BLOB),
        scratch.path(TPM_PRIVATE_BLOB),
    );
    let mut args = vec![
        "-C",
        parent,
        "-i",
        "-",
        "-u",
        &pub_blob,
        "-r",
        &priv_blob,
        "-a",
        &attributes,
        "-Q",
    ];
    if pcrs.is_some() {
        args.extend(["-L", policy.as_str()]);
    }
    // The seed goes to the TPM through a pipe; it never touches disk.
    run(&tpm2("tpm2_create")?, &args, seed)?;
    let settings = TpmSettings {
        parent: parent.to_string(),
        pcrs: pcrs.map(str::to_string),
    };
    // Prove the round trip before anything is written: the TPM gives back this seed.
    let back = unseal(
        &scratch,
        &settings,
        Path::new(&pub_blob),
        Path::new(&priv_blob),
    )?;
    if *back != *seed {
        return Err("the TPM did not return the sealed seed; nothing written".into());
    }
    let mut written = Vec::new();
    let write_new = |path: &Path, bytes: &[u8]| -> Result<(), String> {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .and_then(|mut f| f.write_all(bytes).and_then(|()| f.sync_all()))
            .map_err(|e| format!("cannot write {}: {e}", crate::vis(path)))
    };
    let contents: [Vec<u8>; 4] = [
        std::fs::read(&pub_blob).map_err(|e| format!("cannot read {pub_blob}: {e}"))?,
        std::fs::read(&priv_blob).map_err(|e| format!("cannot read {priv_blob}: {e}"))?,
        settings.text().into_bytes(),
        public_key_pem(public).into_bytes(),
    ];
    for (path, bytes) in files.iter().zip(contents.iter()) {
        if let Err(e) = write_new(path, bytes) {
            for p in &written {
                // Best effort: the error below is the one to report.
                let _ = std::fs::remove_file(p);
            }
            return Err(e);
        }
        written.push(path.clone());
    }
    Ok(written)
}

/// Loads the sealed object under its parent and unseals the seed, through pipes.
fn unseal(
    scratch: &Scratch,
    settings: &TpmSettings,
    pub_blob: &Path,
    priv_blob: &Path,
) -> Result<Zeroizing<[u8; 32]>, String> {
    let context = scratch.path("object.ctx");
    run(
        &tpm2("tpm2_load")?,
        &[
            "-C",
            &settings.parent,
            "-u",
            &pub_blob.display().to_string(),
            "-r",
            &priv_blob.display().to_string(),
            "-c",
            &context,
            "-Q",
        ],
        b"",
    )?;
    let auth = settings.pcrs.as_ref().map(|p| format!("pcr:{p}"));
    let mut args = vec!["-c", context.as_str()];
    if let Some(a) = &auth {
        args.extend(["-p", a.as_str()]);
    }
    let out = run(&tpm2("tpm2_unseal")?, &args, b"")?;
    let seed: [u8; 32] = out
        .as_slice()
        .try_into()
        .map_err(|_| format!("the TPM unsealed {} bytes, not a 32-byte seed", out.len()))?;
    Ok(Zeroizing::new(seed))
}

/// `seal --key-uri tpm-sealed:<dir>`: unseals the seed from this machine's TPM, checks it
/// against the directory's `sfr.pub`, and returns a key with custody `tpm-sealed`.
pub fn tpm_key(dir: &Path) -> Result<FileKey, String> {
    let read = |name: &str| {
        let p = dir.join(name);
        std::fs::read_to_string(&p).map_err(|e| format!("cannot read {}: {e}", crate::vis(p)))
    };
    let settings = TpmSettings::parse(&read(TPM_SETTINGS)?)?;
    let expected = parse_public_key_pem(&read(PUBLIC_KEY_FILE)?)
        .map_err(|e| format!("{}: {e}", crate::vis(dir.join(PUBLIC_KEY_FILE))))?;
    let scratch = Scratch::new()?;
    let seed = unseal(
        &scratch,
        &settings,
        &dir.join(TPM_PUBLIC_BLOB),
        &dir.join(TPM_PRIVATE_BLOB),
    )?;
    let label = dir.file_name().map_or_else(
        || dir.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    );
    let key = FileKey::unsealed_from_tpm(&seed, &label);
    if key.public_key() != expected {
        return Err(format!(
            "the seed this TPM unsealed is not the key in {}",
            crate::vis(dir.join(PUBLIC_KEY_FILE))
        ));
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles_pcrs_and_settings_are_checked() {
        assert!(check_handle("0x81000001").is_ok());
        for bad in ["81000001", "0x8100001", "0x8100000g", "0x810000011"] {
            assert!(check_handle(bad).is_err(), "{bad}");
        }
        assert!(check_pcrs("sha256:0,7").is_ok());
        for bad in ["sha256", "sha256:", "md5:0", "sha256:24", "sha256:0,,7"] {
            assert!(check_pcrs(bad).is_err(), "{bad}");
        }
        let s = TpmSettings {
            parent: DEFAULT_TPM_PARENT.into(),
            pcrs: Some("sha256:0,7".into()),
        };
        let back = TpmSettings::parse(&s.text());
        assert!(back.is_ok_and(|b| b.parent == s.parent && b.pcrs == s.pcrs));
        let none = TpmSettings::parse("parent=0x81000001\npcrs=\n");
        assert!(none.is_ok_and(|b| b.pcrs.is_none()));
        assert!(TpmSettings::parse("pcrs=sha256:0\n").is_err());
        assert!(TpmSettings::parse("parent=0x81000001\nowner=me\n").is_err());
    }
}
