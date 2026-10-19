//! `sfr-pkcs11-helper` (SPEC B1.2): Ed25519 from a PKCS#11 v3.0 token or HSM, one operation
//! per process.
//!
//! `sfr seal --key-uri pkcs11:...` runs this process twice: once for the public key, so the
//! record can name the key's fingerprint before it is signed, and once to sign the payload. It
//! runs apart from `sfr` because a static musl binary cannot load a vendor PKCS#11 module; the
//! module is loaded here and nowhere else. `sfr` verifies the returned signature against the
//! returned public key before it writes anything.
//!
//! ```text
//! sfr-pkcs11-helper public-key <pkcs11 URI>   stdout: the 32-byte public key, lowercase hex
//! sfr-pkcs11-helper sign <pkcs11 URI>         stdin: the payload; stdout: the 64-byte signature, hex
//! ```
//!
//! The URI (RFC 7512, `sfr_core::pkcs11_uri`) names the module, the PIN source, the token and the
//! key. The key must be an Ed25519 key (`CKK_EC_EDWARDS` with the Ed25519 curve) and the
//! signature is pure Ed25519 (`CKM_EDDSA` without parameters, RFC 8032). Exit 0 on success; on
//! any failure a message on stderr and exit 4 (SPEC B1.4), with nothing on stdout.
#![forbid(unsafe_code)]

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use sfr_core::pkcs11_uri::{PinSource, Pkcs11Uri};
use std::io::{Read, Write};
use std::process::ExitCode;
use zeroize::Zeroizing;

/// The DER of the Ed25519 curve's object identifier, 1.3.101.112 (RFC 8410), as `CKA_EC_PARAMS`.
const ED25519_OID_DER: [u8; 5] = [0x06, 0x03, 0x2b, 0x65, 0x70];
/// `CKA_EC_PARAMS` as the printable string "edwards25519", which PKCS#11 v3.0 also allows.
const ED25519_NAME_DER: &[u8] = b"\x13\x0cedwards25519";
/// The largest payload `sign` accepts. The signed payload of a record is 50 bytes (SPEC B1.7).
const MAX_PAYLOAD: u64 = 1024;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(hex) => {
            let mut out = std::io::stdout().lock();
            match writeln!(out, "{hex}").and_then(|()| out.flush()) {
                Ok(()) => ExitCode::SUCCESS,
                Err(_) => ExitCode::from(4),
            }
        }
        Err(message) => {
            // A failed write to stderr changes nothing: the exit code carries the result.
            let _ = writeln!(std::io::stderr().lock(), "sfr-pkcs11-helper: {message}");
            ExitCode::from(4)
        }
    }
}

fn run(args: &[String]) -> Result<String, String> {
    let (command, uri) = match args {
        [c, u] => (c.as_str(), u.as_str()),
        _ => {
            return Err("usage: sfr-pkcs11-helper (public-key | sign) <pkcs11 URI>".into());
        }
    };
    if command != "public-key" && command != "sign" {
        return Err(format!("unknown command `{command}`: public-key or sign"));
    }
    let uri = Pkcs11Uri::parse(uri).map_err(|e| format!("key URI: {e}"))?;
    let payload = if command == "sign" {
        let mut buf = Vec::new();
        std::io::stdin()
            .lock()
            .take(MAX_PAYLOAD + 1)
            .read_to_end(&mut buf)
            .map_err(|e| format!("reading the payload: {e}"))?;
        if buf.len() as u64 > MAX_PAYLOAD || buf.is_empty() {
            return Err(format!(
                "the payload must be 1 to {MAX_PAYLOAD} bytes on standard input"
            ));
        }
        Some(buf)
    } else {
        None
    };
    let pin = read_pin(&uri)?;
    let pkcs11 = Pkcs11::new(&uri.module_path)
        .map_err(|e| format!("cannot load module {}: {e}", uri.module_path))?;
    pkcs11
        .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
        .map_err(|e| format!("C_Initialize: {e}"))?;
    let slot = find_slot(&pkcs11, &uri)?;
    let session = pkcs11
        .open_ro_session(slot)
        .map_err(|e| format!("C_OpenSession: {e}"))?;
    session
        .login(UserType::User, Some(&pin))
        .map_err(|e| format!("C_Login: {e}"))?;
    let public = public_key(&session, &uri)?;
    let result = match payload {
        None => Ok(sfr_core::hex(&public)),
        Some(payload) => {
            let key = one_object(&session, &uri, ObjectClass::PRIVATE_KEY)?;
            let sig = session
                .sign(
                    &Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Pure)),
                    key,
                    &payload,
                )
                .map_err(|e| format!("C_Sign (CKM_EDDSA): {e}"))?;
            if sig.len() != 64 {
                return Err(format!(
                    "the token returned a {}-byte signature; Ed25519 signatures are 64 bytes",
                    sig.len()
                ));
            }
            Ok(sfr_core::hex(&sig))
        }
    };
    // Best effort: the session closes with the process either way.
    let _ = session.logout();
    result
}

fn read_pin(uri: &Pkcs11Uri) -> Result<AuthPin, String> {
    let pin = match &uri.pin_source {
        Some(PinSource::File(path)) => {
            let text = Zeroizing::new(
                std::fs::read_to_string(path)
                    .map_err(|e| format!("cannot read the PIN file {path}: {e}"))?,
            );
            text.lines().next().unwrap_or("").to_string()
        }
        Some(PinSource::Env(var)) => std::env::var(var)
            .map_err(|_| format!("the PIN variable {var} is not set or not UTF-8"))?,
        None => return Err("the key URI has no pin-source".into()),
    };
    if pin.is_empty() {
        return Err("the PIN is empty".into());
    }
    Ok(AuthPin::from(pin))
}

/// The one slot whose token matches every token attribute the URI gives.
fn find_slot(pkcs11: &Pkcs11, uri: &Pkcs11Uri) -> Result<Slot, String> {
    let mut found = Vec::new();
    for slot in pkcs11
        .get_slots_with_token()
        .map_err(|e| format!("C_GetSlotList: {e}"))?
    {
        if uri.slot_id.is_some_and(|id| id != slot.id()) {
            continue;
        }
        let info = pkcs11
            .get_token_info(slot)
            .map_err(|e| format!("C_GetTokenInfo: {e}"))?;
        let matches = |want: &Option<String>, have: &str| {
            want.as_ref()
                .is_none_or(|w| w.trim_end() == have.trim_end())
        };
        if matches(&uri.token, info.label())
            && matches(&uri.serial, info.serial_number())
            && matches(&uri.manufacturer, info.manufacturer_id())
            && matches(&uri.model, info.model())
        {
            found.push(slot);
        }
    }
    match found.as_slice() {
        [slot] => Ok(*slot),
        [] => Err("no token matches the key URI".into()),
        _ => Err(format!(
            "{} tokens match the key URI; add token=, serial= or slot-id= to choose one",
            found.len()
        )),
    }
}

/// The one Ed25519 key object of `class` that the URI names.
fn one_object(
    session: &Session,
    uri: &Pkcs11Uri,
    class: ObjectClass,
) -> Result<ObjectHandle, String> {
    let mut template = vec![
        Attribute::Class(class),
        Attribute::KeyType(KeyType::EC_EDWARDS),
    ];
    if let Some(label) = &uri.object {
        template.push(Attribute::Label(label.as_bytes().to_vec()));
    }
    if let Some(id) = &uri.id {
        template.push(Attribute::Id(id.clone()));
    }
    let what = if class == ObjectClass::PRIVATE_KEY {
        "private"
    } else {
        "public"
    };
    let found = session
        .find_objects(&template)
        .map_err(|e| format!("C_FindObjects: {e}"))?;
    match found.as_slice() {
        [one] => Ok(*one),
        [] => Err(format!(
            "no Edwards-curve {what} key in the token matches the key URI"
        )),
        _ => Err(format!(
            "{} {what} keys match the key URI; give both object= and id=",
            found.len()
        )),
    }
}

/// The 32-byte Ed25519 public key of the key the URI names, from its public key object.
fn public_key(session: &Session, uri: &Pkcs11Uri) -> Result<[u8; 32], String> {
    let key = one_object(session, uri, ObjectClass::PUBLIC_KEY)?;
    let attrs = session
        .get_attributes(key, &[AttributeType::EcParams, AttributeType::EcPoint])
        .map_err(|e| format!("C_GetAttributeValue: {e}"))?;
    let mut params = None;
    let mut point = None;
    for a in attrs {
        match a {
            Attribute::EcParams(p) => params = Some(p),
            Attribute::EcPoint(p) => point = Some(p),
            _ => {}
        }
    }
    let params = params.ok_or("the public key has no CKA_EC_PARAMS")?;
    if params != ED25519_OID_DER && params != ED25519_NAME_DER {
        return Err("the key is not on the Ed25519 curve (CKA_EC_PARAMS)".into());
    }
    let point = point.ok_or("the public key has no CKA_EC_POINT")?;
    ed25519_point(&point).ok_or_else(|| {
        format!(
            "CKA_EC_POINT is neither 32 bytes nor a DER OCTET STRING of 32 bytes ({} bytes)",
            point.len()
        )
    })
}

/// `CKA_EC_POINT` of an Ed25519 key: the 32 raw bytes, which PKCS#11 v3.0 specifies, or the
/// DER OCTET STRING around them, which many tokens return.
fn ed25519_point(point: &[u8]) -> Option<[u8; 32]> {
    let raw = match point {
        [0x04, 0x20, rest @ ..] if rest.len() == 32 => rest,
        _ if point.len() == 32 => point,
        _ => return None,
    };
    raw.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ec_point_accepts_raw_and_der_forms_only() {
        let raw = [7u8; 32];
        let mut der = vec![0x04, 0x20];
        der.extend_from_slice(&raw);
        assert_eq!(ed25519_point(&raw), Some(raw));
        assert_eq!(ed25519_point(&der), Some(raw));
        assert_eq!(ed25519_point(der.get(..33).unwrap_or(&[])), None);
        assert_eq!(ed25519_point(&[0x04; 65]), None);
    }

    #[test]
    fn bad_arguments_are_refused_before_any_module_is_loaded() {
        let e = run(&["sign".into()]).err();
        assert!(e.is_some_and(|e| e.starts_with("usage:")));
        let e = run(&["delete".into(), "pkcs11:object=k".into()]).err();
        assert!(e.is_some_and(|e| e.contains("unknown command")));
        let e = run(&[
            "public-key".into(),
            "pkcs11:object=k?module-path=/m.so&pin-value=1".into(),
        ])
        .err();
        assert!(e.is_some_and(|e| e.contains("pin-value")));
    }
}
