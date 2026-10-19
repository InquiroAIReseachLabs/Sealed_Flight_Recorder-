//! `pkcs11:` key URIs (RFC 7512) for `seal --key-uri` (SPEC B1.3).
//!
//! `sfr` checks the URI before any work and hands it to `sfr-pkcs11-helper`, which parses it
//! again with this module and finds the key in the token. Path attributes select the token and
//! the key; two query attributes say where the token's module is and where its PIN is:
//!
//! ```text
//! pkcs11:token=flight-keys;object=sfr-seal?module-path=/usr/lib/softhsm/libsofthsm2.so&pin-source=file:/etc/sfr/pin
//! ```
//!
//! `pin-value` (a PIN written into the URI, where a process list or a shell history would show
//! it) is refused. `module-path` and `pin-source` are required; `pin-source` is `file:<path>`
//! (the first line of the file) or `env:<variable>`.

use std::fmt;

/// Where the token's user PIN comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinSource {
    /// The first line of this file.
    File(String),
    /// This environment variable.
    Env(String),
}

/// A parsed `pkcs11:` URI.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Pkcs11Uri {
    /// `token`: the token label.
    pub token: Option<String>,
    /// `serial`: the token serial number.
    pub serial: Option<String>,
    /// `manufacturer`: the token manufacturer.
    pub manufacturer: Option<String>,
    /// `model`: the token model.
    pub model: Option<String>,
    /// `slot-id`: the slot number.
    pub slot_id: Option<u64>,
    /// `object`: the key label (CKA_LABEL).
    pub object: Option<String>,
    /// `id`: the key id (CKA_ID), as bytes.
    pub id: Option<Vec<u8>>,
    /// `module-path`: the PKCS#11 module to load.
    pub module_path: String,
    /// `pin-source`.
    pub pin_source: Option<PinSource>,
}

/// Why a URI was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UriError(pub String);

impl fmt::Display for UriError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for UriError {}

fn err(message: impl Into<String>) -> UriError {
    UriError(message.into())
}

/// Percent-decodes one attribute value (RFC 3986 section 2.1).
fn decode(value: &str, name: &str) -> Result<Vec<u8>, UriError> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        if b == b'%' {
            let hex = bytes
                .get(i + 1..i + 3)
                .and_then(|h| std::str::from_utf8(h).ok())
                .and_then(|h| u8::from_str_radix(h, 16).ok())
                .ok_or_else(|| err(format!("`{name}` has a bad percent escape")))?;
            out.push(hex);
            i += 3;
        } else {
            out.push(b);
            i += 1;
        }
    }
    Ok(out)
}

fn text(value: &str, name: &str) -> Result<String, UriError> {
    String::from_utf8(decode(value, name)?)
        .map_err(|_| err(format!("`{name}` is not UTF-8 after percent decoding")))
}

impl Pkcs11Uri {
    /// Parses and checks a `pkcs11:` URI.
    pub fn parse(uri: &str) -> Result<Pkcs11Uri, UriError> {
        let rest = uri
            .strip_prefix("pkcs11:")
            .ok_or_else(|| err("a PKCS#11 key URI starts with `pkcs11:` (RFC 7512)"))?;
        let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
        let mut u = Pkcs11Uri::default();
        let mut module_path = None;
        let mut seen = Vec::new();
        let mut once = |name: &str| -> Result<(), UriError> {
            if seen.iter().any(|s: &String| s == name) {
                return Err(err(format!("`{name}` appears twice")));
            }
            seen.push(name.to_string());
            Ok(())
        };
        for attr in path.split(';').filter(|a| !a.is_empty()) {
            let (name, value) = attr
                .split_once('=')
                .ok_or_else(|| err(format!("path attribute `{attr}` has no `=`")))?;
            once(name)?;
            match name {
                "token" => u.token = Some(text(value, name)?),
                "serial" => u.serial = Some(text(value, name)?),
                "manufacturer" => u.manufacturer = Some(text(value, name)?),
                "model" => u.model = Some(text(value, name)?),
                "object" => u.object = Some(text(value, name)?),
                "id" => u.id = Some(decode(value, name)?),
                "slot-id" => {
                    u.slot_id = Some(
                        text(value, name)?
                            .parse()
                            .map_err(|_| err("`slot-id` is not a number"))?,
                    );
                }
                "type" => {
                    let t = text(value, name)?;
                    if t != "private" {
                        return Err(err(format!(
                            "`type={t}`: the signing key is a private key (`type=private`)"
                        )));
                    }
                }
                // Attributes RFC 7512 defines that do not select a token or key here.
                "library-manufacturer"
                | "library-description"
                | "library-version"
                | "slot-manufacturer"
                | "slot-description" => {}
                _ => return Err(err(format!("unknown path attribute `{name}`"))),
            }
        }
        for attr in query.split('&').filter(|a| !a.is_empty()) {
            let (name, value) = attr
                .split_once('=')
                .ok_or_else(|| err(format!("query attribute `{attr}` has no `=`")))?;
            once(name)?;
            match name {
                "pin-value" => {
                    return Err(err(
                        "`pin-value` is refused: a PIN in the URI shows in process lists and shell \
                         history; use `pin-source=file:<path>` or `pin-source=env:<variable>`",
                    ));
                }
                "module-path" => module_path = Some(text(value, name)?),
                "pin-source" => {
                    let v = text(value, name)?;
                    u.pin_source = Some(if let Some(p) = v.strip_prefix("file:") {
                        PinSource::File(p.to_string())
                    } else if let Some(var) = v.strip_prefix("env:") {
                        PinSource::Env(var.to_string())
                    } else {
                        return Err(err("`pin-source` is `file:<path>` or `env:<variable>`"));
                    });
                }
                "module-name" => {
                    return Err(err(
                        "`module-name` is not supported; name the module with `module-path`",
                    ));
                }
                _ => return Err(err(format!("unknown query attribute `{name}`"))),
            }
        }
        u.module_path = module_path
            .ok_or_else(|| err("`module-path=<path to the token's PKCS#11 module>` is required"))?;
        if u.pin_source.is_none() {
            return Err(err(
                "`pin-source=file:<path>` or `pin-source=env:<variable>` is required",
            ));
        }
        if u.object.is_none() && u.id.is_none() {
            return Err(err(
                "name the key with `object=<label>` or `id=<percent-encoded id>`",
            ));
        }
        Ok(u)
    }

    /// The key's name for the record's `seal.key_label`: the object label, else `id=` and the
    /// id in lowercase hex.
    pub fn label(&self) -> String {
        match (&self.object, &self.id) {
            (Some(o), _) => o.clone(),
            (None, Some(id)) => format!("id={}", crate::hex(id)),
            (None, None) => String::new(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    const Q: &str = "?module-path=/usr/lib/softhsm/libsofthsm2.so&pin-source=file:/etc/sfr/pin";

    #[test]
    fn a_full_uri_parses() {
        let u = Pkcs11Uri::parse(&format!(
            "pkcs11:token=flight%20keys;serial=0123;slot-id=7;object=sfr-seal;id=%01%a0;type=private{Q}"
        ))
        .unwrap();
        assert_eq!(u.token.as_deref(), Some("flight keys"));
        assert_eq!(u.serial.as_deref(), Some("0123"));
        assert_eq!(u.slot_id, Some(7));
        assert_eq!(u.object.as_deref(), Some("sfr-seal"));
        assert_eq!(u.id.as_deref(), Some(&[0x01, 0xa0][..]));
        assert_eq!(u.module_path, "/usr/lib/softhsm/libsofthsm2.so");
        assert_eq!(u.pin_source, Some(PinSource::File("/etc/sfr/pin".into())));
        assert_eq!(u.label(), "sfr-seal");
        let u = Pkcs11Uri::parse("pkcs11:id=%01?module-path=/m.so&pin-source=env:SFR_PIN").unwrap();
        assert_eq!(u.pin_source, Some(PinSource::Env("SFR_PIN".into())));
        assert_eq!(u.label(), "id=01");
    }

    #[test]
    fn unsafe_or_incomplete_uris_are_refused() {
        for (uri, why) in [
            ("token=a;object=b", "starts with `pkcs11:`"),
            (
                "pkcs11:object=b?module-path=/m.so&pin-value=1234",
                "`pin-value` is refused",
            ),
            ("pkcs11:object=b?pin-source=env:P", "`module-path"),
            ("pkcs11:object=b?module-path=/m.so", "`pin-source=file"),
            (
                "pkcs11:object=b?module-path=/m.so&pin-source=stdin",
                "`file:<path>` or `env:<variable>`",
            ),
            (
                "pkcs11:token=a?module-path=/m.so&pin-source=env:P",
                "name the key",
            ),
            (
                "pkcs11:object=b;type=public?module-path=/m.so&pin-source=env:P",
                "`type=private`",
            ),
            (
                "pkcs11:object=b;object=c?module-path=/m.so&pin-source=env:P",
                "appears twice",
            ),
            (
                "pkcs11:object=b;colour=red?module-path=/m.so&pin-source=env:P",
                "unknown path attribute",
            ),
            (
                "pkcs11:id=%zz?module-path=/m.so&pin-source=env:P",
                "bad percent escape",
            ),
        ] {
            let e = Pkcs11Uri::parse(uri).expect_err(uri);
            assert!(e.0.contains(why), "{uri}: {e}");
        }
    }
}
