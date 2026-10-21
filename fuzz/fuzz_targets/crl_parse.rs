//! Fuzz target: arbitrary bytes through the CRL and certificate readers of `sfr verify`
//! (SPEC B1.3 `--trust-anchor --crl`, `crates/sfr/src/certs.rs`).
//!
//! The `sfr` crate is a binary with no library target, so the target includes `certs.rs` as a
//! module. The bytes go to `parse_crl`, `check_crl_der`, `check_anchor_der`, `certificate_key`
//! and `certificate_fingerprint`, and to `current_crls` as one CRL and as two (split after the
//! first byte), in both orders. The laws checked: a CRL that parses has a non-empty issuer text
//! of printable ASCII, a decimal CRL number without a leading zero, and `thisUpdate` and
//! `nextUpdate` in the form `YYYY-MM-DDTHH:MM:SSZ`; `current_crls` gives the same answer in
//! either order of two CRLs; a CRL that `check_crl_der` accepts parses. The seeds are the DER of
//! the CRLs and several certificates in `testdata/pki/`. Any panic, failed check, hang, or
//! out-of-memory fails the run.
#![no_main]
// Including the whole module brings in functions this target never calls.
#![allow(dead_code)]

use libfuzzer_sys::fuzz_target;

#[path = "../../crates/sfr/src/certs.rs"]
mod certs;

/// `YYYY-MM-DDTHH:MM:SSZ`: digits at these positions, the separators at the rest.
fn is_utc_text(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 20
        && b.iter().enumerate().all(|(i, &c)| match i {
            4 | 7 => c == b'-',
            10 => c == b'T',
            13 | 16 => c == b':',
            19 => c == b'Z',
            _ => c.is_ascii_digit(),
        })
}

fn check_info(info: &certs::CrlInfo) {
    let issuer = info.issuer_text();
    assert!(!issuer.is_empty(), "issuer text is empty");
    assert!(
        issuer.bytes().all(|c| c.is_ascii_graphic() || c == b' '),
        "issuer text is not printable ASCII: {issuer:?}"
    );
    let number = info.number_text();
    assert!(
        !number.is_empty() && number.bytes().all(|c| c.is_ascii_digit()),
        "CRL number is not decimal: {number:?}"
    );
    assert!(
        number == "0" || !number.starts_with('0'),
        "CRL number has a leading zero: {number:?}"
    );
    assert!(
        is_utc_text(&info.this_update_text()),
        "thisUpdate text: {:?}",
        info.this_update_text()
    );
    assert!(
        is_utc_text(&info.next_update_text()),
        "nextUpdate text: {:?}",
        info.next_update_text()
    );
}

fuzz_target!(|data: &[u8]| {
    let parsed = certs::parse_crl(data);
    if let Ok(info) = &parsed {
        check_info(info);
    }
    // A CRL that the full check accepts is one `parse_crl` reads.
    if certs::check_crl_der(data).is_ok() {
        assert!(
            parsed.is_ok(),
            "check_crl_der accepts what parse_crl refuses"
        );
    }

    let _ = certs::check_anchor_der(data);
    let _ = certs::certificate_key(data);
    let fingerprint = certs::certificate_fingerprint(data);
    assert!(
        fingerprint.starts_with("sha256:") && fingerprint.len() == 7 + 64,
        "fingerprint form"
    );

    // One CRL: it is current exactly when it parses.
    let one = certs::current_crls(&[data.to_vec()]);
    assert_eq!(
        one.is_ok(),
        parsed.is_ok(),
        "one CRL: current_crls vs parse_crl"
    );
    if let Ok(list) = &one {
        assert_eq!(list.len(), 1, "one CRL gives one current CRL");
        list.iter().for_each(check_info);
    }

    // Two CRLs, split after the first byte, in both orders.
    if let Some((first, rest)) = data.split_at_checked(1) {
        let a = first.to_vec();
        let b = rest.to_vec();
        let ab = certs::current_crls(&[a.clone(), b.clone()]);
        let ba = certs::current_crls(&[b, a]);
        // The verdict and the current CRLs do not depend on the order. The text of an error
        // names the first CRL that fails, so it may differ and is not compared.
        match (&ab, &ba) {
            (Ok(x), Ok(y)) => assert_eq!(x, y, "current_crls depends on the order of two CRLs"),
            (Err(_), Err(_)) => {}
            _ => panic!("current_crls verdict depends on the order of two CRLs"),
        }
        if let Ok(list) = &ab {
            list.iter().for_each(check_info);
        }
    }
});
