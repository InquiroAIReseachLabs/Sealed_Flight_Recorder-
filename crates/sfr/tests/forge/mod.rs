//! Test-only: a record edited and signed again, as its key holder could.
//!
//! The holder of a signing key can change any field of a record, recompute the Merkle root and
//! sign it, and the result is a record `verify` accepts as signed by that key. The attacks that
//! rest on this (a relabelled custody, a changed time) are tests of what `verify` makes of
//! such a record, so the tests need to make one. Everything here is a public call of `sfr-core`.
#![allow(dead_code)]

use sfr_core::crypto::Signer;
use sfr_core::crypto::rustcrypto::{FileKey, RustCrypto};
use sfr_core::json::{Obj, Value, canonical, parse};
use sfr_core::seal::{TreeShape, merkle_root, signed_payload};
use std::collections::BTreeMap;

pub type Record = BTreeMap<String, Value>;

/// The key with this 32-byte seed.
pub fn key_from_seed(seed: &[u8; 32]) -> FileKey {
    FileKey::from_seed(seed, "forged")
}

/// The key in an `sfr.key` file (PEM, PKCS#8).
pub fn key_from_file(path: &std::path::Path) -> FileKey {
    let text = std::fs::read_to_string(path).unwrap();
    let der = sfr_core::keys::pem_decode(&text, "PRIVATE KEY").unwrap();
    FileKey::from_pkcs8_der(&der, "forged").unwrap()
}

/// Applies `edit` to the record's `seal` object.
pub fn edit_seal(r: &mut Record, edit: impl FnOnce(&mut BTreeMap<String, Value>)) {
    let Some(Value::Object(seal)) = r.get_mut("seal") else {
        panic!("the record has no seal object");
    };
    edit(seal);
}

/// `record` with `edit` applied, its Merkle root recomputed, and signed by `key`, which must be
/// the key whose fingerprint the record names (or the edit must change the fingerprint too).
pub fn resign(record: &[u8], key: &FileKey, edit: impl FnOnce(&mut Record)) -> Vec<u8> {
    let Value::Object(mut r) = parse(record).unwrap() else {
        panic!("a record is an object");
    };
    edit(&mut r);
    let (root, shape) = merkle_root(&RustCrypto, &r).unwrap();
    let schema = match r.get("schema_version") {
        Some(Value::Int(v)) => u32::try_from(*v).unwrap(),
        other => panic!("schema_version: {other:?}"),
    };
    let signature = key.sign(&signed_payload(schema, &shape, &root)).unwrap();
    r.insert(
        "merkle".into(),
        Obj::new()
            .field("algorithm", Value::str(sfr_core::merkle::ALGORITHM))
            .field("leaf_count", Value::count(shape.leaf_count()))
            .field("root", Value::str(sfr_core::hex(&root)))
            .field("sections", shape.to_json())
            .build(),
    );
    r.insert(
        "signature".into(),
        Obj::new()
            .field("algorithm", Value::str("ed25519"))
            .field("value", Value::str(sfr_core::hex(&signature)))
            .build(),
    );
    canonical(&Value::Object(r)).into_bytes()
}

/// Like [`resign`], but the signature covers `payload_shape` instead of the shape of the record
/// (the record itself says the true shape): a signature over a tree of another shape.
pub fn resign_over_shape(record: &[u8], key: &FileKey, payload_shape: TreeShape) -> Vec<u8> {
    let Value::Object(mut r) = parse(record).unwrap() else {
        panic!("a record is an object");
    };
    let (root, shape) = merkle_root(&RustCrypto, &r).unwrap();
    let signature = key.sign(&signed_payload(3, &payload_shape, &root)).unwrap();
    r.insert(
        "merkle".into(),
        Obj::new()
            .field("algorithm", Value::str(sfr_core::merkle::ALGORITHM))
            .field("leaf_count", Value::count(shape.leaf_count()))
            .field("root", Value::str(sfr_core::hex(&root)))
            .field("sections", shape.to_json())
            .build(),
    );
    r.insert(
        "signature".into(),
        Obj::new()
            .field("algorithm", Value::str("ed25519"))
            .field("value", Value::str(sfr_core::hex(&signature)))
            .build(),
    );
    canonical(&Value::Object(r)).into_bytes()
}

/// The relabel attack: `record` says its key is held in a PKCS#11 token (`key_custody`
/// `pkcs11-token`, and a token-looking label), signed again by `key`, which is whatever key
/// file the attacker has.
pub fn relabelled_as_pkcs11(record: &[u8], key: &FileKey) -> Vec<u8> {
    resign(record, key, |r| {
        edit_seal(r, |seal| {
            seal.insert("key_custody".into(), Value::str("pkcs11-token"));
            seal.insert(
                "key_label".into(),
                Value::str("pkcs11:token=prod;object=sfr-seal"),
            );
        });
    })
}
