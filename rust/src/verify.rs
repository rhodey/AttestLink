//! Strict Nitro COSE_Sign1 verification. The document's CA bundle supplies
//! untrusted intermediates only; the caller selects the trust anchor.
use std::collections::BTreeMap;
use std::io::Cursor;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ciborium::value::Value;
use openssl::bn::BigNum;
use openssl::ecdsa::EcdsaSig;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::sign::Verifier;
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::verify::X509VerifyParam;
use openssl::x509::{X509StoreContext, X509};
use serde::Serialize;

use crate::{invalid_doc, Result};

const ROOT_PEM: &[u8] = include_bytes!("../root.pem");

enum CertificateTime {
    At(u64), // Milliseconds since the Unix epoch.
    DocumentTimestamp,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    pub pcrs: BTreeMap<u64, String>,
    pub nonce: String,
    pub public_key: String,
    pub user_data: serde_json::Value,
    pub timestamp: u64,
}

pub fn verify(
    document: &[u8],
    nonce: &[u8],
    public_key: &[u8],
    pcr0: Option<&[u8]>,
    root_pem: Option<&[u8]>,
) -> Result<Evidence> {
    let root = X509::from_pem(root_pem.unwrap_or(ROOT_PEM))?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;
    verify_with_root(
        document,
        nonce,
        public_key,
        pcr0,
        &root,
        CertificateTime::At(now),
    )
}

// Checks certificate validity at the document's signed timestamp.
// Used to check fresh local NSM responses before the clock is initialized.
pub fn verify_at_document_time(
    document: &[u8],
    nonce: &[u8],
    public_key: &[u8],
    root_pem: Option<&[u8]>,
) -> Result<Evidence> {
    let root = X509::from_pem(root_pem.unwrap_or(ROOT_PEM))?;
    verify_with_root(
        document,
        nonce,
        public_key,
        None,
        &root,
        CertificateTime::DocumentTimestamp,
    )
}

fn decode(bytes: &[u8]) -> Result<Value> {
    let mut input = Cursor::new(bytes);
    let value =
        ciborium::de::from_reader_with_recursion_limit(&mut input, 32).map_err(invalid_doc)?;
    if input.position() != bytes.len() as u64 {
        return Err(invalid_doc("trailing bytes after CBOR value"));
    }
    Ok(value)
}

fn bytes(value: &Value) -> Result<&[u8]> {
    match value {
        Value::Bytes(bytes) => Ok(bytes),
        _ => Err(invalid_doc("expected CBOR byte string")),
    }
}

fn uint(value: &Value) -> Result<u64> {
    match value {
        Value::Integer(value) => u64::try_from(*value).map_err(invalid_doc),
        _ => Err(invalid_doc("expected unsigned CBOR integer")),
    }
}

fn text(value: &Value) -> Result<&str> {
    match value {
        Value::Text(text) => Ok(text),
        _ => Err(invalid_doc("expected CBOR text string")),
    }
}

fn field<'a>(map: &'a BTreeMap<&str, &Value>, name: &str) -> Result<&'a Value> {
    map.get(name)
        .copied()
        .ok_or_else(|| invalid_doc(format!("missing attestation field: {name}")))
}

fn verify_with_root(
    document: &[u8],
    nonce: &[u8],
    public_key: &[u8],
    approved_pcr0: Option<&[u8]>,
    root: &X509,
    verification_time: CertificateTime,
) -> Result<Evidence> {
    if nonce.len() != 32 || public_key.len() != 32 {
        return Err("expected a 32-byte nonce and X25519 public key".into());
    }
    if document.is_empty() || document.len() > crate::MAX_DOC_BYTES {
        return Err(invalid_doc("invalid attestation document length"));
    }
    let outer = match decode(document)? {
        Value::Tag(18, value) => *value,
        value => value,
    };
    let parts = match outer {
        Value::Array(parts) if parts.len() == 4 => parts,
        _ => return Err(invalid_doc("expected COSE_Sign1 structure")),
    };
    let protected = bytes(&parts[0])?;
    let headers = decode(protected)?;
    match headers {
        Value::Map(headers)
            if headers.len() == 1
                && headers[0].0 == Value::Integer(1.into())
                && headers[0].1 == Value::Integer((-35).into()) => {}
        _ => return Err(invalid_doc("protected COSE header must specify ES384 only")),
    }
    if !matches!(&parts[1], Value::Map(headers) if headers.is_empty()) {
        return Err(invalid_doc("unexpected unprotected COSE headers"));
    }
    let payload = bytes(&parts[2])?;
    let raw_signature = bytes(&parts[3])?;
    if raw_signature.len() != 96 {
        return Err(invalid_doc("ES384 signature must be 96 bytes"));
    }
    let payload_value = decode(payload)?;
    let entries = match &payload_value {
        Value::Map(entries) => entries,
        _ => return Err(invalid_doc("attestation payload must be a CBOR map")),
    };
    let mut fields = BTreeMap::new();
    for (key, value) in entries {
        if fields.insert(text(key)?, value).is_some() {
            return Err(invalid_doc("duplicate attestation field"));
        }
    }
    let certificate_bytes = bytes(field(&fields, "certificate")?)?;
    if certificate_bytes.is_empty() || certificate_bytes.len() > 1024 {
        return Err(invalid_doc("invalid signing certificate length"));
    }
    let leaf = X509::from_der(certificate_bytes).map_err(invalid_doc)?;
    // Check the document signature. The chain below must still establish trust
    // in this signing certificate before any evidence can be returned.
    let signing_key = leaf.public_key().map_err(invalid_doc)?;
    let curve = signing_key
        .ec_key()
        .map_err(invalid_doc)?
        .group()
        .curve_name();
    if curve != Some(Nid::SECP384R1) {
        return Err(invalid_doc("attestation signing key must use P-384"));
    }
    let signature = EcdsaSig::from_private_components(
        BigNum::from_slice(&raw_signature[..48])?,
        BigNum::from_slice(&raw_signature[48..])?,
    )?
    .to_der()?;
    let signed = Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(protected.to_vec()),
        Value::Bytes(vec![]),
        Value::Bytes(payload.to_vec()),
    ]);
    let mut signed_bytes = Vec::new();
    ciborium::ser::into_writer(&signed, &mut signed_bytes)?;
    let mut verifier = Verifier::new(MessageDigest::sha384(), &signing_key)?;
    verifier.update(&signed_bytes)?;
    if !verifier.verify(&signature)? {
        return Err(invalid_doc("invalid attestation signature"));
    }

    let certs = match field(&fields, "cabundle")? {
        Value::Array(certs) if !certs.is_empty() && certs.len() <= 16 => certs,
        _ => return Err(invalid_doc("invalid CA bundle")),
    };
    let mut intermediates = Stack::new()?;
    for certificate in certs {
        let der = bytes(certificate)?;
        if der.is_empty() || der.len() > 1024 {
            return Err(invalid_doc("invalid CA certificate length"));
        }
        intermediates.push(X509::from_der(der).map_err(invalid_doc)?)?;
    }
    let mut store = X509StoreBuilder::new()?;
    store.add_cert(root.clone())?;
    let mut parameters = X509VerifyParam::new()?;
    let certificate_time_ms = match verification_time {
        CertificateTime::At(time) => time,
        CertificateTime::DocumentTimestamp => uint(field(&fields, "timestamp")?)?,
    };
    parameters.set_time((certificate_time_ms / 1000).try_into()?);
    parameters.set_depth(16);
    // Use normal OpenSSL chain validation. Live AWS Nitro certificates can omit
    // Authority Key Identifier, which X509_STRICT additionally requires. Trust
    // anchors, signatures, validity periods and CA constraints still apply;
    // no verification callback or partial-chain trust is enabled.
    store.set_param(&parameters)?;
    let store = store.build();
    let mut context = X509StoreContext::new()?;
    let valid = context.init(&store, &leaf, &intermediates, |ctx| ctx.verify_cert())?;
    if !valid {
        return Err(invalid_doc(format!(
            "certificate chain validation failed: {}",
            context.error()
        )));
    }
    // Validate the remaining claims after chain and signature verification.
    let digest = text(field(&fields, "digest")?)?;
    if digest != "SHA384" {
        return Err(invalid_doc("unsupported PCR digest"));
    }
    let pcr_entries = match field(&fields, "pcrs")? {
        Value::Map(entries) if !entries.is_empty() && entries.len() <= 32 => entries,
        _ => return Err(invalid_doc("invalid PCR map")),
    };
    let mut pcrs = BTreeMap::new();
    for (index, value) in pcr_entries {
        let index = uint(index)?;
        let measurement = bytes(value)?;
        if measurement.len() != 48 {
            return Err(invalid_doc("invalid SHA-384 PCR entry"));
        }
        if pcrs.insert(index, hex::encode(measurement)).is_some() {
            return Err(invalid_doc("duplicate PCR index"));
        }
    }
    let pcr0 = pcrs.get(&0).ok_or_else(|| invalid_doc("missing PCR0"))?;
    if pcr0.bytes().all(|byte| byte == b'0') {
        return Err(invalid_doc("debug/zero-PCR0 documents are not accepted"));
    }
    if let Some(expected) = approved_pcr0 {
        if pcr0 != &hex::encode(expected) {
            return Err(invalid_doc("PCR0 does not match the approved image"));
        }
    }

    if bytes(field(&fields, "nonce")?)? != nonce {
        return Err(invalid_doc("attestation nonce mismatch"));
    }

    if bytes(field(&fields, "public_key")?)? != public_key {
        return Err(invalid_doc(
            "attested key does not match the server's X25519 key",
        ));
    }

    let user_data = match fields.get("user_data").copied() {
        Some(Value::Null) | None => serde_json::json!(0),
        Some(Value::Bytes(data)) => {
            let mut input = Cursor::new(data);
            match rmp_serde::from_read(&mut input) {
                Ok(value) if input.position() == data.len() as u64 => value,
                _ => serde_json::json!(1),
            }
        }
        _ => serde_json::json!(1),
    };

    let timestamp = uint(field(&fields, "timestamp")?)?;
    Ok(Evidence {
        pcrs,
        nonce: hex::encode(nonce),
        public_key: BASE64.encode(public_key),
        user_data,
        timestamp,
    })
}

#[cfg(test)]
#[path = "../tests/verify.rs"]
mod tests;
