//! JSON boundary for the browser. Cryptography, claim checks, MessagePack and
//! the clock all remain in verify.rs, shared with the native CLI.
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::Deserialize;

use crate::{exit_code, invalid_doc, verify, Result, MAX_ENCODED_DOCUMENT};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerifyRequest {
    document: String,
    nonce: String,
    public_key: String,
    pcr0: Option<String>,
    root_pem: Option<String>,
}

fn verify_request(input: &str) -> Result<verify::Evidence> {
    if input.len() > 32 * 1024 {
        return Err(invalid_doc("verification input is too large"));
    }
    let request: VerifyRequest = serde_json::from_str(input)?;
    let nonce = hex::decode(request.nonce)?;
    if nonce.len() != 32 {
        return Err("nonce must contain exactly 32 bytes".into());
    }
    let public_key = BASE64.decode(request.public_key)?;
    if public_key.len() != 32 {
        return Err("X25519 public key must contain exactly 32 bytes".into());
    }
    let pcr0 = request.pcr0.map(hex::decode).transpose()?;
    if let Some(pcr0) = &pcr0 {
        if pcr0.len() != 48 || pcr0.iter().all(|byte| *byte == 0) {
            return Err("PCR0 must be a nonzero SHA-384 measurement (96 hex digits)".into());
        }
    }
    if request.document.len() as u64 > MAX_ENCODED_DOCUMENT {
        return Err(invalid_doc("encoded attestation document is too large"));
    }
    let document = BASE64
        .decode(request.document.trim())
        .map_err(invalid_doc)?;
    verify::verify(
        &document,
        &nonce,
        &public_key,
        pcr0.as_deref(),
        request.root_pem.as_deref().map(str::as_bytes),
    )
}

pub fn verify_json(input: &str) -> String {
    match verify_request(input).and_then(|evidence| Ok(serde_json::to_string(&evidence)?)) {
        Ok(json) => json,
        Err(error) if exit_code(error.as_ref()) == 2 => "false".into(),
        Err(error) => serde_json::json!({ "error": error.to_string() }).to_string(),
    }
}
