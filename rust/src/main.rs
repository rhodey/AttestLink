//! Nitro NSM access and attestation verification for attest-link.
//! The embedded AWS trust root can be replaced explicitly with --root-cert.
use std::collections::BTreeMap;
use std::io::{self, Read};

use attest_link_rust::{
    exit_code, invalid_doc, verify, Result, MAX_DOC_BASE64_BYTES, MAX_DOC_BYTES,
};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;

fn main() {
    if let Err(error) = run() {
        eprintln!("attest-link-rust: {error}");
        std::process::exit(exit_code(error.as_ref()));
    }
}

fn run() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let mut options = BTreeMap::new();
    while let Some(name) = args.next() {
        let value = match name.as_str() {
            "-g" | "-v" | "-x" => String::new(),
            "--nonce" | "--public-key" | "--pcr0" | "--root-cert" | "--user-data" => {
                args.next().ok_or("option needs a value")?
            }
            _ => return Err(format!("unknown option: {name}").into()),
        };
        if options.insert(name, value).is_some() {
            return Err("duplicate option".into());
        }
    }
    let command = match (options.remove("-g"), options.remove("-v")) {
        (Some(_), None) => "-g",
        (None, Some(_)) => "-v",
        _ => return Err("expected exactly one of -g or -v".into()),
    };
    let verify_at_document_time = options.remove("-x").is_some();
    if verify_at_document_time && command != "-g" {
        return Err("-x is only valid with -g".into());
    }
    let nonce = hex::decode(options.remove("--nonce").ok_or("--nonce is required")?)?;
    if nonce.len() != 32 {
        return Err("nonce must contain exactly 32 bytes".into());
    }
    let key_text = options
        .remove("--public-key")
        .ok_or("--public-key is required")?;
    if key_text.len() > 1400 {
        return Err("public key exceeds the NSM limit".into());
    }
    let public_key = BASE64.decode(key_text)?;
    if public_key.len() != 32 {
        return Err("X25519 public key must contain exactly 32 bytes".into());
    }
    let pcr0 = match (command, options.remove("--pcr0")) {
        ("-v", Some(value)) => {
            let bytes = hex::decode(value)?;
            if bytes.len() != 48 || bytes.iter().all(|byte| *byte == 0) {
                return Err("--pcr0 must be a nonzero SHA-384 measurement (96 hex digits)".into());
            }
            Some(bytes)
        }
        (_, Some(_)) => return Err("--pcr0 is only valid with -v".into()),
        _ => None,
    };
    let user_data = match (command, options.remove("--user-data")) {
        ("-g", Some(value)) => {
            let json: serde_json::Value = serde_json::from_slice(&BASE64.decode(value)?)?;
            if !json.is_object() {
                return Err("--user-data must contain a JSON object".into());
            }
            Some(rmp_serde::to_vec(&json)?)
        }
        (_, Some(_)) => return Err("--user-data is only valid with -g".into()),
        _ => None,
    };
    if command == "-g" && !verify_at_document_time && options.contains_key("--root-cert") {
        return Err("--root-cert with -g requires -x".into());
    }
    let root_pem = options
        .remove("--root-cert")
        .map(std::fs::read)
        .transpose()?;
    if command == "-g" {
        let document = get(&nonce, &public_key, user_data)?;
        if verify_at_document_time {
            let evidence = verify::verify_at_document_time(
                &document,
                &nonce,
                &public_key,
                root_pem.as_deref(),
            )?;
            println!("{}", serde_json::to_string(&evidence)?);
        } else {
            println!("{}", BASE64.encode(document));
        }
    } else {
        let mut encoded = Vec::new();
        io::stdin()
            .take(MAX_DOC_BASE64_BYTES + 1)
            .read_to_end(&mut encoded)?;
        if encoded.len() as u64 > MAX_DOC_BASE64_BYTES {
            return Err(invalid_doc("encoded attestation document is too large"));
        }
        let encoded = std::str::from_utf8(&encoded).map_err(invalid_doc)?;
        let document = BASE64.decode(encoded.trim()).map_err(invalid_doc)?;
        if document.len() > MAX_DOC_BYTES {
            return Err(invalid_doc("attestation document is too large"));
        }
        let evidence = verify::verify(
            &document,
            &nonce,
            &public_key,
            pcr0.as_deref(),
            root_pem.as_deref(),
        )?;
        println!("{}", serde_json::to_string(&evidence)?);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn get(nonce: &[u8], public_key: &[u8], user_data: Option<Vec<u8>>) -> Result<Vec<u8>> {
    use aws_nitro_enclaves_nsm_api::api::{Request, Response};
    use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};
    use serde_bytes::ByteBuf;
    let fd = nsm_init();
    if fd < 0 {
        return Err(
            "cannot open /dev/nsm; generation must run inside a Nitro Enclave or Sandbox".into(),
        );
    }
    let response = nsm_process_request(
        fd,
        Request::Attestation {
            nonce: Some(ByteBuf::from(nonce.to_vec())),
            public_key: Some(ByteBuf::from(public_key.to_vec())),
            user_data: user_data.map(ByteBuf::from),
        },
    );
    nsm_exit(fd);
    match response {
        Response::Attestation { document } => Ok(document),
        response => Err(format!("NSM attestation request failed: {response:?}").into()),
    }
}

#[cfg(not(target_os = "linux"))]
fn get(_nonce: &[u8], _public_key: &[u8], _user_data: Option<Vec<u8>>) -> Result<Vec<u8>> {
    Err("NSM generation requires Linux inside a Nitro Enclave or Sandbox".into())
}
