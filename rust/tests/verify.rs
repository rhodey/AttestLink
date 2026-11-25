use super::*;
use openssl::asn1::Asn1Time;
use openssl::ec::{EcGroup, EcKey};
use openssl::pkey::{PKey, Private};
use openssl::sign::Signer;
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectKeyIdentifier,
};
use openssl::x509::X509NameBuilder;

const NOW: u64 = 1_800_000_000_000;
const NONCE: [u8; 32] = [7; 32];
const PUBLIC_KEY: [u8; 32] = [8; 32];
const PCR0: [u8; 48] = [9; 48];

struct Fixture {
    root: X509,
    leaf: X509,
    key: PKey<Private>,
}

fn key() -> PKey<Private> {
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
}

fn certificate(
    key: &PKey<Private>,
    issuer: Option<(&X509, &PKey<Private>)>,
    include_aki: bool,
    now: u64,
) -> X509 {
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text(
        "CN",
        if issuer.is_none() {
            "Test Root"
        } else {
            "Test Leaf"
        },
    )
    .unwrap();
    let name = name.build();
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder
        .set_serial_number(
            &BigNum::from_u32(if issuer.is_none() { 1 } else { 2 })
                .unwrap()
                .to_asn1_integer()
                .unwrap(),
        )
        .unwrap();
    builder.set_subject_name(&name).unwrap();
    builder
        .set_issuer_name(issuer.map(|(cert, _)| cert.subject_name()).unwrap_or(&name))
        .unwrap();
    builder.set_pubkey(key).unwrap();
    builder
        .set_not_before(&Asn1Time::from_unix((now / 1000 - 86400) as i64).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::from_unix((now / 1000 + 86400) as i64).unwrap())
        .unwrap();
    let constraints = if issuer.is_none() {
        BasicConstraints::new().critical().ca().build().unwrap()
    } else {
        BasicConstraints::new().critical().build().unwrap()
    };
    builder.append_extension(constraints).unwrap();
    let usage = if issuer.is_none() {
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()
            .unwrap()
    } else {
        KeyUsage::new()
            .critical()
            .digital_signature()
            .build()
            .unwrap()
    };
    builder.append_extension(usage).unwrap();
    let ski = SubjectKeyIdentifier::new()
        .build(&builder.x509v3_context(issuer.map(|(cert, _)| cert.as_ref()), None))
        .unwrap();
    builder.append_extension(ski).unwrap();
    if include_aki {
        if let Some((cert, _)) = issuer {
            let aki = AuthorityKeyIdentifier::new()
                .keyid(true)
                .build(&builder.x509v3_context(Some(cert), None))
                .unwrap();
            builder.append_extension(aki).unwrap();
        }
    }
    builder
        .sign(
            issuer.map(|(_, key)| key).unwrap_or(key),
            MessageDigest::sha384(),
        )
        .unwrap();
    builder.build()
}

impl Fixture {
    fn new() -> Self {
        Self::with_aki(true)
    }

    fn with_aki(include_aki: bool) -> Self {
        Self::at_time(include_aki, NOW)
    }

    fn at_time(include_aki: bool, now: u64) -> Self {
        let root_key = key();
        let root = certificate(&root_key, None, false, now);
        let key = key();
        let leaf = certificate(&key, Some((&root, &root_key)), include_aki, now);
        Self { root, leaf, key }
    }

    fn claims(&self) -> Vec<(Value, Value)> {
        let entries = [
            ("module_id", Value::Text("test-module".into())),
            ("timestamp", Value::Integer(NOW.into())),
            ("digest", Value::Text("SHA384".into())),
            (
                "pcrs",
                Value::Map(vec![(
                    Value::Integer(0.into()),
                    Value::Bytes(PCR0.to_vec()),
                )]),
            ),
            ("certificate", Value::Bytes(self.leaf.to_der().unwrap())),
            (
                "cabundle",
                Value::Array(vec![Value::Bytes(self.root.to_der().unwrap())]),
            ),
            ("nonce", Value::Bytes(NONCE.to_vec())),
            ("public_key", Value::Bytes(PUBLIC_KEY.to_vec())),
        ];
        entries
            .into_iter()
            .map(|(name, value)| (Value::Text(name.into()), value))
            .collect()
    }

    fn sign(&self, claims: Vec<(Value, Value)>) -> Vec<u8> {
        let protected = encode(&Value::Map(vec![(
            Value::Integer(1.into()),
            Value::Integer((-35).into()),
        )]));
        let payload = encode(&Value::Map(claims));
        let to_sign = encode(&Value::Array(vec![
            Value::Text("Signature1".into()),
            Value::Bytes(protected.clone()),
            Value::Bytes(vec![]),
            Value::Bytes(payload.clone()),
        ]));
        let mut signer = Signer::new(MessageDigest::sha384(), &self.key).unwrap();
        signer.update(&to_sign).unwrap();
        let signature = EcdsaSig::from_der(&signer.sign_to_vec().unwrap()).unwrap();
        let mut raw = signature.r().to_vec_padded(48).unwrap();
        raw.extend(signature.s().to_vec_padded(48).unwrap());
        encode(&Value::Array(vec![
            Value::Bytes(protected),
            Value::Map(vec![]),
            Value::Bytes(payload),
            Value::Bytes(raw),
        ]))
    }

    fn verify(&self, document: &[u8]) -> Result<Evidence> {
        verify_with_root(
            document,
            &NONCE,
            &PUBLIC_KEY,
            Some(&PCR0),
            &self.root,
            CertificateTime::At(NOW),
        )
    }
}

fn encode(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(value, &mut bytes).unwrap();
    bytes
}

fn replace(claims: &mut [(Value, Value)], name: &str, value: Value) {
    claims
        .iter_mut()
        .find(|(key, _)| key == &Value::Text(name.into()))
        .unwrap()
        .1 = value;
}

fn assert_invalid(result: Result<Evidence>) {
    let error = result.unwrap_err();
    assert_eq!(crate::exit_code(error.as_ref()), 2, "{error}");
}

#[test]
fn wasm_json_returns_the_same_evidence_as_native_verification() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let fixture = Fixture::at_time(false, now);
    let root = String::from_utf8(fixture.root.to_pem().unwrap()).unwrap();
    for user_data in [
        None,
        Some(Value::Bytes(
            rmp_serde::to_vec(&serde_json::json!({ "fortune": "Hello browser" })).unwrap(),
        )),
        Some(Value::Bytes(vec![0xc1])),
    ] {
        let mut claims = fixture.claims();
        if let Some(value) = user_data {
            claims.push((Value::Text("user_data".into()), value));
        }
        let document = fixture.sign(claims);
        let evidence = verify(
            &document,
            &NONCE,
            &PUBLIC_KEY,
            Some(&PCR0),
            Some(root.as_bytes()),
        )
        .unwrap();
        let input = serde_json::json!({
            "document": BASE64.encode(document),
            "nonce": hex::encode(NONCE),
            "publicKey": BASE64.encode(PUBLIC_KEY),
            "pcr0": hex::encode(PCR0),
            "rootPem": root,
        });
        let output = crate::wasm::verify_json(&input.to_string());
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&output).unwrap(),
            serde_json::to_value(evidence).unwrap()
        );
    }
}

#[test]
fn wasm_json_distinguishes_invalid_evidence_from_configuration_errors() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let fixture = Fixture::at_time(false, now);
    let document = fixture.sign(fixture.claims());
    let root = String::from_utf8(fixture.root.to_pem().unwrap()).unwrap();
    let input = serde_json::json!({
        "document": BASE64.encode(&document),
        "nonce": hex::encode(NONCE),
        "publicKey": BASE64.encode(PUBLIC_KEY),
        "rootPem": root,
    });
    for (field, value) in [
        ("document", serde_json::json!("not base64!")),
        ("document", serde_json::json!(BASE64.encode(b"not CBOR"))),
        ("document", serde_json::json!("A".repeat(40 * 1024))),
        ("nonce", serde_json::json!(hex::encode([6; 32]))),
        ("publicKey", serde_json::json!(BASE64.encode([6; 32]))),
        ("pcr0", serde_json::json!(hex::encode([6; 48]))),
        ("rootPem", serde_json::Value::Null),
    ] {
        let mut invalid = input.clone();
        invalid[field] = value;
        assert_eq!(
            crate::wasm::verify_json(&invalid.to_string()),
            "false",
            "{field}"
        );
    }
    for (field, value) in [
        ("nonce", serde_json::json!("bad nonce")),
        ("publicKey", serde_json::json!("bad key")),
        ("pcr0", serde_json::json!(hex::encode([0; 48]))),
        ("rootPem", serde_json::json!("not a PEM")),
    ] {
        let mut invalid = input.clone();
        invalid[field] = value;
        let output: serde_json::Value =
            serde_json::from_str(&crate::wasm::verify_json(&invalid.to_string())).unwrap();
        assert!(output["error"].is_string(), "{field}: {output}");
    }
}

// Regenerate the browser fixtures explicitly; no fixture-generation tool or
// private key is needed when running the JavaScript tests.
// ATTEST_LINK_FIXTURES="$PWD/package/test/browser/fixtures/wasm.json" cargo test \
//   --manifest-path rust/Cargo.toml export_wasm_fixtures -- --ignored
#[test]
#[ignore = "writes signed browser fixtures to ATTEST_LINK_FIXTURES"]
fn export_wasm_fixtures() {
    let fixture = Fixture::new();
    let mut documents = Vec::new();
    for (name, user_data) in [
        ("absent", None),
        (
            "object",
            Some(Value::Bytes(
                rmp_serde::to_vec(
                    &serde_json::json!({ "fortune": "Hello browser", "nested": [true, null, 42] }),
                )
                .unwrap(),
            )),
        ),
        ("invalid MessagePack", Some(Value::Bytes(vec![0xc1]))),
    ] {
        let mut claims = fixture.claims();
        if let Some(value) = user_data {
            claims.push((Value::Text("user_data".into()), value));
        }
        let document = fixture.sign(claims);
        documents.push(serde_json::json!({
            "name": name,
            "document": BASE64.encode(&document),
            "evidence": fixture.verify(&document).unwrap(),
        }));
    }
    let tagged = encode(&Value::Tag(
        18,
        Box::new(decode(&fixture.sign(fixture.claims())).unwrap()),
    ));
    documents.push(serde_json::json!({
        "name": "tagged COSE_Sign1", "document": BASE64.encode(&tagged),
        "evidence": fixture.verify(&tagged).unwrap(),
    }));
    let mut claims = fixture.claims();
    replace(
        &mut claims,
        "pcrs",
        Value::Map(vec![(Value::Integer(0.into()), Value::Bytes(vec![0; 48]))]),
    );
    let output = serde_json::json!({
        "time": NOW, "nonce": hex::encode(NONCE), "publicKey": BASE64.encode(PUBLIC_KEY),
        "pcr0": hex::encode(PCR0),
        "rootPem": String::from_utf8(fixture.root.to_pem().unwrap()).unwrap(),
        "otherRootPem": String::from_utf8(Fixture::new().root.to_pem().unwrap()).unwrap(),
        "documents": documents, "debugDocument": BASE64.encode(fixture.sign(claims)),
    });
    let path = std::env::var("ATTEST_LINK_FIXTURES").expect("ATTEST_LINK_FIXTURES is required");
    std::fs::write(path, serde_json::to_string_pretty(&output).unwrap() + "\n").unwrap();
}

#[test]
#[ignore = "exports a current-time signed fixture for installed-package qualification"]
fn export_release_fixture() {
    let path = std::env::var("ATTEST_LINK_FIXTURE").expect("ATTEST_LINK_FIXTURE is required");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let fixture = Fixture::at_time(true, now);
    let mut claims = fixture.claims();
    replace(&mut claims, "timestamp", Value::Integer(now.into()));
    let document = fixture.sign(claims);
    let root = fixture.root.to_pem().unwrap();
    let evidence = verify(&document, &NONCE, &PUBLIC_KEY, Some(&PCR0), Some(&root)).unwrap();
    let output = serde_json::json!({
        "document": BASE64.encode(document), "evidence": evidence,
        "nonce": hex::encode(NONCE), "publicKey": BASE64.encode(PUBLIC_KEY),
        "pcr0": hex::encode(PCR0), "rootPem": String::from_utf8(root).unwrap(),
    });
    std::fs::write(path, serde_json::to_string_pretty(&output).unwrap() + "\n").unwrap();
}

#[test]
fn verifies_signed_evidence_with_optional_measurement_approval() {
    let fixture = Fixture::new();
    let doc = fixture.sign(fixture.claims());
    let evidence = fixture.verify(&doc).unwrap();
    assert_eq!(evidence.pcrs[&0], hex::encode(PCR0));
    assert_eq!(evidence.user_data, serde_json::json!(0));
    let mut claims = fixture.claims();
    replace(
        &mut claims,
        "pcrs",
        Value::Map(vec![(Value::Integer(0.into()), Value::Bytes(vec![2; 48]))]),
    );
    let other_image = fixture.sign(claims);
    let evidence = verify_with_root(
        &other_image,
        &NONCE,
        &PUBLIC_KEY,
        None,
        &fixture.root,
        CertificateTime::At(NOW),
    )
    .unwrap();
    assert_eq!(evidence.pcrs[&0], hex::encode([2; 48]));
    assert_eq!(evidence.user_data, serde_json::json!(0));
    assert_invalid(fixture.verify(&other_image));
    // The default AWS root still rejects evidence signed by the test CA.
    assert_invalid(verify(&doc, &NONCE, &PUBLIC_KEY, Some(&PCR0), None));
}

#[test]
fn returns_authenticated_user_data_and_rejects_tampering() {
    let fixture = Fixture::new();
    // MessagePack for { "role": "ssh" }.
    let user_data = hex::decode("81a4726f6c65a3737368").unwrap();
    let mut claims = fixture.claims();
    claims.push((
        Value::Text("user_data".into()),
        Value::Bytes(user_data.clone()),
    ));
    let doc = fixture.sign(claims);
    assert_eq!(
        fixture.verify(&doc).unwrap().user_data,
        serde_json::json!({ "role": "ssh" })
    );

    let Value::Array(mut parts) = decode(&doc).unwrap() else {
        panic!()
    };
    let Value::Map(mut claims) = decode(bytes(&parts[2]).unwrap()).unwrap() else {
        panic!()
    };
    replace(&mut claims, "user_data", Value::Bytes(vec![0x80]));
    parts[2] = Value::Bytes(encode(&Value::Map(claims)));
    assert_invalid(fixture.verify(&encode(&Value::Array(parts))));
}

#[test]
fn user_data_decoding_does_not_determine_document_validity() {
    let fixture = Fixture::new();
    let object = serde_json::json!({
        "role": "ssh", "enabled": true, "version": 2,
        "labels": ["a", null], "nested": { "name": "日本語" }
    });
    let mut cases = vec![
        (Value::Null, serde_json::json!(0)),
        (Value::Bytes(rmp_serde::to_vec(&object).unwrap()), object),
        (Value::Bytes(vec![0x80]), serde_json::json!({})),
        (Value::Bytes(vec![0x90]), serde_json::json!([])),
        (Value::Bytes(vec![0xc0]), serde_json::Value::Null),
        (Value::Text("not bytes".into()), serde_json::json!(1)),
    ];
    // Empty, reserved marker, truncated string, trailing value, truncated array.
    for hex in ["", "c1", "a2ff", "8080", "ddffffffff"] {
        cases.push((
            Value::Bytes(hex::decode(hex).unwrap()),
            serde_json::json!(1),
        ));
    }
    for (data, expected) in cases {
        let mut claims = fixture.claims();
        claims.push((Value::Text("user_data".into()), data));
        let doc = fixture.sign(claims);
        for pcr0 in [Some(PCR0.as_slice()), None] {
            let evidence = verify_with_root(
                &doc,
                &NONCE,
                &PUBLIC_KEY,
                pcr0,
                &fixture.root,
                CertificateTime::At(NOW),
            )
            .unwrap();
            assert_eq!(evidence.user_data, expected);
        }
    }
}

#[test]
fn document_time_checks_certificate_lifetimes_without_the_system_clock() {
    let fixture = Fixture::new();
    let doc = fixture.sign(fixture.claims());
    let root_pem = fixture.root.to_pem().unwrap();
    let evidence = verify_at_document_time(&doc, &NONCE, &PUBLIC_KEY, Some(&root_pem)).unwrap();
    assert_eq!(evidence.timestamp, NOW);
    // Normal verification rejects both an epoch clock and an expired chain,
    // even though the document timestamp is inside the certificate's lifetime.
    for now in [0, NOW + 2 * 86400 * 1000] {
        assert_invalid(verify_with_root(
            &doc,
            &NONCE,
            &PUBLIC_KEY,
            None,
            &fixture.root,
            CertificateTime::At(now),
        ));
    }
    assert_invalid(verify_at_document_time(&doc, &NONCE, &PUBLIC_KEY, None));
    assert_invalid(verify_at_document_time(
        &doc,
        &[0; 32],
        &PUBLIC_KEY,
        Some(&root_pem),
    ));
    assert_invalid(verify_at_document_time(
        &doc,
        &NONCE,
        &[0; 32],
        Some(&root_pem),
    ));
    let mut corrupted = doc;
    *corrupted.last_mut().unwrap() ^= 1;
    assert_invalid(verify_at_document_time(
        &corrupted,
        &NONCE,
        &PUBLIC_KEY,
        Some(&root_pem),
    ));

    for timestamp in [NOW - 2 * 86400 * 1000, NOW + 2 * 86400 * 1000] {
        let mut claims = fixture.claims();
        replace(&mut claims, "timestamp", Value::Integer(timestamp.into()));
        assert_invalid(verify_at_document_time(
            &fixture.sign(claims),
            &NONCE,
            &PUBLIC_KEY,
            Some(&root_pem),
        ));
    }
}

#[test]
fn custom_root_requires_an_explicit_override() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let fixture = Fixture::at_time(true, now);
    let mut claims = fixture.claims();
    replace(&mut claims, "timestamp", Value::Integer(now.into()));
    let doc = fixture.sign(claims);
    let root_pem = fixture.root.to_pem().unwrap();
    let evidence = verify(&doc, &NONCE, &PUBLIC_KEY, Some(&PCR0), Some(&root_pem)).unwrap();
    assert_eq!(evidence.pcrs[&0], hex::encode(PCR0));
    verify(&doc, &NONCE, &PUBLIC_KEY, None, Some(&root_pem)).unwrap();
    assert_invalid(verify(&doc, &NONCE, &PUBLIC_KEY, Some(&PCR0), None));
    let other_root = Fixture::at_time(true, now).root.to_pem().unwrap();
    assert_invalid(verify(
        &doc,
        &NONCE,
        &PUBLIC_KEY,
        Some(&PCR0),
        Some(&other_root),
    ));
    let error = verify(&doc, &NONCE, &PUBLIC_KEY, Some(&PCR0), Some(b"not PEM")).unwrap_err();
    assert_eq!(crate::exit_code(error.as_ref()), 1);
}

#[test]
fn accepts_aws_style_missing_aki_without_weakening_root_or_signature_checks() {
    let fixture = Fixture::with_aki(false);
    let document = fixture.sign(fixture.claims());
    fixture.verify(&document).unwrap();
    let other_root = Fixture::new().root;
    assert_invalid(verify_with_root(
        &document,
        &NONCE,
        &PUBLIC_KEY,
        Some(&PCR0),
        &other_root,
        CertificateTime::At(NOW),
    ));
    let mut altered = document;
    *altered.last_mut().unwrap() ^= 1;
    assert_invalid(fixture.verify(&altered));
}

#[test]
fn rejects_nonce_key_measurement_and_debug_mismatches() {
    let fixture = Fixture::new();
    for (name, value) in [
        ("nonce", Value::Bytes(vec![0; 32])),
        ("public_key", Value::Bytes(vec![0; 32])),
        (
            "pcrs",
            Value::Map(vec![(Value::Integer(0.into()), Value::Bytes(vec![0; 48]))]),
        ),
        (
            "pcrs",
            Value::Map(vec![(Value::Integer(0.into()), Value::Bytes(vec![2; 48]))]),
        ),
        ("digest", Value::Text("SHA256".into())),
        ("timestamp", Value::Text("invalid timestamp".into())),
    ] {
        let mut claims = fixture.claims();
        replace(&mut claims, name, value);
        assert_invalid(fixture.verify(&fixture.sign(claims)));
    }
}

#[test]
fn document_timestamp_does_not_impose_an_age_window() {
    let fixture = Fixture::new();
    for timestamp in [NOW - 60 * 60 * 1000, NOW + 60 * 60 * 1000] {
        let mut claims = fixture.claims();
        replace(&mut claims, "timestamp", Value::Integer(timestamp.into()));
        let evidence = fixture.verify(&fixture.sign(claims)).unwrap();
        assert_eq!(evidence.timestamp, timestamp);
    }
}

#[test]
fn rejects_expired_chain_wrong_root_and_corrupt_signature() {
    let fixture = Fixture::new();
    let doc = fixture.sign(fixture.claims());
    assert_invalid(verify_with_root(
        &doc,
        &NONCE,
        &PUBLIC_KEY,
        Some(&PCR0),
        &fixture.root,
        CertificateTime::At(NOW + 2 * 86400 * 1000),
    ));
    let other_root = Fixture::new().root;
    assert_invalid(verify_with_root(
        &doc,
        &NONCE,
        &PUBLIC_KEY,
        Some(&PCR0),
        &other_root,
        CertificateTime::At(NOW),
    ));
    let mut corrupted = doc;
    *corrupted.last_mut().unwrap() ^= 1;
    assert_invalid(fixture.verify(&corrupted));
}

#[test]
fn rejects_ambiguous_cbor_and_unsigned_mock_data() {
    let fixture = Fixture::new();
    let mut claims = fixture.claims();
    claims.push((Value::Text("nonce".into()), Value::Bytes(NONCE.to_vec())));
    assert_invalid(fixture.verify(&fixture.sign(claims)));
    let mut claims = fixture.claims();
    replace(
        &mut claims,
        "pcrs",
        Value::Map(vec![
            (Value::Integer(0.into()), Value::Bytes(PCR0.to_vec())),
            (Value::Integer(0.into()), Value::Bytes(PCR0.to_vec())),
        ]),
    );
    assert_invalid(fixture.verify(&fixture.sign(claims)));
    let mut trailing = fixture.sign(fixture.claims());
    trailing.push(0);
    assert_invalid(fixture.verify(&trailing));
    assert_invalid(fixture.verify(b"testdoc,key,nonce,pcr"));
}

#[test]
fn enforces_algorithm_and_accepts_only_the_cose_sign1_tag() {
    let fixture = Fixture::new();
    let doc = decode(&fixture.sign(fixture.claims())).unwrap();
    let tagged = Value::Tag(18, Box::new(doc.clone()));
    fixture.verify(&encode(&tagged)).unwrap();
    assert_invalid(fixture.verify(&encode(&Value::Tag(17, Box::new(doc.clone())))));
    let Value::Array(mut parts) = doc else {
        panic!()
    };
    parts[0] = Value::Bytes(encode(&Value::Map(vec![(
        Value::Integer(1.into()),
        Value::Integer((-7).into()),
    )])));
    assert_invalid(fixture.verify(&encode(&Value::Array(parts))));
}
