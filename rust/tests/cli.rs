use std::io::Write;
use std::process::{Command, Output, Stdio};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;

fn arguments(command: &str) -> Vec<String> {
    vec![
        command.into(),
        "--nonce".into(),
        "07".repeat(32),
        "--public-key".into(),
        BASE64.encode([8; 32]),
    ]
}

fn verification_arguments() -> [Vec<String>; 2] {
    let args = arguments("-v");
    let mut with_pcr0 = args.clone();
    with_pcr0.extend(["--pcr0".into(), "09".repeat(48)]);
    [args, with_pcr0]
}

fn run(args: &[String], input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_attest-link-rust"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn invalid_documents_exit_two_without_stdout() {
    for args in verification_arguments() {
        for input in [
            vec![],
            vec![0xff],
            b"not base64!".to_vec(),
            BASE64.encode(b"not CBOR").into_bytes(),
            BASE64.encode(vec![0; 16 * 1024 + 1]).into_bytes(),
            vec![b'A'; 24 * 1024 + 1],
        ] {
            let output = run(&args, &input);
            assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
            assert!(output.stdout.is_empty());
            assert!(!output.stderr.is_empty());
        }
    }
}

#[test]
fn bad_invocations_exit_one_without_stdout() {
    // Configuration errors must not be confused with rejected peer evidence.
    let mut missing_key = arguments("-v");
    missing_key.truncate(3);
    for args in [
        vec![],
        missing_key,
        arguments("inspect"),
        arguments("get"),
        arguments("verify"),
    ] {
        let output = run(&args, b"");
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
    }
    for pcr0 in ["".into(), "12".into(), "00".repeat(48), "zz".repeat(48)] {
        let mut args = arguments("-v");
        args.extend(["--pcr0".into(), pcr0]);
        let output = run(&args, b"");
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn operation_flags_are_mutually_exclusive_and_can_follow_options() {
    for command in ["-g", "-v"] {
        let mut args = arguments(command);
        args.push(if command == "-g" { "-v" } else { "-g" }.into());
        let output = run(&args, b"");
        assert_eq!(output.status.code(), Some(1));
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("expected exactly one of -g or -v")
        );

        let mut args = arguments(command);
        args.push(command.into());
        let output = run(&args, b"");
        assert_eq!(output.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&output.stderr).contains("duplicate option"));
    }
    let mut args = arguments("-v");
    args.remove(0);
    assert_eq!(run(&args, b"").status.code(), Some(1));
    args.push("-v".into());
    assert_eq!(run(&args, b"").status.code(), Some(2));

    let output = run(&["-x".into()], b"");
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("expected exactly one of -g or -v"));
}

#[test]
fn document_time_flag_is_only_valid_with_get_and_cannot_be_repeated() {
    for mut args in verification_arguments() {
        args.push("-x".into());
        let output = run(&args, b"");
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("-x is only valid with -g"));
    }
    let mut args = arguments("-g");
    args.extend(["-x".into(), "-x".into()]);
    let output = run(&args, b"");
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("duplicate option"));

    for flag in ["--json", "--verify-at-document-time"] {
        let mut args = arguments("-g");
        args.push(flag.into());
        let output = run(&args, b"");
        assert_eq!(output.status.code(), Some(1));
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(&format!("unknown option: {flag}"))
        );
    }
}

#[test]
fn user_data_is_base64_json_and_only_valid_with_get() {
    let mut invalid_data = arguments("-g");
    invalid_data.extend(["--user-data".into(), "not base64!".into()]);
    assert_eq!(run(&invalid_data, b"").status.code(), Some(1));

    for json in ["not JSON", "[]", "null", "1", "\"text\""] {
        let mut args = arguments("-g");
        args.extend(["--user-data".into(), BASE64.encode(json)]);
        let output = run(&args, b"");
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("NSM"));
    }

    for mut args in verification_arguments() {
        args.extend(["--user-data".into(), BASE64.encode("{}")]);
        let output = run(&args, b"");
        assert_eq!(output.status.code(), Some(1));
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("--user-data is only valid with -g")
        );
    }
}

#[test]
fn root_certificate_option_loads_pem_and_reports_configuration_errors() {
    let mut raw_get = arguments("-g");
    raw_get.extend(["--root-cert".into(), "root.pem".into()]);
    let output = run(&raw_get, b"");
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--root-cert with -g requires -x"));

    for args in verification_arguments() {
        for (file, code) in [("root.pem", 2), ("Cargo.toml", 1), ("missing-root.pem", 1)] {
            let mut args = args.clone();
            args.extend([
                "--root-cert".into(),
                format!("{}/{file}", env!("CARGO_MANIFEST_DIR")),
            ]);
            let output = run(&args, b"");
            assert_eq!(
                output.status.code(),
                Some(code),
                "{args:?}, {file}: {output:?}"
            );
            assert!(output.stdout.is_empty());
        }
    }
    let mut missing_path = arguments("-v");
    missing_path.push("--root-cert".into());
    assert_eq!(run(&missing_path, b"").status.code(), Some(1));
}
