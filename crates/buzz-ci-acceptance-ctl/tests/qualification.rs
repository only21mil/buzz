use buzz_ci_acceptance_ctl::{
    dispatch, parse_and_validate, DispatchError, InputError, QualificationRequest,
    QualificationTransport, MAX_INPUT_BYTES,
};
use serde_json::{json, Value};
use std::{
    io::Write,
    process::{Command, Stdio},
};

#[derive(Default)]
struct TransportSpy {
    bytes: Vec<u8>,
    calls: usize,
}

impl QualificationTransport for TransportSpy {
    type Error = std::convert::Infallible;

    fn exchange(&mut self, request: &QualificationRequest) -> Result<(), Self::Error> {
        self.calls += 1;
        self.bytes = serde_json::to_vec(request).expect("validated request serializes");
        Ok(())
    }
}

fn hex(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

fn oid(byte: u8) -> Value {
    json!({"algorithm": "sha256", "hex": hex(byte)})
}

fn host() -> Value {
    json!({
        "integrated_candidate_sha": oid(2),
        "broker_build_identity": hex(3),
        "host_profile_digest": hex(4),
        "suite_identity": hex(5)
    })
}

fn fixture_job() -> Value {
    json!({
        "request_digest": hex(6),
        "manifest_digest": hex(7),
        "isolation_profile_digest": hex(8),
        "source_oid": oid(9),
        "base_oid": oid(10),
        "test_identity": hex(11)
    })
}

fn valid_input() -> Value {
    json!({
        "version": "qualification_v1",
        "permit": {
            "authorized_by": hex(1),
            "host": host(),
            "fixture_job": fixture_job(),
            "fixture_identity": hex(12),
            "fixture_signer": hex(13),
            "nonce": hex(14),
            "not_before": 10,
            "expires_at": 30
        },
        "admission": {
            "host": host(),
            "fixture_job": fixture_job(),
            "fixture_identity": hex(12),
            "signer": hex(13),
            "nonce": hex(14),
            "trust_class": "qualification_fixture"
        }
    })
}

fn set_path(value: &mut Value, path: &[&str], replacement: Value) {
    let (last, parents) = path.split_last().expect("non-empty path");
    let mut cursor = value;
    for key in parents {
        cursor = cursor.get_mut(*key).expect("fixture path exists");
    }
    cursor[*last] = replacement;
}

fn input_bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

#[test]
fn valid_request_reaches_transport_once() {
    let mut spy = TransportSpy::default();
    dispatch(&input_bytes(&valid_input()), &mut spy).unwrap();
    assert_eq!(spy.calls, 1);
    assert!(!spy.bytes.is_empty());
}

#[test]
fn teardown_failure_is_the_only_directive() {
    let mut request = valid_input();
    request["directive"] = json!("teardown_failure");
    parse_and_validate(&input_bytes(&request)).unwrap();

    request["directive"] = json!("kill_runtime");
    assert!(matches!(
        parse_and_validate(&input_bytes(&request)),
        Err(InputError::Malformed(_))
    ));
}

#[test]
fn every_coordinate_and_identity_mismatch_is_rejected_without_transport_bytes() {
    let mismatches: &[(&[&str], Value, &str)] = &[
        (
            &["admission", "host", "integrated_candidate_sha"],
            oid(31),
            "host.integrated_candidate_sha",
        ),
        (
            &["admission", "host", "broker_build_identity"],
            json!(hex(31)),
            "host.broker_build_identity",
        ),
        (
            &["admission", "host", "host_profile_digest"],
            json!(hex(31)),
            "host.host_profile_digest",
        ),
        (
            &["admission", "host", "suite_identity"],
            json!(hex(31)),
            "host.suite_identity",
        ),
        (
            &["admission", "fixture_job", "request_digest"],
            json!(hex(31)),
            "fixture_job.request_digest",
        ),
        (
            &["admission", "fixture_job", "manifest_digest"],
            json!(hex(31)),
            "fixture_job.manifest_digest",
        ),
        (
            &["admission", "fixture_job", "isolation_profile_digest"],
            json!(hex(31)),
            "fixture_job.isolation_profile_digest",
        ),
        (
            &["admission", "fixture_job", "source_oid"],
            oid(31),
            "fixture_job.source_oid",
        ),
        (
            &["admission", "fixture_job", "base_oid"],
            oid(31),
            "fixture_job.base_oid",
        ),
        (
            &["admission", "fixture_job", "test_identity"],
            json!(hex(31)),
            "fixture_job.test_identity",
        ),
        (
            &["admission", "fixture_identity"],
            json!(hex(31)),
            "fixture_identity",
        ),
        (&["admission", "signer"], json!(hex(31)), "fixture_signer"),
        (&["admission", "nonce"], json!(hex(31)), "nonce"),
    ];

    for (path, replacement, expected_field) in mismatches {
        let mut request = valid_input();
        set_path(&mut request, path, replacement.clone());
        let mut spy = TransportSpy::default();
        let error = dispatch(&input_bytes(&request), &mut spy).unwrap_err();
        assert!(matches!(
            error,
            DispatchError::Input(InputError::BindingMismatch(field)) if field == *expected_field
        ));
        assert_eq!(spy.calls, 0, "transport called for {expected_field}");
        assert!(spy.bytes.is_empty(), "transport wrote for {expected_field}");
    }
}

#[test]
fn every_required_fixed_value_rejects_zero_without_transport_bytes() {
    let paths: &[&[&str]] = &[
        &["permit", "authorized_by"],
        &["permit", "host", "integrated_candidate_sha", "hex"],
        &["permit", "host", "broker_build_identity"],
        &["permit", "host", "host_profile_digest"],
        &["permit", "host", "suite_identity"],
        &["permit", "fixture_job", "request_digest"],
        &["permit", "fixture_job", "manifest_digest"],
        &["permit", "fixture_job", "isolation_profile_digest"],
        &["permit", "fixture_job", "source_oid", "hex"],
        &["permit", "fixture_job", "base_oid", "hex"],
        &["permit", "fixture_job", "test_identity"],
        &["permit", "fixture_identity"],
        &["permit", "fixture_signer"],
        &["permit", "nonce"],
        &["admission", "host", "integrated_candidate_sha", "hex"],
        &["admission", "host", "broker_build_identity"],
        &["admission", "host", "host_profile_digest"],
        &["admission", "host", "suite_identity"],
        &["admission", "fixture_job", "request_digest"],
        &["admission", "fixture_job", "manifest_digest"],
        &["admission", "fixture_job", "isolation_profile_digest"],
        &["admission", "fixture_job", "source_oid", "hex"],
        &["admission", "fixture_job", "base_oid", "hex"],
        &["admission", "fixture_job", "test_identity"],
        &["admission", "fixture_identity"],
        &["admission", "signer"],
        &["admission", "nonce"],
    ];

    for path in paths {
        let mut request = valid_input();
        let width = request
            .pointer(&format!("/{}", path.join("/")))
            .unwrap()
            .as_str()
            .unwrap()
            .len();
        set_path(&mut request, path, json!("0".repeat(width)));
        let mut spy = TransportSpy::default();
        assert!(matches!(
            dispatch(&input_bytes(&request), &mut spy),
            Err(DispatchError::Input(InputError::ZeroField(_)))
        ));
        assert_eq!(spy.calls, 0, "transport called for {}", path.join("."));
        assert!(
            spy.bytes.is_empty(),
            "transport wrote for {}",
            path.join(".")
        );
    }
}

#[test]
fn authority_trust_and_time_bounds_fail_closed() {
    let cases = [
        (
            &["admission", "trust_class"][..],
            json!("accepted_reviewed"),
            "unaccepted_trust_class",
        ),
        (&["permit", "not_before"][..], json!(0), "zero_field"),
        (&["permit", "expires_at"][..], json!(0), "zero_field"),
        (
            &["permit", "not_before"][..],
            json!(30),
            "invalid_time_window",
        ),
    ];
    for (path, replacement, code) in cases {
        let mut request = valid_input();
        set_path(&mut request, path, replacement);
        let mut spy = TransportSpy::default();
        let error = dispatch(&input_bytes(&request), &mut spy).unwrap_err();
        let error = match error {
            DispatchError::Input(error) => error,
            DispatchError::Transport(never) => match never {},
        };
        assert_eq!(error.code(), code);
        assert_eq!(spy.calls, 0);
        assert!(spy.bytes.is_empty());
    }
}

#[test]
fn grammar_rejects_unknown_fields_and_non_normalized_hex() {
    let mut unknown = valid_input();
    unknown["repo"] = json!("owner/repo");
    assert!(matches!(
        parse_and_validate(&input_bytes(&unknown)),
        Err(InputError::Malformed(_))
    ));

    let mut uppercase = valid_input();
    uppercase["permit"]["nonce"] = json!(hex(14).to_ascii_uppercase());
    assert!(matches!(
        parse_and_validate(&input_bytes(&uppercase)),
        Err(InputError::Malformed(_))
    ));
}

#[test]
fn oversized_input_never_reaches_transport() {
    let mut spy = TransportSpy::default();
    let input = vec![b' '; MAX_INPUT_BYTES + 1];
    assert!(matches!(
        dispatch(&input, &mut spy),
        Err(DispatchError::Input(InputError::InputTooLarge))
    ));
    assert_eq!(spy.calls, 0);
    assert!(spy.bytes.is_empty());
}

#[test]
fn standalone_cli_rejects_argv_and_invalid_input_with_empty_stdout() {
    let argv = Command::new(env!("CARGO_BIN_EXE_buzz-ci-acceptance-ctl"))
        .arg("--fault")
        .output()
        .unwrap();
    assert_eq!(argv.status.code(), Some(2));
    assert!(argv.stdout.is_empty());
    let argv_error: Value = serde_json::from_slice(&argv.stderr).unwrap();
    assert_eq!(argv_error["code"], "invalid_cli");

    let mut invalid = valid_input();
    invalid["repo"] = json!("forbidden/raw-repo");
    let mut child = Command::new(env!("CARGO_BIN_EXE_buzz-ci-acceptance-ctl"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&input_bytes(&invalid))
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["type"], "qualification_error");
    assert_eq!(error["code"], "malformed_input");
}
