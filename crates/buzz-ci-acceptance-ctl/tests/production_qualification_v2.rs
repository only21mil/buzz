use std::{fs, io::Read, os::unix::net::UnixListener, process::Command, thread, time::Duration};

use buzz_ci_acceptance_ctl::production_qualification::{
    dispatch, DispatchError, ExchangeError, ProductionQualificationTransport,
    UnixProductionQualificationTransport, REQUEST_SCHEMA, RESPONSE_SCHEMA,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const HEADER: usize = 32;
const REQUEST_BODY: usize = 640;
const RESPONSE_BODY: usize = 576;

fn request() -> Value {
    json!({
        "schema_version": REQUEST_SCHEMA,
        "request_id": "10".repeat(16),
        "integrated_candidate_sha": "11".repeat(20),
        "activation_package_digest": "12".repeat(32),
        "fixture_digest": "13".repeat(32),
        "principal_digest": "14".repeat(32),
        "lane_manifest_digest": "15".repeat(32),
        "broker_build_identity_digest": "16".repeat(32),
        "host_profile_digest": "17".repeat(32),
        "suite_digest": "18".repeat(32),
        "isolation_profile_digest": "19".repeat(32),
        "seccomp_profile_digest": "1a".repeat(32),
        "executor_program_digest": "1b".repeat(32),
        "executor_provenance_digest": "1c".repeat(32),
        "nonce": "1d".repeat(32),
        "controller_generation": 21,
        "runner_generation": 22,
        "lane_epoch": 23,
        "admission_key_generation": 24,
        "issued_at": 100,
        "expires_at": 160
    })
}

#[derive(Default)]
struct ScriptedTransport {
    response_code: u16,
    mutate: Option<usize>,
    frames: Vec<Vec<u8>>,
    error: Option<ExchangeError>,
}

impl ProductionQualificationTransport for ScriptedTransport {
    fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, ExchangeError> {
        self.frames.push(request.to_vec());
        if let Some(error) = self.error.take() {
            return Err(error);
        }
        let mut response = response_for(request, self.response_code);
        if let Some(offset) = self.mutate {
            response[offset] ^= 1;
        }
        Ok(response)
    }
}

fn response_for(request: &[u8], code: u16) -> Vec<u8> {
    assert_eq!(request.len(), HEADER + REQUEST_BODY);
    let request_body = &request[HEADER..];
    let mut response = vec![0; HEADER + RESPONSE_BODY];
    response[..4].copy_from_slice(b"BZCI");
    response[4..6].copy_from_slice(&2_u16.to_be_bytes());
    response[6..8].copy_from_slice(&0x8005_u16.to_be_bytes());
    response[12..16].copy_from_slice(&(RESPONSE_BODY as u32).to_be_bytes());
    response[16..32].copy_from_slice(&request[16..32]);
    let body = &mut response[HEADER..];
    body[0..2].copy_from_slice(&code.to_be_bytes());
    body[6..38].copy_from_slice(&request_body[465..497]);
    body[38..70].fill(0x71);
    body[70..103].copy_from_slice(&request_body[0..33]);
    for (response_offset, request_offset) in [
        (103, 33),
        (135, 65),
        (167, 97),
        (199, 129),
        (231, 161),
        (263, 193),
        (295, 225),
        (327, 257),
        (359, 289),
        (423, 321),
        (455, 353),
    ] {
        body[response_offset..response_offset + 32]
            .copy_from_slice(&request_body[request_offset..request_offset + 32]);
    }
    body[391..423].fill(0x72);
    body[487..519].copy_from_slice(&request_body[417..449]);
    body[519..527].copy_from_slice(&150_u64.to_be_bytes());
    body[527..535].copy_from_slice(&request_body[457..465]);
    response
}

#[test]
fn exact_production_v2_success_is_closed_and_fully_bound() {
    let input = serde_json::to_vec(&request()).unwrap();
    let mut transport = ScriptedTransport::default();
    let receipt = dispatch(&input, 150, &mut transport).unwrap();
    assert_eq!(receipt.schema_version, RESPONSE_SCHEMA);
    assert_eq!(receipt.status, "qualified_closed");
    assert_eq!(receipt.disposition, "created");
    assert_eq!(receipt.integrated_candidate_sha, "11".repeat(20));
    assert_eq!(receipt.seccomp_install_receipt_digest, "72".repeat(32));
    assert_eq!(receipt.controller_generation, 21);
    let frame = &transport.frames[0];
    assert_eq!(&frame[..4], b"BZCI");
    assert_eq!(&frame[4..6], &2_u16.to_be_bytes());
    assert_eq!(&frame[6..8], &5_u16.to_be_bytes());
    assert_eq!(frame.len(), HEADER + REQUEST_BODY);
    assert!(frame[HEADER + 497..].iter().all(|byte| *byte == 0));
}

#[test]
fn exact_retry_is_byte_identical_and_existing_is_success() {
    let input = serde_json::to_vec(&request()).unwrap();
    let mut first = ScriptedTransport::default();
    let created = dispatch(&input, 150, &mut first).unwrap();
    let mut retry = ScriptedTransport {
        response_code: 1,
        ..ScriptedTransport::default()
    };
    let existing = dispatch(&input, 150, &mut retry).unwrap();
    assert_eq!(first.frames, retry.frames);
    assert_eq!(created.request_frame_digest, existing.request_frame_digest);
    assert_eq!(existing.disposition, "existing");
}

#[test]
fn replay_drift_cannot_validate_against_the_prior_response() {
    let original = serde_json::to_vec(&request()).unwrap();
    let mut capture = ScriptedTransport::default();
    dispatch(&original, 150, &mut capture).unwrap();
    let prior_response = response_for(&capture.frames[0], 1);
    struct PriorResponse(Vec<u8>);
    impl ProductionQualificationTransport for PriorResponse {
        fn exchange(&mut self, _request: &[u8]) -> Result<Vec<u8>, ExchangeError> {
            Ok(self.0.clone())
        }
    }
    let mut drifted = request();
    drifted["nonce"] = Value::String("2d".repeat(32));
    let error = dispatch(
        &serde_json::to_vec(&drifted).unwrap(),
        150,
        &mut PriorResponse(prior_response),
    )
    .unwrap_err();
    assert_eq!(
        error,
        DispatchError::Exchange(ExchangeError::BindingMismatch)
    );
}

#[test]
fn malformed_legacy_and_unknown_inputs_fail_before_transport() {
    for value in [
        json!({"version": "qualification_v1"}),
        json!({"schema_version": REQUEST_SCHEMA, "command": "/bin/sh"}),
    ] {
        let mut transport = ScriptedTransport::default();
        assert!(matches!(
            dispatch(&serde_json::to_vec(&value).unwrap(), 150, &mut transport),
            Err(DispatchError::Input(_))
        ));
        assert!(transport.frames.is_empty());
    }
}

#[test]
fn not_provisioned_and_every_other_error_fail_closed() {
    let input = serde_json::to_vec(&request()).unwrap();
    for code in [108, 105, 106, 112, 113] {
        let mut transport = ScriptedTransport {
            response_code: code,
            ..ScriptedTransport::default()
        };
        assert!(matches!(
            dispatch(&input, 150, &mut transport),
            Err(DispatchError::Exchange(ExchangeError::Refused(_)))
        ));
    }
}

#[test]
fn response_drift_and_noncanonical_frames_fail_closed() {
    let input = serde_json::to_vec(&request()).unwrap();
    for offset in [16, HEADER + 6, HEADER + 103, HEADER + 487, HEADER + 535] {
        let mut transport = ScriptedTransport {
            mutate: Some(offset),
            ..ScriptedTransport::default()
        };
        assert!(dispatch(&input, 150, &mut transport).is_err());
    }
}

#[test]
fn unix_transport_timeout_is_typed_and_bounded() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("execd.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = vec![0; HEADER + REQUEST_BODY];
        stream.read_exact(&mut request).unwrap();
        thread::sleep(Duration::from_millis(150));
    });
    let input = serde_json::to_vec(&request()).unwrap();
    let mut transport =
        UnixProductionQualificationTransport::at_path(socket, Duration::from_millis(20));
    let error = dispatch(&input, 150, &mut transport).unwrap_err();
    assert_eq!(error, DispatchError::Exchange(ExchangeError::Timeout));
    server.join().unwrap();
}

#[test]
fn standalone_binary_has_no_argv_or_v1_fallback() {
    let binary = env!("CARGO_BIN_EXE_buzz-ci-production-qualification");
    let argv = Command::new(binary).arg("/bin/true").output().unwrap();
    assert_eq!(argv.status.code(), Some(2));
    assert!(argv.stdout.is_empty());
    let error: Value = serde_json::from_slice(&argv.stderr).unwrap();
    assert_eq!(error["code"], "invalid_cli");

    let mut child = Command::new(binary)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    std::io::Write::write_all(
        child.stdin.as_mut().unwrap(),
        br#"{"version":"qualification_v1"}"#,
    )
    .unwrap();
    drop(child.stdin.take());
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let error: Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(error["status"], "qualification_failed_closed");
}

#[test]
fn compatibility_fixture_matches_exact_frames_and_receipt() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/production-qualification-v2-compatibility.json"
    );
    let fixture: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let input = serde_json::to_vec(&fixture["request"]).unwrap();
    let mut transport = ScriptedTransport::default();
    let receipt = dispatch(&input, 150, &mut transport).unwrap();
    assert_eq!(
        hex::encode(&transport.frames[0]),
        fixture["request_frame_hex"]
    );
    assert_eq!(
        hex::encode(response_for(&transport.frames[0], 0)),
        fixture["response_frame_hex"]
    );
    assert_eq!(serde_json::to_value(receipt).unwrap(), fixture["receipt"]);
    let digest = hex::encode(Sha256::digest(&transport.frames[0]));
    assert_eq!(digest, fixture["request_frame_sha256"]);
}
