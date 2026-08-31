use std::{
    fs,
    io::{Read, Write},
    os::unix::net::UnixListener,
    process::Command,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use buzz_ci_acceptance_ctl::production_qualification::{
    dispatch, DispatchError, ExchangeError, ProductionQualificationTransport,
    UnixProductionQualificationTransport, REQUEST_SCHEMA, RESPONSE_SCHEMA,
};
use buzz_ci_broker_protocol::{
    v2::{
        decode_request, decode_request_header, encode_production_qualification_response,
        production_qualification_receipt_digest, ProductionQualificationRequest,
        ProductionQualificationResponse, Request,
    },
    ResponseCode,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const HEADER: usize = 32;
const REQUEST_BODY: usize = 640;

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
    let (header, decoded) = decode_request(request).expect("decode request fixture");
    let Request::AdmitQualification(request) = decoded else {
        panic!("fixture must be production qualification");
    };
    let code = ResponseCode::try_from(code).expect("known response code");
    let response = qualification_response(request, code, 150);
    encode_production_qualification_response(header, response)
        .as_bytes()
        .to_vec()
}

fn qualification_response(
    request: ProductionQualificationRequest,
    code: ResponseCode,
    qualified_at: u64,
) -> ProductionQualificationResponse {
    let mut response = ProductionQualificationResponse {
        code,
        retry_after_millis: 0,
        request_frame_digest: request.request_frame_digest,
        qualification_receipt_digest: [0; 32],
        integrated_candidate_sha: request.integrated_candidate_sha,
        activation_package_digest: request.activation_package_digest,
        fixture_digest: request.fixture_digest,
        principal_digest: request.principal_digest,
        lane_manifest_digest: request.lane_manifest_digest,
        broker_build_identity: request.broker_build_identity,
        host_profile_digest: request.host_profile_digest,
        suite_identity: request.suite_identity,
        isolation_profile_digest: request.isolation_profile_digest,
        seccomp_profile_digest: request.seccomp_profile_digest,
        seccomp_install_receipt_digest: [0x72; 32],
        executor_program_digest: request.executor_program_digest,
        executor_provenance_digest: request.executor_provenance_digest,
        controller_generation: request.controller_generation,
        runner_generation: request.runner_generation,
        lane_epoch: request.lane_epoch,
        admission_key_generation: request.admission_key_generation,
        qualified_at,
        request_expires_at: request.expires_at,
    };
    response.qualification_receipt_digest = production_qualification_receipt_digest(&response);
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
    for offset in [
        0,
        4,
        6,
        8,
        12,
        16,
        HEADER,
        HEADER + 2,
        HEADER + 6,
        HEADER + 38,
        HEADER + 71,
        HEADER + 103,
        HEADER + 135,
        HEADER + 167,
        HEADER + 199,
        HEADER + 231,
        HEADER + 263,
        HEADER + 295,
        HEADER + 327,
        HEADER + 359,
        HEADER + 391,
        HEADER + 423,
        HEADER + 455,
        HEADER + 487,
        HEADER + 495,
        HEADER + 503,
        HEADER + 511,
        HEADER + 519,
        HEADER + 527,
        HEADER + 535,
    ] {
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
        let mut request = Vec::new();
        stream.read_to_end(&mut request).unwrap();
        assert_eq!(request.len(), HEADER + REQUEST_BODY);
        thread::sleep(Duration::from_millis(150));
    });
    let input = serde_json::to_vec(&request()).unwrap();
    let mut transport =
        UnixProductionQualificationTransport::at_path(socket, Duration::from_millis(20));
    let error = dispatch(&input, 150, &mut transport).unwrap_err();
    assert_eq!(error, DispatchError::Exchange(ExchangeError::Timeout));
    server.join().unwrap();
}

fn serve_production_style_qualification(listener: UnixListener) {
    let (mut stream, _) = listener.accept().expect("accept production client");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();

    let mut header_bytes = [0; HEADER];
    stream
        .read_exact(&mut header_bytes)
        .expect("read qualification header");
    let (_, body_size) = decode_request_header(&header_bytes).expect("decode v2 request header");
    assert_eq!(body_size, REQUEST_BODY);
    let mut frame = header_bytes.to_vec();
    frame.resize(HEADER + body_size, 0);
    stream
        .read_exact(&mut frame[HEADER..])
        .expect("read qualification body");

    let mut trailing = [0; 1];
    assert_eq!(
        stream.read(&mut trailing).expect("read request EOF"),
        0,
        "production framing requires the client to half-close SHUT_WR"
    );

    let (header, decoded) = decode_request(&frame).expect("decode production qualification");
    let Request::AdmitQualification(request) = decoded else {
        panic!("client sent an unexpected operation");
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let qualified_at = now.clamp(request.issued_at, request.expires_at - 1);
    let response = qualification_response(request, ResponseCode::Ok, qualified_at);
    stream
        .write_all(encode_production_qualification_response(header, response).as_bytes())
        .expect("write production qualification response");
}

#[test]
fn real_unix_client_interoperates_with_production_server_frame_handler() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("execd.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = thread::spawn(move || serve_production_style_qualification(listener));

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut value = request();
    value["issued_at"] = Value::from(now);
    value["expires_at"] = Value::from(now + 60);
    let input = serde_json::to_vec(&value).unwrap();
    let mut transport =
        UnixProductionQualificationTransport::at_path(socket, Duration::from_secs(2));
    let receipt = dispatch(&input, now, &mut transport).expect("production-v2 qualification");
    assert_eq!(receipt.status, "qualified_closed");
    assert_eq!(receipt.disposition, "created");
    assert_eq!(receipt.request_expires_at, now + 60);
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
    let response = response_for(&transport.frames[0], 0);
    assert_eq!(
        hex::encode(Sha256::digest(response)),
        fixture["response_frame_sha256"]
    );
}
