#![forbid(unsafe_code)]

use buzz_agent_key_handoff::parity_signature::{canonical_json_ascii, CANONICAL_JSON_CONTRACT};
use nostr::secp256k1::{schnorr::Signature, Message, Secp256k1, XOnlyPublicKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Output, Stdio};
use tempfile::tempdir;

const SK1: &str = "0000000000000000000000000000000000000000000000000000000000000001";
const PK1: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const PK2: &str = "c6047f9441ed7d6d3045406e95c07cd85a9e8b036e67d4073b95c709ee5bcc86";

fn pipe_command(command: &mut Command, input: &[u8]) -> Output {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tool");
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn signer_and_verifier_are_deterministic_and_fail_closed() {
    let root = tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let secrets = root.path().join("secrets.env");
    fs::write(
        &secrets,
        format!("IGNORED_CONFIG=value\nBUZZ_OWNER_PRIVATE_KEY={SK1}\n"),
    )
    .unwrap();
    fs::set_permissions(&secrets, fs::Permissions::from_mode(0o600)).unwrap();

    let mut unsigned = json!({
        "canonical_json_contract": CANONICAL_JSON_CONTRACT,
        "checks": {"codex_r_response_policy": true},
        "schema": "buzz-agent-capability-parity-receipt-v2",
        "status": "PASS"
    });
    let canonical = canonical_json_ascii(&unsigned).unwrap();
    let digest = hex::encode(Sha256::digest(canonical));
    unsigned["payload_sha256"] = Value::String(digest.clone());

    let signer_args = [
        "--secrets-file",
        secrets.to_str().unwrap(),
        "--owner-pubkey",
        PK1,
        "--signed-at",
        "2026-08-27T00:00:00Z",
    ];
    let sign = || {
        pipe_command(
            Command::new(env!("CARGO_BIN_EXE_buzz-parity-owner-signer")).args(signer_args),
            format!("{digest}\n").as_bytes(),
        )
    };
    let first = sign();
    let second = sign();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert_eq!(first.stdout, second.stdout);
    assert!(!String::from_utf8_lossy(&first.stdout).contains(SK1));
    assert!(!String::from_utf8_lossy(&first.stderr).contains(SK1));
    let signature: Value = serde_json::from_slice(&first.stdout).unwrap();
    let raw_signature: Signature = signature["signature"].as_str().unwrap().parse().unwrap();
    let raw_message = Message::from_digest_slice(&hex::decode(&digest).unwrap()).unwrap();
    let public_key = XOnlyPublicKey::from_slice(&hex::decode(PK1).unwrap()).unwrap();
    assert!(
        Secp256k1::verification_only()
            .verify_schnorr(&raw_signature, &raw_message, &public_key)
            .is_err(),
        "parity signature must not verify as a raw Nostr event-digest signature"
    );
    let envelope = json!({
        "schema": "buzz-agent-capability-parity-sealed-receipt-v1",
        "receipt": unsigned,
        "signature": signature,
        "signer": {"executable": "reviewed-signer"},
        "verifier": {"executable": "reviewed-verifier"},
        "verified": false
    });
    let verify = |value: &Value, owner: &str| {
        pipe_command(
            Command::new(env!("CARGO_BIN_EXE_buzz-parity-owner-verifier"))
                .args(["--owner-pubkey", owner]),
            &serde_json::to_vec(value).unwrap(),
        )
    };
    let verify_root_owned = |value: &Value, owner: &str| {
        pipe_command(
            Command::new(env!("CARGO_BIN_EXE_buzz-agent-key-handoff")).args([
                "verify-parity-envelope",
                "--owner-pubkey",
                owner,
            ]),
            &serde_json::to_vec(value).unwrap(),
        )
    };
    assert!(verify(&envelope, PK1).status.success());
    assert!(verify_root_owned(&envelope, PK1).status.success());

    let mut persisted = envelope.clone();
    persisted["verified"] = Value::Bool(true);
    let persisted_canonical = canonical_json_ascii(&persisted).unwrap();
    persisted["sealed_sha256"] = Value::String(hex::encode(Sha256::digest(persisted_canonical)));
    assert!(verify(&persisted, PK1).status.success());
    assert!(verify_root_owned(&persisted, PK1).status.success());

    let mut tampered = envelope.clone();
    tampered["receipt"]["status"] = Value::String("BLOCKED".to_owned());
    assert!(!verify(&tampered, PK1).status.success());
    assert!(!verify_root_owned(&tampered, PK1).status.success());
    assert!(!verify(&envelope, PK2).status.success());
    assert!(!verify_root_owned(&envelope, PK2).status.success());
    let mut sealed_tamper = persisted;
    sealed_tamper["verified"] = Value::Bool(false);
    assert!(!verify(&sealed_tamper, PK1).status.success());
}

#[test]
fn shared_canonical_json_contract_vectors() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/parity-canonical-json-v1.json")).unwrap();
    assert_eq!(fixture["contract"], CANONICAL_JSON_CONTRACT);
    for case in fixture["positive"].as_array().unwrap() {
        let observed = canonical_json_ascii(&case["value"]).unwrap();
        assert_eq!(observed, case["canonical"].as_str().unwrap().as_bytes());
    }
    for case in fixture["negative"].as_array().unwrap() {
        let parsed = serde_json::from_str::<Value>(case["json"].as_str().unwrap());
        assert!(
            parsed.is_err() || canonical_json_ascii(&parsed.unwrap()).is_err(),
            "negative vector unexpectedly accepted: {}",
            case["name"]
        );
    }
}

#[test]
fn signer_rejects_relative_or_weak_private_input() {
    let root = tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let secrets = root.path().join("secrets.env");
    fs::write(&secrets, format!("BUZZ_OWNER_PRIVATE_KEY={SK1}\n")).unwrap();
    fs::set_permissions(&secrets, fs::Permissions::from_mode(0o644)).unwrap();
    let output = pipe_command(
        Command::new(env!("CARGO_BIN_EXE_buzz-parity-owner-signer")).args([
            "--secrets-file",
            secrets.to_str().unwrap(),
            "--owner-pubkey",
            PK1,
            "--signed-at",
            "2026-08-27T00:00:00Z",
        ]),
        format!("{}\n", "a".repeat(64)).as_bytes(),
    );
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stderr).contains(SK1));
}
