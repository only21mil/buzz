use std::collections::BTreeMap;

use buzz_ci_controld::manifest::{
    compile_job_manifest, Ed25519ManifestSigner, JobManifestInput, ManifestCompileError,
    ManifestSigningError, WorkspaceIdentity, MANIFEST_SIGNATURE_DOMAIN,
};
use buzz_core::ci::{CiRequestEnvelope, CiRequestType, CI_SCHEMA_VERSION};
use serde_json::Value;
use sha2::{Digest, Sha256};

const LEASE_ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

fn request() -> CiRequestEnvelope {
    CiRequestEnvelope {
        schema_version: CI_SCHEMA_VERSION,
        request_type: CiRequestType::Run,
        target_repo_a: format!("30617:{}:buzz", "11".repeat(32)),
        pr_root_event_id: "22".repeat(32),
        pr_update_event_id: None,
        source_clone_url: "https://relay.example/git/buzz".into(),
        immutable_source_ref: "refs/nostr/source/accepted".into(),
        tip_oid: "33".repeat(20),
        source_branch: "feature".into(),
        base_ref: "refs/heads/main".into(),
        base_oid: "44".repeat(20),
        workflow_id: "ci".into(),
        workflow_digest: "55".repeat(32),
        job_ids: vec!["test".into()],
        run_id: "123e4567-e89b-12d3-a456-426614174011".into(),
        attempt: 1,
        parent_attempt: None,
        parent_run_id: None,
        trigger_event_id: "22".repeat(32),
        actor: "66".repeat(32),
        timeout_seconds: 30,
        idempotency_key: "123e4567-e89b-12d3-a456-426614174012".into(),
        issued_at: 10,
        expires_at: 40,
    }
}

#[derive(Default)]
struct CapturingSigner {
    signing_bytes: Vec<Vec<u8>>,
    private_marker: &'static str,
}

impl Ed25519ManifestSigner for CapturingSigner {
    fn sign_ed25519(&mut self, signing_bytes: &[u8]) -> Result<[u8; 64], ManifestSigningError> {
        self.signing_bytes.push(signing_bytes.to_vec());
        Ok([0x7b; 64])
    }
}

fn manifest_input() -> JobManifestInput {
    JobManifestInput {
        job_id: "test".into(),
        attempt: 1,
        parent_attempt: 0,
        workflow_path: ".github/workflows/ci.yml".into(),
        lease_id: LEASE_ID.into(),
        workspace: WorkspaceIdentity {
            path: "/var/lib/buzzci/workspaces/lease-test".into(),
            device: 42,
            inode: 99,
            owner_uid: 62001,
        },
        policy_digest: "77".repeat(32),
        descriptor_digest: "88".repeat(32),
        audience_digest: "99".repeat(32),
        isolation_profile_digest: "aa".repeat(32),
        argv: vec!["test".into()],
        environment: BTreeMap::from([("CI".into(), "true".into())]),
    }
}

#[test]
fn manifest_is_deterministic_domain_separated_and_binds_every_execution_coordinate() {
    let request = request();
    let mut first_signer = CapturingSigner {
        private_marker: "SUPER-PRIVATE-ED25519-SIGNING-KEY",
        ..CapturingSigner::default()
    };
    let mut second_signer = CapturingSigner {
        private_marker: "SUPER-PRIVATE-ED25519-SIGNING-KEY",
        ..CapturingSigner::default()
    };
    let first = compile_job_manifest(
        &"ab".repeat(32),
        &"cd".repeat(32),
        &request,
        manifest_input(),
        &mut first_signer,
    )
    .expect("first manifest");
    let second = compile_job_manifest(
        &"ab".repeat(32),
        &"cd".repeat(32),
        &request,
        manifest_input(),
        &mut second_signer,
    )
    .expect("second manifest");

    assert_eq!(first, second);
    assert_eq!(first_signer.signing_bytes, second_signer.signing_bytes);
    assert!(first_signer.signing_bytes[0].starts_with(MANIFEST_SIGNATURE_DOMAIN));
    assert_eq!(
        first.job_manifest_digest(),
        hex::encode(Sha256::digest(first.job_manifest().as_bytes()))
    );
    assert!(!first.job_manifest().contains(first_signer.private_marker));

    let value: Value = serde_json::from_str(first.job_manifest()).expect("manifest JSON");
    let environment = value["environment"].as_object().expect("environment");
    let expected = [
        ("BUZZ_CI_REQUEST_EVENT_ID", "ab".repeat(32)),
        ("BUZZ_CI_RUN_ID", request.run_id.clone()),
        ("BUZZ_CI_TARGET_REPO_A", request.target_repo_a.clone()),
        ("BUZZ_CI_SOURCE_REF", request.immutable_source_ref.clone()),
        ("BUZZ_CI_SHA", request.tip_oid.clone()),
        ("BUZZ_CI_BASE_REF", request.base_ref.clone()),
        ("BUZZ_CI_BASE_SHA", request.base_oid.clone()),
        ("BUZZ_CI_WORKFLOW_ID", request.workflow_id.clone()),
        ("BUZZ_CI_WORKFLOW_DIGEST", request.workflow_digest.clone()),
        ("BUZZ_CI_JOB_ID", "test".into()),
        ("BUZZ_CI_ATTEMPT", "1".into()),
        ("BUZZ_CI_PARENT_ATTEMPT", "0".into()),
        ("BUZZ_CI_LEASE_ID", LEASE_ID.into()),
        (
            "BUZZ_CI_WORKSPACE",
            "/var/lib/buzzci/workspaces/lease-test".into(),
        ),
        ("BUZZ_CI_WORKSPACE_DEVICE", "42".into()),
        ("BUZZ_CI_WORKSPACE_INODE", "99".into()),
        ("BUZZ_CI_WORKSPACE_UID", "62001".into()),
        ("BUZZ_CI_POLICY_DIGEST", "77".repeat(32)),
        ("BUZZ_CI_DESCRIPTOR_DIGEST", "88".repeat(32)),
    ];
    for (key, expected_value) in expected {
        assert_eq!(environment[key], expected_value);
    }
}

#[test]
fn manifest_compiler_rejects_mismatch_traversal_and_secret_bearing_inputs() {
    let request = request();
    let compile = |input: JobManifestInput| {
        compile_job_manifest(
            &"ab".repeat(32),
            &"cd".repeat(32),
            &request,
            input,
            &mut CapturingSigner::default(),
        )
    };

    let mut mismatch = manifest_input();
    mismatch.attempt = 2;
    assert_eq!(compile(mismatch), Err(ManifestCompileError::JobMismatch));

    let mut traversal = manifest_input();
    traversal.workspace.path = "/var/lib/buzzci/../signer".into();
    assert_eq!(
        compile(traversal),
        Err(ManifestCompileError::InvalidWorkspace)
    );

    let mut secret_env = manifest_input();
    secret_env
        .environment
        .insert("MANIFEST_SIGNING_KEY".into(), "secret".into());
    assert_eq!(
        compile(secret_env),
        Err(ManifestCompileError::InvalidEnvironment)
    );

    let mut secret_argv = manifest_input();
    secret_argv.argv.push("--signing-key=/secret".into());
    assert_eq!(
        compile(secret_argv),
        Err(ManifestCompileError::InvalidArguments)
    );

    let mut reserved = manifest_input();
    reserved
        .environment
        .insert("BUZZ_CI_SHA".into(), "switched".into());
    assert_eq!(
        compile(reserved),
        Err(ManifestCompileError::InvalidEnvironment)
    );

    for key in ["NOSTR_NSEC", "GITHUB_TOKEN", "GIT_CREDENTIAL"] {
        let mut secret = manifest_input();
        secret.environment.insert(key.into(), "redacted".into());
        assert_eq!(
            compile(secret),
            Err(ManifestCompileError::InvalidEnvironment)
        );
    }
    for value in [
        format!("nsec1{}", "q".repeat(58)),
        "wrapped=ghp_0123456789abcdefghijklmnopqrstuvwxyz".into(),
        "github_pat_0123456789abcdefghijklmnopqrstuvwxyz".into(),
        "glpat-0123456789abcdefghijklmnopqrstuvwxyz".into(),
        "-----BEGIN OPENSSH PRIVATE KEY-----payload".into(),
    ] {
        let mut secret = manifest_input();
        secret.environment.insert("DESCRIPTION".into(), value);
        assert_eq!(
            compile(secret),
            Err(ManifestCompileError::InvalidEnvironment)
        );
    }

    let mut safe_text = manifest_input();
    safe_text.environment.insert(
        "MONKEY_BUSINESS".into(),
        "documentation mentions token, nsec1, ghp_, and private key labels".into(),
    );
    assert!(compile(safe_text).is_ok());

    for path in [
        "./.github/workflows/ci.yml",
        ".github//workflows/ci.yml",
        ".github/./workflows/ci.yml",
        ".github/workflows/ci.yml/",
    ] {
        let mut noncanonical = manifest_input();
        noncanonical.workflow_path = path.into();
        assert_eq!(
            compile(noncanonical),
            Err(ManifestCompileError::InvalidWorkflowPath)
        );
    }
    for path in [
        "/var/lib/buzzci//workspaces/test",
        "/var/lib/buzzci/./workspaces/test",
        "/var/lib/buzzci/workspaces/test/",
    ] {
        let mut noncanonical = manifest_input();
        noncanonical.workspace.path = path.into();
        assert_eq!(
            compile(noncanonical),
            Err(ManifestCompileError::InvalidWorkspace)
        );
    }
}
