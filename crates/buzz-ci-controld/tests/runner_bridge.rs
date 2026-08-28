use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::io::{Cursor, Read, Write};
use std::rc::Rc;

use buzz_ci_controld::manifest::{
    compile_job_manifest, Ed25519ManifestSigner, JobManifestInput, ManifestCompileError,
    ManifestSigningError, WorkspaceIdentity, MANIFEST_SIGNATURE_DOMAIN,
};
use buzz_ci_controld::production::{
    AcceptedRequest, AttemptExecutor, JobMetadata, PreparedRunnerAttempt, RunnerAttemptExecutor,
    RunnerAttemptPreparer,
};
use buzz_ci_controld::runner_client::{
    prepare_runner_request, AttemptOutcome, FailureClass, PreparedRunnerRequest, RunnerClient,
    RunnerClientError, RunnerConnector, ValidatedRunnerResult, RECEIPT_SET_DIGEST_DOMAIN,
};
use buzz_core::ci::{CiRequestEnvelope, CiRequestType, CiSkipPolicy, CI_SCHEMA_VERSION};
use serde_json::{json, Value};
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

fn prepared() -> PreparedRunnerRequest {
    let request = request();
    let mut signer = CapturingSigner {
        private_marker: "SUPER-PRIVATE-ED25519-SIGNING-KEY",
        ..CapturingSigner::default()
    };
    let manifest = compile_job_manifest(
        &"ab".repeat(32),
        &"cd".repeat(32),
        &request,
        manifest_input(),
        &mut signer,
    )
    .expect("compile fixture manifest");
    prepare_runner_request(
        "123e4567-e89b-12d3-a456-426614174010".into(),
        "ab".repeat(32),
        request,
        "cd".repeat(32),
        11,
        40,
        vec![manifest],
    )
    .expect("prepare fixture request")
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

#[test]
fn runner_request_frame_is_exact_big_endian_and_has_no_signer_material() {
    let request = prepared();
    let length = u32::from_be_bytes(request.frame()[..4].try_into().expect("prefix")) as usize;
    assert_eq!(length, request.frame().len() - 4);
    let body = std::str::from_utf8(&request.frame()[4..]).expect("UTF-8 request");
    assert!(body.starts_with(
        r#"{"type":"execute_attempt","schema_version":1,"dispatch_id":"123e4567-e89b-12d3-a456-426614174010","request_event_id":"abab"#
    ));
    assert!(body.contains(
        r#""jobs":[{"job_id":"test","attempt":1,"parent_attempt":0,"workflow_path":".github/workflows/ci.yml","job_manifest":""#
    ));
    assert!(!body.contains("SUPER-PRIVATE-ED25519-SIGNING-KEY"));
    assert_eq!(
        request.frame_digest(),
        hex::encode(Sha256::digest(request.frame()))
    );
}

#[test]
fn runner_request_canonicalizes_jobs_to_the_accepted_request_order() {
    let mut request = request();
    request.job_ids.push("lint".into());
    let mut signer = CapturingSigner::default();
    let test = compile_job_manifest(
        &"ab".repeat(32),
        &"cd".repeat(32),
        &request,
        manifest_input(),
        &mut signer,
    )
    .expect("test manifest");
    let mut lint_input = manifest_input();
    lint_input.job_id = "lint".into();
    lint_input.lease_id = "01ARZ3NDEKTSV4RRFFQ69G5FAW".into();
    let lint = compile_job_manifest(
        &"ab".repeat(32),
        &"cd".repeat(32),
        &request,
        lint_input,
        &mut signer,
    )
    .expect("lint manifest");
    let prepared = prepare_runner_request(
        "123e4567-e89b-12d3-a456-426614174010".into(),
        "ab".repeat(32),
        request,
        "cd".repeat(32),
        11,
        40,
        vec![lint, test],
    )
    .expect("prepared request");
    let body: Value = serde_json::from_slice(&prepared.frame()[4..]).expect("request JSON");
    let job_ids: Vec<_> = body["jobs"]
        .as_array()
        .expect("jobs")
        .iter()
        .map(|job| job["job_id"].as_str().expect("job ID"))
        .collect();
    assert_eq!(job_ids, ["test", "lint"]);
}

fn framed(value: &Value) -> Vec<u8> {
    let body = serde_json::to_vec(value).expect("encode receipt fixture");
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);
    frame
}

fn receipt_identity(kind: &str, sequence: u64) -> Value {
    json!({
        "type": kind,
        "schema_version": 1,
        "dispatch_id": "123e4567-e89b-12d3-a456-426614174010",
        "request_event_id": "ab".repeat(32),
        "run_id": "123e4567-e89b-12d3-a456-426614174011",
        "attempt": 1,
        "receipt_sequence": sequence,
    })
}

fn insert(value: &mut Value, key: &str, field: Value) {
    value
        .as_object_mut()
        .expect("fixture object")
        .insert(key.into(), field);
}

fn completed_stream(accepted_at: u64) -> Vec<u8> {
    let mut accepted = receipt_identity("accepted", 1);
    insert(&mut accepted, "accepted_at", json!(accepted_at));

    let mut started = receipt_identity("job_started", 2);
    insert(&mut started, "job_id", json!("test"));
    insert(&mut started, "job_attempt", json!(1));
    insert(&mut started, "started_at", json!(12));

    let mut finished = receipt_identity("job_finished", 3);
    insert(&mut finished, "job_id", json!("test"));
    insert(&mut finished, "job_attempt", json!(1));
    insert(&mut finished, "state", json!("success"));
    insert(&mut finished, "started_at", json!(12));
    insert(&mut finished, "finished_at", json!(13));
    insert(
        &mut finished,
        "log",
        json!({
            "relative_path": "logs/test.log",
            "sha256": "de".repeat(32),
            "byte_length": 4,
            "cap_bytes": 4096,
            "truncated": false,
        }),
    );
    insert(&mut finished, "artifacts", json!([]));

    let prior = [framed(&accepted), framed(&started), framed(&finished)];
    let mut hasher = Sha256::new();
    hasher.update(RECEIPT_SET_DIGEST_DOMAIN);
    for frame in &prior {
        hasher.update(frame);
    }
    let digest = hex::encode(hasher.finalize());

    let request = request();
    let mut terminal = receipt_identity("attempt_finished", 4);
    insert(&mut terminal, "outcome", json!("completed"));
    insert(&mut terminal, "finished_at", json!(13));
    insert(
        &mut terminal,
        "selected_job_attempts",
        json!([{"job_id":"test","attempt":1}]),
    );
    insert(
        &mut terminal,
        "teardown_attestation",
        json!({
            "schema_version": 1,
            "request_event_id": "ab".repeat(32),
            "run_id": request.run_id,
            "workflow_id": request.workflow_id,
            "target_repo_a": request.target_repo_a,
            "tip_oid": request.tip_oid,
            "base_oid": request.base_oid,
            "workflow_digest": request.workflow_digest,
            "attempt": 1,
            "leases": [{"job_id":"test","attempt":1,"lease_id":LEASE_ID}],
            "lease_empty": true,
            "teardown_at": 13,
            "relay_signer": "ef".repeat(32),
        }),
    );
    insert(&mut terminal, "receipt_set_digest", json!(digest));

    prior
        .into_iter()
        .chain([framed(&terminal)])
        .flatten()
        .collect()
}

struct ScriptedConnection {
    input: Cursor<Vec<u8>>,
    writes: Rc<RefCell<Vec<Vec<u8>>>>,
    write_index: usize,
}

impl Read for ScriptedConnection {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.input.read(buffer)
    }
}

impl Write for ScriptedConnection {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.writes.borrow_mut()[self.write_index].extend_from_slice(buffer);
        Ok(buffer.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct ScriptedConnector {
    responses: VecDeque<Vec<u8>>,
    writes: Rc<RefCell<Vec<Vec<u8>>>>,
}

type WrittenFrames = Rc<RefCell<Vec<Vec<u8>>>>;

impl RunnerConnector for ScriptedConnector {
    type Connection = ScriptedConnection;
    type Error = ();
    fn connect(&mut self) -> Result<Self::Connection, ()> {
        let input = self.responses.pop_front().ok_or(())?;
        let write_index = self.writes.borrow().len();
        self.writes.borrow_mut().push(Vec::new());
        Ok(ScriptedConnection {
            input: Cursor::new(input),
            writes: self.writes.clone(),
            write_index,
        })
    }
}

fn client(
    responses: Vec<Vec<u8>>,
    attempts: u32,
) -> (RunnerClient<ScriptedConnector>, WrittenFrames) {
    let writes = Rc::new(RefCell::new(Vec::new()));
    let connector = ScriptedConnector {
        responses: responses.into(),
        writes: writes.clone(),
    };
    (
        RunnerClient::new(connector, attempts).expect("client"),
        writes,
    )
}

struct FixturePreparer(PreparedRunnerRequest);

impl RunnerAttemptPreparer for FixturePreparer {
    type Error = ();

    fn prepare(
        &mut self,
        _accepted: &AcceptedRequest,
    ) -> Result<PreparedRunnerAttempt, Self::Error> {
        PreparedRunnerAttempt::new(
            self.0.clone(),
            vec![JobMetadata {
                job_id: "test".into(),
                name: "Test".into(),
                required: true,
                skip_policy: CiSkipPolicy::Forbid,
                selected_job_instance: "test".into(),
                also_reruns: Vec::new(),
            }],
        )
        .map_err(|_| ())
    }
}

#[test]
fn production_attempt_executor_invokes_the_public_runner_bridge() {
    let prepared = prepared();
    let expected_frame = prepared.frame().to_vec();
    let (client, writes) = client(vec![completed_stream(11)], 1);
    let mut executor = RunnerAttemptExecutor::new(client, FixturePreparer(prepared));
    let accepted = AcceptedRequest {
        channel_id: "native-ci".into(),
        watch_cursor: 1,
        event_id: "ab".repeat(32),
        envelope: request(),
    };

    let completion = executor.execute(&accepted).expect("runner completion");

    assert_eq!(writes.borrow().as_slice(), &[expected_frame]);
    assert_eq!(completion.finished_at, 13);
    assert_eq!(completion.jobs.len(), 1);
    assert_eq!(completion.jobs[0].metadata.job_id, "test");
    assert_eq!(completion.jobs[0].log_cap_bytes, 4096);
    assert_eq!(completion.teardown.request_event_id, accepted.event_id);
}

#[test]
fn client_validates_terminal_receipts_retries_same_bytes_and_caches_idempotently() {
    let request = prepared();
    let full = completed_stream(11);
    let truncated = full[..25].to_vec();
    let (mut client, writes) = client(vec![truncated, full], 2);
    let result = client.execute(&request).expect("validated result");
    assert!(matches!(
        result,
        ValidatedRunnerResult::Finished(ref receipt)
            if receipt.outcome == AttemptOutcome::Completed
    ));
    assert_eq!(
        writes.borrow().as_slice(),
        &[request.frame().to_vec(), request.frame().to_vec()]
    );

    let cached = client.execute(&request).expect("cached terminal");
    assert_eq!(cached, result);
    assert_eq!(writes.borrow().len(), 2);
    let _connector = client.into_connector();
}

#[test]
fn client_rejects_divergent_replay_unknown_fields_bad_digests_and_truncation() {
    let request = prepared();
    let first = completed_stream(11);
    let accepted_length = 4 + u32::from_be_bytes(first[..4].try_into().expect("prefix")) as usize;
    let (mut replay_client, _) = client(
        vec![first[..accepted_length].to_vec(), completed_stream(12)],
        2,
    );
    assert_eq!(
        replay_client.execute(&request),
        Err(RunnerClientError::ReplayMismatch)
    );

    let mut unknown = completed_stream(11);
    let first_length = 4 + u32::from_be_bytes(unknown[..4].try_into().expect("prefix")) as usize;
    let second_length = 4 + u32::from_be_bytes(
        unknown[first_length..first_length + 4]
            .try_into()
            .expect("prefix"),
    ) as usize;
    let third_start = first_length + second_length;
    let third_length = u32::from_be_bytes(
        unknown[third_start..third_start + 4]
            .try_into()
            .expect("prefix"),
    ) as usize;
    let mut third: Value =
        serde_json::from_slice(&unknown[third_start + 4..third_start + 4 + third_length])
            .expect("third receipt");
    third["log"]["signing_key"] = json!("must-never-appear");
    unknown.splice(third_start..third_start + 4 + third_length, framed(&third));
    let (mut unknown_client, _) = client(vec![unknown], 1);
    assert_eq!(
        unknown_client.execute(&request),
        Err(RunnerClientError::NonCanonicalJson)
    );

    let mut bad_digest = completed_stream(11);
    let terminal_start = frame_starts(&bad_digest)[3];
    let terminal_length = u32::from_be_bytes(
        bad_digest[terminal_start..terminal_start + 4]
            .try_into()
            .expect("prefix"),
    ) as usize;
    let mut terminal: Value = serde_json::from_slice(
        &bad_digest[terminal_start + 4..terminal_start + 4 + terminal_length],
    )
    .expect("terminal");
    terminal["receipt_set_digest"] = json!("00".repeat(32));
    bad_digest.splice(terminal_start.., framed(&terminal));
    let (mut digest_client, _) = client(vec![bad_digest], 1);
    assert_eq!(
        digest_client.execute(&request),
        Err(RunnerClientError::ReceiptDigestMismatch)
    );

    let (mut truncated_client, _) = client(vec![vec![0, 0, 0, 20, b'{']], 1);
    assert_eq!(
        truncated_client.execute(&request),
        Err(RunnerClientError::RetryExhausted)
    );
    assert_eq!(
        RunnerClientError::RetryExhausted.failure_class(),
        FailureClass::RetrySameDispatch
    );

    let duplicate_body = format!(
        "{{\"type\":\"accepted\",\"schema_version\":1,\"dispatch_id\":\"123e4567-e89b-12d3-a456-426614174010\",\"request_event_id\":\"{}\",\"run_id\":\"123e4567-e89b-12d3-a456-426614174011\",\"attempt\":1,\"receipt_sequence\":1,\"accepted_at\":11,\"accepted_at\":11}}",
        "ab".repeat(32)
    );
    let mut duplicate = Vec::new();
    duplicate.extend_from_slice(&(duplicate_body.len() as u32).to_be_bytes());
    duplicate.extend_from_slice(duplicate_body.as_bytes());
    let (mut duplicate_client, _) = client(vec![duplicate], 1);
    assert_eq!(
        duplicate_client.execute(&request),
        Err(RunnerClientError::NonCanonicalJson)
    );

    let mut wrong_identity = completed_stream(11);
    let first_length = u32::from_be_bytes(wrong_identity[..4].try_into().expect("prefix")) as usize;
    let mut first_receipt: Value =
        serde_json::from_slice(&wrong_identity[4..4 + first_length]).expect("accepted receipt");
    first_receipt["dispatch_id"] = json!("123e4567-e89b-12d3-a456-426614174099");
    wrong_identity.splice(..4 + first_length, framed(&first_receipt));
    let (mut identity_client, _) = client(vec![wrong_identity], 1);
    assert_eq!(
        identity_client.execute(&request),
        Err(RunnerClientError::ReceiptMismatch)
    );
    assert_eq!(
        RunnerClientError::ReceiptMismatch.failure_class(),
        FailureClass::PermanentProtocolFailure
    );
}

fn frame_starts(stream: &[u8]) -> Vec<usize> {
    let mut starts = Vec::new();
    let mut offset = 0;
    while offset < stream.len() {
        starts.push(offset);
        let length =
            u32::from_be_bytes(stream[offset..offset + 4].try_into().expect("prefix")) as usize;
        offset += 4 + length;
    }
    starts
}

#[test]
fn client_rejects_truncated_output_descriptors() {
    let request = prepared();
    let mut stream = completed_stream(11);
    let third_start = frame_starts(&stream)[2];
    let third_length = u32::from_be_bytes(
        stream[third_start..third_start + 4]
            .try_into()
            .expect("prefix"),
    ) as usize;
    let mut third: Value =
        serde_json::from_slice(&stream[third_start + 4..third_start + 4 + third_length])
            .expect("third");
    third["log"]["truncated"] = json!(true);
    stream.splice(third_start..third_start + 4 + third_length, framed(&third));
    let (mut client, _) = client(vec![stream], 1);
    assert_eq!(
        client.execute(&request),
        Err(RunnerClientError::InvalidDescriptor)
    );
}
