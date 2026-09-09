//! Test-only broker v2 transport whose job is a real process.
//!
//! Admission spawns `/bin/sh -c 'sleep 300 & exec sleep 300'` in its own
//! process group, exactly as execd's executor handoff does. A cancellation
//! kills that group and reaps the child before the broker records the
//! terminal binding, and the evidence documents it serves pass the executor's
//! digest rules. Tests assert against the kernel: after a stop the group must
//! answer `ESRCH`.

use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use buzz_ci_broker_protocol::v2::{
    self, admission_signature_message, intent_registration_key_digest, AdmitAttemptRequest,
    BrokerResponse, EvidenceChunkResponse, EvidenceDescriptionResponse, EvidenceDescriptor,
    EvidenceKind, IntentRegistrationResponse, Request, WireText64,
};
use buzz_ci_broker_protocol::{BrokerState, CancelReason, Conclusion, ResponseCode};
use buzz_core::ci::{CiRequestEnvelope, CiRequestType, CI_SCHEMA_VERSION};
use nix::errno::Errno;
use nix::sys::signal::{kill, killpg, Signal};
use nix::unistd::Pid;
use sha2::{Digest, Sha256};

use crate::production::{AcceptedRequest, JobMetadata};
use crate::runner_v2::{
    AdmissionSigner, BoundAttempt, RunnerV2Transport, StaticAdmissionBindings,
    StaticArtifactBinding, TerminalAttempt,
};

pub(crate) const WORKFLOW_ID: &str = "native-ci";
pub(crate) const JOB_ID: &str = "test";

pub(crate) struct Signer;

impl AdmissionSigner for Signer {
    type Error = ();

    fn sign_admission(&mut self, request: &mut AdmitAttemptRequest) -> Result<(), Self::Error> {
        request.admission_signature = [0x77; 64];
        Ok(())
    }
}

pub(crate) fn bindings() -> StaticAdmissionBindings {
    StaticAdmissionBindings {
        audience_digest: [0x99; 32],
        isolation_profile_digest: [0xaa; 32],
        lane_manifest_digest: [0xbb; 32],
        lane_epoch: 7,
        admission_key_generation: 3,
        workflow_id: WORKFLOW_ID.into(),
        workflow_digest: [0x66; 32],
        job_ids: vec![JOB_ID.into()],
        artifacts: vec![StaticArtifactBinding {
            artifact_id: "result".into(),
            name: "result.json".into(),
            media_type: "application/json".into(),
            relative_name: "result.json".into(),
            max_bytes: 32 * 1024,
        }],
    }
}

pub(crate) fn job_metadata() -> JobMetadata {
    JobMetadata {
        job_id: JOB_ID.into(),
        name: "Test".into(),
        required: true,
        skip_policy: buzz_core::ci::CiSkipPolicy::Forbid,
        selected_job_instance: JOB_ID.into(),
        also_reruns: Vec::new(),
    }
}

/// One accepted initial request. `event_byte` and `run_byte` distinguish
/// requests; `branch` selects the concurrency group.
pub(crate) fn accepted(
    event_byte: u8,
    run_byte: u8,
    cursor: u64,
    branch: &str,
    timeout_seconds: u64,
) -> AcceptedRequest {
    let run_id = uuid::Uuid::from_bytes([run_byte; 16]).to_string();
    AcceptedRequest {
        channel_id: "123e4567-e89b-12d3-a456-426614174099".into(),
        watch_cursor: cursor,
        event_id: hex::encode([event_byte; 32]),
        envelope: CiRequestEnvelope {
            schema_version: CI_SCHEMA_VERSION,
            request_type: CiRequestType::Run,
            target_repo_a: format!("30617:{}:buzz", "22".repeat(32)),
            pr_root_event_id: "33".repeat(32),
            pr_update_event_id: None,
            source_clone_url: "https://relay.example/git/repo".into(),
            immutable_source_ref: "refs/nostr/source".into(),
            tip_oid: "44".repeat(20),
            source_branch: branch.into(),
            base_ref: "refs/heads/main".into(),
            base_oid: "55".repeat(20),
            workflow_id: WORKFLOW_ID.into(),
            workflow_digest: "66".repeat(32),
            job_ids: vec![JOB_ID.into()],
            run_id,
            attempt: 1,
            parent_attempt: None,
            parent_run_id: None,
            trigger_event_id: "33".repeat(32),
            actor: "88".repeat(32),
            timeout_seconds,
            idempotency_key: uuid::Uuid::from_bytes([event_byte; 16]).to_string(),
            issued_at: 10,
            expires_at: 40,
        },
    }
}

#[derive(Clone, Debug)]
struct Evidence {
    descriptors: Vec<EvidenceDescriptor>,
    bytes: Vec<Vec<u8>>,
    descriptor_set_digest: [u8; 32],
}

#[derive(Default)]
pub(crate) struct JobState {
    child: Option<Child>,
    /// Process group of the spawned job, kept after the child is reaped so a
    /// test can prove the whole group is gone.
    pub(crate) process_group: Option<i32>,
    pub(crate) active: Option<BoundAttempt>,
    terminal: Option<TerminalAttempt>,
    evidence: Option<Evidence>,
    /// Every cancellation reason received, in order.
    pub(crate) cancels: Vec<CancelReason>,
    /// Called once when a job is admitted; lets a relay fake reveal a later
    /// request only after the attempt is running.
    pub(crate) on_admit: Option<Box<dyn FnMut() + Send>>,
    /// Workflow and job identifiers taken from the registered intent, so the
    /// evidence documents name whatever the request named.
    workflow_id: String,
    job_id: String,
}

/// Broker transport shared between the executor and the test.
#[derive(Clone, Default)]
pub(crate) struct ProcessBroker(pub(crate) Arc<Mutex<JobState>>);

impl ProcessBroker {
    pub(crate) fn process_group(&self) -> i32 {
        self.0
            .lock()
            .unwrap()
            .process_group
            .expect("a job was admitted")
    }

    pub(crate) fn cancels(&self) -> Vec<CancelReason> {
        self.0.lock().unwrap().cancels.clone()
    }

    pub(crate) fn is_active(&self) -> bool {
        self.0.lock().unwrap().active.is_some()
    }
}

/// Whether any process in `group` still exists, judged by the kernel.
pub(crate) fn process_group_alive(group: i32) -> bool {
    match kill(Pid::from_raw(-group), None) {
        Ok(()) => true,
        Err(Errno::ESRCH) => false,
        Err(error) => panic!("unexpected probe error {error}"),
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn spawn_job() -> Child {
    Command::new("/bin/sh")
        .args(["-c", "sleep 300 & exec sleep 300"])
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn job")
}

fn stop_job(state: &mut JobState) {
    let group = state.process_group.expect("job group");
    let _ = killpg(Pid::from_raw(group), Signal::SIGKILL);
    if let Some(mut child) = state.child.take() {
        let _ = child.wait();
    }
    // The grandchild `sleep` shares the group; the kernel reaps it once
    // SIGKILL lands. Wait until the group answers ESRCH so the terminal
    // record never precedes the stop.
    for _ in 0..200 {
        if !process_group_alive(group) {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    panic!("job process group survived SIGKILL");
}

fn descriptor_set_digest(
    terminal: TerminalAttempt,
    descriptors: &[EvidenceDescriptor],
) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"buzz-ci-execd:evidence-descriptor-set:v2\0");
    bytes.extend_from_slice(&terminal.response.execution_binding_digest);
    for descriptor in descriptors {
        bytes.push(descriptor.kind as u8);
        bytes.extend_from_slice(&descriptor.digest);
        bytes.extend_from_slice(&descriptor.length.to_be_bytes());
        bytes.extend_from_slice(&descriptor.artifact_name_digest);
        bytes.extend_from_slice(&descriptor.artifact_media_type_digest);
        bytes.extend_from_slice(&descriptor.teardown_lease_id);
        bytes.extend_from_slice(&descriptor.teardown_lease_generation.to_be_bytes());
        bytes.extend_from_slice(&descriptor.teardown_attestation_digest);
        for text in [
            descriptor.artifact_id,
            descriptor.artifact_name,
            descriptor.artifact_media_type,
        ] {
            bytes.push(text.len);
            bytes.extend_from_slice(&text.bytes);
        }
    }
    Sha256::digest(bytes).into()
}

fn conclusion_name(conclusion: Conclusion) -> &'static str {
    match conclusion {
        Conclusion::Success => "success",
        Conclusion::Failure => "failure",
        Conclusion::Cancelled => "cancelled",
        Conclusion::TimedOut => "timed_out",
        Conclusion::None | Conclusion::InfrastructureFailure => "infrastructure_failure",
    }
}

/// Seal a stopped attempt: stdout and teardown only, as execd records for a
/// job it killed before any artifact existed.
fn stopped_terminal(
    active: BoundAttempt,
    conclusion: Conclusion,
    workflow_id: &str,
    job_id: &str,
) -> (TerminalAttempt, Evidence) {
    let stdout = serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "execution_binding_digest": hex::encode(active.response.execution_binding_digest),
        "conclusion": conclusion_name(conclusion),
        "output_sha256": hex::encode(Sha256::digest(b"x")),
        "output_length": 1,
        "output": "x",
    }))
    .unwrap();
    let stdout_digest: [u8; 32] = Sha256::digest(&stdout).into();
    let mut response = active.response;
    response.code = ResponseCode::Ok;
    response.broker_state = BrokerState::Terminal;
    response.conclusion = conclusion;
    response.generation += 1;
    response.updated_at = now().max(response.accepted_at);
    response.evidence_set_digest = stdout_digest;
    let mut terminal = TerminalAttempt {
        admission: active.admission,
        response,
    };
    let mut receipt_set = b"buzz-ci-execd:artifact-receipt-set:v1\0".to_vec();
    receipt_set.extend_from_slice(&response.execution_binding_digest);
    let teardown = serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "execution_binding_digest": hex::encode(response.execution_binding_digest),
        "evidence_set_digest": hex::encode(response.evidence_set_digest),
        "stop_reason": if conclusion == Conclusion::Cancelled { "cancelled" } else { "expired" },
        "executor_receipt_digest": "aa".repeat(32),
        "request_event_id": hex::encode(response.accepted_request_digest),
        "run_id": hex::encode(response.run_id),
        "workflow_id": workflow_id,
        "workflow_digest": hex::encode(active.admission.workflow_digest),
        "job_id": job_id,
        "attempt": active.admission.attempt,
        "lease_id": "bb".repeat(16),
        "lease_generation": response.lease_generation,
        "artifact_receipt_set_digest": hex::encode(Sha256::digest(receipt_set)),
    }))
    .unwrap();
    let teardown_digest: [u8; 32] = Sha256::digest(&teardown).into();
    terminal.response.teardown_digest = teardown_digest;
    let descriptors = vec![
        EvidenceDescriptor {
            kind: EvidenceKind::Stdout,
            digest: stdout_digest,
            length: stdout.len() as u32,
            artifact_name_digest: [0; 32],
            artifact_media_type_digest: [0; 32],
            artifact_id: WireText64::EMPTY,
            artifact_name: WireText64::EMPTY,
            artifact_media_type: WireText64::EMPTY,
            teardown_lease_id: [0; 16],
            teardown_lease_generation: 0,
            teardown_attestation_digest: [0; 32],
        },
        EvidenceDescriptor {
            kind: EvidenceKind::Teardown,
            digest: teardown_digest,
            length: teardown.len() as u32,
            artifact_name_digest: [0; 32],
            artifact_media_type_digest: [0; 32],
            artifact_id: WireText64::EMPTY,
            artifact_name: WireText64::EMPTY,
            artifact_media_type: WireText64::EMPTY,
            teardown_lease_id: [0xbb; 16],
            teardown_lease_generation: response.lease_generation,
            teardown_attestation_digest: teardown_digest,
        },
    ];
    let descriptor_set_digest = descriptor_set_digest(terminal, &descriptors);
    (
        terminal,
        Evidence {
            descriptors,
            bytes: vec![stdout, teardown],
            descriptor_set_digest,
        },
    )
}

impl RunnerV2Transport for ProcessBroker {
    type Error = ();

    fn exchange_frame(
        &mut self,
        request: &[u8],
        response_length: usize,
        _transport_attempts: u32,
    ) -> Result<Vec<u8>, Self::Error> {
        let (header, request) = v2::decode_request(request).unwrap();
        let mut state = self.0.lock().unwrap();
        let response = match request {
            Request::RegisterJobIntent(value) => {
                state.workflow_id = value.workflow_id.as_str().unwrap().to_owned();
                state.job_id = value.job_id.as_str().unwrap().to_owned();
                v2::encode_intent_registration_response(
                    header,
                    IntentRegistrationResponse {
                        code: ResponseCode::Ok,
                        retry_after_millis: 0,
                        signed_request_digest: value.admission.signed_request_digest,
                        job_intent_digest: value.admission.job_intent_digest,
                        request_frame_digest: value.request_frame_digest,
                        admission_message_digest: Sha256::digest(admission_signature_message(
                            &value.admission,
                        ))
                        .into(),
                        registration_key_digest: intent_registration_key_digest(&value),
                        lane_manifest_digest: value.admission.lane_manifest_digest,
                        run_id: value.admission.run_id,
                        lane_epoch: value.admission.lane_epoch,
                        admission_key_generation: value.admission.admission_key_generation,
                        issued_at: value.admission.issued_at,
                        expires_at: value.admission.expires_at,
                        attempt: value.admission.attempt,
                    },
                )
                .as_bytes()
                .to_vec()
            }
            Request::AdmitAttempt(admission) => {
                let response = if let Some(terminal) = state.terminal {
                    terminal.response
                } else if let Some(active) = state.active {
                    let mut response = active.response;
                    response.code = ResponseCode::Existing;
                    response
                } else {
                    let child = spawn_job();
                    state.process_group = Some(child.id() as i32);
                    state.child = Some(child);
                    let accepted_at = now();
                    let active = BoundAttempt {
                        admission,
                        response: BrokerResponse {
                            code: ResponseCode::Ok,
                            retry_after_millis: 0,
                            attempt_id: [admission.attempt as u8 + 1; 16],
                            run_id: admission.run_id,
                            accepted_request_digest: admission.signed_request_digest,
                            job_intent_digest: admission.job_intent_digest,
                            execution_binding_digest: [admission.attempt as u8 + 20; 32],
                            tip_oid: Some(admission.tip_oid),
                            broker_state: BrokerState::Leased,
                            conclusion: Conclusion::None,
                            terminal_reason: 0,
                            generation: 1,
                            accepted_at,
                            updated_at: accepted_at,
                            lease_generation: 1,
                            evidence_set_digest: [0; 32],
                            teardown_digest: [0; 32],
                            attempt: admission.attempt,
                        },
                    };
                    state.active = Some(active);
                    if let Some(hook) = state.on_admit.as_mut() {
                        hook();
                    }
                    active.response
                };
                v2::encode_response(header, response).as_bytes().to_vec()
            }
            Request::GetAttempt(_) => {
                let response = match state.terminal {
                    Some(terminal) => terminal.response,
                    None => {
                        let mut response = state.active.expect("admitted").response;
                        response.code = ResponseCode::Existing;
                        response
                    }
                };
                v2::encode_response(header, response).as_bytes().to_vec()
            }
            Request::CancelAttempt(cancel) => {
                state.cancels.push(cancel.reason);
                if state.terminal.is_none() {
                    stop_job(&mut state);
                    let active = state.active.expect("admitted");
                    let (workflow_id, job_id) = (state.workflow_id.clone(), state.job_id.clone());
                    let (terminal, evidence) =
                        stopped_terminal(active, Conclusion::Cancelled, &workflow_id, &job_id);
                    state.terminal = Some(terminal);
                    state.evidence = Some(evidence);
                }
                v2::encode_response(header, state.terminal.unwrap().response)
                    .as_bytes()
                    .to_vec()
            }
            Request::DescribeAttemptEvidence(value) => {
                let evidence = state.evidence.as_ref().expect("terminal evidence");
                let mut items = [None; v2::MAX_EVIDENCE_ITEMS];
                for (slot, descriptor) in items.iter_mut().zip(&evidence.descriptors) {
                    *slot = Some(*descriptor);
                }
                let coordinates = value.coordinates;
                v2::encode_evidence_description_response(
                    header,
                    EvidenceDescriptionResponse {
                        code: ResponseCode::Ok,
                        execution_binding_digest: coordinates.execution_binding_digest,
                        generation: coordinates.expected_generation,
                        request_frame_digest: value.request_frame_digest,
                        descriptor_set_digest: evidence.descriptor_set_digest,
                        item_count: evidence.descriptors.len() as u8,
                        items,
                        request_event_id: coordinates.request_event_id,
                        run_id: coordinates.run_id,
                        workflow_id: coordinates.workflow_id,
                        workflow_digest: coordinates.workflow_digest,
                        job_id: coordinates.job_id,
                        attempt: coordinates.attempt,
                    },
                )
                .as_bytes()
                .to_vec()
            }
            Request::ReadAttemptEvidence(value) => {
                let bytes = state.evidence.as_ref().expect("terminal evidence").bytes
                    [value.item_index as usize]
                    .clone();
                v2::encode_evidence_chunk_response(
                    header,
                    &EvidenceChunkResponse {
                        code: ResponseCode::Ok,
                        execution_binding_digest: value.coordinates.execution_binding_digest,
                        generation: value.coordinates.expected_generation,
                        request_frame_digest: value.request_frame_digest,
                        kind: value.kind,
                        item_index: value.item_index,
                        descriptor_digest: value.descriptor_digest,
                        offset: value.offset,
                        total_length: bytes.len() as u32,
                        bytes,
                        request_event_id: value.coordinates.request_event_id,
                        run_id: value.coordinates.run_id,
                        workflow_id: value.coordinates.workflow_id,
                        workflow_digest: value.coordinates.workflow_digest,
                        job_id: value.coordinates.job_id,
                        attempt: value.coordinates.attempt,
                    },
                )
                .as_bytes()
                .to_vec()
            }
            _ => unreachable!("unexpected broker request"),
        };
        assert_eq!(response.len(), response_length);
        Ok(response)
    }
}
