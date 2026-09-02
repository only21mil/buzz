//! Fail-closed daemon composition for dormant and capacity-one operation.

use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use buzz_ci_acceptance_ctl::acceptance::{
    AdmissionState, ApprovalSnapshot, AttemptSnapshot, AttemptState,
    Conclusion as AcceptanceConclusion, DriverResponse, ExportSnapshot, Operation, RunSnapshot,
    RunState, SystemSnapshot, DRIVER_VERSION,
};
use buzz_ci_acceptance_ctl::production::{
    AdapterRequest, AdapterResponse, ADAPTER_RESPONSE_SCHEMA,
};
use buzz_ci_broker_protocol::v2::CancelAttemptRequest;
use buzz_ci_broker_protocol::{
    BrokerState, CancelReason, Conclusion as BrokerConclusion, ResponseCode,
};
use buzz_ci_controld::acceptance_socket::{
    AcceptanceBinding, AcceptanceJournal, AcceptanceOperationHandler, AcceptanceSocketError,
};
use buzz_ci_controld::controller::{
    CapacityOneConfig, CapacityOneController, CapacityOneProviderSlots, CapacityOneStatus,
    ControllerError, TerminalInfrastructureReason,
};
use buzz_ci_controld::keyholder::{KeyholderError, UnixKeyholderClient};
use buzz_ci_controld::production::{JobMetadata, RelayControl, SignedCiEvent};
use buzz_ci_controld::production_v2::{
    compose_runner_v2, AttemptCommand, AttemptControl, AttemptObservation, ProductionV2Error,
    RunnerV2AttemptExecutor, RunnerV2EvidenceReader, VerifiedAttemptEvidence,
};
use buzz_ci_controld::runner_client::{UnixRunnerConnector, UnixRunnerConnectorError};
use buzz_ci_controld::runner_v2::{
    live_bound_now, BoundAttempt, RunnerV2Client, StaticAdmissionBindings, StaticArtifactBinding,
    TerminalAttempt,
};
use buzz_ci_controld::source::{AuthenticatedRelay, ReqwestTransport, SourceError, TransportError};
use buzz_ci_controld::store::{DurableControlStore, StoreError};
use buzz_ci_keyholder::{AcceptanceMutation, PublicIdentity};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

use crate::config::DaemonConfig;

/// A locally validated daemon which owns no production capability.
pub(crate) struct CapacityZeroService {
    status: CapacityOneStatus,
    _store: DurableControlStore,
    acceptance: Option<AcceptanceJournal>,
}

type ProductionRelay = AuthenticatedRelay<ReqwestTransport, UnixKeyholderClient>;
type ProductionExecutor = RunnerV2AttemptExecutor<UnixRunnerConnector, UnixKeyholderClient>;
type ProductionOutput = RunnerV2EvidenceReader<UnixRunnerConnector>;
type ProductionController = CapacityOneController<
    ProductionRelay,
    UnixKeyholderClient,
    ProductionExecutor,
    DurableControlStore,
    ProductionOutput,
>;

/// Fully composed capacity-one service. Every constructor performs its own
/// identity, endpoint, or persistence validation before the controller opens.
pub(crate) struct CapacityOneService {
    controller: Option<ProductionController>,
    controller_worker: Option<JoinHandle<(ProductionController, Result<(), ControllerError>)>>,
    observations: Receiver<AttemptObservation>,
    attempt_commands: Sender<AttemptCommand>,
    active_attempt: Option<BoundAttempt>,
    terminal_attempt: Option<TerminalAttempt>,
    verified_evidence: Option<VerifiedAttemptEvidence>,
    gate_waiting: bool,
    cancel_client: RunnerV2Client<UnixRunnerConnector>,
    acceptance_relay: ProductionRelay,
    acceptance_signer: UnixKeyholderClient,
    acceptance_authority: AcceptanceAuthority,
    status: CapacityOneStatus,
    poll_interval: Duration,
    acceptance: AcceptanceJournal,
}

#[derive(Clone, Debug)]
struct AcceptanceAuthority {
    actor: PublicIdentity,
    scenario_sha256: [u8; 32],
    event_ids: [[u8; 32]; 4],
    templates: [serde_json::Value; 4],
}

impl AcceptanceAuthority {
    fn new(binding: &AcceptanceBinding) -> Result<Self, ServiceError> {
        let validated = binding
            .validate()
            .map_err(|_| ServiceError::InvalidConfig)?;
        let config = &binding.acceptance;
        let actor = PublicIdentity {
            public_key: validated.actor_public_key(),
            generation: validated.actor_generation(),
        };
        let templates = [
            config.run_event.clone(),
            config.grant_event.clone(),
            config.rerun_event.clone(),
            config.tombstone_event.clone(),
        ];
        Ok(Self {
            actor,
            scenario_sha256: validated.scenario_sha256(),
            event_ids: validated.event_ids(),
            templates,
        })
    }

    const fn index(mutation: AcceptanceMutation) -> usize {
        match mutation {
            AcceptanceMutation::Run => 0,
            AcceptanceMutation::Grant => 1,
            AcceptanceMutation::Rerun => 2,
            AcceptanceMutation::Tombstone => 3,
        }
    }
}

impl CapacityZeroService {
    pub(crate) fn start(
        config: &DaemonConfig,
        expected_owner_uid: u32,
        acceptance_binding: Option<AcceptanceBinding>,
    ) -> Result<Self, ServiceError> {
        if config.capacity() != 0 {
            return Err(ServiceError::InvalidConfig);
        }
        let store = DurableControlStore::open(config.store_root(), expected_owner_uid)?;
        let acceptance = acceptance_journal(config, expected_owner_uid, acceptance_binding)?;
        Ok(Self {
            status: CapacityOneStatus::parked(),
            _store: store,
            acceptance,
        })
    }

    pub(crate) const fn status(&self) -> CapacityOneStatus {
        self.status
    }

    pub(crate) fn acceptance_credentials(&self) -> Option<(u32, u32, Duration)> {
        self.acceptance.as_ref().map(|journal| {
            (
                journal.acceptance_peer_uid(),
                journal.acceptance_peer_gid(),
                journal.timeout(),
            )
        })
    }

    /// Remain alive without polling, dispatching, networking, or signing.
    pub(crate) fn run(self) -> ! {
        loop {
            thread::park();
        }
    }
}

impl CapacityOneService {
    pub(crate) fn start(
        config: &DaemonConfig,
        expected_owner_uid: u32,
        acceptance_binding: Option<AcceptanceBinding>,
    ) -> Result<Self, ServiceError> {
        let active = config.active().ok_or(ServiceError::InvalidConfig)?;
        let binding = acceptance_binding
            .as_ref()
            .ok_or(ServiceError::InvalidConfig)?;
        let poll_interval = Duration::from_millis(active.poll_interval_millis);
        let controller_config = CapacityOneConfig::new(
            active.channel_id.clone(),
            poll_interval,
            active.runner_transport_attempts,
        )
        .map_err(|_| ServiceError::InvalidConfig)?;
        let cancel_connector = UnixRunnerConnector::new(active.runner.clone())?;
        let cancel_client = RunnerV2Client::new(cancel_connector, active.runner_transport_attempts)
            .map_err(|_| ServiceError::InvalidConfig)?;
        let runner = UnixRunnerConnector::new(active.runner.clone())?;
        let runner = RunnerV2Client::new(runner, active.runner_transport_attempts)
            .map_err(|_| ServiceError::InvalidConfig)?;
        let relay_authorizer = UnixKeyholderClient::connect(active.keyholder.clone())?;
        let relay_signer = UnixKeyholderClient::connect(active.keyholder.clone())?;
        let admission_signer = UnixKeyholderClient::connect(active.keyholder.clone())?;
        let acceptance_signer = UnixKeyholderClient::connect(active.keyholder.clone())?;
        let acceptance_authorizer = UnixKeyholderClient::connect(active.keyholder.clone())?;
        let relay_transport = ReqwestTransport::new(
            Duration::from_secs(5),
            Duration::from_secs(30),
            8 * 1024 * 1024,
        )?;
        let relay = AuthenticatedRelay::new(
            Url::parse(&active.relay_http_origin).map_err(|_| ServiceError::InvalidConfig)?,
            relay_transport,
            relay_authorizer,
        )?;
        let acceptance_transport = ReqwestTransport::new(
            Duration::from_secs(5),
            Duration::from_secs(30),
            8 * 1024 * 1024,
        )?;
        let acceptance_relay = AuthenticatedRelay::new(
            Url::parse(&active.relay_http_origin).map_err(|_| ServiceError::InvalidConfig)?,
            acceptance_transport,
            acceptance_authorizer,
        )?;
        let acceptance_authority = AcceptanceAuthority::new(binding)?;
        let described = acceptance_signer.describe_acceptance()?;
        if described.actor != acceptance_authority.actor
            || described.scenario_sha256 != acceptance_authority.scenario_sha256
            || described.event_ids != acceptance_authority.event_ids
        {
            return Err(ServiceError::InvalidConfig);
        }
        let bindings = StaticAdmissionBindings {
            audience_digest: decode_digest(&active.audience_digest)?,
            isolation_profile_digest: decode_digest(&active.isolation_profile_digest)?,
            lane_manifest_digest: decode_digest(&active.lane_manifest_digest)?,
            lane_epoch: active.lane_epoch,
            admission_key_generation: active.keyholder.keyholder_selectors.manifest.generation,
            workflow_id: active.workflow_id.clone(),
            workflow_digest: decode_digest(&active.workflow_digest)?,
            job_ids: active.jobs.iter().map(|job| job.job_id.clone()).collect(),
            artifacts: active.jobs[0]
                .artifacts
                .iter()
                .map(|artifact| StaticArtifactBinding {
                    artifact_id: artifact.artifact_id.clone(),
                    name: artifact.name.clone(),
                    media_type: artifact.media_type.clone(),
                    relative_name: artifact.relative_name.clone(),
                    max_bytes: artifact.max_bytes,
                })
                .collect(),
        };
        let job = active
            .jobs
            .first()
            .filter(|_| active.jobs.len() == 1)
            .ok_or(ServiceError::InvalidConfig)?;
        let metadata = JobMetadata {
            job_id: job.job_id.clone(),
            name: job.name.clone(),
            required: job.required,
            skip_policy: job.skip_policy,
            selected_job_instance: job.selected_job_instance.clone(),
            also_reruns: job.also_reruns.clone(),
        };
        let (observation_sender, observations) = mpsc::channel();
        let (attempt_commands, command_receiver) = mpsc::channel();
        let (executor, output) = compose_runner_v2(
            runner,
            admission_signer,
            bindings,
            metadata,
            active
                .keyholder
                .keyholder_selectors
                .ci_event
                .public_key
                .clone(),
            poll_interval,
            AttemptControl {
                observer: Some(observation_sender),
                command: Some(command_receiver),
            },
        )?;
        let store = DurableControlStore::open(config.store_root(), expected_owner_uid)?;
        let controller = CapacityOneController::activate(
            controller_config,
            CapacityOneProviderSlots::new(
                Some(relay),
                Some(relay_signer),
                Some(executor),
                Some(store),
                Some(output),
            ),
        )
        .map_err(|_| ServiceError::InvalidConfig)?;
        if binding.scenario_sha256 != hex::encode(acceptance_authority.scenario_sha256)
            || binding.fixture.grant_event_id != hex::encode(acceptance_authority.event_ids[1])
        {
            return Err(ServiceError::InvalidConfig);
        }
        let acceptance = acceptance_journal(config, expected_owner_uid, acceptance_binding)?
            .ok_or(ServiceError::InvalidConfig)?;
        Ok(Self {
            status: controller.status(),
            controller: Some(controller),
            controller_worker: None,
            observations,
            attempt_commands,
            active_attempt: None,
            terminal_attempt: None,
            verified_evidence: None,
            gate_waiting: false,
            cancel_client,
            acceptance_relay,
            acceptance_signer,
            acceptance_authority,
            poll_interval,
            acceptance,
        })
    }

    pub(crate) const fn status(&self) -> CapacityOneStatus {
        self.status
    }

    pub(crate) fn acceptance_credentials(&self) -> (u32, u32, Duration) {
        (
            self.acceptance.acceptance_peer_uid(),
            self.acceptance.acceptance_peer_gid(),
            self.acceptance.timeout(),
        )
    }

    /// Process one request at a time. Any ambiguous provider failure emits a
    /// terminal closed readback and returns so systemd can restart into durable
    /// reconciliation.
    pub(crate) fn poll_once(&mut self) -> Result<(), ControllerError> {
        if self.controller_worker.is_some() {
            return Ok(());
        }
        let controller = self
            .controller
            .as_mut()
            .ok_or(ControllerError::Infrastructure(
                TerminalInfrastructureReason::State,
            ))?;
        let result = controller.poll_once().map(|_| ());
        self.status = controller.status();
        result
    }

    pub(crate) const fn poll_interval(&self) -> Duration {
        self.poll_interval
    }

    fn begin_async_attempt(&mut self) -> Result<BoundAttempt, AcceptanceSocketError> {
        if let Some(active) = self.active_attempt {
            return Ok(active);
        }
        if self.controller_worker.is_some() {
            return Err(AcceptanceSocketError::Operation);
        }
        while self.observations.try_recv().is_ok() {}
        let mut controller = self
            .controller
            .take()
            .ok_or(AcceptanceSocketError::Operation)?;
        self.status = CapacityOneStatus::active_attempt();
        self.controller_worker = Some(thread::spawn(move || {
            let result = controller.poll_once().map(|_| ());
            (controller, result)
        }));
        match self.observations.recv_timeout(self.acceptance.timeout()) {
            Ok(AttemptObservation::Active(active)) => {
                self.active_attempt = Some(active);
                self.gate_waiting = true;
                Ok(active)
            }
            Ok(AttemptObservation::Terminal(terminal)) => {
                let recovered = BoundAttempt {
                    admission: terminal.admission,
                    response: terminal.response,
                };
                self.active_attempt = Some(recovered);
                self.terminal_attempt = Some(terminal);
                Ok(recovered)
            }
            Ok(AttemptObservation::Completed(_)) => self.fail_async_attempt(),
            Err(_) => self.fail_async_attempt(),
        }
    }

    fn release_async_attempt(&mut self) -> Result<(), AcceptanceSocketError> {
        if self.gate_waiting {
            self.attempt_commands
                .send(AttemptCommand::Continue)
                .map_err(|_| AcceptanceSocketError::Operation)?;
            self.gate_waiting = false;
        }
        Ok(())
    }

    fn finish_async_attempt(
        &mut self,
    ) -> Result<(TerminalAttempt, VerifiedAttemptEvidence), AcceptanceSocketError> {
        if self.controller_worker.is_none() {
            self.begin_async_attempt()?;
            self.release_async_attempt()?;
        }
        let worker = self
            .controller_worker
            .take()
            .ok_or(AcceptanceSocketError::Operation)?;
        let (controller, result) = worker
            .join()
            .map_err(|_| AcceptanceSocketError::Operation)?;
        self.status = controller.status();
        self.controller = Some(controller);
        result.map_err(|_| AcceptanceSocketError::Operation)?;
        let terminal = self.terminal_attempt.take().or_else(|| {
            let mut terminal = None;
            while let Ok(observation) = self.observations.try_recv() {
                match observation {
                    AttemptObservation::Active(active) => self.active_attempt = Some(active),
                    AttemptObservation::Terminal(observed) => terminal = Some(observed),
                    AttemptObservation::Completed(evidence) => {
                        self.verified_evidence = Some(evidence)
                    }
                }
            }
            terminal
        });
        let terminal = terminal.ok_or(AcceptanceSocketError::Operation)?;
        let evidence = self
            .verified_evidence
            .take()
            .filter(|evidence| evidence.terminal == terminal)
            .ok_or(AcceptanceSocketError::Operation)?;
        self.active_attempt = None;
        self.gate_waiting = false;
        Ok((terminal, evidence))
    }

    fn fail_async_attempt<T>(&mut self) -> Result<T, AcceptanceSocketError> {
        self.status = CapacityOneStatus::startup_failure(TerminalInfrastructureReason::State);
        Err(AcceptanceSocketError::Operation)
    }
}

impl AcceptanceOperationHandler for CapacityZeroService {
    type Error = AcceptanceSocketError;

    fn handle(
        &mut self,
        request: &AdapterRequest,
        exact_request: &[u8],
    ) -> Result<AdapterResponse, Self::Error> {
        let journal = self
            .acceptance
            .as_ref()
            .ok_or(AcceptanceSocketError::Activation)?;
        journal.execute(request, exact_request, 0, |prior| match request.operation {
            Operation::ObserveInitial if request.sequence == 1 => {
                Ok(host_response(request, None, 0))
            }
            Operation::SetCapacityZero if request.sequence == 13 => {
                Ok(host_response(request, prior, 0))
            }
            _ => Err(AcceptanceSocketError::Operation),
        })
    }
}

impl AcceptanceOperationHandler for CapacityOneService {
    type Error = AcceptanceSocketError;

    fn handle(
        &mut self,
        request: &AdapterRequest,
        exact_request: &[u8],
    ) -> Result<AdapterResponse, Self::Error> {
        let configured_capacity = self.status.configured_capacity();
        let journal = self.acceptance.clone();
        journal.execute(request, exact_request, configured_capacity, |prior| match (
            request.sequence,
            request.operation,
        ) {
            (2, Operation::SetCapacityOne)
            | (11, Operation::RestartController)
            | (12, Operation::RestartRunner) => {
                Ok(host_response(request, prior, configured_capacity))
            }
            (3, Operation::SubmitManifest) => {
                self.publish_acceptance(AcceptanceMutation::Run)?;
                Ok(submitted_response(request))
            }
            (4, Operation::ApproveGrant) => {
                self.publish_acceptance(AcceptanceMutation::Grant)?;
                Ok(approved_response(request))
            }
            (5, Operation::ResumeGrant) => {
                let active = self.begin_async_attempt()?;
                Ok(running_response(request, prior, active, false)?)
            }
            (6, Operation::AwaitFirstTerminal) => {
                let (terminal, evidence) = self.finish_async_attempt()?;
                Ok(first_terminal_response(
                    request, prior, terminal, &evidence,
                )?)
            }
            (7, Operation::ExportFirstEvidence) => Ok(export_response(request, prior)?),
            (8, Operation::Rerun) => {
                self.publish_acceptance(AcceptanceMutation::Rerun)?;
                let active = self.begin_async_attempt()?;
                Ok(running_response(request, prior, active, true)?)
            }
            (9, Operation::CancelRerun) => {
                let active = self
                    .active_attempt
                    .or_else(|| self.begin_async_attempt().ok())
                    .ok_or(AcceptanceSocketError::Operation)?;
                let cancelled = self.cancel_active_attempt(request, active)?;
                self.release_async_attempt()?;
                let (reconciled, _) = self.finish_async_attempt()?;
                if !same_terminal_binding(cancelled, reconciled) {
                    return Err(AcceptanceSocketError::Operation);
                }
                Ok(cancelled_response(request, prior, cancelled)?)
            }
            (10, Operation::TombstoneRerun) => {
                self.publish_acceptance(AcceptanceMutation::Tombstone)?;
                Ok(tombstoned_response(request, prior)?)
            }
            _ => Err(AcceptanceSocketError::Operation),
        })
    }

    fn response_written(&mut self, request: &AdapterRequest) -> Result<(), Self::Error> {
        if request.sequence == 5 && request.operation == Operation::ResumeGrant {
            self.release_async_attempt()?;
        }
        Ok(())
    }
}

impl CapacityOneService {
    fn publish_acceptance(
        &mut self,
        mutation: AcceptanceMutation,
    ) -> Result<(), AcceptanceSocketError> {
        let index = AcceptanceAuthority::index(mutation);
        let event_id = self.acceptance_authority.event_ids[index];
        let signature = self
            .acceptance_signer
            .sign_acceptance_mutation(
                self.acceptance_authority.actor,
                self.acceptance_authority.scenario_sha256,
                mutation,
                event_id,
            )
            .map_err(|_| AcceptanceSocketError::Operation)?;
        let fields = self.acceptance_authority.templates[index]
            .as_array()
            .ok_or(AcceptanceSocketError::Operation)?;
        let created_at = fields[2].as_u64().ok_or(AcceptanceSocketError::Operation)?;
        let kind = u32::try_from(fields[3].as_u64().ok_or(AcceptanceSocketError::Operation)?)
            .map_err(|_| AcceptanceSocketError::Operation)?;
        let content = fields[5]
            .as_str()
            .ok_or(AcceptanceSocketError::Operation)?
            .to_owned();
        let tags = fields[4].clone();
        let event_id_hex = hex::encode(event_id);
        let signed = SignedCiEvent {
            event_id: event_id_hex.clone(),
            kind,
            content: content.clone(),
            tags: tags.clone(),
            signed_event: serde_json::json!({
                "id": event_id_hex,
                "pubkey": hex::encode(signature.identity.public_key),
                "created_at": created_at,
                "kind": kind,
                "tags": tags,
                "content": content,
                "sig": hex::encode(signature.signature),
            }),
        };
        let accepted = self
            .acceptance_relay
            .publish(&signed)
            .map_err(|_| AcceptanceSocketError::Operation)?;
        if accepted != signed.event_id {
            return Err(AcceptanceSocketError::Operation);
        }
        Ok(())
    }

    fn cancel_active_attempt(
        &mut self,
        request: &AdapterRequest,
        active: BoundAttempt,
    ) -> Result<TerminalAttempt, AcceptanceSocketError> {
        // The frozen window is judged against the package time reference by
        // the runner and execd; the live bound is the attempt's deadline on
        // the host clock (`live_bound_now`).
        let now = live_bound_now().map_err(|_| AcceptanceSocketError::Operation)?;
        let deadline_at = active
            .deadline_at()
            .map_err(|_| AcceptanceSocketError::Operation)?;
        if now == 0 || now >= deadline_at {
            return Err(AcceptanceSocketError::Operation);
        }
        if active.response.broker_state == BrokerState::Terminal {
            let terminal = TerminalAttempt {
                admission: active.admission,
                response: active.response,
            };
            validate_cancelled_terminal(active, terminal, false)?;
            return Ok(terminal);
        }
        let mut cancel = CancelAttemptRequest {
            attempt_id: active.response.attempt_id,
            execution_binding_digest: active.response.execution_binding_digest,
            actor_pubkey: active.admission.actor_pubkey,
            cancel_digest: [0; 32],
            issued_at: active.admission.issued_at,
            expires_at: active.admission.expires_at,
            expected_generation: active.response.generation,
            reason: CancelReason::UserRequest,
        };
        cancel.cancel_digest = acceptance_cancel_digest(request, &cancel);
        let response = self
            .cancel_client
            .cancel(cancel)
            .map_err(|_| AcceptanceSocketError::Operation)?;
        let terminal = TerminalAttempt {
            admission: active.admission,
            response,
        };
        validate_cancelled_terminal(active, terminal, true)?;
        Ok(terminal)
    }
}

/// The cancellation answer (execd answers a stop with `Ok`) and the worker's
/// reconciled read of the same closed binding (a state read answers
/// `Existing`) describe one terminal binding; every bound field must agree,
/// the wire code and retry hint are the transport's, not the binding's.
fn same_terminal_binding(cancelled: TerminalAttempt, reconciled: TerminalAttempt) -> bool {
    let mut normalized = reconciled.response;
    normalized.code = cancelled.response.code;
    normalized.retry_after_millis = cancelled.response.retry_after_millis;
    matches!(
        cancelled.response.code,
        ResponseCode::Ok | ResponseCode::Existing
    ) && matches!(
        reconciled.response.code,
        ResponseCode::Ok | ResponseCode::Existing
    ) && cancelled.admission == reconciled.admission
        && cancelled.response == normalized
}

fn validate_cancelled_terminal(
    active: BoundAttempt,
    terminal: TerminalAttempt,
    require_later_generation: bool,
) -> Result<(), AcceptanceSocketError> {
    let response = terminal.response;
    if !matches!(response.code, ResponseCode::Ok | ResponseCode::Existing)
        || response.attempt_id != active.response.attempt_id
        || response.run_id != active.admission.run_id
        || response.accepted_request_digest != active.admission.signed_request_digest
        || response.job_intent_digest != active.admission.job_intent_digest
        || response.execution_binding_digest != active.response.execution_binding_digest
        || response.tip_oid != Some(active.admission.tip_oid)
        || response.attempt != active.admission.attempt
        || (require_later_generation && response.generation <= active.response.generation)
        || response.broker_state != BrokerState::Terminal
        || response.conclusion != BrokerConclusion::Cancelled
        || response.evidence_set_digest == [0; 32]
        || response.teardown_digest == [0; 32]
    {
        return Err(AcceptanceSocketError::Operation);
    }
    Ok(())
}

fn acceptance_journal(
    config: &DaemonConfig,
    expected_owner_uid: u32,
    binding: Option<AcceptanceBinding>,
) -> Result<Option<AcceptanceJournal>, ServiceError> {
    if config.acceptance_binding().is_none() {
        if binding.is_some() {
            return Err(ServiceError::InvalidConfig);
        }
        return Ok(None);
    }
    let binding = binding.ok_or(ServiceError::InvalidConfig)?;
    Ok(Some(AcceptanceJournal::open(
        config.store_root(),
        expected_owner_uid,
        binding,
    )?))
}

fn host_response(
    request: &AdapterRequest,
    prior: Option<&AdapterResponse>,
    capacity: u32,
) -> AdapterResponse {
    let mut snapshot = prior.map_or(
        SystemSnapshot {
            capacity,
            admission: if capacity == 1 {
                AdmissionState::Open
            } else {
                AdmissionState::Closed
            },
            active_run_count: 0,
            active_attempt_count: 0,
            controller_generation: request.host.controller_generation,
            runner_generation: request.host.runner_generation,
            run: None,
        },
        |prior| prior.response.snapshot.clone(),
    );
    snapshot.capacity = capacity;
    snapshot.admission = if capacity == 1 {
        AdmissionState::Open
    } else {
        AdmissionState::Closed
    };
    snapshot.controller_generation = request.host.controller_generation;
    snapshot.runner_generation = request.host.runner_generation;
    AdapterResponse {
        schema_version: ADAPTER_RESPONSE_SCHEMA.to_owned(),
        sequence: request.sequence,
        operation: request.operation,
        scenario_sha256: request.scenario_sha256.clone(),
        operation_id: request.operation_id.clone(),
        response: DriverResponse {
            schema_version: DRIVER_VERSION.to_owned(),
            sequence: request.sequence,
            operation: request.operation,
            snapshot,
            export: None,
        },
    }
}

fn submitted_response(request: &AdapterRequest) -> AdapterResponse {
    acceptance_response(
        request,
        run_snapshot(
            request,
            RunState::AwaitingApproval,
            AcceptanceConclusion::None,
            None,
            None,
            Vec::new(),
        ),
        0,
        None,
    )
}

fn approved_response(request: &AdapterRequest) -> AdapterResponse {
    acceptance_response(
        request,
        run_snapshot(
            request,
            RunState::GrantedAwaitingResume,
            AcceptanceConclusion::None,
            Some(approval_snapshot(request, false)),
            None,
            Vec::new(),
        ),
        0,
        None,
    )
}

fn running_response(
    request: &AdapterRequest,
    prior: Option<&AdapterResponse>,
    active: BoundAttempt,
    rerun: bool,
) -> Result<AdapterResponse, AcceptanceSocketError> {
    let attempt_id = hex::encode(active.response.attempt_id);
    if active.admission.attempt != if rerun { 2 } else { 1 }
        || active.response.broker_state == BrokerState::Terminal
    {
        return Err(AcceptanceSocketError::Operation);
    }
    // The driver names the attempt it reruns at sequence 8 (the first
    // attempt, the only id it holds); the new attempt's id exists only in
    // this response. Sequence 5 carries no attempt id, so the first attempt
    // accepts none or its own.
    let (mut attempts, parent_attempt_id) = if rerun {
        let parent = first_attempt_id(prior)?;
        if parent.is_none() || request.attempt_id != parent {
            return Err(AcceptanceSocketError::Operation);
        }
        (prior_run(prior)?.attempts.clone(), parent)
    } else {
        if request
            .attempt_id
            .as_deref()
            .is_some_and(|value| value != attempt_id)
        {
            return Err(AcceptanceSocketError::Operation);
        }
        (Vec::new(), None)
    };
    attempts.push(attempt_snapshot(
        request,
        attempt_id,
        active.admission.attempt,
        parent_attempt_id,
        AttemptState::Running,
        AcceptanceConclusion::None,
        None,
    ));
    Ok(acceptance_response(
        request,
        run_snapshot(
            request,
            RunState::Running,
            AcceptanceConclusion::None,
            Some(approval_snapshot(request, true)),
            None,
            attempts,
        ),
        1,
        None,
    ))
}

fn first_terminal_response(
    request: &AdapterRequest,
    prior: Option<&AdapterResponse>,
    terminal: TerminalAttempt,
    evidence: &VerifiedAttemptEvidence,
) -> Result<AdapterResponse, AcceptanceSocketError> {
    if terminal.admission.attempt != 1
        || terminal.response.broker_state != BrokerState::Terminal
        || terminal.response.conclusion != BrokerConclusion::Success
        || terminal.response.evidence_set_digest == [0; 32]
        || terminal.response.teardown_digest == [0; 32]
        || evidence.terminal != terminal
        || evidence.descriptor_set_digest == [0; 32]
        || evidence.log_sha256 != request.fixture.expected_log.sha256
        || evidence.log_bytes != request.fixture.expected_log.bytes
        || evidence.artifacts.len() != request.fixture.expected_artifacts.len()
        || evidence
            .artifacts
            .iter()
            .zip(&request.fixture.expected_artifacts)
            .any(|(actual, expected)| {
                actual.name != expected.name
                    || actual.sha256 != expected.sha256
                    || actual.bytes != expected.bytes
            })
    {
        return Err(AcceptanceSocketError::Operation);
    }
    let running = prior_run(prior)?;
    let attempt_id = hex::encode(terminal.response.attempt_id);
    if running.attempts.len() != 1 || running.attempts[0].attempt_id != attempt_id {
        return Err(AcceptanceSocketError::Operation);
    }
    let attempt = attempt_snapshot(
        request,
        attempt_id.clone(),
        1,
        None,
        AttemptState::Terminal,
        AcceptanceConclusion::Success,
        Some(hex::encode(evidence.descriptor_set_digest)),
    );
    Ok(acceptance_response(
        request,
        run_snapshot(
            request,
            RunState::Terminal,
            AcceptanceConclusion::Success,
            Some(approval_snapshot(request, true)),
            Some(attempt_id),
            vec![attempt],
        ),
        0,
        None,
    ))
}

fn export_response(
    request: &AdapterRequest,
    prior: Option<&AdapterResponse>,
) -> Result<AdapterResponse, AcceptanceSocketError> {
    let run = prior_run(prior)?.clone();
    let selected = run
        .selected_attempt_id
        .clone()
        .ok_or(AcceptanceSocketError::Operation)?;
    if request.attempt_id.as_deref() != Some(selected.as_str()) {
        return Err(AcceptanceSocketError::Operation);
    }
    let attempt = run
        .attempts
        .iter()
        .find(|attempt| attempt.attempt_id == selected)
        .ok_or(AcceptanceSocketError::Operation)?;
    let evidence_set_digest = attempt
        .evidence_set_digest
        .clone()
        .ok_or(AcceptanceSocketError::Operation)?;
    let mut objects = Vec::with_capacity(1 + request.fixture.expected_artifacts.len());
    objects.push(request.fixture.expected_log.clone());
    objects.extend(request.fixture.expected_artifacts.clone());
    Ok(acceptance_response(
        request,
        run,
        0,
        Some(ExportSnapshot {
            authenticated: true,
            subject: request.fixture.export_subject.clone(),
            authorization_digest: request.fixture.export_authorization_digest.clone(),
            attempt_id: selected,
            request_digest: request.fixture.request_digest.clone(),
            manifest_digest: request.fixture.manifest_digest.clone(),
            evidence_set_digest,
            objects,
        }),
    ))
}

fn cancelled_response(
    request: &AdapterRequest,
    prior: Option<&AdapterResponse>,
    terminal: TerminalAttempt,
) -> Result<AdapterResponse, AcceptanceSocketError> {
    let prior_run = prior_run(prior)?;
    if prior_run.attempts.len() != 2 || terminal.admission.attempt != 2 {
        return Err(AcceptanceSocketError::Operation);
    }
    let first = prior_run.attempts[0].clone();
    let second_id = hex::encode(terminal.response.attempt_id);
    if prior_run.attempts[1].attempt_id != second_id
        || request.attempt_id.as_deref() != Some(second_id.as_str())
    {
        return Err(AcceptanceSocketError::Operation);
    }
    let second = attempt_snapshot(
        request,
        second_id.clone(),
        2,
        Some(first.attempt_id.clone()),
        AttemptState::Terminal,
        AcceptanceConclusion::Cancelled,
        None,
    );
    Ok(acceptance_response(
        request,
        run_snapshot(
            request,
            RunState::Terminal,
            AcceptanceConclusion::Cancelled,
            Some(approval_snapshot(request, true)),
            Some(second_id),
            vec![first, second],
        ),
        0,
        None,
    ))
}

fn tombstoned_response(
    request: &AdapterRequest,
    prior: Option<&AdapterResponse>,
) -> Result<AdapterResponse, AcceptanceSocketError> {
    let prior_run = prior_run(prior)?;
    if prior_run.attempts.len() != 2 {
        return Err(AcceptanceSocketError::Operation);
    }
    let first = prior_run.attempts[0].clone();
    let mut second = prior_run.attempts[1].clone();
    if request.attempt_id.as_deref() != Some(second.attempt_id.as_str()) {
        return Err(AcceptanceSocketError::Operation);
    }
    second.state = AttemptState::Tombstoned;
    Ok(acceptance_response(
        request,
        run_snapshot(
            request,
            RunState::Terminal,
            AcceptanceConclusion::Success,
            Some(approval_snapshot(request, true)),
            Some(first.attempt_id.clone()),
            vec![first, second],
        ),
        0,
        None,
    ))
}

fn acceptance_response(
    request: &AdapterRequest,
    run: RunSnapshot,
    active: u32,
    export: Option<ExportSnapshot>,
) -> AdapterResponse {
    AdapterResponse {
        schema_version: ADAPTER_RESPONSE_SCHEMA.to_owned(),
        sequence: request.sequence,
        operation: request.operation,
        scenario_sha256: request.scenario_sha256.clone(),
        operation_id: request.operation_id.clone(),
        response: DriverResponse {
            schema_version: DRIVER_VERSION.to_owned(),
            sequence: request.sequence,
            operation: request.operation,
            snapshot: SystemSnapshot {
                capacity: 1,
                admission: AdmissionState::Open,
                active_run_count: active,
                active_attempt_count: active,
                controller_generation: request.host.controller_generation,
                runner_generation: request.host.runner_generation,
                run: Some(run),
            },
            export,
        },
    }
}

fn run_snapshot(
    request: &AdapterRequest,
    state: RunState,
    aggregate_conclusion: AcceptanceConclusion,
    approval: Option<ApprovalSnapshot>,
    selected_attempt_id: Option<String>,
    attempts: Vec<AttemptSnapshot>,
) -> RunSnapshot {
    RunSnapshot {
        run_id: request.fixture.run_id.clone(),
        integrated_candidate_sha: request.fixture.integrated_candidate_sha.clone(),
        request_digest: request.fixture.request_digest.clone(),
        manifest_digest: request.fixture.manifest_digest.clone(),
        source_oid: request.fixture.source_oid.clone(),
        state,
        aggregate_conclusion,
        approval,
        selected_attempt_id,
        attempts,
    }
}

fn approval_snapshot(request: &AdapterRequest, resumed: bool) -> ApprovalSnapshot {
    ApprovalSnapshot {
        approval_id: request.fixture.approval_id.clone(),
        grant_event_id: request.fixture.grant_event_id.clone(),
        grant_digest: request.fixture.grant_digest.clone(),
        approved_by: request.fixture.approved_by.clone(),
        resumed,
    }
}

fn attempt_snapshot(
    request: &AdapterRequest,
    attempt_id: String,
    attempt: u32,
    parent_attempt_id: Option<String>,
    state: AttemptState,
    conclusion: AcceptanceConclusion,
    evidence_set_digest: Option<String>,
) -> AttemptSnapshot {
    let terminal_success = conclusion == AcceptanceConclusion::Success;
    AttemptSnapshot {
        attempt_id,
        attempt,
        parent_attempt_id,
        state,
        conclusion,
        integrated_candidate_sha: request.fixture.integrated_candidate_sha.clone(),
        request_digest: request.fixture.request_digest.clone(),
        manifest_digest: request.fixture.manifest_digest.clone(),
        source_oid: request.fixture.source_oid.clone(),
        evidence_set_digest,
        log: terminal_success.then(|| request.fixture.expected_log.clone()),
        artifacts: if terminal_success {
            request.fixture.expected_artifacts.clone()
        } else {
            Vec::new()
        },
    }
}

fn prior_run(prior: Option<&AdapterResponse>) -> Result<&RunSnapshot, AcceptanceSocketError> {
    prior
        .and_then(|response| response.response.snapshot.run.as_ref())
        .ok_or(AcceptanceSocketError::Operation)
}

fn first_attempt_id(
    prior: Option<&AdapterResponse>,
) -> Result<Option<String>, AcceptanceSocketError> {
    let run = prior_run(prior)?;
    if run.attempts.len() != 1 {
        return Err(AcceptanceSocketError::Operation);
    }
    Ok(Some(run.attempts[0].attempt_id.clone()))
}

fn acceptance_cancel_digest(request: &AdapterRequest, cancel: &CancelAttemptRequest) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"buzz-ci-controld:acceptance-cancel:v1\0")
        .chain_update(request.scenario_sha256.as_bytes())
        .chain_update(request.operation_id.as_bytes())
        .chain_update(cancel.attempt_id)
        .chain_update(cancel.execution_binding_digest)
        .chain_update(cancel.expected_generation.to_be_bytes())
        .chain_update(cancel.issued_at.to_be_bytes())
        .chain_update(cancel.expires_at.to_be_bytes())
        .chain_update((cancel.reason as u16).to_be_bytes())
        .finalize()
        .into()
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum ServiceError {
    #[error("durable control store validation failed")]
    Store(#[from] StoreError),
    #[error("capacity-one service configuration is invalid")]
    InvalidConfig,
    #[error("runner control provider is unavailable")]
    Runner(#[from] UnixRunnerConnectorError),
    #[error("keyholder provider is unavailable")]
    Keyholder(#[from] KeyholderError),
    #[error("relay HTTP provider is unavailable")]
    RelayTransport(#[from] TransportError),
    #[error("relay control provider is invalid")]
    Relay(#[from] SourceError),
    #[error("runner v2 production bridge is invalid")]
    RunnerV2(#[from] ProductionV2Error),
    #[error("acceptance activation provider is invalid")]
    Acceptance(#[from] AcceptanceSocketError),
}

impl ServiceError {
    pub(crate) const fn terminal_reason(&self) -> TerminalInfrastructureReason {
        match self {
            Self::Store(_) => TerminalInfrastructureReason::Store,
            Self::InvalidConfig => TerminalInfrastructureReason::InvalidInput,
            Self::Runner(_) | Self::RunnerV2(_) => TerminalInfrastructureReason::Runner,
            Self::Keyholder(_) => TerminalInfrastructureReason::Signer,
            Self::RelayTransport(_) | Self::Relay(_) => TerminalInfrastructureReason::Relay,
            Self::Acceptance(_) => TerminalInfrastructureReason::InvalidInput,
        }
    }
}

fn decode_digest(value: &str) -> Result<[u8; 32], ServiceError> {
    hex::decode(value)
        .map_err(|_| ServiceError::InvalidConfig)?
        .try_into()
        .map_err(|_| ServiceError::InvalidConfig)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use buzz_ci_acceptance_ctl::acceptance_binding_test_support::canonical_acceptance_binding;
    use buzz_ci_acceptance_ctl::production::{ControlReadback, ADAPTER_REQUEST_SCHEMA};
    use buzz_ci_broker_protocol::v2::{AdmissionSignatureAlgorithm, AdmitAttemptRequest};
    use buzz_ci_broker_protocol::{GitOid, TrustClass};
    use tempfile::TempDir;

    use super::*;
    use crate::config::DaemonConfig;
    use buzz_ci_controld::acceptance_socket::ACCEPTANCE_BINDING_PATH;

    fn config_fixture(store_mode: u32) -> (TempDir, DaemonConfig, u32) {
        let root = tempfile::tempdir().expect("temporary directory");
        let store = root.path().join("store");
        fs::create_dir(&store).expect("create store");
        fs::set_permissions(&store, fs::Permissions::from_mode(store_mode))
            .expect("set store mode");
        let owner_uid = fs::metadata(&store).expect("store metadata").uid();
        let config: DaemonConfig = serde_json::from_value(serde_json::json!({
            "schema_version": 2,
            "capacity": 0,
            "store_root": store,
            "acceptance_binding": ACCEPTANCE_BINDING_PATH,
        }))
        .expect("configuration fixture");
        (root, config, owner_uid)
    }

    #[test]
    fn reports_ready_but_closed_after_store_validation() {
        let (_root, config, owner_uid) = config_fixture(0o700);

        let service =
            CapacityZeroService::start(&config, owner_uid, Some(canonical_acceptance_binding()))
                .expect("service starts");
        let status = serde_json::to_value(service.status()).expect("serialize status");

        assert_eq!(
            status,
            serde_json::json!({
                "schema_version": 2,
                "state": "parked",
                "configured_capacity": 0,
                "available_capacity": 0,
                "in_flight": 0,
                "terminal_reason": null,
            })
        );
    }

    #[test]
    fn refuses_an_insecure_store() {
        let (_root, config, owner_uid) = config_fixture(0o750);

        assert_eq!(
            CapacityZeroService::start(&config, owner_uid, None).map(|service| service.status()),
            Err(ServiceError::Store(StoreError::InsecureMetadata))
        );
    }

    fn active_binding() -> BoundAttempt {
        BoundAttempt {
            admission: AdmitAttemptRequest {
                signed_request_digest: [1; 32],
                actor_pubkey: [2; 32],
                audience_digest: [3; 32],
                idempotency_digest: [4; 32],
                source_pin_event_id: [5; 32],
                workflow_digest: [6; 32],
                job_intent_digest: [7; 32],
                isolation_profile_digest: [8; 32],
                lane_manifest_digest: [9; 32],
                admission_signature: [10; 64],
                run_id: [11; 16],
                tip_oid: GitOid::Sha1([12; 20]),
                base_oid: GitOid::Sha1([13; 20]),
                issued_at: 100,
                expires_at: 200,
                lane_epoch: 1,
                admission_key_generation: 2,
                wall_timeout_seconds: 30,
                attempt: 2,
                parent_attempt: 1,
                trust_class: TrustClass::AcceptedReviewed,
                admission_signature_algorithm: AdmissionSignatureAlgorithm::Bip340Secp256k1Sha256,
            },
            response: buzz_ci_broker_protocol::v2::BrokerResponse {
                code: ResponseCode::Ok,
                retry_after_millis: 0,
                attempt_id: [14; 16],
                run_id: [11; 16],
                accepted_request_digest: [1; 32],
                job_intent_digest: [7; 32],
                execution_binding_digest: [15; 32],
                tip_oid: Some(GitOid::Sha1([12; 20])),
                broker_state: BrokerState::Leased,
                conclusion: BrokerConclusion::None,
                terminal_reason: 0,
                generation: 3,
                accepted_at: 101,
                updated_at: 101,
                lease_generation: 1,
                evidence_set_digest: [0; 32],
                teardown_digest: [0; 32],
                attempt: 2,
            },
        }
    }

    fn rerun_request(attempt_id: Option<&str>) -> AdapterRequest {
        let binding = canonical_acceptance_binding();
        AdapterRequest {
            schema_version: ADAPTER_REQUEST_SCHEMA.to_owned(),
            sequence: 8,
            operation: Operation::Rerun,
            scenario_sha256: binding.scenario_sha256.clone(),
            operation_id: "operation".to_owned(),
            fixture: binding.fixture.clone(),
            attempt_id: attempt_id.map(str::to_owned),
            expected_controller_generation: Some(1),
            expected_runner_generation: Some(1),
            host: ControlReadback {
                activation_id: binding.activation_id.clone(),
                activation_package_digest: binding.activation_package_digest.clone(),
                integrated_candidate_sha: binding.fixture.integrated_candidate_sha.clone(),
                capacity: 1,
                admission: AdmissionState::Open,
                controller_generation: 1,
                runner_generation: 1,
            },
        }
    }

    /// H9 clean host, canary stage 8 (rerun_separation): the driver sent the
    /// first attempt's id (the attempt it reruns, the only id it holds) and
    /// controld compared it with the new attempt's id, failed the operation,
    /// and exited closed. The rerun response binds the request to the first
    /// attempt and reports the second as running under it.
    #[test]
    fn rerun_running_response_binds_the_request_to_the_first_attempt_it_reruns() {
        let active = active_binding();
        let second_id = hex::encode(active.response.attempt_id);
        let first_id = "0123456789abcdef0123456789abcdef".to_owned();
        let mut exported = rerun_request(Some(&first_id));
        exported.sequence = 7;
        exported.operation = Operation::ExportFirstEvidence;
        let prior = acceptance_response(
            &exported,
            run_snapshot(
                &exported,
                RunState::Terminal,
                AcceptanceConclusion::Success,
                Some(approval_snapshot(&exported, true)),
                Some(first_id.clone()),
                vec![attempt_snapshot(
                    &exported,
                    first_id.clone(),
                    1,
                    None,
                    AttemptState::Terminal,
                    AcceptanceConclusion::Success,
                    Some("11".repeat(32)),
                )],
            ),
            0,
            None,
        );

        let response =
            running_response(&rerun_request(Some(&first_id)), Some(&prior), active, true)
                .expect("rerun bound to the first attempt");
        let run = response.response.snapshot.run.expect("run snapshot");
        assert_eq!(run.state, RunState::Running);
        assert_eq!(run.aggregate_conclusion, AcceptanceConclusion::None);
        assert_eq!(run.attempts.len(), 2);
        assert_eq!(run.attempts[0].attempt_id, first_id);
        assert_eq!(run.attempts[0].state, AttemptState::Terminal);
        assert_eq!(run.attempts[1].attempt_id, second_id);
        assert_eq!(run.attempts[1].attempt, 2);
        assert_eq!(
            run.attempts[1].parent_attempt_id.as_deref(),
            Some(first_id.as_str())
        );
        assert_eq!(run.attempts[1].state, AttemptState::Running);
        assert_eq!(run.attempts[1].conclusion, AcceptanceConclusion::None);

        for foreign in [
            None,
            Some(second_id.as_str()),
            Some("ffffffffffffffffffffffffffffffff"),
        ] {
            assert_eq!(
                running_response(&rerun_request(foreign), Some(&prior), active, true).map(|_| ()),
                Err(AcceptanceSocketError::Operation),
                "request attempt id {foreign:?}"
            );
        }
        assert_eq!(
            running_response(&rerun_request(Some(&first_id)), None, active, true).map(|_| ()),
            Err(AcceptanceSocketError::Operation)
        );
        // The first attempt (sequence 5) still carries no id or its own.
        let mut first = active;
        first.admission.attempt = 1;
        first.admission.parent_attempt = 0;
        first.response.attempt = 1;
        let mut resume = rerun_request(None);
        resume.sequence = 5;
        resume.operation = Operation::ResumeGrant;
        let response =
            running_response(&resume, None, first, false).expect("first attempt running");
        assert_eq!(
            response.response.snapshot.run.expect("run").attempts.len(),
            1
        );
        resume.attempt_id = Some(first_id.clone());
        assert_eq!(
            running_response(&resume, None, first, false).map(|_| ()),
            Err(AcceptanceSocketError::Operation)
        );
    }

    /// H10 clean host, boot 6: the cancel answered `Ok` with the closed
    /// binding, the worker's GetAttempt read of the same binding answered
    /// `Existing`, and stage 9 compared the two whole responses and failed
    /// closed. The reconciliation binds every field but the wire code.
    #[test]
    fn cancel_reconciliation_binds_the_closed_binding_not_the_wire_code() {
        let active = active_binding();
        let mut response = active.response;
        response.broker_state = BrokerState::Terminal;
        response.conclusion = BrokerConclusion::Cancelled;
        response.generation += 3;
        response.updated_at += 1;
        response.evidence_set_digest = [16; 32];
        response.teardown_digest = [17; 32];
        let cancelled = TerminalAttempt {
            admission: active.admission,
            response,
        };
        assert_eq!(validate_cancelled_terminal(active, cancelled, true), Ok(()));
        let mut read = cancelled;
        read.response.code = ResponseCode::Existing;
        assert_ne!(read, cancelled);
        assert!(same_terminal_binding(cancelled, read));
        assert!(same_terminal_binding(cancelled, cancelled));
        let mut later = read;
        later.response.generation += 1;
        assert!(!same_terminal_binding(cancelled, later));
        let mut other_evidence = read;
        other_evidence.response.evidence_set_digest[0] ^= 1;
        assert!(!same_terminal_binding(cancelled, other_evidence));
        let mut other_conclusion = read;
        other_conclusion.response.conclusion = BrokerConclusion::Success;
        assert!(!same_terminal_binding(cancelled, other_conclusion));
        let mut refused = read;
        refused.response.code = ResponseCode::PolicyDenied;
        assert!(!same_terminal_binding(cancelled, refused));
        let mut other_admission = read;
        other_admission.admission.attempt = 1;
        assert!(!same_terminal_binding(cancelled, other_admission));
    }

    #[test]
    fn cancellation_reconciliation_accepts_only_the_exact_recovered_terminal_binding() {
        let active = active_binding();
        let mut response = active.response;
        response.code = ResponseCode::Existing;
        response.broker_state = BrokerState::Terminal;
        response.conclusion = BrokerConclusion::Cancelled;
        response.generation += 1;
        response.updated_at += 1;
        response.evidence_set_digest = [16; 32];
        response.teardown_digest = [17; 32];
        let terminal = TerminalAttempt {
            admission: active.admission,
            response,
        };

        assert_eq!(validate_cancelled_terminal(active, terminal, true), Ok(()));
        let recovered = BoundAttempt {
            admission: terminal.admission,
            response: terminal.response,
        };
        assert_eq!(
            validate_cancelled_terminal(recovered, terminal, false),
            Ok(())
        );
        let mut drift = terminal;
        drift.response.execution_binding_digest[0] ^= 1;
        assert_eq!(
            validate_cancelled_terminal(recovered, drift, false),
            Err(AcceptanceSocketError::Operation)
        );
    }
}
