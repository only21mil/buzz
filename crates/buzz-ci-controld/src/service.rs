//! Fail-closed daemon composition for dormant and capacity-one operation.

use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use buzz_ci_acceptance_ctl::acceptance::{
    AdmissionState, ApprovalSnapshot, AttemptSnapshot, AttemptState,
    Conclusion as AcceptanceConclusion, DriverResponse, ExportSnapshot, Operation, RunSnapshot,
    RunState, SystemSnapshot, ACCEPTANCE_STAGE_COUNT, DRIVER_VERSION,
};
use buzz_ci_acceptance_ctl::production::{
    AdapterRequest, AdapterResponse, ADAPTER_RESPONSE_SCHEMA,
};
use buzz_ci_broker_protocol::v2::{AdmitAttemptRequest, BrokerResponse, CancelAttemptRequest};
use buzz_ci_broker_protocol::{
    BrokerState, CancelReason, Conclusion as BrokerConclusion, GitOid, ResponseCode,
};
use buzz_ci_controld::acceptance_socket::{
    AcceptanceBinding, AcceptanceExecution, AcceptanceJournal, AcceptanceOperationHandler,
    AcceptanceSocketError,
};
use buzz_ci_controld::controller::{
    CapacityOneConfig, CapacityOneController, CapacityOneProviderSlots, CapacityOneStatus,
    ControllerError, TerminalInfrastructureReason,
};
use buzz_ci_controld::keyholder::{KeyholderError, UnixKeyholderClient};
use buzz_ci_controld::production::{
    AcceptedRequest, AcceptedRequestBinding, AttemptExecutor, AuthenticatedEvidenceExport,
    CiSigner, ControlStore, EvidenceReader, JobMetadata, RelayControl, SignedCiEvent,
};
use buzz_ci_controld::production_v2::{
    compose_runner_v2, AttemptCommand, AttemptControl, AttemptObservation, ProductionV2Error,
    RunnerV2AttemptExecutor, RunnerV2EvidenceReader, VerifiedAttemptEvidence,
};
use buzz_ci_controld::runner_client::{UnixRunnerConnector, UnixRunnerConnectorError};
use buzz_ci_controld::runner_v2::{
    live_bound_now, BoundAttempt, RunnerV2Client, RunnerV2Transport, StaticAdmissionBindings,
    StaticArtifactBinding, TerminalAttempt,
};
use buzz_ci_controld::source::{AuthenticatedRelay, ReqwestTransport, SourceError, TransportError};
use buzz_ci_controld::store::{DurableControlStore, StoreError};
use buzz_ci_keyholder::{AcceptanceMutation, PublicIdentity};
use buzz_core::ci::CiRequestEnvelope;
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

use crate::config::DaemonConfig;

/// Scenario sequence of `Operation::ApproveGrant`, the step that publishes the
/// activation's kind-46107 grant. Until the ledger records it, a pending
/// publication whose replay the relay refuses as an unauthorized status signer
/// is deferred rather than terminal (the M12 canary failed because the stale
/// terminal replay ran before this step and the grant needed the same key).
const APPROVE_GRANT_SEQUENCE: u32 = 4;
// The qualification socket owns relay polling through its final operation.
// Persistent capacity one starts later against the completed journal.
const COMPLETE_ACCEPTANCE_SEQUENCE: u32 = ACCEPTANCE_STAGE_COUNT;

const fn background_polling_enabled(completed_sequences: u32) -> bool {
    completed_sequences >= COMPLETE_ACCEPTANCE_SEQUENCE
}

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
pub(crate) struct CapacityOneService<
    C = ProductionController,
    T = UnixRunnerConnector,
    X = ProductionExecutor,
    R = ProductionRelay,
    S = UnixKeyholderClient,
> {
    controller: Option<C>,
    controller_worker: Option<JoinHandle<(C, Result<(), ControllerError>)>>,
    observations: Receiver<AttemptObservation>,
    attempt_commands: Sender<AttemptCommand>,
    active_attempt: Option<BoundAttempt>,
    terminal_attempt: Option<TerminalAttempt>,
    verified_evidence: Option<VerifiedAttemptEvidence>,
    gate_waiting: bool,
    cancel_client: RunnerV2Client<T>,
    recovery_executor: X,
    recovery_observations: Receiver<AttemptObservation>,
    acceptance_channel_id: String,
    acceptance_relay: R,
    acceptance_signer: S,
    acceptance_authority: AcceptanceAuthority,
    status: CapacityOneStatus,
    poll_interval: Duration,
    acceptance: AcceptanceJournal,
    background_polling: bool,
    #[cfg(test)]
    crash_before_provider_effect: bool,
    #[cfg(test)]
    crash_after_provider_effect: bool,
}

#[derive(Clone, Debug)]
struct AcceptanceAuthority {
    actor: PublicIdentity,
    scenario_sha256: [u8; 32],
    event_ids: [[u8; 32]; 5],
    templates: [serde_json::Value; 5],
    request_bindings: [AcceptedRequestBinding; 3],
}

enum RecoveryAttempt {
    Active(Box<BoundAttempt>),
    Terminal(Box<(TerminalAttempt, VerifiedAttemptEvidence)>),
    NoObservation,
}

trait AcceptanceRecoveryProvider {
    fn poll_recovery(
        &mut self,
        mutation: AcceptanceMutation,
    ) -> Result<RecoveryAttempt, AcceptanceSocketError>;
    fn release_active(&mut self) -> Result<(), AcceptanceSocketError>;
    fn finish_active(
        &mut self,
        mutation: AcceptanceMutation,
    ) -> Result<(TerminalAttempt, VerifiedAttemptEvidence), AcceptanceSocketError>;
    fn reconstruct_terminal(
        &mut self,
        mutation: AcceptanceMutation,
    ) -> Result<(TerminalAttempt, VerifiedAttemptEvidence), AcceptanceSocketError>;
    fn cancel_active(
        &mut self,
        request: &AdapterRequest,
        active: BoundAttempt,
    ) -> Result<TerminalAttempt, AcceptanceSocketError>;
    fn cancel_fresh(
        &mut self,
        request: &AdapterRequest,
    ) -> Result<TerminalAttempt, AcceptanceSocketError>;
}

pub(crate) trait ServiceController: Send + 'static {
    fn service_status(&self) -> CapacityOneStatus;
    fn service_poll_once(&mut self) -> Result<(), ControllerError>;
    fn service_poll_bound(
        &mut self,
        expected: &AcceptedRequestBinding,
    ) -> Result<(), ControllerError>;
    fn service_set_replay_deferral(&mut self, enabled: bool);
    fn service_replay_deferred_publications_bound(
        &mut self,
        expected: &AcceptedRequestBinding,
    ) -> Result<(), ControllerError>;
    fn service_export_first_evidence(
        &mut self,
        expected: &AcceptedRequestBinding,
        job_id: &str,
        attempt: u32,
    ) -> Result<AuthenticatedEvidenceExport, ControllerError>;
}

impl<R, S, X, P, O> ServiceController for CapacityOneController<R, S, X, P, O>
where
    R: RelayControl + Send + 'static,
    S: CiSigner + Send + 'static,
    X: AttemptExecutor + Send + 'static,
    P: ControlStore + Send + 'static,
    O: EvidenceReader + Send + 'static,
{
    fn service_status(&self) -> CapacityOneStatus {
        self.status()
    }

    fn service_poll_once(&mut self) -> Result<(), ControllerError> {
        self.poll_once().map(|_| ())
    }

    fn service_poll_bound(
        &mut self,
        expected: &AcceptedRequestBinding,
    ) -> Result<(), ControllerError> {
        self.poll_once_bound(expected).map(|_| ())
    }

    fn service_set_replay_deferral(&mut self, enabled: bool) {
        self.set_replay_deferral(enabled);
    }

    fn service_replay_deferred_publications_bound(
        &mut self,
        expected: &AcceptedRequestBinding,
    ) -> Result<(), ControllerError> {
        self.replay_deferred_publications_bound(expected)
            .map(|_| ())
    }

    fn service_export_first_evidence(
        &mut self,
        expected: &AcceptedRequestBinding,
        job_id: &str,
        attempt: u32,
    ) -> Result<AuthenticatedEvidenceExport, ControllerError> {
        self.export_first_evidence(expected, job_id, attempt)
    }
}

pub(crate) trait AcceptanceMutationSigner {
    fn sign_mutation(
        &mut self,
        actor: PublicIdentity,
        scenario_sha256: [u8; 32],
        mutation: AcceptanceMutation,
        event_id: [u8; 32],
    ) -> Result<buzz_ci_keyholder::SignatureResponse, ()>;
}

impl AcceptanceMutationSigner for UnixKeyholderClient {
    fn sign_mutation(
        &mut self,
        actor: PublicIdentity,
        scenario_sha256: [u8; 32],
        mutation: AcceptanceMutation,
        event_id: [u8; 32],
    ) -> Result<buzz_ci_keyholder::SignatureResponse, ()> {
        self.sign_acceptance_mutation(actor, scenario_sha256, mutation, event_id)
            .map_err(|_| ())
    }
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
            config.failure_run_event.clone(),
        ];
        let request_bindings = [
            Self::request_binding(&templates[0], validated.event_ids()[0])?,
            Self::request_binding(&templates[4], validated.event_ids()[4])?,
            Self::request_binding(&templates[2], validated.event_ids()[2])?,
        ];
        Ok(Self {
            actor,
            scenario_sha256: validated.scenario_sha256(),
            event_ids: validated.event_ids(),
            templates,
            request_bindings,
        })
    }

    const fn index(mutation: AcceptanceMutation) -> usize {
        match mutation {
            AcceptanceMutation::Run => 0,
            AcceptanceMutation::Grant => 1,
            AcceptanceMutation::Rerun => 2,
            AcceptanceMutation::Tombstone => 3,
            AcceptanceMutation::FailureRun => 4,
        }
    }

    fn expected_request(
        &self,
        mutation: AcceptanceMutation,
    ) -> Result<AcceptedRequestBinding, AcceptanceSocketError> {
        let index = match mutation {
            AcceptanceMutation::Run => 0,
            AcceptanceMutation::FailureRun => 1,
            AcceptanceMutation::Rerun => 2,
            AcceptanceMutation::Grant | AcceptanceMutation::Tombstone => {
                return Err(AcceptanceSocketError::Operation)
            }
        };
        Ok(self.request_bindings[index].clone())
    }

    fn request_binding(
        template: &serde_json::Value,
        event_id: [u8; 32],
    ) -> Result<AcceptedRequestBinding, ServiceError> {
        let fields = template.as_array().ok_or(ServiceError::InvalidConfig)?;
        let tags = fields
            .get(4)
            .and_then(serde_json::Value::as_array)
            .ok_or(ServiceError::InvalidConfig)?;
        let mut channels = tags.iter().filter_map(|tag| {
            let tag = tag.as_array()?;
            (tag.first()?.as_str()? == "h")
                .then(|| tag.get(1)?.as_str())
                .flatten()
        });
        let channel_id = channels
            .next()
            .filter(|_| channels.next().is_none())
            .ok_or(ServiceError::InvalidConfig)?
            .to_owned();
        let envelope = serde_json::from_str::<CiRequestEnvelope>(
            fields
                .get(5)
                .and_then(serde_json::Value::as_str)
                .ok_or(ServiceError::InvalidConfig)?,
        )
        .map_err(|_| ServiceError::InvalidConfig)?;
        Ok(AcceptedRequestBinding {
            channel_id,
            event_id: hex::encode(event_id),
            envelope,
        })
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
        let recovery_runner = UnixRunnerConnector::new(active.runner.clone())?;
        let recovery_runner =
            RunnerV2Client::new(recovery_runner, active.runner_transport_attempts)
                .map_err(|_| ServiceError::InvalidConfig)?;
        let relay_authorizer = UnixKeyholderClient::connect(active.keyholder.clone())?;
        let relay_signer = UnixKeyholderClient::connect(active.keyholder.clone())?;
        let admission_signer = UnixKeyholderClient::connect(active.keyholder.clone())?;
        let recovery_admission_signer = UnixKeyholderClient::connect(active.keyholder.clone())?;
        let acceptance_signer = UnixKeyholderClient::connect(active.keyholder.clone())?;
        let mut acceptance_authorizer = UnixKeyholderClient::connect(active.keyholder.clone())?;
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
        let acceptance_authority = AcceptanceAuthority::new(binding)?;
        if acceptance_authority
            .request_bindings
            .iter()
            .any(|expected| expected.channel_id != active.channel_id)
        {
            return Err(ServiceError::InvalidConfig);
        }
        let described = acceptance_signer.describe_acceptance()?;
        if described.actor != acceptance_authority.actor
            || described.scenario_sha256 != acceptance_authority.scenario_sha256
            || described.event_ids != acceptance_authority.event_ids
        {
            return Err(ServiceError::InvalidConfig);
        }
        // The acceptance publisher signs its NIP-98 tokens with the actor that
        // signed the frozen events (relay rule: token pubkey equals event
        // pubkey); bind that actor only after the keyholder described it.
        acceptance_authorizer
            .bind_acceptance_actor(acceptance_authority.actor)
            .map_err(|_| ServiceError::InvalidConfig)?;
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
        let (recovery_observation_sender, recovery_observations) = mpsc::channel();
        let (executor, output) = compose_runner_v2(
            runner,
            admission_signer,
            bindings.clone(),
            metadata.clone(),
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
        let (recovery_executor, _recovery_output) = compose_runner_v2(
            recovery_runner,
            recovery_admission_signer,
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
                observer: Some(recovery_observation_sender),
                command: None,
            },
        )?;
        let store = DurableControlStore::open(config.store_root(), expected_owner_uid)?;
        let mut controller = CapacityOneController::activate(
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
        // Startup replays pending publications before the acceptance protocol
        // can approve this activation's grant. Defer unauthorized-signer
        // refusals until that approval; after it (including a restart later in
        // the same activation) they stay terminal.
        let completed_sequences = acceptance.completed_sequences()?;
        let grant_approved = completed_sequences >= APPROVE_GRANT_SEQUENCE;
        let background_polling = background_polling_enabled(completed_sequences);
        controller.set_replay_deferral(!grant_approved);
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
            recovery_executor,
            recovery_observations,
            acceptance_channel_id: active.channel_id.clone(),
            acceptance_relay,
            acceptance_signer,
            acceptance_authority,
            poll_interval,
            acceptance,
            background_polling,
            #[cfg(test)]
            crash_before_provider_effect: false,
            #[cfg(test)]
            crash_after_provider_effect: false,
        })
    }
}

impl<C, T, X, R, S> CapacityOneService<C, T, X, R, S>
where
    C: ServiceController,
    T: RunnerV2Transport,
    X: AttemptExecutor,
    R: RelayControl,
    S: AcceptanceMutationSigner,
{
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
        if !self.background_polling {
            return Ok(());
        }
        if self.controller_worker.is_some() {
            return Ok(());
        }
        let controller = self
            .controller
            .as_mut()
            .ok_or(ControllerError::Infrastructure(
                TerminalInfrastructureReason::State,
            ))?;
        let result = controller.service_poll_once();
        self.status = controller.service_status();
        result
    }

    pub(crate) const fn poll_interval(&self) -> Duration {
        self.poll_interval
    }

    fn start_async_attempt(
        &mut self,
        mutation: AcceptanceMutation,
    ) -> Result<AcceptedRequestBinding, AcceptanceSocketError> {
        if self.controller_worker.is_some() {
            return Err(AcceptanceSocketError::Operation);
        }
        while self.observations.try_recv().is_ok() {}
        let mut controller = self
            .controller
            .take()
            .ok_or(AcceptanceSocketError::Operation)?;
        let expected = self.acceptance_authority.expected_request(mutation)?;
        let polled_expected = expected.clone();
        self.status = CapacityOneStatus::active_attempt();
        self.controller_worker = Some(thread::spawn(move || {
            let result = controller.service_poll_bound(&polled_expected);
            (controller, result)
        }));
        Ok(expected)
    }

    fn begin_async_attempt(
        &mut self,
        mutation: AcceptanceMutation,
    ) -> Result<BoundAttempt, AcceptanceSocketError> {
        if let Some(active) = self.active_attempt {
            return Ok(active);
        }
        let expected = self.start_async_attempt(mutation)?;
        match self.observations.recv_timeout(self.acceptance.timeout()) {
            Ok(AttemptObservation::Active(active))
                if observed_admission_matches(&expected, active.admission, active.response) =>
            {
                self.active_attempt = Some(active);
                self.gate_waiting = true;
                Ok(active)
            }
            Ok(AttemptObservation::Terminal(terminal))
                if observed_admission_matches(&expected, terminal.admission, terminal.response) =>
            {
                let recovered = BoundAttempt {
                    admission: terminal.admission,
                    response: terminal.response,
                };
                self.active_attempt = Some(recovered);
                self.terminal_attempt = Some(terminal);
                Ok(recovered)
            }
            Ok(_) => self.fail_async_attempt(),
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

    fn join_async_attempt(
        &mut self,
        mutation: AcceptanceMutation,
    ) -> Result<Option<(TerminalAttempt, VerifiedAttemptEvidence)>, AcceptanceSocketError> {
        let worker = self
            .controller_worker
            .take()
            .ok_or(AcceptanceSocketError::Operation)?;
        let (controller, result) = worker
            .join()
            .map_err(|_| AcceptanceSocketError::Operation)?;
        self.status = controller.service_status();
        self.controller = Some(controller);
        result.map_err(|_| AcceptanceSocketError::Operation)?;
        let (terminal, evidence) = merge_attempt_observations(
            &mut self.active_attempt,
            self.terminal_attempt.take(),
            self.verified_evidence.take(),
            std::iter::from_fn(|| self.observations.try_recv().ok()),
        )?;
        let Some(terminal) = terminal else {
            self.active_attempt = None;
            self.gate_waiting = false;
            return Ok(None);
        };
        let expected = self.acceptance_authority.expected_request(mutation)?;
        if !observed_admission_matches(&expected, terminal.admission, terminal.response) {
            return self.fail_async_attempt();
        }
        let Some(evidence) = evidence.filter(|evidence| evidence.terminal == terminal) else {
            return Err(AcceptanceSocketError::Operation);
        };
        self.active_attempt = None;
        self.gate_waiting = false;
        Ok(Some((terminal, evidence)))
    }

    fn finish_async_attempt(
        &mut self,
        mutation: AcceptanceMutation,
    ) -> Result<(TerminalAttempt, VerifiedAttemptEvidence), AcceptanceSocketError> {
        if self.controller_worker.is_none() {
            self.begin_async_attempt(mutation)?;
            self.release_async_attempt()?;
        }
        self.join_async_attempt(mutation)?
            .ok_or(AcceptanceSocketError::Operation)
    }

    fn poll_recovery_attempt(
        &mut self,
        mutation: AcceptanceMutation,
    ) -> Result<RecoveryAttempt, AcceptanceSocketError> {
        let expected = self.start_async_attempt(mutation)?;
        let deadline = Instant::now() + self.acceptance.timeout();
        loop {
            if self
                .controller_worker
                .as_ref()
                .is_some_and(JoinHandle::is_finished)
            {
                return Ok(match self.join_async_attempt(mutation)? {
                    Some(recovered) => RecoveryAttempt::Terminal(Box::new(recovered)),
                    None => RecoveryAttempt::NoObservation,
                });
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return self.fail_async_attempt();
            }
            match self
                .observations
                .recv_timeout(remaining.min(Duration::from_millis(10)))
            {
                Ok(AttemptObservation::Active(active))
                    if observed_admission_matches(&expected, active.admission, active.response) =>
                {
                    self.active_attempt = Some(active);
                    self.gate_waiting = true;
                    return Ok(RecoveryAttempt::Active(Box::new(active)));
                }
                Ok(AttemptObservation::Terminal(terminal))
                    if observed_admission_matches(
                        &expected,
                        terminal.admission,
                        terminal.response,
                    ) =>
                {
                    self.terminal_attempt = Some(terminal)
                }
                Ok(AttemptObservation::Completed(evidence)) => {
                    self.verified_evidence = Some(evidence)
                }
                Ok(_) => return self.fail_async_attempt(),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(AcceptanceSocketError::Operation)
                }
            }
        }
    }

    fn reconstruct_runner_attempt(
        &mut self,
        mutation: AcceptanceMutation,
    ) -> Result<(TerminalAttempt, VerifiedAttemptEvidence), AcceptanceSocketError> {
        while self.recovery_observations.try_recv().is_ok() {}
        let accepted = self.frozen_accepted_request(mutation)?;
        self.recovery_executor
            .execute(&accepted)
            .map_err(|_| AcceptanceSocketError::Operation)?;
        let mut terminal = None;
        let mut evidence = None;
        while let Ok(observation) = self.recovery_observations.try_recv() {
            match observation {
                AttemptObservation::Active(_) => return Err(AcceptanceSocketError::Operation),
                AttemptObservation::Terminal(observed) => terminal = Some(observed),
                AttemptObservation::Completed(verified) => evidence = Some(verified),
            }
        }
        let terminal = terminal.ok_or(AcceptanceSocketError::Operation)?;
        let evidence = evidence
            .filter(|verified| verified.terminal == terminal)
            .ok_or(AcceptanceSocketError::Operation)?;
        Ok((terminal, evidence))
    }

    fn frozen_accepted_request(
        &self,
        mutation: AcceptanceMutation,
    ) -> Result<AcceptedRequest, AcceptanceSocketError> {
        let expected = self.acceptance_authority.expected_request(mutation)?;
        Ok(AcceptedRequest {
            channel_id: self.acceptance_channel_id.clone(),
            watch_cursor: 0,
            event_id: expected.event_id,
            envelope: expected.envelope,
        })
    }

    fn fail_async_attempt<V>(&mut self) -> Result<V, AcceptanceSocketError> {
        self.status = CapacityOneStatus::startup_failure(TerminalInfrastructureReason::State);
        Err(AcceptanceSocketError::Operation)
    }

    #[cfg(test)]
    fn inject_provider_crash(&mut self, before_effect: bool) {
        self.crash_before_provider_effect = before_effect;
        self.crash_after_provider_effect = !before_effect;
    }

    #[cfg(test)]
    fn crash_before_provider_effect(&mut self) {
        if std::mem::take(&mut self.crash_before_provider_effect) {
            panic!("injected crash before provider effect");
        }
    }

    #[cfg(test)]
    fn crash_after_provider_effect(&mut self) {
        if std::mem::take(&mut self.crash_after_provider_effect) {
            panic!("injected crash after provider effect");
        }
    }
}

fn observed_admission_matches(
    expected: &AcceptedRequestBinding,
    admission: AdmitAttemptRequest,
    response: BrokerResponse,
) -> bool {
    let Some(event_id) = decode_array::<32>(&expected.event_id) else {
        return false;
    };
    let envelope = &expected.envelope;
    let Some(actor) = decode_array::<32>(&envelope.actor) else {
        return false;
    };
    let Some(workflow_digest) = decode_array::<32>(&envelope.workflow_digest) else {
        return false;
    };
    let Some(source_pin_event_id) = decode_array::<32>(&envelope.trigger_event_id) else {
        return false;
    };
    let Some(run_id) = Uuid::parse_str(&envelope.run_id).ok() else {
        return false;
    };
    let Some(idempotency_key) = Uuid::parse_str(&envelope.idempotency_key).ok() else {
        return false;
    };
    let Some(tip_oid) = decode_git_oid(&envelope.tip_oid) else {
        return false;
    };
    let Some(base_oid) = decode_git_oid(&envelope.base_oid) else {
        return false;
    };
    let Ok(wall_timeout_seconds) = u32::try_from(envelope.timeout_seconds) else {
        return false;
    };
    let idempotency_digest: [u8; 32] = Sha256::digest(idempotency_key.as_bytes()).into();

    admission.signed_request_digest == event_id
        && admission.actor_pubkey == actor
        && admission.idempotency_digest == idempotency_digest
        && admission.source_pin_event_id == source_pin_event_id
        && admission.workflow_digest == workflow_digest
        && admission.run_id == *run_id.as_bytes()
        && admission.tip_oid == tip_oid
        && admission.base_oid == base_oid
        && admission.issued_at == envelope.issued_at
        && admission.expires_at == envelope.expires_at
        && admission.wall_timeout_seconds == wall_timeout_seconds
        && admission.attempt == envelope.attempt
        && admission.parent_attempt == envelope.parent_attempt.unwrap_or(0)
        && response.accepted_request_digest == event_id
        && response.run_id == *run_id.as_bytes()
        && response.tip_oid == Some(tip_oid)
        && response.attempt == envelope.attempt
}

fn decode_array<const N: usize>(value: &str) -> Option<[u8; N]> {
    hex::decode(value).ok()?.try_into().ok()
}

fn decode_git_oid(value: &str) -> Option<GitOid> {
    match value.len() {
        40 => decode_array::<20>(value).map(GitOid::Sha1),
        64 => decode_array::<32>(value).map(GitOid::Sha256),
        _ => None,
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
        journal.execute(
            request,
            exact_request,
            0,
            |prior, _execution| match request.operation {
                Operation::ObserveInitial if request.sequence == 1 => {
                    Ok(host_response(request, None, 0))
                }
                Operation::SetCapacityZero if request.sequence == 16 => {
                    Ok(host_response(request, prior, 0))
                }
                _ => Err(AcceptanceSocketError::Operation),
            },
        )
    }
}

impl<C, T, X, R, S> AcceptanceOperationHandler for CapacityOneService<C, T, X, R, S>
where
    C: ServiceController,
    T: RunnerV2Transport,
    X: AttemptExecutor,
    R: RelayControl,
    S: AcceptanceMutationSigner,
{
    type Error = AcceptanceSocketError;

    fn handle(
        &mut self,
        request: &AdapterRequest,
        exact_request: &[u8],
    ) -> Result<AdapterResponse, Self::Error> {
        let configured_capacity = self.status.configured_capacity();
        let journal = self.acceptance.clone();
        journal.execute(
            request,
            exact_request,
            configured_capacity,
            |prior, execution| match (request.sequence, request.operation) {
                (2, Operation::SetCapacityOne)
                | (14, Operation::RestartController)
                | (15, Operation::RestartRunner) => {
                    Ok(host_response(request, prior, configured_capacity))
                }
                (3, Operation::SubmitManifest) => {
                    self.publish_acceptance(AcceptanceMutation::Run)?;
                    Ok(submitted_response(request))
                }
                (4, Operation::ApproveGrant) => {
                    self.publish_acceptance(AcceptanceMutation::Grant)?;
                    self.replay_deferred_after_grant()?;
                    Ok(approved_response(request))
                }
                (5, Operation::ResumeGrant) => {
                    let active = self.begin_async_attempt(AcceptanceMutation::Run)?;
                    Ok(running_response(request, prior, active, false, false)?)
                }
                (6, Operation::AwaitFirstTerminal) => {
                    #[cfg(test)]
                    self.crash_before_provider_effect();
                    let (terminal, evidence) = if execution == AcceptanceExecution::Recovering {
                        recover_terminal_with(self, AcceptanceMutation::Run)?
                    } else {
                        self.finish_async_attempt(AcceptanceMutation::Run)?
                    };
                    let response = first_terminal_response(request, prior, terminal, &evidence)?;
                    #[cfg(test)]
                    self.crash_after_provider_effect();
                    Ok(response)
                }
                (7, Operation::ExportFirstEvidence) => {
                    #[cfg(test)]
                    self.crash_before_provider_effect();
                    let expected = self
                        .acceptance_authority
                        .expected_request(AcceptanceMutation::Run)?;
                    let export = self
                        .controller
                        .as_mut()
                        .ok_or(AcceptanceSocketError::Operation)?
                        .service_export_first_evidence(&expected, &request.fixture.job_id, 1)
                        .map_err(|_| AcceptanceSocketError::Operation)?;
                    let response = export_response(request, prior, export)?;
                    #[cfg(test)]
                    self.crash_after_provider_effect();
                    Ok(response)
                }
                (8, Operation::SubmitFailureManifest) => {
                    self.publish_acceptance(AcceptanceMutation::FailureRun)?;
                    Ok(failed_submitted_response(request))
                }
                (9, Operation::ResumeFailure) => {
                    let active = self.begin_async_attempt(AcceptanceMutation::FailureRun)?;
                    Ok(running_response(request, prior, active, false, true)?)
                }
                (10, Operation::AwaitFailureTerminal) => {
                    #[cfg(test)]
                    self.crash_before_provider_effect();
                    let (terminal, evidence) = if execution == AcceptanceExecution::Recovering {
                        recover_terminal_with(self, AcceptanceMutation::FailureRun)?
                    } else {
                        self.finish_async_attempt(AcceptanceMutation::FailureRun)?
                    };
                    let response = failure_terminal_response(request, prior, terminal, &evidence)?;
                    #[cfg(test)]
                    self.crash_after_provider_effect();
                    Ok(response)
                }
                (11, Operation::Rerun) => {
                    self.publish_acceptance(AcceptanceMutation::Rerun)?;
                    let active = self.begin_async_attempt(AcceptanceMutation::Rerun)?;
                    Ok(running_response(request, prior, active, true, true)?)
                }
                (12, Operation::CancelRerun) => {
                    #[cfg(test)]
                    self.crash_before_provider_effect();
                    let cancelled = if execution == AcceptanceExecution::Recovering {
                        recover_cancelled_with(self, request)?
                    } else {
                        self.cancel_fresh(request)?
                    };
                    let response = cancelled_response(request, prior, cancelled)?;
                    #[cfg(test)]
                    self.crash_after_provider_effect();
                    Ok(response)
                }
                (13, Operation::TombstoneRerun) => {
                    self.publish_acceptance(AcceptanceMutation::Tombstone)?;
                    Ok(tombstoned_response(request, prior)?)
                }
                _ => Err(AcceptanceSocketError::Operation),
            },
        )
    }

    fn response_written(&mut self, request: &AdapterRequest) -> Result<(), Self::Error> {
        if matches!(
            (request.sequence, request.operation),
            (5, Operation::ResumeGrant) | (9, Operation::ResumeFailure)
        ) {
            self.release_async_attempt()?;
        }
        Ok(())
    }
}

impl<C, T, X, R, S> CapacityOneService<C, T, X, R, S>
where
    C: ServiceController,
    T: RunnerV2Transport,
    X: AttemptExecutor,
    R: RelayControl,
    S: AcceptanceMutationSigner,
{
    fn publish_acceptance(
        &mut self,
        mutation: AcceptanceMutation,
    ) -> Result<(), AcceptanceSocketError> {
        let index = AcceptanceAuthority::index(mutation);
        let event_id = self.acceptance_authority.event_ids[index];
        let signature = self
            .acceptance_signer
            .sign_mutation(
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

    /// The relay acknowledged this activation's grant: replay deferred
    /// publications now, before the approval is answered, so the head of the
    /// relay queue is settled before the driver resumes the attempt. Deferral
    /// is cleared first; a refusal from here on is terminal as it always was.
    fn replay_deferred_after_grant(&mut self) -> Result<(), AcceptanceSocketError> {
        if self.controller_worker.is_some() {
            return Err(AcceptanceSocketError::Operation);
        }
        let controller = self
            .controller
            .as_mut()
            .ok_or(AcceptanceSocketError::Operation)?;
        let expected = self
            .acceptance_authority
            .expected_request(AcceptanceMutation::Run)?;
        controller.service_set_replay_deferral(false);
        let replayed = controller.service_replay_deferred_publications_bound(&expected);
        self.status = controller.service_status();
        replayed.map_err(|_| AcceptanceSocketError::Operation)
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

fn merge_attempt_observations(
    active: &mut Option<BoundAttempt>,
    mut terminal: Option<TerminalAttempt>,
    mut evidence: Option<VerifiedAttemptEvidence>,
    observations: impl IntoIterator<Item = AttemptObservation>,
) -> Result<(Option<TerminalAttempt>, Option<VerifiedAttemptEvidence>), AcceptanceSocketError> {
    for observation in observations {
        match observation {
            AttemptObservation::Active(observed) => *active = Some(observed),
            AttemptObservation::Terminal(observed) => match terminal {
                Some(cached) if cached != observed => return Err(AcceptanceSocketError::Operation),
                Some(_) => {}
                None => terminal = Some(observed),
            },
            AttemptObservation::Completed(observed) => match evidence.as_ref() {
                Some(cached) if cached != &observed => {
                    return Err(AcceptanceSocketError::Operation)
                }
                Some(_) => {}
                None => evidence = Some(observed),
            },
        }
    }
    Ok((terminal, evidence))
}

impl<C, T, X, R, S> AcceptanceRecoveryProvider for CapacityOneService<C, T, X, R, S>
where
    C: ServiceController,
    T: RunnerV2Transport,
    X: AttemptExecutor,
    R: RelayControl,
    S: AcceptanceMutationSigner,
{
    fn poll_recovery(
        &mut self,
        mutation: AcceptanceMutation,
    ) -> Result<RecoveryAttempt, AcceptanceSocketError> {
        self.poll_recovery_attempt(mutation)
    }

    fn release_active(&mut self) -> Result<(), AcceptanceSocketError> {
        self.release_async_attempt()
    }

    fn finish_active(
        &mut self,
        mutation: AcceptanceMutation,
    ) -> Result<(TerminalAttempt, VerifiedAttemptEvidence), AcceptanceSocketError> {
        self.finish_async_attempt(mutation)
    }

    fn reconstruct_terminal(
        &mut self,
        mutation: AcceptanceMutation,
    ) -> Result<(TerminalAttempt, VerifiedAttemptEvidence), AcceptanceSocketError> {
        self.reconstruct_runner_attempt(mutation)
    }

    fn cancel_active(
        &mut self,
        request: &AdapterRequest,
        active: BoundAttempt,
    ) -> Result<TerminalAttempt, AcceptanceSocketError> {
        self.cancel_active_attempt(request, active)
    }

    fn cancel_fresh(
        &mut self,
        request: &AdapterRequest,
    ) -> Result<TerminalAttempt, AcceptanceSocketError> {
        let active = self
            .active_attempt
            .or_else(|| self.begin_async_attempt(AcceptanceMutation::Rerun).ok())
            .ok_or(AcceptanceSocketError::Operation)?;
        let cancelled = self.cancel_active_attempt(request, active)?;
        self.release_async_attempt()?;
        let (reconciled, _) = self.finish_async_attempt(AcceptanceMutation::Rerun)?;
        if !same_terminal_binding(cancelled, reconciled) {
            return Err(AcceptanceSocketError::Operation);
        }
        Ok(cancelled)
    }
}

fn recover_terminal_with<P: AcceptanceRecoveryProvider>(
    provider: &mut P,
    mutation: AcceptanceMutation,
) -> Result<(TerminalAttempt, VerifiedAttemptEvidence), AcceptanceSocketError> {
    match provider.poll_recovery(mutation)? {
        RecoveryAttempt::Active(_) => {
            provider.release_active()?;
            provider.finish_active(mutation)
        }
        RecoveryAttempt::Terminal(recovered) => Ok(*recovered),
        RecoveryAttempt::NoObservation => provider.reconstruct_terminal(mutation),
    }
}

fn recover_cancelled_with<P: AcceptanceRecoveryProvider>(
    provider: &mut P,
    request: &AdapterRequest,
) -> Result<TerminalAttempt, AcceptanceSocketError> {
    match provider.poll_recovery(AcceptanceMutation::Rerun)? {
        RecoveryAttempt::Active(active) => {
            let cancelled = provider.cancel_active(request, *active)?;
            provider.release_active()?;
            let (reconciled, _) = provider.finish_active(AcceptanceMutation::Rerun)?;
            if !same_terminal_binding(cancelled, reconciled) {
                return Err(AcceptanceSocketError::Operation);
            }
            Ok(cancelled)
        }
        RecoveryAttempt::Terminal(recovered) => {
            let (terminal, _) = *recovered;
            let bound = BoundAttempt {
                admission: terminal.admission,
                response: terminal.response,
            };
            validate_cancelled_terminal(bound, terminal, false)?;
            Ok(terminal)
        }
        RecoveryAttempt::NoObservation => {
            let (terminal, _) = provider.reconstruct_terminal(AcceptanceMutation::Rerun)?;
            let bound = BoundAttempt {
                admission: terminal.admission,
                response: terminal.response,
            };
            validate_cancelled_terminal(bound, terminal, false)?;
            Ok(terminal)
        }
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

fn failed_submitted_response(request: &AdapterRequest) -> AdapterResponse {
    acceptance_response(
        request,
        failure_run_snapshot(
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
    failure_lineage: bool,
) -> Result<AdapterResponse, AcceptanceSocketError> {
    let attempt_id = hex::encode(active.response.attempt_id);
    if active.admission.attempt != if rerun { 2 } else { 1 }
        || active.response.broker_state == BrokerState::Terminal
    {
        return Err(AcceptanceSocketError::Operation);
    }
    // The driver names the attempt it reruns at sequence 11 (the first
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
    let attempt = if failure_lineage {
        failure_attempt_snapshot(
            request,
            attempt_id,
            active.admission.attempt,
            parent_attempt_id,
            AttemptState::Running,
            AcceptanceConclusion::None,
            None,
        )
    } else {
        attempt_snapshot(
            request,
            attempt_id,
            active.admission.attempt,
            parent_attempt_id,
            AttemptState::Running,
            AcceptanceConclusion::None,
            None,
        )
    };
    attempts.push(attempt);
    let run = if failure_lineage {
        failure_run_snapshot(
            request,
            RunState::Running,
            AcceptanceConclusion::None,
            Some(approval_snapshot(request, true)),
            None,
            attempts,
        )
    } else {
        run_snapshot(
            request,
            RunState::Running,
            AcceptanceConclusion::None,
            Some(approval_snapshot(request, true)),
            None,
            attempts,
        )
    };
    Ok(acceptance_response(request, run, 1, None))
}

fn failure_terminal_response(
    request: &AdapterRequest,
    prior: Option<&AdapterResponse>,
    terminal: TerminalAttempt,
    evidence: &VerifiedAttemptEvidence,
) -> Result<AdapterResponse, AcceptanceSocketError> {
    if terminal.admission.attempt != 1
        || terminal.response.broker_state != BrokerState::Terminal
        || terminal.response.conclusion != BrokerConclusion::Failure
        || terminal.response.evidence_set_digest == [0; 32]
        || terminal.response.teardown_digest == [0; 32]
        || evidence.terminal != terminal
        || evidence.descriptor_set_digest == [0; 32]
        || evidence.log_sha256 != request.fixture.expected_failure_log.sha256
        || evidence.log_bytes != request.fixture.expected_failure_log.bytes
        || !evidence.artifacts.is_empty()
    {
        return Err(AcceptanceSocketError::Operation);
    }
    let running = prior_run(prior)?;
    let attempt_id = hex::encode(terminal.response.attempt_id);
    if running.attempts.len() != 1 || running.attempts[0].attempt_id != attempt_id {
        return Err(AcceptanceSocketError::Operation);
    }
    let attempt = failure_attempt_snapshot(
        request,
        attempt_id.clone(),
        1,
        None,
        AttemptState::Terminal,
        AcceptanceConclusion::Failure,
        Some(hex::encode(evidence.descriptor_set_digest)),
    );
    Ok(acceptance_response(
        request,
        failure_run_snapshot(
            request,
            RunState::Terminal,
            AcceptanceConclusion::Failure,
            Some(approval_snapshot(request, true)),
            Some(attempt_id),
            vec![attempt],
        ),
        0,
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
    export: AuthenticatedEvidenceExport,
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
    if selected.len() != 32
        || !selected
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || export.request_event_id != request.fixture.request_digest
        || Uuid::parse_str(&export.run_id)
            .map(|value| hex::encode(value.as_bytes()))
            .as_deref()
            != Ok(request.fixture.run_id.as_str())
        || export.job_id != request.fixture.job_id
        || export.attempt != 1
        || export.subject != request.fixture.export_subject
        || export.generation != request.fixture.export_generation
        || export.authorization_digest != request.fixture.export_authorization_digest
        || export.objects.len() != 1 + request.fixture.expected_artifacts.len()
    {
        return Err(AcceptanceSocketError::Operation);
    }
    let expected_objects = std::iter::once(&request.fixture.expected_log)
        .chain(request.fixture.expected_artifacts.iter());
    let mut objects = Vec::with_capacity(export.objects.len());
    for (actual, expected) in export.objects.into_iter().zip(expected_objects) {
        if actual.name != expected.name
            || actual.sha256 != expected.sha256
            || actual.bytes.len() as u64 != expected.bytes
            || hex::encode(Sha256::digest(&actual.bytes)) != actual.sha256
        {
            return Err(AcceptanceSocketError::Operation);
        }
        objects.push(buzz_ci_acceptance_ctl::acceptance::EvidenceObject {
            name: actual.name,
            sha256: actual.sha256,
            bytes: actual.bytes.len() as u64,
        });
    }
    Ok(acceptance_response(
        request,
        run,
        0,
        Some(ExportSnapshot {
            authenticated: true,
            subject: export.subject,
            generation: export.generation,
            authorization_digest: export.authorization_digest,
            attempt_id: selected,
            request_digest: export.request_event_id,
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
    let second = failure_attempt_snapshot(
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
        failure_run_snapshot(
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
        failure_run_snapshot(
            request,
            RunState::Terminal,
            AcceptanceConclusion::Failure,
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

fn failure_run_snapshot(
    request: &AdapterRequest,
    state: RunState,
    aggregate_conclusion: AcceptanceConclusion,
    approval: Option<ApprovalSnapshot>,
    selected_attempt_id: Option<String>,
    attempts: Vec<AttemptSnapshot>,
) -> RunSnapshot {
    RunSnapshot {
        run_id: request.fixture.failure_run_id.clone(),
        integrated_candidate_sha: request.fixture.integrated_candidate_sha.clone(),
        request_digest: request.fixture.failure_request_digest.clone(),
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

fn failure_attempt_snapshot(
    request: &AdapterRequest,
    attempt_id: String,
    attempt: u32,
    parent_attempt_id: Option<String>,
    state: AttemptState,
    conclusion: AcceptanceConclusion,
    evidence_set_digest: Option<String>,
) -> AttemptSnapshot {
    let terminal_failure = conclusion == AcceptanceConclusion::Failure;
    AttemptSnapshot {
        attempt_id,
        attempt,
        parent_attempt_id,
        state,
        conclusion,
        integrated_candidate_sha: request.fixture.integrated_candidate_sha.clone(),
        request_digest: request.fixture.failure_request_digest.clone(),
        manifest_digest: request.fixture.manifest_digest.clone(),
        source_oid: request.fixture.source_oid.clone(),
        evidence_set_digest,
        log: terminal_failure.then(|| request.fixture.expected_failure_log.clone()),
        artifacts: Vec::new(),
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
    use std::collections::{BTreeSet, HashMap, VecDeque};
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::sync::{Arc, Mutex};

    use buzz_ci_acceptance_ctl::acceptance_binding_test_support::canonical_acceptance_binding;
    use buzz_ci_acceptance_ctl::production::{
        expected_adapter_operation_id, ControlReadback, ADAPTER_REQUEST_SCHEMA,
    };
    use buzz_ci_broker_protocol::v2::{
        self, admission_signature_message, intent_registration_key_digest, BrokerResponse,
        EvidenceChunkResponse, EvidenceDescriptionResponse, EvidenceDescriptor, EvidenceKind,
        IntentRegistrationResponse, Request, WireText64,
    };
    use buzz_ci_broker_protocol::v2::{AdmissionSignatureAlgorithm, AdmitAttemptRequest};
    use buzz_ci_broker_protocol::{GitOid, TrustClass};
    use tempfile::TempDir;

    use super::*;
    use crate::config::DaemonConfig;
    use buzz_ci_controld::acceptance_socket::ACCEPTANCE_BINDING_PATH;
    use buzz_ci_controld::production::{
        ArtifactCompletion, AuthenticatedEventRead, AuthenticatedObjectRead, ExportReadError,
        JobCompletion, StoredObject, StoredPublication,
    };
    use buzz_ci_controld::runner_v2::AdmissionSigner;
    use buzz_ci_controld::source::{HttpMethod, Nip98Binding, Nip98Proof};
    use buzz_ci_controld::{RunIdentity, RunRecord, StoreWrite};
    use buzz_core::ci::CiSkipPolicy;

    #[test]
    fn acceptance_authority_selects_each_frozen_request_identity() {
        let binding = canonical_acceptance_binding();
        let validated = binding.validate().expect("validated binding");
        let authority = AcceptanceAuthority::new(&binding).expect("acceptance authority");
        assert_eq!(authority.event_ids, validated.event_ids());

        let cases = [
            (
                AcceptanceMutation::Run,
                0,
                binding.fixture.run_id.as_str(),
                1,
                None,
                None,
            ),
            (
                AcceptanceMutation::FailureRun,
                4,
                binding.fixture.failure_run_id.as_str(),
                1,
                None,
                None,
            ),
            (
                AcceptanceMutation::Rerun,
                2,
                binding.fixture.failure_run_id.as_str(),
                2,
                Some(1),
                Some(binding.fixture.failure_run_id.as_str()),
            ),
        ];
        for (mutation, event_index, run_id, attempt, parent_attempt, parent_run_id) in cases {
            let expected = authority
                .expected_request(mutation)
                .expect("request-bearing mutation");
            assert_eq!(
                expected.event_id,
                hex::encode(authority.event_ids[event_index])
            );
            assert_eq!(expected.envelope.run_id.replace('-', ""), run_id);
            assert_eq!(expected.envelope.attempt, attempt);
            assert_eq!(expected.envelope.parent_attempt, parent_attempt);
            assert_eq!(
                expected
                    .envelope
                    .parent_run_id
                    .as_deref()
                    .map(|value| value.replace('-', "")),
                parent_run_id.map(str::to_owned)
            );
            assert_eq!(expected.envelope.actor, binding.acceptance.actor.public_key);
        }
        assert_eq!(
            authority.expected_request(AcceptanceMutation::Grant),
            Err(AcceptanceSocketError::Operation)
        );
        assert_eq!(
            authority.expected_request(AcceptanceMutation::Tombstone),
            Err(AcceptanceSocketError::Operation)
        );
    }

    #[test]
    fn live_admission_matrix_keeps_rerun_distinct_from_failure_run_root() {
        let binding = canonical_acceptance_binding();
        let authority = AcceptanceAuthority::new(&binding).expect("acceptance authority");
        let run_a = authority
            .expected_request(AcceptanceMutation::Run)
            .expect("Run A");
        let run_b = authority
            .expected_request(AcceptanceMutation::FailureRun)
            .expect("Run B");
        let rerun = authority
            .expected_request(AcceptanceMutation::Rerun)
            .expect("rerun");

        for expected in [&run_a, &run_b, &rerun] {
            let observed = observation_for(expected);
            assert!(observed_admission_matches(
                expected,
                observed.admission,
                observed.response
            ));
        }
        assert_ne!(run_a.event_id, run_b.event_id);
        assert_ne!(run_b.event_id, rerun.event_id);
        assert_eq!(run_b.envelope.run_id, rerun.envelope.run_id);

        let mut relabeled_rerun = observation_for(&rerun);
        relabeled_rerun.admission.signed_request_digest = authority.event_ids[4];
        relabeled_rerun.response.accepted_request_digest = authority.event_ids[4];
        assert!(!observed_admission_matches(
            &rerun,
            relabeled_rerun.admission,
            relabeled_rerun.response
        ));

        for drift in [
            {
                let mut drift = observation_for(&rerun);
                drift.admission.parent_attempt = 0;
                drift
            },
            {
                let mut drift = observation_for(&rerun);
                drift.admission.workflow_digest[0] ^= 1;
                drift
            },
            {
                let mut drift = observation_for(&rerun);
                drift.admission.actor_pubkey[0] ^= 1;
                drift
            },
            {
                let mut drift = observation_for(&rerun);
                drift.admission.base_oid = GitOid::Sha1([99; 20]);
                drift
            },
        ] {
            assert!(!observed_admission_matches(
                &rerun,
                drift.admission,
                drift.response
            ));
        }
    }

    #[test]
    fn incomplete_acceptance_sequence_retains_socket_poll_ownership_after_restart() {
        for completed in 0..COMPLETE_ACCEPTANCE_SEQUENCE {
            assert!(
                !background_polling_enabled(completed),
                "sequence {completed} must remain acceptance-owned"
            );
        }
        assert!(!background_polling_enabled(13));
        assert!(!background_polling_enabled(14));
        assert!(!background_polling_enabled(15));
        assert!(background_polling_enabled(16));
        assert!(background_polling_enabled(COMPLETE_ACCEPTANCE_SEQUENCE));
        assert!(background_polling_enabled(COMPLETE_ACCEPTANCE_SEQUENCE + 1));
    }

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

    #[derive(Clone, Default)]
    struct FakeStoreState {
        cursor: u64,
        runs: Vec<(RunIdentity, u64, RunRecord)>,
        publications: HashMap<String, StoredPublication>,
        deferred: BTreeSet<String>,
        fail_cursor_once: bool,
    }

    #[derive(Clone, Default)]
    struct FakeStore(Arc<Mutex<FakeStoreState>>);

    impl ControlStore for FakeStore {
        type Error = ();

        fn cursor(&self, _channel_id: &str) -> Result<u64, Self::Error> {
            Ok(self.0.lock().unwrap().cursor)
        }

        fn advance_cursor(
            &mut self,
            _channel_id: &str,
            expected: u64,
            next: u64,
        ) -> Result<bool, Self::Error> {
            let mut state = self.0.lock().unwrap();
            if std::mem::take(&mut state.fail_cursor_once) {
                return Err(());
            }
            if state.cursor != expected {
                return Ok(false);
            }
            state.cursor = next;
            Ok(true)
        }

        fn load_run(
            &self,
            identity: &RunIdentity,
        ) -> Result<Option<(u64, RunRecord)>, Self::Error> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .runs
                .iter()
                .find(|(stored, _, _)| stored == identity)
                .map(|(_, revision, run)| (*revision, run.clone())))
        }

        fn compare_and_swap_run(
            &mut self,
            identity: &RunIdentity,
            expected_revision: Option<u64>,
            next: &RunRecord,
        ) -> Result<StoreWrite, Self::Error> {
            let mut state = self.0.lock().unwrap();
            let existing = state
                .runs
                .iter_mut()
                .find(|(stored, _, _)| stored == identity);
            let actual = existing.as_ref().map(|(_, revision, _)| *revision);
            if actual != expected_revision {
                return Ok(StoreWrite::Conflict {
                    actual_revision: actual,
                });
            }
            let revision = actual.unwrap_or(0) + 1;
            if let Some((_, stored_revision, stored)) = existing {
                *stored_revision = revision;
                *stored = next.clone();
            } else {
                state.runs.push((identity.clone(), revision, next.clone()));
            }
            Ok(StoreWrite::Written { revision })
        }

        fn load_publication(&self, key: &str) -> Result<Option<StoredPublication>, Self::Error> {
            Ok(self.0.lock().unwrap().publications.get(key).cloned())
        }

        fn record_publication_intent(
            &mut self,
            key: &str,
            event: &SignedCiEvent,
        ) -> Result<bool, Self::Error> {
            let mut state = self.0.lock().unwrap();
            if state.publications.contains_key(key) {
                return Ok(false);
            }
            state
                .publications
                .insert(key.to_owned(), StoredPublication::Pending(event.clone()));
            Ok(true)
        }

        fn refresh_pending_publication(
            &mut self,
            key: &str,
            expected_event_id: &str,
            replacement: &SignedCiEvent,
        ) -> Result<bool, Self::Error> {
            let mut state = self.0.lock().unwrap();
            let Some(StoredPublication::Pending(stored)) = state.publications.get(key) else {
                return Err(());
            };
            if stored.event_id != expected_event_id {
                return Err(());
            }
            state.publications.insert(
                key.to_owned(),
                StoredPublication::Pending(replacement.clone()),
            );
            Ok(true)
        }

        fn defer_publication(&mut self, key: &str) -> Result<(), Self::Error> {
            self.0.lock().unwrap().deferred.insert(key.to_owned());
            Ok(())
        }

        fn deferred_publications(&self) -> Result<Vec<String>, Self::Error> {
            Ok(self.0.lock().unwrap().deferred.iter().cloned().collect())
        }

        fn accept_publication(&mut self, key: &str, event_id: &str) -> Result<(), Self::Error> {
            let mut state = self.0.lock().unwrap();
            let Some(StoredPublication::Pending(signed)) = state.publications.get(key).cloned()
            else {
                return Err(());
            };
            state.publications.insert(
                key.to_owned(),
                StoredPublication::Accepted {
                    signed,
                    relay_event_id: event_id.to_owned(),
                },
            );
            state.deferred.remove(key);
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct FakeRelayState {
        accepted: VecDeque<AcceptedRequest>,
        published: BTreeSet<String>,
        events: HashMap<String, SignedCiEvent>,
        objects: HashMap<String, Vec<u8>>,
        publish_calls: HashMap<String, usize>,
        export_reads: usize,
        event_proof_subject: Option<String>,
        object_proof_subject: Option<String>,
        object_proof_generation: Option<u64>,
        nip98_generation: u64,
        export_error: Option<ExportReadError>,
        put_url_drift: Option<String>,
    }

    #[derive(Clone, Default)]
    struct FakeRelay(Arc<Mutex<FakeRelayState>>);

    impl RelayControl for FakeRelay {
        type Error = ();

        fn next_accepted(
            &mut self,
            _channel_id: &str,
            after_cursor: u64,
        ) -> Result<Option<AcceptedRequest>, Self::Error> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .accepted
                .iter()
                .find(|request| request.watch_cursor > after_cursor)
                .cloned())
        }

        fn publish(&mut self, event: &SignedCiEvent) -> Result<String, Self::Error> {
            let mut state = self.0.lock().unwrap();
            state.published.insert(event.event_id.clone());
            state.events.insert(event.event_id.clone(), event.clone());
            *state
                .publish_calls
                .entry(event.event_id.clone())
                .or_default() += 1;
            Ok(event.event_id.clone())
        }

        fn publication_exists(&mut self, event: &SignedCiEvent) -> Result<bool, Self::Error> {
            Ok(self.0.lock().unwrap().published.contains(&event.event_id))
        }

        fn put_log(
            &mut self,
            accepted: &AcceptedRequest,
            job: &JobCompletion,
            bytes: &[u8],
        ) -> Result<StoredObject, Self::Error> {
            let request_id = if self.0.lock().unwrap().put_url_drift.as_deref() == Some("log") {
                "ac".repeat(32)
            } else {
                accepted.event_id.clone()
            };
            let url = format!(
                "https://relay.invalid/ci/logs/{}/{}/{}/{}/{}",
                request_id,
                accepted.envelope.run_id,
                job.metadata.job_id,
                job.attempt,
                job.log.sha256
            );
            self.0
                .lock()
                .unwrap()
                .objects
                .insert(url.clone(), bytes.to_vec());
            Ok(stored_object(url, bytes))
        }

        fn put_artifact(
            &mut self,
            accepted: &AcceptedRequest,
            job: &JobCompletion,
            artifact: &ArtifactCompletion,
            bytes: &[u8],
        ) -> Result<StoredObject, Self::Error> {
            let artifact_id = if self.0.lock().unwrap().put_url_drift.as_deref() == Some("artifact")
            {
                "other"
            } else {
                artifact.artifact_id.as_str()
            };
            let url = format!(
                "https://relay.invalid/ci/artifacts/{}/{}/{}/{}/{}/{}",
                accepted.event_id,
                accepted.envelope.run_id,
                job.metadata.job_id,
                job.attempt,
                artifact_id,
                artifact.descriptor.sha256
            );
            self.0
                .lock()
                .unwrap()
                .objects
                .insert(url.clone(), bytes.to_vec());
            Ok(stored_object(url, bytes))
        }

        fn read_exact_event(
            &mut self,
            event_id: &str,
            kind: u32,
            author: &str,
        ) -> Result<AuthenticatedEventRead, ExportReadError> {
            let mut state = self.0.lock().unwrap();
            state.export_reads += 1;
            if let Some(error) = state.export_error {
                return Err(error);
            }
            let event = state
                .events
                .get(event_id)
                .cloned()
                .ok_or(ExportReadError::Invalid)?;
            if event.kind != kind {
                return Err(ExportReadError::Invalid);
            }
            let url = Url::parse("https://relay.invalid/query").unwrap();
            let filter = format!(
                r#"[{{"ids":["{event_id}"],"authors":["{author}"],"kinds":[{kind}],"limit":1}}]"#
            );
            Ok(AuthenticatedEventRead {
                event,
                proof: Nip98Proof {
                    subject: state
                        .event_proof_subject
                        .clone()
                        .unwrap_or_else(|| author.to_owned()),
                    generation: 7,
                    event_id: "aa".repeat(32),
                },
                binding: Nip98Binding {
                    method: HttpMethod::Post,
                    url,
                    payload_sha256: Some(hex::encode(Sha256::digest(filter.as_bytes()))),
                    publisher: Some(author.to_owned()),
                    query_filter: Some(filter.into_bytes()),
                },
            })
        }

        fn read_evidence_object(
            &mut self,
            url: &str,
            expected_sha256: &str,
            expected_bytes: u64,
            maximum_bytes: u64,
        ) -> Result<AuthenticatedObjectRead, ExportReadError> {
            let mut state = self.0.lock().unwrap();
            state.export_reads += 1;
            if let Some(error) = state.export_error {
                return Err(error);
            }
            let bytes = state
                .objects
                .get(url)
                .cloned()
                .ok_or(ExportReadError::Invalid)?;
            if bytes.len() as u64 != expected_bytes
                || maximum_bytes != expected_bytes
                || hex::encode(Sha256::digest(&bytes)) != expected_sha256
            {
                return Err(ExportReadError::Invalid);
            }
            Ok(AuthenticatedObjectRead {
                bytes,
                proof: Nip98Proof {
                    subject: state
                        .object_proof_subject
                        .clone()
                        .unwrap_or_else(|| "1b".repeat(32)),
                    generation: state
                        .object_proof_generation
                        .unwrap_or(state.nip98_generation),
                    event_id: "bb".repeat(32),
                },
                binding: Nip98Binding {
                    method: HttpMethod::Get,
                    url: Url::parse(url).map_err(|_| ExportReadError::Invalid)?,
                    payload_sha256: None,
                    publisher: None,
                    query_filter: None,
                },
            })
        }
    }

    fn stored_object(url: String, bytes: &[u8]) -> StoredObject {
        StoredObject {
            url,
            sha256: hex::encode(Sha256::digest(bytes)),
            byte_length: bytes.len() as u64,
        }
    }

    #[derive(Clone)]
    struct FakeCiSigner(String);

    impl CiSigner for FakeCiSigner {
        type Error = ();

        fn pubkey(&self) -> &str {
            &self.0
        }

        fn generation(&self) -> u64 {
            7
        }

        fn sign(
            &mut self,
            kind: u32,
            content: &str,
            tags: serde_json::Value,
        ) -> Result<SignedCiEvent, Self::Error> {
            let keys = nostr::Keys::parse(&format!("{}01", "00".repeat(31))).unwrap();
            let parsed_tags: Vec<nostr::Tag> = serde_json::from_value(tags.clone()).unwrap();
            let event = nostr::EventBuilder::new(nostr::Kind::Custom(kind as u16), content)
                .tags(parsed_tags)
                .custom_created_at(nostr::Timestamp::from(1_800_000_100_u64 + kind as u64))
                .sign_with_keys(&keys)
                .unwrap();
            let event_id = event.id.to_hex();
            Ok(SignedCiEvent {
                event_id: event_id.clone(),
                kind,
                content: content.to_owned(),
                tags,
                signed_event: serde_json::to_value(event).unwrap(),
            })
        }
    }

    #[derive(Clone, Copy)]
    struct FakeAcceptanceSigner;

    impl AcceptanceMutationSigner for FakeAcceptanceSigner {
        fn sign_mutation(
            &mut self,
            actor: PublicIdentity,
            _scenario_sha256: [u8; 32],
            _mutation: AcceptanceMutation,
            event_id: [u8; 32],
        ) -> Result<buzz_ci_keyholder::SignatureResponse, ()> {
            Ok(buzz_ci_keyholder::SignatureResponse {
                identity: actor,
                signed_digest: event_id,
                signature: [42; 64],
            })
        }
    }

    #[derive(Clone, Copy)]
    struct FakeAdmissionSigner;

    impl AdmissionSigner for FakeAdmissionSigner {
        type Error = ();

        fn sign_admission(&mut self, request: &mut AdmitAttemptRequest) -> Result<(), Self::Error> {
            request.admission_signature = [41; 64];
            Ok(())
        }
    }

    #[derive(Clone)]
    struct FakeRunnerTransport(Arc<Mutex<FakeRunnerState>>);

    #[derive(Debug)]
    struct FakeRunnerState {
        conclusion: BrokerConclusion,
        active: Option<BoundAttempt>,
        terminal: Option<TerminalAttempt>,
        evidence: Option<FakeEvidence>,
        starts: usize,
        starts_by_request: HashMap<[u8; 32], usize>,
        last_request: Option<[u8; 32]>,
        cancels: usize,
        drift: bool,
        exchanges: usize,
    }

    #[derive(Clone, Debug)]
    struct FakeEvidence {
        descriptors: Vec<EvidenceDescriptor>,
        bytes: Vec<Vec<u8>>,
        descriptor_set_digest: [u8; 32],
    }

    #[derive(serde::Serialize)]
    struct FakeArtifactDocument<'a> {
        schema_version: u16,
        execution_binding_digest: String,
        request_event_id: String,
        run_id: String,
        workflow_id: &'a str,
        workflow_digest: String,
        job_id: &'a str,
        attempt: u32,
        artifact_id: String,
        name: String,
        media_type: String,
        sha256: String,
        byte_length: u32,
        content_hex: String,
    }

    fn fake_descriptor_set_digest(
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

    fn fake_terminal(
        active: BoundAttempt,
        conclusion: BrokerConclusion,
    ) -> (TerminalAttempt, FakeEvidence) {
        let output = match conclusion {
            BrokerConclusion::Success => b's',
            _ => b'f',
        };
        let stdout = serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "execution_binding_digest": hex::encode(active.response.execution_binding_digest),
            "conclusion": match conclusion {
                BrokerConclusion::Success => "success",
                BrokerConclusion::Failure => "failure",
                BrokerConclusion::Cancelled => "cancelled",
                _ => "timed_out",
            },
            "output_sha256": hex::encode(Sha256::digest([output])),
            "output_length": 1,
            "output": char::from(output).to_string(),
        }))
        .unwrap();
        let stdout_digest: [u8; 32] = Sha256::digest(&stdout).into();
        let mut response = active.response;
        response.code = ResponseCode::Existing;
        response.broker_state = BrokerState::Terminal;
        response.conclusion = conclusion;
        response.generation += 1;
        response.updated_at += 1;
        response.evidence_set_digest = stdout_digest;
        let mut terminal = TerminalAttempt {
            admission: active.admission,
            response,
        };
        let stdout_descriptor = EvidenceDescriptor {
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
        };
        let mut descriptors = vec![stdout_descriptor];
        let mut evidence_bytes = vec![stdout];
        let mut artifact_receipt_digests: Vec<[u8; 32]> = Vec::new();
        if conclusion == BrokerConclusion::Success {
            let content = b"a";
            let artifact_document = FakeArtifactDocument {
                schema_version: 1,
                execution_binding_digest: hex::encode(response.execution_binding_digest),
                request_event_id: hex::encode(response.accepted_request_digest),
                run_id: hex::encode(response.run_id),
                workflow_id: "native-ci",
                workflow_digest: hex::encode(active.admission.workflow_digest),
                job_id: "test",
                attempt: active.admission.attempt,
                artifact_id: "result".to_owned(),
                name: "result.json".to_owned(),
                media_type: "application/json".to_owned(),
                sha256: hex::encode(Sha256::digest(content)),
                byte_length: 1,
                content_hex: hex::encode(content),
            };
            let bytes = serde_json::to_vec(&artifact_document).unwrap();
            let digest: [u8; 32] = Sha256::digest(&bytes).into();
            let receipt = FakeArtifactDocument {
                schema_version: 1,
                execution_binding_digest: hex::encode(response.execution_binding_digest),
                request_event_id: hex::encode(response.accepted_request_digest),
                run_id: hex::encode(response.run_id),
                workflow_id: "native-ci",
                workflow_digest: hex::encode(active.admission.workflow_digest),
                job_id: "test",
                attempt: active.admission.attempt,
                artifact_id: "result".to_owned(),
                name: "result.json".to_owned(),
                media_type: "application/json".to_owned(),
                sha256: hex::encode(digest),
                byte_length: bytes.len() as u32,
                content_hex: hex::encode(&bytes),
            };
            artifact_receipt_digests
                .push(Sha256::digest(serde_json::to_vec(&receipt).unwrap()).into());
            descriptors.push(EvidenceDescriptor {
                kind: EvidenceKind::Artifact,
                digest,
                length: bytes.len() as u32,
                artifact_name_digest: Sha256::digest(b"result.json").into(),
                artifact_media_type_digest: Sha256::digest(b"application/json").into(),
                artifact_id: WireText64::from_ascii("result").unwrap(),
                artifact_name: WireText64::from_ascii("result.json").unwrap(),
                artifact_media_type: WireText64::from_ascii("application/json").unwrap(),
                teardown_lease_id: [0; 16],
                teardown_lease_generation: 0,
                teardown_attestation_digest: [0; 32],
            });
            evidence_bytes.push(bytes);
        }
        let mut receipt_set = b"buzz-ci-execd:artifact-receipt-set:v1\0".to_vec();
        receipt_set.extend_from_slice(&response.execution_binding_digest);
        for digest in &artifact_receipt_digests {
            receipt_set.extend_from_slice(digest);
        }
        let teardown = serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "execution_binding_digest": hex::encode(response.execution_binding_digest),
            "evidence_set_digest": hex::encode(response.evidence_set_digest),
            "stop_reason": if conclusion == BrokerConclusion::Cancelled { "cancelled" } else { "completed" },
            "executor_receipt_digest": "aa".repeat(32),
            "request_event_id": hex::encode(response.accepted_request_digest),
            "run_id": hex::encode(response.run_id),
            "workflow_id": "native-ci",
            "workflow_digest": hex::encode(active.admission.workflow_digest),
            "job_id": "test",
            "attempt": active.admission.attempt,
            "lease_id": "bb".repeat(16),
            "lease_generation": response.lease_generation,
            "artifact_receipt_set_digest": hex::encode(Sha256::digest(receipt_set)),
        }))
        .unwrap();
        let teardown_digest: [u8; 32] = Sha256::digest(&teardown).into();
        terminal.response.teardown_digest = teardown_digest;
        descriptors.push(EvidenceDescriptor {
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
        });
        evidence_bytes.push(teardown);
        let descriptor_set_digest = fake_descriptor_set_digest(terminal, &descriptors);
        (
            terminal,
            FakeEvidence {
                descriptors,
                bytes: evidence_bytes,
                descriptor_set_digest,
            },
        )
    }

    impl RunnerV2Transport for FakeRunnerTransport {
        type Error = ();

        fn exchange_frame(
            &mut self,
            request: &[u8],
            response_length: usize,
            _transport_attempts: u32,
        ) -> Result<Vec<u8>, Self::Error> {
            let (header, request) = v2::decode_request(request).unwrap();
            let mut state = self.0.lock().unwrap();
            state.exchanges += 1;
            match request {
                Request::RegisterJobIntent(value) => {
                    if state.last_request != Some(value.admission.signed_request_digest) {
                        state.last_request = Some(value.admission.signed_request_digest);
                        state.active = None;
                        state.terminal = None;
                        state.evidence = None;
                    }
                    Ok(v2::encode_intent_registration_response(
                        header,
                        IntentRegistrationResponse {
                            code: if state.active.is_some() {
                                ResponseCode::Existing
                            } else {
                                ResponseCode::Ok
                            },
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
                    .to_vec())
                }
                Request::AdmitAttempt(admission) => {
                    let response = if let Some(terminal) = state.terminal {
                        let mut response = terminal.response;
                        if state.drift {
                            response.attempt_id[0] ^= 1;
                        }
                        response
                    } else if let Some(active) = state.active {
                        let mut response = active.response;
                        response.code = ResponseCode::Existing;
                        response
                    } else {
                        state.starts += 1;
                        *state
                            .starts_by_request
                            .entry(admission.signed_request_digest)
                            .or_default() += 1;
                        let active = BoundAttempt {
                            admission,
                            response: BrokerResponse {
                                code: ResponseCode::Ok,
                                retry_after_millis: 0,
                                attempt_id: [admission.attempt as u8; 16],
                                run_id: admission.run_id,
                                accepted_request_digest: admission.signed_request_digest,
                                job_intent_digest: admission.job_intent_digest,
                                execution_binding_digest: [admission.attempt as u8 + 20; 32],
                                tip_oid: Some(admission.tip_oid),
                                broker_state: BrokerState::Leased,
                                conclusion: BrokerConclusion::None,
                                terminal_reason: 0,
                                generation: 1,
                                accepted_at: admission.issued_at,
                                updated_at: admission.issued_at,
                                lease_generation: 1,
                                evidence_set_digest: [0; 32],
                                teardown_digest: [0; 32],
                                attempt: admission.attempt,
                            },
                        };
                        state.active = Some(active);
                        active.response
                    };
                    Ok(v2::encode_response(header, response).as_bytes().to_vec())
                }
                Request::GetAttempt(_) => {
                    if state.terminal.is_none() {
                        let active = state.active.unwrap();
                        let (terminal, evidence) = fake_terminal(active, state.conclusion);
                        state.terminal = Some(terminal);
                        state.evidence = Some(evidence);
                    }
                    Ok(
                        v2::encode_response(header, state.terminal.unwrap().response)
                            .as_bytes()
                            .to_vec(),
                    )
                }
                Request::CancelAttempt(_) => {
                    if state.terminal.is_none() {
                        state.cancels += 1;
                        let active = state.active.unwrap();
                        let (mut terminal, evidence) =
                            fake_terminal(active, BrokerConclusion::Cancelled);
                        terminal.response.code = ResponseCode::Ok;
                        state.terminal = Some(terminal);
                        state.evidence = Some(evidence);
                    }
                    Ok(
                        v2::encode_response(header, state.terminal.unwrap().response)
                            .as_bytes()
                            .to_vec(),
                    )
                }
                Request::DescribeAttemptEvidence(value) => {
                    let evidence = state.evidence.as_ref().unwrap();
                    let mut items = [None; v2::MAX_EVIDENCE_ITEMS];
                    for (slot, descriptor) in items.iter_mut().zip(&evidence.descriptors) {
                        *slot = Some(*descriptor);
                    }
                    let mut coordinates = value.coordinates;
                    if state.drift {
                        coordinates.attempt_id[0] ^= 1;
                    }
                    let response = EvidenceDescriptionResponse {
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
                    };
                    Ok(v2::encode_evidence_description_response(header, response)
                        .as_bytes()
                        .to_vec())
                }
                Request::ReadAttemptEvidence(value) => {
                    let bytes =
                        state.evidence.as_ref().unwrap().bytes[value.item_index as usize].clone();
                    let response = EvidenceChunkResponse {
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
                    };
                    Ok(v2::encode_evidence_chunk_response(header, &response)
                        .as_bytes()
                        .to_vec())
                }
                _ => unreachable!(),
            }
            .inspect(|response| assert_eq!(response.len(), response_length))
        }
    }

    type FakeExecutor = RunnerV2AttemptExecutor<FakeRunnerTransport, FakeAdmissionSigner>;
    type FakeController = CapacityOneController<
        FakeRelay,
        FakeCiSigner,
        FakeExecutor,
        FakeStore,
        RunnerV2EvidenceReader<FakeRunnerTransport>,
    >;
    type FakeService = CapacityOneService<
        FakeController,
        FakeRunnerTransport,
        FakeExecutor,
        FakeRelay,
        FakeAcceptanceSigner,
    >;

    fn provider_binding() -> AcceptanceBinding {
        let mut binding = canonical_acceptance_binding();
        binding.fixture.expected_log.sha256 = hex::encode(Sha256::digest(b"s"));
        binding.fixture.expected_failure_log.sha256 = hex::encode(Sha256::digest(b"f"));
        let event_id = Sha256::digest(serde_json::to_vec(&binding.acceptance.run_event).unwrap());
        let fields = binding.acceptance.run_event.as_array().unwrap();
        let envelope: CiRequestEnvelope =
            serde_json::from_str(fields[5].as_str().unwrap()).unwrap();
        let artifact = FakeArtifactDocument {
            schema_version: 1,
            execution_binding_digest: hex::encode([21; 32]),
            request_event_id: hex::encode(event_id),
            run_id: hex::encode(uuid::Uuid::parse_str(&envelope.run_id).unwrap().as_bytes()),
            workflow_id: &envelope.workflow_id,
            workflow_digest: envelope.workflow_digest,
            job_id: &binding.fixture.job_id,
            attempt: 1,
            artifact_id: "result".to_owned(),
            name: "result.json".to_owned(),
            media_type: "application/json".to_owned(),
            sha256: hex::encode(Sha256::digest(b"a")),
            byte_length: 1,
            content_hex: hex::encode(b"a"),
        };
        let artifact = serde_json::to_vec(&artifact).unwrap();
        binding.fixture.expected_artifacts[0].sha256 = hex::encode(Sha256::digest(&artifact));
        binding.fixture.expected_artifacts[0].bytes = artifact.len() as u64;
        let plans = std::iter::once((
            "log",
            &binding.fixture.expected_log,
            format!(
                "https://relay.invalid/ci/logs/{}/{}/{}/1/{}",
                hex::encode(event_id),
                envelope.run_id,
                binding.fixture.job_id,
                binding.fixture.expected_log.sha256
            ),
        ))
        .chain(binding.fixture.expected_artifacts.iter().map(|object| {
            (
                "artifact",
                object,
                format!(
                    "https://relay.invalid/ci/artifacts/{}/{}/{}/1/result/{}",
                    hex::encode(event_id),
                    envelope.run_id,
                    binding.fixture.job_id,
                    object.sha256
                ),
            )
        }));
        let mut transcript = Vec::from(b"buzz-ci-acceptance-export-authority:v1\0".as_slice());
        let generation = binding.fixture.export_generation.to_string();
        for (kind, object, url) in plans {
            let event_id_hex = hex::encode(event_id);
            let byte_length = object.bytes.to_string();
            for field in [
                "GET",
                url.as_str(),
                binding.fixture.export_subject.as_str(),
                generation.as_str(),
                event_id_hex.as_str(),
                envelope.run_id.as_str(),
                binding.fixture.job_id.as_str(),
                "1",
                kind,
                object.name.as_str(),
                object.sha256.as_str(),
                byte_length.as_str(),
            ] {
                transcript.extend_from_slice(&(field.len() as u64).to_be_bytes());
                transcript.extend_from_slice(field.as_bytes());
            }
        }
        binding.fixture.export_authorization_digest = hex::encode(Sha256::digest(transcript));
        binding
            .acceptance
            .export_subject
            .clone_from(&binding.fixture.export_subject);
        binding.acceptance.export_generation = binding.fixture.export_generation;
        binding
            .acceptance
            .export_authorization_digest
            .clone_from(&binding.fixture.export_authorization_digest);
        binding
    }

    fn frozen_request(
        binding: &AcceptanceBinding,
        mutation: AcceptanceMutation,
    ) -> AcceptedRequest {
        let authority = AcceptanceAuthority::new(binding).unwrap();
        let index = AcceptanceAuthority::index(mutation);
        let fields = authority.templates[index].as_array().unwrap();
        AcceptedRequest {
            channel_id: "123e4567-e89b-12d3-a456-426614174099".to_owned(),
            watch_cursor: 1,
            event_id: hex::encode(authority.event_ids[index]),
            envelope: serde_json::from_str(fields[5].as_str().unwrap()).unwrap(),
        }
    }

    fn runner_bindings(binding: &AcceptanceBinding) -> StaticAdmissionBindings {
        let request = frozen_request(binding, AcceptanceMutation::Run);
        StaticAdmissionBindings {
            audience_digest: [31; 32],
            isolation_profile_digest: [32; 32],
            lane_manifest_digest: [33; 32],
            lane_epoch: 1,
            admission_key_generation: 1,
            workflow_id: request.envelope.workflow_id.clone(),
            workflow_digest: hex::decode(&request.envelope.workflow_digest)
                .unwrap()
                .try_into()
                .unwrap(),
            job_ids: vec![binding.fixture.job_id.clone()],
            artifacts: vec![StaticArtifactBinding {
                artifact_id: "result".to_owned(),
                name: binding.fixture.expected_artifacts[0].name.clone(),
                media_type: "application/json".to_owned(),
                relative_name: "result.json".to_owned(),
                max_bytes: 4096,
            }],
        }
    }

    fn fake_service(
        root: &std::path::Path,
        owner_uid: u32,
        binding: &AcceptanceBinding,
        relay: FakeRelay,
        store: FakeStore,
        runner: FakeRunnerTransport,
    ) -> FakeService {
        relay.0.lock().unwrap().nip98_generation = binding.fixture.export_generation;
        let bindings = runner_bindings(binding);
        let metadata = JobMetadata {
            job_id: binding.fixture.job_id.clone(),
            name: "test".to_owned(),
            required: true,
            skip_policy: CiSkipPolicy::Forbid,
            selected_job_instance: "test".to_owned(),
            also_reruns: Vec::new(),
        };
        let poll_interval = Duration::from_millis(1);
        let (observation_sender, observations) = mpsc::channel();
        let (attempt_commands, command_receiver) = mpsc::channel();
        let (recovery_sender, recovery_observations) = mpsc::channel();
        let (executor, output) = compose_runner_v2(
            RunnerV2Client::new(runner.clone(), 1).unwrap(),
            FakeAdmissionSigner,
            bindings.clone(),
            metadata.clone(),
            binding.acceptance.actor.public_key.clone(),
            poll_interval,
            AttemptControl {
                observer: Some(observation_sender),
                command: Some(command_receiver),
            },
        )
        .unwrap();
        let (recovery_executor, _) = compose_runner_v2(
            RunnerV2Client::new(runner.clone(), 1).unwrap(),
            FakeAdmissionSigner,
            bindings,
            metadata,
            binding.acceptance.actor.public_key.clone(),
            poll_interval,
            AttemptControl {
                observer: Some(recovery_sender),
                command: None,
            },
        )
        .unwrap();
        let config = CapacityOneConfig::new(
            "123e4567-e89b-12d3-a456-426614174099".to_owned(),
            poll_interval,
            1,
        )
        .unwrap();
        let controller = CapacityOneController::activate(
            config,
            CapacityOneProviderSlots::new(
                Some(relay.clone()),
                Some(FakeCiSigner(binding.acceptance.actor.public_key.clone())),
                Some(executor),
                Some(store),
                Some(output),
            ),
        )
        .unwrap();
        let status = controller.status();
        FakeService {
            controller: Some(controller),
            controller_worker: None,
            observations,
            attempt_commands,
            active_attempt: None,
            terminal_attempt: None,
            verified_evidence: None,
            gate_waiting: false,
            cancel_client: RunnerV2Client::new(runner, 1).unwrap(),
            recovery_executor,
            recovery_observations,
            acceptance_channel_id: "123e4567-e89b-12d3-a456-426614174099".to_owned(),
            acceptance_relay: relay,
            acceptance_signer: FakeAcceptanceSigner,
            acceptance_authority: AcceptanceAuthority::new(binding).unwrap(),
            status,
            poll_interval,
            acceptance: AcceptanceJournal::open(
                root.canonicalize().unwrap(),
                owner_uid,
                binding.clone(),
            )
            .unwrap(),
            background_polling: false,
            crash_before_provider_effect: false,
            crash_after_provider_effect: false,
        }
    }

    fn prime_journal(
        journal: &AcceptanceJournal,
        through: u32,
        last_response: Option<AdapterResponse>,
    ) {
        for sequence in 1..=through {
            let request = sequence_request(sequence, None);
            let exact = serde_json::to_vec(&request).unwrap();
            let capacity = u32::from(sequence != 1);
            let response = if sequence == through {
                last_response
                    .clone()
                    .map(|response| rebind_response(response, &request))
                    .unwrap_or_else(|| host_response(&request, None, capacity))
            } else {
                host_response(&request, None, capacity)
            };
            journal
                .execute(&request, &exact, capacity, |_, _| {
                    Ok::<_, AcceptanceSocketError>(response)
                })
                .unwrap();
        }
    }

    fn rebind_response(mut response: AdapterResponse, request: &AdapterRequest) -> AdapterResponse {
        response.sequence = request.sequence;
        response.operation = request.operation;
        response
            .scenario_sha256
            .clone_from(&request.scenario_sha256);
        response.operation_id.clone_from(&request.operation_id);
        response.response.sequence = request.sequence;
        response.response.operation = request.operation;
        response
    }

    fn handle(
        service: &mut FakeService,
        request: &AdapterRequest,
    ) -> Result<AdapterResponse, AcceptanceSocketError> {
        AcceptanceOperationHandler::handle(service, request, &serde_json::to_vec(request).unwrap())
    }

    fn quiesce_crashed_worker(service: &mut FakeService) {
        let (replacement, _receiver) = mpsc::channel();
        let sender = std::mem::replace(&mut service.attempt_commands, replacement);
        drop(sender);
        if let Some(worker) = service.controller_worker.take() {
            let _ = worker.join().unwrap();
        }
    }

    fn provider_root() -> (TempDir, u32) {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let owner_uid = fs::metadata(root.path()).unwrap().uid();
        (root, owner_uid)
    }

    fn drive_first_terminal(service: &mut FakeService) -> String {
        prime_journal(&service.acceptance, 2, None);
        handle(service, &sequence_request(3, None)).unwrap();
        handle(service, &sequence_request(4, None)).unwrap();
        let resume = sequence_request(5, None);
        handle(service, &resume).unwrap();
        AcceptanceOperationHandler::response_written(service, &resume).unwrap();
        handle(service, &sequence_request(6, None))
            .unwrap()
            .response
            .snapshot
            .run
            .unwrap()
            .selected_attempt_id
            .unwrap()
    }

    #[test]
    fn stage_seven_reads_live_once_retries_fresh_after_crash_and_replays_staged() {
        for crash_before in [None, Some(true), Some(false)] {
            let binding = provider_binding();
            let (root, owner_uid) = provider_root();
            let relay = FakeRelay::default();
            relay
                .0
                .lock()
                .unwrap()
                .accepted
                .push_back(frozen_request(&binding, AcceptanceMutation::Run));
            let store = FakeStore::default();
            let runner_state = Arc::new(Mutex::new(FakeRunnerState {
                conclusion: BrokerConclusion::Success,
                active: None,
                terminal: None,
                evidence: None,
                starts: 0,
                starts_by_request: HashMap::new(),
                last_request: None,
                cancels: 0,
                drift: false,
                exchanges: 0,
            }));
            let runner = FakeRunnerTransport(runner_state.clone());
            let mut service = fake_service(
                root.path(),
                owner_uid,
                &binding,
                relay.clone(),
                store.clone(),
                runner.clone(),
            );
            let attempt_id = drive_first_terminal(&mut service);
            assert_eq!(attempt_id.len(), 32);
            let request = sequence_request(7, Some(attempt_id));
            let before_relay = relay.0.lock().unwrap().clone();
            let before_store = store.0.lock().unwrap().clone();
            let before_runner = {
                let state = runner_state.lock().unwrap();
                (state.starts, state.cancels, state.exchanges)
            };
            let response = if let Some(before) = crash_before {
                service.inject_provider_crash(before);
                assert!(catch_unwind(AssertUnwindSafe(|| handle(&mut service, &request))).is_err());
                let reads_after_crash = relay.0.lock().unwrap().export_reads;
                assert_eq!(reads_after_crash, if before { 0 } else { 8 });
                let mut reopened = fake_service(
                    root.path(),
                    owner_uid,
                    &binding,
                    relay.clone(),
                    store.clone(),
                    runner.clone(),
                );
                let response = handle(&mut reopened, &request).unwrap();
                assert!(response
                    .response
                    .export
                    .as_ref()
                    .is_some_and(|export| export.authenticated));
                let reads_after_retry = relay.0.lock().unwrap().export_reads;
                assert_eq!(reads_after_retry, if before { 8 } else { 16 });
                let replay = handle(&mut reopened, &request).unwrap();
                assert_eq!(
                    serde_json::to_vec(&response).unwrap(),
                    serde_json::to_vec(&replay).unwrap()
                );
                assert_eq!(relay.0.lock().unwrap().export_reads, reads_after_retry);
                response
            } else {
                let result = handle(&mut service, &request);
                assert!(
                    result.is_ok(),
                    "stage 7 failed: {result:?}; reads={}",
                    relay.0.lock().unwrap().export_reads
                );
                let response = result.unwrap();
                let reads = relay.0.lock().unwrap().export_reads;
                assert_eq!(reads, 8);
                assert!(response
                    .response
                    .export
                    .as_ref()
                    .is_some_and(|export| export.authenticated));
                assert_eq!(handle(&mut service, &request).unwrap(), response);
                assert_eq!(relay.0.lock().unwrap().export_reads, reads);
                response
            };
            assert!(response.response.export.is_some());
            let after_relay = relay.0.lock().unwrap().clone();
            assert_eq!(after_relay.published, before_relay.published);
            assert_eq!(after_relay.publish_calls, before_relay.publish_calls);
            let after_store = store.0.lock().unwrap();
            assert_eq!(after_store.cursor, before_store.cursor);
            assert_eq!(after_store.runs, before_store.runs);
            assert_eq!(after_store.publications, before_store.publications);
            drop(after_store);
            assert_eq!(
                {
                    let state = runner_state.lock().unwrap();
                    (state.starts, state.cancels, state.exchanges)
                },
                before_runner
            );

            let mut mismatched = request.clone();
            mismatched.host.integrated_candidate_sha = "00".repeat(32);
            let relay_before_mismatch = relay.0.lock().unwrap().clone();
            let store_before_mismatch = store.0.lock().unwrap().clone();
            let runner_before_mismatch = {
                let state = runner_state.lock().unwrap();
                (state.starts, state.cancels, state.exchanges)
            };
            assert_eq!(
                handle(&mut service, &mismatched),
                Err(AcceptanceSocketError::Replay)
            );
            let relay_after_mismatch = relay.0.lock().unwrap();
            assert_eq!(
                relay_after_mismatch.export_reads,
                relay_before_mismatch.export_reads
            );
            assert_eq!(
                relay_after_mismatch.published,
                relay_before_mismatch.published
            );
            assert_eq!(
                relay_after_mismatch.publish_calls,
                relay_before_mismatch.publish_calls
            );
            drop(relay_after_mismatch);
            let store_after_mismatch = store.0.lock().unwrap();
            assert_eq!(store_after_mismatch.cursor, store_before_mismatch.cursor);
            assert_eq!(store_after_mismatch.runs, store_before_mismatch.runs);
            assert_eq!(
                store_after_mismatch.publications,
                store_before_mismatch.publications
            );
            assert_eq!(
                store_after_mismatch.deferred,
                store_before_mismatch.deferred
            );
            drop(store_after_mismatch);
            assert_eq!(
                {
                    let state = runner_state.lock().unwrap();
                    (state.starts, state.cancels, state.exchanges)
                },
                runner_before_mismatch
            );
        }
    }

    #[test]
    fn stage_seven_after_restart_uses_only_relay_readback_and_prior_receipt() {
        let binding = provider_binding();
        let (root, owner_uid) = provider_root();
        let relay = FakeRelay::default();
        relay
            .0
            .lock()
            .unwrap()
            .accepted
            .push_back(frozen_request(&binding, AcceptanceMutation::Run));
        let store = FakeStore::default();
        let runner_state = Arc::new(Mutex::new(FakeRunnerState {
            conclusion: BrokerConclusion::Success,
            active: None,
            terminal: None,
            evidence: None,
            starts: 0,
            starts_by_request: HashMap::new(),
            last_request: None,
            cancels: 0,
            drift: false,
            exchanges: 0,
        }));
        let runner = FakeRunnerTransport(runner_state.clone());
        let mut service = fake_service(
            root.path(),
            owner_uid,
            &binding,
            relay.clone(),
            store.clone(),
            runner.clone(),
        );
        let attempt_id = drive_first_terminal(&mut service);
        {
            let mut state = runner_state.lock().unwrap();
            state.active = None;
            state.terminal = None;
            state.evidence = None;
            state.last_request = None;
            state.drift = true;
        }
        let before_relay = relay.0.lock().unwrap().clone();
        let before_store = store.0.lock().unwrap().clone();
        let before_runner = {
            let state = runner_state.lock().unwrap();
            (state.starts, state.cancels, state.exchanges)
        };
        let mut reopened = fake_service(
            root.path(),
            owner_uid,
            &binding,
            relay.clone(),
            store.clone(),
            runner,
        );
        let response = handle(&mut reopened, &sequence_request(7, Some(attempt_id))).unwrap();
        assert!(response.response.export.is_some());
        let after_relay = relay.0.lock().unwrap();
        assert_eq!(after_relay.export_reads, before_relay.export_reads + 8);
        assert_eq!(after_relay.published, before_relay.published);
        assert_eq!(after_relay.publish_calls, before_relay.publish_calls);
        let after_store = store.0.lock().unwrap();
        assert_eq!(after_store.cursor, before_store.cursor);
        assert_eq!(after_store.runs, before_store.runs);
        assert_eq!(after_store.publications, before_store.publications);
        assert_eq!(
            {
                let state = runner_state.lock().unwrap();
                (state.starts, state.cancels, state.exchanges)
            },
            before_runner
        );
        assert_eq!(
            reopened.status.state(),
            buzz_ci_controld::controller::ControllerState::Ready
        );
    }

    #[test]
    fn stage_seven_rejects_unavailable_tampered_and_fixture_echo_providers() {
        for drift in [
            "unavailable",
            "event_subject",
            "object_subject",
            "generation",
            "fixture_echo",
        ] {
            let binding = provider_binding();
            let (root, owner_uid) = provider_root();
            let relay = FakeRelay::default();
            relay
                .0
                .lock()
                .unwrap()
                .accepted
                .push_back(frozen_request(&binding, AcceptanceMutation::Run));
            let store = FakeStore::default();
            let runner_state = Arc::new(Mutex::new(FakeRunnerState {
                conclusion: BrokerConclusion::Success,
                active: None,
                terminal: None,
                evidence: None,
                starts: 0,
                starts_by_request: HashMap::new(),
                last_request: None,
                cancels: 0,
                drift: false,
                exchanges: 0,
            }));
            let runner = FakeRunnerTransport(runner_state.clone());
            let mut service = fake_service(
                root.path(),
                owner_uid,
                &binding,
                relay.clone(),
                store.clone(),
                runner,
            );
            let attempt_id = drive_first_terminal(&mut service);
            let before_store = store.0.lock().unwrap().clone();
            let before_relay = relay.0.lock().unwrap().clone();
            let before_runner = {
                let state = runner_state.lock().unwrap();
                (state.starts, state.cancels, state.exchanges)
            };
            {
                let mut state = relay.0.lock().unwrap();
                match drift {
                    "unavailable" => state.export_error = Some(ExportReadError::Unavailable),
                    "event_subject" => state.event_proof_subject = Some("ef".repeat(32)),
                    "object_subject" => state.object_proof_subject = Some("ef".repeat(32)),
                    "generation" => {
                        state.object_proof_generation =
                            Some(binding.fixture.export_generation.saturating_add(1))
                    }
                    "fixture_echo" => state.objects.clear(),
                    _ => unreachable!(),
                }
            }
            assert_eq!(
                handle(&mut service, &sequence_request(7, Some(attempt_id))),
                Err(AcceptanceSocketError::Operation),
                "{drift}"
            );
            assert_eq!(
                {
                    let state = runner_state.lock().unwrap();
                    (state.starts, state.cancels, state.exchanges)
                },
                before_runner
            );
            let after_relay = relay.0.lock().unwrap();
            assert_eq!(after_relay.published, before_relay.published);
            assert_eq!(after_relay.publish_calls, before_relay.publish_calls);
            drop(after_relay);
            let after_store = store.0.lock().unwrap();
            assert_eq!(after_store.cursor, before_store.cursor);
            assert_eq!(after_store.runs, before_store.runs);
            assert_eq!(after_store.publications, before_store.publications);
            assert_eq!(
                service.status.state(),
                buzz_ci_controld::controller::ControllerState::Ready
            );
        }
    }

    #[test]
    fn stage_seven_rejects_signed_canonical_wrong_object_coordinates_before_get() {
        for (drift, expected_queries) in [("log", 2), ("artifact", 3)] {
            let binding = provider_binding();
            let (root, owner_uid) = provider_root();
            let relay = FakeRelay::default();
            {
                let mut state = relay.0.lock().unwrap();
                state
                    .accepted
                    .push_back(frozen_request(&binding, AcceptanceMutation::Run));
                state.put_url_drift = Some(drift.to_owned());
            }
            let store = FakeStore::default();
            let runner_state = Arc::new(Mutex::new(FakeRunnerState {
                conclusion: BrokerConclusion::Success,
                active: None,
                terminal: None,
                evidence: None,
                starts: 0,
                starts_by_request: HashMap::new(),
                last_request: None,
                cancels: 0,
                drift: false,
                exchanges: 0,
            }));
            let mut service = fake_service(
                root.path(),
                owner_uid,
                &binding,
                relay.clone(),
                store,
                FakeRunnerTransport(runner_state.clone()),
            );
            let attempt_id = drive_first_terminal(&mut service);
            let reads_before = relay.0.lock().unwrap().export_reads;
            let runner_before = {
                let state = runner_state.lock().unwrap();
                (state.starts, state.cancels, state.exchanges)
            };
            assert_eq!(
                handle(&mut service, &sequence_request(7, Some(attempt_id))),
                Err(AcceptanceSocketError::Operation),
                "{drift}"
            );
            assert_eq!(
                relay.0.lock().unwrap().export_reads - reads_before,
                expected_queries,
                "the canonical tuple drift must fail before an object GET"
            );
            assert_eq!(
                {
                    let state = runner_state.lock().unwrap();
                    (state.starts, state.cancels, state.exchanges)
                },
                runner_before
            );
        }
    }

    #[test]
    fn capacity_one_handle_recovers_terminal_provider_crashes_without_reexecution() {
        for (sequence, mutation, conclusion, publish_sequence, resume_sequence) in [
            (6, AcceptanceMutation::Run, BrokerConclusion::Success, 3, 5),
            (
                10,
                AcceptanceMutation::FailureRun,
                BrokerConclusion::Failure,
                8,
                9,
            ),
        ] {
            let binding = provider_binding();
            let (root, owner_uid) = provider_root();
            let relay = FakeRelay::default();
            relay
                .0
                .lock()
                .unwrap()
                .accepted
                .push_back(frozen_request(&binding, mutation));
            let store = FakeStore::default();
            let runner_state = Arc::new(Mutex::new(FakeRunnerState {
                conclusion,
                active: None,
                terminal: None,
                evidence: None,
                starts: 0,
                starts_by_request: HashMap::new(),
                last_request: None,
                cancels: 0,
                drift: false,
                exchanges: 0,
            }));
            let runner = FakeRunnerTransport(runner_state.clone());
            let mut service = fake_service(
                root.path(),
                owner_uid,
                &binding,
                relay.clone(),
                store.clone(),
                runner.clone(),
            );
            prime_journal(&service.acceptance, publish_sequence - 1, None);
            for stage in publish_sequence..=resume_sequence {
                let request = sequence_request(stage, None);
                handle(&mut service, &request).unwrap();
                if stage == resume_sequence {
                    AcceptanceOperationHandler::response_written(&mut service, &request).unwrap();
                }
            }
            let target = sequence_request(sequence, None);
            service.inject_provider_crash(false);
            let crash = catch_unwind(AssertUnwindSafe(|| handle(&mut service, &target)));
            assert!(
                crash.is_err(),
                "unexpected target result: {crash:?}, status: {:?}",
                service.status
            );
            let published = relay.0.lock().unwrap().published.clone();
            assert!(!published.is_empty());
            assert_eq!(runner_state.lock().unwrap().starts, 1);

            let mut reopened = fake_service(
                root.path(),
                owner_uid,
                &binding,
                relay.clone(),
                store.clone(),
                runner.clone(),
            );
            let exact = serde_json::to_vec(&target).unwrap();
            let calls_before = {
                let state = runner_state.lock().unwrap();
                (state.starts, state.cancels)
            };
            let mut mismatched = exact.clone();
            mismatched.push(b' ');
            assert_eq!(
                AcceptanceOperationHandler::handle(&mut reopened, &target, &mismatched),
                Err(AcceptanceSocketError::Replay)
            );
            assert_eq!(
                {
                    let state = runner_state.lock().unwrap();
                    (state.starts, state.cancels)
                },
                calls_before
            );
            let recovered =
                AcceptanceOperationHandler::handle(&mut reopened, &target, &exact).unwrap();
            let recovered_bytes = serde_json::to_vec(&recovered).unwrap();
            let replayed =
                AcceptanceOperationHandler::handle(&mut reopened, &target, &exact).unwrap();
            assert_eq!(serde_json::to_vec(&replayed).unwrap(), recovered_bytes);
            assert_eq!(runner_state.lock().unwrap().starts, 1);
            let relay_state = relay.0.lock().unwrap();
            assert_eq!(relay_state.published, published);
            assert!(relay_state.publish_calls.values().all(|calls| *calls == 1));

            let drift_binding = provider_binding();
            let (drift_root, drift_owner) = provider_root();
            let drift_relay = FakeRelay::default();
            drift_relay
                .0
                .lock()
                .unwrap()
                .accepted
                .push_back(frozen_request(&drift_binding, mutation));
            let drift_store = FakeStore::default();
            let drift_state = Arc::new(Mutex::new(FakeRunnerState {
                conclusion,
                active: None,
                terminal: None,
                evidence: None,
                starts: 0,
                starts_by_request: HashMap::new(),
                last_request: None,
                cancels: 0,
                drift: false,
                exchanges: 0,
            }));
            let drift_runner = FakeRunnerTransport(drift_state.clone());
            let mut crashing = fake_service(
                drift_root.path(),
                drift_owner,
                &drift_binding,
                drift_relay.clone(),
                drift_store.clone(),
                drift_runner.clone(),
            );
            prime_journal(&crashing.acceptance, publish_sequence - 1, None);
            for stage in publish_sequence..=resume_sequence {
                let request = sequence_request(stage, None);
                handle(&mut crashing, &request).unwrap();
                if stage == resume_sequence {
                    AcceptanceOperationHandler::response_written(&mut crashing, &request).unwrap();
                }
            }
            crashing.inject_provider_crash(false);
            assert!(catch_unwind(AssertUnwindSafe(|| handle(&mut crashing, &target))).is_err());
            drift_state.lock().unwrap().drift = true;
            let drift_published = drift_relay.0.lock().unwrap().published.clone();
            let mut drifted = fake_service(
                drift_root.path(),
                drift_owner,
                &drift_binding,
                drift_relay.clone(),
                drift_store,
                drift_runner,
            );
            assert_eq!(
                handle(&mut drifted, &target),
                Err(AcceptanceSocketError::Operation)
            );
            let state = drift_state.lock().unwrap();
            assert_eq!((state.starts, state.cancels), (1, 0));
            let relay_state = drift_relay.0.lock().unwrap();
            assert_eq!(relay_state.published, drift_published);
            assert!(relay_state.publish_calls.values().all(|calls| *calls == 1));
        }
    }

    #[test]
    fn capacity_one_handle_recovers_cancel_across_active_terminal_and_advanced_cursor() {
        let mut canonical_bytes: Option<Vec<u8>> = None;
        for recovery in ["active", "terminal", "cursor_advanced", "drift"] {
            let binding = provider_binding();
            let (root, owner_uid) = provider_root();
            let relay = FakeRelay::default();
            let failure_accepted = frozen_request(&binding, AcceptanceMutation::FailureRun);
            let mut rerun_accepted = frozen_request(&binding, AcceptanceMutation::Rerun);
            rerun_accepted.watch_cursor = 2;
            relay
                .0
                .lock()
                .unwrap()
                .accepted
                .extend([failure_accepted, rerun_accepted]);
            let store = FakeStore::default();
            let runner_state = Arc::new(Mutex::new(FakeRunnerState {
                conclusion: BrokerConclusion::Failure,
                active: None,
                terminal: None,
                evidence: None,
                starts: 0,
                starts_by_request: HashMap::new(),
                last_request: None,
                cancels: 0,
                drift: false,
                exchanges: 0,
            }));
            let runner = FakeRunnerTransport(runner_state.clone());
            let mut service = fake_service(
                root.path(),
                owner_uid,
                &binding,
                relay.clone(),
                store.clone(),
                runner.clone(),
            );
            prime_journal(&service.acceptance, 7, None);
            handle(&mut service, &sequence_request(8, None)).unwrap();
            let resume_failure = sequence_request(9, None);
            handle(&mut service, &resume_failure).unwrap();
            AcceptanceOperationHandler::response_written(&mut service, &resume_failure).unwrap();
            let failure_result = handle(&mut service, &sequence_request(10, None));
            assert!(
                failure_result.is_ok(),
                "failure finish failed: {failure_result:?}; status: {:?}",
                service.status
            );
            let failure_response = failure_result.unwrap();
            let first_id = failure_response
                .response
                .snapshot
                .run
                .as_ref()
                .unwrap()
                .attempts[0]
                .attempt_id
                .clone();
            let rerun = sequence_request(11, Some(first_id));
            let rerun_result = handle(&mut service, &rerun);
            assert!(
                rerun_result.is_ok(),
                "rerun failed: {rerun_result:?}; status: {:?}; store: {:?}",
                service.status,
                store.0.lock().unwrap().runs
            );
            let rerun_response = rerun_result.unwrap();
            let second_id = rerun_response
                .response
                .snapshot
                .run
                .as_ref()
                .unwrap()
                .attempts[1]
                .attempt_id
                .clone();
            let cancel = sequence_request(12, Some(second_id));

            if recovery == "active" {
                service.inject_provider_crash(true);
                assert!(catch_unwind(AssertUnwindSafe(|| handle(&mut service, &cancel))).is_err());
            } else {
                if recovery == "terminal" {
                    store.0.lock().unwrap().fail_cursor_once = true;
                    assert_eq!(
                        handle(&mut service, &cancel),
                        Err(AcceptanceSocketError::Operation)
                    );
                } else {
                    service.inject_provider_crash(false);
                    assert!(
                        catch_unwind(AssertUnwindSafe(|| handle(&mut service, &cancel))).is_err()
                    );
                }
            }
            let published = relay.0.lock().unwrap().published.clone();
            let calls = {
                let state = runner_state.lock().unwrap();
                (state.starts, state.cancels)
            };
            assert_eq!(calls.0, 2);
            assert_eq!(calls.1, usize::from(recovery != "active"));
            let rerun_event: [u8; 32] =
                hex::decode(&frozen_request(&binding, AcceptanceMutation::Rerun).event_id)
                    .unwrap()
                    .try_into()
                    .unwrap();
            assert_eq!(
                runner_state.lock().unwrap().starts_by_request[&rerun_event],
                1
            );

            let store_at_crash = store.0.lock().unwrap().clone();
            let relay_at_crash = relay.0.lock().unwrap().clone();
            quiesce_crashed_worker(&mut service);
            if recovery == "active" {
                *store.0.lock().unwrap() = store_at_crash;
                *relay.0.lock().unwrap() = relay_at_crash;
            }
            drop(service);
            let mut reopened = fake_service(
                root.path(),
                owner_uid,
                &binding,
                relay.clone(),
                store.clone(),
                runner.clone(),
            );
            if recovery == "drift" {
                runner_state.lock().unwrap().drift = true;
            }
            let exact = serde_json::to_vec(&cancel).unwrap();
            let before_retry = {
                let state = runner_state.lock().unwrap();
                (state.starts, state.cancels)
            };
            let mut mismatched = exact.clone();
            mismatched.push(b' ');
            assert_eq!(
                AcceptanceOperationHandler::handle(&mut reopened, &cancel, &mismatched),
                Err(AcceptanceSocketError::Replay)
            );
            assert_eq!(
                {
                    let state = runner_state.lock().unwrap();
                    (state.starts, state.cancels)
                },
                before_retry
            );

            if recovery == "drift" {
                assert_eq!(
                    AcceptanceOperationHandler::handle(&mut reopened, &cancel, &exact),
                    Err(AcceptanceSocketError::Operation)
                );
                let state = runner_state.lock().unwrap();
                assert_eq!((state.starts, state.cancels), (2, 1));
            } else {
                let recovery_result =
                    AcceptanceOperationHandler::handle(&mut reopened, &cancel, &exact);
                assert!(
                    recovery_result.is_ok(),
                    "{recovery} recovery failed: {recovery_result:?}; status: {:?}; runs: {:?}; runner: {:?}",
                    reopened.status,
                    store.0.lock().unwrap().runs,
                    runner_state.lock().unwrap()
                );
                let response = recovery_result.unwrap();
                let bytes = serde_json::to_vec(&response).unwrap();
                if let Some(canonical) = &canonical_bytes {
                    assert_eq!(
                        &bytes, canonical,
                        "{recovery} changed cancel response bytes"
                    );
                } else {
                    canonical_bytes = Some(bytes.clone());
                }
                let replay =
                    AcceptanceOperationHandler::handle(&mut reopened, &cancel, &exact).unwrap();
                assert_eq!(serde_json::to_vec(&replay).unwrap(), bytes);
                let state = runner_state.lock().unwrap();
                assert_eq!((state.starts, state.cancels), (2, 1));
            }
            let relay_state = relay.0.lock().unwrap();
            if recovery == "active" {
                assert!(published.is_subset(&relay_state.published));
            } else {
                assert_eq!(relay_state.published, published);
            }
            assert!(relay_state.publish_calls.values().all(|calls| *calls == 1));
        }
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

    fn observation_for(expected: &AcceptedRequestBinding) -> BoundAttempt {
        let mut observed = active_binding();
        let envelope = &expected.envelope;
        observed.admission.signed_request_digest = decode_array(&expected.event_id).unwrap();
        observed.admission.actor_pubkey = decode_array(&envelope.actor).unwrap();
        observed.admission.idempotency_digest = Sha256::digest(
            Uuid::parse_str(&envelope.idempotency_key)
                .unwrap()
                .as_bytes(),
        )
        .into();
        observed.admission.source_pin_event_id = decode_array(&envelope.trigger_event_id).unwrap();
        observed.admission.workflow_digest = decode_array(&envelope.workflow_digest).unwrap();
        observed.admission.run_id = *Uuid::parse_str(&envelope.run_id).unwrap().as_bytes();
        observed.admission.tip_oid = decode_git_oid(&envelope.tip_oid).unwrap();
        observed.admission.base_oid = decode_git_oid(&envelope.base_oid).unwrap();
        observed.admission.issued_at = envelope.issued_at;
        observed.admission.expires_at = envelope.expires_at;
        observed.admission.wall_timeout_seconds = envelope.timeout_seconds.try_into().unwrap();
        observed.admission.attempt = envelope.attempt;
        observed.admission.parent_attempt = envelope.parent_attempt.unwrap_or(0);
        observed.response.accepted_request_digest = observed.admission.signed_request_digest;
        observed.response.run_id = observed.admission.run_id;
        observed.response.tip_oid = Some(observed.admission.tip_oid);
        observed.response.attempt = observed.admission.attempt;
        observed
    }

    fn rerun_request(attempt_id: Option<&str>) -> AdapterRequest {
        let binding = provider_binding();
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

        let response = running_response(
            &rerun_request(Some(&first_id)),
            Some(&prior),
            active,
            true,
            false,
        )
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
                running_response(&rerun_request(foreign), Some(&prior), active, true, false)
                    .map(|_| ()),
                Err(AcceptanceSocketError::Operation),
                "request attempt id {foreign:?}"
            );
        }
        assert_eq!(
            running_response(&rerun_request(Some(&first_id)), None, active, true, false)
                .map(|_| ()),
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
            running_response(&resume, None, first, false, false).expect("first attempt running");
        assert_eq!(
            response.response.snapshot.run.expect("run").attempts.len(),
            1
        );
        resume.attempt_id = Some(first_id.clone());
        assert_eq!(
            running_response(&resume, None, first, false, false).map(|_| ()),
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

    fn terminal_fixture(
        request: &AdapterRequest,
        conclusion: BrokerConclusion,
        attempt: u32,
    ) -> (TerminalAttempt, VerifiedAttemptEvidence) {
        let mut active = active_binding();
        active.admission.attempt = attempt;
        active.admission.parent_attempt = attempt.saturating_sub(1);
        active.response.attempt = attempt;
        active.response.broker_state = BrokerState::Terminal;
        active.response.conclusion = conclusion;
        active.response.generation += 1;
        active.response.updated_at += 1;
        active.response.evidence_set_digest = [16; 32];
        active.response.teardown_digest = [17; 32];
        let terminal = TerminalAttempt {
            admission: active.admission,
            response: active.response,
        };
        let log = if conclusion == BrokerConclusion::Success {
            &request.fixture.expected_log
        } else {
            &request.fixture.expected_failure_log
        };
        let artifacts = if conclusion == BrokerConclusion::Success {
            request
                .fixture
                .expected_artifacts
                .iter()
                .map(
                    |artifact| buzz_ci_controld::production_v2::VerifiedArtifactEvidence {
                        name: artifact.name.clone(),
                        sha256: artifact.sha256.clone(),
                        bytes: artifact.bytes,
                    },
                )
                .collect()
        } else {
            Vec::new()
        };
        let evidence = VerifiedAttemptEvidence {
            terminal,
            descriptor_set_digest: [18; 32],
            log_sha256: log.sha256.clone(),
            log_bytes: log.bytes,
            artifacts,
        };
        (terminal, evidence)
    }

    fn stage_request(
        sequence: u32,
        operation: Operation,
        attempt_id: Option<String>,
    ) -> AdapterRequest {
        let mut request = rerun_request(attempt_id.as_deref());
        request.sequence = sequence;
        request.operation = operation;
        request.operation_id = expected_adapter_operation_id(&request).unwrap();
        request
    }

    const ACCEPTANCE_OPERATIONS: [Operation; 16] = [
        Operation::ObserveInitial,
        Operation::SetCapacityOne,
        Operation::SubmitManifest,
        Operation::ApproveGrant,
        Operation::ResumeGrant,
        Operation::AwaitFirstTerminal,
        Operation::ExportFirstEvidence,
        Operation::SubmitFailureManifest,
        Operation::ResumeFailure,
        Operation::AwaitFailureTerminal,
        Operation::Rerun,
        Operation::CancelRerun,
        Operation::TombstoneRerun,
        Operation::RestartController,
        Operation::RestartRunner,
        Operation::SetCapacityZero,
    ];

    fn sequence_request(sequence: u32, attempt_id: Option<String>) -> AdapterRequest {
        let binding = canonical_acceptance_binding();
        let mut request = stage_request(
            sequence,
            ACCEPTANCE_OPERATIONS[usize::try_from(sequence - 1).unwrap()],
            attempt_id,
        );
        request.expected_controller_generation = Some(binding.fixture.controller_generation);
        request.expected_runner_generation = Some(binding.fixture.runner_generation);
        request.host.controller_generation = binding.fixture.controller_generation;
        request.host.runner_generation = binding.fixture.runner_generation;
        if sequence == 1 {
            request.expected_controller_generation = None;
            request.expected_runner_generation = None;
            request.host.capacity = 0;
            request.host.admission = AdmissionState::Closed;
        }
        request.operation_id = expected_adapter_operation_id(&request).unwrap();
        request
    }

    #[test]
    fn cached_terminal_merges_the_completed_observation_queued_before_worker_exit() {
        let request = stage_request(6, Operation::AwaitFirstTerminal, None);
        let (terminal, evidence) = terminal_fixture(&request, BrokerConclusion::Success, 1);
        let (sender, receiver) = mpsc::channel();
        sender
            .send(AttemptObservation::Completed(evidence.clone()))
            .unwrap();
        let worker = thread::spawn(|| ());
        worker.join().unwrap();
        drop(sender);
        let mut active = None;
        let merged = merge_attempt_observations(
            &mut active,
            Some(terminal),
            None,
            std::iter::from_fn(|| receiver.try_recv().ok()),
        )
        .unwrap();
        assert_eq!(merged, (Some(terminal), Some(evidence)));
    }
}
