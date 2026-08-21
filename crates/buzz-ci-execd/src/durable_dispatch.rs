//! Durable ownership of execd admission and terminal lifecycle transitions.
//!
//! Execution adapters receive opaque lease receipts and return typed outcomes.
//! They never receive the controller. The dispatcher is the sole transition
//! owner and publishes every transition before returning a successful response.

use buzz_ci_broker_protocol::{
    AdmitAttemptRequest, BrokerResponse, BrokerState, Conclusion, FrameHeader,
    QualificationDirective, QualificationRequest, Request, ResponseCode,
};

use crate::{
    activation::{
        ActivationController, ActivationState, AdmissionError, CleanupDisposition,
        DurableStateSnapshot, LeaseConclusion, LeaseToken, OrdinaryAdmission, QualificationLease,
        QualificationOutcome, ReadyRestoreValidation, VerifiedSigner,
    },
    control::{AdmissionBoundaryError, ClosedDispatch, ControlDispatch},
    runtime::{
        prepare_runtime, DurableStateStore, ReadyValidationTarget, RuntimeBootstrap,
        RuntimeLoadError, RuntimePreparation, ServiceAuthority,
    },
};

/// Service-owned authority boundary. Wire signer claims cannot implement it.
pub trait AdmissionAuthority {
    /// Bind an ordinary frame to the exact root-authored admission.
    fn authorize_ordinary(
        &mut self,
        request: AdmitAttemptRequest,
    ) -> Result<OrdinaryAdmission, AdmissionBoundaryError>;

    /// Authenticate a qualification frame independently of its signer claim.
    fn authenticate_qualification(
        &mut self,
        request: QualificationRequest,
    ) -> Result<VerifiedSigner, AdmissionBoundaryError>;
}

impl AdmissionAuthority for ServiceAuthority {
    fn authorize_ordinary(
        &mut self,
        request: AdmitAttemptRequest,
    ) -> Result<OrdinaryAdmission, AdmissionBoundaryError> {
        ServiceAuthority::authorize_ordinary(self, request)
    }

    fn authenticate_qualification(
        &mut self,
        request: QualificationRequest,
    ) -> Result<VerifiedSigner, AdmissionBoundaryError> {
        ServiceAuthority::authenticate_qualification(self, request)
    }
}

/// Atomic, revisioned publication of one controller snapshot.
pub trait StateCommit {
    /// Commit the exact snapshot before any response may claim success.
    fn commit(&mut self, snapshot: DurableStateSnapshot) -> Result<(), RuntimeLoadError>;
}

impl StateCommit for DurableStateStore {
    fn commit(&mut self, snapshot: DurableStateSnapshot) -> Result<(), RuntimeLoadError> {
        DurableStateStore::commit(self, snapshot)
    }
}

/// A concrete host adapter is absent or cannot prove its required facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionUnavailable;

/// Typed ordinary execution and cleanup result.
pub struct OrdinaryExecution {
    /// Terminal lease conclusion recorded before cleanup.
    pub conclusion: LeaseConclusion,
    /// Cleanup proof controlling Ready versus Quarantined.
    pub cleanup: CleanupDisposition,
    /// Legacy executor response. The dispatcher never publishes it.
    ///
    /// This field remains temporarily source-compatible with the host executor
    /// lanes while response construction moves behind the durable boundary.
    pub response: BrokerResponse,
}

/// Closed reconciliation evidence for an ordinary lease whose runner died.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpiredLeaseReconciliation {
    cleanup: CleanupDisposition,
    cleanup_receipt_digest: [u8; 32],
}

impl ExpiredLeaseReconciliation {
    /// Bind a non-ambiguous cleanup disposition to the digest returned by the
    /// root-owned cleanup adapter.
    pub fn receipt_bound(
        cleanup: CleanupDisposition,
        cleanup_receipt_digest: [u8; 32],
    ) -> Option<Self> {
        (cleanup != CleanupDisposition::Ambiguous && cleanup_receipt_digest != [0; 32]).then_some(
            Self {
                cleanup,
                cleanup_receipt_digest,
            },
        )
    }

    /// Missing or contradictory cleanup evidence is always ambiguous.
    pub const fn ambiguous() -> Self {
        Self {
            cleanup: CleanupDisposition::Ambiguous,
            cleanup_receipt_digest: [0; 32],
        }
    }

    /// Return the receipt-backed cleanup disposition.
    pub const fn cleanup(self) -> CleanupDisposition {
        self.cleanup
    }

    /// Return the digest of the root-owned cleanup receipt.
    pub const fn cleanup_receipt_digest(self) -> [u8; 32] {
        self.cleanup_receipt_digest
    }

    /// Expired work always closes as an infrastructure failure.
    pub const fn conclusion(self) -> LeaseConclusion {
        LeaseConclusion::InfrastructureFailure
    }

    /// Expiry reconciliation never authorizes result publication.
    pub const fn publication_suppressed(self) -> bool {
        true
    }
}

/// Concrete ordinary execution seam. It cannot mutate activation state.
pub trait OrdinaryExecutor {
    /// Confirm required concrete execution providers exist before admission.
    fn preflight(
        &mut self,
        request: AdmitAttemptRequest,
        admission: OrdinaryAdmission,
    ) -> Result<(), ExecutionUnavailable>;

    /// Execute one already durably recorded lease and return its typed outcome.
    fn execute(
        &mut self,
        header: FrameHeader,
        request: AdmitAttemptRequest,
        admission: OrdinaryAdmission,
        lease: LeaseToken,
        now: u64,
    ) -> Result<OrdinaryExecution, ExecutionUnavailable>;

    /// Reconcile only resources named by the root-owned receipt for `lease`.
    /// No completion payload or executor-provided publication is accepted.
    fn reconcile_expired(
        &mut self,
        lease: LeaseToken,
        now: u64,
    ) -> Result<ExpiredLeaseReconciliation, ExecutionUnavailable>;
}

/// Terminal qualification transition selected by trusted execution evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QualificationTerminal {
    /// Finish an ordinary qualification fixture with the supplied outcome.
    Completed(QualificationOutcome),
    /// Finish the root-permitted forced teardown-failure fixture.
    TeardownFailure,
}

/// Typed qualification execution result.
pub struct QualificationExecution {
    /// Transition the dispatcher must apply.
    pub terminal: QualificationTerminal,
    /// Legacy executor response. Only teardown evidence digests are consumed;
    /// all protocol coordinates and status fields are rebuilt by the dispatcher.
    pub response: BrokerResponse,
}

/// Concrete qualification execution seam. It cannot mutate activation state.
pub trait QualificationExecutor {
    /// Confirm required concrete fixture providers exist before admission.
    fn preflight(&mut self, request: QualificationRequest) -> Result<(), ExecutionUnavailable>;

    /// Execute one already durably recorded fixture lease.
    fn execute(
        &mut self,
        header: FrameHeader,
        request: QualificationRequest,
        lease: QualificationLease,
        now: u64,
    ) -> Result<QualificationExecution, ExecutionUnavailable>;
}

/// Explicit fail-closed placeholder until concrete host adapters are injected.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableExecution;

impl OrdinaryExecutor for UnavailableExecution {
    fn preflight(
        &mut self,
        _request: AdmitAttemptRequest,
        _admission: OrdinaryAdmission,
    ) -> Result<(), ExecutionUnavailable> {
        Err(ExecutionUnavailable)
    }

    fn execute(
        &mut self,
        _header: FrameHeader,
        _request: AdmitAttemptRequest,
        _admission: OrdinaryAdmission,
        _lease: LeaseToken,
        _now: u64,
    ) -> Result<OrdinaryExecution, ExecutionUnavailable> {
        Err(ExecutionUnavailable)
    }

    fn reconcile_expired(
        &mut self,
        _lease: LeaseToken,
        _now: u64,
    ) -> Result<ExpiredLeaseReconciliation, ExecutionUnavailable> {
        Err(ExecutionUnavailable)
    }
}

impl QualificationExecutor for UnavailableExecution {
    fn preflight(&mut self, _request: QualificationRequest) -> Result<(), ExecutionUnavailable> {
        Err(ExecutionUnavailable)
    }

    fn execute(
        &mut self,
        _header: FrameHeader,
        _request: QualificationRequest,
        _lease: QualificationLease,
        _now: u64,
    ) -> Result<QualificationExecution, ExecutionUnavailable> {
        Err(ExecutionUnavailable)
    }
}

/// Fresh cleanup, seccomp, and DNS evidence bound to one loaded runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadyHostProofs {
    pub target: ReadyValidationTarget,
    pub validation: ReadyRestoreValidation,
    pub cleanup_proof_digest: [u8; 32],
    pub dns_proof_digest: [u8; 32],
    pub observed_at: u64,
}

impl ReadyHostProofs {
    fn restore_validation(
        self,
        target: ReadyValidationTarget,
        now: u64,
    ) -> Option<ReadyRestoreValidation> {
        (self.target == target
            && self.validation.grant == target.grant()
            && self.validation.now == now
            && self.observed_at == now
            && self.cleanup_proof_digest != [0; 32]
            && self.dns_proof_digest != [0; 32])
            .then_some(self.validation)
    }
}

/// Fresh trusted host validation provider used only during bootstrap.
pub trait ReadyValidationProvider {
    /// Return current validation for the exact loaded grant, or fail closed.
    fn ready_validation(
        &mut self,
        target: &ReadyValidationTarget,
        now: u64,
    ) -> Option<ReadyHostProofs>;
}

/// Default bootstrap provider: no host proof, therefore no Ready restore.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableReadyValidation;

impl ReadyValidationProvider for UnavailableReadyValidation {
    fn ready_validation(
        &mut self,
        _target: &ReadyValidationTarget,
        _now: u64,
    ) -> Option<ReadyHostProofs> {
        None
    }
}

/// Sole owner of controller transitions, execution outcomes, and state commits.
pub struct DurableDispatch<S, A, O, Q> {
    controller: ActivationController,
    authority: A,
    store: S,
    ordinary: O,
    qualification: Q,
}

impl<S, A, O, Q> DurableDispatch<S, A, O, Q> {
    /// Bind restored controller state to its exact authority, store, and executors.
    pub fn new(
        controller: ActivationController,
        authority: A,
        store: S,
        ordinary: O,
        qualification: Q,
    ) -> Self {
        Self {
            controller,
            authority,
            store,
            ordinary,
            qualification,
        }
    }

    /// Inspect lifecycle state without exposing mutation.
    pub const fn state(&self) -> ActivationState {
        self.controller.state()
    }
}

impl<S, A, O, Q> DurableDispatch<S, A, O, Q>
where
    S: StateCommit,
    A: AdmissionAuthority,
    O: OrdinaryExecutor,
    Q: QualificationExecutor,
{
    fn commit_result(&mut self) -> Result<(), RuntimeLoadError> {
        match self.store.commit(self.controller.snapshot()) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.quarantine_in_memory();
                Err(error)
            }
        }
    }

    fn commit(&mut self) -> bool {
        self.commit_result().is_ok()
    }

    fn quarantine_in_memory(&mut self) {
        let root = self.controller.snapshot().root_authority;
        let mut invalid = self.controller.snapshot();
        invalid.root_authority = VerifiedSigner([0; 32]);
        self.controller = ActivationController::restore(root, invalid, None).controller;
    }

    /// Reconcile a runner-dead lease after trusted wall time reaches its expiry.
    /// Quarantine is committed before host cleanup and committed again before
    /// any reconciliation evidence becomes observable.
    pub fn reconcile_expired(
        &mut self,
        now: u64,
    ) -> Result<Option<ExpiredLeaseReconciliation>, RuntimeLoadError> {
        let lease = self
            .controller
            .expire_active_lease(now)
            .map_err(|_| RuntimeLoadError::Quarantined)?;
        let Some(lease) = lease else {
            return Ok(None);
        };
        self.commit_result()?;
        let reconciliation = self
            .ordinary
            .reconcile_expired(lease, now)
            .unwrap_or_else(|_| ExpiredLeaseReconciliation::ambiguous());
        self.commit_result()?;
        Ok(Some(reconciliation))
    }

    fn ordinary(
        &mut self,
        header: FrameHeader,
        request: AdmitAttemptRequest,
        now: u64,
    ) -> BrokerResponse {
        let admission = match self.authority.authorize_ordinary(request) {
            Ok(admission) => admission,
            Err(error) => return boundary_error_response(error, now),
        };
        if self.ordinary.preflight(request, admission).is_err() {
            return response(ResponseCode::NotProvisioned, now);
        }
        let lease = match self.controller.admit_ordinary(admission, now) {
            Ok(lease) => lease,
            Err(error) => return response(admission_error_code(error), now),
        };
        if !self.commit() {
            return response(ResponseCode::InternalFailure, now);
        }
        let lease_generation = self.controller.snapshot().next_lease_generation - 1;

        let execution = match self
            .ordinary
            .execute(header, request, admission, lease, now)
        {
            Ok(execution) => execution,
            Err(ExecutionUnavailable) => {
                return self.fail_ordinary_ambiguously(lease, now);
            }
        };
        if self
            .controller
            .finish_lease(lease, execution.conclusion)
            .is_err()
            || !self.commit()
        {
            return response(ResponseCode::InternalFailure, now);
        }
        let cleanup_complete = self
            .controller
            .finish_cleanup(lease, execution.cleanup, now)
            .is_ok();
        if !self.commit() || !cleanup_complete {
            return response(ResponseCode::InternalFailure, now);
        }
        ordinary_response(
            request,
            admission,
            lease_generation,
            execution.conclusion,
            now,
        )
    }

    fn fail_ordinary_ambiguously(&mut self, lease: LeaseToken, now: u64) -> BrokerResponse {
        if self
            .controller
            .finish_lease(lease, LeaseConclusion::InfrastructureFailure)
            .is_err()
            || !self.commit()
        {
            return response(ResponseCode::InternalFailure, now);
        }
        let _ = self
            .controller
            .finish_cleanup(lease, CleanupDisposition::Ambiguous, now);
        let _ = self.commit();
        response(ResponseCode::InternalFailure, now)
    }

    fn qualification(
        &mut self,
        header: FrameHeader,
        request: QualificationRequest,
        now: u64,
    ) -> BrokerResponse {
        let signer = match self.authority.authenticate_qualification(request) {
            Ok(signer) => signer,
            Err(error) => return boundary_error_response(error, now),
        };
        if self.qualification.preflight(request).is_err() {
            return response(ResponseCode::NotProvisioned, now);
        }
        let lease = match self
            .controller
            .admit_qualification_request(request, signer, now)
        {
            Ok(lease) => lease,
            Err(error) => return response(admission_error_code(error), now),
        };
        if !self.commit() {
            return response(ResponseCode::InternalFailure, now);
        }

        let execution = match self.qualification.execute(header, request, lease, now) {
            Ok(execution) => execution,
            Err(ExecutionUnavailable) => {
                let _ = self
                    .controller
                    .finish_qualification(lease, QualificationOutcome::Ambiguous);
                let _ = self.commit();
                return response(ResponseCode::InternalFailure, now);
            }
        };
        let terminal_ok = match (lease.directive(), execution.terminal) {
            (None, QualificationTerminal::Completed(outcome)) => {
                self.controller.finish_qualification(lease, outcome).is_ok()
            }
            (
                Some(QualificationDirective::TeardownFailure),
                QualificationTerminal::TeardownFailure,
            ) => self
                .controller
                .finish_qualification_teardown_failure(lease)
                .is_ok(),
            (None, QualificationTerminal::TeardownFailure) => self
                .controller
                .finish_qualification(lease, QualificationOutcome::Ambiguous)
                .is_ok(),
            (
                Some(QualificationDirective::TeardownFailure),
                QualificationTerminal::Completed(_),
            ) => {
                let _ = self.controller.finish_qualification_teardown_failure(lease);
                false
            }
        };
        if !self.commit() {
            return response(ResponseCode::InternalFailure, now);
        }
        qualification_response(request, lease, execution, terminal_ok, now)
    }
}

impl<S, A, O, Q> ControlDispatch for DurableDispatch<S, A, O, Q>
where
    S: StateCommit,
    A: AdmissionAuthority,
    O: OrdinaryExecutor,
    Q: QualificationExecutor,
{
    fn dispatch(&mut self, header: FrameHeader, request: Request, now: u64) -> BrokerResponse {
        if header.operation != request.operation() {
            return response(ResponseCode::BadFrame, now);
        }
        match request {
            Request::AdmitAttempt(request) => self.ordinary(header, request, now),
            Request::AdmitQualification(request) => self.qualification(header, request, now),
            Request::Hello(_) => response(ResponseCode::NotProvisioned, now),
            Request::CancelAttempt(_) | Request::GetAttempt(_) | Request::CompleteAttempt(_) => {
                response(ResponseCode::NotFound, now)
            }
        }
    }
}

/// Runtime-selected dispatcher: only a structurally Loaded runtime is durable.
pub enum BootstrapDispatch<O, Q> {
    /// Missing or quarantined authority/state exposes zero capacity.
    Closed(ClosedDispatch),
    /// Loaded authority/state retains its durable store and revision.
    Loaded(Box<DurableDispatch<DurableStateStore, ServiceAuthority, O, Q>>),
}

impl<O: OrdinaryExecutor, Q: QualificationExecutor> ControlDispatch for BootstrapDispatch<O, Q> {
    fn dispatch(&mut self, header: FrameHeader, request: Request, now: u64) -> BrokerResponse {
        match self {
            Self::Closed(dispatch) => dispatch.dispatch(header, request, now),
            Self::Loaded(dispatch) => dispatch.dispatch(header, request, now),
        }
    }
}

impl<O: OrdinaryExecutor, Q: QualificationExecutor> BootstrapDispatch<O, Q> {
    /// Drive the trusted-time expiry path without a completion request.
    pub fn reconcile_expired(
        &mut self,
        now: u64,
    ) -> Result<Option<ExpiredLeaseReconciliation>, RuntimeLoadError> {
        match self {
            Self::Closed(_) => Ok(None),
            Self::Loaded(dispatch) => dispatch.reconcile_expired(now),
        }
    }
}

/// Compose a previously loaded bootstrap result without discarding its store.
pub fn compose_bootstrap<O, Q>(
    bootstrap: RuntimeBootstrap,
    ordinary: O,
    qualification: Q,
) -> BootstrapDispatch<O, Q>
where
    O: OrdinaryExecutor,
    Q: QualificationExecutor,
{
    match bootstrap {
        RuntimeBootstrap::Loaded(runtime) => {
            BootstrapDispatch::Loaded(Box::new(runtime.compose(ordinary, qualification)))
        }
        RuntimeBootstrap::NotProvisioned(_) | RuntimeBootstrap::Quarantined { .. } => {
            BootstrapDispatch::Closed(ClosedDispatch::new())
        }
    }
}

/// Load fixed authority/state using freshly injected host validation, then compose.
pub fn load_dispatch<V, O, Q>(
    now: u64,
    validation: &mut V,
    ordinary: O,
    qualification: Q,
) -> BootstrapDispatch<O, Q>
where
    V: ReadyValidationProvider,
    O: OrdinaryExecutor,
    Q: QualificationExecutor,
{
    let preparation = prepare_runtime(now);
    let bootstrap = match preparation {
        RuntimePreparation::Prepared(runtime) => {
            let ready_validation = runtime.ready_validation_target().and_then(|target| {
                validation
                    .ready_validation(&target, now)
                    .and_then(|proofs| proofs.restore_validation(target, now))
            });
            runtime.restore(ready_validation)
        }
        other => other.complete_closed(),
    };
    compose_bootstrap(bootstrap, ordinary, qualification)
}

fn ordinary_response(
    request: AdmitAttemptRequest,
    admission: OrdinaryAdmission,
    lease_generation: u64,
    conclusion: LeaseConclusion,
    now: u64,
) -> BrokerResponse {
    BrokerResponse {
        code: ResponseCode::Ok,
        retry_after_millis: 0,
        attempt_id: admission.lease_id,
        run_id: request.run_id,
        accepted_request_digest: request.signed_request_digest,
        job_manifest_digest: request.job_manifest_digest,
        tip_oid: Some(request.tip_oid),
        broker_state: BrokerState::Ready,
        conclusion: protocol_conclusion(conclusion),
        terminal_reason: u16::from(conclusion == LeaseConclusion::InfrastructureFailure),
        generation: lease_generation,
        accepted_at: now,
        updated_at: now,
        lease_generation,
        evidence_set_digest: [0; 32],
        teardown_digest: [0; 32],
        attempt: request.attempt,
    }
}

fn qualification_response(
    request: QualificationRequest,
    lease: QualificationLease,
    execution: QualificationExecution,
    terminal_ok: bool,
    now: u64,
) -> BrokerResponse {
    let teardown_evidence = validated_teardown_evidence(request, lease, execution.response, now);
    let (code, state, conclusion, evidence_set_digest, teardown_digest) =
        match (execution.terminal, teardown_evidence) {
            (
                QualificationTerminal::Completed(QualificationOutcome::Accepted {
                    evidence_set_digest,
                }),
                _,
            ) if terminal_ok => (
                ResponseCode::Ok,
                BrokerState::Reconciling,
                Conclusion::Success,
                evidence_set_digest,
                [0; 32],
            ),
            (
                QualificationTerminal::TeardownFailure,
                Some((evidence_set_digest, teardown_digest)),
            ) if terminal_ok => (
                ResponseCode::Ok,
                BrokerState::Quarantined,
                Conclusion::InfrastructureFailure,
                evidence_set_digest,
                teardown_digest,
            ),
            (QualificationTerminal::Completed(QualificationOutcome::Failed), _) => (
                ResponseCode::InternalFailure,
                BrokerState::Quarantined,
                Conclusion::Failure,
                [0; 32],
                [0; 32],
            ),
            _ => (
                ResponseCode::InternalFailure,
                BrokerState::Quarantined,
                Conclusion::InfrastructureFailure,
                [0; 32],
                [0; 32],
            ),
        };
    BrokerResponse {
        code,
        retry_after_millis: 0,
        attempt_id: lease.lease_id(),
        run_id: [0; 16],
        accepted_request_digest: request.request_digest,
        job_manifest_digest: request.manifest_digest,
        tip_oid: Some(request.integrated_candidate_sha),
        broker_state: state,
        conclusion,
        terminal_reason: u16::from(code != ResponseCode::Ok),
        generation: lease.generation(),
        accepted_at: now,
        updated_at: now,
        lease_generation: lease.generation(),
        evidence_set_digest,
        teardown_digest,
        attempt: 1,
    }
}

fn validated_teardown_evidence(
    request: QualificationRequest,
    lease: QualificationLease,
    candidate: BrokerResponse,
    now: u64,
) -> Option<([u8; 32], [u8; 32])> {
    (candidate.code == ResponseCode::Ok
        && candidate.retry_after_millis == 0
        && candidate.attempt_id == lease.lease_id()
        && candidate.run_id == [0; 16]
        && candidate.accepted_request_digest == request.request_digest
        && candidate.job_manifest_digest == request.manifest_digest
        && candidate.tip_oid == Some(request.integrated_candidate_sha)
        && candidate.broker_state == BrokerState::Quarantined
        && candidate.conclusion == Conclusion::InfrastructureFailure
        && candidate.terminal_reason == 1
        && candidate.generation == lease.generation()
        && candidate.accepted_at == now
        && candidate.updated_at == now
        && candidate.lease_generation == lease.generation()
        && candidate.evidence_set_digest != [0; 32]
        && candidate.teardown_digest != [0; 32]
        && candidate.attempt == 1)
        .then_some((candidate.evidence_set_digest, candidate.teardown_digest))
}

const fn protocol_conclusion(conclusion: LeaseConclusion) -> Conclusion {
    match conclusion {
        LeaseConclusion::Success => Conclusion::Success,
        LeaseConclusion::Failure => Conclusion::Failure,
        LeaseConclusion::Cancelled => Conclusion::Cancelled,
        LeaseConclusion::TimedOut => Conclusion::TimedOut,
        LeaseConclusion::InfrastructureFailure => Conclusion::InfrastructureFailure,
    }
}

fn boundary_error_response(error: AdmissionBoundaryError, now: u64) -> BrokerResponse {
    let code = match error {
        AdmissionBoundaryError::Unavailable => ResponseCode::NotProvisioned,
        AdmissionBoundaryError::Unauthorized | AdmissionBoundaryError::InvalidCoordinates => {
            ResponseCode::PolicyDenied
        }
    };
    response(code, now)
}

fn admission_error_code(error: AdmissionError) -> ResponseCode {
    match error {
        AdmissionError::Replay => ResponseCode::ReplayConflict,
        AdmissionError::RateLimit | AdmissionError::ConcurrencyLimit => ResponseCode::NoCapacity,
        AdmissionError::QualificationOnly | AdmissionError::NotReady => {
            ResponseCode::NotProvisioned
        }
        AdmissionError::ExpiredNonce
        | AdmissionError::UnauthorizedSigner
        | AdmissionError::UnacceptedTrustClass
        | AdmissionError::CoordinateMismatch
        | AdmissionError::InvalidNonce => ResponseCode::PolicyDenied,
        AdmissionError::GenerationExhausted => ResponseCode::InternalFailure,
    }
}

fn response(code: ResponseCode, now: u64) -> BrokerResponse {
    BrokerResponse {
        code,
        retry_after_millis: 0,
        attempt_id: [0; 16],
        run_id: [0; 16],
        accepted_request_digest: [0; 32],
        job_manifest_digest: [0; 32],
        tip_oid: None,
        broker_state: BrokerState::Reconciling,
        conclusion: Conclusion::None,
        terminal_reason: 0,
        generation: 0,
        accepted_at: 0,
        updated_at: now,
        lease_generation: 0,
        evidence_set_digest: [0; 32],
        teardown_digest: [0; 32],
        attempt: 0,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        rc::Rc,
    };

    use buzz_ci_broker_protocol::{GitOid, Operation, TrustClass};
    use buzz_ci_isolation_contract::{PHASE1_SECCOMP_PROFILE_DIGEST, PHASE1_SECCOMP_PROFILE_PATH};

    use super::*;
    use crate::{
        activation::{
            ActivationGrant, AdmissionTrustClass, FixtureJobCoordinates, HostActivationCoordinates,
            OrdinaryJobCoordinates, QualificationPermit,
        },
        seccomp::{SeccompFileReadback, SeccompFileType, SeccompSeedPlan, SECCOMP_PROFILE_MODE},
    };

    const ROOT: VerifiedSigner = VerifiedSigner([1; 32]);
    const FIXTURE: VerifiedSigner = VerifiedSigner([2; 32]);
    const ORDINARY: VerifiedSigner = VerifiedSigner([3; 32]);

    #[derive(Clone, Copy)]
    struct FakeAuthority {
        ordinary_request: AdmitAttemptRequest,
        admission: OrdinaryAdmission,
        qualification_request: QualificationRequest,
    }

    impl AdmissionAuthority for FakeAuthority {
        fn authorize_ordinary(
            &mut self,
            request: AdmitAttemptRequest,
        ) -> Result<OrdinaryAdmission, AdmissionBoundaryError> {
            (request == self.ordinary_request)
                .then_some(self.admission)
                .ok_or(AdmissionBoundaryError::Unauthorized)
        }

        fn authenticate_qualification(
            &mut self,
            request: QualificationRequest,
        ) -> Result<VerifiedSigner, AdmissionBoundaryError> {
            (request == self.qualification_request)
                .then_some(FIXTURE)
                .ok_or(AdmissionBoundaryError::Unauthorized)
        }
    }

    #[derive(Clone)]
    struct FakeStore {
        commits: Rc<RefCell<Vec<DurableStateSnapshot>>>,
        attempts: Rc<Cell<usize>>,
        fail_on: Option<usize>,
    }

    impl FakeStore {
        fn new(fail_on: Option<usize>) -> Self {
            Self {
                commits: Rc::new(RefCell::new(Vec::new())),
                attempts: Rc::new(Cell::new(0)),
                fail_on,
            }
        }
    }

    impl StateCommit for FakeStore {
        fn commit(&mut self, snapshot: DurableStateSnapshot) -> Result<(), RuntimeLoadError> {
            let attempt = self.attempts.get() + 1;
            self.attempts.set(attempt);
            if self.fail_on == Some(attempt) {
                return Err(RuntimeLoadError::PersistFailed);
            }
            self.commits.borrow_mut().push(snapshot);
            Ok(())
        }
    }

    struct OrderedStore {
        commits: Rc<RefCell<Vec<DurableStateSnapshot>>>,
        events: Rc<RefCell<Vec<&'static str>>>,
        attempts: usize,
        fail_on: Option<usize>,
    }

    impl StateCommit for OrderedStore {
        fn commit(&mut self, snapshot: DurableStateSnapshot) -> Result<(), RuntimeLoadError> {
            self.attempts += 1;
            self.events.borrow_mut().push("commit");
            if self.fail_on == Some(self.attempts) {
                return Err(RuntimeLoadError::PersistFailed);
            }
            self.commits.borrow_mut().push(snapshot);
            Ok(())
        }
    }

    struct ExpiryExecutor {
        events: Rc<RefCell<Vec<&'static str>>>,
        seen_lease: Rc<Cell<Option<LeaseToken>>>,
        reconciliation: ExpiredLeaseReconciliation,
    }

    impl OrdinaryExecutor for ExpiryExecutor {
        fn preflight(
            &mut self,
            _request: AdmitAttemptRequest,
            _admission: OrdinaryAdmission,
        ) -> Result<(), ExecutionUnavailable> {
            Ok(())
        }

        fn execute(
            &mut self,
            _header: FrameHeader,
            _request: AdmitAttemptRequest,
            _admission: OrdinaryAdmission,
            _lease: LeaseToken,
            _now: u64,
        ) -> Result<OrdinaryExecution, ExecutionUnavailable> {
            Err(ExecutionUnavailable)
        }

        fn reconcile_expired(
            &mut self,
            lease: LeaseToken,
            _now: u64,
        ) -> Result<ExpiredLeaseReconciliation, ExecutionUnavailable> {
            self.events.borrow_mut().push("cleanup");
            self.seen_lease.set(Some(lease));
            Ok(self.reconciliation)
        }
    }

    struct OrdinaryFake {
        calls: Rc<Cell<usize>>,
        cleanup: CleanupDisposition,
    }

    impl OrdinaryExecutor for OrdinaryFake {
        fn preflight(
            &mut self,
            _request: AdmitAttemptRequest,
            _admission: OrdinaryAdmission,
        ) -> Result<(), ExecutionUnavailable> {
            Ok(())
        }

        fn execute(
            &mut self,
            _header: FrameHeader,
            _request: AdmitAttemptRequest,
            _admission: OrdinaryAdmission,
            _lease: LeaseToken,
            now: u64,
        ) -> Result<OrdinaryExecution, ExecutionUnavailable> {
            self.calls.set(self.calls.get() + 1);
            Ok(OrdinaryExecution {
                conclusion: LeaseConclusion::Success,
                cleanup: self.cleanup,
                response: response(ResponseCode::Ok, now),
            })
        }

        fn reconcile_expired(
            &mut self,
            _lease: LeaseToken,
            _now: u64,
        ) -> Result<ExpiredLeaseReconciliation, ExecutionUnavailable> {
            Ok(
                ExpiredLeaseReconciliation::receipt_bound(self.cleanup, [44; 32])
                    .unwrap_or_else(ExpiredLeaseReconciliation::ambiguous),
            )
        }
    }

    struct QualificationFake;

    impl QualificationExecutor for QualificationFake {
        fn preflight(
            &mut self,
            _request: QualificationRequest,
        ) -> Result<(), ExecutionUnavailable> {
            Ok(())
        }

        fn execute(
            &mut self,
            _header: FrameHeader,
            _request: QualificationRequest,
            _lease: QualificationLease,
            now: u64,
        ) -> Result<QualificationExecution, ExecutionUnavailable> {
            Ok(QualificationExecution {
                terminal: QualificationTerminal::Completed(QualificationOutcome::Accepted {
                    evidence_set_digest: [16; 32],
                }),
                response: response(ResponseCode::Ok, now),
            })
        }
    }

    fn host() -> HostActivationCoordinates {
        HostActivationCoordinates {
            integrated_candidate_sha: GitOid::Sha256([4; 32]),
            broker_build_identity: [5; 32],
            host_profile_digest: [6; 32],
            suite_identity: [7; 32],
        }
    }

    fn fixture() -> FixtureJobCoordinates {
        FixtureJobCoordinates {
            request_digest: [8; 32],
            manifest_digest: [9; 32],
            isolation_profile_digest: [10; 32],
            source_oid: GitOid::Sha256([11; 32]),
            base_oid: GitOid::Sha256([12; 32]),
            test_identity: [13; 32],
        }
    }

    fn permit() -> QualificationPermit {
        QualificationPermit {
            authorized_by: ROOT,
            host: host(),
            fixture_job: fixture(),
            fixture_identity: [14; 32],
            fixture_signer: FIXTURE,
            nonce: [15; 32],
            not_before: 1,
            expires_at: 1_000,
            directive: None,
        }
    }

    fn qualification_request() -> QualificationRequest {
        let permit = permit();
        QualificationRequest {
            integrated_candidate_sha: permit.host.integrated_candidate_sha,
            broker_build_identity: permit.host.broker_build_identity,
            host_profile_digest: permit.host.host_profile_digest,
            suite_identity: permit.host.suite_identity,
            fixture_signer: permit.fixture_signer.0,
            request_digest: permit.fixture_job.request_digest,
            manifest_digest: permit.fixture_job.manifest_digest,
            isolation_profile_digest: permit.fixture_job.isolation_profile_digest,
            source_oid: permit.fixture_job.source_oid,
            base_oid: permit.fixture_job.base_oid,
            job_identity: permit.fixture_job.test_identity,
            fixture_identity: permit.fixture_identity,
            nonce: permit.nonce,
            not_before: permit.not_before,
            expires_at: permit.expires_at,
            directive: None,
        }
    }

    fn grant() -> ActivationGrant {
        ActivationGrant {
            authorized_by: ROOT,
            host: host(),
            security_records_passed: 17,
            security_records_total: 17,
            probes_passed: 12,
            probes_total: 12,
            evidence_set_digest: [16; 32],
            blocker_closure_digest: [17; 32],
            all_blockers_closed: true,
            ordinary_signer: ORDINARY,
            max_capacity: 1,
            minimum_admission_interval_seconds: 1,
            expires_at: 1_000,
        }
    }

    fn ordinary_request() -> AdmitAttemptRequest {
        AdmitAttemptRequest {
            signed_request_digest: [18; 32],
            actor_pubkey: ORDINARY.0,
            audience_digest: [19; 32],
            idempotency_digest: [20; 32],
            source_pin_event_id: [21; 32],
            workflow_digest: [22; 32],
            job_manifest_digest: [23; 32],
            isolation_profile_digest: [24; 32],
            run_id: [25; 16],
            tip_oid: GitOid::Sha256([26; 32]),
            base_oid: GitOid::Sha256([27; 32]),
            issued_at: 20,
            expires_at: 100,
            wall_timeout_seconds: 30,
            attempt: 1,
            parent_attempt: 0,
            trust_class: TrustClass::AcceptedReviewed,
        }
    }

    fn ordinary_admission() -> OrdinaryAdmission {
        let request = ordinary_request();
        OrdinaryAdmission {
            host: host(),
            job: OrdinaryJobCoordinates {
                request_digest: request.signed_request_digest,
                manifest_digest: request.job_manifest_digest,
                isolation_profile_digest: request.isolation_profile_digest,
                source_oid: request.tip_oid,
                base_oid: request.base_oid,
                job_identity: [28; 32],
            },
            lease_id: [29; 16],
            signer: ORDINARY,
            nonce: [30; 32],
            expires_at: request.expires_at,
            trust_class: AdmissionTrustClass::AcceptedReviewed,
        }
    }

    fn authority() -> FakeAuthority {
        FakeAuthority {
            ordinary_request: ordinary_request(),
            admission: ordinary_admission(),
            qualification_request: qualification_request(),
        }
    }

    fn qualifying_controller() -> ActivationController {
        let mut controller = ActivationController::new(ROOT);
        controller.start_qualification(permit()).unwrap();
        controller
    }

    fn seccomp() -> crate::seccomp::SeccompLeaseEvidence {
        SeccompSeedPlan::phase1()
            .readiness(&SeccompFileReadback {
                path: PHASE1_SECCOMP_PROFILE_PATH.into(),
                canonical_path: PHASE1_SECCOMP_PROFILE_PATH.into(),
                file_type: SeccompFileType::Regular,
                link_count: 1,
                owner_uid: 0,
                owner_gid: 0,
                mode: SECCOMP_PROFILE_MODE,
                digest: PHASE1_SECCOMP_PROFILE_DIGEST.into(),
            })
            .unwrap()
    }

    fn ready_controller() -> ActivationController {
        let mut controller = qualifying_controller();
        let lease = controller
            .admit_qualification_request(qualification_request(), FIXTURE, 10)
            .unwrap();
        controller
            .finish_qualification(
                lease,
                QualificationOutcome::Accepted {
                    evidence_set_digest: [16; 32],
                },
            )
            .unwrap();
        controller
            .reconcile_activation(grant(), seccomp(), host().host_profile_digest, 20)
            .unwrap();
        controller
    }

    fn ordinary_header() -> FrameHeader {
        FrameHeader {
            operation: Operation::AdmitAttempt,
            request_id: [31; 16],
        }
    }

    fn leased_controller() -> (ActivationController, LeaseToken) {
        let mut controller = ready_controller();
        let lease = controller
            .admit_ordinary(ordinary_admission(), 21)
            .expect("ordinary lease");
        (controller, lease)
    }

    #[test]
    fn active_lease_restart_closes_without_cleanup_or_reuse() {
        let (controller, lease) = leased_controller();
        let restart = ActivationController::restore(ROOT, controller.snapshot(), None);
        assert_eq!(restart.controller.state(), ActivationState::Quarantined);
        assert_eq!(
            restart.quarantine_reason,
            Some(crate::activation::ActivationError::RestartAmbiguous)
        );
        assert_eq!(restart.controller.snapshot().active_lease, None);
        assert_eq!(restart.controller.ordinary_capacity(100), 0);
        assert_eq!(lease.expires_at(), 100);
    }

    #[test]
    fn never_completing_job_expiry_commits_quarantine_before_receipt_bound_cleanup() {
        let (controller, lease) = leased_controller();

        let events = Rc::new(RefCell::new(Vec::new()));
        let commits = Rc::new(RefCell::new(Vec::new()));
        let seen_lease = Rc::new(Cell::new(None));
        let reconciliation =
            ExpiredLeaseReconciliation::receipt_bound(CleanupDisposition::Clean, [45; 32]).unwrap();
        let mut dispatch = DurableDispatch::new(
            controller,
            authority(),
            OrderedStore {
                commits: Rc::clone(&commits),
                events: Rc::clone(&events),
                attempts: 0,
                fail_on: None,
            },
            ExpiryExecutor {
                events: Rc::clone(&events),
                seen_lease: Rc::clone(&seen_lease),
                reconciliation,
            },
            QualificationFake,
        );

        assert_eq!(dispatch.reconcile_expired(99), Ok(None));
        assert!(events.borrow().is_empty());
        let observed = dispatch.reconcile_expired(100).unwrap().unwrap();
        assert_eq!(observed, reconciliation);
        assert_eq!(
            observed.conclusion(),
            LeaseConclusion::InfrastructureFailure
        );
        assert!(observed.publication_suppressed());
        assert_eq!(observed.cleanup_receipt_digest(), [45; 32]);
        assert_eq!(seen_lease.get(), Some(lease));
        assert_eq!(dispatch.state(), ActivationState::Quarantined);
        assert_eq!(&*events.borrow(), &["commit", "cleanup", "commit"]);
        assert_eq!(commits.borrow().len(), 2);
        assert!(commits
            .borrow()
            .iter()
            .all(|snapshot| snapshot.state == ActivationState::Quarantined
                && snapshot.active_lease.is_none()));
    }

    #[test]
    fn reconciliation_evidence_requires_a_nonzero_unambiguous_receipt() {
        assert_eq!(
            ExpiredLeaseReconciliation::receipt_bound(CleanupDisposition::Clean, [0; 32]),
            None
        );
        assert_eq!(
            ExpiredLeaseReconciliation::receipt_bound(CleanupDisposition::Ambiguous, [47; 32]),
            None
        );
        let incomplete =
            ExpiredLeaseReconciliation::receipt_bound(CleanupDisposition::Incomplete, [48; 32])
                .unwrap();
        assert_eq!(incomplete.cleanup(), CleanupDisposition::Incomplete);
        assert_eq!(incomplete.cleanup_receipt_digest(), [48; 32]);
        assert!(incomplete.publication_suppressed());
    }

    #[test]
    fn ambiguous_runner_death_cleanup_remains_durably_quarantined() {
        let (controller, _) = leased_controller();
        let events = Rc::new(RefCell::new(Vec::new()));
        let commits = Rc::new(RefCell::new(Vec::new()));
        let mut dispatch = DurableDispatch::new(
            controller,
            authority(),
            OrderedStore {
                commits: Rc::clone(&commits),
                events: Rc::clone(&events),
                attempts: 0,
                fail_on: None,
            },
            ExpiryExecutor {
                events: Rc::clone(&events),
                seen_lease: Rc::new(Cell::new(None)),
                reconciliation: ExpiredLeaseReconciliation::ambiguous(),
            },
            QualificationFake,
        );

        let observed = dispatch.reconcile_expired(100).unwrap().unwrap();
        assert_eq!(observed.cleanup(), CleanupDisposition::Ambiguous);
        assert_eq!(observed.cleanup_receipt_digest(), [0; 32]);
        assert_eq!(
            observed.conclusion(),
            LeaseConclusion::InfrastructureFailure
        );
        assert!(observed.publication_suppressed());
        assert_eq!(dispatch.state(), ActivationState::Quarantined);
        assert_eq!(&*events.borrow(), &["commit", "cleanup", "commit"]);
        assert!(commits
            .borrow()
            .iter()
            .all(|snapshot| snapshot.state == ActivationState::Quarantined));
    }

    #[test]
    fn runner_death_state_commit_failure_never_exposes_cleanup_observation() {
        for fail_on in [1, 2] {
            let (controller, _) = leased_controller();
            let events = Rc::new(RefCell::new(Vec::new()));
            let commits = Rc::new(RefCell::new(Vec::new()));
            let seen_lease = Rc::new(Cell::new(None));
            let mut dispatch = DurableDispatch::new(
                controller,
                authority(),
                OrderedStore {
                    commits: Rc::clone(&commits),
                    events: Rc::clone(&events),
                    attempts: 0,
                    fail_on: Some(fail_on),
                },
                ExpiryExecutor {
                    events: Rc::clone(&events),
                    seen_lease: Rc::clone(&seen_lease),
                    reconciliation: ExpiredLeaseReconciliation::receipt_bound(
                        CleanupDisposition::Clean,
                        [46; 32],
                    )
                    .unwrap(),
                },
                QualificationFake,
            );

            assert_eq!(
                dispatch.reconcile_expired(100),
                Err(RuntimeLoadError::PersistFailed)
            );
            assert_eq!(dispatch.state(), ActivationState::Quarantined);
            if fail_on == 1 {
                assert_eq!(&*events.borrow(), &["commit"]);
                assert_eq!(seen_lease.get(), None);
                assert!(commits.borrow().is_empty());
            } else {
                assert_eq!(&*events.borrow(), &["commit", "cleanup", "commit"]);
                assert!(seen_lease.get().is_some());
                assert_eq!(commits.borrow().len(), 1);
            }
        }
    }

    #[test]
    fn ordinary_success_follows_all_three_durable_transitions() {
        let store = FakeStore::new(None);
        let commits = Rc::clone(&store.commits);
        let calls = Rc::new(Cell::new(0));
        let mut dispatch = DurableDispatch::new(
            ready_controller(),
            authority(),
            store,
            OrdinaryFake {
                calls: Rc::clone(&calls),
                cleanup: CleanupDisposition::Clean,
            },
            QualificationFake,
        );

        let result = dispatch.dispatch(
            ordinary_header(),
            Request::AdmitAttempt(ordinary_request()),
            21,
        );

        assert_eq!(result.code, ResponseCode::Ok);
        assert_eq!(result.attempt_id, ordinary_admission().lease_id);
        assert_eq!(result.run_id, ordinary_request().run_id);
        assert_eq!(
            result.accepted_request_digest,
            ordinary_request().signed_request_digest
        );
        assert_eq!(
            result.job_manifest_digest,
            ordinary_request().job_manifest_digest
        );
        assert_eq!(result.tip_oid, Some(ordinary_request().tip_oid));
        assert_eq!(result.broker_state, BrokerState::Ready);
        assert_eq!(result.conclusion, Conclusion::Success);
        assert_eq!(result.generation, 2);
        assert_eq!(result.lease_generation, 2);
        assert_eq!(result.attempt, ordinary_request().attempt);
        assert_eq!(calls.get(), 1);
        assert_eq!(dispatch.state(), ActivationState::Ready);
        let states: Vec<_> = commits.borrow().iter().map(|entry| entry.state).collect();
        assert_eq!(
            states,
            [
                ActivationState::Leased,
                ActivationState::Draining,
                ActivationState::Ready
            ]
        );
        let restart = ActivationController::restore(ROOT, commits.borrow()[0], None);
        assert_eq!(restart.controller.state(), ActivationState::Quarantined);
        assert_eq!(
            restart.quarantine_reason,
            Some(crate::activation::ActivationError::RestartAmbiguous)
        );
    }

    #[test]
    fn admission_commit_failure_prevents_execution_and_success() {
        let store = FakeStore::new(Some(1));
        let calls = Rc::new(Cell::new(0));
        let mut dispatch = DurableDispatch::new(
            ready_controller(),
            authority(),
            store,
            OrdinaryFake {
                calls: Rc::clone(&calls),
                cleanup: CleanupDisposition::Clean,
            },
            QualificationFake,
        );

        let result = dispatch.dispatch(
            ordinary_header(),
            Request::AdmitAttempt(ordinary_request()),
            21,
        );

        assert_eq!(result.code, ResponseCode::InternalFailure);
        assert_eq!(calls.get(), 0);
        assert_eq!(dispatch.state(), ActivationState::Quarantined);
    }

    #[test]
    fn final_commit_failure_suppresses_success_and_closes_capacity() {
        let store = FakeStore::new(Some(3));
        let calls = Rc::new(Cell::new(0));
        let mut dispatch = DurableDispatch::new(
            ready_controller(),
            authority(),
            store,
            OrdinaryFake {
                calls: Rc::clone(&calls),
                cleanup: CleanupDisposition::Clean,
            },
            QualificationFake,
        );

        let result = dispatch.dispatch(
            ordinary_header(),
            Request::AdmitAttempt(ordinary_request()),
            21,
        );

        assert_eq!(result.code, ResponseCode::InternalFailure);
        assert_eq!(calls.get(), 1);
        assert_eq!(dispatch.state(), ActivationState::Quarantined);
    }

    #[test]
    fn ambiguous_cleanup_is_durably_quarantined_and_suppresses_success() {
        let store = FakeStore::new(None);
        let commits = Rc::clone(&store.commits);
        let mut dispatch = DurableDispatch::new(
            ready_controller(),
            authority(),
            store,
            OrdinaryFake {
                calls: Rc::new(Cell::new(0)),
                cleanup: CleanupDisposition::Ambiguous,
            },
            QualificationFake,
        );

        let result = dispatch.dispatch(
            ordinary_header(),
            Request::AdmitAttempt(ordinary_request()),
            21,
        );

        assert_eq!(result.code, ResponseCode::InternalFailure);
        assert_eq!(dispatch.state(), ActivationState::Quarantined);
        let states: Vec<_> = commits.borrow().iter().map(|entry| entry.state).collect();
        assert_eq!(
            states,
            [
                ActivationState::Leased,
                ActivationState::Draining,
                ActivationState::Quarantined
            ]
        );
    }

    #[test]
    fn unavailable_production_adapter_never_allocates_or_commits() {
        let store = FakeStore::new(None);
        let commits = Rc::clone(&store.commits);
        let mut dispatch = DurableDispatch::new(
            ready_controller(),
            authority(),
            store,
            UnavailableExecution,
            UnavailableExecution,
        );

        let result = dispatch.dispatch(
            ordinary_header(),
            Request::AdmitAttempt(ordinary_request()),
            21,
        );

        assert_eq!(result.code, ResponseCode::NotProvisioned);
        assert_eq!(dispatch.state(), ActivationState::Ready);
        assert!(commits.borrow().is_empty());
    }

    #[test]
    fn qualification_completion_is_committed_before_success() {
        let store = FakeStore::new(None);
        let commits = Rc::clone(&store.commits);
        let mut dispatch = DurableDispatch::new(
            qualifying_controller(),
            authority(),
            store,
            OrdinaryFake {
                calls: Rc::new(Cell::new(0)),
                cleanup: CleanupDisposition::Clean,
            },
            QualificationFake,
        );
        let header = FrameHeader {
            operation: Operation::AdmitQualification,
            request_id: [32; 16],
        };

        let result = dispatch.dispatch(
            header,
            Request::AdmitQualification(qualification_request()),
            10,
        );

        assert_eq!(result.code, ResponseCode::Ok);
        assert_eq!(result.attempt_id, [14; 16]);
        assert_eq!(result.accepted_request_digest, fixture().request_digest);
        assert_eq!(result.job_manifest_digest, fixture().manifest_digest);
        assert_eq!(result.tip_oid, Some(host().integrated_candidate_sha));
        assert_eq!(result.broker_state, BrokerState::Reconciling);
        assert_eq!(result.conclusion, Conclusion::Success);
        assert_eq!(result.evidence_set_digest, [16; 32]);
        assert_eq!(dispatch.state(), ActivationState::Reconciling);
        let states: Vec<_> = commits.borrow().iter().map(|entry| entry.state).collect();
        assert_eq!(
            states,
            [ActivationState::Qualifying, ActivationState::Reconciling]
        );
        assert!(commits.borrow()[0]
            .qualification
            .is_some_and(|state| state.active_lease.is_some()));
    }

    #[test]
    fn ready_proofs_must_be_fresh_and_bound_to_the_loaded_target() {
        let target = ReadyValidationTarget::new(grant(), ordinary_request(), 7, [40; 32], 9);
        let validation = ReadyRestoreValidation {
            grant: grant(),
            seccomp_evidence: seccomp(),
            host_profile_digest: host().host_profile_digest,
            now: 20,
        };
        let proofs = ReadyHostProofs {
            target,
            validation,
            cleanup_proof_digest: [41; 32],
            dns_proof_digest: [42; 32],
            observed_at: 20,
        };
        assert_eq!(proofs.restore_validation(target, 20), Some(validation));

        assert_eq!(
            ReadyHostProofs {
                observed_at: 19,
                ..proofs
            }
            .restore_validation(target, 20),
            None
        );
        assert_eq!(
            ReadyHostProofs {
                dns_proof_digest: [0; 32],
                ..proofs
            }
            .restore_validation(target, 20),
            None
        );
        let other = ReadyValidationTarget::new(grant(), ordinary_request(), 8, [40; 32], 9);
        assert_eq!(proofs.restore_validation(other, 20), None);
    }

    #[test]
    fn teardown_evidence_cannot_override_response_bindings() {
        let mut teardown_permit = permit();
        teardown_permit.directive = Some(QualificationDirective::TeardownFailure);
        let mut teardown_request = qualification_request();
        teardown_request.directive = Some(QualificationDirective::TeardownFailure);
        let mut controller = ActivationController::new(ROOT);
        controller.start_qualification(teardown_permit).unwrap();
        let lease = controller
            .admit_qualification_request(teardown_request, FIXTURE, 10)
            .unwrap();
        let candidate = BrokerResponse {
            code: ResponseCode::Ok,
            retry_after_millis: 0,
            attempt_id: lease.lease_id(),
            run_id: [0; 16],
            accepted_request_digest: teardown_request.request_digest,
            job_manifest_digest: teardown_request.manifest_digest,
            tip_oid: Some(teardown_request.integrated_candidate_sha),
            broker_state: BrokerState::Quarantined,
            conclusion: Conclusion::InfrastructureFailure,
            terminal_reason: 1,
            generation: lease.generation(),
            accepted_at: 10,
            updated_at: 10,
            lease_generation: lease.generation(),
            evidence_set_digest: [43; 32],
            teardown_digest: [44; 32],
            attempt: 1,
        };
        assert_eq!(
            validated_teardown_evidence(teardown_request, lease, candidate, 10),
            Some(([43; 32], [44; 32]))
        );
        assert_eq!(
            validated_teardown_evidence(
                teardown_request,
                lease,
                BrokerResponse {
                    accepted_request_digest: [99; 32],
                    ..candidate
                },
                10,
            ),
            None
        );
    }
}
