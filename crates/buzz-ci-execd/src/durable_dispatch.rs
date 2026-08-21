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
        DurableStateSnapshot, LeaseConclusion, LeaseToken, OrdinaryAdmission,
        QualificationLease, QualificationOutcome, ReadyRestoreValidation, VerifiedSigner,
    },
    control::{AdmissionBoundaryError, ClosedDispatch, ControlDispatch},
    runtime::{
        load_runtime, DurableStateStore, RuntimeBootstrap, RuntimeLoadError, ServiceAuthority,
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
    /// Bounded protocol response released only after the final durable commit.
    pub response: BrokerResponse,
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
    /// Bounded response released only after the terminal durable commit.
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

/// Fresh trusted host validation provider used only during bootstrap.
pub trait ReadyValidationProvider {
    /// Return current validation for the exact loaded grant, or fail closed.
    fn ready_validation(&mut self, now: u64) -> Option<ReadyRestoreValidation>;
}

/// Default bootstrap provider: no host proof, therefore no Ready restore.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableReadyValidation;

impl ReadyValidationProvider for UnavailableReadyValidation {
    fn ready_validation(&mut self, _now: u64) -> Option<ReadyRestoreValidation> {
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
    fn commit(&mut self) -> bool {
        if self.store.commit(self.controller.snapshot()).is_ok() {
            true
        } else {
            self.quarantine_in_memory();
            false
        }
    }

    fn quarantine_in_memory(&mut self) {
        let root = self.controller.snapshot().root_authority;
        let mut invalid = self.controller.snapshot();
        invalid.root_authority = VerifiedSigner([0; 32]);
        self.controller = ActivationController::restore(root, invalid, None).controller;
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
        execution.response
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
                let _ = self
                    .controller
                    .finish_qualification_teardown_failure(lease);
                false
            }
        };
        if !self.commit() || !terminal_ok {
            return response(ResponseCode::InternalFailure, now);
        }
        execution.response
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
            Request::CancelAttempt(_) | Request::GetAttempt(_) => {
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
    Loaded(DurableDispatch<DurableStateStore, ServiceAuthority, O, Q>),
}

impl<O: OrdinaryExecutor, Q: QualificationExecutor> ControlDispatch for BootstrapDispatch<O, Q> {
    fn dispatch(&mut self, header: FrameHeader, request: Request, now: u64) -> BrokerResponse {
        match self {
            Self::Closed(dispatch) => dispatch.dispatch(header, request, now),
            Self::Loaded(dispatch) => dispatch.dispatch(header, request, now),
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
            BootstrapDispatch::Loaded(runtime.compose(ordinary, qualification))
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
    compose_bootstrap(
        load_runtime(now, validation.ready_validation(now)),
        ordinary,
        qualification,
    )
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
    use buzz_ci_isolation_contract::{
        PHASE1_SECCOMP_PROFILE_DIGEST, PHASE1_SECCOMP_PROFILE_PATH,
    };

    use super::*;
    use crate::{
        activation::{
            ActivationGrant, AdmissionTrustClass, FixtureJobCoordinates,
            HostActivationCoordinates, OrdinaryJobCoordinates, QualificationPermit,
        },
        seccomp::{
            SeccompFileReadback, SeccompFileType, SeccompSeedPlan, SECCOMP_PROFILE_MODE,
        },
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
}
