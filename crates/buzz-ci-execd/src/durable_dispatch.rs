//! Durable ownership of execd admission and terminal lifecycle transitions.
//!
//! Execution adapters receive opaque lease receipts and return typed outcomes.
//! They never receive the controller. The dispatcher is the sole transition
//! owner and publishes every transition before returning a successful response.

pub mod crash_recovery;
pub mod teardown_provider;
pub mod terminal_evidence_collector;

use buzz_ci_broker_protocol::{
    AdmitAttemptRequest, BrokerResponse, BrokerState, CancelAttemptRequest, CancelReason,
    CompleteAttemptRequest, Conclusion, FrameHeader, GetAttemptRequest, QualificationDirective,
    QualificationRequest, Request, ResponseCode,
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
        RuntimeLoadError, RuntimePreparation, ServiceAuthority, STATE_TEMPORARY_EXISTS_RECOVERY,
    },
};

fn operator_persistence_log(error: RuntimeLoadError) -> Option<String> {
    (error == RuntimeLoadError::StateTemporaryExists).then(|| {
        format!(
            r#"{{"error":"state_temporary_exists","recovery":"{STATE_TEMPORARY_EXISTS_RECOVERY}"}}"#
        )
    })
}

fn log_operator_persistence_error(error: RuntimeLoadError) {
    if let Some(line) = operator_persistence_log(error) {
        eprintln!("{line}");
    }
}

/// Service-owned authority boundary. Wire signer claims cannot implement it.
pub trait AdmissionAuthority {
    /// Bind an ordinary frame to the exact root-authored admission.
    fn authorize_ordinary(
        &mut self,
        request: AdmitAttemptRequest,
    ) -> Result<OrdinaryAdmission, AdmissionBoundaryError>;

    /// Authenticate a terminal signer claim and return its root-owned admission binding.
    fn authenticate_ordinary_signer(
        &mut self,
        signer_pubkey: [u8; 32],
    ) -> Result<OrdinaryAuthorityBinding, AdmissionBoundaryError>;

    /// Authenticate a qualification frame independently of its signer claim.
    fn authenticate_qualification(
        &mut self,
        request: QualificationRequest,
    ) -> Result<VerifiedSigner, AdmissionBoundaryError>;

    /// Recover root-owned qualification authority for cleanup only.
    fn recover_qualification(
        &mut self,
        _lease: QualificationLease,
    ) -> Result<QualificationRequest, AdmissionBoundaryError> {
        Err(AdmissionBoundaryError::Unavailable)
    }
}

impl AdmissionAuthority for ServiceAuthority {
    fn authorize_ordinary(
        &mut self,
        request: AdmitAttemptRequest,
    ) -> Result<OrdinaryAdmission, AdmissionBoundaryError> {
        ServiceAuthority::authorize_ordinary(self, request)
    }

    fn authenticate_ordinary_signer(
        &mut self,
        signer_pubkey: [u8; 32],
    ) -> Result<OrdinaryAuthorityBinding, AdmissionBoundaryError> {
        ServiceAuthority::authenticate_ordinary_signer(self, signer_pubkey)
    }

    fn authenticate_qualification(
        &mut self,
        request: QualificationRequest,
    ) -> Result<VerifiedSigner, AdmissionBoundaryError> {
        ServiceAuthority::authenticate_qualification(self, request)
    }

    fn recover_qualification(
        &mut self,
        lease: QualificationLease,
    ) -> Result<QualificationRequest, AdmissionBoundaryError> {
        ServiceAuthority::recover_qualification(self, lease)
    }
}

/// Root-owned ordinary request and admission used to bind later mutations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrdinaryAuthorityBinding {
    /// Exact admitted wire request authenticated by the service authority.
    pub request: AdmitAttemptRequest,
    /// Exact controller admission derived from root-owned authority.
    pub admission: OrdinaryAdmission,
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

/// Execd-owned receipt facts for an already running ordinary lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrdinaryReceipts {
    /// Root-observed job conclusion.
    pub conclusion: LeaseConclusion,
    /// Digest computed from root-owned receipts, never copied from the completion claim.
    pub evidence_set_digest: [u8; 32],
}

/// Why root cleanup and reconciliation started.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrdinaryStop {
    /// Completion followed an execd-owned terminal receipt.
    Completed(LeaseConclusion),
    /// The authenticated controller requested cancellation.
    Cancelled {
        /// Signed cancellation digest already authenticated by the authority boundary.
        cancel_digest: [u8; 32],
        /// Closed cancellation reason carried by the authenticated request.
        reason: CancelReason,
    },
    /// The durable lease deadline elapsed without a terminal request.
    Expired,
    /// Startup retained an active token only to clean root resources.
    Recovery,
}

/// Root cleanup result controlling the final durable state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrdinaryCleanup {
    /// Only `Clean` may return the controller to Ready.
    pub disposition: CleanupDisposition,
    /// Root-owned teardown proof. A zero digest cannot prove clean cleanup.
    pub teardown_digest: [u8; 32],
}

/// Concrete ordinary execution seam. It cannot mutate activation state.
pub trait OrdinaryExecutor {
    /// Confirm required concrete execution providers exist before admission.
    fn preflight(
        &mut self,
        request: AdmitAttemptRequest,
        admission: OrdinaryAdmission,
    ) -> Result<(), ExecutionUnavailable>;

    /// Provision root-owned resources under an already committed lease.
    fn provision(
        &mut self,
        request: AdmitAttemptRequest,
        admission: OrdinaryAdmission,
        lease: LeaseToken,
    ) -> Result<(), ExecutionUnavailable>;

    /// Read execd-owned terminal receipts without receiving advisory wire claims.
    fn read_receipts(
        &mut self,
        request: AdmitAttemptRequest,
        admission: OrdinaryAdmission,
        lease: LeaseToken,
    ) -> Result<OrdinaryReceipts, ExecutionUnavailable>;

    /// Stop or clean the root resources bound to one exact durable lease.
    fn reconcile(
        &mut self,
        request: AdmitAttemptRequest,
        admission: OrdinaryAdmission,
        lease: LeaseToken,
        stop: OrdinaryStop,
    ) -> Result<OrdinaryCleanup, ExecutionUnavailable>;

    /// Observe that the controller durably returned this exact lease's slot.
    /// Implementations may use this as an audit hook; capacity authority stays
    /// with the activation controller.
    fn capacity_returned(
        &mut self,
        _request: AdmitAttemptRequest,
        _admission: OrdinaryAdmission,
        _lease: LeaseToken,
        _teardown_digest: [u8; 32],
    ) -> Result<(), ExecutionUnavailable> {
        Ok(())
    }
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

/// Why qualification cleanup-only reconciliation started.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QualificationStop {
    /// Startup retained an active qualification token only for cleanup.
    Recovery,
    /// The root permit expired while its exact fixture token remained active.
    Expired,
}

/// Root cleanup result for one retained qualification token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QualificationCleanup {
    /// Only `Clean` with a nonzero teardown digest clears the token.
    pub disposition: CleanupDisposition,
    /// Root-owned teardown proof. A zero digest cannot prove clean cleanup.
    pub teardown_digest: [u8; 32],
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

    /// Clean root resources without re-running qualification execution.
    fn reconcile(
        &mut self,
        _request: QualificationRequest,
        _lease: QualificationLease,
        _stop: QualificationStop,
    ) -> Result<QualificationCleanup, ExecutionUnavailable> {
        Err(ExecutionUnavailable)
    }
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

    fn provision(
        &mut self,
        _request: AdmitAttemptRequest,
        _admission: OrdinaryAdmission,
        _lease: LeaseToken,
    ) -> Result<(), ExecutionUnavailable> {
        Err(ExecutionUnavailable)
    }

    fn read_receipts(
        &mut self,
        _request: AdmitAttemptRequest,
        _admission: OrdinaryAdmission,
        _lease: LeaseToken,
    ) -> Result<OrdinaryReceipts, ExecutionUnavailable> {
        Err(ExecutionUnavailable)
    }

    fn reconcile(
        &mut self,
        _request: AdmitAttemptRequest,
        _admission: OrdinaryAdmission,
        _lease: LeaseToken,
        _stop: OrdinaryStop,
    ) -> Result<OrdinaryCleanup, ExecutionUnavailable> {
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
    fn commit(&mut self, recovery_lease: Option<LeaseToken>) -> bool {
        match self.store.commit(self.controller.snapshot()) {
            Ok(()) => true,
            Err(error) => {
                log_operator_persistence_error(error);
                self.controller
                    .quarantine_after_commit_failure(recovery_lease);
                false
            }
        }
    }

    fn commit_qualification(&mut self, recovery_lease: QualificationLease) -> bool {
        match self.store.commit(self.controller.snapshot()) {
            Ok(()) => true,
            Err(error) => {
                log_operator_persistence_error(error);
                self.controller
                    .quarantine_qualification_after_commit_failure(recovery_lease);
                false
            }
        }
    }

    fn admit_ordinary(&mut self, request: AdmitAttemptRequest, now: u64) -> BrokerResponse {
        let admission = match self.authority.authorize_ordinary(request) {
            Ok(admission) => admission,
            Err(error) => return boundary_error_response(error, now),
        };
        if let Err(error) = self.controller.preflight_ordinary(admission, now) {
            return response(admission_error_code(error), now);
        }
        if self.ordinary.preflight(request, admission).is_err() {
            return response(ResponseCode::NotProvisioned, now);
        }
        let lease = match self.controller.admit_ordinary(admission, now) {
            Ok(lease) => lease,
            Err(error) => return response(admission_error_code(error), now),
        };
        if !self.commit(Some(lease)) {
            return response(ResponseCode::InternalFailure, now);
        }
        if self.ordinary.provision(request, admission, lease).is_err() {
            return self.finish_ordinary(
                OrdinaryAuthorityBinding { request, admission },
                lease,
                LeaseConclusion::InfrastructureFailure,
                [0; 32],
                OrdinaryStop::Completed(LeaseConclusion::InfrastructureFailure),
                now,
            );
        }
        admitted_ordinary_response(request, admission, lease, now)
    }

    fn complete_ordinary(&mut self, request: CompleteAttemptRequest, now: u64) -> BrokerResponse {
        let binding = match self
            .authority
            .authenticate_ordinary_signer(request.signer_pubkey)
        {
            Ok(binding) => binding,
            Err(error) => return boundary_error_response(error, now),
        };
        if request.signed_request_digest != binding.request.signed_request_digest
            || request.run_id != binding.request.run_id
            || request.attempt != binding.request.attempt
            || request.lease_id != binding.admission.lease_id
            || request.terminal_at < binding.request.issued_at
            || request.terminal_at > now
        {
            return response(ResponseCode::PolicyDenied, now);
        }
        let lease = match self.controller.bind_active_lease(
            request.run_id,
            request.attempt,
            request.lease_id,
            request.lease_generation,
        ) {
            Ok(lease) => lease,
            Err(_) => return response(ResponseCode::NotFound, now),
        };
        let accepted_at = match self.controller.lease_admitted_at(lease) {
            Ok(accepted_at) => accepted_at,
            Err(_) => return response(ResponseCode::NotFound, now),
        };
        if request.terminal_at < accepted_at {
            return response(ResponseCode::PolicyDenied, now);
        }
        if now >= lease.deadline_at() || request.terminal_at > lease.deadline_at() {
            return response(ResponseCode::NotFound, now);
        }
        let receipts = match self
            .ordinary
            .read_receipts(binding.request, binding.admission, lease)
        {
            Ok(receipts)
                if receipts.evidence_set_digest != [0; 32]
                    && receipts.evidence_set_digest == request.evidence_set_digest
                    && !(request.advisory_conclusion == Conclusion::Success
                        && receipts.conclusion != LeaseConclusion::Success) =>
            {
                receipts
            }
            Ok(receipts) => OrdinaryReceipts {
                conclusion: LeaseConclusion::InfrastructureFailure,
                evidence_set_digest: receipts.evidence_set_digest,
            },
            Err(ExecutionUnavailable) => OrdinaryReceipts {
                conclusion: LeaseConclusion::InfrastructureFailure,
                evidence_set_digest: [0; 32],
            },
        };
        self.finish_ordinary(
            binding,
            lease,
            receipts.conclusion,
            receipts.evidence_set_digest,
            OrdinaryStop::Completed(receipts.conclusion),
            now,
        )
    }

    fn get_ordinary(&mut self, request: GetAttemptRequest, now: u64) -> BrokerResponse {
        let snapshot = self.controller.snapshot();
        let Some(lease) = snapshot.active_lease else {
            return response(ResponseCode::NotFound, now);
        };
        if request.attempt_id != lease.lease_id() {
            return response(ResponseCode::NotFound, now);
        }
        let binding = match self
            .authority
            .authenticate_ordinary_signer(lease.signer().0)
        {
            Ok(binding) => binding,
            Err(error) => return boundary_error_response(error, now),
        };
        if !ordinary_binding_matches_lease(binding, lease) {
            return response(ResponseCode::PolicyDenied, now);
        }
        let accepted_at = match self.controller.lease_admitted_at(lease) {
            Ok(accepted_at) => accepted_at,
            Err(_) => return response(ResponseCode::InternalFailure, now),
        };
        if now < accepted_at {
            return response(ResponseCode::InternalFailure, now);
        }
        let receipts = match self
            .ordinary
            .read_receipts(binding.request, binding.admission, lease)
        {
            Ok(receipts) if receipts.evidence_set_digest != [0; 32] => receipts,
            Ok(_) | Err(ExecutionUnavailable) => {
                return response(ResponseCode::InternalFailure, now)
            }
        };
        ordinary_readback_response(binding, lease, receipts, accepted_at, now)
    }

    fn cancel_ordinary(&mut self, request: CancelAttemptRequest, now: u64) -> BrokerResponse {
        let binding = match self
            .authority
            .authenticate_ordinary_signer(request.actor_pubkey)
        {
            Ok(binding) => binding,
            Err(error) => return boundary_error_response(error, now),
        };
        if request.attempt_id != binding.request.run_id
            || request.issued_at > now
            || now >= request.expires_at
            || request.issued_at >= request.expires_at
        {
            return response(ResponseCode::PolicyDenied, now);
        }
        let lease = match self.controller.bind_active_lease(
            binding.request.run_id,
            binding.request.attempt,
            binding.admission.lease_id,
            request.expected_generation,
        ) {
            Ok(lease) => lease,
            Err(_) => return response(ResponseCode::NotFound, now),
        };
        if now >= lease.deadline_at() {
            return response(ResponseCode::NotFound, now);
        }
        let Ok(receipts) = self
            .ordinary
            .read_receipts(binding.request, binding.admission, lease)
        else {
            return response(ResponseCode::InternalFailure, now);
        };
        if receipts.evidence_set_digest == [0; 32] {
            return response(ResponseCode::InternalFailure, now);
        }
        self.finish_ordinary(
            binding,
            lease,
            LeaseConclusion::Cancelled,
            receipts.evidence_set_digest,
            OrdinaryStop::Cancelled {
                cancel_digest: request.cancel_digest,
                reason: request.reason,
            },
            now,
        )
    }

    fn finish_ordinary(
        &mut self,
        binding: OrdinaryAuthorityBinding,
        lease: LeaseToken,
        conclusion: LeaseConclusion,
        evidence_set_digest: [u8; 32],
        stop: OrdinaryStop,
        now: u64,
    ) -> BrokerResponse {
        let accepted_at = match self.controller.lease_admitted_at(lease) {
            Ok(accepted_at) => accepted_at,
            Err(_) => return response(ResponseCode::InternalFailure, now),
        };
        if self.controller.finish_lease(lease, conclusion).is_err() {
            return response(ResponseCode::InternalFailure, now);
        }
        if !self.commit(Some(lease)) {
            let _ = self
                .ordinary
                .reconcile(binding.request, binding.admission, lease, stop);
            return response(ResponseCode::InternalFailure, now);
        }
        let cleanup = self
            .ordinary
            .reconcile(binding.request, binding.admission, lease, stop)
            .unwrap_or(OrdinaryCleanup {
                disposition: CleanupDisposition::Ambiguous,
                teardown_digest: [0; 32],
            });
        let receipts_allow_ready = matches!(
            stop,
            OrdinaryStop::Completed(LeaseConclusion::Success)
                | OrdinaryStop::Completed(LeaseConclusion::Failure)
                | OrdinaryStop::Completed(LeaseConclusion::TimedOut)
                | OrdinaryStop::Cancelled { .. }
                | OrdinaryStop::Expired
        );
        let disposition = if receipts_allow_ready
            && cleanup.disposition == CleanupDisposition::Clean
            && cleanup.teardown_digest != [0; 32]
        {
            CleanupDisposition::Clean
        } else {
            CleanupDisposition::Ambiguous
        };
        let terminal_ok = self
            .controller
            .finish_cleanup(lease, disposition, now)
            .is_ok();
        if !self.commit(Some(lease)) {
            return response(ResponseCode::InternalFailure, now);
        }
        if terminal_ok {
            let _ = self.ordinary.capacity_returned(
                binding.request,
                binding.admission,
                lease,
                cleanup.teardown_digest,
            );
        }
        completed_ordinary_response(
            binding.request,
            binding.admission,
            lease,
            conclusion,
            evidence_set_digest,
            cleanup.teardown_digest,
            terminal_ok,
            accepted_at,
            now,
        )
    }

    fn maintain_ordinary(&mut self, now: u64) {
        if let Some(lease) = self.controller.recovery_lease() {
            let Ok(binding) = self
                .authority
                .authenticate_ordinary_signer(lease.signer().0)
            else {
                return;
            };
            if binding.request.run_id != lease.run_id()
                || binding.request.attempt != lease.attempt()
                || binding.request.signed_request_digest != lease.signed_request_digest()
                || binding.admission.lease_id != lease.lease_id()
            {
                return;
            }
            let receipts = self
                .ordinary
                .read_receipts(binding.request, binding.admission, lease);
            if !receipts.is_ok_and(|receipts| receipts.evidence_set_digest != [0; 32]) {
                return;
            }
            let cleanup = self.ordinary.reconcile(
                binding.request,
                binding.admission,
                lease,
                OrdinaryStop::Recovery,
            );
            let Ok(cleanup) = cleanup else {
                return;
            };
            if cleanup.disposition == CleanupDisposition::Clean
                && cleanup.teardown_digest != [0; 32]
                && self.controller.finish_recovery(lease).is_ok()
                && self.commit(Some(lease))
            {
                let _ = self.ordinary.capacity_returned(
                    binding.request,
                    binding.admission,
                    lease,
                    cleanup.teardown_digest,
                );
            }
            return;
        }
        let Some(lease) = self.controller.expired_active_lease(now) else {
            return;
        };
        let Ok(binding) = self
            .authority
            .authenticate_ordinary_signer(lease.signer().0)
        else {
            return;
        };
        let Ok(receipts) = self
            .ordinary
            .read_receipts(binding.request, binding.admission, lease)
        else {
            return;
        };
        if receipts.evidence_set_digest == [0; 32] {
            return;
        }
        let _ = self.finish_ordinary(
            binding,
            lease,
            receipts.conclusion,
            receipts.evidence_set_digest,
            OrdinaryStop::Expired,
            now,
        );
    }

    fn maintain_qualification(&mut self, now: u64) {
        let (lease, stop) = if let Some(lease) = self.controller.qualification_recovery_lease() {
            (lease, QualificationStop::Recovery)
        } else if let Some(lease) = self.controller.expired_qualification_lease(now) {
            (lease, QualificationStop::Expired)
        } else {
            return;
        };
        let Ok(request) = self.authority.recover_qualification(lease) else {
            return;
        };
        if self
            .controller
            .quarantine_qualification_recovery(lease)
            .is_err()
        {
            return;
        }
        if !self.commit_qualification(lease) {
            return;
        }
        let cleanup = self.qualification.reconcile(request, lease, stop);
        // Failed or ambiguous cleanup leaves the committed Quarantined record and
        // its exact token available for a later cleanup-only retry.
        if cleanup.is_ok_and(|cleanup| {
            cleanup.disposition == CleanupDisposition::Clean && cleanup.teardown_digest != [0; 32]
        }) && self.controller.finish_qualification_recovery(lease).is_ok()
        {
            let _ = self.commit_qualification(lease);
        }
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
        if !self.commit(None) {
            return response(ResponseCode::InternalFailure, now);
        }

        let execution = match self.qualification.execute(header, request, lease, now) {
            Ok(execution) => execution,
            Err(ExecutionUnavailable) => {
                let _ = self
                    .controller
                    .finish_qualification(lease, QualificationOutcome::Ambiguous);
                let _ = self.commit(None);
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
        if !self.commit(None) {
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
            Request::AdmitAttempt(request) => self.admit_ordinary(request, now),
            Request::CancelAttempt(request) => self.cancel_ordinary(request, now),
            Request::GetAttempt(request) => self.get_ordinary(request, now),
            Request::CompleteAttempt(request) => self.complete_ordinary(request, now),
            Request::AdmitQualification(request) => self.qualification(header, request, now),
            Request::Hello(_) => response(ResponseCode::NotProvisioned, now),
        }
    }

    fn maintenance(&mut self, now: u64) {
        self.maintain_ordinary(now);
        self.maintain_qualification(now);
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

    fn maintenance(&mut self, now: u64) {
        if let Self::Loaded(dispatch) = self {
            dispatch.maintenance(now);
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
        RuntimeBootstrap::NotProvisioned(reason) | RuntimeBootstrap::Quarantined { reason, .. } => {
            log_operator_persistence_error(reason);
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

fn admitted_ordinary_response(
    request: AdmitAttemptRequest,
    admission: OrdinaryAdmission,
    lease: LeaseToken,
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
        broker_state: BrokerState::Leased,
        conclusion: Conclusion::None,
        terminal_reason: 0,
        generation: lease.generation(),
        accepted_at: now,
        updated_at: now,
        lease_generation: lease.generation(),
        evidence_set_digest: [0; 32],
        teardown_digest: [0; 32],
        attempt: request.attempt,
    }
}

fn ordinary_binding_matches_lease(binding: OrdinaryAuthorityBinding, lease: LeaseToken) -> bool {
    let request = binding.request;
    let admission = binding.admission;
    request.signed_request_digest != [0; 32]
        && request.signed_request_digest == admission.job.request_digest
        && request.signed_request_digest == lease.signed_request_digest()
        && request.actor_pubkey == admission.signer.0
        && admission.signer == lease.signer()
        && request.run_id == admission.run_id
        && request.run_id == lease.run_id()
        && request.attempt == admission.attempt
        && request.attempt == lease.attempt()
        && request.job_manifest_digest == admission.job.manifest_digest
        && request.isolation_profile_digest == admission.job.isolation_profile_digest
        && request.tip_oid == admission.job.source_oid
        && request.base_oid == admission.job.base_oid
        && request.expires_at == admission.expires_at
        && request.wall_timeout_seconds == admission.wall_timeout_seconds
        && admission.lease_id == lease.lease_id()
        && admission.nonce == lease.nonce()
        && lease.generation() != 0
        && lease.deadline_at() != 0
        && lease.deadline_at() <= admission.expires_at
}

fn ordinary_readback_response(
    binding: OrdinaryAuthorityBinding,
    lease: LeaseToken,
    receipts: OrdinaryReceipts,
    accepted_at: u64,
    now: u64,
) -> BrokerResponse {
    BrokerResponse {
        code: ResponseCode::Existing,
        retry_after_millis: 0,
        attempt_id: lease.lease_id(),
        run_id: lease.run_id(),
        accepted_request_digest: lease.signed_request_digest(),
        job_manifest_digest: binding.request.job_manifest_digest,
        tip_oid: Some(binding.request.tip_oid),
        broker_state: BrokerState::Terminal,
        conclusion: protocol_conclusion(receipts.conclusion),
        terminal_reason: 0,
        generation: lease.generation(),
        accepted_at,
        updated_at: now,
        lease_generation: lease.generation(),
        evidence_set_digest: receipts.evidence_set_digest,
        teardown_digest: [0; 32],
        attempt: lease.attempt(),
    }
}

#[allow(clippy::too_many_arguments)]
fn completed_ordinary_response(
    request: AdmitAttemptRequest,
    admission: OrdinaryAdmission,
    lease: LeaseToken,
    conclusion: LeaseConclusion,
    evidence_set_digest: [u8; 32],
    teardown_digest: [u8; 32],
    terminal_ok: bool,
    accepted_at: u64,
    now: u64,
) -> BrokerResponse {
    BrokerResponse {
        code: if terminal_ok {
            ResponseCode::Ok
        } else {
            ResponseCode::InternalFailure
        },
        retry_after_millis: 0,
        attempt_id: admission.lease_id,
        run_id: request.run_id,
        accepted_request_digest: request.signed_request_digest,
        job_manifest_digest: request.job_manifest_digest,
        tip_oid: Some(request.tip_oid),
        broker_state: if terminal_ok {
            BrokerState::Ready
        } else {
            BrokerState::Quarantined
        },
        conclusion: protocol_conclusion(conclusion),
        terminal_reason: u16::from(!terminal_ok),
        generation: lease.generation(),
        accepted_at,
        updated_at: now,
        lease_generation: lease.generation(),
        evidence_set_digest,
        teardown_digest,
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

    use super::crash_recovery::{
        AttemptEvidenceBinding, CrashRecoveryCoordinator, MemoryRecoveryJournal, RecoveryJournal,
        RecoveryRecord, RecoveryStage,
    };
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

        fn authenticate_ordinary_signer(
            &mut self,
            signer_pubkey: [u8; 32],
        ) -> Result<OrdinaryAuthorityBinding, AdmissionBoundaryError> {
            (signer_pubkey == self.admission.signer.0)
                .then_some(OrdinaryAuthorityBinding {
                    request: self.ordinary_request,
                    admission: self.admission,
                })
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

        fn recover_qualification(
            &mut self,
            lease: QualificationLease,
        ) -> Result<QualificationRequest, AdmissionBoundaryError> {
            let request = self.qualification_request;
            (lease.fixture_identity() == request.fixture_identity
                && lease.lease_id() == request.fixture_identity[..16]
                && lease.generation() != 0
                && lease.nonce() == request.nonce
                && lease.directive() == request.directive)
                .then_some(request)
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

    #[test]
    fn stale_state_temporary_log_names_condition_and_recovery() {
        assert_eq!(
            operator_persistence_log(RuntimeLoadError::StateTemporaryExists).as_deref(),
            Some(
                r#"{"error":"state_temporary_exists","recovery":"Stop every buzz-ci-execd state writer, remove /var/lib/buzzci/activation/.state-v1.json.tmp, then restart buzz-ci-execd."}"#
            )
        );
        assert_eq!(
            operator_persistence_log(RuntimeLoadError::PersistFailed),
            None
        );
    }

    #[derive(Clone)]
    struct OrdinaryCalls {
        provisions: Rc<Cell<usize>>,
        receipts: Rc<Cell<usize>>,
        reconciles: Rc<Cell<usize>>,
    }

    impl OrdinaryCalls {
        fn new() -> Self {
            Self {
                provisions: Rc::new(Cell::new(0)),
                receipts: Rc::new(Cell::new(0)),
                reconciles: Rc::new(Cell::new(0)),
            }
        }
    }

    struct OrdinaryFake {
        calls: OrdinaryCalls,
        provision_available: bool,
        receipts: OrdinaryReceipts,
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

        fn provision(
            &mut self,
            _request: AdmitAttemptRequest,
            _admission: OrdinaryAdmission,
            _lease: LeaseToken,
        ) -> Result<(), ExecutionUnavailable> {
            self.calls.provisions.set(self.calls.provisions.get() + 1);
            if self.provision_available {
                Ok(())
            } else {
                Err(ExecutionUnavailable)
            }
        }

        fn read_receipts(
            &mut self,
            _request: AdmitAttemptRequest,
            _admission: OrdinaryAdmission,
            _lease: LeaseToken,
        ) -> Result<OrdinaryReceipts, ExecutionUnavailable> {
            self.calls.receipts.set(self.calls.receipts.get() + 1);
            Ok(self.receipts)
        }

        fn reconcile(
            &mut self,
            _request: AdmitAttemptRequest,
            _admission: OrdinaryAdmission,
            _lease: LeaseToken,
            _stop: OrdinaryStop,
        ) -> Result<OrdinaryCleanup, ExecutionUnavailable> {
            self.calls.reconciles.set(self.calls.reconciles.get() + 1);
            Ok(OrdinaryCleanup {
                disposition: self.cleanup,
                teardown_digest: [45; 32],
            })
        }
    }

    fn ordinary_fake(calls: OrdinaryCalls) -> OrdinaryFake {
        OrdinaryFake {
            calls,
            provision_available: true,
            receipts: OrdinaryReceipts {
                conclusion: LeaseConclusion::Success,
                evidence_set_digest: [44; 32],
            },
            cleanup: CleanupDisposition::Clean,
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

    #[derive(Clone)]
    struct QualificationRecoveryCalls {
        executes: Rc<Cell<usize>>,
        reconciles: Rc<Cell<usize>>,
        stop: Rc<RefCell<Option<QualificationStop>>>,
    }

    impl QualificationRecoveryCalls {
        fn new() -> Self {
            Self {
                executes: Rc::new(Cell::new(0)),
                reconciles: Rc::new(Cell::new(0)),
                stop: Rc::new(RefCell::new(None)),
            }
        }
    }

    struct QualificationRecoveryFake {
        calls: QualificationRecoveryCalls,
        available: bool,
        cleanup: QualificationCleanup,
    }

    impl QualificationExecutor for QualificationRecoveryFake {
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
            _now: u64,
        ) -> Result<QualificationExecution, ExecutionUnavailable> {
            self.calls.executes.set(self.calls.executes.get() + 1);
            Err(ExecutionUnavailable)
        }

        fn reconcile(
            &mut self,
            _request: QualificationRequest,
            _lease: QualificationLease,
            stop: QualificationStop,
        ) -> Result<QualificationCleanup, ExecutionUnavailable> {
            self.calls.reconciles.set(self.calls.reconciles.get() + 1);
            self.calls.stop.replace(Some(stop));
            if self.available {
                Ok(self.cleanup)
            } else {
                Err(ExecutionUnavailable)
            }
        }
    }

    fn qualification_recovery_fake(calls: QualificationRecoveryCalls) -> QualificationRecoveryFake {
        QualificationRecoveryFake {
            calls,
            available: true,
            cleanup: QualificationCleanup {
                disposition: CleanupDisposition::Clean,
                teardown_digest: [46; 32],
            },
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
            run_id: request.run_id,
            attempt: request.attempt,
            signer: ORDINARY,
            nonce: [30; 32],
            expires_at: request.expires_at,
            wall_timeout_seconds: request.wall_timeout_seconds,
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

    fn active_qualification_controller() -> (ActivationController, QualificationLease) {
        let mut controller = qualifying_controller();
        let lease = controller
            .admit_qualification_request(qualification_request(), FIXTURE, 10)
            .expect("qualification admission");
        (controller, lease)
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

    fn complete_request(generation: u64) -> CompleteAttemptRequest {
        CompleteAttemptRequest {
            signer_pubkey: ORDINARY.0,
            signed_request_digest: ordinary_request().signed_request_digest,
            run_id: ordinary_request().run_id,
            attempt: ordinary_request().attempt,
            lease_id: ordinary_admission().lease_id,
            lease_generation: generation,
            advisory_conclusion: Conclusion::Success,
            evidence_set_digest: [44; 32],
            terminal_at: 22,
        }
    }

    fn complete_header() -> FrameHeader {
        FrameHeader {
            operation: Operation::CompleteAttempt,
            request_id: [32; 16],
        }
    }

    fn get_header() -> FrameHeader {
        FrameHeader {
            operation: Operation::GetAttempt,
            request_id: [34; 16],
        }
    }

    fn get_request(attempt_id: [u8; 16]) -> GetAttemptRequest {
        GetAttemptRequest { attempt_id }
    }

    fn recovery_binding(lease: LeaseToken) -> AttemptEvidenceBinding {
        let mut binding = AttemptEvidenceBinding {
            run_id: lease.run_id(),
            job_id: "durable-readback-job".to_owned(),
            attempt: lease.attempt(),
            controller_lease_id: lease.lease_id(),
            lease_generation: lease.generation(),
            lease_deadline_at: lease.deadline_at(),
            host_lease_id: "durable-readback-host-lease".to_owned(),
            workspace_sha256: [71; 32],
            binding_sha256: [0; 32],
        };
        binding.binding_sha256 = binding.digest();
        binding
    }

    fn cancel_request(generation: u64) -> CancelAttemptRequest {
        CancelAttemptRequest {
            attempt_id: ordinary_request().run_id,
            actor_pubkey: ORDINARY.0,
            cancel_digest: [46; 32],
            issued_at: 21,
            expires_at: 30,
            expected_generation: generation,
            reason: CancelReason::Shutdown,
        }
    }

    fn cancel_header() -> FrameHeader {
        FrameHeader {
            operation: Operation::CancelAttempt,
            request_id: [33; 16],
        }
    }

    #[test]
    fn ordinary_success_is_admitted_then_completed_in_two_durable_phases() {
        let store = FakeStore::new(None);
        let commits = Rc::clone(&store.commits);
        let calls = OrdinaryCalls::new();
        let mut dispatch = DurableDispatch::new(
            ready_controller(),
            authority(),
            store,
            ordinary_fake(calls.clone()),
            QualificationFake,
        );

        let admitted = dispatch.dispatch(
            ordinary_header(),
            Request::AdmitAttempt(ordinary_request()),
            21,
        );

        assert_eq!(admitted.code, ResponseCode::Ok);
        assert_eq!(admitted.attempt_id, ordinary_admission().lease_id);
        assert_eq!(admitted.run_id, ordinary_request().run_id);
        assert_eq!(
            admitted.accepted_request_digest,
            ordinary_request().signed_request_digest
        );
        assert_eq!(
            admitted.job_manifest_digest,
            ordinary_request().job_manifest_digest
        );
        assert_eq!(admitted.tip_oid, Some(ordinary_request().tip_oid));
        assert_eq!(admitted.broker_state, BrokerState::Leased);
        assert_eq!(admitted.conclusion, Conclusion::None);
        assert_eq!(admitted.generation, 2);
        assert_eq!(admitted.lease_generation, 2);
        assert_eq!(admitted.attempt, ordinary_request().attempt);
        assert_eq!(calls.provisions.get(), 1);
        assert_eq!(calls.receipts.get(), 0);
        assert_eq!(calls.reconciles.get(), 0);
        assert_eq!(dispatch.state(), ActivationState::Leased);
        assert_eq!(commits.borrow()[0].state, ActivationState::Leased);

        let mut completion = complete_request(admitted.lease_generation);
        completion.advisory_conclusion = Conclusion::Failure;
        let completed =
            dispatch.dispatch(complete_header(), Request::CompleteAttempt(completion), 22);

        assert_eq!(completed.code, ResponseCode::Ok);
        assert_eq!(completed.attempt_id, admitted.attempt_id);
        assert_eq!(completed.accepted_at, admitted.accepted_at);
        assert_eq!(completed.broker_state, BrokerState::Ready);
        assert_eq!(completed.conclusion, Conclusion::Success);
        assert_eq!(completed.evidence_set_digest, [44; 32]);
        assert_eq!(
            completed.evidence_set_digest,
            completion.evidence_set_digest
        );
        assert_eq!(completed.teardown_digest, [45; 32]);
        assert_eq!(calls.receipts.get(), 1);
        assert_eq!(calls.reconciles.get(), 1);
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
            restart
                .controller
                .recovery_lease()
                .map(LeaseToken::lease_id),
            Some(admitted.attempt_id)
        );
        assert_eq!(
            restart.quarantine_reason,
            Some(crate::activation::ActivationError::RestartAmbiguous)
        );
    }

    #[test]
    fn get_attempt_returns_exact_terminal_receipts_without_state_change() {
        let store = FakeStore::new(None);
        let commits = Rc::clone(&store.commits);
        let calls = OrdinaryCalls::new();
        let mut dispatch = DurableDispatch::new(
            ready_controller(),
            authority(),
            store,
            ordinary_fake(calls.clone()),
            QualificationFake,
        );
        let admitted = dispatch.dispatch(
            ordinary_header(),
            Request::AdmitAttempt(ordinary_request()),
            21,
        );
        let snapshot = dispatch.controller.snapshot();
        let commit_count = commits.borrow().len();

        let result = dispatch.dispatch(
            get_header(),
            Request::GetAttempt(get_request(admitted.attempt_id)),
            22,
        );

        assert_eq!(result.code, ResponseCode::Existing);
        assert_eq!(result.attempt_id, admitted.attempt_id);
        assert_eq!(result.run_id, admitted.run_id);
        assert_eq!(
            result.accepted_request_digest,
            admitted.accepted_request_digest
        );
        assert_eq!(result.job_manifest_digest, admitted.job_manifest_digest);
        assert_eq!(result.tip_oid, admitted.tip_oid);
        assert_eq!(result.broker_state, BrokerState::Terminal);
        assert_eq!(result.conclusion, Conclusion::Success);
        assert_eq!(result.generation, admitted.generation);
        assert_eq!(result.accepted_at, admitted.accepted_at);
        assert_eq!(result.updated_at, 22);
        assert_eq!(result.lease_generation, admitted.lease_generation);
        assert_eq!(result.evidence_set_digest, [44; 32]);
        assert_eq!(result.teardown_digest, [0; 32]);
        assert_eq!(result.attempt, admitted.attempt);
        assert_eq!(calls.receipts.get(), 1);
        assert_eq!(calls.reconciles.get(), 0);
        assert_eq!(dispatch.controller.snapshot(), snapshot);
        assert_eq!(commits.borrow().len(), commit_count);
    }

    #[test]
    fn get_attempt_refuses_unknown_or_mismatched_durable_bindings() {
        let store = FakeStore::new(None);
        let commits = Rc::clone(&store.commits);
        let calls = OrdinaryCalls::new();
        let mut dispatch = DurableDispatch::new(
            ready_controller(),
            authority(),
            store,
            ordinary_fake(calls.clone()),
            QualificationFake,
        );
        let admitted = dispatch.dispatch(
            ordinary_header(),
            Request::AdmitAttempt(ordinary_request()),
            21,
        );
        let snapshot = dispatch.controller.snapshot();
        let commit_count = commits.borrow().len();

        let unknown =
            dispatch.dispatch(get_header(), Request::GetAttempt(get_request([99; 16])), 22);
        assert_eq!(unknown.code, ResponseCode::NotFound);

        dispatch.authority.ordinary_request.run_id = [98; 16];
        let wrong_binding = dispatch.dispatch(
            get_header(),
            Request::GetAttempt(get_request(admitted.attempt_id)),
            22,
        );
        assert_eq!(wrong_binding.code, ResponseCode::PolicyDenied);

        dispatch.authority.ordinary_request.run_id = ordinary_request().run_id;
        dispatch.authority.ordinary_request.signed_request_digest = [97; 32];
        let wrong_digest = dispatch.dispatch(
            get_header(),
            Request::GetAttempt(get_request(admitted.attempt_id)),
            22,
        );
        assert_eq!(wrong_digest.code, ResponseCode::PolicyDenied);
        assert_eq!(calls.receipts.get(), 0);
        assert_eq!(dispatch.controller.snapshot(), snapshot);
        assert_eq!(commits.borrow().len(), commit_count);
    }

    #[test]
    fn get_attempt_replays_persisted_terminal_receipts_after_restart() {
        let store = FakeStore::new(None);
        let commits = Rc::clone(&store.commits);
        let journal = MemoryRecoveryJournal::default();
        let first_calls = OrdinaryCalls::new();
        let mut dispatch = DurableDispatch::new(
            ready_controller(),
            authority(),
            store,
            CrashRecoveryCoordinator::new(ordinary_fake(first_calls), journal.clone()),
            QualificationFake,
        );
        let admitted = dispatch.dispatch(
            ordinary_header(),
            Request::AdmitAttempt(ordinary_request()),
            21,
        );
        let lease = dispatch
            .controller
            .snapshot()
            .active_lease
            .expect("active lease");
        let binding = recovery_binding(lease);
        journal
            .advance(RecoveryRecord {
                binding: binding.clone(),
                stage: RecoveryStage::Active,
            })
            .unwrap();
        journal
            .advance(RecoveryRecord {
                binding,
                stage: RecoveryStage::EvidenceUploaded {
                    conclusion: LeaseConclusion::Success,
                    evidence_set_digest: [44; 32],
                },
            })
            .unwrap();
        let persisted = commits.borrow()[0];
        let restored = ActivationController::restore(ROOT, persisted, None);
        assert_eq!(restored.controller.state(), ActivationState::Quarantined);
        drop(dispatch);

        let restarted_store = FakeStore::new(None);
        let restarted_commits = Rc::clone(&restarted_store.commits);
        let restarted_calls = OrdinaryCalls::new();
        let mut restarted = DurableDispatch::new(
            restored.controller,
            authority(),
            restarted_store,
            CrashRecoveryCoordinator::new(ordinary_fake(restarted_calls.clone()), journal),
            QualificationFake,
        );
        let restart_snapshot = restarted.controller.snapshot();
        let result = restarted.dispatch(
            get_header(),
            Request::GetAttempt(get_request(admitted.attempt_id)),
            23,
        );

        assert_eq!(result.code, ResponseCode::Existing);
        assert_eq!(result.attempt_id, admitted.attempt_id);
        assert_eq!(result.accepted_at, admitted.accepted_at);
        assert_eq!(result.broker_state, BrokerState::Terminal);
        assert_eq!(result.conclusion, Conclusion::Success);
        assert_eq!(result.evidence_set_digest, [44; 32]);
        assert_eq!(restarted_calls.receipts.get(), 0);
        assert_eq!(restarted.controller.snapshot(), restart_snapshot);
        assert!(restarted_commits.borrow().is_empty());
    }

    #[test]
    fn invalid_completion_bindings_have_zero_state_change() {
        let store = FakeStore::new(None);
        let commits = Rc::clone(&store.commits);
        let calls = OrdinaryCalls::new();
        let mut dispatch = DurableDispatch::new(
            ready_controller(),
            authority(),
            store,
            ordinary_fake(calls.clone()),
            QualificationFake,
        );
        let admitted = dispatch.dispatch(
            ordinary_header(),
            Request::AdmitAttempt(ordinary_request()),
            21,
        );
        let snapshot = dispatch.controller.snapshot();
        let commit_count = commits.borrow().len();
        let commit_attempts = dispatch.store.attempts.get();

        let wrong_generation = dispatch.dispatch(
            complete_header(),
            Request::CompleteAttempt(complete_request(admitted.lease_generation + 1)),
            22,
        );
        assert_eq!(wrong_generation.code, ResponseCode::NotFound);

        let mut stale = complete_request(admitted.lease_generation);
        stale.run_id = [88; 16];
        stale.lease_id = [88; 16];
        let stale = dispatch.dispatch(complete_header(), Request::CompleteAttempt(stale), 22);
        assert_eq!(stale.code, ResponseCode::PolicyDenied);

        let mut wrong_signer = complete_request(admitted.lease_generation);
        wrong_signer.signer_pubkey = [89; 32];
        let wrong_signer = dispatch.dispatch(
            complete_header(),
            Request::CompleteAttempt(wrong_signer),
            22,
        );
        assert_eq!(wrong_signer.code, ResponseCode::PolicyDenied);

        let mut before_admission = complete_request(admitted.lease_generation);
        before_admission.terminal_at = 20;
        let before_admission = dispatch.dispatch(
            complete_header(),
            Request::CompleteAttempt(before_admission),
            22,
        );
        assert_eq!(before_admission.code, ResponseCode::PolicyDenied);

        let at_lease_deadline = dispatch.dispatch(
            complete_header(),
            Request::CompleteAttempt(complete_request(admitted.lease_generation)),
            51,
        );
        assert_eq!(at_lease_deadline.code, ResponseCode::NotFound);

        assert_eq!(dispatch.controller.snapshot(), snapshot);
        assert_eq!(commits.borrow().len(), commit_count);
        assert_eq!(dispatch.store.attempts.get(), commit_attempts);
        assert_eq!(calls.receipts.get(), 0);
        assert_eq!(calls.reconciles.get(), 0);
    }

    #[test]
    fn second_completion_has_zero_state_change() {
        let store = FakeStore::new(None);
        let commits = Rc::clone(&store.commits);
        let calls = OrdinaryCalls::new();
        let mut dispatch = DurableDispatch::new(
            ready_controller(),
            authority(),
            store,
            ordinary_fake(calls.clone()),
            QualificationFake,
        );
        let admitted = dispatch.dispatch(
            ordinary_header(),
            Request::AdmitAttempt(ordinary_request()),
            21,
        );
        let completion = complete_request(admitted.lease_generation);
        assert_eq!(
            dispatch
                .dispatch(complete_header(), Request::CompleteAttempt(completion), 22,)
                .code,
            ResponseCode::Ok
        );
        let snapshot = dispatch.controller.snapshot();
        let commit_count = commits.borrow().len();
        let receipt_count = calls.receipts.get();
        let reconcile_count = calls.reconciles.get();

        let second = dispatch.dispatch(complete_header(), Request::CompleteAttempt(completion), 23);

        assert_eq!(second.code, ResponseCode::NotFound);
        assert_eq!(dispatch.controller.snapshot(), snapshot);
        assert_eq!(commits.borrow().len(), commit_count);
        assert_eq!(calls.receipts.get(), receipt_count);
        assert_eq!(calls.reconciles.get(), reconcile_count);
    }

    #[test]
    fn cancel_is_durable_and_later_completion_has_zero_state_change() {
        let store = FakeStore::new(None);
        let commits = Rc::clone(&store.commits);
        let calls = OrdinaryCalls::new();
        let mut dispatch = DurableDispatch::new(
            ready_controller(),
            authority(),
            store,
            ordinary_fake(calls.clone()),
            QualificationFake,
        );
        let admitted = dispatch.dispatch(
            ordinary_header(),
            Request::AdmitAttempt(ordinary_request()),
            21,
        );

        let cancelled = dispatch.dispatch(
            cancel_header(),
            Request::CancelAttempt(cancel_request(admitted.lease_generation)),
            22,
        );

        assert_eq!(cancelled.code, ResponseCode::Ok);
        assert_eq!(cancelled.conclusion, Conclusion::Cancelled);
        assert_eq!(cancelled.broker_state, BrokerState::Ready);
        assert_eq!(cancelled.teardown_digest, [45; 32]);
        assert_eq!(calls.receipts.get(), 1);
        assert_eq!(calls.reconciles.get(), 1);
        let states: Vec<_> = commits.borrow().iter().map(|entry| entry.state).collect();
        assert_eq!(
            states,
            [
                ActivationState::Leased,
                ActivationState::Draining,
                ActivationState::Ready
            ]
        );

        let snapshot = dispatch.controller.snapshot();
        let commit_count = commits.borrow().len();
        let complete = dispatch.dispatch(
            complete_header(),
            Request::CompleteAttempt(complete_request(admitted.lease_generation)),
            23,
        );
        assert_eq!(complete.code, ResponseCode::NotFound);
        assert_eq!(dispatch.controller.snapshot(), snapshot);
        assert_eq!(commits.borrow().len(), commit_count);
        assert_eq!(calls.receipts.get(), 1);
        assert_eq!(calls.reconciles.get(), 1);
    }

    #[test]
    fn invalid_cancel_has_zero_state_change() {
        let store = FakeStore::new(None);
        let commits = Rc::clone(&store.commits);
        let calls = OrdinaryCalls::new();
        let mut dispatch = DurableDispatch::new(
            ready_controller(),
            authority(),
            store,
            ordinary_fake(calls.clone()),
            QualificationFake,
        );
        let admitted = dispatch.dispatch(
            ordinary_header(),
            Request::AdmitAttempt(ordinary_request()),
            21,
        );
        let snapshot = dispatch.controller.snapshot();
        let commit_count = commits.borrow().len();

        let wrong_generation = dispatch.dispatch(
            cancel_header(),
            Request::CancelAttempt(cancel_request(admitted.lease_generation + 1)),
            22,
        );
        assert_eq!(wrong_generation.code, ResponseCode::NotFound);
        let mut wrong_signer = cancel_request(admitted.lease_generation);
        wrong_signer.actor_pubkey = [99; 32];
        assert_eq!(
            dispatch
                .dispatch(cancel_header(), Request::CancelAttempt(wrong_signer), 22,)
                .code,
            ResponseCode::PolicyDenied
        );
        let mut expired = cancel_request(admitted.lease_generation);
        expired.expires_at = 22;
        assert_eq!(
            dispatch
                .dispatch(cancel_header(), Request::CancelAttempt(expired), 22)
                .code,
            ResponseCode::PolicyDenied
        );
        let mut at_lease_deadline = cancel_request(admitted.lease_generation);
        at_lease_deadline.expires_at = 60;
        assert_eq!(
            dispatch
                .dispatch(
                    cancel_header(),
                    Request::CancelAttempt(at_lease_deadline),
                    51,
                )
                .code,
            ResponseCode::NotFound
        );

        assert_eq!(dispatch.controller.snapshot(), snapshot);
        assert_eq!(commits.borrow().len(), commit_count);
        assert_eq!(calls.receipts.get(), 0);
        assert_eq!(calls.reconciles.get(), 0);
    }

    #[test]
    fn leased_commit_failure_retains_recovery_lease_until_cleanup() {
        let store = FakeStore::new(Some(1));
        let commits = Rc::clone(&store.commits);
        let calls = OrdinaryCalls::new();
        let mut dispatch = DurableDispatch::new(
            ready_controller(),
            authority(),
            store,
            ordinary_fake(calls.clone()),
            QualificationFake,
        );

        let result = dispatch.dispatch(
            ordinary_header(),
            Request::AdmitAttempt(ordinary_request()),
            21,
        );

        assert_eq!(result.code, ResponseCode::InternalFailure);
        assert_eq!(calls.provisions.get(), 0);
        assert_eq!(calls.receipts.get(), 0);
        assert_eq!(calls.reconciles.get(), 0);
        assert_eq!(dispatch.state(), ActivationState::Quarantined);
        let recovery_lease = dispatch
            .controller
            .recovery_lease()
            .expect("failed Leased commit retains exact recovery lease");
        assert_eq!(recovery_lease.lease_id(), ordinary_admission().lease_id);
        assert!(commits.borrow().is_empty());

        dispatch.maintenance(21);

        assert_eq!(calls.reconciles.get(), 1);
        assert_eq!(dispatch.state(), ActivationState::Quarantined);
        assert_eq!(dispatch.controller.recovery_lease(), None);
        assert_eq!(commits.borrow().len(), 1);
        assert_eq!(commits.borrow()[0].state, ActivationState::Quarantined);
        assert_eq!(commits.borrow()[0].active_lease, None);
    }

    #[test]
    fn draining_commit_failure_still_reconciles_and_retains_recovery_lease() {
        let store = FakeStore::new(Some(2));
        let commits = Rc::clone(&store.commits);
        let calls = OrdinaryCalls::new();
        let mut dispatch = DurableDispatch::new(
            ready_controller(),
            authority(),
            store,
            ordinary_fake(calls.clone()),
            QualificationFake,
        );
        let admitted = dispatch.dispatch(
            ordinary_header(),
            Request::AdmitAttempt(ordinary_request()),
            21,
        );

        let result = dispatch.dispatch(
            complete_header(),
            Request::CompleteAttempt(complete_request(admitted.lease_generation)),
            22,
        );

        assert_eq!(result.code, ResponseCode::InternalFailure);
        assert_ne!(result.broker_state, BrokerState::Ready);
        assert_eq!(calls.receipts.get(), 1);
        assert_eq!(calls.reconciles.get(), 1);
        assert_eq!(dispatch.state(), ActivationState::Quarantined);
        assert_eq!(
            dispatch
                .controller
                .recovery_lease()
                .map(LeaseToken::lease_id),
            Some(ordinary_admission().lease_id)
        );
        assert_eq!(commits.borrow().len(), 1);
        assert_eq!(commits.borrow()[0].state, ActivationState::Leased);
        assert_eq!(
            commits.borrow()[0].active_lease.map(LeaseToken::lease_id),
            Some(ordinary_admission().lease_id)
        );
    }

    #[test]
    fn cancellation_draining_commit_failure_still_reconciles_fail_closed() {
        let store = FakeStore::new(Some(2));
        let commits = Rc::clone(&store.commits);
        let calls = OrdinaryCalls::new();
        let mut dispatch = DurableDispatch::new(
            ready_controller(),
            authority(),
            store,
            ordinary_fake(calls.clone()),
            QualificationFake,
        );
        let admitted = dispatch.dispatch(
            ordinary_header(),
            Request::AdmitAttempt(ordinary_request()),
            21,
        );

        let result = dispatch.dispatch(
            cancel_header(),
            Request::CancelAttempt(cancel_request(admitted.lease_generation)),
            22,
        );

        assert_eq!(result.code, ResponseCode::InternalFailure);
        assert_ne!(result.broker_state, BrokerState::Ready);
        assert_eq!(calls.receipts.get(), 1);
        assert_eq!(calls.reconciles.get(), 1);
        assert_eq!(dispatch.state(), ActivationState::Quarantined);
        assert_eq!(
            dispatch
                .controller
                .recovery_lease()
                .map(LeaseToken::lease_id),
            Some(ordinary_admission().lease_id)
        );
        assert_eq!(commits.borrow().len(), 1);
        assert_eq!(commits.borrow()[0].state, ActivationState::Leased);
    }

    #[test]
    fn expiry_draining_commit_failure_still_reconciles_fail_closed() {
        let store = FakeStore::new(Some(2));
        let commits = Rc::clone(&store.commits);
        let calls = OrdinaryCalls::new();
        let mut dispatch = DurableDispatch::new(
            ready_controller(),
            authority(),
            store,
            ordinary_fake(calls.clone()),
            QualificationFake,
        );
        dispatch.dispatch(
            ordinary_header(),
            Request::AdmitAttempt(ordinary_request()),
            21,
        );

        dispatch.maintenance(51);

        assert_eq!(calls.receipts.get(), 1);
        assert_eq!(calls.reconciles.get(), 1);
        assert_eq!(dispatch.state(), ActivationState::Quarantined);
        assert_eq!(
            dispatch
                .controller
                .recovery_lease()
                .map(LeaseToken::lease_id),
            Some(ordinary_admission().lease_id)
        );
        assert_eq!(commits.borrow().len(), 1);
        assert_eq!(commits.borrow()[0].state, ActivationState::Leased);
    }

    #[test]
    fn provisioning_starts_only_after_durable_lease_and_failure_is_reconciled() {
        let store = FakeStore::new(None);
        let commits = Rc::clone(&store.commits);
        let calls = OrdinaryCalls::new();
        let mut executor = ordinary_fake(calls.clone());
        executor.provision_available = false;
        let mut dispatch = DurableDispatch::new(
            ready_controller(),
            authority(),
            store,
            executor,
            QualificationFake,
        );

        let result = dispatch.dispatch(
            ordinary_header(),
            Request::AdmitAttempt(ordinary_request()),
            21,
        );

        assert_eq!(result.code, ResponseCode::InternalFailure);
        assert_eq!(result.broker_state, BrokerState::Quarantined);
        assert_eq!(calls.provisions.get(), 1);
        assert_eq!(calls.receipts.get(), 0);
        assert_eq!(calls.reconciles.get(), 1);
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
    fn final_commit_failure_suppresses_success_and_closes_capacity() {
        let store = FakeStore::new(Some(3));
        let commits = Rc::clone(&store.commits);
        let calls = OrdinaryCalls::new();
        let mut dispatch = DurableDispatch::new(
            ready_controller(),
            authority(),
            store,
            ordinary_fake(calls.clone()),
            QualificationFake,
        );

        let admitted = dispatch.dispatch(
            ordinary_header(),
            Request::AdmitAttempt(ordinary_request()),
            21,
        );
        let result = dispatch.dispatch(
            complete_header(),
            Request::CompleteAttempt(complete_request(admitted.lease_generation)),
            22,
        );

        assert_eq!(result.code, ResponseCode::InternalFailure);
        assert_ne!(result.broker_state, BrokerState::Ready);
        assert_eq!(calls.receipts.get(), 1);
        assert_eq!(calls.reconciles.get(), 1);
        assert_eq!(dispatch.state(), ActivationState::Quarantined);
        assert_eq!(
            dispatch
                .controller
                .recovery_lease()
                .map(LeaseToken::lease_id),
            Some(ordinary_admission().lease_id)
        );
        let states: Vec<_> = commits.borrow().iter().map(|entry| entry.state).collect();
        assert_eq!(states, [ActivationState::Leased, ActivationState::Draining]);
        assert_eq!(
            commits.borrow()[1].active_lease.map(LeaseToken::lease_id),
            Some(ordinary_admission().lease_id)
        );
    }

    #[test]
    fn claimed_success_over_failed_receipts_is_durably_quarantined() {
        let store = FakeStore::new(None);
        let commits = Rc::clone(&store.commits);
        let calls = OrdinaryCalls::new();
        let mut dispatch = DurableDispatch::new(
            ready_controller(),
            authority(),
            store,
            OrdinaryFake {
                calls: calls.clone(),
                provision_available: true,
                receipts: OrdinaryReceipts {
                    conclusion: LeaseConclusion::Failure,
                    evidence_set_digest: [47; 32],
                },
                cleanup: CleanupDisposition::Ambiguous,
            },
            QualificationFake,
        );

        let admitted = dispatch.dispatch(
            ordinary_header(),
            Request::AdmitAttempt(ordinary_request()),
            21,
        );
        let mut completion = complete_request(admitted.lease_generation);
        completion.evidence_set_digest = [47; 32];
        let result = dispatch.dispatch(complete_header(), Request::CompleteAttempt(completion), 22);

        assert_eq!(result.code, ResponseCode::InternalFailure);
        assert_eq!(result.broker_state, BrokerState::Quarantined);
        assert_eq!(result.conclusion, Conclusion::InfrastructureFailure);
        assert_eq!(result.evidence_set_digest, [47; 32]);
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
    fn matching_failed_job_receipt_returns_ready_after_clean_cleanup() {
        let store = FakeStore::new(None);
        let calls = OrdinaryCalls::new();
        let mut dispatch = DurableDispatch::new(
            ready_controller(),
            authority(),
            store,
            OrdinaryFake {
                calls,
                provision_available: true,
                receipts: OrdinaryReceipts {
                    conclusion: LeaseConclusion::Failure,
                    evidence_set_digest: [47; 32],
                },
                cleanup: CleanupDisposition::Clean,
            },
            QualificationFake,
        );

        let admitted = dispatch.dispatch(
            ordinary_header(),
            Request::AdmitAttempt(ordinary_request()),
            21,
        );
        let mut completion = complete_request(admitted.lease_generation);
        completion.advisory_conclusion = Conclusion::Failure;
        completion.evidence_set_digest = [47; 32];
        let result = dispatch.dispatch(complete_header(), Request::CompleteAttempt(completion), 22);

        assert_eq!(result.code, ResponseCode::Ok);
        assert_eq!(result.broker_state, BrokerState::Ready);
        assert_eq!(result.conclusion, Conclusion::Failure);
        assert_eq!(result.evidence_set_digest, [47; 32]);
        assert_eq!(dispatch.state(), ActivationState::Ready);
    }

    #[test]
    fn claimed_evidence_mismatch_uses_root_digest_and_quarantines() {
        let store = FakeStore::new(None);
        let calls = OrdinaryCalls::new();
        let mut dispatch = DurableDispatch::new(
            ready_controller(),
            authority(),
            store,
            ordinary_fake(calls),
            QualificationFake,
        );
        let admitted = dispatch.dispatch(
            ordinary_header(),
            Request::AdmitAttempt(ordinary_request()),
            21,
        );
        let mut completion = complete_request(admitted.lease_generation);
        completion.evidence_set_digest = [99; 32];

        let result = dispatch.dispatch(complete_header(), Request::CompleteAttempt(completion), 22);

        assert_eq!(result.code, ResponseCode::InternalFailure);
        assert_eq!(result.broker_state, BrokerState::Quarantined);
        assert_eq!(result.conclusion, Conclusion::InfrastructureFailure);
        assert_eq!(result.evidence_set_digest, [44; 32]);
    }

    #[test]
    fn maintenance_expires_a_lease_without_control_traffic() {
        let store = FakeStore::new(None);
        let commits = Rc::clone(&store.commits);
        let calls = OrdinaryCalls::new();
        let mut dispatch = DurableDispatch::new(
            ready_controller(),
            authority(),
            store,
            ordinary_fake(calls.clone()),
            QualificationFake,
        );
        dispatch.dispatch(
            ordinary_header(),
            Request::AdmitAttempt(ordinary_request()),
            21,
        );

        dispatch.maintenance(50);
        assert_eq!(dispatch.state(), ActivationState::Leased);
        assert_eq!(commits.borrow().len(), 1);
        dispatch.maintenance(51);

        assert_eq!(dispatch.state(), ActivationState::Ready);
        assert_eq!(calls.receipts.get(), 1);
        assert_eq!(calls.reconciles.get(), 1);
        let states: Vec<_> = commits.borrow().iter().map(|entry| entry.state).collect();
        assert_eq!(
            states,
            [
                ActivationState::Leased,
                ActivationState::Draining,
                ActivationState::Ready
            ]
        );
    }

    #[test]
    fn restart_recovery_cleans_only_retained_token_and_stays_quarantined() {
        let mut controller = ready_controller();
        let lease = controller
            .admit_ordinary(ordinary_admission(), 21)
            .expect("ordinary lease");
        let restored = ActivationController::restore(ROOT, controller.snapshot(), None);
        assert_eq!(restored.controller.recovery_lease(), Some(lease));
        let store = FakeStore::new(None);
        let commits = Rc::clone(&store.commits);
        let calls = OrdinaryCalls::new();
        let mut dispatch = DurableDispatch::new(
            restored.controller,
            authority(),
            store,
            ordinary_fake(calls.clone()),
            QualificationFake,
        );

        dispatch.maintenance(22);

        assert_eq!(dispatch.state(), ActivationState::Quarantined);
        assert_eq!(dispatch.controller.recovery_lease(), None);
        assert_eq!(calls.receipts.get(), 1);
        assert_eq!(calls.reconciles.get(), 1);
        assert_eq!(commits.borrow().len(), 1);
        assert_eq!(commits.borrow()[0].state, ActivationState::Quarantined);
        assert_eq!(commits.borrow()[0].active_lease, None);
    }

    #[test]
    fn qualification_restart_recovery_commits_quarantine_before_cleanup_then_commits_clear() {
        let (controller, lease) = active_qualification_controller();
        let restored = ActivationController::restore(ROOT, controller.snapshot(), None);
        assert_eq!(
            restored.controller.qualification_recovery_lease(),
            Some(lease)
        );
        let store = FakeStore::new(None);
        let commits = Rc::clone(&store.commits);
        let calls = QualificationRecoveryCalls::new();
        let mut dispatch = DurableDispatch::new(
            restored.controller,
            authority(),
            store,
            ordinary_fake(OrdinaryCalls::new()),
            qualification_recovery_fake(calls.clone()),
        );

        dispatch.maintenance(20);

        assert_eq!(calls.executes.get(), 0);
        assert_eq!(calls.reconciles.get(), 1);
        assert_eq!(*calls.stop.borrow(), Some(QualificationStop::Recovery));
        assert_eq!(dispatch.state(), ActivationState::Quarantined);
        assert_eq!(dispatch.controller.qualification_recovery_lease(), None);
        assert_eq!(commits.borrow().len(), 2);
        assert_eq!(commits.borrow()[0].state, ActivationState::Quarantined);
        assert!(commits.borrow()[0]
            .qualification
            .is_some_and(|qualification| qualification.active_lease == Some(lease)));
        assert_eq!(commits.borrow()[1].state, ActivationState::Quarantined);
        assert!(commits.borrow()[1]
            .qualification
            .is_some_and(|qualification| qualification.active_lease.is_none()));
    }

    #[test]
    fn qualification_expiry_commits_quarantine_before_cleanup_then_commits_clear() {
        let (controller, lease) = active_qualification_controller();
        let store = FakeStore::new(None);
        let commits = Rc::clone(&store.commits);
        let calls = QualificationRecoveryCalls::new();
        let mut dispatch = DurableDispatch::new(
            controller,
            authority(),
            store,
            ordinary_fake(OrdinaryCalls::new()),
            qualification_recovery_fake(calls.clone()),
        );

        dispatch.maintenance(permit().expires_at);

        assert_eq!(calls.executes.get(), 0);
        assert_eq!(calls.reconciles.get(), 1);
        assert_eq!(*calls.stop.borrow(), Some(QualificationStop::Expired));
        assert_eq!(dispatch.state(), ActivationState::Quarantined);
        assert_eq!(dispatch.controller.qualification_recovery_lease(), None);
        assert_eq!(commits.borrow().len(), 2);
        assert_eq!(commits.borrow()[0].state, ActivationState::Quarantined);
        assert!(commits.borrow()[0]
            .qualification
            .is_some_and(|qualification| qualification.active_lease == Some(lease)));
        assert_eq!(commits.borrow()[1].state, ActivationState::Quarantined);
        assert!(commits.borrow()[1]
            .qualification
            .is_some_and(|qualification| qualification.active_lease.is_none()));
    }

    #[test]
    fn qualification_ambiguous_or_unavailable_cleanup_retains_exact_token() {
        for (available, disposition, teardown_digest) in [
            (true, CleanupDisposition::Ambiguous, [46; 32]),
            (true, CleanupDisposition::Clean, [0; 32]),
            (false, CleanupDisposition::Clean, [46; 32]),
        ] {
            let (controller, lease) = active_qualification_controller();
            let restored = ActivationController::restore(ROOT, controller.snapshot(), None);
            let store = FakeStore::new(None);
            let commits = Rc::clone(&store.commits);
            let calls = QualificationRecoveryCalls::new();
            let mut executor = qualification_recovery_fake(calls.clone());
            executor.available = available;
            executor.cleanup = QualificationCleanup {
                disposition,
                teardown_digest,
            };
            let mut dispatch = DurableDispatch::new(
                restored.controller,
                authority(),
                store,
                ordinary_fake(OrdinaryCalls::new()),
                executor,
            );

            dispatch.maintenance(20);

            assert_eq!(calls.executes.get(), 0);
            assert_eq!(calls.reconciles.get(), 1);
            assert_eq!(dispatch.state(), ActivationState::Quarantined);
            assert_eq!(
                dispatch.controller.qualification_recovery_lease(),
                Some(lease)
            );
            assert_eq!(commits.borrow().len(), 1);
            assert_eq!(commits.borrow()[0].state, ActivationState::Quarantined);
            assert!(commits.borrow()[0]
                .qualification
                .is_some_and(|qualification| qualification.active_lease == Some(lease)));
        }
    }

    #[test]
    fn qualification_quarantine_commit_failure_skips_cleanup_and_retains_exact_token() {
        let (controller, lease) = active_qualification_controller();
        let restored = ActivationController::restore(ROOT, controller.snapshot(), None);
        let store = FakeStore::new(Some(1));
        let commits = Rc::clone(&store.commits);
        let calls = QualificationRecoveryCalls::new();
        let mut dispatch = DurableDispatch::new(
            restored.controller,
            authority(),
            store,
            ordinary_fake(OrdinaryCalls::new()),
            qualification_recovery_fake(calls.clone()),
        );

        dispatch.maintenance(20);

        assert_eq!(calls.executes.get(), 0);
        assert_eq!(calls.reconciles.get(), 0);
        assert_eq!(dispatch.state(), ActivationState::Quarantined);
        assert_eq!(
            dispatch.controller.qualification_recovery_lease(),
            Some(lease)
        );
        assert!(commits.borrow().is_empty());
        assert_eq!(dispatch.store.attempts.get(), 1);
    }

    #[test]
    fn qualification_clear_commit_failure_restores_exact_token_after_safe_quarantine_commit() {
        let (controller, lease) = active_qualification_controller();
        let restored = ActivationController::restore(ROOT, controller.snapshot(), None);
        let store = FakeStore::new(Some(2));
        let commits = Rc::clone(&store.commits);
        let calls = QualificationRecoveryCalls::new();
        let mut dispatch = DurableDispatch::new(
            restored.controller,
            authority(),
            store,
            ordinary_fake(OrdinaryCalls::new()),
            qualification_recovery_fake(calls.clone()),
        );

        dispatch.maintenance(20);

        assert_eq!(calls.executes.get(), 0);
        assert_eq!(calls.reconciles.get(), 1);
        assert_eq!(dispatch.state(), ActivationState::Quarantined);
        assert_eq!(
            dispatch.controller.qualification_recovery_lease(),
            Some(lease)
        );
        assert_eq!(commits.borrow().len(), 1);
        assert_eq!(commits.borrow()[0].state, ActivationState::Quarantined);
        assert!(commits.borrow()[0]
            .qualification
            .is_some_and(|qualification| qualification.active_lease == Some(lease)));
        assert_eq!(dispatch.store.attempts.get(), 2);
    }

    #[test]
    fn qualification_recovery_authority_mismatch_causes_no_cleanup_or_mutation() {
        let (controller, lease) = active_qualification_controller();
        let before = controller.snapshot();
        let store = FakeStore::new(None);
        let commits = Rc::clone(&store.commits);
        let calls = QualificationRecoveryCalls::new();
        let mut mismatched = authority();
        mismatched.qualification_request.fixture_identity = [99; 32];
        let mut dispatch = DurableDispatch::new(
            controller,
            mismatched,
            store,
            ordinary_fake(OrdinaryCalls::new()),
            qualification_recovery_fake(calls.clone()),
        );

        dispatch.maintenance(permit().expires_at);

        assert_eq!(calls.executes.get(), 0);
        assert_eq!(calls.reconciles.get(), 0);
        assert_eq!(dispatch.state(), ActivationState::Qualifying);
        assert_eq!(dispatch.controller.snapshot(), before);
        assert_eq!(
            dispatch
                .controller
                .expired_qualification_lease(permit().expires_at),
            Some(lease)
        );
        assert!(commits.borrow().is_empty());
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
            ordinary_fake(OrdinaryCalls::new()),
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
