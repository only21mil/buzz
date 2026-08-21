//! Pure activation and single-slot admission state for the privileged broker.
//!
//! This module deliberately performs no I/O. Callers must verify signatures
//! and inspect the host before passing the resulting identities and opaque
//! readiness evidence into this state machine.

use crate::seccomp::SeccompLeaseEvidence;
use buzz_ci_broker_protocol::{GitOid, QualificationDirective, QualificationRequest};

/// Exact acceptance record count required before activation.
pub const REQUIRED_SECURITY_RECORDS: u8 = 17;
/// Exact acceptance probe count required before activation.
pub const REQUIRED_PROBES: u8 = 12;
/// Maximum replay records retained in one durable activation snapshot.
pub const NONCE_LEDGER_CAPACITY: usize = 64;

/// Identity returned by an authentication boundary after signature verification.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct VerifiedSigner(pub [u8; 32]);

/// Immutable host and build coordinates covered by the activation grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostActivationCoordinates {
    pub integrated_candidate_sha: GitOid,
    pub broker_build_identity: [u8; 32],
    pub host_profile_digest: [u8; 32],
    pub suite_identity: [u8; 32],
}

/// Exact coordinates for the one qualification fixture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixtureJobCoordinates {
    pub request_digest: [u8; 32],
    pub manifest_digest: [u8; 32],
    pub isolation_profile_digest: [u8; 32],
    pub source_oid: GitOid,
    pub base_oid: GitOid,
    pub test_identity: [u8; 32],
}

/// Exact coordinates for one ordinary accepted-reviewed job.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrdinaryJobCoordinates {
    pub request_digest: [u8; 32],
    pub manifest_digest: [u8; 32],
    pub isolation_profile_digest: [u8; 32],
    pub source_oid: GitOid,
    pub base_oid: GitOid,
    pub job_identity: [u8; 32],
}

/// Root-authorized, one-shot entrance into the qualification-only state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QualificationPermit {
    pub authorized_by: VerifiedSigner,
    pub host: HostActivationCoordinates,
    pub fixture_job: FixtureJobCoordinates,
    pub fixture_identity: [u8; 32],
    pub fixture_signer: VerifiedSigner,
    pub nonce: [u8; 32],
    pub not_before: u64,
    pub expires_at: u64,
    pub directive: Option<QualificationDirective>,
}

/// Trust class presented at the pure admission seam.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionTrustClass {
    /// Root-authorized qualification fixture; never valid for ordinary work.
    QualificationFixture,
    /// Reviewed ordinary job accepted only after activation.
    AcceptedReviewed,
    /// Any source class outside the accepted policy.
    Unaccepted,
}

/// One request to exercise the qualification fixture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QualificationAdmission {
    pub host: HostActivationCoordinates,
    pub fixture_job: FixtureJobCoordinates,
    pub fixture_identity: [u8; 32],
    pub signer: VerifiedSigner,
    pub nonce: [u8; 32],
    pub not_before: u64,
    pub expires_at: u64,
    pub directive: Option<QualificationDirective>,
    pub trust_class: AdmissionTrustClass,
}

/// Opaque receipt required to finish the sole qualification fixture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QualificationLease {
    fixture_identity: [u8; 32],
    lease_id: [u8; 16],
    generation: u64,
    nonce: [u8; 32],
    directive: Option<QualificationDirective>,
}

impl QualificationLease {
    pub const fn fixture_identity(self) -> [u8; 32] {
        self.fixture_identity
    }

    pub const fn lease_id(self) -> [u8; 16] {
        self.lease_id
    }

    pub const fn generation(self) -> u64 {
        self.generation
    }

    pub const fn nonce(self) -> [u8; 32] {
        self.nonce
    }

    /// Return the root-permitted behavior for this exact fixture lease.
    pub const fn directive(self) -> Option<QualificationDirective> {
        self.directive
    }
}

/// Qualification completion reported by the acceptance harness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QualificationOutcome {
    /// The exact suite completed and produced this evidence-set identity.
    Accepted { evidence_set_digest: [u8; 32] },
    /// The suite failed decisively.
    Failed,
    /// Completion cannot be proved one way or the other.
    Ambiguous,
}

/// Root-controlled grant that can make one ordinary execution slot Ready.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActivationGrant {
    pub authorized_by: VerifiedSigner,
    pub host: HostActivationCoordinates,
    pub security_records_passed: u8,
    pub security_records_total: u8,
    pub probes_passed: u8,
    pub probes_total: u8,
    pub evidence_set_digest: [u8; 32],
    pub blocker_closure_digest: [u8; 32],
    pub all_blockers_closed: bool,
    pub ordinary_signer: VerifiedSigner,
    pub max_capacity: u8,
    pub minimum_admission_interval_seconds: u64,
    pub expires_at: u64,
}

/// One ordinary job request after the root activation grant is reconciled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrdinaryAdmission {
    pub host: HostActivationCoordinates,
    pub job: OrdinaryJobCoordinates,
    pub lease_id: [u8; 16],
    pub run_id: [u8; 16],
    pub attempt: u32,
    pub signer: VerifiedSigner,
    pub nonce: [u8; 32],
    pub expires_at: u64,
    pub wall_timeout_seconds: u32,
    pub trust_class: AdmissionTrustClass,
}

/// Opaque receipt required for every terminal conclusion and cleanup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LeaseToken {
    lease_id: [u8; 16],
    run_id: [u8; 16],
    attempt: u32,
    signed_request_digest: [u8; 32],
    signer: VerifiedSigner,
    generation: u64,
    nonce: [u8; 32],
    deadline_at: u64,
}

pub(crate) struct DurableLeaseFields {
    pub lease_id: [u8; 16],
    pub run_id: [u8; 16],
    pub attempt: u32,
    pub signed_request_digest: [u8; 32],
    pub signer: VerifiedSigner,
    pub generation: u64,
    pub nonce: [u8; 32],
    pub deadline_at: u64,
}

impl LeaseToken {
    pub(crate) const fn from_durable(fields: DurableLeaseFields) -> Self {
        Self {
            lease_id: fields.lease_id,
            run_id: fields.run_id,
            attempt: fields.attempt,
            signed_request_digest: fields.signed_request_digest,
            signer: fields.signer,
            generation: fields.generation,
            nonce: fields.nonce,
            deadline_at: fields.deadline_at,
        }
    }

    /// Return the lease identity allocated by the activation controller.
    pub const fn lease_id(self) -> [u8; 16] {
        self.lease_id
    }

    /// Return the controller-owned generation for this lease.
    pub const fn generation(self) -> u64 {
        self.generation
    }

    pub const fn run_id(self) -> [u8; 16] {
        self.run_id
    }

    pub const fn attempt(self) -> u32 {
        self.attempt
    }

    pub const fn signed_request_digest(self) -> [u8; 32] {
        self.signed_request_digest
    }

    pub const fn signer(self) -> VerifiedSigner {
        self.signer
    }

    pub const fn deadline_at(self) -> u64 {
        self.deadline_at
    }

    pub(crate) const fn nonce(self) -> [u8; 32] {
        self.nonce
    }
}

/// Terminal job outcome. No outcome can be recorded without a lease token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeaseConclusion {
    Success,
    Failure,
    Cancelled,
    TimedOut,
    InfrastructureFailure,
}

/// Result of cleanup for a completed or interrupted lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupDisposition {
    Clean,
    Incomplete,
    Ambiguous,
}

/// Closed activation lifecycle for the one-slot broker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivationState {
    Unprovisioned,
    Qualifying,
    Reconciling,
    Ready,
    Leased,
    Draining,
    Quarantined,
}

/// Closed admission failures returned without allocating execution capacity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionError {
    Replay,
    ExpiredNonce,
    UnauthorizedSigner,
    UnacceptedTrustClass,
    RateLimit,
    ConcurrencyLimit,
    CoordinateMismatch,
    QualificationOnly,
    InvalidNonce,
    GenerationExhausted,
    NotReady,
}

/// Closed lifecycle and activation failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivationError {
    InvalidState,
    UnauthorizedRoot,
    InvalidGrant,
    AcceptanceCountMismatch,
    BlockersOpen,
    MissingEvidence,
    MissingLease,
    HostProfileMismatch,
    SnapshotInvalid,
    RestartAmbiguous,
    ActivationExpired,
    ReconciliationAmbiguous,
}

/// Qualification facts retained in a durable snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableQualificationState {
    pub permit: QualificationPermit,
    pub active_lease: Option<QualificationLease>,
    pub evidence_set_digest: Option<[u8; 32]>,
}

/// One replay record retained through its authoritative expiry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableNonceEntry {
    pub nonce: [u8; 32],
    pub expires_at: u64,
}

/// Fixed-size replay ledger retained across broker restarts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableNonceLedger {
    pub entries: [Option<DurableNonceEntry>; NONCE_LEDGER_CAPACITY],
}

impl DurableNonceLedger {
    const fn new() -> Self {
        Self {
            entries: [None; NONCE_LEDGER_CAPACITY],
        }
    }

    fn contains(&self, nonce: &[u8; 32]) -> bool {
        self.entries
            .iter()
            .flatten()
            .any(|entry| entry.nonce == *nonce)
    }

    fn prune_expired(&mut self, now: u64) {
        for entry in &mut self.entries {
            if entry.is_some_and(|entry| entry.expires_at <= now) {
                *entry = None;
            }
        }
    }

    fn insert(&mut self, nonce: [u8; 32], expires_at: u64) -> Result<(), AdmissionError> {
        let Some(slot) = self.entries.iter_mut().find(|entry| entry.is_none()) else {
            return Err(AdmissionError::RateLimit);
        };
        *slot = Some(DurableNonceEntry { nonce, expires_at });
        Ok(())
    }

    fn is_valid(&self) -> bool {
        for (index, entry) in self.entries.iter().enumerate() {
            let Some(entry) = entry else {
                continue;
            };
            if entry.nonce == [0; 32]
                || entry.expires_at == 0
                || self.entries[..index]
                    .iter()
                    .flatten()
                    .any(|prior| prior.nonce == entry.nonce)
            {
                return false;
            }
        }
        true
    }
}

/// Bounded state record that callers can persist atomically outside this module.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableStateSnapshot {
    pub version: u8,
    pub root_authority: VerifiedSigner,
    pub state: ActivationState,
    pub qualification: Option<DurableQualificationState>,
    pub activation: Option<ActivationGrant>,
    pub active_lease: Option<LeaseToken>,
    pub nonce_ledger: DurableNonceLedger,
    pub last_admission_at: Option<u64>,
    pub next_lease_generation: u64,
}

/// Current host facts required to restore a Ready snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadyRestoreValidation {
    pub grant: ActivationGrant,
    pub seccomp_evidence: SeccompLeaseEvidence,
    pub host_profile_digest: [u8; 32],
    pub now: u64,
}

/// Restore result. An unsafe snapshot returns a quarantined controller and reason.
#[derive(Debug, Eq, PartialEq)]
pub struct RestoreOutcome {
    pub controller: ActivationController,
    pub quarantine_reason: Option<ActivationError>,
}

/// Pure, in-memory controller for qualification and initial one-slot activation.
#[derive(Debug, Eq, PartialEq)]
pub struct ActivationController {
    root_authority: VerifiedSigner,
    state: ActivationState,
    qualification: Option<DurableQualificationState>,
    activation: Option<ActivationGrant>,
    active_lease: Option<LeaseToken>,
    seen_nonces: DurableNonceLedger,
    last_admission_at: Option<u64>,
    next_lease_generation: u64,
}

impl ActivationController {
    /// Construct a controller with no qualification or ordinary capacity.
    pub fn new(root_authority: VerifiedSigner) -> Self {
        Self {
            root_authority,
            state: ActivationState::Unprovisioned,
            qualification: None,
            activation: None,
            active_lease: None,
            seen_nonces: DurableNonceLedger::new(),
            last_admission_at: None,
            next_lease_generation: 1,
        }
    }

    /// Return the current closed lifecycle state.
    pub const fn state(&self) -> ActivationState {
        self.state
    }

    /// Return ordinary capacity at `now`; an expired grant always reports zero.
    pub fn ordinary_capacity(&self, now: u64) -> u8 {
        if matches!(self.state, ActivationState::Ready)
            && self.activation.is_some_and(|grant| now < grant.expires_at)
        {
            1
        } else {
            0
        }
    }

    /// Capture all bounded replay, generation, grant, and lifecycle facts.
    pub const fn snapshot(&self) -> DurableStateSnapshot {
        DurableStateSnapshot {
            version: 1,
            root_authority: self.root_authority,
            state: self.state,
            qualification: self.qualification,
            activation: self.activation,
            active_lease: self.active_lease,
            nonce_ledger: self.seen_nonces,
            last_admission_at: self.last_admission_at,
            next_lease_generation: self.next_lease_generation,
        }
    }

    /// Restore a bounded snapshot, quarantining in-flight or unvalidated Ready state.
    pub fn restore(
        root_authority: VerifiedSigner,
        snapshot: DurableStateSnapshot,
        ready_validation: Option<ReadyRestoreValidation>,
    ) -> RestoreOutcome {
        let mut controller = Self {
            root_authority,
            state: snapshot.state,
            qualification: snapshot.qualification,
            activation: snapshot.activation,
            active_lease: snapshot.active_lease,
            seen_nonces: snapshot.nonce_ledger,
            last_admission_at: snapshot.last_admission_at,
            next_lease_generation: snapshot.next_lease_generation,
        };

        let structural_error = if snapshot.version != 1
            || snapshot.root_authority != root_authority
            || root_authority.0 == [0; 32]
            || !snapshot.nonce_ledger.is_valid()
            || snapshot.next_lease_generation == 0
            || !snapshot_shape_is_valid(snapshot)
        {
            Some(ActivationError::SnapshotInvalid)
        } else if matches!(
            snapshot.state,
            ActivationState::Reconciling | ActivationState::Leased | ActivationState::Draining
        ) || snapshot
            .qualification
            .is_some_and(|qualification| qualification.active_lease.is_some())
        {
            Some(ActivationError::RestartAmbiguous)
        } else if snapshot.state == ActivationState::Ready {
            match ready_validation {
                Some(validation) if snapshot.activation == Some(validation.grant) => controller
                    .validate_activation(
                        validation.grant,
                        validation.seccomp_evidence,
                        validation.host_profile_digest,
                        validation.now,
                    )
                    .err(),
                _ => Some(ActivationError::SnapshotInvalid),
            }
        } else {
            None
        };

        if let Some(error) = structural_error {
            if error == ActivationError::RestartAmbiguous && controller.active_lease.is_some() {
                controller.state = ActivationState::Quarantined;
            } else {
                controller.quarantine();
            }
            RestoreOutcome {
                controller,
                quarantine_reason: Some(error),
            }
        } else {
            RestoreOutcome {
                controller,
                quarantine_reason: None,
            }
        }
    }

    /// Enter the qualification-only state under an exact root permit.
    pub fn start_qualification(
        &mut self,
        permit: QualificationPermit,
    ) -> Result<(), ActivationError> {
        if self.state != ActivationState::Unprovisioned {
            return Err(ActivationError::InvalidState);
        }
        if permit.authorized_by != self.root_authority {
            return Err(ActivationError::UnauthorizedRoot);
        }
        if !valid_qualification_permit(self.root_authority, permit) {
            return Err(ActivationError::InvalidGrant);
        }
        self.qualification = Some(DurableQualificationState {
            permit,
            active_lease: None,
            evidence_set_digest: None,
        });
        self.state = ActivationState::Qualifying;
        Ok(())
    }

    /// Authenticate and bind one decoded qualification protocol request.
    pub fn admit_qualification_request(
        &mut self,
        request: QualificationRequest,
        authenticated_signer: VerifiedSigner,
        now: u64,
    ) -> Result<QualificationLease, AdmissionError> {
        if request.fixture_signer != authenticated_signer.0 {
            return Err(AdmissionError::UnauthorizedSigner);
        }
        self.admit_qualification(
            QualificationAdmission {
                host: HostActivationCoordinates {
                    integrated_candidate_sha: request.integrated_candidate_sha,
                    broker_build_identity: request.broker_build_identity,
                    host_profile_digest: request.host_profile_digest,
                    suite_identity: request.suite_identity,
                },
                fixture_job: FixtureJobCoordinates {
                    request_digest: request.request_digest,
                    manifest_digest: request.manifest_digest,
                    isolation_profile_digest: request.isolation_profile_digest,
                    source_oid: request.source_oid,
                    base_oid: request.base_oid,
                    test_identity: request.job_identity,
                },
                fixture_identity: request.fixture_identity,
                signer: authenticated_signer,
                nonce: request.nonce,
                not_before: request.not_before,
                expires_at: request.expires_at,
                directive: request.directive,
                trust_class: AdmissionTrustClass::QualificationFixture,
            },
            now,
        )
    }

    /// Admit the one exact qualification fixture without enabling ordinary jobs.
    pub fn admit_qualification(
        &mut self,
        request: QualificationAdmission,
        now: u64,
    ) -> Result<QualificationLease, AdmissionError> {
        self.seen_nonces.prune_expired(now);
        if self.seen_nonces.contains(&request.nonce) {
            return Err(AdmissionError::Replay);
        }
        let Some(session) = self.qualification else {
            return Err(AdmissionError::NotReady);
        };
        if self.state != ActivationState::Qualifying {
            return Err(AdmissionError::NotReady);
        }
        if session.active_lease.is_some() {
            return Err(AdmissionError::ConcurrencyLimit);
        }
        if now < session.permit.not_before {
            return Err(AdmissionError::RateLimit);
        }
        if now >= session.permit.expires_at {
            return Err(AdmissionError::ExpiredNonce);
        }
        if request.signer != session.permit.fixture_signer {
            return Err(AdmissionError::UnauthorizedSigner);
        }
        if request.trust_class != AdmissionTrustClass::QualificationFixture {
            return Err(AdmissionError::UnacceptedTrustClass);
        }
        if request.host != session.permit.host
            || request.fixture_job != session.permit.fixture_job
            || request.fixture_identity != session.permit.fixture_identity
            || request.not_before != session.permit.not_before
            || request.expires_at != session.permit.expires_at
            || request.directive != session.permit.directive
        {
            return Err(AdmissionError::CoordinateMismatch);
        }
        if request.nonce != session.permit.nonce {
            return Err(AdmissionError::InvalidNonce);
        }
        if self.next_lease_generation == u64::MAX {
            self.quarantine();
            return Err(AdmissionError::GenerationExhausted);
        }

        let mut lease_id = [0; 16];
        lease_id.copy_from_slice(&request.fixture_identity[..16]);
        let lease = QualificationLease {
            fixture_identity: request.fixture_identity,
            lease_id,
            generation: self.next_lease_generation,
            nonce: request.nonce,
            directive: request.directive,
        };
        self.seen_nonces
            .insert(request.nonce, session.permit.expires_at)?;
        self.next_lease_generation += 1;
        self.qualification = Some(DurableQualificationState {
            active_lease: Some(lease),
            ..session
        });
        Ok(lease)
    }

    /// Finish the qualification fixture and move only to reconciliation.
    pub fn finish_qualification(
        &mut self,
        lease: QualificationLease,
        outcome: QualificationOutcome,
    ) -> Result<(), ActivationError> {
        if self.state != ActivationState::Qualifying {
            return Err(ActivationError::InvalidState);
        }
        let Some(session) = self.qualification.as_mut() else {
            return Err(ActivationError::InvalidState);
        };
        if session.active_lease != Some(lease) {
            return Err(ActivationError::MissingLease);
        }
        match outcome {
            QualificationOutcome::Accepted {
                evidence_set_digest,
            } if evidence_set_digest != [0; 32] => {
                session.active_lease = None;
                session.evidence_set_digest = Some(evidence_set_digest);
                self.state = ActivationState::Reconciling;
                Ok(())
            }
            QualificationOutcome::Accepted { .. } => {
                self.quarantine();
                Err(ActivationError::MissingEvidence)
            }
            QualificationOutcome::Failed => {
                self.quarantine();
                Err(ActivationError::ReconciliationAmbiguous)
            }
            QualificationOutcome::Ambiguous => {
                self.quarantine();
                Err(ActivationError::ReconciliationAmbiguous)
            }
        }
    }

    /// Quarantine after the forced teardown fixture, regardless of evidence quality.
    pub fn finish_qualification_teardown_failure(
        &mut self,
        lease: QualificationLease,
    ) -> Result<(), ActivationError> {
        let accepted = self.state == ActivationState::Qualifying
            && self
                .qualification
                .is_some_and(|session| session.active_lease == Some(lease))
            && lease.directive == Some(QualificationDirective::TeardownFailure);
        self.quarantine();
        if accepted {
            Ok(())
        } else {
            Err(ActivationError::MissingLease)
        }
    }

    /// Reconcile the root grant and exact TM-11 profile before becoming Ready.
    pub fn reconcile_activation(
        &mut self,
        grant: ActivationGrant,
        seccomp_evidence: SeccompLeaseEvidence,
        host_profile_digest: [u8; 32],
        now: u64,
    ) -> Result<(), ActivationError> {
        if self.state != ActivationState::Reconciling {
            return Err(ActivationError::InvalidState);
        }
        let result = self.validate_activation(grant, seccomp_evidence, host_profile_digest, now);
        match result {
            Ok(()) => {
                self.activation = Some(grant);
                self.state = ActivationState::Ready;
                Ok(())
            }
            Err(error) => {
                self.quarantine();
                Err(error)
            }
        }
    }

    /// Admit one ordinary reviewed job after activation.
    pub fn preflight_ordinary(
        &self,
        request: OrdinaryAdmission,
        now: u64,
    ) -> Result<(), AdmissionError> {
        if self
            .seen_nonces
            .entries
            .iter()
            .flatten()
            .any(|entry| entry.nonce == request.nonce && entry.expires_at > now)
        {
            return Err(AdmissionError::Replay);
        }
        if matches!(
            self.state,
            ActivationState::Unprovisioned
                | ActivationState::Qualifying
                | ActivationState::Reconciling
        ) {
            return Err(AdmissionError::QualificationOnly);
        }
        if matches!(
            self.state,
            ActivationState::Leased | ActivationState::Draining
        ) {
            return Err(AdmissionError::ConcurrencyLimit);
        }
        if self.state != ActivationState::Ready {
            return Err(AdmissionError::NotReady);
        }
        let Some(grant) = self.activation else {
            return Err(AdmissionError::NotReady);
        };
        if now >= request.expires_at || request.expires_at > grant.expires_at {
            return Err(AdmissionError::ExpiredNonce);
        }
        if request.signer != grant.ordinary_signer {
            return Err(AdmissionError::UnauthorizedSigner);
        }
        if request.trust_class != AdmissionTrustClass::AcceptedReviewed {
            return Err(AdmissionError::UnacceptedTrustClass);
        }
        let Some(qualification) = self.qualification else {
            return Err(AdmissionError::NotReady);
        };
        if request.host != grant.host
            || !valid_job_coordinates(request.job)
            || same_job_coordinates(request.job, qualification.permit.fixture_job)
        {
            return Err(AdmissionError::CoordinateMismatch);
        }
        if request.nonce == [0; 32]
            || request.lease_id == [0; 16]
            || request.run_id == [0; 16]
            || request.attempt == 0
            || request.wall_timeout_seconds == 0
        {
            return Err(AdmissionError::InvalidNonce);
        }
        if let Some(last) = self.last_admission_at {
            if now.saturating_sub(last) < grant.minimum_admission_interval_seconds {
                return Err(AdmissionError::RateLimit);
            }
        }
        if self
            .seen_nonces
            .entries
            .iter()
            .flatten()
            .filter(|entry| entry.expires_at > now)
            .count()
            == NONCE_LEDGER_CAPACITY
        {
            return Err(AdmissionError::RateLimit);
        }
        Ok(())
    }

    /// Admit one ordinary reviewed job after activation.
    pub fn admit_ordinary(
        &mut self,
        request: OrdinaryAdmission,
        now: u64,
    ) -> Result<LeaseToken, AdmissionError> {
        self.preflight_ordinary(request, now)?;
        self.seen_nonces.prune_expired(now);
        if self.next_lease_generation == u64::MAX {
            self.quarantine();
            return Err(AdmissionError::GenerationExhausted);
        }

        let lease = LeaseToken {
            lease_id: request.lease_id,
            run_id: request.run_id,
            attempt: request.attempt,
            signed_request_digest: request.job.request_digest,
            signer: request.signer,
            generation: self.next_lease_generation,
            nonce: request.nonce,
            deadline_at: request
                .expires_at
                .min(now.saturating_add(u64::from(request.wall_timeout_seconds))),
        };
        self.seen_nonces.insert(request.nonce, request.expires_at)?;
        self.next_lease_generation += 1;
        self.last_admission_at = Some(now);
        self.active_lease = Some(lease);
        self.state = ActivationState::Leased;
        Ok(lease)
    }

    /// Bind a mutating terminal request to the one currently active lease.
    pub fn bind_active_lease(
        &self,
        run_id: [u8; 16],
        attempt: u32,
        lease_id: [u8; 16],
        generation: u64,
    ) -> Result<LeaseToken, ActivationError> {
        let Some(lease) = self.active_lease else {
            return Err(ActivationError::MissingLease);
        };
        if self.state != ActivationState::Leased
            || run_id != lease.run_id
            || attempt != lease.attempt
            || lease_id != lease.lease_id
            || generation != lease.generation
        {
            return Err(ActivationError::MissingLease);
        }
        Ok(lease)
    }

    /// Return an expired active lease for traffic-independent maintenance.
    pub fn expired_active_lease(&self, now: u64) -> Option<LeaseToken> {
        self.active_lease
            .filter(|lease| self.state == ActivationState::Leased && now >= lease.deadline_at)
    }

    /// Return a restart recovery token without reopening ordinary capacity.
    pub fn recovery_lease(&self) -> Option<LeaseToken> {
        self.active_lease
            .filter(|_| self.state == ActivationState::Quarantined)
    }

    /// Clear a restart recovery token after root cleanup has run.
    pub fn finish_recovery(&mut self, lease: LeaseToken) -> Result<(), ActivationError> {
        if self.state != ActivationState::Quarantined || self.active_lease != Some(lease) {
            return Err(ActivationError::MissingLease);
        }
        self.active_lease = None;
        Ok(())
    }

    /// Record an outcome and enter Draining. A lease token is mandatory even for success.
    pub fn finish_lease(
        &mut self,
        lease: LeaseToken,
        _conclusion: LeaseConclusion,
    ) -> Result<(), ActivationError> {
        if self.state != ActivationState::Leased {
            return Err(ActivationError::MissingLease);
        }
        if self.active_lease != Some(lease) {
            return Err(ActivationError::MissingLease);
        }
        self.state = ActivationState::Draining;
        Ok(())
    }

    /// Finish cleanup, returning to Ready only for an unambiguous clean result.
    pub fn finish_cleanup(
        &mut self,
        lease: LeaseToken,
        disposition: CleanupDisposition,
        now: u64,
    ) -> Result<(), ActivationError> {
        if self.state != ActivationState::Draining || self.active_lease != Some(lease) {
            return Err(ActivationError::MissingLease);
        }
        self.active_lease = None;
        match disposition {
            CleanupDisposition::Clean => {
                if self.activation.is_none_or(|grant| now >= grant.expires_at) {
                    self.quarantine();
                    return Err(ActivationError::ActivationExpired);
                }
                self.state = ActivationState::Ready;
                Ok(())
            }
            CleanupDisposition::Incomplete | CleanupDisposition::Ambiguous => {
                self.quarantine();
                Err(ActivationError::ReconciliationAmbiguous)
            }
        }
    }

    fn validate_activation(
        &self,
        grant: ActivationGrant,
        _seccomp_evidence: SeccompLeaseEvidence,
        host_profile_digest: [u8; 32],
        now: u64,
    ) -> Result<(), ActivationError> {
        let Some(session) = self.qualification else {
            return Err(ActivationError::InvalidState);
        };
        let Some(evidence_set_digest) = session.evidence_set_digest else {
            return Err(ActivationError::MissingEvidence);
        };
        if grant.authorized_by != self.root_authority {
            return Err(ActivationError::UnauthorizedRoot);
        }
        if grant.host != session.permit.host
            || grant.evidence_set_digest != evidence_set_digest
            || grant.max_capacity != 1
            || grant.ordinary_signer.0 == [0; 32]
            || grant.minimum_admission_interval_seconds == 0
            || grant.expires_at <= now
        {
            return Err(ActivationError::InvalidGrant);
        }
        if grant.security_records_passed != REQUIRED_SECURITY_RECORDS
            || grant.security_records_total != REQUIRED_SECURITY_RECORDS
            || grant.probes_passed != REQUIRED_PROBES
            || grant.probes_total != REQUIRED_PROBES
        {
            return Err(ActivationError::AcceptanceCountMismatch);
        }
        if !grant.all_blockers_closed || grant.blocker_closure_digest == [0; 32] {
            return Err(ActivationError::BlockersOpen);
        }
        if host_profile_digest != grant.host.host_profile_digest {
            return Err(ActivationError::HostProfileMismatch);
        }
        Ok(())
    }

    fn quarantine(&mut self) {
        self.active_lease = None;
        self.state = ActivationState::Quarantined;
    }
}

fn valid_host_coordinates(host: HostActivationCoordinates) -> bool {
    let candidate_is_nonzero = match host.integrated_candidate_sha {
        GitOid::Sha1(bytes) => bytes != [0; 20],
        GitOid::Sha256(bytes) => bytes != [0; 32],
    };
    candidate_is_nonzero
        && host.broker_build_identity != [0; 32]
        && host.host_profile_digest != [0; 32]
        && host.suite_identity != [0; 32]
}

fn valid_fixture_job_coordinates(job: FixtureJobCoordinates) -> bool {
    let source_is_nonzero = match job.source_oid {
        GitOid::Sha1(bytes) => bytes != [0; 20],
        GitOid::Sha256(bytes) => bytes != [0; 32],
    };
    let base_is_nonzero = match job.base_oid {
        GitOid::Sha1(bytes) => bytes != [0; 20],
        GitOid::Sha256(bytes) => bytes != [0; 32],
    };
    source_is_nonzero
        && base_is_nonzero
        && job.request_digest != [0; 32]
        && job.manifest_digest != [0; 32]
        && job.isolation_profile_digest != [0; 32]
        && job.test_identity != [0; 32]
}

fn valid_job_coordinates(job: OrdinaryJobCoordinates) -> bool {
    let source_is_nonzero = match job.source_oid {
        GitOid::Sha1(bytes) => bytes != [0; 20],
        GitOid::Sha256(bytes) => bytes != [0; 32],
    };
    let base_is_nonzero = match job.base_oid {
        GitOid::Sha1(bytes) => bytes != [0; 20],
        GitOid::Sha256(bytes) => bytes != [0; 32],
    };
    source_is_nonzero
        && base_is_nonzero
        && job.request_digest != [0; 32]
        && job.manifest_digest != [0; 32]
        && job.isolation_profile_digest != [0; 32]
        && job.job_identity != [0; 32]
}

fn same_job_coordinates(ordinary: OrdinaryJobCoordinates, fixture: FixtureJobCoordinates) -> bool {
    ordinary.request_digest == fixture.request_digest
        && ordinary.manifest_digest == fixture.manifest_digest
        && ordinary.isolation_profile_digest == fixture.isolation_profile_digest
        && ordinary.source_oid == fixture.source_oid
        && ordinary.base_oid == fixture.base_oid
        && ordinary.job_identity == fixture.test_identity
}

fn valid_qualification_permit(root_authority: VerifiedSigner, permit: QualificationPermit) -> bool {
    permit.authorized_by == root_authority
        && permit.authorized_by.0 != [0; 32]
        && permit.fixture_signer.0 != [0; 32]
        && permit.nonce != [0; 32]
        && permit.fixture_identity != [0; 32]
        && permit.not_before < permit.expires_at
        && valid_host_coordinates(permit.host)
        && valid_fixture_job_coordinates(permit.fixture_job)
}

fn snapshot_shape_is_valid(snapshot: DurableStateSnapshot) -> bool {
    let ordinary_lease_valid = snapshot.active_lease.is_none_or(|lease| {
        lease.lease_id != [0; 16]
            && lease.run_id != [0; 16]
            && lease.attempt != 0
            && lease.signed_request_digest != [0; 32]
            && lease.signer.0 != [0; 32]
            && lease.generation < snapshot.next_lease_generation
            && lease.nonce != [0; 32]
            && lease.deadline_at != 0
            && snapshot.nonce_ledger.contains(&lease.nonce)
    });
    if !ordinary_lease_valid {
        return false;
    }
    let qualification_valid = snapshot.qualification.is_none_or(|qualification| {
        valid_qualification_permit(snapshot.root_authority, qualification.permit)
            && qualification.active_lease.is_none_or(|lease| {
                lease.fixture_identity == qualification.permit.fixture_identity
                    && lease.lease_id == qualification.permit.fixture_identity[..16]
                    && lease.generation < snapshot.next_lease_generation
                    && lease.nonce == qualification.permit.nonce
                    && lease.directive == qualification.permit.directive
                    && snapshot.nonce_ledger.contains(&lease.nonce)
            })
    });
    if !qualification_valid {
        return false;
    }

    match snapshot.state {
        ActivationState::Unprovisioned => {
            snapshot.qualification.is_none()
                && snapshot.activation.is_none()
                && snapshot.active_lease.is_none()
        }
        ActivationState::Qualifying => {
            snapshot
                .qualification
                .is_some_and(|qualification| qualification.evidence_set_digest.is_none())
                && snapshot.activation.is_none()
                && snapshot.active_lease.is_none()
        }
        ActivationState::Reconciling | ActivationState::Ready => {
            snapshot.qualification.is_some_and(|qualification| {
                qualification.active_lease.is_none() && qualification.evidence_set_digest.is_some()
            }) && snapshot.activation.is_some() == (snapshot.state == ActivationState::Ready)
                && snapshot.active_lease.is_none()
        }
        ActivationState::Leased | ActivationState::Draining => {
            snapshot.qualification.is_some_and(|qualification| {
                qualification.active_lease.is_none() && qualification.evidence_set_digest.is_some()
            }) && snapshot.activation.is_some()
                && snapshot
                    .active_lease
                    .is_some_and(|lease| lease.generation < snapshot.next_lease_generation)
        }
        ActivationState::Quarantined => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seccomp::{
        SeccompFileReadback, SeccompFileType, SeccompSeedPlan, SECCOMP_PROFILE_MODE,
    };
    use buzz_ci_isolation_contract::{PHASE1_SECCOMP_PROFILE_DIGEST, PHASE1_SECCOMP_PROFILE_PATH};

    const ROOT: VerifiedSigner = VerifiedSigner([1; 32]);
    const FIXTURE_SIGNER: VerifiedSigner = VerifiedSigner([2; 32]);
    const ORDINARY_SIGNER: VerifiedSigner = VerifiedSigner([3; 32]);

    fn host_coordinates() -> HostActivationCoordinates {
        HostActivationCoordinates {
            integrated_candidate_sha: GitOid::Sha256([10; 32]),
            broker_build_identity: [11; 32],
            host_profile_digest: [12; 32],
            suite_identity: [13; 32],
        }
    }

    fn fixture_job() -> FixtureJobCoordinates {
        FixtureJobCoordinates {
            request_digest: [4; 32],
            manifest_digest: [5; 32],
            isolation_profile_digest: [6; 32],
            source_oid: GitOid::Sha256([7; 32]),
            base_oid: GitOid::Sha256([8; 32]),
            test_identity: [9; 32],
        }
    }

    fn ordinary_job() -> OrdinaryJobCoordinates {
        OrdinaryJobCoordinates {
            request_digest: [31; 32],
            manifest_digest: [32; 32],
            isolation_profile_digest: [33; 32],
            source_oid: GitOid::Sha256([34; 32]),
            base_oid: GitOid::Sha256([35; 32]),
            job_identity: [36; 32],
        }
    }

    fn fixture_job_as_ordinary() -> OrdinaryJobCoordinates {
        let fixture = fixture_job();
        OrdinaryJobCoordinates {
            request_digest: fixture.request_digest,
            manifest_digest: fixture.manifest_digest,
            isolation_profile_digest: fixture.isolation_profile_digest,
            source_oid: fixture.source_oid,
            base_oid: fixture.base_oid,
            job_identity: fixture.test_identity,
        }
    }

    fn mismatched_host_coordinates() -> [HostActivationCoordinates; 4] {
        let mut candidate = host_coordinates();
        candidate.integrated_candidate_sha = GitOid::Sha256([99; 32]);
        let mut build = host_coordinates();
        build.broker_build_identity = [99; 32];
        let mut host = host_coordinates();
        host.host_profile_digest = [99; 32];
        let mut suite = host_coordinates();
        suite.suite_identity = [99; 32];
        [candidate, build, host, suite]
    }

    fn mismatched_job_coordinates() -> [FixtureJobCoordinates; 6] {
        let mut request = fixture_job();
        request.request_digest = [99; 32];
        let mut manifest = fixture_job();
        manifest.manifest_digest = [99; 32];
        let mut isolation = fixture_job();
        isolation.isolation_profile_digest = [99; 32];
        let mut source = fixture_job();
        source.source_oid = GitOid::Sha256([99; 32]);
        let mut base = fixture_job();
        base.base_oid = GitOid::Sha256([99; 32]);
        let mut job = fixture_job();
        job.test_identity = [99; 32];
        [request, manifest, isolation, source, base, job]
    }

    fn malformed_ordinary_job_coordinates() -> [OrdinaryJobCoordinates; 6] {
        let mut request = ordinary_job();
        request.request_digest = [0; 32];
        let mut manifest = ordinary_job();
        manifest.manifest_digest = [0; 32];
        let mut isolation = ordinary_job();
        isolation.isolation_profile_digest = [0; 32];
        let mut source = ordinary_job();
        source.source_oid = GitOid::Sha256([0; 32]);
        let mut base = ordinary_job();
        base.base_oid = GitOid::Sha256([0; 32]);
        let mut job = ordinary_job();
        job.job_identity = [0; 32];
        [request, manifest, isolation, source, base, job]
    }

    fn permit() -> QualificationPermit {
        QualificationPermit {
            authorized_by: ROOT,
            host: host_coordinates(),
            fixture_job: fixture_job(),
            fixture_identity: [14; 32],
            fixture_signer: FIXTURE_SIGNER,
            nonce: [15; 32],
            not_before: 10,
            expires_at: 30,
            directive: None,
        }
    }

    fn qualification_admission() -> QualificationAdmission {
        QualificationAdmission {
            host: host_coordinates(),
            fixture_job: fixture_job(),
            fixture_identity: [14; 32],
            signer: FIXTURE_SIGNER,
            nonce: [15; 32],
            not_before: 10,
            expires_at: 30,
            directive: None,
            trust_class: AdmissionTrustClass::QualificationFixture,
        }
    }

    fn qualification_request(directive: Option<QualificationDirective>) -> QualificationRequest {
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
            directive,
        }
    }

    fn grant() -> ActivationGrant {
        ActivationGrant {
            authorized_by: ROOT,
            host: host_coordinates(),
            security_records_passed: 17,
            security_records_total: 17,
            probes_passed: 12,
            probes_total: 12,
            evidence_set_digest: [16; 32],
            blocker_closure_digest: [17; 32],
            all_blockers_closed: true,
            ordinary_signer: ORDINARY_SIGNER,
            max_capacity: 1,
            minimum_admission_interval_seconds: 5,
            expires_at: 100,
        }
    }

    fn seccomp_readback(path: &str, digest: &str) -> SeccompFileReadback {
        SeccompFileReadback {
            path: path.into(),
            canonical_path: path.into(),
            file_type: SeccompFileType::Regular,
            link_count: 1,
            owner_uid: 0,
            owner_gid: 0,
            mode: SECCOMP_PROFILE_MODE,
            digest: digest.into(),
        }
    }

    fn seccomp() -> SeccompLeaseEvidence {
        SeccompSeedPlan::phase1()
            .readiness(&seccomp_readback(
                PHASE1_SECCOMP_PROFILE_PATH,
                PHASE1_SECCOMP_PROFILE_DIGEST,
            ))
            .expect("exact seccomp readiness")
    }

    fn qualifying_controller() -> ActivationController {
        let mut controller = ActivationController::new(ROOT);
        assert_eq!(controller.start_qualification(permit()), Ok(()));
        controller
    }

    fn ready_controller() -> ActivationController {
        ready_controller_with_grant(grant())
    }

    fn ready_controller_with_grant(activation_grant: ActivationGrant) -> ActivationController {
        let mut controller = qualifying_controller();
        let lease = controller
            .admit_qualification(qualification_admission(), 10)
            .expect("qualification admission");
        assert_eq!(
            controller.finish_qualification(
                lease,
                QualificationOutcome::Accepted {
                    evidence_set_digest: [16; 32],
                },
            ),
            Ok(())
        );
        assert_eq!(
            controller.reconcile_activation(activation_grant, seccomp(), [12; 32], 20),
            Ok(())
        );
        controller
    }

    fn ordinary_admission(nonce: u8, lease_id: u8, expires_at: u64) -> OrdinaryAdmission {
        OrdinaryAdmission {
            host: host_coordinates(),
            job: ordinary_job(),
            lease_id: [lease_id; 16],
            run_id: [44; 16],
            attempt: 1,
            signer: ORDINARY_SIGNER,
            nonce: [nonce; 32],
            expires_at,
            wall_timeout_seconds: 30,
            trust_class: AdmissionTrustClass::AcceptedReviewed,
        }
    }

    #[test]
    fn exact_lifecycle_requires_qualification_reconciliation_and_a_lease() {
        let mut controller = ActivationController::new(ROOT);
        assert_eq!(controller.state(), ActivationState::Unprovisioned);
        assert_eq!(controller.ordinary_capacity(0), 0);

        assert_eq!(controller.start_qualification(permit()), Ok(()));
        assert_eq!(controller.state(), ActivationState::Qualifying);
        assert_eq!(controller.ordinary_capacity(10), 0);

        let qualification_lease = controller
            .admit_qualification(qualification_admission(), 10)
            .expect("qualification admission");
        assert_eq!(
            controller.finish_qualification(
                qualification_lease,
                QualificationOutcome::Accepted {
                    evidence_set_digest: [16; 32],
                },
            ),
            Ok(())
        );
        assert_eq!(controller.state(), ActivationState::Reconciling);
        assert_eq!(controller.ordinary_capacity(20), 0);

        assert_eq!(
            controller.reconcile_activation(grant(), seccomp(), [12; 32], 20),
            Ok(())
        );
        assert_eq!(controller.state(), ActivationState::Ready);
        assert_eq!(controller.ordinary_capacity(20), 1);

        let lease = controller
            .admit_ordinary(ordinary_admission(21, 22, 100), 21)
            .expect("ordinary admission");
        assert_eq!(controller.state(), ActivationState::Leased);
        assert_eq!(controller.ordinary_capacity(21), 0);
        assert_eq!(
            controller.finish_lease(lease, LeaseConclusion::Success),
            Ok(())
        );
        assert_eq!(controller.state(), ActivationState::Draining);
        assert_eq!(
            controller.finish_cleanup(lease, CleanupDisposition::Clean, 22),
            Ok(())
        );
        assert_eq!(controller.state(), ActivationState::Ready);
        assert_eq!(controller.ordinary_capacity(22), 1);
    }

    #[test]
    fn fixture_is_coordinate_scoped_single_use_and_never_enables_jobs() {
        let mut controller = qualifying_controller();
        assert_eq!(
            controller.admit_ordinary(ordinary_admission(11, 12, 25), 10),
            Err(AdmissionError::QualificationOnly)
        );

        for host in mismatched_host_coordinates() {
            let mut wrong_coordinate = qualification_admission();
            wrong_coordinate.host = host;
            assert_eq!(
                controller.admit_qualification(wrong_coordinate, 10),
                Err(AdmissionError::CoordinateMismatch)
            );
        }
        for fixture_job in mismatched_job_coordinates() {
            let mut wrong_coordinate = qualification_admission();
            wrong_coordinate.fixture_job = fixture_job;
            assert_eq!(
                controller.admit_qualification(wrong_coordinate, 10),
                Err(AdmissionError::CoordinateMismatch)
            );
        }

        let admission = qualification_admission();
        assert!(controller.admit_qualification(admission, 10).is_ok());
        assert_eq!(
            controller.admit_qualification(admission, 10),
            Err(AdmissionError::Replay)
        );
        assert_eq!(controller.state(), ActivationState::Qualifying);
        assert_eq!(controller.ordinary_capacity(10), 0);
    }

    #[test]
    fn qualification_admission_errors_are_closed_and_specific() {
        let mut controller = qualifying_controller();
        assert_eq!(
            controller.admit_qualification(qualification_admission(), 9),
            Err(AdmissionError::RateLimit)
        );

        assert_eq!(
            controller.admit_qualification(qualification_admission(), 30),
            Err(AdmissionError::ExpiredNonce)
        );

        let mut unauthorized = qualification_admission();
        unauthorized.signer = VerifiedSigner([99; 32]);
        assert_eq!(
            controller.admit_qualification(unauthorized, 10),
            Err(AdmissionError::UnauthorizedSigner)
        );

        let mut unaccepted = qualification_admission();
        unaccepted.trust_class = AdmissionTrustClass::Unaccepted;
        assert_eq!(
            controller.admit_qualification(unaccepted, 10),
            Err(AdmissionError::UnacceptedTrustClass)
        );

        assert!(controller
            .admit_qualification(qualification_admission(), 10)
            .is_ok());
        let mut second = qualification_admission();
        second.nonce = [13; 32];
        assert_eq!(
            controller.admit_qualification(second, 10),
            Err(AdmissionError::ConcurrencyLimit)
        );
    }

    #[test]
    fn protocol_qualification_binds_authenticated_signer_expiry_and_directive() {
        let mut controller = qualifying_controller();
        assert_eq!(
            controller.admit_qualification_request(
                qualification_request(None),
                VerifiedSigner([99; 32]),
                10,
            ),
            Err(AdmissionError::UnauthorizedSigner)
        );

        let mut wrong_expiry = qualification_request(None);
        wrong_expiry.expires_at += 1;
        assert_eq!(
            controller.admit_qualification_request(wrong_expiry, FIXTURE_SIGNER, 10),
            Err(AdmissionError::CoordinateMismatch)
        );

        let mut unauthorized_directive = qualification_request(None);
        unauthorized_directive.directive = Some(QualificationDirective::TeardownFailure);
        assert_eq!(
            controller.admit_qualification_request(unauthorized_directive, FIXTURE_SIGNER, 10,),
            Err(AdmissionError::CoordinateMismatch)
        );

        let lease = controller
            .admit_qualification_request(qualification_request(None), FIXTURE_SIGNER, 10)
            .expect("ordinary qualification fixture");
        assert_eq!(lease.directive(), None);

        let mut teardown_permit = permit();
        teardown_permit.directive = Some(QualificationDirective::TeardownFailure);
        let mut teardown_controller = ActivationController::new(ROOT);
        teardown_controller
            .start_qualification(teardown_permit)
            .expect("teardown qualification permit");
        let teardown_lease = teardown_controller
            .admit_qualification_request(
                qualification_request(Some(QualificationDirective::TeardownFailure)),
                FIXTURE_SIGNER,
                10,
            )
            .expect("teardown qualification fixture");
        assert_eq!(
            teardown_lease.directive(),
            Some(QualificationDirective::TeardownFailure)
        );
    }

    #[test]
    fn grant_binds_build_host_suite_evidence_capacity_and_blocker_closure() {
        for host in mismatched_host_coordinates() {
            let mut mismatched = grant();
            mismatched.host = host;
            let mut controller = controller_at_reconciliation();
            assert_eq!(
                controller.reconcile_activation(mismatched, seccomp(), [12; 32], 20),
                Err(ActivationError::InvalidGrant)
            );
            assert_eq!(controller.state(), ActivationState::Quarantined);
        }

        let mut wrong_evidence = grant();
        wrong_evidence.evidence_set_digest = [99; 32];
        let mut wrong_root = grant();
        wrong_root.authorized_by = VerifiedSigner([99; 32]);
        for mismatched in [wrong_evidence, wrong_root] {
            let mut controller = controller_at_reconciliation();
            assert!(controller
                .reconcile_activation(mismatched, seccomp(), [12; 32], 20)
                .is_err());
            assert_eq!(controller.state(), ActivationState::Quarantined);
        }

        let mut wrong_capacity = controller_at_reconciliation();
        let mut capacity_grant = grant();
        capacity_grant.max_capacity = 2;
        assert_eq!(
            wrong_capacity.reconcile_activation(capacity_grant, seccomp(), [12; 32], 20),
            Err(ActivationError::InvalidGrant)
        );
        assert_eq!(wrong_capacity.ordinary_capacity(20), 0);

        let mut zero_rate = controller_at_reconciliation();
        let zero_rate_grant = ActivationGrant {
            minimum_admission_interval_seconds: 0,
            ..grant()
        };
        assert_eq!(
            zero_rate.reconcile_activation(zero_rate_grant, seccomp(), [12; 32], 20),
            Err(ActivationError::InvalidGrant)
        );
        assert_eq!(zero_rate.state(), ActivationState::Quarantined);

        for count_grant in [
            ActivationGrant {
                security_records_passed: 16,
                ..grant()
            },
            ActivationGrant {
                security_records_total: 18,
                ..grant()
            },
            ActivationGrant {
                probes_passed: 11,
                ..grant()
            },
            ActivationGrant {
                probes_total: 13,
                ..grant()
            },
        ] {
            let mut controller = controller_at_reconciliation();
            assert_eq!(
                controller.reconcile_activation(count_grant, seccomp(), [12; 32], 20),
                Err(ActivationError::AcceptanceCountMismatch)
            );
            assert_eq!(controller.state(), ActivationState::Quarantined);
        }

        let mut open_blockers = controller_at_reconciliation();
        let mut blocker_grant = grant();
        blocker_grant.all_blockers_closed = false;
        assert_eq!(
            open_blockers.reconcile_activation(blocker_grant, seccomp(), [12; 32], 20),
            Err(ActivationError::BlockersOpen)
        );
        assert_eq!(open_blockers.state(), ActivationState::Quarantined);

        let mut missing_closure = controller_at_reconciliation();
        let mut closure_grant = grant();
        closure_grant.blocker_closure_digest = [0; 32];
        assert_eq!(
            missing_closure.reconcile_activation(closure_grant, seccomp(), [12; 32], 20),
            Err(ActivationError::BlockersOpen)
        );
    }

    #[test]
    fn ready_requires_opaque_seccomp_readiness_and_matching_host_profile() {
        let plan = SeccompSeedPlan::phase1();
        let wrong_path = seccomp_readback(
            "/var/lib/buzzci/seccomp/v1/sha256/wrong.json",
            PHASE1_SECCOMP_PROFILE_DIGEST,
        );
        let wrong_digest = seccomp_readback(PHASE1_SECCOMP_PROFILE_PATH, "00");
        let mut weaker =
            seccomp_readback(PHASE1_SECCOMP_PROFILE_PATH, PHASE1_SECCOMP_PROFILE_DIGEST);
        weaker.mode = 0o644;

        assert!(plan.readiness(&wrong_path).is_err());
        assert!(plan.readiness(&wrong_digest).is_err());
        assert!(plan.readiness(&weaker).is_err());
        let controller = controller_at_reconciliation();
        assert_eq!(controller.state(), ActivationState::Reconciling);
        assert_eq!(controller.ordinary_capacity(20), 0);

        let mut controller = controller_at_reconciliation();
        assert_eq!(
            controller.reconcile_activation(grant(), seccomp(), [99; 32], 20),
            Err(ActivationError::HostProfileMismatch)
        );
        assert_eq!(controller.state(), ActivationState::Quarantined);
        assert_eq!(controller.ordinary_capacity(20), 0);
    }

    #[test]
    fn cleanup_ambiguity_quarantines_and_success_without_lease_is_impossible() {
        let mut controller = ready_controller();
        let fabricated = LeaseToken {
            lease_id: [42; 16],
            run_id: [44; 16],
            attempt: 1,
            signed_request_digest: [4; 32],
            signer: ORDINARY_SIGNER,
            generation: 1,
            nonce: [43; 32],
            deadline_at: 50,
        };
        assert_eq!(
            controller.finish_lease(fabricated, LeaseConclusion::Success),
            Err(ActivationError::MissingLease)
        );
        assert_eq!(controller.state(), ActivationState::Ready);

        let lease = controller
            .admit_ordinary(ordinary_admission(21, 22, 100), 21)
            .expect("ordinary admission");
        controller
            .finish_lease(lease, LeaseConclusion::Success)
            .expect("lease finish");
        assert_eq!(
            controller.finish_cleanup(lease, CleanupDisposition::Ambiguous, 22),
            Err(ActivationError::ReconciliationAmbiguous)
        );
        assert_eq!(controller.state(), ActivationState::Quarantined);
        assert_eq!(controller.ordinary_capacity(22), 0);
    }

    #[test]
    fn ordinary_admission_enforces_replay_rate_trust_signer_and_concurrency() {
        let mut controller = ready_controller();
        for host in mismatched_host_coordinates() {
            let mut mismatched = ordinary_admission(21, 22, 100);
            mismatched.host = host;
            assert_eq!(
                controller.admit_ordinary(mismatched, 21),
                Err(AdmissionError::CoordinateMismatch)
            );
        }
        for job in malformed_ordinary_job_coordinates() {
            let mut mismatched = ordinary_admission(21, 22, 100);
            mismatched.job = job;
            assert_eq!(
                controller.admit_ordinary(mismatched, 21),
                Err(AdmissionError::CoordinateMismatch)
            );
        }
        let mut fixture_reuse = ordinary_admission(21, 22, 100);
        fixture_reuse.job = fixture_job_as_ordinary();
        assert_eq!(
            controller.admit_ordinary(fixture_reuse, 21),
            Err(AdmissionError::CoordinateMismatch)
        );

        assert_eq!(
            controller.admit_ordinary(ordinary_admission(21, 22, 101), 21),
            Err(AdmissionError::ExpiredNonce)
        );

        let mut unauthorized = ordinary_admission(21, 22, 100);
        unauthorized.signer = VerifiedSigner([99; 32]);
        assert_eq!(
            controller.admit_ordinary(unauthorized, 21),
            Err(AdmissionError::UnauthorizedSigner)
        );

        let mut unaccepted = ordinary_admission(21, 22, 100);
        unaccepted.trust_class = AdmissionTrustClass::QualificationFixture;
        assert_eq!(
            controller.admit_ordinary(unaccepted, 21),
            Err(AdmissionError::UnacceptedTrustClass)
        );

        let first = ordinary_admission(21, 22, 100);
        let first_lease = controller
            .admit_ordinary(first, 21)
            .expect("ordinary admission");
        assert_eq!(
            controller.admit_ordinary(first, 21),
            Err(AdmissionError::Replay)
        );
        assert_eq!(
            controller.admit_ordinary(ordinary_admission(23, 24, 100), 21),
            Err(AdmissionError::ConcurrencyLimit)
        );
        controller
            .finish_lease(first_lease, LeaseConclusion::Success)
            .expect("lease finish");
        controller
            .finish_cleanup(first_lease, CleanupDisposition::Clean, 22)
            .expect("cleanup");
        assert_eq!(
            controller.admit_ordinary(ordinary_admission(23, 24, 100), 24),
            Err(AdmissionError::RateLimit)
        );
        assert!(controller
            .admit_ordinary(ordinary_admission(23, 24, 100), 26)
            .is_ok());
    }

    #[test]
    fn validated_host_grant_admits_a_different_ordinary_job() {
        let mut controller = ready_controller();
        let request = ordinary_admission(21, 22, 50);
        assert_eq!(request.host, grant().host);
        assert!(!same_job_coordinates(request.job, permit().fixture_job));
        assert!(controller.admit_ordinary(request, 21).is_ok());
    }

    #[test]
    fn ordinary_expiry_may_precede_but_never_exceed_grant_expiry() {
        let mut controller = ready_controller();
        let lease = controller
            .admit_ordinary(ordinary_admission(21, 22, 50), 21)
            .expect("request expiry before grant");
        controller
            .finish_lease(lease, LeaseConclusion::Success)
            .expect("lease finish");
        controller
            .finish_cleanup(lease, CleanupDisposition::Clean, 22)
            .expect("cleanup");

        assert_eq!(
            controller.admit_ordinary(ordinary_admission(23, 24, 101), 26),
            Err(AdmissionError::ExpiredNonce)
        );
    }

    #[test]
    fn nonce_ledger_prunes_only_expired_entries_and_reuses_capacity() {
        let activation_grant = ActivationGrant {
            minimum_admission_interval_seconds: 1,
            expires_at: 1_000,
            ..grant()
        };
        let mut controller = ready_controller_with_grant(activation_grant);

        for (offset, nonce) in (20_u8..84).enumerate() {
            let now = 21 + u64::try_from(offset).expect("bounded offset");
            let lease = controller
                .admit_ordinary(ordinary_admission(nonce, nonce, 500), now)
                .expect("bounded admission");
            controller
                .finish_lease(lease, LeaseConclusion::Success)
                .expect("lease finish");
            controller
                .finish_cleanup(lease, CleanupDisposition::Clean, now)
                .expect("cleanup");
        }
        assert_eq!(
            controller.admit_ordinary(ordinary_admission(20, 90, 500), 85),
            Err(AdmissionError::Replay)
        );
        let before_full_failure = controller.snapshot();
        assert_eq!(
            controller.admit_ordinary(ordinary_admission(84, 84, 600), 85),
            Err(AdmissionError::RateLimit)
        );
        assert_eq!(controller.snapshot(), before_full_failure);

        assert_eq!(
            controller.admit_ordinary(ordinary_admission(20, 90, 600), 499),
            Err(AdmissionError::Replay)
        );
        let reused = controller
            .admit_ordinary(ordinary_admission(20, 90, 600), 500)
            .expect("expired replay record can be reused");
        controller
            .finish_lease(reused, LeaseConclusion::Success)
            .expect("lease finish");
        controller
            .finish_cleanup(reused, CleanupDisposition::Clean, 500)
            .expect("cleanup");
        let restored = ActivationController::restore(
            ROOT,
            controller.snapshot(),
            Some(ReadyRestoreValidation {
                grant: activation_grant,
                seccomp_evidence: seccomp(),
                host_profile_digest: [12; 32],
                now: 501,
            }),
        );
        assert_eq!(restored.quarantine_reason, None);
        assert_eq!(restored.controller.state(), ActivationState::Ready);
    }

    #[test]
    fn full_nonce_ledger_leaves_qualification_snapshot_unchanged() {
        let qualifying = qualifying_controller();
        let mut snapshot = qualifying.snapshot();
        for (index, nonce) in (100_u8..164).enumerate() {
            snapshot.nonce_ledger.entries[index] = Some(DurableNonceEntry {
                nonce: [nonce; 32],
                expires_at: 30,
            });
        }
        let restored = ActivationController::restore(ROOT, snapshot, None);
        assert_eq!(restored.quarantine_reason, None);
        let mut controller = restored.controller;
        let before = controller.snapshot();

        assert_eq!(
            controller.admit_qualification(qualification_admission(), 10),
            Err(AdmissionError::RateLimit)
        );
        assert_eq!(controller.snapshot(), before);
    }

    #[test]
    fn restart_preserves_replay_generation_and_rate_state() {
        let mut controller = ready_controller();
        let first = ordinary_admission(21, 22, 100);
        let first_lease = controller
            .admit_ordinary(first, 21)
            .expect("ordinary admission");
        controller
            .finish_lease(first_lease, LeaseConclusion::Success)
            .expect("lease finish");
        controller
            .finish_cleanup(first_lease, CleanupDisposition::Clean, 22)
            .expect("cleanup");

        let restored = ActivationController::restore(
            ROOT,
            controller.snapshot(),
            Some(ReadyRestoreValidation {
                grant: grant(),
                seccomp_evidence: seccomp(),
                host_profile_digest: [12; 32],
                now: 23,
            }),
        );
        assert_eq!(restored.quarantine_reason, None);
        let mut controller = restored.controller;
        assert_eq!(controller.state(), ActivationState::Ready);
        assert_eq!(
            controller.admit_ordinary(first, 23),
            Err(AdmissionError::Replay)
        );
        assert_eq!(
            controller.admit_ordinary(ordinary_admission(23, 24, 100), 24),
            Err(AdmissionError::RateLimit)
        );
        let second = controller
            .admit_ordinary(ordinary_admission(23, 24, 100), 26)
            .expect("second admission");
        assert_eq!(second.generation, 3);
    }

    #[test]
    fn restart_retains_leased_but_quarantines_ambiguous_inflight_state() {
        let mut qualifying = qualifying_controller();
        qualifying
            .admit_qualification(qualification_admission(), 10)
            .expect("qualification admission");

        let mut leased = ready_controller();
        let lease = leased
            .admit_ordinary(ordinary_admission(21, 22, 100), 21)
            .expect("ordinary admission");
        let leased_snapshot = leased.snapshot();
        leased
            .finish_lease(lease, LeaseConclusion::Success)
            .expect("lease finish");

        let restored = ActivationController::restore(ROOT, leased_snapshot, None);
        assert_eq!(restored.controller.state(), ActivationState::Quarantined);
        assert_eq!(restored.controller.recovery_lease(), Some(lease));
        assert_eq!(
            restored.quarantine_reason,
            Some(ActivationError::RestartAmbiguous)
        );
        assert_eq!(restored.controller.ordinary_capacity(21), 0);

        let restored = ActivationController::restore(ROOT, leased.snapshot(), None);
        assert_eq!(restored.controller.state(), ActivationState::Quarantined);
        assert_eq!(restored.controller.recovery_lease(), Some(lease));
        assert_eq!(
            restored.quarantine_reason,
            Some(ActivationError::RestartAmbiguous)
        );

        for snapshot in [
            qualifying.snapshot(),
            controller_at_reconciliation().snapshot(),
        ] {
            let restored = ActivationController::restore(ROOT, snapshot, None);
            assert_eq!(restored.controller.state(), ActivationState::Quarantined);
            assert_eq!(
                restored.quarantine_reason,
                Some(ActivationError::RestartAmbiguous)
            );
            assert_eq!(restored.controller.ordinary_capacity(21), 0);
        }

        let ready = ready_controller();
        let restored = ActivationController::restore(ROOT, ready.snapshot(), None);
        assert_eq!(restored.controller.state(), ActivationState::Quarantined);
        assert_eq!(
            restored.quarantine_reason,
            Some(ActivationError::SnapshotInvalid)
        );
    }

    #[test]
    fn ready_restore_revalidates_exact_grant_and_host_profile() {
        let ready = ready_controller();
        let snapshot = ready.snapshot();

        let mut wrong_grant = grant();
        wrong_grant.evidence_set_digest = [99; 32];
        let restored = ActivationController::restore(
            ROOT,
            snapshot,
            Some(ReadyRestoreValidation {
                grant: wrong_grant,
                seccomp_evidence: seccomp(),
                host_profile_digest: [12; 32],
                now: 21,
            }),
        );
        assert_eq!(restored.controller.state(), ActivationState::Quarantined);
        assert_eq!(
            restored.quarantine_reason,
            Some(ActivationError::SnapshotInvalid)
        );

        let restored = ActivationController::restore(
            ROOT,
            snapshot,
            Some(ReadyRestoreValidation {
                grant: grant(),
                seccomp_evidence: seccomp(),
                host_profile_digest: [99; 32],
                now: 21,
            }),
        );
        assert_eq!(restored.controller.state(), ActivationState::Quarantined);
        assert_eq!(
            restored.quarantine_reason,
            Some(ActivationError::HostProfileMismatch)
        );

        let restored = ActivationController::restore(
            ROOT,
            snapshot,
            Some(ReadyRestoreValidation {
                grant: grant(),
                seccomp_evidence: seccomp(),
                host_profile_digest: [12; 32],
                now: 21,
            }),
        );
        assert_eq!(restored.quarantine_reason, None);
        assert_eq!(restored.controller.state(), ActivationState::Ready);
        assert_eq!(restored.controller.ordinary_capacity(21), 1);
    }

    #[test]
    fn expired_activation_has_no_capacity_and_cleanup_cannot_reuse_slot() {
        let mut controller = ready_controller();
        assert_eq!(controller.ordinary_capacity(99), 1);
        assert_eq!(controller.ordinary_capacity(100), 0);
        assert_eq!(
            controller.admit_ordinary(ordinary_admission(21, 22, 100), 100),
            Err(AdmissionError::ExpiredNonce)
        );

        let lease = controller
            .admit_ordinary(ordinary_admission(21, 22, 100), 99)
            .expect("ordinary admission before expiry");
        controller
            .finish_lease(lease, LeaseConclusion::Success)
            .expect("lease finish");
        assert_eq!(
            controller.finish_cleanup(lease, CleanupDisposition::Clean, 100),
            Err(ActivationError::ActivationExpired)
        );
        assert_eq!(controller.state(), ActivationState::Quarantined);
        assert_eq!(controller.ordinary_capacity(100), 0);
    }

    #[test]
    fn exhausted_generation_quarantines_before_lease_or_nonce_allocation() {
        let ready = ready_controller();
        let mut snapshot = ready.snapshot();
        snapshot.next_lease_generation = u64::MAX;
        let restored = ActivationController::restore(
            ROOT,
            snapshot,
            Some(ReadyRestoreValidation {
                grant: grant(),
                seccomp_evidence: seccomp(),
                host_profile_digest: [12; 32],
                now: 21,
            }),
        );
        assert_eq!(restored.quarantine_reason, None);
        let mut controller = restored.controller;
        let before = controller.snapshot();

        assert_eq!(
            controller.admit_ordinary(ordinary_admission(21, 22, 100), 21),
            Err(AdmissionError::GenerationExhausted)
        );
        let after = controller.snapshot();
        assert_eq!(after.state, ActivationState::Quarantined);
        assert_eq!(controller.ordinary_capacity(21), 0);
        assert_eq!(after.active_lease, None);
        assert_eq!(after.next_lease_generation, before.next_lease_generation);
        assert_eq!(after.last_admission_at, before.last_admission_at);
        assert_eq!(after.nonce_ledger, before.nonce_ledger);
    }

    #[test]
    fn malformed_durable_ledger_quarantines_on_restore() {
        let mut snapshot = ActivationController::new(ROOT).snapshot();
        let duplicate = DurableNonceEntry {
            nonce: [99; 32],
            expires_at: 100,
        };
        snapshot.nonce_ledger.entries[0] = Some(duplicate);
        snapshot.nonce_ledger.entries[1] = Some(duplicate);
        let restored = ActivationController::restore(ROOT, snapshot, None);
        assert_eq!(restored.controller.state(), ActivationState::Quarantined);
        assert_eq!(
            restored.quarantine_reason,
            Some(ActivationError::SnapshotInvalid)
        );
    }

    #[test]
    fn ambiguous_qualification_never_reaches_reconciliation() {
        let mut controller = qualifying_controller();
        let lease = controller
            .admit_qualification(qualification_admission(), 10)
            .expect("qualification admission");
        assert_eq!(
            controller.finish_qualification(lease, QualificationOutcome::Ambiguous),
            Err(ActivationError::ReconciliationAmbiguous)
        );
        assert_eq!(controller.state(), ActivationState::Quarantined);
        assert_eq!(controller.ordinary_capacity(10), 0);
    }

    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    #[test]
    fn oci_receipt_name_comes_from_the_opaque_lease_token() {
        let token = LeaseToken {
            lease_id: [0xab; 16],
            run_id: [0xbc; 16],
            attempt: 1,
            signed_request_digest: [0xbd; 32],
            signer: ORDINARY_SIGNER,
            generation: 42,
            nonce: [0xcd; 32],
            deadline_at: 100,
        };
        assert_eq!(token.lease_id(), [0xab; 16]);
        assert_eq!(token.generation(), 42);
        assert_eq!(
            crate::seccomp_exec::oci_receipt_filename(token),
            "abababababababababababababababab-g42.json"
        );
    }

    fn controller_at_reconciliation() -> ActivationController {
        let mut controller = qualifying_controller();
        let lease = controller
            .admit_qualification(qualification_admission(), 10)
            .expect("qualification admission");
        controller
            .finish_qualification(
                lease,
                QualificationOutcome::Accepted {
                    evidence_set_digest: [16; 32],
                },
            )
            .expect("qualification finish");
        controller
    }
}
