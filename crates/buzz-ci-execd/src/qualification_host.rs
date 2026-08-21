//! Closed host-cleanup contract for the teardown-failure qualification fixture.
//!
//! This module performs no host mutation. The in-process root executor consumes
//! a fixed plan and returns only bounded evidence. No wire value becomes a
//! command, path, unit name, or network rule.

use buzz_ci_broker_protocol::{GitOid, QualificationDirective, QualificationRequest};

use crate::activation::QualificationLease;

/// Fixed root-owned location for future atomic qualification receipts.
pub const QUALIFICATION_RECEIPT_ROOT: &str = "/var/lib/buzzci/activation";
/// Exact number of terminal observations required by the teardown fixture.
pub const QUALIFICATION_TERMINAL_EVENT_COUNT: usize = 10;

/// Every identity retained across the admitted request, host plan, and receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QualificationHostBinding {
    pub integrated_candidate_sha: GitOid,
    pub broker_build_identity: [u8; 32],
    pub host_profile_digest: [u8; 32],
    pub suite_identity: [u8; 32],
    pub fixture_signer: [u8; 32],
    pub request_digest: [u8; 32],
    pub manifest_digest: [u8; 32],
    pub isolation_profile_digest: [u8; 32],
    pub source_oid: GitOid,
    pub base_oid: GitOid,
    pub job_identity: [u8; 32],
    pub fixture_identity: [u8; 32],
    pub nonce: [u8; 32],
    pub lease_id: [u8; 16],
    pub lease_generation: u64,
}

/// The sole host behavior authorized by this qualification contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QualificationHostAction {
    TeardownFailure,
}

/// A plan produced only after activation admitted the exact qualification lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QualificationHostPlan {
    binding: QualificationHostBinding,
    action: QualificationHostAction,
}

impl QualificationHostPlan {
    /// Bind an admitted teardown-failure request to its opaque activation lease.
    pub fn from_admitted(
        request: QualificationRequest,
        lease: QualificationLease,
    ) -> Result<Self, QualificationHostContractError> {
        if request.directive != Some(QualificationDirective::TeardownFailure)
            || lease.directive() != Some(QualificationDirective::TeardownFailure)
        {
            return Err(QualificationHostContractError::DirectiveRequired);
        }
        if lease.fixture_identity() != request.fixture_identity
            || lease.nonce() != request.nonce
            || lease.lease_id() != request.fixture_identity[..16]
            || lease.generation() == 0
        {
            return Err(QualificationHostContractError::BindingMismatch);
        }
        Ok(Self {
            binding: QualificationHostBinding {
                integrated_candidate_sha: request.integrated_candidate_sha,
                broker_build_identity: request.broker_build_identity,
                host_profile_digest: request.host_profile_digest,
                suite_identity: request.suite_identity,
                fixture_signer: request.fixture_signer,
                request_digest: request.request_digest,
                manifest_digest: request.manifest_digest,
                isolation_profile_digest: request.isolation_profile_digest,
                source_oid: request.source_oid,
                base_oid: request.base_oid,
                job_identity: request.job_identity,
                fixture_identity: request.fixture_identity,
                nonce: request.nonce,
                lease_id: lease.lease_id(),
                lease_generation: lease.generation(),
            },
            action: QualificationHostAction::TeardownFailure,
        })
    }

    pub const fn binding(self) -> QualificationHostBinding {
        self.binding
    }

    pub const fn action(self) -> QualificationHostAction {
        self.action
    }
}

/// Closed terminal sequence for forced teardown failure and publication refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QualificationTerminalEvent {
    Stop,
    FinalizeRawStream,
    Extract,
    Scrub,
    Scan,
    Hash,
    Upload,
    TeardownFailureObserved,
    PublicationSuppressed,
    Quarantined,
}

/// One position in the exact terminal sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QualificationTerminalRecord {
    pub sequence: u8,
    pub event: QualificationTerminalEvent,
}

/// Canonical terminal ordering required for a complete receipt.
pub const QUALIFICATION_TERMINAL_ORDER: [QualificationTerminalRecord;
    QUALIFICATION_TERMINAL_EVENT_COUNT] = [
    QualificationTerminalRecord {
        sequence: 1,
        event: QualificationTerminalEvent::Stop,
    },
    QualificationTerminalRecord {
        sequence: 2,
        event: QualificationTerminalEvent::FinalizeRawStream,
    },
    QualificationTerminalRecord {
        sequence: 3,
        event: QualificationTerminalEvent::Extract,
    },
    QualificationTerminalRecord {
        sequence: 4,
        event: QualificationTerminalEvent::Scrub,
    },
    QualificationTerminalRecord {
        sequence: 5,
        event: QualificationTerminalEvent::Scan,
    },
    QualificationTerminalRecord {
        sequence: 6,
        event: QualificationTerminalEvent::Hash,
    },
    QualificationTerminalRecord {
        sequence: 7,
        event: QualificationTerminalEvent::Upload,
    },
    QualificationTerminalRecord {
        sequence: 8,
        event: QualificationTerminalEvent::TeardownFailureObserved,
    },
    QualificationTerminalRecord {
        sequence: 9,
        event: QualificationTerminalEvent::PublicationSuppressed,
    },
    QualificationTerminalRecord {
        sequence: 10,
        event: QualificationTerminalEvent::Quarantined,
    },
];

/// Complete bounded host evidence for the forced teardown failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QualificationHostReceipt {
    binding: QualificationHostBinding,
    terminal_order: [QualificationTerminalRecord; QUALIFICATION_TERMINAL_EVENT_COUNT],
    teardown_failure_evidence_digest: [u8; 32],
    no_publish_evidence_digest: [u8; 32],
    quarantine_evidence_digest: [u8; 32],
}

impl QualificationHostReceipt {
    /// Accept only exact ordering and explicit nonzero evidence for every result.
    pub fn new(
        plan: QualificationHostPlan,
        terminal_order: [QualificationTerminalRecord; QUALIFICATION_TERMINAL_EVENT_COUNT],
        teardown_failure_evidence_digest: [u8; 32],
        no_publish_evidence_digest: [u8; 32],
        quarantine_evidence_digest: [u8; 32],
    ) -> Result<Self, QualificationHostContractError> {
        if terminal_order != QUALIFICATION_TERMINAL_ORDER {
            return Err(QualificationHostContractError::TerminalOrder);
        }
        if teardown_failure_evidence_digest == [0; 32]
            || no_publish_evidence_digest == [0; 32]
            || quarantine_evidence_digest == [0; 32]
        {
            return Err(QualificationHostContractError::MissingEvidence);
        }
        Ok(Self {
            binding: plan.binding,
            terminal_order,
            teardown_failure_evidence_digest,
            no_publish_evidence_digest,
            quarantine_evidence_digest,
        })
    }

    pub const fn binding(self) -> QualificationHostBinding {
        self.binding
    }

    pub const fn terminal_order(
        self,
    ) -> [QualificationTerminalRecord; QUALIFICATION_TERMINAL_EVENT_COUNT] {
        self.terminal_order
    }

    pub const fn teardown_failure_evidence_digest(self) -> [u8; 32] {
        self.teardown_failure_evidence_digest
    }

    pub const fn no_publish_evidence_digest(self) -> [u8; 32] {
        self.no_publish_evidence_digest
    }

    pub const fn quarantine_evidence_digest(self) -> [u8; 32] {
        self.quarantine_evidence_digest
    }
}

/// The only observations accepted from the in-process host executor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
// Keeping the bounded receipt inline avoids an allocation in the root broker.
#[allow(clippy::large_enum_variant)]
pub enum QualificationHostExecution {
    Complete(QualificationHostReceipt),
    Missing,
    Ambiguous,
}

/// Why bounded host evidence was or was not accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QualificationHostEvidenceState {
    Complete,
    Missing,
    Ambiguous,
    BindingMismatch,
}

/// Closed conclusion for this forced-failure fixture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QualificationHostConclusion {
    InfrastructureFailure,
}

/// Closed activation state after this fixture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QualificationHostState {
    Quarantined,
}

/// Closed publication result after this fixture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QualificationPublication {
    Suppressed,
}

/// Fail-closed evaluation of one host execution observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QualificationHostOutcome {
    pub binding: QualificationHostBinding,
    pub evidence_state: QualificationHostEvidenceState,
    pub conclusion: QualificationHostConclusion,
    pub state: QualificationHostState,
    pub publication: QualificationPublication,
    receipt: Option<QualificationHostReceipt>,
}

impl QualificationHostOutcome {
    pub fn evaluate(plan: QualificationHostPlan, execution: QualificationHostExecution) -> Self {
        let (evidence_state, receipt) = match execution {
            QualificationHostExecution::Complete(receipt)
                if receipt.binding == plan.binding
                    && receipt.terminal_order == QUALIFICATION_TERMINAL_ORDER =>
            {
                (QualificationHostEvidenceState::Complete, Some(receipt))
            }
            QualificationHostExecution::Complete(_) => {
                (QualificationHostEvidenceState::BindingMismatch, None)
            }
            QualificationHostExecution::Missing => (QualificationHostEvidenceState::Missing, None),
            QualificationHostExecution::Ambiguous => {
                (QualificationHostEvidenceState::Ambiguous, None)
            }
        };
        Self {
            binding: plan.binding,
            evidence_state,
            conclusion: QualificationHostConclusion::InfrastructureFailure,
            state: QualificationHostState::Quarantined,
            publication: QualificationPublication::Suppressed,
            receipt,
        }
    }

    pub const fn receipt(self) -> Option<QualificationHostReceipt> {
        self.receipt
    }

    pub fn is_complete(self) -> bool {
        self.evidence_state == QualificationHostEvidenceState::Complete
    }

    pub fn teardown_digest(self) -> [u8; 32] {
        self.receipt.map_or(
            [0; 32],
            QualificationHostReceipt::teardown_failure_evidence_digest,
        )
    }

    pub fn no_publish_digest(self) -> [u8; 32] {
        self.receipt.map_or(
            [0; 32],
            QualificationHostReceipt::no_publish_evidence_digest,
        )
    }
}

/// Contract construction failure. No failure authorizes ordinary execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QualificationHostContractError {
    DirectiveRequired,
    BindingMismatch,
    TerminalOrder,
    MissingEvidence,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::activation::{
        ActivationController, FixtureJobCoordinates, HostActivationCoordinates,
        QualificationPermit, VerifiedSigner,
    };

    fn admitted(
        directive: Option<QualificationDirective>,
    ) -> (QualificationRequest, QualificationLease) {
        let root = VerifiedSigner([1; 32]);
        let signer = VerifiedSigner([2; 32]);
        let host = HostActivationCoordinates {
            integrated_candidate_sha: GitOid::Sha256([3; 32]),
            broker_build_identity: [4; 32],
            host_profile_digest: [5; 32],
            suite_identity: [6; 32],
        };
        let job = FixtureJobCoordinates {
            request_digest: [7; 32],
            manifest_digest: [8; 32],
            isolation_profile_digest: [9; 32],
            source_oid: GitOid::Sha256([10; 32]),
            base_oid: GitOid::Sha256([11; 32]),
            test_identity: [12; 32],
        };
        let permit = QualificationPermit {
            authorized_by: root,
            host,
            fixture_job: job,
            fixture_identity: [13; 32],
            fixture_signer: signer,
            nonce: [14; 32],
            not_before: 10,
            expires_at: 30,
            directive,
        };
        let request = QualificationRequest {
            integrated_candidate_sha: host.integrated_candidate_sha,
            broker_build_identity: host.broker_build_identity,
            host_profile_digest: host.host_profile_digest,
            suite_identity: host.suite_identity,
            fixture_signer: signer.0,
            request_digest: job.request_digest,
            manifest_digest: job.manifest_digest,
            isolation_profile_digest: job.isolation_profile_digest,
            source_oid: job.source_oid,
            base_oid: job.base_oid,
            job_identity: job.test_identity,
            fixture_identity: permit.fixture_identity,
            nonce: permit.nonce,
            not_before: permit.not_before,
            expires_at: permit.expires_at,
            directive,
        };
        let mut controller = ActivationController::new(root);
        controller.start_qualification(permit).unwrap();
        let lease = controller
            .admit_qualification_request(request, signer, 10)
            .unwrap();
        (request, lease)
    }

    fn receipt(plan: QualificationHostPlan) -> QualificationHostReceipt {
        QualificationHostReceipt::new(
            plan,
            QUALIFICATION_TERMINAL_ORDER,
            [21; 32],
            [22; 32],
            [23; 32],
        )
        .unwrap()
    }

    #[test]
    fn admitted_plan_binds_every_coordinate_and_opaque_lease_fact() {
        let (request, lease) = admitted(Some(QualificationDirective::TeardownFailure));
        let plan = QualificationHostPlan::from_admitted(request, lease).unwrap();
        let binding = plan.binding();
        assert_eq!(plan.action(), QualificationHostAction::TeardownFailure);
        assert_eq!(
            binding.integrated_candidate_sha,
            request.integrated_candidate_sha
        );
        assert_eq!(binding.broker_build_identity, request.broker_build_identity);
        assert_eq!(binding.host_profile_digest, request.host_profile_digest);
        assert_eq!(binding.suite_identity, request.suite_identity);
        assert_eq!(binding.fixture_signer, request.fixture_signer);
        assert_eq!(binding.request_digest, request.request_digest);
        assert_eq!(binding.manifest_digest, request.manifest_digest);
        assert_eq!(
            binding.isolation_profile_digest,
            request.isolation_profile_digest
        );
        assert_eq!(binding.source_oid, request.source_oid);
        assert_eq!(binding.base_oid, request.base_oid);
        assert_eq!(binding.job_identity, request.job_identity);
        assert_eq!(binding.fixture_identity, request.fixture_identity);
        assert_eq!(binding.nonce, request.nonce);
        assert_eq!(binding.lease_id, request.fixture_identity[..16]);
        assert_eq!(binding.lease_generation, 1);
    }

    #[test]
    fn ordinary_qualification_cannot_construct_a_teardown_plan() {
        let (request, lease) = admitted(None);
        assert_eq!(
            QualificationHostPlan::from_admitted(request, lease),
            Err(QualificationHostContractError::DirectiveRequired)
        );
    }

    #[test]
    fn receipt_requires_exact_order_and_explicit_no_publish_evidence() {
        let (request, lease) = admitted(Some(QualificationDirective::TeardownFailure));
        let plan = QualificationHostPlan::from_admitted(request, lease).unwrap();
        let mut wrong_order = QUALIFICATION_TERMINAL_ORDER;
        wrong_order.swap(7, 8);
        assert_eq!(
            QualificationHostReceipt::new(plan, wrong_order, [21; 32], [22; 32], [23; 32]),
            Err(QualificationHostContractError::TerminalOrder)
        );
        assert_eq!(
            QualificationHostReceipt::new(
                plan,
                QUALIFICATION_TERMINAL_ORDER,
                [21; 32],
                [0; 32],
                [23; 32],
            ),
            Err(QualificationHostContractError::MissingEvidence)
        );
    }

    #[test]
    fn every_execution_result_is_failure_quarantine_and_no_publish() {
        let (request, lease) = admitted(Some(QualificationDirective::TeardownFailure));
        let plan = QualificationHostPlan::from_admitted(request, lease).unwrap();
        for execution in [
            QualificationHostExecution::Complete(receipt(plan)),
            QualificationHostExecution::Missing,
            QualificationHostExecution::Ambiguous,
        ] {
            let outcome = QualificationHostOutcome::evaluate(plan, execution);
            assert_eq!(
                outcome.conclusion,
                QualificationHostConclusion::InfrastructureFailure
            );
            assert_eq!(outcome.state, QualificationHostState::Quarantined);
            assert_eq!(outcome.publication, QualificationPublication::Suppressed);
        }
    }

    #[test]
    fn receipt_from_another_lease_is_not_accepted() {
        let (request, lease) = admitted(Some(QualificationDirective::TeardownFailure));
        let plan = QualificationHostPlan::from_admitted(request, lease).unwrap();
        let (other_request, other_lease) = admitted(Some(QualificationDirective::TeardownFailure));
        let mut other_request = other_request;
        other_request.fixture_identity = [99; 32];
        let mut other_plan = QualificationHostPlan::from_admitted(other_request, other_lease);
        assert_eq!(
            other_plan,
            Err(QualificationHostContractError::BindingMismatch)
        );

        other_plan = Ok(QualificationHostPlan {
            binding: QualificationHostBinding {
                fixture_identity: [99; 32],
                ..plan.binding()
            },
            action: QualificationHostAction::TeardownFailure,
        });
        let outcome = QualificationHostOutcome::evaluate(
            plan,
            QualificationHostExecution::Complete(receipt(other_plan.unwrap())),
        );
        assert_eq!(
            outcome.evidence_state,
            QualificationHostEvidenceState::BindingMismatch
        );
        assert_eq!(outcome.receipt(), None);
    }
}
