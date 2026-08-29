//! Crash-safe ordinary lease coordination.
//!
//! The coordinator never invents evidence. Terminal and teardown providers
//! advance the journal, while this wrapper refuses cleanup until the exact
//! lease has a durable, nonzero evidence digest.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use buzz_ci_broker_protocol::AdmitAttemptRequest;
use sha2::{Digest, Sha256};

use crate::activation::{CleanupDisposition, LeaseConclusion, LeaseToken, OrdinaryAdmission};

use super::{
    ExecutionUnavailable, OrdinaryCleanup, OrdinaryExecutor, OrdinaryReceipts, OrdinaryStop,
};

/// Full non-secret identity shared by collection, teardown, and recovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptEvidenceBinding {
    pub run_id: [u8; 16],
    pub job_id: String,
    pub attempt: u32,
    pub controller_lease_id: [u8; 16],
    pub lease_generation: u64,
    pub lease_deadline_at: u64,
    pub host_lease_id: String,
    pub workspace_sha256: [u8; 32],
    pub binding_sha256: [u8; 32],
}

impl AttemptEvidenceBinding {
    pub fn digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"buzz-ci-terminal-binding-v1\0");
        hash.update(self.run_id);
        update_text(&mut hash, &self.job_id);
        hash.update(self.attempt.to_be_bytes());
        hash.update(self.controller_lease_id);
        hash.update(self.lease_generation.to_be_bytes());
        hash.update(self.lease_deadline_at.to_be_bytes());
        update_text(&mut hash, &self.host_lease_id);
        hash.update(self.workspace_sha256);
        hash.finalize().into()
    }

    pub fn matches(
        &self,
        request: AdmitAttemptRequest,
        admission: OrdinaryAdmission,
        lease: LeaseToken,
    ) -> bool {
        self.run_id == request.run_id
            && self.run_id == admission.run_id
            && self.run_id == lease.run_id()
            && self.attempt == request.attempt
            && self.attempt == admission.attempt
            && self.attempt == lease.attempt()
            && self.controller_lease_id == admission.lease_id
            && self.controller_lease_id == lease.lease_id()
            && self.lease_generation == lease.generation()
            && self.lease_deadline_at == lease.deadline_at()
            && self.workspace_sha256 != [0; 32]
            && self.binding_sha256 != [0; 32]
            && !self.job_id.is_empty()
            && !self.host_lease_id.is_empty()
    }
}

/// Last durable recovery fact for one exact controller lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryStage {
    Active,
    EvidenceUploaded {
        conclusion: LeaseConclusion,
        evidence_set_digest: [u8; 32],
    },
    TeardownReadback {
        conclusion: LeaseConclusion,
        evidence_set_digest: [u8; 32],
        teardown_digest: [u8; 32],
    },
    CapacityReturned {
        conclusion: LeaseConclusion,
        evidence_set_digest: [u8; 32],
        teardown_digest: [u8; 32],
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryRecord {
    pub binding: AttemptEvidenceBinding,
    pub stage: RecoveryStage,
}

/// Durable journal contract. Implementations must make `advance` atomic and
/// accept exact replay without replacing a conflicting fact.
pub trait RecoveryJournal {
    fn load(
        &self,
        controller_lease_id: [u8; 16],
    ) -> Result<Option<RecoveryRecord>, ExecutionUnavailable>;

    fn advance(&self, record: RecoveryRecord) -> Result<(), ExecutionUnavailable>;
}

/// Deterministic journal used by host-composition tests.
#[derive(Clone, Default)]
pub struct MemoryRecoveryJournal {
    records: Arc<Mutex<BTreeMap<[u8; 16], RecoveryRecord>>>,
}

impl RecoveryJournal for MemoryRecoveryJournal {
    fn load(
        &self,
        controller_lease_id: [u8; 16],
    ) -> Result<Option<RecoveryRecord>, ExecutionUnavailable> {
        self.records
            .lock()
            .map_err(|_| ExecutionUnavailable)
            .map(|records| records.get(&controller_lease_id).cloned())
    }

    fn advance(&self, record: RecoveryRecord) -> Result<(), ExecutionUnavailable> {
        if record.binding.controller_lease_id == [0; 16]
            || record.binding.binding_sha256 == [0; 32]
            || record.binding.workspace_sha256 == [0; 32]
            || record.binding.digest() != record.binding.binding_sha256
        {
            return Err(ExecutionUnavailable);
        }
        let mut records = self.records.lock().map_err(|_| ExecutionUnavailable)?;
        match records.get(&record.binding.controller_lease_id) {
            None if record.stage == RecoveryStage::Active => {
                records.insert(record.binding.controller_lease_id, record);
                Ok(())
            }
            Some(existing) if existing == &record => Ok(()),
            Some(existing)
                if existing.binding == record.binding
                    && valid_transition(existing.stage, record.stage) =>
            {
                records.insert(record.binding.controller_lease_id, record);
                Ok(())
            }
            _ => Err(ExecutionUnavailable),
        }
    }
}

fn update_text(hash: &mut Sha256, value: &str) {
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value.as_bytes());
}

fn valid_transition(previous: RecoveryStage, next: RecoveryStage) -> bool {
    matches!(
        (previous, next),
        (
            RecoveryStage::Active,
            RecoveryStage::EvidenceUploaded {
                evidence_set_digest,
                ..
            }
        ) if evidence_set_digest != [0; 32]
    ) || matches!(
        (previous, next),
        (
            RecoveryStage::EvidenceUploaded {
                conclusion: left_conclusion,
                evidence_set_digest: left_evidence,
            },
            RecoveryStage::TeardownReadback {
                conclusion: right_conclusion,
                evidence_set_digest: right_evidence,
                teardown_digest,
            }
        ) if left_conclusion == right_conclusion
            && left_evidence == right_evidence
            && teardown_digest != [0; 32]
    ) || matches!(
        (previous, next),
        (
            RecoveryStage::TeardownReadback {
                conclusion: left_conclusion,
                evidence_set_digest: left_evidence,
                teardown_digest: left_teardown,
            },
            RecoveryStage::CapacityReturned {
                conclusion: right_conclusion,
                evidence_set_digest: right_evidence,
                teardown_digest: right_teardown,
            }
        ) if left_conclusion == right_conclusion
            && left_evidence == right_evidence
            && left_teardown == right_teardown
    )
}

fn receipts(stage: RecoveryStage) -> Option<OrdinaryReceipts> {
    match stage {
        RecoveryStage::EvidenceUploaded {
            conclusion,
            evidence_set_digest,
        }
        | RecoveryStage::TeardownReadback {
            conclusion,
            evidence_set_digest,
            ..
        }
        | RecoveryStage::CapacityReturned {
            conclusion,
            evidence_set_digest,
            ..
        } => Some(OrdinaryReceipts {
            conclusion,
            evidence_set_digest,
        }),
        RecoveryStage::Active => None,
    }
}

fn cleanup(stage: RecoveryStage) -> Option<OrdinaryCleanup> {
    match stage {
        RecoveryStage::TeardownReadback {
            teardown_digest, ..
        }
        | RecoveryStage::CapacityReturned {
            teardown_digest, ..
        } => Some(OrdinaryCleanup {
            disposition: CleanupDisposition::Clean,
            teardown_digest,
        }),
        _ => None,
    }
}

/// Wrapper that makes evidence and teardown replay authoritative across a
/// dispatcher restart.
pub struct CrashRecoveryCoordinator<O, J> {
    inner: O,
    journal: J,
}

impl<O, J> CrashRecoveryCoordinator<O, J> {
    pub fn new(inner: O, journal: J) -> Self {
        Self { inner, journal }
    }
}

impl<O: OrdinaryExecutor, J: RecoveryJournal> OrdinaryExecutor for CrashRecoveryCoordinator<O, J> {
    fn preflight(
        &mut self,
        request: AdmitAttemptRequest,
        admission: OrdinaryAdmission,
    ) -> Result<(), ExecutionUnavailable> {
        self.inner.preflight(request, admission)
    }

    fn provision(
        &mut self,
        request: AdmitAttemptRequest,
        admission: OrdinaryAdmission,
        lease: LeaseToken,
    ) -> Result<(), ExecutionUnavailable> {
        self.inner.provision(request, admission, lease)
    }

    fn read_receipts(
        &mut self,
        request: AdmitAttemptRequest,
        admission: OrdinaryAdmission,
        lease: LeaseToken,
    ) -> Result<OrdinaryReceipts, ExecutionUnavailable> {
        if let Some(record) = self.journal.load(lease.lease_id())? {
            if !record.binding.matches(request, admission, lease) {
                return Err(ExecutionUnavailable);
            }
            if let Some(receipts) = receipts(record.stage) {
                return Ok(receipts);
            }
        }
        let result = self.inner.read_receipts(request, admission, lease)?;
        let record = self
            .journal
            .load(lease.lease_id())?
            .ok_or(ExecutionUnavailable)?;
        if !record.binding.matches(request, admission, lease)
            || receipts(record.stage) != Some(result)
        {
            return Err(ExecutionUnavailable);
        }
        Ok(result)
    }

    fn reconcile(
        &mut self,
        request: AdmitAttemptRequest,
        admission: OrdinaryAdmission,
        lease: LeaseToken,
        stop: OrdinaryStop,
    ) -> Result<OrdinaryCleanup, ExecutionUnavailable> {
        let record = self
            .journal
            .load(lease.lease_id())?
            .ok_or(ExecutionUnavailable)?;
        if !record.binding.matches(request, admission, lease) || receipts(record.stage).is_none() {
            return Err(ExecutionUnavailable);
        }
        if let Some(cleanup) = cleanup(record.stage) {
            return Ok(cleanup);
        }
        let result = self.inner.reconcile(request, admission, lease, stop)?;
        let durable = self
            .journal
            .load(lease.lease_id())?
            .and_then(|record| cleanup(record.stage))
            .ok_or(ExecutionUnavailable)?;
        (result == durable)
            .then_some(result)
            .ok_or(ExecutionUnavailable)
    }

    fn capacity_returned(
        &mut self,
        request: AdmitAttemptRequest,
        admission: OrdinaryAdmission,
        lease: LeaseToken,
        teardown_digest: [u8; 32],
    ) -> Result<(), ExecutionUnavailable> {
        let record = self
            .journal
            .load(lease.lease_id())?
            .ok_or(ExecutionUnavailable)?;
        if !record.binding.matches(request, admission, lease) {
            return Err(ExecutionUnavailable);
        }
        if let RecoveryStage::CapacityReturned {
            teardown_digest: durable_teardown,
            ..
        } = record.stage
        {
            return (durable_teardown == teardown_digest)
                .then_some(())
                .ok_or(ExecutionUnavailable);
        }
        self.inner
            .capacity_returned(request, admission, lease, teardown_digest)?;
        let RecoveryStage::TeardownReadback {
            conclusion,
            evidence_set_digest,
            teardown_digest: durable_teardown,
        } = record.stage
        else {
            return matches!(record.stage, RecoveryStage::CapacityReturned { .. })
                .then_some(())
                .ok_or(ExecutionUnavailable);
        };
        if durable_teardown != teardown_digest {
            return Err(ExecutionUnavailable);
        }
        self.journal.advance(RecoveryRecord {
            binding: record.binding,
            stage: RecoveryStage::CapacityReturned {
                conclusion,
                evidence_set_digest,
                teardown_digest,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, rc::Rc};

    use crate::normal_engine::tests::ordinary_fixture;

    use super::*;

    fn binding() -> AttemptEvidenceBinding {
        let mut binding = AttemptEvidenceBinding {
            run_id: [1; 16],
            job_id: "test".into(),
            attempt: 1,
            controller_lease_id: [2; 16],
            lease_generation: 1,
            lease_deadline_at: 10,
            host_lease_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            workspace_sha256: [3; 32],
            binding_sha256: [0; 32],
        };
        binding.binding_sha256 = binding.digest();
        binding
    }

    #[test]
    fn journal_rejects_teardown_before_evidence_and_conflicting_replay() {
        let journal = MemoryRecoveryJournal::default();
        journal
            .advance(RecoveryRecord {
                binding: binding(),
                stage: RecoveryStage::Active,
            })
            .expect("active");
        assert!(journal
            .advance(RecoveryRecord {
                binding: binding(),
                stage: RecoveryStage::TeardownReadback {
                    conclusion: LeaseConclusion::Success,
                    evidence_set_digest: [7; 32],
                    teardown_digest: [8; 32],
                },
            })
            .is_err());
        journal
            .advance(RecoveryRecord {
                binding: binding(),
                stage: RecoveryStage::EvidenceUploaded {
                    conclusion: LeaseConclusion::Success,
                    evidence_set_digest: [7; 32],
                },
            })
            .expect("evidence");
        assert!(journal
            .advance(RecoveryRecord {
                binding: binding(),
                stage: RecoveryStage::EvidenceUploaded {
                    conclusion: LeaseConclusion::Success,
                    evidence_set_digest: [9; 32],
                },
            })
            .is_err());
    }

    #[test]
    fn every_exact_transition_is_idempotent() {
        let journal = MemoryRecoveryJournal::default();
        let stages = [
            RecoveryStage::Active,
            RecoveryStage::EvidenceUploaded {
                conclusion: LeaseConclusion::Failure,
                evidence_set_digest: [7; 32],
            },
            RecoveryStage::TeardownReadback {
                conclusion: LeaseConclusion::Failure,
                evidence_set_digest: [7; 32],
                teardown_digest: [8; 32],
            },
            RecoveryStage::CapacityReturned {
                conclusion: LeaseConclusion::Failure,
                evidence_set_digest: [7; 32],
                teardown_digest: [8; 32],
            },
        ];
        for stage in stages {
            let record = RecoveryRecord {
                binding: binding(),
                stage,
            };
            journal.advance(record.clone()).expect("advance");
            journal.advance(record).expect("exact replay");
        }
    }

    struct FakeExecutor {
        calls: Rc<RefCell<Vec<&'static str>>>,
        journal: MemoryRecoveryJournal,
        binding: AttemptEvidenceBinding,
    }

    impl OrdinaryExecutor for FakeExecutor {
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
            Ok(())
        }

        fn read_receipts(
            &mut self,
            _request: AdmitAttemptRequest,
            _admission: OrdinaryAdmission,
            _lease: LeaseToken,
        ) -> Result<OrdinaryReceipts, ExecutionUnavailable> {
            self.calls.borrow_mut().push("evidence");
            Err(ExecutionUnavailable)
        }

        fn reconcile(
            &mut self,
            _request: AdmitAttemptRequest,
            _admission: OrdinaryAdmission,
            _lease: LeaseToken,
            _stop: OrdinaryStop,
        ) -> Result<OrdinaryCleanup, ExecutionUnavailable> {
            self.calls.borrow_mut().push("teardown");
            self.journal.advance(RecoveryRecord {
                binding: self.binding.clone(),
                stage: RecoveryStage::TeardownReadback {
                    conclusion: LeaseConclusion::Failure,
                    evidence_set_digest: [7; 32],
                    teardown_digest: [8; 32],
                },
            })?;
            Ok(OrdinaryCleanup {
                disposition: CleanupDisposition::Clean,
                teardown_digest: [8; 32],
            })
        }

        fn capacity_returned(
            &mut self,
            _request: AdmitAttemptRequest,
            _admission: OrdinaryAdmission,
            _lease: LeaseToken,
            _teardown_digest: [u8; 32],
        ) -> Result<(), ExecutionUnavailable> {
            self.calls.borrow_mut().push("capacity");
            Ok(())
        }
    }

    fn fixture_binding() -> (
        crate::normal_engine::tests::OrdinaryFixture,
        AttemptEvidenceBinding,
    ) {
        let fixture = ordinary_fixture();
        let binding = fixture.plan.binding.clone();
        let workspace_sha256 =
            super::super::terminal_evidence_collector::workspace_digest(&binding);
        let mut recovery = AttemptEvidenceBinding {
            run_id: fixture.request.run_id,
            job_id: binding.job_id,
            attempt: fixture.request.attempt,
            controller_lease_id: fixture.lease.lease_id(),
            lease_generation: fixture.lease.generation(),
            lease_deadline_at: fixture.lease.deadline_at(),
            host_lease_id: binding.lease_id,
            workspace_sha256,
            binding_sha256: [0; 32],
        };
        recovery.binding_sha256 = recovery.digest();
        (fixture, recovery)
    }

    #[test]
    fn coordinator_never_tears_down_active_evidence() {
        let (fixture, binding) = fixture_binding();
        let journal = MemoryRecoveryJournal::default();
        journal
            .advance(RecoveryRecord {
                binding: binding.clone(),
                stage: RecoveryStage::Active,
            })
            .expect("active");
        let calls = Rc::new(RefCell::new(Vec::new()));
        let inner = FakeExecutor {
            calls: Rc::clone(&calls),
            journal: journal.clone(),
            binding,
        };
        let mut coordinator = CrashRecoveryCoordinator::new(inner, journal);
        assert!(coordinator
            .reconcile(
                fixture.request,
                fixture.admission,
                fixture.lease,
                OrdinaryStop::Recovery,
            )
            .is_err());
        assert!(calls.borrow().is_empty());
    }

    #[test]
    fn recovery_returns_capacity_only_after_evidence_and_teardown_readback() {
        let (fixture, binding) = fixture_binding();
        let journal = MemoryRecoveryJournal::default();
        journal
            .advance(RecoveryRecord {
                binding: binding.clone(),
                stage: RecoveryStage::Active,
            })
            .expect("active");
        journal
            .advance(RecoveryRecord {
                binding: binding.clone(),
                stage: RecoveryStage::EvidenceUploaded {
                    conclusion: LeaseConclusion::Failure,
                    evidence_set_digest: [7; 32],
                },
            })
            .expect("evidence");
        let calls = Rc::new(RefCell::new(Vec::new()));
        let inner = FakeExecutor {
            calls: Rc::clone(&calls),
            journal: journal.clone(),
            binding,
        };
        let mut coordinator = CrashRecoveryCoordinator::new(inner, journal.clone());
        assert_eq!(
            coordinator
                .read_receipts(fixture.request, fixture.admission, fixture.lease)
                .expect("durable receipts")
                .evidence_set_digest,
            [7; 32]
        );
        let cleanup = coordinator
            .reconcile(
                fixture.request,
                fixture.admission,
                fixture.lease,
                OrdinaryStop::Recovery,
            )
            .expect("teardown");
        coordinator
            .capacity_returned(
                fixture.request,
                fixture.admission,
                fixture.lease,
                cleanup.teardown_digest,
            )
            .expect("capacity");
        coordinator
            .capacity_returned(
                fixture.request,
                fixture.admission,
                fixture.lease,
                cleanup.teardown_digest,
            )
            .expect("idempotent replay");
        assert_eq!(calls.borrow().as_slice(), &["teardown", "capacity"]);
        assert!(matches!(
            journal
                .load(fixture.lease.lease_id())
                .expect("journal")
                .expect("record")
                .stage,
            RecoveryStage::CapacityReturned { .. }
        ));
    }
}
