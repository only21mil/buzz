//! Exact terminal evidence collection after the executor stops.

use sha2::{Digest, Sha256};

use buzz_ci_isolation_contract::ValidatedAttemptLeaseBinding;

use crate::{
    activation::{LeaseConclusion, LeaseToken},
    evidence::{CiEventBinding, OrderingEvent, OrderingRecord},
    normal_backend::NormalTerminalCollector,
    normal_engine::{NormalJobPlan, NormalTerminalEvidence},
};

use super::{
    crash_recovery::{AttemptEvidenceBinding, RecoveryJournal, RecoveryRecord, RecoveryStage},
    ExecutionUnavailable,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalStage {
    Stop,
    FinalizeRawStream,
    Extract,
    Scrub,
    Scan,
    Hash,
    Upload,
}

impl TerminalStage {
    const ALL: [Self; 7] = [
        Self::Stop,
        Self::FinalizeRawStream,
        Self::Extract,
        Self::Scrub,
        Self::Scan,
        Self::Hash,
        Self::Upload,
    ];

    const fn ordering(self) -> OrderingEvent {
        match self {
            Self::Stop => OrderingEvent::Stop,
            Self::FinalizeRawStream => OrderingEvent::FinalizeRawStream,
            Self::Extract => OrderingEvent::Extract,
            Self::Scrub => OrderingEvent::Scrub,
            Self::Scan => OrderingEvent::Scan,
            Self::Hash => OrderingEvent::Hash,
            Self::Upload => OrderingEvent::Upload,
        }
    }
}

/// Exact idempotency request for one collection stage. Host implementations
/// must return the same receipt when this request is replayed after a crash.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalStageRequest {
    pub binding: AttemptEvidenceBinding,
    pub stage: TerminalStage,
    pub input_sha256: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TerminalStageReceipt {
    pub binding_sha256: [u8; 32],
    pub stage: TerminalStage,
    pub input_sha256: [u8; 32],
    pub output_sha256: [u8; 32],
    pub observed_at_unix_ns: u64,
    pub conclusion: Option<LeaseConclusion>,
}

/// Root-owned, secret-free host operations. Receipt errors are opaque so a
/// credential, log line, or artifact body cannot enter broker output.
pub trait TerminalEvidenceHost {
    fn run_stage(
        &mut self,
        request: &TerminalStageRequest,
    ) -> Result<TerminalStageReceipt, ExecutionUnavailable>;
}

struct PreparedTerminal {
    run_id: [u8; 16],
    job_id: String,
    attempt: u32,
    host_lease_id: String,
    workspace_sha256: [u8; 32],
    event_binding: CiEventBinding,
}

pub struct ProductionTerminalEvidenceCollector<H, J> {
    host: H,
    journal: J,
    prepared: Option<PreparedTerminal>,
}

impl<H, J> ProductionTerminalEvidenceCollector<H, J> {
    pub fn new(host: H, journal: J) -> Self {
        Self {
            host,
            journal,
            prepared: None,
        }
    }
}

impl<H: TerminalEvidenceHost, J: RecoveryJournal> NormalTerminalCollector
    for ProductionTerminalEvidenceCollector<H, J>
{
    fn preflight(
        &mut self,
        plan: &NormalJobPlan,
        validated: &ValidatedAttemptLeaseBinding,
    ) -> Result<(), ExecutionUnavailable> {
        if self.prepared.is_some() || validated.as_binding() != &plan.binding {
            return Err(ExecutionUnavailable);
        }
        let binding = validated.as_binding();
        let run_id = *uuid::Uuid::parse_str(&binding.run_id)
            .map_err(|_| ExecutionUnavailable)?
            .as_bytes();
        let workspace_sha256 = workspace_digest(binding);
        if workspace_sha256 == [0; 32]
            || binding.job_id != plan.act.job_id
            || binding.lease_id != plan.lease_record.lease_id
        {
            return Err(ExecutionUnavailable);
        }
        self.prepared = Some(PreparedTerminal {
            run_id,
            job_id: binding.job_id.clone(),
            attempt: binding.attempt,
            host_lease_id: binding.lease_id.clone(),
            workspace_sha256,
            event_binding: plan.event_binding,
        });
        Ok(())
    }

    fn collect(
        &mut self,
        lease: LeaseToken,
    ) -> Result<NormalTerminalEvidence, ExecutionUnavailable> {
        let prepared = self.prepared.as_ref().ok_or(ExecutionUnavailable)?;
        if prepared.run_id != lease.run_id() || prepared.attempt != lease.attempt() {
            return Err(ExecutionUnavailable);
        }
        let mut binding = AttemptEvidenceBinding {
            run_id: prepared.run_id,
            job_id: prepared.job_id.clone(),
            attempt: prepared.attempt,
            controller_lease_id: lease.lease_id(),
            lease_generation: lease.generation(),
            lease_deadline_at: lease.deadline_at(),
            host_lease_id: prepared.host_lease_id.clone(),
            workspace_sha256: prepared.workspace_sha256,
            binding_sha256: [0; 32],
        };
        binding.binding_sha256 = binding.digest();
        self.journal.advance(RecoveryRecord {
            binding: binding.clone(),
            stage: RecoveryStage::Active,
        })?;

        let mut input_sha256 = binding.binding_sha256;
        let mut previous_timestamp = 0;
        let mut conclusion = None;
        let mut ordering = Vec::with_capacity(TerminalStage::ALL.len());
        for (offset, stage) in TerminalStage::ALL.into_iter().enumerate() {
            let request = TerminalStageRequest {
                binding: binding.clone(),
                stage,
                input_sha256,
            };
            let receipt = self.host.run_stage(&request)?;
            if receipt.binding_sha256 != binding.binding_sha256
                || receipt.stage != stage
                || receipt.input_sha256 != input_sha256
                || receipt.output_sha256 == [0; 32]
                || receipt.observed_at_unix_ns <= previous_timestamp
                || (stage == TerminalStage::Stop) != receipt.conclusion.is_some()
            {
                return Err(ExecutionUnavailable);
            }
            if stage == TerminalStage::Stop {
                conclusion = receipt.conclusion;
            }
            previous_timestamp = receipt.observed_at_unix_ns;
            input_sha256 = receipt.output_sha256;
            ordering.push(OrderingRecord {
                lease_id: binding.host_lease_id.clone(),
                sequence: 3 + offset as u64,
                event_binding: prepared.event_binding,
                event: stage.ordering(),
                object_id: None,
                timestamp_unix_ns: receipt.observed_at_unix_ns,
                status_event_id: None,
                verdict_event_id: None,
            });
        }
        let conclusion = conclusion.ok_or(ExecutionUnavailable)?;
        self.journal.advance(RecoveryRecord {
            binding,
            stage: RecoveryStage::EvidenceUploaded {
                conclusion,
                evidence_set_digest: input_sha256,
            },
        })?;
        self.prepared = None;
        Ok(NormalTerminalEvidence {
            conclusion,
            evidence_set_digest: input_sha256,
            ordering,
        })
    }
}

pub(crate) fn workspace_digest(
    binding: &buzz_ci_isolation_contract::AttemptLeaseBinding,
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"buzz-ci-workspace-binding-v1\0");
    update_text(&mut hash, &binding.workspace.path);
    hash.update(binding.workspace.object.device.to_be_bytes());
    hash.update(binding.workspace.object.inode.to_be_bytes());
    update_text(&mut hash, &binding.workspace.object.token);
    update_text(&mut hash, &binding.workspace.quota_token);
    hash.finalize().into()
}

fn update_text(hash: &mut Sha256, value: &str) {
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value.as_bytes());
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, rc::Rc};

    use super::*;

    #[derive(Clone)]
    struct ReplayHost {
        calls: Rc<RefCell<Vec<TerminalStage>>>,
        fail_at: Option<TerminalStage>,
    }

    impl TerminalEvidenceHost for ReplayHost {
        fn run_stage(
            &mut self,
            request: &TerminalStageRequest,
        ) -> Result<TerminalStageReceipt, ExecutionUnavailable> {
            self.calls.borrow_mut().push(request.stage);
            if self.fail_at == Some(request.stage) {
                return Err(ExecutionUnavailable);
            }
            let index = TerminalStage::ALL
                .iter()
                .position(|stage| *stage == request.stage)
                .ok_or(ExecutionUnavailable)?;
            Ok(TerminalStageReceipt {
                binding_sha256: request.binding.binding_sha256,
                stage: request.stage,
                input_sha256: request.input_sha256,
                output_sha256: [10 + index as u8; 32],
                observed_at_unix_ns: 100 + index as u64,
                conclusion: (request.stage == TerminalStage::Stop)
                    .then_some(LeaseConclusion::Success),
            })
        }
    }

    #[test]
    fn stage_contract_is_strict_and_secret_free() {
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
        let request = TerminalStageRequest {
            binding,
            stage: TerminalStage::Scrub,
            input_sha256: [7; 32],
        };
        let debug = format!("{request:?}");
        assert!(!debug.to_ascii_lowercase().contains("secret"));
        assert!(!debug.contains("token="));
    }

    #[test]
    fn crash_cutpoint_stops_before_later_stages() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let mut host = ReplayHost {
            calls: Rc::clone(&calls),
            fail_at: Some(TerminalStage::Scan),
        };
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
        let mut input = binding.binding_sha256;
        for stage in TerminalStage::ALL {
            let request = TerminalStageRequest {
                binding: binding.clone(),
                stage,
                input_sha256: input,
            };
            let result = host.run_stage(&request);
            if stage == TerminalStage::Scan {
                assert!(result.is_err());
                break;
            }
            input = result.expect("receipt").output_sha256;
        }
        assert_eq!(calls.borrow().as_slice(), &TerminalStage::ALL[..=4]);
    }

    #[test]
    fn collector_recovers_from_every_stage_cutpoint_with_exact_replay() {
        use crate::normal_engine::tests::ordinary_fixture;

        for failed_stage in TerminalStage::ALL {
            let fixture = ordinary_fixture();
            let validated = fixture
                .plan
                .binding
                .clone()
                .validate_phase1(&fixture.plan.validation.context())
                .expect("validated");
            let journal = super::super::crash_recovery::MemoryRecoveryJournal::default();
            let calls = Rc::new(RefCell::new(Vec::new()));
            let mut failed = ProductionTerminalEvidenceCollector::new(
                ReplayHost {
                    calls: Rc::clone(&calls),
                    fail_at: Some(failed_stage),
                },
                journal.clone(),
            );
            failed
                .preflight(&fixture.plan, &validated)
                .expect("preflight");
            assert!(failed.collect(fixture.lease).is_err());
            assert_eq!(
                calls.borrow().len(),
                TerminalStage::ALL
                    .iter()
                    .position(|stage| *stage == failed_stage)
                    .expect("stage")
                    + 1
            );

            calls.borrow_mut().clear();
            let mut recovered = ProductionTerminalEvidenceCollector::new(
                ReplayHost {
                    calls: Rc::clone(&calls),
                    fail_at: None,
                },
                journal.clone(),
            );
            recovered
                .preflight(&fixture.plan, &validated)
                .expect("recovery preflight");
            let evidence = recovered.collect(fixture.lease).expect("recovered");
            assert_eq!(evidence.evidence_set_digest, [16; 32]);
            assert_eq!(calls.borrow().as_slice(), TerminalStage::ALL);
            assert!(matches!(
                journal
                    .load(fixture.lease.lease_id())
                    .expect("journal")
                    .expect("record")
                    .stage,
                RecoveryStage::EvidenceUploaded { .. }
            ));
        }
    }

    #[test]
    fn successful_collection_releases_prepared_binding_for_next_attempt() {
        use crate::normal_engine::tests::ordinary_fixture;

        let first = ordinary_fixture();
        let first_validated = first
            .plan
            .binding
            .clone()
            .validate_phase1(&first.plan.validation.context())
            .expect("first binding");
        let journal = super::super::crash_recovery::MemoryRecoveryJournal::default();
        let mut collector = ProductionTerminalEvidenceCollector::new(
            ReplayHost {
                calls: Rc::new(RefCell::new(Vec::new())),
                fail_at: None,
            },
            journal,
        );
        collector
            .preflight(&first.plan, &first_validated)
            .expect("first preflight");
        collector.collect(first.lease).expect("first collection");
        assert!(collector.prepared.is_none());

        let mut second = ordinary_fixture();
        second.plan.binding.run_id = uuid::Uuid::from_bytes([14; 16]).to_string();
        second.plan.binding.attempt += 1;
        second.plan.binding.lease_id = "01ARZ3NDEKTSV4RRFFQ69G5FAW".into();
        second.plan.lease_record.lease_id = second.plan.binding.lease_id.clone();
        let second_validated = second
            .plan
            .binding
            .clone()
            .validate_phase1(&second.plan.validation.context())
            .expect("second binding");
        collector
            .preflight(&second.plan, &second_validated)
            .expect("second preflight");
    }
}
