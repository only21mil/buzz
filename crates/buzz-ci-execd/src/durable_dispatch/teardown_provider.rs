//! Evidence-gated teardown and exact empty-host readback.

use std::path::PathBuf;

use buzz_ci_isolation_contract::ValidatedAttemptLeaseBinding;

use crate::{
    activation::LeaseToken,
    evidence::{
        CiEventBinding, Digest32, OrderingEvent, OrderingRecord, ReconcileRecord, ReconcileState,
        ReconciledResource, TeardownRecord,
    },
    normal_backend::NormalTeardownCollector,
    normal_engine::{NormalJobPlan, NormalReconcileEvidence},
};

use super::{
    crash_recovery::{AttemptEvidenceBinding, RecoveryJournal, RecoveryRecord, RecoveryStage},
    terminal_evidence_collector::workspace_digest,
    ExecutionUnavailable, OrdinaryStop,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TeardownRequest {
    pub binding: AttemptEvidenceBinding,
    pub evidence_set_digest: [u8; 32],
    pub stop: OrdinaryStop,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TeardownReadbackReceipt {
    pub binding_sha256: [u8; 32],
    pub evidence_set_digest: [u8; 32],
    pub teardown_digest: [u8; 32],
    pub lease_unit: String,
    pub cgroup_path: PathBuf,
    pub unit_inactive: bool,
    pub cgroup_procs_empty: bool,
    pub mounts_removed: bool,
    pub dirs_removed: bool,
    pub network_namespace_removed: Option<bool>,
    pub runtime_socket_removed: Option<bool>,
    pub proxy_object_state_removed: Option<bool>,
    pub teardown_at_unix_ns: u64,
    pub published_at_unix_ns: u64,
    pub readback_at_unix_ns: u64,
    pub status_event_id: String,
    pub verdict_event_id: String,
}

/// Host teardown operations. `readback` runs first on every replay, so an
/// already-clean lease never repeats deletion.
pub trait TeardownHost {
    fn readback(
        &mut self,
        request: &TeardownRequest,
    ) -> Result<Option<TeardownReadbackReceipt>, ExecutionUnavailable>;

    fn teardown(&mut self, request: &TeardownRequest) -> Result<(), ExecutionUnavailable>;
}

struct PreparedTeardown {
    run_id: [u8; 16],
    job_id: String,
    attempt: u32,
    host_lease_id: String,
    workspace_sha256: [u8; 32],
    event_binding: CiEventBinding,
    lease_unit: String,
    cgroup_path: PathBuf,
}

pub struct ProductionTeardownProvider<H, J> {
    host: H,
    journal: J,
    prepared: Option<PreparedTeardown>,
}

impl<H, J> ProductionTeardownProvider<H, J> {
    pub fn new(host: H, journal: J) -> Self {
        Self {
            host,
            journal,
            prepared: None,
        }
    }
}

impl<H: TeardownHost, J: RecoveryJournal> NormalTeardownCollector
    for ProductionTeardownProvider<H, J>
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
        self.prepared = Some(PreparedTeardown {
            run_id: *uuid::Uuid::parse_str(&binding.run_id)
                .map_err(|_| ExecutionUnavailable)?
                .as_bytes(),
            job_id: binding.job_id.clone(),
            attempt: binding.attempt,
            host_lease_id: binding.lease_id.clone(),
            workspace_sha256: workspace_digest(binding),
            event_binding: plan.event_binding,
            lease_unit: plan.lease_record.lease_unit.clone(),
            cgroup_path: plan.lease_record.cgroup_path.clone(),
        });
        Ok(())
    }

    fn reconcile(
        &mut self,
        lease: LeaseToken,
        stop: OrdinaryStop,
    ) -> Result<NormalReconcileEvidence, ExecutionUnavailable> {
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
        let record = self
            .journal
            .load(lease.lease_id())?
            .ok_or(ExecutionUnavailable)?;
        if record.binding != binding {
            return Err(ExecutionUnavailable);
        }
        let (conclusion, evidence_set_digest, durable_teardown) = match record.stage {
            RecoveryStage::EvidenceUploaded {
                conclusion,
                evidence_set_digest,
            } => (conclusion, evidence_set_digest, None),
            RecoveryStage::TeardownReadback {
                conclusion,
                evidence_set_digest,
                teardown_digest,
            }
            | RecoveryStage::CapacityReturned {
                conclusion,
                evidence_set_digest,
                teardown_digest,
            } => (conclusion, evidence_set_digest, Some(teardown_digest)),
            RecoveryStage::Active => return Err(ExecutionUnavailable),
        };
        if evidence_set_digest == [0; 32] {
            return Err(ExecutionUnavailable);
        }
        let request = TeardownRequest {
            binding: binding.clone(),
            evidence_set_digest,
            stop,
        };
        let mut receipt = self.host.readback(&request)?;
        if receipt.is_none() {
            if durable_teardown.is_some() {
                return Err(ExecutionUnavailable);
            }
            self.host.teardown(&request)?;
            receipt = self.host.readback(&request)?;
        }
        let receipt = receipt.ok_or(ExecutionUnavailable)?;
        validate_receipt(&receipt, &request, prepared, durable_teardown)?;
        self.journal.advance(RecoveryRecord {
            binding,
            stage: RecoveryStage::TeardownReadback {
                conclusion,
                evidence_set_digest,
                teardown_digest: receipt.teardown_digest,
            },
        })?;
        let evidence = reconcile_evidence(prepared, receipt)?;
        self.prepared = None;
        Ok(evidence)
    }
}

fn validate_receipt(
    receipt: &TeardownReadbackReceipt,
    request: &TeardownRequest,
    prepared: &PreparedTeardown,
    durable_teardown: Option<[u8; 32]>,
) -> Result<(), ExecutionUnavailable> {
    if receipt.binding_sha256 != request.binding.binding_sha256
        || receipt.evidence_set_digest != request.evidence_set_digest
        || receipt.teardown_digest == [0; 32]
        || durable_teardown.is_some_and(|digest| digest != receipt.teardown_digest)
        || receipt.lease_unit != prepared.lease_unit
        || receipt.cgroup_path != prepared.cgroup_path
        || !receipt.unit_inactive
        || !receipt.cgroup_procs_empty
        || !receipt.mounts_removed
        || !receipt.dirs_removed
        || receipt.network_namespace_removed != Some(true)
        || receipt.runtime_socket_removed != Some(true)
        || receipt.proxy_object_state_removed != Some(true)
        || receipt.teardown_at_unix_ns == 0
        || receipt.published_at_unix_ns <= receipt.teardown_at_unix_ns
        || receipt.readback_at_unix_ns <= receipt.published_at_unix_ns
        || !event_id(&receipt.status_event_id)
        || !event_id(&receipt.verdict_event_id)
    {
        return Err(ExecutionUnavailable);
    }
    Ok(())
}

fn event_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn reconcile_evidence(
    prepared: &PreparedTeardown,
    receipt: TeardownReadbackReceipt,
) -> Result<NormalReconcileEvidence, ExecutionUnavailable> {
    let emptied_resources = clean_resources(&receipt).ok_or(ExecutionUnavailable)?;
    let teardown = TeardownRecord {
        lease_id: prepared.host_lease_id.clone(),
        event_binding: prepared.event_binding,
        lease_unit: prepared.lease_unit.clone(),
        cgroup_path: prepared.cgroup_path.clone(),
        unit_inactive: receipt.unit_inactive,
        cgroup_procs_empty: receipt.cgroup_procs_empty,
        mounts_removed: receipt.mounts_removed,
        dirs_removed: receipt.dirs_removed,
        teardown_sha256: Digest32(receipt.teardown_digest),
        completed_at_unix_ns: receipt.teardown_at_unix_ns,
    };
    let reconcile = ReconcileRecord {
        lease_id: prepared.host_lease_id.clone(),
        lease_unit: prepared.lease_unit.clone(),
        cgroup_path: prepared.cgroup_path.clone(),
        state: ReconcileState::Clean,
        emptied: true,
        quarantined: false,
        before_reuse: true,
        emptied_resources,
        quarantined_resources: Vec::new(),
        reuse_allowed: true,
        observed_at_unix_ns: receipt.readback_at_unix_ns,
    };
    let ordering = [
        (
            OrderingEvent::TeardownProof,
            receipt.teardown_at_unix_ns,
            None,
            None,
        ),
        (
            OrderingEvent::Publish,
            receipt.published_at_unix_ns,
            Some(receipt.status_event_id),
            Some(receipt.verdict_event_id),
        ),
        (
            OrderingEvent::Reconcile,
            receipt.readback_at_unix_ns,
            None,
            None,
        ),
    ]
    .into_iter()
    .enumerate()
    .map(
        |(offset, (event, timestamp_unix_ns, status_event_id, verdict_event_id))| OrderingRecord {
            lease_id: prepared.host_lease_id.clone(),
            sequence: 10 + offset as u64,
            event_binding: prepared.event_binding,
            event,
            object_id: None,
            timestamp_unix_ns,
            status_event_id,
            verdict_event_id,
        },
    )
    .collect();
    Ok(NormalReconcileEvidence {
        teardown,
        reconcile,
        ordering,
    })
}

fn clean_resources(receipt: &TeardownReadbackReceipt) -> Option<Vec<ReconciledResource>> {
    (receipt.unit_inactive
        && receipt.cgroup_procs_empty
        && receipt.mounts_removed
        && receipt.dirs_removed
        && receipt.network_namespace_removed == Some(true)
        && receipt.runtime_socket_removed == Some(true)
        && receipt.proxy_object_state_removed == Some(true))
    .then(|| {
        vec![
            ReconciledResource::LeaseUnit,
            ReconciledResource::Cgroup,
            ReconciledResource::Workspace,
            ReconciledResource::NetworkNamespace,
            ReconciledResource::RuntimeSocket,
            ReconciledResource::ProxyObjectState,
        ]
    })
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, rc::Rc};

    use crate::normal_engine::tests::ordinary_fixture;

    use super::*;

    struct FakeHost {
        teardown_calls: Rc<Cell<usize>>,
        receipt: Option<TeardownReadbackReceipt>,
    }

    impl TeardownHost for FakeHost {
        fn readback(
            &mut self,
            _request: &TeardownRequest,
        ) -> Result<Option<TeardownReadbackReceipt>, ExecutionUnavailable> {
            Ok(self.receipt.clone())
        }

        fn teardown(&mut self, _request: &TeardownRequest) -> Result<(), ExecutionUnavailable> {
            self.teardown_calls.set(self.teardown_calls.get() + 1);
            Ok(())
        }
    }

    fn validation_fixture() -> (TeardownRequest, PreparedTeardown, TeardownReadbackReceipt) {
        let mut binding = AttemptEvidenceBinding {
            run_id: [1; 16],
            job_id: "job".into(),
            attempt: 1,
            controller_lease_id: [2; 16],
            lease_generation: 1,
            lease_deadline_at: 10,
            host_lease_id: "lease".into(),
            workspace_sha256: [3; 32],
            binding_sha256: [0; 32],
        };
        binding.binding_sha256 = binding.digest();
        let prepared = PreparedTeardown {
            run_id: binding.run_id,
            job_id: binding.job_id.clone(),
            attempt: binding.attempt,
            host_lease_id: binding.host_lease_id.clone(),
            workspace_sha256: binding.workspace_sha256,
            event_binding: CiEventBinding {
                request_event_id_46105: [4; 32],
                teardown_event_id_46106: [5; 32],
            },
            lease_unit: "lease.service".into(),
            cgroup_path: "/sys/fs/cgroup/lease".into(),
        };
        let request = TeardownRequest {
            binding,
            evidence_set_digest: [7; 32],
            stop: OrdinaryStop::Recovery,
        };
        let receipt = TeardownReadbackReceipt {
            binding_sha256: request.binding.binding_sha256,
            evidence_set_digest: request.evidence_set_digest,
            teardown_digest: [8; 32],
            lease_unit: prepared.lease_unit.clone(),
            cgroup_path: prepared.cgroup_path.clone(),
            unit_inactive: true,
            cgroup_procs_empty: true,
            mounts_removed: true,
            dirs_removed: true,
            network_namespace_removed: Some(true),
            runtime_socket_removed: Some(true),
            proxy_object_state_removed: Some(true),
            teardown_at_unix_ns: 1,
            published_at_unix_ns: 2,
            readback_at_unix_ns: 3,
            status_event_id: "a".repeat(64),
            verdict_event_id: "b".repeat(64),
        };
        (request, prepared, receipt)
    }

    fn assert_readback_rejected(
        network_namespace_removed: Option<bool>,
        runtime_socket_removed: Option<bool>,
        proxy_object_state_removed: Option<bool>,
    ) {
        let (request, prepared, mut receipt) = validation_fixture();
        receipt.network_namespace_removed = network_namespace_removed;
        receipt.runtime_socket_removed = runtime_socket_removed;
        receipt.proxy_object_state_removed = proxy_object_state_removed;
        assert!(validate_receipt(&receipt, &request, &prepared, None).is_err());
        assert!(clean_resources(&receipt).is_none());
    }

    #[test]
    fn network_namespace_requires_present_clean_readback() {
        assert_readback_rejected(None, Some(true), Some(true));
        assert_readback_rejected(Some(false), Some(true), Some(true));
    }

    #[test]
    fn runtime_socket_requires_present_clean_readback() {
        assert_readback_rejected(Some(true), None, Some(true));
        assert_readback_rejected(Some(true), Some(false), Some(true));
    }

    #[test]
    fn proxy_object_state_requires_present_clean_readback() {
        assert_readback_rejected(Some(true), Some(true), None);
        assert_readback_rejected(Some(true), Some(true), Some(false));
    }

    #[test]
    fn complete_authoritative_readback_allows_reuse() {
        let (request, prepared, receipt) = validation_fixture();
        validate_receipt(&receipt, &request, &prepared, None).expect("readback");
        let evidence = reconcile_evidence(&prepared, receipt).expect("reconcile");

        assert_eq!(
            evidence.reconcile.emptied_resources,
            vec![
                ReconciledResource::LeaseUnit,
                ReconciledResource::Cgroup,
                ReconciledResource::Workspace,
                ReconciledResource::NetworkNamespace,
                ReconciledResource::RuntimeSocket,
                ReconciledResource::ProxyObjectState,
            ]
        );
        assert!(evidence.reconcile.reuse_allowed);
    }

    #[test]
    fn active_lease_cannot_trigger_teardown() {
        let fixture = ordinary_fixture();
        let validated = fixture
            .plan
            .binding
            .clone()
            .validate_phase1(&fixture.plan.validation.context())
            .expect("validated");
        let journal = super::super::crash_recovery::MemoryRecoveryJournal::default();
        let calls = Rc::new(Cell::new(0));
        let mut provider = ProductionTeardownProvider::new(
            FakeHost {
                teardown_calls: Rc::clone(&calls),
                receipt: None,
            },
            journal.clone(),
        );
        provider
            .preflight(&fixture.plan, &validated)
            .expect("preflight");
        let binding = validated.as_binding();
        let mut recovery_binding = AttemptEvidenceBinding {
            run_id: fixture.request.run_id,
            job_id: binding.job_id.clone(),
            attempt: binding.attempt,
            controller_lease_id: fixture.lease.lease_id(),
            lease_generation: fixture.lease.generation(),
            lease_deadline_at: fixture.lease.deadline_at(),
            host_lease_id: binding.lease_id.clone(),
            workspace_sha256: workspace_digest(binding),
            binding_sha256: [0; 32],
        };
        recovery_binding.binding_sha256 = recovery_binding.digest();
        journal
            .advance(RecoveryRecord {
                binding: recovery_binding,
                stage: RecoveryStage::Active,
            })
            .expect("active");
        assert!(provider
            .reconcile(fixture.lease, OrdinaryStop::Recovery)
            .is_err());
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn successful_teardown_releases_prepared_binding_for_next_attempt() {
        let first = ordinary_fixture();
        let first_validated = first
            .plan
            .binding
            .clone()
            .validate_phase1(&first.plan.validation.context())
            .expect("first binding");
        let binding = first_validated.as_binding();
        let mut recovery_binding = AttemptEvidenceBinding {
            run_id: first.request.run_id,
            job_id: binding.job_id.clone(),
            attempt: binding.attempt,
            controller_lease_id: first.lease.lease_id(),
            lease_generation: first.lease.generation(),
            lease_deadline_at: first.lease.deadline_at(),
            host_lease_id: binding.lease_id.clone(),
            workspace_sha256: workspace_digest(binding),
            binding_sha256: [0; 32],
        };
        recovery_binding.binding_sha256 = recovery_binding.digest();
        let journal = super::super::crash_recovery::MemoryRecoveryJournal::default();
        journal
            .advance(RecoveryRecord {
                binding: recovery_binding.clone(),
                stage: RecoveryStage::Active,
            })
            .expect("active");
        journal
            .advance(RecoveryRecord {
                binding: recovery_binding.clone(),
                stage: RecoveryStage::EvidenceUploaded {
                    conclusion: crate::activation::LeaseConclusion::Success,
                    evidence_set_digest: [7; 32],
                },
            })
            .expect("evidence uploaded");
        let mut provider = ProductionTeardownProvider::new(
            FakeHost {
                teardown_calls: Rc::new(Cell::new(0)),
                receipt: Some(TeardownReadbackReceipt {
                    binding_sha256: recovery_binding.binding_sha256,
                    evidence_set_digest: [7; 32],
                    teardown_digest: [8; 32],
                    lease_unit: first.plan.lease_record.lease_unit.clone(),
                    cgroup_path: first.plan.lease_record.cgroup_path.clone(),
                    unit_inactive: true,
                    cgroup_procs_empty: true,
                    mounts_removed: true,
                    dirs_removed: true,
                    network_namespace_removed: Some(true),
                    runtime_socket_removed: Some(true),
                    proxy_object_state_removed: Some(true),
                    teardown_at_unix_ns: 1,
                    published_at_unix_ns: 2,
                    readback_at_unix_ns: 3,
                    status_event_id: "a".repeat(64),
                    verdict_event_id: "b".repeat(64),
                }),
            },
            journal,
        );
        provider
            .preflight(&first.plan, &first_validated)
            .expect("first preflight");
        provider
            .reconcile(first.lease, OrdinaryStop::Recovery)
            .expect("first teardown");
        assert!(provider.prepared.is_none());

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
        provider
            .preflight(&second.plan, &second_validated)
            .expect("second preflight");
    }
}
