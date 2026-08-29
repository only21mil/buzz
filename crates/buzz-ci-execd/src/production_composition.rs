//! Production-only composition of durable dispatch and privileged host adapters.
//!
//! The composition is deliberately closed until every privileged backend is
//! linked. Partial discovery never falls through to an executor with weaker
//! facts, and tests inject typed fakes without running host commands.

use buzz_ci_broker_protocol::{
    AdmitAttemptRequest, BrokerResponse, FrameHeader, QualificationRequest, Request,
};

use crate::{
    activation::{LeaseToken, OrdinaryAdmission, QualificationLease},
    control::{ClosedDispatch, ControlDispatch},
    durable_dispatch::{
        load_dispatch, BootstrapDispatch, ExecutionUnavailable, OrdinaryCleanup, OrdinaryExecutor,
        OrdinaryReceipts, OrdinaryStop, QualificationCleanup, QualificationExecution,
        QualificationExecutor, QualificationStop, ReadyHostProofs, ReadyValidationProvider,
    },
    host_composition::HostCompositionContract,
    normal_backend::{
        materialization_input::MaterializationInputProvider,
        proxy_input::{BoundPrestartPersister, ProxyInputProvider},
        BrokerProxyRuntime, MediatedActThroughProxyLauncher, RuntimeDescriptorProvider,
    },
    runtime::ReadyValidationTarget,
};

/// Lease-scoped host provider that is not yet linked into canonical startup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostBackendSeam {
    ExecutorUnitHandoff,
    RuntimeDescriptorProvider,
    MaterializationInputProvider,
    ProxyInputAndLeaseProvider,
    TerminalEvidenceCollector,
    TeardownProvider,
    CrashRecoveryCoordinator,
}

/// Exact ordinary provider inventory that canonical startup still requires.
pub const MISSING_ORDINARY_HOST_SEAMS: [HostBackendSeam; 7] = [
    HostBackendSeam::ExecutorUnitHandoff,
    HostBackendSeam::RuntimeDescriptorProvider,
    HostBackendSeam::MaterializationInputProvider,
    HostBackendSeam::ProxyInputAndLeaseProvider,
    HostBackendSeam::TerminalEvidenceCollector,
    HostBackendSeam::TeardownProvider,
    HostBackendSeam::CrashRecoveryCoordinator,
];

/// Why production remains closed before authority/state loading.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductionCompositionError {
    /// Root-authored host composition is absent, partial, or malformed.
    HostContractUnavailable,
    /// Lease-scoped providers are absent even though the static contract loaded.
    HostBackendsMissing(&'static [HostBackendSeam]),
}

/// Concrete PR112/PR113 input consumers bound to one descriptor sequence.
///
/// This composition deliberately does not author the root-owned input records,
/// create the lease-scoped materializer observer, or provide reconciliation.
/// Those host dependencies remain required before canonical activation.
pub struct ProductionInputProviders<P> {
    materialization: MaterializationInputProvider,
    proxy_source: ProxyInputProvider<RuntimeDescriptorProvider, P>,
    proxy_launcher: MediatedActThroughProxyLauncher<RuntimeDescriptorProvider>,
}

/// Concrete proxy runtime assembled from the production input providers.
pub type ProductionProxyInputRuntime<P, R> = BrokerProxyRuntime<
    ProxyInputProvider<RuntimeDescriptorProvider, P>,
    MediatedActThroughProxyLauncher<RuntimeDescriptorProvider>,
    R,
>;

impl<P: BoundPrestartPersister> ProductionInputProviders<P> {
    /// Open both authority consumers with one shared runtime descriptor stream.
    pub fn open(
        contract: &HostCompositionContract,
        persister: P,
    ) -> Result<Self, ExecutionUnavailable> {
        let materialization = MaterializationInputProvider::from_contract(contract)?;
        let descriptors =
            RuntimeDescriptorProvider::new(contract.clone()).map_err(|_| ExecutionUnavailable)?;
        let proxy_source =
            ProxyInputProvider::from_contract(contract, descriptors.clone(), persister)?;
        let proxy_launcher =
            MediatedActThroughProxyLauncher::production(descriptors, contract.clone())
                .map_err(|_| ExecutionUnavailable)?;
        Ok(Self {
            materialization,
            proxy_source,
            proxy_launcher,
        })
    }

    /// Finish proxy assembly once the caller supplies its durable reconciler.
    pub fn into_proxy_runtime<R>(
        self,
        reconciler: R,
    ) -> (
        MaterializationInputProvider,
        ProductionProxyInputRuntime<P, R>,
    ) {
        (
            self.materialization,
            BrokerProxyRuntime::new(self.proxy_source, self.proxy_launcher, reconciler),
        )
    }
}

/// Fresh host proof adapter. The source must bind all facts to `target`.
pub trait ProductionReadyProofSource {
    fn validate(&mut self, target: &ReadyValidationTarget, now: u64) -> Option<ReadyHostProofs>;
}

/// Ready validator used by the production bootstrap path.
pub struct ProductionReadyValidator {
    source: Box<dyn ProductionReadyProofSource>,
}

impl ProductionReadyValidator {
    pub fn new(source: Box<dyn ProductionReadyProofSource>) -> Self {
        Self { source }
    }
}

impl ReadyValidationProvider for ProductionReadyValidator {
    fn ready_validation(
        &mut self,
        target: &ReadyValidationTarget,
        now: u64,
    ) -> Option<ReadyHostProofs> {
        self.source.validate(target, now)
    }
}

/// Ordinary adapter that accepts only the durable dispatcher's typed seam.
pub struct ProductionOrdinaryExecutor {
    backend: Box<dyn OrdinaryExecutor>,
}

impl ProductionOrdinaryExecutor {
    pub fn new(backend: Box<dyn OrdinaryExecutor>) -> Self {
        Self { backend }
    }
}

impl OrdinaryExecutor for ProductionOrdinaryExecutor {
    fn preflight(
        &mut self,
        request: AdmitAttemptRequest,
        admission: OrdinaryAdmission,
    ) -> Result<(), ExecutionUnavailable> {
        self.backend.preflight(request, admission)
    }

    fn provision(
        &mut self,
        request: AdmitAttemptRequest,
        admission: OrdinaryAdmission,
        lease: LeaseToken,
    ) -> Result<(), ExecutionUnavailable> {
        self.backend.provision(request, admission, lease)
    }

    fn read_receipts(
        &mut self,
        request: AdmitAttemptRequest,
        admission: OrdinaryAdmission,
        lease: LeaseToken,
    ) -> Result<OrdinaryReceipts, ExecutionUnavailable> {
        self.backend.read_receipts(request, admission, lease)
    }

    fn reconcile(
        &mut self,
        request: AdmitAttemptRequest,
        admission: OrdinaryAdmission,
        lease: LeaseToken,
        stop: OrdinaryStop,
    ) -> Result<OrdinaryCleanup, ExecutionUnavailable> {
        self.backend.reconcile(request, admission, lease, stop)
    }

    fn capacity_returned(
        &mut self,
        request: AdmitAttemptRequest,
        admission: OrdinaryAdmission,
        lease: LeaseToken,
        teardown_digest: [u8; 32],
    ) -> Result<(), ExecutionUnavailable> {
        self.backend
            .capacity_returned(request, admission, lease, teardown_digest)
    }
}

/// Qualification adapter that accepts only the durable dispatcher's typed seam.
pub struct ProductionQualificationExecutor {
    backend: Box<dyn QualificationExecutor>,
}

impl ProductionQualificationExecutor {
    pub fn new(backend: Box<dyn QualificationExecutor>) -> Self {
        Self { backend }
    }
}

impl QualificationExecutor for ProductionQualificationExecutor {
    fn preflight(&mut self, request: QualificationRequest) -> Result<(), ExecutionUnavailable> {
        self.backend.preflight(request)
    }

    fn execute(
        &mut self,
        header: FrameHeader,
        request: QualificationRequest,
        lease: QualificationLease,
        now: u64,
    ) -> Result<QualificationExecution, ExecutionUnavailable> {
        self.backend.execute(header, request, lease, now)
    }

    fn reconcile(
        &mut self,
        request: QualificationRequest,
        lease: QualificationLease,
        stop: QualificationStop,
    ) -> Result<QualificationCleanup, ExecutionUnavailable> {
        self.backend.reconcile(request, lease, stop)
    }
}

/// Complete production adapter set. It cannot represent a partial composition.
pub struct ProductionAdapters {
    validation: ProductionReadyValidator,
    ordinary: ProductionOrdinaryExecutor,
    qualification: ProductionQualificationExecutor,
}

impl ProductionAdapters {
    pub fn from_backends(
        validation: Box<dyn ProductionReadyProofSource>,
        ordinary: Box<dyn OrdinaryExecutor>,
        qualification: Box<dyn QualificationExecutor>,
    ) -> Self {
        Self {
            validation: ProductionReadyValidator::new(validation),
            ordinary: ProductionOrdinaryExecutor::new(ordinary),
            qualification: ProductionQualificationExecutor::new(qualification),
        }
    }

    /// Discover the complete fixed production backend set.
    ///
    /// Discovery remains closed until every production proof source and host
    /// execution adapter is bound. It never assembles a partial host path.
    pub fn canonical() -> Result<Self, ProductionCompositionError> {
        crate::host_composition::HostCompositionContract::canonical()
            .map_err(|_| ProductionCompositionError::HostContractUnavailable)?;
        Err(ProductionCompositionError::HostBackendsMissing(
            &MISSING_ORDINARY_HOST_SEAMS,
        ))
    }
}

/// Concrete dispatch type used by `buzz-ci-execd` production main.
pub enum ProductionDispatch {
    Closed(ClosedDispatch),
    Configured(BootstrapDispatch<ProductionOrdinaryExecutor, ProductionQualificationExecutor>),
}

impl ControlDispatch for ProductionDispatch {
    fn dispatch(&mut self, header: FrameHeader, request: Request, now: u64) -> BrokerResponse {
        match self {
            Self::Closed(dispatch) => dispatch.dispatch(header, request, now),
            Self::Configured(dispatch) => dispatch.dispatch(header, request, now),
        }
    }

    fn maintenance(&mut self, now: u64) {
        if let Self::Configured(dispatch) = self {
            dispatch.maintenance(now);
        }
    }
}

/// Load the exact production composition. Missing backends expose zero capacity.
pub fn load_production_dispatch(now: u64) -> ProductionDispatch {
    let Ok(adapters) = ProductionAdapters::canonical() else {
        return ProductionDispatch::Closed(ClosedDispatch::new());
    };
    compose_production_dispatch(now, adapters)
}

fn compose_production_dispatch(now: u64, mut adapters: ProductionAdapters) -> ProductionDispatch {
    ProductionDispatch::Configured(load_dispatch(
        now,
        &mut adapters.validation,
        adapters.ordinary,
        adapters.qualification,
    ))
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, rc::Rc};

    use crate::{
        activation::LeaseConclusion,
        durable_dispatch::crash_recovery::{
            AttemptEvidenceBinding, CrashRecoveryCoordinator, MemoryRecoveryJournal,
            RecoveryJournal, RecoveryRecord, RecoveryStage,
        },
        normal_engine::tests::ordinary_fixture,
    };

    use super::*;

    struct TestClosedExecutor;

    impl OrdinaryExecutor for TestClosedExecutor {
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

    impl QualificationExecutor for TestClosedExecutor {
        fn preflight(
            &mut self,
            _request: QualificationRequest,
        ) -> Result<(), ExecutionUnavailable> {
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

    struct TestQualificationForwarder {
        reconciles: Rc<Cell<usize>>,
    }

    struct TestOrdinaryForwarder {
        capacity_returns: Rc<Cell<usize>>,
    }

    impl OrdinaryExecutor for TestOrdinaryForwarder {
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

        fn capacity_returned(
            &mut self,
            _request: AdmitAttemptRequest,
            _admission: OrdinaryAdmission,
            _lease: LeaseToken,
            _teardown_digest: [u8; 32],
        ) -> Result<(), ExecutionUnavailable> {
            self.capacity_returns.set(self.capacity_returns.get() + 1);
            Ok(())
        }
    }

    impl QualificationExecutor for TestQualificationForwarder {
        fn preflight(
            &mut self,
            _request: QualificationRequest,
        ) -> Result<(), ExecutionUnavailable> {
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

        fn reconcile(
            &mut self,
            _request: QualificationRequest,
            _lease: QualificationLease,
            _stop: QualificationStop,
        ) -> Result<QualificationCleanup, ExecutionUnavailable> {
            self.reconciles.set(self.reconciles.get() + 1);
            Ok(QualificationCleanup {
                disposition: crate::activation::CleanupDisposition::Clean,
                teardown_digest: [91; 32],
            })
        }
    }

    fn qualification_request() -> QualificationRequest {
        QualificationRequest {
            integrated_candidate_sha: buzz_ci_broker_protocol::GitOid::Sha256([1; 32]),
            broker_build_identity: [2; 32],
            host_profile_digest: [3; 32],
            suite_identity: [4; 32],
            fixture_signer: [5; 32],
            request_digest: [6; 32],
            manifest_digest: [7; 32],
            isolation_profile_digest: [8; 32],
            source_oid: buzz_ci_broker_protocol::GitOid::Sha256([9; 32]),
            base_oid: buzz_ci_broker_protocol::GitOid::Sha256([10; 32]),
            job_identity: [11; 32],
            fixture_identity: [12; 32],
            nonce: [13; 32],
            not_before: 1,
            expires_at: 2,
            directive: Some(buzz_ci_broker_protocol::QualificationDirective::TeardownFailure),
        }
    }

    fn qualification_lease() -> QualificationLease {
        QualificationLease::from_durable(crate::activation::DurableQualificationLeaseFields {
            fixture_identity: [12; 32],
            lease_id: [12; 16],
            generation: 1,
            nonce: [13; 32],
            directive: Some(buzz_ci_broker_protocol::QualificationDirective::TeardownFailure),
        })
    }

    #[test]
    fn canonical_composition_is_closed_until_every_backend_is_linked() {
        assert!(ProductionAdapters::canonical().is_err());
        assert_eq!(MISSING_ORDINARY_HOST_SEAMS.len(), 7);
        assert_eq!(
            MISSING_ORDINARY_HOST_SEAMS,
            [
                HostBackendSeam::ExecutorUnitHandoff,
                HostBackendSeam::RuntimeDescriptorProvider,
                HostBackendSeam::MaterializationInputProvider,
                HostBackendSeam::ProxyInputAndLeaseProvider,
                HostBackendSeam::TerminalEvidenceCollector,
                HostBackendSeam::TeardownProvider,
                HostBackendSeam::CrashRecoveryCoordinator,
            ]
        );
        assert!(matches!(
            load_production_dispatch(1),
            ProductionDispatch::Closed(_)
        ));
    }

    #[test]
    fn typed_adapter_set_is_constructible_without_host_commands() {
        struct NoProof;
        impl ProductionReadyProofSource for NoProof {
            fn validate(
                &mut self,
                _target: &ReadyValidationTarget,
                _now: u64,
            ) -> Option<ReadyHostProofs> {
                None
            }
        }

        let adapters = ProductionAdapters::from_backends(
            Box::new(NoProof),
            Box::new(TestClosedExecutor),
            Box::new(TestClosedExecutor),
        );
        let _ = compose_production_dispatch(1, adapters);
    }

    #[test]
    fn production_qualification_adapter_forwards_cleanup_reconciliation() {
        let reconciles = Rc::new(Cell::new(0));
        let mut executor =
            ProductionQualificationExecutor::new(Box::new(TestQualificationForwarder {
                reconciles: Rc::clone(&reconciles),
            }));

        let cleanup = executor
            .reconcile(
                qualification_request(),
                qualification_lease(),
                QualificationStop::Recovery,
            )
            .unwrap();

        assert_eq!(reconciles.get(), 1);
        assert_eq!(
            cleanup.disposition,
            crate::activation::CleanupDisposition::Clean
        );
        assert_eq!(cleanup.teardown_digest, [91; 32]);
    }

    #[test]
    fn production_ordinary_adapter_forwards_capacity_returned() {
        let fixture = ordinary_fixture();
        let capacity_returns = Rc::new(Cell::new(0));
        let mut executor = ProductionOrdinaryExecutor::new(Box::new(TestOrdinaryForwarder {
            capacity_returns: Rc::clone(&capacity_returns),
        }));

        executor
            .capacity_returned(fixture.request, fixture.admission, fixture.lease, [8; 32])
            .expect("capacity returned");

        assert_eq!(capacity_returns.get(), 1);
    }

    #[test]
    fn production_wrapper_advances_crash_recovery_journal_to_capacity_returned() {
        let fixture = ordinary_fixture();
        let host_binding = &fixture.plan.binding;
        let mut binding = AttemptEvidenceBinding {
            run_id: fixture.request.run_id,
            job_id: host_binding.job_id.clone(),
            attempt: fixture.request.attempt,
            controller_lease_id: fixture.lease.lease_id(),
            lease_generation: fixture.lease.generation(),
            lease_deadline_at: fixture.lease.deadline_at(),
            host_lease_id: host_binding.lease_id.clone(),
            workspace_sha256:
                crate::durable_dispatch::terminal_evidence_collector::workspace_digest(host_binding),
            binding_sha256: [0; 32],
        };
        binding.binding_sha256 = binding.digest();
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
            .expect("evidence uploaded");
        journal
            .advance(RecoveryRecord {
                binding,
                stage: RecoveryStage::TeardownReadback {
                    conclusion: LeaseConclusion::Failure,
                    evidence_set_digest: [7; 32],
                    teardown_digest: [8; 32],
                },
            })
            .expect("teardown readback");
        let capacity_returns = Rc::new(Cell::new(0));
        let coordinator = CrashRecoveryCoordinator::new(
            TestOrdinaryForwarder {
                capacity_returns: Rc::clone(&capacity_returns),
            },
            journal.clone(),
        );
        let mut executor = ProductionOrdinaryExecutor::new(Box::new(coordinator));

        executor
            .capacity_returned(fixture.request, fixture.admission, fixture.lease, [8; 32])
            .expect("capacity returned");

        assert_eq!(capacity_returns.get(), 1);
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
