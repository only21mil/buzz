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
        load_dispatch, BootstrapDispatch, ExecutionUnavailable, ExpiredLeaseReconciliation,
        OrdinaryExecution, OrdinaryExecutor, QualificationExecution, QualificationExecutor,
        ReadyHostProofs, ReadyValidationProvider,
    },
    runtime::{ReadyValidationTarget, RuntimeLoadError},
};

/// Why production remains closed before authority/state loading.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductionCompositionError {
    /// One or more privileged proof, execution, or cleanup backends is absent.
    HostBackendsMissing,
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

    fn execute(
        &mut self,
        header: FrameHeader,
        request: AdmitAttemptRequest,
        admission: OrdinaryAdmission,
        lease: LeaseToken,
        now: u64,
    ) -> Result<OrdinaryExecution, ExecutionUnavailable> {
        self.backend.execute(header, request, admission, lease, now)
    }

    fn reconcile_expired(
        &mut self,
        lease: LeaseToken,
        now: u64,
    ) -> Result<ExpiredLeaseReconciliation, ExecutionUnavailable> {
        self.backend.reconcile_expired(lease, now)
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
    /// The current integration base lacks the DNS activation binding, opaque
    /// policy-proxy create/start capabilities, ordinary job runner, and concrete
    /// qualification cleanup runner. Until those land together, discovery is
    /// intentionally closed rather than assembling a partial host path.
    pub fn canonical() -> Result<Self, ProductionCompositionError> {
        Err(ProductionCompositionError::HostBackendsMissing)
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
}

impl ProductionDispatch {
    /// Drive trusted-time lease expiry independently of protocol completion.
    pub fn reconcile_expired(
        &mut self,
        now: u64,
    ) -> Result<Option<ExpiredLeaseReconciliation>, RuntimeLoadError> {
        match self {
            Self::Closed(_) => Ok(None),
            Self::Configured(dispatch) => dispatch.reconcile_expired(now),
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

    #[test]
    fn canonical_composition_is_closed_until_every_backend_is_linked() {
        assert_eq!(
            ProductionAdapters::canonical().err(),
            Some(ProductionCompositionError::HostBackendsMissing)
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
}
