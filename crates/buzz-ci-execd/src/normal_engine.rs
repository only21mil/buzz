//! Closed ordinary execution lifecycle and qualification routing.
//!
//! This module owns ordering and durable evidence publication. Host adapters
//! receive only a validated attempt binding and a root-authored launch plan.
//! They cannot replace the executable, environment, socket, unit, or paths.

use std::path::{Component, Path, PathBuf};

use buzz_ci_broker_protocol::{
    AdmitAttemptRequest, BrokerResponse, BrokerState, Conclusion, FrameHeader, GitOid,
    QualificationDirective, QualificationRequest, ResponseCode,
};
use buzz_ci_isolation_contract::{
    AttemptLeaseBinding, Phase1ValidationContext, ValidatedAttemptLeaseBinding,
};

use crate::{
    activation::{
        AdmissionTrustClass, CleanupDisposition, LeaseConclusion, LeaseToken, OrdinaryAdmission,
        QualificationLease, QualificationOutcome,
    },
    durable_dispatch::{
        ExecutionUnavailable, OrdinaryCleanup, OrdinaryExecutor, OrdinaryReceipts, OrdinaryStop,
        QualificationExecution, QualificationExecutor, QualificationTerminal,
    },
    evidence::{
        CiEventBinding, Digest32, DnsReadback, EvidenceStore, LeaseRecord, OrderingEvent,
        OrderingRecord, ReconcileRecord, ReconcileState, TeardownRecord,
    },
};

const FIRST_TERMINAL_SEQUENCE: u64 = 3;
/// Reviewed `nektos/act` v0.2.89 Linux x86_64 binary digest.
pub const PINNED_ACT_SHA256: &str =
    "6be37b104430efc210d5130495bedcff2dc7cd6780a38d88f3d205e7f1185cc1";

const TERMINAL_PREFIX: [OrderingEvent; 7] = [
    OrderingEvent::Stop,
    OrderingEvent::FinalizeRawStream,
    OrderingEvent::Extract,
    OrderingEvent::Scrub,
    OrderingEvent::Scan,
    OrderingEvent::Hash,
    OrderingEvent::Upload,
];

const TERMINAL_SUFFIX: [OrderingEvent; 3] = [
    OrderingEvent::TeardownProof,
    OrderingEvent::Publish,
    OrderingEvent::Reconcile,
];

/// Root-owned validation inputs used to consume an untrusted lease binding.
#[derive(Clone, Debug)]
pub struct BindingValidationAuthority {
    pub now_unix_seconds: u64,
    pub max_expiry_horizon_seconds: u64,
    pub forbidden_host_uids: Vec<u32>,
    pub expected_engine_version: String,
    pub expected_arch: String,
}

impl BindingValidationAuthority {
    fn context(&self) -> Phase1ValidationContext<'_> {
        Phase1ValidationContext {
            now_unix_seconds: self.now_unix_seconds,
            max_expiry_horizon_seconds: self.max_expiry_horizon_seconds,
            forbidden_host_uids: &self.forbidden_host_uids,
            expected_engine_version: &self.expected_engine_version,
            expected_arch: &self.expected_arch,
        }
    }
}

/// Exact `act` invocation selected by root-owned policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActLaunchPlan {
    pub binary: PathBuf,
    pub binary_sha256: [u8; 32],
    pub working_directory: PathBuf,
    pub home_directory: PathBuf,
    pub workflow_path: PathBuf,
    pub job_id: String,
    pub image: String,
    pub secrets_path: PathBuf,
    pub vars_path: PathBuf,
    pub env_path: PathBuf,
    pub inputs_path: PathBuf,
    pub proxy_socket: PathBuf,
    pub executor_unit: String,
    pub runtime_unit: String,
    pub lease_slice: String,
}

impl ActLaunchPlan {
    /// Validate the closed invocation and return its exact argument vector.
    pub fn argv(&self) -> Result<Vec<String>, ExecutionUnavailable> {
        self.validate()?;
        Ok(vec![
            "--pull=false".into(),
            "--concurrent-jobs=1".into(),
            "-P".into(),
            format!("ubuntu-latest={}", self.image),
            "-W".into(),
            path_text(&self.workflow_path)?,
            "-j".into(),
            self.job_id.clone(),
            "--secret-file".into(),
            path_text(&self.secrets_path)?,
            "--var-file".into(),
            path_text(&self.vars_path)?,
            "--env-file".into(),
            path_text(&self.env_path)?,
            "--input-file".into(),
            path_text(&self.inputs_path)?,
        ])
    }

    /// Return the complete cleared-environment replacement. No caller value is
    /// accepted, and the only engine endpoint is the broker proxy socket.
    pub fn environment(&self) -> Result<Vec<(String, String)>, ExecutionUnavailable> {
        self.validate()?;
        let home = path_text(&self.home_directory)?;
        Ok(vec![
            ("HOME".into(), home.clone()),
            (
                "XDG_CONFIG_HOME".into(),
                path_text(&self.home_directory.join("config"))?,
            ),
            (
                "XDG_RUNTIME_DIR".into(),
                path_text(&self.home_directory.join("runtime"))?,
            ),
            (
                "DOCKER_HOST".into(),
                format!("unix://{}", path_text(&self.proxy_socket)?),
            ),
        ])
    }

    fn validate(&self) -> Result<(), ExecutionUnavailable> {
        let paths = [
            &self.binary,
            &self.working_directory,
            &self.home_directory,
            &self.workflow_path,
            &self.secrets_path,
            &self.vars_path,
            &self.env_path,
            &self.inputs_path,
            &self.proxy_socket,
        ];
        if hex::encode(self.binary_sha256) != PINNED_ACT_SHA256
            || paths.iter().any(|path| !safe_absolute(path))
            || self.job_id.is_empty()
            || !safe_token(&self.job_id)
            || !self.image.starts_with("sha256:")
            || self.image.len() != 71
            || !self.image[7..].bytes().all(lower_hex)
            || !safe_service(&self.executor_unit)
            || !safe_service(&self.runtime_unit)
            || !safe_slice(&self.lease_slice)
            || self.executor_unit == self.runtime_unit
        {
            return Err(ExecutionUnavailable);
        }
        Ok(())
    }
}

/// Root-authored inputs for one ordinary lease.
pub struct NormalJobPlan {
    pub binding: AttemptLeaseBinding,
    pub validation: BindingValidationAuthority,
    pub evidence_root: PathBuf,
    pub lease_record: LeaseRecord,
    pub event_binding: CiEventBinding,
    pub act: ActLaunchPlan,
}

impl NormalJobPlan {
    fn validate_identity(
        &self,
        request: AdmitAttemptRequest,
        admission: OrdinaryAdmission,
    ) -> Result<(), ExecutionUnavailable> {
        let binding = &self.binding;
        if admission.trust_class != AdmissionTrustClass::AcceptedReviewed
            || request.signed_request_digest != admission.job.request_digest
            || request.job_manifest_digest != admission.job.manifest_digest
            || request.isolation_profile_digest != admission.job.isolation_profile_digest
            || request.tip_oid != admission.job.source_oid
            || request.base_oid != admission.job.base_oid
            || request.run_id != admission.run_id
            || request.attempt != admission.attempt
            || request.expires_at != admission.expires_at
            || binding.run_id != uuid::Uuid::from_bytes(admission.run_id).to_string()
            || binding.source_sha != oid_hex(admission.job.source_oid)
            || binding.base_oid != oid_hex(admission.job.base_oid)
            || binding.attempt != admission.attempt
            || binding.expires_at_unix_seconds != admission.expires_at
            || binding.workflow_digest != hex::encode(request.workflow_digest)
            || self.act.job_id != binding.job_id
            || self.act.image != binding.isolation_profile.image_digest
            || self.lease_record.lease_id != binding.lease_id
            || self.lease_record.workspace_dir != Path::new(&binding.workspace.path)
            || self.lease_record.lease_unit != self.act.lease_slice
            || !safe_absolute(&self.evidence_root)
            || self.act.argv().is_err()
            || self.act.environment().is_err()
        {
            return Err(ExecutionUnavailable);
        }
        Ok(())
    }
}

/// Root-owned source for sealed job plans. C7 supplies the production source.
pub trait NormalJobSource {
    fn prepare(
        &mut self,
        request: AdmitAttemptRequest,
        admission: OrdinaryAdmission,
    ) -> Result<NormalJobPlan, ExecutionUnavailable>;
}

/// Host lifecycle operations behind the closed normal engine.
///
/// The production adapter composes `DnsLeaseLifecycle`, the materializer
/// `GitBackend`, the broker proxy lease with its seccomp pre-start observer,
/// and the exact transient-unit launcher described by `ActLaunchPlan`.
pub trait NormalExecutionBackend {
    fn preflight(
        &mut self,
        plan: &NormalJobPlan,
        binding: &ValidatedAttemptLeaseBinding,
    ) -> Result<(), ExecutionUnavailable>;

    fn apply_dns(
        &mut self,
        admission: OrdinaryAdmission,
        lease: LeaseToken,
        binding: &ValidatedAttemptLeaseBinding,
    ) -> Result<DnsReadback, ExecutionUnavailable>;

    fn materialize(
        &mut self,
        plan: &NormalJobPlan,
        binding: &ValidatedAttemptLeaseBinding,
        store: &EvidenceStore,
    ) -> Result<(), ExecutionUnavailable>;

    /// Complete create, effective-spec inspection, seccomp persistence, and
    /// start. The pre-start observer must commit before this method succeeds.
    fn proxy_create_inspect_start(
        &mut self,
        admission: OrdinaryAdmission,
        lease: LeaseToken,
        binding: &ValidatedAttemptLeaseBinding,
        store: &EvidenceStore,
    ) -> Result<(), ExecutionUnavailable>;

    /// Launch only the supplied pinned command in its exact executor unit.
    fn start_act(&mut self, plan: &ActLaunchPlan) -> Result<(), ExecutionUnavailable>;

    fn terminal_evidence(
        &mut self,
        lease: LeaseToken,
    ) -> Result<NormalTerminalEvidence, ExecutionUnavailable>;

    fn reconcile(
        &mut self,
        lease: LeaseToken,
        stop: OrdinaryStop,
    ) -> Result<NormalReconcileEvidence, ExecutionUnavailable>;
}

/// Root-observed job outcome and the terminal prefix through artifact upload.
pub struct NormalTerminalEvidence {
    pub conclusion: LeaseConclusion,
    pub evidence_set_digest: [u8; 32],
    pub ordering: Vec<OrderingRecord>,
}

/// Teardown, publication, and reuse evidence returned after host cleanup.
pub struct NormalReconcileEvidence {
    pub teardown: TeardownRecord,
    pub reconcile: ReconcileRecord,
    pub ordering: Vec<OrderingRecord>,
}

struct PreparedJob {
    request: AdmitAttemptRequest,
    admission: OrdinaryAdmission,
    plan: NormalJobPlan,
    binding: ValidatedAttemptLeaseBinding,
}

struct ActiveJob {
    request: AdmitAttemptRequest,
    admission: OrdinaryAdmission,
    lease: LeaseToken,
    plan: NormalJobPlan,
    binding: ValidatedAttemptLeaseBinding,
    terminal_published: bool,
    provision_complete: bool,
}

/// Production ordinary executor. It admits one prepared and one active lease.
pub struct ProductionOrdinaryEngine<S, B> {
    source: S,
    backend: B,
    prepared: Option<PreparedJob>,
    active: Option<ActiveJob>,
}

impl<S, B> ProductionOrdinaryEngine<S, B> {
    pub fn new(source: S, backend: B) -> Self {
        Self {
            source,
            backend,
            prepared: None,
            active: None,
        }
    }
}

impl<S: NormalJobSource, B: NormalExecutionBackend> OrdinaryExecutor
    for ProductionOrdinaryEngine<S, B>
{
    fn preflight(
        &mut self,
        request: AdmitAttemptRequest,
        admission: OrdinaryAdmission,
    ) -> Result<(), ExecutionUnavailable> {
        if self.prepared.is_some() || self.active.is_some() {
            return Err(ExecutionUnavailable);
        }
        let plan = self.source.prepare(request, admission)?;
        plan.validate_identity(request, admission)?;
        let binding = plan
            .binding
            .clone()
            .validate_phase1(&plan.validation.context())
            .map_err(|_| ExecutionUnavailable)?;
        self.backend.preflight(&plan, &binding)?;
        self.prepared = Some(PreparedJob {
            request,
            admission,
            plan,
            binding,
        });
        Ok(())
    }

    fn provision(
        &mut self,
        request: AdmitAttemptRequest,
        admission: OrdinaryAdmission,
        lease: LeaseToken,
    ) -> Result<(), ExecutionUnavailable> {
        if self.active.is_some() {
            return Err(ExecutionUnavailable);
        }
        let prepared = self.prepared.take().ok_or(ExecutionUnavailable)?;
        if prepared.request != request
            || prepared.admission != admission
            || !lease_matches(admission, lease)
        {
            return Err(ExecutionUnavailable);
        }
        self.active = Some(ActiveJob {
            request,
            admission,
            lease,
            plan: prepared.plan,
            binding: prepared.binding,
            terminal_published: false,
            provision_complete: false,
        });

        let active = self.active.as_mut().ok_or(ExecutionUnavailable)?;
        let dns = self.backend.apply_dns(admission, lease, &active.binding)?;
        active.plan.lease_record.dns_readback = dns;
        let store = EvidenceStore::new(active.plan.evidence_root.clone())
            .map_err(|_| ExecutionUnavailable)?;
        store
            .initialize_lease(&active.plan.lease_record)
            .map_err(|_| ExecutionUnavailable)?;
        self.backend
            .materialize(&active.plan, &active.binding, &store)?;
        self.backend
            .proxy_create_inspect_start(admission, lease, &active.binding, &store)?;
        self.backend.start_act(&active.plan.act)?;
        active.provision_complete = true;
        Ok(())
    }

    fn read_receipts(
        &mut self,
        request: AdmitAttemptRequest,
        admission: OrdinaryAdmission,
        lease: LeaseToken,
    ) -> Result<OrdinaryReceipts, ExecutionUnavailable> {
        let active = self.active.as_mut().ok_or(ExecutionUnavailable)?;
        if active.request != request
            || active.admission != admission
            || active.lease != lease
            || !active.provision_complete
            || active.terminal_published
        {
            return Err(ExecutionUnavailable);
        }
        let terminal = self.backend.terminal_evidence(lease)?;
        if terminal.evidence_set_digest == [0; 32] {
            return Err(ExecutionUnavailable);
        }
        validate_ordering_batch(
            &terminal.ordering,
            &TERMINAL_PREFIX,
            FIRST_TERMINAL_SEQUENCE,
            active.plan.event_binding,
            &active.plan.binding.lease_id,
        )?;
        let store = EvidenceStore::new(active.plan.evidence_root.clone())
            .map_err(|_| ExecutionUnavailable)?;
        append_ordering(&store, &terminal.ordering)?;
        active.terminal_published = true;
        Ok(OrdinaryReceipts {
            conclusion: terminal.conclusion,
            evidence_set_digest: terminal.evidence_set_digest,
        })
    }

    fn reconcile(
        &mut self,
        request: AdmitAttemptRequest,
        admission: OrdinaryAdmission,
        lease: LeaseToken,
        stop: OrdinaryStop,
    ) -> Result<OrdinaryCleanup, ExecutionUnavailable> {
        let active = self.active.take().ok_or(ExecutionUnavailable)?;
        if active.request != request || active.admission != admission || active.lease != lease {
            self.active = Some(active);
            return Err(ExecutionUnavailable);
        }
        let cleanup = self.backend.reconcile(lease, stop)?;
        if !active.provision_complete || !active.terminal_published {
            return Ok(ambiguous_cleanup());
        }
        if cleanup.teardown.lease_id != active.plan.binding.lease_id
            || cleanup.teardown.event_binding != active.plan.event_binding
            || cleanup.reconcile.lease_id != active.plan.binding.lease_id
            || cleanup.reconcile.lease_unit != active.plan.lease_record.lease_unit
            || cleanup.reconcile.cgroup_path != active.plan.lease_record.cgroup_path
            || cleanup.reconcile.state != ReconcileState::Clean
            || !cleanup.reconcile.reuse_allowed
            || cleanup.teardown.teardown_sha256 == Digest32([0; 32])
        {
            return Ok(ambiguous_cleanup());
        }
        validate_ordering_batch(
            &cleanup.ordering,
            &TERMINAL_SUFFIX,
            FIRST_TERMINAL_SEQUENCE + TERMINAL_PREFIX.len() as u64,
            active.plan.event_binding,
            &active.plan.binding.lease_id,
        )?;
        let store =
            EvidenceStore::new(active.plan.evidence_root).map_err(|_| ExecutionUnavailable)?;
        store
            .publish_teardown(&cleanup.teardown)
            .map_err(|_| ExecutionUnavailable)?;
        append_ordering(&store, &cleanup.ordering)?;
        store
            .publish_reconcile(&cleanup.reconcile)
            .map_err(|_| ExecutionUnavailable)?;
        Ok(OrdinaryCleanup {
            disposition: CleanupDisposition::Clean,
            teardown_digest: cleanup.teardown.teardown_sha256.0,
        })
    }
}

fn ambiguous_cleanup() -> OrdinaryCleanup {
    OrdinaryCleanup {
        disposition: CleanupDisposition::Ambiguous,
        teardown_digest: [0; 32],
    }
}

fn append_ordering(
    store: &EvidenceStore,
    records: &[OrderingRecord],
) -> Result<(), ExecutionUnavailable> {
    records.iter().try_for_each(|record| {
        store
            .append_ordering(record)
            .map_err(|_| ExecutionUnavailable)
    })
}

fn validate_ordering_batch(
    records: &[OrderingRecord],
    expected: &[OrderingEvent],
    first_sequence: u64,
    event_binding: CiEventBinding,
    lease_id: &str,
) -> Result<(), ExecutionUnavailable> {
    if records.len() != expected.len() {
        return Err(ExecutionUnavailable);
    }
    let mut previous_timestamp = 0;
    for (index, (record, event)) in records.iter().zip(expected).enumerate() {
        if record.sequence != first_sequence + index as u64
            || record.event != *event
            || record.event_binding != event_binding
            || record.lease_id != lease_id
            || record.timestamp_unix_ns <= previous_timestamp
            || (record.event == OrderingEvent::Publish
                && (record.status_event_id.is_none() || record.verdict_event_id.is_none()))
            || (record.event != OrderingEvent::Publish
                && (record.status_event_id.is_some() || record.verdict_event_id.is_some()))
        {
            return Err(ExecutionUnavailable);
        }
        previous_timestamp = record.timestamp_unix_ns;
    }
    Ok(())
}

fn lease_matches(admission: OrdinaryAdmission, lease: LeaseToken) -> bool {
    lease.lease_id() == admission.lease_id
        && lease.run_id() == admission.run_id
        && lease.attempt() == admission.attempt
        && lease.signed_request_digest() == admission.job.request_digest
        && lease.signer() == admission.signer
        && lease.nonce() == admission.nonce
        && lease.generation() != 0
        && lease.deadline_at() != 0
        && lease.deadline_at() <= admission.expires_at
}

/// Normal qualification fixture backend. It runs the same closed engine plan
/// and returns only a decisive accepted or failed outcome.
pub trait NormalQualificationBackend {
    fn preflight(&mut self, request: QualificationRequest) -> Result<(), ExecutionUnavailable>;

    fn execute(
        &mut self,
        request: QualificationRequest,
        lease: QualificationLease,
        now: u64,
    ) -> Result<QualificationOutcome, ExecutionUnavailable>;
}

/// Qualification adapter for the 33 non-fault cases.
pub struct NormalQualificationExecutor<R> {
    runner: R,
}

impl<R> NormalQualificationExecutor<R> {
    pub fn new(runner: R) -> Self {
        Self { runner }
    }
}

impl<R: NormalQualificationBackend> QualificationExecutor for NormalQualificationExecutor<R> {
    fn preflight(&mut self, request: QualificationRequest) -> Result<(), ExecutionUnavailable> {
        if request.directive.is_some() {
            return Err(ExecutionUnavailable);
        }
        self.runner.preflight(request)
    }

    fn execute(
        &mut self,
        _header: FrameHeader,
        request: QualificationRequest,
        lease: QualificationLease,
        now: u64,
    ) -> Result<QualificationExecution, ExecutionUnavailable> {
        if request.directive.is_some() || lease.directive().is_some() {
            return Err(ExecutionUnavailable);
        }
        let outcome = self.runner.execute(request, lease, now)?;
        if matches!(outcome, QualificationOutcome::Ambiguous)
            || matches!(outcome, QualificationOutcome::Accepted { evidence_set_digest } if evidence_set_digest == [0; 32])
        {
            return Err(ExecutionUnavailable);
        }
        Ok(QualificationExecution {
            terminal: QualificationTerminal::Completed(outcome),
            response: normal_qualification_response(request, lease, outcome, now),
        })
    }
}

/// Closed directive router. No catch-all or caller-selected backend exists.
pub struct QualificationMultiplexer<N, T> {
    normal: N,
    teardown: T,
}

impl<N, T> QualificationMultiplexer<N, T> {
    pub fn new(normal: N, teardown: T) -> Self {
        Self { normal, teardown }
    }
}

impl<N: QualificationExecutor, T: QualificationExecutor> QualificationExecutor
    for QualificationMultiplexer<N, T>
{
    fn preflight(&mut self, request: QualificationRequest) -> Result<(), ExecutionUnavailable> {
        match request.directive {
            None => self.normal.preflight(request),
            Some(QualificationDirective::TeardownFailure) => self.teardown.preflight(request),
        }
    }

    fn execute(
        &mut self,
        header: FrameHeader,
        request: QualificationRequest,
        lease: QualificationLease,
        now: u64,
    ) -> Result<QualificationExecution, ExecutionUnavailable> {
        let result = match request.directive {
            None => self.normal.execute(header, request, lease, now)?,
            Some(QualificationDirective::TeardownFailure) => {
                self.teardown.execute(header, request, lease, now)?
            }
        };
        match (request.directive, result.terminal) {
            (
                None,
                QualificationTerminal::Completed(
                    QualificationOutcome::Accepted { .. } | QualificationOutcome::Failed,
                ),
            )
            | (
                Some(QualificationDirective::TeardownFailure),
                QualificationTerminal::TeardownFailure,
            ) => Ok(result),
            _ => Err(ExecutionUnavailable),
        }
    }
}

fn normal_qualification_response(
    request: QualificationRequest,
    lease: QualificationLease,
    outcome: QualificationOutcome,
    now: u64,
) -> BrokerResponse {
    let (code, conclusion, evidence_set_digest) = match outcome {
        QualificationOutcome::Accepted {
            evidence_set_digest,
        } => (ResponseCode::Ok, Conclusion::Success, evidence_set_digest),
        QualificationOutcome::Failed | QualificationOutcome::Ambiguous => {
            (ResponseCode::InternalFailure, Conclusion::Failure, [0; 32])
        }
    };
    BrokerResponse {
        code,
        retry_after_millis: 0,
        attempt_id: lease.lease_id(),
        run_id: [0; 16],
        accepted_request_digest: request.request_digest,
        job_manifest_digest: request.manifest_digest,
        tip_oid: Some(request.integrated_candidate_sha),
        broker_state: BrokerState::Reconciling,
        conclusion,
        terminal_reason: u16::from(code != ResponseCode::Ok),
        generation: lease.generation(),
        accepted_at: now,
        updated_at: now,
        lease_generation: lease.generation(),
        evidence_set_digest,
        teardown_digest: [0; 32],
        attempt: 1,
    }
}

fn safe_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path.components().all(|component| {
            !matches!(
                component,
                Component::ParentDir | Component::CurDir | Component::Prefix(_)
            )
        })
        && path.to_str().is_some_and(|value| !value.contains('\0'))
}

fn safe_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn safe_service(value: &str) -> bool {
    value.ends_with(".service") && safe_token(value)
}

fn safe_slice(value: &str) -> bool {
    value.ends_with(".slice") && safe_token(value)
}

fn lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
}

fn path_text(path: &Path) -> Result<String, ExecutionUnavailable> {
    path.to_str()
        .map(ToOwned::to_owned)
        .ok_or(ExecutionUnavailable)
}

fn oid_hex(oid: GitOid) -> String {
    match oid {
        GitOid::Sha1(bytes) => hex::encode(bytes),
        GitOid::Sha256(bytes) => hex::encode(bytes),
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, rc::Rc};

    use buzz_ci_broker_protocol::{Operation, TrustClass};
    use buzz_ci_isolation_contract::{
        BrokerObjectHandle, CgroupHandle, EngineKind, IsolationProfile, NetnsHandle, NetworkPolicy,
        PrincipalUids, QuotaBackend, QuotaHandle, ResourceLimits, RuntimeEndpointIdentity,
        WorkspaceHandle, PHASE1_SECCOMP_PROFILE_DIGEST, PHASE1_SECCOMP_PROFILE_PATH,
    };
    use tempfile::TempDir;

    use super::*;
    use crate::{
        activation::{
            ActivationController, DurableLeaseFields, FixtureJobCoordinates,
            HostActivationCoordinates, OrdinaryJobCoordinates, QualificationAdmission,
            QualificationPermit, VerifiedSigner,
        },
        evidence::{
            LeaseLimits, ReconciledResource, ResourcePropertyReadback, SeccompEvidence,
            SECCOMP_PROFILE_PATH, SECCOMP_PROFILE_SHA256,
        },
    };

    const ROOT: VerifiedSigner = VerifiedSigner([41; 32]);
    const FIXTURE_SIGNER: VerifiedSigner = VerifiedSigner([42; 32]);

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum FailStage {
        None,
        Preflight,
        Dns,
        Materialize,
        Proxy,
        Act,
        Terminal,
        Cleanup,
    }

    struct OnePlan(Option<NormalJobPlan>);

    impl NormalJobSource for OnePlan {
        fn prepare(
            &mut self,
            _request: AdmitAttemptRequest,
            _admission: OrdinaryAdmission,
        ) -> Result<NormalJobPlan, ExecutionUnavailable> {
            self.0.take().ok_or(ExecutionUnavailable)
        }
    }

    struct FakeBackend {
        fail: FailStage,
        log: Rc<RefCell<Vec<&'static str>>>,
        event_binding: CiEventBinding,
        lease_id: String,
        incomplete_teardown: bool,
        bad_terminal_order: bool,
    }

    impl FakeBackend {
        fn push(&self, value: &'static str) {
            self.log.borrow_mut().push(value);
        }

        fn fail_if(&self, stage: FailStage) -> Result<(), ExecutionUnavailable> {
            if self.fail == stage {
                Err(ExecutionUnavailable)
            } else {
                Ok(())
            }
        }
    }

    impl NormalExecutionBackend for FakeBackend {
        fn preflight(
            &mut self,
            _plan: &NormalJobPlan,
            _binding: &ValidatedAttemptLeaseBinding,
        ) -> Result<(), ExecutionUnavailable> {
            self.push("preflight");
            self.fail_if(FailStage::Preflight)
        }

        fn apply_dns(
            &mut self,
            _admission: OrdinaryAdmission,
            _lease: LeaseToken,
            _binding: &ValidatedAttemptLeaseBinding,
        ) -> Result<DnsReadback, ExecutionUnavailable> {
            self.push("dns");
            self.fail_if(FailStage::Dns)?;
            Ok(complete_dns())
        }

        fn materialize(
            &mut self,
            _plan: &NormalJobPlan,
            _binding: &ValidatedAttemptLeaseBinding,
            _store: &EvidenceStore,
        ) -> Result<(), ExecutionUnavailable> {
            self.push("materialize");
            self.fail_if(FailStage::Materialize)
        }

        fn proxy_create_inspect_start(
            &mut self,
            _admission: OrdinaryAdmission,
            _lease: LeaseToken,
            _binding: &ValidatedAttemptLeaseBinding,
            store: &EvidenceStore,
        ) -> Result<(), ExecutionUnavailable> {
            self.push("prestart");
            self.fail_if(FailStage::Proxy)?;
            store
                .append_ordering(&ordering(
                    &self.lease_id,
                    self.event_binding,
                    1,
                    OrderingEvent::ProxyObjectRecorded,
                ))
                .map_err(|_| ExecutionUnavailable)?;
            store
                .append_ordering(&ordering(
                    &self.lease_id,
                    self.event_binding,
                    2,
                    OrderingEvent::Start,
                ))
                .map_err(|_| ExecutionUnavailable)?;
            self.push("proxy-start");
            Ok(())
        }

        fn start_act(&mut self, plan: &ActLaunchPlan) -> Result<(), ExecutionUnavailable> {
            self.push("act-start");
            self.fail_if(FailStage::Act)?;
            assert_eq!(plan.environment()?.len(), 4);
            assert!(plan
                .environment()?
                .iter()
                .any(|(key, value)| key == "DOCKER_HOST" && value.contains("proxy.sock")));
            assert!(!plan
                .argv()?
                .iter()
                .any(|value| value.contains("DOCKER_HOST")));
            Ok(())
        }

        fn terminal_evidence(
            &mut self,
            _lease: LeaseToken,
        ) -> Result<NormalTerminalEvidence, ExecutionUnavailable> {
            self.push("terminal");
            self.fail_if(FailStage::Terminal)?;
            let mut records = batch(
                &self.lease_id,
                self.event_binding,
                FIRST_TERMINAL_SEQUENCE,
                &TERMINAL_PREFIX,
            );
            if self.bad_terminal_order {
                records.swap(1, 2);
            }
            Ok(NormalTerminalEvidence {
                conclusion: LeaseConclusion::Success,
                evidence_set_digest: [61; 32],
                ordering: records,
            })
        }

        fn reconcile(
            &mut self,
            _lease: LeaseToken,
            _stop: OrdinaryStop,
        ) -> Result<NormalReconcileEvidence, ExecutionUnavailable> {
            self.push("cleanup");
            self.fail_if(FailStage::Cleanup)?;
            let lease_unit = "buzzci-normal.slice".to_owned();
            let cgroup_path = PathBuf::from("/buzzci.slice/buzzci-normal.slice");
            Ok(NormalReconcileEvidence {
                teardown: TeardownRecord {
                    lease_id: self.lease_id.clone(),
                    event_binding: self.event_binding,
                    lease_unit: lease_unit.clone(),
                    cgroup_path: cgroup_path.clone(),
                    unit_inactive: true,
                    cgroup_procs_empty: true,
                    mounts_removed: true,
                    dirs_removed: !self.incomplete_teardown,
                    teardown_sha256: Digest32([62; 32]),
                    completed_at_unix_ns: 10,
                },
                reconcile: ReconcileRecord {
                    lease_id: self.lease_id.clone(),
                    lease_unit,
                    cgroup_path,
                    state: ReconcileState::Clean,
                    emptied: true,
                    quarantined: false,
                    before_reuse: true,
                    emptied_resources: vec![
                        ReconciledResource::LeaseUnit,
                        ReconciledResource::Cgroup,
                        ReconciledResource::Workspace,
                        ReconciledResource::NetworkNamespace,
                        ReconciledResource::RuntimeSocket,
                        ReconciledResource::ProxyObjectState,
                    ],
                    quarantined_resources: Vec::new(),
                    reuse_allowed: true,
                    observed_at_unix_ns: 12,
                },
                ordering: batch(
                    &self.lease_id,
                    self.event_binding,
                    FIRST_TERMINAL_SEQUENCE + TERMINAL_PREFIX.len() as u64,
                    &TERMINAL_SUFFIX,
                ),
            })
        }
    }

    fn complete_dns() -> DnsReadback {
        DnsReadback {
            files_lookup_ok: true,
            arbitrary_getent_refused: true,
            resolved_varlink_inaccessible: true,
            direct_53_refused: true,
            allowed_tuples_only: true,
        }
    }

    fn ordering(
        lease_id: &str,
        event_binding: CiEventBinding,
        sequence: u64,
        event: OrderingEvent,
    ) -> OrderingRecord {
        OrderingRecord {
            lease_id: lease_id.into(),
            sequence,
            event_binding,
            event,
            object_id: matches!(
                event,
                OrderingEvent::ProxyObjectRecorded | OrderingEvent::Start
            )
            .then(|| "container01".into()),
            timestamp_unix_ns: sequence,
            status_event_id: (event == OrderingEvent::Publish).then(|| "status01".into()),
            verdict_event_id: (event == OrderingEvent::Publish).then(|| "verdict01".into()),
        }
    }

    fn batch(
        lease_id: &str,
        event_binding: CiEventBinding,
        first: u64,
        events: &[OrderingEvent],
    ) -> Vec<OrderingRecord> {
        events
            .iter()
            .copied()
            .enumerate()
            .map(|(index, event)| ordering(lease_id, event_binding, first + index as u64, event))
            .collect()
    }

    struct OrdinaryFixture {
        _root: TempDir,
        request: AdmitAttemptRequest,
        admission: OrdinaryAdmission,
        lease: LeaseToken,
        plan: NormalJobPlan,
        event_binding: CiEventBinding,
        lease_id: String,
    }

    fn ordinary_fixture() -> OrdinaryFixture {
        let root = tempfile::tempdir().unwrap();
        let request = AdmitAttemptRequest {
            signed_request_digest: [6; 32],
            actor_pubkey: [5; 32],
            audience_digest: [15; 32],
            idempotency_digest: [16; 32],
            source_pin_event_id: [17; 32],
            workflow_digest: [7; 32],
            job_manifest_digest: [8; 32],
            isolation_profile_digest: [9; 32],
            run_id: [13; 16],
            tip_oid: GitOid::Sha256([10; 32]),
            base_oid: GitOid::Sha256([11; 32]),
            issued_at: 10,
            expires_at: 100,
            wall_timeout_seconds: 30,
            attempt: 2,
            parent_attempt: 0,
            trust_class: TrustClass::AcceptedReviewed,
        };
        let admission = OrdinaryAdmission {
            host: HostActivationCoordinates {
                integrated_candidate_sha: GitOid::Sha256([1; 32]),
                broker_build_identity: [2; 32],
                host_profile_digest: [3; 32],
                suite_identity: [4; 32],
            },
            job: OrdinaryJobCoordinates {
                request_digest: request.signed_request_digest,
                manifest_digest: request.job_manifest_digest,
                isolation_profile_digest: request.isolation_profile_digest,
                source_oid: request.tip_oid,
                base_oid: request.base_oid,
                job_identity: [12; 32],
            },
            lease_id: [20; 16],
            run_id: request.run_id,
            attempt: request.attempt,
            signer: VerifiedSigner(request.actor_pubkey),
            nonce: [21; 32],
            expires_at: request.expires_at,
            wall_timeout_seconds: request.wall_timeout_seconds,
            trust_class: AdmissionTrustClass::AcceptedReviewed,
        };
        let lease = LeaseToken::from_durable(DurableLeaseFields {
            lease_id: admission.lease_id,
            run_id: admission.run_id,
            attempt: admission.attempt,
            signed_request_digest: admission.job.request_digest,
            signer: admission.signer,
            generation: 3,
            nonce: admission.nonce,
            deadline_at: 90,
        });
        let runtime_uid = nix::unistd::geteuid().as_raw();
        let token = |character: char| character.to_string().repeat(64);
        let limits = ResourceLimits {
            cpu_weight: 100,
            mem_max_bytes: 1024 * 1024,
            pids_max: 32,
            io_weight: 100,
        };
        let lease_id = "01ARZ3NDEKTSV4RRFFQ69G5FAV".to_owned();
        let binding = AttemptLeaseBinding {
            schema_version: 1,
            request_event_id: "a".repeat(64),
            run_id: uuid::Uuid::from_bytes(request.run_id).to_string(),
            target_repo_a: format!("30617:{}:buzz", "b".repeat(64)),
            source_sha: oid_hex(request.tip_oid),
            base_oid: oid_hex(request.base_oid),
            workflow_id: "required-ci".into(),
            workflow_digest: hex::encode(request.workflow_digest),
            job_id: "linux".into(),
            attempt: request.attempt,
            lease_id: lease_id.clone(),
            expires_at_unix_seconds: request.expires_at,
            principals: PrincipalUids {
                materializer: runtime_uid + 2,
                executor: runtime_uid + 1,
                runtime: runtime_uid,
            },
            workspace: WorkspaceHandle {
                path: "/var/lib/buzzci/workspaces/normal".into(),
                object: BrokerObjectHandle {
                    token: token('1'),
                    device: 10,
                    inode: 11,
                },
                owner_uid: runtime_uid + 2,
                quota_token: token('5'),
            },
            runtime_endpoint: RuntimeEndpointIdentity::InheritedFd {
                token: token('2'),
                owner_uid: runtime_uid,
            },
            cgroup: CgroupHandle {
                object: BrokerObjectHandle {
                    token: token('3'),
                    device: 20,
                    inode: 21,
                },
                limits: limits.clone(),
            },
            netns: NetnsHandle {
                object: BrokerObjectHandle {
                    token: token('4'),
                    device: 30,
                    inode: 31,
                },
                name: "buzzci-normal".into(),
            },
            quota: QuotaHandle {
                token: token('5'),
                backend: QuotaBackend::BoundedFilesystem,
                quota_id: "quota-normal".into(),
                hard_bytes: 1024 * 1024 * 1024,
            },
            isolation_profile: IsolationProfile {
                image_digest: format!("sha256:{}", "c".repeat(64)),
                engine_kind: EngineKind::Podman,
                engine_version: "5.8.4".into(),
                arch: "x86_64".into(),
                seccomp_profile_path: PHASE1_SECCOMP_PROFILE_PATH.into(),
                seccomp_profile_digest: PHASE1_SECCOMP_PROFILE_DIGEST.into(),
                limits,
                network_policy: NetworkPolicy::None,
                service_requirements: Vec::new(),
                netns: "buzzci-normal".into(),
            },
        };
        let event_binding = CiEventBinding {
            request_event_id_46105: [31; 32],
            teardown_event_id_46106: [32; 32],
        };
        let act = ActLaunchPlan {
            binary: "/usr/local/libexec/buzzci/act-0.2.89".into(),
            binary_sha256: hex::decode(PINNED_ACT_SHA256).unwrap().try_into().unwrap(),
            working_directory: "/var/lib/buzzci/invocations/normal".into(),
            home_directory: "/var/lib/buzzci/invocations/normal/home".into(),
            workflow_path: "/var/lib/buzzci/workspaces/normal/source/.github/workflows/ci.yml"
                .into(),
            job_id: "linux".into(),
            image: format!("sha256:{}", "c".repeat(64)),
            secrets_path: "/var/lib/buzzci/invocations/normal/empty/secrets".into(),
            vars_path: "/var/lib/buzzci/invocations/normal/empty/vars".into(),
            env_path: "/var/lib/buzzci/invocations/normal/empty/env".into(),
            inputs_path: "/var/lib/buzzci/invocations/normal/empty/inputs".into(),
            proxy_socket: "/run/buzzci/proxy.sock".into(),
            executor_unit: "buzzci-normal-exec.service".into(),
            runtime_unit: "buzzci-normal-run.service".into(),
            lease_slice: "buzzci-normal.slice".into(),
        };
        let plan = NormalJobPlan {
            binding,
            validation: BindingValidationAuthority {
                now_unix_seconds: 20,
                max_expiry_horizon_seconds: 100,
                forbidden_host_uids: Vec::new(),
                expected_engine_version: "5.8.4".into(),
                expected_arch: "x86_64".into(),
            },
            evidence_root: root.path().join("evidence"),
            lease_record: LeaseRecord {
                schema_version: 1,
                lease_id: lease_id.clone(),
                lease_unit: act.lease_slice.clone(),
                cgroup_path: "/buzzci.slice/buzzci-normal.slice".into(),
                workspace_dir: "/var/lib/buzzci/workspaces/normal".into(),
                limits: LeaseLimits { wall_deadline: 100 },
                resource_readback: ResourcePropertyReadback {
                    cpu_quota_per_sec_usec: 100,
                    memory_max_bytes: 1024 * 1024,
                    tasks_max: 32,
                    runtime_max_seconds: 30,
                },
                dns_readback: DnsReadback {
                    files_lookup_ok: false,
                    arbitrary_getent_refused: false,
                    resolved_varlink_inaccessible: false,
                    direct_53_refused: false,
                    allowed_tuples_only: false,
                },
                seccomp_profile: SeccompEvidence {
                    path: PathBuf::from(SECCOMP_PROFILE_PATH),
                    sha256: SECCOMP_PROFILE_SHA256.into(),
                },
                sanitized_artifact_store_path: "/var/lib/buzzci/artifacts/normal".into(),
                sanitized_log_store_path: "/var/lib/buzzci/logs/normal".into(),
                created_at_unix_ns: 1,
            },
            event_binding,
            act,
        };
        OrdinaryFixture {
            _root: root,
            request,
            admission,
            lease,
            plan,
            event_binding,
            lease_id,
        }
    }

    type TestEngine = ProductionOrdinaryEngine<OnePlan, FakeBackend>;
    type TestEngineFixture = (OrdinaryFixture, TestEngine, Rc<RefCell<Vec<&'static str>>>);

    fn build_engine(
        fail: FailStage,
        incomplete_teardown: bool,
        bad_terminal_order: bool,
    ) -> TestEngineFixture {
        let fixture = ordinary_fixture();
        let log = Rc::new(RefCell::new(Vec::new()));
        let backend = FakeBackend {
            fail,
            log: Rc::clone(&log),
            event_binding: fixture.event_binding,
            lease_id: fixture.lease_id.clone(),
            incomplete_teardown,
            bad_terminal_order,
        };
        let plan = clone_plan(&fixture);
        (
            fixture,
            ProductionOrdinaryEngine::new(OnePlan(Some(plan)), backend),
            log,
        )
    }

    fn clone_plan(fixture: &OrdinaryFixture) -> NormalJobPlan {
        NormalJobPlan {
            binding: fixture.plan.binding.clone(),
            validation: fixture.plan.validation.clone(),
            evidence_root: fixture.plan.evidence_root.clone(),
            lease_record: fixture.plan.lease_record.clone(),
            event_binding: fixture.plan.event_binding,
            act: fixture.plan.act.clone(),
        }
    }

    fn run_to_terminal(
        fixture: &OrdinaryFixture,
        engine: &mut impl OrdinaryExecutor,
    ) -> Result<OrdinaryReceipts, ExecutionUnavailable> {
        engine.preflight(fixture.request, fixture.admission)?;
        engine.provision(fixture.request, fixture.admission, fixture.lease)?;
        engine.read_receipts(fixture.request, fixture.admission, fixture.lease)
    }

    #[test]
    fn happy_path_enforces_prestart_and_publishes_clean_teardown() {
        let (fixture, mut engine, log) = build_engine(FailStage::None, false, false);
        let receipts = run_to_terminal(&fixture, &mut engine).unwrap();
        assert_eq!(receipts.conclusion, LeaseConclusion::Success);
        let cleanup = engine
            .reconcile(
                fixture.request,
                fixture.admission,
                fixture.lease,
                OrdinaryStop::Completed(LeaseConclusion::Success),
            )
            .unwrap();
        assert_eq!(cleanup.disposition, CleanupDisposition::Clean);
        assert_eq!(cleanup.teardown_digest, [62; 32]);
        assert_eq!(
            log.borrow().as_slice(),
            [
                "preflight",
                "dns",
                "materialize",
                "prestart",
                "proxy-start",
                "act-start",
                "terminal",
                "cleanup"
            ]
        );
    }

    #[test]
    fn every_failed_stage_reconciles_closed() {
        for stage in [
            FailStage::Dns,
            FailStage::Materialize,
            FailStage::Proxy,
            FailStage::Act,
        ] {
            let (fixture, mut engine, _) = build_engine(stage, false, false);
            engine
                .preflight(fixture.request, fixture.admission)
                .unwrap();
            assert!(engine
                .provision(fixture.request, fixture.admission, fixture.lease)
                .is_err());
            let cleanup = engine
                .reconcile(
                    fixture.request,
                    fixture.admission,
                    fixture.lease,
                    OrdinaryStop::Completed(LeaseConclusion::InfrastructureFailure),
                )
                .unwrap();
            assert_eq!(cleanup.disposition, CleanupDisposition::Ambiguous);
            assert_eq!(cleanup.teardown_digest, [0; 32]);
        }

        let (fixture, mut engine, _) = build_engine(FailStage::Terminal, false, false);
        engine
            .preflight(fixture.request, fixture.admission)
            .unwrap();
        engine
            .provision(fixture.request, fixture.admission, fixture.lease)
            .unwrap();
        assert!(engine
            .read_receipts(fixture.request, fixture.admission, fixture.lease)
            .is_err());
        assert_eq!(
            engine
                .reconcile(
                    fixture.request,
                    fixture.admission,
                    fixture.lease,
                    OrdinaryStop::Completed(LeaseConclusion::InfrastructureFailure),
                )
                .unwrap()
                .disposition,
            CleanupDisposition::Ambiguous
        );

        let (fixture, mut engine, _) = build_engine(FailStage::Cleanup, false, false);
        run_to_terminal(&fixture, &mut engine).unwrap();
        assert!(engine
            .reconcile(
                fixture.request,
                fixture.admission,
                fixture.lease,
                OrdinaryStop::Completed(LeaseConclusion::Success),
            )
            .is_err());
    }

    #[test]
    fn preflight_terminal_order_and_teardown_are_fail_closed() {
        let (fixture, mut engine, _) = build_engine(FailStage::Preflight, false, false);
        assert!(engine
            .preflight(fixture.request, fixture.admission)
            .is_err());

        let (fixture, mut engine, _) = build_engine(FailStage::None, false, true);
        engine
            .preflight(fixture.request, fixture.admission)
            .unwrap();
        engine
            .provision(fixture.request, fixture.admission, fixture.lease)
            .unwrap();
        assert!(engine
            .read_receipts(fixture.request, fixture.admission, fixture.lease)
            .is_err());

        let (fixture, mut engine, _) = build_engine(FailStage::None, true, false);
        run_to_terminal(&fixture, &mut engine).unwrap();
        assert!(engine
            .reconcile(
                fixture.request,
                fixture.admission,
                fixture.lease,
                OrdinaryStop::Completed(LeaseConclusion::Success),
            )
            .is_err());
    }

    #[derive(Clone)]
    struct NormalQualificationFake {
        calls: Rc<RefCell<Vec<&'static str>>>,
    }

    impl NormalQualificationBackend for NormalQualificationFake {
        fn preflight(
            &mut self,
            _request: QualificationRequest,
        ) -> Result<(), ExecutionUnavailable> {
            self.calls.borrow_mut().push("normal-preflight");
            Ok(())
        }

        fn execute(
            &mut self,
            _request: QualificationRequest,
            _lease: QualificationLease,
            _now: u64,
        ) -> Result<QualificationOutcome, ExecutionUnavailable> {
            self.calls.borrow_mut().push("normal-execute");
            Ok(QualificationOutcome::Accepted {
                evidence_set_digest: [71; 32],
            })
        }
    }

    struct TeardownQualificationFake {
        calls: Rc<RefCell<Vec<&'static str>>>,
    }

    impl QualificationExecutor for TeardownQualificationFake {
        fn preflight(
            &mut self,
            _request: QualificationRequest,
        ) -> Result<(), ExecutionUnavailable> {
            self.calls.borrow_mut().push("teardown-preflight");
            Ok(())
        }

        fn execute(
            &mut self,
            _header: FrameHeader,
            _request: QualificationRequest,
            _lease: QualificationLease,
            now: u64,
        ) -> Result<QualificationExecution, ExecutionUnavailable> {
            self.calls.borrow_mut().push("teardown-execute");
            Ok(QualificationExecution {
                terminal: QualificationTerminal::TeardownFailure,
                response: empty_response(now),
            })
        }
    }

    fn qualification_request(directive: Option<QualificationDirective>) -> QualificationRequest {
        QualificationRequest {
            integrated_candidate_sha: GitOid::Sha256([1; 32]),
            broker_build_identity: [2; 32],
            host_profile_digest: [3; 32],
            suite_identity: [4; 32],
            fixture_signer: FIXTURE_SIGNER.0,
            request_digest: [5; 32],
            manifest_digest: [6; 32],
            isolation_profile_digest: [7; 32],
            source_oid: GitOid::Sha256([8; 32]),
            base_oid: GitOid::Sha256([9; 32]),
            job_identity: [10; 32],
            fixture_identity: [11; 32],
            nonce: [12; 32],
            not_before: 1,
            expires_at: 100,
            directive,
        }
    }

    fn qualification_lease(directive: Option<QualificationDirective>) -> QualificationLease {
        let request = qualification_request(directive);
        let permit = QualificationPermit {
            authorized_by: ROOT,
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
            fixture_signer: FIXTURE_SIGNER,
            nonce: request.nonce,
            not_before: request.not_before,
            expires_at: request.expires_at,
            directive,
        };
        let admission = QualificationAdmission {
            host: permit.host,
            fixture_job: permit.fixture_job,
            fixture_identity: permit.fixture_identity,
            signer: permit.fixture_signer,
            nonce: permit.nonce,
            not_before: permit.not_before,
            expires_at: permit.expires_at,
            directive,
            trust_class: AdmissionTrustClass::QualificationFixture,
        };
        let mut controller = ActivationController::new(ROOT);
        controller.start_qualification(permit).unwrap();
        controller.admit_qualification(admission, 10).unwrap()
    }

    fn empty_response(now: u64) -> BrokerResponse {
        BrokerResponse {
            code: ResponseCode::InternalFailure,
            retry_after_millis: 0,
            attempt_id: [0; 16],
            run_id: [0; 16],
            accepted_request_digest: [0; 32],
            job_manifest_digest: [0; 32],
            tip_oid: None,
            broker_state: BrokerState::Quarantined,
            conclusion: Conclusion::InfrastructureFailure,
            terminal_reason: 1,
            generation: 1,
            accepted_at: now,
            updated_at: now,
            lease_generation: 1,
            evidence_set_digest: [0; 32],
            teardown_digest: [0; 32],
            attempt: 1,
        }
    }

    #[test]
    fn qualification_multiplexer_routes_both_closed_directives() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let normal = NormalQualificationExecutor::new(NormalQualificationFake {
            calls: Rc::clone(&calls),
        });
        let teardown = TeardownQualificationFake {
            calls: Rc::clone(&calls),
        };
        let mut mux = QualificationMultiplexer::new(normal, teardown);
        let header = FrameHeader {
            operation: Operation::AdmitQualification,
            request_id: [1; 16],
        };

        let normal_request = qualification_request(None);
        mux.preflight(normal_request).unwrap();
        let normal_result = mux
            .execute(header, normal_request, qualification_lease(None), 10)
            .unwrap();
        assert!(matches!(
            normal_result.terminal,
            QualificationTerminal::Completed(QualificationOutcome::Accepted { .. })
        ));

        let directive = Some(QualificationDirective::TeardownFailure);
        let teardown_request = qualification_request(directive);
        mux.preflight(teardown_request).unwrap();
        let teardown_result = mux
            .execute(header, teardown_request, qualification_lease(directive), 10)
            .unwrap();
        assert_eq!(
            teardown_result.terminal,
            QualificationTerminal::TeardownFailure
        );
        assert_eq!(
            calls.borrow().as_slice(),
            [
                "normal-preflight",
                "normal-execute",
                "teardown-preflight",
                "teardown-execute"
            ]
        );
    }
}
