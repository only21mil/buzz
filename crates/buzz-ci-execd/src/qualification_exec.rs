//! Concrete in-process teardown executor for the qualification fixture.
//!
//! The executor accepts only typed operations derived from an admitted opaque
//! lease. It never accepts a command, program, argument list, path, or fault
//! name from the wire.

use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use buzz_ci_broker_protocol::{
    BrokerResponse, BrokerState, Conclusion, FrameHeader, GitOid, QualificationRequest,
    ResponseCode,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{
    activation::QualificationLease,
    durable_dispatch::{
        ExecutionUnavailable, QualificationExecution, QualificationExecutor, QualificationTerminal,
    },
    qualification_host::{
        QualificationHostBinding, QualificationHostExecution, QualificationHostOutcome,
        QualificationHostPlan, QualificationHostReceipt, QualificationTerminalEvent,
        QUALIFICATION_TERMINAL_ORDER,
    },
};

pub const QUALIFICATION_CLEANUP_RECEIPT_ROOT: &str = "/var/lib/buzzci/activation/receipts/cleanup";
const ACTIVATION_ROOT: &str = "/var/lib/buzzci/activation";
const LEASE_ROOT: &str = "/var/lib/buzzci/leases";
const NETWORK_NAMESPACE_ROOT: &str = "/run/netns";
const CGROUP_ROOT: &str = "/buzzci.slice";
const NFT_FAMILY: &str = "inet";
const DIRECTORY_MODE: u32 = 0o700;
const RECEIPT_MODE: u32 = 0o600;
const RECEIPT_VERSION: u8 = 1;
const MAX_RECEIPT_BYTES: usize = 64 * 1024;

/// Exact lease-owned host targets. Callers cannot construct or alter them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QualificationCleanupTargets {
    lease_slice: String,
    lease_cgroup: PathBuf,
    namespace_name: String,
    namespace_path: PathBuf,
    nft_family: &'static str,
    nft_table: String,
    lease_files: PathBuf,
}

impl QualificationCleanupTargets {
    fn from_binding(binding: QualificationHostBinding) -> Self {
        let lease_id = hex::encode(binding.lease_id);
        let lease_slice = format!("buzzci-{lease_id}.slice");
        let namespace_name = format!("buzzci-{lease_id}");
        Self {
            lease_cgroup: Path::new(CGROUP_ROOT).join(&lease_slice),
            namespace_path: Path::new(NETWORK_NAMESPACE_ROOT).join(&namespace_name),
            nft_table: format!("buzzci_{lease_id}"),
            lease_files: Path::new(LEASE_ROOT).join(&lease_id),
            lease_slice,
            namespace_name,
            nft_family: NFT_FAMILY,
        }
    }

    pub fn lease_slice(&self) -> &str {
        &self.lease_slice
    }

    pub fn lease_cgroup(&self) -> &Path {
        &self.lease_cgroup
    }

    pub fn namespace_name(&self) -> &str {
        &self.namespace_name
    }

    pub fn namespace_path(&self) -> &Path {
        &self.namespace_path
    }

    pub const fn nft_family(&self) -> &'static str {
        self.nft_family
    }

    pub fn nft_table(&self) -> &str {
        &self.nft_table
    }

    pub fn lease_files(&self) -> &Path {
        &self.lease_files
    }
}

/// Closed cleanup operations. There is no generic command variant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QualificationCleanupOperation {
    StopLeaseSlice,
    KillLeaseSlice,
    RemoveLeaseNftTable,
    RemoveLeaseNetworkNamespace,
    RemoveLeaseFiles,
}

const CLEANUP_OPERATIONS: [QualificationCleanupOperation; 5] = [
    QualificationCleanupOperation::StopLeaseSlice,
    QualificationCleanupOperation::KillLeaseSlice,
    QualificationCleanupOperation::RemoveLeaseNftTable,
    QualificationCleanupOperation::RemoveLeaseNetworkNamespace,
    QualificationCleanupOperation::RemoveLeaseFiles,
];

/// Bounded post-cleanup observation from the privileged typed runner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QualificationCleanupObservation {
    pub lease_slice_inactive: bool,
    pub lease_cgroup_empty: bool,
    pub nft_table_absent: bool,
    pub namespace_absent: bool,
    pub lease_files_absent: bool,
    pub teardown_failure_observed: bool,
    pub slice_quarantined: bool,
    pub publish_observed: bool,
}

impl QualificationCleanupObservation {
    fn complete(self) -> bool {
        self.lease_slice_inactive
            && self.lease_cgroup_empty
            && self.nft_table_absent
            && self.namespace_absent
            && self.lease_files_absent
            && self.teardown_failure_observed
            && self.slice_quarantined
            && !self.publish_observed
    }
}

/// Narrow privileged runner. Production adapters match only these typed values.
pub trait QualificationCleanupRunner {
    type Error;

    fn execute(
        &mut self,
        operation: &QualificationCleanupOperation,
        targets: &QualificationCleanupTargets,
    ) -> Result<(), Self::Error>;

    fn observe(
        &mut self,
        targets: &QualificationCleanupTargets,
    ) -> Result<Option<QualificationCleanupObservation>, Self::Error>;
}

/// Concrete cleanup executor plus its atomic receipt store.
pub struct QualificationCleanupExecutor<R> {
    runner: R,
    receipts: CleanupReceiptStore,
}

impl<R> QualificationCleanupExecutor<R> {
    /// Construct the production executor rooted at the canonical activation path.
    pub fn new(runner: R) -> Self {
        Self {
            runner,
            receipts: CleanupReceiptStore::canonical(),
        }
    }

    #[cfg(test)]
    fn for_test(runner: R, activation_root: PathBuf, uid: u32, gid: u32) -> Self {
        Self {
            runner,
            receipts: CleanupReceiptStore {
                activation_root,
                expected_uid: uid,
                expected_gid: gid,
            },
        }
    }

    #[cfg(test)]
    fn runner(&self) -> &R {
        &self.runner
    }
}

impl<R: QualificationCleanupRunner> QualificationCleanupExecutor<R> {
    pub fn execute(&mut self, plan: QualificationHostPlan) -> QualificationHostExecution {
        let targets = QualificationCleanupTargets::from_binding(plan.binding());
        let mut completed = [false; CLEANUP_OPERATIONS.len()];
        for (index, operation) in CLEANUP_OPERATIONS.iter().enumerate() {
            completed[index] = self.runner.execute(operation, &targets).is_ok();
        }

        let observation = self.runner.observe(&targets);
        let observed = observation.as_ref().ok().copied().flatten();
        let observation_failed = observation.is_err();
        let execution = match (observation_failed, observed) {
            (false, Some(observation))
                if completed.iter().all(|value| *value) && observation.complete() =>
            {
                let teardown_digest = evidence_digest(b"teardown-failure-v1", plan.binding());
                let no_publish_digest = evidence_digest(b"no-publish-v1", plan.binding());
                let quarantine_digest = evidence_digest(b"quarantine-v1", plan.binding());
                match QualificationHostReceipt::new(
                    plan,
                    QUALIFICATION_TERMINAL_ORDER,
                    teardown_digest,
                    no_publish_digest,
                    quarantine_digest,
                ) {
                    Ok(receipt) => QualificationHostExecution::Complete(receipt),
                    Err(_) => QualificationHostExecution::Ambiguous,
                }
            }
            (false, None) if completed.iter().all(|value| *value) => {
                QualificationHostExecution::Missing
            }
            _ => QualificationHostExecution::Ambiguous,
        };

        if self
            .receipts
            .persist(plan, &targets, completed, observed, execution)
            .is_err()
        {
            return QualificationHostExecution::Ambiguous;
        }
        execution
    }
}

impl<R: QualificationCleanupRunner> QualificationExecutor for QualificationCleanupExecutor<R> {
    fn preflight(&mut self, request: QualificationRequest) -> Result<(), ExecutionUnavailable> {
        if request.directive
            == Some(buzz_ci_broker_protocol::QualificationDirective::TeardownFailure)
        {
            Ok(())
        } else {
            Err(ExecutionUnavailable)
        }
    }

    fn execute(
        &mut self,
        _header: FrameHeader,
        request: QualificationRequest,
        lease: QualificationLease,
        now: u64,
    ) -> Result<QualificationExecution, ExecutionUnavailable> {
        let outcome = QualificationHostPlan::from_admitted(request, lease)
            .ok()
            .map(|plan| {
                QualificationHostOutcome::evaluate(
                    plan,
                    QualificationCleanupExecutor::execute(self, plan),
                )
            });
        Ok(QualificationExecution {
            terminal: QualificationTerminal::TeardownFailure,
            response: qualification_teardown_response(request, lease, outcome, now),
        })
    }
}

fn qualification_teardown_response(
    request: QualificationRequest,
    lease: QualificationLease,
    outcome: Option<QualificationHostOutcome>,
    now: u64,
) -> BrokerResponse {
    let complete = outcome.is_some_and(QualificationHostOutcome::is_complete);
    BrokerResponse {
        code: if complete {
            ResponseCode::Ok
        } else {
            ResponseCode::InternalFailure
        },
        retry_after_millis: 0,
        attempt_id: lease.lease_id(),
        run_id: [0; 16],
        accepted_request_digest: request.request_digest,
        job_manifest_digest: request.manifest_digest,
        tip_oid: Some(request.integrated_candidate_sha),
        broker_state: BrokerState::Quarantined,
        conclusion: Conclusion::InfrastructureFailure,
        terminal_reason: 1,
        generation: lease.generation(),
        accepted_at: now,
        updated_at: now,
        lease_generation: lease.generation(),
        evidence_set_digest: outcome.map_or([0; 32], QualificationHostOutcome::no_publish_digest),
        teardown_digest: outcome.map_or([0; 32], QualificationHostOutcome::teardown_digest),
        attempt: 1,
    }
}

#[derive(Clone)]
struct CleanupReceiptStore {
    activation_root: PathBuf,
    expected_uid: u32,
    expected_gid: u32,
}

impl CleanupReceiptStore {
    fn canonical() -> Self {
        Self {
            activation_root: ACTIVATION_ROOT.into(),
            expected_uid: 0,
            expected_gid: 0,
        }
    }

    fn persist(
        &self,
        plan: QualificationHostPlan,
        targets: &QualificationCleanupTargets,
        completed: [bool; CLEANUP_OPERATIONS.len()],
        observation: Option<QualificationCleanupObservation>,
        execution: QualificationHostExecution,
    ) -> Result<(), QualificationCleanupPersistError> {
        validate_directory(&self.activation_root, self.expected_uid, self.expected_gid)?;
        let receipts = ensure_child_directory(
            &self.activation_root,
            "receipts",
            self.expected_uid,
            self.expected_gid,
        )?;
        let cleanup =
            ensure_child_directory(&receipts, "cleanup", self.expected_uid, self.expected_gid)?;
        let lease = hex::encode(plan.binding().lease_id);
        let name = format!("{lease}-g{}.json", plan.binding().lease_generation);
        let destination = cleanup.join(&name);
        if destination.exists() {
            return Err(QualificationCleanupPersistError);
        }
        let temporary = cleanup.join(format!(".{name}.tmp"));
        let receipt = CleanupReceiptDisk::new(plan, targets, completed, observation, execution);
        let bytes = serde_json::to_vec(&receipt).map_err(|_| QualificationCleanupPersistError)?;
        if bytes.is_empty() || bytes.len() > MAX_RECEIPT_BYTES {
            return Err(QualificationCleanupPersistError);
        }

        let mut options = OpenOptions::new();
        options
            .create_new(true)
            .write(true)
            .mode(RECEIPT_MODE)
            .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
        let result = (|| {
            let mut file = options
                .open(&temporary)
                .map_err(|_| QualificationCleanupPersistError)?;
            file.write_all(&bytes)
                .and_then(|()| file.sync_all())
                .map_err(|_| QualificationCleanupPersistError)?;
            fs::rename(&temporary, &destination).map_err(|_| QualificationCleanupPersistError)?;
            File::open(&cleanup)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| QualificationCleanupPersistError)?;
            validate_receipt(
                &destination,
                bytes.len() as u64,
                self.expected_uid,
                self.expected_gid,
            )
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct QualificationCleanupPersistError;

fn ensure_child_directory(
    parent: &Path,
    name: &str,
    uid: u32,
    gid: u32,
) -> Result<PathBuf, QualificationCleanupPersistError> {
    let path = parent.join(name);
    match fs::create_dir(&path) {
        Ok(()) => fs::set_permissions(&path, fs::Permissions::from_mode(DIRECTORY_MODE))
            .map_err(|_| QualificationCleanupPersistError)?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(QualificationCleanupPersistError),
    }
    validate_directory(&path, uid, gid)?;
    Ok(path)
}

fn validate_directory(
    path: &Path,
    uid: u32,
    gid: u32,
) -> Result<(), QualificationCleanupPersistError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| QualificationCleanupPersistError)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.permissions().mode() & 0o7777 != DIRECTORY_MODE
    {
        return Err(QualificationCleanupPersistError);
    }
    Ok(())
}

fn validate_receipt(
    path: &Path,
    expected_len: u64,
    uid: u32,
    gid: u32,
) -> Result<(), QualificationCleanupPersistError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| QualificationCleanupPersistError)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o7777 != RECEIPT_MODE
        || metadata.len() != expected_len
    {
        return Err(QualificationCleanupPersistError);
    }
    Ok(())
}

fn evidence_digest(domain: &[u8], binding: QualificationHostBinding) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(domain);
    update_oid(&mut digest, binding.integrated_candidate_sha);
    digest.update(binding.broker_build_identity);
    digest.update(binding.host_profile_digest);
    digest.update(binding.suite_identity);
    digest.update(binding.fixture_signer);
    digest.update(binding.request_digest);
    digest.update(binding.manifest_digest);
    digest.update(binding.isolation_profile_digest);
    update_oid(&mut digest, binding.source_oid);
    update_oid(&mut digest, binding.base_oid);
    digest.update(binding.job_identity);
    digest.update(binding.fixture_identity);
    digest.update(binding.nonce);
    digest.update(binding.lease_id);
    digest.update(binding.lease_generation.to_be_bytes());
    digest.finalize().into()
}

fn update_oid(digest: &mut Sha256, oid: GitOid) {
    match oid {
        GitOid::Sha1(bytes) => {
            digest.update([1]);
            digest.update(bytes);
        }
        GitOid::Sha256(bytes) => {
            digest.update([2]);
            digest.update(bytes);
        }
    }
}

#[derive(Serialize)]
struct CleanupReceiptDisk {
    version: u8,
    committed: bool,
    binding: CleanupBindingDisk,
    targets: CleanupTargetsDisk,
    operations: Vec<CleanupOperationDisk>,
    observation: Option<CleanupObservationDisk>,
    terminal_order: Vec<CleanupTerminalDisk>,
    conclusion: &'static str,
    state: &'static str,
    publication: &'static str,
    evidence_state: &'static str,
    teardown_digest: String,
    no_publish_digest: String,
    quarantine_digest: String,
}

impl CleanupReceiptDisk {
    fn new(
        plan: QualificationHostPlan,
        targets: &QualificationCleanupTargets,
        completed: [bool; CLEANUP_OPERATIONS.len()],
        observation: Option<QualificationCleanupObservation>,
        execution: QualificationHostExecution,
    ) -> Self {
        let outcome = QualificationHostOutcome::evaluate(plan, execution);
        let receipt = outcome.receipt();
        Self {
            version: RECEIPT_VERSION,
            committed: true,
            binding: CleanupBindingDisk::new(plan.binding()),
            targets: CleanupTargetsDisk::new(targets),
            operations: CLEANUP_OPERATIONS
                .iter()
                .zip(completed)
                .map(|(operation, completed)| CleanupOperationDisk {
                    operation: operation_name(operation),
                    completed,
                })
                .collect(),
            observation: observation.map(CleanupObservationDisk::from),
            terminal_order: receipt
                .map(|receipt| {
                    receipt
                        .terminal_order()
                        .into_iter()
                        .map(|record| CleanupTerminalDisk {
                            sequence: record.sequence,
                            event: terminal_event_name(record.event),
                        })
                        .collect()
                })
                .unwrap_or_default(),
            conclusion: "infrastructure_failure",
            state: "quarantined",
            publication: "suppressed",
            evidence_state: match outcome.evidence_state {
                crate::qualification_host::QualificationHostEvidenceState::Complete => "complete",
                crate::qualification_host::QualificationHostEvidenceState::Missing => "missing",
                crate::qualification_host::QualificationHostEvidenceState::Ambiguous => "ambiguous",
                crate::qualification_host::QualificationHostEvidenceState::BindingMismatch => {
                    "binding_mismatch"
                }
            },
            teardown_digest: receipt.map_or_else(String::new, |value| {
                hex::encode(value.teardown_failure_evidence_digest())
            }),
            no_publish_digest: receipt.map_or_else(String::new, |value| {
                hex::encode(value.no_publish_evidence_digest())
            }),
            quarantine_digest: receipt.map_or_else(String::new, |value| {
                hex::encode(value.quarantine_evidence_digest())
            }),
        }
    }
}

#[derive(Serialize)]
struct CleanupBindingDisk {
    integrated_candidate: OidDisk,
    broker_build_identity: String,
    host_profile_digest: String,
    suite_identity: String,
    fixture_signer: String,
    request_digest: String,
    manifest_digest: String,
    isolation_profile_digest: String,
    source: OidDisk,
    base: OidDisk,
    job_identity: String,
    fixture_identity: String,
    nonce: String,
    lease_id: String,
    lease_generation: u64,
}

impl CleanupBindingDisk {
    fn new(binding: QualificationHostBinding) -> Self {
        Self {
            integrated_candidate: OidDisk::new(binding.integrated_candidate_sha),
            broker_build_identity: hex::encode(binding.broker_build_identity),
            host_profile_digest: hex::encode(binding.host_profile_digest),
            suite_identity: hex::encode(binding.suite_identity),
            fixture_signer: hex::encode(binding.fixture_signer),
            request_digest: hex::encode(binding.request_digest),
            manifest_digest: hex::encode(binding.manifest_digest),
            isolation_profile_digest: hex::encode(binding.isolation_profile_digest),
            source: OidDisk::new(binding.source_oid),
            base: OidDisk::new(binding.base_oid),
            job_identity: hex::encode(binding.job_identity),
            fixture_identity: hex::encode(binding.fixture_identity),
            nonce: hex::encode(binding.nonce),
            lease_id: hex::encode(binding.lease_id),
            lease_generation: binding.lease_generation,
        }
    }
}

#[derive(Serialize)]
struct OidDisk {
    algorithm: &'static str,
    bytes: String,
}

impl OidDisk {
    fn new(oid: GitOid) -> Self {
        match oid {
            GitOid::Sha1(bytes) => Self {
                algorithm: "sha1",
                bytes: hex::encode(bytes),
            },
            GitOid::Sha256(bytes) => Self {
                algorithm: "sha256",
                bytes: hex::encode(bytes),
            },
        }
    }
}

#[derive(Serialize)]
struct CleanupTargetsDisk {
    lease_slice: String,
    lease_cgroup: PathBuf,
    namespace_name: String,
    namespace_path: PathBuf,
    nft_family: &'static str,
    nft_table: String,
    lease_files: PathBuf,
}

impl CleanupTargetsDisk {
    fn new(targets: &QualificationCleanupTargets) -> Self {
        Self {
            lease_slice: targets.lease_slice.clone(),
            lease_cgroup: targets.lease_cgroup.clone(),
            namespace_name: targets.namespace_name.clone(),
            namespace_path: targets.namespace_path.clone(),
            nft_family: targets.nft_family,
            nft_table: targets.nft_table.clone(),
            lease_files: targets.lease_files.clone(),
        }
    }
}

#[derive(Serialize)]
struct CleanupOperationDisk {
    operation: &'static str,
    completed: bool,
}

#[derive(Serialize)]
struct CleanupObservationDisk {
    lease_slice_inactive: bool,
    lease_cgroup_empty: bool,
    nft_table_absent: bool,
    namespace_absent: bool,
    lease_files_absent: bool,
    teardown_failure_observed: bool,
    slice_quarantined: bool,
    publish_observed: bool,
}

impl From<QualificationCleanupObservation> for CleanupObservationDisk {
    fn from(value: QualificationCleanupObservation) -> Self {
        Self {
            lease_slice_inactive: value.lease_slice_inactive,
            lease_cgroup_empty: value.lease_cgroup_empty,
            nft_table_absent: value.nft_table_absent,
            namespace_absent: value.namespace_absent,
            lease_files_absent: value.lease_files_absent,
            teardown_failure_observed: value.teardown_failure_observed,
            slice_quarantined: value.slice_quarantined,
            publish_observed: value.publish_observed,
        }
    }
}

#[derive(Serialize)]
struct CleanupTerminalDisk {
    sequence: u8,
    event: &'static str,
}

fn operation_name(operation: &QualificationCleanupOperation) -> &'static str {
    match operation {
        QualificationCleanupOperation::StopLeaseSlice => "stop_lease_slice",
        QualificationCleanupOperation::KillLeaseSlice => "kill_lease_slice",
        QualificationCleanupOperation::RemoveLeaseNftTable => "remove_lease_nft_table",
        QualificationCleanupOperation::RemoveLeaseNetworkNamespace => {
            "remove_lease_network_namespace"
        }
        QualificationCleanupOperation::RemoveLeaseFiles => "remove_lease_files",
    }
}

fn terminal_event_name(event: QualificationTerminalEvent) -> &'static str {
    match event {
        QualificationTerminalEvent::Stop => "stop",
        QualificationTerminalEvent::FinalizeRawStream => "finalize_raw_stream",
        QualificationTerminalEvent::Extract => "extract",
        QualificationTerminalEvent::Scrub => "scrub",
        QualificationTerminalEvent::Scan => "scan",
        QualificationTerminalEvent::Hash => "hash",
        QualificationTerminalEvent::Upload => "upload",
        QualificationTerminalEvent::TeardownFailureObserved => "teardown_failure_observed",
        QualificationTerminalEvent::PublicationSuppressed => "publication_suppressed",
        QualificationTerminalEvent::Quarantined => "quarantined",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::activation::{
        ActivationController, FixtureJobCoordinates, HostActivationCoordinates,
        QualificationPermit, VerifiedSigner,
    };
    use buzz_ci_broker_protocol::{Operation, QualificationDirective};

    #[derive(Clone, Copy)]
    enum FakeObservation {
        Complete,
        Missing,
        PublishSeen,
        Error,
    }

    struct FakeRunner {
        operations: Vec<QualificationCleanupOperation>,
        targets: Option<QualificationCleanupTargets>,
        fail_operation: Option<usize>,
        observation: FakeObservation,
    }

    impl QualificationCleanupRunner for FakeRunner {
        type Error = ();

        fn execute(
            &mut self,
            operation: &QualificationCleanupOperation,
            targets: &QualificationCleanupTargets,
        ) -> Result<(), Self::Error> {
            self.targets = Some(targets.clone());
            self.operations.push(operation.clone());
            if self.fail_operation == Some(self.operations.len() - 1) {
                Err(())
            } else {
                Ok(())
            }
        }

        fn observe(
            &mut self,
            targets: &QualificationCleanupTargets,
        ) -> Result<Option<QualificationCleanupObservation>, Self::Error> {
            self.targets = Some(targets.clone());
            match self.observation {
                FakeObservation::Complete => Ok(Some(QualificationCleanupObservation {
                    lease_slice_inactive: true,
                    lease_cgroup_empty: true,
                    nft_table_absent: true,
                    namespace_absent: true,
                    lease_files_absent: true,
                    teardown_failure_observed: true,
                    slice_quarantined: true,
                    publish_observed: false,
                })),
                FakeObservation::Missing => Ok(None),
                FakeObservation::PublishSeen => Ok(Some(QualificationCleanupObservation {
                    lease_slice_inactive: true,
                    lease_cgroup_empty: true,
                    nft_table_absent: true,
                    namespace_absent: true,
                    lease_files_absent: true,
                    teardown_failure_observed: true,
                    slice_quarantined: true,
                    publish_observed: true,
                })),
                FakeObservation::Error => Err(()),
            }
        }
    }

    fn admitted_fixture() -> (QualificationRequest, QualificationLease) {
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
            directive: Some(QualificationDirective::TeardownFailure),
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
            directive: permit.directive,
        };
        let mut controller = ActivationController::new(root);
        controller.start_qualification(permit).unwrap();
        let lease = controller
            .admit_qualification_request(request, signer, 10)
            .unwrap();
        (request, lease)
    }

    fn admitted_plan() -> QualificationHostPlan {
        let (request, lease) = admitted_fixture();
        QualificationHostPlan::from_admitted(request, lease).unwrap()
    }

    fn executor(
        root: &Path,
        observation: FakeObservation,
        fail_operation: Option<usize>,
    ) -> QualificationCleanupExecutor<FakeRunner> {
        fs::create_dir(root).unwrap();
        fs::set_permissions(root, fs::Permissions::from_mode(DIRECTORY_MODE)).unwrap();
        let metadata = root.metadata().unwrap();
        QualificationCleanupExecutor::for_test(
            FakeRunner {
                operations: Vec::new(),
                targets: None,
                fail_operation,
                observation,
            },
            root.to_path_buf(),
            metadata.uid(),
            metadata.gid(),
        )
    }

    fn receipt_path(root: &Path) -> PathBuf {
        root.join("receipts/cleanup")
            .join(format!("{}-g1.json", hex::encode([13; 16])))
    }

    #[test]
    fn complete_cleanup_runs_exact_operations_and_persists_bound_receipt() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("activation");
        let mut executor = executor(&root, FakeObservation::Complete, None);
        let execution = executor.execute(admitted_plan());
        assert!(matches!(execution, QualificationHostExecution::Complete(_)));
        assert_eq!(executor.runner().operations, CLEANUP_OPERATIONS);
        let targets = executor.runner().targets.as_ref().unwrap();
        let lease = hex::encode([13; 16]);
        assert_eq!(targets.lease_slice(), format!("buzzci-{lease}.slice"));
        assert_eq!(targets.namespace_name(), format!("buzzci-{lease}"));
        assert_eq!(targets.nft_table(), format!("buzzci_{lease}"));
        assert_eq!(targets.lease_files(), Path::new(LEASE_ROOT).join(&lease));

        let destination = receipt_path(&root);
        let metadata = destination.metadata().unwrap();
        assert_eq!(metadata.permissions().mode() & 0o7777, RECEIPT_MODE);
        let value: serde_json::Value =
            serde_json::from_slice(&fs::read(destination).unwrap()).unwrap();
        assert_eq!(value["version"], 1);
        assert_eq!(value["committed"], true);
        assert_eq!(
            value["binding"]["integrated_candidate"]["bytes"],
            hex::encode([3; 32])
        );
        assert_eq!(
            value["binding"]["broker_build_identity"],
            hex::encode([4; 32])
        );
        assert_eq!(
            value["binding"]["host_profile_digest"],
            hex::encode([5; 32])
        );
        assert_eq!(value["binding"]["lease_generation"], 1);
        assert_eq!(value["binding"]["suite_identity"], hex::encode([6; 32]));
        assert_eq!(value["binding"]["fixture_signer"], hex::encode([2; 32]));
        assert_eq!(value["binding"]["request_digest"], hex::encode([7; 32]));
        assert_eq!(value["binding"]["manifest_digest"], hex::encode([8; 32]));
        assert_eq!(
            value["binding"]["isolation_profile_digest"],
            hex::encode([9; 32])
        );
        assert_eq!(value["binding"]["source"]["bytes"], hex::encode([10; 32]));
        assert_eq!(value["binding"]["base"]["bytes"], hex::encode([11; 32]));
        assert_eq!(value["binding"]["job_identity"], hex::encode([12; 32]));
        assert_eq!(value["binding"]["fixture_identity"], hex::encode([13; 32]));
        assert_eq!(value["binding"]["nonce"], hex::encode([14; 32]));
        assert_eq!(value["binding"]["lease_id"], hex::encode([13; 16]));
        assert_eq!(
            value["operations"]
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| entry["operation"].as_str().unwrap())
                .collect::<Vec<_>>(),
            [
                "stop_lease_slice",
                "kill_lease_slice",
                "remove_lease_nft_table",
                "remove_lease_network_namespace",
                "remove_lease_files",
            ]
        );
        assert!(value["operations"]
            .as_array()
            .unwrap()
            .iter()
            .all(|entry| entry["completed"] == true));
        assert_eq!(value["conclusion"], "infrastructure_failure");
        assert_eq!(value["state"], "quarantined");
        assert_eq!(value["publication"], "suppressed");
        assert_eq!(value["evidence_state"], "complete");
        assert_eq!(value["terminal_order"].as_array().unwrap().len(), 10);
        assert_eq!(
            value["terminal_order"][8]["event"],
            "publication_suppressed"
        );
        assert!(!value["no_publish_digest"].as_str().unwrap().is_empty());
    }

    #[test]
    fn durable_dispatch_receives_only_the_teardown_failure_terminal() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("activation");
        let mut cleanup_executor = executor(&root, FakeObservation::Complete, None);
        let (request, lease) = admitted_fixture();
        assert_eq!(
            QualificationExecutor::preflight(&mut cleanup_executor, request),
            Ok(())
        );

        let mut ordinary = request;
        ordinary.directive = None;
        assert_eq!(
            QualificationExecutor::preflight(&mut cleanup_executor, ordinary),
            Err(ExecutionUnavailable)
        );

        let execution = QualificationExecutor::execute(
            &mut cleanup_executor,
            FrameHeader {
                operation: Operation::AdmitQualification,
                request_id: [21; 16],
            },
            request,
            lease,
            10,
        )
        .unwrap();
        assert_eq!(execution.terminal, QualificationTerminal::TeardownFailure);
        assert_eq!(execution.response.code, ResponseCode::Ok);
        assert_eq!(execution.response.broker_state, BrokerState::Quarantined);
        assert_eq!(
            execution.response.conclusion,
            Conclusion::InfrastructureFailure
        );
        assert_ne!(execution.response.evidence_set_digest, [0; 32]);
        assert_ne!(execution.response.teardown_digest, [0; 32]);

        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("activation");
        let mut missing = executor(&root, FakeObservation::Missing, None);
        let (request, lease) = admitted_fixture();
        let execution = QualificationExecutor::execute(
            &mut missing,
            FrameHeader {
                operation: Operation::AdmitQualification,
                request_id: [22; 16],
            },
            request,
            lease,
            10,
        )
        .unwrap();
        assert_eq!(execution.terminal, QualificationTerminal::TeardownFailure);
        assert_eq!(execution.response.code, ResponseCode::InternalFailure);
        assert_eq!(execution.response.broker_state, BrokerState::Quarantined);
        assert_eq!(
            execution.response.conclusion,
            Conclusion::InfrastructureFailure
        );
        assert_eq!(execution.response.evidence_set_digest, [0; 32]);
        assert_eq!(execution.response.teardown_digest, [0; 32]);
    }

    #[test]
    fn missing_ambiguous_or_publish_evidence_never_completes() {
        for (observation, fail_operation) in [
            (FakeObservation::Missing, None),
            (FakeObservation::PublishSeen, None),
            (FakeObservation::Error, None),
            (FakeObservation::Complete, Some(1)),
        ] {
            let temporary = tempfile::tempdir().unwrap();
            let root = temporary.path().join("activation");
            let mut executor = executor(&root, observation, fail_operation);
            assert!(!matches!(
                executor.execute(admitted_plan()),
                QualificationHostExecution::Complete(_)
            ));
            assert_eq!(executor.runner().operations, CLEANUP_OPERATIONS);
            let value: serde_json::Value =
                serde_json::from_slice(&fs::read(receipt_path(&root)).unwrap()).unwrap();
            assert_eq!(value["conclusion"], "infrastructure_failure");
            assert_eq!(value["state"], "quarantined");
            assert_eq!(value["publication"], "suppressed");
            assert!(value["terminal_order"].as_array().unwrap().is_empty());
        }
    }

    #[test]
    fn unsafe_receipt_directory_fails_closed() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("activation");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        let metadata = root.metadata().unwrap();
        let mut executor = QualificationCleanupExecutor::for_test(
            FakeRunner {
                operations: Vec::new(),
                targets: None,
                fail_operation: None,
                observation: FakeObservation::Complete,
            },
            root,
            metadata.uid(),
            metadata.gid(),
        );
        assert_eq!(
            executor.execute(admitted_plan()),
            QualificationHostExecution::Ambiguous
        );
    }
}
