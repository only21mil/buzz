//! Root-owned authority and durable activation-state loading.
//!
//! Authority never comes from the environment or a wire identity claim. The
//! production loader reads two fixed files beneath canonical root-owned
//! directories. A Ready snapshot additionally needs current host validation
//! supplied by the caller.

use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use buzz_ci_broker_protocol::{
    AdmitAttemptRequest, GitOid, QualificationDirective, QualificationRequest, TrustClass,
};
use nix::fcntl::{Flock, FlockArg};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    activation::{
        ActivationController, ActivationGrant, ActivationState, AdmissionTrustClass,
        DurableLeaseFields, DurableNonceEntry, DurableNonceLedger, DurableQualificationLeaseFields,
        DurableQualificationState, DurableStateSnapshot, FixtureJobCoordinates,
        HostActivationCoordinates, LeaseToken, OrdinaryAdmission, OrdinaryJobCoordinates,
        QualificationLease, QualificationPermit, ReadyRestoreValidation, VerifiedSigner,
        NONCE_LEDGER_CAPACITY,
    },
    control::AdmissionBoundaryError,
    durable_dispatch::{
        DurableDispatch, OrdinaryAuthorityBinding, OrdinaryExecutor, QualificationExecutor,
    },
};

/// Canonical immutable authority directory.
pub const AUTHORITY_ROOT: &str = "/etc/buzzci/authority";
/// Canonical durable activation directory.
pub const ACTIVATION_ROOT: &str = "/var/lib/buzzci/activation";
/// Canonical root-authored authority record.
pub const AUTHORITY_FILE: &str = "/etc/buzzci/authority/authority-v1.json";
/// Canonical atomic controller-state record.
pub const ACTIVATION_STATE_FILE: &str = "/var/lib/buzzci/activation/state-v1.json";

pub(crate) const DIRECTORY_MODE: u32 = 0o700;
pub(crate) const AUTHORITY_MODE: u32 = 0o400;
pub(crate) const STATE_MODE: u32 = 0o600;
pub(crate) const MAX_AUTHORITY_BYTES: u64 = 64 * 1024;
pub(crate) const MAX_STATE_BYTES: u64 = 128 * 1024;
pub(crate) const FORMAT_VERSION: u8 = 1;
pub(crate) const COORDINATOR_LOCK_FILE: &str = "authority-state-v1.lock";
pub(crate) const COORDINATOR_MARKER_FILE: &str = ".authority-state-v1.pending";
/// Operator action after a stale fixed-name state temporary blocks publication.
pub const STATE_TEMPORARY_EXISTS_RECOVERY: &str = "Stop every buzz-ci-execd state writer, remove /var/lib/buzzci/activation/.state-v1.json.tmp, then restart buzz-ci-execd.";

/// Why authority or controller state did not open capacity.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum RuntimeLoadError {
    /// A required canonical artifact is absent.
    #[error("runtime authority is not provisioned")]
    NotProvisioned,
    /// A directory or file failed its exact ownership, mode, type, or link check.
    #[error("runtime artifact metadata is unsafe")]
    UnsafeMetadata,
    /// A bounded file could not be read without mutation or overflow.
    #[error("runtime artifact read failed")]
    ReadFailed,
    /// JSON or a closed field value is malformed or non-canonical.
    #[error("runtime artifact is malformed")]
    Malformed,
    /// Authority and state do not name the same immutable revision.
    #[error("runtime authority and state binding mismatch")]
    BindingMismatch,
    /// Root-authored authority or active state has expired.
    #[error("runtime authority is stale")]
    Stale,
    /// The pure activation controller quarantined the restored state.
    #[error("runtime activation state quarantined")]
    Quarantined,
    /// Atomic state publication failed before durable completion.
    #[error("runtime state persistence failed")]
    PersistFailed,
    /// The fixed-name atomic-publication temporary already exists.
    #[error("runtime state temporary already exists")]
    StateTemporaryExists,
}

/// Result of bootstrapping the fixed authority and durable state.
pub enum RuntimeBootstrap {
    /// No trusted root identity was available, so no controller was constructed.
    NotProvisioned(RuntimeLoadError),
    /// A trusted root was available but state failed closed in Quarantined.
    Quarantined {
        /// Quarantined controller with zero capacity.
        controller: Box<ActivationController>,
        /// Loader or activation reason.
        reason: RuntimeLoadError,
    },
    /// Structurally restored runtime and its service-owned request bindings.
    Loaded(Box<LoadedRuntime>),
}

/// Immutable authority/state binding presented to fresh host validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadyValidationTarget {
    grant: ActivationGrant,
    request: AdmitAttemptRequest,
    authority_revision: u64,
    authority_sha256: [u8; 32],
    state_revision: u64,
}

impl ReadyValidationTarget {
    pub(crate) const fn new(
        grant: ActivationGrant,
        request: AdmitAttemptRequest,
        authority_revision: u64,
        authority_sha256: [u8; 32],
        state_revision: u64,
    ) -> Self {
        Self {
            grant,
            request,
            authority_revision,
            authority_sha256,
            state_revision,
        }
    }

    pub const fn grant(self) -> ActivationGrant {
        self.grant
    }

    pub const fn request(self) -> AdmitAttemptRequest {
        self.request
    }

    pub const fn authority_revision(self) -> u64 {
        self.authority_revision
    }

    pub const fn authority_sha256(self) -> [u8; 32] {
        self.authority_sha256
    }

    pub const fn state_revision(self) -> u64 {
        self.state_revision
    }
}

/// Securely loaded authority and state awaiting fresh Ready validation.
pub struct PreparedRuntime {
    snapshot: DurableStateSnapshot,
    authority: ServiceAuthority,
    state_revision: u64,
    authority_sha256: [u8; 32],
    paths: RuntimePaths,
    expected_uid: u32,
}

impl PreparedRuntime {
    /// Return the exact immutable grant/request pair that fresh proofs must bind.
    pub fn ready_validation_target(&self) -> Option<ReadyValidationTarget> {
        if self.snapshot.state != ActivationState::Ready {
            return None;
        }
        let ordinary = self.authority.ordinary.as_ref()?;
        Some(ReadyValidationTarget::new(
            ordinary.grant,
            ordinary.request,
            self.authority.revision,
            self.authority_sha256,
            self.state_revision,
        ))
    }

    /// Restore only after validation has observed the exact loaded target.
    pub(crate) fn restore(
        self,
        ready_validation: Option<ReadyRestoreValidation>,
    ) -> RuntimeBootstrap {
        let root = self.authority.root;
        let restored = ActivationController::restore(root, self.snapshot, ready_validation);
        if restored.quarantine_reason.is_some() {
            if restored.controller.recovery_lease().is_some() {
                let mut store = DurableStateStore {
                    state_revision: self.state_revision,
                    authority_revision: self.authority.revision,
                    authority_sha256: self.authority_sha256,
                    paths: self.paths.clone(),
                    expected_uid: self.expected_uid,
                };
                if store.commit(restored.controller.snapshot()).is_ok() {
                    return RuntimeBootstrap::Loaded(Box::new(LoadedRuntime {
                        controller: restored.controller,
                        authority: self.authority,
                        state_revision: store.revision(),
                        authority_sha256: self.authority_sha256,
                        paths: self.paths,
                        expected_uid: self.expected_uid,
                    }));
                }
            }
            if restored.controller.qualification_recovery_lease().is_some() {
                return RuntimeBootstrap::Loaded(Box::new(LoadedRuntime {
                    controller: restored.controller,
                    authority: self.authority,
                    state_revision: self.state_revision,
                    authority_sha256: self.authority_sha256,
                    paths: self.paths,
                    expected_uid: self.expected_uid,
                }));
            }
            return persist_quarantine(
                restored.controller,
                self.state_revision,
                self.authority.revision,
                self.authority_sha256,
                self.paths,
                self.expected_uid,
                RuntimeLoadError::Quarantined,
            );
        }
        RuntimeBootstrap::Loaded(Box::new(LoadedRuntime {
            controller: restored.controller,
            authority: self.authority,
            state_revision: self.state_revision,
            authority_sha256: self.authority_sha256,
            paths: self.paths,
            expected_uid: self.expected_uid,
        }))
    }
}

/// First bootstrap phase: no Ready state is restored before fresh validation.
pub enum RuntimePreparation {
    NotProvisioned(RuntimeLoadError),
    Quarantined {
        controller: Box<ActivationController>,
        reason: RuntimeLoadError,
    },
    Prepared(Box<PreparedRuntime>),
}

impl RuntimePreparation {
    pub(crate) fn complete_closed(self) -> RuntimeBootstrap {
        match self {
            Self::NotProvisioned(reason) => RuntimeBootstrap::NotProvisioned(reason),
            Self::Quarantined { controller, reason } => {
                RuntimeBootstrap::Quarantined { controller, reason }
            }
            Self::Prepared(runtime) => runtime.restore(None),
        }
    }
}

impl RuntimeBootstrap {
    /// Report ordinary capacity without exposing a fallback-to-ready path.
    pub fn ordinary_capacity(&self, now: u64) -> u8 {
        match self {
            Self::Loaded(runtime) => runtime.controller.ordinary_capacity(now),
            Self::NotProvisioned(_) | Self::Quarantined { .. } => 0,
        }
    }
}

/// Restored controller paired with the exact authority revision that opened it.
pub struct LoadedRuntime {
    controller: ActivationController,
    authority: ServiceAuthority,
    state_revision: u64,
    authority_sha256: [u8; 32],
    paths: RuntimePaths,
    expected_uid: u32,
}

impl LoadedRuntime {
    /// Inspect the restored lifecycle state.
    pub const fn state(&self) -> ActivationState {
        self.controller.state()
    }

    /// Access the service-owned request bindings without wire promotion.
    pub const fn authority(&self) -> &ServiceAuthority {
        &self.authority
    }

    /// Compose restored state with durable lifecycle executors.
    ///
    /// The returned dispatcher retains the state writer and revision. It
    /// authenticates through root-owned authority and commits each lifecycle
    /// transition before exposing a successful response.
    pub fn compose<O, Q>(
        self,
        ordinary: O,
        qualification: Q,
    ) -> DurableDispatch<DurableStateStore, ServiceAuthority, O, Q>
    where
        O: OrdinaryExecutor,
        Q: QualificationExecutor,
    {
        let (controller, authority, store) = self.into_durable_parts();
        DurableDispatch::new(controller, authority, store, ordinary, qualification)
    }

    /// Persist the current snapshot and advance this runtime's durable revision.
    ///
    /// In-flight records restore with zero capacity; exact retained receipts
    /// authorize cleanup only.
    pub fn persist(&mut self) -> Result<(), RuntimeLoadError> {
        let mut store = DurableStateStore {
            state_revision: self.state_revision,
            authority_revision: self.authority.revision,
            authority_sha256: self.authority_sha256,
            paths: self.paths.clone(),
            expected_uid: self.expected_uid,
        };
        store.commit(self.controller.snapshot())?;
        self.state_revision = store.revision();
        Ok(())
    }

    /// Split a loaded runtime into the controller, authority, and revisioned store.
    pub(crate) fn into_durable_parts(
        self,
    ) -> (ActivationController, ServiceAuthority, DurableStateStore) {
        let store = DurableStateStore {
            state_revision: self.state_revision,
            authority_revision: self.authority.revision,
            authority_sha256: self.authority_sha256,
            paths: self.paths,
            expected_uid: self.expected_uid,
        };
        (self.controller, self.authority, store)
    }
}

/// Canonical revisioned state writer used by the production durable dispatcher.
pub struct DurableStateStore {
    state_revision: u64,
    authority_revision: u64,
    authority_sha256: [u8; 32],
    paths: RuntimePaths,
    expected_uid: u32,
}

impl DurableStateStore {
    /// Publish one exact controller snapshot, advancing revision only after fsync.
    pub fn commit(&mut self, snapshot: DurableStateSnapshot) -> Result<(), RuntimeLoadError> {
        let next_revision = self
            .state_revision
            .checked_add(1)
            .ok_or(RuntimeLoadError::PersistFailed)?;
        // Shared locking is safe only while one writer exists. Fixed-name create_new
        // serializes accidental concurrent writes; a second writer requires an
        // exclusive lock or another proven mechanism.
        let _lock = acquire_runtime_lock(&self.paths, FlockArg::LockShared, self.expected_uid)?;
        self.validate_commit_base()?;
        persist_to_validated_path(
            &self.paths.activation_root,
            &self.paths.state_file,
            snapshot,
            next_revision,
            self.authority_revision,
            self.authority_sha256,
        )?;
        self.state_revision = next_revision;
        Ok(())
    }

    /// Current durable revision.
    pub const fn revision(&self) -> u64 {
        self.state_revision
    }

    fn validate_commit_base(&self) -> Result<(), RuntimeLoadError> {
        if self
            .paths
            .activation_root
            .join(COORDINATOR_MARKER_FILE)
            .try_exists()
            .unwrap_or(true)
        {
            return Err(RuntimeLoadError::Quarantined);
        }
        let authority_bytes = read_artifact_for_owner(
            &self.paths.authority_root,
            &self.paths.authority_file,
            AUTHORITY_MODE,
            MAX_AUTHORITY_BYTES,
            self.expected_uid,
        )?;
        let authority_disk: AuthorityFile =
            serde_json::from_slice(&authority_bytes).map_err(|_| RuntimeLoadError::Malformed)?;
        let authority = authority_disk.decode()?;
        let authority_sha256: [u8; 32] = Sha256::digest(&authority_bytes).into();
        let state_bytes = read_artifact_for_owner(
            &self.paths.activation_root,
            &self.paths.state_file,
            STATE_MODE,
            MAX_STATE_BYTES,
            self.expected_uid,
        )?;
        let state: StateFile =
            serde_json::from_slice(&state_bytes).map_err(|_| RuntimeLoadError::Malformed)?;
        if authority.revision != self.authority_revision
            || authority_sha256 != self.authority_sha256
            || state.version != FORMAT_VERSION
            || state.revision != self.state_revision
            || state.authority_revision != self.authority_revision
            || !state.committed
            || hex_array::<32>(&state.authority_sha256)? != self.authority_sha256
        {
            return Err(RuntimeLoadError::BindingMismatch);
        }
        Ok(())
    }
}

/// Exact root-authored signer and permit bindings.
#[derive(Clone)]
pub struct ServiceAuthority {
    revision: u64,
    root: VerifiedSigner,
    qualification: Option<QualificationAuthority>,
    ordinary: Option<OrdinaryAuthority>,
}

impl ServiceAuthority {
    pub(crate) const fn revision(&self) -> u64 {
        self.revision
    }

    /// Root identity used by the pure activation controller.
    pub const fn root(&self) -> VerifiedSigner {
        self.root
    }

    /// Authorize one ordinary wire request only when every root-authored byte matches.
    pub fn authorize_ordinary(
        &self,
        request: AdmitAttemptRequest,
    ) -> Result<OrdinaryAdmission, AdmissionBoundaryError> {
        let binding = self
            .ordinary
            .as_ref()
            .ok_or(AdmissionBoundaryError::Unavailable)?;
        if request != binding.request {
            return Err(AdmissionBoundaryError::Unauthorized);
        }
        Ok(binding.admission)
    }

    /// Authenticate a later ordinary mutation against the root-owned signer.
    pub fn authenticate_ordinary_signer(
        &self,
        signer_pubkey: [u8; 32],
    ) -> Result<OrdinaryAuthorityBinding, AdmissionBoundaryError> {
        let binding = self
            .ordinary
            .as_ref()
            .ok_or(AdmissionBoundaryError::Unavailable)?;
        if signer_pubkey != binding.admission.signer.0 {
            return Err(AdmissionBoundaryError::Unauthorized);
        }
        Ok(OrdinaryAuthorityBinding {
            request: binding.request,
            admission: binding.admission,
        })
    }

    /// Authenticate one qualification claim against the exact root permit.
    pub fn authenticate_qualification(
        &self,
        request: QualificationRequest,
    ) -> Result<VerifiedSigner, AdmissionBoundaryError> {
        let binding = self
            .qualification
            .as_ref()
            .ok_or(AdmissionBoundaryError::Unavailable)?;
        if request != binding.request {
            return Err(AdmissionBoundaryError::Unauthorized);
        }
        Ok(binding.authenticated_signer)
    }

    /// Recover the exact root-authored qualification request for cleanup only.
    pub fn recover_qualification(
        &self,
        lease: QualificationLease,
    ) -> Result<QualificationRequest, AdmissionBoundaryError> {
        let binding = self
            .qualification
            .as_ref()
            .ok_or(AdmissionBoundaryError::Unavailable)?;
        let mut expected_lease_id = [0; 16];
        expected_lease_id.copy_from_slice(&binding.permit.fixture_identity[..16]);
        if lease.fixture_identity() != binding.permit.fixture_identity
            || lease.lease_id() != expected_lease_id
            || lease.generation() == 0
            || lease.nonce() != binding.permit.nonce
            || lease.directive() != binding.permit.directive
        {
            return Err(AdmissionBoundaryError::Unauthorized);
        }
        Ok(binding.request)
    }
}

#[derive(Clone)]
struct QualificationAuthority {
    permit: QualificationPermit,
    request: QualificationRequest,
    authenticated_signer: VerifiedSigner,
}

#[derive(Clone)]
struct OrdinaryAuthority {
    grant: ActivationGrant,
    request: AdmitAttemptRequest,
    admission: OrdinaryAdmission,
}

/// Exact root-authored ordinary request bound to an activation grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootOrdinaryAuthority {
    pub grant: ActivationGrant,
    pub request: AdmitAttemptRequest,
    pub job_identity: [u8; 32],
    pub lease_id: [u8; 16],
    pub nonce: [u8; 32],
    pub authenticated_signer: VerifiedSigner,
}

#[derive(Clone)]
pub(crate) struct RuntimePaths {
    pub(crate) authority_root: PathBuf,
    pub(crate) authority_file: PathBuf,
    pub(crate) activation_root: PathBuf,
    pub(crate) state_file: PathBuf,
}

/// Exact ordinary authority recovered from the same root-owned runtime files
/// that control durable dispatch.
pub(crate) struct ReopenedOrdinaryAuthority {
    pub(crate) request: AdmitAttemptRequest,
    pub(crate) admission: OrdinaryAdmission,
    pub(crate) recovery_lease: Option<LeaseToken>,
    pub(crate) authority_revision: u64,
    pub(crate) authority_sha256: [u8; 32],
}

impl RuntimePaths {
    pub(crate) fn canonical() -> Self {
        Self {
            authority_root: AUTHORITY_ROOT.into(),
            authority_file: AUTHORITY_FILE.into(),
            activation_root: ACTIVATION_ROOT.into(),
            state_file: ACTIVATION_STATE_FILE.into(),
        }
    }
}

/// Securely load and bind canonical authority/state without restoring Ready.
pub fn prepare_runtime(now: u64) -> RuntimePreparation {
    prepare_from_paths(&RuntimePaths::canonical(), now)
}

fn prepare_from_paths(paths: &RuntimePaths, now: u64) -> RuntimePreparation {
    prepare_from_paths_for_owner(paths, now, 0)
}

fn prepare_from_paths_for_owner(
    paths: &RuntimePaths,
    now: u64,
    expected_uid: u32,
) -> RuntimePreparation {
    let _lock = match acquire_runtime_lock(paths, FlockArg::LockShared, expected_uid) {
        Ok(lock) => lock,
        Err(error) => return RuntimePreparation::NotProvisioned(error),
    };
    if paths
        .activation_root
        .join(COORDINATOR_MARKER_FILE)
        .try_exists()
        .unwrap_or(true)
    {
        return RuntimePreparation::NotProvisioned(RuntimeLoadError::Quarantined);
    }
    let authority_bytes = match read_artifact_for_runtime_owner(
        &paths.authority_root,
        &paths.authority_file,
        AUTHORITY_MODE,
        MAX_AUTHORITY_BYTES,
        expected_uid,
    ) {
        Ok(bytes) => bytes,
        Err(error) => return RuntimePreparation::NotProvisioned(error),
    };
    let authority_disk: AuthorityFile = match serde_json::from_slice(&authority_bytes) {
        Ok(value) => value,
        Err(_) => return RuntimePreparation::NotProvisioned(RuntimeLoadError::Malformed),
    };
    let authority = match authority_disk.decode() {
        Ok(value) => value,
        Err(error) => return RuntimePreparation::NotProvisioned(error),
    };
    let root = authority.root;
    let authority_sha256: [u8; 32] = Sha256::digest(&authority_bytes).into();

    let state_bytes = match read_artifact_for_runtime_owner(
        &paths.activation_root,
        &paths.state_file,
        STATE_MODE,
        MAX_STATE_BYTES,
        expected_uid,
    ) {
        Ok(bytes) => bytes,
        Err(error) => {
            return RuntimePreparation::Quarantined {
                controller: Box::new(quarantine(root)),
                reason: error,
            }
        }
    };
    let state_disk: StateFile = match serde_json::from_slice(&state_bytes) {
        Ok(value) => value,
        Err(_) => {
            return RuntimePreparation::Quarantined {
                controller: Box::new(quarantine(root)),
                reason: RuntimeLoadError::Malformed,
            }
        }
    };
    let snapshot = match state_disk.decode(&authority, authority_sha256, now) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return match persist_quarantine(
                quarantine(root),
                state_disk.revision,
                authority.revision,
                authority_sha256,
                paths.clone(),
                expected_uid,
                error,
            ) {
                RuntimeBootstrap::Quarantined { controller, reason } => {
                    RuntimePreparation::Quarantined { controller, reason }
                }
                RuntimeBootstrap::NotProvisioned(reason) => {
                    RuntimePreparation::NotProvisioned(reason)
                }
                RuntimeBootstrap::Loaded(_) => unreachable!("quarantine persistence cannot load"),
            };
        }
    };
    let state_revision = state_disk.revision;
    RuntimePreparation::Prepared(Box::new(PreparedRuntime {
        snapshot,
        authority,
        state_revision,
        authority_sha256,
        paths: paths.clone(),
        expected_uid,
    }))
}

/// Reopen the ordinary request and any retained opaque lease without restoring
/// or mutating the controller. Production job plans use this instead of caller
/// claims for request, signer, generation, and deadline authority.
pub(crate) fn reopen_ordinary_authority(
    paths: &RuntimePaths,
    now: u64,
    expected_uid: u32,
) -> Result<ReopenedOrdinaryAuthority, RuntimeLoadError> {
    let prepared = match prepare_from_paths_for_owner(paths, now, expected_uid) {
        RuntimePreparation::Prepared(prepared) => prepared,
        RuntimePreparation::NotProvisioned(error)
        | RuntimePreparation::Quarantined { reason: error, .. } => return Err(error),
    };
    let ordinary = prepared
        .authority
        .ordinary
        .as_ref()
        .ok_or(RuntimeLoadError::NotProvisioned)?;
    Ok(ReopenedOrdinaryAuthority {
        request: ordinary.request,
        admission: ordinary.admission,
        recovery_lease: prepared.snapshot.active_lease,
        authority_revision: prepared.authority.revision,
        authority_sha256: prepared.authority_sha256,
    })
}

fn persist_quarantine(
    controller: ActivationController,
    state_revision: u64,
    authority_revision: u64,
    authority_sha256: [u8; 32],
    paths: RuntimePaths,
    expected_uid: u32,
    reason: RuntimeLoadError,
) -> RuntimeBootstrap {
    let mut store = DurableStateStore {
        state_revision,
        authority_revision,
        authority_sha256,
        paths,
        expected_uid,
    };
    let persisted_reason = match store.commit(controller.snapshot()) {
        Ok(()) => reason,
        Err(error) => error,
    };
    RuntimeBootstrap::Quarantined {
        controller: Box::new(controller),
        reason: persisted_reason,
    }
}

fn quarantine(root: VerifiedSigner) -> ActivationController {
    let snapshot = DurableStateSnapshot {
        version: FORMAT_VERSION,
        root_authority: VerifiedSigner([0; 32]),
        state: ActivationState::Unprovisioned,
        qualification: None,
        activation: None,
        active_lease: None,
        nonce_ledger: DurableNonceLedger {
            entries: [None; NONCE_LEDGER_CAPACITY],
        },
        last_admission_at: None,
        next_lease_generation: 1,
    };
    ActivationController::restore(root, snapshot, None).controller
}

pub(crate) fn read_artifact(
    directory: &Path,
    path: &Path,
    expected_mode: u32,
    max_bytes: u64,
) -> Result<Vec<u8>, RuntimeLoadError> {
    validate_directory(directory)?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
    let mut file = options.open(path).map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => RuntimeLoadError::NotProvisioned,
        _ => RuntimeLoadError::ReadFailed,
    })?;
    let before = file.metadata().map_err(|_| RuntimeLoadError::ReadFailed)?;
    validate_file(&before, expected_mode, max_bytes)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| RuntimeLoadError::ReadFailed)?;
    if bytes.len() as u64 > max_bytes {
        return Err(RuntimeLoadError::ReadFailed);
    }
    let after = file.metadata().map_err(|_| RuntimeLoadError::ReadFailed)?;
    if file_identity(&before) != file_identity(&after) || after.len() != bytes.len() as u64 {
        return Err(RuntimeLoadError::ReadFailed);
    }
    Ok(bytes)
}

fn read_artifact_for_runtime_owner(
    directory: &Path,
    path: &Path,
    expected_mode: u32,
    max_bytes: u64,
    expected_uid: u32,
) -> Result<Vec<u8>, RuntimeLoadError> {
    if expected_uid == 0 {
        read_artifact(directory, path, expected_mode, max_bytes)
    } else {
        read_artifact_for_owner(directory, path, expected_mode, max_bytes, expected_uid)
    }
}

pub(crate) fn read_artifact_for_owner(
    directory: &Path,
    path: &Path,
    expected_mode: u32,
    max_bytes: u64,
    expected_uid: u32,
) -> Result<Vec<u8>, RuntimeLoadError> {
    validate_directory_for_owner(directory, expected_uid)?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
    let mut file = options.open(path).map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => RuntimeLoadError::NotProvisioned,
        _ => RuntimeLoadError::ReadFailed,
    })?;
    let before = file.metadata().map_err(|_| RuntimeLoadError::ReadFailed)?;
    validate_file_for_owner(&before, expected_mode, max_bytes, expected_uid)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| RuntimeLoadError::ReadFailed)?;
    if bytes.len() as u64 > max_bytes {
        return Err(RuntimeLoadError::ReadFailed);
    }
    let after = file.metadata().map_err(|_| RuntimeLoadError::ReadFailed)?;
    if file_identity(&before) != file_identity(&after) || after.len() != bytes.len() as u64 {
        return Err(RuntimeLoadError::ReadFailed);
    }
    Ok(bytes)
}

fn validate_directory(path: &Path) -> Result<(), RuntimeLoadError> {
    validate_directory_for_owner(path, 0)
}

pub(crate) fn validate_directory_for_owner(
    path: &Path,
    expected_uid: u32,
) -> Result<(), RuntimeLoadError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => RuntimeLoadError::NotProvisioned,
        _ => RuntimeLoadError::UnsafeMetadata,
    })?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != expected_uid
        || metadata.gid() != expected_uid
        || metadata.permissions().mode() & 0o7777 != DIRECTORY_MODE
    {
        return Err(RuntimeLoadError::UnsafeMetadata);
    }
    Ok(())
}

fn validate_file(
    metadata: &Metadata,
    expected_mode: u32,
    max_bytes: u64,
) -> Result<(), RuntimeLoadError> {
    validate_file_for_owner(metadata, expected_mode, max_bytes, 0)
}

pub(crate) fn validate_file_for_owner(
    metadata: &Metadata,
    expected_mode: u32,
    max_bytes: u64,
    expected_uid: u32,
) -> Result<(), RuntimeLoadError> {
    if !metadata.file_type().is_file()
        || metadata.uid() != expected_uid
        || metadata.gid() != expected_uid
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o7777 != expected_mode
        || metadata.len() == 0
        || metadata.len() > max_bytes
    {
        return Err(RuntimeLoadError::UnsafeMetadata);
    }
    Ok(())
}

pub(crate) fn acquire_runtime_lock(
    paths: &RuntimePaths,
    operation: FlockArg,
    expected_uid: u32,
) -> Result<Flock<File>, RuntimeLoadError> {
    validate_directory_for_owner(&paths.activation_root, expected_uid)?;
    let path = paths.activation_root.join(COORDINATOR_LOCK_FILE);
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
    let file = options.open(path).map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => RuntimeLoadError::NotProvisioned,
        _ => RuntimeLoadError::ReadFailed,
    })?;
    validate_file_for_owner(
        &file.metadata().map_err(|_| RuntimeLoadError::ReadFailed)?,
        STATE_MODE,
        1,
        expected_uid,
    )?;
    Flock::lock(file, operation).map_err(|_| RuntimeLoadError::ReadFailed)
}

fn file_identity(metadata: &Metadata) -> (u64, u64, u64, i64, i64, i64, i64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

pub(crate) fn persist_to_validated_path(
    directory: &Path,
    destination: &Path,
    snapshot: DurableStateSnapshot,
    revision: u64,
    authority_revision: u64,
    authority_sha256: [u8; 32],
) -> Result<(), RuntimeLoadError> {
    if revision == 0 {
        return Err(RuntimeLoadError::PersistFailed);
    }
    let disk = StateFile::encode(snapshot, revision, authority_revision, authority_sha256)?;
    let bytes = serde_json::to_vec(&disk).map_err(|_| RuntimeLoadError::PersistFailed)?;
    if bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(RuntimeLoadError::PersistFailed);
    }
    let temporary = directory.join(".state-v1.json.tmp");
    let mut options = OpenOptions::new();
    options
        .create_new(true)
        .write(true)
        .mode(STATE_MODE)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
    let mut file = options.open(&temporary).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            RuntimeLoadError::StateTemporaryExists
        } else {
            RuntimeLoadError::PersistFailed
        }
    })?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| RuntimeLoadError::PersistFailed)?;
    fs::rename(&temporary, destination).map_err(|_| RuntimeLoadError::PersistFailed)?;
    File::open(directory)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| RuntimeLoadError::PersistFailed)?;
    Ok(())
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuthorityFile {
    version: u8,
    revision: u64,
    root_authority: String,
    qualification: Option<QualificationAuthorityFile>,
    ordinary: Option<OrdinaryAuthorityFile>,
}

impl AuthorityFile {
    pub(crate) fn decode(self) -> Result<ServiceAuthority, RuntimeLoadError> {
        if self.version != FORMAT_VERSION || self.revision == 0 {
            return Err(RuntimeLoadError::Malformed);
        }
        let root = VerifiedSigner(hex_array(&self.root_authority)?);
        if root.0 == [0; 32] {
            return Err(RuntimeLoadError::Malformed);
        }
        let qualification = self
            .qualification
            .map(|value| value.decode(root))
            .transpose()?;
        let ordinary = self.ordinary.map(|value| value.decode(root)).transpose()?;
        Ok(ServiceAuthority {
            revision: self.revision,
            root,
            qualification,
            ordinary,
        })
    }

    pub(crate) fn encode(
        revision: u64,
        root: VerifiedSigner,
        qualification: Option<QualificationPermit>,
        ordinary: Option<RootOrdinaryAuthority>,
    ) -> Result<Self, RuntimeLoadError> {
        let value = Self {
            version: FORMAT_VERSION,
            revision,
            root_authority: hex::encode(root.0),
            qualification: qualification.map(QualificationAuthorityFile::encode),
            ordinary: ordinary.map(OrdinaryAuthorityFile::encode),
        };
        value.clone().decode()?;
        Ok(value)
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct QualificationAuthorityFile {
    permit: PermitFile,
    authenticated_signer: String,
}

impl QualificationAuthorityFile {
    fn decode(self, root: VerifiedSigner) -> Result<QualificationAuthority, RuntimeLoadError> {
        let permit = self.permit.decode()?;
        let authenticated_signer = VerifiedSigner(hex_array(&self.authenticated_signer)?);
        if permit.authorized_by != root
            || authenticated_signer != permit.fixture_signer
            || authenticated_signer.0 == [0; 32]
        {
            return Err(RuntimeLoadError::BindingMismatch);
        }
        let request = qualification_request(permit);
        let mut validator = ActivationController::new(root);
        validator
            .start_qualification(permit)
            .map_err(|_| RuntimeLoadError::Malformed)?;
        Ok(QualificationAuthority {
            permit,
            request,
            authenticated_signer,
        })
    }

    fn encode(permit: QualificationPermit) -> Self {
        Self {
            permit: PermitFile::encode(permit),
            authenticated_signer: hex::encode(permit.fixture_signer.0),
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OrdinaryAuthorityFile {
    grant: GrantFile,
    request: AdmitFile,
    host: HostFile,
    job_identity: String,
    lease_id: String,
    nonce: String,
    authenticated_signer: String,
}

impl OrdinaryAuthorityFile {
    fn decode(self, root: VerifiedSigner) -> Result<OrdinaryAuthority, RuntimeLoadError> {
        let grant = self.grant.decode()?;
        let request = self.request.decode()?;
        let host = self.host.decode()?;
        let authenticated_signer = VerifiedSigner(hex_array(&self.authenticated_signer)?);
        if grant.authorized_by != root
            || grant.host != host
            || grant.ordinary_signer != authenticated_signer
            || request.actor_pubkey != authenticated_signer.0
        {
            return Err(RuntimeLoadError::BindingMismatch);
        }
        let admission = OrdinaryAdmission {
            host,
            job: OrdinaryJobCoordinates {
                request_digest: request.signed_request_digest,
                manifest_digest: request.job_manifest_digest,
                isolation_profile_digest: request.isolation_profile_digest,
                source_oid: request.tip_oid,
                base_oid: request.base_oid,
                job_identity: hex_array(&self.job_identity)?,
            },
            lease_id: hex_array(&self.lease_id)?,
            run_id: request.run_id,
            attempt: request.attempt,
            signer: authenticated_signer,
            nonce: hex_array(&self.nonce)?,
            expires_at: request.expires_at,
            wall_timeout_seconds: request.wall_timeout_seconds,
            trust_class: AdmissionTrustClass::AcceptedReviewed,
        };
        Ok(OrdinaryAuthority {
            grant,
            request,
            admission,
        })
    }

    fn encode(value: RootOrdinaryAuthority) -> Self {
        Self {
            grant: GrantFile::encode(value.grant),
            request: AdmitFile::encode(value.request),
            host: HostFile::encode(value.grant.host),
            job_identity: hex::encode(value.job_identity),
            lease_id: hex::encode(value.lease_id),
            nonce: hex::encode(value.nonce),
            authenticated_signer: hex::encode(value.authenticated_signer.0),
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StateFile {
    version: u8,
    revision: u64,
    authority_revision: u64,
    authority_sha256: String,
    committed: bool,
    state: String,
    qualification: Option<DurableQualificationFile>,
    activation: Option<GrantFile>,
    active_lease: ActiveLeaseFile,
    nonce_ledger: Vec<NonceFile>,
    last_admission_at: Option<u64>,
    next_lease_generation: u64,
}

impl StateFile {
    pub(crate) const fn revision(&self) -> u64 {
        self.revision
    }

    pub(crate) fn decode(
        &self,
        authority: &ServiceAuthority,
        authority_sha256: [u8; 32],
        now: u64,
    ) -> Result<DurableStateSnapshot, RuntimeLoadError> {
        if self.version != FORMAT_VERSION
            || self.revision == 0
            || self.authority_revision != authority.revision
            || !self.committed
            || hex_array::<32>(&self.authority_sha256)? != authority_sha256
            || self.nonce_ledger.len() > NONCE_LEDGER_CAPACITY
        {
            return Err(RuntimeLoadError::BindingMismatch);
        }
        let state = parse_state(&self.state)?;
        let mut entries = [None; NONCE_LEDGER_CAPACITY];
        for (index, value) in self.nonce_ledger.iter().enumerate() {
            entries[index] = Some(value.decode()?);
        }
        let nonce_ledger = DurableNonceLedger { entries };
        let qualification = self
            .qualification
            .as_ref()
            .map(|value| {
                value.decode(
                    authority.qualification.as_ref().map(|value| value.permit),
                    state,
                    nonce_ledger,
                    self.next_lease_generation,
                )
            })
            .transpose()?;
        let activation = self
            .activation
            .as_ref()
            .map(GrantFile::decode)
            .transpose()?;
        let active_lease = self.active_lease.decode(authority)?;
        let authority_bound = qualification.as_ref().map(|value| value.permit)
            == authority.qualification.as_ref().map(|value| value.permit)
            && activation == authority.ordinary.as_ref().map(|value| value.grant);
        let durable_closed_quarantine = state == ActivationState::Quarantined
            && qualification.is_none()
            && activation.is_none();
        if !authority_bound && !durable_closed_quarantine {
            return Err(RuntimeLoadError::BindingMismatch);
        }
        if (state == ActivationState::Qualifying
            && qualification.is_some_and(|value| {
                value.active_lease.is_none() && now >= value.permit.expires_at
            }))
            || (state == ActivationState::Ready
                && activation.is_some_and(|value| now >= value.expires_at))
        {
            return Err(RuntimeLoadError::Stale);
        }
        Ok(DurableStateSnapshot {
            version: FORMAT_VERSION,
            root_authority: authority.root,
            state,
            qualification,
            activation,
            active_lease,
            nonce_ledger,
            last_admission_at: self.last_admission_at,
            next_lease_generation: self.next_lease_generation,
        })
    }

    pub(crate) fn encode(
        snapshot: DurableStateSnapshot,
        revision: u64,
        authority_revision: u64,
        authority_sha256: [u8; 32],
    ) -> Result<Self, RuntimeLoadError> {
        Ok(Self {
            version: FORMAT_VERSION,
            revision,
            authority_revision,
            authority_sha256: hex::encode(authority_sha256),
            committed: true,
            state: state_name(snapshot.state).into(),
            qualification: snapshot
                .qualification
                .map(DurableQualificationFile::encode)
                .transpose()?,
            activation: snapshot.activation.map(GrantFile::encode),
            active_lease: ActiveLeaseFile::encode(snapshot.active_lease),
            nonce_ledger: snapshot
                .nonce_ledger
                .entries
                .iter()
                .flatten()
                .copied()
                .map(NonceFile::encode)
                .collect(),
            last_admission_at: snapshot.last_admission_at,
            next_lease_generation: snapshot.next_lease_generation,
        })
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(untagged)]
enum ActiveLeaseFile {
    Legacy(bool),
    Lease(LeaseFile),
}

impl ActiveLeaseFile {
    fn decode(&self, authority: &ServiceAuthority) -> Result<Option<LeaseToken>, RuntimeLoadError> {
        match self {
            Self::Legacy(false) => Ok(None),
            Self::Legacy(true) => Err(RuntimeLoadError::Quarantined),
            Self::Lease(lease) => lease.decode(authority).map(Some),
        }
    }

    fn encode(lease: Option<LeaseToken>) -> Self {
        match lease {
            None => Self::Legacy(false),
            Some(lease) => Self::Lease(LeaseFile {
                lease_id: hex::encode(lease.lease_id()),
                run_id: hex::encode(lease.run_id()),
                attempt: lease.attempt(),
                signed_request_digest: hex::encode(lease.signed_request_digest()),
                signer_pubkey: hex::encode(lease.signer().0),
                generation: lease.generation(),
                nonce: hex::encode(lease.nonce()),
                deadline_at: lease.deadline_at(),
            }),
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LeaseFile {
    lease_id: String,
    run_id: String,
    attempt: u32,
    signed_request_digest: String,
    signer_pubkey: String,
    generation: u64,
    nonce: String,
    deadline_at: u64,
}

impl LeaseFile {
    fn decode(&self, authority: &ServiceAuthority) -> Result<LeaseToken, RuntimeLoadError> {
        let binding = authority
            .ordinary
            .as_ref()
            .ok_or(RuntimeLoadError::BindingMismatch)?;
        let lease_id = hex_array(&self.lease_id)?;
        let run_id = hex_array(&self.run_id)?;
        let nonce = hex_array(&self.nonce)?;
        if self.generation == 0
            || lease_id != binding.admission.lease_id
            || run_id != binding.request.run_id
            || self.attempt != binding.request.attempt
            || hex_array::<32>(&self.signed_request_digest)?
                != binding.request.signed_request_digest
            || hex_array::<32>(&self.signer_pubkey)? != binding.admission.signer.0
            || nonce != binding.admission.nonce
            || self.deadline_at == 0
            || self.deadline_at > binding.request.expires_at
        {
            return Err(RuntimeLoadError::BindingMismatch);
        }
        Ok(LeaseToken::from_durable(DurableLeaseFields {
            lease_id,
            run_id,
            attempt: self.attempt,
            signed_request_digest: binding.request.signed_request_digest,
            signer: binding.admission.signer,
            generation: self.generation,
            nonce,
            deadline_at: self.deadline_at,
        }))
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DurableQualificationFile {
    permit: PermitFile,
    evidence_set_digest: Option<String>,
    active_lease: QualificationLeaseFile,
}

impl DurableQualificationFile {
    fn decode(
        &self,
        authority_permit: Option<QualificationPermit>,
        state: ActivationState,
        nonce_ledger: DurableNonceLedger,
        next_lease_generation: u64,
    ) -> Result<DurableQualificationState, RuntimeLoadError> {
        let permit = self.permit.decode()?;
        if authority_permit != Some(permit) {
            return Err(RuntimeLoadError::BindingMismatch);
        }
        let evidence_set_digest = self
            .evidence_set_digest
            .as_ref()
            .map(|value| hex_array(value))
            .transpose()?;
        let active_lease = self.active_lease.decode(
            permit,
            state,
            evidence_set_digest,
            nonce_ledger,
            next_lease_generation,
        )?;
        Ok(DurableQualificationState {
            permit,
            active_lease,
            evidence_set_digest,
        })
    }

    fn encode(value: DurableQualificationState) -> Result<Self, RuntimeLoadError> {
        Ok(Self {
            permit: PermitFile::encode(value.permit),
            evidence_set_digest: value.evidence_set_digest.map(hex::encode),
            active_lease: QualificationLeaseFile::encode(value.active_lease),
        })
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(untagged)]
enum QualificationLeaseFile {
    Legacy(bool),
    Lease(ExactQualificationLeaseFile),
}

impl QualificationLeaseFile {
    fn decode(
        &self,
        permit: QualificationPermit,
        state: ActivationState,
        evidence_set_digest: Option<[u8; 32]>,
        nonce_ledger: DurableNonceLedger,
        next_lease_generation: u64,
    ) -> Result<Option<QualificationLease>, RuntimeLoadError> {
        match self {
            Self::Legacy(false) => Ok(None),
            Self::Legacy(true) => Err(RuntimeLoadError::Quarantined),
            Self::Lease(lease) => lease
                .decode(
                    permit,
                    state,
                    evidence_set_digest,
                    nonce_ledger,
                    next_lease_generation,
                )
                .map(Some),
        }
    }

    fn encode(lease: Option<QualificationLease>) -> Self {
        match lease {
            None => Self::Legacy(false),
            Some(lease) => Self::Lease(ExactQualificationLeaseFile {
                fixture_identity: hex::encode(lease.fixture_identity()),
                lease_id: hex::encode(lease.lease_id()),
                generation: lease.generation(),
                nonce: hex::encode(lease.nonce()),
                directive: lease.directive().map(|_| "teardown_failure".into()),
            }),
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ExactQualificationLeaseFile {
    fixture_identity: String,
    lease_id: String,
    generation: u64,
    nonce: String,
    directive: Option<String>,
}

impl ExactQualificationLeaseFile {
    fn decode(
        &self,
        permit: QualificationPermit,
        state: ActivationState,
        evidence_set_digest: Option<[u8; 32]>,
        nonce_ledger: DurableNonceLedger,
        next_lease_generation: u64,
    ) -> Result<QualificationLease, RuntimeLoadError> {
        let fixture_identity = hex_array(&self.fixture_identity)?;
        let lease_id = hex_array(&self.lease_id)?;
        let nonce = hex_array(&self.nonce)?;
        let directive = parse_directive(self.directive.as_deref())?;
        if state != ActivationState::Qualifying
            || evidence_set_digest.is_some()
            || fixture_identity != permit.fixture_identity
            || lease_id != permit.fixture_identity[..16]
            || self.generation == 0
            || self.generation.checked_add(1) != Some(next_lease_generation)
            || nonce != permit.nonce
            || directive != permit.directive
            || !nonce_ledger
                .entries
                .iter()
                .flatten()
                .any(|entry| entry.nonce == nonce && entry.expires_at == permit.expires_at)
        {
            return Err(RuntimeLoadError::BindingMismatch);
        }
        Ok(QualificationLease::from_durable(
            DurableQualificationLeaseFields {
                fixture_identity,
                lease_id,
                generation: self.generation,
                nonce,
                directive,
            },
        ))
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NonceFile {
    nonce: String,
    expires_at: u64,
}

impl NonceFile {
    fn decode(&self) -> Result<DurableNonceEntry, RuntimeLoadError> {
        Ok(DurableNonceEntry {
            nonce: hex_array(&self.nonce)?,
            expires_at: self.expires_at,
        })
    }

    fn encode(value: DurableNonceEntry) -> Self {
        Self {
            nonce: hex::encode(value.nonce),
            expires_at: value.expires_at,
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HostFile {
    integrated_candidate_sha: OidFile,
    broker_build_identity: String,
    host_profile_digest: String,
    suite_identity: String,
}

impl HostFile {
    fn decode(&self) -> Result<HostActivationCoordinates, RuntimeLoadError> {
        Ok(HostActivationCoordinates {
            integrated_candidate_sha: self.integrated_candidate_sha.decode()?,
            broker_build_identity: hex_array(&self.broker_build_identity)?,
            host_profile_digest: hex_array(&self.host_profile_digest)?,
            suite_identity: hex_array(&self.suite_identity)?,
        })
    }

    fn encode(value: HostActivationCoordinates) -> Self {
        Self {
            integrated_candidate_sha: OidFile::encode(value.integrated_candidate_sha),
            broker_build_identity: hex::encode(value.broker_build_identity),
            host_profile_digest: hex::encode(value.host_profile_digest),
            suite_identity: hex::encode(value.suite_identity),
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PermitFile {
    authorized_by: String,
    host: HostFile,
    request_digest: String,
    manifest_digest: String,
    isolation_profile_digest: String,
    source_oid: OidFile,
    base_oid: OidFile,
    test_identity: String,
    fixture_identity: String,
    fixture_signer: String,
    nonce: String,
    not_before: u64,
    expires_at: u64,
    directive: Option<String>,
}

impl PermitFile {
    fn decode(&self) -> Result<QualificationPermit, RuntimeLoadError> {
        Ok(QualificationPermit {
            authorized_by: VerifiedSigner(hex_array(&self.authorized_by)?),
            host: self.host.decode()?,
            fixture_job: FixtureJobCoordinates {
                request_digest: hex_array(&self.request_digest)?,
                manifest_digest: hex_array(&self.manifest_digest)?,
                isolation_profile_digest: hex_array(&self.isolation_profile_digest)?,
                source_oid: self.source_oid.decode()?,
                base_oid: self.base_oid.decode()?,
                test_identity: hex_array(&self.test_identity)?,
            },
            fixture_identity: hex_array(&self.fixture_identity)?,
            fixture_signer: VerifiedSigner(hex_array(&self.fixture_signer)?),
            nonce: hex_array(&self.nonce)?,
            not_before: self.not_before,
            expires_at: self.expires_at,
            directive: parse_directive(self.directive.as_deref())?,
        })
    }

    fn encode(value: QualificationPermit) -> Self {
        Self {
            authorized_by: hex::encode(value.authorized_by.0),
            host: HostFile::encode(value.host),
            request_digest: hex::encode(value.fixture_job.request_digest),
            manifest_digest: hex::encode(value.fixture_job.manifest_digest),
            isolation_profile_digest: hex::encode(value.fixture_job.isolation_profile_digest),
            source_oid: OidFile::encode(value.fixture_job.source_oid),
            base_oid: OidFile::encode(value.fixture_job.base_oid),
            test_identity: hex::encode(value.fixture_job.test_identity),
            fixture_identity: hex::encode(value.fixture_identity),
            fixture_signer: hex::encode(value.fixture_signer.0),
            nonce: hex::encode(value.nonce),
            not_before: value.not_before,
            expires_at: value.expires_at,
            directive: value.directive.map(|_| "teardown_failure".into()),
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GrantFile {
    authorized_by: String,
    host: HostFile,
    security_records_passed: u8,
    security_records_total: u8,
    probes_passed: u8,
    probes_total: u8,
    evidence_set_digest: String,
    blocker_closure_digest: String,
    all_blockers_closed: bool,
    ordinary_signer: String,
    max_capacity: u8,
    minimum_admission_interval_seconds: u64,
    expires_at: u64,
}

impl GrantFile {
    fn decode(&self) -> Result<ActivationGrant, RuntimeLoadError> {
        Ok(ActivationGrant {
            authorized_by: VerifiedSigner(hex_array(&self.authorized_by)?),
            host: self.host.decode()?,
            security_records_passed: self.security_records_passed,
            security_records_total: self.security_records_total,
            probes_passed: self.probes_passed,
            probes_total: self.probes_total,
            evidence_set_digest: hex_array(&self.evidence_set_digest)?,
            blocker_closure_digest: hex_array(&self.blocker_closure_digest)?,
            all_blockers_closed: self.all_blockers_closed,
            ordinary_signer: VerifiedSigner(hex_array(&self.ordinary_signer)?),
            max_capacity: self.max_capacity,
            minimum_admission_interval_seconds: self.minimum_admission_interval_seconds,
            expires_at: self.expires_at,
        })
    }

    fn encode(value: ActivationGrant) -> Self {
        Self {
            authorized_by: hex::encode(value.authorized_by.0),
            host: HostFile::encode(value.host),
            security_records_passed: value.security_records_passed,
            security_records_total: value.security_records_total,
            probes_passed: value.probes_passed,
            probes_total: value.probes_total,
            evidence_set_digest: hex::encode(value.evidence_set_digest),
            blocker_closure_digest: hex::encode(value.blocker_closure_digest),
            all_blockers_closed: value.all_blockers_closed,
            ordinary_signer: hex::encode(value.ordinary_signer.0),
            max_capacity: value.max_capacity,
            minimum_admission_interval_seconds: value.minimum_admission_interval_seconds,
            expires_at: value.expires_at,
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AdmitFile {
    signed_request_digest: String,
    actor_pubkey: String,
    audience_digest: String,
    idempotency_digest: String,
    source_pin_event_id: String,
    workflow_digest: String,
    job_manifest_digest: String,
    isolation_profile_digest: String,
    run_id: String,
    tip_oid: OidFile,
    base_oid: OidFile,
    issued_at: u64,
    expires_at: u64,
    wall_timeout_seconds: u32,
    attempt: u32,
    parent_attempt: u32,
    trust_class: String,
}

impl AdmitFile {
    fn decode(self) -> Result<AdmitAttemptRequest, RuntimeLoadError> {
        if self.trust_class != "accepted_reviewed" {
            return Err(RuntimeLoadError::Malformed);
        }
        Ok(AdmitAttemptRequest {
            signed_request_digest: hex_array(&self.signed_request_digest)?,
            actor_pubkey: hex_array(&self.actor_pubkey)?,
            audience_digest: hex_array(&self.audience_digest)?,
            idempotency_digest: hex_array(&self.idempotency_digest)?,
            source_pin_event_id: hex_array(&self.source_pin_event_id)?,
            workflow_digest: hex_array(&self.workflow_digest)?,
            job_manifest_digest: hex_array(&self.job_manifest_digest)?,
            isolation_profile_digest: hex_array(&self.isolation_profile_digest)?,
            run_id: hex_array(&self.run_id)?,
            tip_oid: self.tip_oid.decode()?,
            base_oid: self.base_oid.decode()?,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            wall_timeout_seconds: self.wall_timeout_seconds,
            attempt: self.attempt,
            parent_attempt: self.parent_attempt,
            trust_class: TrustClass::AcceptedReviewed,
        })
    }

    fn encode(value: AdmitAttemptRequest) -> Self {
        Self {
            signed_request_digest: hex::encode(value.signed_request_digest),
            actor_pubkey: hex::encode(value.actor_pubkey),
            audience_digest: hex::encode(value.audience_digest),
            idempotency_digest: hex::encode(value.idempotency_digest),
            source_pin_event_id: hex::encode(value.source_pin_event_id),
            workflow_digest: hex::encode(value.workflow_digest),
            job_manifest_digest: hex::encode(value.job_manifest_digest),
            isolation_profile_digest: hex::encode(value.isolation_profile_digest),
            run_id: hex::encode(value.run_id),
            tip_oid: OidFile::encode(value.tip_oid),
            base_oid: OidFile::encode(value.base_oid),
            issued_at: value.issued_at,
            expires_at: value.expires_at,
            wall_timeout_seconds: value.wall_timeout_seconds,
            attempt: value.attempt,
            parent_attempt: value.parent_attempt,
            trust_class: "accepted_reviewed".into(),
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OidFile {
    algorithm: String,
    value: String,
}

impl OidFile {
    fn decode(&self) -> Result<GitOid, RuntimeLoadError> {
        match self.algorithm.as_str() {
            "sha1" => Ok(GitOid::Sha1(hex_array(&self.value)?)),
            "sha256" => Ok(GitOid::Sha256(hex_array(&self.value)?)),
            _ => Err(RuntimeLoadError::Malformed),
        }
    }

    fn encode(value: GitOid) -> Self {
        match value {
            GitOid::Sha1(value) => Self {
                algorithm: "sha1".into(),
                value: hex::encode(value),
            },
            GitOid::Sha256(value) => Self {
                algorithm: "sha256".into(),
                value: hex::encode(value),
            },
        }
    }
}

pub(crate) fn qualification_request(permit: QualificationPermit) -> QualificationRequest {
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
        directive: permit.directive,
    }
}

fn parse_state(value: &str) -> Result<ActivationState, RuntimeLoadError> {
    match value {
        "unprovisioned" => Ok(ActivationState::Unprovisioned),
        "qualifying" => Ok(ActivationState::Qualifying),
        "reconciling" => Ok(ActivationState::Reconciling),
        "ready" => Ok(ActivationState::Ready),
        "leased" => Ok(ActivationState::Leased),
        "draining" => Ok(ActivationState::Draining),
        "quarantined" => Ok(ActivationState::Quarantined),
        _ => Err(RuntimeLoadError::Malformed),
    }
}

fn state_name(value: ActivationState) -> &'static str {
    match value {
        ActivationState::Unprovisioned => "unprovisioned",
        ActivationState::Qualifying => "qualifying",
        ActivationState::Reconciling => "reconciling",
        ActivationState::Ready => "ready",
        ActivationState::Leased => "leased",
        ActivationState::Draining => "draining",
        ActivationState::Quarantined => "quarantined",
    }
}

fn parse_directive(
    value: Option<&str>,
) -> Result<Option<QualificationDirective>, RuntimeLoadError> {
    match value {
        None => Ok(None),
        Some("teardown_failure") => Ok(Some(QualificationDirective::TeardownFailure)),
        Some(_) => Err(RuntimeLoadError::Malformed),
    }
}

fn hex_array<const N: usize>(value: &str) -> Result<[u8; N], RuntimeLoadError> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(RuntimeLoadError::Malformed);
    }
    let bytes = hex::decode(value).map_err(|_| RuntimeLoadError::Malformed)?;
    bytes.try_into().map_err(|_| RuntimeLoadError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::activation::ActivationError;
    use std::sync::mpsc;

    const ROOT: VerifiedSigner = VerifiedSigner([1; 32]);
    const FIXTURE: VerifiedSigner = VerifiedSigner([2; 32]);
    const ORDINARY: VerifiedSigner = VerifiedSigner([3; 32]);

    fn host() -> HostActivationCoordinates {
        HostActivationCoordinates {
            integrated_candidate_sha: GitOid::Sha256([4; 32]),
            broker_build_identity: [5; 32],
            host_profile_digest: [6; 32],
            suite_identity: [7; 32],
        }
    }

    fn permit(expires_at: u64) -> QualificationPermit {
        QualificationPermit {
            authorized_by: ROOT,
            host: host(),
            fixture_job: FixtureJobCoordinates {
                request_digest: [8; 32],
                manifest_digest: [9; 32],
                isolation_profile_digest: [10; 32],
                source_oid: GitOid::Sha256([11; 32]),
                base_oid: GitOid::Sha256([12; 32]),
                test_identity: [13; 32],
            },
            fixture_identity: [14; 32],
            fixture_signer: FIXTURE,
            nonce: [15; 32],
            not_before: 10,
            expires_at,
            directive: None,
        }
    }

    fn grant(expires_at: u64) -> ActivationGrant {
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
            minimum_admission_interval_seconds: 5,
            expires_at,
        }
    }

    fn admit() -> AdmitAttemptRequest {
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
            expires_at: 90,
            wall_timeout_seconds: 30,
            attempt: 1,
            parent_attempt: 0,
            trust_class: TrustClass::AcceptedReviewed,
        }
    }

    fn ordinary_authority() -> OrdinaryAuthority {
        let request = admit();
        OrdinaryAuthority {
            grant: grant(100),
            request,
            admission: OrdinaryAdmission {
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
            },
        }
    }

    fn authority(with_ordinary: bool, expires_at: u64) -> ServiceAuthority {
        let permit = permit(expires_at);
        ServiceAuthority {
            revision: 7,
            root: ROOT,
            qualification: Some(QualificationAuthority {
                permit,
                request: qualification_request(permit),
                authenticated_signer: FIXTURE,
            }),
            ordinary: with_ordinary.then(ordinary_authority),
        }
    }

    struct RuntimeFixture {
        _temporary: tempfile::TempDir,
        paths: RuntimePaths,
        expected_uid: u32,
    }

    impl RuntimeFixture {
        fn new() -> Self {
            let temporary = tempfile::tempdir().unwrap();
            let authority_root = temporary.path().join("authority");
            let activation_root = temporary.path().join("activation");
            fs::create_dir(&authority_root).unwrap();
            fs::create_dir(&activation_root).unwrap();
            fs::set_permissions(&authority_root, fs::Permissions::from_mode(DIRECTORY_MODE))
                .unwrap();
            fs::set_permissions(&activation_root, fs::Permissions::from_mode(DIRECTORY_MODE))
                .unwrap();
            let paths = RuntimePaths {
                authority_file: authority_root.join("authority-v1.json"),
                state_file: activation_root.join("state-v1.json"),
                authority_root,
                activation_root,
            };
            let authority = AuthorityFile::encode(7, ROOT, None, None).unwrap();
            let authority_bytes = serde_json::to_vec(&authority).unwrap();
            fs::write(&paths.authority_file, &authority_bytes).unwrap();
            fs::set_permissions(
                &paths.authority_file,
                fs::Permissions::from_mode(AUTHORITY_MODE),
            )
            .unwrap();
            persist_to_validated_path(
                &paths.activation_root,
                &paths.state_file,
                ActivationController::new(ROOT).snapshot(),
                1,
                7,
                Sha256::digest(&authority_bytes).into(),
            )
            .unwrap();
            fs::write(paths.activation_root.join(COORDINATOR_LOCK_FILE), b"1").unwrap();
            fs::set_permissions(
                paths.activation_root.join(COORDINATOR_LOCK_FILE),
                fs::Permissions::from_mode(STATE_MODE),
            )
            .unwrap();
            Self {
                expected_uid: nix::unistd::geteuid().as_raw(),
                _temporary: temporary,
                paths,
            }
        }

        fn store(&self) -> DurableStateStore {
            let prepared = match prepare_from_paths_for_owner(&self.paths, 20, self.expected_uid) {
                RuntimePreparation::Prepared(prepared) => prepared,
                RuntimePreparation::NotProvisioned(error) => {
                    panic!("fixture was not provisioned: {error}")
                }
                RuntimePreparation::Quarantined { reason, .. } => {
                    panic!("fixture was quarantined: {reason}")
                }
            };
            let loaded = match prepared.restore(None) {
                RuntimeBootstrap::Loaded(loaded) => loaded,
                RuntimeBootstrap::NotProvisioned(error) => {
                    panic!("fixture failed to load: {error}")
                }
                RuntimeBootstrap::Quarantined { reason, .. } => {
                    panic!("fixture load quarantined: {reason}")
                }
            };
            loaded.into_durable_parts().2
        }

        fn replace_authority(&self, authority: AuthorityFile) -> Vec<u8> {
            let bytes = serde_json::to_vec(&authority).unwrap();
            fs::set_permissions(
                &self.paths.authority_file,
                fs::Permissions::from_mode(STATE_MODE),
            )
            .unwrap();
            fs::write(&self.paths.authority_file, &bytes).unwrap();
            fs::set_permissions(
                &self.paths.authority_file,
                fs::Permissions::from_mode(AUTHORITY_MODE),
            )
            .unwrap();
            bytes
        }

        fn state_bytes(&self) -> Vec<u8> {
            fs::read(&self.paths.state_file).unwrap()
        }
    }

    #[test]
    fn wire_signer_claims_never_create_authority() {
        let authority = authority(true, 100);
        let admitted = authority.authorize_ordinary(admit()).unwrap();
        assert_eq!(admitted.signer, ORDINARY);

        let mut forged = admit();
        forged.actor_pubkey = [99; 32];
        assert_eq!(
            authority.authorize_ordinary(forged),
            Err(AdmissionBoundaryError::Unauthorized)
        );

        let request = qualification_request(permit(100));
        assert_eq!(authority.authenticate_qualification(request), Ok(FIXTURE));
        let mut forged = request;
        forged.fixture_signer = [99; 32];
        assert_eq!(
            authority.authenticate_qualification(forged),
            Err(AdmissionBoundaryError::Unauthorized)
        );
    }

    #[test]
    fn qualifying_snapshot_restores_only_under_exact_authority_binding() {
        let authority = authority(false, 100);
        let mut controller = ActivationController::new(ROOT);
        controller.start_qualification(permit(100)).unwrap();
        let hash = [31; 32];
        let mut disk = StateFile::encode(controller.snapshot(), 9, 7, hash).unwrap();
        let snapshot = disk.decode(&authority, hash, 20).unwrap();
        let restored = ActivationController::restore(ROOT, snapshot, None);
        assert_eq!(restored.quarantine_reason, None);
        assert_eq!(restored.controller.state(), ActivationState::Qualifying);
        assert_eq!(restored.controller.ordinary_capacity(20), 0);

        disk.authority_revision = 8;
        assert_eq!(
            disk.decode(&authority, hash, 20),
            Err(RuntimeLoadError::BindingMismatch)
        );
    }

    #[test]
    fn leased_snapshot_round_trips_with_exact_authority_binding() {
        let authority = authority(true, 100);
        let binding = ordinary_authority();
        let lease = LeaseToken::from_durable(DurableLeaseFields {
            lease_id: binding.admission.lease_id,
            run_id: binding.request.run_id,
            attempt: binding.request.attempt,
            signed_request_digest: binding.request.signed_request_digest,
            signer: binding.admission.signer,
            generation: 2,
            nonce: binding.admission.nonce,
            deadline_at: 51,
        });
        let mut entries = [None; NONCE_LEDGER_CAPACITY];
        entries[0] = Some(DurableNonceEntry {
            nonce: binding.admission.nonce,
            expires_at: binding.admission.expires_at,
        });
        let snapshot = DurableStateSnapshot {
            version: FORMAT_VERSION,
            root_authority: ROOT,
            state: ActivationState::Leased,
            qualification: Some(DurableQualificationState {
                permit: permit(100),
                active_lease: None,
                evidence_set_digest: Some([16; 32]),
            }),
            activation: Some(grant(100)),
            active_lease: Some(lease),
            nonce_ledger: DurableNonceLedger { entries },
            last_admission_at: Some(21),
            next_lease_generation: 3,
        };
        let hash = [42; 32];
        let mut disk = StateFile::encode(snapshot, 9, 7, hash).unwrap();

        let decoded = disk.decode(&authority, hash, 22).unwrap();
        let restored = ActivationController::restore(ROOT, decoded, None);
        assert_eq!(
            restored.quarantine_reason,
            Some(ActivationError::RestartAmbiguous)
        );
        assert_eq!(restored.controller.state(), ActivationState::Quarantined);
        assert_eq!(restored.controller.recovery_lease(), Some(lease));

        let ActiveLeaseFile::Lease(active) = &mut disk.active_lease else {
            panic!("leased state must encode an exact lease record");
        };
        active.run_id = hex::encode([99; 16]);
        assert_eq!(
            disk.decode(&authority, hash, 22),
            Err(RuntimeLoadError::BindingMismatch)
        );
    }

    #[test]
    fn stale_or_inflight_state_never_restores() {
        let authority = authority(false, 30);
        let mut controller = ActivationController::new(ROOT);
        controller.start_qualification(permit(30)).unwrap();
        let hash = [32; 32];
        let mut disk = StateFile::encode(controller.snapshot(), 1, 7, hash).unwrap();
        let QualificationLeaseFile::Legacy(active) = &disk
            .qualification
            .as_ref()
            .expect("qualification")
            .active_lease
        else {
            panic!("inactive qualification must use the legacy boolean encoding");
        };
        assert!(!*active);
        assert_eq!(
            disk.decode(&authority, hash, 30),
            Err(RuntimeLoadError::Stale)
        );
        disk.qualification
            .as_mut()
            .expect("qualification")
            .active_lease = QualificationLeaseFile::Legacy(true);
        assert_eq!(
            disk.decode(&authority, hash, 20),
            Err(RuntimeLoadError::Quarantined)
        );
    }

    #[test]
    fn exact_qualification_lease_round_trips_and_rejects_every_mutation() {
        let authority = authority(false, 100);
        let mut controller = ActivationController::new(ROOT);
        controller.start_qualification(permit(100)).unwrap();
        let lease = controller
            .admit_qualification_request(qualification_request(permit(100)), FIXTURE, 20)
            .unwrap();
        let hash = [43; 32];
        let disk = StateFile::encode(controller.snapshot(), 4, 7, hash).unwrap();
        let decoded = disk.decode(&authority, hash, 20).unwrap();
        assert_eq!(
            decoded
                .qualification
                .and_then(|qualification| qualification.active_lease),
            Some(lease)
        );
        let expired = disk.decode(&authority, hash, 100).unwrap();
        assert_eq!(
            expired
                .qualification
                .and_then(|qualification| qualification.active_lease),
            Some(lease)
        );

        let mutate = |change: fn(&mut ExactQualificationLeaseFile)| {
            let mut candidate = disk.clone();
            let QualificationLeaseFile::Lease(active) = &mut candidate
                .qualification
                .as_mut()
                .expect("qualification")
                .active_lease
            else {
                panic!("active qualification must encode an exact lease");
            };
            change(active);
            assert_eq!(
                candidate.decode(&authority, hash, 20),
                Err(RuntimeLoadError::BindingMismatch)
            );
        };
        mutate(|active| active.fixture_identity = hex::encode([99; 32]));
        mutate(|active| active.lease_id = hex::encode([99; 16]));
        mutate(|active| active.generation += 1);
        mutate(|active| active.nonce = hex::encode([99; 32]));
        mutate(|active| active.directive = Some("teardown_failure".into()));

        let mut wrong_expiry = disk.clone();
        wrong_expiry.nonce_ledger[0].expires_at -= 1;
        assert_eq!(
            wrong_expiry.decode(&authority, hash, 20),
            Err(RuntimeLoadError::BindingMismatch)
        );

        let mut with_evidence = disk.clone();
        with_evidence
            .qualification
            .as_mut()
            .expect("qualification")
            .evidence_set_digest = Some(hex::encode([44; 32]));
        assert_eq!(
            with_evidence.decode(&authority, hash, 20),
            Err(RuntimeLoadError::BindingMismatch)
        );

        let mut value = serde_json::to_value(&disk).unwrap();
        value["qualification"]["active_lease"]["unknown"] = serde_json::json!(true);
        assert!(serde_json::from_value::<StateFile>(value).is_err());
    }

    #[test]
    fn ready_snapshot_without_current_host_validation_quarantines() {
        let authority = authority(true, 100);
        let snapshot = DurableStateSnapshot {
            version: FORMAT_VERSION,
            root_authority: ROOT,
            state: ActivationState::Ready,
            qualification: Some(DurableQualificationState {
                permit: permit(100),
                active_lease: None,
                evidence_set_digest: Some([16; 32]),
            }),
            activation: Some(grant(100)),
            active_lease: None,
            nonce_ledger: DurableNonceLedger {
                entries: [None; NONCE_LEDGER_CAPACITY],
            },
            last_admission_at: None,
            next_lease_generation: 1,
        };
        let hash = [33; 32];
        let disk = StateFile::encode(snapshot, 2, 7, hash).unwrap();
        let decoded = disk.decode(&authority, hash, 20).unwrap();
        let restored = ActivationController::restore(ROOT, decoded, None);
        assert_eq!(restored.controller.state(), ActivationState::Quarantined);
        assert_eq!(restored.controller.ordinary_capacity(20), 0);
        assert_eq!(
            restored.quarantine_reason,
            Some(ActivationError::SnapshotInvalid)
        );
    }

    #[test]
    fn state_codec_is_closed_and_bounded() {
        assert_eq!(hex_array::<2>("00ff"), Ok([0, 255]));
        for malformed in ["FF", "abc", "00gg", " 00"] {
            assert_eq!(hex_array::<2>(malformed), Err(RuntimeLoadError::Malformed));
        }
        assert_eq!(parse_state("READY"), Err(RuntimeLoadError::Malformed));
        assert_eq!(
            parse_directive(Some("anything_else")),
            Err(RuntimeLoadError::Malformed)
        );
    }

    #[test]
    fn authority_json_rejects_unknown_fields_and_noncanonical_hex() {
        let valid = serde_json::json!({
            "version": 1,
            "revision": 7,
            "root_authority": hex::encode(ROOT.0),
            "qualification": null,
            "ordinary": null
        });
        let decoded: AuthorityFile = serde_json::from_value(valid.clone()).unwrap();
        assert_eq!(decoded.decode().unwrap().root(), ROOT);

        let mut unknown = valid.clone();
        unknown["wire_signer"] = serde_json::Value::String(hex::encode([99; 32]));
        assert!(serde_json::from_value::<AuthorityFile>(unknown).is_err());

        let mut uppercase = valid;
        uppercase["root_authority"] = serde_json::Value::String("AA".repeat(32));
        let decoded: AuthorityFile = serde_json::from_value(uppercase).unwrap();
        assert!(matches!(decoded.decode(), Err(RuntimeLoadError::Malformed)));
    }

    #[test]
    fn missing_authority_is_zero_capacity_by_construction() {
        let bootstrap = RuntimeBootstrap::NotProvisioned(RuntimeLoadError::NotProvisioned);
        assert_eq!(bootstrap.ordinary_capacity(20), 0);
        let quarantined = RuntimeBootstrap::Quarantined {
            controller: Box::new(quarantine(ROOT)),
            reason: RuntimeLoadError::Malformed,
        };
        assert_eq!(quarantined.ordinary_capacity(20), 0);
    }

    #[test]
    fn exhausted_state_revision_refuses_before_host_io() {
        let mut runtime = LoadedRuntime {
            controller: ActivationController::new(ROOT),
            authority: ServiceAuthority {
                revision: 7,
                root: ROOT,
                qualification: None,
                ordinary: None,
            },
            state_revision: u64::MAX,
            authority_sha256: [35; 32],
            paths: RuntimePaths::canonical(),
            expected_uid: 0,
        };
        assert_eq!(runtime.persist(), Err(RuntimeLoadError::PersistFailed));
    }

    #[test]
    fn durable_store_commits_only_to_its_loaded_runtime_paths() {
        let fixture = RuntimeFixture::new();
        let mut store = fixture.store();

        store
            .commit(ActivationController::new(ROOT).snapshot())
            .unwrap();

        assert_eq!(store.revision(), 2);
        let persisted: StateFile = serde_json::from_slice(&fixture.state_bytes()).unwrap();
        assert_eq!(persisted.revision(), 2);
    }

    #[test]
    fn durable_store_refuses_a_stale_state_revision_without_replacing_it() {
        let fixture = RuntimeFixture::new();
        let mut store = fixture.store();
        let authority_bytes = fs::read(&fixture.paths.authority_file).unwrap();
        persist_to_validated_path(
            &fixture.paths.activation_root,
            &fixture.paths.state_file,
            ActivationController::new(ROOT).snapshot(),
            2,
            7,
            Sha256::digest(authority_bytes).into(),
        )
        .unwrap();
        let newer_state = fixture.state_bytes();

        assert_eq!(
            store.commit(ActivationController::new(ROOT).snapshot()),
            Err(RuntimeLoadError::BindingMismatch)
        );
        assert_eq!(store.revision(), 1);
        assert_eq!(fixture.state_bytes(), newer_state);
    }

    #[test]
    fn durable_store_refuses_changed_authority_bytes_and_revision() {
        for replacement in [
            AuthorityFile::encode(7, VerifiedSigner([9; 32]), None, None).unwrap(),
            AuthorityFile::encode(8, ROOT, None, None).unwrap(),
        ] {
            let fixture = RuntimeFixture::new();
            let mut store = fixture.store();
            fixture.replace_authority(replacement);
            let state_before = fixture.state_bytes();

            assert_eq!(
                store.commit(ActivationController::new(ROOT).snapshot()),
                Err(RuntimeLoadError::BindingMismatch)
            );
            assert_eq!(store.revision(), 1);
            assert_eq!(fixture.state_bytes(), state_before);
        }
    }

    #[test]
    fn durable_store_refuses_a_pending_pair_publication_marker() {
        let fixture = RuntimeFixture::new();
        let mut store = fixture.store();
        let marker = fixture.paths.activation_root.join(COORDINATOR_MARKER_FILE);
        fs::write(&marker, b"pending-v1").unwrap();
        fs::set_permissions(&marker, fs::Permissions::from_mode(STATE_MODE)).unwrap();
        let state_before = fixture.state_bytes();

        assert_eq!(
            store.commit(ActivationController::new(ROOT).snapshot()),
            Err(RuntimeLoadError::Quarantined)
        );
        assert_eq!(store.revision(), 1);
        assert_eq!(fixture.state_bytes(), state_before);
    }

    #[test]
    fn coordinator_rotation_wins_the_lock_race_against_a_stale_daemon_commit() {
        let fixture = RuntimeFixture::new();
        let mut store = fixture.store();
        let lock = acquire_runtime_lock(
            &fixture.paths,
            FlockArg::LockExclusive,
            fixture.expected_uid,
        )
        .unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        let daemon = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            let result = store.commit(ActivationController::new(ROOT).snapshot());
            (result, store.revision())
        });
        started_rx.recv().unwrap();

        let marker = fixture.paths.activation_root.join(COORDINATOR_MARKER_FILE);
        fs::write(&marker, b"pending-v1").unwrap();
        fs::set_permissions(&marker, fs::Permissions::from_mode(STATE_MODE)).unwrap();
        let authority_bytes =
            fixture.replace_authority(AuthorityFile::encode(8, ROOT, None, None).unwrap());
        persist_to_validated_path(
            &fixture.paths.activation_root,
            &fixture.paths.state_file,
            ActivationController::new(ROOT).snapshot(),
            2,
            8,
            Sha256::digest(authority_bytes).into(),
        )
        .unwrap();
        fs::remove_file(marker).unwrap();
        let rotated_authority = fs::read(&fixture.paths.authority_file).unwrap();
        let rotated_state = fixture.state_bytes();
        drop(lock);

        let (result, revision) = daemon.join().unwrap();
        assert_eq!(result, Err(RuntimeLoadError::BindingMismatch));
        assert_eq!(revision, 1);
        assert_eq!(
            fs::read(&fixture.paths.authority_file).unwrap(),
            rotated_authority
        );
        assert_eq!(fixture.state_bytes(), rotated_state);
    }

    #[test]
    fn stale_state_temporary_refuses_without_unlinking_or_replacing() {
        let fixture = RuntimeFixture::new();
        let mut store = fixture.store();
        let temporary = fixture.paths.activation_root.join(".state-v1.json.tmp");
        fs::write(&temporary, b"untrusted-stale-temporary").unwrap();
        let temporary_before = temporary.symlink_metadata().unwrap();
        let state_before = fixture.state_bytes();

        assert_eq!(
            store.commit(ActivationController::new(ROOT).snapshot()),
            Err(RuntimeLoadError::StateTemporaryExists)
        );
        assert_eq!(store.revision(), 1);
        assert_eq!(fixture.state_bytes(), state_before);
        let temporary_after = temporary.symlink_metadata().unwrap();
        assert_eq!(
            file_identity(&temporary_after),
            file_identity(&temporary_before)
        );
    }

    #[test]
    fn atomic_state_publication_syncs_a_committed_mode_0600_record() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = temporary.path().join("activation");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(DIRECTORY_MODE)).unwrap();
        let destination = directory.join("state-v1.json");
        let snapshot = ActivationController::new(ROOT).snapshot();
        persist_to_validated_path(&directory, &destination, snapshot, 2, 7, [34; 32]).unwrap();

        let metadata = destination.metadata().unwrap();
        assert!(metadata.file_type().is_file());
        assert_eq!(metadata.permissions().mode() & 0o7777, STATE_MODE);
        assert!(!directory.join(".state-v1.json.tmp").exists());
        let persisted: StateFile = serde_json::from_slice(&fs::read(destination).unwrap()).unwrap();
        assert!(persisted.committed);
        assert_eq!(persisted.revision, 2);
        assert_eq!(persisted.authority_revision, 7);
    }

    #[test]
    fn non_root_artifacts_fail_the_production_metadata_gate() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = temporary.path().join("authority");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(DIRECTORY_MODE)).unwrap();
        if directory.metadata().unwrap().uid() != 0 {
            assert_eq!(
                validate_directory(&directory),
                Err(RuntimeLoadError::UnsafeMetadata)
            );
        }
    }
}
