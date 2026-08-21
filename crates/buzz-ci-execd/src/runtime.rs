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
    AdmitAttemptRequest, BrokerResponse, FrameHeader, GitOid, QualificationDirective,
    QualificationRequest, TrustClass,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    activation::{
        ActivationController, ActivationGrant, ActivationState, AdmissionTrustClass,
        DurableNonceEntry, DurableNonceLedger, DurableQualificationState, DurableStateSnapshot,
        FixtureJobCoordinates, HostActivationCoordinates, LeaseToken, OrdinaryAdmission,
        OrdinaryJobCoordinates, QualificationLease, QualificationPermit, ReadyRestoreValidation,
        VerifiedSigner, NONCE_LEDGER_CAPACITY,
    },
    control::{
        ActivationDispatch, AdmissionBoundaryError, OrdinaryAdmissionBoundary,
        QualificationAdmissionBoundary,
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

const DIRECTORY_MODE: u32 = 0o700;
const AUTHORITY_MODE: u32 = 0o400;
const STATE_MODE: u32 = 0o600;
const MAX_AUTHORITY_BYTES: u64 = 64 * 1024;
const MAX_STATE_BYTES: u64 = 128 * 1024;
const FORMAT_VERSION: u8 = 1;

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

    /// Compose restored state with execution/response handlers.
    ///
    /// The returned dispatcher always authenticates through the loaded root
    /// artifacts before either handler can receive an admitted lease.
    pub fn compose<O, Q>(
        self,
        ordinary: O,
        qualification: Q,
    ) -> ActivationDispatch<AuthorityOrdinary<O>, AuthorityQualification<Q>>
    where
        O: OrdinaryLeaseResponse,
        Q: QualificationLeaseResponse,
    {
        let qualification_authority = self.authority.clone();
        ActivationDispatch::new(
            self.controller,
            AuthorityOrdinary {
                authority: self.authority,
                response: ordinary,
            },
            AuthorityQualification {
                authority: qualification_authority,
                response: qualification,
            },
        )
    }

    /// Persist an idle snapshot atomically beneath the canonical activation root.
    ///
    /// In-flight snapshots are refused because their opaque receipts cannot be
    /// reconstructed safely after a process restart.
    pub fn persist(&self) -> Result<(), RuntimeLoadError> {
        let next_revision = self
            .state_revision
            .checked_add(1)
            .ok_or(RuntimeLoadError::PersistFailed)?;
        persist_to_path(
            Path::new(ACTIVATION_ROOT),
            Path::new(ACTIVATION_STATE_FILE),
            self.controller.snapshot(),
            next_revision,
            self.authority.revision,
            self.authority_sha256,
        )
    }
}

/// Encodes the result of an ordinary lease admitted under loaded authority.
pub trait OrdinaryLeaseResponse {
    /// Produce one bounded response after the controller allocates the lease.
    fn admitted_response(
        &mut self,
        header: FrameHeader,
        request: AdmitAttemptRequest,
        admission: OrdinaryAdmission,
        lease: LeaseToken,
        now: u64,
    ) -> BrokerResponse;
}

/// Encodes or executes a qualification lease admitted under loaded authority.
pub trait QualificationLeaseResponse {
    /// Produce one bounded response after the controller allocates the fixture lease.
    fn admitted_response(
        &mut self,
        header: FrameHeader,
        request: QualificationRequest,
        lease: QualificationLease,
        now: u64,
    ) -> BrokerResponse;
}

/// Authority-enforcing ordinary boundary created only by [`LoadedRuntime::compose`].
pub struct AuthorityOrdinary<R> {
    authority: ServiceAuthority,
    response: R,
}

impl<R: OrdinaryLeaseResponse> OrdinaryAdmissionBoundary for AuthorityOrdinary<R> {
    fn authorize(
        &mut self,
        _header: FrameHeader,
        request: AdmitAttemptRequest,
    ) -> Result<OrdinaryAdmission, AdmissionBoundaryError> {
        self.authority.authorize_ordinary(request)
    }

    fn admitted_response(
        &mut self,
        header: FrameHeader,
        request: AdmitAttemptRequest,
        admission: OrdinaryAdmission,
        lease: LeaseToken,
        now: u64,
    ) -> BrokerResponse {
        self.response
            .admitted_response(header, request, admission, lease, now)
    }
}

/// Authority-enforcing qualification boundary created by [`LoadedRuntime::compose`].
pub struct AuthorityQualification<R> {
    authority: ServiceAuthority,
    response: R,
}

impl<R: QualificationLeaseResponse> QualificationAdmissionBoundary for AuthorityQualification<R> {
    fn authenticate(
        &mut self,
        _header: FrameHeader,
        request: QualificationRequest,
    ) -> Result<VerifiedSigner, AdmissionBoundaryError> {
        self.authority.authenticate_qualification(request)
    }

    fn admitted_response(
        &mut self,
        header: FrameHeader,
        request: QualificationRequest,
        lease: QualificationLease,
        now: u64,
    ) -> BrokerResponse {
        self.response.admitted_response(header, request, lease, now)
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

#[derive(Clone)]
struct RuntimePaths {
    authority_root: PathBuf,
    authority_file: PathBuf,
    activation_root: PathBuf,
    state_file: PathBuf,
}

impl RuntimePaths {
    fn canonical() -> Self {
        Self {
            authority_root: AUTHORITY_ROOT.into(),
            authority_file: AUTHORITY_FILE.into(),
            activation_root: ACTIVATION_ROOT.into(),
            state_file: ACTIVATION_STATE_FILE.into(),
        }
    }
}

/// Load only the canonical authority and activation artifacts.
pub fn load_runtime(
    now: u64,
    ready_validation: Option<ReadyRestoreValidation>,
) -> RuntimeBootstrap {
    load_from_paths(&RuntimePaths::canonical(), now, ready_validation)
}

fn load_from_paths(
    paths: &RuntimePaths,
    now: u64,
    ready_validation: Option<ReadyRestoreValidation>,
) -> RuntimeBootstrap {
    let authority_bytes = match read_artifact(
        &paths.authority_root,
        &paths.authority_file,
        AUTHORITY_MODE,
        MAX_AUTHORITY_BYTES,
    ) {
        Ok(bytes) => bytes,
        Err(error) => return RuntimeBootstrap::NotProvisioned(error),
    };
    let authority_disk: AuthorityFile = match serde_json::from_slice(&authority_bytes) {
        Ok(value) => value,
        Err(_) => return RuntimeBootstrap::NotProvisioned(RuntimeLoadError::Malformed),
    };
    let authority = match authority_disk.decode() {
        Ok(value) => value,
        Err(error) => return RuntimeBootstrap::NotProvisioned(error),
    };
    let root = authority.root;
    let authority_sha256: [u8; 32] = Sha256::digest(&authority_bytes).into();

    let state_bytes = match read_artifact(
        &paths.activation_root,
        &paths.state_file,
        STATE_MODE,
        MAX_STATE_BYTES,
    ) {
        Ok(bytes) => bytes,
        Err(error) => {
            return RuntimeBootstrap::Quarantined {
                controller: Box::new(quarantine(root)),
                reason: error,
            }
        }
    };
    let state_disk: StateFile = match serde_json::from_slice(&state_bytes) {
        Ok(value) => value,
        Err(_) => {
            return RuntimeBootstrap::Quarantined {
                controller: Box::new(quarantine(root)),
                reason: RuntimeLoadError::Malformed,
            }
        }
    };
    let snapshot = match state_disk.decode(&authority, authority_sha256, now) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return RuntimeBootstrap::Quarantined {
                controller: Box::new(quarantine(root)),
                reason: error,
            }
        }
    };
    let state_revision = state_disk.revision;
    let restored = ActivationController::restore(root, snapshot, ready_validation);
    if restored.quarantine_reason.is_some() {
        RuntimeBootstrap::Quarantined {
            controller: Box::new(restored.controller),
            reason: RuntimeLoadError::Quarantined,
        }
    } else {
        RuntimeBootstrap::Loaded(Box::new(LoadedRuntime {
            controller: restored.controller,
            authority,
            state_revision,
            authority_sha256,
        }))
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

fn read_artifact(
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

fn validate_directory(path: &Path) -> Result<(), RuntimeLoadError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => RuntimeLoadError::NotProvisioned,
        _ => RuntimeLoadError::UnsafeMetadata,
    })?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != 0
        || metadata.gid() != 0
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
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o7777 != expected_mode
        || metadata.len() == 0
        || metadata.len() > max_bytes
    {
        return Err(RuntimeLoadError::UnsafeMetadata);
    }
    Ok(())
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

fn persist_to_path(
    directory: &Path,
    destination: &Path,
    snapshot: DurableStateSnapshot,
    revision: u64,
    authority_revision: u64,
    authority_sha256: [u8; 32],
) -> Result<(), RuntimeLoadError> {
    validate_directory(directory)?;
    persist_to_validated_path(
        directory,
        destination,
        snapshot,
        revision,
        authority_revision,
        authority_sha256,
    )
}

fn persist_to_validated_path(
    directory: &Path,
    destination: &Path,
    snapshot: DurableStateSnapshot,
    revision: u64,
    authority_revision: u64,
    authority_sha256: [u8; 32],
) -> Result<(), RuntimeLoadError> {
    if snapshot.active_lease.is_some()
        || snapshot
            .qualification
            .is_some_and(|state| state.active_lease.is_some())
        || matches!(
            snapshot.state,
            ActivationState::Leased | ActivationState::Draining
        )
        || revision == 0
    {
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
    let mut file = options
        .open(&temporary)
        .map_err(|_| RuntimeLoadError::PersistFailed)?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| RuntimeLoadError::PersistFailed)?;
    fs::rename(&temporary, destination).map_err(|_| RuntimeLoadError::PersistFailed)?;
    File::open(directory)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| RuntimeLoadError::PersistFailed)?;
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityFile {
    version: u8,
    revision: u64,
    root_authority: String,
    qualification: Option<QualificationAuthorityFile>,
    ordinary: Option<OrdinaryAuthorityFile>,
}

impl AuthorityFile {
    fn decode(self) -> Result<ServiceAuthority, RuntimeLoadError> {
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
}

#[derive(Deserialize)]
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
}

#[derive(Deserialize)]
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
            signer: authenticated_signer,
            nonce: hex_array(&self.nonce)?,
            expires_at: request.expires_at,
            trust_class: AdmissionTrustClass::AcceptedReviewed,
        };
        Ok(OrdinaryAuthority {
            grant,
            request,
            admission,
        })
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StateFile {
    version: u8,
    revision: u64,
    authority_revision: u64,
    authority_sha256: String,
    committed: bool,
    state: String,
    qualification: Option<DurableQualificationFile>,
    activation: Option<GrantFile>,
    active_lease: bool,
    nonce_ledger: Vec<NonceFile>,
    last_admission_at: Option<u64>,
    next_lease_generation: u64,
}

impl StateFile {
    fn decode(
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
            || self.active_lease
            || self.nonce_ledger.len() > NONCE_LEDGER_CAPACITY
        {
            return Err(RuntimeLoadError::BindingMismatch);
        }
        let state = parse_state(&self.state)?;
        let qualification = self
            .qualification
            .as_ref()
            .map(DurableQualificationFile::decode)
            .transpose()?;
        let activation = self
            .activation
            .as_ref()
            .map(GrantFile::decode)
            .transpose()?;
        if qualification.as_ref().map(|value| value.permit)
            != authority.qualification.as_ref().map(|value| value.permit)
            || activation != authority.ordinary.as_ref().map(|value| value.grant)
        {
            return Err(RuntimeLoadError::BindingMismatch);
        }
        if (state == ActivationState::Qualifying
            && qualification.is_some_and(|value| now >= value.permit.expires_at))
            || (state == ActivationState::Ready
                && activation.is_some_and(|value| now >= value.expires_at))
        {
            return Err(RuntimeLoadError::Stale);
        }
        let mut entries = [None; NONCE_LEDGER_CAPACITY];
        for (index, value) in self.nonce_ledger.iter().enumerate() {
            entries[index] = Some(value.decode()?);
        }
        Ok(DurableStateSnapshot {
            version: FORMAT_VERSION,
            root_authority: authority.root,
            state,
            qualification,
            activation,
            active_lease: None,
            nonce_ledger: DurableNonceLedger { entries },
            last_admission_at: self.last_admission_at,
            next_lease_generation: self.next_lease_generation,
        })
    }

    fn encode(
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
            active_lease: false,
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

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DurableQualificationFile {
    permit: PermitFile,
    evidence_set_digest: Option<String>,
    active_lease: bool,
}

impl DurableQualificationFile {
    fn decode(&self) -> Result<DurableQualificationState, RuntimeLoadError> {
        if self.active_lease {
            return Err(RuntimeLoadError::Quarantined);
        }
        Ok(DurableQualificationState {
            permit: self.permit.decode()?,
            active_lease: None,
            evidence_set_digest: self
                .evidence_set_digest
                .as_ref()
                .map(|value| hex_array(value))
                .transpose()?,
        })
    }

    fn encode(value: DurableQualificationState) -> Result<Self, RuntimeLoadError> {
        if value.active_lease.is_some() {
            return Err(RuntimeLoadError::PersistFailed);
        }
        Ok(Self {
            permit: PermitFile::encode(value.permit),
            evidence_set_digest: value.evidence_set_digest.map(hex::encode),
            active_lease: false,
        })
    }
}

#[derive(Deserialize, Serialize)]
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

#[derive(Deserialize)]
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

fn qualification_request(permit: QualificationPermit) -> QualificationRequest {
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
                signer: ORDINARY,
                nonce: [30; 32],
                expires_at: request.expires_at,
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
    fn stale_or_inflight_state_never_restores() {
        let authority = authority(false, 30);
        let mut controller = ActivationController::new(ROOT);
        controller.start_qualification(permit(30)).unwrap();
        let hash = [32; 32];
        let mut disk = StateFile::encode(controller.snapshot(), 1, 7, hash).unwrap();
        assert_eq!(
            disk.decode(&authority, hash, 30),
            Err(RuntimeLoadError::Stale)
        );
        disk.active_lease = true;
        assert_eq!(
            disk.decode(&authority, hash, 20),
            Err(RuntimeLoadError::BindingMismatch)
        );
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
        let runtime = LoadedRuntime {
            controller: ActivationController::new(ROOT),
            authority: ServiceAuthority {
                revision: 7,
                root: ROOT,
                qualification: None,
                ordinary: None,
            },
            state_revision: u64::MAX,
            authority_sha256: [35; 32],
        };
        assert_eq!(runtime.persist(), Err(RuntimeLoadError::PersistFailed));
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
