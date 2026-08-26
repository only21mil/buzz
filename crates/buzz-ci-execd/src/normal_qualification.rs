//! Root-owned sealed-case loading for normal qualification execution.
//!
//! The request selects a case only by its sealed fixture identity. Candidate
//! and live host/job coordinates are checked after selection, so a case sealed
//! for another candidate cannot cause a fallback search.

use std::{
    fs::{self, Metadata, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use buzz_ci_broker_protocol::{GitOid, QualificationDirective, QualificationRequest};
use serde::Deserialize;

use crate::{
    activation::{QualificationLease, QualificationOutcome},
    durable_dispatch::ExecutionUnavailable,
    normal_engine::NormalQualificationBackend,
};

/// Canonical root-owned materialized qualification-case directory.
pub const QUALIFICATION_CASE_ROOT: &str = "/etc/buzzci/qualification-cases";

const CASE_DIRECTORY_MODE: u32 = 0o755;
const CASE_FILE_MODE: u32 = 0o444;
const MAX_CASE_BYTES: u64 = 64 * 1024;

/// Expected control result from the reviewed qualification catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NormalQualificationExpectedCode {
    Ok,
    PolicyDenied,
    ReplayConflict,
    NoCapacity,
}

/// Resource-limit fixture selected by a sealed case.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceLimitFixture {
    CpuBurn,
    MemoryBalloon,
    PidForkStorm,
    DiskFill,
    LogFlood,
    WallTimeOverrun,
    ArtifactOverrun,
}

/// Component whose crash or replacement is exercised by a sealed case.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CrashFixture {
    Act,
    Podman,
    Proxy,
    Materializer,
    Broker,
    SimulatedHost,
    CleanupAdapter,
    DnsAdapter,
}

/// Closed behavior selected by the reviewed TM-ID and case-name catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NormalQualificationSemantics {
    ExclusiveCapacity,
    SocketIsolation,
    DnsReadback,
    PrestartOci,
    ResourceLimit(ResourceLimitFixture),
    HostileArtifacts,
    TerminalOrdering,
    CrashRecovery(CrashFixture),
    ReuseAfterCrash(CrashFixture),
    RetryAttempt(u8),
    ExpiryRefusal,
    ReplayRefusal,
    RateLimitRefusal,
    ConcurrencyPrimary,
    ConcurrencyOverflowRefusal,
}

/// Reviewed case identity and the required durable readback set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NormalQualificationCase {
    pub test_id: &'static str,
    pub case_name: &'static str,
    pub semantics: NormalQualificationSemantics,
    pub expected_code: NormalQualificationExpectedCode,
    pub required_readbacks: &'static str,
}

/// Fresh host and materialization facts measured by the normal primitive set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NormalQualificationLiveBinding {
    pub integrated_candidate_sha: GitOid,
    pub broker_build_identity: [u8; 32],
    pub host_profile_digest: [u8; 32],
    pub suite_identity: [u8; 32],
    pub request_digest: [u8; 32],
    pub manifest_digest: [u8; 32],
    pub isolation_profile_digest: [u8; 32],
    pub source_oid: GitOid,
    pub base_oid: GitOid,
    pub job_identity: [u8; 32],
}

impl NormalQualificationLiveBinding {
    fn matches(self, request: QualificationRequest) -> bool {
        self.integrated_candidate_sha == request.integrated_candidate_sha
            && self.broker_build_identity == request.broker_build_identity
            && self.host_profile_digest == request.host_profile_digest
            && self.suite_identity == request.suite_identity
            && self.request_digest == request.request_digest
            && self.manifest_digest == request.manifest_digest
            && self.isolation_profile_digest == request.isolation_profile_digest
            && self.source_oid == request.source_oid
            && self.base_oid == request.base_oid
            && self.job_identity == request.job_identity
    }
}

/// Decisive result returned by the normal DNS/materializer/proxy/Act path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NormalQualificationCaseResult {
    Passed { evidence_set_digest: [u8; 32] },
    Failed,
}

/// Narrow adapter to the same host operations used by `NormalExecutionBackend`.
///
/// Implementations must derive all paths, commands, sockets, units, and
/// evidence from root-owned normal-engine plans. `preflight_case` is a
/// non-reserving availability check because admission may reject a negative
/// qualification case after preflight.
pub trait NormalQualificationPrimitiveSet {
    fn live_binding(
        &mut self,
        case: NormalQualificationCase,
    ) -> Result<NormalQualificationLiveBinding, ExecutionUnavailable>;

    fn preflight_case(
        &mut self,
        case: NormalQualificationCase,
        request: QualificationRequest,
    ) -> Result<(), ExecutionUnavailable>;

    fn execute_case(
        &mut self,
        case: NormalQualificationCase,
        request: QualificationRequest,
        lease: QualificationLease,
        now: u64,
    ) -> Result<NormalQualificationCaseResult, ExecutionUnavailable>;
}

/// Production normal qualification backend backed by the sealed case store.
pub struct ProductionNormalQualificationBackend<P> {
    store: QualificationCaseStore,
    primitives: P,
    clock: Box<dyn QualificationClock>,
}

impl<P: NormalQualificationPrimitiveSet> ProductionNormalQualificationBackend<P> {
    /// Open and validate the complete canonical production case catalog.
    pub fn open(primitives: P) -> Result<Self, ExecutionUnavailable> {
        Self::open_with(
            QualificationCaseStore::canonical(),
            primitives,
            Box::new(SystemQualificationClock),
        )
    }

    fn open_with(
        store: QualificationCaseStore,
        primitives: P,
        clock: Box<dyn QualificationClock>,
    ) -> Result<Self, ExecutionUnavailable> {
        store.validate_catalog()?;
        Ok(Self {
            store,
            primitives,
            clock,
        })
    }
}

impl<P: NormalQualificationPrimitiveSet> NormalQualificationBackend
    for ProductionNormalQualificationBackend<P>
{
    fn preflight(&mut self, request: QualificationRequest) -> Result<(), ExecutionUnavailable> {
        if request.directive.is_some() {
            return Err(ExecutionUnavailable);
        }
        let resolved = self.store.resolve(request)?;
        let now = self.clock.now()?;
        if resolved.case.expected_code == NormalQualificationExpectedCode::Ok {
            validate_time(request, now)?;
        }
        let live = self.primitives.live_binding(resolved.case)?;
        if !live.matches(request) {
            return Err(ExecutionUnavailable);
        }
        self.primitives.preflight_case(resolved.case, request)
    }

    fn execute(
        &mut self,
        request: QualificationRequest,
        lease: QualificationLease,
        now: u64,
    ) -> Result<QualificationOutcome, ExecutionUnavailable> {
        if request.directive.is_some() || !lease_matches(request, lease) {
            return Err(ExecutionUnavailable);
        }
        let resolved = self.store.resolve(request)?;
        let live = self.primitives.live_binding(resolved.case)?;
        if !live.matches(request) {
            return Err(ExecutionUnavailable);
        }
        if resolved.case.expected_code != NormalQualificationExpectedCode::Ok {
            return Ok(QualificationOutcome::Failed);
        }
        validate_time(request, now)?;
        match self
            .primitives
            .execute_case(resolved.case, request, lease, now)?
        {
            NormalQualificationCaseResult::Passed {
                evidence_set_digest,
            } if evidence_set_digest != [0; 32] => Ok(QualificationOutcome::Accepted {
                evidence_set_digest,
            }),
            NormalQualificationCaseResult::Passed { .. } => Err(ExecutionUnavailable),
            NormalQualificationCaseResult::Failed => Ok(QualificationOutcome::Failed),
        }
    }
}

fn validate_time(request: QualificationRequest, now: u64) -> Result<(), ExecutionUnavailable> {
    if now < request.not_before || now >= request.expires_at {
        Err(ExecutionUnavailable)
    } else {
        Ok(())
    }
}

fn lease_matches(request: QualificationRequest, lease: QualificationLease) -> bool {
    let mut expected_lease_id = [0; 16];
    expected_lease_id.copy_from_slice(&request.fixture_identity[..16]);
    lease.fixture_identity() == request.fixture_identity
        && lease.lease_id() == expected_lease_id
        && lease.nonce() == request.nonce
        && lease.directive() == request.directive
        && lease.generation() != 0
}

trait QualificationClock {
    fn now(&self) -> Result<u64, ExecutionUnavailable>;
}

struct SystemQualificationClock;

impl QualificationClock for SystemQualificationClock {
    fn now(&self) -> Result<u64, ExecutionUnavailable> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .map_err(|_| ExecutionUnavailable)
    }
}

#[derive(Clone, Copy)]
struct QualificationCaseSpec {
    case: NormalQualificationCase,
}

impl QualificationCaseSpec {
    fn path(self, root: &Path) -> PathBuf {
        root.join(self.case.test_id)
            .join(format!("{}.json", self.case.case_name))
    }
}

struct QualificationCaseStore {
    root: PathBuf,
    expected_uid: u32,
    expected_gid: u32,
    specs: Vec<QualificationCaseSpec>,
}

impl QualificationCaseStore {
    fn canonical() -> Self {
        Self {
            root: QUALIFICATION_CASE_ROOT.into(),
            expected_uid: 0,
            expected_gid: 0,
            specs: NORMAL_CASE_CATALOG.to_vec(),
        }
    }

    fn validate_catalog(&self) -> Result<(), ExecutionUnavailable> {
        let mut identities = Vec::with_capacity(self.specs.len());
        for spec in &self.specs {
            let loaded = self.load(*spec)?;
            if identities.contains(&loaded.request.fixture_identity) {
                return Err(ExecutionUnavailable);
            }
            identities.push(loaded.request.fixture_identity);
        }
        Ok(())
    }

    fn resolve(
        &self,
        request: QualificationRequest,
    ) -> Result<ResolvedQualificationCase, ExecutionUnavailable> {
        let mut selected = None;
        for spec in &self.specs {
            let loaded = self.load(*spec)?;
            if loaded.request.fixture_identity == request.fixture_identity {
                if selected.is_some() {
                    return Err(ExecutionUnavailable);
                }
                selected = Some(loaded);
            }
        }
        let selected = selected.ok_or(ExecutionUnavailable)?;
        if selected.request != request {
            return Err(ExecutionUnavailable);
        }
        Ok(ResolvedQualificationCase {
            case: selected.case,
        })
    }

    fn load(
        &self,
        spec: QualificationCaseSpec,
    ) -> Result<LoadedQualificationCase, ExecutionUnavailable> {
        validate_directory(
            &self.root,
            self.expected_uid,
            self.expected_gid,
            CASE_DIRECTORY_MODE,
        )?;
        let directory = self.root.join(spec.case.test_id);
        validate_directory(
            &directory,
            self.expected_uid,
            self.expected_gid,
            CASE_DIRECTORY_MODE,
        )?;
        let bytes = read_case_file(&spec.path(&self.root), self.expected_uid, self.expected_gid)?;
        let sealed: SealedQualificationCase =
            serde_json::from_slice(&bytes).map_err(|_| ExecutionUnavailable)?;
        let directive = sealed.directive.map(|directive| match directive {
            SealedDirective::TeardownFailure => QualificationDirective::TeardownFailure,
        });
        if sealed.version != "qualification_v1" || directive.is_some() {
            return Err(ExecutionUnavailable);
        }
        let permit = sealed.permit.to_request(directive)?;
        sealed.admission.validate(permit)?;
        Ok(LoadedQualificationCase {
            case: spec.case,
            request: permit,
        })
    }
}

struct LoadedQualificationCase {
    case: NormalQualificationCase,
    request: QualificationRequest,
}

struct ResolvedQualificationCase {
    case: NormalQualificationCase,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedQualificationCase {
    version: String,
    permit: SealedPermit,
    admission: SealedAdmission,
    #[serde(default)]
    directive: Option<SealedDirective>,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SealedDirective {
    TeardownFailure,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedHost {
    integrated_candidate_sha: SealedOid,
    broker_build_identity: String,
    host_profile_digest: String,
    suite_identity: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedJob {
    request_digest: String,
    manifest_digest: String,
    isolation_profile_digest: String,
    source_oid: SealedOid,
    base_oid: SealedOid,
    test_identity: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedPermit {
    authorized_by: String,
    host: SealedHost,
    fixture_job: SealedJob,
    fixture_identity: String,
    fixture_signer: String,
    nonce: String,
    not_before: u64,
    expires_at: u64,
}

impl SealedPermit {
    fn to_request(
        &self,
        directive: Option<QualificationDirective>,
    ) -> Result<QualificationRequest, ExecutionUnavailable> {
        decode_hex32(&self.authorized_by)?;
        if self.not_before == 0 || self.not_before >= self.expires_at {
            return Err(ExecutionUnavailable);
        }
        Ok(QualificationRequest {
            integrated_candidate_sha: self.host.integrated_candidate_sha.decode()?,
            broker_build_identity: decode_hex32(&self.host.broker_build_identity)?,
            host_profile_digest: decode_hex32(&self.host.host_profile_digest)?,
            suite_identity: decode_hex32(&self.host.suite_identity)?,
            fixture_signer: decode_hex32(&self.fixture_signer)?,
            request_digest: decode_hex32(&self.fixture_job.request_digest)?,
            manifest_digest: decode_hex32(&self.fixture_job.manifest_digest)?,
            isolation_profile_digest: decode_hex32(&self.fixture_job.isolation_profile_digest)?,
            source_oid: self.fixture_job.source_oid.decode()?,
            base_oid: self.fixture_job.base_oid.decode()?,
            job_identity: decode_hex32(&self.fixture_job.test_identity)?,
            fixture_identity: decode_hex32(&self.fixture_identity)?,
            nonce: decode_hex32(&self.nonce)?,
            not_before: self.not_before,
            expires_at: self.expires_at,
            directive,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedAdmission {
    host: SealedHost,
    fixture_job: SealedJob,
    fixture_identity: String,
    signer: String,
    nonce: String,
    trust_class: SealedTrustClass,
}

impl SealedAdmission {
    fn validate(&self, permit: QualificationRequest) -> Result<(), ExecutionUnavailable> {
        if self.trust_class != SealedTrustClass::QualificationFixture
            || self.host.integrated_candidate_sha.decode()? != permit.integrated_candidate_sha
            || decode_hex32(&self.host.broker_build_identity)? != permit.broker_build_identity
            || decode_hex32(&self.host.host_profile_digest)? != permit.host_profile_digest
            || decode_hex32(&self.host.suite_identity)? != permit.suite_identity
            || decode_hex32(&self.fixture_job.request_digest)? != permit.request_digest
            || decode_hex32(&self.fixture_job.manifest_digest)? != permit.manifest_digest
            || decode_hex32(&self.fixture_job.isolation_profile_digest)?
                != permit.isolation_profile_digest
            || self.fixture_job.source_oid.decode()? != permit.source_oid
            || self.fixture_job.base_oid.decode()? != permit.base_oid
            || decode_hex32(&self.fixture_job.test_identity)? != permit.job_identity
            || decode_hex32(&self.fixture_identity)? != permit.fixture_identity
            || decode_hex32(&self.signer)? != permit.fixture_signer
            || decode_hex32(&self.nonce)? != permit.nonce
        {
            return Err(ExecutionUnavailable);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum SealedTrustClass {
    QualificationFixture,
    Unaccepted,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedOid {
    algorithm: String,
    hex: String,
}

impl SealedOid {
    fn decode(&self) -> Result<GitOid, ExecutionUnavailable> {
        match self.algorithm.as_str() {
            "sha1" => decode_hex::<20>(&self.hex).map(GitOid::Sha1),
            "sha256" => decode_hex::<32>(&self.hex).map(GitOid::Sha256),
            _ => Err(ExecutionUnavailable),
        }
    }
}

fn decode_hex32(value: &str) -> Result<[u8; 32], ExecutionUnavailable> {
    decode_hex(value)
}

fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], ExecutionUnavailable> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(ExecutionUnavailable);
    }
    let mut decoded = [0; N];
    hex::decode_to_slice(value, &mut decoded).map_err(|_| ExecutionUnavailable)?;
    if decoded.iter().all(|byte| *byte == 0) {
        return Err(ExecutionUnavailable);
    }
    Ok(decoded)
}

fn validate_directory(
    path: &Path,
    expected_uid: u32,
    expected_gid: u32,
    expected_mode: u32,
) -> Result<(), ExecutionUnavailable> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ExecutionUnavailable)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != expected_uid
        || metadata.gid() != expected_gid
        || metadata.permissions().mode() & 0o7777 != expected_mode
    {
        return Err(ExecutionUnavailable);
    }
    Ok(())
}

fn read_case_file(
    path: &Path,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<Vec<u8>, ExecutionUnavailable> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW);
    let mut file = options.open(path).map_err(|_| ExecutionUnavailable)?;
    let before = file.metadata().map_err(|_| ExecutionUnavailable)?;
    validate_case_metadata(&before, expected_uid, expected_gid)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_CASE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ExecutionUnavailable)?;
    if bytes.len() as u64 > MAX_CASE_BYTES {
        return Err(ExecutionUnavailable);
    }
    let after = file.metadata().map_err(|_| ExecutionUnavailable)?;
    if file_identity(&before) != file_identity(&after) || after.len() != bytes.len() as u64 {
        return Err(ExecutionUnavailable);
    }
    Ok(bytes)
}

fn validate_case_metadata(
    metadata: &Metadata,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), ExecutionUnavailable> {
    if !metadata.file_type().is_file()
        || metadata.uid() != expected_uid
        || metadata.gid() != expected_gid
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o7777 != CASE_FILE_MODE
        || metadata.len() == 0
        || metadata.len() > MAX_CASE_BYTES
    {
        return Err(ExecutionUnavailable);
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

const fn case(
    test_id: &'static str,
    case_name: &'static str,
    semantics: NormalQualificationSemantics,
    expected_code: NormalQualificationExpectedCode,
    required_readbacks: &'static str,
) -> QualificationCaseSpec {
    QualificationCaseSpec {
        case: NormalQualificationCase {
            test_id,
            case_name,
            semantics,
            expected_code,
            required_readbacks,
        },
    }
}

const NORMAL_CASE_CATALOG: &[QualificationCaseSpec] = &[
    case(
        "TM-06",
        "exclusive_capacity",
        NormalQualificationSemantics::ExclusiveCapacity,
        NormalQualificationExpectedCode::Ok,
        "lease.json,reconcile.json",
    ),
    case(
        "TM-07",
        "socket_isolation",
        NormalQualificationSemantics::SocketIsolation,
        NormalQualificationExpectedCode::Ok,
        "lease.json,proxy/objects",
    ),
    case(
        "TM-09",
        "dns_readback",
        NormalQualificationSemantics::DnsReadback,
        NormalQualificationExpectedCode::Ok,
        "receipts/dns/<lease>-g<generation>.json",
    ),
    case(
        "TM-11",
        "prestart_oci",
        NormalQualificationSemantics::PrestartOci,
        NormalQualificationExpectedCode::Ok,
        "receipts/seccomp.json,receipts/oci/<lease>-g<generation>.json",
    ),
    case(
        "TM-12",
        "cpu-burn",
        NormalQualificationSemantics::ResourceLimit(ResourceLimitFixture::CpuBurn),
        NormalQualificationExpectedCode::Ok,
        "lease.json,ordering.jsonl,teardown.json",
    ),
    case(
        "TM-12",
        "memory-balloon",
        NormalQualificationSemantics::ResourceLimit(ResourceLimitFixture::MemoryBalloon),
        NormalQualificationExpectedCode::Ok,
        "lease.json,ordering.jsonl,teardown.json",
    ),
    case(
        "TM-12",
        "pid-fork-storm",
        NormalQualificationSemantics::ResourceLimit(ResourceLimitFixture::PidForkStorm),
        NormalQualificationExpectedCode::Ok,
        "lease.json,ordering.jsonl,teardown.json",
    ),
    case(
        "TM-12",
        "disk-fill",
        NormalQualificationSemantics::ResourceLimit(ResourceLimitFixture::DiskFill),
        NormalQualificationExpectedCode::Ok,
        "lease.json,ordering.jsonl,teardown.json",
    ),
    case(
        "TM-12",
        "log-flood",
        NormalQualificationSemantics::ResourceLimit(ResourceLimitFixture::LogFlood),
        NormalQualificationExpectedCode::Ok,
        "lease.json,ordering.jsonl,teardown.json",
    ),
    case(
        "TM-12",
        "wall-time-overrun",
        NormalQualificationSemantics::ResourceLimit(ResourceLimitFixture::WallTimeOverrun),
        NormalQualificationExpectedCode::Ok,
        "lease.json,ordering.jsonl,teardown.json",
    ),
    case(
        "TM-12",
        "artifact-overrun",
        NormalQualificationSemantics::ResourceLimit(ResourceLimitFixture::ArtifactOverrun),
        NormalQualificationExpectedCode::Ok,
        "lease.json,ordering.jsonl,teardown.json",
    ),
    case(
        "TM-13",
        "hostile_artifacts",
        NormalQualificationSemantics::HostileArtifacts,
        NormalQualificationExpectedCode::Ok,
        "lease.json,ordering.jsonl,teardown.json",
    ),
    case(
        "TM-14",
        "normal",
        NormalQualificationSemantics::TerminalOrdering,
        NormalQualificationExpectedCode::Ok,
        "ordering.jsonl,teardown.json",
    ),
    case(
        "TM-15",
        "act",
        NormalQualificationSemantics::CrashRecovery(CrashFixture::Act),
        NormalQualificationExpectedCode::Ok,
        "lease.json,reconcile.json",
    ),
    case(
        "TM-15",
        "reuse-act",
        NormalQualificationSemantics::ReuseAfterCrash(CrashFixture::Act),
        NormalQualificationExpectedCode::Ok,
        "lease.json",
    ),
    case(
        "TM-15",
        "podman",
        NormalQualificationSemantics::CrashRecovery(CrashFixture::Podman),
        NormalQualificationExpectedCode::Ok,
        "lease.json,reconcile.json",
    ),
    case(
        "TM-15",
        "reuse-podman",
        NormalQualificationSemantics::ReuseAfterCrash(CrashFixture::Podman),
        NormalQualificationExpectedCode::Ok,
        "lease.json",
    ),
    case(
        "TM-15",
        "proxy",
        NormalQualificationSemantics::CrashRecovery(CrashFixture::Proxy),
        NormalQualificationExpectedCode::Ok,
        "lease.json,reconcile.json",
    ),
    case(
        "TM-15",
        "reuse-proxy",
        NormalQualificationSemantics::ReuseAfterCrash(CrashFixture::Proxy),
        NormalQualificationExpectedCode::Ok,
        "lease.json",
    ),
    case(
        "TM-15",
        "materializer",
        NormalQualificationSemantics::CrashRecovery(CrashFixture::Materializer),
        NormalQualificationExpectedCode::Ok,
        "lease.json,reconcile.json",
    ),
    case(
        "TM-15",
        "reuse-materializer",
        NormalQualificationSemantics::ReuseAfterCrash(CrashFixture::Materializer),
        NormalQualificationExpectedCode::Ok,
        "lease.json",
    ),
    case(
        "TM-15",
        "broker",
        NormalQualificationSemantics::CrashRecovery(CrashFixture::Broker),
        NormalQualificationExpectedCode::Ok,
        "lease.json,reconcile.json",
    ),
    case(
        "TM-15",
        "reuse-broker",
        NormalQualificationSemantics::ReuseAfterCrash(CrashFixture::Broker),
        NormalQualificationExpectedCode::Ok,
        "lease.json",
    ),
    case(
        "TM-15",
        "simulated_host_crash",
        NormalQualificationSemantics::CrashRecovery(CrashFixture::SimulatedHost),
        NormalQualificationExpectedCode::Ok,
        "lease.json,reconcile.json",
    ),
    case(
        "TM-15",
        "reuse-simulated_host_crash",
        NormalQualificationSemantics::ReuseAfterCrash(CrashFixture::SimulatedHost),
        NormalQualificationExpectedCode::Ok,
        "lease.json",
    ),
    case(
        "TM-15",
        "cleanup_adapter_recovery",
        NormalQualificationSemantics::CrashRecovery(CrashFixture::CleanupAdapter),
        NormalQualificationExpectedCode::Ok,
        "lease.json,reconcile.json",
    ),
    case(
        "TM-15",
        "reuse-cleanup_adapter_recovery",
        NormalQualificationSemantics::ReuseAfterCrash(CrashFixture::CleanupAdapter),
        NormalQualificationExpectedCode::Ok,
        "lease.json",
    ),
    case(
        "TM-15",
        "dns_adapter_recovery",
        NormalQualificationSemantics::CrashRecovery(CrashFixture::DnsAdapter),
        NormalQualificationExpectedCode::Ok,
        "lease.json,reconcile.json",
    ),
    case(
        "TM-15",
        "reuse-dns_adapter_recovery",
        NormalQualificationSemantics::ReuseAfterCrash(CrashFixture::DnsAdapter),
        NormalQualificationExpectedCode::Ok,
        "lease.json",
    ),
    case(
        "TM-16",
        "attempt_1",
        NormalQualificationSemantics::RetryAttempt(1),
        NormalQualificationExpectedCode::Ok,
        "lease.json",
    ),
    case(
        "TM-16",
        "attempt_2",
        NormalQualificationSemantics::RetryAttempt(2),
        NormalQualificationExpectedCode::Ok,
        "lease.json",
    ),
    case(
        "TM-16",
        "expired",
        NormalQualificationSemantics::ExpiryRefusal,
        NormalQualificationExpectedCode::PolicyDenied,
        "none",
    ),
    case(
        "TM-16",
        "replay",
        NormalQualificationSemantics::ReplayRefusal,
        NormalQualificationExpectedCode::ReplayConflict,
        "none",
    ),
    case(
        "TM-16",
        "rate_limit",
        NormalQualificationSemantics::RateLimitRefusal,
        NormalQualificationExpectedCode::NoCapacity,
        "none",
    ),
    case(
        "TM-16",
        "concurrency_primary",
        NormalQualificationSemantics::ConcurrencyPrimary,
        NormalQualificationExpectedCode::Ok,
        "lease.json",
    ),
    case(
        "TM-16",
        "concurrency_overflow",
        NormalQualificationSemantics::ConcurrencyOverflowRefusal,
        NormalQualificationExpectedCode::NoCapacity,
        "none",
    ),
    // The unauthorized-signer, unaccepted-trust, and external-fork rows are
    // deliberately invalid local zero-transport fixtures. Teardown rows route
    // through `QualificationCleanupExecutor`. Neither group is executable by
    // this backend.
];

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::BTreeMap, os::unix::fs::PermissionsExt, rc::Rc};

    use super::*;
    use crate::{
        activation::DurableQualificationLeaseFields,
        durable_dispatch::{QualificationExecutor, QualificationTerminal},
        normal_engine::NormalQualificationExecutor,
    };
    use buzz_ci_broker_protocol::{FrameHeader, Operation, ResponseCode};

    const HOSTILE_ROOT: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../ci-acceptance/qualification-cases/fixtures/hostile"
    );

    #[derive(Clone, Copy)]
    struct FixedClock(u64);

    impl QualificationClock for FixedClock {
        fn now(&self) -> Result<u64, ExecutionUnavailable> {
            Ok(self.0)
        }
    }

    #[derive(Default)]
    struct Calls {
        preflight: usize,
        execute: usize,
    }

    struct FakePrimitives {
        live: NormalQualificationLiveBinding,
        result: NormalQualificationCaseResult,
        calls: Rc<RefCell<Calls>>,
    }

    impl NormalQualificationPrimitiveSet for FakePrimitives {
        fn live_binding(
            &mut self,
            _case: NormalQualificationCase,
        ) -> Result<NormalQualificationLiveBinding, ExecutionUnavailable> {
            Ok(self.live)
        }

        fn preflight_case(
            &mut self,
            _case: NormalQualificationCase,
            _request: QualificationRequest,
        ) -> Result<(), ExecutionUnavailable> {
            self.calls.borrow_mut().preflight += 1;
            Ok(())
        }

        fn execute_case(
            &mut self,
            _case: NormalQualificationCase,
            _request: QualificationRequest,
            _lease: QualificationLease,
            _now: u64,
        ) -> Result<NormalQualificationCaseResult, ExecutionUnavailable> {
            self.calls.borrow_mut().execute += 1;
            Ok(self.result)
        }
    }

    struct Fixture {
        _temporary: tempfile::TempDir,
        store: QualificationCaseStore,
        request: QualificationRequest,
    }

    impl Fixture {
        fn hostile(name: &str) -> Self {
            let temporary = tempfile::tempdir().unwrap();
            let root = temporary.path().join("qualification-cases");
            let tm = root.join("TM-14");
            fs::create_dir(&root).unwrap();
            fs::create_dir(&tm).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(CASE_DIRECTORY_MODE)).unwrap();
            fs::set_permissions(&tm, fs::Permissions::from_mode(CASE_DIRECTORY_MODE)).unwrap();
            let bytes = fs::read(Path::new(HOSTILE_ROOT).join(name)).unwrap();
            let path = tm.join("normal.json");
            fs::write(&path, &bytes).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(CASE_FILE_MODE)).unwrap();
            let expected_uid = nix::unistd::geteuid().as_raw();
            let expected_gid = nix::unistd::getegid().as_raw();
            let store = QualificationCaseStore {
                root,
                expected_uid,
                expected_gid,
                specs: vec![case(
                    "TM-14",
                    "normal",
                    NormalQualificationSemantics::TerminalOrdering,
                    NormalQualificationExpectedCode::Ok,
                    "ordering.jsonl,teardown.json",
                )],
            };
            let request = store.load(store.specs[0]).unwrap().request;
            Self {
                _temporary: temporary,
                store,
                request,
            }
        }

        fn backend(
            &self,
            live: NormalQualificationLiveBinding,
            result: NormalQualificationCaseResult,
            now: u64,
            calls: Rc<RefCell<Calls>>,
        ) -> ProductionNormalQualificationBackend<FakePrimitives> {
            ProductionNormalQualificationBackend::open_with(
                QualificationCaseStore {
                    root: self.store.root.clone(),
                    expected_uid: self.store.expected_uid,
                    expected_gid: self.store.expected_gid,
                    specs: self.store.specs.clone(),
                },
                FakePrimitives {
                    live,
                    result,
                    calls,
                },
                Box::new(FixedClock(now)),
            )
            .unwrap()
        }
    }

    fn live(request: QualificationRequest) -> NormalQualificationLiveBinding {
        NormalQualificationLiveBinding {
            integrated_candidate_sha: request.integrated_candidate_sha,
            broker_build_identity: request.broker_build_identity,
            host_profile_digest: request.host_profile_digest,
            suite_identity: request.suite_identity,
            request_digest: request.request_digest,
            manifest_digest: request.manifest_digest,
            isolation_profile_digest: request.isolation_profile_digest,
            source_oid: request.source_oid,
            base_oid: request.base_oid,
            job_identity: request.job_identity,
        }
    }

    fn lease(request: QualificationRequest) -> QualificationLease {
        let mut lease_id = [0; 16];
        lease_id.copy_from_slice(&request.fixture_identity[..16]);
        QualificationLease::from_durable(DurableQualificationLeaseFields {
            fixture_identity: request.fixture_identity,
            lease_id,
            generation: 1,
            nonce: request.nonce,
            directive: request.directive,
        })
    }

    #[test]
    fn exact_sealed_case_maps_primitive_pass_and_failure() {
        let fixture = Fixture::hostile("cross-candidate-sealed.json");
        let calls = Rc::new(RefCell::new(Calls::default()));
        let mut accepted = fixture.backend(
            live(fixture.request),
            NormalQualificationCaseResult::Passed {
                evidence_set_digest: [41; 32],
            },
            100,
            Rc::clone(&calls),
        );
        accepted.preflight(fixture.request).unwrap();
        assert_eq!(
            accepted
                .execute(fixture.request, lease(fixture.request), 100)
                .unwrap(),
            QualificationOutcome::Accepted {
                evidence_set_digest: [41; 32]
            }
        );

        let mut failed = fixture.backend(
            live(fixture.request),
            NormalQualificationCaseResult::Failed,
            100,
            Rc::clone(&calls),
        );
        assert_eq!(
            failed
                .execute(fixture.request, lease(fixture.request), 100)
                .unwrap(),
            QualificationOutcome::Failed
        );
        assert_eq!(calls.borrow().preflight, 1);
        assert_eq!(calls.borrow().execute, 2);
    }

    #[test]
    fn normal_executor_builds_completed_execution_and_protocol_response() {
        let fixture = Fixture::hostile("cross-candidate-sealed.json");
        let calls = Rc::new(RefCell::new(Calls::default()));
        let backend = fixture.backend(
            live(fixture.request),
            NormalQualificationCaseResult::Passed {
                evidence_set_digest: [45; 32],
            },
            100,
            calls,
        );
        let mut executor = NormalQualificationExecutor::new(backend);
        executor.preflight(fixture.request).unwrap();
        let execution = executor
            .execute(
                FrameHeader {
                    operation: Operation::AdmitQualification,
                    request_id: [46; 16],
                },
                fixture.request,
                lease(fixture.request),
                100,
            )
            .unwrap();

        assert_eq!(
            execution.terminal,
            QualificationTerminal::Completed(QualificationOutcome::Accepted {
                evidence_set_digest: [45; 32]
            })
        );
        assert_eq!(execution.response.code, ResponseCode::Ok);
        assert_eq!(execution.response.evidence_set_digest, [45; 32]);
        assert_eq!(
            execution.response.accepted_request_digest,
            fixture.request.request_digest
        );
    }

    #[test]
    fn cross_candidate_sealed_case_is_unavailable_without_fallback() {
        let fixture = Fixture::hostile("cross-candidate-sealed.json");
        let calls = Rc::new(RefCell::new(Calls::default()));
        let mut current = live(fixture.request);
        current.integrated_candidate_sha = GitOid::Sha1([0x22; 20]);
        let mut backend = fixture.backend(
            current,
            NormalQualificationCaseResult::Passed {
                evidence_set_digest: [42; 32],
            },
            100,
            Rc::clone(&calls),
        );

        assert_eq!(
            backend.preflight(fixture.request),
            Err(ExecutionUnavailable)
        );
        assert_eq!(calls.borrow().preflight, 0);
        assert_eq!(calls.borrow().execute, 0);
    }

    #[test]
    fn stale_sealed_case_is_unavailable_before_primitives_run() {
        let fixture = Fixture::hostile("stale-sealed.json");
        let calls = Rc::new(RefCell::new(Calls::default()));
        let mut backend = fixture.backend(
            live(fixture.request),
            NormalQualificationCaseResult::Passed {
                evidence_set_digest: [43; 32],
            },
            3,
            Rc::clone(&calls),
        );

        assert_eq!(
            backend.preflight(fixture.request),
            Err(ExecutionUnavailable)
        );
        assert_eq!(calls.borrow().preflight, 0);
        assert_eq!(calls.borrow().execute, 0);
    }

    #[test]
    fn request_drift_and_zero_evidence_fail_closed() {
        let fixture = Fixture::hostile("cross-candidate-sealed.json");
        let calls = Rc::new(RefCell::new(Calls::default()));
        let mut backend = fixture.backend(
            live(fixture.request),
            NormalQualificationCaseResult::Passed {
                evidence_set_digest: [0; 32],
            },
            100,
            calls,
        );
        let mut drifted = fixture.request;
        drifted.base_oid = GitOid::Sha1([0x44; 20]);
        assert_eq!(backend.preflight(drifted), Err(ExecutionUnavailable));
        assert_eq!(
            backend.execute(fixture.request, lease(fixture.request), 100),
            Err(ExecutionUnavailable)
        );
    }

    #[test]
    fn service_refusal_case_reaches_admission_but_cannot_execute_green() {
        let mut fixture = Fixture::hostile("stale-sealed.json");
        fixture.store.specs[0].case.expected_code = NormalQualificationExpectedCode::PolicyDenied;
        fixture.store.specs[0].case.semantics = NormalQualificationSemantics::ExpiryRefusal;
        let calls = Rc::new(RefCell::new(Calls::default()));
        let mut backend = fixture.backend(
            live(fixture.request),
            NormalQualificationCaseResult::Passed {
                evidence_set_digest: [44; 32],
            },
            3,
            Rc::clone(&calls),
        );

        backend.preflight(fixture.request).unwrap();
        assert_eq!(
            backend
                .execute(fixture.request, lease(fixture.request), 3)
                .unwrap(),
            QualificationOutcome::Failed
        );
        assert_eq!(calls.borrow().preflight, 1);
        assert_eq!(calls.borrow().execute, 0);
    }

    #[test]
    fn production_catalog_matches_executable_expectations() {
        let actual: BTreeMap<_, _> = NORMAL_CASE_CATALOG
            .iter()
            .map(|spec| {
                (
                    (spec.case.test_id, spec.case.case_name),
                    (spec.case.expected_code, spec.case.required_readbacks),
                )
            })
            .collect();
        assert_eq!(actual.len(), NORMAL_CASE_CATALOG.len());

        let expectations = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../ci-acceptance/qualification-cases/expectations.tsv"
        ));
        let mut expected = BTreeMap::new();
        for line in expectations.lines().skip(1) {
            let fields: Vec<_> = line.split('\t').collect();
            assert_eq!(fields.len(), 6);
            let key = (fields[0], fields[1]);
            if fields[2] == "teardown_failure"
                || matches!(
                    key,
                    ("TM-16", "unauthorized_signer")
                        | ("TM-17", "unaccepted")
                        | ("TM-17", "external_fork")
                )
            {
                continue;
            }
            let code = match fields[3] {
                "ok" => NormalQualificationExpectedCode::Ok,
                "policy_denied" => NormalQualificationExpectedCode::PolicyDenied,
                "replay_conflict" => NormalQualificationExpectedCode::ReplayConflict,
                "no_capacity" => NormalQualificationExpectedCode::NoCapacity,
                unexpected => panic!("unexpected executable expectation code {unexpected}"),
            };
            assert!(expected.insert(key, (code, fields[4])).is_none());
        }

        assert_eq!(actual, expected);
    }
}
