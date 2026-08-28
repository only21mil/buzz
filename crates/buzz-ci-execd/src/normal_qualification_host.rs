//! Durable ownership and root-owned handoff for normal qualification cases.
//!
//! The broker first commits a lease record with compare-and-swap. Only then
//! may the host executor publish the exact handoff request. A separate
//! lease-scoped host provider consumes that request and atomically publishes a
//! bound readback. Missing or partial readback never becomes success.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::path::Path;

use buzz_ci_broker_protocol::{GitOid, QualificationRequest};
use nix::errno::Errno;
use nix::fcntl::{open, openat, renameat2, Flock, FlockArg, OFlag, RenameFlags};
use nix::sys::stat::{fchmod, fstat, Mode, SFlag};
use nix::unistd::{fchown, fsync, unlinkat, Gid, Uid, UnlinkatFlags};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::durable_dispatch::ExecutionUnavailable;
use crate::host_composition::HostCompositionContract;
use crate::normal_backend::{
    NormalQualificationHostExecutor, NormalQualificationHostPlan, NormalQualificationHostProgress,
    NormalQualificationPreflightPlan,
};
use crate::normal_qualification::{
    CasNormalQualificationPrimitiveSet, NormalQualificationCase, NormalQualificationCaseResult,
    NormalQualificationLeasePhase, NormalQualificationLeaseRecord, NormalQualificationLeaseStore,
    NormalQualificationLiveBinding,
};

const SCHEMA_VERSION: u16 = 1;
const DIRECTORY_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;
const MAX_RECORD_BYTES: usize = 64 * 1024;
const LOCK_NAME: &str = ".qualification.lock";

#[derive(Clone, Copy)]
struct ExpectedOwner {
    uid: u32,
    gid: u32,
}

struct DescriptorRoot {
    descriptor: OwnedFd,
    owner: ExpectedOwner,
}

impl DescriptorRoot {
    fn open(path: &Path, owner: ExpectedOwner) -> Result<Self, ExecutionUnavailable> {
        let descriptor = open(
            path,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ExecutionUnavailable)?;
        validate_directory(&descriptor, owner)?;
        Ok(Self { descriptor, owner })
    }

    fn lock(&self) -> Result<Flock<File>, ExecutionUnavailable> {
        let descriptor = openat(
            &self.descriptor,
            LOCK_NAME,
            OFlag::O_RDWR | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| ExecutionUnavailable)?;
        let file = File::from(descriptor);
        validate_regular(&file, self.owner, None)?;
        Flock::lock(file, FlockArg::LockExclusive).map_err(|_| ExecutionUnavailable)
    }

    fn read<T>(&self, name: &str) -> Result<Option<Snapshot<T>>, ExecutionUnavailable>
    where
        T: DeserializeOwned + Serialize,
    {
        read_snapshot(self, name)
    }

    fn publish<T>(
        &self,
        name: &str,
        value: &T,
        expected: Option<FileIdentity>,
    ) -> Result<(), ExecutionUnavailable>
    where
        T: DeserializeOwned + Serialize,
    {
        let bytes = serde_json::to_vec(value).map_err(|_| ExecutionUnavailable)?;
        if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
            return Err(ExecutionUnavailable);
        }
        let temporary_name = format!(".{name}.new");
        let descriptor = openat(
            &self.descriptor,
            temporary_name.as_str(),
            OFlag::O_WRONLY
                | OFlag::O_CREAT
                | OFlag::O_EXCL
                | OFlag::O_NOFOLLOW
                | OFlag::O_CLOEXEC
                | OFlag::O_NONBLOCK,
            Mode::from_bits_truncate(FILE_MODE),
        )
        .map_err(|_| ExecutionUnavailable)?;
        let mut temporary = File::from(descriptor);
        let result = (|| {
            fchown(
                &temporary,
                Some(Uid::from_raw(self.owner.uid)),
                Some(Gid::from_raw(self.owner.gid)),
            )
            .map_err(|_| ExecutionUnavailable)?;
            fchmod(&temporary, Mode::from_bits_truncate(FILE_MODE))
                .map_err(|_| ExecutionUnavailable)?;
            temporary
                .write_all(&bytes)
                .and_then(|()| temporary.sync_all())
                .map_err(|_| ExecutionUnavailable)?;
            validate_regular(&temporary, self.owner, Some(bytes.len()))?;
            let temporary_identity = file_identity(&temporary)?;
            verify_named_identity(self, &temporary_name, temporary_identity)?;
            match expected {
                Some(identity) => verify_named_identity(self, name, identity)?,
                None => ensure_absent(self, name)?,
            }
            let flags = if expected.is_none() {
                RenameFlags::RENAME_NOREPLACE
            } else {
                RenameFlags::empty()
            };
            renameat2(
                &self.descriptor,
                temporary_name.as_str(),
                &self.descriptor,
                name,
                flags,
            )
            .map_err(|_| ExecutionUnavailable)?;
            fsync(self.descriptor.as_fd()).map_err(|_| ExecutionUnavailable)?;
            let final_snapshot: Snapshot<T> =
                read_snapshot(self, name)?.ok_or(ExecutionUnavailable)?;
            if final_snapshot.bytes != bytes
                || !final_snapshot.identity.same_inode(temporary_identity)
            {
                return Err(ExecutionUnavailable);
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = unlinkat(
                &self.descriptor,
                temporary_name.as_str(),
                UnlinkatFlags::NoRemoveDir,
            );
        }
        result
    }

    fn publish_create_or_exact<T>(&self, name: &str, value: &T) -> Result<(), ExecutionUnavailable>
    where
        T: DeserializeOwned + Eq + Serialize,
    {
        let _lock = self.lock()?;
        if let Some(existing) = self.read::<T>(name)? {
            return (existing.value == *value)
                .then_some(())
                .ok_or(ExecutionUnavailable);
        }
        self.publish(name, value, None)
    }
}

#[derive(Clone, Copy)]
struct FileIdentity {
    device: u64,
    inode: u64,
    size: i64,
    mtime_seconds: i64,
    mtime_nanoseconds: i64,
    ctime_seconds: i64,
    ctime_nanoseconds: i64,
}

impl FileIdentity {
    fn same_inode(self, other: Self) -> bool {
        self.device == other.device && self.inode == other.inode
    }
}

struct Snapshot<T> {
    value: T,
    bytes: Vec<u8>,
    identity: FileIdentity,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredLeaseRecord {
    schema_version: u16,
    record: NormalQualificationLeaseRecord,
}

impl StoredLeaseRecord {
    fn new(record: NormalQualificationLeaseRecord) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            record,
        }
    }

    fn decode(self) -> Result<NormalQualificationLeaseRecord, ExecutionUnavailable> {
        (self.schema_version == SCHEMA_VERSION)
            .then_some(self.record)
            .ok_or(ExecutionUnavailable)
    }
}

/// Descriptor-relative, atomic CAS store for qualification lease ownership.
pub struct ProductionNormalQualificationLeaseStore {
    root: DescriptorRoot,
}

impl ProductionNormalQualificationLeaseStore {
    /// Open the root-owned lease store named by the validated host contract.
    pub fn open(contract: &HostCompositionContract) -> Result<Self, ExecutionUnavailable> {
        contract.validate().map_err(|_| ExecutionUnavailable)?;
        Self::open_for_owner(&contract.qualification_lease_root, 0, 0)
    }

    fn open_for_owner(path: &Path, uid: u32, gid: u32) -> Result<Self, ExecutionUnavailable> {
        let root = DescriptorRoot::open(path, ExpectedOwner { uid, gid })?;
        let _lock = root.lock()?;
        Ok(Self { root })
    }
}

impl NormalQualificationLeaseStore for ProductionNormalQualificationLeaseStore {
    fn load(
        &mut self,
        lease_id: [u8; 16],
    ) -> Result<Option<NormalQualificationLeaseRecord>, ExecutionUnavailable> {
        let _lock = self.root.lock()?;
        let record = self
            .root
            .read::<StoredLeaseRecord>(&lease_name(lease_id))?
            .map(|snapshot| snapshot.value.decode())
            .transpose()?;
        if record.is_some_and(|record| !valid_record(record, lease_id)) {
            return Err(ExecutionUnavailable);
        }
        Ok(record)
    }

    fn compare_and_swap(
        &mut self,
        lease_id: [u8; 16],
        expected: Option<NormalQualificationLeaseRecord>,
        replacement: NormalQualificationLeaseRecord,
    ) -> Result<bool, ExecutionUnavailable> {
        if !valid_transition(lease_id, expected, replacement) {
            return Err(ExecutionUnavailable);
        }
        let _lock = self.root.lock()?;
        let name = lease_name(lease_id);
        let current = self.root.read::<StoredLeaseRecord>(&name)?;
        let current_record = current
            .as_ref()
            .map(|snapshot| snapshot.value.decode())
            .transpose()?;
        if current_record != expected {
            return Ok(false);
        }
        self.root.publish(
            &name,
            &StoredLeaseRecord::new(replacement),
            current.as_ref().map(|snapshot| snapshot.identity),
        )?;
        Ok(true)
    }
}

/// File-protocol host executor. It never supplies ordinary capacity itself.
pub struct ProductionNormalQualificationHostExecutor {
    ownership: DescriptorRoot,
    bindings: DescriptorRoot,
    handoffs: DescriptorRoot,
    readbacks: DescriptorRoot,
}

/// Fully durable B5-to-B6 qualification primitive composition.
pub type ProductionNormalQualificationPrimitiveSet = CasNormalQualificationPrimitiveSet<
    ProductionNormalQualificationHostExecutor,
    ProductionNormalQualificationLeaseStore,
>;

/// Construct the qualification-only production seam from one validated host
/// contract. This does not open ordinary execution capacity.
pub fn open_production_normal_qualification_primitives(
    contract: &HostCompositionContract,
) -> Result<ProductionNormalQualificationPrimitiveSet, ExecutionUnavailable> {
    Ok(CasNormalQualificationPrimitiveSet::new(
        ProductionNormalQualificationHostExecutor::open(contract)?,
        ProductionNormalQualificationLeaseStore::open(contract)?,
    ))
}

impl ProductionNormalQualificationHostExecutor {
    /// Open the three disjoint roots from the validated host contract.
    pub fn open(contract: &HostCompositionContract) -> Result<Self, ExecutionUnavailable> {
        contract.validate().map_err(|_| ExecutionUnavailable)?;
        Self::open_for_owner(contract, 0, 0)
    }

    fn open_for_owner(
        contract: &HostCompositionContract,
        uid: u32,
        gid: u32,
    ) -> Result<Self, ExecutionUnavailable> {
        let owner = ExpectedOwner { uid, gid };
        Ok(Self {
            ownership: DescriptorRoot::open(&contract.qualification_lease_root, owner)?,
            bindings: DescriptorRoot::open(&contract.qualification_binding_root, owner)?,
            handoffs: DescriptorRoot::open(&contract.qualification_handoff_root, owner)?,
            readbacks: DescriptorRoot::open(&contract.qualification_readback_root, owner)?,
        })
    }

    fn read_live_binding(
        &self,
        case: NormalQualificationCase,
    ) -> Result<NormalQualificationLiveBinding, ExecutionUnavailable> {
        let name = case_name(case)?;
        let binding = self
            .bindings
            .read::<LiveBindingRecord>(&name)?
            .ok_or(ExecutionUnavailable)?
            .value;
        binding.decode(case)
    }

    fn verify_live_plan(
        &self,
        plan: NormalQualificationPreflightPlan,
    ) -> Result<(), ExecutionUnavailable> {
        (self.read_live_binding(plan.case())? == binding_from_request(plan.request()))
            .then_some(())
            .ok_or(ExecutionUnavailable)
    }

    fn progress(
        &self,
        request: &QualificationHandoffRecord,
        now: u64,
    ) -> Result<NormalQualificationHostProgress, ExecutionUnavailable> {
        let Some(readback) = self
            .readbacks
            .read::<QualificationReadbackRecord>(&readback_name(request.lease_id.clone())?)?
        else {
            return Ok(NormalQualificationHostProgress::Partial);
        };
        readback.value.progress(request, now)
    }

    fn verify_ownership(
        &self,
        plan: NormalQualificationHostPlan,
    ) -> Result<Flock<File>, ExecutionUnavailable> {
        let guard = self.ownership.lock()?;
        let record = self
            .ownership
            .read::<StoredLeaseRecord>(&lease_name(plan.lease().lease_id()))?
            .ok_or(ExecutionUnavailable)?
            .value
            .decode()?;
        if !record_matches_plan(record, plan)
            || record.phase != NormalQualificationLeasePhase::Running
        {
            return Err(ExecutionUnavailable);
        }
        Ok(guard)
    }
}

impl NormalQualificationHostExecutor for ProductionNormalQualificationHostExecutor {
    fn live_binding(
        &mut self,
        case: NormalQualificationCase,
    ) -> Result<NormalQualificationLiveBinding, ExecutionUnavailable> {
        self.read_live_binding(case)
    }

    fn preflight(
        &mut self,
        plan: NormalQualificationPreflightPlan,
    ) -> Result<(), ExecutionUnavailable> {
        self.verify_live_plan(plan)?;
        let mut lease_id = [0; 16];
        lease_id.copy_from_slice(&plan.request().fixture_identity[..16]);
        if self
            .handoffs
            .read::<QualificationHandoffRecord>(&handoff_name(lease_id))?
            .is_some()
        {
            return Err(ExecutionUnavailable);
        }
        Ok(())
    }

    fn execute(
        &mut self,
        plan: NormalQualificationHostPlan,
        now: u64,
    ) -> Result<NormalQualificationHostProgress, ExecutionUnavailable> {
        let request = QualificationHandoffRecord::from_plan(plan)?;
        request.validate_time(now)?;
        self.verify_live_plan(plan.preflight())?;
        let _ownership = self.verify_ownership(plan)?;
        self.handoffs
            .publish_create_or_exact(&handoff_name(plan.lease().lease_id()), &request)?;
        self.progress(&request, now)
    }

    fn recover(
        &mut self,
        plan: NormalQualificationHostPlan,
        now: u64,
    ) -> Result<NormalQualificationHostProgress, ExecutionUnavailable> {
        let request = QualificationHandoffRecord::from_plan(plan)?;
        request.validate_time(now)?;
        self.verify_live_plan(plan.preflight())?;
        let _ownership = self.verify_ownership(plan)?;
        let persisted = self
            .handoffs
            .read::<QualificationHandoffRecord>(&handoff_name(plan.lease().lease_id()))?
            .ok_or(ExecutionUnavailable)?;
        if persisted.value != request {
            return Err(ExecutionUnavailable);
        }
        self.progress(&request, now)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct QualificationHandoffRecord {
    schema_version: u16,
    test_id: String,
    case_name: String,
    case_digest: String,
    run_identity: String,
    owner: String,
    fixture_identity: String,
    job_identity: String,
    request_digest: String,
    lease_id: String,
    lease_generation: u64,
    not_before: u64,
    expires_at: u64,
}

impl QualificationHandoffRecord {
    fn from_plan(plan: NormalQualificationHostPlan) -> Result<Self, ExecutionUnavailable> {
        let preflight = plan.preflight();
        let request = preflight.request();
        let record = Self {
            schema_version: SCHEMA_VERSION,
            test_id: preflight.case().test_id.to_owned(),
            case_name: preflight.case().case_name.to_owned(),
            case_digest: hex::encode(preflight.case_digest()),
            run_identity: hex::encode(preflight.run_identity()),
            owner: hex::encode(plan.owner()),
            fixture_identity: hex::encode(request.fixture_identity),
            job_identity: hex::encode(request.job_identity),
            request_digest: hex::encode(request.request_digest),
            lease_id: hex::encode(plan.lease().lease_id()),
            lease_generation: plan.lease().generation(),
            not_before: request.not_before,
            expires_at: plan.expires_at(),
        };
        record.validate()?;
        Ok(record)
    }

    fn validate(&self) -> Result<(), ExecutionUnavailable> {
        if self.schema_version != SCHEMA_VERSION
            || !safe_token(&self.test_id)
            || !safe_token(&self.case_name)
            || decode_hex::<32>(&self.case_digest).is_err()
            || decode_hex::<32>(&self.run_identity).is_err()
            || decode_hex::<32>(&self.owner).is_err()
            || decode_hex::<32>(&self.fixture_identity).is_err()
            || decode_hex::<32>(&self.job_identity).is_err()
            || decode_hex::<32>(&self.request_digest).is_err()
            || decode_hex::<16>(&self.lease_id).is_err()
            || self.lease_generation == 0
            || self.not_before == 0
            || self.not_before >= self.expires_at
        {
            return Err(ExecutionUnavailable);
        }
        Ok(())
    }

    fn validate_time(&self, now: u64) -> Result<(), ExecutionUnavailable> {
        self.validate()?;
        if now < self.not_before || now >= self.expires_at {
            Err(ExecutionUnavailable)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct QualificationReadbackRecord {
    schema_version: u16,
    handoff: QualificationHandoffRecord,
    revision: u64,
    observed_at: u64,
    status: ReadbackStatus,
    evidence_set_digest: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ReadbackStatus {
    Passed,
    Failed,
    Partial,
}

impl QualificationReadbackRecord {
    fn progress(
        self,
        expected: &QualificationHandoffRecord,
        now: u64,
    ) -> Result<NormalQualificationHostProgress, ExecutionUnavailable> {
        if self.schema_version != SCHEMA_VERSION
            || self.handoff != *expected
            || self.revision == 0
            || self.observed_at < expected.not_before
            || self.observed_at >= expected.expires_at
            || self.observed_at > now
        {
            return Err(ExecutionUnavailable);
        }
        match (self.status, self.evidence_set_digest) {
            (ReadbackStatus::Passed, Some(digest)) => {
                let digest = decode_hex::<32>(&digest)?;
                if digest == [0; 32] {
                    Err(ExecutionUnavailable)
                } else {
                    Ok(NormalQualificationHostProgress::Passed {
                        evidence_set_digest: digest,
                    })
                }
            }
            (ReadbackStatus::Failed, None) => Ok(NormalQualificationHostProgress::Failed),
            (ReadbackStatus::Partial, None) => Ok(NormalQualificationHostProgress::Partial),
            _ => Err(ExecutionUnavailable),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LiveBindingRecord {
    schema_version: u16,
    test_id: String,
    case_name: String,
    integrated_candidate_sha: WireOid,
    broker_build_identity: String,
    host_profile_digest: String,
    suite_identity: String,
    request_digest: String,
    manifest_digest: String,
    isolation_profile_digest: String,
    source_oid: WireOid,
    base_oid: WireOid,
    job_identity: String,
}

impl LiveBindingRecord {
    fn decode(
        self,
        case: NormalQualificationCase,
    ) -> Result<NormalQualificationLiveBinding, ExecutionUnavailable> {
        if self.schema_version != SCHEMA_VERSION
            || self.test_id != case.test_id
            || self.case_name != case.case_name
        {
            return Err(ExecutionUnavailable);
        }
        Ok(NormalQualificationLiveBinding {
            integrated_candidate_sha: self.integrated_candidate_sha.decode()?,
            broker_build_identity: decode_hex(&self.broker_build_identity)?,
            host_profile_digest: decode_hex(&self.host_profile_digest)?,
            suite_identity: decode_hex(&self.suite_identity)?,
            request_digest: decode_hex(&self.request_digest)?,
            manifest_digest: decode_hex(&self.manifest_digest)?,
            isolation_profile_digest: decode_hex(&self.isolation_profile_digest)?,
            source_oid: self.source_oid.decode()?,
            base_oid: self.base_oid.decode()?,
            job_identity: decode_hex(&self.job_identity)?,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct WireOid {
    algorithm: String,
    hex: String,
}

impl WireOid {
    fn decode(self) -> Result<GitOid, ExecutionUnavailable> {
        match self.algorithm.as_str() {
            "sha1" => decode_hex(&self.hex).map(GitOid::Sha1),
            "sha256" => decode_hex(&self.hex).map(GitOid::Sha256),
            _ => Err(ExecutionUnavailable),
        }
    }
}

fn binding_from_request(request: QualificationRequest) -> NormalQualificationLiveBinding {
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

fn valid_record(record: NormalQualificationLeaseRecord, lease_id: [u8; 16]) -> bool {
    record.lease_id == lease_id
        && record.case_digest != [0; 32]
        && record.run_identity != [0; 32]
        && record.owner != [0; 32]
        && record.fixture_identity != [0; 32]
        && record.job_identity != [0; 32]
        && record.request_digest != [0; 32]
        && record.lease_generation != 0
        && record.expires_at != 0
        && record.revision != 0
        && match record.phase {
            NormalQualificationLeasePhase::Completed(NormalQualificationCaseResult::Passed {
                evidence_set_digest,
            }) => evidence_set_digest != [0; 32],
            _ => true,
        }
}

fn record_matches_plan(
    record: NormalQualificationLeaseRecord,
    plan: NormalQualificationHostPlan,
) -> bool {
    let preflight = plan.preflight();
    let request = preflight.request();
    record.case_digest == preflight.case_digest()
        && record.run_identity == preflight.run_identity()
        && record.owner == plan.owner()
        && record.fixture_identity == request.fixture_identity
        && record.job_identity == request.job_identity
        && record.request_digest == request.request_digest
        && record.lease_id == plan.lease().lease_id()
        && record.lease_generation == plan.lease().generation()
        && record.expires_at == plan.expires_at()
}

fn valid_transition(
    lease_id: [u8; 16],
    expected: Option<NormalQualificationLeaseRecord>,
    replacement: NormalQualificationLeaseRecord,
) -> bool {
    if !valid_record(replacement, lease_id) {
        return false;
    }
    match expected {
        None => {
            replacement.revision == 1 && replacement.phase == NormalQualificationLeasePhase::Running
        }
        Some(current) => {
            valid_record(current, lease_id)
                && current.phase == NormalQualificationLeasePhase::Running
                && replacement.revision == current.revision.checked_add(1).unwrap_or(0)
                && matches!(
                    replacement.phase,
                    NormalQualificationLeasePhase::Completed(_)
                )
                && NormalQualificationLeaseRecord {
                    revision: replacement.revision,
                    phase: replacement.phase,
                    ..current
                } == replacement
        }
    }
}

fn lease_name(lease_id: [u8; 16]) -> String {
    format!("lease-{}.json", hex::encode(lease_id))
}

fn handoff_name(lease_id: [u8; 16]) -> String {
    format!("handoff-{}.json", hex::encode(lease_id))
}

fn readback_name(lease_id: String) -> Result<String, ExecutionUnavailable> {
    decode_hex::<16>(&lease_id)?;
    Ok(format!("readback-{lease_id}.json"))
}

fn case_name(case: NormalQualificationCase) -> Result<String, ExecutionUnavailable> {
    if !safe_token(case.test_id) || !safe_token(case.case_name) {
        return Err(ExecutionUnavailable);
    }
    Ok(format!("{}--{}.json", case.test_id, case.case_name))
}

fn safe_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
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
    Ok(decoded)
}

fn validate_directory(
    descriptor: &OwnedFd,
    owner: ExpectedOwner,
) -> Result<(), ExecutionUnavailable> {
    let metadata = fstat(descriptor).map_err(|_| ExecutionUnavailable)?;
    if SFlag::from_bits_truncate(metadata.st_mode) != SFlag::S_IFDIR
        || metadata.st_uid != owner.uid
        || metadata.st_gid != owner.gid
        || metadata.st_mode & 0o7777 != DIRECTORY_MODE
    {
        return Err(ExecutionUnavailable);
    }
    Ok(())
}

fn validate_regular(
    file: &File,
    owner: ExpectedOwner,
    expected_size: Option<usize>,
) -> Result<(), ExecutionUnavailable> {
    let metadata = fstat(file).map_err(|_| ExecutionUnavailable)?;
    if SFlag::from_bits_truncate(metadata.st_mode) != SFlag::S_IFREG
        || metadata.st_uid != owner.uid
        || metadata.st_gid != owner.gid
        || metadata.st_mode & 0o7777 != FILE_MODE
        || metadata.st_nlink != 1
        || metadata.st_size < 0
        || metadata.st_size as usize > MAX_RECORD_BYTES
        || expected_size.is_some_and(|size| metadata.st_size as usize != size)
    {
        return Err(ExecutionUnavailable);
    }
    Ok(())
}

fn file_identity(file: &File) -> Result<FileIdentity, ExecutionUnavailable> {
    let metadata = fstat(file).map_err(|_| ExecutionUnavailable)?;
    Ok(FileIdentity {
        device: metadata.st_dev,
        inode: metadata.st_ino,
        size: metadata.st_size,
        mtime_seconds: metadata.st_mtime,
        mtime_nanoseconds: metadata.st_mtime_nsec,
        ctime_seconds: metadata.st_ctime,
        ctime_nanoseconds: metadata.st_ctime_nsec,
    })
}

fn read_snapshot<T>(
    root: &DescriptorRoot,
    name: &str,
) -> Result<Option<Snapshot<T>>, ExecutionUnavailable>
where
    T: DeserializeOwned + Serialize,
{
    read_snapshot_with_hook(root, name, || {})
}

fn read_snapshot_with_hook<T, F>(
    root: &DescriptorRoot,
    name: &str,
    after_open: F,
) -> Result<Option<Snapshot<T>>, ExecutionUnavailable>
where
    T: DeserializeOwned + Serialize,
    F: FnOnce(),
{
    let descriptor = match openat(
        &root.descriptor,
        name,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(Errno::ENOENT) => return Ok(None),
        Err(_) => return Err(ExecutionUnavailable),
    };
    let mut file = File::from(descriptor);
    validate_regular(&file, root.owner, None)?;
    let identity = file_identity(&file)?;
    if identity.size == 0 {
        return Err(ExecutionUnavailable);
    }
    after_open();
    let mut bytes = Vec::with_capacity(identity.size as usize);
    (&mut file)
        .take(MAX_RECORD_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ExecutionUnavailable)?;
    if bytes.len() != identity.size as usize || !file_identity(&file)?.same_inode(identity) {
        return Err(ExecutionUnavailable);
    }
    verify_named_identity(root, name, identity)?;
    let value: T = serde_json::from_slice(&bytes).map_err(|_| ExecutionUnavailable)?;
    if serde_json::to_vec(&value).map_err(|_| ExecutionUnavailable)? != bytes {
        return Err(ExecutionUnavailable);
    }
    Ok(Some(Snapshot {
        value,
        bytes,
        identity,
    }))
}

fn verify_named_identity(
    root: &DescriptorRoot,
    name: &str,
    expected: FileIdentity,
) -> Result<(), ExecutionUnavailable> {
    let descriptor = openat(
        &root.descriptor,
        name,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| ExecutionUnavailable)?;
    let file = File::from(descriptor);
    validate_regular(&file, root.owner, Some(expected.size as usize))?;
    let observed = file_identity(&file)?;
    if !observed.same_inode(expected)
        || observed.size != expected.size
        || observed.mtime_seconds != expected.mtime_seconds
        || observed.mtime_nanoseconds != expected.mtime_nanoseconds
        || observed.ctime_seconds != expected.ctime_seconds
        || observed.ctime_nanoseconds != expected.ctime_nanoseconds
    {
        return Err(ExecutionUnavailable);
    }
    Ok(())
}

fn ensure_absent(root: &DescriptorRoot, name: &str) -> Result<(), ExecutionUnavailable> {
    match openat(
        &root.descriptor,
        name,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
        Mode::empty(),
    ) {
        Err(Errno::ENOENT) => Ok(()),
        Ok(_) | Err(_) => Err(ExecutionUnavailable),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

    use buzz_ci_broker_protocol::QualificationRequest;
    use tempfile::TempDir;

    use super::*;
    use crate::activation::{DurableQualificationLeaseFields, QualificationLease};
    use crate::normal_qualification::{
        NormalQualificationExpectedCode, NormalQualificationPrimitiveSet,
        NormalQualificationSemantics,
    };

    struct Fixture {
        temporary: TempDir,
        contract: HostCompositionContract,
        owner: ExpectedOwner,
    }

    impl Fixture {
        fn new() -> Self {
            let temporary = tempfile::tempdir().unwrap();
            let owner = ExpectedOwner {
                uid: fs::metadata(temporary.path()).unwrap().uid(),
                gid: fs::metadata(temporary.path()).unwrap().gid(),
            };
            let roots = (0..4)
                .map(|index| temporary.path().join(format!("root-{index}")))
                .collect::<Vec<_>>();
            for root in &roots {
                fs::create_dir(root).unwrap();
                fs::set_permissions(root, fs::Permissions::from_mode(DIRECTORY_MODE)).unwrap();
                let lock = root.join(LOCK_NAME);
                fs::write(&lock, []).unwrap();
                fs::set_permissions(lock, fs::Permissions::from_mode(FILE_MODE)).unwrap();
            }
            let mut contract = HostCompositionContract {
                schema_version: 1,
                revision: 1,
                executor_uid: 965,
                runtime_uid: 964,
                executor_socket_template: "/run/buzzci-{lease_id}-exec/executor.sock".into(),
                runtime_socket_template: "/run/buzzci-{lease_id}-runtime/runtime.sock".into(),
                materialization_authority_root: "/var/lib/buzz-ci/materialization".into(),
                proxy_authority_root: "/var/lib/buzz-ci/proxy".into(),
                terminal_evidence_root: "/var/lib/buzz-ci/terminal".into(),
                teardown_authority_root: "/var/lib/buzz-ci/teardown".into(),
                qualification_lease_root: roots[0].clone(),
                qualification_binding_root: roots[1].clone(),
                qualification_handoff_root: roots[2].clone(),
                qualification_readback_root: roots[3].clone(),
                proved_invariants: crate::host_composition::REQUIRED_HOST_INVARIANTS
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
            };
            contract.qualification_lease_root = roots[0].clone();
            contract.qualification_binding_root = roots[1].clone();
            contract.qualification_handoff_root = roots[2].clone();
            contract.qualification_readback_root = roots[3].clone();
            Self {
                temporary,
                contract,
                owner,
            }
        }

        fn store(&self) -> ProductionNormalQualificationLeaseStore {
            ProductionNormalQualificationLeaseStore::open_for_owner(
                &self.contract.qualification_lease_root,
                self.owner.uid,
                self.owner.gid,
            )
            .unwrap()
        }

        fn host(&self) -> ProductionNormalQualificationHostExecutor {
            ProductionNormalQualificationHostExecutor::open_for_owner(
                &self.contract,
                self.owner.uid,
                self.owner.gid,
            )
            .unwrap()
        }
    }

    fn running() -> NormalQualificationLeaseRecord {
        NormalQualificationLeaseRecord {
            case_digest: [1; 32],
            run_identity: [2; 32],
            owner: [3; 32],
            fixture_identity: [4; 32],
            job_identity: [5; 32],
            request_digest: [6; 32],
            lease_id: [4; 16],
            lease_generation: 1,
            expires_at: 200,
            revision: 1,
            phase: NormalQualificationLeasePhase::Running,
        }
    }

    #[test]
    fn durable_store_cas_reopens_and_completes_idempotently() {
        let fixture = Fixture::new();
        let mut store = fixture.store();
        let running = running();
        assert!(store
            .compare_and_swap(running.lease_id, None, running)
            .unwrap());
        drop(store);

        let mut reopened = fixture.store();
        assert_eq!(reopened.load(running.lease_id).unwrap(), Some(running));
        let completed = NormalQualificationLeaseRecord {
            revision: 2,
            phase: NormalQualificationLeasePhase::Completed(
                NormalQualificationCaseResult::Passed {
                    evidence_set_digest: [7; 32],
                },
            ),
            ..running
        };
        assert!(reopened
            .compare_and_swap(running.lease_id, Some(running), completed)
            .unwrap());
        assert!(!reopened
            .compare_and_swap(running.lease_id, Some(running), completed)
            .unwrap());
        assert_eq!(reopened.load(running.lease_id).unwrap(), Some(completed));
    }

    #[test]
    fn store_rejects_revision_drift_and_symlink_substitution() {
        let fixture = Fixture::new();
        let mut store = fixture.store();
        let mut drift = running();
        drift.revision = 2;
        assert!(store.compare_and_swap(drift.lease_id, None, drift).is_err());

        let name = lease_name(running().lease_id);
        symlink(
            "missing",
            fixture.contract.qualification_lease_root.join(name),
        )
        .unwrap();
        assert!(store.load(running().lease_id).is_err());
    }

    #[test]
    fn store_rejects_inode_replacement_between_open_and_parse() {
        let fixture = Fixture::new();
        let mut store = fixture.store();
        let running = running();
        assert!(store
            .compare_and_swap(running.lease_id, None, running)
            .unwrap());
        let name = lease_name(running.lease_id);
        let replacement = fixture
            .contract
            .qualification_lease_root
            .join("replacement.json");
        write_record(
            &fixture.contract.qualification_lease_root,
            "replacement.json",
            &StoredLeaseRecord::new(running),
        );
        let result = read_snapshot_with_hook::<StoredLeaseRecord, _>(&store.root, &name, || {
            fs::rename(
                &replacement,
                fixture.contract.qualification_lease_root.join(&name),
            )
            .unwrap();
        });
        assert!(result.is_err());
    }

    const CASE: NormalQualificationCase = NormalQualificationCase {
        test_id: "TM-01",
        case_name: "exclusive",
        semantics: NormalQualificationSemantics::ExclusiveCapacity,
        expected_code: NormalQualificationExpectedCode::Ok,
        required_readbacks: "lease",
    };

    fn request() -> QualificationRequest {
        QualificationRequest {
            integrated_candidate_sha: GitOid::Sha1([1; 20]),
            broker_build_identity: [2; 32],
            host_profile_digest: [3; 32],
            suite_identity: [4; 32],
            fixture_signer: [5; 32],
            request_digest: [6; 32],
            manifest_digest: [7; 32],
            isolation_profile_digest: [8; 32],
            source_oid: GitOid::Sha1([9; 20]),
            base_oid: GitOid::Sha1([10; 20]),
            job_identity: [11; 32],
            fixture_identity: [12; 32],
            nonce: [13; 32],
            not_before: 100,
            expires_at: 200,
            directive: None,
        }
    }

    fn plan() -> NormalQualificationHostPlan {
        let request = request();
        let preflight = NormalQualificationPreflightPlan::from_sealed_case(CASE, request).unwrap();
        let mut lease_id = [0; 16];
        lease_id.copy_from_slice(&request.fixture_identity[..16]);
        let lease = QualificationLease::from_durable(DurableQualificationLeaseFields {
            fixture_identity: request.fixture_identity,
            lease_id,
            generation: 1,
            nonce: request.nonce,
            directive: None,
        });
        NormalQualificationHostPlan::from_admitted(preflight, lease).unwrap()
    }

    fn running_for_plan(plan: NormalQualificationHostPlan) -> NormalQualificationLeaseRecord {
        let preflight = plan.preflight();
        let request = preflight.request();
        NormalQualificationLeaseRecord {
            case_digest: preflight.case_digest(),
            run_identity: preflight.run_identity(),
            owner: plan.owner(),
            fixture_identity: request.fixture_identity,
            job_identity: request.job_identity,
            request_digest: request.request_digest,
            lease_id: plan.lease().lease_id(),
            lease_generation: plan.lease().generation(),
            expires_at: plan.expires_at(),
            revision: 1,
            phase: NormalQualificationLeasePhase::Running,
        }
    }

    fn live_record() -> LiveBindingRecord {
        let request = request();
        LiveBindingRecord {
            schema_version: 1,
            test_id: CASE.test_id.into(),
            case_name: CASE.case_name.into(),
            integrated_candidate_sha: WireOid {
                algorithm: "sha1".into(),
                hex: hex::encode([1; 20]),
            },
            broker_build_identity: hex::encode(request.broker_build_identity),
            host_profile_digest: hex::encode(request.host_profile_digest),
            suite_identity: hex::encode(request.suite_identity),
            request_digest: hex::encode(request.request_digest),
            manifest_digest: hex::encode(request.manifest_digest),
            isolation_profile_digest: hex::encode(request.isolation_profile_digest),
            source_oid: WireOid {
                algorithm: "sha1".into(),
                hex: hex::encode([9; 20]),
            },
            base_oid: WireOid {
                algorithm: "sha1".into(),
                hex: hex::encode([10; 20]),
            },
            job_identity: hex::encode(request.job_identity),
        }
    }

    fn write_record<T: Serialize>(root: &Path, name: &str, value: &T) {
        let path = root.join(name);
        fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(FILE_MODE)).unwrap();
    }

    #[test]
    fn host_executor_publishes_after_ownership_and_recovers_exact_readback() {
        let fixture = Fixture::new();
        write_record(
            &fixture.contract.qualification_binding_root,
            &case_name(CASE).unwrap(),
            &live_record(),
        );
        let mut host = ProductionNormalQualificationHostExecutor::open_for_owner(
            &fixture.contract,
            fixture.owner.uid,
            fixture.owner.gid,
        )
        .unwrap();
        host.preflight(plan().preflight()).unwrap();
        assert!(host.execute(plan(), 150).is_err());
        assert!(!fixture
            .contract
            .qualification_handoff_root
            .join(handoff_name(plan().lease().lease_id()))
            .exists());
        let running = running_for_plan(plan());
        assert!(fixture
            .store()
            .compare_and_swap(running.lease_id, None, running)
            .unwrap());
        assert_eq!(
            host.execute(plan(), 150).unwrap(),
            NormalQualificationHostProgress::Partial
        );

        let handoff = QualificationHandoffRecord::from_plan(plan()).unwrap();
        let readback = QualificationReadbackRecord {
            schema_version: 1,
            handoff: handoff.clone(),
            revision: 1,
            observed_at: 151,
            status: ReadbackStatus::Passed,
            evidence_set_digest: Some(hex::encode([14; 32])),
        };
        write_record(
            &fixture.contract.qualification_readback_root,
            &readback_name(handoff.lease_id.clone()).unwrap(),
            &readback,
        );
        assert_eq!(
            host.recover(plan(), 152).unwrap(),
            NormalQualificationHostProgress::Passed {
                evidence_set_digest: [14; 32]
            }
        );
        assert!(!fixture.temporary.path().as_os_str().is_empty());
    }

    #[test]
    fn host_executor_refuses_cross_run_and_expired_readback() {
        let fixture = Fixture::new();
        write_record(
            &fixture.contract.qualification_binding_root,
            &case_name(CASE).unwrap(),
            &live_record(),
        );
        let mut host = ProductionNormalQualificationHostExecutor::open_for_owner(
            &fixture.contract,
            fixture.owner.uid,
            fixture.owner.gid,
        )
        .unwrap();
        assert!(host.execute(plan(), request().expires_at).is_err());
        assert!(host.recover(plan(), 150).is_err());

        let running = running_for_plan(plan());
        assert!(fixture
            .store()
            .compare_and_swap(running.lease_id, None, running)
            .unwrap());
        assert_eq!(
            host.execute(plan(), 150).unwrap(),
            NormalQualificationHostProgress::Partial
        );
        let mut wrong_handoff = QualificationHandoffRecord::from_plan(plan()).unwrap();
        wrong_handoff.run_identity = hex::encode([99; 32]);
        let readback = QualificationReadbackRecord {
            schema_version: 1,
            handoff: wrong_handoff,
            revision: 1,
            observed_at: 151,
            status: ReadbackStatus::Failed,
            evidence_set_digest: None,
        };
        write_record(
            &fixture.contract.qualification_readback_root,
            &readback_name(hex::encode(plan().lease().lease_id())).unwrap(),
            &readback,
        );
        assert!(host.recover(plan(), 152).is_err());
    }

    #[test]
    fn concrete_bridge_recovers_running_ownership_and_completes_once() {
        let fixture = Fixture::new();
        write_record(
            &fixture.contract.qualification_binding_root,
            &case_name(CASE).unwrap(),
            &live_record(),
        );
        let admitted = plan().lease();
        let mut first = CasNormalQualificationPrimitiveSet::new(fixture.host(), fixture.store());
        assert!(first.execute_case(CASE, request(), admitted, 150).is_err());
        drop(first);

        let mut store = fixture.store();
        let running = store.load(admitted.lease_id()).unwrap().unwrap();
        assert_eq!(running.phase, NormalQualificationLeasePhase::Running);
        let handoff = QualificationHandoffRecord::from_plan(plan()).unwrap();
        let readback = QualificationReadbackRecord {
            schema_version: 1,
            handoff: handoff.clone(),
            revision: 1,
            observed_at: 151,
            status: ReadbackStatus::Passed,
            evidence_set_digest: Some(hex::encode([15; 32])),
        };
        write_record(
            &fixture.contract.qualification_readback_root,
            &readback_name(handoff.lease_id.clone()).unwrap(),
            &readback,
        );

        let mut recovered =
            CasNormalQualificationPrimitiveSet::new(fixture.host(), fixture.store());
        let expected = NormalQualificationCaseResult::Passed {
            evidence_set_digest: [15; 32],
        };
        assert_eq!(
            recovered
                .execute_case(CASE, request(), admitted, 152)
                .unwrap(),
            expected
        );
        assert_eq!(
            recovered
                .execute_case(CASE, request(), admitted, 153)
                .unwrap(),
            expected
        );
        drop(recovered);
        assert_eq!(
            fixture
                .store()
                .load(admitted.lease_id())
                .unwrap()
                .unwrap()
                .phase,
            NormalQualificationLeasePhase::Completed(expected)
        );
    }
}
