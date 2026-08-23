//! Root-owned production job-plan loading for the ordinary engine.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use buzz_ci_broker_protocol::AdmitAttemptRequest;
use buzz_ci_isolation_contract::AttemptLeaseBinding;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    activation::{LeaseToken, OrdinaryAdmission},
    durable_dispatch::ExecutionUnavailable,
    evidence::{CiEventBinding, LeaseRecord},
    normal_engine::{ActLaunchPlan, BindingValidationAuthority, NormalJobPlan, NormalJobSource},
    runtime::{
        read_artifact, read_artifact_for_owner, reopen_ordinary_authority, RuntimePaths,
        AUTHORITY_MODE, STATE_MODE,
    },
};

/// Canonical root-authored binding for one ordinary job plan.
pub const NORMAL_JOB_AUTHORITY_FILE: &str = "/etc/buzzci/authority/normal-job-source-v1.json";
/// Canonical root-owned live host allocation and readback record.
pub const NORMAL_JOB_INPUTS_FILE: &str = "/var/lib/buzzci/activation/normal-job-inputs-v1.json";

const NORMAL_JOB_FORMAT_VERSION: u16 = 1;
const MAX_NORMAL_JOB_AUTHORITY_BYTES: u64 = 16 * 1024;
const MAX_NORMAL_JOB_INPUTS_BYTES: u64 = 256 * 1024;

/// Root record binding a job plan to one runtime-authority revision and one
/// exact live-input file.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NormalJobAuthorityRecord {
    pub(crate) schema_version: u16,
    pub(crate) runtime_authority_revision: u64,
    pub(crate) runtime_authority_sha256: String,
    pub(crate) live_inputs_sha256: String,
}

/// Root-owned host allocations and launch policy used to build one exact plan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NormalJobInputs {
    pub(crate) schema_version: u16,
    pub(crate) binding: AttemptLeaseBinding,
    pub(crate) validation: BindingValidationAuthority,
    pub(crate) evidence_root: PathBuf,
    pub(crate) lease_record: LeaseRecord,
    pub(crate) event_binding: CiEventBinding,
    pub(crate) act: ActLaunchPlan,
}

#[derive(Clone)]
struct NormalSourcePaths {
    runtime: RuntimePaths,
    authority_file: PathBuf,
    inputs_file: PathBuf,
}

impl NormalSourcePaths {
    fn canonical() -> Self {
        Self {
            runtime: RuntimePaths::canonical(),
            authority_file: NORMAL_JOB_AUTHORITY_FILE.into(),
            inputs_file: NORMAL_JOB_INPUTS_FILE.into(),
        }
    }
}

/// Production source that reconstructs each plan from fixed root-owned files.
///
/// It retains no caller-provided plan or path. Each operation reopens the
/// runtime authority, the source authority, and the live inputs, then rejects
/// any cross-file revision or digest drift before the engine can touch the host.
pub struct ProductionNormalJobSource {
    paths: NormalSourcePaths,
    expected_uid: u32,
    clock: Arc<dyn NormalSourceClock>,
}

impl ProductionNormalJobSource {
    /// Open the canonical production source under root ownership.
    pub fn open() -> Result<Self, ExecutionUnavailable> {
        Self::open_from_paths(NormalSourcePaths::canonical(), 0, Arc::new(SystemClock))
    }

    fn open_from_paths(
        paths: NormalSourcePaths,
        expected_uid: u32,
        clock: Arc<dyn NormalSourceClock>,
    ) -> Result<Self, ExecutionUnavailable> {
        if paths.authority_file.parent() != Some(paths.runtime.authority_root.as_path())
            || paths.inputs_file.parent() != Some(paths.runtime.activation_root.as_path())
        {
            return Err(ExecutionUnavailable);
        }
        let source = Self {
            paths,
            expected_uid,
            clock,
        };
        source.load(ValidationTime::Persisted)?;
        Ok(source)
    }

    #[cfg(test)]
    fn open_for_owner(
        runtime: RuntimePaths,
        expected_uid: u32,
        clock: Arc<dyn NormalSourceClock>,
    ) -> Result<Self, ExecutionUnavailable> {
        let authority_file = runtime.authority_root.join("normal-job-source-v1.json");
        let inputs_file = runtime.activation_root.join("normal-job-inputs-v1.json");
        Self::open_from_paths(
            NormalSourcePaths {
                runtime,
                authority_file,
                inputs_file,
            },
            expected_uid,
            clock,
        )
    }

    fn load(
        &self,
        validation_time: ValidationTime,
    ) -> Result<
        (
            NormalJobPlan,
            Option<LeaseToken>,
            AdmitAttemptRequest,
            OrdinaryAdmission,
        ),
        ExecutionUnavailable,
    > {
        let authority_before = self.read_authority()?;
        let inputs_before = self.read_inputs()?;
        let inputs: NormalJobInputs =
            serde_json::from_slice(&inputs_before).map_err(|_| ExecutionUnavailable)?;
        let now_unix_seconds = match validation_time {
            ValidationTime::Live(now_unix_seconds) => now_unix_seconds,
            ValidationTime::Persisted => inputs.validation.now_unix_seconds,
        };
        if now_unix_seconds == 0 {
            return Err(ExecutionUnavailable);
        }
        let runtime =
            reopen_ordinary_authority(&self.paths.runtime, now_unix_seconds, self.expected_uid)
                .map_err(|_| ExecutionUnavailable)?;
        let authority_after = self.read_authority()?;
        let inputs_after = self.read_inputs()?;
        if authority_before != authority_after || inputs_before != inputs_after {
            return Err(ExecutionUnavailable);
        }

        let authority: NormalJobAuthorityRecord =
            serde_json::from_slice(&authority_before).map_err(|_| ExecutionUnavailable)?;
        if authority.schema_version != NORMAL_JOB_FORMAT_VERSION
            || inputs.schema_version != NORMAL_JOB_FORMAT_VERSION
            || authority.runtime_authority_revision != runtime.authority_revision
            || decode_sha256(&authority.runtime_authority_sha256)? != runtime.authority_sha256
            || decode_sha256(&authority.live_inputs_sha256)?
                != <[u8; 32]>::from(Sha256::digest(&inputs_before))
        {
            return Err(ExecutionUnavailable);
        }

        let plan = NormalJobPlan {
            binding: inputs.binding,
            validation: inputs.validation,
            evidence_root: inputs.evidence_root,
            lease_record: inputs.lease_record,
            event_binding: inputs.event_binding,
            act: inputs.act,
        };
        plan.validate_identity(runtime.request, runtime.admission)?;
        plan.binding
            .clone()
            .validate_phase1(&plan.validation.context_at(now_unix_seconds))
            .map_err(|_| ExecutionUnavailable)?;
        Ok((
            plan,
            runtime.recovery_lease,
            runtime.request,
            runtime.admission,
        ))
    }

    fn read_authority(&self) -> Result<Vec<u8>, ExecutionUnavailable> {
        self.read_root_owned(
            &self.paths.runtime.authority_root,
            &self.paths.authority_file,
            AUTHORITY_MODE,
            MAX_NORMAL_JOB_AUTHORITY_BYTES,
        )
    }

    fn read_inputs(&self) -> Result<Vec<u8>, ExecutionUnavailable> {
        self.read_root_owned(
            &self.paths.runtime.activation_root,
            &self.paths.inputs_file,
            STATE_MODE,
            MAX_NORMAL_JOB_INPUTS_BYTES,
        )
    }

    fn read_root_owned(
        &self,
        directory: &Path,
        path: &Path,
        mode: u32,
        maximum: u64,
    ) -> Result<Vec<u8>, ExecutionUnavailable> {
        let result = if self.expected_uid == 0 {
            read_artifact(directory, path, mode, maximum)
        } else {
            read_artifact_for_owner(directory, path, mode, maximum, self.expected_uid)
        };
        result.map_err(|_| ExecutionUnavailable)
    }
}

impl NormalJobSource for ProductionNormalJobSource {
    fn prepare(
        &mut self,
        request: AdmitAttemptRequest,
        admission: OrdinaryAdmission,
    ) -> Result<NormalJobPlan, ExecutionUnavailable> {
        let now_unix_seconds = self.clock.now_unix_seconds()?;
        let (plan, recovery_lease, root_request, root_admission) =
            self.load(ValidationTime::Live(now_unix_seconds))?;
        if recovery_lease.is_some() || request != root_request || admission != root_admission {
            return Err(ExecutionUnavailable);
        }
        plan.validate_identity(request, admission)?;
        Ok(plan)
    }

    fn recover(
        &mut self,
        request: AdmitAttemptRequest,
        admission: OrdinaryAdmission,
        lease: LeaseToken,
    ) -> Result<NormalJobPlan, ExecutionUnavailable> {
        let (plan, recovery_lease, root_request, root_admission) =
            self.load(ValidationTime::Persisted)?;
        if recovery_lease != Some(lease) || request != root_request || admission != root_admission {
            return Err(ExecutionUnavailable);
        }
        plan.validate_identity(request, admission)?;
        Ok(plan)
    }
}

#[derive(Clone, Copy)]
enum ValidationTime {
    Live(u64),
    Persisted,
}

trait NormalSourceClock: Send + Sync {
    fn now_unix_seconds(&self) -> Result<u64, ExecutionUnavailable>;
}

struct SystemClock;

impl NormalSourceClock for SystemClock {
    fn now_unix_seconds(&self) -> Result<u64, ExecutionUnavailable> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ExecutionUnavailable)?
            .as_secs();
        if now == 0 {
            return Err(ExecutionUnavailable);
        }
        Ok(now)
    }
}

fn decode_sha256(value: &str) -> Result<[u8; 32], ExecutionUnavailable> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(ExecutionUnavailable);
    }
    hex::decode(value)
        .map_err(|_| ExecutionUnavailable)?
        .try_into()
        .map_err(|_| ExecutionUnavailable)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        sync::atomic::{AtomicU64, Ordering},
    };

    use buzz_ci_broker_protocol::{GitOid, TrustClass};
    use buzz_ci_isolation_contract::{
        BrokerObjectHandle, CgroupHandle, EngineKind, IsolationProfile, NetnsHandle, NetworkPolicy,
        PrincipalUids, QuotaBackend, QuotaHandle, ResourceLimits, RuntimeEndpointIdentity,
        WorkspaceHandle, PHASE1_SECCOMP_PROFILE_DIGEST, PHASE1_SECCOMP_PROFILE_PATH,
    };
    use tempfile::TempDir;

    use super::*;
    use crate::{
        activation::{
            ActivationGrant, ActivationState, AdmissionTrustClass, DurableLeaseFields,
            DurableNonceEntry, DurableNonceLedger, DurableQualificationState, DurableStateSnapshot,
            FixtureJobCoordinates, HostActivationCoordinates, OrdinaryJobCoordinates,
            QualificationPermit, VerifiedSigner, NONCE_LEDGER_CAPACITY, REQUIRED_PROBES,
            REQUIRED_SECURITY_RECORDS,
        },
        evidence::{
            DnsReadback, LeaseLimits, ResourcePropertyReadback, SeccompEvidence,
            SECCOMP_PROFILE_PATH, SECCOMP_PROFILE_SHA256,
        },
        normal_engine::{PINNED_ACT_PATH, PINNED_ACT_SHA256},
        runtime::{
            AuthorityFile, RootOrdinaryAuthority, StateFile, AUTHORITY_MODE, COORDINATOR_LOCK_FILE,
            DIRECTORY_MODE, STATE_MODE,
        },
    };

    const ROOT: VerifiedSigner = VerifiedSigner([1; 32]);
    const FIXTURE: VerifiedSigner = VerifiedSigner([2; 32]);
    const ORDINARY: VerifiedSigner = VerifiedSigner([3; 32]);

    struct TestClock(AtomicU64);

    impl TestClock {
        fn new(now_unix_seconds: u64) -> Self {
            Self(AtomicU64::new(now_unix_seconds))
        }

        fn set(&self, now_unix_seconds: u64) {
            self.0.store(now_unix_seconds, Ordering::SeqCst);
        }
    }

    impl NormalSourceClock for TestClock {
        fn now_unix_seconds(&self) -> Result<u64, ExecutionUnavailable> {
            let now = self.0.load(Ordering::SeqCst);
            if now == 0 {
                return Err(ExecutionUnavailable);
            }
            Ok(now)
        }
    }

    struct SourceFixture {
        _temporary: TempDir,
        paths: RuntimePaths,
        expected_uid: u32,
        request: AdmitAttemptRequest,
        admission: OrdinaryAdmission,
        lease: LeaseToken,
        authority_revision: u64,
        authority_sha256: [u8; 32],
        clock: Arc<TestClock>,
    }

    impl SourceFixture {
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
            let expected_uid = nix::unistd::geteuid().as_raw();
            let request = request();
            let admission = admission(request);
            write_mode(
                &paths.activation_root.join(COORDINATOR_LOCK_FILE),
                b"1",
                STATE_MODE,
            );
            let lease = LeaseToken::from_durable(DurableLeaseFields {
                lease_id: admission.lease_id,
                run_id: admission.run_id,
                attempt: admission.attempt,
                signed_request_digest: admission.job.request_digest,
                signer: admission.signer,
                generation: 3,
                nonce: admission.nonce,
                deadline_at: 50,
            });
            let mut fixture = Self {
                _temporary: temporary,
                paths,
                expected_uid,
                request,
                admission,
                lease,
                authority_revision: 7,
                authority_sha256: [0; 32],
                clock: Arc::new(TestClock::new(20)),
            };
            fixture.write_runtime_authority();
            fixture.write_state(None);
            fixture.write_source_records(inputs(request, admission, expected_uid));
            fixture
        }

        fn source(&self) -> ProductionNormalJobSource {
            ProductionNormalJobSource::open_for_owner(
                self.paths.clone(),
                self.expected_uid,
                self.clock.clone(),
            )
            .unwrap()
        }

        fn write_runtime_authority(&mut self) {
            let root_ordinary = RootOrdinaryAuthority {
                grant: grant(),
                request: self.request,
                job_identity: self.admission.job.job_identity,
                lease_id: self.admission.lease_id,
                nonce: self.admission.nonce,
                authenticated_signer: ORDINARY,
            };
            let authority = AuthorityFile::encode(
                self.authority_revision,
                ROOT,
                Some(permit()),
                Some(root_ordinary),
            )
            .unwrap();
            let authority_bytes = serde_json::to_vec(&authority).unwrap();
            self.authority_sha256 = Sha256::digest(&authority_bytes).into();
            write_mode(&self.paths.authority_file, &authority_bytes, AUTHORITY_MODE);
        }

        fn rotate_fresh(&mut self, request: AdmitAttemptRequest, validation_now: u64) {
            self.request = request;
            self.admission = admission(request);
            self.authority_revision += 1;
            self.write_runtime_authority();
            self.write_state(None);
            let mut rotated_inputs = inputs(self.request, self.admission, self.expected_uid);
            rotated_inputs.validation.now_unix_seconds = validation_now;
            self.write_source_records(rotated_inputs);
        }

        fn write_state(&self, lease: Option<LeaseToken>) {
            let mut entries = [None; NONCE_LEDGER_CAPACITY];
            if lease.is_some() {
                entries[0] = Some(DurableNonceEntry {
                    nonce: self.admission.nonce,
                    expires_at: self.admission.expires_at,
                });
            }
            let snapshot = DurableStateSnapshot {
                version: 1,
                root_authority: ROOT,
                state: if lease.is_some() {
                    ActivationState::Leased
                } else {
                    ActivationState::Ready
                },
                qualification: Some(DurableQualificationState {
                    permit: permit(),
                    active_lease: None,
                    evidence_set_digest: Some([16; 32]),
                }),
                activation: Some(grant()),
                active_lease: lease,
                nonce_ledger: DurableNonceLedger { entries },
                last_admission_at: lease.map(|_| 20),
                next_lease_generation: if lease.is_some() { 4 } else { 3 },
            };
            let state =
                StateFile::encode(snapshot, 9, self.authority_revision, self.authority_sha256)
                    .unwrap();
            write_mode(
                &self.paths.state_file,
                &serde_json::to_vec(&state).unwrap(),
                STATE_MODE,
            );
        }

        fn write_source_records(&self, inputs: NormalJobInputs) {
            let input_bytes = serde_json::to_vec(&inputs).unwrap();
            write_mode(
                &self.paths.activation_root.join("normal-job-inputs-v1.json"),
                &input_bytes,
                STATE_MODE,
            );
            let authority = NormalJobAuthorityRecord {
                schema_version: 1,
                runtime_authority_revision: self.authority_revision,
                runtime_authority_sha256: hex::encode(self.authority_sha256),
                live_inputs_sha256: hex::encode(Sha256::digest(&input_bytes)),
            };
            write_mode(
                &self.paths.authority_root.join("normal-job-source-v1.json"),
                &serde_json::to_vec(&authority).unwrap(),
                AUTHORITY_MODE,
            );
        }
    }

    #[test]
    fn production_source_constructs_root_bound_plan() {
        let fixture = SourceFixture::new();
        let mut source = fixture.source();
        let plan = source.prepare(fixture.request, fixture.admission).unwrap();

        assert_eq!(
            plan.binding.run_id,
            uuid::Uuid::from_bytes(fixture.request.run_id).to_string()
        );
        assert_eq!(plan.binding.source_sha, oid_hex(fixture.request.tip_oid));
        assert_eq!(plan.binding.base_oid, oid_hex(fixture.request.base_oid));
        assert_eq!(plan.binding.attempt, fixture.admission.attempt);
        assert_eq!(
            plan.binding.expires_at_unix_seconds,
            fixture.admission.expires_at
        );
        assert_eq!(
            plan.binding.request_event_id,
            hex::encode(fixture.request.signed_request_digest)
        );
        assert_eq!(
            plan.binding.workflow_digest,
            hex::encode(fixture.request.workflow_digest)
        );
        assert_eq!(
            plan.binding.target_repo_a,
            format!("30617:{}:buzz", "b".repeat(64))
        );
        assert_eq!(plan.binding.workflow_id, "required-ci");
        assert_eq!(plan.binding.job_id, "linux");
        assert_eq!(plan.binding.lease_id, "01ARZ3NDEKTSV4RRFFQ69G5FAV");
        assert_eq!(
            plan.binding.principals.materializer,
            fixture.expected_uid + 2
        );
        assert_eq!(plan.binding.principals.executor, fixture.expected_uid + 1);
        assert_eq!(plan.binding.principals.runtime, fixture.expected_uid);
        assert_eq!(
            plan.binding.workspace.path,
            "/var/lib/buzzci/workspaces/normal"
        );
        assert!(matches!(
            plan.binding.runtime_endpoint,
            RuntimeEndpointIdentity::InheritedFd { owner_uid, .. } if owner_uid == fixture.expected_uid
        ));
        assert_eq!(plan.binding.cgroup.object.inode, 21);
        assert_eq!(plan.binding.netns.name, "buzzci-normal");
        assert_eq!(plan.binding.quota.quota_id, "quota-normal");
        assert_eq!(plan.act.job_id, plan.binding.job_id);
        assert_eq!(plan.act.image, plan.binding.isolation_profile.image_digest);
        assert_eq!(hex::encode(plan.act.binary_sha256), PINNED_ACT_SHA256);
        assert_eq!(plan.act.binary, Path::new(PINNED_ACT_PATH));
        assert_eq!(
            plan.act.workflow_path,
            Path::new("/var/lib/buzzci/workspaces/normal/source/.github/workflows/ci.yml")
        );
        assert_eq!(plan.act.executor_unit, "buzzci-normal-exec.service");
        assert_eq!(plan.act.runtime_unit, "buzzci-normal-run.service");
        assert_eq!(
            plan.lease_record.workspace_dir,
            Path::new(&plan.binding.workspace.path)
        );
        assert_eq!(plan.lease_record.lease_unit, plan.act.lease_slice);
        assert_eq!(plan.evidence_root, Path::new("/var/lib/buzzci/evidence"));
        assert_eq!(
            plan.lease_record.sanitized_artifact_store_path,
            Path::new("/var/lib/buzzci/artifacts/normal")
        );
        assert_eq!(
            plan.lease_record.sanitized_log_store_path,
            Path::new("/var/lib/buzzci/logs/normal")
        );

        let mut wrong_request = fixture.request;
        wrong_request.base_oid = GitOid::Sha256([99; 32]);
        assert!(source.prepare(wrong_request, fixture.admission).is_err());
        let mut wrong_admission = fixture.admission;
        wrong_admission.signer = VerifiedSigner([99; 32]);
        assert!(source.prepare(fixture.request, wrong_admission).is_err());

        let inputs_path = fixture
            .paths
            .activation_root
            .join("normal-job-inputs-v1.json");
        let mut unbound_inputs: NormalJobInputs =
            serde_json::from_slice(&fs::read(&inputs_path).unwrap()).unwrap();
        unbound_inputs.binding.workflow_id = "unbound-ci".into();
        write_mode(
            &inputs_path,
            &serde_json::to_vec(&unbound_inputs).unwrap(),
            STATE_MODE,
        );
        assert!(source.prepare(fixture.request, fixture.admission).is_err());
    }

    #[test]
    fn same_source_accepts_later_root_rotation_at_live_time() {
        let mut fixture = SourceFixture::new();
        let mut source = fixture.source();
        source.prepare(fixture.request, fixture.admission).unwrap();
        fixture.clock.set(40);
        let mut rotated_request = fixture.request;
        rotated_request.signed_request_digest = [41; 32];
        rotated_request.idempotency_digest = [42; 32];
        rotated_request.run_id = [43; 16];
        rotated_request.tip_oid = GitOid::Sha256([44; 32]);
        rotated_request.base_oid = GitOid::Sha256([45; 32]);
        rotated_request.issued_at = 40;
        rotated_request.expires_at = 95;
        fixture.rotate_fresh(rotated_request, 30);

        let plan = source.prepare(fixture.request, fixture.admission).unwrap();

        assert_eq!(plan.validation.now_unix_seconds, 30);
        assert_eq!(
            plan.binding.run_id,
            uuid::Uuid::from_bytes([43; 16]).to_string()
        );
        assert_eq!(plan.binding.expires_at_unix_seconds, 95);
    }

    #[test]
    fn fresh_prepare_rejects_expired_plan_at_live_time() {
        let fixture = SourceFixture::new();
        let mut source = fixture.source();
        fixture.clock.set(91);

        assert!(source.prepare(fixture.request, fixture.admission).is_err());
    }

    #[test]
    fn recovery_after_live_expiry_requires_exact_retained_lease() {
        let fixture = SourceFixture::new();
        fixture.write_state(Some(fixture.lease));
        let mut source = fixture.source();
        fixture.clock.set(91);
        let wrong_generation = LeaseToken::from_durable(DurableLeaseFields {
            lease_id: fixture.lease.lease_id(),
            run_id: fixture.lease.run_id(),
            attempt: fixture.lease.attempt(),
            signed_request_digest: fixture.lease.signed_request_digest(),
            signer: fixture.lease.signer(),
            generation: fixture.lease.generation() + 1,
            nonce: fixture.admission.nonce,
            deadline_at: fixture.lease.deadline_at(),
        });
        let wrong_deadline = LeaseToken::from_durable(DurableLeaseFields {
            lease_id: fixture.lease.lease_id(),
            run_id: fixture.lease.run_id(),
            attempt: fixture.lease.attempt(),
            signed_request_digest: fixture.lease.signed_request_digest(),
            signer: fixture.lease.signer(),
            generation: fixture.lease.generation(),
            nonce: fixture.admission.nonce,
            deadline_at: fixture.lease.deadline_at() + 1,
        });

        assert!(source
            .recover(fixture.request, fixture.admission, wrong_generation)
            .is_err());
        assert!(source
            .recover(fixture.request, fixture.admission, wrong_deadline)
            .is_err());
        assert!(source
            .recover(fixture.request, fixture.admission, fixture.lease)
            .is_ok());
    }

    fn write_mode(path: &Path, bytes: &[u8], mode: u32) {
        if path.exists() {
            fs::set_permissions(path, fs::Permissions::from_mode(STATE_MODE)).unwrap();
        }
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn host() -> HostActivationCoordinates {
        HostActivationCoordinates {
            integrated_candidate_sha: GitOid::Sha256([4; 32]),
            broker_build_identity: [5; 32],
            host_profile_digest: [6; 32],
            suite_identity: [7; 32],
        }
    }

    fn permit() -> QualificationPermit {
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
            expires_at: 100,
            directive: None,
        }
    }

    fn grant() -> ActivationGrant {
        ActivationGrant {
            authorized_by: ROOT,
            host: host(),
            security_records_passed: REQUIRED_SECURITY_RECORDS,
            security_records_total: REQUIRED_SECURITY_RECORDS,
            probes_passed: REQUIRED_PROBES,
            probes_total: REQUIRED_PROBES,
            evidence_set_digest: [16; 32],
            blocker_closure_digest: [17; 32],
            all_blockers_closed: true,
            ordinary_signer: ORDINARY,
            max_capacity: 1,
            minimum_admission_interval_seconds: 1,
            expires_at: 100,
        }
    }

    fn request() -> AdmitAttemptRequest {
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

    fn admission(request: AdmitAttemptRequest) -> OrdinaryAdmission {
        OrdinaryAdmission {
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
        }
    }

    fn inputs(
        request: AdmitAttemptRequest,
        admission: OrdinaryAdmission,
        uid: u32,
    ) -> NormalJobInputs {
        let token = |value: char| value.to_string().repeat(64);
        let limits = ResourceLimits {
            cpu_weight: 100,
            mem_max_bytes: 1024 * 1024,
            pids_max: 32,
            io_weight: 100,
        };
        let lease_id = "01ARZ3NDEKTSV4RRFFQ69G5FAV".to_owned();
        let binding = AttemptLeaseBinding {
            schema_version: 1,
            request_event_id: hex::encode(request.signed_request_digest),
            run_id: uuid::Uuid::from_bytes(request.run_id).to_string(),
            target_repo_a: format!("30617:{}:buzz", "b".repeat(64)),
            source_sha: oid_hex(request.tip_oid),
            base_oid: oid_hex(request.base_oid),
            workflow_id: "required-ci".into(),
            workflow_digest: hex::encode(request.workflow_digest),
            job_id: "linux".into(),
            attempt: admission.attempt,
            lease_id: lease_id.clone(),
            expires_at_unix_seconds: admission.expires_at,
            principals: PrincipalUids {
                materializer: uid + 2,
                executor: uid + 1,
                runtime: uid,
            },
            workspace: WorkspaceHandle {
                path: "/var/lib/buzzci/workspaces/normal".into(),
                object: BrokerObjectHandle {
                    token: token('1'),
                    device: 10,
                    inode: 11,
                },
                owner_uid: uid + 2,
                quota_token: token('5'),
            },
            runtime_endpoint: RuntimeEndpointIdentity::InheritedFd {
                token: token('2'),
                owner_uid: uid,
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
        let act = ActLaunchPlan {
            binary: PINNED_ACT_PATH.into(),
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
        let workspace_dir = PathBuf::from(&binding.workspace.path);
        NormalJobInputs {
            schema_version: 1,
            binding,
            validation: BindingValidationAuthority {
                now_unix_seconds: 20,
                max_expiry_horizon_seconds: 100,
                forbidden_host_uids: Vec::new(),
                expected_engine_version: "5.8.4".into(),
                expected_arch: "x86_64".into(),
            },
            evidence_root: "/var/lib/buzzci/evidence".into(),
            lease_record: LeaseRecord {
                schema_version: 1,
                lease_id,
                lease_unit: act.lease_slice.clone(),
                cgroup_path: "/buzzci.slice/buzzci-normal.slice".into(),
                workspace_dir,
                limits: LeaseLimits { wall_deadline: 90 },
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
                    path: SECCOMP_PROFILE_PATH.into(),
                    sha256: SECCOMP_PROFILE_SHA256.into(),
                },
                sanitized_artifact_store_path: "/var/lib/buzzci/artifacts/normal".into(),
                sanitized_log_store_path: "/var/lib/buzzci/logs/normal".into(),
                created_at_unix_ns: 1,
            },
            event_binding: CiEventBinding {
                request_event_id_46105: [31; 32],
                teardown_event_id_46106: [32; 32],
            },
            act,
        }
    }

    fn oid_hex(oid: GitOid) -> String {
        match oid {
            GitOid::Sha1(bytes) => hex::encode(bytes),
            GitOid::Sha256(bytes) => hex::encode(bytes),
        }
    }
}
