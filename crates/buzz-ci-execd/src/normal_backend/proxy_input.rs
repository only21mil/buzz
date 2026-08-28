//! Root-owned proxy authority and one-shot runtime descriptors.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use buzz_ci_broker_protocol::GitOid;
use buzz_ci_isolation_contract::ValidatedAttemptLeaseBinding;
use buzz_ci_policy_proxy::PolicyManifest;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::activation::{LeaseToken, OrdinaryAdmission};
use crate::durable_dispatch::ExecutionUnavailable;
use crate::evidence::CiEventBinding;
use crate::host_composition::HostCompositionContract;
use crate::normal_backend::{
    populate_expected_execs, ActRuntimeDescriptorSource, BrokerProxyInputSource, BrokerProxyInputs,
};
use crate::normal_engine::ActLaunchPlan;
use crate::proxy_lease::{PrestartPersister, ProxyLeaseAuthority};
use crate::seccomp_activation::SeccompInstallCapability;

use super::materialization_input::{non_secret_json, DescriptorRoot, ExpectedOwner};

const SCHEMA_VERSION: u16 = 1;

/// A pre-start persister whose retained profile identity can be checked against
/// root-owned proxy authority before any listener or runtime exchange exists.
pub trait BoundPrestartPersister: PrestartPersister + Clone {
    /// Fixed content-addressed profile path.
    fn profile_path(&self) -> &str;
    /// Digest of the independently persisted activation receipt.
    fn receipt_digest(&self) -> String;
}

impl BoundPrestartPersister for SeccompInstallCapability {
    fn profile_path(&self) -> &str {
        (*self).profile_path()
    }

    fn receipt_digest(&self) -> String {
        (*self).receipt_digest()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProxyAuthorityRecord {
    listener_root: PathBuf,
    evidence_root: PathBuf,
    event_binding: CiEventBinding,
    bundle: PathBuf,
    pid_file: PathBuf,
    exec_argv: Vec<String>,
    exec_working_directory: PathBuf,
    exec_uid: u32,
    exec_gid: u32,
    listener_gid: u32,
}

impl ProxyAuthorityRecord {
    fn build(&self) -> Result<ProxyLeaseAuthority, ExecutionUnavailable> {
        ProxyLeaseAuthority::new(
            self.listener_root.clone(),
            self.evidence_root.clone(),
            self.event_binding,
            self.bundle.clone(),
            self.pid_file.clone(),
            self.exec_argv.clone(),
            self.exec_working_directory.clone(),
            self.exec_uid,
            self.exec_gid,
            self.listener_gid,
        )
        .map_err(|_| ExecutionUnavailable)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProxyInputRecord {
    schema_version: u16,
    lease_id: String,
    controller_lease_id: String,
    lease_generation: u64,
    lease_token_sha256: String,
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    manifest: PolicyManifest,
    canonical_job_manifest: Vec<u8>,
    authority: ProxyAuthorityRecord,
    seccomp_profile_path: String,
    seccomp_receipt_sha256: String,
}

impl ProxyInputRecord {
    fn validate<P: BoundPrestartPersister>(
        &self,
        now: u64,
        plan: &ActLaunchPlan,
        binding: &ValidatedAttemptLeaseBinding,
        persister: &P,
    ) -> Result<(), ExecutionUnavailable> {
        let expected = binding.as_binding();
        let derived_socket = self.authority.listener_root.join(format!(
            "proxy-{}-{}.sock",
            self.controller_lease_id, self.lease_generation
        ));
        if self.schema_version != SCHEMA_VERSION
            || self.lease_id != expected.lease_id
            || !lower_hex(&self.controller_lease_id, 32)
            || self.lease_generation == 0
            || !lower_hex(&self.lease_token_sha256, 64)
            || self.issued_at_unix_seconds == 0
            || self.issued_at_unix_seconds > now
            || self.expires_at_unix_seconds != expected.expires_at_unix_seconds
            || self.expires_at_unix_seconds <= now
            || self.manifest.request_event_id != expected.request_event_id
            || self.manifest.run_id != expected.run_id
            || self.manifest.target_repo_a != expected.target_repo_a
            || self.manifest.sha != expected.source_sha
            || self.manifest.base_oid != expected.base_oid
            || self.manifest.workflow_id != expected.workflow_id
            || self.manifest.workflow_digest != expected.workflow_digest
            || self.manifest.job_id != expected.job_id
            || self.manifest.attempt != expected.attempt
            || self.manifest.lease_id != expected.lease_id
            || self.manifest.isolation_profile.image_digest
                != expected.isolation_profile.image_digest
            || self.manifest.isolation_profile.engine_version
                != expected.isolation_profile.engine_version
            || self.manifest.isolation_profile.arch != expected.isolation_profile.arch
            || self.manifest.isolation_profile.seccomp_profile_path
                != expected.isolation_profile.seccomp_profile_path
            || self.manifest.isolation_profile.seccomp_profile_digest
                != expected.isolation_profile.seccomp_profile_digest
            || self.manifest.isolation_profile.netns != expected.isolation_profile.netns
            || self.manifest.isolation_profile.limits.memory_max_bytes
                != expected.isolation_profile.limits.mem_max_bytes
            || self.manifest.isolation_profile.limits.pids_max
                != u64::from(expected.isolation_profile.limits.pids_max)
            || self.authority.exec_argv != plan.argv()?
            || self.authority.exec_working_directory != plan.working_directory
            || self.authority.exec_uid != expected.principals.executor
            || self.authority.listener_root
                != plan.proxy_socket.parent().ok_or(ExecutionUnavailable)?
            || derived_socket != plan.proxy_socket
            || self.seccomp_profile_path != persister.profile_path()
            || self.seccomp_profile_path != expected.isolation_profile.seccomp_profile_path
            || self.seccomp_receipt_sha256 != persister.receipt_digest()
            || !lower_hex(&self.seccomp_receipt_sha256, 64)
        {
            return Err(ExecutionUnavailable);
        }
        let canonical_json: serde_json::Value =
            serde_json::from_slice(&self.canonical_job_manifest)
                .map_err(|_| ExecutionUnavailable)?;
        if !non_secret_json(&canonical_json) {
            return Err(ExecutionUnavailable);
        }
        self.authority.build()?;
        let mut manifest = self.manifest.clone();
        populate_expected_execs(&mut manifest, &self.canonical_job_manifest)
            .map_err(|_| ExecutionUnavailable)?;
        Ok(())
    }
}

/// Root-owned proxy input source that consumes one exact lease generation.
pub struct ProxyInputProvider<D, P = SeccompInstallCapability> {
    root: DescriptorRoot,
    descriptors: D,
    persister: P,
    consumed: BTreeSet<(String, u64)>,
    now: fn() -> Result<u64, ExecutionUnavailable>,
}

impl<D, P> ProxyInputProvider<D, P>
where
    D: ActRuntimeDescriptorSource,
    P: BoundPrestartPersister,
{
    /// Open the root-owned proxy authority named by host composition.
    pub fn from_contract(
        contract: &HostCompositionContract,
        descriptors: D,
        persister: P,
    ) -> Result<Self, ExecutionUnavailable> {
        Self::open_for_owner(
            &contract.proxy_authority_root,
            0,
            0,
            descriptors,
            persister,
            system_now,
        )
    }

    fn open_for_owner(
        path: &Path,
        uid: u32,
        gid: u32,
        descriptors: D,
        persister: P,
        now: fn() -> Result<u64, ExecutionUnavailable>,
    ) -> Result<Self, ExecutionUnavailable> {
        Ok(Self {
            root: DescriptorRoot::open(path, ExpectedOwner { uid, gid })?,
            descriptors,
            persister,
            consumed: BTreeSet::new(),
            now,
        })
    }

    fn record(
        &self,
        plan: &ActLaunchPlan,
        binding: &ValidatedAttemptLeaseBinding,
    ) -> Result<ProxyInputRecord, ExecutionUnavailable> {
        let name = format!("{}.json", binding.as_binding().lease_id);
        let record: ProxyInputRecord = self.root.read(&name)?;
        record.validate((self.now)()?, plan, binding, &self.persister)?;
        Ok(record)
    }
}

impl<D, P> BrokerProxyInputSource for ProxyInputProvider<D, P>
where
    D: ActRuntimeDescriptorSource,
    P: BoundPrestartPersister,
{
    type Persister = P;

    fn preflight(
        &mut self,
        plan: &ActLaunchPlan,
        binding: &ValidatedAttemptLeaseBinding,
    ) -> Result<(), ExecutionUnavailable> {
        let record = self.record(plan, binding)?;
        if self
            .consumed
            .contains(&(record.lease_id.clone(), record.lease_generation))
        {
            return Err(ExecutionUnavailable);
        }
        self.descriptors
            .preflight(plan, binding)
            .map_err(|_| ExecutionUnavailable)
    }

    fn prepare(
        &mut self,
        admission: OrdinaryAdmission,
        lease: LeaseToken,
        plan: &ActLaunchPlan,
        binding: &ValidatedAttemptLeaseBinding,
    ) -> Result<BrokerProxyInputs<Self::Persister>, ExecutionUnavailable> {
        self.preflight(plan, binding)?;
        let record = self.record(plan, binding)?;
        if record.lease_generation != lease.generation()
            || record.controller_lease_id != hex::encode(lease.lease_id())
            || record.lease_token_sha256 != proxy_lease_token_digest(lease)
            || admission.lease_id != lease.lease_id()
            || admission.run_id != lease.run_id()
            || admission.attempt != lease.attempt()
            || admission.job.source_oid != parse_oid(&record.manifest.sha)?
            || admission.job.base_oid != parse_oid(&record.manifest.base_oid)?
            || hex::encode(admission.job.manifest_digest)
                != record
                    .manifest
                    .manifest_digest
                    .strip_prefix("sha256:")
                    .ok_or(ExecutionUnavailable)?
        {
            return Err(ExecutionUnavailable);
        }
        let now = (self.now)()?;
        let remaining = record
            .expires_at_unix_seconds
            .checked_sub(now)
            .filter(|seconds| *seconds > 0)
            .ok_or(ExecutionUnavailable)?;
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(remaining))
            .ok_or(ExecutionUnavailable)?;
        let upstream = self
            .descriptors
            .next_upstream(lease, deadline)
            .map_err(|_| ExecutionUnavailable)?;
        let key = (record.lease_id.clone(), lease.generation());
        if !self.consumed.insert(key) {
            return Err(ExecutionUnavailable);
        }
        Ok(BrokerProxyInputs {
            authority: record.authority.build()?,
            manifest: record.manifest,
            canonical_job_manifest: record.canonical_job_manifest,
            upstream,
            persister: self.persister.clone(),
        })
    }
}

fn system_now() -> Result<u64, ExecutionUnavailable> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ExecutionUnavailable)
}

/// Digest every opaque controller coordinate stored in one proxy input record.
pub fn proxy_lease_token_digest(lease: LeaseToken) -> String {
    let mut digest = Sha256::new();
    digest.update(b"buzzci-proxy-input-lease-v1\0");
    digest.update(lease.lease_id());
    digest.update(lease.run_id());
    digest.update(lease.attempt().to_be_bytes());
    digest.update(lease.signed_request_digest());
    digest.update(lease.signer().0);
    digest.update(lease.generation().to_be_bytes());
    digest.update(lease.nonce());
    digest.update(lease.deadline_at().to_be_bytes());
    hex::encode(digest.finalize())
}

fn lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn parse_oid(value: &str) -> Result<GitOid, ExecutionUnavailable> {
    match value.len() {
        40 => {
            let mut bytes = [0; 20];
            hex::decode_to_slice(value, &mut bytes).map_err(|_| ExecutionUnavailable)?;
            Ok(GitOid::Sha1(bytes))
        }
        64 => {
            let mut bytes = [0; 32];
            hex::decode_to_slice(value, &mut bytes).map_err(|_| ExecutionUnavailable)?;
            Ok(GitOid::Sha256(bytes))
        }
        _ => Err(ExecutionUnavailable),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::os::unix::net::UnixStream;

    use buzz_ci_policy_proxy::{
        AllowedMount, CanonicalCreate, EffectiveContainerSpec, EngineKind, ExecExpectation,
        IsolationLimits, IsolationProfile, NetworkPolicy, VerifiedStart,
    };
    use nix::unistd::getegid;
    use tempfile::TempDir;

    use super::*;

    #[derive(Clone)]
    struct FakePersister;

    impl PrestartPersister for FakePersister {
        fn persist(
            &mut self,
            _admission: &OrdinaryAdmission,
            _lease: LeaseToken,
            _create: &CanonicalCreate,
            _proof: &VerifiedStart,
            _effective: &EffectiveContainerSpec,
        ) -> Result<(), crate::seccomp_exec::SeccompExecError> {
            Ok(())
        }
    }

    impl BoundPrestartPersister for FakePersister {
        fn profile_path(&self) -> &str {
            buzz_ci_isolation_contract::PHASE1_SECCOMP_PROFILE_PATH
        }

        fn receipt_digest(&self) -> String {
            "d".repeat(64)
        }
    }

    struct FakeDescriptors;

    impl ActRuntimeDescriptorSource for FakeDescriptors {
        fn preflight(
            &self,
            _plan: &ActLaunchPlan,
            _binding: &ValidatedAttemptLeaseBinding,
        ) -> Result<(), crate::normal_backend::ActProxyLaunchError> {
            Ok(())
        }

        fn next_upstream(
            &mut self,
            _lease: LeaseToken,
            _deadline: Instant,
        ) -> Result<UnixStream, crate::normal_backend::ActProxyLaunchError> {
            let (broker, runtime) = UnixStream::pair()
                .map_err(|_| crate::normal_backend::ActProxyLaunchError::Unavailable)?;
            drop(runtime);
            Ok(broker)
        }
    }

    fn fixed_now() -> Result<u64, ExecutionUnavailable> {
        Ok(20)
    }

    fn proxy_record(
        plan: &ActLaunchPlan,
        binding: &ValidatedAttemptLeaseBinding,
        lease: LeaseToken,
        authority_root: &Path,
        evidence_root: &Path,
    ) -> ProxyInputRecord {
        let expected = binding.as_binding();
        let profile = IsolationProfile {
            image_digest: expected.isolation_profile.image_digest.clone(),
            engine_kind: EngineKind::Podman,
            engine_version: expected.isolation_profile.engine_version.clone(),
            arch: expected.isolation_profile.arch.clone(),
            seccomp_profile_path: expected.isolation_profile.seccomp_profile_path.clone(),
            seccomp_profile_digest: expected.isolation_profile.seccomp_profile_digest.clone(),
            limits: IsolationLimits {
                cpu_quota_micros: 100_000,
                memory_max_bytes: expected.isolation_profile.limits.mem_max_bytes,
                memory_swap_max_bytes: 0,
                pids_max: u64::from(expected.isolation_profile.limits.pids_max),
                shm_size_bytes: 64 * 1024 * 1024,
                disk_max_bytes: 1024 * 1024 * 1024,
                timeout_seconds: 30,
            },
            network_policy: NetworkPolicy::None,
            service_requirements: Vec::new(),
            netns: expected.isolation_profile.netns.clone(),
        };
        let exec = ExecExpectation {
            argv: vec!["/bin/sh".into(), "-c".into(), "true".into()],
            environment: Vec::new(),
            user: "2000:2000".into(),
            working_dir: "/workspace".into(),
            attach_stdin: false,
            attach_stdout: true,
            attach_stderr: true,
            tty: false,
        };
        let mounts = vec![AllowedMount {
            source: "/var/lib/buzz-ci/workspaces/test".into(),
            destination: "/workspace".into(),
            read_only: true,
        }];
        let canonical = crate::normal_backend::CanonicalExecManifest {
            schema_version: 1,
            request_event_id: expected.request_event_id.clone(),
            run_id: expected.run_id.clone(),
            target_repo_a: expected.target_repo_a.clone(),
            sha: expected.source_sha.clone(),
            base_oid: expected.base_oid.clone(),
            workflow_id: expected.workflow_id.clone(),
            workflow_digest: expected.workflow_digest.clone(),
            job_id: expected.job_id.clone(),
            attempt: expected.attempt,
            lease_id: expected.lease_id.clone(),
            isolation_profile: profile.clone(),
            container_user: "2000:2000".into(),
            mounts: mounts.clone(),
            allowed_environment: Vec::new(),
            expected_execs: vec![exec],
        };
        let canonical_job_manifest = serde_json::to_vec(&canonical).unwrap();
        let manifest = PolicyManifest {
            schema_version: 1,
            request_event_id: expected.request_event_id.clone(),
            run_id: expected.run_id.clone(),
            target_repo_a: expected.target_repo_a.clone(),
            sha: expected.source_sha.clone(),
            base_oid: expected.base_oid.clone(),
            workflow_id: expected.workflow_id.clone(),
            workflow_digest: expected.workflow_digest.clone(),
            job_id: expected.job_id.clone(),
            attempt: expected.attempt,
            lease_id: expected.lease_id.clone(),
            manifest_digest: format!(
                "sha256:{}",
                hex::encode(Sha256::digest(&canonical_job_manifest))
            ),
            isolation_profile: profile,
            container_user: "2000:2000".into(),
            mounts,
            allowed_environment: Vec::new(),
            expected_execs: Vec::new(),
        };
        ProxyInputRecord {
            schema_version: 1,
            lease_id: expected.lease_id.clone(),
            controller_lease_id: hex::encode(lease.lease_id()),
            lease_generation: lease.generation(),
            lease_token_sha256: proxy_lease_token_digest(lease),
            issued_at_unix_seconds: 20,
            expires_at_unix_seconds: expected.expires_at_unix_seconds,
            manifest,
            canonical_job_manifest,
            authority: ProxyAuthorityRecord {
                listener_root: authority_root.into(),
                evidence_root: evidence_root.into(),
                event_binding: CiEventBinding {
                    request_event_id_46105: [31; 32],
                    teardown_event_id_46106: [32; 32],
                },
                bundle: authority_root.join("bundle"),
                pid_file: authority_root.join("pid"),
                exec_argv: plan.argv().unwrap(),
                exec_working_directory: plan.working_directory.clone(),
                exec_uid: expected.principals.executor,
                exec_gid: getegid().as_raw(),
                listener_gid: getegid().as_raw(),
            },
            seccomp_profile_path: buzz_ci_isolation_contract::PHASE1_SECCOMP_PROFILE_PATH.into(),
            seccomp_receipt_sha256: "d".repeat(64),
        }
    }

    fn write_record(root: &Path, name: &str, record: &ProxyInputRecord) {
        let path = root.join(name);
        fs::write(&path, serde_json::to_vec(record).unwrap()).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn lease_digest_binds_generation_deadline_and_nonce() {
        let fixture = crate::normal_engine::tests::ordinary_fixture();
        let first = proxy_lease_token_digest(fixture.lease);
        assert!(lower_hex(&first, 64));
        assert_eq!(first, proxy_lease_token_digest(fixture.lease));
    }

    #[test]
    fn object_ids_are_exact_and_full_width() {
        assert!(matches!(parse_oid(&"a".repeat(40)), Ok(GitOid::Sha1(_))));
        assert!(matches!(parse_oid(&"b".repeat(64)), Ok(GitOid::Sha256(_))));
        assert!(parse_oid(&"c".repeat(39)).is_err());
        assert!(parse_oid(&"g".repeat(40)).is_err());
    }

    #[test]
    fn provider_binds_authority_descriptor_lease_seccomp_and_replay() {
        let authority = TempDir::new().unwrap();
        fs::set_permissions(authority.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let listener = TempDir::new().unwrap();
        let evidence = TempDir::new().unwrap();
        let fixture = crate::normal_engine::tests::ordinary_fixture();
        let binding = fixture
            .plan
            .binding
            .clone()
            .validate_phase1(&fixture.plan.validation.context())
            .unwrap();
        let mut plan = fixture.plan.act;
        plan.proxy_socket = listener.path().join(format!(
            "proxy-{}-{}.sock",
            hex::encode(fixture.lease.lease_id()),
            fixture.lease.generation()
        ));
        let record = proxy_record(
            &plan,
            &binding,
            fixture.lease,
            listener.path(),
            evidence.path(),
        );
        write_record(
            authority.path(),
            &format!("{}.json", binding.as_binding().lease_id),
            &record,
        );
        let owner = fs::metadata(authority.path()).unwrap();
        let mut provider = ProxyInputProvider::open_for_owner(
            authority.path(),
            owner.uid(),
            owner.gid(),
            FakeDescriptors,
            FakePersister,
            fixed_now,
        )
        .unwrap();
        assert!(non_secret_json(
            &serde_json::from_slice(&record.canonical_job_manifest).unwrap()
        ));
        let mut populated = record.manifest.clone();
        assert_eq!(
            populate_expected_execs(&mut populated, &record.canonical_job_manifest),
            Ok(())
        );
        record
            .validate(20, &plan, &binding, &FakePersister)
            .unwrap();
        provider.preflight(&plan, &binding).unwrap();
        let mut admission = fixture.admission;
        admission.job.manifest_digest = Sha256::digest(&record.canonical_job_manifest).into();
        let prepared = provider
            .prepare(admission, fixture.lease, &plan, &binding)
            .unwrap();
        assert_eq!(prepared.manifest, record.manifest);
        assert_eq!(prepared.persister.receipt_digest(), "d".repeat(64));
        assert!(provider
            .prepare(admission, fixture.lease, &plan, &binding)
            .is_err());

        let hostile = TempDir::new().unwrap();
        fs::set_permissions(hostile.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut tampered = record;
        tampered.lease_token_sha256 = "0".repeat(64);
        write_record(
            hostile.path(),
            &format!("{}.json", binding.as_binding().lease_id),
            &tampered,
        );
        let owner = fs::metadata(hostile.path()).unwrap();
        let mut hostile_provider = ProxyInputProvider::open_for_owner(
            hostile.path(),
            owner.uid(),
            owner.gid(),
            FakeDescriptors,
            FakePersister,
            fixed_now,
        )
        .unwrap();
        assert!(hostile_provider
            .prepare(admission, fixture.lease, &plan, &binding)
            .is_err());
    }
}
