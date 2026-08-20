use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    profile::validate_ascii_token, CgroupHandle, ContractError, IsolationProfile, NetnsHandle,
    QuotaHandle, RuntimeEndpointIdentity, WorkspaceHandle,
};

/// Three distinct host principals assigned to one attempt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalUids {
    /// UID that performs bounded materialization and owns no runtime socket.
    pub materializer: u32,
    /// UID that runs the pinned outer `act` process and sees only the proxy.
    pub executor: u32,
    /// UID that owns the rootless runtime and its raw endpoint.
    pub runtime: u32,
}

impl PrincipalUids {
    fn validate(&self, forbidden_host_uids: &[u32]) -> Result<(), ContractError> {
        let values = [self.materializer, self.executor, self.runtime];
        if values.contains(&0) {
            return Err(ContractError::invalid(
                "principals",
                "all principals must be non-root",
            ));
        }
        if values.into_iter().collect::<BTreeSet<_>>().len() != values.len() {
            return Err(ContractError::invalid(
                "principals",
                "materializer, executor, and runtime UIDs must be distinct",
            ));
        }
        if values.iter().any(|uid| forbidden_host_uids.contains(uid)) {
            return Err(ContractError::invalid(
                "principals",
                "a principal matches a forbidden login, runner, relay, or broker UID",
            ));
        }
        Ok(())
    }
}

/// Host facts against which a wire binding is validated.
#[derive(Clone, Debug)]
pub struct Phase1ValidationContext<'a> {
    /// Current broker wall-clock time in Unix seconds.
    pub now_unix_seconds: u64,
    /// Maximum accepted future lease horizon.
    pub max_expiry_horizon_seconds: u64,
    /// Login, runner, relay, broker, and other forbidden host UIDs.
    pub forbidden_host_uids: &'a [u32],
    /// Exact engine version qualified on this host.
    pub expected_engine_version: &'a str,
    /// Exact canonical architecture qualified on this host.
    pub expected_arch: &'a str,
}

/// Unvalidated wire representation joining protocol identity to lease handles.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptLeaseBinding {
    /// Contract schema. Phase 1 accepts version 1 only.
    pub schema_version: u16,
    /// Exact accepted kind-46100 request event ID.
    pub request_event_id: String,
    /// Exact protocol run identifier.
    pub run_id: String,
    /// Exact NIP-33 repository coordinate from the accepted request.
    pub target_repo_a: String,
    /// Full lowercase Git SHA-1 or SHA-256 object ID.
    ///
    /// This internal field maps to frozen protocol field/tag `c`.
    pub source_sha: String,
    /// Full trusted base commit whose tree supplies the workflow bytes.
    pub base_oid: String,
    /// Exact static workflow identifier from the accepted request.
    pub workflow_id: String,
    /// SHA-256 of the trusted-base workflow bytes.
    pub workflow_digest: String,
    /// Exact static job identifier.
    pub job_id: String,
    /// One-based protocol attempt number.
    pub attempt: u32,
    /// Broker-issued ULID identifying one exclusive lease.
    pub lease_id: String,
    /// Lease expiry in Unix seconds.
    pub expires_at_unix_seconds: u64,
    /// Dedicated per-phase host principals.
    pub principals: PrincipalUids,
    /// Broker-issued private workspace identity.
    pub workspace: WorkspaceHandle,
    /// Raw rootless runtime endpoint available only to the policy proxy.
    pub runtime_endpoint: RuntimeEndpointIdentity,
    /// Broker-issued cgroup identity and exact limits.
    pub cgroup: CgroupHandle,
    /// Broker-issued execution network namespace.
    pub netns: NetnsHandle,
    /// Broker-issued hard workspace quota.
    pub quota: QuotaHandle,
    /// Full frozen execution profile.
    pub isolation_profile: IsolationProfile,
}

/// Protocol v1.4 identity contributed by one released per-job lease.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeardownLeaseIdentity {
    /// Static job identifier.
    pub job_id: String,
    /// Selected one-based job attempt.
    pub attempt: u32,
    /// Job-attempt-scoped isolation lease identifier.
    pub lease_id: String,
}

/// An attempt/lease binding that passed all Phase-1 validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedAttemptLeaseBinding(AttemptLeaseBinding);

impl AttemptLeaseBinding {
    /// Validate and consume an untrusted binding.
    ///
    /// This validates contract and cross-field consistency only. Signature,
    /// authorization, descriptor ownership, cgroup/namespace readback, quota
    /// enforcement, and socket ACLs remain trusted-broker responsibilities.
    pub fn validate_phase1(
        self,
        context: &Phase1ValidationContext<'_>,
    ) -> Result<ValidatedAttemptLeaseBinding, ContractError> {
        if self.schema_version != 1 {
            return Err(ContractError::invalid(
                "schema_version",
                "Phase 1 accepts version 1 only",
            ));
        }
        validate_lower_hex("request_event_id", &self.request_event_id, 64)?;
        Uuid::parse_str(&self.run_id)
            .map_err(|_| ContractError::invalid("run_id", "must be a UUID"))?;
        validate_repository_coordinate(&self.target_repo_a)?;
        validate_git_object_id("source_sha", &self.source_sha)?;
        validate_git_object_id("base_oid", &self.base_oid)?;
        if self.source_sha.len() != self.base_oid.len() {
            return Err(ContractError::mismatch(
                "base_oid",
                "tip and base object IDs must use the same width",
            ));
        }
        validate_ascii_token("workflow_id", &self.workflow_id, 256)?;
        validate_lower_hex("workflow_digest", &self.workflow_digest, 64)?;
        validate_job_id(&self.job_id)?;
        if self.attempt == 0 {
            return Err(ContractError::invalid("attempt", "must be at least 1"));
        }
        validate_ulid(&self.lease_id)?;
        validate_expiry(
            self.expires_at_unix_seconds,
            context.now_unix_seconds,
            context.max_expiry_horizon_seconds,
        )?;
        self.principals.validate(context.forbidden_host_uids)?;
        self.workspace.validate(self.principals.materializer)?;
        self.runtime_endpoint.validate(self.principals.runtime)?;
        self.cgroup.validate()?;
        self.netns.validate()?;
        self.quota.validate()?;
        self.isolation_profile
            .validate_phase1(context.expected_engine_version, context.expected_arch)?;

        if self.workspace.quota_token != self.quota.token {
            return Err(ContractError::mismatch(
                "workspace.quota_token",
                "workspace is not bound to the supplied quota",
            ));
        }
        if self.cgroup.limits != self.isolation_profile.limits {
            return Err(ContractError::mismatch(
                "cgroup.limits",
                "cgroup lease limits differ from the isolation profile",
            ));
        }
        if self.netns.name != self.isolation_profile.netns {
            return Err(ContractError::mismatch(
                "netns.name",
                "network namespace differs from the isolation profile",
            ));
        }

        let tokens = [
            self.workspace.object.token.as_str(),
            self.runtime_endpoint.token(),
            self.cgroup.object.token.as_str(),
            self.netns.object.token.as_str(),
            self.quota.token.as_str(),
        ];
        if tokens.into_iter().collect::<BTreeSet<_>>().len() != tokens.len() {
            return Err(ContractError::invalid(
                "capability_tokens",
                "every broker resource must use a distinct capability token",
            ));
        }

        let mut objects = BTreeSet::new();
        for object in [
            Some((self.workspace.object.device, self.workspace.object.inode)),
            self.runtime_endpoint.object_identity(),
            Some((self.cgroup.object.device, self.cgroup.object.inode)),
            Some((self.netns.object.device, self.netns.object.inode)),
        ]
        .into_iter()
        .flatten()
        {
            if !objects.insert(object) {
                return Err(ContractError::invalid(
                    "object_identity",
                    "broker resources must not alias the same device and inode",
                ));
            }
        }

        Ok(ValidatedAttemptLeaseBinding(self))
    }
}

impl ValidatedAttemptLeaseBinding {
    /// Borrow the validated contract.
    pub fn as_binding(&self) -> &AttemptLeaseBinding {
        &self.0
    }

    /// Consume the proof wrapper and return the validated contract.
    pub fn into_binding(self) -> AttemptLeaseBinding {
        self.0
    }

    /// Return the exact protocol v1.4 teardown tuple for this lease.
    pub fn teardown_identity(&self) -> TeardownLeaseIdentity {
        TeardownLeaseIdentity {
            job_id: self.0.job_id.clone(),
            attempt: self.0.attempt,
            lease_id: self.0.lease_id.clone(),
        }
    }
}

fn validate_lower_hex(
    field: &'static str,
    value: &str,
    length: usize,
) -> Result<(), ContractError> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ContractError::invalid(
            field,
            "must be lowercase hexadecimal with the required width",
        ));
    }
    Ok(())
}

fn validate_repository_coordinate(value: &str) -> Result<(), ContractError> {
    let mut parts = value.splitn(3, ':');
    if parts.next() != Some("30617") {
        return Err(ContractError::invalid(
            "target_repo_a",
            "must use repository kind 30617",
        ));
    }
    let owner = parts.next().unwrap_or_default();
    validate_lower_hex("target_repo_a", owner, 64)?;
    let repo_id = parts.next().unwrap_or_default();
    if repo_id.is_empty() || repo_id.chars().any(char::is_control) {
        return Err(ContractError::invalid(
            "target_repo_a",
            "repository d-tag must be non-empty and control-free",
        ));
    }
    Ok(())
}

fn validate_job_id(value: &str) -> Result<(), ContractError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(ContractError::invalid(
            "job_id",
            "must match the protocol static job grammar",
        ));
    }
    Ok(())
}

fn validate_git_object_id(field: &'static str, value: &str) -> Result<(), ContractError> {
    if !matches!(value.len(), 40 | 64)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ContractError::invalid(
            field,
            "must be a full lowercase SHA-1 or SHA-256 object ID",
        ));
    }
    Ok(())
}

fn validate_ulid(value: &str) -> Result<(), ContractError> {
    const CROCKFORD: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    if value.len() != 26
        || !value
            .as_bytes()
            .first()
            .is_some_and(|byte| (b'0'..=b'7').contains(byte))
        || !value.bytes().all(|byte| CROCKFORD.contains(&byte))
    {
        return Err(ContractError::invalid(
            "lease_id",
            "must be a canonical 26-character uppercase ULID",
        ));
    }
    Ok(())
}

fn validate_expiry(expiry: u64, now: u64, maximum_horizon: u64) -> Result<(), ContractError> {
    const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
    if expiry > MAX_SAFE_INTEGER || now > MAX_SAFE_INTEGER || maximum_horizon > MAX_SAFE_INTEGER {
        return Err(ContractError::invalid(
            "expires_at_unix_seconds",
            "lease time values must be JavaScript-safe integers",
        ));
    }
    if maximum_horizon == 0 {
        return Err(ContractError::invalid(
            "validation_context.max_expiry_horizon_seconds",
            "must be non-zero",
        ));
    }
    if expiry <= now {
        return Err(ContractError::invalid(
            "expires_at_unix_seconds",
            "lease is expired",
        ));
    }
    let latest = now.checked_add(maximum_horizon).ok_or_else(|| {
        ContractError::invalid(
            "validation_context.max_expiry_horizon_seconds",
            "overflows Unix time",
        )
    })?;
    if expiry > latest {
        return Err(ContractError::invalid(
            "expires_at_unix_seconds",
            "lease exceeds the maximum future horizon",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BrokerObjectHandle, EngineKind, NetworkPolicy, QuotaBackend, ResourceLimits};

    fn token(byte: char) -> String {
        byte.to_string().repeat(64)
    }

    fn limits() -> ResourceLimits {
        ResourceLimits {
            cpu_weight: 100,
            mem_max_bytes: 2 * 1024 * 1024 * 1024,
            pids_max: 512,
            io_weight: 100,
        }
    }

    fn object(token_byte: char, device: u64, inode: u64) -> BrokerObjectHandle {
        BrokerObjectHandle {
            token: token(token_byte),
            device,
            inode,
        }
    }

    fn binding() -> AttemptLeaseBinding {
        AttemptLeaseBinding {
            schema_version: 1,
            request_event_id: "f".repeat(64),
            run_id: "018f47a2-7f0f-7cc1-9a55-01f93e42b1e0".into(),
            target_repo_a: format!("30617:{}:buzz", "e".repeat(64)),
            source_sha: "a".repeat(40),
            base_oid: "c".repeat(40),
            workflow_id: "required-ci".into(),
            workflow_digest: "d".repeat(64),
            job_id: "linux".into(),
            attempt: 1,
            lease_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            expires_at_unix_seconds: 1_060,
            principals: PrincipalUids {
                materializer: 991,
                executor: 992,
                runtime: 993,
            },
            workspace: WorkspaceHandle {
                path: "/var/lib/buzz-ci/attempts/run-01".into(),
                object: object('1', 10, 11),
                owner_uid: 991,
                quota_token: token('5'),
            },
            runtime_endpoint: RuntimeEndpointIdentity::UnixSocket {
                token: token('2'),
                device: 10,
                inode: 12,
                owner_uid: 993,
            },
            cgroup: CgroupHandle {
                object: object('3', 20, 21),
                limits: limits(),
            },
            netns: NetnsHandle {
                object: object('4', 30, 31),
                name: "buzzci-run-01".into(),
            },
            quota: QuotaHandle {
                token: token('5'),
                backend: QuotaBackend::XfsProject,
                quota_id: "project-7001".into(),
                hard_bytes: 20 * 1024 * 1024 * 1024,
            },
            isolation_profile: IsolationProfile {
                image_digest: format!("sha256:{}", "b".repeat(64)),
                engine_kind: EngineKind::Podman,
                engine_version: "5.8.4".into(),
                arch: "x86_64".into(),
                seccomp_profile_path: crate::PHASE1_SECCOMP_PROFILE_PATH.into(),
                seccomp_profile_digest: crate::PHASE1_SECCOMP_PROFILE_DIGEST.into(),
                limits: limits(),
                network_policy: NetworkPolicy::None,
                service_requirements: Vec::new(),
                netns: "buzzci-run-01".into(),
            },
        }
    }

    fn context() -> Phase1ValidationContext<'static> {
        Phase1ValidationContext {
            now_unix_seconds: 1_000,
            max_expiry_horizon_seconds: 300,
            forbidden_host_uids: &[0, 1_000, 2_000],
            expected_engine_version: "5.8.4",
            expected_arch: "x86_64",
        }
    }

    #[test]
    fn valid_binding_cross_checks_every_shared_resource() {
        let validated = binding()
            .validate_phase1(&context())
            .expect("valid binding");
        assert_eq!(validated.as_binding().principals.runtime, 993);
        assert_eq!(
            validated.teardown_identity(),
            TeardownLeaseIdentity {
                job_id: "linux".into(),
                attempt: 1,
                lease_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            }
        );
    }

    #[test]
    fn three_principals_must_be_distinct_non_root_and_non_host() {
        for principals in [
            PrincipalUids {
                materializer: 0,
                executor: 992,
                runtime: 993,
            },
            PrincipalUids {
                materializer: 991,
                executor: 991,
                runtime: 993,
            },
            PrincipalUids {
                materializer: 1_000,
                executor: 992,
                runtime: 993,
            },
        ] {
            let mut candidate = binding();
            candidate.principals = principals;
            assert!(candidate.validate_phase1(&context()).is_err());
        }
    }

    #[test]
    fn runtime_and_workspace_owners_are_phase_specific() {
        let mut wrong_runtime = binding();
        wrong_runtime.runtime_endpoint = RuntimeEndpointIdentity::InheritedFd {
            token: token('2'),
            owner_uid: wrong_runtime.principals.executor,
        };
        assert!(wrong_runtime.validate_phase1(&context()).is_err());

        let mut wrong_workspace = binding();
        wrong_workspace.workspace.owner_uid = wrong_workspace.principals.runtime;
        assert!(wrong_workspace.validate_phase1(&context()).is_err());
    }

    #[test]
    fn expired_and_overlong_leases_fail_closed() {
        let mut expired = binding();
        expired.expires_at_unix_seconds = 1_000;
        assert!(expired.validate_phase1(&context()).is_err());

        let mut overlong = binding();
        overlong.expires_at_unix_seconds = 1_301;
        assert!(overlong.validate_phase1(&context()).is_err());

        let mut unsafe_integer = binding();
        unsafe_integer.expires_at_unix_seconds = 9_007_199_254_740_992;
        assert!(unsafe_integer.validate_phase1(&context()).is_err());
    }

    #[test]
    fn cgroup_netns_and_quota_must_match_the_profile_and_workspace() {
        let mut cgroup = binding();
        cgroup.cgroup.limits.cpu_weight = 200;
        assert!(cgroup.validate_phase1(&context()).is_err());

        let mut netns = binding();
        netns.isolation_profile.netns = "other-netns".into();
        assert!(netns.validate_phase1(&context()).is_err());

        let mut quota = binding();
        quota.workspace.quota_token = token('6');
        assert!(quota.validate_phase1(&context()).is_err());
    }

    #[test]
    fn phase1_refuses_network_services_and_unqualified_host_facts() {
        let mut network = binding();
        network.isolation_profile.network_policy = NetworkPolicy::Allowlist;
        assert!(network.validate_phase1(&context()).is_err());

        let mut service = binding();
        service
            .isolation_profile
            .service_requirements
            .push("postgres".into());
        assert!(service.validate_phase1(&context()).is_err());

        let mut wrong_arch = binding();
        wrong_arch.isolation_profile.arch = "amd64".into();
        assert!(wrong_arch.validate_phase1(&context()).is_err());

        let mut wrong_seccomp_path = binding();
        wrong_seccomp_path.isolation_profile.seccomp_profile_path =
            "/var/lib/buzzci/seccomp/unconfined.json".into();
        assert!(wrong_seccomp_path.validate_phase1(&context()).is_err());

        let mut wrong_seccomp_digest = binding();
        wrong_seccomp_digest
            .isolation_profile
            .seccomp_profile_digest = "0".repeat(64);
        assert!(wrong_seccomp_digest.validate_phase1(&context()).is_err());
    }

    #[test]
    fn lease_record_serializes_the_exact_seccomp_identity() {
        let value = serde_json::to_value(binding()).unwrap();
        let profile = &value["isolation_profile"];
        assert_eq!(
            profile["seccomp_profile_path"],
            crate::PHASE1_SECCOMP_PROFILE_PATH
        );
        assert_eq!(
            profile["seccomp_profile_digest"],
            crate::PHASE1_SECCOMP_PROFILE_DIGEST
        );
    }

    #[test]
    fn capabilities_and_object_identities_cannot_alias() {
        let mut token_alias = binding();
        token_alias.cgroup.object.token = token_alias.workspace.object.token.clone();
        assert!(token_alias.validate_phase1(&context()).is_err());

        let mut object_alias = binding();
        object_alias.netns.object.device = object_alias.cgroup.object.device;
        object_alias.netns.object.inode = object_alias.cgroup.object.inode;
        assert!(object_alias.validate_phase1(&context()).is_err());
    }

    #[test]
    fn malformed_identity_and_digest_fields_are_rejected() {
        let mut request = binding();
        request.request_event_id = "F".repeat(64);
        assert!(request.validate_phase1(&context()).is_err());

        let mut run = binding();
        run.run_id = "run-01".into();
        assert!(run.validate_phase1(&context()).is_err());

        let mut repo = binding();
        repo.target_repo_a = "owner/repo".into();
        assert!(repo.validate_phase1(&context()).is_err());

        let mut lease = binding();
        lease.lease_id = "lowercase-is-not-a-ulid".into();
        assert!(lease.validate_phase1(&context()).is_err());

        let mut digest = binding();
        digest.isolation_profile.image_digest = format!("sha256:{}", "B".repeat(64));
        assert!(digest.validate_phase1(&context()).is_err());

        let mut sha = binding();
        sha.source_sha = "short".into();
        assert!(sha.validate_phase1(&context()).is_err());

        let mut base = binding();
        base.base_oid = "short".into();
        assert!(base.validate_phase1(&context()).is_err());

        let mut width = binding();
        width.base_oid = "c".repeat(64);
        assert!(width.validate_phase1(&context()).is_err());

        let mut workflow = binding();
        workflow.workflow_digest = "D".repeat(64);
        assert!(workflow.validate_phase1(&context()).is_err());

        let mut job = binding();
        job.job_id = "linux-job".into();
        assert!(job.validate_phase1(&context()).is_err());
    }

    #[test]
    fn teardown_tuple_serializes_exactly_like_protocol_v14() {
        assert_eq!(
            buzz_core::ci::CI_PROTOCOL_CONTRACT_SHA256,
            "8b9715d719b057d5d297074c3d019e40d1d2104eeafa2b6033f17b465e7d5a1c"
        );
        let validated = binding().validate_phase1(&context()).unwrap();
        let local = serde_json::to_vec(&validated.teardown_identity()).unwrap();
        let core = serde_json::to_vec(&buzz_core::ci::CiTeardownLease {
            job_id: "linux".into(),
            attempt: 1,
            lease_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
        })
        .unwrap();
        assert_eq!(local, core);
        assert_eq!(
            String::from_utf8(local).unwrap(),
            r#"{"job_id":"linux","attempt":1,"lease_id":"01ARZ3NDEKTSV4RRFFQ69G5FAV"}"#
        );
    }

    #[test]
    fn unknown_wire_fields_are_rejected() {
        let mut value = serde_json::to_value(binding()).expect("serialize fixture");
        value["surprise"] = serde_json::json!(true);
        assert!(serde_json::from_value::<AttemptLeaseBinding>(value).is_err());
    }

    #[test]
    fn inherited_runtime_descriptor_is_supported() {
        let mut candidate = binding();
        candidate.runtime_endpoint = RuntimeEndpointIdentity::InheritedFd {
            token: token('2'),
            owner_uid: candidate.principals.runtime,
        };
        assert!(candidate.validate_phase1(&context()).is_ok());
    }
}
