use std::collections::BTreeMap;
use std::path::Path;

use buzz_ci_isolation_contract::{RuntimeEndpointIdentity, ValidatedAttemptLeaseBinding};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::{
    contract::{is_environment_name, is_socket_path, IsolationProfile},
    AttemptPhase, DockerMethod, DockerRoute, ObjectLedger, PolicyManifest, ProxyError,
};

const RESERVED_ENVIRONMENT: [&str; 3] = ["BUZZ_CI_RUN_ID", "BUZZ_CI_SHA", "BUZZ_CI_ATTEMPT"];
const FORBIDDEN_ENVIRONMENT: [&str; 8] = [
    "BUZZ_PRIVATE_KEY",
    "BUZZ_AUTH_TAG",
    "NOSTR_PRIVATE_KEY",
    "GITHUB_TOKEN",
    "SSH_AUTH_SOCK",
    "DOCKER_HOST",
    "CONTAINER_HOST",
    "XDG_RUNTIME_DIR",
];

/// Canonical create request and its pre-start fingerprint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalCreate {
    /// Canonical upstream request target. Caller-supplied names are ignored.
    pub target: String,
    /// Rebuilt JSON body to forward.
    pub body: Vec<u8>,
    /// SHA-256 over the canonical body and immutable attempt identity.
    pub fingerprint: String,
    operation_id: u64,
}

/// Canonical exec-create request tied to one owned started container.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalExec {
    /// Canonical upstream request target.
    pub target: String,
    /// Rebuilt JSON body.
    pub body: Vec<u8>,
    container_id: String,
    operation_id: u64,
}

impl CanonicalExec {
    /// Return the exact owned container this exec-create targets.
    pub fn container_id(&self) -> &str {
        &self.container_id
    }
}

/// Security-sensitive effective container fields returned by pre-start inspect.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectiveContainerSpec {
    /// Digest-pinned image.
    pub image: String,
    /// Numeric non-root UID:GID.
    pub user: String,
    /// Exact bind list.
    pub binds: Vec<String>,
    /// Network mode.
    pub network_mode: String,
    /// Read-only rootfs.
    pub readonly_rootfs: bool,
    /// Dropped capabilities.
    pub cap_drop: Vec<String>,
    /// Added capabilities.
    pub cap_add: Vec<String>,
    /// Privileged flag.
    pub privileged: bool,
    /// Security options.
    pub security_opt: Vec<String>,
    /// PID limit.
    pub pids_limit: u64,
    /// Memory limit.
    pub memory: u64,
    /// Swap limit.
    pub memory_swap: u64,
    /// Shared memory limit.
    pub shm_size: u64,
    /// CPU limit in Docker `NanoCpus` units.
    pub nano_cpus: u64,
    /// Effective device mappings. Phase 1 requires none.
    pub devices: Vec<String>,
    /// Effective published port bindings. Phase 1 requires none.
    pub port_bindings: BTreeMap<String, Vec<String>>,
    /// Whether all exposed ports are published.
    pub publish_all_ports: bool,
    /// Effective PID namespace mode.
    pub pid_mode: String,
    /// Effective IPC namespace mode.
    pub ipc_mode: String,
    /// Effective UTS namespace mode.
    pub uts_mode: String,
    /// Effective cgroup namespace mode.
    pub cgroupns_mode: String,
    /// Effective user namespace mode.
    pub userns_mode: String,
    /// Effective restart policy name.
    pub restart_policy: String,
    /// Effective log driver.
    pub log_driver: String,
    /// Effective network endpoint names. Phase 1 requires none.
    pub network_endpoints: Vec<String>,
    /// Complete immutable attempt labels.
    pub labels: BTreeMap<String, String>,
}

/// Opaque proof that a fresh upstream inspect matched every modeled control.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedStart {
    container_id: String,
    create_fingerprint: String,
}

impl VerifiedStart {
    /// Return whether this opaque pre-start proof belongs to the supplied
    /// canonical create capability.
    pub fn matches_create(&self, create: &CanonicalCreate) -> bool {
        self.create_fingerprint == create.fingerprint
    }
}

/// Admission result. Denied requests return [`ProxyError`] and therefore never
/// reach the upstream runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Admission {
    /// Answer locally without leaking runtime host details.
    LocalResponse(Vec<u8>),
    /// Forward an unmodified bounded read/cleanup request.
    Forward {
        /// Canonical target to forward.
        target: String,
    },
    /// Forward a rebuilt canonical exec-create request.
    ExecCreate(CanonicalExec),
    /// A create request awaiting an upstream object ID.
    Create(CanonicalCreate),
    /// Start is permitted only after caller compares a fresh inspect result
    /// through [`ProxyPolicy::verify_pre_start`].
    NeedsPreStartProof {
        /// Attempt-owned container ID.
        container_id: String,
        /// Canonical start target.
        target: String,
    },
    /// Delete may be forwarded, but ledger removal is committed only after an
    /// upstream success response.
    Delete {
        /// Attempt-owned container ID to remove after upstream success.
        container_id: String,
        /// Canonical delete target.
        target: String,
    },
    /// Wait may be forwarded, but stopped state is committed only after the
    /// upstream response proves the container stopped.
    Wait {
        /// Attempt-owned container ID.
        container_id: String,
        /// Canonical wait target.
        target: String,
    },
}

/// Closed policy engine used by the Unix-socket frontend.
pub struct ProxyPolicy {
    manifest: PolicyManifest,
    phase: AttemptPhase,
    ledger: ObjectLedger,
    next_operation: u64,
    pending_creates: BTreeMap<u64, String>,
    created_requests: BTreeMap<String, CanonicalCreate>,
    pending_execs: BTreeMap<u64, String>,
    container_lifecycle: ContainerLifecycle,
    executor_uid: u32,
    runtime_uid: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ContainerLifecycle {
    AwaitCreate,
    Creating {
        operation_id: u64,
        fingerprint: String,
    },
    Created {
        container_id: String,
    },
    Starting {
        container_id: String,
    },
    Started {
        container_id: String,
    },
    Deleting {
        container_id: String,
        was_started: bool,
    },
    Removed {
        container_id: String,
    },
}

impl ProxyPolicy {
    /// Install an immutable manifest bound to the broker-validated attempt lease.
    pub fn install(
        manifest: PolicyManifest,
        lease: &ValidatedAttemptLeaseBinding,
    ) -> Result<Self, ProxyError> {
        manifest.validate()?;
        verify_lease_binding(&manifest, lease)?;
        let binding = lease.as_binding();
        if !matches!(
            binding.runtime_endpoint,
            RuntimeEndpointIdentity::InheritedFd { .. }
        ) {
            return Err(ProxyError::InvalidManifest(
                "the policy proxy requires a broker-inherited runtime endpoint".into(),
            ));
        }
        Self::install_validated(
            manifest,
            binding.principals.executor,
            binding.principals.runtime,
        )
    }

    fn install_validated(
        manifest: PolicyManifest,
        executor_uid: u32,
        runtime_uid: u32,
    ) -> Result<Self, ProxyError> {
        Ok(Self {
            manifest,
            phase: AttemptPhase::Running,
            ledger: ObjectLedger::default(),
            next_operation: 1,
            pending_creates: BTreeMap::new(),
            created_requests: BTreeMap::new(),
            pending_execs: BTreeMap::new(),
            container_lifecycle: ContainerLifecycle::AwaitCreate,
            executor_uid,
            runtime_uid,
        })
    }

    #[cfg(test)]
    pub(crate) fn install_for_test(manifest: PolicyManifest) -> Result<Self, ProxyError> {
        manifest.validate()?;
        Self::install_validated(manifest, 65_532, 65_533)
    }

    #[cfg(test)]
    pub(crate) fn install_for_transport_test(
        manifest: PolicyManifest,
        executor_uid: u32,
        runtime_uid: u32,
    ) -> Result<Self, ProxyError> {
        manifest.validate()?;
        Self::install_validated(manifest, executor_uid, runtime_uid)
    }

    /// Dedicated executor UID permitted on the proxy listener.
    pub fn executor_uid(&self) -> u32 {
        self.executor_uid
    }

    /// Dedicated runtime UID that must own the inherited upstream peer.
    pub fn runtime_uid(&self) -> u32 {
        self.runtime_uid
    }

    pub(crate) fn image_digest(&self) -> &str {
        &self.manifest.isolation_profile.image_digest
    }

    pub(crate) fn engine_arch(&self) -> &str {
        &self.manifest.isolation_profile.arch
    }

    /// Return the current phase.
    pub fn phase(&self) -> AttemptPhase {
        self.phase
    }

    /// Classify and authorize one bounded executor-facing request.
    pub fn admit(
        &mut self,
        method: DockerMethod,
        target: &str,
        body: &[u8],
    ) -> Result<Admission, ProxyError> {
        if self.phase != AttemptPhase::Running {
            return Err(ProxyError::StateRefused(
                "executor requests require Running phase".into(),
            ));
        }
        let parsed = DockerRoute::parse_canonical(method, target)?;
        let canonical_target = parsed.target;
        match parsed.route {
            DockerRoute::Ping => Ok(Admission::LocalResponse(b"OK".to_vec())),
            DockerRoute::Version => Ok(Admission::LocalResponse(
                serde_json::to_vec(&serde_json::json!({
                    "Version": self.manifest.isolation_profile.engine_version,
                    "ApiVersion": "1.47",
                    "MinAPIVersion": "1.41",
                    "Os": "linux",
                    "Arch": self.manifest.isolation_profile.arch,
                }))
                .map_err(|error| ProxyError::InvalidRequest(error.to_string()))?,
            )),
            DockerRoute::Info => Ok(Admission::LocalResponse(
                serde_json::to_vec(&serde_json::json!({
                    "Name": "buzz-ci-policy-proxy",
                    "Containers": self.ledger.container_ids().count(),
                    "Images": 1,
                    "OSType": "linux",
                    "Architecture": self.manifest.isolation_profile.arch,
                }))
                .map_err(|error| ProxyError::InvalidRequest(error.to_string()))?,
            )),
            DockerRoute::ContainerList => {
                Ok(Admission::LocalResponse(self.container_list_response()?))
            }
            DockerRoute::ImageInspect { image } => {
                if image != self.manifest.isolation_profile.image_digest {
                    return Err(ProxyError::PolicyRefused(
                        "image inspect is not manifest-pinned".into(),
                    ));
                }
                Ok(Admission::Forward {
                    target: canonical_target,
                })
            }
            DockerRoute::VolumeList => Ok(Admission::LocalResponse(
                br#"{"Volumes":[],"Warnings":[]}"#.to_vec(),
            )),
            DockerRoute::ContainerCreate => {
                if self.container_lifecycle != ContainerLifecycle::AwaitCreate {
                    return Err(ProxyError::StateRefused(
                        "container create is permitted exactly once".into(),
                    ));
                }
                self.canonical_create(body).map(Admission::Create)
            }
            DockerRoute::ContainerInspect { id }
            | DockerRoute::ContainerAttach { id }
            | DockerRoute::ContainerLogs { id } => {
                self.ledger.container_fingerprint(&id)?;
                Ok(Admission::Forward {
                    target: canonical_target,
                })
            }
            DockerRoute::ContainerWait { id } => {
                self.ledger.container_fingerprint(&id)?;
                Ok(Admission::Wait {
                    container_id: id,
                    target: canonical_target,
                })
            }
            DockerRoute::ContainerStart { id } => {
                self.require_created_container(&id)?;
                Ok(Admission::NeedsPreStartProof {
                    container_id: id,
                    target: canonical_target,
                })
            }
            DockerRoute::ContainerDelete { id } => {
                self.begin_delete(&id)?;
                Ok(Admission::Delete {
                    container_id: id,
                    target: canonical_target,
                })
            }
            DockerRoute::ExecCreate { container_id } => {
                self.ledger.require_started(&container_id)?;
                let body = canonical_exec(body, &self.manifest)?;
                let operation_id = self.allocate_operation()?;
                self.pending_execs
                    .insert(operation_id, container_id.clone());
                Ok(Admission::ExecCreate(CanonicalExec {
                    target: canonical_target,
                    body,
                    container_id,
                    operation_id,
                }))
            }
            DockerRoute::ExecStart { exec_id } | DockerRoute::ExecInspect { exec_id } => {
                self.ledger.require_exec(&exec_id)?;
                Ok(Admission::Forward {
                    target: canonical_target,
                })
            }
            DockerRoute::Archive { .. } => Err(ProxyError::PolicyRefused(
                "executor archive access is disabled in Phase 1".into(),
            )),
            DockerRoute::ImagePull => Err(ProxyError::PolicyRefused(
                "runtime image pulls are disabled; preload is mandatory".into(),
            )),
            DockerRoute::Build => Err(ProxyError::PolicyRefused(
                "runtime builds are disabled in Phase 1".into(),
            )),
            DockerRoute::ForbiddenFamily => Err(ProxyError::PolicyRefused(
                "Docker API family is disabled in Phase 1".into(),
            )),
        }
    }

    /// Bind the upstream container ID to a previously approved create body.
    pub fn record_created(
        &mut self,
        container_id: String,
        approved: &CanonicalCreate,
    ) -> Result<(), ProxyError> {
        if !matches!(
            &self.container_lifecycle,
            ContainerLifecycle::Creating {
                operation_id,
                fingerprint,
            } if *operation_id == approved.operation_id && fingerprint == &approved.fingerprint
        ) {
            return Err(ProxyError::StateRefused(
                "create result does not match create lifecycle state".into(),
            ));
        }
        if self.pending_creates.get(&approved.operation_id) != Some(&approved.fingerprint) {
            return Err(ProxyError::StateRefused(
                "create result has no matching pending request".into(),
            ));
        }
        self.pending_creates.remove(&approved.operation_id);
        self.ledger
            .record_container(container_id.clone(), approved.fingerprint.clone())?;
        self.created_requests
            .insert(container_id.clone(), approved.clone());
        self.container_lifecycle = ContainerLifecycle::Created { container_id };
        Ok(())
    }

    /// Abandon a pending create after a failed upstream response.
    pub fn abort_create(&mut self, approved: &CanonicalCreate) -> Result<(), ProxyError> {
        match (
            self.pending_creates.remove(&approved.operation_id),
            &self.container_lifecycle,
        ) {
            (
                Some(fingerprint),
                ContainerLifecycle::Creating {
                    operation_id,
                    fingerprint: lifecycle_fingerprint,
                },
            ) if fingerprint == approved.fingerprint
                && *operation_id == approved.operation_id
                && lifecycle_fingerprint == &approved.fingerprint =>
            {
                self.container_lifecycle = ContainerLifecycle::AwaitCreate;
                Ok(())
            }
            _ => Err(ProxyError::StateRefused(
                "create request is not pending".into(),
            )),
        }
    }

    /// Compare a fresh pre-start inspect snapshot to the complete expected
    /// isolation surface. Only an exact match permits `start`.
    pub fn verify_pre_start(
        &self,
        container_id: &str,
        effective: &EffectiveContainerSpec,
    ) -> Result<VerifiedStart, ProxyError> {
        self.require_created_container(container_id)?;
        let create_fingerprint = self.ledger.container_fingerprint(container_id)?;
        let expected = self.expected_effective_spec();
        if effective != &expected {
            return Err(ProxyError::PolicyRefused(
                "effective pre-start container config differs from policy".into(),
            ));
        }
        Ok(VerifiedStart {
            container_id: container_id.into(),
            create_fingerprint: create_fingerprint.into(),
        })
    }

    /// Return the canonical create capability retained for an owned container.
    pub fn created_request(&self, container_id: &str) -> Result<&CanonicalCreate, ProxyError> {
        self.ledger.container_fingerprint(container_id)?;
        self.created_requests.get(container_id).ok_or_else(|| {
            ProxyError::StateRefused("owned container lacks its canonical create record".into())
        })
    }

    /// Commit start state only after the upstream runtime reports success.
    pub fn commit_started(&mut self, proof: &VerifiedStart) -> Result<(), ProxyError> {
        match &self.container_lifecycle {
            ContainerLifecycle::Starting { container_id }
                if container_id == &proof.container_id => {}
            _ => {
                return Err(ProxyError::StateRefused(
                    "start commit has no matching start intent".into(),
                ));
            }
        }
        if self.ledger.container_fingerprint(&proof.container_id)?
            != proof.create_fingerprint.as_str()
        {
            return Err(ProxyError::StateRefused(
                "container ownership changed after pre-start proof".into(),
            ));
        }
        self.ledger.mark_started(&proof.container_id)?;
        self.container_lifecycle = ContainerLifecycle::Started {
            container_id: proof.container_id.clone(),
        };
        Ok(())
    }

    /// Bind a verified pre-start proof to the one pending start operation.
    pub fn begin_start(&mut self, proof: &VerifiedStart) -> Result<(), ProxyError> {
        self.require_created_container(&proof.container_id)?;
        if self.ledger.container_fingerprint(&proof.container_id)?
            != proof.create_fingerprint.as_str()
        {
            return Err(ProxyError::StateRefused(
                "pre-start proof no longer matches the owned container".into(),
            ));
        }
        self.container_lifecycle = ContainerLifecycle::Starting {
            container_id: proof.container_id.clone(),
        };
        Ok(())
    }

    /// Resolve a start that received a definite upstream rejection or was not sent.
    pub fn abort_start(&mut self, proof: &VerifiedStart) -> Result<(), ProxyError> {
        match &self.container_lifecycle {
            ContainerLifecycle::Starting { container_id }
                if container_id == &proof.container_id =>
            {
                self.container_lifecycle = ContainerLifecycle::Created {
                    container_id: container_id.clone(),
                };
                Ok(())
            }
            _ => Err(ProxyError::StateRefused(
                "start request is not pending".into(),
            )),
        }
    }

    /// Commit deletion only after the upstream runtime reports success.
    pub fn commit_deleted(&mut self, container_id: &str) -> Result<(), ProxyError> {
        if !matches!(
            &self.container_lifecycle,
            ContainerLifecycle::Deleting {
                container_id: deleting,
                ..
            } if deleting == container_id
        ) {
            return Err(ProxyError::StateRefused(
                "delete commit has no matching delete intent".into(),
            ));
        }
        if !self.created_requests.contains_key(container_id) {
            return Err(ProxyError::StateRefused(
                "deleted container lacked its canonical create record".into(),
            ));
        }
        self.ledger.remove_container(container_id)?;
        self.created_requests.remove(container_id);
        self.container_lifecycle = ContainerLifecycle::Removed {
            container_id: container_id.into(),
        };
        Ok(())
    }

    /// Bind one owned container to a pending delete mutation.
    pub fn begin_delete(&mut self, container_id: &str) -> Result<(), ProxyError> {
        self.ledger.container_fingerprint(container_id)?;
        let was_started = match &self.container_lifecycle {
            ContainerLifecycle::Created {
                container_id: owned,
            } if owned == container_id => false,
            ContainerLifecycle::Started {
                container_id: owned,
            } if owned == container_id => true,
            _ => {
                return Err(ProxyError::StateRefused(
                    "delete requires the one created or started container".into(),
                ));
            }
        };
        self.container_lifecycle = ContainerLifecycle::Deleting {
            container_id: container_id.into(),
            was_started,
        };
        Ok(())
    }

    /// Resolve a delete that was refused before mutation could occur.
    pub fn abort_delete(&mut self, container_id: &str) -> Result<(), ProxyError> {
        let was_started = match &self.container_lifecycle {
            ContainerLifecycle::Deleting {
                container_id: deleting,
                was_started,
            } if deleting == container_id => *was_started,
            _ => {
                return Err(ProxyError::StateRefused(
                    "delete request is not pending".into(),
                ));
            }
        };
        self.container_lifecycle = if was_started {
            ContainerLifecycle::Started {
                container_id: container_id.into(),
            }
        } else {
            ContainerLifecycle::Created {
                container_id: container_id.into(),
            }
        };
        Ok(())
    }

    /// Commit stopped state only after a successful upstream wait/readback.
    pub fn commit_stopped(&mut self, container_id: &str) -> Result<(), ProxyError> {
        self.ledger.mark_stopped(container_id)
    }

    /// Bind an upstream exec ID to an owned started container.
    pub fn record_exec(
        &mut self,
        exec_id: String,
        approved: &CanonicalExec,
    ) -> Result<(), ProxyError> {
        if self.pending_execs.get(&approved.operation_id) != Some(&approved.container_id) {
            return Err(ProxyError::StateRefused(
                "exec result has no matching pending request".into(),
            ));
        }
        self.ledger.record_exec(exec_id, &approved.container_id)?;
        self.pending_execs.remove(&approved.operation_id);
        Ok(())
    }

    /// Abandon a pending exec create after a failed upstream response.
    pub fn abort_exec(&mut self, approved: &CanonicalExec) -> Result<(), ProxyError> {
        match self.pending_execs.remove(&approved.operation_id) {
            Some(container_id) if container_id == approved.container_id => Ok(()),
            _ => Err(ProxyError::StateRefused(
                "exec request is not pending".into(),
            )),
        }
    }

    /// Start the terminal barrier. The frontend must drain active mutations
    /// before calling [`Self::finish_seal`].
    pub fn begin_seal(&mut self) -> Result<(), ProxyError> {
        if self.phase != AttemptPhase::Running {
            return Err(ProxyError::StateRefused(
                "seal may begin from Running only".into(),
            ));
        }
        if !self.pending_creates.is_empty()
            || !self.pending_execs.is_empty()
            || matches!(
                self.container_lifecycle,
                ContainerLifecycle::Creating { .. }
                    | ContainerLifecycle::Starting { .. }
                    | ContainerLifecycle::Deleting { .. }
            )
        {
            return Err(ProxyError::StateRefused(
                "seal cannot begin with pending upstream mutations".into(),
            ));
        }
        self.phase = AttemptPhase::Sealing;
        Ok(())
    }

    /// Enter terminal read-only mode after every managed container is stopped.
    pub fn finish_seal(&mut self) -> Result<(), ProxyError> {
        if self.phase != AttemptPhase::Sealing || !self.ledger.all_stopped() {
            return Err(ProxyError::StateRefused(
                "terminal mode requires Sealing and stopped containers".into(),
            ));
        }
        self.phase = AttemptPhase::TerminalReadOnly;
        Ok(())
    }

    fn canonical_create(&mut self, body: &[u8]) -> Result<CanonicalCreate, ProxyError> {
        if body.len() > 1024 * 1024 {
            return Err(ProxyError::InvalidRequest(
                "container create body exceeds 1 MiB".into(),
            ));
        }
        let input: Value = serde_json::from_slice(body)
            .map_err(|error| ProxyError::InvalidRequest(error.to_string()))?;
        let object = input.as_object().ok_or_else(|| {
            ProxyError::InvalidRequest("container create body must be an object".into())
        })?;
        let image = object
            .get("Image")
            .and_then(Value::as_str)
            .ok_or_else(|| ProxyError::InvalidRequest("container create requires Image".into()))?;
        if image != self.manifest.isolation_profile.image_digest {
            return Err(ProxyError::PolicyRefused(
                "container image is not the pinned digest".into(),
            ));
        }
        if object.contains_key("SecurityOpt") {
            return Err(ProxyError::PolicyRefused(
                "caller may not set container SecurityOpt".into(),
            ));
        }
        reject_conflicting_host_config(object.get("HostConfig"))?;
        reject_socket_mounts(object)?;
        let environment = canonical_environment(object.get("Env"), &self.manifest)?;
        let binds = canonical_binds(&self.manifest);
        let mut output = Map::new();
        output.insert("Image".into(), Value::String(image.into()));
        output.insert(
            "User".into(),
            Value::String(self.manifest.container_user.clone()),
        );
        output.insert("Env".into(), Value::Array(environment));
        copy_bounded_string_array(object, &mut output, "Cmd")?;
        copy_bounded_string_array(object, &mut output, "Entrypoint")?;
        copy_safe_string(object, &mut output, "WorkingDir", 4096)?;
        for field in [
            "AttachStdin",
            "AttachStdout",
            "AttachStderr",
            "OpenStdin",
            "StdinOnce",
            "Tty",
        ] {
            if let Some(value @ Value::Bool(_)) = object.get(field) {
                output.insert(field.into(), value.clone());
            }
        }
        output.insert(
            "Labels".into(),
            serde_json::to_value(self.attempt_labels())
                .map_err(|error| ProxyError::InvalidRequest(error.to_string()))?,
        );
        let limits = &self.manifest.isolation_profile.limits;
        let nano_cpus = limits.cpu_quota_micros.checked_mul(10_000).ok_or_else(|| {
            ProxyError::InvalidManifest("cpu_quota_micros overflows NanoCpus".into())
        })?;
        output.insert(
            "HostConfig".into(),
            serde_json::json!({
                "NetworkMode": "none",
                "ReadonlyRootfs": true,
                "Privileged": false,
                "CapAdd": [],
                "CapDrop": ["ALL"],
                "SecurityOpt": security_options(&self.manifest.isolation_profile),
                "Binds": binds,
                "Devices": [],
                "PortBindings": {},
                "PublishAllPorts": false,
                "PidMode": "private",
                "IpcMode": "private",
                "UTSMode": "private",
                "CgroupnsMode": "private",
                "UsernsMode": "private",
                "PidsLimit": limits.pids_max,
                "Memory": limits.memory_max_bytes,
                "MemorySwap": limits.memory_swap_max_bytes,
                "NanoCpus": nano_cpus,
                "ShmSize": limits.shm_size_bytes,
                "AutoRemove": false,
                "LogConfig": {"Type": "none", "Config": {}},
                "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
            }),
        );
        output.insert(
            "NetworkingConfig".into(),
            serde_json::json!({"EndpointsConfig": {}}),
        );
        let body = serde_json::to_vec(&Value::Object(output))
            .map_err(|error| ProxyError::InvalidRequest(error.to_string()))?;
        let mut hasher = Sha256::new();
        hasher.update(self.manifest.run_id.as_bytes());
        hasher.update(self.manifest.sha.as_bytes());
        hasher.update(self.manifest.job_id.as_bytes());
        hasher.update(self.manifest.attempt.to_be_bytes());
        hasher.update(self.manifest.manifest_digest.as_bytes());
        hasher.update(&body);
        let operation_id = self.allocate_operation()?;
        let fingerprint = hex::encode(hasher.finalize());
        self.pending_creates
            .insert(operation_id, fingerprint.clone());
        self.container_lifecycle = ContainerLifecycle::Creating {
            operation_id,
            fingerprint: fingerprint.clone(),
        };
        Ok(CanonicalCreate {
            target: format!(
                "/containers/create?name=buzz-ci-{}-{}",
                &self.manifest.manifest_digest[7..23],
                self.manifest.attempt
            ),
            body,
            fingerprint,
            operation_id,
        })
    }

    fn expected_effective_spec(&self) -> EffectiveContainerSpec {
        let limits = &self.manifest.isolation_profile.limits;
        // Validation in `canonical_create` rejects overflow before an object
        // can be recorded, so an owned container always has this exact value.
        let nano_cpus = limits.cpu_quota_micros.saturating_mul(10_000);
        EffectiveContainerSpec {
            image: self.manifest.isolation_profile.image_digest.clone(),
            user: self.manifest.container_user.clone(),
            binds: canonical_binds(&self.manifest),
            network_mode: "none".into(),
            readonly_rootfs: true,
            cap_drop: vec!["ALL".into()],
            cap_add: Vec::new(),
            privileged: false,
            security_opt: security_options(&self.manifest.isolation_profile),
            pids_limit: limits.pids_max,
            memory: limits.memory_max_bytes,
            memory_swap: limits.memory_swap_max_bytes,
            shm_size: limits.shm_size_bytes,
            nano_cpus,
            devices: Vec::new(),
            port_bindings: BTreeMap::new(),
            publish_all_ports: false,
            pid_mode: "private".into(),
            ipc_mode: "private".into(),
            uts_mode: "private".into(),
            cgroupns_mode: "private".into(),
            userns_mode: "private".into(),
            restart_policy: "no".into(),
            log_driver: "none".into(),
            network_endpoints: Vec::new(),
            labels: self.attempt_labels(),
        }
    }

    fn attempt_labels(&self) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("buzz.ci.run".into(), self.manifest.run_id.clone()),
            ("buzz.ci.sha".into(), self.manifest.sha.clone()),
            ("buzz.ci.job".into(), self.manifest.job_id.clone()),
            ("buzz.ci.attempt".into(), self.manifest.attempt.to_string()),
            (
                "buzz.ci.manifest".into(),
                self.manifest.manifest_digest.clone(),
            ),
        ])
    }

    fn container_list_response(&self) -> Result<Vec<u8>, ProxyError> {
        let name = format!(
            "/buzz-ci-{}-{}",
            &self.manifest.manifest_digest[7..23],
            self.manifest.attempt
        );
        let items = self
            .ledger
            .container_ids()
            .map(|id| {
                let running = self.ledger.is_started(id)?;
                Ok(serde_json::json!({
                    "Id": id,
                    "Names": [name.as_str()],
                    "Image": self.manifest.isolation_profile.image_digest,
                    "State": if running { "running" } else { "created" },
                    "Status": if running { "Up" } else { "Created" },
                }))
            })
            .collect::<Result<Vec<_>, ProxyError>>()?;
        serde_json::to_vec(&items).map_err(|error| ProxyError::InvalidRequest(error.to_string()))
    }

    fn allocate_operation(&mut self) -> Result<u64, ProxyError> {
        let operation = self.next_operation;
        self.next_operation = self
            .next_operation
            .checked_add(1)
            .ok_or_else(|| ProxyError::StateRefused("operation sequence exhausted".into()))?;
        Ok(operation)
    }

    fn require_created_container(&self, container_id: &str) -> Result<(), ProxyError> {
        match &self.container_lifecycle {
            ContainerLifecycle::Created {
                container_id: owned,
            } if owned == container_id => Ok(()),
            ContainerLifecycle::Created { .. } => Err(ProxyError::StateRefused(
                "start ID does not match the one created container".into(),
            )),
            ContainerLifecycle::Starting { .. } | ContainerLifecycle::Started { .. } => Err(
                ProxyError::StateRefused("container start is permitted exactly once".into()),
            ),
            _ => Err(ProxyError::StateRefused(
                "container has not completed create".into(),
            )),
        }
    }

    pub(crate) fn lifecycle_snapshot(&self) -> (crate::LifecyclePhase, Option<&str>) {
        match &self.container_lifecycle {
            ContainerLifecycle::AwaitCreate => (crate::LifecyclePhase::AwaitCreate, None),
            ContainerLifecycle::Creating { .. } => (crate::LifecyclePhase::Creating, None),
            ContainerLifecycle::Created { container_id } => {
                (crate::LifecyclePhase::Created, Some(container_id))
            }
            ContainerLifecycle::Starting { container_id } => {
                (crate::LifecyclePhase::Starting, Some(container_id))
            }
            ContainerLifecycle::Started { container_id } => {
                (crate::LifecyclePhase::Started, Some(container_id))
            }
            ContainerLifecycle::Deleting { container_id, .. } => {
                (crate::LifecyclePhase::Deleting, Some(container_id))
            }
            ContainerLifecycle::Removed { container_id } => {
                (crate::LifecyclePhase::Removed, Some(container_id))
            }
        }
    }
}

fn verify_lease_binding(
    manifest: &PolicyManifest,
    lease: &ValidatedAttemptLeaseBinding,
) -> Result<(), ProxyError> {
    let binding = lease.as_binding();
    let shared = &binding.isolation_profile;
    let local = &manifest.isolation_profile;
    let workspace_source = Path::new(&binding.workspace.path).join("source");
    if manifest.request_event_id != binding.request_event_id
        || manifest.run_id != binding.run_id
        || manifest.target_repo_a != binding.target_repo_a
        || manifest.sha != binding.source_sha
        || manifest.base_oid != binding.base_oid
        || manifest.workflow_id != binding.workflow_id
        || manifest.workflow_digest != binding.workflow_digest
        || manifest.job_id != binding.job_id
        || manifest.attempt != binding.attempt
        || manifest.lease_id != binding.lease_id
        || local.image_digest != shared.image_digest
        || local.engine_version != shared.engine_version
        || local.arch != shared.arch
        || local.seccomp_profile_path != shared.seccomp_profile_path
        || local.seccomp_profile_digest != shared.seccomp_profile_digest
        || local.netns != shared.netns
        || local.limits.memory_max_bytes != shared.limits.mem_max_bytes
        || local.limits.pids_max != u64::from(shared.limits.pids_max)
        || manifest
            .mounts
            .iter()
            .any(|mount| Path::new(&mount.source) != workspace_source)
    {
        return Err(ProxyError::InvalidManifest(
            "proxy manifest does not match the validated attempt lease".into(),
        ));
    }
    Ok(())
}

fn canonical_environment(
    input: Option<&Value>,
    manifest: &PolicyManifest,
) -> Result<Vec<Value>, ProxyError> {
    let mut values = BTreeMap::new();
    if let Some(input) = input {
        let input = input.as_array().ok_or_else(|| {
            ProxyError::InvalidRequest("Env must be an array of NAME=value strings".into())
        })?;
        if input.len() > 256 {
            return Err(ProxyError::InvalidRequest(
                "too many environment values".into(),
            ));
        }
        for value in input {
            let value = value
                .as_str()
                .ok_or_else(|| ProxyError::InvalidRequest("Env contains a non-string".into()))?;
            if value.len() > 8192 {
                return Err(ProxyError::InvalidRequest(
                    "environment value too long".into(),
                ));
            }
            let (name, _) = value.split_once('=').unwrap_or((value, ""));
            if !is_environment_name(name) {
                return Err(ProxyError::InvalidRequest(
                    "environment contains an invalid name".into(),
                ));
            }
            if RESERVED_ENVIRONMENT.contains(&name) || FORBIDDEN_ENVIRONMENT.contains(&name) {
                return Err(ProxyError::PolicyRefused(format!(
                    "workflow attempted to set reserved environment {name}"
                )));
            }
            if !manifest
                .allowed_environment
                .iter()
                .any(|allowed| allowed == name)
            {
                return Err(ProxyError::PolicyRefused(format!(
                    "environment {name} is not broker-allowlisted"
                )));
            }
            if name.is_empty() || values.insert(name.to_string(), value.to_string()).is_some() {
                return Err(ProxyError::InvalidRequest(
                    "environment contains an empty or duplicate name".into(),
                ));
            }
        }
    }
    values.insert(
        "BUZZ_CI_RUN_ID".into(),
        format!("BUZZ_CI_RUN_ID={}", manifest.run_id),
    );
    values.insert(
        "BUZZ_CI_SHA".into(),
        format!("BUZZ_CI_SHA={}", manifest.sha),
    );
    values.insert(
        "BUZZ_CI_ATTEMPT".into(),
        format!("BUZZ_CI_ATTEMPT={}", manifest.attempt),
    );
    Ok(values.into_values().map(Value::String).collect())
}

fn canonical_exec(body: &[u8], manifest: &PolicyManifest) -> Result<Vec<u8>, ProxyError> {
    if body.len() > 1024 * 1024 {
        return Err(ProxyError::InvalidRequest("exec body exceeds 1 MiB".into()));
    }
    let input: Value = serde_json::from_slice(body)
        .map_err(|error| ProxyError::InvalidRequest(error.to_string()))?;
    let object = input
        .as_object()
        .ok_or_else(|| ProxyError::InvalidRequest("exec body must be an object".into()))?;
    if object.get("Privileged").and_then(Value::as_bool) == Some(true) {
        return Err(ProxyError::PolicyRefused(
            "privileged exec is forbidden".into(),
        ));
    }
    if object.contains_key("SecurityOpt") {
        return Err(ProxyError::PolicyRefused(
            "caller may not set exec SecurityOpt".into(),
        ));
    }
    let mut output = Map::new();
    output.insert("Privileged".into(), Value::Bool(false));
    output.insert(
        "User".into(),
        Value::String(manifest.container_user.clone()),
    );
    output.insert(
        "Env".into(),
        Value::Array(canonical_environment(object.get("Env"), manifest)?),
    );
    copy_bounded_string_array(object, &mut output, "Cmd")?;
    copy_safe_string(object, &mut output, "WorkingDir", 4096)?;
    for field in ["AttachStdin", "AttachStdout", "AttachStderr", "Tty"] {
        if let Some(value @ Value::Bool(_)) = object.get(field) {
            output.insert(field.into(), value.clone());
        }
    }
    serde_json::to_vec(&Value::Object(output))
        .map_err(|error| ProxyError::InvalidRequest(error.to_string()))
}

fn reject_conflicting_host_config(host_config: Option<&Value>) -> Result<(), ProxyError> {
    let Some(host_config) = host_config else {
        return Ok(());
    };
    let object = host_config
        .as_object()
        .ok_or_else(|| ProxyError::InvalidRequest("HostConfig must be an object".into()))?;
    let forbidden = [
        "Privileged",
        "CapAdd",
        "Devices",
        "DeviceRequests",
        "PortBindings",
        "PublishAllPorts",
        "Dns",
        "DnsOptions",
        "DnsSearch",
        "ExtraHosts",
        "PidMode",
        "IpcMode",
        "UTSMode",
        "CgroupnsMode",
        "UsernsMode",
        "Runtime",
        "SecurityOpt",
        "ReadonlyRootfs",
        "NetworkMode",
        "Binds",
        "Mounts",
        "LogConfig",
        "RestartPolicy",
    ];
    if let Some(field) = forbidden
        .into_iter()
        .find(|field| object.contains_key(*field))
    {
        return Err(ProxyError::PolicyRefused(format!(
            "caller may not set security-sensitive HostConfig.{field}"
        )));
    }
    Ok(())
}

fn reject_socket_mounts(object: &Map<String, Value>) -> Result<(), ProxyError> {
    let serialized = serde_json::to_string(object)
        .map_err(|error| ProxyError::InvalidRequest(error.to_string()))?;
    if [
        "/var/run/docker.sock",
        "/run/docker.sock",
        "/podman/podman.sock",
        "policy-proxy.sock",
    ]
    .iter()
    .any(|value| serialized.contains(value))
        || object
            .values()
            .any(|value| value.as_str().is_some_and(is_socket_path))
    {
        return Err(ProxyError::PolicyRefused(
            "runtime/proxy socket exposure is forbidden".into(),
        ));
    }
    Ok(())
}

fn canonical_binds(manifest: &PolicyManifest) -> Vec<String> {
    let mut binds = manifest
        .mounts
        .iter()
        .map(|mount| format!("{}:{}:ro,Z", mount.source, mount.destination))
        .collect::<Vec<_>>();
    binds.sort();
    binds
}

fn security_options(profile: &IsolationProfile) -> Vec<String> {
    vec![
        "no-new-privileges".into(),
        "label=type:container_t".into(),
        format!("seccomp={}", profile.seccomp_profile_path),
    ]
}

fn copy_bounded_string_array(
    input: &Map<String, Value>,
    output: &mut Map<String, Value>,
    field: &str,
) -> Result<(), ProxyError> {
    let Some(value) = input.get(field) else {
        return Ok(());
    };
    let values = value
        .as_array()
        .ok_or_else(|| ProxyError::InvalidRequest(format!("{field} must be a string array")))?;
    if values.len() > 1024
        || values.iter().any(|value| {
            value
                .as_str()
                .is_none_or(|value| value.len() > 64 * 1024 || value.contains('\0'))
        })
    {
        return Err(ProxyError::InvalidRequest(format!(
            "{field} exceeds its bounds"
        )));
    }
    output.insert(field.into(), value.clone());
    Ok(())
}

fn copy_safe_string(
    input: &Map<String, Value>,
    output: &mut Map<String, Value>,
    field: &str,
    maximum: usize,
) -> Result<(), ProxyError> {
    let Some(value) = input.get(field) else {
        return Ok(());
    };
    let value = value
        .as_str()
        .ok_or_else(|| ProxyError::InvalidRequest(format!("{field} must be a string")))?;
    if value.len() > maximum || value.contains('\0') {
        return Err(ProxyError::InvalidRequest(format!(
            "{field} exceeds its bounds"
        )));
    }
    output.insert(field.into(), Value::String(value.into()));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AllowedMount, EngineKind, IsolationLimits, IsolationProfile, NetworkPolicy};
    use buzz_ci_isolation_contract::{
        AttemptLeaseBinding, BrokerObjectHandle, CgroupHandle, EngineKind as SharedEngineKind,
        IsolationProfile as SharedIsolationProfile, NetnsHandle,
        NetworkPolicy as SharedNetworkPolicy, Phase1ValidationContext, PrincipalUids, QuotaBackend,
        QuotaHandle, ResourceLimits, RuntimeEndpointIdentity, WorkspaceHandle,
    };

    fn manifest() -> PolicyManifest {
        PolicyManifest {
            schema_version: 1,
            request_event_id: "f".repeat(64),
            run_id: "018f47a2-7f0f-7cc1-9a55-01f93e42b1e0".into(),
            target_repo_a: format!("30617:{}:buzz", "e".repeat(64)),
            sha: "a".repeat(40),
            base_oid: "d".repeat(40),
            workflow_id: "required-ci".into(),
            workflow_digest: "7".repeat(64),
            job_id: "linux".into(),
            attempt: 1,
            lease_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            manifest_digest: format!("sha256:{}", "b".repeat(64)),
            isolation_profile: IsolationProfile {
                image_digest: format!("sha256:{}", "c".repeat(64)),
                engine_kind: EngineKind::Podman,
                engine_version: "5.8.4".into(),
                arch: "x86_64".into(),
                seccomp_profile_path: buzz_ci_isolation_contract::PHASE1_SECCOMP_PROFILE_PATH
                    .into(),
                seccomp_profile_digest: buzz_ci_isolation_contract::PHASE1_SECCOMP_PROFILE_DIGEST
                    .into(),
                limits: IsolationLimits {
                    cpu_quota_micros: 100_000,
                    memory_max_bytes: 1024 * 1024 * 1024,
                    memory_swap_max_bytes: 0,
                    pids_max: 512,
                    shm_size_bytes: 64 * 1024 * 1024,
                    disk_max_bytes: 2 * 1024 * 1024 * 1024,
                    timeout_seconds: 600,
                },
                network_policy: NetworkPolicy::None,
                service_requirements: Vec::new(),
                netns: "buzzci-slot-01".into(),
            },
            container_user: "65534:65534".into(),
            mounts: vec![AllowedMount {
                source: "/var/lib/buzz-ci/slots/01/source".into(),
                destination: "/workspace".into(),
                read_only: true,
            }],
            allowed_environment: vec!["CI".into()],
        }
    }

    fn create_body() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "Image": format!("sha256:{}", "c".repeat(64)),
            "Cmd": ["sh", "-c", "true"],
            "Env": ["CI=true"],
            "WorkingDir": "/workspace"
        }))
        .unwrap()
    }

    fn validated_lease() -> ValidatedAttemptLeaseBinding {
        let token = |byte: char| byte.to_string().repeat(64);
        let limits = ResourceLimits {
            cpu_weight: 100,
            mem_max_bytes: 1024 * 1024 * 1024,
            pids_max: 512,
            io_weight: 100,
        };
        AttemptLeaseBinding {
            schema_version: 1,
            request_event_id: "f".repeat(64),
            run_id: "018f47a2-7f0f-7cc1-9a55-01f93e42b1e0".into(),
            target_repo_a: format!("30617:{}:buzz", "e".repeat(64)),
            source_sha: "a".repeat(40),
            base_oid: "d".repeat(40),
            workflow_id: "required-ci".into(),
            workflow_digest: "7".repeat(64),
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
                path: "/var/lib/buzz-ci/slots/01".into(),
                object: BrokerObjectHandle {
                    token: token('1'),
                    device: 10,
                    inode: 11,
                },
                owner_uid: 991,
                quota_token: token('5'),
            },
            runtime_endpoint: RuntimeEndpointIdentity::InheritedFd {
                token: token('2'),
                owner_uid: 993,
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
                name: "buzzci-slot-01".into(),
            },
            quota: QuotaHandle {
                token: token('5'),
                backend: QuotaBackend::BoundedFilesystem,
                quota_id: "quota-01".into(),
                hard_bytes: 2 * 1024 * 1024 * 1024,
            },
            isolation_profile: SharedIsolationProfile {
                image_digest: format!("sha256:{}", "c".repeat(64)),
                engine_kind: SharedEngineKind::Podman,
                engine_version: "5.8.4".into(),
                arch: "x86_64".into(),
                seccomp_profile_path: buzz_ci_isolation_contract::PHASE1_SECCOMP_PROFILE_PATH
                    .into(),
                seccomp_profile_digest: buzz_ci_isolation_contract::PHASE1_SECCOMP_PROFILE_DIGEST
                    .into(),
                limits,
                network_policy: SharedNetworkPolicy::None,
                service_requirements: Vec::new(),
                netns: "buzzci-slot-01".into(),
            },
        }
        .validate_phase1(&Phase1ValidationContext {
            now_unix_seconds: 1_000,
            max_expiry_horizon_seconds: 300,
            forbidden_host_uids: &[],
            expected_engine_version: "5.8.4",
            expected_arch: "x86_64",
        })
        .unwrap()
    }

    #[test]
    fn production_install_requires_the_same_validated_attempt_lease() {
        let lease = validated_lease();
        let policy = ProxyPolicy::install(manifest(), &lease).unwrap();
        assert_eq!(policy.executor_uid(), 992);
        assert_eq!(policy.runtime_uid(), 993);

        let mut mismatches = Vec::new();
        let mut request = manifest();
        request.request_event_id = "1".repeat(64);
        mismatches.push(request);
        let mut repo = manifest();
        repo.target_repo_a = format!("30617:{}:other", "e".repeat(64));
        mismatches.push(repo);
        let mut tip = manifest();
        tip.sha = "1".repeat(40);
        mismatches.push(tip);
        let mut base = manifest();
        base.base_oid = "1".repeat(40);
        mismatches.push(base);
        let mut workflow = manifest();
        workflow.workflow_id = "other".into();
        mismatches.push(workflow);
        let mut workflow_digest = manifest();
        workflow_digest.workflow_digest = "1".repeat(64);
        mismatches.push(workflow_digest);
        let mut job = manifest();
        job.job_id = "other".into();
        mismatches.push(job);
        let mut attempt = manifest();
        attempt.attempt = 2;
        mismatches.push(attempt);
        let mut lease_id = manifest();
        lease_id.lease_id = "01ARZ3NDEKTSV4RRFFQ69G5FAA".into();
        mismatches.push(lease_id);
        assert!(mismatches
            .into_iter()
            .all(|manifest| ProxyPolicy::install(manifest, &lease).is_err()));

        let mut wrong_mount = manifest();
        wrong_mount.mounts[0].source = "/var/lib/buzz-ci/slots/other/source".into();
        assert!(ProxyPolicy::install(wrong_mount, &lease).is_err());
    }

    #[test]
    fn canonical_create_injects_every_load_bearing_control() {
        let mut policy = ProxyPolicy::install_for_test(manifest()).unwrap();
        let Admission::Create(create) = policy
            .admit(
                DockerMethod::Post,
                "/v1.47/containers/create",
                &create_body(),
            )
            .unwrap()
        else {
            panic!("expected create");
        };
        let value: Value = serde_json::from_slice(&create.body).unwrap();
        assert_eq!(value["HostConfig"]["NetworkMode"], "none");
        assert_eq!(value["HostConfig"]["ReadonlyRootfs"], true);
        assert_eq!(value["HostConfig"]["CapDrop"], serde_json::json!(["ALL"]));
        assert_eq!(value["HostConfig"]["Privileged"], false);
        assert_eq!(
            value["HostConfig"]["SecurityOpt"],
            serde_json::json!([
                "no-new-privileges",
                "label=type:container_t",
                format!(
                    "seccomp={}",
                    buzz_ci_isolation_contract::PHASE1_SECCOMP_PROFILE_PATH
                )
            ])
        );
        assert_eq!(value["HostConfig"]["LogConfig"]["Type"], "none");
        assert_eq!(value["HostConfig"]["NanoCpus"], 1_000_000_000_u64);
        assert_eq!(
            create.target,
            format!("/containers/create?name=buzz-ci-{}-1", "b".repeat(16))
        );
        let env = value["Env"].as_array().unwrap();
        assert!(env.iter().any(|value| value == "BUZZ_CI_ATTEMPT=1"));
        assert!(!create.fingerprint.is_empty());
    }

    #[test]
    fn hostile_security_fields_never_reach_admission() {
        let fields = [
            ("Privileged", serde_json::json!(true)),
            ("NetworkMode", serde_json::json!("host")),
            ("Binds", serde_json::json!(["/var/run/docker.sock:/d.sock"])),
            ("CapAdd", serde_json::json!(["SYS_ADMIN"])),
            ("SecurityOpt", serde_json::json!(["seccomp=unconfined"])),
            (
                "SecurityOpt",
                serde_json::json!(["unknown-security-option"]),
            ),
        ];
        for (field, value) in fields {
            let mut body = serde_json::json!({
                "Image": format!("sha256:{}", "c".repeat(64)),
                "HostConfig": {}
            });
            body["HostConfig"][field] = value;
            let mut policy = ProxyPolicy::install_for_test(manifest()).unwrap();
            assert!(policy
                .admit(
                    DockerMethod::Post,
                    "/containers/create",
                    &serde_json::to_vec(&body).unwrap()
                )
                .is_err());
        }
        for security_opt in ["seccomp=unconfined", "unknown-security-option"] {
            let body = serde_json::json!({
                "Image": format!("sha256:{}", "c".repeat(64)),
                "SecurityOpt": [security_opt]
            });
            let mut policy = ProxyPolicy::install_for_test(manifest()).unwrap();
            assert!(matches!(
                policy.admit(
                    DockerMethod::Post,
                    "/containers/create",
                    &serde_json::to_vec(&body).unwrap()
                ),
                Err(ProxyError::PolicyRefused(_))
            ));
        }
    }

    #[test]
    fn container_list_projects_only_attempt_owned_state() {
        let mut policy = ProxyPolicy::install_for_test(manifest()).unwrap();
        let Admission::Create(create) = policy
            .admit(DockerMethod::Post, "/containers/create", &create_body())
            .unwrap()
        else {
            panic!("expected create admission");
        };
        policy
            .record_created("container-one".into(), &create)
            .unwrap();

        let Admission::LocalResponse(body) = policy
            .admit(DockerMethod::Get, "/containers/json?all=1", &[])
            .unwrap()
        else {
            panic!("expected local container list");
        };
        let list: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(list.as_array().unwrap().len(), 1);
        assert_eq!(list[0]["Id"], "container-one");
        assert_eq!(list[0]["State"], "created");
        assert_eq!(list[0].as_object().unwrap().len(), 5);
    }

    #[test]
    fn pull_build_network_and_archive_are_explicitly_denied() {
        let cases = [
            (DockerMethod::Post, "/images/create"),
            (DockerMethod::Post, "/build"),
            (DockerMethod::Post, "/networks/create"),
            (DockerMethod::Get, "/containers/id/archive?path=/tmp/x"),
        ];
        for (method, path) in cases {
            let mut policy = ProxyPolicy::install_for_test(manifest()).unwrap();
            assert!(matches!(
                policy.admit(method, path, b""),
                Err(ProxyError::PolicyRefused(_)) | Err(ProxyError::StateRefused(_))
            ));
        }
    }

    #[test]
    fn reserved_environment_cannot_be_overridden() {
        let mut body: Value = serde_json::from_slice(&create_body()).unwrap();
        body["Env"] = serde_json::json!(["BUZZ_CI_SHA=evil"]);
        let mut policy = ProxyPolicy::install_for_test(manifest()).unwrap();
        assert!(matches!(
            policy.admit(
                DockerMethod::Post,
                "/containers/create",
                &serde_json::to_vec(&body).unwrap()
            ),
            Err(ProxyError::PolicyRefused(_))
        ));
    }

    #[test]
    fn environment_is_empty_by_default_and_exactly_allowlisted() {
        let mut restricted = manifest();
        restricted.allowed_environment.clear();
        let mut policy = ProxyPolicy::install_for_test(restricted).unwrap();
        assert!(matches!(
            policy.admit(DockerMethod::Post, "/containers/create", &create_body()),
            Err(ProxyError::PolicyRefused(_))
        ));
    }

    #[test]
    fn start_requires_complete_pre_start_proof() {
        let mut policy = ProxyPolicy::install_for_test(manifest()).unwrap();
        let Admission::Create(create) = policy
            .admit(DockerMethod::Post, "/containers/create", &create_body())
            .unwrap()
        else {
            panic!("expected create");
        };
        policy
            .record_created("container-1".into(), &create)
            .unwrap();
        assert!(matches!(
            policy
                .admit(DockerMethod::Post, "/containers/container-1/start", b"")
                .unwrap(),
            Admission::NeedsPreStartProof { .. }
        ));
        let mut effective = policy.expected_effective_spec();
        effective.network_mode = "host".into();
        assert!(policy.verify_pre_start("container-1", &effective).is_err());
        let mut effective = policy.expected_effective_spec();
        effective.nano_cpus = 0;
        assert!(policy.verify_pre_start("container-1", &effective).is_err());
        let mut effective = policy.expected_effective_spec();
        effective.devices.push("/dev/kvm".into());
        assert!(policy.verify_pre_start("container-1", &effective).is_err());
        let mut effective = policy.expected_effective_spec();
        effective.security_opt.pop();
        assert!(policy.verify_pre_start("container-1", &effective).is_err());
        let mut effective = policy.expected_effective_spec();
        effective.security_opt[2] = "seccomp=unconfined".into();
        assert!(policy.verify_pre_start("container-1", &effective).is_err());
        let mut effective = policy.expected_effective_spec();
        effective
            .security_opt
            .push("unknown-security-option".into());
        assert!(policy.verify_pre_start("container-1", &effective).is_err());
        let effective = policy.expected_effective_spec();
        let proof = policy.verify_pre_start("container-1", &effective).unwrap();
        policy.begin_start(&proof).unwrap();
        policy.commit_started(&proof).unwrap();

        for security_opt in ["seccomp=unconfined", "unknown-security-option"] {
            let body = serde_json::to_vec(&serde_json::json!({
                "Cmd": ["true"],
                "SecurityOpt": [security_opt]
            }))
            .unwrap();
            assert!(matches!(
                policy.admit(DockerMethod::Post, "/containers/container-1/exec", &body),
                Err(ProxyError::PolicyRefused(_))
            ));
        }
    }

    #[test]
    fn verified_start_is_bound_to_its_canonical_create() {
        let mut first = ProxyPolicy::install_for_test(manifest()).unwrap();
        let Admission::Create(first_create) = first
            .admit(DockerMethod::Post, "/containers/create", &create_body())
            .unwrap()
        else {
            panic!("expected create");
        };
        first
            .record_created("container-1".into(), &first_create)
            .unwrap();
        let proof = first
            .verify_pre_start("container-1", &first.expected_effective_spec())
            .unwrap();
        assert!(proof.matches_create(&first_create));

        let mut changed = manifest();
        changed.job_id = "different-job".into();
        let mut second = ProxyPolicy::install_for_test(changed).unwrap();
        let Admission::Create(other_create) = second
            .admit(DockerMethod::Post, "/containers/create", &create_body())
            .unwrap()
        else {
            panic!("expected create");
        };
        assert!(!proof.matches_create(&other_create));
    }

    #[test]
    fn failed_start_and_delete_do_not_advance_the_ledger() {
        let mut policy = ProxyPolicy::install_for_test(manifest()).unwrap();
        let Admission::Create(create) = policy
            .admit(
                DockerMethod::Post,
                "/containers/create?name=caller",
                &create_body(),
            )
            .unwrap()
        else {
            panic!("expected create");
        };
        policy
            .record_created("container-1".into(), &create)
            .unwrap();
        assert!(matches!(
            policy.record_created("container-2".into(), &create),
            Err(ProxyError::StateRefused(_))
        ));
        let effective = policy.expected_effective_spec();
        let proof = policy.verify_pre_start("container-1", &effective).unwrap();

        // Simulate an upstream start failure: without commit, exec remains
        // forbidden even though pre-start inspection succeeded.
        assert!(matches!(
            policy.admit(
                DockerMethod::Post,
                "/containers/container-1/exec",
                br#"{"Cmd":["true"]}"#
            ),
            Err(ProxyError::StateRefused(_))
        ));
        policy.begin_start(&proof).unwrap();
        policy.commit_started(&proof).unwrap();

        // Admission alone is prepare-only. A failed upstream delete leaves the
        // object owned and retryable.
        assert!(matches!(
            policy
                .admit(
                    DockerMethod::Delete,
                    "/containers/container-1?force=true",
                    b""
                )
                .unwrap(),
            Admission::Delete { .. }
        ));
        assert!(policy
            .admit(DockerMethod::Get, "/containers/container-1/json", b"")
            .is_ok());
        policy.commit_deleted("container-1").unwrap();
        assert!(policy
            .admit(DockerMethod::Get, "/containers/container-1/json", b"")
            .is_err());
    }

    #[test]
    fn container_enumeration_is_local_and_never_forwarded() {
        let mut policy = ProxyPolicy::install_for_test(manifest()).unwrap();
        assert!(matches!(
            policy.admit(DockerMethod::Get, "/containers/json?all=true", b""),
            Ok(Admission::LocalResponse(_))
        ));
    }

    #[test]
    fn terminal_barrier_refuses_every_executor_request() {
        let mut policy = ProxyPolicy::install_for_test(manifest()).unwrap();
        policy.begin_seal().unwrap();
        policy.finish_seal().unwrap();
        assert!(policy.admit(DockerMethod::Get, "/_ping", b"").is_err());
    }

    #[test]
    fn pending_upstream_mutation_blocks_seal_until_aborted() {
        let mut policy = ProxyPolicy::install_for_test(manifest()).unwrap();
        let Admission::Create(create) = policy
            .admit(DockerMethod::Post, "/containers/create", &create_body())
            .unwrap()
        else {
            panic!("expected create");
        };
        assert!(policy.begin_seal().is_err());
        policy.abort_create(&create).unwrap();
        policy.begin_seal().unwrap();
        policy.finish_seal().unwrap();
    }

    #[test]
    fn terminal_barrier_uses_committed_ledger_state() {
        let mut policy = ProxyPolicy::install_for_test(manifest()).unwrap();
        let Admission::Create(create) = policy
            .admit(DockerMethod::Post, "/containers/create", &create_body())
            .unwrap()
        else {
            panic!("expected create");
        };
        policy
            .record_created("container-1".into(), &create)
            .unwrap();
        let proof = policy
            .verify_pre_start("container-1", &policy.expected_effective_spec())
            .unwrap();
        policy.begin_start(&proof).unwrap();
        policy.commit_started(&proof).unwrap();
        policy.begin_seal().unwrap();
        assert!(policy.finish_seal().is_err());
        policy.commit_stopped("container-1").unwrap();
        policy.finish_seal().unwrap();
    }
}
