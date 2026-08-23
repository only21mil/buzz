//! Broker-owned policy proxy and rootless Podman lease lifecycle.
//!
//! The builder accepts only an authenticated ordinary admission, its opaque
//! lease token, and a root-validated isolation binding. It creates the proxy
//! listener itself and binds one inherited rootless-runtime descriptor to the
//! resulting capability. The pre-start observer persists seccomp and evidence
//! before the transport can forward Podman's start request.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use buzz_ci_broker_protocol::GitOid;
use buzz_ci_isolation_contract::ValidatedAttemptLeaseBinding;
use buzz_ci_policy_proxy::{
    Admission, CanonicalCreate, DockerMethod, EffectiveContainerSpec, InheritedOneShotConnector,
    InheritedProxy, OneShotUpstreamConnector, PolicyManifest, PreStartObserver, ProxyError,
    ProxyPolicy, TransportLimits, UpstreamCapability, VerifiedStart,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::activation::{AdmissionTrustClass, LeaseToken, OrdinaryAdmission};
use crate::evidence::{
    self, CanonicalCreateRequest, CanonicalExecRequest, CiEventBinding, Digest32,
    EffectiveSpecProof, EvidenceStore, OrderingEvent, OrderingRecord, ProxyDecisionReason,
    ProxyDecisionRecord, ProxyObjectRecord, ProxyRoute, ProxyVerdict,
};
use crate::seccomp_activation::SeccompInstallCapability;
use crate::seccomp_exec::{persist_oci_prestart_observation, SeccompExecError};

const LISTENER_MODE: u32 = 0o660;
const MAX_LEASE_OBJECTS: usize = 32;
const MAX_PODMAN_HEADER_BYTES: usize = 32 * 1024;
const MAX_PODMAN_HEADER_COUNT: usize = 64;

/// Immutable broker-owned paths and evidence facts for one policy proxy.
#[derive(Clone, Debug)]
pub struct ProxyLeaseAuthority {
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

impl ProxyLeaseAuthority {
    /// Construct root-owned authority. The exec request is retained as planned
    /// evidence only; C5 never invokes it.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
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
    ) -> Result<Self, ProxyLeaseError> {
        if !listener_root.is_absolute()
            || !evidence_root.is_absolute()
            || !bundle.is_absolute()
            || !pid_file.is_absolute()
            || !exec_working_directory.is_absolute()
            || exec_argv.is_empty()
            || exec_uid == 0
            || exec_gid == 0
            || listener_gid == 0
            || event_binding.request_event_id_46105 == [0; 32]
            || event_binding.teardown_event_id_46106 == [0; 32]
        {
            return Err(ProxyLeaseError::Authority);
        }
        Ok(Self {
            listener_root,
            evidence_root,
            event_binding,
            bundle,
            pid_file,
            exec_argv,
            exec_working_directory,
            exec_uid,
            exec_gid,
            listener_gid,
        })
    }
}

/// Persists the retained C2 seccomp capability before Podman start.
pub trait PrestartPersister {
    /// Persist and reopen the exact verified create/effective-spec observation.
    fn persist(
        &mut self,
        admission: &OrdinaryAdmission,
        lease: LeaseToken,
        create: &CanonicalCreate,
        proof: &VerifiedStart,
        effective: &EffectiveContainerSpec,
    ) -> Result<(), SeccompExecError>;
}

impl PrestartPersister for SeccompInstallCapability {
    fn persist(
        &mut self,
        admission: &OrdinaryAdmission,
        lease: LeaseToken,
        create: &CanonicalCreate,
        proof: &VerifiedStart,
        effective: &EffectiveContainerSpec,
    ) -> Result<(), SeccompExecError> {
        persist_oci_prestart_observation(
            self.receipt(),
            admission,
            lease,
            create,
            proof,
            effective,
        )?;
        Ok(())
    }
}

/// Source of strictly increasing evidence timestamps.
pub trait ProxyClock {
    /// Return the next nonzero Unix timestamp in nanoseconds.
    fn now_ns(&mut self) -> Result<u64, ProxyLeaseError>;
}

/// Production wall clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemProxyClock;

impl ProxyClock for SystemProxyClock {
    fn now_ns(&mut self) -> Result<u64, ProxyLeaseError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ProxyLeaseError::Clock)?
            .as_nanos()
            .try_into()
            .map_err(|_| ProxyLeaseError::Clock)
    }
}

/// C5 observer installed directly in [`InheritedProxy`].
pub struct ProxyLeaseObserver<P, C = SystemProxyClock> {
    admission: OrdinaryAdmission,
    lease: LeaseToken,
    lease_id: String,
    authority: ProxyLeaseAuthority,
    store: EvidenceStore,
    persister: P,
    clock: C,
    started_object: Option<String>,
}

impl<P: PrestartPersister> ProxyLeaseObserver<P, SystemProxyClock> {
    fn production(
        admission: OrdinaryAdmission,
        lease: LeaseToken,
        lease_id: String,
        authority: ProxyLeaseAuthority,
        persister: P,
    ) -> Result<Self, ProxyLeaseError> {
        let store = EvidenceStore::new(authority.evidence_root.clone())?;
        Ok(Self {
            admission,
            lease,
            lease_id,
            authority,
            store,
            persister,
            clock: SystemProxyClock,
            started_object: None,
        })
    }
}

impl<P: PrestartPersister, C: ProxyClock> PreStartObserver for ProxyLeaseObserver<P, C> {
    fn observe_pre_start(
        &mut self,
        create: &CanonicalCreate,
        container_id: &str,
        effective: &EffectiveContainerSpec,
        proof: &VerifiedStart,
    ) -> Result<(), ProxyError> {
        if self.started_object.is_some() {
            return Err(ProxyError::StateRefused(
                "pre-start observer may bind only one object".into(),
            ));
        }
        self.persister
            .persist(&self.admission, self.lease, create, proof, effective)
            .map_err(|_| ProxyError::Transport("seccomp pre-start persistence failed".into()))?;
        let recorded_at = self
            .clock
            .now_ns()
            .map_err(|_| ProxyError::Transport("proxy evidence clock failed".into()))?;
        self.record_allowed_decisions(create, container_id, recorded_at)
            .map_err(|_| ProxyError::Transport("proxy decision evidence failed".into()))?;
        self.record_object(create, container_id, effective, recorded_at)
            .map_err(|_| ProxyError::Transport("proxy object evidence failed".into()))?;
        self.store
            .append_ordering(&OrderingRecord {
                lease_id: self.lease_id.clone(),
                sequence: 1,
                event_binding: self.authority.event_binding,
                event: OrderingEvent::ProxyObjectRecorded,
                object_id: Some(container_id.to_owned()),
                timestamp_unix_ns: recorded_at,
                status_event_id: None,
                verdict_event_id: None,
            })
            .map_err(|_| ProxyError::Transport("proxy pre-start ordering failed".into()))?;
        self.started_object = Some(container_id.to_owned());
        Ok(())
    }

    fn observe_started(&mut self, container_id: &str) -> Result<(), ProxyError> {
        if self.started_object.as_deref() != Some(container_id) {
            return Err(ProxyError::StateRefused(
                "start does not match persisted pre-start evidence".into(),
            ));
        }
        let timestamp = self
            .clock
            .now_ns()
            .map_err(|_| ProxyError::Transport("proxy evidence clock failed".into()))?;
        self.store
            .append_ordering(&OrderingRecord {
                lease_id: self.lease_id.clone(),
                sequence: 2,
                event_binding: self.authority.event_binding,
                event: OrderingEvent::Start,
                object_id: Some(container_id.to_owned()),
                timestamp_unix_ns: timestamp,
                status_event_id: None,
                verdict_event_id: None,
            })
            .map_err(|_| ProxyError::Transport("proxy start ordering failed".into()))
    }
}

impl<P, C> ProxyLeaseObserver<P, C> {
    fn record_allowed_decisions(
        &self,
        create: &CanonicalCreate,
        container_id: &str,
        timestamp: u64,
    ) -> Result<(), evidence::PublicationError> {
        for (sequence, route, method, target, hash) in [
            (
                1,
                ProxyRoute::ContainerCreate,
                evidence::DockerMethod::Post,
                create.target.clone(),
                sha256_hex(&create.body),
            ),
            (
                2,
                ProxyRoute::ContainerStart,
                evidence::DockerMethod::Post,
                format!("/containers/{container_id}/start"),
                sha256_hex(format!("{container_id}\0start").as_bytes()),
            ),
        ] {
            self.store.append_proxy_decision(&ProxyDecisionRecord {
                schema_version: 1,
                lease_id: self.lease_id.clone(),
                sequence,
                route,
                verdict: ProxyVerdict::Allowed,
                reason: ProxyDecisionReason::PolicyAllowed,
                request_hash: hash,
                method,
                target,
                decided_at_unix_ns: timestamp,
            })?;
        }
        Ok(())
    }

    fn record_object(
        &self,
        create: &CanonicalCreate,
        container_id: &str,
        effective: &EffectiveContainerSpec,
        timestamp: u64,
    ) -> Result<(), evidence::PublicationError> {
        let rebuilt_create = CanonicalCreateRequest {
            container_id: container_id.to_owned(),
            bundle: self.authority.bundle.clone(),
            pid_file: self.authority.pid_file.clone(),
            rootfs_read_only: true,
            no_new_privileges: true,
            network_disabled: true,
            seccomp_profile_path: PathBuf::from(evidence::SECCOMP_PROFILE_PATH),
        };
        let rebuilt_exec = CanonicalExecRequest {
            container_id: container_id.to_owned(),
            argv: self.authority.exec_argv.clone(),
            clear_environment: true,
            working_directory: self.authority.exec_working_directory.clone(),
            uid: self.authority.exec_uid,
            gid: self.authority.exec_gid,
        };
        let evidence_spec = evidence::EffectiveContainerSpec {
            user: effective.user.clone(),
            userns_mode: effective.userns_mode.clone(),
            cap_drop: effective.cap_drop.clone(),
            security_opt: effective.security_opt.clone(),
            network_mode: effective.network_mode.clone(),
            image: effective.image.clone(),
            binds: effective.binds.iter().map(PathBuf::from).collect(),
            log_driver: effective.log_driver.clone(),
            artifact_server_enabled: false,
            persistent_logs: false,
            nano_cpus: effective.nano_cpus,
            memory: effective.memory,
            pids_limit: effective.pids_limit,
        };
        let environment = BTreeMap::from([
            (
                "BUZZ_CI_RUN_ID".into(),
                Uuid::from_bytes(self.admission.run_id).to_string(),
            ),
            ("BUZZ_CI_SHA".into(), oid_hex(self.admission.job.source_oid)),
            ("BUZZ_CI_ATTEMPT".into(), self.admission.attempt.to_string()),
        ]);
        let rebuilt_create_bytes = serde_json::to_vec(&rebuilt_create)?;
        let rebuilt_exec_bytes = serde_json::to_vec(&rebuilt_exec)?;
        let effective_bytes = serde_json::to_vec(&evidence_spec)?;
        self.store.publish_proxy_object(&ProxyObjectRecord {
            lease_id: self.lease_id.clone(),
            sequence: 1,
            object_id: container_id.to_owned(),
            rebuilt_create_request: rebuilt_create,
            rebuilt_exec_request: rebuilt_exec,
            environment,
            effective_spec: evidence_spec,
            proof: EffectiveSpecProof {
                source_request_sha256: digest32(&create.body),
                rebuilt_create_sha256: digest32(&rebuilt_create_bytes),
                rebuilt_exec_sha256: digest32(&rebuilt_exec_bytes),
                effective_spec_sha256: digest32(&effective_bytes),
                seccomp_profile_sha256: fixed_seccomp_digest()?,
                recorded_before_unit_start: true,
            },
            image_digest: effective.image.clone(),
            recorded_at_ns: timestamp,
        })
    }
}

/// Broker-owned descriptor bundle for one authenticated proxy exchange.
pub struct BrokerProxyLease<P: PrestartPersister> {
    listener_path: PathBuf,
    lease: LeaseToken,
    capability: UpstreamCapability,
    proxy: InheritedProxy<InheritedOneShotConnector, ProxyLeaseObserver<P>>,
}

impl<P: PrestartPersister> BrokerProxyLease<P> {
    /// Return the executor-visible broker socket path.
    pub fn listener_path(&self) -> &Path {
        &self.listener_path
    }

    /// Serve the single exchange authorized by the inherited upstream descriptor.
    pub fn serve_once(&mut self) -> Result<(), ProxyError> {
        self.proxy.serve_once()
    }

    /// Report whether ambiguous upstream state requires reconciliation.
    pub fn is_poisoned(&self) -> bool {
        self.proxy.is_poisoned()
    }

    /// Authenticate the next one-shot Podman descriptor without resetting the
    /// canonical create ledger or pre-start evidence state.
    pub fn replace_upstream(
        &mut self,
        lease: LeaseToken,
        upstream: UnixStream,
    ) -> Result<(), ProxyLeaseError> {
        if lease != self.lease {
            return Err(ProxyLeaseError::DescriptorIdentity);
        }
        self.proxy.replace_inherited_upstream(upstream)?;
        Ok(())
    }

    /// Stop and delete every retained object, prove an empty inventory, then
    /// remove the broker-owned executor listener.
    pub fn reconcile<R: PodmanReconcileRunner>(
        &mut self,
        lease: LeaseToken,
        runner: &mut R,
        retained_ids: &BTreeSet<String>,
    ) -> Result<(), ProxyLeaseError> {
        if lease != self.lease {
            return Err(ProxyLeaseError::DescriptorIdentity);
        }
        reconcile_podman_objects(runner, &self.capability, retained_ids)?;
        fs::remove_file(&self.listener_path)?;
        Ok(())
    }
}

/// One authenticated rootless Podman descriptor acquisition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PodmanLaunchOperation {
    /// Canonical container creation on a fresh descriptor.
    Create,
    /// Fresh inspection followed by start of the exact created object.
    InspectStart {
        /// Full runtime object ID returned by create.
        object_id: String,
    },
}

/// Typed refusal while acquiring a one-shot rootless Podman descriptor.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum PodmanDescriptorError {
    /// The descriptor, peer, or capability does not match the lease.
    #[error("Podman descriptor identity refused")]
    Identity,
    /// The authenticated descriptor transport failed closed.
    #[error("Podman descriptor transport failed")]
    Transport,
}

/// Trusted source of one authenticated descriptor per launch operation.
///
/// Implementors consume a broker-authenticated capability channel. They must
/// never resolve an executor-provided socket path, URL, or environment value.
pub trait PodmanLaunchDescriptorSource {
    /// Acquire a descriptor bound to the exact lease and operation.
    fn acquire(
        &mut self,
        capability: &UpstreamCapability,
        operation: &PodmanLaunchOperation,
    ) -> Result<InheritedOneShotConnector, PodmanDescriptorError>;
}

/// Broker-owned capability for canonical create and authenticated pre-start.
///
/// The first descriptor carries only canonical create. A second descriptor
/// carries fresh inspect and, only after the observer persists the exact
/// effective specification, start. Any ambiguity after create leaves the
/// capability poisoned with the object ID retained for reconciliation.
pub struct BrokerPodmanLaunch<P: PrestartPersister, S: PodmanLaunchDescriptorSource> {
    lease: LeaseToken,
    capability: UpstreamCapability,
    policy: ProxyPolicy,
    observer: ProxyLeaseObserver<P>,
    source: S,
    limits: TransportLimits,
    retained_object_id: Option<String>,
    consumed: bool,
    poisoned: bool,
}

impl<P: PrestartPersister, S: PodmanLaunchDescriptorSource> BrokerPodmanLaunch<P, S> {
    /// Canonicalize create, verify a fresh inspect, persist the observation,
    /// and then issue start on the same authenticated descriptor.
    pub fn create_inspect_persist_start(
        &mut self,
        lease: LeaseToken,
        requested_create: &[u8],
    ) -> Result<String, ProxyLeaseError> {
        if lease != self.lease {
            return Err(ProxyLeaseError::DescriptorIdentity);
        }
        if self.consumed || self.poisoned {
            return Err(ProxyLeaseError::LaunchState);
        }
        self.consumed = true;
        if requested_create.len() > self.limits.request_body_bytes {
            return Err(ProxyLeaseError::Create);
        }
        let create =
            match self
                .policy
                .admit(DockerMethod::Post, "/containers/create", requested_create)?
            {
                Admission::Create(create) => create,
                _ => return Err(ProxyLeaseError::LaunchState),
            };
        if create.body.len() > self.limits.request_body_bytes {
            self.policy.abort_create(&create)?;
            return Err(ProxyLeaseError::Create);
        }

        let create_response = match launch_exchange(
            &mut self.source,
            &self.capability,
            &PodmanLaunchOperation::Create,
            DockerMethod::Post,
            &create.target,
            &create.body,
            self.limits,
        ) {
            Ok(response) => response,
            Err(error) => {
                let _ = self.policy.abort_create(&create);
                self.poisoned = true;
                return Err(error);
            }
        };
        if !create_response.success() {
            self.policy.abort_create(&create)?;
            return Err(ProxyLeaseError::Create);
        }
        let object_id = match podman_object_id(&create_response.body) {
            Ok(object_id) => object_id,
            Err(error) => {
                self.poisoned = true;
                return Err(error);
            }
        };
        self.retained_object_id = Some(object_id.clone());
        if self
            .policy
            .record_created(object_id.clone(), &create)
            .is_err()
        {
            self.poisoned = true;
            return Err(ProxyLeaseError::Create);
        }

        if let Err(error) = self.inspect_persist_start(&create, &object_id) {
            self.poisoned = true;
            return Err(error);
        }
        Ok(object_id)
    }

    /// Whether runtime state is ambiguous and cleanup is mandatory.
    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Exact created object retained for later reconciliation.
    pub fn retained_object_id(&self) -> Option<&str> {
        self.retained_object_id.as_deref()
    }

    /// Reconcile the exact retained object through the existing bounded path.
    pub fn reconcile<R: PodmanReconcileRunner>(
        &mut self,
        lease: LeaseToken,
        runner: &mut R,
    ) -> Result<(), ProxyLeaseError> {
        if lease != self.lease {
            return Err(ProxyLeaseError::DescriptorIdentity);
        }
        let object_id = self
            .retained_object_id
            .clone()
            .ok_or(ProxyLeaseError::LaunchState)?;
        reconcile_podman_objects(runner, &self.capability, &BTreeSet::from([object_id]))?;
        self.retained_object_id = None;
        Ok(())
    }

    fn inspect_persist_start(
        &mut self,
        create: &CanonicalCreate,
        object_id: &str,
    ) -> Result<(), ProxyLeaseError> {
        let operation = PodmanLaunchOperation::InspectStart {
            object_id: object_id.to_owned(),
        };
        let mut connector = self
            .source
            .acquire(&self.capability, &operation)
            .map_err(descriptor_error)?;
        let mut upstream = connector
            .connect(&self.capability)
            .map_err(|_| ProxyLeaseError::DescriptorIdentity)?;
        configure_podman_stream(&upstream, self.limits)?;

        let inspect = exchange_connected(
            &mut upstream,
            DockerMethod::Get,
            &format!("/containers/{object_id}/json"),
            &[],
            self.limits.response_body_bytes,
        )
        .map_err(|_| ProxyLeaseError::Inspect)?;
        if !inspect.success() {
            return Err(ProxyLeaseError::Inspect);
        }
        let effective =
            decode_podman_effective_spec(&inspect.body).map_err(|_| ProxyLeaseError::Inspect)?;
        let proof = self
            .policy
            .verify_pre_start(object_id, &effective)
            .map_err(|_| ProxyLeaseError::Inspect)?;
        let retained_create = self
            .policy
            .created_request(object_id)
            .map_err(|_| ProxyLeaseError::Inspect)?;
        if retained_create != create {
            return Err(ProxyLeaseError::Inspect);
        }
        self.observer
            .observe_pre_start(create, object_id, &effective, &proof)?;

        let start = exchange_connected(
            &mut upstream,
            DockerMethod::Post,
            &format!("/containers/{object_id}/start"),
            &[],
            self.limits.response_body_bytes,
        )
        .map_err(|_| ProxyLeaseError::Start)?;
        if !start.success() || !start.body.is_empty() {
            return Err(ProxyLeaseError::Start);
        }
        self.policy
            .commit_started(&proof)
            .map_err(|_| ProxyLeaseError::Start)?;
        self.observer
            .observe_started(object_id)
            .map_err(|_| ProxyLeaseError::Start)
    }
}

/// Build the broker-owned launch capability from authenticated authority.
#[allow(clippy::too_many_arguments)]
pub fn build_broker_podman_launch<P, S>(
    authority: ProxyLeaseAuthority,
    admission: OrdinaryAdmission,
    lease: LeaseToken,
    validated: &ValidatedAttemptLeaseBinding,
    manifest: PolicyManifest,
    source: S,
    persister: P,
    limits: TransportLimits,
) -> Result<BrokerPodmanLaunch<P, S>, ProxyLeaseError>
where
    P: PrestartPersister,
    S: PodmanLaunchDescriptorSource,
{
    validate_authenticated_binding(admission, lease, validated, &manifest)?;
    if limits.request_body_bytes == 0
        || limits.response_body_bytes == 0
        || limits.io_timeout.is_zero()
    {
        return Err(ProxyLeaseError::Authority);
    }
    let policy = ProxyPolicy::install(manifest, validated)?;
    let capability = UpstreamCapability::from_validated_lease(validated);
    if capability.lease_id() != validated.as_binding().lease_id {
        return Err(ProxyLeaseError::DescriptorIdentity);
    }
    let observer = ProxyLeaseObserver::production(
        admission,
        lease,
        validated.as_binding().lease_id.clone(),
        authority,
        persister,
    )?;
    Ok(BrokerPodmanLaunch {
        lease,
        capability,
        policy,
        observer,
        source,
        limits,
        retained_object_id: None,
        consumed: false,
        poisoned: false,
    })
}

struct PodmanHttpResponse {
    status: u16,
    body: Vec<u8>,
}

impl PodmanHttpResponse {
    fn success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

fn launch_exchange<S: PodmanLaunchDescriptorSource>(
    source: &mut S,
    capability: &UpstreamCapability,
    operation: &PodmanLaunchOperation,
    method: DockerMethod,
    target: &str,
    body: &[u8],
    limits: TransportLimits,
) -> Result<PodmanHttpResponse, ProxyLeaseError> {
    let mut connector = source
        .acquire(capability, operation)
        .map_err(descriptor_error)?;
    let mut upstream = connector
        .connect(capability)
        .map_err(|_| ProxyLeaseError::DescriptorIdentity)?;
    configure_podman_stream(&upstream, limits)?;
    exchange_connected(
        &mut upstream,
        method,
        target,
        body,
        limits.response_body_bytes,
    )
    .map_err(|_| ProxyLeaseError::Create)
}

fn descriptor_error(error: PodmanDescriptorError) -> ProxyLeaseError {
    match error {
        PodmanDescriptorError::Identity => ProxyLeaseError::DescriptorIdentity,
        PodmanDescriptorError::Transport => ProxyLeaseError::DescriptorTransport,
    }
}

fn configure_podman_stream(
    stream: &UnixStream,
    limits: TransportLimits,
) -> Result<(), ProxyLeaseError> {
    stream.set_read_timeout(Some(limits.io_timeout))?;
    stream.set_write_timeout(Some(limits.io_timeout))?;
    Ok(())
}

fn exchange_connected(
    stream: &mut UnixStream,
    method: DockerMethod,
    target: &str,
    body: &[u8],
    max_response: usize,
) -> Result<PodmanHttpResponse, ProxyError> {
    if body.len() > 1024 * 1024
        || target.is_empty()
        || !target.starts_with('/')
        || target.bytes().any(|byte| byte <= 0x20 || byte >= 0x7f)
    {
        return Err(ProxyError::Transport(
            "invalid broker-built Podman request".into(),
        ));
    }
    let method = match method {
        DockerMethod::Get => "GET",
        DockerMethod::Post => "POST",
        _ => {
            return Err(ProxyError::Transport(
                "launch capability supports only GET and POST".into(),
            ))
        }
    };
    write!(
        stream,
        "{method} {target} HTTP/1.1\r\nHost: podman\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .map_err(|_| ProxyError::Transport("Podman request write failed".into()))?;
    stream
        .write_all(body)
        .map_err(|_| ProxyError::Transport("Podman request body write failed".into()))?;
    stream
        .flush()
        .map_err(|_| ProxyError::Transport("Podman request flush failed".into()))?;
    read_podman_response(stream, max_response)
}

fn read_podman_response(
    stream: &mut UnixStream,
    max_body: usize,
) -> Result<PodmanHttpResponse, ProxyError> {
    let mut bytes = Vec::with_capacity(1024);
    let mut buffer = [0_u8; 1024];
    let head_end = loop {
        let count = stream
            .read(&mut buffer)
            .map_err(|_| ProxyError::Transport("Podman response read failed".into()))?;
        if count == 0 {
            return Err(ProxyError::Transport(
                "Podman response closed before its header".into(),
            ));
        }
        bytes.extend_from_slice(&buffer[..count]);
        if bytes.len() > MAX_PODMAN_HEADER_BYTES + max_body {
            return Err(ProxyError::Transport(
                "Podman response exceeds its bound".into(),
            ));
        }
        if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            let head_end = end + 4;
            if head_end > MAX_PODMAN_HEADER_BYTES {
                return Err(ProxyError::Transport(
                    "Podman response header exceeds its bound".into(),
                ));
            }
            break head_end;
        }
        if bytes.len() > MAX_PODMAN_HEADER_BYTES {
            return Err(ProxyError::Transport(
                "Podman response header exceeds its bound".into(),
            ));
        }
    };
    let head = std::str::from_utf8(&bytes[..head_end - 4])
        .map_err(|_| ProxyError::Transport("Podman response header is not UTF-8".into()))?;
    let mut lines = head.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| ProxyError::Transport("Podman response has no status".into()))?;
    let mut status_parts = status_line.splitn(3, ' ');
    if status_parts.next() != Some("HTTP/1.1") {
        return Err(ProxyError::Transport(
            "Podman response is not HTTP/1.1".into(),
        ));
    }
    let status = status_parts
        .next()
        .ok_or_else(|| ProxyError::Transport("Podman response status is missing".into()))?
        .parse::<u16>()
        .map_err(|_| ProxyError::Transport("Podman response status is invalid".into()))?;
    if !(200..600).contains(&status) || status == 101 {
        return Err(ProxyError::Transport(
            "Podman informational or upgrade response refused".into(),
        ));
    }
    let mut content_length = None;
    for (index, line) in lines.enumerate() {
        if index >= MAX_PODMAN_HEADER_COUNT
            || line.is_empty()
            || line.starts_with([' ', '\t'])
            || !line.is_ascii()
        {
            return Err(ProxyError::Transport(
                "Podman response header is malformed".into(),
            ));
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| ProxyError::Transport("Podman response header is malformed".into()))?;
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(ProxyError::Transport(
                "Podman transfer encoding is refused".into(),
            ));
        }
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(ProxyError::Transport(
                    "duplicate Podman content length".into(),
                ));
            }
            content_length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| ProxyError::Transport("invalid Podman content length".into()))?,
            );
        }
    }
    let content_length = match (content_length, status) {
        (Some(content_length), _) => content_length,
        (None, 204 | 304) => 0,
        (None, _) => {
            return Err(ProxyError::Transport(
                "Podman content length is missing".into(),
            ))
        }
    };
    if content_length > max_body || bytes.len() - head_end > content_length {
        return Err(ProxyError::Transport(
            "Podman response body exceeds its bound".into(),
        ));
    }
    let received_body = bytes.len() - head_end;
    bytes.resize(head_end + content_length, 0);
    stream
        .read_exact(&mut bytes[head_end + received_body..])
        .map_err(|_| ProxyError::Transport("Podman response body is incomplete".into()))?;
    Ok(PodmanHttpResponse {
        status,
        body: bytes[head_end..].to_vec(),
    })
}

fn podman_object_id(body: &[u8]) -> Result<String, ProxyLeaseError> {
    let value: Value = serde_json::from_slice(body).map_err(|_| ProxyLeaseError::Create)?;
    let object_id = value
        .get("Id")
        .and_then(Value::as_str)
        .ok_or(ProxyLeaseError::Create)?;
    if !safe_object_id(object_id) {
        return Err(ProxyLeaseError::Create);
    }
    Ok(object_id.to_owned())
}

fn decode_podman_effective_spec(body: &[u8]) -> Result<EffectiveContainerSpec, ProxyError> {
    let value: Value = serde_json::from_slice(body)
        .map_err(|_| ProxyError::Transport("Podman inspect JSON is invalid".into()))?;
    let config = podman_object_field(&value, "Config")?;
    let host = podman_object_field(&value, "HostConfig")?;
    let networking = podman_object_field(&value, "NetworkSettings")?;
    let devices = podman_array_field(host, "Devices")?;
    let port_bindings = podman_nested_object_field(host, "PortBindings")?;
    if !devices.is_empty() || !port_bindings.is_empty() {
        return Err(ProxyError::Transport(
            "Podman inspect reports forbidden device or port state".into(),
        ));
    }
    let networks = podman_nested_object_field(networking, "Networks")?;
    let restart = podman_nested_object_field(host, "RestartPolicy")?;
    let log = podman_nested_object_field(host, "LogConfig")?;
    Ok(EffectiveContainerSpec {
        image: podman_string_field(config, "Image")?,
        user: podman_string_field(config, "User")?,
        binds: podman_strings_field(host, "Binds")?,
        network_mode: podman_string_field(host, "NetworkMode")?,
        readonly_rootfs: podman_bool_field(host, "ReadonlyRootfs")?,
        cap_drop: podman_strings_field(host, "CapDrop")?,
        cap_add: podman_strings_field(host, "CapAdd")?,
        privileged: podman_bool_field(host, "Privileged")?,
        security_opt: podman_strings_field(host, "SecurityOpt")?,
        pids_limit: podman_u64_field(host, "PidsLimit")?,
        memory: podman_u64_field(host, "Memory")?,
        memory_swap: podman_u64_field(host, "MemorySwap")?,
        shm_size: podman_u64_field(host, "ShmSize")?,
        nano_cpus: podman_u64_field(host, "NanoCpus")?,
        devices: Vec::new(),
        port_bindings: BTreeMap::new(),
        publish_all_ports: podman_bool_field(host, "PublishAllPorts")?,
        pid_mode: podman_string_field(host, "PidMode")?,
        ipc_mode: podman_string_field(host, "IpcMode")?,
        uts_mode: podman_string_field(host, "UTSMode")?,
        cgroupns_mode: podman_string_field(host, "CgroupnsMode")?,
        userns_mode: podman_string_field(host, "UsernsMode")?,
        restart_policy: podman_string_field(restart, "Name")?,
        log_driver: podman_string_field(log, "Type")?,
        network_endpoints: networks.keys().cloned().collect(),
        labels: podman_string_map_field(config, "Labels")?,
    })
}

fn podman_object_field<'a>(
    value: &'a Value,
    name: &str,
) -> Result<&'a serde_json::Map<String, Value>, ProxyError> {
    value
        .get(name)
        .and_then(Value::as_object)
        .ok_or_else(|| ProxyError::Transport(format!("Podman inspect {name} is not an object")))
}

fn podman_nested_object_field<'a>(
    value: &'a serde_json::Map<String, Value>,
    name: &str,
) -> Result<&'a serde_json::Map<String, Value>, ProxyError> {
    value
        .get(name)
        .and_then(Value::as_object)
        .ok_or_else(|| ProxyError::Transport(format!("Podman inspect {name} is not an object")))
}

fn podman_array_field<'a>(
    value: &'a serde_json::Map<String, Value>,
    name: &str,
) -> Result<&'a Vec<Value>, ProxyError> {
    value
        .get(name)
        .and_then(Value::as_array)
        .ok_or_else(|| ProxyError::Transport(format!("Podman inspect {name} is not an array")))
}

fn podman_strings_field(
    value: &serde_json::Map<String, Value>,
    name: &str,
) -> Result<Vec<String>, ProxyError> {
    podman_array_field(value, name)?
        .iter()
        .map(|item| {
            item.as_str().map(str::to_owned).ok_or_else(|| {
                ProxyError::Transport(format!("Podman inspect {name} contains a non-string"))
            })
        })
        .collect()
}

fn podman_string_field(
    value: &serde_json::Map<String, Value>,
    name: &str,
) -> Result<String, ProxyError> {
    value
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| ProxyError::Transport(format!("Podman inspect {name} is not a string")))
}

fn podman_bool_field(
    value: &serde_json::Map<String, Value>,
    name: &str,
) -> Result<bool, ProxyError> {
    value
        .get(name)
        .and_then(Value::as_bool)
        .ok_or_else(|| ProxyError::Transport(format!("Podman inspect {name} is not a bool")))
}

fn podman_u64_field(value: &serde_json::Map<String, Value>, name: &str) -> Result<u64, ProxyError> {
    value
        .get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| ProxyError::Transport(format!("Podman inspect {name} is not a u64")))
}

fn podman_string_map_field(
    value: &serde_json::Map<String, Value>,
    name: &str,
) -> Result<BTreeMap<String, String>, ProxyError> {
    podman_nested_object_field(value, name)?
        .iter()
        .map(|(key, value)| {
            value
                .as_str()
                .map(|value| (key.clone(), value.to_owned()))
                .ok_or_else(|| {
                    ProxyError::Transport(format!("Podman inspect {name} contains a non-string"))
                })
        })
        .collect()
}

/// Build broker-owned descriptors from authenticated authority only.
#[allow(clippy::too_many_arguments)]
pub fn build_broker_proxy_lease<P: PrestartPersister>(
    authority: ProxyLeaseAuthority,
    admission: OrdinaryAdmission,
    lease: LeaseToken,
    validated: &ValidatedAttemptLeaseBinding,
    manifest: PolicyManifest,
    upstream: UnixStream,
    persister: P,
    limits: TransportLimits,
) -> Result<BrokerProxyLease<P>, ProxyLeaseError> {
    validate_authenticated_binding(admission, lease, validated, &manifest)?;
    let policy = ProxyPolicy::install(manifest, validated)?;
    let capability = UpstreamCapability::from_validated_lease(validated);
    if capability.lease_id() != validated.as_binding().lease_id {
        return Err(ProxyLeaseError::DescriptorIdentity);
    }
    let connector = InheritedOneShotConnector::new(upstream, capability.clone())?;
    prepare_broker_directory(&authority.listener_root)?;
    let listener_path = authority.listener_root.join(format!(
        "proxy-{}-{}.sock",
        hex::encode(lease.lease_id()),
        lease.generation()
    ));
    if listener_path.exists() {
        return Err(ProxyLeaseError::ListenerExists);
    }
    let listener = UnixListener::bind(&listener_path)?;
    nix::unistd::chown(
        &listener_path,
        Some(nix::unistd::geteuid()),
        Some(nix::unistd::Gid::from_raw(authority.listener_gid)),
    )?;
    fs::set_permissions(&listener_path, fs::Permissions::from_mode(LISTENER_MODE))?;
    let socket = fs::symlink_metadata(&listener_path)?;
    if !socket.file_type().is_socket()
        || socket.uid() != nix::unistd::geteuid().as_raw()
        || socket.gid() != authority.listener_gid
    {
        return Err(ProxyLeaseError::Authority);
    }
    let observer = ProxyLeaseObserver::production(
        admission,
        lease,
        validated.as_binding().lease_id.clone(),
        authority,
        persister,
    )?;
    let proxy = InheritedProxy::new_with_observer(
        listener,
        connector,
        capability.clone(),
        limits,
        policy,
        observer,
    )?;
    Ok(BrokerProxyLease {
        listener_path,
        lease,
        capability,
        proxy,
    })
}

fn validate_authenticated_binding(
    admission: OrdinaryAdmission,
    lease: LeaseToken,
    validated: &ValidatedAttemptLeaseBinding,
    manifest: &PolicyManifest,
) -> Result<(), ProxyLeaseError> {
    let binding = validated.as_binding();
    if admission.trust_class != AdmissionTrustClass::AcceptedReviewed
        || admission.lease_id == [0; 16]
        || admission.run_id == [0; 16]
        || admission.attempt == 0
        || lease.lease_id() != admission.lease_id
        || lease.run_id() != admission.run_id
        || lease.attempt() != admission.attempt
        || lease.signed_request_digest() != admission.job.request_digest
        || lease.signer() != admission.signer
        || lease.nonce() != admission.nonce
        || lease.generation() == 0
        || lease.deadline_at() == 0
        || lease.deadline_at() > admission.expires_at
        || binding.run_id != Uuid::from_bytes(admission.run_id).to_string()
        || binding.source_sha != oid_hex(admission.job.source_oid)
        || binding.base_oid != oid_hex(admission.job.base_oid)
        || binding.attempt != admission.attempt
        || binding.expires_at_unix_seconds != admission.expires_at
        || manifest.manifest_digest
            != format!("sha256:{}", hex::encode(admission.job.manifest_digest))
    {
        return Err(ProxyLeaseError::DescriptorIdentity);
    }
    Ok(())
}

/// One retained Podman object and its observed state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PodmanObject {
    /// Full runtime object ID.
    pub id: String,
    /// Whether the object is still running.
    pub running: bool,
}

/// Bounded rootless Podman operations used only for reconciliation.
pub trait PodmanReconcileRunner {
    /// Enumerate all objects bearing the exact broker lease label. Implementors
    /// must cap bytes, object count, and duration before returning.
    fn list(
        &mut self,
        capability: &UpstreamCapability,
    ) -> Result<Vec<PodmanObject>, ProxyLeaseError>;
    /// Stop one exact object through a fresh authenticated descriptor.
    fn stop(
        &mut self,
        capability: &UpstreamCapability,
        object_id: &str,
    ) -> Result<(), ProxyLeaseError>;
    /// Delete one exact stopped object through a fresh authenticated descriptor.
    fn delete(
        &mut self,
        capability: &UpstreamCapability,
        object_id: &str,
    ) -> Result<(), ProxyLeaseError>;
}

/// Reconcile exactly the object IDs retained by the policy ledger.
pub fn reconcile_podman_objects<R: PodmanReconcileRunner>(
    runner: &mut R,
    capability: &UpstreamCapability,
    retained_ids: &BTreeSet<String>,
) -> Result<(), ProxyLeaseError> {
    if retained_ids.is_empty()
        || retained_ids.len() > MAX_LEASE_OBJECTS
        || retained_ids.iter().any(|id| !safe_object_id(id))
    {
        return Err(ProxyLeaseError::AmbiguousObjects);
    }
    let observed = runner.list(capability)?;
    let observed_ids = observed
        .iter()
        .map(|object| object.id.clone())
        .collect::<BTreeSet<_>>();
    if observed.len() > MAX_LEASE_OBJECTS
        || observed.len() != observed_ids.len()
        || observed.iter().any(|object| !safe_object_id(&object.id))
        || &observed_ids != retained_ids
    {
        return Err(ProxyLeaseError::AmbiguousObjects);
    }
    for object in observed {
        if object.running {
            runner.stop(capability, &object.id)?;
        }
        runner.delete(capability, &object.id)?;
    }
    if !runner.list(capability)?.is_empty() {
        return Err(ProxyLeaseError::ObjectsRemain);
    }
    Ok(())
}

/// Fail-closed C5 construction, persistence, and reconciliation errors.
#[derive(Debug, Error)]
pub enum ProxyLeaseError {
    /// Root authority contains an unsafe or incomplete value.
    #[error("invalid proxy lease authority")]
    Authority,
    /// Authenticated admission, opaque lease, manifest, and descriptor disagree.
    #[error("proxy descriptor identity mismatch")]
    DescriptorIdentity,
    /// The derived listener already exists.
    #[error("derived proxy listener already exists")]
    ListenerExists,
    /// The broker-side launch capability was consumed or used out of order.
    #[error("Podman launch capability state refused")]
    LaunchState,
    /// Canonical create failed or returned an invalid object identity.
    #[error("Podman canonical create failed")]
    Create,
    /// Fresh pre-start inspection failed or drifted from policy.
    #[error("Podman pre-start inspection failed")]
    Inspect,
    /// Start failed after the persisted pre-start observation.
    #[error("Podman start failed and requires reconciliation")]
    Start,
    /// The authenticated descriptor channel was unavailable.
    #[error("Podman descriptor transport failed")]
    DescriptorTransport,
    /// Runtime objects are duplicated, malformed, missing, or unexpected.
    #[error("Podman object inventory is ambiguous")]
    AmbiguousObjects,
    /// Stop failed.
    #[error("Podman object stop failed")]
    Stop,
    /// Delete failed.
    #[error("Podman object delete failed")]
    Delete,
    /// Final enumeration still found lease objects.
    #[error("Podman objects remain after reconciliation")]
    ObjectsRemain,
    /// Clock failed or overflowed.
    #[error("proxy evidence clock failed")]
    Clock,
    /// Policy or transport construction failed.
    #[error(transparent)]
    Proxy(#[from] ProxyError),
    /// Evidence publication failed.
    #[error(transparent)]
    Evidence(#[from] evidence::PublicationError),
    /// Broker listener filesystem operation failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Broker socket ownership operation failed.
    #[error(transparent)]
    Ownership(#[from] nix::errno::Errno),
}

fn safe_object_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn prepare_broker_directory(path: &Path) -> Result<(), ProxyLeaseError> {
    if fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err(ProxyLeaseError::Authority);
    }
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.gid() != nix::unistd::getegid().as_raw()
    {
        return Err(ProxyLeaseError::Authority);
    }
    Ok(())
}

fn digest32(bytes: &[u8]) -> Digest32 {
    Digest32(Sha256::digest(bytes).into())
}

fn fixed_seccomp_digest() -> Result<Digest32, evidence::PublicationError> {
    let bytes = hex::decode(evidence::SECCOMP_PROFILE_SHA256)
        .map_err(|_| evidence::PublicationError::RecordMismatch)?;
    let bytes = bytes
        .try_into()
        .map_err(|_| evidence::PublicationError::RecordMismatch)?;
    Ok(Digest32(bytes))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn oid_hex(oid: GitOid) -> String {
    match oid {
        GitOid::Sha1(bytes) => hex::encode(bytes),
        GitOid::Sha256(bytes) => hex::encode(bytes),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io::{Read, Write};
    use std::os::unix::fs::FileTypeExt;
    use std::sync::{Arc, Mutex};

    use buzz_ci_isolation_contract::{
        AttemptLeaseBinding, BrokerObjectHandle, CgroupHandle, EngineKind as SharedEngineKind,
        IsolationProfile as SharedIsolationProfile, NetnsHandle,
        NetworkPolicy as SharedNetworkPolicy, Phase1ValidationContext, PrincipalUids, QuotaBackend,
        QuotaHandle, ResourceLimits, RuntimeEndpointIdentity, WorkspaceHandle,
    };
    use buzz_ci_policy_proxy::{
        Admission, AllowedMount, EngineKind, IsolationLimits, IsolationProfile, NetworkPolicy,
    };
    use tempfile::TempDir;

    use super::*;
    use crate::activation::{
        DurableLeaseFields, HostActivationCoordinates, OrdinaryJobCoordinates, VerifiedSigner,
    };
    use crate::evidence::{
        DnsReadback, LeaseLimits, LeaseRecord, ResourcePropertyReadback, SeccompEvidence,
    };

    #[derive(Default)]
    struct FakePersister {
        fail: bool,
        calls: usize,
    }

    impl PrestartPersister for FakePersister {
        fn persist(
            &mut self,
            _admission: &OrdinaryAdmission,
            _lease: LeaseToken,
            _create: &CanonicalCreate,
            _proof: &VerifiedStart,
            _effective: &EffectiveContainerSpec,
        ) -> Result<(), SeccompExecError> {
            self.calls += 1;
            if self.fail {
                Err(SeccompExecError::Clock)
            } else {
                Ok(())
            }
        }
    }

    struct FakeRunner {
        lists: VecDeque<Result<Vec<PodmanObject>, ProxyLeaseError>>,
        stop_fail: bool,
        delete_fail: bool,
        actions: Vec<String>,
    }

    impl PodmanReconcileRunner for FakeRunner {
        fn list(
            &mut self,
            _capability: &UpstreamCapability,
        ) -> Result<Vec<PodmanObject>, ProxyLeaseError> {
            self.actions.push("list".into());
            self.lists.pop_front().unwrap()
        }

        fn stop(
            &mut self,
            _capability: &UpstreamCapability,
            object_id: &str,
        ) -> Result<(), ProxyLeaseError> {
            self.actions.push(format!("stop:{object_id}"));
            if self.stop_fail {
                Err(ProxyLeaseError::Stop)
            } else {
                Ok(())
            }
        }

        fn delete(
            &mut self,
            _capability: &UpstreamCapability,
            object_id: &str,
        ) -> Result<(), ProxyLeaseError> {
            self.actions.push(format!("delete:{object_id}"));
            if self.delete_fail {
                Err(ProxyLeaseError::Delete)
            } else {
                Ok(())
            }
        }
    }

    fn capability() -> UpstreamCapability {
        let (_, _, validated, _) = binding_fixture();
        UpstreamCapability::from_validated_lease(&validated)
    }

    fn runner(lists: Vec<Vec<PodmanObject>>) -> FakeRunner {
        FakeRunner {
            lists: lists.into_iter().map(Ok).collect(),
            stop_fail: false,
            delete_fail: false,
            actions: Vec::new(),
        }
    }

    #[test]
    fn reconciliation_stops_deletes_and_proves_empty() {
        let objects = vec![
            PodmanObject {
                id: "one".into(),
                running: true,
            },
            PodmanObject {
                id: "two".into(),
                running: false,
            },
        ];
        let mut fake = runner(vec![objects, vec![]]);
        reconcile_podman_objects(
            &mut fake,
            &capability(),
            &BTreeSet::from(["one".into(), "two".into()]),
        )
        .unwrap();
        assert_eq!(
            fake.actions,
            ["list", "stop:one", "delete:one", "delete:two", "list"]
        );
    }

    #[test]
    fn reconciliation_fails_on_inventory_stop_delete_and_residue() {
        let retained = BTreeSet::from(["one".into()]);
        let mut ambiguous = runner(vec![vec![PodmanObject {
            id: "other".into(),
            running: true,
        }]]);
        assert!(matches!(
            reconcile_podman_objects(&mut ambiguous, &capability(), &retained),
            Err(ProxyLeaseError::AmbiguousObjects)
        ));

        let mut stop = runner(vec![vec![PodmanObject {
            id: "one".into(),
            running: true,
        }]]);
        stop.stop_fail = true;
        assert!(matches!(
            reconcile_podman_objects(&mut stop, &capability(), &retained),
            Err(ProxyLeaseError::Stop)
        ));

        let mut delete = runner(vec![vec![PodmanObject {
            id: "one".into(),
            running: false,
        }]]);
        delete.delete_fail = true;
        assert!(matches!(
            reconcile_podman_objects(&mut delete, &capability(), &retained),
            Err(ProxyLeaseError::Delete)
        ));

        let residue = vec![PodmanObject {
            id: "one".into(),
            running: false,
        }];
        let mut remains = runner(vec![residue.clone(), residue]);
        assert!(matches!(
            reconcile_podman_objects(&mut remains, &capability(), &retained),
            Err(ProxyLeaseError::ObjectsRemain)
        ));
    }

    // The complete admission fixture below mirrors dns_activation tests. It
    // proves descriptor identity without touching Podman or the host.
    fn binding_fixture() -> (
        OrdinaryAdmission,
        LeaseToken,
        ValidatedAttemptLeaseBinding,
        PolicyManifest,
    ) {
        let runtime_uid = nix::unistd::geteuid().as_raw();
        assert_ne!(runtime_uid, 0, "tests require an unprivileged process");
        let run_id = [13; 16];
        let admission = OrdinaryAdmission {
            host: HostActivationCoordinates {
                integrated_candidate_sha: GitOid::Sha256([1; 32]),
                broker_build_identity: [2; 32],
                host_profile_digest: [3; 32],
                suite_identity: [4; 32],
            },
            job: OrdinaryJobCoordinates {
                request_digest: [6; 32],
                manifest_digest: [7; 32],
                isolation_profile_digest: [8; 32],
                source_oid: GitOid::Sha256([9; 32]),
                base_oid: GitOid::Sha256([10; 32]),
                job_identity: [11; 32],
            },
            lease_id: [12; 16],
            run_id,
            attempt: 2,
            signer: VerifiedSigner([5; 32]),
            nonce: [14; 32],
            expires_at: 100,
            wall_timeout_seconds: 30,
            trust_class: AdmissionTrustClass::AcceptedReviewed,
        };
        let lease = LeaseToken::from_durable(DurableLeaseFields {
            lease_id: admission.lease_id,
            run_id,
            attempt: admission.attempt,
            signed_request_digest: admission.job.request_digest,
            signer: admission.signer,
            generation: 17,
            nonce: admission.nonce,
            deadline_at: 90,
        });
        let token = |byte: char| byte.to_string().repeat(64);
        let limits = ResourceLimits {
            cpu_weight: 100,
            mem_max_bytes: 1024 * 1024 * 1024,
            pids_max: 512,
            io_weight: 100,
        };
        let lease_id = "01ARZ3NDEKTSV4RRFFQ69G5FAV".to_owned();
        let validated = AttemptLeaseBinding {
            schema_version: 1,
            request_event_id: "f".repeat(64),
            run_id: Uuid::from_bytes(run_id).to_string(),
            target_repo_a: format!("30617:{}:buzz", "e".repeat(64)),
            source_sha: oid_hex(admission.job.source_oid),
            base_oid: oid_hex(admission.job.base_oid),
            workflow_id: "required-ci".into(),
            workflow_digest: "7".repeat(64),
            job_id: "linux".into(),
            attempt: admission.attempt,
            lease_id: lease_id.clone(),
            expires_at_unix_seconds: admission.expires_at,
            principals: PrincipalUids {
                materializer: runtime_uid + 2,
                executor: runtime_uid + 1,
                runtime: runtime_uid,
            },
            workspace: WorkspaceHandle {
                path: "/var/lib/buzz-ci/slots/01".into(),
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
            now_unix_seconds: 20,
            max_expiry_horizon_seconds: 100,
            forbidden_host_uids: &[],
            expected_engine_version: "5.8.4",
            expected_arch: "x86_64",
        })
        .unwrap();
        let manifest = PolicyManifest {
            schema_version: 1,
            request_event_id: "f".repeat(64),
            run_id: Uuid::from_bytes(run_id).to_string(),
            target_repo_a: format!("30617:{}:buzz", "e".repeat(64)),
            sha: oid_hex(admission.job.source_oid),
            base_oid: oid_hex(admission.job.base_oid),
            workflow_id: "required-ci".into(),
            workflow_digest: "7".repeat(64),
            job_id: "linux".into(),
            attempt: admission.attempt,
            lease_id,
            manifest_digest: format!("sha256:{}", hex::encode(admission.job.manifest_digest)),
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
                    timeout_seconds: 30,
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
            allowed_environment: Vec::new(),
        };
        (admission, lease, validated, manifest)
    }

    fn effective(manifest: &PolicyManifest) -> EffectiveContainerSpec {
        EffectiveContainerSpec {
            image: manifest.isolation_profile.image_digest.clone(),
            user: manifest.container_user.clone(),
            binds: vec!["/var/lib/buzz-ci/slots/01/source:/workspace:ro,Z".into()],
            network_mode: "none".into(),
            readonly_rootfs: true,
            cap_drop: vec!["ALL".into()],
            cap_add: vec![],
            privileged: false,
            security_opt: vec![
                "no-new-privileges".into(),
                "label=type:container_t".into(),
                format!("seccomp={}", evidence::SECCOMP_PROFILE_PATH),
            ],
            pids_limit: 512,
            memory: 1024 * 1024 * 1024,
            memory_swap: 0,
            shm_size: 64 * 1024 * 1024,
            nano_cpus: 1_000_000_000,
            devices: vec![],
            port_bindings: BTreeMap::new(),
            publish_all_ports: false,
            pid_mode: "private".into(),
            ipc_mode: "private".into(),
            uts_mode: "private".into(),
            cgroupns_mode: "private".into(),
            userns_mode: "private".into(),
            restart_policy: "no".into(),
            log_driver: "none".into(),
            network_endpoints: vec![],
            labels: BTreeMap::from([
                ("buzz.ci.run".into(), manifest.run_id.clone()),
                ("buzz.ci.sha".into(), manifest.sha.clone()),
                ("buzz.ci.job".into(), manifest.job_id.clone()),
                ("buzz.ci.attempt".into(), manifest.attempt.to_string()),
                ("buzz.ci.manifest".into(), manifest.manifest_digest.clone()),
            ]),
        }
    }

    fn authority(root: &TempDir) -> ProxyLeaseAuthority {
        ProxyLeaseAuthority::new(
            root.path().join("listeners"),
            root.path().join("evidence"),
            CiEventBinding {
                request_event_id_46105: [1; 32],
                teardown_event_id_46106: [2; 32],
            },
            PathBuf::from("/run/buzzci/bundle"),
            PathBuf::from("/run/buzzci/pid"),
            vec!["act".into(), "--concurrent-jobs=1".into()],
            PathBuf::from("/workspace"),
            65534,
            65534,
            nix::unistd::getegid().as_raw(),
        )
        .unwrap()
    }

    fn initialize_evidence(root: &TempDir, lease_id: &str) {
        EvidenceStore::new(root.path().join("evidence"))
            .unwrap()
            .initialize_lease(&LeaseRecord {
                schema_version: 1,
                lease_id: lease_id.into(),
                lease_unit: "buzzci-test.slice".into(),
                cgroup_path: PathBuf::from("/buzzci.slice/buzzci-test.slice"),
                workspace_dir: PathBuf::from("/var/lib/buzz-ci/slots/01"),
                limits: LeaseLimits { wall_deadline: 100 },
                resource_readback: ResourcePropertyReadback {
                    cpu_quota_per_sec_usec: 100_000,
                    memory_max_bytes: 1024 * 1024 * 1024,
                    tasks_max: 512,
                    runtime_max_seconds: 30,
                },
                dns_readback: DnsReadback {
                    files_lookup_ok: true,
                    arbitrary_getent_refused: true,
                    resolved_varlink_inaccessible: true,
                    direct_53_refused: true,
                    allowed_tuples_only: true,
                },
                seccomp_profile: SeccompEvidence {
                    path: PathBuf::from(evidence::SECCOMP_PROFILE_PATH),
                    sha256: evidence::SECCOMP_PROFILE_SHA256.into(),
                },
                sanitized_artifact_store_path: PathBuf::from("/var/lib/buzz-ci/artifacts"),
                sanitized_log_store_path: PathBuf::from("/var/lib/buzz-ci/logs"),
                created_at_unix_ns: 1,
            })
            .unwrap();
    }

    struct FakeClock(VecDeque<u64>);

    impl ProxyClock for FakeClock {
        fn now_ns(&mut self) -> Result<u64, ProxyLeaseError> {
            self.0.pop_front().ok_or(ProxyLeaseError::Clock)
        }
    }

    #[derive(Clone)]
    struct RecordingPersister(Arc<Mutex<Vec<&'static str>>>);

    impl PrestartPersister for RecordingPersister {
        fn persist(
            &mut self,
            _admission: &OrdinaryAdmission,
            _lease: LeaseToken,
            _create: &CanonicalCreate,
            _proof: &VerifiedStart,
            _effective: &EffectiveContainerSpec,
        ) -> Result<(), SeccompExecError> {
            self.0.lock().unwrap().push("persist");
            Ok(())
        }
    }

    struct ScriptedLaunchDescriptors {
        inspect_body: Vec<u8>,
        ordering: Arc<Mutex<Vec<&'static str>>>,
        requests: Arc<Mutex<Vec<Vec<u8>>>>,
        fail_start: bool,
    }

    impl PodmanLaunchDescriptorSource for ScriptedLaunchDescriptors {
        fn acquire(
            &mut self,
            capability: &UpstreamCapability,
            operation: &PodmanLaunchOperation,
        ) -> Result<InheritedOneShotConnector, PodmanDescriptorError> {
            let (broker, mut runtime) = UnixStream::pair().unwrap();
            let operation = operation.clone();
            let inspect_body = self.inspect_body.clone();
            let ordering = Arc::clone(&self.ordering);
            let requests = Arc::clone(&self.requests);
            let fail_start = self.fail_start;
            std::thread::spawn(move || match operation {
                PodmanLaunchOperation::Create => {
                    let request = read_test_request(&mut runtime);
                    ordering.lock().unwrap().push("create");
                    requests.lock().unwrap().push(request);
                    write_test_response(&mut runtime, 201, "Created", br#"{"Id":"container-1"}"#);
                }
                PodmanLaunchOperation::InspectStart { object_id } => {
                    assert_eq!(object_id, "container-1");
                    let inspect = read_test_request(&mut runtime);
                    ordering.lock().unwrap().push("inspect");
                    requests.lock().unwrap().push(inspect);
                    write_test_response(&mut runtime, 200, "OK", &inspect_body);
                    let start = read_test_request(&mut runtime);
                    ordering.lock().unwrap().push("start");
                    requests.lock().unwrap().push(start);
                    if !fail_start {
                        write_test_response(&mut runtime, 204, "No Content", &[]);
                    }
                }
            });
            InheritedOneShotConnector::new(broker, capability.clone())
                .map_err(|_| PodmanDescriptorError::Identity)
        }
    }

    fn read_test_request(stream: &mut UnixStream) -> Vec<u8> {
        let mut request = Vec::new();
        let mut byte = [0_u8; 1];
        while !request.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
        }
        let head = std::str::from_utf8(&request).unwrap();
        let content_length = head
            .lines()
            .find_map(|line| {
                line.strip_prefix("Content-Length: ")
                    .map(|value| value.parse::<usize>().unwrap())
            })
            .unwrap();
        let head_len = request.len();
        request.resize(head_len + content_length, 0);
        stream.read_exact(&mut request[head_len..]).unwrap();
        request
    }

    fn write_test_response(stream: &mut UnixStream, status: u16, reason: &str, body: &[u8]) {
        write!(
            stream,
            "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .unwrap();
        stream.write_all(body).unwrap();
    }

    fn inspect_body(manifest: &PolicyManifest) -> Vec<u8> {
        let expected = effective(manifest);
        serde_json::to_vec(&serde_json::json!({
            "Config": {
                "Image": expected.image,
                "User": expected.user,
                "Labels": expected.labels,
            },
            "HostConfig": {
                "Binds": expected.binds,
                "NetworkMode": expected.network_mode,
                "ReadonlyRootfs": expected.readonly_rootfs,
                "CapDrop": expected.cap_drop,
                "CapAdd": expected.cap_add,
                "Privileged": expected.privileged,
                "SecurityOpt": expected.security_opt,
                "PidsLimit": expected.pids_limit,
                "Memory": expected.memory,
                "MemorySwap": expected.memory_swap,
                "ShmSize": expected.shm_size,
                "NanoCpus": expected.nano_cpus,
                "Devices": expected.devices,
                "PortBindings": expected.port_bindings,
                "PublishAllPorts": expected.publish_all_ports,
                "PidMode": expected.pid_mode,
                "IpcMode": expected.ipc_mode,
                "UTSMode": expected.uts_mode,
                "CgroupnsMode": expected.cgroupns_mode,
                "UsernsMode": expected.userns_mode,
                "RestartPolicy": {"Name": expected.restart_policy},
                "LogConfig": {"Type": expected.log_driver},
            },
            "NetworkSettings": {"Networks": {}},
        }))
        .unwrap()
    }

    #[test]
    fn production_launch_capability_owns_create_inspect_persist_start_boundary() {
        let root = tempfile::tempdir().unwrap();
        let (admission, lease, validated, manifest) = binding_fixture();
        initialize_evidence(&root, &manifest.lease_id);
        let ordering = Arc::new(Mutex::new(Vec::new()));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let source = ScriptedLaunchDescriptors {
            inspect_body: inspect_body(&manifest),
            ordering: Arc::clone(&ordering),
            requests: Arc::clone(&requests),
            fail_start: false,
        };
        let persister = RecordingPersister(Arc::clone(&ordering));
        let image = manifest.isolation_profile.image_digest.clone();
        let mut launch = build_broker_podman_launch(
            authority(&root),
            admission,
            lease,
            &validated,
            manifest,
            source,
            persister,
            TransportLimits::default(),
        )
        .unwrap();

        let object_id = launch
            .create_inspect_persist_start(
                lease,
                &serde_json::to_vec(&serde_json::json!({
                    "Image": image,
                    "Cmd": ["true"],
                    "WorkingDir": "/workspace",
                }))
                .unwrap(),
            )
            .unwrap();

        assert_eq!(object_id, "container-1");
        assert_eq!(
            *ordering.lock().unwrap(),
            ["create", "inspect", "persist", "start"]
        );
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        assert!(requests[0].starts_with(b"POST /containers/create?name="));
        assert!(requests[1].starts_with(b"GET /containers/container-1/json HTTP/1.1"));
        assert!(requests[2].starts_with(b"POST /containers/container-1/start HTTP/1.1"));
        let body_start = requests[0]
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap()
            + 4;
        let create_body = &requests[0][body_start..];
        let create: serde_json::Value = serde_json::from_slice(create_body).unwrap();
        assert_eq!(create["HostConfig"]["Privileged"], false);
        assert_eq!(create["HostConfig"]["NetworkMode"], "none");
        assert!(launch.retained_object_id().is_some());
        assert!(!launch.is_poisoned());
    }

    #[test]
    fn record_created_failure_retains_exact_id_for_reconciliation() {
        let root = tempfile::tempdir().unwrap();
        let (admission, lease, validated, manifest) = binding_fixture();
        initialize_evidence(&root, &manifest.lease_id);
        let ordering = Arc::new(Mutex::new(Vec::new()));
        let source = ScriptedLaunchDescriptors {
            inspect_body: inspect_body(&manifest),
            ordering: Arc::clone(&ordering),
            requests: Arc::new(Mutex::new(Vec::new())),
            fail_start: false,
        };
        let persister = RecordingPersister(Arc::clone(&ordering));
        let image = manifest.isolation_profile.image_digest.clone();
        let requested_create = serde_json::to_vec(&serde_json::json!({"Image": image})).unwrap();
        let mut launch = build_broker_podman_launch(
            authority(&root),
            admission,
            lease,
            &validated,
            manifest,
            source,
            persister,
            TransportLimits::default(),
        )
        .unwrap();
        let Admission::Create(existing) = launch
            .policy
            .admit(DockerMethod::Post, "/containers/create", &requested_create)
            .unwrap()
        else {
            panic!("create admission")
        };
        launch
            .policy
            .record_created("container-1".into(), &existing)
            .unwrap();

        assert!(matches!(
            launch.create_inspect_persist_start(lease, &requested_create),
            Err(ProxyLeaseError::Create)
        ));
        assert!(launch.is_poisoned());
        assert_eq!(launch.retained_object_id(), Some("container-1"));
        assert_eq!(*ordering.lock().unwrap(), ["create"]);

        let mut cleanup = runner(vec![
            vec![PodmanObject {
                id: "container-1".into(),
                running: false,
            }],
            vec![],
        ]);
        launch.reconcile(lease, &mut cleanup).unwrap();
        assert_eq!(cleanup.actions, ["list", "delete:container-1", "list"]);
        assert!(launch.retained_object_id().is_none());
    }

    #[test]
    fn ambiguous_start_poison_requires_exact_reconciliation() {
        let root = tempfile::tempdir().unwrap();
        let (admission, lease, validated, manifest) = binding_fixture();
        initialize_evidence(&root, &manifest.lease_id);
        let ordering = Arc::new(Mutex::new(Vec::new()));
        let source = ScriptedLaunchDescriptors {
            inspect_body: inspect_body(&manifest),
            ordering: Arc::clone(&ordering),
            requests: Arc::new(Mutex::new(Vec::new())),
            fail_start: true,
        };
        let persister = RecordingPersister(Arc::clone(&ordering));
        let image = manifest.isolation_profile.image_digest.clone();
        let mut launch = build_broker_podman_launch(
            authority(&root),
            admission,
            lease,
            &validated,
            manifest,
            source,
            persister,
            TransportLimits::default(),
        )
        .unwrap();

        assert!(matches!(
            launch.create_inspect_persist_start(
                lease,
                &serde_json::to_vec(&serde_json::json!({"Image": image})).unwrap(),
            ),
            Err(ProxyLeaseError::Start)
        ));
        assert!(launch.is_poisoned());
        assert_eq!(launch.retained_object_id(), Some("container-1"));
        assert_eq!(
            *ordering.lock().unwrap(),
            ["create", "inspect", "persist", "start"]
        );

        let mut cleanup = runner(vec![
            vec![PodmanObject {
                id: "container-1".into(),
                running: true,
            }],
            vec![],
        ]);
        launch.reconcile(lease, &mut cleanup).unwrap();
        assert_eq!(
            cleanup.actions,
            ["list", "stop:container-1", "delete:container-1", "list"]
        );
        assert!(launch.retained_object_id().is_none());
    }

    #[test]
    fn create_inspect_prestart_persist_and_start_are_ordered() {
        let root = tempfile::tempdir().unwrap();
        let (admission, lease, validated, manifest) = binding_fixture();
        initialize_evidence(&root, &manifest.lease_id);
        let mut policy = ProxyPolicy::install(manifest.clone(), &validated).unwrap();
        let body = serde_json::to_vec(&serde_json::json!({
            "Image": manifest.isolation_profile.image_digest,
            "Cmd": ["true"],
            "WorkingDir": "/workspace"
        }))
        .unwrap();
        let Admission::Create(create) = policy
            .admit(
                buzz_ci_policy_proxy::DockerMethod::Post,
                "/containers/create",
                &body,
            )
            .unwrap()
        else {
            panic!("create admission")
        };
        policy
            .record_created("container-1".into(), &create)
            .unwrap();
        let effective = effective(&manifest);
        let proof = policy.verify_pre_start("container-1", &effective).unwrap();
        let mut observer = ProxyLeaseObserver {
            admission,
            lease,
            lease_id: manifest.lease_id.clone(),
            authority: authority(&root),
            store: EvidenceStore::new(root.path().join("evidence")).unwrap(),
            persister: FakePersister::default(),
            clock: FakeClock(VecDeque::from([10, 20])),
            started_object: None,
        };
        observer
            .observe_pre_start(&create, "container-1", &effective, &proof)
            .unwrap();
        policy.commit_started(&proof).unwrap();
        observer.observe_started("container-1").unwrap();
        assert_eq!(observer.persister.calls, 1);
        let paths = observer.store.paths(&manifest.lease_id).unwrap();
        assert!(paths.proxy_object(1).unwrap().is_file());
        let ordering = fs::read_to_string(paths.ordering).unwrap();
        assert!(ordering
            .lines()
            .next()
            .unwrap()
            .contains("proxy_object_recorded"));
        assert!(ordering.lines().nth(1).unwrap().contains("\"start\""));
    }

    #[test]
    fn effective_drift_and_prestart_persistence_failure_refuse_start() {
        let root = tempfile::tempdir().unwrap();
        let (admission, lease, validated, manifest) = binding_fixture();
        initialize_evidence(&root, &manifest.lease_id);
        let mut policy = ProxyPolicy::install(manifest.clone(), &validated).unwrap();
        let body = serde_json::to_vec(
            &serde_json::json!({"Image": manifest.isolation_profile.image_digest}),
        )
        .unwrap();
        let Admission::Create(create) = policy
            .admit(
                buzz_ci_policy_proxy::DockerMethod::Post,
                "/containers/create",
                &body,
            )
            .unwrap()
        else {
            panic!("create admission")
        };
        policy
            .record_created("container-1".into(), &create)
            .unwrap();
        let mut drifted = effective(&manifest);
        drifted.privileged = true;
        assert!(policy.verify_pre_start("container-1", &drifted).is_err());

        let effective = effective(&manifest);
        let proof = policy.verify_pre_start("container-1", &effective).unwrap();
        let mut observer = ProxyLeaseObserver {
            admission,
            lease,
            lease_id: manifest.lease_id.clone(),
            authority: authority(&root),
            store: EvidenceStore::new(root.path().join("evidence")).unwrap(),
            persister: FakePersister {
                fail: true,
                calls: 0,
            },
            clock: FakeClock(VecDeque::from([10])),
            started_object: None,
        };
        assert!(observer
            .observe_pre_start(&create, "container-1", &effective, &proof)
            .is_err());
        assert_eq!(observer.persister.calls, 1);
        assert!(!observer
            .store
            .paths(&manifest.lease_id)
            .unwrap()
            .proxy_object(1)
            .unwrap()
            .exists());
    }

    #[test]
    fn descriptor_identity_mismatch_is_refused() {
        let (admission, lease, validated, manifest) = binding_fixture();
        let mut wrong = admission;
        wrong.attempt += 1;
        assert!(matches!(
            validate_authenticated_binding(wrong, lease, &validated, &manifest),
            Err(ProxyLeaseError::DescriptorIdentity)
        ));

        let mut wrong_manifest = manifest.clone();
        wrong_manifest.request_event_id = "1".repeat(64);
        let (upstream, _runtime) = UnixStream::pair().unwrap();
        let root = tempfile::tempdir().unwrap();
        assert!(matches!(
            build_broker_proxy_lease(
                authority(&root),
                admission,
                lease,
                &validated,
                wrong_manifest,
                upstream,
                FakePersister::default(),
                TransportLimits::default(),
            ),
            Err(ProxyLeaseError::Proxy(ProxyError::InvalidManifest(_)))
        ));
    }

    #[test]
    fn broker_creates_listener_and_binds_one_shot_runtime_descriptor() {
        let root = tempfile::tempdir().unwrap();
        let (admission, lease, validated, manifest) = binding_fixture();
        initialize_evidence(&root, &manifest.lease_id);
        let (upstream, _runtime) = UnixStream::pair().unwrap();
        let mut broker = build_broker_proxy_lease(
            authority(&root),
            admission,
            lease,
            &validated,
            manifest,
            upstream,
            FakePersister::default(),
            TransportLimits::default(),
        )
        .unwrap();
        assert!(fs::metadata(broker.listener_path())
            .unwrap()
            .file_type()
            .is_socket());
        assert_eq!(
            fs::metadata(broker.listener_path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            LISTENER_MODE
        );
        assert!(!broker.is_poisoned());
        let (next, _runtime) = UnixStream::pair().unwrap();
        broker.replace_upstream(lease, next).unwrap();
    }

    #[test]
    fn lease_token_gates_reconciliation_and_listener_removal() {
        let root = tempfile::tempdir().unwrap();
        let (admission, lease, validated, manifest) = binding_fixture();
        initialize_evidence(&root, &manifest.lease_id);
        let (upstream, _runtime) = UnixStream::pair().unwrap();
        let mut broker = build_broker_proxy_lease(
            authority(&root),
            admission,
            lease,
            &validated,
            manifest,
            upstream,
            FakePersister::default(),
            TransportLimits::default(),
        )
        .unwrap();
        let path = broker.listener_path().to_owned();
        let mut wrong = lease;
        wrong = LeaseToken::from_durable(DurableLeaseFields {
            lease_id: wrong.lease_id(),
            run_id: wrong.run_id(),
            attempt: wrong.attempt(),
            signed_request_digest: wrong.signed_request_digest(),
            signer: wrong.signer(),
            generation: wrong.generation() + 1,
            nonce: wrong.nonce(),
            deadline_at: wrong.deadline_at(),
        });
        let retained = BTreeSet::from(["one".into()]);
        let mut unused = runner(vec![]);
        assert!(matches!(
            broker.reconcile(wrong, &mut unused, &retained),
            Err(ProxyLeaseError::DescriptorIdentity)
        ));
        assert!(path.exists());
        let mut cleanup = runner(vec![
            vec![PodmanObject {
                id: "one".into(),
                running: true,
            }],
            vec![],
        ]);
        broker.reconcile(lease, &mut cleanup, &retained).unwrap();
        assert!(!path.exists());
    }
}
