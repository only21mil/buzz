//! Broker-owned policy proxy and rootless Podman lease lifecycle.
//!
//! The builder accepts only an authenticated ordinary admission, its opaque
//! lease token, and a root-validated isolation binding. It creates the proxy
//! listener itself and binds one inherited rootless-runtime descriptor to the
//! resulting capability. The pre-start observer persists seccomp and evidence
//! before the transport can forward Podman's start request.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use buzz_ci_broker_protocol::GitOid;
use buzz_ci_isolation_contract::ValidatedAttemptLeaseBinding;
use buzz_ci_policy_proxy::{
    CanonicalCreate, EffectiveContainerSpec, InheritedOneShotConnector, InheritedProxy,
    LifecycleEvent, LifecycleObserver, PolicyManifest, ProxyError, ProxyPolicy, TransportLimits,
    UpstreamCapability, VerifiedStart,
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::activation::{AdmissionTrustClass, LeaseToken, OrdinaryAdmission};
use crate::evidence::{
    self, CanonicalCreateRequest, CanonicalExecRequest, CiEventBinding, Digest32,
    EffectiveSpecProof, EvidenceStore, OrderingEvent, OrderingRecord, ProxyDecisionReason,
    ProxyDecisionRecord, ProxyObjectRecord, ProxyRoute, ProxyVerdict,
};
use crate::proxy_journal::{
    CanonicalCreateAuthority, ProxyJournalFact, ProxyJournalStore, ProxyJournalStoreError,
    ProxyMutationIntent, ReconcileObject,
};
use crate::seccomp_activation::SeccompInstallCapability;
use crate::seccomp_exec::{persist_oci_prestart_observation, SeccompExecError};

const LISTENER_MODE: u32 = 0o660;
const MAX_LEASE_OBJECTS: usize = 32;
const UPSTREAM_CAPABILITY_DIGEST_DOMAIN: &[u8] = b"buzz-ci/upstream-capability/v1\0";

#[cfg(test)]
thread_local! {
    static FAIL_CONSTRUCTION_AFTER_AUTHORITY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SocketIdentity {
    device: u64,
    inode: u64,
}

impl SocketIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

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
    journal_store: Arc<ProxyJournalStore>,
    event_binding: CiEventBinding,
    upstream_capability_sha256: Digest32,
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
        journal_store: Arc<ProxyJournalStore>,
        upstream_capability_sha256: Digest32,
        persister: P,
    ) -> Result<Self, ProxyLeaseError> {
        let store = EvidenceStore::new(authority.evidence_root.clone())?;
        let event_binding = authority.event_binding;
        Ok(Self {
            admission,
            lease,
            lease_id,
            authority,
            store,
            journal_store,
            event_binding,
            upstream_capability_sha256,
            persister,
            clock: SystemProxyClock,
            started_object: None,
        })
    }
}

impl<P: PrestartPersister, C: ProxyClock> LifecycleObserver for ProxyLeaseObserver<P, C> {
    fn observe_lifecycle(&mut self, event: LifecycleEvent<'_>) -> Result<(), ProxyError> {
        if let LifecycleEvent::Started { container_id } = event {
            if self.started_object.as_deref() != Some(container_id) {
                return Err(ProxyError::StateRefused(
                    "start does not match persisted pre-start evidence".into(),
                ));
            }
        }

        let fact = match event {
            LifecycleEvent::CreateIntent { create } => {
                ProxyJournalFact::create_intent(canonical_create_authority(create)?)
            }
            LifecycleEvent::CreateRejected { create } => {
                ProxyJournalFact::create_rejected(canonical_create_authority(create)?)
            }
            LifecycleEvent::Created {
                create,
                container_id,
            } => ProxyJournalFact::created(
                canonical_create_authority(create)?,
                container_id.to_owned(),
            ),
            LifecycleEvent::StartIntent { container_id } => {
                ProxyJournalFact::start_intent(container_id.to_owned())
            }
            LifecycleEvent::StartRejected { container_id } => {
                ProxyJournalFact::start_rejected(container_id.to_owned())
            }
            LifecycleEvent::Started { container_id } => {
                ProxyJournalFact::started(container_id.to_owned())
            }
            LifecycleEvent::ExecCreateIntent { exec } => {
                ProxyJournalFact::exec_create_intent(exec.container_id().to_owned())
            }
            LifecycleEvent::ExecCreateRejected { exec } => {
                ProxyJournalFact::exec_create_rejected(exec.container_id().to_owned())
            }
            LifecycleEvent::ExecCreated { exec, exec_id } => {
                ProxyJournalFact::exec_created(exec.container_id().to_owned(), exec_id.to_owned())
            }
            LifecycleEvent::DeleteIntent { container_id } => {
                ProxyJournalFact::delete_intent(container_id.to_owned())
            }
            LifecycleEvent::DeleteRejected { container_id } => {
                ProxyJournalFact::delete_rejected(container_id.to_owned())
            }
            LifecycleEvent::Removed { container_id } => {
                ProxyJournalFact::removed(container_id.to_owned())
            }
            LifecycleEvent::Poisoned {
                phase,
                container_id,
            } => ProxyJournalFact::poisoned(phase, container_id.map(str::to_owned))
                .map_err(|_| ProxyError::Transport("proxy journal persistence failed".into()))?,
            _ => {
                return Err(ProxyError::Transport(
                    "unsupported proxy lifecycle journal event".into(),
                ));
            }
        };
        let timestamp = self.journal_timestamp()?;
        self.journal_store
            .append(
                &self.lease_id,
                self.event_binding,
                self.upstream_capability_sha256,
                timestamp,
                fact,
            )
            .map_err(|_| ProxyError::Transport("proxy journal persistence failed".into()))?;

        if let LifecycleEvent::Started { container_id } = event {
            self.store
                .append_ordering(&OrderingRecord {
                    lease_id: self.lease_id.clone(),
                    sequence: 2,
                    event_binding: self.event_binding,
                    event: OrderingEvent::Start,
                    object_id: Some(container_id.to_owned()),
                    timestamp_unix_ns: timestamp,
                    status_event_id: None,
                    verdict_event_id: None,
                })
                .map_err(|_| ProxyError::Transport("proxy start ordering failed".into()))?;
        }
        Ok(())
    }

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
}

impl<P, C> ProxyLeaseObserver<P, C> {
    fn journal_timestamp(&mut self) -> Result<u64, ProxyError>
    where
        C: ProxyClock,
    {
        match self.clock.now_ns() {
            Ok(timestamp) if timestamp != 0 => Ok(timestamp),
            _ => Err(ProxyError::Transport("proxy evidence clock failed".into())),
        }
    }

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
    journal_store: Arc<ProxyJournalStore>,
    lease_id: String,
    event_binding: CiEventBinding,
    recovery_clock: SystemProxyClock,
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

    /// Poll a nonblocking listener once. `false` means no Act connection was
    /// ready and does not consume the installed upstream descriptor.
    pub fn try_serve_once(&mut self) -> Result<bool, ProxyError> {
        self.proxy.try_serve_once()
    }

    /// Select listener blocking mode for a controller-owned bounded poll loop.
    pub fn set_listener_nonblocking(&self, nonblocking: bool) -> Result<(), ProxyError> {
        self.proxy.set_listener_nonblocking(nonblocking)
    }

    /// Report whether the next upstream exchange has a broker descriptor.
    pub fn has_upstream(&self) -> bool {
        self.proxy.has_inherited_upstream()
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
    ) -> Result<(), ProxyLeaseError> {
        if lease != self.lease {
            return Err(ProxyLeaseError::DescriptorIdentity);
        }
        reconcile_podman_objects(
            runner,
            &self.capability,
            &self.journal_store,
            &self.lease_id,
            self.event_binding,
            &mut self.recovery_clock,
        )?;
        match fs::remove_file(&self.listener_path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }
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
    let journal_store = Arc::new(ProxyJournalStore::open(&authority.evidence_root)?);
    build_broker_proxy_lease_with_journal_store(
        authority,
        admission,
        lease,
        validated,
        manifest,
        upstream,
        persister,
        limits,
        journal_store,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_broker_proxy_lease_with_journal_store<P: PrestartPersister>(
    authority: ProxyLeaseAuthority,
    admission: OrdinaryAdmission,
    lease: LeaseToken,
    validated: &ValidatedAttemptLeaseBinding,
    manifest: PolicyManifest,
    upstream: UnixStream,
    persister: P,
    limits: TransportLimits,
    journal_store: Arc<ProxyJournalStore>,
) -> Result<BrokerProxyLease<P>, ProxyLeaseError> {
    validate_authenticated_binding(admission, lease, validated, &manifest)?;
    let policy = ProxyPolicy::install(manifest, validated)?;
    let capability = UpstreamCapability::from_validated_lease(validated);
    if capability.lease_id() != validated.as_binding().lease_id {
        return Err(ProxyLeaseError::DescriptorIdentity);
    }
    let lease_id = validated.as_binding().lease_id.clone();
    let event_binding = authority.event_binding;
    let upstream_capability_sha256 = upstream_capability_digest(&capability);
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
    let journal_creation = journal_store.create_initial(
        validated.as_binding().lease_id.clone(),
        authority.event_binding,
        upstream_capability_sha256,
    )?;
    let mut listener_identity = None;
    let result = (|| {
        let listener = UnixListener::bind(&listener_path)?;
        let created_socket = fs::symlink_metadata(&listener_path)?;
        if !created_socket.file_type().is_socket() {
            return Err(ProxyLeaseError::Authority);
        }
        listener_identity = Some(SocketIdentity::from_metadata(&created_socket));
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
            || SocketIdentity::from_metadata(&socket) != listener_identity.unwrap()
        {
            return Err(ProxyLeaseError::Authority);
        }
        #[cfg(test)]
        FAIL_CONSTRUCTION_AFTER_AUTHORITY.with(|fail| {
            if fail.replace(false) {
                Err(ProxyLeaseError::Authority)
            } else {
                Ok(())
            }
        })?;
        let observer = ProxyLeaseObserver::production(
            admission,
            lease,
            validated.as_binding().lease_id.clone(),
            authority,
            Arc::clone(&journal_store),
            upstream_capability_sha256,
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
            listener_path: listener_path.clone(),
            lease,
            capability,
            journal_store: Arc::clone(&journal_store),
            lease_id,
            event_binding,
            recovery_clock: SystemProxyClock,
            proxy,
        })
    })();
    if result.is_err() {
        let listener_cleanup = listener_identity
            .map(|identity| remove_created_listener(&listener_path, identity))
            .transpose();
        let journal_cleanup = journal_store.remove_created(journal_creation);
        listener_cleanup?;
        journal_cleanup?;
    }
    result
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

/// Reconcile the exact lease-labelled runtime inventory proven by the durable journal.
pub(crate) fn reconcile_podman_objects<R: PodmanReconcileRunner, C: ProxyClock>(
    runner: &mut R,
    capability: &UpstreamCapability,
    journal_store: &Arc<ProxyJournalStore>,
    expected_lease_id: &str,
    expected_event_binding: CiEventBinding,
    clock: &mut C,
) -> Result<(), ProxyLeaseError> {
    if capability.lease_id() != expected_lease_id {
        return Err(ProxyLeaseError::DescriptorIdentity);
    }
    let upstream_capability_sha256 = upstream_capability_digest(capability);
    let mut replay = journal_store.load(
        expected_lease_id,
        expected_event_binding,
        upstream_capability_sha256,
    )?;
    if replay.is_clean_terminal() {
        return Ok(());
    }

    let observed = runner.list(capability)?;
    validate_runtime_inventory(&observed)?;
    replay = append_reconcile_fact(
        journal_store,
        expected_lease_id,
        expected_event_binding,
        upstream_capability_sha256,
        clock,
        ProxyJournalFact::reconcile_inventory(
            observed
                .iter()
                .map(|object| ReconcileObject {
                    id: object.id.clone(),
                    running: object.running,
                })
                .collect(),
        ),
    )?;

    loop {
        match replay.unresolved_intent {
            Some(ProxyMutationIntent::Stop) => {
                let object_id = replay
                    .reconcile
                    .pending_object_id
                    .clone()
                    .ok_or(ProxyLeaseError::Journal)?;
                runner.stop(capability, &object_id)?;
                replay = append_reconcile_fact(
                    journal_store,
                    expected_lease_id,
                    expected_event_binding,
                    upstream_capability_sha256,
                    clock,
                    ProxyJournalFact::stopped(object_id),
                )?;
            }
            Some(ProxyMutationIntent::DeleteObject) => {
                let object_id = replay
                    .reconcile
                    .pending_object_id
                    .clone()
                    .ok_or(ProxyLeaseError::Journal)?;
                runner.delete(capability, &object_id)?;
                replay = append_reconcile_fact(
                    journal_store,
                    expected_lease_id,
                    expected_event_binding,
                    upstream_capability_sha256,
                    clock,
                    ProxyJournalFact::deleted_object(object_id),
                )?;
            }
            Some(_) => return Err(ProxyLeaseError::Journal),
            None => {
                let Some((object_id, running)) = replay
                    .reconcile
                    .current_objects
                    .iter()
                    .next()
                    .map(|(id, running)| (id.clone(), *running))
                else {
                    break;
                };
                if running {
                    replay = append_reconcile_fact(
                        journal_store,
                        expected_lease_id,
                        expected_event_binding,
                        upstream_capability_sha256,
                        clock,
                        ProxyJournalFact::stop_intent(object_id),
                    )?;
                } else {
                    replay = append_reconcile_fact(
                        journal_store,
                        expected_lease_id,
                        expected_event_binding,
                        upstream_capability_sha256,
                        clock,
                        ProxyJournalFact::delete_object_intent(object_id),
                    )?;
                }
            }
        }
    }

    let final_observed = runner.list(capability)?;
    validate_runtime_inventory(&final_observed)?;
    if !final_observed.is_empty() {
        return Err(ProxyLeaseError::ObjectsRemain);
    }
    append_reconcile_fact(
        journal_store,
        expected_lease_id,
        expected_event_binding,
        upstream_capability_sha256,
        clock,
        ProxyJournalFact::reconcile_inventory(Vec::new()),
    )?;
    append_reconcile_fact(
        journal_store,
        expected_lease_id,
        expected_event_binding,
        upstream_capability_sha256,
        clock,
        ProxyJournalFact::reconcile_verified_empty(),
    )?;
    if !journal_store
        .load(
            expected_lease_id,
            expected_event_binding,
            upstream_capability_sha256,
        )?
        .is_clean_terminal()
    {
        return Err(ProxyLeaseError::Journal);
    }
    Ok(())
}

fn append_reconcile_fact<C: ProxyClock>(
    journal_store: &Arc<ProxyJournalStore>,
    lease_id: &str,
    event_binding: CiEventBinding,
    upstream_capability_sha256: Digest32,
    clock: &mut C,
    fact: ProxyJournalFact,
) -> Result<crate::proxy_journal::ProxyJournalReplay, ProxyLeaseError> {
    let timestamp = clock.now_ns()?;
    if timestamp == 0 {
        return Err(ProxyLeaseError::Clock);
    }
    Ok(journal_store.append(
        lease_id,
        event_binding,
        upstream_capability_sha256,
        timestamp,
        fact,
    )?)
}

fn validate_runtime_inventory(objects: &[PodmanObject]) -> Result<(), ProxyLeaseError> {
    let object_ids = objects
        .iter()
        .map(|object| object.id.as_str())
        .collect::<BTreeSet<_>>();
    if objects.len() > MAX_LEASE_OBJECTS
        || objects.len() != object_ids.len()
        || objects.iter().any(|object| !safe_object_id(&object.id))
    {
        return Err(ProxyLeaseError::AmbiguousObjects);
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
    /// Durable lifecycle journal operation failed.
    #[error("durable proxy lifecycle journal operation failed")]
    Journal,
    /// Broker listener filesystem operation failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Broker socket ownership operation failed.
    #[error(transparent)]
    Ownership(#[from] nix::errno::Errno),
}

impl From<ProxyJournalStoreError> for ProxyLeaseError {
    fn from(_error: ProxyJournalStoreError) -> Self {
        Self::Journal
    }
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

fn upstream_capability_digest(capability: &UpstreamCapability) -> Digest32 {
    let mut digest = Sha256::new();
    digest.update(UPSTREAM_CAPABILITY_DIGEST_DOMAIN);
    for field in [
        capability.lease_id().as_bytes(),
        capability.token().as_bytes(),
    ] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field);
    }
    digest.update(capability.runtime_uid().to_be_bytes());
    Digest32(digest.finalize().into())
}

fn remove_created_listener(
    listener_path: &Path,
    expected: SocketIdentity,
) -> Result<(), ProxyLeaseError> {
    let metadata = match fs::symlink_metadata(listener_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_socket() || SocketIdentity::from_metadata(&metadata) != expected {
        return Err(ProxyLeaseError::Authority);
    }
    fs::remove_file(listener_path)?;
    Ok(())
}

fn canonical_create_authority(
    create: &CanonicalCreate,
) -> Result<CanonicalCreateAuthority, ProxyError> {
    CanonicalCreateAuthority::new(
        create.fingerprint.clone(),
        create.target.clone(),
        digest32(&create.body),
    )
    .map_err(|_| ProxyError::Transport("proxy journal persistence failed".into()))
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
    use std::io::Read;
    use std::os::unix::fs::FileTypeExt;
    use std::process::Command;
    use std::time::Duration;

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
    use crate::proxy_journal::ProxyJournal;

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

    struct JournalFailureRunner {
        journal_path: PathBuf,
        actions: Vec<String>,
    }

    impl PodmanReconcileRunner for JournalFailureRunner {
        fn list(
            &mut self,
            _capability: &UpstreamCapability,
        ) -> Result<Vec<PodmanObject>, ProxyLeaseError> {
            self.actions.push("list".into());
            Ok(vec![PodmanObject {
                id: "one".into(),
                running: true,
            }])
        }

        fn stop(
            &mut self,
            _capability: &UpstreamCapability,
            object_id: &str,
        ) -> Result<(), ProxyLeaseError> {
            self.actions.push(format!("stop:{object_id}"));
            fs::set_permissions(&self.journal_path, fs::Permissions::from_mode(0o644))?;
            Ok(())
        }

        fn delete(
            &mut self,
            _capability: &UpstreamCapability,
            object_id: &str,
        ) -> Result<(), ProxyLeaseError> {
            self.actions.push(format!("delete:{object_id}"));
            Ok(())
        }
    }

    fn capability() -> UpstreamCapability {
        let (_, _, validated, _) = binding_fixture();
        UpstreamCapability::from_validated_lease(&validated)
    }

    fn capability_with_runtime(token: char, uid_offset: u32) -> UpstreamCapability {
        let (_, _, validated, _) = binding_fixture_with_runtime(token, uid_offset);
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

    fn recovery_event_binding() -> CiEventBinding {
        CiEventBinding {
            request_event_id_46105: [1; 32],
            teardown_event_id_46106: [2; 32],
        }
    }

    fn recovery_create_authority() -> CanonicalCreateAuthority {
        CanonicalCreateAuthority::new(
            "a".repeat(64),
            "/containers/create?name=recovery".into(),
            Digest32([3; 32]),
        )
        .unwrap()
    }

    // The complete admission fixture below mirrors dns_activation tests. It
    // proves descriptor identity without touching Podman or the host.
    fn binding_fixture() -> (
        OrdinaryAdmission,
        LeaseToken,
        ValidatedAttemptLeaseBinding,
        PolicyManifest,
    ) {
        binding_fixture_with_runtime('2', 0)
    }

    fn binding_fixture_with_runtime(
        runtime_token: char,
        runtime_uid_offset: u32,
    ) -> (
        OrdinaryAdmission,
        LeaseToken,
        ValidatedAttemptLeaseBinding,
        PolicyManifest,
    ) {
        let runtime_uid = nix::unistd::geteuid().as_raw() + runtime_uid_offset;
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
                token: token(runtime_token),
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
            expected_execs: Vec::new(),
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

    fn test_journal_store(root: &TempDir) -> Arc<ProxyJournalStore> {
        Arc::new(
            ProxyJournalStore::open_with_expected_owner(
                root.path().join("evidence"),
                nix::unistd::getuid().as_raw(),
                nix::unistd::getgid().as_raw(),
            )
            .unwrap(),
        )
    }

    fn initialize_journal(
        root: &TempDir,
        lease_id: &str,
        event_binding: CiEventBinding,
    ) -> Arc<ProxyJournalStore> {
        let store = test_journal_store(root);
        store
            .create_initial(
                lease_id.to_owned(),
                event_binding,
                upstream_capability_digest(&capability()),
            )
            .unwrap();
        store
    }

    fn read_journal(root: &TempDir, lease_id: &str) -> ProxyJournal {
        read_journal_at(root.path(), lease_id)
    }

    fn read_journal_at(root: &Path, lease_id: &str) -> ProxyJournal {
        let path = root
            .join("evidence")
            .join(format!("proxy-journal-{lease_id}.json"));
        serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
    }

    fn append_journal_facts(
        store: &Arc<ProxyJournalStore>,
        lease_id: &str,
        event_binding: CiEventBinding,
        facts: impl IntoIterator<Item = ProxyJournalFact>,
    ) {
        for (index, fact) in facts.into_iter().enumerate() {
            store
                .append(
                    lease_id,
                    event_binding,
                    upstream_capability_digest(&capability()),
                    index as u64 + 1,
                    fact,
                )
                .unwrap();
        }
    }

    fn recovery_journal(
        root: &TempDir,
        facts: impl IntoIterator<Item = ProxyJournalFact>,
    ) -> (Arc<ProxyJournalStore>, String, CiEventBinding) {
        let (_, _, _, manifest) = binding_fixture();
        initialize_evidence(root, &manifest.lease_id);
        let event_binding = recovery_event_binding();
        let store = initialize_journal(root, &manifest.lease_id, event_binding);
        append_journal_facts(&store, &manifest.lease_id, event_binding, facts);
        (store, manifest.lease_id, event_binding)
    }

    fn reconcile_recovery(
        fake: &mut FakeRunner,
        store: &Arc<ProxyJournalStore>,
        lease_id: &str,
        event_binding: CiEventBinding,
    ) -> Result<(), ProxyLeaseError> {
        reconcile_podman_objects(
            fake,
            &capability(),
            store,
            lease_id,
            event_binding,
            &mut FakeClock((100..=200).collect()),
        )
    }

    fn journal_facts(root: &TempDir, lease_id: &str) -> Vec<ProxyJournalFact> {
        read_journal(root, lease_id)
            .entries
            .into_iter()
            .map(|entry| entry.fact)
            .collect()
    }

    struct FakeClock(VecDeque<u64>);

    impl ProxyClock for FakeClock {
        fn now_ns(&mut self) -> Result<u64, ProxyLeaseError> {
            self.0.pop_front().ok_or(ProxyLeaseError::Clock)
        }
    }

    #[test]
    fn reconciliation_uses_journal_inventory_and_proves_durable_empty() {
        let root = tempfile::tempdir().unwrap();
        let create = recovery_create_authority();
        let (store, lease_id, event_binding) =
            recovery_journal(&root, [ProxyJournalFact::create_intent(create.clone())]);
        let mut fake = runner(vec![
            vec![PodmanObject {
                id: "one".into(),
                running: true,
            }],
            vec![],
        ]);

        reconcile_recovery(&mut fake, &store, &lease_id, event_binding).unwrap();

        assert_eq!(fake.actions, ["list", "stop:one", "delete:one", "list"]);
        assert_eq!(
            journal_facts(&root, &lease_id),
            [
                ProxyJournalFact::create_intent(create),
                ProxyJournalFact::reconcile_inventory(vec![ReconcileObject {
                    id: "one".into(),
                    running: true,
                }]),
                ProxyJournalFact::stop_intent("one".into()),
                ProxyJournalFact::stopped("one".into()),
                ProxyJournalFact::delete_object_intent("one".into()),
                ProxyJournalFact::deleted_object("one".into()),
                ProxyJournalFact::reconcile_inventory(vec![]),
                ProxyJournalFact::reconcile_verified_empty(),
            ]
        );
        assert!(store
            .load(
                &lease_id,
                event_binding,
                upstream_capability_digest(&capability()),
            )
            .unwrap()
            .is_clean_terminal());
    }

    #[test]
    fn recovery_refuses_same_lease_wrong_token_or_runtime_uid_before_listing() {
        for wrong_capability in [
            capability_with_runtime('6', 0),
            capability_with_runtime('2', 1),
        ] {
            let root = tempfile::tempdir().unwrap();
            let (store, lease_id, event_binding) = recovery_journal(
                &root,
                [ProxyJournalFact::create_intent(recovery_create_authority())],
            );
            let mut fake = runner(vec![vec![]]);

            assert!(matches!(
                reconcile_podman_objects(
                    &mut fake,
                    &wrong_capability,
                    &store,
                    &lease_id,
                    event_binding,
                    &mut FakeClock((100..=200).collect()),
                ),
                Err(ProxyLeaseError::Journal)
            ));
            assert!(fake.actions.is_empty());
        }
    }

    #[test]
    fn journal_header_persists_only_the_upstream_capability_digest() {
        let root = tempfile::tempdir().unwrap();
        let capability = capability();
        let (_store, lease_id, _event_binding) = recovery_journal(&root, []);
        let bytes = fs::read(
            root.path()
                .join("evidence")
                .join(format!("proxy-journal-{lease_id}.json")),
        )
        .unwrap();

        assert!(!bytes
            .windows(capability.token().len())
            .any(|window| window == capability.token().as_bytes()));
        assert_eq!(
            read_journal(&root, &lease_id).upstream_capability_sha256,
            upstream_capability_digest(&capability)
        );
    }

    #[test]
    fn known_id_extra_or_different_inventory_refuses_before_mutation() {
        for observed in [
            vec![PodmanObject {
                id: "other".into(),
                running: true,
            }],
            vec![
                PodmanObject {
                    id: "known".into(),
                    running: true,
                },
                PodmanObject {
                    id: "extra".into(),
                    running: false,
                },
            ],
        ] {
            let root = tempfile::tempdir().unwrap();
            let create = recovery_create_authority();
            let (store, lease_id, event_binding) = recovery_journal(
                &root,
                [
                    ProxyJournalFact::create_intent(create.clone()),
                    ProxyJournalFact::created(create, "known".into()),
                ],
            );
            let mut fake = runner(vec![observed]);

            assert!(matches!(
                reconcile_recovery(&mut fake, &store, &lease_id, event_binding),
                Err(ProxyLeaseError::Journal)
            ));
            assert_eq!(fake.actions, ["list"]);
            assert_eq!(journal_facts(&root, &lease_id).len(), 2);
        }
    }

    #[test]
    fn removed_and_invalid_inventories_refuse_before_mutation() {
        let root = tempfile::tempdir().unwrap();
        let create = recovery_create_authority();
        let (store, lease_id, event_binding) = recovery_journal(
            &root,
            [
                ProxyJournalFact::create_intent(create.clone()),
                ProxyJournalFact::created(create, "known".into()),
                ProxyJournalFact::delete_intent("known".into()),
                ProxyJournalFact::removed("known".into()),
            ],
        );
        let mut removed = runner(vec![vec![PodmanObject {
            id: "known".into(),
            running: false,
        }]]);
        assert!(matches!(
            reconcile_recovery(&mut removed, &store, &lease_id, event_binding),
            Err(ProxyLeaseError::Journal)
        ));
        assert_eq!(removed.actions, ["list"]);

        for observed in [
            vec![
                PodmanObject {
                    id: "duplicate".into(),
                    running: true,
                },
                PodmanObject {
                    id: "duplicate".into(),
                    running: false,
                },
            ],
            vec![PodmanObject {
                id: "bad/id".into(),
                running: true,
            }],
        ] {
            let root = tempfile::tempdir().unwrap();
            let (store, lease_id, event_binding) = recovery_journal(
                &root,
                [ProxyJournalFact::create_intent(recovery_create_authority())],
            );
            let mut invalid = runner(vec![observed]);
            assert!(matches!(
                reconcile_recovery(&mut invalid, &store, &lease_id, event_binding),
                Err(ProxyLeaseError::AmbiguousObjects)
            ));
            assert_eq!(invalid.actions, ["list"]);
        }
    }

    #[test]
    fn crashed_stop_intent_resumes_without_second_intent() {
        let root = tempfile::tempdir().unwrap();
        let (store, lease_id, event_binding) = recovery_journal(
            &root,
            [
                ProxyJournalFact::create_intent(recovery_create_authority()),
                ProxyJournalFact::reconcile_inventory(vec![ReconcileObject {
                    id: "one".into(),
                    running: true,
                }]),
                ProxyJournalFact::stop_intent("one".into()),
            ],
        );
        let mut fake = runner(vec![
            vec![PodmanObject {
                id: "one".into(),
                running: true,
            }],
            vec![],
        ]);

        reconcile_recovery(&mut fake, &store, &lease_id, event_binding).unwrap();

        assert_eq!(fake.actions, ["list", "stop:one", "delete:one", "list"]);
        assert_eq!(
            journal_facts(&root, &lease_id)
                .iter()
                .filter(|fact| matches!(fact, ProxyJournalFact::StopIntent { .. }))
                .count(),
            1
        );
    }

    #[test]
    fn completed_stop_intent_does_not_repeat_stop() {
        for (initial, expected_actions) in [
            (
                vec![PodmanObject {
                    id: "one".into(),
                    running: false,
                }],
                vec!["list", "delete:one", "list"],
            ),
            (vec![], vec!["list", "list"]),
        ] {
            let root = tempfile::tempdir().unwrap();
            let (store, lease_id, event_binding) = recovery_journal(
                &root,
                [
                    ProxyJournalFact::create_intent(recovery_create_authority()),
                    ProxyJournalFact::reconcile_inventory(vec![ReconcileObject {
                        id: "one".into(),
                        running: true,
                    }]),
                    ProxyJournalFact::stop_intent("one".into()),
                ],
            );
            let mut fake = runner(vec![initial, vec![]]);

            reconcile_recovery(&mut fake, &store, &lease_id, event_binding).unwrap();

            assert_eq!(fake.actions, expected_actions);
        }
    }

    #[test]
    fn crashed_delete_intent_resumes_or_accepts_absence_without_second_intent() {
        for (initial, expected_actions) in [
            (
                vec![PodmanObject {
                    id: "one".into(),
                    running: false,
                }],
                vec!["list", "delete:one", "list"],
            ),
            (vec![], vec!["list", "list"]),
        ] {
            let root = tempfile::tempdir().unwrap();
            let (store, lease_id, event_binding) = recovery_journal(
                &root,
                [
                    ProxyJournalFact::create_intent(recovery_create_authority()),
                    ProxyJournalFact::reconcile_inventory(vec![ReconcileObject {
                        id: "one".into(),
                        running: false,
                    }]),
                    ProxyJournalFact::delete_object_intent("one".into()),
                ],
            );
            let mut fake = runner(vec![initial, vec![]]);

            reconcile_recovery(&mut fake, &store, &lease_id, event_binding).unwrap();

            assert_eq!(fake.actions, expected_actions);
            assert_eq!(
                journal_facts(&root, &lease_id)
                    .iter()
                    .filter(|fact| matches!(fact, ProxyJournalFact::DeleteObjectIntent { .. }))
                    .count(),
                1
            );
        }
    }

    fn journal_observer(
        root: &TempDir,
        admission: OrdinaryAdmission,
        lease: LeaseToken,
        lease_id: &str,
    ) -> ProxyLeaseObserver<FakePersister, FakeClock> {
        let authority = authority(root);
        let journal_store = initialize_journal(root, lease_id, authority.event_binding);
        ProxyLeaseObserver {
            admission,
            lease,
            lease_id: lease_id.to_owned(),
            event_binding: authority.event_binding,
            authority,
            store: EvidenceStore::new(root.path().join("evidence")).unwrap(),
            journal_store,
            upstream_capability_sha256: upstream_capability_digest(&capability()),
            persister: FakePersister::default(),
            clock: FakeClock((1..=64).collect()),
            started_object: None,
        }
    }

    #[test]
    fn lifecycle_events_append_one_exact_ordered_journal_fact() {
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
        policy.begin_start(&proof).unwrap();
        policy.commit_started(&proof).unwrap();
        let Admission::ExecCreate(exec) = policy
            .admit(
                buzz_ci_policy_proxy::DockerMethod::Post,
                "/containers/container-1/exec",
                br#"{"Cmd":["true"]}"#,
            )
            .unwrap()
        else {
            panic!("exec admission")
        };

        let mut observer = journal_observer(&root, admission, lease, &manifest.lease_id);
        for event in [
            LifecycleEvent::CreateIntent { create: &create },
            LifecycleEvent::CreateRejected { create: &create },
            LifecycleEvent::CreateIntent { create: &create },
            LifecycleEvent::Created {
                create: &create,
                container_id: "container-1",
            },
        ] {
            observer.observe_lifecycle(event).unwrap();
        }
        observer
            .observe_pre_start(&create, "container-1", &effective, &proof)
            .unwrap();
        for event in [
            LifecycleEvent::StartIntent {
                container_id: "container-1",
            },
            LifecycleEvent::StartRejected {
                container_id: "container-1",
            },
            LifecycleEvent::StartIntent {
                container_id: "container-1",
            },
            LifecycleEvent::Started {
                container_id: "container-1",
            },
            LifecycleEvent::ExecCreateIntent { exec: &exec },
            LifecycleEvent::ExecCreateRejected { exec: &exec },
            LifecycleEvent::ExecCreateIntent { exec: &exec },
            LifecycleEvent::ExecCreated {
                exec: &exec,
                exec_id: "exec-1",
            },
            LifecycleEvent::DeleteIntent {
                container_id: "container-1",
            },
            LifecycleEvent::DeleteRejected {
                container_id: "container-1",
            },
            LifecycleEvent::DeleteIntent {
                container_id: "container-1",
            },
            LifecycleEvent::Removed {
                container_id: "container-1",
            },
        ] {
            observer.observe_lifecycle(event).unwrap();
        }

        let create_authority = canonical_create_authority(&create).unwrap();
        let expected = vec![
            ProxyJournalFact::create_intent(create_authority.clone()),
            ProxyJournalFact::create_rejected(create_authority.clone()),
            ProxyJournalFact::create_intent(create_authority.clone()),
            ProxyJournalFact::created(create_authority, "container-1".into()),
            ProxyJournalFact::start_intent("container-1".into()),
            ProxyJournalFact::start_rejected("container-1".into()),
            ProxyJournalFact::start_intent("container-1".into()),
            ProxyJournalFact::started("container-1".into()),
            ProxyJournalFact::exec_create_intent("container-1".into()),
            ProxyJournalFact::exec_create_rejected("container-1".into()),
            ProxyJournalFact::exec_create_intent("container-1".into()),
            ProxyJournalFact::exec_created("container-1".into(), "exec-1".into()),
            ProxyJournalFact::delete_intent("container-1".into()),
            ProxyJournalFact::delete_rejected("container-1".into()),
            ProxyJournalFact::delete_intent("container-1".into()),
            ProxyJournalFact::removed("container-1".into()),
        ];
        let journal = read_journal(&root, &manifest.lease_id);
        assert_eq!(
            journal
                .entries
                .iter()
                .map(|entry| entry.fact.clone())
                .collect::<Vec<_>>(),
            expected
        );
        assert!(journal
            .entries
            .iter()
            .all(|entry| entry.timestamp_unix_ns != 0));

        let poison_root = tempfile::tempdir().unwrap();
        initialize_evidence(&poison_root, &manifest.lease_id);
        let mut poisoned = journal_observer(&poison_root, admission, lease, &manifest.lease_id);
        poisoned
            .observe_lifecycle(LifecycleEvent::CreateIntent { create: &create })
            .unwrap();
        poisoned
            .observe_lifecycle(LifecycleEvent::Poisoned {
                phase: buzz_ci_policy_proxy::LifecyclePhase::Creating,
                container_id: None,
            })
            .unwrap();
        assert_eq!(
            read_journal(&poison_root, &manifest.lease_id)
                .entries
                .last()
                .unwrap()
                .fact,
            ProxyJournalFact::poisoned(buzz_ci_policy_proxy::LifecyclePhase::Creating, None,)
                .unwrap()
        );

        let bound_poison_root = tempfile::tempdir().unwrap();
        initialize_evidence(&bound_poison_root, &manifest.lease_id);
        let mut bound_poisoned =
            journal_observer(&bound_poison_root, admission, lease, &manifest.lease_id);
        bound_poisoned
            .observe_lifecycle(LifecycleEvent::CreateIntent { create: &create })
            .unwrap();
        bound_poisoned
            .observe_lifecycle(LifecycleEvent::Created {
                create: &create,
                container_id: "container-1",
            })
            .unwrap();
        bound_poisoned.started_object = Some("container-1".into());
        bound_poisoned
            .observe_lifecycle(LifecycleEvent::StartIntent {
                container_id: "container-1",
            })
            .unwrap();
        bound_poisoned
            .observe_lifecycle(LifecycleEvent::Poisoned {
                phase: buzz_ci_policy_proxy::LifecyclePhase::Starting,
                container_id: Some("container-1"),
            })
            .unwrap();
        assert_eq!(
            read_journal(&bound_poison_root, &manifest.lease_id)
                .entries
                .last()
                .unwrap()
                .fact,
            ProxyJournalFact::poisoned(
                buzz_ci_policy_proxy::LifecyclePhase::Starting,
                Some("container-1".into()),
            )
            .unwrap()
        );
    }

    #[test]
    fn journal_initialization_failure_creates_no_listener() {
        let root = tempfile::tempdir().unwrap();
        let (admission, lease, validated, manifest) = binding_fixture();
        initialize_evidence(&root, &manifest.lease_id);
        let authority = authority(&root);
        let listener_path = authority.listener_root.join(format!(
            "proxy-{}-{}.sock",
            hex::encode(lease.lease_id()),
            lease.generation()
        ));
        let journal_store = test_journal_store(&root);
        journal_store
            .create_initial(
                manifest.lease_id.clone(),
                authority.event_binding,
                upstream_capability_digest(&capability()),
            )
            .unwrap();
        let (upstream, _runtime) = UnixStream::pair().unwrap();

        assert!(matches!(
            build_broker_proxy_lease_with_journal_store(
                authority,
                admission,
                lease,
                &validated,
                manifest,
                upstream,
                FakePersister::default(),
                TransportLimits::default(),
                journal_store,
            ),
            Err(ProxyLeaseError::Journal)
        ));
        assert!(!listener_path.exists());
        assert!(root
            .path()
            .join("evidence")
            .join(format!(
                "proxy-journal-{}.json",
                validated.as_binding().lease_id
            ))
            .exists());
    }

    #[test]
    fn started_journal_persistence_precedes_start_ordering_publication() {
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
        let mut observer = journal_observer(&root, admission, lease, &manifest.lease_id);
        observer
            .observe_lifecycle(LifecycleEvent::CreateIntent { create: &create })
            .unwrap();
        observer
            .observe_lifecycle(LifecycleEvent::Created {
                create: &create,
                container_id: "container-1",
            })
            .unwrap();
        observer
            .observe_pre_start(&create, "container-1", &effective, &proof)
            .unwrap();
        observer
            .observe_lifecycle(LifecycleEvent::StartIntent {
                container_id: "container-1",
            })
            .unwrap();
        let ordering = observer.store.paths(&manifest.lease_id).unwrap().ordering;
        fs::remove_file(&ordering).unwrap();
        fs::create_dir(&ordering).unwrap();

        assert!(matches!(
            observer.observe_lifecycle(LifecycleEvent::Started {
                container_id: "container-1",
            }),
            Err(ProxyError::Transport(message)) if message == "proxy start ordering failed"
        ));
        assert!(matches!(
            read_journal(&root, &manifest.lease_id)
                .entries
                .last()
                .unwrap()
                .fact,
            ProxyJournalFact::Started { ref container_id } if container_id == "container-1"
        ));
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
        let authority = authority(&root);
        let journal_store = initialize_journal(&root, &manifest.lease_id, authority.event_binding);
        let mut observer = ProxyLeaseObserver {
            admission,
            lease,
            lease_id: manifest.lease_id.clone(),
            event_binding: authority.event_binding,
            authority,
            store: EvidenceStore::new(root.path().join("evidence")).unwrap(),
            journal_store,
            upstream_capability_sha256: upstream_capability_digest(&capability()),
            persister: FakePersister::default(),
            clock: FakeClock((10..=60).collect()),
            started_object: None,
        };
        observer
            .observe_lifecycle(LifecycleEvent::CreateIntent { create: &create })
            .unwrap();
        observer
            .observe_lifecycle(LifecycleEvent::Created {
                create: &create,
                container_id: "container-1",
            })
            .unwrap();
        observer
            .observe_pre_start(&create, "container-1", &effective, &proof)
            .unwrap();
        observer
            .observe_lifecycle(LifecycleEvent::StartIntent {
                container_id: "container-1",
            })
            .unwrap();
        observer
            .observe_lifecycle(LifecycleEvent::Started {
                container_id: "container-1",
            })
            .unwrap();
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
        let authority = authority(&root);
        let journal_store = initialize_journal(&root, &manifest.lease_id, authority.event_binding);
        let mut observer = ProxyLeaseObserver {
            admission,
            lease,
            lease_id: manifest.lease_id.clone(),
            event_binding: authority.event_binding,
            authority,
            store: EvidenceStore::new(root.path().join("evidence")).unwrap(),
            journal_store,
            upstream_capability_sha256: upstream_capability_digest(&capability()),
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
        initialize_evidence(&root, &manifest.lease_id);
        assert!(matches!(
            build_broker_proxy_lease_with_journal_store(
                authority(&root),
                admission,
                lease,
                &validated,
                wrong_manifest,
                upstream,
                FakePersister::default(),
                TransportLimits::default(),
                test_journal_store(&root),
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
        let mut broker = build_broker_proxy_lease_with_journal_store(
            authority(&root),
            admission,
            lease,
            &validated,
            manifest,
            upstream,
            FakePersister::default(),
            TransportLimits::default(),
            test_journal_store(&root),
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
    fn failed_transport_construction_removes_only_created_authority_and_retries() {
        let root = tempfile::tempdir().unwrap();
        let (admission, lease, validated, manifest) = binding_fixture();
        initialize_evidence(&root, &manifest.lease_id);
        let authority = authority(&root);
        let listener_path = authority.listener_root.join(format!(
            "proxy-{}-{}.sock",
            hex::encode(lease.lease_id()),
            lease.generation()
        ));
        let journal_path = authority
            .evidence_root
            .join(format!("proxy-journal-{}.json", manifest.lease_id));
        let journal_store = test_journal_store(&root);
        let (upstream, _runtime) = UnixStream::pair().unwrap();
        FAIL_CONSTRUCTION_AFTER_AUTHORITY.with(|fail| fail.set(true));

        assert!(matches!(
            build_broker_proxy_lease_with_journal_store(
                authority.clone(),
                admission,
                lease,
                &validated,
                manifest.clone(),
                upstream,
                FakePersister::default(),
                TransportLimits::default(),
                Arc::clone(&journal_store),
            ),
            Err(ProxyLeaseError::Authority)
        ));
        assert!(!listener_path.exists());
        assert!(!journal_path.exists());

        let (upstream, _runtime) = UnixStream::pair().unwrap();
        let broker = build_broker_proxy_lease_with_journal_store(
            authority,
            admission,
            lease,
            &validated,
            manifest,
            upstream,
            FakePersister::default(),
            TransportLimits::default(),
            journal_store,
        )
        .unwrap();
        assert_eq!(broker.listener_path(), listener_path);
        assert!(journal_path.exists());
    }

    #[test]
    fn broker_proxy_install_writes_zero_runtime_bytes() {
        let root = tempfile::tempdir().unwrap();
        let (admission, lease, validated, manifest) = binding_fixture();
        initialize_evidence(&root, &manifest.lease_id);
        let (upstream, mut runtime) = UnixStream::pair().unwrap();
        runtime
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let _broker = build_broker_proxy_lease_with_journal_store(
            authority(&root),
            admission,
            lease,
            &validated,
            manifest,
            upstream,
            FakePersister::default(),
            TransportLimits::default(),
            test_journal_store(&root),
        )
        .unwrap();

        let mut byte = [0_u8; 1];
        assert!(matches!(
            runtime.read(&mut byte),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                )
        ));
    }

    fn build_recovery_broker(
        root: &TempDir,
    ) -> (
        BrokerProxyLease<FakePersister>,
        LeaseToken,
        String,
        CiEventBinding,
    ) {
        let (admission, lease, validated, manifest) = binding_fixture();
        let lease_id = manifest.lease_id.clone();
        initialize_evidence(root, &lease_id);
        let authority = authority(root);
        let event_binding = authority.event_binding;
        let (upstream, _runtime) = UnixStream::pair().unwrap();
        let broker = build_broker_proxy_lease_with_journal_store(
            authority,
            admission,
            lease,
            &validated,
            manifest,
            upstream,
            FakePersister::default(),
            TransportLimits::default(),
            test_journal_store(root),
        )
        .unwrap();
        (broker, lease, lease_id, event_binding)
    }

    fn seed_broker_create_intent(
        broker: &BrokerProxyLease<FakePersister>,
        lease_id: &str,
        event_binding: CiEventBinding,
    ) {
        broker
            .journal_store
            .append(
                lease_id,
                event_binding,
                upstream_capability_digest(&broker.capability),
                1,
                ProxyJournalFact::create_intent(recovery_create_authority()),
            )
            .unwrap();
    }

    #[test]
    fn lease_token_gates_reconciliation_and_listener_removal() {
        let root = tempfile::tempdir().unwrap();
        let (mut broker, lease, lease_id, event_binding) = build_recovery_broker(&root);
        seed_broker_create_intent(&broker, &lease_id, event_binding);
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
        let mut unused = runner(vec![]);
        assert!(matches!(
            broker.reconcile(wrong, &mut unused),
            Err(ProxyLeaseError::DescriptorIdentity)
        ));
        assert!(unused.actions.is_empty());
        assert!(path.exists());
        let mut cleanup = runner(vec![
            vec![PodmanObject {
                id: "one".into(),
                running: true,
            }],
            vec![],
        ]);
        broker.reconcile(lease, &mut cleanup).unwrap();
        assert!(!path.exists());
        assert!(broker
            .journal_store
            .load(
                &lease_id,
                event_binding,
                upstream_capability_digest(&broker.capability),
            )
            .unwrap()
            .is_clean_terminal());
    }

    #[test]
    fn listener_survives_list_stop_delete_storage_and_residue_failures() {
        {
            let root = tempfile::tempdir().unwrap();
            let (mut broker, lease, lease_id, event_binding) = build_recovery_broker(&root);
            seed_broker_create_intent(&broker, &lease_id, event_binding);
            let path = broker.listener_path().to_owned();
            let mut fake = FakeRunner {
                lists: VecDeque::from([Err(ProxyLeaseError::AmbiguousObjects)]),
                stop_fail: false,
                delete_fail: false,
                actions: Vec::new(),
            };
            assert!(matches!(
                broker.reconcile(lease, &mut fake),
                Err(ProxyLeaseError::AmbiguousObjects)
            ));
            assert!(path.exists());
        }

        {
            let root = tempfile::tempdir().unwrap();
            let (mut broker, lease, lease_id, event_binding) = build_recovery_broker(&root);
            seed_broker_create_intent(&broker, &lease_id, event_binding);
            let path = broker.listener_path().to_owned();
            let mut fake = runner(vec![vec![PodmanObject {
                id: "one".into(),
                running: true,
            }]]);
            fake.stop_fail = true;
            assert!(matches!(
                broker.reconcile(lease, &mut fake),
                Err(ProxyLeaseError::Stop)
            ));
            assert!(path.exists());
            assert!(matches!(
                journal_facts(&root, &lease_id).last(),
                Some(ProxyJournalFact::StopIntent { container_id }) if container_id == "one"
            ));
        }

        {
            let root = tempfile::tempdir().unwrap();
            let (mut broker, lease, lease_id, event_binding) = build_recovery_broker(&root);
            seed_broker_create_intent(&broker, &lease_id, event_binding);
            let path = broker.listener_path().to_owned();
            let mut fake = runner(vec![vec![PodmanObject {
                id: "one".into(),
                running: false,
            }]]);
            fake.delete_fail = true;
            assert!(matches!(
                broker.reconcile(lease, &mut fake),
                Err(ProxyLeaseError::Delete)
            ));
            assert!(path.exists());
            assert!(matches!(
                journal_facts(&root, &lease_id).last(),
                Some(ProxyJournalFact::DeleteObjectIntent { object_id }) if object_id == "one"
            ));
        }

        {
            let root = tempfile::tempdir().unwrap();
            let (mut broker, lease, lease_id, event_binding) = build_recovery_broker(&root);
            seed_broker_create_intent(&broker, &lease_id, event_binding);
            let path = broker.listener_path().to_owned();
            let journal_path = root
                .path()
                .join("evidence")
                .join(format!("proxy-journal-{lease_id}.json"));
            let mut fake = JournalFailureRunner {
                journal_path: journal_path.clone(),
                actions: Vec::new(),
            };
            assert!(matches!(
                broker.reconcile(lease, &mut fake),
                Err(ProxyLeaseError::Journal)
            ));
            assert_eq!(fake.actions, ["list", "stop:one"]);
            assert!(path.exists());
            fs::set_permissions(&journal_path, fs::Permissions::from_mode(0o600)).unwrap();
            assert!(matches!(
                journal_facts(&root, &lease_id).last(),
                Some(ProxyJournalFact::StopIntent { container_id }) if container_id == "one"
            ));
        }

        {
            let root = tempfile::tempdir().unwrap();
            let (mut broker, lease, lease_id, event_binding) = build_recovery_broker(&root);
            seed_broker_create_intent(&broker, &lease_id, event_binding);
            let path = broker.listener_path().to_owned();
            let residue = vec![PodmanObject {
                id: "one".into(),
                running: false,
            }];
            let mut fake = runner(vec![
                vec![PodmanObject {
                    id: "one".into(),
                    running: true,
                }],
                residue,
            ]);
            assert!(matches!(
                broker.reconcile(lease, &mut fake),
                Err(ProxyLeaseError::ObjectsRemain)
            ));
            assert!(path.exists());
            assert!(matches!(
                journal_facts(&root, &lease_id).last(),
                Some(ProxyJournalFact::DeletedObject { object_id }) if object_id == "one"
            ));
        }
    }

    #[test]
    fn already_clean_replay_skips_runtime_and_retries_listener_unlink() {
        let root = tempfile::tempdir().unwrap();
        let (mut broker, lease, lease_id, event_binding) = build_recovery_broker(&root);
        append_journal_facts(
            &broker.journal_store,
            &lease_id,
            event_binding,
            [
                ProxyJournalFact::reconcile_inventory(vec![]),
                ProxyJournalFact::reconcile_verified_empty(),
            ],
        );
        let path = broker.listener_path().to_owned();
        let mut unused = runner(vec![]);

        broker.reconcile(lease, &mut unused).unwrap();

        assert!(unused.actions.is_empty());
        assert!(!path.exists());
    }

    #[test]
    fn journal_restart_process() {
        let Some(root) = std::env::var_os("BUZZ_PROXY_JOURNAL_RESTART_ROOT") else {
            return;
        };
        let phase = std::env::var("BUZZ_PROXY_JOURNAL_RESTART_PHASE").unwrap();
        let root = PathBuf::from(root);
        assert_eq!(
            fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let evidence_root = root.join("evidence");
        let (_, _, _, manifest) = binding_fixture();
        let event_binding = recovery_event_binding();
        if phase == "write" {
            fs::create_dir(&evidence_root).unwrap();
            fs::set_permissions(&evidence_root, fs::Permissions::from_mode(0o700)).unwrap();
            let store = ProxyJournalStore::open_with_expected_owner(
                &evidence_root,
                nix::unistd::getuid().as_raw(),
                nix::unistd::getgid().as_raw(),
            )
            .unwrap();
            store
                .create_initial(
                    manifest.lease_id.clone(),
                    event_binding,
                    upstream_capability_digest(&capability()),
                )
                .unwrap();
            store
                .append(
                    &manifest.lease_id,
                    event_binding,
                    upstream_capability_digest(&capability()),
                    1,
                    ProxyJournalFact::create_intent(recovery_create_authority()),
                )
                .unwrap();
            std::process::exit(86);
        }

        assert_eq!(phase, "recover");
        let store = Arc::new(
            ProxyJournalStore::open_with_expected_owner(
                &evidence_root,
                nix::unistd::getuid().as_raw(),
                nix::unistd::getgid().as_raw(),
            )
            .unwrap(),
        );
        let mut fake = runner(vec![
            vec![PodmanObject {
                id: "orphan".into(),
                running: true,
            }],
            vec![],
        ]);
        reconcile_podman_objects(
            &mut fake,
            &capability(),
            &store,
            &manifest.lease_id,
            event_binding,
            &mut FakeClock((100..=200).collect()),
        )
        .unwrap();
        assert_eq!(
            fake.actions,
            ["list", "stop:orphan", "delete:orphan", "list"]
        );
    }

    #[test]
    fn fresh_process_create_intent_reopens_and_reconciles() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let status = Command::new(std::env::current_exe().unwrap())
            .env_clear()
            .env("BUZZ_PROXY_JOURNAL_RESTART_ROOT", root.path())
            .env("BUZZ_PROXY_JOURNAL_RESTART_PHASE", "write")
            .arg("--exact")
            .arg("proxy_lease::tests::journal_restart_process")
            .arg("--nocapture")
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(86));
        assert_eq!(
            fs::metadata(root.path()).unwrap().permissions().mode() & 0o777,
            0o700
        );

        let status = Command::new(std::env::current_exe().unwrap())
            .env_clear()
            .env("BUZZ_PROXY_JOURNAL_RESTART_ROOT", root.path())
            .env("BUZZ_PROXY_JOURNAL_RESTART_PHASE", "recover")
            .arg("--exact")
            .arg("proxy_lease::tests::journal_restart_process")
            .arg("--nocapture")
            .status()
            .unwrap();
        assert!(status.success());

        let (_, _, _, manifest) = binding_fixture();
        let lease_id = manifest.lease_id;
        assert_eq!(
            read_journal_at(root.path(), &lease_id)
                .entries
                .into_iter()
                .map(|entry| entry.fact)
                .collect::<Vec<_>>(),
            [
                ProxyJournalFact::create_intent(recovery_create_authority()),
                ProxyJournalFact::reconcile_inventory(vec![ReconcileObject {
                    id: "orphan".into(),
                    running: true,
                }]),
                ProxyJournalFact::stop_intent("orphan".into()),
                ProxyJournalFact::stopped("orphan".into()),
                ProxyJournalFact::delete_object_intent("orphan".into()),
                ProxyJournalFact::deleted_object("orphan".into()),
                ProxyJournalFact::reconcile_inventory(vec![]),
                ProxyJournalFact::reconcile_verified_empty(),
            ]
        );
    }
}
