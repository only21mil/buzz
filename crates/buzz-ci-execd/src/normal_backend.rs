//! Production composition for the closed normal execution lifecycle.
//!
//! Existing host implementations are wired directly. The remaining host
//! handoffs stay behind narrow traits so the backend remains unavailable until
//! their reviewed implementations land.

use std::fs::{self, File};
use std::io::Read;
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use buzz_ci_isolation_contract::ValidatedAttemptLeaseBinding;
use buzz_ci_materializer::{
    execute_materialization, CleanupProof, CommandExecution, CommandOutput, CommandSpec,
    ConfinedGitProcessResult, GitBackend, GitCommandLog, GitCommandResultLog, GitHostObserver,
    MaterializationManifest, MaterializationSlot, PendingSeal, RootOwnedPolicy, Sha256Digest,
};
use buzz_ci_policy_proxy::{
    AllowedMount, ExecExpectation, IsolationProfile, PolicyManifest, TransportLimits,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::activation::{LeaseToken, OrdinaryAdmission};
use crate::dns_activation::DnsLeaseLifecycle;
use crate::dns_exec::{MaterializerCommandPlan, MaterializerHandoffBinding, ProcessCommandRunner};
use crate::durable_dispatch::{ExecutionUnavailable, OrdinaryStop};
use crate::evidence::{DnsReadback, EvidenceStore};
use crate::materializer_evidence::{publish_materializer_evidence, MaterializerEvidenceContext};
use crate::materializer_handoff::execute_materializer_handoff;
use crate::normal_engine::{
    ActLaunchPlan, NormalExecutionBackend, NormalJobPlan, NormalReconcileEvidence,
    NormalTerminalEvidence,
};
use crate::proxy_lease::{
    build_broker_proxy_lease, BrokerProxyLease, PodmanReconcileRunner, PrestartPersister,
    ProxyLeaseAuthority,
};

const MAX_CANONICAL_JOB_MANIFEST_BYTES: usize = 4 * 1024 * 1024;
const ACT_PROXY_ARCHIVE_BYTES: usize = 64 * 1024 * 1024;
const ACT_PROXY_IO_TIMEOUT: Duration = Duration::from_secs(30);

/// Fixed attempt-scoped ceilings used by the integrated archive and hijack
/// mediators. The broker input source cannot widen them.
pub const fn normal_act_transport_limits() -> TransportLimits {
    TransportLimits {
        request_body_bytes: ACT_PROXY_ARCHIVE_BYTES,
        response_body_bytes: ACT_PROXY_ARCHIVE_BYTES,
        io_timeout: ACT_PROXY_IO_TIMEOUT,
    }
}

/// Canonical signed job-manifest projection that owns Docker exec classes.
///
/// The broker source supplies these exact bytes from the signed manifest
/// store. The proxy manifest accepts no pre-populated expectations and binds
/// this projection by SHA-256 plus every attempt identity coordinate.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalExecManifest {
    /// Frozen projection schema.
    pub schema_version: u16,
    /// Accepted request event identity.
    pub request_event_id: String,
    /// Run identity.
    pub run_id: String,
    /// Repository coordinate.
    pub target_repo_a: String,
    /// Exact source object ID.
    pub sha: String,
    /// Exact trusted base object ID.
    pub base_oid: String,
    /// Static workflow identity.
    pub workflow_id: String,
    /// Trusted workflow digest.
    pub workflow_digest: String,
    /// Static job identity.
    pub job_id: String,
    /// One-based attempt number.
    pub attempt: u32,
    /// Attempt lease identity.
    pub lease_id: String,
    /// Exact runtime isolation policy copied from the signed job.
    pub isolation_profile: IsolationProfile,
    /// Exact container principal copied from the signed job.
    pub container_user: String,
    /// Exact broker-enumerated mounts copied from the signed job.
    pub mounts: Vec<AllowedMount>,
    /// Exact non-secret caller environment names.
    pub allowed_environment: Vec<String>,
    /// Exact exec classes derived while canonicalizing the signed job.
    pub expected_execs: Vec<ExecExpectation>,
}

/// Fail-closed reason for refusing an expected-exec source.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ExpectedExecSourceError {
    /// The policy input already carried operator-supplied expectations.
    #[error("policy manifest carried unbound exec expectations")]
    Prepopulated,
    /// The canonical source was absent or outside its byte ceiling.
    #[error("canonical expected-exec source is unavailable")]
    Unavailable,
    /// Source bytes were not the one canonical JSON encoding.
    #[error("canonical expected-exec source is malformed")]
    Malformed,
    /// Source bytes did not match the signed job-manifest digest.
    #[error("canonical expected-exec source digest does not match")]
    DigestMismatch,
    /// Source identity differed from the admitted proxy manifest.
    #[error("canonical expected-exec source identity does not match")]
    IdentityMismatch,
    /// Pinned Act cannot run without at least one signed exec class.
    #[error("canonical expected-exec source grants no exec class")]
    Empty,
}

/// Populate the proxy contract only from canonical, digest-bound job bytes.
pub fn populate_expected_execs(
    manifest: &mut PolicyManifest,
    canonical_job_manifest: &[u8],
) -> Result<(), ExpectedExecSourceError> {
    if !manifest.expected_execs.is_empty() {
        return Err(ExpectedExecSourceError::Prepopulated);
    }
    if canonical_job_manifest.is_empty()
        || canonical_job_manifest.len() > MAX_CANONICAL_JOB_MANIFEST_BYTES
    {
        return Err(ExpectedExecSourceError::Unavailable);
    }
    let expected_digest = manifest
        .manifest_digest
        .strip_prefix("sha256:")
        .ok_or(ExpectedExecSourceError::DigestMismatch)?;
    if hex::encode(Sha256::digest(canonical_job_manifest)) != expected_digest {
        return Err(ExpectedExecSourceError::DigestMismatch);
    }
    let canonical: CanonicalExecManifest = serde_json::from_slice(canonical_job_manifest)
        .map_err(|_| ExpectedExecSourceError::Malformed)?;
    if serde_json::to_vec(&canonical).map_err(|_| ExpectedExecSourceError::Malformed)?
        != canonical_job_manifest
    {
        return Err(ExpectedExecSourceError::Malformed);
    }
    if canonical.schema_version != 1
        || canonical.request_event_id != manifest.request_event_id
        || canonical.run_id != manifest.run_id
        || canonical.target_repo_a != manifest.target_repo_a
        || canonical.sha != manifest.sha
        || canonical.base_oid != manifest.base_oid
        || canonical.workflow_id != manifest.workflow_id
        || canonical.workflow_digest != manifest.workflow_digest
        || canonical.job_id != manifest.job_id
        || canonical.attempt != manifest.attempt
        || canonical.lease_id != manifest.lease_id
        || canonical.isolation_profile != manifest.isolation_profile
        || canonical.container_user != manifest.container_user
        || canonical.mounts != manifest.mounts
        || canonical.allowed_environment != manifest.allowed_environment
    {
        return Err(ExpectedExecSourceError::IdentityMismatch);
    }
    if canonical.expected_execs.is_empty() {
        return Err(ExpectedExecSourceError::Empty);
    }
    manifest.expected_execs = canonical.expected_execs;
    manifest
        .validate()
        .map_err(|_| ExpectedExecSourceError::Malformed)
}

/// DNS operations used by the production normal backend.
pub trait NormalDnsLifecycle {
    /// Refuse a new attempt while an earlier DNS lease remains retained.
    fn preflight(&mut self) -> Result<(), ExecutionUnavailable>;

    /// Apply and retain the exact admitted DNS lease.
    fn apply(
        &mut self,
        admission: OrdinaryAdmission,
        lease: LeaseToken,
    ) -> Result<DnsReadback, ExecutionUnavailable>;

    /// Tear down the exact retained DNS lease.
    fn reconcile(&mut self, lease: LeaseToken) -> Result<(), ExecutionUnavailable>;
}

impl NormalDnsLifecycle for DnsLeaseLifecycle<ProcessCommandRunner> {
    fn preflight(&mut self) -> Result<(), ExecutionUnavailable> {
        if self.active().is_some() {
            return Err(ExecutionUnavailable);
        }
        Ok(())
    }

    fn apply(
        &mut self,
        admission: OrdinaryAdmission,
        lease: LeaseToken,
    ) -> Result<DnsReadback, ExecutionUnavailable> {
        let observed_at_unix_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ExecutionUnavailable)?
            .as_nanos()
            .try_into()
            .map_err(|_| ExecutionUnavailable)?;
        DnsLeaseLifecycle::apply(self, admission, lease, observed_at_unix_ns)
            .map(|retained| retained.evidence())
            .map_err(|_| ExecutionUnavailable)
    }

    fn reconcile(&mut self, lease: LeaseToken) -> Result<(), ExecutionUnavailable> {
        DnsLeaseLifecycle::reconcile(self, lease)
            .map(|_retained| ())
            .map_err(|_| ExecutionUnavailable)
    }
}

/// Root-owned inputs needed to execute one materialization.
pub struct NormalMaterializationInputs {
    /// Signed manifest already matched to the admitted attempt.
    pub manifest: MaterializationManifest,
    /// Canonical broker-supplied, non-secret input bytes.
    pub canonical_inputs: Vec<u8>,
    /// Root-owned origin and resource policy.
    pub policy: RootOwnedPolicy,
    /// Open descriptor for the broker-created workspace.
    pub workspace_directory: File,
    /// Exact authenticated descriptor-handoff binding for the retained unit.
    pub handoff: MaterializerHandoffBinding,
    /// Broker-owned evidence fields not claimed by the materializer.
    pub evidence_context: MaterializerEvidenceContext,
}

/// Root-owned source for materialization inputs and descriptor-bound cleanup.
pub trait NormalMaterializationSource {
    /// Validate that inputs exist for this exact plan without consuming them.
    fn preflight(
        &mut self,
        plan: &NormalJobPlan,
        binding: &ValidatedAttemptLeaseBinding,
    ) -> Result<(), ExecutionUnavailable>;

    /// Open one fresh set of inputs for the exact validated lease.
    fn prepare(
        &mut self,
        plan: &NormalJobPlan,
        binding: &ValidatedAttemptLeaseBinding,
    ) -> Result<NormalMaterializationInputs, ExecutionUnavailable>;

    /// Remove only the workspace retained by the pending-seal capability.
    fn reconcile(
        &mut self,
        lease: LeaseToken,
        stop: OrdinaryStop,
        pending: &PendingSeal,
    ) -> Result<(), ExecutionUnavailable>;
}

/// Materialization lifecycle consumed by the production backend.
pub trait NormalMaterializer {
    /// Validate one exact materialization before lease commitment.
    fn preflight(
        &mut self,
        plan: &NormalJobPlan,
        binding: &ValidatedAttemptLeaseBinding,
    ) -> Result<(), ExecutionUnavailable>;

    /// Execute materialization and publish its translated durable evidence.
    fn materialize(
        &mut self,
        plan: &NormalJobPlan,
        binding: &ValidatedAttemptLeaseBinding,
        store: &EvidenceStore,
    ) -> Result<(), ExecutionUnavailable>;

    /// Reconcile the retained workspace capability.
    fn reconcile(
        &mut self,
        lease: LeaseToken,
        stop: OrdinaryStop,
    ) -> Result<(), ExecutionUnavailable>;
}

/// Injectable client for the authenticated B4 descriptor handoff.
pub trait MaterializerHandoffClient {
    /// Execute one already-validated command in the confined materializer unit.
    fn execute(
        &mut self,
        plan: &MaterializerCommandPlan,
        workspace_directory: &File,
    ) -> Result<ConfinedGitProcessResult, String>;
}

/// Production Unix-socket and `SCM_RIGHTS` client for the B4 shim.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProductionMaterializerHandoffClient;

impl MaterializerHandoffClient for ProductionMaterializerHandoffClient {
    fn execute(
        &mut self,
        plan: &MaterializerCommandPlan,
        workspace_directory: &File,
    ) -> Result<ConfinedGitProcessResult, String> {
        execute_materializer_handoff(plan, workspace_directory).map_err(|error| error.to_string())
    }
}

/// Credential-free materializer using B4's confined shim and B1's root observer.
pub struct HandoffNormalMaterializer<O, S, C = ProductionMaterializerHandoffClient> {
    observer: Option<O>,
    source: S,
    client: C,
    pending: Option<PendingSeal>,
}

impl<O, S, C> HandoffNormalMaterializer<O, S, C> {
    /// Retain the observer, root-owned input source, and bounded handoff client.
    pub fn new(observer: O, source: S, client: C) -> Self {
        Self {
            observer: Some(observer),
            source,
            client,
            pending: None,
        }
    }
}

struct HandoffGitBackend<'a, O, C> {
    observer: &'a mut O,
    handoff: MaterializerHandoffBinding,
    client: &'a mut C,
    command_logs: Vec<GitCommandLog>,
}

impl<O: GitHostObserver, C: MaterializerHandoffClient> GitBackend for HandoffGitBackend<'_, O, C> {
    fn now_unix_seconds(&self) -> u64 {
        unix_time().0
    }

    fn run(&mut self, command: &CommandSpec, workspace_directory: &File) -> CommandExecution {
        let failed_cleanup = || CleanupProof {
            lease_id: command.lease_id.clone(),
            cgroup_token: command.cgroup_token.clone(),
            netns_token: command.netns_token.clone(),
            descendants_empty: false,
            completed_at_unix_seconds: unix_time().0,
        };
        let command_plan = match self.handoff.command_plan(command) {
            Ok(plan) => plan,
            Err(error) => {
                return CommandExecution {
                    output: Err(error.to_string()),
                    cleanup: failed_cleanup(),
                }
            }
        };
        let checkpoint = match self.observer.before_command(command) {
            Ok(checkpoint) => checkpoint,
            Err(error) => {
                return CommandExecution {
                    output: Err(bounded_diagnostic(&error)),
                    cleanup: failed_cleanup(),
                }
            }
        };
        let started_at_unix_ns = unix_time().1;
        let process = self.client.execute(&command_plan, workspace_directory);
        let finished_at_unix_ns = unix_time().1.max(started_at_unix_ns);
        let process_group_empty = process
            .as_ref()
            .is_ok_and(|result| result.process_group_empty);
        let observation = self
            .observer
            .after_command(checkpoint, command, process_group_empty);
        if let Ok(result) = &process {
            self.command_logs.push(GitCommandLog {
                sequence: self.command_logs.len() as u64 + 1,
                command: command.clone(),
                result: GitCommandResultLog {
                    exit_code: result.exit_code,
                    timed_out: result.timed_out,
                    stdout_sha256: digest_bytes(&result.stdout),
                    stderr_sha256: digest_bytes(&result.stderr),
                    stdout_bytes: result.stdout_observed_bytes,
                    stderr_bytes: result.stderr_observed_bytes,
                    stdout_truncated: result.stdout_truncated,
                    stderr_truncated: result.stderr_truncated,
                },
                started_at_unix_ns,
                finished_at_unix_ns,
            });
        }
        let observation = match observation {
            Ok(observation) => observation,
            Err(error) => {
                return CommandExecution {
                    output: Err(bounded_diagnostic(&error)),
                    cleanup: failed_cleanup(),
                }
            }
        };
        let cleanup = CleanupProof {
            lease_id: command.lease_id.clone(),
            cgroup_token: command.cgroup_token.clone(),
            netns_token: command.netns_token.clone(),
            descendants_empty: process_group_empty && observation.cgroup_descendants_empty,
            completed_at_unix_seconds: observation.completed_at_unix_seconds,
        };
        let result = match process {
            Ok(result) => result,
            Err(error) => {
                return CommandExecution {
                    output: Err(bounded_diagnostic(&error)),
                    cleanup,
                }
            }
        };
        let output = handoff_output(command, result, observation.network_bytes);
        CommandExecution { output, cleanup }
    }
}

impl<O: GitHostObserver, S: NormalMaterializationSource, C: MaterializerHandoffClient>
    NormalMaterializer for HandoffNormalMaterializer<O, S, C>
{
    fn preflight(
        &mut self,
        plan: &NormalJobPlan,
        binding: &ValidatedAttemptLeaseBinding,
    ) -> Result<(), ExecutionUnavailable> {
        if self.observer.is_none() || self.pending.is_some() {
            return Err(ExecutionUnavailable);
        }
        self.source.preflight(plan, binding)
    }

    fn materialize(
        &mut self,
        plan: &NormalJobPlan,
        binding: &ValidatedAttemptLeaseBinding,
        store: &EvidenceStore,
    ) -> Result<(), ExecutionUnavailable> {
        if self.pending.is_some() {
            return Err(ExecutionUnavailable);
        }
        let inputs = self.source.prepare(plan, binding)?;
        let slot = MaterializationSlot::from_lease(binding.clone(), inputs.workspace_directory)
            .map_err(|_| ExecutionUnavailable)?;
        let observer = self.observer.as_mut().ok_or(ExecutionUnavailable)?;
        let mut backend = HandoffGitBackend {
            observer,
            handoff: inputs.handoff,
            client: &mut self.client,
            command_logs: Vec::new(),
        };
        let result = execute_materialization(
            &inputs.manifest,
            &inputs.canonical_inputs,
            &inputs.policy,
            slot,
            &mut backend,
        );
        let command_logs = backend.command_logs;
        self.pending = Some(result.map_err(|_| ExecutionUnavailable)?);
        let receipt = self
            .pending
            .as_ref()
            .map(PendingSeal::receipt)
            .ok_or(ExecutionUnavailable)?;
        publish_materializer_evidence(store, receipt, &command_logs, inputs.evidence_context)
            .map_err(|_| ExecutionUnavailable)?;
        Ok(())
    }

    fn reconcile(
        &mut self,
        lease: LeaseToken,
        stop: OrdinaryStop,
    ) -> Result<(), ExecutionUnavailable> {
        let pending = self.pending.as_ref().ok_or(ExecutionUnavailable)?;
        self.source.reconcile(lease, stop, pending)?;
        self.pending = None;
        Ok(())
    }
}

fn unix_time() -> (u64, u64) {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| {
            (
                elapsed.as_secs(),
                u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX),
            )
        })
        .unwrap_or((u64::MAX, 0))
}

fn digest_bytes(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::digest(bytes)
}

fn bounded_diagnostic(value: &str) -> String {
    value.chars().take(8_192).collect()
}

fn handoff_output(
    command: &CommandSpec,
    result: ConfinedGitProcessResult,
    network_bytes: u64,
) -> Result<CommandOutput, String> {
    if result.timed_out || result.elapsed_millis > command.deadline_millis {
        return Err("Git command exceeded its timeout".into());
    }
    if result.stdout_truncated || result.stderr_truncated {
        return Err("Git command output exceeded its byte ceiling".into());
    }
    if result.exit_code != Some(0) {
        return Err(bounded_diagnostic(&format!(
            "Git exited nonzero: {}",
            String::from_utf8_lossy(&result.stderr)
        )));
    }
    if !result.process_group_empty {
        return Err("Git process group remained live after cleanup".into());
    }
    Ok(CommandOutput {
        success: true,
        stdout: result.stdout,
        stderr: result.stderr,
        network_bytes,
        elapsed_millis: result.elapsed_millis,
        effective_uid: command.required_uid,
    })
}

/// Typed reason that Act cannot be launched through the proxy.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ActProxyLaunchError {
    /// Proxy construction, supervision, or the child process failed closed.
    #[error("Act proxy launch failed closed")]
    Unavailable,
}

/// Concurrent supervisor for pinned Act and one broker proxy lease.
pub trait ActThroughProxyLauncher<P: PrestartPersister> {
    /// Fail before listener creation when the reviewed mediator set is absent.
    fn readiness(&self) -> Result<(), ActProxyLaunchError>;

    /// Run Act with the exact launch plan while serving its proxy exchanges.
    fn launch(
        &mut self,
        lease: LeaseToken,
        plan: &ActLaunchPlan,
        binding: &ValidatedAttemptLeaseBinding,
        proxy: &mut BrokerProxyLease<P>,
    ) -> Result<(), ActProxyLaunchError>;
}

/// Root-owned source of fresh one-shot Podman connections for Act exchanges.
pub trait ActRuntimeDescriptorSource {
    /// Open one exact lease-bound descriptor before the next upstream exchange.
    fn next_upstream(
        &mut self,
        lease: LeaseToken,
        deadline: Instant,
    ) -> Result<UnixStream, ActProxyLaunchError>;
}

/// Child process contract used by the bounded Act supervisor.
pub trait ActChild {
    /// Poll without blocking.
    fn try_wait(&mut self) -> Result<Option<ExitStatus>, ActProxyLaunchError>;

    /// Stop the exact transient unit and reap its controller process.
    fn stop_and_reap(&mut self) -> Result<(), ActProxyLaunchError>;
}

/// Exact transient-unit process start seam.
pub trait ActProcessSpawner {
    /// Concrete child controller.
    type Child: ActChild;

    /// Start the pinned plan as the validated executor principal.
    fn spawn(
        &mut self,
        plan: &ActLaunchPlan,
        binding: &ValidatedAttemptLeaseBinding,
    ) -> Result<Self::Child, ActProxyLaunchError>;
}

/// Production no-shell `systemd-run` launcher for the exact Act unit.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemdActProcessSpawner;

/// Controller child for one exact transient Act unit.
pub struct SystemdActChild {
    child: Child,
    unit: String,
}

impl ActChild for SystemdActChild {
    fn try_wait(&mut self) -> Result<Option<ExitStatus>, ActProxyLaunchError> {
        self.child
            .try_wait()
            .map_err(|_| ActProxyLaunchError::Unavailable)
    }

    fn stop_and_reap(&mut self) -> Result<(), ActProxyLaunchError> {
        let status = Command::new("/usr/bin/systemctl")
            .arg("stop")
            .arg(&self.unit)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|_| ActProxyLaunchError::Unavailable)?;
        let reaped = self
            .child
            .wait()
            .map_err(|_| ActProxyLaunchError::Unavailable)?;
        if status.success() && reaped.success() {
            Ok(())
        } else {
            Err(ActProxyLaunchError::Unavailable)
        }
    }
}

impl ActProcessSpawner for SystemdActProcessSpawner {
    type Child = SystemdActChild;

    fn spawn(
        &mut self,
        plan: &ActLaunchPlan,
        binding: &ValidatedAttemptLeaseBinding,
    ) -> Result<Self::Child, ActProxyLaunchError> {
        verify_act_binary(plan)?;
        let argv = plan.argv().map_err(|_| ActProxyLaunchError::Unavailable)?;
        let environment = plan
            .environment()
            .map_err(|_| ActProxyLaunchError::Unavailable)?;
        let executor_uid = binding.as_binding().principals.executor;
        let mut command = Command::new("/usr/bin/systemd-run");
        command
            .arg("--quiet")
            .arg("--wait")
            .arg("--collect")
            .arg("--service-type=exec")
            .arg(format!("--unit={}", plan.executor_unit))
            .arg(format!("--slice={}", plan.lease_slice))
            .arg(format!("--uid={executor_uid}"))
            .arg(format!(
                "--working-directory={}",
                plan.working_directory.display()
            ))
            .arg("--property=NoNewPrivileges=yes")
            .arg("--property=PrivateTmp=yes");
        for (name, value) in environment {
            command.arg(format!("--setenv={name}={value}"));
        }
        command
            .arg("--")
            .arg(&plan.binary)
            .args(argv)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = command
            .spawn()
            .map_err(|_| ActProxyLaunchError::Unavailable)?;
        Ok(SystemdActChild {
            child,
            unit: plan.executor_unit.clone(),
        })
    }
}

/// Bounded production supervisor using both reviewed proxy mediators.
pub struct MediatedActThroughProxyLauncher<D, S = SystemdActProcessSpawner> {
    descriptors: D,
    spawner: S,
    maximum_exchanges: usize,
    poll_interval: Duration,
}

impl<D> MediatedActThroughProxyLauncher<D, SystemdActProcessSpawner> {
    /// Construct the production supervisor with fixed polling bounds.
    pub fn production(descriptors: D) -> Self {
        Self {
            descriptors,
            spawner: SystemdActProcessSpawner,
            maximum_exchanges: 4096,
            poll_interval: Duration::from_millis(5),
        }
    }
}

impl<P, D, S> ActThroughProxyLauncher<P> for MediatedActThroughProxyLauncher<D, S>
where
    P: PrestartPersister,
    D: ActRuntimeDescriptorSource,
    S: ActProcessSpawner,
{
    fn readiness(&self) -> Result<(), ActProxyLaunchError> {
        if self.maximum_exchanges == 0 || self.poll_interval.is_zero() {
            Err(ActProxyLaunchError::Unavailable)
        } else {
            Ok(())
        }
    }

    fn launch(
        &mut self,
        lease: LeaseToken,
        plan: &ActLaunchPlan,
        binding: &ValidatedAttemptLeaseBinding,
        proxy: &mut BrokerProxyLease<P>,
    ) -> Result<(), ActProxyLaunchError> {
        <Self as ActThroughProxyLauncher<P>>::readiness(self)?;
        if proxy.listener_path() != plan.proxy_socket {
            return Err(ActProxyLaunchError::Unavailable);
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ActProxyLaunchError::Unavailable)?;
        let remaining = binding
            .as_binding()
            .expires_at_unix_seconds
            .checked_sub(now.as_secs())
            .filter(|seconds| *seconds > 0)
            .ok_or(ActProxyLaunchError::Unavailable)?;
        let deadline = Instant::now() + Duration::from_secs(remaining);
        let mut child = self.spawner.spawn(plan, binding)?;
        proxy
            .set_listener_nonblocking(true)
            .map_err(|_| ActProxyLaunchError::Unavailable)?;
        let outcome = self.drive(lease, deadline, &mut child, proxy);
        if outcome.is_err() {
            let _ = child.stop_and_reap();
        }
        outcome
    }
}

impl<D: ActRuntimeDescriptorSource, S: ActProcessSpawner> MediatedActThroughProxyLauncher<D, S> {
    fn drive<P: PrestartPersister>(
        &mut self,
        lease: LeaseToken,
        deadline: Instant,
        child: &mut S::Child,
        proxy: &mut BrokerProxyLease<P>,
    ) -> Result<(), ActProxyLaunchError> {
        let mut exchanges = 0_usize;
        loop {
            if Instant::now() >= deadline {
                return Err(ActProxyLaunchError::Unavailable);
            }
            if let Some(status) = child.try_wait()? {
                return if status.success() && !proxy.is_poisoned() && exchanges > 0 {
                    Ok(())
                } else {
                    Err(ActProxyLaunchError::Unavailable)
                };
            }
            if !proxy.has_upstream() {
                let upstream = self.descriptors.next_upstream(lease, deadline)?;
                proxy
                    .replace_upstream(lease, upstream)
                    .map_err(|_| ActProxyLaunchError::Unavailable)?;
            }
            if proxy
                .try_serve_once()
                .map_err(|_| ActProxyLaunchError::Unavailable)?
            {
                exchanges = exchanges.saturating_add(1);
                if exchanges > self.maximum_exchanges {
                    return Err(ActProxyLaunchError::Unavailable);
                }
            } else {
                thread::sleep(self.poll_interval);
            }
        }
    }
}

fn verify_act_binary(plan: &ActLaunchPlan) -> Result<(), ActProxyLaunchError> {
    plan.argv().map_err(|_| ActProxyLaunchError::Unavailable)?;
    let metadata =
        fs::symlink_metadata(&plan.binary).map_err(|_| ActProxyLaunchError::Unavailable)?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > 128 * 1024 * 1024
    {
        return Err(ActProxyLaunchError::Unavailable);
    }
    let mut file = File::open(&plan.binary).map_err(|_| ActProxyLaunchError::Unavailable)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| ActProxyLaunchError::Unavailable)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    if hasher.finalize().as_slice() == plan.binary_sha256 {
        Ok(())
    } else {
        Err(ActProxyLaunchError::Unavailable)
    }
}

/// Exact root-owned values needed to build one broker proxy lease.
pub struct BrokerProxyInputs<P: PrestartPersister> {
    /// Broker-owned socket, UID, and evidence authority.
    pub authority: ProxyLeaseAuthority,
    /// Signed policy manifest bound to the validated lease.
    pub manifest: PolicyManifest,
    /// Canonical signed job-manifest bytes that exclusively own exec classes.
    pub canonical_job_manifest: Vec<u8>,
    /// Inherited one-shot descriptor for the raw rootless Podman endpoint.
    pub upstream: UnixStream,
    /// Retained seccomp pre-start persistence capability.
    pub persister: P,
}

/// Root-owned input source for [`build_broker_proxy_lease`].
pub trait BrokerProxyInputSource {
    /// Concrete pre-start persistence capability.
    type Persister: PrestartPersister;

    /// Validate availability without opening or mutating the proxy listener.
    fn preflight(
        &mut self,
        plan: &ActLaunchPlan,
        binding: &ValidatedAttemptLeaseBinding,
    ) -> Result<(), ExecutionUnavailable>;

    /// Open fresh, exact inputs for one authenticated proxy lease.
    fn prepare(
        &mut self,
        admission: OrdinaryAdmission,
        lease: LeaseToken,
        plan: &ActLaunchPlan,
        binding: &ValidatedAttemptLeaseBinding,
    ) -> Result<BrokerProxyInputs<Self::Persister>, ExecutionUnavailable>;
}

/// Proxy lifecycle used by the production normal backend.
pub trait NormalActProxy {
    /// Validate root-owned proxy inputs before lease commitment.
    fn preflight(
        &mut self,
        plan: &ActLaunchPlan,
        binding: &ValidatedAttemptLeaseBinding,
    ) -> Result<(), ExecutionUnavailable>;

    /// Build the proxy and supervise pinned Act through it.
    fn run(
        &mut self,
        admission: OrdinaryAdmission,
        lease: LeaseToken,
        plan: &ActLaunchPlan,
        binding: &ValidatedAttemptLeaseBinding,
    ) -> Result<(), ExecutionUnavailable>;

    /// Reconcile all journaled Podman objects and the listener.
    fn reconcile(
        &mut self,
        lease: LeaseToken,
        stop: OrdinaryStop,
    ) -> Result<(), ExecutionUnavailable>;
}

/// Concrete broker proxy builder and recovery-aware reconciler.
pub struct BrokerProxyRuntime<S, L, R>
where
    S: BrokerProxyInputSource,
{
    source: S,
    launcher: L,
    reconciler: R,
    active: Option<BrokerProxyLease<S::Persister>>,
}

impl<S: BrokerProxyInputSource, L, R> BrokerProxyRuntime<S, L, R> {
    /// Construct a single-slot proxy runtime.
    pub fn new(source: S, launcher: L, reconciler: R) -> Self {
        Self {
            source,
            launcher,
            reconciler,
            active: None,
        }
    }
}

impl<S, L, R> NormalActProxy for BrokerProxyRuntime<S, L, R>
where
    S: BrokerProxyInputSource,
    L: ActThroughProxyLauncher<S::Persister>,
    R: PodmanReconcileRunner,
{
    fn preflight(
        &mut self,
        plan: &ActLaunchPlan,
        binding: &ValidatedAttemptLeaseBinding,
    ) -> Result<(), ExecutionUnavailable> {
        if self.active.is_some() || plan.argv().is_err() || plan.environment().is_err() {
            return Err(ExecutionUnavailable);
        }
        self.source.preflight(plan, binding)
    }

    fn run(
        &mut self,
        admission: OrdinaryAdmission,
        lease: LeaseToken,
        plan: &ActLaunchPlan,
        binding: &ValidatedAttemptLeaseBinding,
    ) -> Result<(), ExecutionUnavailable> {
        if self.active.is_some() {
            return Err(ExecutionUnavailable);
        }
        self.launcher
            .readiness()
            .map_err(|_| ExecutionUnavailable)?;
        let inputs = self.source.prepare(admission, lease, plan, binding)?;
        let mut manifest = inputs.manifest;
        populate_expected_execs(&mut manifest, &inputs.canonical_job_manifest)
            .map_err(|_| ExecutionUnavailable)?;
        let proxy = build_broker_proxy_lease(
            inputs.authority,
            admission,
            lease,
            binding,
            manifest,
            inputs.upstream,
            inputs.persister,
            normal_act_transport_limits(),
        )
        .map_err(|_| ExecutionUnavailable)?;
        self.active = Some(proxy);
        if self
            .active
            .as_ref()
            .is_none_or(|proxy| proxy.listener_path() != plan.proxy_socket)
        {
            return Err(ExecutionUnavailable);
        }
        self.launcher
            .launch(
                lease,
                plan,
                binding,
                self.active.as_mut().ok_or(ExecutionUnavailable)?,
            )
            .map_err(|_| ExecutionUnavailable)
    }

    fn reconcile(
        &mut self,
        lease: LeaseToken,
        _stop: OrdinaryStop,
    ) -> Result<(), ExecutionUnavailable> {
        let Some(proxy) = self.active.as_mut() else {
            return Ok(());
        };
        proxy
            .reconcile(lease, &mut self.reconciler)
            .map_err(|_| ExecutionUnavailable)?;
        self.active = None;
        Ok(())
    }
}

/// Host terminal evidence collector used after Act exits.
pub trait NormalTerminalCollector {
    /// Collect terminal outcome and the strict stop-through-upload ordering.
    fn collect(
        &mut self,
        lease: LeaseToken,
    ) -> Result<NormalTerminalEvidence, ExecutionUnavailable>;
}

/// Final host teardown and receipt builder.
pub trait NormalTeardownCollector {
    /// Prove the unit, cgroup, mounts, directories, and lease resources empty.
    fn reconcile(
        &mut self,
        lease: LeaseToken,
        stop: OrdinaryStop,
    ) -> Result<NormalReconcileEvidence, ExecutionUnavailable>;
}

/// Production implementation of the closed six-method backend contract.
pub struct ProductionNormalExecutionBackend<D, M, P, T, R> {
    dns: D,
    materializer: M,
    proxy: P,
    terminal: T,
    teardown: R,
    active: Option<LeaseToken>,
}

impl<D, M, P, T, R> ProductionNormalExecutionBackend<D, M, P, T, R> {
    /// Compose one single-slot production backend from its host adapters.
    pub fn new(dns: D, materializer: M, proxy: P, terminal: T, teardown: R) -> Self {
        Self {
            dns,
            materializer,
            proxy,
            terminal,
            teardown,
            active: None,
        }
    }
}

impl<D, M, P, T, R> NormalExecutionBackend for ProductionNormalExecutionBackend<D, M, P, T, R>
where
    D: NormalDnsLifecycle,
    M: NormalMaterializer,
    P: NormalActProxy,
    T: NormalTerminalCollector,
    R: NormalTeardownCollector,
{
    fn preflight(
        &mut self,
        plan: &NormalJobPlan,
        binding: &ValidatedAttemptLeaseBinding,
    ) -> Result<(), ExecutionUnavailable> {
        if self.active.is_some() {
            return Err(ExecutionUnavailable);
        }
        self.dns.preflight()?;
        self.materializer.preflight(plan, binding)?;
        self.proxy.preflight(&plan.act, binding)
    }

    fn apply_dns(
        &mut self,
        admission: OrdinaryAdmission,
        lease: LeaseToken,
        _binding: &ValidatedAttemptLeaseBinding,
    ) -> Result<DnsReadback, ExecutionUnavailable> {
        if self.active.is_some() {
            return Err(ExecutionUnavailable);
        }
        let readback = self.dns.apply(admission, lease)?;
        self.active = Some(lease);
        Ok(readback)
    }

    fn materialize(
        &mut self,
        plan: &NormalJobPlan,
        binding: &ValidatedAttemptLeaseBinding,
        store: &EvidenceStore,
    ) -> Result<(), ExecutionUnavailable> {
        if self.active.is_none() {
            return Err(ExecutionUnavailable);
        }
        self.materializer.materialize(plan, binding, store)
    }

    fn run_act_through_proxy(
        &mut self,
        admission: OrdinaryAdmission,
        lease: LeaseToken,
        plan: &ActLaunchPlan,
        binding: &ValidatedAttemptLeaseBinding,
        _store: &EvidenceStore,
    ) -> Result<(), ExecutionUnavailable> {
        if self.active != Some(lease) {
            return Err(ExecutionUnavailable);
        }
        self.proxy.run(admission, lease, plan, binding)
    }

    fn terminal_evidence(
        &mut self,
        lease: LeaseToken,
    ) -> Result<NormalTerminalEvidence, ExecutionUnavailable> {
        if self.active != Some(lease) {
            return Err(ExecutionUnavailable);
        }
        self.terminal.collect(lease)
    }

    fn reconcile(
        &mut self,
        lease: LeaseToken,
        stop: OrdinaryStop,
    ) -> Result<NormalReconcileEvidence, ExecutionUnavailable> {
        if self.active != Some(lease) {
            return Err(ExecutionUnavailable);
        }
        let proxy = self.proxy.reconcile(lease, stop);
        let materializer = self.materializer.reconcile(lease, stop);
        let dns = self.dns.reconcile(lease);
        let teardown = self.teardown.reconcile(lease, stop);
        if proxy.is_err() || materializer.is_err() || dns.is_err() {
            return Err(ExecutionUnavailable);
        }
        let evidence = teardown?;
        self.active = None;
        Ok(evidence)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use crate::activation::LeaseConclusion;
    use crate::evidence::{
        CiEventBinding, Digest32, ReconcileRecord, ReconcileState, TeardownRecord,
    };
    use crate::normal_engine::tests::ordinary_fixture;
    use buzz_ci_policy_proxy::{
        AllowedMount, EngineKind, IsolationLimits, IsolationProfile, NetworkPolicy,
    };

    use super::*;

    type Calls = Rc<RefCell<Vec<&'static str>>>;

    struct FakeDns(Calls);

    impl NormalDnsLifecycle for FakeDns {
        fn preflight(&mut self) -> Result<(), ExecutionUnavailable> {
            self.0.borrow_mut().push("dns-preflight");
            Ok(())
        }

        fn apply(
            &mut self,
            _admission: OrdinaryAdmission,
            _lease: LeaseToken,
        ) -> Result<DnsReadback, ExecutionUnavailable> {
            self.0.borrow_mut().push("dns-apply");
            Ok(DnsReadback {
                files_lookup_ok: true,
                arbitrary_getent_refused: true,
                resolved_varlink_inaccessible: true,
                direct_53_refused: true,
                allowed_tuples_only: true,
            })
        }

        fn reconcile(&mut self, _lease: LeaseToken) -> Result<(), ExecutionUnavailable> {
            self.0.borrow_mut().push("dns-reconcile");
            Ok(())
        }
    }

    struct FakeMaterializer(Calls);

    impl NormalMaterializer for FakeMaterializer {
        fn preflight(
            &mut self,
            _plan: &NormalJobPlan,
            _binding: &ValidatedAttemptLeaseBinding,
        ) -> Result<(), ExecutionUnavailable> {
            self.0.borrow_mut().push("materializer-preflight");
            Ok(())
        }

        fn materialize(
            &mut self,
            _plan: &NormalJobPlan,
            _binding: &ValidatedAttemptLeaseBinding,
            _store: &EvidenceStore,
        ) -> Result<(), ExecutionUnavailable> {
            self.0.borrow_mut().push("materialize");
            Ok(())
        }

        fn reconcile(
            &mut self,
            _lease: LeaseToken,
            _stop: OrdinaryStop,
        ) -> Result<(), ExecutionUnavailable> {
            self.0.borrow_mut().push("materializer-reconcile");
            Ok(())
        }
    }

    struct FakeProxy {
        calls: Calls,
        available: bool,
    }

    impl NormalActProxy for FakeProxy {
        fn preflight(
            &mut self,
            _plan: &ActLaunchPlan,
            _binding: &ValidatedAttemptLeaseBinding,
        ) -> Result<(), ExecutionUnavailable> {
            self.calls.borrow_mut().push("proxy-preflight");
            Ok(())
        }

        fn run(
            &mut self,
            _admission: OrdinaryAdmission,
            _lease: LeaseToken,
            _plan: &ActLaunchPlan,
            _binding: &ValidatedAttemptLeaseBinding,
        ) -> Result<(), ExecutionUnavailable> {
            self.calls.borrow_mut().push("act");
            self.available.then_some(()).ok_or(ExecutionUnavailable)
        }

        fn reconcile(
            &mut self,
            _lease: LeaseToken,
            _stop: OrdinaryStop,
        ) -> Result<(), ExecutionUnavailable> {
            self.calls.borrow_mut().push("proxy-reconcile");
            Ok(())
        }
    }

    struct FakeTerminal(Calls);

    impl NormalTerminalCollector for FakeTerminal {
        fn collect(
            &mut self,
            _lease: LeaseToken,
        ) -> Result<NormalTerminalEvidence, ExecutionUnavailable> {
            self.0.borrow_mut().push("terminal");
            Ok(NormalTerminalEvidence {
                conclusion: LeaseConclusion::Success,
                evidence_set_digest: [9; 32],
                ordering: Vec::new(),
            })
        }
    }

    struct FakeTeardown(Calls);

    impl NormalTeardownCollector for FakeTeardown {
        fn reconcile(
            &mut self,
            _lease: LeaseToken,
            _stop: OrdinaryStop,
        ) -> Result<NormalReconcileEvidence, ExecutionUnavailable> {
            self.0.borrow_mut().push("teardown");
            Ok(reconcile_evidence())
        }
    }

    fn reconcile_evidence() -> NormalReconcileEvidence {
        let event_binding = CiEventBinding {
            request_event_id_46105: [1; 32],
            teardown_event_id_46106: [2; 32],
        };
        NormalReconcileEvidence {
            teardown: TeardownRecord {
                lease_id: "lease".into(),
                event_binding,
                lease_unit: "buzzci-test.slice".into(),
                cgroup_path: "/buzzci.slice/buzzci-test.slice".into(),
                unit_inactive: true,
                cgroup_procs_empty: true,
                mounts_removed: true,
                dirs_removed: true,
                teardown_sha256: Digest32([3; 32]),
                completed_at_unix_ns: 3,
            },
            reconcile: ReconcileRecord {
                lease_id: "lease".into(),
                lease_unit: "buzzci-test.slice".into(),
                cgroup_path: "/buzzci.slice/buzzci-test.slice".into(),
                state: ReconcileState::Clean,
                emptied: true,
                quarantined: false,
                before_reuse: true,
                emptied_resources: Vec::new(),
                quarantined_resources: Vec::new(),
                reuse_allowed: true,
                observed_at_unix_ns: 4,
            },
            ordering: Vec::new(),
        }
    }

    fn backend(calls: &Calls, act_available: bool) -> impl NormalExecutionBackend + '_ {
        ProductionNormalExecutionBackend::new(
            FakeDns(calls.clone()),
            FakeMaterializer(calls.clone()),
            FakeProxy {
                calls: calls.clone(),
                available: act_available,
            },
            FakeTerminal(calls.clone()),
            FakeTeardown(calls.clone()),
        )
    }

    fn policy_manifest() -> PolicyManifest {
        PolicyManifest {
            schema_version: 1,
            request_event_id: "f".repeat(64),
            run_id: "run-1".into(),
            target_repo_a: format!("30617:{}:buzz", "e".repeat(64)),
            sha: "a".repeat(40),
            base_oid: "b".repeat(40),
            workflow_id: "required-ci".into(),
            workflow_digest: "7".repeat(64),
            job_id: "linux".into(),
            attempt: 1,
            lease_id: "lease-1".into(),
            manifest_digest: format!("sha256:{}", "0".repeat(64)),
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
        }
    }

    fn canonical_exec_manifest(manifest: &PolicyManifest) -> CanonicalExecManifest {
        CanonicalExecManifest {
            schema_version: 1,
            request_event_id: manifest.request_event_id.clone(),
            run_id: manifest.run_id.clone(),
            target_repo_a: manifest.target_repo_a.clone(),
            sha: manifest.sha.clone(),
            base_oid: manifest.base_oid.clone(),
            workflow_id: manifest.workflow_id.clone(),
            workflow_digest: manifest.workflow_digest.clone(),
            job_id: manifest.job_id.clone(),
            attempt: manifest.attempt,
            lease_id: manifest.lease_id.clone(),
            isolation_profile: manifest.isolation_profile.clone(),
            container_user: manifest.container_user.clone(),
            mounts: manifest.mounts.clone(),
            allowed_environment: manifest.allowed_environment.clone(),
            expected_execs: vec![ExecExpectation {
                argv: vec!["/bin/sh".into(), "-e".into(), "/workspace/step.sh".into()],
                environment: Vec::new(),
                user: manifest.container_user.clone(),
                working_dir: "/workspace".into(),
                attach_stdin: false,
                attach_stdout: true,
                attach_stderr: true,
                tty: false,
            }],
        }
    }

    #[test]
    fn canonical_expected_execs_are_digest_and_identity_bound() {
        let mut manifest = policy_manifest();
        let canonical = canonical_exec_manifest(&manifest);
        let bytes = serde_json::to_vec(&canonical).expect("fixture should serialize");
        manifest.manifest_digest = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
        populate_expected_execs(&mut manifest, &bytes).expect("bound source should populate");
        assert_eq!(manifest.expected_execs, canonical.expected_execs);

        let mut drifted = policy_manifest();
        let mut canonical = canonical_exec_manifest(&drifted);
        canonical.job_id = "other".into();
        let bytes = serde_json::to_vec(&canonical).expect("fixture should serialize");
        drifted.manifest_digest = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
        assert_eq!(
            populate_expected_execs(&mut drifted, &bytes),
            Err(ExpectedExecSourceError::IdentityMismatch)
        );
    }

    #[test]
    fn unavailable_and_noncanonical_expected_exec_sources_are_refused() {
        let mut manifest = policy_manifest();
        assert_eq!(
            populate_expected_execs(&mut manifest, &[]),
            Err(ExpectedExecSourceError::Unavailable)
        );

        let canonical = canonical_exec_manifest(&manifest);
        let mut bytes = serde_json::to_vec(&canonical).expect("fixture should serialize");
        bytes.push(b'\n');
        manifest.manifest_digest = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
        assert_eq!(
            populate_expected_execs(&mut manifest, &bytes),
            Err(ExpectedExecSourceError::Malformed)
        );
    }

    #[test]
    fn all_six_backend_methods_are_wired_in_order() {
        let fixture = ordinary_fixture();
        let binding = fixture
            .plan
            .binding
            .clone()
            .validate_phase1(&fixture.plan.validation.context())
            .expect("fixture binding should validate");
        let store = EvidenceStore::new(fixture.plan.evidence_root.clone())
            .expect("fixture evidence root should be valid");
        let calls = Rc::new(RefCell::new(Vec::new()));
        let mut backend = backend(&calls, true);

        backend
            .preflight(&fixture.plan, &binding)
            .expect("preflight should pass");
        backend
            .apply_dns(fixture.admission, fixture.lease, &binding)
            .expect("DNS apply should pass");
        backend
            .materialize(&fixture.plan, &binding, &store)
            .expect("materialization should pass");
        backend
            .run_act_through_proxy(
                fixture.admission,
                fixture.lease,
                &fixture.plan.act,
                &binding,
                &store,
            )
            .expect("fake proxy launch should pass");
        let terminal = backend
            .terminal_evidence(fixture.lease)
            .expect("terminal collection should pass");
        assert_eq!(terminal.conclusion, LeaseConclusion::Success);
        backend
            .reconcile(
                fixture.lease,
                OrdinaryStop::Completed(LeaseConclusion::Success),
            )
            .expect("reconciliation should pass");

        assert_eq!(
            *calls.borrow(),
            vec![
                "dns-preflight",
                "materializer-preflight",
                "proxy-preflight",
                "dns-apply",
                "materialize",
                "act",
                "terminal",
                "proxy-reconcile",
                "materializer-reconcile",
                "dns-reconcile",
                "teardown",
            ]
        );
    }

    #[test]
    fn unavailable_act_fails_closed_and_cleanup_still_runs() {
        let fixture = ordinary_fixture();
        let binding = fixture
            .plan
            .binding
            .clone()
            .validate_phase1(&fixture.plan.validation.context())
            .expect("fixture binding should validate");
        let store = EvidenceStore::new(fixture.plan.evidence_root.clone())
            .expect("fixture evidence root should be valid");
        let calls = Rc::new(RefCell::new(Vec::new()));
        let mut backend = backend(&calls, false);
        backend
            .preflight(&fixture.plan, &binding)
            .expect("preflight should pass");
        backend
            .apply_dns(fixture.admission, fixture.lease, &binding)
            .expect("DNS apply should pass");
        backend
            .materialize(&fixture.plan, &binding, &store)
            .expect("materialization should pass");

        assert!(backend
            .run_act_through_proxy(
                fixture.admission,
                fixture.lease,
                &fixture.plan.act,
                &binding,
                &store,
            )
            .is_err());
        backend
            .reconcile(fixture.lease, OrdinaryStop::Expired)
            .expect("cleanup should remain available after launch refusal");
        assert!(calls.borrow().contains(&"proxy-reconcile"));
        assert!(calls.borrow().contains(&"materializer-reconcile"));
        assert!(calls.borrow().contains(&"dns-reconcile"));
        assert!(calls.borrow().contains(&"teardown"));
    }
}
