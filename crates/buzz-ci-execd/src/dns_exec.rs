//! Concrete bounded Linux executor for the closed DNS host plan.
//!
//! Production execution uses only the absolute binaries in [`AllowedBinary`],
//! clears the environment, supplies fixed argv without a shell, closes stdin,
//! caps captured output, and kills commands at the compiled timeout. Tests use
//! the same command construction with a scripted runner and mapped file roots;
//! they never invoke host networking or systemd.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::IpAddr;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::fcntl::{fcntl, openat, renameat2, FcntlArg, OFlag, RenameFlags};
use nix::sys::signal::{killpg, Signal};
use nix::sys::stat::{fchmod, mkdirat, Mode};
use nix::unistd::{fchown, unlinkat, Gid, Pid, Uid, UnlinkatFlags};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::dns_host::{
    DnsHostAction, DnsHostAdapter, DnsHostApplyError, DnsHostApplyResult, DnsHostBackend,
    DnsHostObservation, DnsHostPlan, DnsHostPlanError, DnsHostReadbackTarget, LeaseSliceQuarantine,
    MaterializerNftPlan, MaterializerNftReadback, NetworkNamespacePlan, NetworkNamespaceReadback,
    NftHook,
};
use crate::dns_isolation::{
    BrokerFileType, BrokerPinnedFileReadback, DnsFilesReadback, DnsReadback, FilesLookupProbe,
    LeaseIsolationObservation, LeaseIsolationPlan, LeaseSliceReadback, PrincipalDnsObservation,
    PrincipalRole, TcpServiceTuple, TransientUnitPlan, TransientUnitReadback, TupleConnectProbe,
    UnitNetworkMode,
};

pub const LEASE_ROOT: &str = "/var/lib/buzzci/leases";
pub const ACTIVATION_ROOT: &str = "/var/lib/buzzci/activation";
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
pub const MAX_COMMAND_OUTPUT: usize = 64 * 1024;
const OUTPUT_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

const DIRECTORY_MODE: u32 = 0o700;
const DNS_FILE_MODE: u32 = 0o444;
const RECEIPT_FILE_MODE: u32 = 0o400;
const RECEIPT_VERSION: u8 = 2;
const DENIED_CONTROL_ADDRESS: &str = "203.0.113.1";
const DENIED_CONTROL_PORT: u16 = 9;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// Only binaries the production runner can execute.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AllowedBinary {
    Systemctl,
    SystemdRun,
    Ip,
    Nft,
    Getent,
    Dig,
    Stat,
    Ncat,
    Sleep,
}

impl AllowedBinary {
    pub const fn path(self) -> &'static str {
        match self {
            Self::Systemctl => "/usr/bin/systemctl",
            Self::SystemdRun => "/usr/bin/systemd-run",
            Self::Ip => "/usr/sbin/ip",
            Self::Nft => "/usr/sbin/nft",
            Self::Getent => "/usr/bin/getent",
            Self::Dig => "/usr/bin/dig",
            Self::Stat => "/usr/bin/stat",
            Self::Ncat => "/usr/bin/ncat",
            Self::Sleep => "/usr/bin/sleep",
        }
    }
}

/// Private-construction command with bounded execution metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExactCommand {
    binary: AllowedBinary,
    argv: Vec<OsString>,
    timeout: Duration,
    #[cfg(test)]
    executable_override: Option<PathBuf>,
    #[cfg(test)]
    environment_override: Option<(OsString, OsString)>,
}

impl ExactCommand {
    fn new(binary: AllowedBinary, argv: Vec<OsString>, timeout: Duration) -> Self {
        Self {
            binary,
            argv,
            timeout,
            #[cfg(test)]
            executable_override: None,
            #[cfg(test)]
            environment_override: None,
        }
    }

    fn executable_path(&self) -> &Path {
        #[cfg(test)]
        if let Some(path) = &self.executable_override {
            return path;
        }
        Path::new(self.binary.path())
    }

    #[cfg(test)]
    fn test_process(
        executable: PathBuf,
        argv: Vec<OsString>,
        timeout: Duration,
        environment: (OsString, OsString),
    ) -> Self {
        Self {
            binary: AllowedBinary::Sleep,
            argv,
            timeout,
            executable_override: Some(executable),
            environment_override: Some(environment),
        }
    }

    pub const fn binary(&self) -> AllowedBinary {
        self.binary
    }

    pub fn argv(&self) -> &[OsString] {
        &self.argv
    }

    pub const fn timeout(&self) -> Duration {
        self.timeout
    }
}

/// Bounded command result. Output beyond the cap is drained and discarded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExactCommandOutput {
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

impl ExactCommandOutput {
    pub fn success(&self) -> bool {
        self.exit_code == Some(0)
    }
}

/// Injectable command boundary used by the concrete backend and fake tests.
pub trait ExactCommandRunner {
    type Error: std::error::Error + Send + Sync + 'static;

    fn run(&mut self, command: &ExactCommand) -> Result<ExactCommandOutput, Self::Error>;
}

/// Production runner with no shell, no inherited environment, and bounded I/O.
#[derive(Default)]
pub struct ProcessCommandRunner;

#[derive(Debug, Error)]
pub enum ProcessCommandError {
    #[error("failed to spawn allowlisted host command")]
    Spawn(#[source] std::io::Error),
    #[error("failed to wait for allowlisted host command")]
    Wait(#[source] std::io::Error),
    #[error("allowlisted host command exceeded its timeout")]
    Timeout,
    #[error("failed to drain bounded command output")]
    Output(#[source] std::io::Error),
    #[error("command output pipes did not close within the structural deadline")]
    OutputDrainTimeout,
}

impl ExactCommandRunner for ProcessCommandRunner {
    type Error = ProcessCommandError;

    fn run(&mut self, command: &ExactCommand) -> Result<ExactCommandOutput, Self::Error> {
        let mut process = Command::new(command.executable_path());
        process
            .args(&command.argv)
            .env_clear()
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(test)]
        if let Some((name, value)) = &command.environment_override {
            process.env(name, value);
        }
        let mut child = process.spawn().map_err(ProcessCommandError::Spawn)?;
        let mut stdout = child
            .stdout
            .take()
            .ok_or(ProcessCommandError::OutputDrainTimeout)?;
        let mut stderr = child
            .stderr
            .take()
            .ok_or(ProcessCommandError::OutputDrainTimeout)?;
        set_nonblocking(&stdout)?;
        set_nonblocking(&stderr)?;
        let mut stdout_state = BoundedOutput::default();
        let mut stderr_state = BoundedOutput::default();
        let started = Instant::now();
        let status = loop {
            stdout_state.drain(&mut stdout)?;
            stderr_state.drain(&mut stderr)?;
            if let Some(status) = child.try_wait().map_err(ProcessCommandError::Wait)? {
                break status;
            }
            if started.elapsed() >= command.timeout {
                terminate_process_group(&mut child)?;
                drain_pipes_until_closed(
                    &mut stdout,
                    &mut stderr,
                    &mut stdout_state,
                    &mut stderr_state,
                )?;
                return Err(ProcessCommandError::Timeout);
            }
            thread::sleep(Duration::from_millis(10));
        };
        if drain_pipes_until_closed(
            &mut stdout,
            &mut stderr,
            &mut stdout_state,
            &mut stderr_state,
        )
        .is_err()
        {
            // A descendant retained an inherited pipe after the command leader
            // exited. Kill the whole command group, then demand EOF once more.
            let _ = killpg(Pid::from_raw(child.id() as i32), Signal::SIGKILL);
            drain_pipes_until_closed(
                &mut stdout,
                &mut stderr,
                &mut stdout_state,
                &mut stderr_state,
            )?;
        }
        Ok(ExactCommandOutput {
            exit_code: status.code(),
            stdout: stdout_state.retained,
            stderr: stderr_state.retained,
            stdout_truncated: stdout_state.truncated,
            stderr_truncated: stderr_state.truncated,
        })
    }
}

fn set_nonblocking(fd: &impl std::os::fd::AsFd) -> Result<(), ProcessCommandError> {
    let flags = fcntl(fd, FcntlArg::F_GETFL).map_err(|error| {
        ProcessCommandError::Output(std::io::Error::from_raw_os_error(error as i32))
    })?;
    let flags = OFlag::from_bits_truncate(flags) | OFlag::O_NONBLOCK;
    fcntl(fd, FcntlArg::F_SETFL(flags)).map_err(|error| {
        ProcessCommandError::Output(std::io::Error::from_raw_os_error(error as i32))
    })?;
    Ok(())
}

#[derive(Default)]
struct BoundedOutput {
    retained: Vec<u8>,
    truncated: bool,
    eof: bool,
}

impl BoundedOutput {
    fn drain(&mut self, reader: &mut impl Read) -> Result<(), ProcessCommandError> {
        let mut buffer = [0_u8; 8192];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => {
                    self.eof = true;
                    return Ok(());
                }
                Ok(count) => {
                    let remaining = MAX_COMMAND_OUTPUT.saturating_sub(self.retained.len());
                    let copied = remaining.min(count);
                    self.retained.extend_from_slice(&buffer[..copied]);
                    self.truncated |= copied != count;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) => return Err(ProcessCommandError::Output(error)),
            }
        }
    }
}

fn terminate_process_group(child: &mut std::process::Child) -> Result<(), ProcessCommandError> {
    match killpg(Pid::from_raw(child.id() as i32), Signal::SIGKILL) {
        Ok(()) | Err(Errno::ESRCH) => {}
        Err(error) => {
            return Err(ProcessCommandError::Wait(
                std::io::Error::from_raw_os_error(error as i32),
            ));
        }
    }
    child.wait().map_err(ProcessCommandError::Wait)?;
    Ok(())
}

fn drain_pipes_until_closed(
    stdout: &mut impl Read,
    stderr: &mut impl Read,
    stdout_state: &mut BoundedOutput,
    stderr_state: &mut BoundedOutput,
) -> Result<(), ProcessCommandError> {
    let deadline = Instant::now() + OUTPUT_DRAIN_TIMEOUT;
    loop {
        stdout_state.drain(stdout)?;
        stderr_state.drain(stderr)?;
        if stdout_state.eof && stderr_state.eof {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(ProcessCommandError::OutputDrainTimeout);
        }
        thread::sleep(Duration::from_millis(5));
    }
}

/// Validated executor input and exact sealed file bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsExecPlan {
    isolation: LeaseIsolationPlan,
    host: DnsHostPlan,
    activation: DnsActivationBinding,
    resolv_conf: Vec<u8>,
    hosts: Vec<u8>,
    receipt_name: String,
}

impl DnsExecPlan {
    pub fn new(
        isolation: LeaseIsolationPlan,
        activation: DnsActivationBinding,
    ) -> Result<Self, DnsExecPlanError> {
        activation.validate(&isolation.lease_id)?;
        let host = DnsHostPlan::new(isolation.clone()).map_err(DnsExecPlanError::Host)?;
        let resolv_conf = Vec::new();
        let hosts = render_hosts(&isolation);
        if sha256_hex(&resolv_conf) != isolation.dns_files.resolv_conf.sha256()
            || sha256_hex(&hosts) != isolation.dns_files.hosts.sha256()
        {
            return Err(DnsExecPlanError::DnsFileDigest);
        }
        Ok(Self {
            receipt_name: format!(
                "{}-g{}.json",
                isolation.lease_id, activation.lease_generation
            ),
            isolation,
            host,
            activation,
            resolv_conf,
            hosts,
        })
    }

    pub fn host_plan(&self) -> &DnsHostPlan {
        &self.host
    }

    pub fn receipt_name(&self) -> &str {
        &self.receipt_name
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum DnsExecPlanError {
    #[error("invalid closed DNS host plan")]
    Host(DnsHostPlanError),
    #[error("rendered DNS files do not match the broker-pinned digests")]
    DnsFileDigest,
    #[error("activation binding is incomplete or does not match the lease")]
    ActivationBinding,
}

/// Authenticated activation coordinates supplied by the composition layer.
///
/// The DNS executor validates but never derives or defaults these values.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DnsActivationBinding {
    pub integrated_candidate_sha: String,
    pub broker_build_identity: String,
    pub host_profile_digest: String,
    pub suite_identity: String,
    pub fixture_signer: String,
    pub request_digest: String,
    pub manifest_digest: String,
    pub isolation_profile_digest: String,
    pub lease_id: String,
    pub lease_generation: u64,
    pub observed_at_unix_ns: u64,
}

impl DnsActivationBinding {
    fn validate(&self, expected_lease_id: &str) -> Result<(), DnsExecPlanError> {
        let full_oid = is_nonzero_lower_hex(&self.integrated_candidate_sha, 40)
            || is_nonzero_lower_hex(&self.integrated_candidate_sha, 64);
        let digests = [
            &self.broker_build_identity,
            &self.host_profile_digest,
            &self.suite_identity,
            &self.fixture_signer,
            &self.request_digest,
            &self.manifest_digest,
            &self.isolation_profile_digest,
        ];
        if !full_oid
            || digests.iter().any(|value| !is_nonzero_lower_hex(value, 64))
            || self.lease_id != expected_lease_id
            || self.lease_generation == 0
            || self.observed_at_unix_ns == 0
        {
            return Err(DnsExecPlanError::ActivationBinding);
        }
        Ok(())
    }
}

fn is_nonzero_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && value.bytes().any(|byte| byte != b'0')
}

fn render_hosts(plan: &LeaseIsolationPlan) -> Vec<u8> {
    let mut entries = plan
        .dns_files
        .sni_host_pins
        .iter()
        .flat_map(|pin| {
            pin.addresses
                .iter()
                .map(move |address| (pin.hostname.as_str(), *address))
        })
        .collect::<Vec<_>>();
    entries.sort_unstable();
    let mut bytes = Vec::new();
    for (hostname, address) in entries {
        bytes.extend_from_slice(format!("{address} {hostname}\n").as_bytes());
    }
    bytes
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Canonical production roots or test-only mapped roots.
#[derive(Clone, Debug)]
struct ExecutorRoots {
    base_root: PathBuf,
    owner_uid: u32,
    owner_gid: u32,
}

impl ExecutorRoots {
    fn production() -> Self {
        Self {
            base_root: PathBuf::from("/"),
            owner_uid: 0,
            owner_gid: 0,
        }
    }

    #[cfg(test)]
    fn mapped(base: &Path) -> Self {
        let owner = fs::metadata(base).expect("test root must exist");
        Self {
            base_root: base.to_path_buf(),
            owner_uid: owner.uid(),
            owner_gid: owner.gid(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum DnsExecFsError {
    #[error("executor path escaped its fixed root")]
    UnsafePath,
    #[error("executor directory metadata is unsafe")]
    UnsafeDirectory,
    #[error("executor file metadata is unsafe")]
    UnsafeFile,
    #[error("exclusive atomic file publication failed")]
    Publish,
    #[error("owned resource removal failed")]
    Remove,
}

/// Durable executor state. It contains only identities derived from the plan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DnsExecReceipt {
    version: u8,
    committed: bool,
    #[serde(flatten)]
    activation: DnsActivationBinding,
    lease_slice: String,
    namespace_name: String,
    nft_table: String,
    resolv_conf_sha256: String,
    hosts_sha256: String,
    readback: DnsReadback,
}

impl DnsExecReceipt {
    fn from_released(plan: &DnsExecPlan, readback: DnsReadback) -> Self {
        Self {
            version: RECEIPT_VERSION,
            committed: true,
            activation: plan.activation.clone(),
            lease_slice: plan.host.identifiers().lease_slice().to_owned(),
            namespace_name: plan.host.identifiers().namespace_name().to_owned(),
            nft_table: plan.host.identifiers().nft_table().to_owned(),
            resolv_conf_sha256: sha256_hex(&plan.resolv_conf),
            hosts_sha256: sha256_hex(&plan.hosts),
            readback,
        }
    }
}

/// Concrete executor which applies [`DnsHostPlan`] through exact commands.
pub struct DnsExecutor<R> {
    runner: R,
    roots: ExecutorRoots,
}

impl DnsExecutor<ProcessCommandRunner> {
    pub fn production() -> Self {
        Self {
            runner: ProcessCommandRunner,
            roots: ExecutorRoots::production(),
        }
    }
}

impl<R: ExactCommandRunner> DnsExecutor<R> {
    #[cfg(test)]
    fn mapped(runner: R, base: &Path) -> Self {
        Self {
            runner,
            roots: ExecutorRoots::mapped(base),
        }
    }

    pub fn apply(&mut self, plan: &DnsExecPlan) -> Result<DnsExecOutcome, DnsExecError<R::Error>> {
        let mut owned = OwnedResources::default();
        if let Err(source) = publish_dns_files(&self.roots, plan, &mut owned) {
            remove_lease_files(&self.roots, &plan.isolation.lease_id, &owned)
                .map_err(DnsExecError::Files)?;
            return Err(DnsExecError::Files(source));
        }
        let adapter = DnsHostAdapter::new(plan.host.clone());
        let mut backend = DnsExecBackend {
            runner: &mut self.runner,
            roots: &self.roots,
            owned: &mut owned,
        };
        let result = adapter.apply(&mut backend);
        let host = result.map_err(DnsExecError::Host)?;
        if !host.released() {
            return Err(DnsExecError::Files(DnsExecFsError::Publish));
        }
        let receipt = DnsExecReceipt::from_released(plan, host.readback.dns_readback);
        if let Err(source) = publish_receipt(&self.roots, plan.receipt_name(), &receipt) {
            cleanup_owned(&mut self.runner, &self.roots, plan, &owned)
                .map_err(DnsExecError::Cleanup)?;
            return Err(DnsExecError::Files(source));
        }
        Ok(DnsExecOutcome { host, receipt })
    }

    /// Remove only resources bound by a validated executor receipt.
    pub fn reconcile_stale(
        &mut self,
        plan: &DnsExecPlan,
        receipt: &DnsExecReceipt,
    ) -> Result<(), DnsExecError<R::Error>> {
        if receipt != &DnsExecReceipt::from_released(plan, receipt.readback) {
            return Err(DnsExecError::StaleReceipt);
        }
        let owned = owned_from_receipt(&self.roots, plan).map_err(DnsExecError::Files)?;
        cleanup_owned(&mut self.runner, &self.roots, plan, &owned).map_err(DnsExecError::Cleanup)
    }
}

pub struct DnsExecOutcome {
    pub host: DnsHostApplyResult,
    pub receipt: DnsExecReceipt,
}

#[derive(Debug, Error)]
pub enum DnsExecError<E: std::error::Error + 'static> {
    #[error("sealed DNS file or receipt operation failed")]
    Files(DnsExecFsError),
    #[error("closed DNS host apply failed")]
    Host(#[source] DnsHostApplyError<DnsExecBackendError<E>>),
    #[error("stale receipt did not match the validated plan")]
    StaleReceipt,
    #[error("stale owned resource reconciliation failed")]
    Cleanup(DnsExecBackendError<E>),
}

struct DnsExecBackend<'a, R> {
    runner: &'a mut R,
    roots: &'a ExecutorRoots,
    owned: &'a mut OwnedResources,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[derive(Default)]
struct OwnedResources {
    slice: bool,
    namespace: bool,
    nft_table: bool,
    lease_directory: Option<FileIdentity>,
    resolv_conf: Option<FileIdentity>,
    hosts: Option<FileIdentity>,
}

#[derive(Debug, Error)]
pub enum DnsExecBackendError<E: std::error::Error + 'static> {
    #[error("allowlisted command transport failed")]
    Transport(#[source] E),
    #[error("allowlisted command returned failure or truncated output")]
    Command,
    #[error("host readback was malformed")]
    Readback,
    #[error("sealed DNS file readback failed")]
    Files(#[source] DnsExecFsError),
    #[error("a same-named host resource already exists")]
    ResourceCollision,
    #[error("lease quarantine cleanup failed")]
    Quarantine,
}

impl<R: ExactCommandRunner> DnsHostBackend for DnsExecBackend<'_, R> {
    type Error = DnsExecBackendError<R::Error>;

    fn apply(&mut self, action: &DnsHostAction) -> Result<(), Self::Error> {
        let commands = commands_for_action(action);
        match action {
            DnsHostAction::EnsureLeaseSlice { slice } => {
                require_slice_absent(self.runner, &slice.unit_name)?;
                run_required(self.runner, &commands[0])?;
                self.owned.slice = true;
            }
            DnsHostAction::EnsureNoEgressNamespace { namespace } => {
                require_namespace_absent(self.runner, namespace.name())?;
                run_required(self.runner, &commands[0])?;
                self.owned.namespace = true;
                for command in &commands[1..] {
                    run_required(self.runner, command)?;
                }
            }
            DnsHostAction::InstallMaterializerPolicy { policy } => {
                require_nft_table_absent(self.runner, policy.family(), policy.table())?;
                run_required(self.runner, &commands[0])?;
                self.owned.nft_table = true;
                for command in &commands[1..] {
                    run_required(self.runner, command)?;
                }
            }
            DnsHostAction::EnsurePrincipalService { .. } => {
                for command in &commands {
                    run_required(self.runner, command)?;
                }
            }
        }
        Ok(())
    }

    fn observe(
        &mut self,
        target: &DnsHostReadbackTarget,
    ) -> Result<DnsHostObservation, Self::Error> {
        collect_observation(self.runner, self.roots, target)
    }

    fn quarantine_slice(&mut self, target: &LeaseSliceQuarantine) -> Result<(), Self::Error> {
        let identifiers = quarantine_identifiers(target).ok_or(DnsExecBackendError::Quarantine)?;
        cleanup_host(
            self.runner,
            target.unit_name(),
            &identifiers.namespace_name,
            &identifiers.nft_table,
            self.owned,
        )?;
        remove_lease_files(self.roots, &identifiers.lease_id, self.owned)
            .map_err(DnsExecBackendError::Files)
    }
}

fn require_slice_absent<R: ExactCommandRunner>(
    runner: &mut R,
    unit: &str,
) -> Result<(), DnsExecBackendError<R::Error>> {
    let output = run_required(runner, &show_command(unit, &["LoadState"]))?;
    let values = parse_show_generic(&output.stdout)?;
    if values.len() == 1 && values.get("LoadState").map(String::as_str) == Some("not-found") {
        Ok(())
    } else {
        Err(DnsExecBackendError::ResourceCollision)
    }
}

fn require_namespace_absent<R: ExactCommandRunner>(
    runner: &mut R,
    namespace: &str,
) -> Result<(), DnsExecBackendError<R::Error>> {
    let output = run_required(
        runner,
        &ExactCommand::new(
            AllowedBinary::Ip,
            vec![os("-j"), os("netns"), os("list")],
            COMMAND_TIMEOUT,
        ),
    )?;
    let value: Value =
        serde_json::from_slice(&output.stdout).map_err(|_| DnsExecBackendError::Readback)?;
    let entries = value.as_array().ok_or(DnsExecBackendError::Readback)?;
    if entries
        .iter()
        .any(|entry| entry.get("name").and_then(Value::as_str) == Some(namespace))
    {
        Err(DnsExecBackendError::ResourceCollision)
    } else {
        Ok(())
    }
}

fn require_nft_table_absent<R: ExactCommandRunner>(
    runner: &mut R,
    family: &str,
    table: &str,
) -> Result<(), DnsExecBackendError<R::Error>> {
    let output = run_required(runner, &nft(vec![os("-j"), os("list"), os("tables")]))?;
    let value: Value =
        serde_json::from_slice(&output.stdout).map_err(|_| DnsExecBackendError::Readback)?;
    let objects = value
        .get("nftables")
        .and_then(Value::as_array)
        .ok_or(DnsExecBackendError::Readback)?;
    if objects.iter().any(|object| {
        object.get("table").is_some_and(|candidate| {
            candidate.get("family").and_then(Value::as_str) == Some(family)
                && candidate.get("name").and_then(Value::as_str) == Some(table)
        })
    }) {
        Err(DnsExecBackendError::ResourceCollision)
    } else {
        Ok(())
    }
}

struct QuarantineIdentifiers {
    lease_id: String,
    namespace_name: String,
    nft_table: String,
}

fn quarantine_identifiers(target: &LeaseSliceQuarantine) -> Option<QuarantineIdentifiers> {
    let lease_id = target
        .unit_name()
        .strip_prefix("buzzci-")?
        .strip_suffix(".slice")?;
    if lease_id.is_empty()
        || !lease_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        || target.cgroup_path() != Path::new("/buzzci.slice").join(target.unit_name())
    {
        return None;
    }
    Some(QuarantineIdentifiers {
        lease_id: lease_id.to_owned(),
        namespace_name: format!("buzzci-{lease_id}"),
        nft_table: format!("buzzci_{lease_id}"),
    })
}

fn commands_for_action(action: &DnsHostAction) -> Vec<ExactCommand> {
    match action {
        DnsHostAction::EnsureLeaseSlice { slice } => {
            let mut argv = vec![os("set-property"), os("--runtime"), os(&slice.unit_name)];
            argv.extend(
                slice
                    .properties
                    .iter()
                    .map(|(name, value)| os(format!("{name}={value}"))),
            );
            vec![ExactCommand::new(
                AllowedBinary::Systemctl,
                argv,
                COMMAND_TIMEOUT,
            )]
        }
        DnsHostAction::EnsureNoEgressNamespace { namespace } => vec![
            ExactCommand::new(
                AllowedBinary::Ip,
                vec![os("netns"), os("add"), os(namespace.name())],
                COMMAND_TIMEOUT,
            ),
            ExactCommand::new(
                AllowedBinary::Ip,
                vec![
                    os("-n"),
                    os(namespace.name()),
                    os("link"),
                    os("set"),
                    os("lo"),
                    os("up"),
                ],
                COMMAND_TIMEOUT,
            ),
        ],
        DnsHostAction::InstallMaterializerPolicy { policy } => nft_apply_commands(policy),
        DnsHostAction::EnsurePrincipalService { service } => {
            vec![service_apply_command(service)]
        }
    }
}

fn service_apply_command(service: &TransientUnitPlan) -> ExactCommand {
    let mut argv = vec![
        os("--quiet"),
        os("--collect"),
        os(format!("--unit={}", service.unit_name)),
        os(format!(
            "--slice={}",
            service
                .properties
                .get("Slice")
                .expect("closed plan has Slice")
        )),
        os(format!("--uid={}", service.uid)),
    ];
    argv.extend(
        service
            .properties
            .iter()
            .filter(|(name, _)| name.as_str() != "Slice" && name.as_str() != "User")
            .map(|(name, value)| os(format!("--property={name}={value}"))),
    );
    argv.extend([os(AllowedBinary::Sleep.path()), os("infinity")]);
    ExactCommand::new(AllowedBinary::SystemdRun, argv, COMMAND_TIMEOUT)
}

fn nft_apply_commands(policy: &MaterializerNftPlan) -> Vec<ExactCommand> {
    let mut commands = vec![
        nft(vec![
            os("add"),
            os("table"),
            os(policy.family()),
            os(policy.table()),
        ]),
        nft(vec![
            os("add"),
            os("chain"),
            os(policy.family()),
            os(policy.table()),
            os(policy.chain()),
            os("{"),
            os("type"),
            os("filter"),
            os("hook"),
            os("output"),
            os("priority"),
            os(policy.priority().to_string()),
            os(";"),
            os("policy"),
            os("accept"),
            os(";"),
            os("}"),
        ]),
    ];
    for tuple in policy.allowed_tcp_tuples() {
        let address_family = if tuple.address.is_ipv4() { "ip" } else { "ip6" };
        commands.push(nft(vec![
            os("add"),
            os("rule"),
            os(policy.family()),
            os(policy.table()),
            os(policy.chain()),
            os("meta"),
            os("skuid"),
            os(policy.principal_uid().to_string()),
            os(address_family),
            os("daddr"),
            os(tuple.address.to_string()),
            os("tcp"),
            os("dport"),
            os(tuple.port.to_string()),
            os("accept"),
        ]));
    }
    commands.push(nft(vec![
        os("add"),
        os("rule"),
        os(policy.family()),
        os(policy.table()),
        os(policy.chain()),
        os("meta"),
        os("skuid"),
        os(policy.principal_uid().to_string()),
        os("drop"),
    ]));
    commands
}

fn nft(argv: Vec<OsString>) -> ExactCommand {
    ExactCommand::new(AllowedBinary::Nft, argv, COMMAND_TIMEOUT)
}

fn cleanup_commands(slice: &str, namespace: &str, table: &str) -> Vec<ExactCommand> {
    vec![
        ExactCommand::new(
            AllowedBinary::Systemctl,
            vec![os("stop"), os(slice)],
            COMMAND_TIMEOUT,
        ),
        nft(vec![os("delete"), os("table"), os("inet"), os(table)]),
        ExactCommand::new(
            AllowedBinary::Ip,
            vec![os("netns"), os("delete"), os(namespace)],
            COMMAND_TIMEOUT,
        ),
    ]
}

fn cleanup_host<R: ExactCommandRunner>(
    runner: &mut R,
    slice: &str,
    namespace: &str,
    table: &str,
    owned: &OwnedResources,
) -> Result<(), DnsExecBackendError<R::Error>> {
    let commands = cleanup_commands(slice, namespace, table);
    if owned.slice {
        run_any(runner, &commands[0])?;
        let active = run_any(
            runner,
            &ExactCommand::new(
                AllowedBinary::Systemctl,
                vec![os("is-active"), os("--quiet"), os(slice)],
                COMMAND_TIMEOUT,
            ),
        )?;
        if active.success() {
            return Err(DnsExecBackendError::Quarantine);
        }
    }

    if owned.nft_table {
        run_any(runner, &commands[1])?;
        let table_present = run_any(
            runner,
            &nft(vec![os("list"), os("table"), os("inet"), os(table)]),
        )?;
        if table_present.success() {
            return Err(DnsExecBackendError::Quarantine);
        }
    }

    if owned.namespace {
        run_any(runner, &commands[2])?;
        let namespaces = run_required(
            runner,
            &ExactCommand::new(
                AllowedBinary::Ip,
                vec![os("-j"), os("netns"), os("list")],
                COMMAND_TIMEOUT,
            ),
        )?;
        let value: Value = serde_json::from_slice(&namespaces.stdout)
            .map_err(|_| DnsExecBackendError::Quarantine)?;
        if value.as_array().is_none_or(|entries| {
            entries
                .iter()
                .any(|entry| entry.get("name").and_then(Value::as_str) == Some(namespace))
        }) {
            return Err(DnsExecBackendError::Quarantine);
        }
    }
    Ok(())
}

fn os(value: impl AsRef<OsStr>) -> OsString {
    value.as_ref().to_os_string()
}

fn run_required<R: ExactCommandRunner>(
    runner: &mut R,
    command: &ExactCommand,
) -> Result<ExactCommandOutput, DnsExecBackendError<R::Error>> {
    let output = runner
        .run(command)
        .map_err(DnsExecBackendError::Transport)?;
    if !output.success() || output.stdout_truncated || output.stderr_truncated {
        return Err(DnsExecBackendError::Command);
    }
    Ok(output)
}

fn run_any<R: ExactCommandRunner>(
    runner: &mut R,
    command: &ExactCommand,
) -> Result<ExactCommandOutput, DnsExecBackendError<R::Error>> {
    let output = runner
        .run(command)
        .map_err(DnsExecBackendError::Transport)?;
    if output.stdout_truncated || output.stderr_truncated {
        return Err(DnsExecBackendError::Command);
    }
    Ok(output)
}

fn collect_observation<R: ExactCommandRunner>(
    runner: &mut R,
    roots: &ExecutorRoots,
    target: &DnsHostReadbackTarget,
) -> Result<DnsHostObservation, DnsExecBackendError<R::Error>> {
    let isolation = target.isolation();
    let lease_slice = read_slice(runner, isolation)?;
    let mut units = Vec::new();
    for expected in &isolation.units {
        units.push(read_unit(runner, expected)?);
    }
    let dns_files = read_dns_files(roots, isolation).map_err(DnsExecBackendError::Files)?;
    let namespace = read_namespace(runner, target.namespace())?;
    let (materializer_policy, effective_materializer_allowlist) =
        read_nft(runner, target.materializer_policy())?;
    let probes = run_dns_probes(runner, isolation)?;
    Ok(DnsHostObservation {
        isolation: LeaseIsolationObservation {
            lease_slice,
            units,
            dns_files,
            principal_dns: probes.principal_dns,
            effective_materializer_allowlist,
            tuple_connect_probes: probes.tuple_connect_probes,
        },
        namespace,
        materializer_policy,
    })
}

fn show_command(unit: &str, properties: &[&str]) -> ExactCommand {
    let mut argv = vec![os("show"), os("--no-pager"), os(unit)];
    argv.extend(
        properties
            .iter()
            .map(|property| os(format!("--property={property}"))),
    );
    ExactCommand::new(AllowedBinary::Systemctl, argv, COMMAND_TIMEOUT)
}

fn parse_show_generic<E: std::error::Error + 'static>(
    bytes: &[u8],
) -> Result<BTreeMap<String, String>, DnsExecBackendError<E>> {
    let text = std::str::from_utf8(bytes).map_err(|_| DnsExecBackendError::Readback)?;
    let mut values = BTreeMap::new();
    for line in text.lines() {
        let (name, value) = line.split_once('=').ok_or(DnsExecBackendError::Readback)?;
        if name.is_empty() || values.insert(name.to_owned(), value.to_owned()).is_some() {
            return Err(DnsExecBackendError::Readback);
        }
    }
    Ok(values)
}

fn read_slice<R: ExactCommandRunner>(
    runner: &mut R,
    plan: &LeaseIsolationPlan,
) -> Result<LeaseSliceReadback, DnsExecBackendError<R::Error>> {
    let names = [
        "ControlGroup",
        "CPUQuotaPerSecUSec",
        "CPUWeight",
        "IOWeight",
        "MemoryMax",
        "MemorySwapMax",
        "TasksMax",
    ];
    let output = run_required(runner, &show_command(&plan.lease_slice.unit_name, &names))?;
    let mut properties = parse_show_generic(&output.stdout)?;
    let cgroup_path = properties
        .remove("ControlGroup")
        .map(PathBuf::from)
        .ok_or(DnsExecBackendError::Readback)?;
    Ok(LeaseSliceReadback {
        unit_name: plan.lease_slice.unit_name.clone(),
        cgroup_path,
        properties,
    })
}

fn read_unit<R: ExactCommandRunner>(
    runner: &mut R,
    expected: &TransientUnitPlan,
) -> Result<TransientUnitReadback, DnsExecBackendError<R::Error>> {
    let names = [
        "ControlGroup",
        "BindReadOnlyPaths",
        "InaccessiblePaths",
        "NetworkNamespacePath",
        "PrivateNetwork",
        "Slice",
        "User",
    ];
    let output = run_required(runner, &show_command(&expected.unit_name, &names))?;
    let mut values = parse_show_generic(&output.stdout)?;
    let cgroup_path = values
        .remove("ControlGroup")
        .map(PathBuf::from)
        .ok_or(DnsExecBackendError::Readback)?;
    values.retain(|_, value| !value.is_empty());
    let uid = values
        .get("User")
        .and_then(|value| value.parse().ok())
        .ok_or(DnsExecBackendError::Readback)?;
    let network_mode = if expected.role == PrincipalRole::Materializer {
        UnitNetworkMode::HostTupleAllowlist {
            tuples: match &expected.network_mode {
                UnitNetworkMode::HostTupleAllowlist { tuples } => tuples.clone(),
                _ => return Err(DnsExecBackendError::Readback),
            },
        }
    } else {
        UnitNetworkMode::BrokerNoEgressNamespace {
            path: values
                .get("NetworkNamespacePath")
                .map(PathBuf::from)
                .ok_or(DnsExecBackendError::Readback)?,
        }
    };
    Ok(TransientUnitReadback {
        role: expected.role,
        uid,
        unit_name: expected.unit_name.clone(),
        cgroup_path,
        properties: values,
        network_mode,
    })
}

fn read_namespace<R: ExactCommandRunner>(
    runner: &mut R,
    expected: &NetworkNamespacePlan,
) -> Result<NetworkNamespaceReadback, DnsExecBackendError<R::Error>> {
    let list = run_required(
        runner,
        &ExactCommand::new(
            AllowedBinary::Ip,
            vec![os("-j"), os("netns"), os("list")],
            COMMAND_TIMEOUT,
        ),
    )?;
    let namespaces: Value =
        serde_json::from_slice(&list.stdout).map_err(|_| DnsExecBackendError::Readback)?;
    let present = namespaces.as_array().is_some_and(|entries| {
        entries
            .iter()
            .any(|entry| entry.get("name").and_then(Value::as_str) == Some(expected.name()))
    });
    let links = run_required(
        runner,
        &ExactCommand::new(
            AllowedBinary::Ip,
            vec![
                os("-n"),
                os(expected.name()),
                os("-j"),
                os("link"),
                os("show"),
            ],
            COMMAND_TIMEOUT,
        ),
    )?;
    let links: Value =
        serde_json::from_slice(&links.stdout).map_err(|_| DnsExecBackendError::Readback)?;
    let only_loopback_up = links.as_array().is_some_and(|entries| {
        entries.len() == 1
            && entries[0].get("ifname").and_then(Value::as_str) == Some("lo")
            && entries[0]
                .get("flags")
                .and_then(Value::as_array)
                .is_some_and(|flags| flags.iter().any(|flag| flag.as_str() == Some("UP")))
    });
    Ok(NetworkNamespaceReadback {
        name: if present {
            expected.name().to_owned()
        } else {
            String::new()
        },
        path: if present {
            expected.path().to_path_buf()
        } else {
            PathBuf::new()
        },
        loopback_up: only_loopback_up,
        egress_blocked: only_loopback_up,
    })
}

fn read_nft<R: ExactCommandRunner>(
    runner: &mut R,
    expected: &MaterializerNftPlan,
) -> Result<(MaterializerNftReadback, Vec<TcpServiceTuple>), DnsExecBackendError<R::Error>> {
    let output = run_required(
        runner,
        &nft(vec![
            os("-j"),
            os("list"),
            os("table"),
            os(expected.family()),
            os(expected.table()),
        ]),
    )?;
    let value: Value =
        serde_json::from_slice(&output.stdout).map_err(|_| DnsExecBackendError::Readback)?;
    let exact = nft_json_matches(&value, expected);
    let tuples = if exact {
        expected.allowed_tcp_tuples().to_vec()
    } else {
        Vec::new()
    };
    Ok((
        MaterializerNftReadback {
            family: expected.family().to_owned(),
            table: expected.table().to_owned(),
            chain: expected.chain().to_owned(),
            hook: NftHook::Output,
            priority: expected.priority(),
            principal_uid: expected.principal_uid(),
            allowed_tcp_tuples: tuples.clone(),
            unmatched_traffic_denied: exact,
        },
        tuples,
    ))
}

fn nft_json_matches(value: &Value, expected: &MaterializerNftPlan) -> bool {
    let Some(objects) = value.get("nftables").and_then(Value::as_array) else {
        return false;
    };
    let tables = objects
        .iter()
        .filter_map(|object| object.get("table"))
        .filter(|table| {
            table.get("family").and_then(Value::as_str) == Some(expected.family())
                && table.get("name").and_then(Value::as_str) == Some(expected.table())
        })
        .count();
    let chains = objects
        .iter()
        .filter_map(|object| object.get("chain"))
        .filter(|chain| {
            chain.get("family").and_then(Value::as_str) == Some(expected.family())
                && chain.get("table").and_then(Value::as_str) == Some(expected.table())
        })
        .collect::<Vec<_>>();
    if tables != 1
        || chains.len() != 1
        || chains[0].get("name").and_then(Value::as_str) != Some(expected.chain())
        || chains[0].get("type").and_then(Value::as_str) != Some("filter")
        || chains[0].get("hook").and_then(Value::as_str) != Some("output")
        || chains[0].get("prio").and_then(Value::as_i64) != Some(expected.priority().into())
        || chains[0].get("policy").and_then(Value::as_str) != Some("accept")
    {
        return false;
    }

    let rules = objects
        .iter()
        .filter_map(|object| object.get("rule"))
        .filter(|rule| {
            rule.get("family").and_then(Value::as_str) == Some(expected.family())
                && rule.get("table").and_then(Value::as_str) == Some(expected.table())
        })
        .collect::<Vec<_>>();
    if rules.len() != expected.allowed_tcp_tuples().len() + 1
        || rules
            .iter()
            .any(|rule| rule.get("chain").and_then(Value::as_str) != Some(expected.chain()))
    {
        return false;
    }

    let mut allows = BTreeSet::new();
    let mut drops = 0_usize;
    for rule in rules {
        match parse_nft_rule(rule, expected.principal_uid()) {
            Some(ParsedNftRule::Allow(tuple)) if allows.insert(tuple) => {}
            Some(ParsedNftRule::Drop) => drops += 1,
            _ => return false,
        }
    }
    allows == expected.allowed_tcp_tuples().iter().cloned().collect() && drops == 1
}

enum ParsedNftRule {
    Allow(TcpServiceTuple),
    Drop,
}

fn parse_nft_rule(rule: &Value, expected_uid: u32) -> Option<ParsedNftRule> {
    let expressions = rule.get("expr")?.as_array()?;
    if expressions.len() == 2
        && parse_uid_match(&expressions[0]) == Some(expected_uid)
        && exact_verdict(&expressions[1], "drop")
    {
        return Some(ParsedNftRule::Drop);
    }
    if expressions.len() != 4 || parse_uid_match(&expressions[0]) != Some(expected_uid) {
        return None;
    }
    let address = parse_address_match(&expressions[1])?;
    let port = parse_port_match(&expressions[2])?;
    if !exact_verdict(&expressions[3], "accept") {
        return None;
    }
    Some(ParsedNftRule::Allow(TcpServiceTuple { address, port }))
}

fn parse_uid_match(value: &Value) -> Option<u32> {
    let object = value.as_object()?;
    if object.len() != 1 {
        return None;
    }
    let matcher = object.get("match")?.as_object()?;
    if matcher.len() != 3 || matcher.get("op")?.as_str()? != "==" {
        return None;
    }
    let left = matcher.get("left")?.as_object()?;
    let meta = left.get("meta")?.as_object()?;
    if left.len() != 1 || meta.len() != 1 || meta.get("key")?.as_str()? != "skuid" {
        return None;
    }
    u32::try_from(matcher.get("right")?.as_u64()?).ok()
}

fn parse_address_match(value: &Value) -> Option<IpAddr> {
    let matcher = exact_match(value)?;
    let left = matcher.get("left")?.as_object()?;
    let payload = left.get("payload")?.as_object()?;
    if left.len() != 1 || payload.len() != 2 || payload.get("field")?.as_str()? != "daddr" {
        return None;
    }
    let address: IpAddr = matcher.get("right")?.as_str()?.parse().ok()?;
    let expected_protocol = if address.is_ipv4() { "ip" } else { "ip6" };
    (payload.get("protocol")?.as_str()? == expected_protocol).then_some(address)
}

fn parse_port_match(value: &Value) -> Option<u16> {
    let matcher = exact_match(value)?;
    let left = matcher.get("left")?.as_object()?;
    let payload = left.get("payload")?.as_object()?;
    if left.len() != 1
        || payload.len() != 2
        || payload.get("protocol")?.as_str()? != "tcp"
        || payload.get("field")?.as_str()? != "dport"
    {
        return None;
    }
    u16::try_from(matcher.get("right")?.as_u64()?).ok()
}

fn exact_match(value: &Value) -> Option<&serde_json::Map<String, Value>> {
    let object = value.as_object()?;
    if object.len() != 1 {
        return None;
    }
    let matcher = object.get("match")?.as_object()?;
    (matcher.len() == 3 && matcher.get("op")?.as_str()? == "==").then_some(matcher)
}

fn exact_verdict(value: &Value, verdict: &str) -> bool {
    value
        .as_object()
        .is_some_and(|object| object.len() == 1 && object.get(verdict) == Some(&Value::Null))
}

struct DnsProbeReadback {
    principal_dns: Vec<PrincipalDnsObservation>,
    tuple_connect_probes: Vec<TupleConnectProbe>,
}

fn run_dns_probes<R: ExactCommandRunner>(
    runner: &mut R,
    plan: &LeaseIsolationPlan,
) -> Result<DnsProbeReadback, DnsExecBackendError<R::Error>> {
    let mut principal_dns = Vec::new();
    for unit in &plan.units {
        let mut files_lookups = Vec::new();
        if unit.role == PrincipalRole::Materializer {
            for pin in &plan.dns_files.sni_host_pins {
                let label = match pin.service {
                    crate::dns_isolation::PinnedServiceKind::Relay => "files-relay",
                    crate::dns_isolation::PinnedServiceKind::Mirror => "files-mirror",
                };
                let output = runner
                    .run(&probe_command(
                        unit,
                        AllowedBinary::Getent,
                        vec![os("ahosts"), os(&pin.hostname)],
                        label,
                    ))
                    .map_err(DnsExecBackendError::Transport)?;
                files_lookups.push(FilesLookupProbe {
                    hostname: pin.hostname.clone(),
                    addresses: parse_getent_addresses(&output.stdout),
                    resolved_by_files: output.success(),
                });
            }
        }
        let arbitrary_getent_succeeded = probe_succeeded(
            runner,
            &probe_command(
                unit,
                AllowedBinary::Getent,
                vec![os("hosts"), os("unlisted.invalid")],
                "getent",
            ),
        )?;
        let resolved_varlink_accessible = probe_succeeded(
            runner,
            &probe_command(
                unit,
                AllowedBinary::Stat,
                vec![os("/run/systemd/resolve/io.systemd.Resolve")],
                "varlink",
            ),
        )?;
        let direct_tcp_53_connected = probe_succeeded(
            runner,
            &probe_command(
                unit,
                AllowedBinary::Ncat,
                vec![os("-z"), os("-w"), os("1"), os("1.1.1.1"), os("53")],
                "tcp53",
            ),
        )?;
        let direct_udp_53_connected = probe_succeeded(
            runner,
            &probe_command(
                unit,
                AllowedBinary::Dig,
                vec![
                    os("+time=1"),
                    os("+tries=1"),
                    os("@1.1.1.1"),
                    os("unlisted.invalid"),
                ],
                "udp53",
            ),
        )?;
        principal_dns.push(PrincipalDnsObservation {
            role: unit.role,
            files_lookups,
            arbitrary_getent_succeeded,
            resolved_varlink_accessible,
            direct_udp_53_connected,
            direct_tcp_53_connected,
        });
    }
    let materializer = plan
        .units
        .iter()
        .find(|unit| unit.role == PrincipalRole::Materializer)
        .ok_or(DnsExecBackendError::Readback)?;
    let denied = TcpServiceTuple {
        address: DENIED_CONTROL_ADDRESS
            .parse()
            .map_err(|_| DnsExecBackendError::Readback)?,
        port: DENIED_CONTROL_PORT,
    };
    let mut tuples = plan.materializer_allowlist.clone();
    tuples.push(denied);
    let mut tuple_connect_probes = Vec::new();
    for (index, tuple) in tuples.into_iter().enumerate() {
        let label = format!("tuple-{index}");
        let connected = probe_succeeded(
            runner,
            &probe_command(
                materializer,
                AllowedBinary::Ncat,
                vec![
                    os("-z"),
                    os("-w"),
                    os("2"),
                    os(tuple.address.to_string()),
                    os(tuple.port.to_string()),
                ],
                &label,
            ),
        )?;
        tuple_connect_probes.push(TupleConnectProbe {
            role: PrincipalRole::Materializer,
            tuple,
            connected,
        });
    }
    Ok(DnsProbeReadback {
        principal_dns,
        tuple_connect_probes,
    })
}

fn probe_command(
    unit: &TransientUnitPlan,
    program: AllowedBinary,
    program_argv: Vec<OsString>,
    label: &str,
) -> ExactCommand {
    let mut argv = vec![
        os("--quiet"),
        os("--wait"),
        os("--pipe"),
        os("--collect"),
        os(format!(
            "--unit={}-probe-{label}",
            unit.unit_name.trim_end_matches(".service")
        )),
        os(format!(
            "--slice={}",
            unit.properties.get("Slice").expect("closed plan has Slice")
        )),
        os(format!("--uid={}", unit.uid)),
    ];
    argv.extend(
        unit.properties
            .iter()
            .filter(|(name, _)| name.as_str() != "Slice" && name.as_str() != "User")
            .map(|(name, value)| os(format!("--property={name}={value}"))),
    );
    argv.push(os(program.path()));
    argv.extend(program_argv);
    ExactCommand::new(AllowedBinary::SystemdRun, argv, PROBE_TIMEOUT)
}

fn probe_succeeded<R: ExactCommandRunner>(
    runner: &mut R,
    command: &ExactCommand,
) -> Result<bool, DnsExecBackendError<R::Error>> {
    let output = runner
        .run(command)
        .map_err(DnsExecBackendError::Transport)?;
    if output.stdout_truncated || output.stderr_truncated {
        return Err(DnsExecBackendError::Command);
    }
    Ok(output.success())
}

fn parse_getent_addresses(bytes: &[u8]) -> Vec<IpAddr> {
    bytes
        .split(|byte| byte.is_ascii_whitespace())
        .filter_map(|field| std::str::from_utf8(field).ok())
        .filter_map(|field| field.parse().ok())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn publish_dns_files(
    roots: &ExecutorRoots,
    plan: &DnsExecPlan,
    owned: &mut OwnedResources,
) -> Result<(), DnsExecFsError> {
    open_directory_path(roots, Path::new(LEASE_ROOT), true)?;
    let lease_directory = Path::new(LEASE_ROOT).join(&plan.isolation.lease_id);
    let lease = open_directory_path(roots, &lease_directory, true)?;
    if lease.created {
        owned.lease_directory = Some(lease.identity);
    }
    let resolv = atomic_publish(
        roots,
        &lease_directory,
        "empty-resolv.conf",
        &plan.resolv_conf,
        DNS_FILE_MODE,
    )?;
    if resolv.created {
        owned.resolv_conf = Some(resolv.identity);
    }
    let hosts = atomic_publish(roots, &lease_directory, "hosts", &plan.hosts, DNS_FILE_MODE)?;
    if hosts.created {
        owned.hosts = Some(hosts.identity);
    }
    Ok(())
}

fn publish_receipt(
    roots: &ExecutorRoots,
    name: &str,
    receipt: &DnsExecReceipt,
) -> Result<(), DnsExecFsError> {
    let receipt_directory = Path::new(ACTIVATION_ROOT).join("receipts/dns");
    open_directory_path(roots, &receipt_directory, true)?;
    let bytes = serde_json::to_vec(receipt).map_err(|_| DnsExecFsError::Publish)?;
    atomic_publish(roots, &receipt_directory, name, &bytes, RECEIPT_FILE_MODE)?;
    Ok(())
}

struct OpenDirectory {
    file: File,
    identity: FileIdentity,
    created: bool,
}

struct PublishedFile {
    identity: FileIdentity,
    created: bool,
}

fn open_directory_path(
    roots: &ExecutorRoots,
    canonical: &Path,
    create: bool,
) -> Result<OpenDirectory, DnsExecFsError> {
    let components = canonical_components(canonical)?;
    let mut current = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(&roots.base_root)
        .map_err(|_| DnsExecFsError::UnsafeDirectory)?;
    validate_directory(&current, roots, false)?;
    let mut created_final = false;
    for (index, component) in components.iter().enumerate() {
        let final_component = index + 1 == components.len();
        let opened = openat(
            &current,
            *component,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        );
        let descriptor = match opened {
            Ok(descriptor) => descriptor,
            Err(Errno::ENOENT) if create => {
                mkdirat(
                    &current,
                    *component,
                    Mode::from_bits_truncate(DIRECTORY_MODE),
                )
                .map_err(|_| DnsExecFsError::Publish)?;
                let descriptor = openat(
                    &current,
                    *component,
                    OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| DnsExecFsError::UnsafeDirectory)?;
                fchown(
                    &descriptor,
                    Some(Uid::from_raw(roots.owner_uid)),
                    Some(Gid::from_raw(roots.owner_gid)),
                )
                .map_err(|_| DnsExecFsError::Publish)?;
                fchmod(&descriptor, Mode::from_bits_truncate(DIRECTORY_MODE))
                    .map_err(|_| DnsExecFsError::Publish)?;
                created_final = final_component;
                descriptor
            }
            Err(_) => return Err(DnsExecFsError::UnsafeDirectory),
        };
        current = File::from(descriptor);
        validate_directory(&current, roots, final_component)?;
    }
    if descriptor_canonical_path(roots, &current)? != canonical {
        return Err(DnsExecFsError::UnsafeDirectory);
    }
    let identity = file_identity(&current).map_err(|_| DnsExecFsError::UnsafeDirectory)?;
    Ok(OpenDirectory {
        file: current,
        identity,
        created: created_final,
    })
}

fn canonical_components(path: &Path) -> Result<Vec<&OsStr>, DnsExecFsError> {
    if !path.is_absolute() {
        return Err(DnsExecFsError::UnsafePath);
    }
    path.components()
        .filter_map(|component| match component {
            Component::RootDir => None,
            Component::Normal(value) => Some(Ok(value)),
            _ => Some(Err(DnsExecFsError::UnsafePath)),
        })
        .collect()
}

fn validate_directory(
    directory: &File,
    roots: &ExecutorRoots,
    require_private: bool,
) -> Result<(), DnsExecFsError> {
    let metadata = directory
        .metadata()
        .map_err(|_| DnsExecFsError::UnsafeDirectory)?;
    let mode = metadata.permissions().mode() & 0o7777;
    if !metadata.file_type().is_dir()
        || metadata.uid() != roots.owner_uid
        || metadata.gid() != roots.owner_gid
        || if require_private {
            mode != DIRECTORY_MODE
        } else {
            mode & 0o022 != 0
        }
    {
        return Err(DnsExecFsError::UnsafeDirectory);
    }
    Ok(())
}

fn descriptor_canonical_path(
    roots: &ExecutorRoots,
    descriptor: &File,
) -> Result<PathBuf, DnsExecFsError> {
    let actual = fs::read_link(format!("/proc/self/fd/{}", descriptor.as_raw_fd()))
        .map_err(|_| DnsExecFsError::UnsafePath)?;
    if roots.base_root == Path::new("/") {
        return Ok(actual);
    }
    let relative = actual
        .strip_prefix(&roots.base_root)
        .map_err(|_| DnsExecFsError::UnsafePath)?;
    Ok(Path::new("/").join(relative))
}

fn atomic_publish(
    roots: &ExecutorRoots,
    directory: &Path,
    name: &str,
    bytes: &[u8],
    mode: u32,
) -> Result<PublishedFile, DnsExecFsError> {
    validate_name(name)?;
    let directory = open_directory_path(roots, directory, false)?;
    match openat(
        &directory.file,
        name,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    ) {
        Ok(descriptor) => {
            return verify_published_file(
                roots,
                File::from(descriptor),
                directory_path_from_fd(roots, &directory.file)?.join(name),
                bytes,
                mode,
                false,
            );
        }
        Err(Errno::ENOENT) => {}
        Err(_) => return Err(DnsExecFsError::UnsafeFile),
    }

    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary_name = format!(".{name}.{}.{}.tmp", std::process::id(), sequence);
    let descriptor = openat(
        &directory.file,
        temporary_name.as_str(),
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(|_| DnsExecFsError::Publish)?;
    let mut temporary = File::from(descriptor);
    let publication = (|| {
        temporary
            .write_all(bytes)
            .map_err(|_| DnsExecFsError::Publish)?;
        temporary.sync_all().map_err(|_| DnsExecFsError::Publish)?;
        fchown(
            &temporary,
            Some(Uid::from_raw(roots.owner_uid)),
            Some(Gid::from_raw(roots.owner_gid)),
        )
        .map_err(|_| DnsExecFsError::Publish)?;
        fchmod(&temporary, Mode::from_bits_truncate(mode)).map_err(|_| DnsExecFsError::Publish)?;
        temporary.sync_all().map_err(|_| DnsExecFsError::Publish)?;
        match renameat2(
            &directory.file,
            temporary_name.as_str(),
            &directory.file,
            name,
            RenameFlags::RENAME_NOREPLACE,
        ) {
            Ok(()) => {}
            Err(Errno::EEXIST) => {
                unlinkat(
                    &directory.file,
                    temporary_name.as_str(),
                    UnlinkatFlags::NoRemoveDir,
                )
                .map_err(|_| DnsExecFsError::Remove)?;
                let existing = openat(
                    &directory.file,
                    name,
                    OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| DnsExecFsError::UnsafeFile)?;
                return verify_published_file(
                    roots,
                    File::from(existing),
                    directory_path_from_fd(roots, &directory.file)?.join(name),
                    bytes,
                    mode,
                    false,
                );
            }
            Err(_) => return Err(DnsExecFsError::Publish),
        }
        directory
            .file
            .sync_all()
            .map_err(|_| DnsExecFsError::Publish)?;
        let published = openat(
            &directory.file,
            name,
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| DnsExecFsError::UnsafeFile)?;
        verify_published_file(
            roots,
            File::from(published),
            directory_path_from_fd(roots, &directory.file)?.join(name),
            bytes,
            mode,
            true,
        )
    })();
    if publication.is_err() {
        let _ = unlinkat(
            &directory.file,
            temporary_name.as_str(),
            UnlinkatFlags::NoRemoveDir,
        );
    }
    publication
}

fn directory_path_from_fd(
    roots: &ExecutorRoots,
    directory: &File,
) -> Result<PathBuf, DnsExecFsError> {
    descriptor_canonical_path(roots, directory)
}

fn validate_name(name: &str) -> Result<(), DnsExecFsError> {
    if name.is_empty()
        || name
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && !b"._-".contains(&byte))
    {
        return Err(DnsExecFsError::UnsafePath);
    }
    Ok(())
}

fn verify_published_file(
    roots: &ExecutorRoots,
    mut file: File,
    expected_path: PathBuf,
    bytes: &[u8],
    mode: u32,
    created: bool,
) -> Result<PublishedFile, DnsExecFsError> {
    let metadata = file.metadata().map_err(|_| DnsExecFsError::UnsafeFile)?;
    let identity = FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    let mut observed = Vec::new();
    file.read_to_end(&mut observed)
        .map_err(|_| DnsExecFsError::UnsafeFile)?;
    if !safe_owned_file(&metadata, roots, mode)
        || observed != bytes
        || descriptor_canonical_path(roots, &file)? != expected_path
    {
        return Err(DnsExecFsError::UnsafeFile);
    }
    Ok(PublishedFile { identity, created })
}

fn safe_owned_file(metadata: &fs::Metadata, roots: &ExecutorRoots, mode: u32) -> bool {
    metadata.file_type().is_file()
        && metadata.uid() == roots.owner_uid
        && metadata.gid() == roots.owner_gid
        && metadata.nlink() == 1
        && metadata.permissions().mode() & 0o7777 == mode
}

fn file_identity(file: &File) -> Result<FileIdentity, std::io::Error> {
    let metadata = file.metadata()?;
    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn read_dns_files(
    roots: &ExecutorRoots,
    plan: &LeaseIsolationPlan,
) -> Result<DnsFilesReadback, DnsExecFsError> {
    Ok(DnsFilesReadback {
        resolv_conf: read_pinned_file(roots, plan.dns_files.resolv_conf.requested_path())?,
        hosts: read_pinned_file(roots, plan.dns_files.hosts.requested_path())?,
    })
}

fn read_pinned_file(
    roots: &ExecutorRoots,
    canonical: &Path,
) -> Result<BrokerPinnedFileReadback, DnsExecFsError> {
    let parent = canonical.parent().ok_or(DnsExecFsError::UnsafePath)?;
    let name = canonical
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or(DnsExecFsError::UnsafePath)?;
    validate_name(name)?;
    let directory = open_directory_path(roots, parent, false)?;
    let descriptor = openat(
        &directory.file,
        name,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| DnsExecFsError::UnsafeFile)?;
    let mut file = File::from(descriptor);
    let metadata = file.metadata().map_err(|_| DnsExecFsError::UnsafeFile)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|_| DnsExecFsError::UnsafeFile)?;
    Ok(BrokerPinnedFileReadback {
        requested_path: canonical.to_path_buf(),
        canonical_path: descriptor_canonical_path(roots, &file)?,
        owner_uid: if metadata.uid() == roots.owner_uid {
            0
        } else {
            metadata.uid()
        },
        owner_gid: if metadata.gid() == roots.owner_gid {
            0
        } else {
            metadata.gid()
        },
        mode: metadata.permissions().mode() & 0o7777,
        file_type: if metadata.file_type().is_file() {
            BrokerFileType::Regular
        } else if metadata.file_type().is_symlink() {
            BrokerFileType::Symlink
        } else {
            BrokerFileType::Other
        },
        type_checked_no_follow: true,
        link_count: metadata.nlink(),
        sha256: sha256_hex(&bytes),
    })
}

fn cleanup_owned<R: ExactCommandRunner>(
    runner: &mut R,
    roots: &ExecutorRoots,
    plan: &DnsExecPlan,
    owned: &OwnedResources,
) -> Result<(), DnsExecBackendError<R::Error>> {
    cleanup_host(
        runner,
        plan.host.identifiers().lease_slice(),
        plan.host.identifiers().namespace_name(),
        plan.host.identifiers().nft_table(),
        owned,
    )?;
    remove_lease_files(roots, &plan.isolation.lease_id, owned).map_err(DnsExecBackendError::Files)
}

fn remove_lease_files(
    roots: &ExecutorRoots,
    lease_id: &str,
    owned: &OwnedResources,
) -> Result<(), DnsExecFsError> {
    if lease_id.is_empty()
        || !lease_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(DnsExecFsError::UnsafePath);
    }
    if owned.lease_directory.is_none() && owned.resolv_conf.is_none() && owned.hosts.is_none() {
        return Ok(());
    }
    let canonical = Path::new(LEASE_ROOT).join(lease_id);
    let directory = open_directory_path(roots, &canonical, false)?;
    for (name, expected) in [
        ("empty-resolv.conf", owned.resolv_conf),
        ("hosts", owned.hosts),
    ] {
        if let Some(expected) = expected {
            verify_identity_at(&directory.file, name, expected, roots, DNS_FILE_MODE)?;
            unlinkat(&directory.file, name, UnlinkatFlags::NoRemoveDir)
                .map_err(|_| DnsExecFsError::Remove)?;
        }
    }
    if let Some(expected) = owned.lease_directory {
        if directory.identity != expected {
            return Err(DnsExecFsError::UnsafeDirectory);
        }
        let parent = open_directory_path(roots, Path::new(LEASE_ROOT), false)?;
        unlinkat(&parent.file, lease_id, UnlinkatFlags::RemoveDir)
            .map_err(|_| DnsExecFsError::Remove)?;
    }
    Ok(())
}

fn verify_identity_at(
    directory: &File,
    name: &str,
    expected: FileIdentity,
    roots: &ExecutorRoots,
    mode: u32,
) -> Result<(), DnsExecFsError> {
    let descriptor = openat(
        directory,
        name,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| DnsExecFsError::UnsafeFile)?;
    let file = File::from(descriptor);
    let metadata = file.metadata().map_err(|_| DnsExecFsError::UnsafeFile)?;
    if !safe_owned_file(&metadata, roots, mode)
        || (FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        }) != expected
    {
        return Err(DnsExecFsError::UnsafeFile);
    }
    Ok(())
}

fn owned_from_receipt(
    roots: &ExecutorRoots,
    plan: &DnsExecPlan,
) -> Result<OwnedResources, DnsExecFsError> {
    let directory_path = Path::new(LEASE_ROOT).join(&plan.isolation.lease_id);
    let directory = open_directory_path(roots, &directory_path, false)?;
    let resolv = existing_file_identity(
        roots,
        &directory,
        "empty-resolv.conf",
        &plan.resolv_conf,
        DNS_FILE_MODE,
    )?;
    let hosts = existing_file_identity(roots, &directory, "hosts", &plan.hosts, DNS_FILE_MODE)?;
    Ok(OwnedResources {
        slice: true,
        namespace: true,
        nft_table: true,
        lease_directory: Some(directory.identity),
        resolv_conf: Some(resolv),
        hosts: Some(hosts),
    })
}

fn existing_file_identity(
    roots: &ExecutorRoots,
    directory: &OpenDirectory,
    name: &str,
    bytes: &[u8],
    mode: u32,
) -> Result<FileIdentity, DnsExecFsError> {
    let descriptor = openat(
        &directory.file,
        name,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| DnsExecFsError::UnsafeFile)?;
    Ok(verify_published_file(
        roots,
        File::from(descriptor),
        directory_path_from_fd(roots, &directory.file)?.join(name),
        bytes,
        mode,
        false,
    )?
    .identity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_host::DnsHostDisposition;
    use crate::dns_isolation::{
        build_lease_isolation_plan, BrokerApprovedMaterializerNetwork, BrokerPinnedFile,
        DelegationCanaryReadback, DnsFiles, LeaseIsolationRequest, LeaseSliceIdentity,
        NetworkNamespaceProperty, PinnedServiceKind, PrincipalUnitIdentity, SniHostPin,
        UnitResources, EMPTY_FILE_SHA256,
    };
    use serde_json::json;
    use std::os::unix::fs::symlink;
    use tempfile::tempdir;

    fn tuple(address: &str, port: u16) -> TcpServiceTuple {
        TcpServiceTuple {
            address: address.parse().unwrap(),
            port,
        }
    }

    fn isolation_plan() -> LeaseIsolationPlan {
        let lease_id = "lease01";
        let slice_name = format!("buzzci-{lease_id}.slice");
        let slice_path = Path::new("/buzzci.slice").join(&slice_name);
        let units = [
            (PrincipalRole::Materializer, 966, "mat"),
            (PrincipalRole::Executor, 965, "exec"),
            (PrincipalRole::Runtime, 964, "run"),
        ]
        .into_iter()
        .map(|(role, uid, suffix)| {
            let unit_name = format!("buzzci-{lease_id}-{suffix}.service");
            PrincipalUnitIdentity {
                role,
                uid,
                cgroup_path: slice_path.join(&unit_name),
                unit_name,
            }
        })
        .collect::<Vec<_>>();
        let pins = vec![
            SniHostPin {
                service: PinnedServiceKind::Relay,
                hostname: "relay.example".to_owned(),
                addresses: vec!["198.51.100.10".parse().unwrap()],
            },
            SniHostPin {
                service: PinnedServiceKind::Mirror,
                hostname: "mirror.example".to_owned(),
                addresses: vec!["2001:db8::20".parse().unwrap()],
            },
        ];
        let hosts = b"2001:db8::20 mirror.example\n198.51.100.10 relay.example\n";
        build_lease_isolation_plan(LeaseIsolationRequest {
            lease_id: lease_id.to_owned(),
            resources: UnitResources {
                cpu_weight: 100,
                memory_max_bytes: 2 * 1024 * 1024 * 1024,
                tasks_max: 512,
                io_weight: 100,
                cpu_quota_per_sec_usec: 200_000,
            },
            lease_slice: LeaseSliceIdentity {
                unit_name: slice_name,
                cgroup_path: slice_path,
            },
            units,
            delegation_canary: DelegationCanaryReadback {
                fedora_release: "42".to_owned(),
                systemd_version: "257.7-1.fc42".to_owned(),
                property: NetworkNamespaceProperty::NetworkNamespacePath,
                namespace_path: PathBuf::from("/run/netns/buzzci-lease01"),
                uid_results: BTreeMap::from([(964, true), (965, true), (966, true)]),
            },
            dns_files: DnsFiles {
                resolv_conf: BrokerPinnedFile::new(
                    PathBuf::from("/var/lib/buzzci/leases/lease01/empty-resolv.conf"),
                    EMPTY_FILE_SHA256.to_owned(),
                )
                .unwrap(),
                hosts: BrokerPinnedFile::new(
                    PathBuf::from("/var/lib/buzzci/leases/lease01/hosts"),
                    sha256_hex(hosts),
                )
                .unwrap(),
                sni_host_pins: pins,
            },
            approved_materializer_network: BrokerApprovedMaterializerNetwork::new(
                tuple("198.51.100.10", 443),
                tuple("2001:db8::20", 443),
            )
            .unwrap(),
        })
        .unwrap()
    }

    fn activation_binding() -> DnsActivationBinding {
        DnsActivationBinding {
            integrated_candidate_sha: "1".repeat(40),
            broker_build_identity: "2".repeat(64),
            host_profile_digest: "3".repeat(64),
            suite_identity: "4".repeat(64),
            fixture_signer: "5".repeat(64),
            request_digest: "6".repeat(64),
            manifest_digest: "7".repeat(64),
            isolation_profile_digest: "8".repeat(64),
            lease_id: "lease01".to_owned(),
            lease_generation: 9,
            observed_at_unix_ns: 10,
        }
    }

    #[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
    #[error("scripted runner transport failure")]
    struct ScriptedError;

    struct ScriptedRunner {
        plan: LeaseIsolationPlan,
        commands: Vec<ExactCommand>,
        fail_at: Option<usize>,
        slice_exists: bool,
        namespace_exists: bool,
        table_exists: bool,
        namespace_deleted: bool,
        table_deleted: bool,
        slice_stopped: bool,
    }

    impl ScriptedRunner {
        fn new(plan: LeaseIsolationPlan) -> Self {
            Self {
                plan,
                commands: Vec::new(),
                fail_at: None,
                slice_exists: false,
                namespace_exists: false,
                table_exists: false,
                namespace_deleted: false,
                table_deleted: false,
                slice_stopped: false,
            }
        }

        fn output(exit_code: i32, stdout: impl Into<Vec<u8>>) -> ExactCommandOutput {
            ExactCommandOutput {
                exit_code: Some(exit_code),
                stdout: stdout.into(),
                stderr: Vec::new(),
                stdout_truncated: false,
                stderr_truncated: false,
            }
        }

        fn args(command: &ExactCommand) -> Vec<String> {
            command
                .argv()
                .iter()
                .map(|value| value.to_string_lossy().into_owned())
                .collect()
        }

        fn systemctl_show(&self, args: &[String]) -> ExactCommandOutput {
            let unit = &args[2];
            if args.iter().any(|arg| arg == "--property=LoadState") {
                let state = if self.slice_exists {
                    "loaded"
                } else {
                    "not-found"
                };
                return Self::output(0, format!("LoadState={state}\n").into_bytes());
            }
            if unit == &self.plan.lease_slice.unit_name {
                let mut values = self.plan.lease_slice.properties.clone();
                values.insert(
                    "ControlGroup".to_owned(),
                    self.plan.lease_slice.cgroup_path.display().to_string(),
                );
                return Self::output(0, encode_show(&values));
            }
            let expected = self
                .plan
                .units
                .iter()
                .find(|candidate| candidate.unit_name == *unit)
                .unwrap();
            let mut values = expected.properties.clone();
            values.insert(
                "ControlGroup".to_owned(),
                expected.cgroup_path.display().to_string(),
            );
            Self::output(0, encode_show(&values))
        }

        fn nft_readback(&self) -> Vec<u8> {
            let policy = DnsHostPlan::new(self.plan.clone()).unwrap();
            let policy = policy.materializer_policy();
            let mut objects = vec![
                json!({
                    "table": {
                        "family": policy.family(),
                        "name": policy.table()
                    }
                }),
                json!({
                    "chain": {
                        "family": policy.family(),
                        "table": policy.table(),
                        "name": policy.chain(),
                        "type": "filter",
                        "hook": "output",
                        "prio": policy.priority(),
                        "policy": "accept"
                    }
                }),
            ];
            for tuple in policy.allowed_tcp_tuples() {
                objects.push(json!({
                    "rule": {
                        "family": policy.family(),
                        "table": policy.table(),
                        "chain": policy.chain(),
                        "expr": [
                            {"match": {"op": "==", "left": {"meta": {"key": "skuid"}}, "right": policy.principal_uid()}},
                            {"match": {"op": "==", "left": {"payload": {"protocol": if tuple.address.is_ipv4() { "ip" } else { "ip6" }, "field": "daddr"}}, "right": tuple.address.to_string()}},
                            {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": tuple.port}},
                            {"accept": null}
                        ]
                    }
                }));
            }
            objects.push(json!({
                "rule": {
                        "family": policy.family(),
                        "table": policy.table(),
                        "chain": policy.chain(),
                        "expr": [
                            {"match": {"op": "==", "left": {"meta": {"key": "skuid"}}, "right": policy.principal_uid()}},
                            {"drop": null}
                        ]
                }
            }));
            serde_json::to_vec(&json!({"nftables": objects})).unwrap()
        }

        fn probe_output(&self, args: &[String]) -> ExactCommandOutput {
            let Some(program_index) = args.iter().position(|arg| {
                [
                    AllowedBinary::Getent.path(),
                    AllowedBinary::Dig.path(),
                    AllowedBinary::Stat.path(),
                    AllowedBinary::Ncat.path(),
                ]
                .contains(&arg.as_str())
            }) else {
                return Self::output(0, Vec::new());
            };
            match args[program_index].as_str() {
                path if path == AllowedBinary::Getent.path() => {
                    let hostname = args.last().unwrap();
                    match hostname.as_str() {
                        "relay.example" => {
                            Self::output(0, b"198.51.100.10 STREAM relay.example\n".to_vec())
                        }
                        "mirror.example" => {
                            Self::output(0, b"2001:db8::20 STREAM mirror.example\n".to_vec())
                        }
                        _ => Self::output(2, Vec::new()),
                    }
                }
                path if path == AllowedBinary::Stat.path() => Self::output(1, Vec::new()),
                path if path == AllowedBinary::Dig.path() => Self::output(1, Vec::new()),
                path if path == AllowedBinary::Ncat.path() => {
                    let port = args.last().unwrap().parse::<u16>().unwrap();
                    Self::output(
                        if port == 53 || port == DENIED_CONTROL_PORT {
                            1
                        } else {
                            0
                        },
                        Vec::new(),
                    )
                }
                _ => unreachable!(),
            }
        }
    }

    impl ExactCommandRunner for ScriptedRunner {
        type Error = ScriptedError;

        fn run(&mut self, command: &ExactCommand) -> Result<ExactCommandOutput, Self::Error> {
            let index = self.commands.len();
            self.commands.push(command.clone());
            if self.fail_at == Some(index) {
                self.fail_at = None;
                return Ok(Self::output(1, Vec::new()));
            }
            let args = Self::args(command);
            match command.binary() {
                AllowedBinary::Systemctl if args.first().map(String::as_str) == Some("show") => {
                    Ok(self.systemctl_show(&args))
                }
                AllowedBinary::Systemctl
                    if args.first().map(String::as_str) == Some("set-property") =>
                {
                    self.slice_exists = true;
                    Ok(Self::output(0, Vec::new()))
                }
                AllowedBinary::Systemctl if args.first().map(String::as_str) == Some("stop") => {
                    self.slice_exists = false;
                    self.slice_stopped = true;
                    Ok(Self::output(0, Vec::new()))
                }
                AllowedBinary::Systemctl
                    if args.first().map(String::as_str) == Some("is-active") =>
                {
                    Ok(Self::output(
                        if self.slice_exists { 0 } else { 3 },
                        Vec::new(),
                    ))
                }
                AllowedBinary::Ip if args == ["-j", "netns", "list"] => {
                    let value = if self.namespace_exists {
                        json!([{"name": "buzzci-lease01"}])
                    } else {
                        json!([])
                    };
                    Ok(Self::output(0, serde_json::to_vec(&value).unwrap()))
                }
                AllowedBinary::Ip
                    if args.first().map(String::as_str) == Some("netns")
                        && args.get(1).map(String::as_str) == Some("add") =>
                {
                    self.namespace_exists = true;
                    Ok(Self::output(0, Vec::new()))
                }
                AllowedBinary::Ip
                    if args.first().map(String::as_str) == Some("netns")
                        && args.get(1).map(String::as_str) == Some("delete") =>
                {
                    self.namespace_exists = false;
                    self.namespace_deleted = true;
                    Ok(Self::output(0, Vec::new()))
                }
                AllowedBinary::Ip if args.contains(&"show".to_owned()) => Ok(Self::output(
                    0,
                    serde_json::to_vec(&json!([{"ifname":"lo","flags":["LOOPBACK","UP"]}]))
                        .unwrap(),
                )),
                AllowedBinary::Nft if args.first().map(String::as_str) == Some("delete") => {
                    self.table_exists = false;
                    self.table_deleted = true;
                    Ok(Self::output(0, Vec::new()))
                }
                AllowedBinary::Nft if args.first().map(String::as_str) == Some("list") => Ok(
                    Self::output(if self.table_exists { 0 } else { 1 }, Vec::new()),
                ),
                AllowedBinary::Nft if args == ["-j", "list", "tables"] => {
                    let tables = if self.table_exists {
                        json!([{"table": {"family": "inet", "name": "buzzci_lease01"}}])
                    } else {
                        json!([])
                    };
                    Ok(Self::output(
                        0,
                        serde_json::to_vec(&json!({"nftables": tables})).unwrap(),
                    ))
                }
                AllowedBinary::Nft if args.first().map(String::as_str) == Some("-j") => {
                    Ok(Self::output(0, self.nft_readback()))
                }
                AllowedBinary::Nft if args.starts_with(&["add".to_owned(), "table".to_owned()]) => {
                    self.table_exists = true;
                    Ok(Self::output(0, Vec::new()))
                }
                AllowedBinary::SystemdRun => Ok(self.probe_output(&args)),
                _ => Ok(Self::output(0, Vec::new())),
            }
        }
    }

    fn encode_show(values: &BTreeMap<String, String>) -> Vec<u8> {
        values
            .iter()
            .map(|(name, value)| format!("{name}={value}\n"))
            .collect::<String>()
            .into_bytes()
    }

    fn precreate_lease_files(base: &Path, hosts: &[u8]) -> PathBuf {
        let lease = base.join("var/lib/buzzci/leases/lease01");
        fs::create_dir_all(&lease).unwrap();
        fs::set_permissions(
            base.join("var/lib/buzzci/leases"),
            fs::Permissions::from_mode(DIRECTORY_MODE),
        )
        .unwrap();
        fs::set_permissions(&lease, fs::Permissions::from_mode(DIRECTORY_MODE)).unwrap();
        fs::write(lease.join("empty-resolv.conf"), []).unwrap();
        fs::write(lease.join("hosts"), hosts).unwrap();
        for name in ["empty-resolv.conf", "hosts"] {
            fs::set_permissions(lease.join(name), fs::Permissions::from_mode(DNS_FILE_MODE))
                .unwrap();
        }
        lease
    }

    #[test]
    fn command_plan_is_absolute_allowlisted_shell_free_and_deterministic() {
        let plan = DnsExecPlan::new(isolation_plan(), activation_binding()).unwrap();
        let commands = plan
            .host
            .actions()
            .iter()
            .flat_map(commands_for_action)
            .collect::<Vec<_>>();
        assert_eq!(commands.len(), 12);
        assert!(commands.iter().all(|command| {
            command.binary().path().starts_with('/')
                && command.timeout() == COMMAND_TIMEOUT
                && !matches!(
                    command.binary().path(),
                    "/bin/sh" | "/usr/bin/bash" | "/usr/bin/env"
                )
        }));
        assert_eq!(commands[0].binary(), AllowedBinary::Systemctl);
        assert_eq!(commands[1].binary(), AllowedBinary::Ip);
        assert_eq!(commands[3].binary(), AllowedBinary::Nft);
        assert_eq!(commands[9].binary(), AllowedBinary::SystemdRun);
        assert!(ScriptedRunner::args(&commands[9])
            .iter()
            .any(|arg| arg == "--property=PrivateNetwork=no"));
    }

    #[test]
    fn complete_executor_seals_files_runs_readback_and_records_ready() {
        let isolation = isolation_plan();
        let plan = DnsExecPlan::new(isolation.clone(), activation_binding()).unwrap();
        let temporary = tempdir().unwrap();
        let runner = ScriptedRunner::new(isolation);
        let mut executor = DnsExecutor::mapped(runner, temporary.path());
        let outcome = executor.apply(&plan).unwrap();
        assert!(outcome.host.readback.dns_readback.files_lookup_ok);
        assert!(outcome.host.readback.dns_readback.allowed_tuples_only);
        assert_eq!(outcome.host.disposition, DnsHostDisposition::Released);
        assert!(outcome.receipt.committed);
        assert_eq!(outcome.receipt.activation, activation_binding());

        let lease_root = temporary.path().join("var/lib/buzzci/leases/lease01");
        let resolv = lease_root.join("empty-resolv.conf");
        let hosts = lease_root.join("hosts");
        assert_eq!(fs::read(&resolv).unwrap(), Vec::<u8>::new());
        assert_eq!(fs::read(&hosts).unwrap(), plan.hosts);
        for file in [resolv, hosts] {
            assert_eq!(
                fs::metadata(file).unwrap().permissions().mode() & 0o7777,
                DNS_FILE_MODE
            );
        }
        let receipt = temporary
            .path()
            .join("var/lib/buzzci/activation/receipts/dns")
            .join(plan.receipt_name());
        assert_eq!(
            fs::metadata(&receipt).unwrap().permissions().mode() & 0o7777,
            RECEIPT_FILE_MODE
        );
        let persisted: DnsExecReceipt =
            serde_json::from_slice(&fs::read(receipt).unwrap()).unwrap();
        assert_eq!(persisted, outcome.receipt);
        assert!(!executor.runner.commands.is_empty());
        assert!(!executor.runner.slice_stopped);
    }

    #[test]
    fn partial_apply_stops_slice_removes_only_created_resources_and_writes_no_receipt() {
        let isolation = isolation_plan();
        let plan = DnsExecPlan::new(isolation.clone(), activation_binding()).unwrap();
        let temporary = tempdir().unwrap();
        let mut runner = ScriptedRunner::new(isolation);
        runner.fail_at = Some(7);
        let mut executor = DnsExecutor::mapped(runner, temporary.path());
        assert!(matches!(
            executor.apply(&plan),
            Err(DnsExecError::Host(
                DnsHostApplyError::ActionFailedQuarantined { .. }
            ))
        ));
        assert!(executor.runner.slice_stopped);
        assert!(executor.runner.namespace_deleted);
        assert!(executor.runner.table_deleted);
        assert!(!temporary
            .path()
            .join("var/lib/buzzci/leases/lease01")
            .exists());
        let receipt_path = temporary
            .path()
            .join("var/lib/buzzci/activation/receipts/dns")
            .join(plan.receipt_name());
        assert!(!receipt_path.exists());
        let commands = executor
            .runner
            .commands
            .iter()
            .map(ScriptedRunner::args)
            .collect::<Vec<_>>();
        let stop = commands
            .iter()
            .position(|args| args.first().map(String::as_str) == Some("stop"))
            .unwrap();
        let delete_table = commands
            .iter()
            .position(|args| args.starts_with(&["delete".to_owned(), "table".to_owned()]))
            .unwrap();
        let delete_namespace = commands
            .iter()
            .position(|args| args.starts_with(&["netns".to_owned(), "delete".to_owned()]))
            .unwrap();
        assert!(stop < delete_table && delete_table < delete_namespace);
    }

    #[test]
    fn stale_reconcile_accepts_only_receipt_bound_owned_resources() {
        let isolation = isolation_plan();
        let plan = DnsExecPlan::new(isolation.clone(), activation_binding()).unwrap();
        let temporary = tempdir().unwrap();
        let runner = ScriptedRunner::new(isolation);
        let mut executor = DnsExecutor::mapped(runner, temporary.path());
        let mut created = OwnedResources::default();
        publish_dns_files(&executor.roots, &plan, &mut created).unwrap();
        let receipt = DnsExecReceipt::from_released(
            &plan,
            DnsReadback {
                files_lookup_ok: true,
                arbitrary_getent_refused: true,
                resolved_varlink_inaccessible: true,
                direct_53_refused: true,
                allowed_tuples_only: true,
            },
        );
        let mut foreign = receipt.clone();
        foreign.nft_table = "buzzci_other".to_owned();
        assert!(matches!(
            executor.reconcile_stale(&plan, &foreign),
            Err(DnsExecError::StaleReceipt)
        ));
        assert!(temporary
            .path()
            .join("var/lib/buzzci/leases/lease01/hosts")
            .exists());

        executor.reconcile_stale(&plan, &receipt).unwrap();
        assert!(!temporary
            .path()
            .join("var/lib/buzzci/leases/lease01")
            .exists());
        assert!(executor.runner.slice_stopped);
        assert!(executor.runner.namespace_deleted);
        assert!(executor.runner.table_deleted);
    }

    #[test]
    fn activation_binding_rejects_missing_or_cross_lease_coordinates() {
        let mut zero = activation_binding();
        zero.request_digest = "0".repeat(64);
        assert_eq!(
            DnsExecPlan::new(isolation_plan(), zero),
            Err(DnsExecPlanError::ActivationBinding)
        );

        let mut foreign = activation_binding();
        foreign.lease_id = "other".to_owned();
        assert_eq!(
            DnsExecPlan::new(isolation_plan(), foreign),
            Err(DnsExecPlanError::ActivationBinding)
        );
    }

    #[test]
    fn foreign_namespace_collision_preserves_foreign_host_and_files() {
        let isolation = isolation_plan();
        let plan = DnsExecPlan::new(isolation.clone(), activation_binding()).unwrap();
        let temporary = tempdir().unwrap();
        let lease = precreate_lease_files(temporary.path(), &plan.hosts);
        let mut runner = ScriptedRunner::new(isolation);
        runner.namespace_exists = true;
        let mut executor = DnsExecutor::mapped(runner, temporary.path());

        assert!(matches!(
            executor.apply(&plan),
            Err(DnsExecError::Host(
                DnsHostApplyError::ActionFailedQuarantined { .. }
            ))
        ));
        assert!(executor.runner.slice_stopped);
        assert!(!executor.runner.namespace_deleted);
        assert!(!executor.runner.table_deleted);
        assert_eq!(fs::read(lease.join("hosts")).unwrap(), plan.hosts);
        assert!(lease.join("empty-resolv.conf").exists());
    }

    #[test]
    fn nft_readback_rejects_comment_forgery_extra_expression_and_duplicate_rule() {
        let isolation = isolation_plan();
        let policy = DnsHostPlan::new(isolation.clone()).unwrap();
        let policy = policy.materializer_policy();
        let runner = ScriptedRunner::new(isolation);
        let valid: Value = serde_json::from_slice(&runner.nft_readback()).unwrap();
        assert!(nft_json_matches(&valid, policy));

        let mut comment_forgery = valid.clone();
        let rule = comment_forgery["nftables"][2]["rule"]
            .as_object_mut()
            .unwrap();
        rule.insert(
            "comment".to_owned(),
            json!("skuid 966 198.51.100.10 443 accept"),
        );
        rule.insert("expr".to_owned(), json!([{"counter": null}]));
        assert!(!nft_json_matches(&comment_forgery, policy));

        let mut extra_expression = valid.clone();
        extra_expression["nftables"][2]["rule"]["expr"]
            .as_array_mut()
            .unwrap()
            .push(json!({"counter": {"packets": 0, "bytes": 0}}));
        assert!(!nft_json_matches(&extra_expression, policy));

        let mut duplicate = valid.clone();
        duplicate["nftables"][3] = duplicate["nftables"][2].clone();
        assert!(!nft_json_matches(&duplicate, policy));
    }

    #[test]
    fn descriptor_walk_rejects_symlinked_parent() {
        let isolation = isolation_plan();
        let plan = DnsExecPlan::new(isolation.clone(), activation_binding()).unwrap();
        let temporary = tempdir().unwrap();
        let outside = tempdir().unwrap();
        fs::create_dir_all(temporary.path().join("var/lib/buzzci")).unwrap();
        symlink(
            outside.path(),
            temporary.path().join("var/lib/buzzci/leases"),
        )
        .unwrap();
        let runner = ScriptedRunner::new(isolation);
        let mut executor = DnsExecutor::mapped(runner, temporary.path());

        assert!(matches!(
            executor.apply(&plan),
            Err(DnsExecError::Files(DnsExecFsError::UnsafeDirectory))
        ));
        assert!(fs::read_dir(outside.path()).unwrap().next().is_none());
        assert!(executor.runner.commands.is_empty());
    }

    #[test]
    fn existing_drift_and_hardlinks_are_never_replaced_or_removed() {
        let isolation = isolation_plan();
        let plan = DnsExecPlan::new(isolation.clone(), activation_binding()).unwrap();
        let temporary = tempdir().unwrap();
        let lease = precreate_lease_files(temporary.path(), b"foreign\n");
        fs::remove_file(lease.join("empty-resolv.conf")).unwrap();
        let runner = ScriptedRunner::new(isolation.clone());
        let mut executor = DnsExecutor::mapped(runner, temporary.path());
        assert!(matches!(
            executor.apply(&plan),
            Err(DnsExecError::Files(DnsExecFsError::UnsafeFile))
        ));
        assert_eq!(fs::read(lease.join("hosts")).unwrap(), b"foreign\n");
        assert!(!lease.join("empty-resolv.conf").exists());

        fs::remove_file(lease.join("hosts")).unwrap();
        let foreign = temporary.path().join("foreign-hosts");
        fs::write(&foreign, &plan.hosts).unwrap();
        fs::set_permissions(&foreign, fs::Permissions::from_mode(DNS_FILE_MODE)).unwrap();
        fs::hard_link(&foreign, lease.join("hosts")).unwrap();
        let runner = ScriptedRunner::new(isolation);
        let mut executor = DnsExecutor::mapped(runner, temporary.path());
        assert!(matches!(
            executor.apply(&plan),
            Err(DnsExecError::Files(DnsExecFsError::UnsafeFile))
        ));
        assert!(foreign.exists());
        assert!(lease.join("hosts").exists());
    }

    #[test]
    fn partial_namespace_failure_cleans_only_resources_created_so_far() {
        let isolation = isolation_plan();
        let plan = DnsExecPlan::new(isolation.clone(), activation_binding()).unwrap();
        let temporary = tempdir().unwrap();
        let mut runner = ScriptedRunner::new(isolation);
        runner.fail_at = Some(4);
        let mut executor = DnsExecutor::mapped(runner, temporary.path());
        assert!(executor.apply(&plan).is_err());
        assert!(executor.runner.slice_stopped);
        assert!(executor.runner.namespace_deleted);
        assert!(!executor.runner.table_deleted);
    }

    #[test]
    fn timeout_kills_descendants_and_waits_for_pipe_eof() {
        let temporary = tempdir().unwrap();
        let pid_file = temporary.path().join("descendant.pid");
        let command = ExactCommand::test_process(
            std::env::current_exe().unwrap(),
            vec![
                os("--exact"),
                os("dns_exec::tests::timeout_descendant_helper"),
                os("--nocapture"),
            ],
            Duration::from_millis(750),
            (
                os("BUZZ_DNS_TIMEOUT_HELPER"),
                pid_file.as_os_str().to_os_string(),
            ),
        );
        let started = Instant::now();
        let result = ProcessCommandRunner.run(&command);
        assert!(matches!(result, Err(ProcessCommandError::Timeout)));
        assert!(started.elapsed() < Duration::from_secs(3));
        let pid: u32 = fs::read_to_string(pid_file).unwrap().parse().unwrap();
        let stat = fs::read_to_string(format!("/proc/{pid}/stat"));
        assert!(stat.is_err() || stat.unwrap().split_whitespace().nth(2) == Some("Z"));
    }

    #[test]
    fn timeout_descendant_helper() {
        let Some(pid_file) = std::env::var_os("BUZZ_DNS_TIMEOUT_HELPER") else {
            return;
        };
        let mut child = Command::new(AllowedBinary::Sleep.path())
            .arg("30")
            .spawn()
            .unwrap();
        fs::write(pid_file, child.id().to_string()).unwrap();
        child.wait().unwrap();
    }
}
