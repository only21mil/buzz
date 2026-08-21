//! Concrete bounded Linux executor for the closed DNS host plan.
//!
//! Production execution uses only the absolute binaries in [`AllowedBinary`],
//! clears the environment, supplies fixed argv without a shell, closes stdin,
//! caps captured output, and kills commands at the compiled timeout. Tests use
//! the same command construction with a scripted runner and mapped file roots;
//! they never invoke host networking or systemd.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::IpAddr;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use nix::fcntl::{renameat2, RenameFlags};
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
    BrokerFileType, BrokerPinnedFileReadback, DnsFilesReadback, FilesLookupProbe,
    LeaseIsolationObservation, LeaseIsolationPlan, LeaseSliceReadback, PrincipalDnsObservation,
    PrincipalRole, TcpServiceTuple, TransientUnitPlan, TransientUnitReadback, TupleConnectProbe,
    UnitNetworkMode,
};

pub const LEASE_ROOT: &str = "/var/lib/buzzci/leases";
pub const ACTIVATION_ROOT: &str = "/var/lib/buzzci/activation";
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
pub const MAX_COMMAND_OUTPUT: usize = 64 * 1024;

const DIRECTORY_MODE: u32 = 0o700;
const DNS_FILE_MODE: u32 = 0o444;
const RECEIPT_FILE_MODE: u32 = 0o400;
const RECEIPT_VERSION: u8 = 1;
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
}

impl ExactCommand {
    fn new(binary: AllowedBinary, argv: Vec<OsString>, timeout: Duration) -> Self {
        Self {
            binary,
            argv,
            timeout,
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
    #[error("failed to join bounded output reader")]
    OutputReader,
}

impl ExactCommandRunner for ProcessCommandRunner {
    type Error = ProcessCommandError;

    fn run(&mut self, command: &ExactCommand) -> Result<ExactCommandOutput, Self::Error> {
        let mut child = Command::new(command.binary.path())
            .args(&command.argv)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(ProcessCommandError::Spawn)?;
        let stdout = child
            .stdout
            .take()
            .ok_or(ProcessCommandError::OutputReader)?;
        let stderr = child
            .stderr
            .take()
            .ok_or(ProcessCommandError::OutputReader)?;
        let stdout_reader = thread::spawn(move || drain_bounded(stdout));
        let stderr_reader = thread::spawn(move || drain_bounded(stderr));
        let started = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().map_err(ProcessCommandError::Wait)? {
                break status;
            }
            if started.elapsed() >= command.timeout {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(ProcessCommandError::Timeout);
            }
            thread::sleep(Duration::from_millis(10));
        };
        let (stdout, stdout_truncated) = stdout_reader
            .join()
            .map_err(|_| ProcessCommandError::OutputReader)?;
        let (stderr, stderr_truncated) = stderr_reader
            .join()
            .map_err(|_| ProcessCommandError::OutputReader)?;
        Ok(ExactCommandOutput {
            exit_code: status.code(),
            stdout,
            stderr,
            stdout_truncated,
            stderr_truncated,
        })
    }
}

fn drain_bounded(mut reader: impl Read) -> (Vec<u8>, bool) {
    let mut retained = Vec::new();
    let mut buffer = [0_u8; 8192];
    let mut truncated = false;
    while let Ok(count) = reader.read(&mut buffer) {
        if count == 0 {
            break;
        }
        let remaining = MAX_COMMAND_OUTPUT.saturating_sub(retained.len());
        let copied = remaining.min(count);
        retained.extend_from_slice(&buffer[..copied]);
        truncated |= copied != count;
    }
    (retained, truncated)
}

/// Validated executor input and exact sealed file bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsExecPlan {
    isolation: LeaseIsolationPlan,
    host: DnsHostPlan,
    resolv_conf: Vec<u8>,
    hosts: Vec<u8>,
    receipt_name: String,
}

impl DnsExecPlan {
    pub fn new(isolation: LeaseIsolationPlan) -> Result<Self, DnsExecPlanError> {
        let host = DnsHostPlan::new(isolation.clone()).map_err(DnsExecPlanError::Host)?;
        let resolv_conf = Vec::new();
        let hosts = render_hosts(&isolation);
        if sha256_hex(&resolv_conf) != isolation.dns_files.resolv_conf.sha256()
            || sha256_hex(&hosts) != isolation.dns_files.hosts.sha256()
        {
            return Err(DnsExecPlanError::DnsFileDigest);
        }
        Ok(Self {
            receipt_name: format!("dns-host-{}.json", isolation.lease_id),
            isolation,
            host,
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
    lease_root: PathBuf,
    activation_root: PathBuf,
    owner_uid: u32,
    owner_gid: u32,
}

impl ExecutorRoots {
    fn production() -> Self {
        Self {
            lease_root: LEASE_ROOT.into(),
            activation_root: ACTIVATION_ROOT.into(),
            owner_uid: 0,
            owner_gid: 0,
        }
    }

    #[cfg(test)]
    fn mapped(base: &Path) -> Self {
        let owner = fs::metadata(base).expect("test root must exist");
        Self {
            lease_root: base.join("var/lib/buzzci/leases"),
            activation_root: base.join("var/lib/buzzci/activation"),
            owner_uid: owner.uid(),
            owner_gid: owner.gid(),
        }
    }

    fn map_lease_path(&self, canonical: &Path) -> Result<PathBuf, DnsExecFsError> {
        let relative = canonical
            .strip_prefix(LEASE_ROOT)
            .map_err(|_| DnsExecFsError::UnsafePath)?;
        if relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(DnsExecFsError::UnsafePath);
        }
        Ok(self.lease_root.join(relative))
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
    lease_id: String,
    disposition: DnsExecDisposition,
    lease_slice: String,
    namespace_name: String,
    nft_table: String,
    resolv_conf_sha256: String,
    hosts_sha256: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsExecDisposition {
    Ready,
    Quarantined,
}

impl DnsExecReceipt {
    fn from_plan(plan: &DnsExecPlan, disposition: DnsExecDisposition) -> Self {
        Self {
            version: RECEIPT_VERSION,
            lease_id: plan.isolation.lease_id.clone(),
            disposition,
            lease_slice: plan.host.identifiers().lease_slice().to_owned(),
            namespace_name: plan.host.identifiers().namespace_name().to_owned(),
            nft_table: plan.host.identifiers().nft_table().to_owned(),
            resolv_conf_sha256: sha256_hex(&plan.resolv_conf),
            hosts_sha256: sha256_hex(&plan.hosts),
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
        if let Err(source) = publish_dns_files(&self.roots, plan) {
            cleanup_owned(&mut self.runner, &self.roots, plan).map_err(DnsExecError::Cleanup)?;
            let receipt = DnsExecReceipt::from_plan(plan, DnsExecDisposition::Quarantined);
            publish_receipt(&self.roots, plan.receipt_name(), &receipt)
                .map_err(DnsExecError::Files)?;
            return Err(DnsExecError::Files(source));
        }
        let adapter = DnsHostAdapter::new(plan.host.clone());
        let mut backend = DnsExecBackend {
            runner: &mut self.runner,
            roots: &self.roots,
        };
        let result = adapter.apply(&mut backend);
        let disposition = match &result {
            Ok(value) if value.released() => DnsExecDisposition::Ready,
            _ => DnsExecDisposition::Quarantined,
        };
        let receipt = DnsExecReceipt::from_plan(plan, disposition);
        if let Err(source) = publish_receipt(&self.roots, plan.receipt_name(), &receipt) {
            cleanup_owned(&mut self.runner, &self.roots, plan).map_err(DnsExecError::Cleanup)?;
            let quarantine = DnsExecReceipt::from_plan(plan, DnsExecDisposition::Quarantined);
            publish_receipt(&self.roots, plan.receipt_name(), &quarantine)
                .map_err(DnsExecError::Files)?;
            return Err(DnsExecError::Files(source));
        }
        match result {
            Ok(host) => Ok(DnsExecOutcome { host, receipt }),
            Err(source) => Err(DnsExecError::Host(source)),
        }
    }

    /// Remove only resources bound by a validated executor receipt.
    pub fn reconcile_stale(
        &mut self,
        plan: &DnsExecPlan,
        receipt: &DnsExecReceipt,
    ) -> Result<(), DnsExecError<R::Error>> {
        if receipt != &DnsExecReceipt::from_plan(plan, receipt.disposition) {
            return Err(DnsExecError::StaleReceipt);
        }
        cleanup_owned(&mut self.runner, &self.roots, plan).map_err(DnsExecError::Cleanup)
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
    #[error("lease quarantine cleanup failed")]
    Quarantine,
}

impl<R: ExactCommandRunner> DnsHostBackend for DnsExecBackend<'_, R> {
    type Error = DnsExecBackendError<R::Error>;

    fn apply(&mut self, action: &DnsHostAction) -> Result<(), Self::Error> {
        for command in commands_for_action(action) {
            run_required(self.runner, &command)?;
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
        )?;
        remove_lease_files(self.roots, &identifiers.lease_id).map_err(DnsExecBackendError::Files)
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
) -> Result<(), DnsExecBackendError<R::Error>> {
    let commands = cleanup_commands(slice, namespace, table);
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

    run_any(runner, &commands[1])?;
    let table_present = run_any(
        runner,
        &nft(vec![os("list"), os("table"), os("inet"), os(table)]),
    )?;
    if table_present.success() {
        return Err(DnsExecBackendError::Quarantine);
    }

    run_any(runner, &commands[2])?;
    let namespaces = run_required(
        runner,
        &ExactCommand::new(
            AllowedBinary::Ip,
            vec![os("-j"), os("netns"), os("list")],
            COMMAND_TIMEOUT,
        ),
    )?;
    let value: Value =
        serde_json::from_slice(&namespaces.stdout).map_err(|_| DnsExecBackendError::Quarantine)?;
    if value.as_array().is_none_or(|entries| {
        entries
            .iter()
            .any(|entry| entry.get("name").and_then(Value::as_str) == Some(namespace))
    }) {
        return Err(DnsExecBackendError::Quarantine);
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
    let chain_ok = objects.iter().any(|object| {
        let Some(chain) = object.get("chain") else {
            return false;
        };
        chain.get("family").and_then(Value::as_str) == Some(expected.family())
            && chain.get("table").and_then(Value::as_str) == Some(expected.table())
            && chain.get("name").and_then(Value::as_str) == Some(expected.chain())
            && chain.get("hook").and_then(Value::as_str) == Some("output")
            && chain.get("prio").and_then(Value::as_i64) == Some(expected.priority().into())
            && chain.get("policy").and_then(Value::as_str) == Some("accept")
    });
    let rules = objects
        .iter()
        .filter_map(|object| object.get("rule"))
        .filter(|rule| {
            rule.get("family").and_then(Value::as_str) == Some(expected.family())
                && rule.get("table").and_then(Value::as_str) == Some(expected.table())
                && rule.get("chain").and_then(Value::as_str) == Some(expected.chain())
        })
        .collect::<Vec<_>>();
    if !chain_ok || rules.len() != expected.allowed_tcp_tuples().len() + 1 {
        return false;
    }
    let uid = expected.principal_uid().to_string();
    let allow_rules_ok = expected.allowed_tcp_tuples().iter().all(|tuple| {
        rules.iter().any(|rule| {
            let text = rule.to_string();
            text.contains("skuid")
                && text.contains(&uid)
                && text.contains(&tuple.address.to_string())
                && text.contains(&tuple.port.to_string())
                && text.contains("accept")
        })
    });
    let drop_rules = rules
        .iter()
        .filter(|rule| {
            let text = rule.to_string();
            text.contains("skuid") && text.contains(&uid) && text.contains("drop")
        })
        .count();
    allow_rules_ok && drop_rules == 1
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

fn publish_dns_files(roots: &ExecutorRoots, plan: &DnsExecPlan) -> Result<(), DnsExecFsError> {
    ensure_directory(&roots.lease_root, roots)?;
    let lease_directory = roots.lease_root.join(&plan.isolation.lease_id);
    ensure_directory(&lease_directory, roots)?;
    let resolv = roots.map_lease_path(plan.isolation.dns_files.resolv_conf.requested_path())?;
    let hosts = roots.map_lease_path(plan.isolation.dns_files.hosts.requested_path())?;
    atomic_publish(
        &lease_directory,
        &resolv,
        &plan.resolv_conf,
        DNS_FILE_MODE,
        roots,
    )?;
    atomic_publish(&lease_directory, &hosts, &plan.hosts, DNS_FILE_MODE, roots)
}

fn publish_receipt(
    roots: &ExecutorRoots,
    name: &str,
    receipt: &DnsExecReceipt,
) -> Result<(), DnsExecFsError> {
    ensure_directory(&roots.activation_root, roots)?;
    let bytes = serde_json::to_vec(receipt).map_err(|_| DnsExecFsError::Publish)?;
    atomic_publish(
        &roots.activation_root,
        &roots.activation_root.join(name),
        &bytes,
        RECEIPT_FILE_MODE,
        roots,
    )
}

fn ensure_directory(path: &Path, roots: &ExecutorRoots) -> Result<(), DnsExecFsError> {
    if !path.exists() {
        fs::create_dir_all(path).map_err(|_| DnsExecFsError::Publish)?;
        fs::set_permissions(path, fs::Permissions::from_mode(DIRECTORY_MODE))
            .map_err(|_| DnsExecFsError::Publish)?;
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| DnsExecFsError::UnsafeDirectory)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != roots.owner_uid
        || metadata.gid() != roots.owner_gid
        || metadata.permissions().mode() & 0o7777 != DIRECTORY_MODE
        || fs::canonicalize(path).map_err(|_| DnsExecFsError::UnsafeDirectory)? != path
    {
        return Err(DnsExecFsError::UnsafeDirectory);
    }
    Ok(())
}

fn atomic_publish(
    directory: &Path,
    destination: &Path,
    bytes: &[u8],
    mode: u32,
    roots: &ExecutorRoots,
) -> Result<(), DnsExecFsError> {
    if destination.parent() != Some(directory) {
        return Err(DnsExecFsError::UnsafePath);
    }
    let name = destination
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or(DnsExecFsError::UnsafePath)?;
    if name.is_empty()
        || name
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && !b"._-".contains(&byte))
    {
        return Err(DnsExecFsError::UnsafePath);
    }
    let directory_file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(directory)
        .map_err(|_| DnsExecFsError::UnsafeDirectory)?;
    if let Ok(metadata) = fs::symlink_metadata(destination) {
        if !safe_owned_file(&metadata, roots, mode) {
            return Err(DnsExecFsError::UnsafeFile);
        }
        fs::remove_file(destination).map_err(|_| DnsExecFsError::Remove)?;
    }
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary_name = format!(".{name}.{}.{}.tmp", std::process::id(), sequence);
    let temporary_path = directory.join(&temporary_name);
    let mut temporary = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(&temporary_path)
        .map_err(|_| DnsExecFsError::Publish)?;
    let publication = (|| {
        temporary
            .write_all(bytes)
            .map_err(|_| DnsExecFsError::Publish)?;
        temporary.sync_all().map_err(|_| DnsExecFsError::Publish)?;
        temporary
            .set_permissions(fs::Permissions::from_mode(mode))
            .map_err(|_| DnsExecFsError::Publish)?;
        temporary.sync_all().map_err(|_| DnsExecFsError::Publish)?;
        renameat2(
            &directory_file,
            temporary_name.as_str(),
            &directory_file,
            name,
            RenameFlags::RENAME_NOREPLACE,
        )
        .map_err(|_| DnsExecFsError::Publish)?;
        directory_file
            .sync_all()
            .map_err(|_| DnsExecFsError::Publish)?;
        let metadata = fs::symlink_metadata(destination).map_err(|_| DnsExecFsError::UnsafeFile)?;
        if !safe_owned_file(&metadata, roots, mode)
            || metadata.len() != bytes.len() as u64
            || fs::read(destination).map_err(|_| DnsExecFsError::UnsafeFile)? != bytes
        {
            return Err(DnsExecFsError::UnsafeFile);
        }
        Ok(())
    })();
    if publication.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    publication
}

fn safe_owned_file(metadata: &fs::Metadata, roots: &ExecutorRoots, mode: u32) -> bool {
    metadata.file_type().is_file()
        && metadata.uid() == roots.owner_uid
        && metadata.gid() == roots.owner_gid
        && metadata.nlink() == 1
        && metadata.permissions().mode() & 0o7777 == mode
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
    let mapped = roots.map_lease_path(canonical)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(&mapped)
        .map_err(|_| DnsExecFsError::UnsafeFile)?;
    let metadata = file.metadata().map_err(|_| DnsExecFsError::UnsafeFile)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|_| DnsExecFsError::UnsafeFile)?;
    Ok(BrokerPinnedFileReadback {
        requested_path: canonical.to_path_buf(),
        canonical_path: canonical.to_path_buf(),
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
) -> Result<(), DnsExecBackendError<R::Error>> {
    cleanup_host(
        runner,
        plan.host.identifiers().lease_slice(),
        plan.host.identifiers().namespace_name(),
        plan.host.identifiers().nft_table(),
    )?;
    remove_lease_files(roots, &plan.isolation.lease_id).map_err(DnsExecBackendError::Files)
}

fn remove_lease_files(roots: &ExecutorRoots, lease_id: &str) -> Result<(), DnsExecFsError> {
    if lease_id.is_empty()
        || !lease_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(DnsExecFsError::UnsafePath);
    }
    let directory = roots.lease_root.join(lease_id);
    if !directory.exists() {
        return Ok(());
    }
    ensure_directory(&directory, roots)?;
    for name in ["empty-resolv.conf", "hosts"] {
        let path = directory.join(name);
        if let Ok(metadata) = fs::symlink_metadata(&path) {
            if !safe_owned_file(&metadata, roots, DNS_FILE_MODE) {
                return Err(DnsExecFsError::UnsafeFile);
            }
            fs::remove_file(path).map_err(|_| DnsExecFsError::Remove)?;
        }
    }
    if fs::read_dir(&directory)
        .map_err(|_| DnsExecFsError::Remove)?
        .next()
        .is_none()
    {
        fs::remove_dir(directory).map_err(|_| DnsExecFsError::Remove)?;
    }
    Ok(())
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

    #[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
    #[error("scripted runner transport failure")]
    struct ScriptedError;

    struct ScriptedRunner {
        plan: LeaseIsolationPlan,
        commands: Vec<ExactCommand>,
        fail_at: Option<usize>,
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
            let mut objects = vec![json!({
                "chain": {
                    "family": policy.family(),
                    "table": policy.table(),
                    "name": policy.chain(),
                    "hook": "output",
                    "prio": policy.priority(),
                    "policy": "accept"
                }
            })];
            for tuple in policy.allowed_tcp_tuples() {
                objects.push(json!({
                    "rule": {
                        "family": policy.family(),
                        "table": policy.table(),
                        "chain": policy.chain(),
                        "expr": ["skuid", policy.principal_uid(), tuple.address.to_string(), tuple.port, "accept"]
                    }
                }));
            }
            objects.push(json!({
                "rule": {
                    "family": policy.family(),
                    "table": policy.table(),
                    "chain": policy.chain(),
                    "expr": ["skuid", policy.principal_uid(), "drop"]
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
                AllowedBinary::Systemctl if args.first().map(String::as_str) == Some("stop") => {
                    self.slice_stopped = true;
                    Ok(Self::output(0, Vec::new()))
                }
                AllowedBinary::Systemctl
                    if args.first().map(String::as_str) == Some("is-active") =>
                {
                    Ok(Self::output(
                        if self.slice_stopped { 3 } else { 0 },
                        Vec::new(),
                    ))
                }
                AllowedBinary::Ip if args == ["-j", "netns", "list"] => {
                    let value = if self.namespace_deleted {
                        json!([])
                    } else {
                        json!([{"name": "buzzci-lease01"}])
                    };
                    Ok(Self::output(0, serde_json::to_vec(&value).unwrap()))
                }
                AllowedBinary::Ip
                    if args.first().map(String::as_str) == Some("netns")
                        && args.get(1).map(String::as_str) == Some("delete") =>
                {
                    self.namespace_deleted = true;
                    Ok(Self::output(0, Vec::new()))
                }
                AllowedBinary::Ip if args.contains(&"show".to_owned()) => Ok(Self::output(
                    0,
                    serde_json::to_vec(&json!([{"ifname":"lo","flags":["LOOPBACK","UP"]}]))
                        .unwrap(),
                )),
                AllowedBinary::Nft if args.first().map(String::as_str) == Some("delete") => {
                    self.table_deleted = true;
                    Ok(Self::output(0, Vec::new()))
                }
                AllowedBinary::Nft if args.first().map(String::as_str) == Some("list") => Ok(
                    Self::output(if self.table_deleted { 1 } else { 0 }, Vec::new()),
                ),
                AllowedBinary::Nft if args.first().map(String::as_str) == Some("-j") => {
                    Ok(Self::output(0, self.nft_readback()))
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

    #[test]
    fn command_plan_is_absolute_allowlisted_shell_free_and_deterministic() {
        let plan = DnsExecPlan::new(isolation_plan()).unwrap();
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
        let plan = DnsExecPlan::new(isolation.clone()).unwrap();
        let temporary = tempdir().unwrap();
        let runner = ScriptedRunner::new(isolation);
        let mut executor = DnsExecutor::mapped(runner, temporary.path());
        let outcome = executor.apply(&plan).unwrap();
        assert!(outcome.host.readback.dns_readback.files_lookup_ok);
        assert!(outcome.host.readback.dns_readback.allowed_tuples_only);
        assert_eq!(outcome.host.disposition, DnsHostDisposition::Released);
        assert_eq!(outcome.receipt.disposition, DnsExecDisposition::Ready);

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
            .join("var/lib/buzzci/activation")
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
    fn partial_apply_stops_slice_removes_owned_resources_and_records_quarantine() {
        let isolation = isolation_plan();
        let plan = DnsExecPlan::new(isolation.clone()).unwrap();
        let temporary = tempdir().unwrap();
        let mut runner = ScriptedRunner::new(isolation);
        runner.fail_at = Some(3);
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
            .join("var/lib/buzzci/activation")
            .join(plan.receipt_name());
        let receipt: DnsExecReceipt =
            serde_json::from_slice(&fs::read(receipt_path).unwrap()).unwrap();
        assert_eq!(receipt.disposition, DnsExecDisposition::Quarantined);
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
        let plan = DnsExecPlan::new(isolation.clone()).unwrap();
        let temporary = tempdir().unwrap();
        let runner = ScriptedRunner::new(isolation);
        let mut executor = DnsExecutor::mapped(runner, temporary.path());
        publish_dns_files(&executor.roots, &plan).unwrap();
        let receipt = DnsExecReceipt::from_plan(&plan, DnsExecDisposition::Ready);
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
}
