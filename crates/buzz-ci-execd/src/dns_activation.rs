//! Trusted construction and lifecycle ownership for per-lease DNS isolation.
//!
//! This module accepts only an authenticated [`OrdinaryAdmission`] and the
//! opaque [`LeaseToken`] issued for it. It derives every host identity from
//! those values and immutable root-owned DNS authority. Flattened case JSON
//! never enters this boundary.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read};
use std::net::IpAddr;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use buzz_ci_broker_protocol::{GitOid, TrustClass};
use buzz_ci_isolation_contract::PrincipalUids;
use nix::dir::Dir;
use nix::errno::Errno;
use nix::fcntl::{openat, OFlag};
use nix::sys::stat::Mode;
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::activation::{AdmissionTrustClass, LeaseToken, OrdinaryAdmission};
use crate::dns_exec::{
    AllowedBinary, DnsExecError, DnsExecPlan, DnsExecPlanError, DnsExecReceipt, DnsExecutor,
    ExactCommand, ExactCommandOutput, ExactCommandRunner, ProcessCommandRunner, ACTIVATION_ROOT,
    COMMAND_TIMEOUT, LEASE_ROOT,
};
use crate::dns_isolation::{
    build_lease_isolation_plan, BrokerApprovedMaterializerNetwork, BrokerPinnedFile,
    DelegationCanaryReadback, DnsFiles, DnsReadback, IsolationPlanError, LeaseIsolationPlan,
    LeaseIsolationRequest, LeaseSliceIdentity, NetworkNamespaceProperty, PinnedServiceKind,
    PrincipalRole, PrincipalUnitIdentity, SniHostPin, TcpServiceTuple, UnitResources,
    BUZZCI_ROOT_CGROUP_PATH, EMPTY_FILE_SHA256,
};
use crate::evidence;
use crate::runtime::ReadyValidationTarget;

const DNS_RECEIPT_DIRECTORY_MODE: u32 = 0o700;
const DNS_RECEIPT_FILE_MODE: u32 = 0o400;
const DNS_RECEIPT_VERSION: u8 = 2;
const MAX_DNS_RECEIPT_BYTES: u64 = 64 * 1024;

/// Root-owned proof that all three principal UIDs may join the broker namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsDelegationAuthority {
    fedora_release: String,
    systemd_version: String,
    proven_uids: BTreeSet<u32>,
}

impl DnsDelegationAuthority {
    /// Retain the exact host release, systemd version, and successfully tested UIDs.
    pub fn new(
        fedora_release: String,
        systemd_version: String,
        proven_uids: impl IntoIterator<Item = u32>,
    ) -> Self {
        Self {
            fedora_release,
            systemd_version,
            proven_uids: proven_uids.into_iter().collect(),
        }
    }
}

/// One root-qualified HTTPS service and the hostname pinned for SNI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsServiceAuthority {
    hostname: String,
    address: IpAddr,
}

impl DnsServiceAuthority {
    /// Retain one root-qualified hostname and its single pinned address.
    pub fn new(hostname: String, address: IpAddr) -> Self {
        Self { hostname, address }
    }
}

/// Immutable values measured or selected by root before any lease is admitted.
///
/// The type is intentionally not deserializable. A future production composer
/// must construct it from reopened root-owned authority and live host proofs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsLeaseAuthority {
    principals: PrincipalUids,
    resources: UnitResources,
    delegation: DnsDelegationAuthority,
    relay: DnsServiceAuthority,
    mirror: DnsServiceAuthority,
}

impl DnsLeaseAuthority {
    /// Assemble immutable root-owned inputs for all future lease plans.
    pub fn new(
        principals: PrincipalUids,
        resources: UnitResources,
        delegation: DnsDelegationAuthority,
        relay: DnsServiceAuthority,
        mirror: DnsServiceAuthority,
    ) -> Self {
        Self {
            principals,
            resources,
            delegation,
            relay,
            mirror,
        }
    }
}

/// Trusted pure builder for the exact executor plan of one admitted lease.
#[derive(Clone, Debug)]
pub struct DnsLeaseBuilder {
    authority: DnsLeaseAuthority,
}

impl DnsLeaseBuilder {
    /// Create a builder which can only use the supplied root-owned authority.
    pub fn new(authority: DnsLeaseAuthority) -> Self {
        Self { authority }
    }

    /// Bind one authenticated admission and opaque token into an executable plan.
    pub fn build(
        &self,
        admission: OrdinaryAdmission,
        lease: LeaseToken,
        observed_at_unix_ns: u64,
    ) -> Result<DnsExecPlan, DnsLeaseBuildError> {
        validate_lease_binding(admission, lease, observed_at_unix_ns)?;
        let identity = LeaseDnsIdentity::from_bytes(lease.lease_id());
        let isolation = self.build_isolation(&identity)?;
        let activation = activation_binding(admission, lease, &identity, observed_at_unix_ns);
        DnsExecPlan::new(isolation, activation).map_err(DnsLeaseBuildError::ExecPlan)
    }

    fn build_isolation(
        &self,
        identity: &LeaseDnsIdentity,
    ) -> Result<LeaseIsolationPlan, IsolationPlanError> {
        let lease_slice = LeaseSliceIdentity {
            unit_name: identity.slice_name.clone(),
            cgroup_path: identity.slice_path.clone(),
        };
        let units = [
            (
                PrincipalRole::Materializer,
                self.authority.principals.materializer,
                "mat",
            ),
            (
                PrincipalRole::Executor,
                self.authority.principals.executor,
                "exec",
            ),
            (
                PrincipalRole::Runtime,
                self.authority.principals.runtime,
                "run",
            ),
        ]
        .into_iter()
        .map(|(role, uid, suffix)| {
            let unit_name = format!("buzzci-{}-{suffix}.service", identity.lease_id);
            PrincipalUnitIdentity {
                role,
                uid,
                cgroup_path: identity.slice_path.join(&unit_name),
                unit_name,
            }
        })
        .collect();
        let expected_uids = BTreeSet::from([
            self.authority.principals.materializer,
            self.authority.principals.executor,
            self.authority.principals.runtime,
        ]);
        let uid_results = self
            .authority
            .delegation
            .proven_uids
            .iter()
            .copied()
            .map(|uid| (uid, true))
            .collect::<BTreeMap<_, _>>();
        if self.authority.delegation.proven_uids != expected_uids {
            return Err(IsolationPlanError::InvalidField {
                field: "delegation_canary.uid_results",
                reason: "root authority must prove exactly the three principal UIDs",
            });
        }

        let relay_tuple = tcp_443(self.authority.relay.address);
        let mirror_tuple = tcp_443(self.authority.mirror.address);
        let network = BrokerApprovedMaterializerNetwork::new(relay_tuple, mirror_tuple)?;
        let pins = vec![
            SniHostPin {
                service: PinnedServiceKind::Relay,
                hostname: self.authority.relay.hostname.clone(),
                addresses: vec![self.authority.relay.address],
            },
            SniHostPin {
                service: PinnedServiceKind::Mirror,
                hostname: self.authority.mirror.hostname.clone(),
                addresses: vec![self.authority.mirror.address],
            },
        ];
        let hosts = render_hosts(&pins);
        let lease_files = Path::new(LEASE_ROOT).join(&identity.lease_id);
        build_lease_isolation_plan(LeaseIsolationRequest {
            lease_id: identity.lease_id.clone(),
            resources: self.authority.resources,
            lease_slice,
            units,
            delegation_canary: DelegationCanaryReadback {
                fedora_release: self.authority.delegation.fedora_release.clone(),
                systemd_version: self.authority.delegation.systemd_version.clone(),
                property: NetworkNamespaceProperty::NetworkNamespacePath,
                namespace_path: identity.namespace_path.clone(),
                uid_results,
            },
            dns_files: DnsFiles {
                resolv_conf: BrokerPinnedFile::new(
                    lease_files.join("empty-resolv.conf"),
                    EMPTY_FILE_SHA256.to_owned(),
                )?,
                hosts: BrokerPinnedFile::new(lease_files.join("hosts"), sha256_hex(&hosts))?,
                sni_host_pins: pins,
            },
            approved_materializer_network: network,
        })
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DnsLeaseBuildError {
    /// Admission and token identities are not the same issued lease.
    #[error("lease token does not match the authenticated ordinary admission")]
    Binding,
    /// Root authority failed the existing pure isolation planner.
    #[error("root DNS authority could not produce a valid lease plan")]
    Isolation(#[from] IsolationPlanError),
    /// The closed executor plan rejected the derived activation binding.
    #[error("DNS executor plan rejected the authenticated binding")]
    ExecPlan(#[from] DnsExecPlanError),
}

#[derive(Clone, Debug)]
struct DnsReceiptRoots {
    base_root: PathBuf,
    owner_uid: u32,
    owner_gid: u32,
}

impl DnsReceiptRoots {
    fn production() -> Self {
        Self {
            base_root: PathBuf::from("/"),
            owner_uid: 0,
            owner_gid: 0,
        }
    }

    #[cfg(test)]
    fn mapped(base_root: &Path) -> Self {
        let owner = fs::metadata(base_root).expect("test root must exist");
        Self {
            base_root: base_root.to_path_buf(),
            owner_uid: owner.uid(),
            owner_gid: owner.gid(),
        }
    }
}

#[derive(Clone, Debug)]
struct DnsReceiptStore {
    roots: DnsReceiptRoots,
}

impl DnsReceiptStore {
    fn production() -> Self {
        Self {
            roots: DnsReceiptRoots::production(),
        }
    }

    #[cfg(test)]
    fn mapped(base_root: &Path) -> Self {
        Self {
            roots: DnsReceiptRoots::mapped(base_root),
        }
    }

    fn read(
        &self,
        lease_id: &str,
        generation: u64,
    ) -> Result<(String, Vec<u8>), DnsLeaseRecoveryError> {
        if generation == 0 || !is_lower_hex(lease_id, 32) {
            return Err(DnsLeaseRecoveryError::Stale);
        }
        let receipt_name = format!("{lease_id}-g{generation}.json");
        let receipt_directory = self.open_receipt_directory()?;
        let descriptor = match openat(
            &receipt_directory,
            receipt_name.as_str(),
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        ) {
            Ok(descriptor) => descriptor,
            Err(Errno::ENOENT) => return Err(DnsLeaseRecoveryError::Missing),
            Err(_) => return Err(DnsLeaseRecoveryError::UnsafeAuthority),
        };
        let mut receipt = File::from(descriptor);
        let before = receipt
            .metadata()
            .map_err(|_| DnsLeaseRecoveryError::UnsafeAuthority)?;
        if !safe_receipt_file(&before, &self.roots) {
            return Err(DnsLeaseRecoveryError::UnsafeAuthority);
        }
        self.require_unambiguous_receipt(&receipt_directory, lease_id, &receipt_name)?;

        let mut bytes = Vec::new();
        receipt
            .by_ref()
            .take(MAX_DNS_RECEIPT_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| DnsLeaseRecoveryError::UnsafeAuthority)?;
        let after = receipt
            .metadata()
            .map_err(|_| DnsLeaseRecoveryError::UnsafeAuthority)?;
        if bytes.is_empty()
            || bytes.len() as u64 > MAX_DNS_RECEIPT_BYTES
            || !safe_receipt_file(&after, &self.roots)
            || before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.len() != after.len()
        {
            return Err(DnsLeaseRecoveryError::UnsafeAuthority);
        }
        Ok((receipt_name, bytes))
    }

    fn open_receipt_directory(&self) -> Result<File, DnsLeaseRecoveryError> {
        let mut current = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(&self.roots.base_root)
            .map_err(|_| DnsLeaseRecoveryError::UnsafeAuthority)?;
        validate_receipt_directory(&current, &self.roots, false)?;
        let canonical = Path::new(ACTIVATION_ROOT).join("receipts/dns");
        let components = canonical
            .components()
            .filter_map(|component| match component {
                std::path::Component::RootDir => None,
                std::path::Component::Normal(value) => Some(Ok(value)),
                _ => Some(Err(DnsLeaseRecoveryError::UnsafeAuthority)),
            })
            .collect::<Result<Vec<_>, _>>()?;
        for (index, component) in components.iter().enumerate() {
            let descriptor = match openat(
                &current,
                *component,
                OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                Mode::empty(),
            ) {
                Ok(descriptor) => descriptor,
                Err(Errno::ENOENT) => return Err(DnsLeaseRecoveryError::Missing),
                Err(_) => return Err(DnsLeaseRecoveryError::UnsafeAuthority),
            };
            current = File::from(descriptor);
            validate_receipt_directory(&current, &self.roots, index + 1 == components.len())?;
        }
        Ok(current)
    }

    fn require_unambiguous_receipt(
        &self,
        directory: &File,
        lease_id: &str,
        receipt_name: &str,
    ) -> Result<(), DnsLeaseRecoveryError> {
        let descriptor = openat(
            directory,
            OsStr::new("."),
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| DnsLeaseRecoveryError::UnsafeAuthority)?;
        let mut entries =
            Dir::from_fd(descriptor).map_err(|_| DnsLeaseRecoveryError::UnsafeAuthority)?;
        let prefix = format!("{lease_id}-g");
        let mut matching = 0_usize;
        for entry in entries.iter() {
            let entry = entry.map_err(|_| DnsLeaseRecoveryError::UnsafeAuthority)?;
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            if name.starts_with(prefix.as_bytes()) {
                if name != receipt_name.as_bytes() {
                    return Err(DnsLeaseRecoveryError::Ambiguous);
                }
                matching += 1;
            }
        }
        match matching {
            1 => Ok(()),
            0 => Err(DnsLeaseRecoveryError::Missing),
            _ => Err(DnsLeaseRecoveryError::Ambiguous),
        }
    }
}

fn validate_receipt_directory(
    directory: &File,
    roots: &DnsReceiptRoots,
    require_private: bool,
) -> Result<(), DnsLeaseRecoveryError> {
    let metadata = directory
        .metadata()
        .map_err(|_| DnsLeaseRecoveryError::UnsafeAuthority)?;
    let mode = metadata.permissions().mode() & 0o7777;
    if !metadata.file_type().is_dir()
        || metadata.uid() != roots.owner_uid
        || metadata.gid() != roots.owner_gid
        || if require_private {
            mode != DNS_RECEIPT_DIRECTORY_MODE
        } else {
            mode & 0o022 != 0
        }
    {
        return Err(DnsLeaseRecoveryError::UnsafeAuthority);
    }
    Ok(())
}

fn safe_receipt_file(metadata: &fs::Metadata, roots: &DnsReceiptRoots) -> bool {
    metadata.file_type().is_file()
        && metadata.uid() == roots.owner_uid
        && metadata.gid() == roots.owner_gid
        && metadata.nlink() == 1
        && metadata.permissions().mode() & 0o7777 == DNS_RECEIPT_FILE_MODE
        && metadata.len() > 0
        && metadata.len() <= MAX_DNS_RECEIPT_BYTES
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Why root-owned retained DNS state could not be recovered safely.
#[derive(Debug, Error)]
pub enum DnsLeaseRecoveryError {
    /// The exact generation-bound receipt does not exist.
    #[error("the exact DNS receipt is missing")]
    Missing,
    /// A receipt path or descriptor failed root ownership, mode, type, or no-follow checks.
    #[error("DNS receipt authority is unsafe")]
    UnsafeAuthority,
    /// More than one receipt can claim the durable lease identity.
    #[error("DNS receipt state is ambiguous")]
    Ambiguous,
    /// Receipt bytes are not the canonical closed receipt schema.
    #[error("DNS receipt is malformed")]
    Malformed,
    /// Receipt lease or generation identity is stale.
    #[error("DNS receipt is stale")]
    Stale,
    /// Persisted state differs from the freshly rebuilt plan.
    #[error("DNS receipt does not match the rebuilt plan")]
    Mismatch,
    /// Fresh construction from durable admission and root authority failed.
    #[error("DNS recovery plan construction failed")]
    Build(#[source] DnsLeaseBuildError),
}

/// Receipt retained until the ordinary cleanup machine reconciles this lease.
#[derive(Clone, Debug)]
pub struct RetainedDnsLease {
    lease: LeaseToken,
    plan: DnsExecPlan,
    exec_receipt: DnsExecReceipt,
    evidence: evidence::DnsReadback,
}

impl RetainedDnsLease {
    /// Return the opaque lease identity associated with this receipt.
    pub const fn lease_id(&self) -> [u8; 16] {
        self.lease.lease_id()
    }

    /// Return the exact plan retained for receipt-bound reconciliation.
    pub fn plan(&self) -> &DnsExecPlan {
        &self.plan
    }

    /// Return the executor receipt retained for ordinary lifecycle evidence.
    pub fn exec_receipt(&self) -> &DnsExecReceipt {
        &self.exec_receipt
    }

    /// Return the five DNS proof bits in the durable evidence type.
    pub const fn evidence(&self) -> evidence::DnsReadback {
        self.evidence
    }
}

/// Single-slot owner of DNS apply, retained receipt state, and reconciliation.
///
/// `dns_exec` starts the materializer unit with its fixed handoff shim. The
/// executor and runtime units remain dormant placeholders until their reviewed
/// handoffs land. This lifecycle retains all three units under the same cleanup
/// token and lease slice.
pub struct DnsLeaseLifecycle<R> {
    builder: DnsLeaseBuilder,
    executor: DnsExecutor<R>,
    receipts: DnsReceiptStore,
    active: Option<RetainedDnsLease>,
}

impl DnsLeaseLifecycle<ProcessCommandRunner> {
    /// Construct the dormant production adapter with the bounded process runner.
    pub fn production(authority: DnsLeaseAuthority) -> Self {
        Self::with_executor(DnsLeaseBuilder::new(authority), DnsExecutor::production())
    }
}

impl<R: ExactCommandRunner> DnsLeaseLifecycle<R> {
    /// Construct a lifecycle around an existing executor seam.
    pub fn with_executor(builder: DnsLeaseBuilder, executor: DnsExecutor<R>) -> Self {
        Self {
            builder,
            executor,
            receipts: DnsReceiptStore::production(),
            active: None,
        }
    }

    #[cfg(test)]
    fn with_mapped_executor(
        builder: DnsLeaseBuilder,
        executor: DnsExecutor<R>,
        base_root: &Path,
    ) -> Self {
        Self {
            builder,
            executor,
            receipts: DnsReceiptStore::mapped(base_root),
            active: None,
        }
    }

    /// Apply and retain one DNS lease after durable admission commits its token.
    pub fn apply(
        &mut self,
        admission: OrdinaryAdmission,
        lease: LeaseToken,
        observed_at_unix_ns: u64,
    ) -> Result<&RetainedDnsLease, DnsLeaseLifecycleError<R::Error>> {
        if self.active.is_some() {
            return Err(DnsLeaseLifecycleError::ActiveLease);
        }
        let plan = self
            .builder
            .build(admission, lease, observed_at_unix_ns)
            .map_err(DnsLeaseLifecycleError::Build)?;
        let outcome = self
            .executor
            .apply(&plan)
            .map_err(DnsLeaseLifecycleError::Exec)?;
        let evidence = evidence_dns_readback(outcome.host.readback.dns_readback);
        Ok(self.active.insert(RetainedDnsLease {
            lease,
            plan,
            exec_receipt: outcome.receipt,
            evidence,
        }))
    }

    /// Reopen the exact generation receipt and retain it for bounded cleanup.
    pub fn recover(
        &mut self,
        admission: OrdinaryAdmission,
        lease: LeaseToken,
    ) -> Result<&RetainedDnsLease, DnsLeaseLifecycleError<R::Error>> {
        if self.active.is_some() {
            return Err(DnsLeaseLifecycleError::ActiveLease);
        }
        let lease_id = hex::encode(lease.lease_id());
        let (receipt_name, bytes) = self
            .receipts
            .read(&lease_id, lease.generation())
            .map_err(DnsLeaseLifecycleError::Recovery)?;
        let receipt: DnsExecReceipt = serde_json::from_slice(&bytes)
            .map_err(|_| DnsLeaseLifecycleError::Recovery(DnsLeaseRecoveryError::Malformed))?;
        let canonical = serde_json::to_vec(&receipt)
            .map_err(|_| DnsLeaseLifecycleError::Recovery(DnsLeaseRecoveryError::Malformed))?;
        if canonical != bytes {
            return Err(DnsLeaseLifecycleError::Recovery(
                DnsLeaseRecoveryError::Malformed,
            ));
        }
        if receipt.activation_binding().lease_id != lease_id
            || receipt.activation_binding().lease_generation != lease.generation()
        {
            return Err(DnsLeaseLifecycleError::Recovery(
                DnsLeaseRecoveryError::Stale,
            ));
        }
        let plan = self
            .builder
            .build(
                admission,
                lease,
                receipt.activation_binding().observed_at_unix_ns,
            )
            .map_err(|error| {
                DnsLeaseLifecycleError::Recovery(DnsLeaseRecoveryError::Build(error))
            })?;
        if receipt_name != plan.receipt_name() || !receipt_matches_plan(&bytes, &receipt, &plan) {
            return Err(DnsLeaseLifecycleError::Recovery(
                DnsLeaseRecoveryError::Mismatch,
            ));
        }
        let evidence = evidence_dns_readback(receipt.readback());
        Ok(self.active.insert(RetainedDnsLease {
            lease,
            plan,
            exec_receipt: receipt,
            evidence,
        }))
    }

    /// Borrow the currently retained lease, if apply reached released readback.
    pub fn active(&self) -> Option<&RetainedDnsLease> {
        self.active.as_ref()
    }

    /// Reconcile only the resources bound by the retained receipt and exact token.
    pub fn reconcile(
        &mut self,
        lease: LeaseToken,
    ) -> Result<RetainedDnsLease, DnsLeaseLifecycleError<R::Error>> {
        let retained = self
            .active
            .as_ref()
            .ok_or(DnsLeaseLifecycleError::NoActiveLease)?;
        if retained.lease != lease {
            return Err(DnsLeaseLifecycleError::LeaseMismatch);
        }
        self.executor
            .reconcile_stale(&retained.plan, &retained.exec_receipt)
            .map_err(DnsLeaseLifecycleError::Exec)?;
        self.active
            .take()
            .ok_or(DnsLeaseLifecycleError::NoActiveLease)
    }
}

#[derive(Debug, Error)]
pub enum DnsLeaseLifecycleError<E: std::error::Error + 'static> {
    /// The single-slot lifecycle already owns a released lease.
    #[error("another DNS lease is already retained")]
    ActiveLease,
    /// Cleanup was requested without a released lease.
    #[error("no DNS lease is retained for cleanup")]
    NoActiveLease,
    /// Cleanup presented a different opaque lease token.
    #[error("cleanup token does not match the retained DNS lease")]
    LeaseMismatch,
    /// Trusted plan construction failed before host mutation.
    #[error("DNS lease construction failed")]
    Build(#[source] DnsLeaseBuildError),
    /// Root-owned retained state could not be reopened exactly.
    #[error("DNS lease recovery failed closed")]
    Recovery(#[source] DnsLeaseRecoveryError),
    /// Host apply, readback, quarantine, or cleanup failed.
    #[error("DNS executor failed or quarantined the lease")]
    Exec(#[source] DnsExecError<E>),
}

/// Exact leftover that prevents a restored grant from becoming Ready.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StaleDnsState {
    /// The exact per-lease systemd slice still exists.
    LeaseSlice,
    /// The exact per-lease network namespace still exists.
    NetworkNamespace,
    /// The exact per-lease nftables table still exists.
    NftTable,
    /// The exact per-lease DNS state directory still exists.
    LeaseFiles,
}

/// Fresh absence proof tied to one root-authored Ready restoration target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FreshDnsStartupProof {
    target: ReadyValidationTarget,
    lease_id: [u8; 16],
    observed_at: u64,
    digest: [u8; 32],
}

impl FreshDnsStartupProof {
    /// Return the restored authority and state revisions this proof covers.
    pub const fn target(self) -> ReadyValidationTarget {
        self.target
    }

    /// Return the root-reserved lease identity checked for stale state.
    pub const fn lease_id(self) -> [u8; 16] {
        self.lease_id
    }

    /// Return the Unix-second timestamp of the fresh readback.
    pub const fn observed_at(self) -> u64 {
        self.observed_at
    }

    /// Return the nonzero digest consumed later by Ready restoration evidence.
    pub const fn digest(self) -> [u8; 32] {
        self.digest
    }
}

/// Read-only startup verifier for stale per-lease DNS and systemd state.
pub struct DnsStartupVerifier<R> {
    runner: R,
    base_root: PathBuf,
}

impl DnsStartupVerifier<ProcessCommandRunner> {
    /// Construct the canonical root-filesystem startup verifier.
    pub fn production() -> Self {
        Self {
            runner: ProcessCommandRunner,
            base_root: PathBuf::from("/"),
        }
    }
}

impl<R: ExactCommandRunner> DnsStartupVerifier<R> {
    #[cfg(test)]
    fn mapped(runner: R, base_root: &Path) -> Self {
        Self {
            runner,
            base_root: base_root.to_path_buf(),
        }
    }

    /// Prove that the lease reserved by the restored root authority has no
    /// surviving slice, namespace, nft table, or lease DNS files.
    pub fn prove_restored_grant_clean(
        &mut self,
        target: &ReadyValidationTarget,
        admission: OrdinaryAdmission,
        now: u64,
    ) -> Result<FreshDnsStartupProof, DnsStartupProofError<R::Error>> {
        if now == 0 || !admission_matches_target(admission, *target) {
            return Err(DnsStartupProofError::Binding);
        }
        let identity = LeaseDnsIdentity::from_bytes(admission.lease_id);
        let load_state = self.run_required(ExactCommand::new(
            AllowedBinary::Systemctl,
            vec![
                os("show"),
                os("--no-pager"),
                os(&identity.slice_name),
                os("--property=LoadState"),
            ],
            COMMAND_TIMEOUT,
        ))?;
        if load_state.stdout != b"LoadState=not-found\n" {
            return Err(DnsStartupProofError::Leftover(StaleDnsState::LeaseSlice));
        }

        let namespaces = self.run_required(ExactCommand::new(
            AllowedBinary::Ip,
            vec![os("-j"), os("netns"), os("list")],
            COMMAND_TIMEOUT,
        ))?;
        let namespaces: Value = serde_json::from_slice(&namespaces.stdout)
            .map_err(|_| DnsStartupProofError::Readback)?;
        let Some(namespaces) = namespaces.as_array() else {
            return Err(DnsStartupProofError::Readback);
        };
        if namespaces.iter().any(|entry| {
            entry.get("name").and_then(Value::as_str) == Some(identity.namespace_name.as_str())
        }) {
            return Err(DnsStartupProofError::Leftover(
                StaleDnsState::NetworkNamespace,
            ));
        }

        let tables = self.run_required(ExactCommand::new(
            AllowedBinary::Nft,
            vec![os("-j"), os("list"), os("tables")],
            COMMAND_TIMEOUT,
        ))?;
        let tables: Value =
            serde_json::from_slice(&tables.stdout).map_err(|_| DnsStartupProofError::Readback)?;
        let Some(tables) = tables.get("nftables").and_then(Value::as_array) else {
            return Err(DnsStartupProofError::Readback);
        };
        if tables.iter().any(|entry| {
            entry.get("table").is_some_and(|table| {
                table.get("family").and_then(Value::as_str) == Some("inet")
                    && table.get("name").and_then(Value::as_str)
                        == Some(identity.nft_table.as_str())
            })
        }) {
            return Err(DnsStartupProofError::Leftover(StaleDnsState::NftTable));
        }

        let lease_path = mapped_path(
            &self.base_root,
            &Path::new(LEASE_ROOT).join(&identity.lease_id),
        );
        match fs::symlink_metadata(lease_path) {
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Ok(_) => {
                return Err(DnsStartupProofError::Leftover(StaleDnsState::LeaseFiles));
            }
            Err(_) => return Err(DnsStartupProofError::FileReadback),
        }

        Ok(FreshDnsStartupProof {
            target: *target,
            lease_id: admission.lease_id,
            observed_at: now,
            digest: startup_digest(*target, admission, now),
        })
    }

    fn run_required(
        &mut self,
        command: ExactCommand,
    ) -> Result<ExactCommandOutput, DnsStartupProofError<R::Error>> {
        let output = self
            .runner
            .run(&command)
            .map_err(DnsStartupProofError::Transport)?;
        if !output.success() || output.stdout_truncated || output.stderr_truncated {
            return Err(DnsStartupProofError::Command);
        }
        Ok(output)
    }
}

#[derive(Debug, Error)]
pub enum DnsStartupProofError<E: std::error::Error + 'static> {
    /// Root-authored admission fields do not match the restoration target.
    #[error("ordinary admission does not match the restored Ready target")]
    Binding,
    /// The bounded command runner could not execute a readback.
    #[error("fresh DNS startup command transport failed")]
    Transport(#[source] E),
    /// A readback command failed or returned truncated output.
    #[error("fresh DNS startup command failed or truncated its output")]
    Command,
    /// A command returned malformed structured output.
    #[error("fresh DNS startup readback was malformed")]
    Readback,
    /// The lease DNS path could not be inspected safely.
    #[error("fresh DNS startup filesystem readback failed")]
    FileReadback,
    /// One exact live identity survived startup cleanup.
    #[error("stale DNS state survived startup reconciliation: {0:?}")]
    Leftover(StaleDnsState),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LeaseDnsIdentity {
    lease_id: String,
    slice_name: String,
    slice_path: PathBuf,
    namespace_name: String,
    namespace_path: PathBuf,
    nft_table: String,
}

impl LeaseDnsIdentity {
    fn from_bytes(bytes: [u8; 16]) -> Self {
        let lease_id = hex::encode(bytes);
        let slice_name = format!("buzzci-{lease_id}.slice");
        let namespace_name = format!("buzzci-{lease_id}");
        Self {
            slice_path: Path::new(BUZZCI_ROOT_CGROUP_PATH).join(&slice_name),
            namespace_path: Path::new("/run/netns").join(&namespace_name),
            nft_table: format!("buzzci_{lease_id}"),
            lease_id,
            slice_name,
            namespace_name,
        }
    }
}

fn validate_lease_binding(
    admission: OrdinaryAdmission,
    lease: LeaseToken,
    observed_at_unix_ns: u64,
) -> Result<(), DnsLeaseBuildError> {
    if admission.trust_class != AdmissionTrustClass::AcceptedReviewed
        || observed_at_unix_ns == 0
        || admission.lease_id == [0; 16]
        || admission.run_id == [0; 16]
        || admission.attempt == 0
        || admission.wall_timeout_seconds == 0
        || admission.expires_at == 0
        || admission.nonce == [0; 32]
        || admission.job.request_digest == [0; 32]
        || admission.job.manifest_digest == [0; 32]
        || admission.job.isolation_profile_digest == [0; 32]
        || lease.lease_id() != admission.lease_id
        || lease.run_id() != admission.run_id
        || lease.attempt() != admission.attempt
        || lease.signed_request_digest() != admission.job.request_digest
        || lease.signer() != admission.signer
        || lease.nonce() != admission.nonce
        || lease.generation() == 0
        || lease.deadline_at() == 0
        || lease.deadline_at() > admission.expires_at
    {
        return Err(DnsLeaseBuildError::Binding);
    }
    Ok(())
}

fn activation_binding(
    admission: OrdinaryAdmission,
    lease: LeaseToken,
    identity: &LeaseDnsIdentity,
    observed_at_unix_ns: u64,
) -> crate::dns_exec::DnsActivationBinding {
    crate::dns_exec::DnsActivationBinding {
        integrated_candidate_sha: oid_hex(admission.host.integrated_candidate_sha),
        broker_build_identity: hex::encode(admission.host.broker_build_identity),
        host_profile_digest: hex::encode(admission.host.host_profile_digest),
        suite_identity: hex::encode(admission.host.suite_identity),
        fixture_signer: hex::encode(admission.signer.0),
        request_digest: hex::encode(admission.job.request_digest),
        manifest_digest: hex::encode(admission.job.manifest_digest),
        isolation_profile_digest: hex::encode(admission.job.isolation_profile_digest),
        lease_id: identity.lease_id.clone(),
        lease_generation: lease.generation(),
        observed_at_unix_ns,
    }
}

fn evidence_dns_readback(readback: crate::dns_isolation::DnsReadback) -> evidence::DnsReadback {
    evidence::DnsReadback {
        files_lookup_ok: readback.files_lookup_ok,
        arbitrary_getent_refused: readback.arbitrary_getent_refused,
        resolved_varlink_inaccessible: readback.resolved_varlink_inaccessible,
        direct_53_refused: readback.direct_53_refused,
        allowed_tuples_only: readback.allowed_tuples_only,
    }
}

fn receipt_matches_plan(bytes: &[u8], receipt: &DnsExecReceipt, plan: &DnsExecPlan) -> bool {
    if receipt.readback() != released_dns_readback() {
        return false;
    }
    let Ok(Value::Object(mut expected)) = serde_json::to_value(plan.activation_binding()) else {
        return false;
    };
    let identifiers = plan.host_plan().identifiers();
    let isolation = plan.isolation_plan();
    expected.insert("version".into(), Value::from(DNS_RECEIPT_VERSION));
    expected.insert("committed".into(), Value::Bool(true));
    expected.insert(
        "lease_slice".into(),
        Value::String(identifiers.lease_slice().to_owned()),
    );
    expected.insert(
        "namespace_name".into(),
        Value::String(identifiers.namespace_name().to_owned()),
    );
    expected.insert(
        "nft_table".into(),
        Value::String(identifiers.nft_table().to_owned()),
    );
    expected.insert(
        "resolv_conf_sha256".into(),
        Value::String(isolation.dns_files.resolv_conf.sha256().to_owned()),
    );
    expected.insert(
        "hosts_sha256".into(),
        Value::String(isolation.dns_files.hosts.sha256().to_owned()),
    );
    let Ok(readback) = serde_json::to_value(released_dns_readback()) else {
        return false;
    };
    expected.insert("readback".into(), readback);
    matches!(
        serde_json::from_slice::<Value>(bytes),
        Ok(observed) if observed == Value::Object(expected)
    )
}

const fn released_dns_readback() -> DnsReadback {
    DnsReadback {
        files_lookup_ok: true,
        arbitrary_getent_refused: true,
        resolved_varlink_inaccessible: true,
        direct_53_refused: true,
        allowed_tuples_only: true,
    }
}

fn admission_matches_target(admission: OrdinaryAdmission, target: ReadyValidationTarget) -> bool {
    let request = target.request();
    let grant = target.grant();
    admission.trust_class == AdmissionTrustClass::AcceptedReviewed
        && request.trust_class == TrustClass::AcceptedReviewed
        && admission.host == grant.host
        && admission.signer == grant.ordinary_signer
        && request.actor_pubkey == admission.signer.0
        && request.signed_request_digest == admission.job.request_digest
        && request.job_manifest_digest == admission.job.manifest_digest
        && request.isolation_profile_digest == admission.job.isolation_profile_digest
        && request.tip_oid == admission.job.source_oid
        && request.base_oid == admission.job.base_oid
        && request.run_id == admission.run_id
        && request.attempt == admission.attempt
        && request.expires_at == admission.expires_at
        && request.wall_timeout_seconds == admission.wall_timeout_seconds
        && admission.lease_id != [0; 16]
}

fn startup_digest(
    target: ReadyValidationTarget,
    admission: OrdinaryAdmission,
    now: u64,
) -> [u8; 32] {
    let request = target.request();
    let mut digest = Sha256::new();
    digest.update(b"buzz-ci-dns-startup-proof-v1\0");
    digest.update(target.authority_revision().to_be_bytes());
    digest.update(target.authority_sha256());
    digest.update(target.state_revision().to_be_bytes());
    digest.update(admission.lease_id);
    digest.update(request.signed_request_digest);
    digest.update(request.job_manifest_digest);
    digest.update(request.isolation_profile_digest);
    digest.update(now.to_be_bytes());
    digest.finalize().into()
}

fn tcp_443(address: IpAddr) -> TcpServiceTuple {
    TcpServiceTuple { address, port: 443 }
}

fn render_hosts(pins: &[SniHostPin]) -> Vec<u8> {
    let mut entries = pins
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

fn oid_hex(oid: GitOid) -> String {
    match oid {
        GitOid::Sha1(bytes) => hex::encode(bytes),
        GitOid::Sha256(bytes) => hex::encode(bytes),
    }
}

fn mapped_path(base_root: &Path, canonical: &Path) -> PathBuf {
    if base_root == Path::new("/") {
        canonical.to_path_buf()
    } else {
        base_root.join(canonical.strip_prefix("/").unwrap_or(canonical))
    }
}

fn os(value: impl Into<OsString>) -> OsString {
    value.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::os::unix::fs::PermissionsExt;

    use buzz_ci_broker_protocol::AdmitAttemptRequest;
    use serde_json::json;
    use tempfile::tempdir;

    use crate::activation::{
        ActivationGrant, DurableLeaseFields, HostActivationCoordinates, OrdinaryJobCoordinates,
        VerifiedSigner,
    };
    use crate::dns_exec::DnsExecFsError;
    use crate::dns_host::{DnsHostApplyError, DnsHostPlan};

    const SIGNER: VerifiedSigner = VerifiedSigner([5; 32]);

    fn host() -> HostActivationCoordinates {
        HostActivationCoordinates {
            integrated_candidate_sha: GitOid::Sha256([1; 32]),
            broker_build_identity: [2; 32],
            host_profile_digest: [3; 32],
            suite_identity: [4; 32],
        }
    }

    fn admission() -> OrdinaryAdmission {
        OrdinaryAdmission {
            host: host(),
            job: OrdinaryJobCoordinates {
                request_digest: [6; 32],
                manifest_digest: [7; 32],
                isolation_profile_digest: [8; 32],
                source_oid: GitOid::Sha256([9; 32]),
                base_oid: GitOid::Sha256([10; 32]),
                job_identity: [11; 32],
            },
            lease_id: [12; 16],
            run_id: [13; 16],
            attempt: 2,
            signer: SIGNER,
            nonce: [14; 32],
            expires_at: 100,
            wall_timeout_seconds: 30,
            trust_class: AdmissionTrustClass::AcceptedReviewed,
        }
    }

    fn lease() -> LeaseToken {
        LeaseToken::from_durable(DurableLeaseFields {
            lease_id: admission().lease_id,
            run_id: admission().run_id,
            attempt: admission().attempt,
            signed_request_digest: admission().job.request_digest,
            signer: SIGNER,
            generation: 17,
            nonce: admission().nonce,
            deadline_at: 90,
        })
    }

    fn authority() -> DnsLeaseAuthority {
        DnsLeaseAuthority::new(
            PrincipalUids {
                materializer: 966,
                executor: 965,
                runtime: 964,
            },
            UnitResources {
                cpu_weight: 100,
                memory_max_bytes: 2 * 1024 * 1024 * 1024,
                tasks_max: 512,
                io_weight: 100,
                cpu_quota_per_sec_usec: 200_000,
            },
            DnsDelegationAuthority::new("42".into(), "257.7-1.fc42".into(), [964, 965, 966]),
            DnsServiceAuthority::new("relay.example".into(), "198.51.100.10".parse().unwrap()),
            DnsServiceAuthority::new("mirror.example".into(), "2001:db8::20".parse().unwrap()),
        )
    }

    fn request() -> AdmitAttemptRequest {
        let admission = admission();
        AdmitAttemptRequest {
            signed_request_digest: admission.job.request_digest,
            actor_pubkey: admission.signer.0,
            audience_digest: [15; 32],
            idempotency_digest: [16; 32],
            source_pin_event_id: [17; 32],
            workflow_digest: [18; 32],
            job_manifest_digest: admission.job.manifest_digest,
            isolation_profile_digest: admission.job.isolation_profile_digest,
            run_id: admission.run_id,
            tip_oid: admission.job.source_oid,
            base_oid: admission.job.base_oid,
            issued_at: 20,
            expires_at: admission.expires_at,
            wall_timeout_seconds: admission.wall_timeout_seconds,
            attempt: admission.attempt,
            parent_attempt: 1,
            trust_class: TrustClass::AcceptedReviewed,
        }
    }

    fn grant() -> ActivationGrant {
        ActivationGrant {
            authorized_by: VerifiedSigner([19; 32]),
            host: host(),
            security_records_passed: 17,
            security_records_total: 17,
            probes_passed: 12,
            probes_total: 12,
            evidence_set_digest: [20; 32],
            blocker_closure_digest: [21; 32],
            all_blockers_closed: true,
            ordinary_signer: SIGNER,
            max_capacity: 1,
            minimum_admission_interval_seconds: 1,
            expires_at: 200,
        }
    }

    fn target() -> ReadyValidationTarget {
        ReadyValidationTarget::new(grant(), request(), 3, [22; 32], 4)
    }

    #[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
    #[error("fake command transport failed")]
    struct FakeCommandError;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ApplyFault {
        None,
        Action,
        Observation,
        WrongUid,
        DriftDnsFile,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum CleanupLeftover {
        None,
        Slice,
        Namespace,
        Table,
    }

    struct FakeApplyRunner {
        plan: LeaseIsolationPlan,
        root: PathBuf,
        fault: ApplyFault,
        leftover: CleanupLeftover,
        action_failed: bool,
        file_drifted: bool,
        slice_exists: bool,
        namespace_exists: bool,
        table_exists: bool,
    }

    impl FakeApplyRunner {
        fn new(plan: LeaseIsolationPlan, root: &Path) -> Self {
            Self {
                plan,
                root: root.to_path_buf(),
                fault: ApplyFault::None,
                leftover: CleanupLeftover::None,
                action_failed: false,
                file_drifted: false,
                slice_exists: false,
                namespace_exists: false,
                table_exists: false,
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

        fn show(&mut self, args: &[String]) -> ExactCommandOutput {
            if args.iter().any(|arg| arg == "--property=LoadState") {
                return Self::output(
                    0,
                    format!(
                        "LoadState={}\n",
                        if self.slice_exists {
                            "loaded"
                        } else {
                            "not-found"
                        }
                    )
                    .into_bytes(),
                );
            }
            if self.fault == ApplyFault::Observation {
                return Self::output(1, Vec::new());
            }
            if self.fault == ApplyFault::DriftDnsFile && !self.file_drifted {
                let hosts = mapped_path(&self.root, self.plan.dns_files.hosts.requested_path());
                fs::set_permissions(&hosts, fs::Permissions::from_mode(0o600)).unwrap();
                fs::write(&hosts, b"203.0.113.9 hostile.example\n").unwrap();
                fs::set_permissions(&hosts, fs::Permissions::from_mode(0o444)).unwrap();
                self.file_drifted = true;
            }
            let unit = &args[2];
            if unit == &self.plan.lease_slice.unit_name {
                let mut values = self.plan.lease_slice.properties.clone();
                values.insert(
                    "ControlGroup".into(),
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
                "ControlGroup".into(),
                expected.cgroup_path.display().to_string(),
            );
            if self.fault == ApplyFault::WrongUid && expected.role == PrincipalRole::Executor {
                values.insert("User".into(), "999".into());
            }
            Self::output(0, encode_show(&values))
        }

        fn nft_readback(&self) -> Vec<u8> {
            let host = DnsHostPlan::new(self.plan.clone()).unwrap();
            let policy = host.materializer_policy();
            let mut objects = vec![
                json!({"table": {"family": policy.family(), "name": policy.table()}}),
                json!({"chain": {
                    "family": policy.family(), "table": policy.table(), "name": policy.chain(),
                    "type": "filter", "hook": "output", "prio": policy.priority(),
                    "policy": "accept"
                }}),
            ];
            for tuple in policy.allowed_tcp_tuples() {
                objects.push(json!({"rule": {
                    "family": policy.family(), "table": policy.table(), "chain": policy.chain(),
                    "expr": [
                        {"match": {"op": "==", "left": {"meta": {"key": "skuid"}}, "right": policy.principal_uid()}},
                        {"match": {"op": "==", "left": {"payload": {"protocol": if tuple.address.is_ipv4() { "ip" } else { "ip6" }, "field": "daddr"}}, "right": tuple.address.to_string()}},
                        {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": tuple.port}},
                        {"accept": null}
                    ]
                }}));
            }
            objects.push(json!({"rule": {
                "family": policy.family(), "table": policy.table(), "chain": policy.chain(),
                "expr": [
                    {"match": {"op": "==", "left": {"meta": {"key": "skuid"}}, "right": policy.principal_uid()}},
                    {"drop": null}
                ]
            }}));
            serde_json::to_vec(&json!({"nftables": objects})).unwrap()
        }

        fn probe(&self, args: &[String]) -> ExactCommandOutput {
            let Some(index) = args.iter().position(|arg| {
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
            match args[index].as_str() {
                path if path == AllowedBinary::Getent.path() => match args.last().unwrap().as_str()
                {
                    "relay.example" => {
                        Self::output(0, b"198.51.100.10 STREAM relay.example\n".to_vec())
                    }
                    "mirror.example" => {
                        Self::output(0, b"2001:db8::20 STREAM mirror.example\n".to_vec())
                    }
                    _ => Self::output(2, Vec::new()),
                },
                path if path == AllowedBinary::Stat.path() => Self::output(1, Vec::new()),
                path if path == AllowedBinary::Dig.path() => Self::output(1, Vec::new()),
                path if path == AllowedBinary::Ncat.path() => {
                    let port = args.last().unwrap().parse::<u16>().unwrap();
                    Self::output(if port == 53 || port == 9 { 1 } else { 0 }, Vec::new())
                }
                _ => unreachable!(),
            }
        }
    }

    impl ExactCommandRunner for FakeApplyRunner {
        type Error = FakeCommandError;

        fn run(&mut self, command: &ExactCommand) -> Result<ExactCommandOutput, Self::Error> {
            let args = Self::args(command);
            match command.binary() {
                AllowedBinary::Systemctl if args.first().map(String::as_str) == Some("show") => {
                    Ok(self.show(&args))
                }
                AllowedBinary::Systemctl
                    if args.first().map(String::as_str) == Some("set-property") =>
                {
                    self.slice_exists = true;
                    Ok(Self::output(0, Vec::new()))
                }
                AllowedBinary::Systemctl if args.first().map(String::as_str) == Some("stop") => {
                    if self.leftover != CleanupLeftover::Slice {
                        self.slice_exists = false;
                    }
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
                    let entries = if self.namespace_exists {
                        json!([{"name": DnsHostPlan::new(self.plan.clone()).unwrap().identifiers().namespace_name()}])
                    } else {
                        json!([])
                    };
                    Ok(Self::output(0, serde_json::to_vec(&entries).unwrap()))
                }
                AllowedBinary::Ip if args.starts_with(&["netns".into(), "add".into()]) => {
                    self.namespace_exists = true;
                    Ok(Self::output(0, Vec::new()))
                }
                AllowedBinary::Ip if args.starts_with(&["netns".into(), "delete".into()]) => {
                    if self.leftover != CleanupLeftover::Namespace {
                        self.namespace_exists = false;
                    }
                    Ok(Self::output(0, Vec::new()))
                }
                AllowedBinary::Ip if args.contains(&"show".into()) => Ok(Self::output(
                    0,
                    serde_json::to_vec(&json!([{"ifname":"lo","flags":["LOOPBACK","UP"]}]))
                        .unwrap(),
                )),
                AllowedBinary::Nft if args.first().map(String::as_str) == Some("delete") => {
                    if self.leftover != CleanupLeftover::Table {
                        self.table_exists = false;
                    }
                    Ok(Self::output(0, Vec::new()))
                }
                AllowedBinary::Nft if args == ["-j", "list", "tables"] => {
                    let tables = if self.table_exists {
                        let table = DnsHostPlan::new(self.plan.clone()).unwrap();
                        json!([{"table": {"family": "inet", "name": table.identifiers().nft_table()}}])
                    } else {
                        json!([])
                    };
                    Ok(Self::output(
                        0,
                        serde_json::to_vec(&json!({"nftables": tables})).unwrap(),
                    ))
                }
                AllowedBinary::Nft if args.first().map(String::as_str) == Some("list") => Ok(
                    Self::output(if self.table_exists { 0 } else { 1 }, Vec::new()),
                ),
                AllowedBinary::Nft if args.first().map(String::as_str) == Some("-j") => {
                    Ok(Self::output(0, self.nft_readback()))
                }
                AllowedBinary::Nft if args.starts_with(&["add".into(), "table".into()]) => {
                    self.table_exists = true;
                    Ok(Self::output(0, Vec::new()))
                }
                AllowedBinary::SystemdRun
                    if !self.action_failed && self.fault == ApplyFault::Action =>
                {
                    self.action_failed = true;
                    Ok(Self::output(1, Vec::new()))
                }
                AllowedBinary::SystemdRun => Ok(self.probe(&args)),
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

    fn lifecycle(
        root: &Path,
        fault: ApplyFault,
        leftover: CleanupLeftover,
    ) -> DnsLeaseLifecycle<FakeApplyRunner> {
        let builder = DnsLeaseBuilder::new(authority());
        let plan = builder.build(admission(), lease(), 123).unwrap();
        let mut runner = FakeApplyRunner::new(plan.isolation_plan().clone(), root);
        runner.fault = fault;
        runner.leftover = leftover;
        DnsLeaseLifecycle::with_mapped_executor(builder, DnsExecutor::mapped(runner, root), root)
    }

    fn recovery_lifecycle(root: &Path) -> DnsLeaseLifecycle<FakeApplyRunner> {
        let builder = DnsLeaseBuilder::new(authority());
        let plan = builder.build(admission(), lease(), 123).unwrap();
        let mut runner = FakeApplyRunner::new(plan.isolation_plan().clone(), root);
        runner.slice_exists = true;
        runner.namespace_exists = true;
        runner.table_exists = true;
        DnsLeaseLifecycle::with_mapped_executor(builder, DnsExecutor::mapped(runner, root), root)
    }

    fn persisted_receipt(root: &Path) -> PathBuf {
        let mut lifecycle = lifecycle(root, ApplyFault::None, CleanupLeftover::None);
        lifecycle.apply(admission(), lease(), 123).unwrap();
        root.join("var/lib/buzzci/activation/receipts/dns")
            .join(format!(
                "{}-g{}.json",
                hex::encode(lease().lease_id()),
                lease().generation()
            ))
    }

    fn replace_receipt(path: &Path, bytes: &[u8]) {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(DNS_RECEIPT_FILE_MODE)).unwrap();
    }

    #[test]
    fn builder_derives_every_identity_and_activation_field() {
        let plan = DnsLeaseBuilder::new(authority())
            .build(admission(), lease(), 123)
            .unwrap();
        let lease_id = hex::encode(admission().lease_id);
        assert_eq!(plan.isolation_plan().lease_id, lease_id);
        assert_eq!(
            plan.isolation_plan().lease_unit,
            format!("buzzci-{lease_id}.slice")
        );
        assert_eq!(
            plan.host_plan().identifiers().namespace_name(),
            format!("buzzci-{lease_id}")
        );
        assert_eq!(
            plan.host_plan().identifiers().nft_table(),
            format!("buzzci_{lease_id}")
        );
        assert_eq!(
            plan.isolation_plan()
                .units
                .iter()
                .map(|unit| (unit.role, unit.uid))
                .collect::<BTreeMap<_, _>>(),
            BTreeMap::from([
                (PrincipalRole::Materializer, 966),
                (PrincipalRole::Executor, 965),
                (PrincipalRole::Runtime, 964),
            ])
        );
        assert_eq!(
            plan.activation_binding().request_digest,
            hex::encode(admission().job.request_digest)
        );
        assert_eq!(plan.activation_binding().lease_generation, 17);

        let mut foreign = admission();
        foreign.run_id = [99; 16];
        assert_eq!(
            DnsLeaseBuilder::new(authority()).build(foreign, lease(), 123),
            Err(DnsLeaseBuildError::Binding)
        );
        let mut untrusted = admission();
        untrusted.trust_class = AdmissionTrustClass::Unaccepted;
        assert_eq!(
            DnsLeaseBuilder::new(authority()).build(untrusted, lease(), 123),
            Err(DnsLeaseBuildError::Binding)
        );
    }

    #[test]
    fn lifecycle_retains_receipt_and_evidence_until_exact_cleanup() {
        let temporary = tempdir().unwrap();
        let mut lifecycle = lifecycle(temporary.path(), ApplyFault::None, CleanupLeftover::None);
        let retained = lifecycle.apply(admission(), lease(), 123).unwrap();
        assert_eq!(retained.lease_id(), admission().lease_id);
        assert!(retained.exec_receipt().readback().files_lookup_ok);
        assert_eq!(
            retained.exec_receipt().activation_binding(),
            retained.plan().activation_binding()
        );
        assert_eq!(
            retained.evidence(),
            evidence::DnsReadback {
                files_lookup_ok: true,
                arbitrary_getent_refused: true,
                resolved_varlink_inaccessible: true,
                direct_53_refused: true,
                allowed_tuples_only: true,
            }
        );
        let retained_receipt = retained.exec_receipt().clone();
        assert!(matches!(
            lifecycle.apply(admission(), lease(), 124),
            Err(DnsLeaseLifecycleError::ActiveLease)
        ));
        let released = lifecycle.reconcile(lease()).unwrap();
        assert_eq!(released.exec_receipt(), &retained_receipt);
        assert!(lifecycle.active().is_none());
        assert!(!temporary
            .path()
            .join("var/lib/buzzci/leases")
            .join(hex::encode(admission().lease_id))
            .exists());
    }

    #[test]
    fn lifecycle_recovers_exact_receipt_then_uses_bounded_reconcile() {
        let temporary = tempdir().unwrap();
        let receipt_path = persisted_receipt(temporary.path());
        let persisted = fs::read(&receipt_path).unwrap();

        let mut lifecycle = recovery_lifecycle(temporary.path());
        let retained = lifecycle.recover(admission(), lease()).unwrap();
        assert_eq!(retained.lease_id(), lease().lease_id());
        assert_eq!(
            retained.plan().receipt_name(),
            receipt_path.file_name().unwrap()
        );
        assert_eq!(
            serde_json::to_vec(retained.exec_receipt()).unwrap(),
            persisted
        );
        assert_eq!(
            retained.evidence(),
            evidence_dns_readback(released_dns_readback())
        );

        lifecycle.reconcile(lease()).unwrap();
        assert!(lifecycle.active().is_none());
        assert!(!temporary
            .path()
            .join("var/lib/buzzci/leases")
            .join(hex::encode(lease().lease_id()))
            .exists());
        assert!(receipt_path.exists());
    }

    #[test]
    fn recovery_rejects_missing_symlinked_wrong_owner_mode_and_ambiguous_receipts() {
        let temporary = tempdir().unwrap();
        let receipt = persisted_receipt(temporary.path());
        fs::remove_file(&receipt).unwrap();
        assert!(matches!(
            recovery_lifecycle(temporary.path()).recover(admission(), lease()),
            Err(DnsLeaseLifecycleError::Recovery(
                DnsLeaseRecoveryError::Missing
            ))
        ));

        let temporary = tempdir().unwrap();
        let receipt = persisted_receipt(temporary.path());
        let outside = temporary.path().join("outside-receipt");
        fs::copy(&receipt, &outside).unwrap();
        fs::remove_file(&receipt).unwrap();
        symlink(&outside, &receipt).unwrap();
        assert!(matches!(
            recovery_lifecycle(temporary.path()).recover(admission(), lease()),
            Err(DnsLeaseLifecycleError::Recovery(
                DnsLeaseRecoveryError::UnsafeAuthority
            ))
        ));

        let temporary = tempdir().unwrap();
        persisted_receipt(temporary.path());
        let mut wrong_owner = recovery_lifecycle(temporary.path());
        wrong_owner.receipts.roots.owner_uid = wrong_owner.receipts.roots.owner_uid.wrapping_add(1);
        assert!(matches!(
            wrong_owner.recover(admission(), lease()),
            Err(DnsLeaseLifecycleError::Recovery(
                DnsLeaseRecoveryError::UnsafeAuthority
            ))
        ));

        let temporary = tempdir().unwrap();
        let receipt = persisted_receipt(temporary.path());
        fs::set_permissions(&receipt, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            recovery_lifecycle(temporary.path()).recover(admission(), lease()),
            Err(DnsLeaseLifecycleError::Recovery(
                DnsLeaseRecoveryError::UnsafeAuthority
            ))
        ));

        let temporary = tempdir().unwrap();
        let receipt = persisted_receipt(temporary.path());
        let alternate = receipt.with_file_name(format!(
            "{}-g{}.json",
            hex::encode(lease().lease_id()),
            lease().generation() + 1
        ));
        fs::copy(&receipt, &alternate).unwrap();
        fs::set_permissions(
            &alternate,
            fs::Permissions::from_mode(DNS_RECEIPT_FILE_MODE),
        )
        .unwrap();
        assert!(matches!(
            recovery_lifecycle(temporary.path()).recover(admission(), lease()),
            Err(DnsLeaseLifecycleError::Recovery(
                DnsLeaseRecoveryError::Ambiguous
            ))
        ));
    }

    #[test]
    fn recovery_rejects_malformed_stale_and_plan_mismatched_receipts() {
        let temporary = tempdir().unwrap();
        let receipt = persisted_receipt(temporary.path());
        replace_receipt(&receipt, b"{}");
        assert!(matches!(
            recovery_lifecycle(temporary.path()).recover(admission(), lease()),
            Err(DnsLeaseLifecycleError::Recovery(
                DnsLeaseRecoveryError::Malformed
            ))
        ));

        let temporary = tempdir().unwrap();
        let receipt = persisted_receipt(temporary.path());
        let original = String::from_utf8(fs::read(&receipt).unwrap()).unwrap();
        let stale = original.replacen(
            &format!("\"lease_generation\":{}", lease().generation()),
            &format!("\"lease_generation\":{}", lease().generation() + 1),
            1,
        );
        replace_receipt(&receipt, stale.as_bytes());
        assert!(matches!(
            recovery_lifecycle(temporary.path()).recover(admission(), lease()),
            Err(DnsLeaseLifecycleError::Recovery(
                DnsLeaseRecoveryError::Stale
            ))
        ));

        let temporary = tempdir().unwrap();
        let receipt = persisted_receipt(temporary.path());
        let plan = DnsLeaseBuilder::new(authority())
            .build(admission(), lease(), 123)
            .unwrap();
        let original = String::from_utf8(fs::read(&receipt).unwrap()).unwrap();
        let mismatched = original.replacen(
            plan.isolation_plan().dns_files.hosts.sha256(),
            &"0".repeat(64),
            1,
        );
        replace_receipt(&receipt, mismatched.as_bytes());
        assert!(matches!(
            recovery_lifecycle(temporary.path()).recover(admission(), lease()),
            Err(DnsLeaseLifecycleError::Recovery(
                DnsLeaseRecoveryError::Mismatch
            ))
        ));
    }

    #[test]
    fn action_and_observation_failures_quarantine_without_retaining_receipts() {
        for fault in [ApplyFault::Action, ApplyFault::Observation] {
            let temporary = tempdir().unwrap();
            let mut lifecycle = lifecycle(temporary.path(), fault, CleanupLeftover::None);
            let error = lifecycle.apply(admission(), lease(), 123).unwrap_err();
            assert!(matches!(
                error,
                DnsLeaseLifecycleError::Exec(DnsExecError::Host(
                    DnsHostApplyError::ActionFailedQuarantined { .. }
                        | DnsHostApplyError::ObservationFailedQuarantined { .. }
                ))
            ));
            assert!(lifecycle.active().is_none());
        }
    }

    #[test]
    fn leftover_table_and_namespace_make_quarantine_fail_closed() {
        for leftover in [CleanupLeftover::Table, CleanupLeftover::Namespace] {
            let temporary = tempdir().unwrap();
            let mut lifecycle = lifecycle(temporary.path(), ApplyFault::Action, leftover);
            assert!(matches!(
                lifecycle.apply(admission(), lease(), 123),
                Err(DnsLeaseLifecycleError::Exec(DnsExecError::Host(
                    DnsHostApplyError::ActionFailedQuarantineFailed { .. }
                )))
            ));
            assert!(lifecycle.active().is_none());
        }
    }

    #[test]
    fn observation_and_drift_quarantine_failures_remain_closed() {
        let temporary = tempdir().unwrap();
        let mut observation = lifecycle(
            temporary.path(),
            ApplyFault::Observation,
            CleanupLeftover::Slice,
        );
        assert!(matches!(
            observation.apply(admission(), lease(), 123),
            Err(DnsLeaseLifecycleError::Exec(DnsExecError::Host(
                DnsHostApplyError::ObservationFailedQuarantineFailed { .. }
            )))
        ));

        let temporary = tempdir().unwrap();
        let mut drift = lifecycle(
            temporary.path(),
            ApplyFault::WrongUid,
            CleanupLeftover::Slice,
        );
        assert!(matches!(
            drift.apply(admission(), lease(), 123),
            Err(DnsLeaseLifecycleError::Exec(DnsExecError::Host(
                DnsHostApplyError::DriftQuarantineFailed { .. }
            )))
        ));
    }

    #[test]
    fn hostile_uid_and_dns_file_readbacks_never_release() {
        for fault in [ApplyFault::WrongUid, ApplyFault::DriftDnsFile] {
            let temporary = tempdir().unwrap();
            let mut lifecycle = lifecycle(temporary.path(), fault, CleanupLeftover::None);
            assert!(matches!(
                lifecycle.apply(admission(), lease(), 123),
                Err(DnsLeaseLifecycleError::Exec(DnsExecError::Files(
                    DnsExecFsError::Publish
                )))
            ));
            assert!(lifecycle.active().is_none());
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum StartupLeftover {
        None,
        Slice,
        Namespace,
        Table,
    }

    struct FakeStartupRunner {
        identity: LeaseDnsIdentity,
        leftover: StartupLeftover,
    }

    impl ExactCommandRunner for FakeStartupRunner {
        type Error = FakeCommandError;

        fn run(&mut self, command: &ExactCommand) -> Result<ExactCommandOutput, Self::Error> {
            let args = FakeApplyRunner::args(command);
            let output = match command.binary() {
                AllowedBinary::Systemctl => FakeApplyRunner::output(
                    0,
                    format!(
                        "LoadState={}\n",
                        if self.leftover == StartupLeftover::Slice {
                            "loaded"
                        } else {
                            "not-found"
                        }
                    )
                    .into_bytes(),
                ),
                AllowedBinary::Ip => {
                    let entries = if self.leftover == StartupLeftover::Namespace {
                        json!([{"name": self.identity.namespace_name}])
                    } else {
                        json!([])
                    };
                    FakeApplyRunner::output(0, serde_json::to_vec(&entries).unwrap())
                }
                AllowedBinary::Nft => {
                    let tables = if self.leftover == StartupLeftover::Table {
                        json!([{"table": {"family": "inet", "name": self.identity.nft_table}}])
                    } else {
                        json!([])
                    };
                    FakeApplyRunner::output(
                        0,
                        serde_json::to_vec(&json!({"nftables": tables})).unwrap(),
                    )
                }
                _ => panic!("unexpected startup command: {args:?}"),
            };
            Ok(output)
        }
    }

    fn startup_verifier(
        root: &Path,
        leftover: StartupLeftover,
    ) -> DnsStartupVerifier<FakeStartupRunner> {
        DnsStartupVerifier::mapped(
            FakeStartupRunner {
                identity: LeaseDnsIdentity::from_bytes(admission().lease_id),
                leftover,
            },
            root,
        )
    }

    #[test]
    fn startup_proof_binds_the_restored_grant_and_fresh_absence() {
        let temporary = tempdir().unwrap();
        let mut verifier = startup_verifier(temporary.path(), StartupLeftover::None);
        let proof = verifier
            .prove_restored_grant_clean(&target(), admission(), 50)
            .unwrap();
        assert_eq!(proof.target(), target());
        assert_eq!(proof.lease_id(), admission().lease_id);
        assert_eq!(proof.observed_at(), 50);
        assert_ne!(proof.digest(), [0; 32]);

        let mut foreign = admission();
        foreign.job.manifest_digest = [99; 32];
        assert!(matches!(
            verifier.prove_restored_grant_clean(&target(), foreign, 50),
            Err(DnsStartupProofError::Binding)
        ));
    }

    #[test]
    fn startup_proof_refuses_every_leftover_dns_identity() {
        for (leftover, expected) in [
            (StartupLeftover::Slice, StaleDnsState::LeaseSlice),
            (StartupLeftover::Namespace, StaleDnsState::NetworkNamespace),
            (StartupLeftover::Table, StaleDnsState::NftTable),
        ] {
            let temporary = tempdir().unwrap();
            let mut verifier = startup_verifier(temporary.path(), leftover);
            assert!(matches!(
                verifier.prove_restored_grant_clean(&target(), admission(), 50),
                Err(DnsStartupProofError::Leftover(found)) if found == expected
            ));
        }

        let temporary = tempdir().unwrap();
        let lease_dir = temporary
            .path()
            .join("var/lib/buzzci/leases")
            .join(hex::encode(admission().lease_id));
        fs::create_dir_all(&lease_dir).unwrap();
        fs::set_permissions(&lease_dir, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(lease_dir.join("hosts"), b"hostile").unwrap();
        let mut verifier = startup_verifier(temporary.path(), StartupLeftover::None);
        assert!(matches!(
            verifier.prove_restored_grant_clean(&target(), admission(), 50),
            Err(DnsStartupProofError::Leftover(StaleDnsState::LeaseFiles))
        ));
    }
}
