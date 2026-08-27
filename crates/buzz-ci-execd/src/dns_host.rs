//! Closed host-application seam for per-lease DNS isolation.
//!
//! This module does not execute commands or mutate the host. It translates a
//! validated [`LeaseIsolationPlan`] into a fixed sequence of typed operations
//! for the in-process root broker. A backend can implement those operations
//! with native systemd, network-namespace, and nftables APIs. Any partial
//! apply, observation failure, or readback drift quarantines the exact lease
//! slice before this adapter can report the lease ready.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::dns_isolation::{
    verify_lease_isolation, IsolationMismatch, LeaseIsolationObservation, LeaseIsolationPlan,
    LeaseIsolationReadback, LeaseSlicePlan, PrincipalRole, TcpServiceTuple, TransientUnitPlan,
    UnitNetworkMode, CAS_LOOPBACK_ADDRESS, CAS_LOOPBACK_PORT, SYSTEMD_RESOLVE_RUNTIME_PATH,
};

/// Root-owned namespace directory used by the broker.
pub const NETWORK_NAMESPACE_ROOT: &str = "/run/netns";

/// nftables family used for the materializer egress policy.
pub const MATERIALIZER_NFT_FAMILY: &str = "inet";

/// Fixed chain within each per-lease nftables table.
pub const MATERIALIZER_NFT_CHAIN: &str = "materializer_output";

/// Named byte counter shared by every materializer rule in one lease table.
pub const MATERIALIZER_NFT_COUNTER: &str = "materializer_git_bytes";

const LEASE_FILE_ROOT: &str = "/var/lib/buzzci/leases";
const MATERIALIZER_NFT_PRIORITY: i32 = 0;
const EXPECTED_SLICE_PROPERTIES: [&str; 6] = [
    "CPUQuotaPerSecUSec",
    "CPUWeight",
    "IOWeight",
    "MemoryMax",
    "MemorySwapMax",
    "TasksMax",
];

/// Host identities derived solely from a validated lease identifier.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LeaseHostIdentifiers {
    lease_slice: String,
    lease_cgroup: PathBuf,
    namespace_name: String,
    namespace_path: PathBuf,
    nft_table: String,
    nft_chain: String,
    principal_units: BTreeMap<PrincipalRole, String>,
}

impl LeaseHostIdentifiers {
    fn for_lease(lease_id: &str) -> Result<Self, DnsHostPlanError> {
        if !safe_lease_id(lease_id) {
            return Err(DnsHostPlanError::InvalidLeaseId);
        }
        let lease_slice = format!("buzzci-{lease_id}.slice");
        let lease_cgroup = Path::new("/buzzci.slice").join(&lease_slice);
        let namespace_name = format!("buzzci-{lease_id}");
        let namespace_path = Path::new(NETWORK_NAMESPACE_ROOT).join(&namespace_name);
        let principal_units = BTreeMap::from([
            (
                PrincipalRole::Materializer,
                format!("buzzci-{lease_id}-mat.service"),
            ),
            (
                PrincipalRole::Executor,
                format!("buzzci-{lease_id}-exec.service"),
            ),
            (
                PrincipalRole::Runtime,
                format!("buzzci-{lease_id}-run.service"),
            ),
        ]);
        Ok(Self {
            lease_slice,
            lease_cgroup,
            namespace_name,
            namespace_path,
            nft_table: format!("buzzci_{lease_id}"),
            nft_chain: MATERIALIZER_NFT_CHAIN.to_owned(),
            principal_units,
        })
    }

    pub fn lease_slice(&self) -> &str {
        &self.lease_slice
    }

    pub fn lease_cgroup(&self) -> &Path {
        &self.lease_cgroup
    }

    pub fn namespace_name(&self) -> &str {
        &self.namespace_name
    }

    pub fn namespace_path(&self) -> &Path {
        &self.namespace_path
    }

    pub fn nft_table(&self) -> &str {
        &self.nft_table
    }

    pub fn nft_chain(&self) -> &str {
        &self.nft_chain
    }

    pub fn principal_unit(&self, role: PrincipalRole) -> &str {
        self.principal_units
            .get(&role)
            .expect("all three principal identities are compiled into the plan")
    }
}

/// Broker-owned no-egress namespace applied before principal services start.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NetworkNamespacePlan {
    name: String,
    path: PathBuf,
    loopback_up: bool,
    egress_blocked: bool,
}

impl NetworkNamespacePlan {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub const fn loopback_up(&self) -> bool {
        self.loopback_up
    }

    pub const fn egress_blocked(&self) -> bool {
        self.egress_blocked
    }
}

/// Fixed nftables base-chain hook for materializer egress.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NftHook {
    Output,
}

/// Exact materializer nftables policy. Unmatched traffic is denied.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MaterializerNftPlan {
    family: String,
    table: String,
    chain: String,
    counter: String,
    hook: NftHook,
    priority: i32,
    principal_uid: u32,
    allowed_tcp_tuples: Vec<TcpServiceTuple>,
    unmatched_traffic_denied: bool,
}

impl MaterializerNftPlan {
    pub fn family(&self) -> &str {
        &self.family
    }

    pub fn table(&self) -> &str {
        &self.table
    }

    pub fn chain(&self) -> &str {
        &self.chain
    }

    pub fn counter(&self) -> &str {
        &self.counter
    }

    pub const fn hook(&self) -> NftHook {
        self.hook
    }

    pub const fn priority(&self) -> i32 {
        self.priority
    }

    pub const fn principal_uid(&self) -> u32 {
        self.principal_uid
    }

    pub fn allowed_tcp_tuples(&self) -> &[TcpServiceTuple] {
        &self.allowed_tcp_tuples
    }

    pub const fn unmatched_traffic_denied(&self) -> bool {
        self.unmatched_traffic_denied
    }
}

/// One operation in the only accepted host-application order.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum DnsHostAction {
    EnsureLeaseSlice { slice: LeaseSlicePlan },
    EnsureNoEgressNamespace { namespace: NetworkNamespacePlan },
    InstallMaterializerPolicy { policy: MaterializerNftPlan },
    EnsurePrincipalService { service: TransientUnitPlan },
}

/// Exact slice which may be quarantined. No general cleanup path is exposed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LeaseSliceQuarantine {
    unit_name: String,
    cgroup_path: PathBuf,
}

impl LeaseSliceQuarantine {
    pub fn unit_name(&self) -> &str {
        &self.unit_name
    }

    pub fn cgroup_path(&self) -> &Path {
        &self.cgroup_path
    }
}

/// Closed readback target supplied to the privileged backend.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DnsHostReadbackTarget {
    isolation: LeaseIsolationPlan,
    identifiers: LeaseHostIdentifiers,
    namespace: NetworkNamespacePlan,
    materializer_policy: MaterializerNftPlan,
}

impl DnsHostReadbackTarget {
    pub fn isolation(&self) -> &LeaseIsolationPlan {
        &self.isolation
    }

    pub fn identifiers(&self) -> &LeaseHostIdentifiers {
        &self.identifiers
    }

    pub fn namespace(&self) -> &NetworkNamespacePlan {
        &self.namespace
    }

    pub fn materializer_policy(&self) -> &MaterializerNftPlan {
        &self.materializer_policy
    }
}

/// Namespace identity and deny-by-default state collected from the host.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkNamespaceReadback {
    pub name: String,
    pub path: PathBuf,
    pub loopback_up: bool,
    pub egress_blocked: bool,
}

/// Effective nftables identity and tuple policy collected from the host.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MaterializerNftReadback {
    pub family: String,
    pub table: String,
    pub chain: String,
    pub counter: String,
    pub hook: NftHook,
    pub priority: i32,
    pub principal_uid: u32,
    pub allowed_tcp_tuples: Vec<TcpServiceTuple>,
    pub unmatched_traffic_denied: bool,
}

/// Complete observation consumed by [`DnsHostAdapter::apply`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DnsHostObservation {
    pub isolation: LeaseIsolationObservation,
    pub namespace: NetworkNamespaceReadback,
    pub materializer_policy: MaterializerNftReadback,
}

/// Validated host plan. Its operation list cannot be extended by a caller.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DnsHostPlan {
    isolation: LeaseIsolationPlan,
    identifiers: LeaseHostIdentifiers,
    namespace: NetworkNamespacePlan,
    materializer_policy: MaterializerNftPlan,
    actions: Vec<DnsHostAction>,
    quarantine: LeaseSliceQuarantine,
}

impl DnsHostPlan {
    /// Convert a pure isolation plan into the closed host plan.
    pub fn new(isolation: LeaseIsolationPlan) -> Result<Self, DnsHostPlanError> {
        let identifiers = LeaseHostIdentifiers::for_lease(&isolation.lease_id)?;
        validate_isolation_shape(&isolation, &identifiers)?;

        let namespace = NetworkNamespacePlan {
            name: identifiers.namespace_name.clone(),
            path: identifiers.namespace_path.clone(),
            loopback_up: true,
            egress_blocked: true,
        };
        let materializer = isolation
            .units
            .iter()
            .find(|unit| unit.role == PrincipalRole::Materializer)
            .expect("validated plan has one materializer");
        let mut allowed_tcp_tuples = isolation.materializer_allowlist.clone();
        allowed_tcp_tuples.sort_unstable();
        let materializer_policy = MaterializerNftPlan {
            family: MATERIALIZER_NFT_FAMILY.to_owned(),
            table: identifiers.nft_table.clone(),
            chain: identifiers.nft_chain.clone(),
            counter: MATERIALIZER_NFT_COUNTER.to_owned(),
            hook: NftHook::Output,
            priority: MATERIALIZER_NFT_PRIORITY,
            principal_uid: materializer.uid,
            allowed_tcp_tuples,
            unmatched_traffic_denied: true,
        };

        let mut actions = vec![
            DnsHostAction::EnsureLeaseSlice {
                slice: isolation.lease_slice.clone(),
            },
            DnsHostAction::EnsureNoEgressNamespace {
                namespace: namespace.clone(),
            },
            DnsHostAction::InstallMaterializerPolicy {
                policy: materializer_policy.clone(),
            },
        ];
        actions.extend(
            isolation
                .units
                .iter()
                .cloned()
                .map(|service| DnsHostAction::EnsurePrincipalService { service }),
        );
        let quarantine = LeaseSliceQuarantine {
            unit_name: identifiers.lease_slice.clone(),
            cgroup_path: identifiers.lease_cgroup.clone(),
        };

        Ok(Self {
            isolation,
            identifiers,
            namespace,
            materializer_policy,
            actions,
            quarantine,
        })
    }

    pub fn actions(&self) -> &[DnsHostAction] {
        &self.actions
    }

    pub fn identifiers(&self) -> &LeaseHostIdentifiers {
        &self.identifiers
    }

    pub fn namespace(&self) -> &NetworkNamespacePlan {
        &self.namespace
    }

    pub fn materializer_policy(&self) -> &MaterializerNftPlan {
        &self.materializer_policy
    }

    pub fn quarantine_target(&self) -> &LeaseSliceQuarantine {
        &self.quarantine
    }

    fn readback_target(&self) -> DnsHostReadbackTarget {
        DnsHostReadbackTarget {
            isolation: self.isolation.clone(),
            identifiers: self.identifiers.clone(),
            namespace: self.namespace.clone(),
            materializer_policy: self.materializer_policy.clone(),
        }
    }
}

/// Narrow in-process host seam. Implementations receive typed operations only.
pub trait DnsHostBackend {
    type Error: std::error::Error + Send + Sync + 'static;

    fn apply(&mut self, action: &DnsHostAction) -> Result<(), Self::Error>;

    fn observe(
        &mut self,
        target: &DnsHostReadbackTarget,
    ) -> Result<DnsHostObservation, Self::Error>;

    fn quarantine_slice(&mut self, target: &LeaseSliceQuarantine) -> Result<(), Self::Error>;
}

/// In-process adapter which owns apply order and the release decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsHostAdapter {
    plan: DnsHostPlan,
}

impl DnsHostAdapter {
    pub fn new(plan: DnsHostPlan) -> Self {
        Self { plan }
    }

    pub fn plan(&self) -> &DnsHostPlan {
        &self.plan
    }

    /// Apply the fixed plan and release only after exact host and DNS readback.
    pub fn apply<B: DnsHostBackend>(
        &self,
        backend: &mut B,
    ) -> Result<DnsHostApplyResult, DnsHostApplyError<B::Error>> {
        for (index, action) in self.plan.actions.iter().enumerate() {
            if let Err(source) = backend.apply(action) {
                return match backend.quarantine_slice(&self.plan.quarantine) {
                    Ok(()) => Err(DnsHostApplyError::ActionFailedQuarantined { index, source }),
                    Err(quarantine) => Err(DnsHostApplyError::ActionFailedQuarantineFailed {
                        index,
                        source,
                        quarantine,
                    }),
                };
            }
        }

        let observation = match backend.observe(&self.plan.readback_target()) {
            Ok(observation) => observation,
            Err(source) => {
                return match backend.quarantine_slice(&self.plan.quarantine) {
                    Ok(()) => Err(DnsHostApplyError::ObservationFailedQuarantined { source }),
                    Err(quarantine) => Err(DnsHostApplyError::ObservationFailedQuarantineFailed {
                        source,
                        quarantine,
                    }),
                };
            }
        };

        let mut readback = verify_lease_isolation(&self.plan.isolation, observation.isolation);
        compare_namespace(
            &self.plan.namespace,
            &observation.namespace,
            &mut readback.mismatches,
        );
        compare_materializer_policy(
            &self.plan.materializer_policy,
            &observation.materializer_policy,
            &mut readback.mismatches,
        );
        if !readback.mismatches.is_empty() {
            quarantine_readback(&mut readback);
        }

        if readback.quarantined {
            return match backend.quarantine_slice(&self.plan.quarantine) {
                Ok(()) => Ok(DnsHostApplyResult {
                    disposition: DnsHostDisposition::Quarantined,
                    readback,
                }),
                Err(source) => Err(DnsHostApplyError::DriftQuarantineFailed {
                    readback: Box::new(readback),
                    source,
                }),
            };
        }

        Ok(DnsHostApplyResult {
            disposition: DnsHostDisposition::Released,
            readback,
        })
    }
}

/// Terminal adapter disposition.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsHostDisposition {
    Released,
    Quarantined,
}

/// Successful adapter return. Quarantined drift is a successful fail-closed result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DnsHostApplyResult {
    pub disposition: DnsHostDisposition,
    pub readback: LeaseIsolationReadback,
}

impl DnsHostApplyResult {
    pub fn released(&self) -> bool {
        self.disposition == DnsHostDisposition::Released
            && !self.readback.quarantined
            && self.readback.teardown_attestation_allowed
            && self.readback.capacity_restoration_allowed
    }
}

/// Failure which never authorizes lease release.
#[derive(Debug, Error)]
pub enum DnsHostApplyError<E: std::error::Error + 'static> {
    #[error("DNS host action {index} failed; the lease slice was quarantined")]
    ActionFailedQuarantined {
        index: usize,
        #[source]
        source: E,
    },
    #[error("DNS host action {index} failed and lease-slice quarantine also failed")]
    ActionFailedQuarantineFailed {
        index: usize,
        source: E,
        quarantine: E,
    },
    #[error("DNS host observation failed; the lease slice was quarantined")]
    ObservationFailedQuarantined {
        #[source]
        source: E,
    },
    #[error("DNS host observation failed and lease-slice quarantine also failed")]
    ObservationFailedQuarantineFailed { source: E, quarantine: E },
    #[error("DNS host readback drifted and lease-slice quarantine failed")]
    DriftQuarantineFailed {
        readback: Box<LeaseIsolationReadback>,
        #[source]
        source: E,
    },
}

/// Invalid or caller-expandable host plan.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum DnsHostPlanError {
    #[error("invalid lease identifier")]
    InvalidLeaseId,
    #[error("lease slice identity or resource properties are not exact")]
    InvalidLeaseSlice,
    #[error("principal service identities are not the compiled three-role set")]
    InvalidPrincipalIdentity,
    #[error("principal systemd properties or network placement are not exact")]
    InvalidPrincipalProperties,
    #[error("DNS files are not the fixed files under the lease state directory")]
    InvalidDnsFilePath,
    #[error("materializer allowlist is not relay, mirror, and fixed loopback CAS")]
    InvalidMaterializerAllowlist,
}

fn validate_isolation_shape(
    plan: &LeaseIsolationPlan,
    identifiers: &LeaseHostIdentifiers,
) -> Result<(), DnsHostPlanError> {
    if plan.lease_unit != identifiers.lease_slice
        || plan.cgroup_path != identifiers.lease_cgroup
        || plan.lease_slice.unit_name != identifiers.lease_slice
        || plan.lease_slice.cgroup_path != identifiers.lease_cgroup
        || !exact_slice_properties(&plan.lease_slice.properties)
    {
        return Err(DnsHostPlanError::InvalidLeaseSlice);
    }

    let lease_file_root = Path::new(LEASE_FILE_ROOT).join(&plan.lease_id);
    if plan.dns_files.resolv_conf.requested_path()
        != lease_file_root.join("empty-resolv.conf").as_path()
        || plan.dns_files.hosts.requested_path() != lease_file_root.join("hosts").as_path()
    {
        return Err(DnsHostPlanError::InvalidDnsFilePath);
    }

    let expected_roles = [
        PrincipalRole::Materializer,
        PrincipalRole::Executor,
        PrincipalRole::Runtime,
    ];
    if plan.units.len() != expected_roles.len()
        || plan.units.iter().map(|unit| unit.role).ne(expected_roles)
        || plan
            .units
            .iter()
            .map(|unit| unit.uid)
            .collect::<BTreeSet<_>>()
            .len()
            != expected_roles.len()
    {
        return Err(DnsHostPlanError::InvalidPrincipalIdentity);
    }

    for unit in &plan.units {
        let expected_name = identifiers.principal_unit(unit.role);
        if unit.unit_name != expected_name
            || unit.cgroup_path != identifiers.lease_cgroup.join(expected_name)
            || unit.uid == 0
        {
            return Err(DnsHostPlanError::InvalidPrincipalIdentity);
        }
        validate_principal_properties(plan, identifiers, unit)?;
    }

    validate_materializer_allowlist(plan)?;
    Ok(())
}

fn exact_slice_properties(properties: &BTreeMap<String, String>) -> bool {
    if properties.len() != EXPECTED_SLICE_PROPERTIES.len()
        || !EXPECTED_SLICE_PROPERTIES
            .iter()
            .all(|name| properties.contains_key(*name))
        || properties.get("MemorySwapMax").map(String::as_str) != Some("0")
    {
        return false;
    }
    let parse = |name: &str| {
        properties
            .get(name)
            .and_then(|value| value.parse::<u64>().ok())
    };
    matches!(parse("CPUWeight"), Some(1..=10_000))
        && matches!(parse("IOWeight"), Some(1..=10_000))
        && matches!(parse("CPUQuotaPerSecUSec"), Some(1..))
        && matches!(parse("MemoryMax"), Some(1..))
        && matches!(parse("TasksMax"), Some(1..))
}

fn validate_principal_properties(
    plan: &LeaseIsolationPlan,
    identifiers: &LeaseHostIdentifiers,
    unit: &TransientUnitPlan,
) -> Result<(), DnsHostPlanError> {
    let bind_files = format!(
        "{}:/etc/resolv.conf {}:/etc/hosts",
        plan.dns_files.resolv_conf.requested_path().display(),
        plan.dns_files.hosts.requested_path().display()
    );
    let common = [
        ("BindReadOnlyPaths", bind_files.as_str()),
        ("InaccessiblePaths", SYSTEMD_RESOLVE_RUNTIME_PATH),
        ("Slice", identifiers.lease_slice()),
    ];
    if common
        .iter()
        .any(|(name, expected)| unit.properties.get(*name).map(String::as_str) != Some(*expected))
        || unit.properties.get("User").map(String::as_str) != Some(unit.uid.to_string().as_str())
    {
        return Err(DnsHostPlanError::InvalidPrincipalProperties);
    }

    match (&unit.role, &unit.network_mode) {
        (PrincipalRole::Materializer, UnitNetworkMode::HostTupleAllowlist { tuples })
            if unit.properties.len() == 7
                && unit.properties.get("PrivateNetwork").map(String::as_str) == Some("no")
                && unit.properties.get("RuntimeDirectory").map(String::as_str)
                    == unit.unit_name.strip_suffix(".service")
                && unit
                    .properties
                    .get("RuntimeDirectoryMode")
                    .map(String::as_str)
                    == Some("0700")
                && tuples == &plan.materializer_allowlist =>
        {
            Ok(())
        }
        (
            PrincipalRole::Executor | PrincipalRole::Runtime,
            UnitNetworkMode::BrokerNoEgressNamespace { path },
        ) if unit.properties.len() == 5
            && path == identifiers.namespace_path()
            && unit
                .properties
                .get("NetworkNamespacePath")
                .map(String::as_str)
                == identifiers.namespace_path().to_str() =>
        {
            Ok(())
        }
        _ => Err(DnsHostPlanError::InvalidPrincipalProperties),
    }
}

fn validate_materializer_allowlist(plan: &LeaseIsolationPlan) -> Result<(), DnsHostPlanError> {
    let allowlist = &plan.materializer_allowlist;
    let unique = allowlist.iter().copied().collect::<BTreeSet<_>>();
    let cas = TcpServiceTuple {
        address: IpAddr::V4(CAS_LOOPBACK_ADDRESS),
        port: CAS_LOOPBACK_PORT,
    };
    if allowlist.len() != 3
        || unique.len() != 3
        || !unique.contains(&cas)
        || unique
            .iter()
            .filter(|tuple| tuple.address.is_loopback())
            .copied()
            .ne([cas])
        || unique
            .iter()
            .filter(|tuple| !tuple.address.is_loopback())
            .any(|tuple| {
                tuple.port != 443 || tuple.address.is_unspecified() || tuple.address.is_multicast()
            })
    {
        return Err(DnsHostPlanError::InvalidMaterializerAllowlist);
    }
    Ok(())
}

fn compare_namespace(
    expected: &NetworkNamespacePlan,
    observed: &NetworkNamespaceReadback,
    mismatches: &mut Vec<IsolationMismatch>,
) {
    if observed.name != expected.name
        || observed.path != expected.path
        || observed.loopback_up != expected.loopback_up
        || observed.egress_blocked != expected.egress_blocked
    {
        mismatches.push(IsolationMismatch {
            field: "dns_host.namespace".to_owned(),
            expected: format!("{expected:?}"),
            observed: format!("{observed:?}"),
        });
    }
}

fn compare_materializer_policy(
    expected: &MaterializerNftPlan,
    observed: &MaterializerNftReadback,
    mismatches: &mut Vec<IsolationMismatch>,
) {
    let mut observed_tuples = observed.allowed_tcp_tuples.clone();
    observed_tuples.sort_unstable();
    if observed.family != expected.family
        || observed.table != expected.table
        || observed.chain != expected.chain
        || observed.hook != expected.hook
        || observed.priority != expected.priority
        || observed.principal_uid != expected.principal_uid
        || observed_tuples != expected.allowed_tcp_tuples
        || observed.unmatched_traffic_denied != expected.unmatched_traffic_denied
    {
        mismatches.push(IsolationMismatch {
            field: "dns_host.materializer_policy".to_owned(),
            expected: format!("{expected:?}"),
            observed: format!("{observed:?}"),
        });
    }
}

fn quarantine_readback(readback: &mut LeaseIsolationReadback) {
    readback.quarantined = true;
    readback.teardown_attestation_allowed = false;
    readback.capacity_restoration_allowed = false;
}

fn safe_lease_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_isolation::{
        build_lease_isolation_plan, BrokerApprovedMaterializerNetwork, BrokerFileType,
        BrokerPinnedFile, BrokerPinnedFileReadback, DelegationCanaryReadback, DnsFiles,
        DnsFilesReadback, FilesLookupProbe, LeaseIsolationRequest, LeaseSliceIdentity,
        LeaseSliceReadback, NetworkNamespaceProperty, PinnedServiceKind, PrincipalDnsObservation,
        PrincipalUnitIdentity, SniHostPin, TransientUnitReadback, TupleConnectProbe, UnitResources,
        EMPTY_FILE_SHA256,
    };
    use std::net::Ipv4Addr;

    fn tuple(address: &str, port: u16) -> TcpServiceTuple {
        TcpServiceTuple {
            address: address.parse().unwrap(),
            port,
        }
    }

    fn isolation_plan() -> LeaseIsolationPlan {
        isolation_plan_with_file_root("/var/lib/buzzci/leases/lease01")
    }

    fn isolation_plan_with_file_root(file_root: &str) -> LeaseIsolationPlan {
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
                    Path::new(file_root).join("empty-resolv.conf"),
                    EMPTY_FILE_SHA256.to_owned(),
                )
                .unwrap(),
                hosts: BrokerPinnedFile::new(Path::new(file_root).join("hosts"), "a".repeat(64))
                    .unwrap(),
                sni_host_pins: vec![
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
                ],
            },
            approved_materializer_network: BrokerApprovedMaterializerNetwork::new(
                tuple("198.51.100.10", 443),
                tuple("2001:db8::20", 443),
            )
            .unwrap(),
        })
        .unwrap()
    }

    fn file_readback(path: &Path, sha256: &str) -> BrokerPinnedFileReadback {
        BrokerPinnedFileReadback {
            requested_path: path.to_path_buf(),
            canonical_path: path.to_path_buf(),
            owner_uid: 0,
            owner_gid: 0,
            mode: 0o444,
            file_type: BrokerFileType::Regular,
            type_checked_no_follow: true,
            link_count: 1,
            sha256: sha256.to_owned(),
        }
    }

    fn host_observation(plan: &DnsHostPlan) -> DnsHostObservation {
        let isolation = &plan.isolation;
        let principal_dns = isolation
            .units
            .iter()
            .map(|unit| PrincipalDnsObservation {
                role: unit.role,
                files_lookups: if unit.role == PrincipalRole::Materializer {
                    vec![
                        FilesLookupProbe {
                            hostname: "relay.example".to_owned(),
                            addresses: vec!["198.51.100.10".parse().unwrap()],
                            resolved_by_files: true,
                        },
                        FilesLookupProbe {
                            hostname: "mirror.example".to_owned(),
                            addresses: vec!["2001:db8::20".parse().unwrap()],
                            resolved_by_files: true,
                        },
                    ]
                } else {
                    Vec::new()
                },
                arbitrary_getent_succeeded: false,
                resolved_varlink_accessible: false,
                direct_udp_53_connected: false,
                direct_tcp_53_connected: false,
            })
            .collect();
        let mut probes = isolation
            .materializer_allowlist
            .iter()
            .copied()
            .map(|tuple| TupleConnectProbe {
                role: PrincipalRole::Materializer,
                tuple,
                connected: true,
            })
            .collect::<Vec<_>>();
        probes.push(TupleConnectProbe {
            role: PrincipalRole::Materializer,
            tuple: tuple("203.0.113.44", 443),
            connected: false,
        });
        DnsHostObservation {
            isolation: LeaseIsolationObservation {
                lease_slice: LeaseSliceReadback {
                    unit_name: isolation.lease_slice.unit_name.clone(),
                    cgroup_path: isolation.lease_slice.cgroup_path.clone(),
                    properties: isolation.lease_slice.properties.clone(),
                },
                units: isolation
                    .units
                    .iter()
                    .map(|unit| TransientUnitReadback {
                        role: unit.role,
                        uid: unit.uid,
                        unit_name: unit.unit_name.clone(),
                        cgroup_path: unit.cgroup_path.clone(),
                        properties: unit.properties.clone(),
                        network_mode: unit.network_mode.clone(),
                    })
                    .collect(),
                dns_files: DnsFilesReadback {
                    resolv_conf: file_readback(
                        isolation.dns_files.resolv_conf.requested_path(),
                        EMPTY_FILE_SHA256,
                    ),
                    hosts: file_readback(
                        isolation.dns_files.hosts.requested_path(),
                        isolation.dns_files.hosts.sha256(),
                    ),
                },
                principal_dns,
                effective_materializer_allowlist: isolation.materializer_allowlist.clone(),
                tuple_connect_probes: probes,
            },
            namespace: NetworkNamespaceReadback {
                name: plan.namespace.name.clone(),
                path: plan.namespace.path.clone(),
                loopback_up: true,
                egress_blocked: true,
            },
            materializer_policy: MaterializerNftReadback {
                family: plan.materializer_policy.family.clone(),
                table: plan.materializer_policy.table.clone(),
                chain: plan.materializer_policy.chain.clone(),
                counter: plan.materializer_policy.counter.clone(),
                hook: NftHook::Output,
                priority: MATERIALIZER_NFT_PRIORITY,
                principal_uid: plan.materializer_policy.principal_uid,
                allowed_tcp_tuples: plan.materializer_policy.allowed_tcp_tuples.clone(),
                unmatched_traffic_denied: true,
            },
        }
    }

    #[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
    #[error("fake host failure")]
    struct FakeError;

    struct FakeBackend {
        actions: Vec<DnsHostAction>,
        observation: Option<DnsHostObservation>,
        fail_action: Option<usize>,
        fail_observation: bool,
        fail_quarantine: bool,
        quarantine: Vec<LeaseSliceQuarantine>,
    }

    impl FakeBackend {
        fn ready(plan: &DnsHostPlan) -> Self {
            Self {
                actions: Vec::new(),
                observation: Some(host_observation(plan)),
                fail_action: None,
                fail_observation: false,
                fail_quarantine: false,
                quarantine: Vec::new(),
            }
        }
    }

    impl DnsHostBackend for FakeBackend {
        type Error = FakeError;

        fn apply(&mut self, action: &DnsHostAction) -> Result<(), Self::Error> {
            let index = self.actions.len();
            self.actions.push(action.clone());
            if self.fail_action == Some(index) {
                Err(FakeError)
            } else {
                Ok(())
            }
        }

        fn observe(
            &mut self,
            _target: &DnsHostReadbackTarget,
        ) -> Result<DnsHostObservation, Self::Error> {
            if self.fail_observation {
                Err(FakeError)
            } else {
                Ok(self.observation.clone().unwrap())
            }
        }

        fn quarantine_slice(&mut self, target: &LeaseSliceQuarantine) -> Result<(), Self::Error> {
            self.quarantine.push(target.clone());
            if self.fail_quarantine {
                Err(FakeError)
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn plan_derives_exact_identifiers_and_fixed_action_order() {
        let plan = DnsHostPlan::new(isolation_plan()).unwrap();
        assert_eq!(plan.identifiers.lease_slice(), "buzzci-lease01.slice");
        assert_eq!(
            plan.identifiers.lease_cgroup(),
            Path::new("/buzzci.slice/buzzci-lease01.slice")
        );
        assert_eq!(plan.identifiers.namespace_name(), "buzzci-lease01");
        assert_eq!(
            plan.identifiers.namespace_path(),
            Path::new("/run/netns/buzzci-lease01")
        );
        assert_eq!(plan.identifiers.nft_table(), "buzzci_lease01");
        assert_eq!(plan.identifiers.nft_chain(), MATERIALIZER_NFT_CHAIN);
        assert_eq!(plan.materializer_policy.hook(), NftHook::Output);
        assert_eq!(plan.materializer_policy.priority(), 0);
        assert!(plan.materializer_policy.unmatched_traffic_denied());
        assert_eq!(plan.actions.len(), 6);
        assert!(matches!(
            plan.actions[0],
            DnsHostAction::EnsureLeaseSlice { .. }
        ));
        assert!(matches!(
            plan.actions[1],
            DnsHostAction::EnsureNoEgressNamespace { .. }
        ));
        assert!(matches!(
            plan.actions[2],
            DnsHostAction::InstallMaterializerPolicy { .. }
        ));
        for (action, role) in plan.actions[3..].iter().zip([
            PrincipalRole::Materializer,
            PrincipalRole::Executor,
            PrincipalRole::Runtime,
        ]) {
            assert!(matches!(
                action,
                DnsHostAction::EnsurePrincipalService { service } if service.role == role
            ));
        }
        assert!(plan
            .materializer_policy
            .allowed_tcp_tuples
            .contains(&TcpServiceTuple {
                address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: CAS_LOOPBACK_PORT,
            }));
    }

    #[test]
    fn exact_apply_and_all_five_proofs_release() {
        let plan = DnsHostPlan::new(isolation_plan()).unwrap();
        let adapter = DnsHostAdapter::new(plan.clone());
        let mut backend = FakeBackend::ready(&plan);
        let result = adapter.apply(&mut backend).unwrap();
        assert!(result.released());
        assert_eq!(result.disposition, DnsHostDisposition::Released);
        assert!(result.readback.dns_readback.files_lookup_ok);
        assert!(result.readback.dns_readback.arbitrary_getent_refused);
        assert!(result.readback.dns_readback.resolved_varlink_inaccessible);
        assert!(result.readback.dns_readback.direct_53_refused);
        assert!(result.readback.dns_readback.allowed_tuples_only);
        assert_eq!(backend.actions, plan.actions);
        assert!(backend.quarantine.is_empty());
    }

    #[test]
    fn partial_apply_quarantines_only_the_exact_lease_slice() {
        let plan = DnsHostPlan::new(isolation_plan()).unwrap();
        let adapter = DnsHostAdapter::new(plan.clone());
        let mut backend = FakeBackend::ready(&plan);
        backend.fail_action = Some(2);
        assert!(matches!(
            adapter.apply(&mut backend),
            Err(DnsHostApplyError::ActionFailedQuarantined { index: 2, .. })
        ));
        assert_eq!(backend.actions.len(), 3);
        assert_eq!(backend.quarantine, vec![plan.quarantine.clone()]);
        assert_eq!(backend.quarantine[0].unit_name(), "buzzci-lease01.slice");
        assert_eq!(
            backend.quarantine[0].cgroup_path(),
            Path::new("/buzzci.slice/buzzci-lease01.slice")
        );
    }

    #[test]
    fn systemd_namespace_or_nft_drift_quarantines_before_release() {
        let plan = DnsHostPlan::new(isolation_plan()).unwrap();
        let adapter = DnsHostAdapter::new(plan.clone());

        let mut systemd = FakeBackend::ready(&plan);
        systemd.observation.as_mut().unwrap().isolation.units[0]
            .properties
            .insert("PrivateNetwork".to_owned(), "yes".to_owned());
        let result = adapter.apply(&mut systemd).unwrap();
        assert_eq!(result.disposition, DnsHostDisposition::Quarantined);
        assert!(!result.released());
        assert_eq!(systemd.quarantine.len(), 1);

        let mut namespace = FakeBackend::ready(&plan);
        namespace.observation.as_mut().unwrap().namespace.path =
            PathBuf::from("/run/netns/buzzci-other");
        let result = adapter.apply(&mut namespace).unwrap();
        assert_eq!(result.disposition, DnsHostDisposition::Quarantined);
        assert!(result
            .readback
            .mismatches
            .iter()
            .any(|mismatch| mismatch.field == "dns_host.namespace"));

        let mut nft = FakeBackend::ready(&plan);
        nft.observation
            .as_mut()
            .unwrap()
            .materializer_policy
            .unmatched_traffic_denied = false;
        let result = adapter.apply(&mut nft).unwrap();
        assert_eq!(result.disposition, DnsHostDisposition::Quarantined);
        assert!(result
            .readback
            .mismatches
            .iter()
            .any(|mismatch| mismatch.field == "dns_host.materializer_policy"));
    }

    #[test]
    fn failed_observation_or_quarantine_never_releases() {
        let plan = DnsHostPlan::new(isolation_plan()).unwrap();
        let adapter = DnsHostAdapter::new(plan.clone());
        let mut observed = FakeBackend::ready(&plan);
        observed.fail_observation = true;
        assert!(matches!(
            adapter.apply(&mut observed),
            Err(DnsHostApplyError::ObservationFailedQuarantined { .. })
        ));
        assert_eq!(observed.quarantine.len(), 1);

        let mut quarantine = FakeBackend::ready(&plan);
        quarantine.fail_action = Some(1);
        quarantine.fail_quarantine = true;
        assert!(matches!(
            adapter.apply(&mut quarantine),
            Err(DnsHostApplyError::ActionFailedQuarantineFailed { index: 1, .. })
        ));
    }

    #[test]
    fn arbitrary_paths_units_and_allowlists_are_rejected() {
        let mut namespace = isolation_plan();
        for unit in &mut namespace.units {
            if let UnitNetworkMode::BrokerNoEgressNamespace { path } = &mut unit.network_mode {
                *path = PathBuf::from("/run/netns/caller-selected");
                unit.properties.insert(
                    "NetworkNamespacePath".to_owned(),
                    "/run/netns/caller-selected".to_owned(),
                );
            }
        }
        assert_eq!(
            DnsHostPlan::new(namespace),
            Err(DnsHostPlanError::InvalidPrincipalProperties)
        );

        let mut unit = isolation_plan();
        unit.units[0].unit_name = "caller.service".to_owned();
        assert_eq!(
            DnsHostPlan::new(unit),
            Err(DnsHostPlanError::InvalidPrincipalIdentity)
        );

        let mut duplicate_uid = isolation_plan();
        let materializer_uid = duplicate_uid.units[0].uid;
        duplicate_uid.units[1].uid = materializer_uid;
        duplicate_uid.units[1]
            .properties
            .insert("User".to_owned(), materializer_uid.to_string());
        assert_eq!(
            DnsHostPlan::new(duplicate_uid),
            Err(DnsHostPlanError::InvalidPrincipalIdentity)
        );

        let mut allowlist = isolation_plan();
        let extra = tuple("203.0.113.50", 443);
        allowlist.materializer_allowlist.push(extra);
        let UnitNetworkMode::HostTupleAllowlist { tuples } = &mut allowlist.units[0].network_mode
        else {
            panic!("materializer must use the host allowlist");
        };
        tuples.push(extra);
        assert_eq!(
            DnsHostPlan::new(allowlist),
            Err(DnsHostPlanError::InvalidMaterializerAllowlist)
        );

        assert_eq!(
            DnsHostPlan::new(isolation_plan_with_file_root(
                "/var/lib/buzzci/activation/lease01"
            )),
            Err(DnsHostPlanError::InvalidDnsFilePath)
        );

        let lease_id = "lease01";
        let mut request_plan = isolation_plan();
        request_plan.lease_id = format!("{lease_id}/escape");
        assert_eq!(
            DnsHostPlan::new(request_plan),
            Err(DnsHostPlanError::InvalidLeaseId)
        );
    }
}
