//! Pure per-lease systemd and DNS isolation planning.
//!
//! This module performs no host I/O. A privileged adapter supplies broker
//! configuration and machine readbacks; this module builds the expected slice
//! and decides whether the lease stays quarantined.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// SHA-256 of an empty byte string.
pub const EMPTY_FILE_SHA256: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// All three principals must be unable to reach this directory.
pub const SYSTEMD_RESOLVE_RUNTIME_PATH: &str = "/run/systemd/resolve";

/// Fixed loopback CAS endpoint exposed to the materializer.
pub const CAS_LOOPBACK_ADDRESS: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);

/// Fixed loopback CAS port exposed to the materializer.
pub const CAS_LOOPBACK_PORT: u16 = 38_445;

/// Phase 1 admits the relay, mirror, and loopback CAS tuples only.
pub const APPROVED_TUPLE_COUNT: usize = 3;

/// Fixed root slice which owns all per-lease slices.
pub const BUZZCI_ROOT_SLICE: &str = "buzzci.slice";

/// Fixed cgroup-v2 path for [`BUZZCI_ROOT_SLICE`].
pub const BUZZCI_ROOT_CGROUP_PATH: &str = "/buzzci.slice";

const BROKER_FILE_OWNER_UID: u32 = 0;
const BROKER_FILE_OWNER_GID: u32 = 0;
const BROKER_FILE_MODE: u32 = 0o444;
const BROKER_FILE_LINK_COUNT: u64 = 1;

const LEASE_SLICE_RESOURCE_PROPERTY_NAMES: [&str; 6] = [
    "CPUQuotaPerSecUSec",
    "CPUWeight",
    "IOWeight",
    "MemoryMax",
    "MemorySwapMax",
    "TasksMax",
];
const PRINCIPAL_PROPERTY_NAMES: [&str; 8] = [
    "BindReadOnlyPaths",
    "InaccessiblePaths",
    "NetworkNamespacePath",
    "PrivateNetwork",
    "RuntimeDirectory",
    "RuntimeDirectoryMode",
    "Slice",
    "User",
];

/// One of the three fixed per-slot principals.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalRole {
    Materializer,
    Executor,
    Runtime,
}

/// Fedora/systemd property proven by the three-UID delegation canary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkNamespaceProperty {
    NetworkNamespacePath,
}

impl NetworkNamespaceProperty {
    fn systemd_name(self) -> &'static str {
        match self {
            Self::NetworkNamespacePath => "NetworkNamespacePath",
        }
    }
}

/// Fixed cgroup-v2 properties placed on the per-lease slice.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UnitResources {
    pub cpu_weight: u16,
    pub memory_max_bytes: u64,
    pub tasks_max: u32,
    pub io_weight: u16,
    /// Hard CPU bandwidth in microseconds per one-second period.
    pub cpu_quota_per_sec_usec: u64,
}

/// Exact broker-created per-lease slice identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseSliceIdentity {
    pub unit_name: String,
    pub cgroup_path: PathBuf,
}

/// Exact transient service identity allocated for one principal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalUnitIdentity {
    pub role: PrincipalRole,
    pub uid: u32,
    pub unit_name: String,
    pub cgroup_path: PathBuf,
}

/// Result of the root-run Fedora delegation canary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationCanaryReadback {
    pub fedora_release: String,
    pub systemd_version: String,
    pub property: NetworkNamespaceProperty,
    pub namespace_path: PathBuf,
    /// Exact UID to successful namespace-join result mapping.
    pub uid_results: BTreeMap<u32, bool>,
}

/// Broker-owned file pinned into each principal unit.
///
/// Construction compiles the root authority and readable file invariants into
/// the plan. Callers supply only the requested path and expected content hash.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BrokerPinnedFile {
    requested_path: PathBuf,
    canonical_path: PathBuf,
    owner_uid: u32,
    owner_gid: u32,
    mode: u32,
    file_type: BrokerFileType,
    type_checked_no_follow: bool,
    link_count: u64,
    sha256: String,
}

impl BrokerPinnedFile {
    /// Bind a requested absolute path and expected digest to the compiled root
    /// file authority.
    pub fn new(path: PathBuf, sha256: String) -> Result<Self, IsolationPlanError> {
        if !safe_absolute_path(&path) || !valid_sha256(&sha256) {
            return Err(IsolationPlanError::invalid(
                "dns_files",
                "file paths must be absolute and hashes must be lowercase SHA-256",
            ));
        }
        Ok(Self {
            canonical_path: path.clone(),
            requested_path: path,
            owner_uid: BROKER_FILE_OWNER_UID,
            owner_gid: BROKER_FILE_OWNER_GID,
            mode: BROKER_FILE_MODE,
            file_type: BrokerFileType::Regular,
            type_checked_no_follow: true,
            link_count: BROKER_FILE_LINK_COUNT,
            sha256,
        })
    }

    /// Return the source path bound into the unit.
    pub fn requested_path(&self) -> &Path {
        &self.requested_path
    }

    /// Return the pinned content digest.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

/// File type reported by no-follow metadata inspection.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerFileType {
    Regular,
    Symlink,
    Other,
}

/// TLS service represented in the broker-pinned hosts file.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PinnedServiceKind {
    Relay,
    Mirror,
}

/// One hosts-file entry retained only when its service needs SNI.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SniHostPin {
    pub service: PinnedServiceKind,
    pub hostname: String,
    pub addresses: Vec<IpAddr>,
}

/// Broker-pinned resolver and hosts files.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DnsFiles {
    pub resolv_conf: BrokerPinnedFile,
    pub hosts: BrokerPinnedFile,
    pub sni_host_pins: Vec<SniHostPin>,
}

/// One TCP `addr . inet_service` tuple.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TcpServiceTuple {
    pub address: IpAddr,
    pub port: u16,
}

/// Broker-qualified relay and mirror destinations.
///
/// The fields are private so a lease request cannot supply an arbitrary set of
/// three tuples. The constructor accepts one relay and one mirror endpoint and
/// adds the fixed loopback CAS tuple itself.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BrokerApprovedMaterializerNetwork {
    relay: TcpServiceTuple,
    mirror: TcpServiceTuple,
}

impl BrokerApprovedMaterializerNetwork {
    /// Qualify the broker-configured relay and mirror HTTPS endpoints.
    pub fn new(
        relay: TcpServiceTuple,
        mirror: TcpServiceTuple,
    ) -> Result<Self, IsolationPlanError> {
        if relay.port != 443
            || mirror.port != 443
            || unusable_external_address(relay.address)
            || unusable_external_address(mirror.address)
            || relay == mirror
        {
            return Err(IsolationPlanError::invalid(
                "approved_materializer_network",
                "requires distinct usable relay:443 and mirror:443 endpoints",
            ));
        }
        Ok(Self { relay, mirror })
    }

    /// Return the exact relay, mirror, and fixed loopback CAS tuples.
    pub fn tuples(&self) -> Vec<TcpServiceTuple> {
        vec![self.relay, self.mirror, cas_loopback_tuple()]
    }

    fn tuple_for(&self, service: PinnedServiceKind) -> TcpServiceTuple {
        match service {
            PinnedServiceKind::Relay => self.relay,
            PinnedServiceKind::Mirror => self.mirror,
        }
    }
}

/// Complete pure input for one lease slice and its three principal services.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LeaseIsolationRequest {
    pub lease_id: String,
    pub resources: UnitResources,
    pub lease_slice: LeaseSliceIdentity,
    pub units: Vec<PrincipalUnitIdentity>,
    pub delegation_canary: DelegationCanaryReadback,
    pub dns_files: DnsFiles,
    pub approved_materializer_network: BrokerApprovedMaterializerNetwork,
}

/// Network placement expected for one principal service.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum UnitNetworkMode {
    HostTupleAllowlist { tuples: Vec<TcpServiceTuple> },
    BrokerNoEgressNamespace { path: PathBuf },
}

/// Expected per-lease slice and resource properties.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LeaseSlicePlan {
    pub unit_name: String,
    pub cgroup_path: PathBuf,
    pub properties: BTreeMap<String, String>,
}

/// Exact principal-service plan that a host adapter must apply and read back.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TransientUnitPlan {
    pub role: PrincipalRole,
    pub uid: u32,
    pub unit_name: String,
    pub cgroup_path: PathBuf,
    pub properties: BTreeMap<String, String>,
    pub network_mode: UnitNetworkMode,
}

/// Validated per-lease slice, principal-service, and DNS plan.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LeaseIsolationPlan {
    pub lease_id: String,
    /// The broker-created slice named in `lease.json` and used as the kill target.
    pub lease_unit: String,
    pub cgroup_path: PathBuf,
    pub lease_slice: LeaseSlicePlan,
    pub units: Vec<TransientUnitPlan>,
    pub dns_files: DnsFiles,
    pub materializer_allowlist: Vec<TcpServiceTuple>,
}

/// Machine-collected per-lease slice readback.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseSliceReadback {
    pub unit_name: String,
    pub cgroup_path: PathBuf,
    pub properties: BTreeMap<String, String>,
}

/// Machine-collected principal-service readback.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransientUnitReadback {
    pub role: PrincipalRole,
    pub uid: u32,
    pub unit_name: String,
    pub cgroup_path: PathBuf,
    pub properties: BTreeMap<String, String>,
    pub network_mode: UnitNetworkMode,
}

/// Broker readback for one pinned file.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerPinnedFileReadback {
    pub requested_path: PathBuf,
    pub canonical_path: PathBuf,
    pub owner_uid: u32,
    pub owner_gid: u32,
    pub mode: u32,
    pub file_type: BrokerFileType,
    pub type_checked_no_follow: bool,
    pub link_count: u64,
    pub sha256: String,
}

/// Broker readback for both DNS files.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DnsFilesReadback {
    pub resolv_conf: BrokerPinnedFileReadback,
    pub hosts: BrokerPinnedFileReadback,
}

/// Result of one `hosts: files` lookup.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FilesLookupProbe {
    pub hostname: String,
    pub addresses: Vec<IpAddr>,
    pub resolved_by_files: bool,
}

/// All DNS-negative observations for one principal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalDnsObservation {
    pub role: PrincipalRole,
    pub files_lookups: Vec<FilesLookupProbe>,
    pub arbitrary_getent_succeeded: bool,
    pub resolved_varlink_accessible: bool,
    pub direct_udp_53_connected: bool,
    pub direct_tcp_53_connected: bool,
}

/// One functional materializer TCP connection probe.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TupleConnectProbe {
    pub role: PrincipalRole,
    pub tuple: TcpServiceTuple,
    pub connected: bool,
}

/// Raw observations collected by the root-owned broker adapter.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseIsolationObservation {
    pub lease_slice: LeaseSliceReadback,
    pub units: Vec<TransientUnitReadback>,
    pub dns_files: DnsFilesReadback,
    pub principal_dns: Vec<PrincipalDnsObservation>,
    pub effective_materializer_allowlist: Vec<TcpServiceTuple>,
    pub tuple_connect_probes: Vec<TupleConnectProbe>,
}

/// Stable five-proof object consumed by TM-09 from `lease.json`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DnsReadback {
    pub files_lookup_ok: bool,
    pub arbitrary_getent_refused: bool,
    pub resolved_varlink_inaccessible: bool,
    pub direct_53_refused: bool,
    pub allowed_tuples_only: bool,
}

/// One exact mismatch that keeps the lease quarantined.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IsolationMismatch {
    pub field: String,
    pub expected: String,
    pub observed: String,
}

/// Fail-closed result stored beside the lease.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseIsolationReadback {
    pub lease_id: String,
    pub lease_unit: String,
    pub cgroup_path: PathBuf,
    pub resource_properties: BTreeMap<String, String>,
    pub network_properties: BTreeMap<PrincipalRole, BTreeMap<String, String>>,
    pub lease_slice_readback: LeaseSliceReadback,
    pub unit_readback: Vec<TransientUnitReadback>,
    pub broker_file_readback: DnsFilesReadback,
    pub principal_dns_readback: Vec<PrincipalDnsObservation>,
    pub dns_readback: DnsReadback,
    pub mismatches: Vec<IsolationMismatch>,
    pub quarantined: bool,
    pub teardown_attestation_allowed: bool,
    pub capacity_restoration_allowed: bool,
}

/// Invalid input to the pure builder.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum IsolationPlanError {
    #[error("invalid lease isolation field {field}: {reason}")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
}

impl IsolationPlanError {
    fn invalid(field: &'static str, reason: &'static str) -> Self {
        Self::InvalidField { field, reason }
    }
}

/// Build the exact per-lease slice and three principal-service plans.
pub fn build_lease_isolation_plan(
    request: LeaseIsolationRequest,
) -> Result<LeaseIsolationPlan, IsolationPlanError> {
    validate_request(&request)?;

    let allowlist = request.approved_materializer_network.tuples();
    let slice_properties = BTreeMap::from([
        (
            "CPUQuotaPerSecUSec".to_owned(),
            request.resources.cpu_quota_per_sec_usec.to_string(),
        ),
        (
            "CPUWeight".to_owned(),
            request.resources.cpu_weight.to_string(),
        ),
        (
            "IOWeight".to_owned(),
            request.resources.io_weight.to_string(),
        ),
        (
            "MemoryMax".to_owned(),
            request.resources.memory_max_bytes.to_string(),
        ),
        ("MemorySwapMax".to_owned(), "0".to_owned()),
        (
            "TasksMax".to_owned(),
            request.resources.tasks_max.to_string(),
        ),
    ]);
    let lease_slice = LeaseSlicePlan {
        unit_name: request.lease_slice.unit_name.clone(),
        cgroup_path: request.lease_slice.cgroup_path.clone(),
        properties: slice_properties,
    };

    let bind_files = format!(
        "{}:/etc/resolv.conf {}:/etc/hosts",
        request.dns_files.resolv_conf.requested_path().display(),
        request.dns_files.hosts.requested_path().display()
    );
    let mut identities = request.units.clone();
    identities.sort_by_key(|unit| unit.role);
    let mut units = Vec::with_capacity(identities.len());
    for unit in identities {
        let mut properties = BTreeMap::from([
            ("BindReadOnlyPaths".to_owned(), bind_files.clone()),
            (
                "InaccessiblePaths".to_owned(),
                SYSTEMD_RESOLVE_RUNTIME_PATH.to_owned(),
            ),
            ("Slice".to_owned(), request.lease_slice.unit_name.clone()),
            ("User".to_owned(), unit.uid.to_string()),
        ]);
        let network_mode = if unit.role == PrincipalRole::Materializer {
            properties.insert("PrivateNetwork".to_owned(), "no".to_owned());
            properties.insert(
                "RuntimeDirectory".to_owned(),
                unit.unit_name.trim_end_matches(".service").to_owned(),
            );
            properties.insert("RuntimeDirectoryMode".to_owned(), "0700".to_owned());
            UnitNetworkMode::HostTupleAllowlist {
                tuples: allowlist.clone(),
            }
        } else {
            properties.insert(
                request.delegation_canary.property.systemd_name().to_owned(),
                request
                    .delegation_canary
                    .namespace_path
                    .display()
                    .to_string(),
            );
            UnitNetworkMode::BrokerNoEgressNamespace {
                path: request.delegation_canary.namespace_path.clone(),
            }
        };
        units.push(TransientUnitPlan {
            role: unit.role,
            uid: unit.uid,
            unit_name: unit.unit_name,
            cgroup_path: unit.cgroup_path,
            properties,
            network_mode,
        });
    }

    Ok(LeaseIsolationPlan {
        lease_id: request.lease_id,
        lease_unit: request.lease_slice.unit_name,
        cgroup_path: request.lease_slice.cgroup_path,
        lease_slice,
        units,
        dns_files: request.dns_files,
        materializer_allowlist: allowlist,
    })
}

/// Verify the complete slice, service, file, network, and DNS readback.
///
/// Any mismatch blocks teardown attestation and capacity restoration.
pub fn verify_lease_isolation(
    plan: &LeaseIsolationPlan,
    observation: LeaseIsolationObservation,
) -> LeaseIsolationReadback {
    let mut mismatches = Vec::new();
    compare_lease_slice(plan, &observation.lease_slice, &mut mismatches);
    compare_units(plan, &observation.units, &mut mismatches);
    compare_dns_files(plan, &observation.dns_files, &mut mismatches);

    let principal_set_complete = exact_principal_set(&observation.principal_dns);
    if !principal_set_complete {
        mismatches.push(IsolationMismatch {
            field: "principal_dns_readback.roles".to_owned(),
            expected: format!("{:?}", all_roles()),
            observed: format!(
                "{:?}",
                observation
                    .principal_dns
                    .iter()
                    .map(|proof| proof.role)
                    .collect::<Vec<_>>()
            ),
        });
    }

    let dns_readback = DnsReadback {
        files_lookup_ok: principal_set_complete
            && files_lookup_ok(&plan.dns_files, &observation.principal_dns),
        arbitrary_getent_refused: principal_set_complete
            && observation
                .principal_dns
                .iter()
                .all(|proof| !proof.arbitrary_getent_succeeded),
        resolved_varlink_inaccessible: principal_set_complete
            && observation
                .principal_dns
                .iter()
                .all(|proof| !proof.resolved_varlink_accessible),
        direct_53_refused: principal_set_complete
            && observation
                .principal_dns
                .iter()
                .all(|proof| !proof.direct_udp_53_connected && !proof.direct_tcp_53_connected),
        allowed_tuples_only: principal_set_complete
            && allowed_tuples_only(
                &plan.materializer_allowlist,
                &observation.effective_materializer_allowlist,
                &observation.tuple_connect_probes,
            ),
    };
    append_dns_mismatches(dns_readback, &mut mismatches);

    let quarantined = !mismatches.is_empty();
    let resource_properties = selected_slice_properties(&observation.lease_slice);
    let network_properties = selected_network_properties(&observation.units);
    LeaseIsolationReadback {
        lease_id: plan.lease_id.clone(),
        lease_unit: plan.lease_unit.clone(),
        cgroup_path: plan.cgroup_path.clone(),
        resource_properties,
        network_properties,
        lease_slice_readback: observation.lease_slice,
        unit_readback: observation.units,
        broker_file_readback: observation.dns_files,
        principal_dns_readback: observation.principal_dns,
        dns_readback,
        mismatches,
        quarantined,
        teardown_attestation_allowed: !quarantined,
        capacity_restoration_allowed: !quarantined,
    }
}

fn append_dns_mismatches(readback: DnsReadback, mismatches: &mut Vec<IsolationMismatch>) {
    for (field, passed) in [
        ("dns_readback.files_lookup_ok", readback.files_lookup_ok),
        (
            "dns_readback.arbitrary_getent_refused",
            readback.arbitrary_getent_refused,
        ),
        (
            "dns_readback.resolved_varlink_inaccessible",
            readback.resolved_varlink_inaccessible,
        ),
        ("dns_readback.direct_53_refused", readback.direct_53_refused),
        (
            "dns_readback.allowed_tuples_only",
            readback.allowed_tuples_only,
        ),
    ] {
        if !passed {
            mismatches.push(IsolationMismatch {
                field: field.to_owned(),
                expected: "true".to_owned(),
                observed: "false".to_owned(),
            });
        }
    }
}

fn selected_slice_properties(slice: &LeaseSliceReadback) -> BTreeMap<String, String> {
    slice
        .properties
        .iter()
        .filter(|(name, _)| LEASE_SLICE_RESOURCE_PROPERTY_NAMES.contains(&name.as_str()))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

fn selected_network_properties(
    units: &[TransientUnitReadback],
) -> BTreeMap<PrincipalRole, BTreeMap<String, String>> {
    units
        .iter()
        .map(|unit| {
            let properties = unit
                .properties
                .iter()
                .filter(|(name, _)| PRINCIPAL_PROPERTY_NAMES.contains(&name.as_str()))
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect();
            (unit.role, properties)
        })
        .collect()
}

fn validate_request(request: &LeaseIsolationRequest) -> Result<(), IsolationPlanError> {
    if !safe_lease_id(&request.lease_id) {
        return Err(IsolationPlanError::invalid(
            "lease_id",
            "must be a bounded ASCII alphanumeric or underscore token",
        ));
    }
    validate_resources(request.resources)?;
    validate_lease_slice(&request.lease_id, &request.lease_slice)?;
    validate_units(&request.lease_slice, &request.units)?;
    validate_canary(&request.units, &request.delegation_canary)?;
    validate_dns_files(&request.dns_files, &request.approved_materializer_network)?;
    Ok(())
}

fn validate_resources(resources: UnitResources) -> Result<(), IsolationPlanError> {
    if !(1..=10_000).contains(&resources.cpu_weight)
        || !(1..=10_000).contains(&resources.io_weight)
        || resources.memory_max_bytes == 0
        || resources.tasks_max == 0
        || resources.cpu_quota_per_sec_usec == 0
    {
        return Err(IsolationPlanError::invalid(
            "resources",
            "weights must be bounded and every hard limit must be non-zero",
        ));
    }
    Ok(())
}

fn validate_lease_slice(
    lease_id: &str,
    lease_slice: &LeaseSliceIdentity,
) -> Result<(), IsolationPlanError> {
    let expected_name = format!("buzzci-{lease_id}.slice");
    let expected_path = Path::new(BUZZCI_ROOT_CGROUP_PATH).join(&expected_name);
    if lease_slice.unit_name != expected_name
        || !safe_lease_slice_name(&lease_slice.unit_name)
        || !safe_absolute_path(&lease_slice.cgroup_path)
        || lease_slice.cgroup_path != expected_path
    {
        return Err(IsolationPlanError::invalid(
            "lease_slice",
            "must be the exact per-lease .slice directly under buzzci.slice",
        ));
    }
    Ok(())
}

fn validate_units(
    lease_slice: &LeaseSliceIdentity,
    units: &[PrincipalUnitIdentity],
) -> Result<(), IsolationPlanError> {
    let roles = units.iter().map(|unit| unit.role).collect::<BTreeSet<_>>();
    let uids = units.iter().map(|unit| unit.uid).collect::<BTreeSet<_>>();
    let names = units
        .iter()
        .map(|unit| unit.unit_name.as_str())
        .collect::<BTreeSet<_>>();
    if units.len() != 3
        || roles.len() != 3
        || uids.len() != 3
        || names.len() != 3
        || uids.contains(&0)
    {
        return Err(IsolationPlanError::invalid(
            "units",
            "must contain exactly three distinct service names, non-root UIDs, and roles",
        ));
    }
    for unit in units {
        if !safe_service_name(&unit.unit_name)
            || !safe_absolute_path(&unit.cgroup_path)
            || unit.cgroup_path.parent() != Some(lease_slice.cgroup_path.as_path())
            || unit.cgroup_path.file_name().and_then(|name| name.to_str())
                != Some(unit.unit_name.as_str())
        {
            return Err(IsolationPlanError::invalid(
                "units",
                "every principal must be a distinct .service directly under the lease slice",
            ));
        }
    }
    Ok(())
}

fn validate_canary(
    units: &[PrincipalUnitIdentity],
    canary: &DelegationCanaryReadback,
) -> Result<(), IsolationPlanError> {
    if !safe_token(&canary.fedora_release, 64)
        || !safe_token(&canary.systemd_version, 64)
        || !safe_absolute_path(&canary.namespace_path)
        || !canary.namespace_path.starts_with("/run/netns")
    {
        return Err(IsolationPlanError::invalid(
            "delegation_canary",
            "must identify Fedora, systemd, and a broker namespace under /run/netns",
        ));
    }
    let expected = units.iter().map(|unit| unit.uid).collect::<BTreeSet<_>>();
    let observed = canary.uid_results.keys().copied().collect::<BTreeSet<_>>();
    if observed != expected || canary.uid_results.values().any(|passed| !passed) {
        return Err(IsolationPlanError::invalid(
            "delegation_canary.uid_results",
            "the chosen property must pass for exactly the three lease UIDs",
        ));
    }
    Ok(())
}

fn validate_dns_files(
    files: &DnsFiles,
    network: &BrokerApprovedMaterializerNetwork,
) -> Result<(), IsolationPlanError> {
    for file in [&files.resolv_conf, &files.hosts] {
        if file.owner_uid != BROKER_FILE_OWNER_UID
            || file.owner_gid != BROKER_FILE_OWNER_GID
            || file.mode != BROKER_FILE_MODE
            || file.file_type != BrokerFileType::Regular
            || !file.type_checked_no_follow
            || file.link_count != BROKER_FILE_LINK_COUNT
            || file.canonical_path != file.requested_path
            || !safe_absolute_path(&file.requested_path)
            || !valid_sha256(&file.sha256)
        {
            return Err(IsolationPlanError::invalid(
                "dns_files",
                "files must retain the compiled root-readable no-follow identity",
            ));
        }
    }
    if files.resolv_conf.sha256 != EMPTY_FILE_SHA256 {
        return Err(IsolationPlanError::invalid(
            "dns_files.resolv_conf",
            "resolv.conf must be the pinned empty file",
        ));
    }
    if files.sni_host_pins.is_empty() {
        if files.hosts.sha256 != EMPTY_FILE_SHA256 {
            return Err(IsolationPlanError::invalid(
                "dns_files.hosts",
                "a hosts file without SNI pins must be the pinned empty file",
            ));
        }
        return Ok(());
    }
    if files.hosts.sha256 == EMPTY_FILE_SHA256 || files.sni_host_pins.len() != 2 {
        return Err(IsolationPlanError::invalid(
            "dns_files.sni_host_pins",
            "a non-empty hosts file requires exactly one relay and one mirror pin",
        ));
    }
    let services = files
        .sni_host_pins
        .iter()
        .map(|pin| pin.service)
        .collect::<BTreeSet<_>>();
    if services != BTreeSet::from([PinnedServiceKind::Relay, PinnedServiceKind::Mirror]) {
        return Err(IsolationPlanError::invalid(
            "dns_files.sni_host_pins",
            "a non-empty hosts file requires exact relay and mirror pins",
        ));
    }
    let mut hostnames = BTreeSet::new();
    for pin in &files.sni_host_pins {
        if !safe_hostname(&pin.hostname)
            || !hostnames.insert(pin.hostname.clone())
            || pin.addresses.len() != 1
            || pin.addresses[0] != network.tuple_for(pin.service).address
        {
            return Err(IsolationPlanError::invalid(
                "dns_files.sni_host_pins",
                "pins must uniquely bind each service name to its approved address",
            ));
        }
    }
    Ok(())
}

fn compare_lease_slice(
    plan: &LeaseIsolationPlan,
    observed: &LeaseSliceReadback,
    mismatches: &mut Vec<IsolationMismatch>,
) {
    compare(
        "lease_slice_readback.unit_name".to_owned(),
        &plan.lease_slice.unit_name,
        &observed.unit_name,
        mismatches,
    );
    compare(
        "lease_slice_readback.cgroup_path".to_owned(),
        &plan.lease_slice.cgroup_path,
        &observed.cgroup_path,
        mismatches,
    );
    compare(
        "lease_slice_readback.properties".to_owned(),
        &plan.lease_slice.properties,
        &observed.properties,
        mismatches,
    );
}

fn compare_units(
    plan: &LeaseIsolationPlan,
    observed: &[TransientUnitReadback],
    mismatches: &mut Vec<IsolationMismatch>,
) {
    let expected_roles = all_roles();
    let observed_roles = observed
        .iter()
        .map(|unit| unit.role)
        .collect::<BTreeSet<_>>();
    if observed.len() != 3 || observed_roles != expected_roles {
        mismatches.push(IsolationMismatch {
            field: "unit_readback.roles".to_owned(),
            expected: format!("{expected_roles:?}"),
            observed: format!("{observed_roles:?}"),
        });
        return;
    }
    for expected in &plan.units {
        let Some(actual) = observed.iter().find(|unit| unit.role == expected.role) else {
            continue;
        };
        compare(
            role_field(expected.role, "uid"),
            expected.uid,
            actual.uid,
            mismatches,
        );
        compare(
            role_field(expected.role, "unit_name"),
            &expected.unit_name,
            &actual.unit_name,
            mismatches,
        );
        compare(
            role_field(expected.role, "cgroup_path"),
            &expected.cgroup_path,
            &actual.cgroup_path,
            mismatches,
        );
        compare(
            role_field(expected.role, "properties"),
            &expected.properties,
            &actual.properties,
            mismatches,
        );
        compare(
            role_field(expected.role, "network_mode"),
            &expected.network_mode,
            &actual.network_mode,
            mismatches,
        );
    }
}

fn compare_dns_files(
    plan: &LeaseIsolationPlan,
    observed: &DnsFilesReadback,
    mismatches: &mut Vec<IsolationMismatch>,
) {
    compare_file(
        "broker_file_readback.resolv_conf",
        &plan.dns_files.resolv_conf,
        &observed.resolv_conf,
        mismatches,
    );
    compare_file(
        "broker_file_readback.hosts",
        &plan.dns_files.hosts,
        &observed.hosts,
        mismatches,
    );
}

fn compare_file(
    field: &str,
    expected: &BrokerPinnedFile,
    observed: &BrokerPinnedFileReadback,
    mismatches: &mut Vec<IsolationMismatch>,
) {
    let exact = observed.requested_path == expected.requested_path
        && observed.canonical_path == expected.canonical_path
        && observed.owner_uid == expected.owner_uid
        && observed.owner_gid == expected.owner_gid
        && observed.mode == expected.mode
        && observed.file_type == expected.file_type
        && observed.type_checked_no_follow == expected.type_checked_no_follow
        && observed.link_count == expected.link_count
        && observed.sha256 == expected.sha256;
    if !exact {
        mismatches.push(IsolationMismatch {
            field: field.to_owned(),
            expected: format!(
                "requested={:?},canonical={:?},uid={},gid={},mode={:o},type={:?},nofollow={},links={},sha256={}",
                expected.requested_path,
                expected.canonical_path,
                expected.owner_uid,
                expected.owner_gid,
                expected.mode,
                expected.file_type,
                expected.type_checked_no_follow,
                expected.link_count,
                expected.sha256
            ),
            observed: format!(
                "requested={:?},canonical={:?},uid={},gid={},mode={:o},type={:?},nofollow={},links={},sha256={}",
                observed.requested_path,
                observed.canonical_path,
                observed.owner_uid,
                observed.owner_gid,
                observed.mode,
                observed.file_type,
                observed.type_checked_no_follow,
                observed.link_count,
                observed.sha256
            ),
        });
    }
}

fn compare<T: std::fmt::Debug + PartialEq>(
    field: String,
    expected: T,
    observed: T,
    mismatches: &mut Vec<IsolationMismatch>,
) {
    if expected != observed {
        mismatches.push(IsolationMismatch {
            field,
            expected: format!("{expected:?}"),
            observed: format!("{observed:?}"),
        });
    }
}

fn files_lookup_ok(files: &DnsFiles, proofs: &[PrincipalDnsObservation]) -> bool {
    proofs.iter().all(|proof| match proof.role {
        PrincipalRole::Materializer => exact_files_lookups(&files.sni_host_pins, proof),
        PrincipalRole::Executor | PrincipalRole::Runtime => proof.files_lookups.is_empty(),
    })
}

fn exact_files_lookups(expected: &[SniHostPin], proof: &PrincipalDnsObservation) -> bool {
    if proof.files_lookups.len() != expected.len() {
        return false;
    }
    expected.iter().all(|pin| {
        let Some(observed) = proof
            .files_lookups
            .iter()
            .find(|lookup| lookup.hostname == pin.hostname)
        else {
            return false;
        };
        observed.resolved_by_files
            && observed.addresses.iter().copied().collect::<BTreeSet<_>>()
                == pin.addresses.iter().copied().collect::<BTreeSet<_>>()
    })
}

fn allowed_tuples_only(
    expected: &[TcpServiceTuple],
    effective: &[TcpServiceTuple],
    probes: &[TupleConnectProbe],
) -> bool {
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    let effective_set = effective.iter().copied().collect::<BTreeSet<_>>();
    let probed = probes
        .iter()
        .map(|probe| probe.tuple)
        .collect::<BTreeSet<_>>();
    let connected = probes
        .iter()
        .filter(|probe| probe.connected)
        .map(|probe| probe.tuple)
        .collect::<BTreeSet<_>>();
    let denied_controls = probed.difference(&expected).count();
    effective_set == expected
        && effective.len() == APPROVED_TUPLE_COUNT
        && effective_set.len() == APPROVED_TUPLE_COUNT
        && probes
            .iter()
            .all(|probe| probe.role == PrincipalRole::Materializer)
        && probes.len() == probed.len()
        && expected.is_subset(&probed)
        && connected == expected
        && denied_controls == 1
}

fn exact_principal_set(proofs: &[PrincipalDnsObservation]) -> bool {
    proofs.len() == 3
        && proofs
            .iter()
            .map(|proof| proof.role)
            .collect::<BTreeSet<_>>()
            == all_roles()
}

fn all_roles() -> BTreeSet<PrincipalRole> {
    BTreeSet::from([
        PrincipalRole::Materializer,
        PrincipalRole::Executor,
        PrincipalRole::Runtime,
    ])
}

fn role_field(role: PrincipalRole, suffix: &str) -> String {
    format!("unit_readback.{role:?}.{suffix}").to_lowercase()
}

fn cas_loopback_tuple() -> TcpServiceTuple {
    TcpServiceTuple {
        address: IpAddr::V4(CAS_LOOPBACK_ADDRESS),
        port: CAS_LOOPBACK_PORT,
    }
}

fn safe_token(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn safe_lease_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn safe_lease_slice_name(value: &str) -> bool {
    value.starts_with("buzzci-")
        && value.ends_with(".slice")
        && value.matches('-').count() == 1
        && safe_token(value, 255)
}

fn safe_service_name(value: &str) -> bool {
    value.ends_with(".service") && safe_token(value, 255)
}

fn safe_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path.components().all(|component| {
            matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
        && path.to_str().is_some_and(|value| {
            !value
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        })
}

fn safe_hostname(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn unusable_external_address(address: IpAddr) -> bool {
    address.is_unspecified() || address.is_loopback() || address.is_multicast()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tuple(address: &str, port: u16) -> TcpServiceTuple {
        TcpServiceTuple {
            address: address.parse().unwrap(),
            port,
        }
    }

    fn approved_network() -> BrokerApprovedMaterializerNetwork {
        BrokerApprovedMaterializerNetwork::new(
            tuple("198.51.100.10", 443),
            tuple("2001:db8::20", 443),
        )
        .unwrap()
    }

    fn request() -> LeaseIsolationRequest {
        let lease_slice = LeaseSliceIdentity {
            unit_name: "buzzci-lease01.slice".to_owned(),
            cgroup_path: PathBuf::from("/buzzci.slice/buzzci-lease01.slice"),
        };
        let units = [
            (PrincipalRole::Materializer, 966, "mat"),
            (PrincipalRole::Executor, 965, "exec"),
            (PrincipalRole::Runtime, 964, "run"),
        ]
        .into_iter()
        .map(|(role, uid, label)| PrincipalUnitIdentity {
            role,
            uid,
            unit_name: format!("buzzci-lease01-{label}.service"),
            cgroup_path: lease_slice
                .cgroup_path
                .join(format!("buzzci-lease01-{label}.service")),
        })
        .collect::<Vec<_>>();
        LeaseIsolationRequest {
            lease_id: "lease01".to_owned(),
            resources: UnitResources {
                cpu_weight: 100,
                memory_max_bytes: 2 * 1024 * 1024 * 1024,
                tasks_max: 512,
                io_weight: 100,
                cpu_quota_per_sec_usec: 200_000,
            },
            lease_slice,
            delegation_canary: DelegationCanaryReadback {
                fedora_release: "42".to_owned(),
                systemd_version: "257.7-1.fc42".to_owned(),
                property: NetworkNamespaceProperty::NetworkNamespacePath,
                namespace_path: PathBuf::from("/run/netns/buzzci-job01"),
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
                    "a".repeat(64),
                )
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
            approved_materializer_network: approved_network(),
            units,
        }
    }

    fn file_readback(file: &BrokerPinnedFile) -> BrokerPinnedFileReadback {
        BrokerPinnedFileReadback {
            requested_path: file.requested_path.clone(),
            canonical_path: file.canonical_path.clone(),
            owner_uid: file.owner_uid,
            owner_gid: file.owner_gid,
            mode: file.mode,
            file_type: file.file_type,
            type_checked_no_follow: file.type_checked_no_follow,
            link_count: file.link_count,
            sha256: file.sha256.clone(),
        }
    }

    fn observation(plan: &LeaseIsolationPlan) -> LeaseIsolationObservation {
        let lease_slice = LeaseSliceReadback {
            unit_name: plan.lease_slice.unit_name.clone(),
            cgroup_path: plan.lease_slice.cgroup_path.clone(),
            properties: plan.lease_slice.properties.clone(),
        };
        let units = plan
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
            .collect();
        let principal_dns = all_roles()
            .into_iter()
            .map(|role| PrincipalDnsObservation {
                role,
                files_lookups: if role == PrincipalRole::Materializer {
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
        LeaseIsolationObservation {
            lease_slice,
            units,
            dns_files: DnsFilesReadback {
                resolv_conf: file_readback(&plan.dns_files.resolv_conf),
                hosts: file_readback(&plan.dns_files.hosts),
            },
            principal_dns,
            effective_materializer_allowlist: plan.materializer_allowlist.clone(),
            tuple_connect_probes: plan
                .materializer_allowlist
                .iter()
                .copied()
                .map(|tuple| TupleConnectProbe {
                    role: PrincipalRole::Materializer,
                    tuple,
                    connected: true,
                })
                .chain([TupleConnectProbe {
                    role: PrincipalRole::Materializer,
                    tuple: tuple("203.0.113.99", 443),
                    connected: false,
                }])
                .collect(),
        }
    }

    #[test]
    fn builds_lease_slice_and_exact_principal_network_split() {
        let plan = build_lease_isolation_plan(request()).unwrap();
        assert_eq!(plan.lease_unit, "buzzci-lease01.slice");
        assert_eq!(
            plan.cgroup_path,
            PathBuf::from("/buzzci.slice/buzzci-lease01.slice")
        );
        let slice = &plan.lease_slice.properties;
        assert_eq!(
            slice,
            &BTreeMap::from([
                ("CPUQuotaPerSecUSec".to_owned(), "200000".to_owned()),
                ("CPUWeight".to_owned(), "100".to_owned()),
                ("IOWeight".to_owned(), "100".to_owned()),
                (
                    "MemoryMax".to_owned(),
                    (2_u64 * 1024 * 1024 * 1024).to_string()
                ),
                ("MemorySwapMax".to_owned(), "0".to_owned()),
                ("TasksMax".to_owned(), "512".to_owned()),
            ])
        );
        for unit in &plan.units {
            assert_eq!(unit.cgroup_path.parent(), Some(plan.cgroup_path.as_path()));
            assert!(unit.unit_name.ends_with(".service"));
            assert!(LEASE_SLICE_RESOURCE_PROPERTY_NAMES
                .iter()
                .all(|name| !unit.properties.contains_key(*name)));
            assert_eq!(
                unit.properties.get("Slice").map(String::as_str),
                Some("buzzci-lease01.slice")
            );
            assert_eq!(
                unit.properties.get("User").map(String::as_str),
                Some(unit.uid.to_string().as_str())
            );
            assert_eq!(
                unit.properties.get("InaccessiblePaths").map(String::as_str),
                Some(SYSTEMD_RESOLVE_RUNTIME_PATH)
            );
            match unit.role {
                PrincipalRole::Materializer => {
                    assert_eq!(unit.properties.get("PrivateNetwork").unwrap(), "no");
                    assert!(!unit.properties.contains_key("NetworkNamespacePath"));
                }
                PrincipalRole::Executor | PrincipalRole::Runtime => {
                    assert_eq!(
                        unit.properties.get("NetworkNamespacePath").unwrap(),
                        "/run/netns/buzzci-job01"
                    );
                    assert!(!unit.properties.contains_key("PrivateNetwork"));
                }
            }
        }
    }

    #[test]
    fn lease_unit_is_the_exact_slice_kill_target() {
        let plan = build_lease_isolation_plan(request()).unwrap();
        assert_eq!(plan.lease_unit, plan.lease_slice.unit_name);
        assert_eq!(plan.cgroup_path, plan.lease_slice.cgroup_path);
        assert_eq!(plan.lease_unit, "buzzci-lease01.slice");
        assert!(!plan.lease_unit.ends_with(".service"));
        assert!(!plan.lease_unit.ends_with(".scope"));
    }

    #[test]
    fn principal_service_names_and_uids_are_distinct() {
        let plan = build_lease_isolation_plan(request()).unwrap();
        assert_eq!(
            plan.units
                .iter()
                .map(|unit| unit.unit_name.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
            3
        );
        assert_eq!(
            plan.units
                .iter()
                .map(|unit| unit.uid)
                .collect::<BTreeSet<_>>()
                .len(),
            3
        );

        let mut duplicate_name = request();
        duplicate_name.units[1].unit_name = duplicate_name.units[0].unit_name.clone();
        duplicate_name.units[1].cgroup_path = duplicate_name.units[0].cgroup_path.clone();
        assert!(build_lease_isolation_plan(duplicate_name).is_err());

        let mut duplicate_uid = request();
        duplicate_uid.units[1].uid = duplicate_uid.units[0].uid;
        assert!(build_lease_isolation_plan(duplicate_uid).is_err());
    }

    #[test]
    fn exact_loopback_cas_tuple_is_approved() {
        let plan = build_lease_isolation_plan(request()).unwrap();
        assert_eq!(plan.materializer_allowlist.len(), APPROVED_TUPLE_COUNT);
        assert!(plan.materializer_allowlist.contains(&TcpServiceTuple {
            address: IpAddr::V4(CAS_LOOPBACK_ADDRESS),
            port: CAS_LOOPBACK_PORT,
        }));
    }

    #[test]
    fn arbitrary_tuple_configuration_is_rejected() {
        assert!(BrokerApprovedMaterializerNetwork::new(
            tuple("198.51.100.10", 444),
            tuple("2001:db8::20", 443)
        )
        .is_err());
        assert!(BrokerApprovedMaterializerNetwork::new(
            tuple("127.0.0.1", CAS_LOOPBACK_PORT),
            tuple("2001:db8::20", 443)
        )
        .is_err());
    }

    #[test]
    fn rejects_slice_or_service_path_traversal_and_wrong_membership() {
        let mut value = request();
        value.lease_slice.cgroup_path = PathBuf::from("/buzzci.slice/../escape.slice");
        assert!(build_lease_isolation_plan(value).is_err());

        let mut value = request();
        value.units[0].cgroup_path = PathBuf::from("/buzzci.slice/buzzci-lease01-mat.service");
        assert!(build_lease_isolation_plan(value).is_err());
    }

    #[test]
    fn rejects_scope_service_and_custom_root_supervisor_forms() {
        let mut scope = request();
        scope.lease_slice.unit_name = "buzzci-lease01.scope".to_owned();
        scope.lease_slice.cgroup_path = PathBuf::from("/buzzci.slice/buzzci-lease01.scope");
        assert!(build_lease_isolation_plan(scope).is_err());

        let mut service = request();
        service.lease_slice.unit_name = "buzzci-lease01.service".to_owned();
        service.lease_slice.cgroup_path = PathBuf::from("/buzzci.slice/buzzci-lease01.service");
        assert!(build_lease_isolation_plan(service).is_err());

        let mut custom_root = request();
        custom_root.lease_slice.cgroup_path = PathBuf::from("/custom.slice/buzzci-lease01.slice");
        assert!(build_lease_isolation_plan(custom_root).is_err());

        let mut scope_nested_service = request();
        scope_nested_service.units[0].cgroup_path = PathBuf::from(
            "/buzzci.slice/buzzci-lease01.slice/buzzci-supervisor.scope/buzzci-lease01-mat.service",
        );
        assert!(build_lease_isolation_plan(scope_nested_service).is_err());

        let mut service_nested_service = request();
        service_nested_service.units[0].cgroup_path = PathBuf::from(
            "/buzzci.slice/buzzci-lease01.slice/buzzci-supervisor.service/buzzci-lease01-mat.service",
        );
        assert!(build_lease_isolation_plan(service_nested_service).is_err());

        let mut scope_principal = request();
        scope_principal.units[0].unit_name = "buzzci-lease01-mat.scope".to_owned();
        scope_principal.units[0].cgroup_path = scope_principal
            .lease_slice
            .cgroup_path
            .join("buzzci-lease01-mat.scope");
        assert!(build_lease_isolation_plan(scope_principal).is_err());
    }

    #[test]
    fn empty_hosts_mode_requires_the_pinned_empty_file() {
        let mut value = request();
        value.dns_files.sni_host_pins.clear();
        value.dns_files.hosts = BrokerPinnedFile::new(
            PathBuf::from("/var/lib/buzzci/leases/lease01/hosts"),
            EMPTY_FILE_SHA256.to_owned(),
        )
        .unwrap();
        let plan = build_lease_isolation_plan(value).unwrap();
        let mut observed = observation(&plan);
        for proof in &mut observed.principal_dns {
            proof.files_lookups.clear();
        }
        let readback = verify_lease_isolation(&plan, observed);
        assert!(readback.dns_readback.files_lookup_ok);
        assert!(!readback.quarantined);

        let mut invalid = request();
        invalid.dns_files.sni_host_pins.clear();
        assert!(build_lease_isolation_plan(invalid).is_err());
    }

    #[test]
    fn canary_must_cover_exactly_the_three_principal_uids() {
        let mut value = request();
        value.delegation_canary.uid_results.remove(&966);
        assert!(build_lease_isolation_plan(value).is_err());
        let mut value = request();
        value.delegation_canary.uid_results.insert(1_000, true);
        assert!(build_lease_isolation_plan(value).is_err());
        let mut value = request();
        value.delegation_canary.uid_results.insert(965, false);
        assert!(build_lease_isolation_plan(value).is_err());
    }

    #[test]
    fn complete_readback_releases_quarantine_with_stable_json() {
        let plan = build_lease_isolation_plan(request()).unwrap();
        let readback = verify_lease_isolation(&plan, observation(&plan));
        assert!(!readback.quarantined);
        assert!(readback.teardown_attestation_allowed);
        assert!(readback.capacity_restoration_allowed);
        let json = serde_json::to_value(readback).unwrap();
        assert_eq!(json["lease_unit"], "buzzci-lease01.slice");
        assert!(json["resource_properties"].get("Delegate").is_none());
        assert_eq!(
            json["network_properties"]["materializer"]["Slice"],
            "buzzci-lease01.slice"
        );
        assert_eq!(json["dns_readback"]["files_lookup_ok"], true);
        assert_eq!(json["dns_readback"]["allowed_tuples_only"], true);
        assert_eq!(json["principal_dns_readback"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn lease_slice_drift_quarantines() {
        let plan = build_lease_isolation_plan(request()).unwrap();
        let mut observed = observation(&plan);
        observed
            .lease_slice
            .properties
            .insert("MemorySwapMax".to_owned(), "1".to_owned());
        let readback = verify_lease_isolation(&plan, observed);
        assert!(readback.quarantined);
        assert!(!readback.teardown_attestation_allowed);
        assert!(!readback.capacity_restoration_allowed);
    }

    #[test]
    fn principal_slice_membership_drift_quarantines() {
        let plan = build_lease_isolation_plan(request()).unwrap();
        let mut observed = observation(&plan);
        observed.units[0]
            .properties
            .insert("Slice".to_owned(), "buzzci-other.slice".to_owned());
        let readback = verify_lease_isolation(&plan, observed);
        assert!(readback.quarantined);
        assert!(!readback.teardown_attestation_allowed);
        assert!(!readback.capacity_restoration_allowed);
        assert!(readback.mismatches.iter().any(|mismatch| {
            mismatch.field.ends_with(".properties")
                && mismatch.observed.contains("buzzci-other.slice")
        }));
    }

    #[test]
    fn missing_per_role_dns_probe_fails_every_stable_proof() {
        let plan = build_lease_isolation_plan(request()).unwrap();
        let mut observed = observation(&plan);
        observed
            .principal_dns
            .retain(|proof| proof.role != PrincipalRole::Runtime);
        let readback = verify_lease_isolation(&plan, observed);
        assert_eq!(
            readback.dns_readback,
            DnsReadback {
                files_lookup_ok: false,
                arbitrary_getent_refused: false,
                resolved_varlink_inaccessible: false,
                direct_53_refused: false,
                allowed_tuples_only: false,
            }
        );
        assert!(readback.quarantined);
    }

    #[test]
    fn broker_file_drift_quarantines_before_release() {
        let plan = build_lease_isolation_plan(request()).unwrap();
        let mut observed = observation(&plan);
        observed.dns_files.resolv_conf.owner_uid = 965;
        observed.dns_files.hosts.file_type = BrokerFileType::Other;
        observed.dns_files.hosts.sha256 = "b".repeat(64);
        let readback = verify_lease_isolation(&plan, observed);
        assert!(readback.quarantined);
        assert!(!readback.teardown_attestation_allowed);
        assert!(readback
            .mismatches
            .iter()
            .any(|mismatch| mismatch.field == "broker_file_readback.resolv_conf"));
        assert!(readback
            .mismatches
            .iter()
            .any(|mismatch| mismatch.field == "broker_file_readback.hosts"));
    }

    #[test]
    fn every_root_readable_file_identity_field_is_mandatory() {
        let plan = build_lease_isolation_plan(request()).unwrap();
        let mut cases = Vec::new();

        let mut mode_0400 = observation(&plan);
        mode_0400.dns_files.resolv_conf.mode = 0o400;
        cases.push(mode_0400);

        let mut mode_0644 = observation(&plan);
        mode_0644.dns_files.resolv_conf.mode = 0o644;
        cases.push(mode_0644);

        let mut wrong_uid = observation(&plan);
        wrong_uid.dns_files.resolv_conf.owner_uid = 1;
        cases.push(wrong_uid);

        let mut wrong_gid = observation(&plan);
        wrong_gid.dns_files.resolv_conf.owner_gid = 1;
        cases.push(wrong_gid);

        let mut symlink = observation(&plan);
        symlink.dns_files.resolv_conf.file_type = BrokerFileType::Symlink;
        cases.push(symlink);

        let mut followed = observation(&plan);
        followed.dns_files.resolv_conf.type_checked_no_follow = false;
        cases.push(followed);

        let mut canonical_substitution = observation(&plan);
        canonical_substitution.dns_files.resolv_conf.canonical_path =
            PathBuf::from("/var/lib/buzzci/leases/other/empty-resolv.conf");
        cases.push(canonical_substitution);

        let mut hard_link = observation(&plan);
        hard_link.dns_files.resolv_conf.link_count = 2;
        cases.push(hard_link);

        for observed in cases {
            let readback = verify_lease_isolation(&plan, observed);
            assert!(readback.quarantined);
            assert!(!readback.teardown_attestation_allowed);
            assert!(!readback.capacity_restoration_allowed);
            assert!(readback
                .mismatches
                .iter()
                .any(|mismatch| mismatch.field == "broker_file_readback.resolv_conf"));
        }
    }

    #[test]
    fn root_owned_0444_files_remain_readable_to_materializer_files_lookup() {
        let plan = build_lease_isolation_plan(request()).unwrap();
        let observed = observation(&plan);
        for file in [&observed.dns_files.resolv_conf, &observed.dns_files.hosts] {
            assert_eq!(file.owner_uid, 0);
            assert_eq!(file.owner_gid, 0);
            assert_eq!(file.mode, 0o444);
            assert_eq!(file.file_type, BrokerFileType::Regular);
            assert!(file.type_checked_no_follow);
            assert_eq!(file.link_count, 1);
            assert_eq!(file.requested_path, file.canonical_path);
        }
        let materializer = observed
            .principal_dns
            .iter()
            .find(|proof| proof.role == PrincipalRole::Materializer)
            .unwrap();
        assert_eq!(materializer.files_lookups.len(), 2);
        assert!(materializer
            .files_lookups
            .iter()
            .all(|lookup| lookup.resolved_by_files));
        let readback = verify_lease_isolation(&plan, observed);
        assert!(readback.dns_readback.files_lookup_ok);
        assert!(!readback.quarantined);
    }

    #[test]
    fn every_dns_proof_is_required_for_all_applicable_roles() {
        let plan = build_lease_isolation_plan(request()).unwrap();

        let mut files = observation(&plan);
        files.principal_dns[0].files_lookups[0].resolved_by_files = false;
        assert!(
            !verify_lease_isolation(&plan, files)
                .dns_readback
                .files_lookup_ok
        );

        let mut getent = observation(&plan);
        getent.principal_dns[1].arbitrary_getent_succeeded = true;
        assert!(
            !verify_lease_isolation(&plan, getent)
                .dns_readback
                .arbitrary_getent_refused
        );

        let mut varlink = observation(&plan);
        varlink.principal_dns[2].resolved_varlink_accessible = true;
        assert!(
            !verify_lease_isolation(&plan, varlink)
                .dns_readback
                .resolved_varlink_inaccessible
        );

        let mut udp = observation(&plan);
        udp.principal_dns[0].direct_udp_53_connected = true;
        assert!(
            !verify_lease_isolation(&plan, udp)
                .dns_readback
                .direct_53_refused
        );

        let mut tcp = observation(&plan);
        tcp.principal_dns[2].direct_tcp_53_connected = true;
        assert!(
            !verify_lease_isolation(&plan, tcp)
                .dns_readback
                .direct_53_refused
        );

        let mut tuples = observation(&plan);
        tuples.tuple_connect_probes.last_mut().unwrap().connected = true;
        assert!(
            !verify_lease_isolation(&plan, tuples)
                .dns_readback
                .allowed_tuples_only
        );
    }

    #[test]
    fn tuple_proof_keeps_exactly_one_denied_control() {
        let plan = build_lease_isolation_plan(request()).unwrap();
        let mut wrong_role = observation(&plan);
        wrong_role.tuple_connect_probes[0].role = PrincipalRole::Executor;
        assert!(
            !verify_lease_isolation(&plan, wrong_role)
                .dns_readback
                .allowed_tuples_only
        );

        let mut observed = observation(&plan);
        observed
            .tuple_connect_probes
            .retain(|probe| plan.materializer_allowlist.contains(&probe.tuple));
        assert!(
            !verify_lease_isolation(&plan, observed)
                .dns_readback
                .allowed_tuples_only
        );

        let mut observed = observation(&plan);
        observed.tuple_connect_probes.push(TupleConnectProbe {
            role: PrincipalRole::Materializer,
            tuple: tuple("203.0.113.100", 443),
            connected: false,
        });
        assert!(
            !verify_lease_isolation(&plan, observed)
                .dns_readback
                .allowed_tuples_only
        );
    }
}
