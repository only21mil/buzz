use serde::{Deserialize, Serialize};

use crate::ContractError;

/// Qualified container engine implementation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineKind {
    /// Rootless Podman. This is the only Phase-1 engine.
    Podman,
}

/// Execution-network policy bound into the signed attempt manifest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPolicy {
    /// No execution egress; all inputs must be pre-materialized.
    None,
    /// Reserved for a later independently reviewed selective-egress phase.
    Allowlist,
}

/// Resource limits shared by the protocol, lease, and execution policy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimits {
    /// systemd/cgroup-v2 CPU weight in the inclusive range `1..=10_000`.
    pub cpu_weight: u16,
    /// Hard cgroup-v2 memory ceiling in bytes.
    pub mem_max_bytes: u64,
    /// Hard process-count ceiling.
    pub pids_max: u32,
    /// systemd/cgroup-v2 I/O weight in the inclusive range `1..=10_000`.
    pub io_weight: u16,
}

impl ResourceLimits {
    pub(crate) fn validate(&self) -> Result<(), ContractError> {
        if !(1..=10_000).contains(&self.cpu_weight) {
            return Err(ContractError::invalid(
                "isolation_profile.limits.cpu_weight",
                "must be in 1..=10000",
            ));
        }
        if self.mem_max_bytes == 0 {
            return Err(ContractError::invalid(
                "isolation_profile.limits.mem_max_bytes",
                "must be non-zero",
            ));
        }
        if self.pids_max == 0 {
            return Err(ContractError::invalid(
                "isolation_profile.limits.pids_max",
                "must be non-zero",
            ));
        }
        if !(1..=10_000).contains(&self.io_weight) {
            return Err(ContractError::invalid(
                "isolation_profile.limits.io_weight",
                "must be in 1..=10000",
            ));
        }
        Ok(())
    }
}

/// Full execution profile carried by the frozen protocol and lease.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IsolationProfile {
    /// Runner image in canonical `sha256:<64 lowercase hex>` form.
    pub image_digest: String,
    /// Qualified runtime engine.
    pub engine_kind: EngineKind,
    /// Exact engine version qualified by host acceptance tests.
    pub engine_version: String,
    /// Exact canonical architecture qualified by host acceptance tests.
    pub arch: String,
    /// Resource limits that must equal the cgroup lease limits.
    pub limits: ResourceLimits,
    /// Execution-network policy.
    pub network_policy: NetworkPolicy,
    /// Required service-container capabilities. Phase 1 requires this empty.
    pub service_requirements: Vec<String>,
    /// Broker-issued execution network-namespace identifier.
    pub netns: String,
}

impl IsolationProfile {
    pub(crate) fn validate_phase1(
        &self,
        expected_engine_version: &str,
        expected_arch: &str,
    ) -> Result<(), ContractError> {
        validate_sha256_digest("isolation_profile.image_digest", &self.image_digest)?;
        validate_ascii_token("isolation_profile.engine_version", &self.engine_version, 64)?;
        validate_ascii_token("isolation_profile.arch", &self.arch, 32)?;
        if self.engine_version != expected_engine_version {
            return Err(ContractError::mismatch(
                "isolation_profile.engine_version",
                "profile does not match the qualified host engine",
            ));
        }
        if self.arch != expected_arch {
            return Err(ContractError::mismatch(
                "isolation_profile.arch",
                "profile does not match the qualified host architecture",
            ));
        }
        self.limits.validate()?;
        if self.network_policy != NetworkPolicy::None {
            return Err(ContractError::invalid(
                "isolation_profile.network_policy",
                "Phase 1 requires network_policy=none",
            ));
        }
        if !self.service_requirements.is_empty() {
            return Err(ContractError::invalid(
                "isolation_profile.service_requirements",
                "Phase 1 refuses service containers",
            ));
        }
        validate_handle_name("isolation_profile.netns", &self.netns)?;
        if self.netns == "none" || self.netns == "host" {
            return Err(ContractError::invalid(
                "isolation_profile.netns",
                "Phase 1 requires a broker-issued no-egress namespace",
            ));
        }
        Ok(())
    }
}

pub(crate) fn validate_sha256_digest(
    field: &'static str,
    value: &str,
) -> Result<(), ContractError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(ContractError::invalid(
            field,
            "must use sha256:<64 lowercase hex> form",
        ));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ContractError::invalid(
            field,
            "must use sha256:<64 lowercase hex> form",
        ));
    }
    Ok(())
}

pub(crate) fn validate_ascii_token(
    field: &'static str,
    value: &str,
    maximum: usize,
) -> Result<(), ContractError> {
    if value.is_empty()
        || value.len() > maximum
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
    {
        return Err(ContractError::invalid(
            field,
            "must be a bounded ASCII token",
        ));
    }
    Ok(())
}

pub(crate) fn validate_handle_name(field: &'static str, value: &str) -> Result<(), ContractError> {
    validate_ascii_token(field, value, 128)
}
