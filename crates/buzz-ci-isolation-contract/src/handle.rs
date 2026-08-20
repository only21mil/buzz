use serde::{Deserialize, Serialize};

use crate::{profile::validate_handle_name, ContractError, ResourceLimits};

/// Broker-issued filesystem object identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerObjectHandle {
    /// Opaque 256-bit capability token encoded as lowercase hexadecimal.
    pub token: String,
    /// Device number observed by the trusted broker.
    pub device: u64,
    /// Inode number observed by the trusted broker.
    pub inode: u64,
}

impl BrokerObjectHandle {
    pub(crate) fn validate(&self, field: &'static str) -> Result<(), ContractError> {
        validate_capability_token(field, &self.token)?;
        if self.device == 0 || self.inode == 0 {
            return Err(ContractError::invalid(
                field,
                "device and inode must both be non-zero",
            ));
        }
        Ok(())
    }
}

/// Broker-issued workspace identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceHandle {
    /// Exact absolute path opened and pinned by the trusted broker.
    pub path: String,
    /// Directory capability; callers must consume an already-open descriptor.
    pub object: BrokerObjectHandle,
    /// Dedicated materializer UID that initially owns the private workspace.
    pub owner_uid: u32,
    /// Capability token of the hard quota that contains this workspace.
    pub quota_token: String,
}

/// Identity of the runtime endpoint passed to the policy proxy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuntimeEndpointIdentity {
    /// A rootless Unix socket pinned by device and inode.
    UnixSocket {
        /// Opaque broker capability token.
        token: String,
        /// Device number observed by the broker.
        device: u64,
        /// Inode number observed by the broker.
        inode: u64,
        /// UID that owns the rootless runtime endpoint.
        owner_uid: u32,
    },
    /// An already-connected endpoint passed by inherited descriptor.
    InheritedFd {
        /// Opaque broker capability token associated with the passed descriptor.
        token: String,
        /// UID whose rootless runtime is reached by the descriptor.
        owner_uid: u32,
    },
}

impl RuntimeEndpointIdentity {
    pub(crate) fn validate(&self, expected_owner: u32) -> Result<(), ContractError> {
        let (token, owner_uid) = match self {
            Self::UnixSocket {
                token,
                device,
                inode,
                owner_uid,
            } => {
                if *device == 0 || *inode == 0 {
                    return Err(ContractError::invalid(
                        "runtime_endpoint",
                        "socket device and inode must both be non-zero",
                    ));
                }
                (token, *owner_uid)
            }
            Self::InheritedFd { token, owner_uid } => (token, *owner_uid),
        };
        validate_capability_token("runtime_endpoint.token", token)?;
        if owner_uid != expected_owner {
            return Err(ContractError::mismatch(
                "runtime_endpoint.owner_uid",
                "runtime endpoint is not owned by the runtime principal",
            ));
        }
        Ok(())
    }

    pub(crate) fn token(&self) -> &str {
        match self {
            Self::UnixSocket { token, .. } | Self::InheritedFd { token, .. } => token,
        }
    }

    pub(crate) fn object_identity(&self) -> Option<(u64, u64)> {
        match self {
            Self::UnixSocket { device, inode, .. } => Some((*device, *inode)),
            Self::InheritedFd { .. } => None,
        }
    }
}

/// Broker-issued cgroup-v2 identity and its immutable resource policy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CgroupHandle {
    /// Pinned cgroup filesystem object.
    pub object: BrokerObjectHandle,
    /// Limits the broker must write and read back on this exact cgroup.
    pub limits: ResourceLimits,
}

/// Broker-issued execution network-namespace identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetnsHandle {
    /// Pinned namespace filesystem object.
    pub object: BrokerObjectHandle,
    /// Stable broker identifier bound into the isolation profile.
    pub name: String,
}

/// Supported hard-quota backends.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaBackend {
    /// XFS project quota.
    XfsProject,
    /// Btrfs qgroup quota.
    BtrfsQgroup,
    /// A dedicated filesystem or logical volume with a fixed capacity.
    BoundedFilesystem,
}

/// Broker-issued hard workspace-quota identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuotaHandle {
    /// Opaque broker capability token.
    pub token: String,
    /// Qualified quota mechanism.
    pub backend: QuotaBackend,
    /// Backend-specific project, qgroup, filesystem, or volume identifier.
    pub quota_id: String,
    /// Hard byte ceiling read back by the trusted broker.
    pub hard_bytes: u64,
}

impl WorkspaceHandle {
    pub(crate) fn validate(&self, expected_owner: u32) -> Result<(), ContractError> {
        self.object.validate("workspace.object")?;
        let path = std::path::Path::new(&self.path);
        if !path.is_absolute()
            || path.components().any(|component| {
                !matches!(
                    component,
                    std::path::Component::RootDir | std::path::Component::Normal(_)
                )
            })
        {
            return Err(ContractError::invalid(
                "workspace.path",
                "must be a normalized absolute broker path",
            ));
        }
        validate_capability_token("workspace.quota_token", &self.quota_token)?;
        if self.owner_uid != expected_owner {
            return Err(ContractError::mismatch(
                "workspace.owner_uid",
                "workspace is not owned by the materializer principal",
            ));
        }
        Ok(())
    }
}

impl CgroupHandle {
    pub(crate) fn validate(&self) -> Result<(), ContractError> {
        self.object.validate("cgroup.object")?;
        self.limits.validate()
    }
}

impl NetnsHandle {
    pub(crate) fn validate(&self) -> Result<(), ContractError> {
        self.object.validate("netns.object")?;
        validate_handle_name("netns.name", &self.name)?;
        if self.name == "none" || self.name == "host" {
            return Err(ContractError::invalid(
                "netns.name",
                "must identify a broker-issued no-egress namespace",
            ));
        }
        Ok(())
    }
}

impl QuotaHandle {
    pub(crate) fn validate(&self) -> Result<(), ContractError> {
        validate_capability_token("quota.token", &self.token)?;
        validate_handle_name("quota.quota_id", &self.quota_id)?;
        if self.hard_bytes == 0 {
            return Err(ContractError::invalid(
                "quota.hard_bytes",
                "must be non-zero",
            ));
        }
        Ok(())
    }
}

pub(crate) fn validate_capability_token(
    field: &'static str,
    token: &str,
) -> Result<(), ContractError> {
    if token.len() != 64
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ContractError::invalid(
            field,
            "must be 64 lowercase hexadecimal characters",
        ));
    }
    Ok(())
}
