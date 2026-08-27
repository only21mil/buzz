//! Fail-closed contract for the lease-scoped ordinary host providers.
//!
//! This module deliberately does not turn a static manifest into execution
//! authority. Executor and runtime sockets are created inside DNS-owned units
//! for one lease, so their availability must be proved again by the concrete
//! providers during `NormalExecutionBackend::preflight`.

use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Fixed root-authored host-composition declaration.
pub const HOST_COMPOSITION_PATH: &str = "/etc/buzzci/execd-host-v1.json";
const HOST_COMPOSITION_SCHEMA: u16 = 1;
const MAX_HOST_COMPOSITION_BYTES: u64 = 64 * 1024;
const DIRECTORY_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;

/// The security obligations that a complete ordinary provider set must prove.
///
/// Names are stable audit identifiers, not operator-selected claims. A
/// declaration must contain this exact ordered set, and provider tests still
/// have to prove the behaviors themselves.
pub const REQUIRED_HOST_INVARIANTS: [&str; 17] = [
    "executor-unit-handoff",
    "runtime-descriptor-freshness",
    "materializer-descriptor-handoff",
    "proxy-lease-binding",
    "terminal-stop-upload-ordering",
    "teardown-readback",
    "crash-restart-recovery",
    "namespace-uniqueness",
    "symlink-refusal",
    "inode-stability",
    "lease-generation-binding",
    "manifest-digest-binding",
    "cleanup-completeness",
    "seccomp-before-start",
    "exec-hijack-ownership",
    "dns-before-exec",
    "capacity-after-cleanup",
];

/// Static paths and identities needed before lease-scoped providers may load.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostCompositionContract {
    pub schema_version: u16,
    pub revision: u64,
    pub executor_uid: u32,
    pub runtime_uid: u32,
    pub executor_socket_template: PathBuf,
    pub runtime_socket_template: PathBuf,
    pub materialization_authority_root: PathBuf,
    pub proxy_authority_root: PathBuf,
    pub terminal_evidence_root: PathBuf,
    pub teardown_authority_root: PathBuf,
    pub qualification_lease_root: PathBuf,
    pub qualification_binding_root: PathBuf,
    pub qualification_handoff_root: PathBuf,
    pub qualification_readback_root: PathBuf,
    pub proved_invariants: Vec<String>,
}

impl HostCompositionContract {
    /// Read the fixed root-owned declaration without following a final symlink.
    pub fn canonical() -> Result<Self, HostCompositionError> {
        Self::open_for_owner(Path::new(HOST_COMPOSITION_PATH), 0)
    }

    fn open_for_owner(path: &Path, expected_uid: u32) -> Result<Self, HostCompositionError> {
        Self::open_for_owner_with_hook(path, expected_uid, || {})
    }

    fn open_for_owner_with_hook<F>(
        path: &Path,
        expected_uid: u32,
        after_open: F,
    ) -> Result<Self, HostCompositionError>
    where
        F: FnOnce(),
    {
        let parent = path.parent().ok_or(HostCompositionError::UnsafePath)?;
        validate_directory(parent, expected_uid)?;
        let before = std::fs::symlink_metadata(path).map_err(HostCompositionError::Io)?;
        validate_file_metadata(&before, expected_uid)?;
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW)
            .open(path)
            .map_err(HostCompositionError::Io)?;
        let opened = file.metadata().map_err(HostCompositionError::Io)?;
        if !same_identity(&before, &opened) {
            return Err(HostCompositionError::ChangedDuringRead);
        }
        after_open();
        let mut bytes = Vec::with_capacity(opened.len() as usize);
        (&mut file)
            .take(MAX_HOST_COMPOSITION_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(HostCompositionError::Io)?;
        if bytes.is_empty() || bytes.len() as u64 > MAX_HOST_COMPOSITION_BYTES {
            return Err(HostCompositionError::Size);
        }
        let after = file.metadata().map_err(HostCompositionError::Io)?;
        let named_after = std::fs::symlink_metadata(path).map_err(HostCompositionError::Io)?;
        if !same_identity(&opened, &after)
            || !same_identity(&opened, &named_after)
            || after.len() != bytes.len() as u64
        {
            return Err(HostCompositionError::ChangedDuringRead);
        }
        let contract: Self =
            serde_json::from_slice(&bytes).map_err(|_| HostCompositionError::Malformed)?;
        if serde_json::to_vec(&contract).map_err(|_| HostCompositionError::Malformed)? != bytes {
            return Err(HostCompositionError::NonCanonical);
        }
        contract.validate()?;
        Ok(contract)
    }

    /// Validate identities, namespace separation, and the exact invariant set.
    pub fn validate(&self) -> Result<(), HostCompositionError> {
        if self.schema_version != HOST_COMPOSITION_SCHEMA
            || self.revision == 0
            || self.executor_uid == 0
            || self.runtime_uid == 0
            || self.executor_uid == self.runtime_uid
        {
            return Err(HostCompositionError::Identity);
        }
        if self.proved_invariants.len() != REQUIRED_HOST_INVARIANTS.len()
            || self
                .proved_invariants
                .iter()
                .map(String::as_str)
                .ne(REQUIRED_HOST_INVARIANTS)
        {
            return Err(HostCompositionError::InvariantSet);
        }
        validate_socket_template(&self.executor_socket_template, "executor.sock")?;
        validate_socket_template(&self.runtime_socket_template, "runtime.sock")?;
        if self.executor_socket_template == self.runtime_socket_template {
            return Err(HostCompositionError::NamespaceCollision);
        }
        let authority_roots = [
            &self.materialization_authority_root,
            &self.proxy_authority_root,
            &self.terminal_evidence_root,
            &self.teardown_authority_root,
            &self.qualification_lease_root,
            &self.qualification_binding_root,
            &self.qualification_handoff_root,
            &self.qualification_readback_root,
        ];
        for root in authority_roots {
            validate_authority_root(root)?;
        }
        for (index, left) in authority_roots.iter().enumerate() {
            for right in authority_roots.iter().skip(index + 1) {
                if left == right || left.starts_with(right) || right.starts_with(left) {
                    return Err(HostCompositionError::NamespaceCollision);
                }
            }
        }
        Ok(())
    }
}

fn validate_directory(path: &Path, expected_uid: u32) -> Result<(), HostCompositionError> {
    let metadata = std::fs::symlink_metadata(path).map_err(HostCompositionError::Io)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != expected_uid
        || metadata.permissions().mode() & 0o7777 != DIRECTORY_MODE
    {
        return Err(HostCompositionError::Ownership);
    }
    Ok(())
}

fn validate_file_metadata(
    metadata: &std::fs::Metadata,
    expected_uid: u32,
) -> Result<(), HostCompositionError> {
    if !metadata.file_type().is_file()
        || metadata.uid() != expected_uid
        || metadata.permissions().mode() & 0o7777 != FILE_MODE
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > MAX_HOST_COMPOSITION_BYTES
    {
        return Err(HostCompositionError::Ownership);
    }
    Ok(())
}

fn same_identity(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.uid() == right.uid()
        && left.mode() == right.mode()
        && left.nlink() == right.nlink()
        && left.len() == right.len()
}

fn validate_socket_template(path: &Path, filename: &str) -> Result<(), HostCompositionError> {
    if !safe_absolute(path)
        || path.parent().and_then(Path::parent) != Some(Path::new("/run"))
        || path.file_name().and_then(|name| name.to_str()) != Some(filename)
        || !path
            .parent()
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
            .is_some_and(|name| {
                name == "buzzci-{lease_id}-exec" || name == "buzzci-{lease_id}-runtime"
            })
    {
        return Err(HostCompositionError::UnsafePath);
    }
    Ok(())
}

fn validate_authority_root(path: &Path) -> Result<(), HostCompositionError> {
    if !safe_absolute(path)
        || !path.starts_with("/var/lib/buzz-ci")
        || path == Path::new("/var/lib/buzz-ci")
    {
        return Err(HostCompositionError::UnsafePath);
    }
    Ok(())
}

fn safe_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

/// Exact reason the static host declaration cannot authorize provider loading.
#[derive(Debug, Error)]
pub enum HostCompositionError {
    #[error("host composition path is outside the fixed namespace")]
    UnsafePath,
    #[error("host composition identity is invalid")]
    Identity,
    #[error("host composition namespaces collide")]
    NamespaceCollision,
    #[error("host composition does not name the exact 17 invariants")]
    InvariantSet,
    #[error("host composition ownership, mode, type, or link count is invalid")]
    Ownership,
    #[error("host composition file changed while being read")]
    ChangedDuringRead,
    #[error("host composition file size is invalid")]
    Size,
    #[error("host composition JSON is malformed")]
    Malformed,
    #[error("host composition JSON is not canonical")]
    NonCanonical,
    #[error("host composition I/O failed")]
    Io(#[source] std::io::Error),
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};

    use tempfile::TempDir;

    use super::*;

    fn contract() -> HostCompositionContract {
        HostCompositionContract {
            schema_version: 1,
            revision: 1,
            executor_uid: 965,
            runtime_uid: 964,
            executor_socket_template: "/run/buzzci-{lease_id}-exec/executor.sock".into(),
            runtime_socket_template: "/run/buzzci-{lease_id}-runtime/runtime.sock".into(),
            materialization_authority_root: "/var/lib/buzz-ci/materialization".into(),
            proxy_authority_root: "/var/lib/buzz-ci/proxy".into(),
            terminal_evidence_root: "/var/lib/buzz-ci/terminal".into(),
            teardown_authority_root: "/var/lib/buzz-ci/teardown".into(),
            qualification_lease_root: "/var/lib/buzz-ci/qualification-leases".into(),
            qualification_binding_root: "/var/lib/buzz-ci/qualification-bindings".into(),
            qualification_handoff_root: "/var/lib/buzz-ci/qualification-handoffs".into(),
            qualification_readback_root: "/var/lib/buzz-ci/qualification-readbacks".into(),
            proved_invariants: REQUIRED_HOST_INVARIANTS
                .into_iter()
                .map(str::to_owned)
                .collect(),
        }
    }

    fn write_fixture(contract: &HostCompositionContract) -> (TempDir, PathBuf, u32) {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("execd-host-v1.json");
        fs::write(&path, serde_json::to_vec(contract).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let uid = fs::metadata(&path).unwrap().uid();
        (directory, path, uid)
    }

    #[test]
    fn exact_seventeen_invariants_and_disjoint_namespaces_validate() {
        let value = contract();
        assert_eq!(value.proved_invariants.len(), 17);
        value.validate().unwrap();
    }

    #[test]
    fn partial_reordered_or_extra_invariant_sets_fail_closed() {
        let mut cases = Vec::new();
        let mut missing = contract();
        missing.proved_invariants.pop();
        cases.push(missing);
        let mut reordered = contract();
        reordered.proved_invariants.swap(0, 1);
        cases.push(reordered);
        let mut extra = contract();
        extra.proved_invariants.push("operator-assertion".into());
        cases.push(extra);
        for value in cases {
            assert!(matches!(
                value.validate(),
                Err(HostCompositionError::InvariantSet)
            ));
        }
    }

    #[test]
    fn uid_and_namespace_collisions_fail_closed() {
        let mut uid = contract();
        uid.runtime_uid = uid.executor_uid;
        assert!(matches!(
            uid.validate(),
            Err(HostCompositionError::Identity)
        ));
        let mut root = contract();
        root.proxy_authority_root = root.materialization_authority_root.clone();
        assert!(matches!(
            root.validate(),
            Err(HostCompositionError::NamespaceCollision)
        ));
    }

    #[test]
    fn canonical_root_owned_fixture_reopens_exact_bytes() {
        let expected = contract();
        let (_directory, path, uid) = write_fixture(&expected);
        assert_eq!(
            HostCompositionContract::open_for_owner(&path, uid).unwrap(),
            expected
        );
        assert_eq!(
            HostCompositionContract::open_for_owner(&path, uid).unwrap(),
            expected
        );
    }

    #[test]
    fn symlink_hardlink_and_noncanonical_json_are_rejected() {
        let expected = contract();
        let (directory, path, uid) = write_fixture(&expected);
        let link = directory.path().join("link.json");
        symlink(&path, &link).unwrap();
        assert!(HostCompositionContract::open_for_owner(&link, uid).is_err());

        let alias = directory.path().join("alias.json");
        fs::hard_link(&path, &alias).unwrap();
        assert!(HostCompositionContract::open_for_owner(&path, uid).is_err());

        fs::remove_file(&alias).unwrap();
        fs::write(&path, serde_json::to_string_pretty(&expected).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            HostCompositionContract::open_for_owner(&path, uid),
            Err(HostCompositionError::NonCanonical)
        ));
    }

    #[test]
    fn unsafe_templates_and_overlapping_authority_roots_are_rejected() {
        let mut traversal = contract();
        traversal.executor_socket_template = "/run/../executor.sock".into();
        assert!(matches!(
            traversal.validate(),
            Err(HostCompositionError::UnsafePath)
        ));
        let mut overlap = contract();
        overlap.proxy_authority_root = "/var/lib/buzz-ci/materialization/proxy".into();
        assert!(matches!(
            overlap.validate(),
            Err(HostCompositionError::NamespaceCollision)
        ));
    }

    #[test]
    fn inode_replacement_between_open_and_read_is_rejected() {
        let expected = contract();
        let (directory, path, uid) = write_fixture(&expected);
        let replacement = directory.path().join("replacement.json");
        fs::write(&replacement, serde_json::to_vec(&expected).unwrap()).unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
        let result = HostCompositionContract::open_for_owner_with_hook(&path, uid, || {
            fs::rename(&replacement, &path).unwrap();
        });
        assert!(matches!(
            result,
            Err(HostCompositionError::ChangedDuringRead)
        ));
    }
}
