//! Concrete bounded cleanup runner for teardown-failure qualification.
//!
//! Every command is constructed from broker-derived targets, runs without a
//! shell through the shared bounded process runner, and is checked against one
//! monotonic deadline. Lease files are removed only through no-follow
//! descriptors after ownership and inode checks.

use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::File;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::thread;
use std::time::Duration;

use nix::dir::Dir;
use nix::errno::Errno;
use nix::fcntl::{open, openat, AtFlags, OFlag};
use nix::sys::stat::{fstat, fstatat, FileStat, Mode, SFlag};
use nix::unistd::{unlinkat, UnlinkatFlags};
use serde_json::Value;
use thiserror::Error;

use crate::dns_exec::{
    AllowedBinary, ExactCommand, ExactCommandOutput, ExactCommandRunner, ProcessCommandRunner,
    COMMAND_TIMEOUT, MAX_COMMAND_OUTPUT,
};
use crate::qualification_exec::{
    QualificationCleanupDeadline, QualificationCleanupObservation, QualificationCleanupOperation,
    QualificationCleanupRunner, QualificationCleanupTargets,
};

const CGROUP_FS_ROOT: &str = "/sys/fs/cgroup";
const LEASE_ROOT: &str = "/var/lib/buzzci/leases";
const NETWORK_NAMESPACE_ROOT: &str = "/run/netns";
const MAX_TREE_DEPTH: usize = 64;
const MAX_TREE_ENTRIES: usize = 4096;
const REAP_POLL_INTERVAL: Duration = Duration::from_millis(5);

/// Production implementation of the closed qualification cleanup contract.
pub struct ProductionQualificationCleanupRunner<R = ProcessCommandRunner> {
    commands: R,
    roots: CleanupRoots,
    target: Option<String>,
    completed: [bool; 5],
}

impl ProductionQualificationCleanupRunner<ProcessCommandRunner> {
    /// Construct the production runner for canonical Linux host roots.
    pub fn production() -> Self {
        Self::with_runner(ProcessCommandRunner)
    }
}

impl<R> ProductionQualificationCleanupRunner<R> {
    /// Construct a runner with the production command paths and filesystem roots.
    pub fn with_runner(commands: R) -> Self {
        Self {
            commands,
            roots: CleanupRoots::production(),
            target: None,
            completed: [false; 5],
        }
    }

    #[cfg(test)]
    fn for_test(commands: R, roots: CleanupRoots) -> Self {
        Self {
            commands,
            roots,
            target: None,
            completed: [false; 5],
        }
    }

    fn bind_target<E: std::error::Error + Send + Sync + 'static>(
        &mut self,
        targets: &QualificationCleanupTargets,
    ) -> Result<(), QualificationCleanupRunnerError<E>> {
        match &self.target {
            Some(target) if target != targets.lease_slice() => {
                Err(QualificationCleanupRunnerError::TargetChanged)
            }
            Some(_) => Ok(()),
            None => {
                self.target = Some(targets.lease_slice().to_owned());
                Ok(())
            }
        }
    }
}

impl<R: ExactCommandRunner> QualificationCleanupRunner for ProductionQualificationCleanupRunner<R> {
    type Error = QualificationCleanupRunnerError<R::Error>;

    fn execute(
        &mut self,
        operation: &QualificationCleanupOperation,
        targets: &QualificationCleanupTargets,
        deadline: QualificationCleanupDeadline,
    ) -> Result<(), Self::Error> {
        self.bind_target(targets)?;
        require_time(deadline)?;
        let index = operation_index(operation);
        if self.completed[index] {
            return Err(QualificationCleanupRunnerError::RepeatedOperation);
        }
        match operation {
            QualificationCleanupOperation::StopLeaseSlice => {
                self.run_required(
                    AllowedBinary::Systemctl,
                    vec![os("stop"), os(targets.lease_slice())],
                    deadline,
                )?;
            }
            QualificationCleanupOperation::KillLeaseSlice => {
                self.run_required(
                    AllowedBinary::Systemctl,
                    vec![
                        os("kill"),
                        os("--kill-whom=all"),
                        os("--signal=KILL"),
                        os(targets.lease_slice()),
                    ],
                    deadline,
                )?;
                self.wait_for_empty_cgroup(targets, deadline)?;
            }
            QualificationCleanupOperation::RemoveLeaseNftTable => {
                self.run_required(
                    AllowedBinary::Nft,
                    vec![
                        os("delete"),
                        os("table"),
                        os(targets.nft_family()),
                        os(targets.nft_table()),
                    ],
                    deadline,
                )?;
            }
            QualificationCleanupOperation::RemoveLeaseNetworkNamespace => {
                self.run_required(
                    AllowedBinary::Ip,
                    vec![os("netns"), os("delete"), os(targets.namespace_name())],
                    deadline,
                )?;
            }
            QualificationCleanupOperation::RemoveLeaseFiles => {
                remove_lease_tree(&self.roots, targets, deadline)?;
            }
        }
        require_time(deadline)?;
        self.completed[index] = true;
        Ok(())
    }

    fn observe(
        &mut self,
        targets: &QualificationCleanupTargets,
        deadline: QualificationCleanupDeadline,
    ) -> Result<Option<QualificationCleanupObservation>, Self::Error> {
        self.bind_target(targets)?;
        require_time(deadline)?;

        let slice = self.run_required(
            AllowedBinary::Systemctl,
            vec![
                os("show"),
                os(targets.lease_slice()),
                os("--property=LoadState"),
                os("--property=ActiveState"),
            ],
            deadline,
        )?;
        let lease_slice_inactive = parse_slice_inactive(&slice.stdout)?;
        let lease_cgroup_empty = cgroup_empty(&self.roots, targets)?;

        let nft = self.run_required(
            AllowedBinary::Nft,
            vec![os("-j"), os("list"), os("tables")],
            deadline,
        )?;
        let nft_table_absent =
            parse_nft_table_absent(&nft.stdout, targets.nft_family(), targets.nft_table())?;

        let namespaces = self.run_required(
            AllowedBinary::Ip,
            vec![os("-j"), os("netns"), os("list")],
            deadline,
        )?;
        let namespace_absent =
            parse_namespace_absent(&namespaces.stdout, targets.namespace_name())?
                && mapped_target_absent(
                    &self.roots.namespace_root,
                    Path::new(NETWORK_NAMESPACE_ROOT),
                    targets.namespace_path(),
                )?;
        let lease_files_absent = mapped_target_absent(
            &self.roots.lease_root,
            Path::new(LEASE_ROOT),
            targets.lease_files(),
        )?;
        require_time(deadline)?;

        let teardown_failure_observed = self.completed.iter().all(|value| *value);
        let slice_quarantined =
            self.completed[0] && self.completed[1] && lease_slice_inactive && lease_cgroup_empty;
        Ok(Some(QualificationCleanupObservation {
            lease_slice_inactive,
            lease_cgroup_empty,
            nft_table_absent,
            namespace_absent,
            lease_files_absent,
            teardown_failure_observed,
            slice_quarantined,
            // This runner has no publication operation or output path. The
            // closed teardown-failure plan therefore records no publication.
            publish_observed: false,
        }))
    }

    fn cancel_and_reap(
        &mut self,
        targets: &QualificationCleanupTargets,
        deadline: QualificationCleanupDeadline,
    ) -> Result<(), Self::Error> {
        self.bind_target(targets)?;
        require_time(deadline)?;
        self.run_required(
            AllowedBinary::Systemctl,
            vec![
                os("kill"),
                os("--kill-whom=all"),
                os("--signal=KILL"),
                os(targets.lease_slice()),
            ],
            deadline,
        )?;
        self.wait_for_empty_cgroup(targets, deadline)
    }
}

impl<R: ExactCommandRunner> ProductionQualificationCleanupRunner<R> {
    fn run_required(
        &mut self,
        binary: AllowedBinary,
        argv: Vec<OsString>,
        deadline: QualificationCleanupDeadline,
    ) -> Result<ExactCommandOutput, QualificationCleanupRunnerError<R::Error>> {
        let timeout = command_timeout(deadline)?;
        let output = self
            .commands
            .run(&ExactCommand::new(binary, argv, timeout))
            .map_err(QualificationCleanupRunnerError::Command)?;
        require_time(deadline)?;
        if output.stdout_truncated || output.stderr_truncated {
            return Err(QualificationCleanupRunnerError::TruncatedOutput);
        }
        if !output.success() {
            return Err(QualificationCleanupRunnerError::CommandFailed);
        }
        Ok(output)
    }

    fn wait_for_empty_cgroup(
        &self,
        targets: &QualificationCleanupTargets,
        deadline: QualificationCleanupDeadline,
    ) -> Result<(), QualificationCleanupRunnerError<R::Error>> {
        loop {
            require_time(deadline)?;
            if cgroup_empty(&self.roots, targets)? {
                return Ok(());
            }
            let remaining = deadline
                .remaining()
                .ok_or(QualificationCleanupRunnerError::Deadline)?;
            thread::sleep(REAP_POLL_INTERVAL.min(remaining));
        }
    }
}

/// Fail-closed errors returned by the concrete cleanup runner.
#[derive(Debug, Error)]
pub enum QualificationCleanupRunnerError<E: std::error::Error + Send + Sync + 'static> {
    #[error("qualification cleanup deadline expired")]
    Deadline,
    #[error("qualification cleanup command failed")]
    Command(#[source] E),
    #[error("qualification cleanup command returned a nonzero or signaled status")]
    CommandFailed,
    #[error("qualification cleanup command output exceeded the retained bound")]
    TruncatedOutput,
    #[error("qualification cleanup command readback was malformed or ambiguous")]
    Readback,
    #[error("qualification cleanup filesystem state was unsafe or ambiguous")]
    Filesystem,
    #[error("qualification cleanup runner was reused for a different lease")]
    TargetChanged,
    #[error("qualification cleanup operation was repeated")]
    RepeatedOperation,
}

#[derive(Clone)]
struct CleanupRoots {
    cgroup_root: PathBuf,
    namespace_root: PathBuf,
    lease_root: PathBuf,
    expected_uid: u32,
    expected_gid: u32,
}

impl CleanupRoots {
    fn production() -> Self {
        Self {
            cgroup_root: PathBuf::from(CGROUP_FS_ROOT),
            namespace_root: PathBuf::from(NETWORK_NAMESPACE_ROOT),
            lease_root: PathBuf::from(LEASE_ROOT),
            expected_uid: 0,
            expected_gid: 0,
        }
    }
}

fn operation_index(operation: &QualificationCleanupOperation) -> usize {
    match operation {
        QualificationCleanupOperation::StopLeaseSlice => 0,
        QualificationCleanupOperation::KillLeaseSlice => 1,
        QualificationCleanupOperation::RemoveLeaseNftTable => 2,
        QualificationCleanupOperation::RemoveLeaseNetworkNamespace => 3,
        QualificationCleanupOperation::RemoveLeaseFiles => 4,
    }
}

fn os(value: impl AsRef<OsStr>) -> OsString {
    value.as_ref().to_owned()
}

fn require_time<E: std::error::Error + Send + Sync + 'static>(
    deadline: QualificationCleanupDeadline,
) -> Result<(), QualificationCleanupRunnerError<E>> {
    if deadline.expired() {
        Err(QualificationCleanupRunnerError::Deadline)
    } else {
        Ok(())
    }
}

fn command_timeout<E: std::error::Error + Send + Sync + 'static>(
    deadline: QualificationCleanupDeadline,
) -> Result<Duration, QualificationCleanupRunnerError<E>> {
    let remaining = deadline
        .remaining()
        .ok_or(QualificationCleanupRunnerError::Deadline)?;
    if remaining.is_zero() {
        return Err(QualificationCleanupRunnerError::Deadline);
    }
    Ok(COMMAND_TIMEOUT.min(remaining))
}

fn parse_slice_inactive<E: std::error::Error + Send + Sync + 'static>(
    bytes: &[u8],
) -> Result<bool, QualificationCleanupRunnerError<E>> {
    let text = std::str::from_utf8(bytes).map_err(|_| QualificationCleanupRunnerError::Readback)?;
    let mut load = None;
    let mut active = None;
    for line in text.lines() {
        let (name, value) = line
            .split_once('=')
            .ok_or(QualificationCleanupRunnerError::Readback)?;
        let slot = match name {
            "LoadState" => &mut load,
            "ActiveState" => &mut active,
            _ => return Err(QualificationCleanupRunnerError::Readback),
        };
        if slot.replace(value).is_some() {
            return Err(QualificationCleanupRunnerError::Readback);
        }
    }
    let load = load.ok_or(QualificationCleanupRunnerError::Readback)?;
    let active = active.ok_or(QualificationCleanupRunnerError::Readback)?;
    if !matches!(load, "loaded" | "not-found") {
        return Err(QualificationCleanupRunnerError::Readback);
    }
    Ok(active == "inactive" || (load == "not-found" && active.is_empty()))
}

fn parse_nft_table_absent<E: std::error::Error + Send + Sync + 'static>(
    bytes: &[u8],
    family: &str,
    table: &str,
) -> Result<bool, QualificationCleanupRunnerError<E>> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| QualificationCleanupRunnerError::Readback)?;
    let objects = value
        .get("nftables")
        .and_then(Value::as_array)
        .ok_or(QualificationCleanupRunnerError::Readback)?;
    let mut absent = true;
    for object in objects {
        if let Some(candidate) = object.get("table") {
            let candidate = candidate
                .as_object()
                .ok_or(QualificationCleanupRunnerError::Readback)?;
            let candidate_family = candidate
                .get("family")
                .and_then(Value::as_str)
                .ok_or(QualificationCleanupRunnerError::Readback)?;
            let candidate_name = candidate
                .get("name")
                .and_then(Value::as_str)
                .ok_or(QualificationCleanupRunnerError::Readback)?;
            absent &= candidate_family != family || candidate_name != table;
        } else if object.get("metainfo").is_none() {
            return Err(QualificationCleanupRunnerError::Readback);
        }
    }
    Ok(absent)
}

fn parse_namespace_absent<E: std::error::Error + Send + Sync + 'static>(
    bytes: &[u8],
    namespace: &str,
) -> Result<bool, QualificationCleanupRunnerError<E>> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| QualificationCleanupRunnerError::Readback)?;
    let entries = value
        .as_array()
        .ok_or(QualificationCleanupRunnerError::Readback)?;
    if entries.iter().any(|entry| {
        entry.as_object().is_none_or(|object| {
            object.keys().any(|key| key != "name")
                || object.get("name").and_then(Value::as_str).is_none()
        })
    }) {
        return Err(QualificationCleanupRunnerError::Readback);
    }
    Ok(!entries
        .iter()
        .any(|entry| entry.get("name").and_then(Value::as_str) == Some(namespace)))
}

fn cgroup_empty<E: std::error::Error + Send + Sync + 'static>(
    roots: &CleanupRoots,
    targets: &QualificationCleanupTargets,
) -> Result<bool, QualificationCleanupRunnerError<E>> {
    let relative = targets
        .lease_cgroup()
        .strip_prefix(Path::new("/"))
        .map_err(|_| QualificationCleanupRunnerError::Filesystem)?;
    if relative
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(QualificationCleanupRunnerError::Filesystem);
    }
    let cgroup_root = open_directory_path(&roots.cgroup_root)
        .map_err(|_| QualificationCleanupRunnerError::Filesystem)?;
    validate_owned_directory(&cgroup_root, roots.expected_uid, roots.expected_gid)?;
    let directory = match open_directory_beneath(cgroup_root, relative) {
        Ok(directory) => directory,
        Err(Errno::ENOENT) => return Ok(true),
        Err(_) => return Err(QualificationCleanupRunnerError::Filesystem),
    };
    validate_owned_directory(&directory, roots.expected_uid, roots.expected_gid)?;
    let procs = read_owned_bounded_file(
        &directory,
        "cgroup.procs",
        roots.expected_uid,
        roots.expected_gid,
    )?;
    let events = read_owned_bounded_file(
        &directory,
        "cgroup.events",
        roots.expected_uid,
        roots.expected_gid,
    )?;
    Ok(procs.iter().all(u8::is_ascii_whitespace) && !parse_cgroup_populated(&events)?)
}

fn read_owned_bounded_file<E: std::error::Error + Send + Sync + 'static>(
    directory: &OwnedFd,
    name: &str,
    uid: u32,
    gid: u32,
) -> Result<Vec<u8>, QualificationCleanupRunnerError<E>> {
    let descriptor = openat(
        directory,
        name,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| QualificationCleanupRunnerError::Filesystem)?;
    let mut file = File::from(descriptor);
    validate_owned_regular(&file, uid, gid, false)?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take((MAX_COMMAND_OUTPUT + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| QualificationCleanupRunnerError::Filesystem)?;
    if bytes.len() > MAX_COMMAND_OUTPUT {
        return Err(QualificationCleanupRunnerError::Filesystem);
    }
    Ok(bytes)
}

fn parse_cgroup_populated<E: std::error::Error + Send + Sync + 'static>(
    bytes: &[u8],
) -> Result<bool, QualificationCleanupRunnerError<E>> {
    let text = std::str::from_utf8(bytes).map_err(|_| QualificationCleanupRunnerError::Readback)?;
    let mut populated = None;
    for line in text.lines() {
        let (name, value) = line
            .split_once(' ')
            .ok_or(QualificationCleanupRunnerError::Readback)?;
        if name == "populated" {
            let value = match value {
                "0" => false,
                "1" => true,
                _ => return Err(QualificationCleanupRunnerError::Readback),
            };
            if populated.replace(value).is_some() {
                return Err(QualificationCleanupRunnerError::Readback);
            }
        }
    }
    populated.ok_or(QualificationCleanupRunnerError::Readback)
}

fn mapped_target_absent<E: std::error::Error + Send + Sync + 'static>(
    mapped_parent: &Path,
    canonical_parent: &Path,
    target: &Path,
) -> Result<bool, QualificationCleanupRunnerError<E>> {
    let name = exact_child_name(canonical_parent, target)?;
    let parent = open_directory_path(mapped_parent)
        .map_err(|_| QualificationCleanupRunnerError::Filesystem)?;
    match fstatat(&parent, name, AtFlags::AT_SYMLINK_NOFOLLOW) {
        Ok(_) => Ok(false),
        Err(Errno::ENOENT) => Ok(true),
        Err(_) => Err(QualificationCleanupRunnerError::Filesystem),
    }
}

fn remove_lease_tree<E: std::error::Error + Send + Sync + 'static>(
    roots: &CleanupRoots,
    targets: &QualificationCleanupTargets,
    deadline: QualificationCleanupDeadline,
) -> Result<(), QualificationCleanupRunnerError<E>> {
    require_time(deadline)?;
    let name = exact_child_name(Path::new(LEASE_ROOT), targets.lease_files())?;
    let parent = open_directory_path(&roots.lease_root)
        .map_err(|_| QualificationCleanupRunnerError::Filesystem)?;
    validate_owned_directory(&parent, roots.expected_uid, roots.expected_gid)?;
    let expected = match fstatat(&parent, name, AtFlags::AT_SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(Errno::ENOENT) => return Ok(()),
        Err(_) => return Err(QualificationCleanupRunnerError::Filesystem),
    };
    validate_directory_stat(&expected, roots.expected_uid, roots.expected_gid)?;
    let descriptor = openat(
        &parent,
        name,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| QualificationCleanupRunnerError::Filesystem)?;
    let opened = fstat(&descriptor).map_err(|_| QualificationCleanupRunnerError::Filesystem)?;
    if !same_identity(&expected, &opened) {
        return Err(QualificationCleanupRunnerError::Filesystem);
    }
    let mut directory =
        Dir::from_fd(descriptor).map_err(|_| QualificationCleanupRunnerError::Filesystem)?;
    let mut entries = 0_usize;
    remove_directory_contents(&mut directory, roots, deadline, 0, &mut entries)?;
    drop(directory);
    require_time(deadline)?;
    let current = fstatat(&parent, name, AtFlags::AT_SYMLINK_NOFOLLOW)
        .map_err(|_| QualificationCleanupRunnerError::Filesystem)?;
    if !same_identity(&expected, &current) {
        return Err(QualificationCleanupRunnerError::Filesystem);
    }
    unlinkat(&parent, name, UnlinkatFlags::RemoveDir)
        .map_err(|_| QualificationCleanupRunnerError::Filesystem)
}

fn remove_directory_contents<E: std::error::Error + Send + Sync + 'static>(
    directory: &mut Dir,
    roots: &CleanupRoots,
    deadline: QualificationCleanupDeadline,
    depth: usize,
    entries: &mut usize,
) -> Result<(), QualificationCleanupRunnerError<E>> {
    if depth >= MAX_TREE_DEPTH {
        return Err(QualificationCleanupRunnerError::Filesystem);
    }
    let names: Vec<CString> = directory
        .iter()
        .map(|entry| {
            entry
                .map(|entry| entry.file_name().to_owned())
                .map_err(|_| QualificationCleanupRunnerError::Filesystem)
        })
        .collect::<Result<_, _>>()?;
    for name in names {
        if name.as_c_str() == c"." || name.as_c_str() == c".." {
            continue;
        }
        require_time(deadline)?;
        *entries = entries
            .checked_add(1)
            .ok_or(QualificationCleanupRunnerError::Filesystem)?;
        if *entries > MAX_TREE_ENTRIES {
            return Err(QualificationCleanupRunnerError::Filesystem);
        }
        remove_entry(directory, name.as_c_str(), roots, deadline, depth, entries)?;
    }
    Ok(())
}

fn remove_entry<E: std::error::Error + Send + Sync + 'static>(
    parent: &Dir,
    name: &CStr,
    roots: &CleanupRoots,
    deadline: QualificationCleanupDeadline,
    depth: usize,
    entries: &mut usize,
) -> Result<(), QualificationCleanupRunnerError<E>> {
    let expected = fstatat(parent, name, AtFlags::AT_SYMLINK_NOFOLLOW)
        .map_err(|_| QualificationCleanupRunnerError::Filesystem)?;
    match SFlag::from_bits_truncate(expected.st_mode) {
        SFlag::S_IFREG => {
            validate_regular_stat(&expected, roots.expected_uid, roots.expected_gid, true)?;
            let descriptor = openat(
                parent,
                name,
                OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
                Mode::empty(),
            )
            .map_err(|_| QualificationCleanupRunnerError::Filesystem)?;
            let opened =
                fstat(&descriptor).map_err(|_| QualificationCleanupRunnerError::Filesystem)?;
            if !same_identity(&expected, &opened) {
                return Err(QualificationCleanupRunnerError::Filesystem);
            }
            unlinkat(parent, name, UnlinkatFlags::NoRemoveDir)
                .map_err(|_| QualificationCleanupRunnerError::Filesystem)
        }
        SFlag::S_IFDIR => {
            validate_directory_stat(&expected, roots.expected_uid, roots.expected_gid)?;
            let descriptor = openat(
                parent,
                name,
                OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| QualificationCleanupRunnerError::Filesystem)?;
            let opened =
                fstat(&descriptor).map_err(|_| QualificationCleanupRunnerError::Filesystem)?;
            if !same_identity(&expected, &opened) {
                return Err(QualificationCleanupRunnerError::Filesystem);
            }
            let mut child = Dir::from_fd(descriptor)
                .map_err(|_| QualificationCleanupRunnerError::Filesystem)?;
            remove_directory_contents(&mut child, roots, deadline, depth + 1, entries)?;
            drop(child);
            require_time(deadline)?;
            let current = fstatat(parent, name, AtFlags::AT_SYMLINK_NOFOLLOW)
                .map_err(|_| QualificationCleanupRunnerError::Filesystem)?;
            if !same_identity(&expected, &current) {
                return Err(QualificationCleanupRunnerError::Filesystem);
            }
            unlinkat(parent, name, UnlinkatFlags::RemoveDir)
                .map_err(|_| QualificationCleanupRunnerError::Filesystem)
        }
        _ => Err(QualificationCleanupRunnerError::Filesystem),
    }
}

fn exact_child_name<'a, E: std::error::Error + Send + Sync + 'static>(
    expected_parent: &Path,
    target: &'a Path,
) -> Result<&'a OsStr, QualificationCleanupRunnerError<E>> {
    if target.parent() != Some(expected_parent) {
        return Err(QualificationCleanupRunnerError::Filesystem);
    }
    let name = target
        .file_name()
        .ok_or(QualificationCleanupRunnerError::Filesystem)?;
    if name.is_empty() || name.as_bytes().contains(&b'/') {
        return Err(QualificationCleanupRunnerError::Filesystem);
    }
    Ok(name)
}

fn open_directory_path(path: &Path) -> Result<OwnedFd, Errno> {
    if !path.is_absolute() {
        return Err(Errno::EINVAL);
    }
    let mut directory = open(
        "/",
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                directory = openat(
                    &directory,
                    name,
                    OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                    Mode::empty(),
                )?;
            }
            _ => return Err(Errno::EINVAL),
        }
    }
    Ok(directory)
}

fn open_directory_beneath(mut directory: OwnedFd, path: &Path) -> Result<OwnedFd, Errno> {
    for component in path.components() {
        let Component::Normal(name) = component else {
            return Err(Errno::EINVAL);
        };
        directory = openat(
            &directory,
            name,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )?;
    }
    Ok(directory)
}

fn validate_owned_directory<E: std::error::Error + Send + Sync + 'static>(
    directory: &OwnedFd,
    uid: u32,
    gid: u32,
) -> Result<(), QualificationCleanupRunnerError<E>> {
    let stat = fstat(directory).map_err(|_| QualificationCleanupRunnerError::Filesystem)?;
    validate_directory_stat(&stat, uid, gid)
}

fn validate_directory_stat<E: std::error::Error + Send + Sync + 'static>(
    stat: &FileStat,
    uid: u32,
    gid: u32,
) -> Result<(), QualificationCleanupRunnerError<E>> {
    if SFlag::from_bits_truncate(stat.st_mode) != SFlag::S_IFDIR
        || stat.st_uid != uid
        || stat.st_gid != gid
        || stat.st_mode & 0o022 != 0
    {
        return Err(QualificationCleanupRunnerError::Filesystem);
    }
    Ok(())
}

fn validate_owned_regular<E: std::error::Error + Send + Sync + 'static>(
    file: &File,
    uid: u32,
    gid: u32,
    single_link: bool,
) -> Result<(), QualificationCleanupRunnerError<E>> {
    let stat = fstat(file).map_err(|_| QualificationCleanupRunnerError::Filesystem)?;
    validate_regular_stat(&stat, uid, gid, single_link)
}

fn validate_regular_stat<E: std::error::Error + Send + Sync + 'static>(
    stat: &FileStat,
    uid: u32,
    gid: u32,
    single_link: bool,
) -> Result<(), QualificationCleanupRunnerError<E>> {
    if SFlag::from_bits_truncate(stat.st_mode) != SFlag::S_IFREG
        || stat.st_uid != uid
        || stat.st_gid != gid
        || (single_link && stat.st_nlink != 1)
    {
        return Err(QualificationCleanupRunnerError::Filesystem);
    }
    Ok(())
}

fn same_identity(left: &FileStat, right: &FileStat) -> bool {
    left.st_dev == right.st_dev
        && left.st_ino == right.st_ino
        && left.st_mode == right.st_mode
        && left.st_uid == right.st_uid
        && left.st_gid == right.st_gid
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::fs;
    use std::os::unix::fs::symlink;

    use buzz_ci_broker_protocol::GitOid;
    use tempfile::TempDir;

    use crate::qualification_host::QualificationHostBinding;

    #[derive(Debug, Error)]
    #[error("fake command failure")]
    struct FakeCommandError;

    struct FakeResponse {
        output: Result<ExactCommandOutput, FakeCommandError>,
        delay: Duration,
    }

    #[derive(Default)]
    struct FakeCommandRunner {
        responses: VecDeque<FakeResponse>,
        seen: Vec<(AllowedBinary, Vec<OsString>, Duration)>,
    }

    impl FakeCommandRunner {
        fn push(&mut self, output: ExactCommandOutput) {
            self.responses.push_back(FakeResponse {
                output: Ok(output),
                delay: Duration::ZERO,
            });
        }

        fn push_delayed(&mut self, output: ExactCommandOutput, delay: Duration) {
            self.responses.push_back(FakeResponse {
                output: Ok(output),
                delay,
            });
        }
    }

    impl ExactCommandRunner for FakeCommandRunner {
        type Error = FakeCommandError;

        fn run(&mut self, command: &ExactCommand) -> Result<ExactCommandOutput, Self::Error> {
            self.seen
                .push((command.binary(), command.argv().to_vec(), command.timeout()));
            let response = self.responses.pop_front().ok_or(FakeCommandError)?;
            thread::sleep(response.delay);
            response.output
        }
    }

    struct Fixture {
        _temp: TempDir,
        roots: CleanupRoots,
        targets: QualificationCleanupTargets,
        cgroup_procs: PathBuf,
        cgroup_events: PathBuf,
        lease_tree: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let temp = tempfile::tempdir().unwrap();
            let uid = nix::unistd::Uid::current().as_raw();
            let gid = nix::unistd::Gid::current().as_raw();
            let cgroup_root = temp.path().join("cgroup");
            let namespace_root = temp.path().join("netns");
            let lease_root = temp.path().join("leases");
            fs::create_dir_all(cgroup_root.join("buzzci.slice")).unwrap();
            fs::create_dir_all(&namespace_root).unwrap();
            fs::create_dir_all(&lease_root).unwrap();
            let targets = QualificationCleanupTargets::from_binding(binding());
            let cgroup = cgroup_root.join("buzzci.slice").join(targets.lease_slice());
            fs::create_dir(&cgroup).unwrap();
            let cgroup_procs = cgroup.join("cgroup.procs");
            fs::write(&cgroup_procs, b"").unwrap();
            let cgroup_events = cgroup.join("cgroup.events");
            fs::write(&cgroup_events, b"populated 0\nfrozen 0\n").unwrap();
            let lease_tree = lease_root.join(targets.lease_files().file_name().unwrap());
            fs::create_dir(&lease_tree).unwrap();
            fs::create_dir(lease_tree.join("nested")).unwrap();
            fs::write(lease_tree.join("root-file"), b"root").unwrap();
            fs::write(lease_tree.join("nested/child-file"), b"child").unwrap();
            Self {
                _temp: temp,
                roots: CleanupRoots {
                    cgroup_root,
                    namespace_root,
                    lease_root,
                    expected_uid: uid,
                    expected_gid: gid,
                },
                targets,
                cgroup_procs,
                cgroup_events,
                lease_tree,
            }
        }
    }

    fn binding() -> QualificationHostBinding {
        QualificationHostBinding {
            integrated_candidate_sha: GitOid::Sha1([1; 20]),
            broker_build_identity: [2; 32],
            host_profile_digest: [3; 32],
            suite_identity: [4; 32],
            fixture_signer: [5; 32],
            request_digest: [6; 32],
            manifest_digest: [7; 32],
            isolation_profile_digest: [8; 32],
            source_oid: GitOid::Sha1([9; 20]),
            base_oid: GitOid::Sha1([10; 20]),
            job_identity: [11; 32],
            fixture_identity: [12; 32],
            nonce: [13; 32],
            lease_id: [14; 16],
            lease_generation: 1,
        }
    }

    fn success(bytes: impl Into<Vec<u8>>) -> ExactCommandOutput {
        ExactCommandOutput {
            exit_code: Some(0),
            stdout: bytes.into(),
            stderr: Vec::new(),
            stdout_truncated: false,
            stderr_truncated: false,
        }
    }

    fn failure() -> ExactCommandOutput {
        ExactCommandOutput {
            exit_code: Some(1),
            stdout: Vec::new(),
            stderr: b"failed".to_vec(),
            stdout_truncated: false,
            stderr_truncated: false,
        }
    }

    fn mutation_successes(runner: &mut FakeCommandRunner) {
        for _ in 0..4 {
            runner.push(success(Vec::new()));
        }
    }

    fn execute_all(
        runner: &mut ProductionQualificationCleanupRunner<FakeCommandRunner>,
        targets: &QualificationCleanupTargets,
    ) {
        let deadline = QualificationCleanupDeadline::after(Duration::from_secs(1));
        for operation in [
            QualificationCleanupOperation::StopLeaseSlice,
            QualificationCleanupOperation::KillLeaseSlice,
            QualificationCleanupOperation::RemoveLeaseNftTable,
            QualificationCleanupOperation::RemoveLeaseNetworkNamespace,
            QualificationCleanupOperation::RemoveLeaseFiles,
        ] {
            runner.execute(&operation, targets, deadline).unwrap();
        }
    }

    fn runner_ready_for_observation(
        fixture: &Fixture,
        nft: Value,
        namespaces: Value,
    ) -> ProductionQualificationCleanupRunner<FakeCommandRunner> {
        let mut commands = FakeCommandRunner::default();
        mutation_successes(&mut commands);
        commands.push(success(
            b"LoadState=not-found\nActiveState=inactive\n".to_vec(),
        ));
        commands.push(success(serde_json::to_vec(&nft).unwrap()));
        commands.push(success(serde_json::to_vec(&namespaces).unwrap()));
        let mut runner =
            ProductionQualificationCleanupRunner::for_test(commands, fixture.roots.clone());
        execute_all(&mut runner, &fixture.targets);
        runner
    }

    #[test]
    fn cleanup_succeeds_with_exact_commands_and_complete_observation() {
        let fixture = Fixture::new();
        let mut runner = runner_ready_for_observation(
            &fixture,
            serde_json::json!({"nftables": []}),
            serde_json::json!([]),
        );
        let observation = runner
            .observe(
                &fixture.targets,
                QualificationCleanupDeadline::after(Duration::from_secs(1)),
            )
            .unwrap()
            .unwrap();

        assert!(observation.lease_slice_inactive);
        assert!(observation.lease_cgroup_empty);
        assert!(observation.nft_table_absent);
        assert!(observation.namespace_absent);
        assert!(observation.lease_files_absent);
        assert!(observation.teardown_failure_observed);
        assert!(observation.slice_quarantined);
        assert!(!observation.publish_observed);
        assert!(!fixture.lease_tree.exists());
        assert_eq!(runner.commands.seen.len(), 7);
        assert_eq!(
            runner.commands.seen[0].1,
            vec![os("stop"), os(fixture.targets.lease_slice())]
        );
        assert_eq!(
            runner.commands.seen[1].1,
            vec![
                os("kill"),
                os("--kill-whom=all"),
                os("--signal=KILL"),
                os(fixture.targets.lease_slice()),
            ]
        );
    }

    #[test]
    fn every_typed_operation_fails_closed() {
        for failed_index in 0..4 {
            let fixture = Fixture::new();
            let mut commands = FakeCommandRunner::default();
            commands.push(failure());
            let mut runner =
                ProductionQualificationCleanupRunner::for_test(commands, fixture.roots.clone());
            let operation = [
                QualificationCleanupOperation::StopLeaseSlice,
                QualificationCleanupOperation::KillLeaseSlice,
                QualificationCleanupOperation::RemoveLeaseNftTable,
                QualificationCleanupOperation::RemoveLeaseNetworkNamespace,
            ][failed_index]
                .clone();
            let result = runner.execute(
                &operation,
                &fixture.targets,
                QualificationCleanupDeadline::after(Duration::from_secs(1)),
            );
            assert!(matches!(
                result,
                Err(QualificationCleanupRunnerError::CommandFailed)
            ));
        }

        let fixture = Fixture::new();
        fs::remove_dir_all(&fixture.lease_tree).unwrap();
        symlink("elsewhere", &fixture.lease_tree).unwrap();
        let mut runner = ProductionQualificationCleanupRunner::for_test(
            FakeCommandRunner::default(),
            fixture.roots.clone(),
        );
        let result = runner.execute(
            &QualificationCleanupOperation::RemoveLeaseFiles,
            &fixture.targets,
            QualificationCleanupDeadline::after(Duration::from_secs(1)),
        );
        assert!(matches!(
            result,
            Err(QualificationCleanupRunnerError::Filesystem)
        ));
    }

    #[test]
    fn deadline_expiry_mid_sequence_stops_new_commands() {
        let fixture = Fixture::new();
        let mut commands = FakeCommandRunner::default();
        commands.push_delayed(success(Vec::new()), Duration::from_millis(30));
        let mut runner =
            ProductionQualificationCleanupRunner::for_test(commands, fixture.roots.clone());
        let deadline = QualificationCleanupDeadline::after(Duration::from_millis(10));
        assert!(matches!(
            runner.execute(
                &QualificationCleanupOperation::StopLeaseSlice,
                &fixture.targets,
                deadline,
            ),
            Err(QualificationCleanupRunnerError::Deadline)
        ));
        assert!(matches!(
            runner.execute(
                &QualificationCleanupOperation::KillLeaseSlice,
                &fixture.targets,
                deadline,
            ),
            Err(QualificationCleanupRunnerError::Deadline)
        ));
        assert_eq!(runner.commands.seen.len(), 1);
    }

    #[test]
    fn hostile_cgroup_nft_and_namespace_readbacks_stay_incomplete() {
        let fixture = Fixture::new();
        let table = fixture.targets.nft_table().to_owned();
        let namespace = fixture.targets.namespace_name().to_owned();
        let cases = [
            (
                b"42\n".as_slice(),
                b"populated 1\n".as_slice(),
                serde_json::json!({"nftables": []}),
                serde_json::json!([]),
                [false, true, true],
            ),
            (
                b"".as_slice(),
                b"populated 1\n".as_slice(),
                serde_json::json!({"nftables": []}),
                serde_json::json!([]),
                [false, true, true],
            ),
            (
                b"".as_slice(),
                b"populated 0\n".as_slice(),
                serde_json::json!({"nftables": [{"table": {"family": "inet", "name": table}}]}),
                serde_json::json!([]),
                [true, false, true],
            ),
            (
                b"".as_slice(),
                b"populated 0\n".as_slice(),
                serde_json::json!({"nftables": []}),
                serde_json::json!([{"name": namespace}]),
                [true, true, false],
            ),
        ];
        for (cgroup, events, nft, namespaces, expected) in cases {
            let fixture = Fixture::new();
            let mut runner = runner_ready_for_observation(&fixture, nft, namespaces);
            fs::write(&fixture.cgroup_procs, cgroup).unwrap();
            fs::write(&fixture.cgroup_events, events).unwrap();
            let observation = runner
                .observe(
                    &fixture.targets,
                    QualificationCleanupDeadline::after(Duration::from_secs(1)),
                )
                .unwrap()
                .unwrap();
            assert_eq!(observation.lease_cgroup_empty, expected[0]);
            assert_eq!(observation.nft_table_absent, expected[1]);
            assert_eq!(observation.namespace_absent, expected[2]);
        }
    }

    #[test]
    fn symlinked_lease_path_and_wrong_owner_fail_closed() {
        let fixture = Fixture::new();
        fs::remove_dir_all(&fixture.lease_tree).unwrap();
        symlink("elsewhere", &fixture.lease_tree).unwrap();
        let mut runner = ProductionQualificationCleanupRunner::for_test(
            FakeCommandRunner::default(),
            fixture.roots.clone(),
        );
        assert!(matches!(
            runner.execute(
                &QualificationCleanupOperation::RemoveLeaseFiles,
                &fixture.targets,
                QualificationCleanupDeadline::after(Duration::from_secs(1)),
            ),
            Err(QualificationCleanupRunnerError::Filesystem)
        ));

        let fixture = Fixture::new();
        let mut wrong_roots = fixture.roots.clone();
        wrong_roots.expected_uid = wrong_roots.expected_uid.wrapping_add(1);
        let mut runner = ProductionQualificationCleanupRunner::for_test(
            FakeCommandRunner::default(),
            wrong_roots,
        );
        assert!(matches!(
            runner.execute(
                &QualificationCleanupOperation::RemoveLeaseFiles,
                &fixture.targets,
                QualificationCleanupDeadline::after(Duration::from_secs(1)),
            ),
            Err(QualificationCleanupRunnerError::Filesystem)
        ));
        assert!(fixture.lease_tree.exists());
    }

    #[test]
    fn expired_cancel_returns_without_launching_a_child() {
        let fixture = Fixture::new();
        let mut runner = ProductionQualificationCleanupRunner::for_test(
            FakeCommandRunner::default(),
            fixture.roots.clone(),
        );
        let deadline = QualificationCleanupDeadline::after(Duration::from_nanos(1));
        thread::sleep(Duration::from_millis(1));
        assert!(matches!(
            runner.cancel_and_reap(&fixture.targets, deadline),
            Err(QualificationCleanupRunnerError::Deadline)
        ));
        assert!(runner.commands.seen.is_empty());
    }
}
