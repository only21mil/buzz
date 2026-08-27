//! Root-owned cgroup and nft observations for materializer Git commands.
//!
//! The observer retains the broker-opened cgroup directory, binds it to the
//! validated isolation handle, and reads one compiled named nft counter
//! through the shared no-shell command runner. The unprivileged materializer
//! supplies no paths, table names, counter names, or executable choices.

use std::ffi::OsString;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::time::{SystemTime, UNIX_EPOCH};

use buzz_ci_isolation_contract::ValidatedAttemptLeaseBinding;
use buzz_ci_materializer::{CommandSpec, GitHostObservation, GitHostObserver, NetworkScope};
use nix::fcntl::{openat, OFlag};
use nix::sys::stat::{fstat, Mode, SFlag};
use serde_json::Value;
use thiserror::Error;

use crate::dns_exec::{
    AllowedBinary, ExactCommand, ExactCommandOutput, ExactCommandRunner, ProcessCommandRunner,
    COMMAND_TIMEOUT, MAX_COMMAND_OUTPUT,
};
use crate::dns_host::MaterializerNftPlan;

/// Opaque counter checkpoint captured immediately before a Git command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GitHostCheckpoint {
    bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BoundGitHostLease {
    lease_id: String,
    cgroup_token: String,
    netns_token: String,
    materializer_uid: u32,
    cgroup_device: u64,
    cgroup_inode: u64,
    nft_family: String,
    nft_table: String,
    nft_counter: String,
}

/// Production root-side observer for one validated materializer lease.
pub struct ProductionGitHostObserver<R = ProcessCommandRunner> {
    commands: R,
    cgroup_directory: File,
    binding: BoundGitHostLease,
}

impl ProductionGitHostObserver<ProcessCommandRunner> {
    /// Bind the production observer to one validated lease and DNS policy.
    pub fn production(
        lease: &ValidatedAttemptLeaseBinding,
        policy: &MaterializerNftPlan,
        cgroup_directory: File,
    ) -> Result<Self, GitHostObserverBuildError> {
        Self::with_runner(lease, policy, cgroup_directory, ProcessCommandRunner)
    }
}

impl<R> ProductionGitHostObserver<R> {
    /// Bind an observer to root-owned typed policy and an open cgroup handle.
    pub fn with_runner(
        lease: &ValidatedAttemptLeaseBinding,
        policy: &MaterializerNftPlan,
        cgroup_directory: File,
        commands: R,
    ) -> Result<Self, GitHostObserverBuildError> {
        let lease = lease.as_binding();
        if policy.principal_uid() != lease.principals.materializer {
            return Err(GitHostObserverBuildError::PolicyMismatch);
        }
        let binding = BoundGitHostLease {
            lease_id: lease.lease_id.clone(),
            cgroup_token: lease.cgroup.object.token.clone(),
            netns_token: lease.netns.object.token.clone(),
            materializer_uid: lease.principals.materializer,
            cgroup_device: lease.cgroup.object.device,
            cgroup_inode: lease.cgroup.object.inode,
            nft_family: policy.family().to_owned(),
            nft_table: policy.table().to_owned(),
            nft_counter: policy.counter().to_owned(),
        };
        Self::from_bound_parts(binding, cgroup_directory, commands)
    }

    fn from_bound_parts(
        binding: BoundGitHostLease,
        cgroup_directory: File,
        commands: R,
    ) -> Result<Self, GitHostObserverBuildError> {
        verify_cgroup_directory(&cgroup_directory, &binding)
            .map_err(|_| GitHostObserverBuildError::CgroupDescriptor)?;
        Ok(Self {
            commands,
            cgroup_directory,
            binding,
        })
    }

    fn validate_command(&self, command: &CommandSpec) -> Result<(), String> {
        if command.lease_id != self.binding.lease_id
            || command.cgroup_token != self.binding.cgroup_token
            || command.netns_token != self.binding.netns_token
            || command.required_uid != self.binding.materializer_uid
        {
            return Err("Git command does not match the root-owned lease binding".into());
        }
        if matches!(command.network, NetworkScope::Origin { .. })
            && command.maximum_network_bytes == 0
        {
            return Err("networked Git command has no byte allowance".into());
        }
        Ok(())
    }
}

impl<R: ExactCommandRunner> ProductionGitHostObserver<R> {
    fn read_counter(&mut self) -> Result<u64, String> {
        let command = ExactCommand::new(
            AllowedBinary::Nft,
            vec![
                os("-j"),
                os("list"),
                os("counter"),
                os(&self.binding.nft_family),
                os(&self.binding.nft_table),
                os(&self.binding.nft_counter),
            ],
            COMMAND_TIMEOUT,
        );
        let output = self
            .commands
            .run(&command)
            .map_err(|_| "named nft counter read failed".to_owned())?;
        parse_counter_output(
            &output,
            &self.binding.nft_family,
            &self.binding.nft_table,
            &self.binding.nft_counter,
        )
    }

    fn cgroup_empty(&self) -> Result<bool, String> {
        verify_cgroup_directory(&self.cgroup_directory, &self.binding)
            .map_err(|_| "lease cgroup descriptor changed".to_owned())?;
        let descriptor = openat(
            &self.cgroup_directory,
            "cgroup.procs",
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| "lease cgroup process read failed".to_owned())?;
        let stat = fstat(&descriptor).map_err(|_| "lease cgroup process read failed".to_owned())?;
        if SFlag::from_bits_truncate(stat.st_mode) != SFlag::S_IFREG {
            return Err("lease cgroup process file is not regular".into());
        }
        let mut file = File::from(descriptor);
        let mut bytes = Vec::new();
        file.by_ref()
            .take((MAX_COMMAND_OUTPUT + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| "lease cgroup process read failed".to_owned())?;
        if bytes.len() > MAX_COMMAND_OUTPUT {
            return Err("lease cgroup process read exceeded its bound".into());
        }
        Ok(bytes.iter().all(u8::is_ascii_whitespace))
    }
}

impl<R: ExactCommandRunner> GitHostObserver for ProductionGitHostObserver<R> {
    type Checkpoint = GitHostCheckpoint;

    fn before_command(&mut self, command: &CommandSpec) -> Result<Self::Checkpoint, String> {
        self.validate_command(command)?;
        Ok(GitHostCheckpoint {
            bytes: self.read_counter()?,
        })
    }

    fn after_command(
        &mut self,
        checkpoint: Self::Checkpoint,
        command: &CommandSpec,
        process_group_empty: bool,
    ) -> Result<GitHostObservation, String> {
        self.validate_command(command)?;
        if !process_group_empty {
            return Err("Git process group is not empty".into());
        }
        if !self.cgroup_empty()? {
            return Err("lease cgroup is not empty".into());
        }
        let bytes = self.read_counter()?;
        let network_bytes = bytes
            .checked_sub(checkpoint.bytes)
            .ok_or_else(|| "named nft counter moved backwards".to_owned())?;
        let completed_at_unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "trusted host clock is before the Unix epoch".to_owned())?
            .as_secs();
        Ok(GitHostObservation {
            network_bytes,
            cgroup_descendants_empty: true,
            completed_at_unix_seconds,
        })
    }
}

/// Failure to bind the root observer to the supplied capabilities.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GitHostObserverBuildError {
    /// The typed DNS policy belongs to another materializer principal.
    #[error("materializer nft policy does not match the validated lease")]
    PolicyMismatch,
    /// The supplied directory is not the exact cgroup object in the lease.
    #[error("cgroup descriptor does not match the validated lease")]
    CgroupDescriptor,
}

fn verify_cgroup_directory(file: &File, binding: &BoundGitHostLease) -> Result<(), ()> {
    let metadata = file.metadata().map_err(|_| ())?;
    if !metadata.file_type().is_dir()
        || metadata.dev() != binding.cgroup_device
        || metadata.ino() != binding.cgroup_inode
    {
        return Err(());
    }
    Ok(())
}

fn parse_counter_output(
    output: &ExactCommandOutput,
    family: &str,
    table: &str,
    name: &str,
) -> Result<u64, String> {
    if !output.success() || output.stdout_truncated || output.stderr_truncated {
        return Err("named nft counter read was incomplete".into());
    }
    let value: Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| "named nft counter readback is malformed".to_owned())?;
    let objects = value
        .get("nftables")
        .and_then(Value::as_array)
        .ok_or_else(|| "named nft counter readback is malformed".to_owned())?;
    let counters = objects
        .iter()
        .filter_map(|object| object.get("counter"))
        .collect::<Vec<_>>();
    if counters.len() != 1 {
        return Err("named nft counter is missing or ambiguous".into());
    }
    let counter = counters[0];
    if counter.get("family").and_then(Value::as_str) != Some(family)
        || counter.get("table").and_then(Value::as_str) != Some(table)
        || counter.get("name").and_then(Value::as_str) != Some(name)
        || counter.get("packets").and_then(Value::as_u64).is_none()
    {
        return Err("named nft counter identity does not match the lease".into());
    }
    counter
        .get("bytes")
        .and_then(Value::as_u64)
        .ok_or_else(|| "named nft counter byte value is missing".to_owned())
}

fn os(value: impl AsRef<std::ffi::OsStr>) -> OsString {
    value.as_ref().to_os_string()
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, VecDeque};
    use std::fs::{self, OpenOptions};
    use std::os::unix::fs::MetadataExt;
    use std::path::PathBuf;

    use buzz_ci_materializer::GitOperation;
    use thiserror::Error;

    use super::*;
    use crate::dns_host::MATERIALIZER_NFT_COUNTER;

    #[derive(Debug, Error)]
    #[error("fake command failure")]
    struct FakeCommandError;

    #[derive(Default)]
    struct FakeCommandRunner {
        outputs: VecDeque<ExactCommandOutput>,
        seen: Vec<(AllowedBinary, Vec<OsString>)>,
    }

    impl ExactCommandRunner for FakeCommandRunner {
        type Error = FakeCommandError;

        fn run(&mut self, command: &ExactCommand) -> Result<ExactCommandOutput, Self::Error> {
            self.seen.push((command.binary(), command.argv().to_vec()));
            self.outputs.pop_front().ok_or(FakeCommandError)
        }
    }

    fn counter(bytes: u64) -> ExactCommandOutput {
        ExactCommandOutput {
            exit_code: Some(0),
            stdout: serde_json::to_vec(&serde_json::json!({
                "nftables": [
                    {"metainfo": {"json_schema_version": 1}},
                    {"counter": {
                        "family": "inet",
                        "table": "buzzci_lease",
                        "name": MATERIALIZER_NFT_COUNTER,
                        "handle": 9,
                        "packets": 1,
                        "bytes": bytes
                    }}
                ]
            }))
            .unwrap(),
            stderr: Vec::new(),
            stdout_truncated: false,
            stderr_truncated: false,
        }
    }

    fn missing_counter() -> ExactCommandOutput {
        ExactCommandOutput {
            exit_code: Some(0),
            stdout: br#"{"nftables":[{"metainfo":{"json_schema_version":1}}]}"#.to_vec(),
            stderr: Vec::new(),
            stdout_truncated: false,
            stderr_truncated: false,
        }
    }

    fn command() -> CommandSpec {
        CommandSpec {
            operation: GitOperation::Init,
            program: PathBuf::from("/usr/bin/git"),
            arguments: vec!["init".into()],
            current_dir: PathBuf::from("/proc/self/fd/7"),
            clear_environment: true,
            environment: BTreeMap::new(),
            required_uid: 966,
            lease_id: "lease".into(),
            cgroup_token: "cgroup-token".into(),
            netns_token: "netns-token".into(),
            lease_expires_at_unix_seconds: u64::MAX,
            maximum_stdout_bytes: 1024,
            maximum_stderr_bytes: 1024,
            deadline_millis: 1000,
            network: NetworkScope::None,
            maximum_network_bytes: 0,
            maximum_processes: 16,
        }
    }

    fn observer(
        cgroup: &File,
        commands: FakeCommandRunner,
    ) -> ProductionGitHostObserver<FakeCommandRunner> {
        let metadata = cgroup.metadata().unwrap();
        ProductionGitHostObserver::from_bound_parts(
            BoundGitHostLease {
                lease_id: "lease".into(),
                cgroup_token: "cgroup-token".into(),
                netns_token: "netns-token".into(),
                materializer_uid: 966,
                cgroup_device: metadata.dev(),
                cgroup_inode: metadata.ino(),
                nft_family: "inet".into(),
                nft_table: "buzzci_lease".into(),
                nft_counter: MATERIALIZER_NFT_COUNTER.into(),
            },
            cgroup.try_clone().unwrap(),
            commands,
        )
        .unwrap()
    }

    fn cgroup_fixture(procs: &[u8]) -> (tempfile::TempDir, File) {
        let temporary = tempfile::tempdir().unwrap();
        fs::write(temporary.path().join("cgroup.procs"), procs).unwrap();
        let directory = OpenOptions::new()
            .read(true)
            .open(temporary.path())
            .unwrap();
        (temporary, directory)
    }

    #[test]
    fn non_empty_cgroup_refuses_completion() {
        let (_temporary, cgroup) = cgroup_fixture(b"4242\n");
        let mut commands = FakeCommandRunner::default();
        commands.outputs.push_back(counter(10));
        let mut observer = observer(&cgroup, commands);
        let checkpoint = observer.before_command(&command()).unwrap();

        let error = observer
            .after_command(checkpoint, &command(), true)
            .unwrap_err();

        assert_eq!(error, "lease cgroup is not empty");
        assert_eq!(observer.commands.seen.len(), 1);
    }

    #[test]
    fn missing_named_counter_refuses_checkpoint() {
        let (_temporary, cgroup) = cgroup_fixture(b"");
        let mut commands = FakeCommandRunner::default();
        commands.outputs.push_back(missing_counter());
        let mut observer = observer(&cgroup, commands);

        let error = observer.before_command(&command()).unwrap_err();

        assert_eq!(error, "named nft counter is missing or ambiguous");
    }

    #[test]
    fn exact_counter_delta_and_empty_cgroup_complete() {
        let (_temporary, cgroup) = cgroup_fixture(b"\n");
        let mut commands = FakeCommandRunner::default();
        commands.outputs.push_back(counter(10));
        commands.outputs.push_back(counter(42));
        let mut observer = observer(&cgroup, commands);
        let checkpoint = observer.before_command(&command()).unwrap();

        let observation = observer
            .after_command(checkpoint, &command(), true)
            .unwrap();

        assert_eq!(observation.network_bytes, 32);
        assert!(observation.cgroup_descendants_empty);
        assert_eq!(observer.commands.seen.len(), 2);
        assert_eq!(observer.commands.seen[0].0, AllowedBinary::Nft);
        assert_eq!(
            observer.commands.seen[0].1,
            [
                "-j",
                "list",
                "counter",
                "inet",
                "buzzci_lease",
                MATERIALIZER_NFT_COUNTER,
            ]
            .map(OsString::from)
        );
    }

    #[test]
    fn non_empty_process_group_refuses_before_cgroup_or_second_counter_read() {
        let (_temporary, cgroup) = cgroup_fixture(b"");
        let mut commands = FakeCommandRunner::default();
        commands.outputs.push_back(counter(10));
        let mut observer = observer(&cgroup, commands);
        let checkpoint = observer.before_command(&command()).unwrap();

        let error = observer
            .after_command(checkpoint, &command(), false)
            .unwrap_err();

        assert_eq!(error, "Git process group is not empty");
        assert_eq!(observer.commands.seen.len(), 1);
    }

    #[test]
    fn counter_reset_refuses_delta() {
        let (_temporary, cgroup) = cgroup_fixture(b"");
        let mut commands = FakeCommandRunner::default();
        commands.outputs.push_back(counter(42));
        commands.outputs.push_back(counter(10));
        let mut observer = observer(&cgroup, commands);
        let checkpoint = observer.before_command(&command()).unwrap();

        let error = observer
            .after_command(checkpoint, &command(), true)
            .unwrap_err();

        assert_eq!(error, "named nft counter moved backwards");
    }

    #[test]
    fn mismatched_descriptor_refuses_binding() {
        let (_temporary, cgroup) = cgroup_fixture(b"");
        let metadata = cgroup.metadata().unwrap();
        let result = ProductionGitHostObserver::from_bound_parts(
            BoundGitHostLease {
                lease_id: "lease".into(),
                cgroup_token: "cgroup-token".into(),
                netns_token: "netns-token".into(),
                materializer_uid: 966,
                cgroup_device: metadata.dev(),
                cgroup_inode: metadata.ino() + 1,
                nft_family: "inet".into(),
                nft_table: "buzzci_lease".into(),
                nft_counter: MATERIALIZER_NFT_COUNTER.into(),
            },
            cgroup,
            FakeCommandRunner::default(),
        );

        assert!(matches!(
            result,
            Err(GitHostObserverBuildError::CgroupDescriptor)
        ));
    }
}
