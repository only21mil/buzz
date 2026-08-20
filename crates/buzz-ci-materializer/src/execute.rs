use std::collections::BTreeMap;
use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::plan::{MaterializationPlan, NetworkScope};
use crate::tree::{materialize_tree, parse_ls_tree, BlobSource, TreeMaterialization};
use crate::{
    CommandSpec, MaterializationManifest, MaterializationReceipt, MaterializationSlot,
    MaterializeError, RootOwnedPolicy, Sha256Digest,
};

/// Metered output from one broker-executed Git command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandOutput {
    /// True only for a normal zero exit status.
    pub success: bool,
    /// Bounded stdout bytes.
    pub stdout: Vec<u8>,
    /// Bounded stderr bytes.
    pub stderr: Vec<u8>,
    /// Bytes observed by the root-owned egress meter for this command.
    pub network_bytes: u64,
    /// Observed wall time.
    pub elapsed_millis: u64,
    /// Effective UID observed by the trusted backend at child launch.
    pub effective_uid: u32,
}

/// Cleanup evidence returned for every backend outcome, including failures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CleanupProof {
    /// Exact lease whose materializer cgroup was inspected.
    pub lease_id: String,
    /// Exact cgroup capability inspected after process-group termination.
    pub cgroup_token: String,
    /// Exact network namespace capability used for the command.
    pub netns_token: String,
    /// True only after all descendants were killed/reaped and the cgroup read empty.
    pub descendants_empty: bool,
    /// Trusted broker wall clock after cleanup completed.
    pub completed_at_unix_seconds: u64,
}

/// One backend attempt whose cleanup proof cannot be bypassed by an error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandExecution {
    /// Bounded command result; errors must be bounded diagnostic text.
    pub output: Result<CommandOutput, String>,
    /// Out-of-band cleanup evidence produced regardless of command success.
    pub cleanup: CleanupProof,
}

/// Trusted command boundary used by the integrated materializer.
///
/// The implementation must apply the environment, network namespace/egress
/// grant, byte caps, and deadline from `CommandSpec` while the child is
/// running. Returning an oversized buffer and relying on post-validation is
/// not conforming: the checks here are defense in depth, not allocation caps.
pub trait GitBackend {
    /// Trusted current Unix time used to reject queued/expired leases.
    fn now_unix_seconds(&self) -> u64;

    /// Execute exactly one command and always return lease-bound cleanup proof.
    ///
    /// The backend must consume `workspace_directory` as the cwd capability
    /// (same-process pre-exec `fchdir`, or an authenticated descriptor transfer
    /// to an isolated spawner). It must not resolve `current_dir` in an unrelated
    /// process fd table. The procfd string exists only to describe the same
    /// already-open object to an in-process spawner.
    fn run(&mut self, command: &CommandSpec, workspace_directory: &File) -> CommandExecution;
}

/// Digest-verified source that still requires a privileged ownership/mount seal.
///
/// The materializer intentionally cannot claim that Unix mode bits isolate the
/// source from another process with the same UID. A root broker must move or
/// bind-mount `source_path()` read-only for the job before treating `receipt()`
/// as runner-admission evidence.
#[derive(Debug)]
pub struct PendingSeal {
    receipt: MaterializationReceipt,
    source_path: PathBuf,
    workspace: PathBuf,
    source_directory: File,
    workspace_directory: File,
    source_device: u64,
    source_inode: u64,
}

impl PendingSeal {
    /// Verified pre-seal evidence.
    pub fn receipt(&self) -> &MaterializationReceipt {
        &self.receipt
    }

    /// Digest-verified source tree awaiting a privileged seal.
    pub fn source_path(&self) -> &Path {
        &self.source_path
    }

    /// Fresh attempt workspace retained for broker-owned cleanup.
    pub fn workspace(&self) -> &Path {
        &self.workspace
    }

    /// Already-open verified source directory for the privileged sealing step.
    pub fn source_directory(&self) -> &File {
        &self.source_directory
    }

    /// Already-open attempt workspace retained for broker-owned cleanup.
    pub fn workspace_directory(&self) -> &File {
        &self.workspace_directory
    }

    /// Device/inode read back from the pinned source directory.
    pub fn source_identity(&self) -> (u64, u64) {
        (self.source_device, self.source_inode)
    }
}

#[derive(Default)]
struct Meter {
    network_bytes: u64,
    elapsed_millis: u64,
}

/// Execute and verify one complete materialization attempt.
///
/// This is the only public route to publication. It consumes a fresh slot,
/// verifies the effective root policy digest, reads source/tree/trusted-base
/// identities back from Git, obtains workflow bytes from that exact trusted
/// base, materializes only raw blobs, and returns a typed pending-seal result.
pub fn execute_materialization(
    manifest: &MaterializationManifest,
    canonical_inputs: &[u8],
    policy: &RootOwnedPolicy,
    mut slot: MaterializationSlot,
    backend: &mut dyn GitBackend,
) -> Result<PendingSeal, MaterializeError> {
    manifest.validate()?;
    slot.verify_manifest(manifest)?;
    slot.verify_workspace_descriptor()?;
    verify_digest("policy_sha256", &manifest.policy_sha256, policy.digest())?;
    verify_digest(
        "inputs_sha256",
        &manifest.inputs_sha256,
        &digest(canonical_inputs),
    )?;
    create_fresh_workspace(&slot)?;
    let filesystem_root = slot.filesystem_root()?;
    fs::create_dir(filesystem_root.join("home"))?;
    fs::set_permissions(
        filesystem_root.join("home"),
        fs::Permissions::from_mode(0o700),
    )?;

    let plan = MaterializationPlan::build(manifest, policy, &slot)?;
    let mut meter = Meter::default();
    // init, fetch, source commit, source tree, trusted-base commit, ls-tree,
    // trusted-base workflow bytes.
    if plan.commands.len() != 7 {
        return Err(MaterializeError::InvalidPolicy(
            "internal Git plan shape changed".into(),
        ));
    }
    run_bounded(backend, &plan.commands[0], policy, &mut meter, &slot)?;
    run_bounded(backend, &plan.commands[1], policy, &mut meter, &slot)?;
    let source_readback = run_bounded(backend, &plan.commands[2], policy, &mut meter, &slot)?;
    let tree_readback = run_bounded(backend, &plan.commands[3], policy, &mut meter, &slot)?;
    let trusted_base_readback = run_bounded(backend, &plan.commands[4], policy, &mut meter, &slot)?;
    plan.verify_readbacks(
        &source_readback.stdout,
        &tree_readback.stdout,
        &trusted_base_readback.stdout,
    )?;
    let tree_listing = run_bounded(backend, &plan.commands[5], policy, &mut meter, &slot)?;
    let trusted_workflow = run_bounded(backend, &plan.commands[6], policy, &mut meter, &slot)?;
    verify_digest(
        "workflow_sha256",
        &manifest.workflow_sha256,
        &digest(&trusted_workflow.stdout),
    )?;

    let entries = parse_ls_tree(
        &tree_listing.stdout,
        plan.commands[5].maximum_stdout_bytes,
        policy.limits().max_entries,
    )?;
    let declared_bytes = entries.iter().try_fold(0_u64, |total, entry| {
        total
            .checked_add(entry.size)
            .ok_or_else(|| MaterializeError::ResourceLimit("checkout bytes".into()))
    })?;
    if declared_bytes > policy.limits().max_checkout_bytes {
        return Err(MaterializeError::ResourceLimit("checkout bytes".into()));
    }

    let mut blobs = MemoryBlobs::default();
    for entry in &entries {
        if entry.size > policy.limits().max_blob_bytes {
            return Err(MaterializeError::ResourceLimit("blob bytes".into()));
        }
        let command = plan.blob_command(&entry.object_id)?;
        let output = run_bounded(backend, &command, policy, &mut meter, &slot)?;
        if output.stdout.len() as u64 != entry.size {
            return Err(MaterializeError::DigestMismatch {
                field: "blob_size",
                expected: entry.size.to_string(),
                actual: output.stdout.len().to_string(),
            });
        }
        // Multiple paths may legitimately share a blob. The retained bytes are
        // already bound to the same object ID, so replacement is safe.
        drop(blobs.0.insert(entry.object_id.clone(), output.stdout));
    }

    let now = || backend.now_unix_seconds();
    let publication = materialize_tree(
        TreeMaterialization {
            manifest,
            entries: &entries,
            staging: &plan.staging_tree,
            destination: &plan.destination_tree,
            maximum_blob_bytes: policy.limits().max_blob_bytes,
            maximum_checkout_bytes: policy.limits().max_checkout_bytes,
            maximum_entries: policy.limits().max_entries,
            maximum_path_bytes: policy.limits().max_path_bytes,
            maximum_depth: policy.limits().max_depth,
            trusted_workflow: &trusted_workflow.stdout,
            canonical_inputs,
            now_unix_seconds: &now,
            expires_at_unix_seconds: slot.lease_expires_at_unix_seconds(),
        },
        &mut blobs,
    )?;

    let workspace_directory = slot.take_workspace_directory()?;
    let source_path = PathBuf::from(format!(
        "/proc/self/fd/{}",
        publication.directory.as_raw_fd()
    ));
    Ok(PendingSeal {
        receipt: publication.receipt,
        source_path,
        workspace: slot.workspace().to_path_buf(),
        source_directory: publication.directory,
        workspace_directory,
        source_device: publication.device,
        source_inode: publication.inode,
    })
}

fn run_bounded(
    backend: &mut dyn GitBackend,
    command: &CommandSpec,
    policy: &RootOwnedPolicy,
    meter: &mut Meter,
    slot: &MaterializationSlot,
) -> Result<CommandOutput, MaterializeError> {
    let now = backend.now_unix_seconds();
    if now >= command.lease_expires_at_unix_seconds {
        return Err(MaterializeError::InvalidPolicy(
            "attempt lease expired before Git command".into(),
        ));
    }
    let maximum_attempt_millis = policy
        .limits()
        .deadline_seconds
        .checked_mul(1_000)
        .ok_or_else(|| MaterializeError::InvalidPolicy("deadline overflow".into()))?;
    let remaining_millis = maximum_attempt_millis
        .checked_sub(meter.elapsed_millis)
        .ok_or_else(|| MaterializeError::ResourceLimit("attempt deadline".into()))?;
    let remaining_wire = policy
        .limits()
        .max_wire_bytes
        .checked_sub(meter.network_bytes)
        .ok_or_else(|| MaterializeError::ResourceLimit("wire bytes".into()))?;
    let mut effective = command.clone();
    let lease_remaining_millis = command
        .lease_expires_at_unix_seconds
        .saturating_sub(now)
        .saturating_mul(1_000);
    effective.deadline_millis = effective
        .deadline_millis
        .min(remaining_millis)
        .min(lease_remaining_millis);
    effective.maximum_network_bytes = effective.maximum_network_bytes.min(remaining_wire);
    let execution = backend.run(&effective, slot.workspace_directory()?);
    if execution.cleanup.lease_id != effective.lease_id
        || execution.cleanup.cgroup_token != effective.cgroup_token
        || execution.cleanup.netns_token != effective.netns_token
    {
        return Err(MaterializeError::InvalidPolicy(
            "backend cleanup proof does not match the command lease".into(),
        ));
    }
    if !execution.cleanup.descendants_empty {
        return Err(MaterializeError::InvalidPolicy(
            "Git backend left a materializer descendant running".into(),
        ));
    }
    if execution.cleanup.completed_at_unix_seconds >= effective.lease_expires_at_unix_seconds {
        return Err(MaterializeError::InvalidPolicy(
            "Git command cleanup completed after lease expiry".into(),
        ));
    }
    let output = execution
        .output
        .map_err(|stderr| MaterializeError::CommandFailed {
            stderr: bounded_diagnostic(&stderr),
        })?;
    if output.stdout.len() as u64 > effective.maximum_stdout_bytes {
        return Err(MaterializeError::ResourceLimit(
            "command stdout bytes".into(),
        ));
    }
    if output.stderr.len() as u64 > effective.maximum_stderr_bytes {
        return Err(MaterializeError::ResourceLimit(
            "command stderr bytes".into(),
        ));
    }
    if output.elapsed_millis > effective.deadline_millis {
        return Err(MaterializeError::ResourceLimit("command deadline".into()));
    }
    if output.effective_uid != effective.required_uid {
        return Err(MaterializeError::InvalidPolicy(
            "Git backend ran under the wrong UID".into(),
        ));
    }
    if matches!(&effective.network, NetworkScope::None) && output.network_bytes != 0 {
        return Err(MaterializeError::InvalidPolicy(
            "network observed for a network-denied command".into(),
        ));
    }
    if output.network_bytes > effective.maximum_network_bytes {
        return Err(MaterializeError::ResourceLimit("command wire bytes".into()));
    }
    meter.network_bytes = meter
        .network_bytes
        .checked_add(output.network_bytes)
        .ok_or_else(|| MaterializeError::ResourceLimit("wire bytes".into()))?;
    meter.elapsed_millis = meter
        .elapsed_millis
        .checked_add(output.elapsed_millis)
        .ok_or_else(|| MaterializeError::ResourceLimit("attempt deadline".into()))?;
    if meter.network_bytes > policy.limits().max_wire_bytes {
        return Err(MaterializeError::ResourceLimit("wire bytes".into()));
    }
    if meter.elapsed_millis > maximum_attempt_millis {
        return Err(MaterializeError::ResourceLimit("attempt deadline".into()));
    }
    if !output.success {
        return Err(MaterializeError::CommandFailed {
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    Ok(output)
}

fn bounded_diagnostic(value: &str) -> String {
    value.chars().take(8_192).collect()
}

fn create_fresh_workspace(slot: &MaterializationSlot) -> Result<(), MaterializeError> {
    let workspace = slot.filesystem_root()?;
    slot.verify_workspace_descriptor()?;
    let metadata = fs::metadata(&workspace)?;
    slot.verify_workspace_metadata(&metadata)?;
    if metadata.permissions().mode() & 0o777 != 0o700 {
        return Err(MaterializeError::InvalidPolicy(
            "workspace mode changed before materialization".into(),
        ));
    }
    if fs::read_dir(workspace)?.next().transpose()?.is_some() {
        return Err(MaterializeError::InvalidPolicy(
            "attempt workspace must be fresh and empty".into(),
        ));
    }
    Ok(())
}

#[derive(Default)]
struct MemoryBlobs(BTreeMap<String, Vec<u8>>);

impl BlobSource for MemoryBlobs {
    fn read_blob(
        &mut self,
        object_id: &str,
        maximum_bytes: u64,
    ) -> Result<Vec<u8>, MaterializeError> {
        let bytes = self
            .0
            .get(object_id)
            .cloned()
            .ok_or_else(|| MaterializeError::InvalidManifest("missing fetched blob".into()))?;
        if bytes.len() as u64 > maximum_bytes {
            return Err(MaterializeError::ResourceLimit("blob bytes".into()));
        }
        Ok(bytes)
    }
}

fn verify_digest(
    field: &'static str,
    expected: &Sha256Digest,
    actual: &Sha256Digest,
) -> Result<(), MaterializeError> {
    if expected == actual {
        return Ok(());
    }
    Err(MaterializeError::DigestMismatch {
        field,
        expected: expected.as_str().into(),
        actual: actual.as_str().into(),
    })
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_sha256_bytes(Sha256::digest(bytes).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MaterializationLimits;
    use std::collections::{BTreeMap, VecDeque};
    use std::os::unix::fs::MetadataExt;
    use url::Url;

    #[derive(Default)]
    struct FakeBackend {
        outputs: VecDeque<CommandOutput>,
        commands: Vec<CommandSpec>,
    }

    impl GitBackend for FakeBackend {
        fn now_unix_seconds(&self) -> u64 {
            1_000
        }

        fn run(&mut self, command: &CommandSpec, _workspace_directory: &File) -> CommandExecution {
            self.commands.push(command.clone());
            let output = self
                .outputs
                .pop_front()
                .ok_or_else(|| "unexpected test command".into());
            CommandExecution {
                output,
                cleanup: CleanupProof {
                    lease_id: command.lease_id.clone(),
                    cgroup_token: command.cgroup_token.clone(),
                    netns_token: command.netns_token.clone(),
                    descendants_empty: true,
                    completed_at_unix_seconds: 1_001,
                },
            }
        }
    }

    fn output(stdout: impl Into<Vec<u8>>) -> CommandOutput {
        CommandOutput {
            success: true,
            stdout: stdout.into(),
            stderr: Vec::new(),
            network_bytes: 0,
            elapsed_millis: 1,
            effective_uid: current_uid(),
        }
    }

    fn policy() -> RootOwnedPolicy {
        RootOwnedPolicy::new(
            "/usr/bin/git".into(),
            "/usr/lib/git-core".into(),
            BTreeMap::from([(
                format!("30617:{}:buzz", "e".repeat(64)),
                Url::parse("https://relay.example/git/owner/repo").unwrap(),
            )]),
            MaterializationLimits {
                max_wire_bytes: 1_000,
                max_blob_bytes: 1_024,
                max_checkout_bytes: 4_096,
                max_entries: 10,
                max_path_bytes: 100,
                max_depth: 5,
                deadline_seconds: 5,
            },
        )
        .unwrap()
    }

    fn current_uid() -> u32 {
        fs::metadata(".").unwrap().uid()
    }

    fn test_slot(workspace: PathBuf) -> MaterializationSlot {
        fs::create_dir(&workspace).unwrap();
        fs::set_permissions(&workspace, fs::Permissions::from_mode(0o700)).unwrap();
        let mut slot = MaterializationSlot::for_test(workspace, current_uid());
        slot.set_workflow_digest_for_test(digest(b"name: CI\n"));
        slot
    }

    fn checkout_digest() -> Sha256Digest {
        let mut hasher = Sha256::new();
        hasher.update(8_u64.to_be_bytes());
        hasher.update(b"file.txt");
        hasher.update(3_u64.to_be_bytes());
        hasher.update(b"abc");
        Sha256Digest::parse(hex::encode(hasher.finalize())).unwrap()
    }

    fn manifest(policy: &RootOwnedPolicy) -> MaterializationManifest {
        MaterializationManifest {
            schema_version: 1,
            request_event_id: "f".repeat(64),
            run_id: "018f47a2-7f0f-7cc1-9a55-01f93e42b1e0".into(),
            source_sha: "a".repeat(40),
            job_id: "linux".into(),
            attempt: 1,
            repo_coordinate: format!("30617:{}:buzz", "e".repeat(64)),
            workflow_id: "required-ci".into(),
            lease_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            tree_oid: "b".repeat(40),
            trusted_base_sha: "c".repeat(40),
            workflow_path: ".github/workflows/ci.yml".into(),
            workflow_sha256: digest(b"name: CI\n"),
            checkout_sha256: checkout_digest(),
            inputs_sha256: digest(b"{}"),
            policy_sha256: policy.digest().clone(),
        }
    }

    fn successful_backend() -> FakeBackend {
        let listing = format!("100644 blob {} 3\tfile.txt\0", "d".repeat(40));
        let mut fetch = output(Vec::new());
        fetch.network_bytes = 100;
        FakeBackend {
            outputs: VecDeque::from([
                output(Vec::new()),
                fetch,
                output(format!("{}\n", "a".repeat(40))),
                output(format!("{}\n", "b".repeat(40))),
                output(format!("{}\n", "c".repeat(40))),
                output(listing),
                output(b"name: CI\n".to_vec()),
                output(b"abc".to_vec()),
            ]),
            commands: Vec::new(),
        }
    }

    #[test]
    fn integrated_path_binds_readbacks_workflow_blobs_and_receipt() {
        let temporary = tempfile::tempdir().unwrap();
        let workspace = temporary.path().join("attempt");
        let slot = test_slot(workspace.clone());
        let policy = policy();
        let manifest = manifest(&policy);
        let mut backend = successful_backend();

        let pending =
            execute_materialization(&manifest, b"{}", &policy, slot, &mut backend).unwrap();

        assert_eq!(pending.receipt().request_event_id(), "f".repeat(64));
        assert_eq!(
            pending.receipt().run_id(),
            "018f47a2-7f0f-7cc1-9a55-01f93e42b1e0"
        );
        assert_eq!(
            pending.receipt().repo_coordinate(),
            format!("30617:{}:buzz", "e".repeat(64))
        );
        assert_eq!(pending.receipt().source_sha(), "a".repeat(40));
        assert_eq!(pending.receipt().tree_oid(), "b".repeat(40));
        assert_eq!(pending.receipt().trusted_base_sha(), "c".repeat(40));
        assert_eq!(pending.receipt().workflow_id(), "required-ci");
        assert_eq!(pending.receipt().job_id(), "linux");
        assert_eq!(pending.receipt().attempt(), 1);
        assert_eq!(pending.receipt().lease_id(), "01ARZ3NDEKTSV4RRFFQ69G5FAV");
        assert_eq!(pending.receipt().policy_sha256(), policy.digest());
        assert_eq!(
            fs::read(pending.source_path().join("file.txt")).unwrap(),
            b"abc"
        );
        assert_eq!(backend.commands.len(), 8);
        assert!(matches!(
            &backend.commands[1].network,
            NetworkScope::Origin { .. }
        ));
        assert!(backend
            .commands
            .iter()
            .enumerate()
            .all(|(index, command)| index == 1 || matches!(&command.network, NetworkScope::None)));
    }

    #[test]
    fn trusted_base_mismatch_stops_before_tree_or_workflow_reads() {
        let temporary = tempfile::tempdir().unwrap();
        let slot = test_slot(temporary.path().join("attempt"));
        let policy = policy();
        let manifest = manifest(&policy);
        let mut backend = successful_backend();
        backend.outputs[4] = output(format!("{}\n", "e".repeat(40)));

        let error =
            execute_materialization(&manifest, b"{}", &policy, slot, &mut backend).unwrap_err();

        assert!(matches!(error, MaterializeError::DigestMismatch { .. }));
        assert_eq!(backend.commands.len(), 5);
    }

    #[test]
    fn policy_digest_and_fresh_slot_are_mandatory() {
        let temporary = tempfile::tempdir().unwrap();
        let policy = policy();
        let mut mismatched_manifest = manifest(&policy);
        mismatched_manifest.policy_sha256 = digest(b"other policy");
        let workspace = temporary.path().join("attempt");
        let slot = test_slot(workspace.clone());
        let mut backend = FakeBackend::default();
        assert!(matches!(
            execute_materialization(&mismatched_manifest, b"{}", &policy, slot, &mut backend),
            Err(MaterializeError::DigestMismatch { .. })
        ));
        assert!(workspace.read_dir().unwrap().next().is_none());
        assert!(backend.commands.is_empty());

        fs::write(workspace.join("stale"), b"stale").unwrap();
        let slot = MaterializationSlot::for_test(workspace, current_uid());
        let manifest = manifest(&policy);
        assert!(matches!(
            execute_materialization(&manifest, b"{}", &policy, slot, &mut backend),
            Err(MaterializeError::InvalidPolicy(_))
        ));
    }

    #[test]
    fn backend_metrics_fail_closed_before_unbounded_work_continues() {
        let temporary = tempfile::tempdir().unwrap();
        let slot = test_slot(temporary.path().join("attempt"));
        let policy = policy();
        let manifest = manifest(&policy);
        let mut fetch = output(Vec::new());
        fetch.network_bytes = policy.limits().max_wire_bytes + 1;
        let mut backend = FakeBackend {
            outputs: VecDeque::from([output(Vec::new()), fetch]),
            commands: Vec::new(),
        };

        assert!(matches!(
            execute_materialization(&manifest, b"{}", &policy, slot, &mut backend),
            Err(MaterializeError::ResourceLimit(_))
        ));
        assert_eq!(backend.commands.len(), 2);
    }

    #[test]
    fn every_backend_boundary_metric_is_checked() {
        let policy = policy();
        let mut oversized_stdout = output(vec![0; 4 * 1024 + 1]);
        let mut oversized_stderr = output(Vec::new());
        oversized_stderr.stderr = vec![0; 64 * 1024 + 1];
        let mut overdue = output(Vec::new());
        overdue.elapsed_millis = policy.limits().deadline_seconds * 1_000 + 1;
        let mut wrong_uid = output(Vec::new());
        wrong_uid.effective_uid = current_uid() ^ 1;
        let mut forbidden_network = output(Vec::new());
        forbidden_network.network_bytes = 1;
        for first_output in [
            &mut oversized_stdout,
            &mut oversized_stderr,
            &mut overdue,
            &mut wrong_uid,
            &mut forbidden_network,
        ] {
            let temporary = tempfile::tempdir().unwrap();
            let slot = test_slot(temporary.path().join("attempt"));
            let manifest = manifest(&policy);
            let mut backend = FakeBackend {
                outputs: VecDeque::from([first_output.clone()]),
                commands: Vec::new(),
            };
            assert!(
                execute_materialization(&manifest, b"{}", &policy, slot, &mut backend).is_err()
            );
            assert_eq!(backend.commands.len(), 1);
        }
    }

    #[test]
    fn backend_error_cannot_bypass_lease_bound_cleanup_proof() {
        struct FailingBackend {
            descendants_empty: bool,
        }

        impl GitBackend for FailingBackend {
            fn now_unix_seconds(&self) -> u64 {
                1_000
            }

            fn run(
                &mut self,
                command: &CommandSpec,
                _workspace_directory: &File,
            ) -> CommandExecution {
                CommandExecution {
                    output: Err("spawn failed after child creation".into()),
                    cleanup: CleanupProof {
                        lease_id: command.lease_id.clone(),
                        cgroup_token: command.cgroup_token.clone(),
                        netns_token: command.netns_token.clone(),
                        descendants_empty: self.descendants_empty,
                        completed_at_unix_seconds: 1_001,
                    },
                }
            }
        }

        for (descendants_empty, expected_policy_error) in [(false, true), (true, false)] {
            let temporary = tempfile::tempdir().unwrap();
            let slot = test_slot(temporary.path().join("attempt"));
            let policy = policy();
            let manifest = manifest(&policy);
            let error = execute_materialization(
                &manifest,
                b"{}",
                &policy,
                slot,
                &mut FailingBackend { descendants_empty },
            )
            .unwrap_err();
            assert_eq!(
                matches!(error, MaterializeError::InvalidPolicy(_)),
                expected_policy_error
            );
        }
    }

    #[test]
    fn queued_or_overrunning_lease_fails_closed() {
        let temporary = tempfile::tempdir().unwrap();
        let mut slot = test_slot(temporary.path().join("attempt"));
        slot.set_expiry_for_test(1_000);
        let policy = policy();
        let manifest = manifest(&policy);
        let mut backend = successful_backend();

        assert!(matches!(
            execute_materialization(&manifest, b"{}", &policy, slot, &mut backend),
            Err(MaterializeError::InvalidPolicy(_))
        ));
        assert!(backend.commands.is_empty());
    }
}
