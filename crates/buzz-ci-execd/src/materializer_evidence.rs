//! Translation from materializer-owned receipts into broker evidence records.

use std::path::PathBuf;

use buzz_ci_materializer::{
    GitCommandLog, GitOperation, MaterializationReceipt as SourceReceipt, Sha256Digest,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::evidence::{
    CommandCeilings, CommandResult, Digest32, EvidenceStore, GitObjectId, HardenedEnvironment,
    MaterializedInputDigest, MaterializerCommandRecord, MaterializerOperation, MaterializerReceipt,
    PublicationError,
};

/// Broker-owned fields that are not claims made by the unprivileged materializer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializerEvidenceContext {
    /// Digest from the authenticated ordinary admission.
    pub manifest_sha256: [u8; 32],
    /// Broker-resolved input records bound to the admitted job.
    pub input_digests: Vec<MaterializedInputDigest>,
}

/// Validated records ready for `EvidenceStore` publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaterializerEvidenceRecords {
    pub receipt: MaterializerReceipt,
    pub commands: Vec<MaterializerCommandRecord>,
}

#[derive(Debug, Error)]
pub enum MaterializerEvidenceError {
    #[error("materializer evidence does not satisfy the translation contract")]
    Invalid,
    #[error("materializer evidence publication failed")]
    Publication(#[from] PublicationError),
}

/// Translate one completed materialization without publishing it.
pub fn translate_materializer_evidence(
    receipt: &SourceReceipt,
    commands: &[GitCommandLog],
    context: MaterializerEvidenceContext,
) -> Result<MaterializerEvidenceRecords, MaterializerEvidenceError> {
    translate_receipt_source(receipt, commands, context)
}

/// Translate and publish `commands.jsonl` followed by `receipt.json`.
pub fn publish_materializer_evidence(
    store: &EvidenceStore,
    receipt: &SourceReceipt,
    commands: &[GitCommandLog],
    context: MaterializerEvidenceContext,
) -> Result<MaterializerEvidenceRecords, MaterializerEvidenceError> {
    let records = translate_materializer_evidence(receipt, commands, context)?;
    for command in &records.commands {
        store.append_materializer_command(command)?;
    }
    store.publish_materializer_receipt(&records.receipt)?;
    Ok(records)
}

trait ReceiptSource {
    fn lease_id(&self) -> &str;
    fn source_sha(&self) -> &str;
    fn tree_oid(&self) -> &str;
    fn workflow_blob_oid(&self) -> &str;
    fn workflow_sha256(&self) -> &Sha256Digest;
    fn inputs_sha256(&self) -> &Sha256Digest;
}

impl ReceiptSource for SourceReceipt {
    fn lease_id(&self) -> &str {
        self.lease_id()
    }

    fn source_sha(&self) -> &str {
        self.source_sha()
    }

    fn tree_oid(&self) -> &str {
        self.tree_oid()
    }

    fn workflow_blob_oid(&self) -> &str {
        self.workflow_blob_oid()
    }

    fn workflow_sha256(&self) -> &Sha256Digest {
        self.workflow_sha256()
    }

    fn inputs_sha256(&self) -> &Sha256Digest {
        self.inputs_sha256()
    }
}

fn translate_receipt_source(
    receipt: &impl ReceiptSource,
    commands: &[GitCommandLog],
    context: MaterializerEvidenceContext,
) -> Result<MaterializerEvidenceRecords, MaterializerEvidenceError> {
    if commands.is_empty()
        || context.manifest_sha256 == [0; 32]
        || context.input_digests.len() > 127
    {
        return Err(MaterializerEvidenceError::Invalid);
    }
    let mut translated = Vec::with_capacity(commands.len());
    for (index, command) in commands.iter().enumerate() {
        let sequence = u64::try_from(index + 1).map_err(|_| MaterializerEvidenceError::Invalid)?;
        if command.sequence != sequence || command.command.lease_id != receipt.lease_id() {
            return Err(MaterializerEvidenceError::Invalid);
        }
        if command.result.exit_code != Some(0)
            || command.result.timed_out
            || command.result.stdout_truncated
            || command.result.stderr_truncated
            || command.result.stdout_bytes > command.command.maximum_stdout_bytes
            || command.result.stderr_bytes > command.command.maximum_stderr_bytes
        {
            return Err(MaterializerEvidenceError::Invalid);
        }
        translated.push(translate_command(command)?);
    }
    let completed_at_unix_ns = translated
        .last()
        .map(|command| command.finished_at_unix_ns)
        .filter(|timestamp| *timestamp != 0)
        .ok_or(MaterializerEvidenceError::Invalid)?;
    let source = parse_object_id(receipt.source_sha())?;
    let mut input_digests = Vec::with_capacity(context.input_digests.len() + 1);
    input_digests.push(MaterializedInputDigest {
        kind: crate::evidence::MaterializedInputKind::JobDefinition,
        name_sha256: Digest32(Sha256::digest(b"buzz-ci-materializer-canonical-inputs-v1").into()),
        value_sha256: parse_digest(receipt.inputs_sha256())?,
    });
    input_digests.extend(context.input_digests);
    Ok(MaterializerEvidenceRecords {
        receipt: MaterializerReceipt {
            lease_id: receipt.lease_id().to_owned(),
            requested_commit_oid: source,
            exact_commit_oid: source,
            exact_tree_oid: parse_object_id(receipt.tree_oid())?,
            exact_workflow_blob_oid: parse_object_id(receipt.workflow_blob_oid())?,
            workflow_sha256: parse_digest(receipt.workflow_sha256())?,
            manifest_sha256: Digest32(context.manifest_sha256),
            input_digests,
            completed_at_unix_ns,
        },
        commands: translated,
    })
}

fn translate_command(
    value: &GitCommandLog,
) -> Result<MaterializerCommandRecord, MaterializerEvidenceError> {
    let command = &value.command;
    let wall_seconds = command
        .deadline_millis
        .checked_add(999)
        .and_then(|value| u32::try_from(value / 1_000).ok())
        .filter(|value| *value != 0)
        .ok_or(MaterializerEvidenceError::Invalid)?;
    let home = command
        .environment
        .get("HOME")
        .map(PathBuf::from)
        .ok_or(MaterializerEvidenceError::Invalid)?;
    let locale = command
        .environment
        .get("LC_ALL")
        .cloned()
        .ok_or(MaterializerEvidenceError::Invalid)?;
    let mut argv = Vec::with_capacity(command.arguments.len() + 1);
    argv.push("git".to_owned());
    argv.extend(command.arguments.iter().cloned());
    Ok(MaterializerCommandRecord {
        lease_id: command.lease_id.clone(),
        sequence: value.sequence,
        operation: match command.operation {
            GitOperation::Init => MaterializerOperation::Init,
            GitOperation::FetchExactObject => MaterializerOperation::FetchExactObject,
            GitOperation::ReadCommit => MaterializerOperation::ReadCommit,
            GitOperation::ReadTree | GitOperation::ReadBlob => MaterializerOperation::ReadTree,
            GitOperation::ReadWorkflow => MaterializerOperation::ReadWorkflow,
        },
        argv,
        environment: HardenedEnvironment {
            clear_environment: command.clear_environment,
            home,
            locale,
            git_config_nosystem: command.environment.get("GIT_CONFIG_NOSYSTEM")
                == Some(&"1".to_owned()),
            git_terminal_prompt: command.environment.get("GIT_TERMINAL_PROMPT")
                != Some(&"0".to_owned()),
            git_askpass_disabled: command.environment.get("GIT_ASKPASS")
                == Some(&"/bin/false".to_owned()),
            credential_helper_disabled: command.environment.get("GIT_CONFIG_KEY_0")
                == Some(&"credential.helper".to_owned())
                && command.environment.get("GIT_CONFIG_VALUE_0") == Some(&String::new()),
            hooks_path_dev_null: command.environment.get("GIT_CONFIG_KEY_1")
                == Some(&"core.hooksPath".to_owned())
                && command.environment.get("GIT_CONFIG_VALUE_1") == Some(&"/dev/null".to_owned()),
        },
        ceilings: CommandCeilings {
            wall_seconds,
            output_bytes: command
                .maximum_stdout_bytes
                .max(command.maximum_stderr_bytes),
            process_count: command.maximum_processes,
        },
        result: CommandResult {
            exit_code: value.result.exit_code.unwrap_or(-1),
            timed_out: value.result.timed_out,
            stdout_sha256: parse_digest(&value.result.stdout_sha256)?,
            stderr_sha256: parse_digest(&value.result.stderr_sha256)?,
            stdout_bytes: value.result.stdout_bytes,
            stderr_bytes: value.result.stderr_bytes,
        },
        started_at_unix_ns: value.started_at_unix_ns,
        finished_at_unix_ns: value.finished_at_unix_ns,
    })
}

fn parse_object_id(value: &str) -> Result<GitObjectId, MaterializerEvidenceError> {
    let bytes = hex::decode(value).map_err(|_| MaterializerEvidenceError::Invalid)?;
    match bytes.len() {
        20 => Ok(GitObjectId::Sha1(
            bytes
                .try_into()
                .map_err(|_| MaterializerEvidenceError::Invalid)?,
        )),
        32 => Ok(GitObjectId::Sha256(
            bytes
                .try_into()
                .map_err(|_| MaterializerEvidenceError::Invalid)?,
        )),
        _ => Err(MaterializerEvidenceError::Invalid),
    }
}

fn parse_digest(value: &Sha256Digest) -> Result<Digest32, MaterializerEvidenceError> {
    let bytes = hex::decode(value.as_str()).map_err(|_| MaterializerEvidenceError::Invalid)?;
    Ok(Digest32(
        bytes
            .try_into()
            .map_err(|_| MaterializerEvidenceError::Invalid)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use buzz_ci_materializer::{CommandSpec, GitCommandResultLog, NetworkScope};
    use std::collections::BTreeMap;
    use std::fs;

    use crate::evidence::{
        DnsReadback, LeaseLimits, LeaseRecord, ResourcePropertyReadback, SeccompEvidence,
        SECCOMP_PROFILE_PATH, SECCOMP_PROFILE_SHA256,
    };

    struct FakeReceipt {
        lease_id: String,
        source: String,
        tree: String,
        workflow_blob: String,
        workflow_digest: Sha256Digest,
        inputs_digest: Sha256Digest,
    }

    impl ReceiptSource for FakeReceipt {
        fn lease_id(&self) -> &str {
            &self.lease_id
        }

        fn source_sha(&self) -> &str {
            &self.source
        }

        fn tree_oid(&self) -> &str {
            &self.tree
        }

        fn workflow_blob_oid(&self) -> &str {
            &self.workflow_blob
        }

        fn workflow_sha256(&self) -> &Sha256Digest {
            &self.workflow_digest
        }

        fn inputs_sha256(&self) -> &Sha256Digest {
            &self.inputs_digest
        }
    }

    fn environment() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("HOME".into(), "/proc/self/cwd/home".into()),
            ("LC_ALL".into(), "C.UTF-8".into()),
            ("GIT_CONFIG_NOSYSTEM".into(), "1".into()),
            ("GIT_TERMINAL_PROMPT".into(), "0".into()),
            ("GIT_ASKPASS".into(), "/bin/false".into()),
            ("GIT_CONFIG_KEY_0".into(), "credential.helper".into()),
            ("GIT_CONFIG_VALUE_0".into(), String::new()),
            ("GIT_CONFIG_KEY_1".into(), "core.hooksPath".into()),
            ("GIT_CONFIG_VALUE_1".into(), "/dev/null".into()),
        ])
    }

    fn command_log() -> GitCommandLog {
        GitCommandLog {
            sequence: 1,
            command: CommandSpec {
                operation: GitOperation::Init,
                program: "/usr/bin/git".into(),
                arguments: vec![
                    "--git-dir=objects.git".into(),
                    "init".into(),
                    "--bare".into(),
                ],
                current_dir: "/proc/self/fd/7".into(),
                clear_environment: true,
                environment: environment(),
                required_uid: 65534,
                lease_id: "lease-1".into(),
                cgroup_token: "cgroup".into(),
                netns_token: "netns".into(),
                lease_expires_at_unix_seconds: 10,
                maximum_stdout_bytes: 4_096,
                maximum_stderr_bytes: 4_096,
                deadline_millis: 1_000,
                network: NetworkScope::None,
                maximum_network_bytes: 0,
                maximum_processes: 32,
            },
            result: GitCommandResultLog {
                exit_code: Some(0),
                timed_out: false,
                stdout_sha256: Sha256Digest::parse("1".repeat(64)).unwrap(),
                stderr_sha256: Sha256Digest::parse("2".repeat(64)).unwrap(),
                stdout_bytes: 0,
                stderr_bytes: 0,
                stdout_truncated: false,
                stderr_truncated: false,
            },
            started_at_unix_ns: 10,
            finished_at_unix_ns: 20,
        }
    }

    fn lease(root: &std::path::Path) -> LeaseRecord {
        LeaseRecord {
            schema_version: 1,
            lease_id: "lease-1".into(),
            lease_unit: "lease-1.scope".into(),
            cgroup_path: "/buzzci.slice/lease-1.scope".into(),
            workspace_dir: root.join("workspace"),
            limits: LeaseLimits { wall_deadline: 2 },
            resource_readback: ResourcePropertyReadback {
                cpu_quota_per_sec_usec: 1,
                memory_max_bytes: 1,
                tasks_max: 1,
                runtime_max_seconds: 1,
            },
            dns_readback: DnsReadback {
                files_lookup_ok: true,
                arbitrary_getent_refused: true,
                resolved_varlink_inaccessible: true,
                direct_53_refused: true,
                allowed_tuples_only: true,
            },
            seccomp_profile: SeccompEvidence {
                path: SECCOMP_PROFILE_PATH.into(),
                sha256: SECCOMP_PROFILE_SHA256.into(),
            },
            sanitized_artifact_store_path: root.join("artifacts"),
            sanitized_log_store_path: root.join("logs"),
            created_at_unix_ns: 1,
        }
    }

    #[test]
    fn translated_receipt_and_commands_round_trip_through_store_validators() {
        let temporary = tempfile::tempdir().unwrap();
        let store = EvidenceStore::new(temporary.path().join("evidence")).unwrap();
        store.initialize_lease(&lease(temporary.path())).unwrap();
        let receipt = FakeReceipt {
            lease_id: "lease-1".into(),
            source: "1".repeat(40),
            tree: "2".repeat(40),
            workflow_blob: "3".repeat(40),
            workflow_digest: Sha256Digest::parse("4".repeat(64)).unwrap(),
            inputs_digest: Sha256Digest::parse("6".repeat(64)).unwrap(),
        };
        let records = translate_receipt_source(
            &receipt,
            &[command_log()],
            MaterializerEvidenceContext {
                manifest_sha256: [5; 32],
                input_digests: Vec::new(),
            },
        )
        .unwrap();
        for command in &records.commands {
            store.append_materializer_command(command).unwrap();
        }
        store
            .publish_materializer_receipt(&records.receipt)
            .unwrap();

        let paths = store.paths("lease-1").unwrap();
        let round_trip_receipt: MaterializerReceipt =
            serde_json::from_slice(&fs::read(paths.materializer_receipt).unwrap()).unwrap();
        let round_trip_commands = fs::read_to_string(paths.materializer_commands)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<MaterializerCommandRecord>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(round_trip_receipt, records.receipt);
        assert_eq!(round_trip_commands, records.commands);
    }
}
