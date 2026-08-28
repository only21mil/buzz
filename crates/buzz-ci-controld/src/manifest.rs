//! Deterministic compiler for runner job manifests.
//!
//! The Ed25519 key remains behind [`Ed25519ManifestSigner`]. This module only
//! receives a detached signature and cannot place key material in a manifest,
//! command line, environment, log descriptor, or runner receipt.

use std::collections::BTreeMap;
use std::path::Path;

use buzz_core::ci::CiRequestEnvelope;
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Frozen signature domain verified by `buzz-ci-runner`.
pub const MANIFEST_SIGNATURE_DOMAIN: &[u8] = b"buzz-ci-runner:job-manifest-signature:v1\0";
/// Frozen signed-manifest schema.
pub const MANIFEST_SCHEMA_VERSION: u32 = 1;
/// Maximum argument count accepted by the default runner profile.
pub const MAX_MANIFEST_ARGV_ITEMS: usize = 32;
/// Maximum aggregate argument bytes accepted by the default runner profile.
pub const MAX_MANIFEST_ARGV_BYTES: usize = 8 * 1024;
/// Maximum environment count accepted by the default runner profile.
pub const MAX_MANIFEST_ENV_ITEMS: usize = 32;
/// Maximum aggregate environment bytes accepted by the default runner profile.
pub const MAX_MANIFEST_ENV_BYTES: usize = 8 * 1024;

const RESERVED_ENVIRONMENT: [(&str, BindingValue); 19] = [
    ("BUZZ_CI_REQUEST_EVENT_ID", BindingValue::RequestEventId),
    ("BUZZ_CI_RUN_ID", BindingValue::RunId),
    ("BUZZ_CI_TARGET_REPO_A", BindingValue::TargetRepo),
    ("BUZZ_CI_SOURCE_REF", BindingValue::SourceRef),
    ("BUZZ_CI_SHA", BindingValue::SourceSha),
    ("BUZZ_CI_BASE_REF", BindingValue::BaseRef),
    ("BUZZ_CI_BASE_SHA", BindingValue::BaseSha),
    ("BUZZ_CI_WORKFLOW_ID", BindingValue::WorkflowId),
    ("BUZZ_CI_WORKFLOW_DIGEST", BindingValue::WorkflowDigest),
    ("BUZZ_CI_JOB_ID", BindingValue::JobId),
    ("BUZZ_CI_ATTEMPT", BindingValue::Attempt),
    ("BUZZ_CI_PARENT_ATTEMPT", BindingValue::ParentAttempt),
    ("BUZZ_CI_LEASE_ID", BindingValue::LeaseId),
    ("BUZZ_CI_WORKSPACE", BindingValue::WorkspacePath),
    ("BUZZ_CI_WORKSPACE_DEVICE", BindingValue::WorkspaceDevice),
    ("BUZZ_CI_WORKSPACE_INODE", BindingValue::WorkspaceInode),
    ("BUZZ_CI_WORKSPACE_UID", BindingValue::WorkspaceUid),
    ("BUZZ_CI_POLICY_DIGEST", BindingValue::PolicyDigest),
    ("BUZZ_CI_DESCRIPTOR_DIGEST", BindingValue::DescriptorDigest),
];

#[derive(Clone, Copy)]
enum BindingValue {
    RequestEventId,
    RunId,
    TargetRepo,
    SourceRef,
    SourceSha,
    BaseRef,
    BaseSha,
    WorkflowId,
    WorkflowDigest,
    JobId,
    Attempt,
    ParentAttempt,
    LeaseId,
    WorkspacePath,
    WorkspaceDevice,
    WorkspaceInode,
    WorkspaceUid,
    PolicyDigest,
    DescriptorDigest,
}

/// Opaque error returned by the process that owns the Ed25519 signing key.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("manifest signing failed")]
pub struct ManifestSigningError;

/// Separate Ed25519 signing boundary.
///
/// Implementations own and protect the private key. The compiler passes only
/// domain-separated bytes across this boundary and receives a detached
/// 64-byte Ed25519 signature.
pub trait Ed25519ManifestSigner {
    /// Sign the exact domain-separated manifest payload.
    fn sign_ed25519(&mut self, signing_bytes: &[u8]) -> Result<[u8; 64], ManifestSigningError>;
}

/// Root-observed workspace identity bound into the signed environment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceIdentity {
    /// Absolute broker-issued workspace path.
    pub path: String,
    /// Device number observed from the opened workspace descriptor.
    pub device: u64,
    /// Inode observed from the opened workspace descriptor.
    pub inode: u64,
    /// Non-root owner UID observed from the opened workspace descriptor.
    pub owner_uid: u32,
}

/// Exact static and broker-issued inputs for one signed job manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobManifestInput {
    /// Selected static job ID.
    pub job_id: String,
    /// Selected one-based job attempt.
    pub attempt: u32,
    /// Parent attempt, or zero for an initial run.
    pub parent_attempt: u32,
    /// Trusted-base workflow path.
    pub workflow_path: String,
    /// Broker-issued lease ID.
    pub lease_id: String,
    /// Broker-observed workspace descriptor identity.
    pub workspace: WorkspaceIdentity,
    /// SHA-256 of the exact policy supplied to the proxy.
    pub policy_digest: String,
    /// SHA-256 of the canonical job descriptor.
    pub descriptor_digest: String,
    /// SHA-256 of the allowed audience set.
    pub audience_digest: String,
    /// SHA-256 of the complete isolation profile.
    pub isolation_profile_digest: String,
    /// Arguments passed to the fixed runner executor program.
    pub argv: Vec<String>,
    /// Non-secret job environment. `BUZZ_CI_*` is compiler-owned.
    pub environment: BTreeMap<String, String>,
}

/// Signed JSON and immutable digests used to construct one `ExecuteJob`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledJobManifest {
    job_id: String,
    attempt: u32,
    parent_attempt: u32,
    workflow_path: String,
    job_manifest: String,
    job_manifest_digest: String,
    audience_digest: String,
    isolation_profile_digest: String,
}

impl CompiledJobManifest {
    /// Return the selected job ID.
    pub fn job_id(&self) -> &str {
        &self.job_id
    }
    /// Return the selected job attempt.
    pub const fn attempt(&self) -> u32 {
        self.attempt
    }
    /// Return the parent attempt, or zero for an initial run.
    pub const fn parent_attempt(&self) -> u32 {
        self.parent_attempt
    }
    /// Return the trusted-base workflow path.
    pub fn workflow_path(&self) -> &str {
        &self.workflow_path
    }
    /// Return the exact compact signed JSON sent to the runner.
    pub fn job_manifest(&self) -> &str {
        &self.job_manifest
    }
    /// Return SHA-256 of the exact signed JSON bytes.
    pub fn job_manifest_digest(&self) -> &str {
        &self.job_manifest_digest
    }
    /// Return the bound audience digest.
    pub fn audience_digest(&self) -> &str {
        &self.audience_digest
    }
    /// Return the bound isolation profile digest.
    pub fn isolation_profile_digest(&self) -> &str {
        &self.isolation_profile_digest
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ManifestCompileError {
    /// The accepted request failed its frozen envelope validation.
    #[error("accepted request is invalid")]
    InvalidRequest,
    /// The event ID or signed request digest was not lowercase SHA-256 hex.
    #[error("request event ID or signed request digest is invalid")]
    InvalidRequestBinding,
    /// Job ID, attempt, or parent attempt differed from the request.
    #[error("job identity does not match the accepted request")]
    JobMismatch,
    /// The trusted workflow path was absolute or contained traversal.
    #[error("workflow path is invalid")]
    InvalidWorkflowPath,
    /// The broker lease ID was not a canonical ULID.
    #[error("lease identity is invalid")]
    InvalidLease,
    /// Workspace path or descriptor identity was invalid.
    #[error("workspace identity is invalid")]
    InvalidWorkspace,
    /// A bound execution digest was not lowercase SHA-256 hex.
    #[error("policy, descriptor, audience, or isolation digest is invalid")]
    InvalidDigest,
    /// Arguments exceeded bounds or could carry secret material.
    #[error("argument vector is invalid or may carry secret material")]
    InvalidArguments,
    /// Environment data exceeded bounds or could carry secret material.
    #[error("environment is invalid or may carry secret material")]
    InvalidEnvironment,
    /// Deterministic JSON serialization failed.
    #[error("manifest serialization failed")]
    Serialization,
    /// The isolated signing boundary failed.
    #[error(transparent)]
    Signing(#[from] ManifestSigningError),
}

#[derive(Serialize)]
struct UnsignedManifest<'a> {
    schema_version: u32,
    request_event_id: &'a str,
    signed_request_digest: &'a str,
    job_id: &'a str,
    workflow_path: &'a str,
    audience_digest: &'a str,
    isolation_profile_digest: &'a str,
    argv: &'a [String],
    environment: &'a BTreeMap<String, String>,
}

#[derive(Serialize)]
struct SignedManifest<'a> {
    schema_version: u32,
    request_event_id: &'a str,
    signed_request_digest: &'a str,
    job_id: &'a str,
    workflow_path: &'a str,
    audience_digest: &'a str,
    isolation_profile_digest: &'a str,
    argv: &'a [String],
    environment: &'a BTreeMap<String, String>,
    signature: String,
}

/// Compile and sign one deterministic runner job manifest.
pub fn compile_job_manifest(
    request_event_id: &str,
    signed_request_digest: &str,
    request: &CiRequestEnvelope,
    input: JobManifestInput,
    signer: &mut impl Ed25519ManifestSigner,
) -> Result<CompiledJobManifest, ManifestCompileError> {
    request
        .validate()
        .map_err(|_| ManifestCompileError::InvalidRequest)?;
    if !is_lower_hex(request_event_id, 64) || !is_lower_hex(signed_request_digest, 64) {
        return Err(ManifestCompileError::InvalidRequestBinding);
    }
    let expected_parent_attempt = request.parent_attempt.unwrap_or(0);
    if input.attempt != request.attempt
        || input.parent_attempt != expected_parent_attempt
        || !request.job_ids.iter().any(|job_id| job_id == &input.job_id)
    {
        return Err(ManifestCompileError::JobMismatch);
    }
    if !safe_relative_path(&input.workflow_path) {
        return Err(ManifestCompileError::InvalidWorkflowPath);
    }
    if !valid_ulid(&input.lease_id) {
        return Err(ManifestCompileError::InvalidLease);
    }
    if !safe_absolute_path(&input.workspace.path)
        || input.workspace.device == 0
        || input.workspace.inode == 0
        || input.workspace.owner_uid == 0
    {
        return Err(ManifestCompileError::InvalidWorkspace);
    }
    if [
        input.policy_digest.as_str(),
        input.descriptor_digest.as_str(),
        input.audience_digest.as_str(),
        input.isolation_profile_digest.as_str(),
    ]
    .iter()
    .any(|digest| !is_lower_hex(digest, 64))
    {
        return Err(ManifestCompileError::InvalidDigest);
    }
    validate_arguments(&input.argv)?;
    validate_environment(&input.environment)?;

    let mut environment = input.environment.clone();
    for (key, selector) in RESERVED_ENVIRONMENT {
        environment.insert(
            key.to_owned(),
            binding_value(selector, request_event_id, request, &input),
        );
    }
    validate_compiled_environment(&environment)?;

    let unsigned = UnsignedManifest {
        schema_version: MANIFEST_SCHEMA_VERSION,
        request_event_id,
        signed_request_digest,
        job_id: &input.job_id,
        workflow_path: &input.workflow_path,
        audience_digest: &input.audience_digest,
        isolation_profile_digest: &input.isolation_profile_digest,
        argv: &input.argv,
        environment: &environment,
    };
    let payload = serde_json::to_vec(&unsigned).map_err(|_| ManifestCompileError::Serialization)?;
    let mut signing_bytes = Vec::with_capacity(MANIFEST_SIGNATURE_DOMAIN.len() + payload.len());
    signing_bytes.extend_from_slice(MANIFEST_SIGNATURE_DOMAIN);
    signing_bytes.extend_from_slice(&payload);
    let signature = signer.sign_ed25519(&signing_bytes)?;

    let signed = SignedManifest {
        schema_version: MANIFEST_SCHEMA_VERSION,
        request_event_id,
        signed_request_digest,
        job_id: &input.job_id,
        workflow_path: &input.workflow_path,
        audience_digest: &input.audience_digest,
        isolation_profile_digest: &input.isolation_profile_digest,
        argv: &input.argv,
        environment: &environment,
        signature: hex::encode(signature),
    };
    let job_manifest =
        serde_json::to_string(&signed).map_err(|_| ManifestCompileError::Serialization)?;
    let job_manifest_digest = hex::encode(Sha256::digest(job_manifest.as_bytes()));

    Ok(CompiledJobManifest {
        job_id: input.job_id,
        attempt: input.attempt,
        parent_attempt: input.parent_attempt,
        workflow_path: input.workflow_path,
        job_manifest,
        job_manifest_digest,
        audience_digest: input.audience_digest,
        isolation_profile_digest: input.isolation_profile_digest,
    })
}

fn binding_value(
    selector: BindingValue,
    request_event_id: &str,
    request: &CiRequestEnvelope,
    input: &JobManifestInput,
) -> String {
    match selector {
        BindingValue::RequestEventId => request_event_id.to_owned(),
        BindingValue::RunId => request.run_id.clone(),
        BindingValue::TargetRepo => request.target_repo_a.clone(),
        BindingValue::SourceRef => request.immutable_source_ref.clone(),
        BindingValue::SourceSha => request.tip_oid.clone(),
        BindingValue::BaseRef => request.base_ref.clone(),
        BindingValue::BaseSha => request.base_oid.clone(),
        BindingValue::WorkflowId => request.workflow_id.clone(),
        BindingValue::WorkflowDigest => request.workflow_digest.clone(),
        BindingValue::JobId => input.job_id.clone(),
        BindingValue::Attempt => input.attempt.to_string(),
        BindingValue::ParentAttempt => input.parent_attempt.to_string(),
        BindingValue::LeaseId => input.lease_id.clone(),
        BindingValue::WorkspacePath => input.workspace.path.clone(),
        BindingValue::WorkspaceDevice => input.workspace.device.to_string(),
        BindingValue::WorkspaceInode => input.workspace.inode.to_string(),
        BindingValue::WorkspaceUid => input.workspace.owner_uid.to_string(),
        BindingValue::PolicyDigest => input.policy_digest.clone(),
        BindingValue::DescriptorDigest => input.descriptor_digest.clone(),
    }
}

fn validate_arguments(argv: &[String]) -> Result<(), ManifestCompileError> {
    if argv.is_empty()
        || argv.len() > MAX_MANIFEST_ARGV_ITEMS
        || argv.iter().map(String::len).sum::<usize>() > MAX_MANIFEST_ARGV_BYTES
        || argv.iter().any(|value| {
            value.is_empty() || value.contains(['\0', '\r', '\n']) || sensitive_argument(value)
        })
    {
        return Err(ManifestCompileError::InvalidArguments);
    }
    Ok(())
}

fn validate_environment(
    environment: &BTreeMap<String, String>,
) -> Result<(), ManifestCompileError> {
    if environment.keys().any(|key| key.starts_with("BUZZ_CI_"))
        || environment.iter().any(|(key, value)| {
            !valid_env_key(key)
                || sensitive_environment_key(key)
                || value.contains(['\0', '\r', '\n'])
                || contains_secret_material(value)
        })
    {
        return Err(ManifestCompileError::InvalidEnvironment);
    }
    Ok(())
}

fn validate_compiled_environment(
    environment: &BTreeMap<String, String>,
) -> Result<(), ManifestCompileError> {
    if environment.len() > MAX_MANIFEST_ENV_ITEMS
        || environment
            .iter()
            .map(|(key, value)| key.len() + value.len())
            .sum::<usize>()
            > MAX_MANIFEST_ENV_BYTES
    {
        return Err(ManifestCompileError::InvalidEnvironment);
    }
    Ok(())
}

fn valid_env_key(key: &str) -> bool {
    !key.is_empty()
        && !key.contains('=')
        && key
            .bytes()
            .all(|byte| byte == b'_' || byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

fn sensitive_environment_key(key: &str) -> bool {
    [
        "KEY",
        "NSEC",
        "SECRET",
        "TOKEN",
        "PASSWORD",
        "PASSPHRASE",
        "CREDENTIAL",
        "AUTH",
    ]
    .iter()
    .any(|word| key.split('_').any(|part| part == *word))
}

fn contains_secret_material(value: &str) -> bool {
    let trimmed = value.trim();
    let lower = trimmed.to_ascii_lowercase();
    contains_nostr_nsec(&lower)
        || [
            ("ghp_", 36),
            ("gho_", 36),
            ("ghu_", 36),
            ("ghs_", 36),
            ("ghr_", 36),
            ("github_pat_", 20),
            ("glpat-", 20),
        ]
        .iter()
        .any(|(prefix, minimum_suffix_length)| {
            contains_prefixed_secret(&lower, prefix, *minimum_suffix_length)
        })
        || (lower.contains("-----begin ") && lower.contains(" private key-----"))
}

fn contains_nostr_nsec(value: &str) -> bool {
    value.match_indices("nsec1").any(|(index, prefix)| {
        value[index + prefix.len()..]
            .chars()
            .take_while(|character| {
                matches!(
                    character,
                    '0' | '2'..='9'
                        | 'a'
                        | 'c'..='h'
                        | 'j'..='n'
                        | 'p'..='z'
                )
            })
            .count()
            >= 58
    })
}

fn contains_prefixed_secret(value: &str, prefix: &str, minimum_suffix_length: usize) -> bool {
    value.match_indices(prefix).any(|(index, prefix)| {
        value[index + prefix.len()..]
            .chars()
            .take_while(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '_' | '-')
            })
            .count()
            >= minimum_suffix_length
    })
}

fn sensitive_argument(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    if lower.starts_with("nsec1") {
        return true;
    }
    [
        "--key",
        "--private-key",
        "--secret",
        "--secret-key",
        "--signing-key",
        "--manifest-key",
        "--token",
        "--password",
    ]
    .iter()
    .any(|needle| lower == *needle || lower.starts_with(&format!("{needle}=")))
}

fn safe_relative_path(value: &str) -> bool {
    let path = Path::new(value);
    !value.is_empty()
        && !value.contains(['\0', '\r', '\n', '\\'])
        && !path.is_absolute()
        && value
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

fn safe_absolute_path(value: &str) -> bool {
    let path = Path::new(value);
    path.is_absolute()
        && !value.contains(['\0', '\r', '\n', '\\'])
        && value.strip_prefix('/').is_some_and(|relative| {
            !relative.is_empty()
                && relative
                    .split('/')
                    .all(|component| !component.is_empty() && component != "." && component != "..")
        })
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_ulid(value: &str) -> bool {
    value.len() == 26
        && value
            .as_bytes()
            .first()
            .is_some_and(|byte| (b'0'..=b'7').contains(byte))
        && value.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'A'..=b'H' | b'J'..=b'K' | b'M'..=b'N' | b'P'..=b'T' | b'V'..=b'Z'))
}
