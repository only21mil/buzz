//! Typed parsing and static job selection for Buzz CI workflows.
//!
//! Workflows retain their GitHub Actions shape. This crate reads only the
//! fields needed to build broker-signed static job policy and tolerates other
//! GitHub Actions fields. [`WorkflowJob`] and [`JobSelection`] deny unknown
//! fields because they are the closed values consumers copy into signed state.
//!
//! A job-level `required` field is the only in-file source of required-job
//! policy. It defaults to `true`. A top-level `manifest` block is rejected so
//! `manifest.required_jobs` cannot disagree with job policy. The broker signs
//! each parsed [`WorkflowJob::required`] value and its derived
//! [`WorkflowJob::skip_policy`]. Skip policy is [`SkipPolicy::Allow`] when an
//! `if` key is present or `required` is false, and [`SkipPolicy::Forbid`]
//! otherwise.
//!
//! Compatibility with the rev2 relay parser is intentional: job order,
//! workflow-name fallback, default required policy, skip derivation, `needs`
//! syntax, and selected-job order are unchanged. This parser deliberately
//! rejects malformed `required` values, duplicate job IDs, duplicate or
//! missing dependencies, and deprecated `manifest` blocks that rev2 could
//! ignore or normalize.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::collections::HashSet;
use std::fmt;

use serde::de::{self, IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Maximum accepted canonical workflow size, matching the rev2 relay bound.
pub const MAX_WORKFLOW_BYTES: usize = 128 * 1024;

/// Workflow identifier used when the top-level `name` is absent or empty.
pub const DEFAULT_WORKFLOW_ID: &str = "ci";

/// A parsed workflow and the digest of its original canonical bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedWorkflow {
    /// Top-level workflow `name`, or [`DEFAULT_WORKFLOW_ID`] when absent.
    pub workflow_id: String,
    /// Lowercase SHA-256 of the original bytes, without YAML normalization.
    pub workflow_digest: String,
    /// Static jobs in source order.
    pub jobs: Vec<WorkflowJob>,
}

/// Static policy copied into the broker-signed per-job manifest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowJob {
    /// Static job-map key matching `^[A-Za-z0-9_]{1,64}$`.
    pub job_id: String,
    /// Human-readable job name, falling back to `job_id`.
    pub name: String,
    /// Whether this job contributes to the green verdict.
    pub required: bool,
    /// Signed interpretation of a terminal skipped state.
    pub skip_policy: SkipPolicy,
    /// Static dependency IDs in workflow order.
    pub needs: Vec<String>,
}

/// Closed signed policy for a terminal skipped job.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SkipPolicy {
    /// A skipped job is permitted by its static workflow policy.
    Allow,
    /// A skipped job violates its static workflow policy.
    Forbid,
}

/// Complete static jobs plus the selected job IDs for one request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JobSelection {
    /// Complete static job set in workflow order.
    pub jobs: Vec<WorkflowJob>,
    /// Selected IDs, preserving workflow order when omitted or request order
    /// when explicit.
    pub selected_job_ids: Vec<String>,
}

/// A workflow parsing or static-selection refusal.
#[derive(Debug, Error)]
pub enum WorkflowError {
    /// Canonical bytes exceed [`MAX_WORKFLOW_BYTES`].
    #[error("workflow is {actual} bytes; maximum is {maximum}")]
    TooLarge {
        /// Observed byte length.
        actual: usize,
        /// Accepted byte length.
        maximum: usize,
    },
    /// YAML shape or typed field validation failed.
    #[error("workflow YAML is invalid: {0}")]
    InvalidYaml(String),
    /// The workflow contains no static jobs.
    #[error("workflow defines no static jobs")]
    NoJobs,
    /// A static job ID does not match the protocol grammar.
    #[error("invalid static job id {0:?}")]
    InvalidJobId(String),
    /// A job dependency repeats within one job.
    #[error("job {job_id} repeats dependency {dependency}")]
    DuplicateDependency {
        /// Job declaring the dependency.
        job_id: String,
        /// Repeated dependency ID.
        dependency: String,
    },
    /// A job depends on itself.
    #[error("job {0} depends on itself")]
    SelfDependency(String),
    /// A job names a dependency absent from the static job set.
    #[error("job {job_id} depends on unknown job {dependency}")]
    UnknownDependency {
        /// Job declaring the dependency.
        job_id: String,
        /// Missing dependency ID.
        dependency: String,
    },
    /// The caller supplied an explicit empty selection.
    #[error("requested job ids must be non-empty")]
    EmptySelection,
    /// The caller repeated a selected job ID.
    #[error("requested job id {0} is duplicated")]
    DuplicateSelection(String),
    /// The caller selected an ID absent from the workflow.
    #[error("requested job id {0} is not in the workflow")]
    UnknownSelection(String),
}

/// Compute the lowercase SHA-256 of the original canonical workflow bytes.
///
/// The bytes are hashed unchanged. No YAML parse, normalization, or
/// reserialization occurs.
pub fn workflow_digest(bytes: &[u8]) -> Result<String, WorkflowError> {
    enforce_size(bytes)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

/// Parse canonical workflow bytes into static broker policy.
pub fn parse_workflow(bytes: &[u8]) -> Result<ParsedWorkflow, WorkflowError> {
    enforce_size(bytes)?;
    let raw: RawWorkflow = serde_yaml::from_slice(bytes)
        .map_err(|error| WorkflowError::InvalidYaml(error.to_string()))?;
    if raw.jobs.0.is_empty() {
        return Err(WorkflowError::NoJobs);
    }

    let mut jobs = Vec::with_capacity(raw.jobs.0.len());
    for (job_id, raw_job) in raw.jobs.0 {
        validate_job_id(&job_id)?;
        let name = raw_job
            .name
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| job_id.clone());
        let skip_policy = if raw_job.condition.is_some() || !raw_job.required {
            SkipPolicy::Allow
        } else {
            SkipPolicy::Forbid
        };
        let needs = raw_job.needs.into_vec();
        let mut seen = HashSet::with_capacity(needs.len());
        for dependency in &needs {
            validate_job_id(dependency)?;
            if dependency == &job_id {
                return Err(WorkflowError::SelfDependency(job_id));
            }
            if !seen.insert(dependency.as_str()) {
                return Err(WorkflowError::DuplicateDependency {
                    job_id,
                    dependency: dependency.clone(),
                });
            }
        }
        jobs.push(WorkflowJob {
            job_id,
            name,
            required: raw_job.required,
            skip_policy,
            needs,
        });
    }

    let job_ids: HashSet<&str> = jobs.iter().map(|job| job.job_id.as_str()).collect();
    for job in &jobs {
        for dependency in &job.needs {
            if !job_ids.contains(dependency.as_str()) {
                return Err(WorkflowError::UnknownDependency {
                    job_id: job.job_id.clone(),
                    dependency: dependency.clone(),
                });
            }
        }
    }

    Ok(ParsedWorkflow {
        workflow_id: raw
            .name
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| DEFAULT_WORKFLOW_ID.to_string()),
        workflow_digest: hex::encode(Sha256::digest(bytes)),
        jobs,
    })
}

/// Resolve an omitted selection to every job, or validate an explicit unique
/// non-empty subset. The complete job set remains in workflow order.
pub fn select_jobs(
    workflow: &ParsedWorkflow,
    requested: Option<&[String]>,
) -> Result<JobSelection, WorkflowError> {
    if workflow.jobs.is_empty() {
        return Err(WorkflowError::NoJobs);
    }
    let job_ids: HashSet<&str> = workflow
        .jobs
        .iter()
        .map(|job| job.job_id.as_str())
        .collect();
    let selected_job_ids = match requested {
        None => workflow.jobs.iter().map(|job| job.job_id.clone()).collect(),
        Some([]) => return Err(WorkflowError::EmptySelection),
        Some(requested) => {
            let mut seen = HashSet::with_capacity(requested.len());
            let mut selected = Vec::with_capacity(requested.len());
            for job_id in requested {
                if !seen.insert(job_id.as_str()) {
                    return Err(WorkflowError::DuplicateSelection(job_id.clone()));
                }
                if !job_ids.contains(job_id.as_str()) {
                    return Err(WorkflowError::UnknownSelection(job_id.clone()));
                }
                selected.push(job_id.clone());
            }
            selected
        }
    };
    Ok(JobSelection {
        jobs: workflow.jobs.clone(),
        selected_job_ids,
    })
}

fn enforce_size(bytes: &[u8]) -> Result<(), WorkflowError> {
    if bytes.len() > MAX_WORKFLOW_BYTES {
        return Err(WorkflowError::TooLarge {
            actual: bytes.len(),
            maximum: MAX_WORKFLOW_BYTES,
        });
    }
    Ok(())
}

fn validate_job_id(job_id: &str) -> Result<(), WorkflowError> {
    if job_id.is_empty()
        || job_id.len() > 64
        || !job_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(WorkflowError::InvalidJobId(job_id.to_string()));
    }
    Ok(())
}

#[derive(Deserialize)]
struct RawWorkflow {
    #[serde(default)]
    name: Option<String>,
    jobs: UniqueJobs,
    #[serde(
        rename = "manifest",
        default,
        deserialize_with = "reject_deprecated_manifest"
    )]
    _manifest: (),
}

fn reject_deprecated_manifest<'de, D>(deserializer: D) -> Result<(), D::Error>
where
    D: Deserializer<'de>,
{
    let _ = IgnoredAny::deserialize(deserializer)?;
    Err(de::Error::custom(
        "top-level manifest is deprecated; declare required on each job",
    ))
}

#[derive(Deserialize)]
struct RawJob {
    #[serde(default)]
    name: Option<String>,
    #[serde(default = "required_by_default")]
    required: bool,
    #[serde(rename = "if", default, deserialize_with = "mark_condition_present")]
    condition: Option<()>,
    #[serde(default)]
    needs: RawNeeds,
}

fn required_by_default() -> bool {
    true
}

fn mark_condition_present<'de, D>(deserializer: D) -> Result<Option<()>, D::Error>
where
    D: Deserializer<'de>,
{
    let _ = IgnoredAny::deserialize(deserializer)?;
    Ok(Some(()))
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawNeeds {
    One(String),
    Many(Vec<String>),
}

impl Default for RawNeeds {
    fn default() -> Self {
        Self::Many(Vec::new())
    }
}

impl RawNeeds {
    fn into_vec(self) -> Vec<String> {
        match self {
            Self::One(value) => vec![value],
            Self::Many(values) => values,
        }
    }
}

struct UniqueJobs(Vec<(String, RawJob)>);

impl<'de> Deserialize<'de> for UniqueJobs {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(UniqueJobsVisitor)
    }
}

struct UniqueJobsVisitor;

impl<'de> Visitor<'de> for UniqueJobsVisitor {
    type Value = UniqueJobs;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a mapping of unique static job IDs to job definitions")
    }

    fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut jobs = Vec::with_capacity(map.size_hint().unwrap_or(0));
        let mut seen = HashSet::new();
        while let Some((job_id, job)) = map.next_entry::<String, RawJob>()? {
            if !seen.insert(job_id.clone()) {
                return Err(de::Error::custom(format_args!(
                    "duplicate static job id {job_id:?}"
                )));
            }
            jobs.push((job_id, job));
        }
        Ok(UniqueJobs(jobs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROBE_WORKFLOW: &[u8] = include_bytes!("../../../ci-acceptance/probe-repo/workflow.yml");
    const BUZZ_LIKE_WORKFLOW: &[u8] = include_bytes!("../tests/fixtures/buzz-like.yml");

    #[test]
    fn parses_probe_policy_from_jobs() {
        let parsed = parse_workflow(PROBE_WORKFLOW).expect("probe workflow should parse");
        assert_eq!(parsed.workflow_id, "buzz-ci-phase2-probe");
        assert_eq!(parsed.jobs.len(), 4);
        assert_eq!(parsed.jobs[0].job_id, "ok");
        assert!(!parsed.jobs[0].required);
        assert_eq!(parsed.jobs[0].skip_policy, SkipPolicy::Allow);
        assert_eq!(parsed.jobs[1].job_id, "flaky");
        assert!(parsed.jobs[1].required);
        assert_eq!(parsed.jobs[1].skip_policy, SkipPolicy::Forbid);
    }

    #[test]
    fn parses_buzz_like_workflow_and_static_dependencies() {
        let parsed = parse_workflow(BUZZ_LIKE_WORKFLOW).expect("fixture should parse");
        assert_eq!(parsed.workflow_id, "CI");
        assert_eq!(
            parsed
                .jobs
                .iter()
                .map(|job| job.job_id.as_str())
                .collect::<Vec<_>>(),
            ["changes", "rust_lint", "unit_tests"]
        );
        assert_eq!(parsed.jobs[1].needs, ["changes"]);
        assert_eq!(parsed.jobs[1].skip_policy, SkipPolicy::Allow);
        assert_eq!(parsed.jobs[2].needs, ["changes"]);
        assert_eq!(parsed.jobs[2].skip_policy, SkipPolicy::Forbid);
    }

    #[test]
    fn digest_uses_original_bytes() {
        let first = b"name: CI\njobs: {}\n";
        let second = b"name: CI\njobs: {}";
        assert_eq!(
            workflow_digest(first).expect("digest should succeed"),
            "a79762eeef1a770537be973e3c651ec96d90af5b33f9306a69f47cbded951c16"
        );
        assert_ne!(
            workflow_digest(first).expect("digest should succeed"),
            workflow_digest(second).expect("digest should succeed")
        );
    }

    #[test]
    fn selects_all_or_preserves_explicit_order() {
        let parsed = parse_workflow(BUZZ_LIKE_WORKFLOW).expect("fixture should parse");
        assert_eq!(
            select_jobs(&parsed, None)
                .expect("all jobs should select")
                .selected_job_ids,
            ["changes", "rust_lint", "unit_tests"]
        );
        let requested = vec!["unit_tests".to_string(), "changes".to_string()];
        assert_eq!(
            select_jobs(&parsed, Some(&requested))
                .expect("subset should select")
                .selected_job_ids,
            requested
        );
    }

    #[test]
    fn rejects_invalid_explicit_selections() {
        let parsed = parse_workflow(BUZZ_LIKE_WORKFLOW).expect("fixture should parse");
        assert!(matches!(
            select_jobs(&parsed, Some(&[])),
            Err(WorkflowError::EmptySelection)
        ));
        let duplicate = vec!["changes".to_string(), "changes".to_string()];
        assert!(matches!(
            select_jobs(&parsed, Some(&duplicate)),
            Err(WorkflowError::DuplicateSelection(job_id)) if job_id == "changes"
        ));
        let unknown = vec!["missing".to_string()];
        assert!(matches!(
            select_jobs(&parsed, Some(&unknown)),
            Err(WorkflowError::UnknownSelection(job_id)) if job_id == "missing"
        ));
    }

    #[test]
    fn rejects_deprecated_manifest_policy() {
        let error = parse_workflow(
            b"name: stale\nmanifest:\n  required_jobs: [build]\njobs:\n  build:\n    runs-on: linux\n",
        )
        .expect_err("manifest policy must be rejected");
        assert!(error
            .to_string()
            .contains("top-level manifest is deprecated"));
    }

    #[test]
    fn rejects_duplicate_job_ids() {
        let error =
            parse_workflow(b"jobs:\n  build:\n    runs-on: linux\n  build:\n    runs-on: linux\n")
                .expect_err("duplicate IDs must be rejected");
        assert!(error.to_string().contains("duplicate static job id"));
    }

    #[test]
    fn rejects_bad_regex_job_ids() {
        assert!(matches!(
            parse_workflow(b"jobs:\n  bad-id:\n    runs-on: linux\n"),
            Err(WorkflowError::InvalidJobId(job_id)) if job_id == "bad-id"
        ));
        let oversized_id = "x".repeat(65);
        let workflow = format!("jobs:\n  {oversized_id}:\n    runs-on: linux\n");
        assert!(matches!(
            parse_workflow(workflow.as_bytes()),
            Err(WorkflowError::InvalidJobId(job_id)) if job_id == oversized_id
        ));
    }

    #[test]
    fn rejects_oversized_workflows_before_yaml_parsing() {
        let bytes = vec![b' '; MAX_WORKFLOW_BYTES + 1];
        assert!(matches!(
            parse_workflow(&bytes),
            Err(WorkflowError::TooLarge { actual, maximum })
                if actual == MAX_WORKFLOW_BYTES + 1 && maximum == MAX_WORKFLOW_BYTES
        ));
    }

    #[test]
    fn rejects_malformed_required_and_dependency_policy() {
        let malformed = b"jobs:\n  build:\n    required: yes\n";
        assert!(matches!(
            parse_workflow(malformed),
            Err(WorkflowError::InvalidYaml(_))
        ));
        let missing = b"jobs:\n  build:\n    needs: absent\n";
        assert!(matches!(
            parse_workflow(missing),
            Err(WorkflowError::UnknownDependency { job_id, dependency })
                if job_id == "build" && dependency == "absent"
        ));
    }

    #[test]
    fn defaults_empty_name_and_job_name() {
        let parsed = parse_workflow(b"name: ''\njobs:\n  build: {}\n")
            .expect("empty names should use stable fallbacks");
        assert_eq!(parsed.workflow_id, DEFAULT_WORKFLOW_ID);
        assert_eq!(parsed.jobs[0].name, "build");
        assert!(parsed.jobs[0].required);
        assert_eq!(parsed.jobs[0].skip_policy, SkipPolicy::Forbid);
    }
}
