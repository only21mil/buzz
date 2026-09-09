//! GitHub mirror reads: pull requests by head branch and check runs by exact
//! commit. Every list is paged to the end before any filtering.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::commands::repo_sync::{
    github_get, github_get_status, CheckRun, CheckRunsResponse, GitHubAuth, GitHubRepo,
    GITHUB_ACTIONS_APP_ID,
};
use crate::error::CliError;

const PAGE: usize = 100;
const MAX_PAGES: u16 = 100;

/// One mirror pull request, reduced to the fields the reconciler compares.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(super) struct MirrorPull {
    pub(super) number: u64,
    /// `open`, `closed` or `merged`.
    pub(super) state: String,
    pub(super) head_ref: String,
    pub(super) head_sha: String,
    pub(super) head_repo: Option<String>,
    pub(super) base_ref: String,
    pub(super) merge_commit_sha: Option<String>,
    pub(super) updated_at: String,
}

#[derive(Debug, Deserialize)]
struct RawPull {
    number: u64,
    state: String,
    merged_at: Option<String>,
    updated_at: String,
    head: RawRef,
    base: RawBase,
    merge_commit_sha: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawRef {
    #[serde(rename = "ref")]
    name: String,
    sha: String,
    repo: Option<RawRepo>,
}

#[derive(Debug, Deserialize)]
struct RawRepo {
    full_name: String,
}

#[derive(Debug, Deserialize)]
struct RawBase {
    #[serde(rename = "ref")]
    name: String,
}

pub(super) fn parse_pulls(json: &str) -> Result<Vec<MirrorPull>, CliError> {
    let raw: Vec<RawPull> = serde_json::from_str(json)
        .map_err(|error| CliError::Other(format!("parse GitHub pull requests: {error}")))?;
    Ok(raw.into_iter().map(MirrorPull::from).collect())
}

impl From<RawPull> for MirrorPull {
    fn from(raw: RawPull) -> Self {
        let state = match (raw.state.as_str(), raw.merged_at.is_some()) {
            ("open", _) => "open",
            (_, true) => "merged",
            _ => "closed",
        };
        MirrorPull {
            number: raw.number,
            state: state.into(),
            head_ref: raw.head.name,
            head_sha: raw.head.sha.to_ascii_lowercase(),
            head_repo: raw.head.repo.map(|repo| repo.full_name),
            base_ref: raw.base.name,
            merge_commit_sha: raw
                .merge_commit_sha
                .filter(|_| state == "merged")
                .map(|sha| sha.to_ascii_lowercase()),
            updated_at: raw.updated_at,
        }
    }
}

/// All pull requests of the mirror in every state. Pages until a short page.
pub(super) async fn read_all_pulls(
    github: &GitHubRepo,
    auth: &GitHubAuth,
) -> Result<Vec<MirrorPull>, CliError> {
    let client = reqwest::Client::new();
    let mut all = Vec::new();
    for page in 1..=MAX_PAGES {
        let url = format!(
            "https://api.github.com/repos/{}/{}/pulls?state=all&sort=updated&direction=desc&per_page={PAGE}&page={page}",
            github.owner, github.repo
        );
        let response = github_get(&client, auth, url, "pull requests").await?;
        let body = response.text().await?;
        let pulls = parse_pulls(&body)?;
        let count = pulls.len();
        all.extend(pulls);
        if count < PAGE {
            return Ok(all);
        }
    }
    Err(CliError::Other(
        "GitHub returned more than 10,000 pull requests".into(),
    ))
}

/// Same-repository pulls targeting `base`, keyed by head branch.
pub(super) fn index_pulls(
    pulls: &[MirrorPull],
    github_full_name: &str,
    base: &str,
) -> BTreeMap<String, Vec<MirrorPull>> {
    let mut index: BTreeMap<String, Vec<MirrorPull>> = BTreeMap::new();
    for pull in pulls {
        if pull.base_ref != base
            || pull
                .head_repo
                .as_deref()
                .is_none_or(|repo| !repo.eq_ignore_ascii_case(github_full_name))
        {
            continue;
        }
        index
            .entry(pull.head_ref.clone())
            .or_default()
            .push(pull.clone());
    }
    for pulls in index.values_mut() {
        pulls.sort_by(|a, b| {
            b.updated_at
                .cmp(&a.updated_at)
                .then(b.number.cmp(&a.number))
        });
    }
    index
}

/// The mirror pull for a branch: the exact-head match if any, else the most
/// recently updated.
pub(super) fn select_pull<'a>(
    candidates: &'a [MirrorPull],
    commit: Option<&str>,
) -> Option<&'a MirrorPull> {
    commit
        .and_then(|commit| {
            candidates
                .iter()
                .find(|pull| pull.head_sha == commit && pull.state == "merged")
                .or_else(|| candidates.iter().find(|pull| pull.head_sha == commit))
        })
        .or_else(|| candidates.first())
}

/// Aggregate CI verdict for trusted GitHub Actions runs at one exact commit.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(super) struct CiSummary {
    /// `success`, `failure`, `pending`, `missing` or `not_on_mirror`.
    pub(super) state: String,
    pub(super) trusted_runs: usize,
    pub(super) failed: Vec<String>,
    pub(super) pending: Vec<String>,
}

const OK_CONCLUSIONS: [&str; 3] = ["success", "skipped", "neutral"];

pub(super) fn summarize_checks(commit: &str, runs: &[CheckRun]) -> CiSummary {
    let trusted: Vec<&CheckRun> = runs
        .iter()
        .filter(|run| {
            run.app.id == GITHUB_ACTIONS_APP_ID && run.head_sha.eq_ignore_ascii_case(commit)
        })
        .collect();
    let mut failed = Vec::new();
    let mut pending = Vec::new();
    for run in &trusted {
        if run.status != "completed" {
            pending.push(run.name.clone());
        } else if !run
            .conclusion
            .as_deref()
            .is_some_and(|conclusion| OK_CONCLUSIONS.contains(&conclusion))
        {
            failed.push(run.name.clone());
        }
    }
    failed.sort();
    failed.dedup();
    pending.sort();
    pending.dedup();
    let state = if trusted.is_empty() {
        "missing"
    } else if !failed.is_empty() {
        "failure"
    } else if !pending.is_empty() {
        "pending"
    } else {
        "success"
    };
    CiSummary {
        state: state.into(),
        trusted_runs: trusted.len(),
        failed,
        pending,
    }
}

/// Check runs at one exact commit. GitHub answers 422 when the commit does
/// not exist on the mirror; that is recorded as `not_on_mirror`, not an error.
pub(super) async fn read_checks(
    github: &GitHubRepo,
    auth: &GitHubAuth,
    commit: &str,
) -> Result<CiSummary, CliError> {
    let client = reqwest::Client::new();
    let mut runs = Vec::new();
    for page in 1..=MAX_PAGES {
        let url = format!(
            "https://api.github.com/repos/{}/{}/commits/{commit}/check-runs?per_page={PAGE}&page={page}",
            github.owner, github.repo
        );
        let response = github_get_status(&client, auth, url, "checks").await?;
        let status = response.status();
        if status == reqwest::StatusCode::UNPROCESSABLE_ENTITY {
            return Ok(CiSummary {
                state: "not_on_mirror".into(),
                trusted_runs: 0,
                failed: Vec::new(),
                pending: Vec::new(),
            });
        }
        if !status.is_success() {
            return Err(CliError::Other(format!(
                "GitHub checks request failed (HTTP {})",
                status.as_u16()
            )));
        }
        let body: CheckRunsResponse = response.json().await?;
        let count = body.check_runs.len();
        runs.extend(body.check_runs);
        if count < PAGE {
            return Ok(summarize_checks(commit, &runs));
        }
    }
    Err(CliError::Other(
        "GitHub returned more than 10,000 check runs for the exact commit".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PULLS: &str = include_str!("../../../../tests/fixtures/reconcile/github-pulls.json");
    const CHECKS: &str =
        include_str!("../../../../tests/fixtures/reconcile/github-check-runs.json");

    #[test]
    fn pulls_reduce_state_and_drop_unmerged_test_merge_sha() {
        let pulls = parse_pulls(PULLS).unwrap();
        assert_eq!(pulls.len(), 4);
        let by_number: BTreeMap<u64, &MirrorPull> =
            pulls.iter().map(|pull| (pull.number, pull)).collect();
        assert_eq!(by_number[&205].state, "merged");
        assert_eq!(
            by_number[&205].merge_commit_sha.as_deref(),
            Some("4ba4ed31b984c3d04fc689d520aeae4355c803e7")
        );
        assert_eq!(by_number[&190].state, "closed");
        assert_eq!(by_number[&190].merge_commit_sha, None);
        assert_eq!(by_number[&210].state, "open");
        let index = index_pulls(&pulls, "only21mil/buzz", "main");
        assert!(
            !index.contains_key("fork/feature"),
            "fork heads are ignored"
        );
        let train = &index["sats/train-ci-hygiene-20260908"];
        assert_eq!(train.len(), 2);
        let chosen = select_pull(train, Some("4ba4ed31b984c3d04fc689d520aeae4355c803e7")).unwrap();
        assert_eq!(chosen.number, 205);
        let fallback =
            select_pull(train, Some("ffffffffffffffffffffffffffffffffffffffff")).unwrap();
        assert_eq!(
            fallback.number, 210,
            "latest updated wins without an exact head"
        );
        assert!(select_pull(&[], None).is_none());
    }

    #[test]
    fn check_summary_trusts_only_actions_at_the_exact_head() {
        let raw: crate::commands::repo_sync::CheckRunsResponse =
            serde_json::from_str(CHECKS).unwrap();
        let runs = raw.check_runs;
        let summary = summarize_checks("ce26abb48839a6f9dd208823d387bc5919e12120", &runs);
        assert_eq!(summary.state, "failure");
        assert_eq!(summary.trusted_runs, 4);
        assert_eq!(summary.failed, ["Unit Tests"]);
        assert_eq!(summary.pending, ["Web"]);
        let missing = summarize_checks("0000000000000000000000000000000000000000", &runs);
        assert_eq!(missing.state, "missing");
        assert_eq!(missing.trusted_runs, 0);
        let clean: Vec<CheckRun> = runs
            .into_iter()
            .filter(|run| run.name != "Unit Tests" && run.name != "Web")
            .collect();
        let summary = summarize_checks("ce26abb48839a6f9dd208823d387bc5919e12120", &clean);
        assert_eq!(summary.state, "success");
        assert_eq!(summary.trusted_runs, 2);
    }

    #[test]
    fn pending_beats_success_but_not_failure() {
        let raw: crate::commands::repo_sync::CheckRunsResponse =
            serde_json::from_str(CHECKS).unwrap();
        let pending_only: Vec<CheckRun> = raw
            .check_runs
            .into_iter()
            .filter(|run| run.name != "Unit Tests")
            .collect();
        let summary = summarize_checks("ce26abb48839a6f9dd208823d387bc5919e12120", &pending_only);
        assert_eq!(summary.state, "pending");
    }
}
