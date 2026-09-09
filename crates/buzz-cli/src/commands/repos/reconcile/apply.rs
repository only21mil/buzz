//! Status writes for proven merges. Every write goes through the same signed
//! status builders as `buzz pr status` and `buzz issues status`.
use serde::{Deserialize, Serialize};

use super::ancestry::GitReader;
use crate::client::BuzzClient;
use crate::commands::{issues::publish_issue_status, pr::publish_pr_status};
use crate::error::CliError;
use buzz_sdk::{GitRepoCoord, GitStatus, GitStatusMeta};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(super) struct PlannedWrite {
    /// `pr_status` or `issue_status`.
    pub(super) kind: String,
    pub(super) root_id: String,
    pub(super) root_author: String,
    /// `merged` for PRs, `resolved` for issues.
    pub(super) status: String,
    pub(super) merge_commit: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct WriteResult {
    #[serde(flatten)]
    pub(super) planned: PlannedWrite,
    pub(super) event_id: Option<String>,
    pub(super) accepted: bool,
    pub(super) response: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct Skipped {
    #[serde(flatten)]
    pub(super) planned: PlannedWrite,
    pub(super) reason: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub(super) struct ApplyReport {
    /// `dry_run` or `apply`.
    pub(super) mode: String,
    pub(super) planned: Vec<PlannedWrite>,
    pub(super) written: Vec<WriteResult>,
    pub(super) skipped: Vec<Skipped>,
}

/// Write each planned status after both mains read back unchanged. A moved
/// main aborts before any write; a rejected write stops the remainder.
pub(super) async fn run(
    client: &BuzzClient,
    owner: &str,
    repo: &str,
    reader: &GitReader,
    expected_buzz_main: &str,
    expected_mirror_main: &str,
    planned: Vec<PlannedWrite>,
) -> Result<ApplyReport, CliError> {
    let mut report = ApplyReport {
        mode: "apply".into(),
        planned: planned.clone(),
        written: Vec::new(),
        skipped: Vec::new(),
    };
    if planned.is_empty() {
        return Ok(report);
    }
    let (buzz, mirror) = reader.read_mains()?;
    if buzz.main.as_deref() != Some(expected_buzz_main)
        || mirror.as_deref() != Some(expected_mirror_main)
    {
        return Err(CliError::Conflict(
            "a main ref moved between verification and apply; nothing was written".into(),
        ));
    }
    let writer = client.keys().public_key().to_hex();
    for write in planned {
        if writer != owner && writer != write.root_author {
            report.skipped.push(Skipped {
                planned: write,
                reason: "unauthorized_writer".into(),
            });
            continue;
        }
        let meta = GitStatusMeta {
            root_event: write.root_id.clone(),
            accepted_revision_root: None,
            repo: Some(GitRepoCoord {
                owner: owner.to_owned(),
                id: repo.to_owned(),
            }),
            euc: None,
            recipients: vec![owner.to_owned()],
            applied_patches: vec![],
            merge_commit: write.merge_commit.clone(),
            applied_as_commits: vec![],
        };
        let content = match write.kind.as_str() {
            "pr_status" => "Merged; reconciled from exact main refs on Buzz and the mirror.",
            _ => "Resolved; the linked pull request merge was verified on both main refs.",
        };
        let response = match write.kind.as_str() {
            "pr_status" => {
                publish_pr_status(client, GitStatus::AppliedOrResolved, content, meta).await?
            }
            "issue_status" => {
                publish_issue_status(client, GitStatus::AppliedOrResolved, content, meta).await?
            }
            other => {
                return Err(CliError::Other(format!(
                    "unknown planned write kind {other}"
                )));
            }
        };
        let parsed: serde_json::Value = serde_json::from_str(&response).unwrap_or_default();
        let accepted = parsed
            .get("accepted")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let event_id = parsed
            .get("event_id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        report.written.push(WriteResult {
            planned: write,
            event_id,
            accepted,
            response,
        });
        if !accepted {
            return Err(CliError::Other(format!(
                "relay did not accept a reconciliation status write; {} written, remainder skipped",
                report.written.len()
            )));
        }
    }
    Ok(report)
}
