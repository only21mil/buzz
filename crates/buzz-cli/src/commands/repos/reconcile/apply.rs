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

/// What apply needs from the world: who signs, where the mains are, and a
/// way to publish one status. Live runs use the relay and the git reader;
/// tests use a fake.
pub(super) trait ApplyBackend {
    fn writer(&self) -> String;
    fn read_mains(&self) -> Result<(Option<String>, Option<String>), CliError>;
    async fn publish(
        &self,
        write: &PlannedWrite,
        content: &str,
        meta: GitStatusMeta,
    ) -> Result<String, CliError>;
}

pub(super) struct LiveBackend<'a> {
    pub(super) client: &'a BuzzClient,
    pub(super) reader: &'a GitReader,
}

impl ApplyBackend for LiveBackend<'_> {
    fn writer(&self) -> String {
        self.client.keys().public_key().to_hex()
    }

    fn read_mains(&self) -> Result<(Option<String>, Option<String>), CliError> {
        let (buzz, mirror) = self.reader.read_mains()?;
        Ok((buzz.main, mirror))
    }

    async fn publish(
        &self,
        write: &PlannedWrite,
        content: &str,
        meta: GitStatusMeta,
    ) -> Result<String, CliError> {
        match write.kind.as_str() {
            "pr_status" => {
                publish_pr_status(self.client, GitStatus::AppliedOrResolved, content, meta).await
            }
            "issue_status" => {
                publish_issue_status(self.client, GitStatus::AppliedOrResolved, content, meta).await
            }
            other => Err(CliError::Other(format!(
                "unknown planned write kind {other}"
            ))),
        }
    }
}

/// Write each planned status after both mains read back unchanged. A moved
/// main aborts before any write; a rejected write stops the remainder. Writes
/// already held back by the planner arrive as `skipped` and stay reported.
pub(super) async fn run(
    backend: &impl ApplyBackend,
    owner: &str,
    repo: &str,
    expected_buzz_main: &str,
    expected_mirror_main: &str,
    planned: Vec<PlannedWrite>,
    skipped: Vec<Skipped>,
) -> Result<ApplyReport, CliError> {
    let mut report = ApplyReport {
        mode: "apply".into(),
        planned: planned.clone(),
        written: Vec::new(),
        skipped,
    };
    if planned.is_empty() {
        return Ok(report);
    }
    let (buzz, mirror) = backend.read_mains()?;
    if buzz.as_deref() != Some(expected_buzz_main)
        || mirror.as_deref() != Some(expected_mirror_main)
    {
        return Err(CliError::Conflict(
            "a main ref moved between verification and apply; nothing was written".into(),
        ));
    }
    let writer = backend.writer();
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
        let response = backend.publish(&write, content, meta).await?;
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

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    struct Fake {
        writer: String,
        mains: (Option<String>, Option<String>),
        /// Relay responses in order; `None` is a transport error.
        responses: RefCell<Vec<Option<String>>>,
        published: RefCell<Vec<(String, Option<String>)>>,
    }

    impl ApplyBackend for Fake {
        fn writer(&self) -> String {
            self.writer.clone()
        }
        fn read_mains(&self) -> Result<(Option<String>, Option<String>), CliError> {
            Ok(self.mains.clone())
        }
        async fn publish(
            &self,
            write: &PlannedWrite,
            _content: &str,
            meta: GitStatusMeta,
        ) -> Result<String, CliError> {
            assert_eq!(meta.root_event, write.root_id);
            assert_eq!(meta.merge_commit, write.merge_commit);
            self.published
                .borrow_mut()
                .push((write.root_id.clone(), write.merge_commit.clone()));
            let mut responses = self.responses.borrow_mut();
            if responses.is_empty() {
                return Err(CliError::Other("no response".into()));
            }
            responses
                .remove(0)
                .ok_or_else(|| CliError::Other("transport".into()))
        }
    }

    fn write(kind: &str, root: &str, author: &str) -> PlannedWrite {
        PlannedWrite {
            kind: kind.into(),
            root_id: root.into(),
            root_author: author.into(),
            status: if kind == "pr_status" {
                "merged"
            } else {
                "resolved"
            }
            .into(),
            merge_commit: (kind == "pr_status").then(|| "merge".to_owned()),
        }
    }

    fn fake(writer: &str, responses: Vec<Option<&str>>) -> Fake {
        Fake {
            writer: writer.into(),
            mains: (Some("main".into()), Some("main".into())),
            responses: RefCell::new(
                responses
                    .into_iter()
                    .map(|r| r.map(str::to_owned))
                    .collect(),
            ),
            published: RefCell::new(Vec::new()),
        }
    }

    const OK: &str = r#"{"accepted":true,"event_id":"e1","message":""}"#;
    const REJECTED: &str = r#"{"accepted":false,"event_id":"e2","message":"policy"}"#;

    #[tokio::test]
    async fn moved_main_aborts_before_any_write() {
        let mut backend = fake("owner", vec![Some(OK)]);
        backend.mains.1 = Some("moved".into());
        let error = run(
            &backend,
            "owner",
            "repo",
            "main",
            "main",
            vec![write("pr_status", "p1", "author")],
            Vec::new(),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, CliError::Conflict(_)));
        assert!(backend.published.borrow().is_empty());
    }

    #[tokio::test]
    async fn first_rejection_stops_the_remainder() {
        let backend = fake("owner", vec![Some(OK), Some(REJECTED), Some(OK)]);
        let error = run(
            &backend,
            "owner",
            "repo",
            "main",
            "main",
            vec![
                write("pr_status", "p1", "author"),
                write("issue_status", "i1", "author"),
                write("pr_status", "p2", "author"),
            ],
            Vec::new(),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("2 written"));
        let published = backend.published.borrow();
        assert_eq!(published.len(), 2);
        assert_eq!(published[0], ("p1".into(), Some("merge".into())));
        assert_eq!(published[1], ("i1".into(), None));
    }

    #[tokio::test]
    async fn unauthorized_writer_is_skipped_and_reported() {
        let backend = fake("someone", vec![Some(OK), Some(OK)]);
        let report = run(
            &backend,
            "owner",
            "repo",
            "main",
            "main",
            vec![
                write("pr_status", "p1", "author"),
                write("pr_status", "p2", "someone"),
            ],
            Vec::new(),
        )
        .await
        .unwrap();
        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.skipped[0].planned.root_id, "p1");
        assert_eq!(report.skipped[0].reason, "unauthorized_writer");
        assert_eq!(report.written.len(), 1);
        assert_eq!(report.written[0].planned.root_id, "p2");
        assert!(report.written[0].accepted);
        assert_eq!(report.written[0].event_id.as_deref(), Some("e1"));
        assert_eq!(backend.published.borrow().len(), 1);
    }

    #[tokio::test]
    async fn planner_gated_writes_are_never_published() {
        let backend = fake("owner", vec![Some(OK)]);
        let held = Skipped {
            planned: write("issue_status", "i9", "author"),
            reason: "blocked_by:partial_pr_coverage".into(),
        };
        let report = run(
            &backend,
            "owner",
            "repo",
            "main",
            "main",
            vec![write("pr_status", "p1", "author")],
            vec![held],
        )
        .await
        .unwrap();
        assert_eq!(report.written.len(), 1);
        assert_eq!(report.skipped.len(), 1);
        assert_eq!(report.skipped[0].planned.root_id, "i9");
        assert!(backend
            .published
            .borrow()
            .iter()
            .all(|(root, _)| root != "i9"));
        // Nothing planned: no main read, no write.
        let mut idle = fake("owner", vec![]);
        idle.mains = (None, None);
        let report = run(&idle, "owner", "repo", "main", "main", vec![], vec![])
            .await
            .unwrap();
        assert!(report.written.is_empty());
    }
}
