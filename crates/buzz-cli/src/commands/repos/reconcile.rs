//! Read-only NIP-34 lifecycle claims. Missing backend evidence never proves closure.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::{read_branches, RepositoryBranchesResponse};
use crate::{client::BuzzClient, error::CliError};

const EVENT_BOUND: u32 = 100_000;

#[derive(Clone, Debug, Deserialize)]
struct Event {
    id: String,
    pubkey: String,
    created_at: u64,
    kind: u16,
    tags: Vec<Vec<String>>,
}

impl Event {
    fn value(&self, name: &str) -> Option<&str> {
        self.tags.iter().find_map(|tag| {
            (tag.first().map(String::as_str) == Some(name))
                .then(|| tag.get(1).map(String::as_str))
                .flatten()
        })
    }

    fn has(&self, name: &str, value: &str) -> bool {
        self.tags.iter().any(|tag| {
            tag.first().map(String::as_str) == Some(name)
                && tag.get(1).map(String::as_str) == Some(value)
        })
    }

    fn refs(&self, marker: &str) -> Vec<&str> {
        self.tags
            .iter()
            .filter_map(|tag| {
                (tag.first().map(String::as_str) == Some("e")
                    && tag.get(3).map(String::as_str) == Some(marker))
                .then(|| tag.get(1).map(String::as_str))
                .flatten()
            })
            .collect()
    }

    fn root(&self) -> Option<&str> {
        let roots = self.refs("root");
        if roots.len() == 1 {
            return roots.first().copied();
        }
        if !roots.is_empty() {
            return None;
        }
        let refs: Vec<_> = self
            .tags
            .iter()
            .filter(|tag| tag.first().map(String::as_str) == Some("e"))
            .collect();
        if refs.len() == 1 && refs[0].get(3).is_none_or(String::is_empty) {
            refs[0].get(1).map(String::as_str)
        } else {
            None
        }
    }
}

#[derive(Debug, Serialize)]
struct Item {
    issue_id: Option<String>,
    issue_status: Option<String>,
    issue_status_event_id: Option<String>,
    buzz_pr_id: Option<String>,
    pr_status: Option<String>,
    pr_status_event_id: Option<String>,
    revision_event_id: Option<String>,
    superseded_by: Vec<String>,
    branch: Option<String>,
    commit: Option<String>,
    hosted_tip: Option<String>,
    fully_merged: Option<bool>,
    merge_sha: Option<String>,
    closure_state: String,
    blockers: Vec<String>,
}

#[derive(Debug, Serialize)]
struct Ledger {
    schema_version: u32,
    repository: String,
    event_scan_exhausted: bool,
    default_branch: String,
    buzz_default_ref: Option<String>,
    mirror_default_ref: Option<String>,
    ci_verified: bool,
    closure_verified: bool,
    coverage_gaps: Vec<String>,
    items_total: usize,
    items_truncated: bool,
    items: Vec<Item>,
}

pub(super) async fn run(
    client: &BuzzClient,
    owner: &str,
    repo: &str,
    limit: Option<usize>,
) -> Result<(), CliError> {
    // Fetch authorization and hosted refs first; errors remain errors.
    let branches = read_branches(client, repo, owner).await?;
    // Older relays filter #a after LIMIT. Exhaust the authorized kind stream
    // with the existing composite cursor, then scope roots locally. This also
    // captures legacy statuses which have no a tag.
    let values = client
        .query_all_bounded(
            serde_json::json!({
                "kinds": [1618, 1619, 1621, 1630, 1631, 1632, 1633]
            }),
            EVENT_BOUND,
        )
        .await?;
    let events: Vec<Event> = values
        .into_iter()
        .map(serde_json::from_value)
        .collect::<Result<_, _>>()
        .map_err(|error| CliError::Other(format!("parse lifecycle events: {error}")))?;
    let mut ledger = reduce(&owner.to_ascii_lowercase(), repo, &events, &branches);
    if let Some(limit) = limit {
        ledger.items.truncate(limit);
    }
    ledger.items_truncated = ledger.items.len() != ledger.items_total;
    println!(
        "{}",
        serde_json::to_string(&ledger)
            .map_err(|error| CliError::Other(format!("serialize lifecycle ledger: {error}")))?
    );
    Ok(())
}

// NIP-01 tie ordering: lower event ID wins at the same timestamp.
fn latest<'a>(events: impl Iterator<Item = &'a Event>) -> Option<&'a Event> {
    events.max_by(|a, b| {
        a.created_at
            .cmp(&b.created_at)
            .then_with(|| b.id.cmp(&a.id))
    })
}

fn status_name(event: Option<&Event>) -> &'static str {
    match event.map(|event| event.kind) {
        Some(1631) => "merged_or_resolved",
        Some(1632) => "closed",
        Some(1633) => "draft",
        _ => "open",
    }
}

fn reduce(
    owner: &str,
    repo: &str,
    events: &[Event],
    branches: &RepositoryBranchesResponse,
) -> Ledger {
    let coordinate = format!("30617:{owner}:{repo}");
    let roots: BTreeMap<&str, &Event> = events
        .iter()
        .filter(|event| matches!(event.kind, 1618 | 1621) && event.has("a", &coordinate))
        .map(|event| (event.id.as_str(), event))
        .collect();
    let mut statuses = BTreeMap::new();
    let mut ignored = BTreeSet::new();
    for (id, root) in &roots {
        let candidates = events
            .iter()
            .filter(|event| (1630..=1633).contains(&event.kind) && event.root() == Some(*id));
        let mut accepted = Vec::new();
        for event in candidates {
            // Conservative authority: do not turn arbitrary channel members'
            // status events into repository state. Roles are not guessed.
            if (event.pubkey == root.pubkey || event.pubkey == owner)
                && event.value("a").is_none_or(|value| value == coordinate)
            {
                accepted.push(event);
            } else {
                ignored.insert(*id);
            }
        }
        statuses.insert(*id, latest(accepted.into_iter()));
    }
    let mut items = Vec::new();
    let mut covered_issues = BTreeSet::new();
    let mut covered_branches = BTreeSet::new();
    for pr in roots.values().filter(|event| event.kind == 1618) {
        let updates = events.iter().filter(|event| {
            event.kind == 1619
                && event.value("E") == Some(pr.id.as_str())
                && event.pubkey == pr.pubkey
                && event.has("a", &coordinate)
                && event.created_at >= pr.created_at
        });
        let revision = latest(updates);
        let commit = revision.unwrap_or(pr).value("c").map(str::to_owned);
        let branch = pr.value("branch-name").map(str::to_owned);
        let hosted = branch
            .as_deref()
            .and_then(|name| branches.branches.iter().find(|branch| branch.name == name));
        if let Some(branch) = &branch {
            covered_branches.insert(branch.clone());
        }
        let superseded_by: Vec<String> = roots
            .values()
            .filter(|event| {
                event.kind == 1618
                    && event.pubkey == pr.pubkey
                    && event.created_at >= pr.created_at
                    && event.id != pr.id
                    && event.tags.iter().any(|tag| {
                        tag.first().map(String::as_str) == Some("e")
                            && tag.get(1).map(String::as_str) == Some(pr.id.as_str())
                            && tag
                                .get(3)
                                .is_none_or(|marker| marker.is_empty() || marker == "root")
                    })
            })
            .map(|event| event.id.clone())
            .collect();
        let status = statuses[pr.id.as_str()];
        let pr_state = status_name(status);
        let links: BTreeSet<_> = pr.refs("issue").into_iter().collect();
        let links: Vec<Option<&str>> = if links.is_empty() {
            vec![None]
        } else {
            links.into_iter().map(Some).collect()
        };
        for link in links {
            let issue = link
                .and_then(|id| roots.get(id).copied())
                .filter(|event| event.kind == 1621);
            if let Some(issue) = issue {
                covered_issues.insert(issue.id.as_str());
            }
            let issue_status = issue.and_then(|issue| statuses[issue.id.as_str()]);
            let mut blockers = Vec::new();
            if issue.is_none() {
                blockers.push(
                    if link.is_some() {
                        "missing_issue_root"
                    } else {
                        "missing_issue_link"
                    }
                    .into(),
                );
            }
            if hosted.is_none() {
                blockers.push("missing_hosted_branch".into());
            }
            if commit.is_none() {
                blockers.push("missing_commit".into());
            }
            if hosted.is_some_and(|branch| Some(&branch.tip) != commit.as_ref()) {
                blockers.push("mismatched_head".into());
            }
            if !superseded_by.is_empty() {
                blockers.push("superseded_pr".into());
            }
            if revision.is_some_and(|revision| {
                status.is_some_and(|status| status.created_at < revision.created_at)
            }) {
                blockers.push("status_precedes_revision".into());
            }
            if ignored.contains(pr.id.as_str())
                || issue.is_some_and(|issue| ignored.contains(issue.id.as_str()))
            {
                blockers.push("unrecognized_status_authority".into());
            }
            if pr_state == "closed"
                && !hosted.is_some_and(|branch| {
                    branch.fully_merged && Some(&branch.tip) == commit.as_ref()
                })
            {
                blockers.push("closed_unmerged".into());
            }
            if hosted.is_some_and(|branch| branch.fully_merged)
                && matches!(pr_state, "open" | "draft")
            {
                blockers.push("stale_open_pr".into());
            }
            let closure_claimed = matches!(pr_state, "merged_or_resolved" | "closed")
                || issue.is_some_and(|_| {
                    matches!(status_name(issue_status), "merged_or_resolved" | "closed")
                });
            if closure_claimed {
                blockers.push("closure_unverified".into());
            }
            items.push(Item {
                issue_id: link.map(str::to_owned),
                issue_status: issue.map(|_| status_name(issue_status).into()),
                issue_status_event_id: issue_status.map(|event| event.id.clone()),
                buzz_pr_id: Some(pr.id.clone()),
                pr_status: Some(pr_state.into()),
                pr_status_event_id: status.map(|event| event.id.clone()),
                revision_event_id: revision.map(|event| event.id.clone()),
                superseded_by: superseded_by.clone(),
                branch: branch.clone(),
                commit: commit.clone(),
                hosted_tip: hosted.map(|branch| branch.tip.clone()),
                fully_merged: hosted.map(|branch| branch.fully_merged),
                merge_sha: status
                    .filter(|event| event.kind == 1631)
                    .and_then(|event| event.value("merge-commit"))
                    .map(str::to_owned),
                closure_state: if closure_claimed {
                    "claimed_unverified"
                } else {
                    "active"
                }
                .into(),
                blockers,
            });
        }
    }
    for issue in roots
        .values()
        .filter(|event| event.kind == 1621 && !covered_issues.contains(event.id.as_str()))
    {
        let status = statuses[issue.id.as_str()];
        let state = status_name(status);
        let mut item = empty_item();
        item.issue_id = Some(issue.id.clone());
        item.issue_status = Some(state.into());
        item.issue_status_event_id = status.map(|event| event.id.clone());
        item.blockers.push("missing_pr_link".into());
        if ignored.contains(issue.id.as_str()) {
            item.blockers.push("unrecognized_status_authority".into());
        }
        if matches!(state, "merged_or_resolved" | "closed") {
            item.closure_state = "claimed_unverified".into();
            item.blockers.push("closure_unverified".into());
        }
        items.push(item);
    }
    for branch in &branches.branches {
        if branch.name == branches.default_branch || covered_branches.contains(&branch.name) {
            continue;
        }
        let mut item = empty_item();
        item.branch = Some(branch.name.clone());
        item.commit = Some(branch.tip.clone());
        item.hosted_tip = Some(branch.tip.clone());
        item.fully_merged = Some(branch.fully_merged);
        item.blockers.push("dangling_branch".into());
        items.push(item);
    }
    let mut coverage: BTreeMap<String, (bool, bool)> = BTreeMap::new();
    for item in &items {
        if let (Some(issue), Some(status)) = (&item.issue_id, &item.pr_status) {
            let entry = coverage.entry(issue.clone()).or_default();
            if status == "merged_or_resolved" {
                entry.0 = true;
            } else {
                entry.1 = true;
            }
        }
    }
    for item in &mut items {
        if item.issue_id.as_ref().and_then(|issue| coverage.get(issue)) == Some(&(true, true)) {
            item.blockers.push("partial_pr_coverage".into());
        }
    }
    items.sort_by(|a, b| {
        (&a.issue_id, &a.buzz_pr_id, &a.branch).cmp(&(&b.issue_id, &b.buzz_pr_id, &b.branch))
    });
    Ledger {
        schema_version: 1,
        repository: coordinate,
        event_scan_exhausted: true,
        default_branch: branches.default_branch.clone(),
        buzz_default_ref: branches
            .branches
            .iter()
            .find(|branch| branch.name == branches.default_branch)
            .map(|branch| branch.tip.clone()),
        mirror_default_ref: None,
        ci_verified: false,
        closure_verified: false,
        coverage_gaps: vec![
            "ci_not_queried".into(),
            "mirror_not_queried".into(),
            "merge_ancestry_not_verified".into(),
            "status_authority_limited_to_root_author_and_repo_owner".into(),
            "refs_and_events_are_separate_snapshots".into(),
        ],
        items_total: items.len(),
        items_truncated: false,
        items,
    }
}

fn empty_item() -> Item {
    Item {
        issue_id: None,
        issue_status: None,
        issue_status_event_id: None,
        buzz_pr_id: None,
        pr_status: None,
        pr_status_event_id: None,
        revision_event_id: None,
        superseded_by: Vec::new(),
        branch: None,
        commit: None,
        hosted_tip: None,
        fully_merged: None,
        merge_sha: None,
        closure_state: "active".into(),
        blockers: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::repos::RepositoryBranch;

    fn event(id: &str, kind: u16, time: u64, tags: &[&[&str]]) -> Event {
        Event {
            id: id.into(),
            kind,
            created_at: time,
            pubkey: "author".into(),
            tags: tags
                .iter()
                .map(|tag| tag.iter().map(|v| (*v).into()).collect())
                .collect(),
        }
    }
    fn branches() -> RepositoryBranchesResponse {
        RepositoryBranchesResponse {
            default_branch: "main".into(),
            branch_limit: 200,
            branches_total: 1,
            next_offset: None,
            snapshot: "snapshot".into(),
            branches: vec![RepositoryBranch {
                name: "feature".into(),
                tip: "tip".into(),
                ahead: 1,
                behind: 0,
                fully_merged: false,
                last_commit_at: 10,
                open_pr_event_id: None,
            }],
        }
    }
    fn roots() -> Vec<Event> {
        vec![
            event("issue", 1621, 1, &[&["a", "30617:owner:repo"]]),
            event(
                "pr",
                1618,
                2,
                &[
                    &["a", "30617:owner:repo"],
                    &["e", "issue", "", "issue"],
                    &["c", "tip"],
                    &["branch-name", "feature"],
                ],
            ),
        ]
    }
    #[test]
    fn issue_to_pr_uses_explicit_links_and_exact_tip() {
        let ledger = reduce("owner", "repo", &roots(), &branches());
        assert_eq!(ledger.items.len(), 1);
        assert_eq!(ledger.items[0].issue_id.as_deref(), Some("issue"));
        assert_eq!(ledger.items[0].pr_status.as_deref(), Some("open"));
        assert!(ledger.items[0].blockers.is_empty());
        assert!(!ledger.closure_verified);
        assert!(!ledger.ci_verified);
    }
    #[test]
    fn latest_status_is_order_independent_and_respects_root_marker() {
        let mut events = roots();
        events.extend([
            event(
                "z",
                1631,
                3,
                &[
                    &["e", "other", "", "reply"],
                    &["e", "pr", "", "root"],
                    &["merge-commit", "merge"],
                ],
            ),
            event("a", 1632, 3, &[&["e", "pr", "", "root"]]),
            event("old", 1630, 1, &[&["e", "pr", "", "root"]]),
        ]);
        let one = reduce("owner", "repo", &events, &branches());
        events.reverse();
        let two = reduce("owner", "repo", &events, &branches());
        assert_eq!(
            serde_json::to_value(&one).unwrap(),
            serde_json::to_value(&two).unwrap()
        );
        assert_eq!(one.items[0].pr_status.as_deref(), Some("closed"));
        assert!(one.items[0].blockers.iter().any(|v| v == "closed_unmerged"));
        assert_eq!(one.items[0].merge_sha, None);
    }
    #[test]
    fn revisions_supersession_and_foreign_authors_do_not_prove_completion() {
        let mut events = roots();
        events.extend([
            event(
                "update",
                1619,
                3,
                &[&["a", "30617:owner:repo"], &["E", "pr"], &["c", "updated"]],
            ),
            event(
                "replacement",
                1618,
                4,
                &[&["a", "30617:owner:repo"], &["e", "pr"], &["c", "updated"]],
            ),
            event("forged", 1631, 10, &[&["e", "pr", "", "root"]]),
        ]);
        events.last_mut().unwrap().pubkey = "stranger".into();
        let ledger = reduce("owner", "repo", &events, &branches());
        let pr = ledger
            .items
            .iter()
            .find(|item| item.buzz_pr_id.as_deref() == Some("pr"))
            .unwrap();
        assert_eq!(pr.commit.as_deref(), Some("updated"));
        assert_eq!(pr.pr_status.as_deref(), Some("open"));
        assert_eq!(pr.superseded_by, ["replacement"]);
        assert!(pr.blockers.iter().any(|v| v == "mismatched_head"));
        assert!(pr
            .blockers
            .iter()
            .any(|v| v == "unrecognized_status_authority"));
    }
    #[test]
    fn merged_claim_and_missing_link_stay_unverified() {
        let mut events = roots();
        events.push(event(
            "merged",
            1631,
            3,
            &[&["e", "pr", "", "root"], &["merge-commit", "merge"]],
        ));
        let ledger = reduce("owner", "repo", &events, &branches());
        assert_eq!(ledger.items[0].merge_sha.as_deref(), Some("merge"));
        assert_eq!(ledger.items[0].closure_state, "claimed_unverified");
        assert!(!ledger.closure_verified);
        let ledger = reduce("owner", "repo", &events[..1], &branches());
        assert_eq!(ledger.items.len(), 2);
        assert!(ledger
            .items
            .iter()
            .any(|item| item.blockers.iter().any(|v| v == "dangling_branch")));
        assert!(ledger
            .items
            .iter()
            .any(|item| item.blockers.iter().any(|v| v == "missing_pr_link")));
    }
    #[test]
    fn coordinate_filter_does_not_join_foreign_issue_or_status() {
        // Regression binding: af633f9f6be8c27c2261778c11fe52613583a68a47719148d553b3c8ad9d9fa5.
        let mut events = roots();
        events[0].tags = vec![vec!["a".into(), "30617:owner:other".into()]];
        events.push(event(
            "foreign",
            1632,
            9,
            &[&["a", "30617:owner:other"], &["e", "pr", "", "root"]],
        ));
        let ledger = reduce("owner", "repo", &events, &branches());
        assert_eq!(ledger.items.len(), 1);
        assert_eq!(ledger.items[0].issue_status, None);
        assert_eq!(ledger.items[0].pr_status.as_deref(), Some("open"));
        assert!(ledger.items[0]
            .blockers
            .iter()
            .any(|v| v == "missing_issue_root"));
    }
    #[test]
    fn every_linked_pr_remains_visible_when_coverage_is_partial() {
        let mut events = roots();
        events.push(event(
            "other-pr",
            1618,
            3,
            &[
                &["a", "30617:owner:repo"],
                &["e", "issue", "", "issue"],
                &["c", "other"],
            ],
        ));
        events.push(event("merged", 1631, 4, &[&["e", "pr", "", "root"]]));
        let ledger = reduce("owner", "repo", &events, &branches());
        assert_eq!(ledger.items.len(), 2);
        assert!(ledger
            .items
            .iter()
            .all(|item| item.issue_id.as_deref() == Some("issue")));
        assert!(ledger.items.iter().all(|item| item
            .blockers
            .iter()
            .any(|blocker| blocker == "partial_pr_coverage")));
        assert!(!ledger.closure_verified);
    }
}
