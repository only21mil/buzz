//! NIP-34 lifecycle claims verified against both main refs, mirror PR state
//! and CI. Missing backend evidence never proves closure.
mod ancestry;
mod apply;
mod mirror;

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use self::ancestry::{pair_key, GitEvidence, GitReader};
use self::apply::{ApplyReport, PlannedWrite, Skipped};
use self::mirror::{CiSummary, MirrorPull};
use super::{read_branches, RepositoryBranch, RepositoryBranchesResponse};
use crate::commands::repo_sync::{github_auth_from_env, github_repo, GitHubRepo, GitRepo};
use crate::{client::BuzzClient, error::CliError};

const EVENT_BOUND: u32 = 100_000;
const MERGED: &str = "merged_or_resolved";

pub(super) struct Options {
    pub(super) limit: Option<usize>,
    pub(super) apply: bool,
    pub(super) git_cache: Option<String>,
}

/// Backend evidence gathered after the event reduction. Every `None` or
/// missing key means "not read", which never verifies anything.
#[derive(Debug, Default, Deserialize, Serialize)]
struct Evidence {
    git: Option<GitEvidence>,
    mirror_repository: Option<String>,
    /// Same-repository mirror pulls keyed by head branch; `None` = not queried.
    pulls: Option<BTreeMap<String, Vec<MirrorPull>>>,
    /// Trusted check-run summaries keyed by exact commit.
    checks: BTreeMap<String, CiSummary>,
    checks_queried: bool,
    gaps: Vec<String>,
}

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

    /// The principal named by a verified NIP-OA `auth` tag. Exactly one tag
    /// counts (more than one means none, as in the relay helper) and it must
    /// verify client-side against this event's signer: the relay does not
    /// inspect `auth` tags on status ingest, so an unverified tag proves
    /// nothing. The delegation's `kind=` and `created_at` clauses are held
    /// against this event, as the relay's action path does; a scoped or
    /// expired delegation leaves the event speaking for its signer only.
    fn principal(&self) -> Option<String> {
        let mut tags = self
            .tags
            .iter()
            .filter(|tag| tag.first().map(String::as_str) == Some("auth"));
        let tag = tags.next()?;
        if tags.next().is_some() {
            return None;
        }
        let signer = nostr::PublicKey::from_hex(&self.pubkey).ok()?;
        let json = serde_json::to_string(tag).ok()?;
        buzz_sdk::nip_oa::verify_auth_tag_for_signed_kind(
            &json,
            &signer,
            self.kind,
            self.created_at,
        )
        .ok()
        .map(|owner| owner.to_hex())
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
    issue_author: Option<String>,
    issue_status: Option<String>,
    issue_status_event_id: Option<String>,
    buzz_pr_id: Option<String>,
    pr_author: Option<String>,
    pr_status: Option<String>,
    pr_status_event_id: Option<String>,
    revision_event_id: Option<String>,
    superseded_by: Vec<String>,
    branch: Option<String>,
    commit: Option<String>,
    hosted_tip: Option<String>,
    fully_merged: Option<bool>,
    mirror_pr_number: Option<u64>,
    /// `open`, `closed` or `merged` on the mirror.
    mirror_pr_state: Option<String>,
    mirror_head: Option<String>,
    mirror_merge_sha: Option<String>,
    /// `success`, `failure`, `pending`, `missing`, `not_on_mirror` or
    /// `not_queried`.
    ci_state: Option<String>,
    ci_trusted_runs: Option<usize>,
    ci_failed: Vec<String>,
    in_buzz_main: Option<bool>,
    in_mirror_main: Option<bool>,
    /// First-parent commit of Buzz main containing this head.
    landing_sha: Option<String>,
    /// `merge-commit` named by the latest merged PR status.
    claimed_merge_sha: Option<String>,
    /// Merge commit proven to contain the head and to sit on both mains.
    merge_sha: Option<String>,
    merge_verified: bool,
    /// `active`, `verified`, `merged_unrecorded`, `claimed_unverified` or
    /// `merged_branch_undeleted`.
    closure_state: String,
    closure_verified: bool,
    pending_writes: Vec<String>,
    blockers: Vec<String>,
}

#[derive(Debug, Serialize)]
struct Ledger {
    schema_version: u32,
    repository: String,
    event_scan_exhausted: bool,
    default_branch: String,
    /// Default-branch tip from the hosted refs reader.
    buzz_default_ref: Option<String>,
    /// `refs/heads/main` read directly from the relay's git endpoint.
    buzz_main: Option<String>,
    mirror_repository: Option<String>,
    mirror_default_ref: Option<String>,
    ci_verified: bool,
    closure_verified: bool,
    coverage_gaps: Vec<String>,
    items_total: usize,
    items_truncated: bool,
    apply: ApplyReport,
    items: Vec<Item>,
}

pub(super) async fn run(
    client: &BuzzClient,
    owner: &str,
    repo: &str,
    options: Options,
) -> Result<(), CliError> {
    let owner = owner.to_ascii_lowercase();
    // Fetch authorization and hosted refs first; errors remain errors. A relay
    // without the branches endpoint falls back to git ls-remote below.
    let hosted = match read_branches(client, repo, &owner).await {
        Ok(branches) => Some(branches),
        Err(CliError::Relay { status: 404, .. }) => None,
        Err(error) => return Err(error),
    };
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
    let mut backends = Backends::open(client, &owner, repo, &options).await?;
    let (buzz, mirror_main) = backends.reader.read_mains()?;
    let branches = match hosted {
        Some(branches) => branches,
        None => {
            backends
                .gaps
                .push("hosted_refs_reader_unavailable_used_git_ls_remote".into());
            synthesize_branches(&backends.reader, &buzz)?
        }
    };
    let mut ledger = reduce(&owner, repo, &events, &branches);
    let evidence = backends
        .gather(&ledger, buzz.main.as_deref(), mirror_main.as_deref())
        .await?;
    verify(&mut ledger, &evidence);
    ledger.apply = if options.apply {
        let (Some(buzz_main), Some(mirror_main)) =
            (ledger.buzz_main.clone(), ledger.mirror_default_ref.clone())
        else {
            return Err(CliError::Conflict(
                "--apply refused: both main refs must read back before any status write".into(),
            ));
        };
        if ledger.buzz_default_ref != ledger.buzz_main {
            return Err(CliError::Conflict(
                "--apply refused: hosted refs and git main disagree; retry the read".into(),
            ));
        }
        let (planned, skipped) = plan_writes(&ledger);
        apply::run(
            &apply::LiveBackend {
                client,
                reader: &backends.reader,
            },
            &owner,
            repo,
            &buzz_main,
            &mirror_main,
            planned,
            skipped,
        )
        .await?
    } else {
        let (planned, skipped) = plan_writes(&ledger);
        ApplyReport {
            mode: "dry_run".into(),
            planned,
            written: Vec::new(),
            skipped,
        }
    };
    if let Some(limit) = options.limit {
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

/// Branch listing built from git refs when the relay has no hosted refs
/// endpoint. Divergence counts are unavailable and stay zero.
fn synthesize_branches(
    reader: &GitReader,
    buzz: &crate::commands::repo_sync::RemoteState,
) -> Result<RepositoryBranchesResponse, CliError> {
    let default_branch = buzz
        .head_target
        .as_deref()
        .and_then(|target| target.strip_prefix("refs/heads/"))
        .unwrap_or("main")
        .to_owned();
    let branches: Vec<RepositoryBranch> = reader
        .heads(buzz.main.as_deref())?
        .into_iter()
        .map(|(name, tip, fully_merged)| RepositoryBranch {
            name,
            tip,
            ahead: 0,
            behind: 0,
            fully_merged,
            last_commit_at: 0,
            open_pr_event_id: None,
        })
        .collect();
    Ok(RepositoryBranchesResponse {
        default_branch,
        branch_limit: branches.len(),
        branches_total: branches.len(),
        next_offset: None,
        snapshot: "git-ls-remote".into(),
        branches,
    })
}

/// The mirror clone announced for the repository, if any. No `limit`: some
/// relays apply `#d` after LIMIT and would drop the announcement.
async fn mirror_from_announcement(
    client: &BuzzClient,
    owner: &str,
    repo: &str,
) -> Result<Option<GitHubRepo>, CliError> {
    let raw = client
        .query(&serde_json::json!({
            "kinds": [30617],
            "authors": [owner],
            "#d": [repo],
        }))
        .await?;
    let events: Vec<Event> = serde_json::from_str(&raw)
        .map_err(|error| CliError::Other(format!("parse repository announcement: {error}")))?;
    let Some(announcement) = latest(
        events
            .iter()
            .filter(|event| event.kind == 30617 && event.value("d") == Some(repo)),
    ) else {
        return Ok(None);
    };
    let clone = announcement
        .tags
        .iter()
        .find(|tag| tag.first().map(String::as_str) == Some("clone"));
    Ok(clone.and_then(|tag| tag.iter().skip(1).find_map(|url| github_repo(url).ok())))
}

struct Backends {
    reader: GitReader,
    mirror: Option<GitHubRepo>,
    github_auth: crate::commands::repo_sync::GitHubAuth,
    gaps: Vec<String>,
}

impl Backends {
    async fn open(
        client: &BuzzClient,
        owner: &str,
        repo: &str,
        options: &Options,
    ) -> Result<Self, CliError> {
        let mut gaps = Vec::new();
        let mirror = mirror_from_announcement(client, owner, repo).await?;
        let github_auth = github_auth_from_env();
        if mirror.is_none() {
            gaps.push("mirror_not_configured".into());
        }
        if github_auth.is_err() {
            gaps.push("mirror_auth_missing".into());
        }
        let mirror = mirror.filter(|_| github_auth.is_ok());
        let github_auth =
            github_auth.unwrap_or_else(|_| crate::commands::repo_sync::GitHubAuth::absent());
        let cache = match &options.git_cache {
            Some(path) => std::path::PathBuf::from(path),
            None => GitRepo::work_root()?
                .join(".buzz-reconcile")
                .join(format!("{owner}-{repo}.git")),
        };
        let buzz_url = format!(
            "{}/git/{owner}/{repo}",
            client.relay_url().trim_end_matches('/')
        );
        let reader = GitReader::open(
            client,
            buzz_url,
            mirror.as_ref(),
            github_auth.clone(),
            cache,
        )?;
        Ok(Self {
            reader,
            mirror,
            github_auth,
            gaps,
        })
    }

    async fn gather(
        &self,
        ledger: &Ledger,
        buzz_main: Option<&str>,
        mirror_main: Option<&str>,
    ) -> Result<Evidence, CliError> {
        let mut evidence = Evidence {
            gaps: self.gaps.clone(),
            ..Evidence::default()
        };
        if let Some(mirror) = &self.mirror {
            let full_name = format!("{}/{}", mirror.owner, mirror.repo);
            let pulls = mirror::read_all_pulls(mirror, &self.github_auth).await?;
            evidence.pulls = Some(mirror::index_pulls(
                &pulls,
                &full_name,
                &ledger.default_branch,
            ));
            evidence.mirror_repository = Some(full_name);
        }
        let candidates = candidate_commits(ledger, evidence.pulls.as_ref());
        evidence.git = Some(self.reader.evidence(
            buzz_main,
            mirror_main,
            &candidates.commits,
            &candidates.pairs,
        )?);
        if let Some(mirror) = &self.mirror {
            for commit in ledger
                .items
                .iter()
                .filter_map(|item| item.commit.as_deref())
            {
                if evidence.checks.contains_key(commit) {
                    continue;
                }
                let summary = mirror::read_checks(mirror, &self.github_auth, commit).await?;
                evidence.checks.insert(commit.to_owned(), summary);
            }
            evidence.checks_queried = true;
        } else {
            evidence.gaps.push("ci_not_queried".into());
        }
        evidence.gaps.push("native_ci_not_queried".into());
        Ok(evidence)
    }
}

struct Candidates {
    commits: BTreeSet<String>,
    pairs: BTreeSet<(String, String)>,
}

/// Every commit the verifier will ask about: heads, claimed merges and mirror
/// merges, plus the head-in-merge pairs.
fn candidate_commits(
    ledger: &Ledger,
    pulls: Option<&BTreeMap<String, Vec<MirrorPull>>>,
) -> Candidates {
    let mut candidates = Candidates {
        commits: BTreeSet::new(),
        pairs: BTreeSet::new(),
    };
    for item in &ledger.items {
        let Some(commit) = &item.commit else {
            continue;
        };
        candidates.commits.insert(commit.clone());
        if let Some(claimed) = &item.claimed_merge_sha {
            candidates.commits.insert(claimed.clone());
            candidates.pairs.insert((commit.clone(), claimed.clone()));
        }
        if let Some(pull) = mirror_pull(item, pulls) {
            if let Some(merge) = &pull.merge_commit_sha {
                candidates.commits.insert(merge.clone());
                candidates.pairs.insert((commit.clone(), merge.clone()));
            }
        }
    }
    candidates
}

fn mirror_pull<'a>(
    item: &Item,
    pulls: Option<&'a BTreeMap<String, Vec<MirrorPull>>>,
) -> Option<&'a MirrorPull> {
    let branch = item.branch.as_deref()?;
    let candidates = pulls?.get(branch)?;
    mirror::select_pull(candidates, item.commit.as_deref())
}

/// Attach backend evidence to each item and decide closure. Pure; the decision
/// table is exercised by fixtures.
///
/// `closure_verified` means exactly: the head is an ancestor of both mains at
/// the SHAs read this run, the merged PR status names a commit that contains
/// the head and sits on both mains, and any linked issue is resolved. Blockers
/// stay reported alongside it; an orchestrator that wants to fail closed
/// requires `closure_verified` and an empty `blockers` list.
fn verify(ledger: &mut Ledger, evidence: &Evidence) {
    let mut gaps: Vec<String> = evidence.gaps.clone();
    let git = evidence.git.as_ref();
    ledger.buzz_main = git.and_then(|git| git.buzz_main.clone());
    ledger.mirror_repository = evidence.mirror_repository.clone();
    ledger.mirror_default_ref = git.and_then(|git| git.mirror_main.clone());
    let refs_agree = ledger.buzz_main.is_some() && ledger.buzz_main == ledger.buzz_default_ref;
    if ledger.buzz_main.is_some() && !refs_agree {
        gaps.push("buzz_refs_snapshot_mismatch".into());
    }
    if ledger.buzz_main.is_none() {
        gaps.push("buzz_main_unread".into());
    }
    if ledger.mirror_default_ref.is_none() {
        gaps.push("mirror_main_unread".into());
    }
    let mains_ok = refs_agree && ledger.mirror_default_ref.is_some();
    let mut all_claims_verified = true;
    for item in &mut ledger.items {
        item.blockers
            .retain(|blocker| blocker != "closure_unverified");
        let merge_claimed = item.pr_status.as_deref() == Some(MERGED)
            || item.issue_status.as_deref() == Some(MERGED);
        let closure_claimed = merge_claimed
            || item.pr_status.as_deref() == Some("closed")
            || item.issue_status.as_deref() == Some("closed");
        let Some(commit) = item.commit.clone() else {
            if closure_claimed {
                item.closure_state = "claimed_unverified".into();
                item.blockers.push("closure_unverified".into());
                all_claims_verified &= !merge_claimed;
            }
            continue;
        };
        // Mirror PR state.
        let pull = mirror_pull(item, evidence.pulls.as_ref());
        if let Some(pull) = pull {
            item.mirror_pr_number = Some(pull.number);
            item.mirror_pr_state = Some(pull.state.clone());
            item.mirror_head = Some(pull.head_sha.clone());
            item.mirror_merge_sha = pull.merge_commit_sha.clone();
            if pull.state == "open" && pull.head_sha != commit {
                item.blockers.push("mirror_head_mismatch".into());
            }
        } else if evidence.pulls.is_some() && item.branch.is_some() {
            item.blockers.push("missing_mirror_pr".into());
        }
        // CI at the exact head.
        match evidence.checks.get(&commit) {
            Some(summary) => {
                item.ci_state = Some(summary.state.clone());
                item.ci_trusted_runs = Some(summary.trusted_runs);
                item.ci_failed = summary.failed.clone();
            }
            None => item.ci_state = Some("not_queried".into()),
        }
        // Ancestry on both mains.
        let containment = git.and_then(|git| git.commits.get(&commit));
        if let Some(containment) = containment {
            item.in_buzz_main = Some(containment.in_buzz_main);
            item.in_mirror_main = Some(containment.in_mirror_main);
            item.landing_sha = containment.landing.clone();
        }
        // A named merge commit is valid when it sits on both mains and
        // contains the head. `Ok(())` or the blocker suffix that explains why
        // not: `not_on_main`, or `does_not_contain_head` (squash or rebase).
        let contained = |newer: &str| -> Result<(), &'static str> {
            let git = git.ok_or("not_on_main")?;
            let on_mains = git
                .commits
                .get(newer)
                .is_some_and(|c| c.in_buzz_main && c.in_mirror_main);
            if !on_mains {
                return Err("not_on_main");
            }
            if git.pairs.get(&pair_key(&commit, newer)).copied() != Some(true) {
                return Err("does_not_contain_head");
            }
            Ok(())
        };
        item.merge_verified =
            mains_ok && containment.is_some_and(|c| c.in_buzz_main && c.in_mirror_main);
        let claim_valid = item.claimed_merge_sha.as_deref().map(contained);
        if let (Some(Err(reason)), true) = (claim_valid, mains_ok) {
            item.blockers.push(format!("claimed_merge_{reason}"));
        }
        let mirror_merge_valid = item.mirror_merge_sha.as_deref().map(contained);
        if let (Some(Err(reason)), true) = (mirror_merge_valid, mains_ok) {
            item.blockers.push(format!("mirror_merge_{reason}"));
        }
        let claim_valid = claim_valid.map(|result| result.is_ok());
        let mirror_merge_valid = mirror_merge_valid.map(|result| result.is_ok());
        if item.buzz_pr_id.is_none() {
            // Branch-only rows have no status to record. A merged branch that
            // still exists is its own terminal state, never a pending write.
            item.closure_state = if item.merge_verified {
                "merged_branch_undeleted"
            } else {
                "active"
            }
            .into();
            continue;
        }
        if !item.merge_verified {
            if closure_claimed {
                item.closure_state = "claimed_unverified".into();
                item.blockers.push("closure_unverified".into());
                all_claims_verified &= !merge_claimed;
            } else {
                item.closure_state = "active".into();
            }
            continue;
        }
        item.merge_sha = if claim_valid == Some(true) {
            item.claimed_merge_sha.clone()
        } else if mirror_merge_valid == Some(true) {
            item.mirror_merge_sha.clone()
        } else {
            item.landing_sha.clone()
        };
        if item.mirror_pr_state.as_deref() == Some("open") {
            item.blockers.push("mirror_pr_open".into());
        }
        match item.ci_state.as_deref() {
            Some("success") => {}
            Some(state) => item.blockers.push(format!("ci_{state}")),
            None => item.blockers.push("ci_not_queried".into()),
        }
        let pr_recorded = item.pr_status.as_deref() == Some(MERGED) && claim_valid == Some(true);
        if !pr_recorded {
            item.pending_writes.push("pr_status:merged".into());
        }
        let issue_linked = item.issue_id.is_some() && item.issue_status.is_some();
        if issue_linked && item.issue_status.as_deref() != Some(MERGED) {
            item.pending_writes.push("issue_status:resolved".into());
        }
        if item.pending_writes.is_empty() {
            item.closure_state = "verified".into();
            item.closure_verified = true;
        } else {
            item.closure_state = "merged_unrecorded".into();
            item.blockers.push("closure_unrecorded".into());
            all_claims_verified = false;
        }
    }
    ledger.ci_verified = evidence.checks_queried
        && ledger
            .items
            .iter()
            .all(|item| item.commit.is_none() || item.ci_state.as_deref() != Some("not_queried"));
    ledger.closure_verified = mains_ok && all_claims_verified;
    if !mains_ok {
        gaps.push("merge_ancestry_not_verified".into());
    }
    gaps.push("status_authority_limited_to_root_author_and_repo_owner".into());
    gaps.push("refs_and_events_are_separate_snapshots".into());
    gaps.sort();
    gaps.dedup();
    ledger.coverage_gaps = gaps;
}

/// Blockers that keep a stale status from being written even after the merge
/// is proven: the record itself is contradictory, so a human decides.
const APPLY_GATES: [&str; 3] = [
    "partial_pr_coverage",
    "mismatched_head",
    "status_precedes_revision",
];

/// Stale statuses behind proven merges, one write per root, and the writes
/// held back because some row for that root carries an apply gate.
fn plan_writes(ledger: &Ledger) -> (Vec<PlannedWrite>, Vec<Skipped>) {
    let mut candidates: Vec<(PlannedWrite, Option<String>)> = Vec::new();
    for item in &ledger.items {
        let gate = item
            .blockers
            .iter()
            .find(|blocker| APPLY_GATES.contains(&blocker.as_str()))
            .map(|blocker| format!("blocked_by:{blocker}"));
        for write in &item.pending_writes {
            let candidate = match write.as_str() {
                "pr_status:merged" => PlannedWrite {
                    kind: "pr_status".into(),
                    root_id: item.buzz_pr_id.clone().unwrap_or_default(),
                    root_author: item.pr_author.clone().unwrap_or_default(),
                    status: "merged".into(),
                    merge_commit: item.merge_sha.clone(),
                },
                _ => PlannedWrite {
                    kind: "issue_status".into(),
                    root_id: item.issue_id.clone().unwrap_or_default(),
                    root_author: item.issue_author.clone().unwrap_or_default(),
                    status: "resolved".into(),
                    merge_commit: None,
                },
            };
            if !candidate.root_id.is_empty() {
                candidates.push((candidate, gate.clone()));
            }
        }
    }
    let gated: BTreeSet<(String, String)> = candidates
        .iter()
        .filter(|(_, gate)| gate.is_some())
        .map(|(write, _)| (write.kind.clone(), write.root_id.clone()))
        .collect();
    let mut planned: Vec<PlannedWrite> = Vec::new();
    let mut skipped: Vec<Skipped> = Vec::new();
    for (write, gate) in candidates {
        let key = (write.kind.clone(), write.root_id.clone());
        if gated.contains(&key) {
            if let Some(reason) = gate {
                if !skipped
                    .iter()
                    .any(|s| s.planned.kind == key.0 && s.planned.root_id == key.1)
                {
                    skipped.push(Skipped {
                        planned: write,
                        reason,
                    });
                }
            }
        } else if !planned
            .iter()
            .any(|existing| existing.kind == key.0 && existing.root_id == key.1)
        {
            planned.push(write);
        }
    }
    (planned, skipped)
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
    // Identities each event speaks for: its signer plus a verified principal.
    let identities: BTreeMap<&str, Vec<String>> = events
        .iter()
        .filter(|event| matches!(event.kind, 1618 | 1621 | 1630..=1633))
        .map(|event| {
            let mut ids = vec![event.pubkey.clone()];
            ids.extend(event.principal());
            (event.id.as_str(), ids)
        })
        .collect();
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
            // status events into repository state. Roles are not guessed; a
            // status counts when one of its identities is the repository
            // owner or one of the root's identities.
            let root_ids = &identities[root.id.as_str()];
            let authorized = identities[event.id.as_str()]
                .iter()
                .any(|identity| identity == owner || root_ids.contains(identity));
            if authorized && event.value("a").is_none_or(|value| value == coordinate) {
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
            let mut item = empty_item();
            item.issue_id = link.map(str::to_owned);
            item.issue_author = issue.map(|issue| issue.pubkey.clone());
            item.issue_status = issue.map(|_| status_name(issue_status).into());
            item.issue_status_event_id = issue_status.map(|event| event.id.clone());
            item.buzz_pr_id = Some(pr.id.clone());
            item.pr_author = Some(pr.pubkey.clone());
            item.pr_status = Some(pr_state.into());
            item.pr_status_event_id = status.map(|event| event.id.clone());
            item.revision_event_id = revision.map(|event| event.id.clone());
            item.superseded_by = superseded_by.clone();
            item.branch = branch.clone();
            item.commit = commit.clone();
            item.hosted_tip = hosted.map(|branch| branch.tip.clone());
            item.fully_merged = hosted.map(|branch| branch.fully_merged);
            item.claimed_merge_sha = status
                .filter(|event| event.kind == 1631)
                .and_then(|event| event.value("merge-commit"))
                .map(|value| value.to_ascii_lowercase());
            item.closure_state = if closure_claimed {
                "claimed_unverified"
            } else {
                "active"
            }
            .into();
            item.blockers = blockers;
            items.push(item);
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
        item.issue_author = Some(issue.pubkey.clone());
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
        schema_version: 2,
        repository: coordinate,
        event_scan_exhausted: true,
        default_branch: branches.default_branch.clone(),
        buzz_default_ref: branches
            .branches
            .iter()
            .find(|branch| branch.name == branches.default_branch)
            .map(|branch| branch.tip.clone()),
        buzz_main: None,
        mirror_repository: None,
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
        apply: ApplyReport {
            mode: "dry_run".into(),
            ..ApplyReport::default()
        },
        items,
    }
}

fn empty_item() -> Item {
    Item {
        issue_id: None,
        issue_author: None,
        issue_status: None,
        issue_status_event_id: None,
        buzz_pr_id: None,
        pr_author: None,
        pr_status: None,
        pr_status_event_id: None,
        revision_event_id: None,
        superseded_by: Vec::new(),
        branch: None,
        commit: None,
        hosted_tip: None,
        fully_merged: None,
        mirror_pr_number: None,
        mirror_pr_state: None,
        mirror_head: None,
        mirror_merge_sha: None,
        ci_state: None,
        ci_trusted_runs: None,
        ci_failed: Vec::new(),
        in_buzz_main: None,
        in_mirror_main: None,
        landing_sha: None,
        claimed_merge_sha: None,
        merge_sha: None,
        merge_verified: false,
        closure_state: "active".into(),
        closure_verified: false,
        pending_writes: Vec::new(),
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
        assert_eq!(one.items[0].claimed_merge_sha, None);
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
        assert_eq!(ledger.items[0].claimed_merge_sha.as_deref(), Some("merge"));
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
    const EVENTS: &str = include_str!("../../../tests/fixtures/reconcile/events.json");
    const BRANCHES: &str = include_str!("../../../tests/fixtures/reconcile/branches.json");
    const EVIDENCE: &str = include_str!("../../../tests/fixtures/reconcile/evidence.json");

    fn sha(tag: &str) -> String {
        tag.repeat(40)[..40].to_owned()
    }

    fn fixture_ledger() -> (Ledger, Evidence) {
        let events: Vec<Event> = serde_json::from_str(EVENTS).unwrap();
        let branches: RepositoryBranchesResponse = serde_json::from_str(BRANCHES).unwrap();
        let evidence: Evidence = serde_json::from_str(EVIDENCE).unwrap();
        (reduce("owner", "repo", &events, &branches), evidence)
    }

    fn pr_item<'a>(ledger: &'a Ledger, pr: &str) -> &'a Item {
        ledger
            .items
            .iter()
            .find(|item| item.buzz_pr_id.as_deref() == Some(pr))
            .unwrap_or_else(|| panic!("missing item for {pr}"))
    }

    fn has(item: &Item, blocker: &str) -> bool {
        item.blockers.iter().any(|value| value == blocker)
    }

    #[test]
    fn dry_run_decision_table_over_recorded_evidence() {
        let (mut ledger, evidence) = fixture_ledger();
        verify(&mut ledger, &evidence);
        assert_eq!(ledger.buzz_main.as_deref(), Some(sha("ma").as_str()));
        assert_eq!(
            ledger.mirror_default_ref.as_deref(),
            Some(sha("ma").as_str())
        );
        assert!(ledger.ci_verified);
        assert!(
            !ledger.closure_verified,
            "unrecorded and unverified claims remain"
        );

        // Merged, recorded, CI green, mirror merged: verified.
        let p1 = pr_item(&ledger, "p1");
        assert_eq!(p1.closure_state, "verified");
        assert!(p1.closure_verified && p1.merge_verified);
        assert_eq!(p1.merge_sha, Some(sha("d1")));
        assert_eq!(p1.mirror_pr_number, Some(1));
        assert_eq!(p1.ci_state.as_deref(), Some("success"));
        assert!(p1.blockers.is_empty(), "{:?}", p1.blockers);

        // Landed via the mirror but Buzz PR and issue still open: writes planned.
        let p2 = pr_item(&ledger, "p2");
        assert_eq!(p2.closure_state, "merged_unrecorded");
        assert!(p2.merge_verified && !p2.closure_verified);
        assert_eq!(
            p2.merge_sha,
            Some(sha("l2")),
            "mirror merge commit is adopted"
        );
        assert_eq!(
            p2.pending_writes,
            ["pr_status:merged", "issue_status:resolved"]
        );
        assert!(has(p2, "closure_unrecorded") && has(p2, "stale_open_pr"));

        // Merged status names a commit that does not contain the head.
        let p3 = pr_item(&ledger, "p3");
        assert!(has(p3, "claimed_merge_not_on_main"));
        assert_eq!(
            p3.merge_sha,
            Some(sha("l3")),
            "falls back to the landing commit"
        );
        assert_eq!(p3.pending_writes, ["pr_status:merged"]);
        assert_eq!(p3.closure_state, "merged_unrecorded");

        // Open, not landed: active, CI pending is informational only.
        let p4 = pr_item(&ledger, "p4");
        assert_eq!(p4.closure_state, "active");
        assert_eq!(p4.ci_state.as_deref(), Some("pending"));
        assert_eq!(p4.blockers, ["missing_issue_link"]);
        assert_eq!(p4.in_buzz_main, Some(false));

        // Merged claim with no ancestry on either main.
        let p5 = pr_item(&ledger, "p5");
        assert_eq!(p5.closure_state, "claimed_unverified");
        assert!(has(p5, "closure_unverified") && has(p5, "claimed_merge_does_not_contain_head"));
        assert!(!p5.merge_verified && p5.pending_writes.is_empty());

        // Closed without merge stays a claim, never a write.
        let p6 = pr_item(&ledger, "p6");
        assert_eq!(p6.closure_state, "claimed_unverified");
        assert!(has(p6, "closed_unmerged") && p6.pending_writes.is_empty());

        // Hosted tip and mirror head disagree with the PR commit.
        let p7 = pr_item(&ledger, "p7");
        assert!(has(p7, "mismatched_head") && has(p7, "mirror_head_mismatch"));
        assert_eq!(p7.closure_state, "active");

        // Merged and recorded but no trusted CI at the head: closure holds by
        // ancestry and status, the CI gap stays a blocker for fail-closed callers.
        let p8 = pr_item(&ledger, "p8");
        assert_eq!(p8.ci_state.as_deref(), Some("missing"));
        assert!(has(p8, "ci_missing"));
        assert_eq!(p8.closure_state, "verified");
        assert!(p8.merge_verified && p8.closure_verified && p8.pending_writes.is_empty());
        assert!(!p8.blockers.is_empty());

        // Dangling branches and PR-less resolved issues stay visible. A merged
        // branch that still exists is terminal, never a pending write.
        let dangling = ledger
            .items
            .iter()
            .find(|item| item.branch.as_deref() == Some("b9"))
            .unwrap();
        assert!(has(dangling, "dangling_branch"));
        assert_eq!(dangling.closure_state, "active");
        let undeleted = ledger
            .items
            .iter()
            .find(|item| item.branch.as_deref() == Some("b17"))
            .unwrap();
        assert!(has(undeleted, "dangling_branch"));
        assert_eq!(undeleted.closure_state, "merged_branch_undeleted");
        assert!(undeleted.merge_verified && !undeleted.closure_verified);
        assert!(undeleted.pending_writes.is_empty());
        assert!(!has(undeleted, "closure_unrecorded"));
        let orphan = ledger
            .items
            .iter()
            .find(|item| item.issue_id.as_deref() == Some("i10"))
            .unwrap();
        assert!(has(orphan, "missing_pr_link") && has(orphan, "closure_unverified"));

        // Superseded PR whose commit landed: merged but unrecorded; its moved
        // branch tip gates the write.
        let p11 = pr_item(&ledger, "p11");
        assert!(has(p11, "superseded_pr") && has(p11, "mismatched_head"));
        assert_eq!(p11.closure_state, "merged_unrecorded");
        assert_eq!(p11.mirror_pr_number, Some(11));
        let p12 = pr_item(&ledger, "p12");
        assert_eq!(p12.closure_state, "verified");
        assert_eq!(p12.mirror_pr_number, Some(12));
        assert_eq!(p12.blockers, ["missing_issue_link"]);

        // Apply gates: partial coverage (i14 has an unmerged second PR) and a
        // status older than the revision (p16) hold their writes back.
        let p14 = pr_item(&ledger, "p14");
        assert!(has(p14, "partial_pr_coverage") && p14.merge_verified);
        assert_eq!(p14.pending_writes, ["issue_status:resolved"]);
        let p16 = pr_item(&ledger, "p16");
        assert!(has(p16, "status_precedes_revision") && p16.merge_verified);
        assert_eq!(p16.pending_writes, ["pr_status:merged"]);

        let (planned, skipped) = plan_writes(&ledger);
        let keys: Vec<String> = planned
            .iter()
            .map(|write| format!("{}:{}", write.kind, write.root_id))
            .collect();
        assert_eq!(
            keys,
            [
                "pr_status:p16-old",
                "pr_status:p3",
                "pr_status:p2",
                "issue_status:i2"
            ]
        );
        let held: Vec<(String, String)> = skipped
            .iter()
            .map(|s| {
                (
                    format!("{}:{}", s.planned.kind, s.planned.root_id),
                    s.reason.clone(),
                )
            })
            .collect();
        assert_eq!(
            held,
            [
                (
                    "pr_status:p11".to_owned(),
                    "blocked_by:mismatched_head".to_owned()
                ),
                (
                    "pr_status:p16".to_owned(),
                    "blocked_by:status_precedes_revision".to_owned()
                ),
                (
                    "issue_status:i14".to_owned(),
                    "blocked_by:partial_pr_coverage".to_owned()
                ),
            ]
        );
        assert!(planned
            .iter()
            .all(|write| write.kind != "pr_status" || write.merge_commit.is_some()));
        assert!(planned.iter().all(|write| write.root_author == "author"));
        assert!(ledger
            .coverage_gaps
            .iter()
            .any(|gap| gap == "native_ci_not_queried"));
        assert!(!ledger
            .coverage_gaps
            .iter()
            .any(|gap| gap == "merge_ancestry_not_verified"));
    }

    #[test]
    fn unread_or_disagreeing_mains_verify_nothing_and_plan_nothing() {
        let (mut ledger, mut evidence) = fixture_ledger();
        evidence.git = None;
        verify(&mut ledger, &evidence);
        assert!(!ledger.closure_verified);
        assert!(ledger.items.iter().all(|item| !item.merge_verified));
        assert!(ledger
            .items
            .iter()
            .all(|item| item.pending_writes.is_empty()));
        assert!(plan_writes(&ledger).0.is_empty());
        assert!(ledger
            .coverage_gaps
            .iter()
            .any(|gap| gap == "buzz_main_unread"));
        assert_eq!(pr_item(&ledger, "p1").closure_state, "claimed_unverified");

        let (mut ledger, evidence) = fixture_ledger();
        ledger.buzz_default_ref = Some(sha("ff"));
        verify(&mut ledger, &evidence);
        assert!(ledger
            .coverage_gaps
            .iter()
            .any(|gap| gap == "buzz_refs_snapshot_mismatch"));
        assert!(ledger.items.iter().all(|item| !item.merge_verified));
        assert!(plan_writes(&ledger).0.is_empty());

        let (mut ledger, mut evidence) = fixture_ledger();
        evidence.git.as_mut().unwrap().mirror_main = None;
        verify(&mut ledger, &evidence);
        assert!(ledger
            .coverage_gaps
            .iter()
            .any(|gap| gap == "mirror_main_unread"));
        assert!(!ledger.closure_verified);
        assert!(plan_writes(&ledger).0.is_empty());
    }

    #[test]
    fn verification_is_order_independent() {
        let (mut one, evidence) = fixture_ledger();
        verify(&mut one, &evidence);
        let mut events: Vec<Event> = serde_json::from_str(EVENTS).unwrap();
        events.reverse();
        let branches: RepositoryBranchesResponse = serde_json::from_str(BRANCHES).unwrap();
        let mut two = reduce("owner", "repo", &events, &branches);
        verify(&mut two, &evidence);
        assert_eq!(
            serde_json::to_value(&one).unwrap(),
            serde_json::to_value(&two).unwrap()
        );
    }

    fn auth_tag(principal: &nostr::Keys, agent: &nostr::Keys) -> Vec<String> {
        scoped_auth_tag(principal, agent, "created_at<4294967295")
    }

    fn scoped_auth_tag(
        principal: &nostr::Keys,
        agent: &nostr::Keys,
        conditions: &str,
    ) -> Vec<String> {
        let json =
            buzz_sdk::nip_oa::compute_auth_tag(principal, &agent.public_key(), conditions).unwrap();
        serde_json::from_str(&json).unwrap()
    }

    fn merged_status(pubkey: &str, tags: &[&[&str]]) -> Event {
        let mut base: Vec<&[&str]> = vec![&["e", "pr", "", "root"], &["merge-commit", "merge"]];
        base.extend_from_slice(tags);
        let mut status = event("merged", 1631, 3, &base);
        status.pubkey = pubkey.into();
        status
    }

    fn pr_status(events: &[Event]) -> (String, bool) {
        let ledger = reduce("owner", "repo", events, &branches());
        let item = &ledger.items[0];
        (
            item.pr_status.clone().unwrap(),
            item.blockers
                .iter()
                .any(|v| v == "unrecognized_status_authority"),
        )
    }

    #[test]
    fn status_authority_follows_a_verified_auth_principal_only() {
        let principal = nostr::Keys::generate();
        let agent = nostr::Keys::generate();
        // Root signed by the agent under the principal's verified auth tag;
        // the status is signed by the principal directly.
        let mut events = roots();
        events[1].pubkey = agent.public_key().to_hex();
        events[1].tags.push(auth_tag(&principal, &agent));
        events.push(merged_status(&principal.public_key().to_hex(), &[]));
        assert_eq!(pr_status(&events), ("merged_or_resolved".into(), false));

        // The status may instead carry its own verified tag naming the root's
        // signer as principal.
        let mut events = roots();
        events[1].pubkey = principal.public_key().to_hex();
        let mut status = merged_status(&agent.public_key().to_hex(), &[]);
        status.tags.push(auth_tag(&principal, &agent));
        events.push(status);
        assert_eq!(pr_status(&events), ("merged_or_resolved".into(), false));

        // Forged: a tag naming the repository owner, or the root's signer,
        // with a bogus signature is ignored.
        let forger = nostr::Keys::generate();
        let mut events = roots();
        events[1].pubkey = agent.public_key().to_hex();
        let mut forged = merged_status(&forger.public_key().to_hex(), &[]);
        forged.tags.push(vec![
            "auth".into(),
            "owner".into(),
            "".into(),
            "ab".repeat(64),
        ]);
        events.push(forged);
        assert_eq!(pr_status(&events), ("open".into(), true));
        events.last_mut().unwrap().tags[2][1] = agent.public_key().to_hex();
        assert_eq!(pr_status(&events), ("open".into(), true));

        // A tag signed for a different agent does not transfer.
        let mut events = roots();
        events[1].pubkey = agent.public_key().to_hex();
        let other = nostr::Keys::generate();
        let mut wrong = merged_status(&other.public_key().to_hex(), &[]);
        wrong.tags.push(auth_tag(&principal, &agent));
        events.push(wrong);
        assert_eq!(pr_status(&events), ("open".into(), true));

        // More than one auth tag means none.
        let mut events = roots();
        events[1].pubkey = agent.public_key().to_hex();
        events[1].tags.push(auth_tag(&principal, &agent));
        events[1].tags.push(auth_tag(&principal, &agent));
        events.push(merged_status(&principal.public_key().to_hex(), &[]));
        assert_eq!(pr_status(&events), ("open".into(), true));
    }

    #[test]
    fn status_authority_holds_delegation_conditions_against_the_status() {
        let principal = nostr::Keys::generate();
        let agent = nostr::Keys::generate();
        // Root signed by the principal; the status (kind 1631 at t=3) is
        // signed by the agent under a delegation with conditions.
        let delegated = |conditions: &str| {
            let mut events = roots();
            events[1].pubkey = principal.public_key().to_hex();
            let mut status = merged_status(&agent.public_key().to_hex(), &[]);
            status
                .tags
                .push(scoped_auth_tag(&principal, &agent, conditions));
            events.push(status);
            pr_status(&events)
        };

        // Scoped to another kind: the agent speaks for itself only.
        assert_eq!(delegated("kind=1"), ("open".into(), true));
        // Expired before the status was created (strict bound).
        assert_eq!(delegated("created_at<3"), ("open".into(), true));
        // Not yet valid at the status time.
        assert_eq!(delegated("created_at>3"), ("open".into(), true));
        // Conditions cover the status kind and time window.
        assert_eq!(
            delegated("kind=1631&created_at>1&created_at<10"),
            ("merged_or_resolved".into(), false)
        );
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
