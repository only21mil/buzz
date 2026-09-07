//! Bounded branch visibility for hosted repositories.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    extract::{Path as AxumPath, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::process::Command;
use tracing::error;

use super::hydrate::{hydrate_for_read, HydrationOptions};
use super::transport::{
    authorize_git_read, harden_git_env, hydrate_error_to_response, validate_repo_id, GitAuth,
    GitRepoParams,
};
use crate::state::AppState;

const BRANCH_LIMIT: usize = 200;
const PR_LIMIT: i64 = 10_000;
const STATUS_LIMIT: i64 = 20_000;
const BRANCH_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_GIT_OUTPUT_BYTES: usize = 1024 * 1024;

/// One hosted branch and its relationship to the repository default branch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RepositoryBranch {
    /// Unprefixed branch name.
    pub name: String,
    /// Full commit object ID at the branch tip.
    pub tip: String,
    /// Commits reachable only from this branch.
    pub ahead: u64,
    /// Commits reachable only from the default branch.
    pub behind: u64,
    /// Whether the branch tip is fully contained in the default branch.
    pub fully_merged: bool,
    /// Unix timestamp of the tip commit.
    pub last_commit_at: i64,
    /// Linked open pull-request root event, when one exists.
    pub open_pr_event_id: Option<String>,
}

/// Bounded result page; ordering is unmerged first, then newest commit and name.
#[derive(Default, Deserialize)]
pub struct BranchQuery {
    offset: Option<usize>,
    limit: Option<usize>,
}

#[derive(Debug, Serialize)]
struct RepositoryBranchesResponse {
    default_branch: String,
    branches: Vec<RepositoryBranch>,
    branch_limit: usize,
    branches_total: usize,
    next_offset: Option<usize>,
    snapshot: String,
}

/// Return the bounded branch listing for one fetch-authorized repository.
pub async fn repository_branches(
    State(state): State<Arc<AppState>>,
    auth: GitAuth,
    AxumPath(params): AxumPath<GitRepoParams>,
    Query(query): Query<BranchQuery>,
) -> Response {
    let started_at = Instant::now();
    let response = repository_branches_inner(&state, &auth, &params, query, started_at).await;
    metrics::counter!(
        "buzz_git_branch_requests_total",
        "status" => response.status().as_u16().to_string()
    )
    .increment(1);
    metrics::histogram!("buzz_git_branch_seconds").record(started_at.elapsed().as_secs_f64());
    response
}

async fn repository_branches_inner(
    state: &Arc<AppState>,
    auth: &GitAuth,
    params: &GitRepoParams,
    query: BranchQuery,
    started_at: Instant,
) -> Response {
    let repo_name = match validate_repo_id(&params.owner, &params.repo) {
        Ok(repo_name) => repo_name,
        Err(response) => return response,
    };

    // This is the exact clone/fetch read gate. It runs before any ref, manifest,
    // object, or PR lookup so a denied caller cannot enumerate repository state.
    let channel_id = match authorize_git_read(
        &state.db,
        auth.tenant.community(),
        &auth.pubkey,
        &params.owner,
        repo_name,
    )
    .await
    {
        Ok(channel_id) => channel_id,
        Err(response) => return response,
    };

    let limit = query.limit.unwrap_or(BRANCH_LIMIT);
    if !(1..=BRANCH_LIMIT).contains(&limit) {
        return (StatusCode::BAD_REQUEST, "limit must be between 1 and 200").into_response();
    }
    let offset = query.offset.unwrap_or(0);
    let deadline = started_at + BRANCH_TIMEOUT;
    let _permit = match Arc::clone(&state.git_semaphore).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [(header::RETRY_AFTER, "5")],
                "git service busy",
            )
                .into_response()
        }
    };

    let hydration = hydrate_for_read(
        &state.git_store,
        &auth.tenant,
        &params.owner,
        repo_name,
        HydrationOptions {
            pack_cache: &state.git_pack_cache,
            scratch_dir: &state.config.git_repo_path,
            max_pack_bytes: state.config.git_max_pack_bytes,
            max_repo_bytes: state.config.git_max_repo_bytes,
        },
    );
    let repo = match tokio::time::timeout(remaining(deadline), hydration).await {
        Err(_) => return timeout_response(),
        Ok(Ok(Some(repo))) => repo,
        Ok(Ok(None)) => return (StatusCode::NOT_FOUND, "repository not found").into_response(),
        Ok(Err(error)) => return hydrate_error_to_response(&params.owner, repo_name, error),
    };

    // Read HEAD and refs from the same hydrated manifest snapshot.
    let head = match run_git(repo.path(), &["symbolic-ref", "HEAD"], deadline).await {
        Ok(head) => head,
        Err(response) => return response,
    };
    let default_ref = match std::str::from_utf8(&head) {
        Ok(head) => head.trim(),
        Err(_) => return git_error("invalid HEAD"),
    };
    let Some(default_branch) = default_ref.strip_prefix("refs/heads/") else {
        return (
            StatusCode::CONFLICT,
            "repository default ref is not a branch",
        )
            .into_response();
    };
    let (mut branches, branches_total, snapshot) =
        match collect_branch_page(repo.path(), default_ref, deadline, offset, limit).await {
            Ok(page) => page,
            Err(response) => return response,
        };
    drop(repo);

    if let Err(response) = match tokio::time::timeout(
        remaining(deadline),
        attach_open_prs(
            state,
            auth,
            channel_id,
            &params.owner,
            repo_name,
            &mut branches,
        ),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => return timeout_response(),
    } {
        return response;
    }

    branches.sort_by(|left, right| {
        left.fully_merged
            .cmp(&right.fully_merged)
            .then_with(|| right.last_commit_at.cmp(&left.last_commit_at))
            .then_with(|| left.name.cmp(&right.name))
    });

    json_response(RepositoryBranchesResponse {
        default_branch: default_branch.to_string(),
        branches,
        branch_limit: BRANCH_LIMIT,
        branches_total,
        next_offset: (offset.saturating_add(limit) < branches_total)
            .then_some(offset.saturating_add(limit)),
        snapshot,
    })
}

async fn collect_branch_page(
    repo_path: &Path,
    default_ref: &str,
    deadline: Instant,
    offset: usize,
    limit: usize,
) -> Result<(Vec<RepositoryBranch>, usize, String), Response> {
    let output = run_git(
        repo_path,
        &[
            "for-each-ref",
            "--format=%(refname)%00%(objectname)%00%(committerdate:unix)",
            "refs/heads/",
        ],
        deadline,
    )
    .await?;
    let text = std::str::from_utf8(&output)
        .map_err(|_| git_error("git returned non-UTF-8 branch metadata"))?;
    if !text.is_empty()
        && !text
            .lines()
            .any(|line| line.split('\0').next() == Some(default_ref))
    {
        return Err((StatusCode::CONFLICT, "hosted default branch is missing").into_response());
    }
    let snapshot = hex::encode(Sha256::digest([default_ref.as_bytes(), &output].concat()));
    let merged_output = if text.is_empty() {
        Vec::new()
    } else {
        run_git(
            repo_path,
            &[
                "for-each-ref",
                "--format=%(refname)",
                &format!("--merged={default_ref}"),
                "refs/heads/",
            ],
            deadline,
        )
        .await?
    };
    let merged_text =
        std::str::from_utf8(&merged_output).map_err(|_| git_error("invalid merged refs"))?;
    let merged: HashSet<&str> = merged_text.lines().collect();
    let mut rows = Vec::new();
    for line in text.lines() {
        let mut fields = line.split('\0');
        let full_name = fields.next().unwrap_or_default();
        let tip = fields.next().unwrap_or_default();
        let timestamp = fields.next().unwrap_or_default();
        if fields.next().is_some() || !full_name.starts_with("refs/heads/") {
            return Err(git_error("git returned malformed branch metadata"));
        }
        let last_commit_at = timestamp
            .parse::<i64>()
            .map_err(|_| git_error("git returned malformed commit timestamp"))?;
        rows.push(RepositoryBranch {
            name: full_name["refs/heads/".len()..].to_string(),
            tip: tip.to_string(),
            ahead: 0,
            behind: 0,
            fully_merged: merged.contains(full_name),
            last_commit_at,
            open_pr_event_id: None,
        });
    }
    rows.sort_by(|a, b| {
        a.fully_merged
            .cmp(&b.fully_merged)
            .then_with(|| b.last_commit_at.cmp(&a.last_commit_at))
            .then_with(|| a.name.cmp(&b.name))
    });
    let total = rows.len();
    let mut rows: Vec<_> = rows.into_iter().skip(offset).take(limit).collect();
    for row in &mut rows {
        let full_name = format!("refs/heads/{}", row.name);
        if full_name != default_ref {
            let counts = run_git(
                repo_path,
                &[
                    "rev-list",
                    "--left-right",
                    "--count",
                    &format!("{default_ref}...{full_name}"),
                ],
                deadline,
            )
            .await?;
            (row.behind, row.ahead) = parse_counts(&counts)?;
        }
    }
    Ok((rows, total, snapshot))
}

#[cfg(test)]
async fn collect_branch_rows(
    repo_path: &Path,
    default_ref: &str,
    deadline: Instant,
) -> Result<Vec<RepositoryBranch>, Response> {
    collect_branch_page(repo_path, default_ref, deadline, 0, BRANCH_LIMIT)
        .await
        .map(|page| page.0)
}

fn parse_counts(output: &[u8]) -> Result<(u64, u64), Response> {
    let text = std::str::from_utf8(output)
        .map_err(|_| git_error("git returned non-UTF-8 ahead/behind counts"))?;
    let mut values = text.split_whitespace();
    let behind = values
        .next()
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| git_error("git returned malformed ahead/behind counts"))?;
    let ahead = values
        .next()
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| git_error("git returned malformed ahead/behind counts"))?;
    if values.next().is_some() {
        return Err(git_error("git returned malformed ahead/behind counts"));
    }
    Ok((behind, ahead))
}

async fn attach_open_prs(
    state: &Arc<AppState>,
    auth: &GitAuth,
    channel_id: uuid::Uuid,
    owner: &str,
    repo: &str,
    branches: &mut [RepositoryBranch],
) -> Result<(), Response> {
    let coordinate = format!("30617:{owner}:{repo}");
    let prs = state
        .db
        .query_events(&buzz_db::EventQuery {
            kinds: Some(vec![buzz_core::kind::KIND_GIT_PULL_REQUEST as i32]),
            custom_tag: Some(("a".into(), coordinate)),
            channel_ids: Some(vec![channel_id]),
            limit: Some(PR_LIMIT + 1),
            max_limit: Some(PR_LIMIT + 1),
            ..buzz_db::EventQuery::for_community(auth.tenant.community())
        })
        .await
        .map_err(|error| {
            error!(%error, "branch PR lookup failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "branch metadata unavailable",
            )
                .into_response()
        })?;
    if prs.len() > PR_LIMIT as usize {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            "repository has too many pull requests",
        )
            .into_response());
    }
    if prs.is_empty() {
        return Ok(());
    }

    let pr_ids: Vec<String> = prs.iter().map(|event| event.event.id.to_hex()).collect();
    let statuses = state
        .db
        .query_events(&buzz_db::EventQuery {
            kinds: Some(vec![
                buzz_core::kind::KIND_GIT_STATUS_OPEN as i32,
                buzz_core::kind::KIND_GIT_STATUS_MERGED as i32,
                buzz_core::kind::KIND_GIT_STATUS_CLOSED as i32,
                buzz_core::kind::KIND_GIT_STATUS_DRAFT as i32,
            ]),
            e_tags: Some(pr_ids),
            channel_ids: Some(vec![channel_id]),
            limit: Some(STATUS_LIMIT + 1),
            max_limit: Some(STATUS_LIMIT + 1),
            ..buzz_db::EventQuery::for_community(auth.tenant.community())
        })
        .await
        .map_err(|error| {
            error!(%error, "branch PR status lookup failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "branch metadata unavailable",
            )
                .into_response()
        })?;
    if statuses.len() > STATUS_LIMIT as usize {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            "repository has too many pull request statuses",
        )
            .into_response());
    }

    let mut prs: Vec<_> = prs.into_iter().map(|event| event.event).collect();
    let statuses: Vec<_> = statuses.into_iter().map(|event| event.event).collect();
    link_open_prs(owner, repo, branches, &mut prs, &statuses);
    Ok(())
}

fn link_open_prs(
    owner: &str,
    repo: &str,
    branches: &mut [RepositoryBranch],
    prs: &mut [nostr::Event],
    statuses: &[nostr::Event],
) {
    let roots: HashMap<String, &nostr::Event> = prs.iter().map(|pr| (pr.id.to_hex(), pr)).collect();
    let mut latest_status: HashMap<String, &nostr::Event> = HashMap::new();
    for status in statuses {
        let event = status;
        let Some(root) = status_root(event) else {
            continue;
        };
        let Some(pr) = roots.get(root) else { continue };
        if event.pubkey != pr.pubkey && event.pubkey.to_hex() != owner {
            continue;
        }
        if tag_value(event, "a").is_some_and(|value| value != format!("30617:{owner}:{repo}")) {
            continue;
        }
        let replace = latest_status
            .get(root)
            .is_none_or(|prior| newer(event, prior));
        if replace {
            latest_status.insert(root.to_owned(), event);
        }
    }
    // Newest root wins when several open PRs name the same branch.
    prs.sort_by(|a, b| {
        b.created_at
            .cmp(&a.created_at)
            .then_with(|| a.id.cmp(&b.id))
    });
    for branch in branches {
        branch.open_pr_event_id = prs
            .iter()
            .find(|pr| {
                let id = pr.id.to_hex();
                let kind = latest_status
                    .get(&id)
                    .map(|event| event.kind.as_u16())
                    .unwrap_or(1630);
                kind == 1630 && tag_value(pr, "branch-name") == Some(branch.name.as_str())
            })
            .map(|pr| pr.id.to_hex());
    }
}

fn tag_value<'a>(event: &'a nostr::Event, name: &str) -> Option<&'a str> {
    event.tags.iter().find_map(|tag| {
        let parts = tag.as_slice();
        (parts.first().map(String::as_str) == Some(name))
            .then(|| parts.get(1).map(String::as_str))
            .flatten()
    })
}

fn status_root(event: &nostr::Event) -> Option<&str> {
    let roots: Vec<_> = event
        .tags
        .iter()
        .filter_map(|tag| {
            let parts = tag.as_slice();
            (parts.first().map(String::as_str) == Some("e")
                && parts.get(3).map(String::as_str) == Some("root"))
            .then(|| parts.get(1).map(String::as_str))
            .flatten()
        })
        .collect();
    if roots.len() == 1 {
        roots.first().copied()
    } else if roots.is_empty() {
        let refs: Vec<_> = event
            .tags
            .iter()
            .filter(|tag| tag.as_slice().first().map(String::as_str) == Some("e"))
            .collect();
        if refs.len() == 1 && refs[0].as_slice().get(3).is_none_or(String::is_empty) {
            refs[0].as_slice().get(1).map(String::as_str)
        } else {
            None
        }
    } else {
        None
    }
}

fn newer(event: &nostr::Event, prior: &nostr::Event) -> bool {
    event.created_at > prior.created_at
        || (event.created_at == prior.created_at && event.id < prior.id)
}

async fn run_git(repo_path: &Path, args: &[&str], deadline: Instant) -> Result<Vec<u8>, Response> {
    use std::process::Stdio;
    use tokio::io::AsyncReadExt;
    let mut command = Command::new("git");
    command.arg("--git-dir").arg(repo_path).args(args);
    harden_git_env(&mut command);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut child = command.spawn().map_err(|_| git_error("spawn git"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| git_error("missing git output"))?;
    let mut output = Vec::new();
    tokio::time::timeout(remaining(deadline), async {
        stdout
            .take(MAX_GIT_OUTPUT_BYTES as u64 + 1)
            .read_to_end(&mut output)
            .await
            .map_err(|_| git_error("read git output"))?;
        if output.len() > MAX_GIT_OUTPUT_BYTES {
            return Err((
                StatusCode::PAYLOAD_TOO_LARGE,
                "git branch output exceeds relay limits",
            )
                .into_response());
        }
        let status = child.wait().await.map_err(|_| git_error("wait git"))?;
        if !status.success() {
            return Err(git_error("git branch inspection failed"));
        }
        Ok(())
    })
    .await
    .map_err(|_| timeout_response())??;
    Ok(output)
}

fn remaining(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

fn timeout_response() -> Response {
    (
        StatusCode::GATEWAY_TIMEOUT,
        "git branch inspection timed out",
    )
        .into_response()
}

fn git_error(message: &str) -> Response {
    error!(%message, "git branch inspection failed");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "git branch inspection failed",
    )
        .into_response()
}

fn json_response(body: RepositoryBranchesResponse) -> Response {
    let mut response = Json(body).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-cache"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command as StdCommand;

    fn git(dir: &Path, args: &[&str]) {
        let output = StdCommand::new("git")
            .current_dir(dir)
            .args(args)
            .env("GIT_AUTHOR_NAME", "Branch Test")
            .env("GIT_AUTHOR_EMAIL", "branch@example.com")
            .env("GIT_COMMITTER_NAME", "Branch Test")
            .env("GIT_COMMITTER_EMAIL", "branch@example.com")
            .output()
            .expect("run git");
        assert!(
            output.status.success(),
            "git {:?}: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn commit(dir: &Path, message: &str, contents: &str) {
        std::fs::write(dir.join("file.txt"), contents).expect("write fixture");
        git(dir, &["add", "file.txt"]);
        git(dir, &["commit", "-m", message]);
    }

    #[tokio::test]
    async fn classifies_merged_and_unmerged_with_exact_counts() {
        let temp = tempfile::tempdir().expect("tempdir");
        git(temp.path(), &["init", "-b", "main"]);
        commit(temp.path(), "base", "base");
        git(temp.path(), &["branch", "merged"]);
        git(temp.path(), &["checkout", "-b", "feature"]);
        commit(temp.path(), "feature", "feature");
        git(temp.path(), &["checkout", "main"]);
        commit(temp.path(), "main", "main");

        let mut rows = collect_branch_rows(
            &temp.path().join(".git"),
            "refs/heads/main",
            Instant::now() + Duration::from_secs(5),
        )
        .await
        .expect("collect branches");
        rows.sort_by(|a, b| a.name.cmp(&b.name));

        let feature = rows.iter().find(|row| row.name == "feature").unwrap();
        assert_eq!(
            (feature.behind, feature.ahead, feature.fully_merged),
            (1, 1, false)
        );
        let main = rows.iter().find(|row| row.name == "main").unwrap();
        assert_eq!((main.behind, main.ahead, main.fully_merged), (0, 0, true));
        let merged = rows.iter().find(|row| row.name == "merged").unwrap();
        assert_eq!(
            (merged.behind, merged.ahead, merged.fully_merged),
            (1, 0, true)
        );
    }

    #[tokio::test]
    async fn empty_and_default_only_repositories_are_supported() {
        let empty = tempfile::tempdir().expect("tempdir");
        git(empty.path(), &["init", "-b", "main"]);
        let rows = collect_branch_rows(
            &empty.path().join(".git"),
            "refs/heads/main",
            Instant::now() + Duration::from_secs(5),
        )
        .await
        .expect("empty repo");
        assert!(rows.is_empty());

        commit(empty.path(), "main", "main");
        let rows = collect_branch_rows(
            &empty.path().join(".git"),
            "refs/heads/main",
            Instant::now() + Duration::from_secs(5),
        )
        .await
        .expect("default-only repo");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "main");
        assert!(rows[0].fully_merged);
    }
    #[tokio::test]
    async fn pages_keep_unmerged_first_and_bind_ref_snapshot() {
        let temp = tempfile::tempdir().unwrap();
        git(temp.path(), &["init", "-b", "main"]);
        commit(temp.path(), "base", "base");
        git(temp.path(), &["checkout", "-b", "feature"]);
        commit(temp.path(), "feature", "feature");
        git(temp.path(), &["checkout", "main"]);
        let deadline = Instant::now() + Duration::from_secs(5);
        let (first, total, snapshot) =
            collect_branch_page(&temp.path().join(".git"), "refs/heads/main", deadline, 0, 1)
                .await
                .unwrap();
        let (second, _, snapshot2) =
            collect_branch_page(&temp.path().join(".git"), "refs/heads/main", deadline, 1, 1)
                .await
                .unwrap();
        assert_eq!(total, 2);
        assert_eq!(first[0].name, "feature");
        assert_eq!(first[0].ahead, 1);
        assert_eq!(second[0].name, "main");
        assert_eq!(snapshot, snapshot2);
        git(temp.path(), &["branch", "another"]);
        let (_, total, changed) =
            collect_branch_page(&temp.path().join(".git"), "refs/heads/main", deadline, 2, 1)
                .await
                .unwrap();
        assert_eq!(total, 3);
        assert_ne!(snapshot, changed);
    }

    #[test]
    fn open_pr_links_follow_root_status_and_ignore_unrelated_same_tip() {
        use nostr::{EventBuilder, Keys, Kind, Tag, Timestamp};
        let author = Keys::generate();
        let stranger = Keys::generate();
        let make = |keys: &Keys, kind, time, tags: Vec<Tag>| {
            EventBuilder::new(Kind::Custom(kind), "")
                .tags(tags)
                .custom_created_at(Timestamp::from_secs(time))
                .sign_with_keys(keys)
                .unwrap()
        };
        let pr = make(
            &author,
            1618,
            1,
            vec![
                Tag::parse(["branch-name", "feature"]).unwrap(),
                Tag::parse(["c", "tip"]).unwrap(),
            ],
        );
        let old = make(
            &author,
            1630,
            2,
            vec![Tag::parse(["e", &pr.id.to_hex(), "", "root"]).unwrap()],
        );
        let closed = make(
            &author,
            1632,
            3,
            vec![
                Tag::parse(["e", &"a".repeat(64), "", "reply"]).unwrap(),
                Tag::parse(["e", &pr.id.to_hex(), "", "root"]).unwrap(),
            ],
        );
        let forged = make(
            &stranger,
            1630,
            4,
            vec![Tag::parse(["e", &pr.id.to_hex(), "", "root"]).unwrap()],
        );
        let row = |name: &str| RepositoryBranch {
            name: name.into(),
            tip: "tip".into(),
            ahead: 1,
            behind: 0,
            fully_merged: false,
            last_commit_at: 1,
            open_pr_event_id: None,
        };
        let mut rows = vec![row("feature"), row("unrelated")];
        link_open_prs(
            "owner",
            "repo",
            &mut rows,
            &mut [pr.clone()],
            &[closed.clone(), old.clone(), forged],
        );
        assert!(rows.iter().all(|row| row.open_pr_event_id.is_none()));
        link_open_prs("owner", "repo", &mut rows, &mut [pr.clone()], &[old]);
        assert_eq!(rows[0].open_pr_event_id, Some(pr.id.to_hex()));
        assert!(rows[1].open_pr_event_id.is_none());
        let draft = make(
            &author,
            1633,
            5,
            vec![Tag::parse(["e", &pr.id.to_hex(), "", "root"]).unwrap()],
        );
        link_open_prs("owner", "repo", &mut rows, &mut [pr], &[closed, draft]);
        assert!(rows[0].open_pr_event_id.is_none());
    }
    #[tokio::test]
    async fn nonempty_repository_without_default_branch_is_a_conflict() {
        let temp = tempfile::tempdir().unwrap();
        git(temp.path(), &["init", "-b", "feature"]);
        commit(temp.path(), "base", "base");
        let response = collect_branch_page(
            &temp.path().join(".git"),
            "refs/heads/main",
            Instant::now() + Duration::from_secs(5),
            0,
            200,
        )
        .await
        .unwrap_err();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }
}
