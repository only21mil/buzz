//! Bounded branch visibility for hosted repositories.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    extract::{Path as AxumPath, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use tokio::process::Command;
use tracing::{error, warn};

use super::hydrate::{hydrate_for_read, load_manifest_for_read, HydrationOptions};
use super::transport::{
    authorize_git_read, harden_git_env, hydrate_error_to_response, validate_repo_id, GitAuth,
    GitRepoParams,
};
use crate::state::AppState;

const BRANCH_LIMIT: usize = 200;
const PR_LIMIT: i64 = 500;
const STATUS_LIMIT: i64 = 1_000;
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

#[derive(Debug, Serialize)]
struct RepositoryBranchesResponse {
    default_branch: String,
    branches: Vec<RepositoryBranch>,
    branch_limit: usize,
}

/// Return the bounded branch listing for one fetch-authorized repository.
pub async fn repository_branches(
    State(state): State<Arc<AppState>>,
    auth: GitAuth,
    AxumPath(params): AxumPath<GitRepoParams>,
) -> Response {
    let started_at = Instant::now();
    let response = repository_branches_inner(&state, &auth, &params, started_at).await;
    metrics::counter!(
        "buzz_git_branch_requests_total",
        "status" => response.status().as_u16().to_string()
    )
    .increment(1);
    metrics::histogram!("buzz_git_branch_seconds")
        .record(started_at.elapsed().as_secs_f64());
    response
}

async fn repository_branches_inner(
    state: &Arc<AppState>,
    auth: &GitAuth,
    params: &GitRepoParams,
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

    let deadline = started_at + BRANCH_TIMEOUT;
    let manifest = match tokio::time::timeout(
        remaining(deadline),
        load_manifest_for_read(&state.git_store, &auth.tenant, &params.owner, repo_name),
    )
    .await
    {
        Err(_) => return timeout_response(),
        Ok(Ok(Some(manifest))) => manifest,
        Ok(Ok(None)) => return (StatusCode::NOT_FOUND, "repository not found").into_response(),
        Ok(Err(error)) => return hydrate_error_to_response(&params.owner, repo_name, error),
    };

    let branch_count = manifest
        .refs
        .keys()
        .filter(|name| name.starts_with("refs/heads/"))
        .count();
    if branch_count > BRANCH_LIMIT {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("repository has more than {BRANCH_LIMIT} branches"),
        )
            .into_response();
    }
    let Some(default_branch) = manifest.head.strip_prefix("refs/heads/") else {
        return (
            StatusCode::CONFLICT,
            "repository default ref is not a branch",
        )
            .into_response();
    };

    if branch_count == 0 {
        return json_response(RepositoryBranchesResponse {
            default_branch: default_branch.to_string(),
            branches: Vec::new(),
            branch_limit: BRANCH_LIMIT,
        });
    }

    let _permit = match Arc::clone(&state.git_semaphore).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .header(header::RETRY_AFTER, "5")
                .body(axum::body::Body::from("git service busy"))
                .expect("static busy response")
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

    let mut branches = match collect_branch_rows(repo.path(), &manifest.head, deadline).await {
        Ok(branches) => branches,
        Err(response) => return response,
    };
    drop(repo);

    if let Err(response) = attach_open_prs(
        state,
        auth,
        channel_id,
        &params.owner,
        repo_name,
        &mut branches,
    )
    .await
    {
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
    })
}

async fn collect_branch_rows(
    repo_path: &Path,
    default_ref: &str,
    deadline: Instant,
) -> Result<Vec<RepositoryBranch>, Response> {
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
        let (behind, ahead) = if full_name == default_ref {
            (0, 0)
        } else {
            let range = format!("{default_ref}...{full_name}");
            let counts = run_git(
                repo_path,
                &["rev-list", "--left-right", "--count", &range],
                deadline,
            )
            .await?;
            parse_counts(&counts)?
        };
        rows.push(RepositoryBranch {
            name: full_name["refs/heads/".len()..].to_string(),
            tip: tip.to_string(),
            ahead,
            behind,
            fully_merged: ahead == 0,
            last_commit_at,
            open_pr_event_id: None,
        });
    }
    Ok(rows)
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
    let mut prs = state
        .db
        .query_events(&buzz_db::EventQuery {
            kinds: Some(vec![buzz_core::kind::KIND_GIT_PULL_REQUEST as i32]),
            a_tags: Some(vec![coordinate]),
            channel_ids: Some(vec![channel_id]),
            limit: Some(PR_LIMIT + 1),
            max_limit: Some(PR_LIMIT + 1),
            ..buzz_db::EventQuery::for_community(auth.tenant.community())
        })
        .await
        .map_err(|error| {
            error!(%error, "branch PR lookup failed");
            (StatusCode::SERVICE_UNAVAILABLE, "branch metadata unavailable").into_response()
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
            (StatusCode::SERVICE_UNAVAILABLE, "branch metadata unavailable").into_response()
        })?;
    if statuses.len() > STATUS_LIMIT as usize {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            "repository has too many pull request statuses",
        )
            .into_response());
    }

    let mut latest_status = HashMap::new();
    for status in statuses {
        if let Some(root) = tag_value(&status.event, "e") {
            latest_status.entry(root.to_string()).or_insert(status.event.kind.as_u16() as u32);
        }
    }
    let branch_names: HashSet<&str> = branches.iter().map(|branch| branch.name.as_str()).collect();
    let branch_tips: HashSet<&str> = branches.iter().map(|branch| branch.tip.as_str()).collect();
    let mut links = HashMap::new();
    for pr in prs.drain(..) {
        let id = pr.event.id.to_hex();
        if matches!(
            latest_status.get(&id),
            Some(&buzz_core::kind::KIND_GIT_STATUS_MERGED)
                | Some(&buzz_core::kind::KIND_GIT_STATUS_CLOSED)
        ) {
            continue;
        }
        let name = tag_value(&pr.event, "branch-name");
        let tip = tag_value(&pr.event, "c");
        if let Some(name) = name.filter(|name| branch_names.contains(*name)) {
            links.entry(name.to_string()).or_insert(id.clone());
        }
        if let Some(tip) = tip.filter(|tip| branch_tips.contains(*tip)) {
            for branch in branches.iter().filter(|branch| branch.tip == tip) {
                links.entry(branch.name.clone()).or_insert(id.clone());
            }
        }
    }
    for branch in branches {
        branch.open_pr_event_id = links.remove(&branch.name);
    }
    Ok(())
}

fn tag_value<'a>(event: &'a nostr::Event, name: &str) -> Option<&'a str> {
    event.tags.iter().find_map(|tag| {
        let parts = tag.as_slice();
        (parts.first().map(String::as_str) == Some(name))
            .then(|| parts.get(1).map(String::as_str))
            .flatten()
    })
}

async fn run_git(repo_path: &Path, args: &[&str], deadline: Instant) -> Result<Vec<u8>, Response> {
    if remaining(deadline).is_zero() {
        return Err(timeout_response());
    }
    let mut command = Command::new("git");
    command.arg("--git-dir").arg(repo_path).args(args);
    harden_git_env(&mut command);
    let output = tokio::time::timeout(remaining(deadline), command.output())
        .await
        .map_err(|_| timeout_response())?
        .map_err(|error| git_error(&format!("spawn git: {error}")))?;
    if !output.status.success() {
        warn!(stderr = %String::from_utf8_lossy(&output.stderr), "branch git command failed");
        return Err(git_error("git branch inspection failed"));
    }
    if output.stdout.len() > MAX_GIT_OUTPUT_BYTES {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            "git branch output exceeds relay limits",
        )
            .into_response());
    }
    Ok(output.stdout)
}

fn remaining(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

fn timeout_response() -> Response {
    (StatusCode::GATEWAY_TIMEOUT, "git branch inspection timed out").into_response()
}

fn git_error(message: &str) -> Response {
    error!(%message, "git branch inspection failed");
    (StatusCode::INTERNAL_SERVER_ERROR, "git branch inspection failed").into_response()
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
        assert_eq!(
            (main.behind, main.ahead, main.fully_merged),
            (0, 0, true)
        );
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
}
