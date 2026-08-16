//! Bounded JSON repository snapshots for browser clients.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    body::{to_bytes, Body},
    extract::{Path as AxumPath, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tracing::{error, warn};

use super::hydrate::{hydrate_for_read, HydrationOptions};
use super::transport::{
    authorize_git_read, harden_git_env, hydrate_error_to_response, validate_repo_id, GitAuth,
    GitRepoParams,
};
use crate::state::AppState;

const SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(10);
const SNAPSHOT_MAX_JSON_BYTES: usize = 2 * 1024 * 1024;
const SNAPSHOT_FILE_LIMIT: usize = 250;
const SNAPSHOT_MAX_COMMITS: usize = 50;
const SNAPSHOT_DEFAULT_COMMITS: usize = 20;
const MAX_PREVIEW_BYTES: u64 = 64 * 1024;
const MAX_TREE_OUTPUT_BYTES: u64 = 8 * 1024 * 1024;
const MAX_HISTORY_OUTPUT_BYTES: u64 = 8 * 1024 * 1024;
const MAX_RECENT_COMMITS_OUTPUT_BYTES: u64 = 1024 * 1024;
const MAX_PREVIEW_BATCH_OUTPUT_BYTES: u64 =
    (SNAPSHOT_FILE_LIMIT as u64 + 1) * (MAX_PREVIEW_BYTES + 256);
const SNAPSHOT_ERROR_BODY_LIMIT: usize = 16 * 1024;
const REPOSITORY_NOT_FOUND: &str = "repository not found";
const UNBOUND_REPOSITORY_PREFIX: &str = "run: buzz repos bind --id ";

#[derive(Deserialize)]
/// Optional revision and recent-commit count for a repository snapshot.
pub struct SnapshotQuery {
    #[serde(rename = "ref")]
    reference: Option<String>,
    commits: Option<usize>,
}

#[derive(Clone, Debug, Serialize)]
struct ProjectRepoCommit {
    hash: String,
    short_hash: String,
    author_name: String,
    author_email: String,
    timestamp: i64,
    subject: String,
}

#[derive(Clone, Debug, Serialize)]
struct ProjectRepoFile {
    path: String,
    kind: String,
    size: Option<u64>,
    preview_content: Option<String>,
    last_changed_at: Option<i64>,
    latest_commit: Option<ProjectRepoCommit>,
}

#[derive(Clone, Debug, Serialize)]
struct ProjectRepoContributor {
    name: String,
    email: String,
    commit_count: usize,
    last_commit_at: i64,
}

#[derive(Debug, Serialize)]
struct ProjectRepoSnapshot {
    latest_commit: Option<ProjectRepoCommit>,
    commit_count: Option<usize>,
    commits: Vec<ProjectRepoCommit>,
    files: Vec<ProjectRepoFile>,
    contributors: Vec<ProjectRepoContributor>,
    truncated: bool,
}

#[derive(Debug, Serialize)]
struct SnapshotErrorMarker<'a> {
    error: &'static str,
    message: &'a str,
}

#[derive(Clone, Debug)]
struct TreeEntry {
    file: ProjectRepoFile,
    object_id: String,
}

struct GitOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: String,
}

enum GitRunError {
    Timeout,
    OutputTooLarge,
    Internal(String),
}

/// `GET /git/{owner}/{repo}/snapshot?ref=...&commits=N`.
pub async fn repository_snapshot(
    State(state): State<Arc<AppState>>,
    auth: GitAuth,
    AxumPath(params): AxumPath<GitRepoParams>,
    Query(query): Query<SnapshotQuery>,
) -> Response {
    let started_at = Instant::now();
    let response = repository_snapshot_inner(&state, &auth, &params, query, started_at).await;
    let outcome = status_outcome(response.status());
    metrics::counter!("buzz_git_snapshot_requests_total", "outcome" => outcome).increment(1);
    metrics::histogram!("buzz_git_snapshot_seconds", "outcome" => outcome)
        .record(started_at.elapsed().as_secs_f64());
    response
}

async fn repository_snapshot_inner(
    state: &Arc<AppState>,
    auth: &GitAuth,
    params: &GitRepoParams,
    query: SnapshotQuery,
    started_at: Instant,
) -> Response {
    let repo_name = match validate_repo_id(&params.owner, &params.repo) {
        Ok(repo_name) => repo_name,
        Err(response) => return response,
    };
    let commits = query.commits.unwrap_or(SNAPSHOT_DEFAULT_COMMITS);
    if !(1..=SNAPSHOT_MAX_COMMITS).contains(&commits) {
        return (StatusCode::BAD_REQUEST, "commits must be between 1 and 50").into_response();
    }
    if let Some(reference) = query.reference.as_deref() {
        if let Err(message) = validate_snapshot_ref(reference) {
            return (StatusCode::BAD_REQUEST, message).into_response();
        }
    }

    if let Err(response) = authorize_git_read(
        &state.db,
        auth.tenant.community(),
        &auth.pubkey,
        &params.owner,
        repo_name,
    )
    .await
    {
        return map_snapshot_response(response).await;
    }

    let _permit = match Arc::clone(&state.git_semaphore).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            metrics::counter!(
                "buzz_git_semaphore_rejections_total",
                "operation" => "snapshot"
            )
            .increment(1);
            return Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .header(header::RETRY_AFTER, "5")
                .body(Body::from("git service busy"))
                .expect("static snapshot busy response");
        }
    };

    let deadline = started_at + SNAPSHOT_TIMEOUT;
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
        Ok(Ok(None)) => {
            return map_snapshot_response(
                (StatusCode::NOT_FOUND, REPOSITORY_NOT_FOUND).into_response(),
            )
            .await;
        }
        Ok(Err(error)) => {
            return map_snapshot_response(hydrate_error_to_response(
                &params.owner,
                repo_name,
                error,
            ))
            .await;
        }
    };

    let requested_ref = query.reference.as_deref().unwrap_or("HEAD");
    let snapshot = match snapshot_from_repo(
        repo.path(),
        requested_ref,
        query.reference.is_some(),
        commits,
        deadline,
    )
    .await
    {
        Ok(snapshot) => snapshot,
        Err(response) => return response,
    };
    drop(repo);

    let (body, truncated) = match serialize_bounded(snapshot) {
        Ok(result) => result,
        Err(response) => return *response,
    };
    metrics::histogram!("buzz_git_snapshot_response_bytes", "truncated" => if truncated { "true" } else { "false" })
        .record(body.len() as f64);
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-cache")
        .body(Body::from(body))
        .expect("static snapshot response")
}

async fn map_snapshot_response(response: Response) -> Response {
    if response.status() != StatusCode::NOT_FOUND {
        return response;
    }

    let body = to_bytes(response.into_body(), SNAPSHOT_ERROR_BODY_LIMIT)
        .await
        .ok();
    let message = body
        .as_deref()
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .filter(|message| message.starts_with(UNBOUND_REPOSITORY_PREFIX))
        .unwrap_or(REPOSITORY_NOT_FOUND);
    let error = if message.starts_with(UNBOUND_REPOSITORY_PREFIX) {
        "repository_unbound"
    } else {
        "repository_unavailable"
    };
    let body = serde_json::to_vec(&SnapshotErrorMarker { error, message })
        .expect("static snapshot error marker serializes");

    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .expect("static snapshot not-found response")
}

fn status_outcome(status: StatusCode) -> &'static str {
    match status {
        StatusCode::OK => "success",
        StatusCode::BAD_REQUEST => "bad_request",
        StatusCode::NOT_FOUND => "not_found",
        StatusCode::TOO_MANY_REQUESTS => "busy",
        StatusCode::PAYLOAD_TOO_LARGE => "too_large",
        StatusCode::GATEWAY_TIMEOUT => "timeout",
        _ => "error",
    }
}

fn remaining(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

fn timeout_response() -> Response {
    (StatusCode::GATEWAY_TIMEOUT, "git operation timed out").into_response()
}

fn validate_snapshot_ref(reference: &str) -> Result<(), &'static str> {
    if reference.is_empty() {
        return Err("ref must not be empty");
    }
    if reference.starts_with('-')
        || reference.starts_with('/')
        || reference.ends_with('/')
        || reference.ends_with('.')
        || reference.contains("..")
        || reference.contains("@{")
        || reference.contains("//")
        || reference == "@"
    {
        return Err("invalid ref");
    }
    if reference.bytes().any(|byte| {
        byte.is_ascii_control()
            || byte == b' '
            || matches!(byte, b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')
    }) {
        return Err("invalid ref");
    }
    if reference.split('/').any(|component| {
        component.is_empty() || component.starts_with('.') || component.ends_with(".lock")
    }) {
        return Err("invalid ref");
    }
    Ok(())
}

async fn snapshot_from_repo(
    repo_path: &Path,
    requested_ref: &str,
    explicit_ref: bool,
    commit_limit: usize,
    deadline: Instant,
) -> Result<ProjectRepoSnapshot, Response> {
    let commit_spec = format!("{requested_ref}^{{commit}}");
    let resolved_output = run_git_bounded(
        repo_path,
        &[
            "rev-parse",
            "--verify",
            "--quiet",
            "--end-of-options",
            &commit_spec,
        ],
        None,
        256,
        deadline,
    )
    .await
    .map_err(git_run_error_response)?;
    if !resolved_output.status.success() {
        if explicit_ref {
            return Err(
                (StatusCode::BAD_REQUEST, "ref does not resolve to a commit").into_response(),
            );
        }
        return Ok(ProjectRepoSnapshot {
            latest_commit: None,
            commit_count: Some(0),
            commits: Vec::new(),
            files: Vec::new(),
            contributors: Vec::new(),
            truncated: false,
        });
    }
    let resolved = std::str::from_utf8(&resolved_output.stdout)
        .ok()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| git_error_response("git returned an invalid resolved ref"))?
        .to_string();

    let max_count = format!("--max-count={commit_limit}");
    let recent_output = run_git_bounded(
        repo_path,
        &[
            "log",
            "--first-parent",
            &max_count,
            "--encoding=UTF-8",
            "--format=%H%x00%h%x00%an%x00%ae%x00%at%x00%s",
            &resolved,
            "--",
        ],
        None,
        MAX_RECENT_COMMITS_OUTPUT_BYTES,
        deadline,
    )
    .await
    .map_err(git_run_error_response)?;
    ensure_git_success(&recent_output, "recent commit log").map_err(|response| *response)?;
    let commits = parse_commits(&recent_output.stdout).map_err(|response| *response)?;
    let latest_commit = commits.first().cloned();

    let count_output = run_git_bounded(
        repo_path,
        &["rev-list", "--count", &resolved, "--"],
        None,
        64,
        deadline,
    )
    .await
    .map_err(git_run_error_response)?;
    let commit_count = if count_output.status.success() {
        std::str::from_utf8(&count_output.stdout)
            .ok()
            .and_then(|value| value.trim().parse::<usize>().ok())
    } else {
        None
    };

    let contributor_output = run_git_bounded(
        repo_path,
        &[
            "log",
            "--encoding=UTF-8",
            "--format=%an%x00%ae%x00%at",
            &resolved,
            "--",
        ],
        None,
        MAX_HISTORY_OUTPUT_BYTES,
        deadline,
    )
    .await
    .map_err(git_run_error_response)?;
    ensure_git_success(&contributor_output, "contributor log").map_err(|response| *response)?;
    let contributors =
        parse_contributors(&contributor_output.stdout).map_err(|response| *response)?;

    let tree_output = run_git_bounded(
        repo_path,
        &["ls-tree", "-r", "-l", "-z", &resolved, "--"],
        None,
        MAX_TREE_OUTPUT_BYTES,
        deadline,
    )
    .await
    .map_err(git_run_error_response)?;
    ensure_git_success(&tree_output, "repository tree").map_err(|response| *response)?;
    let (mut tree, tree_truncated) =
        parse_tree(&tree_output.stdout).map_err(|response| *response)?;
    populate_previews(repo_path, &mut tree, deadline).await?;

    Ok(ProjectRepoSnapshot {
        latest_commit,
        commit_count,
        commits,
        files: tree.into_iter().map(|entry| entry.file).collect(),
        contributors,
        truncated: tree_truncated,
    })
}

fn parse_commits(output: &[u8]) -> Result<Vec<ProjectRepoCommit>, Box<Response>> {
    let output = std::str::from_utf8(output)
        .map_err(|_| boxed_git_error_response("git commit metadata was not UTF-8"))?;
    Ok(output
        .lines()
        .filter(|line| !line.is_empty())
        .filter_map(parse_commit_line)
        .take(SNAPSHOT_MAX_COMMITS)
        .collect())
}

fn parse_commit_line(line: &str) -> Option<ProjectRepoCommit> {
    let mut parts = line.split('\0');
    Some(ProjectRepoCommit {
        hash: parts.next()?.to_string(),
        short_hash: parts.next()?.to_string(),
        author_name: parts.next()?.to_string(),
        author_email: parts.next()?.to_string(),
        timestamp: parts.next()?.parse().ok()?,
        subject: parts.next().unwrap_or_default().to_string(),
    })
}

fn parse_contributors(output: &[u8]) -> Result<Vec<ProjectRepoContributor>, Box<Response>> {
    let output = std::str::from_utf8(output)
        .map_err(|_| boxed_git_error_response("git contributor metadata was not UTF-8"))?;
    let mut contributors: HashMap<String, ProjectRepoContributor> = HashMap::new();
    for line in output.lines().filter(|line| !line.trim().is_empty()) {
        let mut parts = line.split('\0');
        let name = parts.next().unwrap_or_default().trim().to_string();
        let email = parts.next().unwrap_or_default().trim().to_string();
        let timestamp = parts
            .next()
            .and_then(|value| value.trim().parse::<i64>().ok())
            .unwrap_or_default();
        if name.is_empty() && email.is_empty() {
            continue;
        }
        let key = if email.is_empty() {
            name.to_lowercase()
        } else {
            email.to_lowercase()
        };
        contributors
            .entry(key)
            .and_modify(|contributor| {
                contributor.commit_count += 1;
                contributor.last_commit_at = contributor.last_commit_at.max(timestamp);
            })
            .or_insert(ProjectRepoContributor {
                name,
                email,
                commit_count: 1,
                last_commit_at: timestamp,
            });
    }
    let mut contributors = contributors.into_values().collect::<Vec<_>>();
    contributors.sort_by(|left, right| {
        right
            .commit_count
            .cmp(&left.commit_count)
            .then_with(|| right.last_commit_at.cmp(&left.last_commit_at))
            .then_with(|| left.name.cmp(&right.name))
    });
    contributors.truncate(50);
    Ok(contributors)
}

fn parse_tree(output: &[u8]) -> Result<(Vec<TreeEntry>, bool), Box<Response>> {
    let mut selected = Vec::new();
    let mut readme_beyond_limit = None;
    let mut total = 0usize;
    for record in output
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        total += 1;
        let record = std::str::from_utf8(record)
            .map_err(|_| boxed_git_error_response("git tree contained a non-UTF-8 path"))?;
        let (metadata, path) = record
            .split_once('\t')
            .ok_or_else(|| boxed_git_error_response("git returned malformed tree metadata"))?;
        let mut fields = metadata.split_whitespace();
        let mode = fields
            .next()
            .ok_or_else(|| boxed_git_error_response("git tree mode was missing"))?;
        let object_kind = fields
            .next()
            .ok_or_else(|| boxed_git_error_response("git tree kind was missing"))?;
        let object_id = fields
            .next()
            .ok_or_else(|| boxed_git_error_response("git tree object id was missing"))?
            .to_string();
        let size = fields.next().and_then(|value| value.parse::<u64>().ok());
        let kind = match mode {
            "120000" => "symlink",
            "160000" => "commit",
            "040000" => "tree",
            _ => object_kind,
        };
        let entry = TreeEntry {
            file: ProjectRepoFile {
                path: path.to_string(),
                kind: kind.to_string(),
                size,
                preview_content: None,
                last_changed_at: None,
                latest_commit: None,
            },
            object_id,
        };
        if selected.len() < SNAPSHOT_FILE_LIMIT {
            selected.push(entry);
        } else if readme_beyond_limit.is_none() && is_root_readme(path) {
            readme_beyond_limit = Some(entry);
        }
    }
    if let Some(readme) = readme_beyond_limit {
        selected.push(readme);
    }
    Ok((selected, total > SNAPSHOT_FILE_LIMIT))
}

fn is_root_readme(path: &str) -> bool {
    if path.contains('/') {
        return false;
    }
    let lowercase = path.to_ascii_lowercase();
    lowercase == "readme" || lowercase.starts_with("readme.")
}

async fn populate_previews(
    repo_path: &Path,
    entries: &mut [TreeEntry],
    deadline: Instant,
) -> Result<(), Response> {
    let mut seen = HashSet::new();
    let object_ids = entries
        .iter()
        .filter(|entry| {
            entry.file.kind == "blob"
                && entry.file.size.is_none_or(|size| size <= MAX_PREVIEW_BYTES)
        })
        .filter_map(|entry| {
            seen.insert(entry.object_id.clone())
                .then_some(entry.object_id.as_str())
        })
        .collect::<Vec<_>>();
    if object_ids.is_empty() {
        return Ok(());
    }
    let mut input = object_ids.join("\n").into_bytes();
    input.push(b'\n');
    let output = run_git_bounded(
        repo_path,
        &["cat-file", "--batch"],
        Some(&input),
        MAX_PREVIEW_BATCH_OUTPUT_BYTES,
        deadline,
    )
    .await
    .map_err(git_run_error_response)?;
    ensure_git_success(&output, "preview batch").map_err(|response| *response)?;
    let previews =
        parse_batch_previews(&output.stdout, object_ids.len()).map_err(|response| *response)?;
    for entry in entries {
        if let Some(preview) = previews.get(&entry.object_id) {
            entry.file.preview_content.clone_from(preview);
        }
    }
    Ok(())
}

fn parse_batch_previews(
    output: &[u8],
    expected: usize,
) -> Result<HashMap<String, Option<String>>, Box<Response>> {
    let mut previews = HashMap::new();
    let mut cursor = 0usize;
    for _ in 0..expected {
        let line_end = output[cursor..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|offset| cursor + offset)
            .ok_or_else(|| boxed_git_error_response("git returned malformed preview metadata"))?;
        let header = std::str::from_utf8(&output[cursor..line_end])
            .map_err(|_| boxed_git_error_response("git returned non-UTF-8 preview metadata"))?;
        let mut fields = header.split_whitespace();
        let object_id = fields
            .next()
            .ok_or_else(|| boxed_git_error_response("git preview object id was missing"))?;
        let object_kind = fields
            .next()
            .ok_or_else(|| boxed_git_error_response("git preview kind was missing"))?;
        let size = fields
            .next()
            .and_then(|value| value.parse::<usize>().ok())
            .ok_or_else(|| boxed_git_error_response("git preview size was invalid"))?;
        let content_start = line_end + 1;
        let content_end = content_start
            .checked_add(size)
            .filter(|end| *end < output.len())
            .ok_or_else(|| boxed_git_error_response("git preview content was truncated"))?;
        if object_kind != "blob" || output.get(content_end) != Some(&b'\n') {
            return Err(boxed_git_error_response(
                "git returned malformed preview content",
            ));
        }
        let content = &output[content_start..content_end];
        let preview = if content.contains(&0) {
            None
        } else {
            std::str::from_utf8(content).ok().map(str::to_string)
        };
        previews.insert(object_id.to_string(), preview);
        cursor = content_end + 1;
    }
    Ok(previews)
}

fn serialize_bounded(mut snapshot: ProjectRepoSnapshot) -> Result<(Vec<u8>, bool), Box<Response>> {
    let body = serde_json::to_vec(&snapshot)
        .map_err(|error| boxed_git_error_response(&format!("serialize snapshot: {error}")))?;
    if body.len() <= SNAPSHOT_MAX_JSON_BYTES {
        return Ok((body, snapshot.truncated));
    }

    snapshot.truncated = true;
    let all_files = std::mem::take(&mut snapshot.files);
    let readme = all_files
        .iter()
        .find(|file| is_root_readme(&file.path))
        .cloned();
    let mut low = 0usize;
    let mut high = all_files.len();
    let mut best = Vec::new();
    while low <= high {
        let middle = low + (high - low) / 2;
        let mut candidate = all_files[..middle].to_vec();
        if let Some(readme) = &readme {
            if !candidate.iter().any(|file| file.path == readme.path) {
                candidate.push(readme.clone());
            }
        }
        snapshot.files = candidate;
        let candidate_body = serde_json::to_vec(&snapshot)
            .map_err(|error| boxed_git_error_response(&format!("serialize snapshot: {error}")))?;
        if candidate_body.len() <= SNAPSHOT_MAX_JSON_BYTES {
            best = candidate_body;
            low = middle + 1;
        } else if middle == 0 {
            break;
        } else {
            high = middle - 1;
        }
    }
    if best.is_empty() {
        return Err(Box::new(
            (
                StatusCode::PAYLOAD_TOO_LARGE,
                "repository snapshot exceeds relay limits",
            )
                .into_response(),
        ));
    }
    Ok((best, true))
}

async fn run_git_bounded(
    repo_path: &Path,
    args: &[&str],
    input: Option<&[u8]>,
    max_stdout_bytes: u64,
    deadline: Instant,
) -> Result<GitOutput, GitRunError> {
    if remaining(deadline).is_zero() {
        return Err(GitRunError::Timeout);
    }
    let temp_parent = repo_path.parent().unwrap_or(repo_path);
    let stdout_tmp = tempfile::NamedTempFile::new_in(temp_parent)
        .map_err(|error| GitRunError::Internal(format!("create git stdout tempfile: {error}")))?;
    let stderr_tmp = tempfile::NamedTempFile::new_in(temp_parent)
        .map_err(|error| GitRunError::Internal(format!("create git stderr tempfile: {error}")))?;
    let stdout_file = stdout_tmp
        .reopen()
        .map_err(|error| GitRunError::Internal(format!("reopen git stdout tempfile: {error}")))?;
    let stderr_file = stderr_tmp
        .reopen()
        .map_err(|error| GitRunError::Internal(format!("reopen git stderr tempfile: {error}")))?;

    let mut command = Command::new("git");
    command
        .arg("--git-dir")
        .arg(repo_path)
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file))
        .kill_on_drop(true);
    harden_git_env(&mut command);
    let mut child = command
        .spawn()
        .map_err(|error| GitRunError::Internal(format!("spawn git: {error}")))?;
    if let Some(input) = input {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| GitRunError::Internal("git stdin unavailable".to_string()))?;
        tokio::time::timeout(remaining(deadline), async {
            stdin.write_all(input).await?;
            stdin.shutdown().await
        })
        .await
        .map_err(|_| GitRunError::Timeout)?
        .map_err(|error| GitRunError::Internal(format!("write git stdin: {error}")))?;
    }
    let status = tokio::time::timeout(remaining(deadline), child.wait())
        .await
        .map_err(|_| GitRunError::Timeout)?
        .map_err(|error| GitRunError::Internal(format!("wait for git: {error}")))?;
    let stdout_len = std::fs::metadata(stdout_tmp.path())
        .map_err(|error| GitRunError::Internal(format!("stat git stdout: {error}")))?
        .len();
    if stdout_len > max_stdout_bytes {
        return Err(GitRunError::OutputTooLarge);
    }
    let stdout = std::fs::read(stdout_tmp.path())
        .map_err(|error| GitRunError::Internal(format!("read git stdout: {error}")))?;
    let stderr = std::fs::read(stderr_tmp.path())
        .map(|bytes| String::from_utf8_lossy(&bytes[..bytes.len().min(64 * 1024)]).into_owned())
        .unwrap_or_default();
    Ok(GitOutput {
        status,
        stdout,
        stderr,
    })
}

fn ensure_git_success(output: &GitOutput, operation: &str) -> Result<(), Box<Response>> {
    if output.status.success() {
        return Ok(());
    }
    error!(operation, stderr = %output.stderr, "git snapshot subprocess failed");
    Err(Box::new(
        (StatusCode::INTERNAL_SERVER_ERROR, "git snapshot failed").into_response(),
    ))
}

fn git_run_error_response(error: GitRunError) -> Response {
    match error {
        GitRunError::Timeout => {
            warn!("git snapshot subprocess timed out");
            timeout_response()
        }
        GitRunError::OutputTooLarge => (
            StatusCode::PAYLOAD_TOO_LARGE,
            "repository snapshot exceeds relay limits",
        )
            .into_response(),
        GitRunError::Internal(message) => git_error_response(&message),
    }
}

fn git_error_response(message: &str) -> Response {
    error!(error = message, "git snapshot failed");
    (StatusCode::INTERNAL_SERVER_ERROR, "git snapshot failed").into_response()
}

fn boxed_git_error_response(message: &str) -> Box<Response> {
    Box::new(git_error_response(message))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::process::Command as StdCommand;

    #[test]
    fn ref_validation_accepts_supported_forms() {
        for reference in [
            "HEAD",
            "main",
            "feature/snapshot-v1",
            "refs/heads/main",
            "refs/tags/v1.2.3",
            "a4f1c9e8d7b6a5f4c3b2a19087654321a4f1c9e8d7b6a5f4c3b2a19087654321",
        ] {
            assert_eq!(validate_snapshot_ref(reference), Ok(()), "{reference}");
        }
    }

    #[test]
    fn ref_validation_rejects_unsafe_forms() {
        for reference in [
            "",
            "-main",
            "/main",
            "main/",
            "main..next",
            "main@{1}",
            "main//next",
            "refs/heads/.hidden",
            "refs/heads/main.lock",
            "refs/heads/with space",
            "refs/heads/with~tilde",
            "refs/heads/with\\slash",
            "refs/heads/control\n",
        ] {
            assert!(validate_snapshot_ref(reference).is_err(), "{reference:?}");
        }
    }

    #[test]
    fn snapshot_json_uses_the_desktop_wire_names() {
        let commit = ProjectRepoCommit {
            hash: "abcd".to_string(),
            short_hash: "abc".to_string(),
            author_name: "A".to_string(),
            author_email: "a@example.com".to_string(),
            timestamp: 1,
            subject: "subject".to_string(),
        };
        let snapshot = ProjectRepoSnapshot {
            latest_commit: Some(commit.clone()),
            commit_count: Some(1),
            commits: vec![commit.clone()],
            files: vec![ProjectRepoFile {
                path: "README.md".to_string(),
                kind: "blob".to_string(),
                size: Some(5),
                preview_content: Some("hello".to_string()),
                last_changed_at: None,
                latest_commit: Some(commit),
            }],
            contributors: vec![ProjectRepoContributor {
                name: "A".to_string(),
                email: "a@example.com".to_string(),
                commit_count: 1,
                last_commit_at: 1,
            }],
            truncated: false,
        };
        let value = serde_json::to_value(snapshot).expect("serialize snapshot");
        let object = value.as_object().expect("snapshot object");
        assert_eq!(
            object.keys().map(String::as_str).collect::<Vec<_>>(),
            [
                "commit_count",
                "commits",
                "contributors",
                "files",
                "latest_commit",
                "truncated",
            ]
        );
        assert_eq!(
            object["files"][0]
                .as_object()
                .expect("file object")
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            [
                "kind",
                "last_changed_at",
                "latest_commit",
                "path",
                "preview_content",
                "size",
            ]
        );
        assert_eq!(object["files"][0]["last_changed_at"], Value::Null);
    }

    async fn mapped_not_found(response: Response) -> (StatusCode, String, Value) {
        let response = map_snapshot_response(response).await;
        let status = response.status();
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .expect("content type")
            .to_string();
        let body = to_bytes(response.into_body(), SNAPSHOT_ERROR_BODY_LIMIT)
            .await
            .expect("read marker body");
        let marker = serde_json::from_slice(&body).expect("parse marker body");
        (status, content_type, marker)
    }

    #[tokio::test]
    async fn missing_or_denied_repository_maps_to_generic_json_marker() {
        let (status, content_type, marker) =
            mapped_not_found((StatusCode::NOT_FOUND, REPOSITORY_NOT_FOUND).into_response()).await;

        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(content_type, "application/json");
        assert_eq!(
            marker,
            serde_json::json!({
                "error": "repository_unavailable",
                "message": "repository not found",
            })
        );
    }

    #[tokio::test]
    async fn author_unbound_repository_maps_to_remediation_json_marker() {
        let message = "run: buzz repos bind --id example --channel <channel-uuid> — repository \"example\" has no channel binding, so the relay cannot authorize access";
        let (status, content_type, marker) =
            mapped_not_found((StatusCode::NOT_FOUND, message).into_response()).await;

        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(content_type, "application/json");
        assert_eq!(
            marker,
            serde_json::json!({
                "error": "repository_unbound",
                "message": message,
            })
        );
    }

    fn git(cwd: &Path, args: &[&str]) -> std::process::Output {
        StdCommand::new("git")
            .current_dir(cwd)
            .args(args)
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("HOME", "/dev/null")
            .output()
            .expect("run fixture git")
    }

    fn assert_git(output: std::process::Output) {
        assert!(
            output.status.success(),
            "git failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[tokio::test]
    async fn snapshot_reads_a_sha256_bare_repository() {
        let temp = tempfile::TempDir::new().expect("fixture tempdir");
        let source = temp.path().join("source");
        let bare = temp.path().join("remote.git");
        assert_git(git(
            temp.path(),
            &[
                "init",
                "--object-format=sha256",
                "--initial-branch=main",
                source.to_str().expect("source path"),
            ],
        ));
        assert_git(git(
            temp.path(),
            &[
                "init",
                "--bare",
                "--object-format=sha256",
                "--initial-branch=main",
                bare.to_str().expect("bare path"),
            ],
        ));
        assert_git(git(&source, &["config", "user.name", "Snapshot Test"]));
        assert_git(git(
            &source,
            &["config", "user.email", "snapshot@example.com"],
        ));
        std::fs::write(source.join("README.md"), "# Snapshot\n").expect("write README");
        std::fs::write(source.join("notes.txt"), "hello\n").expect("write notes");
        assert_git(git(&source, &["add", "--", "README.md", "notes.txt"]));
        assert_git(git(&source, &["commit", "-m", "initial snapshot"]));
        assert_git(git(
            &source,
            &["push", bare.to_str().expect("bare path"), "main:main"],
        ));

        let snapshot = snapshot_from_repo(
            &bare,
            "HEAD",
            false,
            SNAPSHOT_DEFAULT_COMMITS,
            Instant::now() + SNAPSHOT_TIMEOUT,
        )
        .await
        .expect("build snapshot");
        let latest = snapshot.latest_commit.expect("latest commit");
        assert_eq!(latest.hash.len(), 64, "fixture must use SHA-256 object IDs");
        assert_eq!(latest.subject, "initial snapshot");
        assert_eq!(snapshot.commit_count, Some(1));
        assert_eq!(snapshot.commits.len(), 1);
        assert_eq!(snapshot.contributors.len(), 1);
        assert_eq!(snapshot.contributors[0].commit_count, 1);
        assert_eq!(
            snapshot
                .files
                .iter()
                .map(|file| file.path.as_str())
                .collect::<Vec<_>>(),
            ["README.md", "notes.txt"]
        );
        let readme = snapshot
            .files
            .iter()
            .find(|file| file.path == "README.md")
            .expect("README entry");
        assert_eq!(readme.preview_content.as_deref(), Some("# Snapshot\n"));
        assert!(readme.last_changed_at.is_none());
        assert!(readme.latest_commit.is_none());
    }
}
