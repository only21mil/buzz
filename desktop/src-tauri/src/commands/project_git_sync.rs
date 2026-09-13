//! Local-vs-remote sync status for project checkouts.
//!
//! The status poll refreshes the checkout's tracking refs with `git fetch`,
//! then compares them against the local HEAD. A failed fetch must never read
//! as an up-to-date remote: the counts then describe cached refs, so the
//! "up to date" and "already pushed" claims become an explicit stale notice.

use super::project_git::{
    first_output_line, has_uncommitted_changes, has_untracked_files, normalize_branch_option,
    parse_count, short_hash,
};
use super::project_git_exec::{run_git, GitAuthConfig};
use super::project_repo_paths::LocalProjectCheckout;
use serde::Serialize;

#[derive(Serialize)]
pub struct ProjectRepoSyncStatusInfo {
    pub local_path: Option<String>,
    pub local_branch: Option<String>,
    pub local_branches: Vec<String>,
    pub local_checkouts: Vec<LocalProjectCheckout>,
    pub local_head: Option<String>,
    pub local_short_head: Option<String>,
    pub remote_branch: Option<String>,
    pub remote_head: Option<String>,
    pub remote_short_head: Option<String>,
    pub merge_base: Option<String>,
    pub ahead_count: usize,
    pub behind_count: usize,
    pub has_uncommitted_changes: bool,
    pub has_untracked_files: bool,
    pub can_push: bool,
    pub push_block_reason: Option<String>,
    pub can_pull: bool,
    pub pull_block_reason: Option<String>,
    /// True when this poll's `git fetch` failed, so `remote_head`,
    /// `ahead_count`, and `behind_count` describe the last cached remote
    /// state rather than the live remote.
    pub fetch_failed: bool,
    /// The fetch failure message when `fetch_failed` is true.
    pub fetch_error: Option<String>,
}

/// Reported in place of an "up to date" or "already pushed" claim when the
/// status poll's fetch failed. The ahead/behind counts then describe cached
/// tracking refs, so presenting them as the live remote state would be wrong.
const STALE_REMOTE_STATUS_REASON: &str = "Remote state may be stale. The last fetch failed.";

pub(crate) fn compare_local_remote_status(
    repo_dir: &std::path::Path,
    clone_url: &str,
    branch_name: Option<&str>,
    base_branch: Option<&str>,
    auth: &GitAuthConfig,
) -> ProjectRepoSyncStatusInfo {
    let local_branch = run_git(&["branch", "--show-current"], Some(repo_dir), auth)
        .ok()
        .and_then(|output| first_output_line(&output));
    let local_branches = run_git(
        &[
            "for-each-ref",
            "--count=200",
            "--format=%(refname:short)",
            "refs/heads/",
        ],
        Some(repo_dir),
        auth,
    )
    .map(|output| {
        output
            .lines()
            .filter_map(|branch| normalize_branch_option(Some(branch)))
            .collect()
    })
    .unwrap_or_default();
    // The local checkout's branch name is attacker-influencable (a hostile
    // remote can point HEAD at a flag-shaped refname), so it must pass the
    // same `clean_branch` validation as relay-supplied names before it is
    // ever handed to git as an argument.
    let branch = normalize_branch_option(branch_name)
        .or_else(|| normalize_branch_option(local_branch.as_deref()))
        .unwrap_or_else(|| "main".to_string());

    // Only rewrite the checkout's origin when it actually differs from the
    // project's clone URL — a read-only status poll must not silently
    // re-point the user's remote on every run.
    let current_origin = run_git(&["remote", "get-url", "origin"], Some(repo_dir), auth)
        .ok()
        .and_then(|output| first_output_line(&output));
    if current_origin.as_deref() != Some(clone_url) {
        let _ = run_git(
            &["remote", "set-url", "origin", clone_url],
            Some(repo_dir),
            auth,
        );
    }
    let base_branch =
        normalize_branch_option(base_branch).filter(|base_branch| *base_branch != branch);
    let mut fetch_args = vec![
        "fetch",
        "--quiet",
        "--depth=100",
        "--end-of-options",
        "origin",
        branch.as_str(),
    ];
    if let Some(base_branch) = base_branch.as_deref() {
        fetch_args.push(base_branch);
    }
    // A failed fetch must not silently pass: the tracking refs below would
    // otherwise be compared as if they were the live remote state.
    let (fetch_failed, fetch_error) = match run_git(&fetch_args, Some(repo_dir), auth) {
        Ok(_) => (false, None),
        Err(error) => (true, Some(error)),
    };

    let local_head = run_git(&["rev-parse", "HEAD"], Some(repo_dir), auth)
        .ok()
        .and_then(|output| first_output_line(&output));
    let remote_ref = format!("refs/remotes/origin/{branch}");
    let remote_head = run_git(
        &["rev-parse", "--verify", "--quiet", remote_ref.as_str()],
        Some(repo_dir),
        auth,
    )
    .ok()
    .and_then(|output| first_output_line(&output));
    // A legacy empty clone may have an unborn local `master` while the project
    // declares `main`. Permit that mismatch only when the remote has no branch
    // refs at all; any lookup failure is treated as non-empty (fail closed).
    let remote_has_branches = run_git(
        &["ls-remote", "--heads", "--end-of-options", "origin"],
        Some(repo_dir),
        auth,
    )
    .map(|output| !output.trim().is_empty())
    .unwrap_or(true);
    let is_first_publish = remote_head.is_none() && !remote_has_branches;
    let merge_base = base_branch.as_deref().and_then(|base_branch| {
        run_git(
            &[
                "merge-base",
                "HEAD",
                format!("origin/{base_branch}").as_str(),
            ],
            Some(repo_dir),
            auth,
        )
        .ok()
        .and_then(|output| first_output_line(&output))
    });
    let status = run_git(&["status", "--porcelain"], Some(repo_dir), auth).unwrap_or_default();
    let has_uncommitted_changes = has_uncommitted_changes(&status);
    let has_untracked_files = has_untracked_files(&status);
    let ahead_count = match remote_head.as_deref() {
        Some(_) => run_git(
            &[
                "rev-list",
                "--count",
                format!("origin/{branch}..HEAD").as_str(),
            ],
            Some(repo_dir),
            auth,
        )
        .map(|output| parse_count(&output))
        .unwrap_or_default(),
        None => usize::from(local_head.is_some()),
    };
    let behind_count = match remote_head.as_deref() {
        Some(_) => run_git(
            &[
                "rev-list",
                "--count",
                format!("HEAD..origin/{branch}").as_str(),
            ],
            Some(repo_dir),
            auth,
        )
        .map(|output| parse_count(&output))
        .unwrap_or_default(),
        None => 0,
    };

    let mut push_block_reason = if local_head.is_none() {
        Some("No local commits to push.".to_string())
    } else if local_branch.as_deref() != Some(branch.as_str()) && !is_first_publish {
        Some(format!(
            "Local checkout is on a different branch than {branch}."
        ))
    } else if has_uncommitted_changes || has_untracked_files {
        Some("Commit or discard local changes before pushing.".to_string())
    } else if behind_count > 0 {
        Some("Pull or reconcile remote commits before pushing.".to_string())
    } else if ahead_count == 0 {
        Some("Local branch is already pushed.".to_string())
    } else {
        None
    };

    // Pulling is a fast-forward only merge of origin/<branch> into the
    // current checkout, so it is blocked whenever that would not apply
    // cleanly (diverged history, dirty worktree, branch mismatch).
    let mut pull_block_reason = if local_head.is_none() {
        Some("No local commits yet — clone instead of pulling.".to_string())
    } else if remote_head.is_none() {
        Some("Remote branch not found.".to_string())
    } else if behind_count == 0 {
        Some("Local branch is up to date.".to_string())
    } else if local_branch.as_deref() != Some(branch.as_str()) {
        Some(format!(
            "Local checkout is on a different branch than {branch}."
        ))
    } else if has_uncommitted_changes {
        Some("Commit or stash local changes before pulling.".to_string())
    } else if ahead_count > 0 {
        Some("Local and remote have diverged — reconcile in a terminal.".to_string())
    } else {
        None
    };

    // A failed fetch leaves stale tracking refs behind. Locally determined
    // blocks (dirty worktree, diverged history, branch mismatch) still stand,
    // but "up to date" and "already pushed" claims require a live remote, so
    // they become an explicit stale notice instead.
    if fetch_failed {
        if push_block_reason.as_deref() == Some("Local branch is already pushed.") {
            push_block_reason = Some(STALE_REMOTE_STATUS_REASON.to_string());
        }
        if pull_block_reason.as_deref() == Some("Local branch is up to date.") {
            pull_block_reason = Some(STALE_REMOTE_STATUS_REASON.to_string());
        }
    }

    ProjectRepoSyncStatusInfo {
        local_path: Some(repo_dir.display().to_string()),
        local_branch,
        local_branches,
        local_checkouts: Vec::new(),
        local_head: local_head.clone(),
        local_short_head: local_head.as_deref().map(short_hash),
        remote_branch: Some(branch),
        remote_head: remote_head.clone(),
        remote_short_head: remote_head.as_deref().map(short_hash),
        merge_base,
        ahead_count,
        behind_count,
        has_uncommitted_changes,
        has_untracked_files,
        can_push: push_block_reason.is_none(),
        push_block_reason,
        can_pull: pull_block_reason.is_none(),
        pull_block_reason,
        fetch_failed,
        fetch_error,
    }
}
