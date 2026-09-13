use super::{compare_local_remote_status, snapshot_from_worktree};
use crate::commands::project_git_exec::{build_test_git_auth_config, run_git};

#[test]
fn snapshot_reports_exact_commit_count_beyond_preview_limit() {
    let auth = build_test_git_auth_config().expect("build test git config");
    let root = tempfile::tempdir().expect("create test directory");
    let repo = root.path();

    run_git(&["init", "--initial-branch=main"], Some(repo), &auth).expect("initialize repository");
    run_git(&["config", "user.name", "Buzz Test"], Some(repo), &auth).expect("configure user name");
    run_git(
        &["config", "user.email", "buzz-test@example.com"],
        Some(repo),
        &auth,
    )
    .expect("configure user email");

    for index in 0..51 {
        run_git(
            &["commit", "--allow-empty", "-m", &format!("commit {index}")],
            Some(repo),
            &auth,
        )
        .expect("create commit");
    }

    let snapshot = snapshot_from_worktree(repo, &auth, Some("main"), Some("main"));

    assert_eq!(snapshot.commits.len(), 50);
    assert_eq!(snapshot.commit_count, Some(51));
}

#[test]
fn selected_branch_filters_non_branch_and_invalid_refs() {
    for branch in [
        "refs/tags/v1",
        "refs/remotes/origin/main",
        "feature//a",
        "feature/.hidden",
        "feature.lock",
        "--help",
    ] {
        assert_eq!(
            super::normalize_branch_option(Some(branch)),
            None,
            "{branch}"
        );
    }
    assert_eq!(
        super::normalize_branch_option(Some("refs/heads/feature/a")),
        Some("feature/a".to_string())
    );
}

#[test]
fn sync_status_reports_stale_instead_of_up_to_date_when_fetch_fails() {
    let auth = build_test_git_auth_config().expect("build test git config");
    let root = tempfile::tempdir().expect("create test directory");

    // Seed a bare origin with one commit on main.
    let origin = root.path().join("origin.git");
    let origin_url = origin.to_str().expect("utf8 path").to_string();
    run_git(&["init", "--bare", origin_url.as_str()], None, &auth).expect("initialize bare origin");
    let seed = root.path().join("seed");
    std::fs::create_dir_all(&seed).expect("create seed dir");
    run_git(&["init", "--initial-branch=main"], Some(&seed), &auth).expect("initialize seed");
    run_git(&["config", "user.name", "Buzz Test"], Some(&seed), &auth)
        .expect("configure user name");
    run_git(
        &["config", "user.email", "buzz-test@example.com"],
        Some(&seed),
        &auth,
    )
    .expect("configure user email");
    run_git(
        &["commit", "--allow-empty", "-m", "seed"],
        Some(&seed),
        &auth,
    )
    .expect("create seed commit");
    run_git(
        &["remote", "add", "origin", origin_url.as_str()],
        Some(&seed),
        &auth,
    )
    .expect("add seed remote");
    run_git(&["push", "origin", "main"], Some(&seed), &auth).expect("push seed");
    run_git(
        &[
            "--git-dir",
            origin_url.as_str(),
            "symbolic-ref",
            "HEAD",
            "refs/heads/main",
        ],
        None,
        &auth,
    )
    .expect("point origin HEAD at main");

    // Clone, then break the remote URL so the status poll's fetch fails
    // while the tracking ref stays cached.
    let local = root.path().join("local");
    let local_str = local.to_str().expect("utf8 path").to_string();
    run_git(
        &["clone", origin_url.as_str(), local_str.as_str()],
        None,
        &auth,
    )
    .expect("clone origin");
    let missing = root.path().join("missing-origin.git");
    let missing_url = missing.to_str().expect("utf8 path").to_string();
    run_git(
        &["remote", "set-url", "origin", missing_url.as_str()],
        Some(&local),
        &auth,
    )
    .expect("break origin url");

    let status = compare_local_remote_status(&local, &missing_url, Some("main"), None, &auth);

    assert!(
        status.fetch_failed,
        "broken origin must fail the poll fetch"
    );
    assert!(
        status.fetch_error.is_some(),
        "fetch failure must carry its message"
    );
    assert_eq!(status.ahead_count, 0);
    assert_eq!(status.behind_count, 0);
    assert_eq!(
        status.pull_block_reason.as_deref(),
        Some("Remote state may be stale. The last fetch failed."),
        "stale tracking refs must not be called up to date",
    );
    assert_eq!(
        status.push_block_reason.as_deref(),
        Some("Remote state may be stale. The last fetch failed."),
        "stale tracking refs must not be called already pushed",
    );
    assert!(!status.can_pull);
    assert!(!status.can_push);
}
