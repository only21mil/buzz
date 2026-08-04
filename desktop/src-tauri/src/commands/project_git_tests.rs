use super::snapshot_from_worktree;
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
