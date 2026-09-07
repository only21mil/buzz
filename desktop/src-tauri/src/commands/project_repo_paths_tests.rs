use super::*;
use std::path::Path;
use std::process::Command;

fn git(path: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args([
            "-c",
            "user.name=Buzz Test",
            "-c",
            "user.email=buzz-test@example.com",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .current_dir(path)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("run fixture git");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("git output")
}

fn init(root: &Path, name: &str, origin: &str) -> std::path::PathBuf {
    let path = root.join(name);
    std::fs::create_dir(&path).expect("create fixture repo");
    git(&path, &["init", "--initial-branch=main"]);
    std::fs::write(path.join("tracked.txt"), "original\n").expect("write fixture");
    git(&path, &["add", "."]);
    git(&path, &["commit", "-m", "initial"]);
    git(&path, &["remote", "add", "origin", origin]);
    path
}

#[test]
fn discovers_two_worktrees_and_matches_origin_instead_of_directory_name() {
    let root = tempfile::tempdir().expect("root");
    let outside = tempfile::tempdir().expect("linked worktrees");
    let url = "https://relay.example/git/alice/repo.git";
    init(
        root.path(),
        "alice--repo",
        "https://relay.example/git/bob/repo.git",
    );
    let main = init(root.path(), "custom-checkout", url);
    let feature = outside.path().join("feature checkout");
    git(
        &main,
        &[
            "worktree",
            "add",
            "-b",
            "feature/a",
            feature.to_str().unwrap(),
        ],
    );
    let checkouts =
        local_project_checkouts(root.path().to_str(), Some(("repo", Some(url)))).unwrap();
    assert_eq!(checkouts.len(), 2);
    assert!(checkouts
        .iter()
        .any(|checkout| checkout.path == main && checkout.branch.as_deref() == Some("main")));
    assert!(checkouts.iter().any(
        |checkout| checkout.path == feature && checkout.branch.as_deref() == Some("feature/a")
    ));
    let selected =
        find_local_repo_for_branch(root.path().to_str(), "repo", Some(url), Some("feature/a"))
            .unwrap()
            .unwrap();
    assert_eq!(selected.path, feature);
}

#[test]
fn mismatched_and_dirty_checkouts_are_preserved_and_command_creates_separate_worktree() {
    let root = tempfile::tempdir().expect("root");
    let url = "https://relay.example/git/alice/repo.git";
    let main = init(root.path(), "repo's checkout", url);
    let remote = root.path().join("fixture.git");
    git(
        root.path(),
        &[
            "clone",
            "--bare",
            main.to_str().unwrap(),
            remote.to_str().unwrap(),
        ],
    );
    git(
        &main,
        &["remote", "set-url", "origin", remote.to_str().unwrap()],
    );
    git(&main, &["branch", "feature/a"]);
    std::fs::write(main.join("tracked.txt"), "dirty\n").unwrap();
    std::fs::write(main.join("untracked.txt"), "keep\n").unwrap();
    let before = git(&main, &["status", "--porcelain=v1"]);
    let selected = find_local_repo_for_branch(
        root.path().to_str(),
        "repo",
        Some(remote.to_str().unwrap()),
        Some("feature/a"),
    )
    .unwrap()
    .unwrap();
    assert_eq!(selected.branch.as_deref(), Some("main"));
    let message = checkout_mismatch_message(&selected, "feature/a");
    assert!(message.contains("is on main"));
    let command = worktree_add_command(&selected, "feature/a");
    assert!(Command::new("sh")
        .arg("-c")
        .arg(command)
        .status()
        .unwrap()
        .success());
    assert_eq!(git(&main, &["status", "--porcelain=v1"]), before);
    assert_eq!(git(&main, &["branch", "--show-current"]).trim(), "main");
    assert_eq!(
        std::fs::read_to_string(main.join("tracked.txt")).unwrap(),
        "dirty\n"
    );
    let selected = find_local_repo_for_branch(
        root.path().to_str(),
        "repo",
        Some(remote.to_str().unwrap()),
        Some("feature/a"),
    )
    .unwrap()
    .unwrap();
    assert_ne!(selected.path, main);
    assert_eq!(selected.branch.as_deref(), Some("feature/a"));
}

#[test]
fn detached_worktree_is_listed_but_does_not_match_selected_branch() {
    let root = tempfile::tempdir().unwrap();
    let url = "https://relay.example/git/alice/repo.git";
    let main = init(root.path(), "repo", url);
    git(&main, &["checkout", "--detach"]);
    let selected =
        find_local_repo_for_branch(root.path().to_str(), "repo", Some(url), Some("main"))
            .unwrap()
            .unwrap();
    assert_eq!(selected.branch, None);
    assert!(checkout_mismatch_message(&selected, "main").contains("detached HEAD"));
}

#[test]
fn suggested_command_creates_remote_only_branch_without_switching_existing_checkout() {
    let root = tempfile::tempdir().unwrap();
    let main = init(
        root.path(),
        "main-checkout",
        "https://relay.example/git/alice/repo.git",
    );
    let remote = root.path().join("fixture.git");
    git(
        root.path(),
        &[
            "clone",
            "--bare",
            main.to_str().unwrap(),
            remote.to_str().unwrap(),
        ],
    );
    git(&remote, &["branch", "feature/remote", "main"]);
    git(
        &main,
        &["remote", "set-url", "origin", remote.to_str().unwrap()],
    );
    let checkout = find_local_repo_for_branch(
        root.path().to_str(),
        "repo",
        Some(remote.to_str().unwrap()),
        Some("feature/remote"),
    )
    .unwrap()
    .unwrap();
    let command = worktree_add_command(&checkout, "feature/remote");
    assert!(Command::new("sh")
        .arg("-c")
        .arg(command)
        .status()
        .unwrap()
        .success());
    assert_eq!(git(&main, &["branch", "--show-current"]).trim(), "main");
    let selected = find_local_repo_for_branch(
        root.path().to_str(),
        "repo",
        Some(remote.to_str().unwrap()),
        Some("feature/remote"),
    )
    .unwrap()
    .unwrap();
    assert_eq!(selected.branch.as_deref(), Some("feature/remote"));
    assert_ne!(selected.path, main);
}
