//! Resolution of local project checkouts under the configured repos roots.
//!
//! Shared by the project git commands (snapshots, sync status, push) and the
//! project terminal launcher.

use crate::managed_agents::nest_dir;
use url::Url;

fn local_repo_name_candidate(value: &str) -> Option<String> {
    let trimmed = value.trim().trim_end_matches(".git");
    if trimmed.is_empty()
        || trimmed == "."
        || trimmed == ".."
        || trimmed.contains('/')
        || trimmed.contains('\\')
    {
        return None;
    }
    Some(trimmed.to_string())
}

fn clone_url_repo_name(clone_url: &str) -> Option<String> {
    let parsed = Url::parse(clone_url).ok()?;
    let last_segment = parsed.path_segments()?.rfind(|part| !part.is_empty())?;
    local_repo_name_candidate(last_segment)
}

fn clone_url_owner_repo_name(clone_url: &str) -> Option<String> {
    let parsed = Url::parse(clone_url).ok()?;
    let parts = parsed
        .path_segments()?
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    let [.., owner, repo] = parts.as_slice() else {
        return None;
    };
    local_repo_name_candidate(&format!(
        "{}--{}",
        local_repo_name_candidate(owner)?,
        local_repo_name_candidate(repo)?
    ))
}

fn normalized_clone_url(value: &str) -> &str {
    value.trim().trim_end_matches('/').trim_end_matches(".git")
}

fn checkout_git_dir(
    repo_dir: &std::path::Path,
    repos_root: &std::path::Path,
) -> Option<std::path::PathBuf> {
    let dot_git = repo_dir.join(".git");
    let git_dir = if dot_git.is_dir() {
        dot_git
    } else {
        let pointer = std::fs::read_to_string(dot_git).ok()?;
        let git_dir = std::path::PathBuf::from(pointer.trim().strip_prefix("gitdir:")?.trim());
        if git_dir.is_absolute() {
            git_dir
        } else {
            repo_dir.join(git_dir)
        }
    };
    let git_dir = git_dir.canonicalize().ok()?;
    if !git_dir.starts_with(repos_root) {
        return None;
    }
    Some(git_dir)
}

fn checkout_origin_matches(
    repo_dir: &std::path::Path,
    repos_root: &std::path::Path,
    clone_url: &str,
) -> bool {
    let Some(git_dir) = checkout_git_dir(repo_dir, repos_root) else {
        return false;
    };
    let Some(common_dir) = checkout_common_dir(&git_dir, repos_root) else {
        return false;
    };
    let Ok(config) = std::fs::read_to_string(common_dir.join("config")) else {
        return false;
    };
    let mut in_origin = false;
    for line in config.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_origin = line == r#"[remote "origin"]"#;
            continue;
        }
        if in_origin {
            if let Some((key, value)) = line.split_once('=') {
                if key.trim() == "url" {
                    return normalized_clone_url(value) == normalized_clone_url(clone_url);
                }
            }
        }
    }
    false
}

pub(crate) fn local_repo_candidates(project_dtag: &str, clone_url: Option<&str>) -> Vec<String> {
    let mut candidates = Vec::new();
    if let Some(candidate) = clone_url.and_then(clone_url_owner_repo_name) {
        candidates.push(candidate);
    }
    if let Some(candidate) = local_repo_name_candidate(project_dtag) {
        if !candidates.iter().any(|existing| existing == &candidate) {
            candidates.push(candidate);
        }
    }
    if let Some(candidate) = clone_url.and_then(clone_url_repo_name) {
        if !candidates.iter().any(|existing| existing == &candidate) {
            candidates.push(candidate);
        }
    }
    candidates
}

fn checkout_common_dir(
    git_dir: &std::path::Path,
    repos_root: &std::path::Path,
) -> Option<std::path::PathBuf> {
    let common_dir = match std::fs::read_to_string(git_dir.join("commondir")) {
        Ok(pointer) => git_dir.join(pointer.trim()).canonicalize().ok()?,
        Err(_) => git_dir.to_path_buf(),
    };
    common_dir.starts_with(repos_root).then_some(common_dir)
}

#[derive(Clone, serde::Serialize)]
pub(crate) struct LocalProjectCheckout {
    pub path: std::path::PathBuf,
    pub branch: Option<String>,
}

impl LocalProjectCheckout {
    pub(crate) fn name(&self) -> String {
        self.path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string()
    }
}

fn checkout_info(path: std::path::PathBuf, root: &std::path::Path) -> Option<LocalProjectCheckout> {
    let git_dir = checkout_git_dir(&path, root)?;
    let head = std::fs::read_to_string(git_dir.join("HEAD")).ok()?;
    Some(LocalProjectCheckout {
        path,
        branch: head
            .trim()
            .strip_prefix("ref: refs/heads/")
            .map(str::to_string),
    })
}

/// Discover rooted checkouts and their registered linked worktrees without changing Git state.
pub(crate) fn local_project_checkouts(
    repos_dir: Option<&str>,
    project: Option<(&str, Option<&str>)>,
) -> Result<Vec<LocalProjectCheckout>, String> {
    let mut checkouts = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for root in canonical_repos_roots(repos_dir)? {
        let entries =
            std::fs::read_dir(&root).map_err(|error| format!("read reposDir: {error}"))?;
        let mut seeds = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .collect::<Vec<_>>();
        seeds.sort();
        for seed in seeds {
            let Ok(seed) = seed.canonicalize() else {
                continue;
            };
            if !seed.starts_with(&root) || !seed.is_dir() {
                continue;
            }
            let Some(git_dir) = checkout_git_dir(&seed, &root) else {
                continue;
            };
            let Some(common_dir) = checkout_common_dir(&git_dir, &root) else {
                continue;
            };
            if let Some((dtag, url)) = project {
                if let Some(url) = url {
                    if !checkout_origin_matches(&seed, &root, url) {
                        continue;
                    }
                } else if !local_repo_candidates(dtag, None)
                    .iter()
                    .any(|name| seed.file_name().is_some_and(|file| file == name.as_str()))
                {
                    continue;
                }
            }
            let mut paths = vec![seed];
            // Git records each linked worktree's .git file here. Only follow registrations
            // that point back to this repository; stale or unrelated pointers are ignored.
            if let Ok(entries) = std::fs::read_dir(common_dir.join("worktrees")) {
                for entry in entries.filter_map(Result::ok) {
                    let registration = entry.path();
                    let Ok(pointer) = std::fs::read_to_string(registration.join("gitdir")) else {
                        continue;
                    };
                    let Some(path) = std::path::Path::new(pointer.trim()).parent() else {
                        continue;
                    };
                    let Ok(path) = path.canonicalize() else {
                        continue;
                    };
                    if checkout_git_dir(&path, &root) == registration.canonicalize().ok() {
                        paths.push(path);
                    }
                }
            }
            for path in paths {
                if seen.insert(path.clone()) {
                    if let Some(checkout) = checkout_info(path, &root) {
                        checkouts.push(checkout);
                    }
                }
            }
        }
    }
    checkouts.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(checkouts)
}

pub(crate) fn find_local_repo_for_branch(
    repos_dir: Option<&str>,
    project_dtag: &str,
    clone_url: Option<&str>,
    branch: Option<&str>,
) -> Result<Option<LocalProjectCheckout>, String> {
    let checkouts = local_project_checkouts(repos_dir, Some((project_dtag, clone_url)))?;
    Ok(checkouts
        .iter()
        .find(|checkout| branch.is_some() && checkout.branch.as_deref() == branch)
        .or_else(|| checkouts.first())
        .cloned())
}

pub(crate) fn find_local_repo_dir(
    repos_dir: Option<&str>,
    project_dtag: &str,
    clone_url: Option<&str>,
) -> Result<Option<std::path::PathBuf>, String> {
    Ok(
        find_local_repo_for_branch(repos_dir, project_dtag, clone_url, None)?
            .map(|checkout| checkout.path),
    )
}

/// A command for a new worktree; producing it never fetches or switches the existing checkout.
pub(crate) fn worktree_add_command(checkout: &LocalProjectCheckout, branch: &str) -> String {
    fn quote(value: &str) -> String {
        format!("'{}'", value.replace('\'', "'\"'\"'"))
    }
    let destination = checkout.path.with_file_name(format!(
        "{}--{}",
        checkout
            .path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy(),
        branch.replace('/', "-")
    ));
    let repo = quote(&checkout.path.to_string_lossy());
    let destination = quote(&destination.to_string_lossy());
    let local_ref = quote(&format!("refs/heads/{branch}"));
    let remote_ref = quote(&format!("refs/remotes/origin/{branch}"));
    let refspec = quote(&format!(
        "+refs/heads/{branch}:refs/remotes/origin/{branch}"
    ));
    let branch = quote(branch);
    // Keep an existing local branch intact, including unpublished commits.
    // Otherwise fetch the exact ref: a single-branch clone's configured fetch
    // refspec cannot fetch or guess other remote branches.
    format!("if git -C {repo} show-ref --verify --quiet {local_ref}; then git -C {repo} worktree add -- {destination} {branch}; else git -C {repo} fetch -- origin {refspec} && git -C {repo} worktree add -b {branch} -- {destination} {remote_ref}; fi")
}

pub(crate) fn checkout_mismatch_message(checkout: &LocalProjectCheckout, branch: &str) -> String {
    format!("Selected branch {branch} has no local checkout. {} is on {}. Create a separate worktree:\n{}",
        checkout.path.display(), checkout.branch.as_deref().unwrap_or("a detached HEAD"),
        worktree_add_command(checkout, branch))
}

pub(crate) fn default_repos_root_candidates() -> Vec<std::path::PathBuf> {
    let mut candidates = Vec::new();
    candidates.extend(nest_dir().map(|path| path.join("REPOS")));
    candidates.extend(
        dirs::home_dir()
            .map(|home| home.join(".buzz").join("REPOS"))
            .filter(|path| !candidates.iter().any(|candidate| candidate == path)),
    );
    candidates
}

pub(crate) fn canonicalize_repos_root(
    repos_root: std::path::PathBuf,
) -> Result<std::path::PathBuf, String> {
    if !repos_root.is_absolute() {
        return Err("reposDir must be an absolute path".to_string());
    }
    let repos_root = repos_root
        .canonicalize()
        .map_err(|error| format!("reposDir is not accessible: {error}"))?;
    if !repos_root.is_dir() {
        return Err("reposDir is not a directory".to_string());
    }
    Ok(repos_root)
}

pub(crate) fn canonical_repos_roots(
    repos_dir: Option<&str>,
) -> Result<Vec<std::path::PathBuf>, String> {
    if let Some(repos_root) = repos_dir
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(std::path::PathBuf::from)
    {
        return canonicalize_repos_root(repos_root).map(|root| vec![root]);
    }

    let roots = default_repos_root_candidates()
        .into_iter()
        .filter_map(|root| canonicalize_repos_root(root).ok())
        .collect::<Vec<_>>();
    if roots.is_empty() {
        return Err("reposDir is not accessible".to_string());
    }
    Ok(roots)
}

#[cfg(test)]
#[path = "project_repo_paths_tests.rs"]
mod tests;
