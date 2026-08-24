//! Buzz-authoritative, exact-ref synchronization to a GitHub CI mirror.
//!
//! These commands intentionally do not publish Nostr status events. The
//! caller-owned kind:30617 announcement is the only source of remote URLs,
//! Buzz is the source for every ongoing write; `import-main` is bootstrap-only.

use std::ffi::OsStr;
use std::process::{Command, Output};

#[cfg(unix)]
use std::{io::Write, os::unix::fs::OpenOptionsExt};

use nostr::Event;
use tempfile::TempDir;

use crate::client::BuzzClient;
use crate::error::CliError;

const MAIN_REF: &str = "refs/heads/main";
const BUZZ_TRACKING_REF: &str = "refs/remotes/buzz/main";
const BUZZ_SOURCE_TRACKING_REF: &str = "refs/remotes/buzz/source";
const GITHUB_ACTIONS_APP_ID: u64 = 15_368;
#[cfg(unix)]
const GITHUB_ASKPASS: &str = r#"#!/bin/sh
case "$1" in
  *Username*) printf '%s\n' 'x-access-token' ;;
  *Password*)
    if test -n "${GH_TOKEN:-}"; then
      printf '%s\n' "$GH_TOKEN"
    elif test -n "${GITHUB_TOKEN:-}"; then
      printf '%s\n' "$GITHUB_TOKEN"
    else
      exit 1
    fi
    ;;
  *) exit 1 ;;
esac
"#;

#[derive(Debug, Clone)]
struct RepoRemotes {
    repo_id: String,
    buzz_url: String,
    github: GitHubRepo,
}

#[derive(Debug, Clone)]
struct GitHubRepo {
    clone_url: String,
    owner: String,
    repo: String,
}

#[derive(Clone)]
struct GitAuth {
    private_key: String,
    auth_tag: Option<String>,
}

#[derive(Clone)]
struct GitHubAuth {
    variable: &'static str,
    token: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RemoteState {
    main: Option<String>,
    head: Option<String>,
    head_target: Option<String>,
}

#[derive(Debug, serde::Serialize)]
struct StatusOutput<'a> {
    repo_id: &'a str,
    direction: &'static str,
    github_url: &'a str,
    buzz_url: &'a str,
    buzz_main: &'a str,
    buzz_head: Option<&'a str>,
    github_main: Option<&'a str>,
    in_sync: bool,
}

#[derive(Debug, serde::Serialize)]
struct WriteOutput {
    repo_id: String,
    direction: &'static str,
    commit: String,
    changed: bool,
    github_main: String,
    buzz_main: String,
    buzz_head: String,
}

#[derive(Debug, serde::Serialize)]
struct StageOutput {
    repo_id: String,
    direction: &'static str,
    source_ref: String,
    commit: String,
    github_ci_ref: String,
    changed: bool,
    github_ci_commit: String,
}

#[derive(Debug, serde::Serialize)]
struct PromoteOutput {
    repo_id: String,
    direction: &'static str,
    base: String,
    head: String,
    source_ref: String,
    github_ci_ref: String,
    required_checks: Vec<String>,
    resumed_after_buzz_advance: bool,
    buzz_main_changed: bool,
    github_main_changed: bool,
    buzz_main: String,
    buzz_head: String,
    github_main: String,
}

struct PromoteRequest<'a> {
    base: &'a str,
    head: &'a str,
    source_ref: &'a str,
    ci_ref: &'a str,
    required_checks: &'a [String],
}

/// Exact inputs for a read-only lifecycle proof.
///
/// The CI ref is derived from `head`; callers cannot point the proof at an
/// unrelated hosted ref. An empty `required_checks` list skips the GitHub
/// Checks API while retaining exact Git ref and ancestry readbacks.
pub(super) struct LifecycleSnapshotRequest<'a> {
    pub(super) base: &'a str,
    pub(super) head: &'a str,
    pub(super) source_ref: &'a str,
    pub(super) required_checks: &'a [String],
}

/// Stable, read-only evidence for the Git portion of a repository lifecycle.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(super) struct LifecycleSnapshot {
    pub(super) repo_id: String,
    pub(super) buzz_url: String,
    pub(super) github_url: String,
    pub(super) github_owner: String,
    pub(super) github_repo: String,
    pub(super) base: String,
    pub(super) head: String,
    pub(super) source_ref: String,
    pub(super) github_ci_ref: String,
    pub(super) buzz_main: String,
    pub(super) buzz_head: String,
    pub(super) buzz_head_target: String,
    pub(super) buzz_source: Option<String>,
    pub(super) github_main: Option<String>,
    pub(super) github_ci_commit: Option<String>,
    pub(super) base_is_ancestor_of_head: bool,
    pub(super) required_checks: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LifecycleRefSnapshot {
    buzz: RemoteState,
    buzz_source: Option<String>,
    github_main: Option<String>,
    github_ci: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct CheckRunsResponse {
    check_runs: Vec<CheckRun>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct CheckRun {
    name: String,
    status: String,
    conclusion: Option<String>,
    head_sha: String,
    app: CheckApp,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct CheckApp {
    id: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PromoteStart {
    Initial,
    ResumeAfterBuzzAdvance,
}

fn exact_oid(value: &str, flag: &str) -> Result<String, CliError> {
    if value.len() != 40 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(CliError::Usage(format!(
            "{flag} must be an exact 40-hex commit"
        )));
    }
    Ok(value.to_ascii_lowercase())
}

fn exact_tag_values<'a>(event: &'a Event, name: &str) -> Result<Option<Vec<&'a str>>, CliError> {
    let mut matching = event
        .tags
        .iter()
        .filter(|tag| tag.as_slice().first().map(String::as_str) == Some(name));
    let Some(tag) = matching.next() else {
        return Ok(None);
    };
    if matching.next().is_some() {
        return Err(CliError::Usage(format!(
            "repository announcement has multiple {name} tags"
        )));
    }
    Ok(Some(
        tag.as_slice().iter().skip(1).map(String::as_str).collect(),
    ))
}

fn github_repo(value: &str) -> Result<GitHubRepo, CliError> {
    let url = url::Url::parse(value)
        .map_err(|_| CliError::Usage("GitHub clone URL must be a valid HTTPS URL".into()))?;
    let parts = url
        .path_segments()
        .map(|parts| parts.collect::<Vec<_>>())
        .unwrap_or_default();
    if url.scheme() != "https"
        || url
            .host_str()
            .map(|host| host.eq_ignore_ascii_case("github.com"))
            != Some(true)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || parts.len() != 2
    {
        return Err(CliError::Usage(
            "GitHub clone URL must be https://github.com/<owner>/<repo>[.git] without credentials, query, or fragment"
                .into(),
        ));
    }
    let owner = parts[0];
    let repo = parts[1].strip_suffix(".git").unwrap_or(parts[1]);
    let valid_component = |part: &str| {
        !part.is_empty()
            && part != "."
            && part != ".."
            && part
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    };
    if !valid_component(owner) || !valid_component(repo) {
        return Err(CliError::Usage(
            "GitHub owner and repository must use only ASCII letters, digits, '.', '-', or '_'"
                .into(),
        ));
    }
    Ok(GitHubRepo {
        clone_url: value.to_owned(),
        owner: owner.to_owned(),
        repo: repo.to_owned(),
    })
}

pub(super) fn validate_github_clone(value: &str) -> Result<(), CliError> {
    github_repo(value).map(|_| ())
}

fn validate_branch_ref(value: &str, flag: &str) -> Result<String, CliError> {
    let Some(branch) = value.strip_prefix("refs/heads/") else {
        return Err(CliError::Usage(format!(
            "{flag} must be a full refs/heads/<branch> ref"
        )));
    };
    let invalid_byte = |byte: u8| {
        byte <= b' '
            || byte == 0x7f
            || matches!(byte, b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')
    };
    if branch.is_empty()
        || branch.starts_with('/')
        || branch.ends_with('/')
        || branch.ends_with('.')
        || branch.contains("..")
        || branch.contains("@{")
        || branch.bytes().any(invalid_byte)
        || branch
            .split('/')
            .any(|part| part.is_empty() || part.starts_with('.') || part.ends_with(".lock"))
    {
        return Err(CliError::Usage(format!("{flag} is not a safe branch ref")));
    }
    Ok(value.to_owned())
}

fn ci_ref_for(commit: &str) -> String {
    format!("refs/heads/buzz-ci/{commit}")
}

fn expected_ref(value: &str, flag: &str) -> Result<Option<String>, CliError> {
    if value == "absent" {
        Ok(None)
    } else {
        exact_oid(value, flag).map(Some)
    }
}

fn github_auth_from_env() -> Result<GitHubAuth, CliError> {
    for variable in ["GH_TOKEN", "GITHUB_TOKEN"] {
        if let Some(token) = std::env::var_os(variable).filter(|value| !value.is_empty()) {
            let token = token
                .into_string()
                .map_err(|_| CliError::Auth(format!("{variable} must contain valid UTF-8 text")))?;
            return Ok(GitHubAuth { variable, token });
        }
    }
    Err(CliError::Auth(
        "GH_TOKEN or GITHUB_TOKEN is required for GitHub repository synchronization".into(),
    ))
}

fn derive_remotes(client: &BuzzClient, announcement: &Event) -> Result<RepoRemotes, CliError> {
    // A NIP-OA tag delegates authority to this signing identity; it does not
    // replace the event author or the repository path owner. Git repository
    // announcements and `/git/<owner>/<repo>` paths remain keyed by the
    // signing key that authored kind:30617.
    let owner = client.keys().public_key().to_hex();
    if announcement.pubkey.to_hex() != owner {
        return Err(CliError::Auth(
            "repository announcement is not owned by the effective caller".into(),
        ));
    }

    let repo_id = exact_tag_values(announcement, "d")?
        .and_then(|values| values.first().copied())
        .ok_or_else(|| CliError::Other("repository announcement is missing its d tag".into()))?
        .to_owned();
    crate::validate::validate_repo_id(&repo_id)?;
    let buzz_url = format!(
        "{}/git/{owner}/{repo_id}",
        client.relay_url().trim_end_matches('/')
    );
    let clones = exact_tag_values(announcement, "clone")?
        .filter(|values| !values.is_empty())
        .ok_or_else(|| CliError::Usage("repository announcement has no clone URLs".into()))?;
    if clones.first().copied() != Some(buzz_url.as_str()) {
        return Err(CliError::Usage(format!(
            "repository clone tag must list the canonical Buzz URL first: {buzz_url}"
        )));
    }

    let github: Vec<&str> = clones
        .iter()
        .skip(1)
        .copied()
        .filter(|value| {
            url::Url::parse(value).ok().and_then(|url| {
                url.host_str()
                    .map(|host| host.eq_ignore_ascii_case("github.com"))
            }) == Some(true)
        })
        .collect();
    if clones.len() != github.len() + 1 {
        return Err(CliError::Usage(
            "repository clone tag may contain only canonical Buzz followed by an optional GitHub clone"
                .into(),
        ));
    }
    let github_url = match github.as_slice() {
        [url] => (*url).to_owned(),
        [] => {
            return Err(CliError::Usage(
                "one GitHub clone URL is required for repository synchronization".into(),
            ))
        }
        _ => {
            return Err(CliError::Usage(
                "repository announcement has multiple GitHub clone URLs".into(),
            ))
        }
    };
    let github = github_repo(&github_url)?;

    Ok(RepoRemotes {
        repo_id,
        buzz_url,
        github,
    })
}

struct GitRepo {
    _temp: TempDir,
    git_dir: std::path::PathBuf,
    buzz_auth: GitAuth,
    github_auth: GitHubAuth,
    askpass: std::path::PathBuf,
}

#[derive(Clone, Copy)]
enum RemoteAuth {
    None,
    Buzz,
    GitHub,
}

fn write_github_askpass(path: &std::path::Path) -> Result<(), CliError> {
    #[cfg(unix)]
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(path)
            .map_err(|_| CliError::Other("failed to prepare GitHub authentication".into()))?;
        file.write_all(GITHUB_ASKPASS.as_bytes())
            .map_err(|_| CliError::Other("failed to prepare GitHub authentication".into()))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(CliError::Other(
            "GitHub synchronization requires a mode-protected askpass platform".into(),
        ))
    }
}

impl GitRepo {
    fn new(buzz_auth: GitAuth, github_auth: GitHubAuth) -> Result<Self, CliError> {
        let work_root = dirs::home_dir()
            .ok_or_else(|| CliError::Other("home directory is unavailable".into()))?
            .join("work");
        std::fs::create_dir_all(&work_root)
            .map_err(|_| CliError::Other("failed to prepare the private sync workspace".into()))?;
        let temp = tempfile::Builder::new()
            .prefix("buzz-repo-sync-")
            .tempdir_in(work_root)
            .map_err(|_| CliError::Other("failed to create private temporary repository".into()))?;
        let git_dir = temp.path().join("repo.git");
        let askpass = temp.path().join("github-askpass");
        write_github_askpass(&askpass)?;
        let repo = Self {
            _temp: temp,
            git_dir,
            buzz_auth,
            github_auth,
            askpass,
        };
        repo.run(
            RemoteAuth::None,
            "initialize temporary repository",
            ["init", "--bare"],
        )?;
        Ok(repo)
    }

    fn command(&self, auth: RemoteAuth) -> Command {
        let mut command = Command::new("git");
        let path = std::env::var_os("PATH").unwrap_or_default();
        command
            .env_clear()
            .env("PATH", path)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", self.git_dir.join("no-global-config"))
            .env("GIT_TERMINAL_PROMPT", "0")
            .arg("--git-dir")
            .arg(&self.git_dir)
            .arg("-c")
            .arg(format!(
                "core.hooksPath={}",
                self.git_dir.join("no-hooks").display()
            ))
            .args(["-c", "credential.helper="])
            .args(["-c", "credential.useHttpPath=true"]);
        match auth {
            RemoteAuth::None => {}
            RemoteAuth::Buzz => {
                command
                    .args(["-c", "credential.helper=nostr"])
                    .env("NOSTR_PRIVATE_KEY", &self.buzz_auth.private_key);
                if let Some(auth_tag) = &self.buzz_auth.auth_tag {
                    command.env("BUZZ_AUTH_TAG", auth_tag);
                }
            }
            RemoteAuth::GitHub => {
                command
                    .env("GIT_ASKPASS", &self.askpass)
                    .env("GIT_ASKPASS_REQUIRE", "force")
                    .env(self.github_auth.variable, &self.github_auth.token);
            }
        }
        command
    }

    fn output<I, S>(&self, auth: RemoteAuth, operation: &str, args: I) -> Result<Output, CliError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let output = self
            .command(auth)
            .args(args)
            .output()
            .map_err(|_| CliError::Other(format!("failed to run git for {operation}")))?;
        if !output.status.success() {
            return Err(CliError::Other(format!(
                "git {operation} failed (exit {})",
                output.status.code().unwrap_or(-1)
            )));
        }
        Ok(output)
    }

    fn run<I, S>(&self, auth: RemoteAuth, operation: &str, args: I) -> Result<(), CliError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.output(auth, operation, args).map(|_| ())
    }

    fn ls_remote(
        &self,
        url: &str,
        auth: RemoteAuth,
        remote: &str,
    ) -> Result<RemoteState, CliError> {
        let output = self.output(
            auth,
            &format!("read {remote} remote refs"),
            ["ls-remote", "--symref", url, "HEAD", MAIN_REF],
        )?;
        let stdout = std::str::from_utf8(&output.stdout)
            .map_err(|_| CliError::Other("git returned invalid ref data".into()))?;
        parse_remote_state(stdout)
    }

    fn remote_ref(
        &self,
        url: &str,
        auth: RemoteAuth,
        remote: &str,
        reference: &str,
    ) -> Result<Option<String>, CliError> {
        let output = self.output(
            auth,
            &format!("read {remote} ref"),
            ["ls-remote", "--refs", url, reference],
        )?;
        let stdout = std::str::from_utf8(&output.stdout)
            .map_err(|_| CliError::Other("git returned invalid ref data".into()))?;
        let mut values = stdout.lines().map(|line| {
            let (oid, name) = line
                .split_once('\t')
                .ok_or_else(|| CliError::Other("git returned malformed ref data".into()))?;
            if name != reference {
                return Err(CliError::Other("git returned an unexpected ref".into()));
            }
            exact_oid(oid, "remote ref")
        });
        let first = values.next().transpose()?;
        if values.next().is_some() {
            return Err(CliError::Other("git returned duplicate remote refs".into()));
        }
        Ok(first)
    }

    fn github_main(&self, url: &str) -> Result<Option<String>, CliError> {
        self.remote_ref(url, RemoteAuth::GitHub, "GitHub", MAIN_REF)
    }

    fn fetch_ref(
        &self,
        url: &str,
        auth: RemoteAuth,
        remote: &str,
        source: &str,
        tracking: &str,
        expected: &str,
    ) -> Result<(), CliError> {
        let refspec = format!("+{source}:{tracking}");
        self.run(
            auth,
            &format!("fetch {remote} ref"),
            ["fetch", "--no-tags", "--force", url, refspec.as_str()],
        )?;
        let fetched = self.rev_parse(tracking)?;
        if fetched != expected {
            return Err(CliError::Conflict(format!(
                "{remote} ref changed while it was being fetched; no write was attempted"
            )));
        }
        Ok(())
    }

    fn fetch_github_main(&self, url: &str, commit: &str) -> Result<(), CliError> {
        self.fetch_ref(
            url,
            RemoteAuth::GitHub,
            "GitHub main",
            MAIN_REF,
            "refs/remotes/github/main",
            commit,
        )
    }

    fn rev_parse(&self, reference: &str) -> Result<String, CliError> {
        let output = self.output(
            RemoteAuth::None,
            "resolve commit",
            ["rev-parse", "--verify", reference],
        )?;
        let value = std::str::from_utf8(&output.stdout)
            .map_err(|_| CliError::Other("git returned invalid commit data".into()))?
            .trim();
        exact_oid(value, "resolved ref")
    }

    fn is_ancestor(&self, older: &str, newer: &str) -> Result<bool, CliError> {
        let output = self
            .command(RemoteAuth::None)
            .args(["merge-base", "--is-ancestor", older, newer])
            .output()
            .map_err(|_| CliError::Other("failed to run git for ancestry proof".into()))?;
        match output.status.code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => Err(CliError::Other("git ancestry proof failed".into())),
        }
    }

    fn push_ref(
        &self,
        url: &str,
        auth: RemoteAuth,
        remote: &str,
        reference: &str,
        commit: &str,
        expected: Option<&str>,
    ) -> Result<bool, CliError> {
        let lease = format!(
            "--force-with-lease={reference}:{}",
            expected.unwrap_or_default()
        );
        let refspec = format!("{commit}:{reference}");
        let output = self
            .command(auth)
            .args([
                "push",
                "--porcelain",
                "--no-follow-tags",
                lease.as_str(),
                url,
                refspec.as_str(),
            ])
            .output()
            .map_err(|_| CliError::Other(format!("failed to run git for push {remote} ref")))?;
        if output.status.success() {
            let porcelain = String::from_utf8_lossy(&output.stdout);
            let changed = !porcelain.lines().any(|line| line.starts_with('='));
            return Ok(changed);
        }
        let porcelain = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if porcelain.lines().any(|line| {
            line.starts_with('!')
                && line.contains("[rejected]")
                && !line.contains("[remote rejected]")
        }) {
            return Err(CliError::Conflict(format!(
                "{remote} ref is absent, present, or moved contrary to its exact lease"
            )));
        }
        let stderr = stderr.trim();
        let detail = if matches!(auth, RemoteAuth::GitHub) || stderr.is_empty() {
            String::new()
        } else {
            format!(": {stderr}")
        };
        Err(CliError::Other(format!(
            "git push {remote} ref failed (exit {}){detail}",
            output.status.code().unwrap_or(-1),
        )))
    }
}

fn parse_remote_state(stdout: &str) -> Result<RemoteState, CliError> {
    let mut state = RemoteState {
        main: None,
        head: None,
        head_target: None,
    };
    for line in stdout.lines() {
        let Some((left, name)) = line.split_once('\t') else {
            return Err(CliError::Other("git returned malformed ref data".into()));
        };
        match name {
            "HEAD" if left.starts_with("ref: ") => {
                state.head_target = Some(left[5..].to_owned());
            }
            "HEAD" => state.head = Some(exact_oid(left, "remote HEAD")?),
            MAIN_REF => state.main = Some(exact_oid(left, "remote main")?),
            _ => {}
        }
    }
    Ok(state)
}

fn require_exact_head(state: &RemoteState, commit: &str) -> Result<(), CliError> {
    if state.main.as_deref() != Some(commit)
        || state.head.as_deref() != Some(commit)
        || state.head_target.as_deref() != Some(MAIN_REF)
    {
        return Err(CliError::Conflict(
            "Buzz main and HEAD did not read back at the exact requested commit".into(),
        ));
    }
    Ok(())
}

fn require_consistent_head(state: &RemoteState) -> Result<String, CliError> {
    let main = state
        .main
        .as_deref()
        .ok_or_else(|| CliError::NotFound("Buzz canonical main is absent".into()))?;
    require_exact_head(state, main)?;
    Ok(main.to_owned())
}

fn read_lifecycle_refs(
    repo: &GitRepo,
    remotes: &RepoRemotes,
    source_ref: &str,
    ci_ref: &str,
) -> Result<LifecycleRefSnapshot, CliError> {
    Ok(LifecycleRefSnapshot {
        buzz: repo.ls_remote(&remotes.buzz_url, RemoteAuth::Buzz, "Buzz")?,
        buzz_source: repo.remote_ref(
            &remotes.buzz_url,
            RemoteAuth::Buzz,
            "Buzz source",
            source_ref,
        )?,
        github_main: repo.github_main(&remotes.github.clone_url)?,
        github_ci: repo.remote_ref(
            &remotes.github.clone_url,
            RemoteAuth::GitHub,
            "GitHub CI",
            ci_ref,
        )?,
    })
}

fn require_unchanged_lifecycle_refs(
    before: &LifecycleRefSnapshot,
    after: &LifecycleRefSnapshot,
) -> Result<(), CliError> {
    if before != after {
        return Err(CliError::Conflict(
            "a Buzz or GitHub ref moved during the lifecycle readback".into(),
        ));
    }
    Ok(())
}

fn buzz_ref_for_head<'a>(
    refs: &LifecycleRefSnapshot,
    source_ref: &'a str,
    head: &str,
) -> Result<&'a str, CliError> {
    if refs.buzz_source.as_deref() == Some(head) {
        Ok(source_ref)
    } else if refs.buzz.main.as_deref() == Some(head) {
        Ok(MAIN_REF)
    } else {
        Err(CliError::Conflict(
            "neither Buzz source nor Buzz main equals the requested lifecycle head".into(),
        ))
    }
}

/// Read exact hosted refs and prove ancestry without mutating either remote.
///
/// The only Git mutation is a fetch into a private temporary bare repository.
/// Hosted refs are read once before GitHub checks and once afterward; any
/// movement fails the snapshot rather than returning mixed-time evidence.
pub(super) async fn read_lifecycle_snapshot(
    client: &BuzzClient,
    announcement: &Event,
    request: LifecycleSnapshotRequest<'_>,
) -> Result<LifecycleSnapshot, CliError> {
    let base = exact_oid(request.base, "lifecycle base")?;
    let head = exact_oid(request.head, "lifecycle head")?;
    if base == head {
        return Err(CliError::Usage(
            "lifecycle base and head must differ".into(),
        ));
    }
    let source_ref = validate_branch_ref(request.source_ref, "lifecycle source ref")?;
    let ci_ref = ci_ref_for(&head);
    let remotes = derive_remotes(client, announcement)?;
    let github_auth = github_auth_from_env()?;
    let repo = GitRepo::new(auth_from_client(client), github_auth.clone())?;
    let before = read_lifecycle_refs(&repo, &remotes, &source_ref, &ci_ref)?;
    let buzz_main = require_consistent_head(&before.buzz)?;
    let head_ref = buzz_ref_for_head(&before, &source_ref, &head)?;
    repo.fetch_ref(
        &remotes.buzz_url,
        RemoteAuth::Buzz,
        "Buzz lifecycle head",
        head_ref,
        BUZZ_SOURCE_TRACKING_REF,
        &head,
    )?;
    let base_is_ancestor_of_head = repo.is_ancestor(&base, &head)?;
    if !request.required_checks.is_empty() {
        let checks = github_check_runs(&remotes.github, &github_auth, &head).await?;
        evaluate_required_checks(request.required_checks, &checks, &head)?;
    }
    let after = read_lifecycle_refs(&repo, &remotes, &source_ref, &ci_ref)?;
    require_unchanged_lifecycle_refs(&before, &after)?;

    Ok(LifecycleSnapshot {
        repo_id: remotes.repo_id,
        buzz_url: remotes.buzz_url,
        github_url: remotes.github.clone_url,
        github_owner: remotes.github.owner,
        github_repo: remotes.github.repo,
        base,
        head,
        source_ref,
        github_ci_ref: ci_ref,
        buzz_main,
        buzz_head: before
            .buzz
            .head
            .ok_or_else(|| CliError::Other("Buzz HEAD missing after exact readback".into()))?,
        buzz_head_target: before.buzz.head_target.ok_or_else(|| {
            CliError::Other("Buzz HEAD target missing after exact readback".into())
        })?,
        buzz_source: before.buzz_source,
        github_main: before.github_main,
        github_ci_commit: before.github_ci,
        base_is_ancestor_of_head,
        required_checks: request.required_checks.to_vec(),
    })
}

fn auth_from_client(client: &BuzzClient) -> GitAuth {
    GitAuth {
        private_key: client.keys().secret_key().to_secret_hex(),
        auth_tag: client.auth_tag_json().map(str::to_owned),
    }
}

fn execute_import(
    remotes: &RepoRemotes,
    buzz_auth: GitAuth,
    github_auth: GitHubAuth,
    commit: &str,
) -> Result<WriteOutput, CliError> {
    let repo = GitRepo::new(buzz_auth, github_auth)?;
    if repo.github_main(&remotes.github.clone_url)?.as_deref() != Some(commit) {
        return Err(CliError::Conflict(
            "GitHub main does not equal --commit; no write was attempted".into(),
        ));
    }
    repo.fetch_github_main(&remotes.github.clone_url, commit)?;
    // Re-read GitHub after the fetch, then use an empty lease so a concurrent
    // Buzz main creation loses the race. Git reports an existing main already
    // at `commit` as unchanged without exercising the lease, so an unchanged
    // push is also a bootstrap conflict.
    if repo.github_main(&remotes.github.clone_url)?.as_deref() != Some(commit) {
        return Err(CliError::Conflict(
            "GitHub main changed before the Buzz write; no write was attempted".into(),
        ));
    }
    let changed = repo.push_ref(
        &remotes.buzz_url,
        RemoteAuth::Buzz,
        "Buzz main",
        MAIN_REF,
        commit,
        None,
    )?;
    if !changed {
        return Err(CliError::Conflict(
            "Buzz main already exists; import-main is bootstrap-only".into(),
        ));
    }
    let github_after = repo.github_main(&remotes.github.clone_url)?;
    if github_after.as_deref() != Some(commit) {
        return Err(CliError::Conflict(
            "GitHub main changed during synchronization".into(),
        ));
    }
    let buzz_after = repo.ls_remote(&remotes.buzz_url, RemoteAuth::Buzz, "Buzz")?;
    require_exact_head(&buzz_after, commit)?;
    let buzz_main = buzz_after
        .main
        .ok_or_else(|| CliError::Other("Buzz main missing after exact readback".into()))?;
    let buzz_head = buzz_after
        .head
        .ok_or_else(|| CliError::Other("Buzz HEAD missing after exact readback".into()))?;
    Ok(WriteOutput {
        repo_id: remotes.repo_id.clone(),
        direction: "github-to-buzz-bootstrap-only",
        commit: commit.to_owned(),
        changed,
        github_main: github_after
            .ok_or_else(|| CliError::Other("GitHub main missing after exact readback".into()))?,
        buzz_main,
        buzz_head,
    })
}

fn execute_stage(
    remotes: &RepoRemotes,
    buzz_auth: GitAuth,
    github_auth: GitHubAuth,
    source_ref: &str,
    commit: &str,
    expected_ci: Option<&str>,
) -> Result<StageOutput, CliError> {
    let repo = GitRepo::new(buzz_auth, github_auth)?;
    let source = repo.remote_ref(
        &remotes.buzz_url,
        RemoteAuth::Buzz,
        "Buzz source",
        source_ref,
    )?;
    if source.as_deref() != Some(commit) {
        return Err(CliError::Conflict(
            "Buzz source ref does not equal --commit; no write was attempted".into(),
        ));
    }
    repo.fetch_ref(
        &remotes.buzz_url,
        RemoteAuth::Buzz,
        "Buzz source",
        source_ref,
        BUZZ_SOURCE_TRACKING_REF,
        commit,
    )?;
    let ci_ref = ci_ref_for(commit);
    let github_before = repo.remote_ref(
        &remotes.github.clone_url,
        RemoteAuth::GitHub,
        "GitHub CI",
        &ci_ref,
    )?;
    if github_before.as_deref() != expected_ci {
        return Err(CliError::Conflict(
            "GitHub CI ref does not match --expected-github-ci; no write was attempted".into(),
        ));
    }
    let changed = repo.push_ref(
        &remotes.github.clone_url,
        RemoteAuth::GitHub,
        "GitHub CI",
        &ci_ref,
        commit,
        expected_ci,
    )?;
    if !changed && expected_ci != Some(commit) {
        return Err(CliError::Conflict(
            "GitHub CI ref reached --commit without exercising the requested lease".into(),
        ));
    }
    let github_after = repo.remote_ref(
        &remotes.github.clone_url,
        RemoteAuth::GitHub,
        "GitHub CI",
        &ci_ref,
    )?;
    if github_after.as_deref() != Some(commit) {
        return Err(CliError::Conflict(
            "GitHub CI ref did not read back at the exact Buzz commit".into(),
        ));
    }
    Ok(StageOutput {
        repo_id: remotes.repo_id.clone(),
        direction: "buzz-to-github-ci",
        source_ref: source_ref.to_owned(),
        commit: commit.to_owned(),
        github_ci_ref: ci_ref,
        changed,
        github_ci_commit: github_after
            .ok_or_else(|| CliError::Other("GitHub CI ref missing after exact readback".into()))?,
    })
}

fn evaluate_required_checks(
    required: &[String],
    runs: &[CheckRun],
    commit: &str,
) -> Result<(), CliError> {
    let mut seen = std::collections::HashSet::new();
    for name in required {
        if name.is_empty() || name.trim() != name {
            return Err(CliError::Usage(
                "--required-check names must be non-empty and have no surrounding whitespace"
                    .into(),
            ));
        }
        if !seen.insert(name) {
            return Err(CliError::Usage(format!(
                "--required-check was provided more than once: {name}"
            )));
        }
        let matching: Vec<&CheckRun> = runs.iter().filter(|run| run.name == *name).collect();
        let [run] = matching.as_slice() else {
            return Err(CliError::Conflict(if matching.is_empty() {
                format!("required GitHub check is missing at {commit}: {name}")
            } else {
                format!("required GitHub check is not unique at {commit}: {name}")
            }));
        };
        if exact_oid(&run.head_sha, "GitHub check head_sha")? != commit
            || run.app.id != GITHUB_ACTIONS_APP_ID
            || run.status != "completed"
            || run.conclusion.as_deref() != Some("success")
        {
            return Err(CliError::Conflict(format!(
                "required GitHub Actions check is not trusted+completed+success at {commit}: {name}"
            )));
        }
    }
    Ok(())
}

async fn github_check_runs(
    github: &GitHubRepo,
    auth: &GitHubAuth,
    commit: &str,
) -> Result<Vec<CheckRun>, CliError> {
    let client = reqwest::Client::new();
    let mut all = Vec::new();
    for page in 1..=100_u16 {
        let url = format!(
            "https://api.github.com/repos/{}/{}/commits/{commit}/check-runs?per_page=100&page={page}",
            github.owner, github.repo
        );
        let response = client
            .get(url)
            .header(reqwest::header::ACCEPT, "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header(reqwest::header::USER_AGENT, "buzz-cli-repo-sync")
            .bearer_auth(&auth.token)
            .send()
            .await?;
        let status = response.status();
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            return Err(CliError::Auth(format!(
                "GitHub checks request was rejected (HTTP {})",
                status.as_u16()
            )));
        }
        if !status.is_success() {
            return Err(CliError::Other(format!(
                "GitHub checks request failed (HTTP {})",
                status.as_u16()
            )));
        }
        let page: CheckRunsResponse = response.json().await?;
        let count = page.check_runs.len();
        all.extend(page.check_runs);
        if count < 100 {
            return Ok(all);
        }
    }
    Err(CliError::Other(
        "GitHub returned more than 10,000 check runs for the exact commit".into(),
    ))
}

fn classify_promote_start(
    buzz_main: Option<&str>,
    github_main: Option<&str>,
    base: &str,
    head: &str,
) -> Result<PromoteStart, CliError> {
    match (buzz_main, github_main) {
        (Some(buzz), Some(github)) if buzz == base && github == base => Ok(PromoteStart::Initial),
        (Some(buzz), Some(github)) if buzz == head && github == base => {
            Ok(PromoteStart::ResumeAfterBuzzAdvance)
        }
        _ => Err(CliError::Conflict(
            "expected both mains at --base, or retry state Buzz main at --head and GitHub main at --base"
                .into(),
        )),
    }
}

fn partial_success(head: &str, error: CliError) -> CliError {
    CliError::Other(format!(
        "Buzz main is at {head}, but GitHub main completion is unproven ({error}); run repos status, then retry the same promote command only if GitHub main remains --base"
    ))
}

async fn execute_promote(
    remotes: &RepoRemotes,
    buzz_auth: GitAuth,
    github_auth: GitHubAuth,
    request: PromoteRequest<'_>,
) -> Result<PromoteOutput, CliError> {
    let PromoteRequest {
        base,
        head,
        source_ref,
        ci_ref,
        required_checks,
    } = request;
    if required_checks.is_empty() {
        return Err(CliError::Usage(
            "at least one --required-check must be provided".into(),
        ));
    }
    let repo = GitRepo::new(buzz_auth, github_auth.clone())?;
    let buzz_before = repo.ls_remote(&remotes.buzz_url, RemoteAuth::Buzz, "Buzz")?;
    let github_before = repo.github_main(&remotes.github.clone_url)?;
    let start = classify_promote_start(
        buzz_before.main.as_deref(),
        github_before.as_deref(),
        base,
        head,
    )?;
    let expected_buzz_main = match start {
        PromoteStart::Initial => base,
        PromoteStart::ResumeAfterBuzzAdvance => head,
    };
    require_exact_head(&buzz_before, expected_buzz_main)?;
    if repo
        .remote_ref(
            &remotes.buzz_url,
            RemoteAuth::Buzz,
            "Buzz source",
            source_ref,
        )?
        .as_deref()
        != Some(head)
    {
        return Err(CliError::Conflict(
            "Buzz source ref does not equal --head; no write was attempted".into(),
        ));
    }
    if repo
        .remote_ref(
            &remotes.github.clone_url,
            RemoteAuth::GitHub,
            "GitHub CI",
            ci_ref,
        )?
        .as_deref()
        != Some(head)
    {
        return Err(CliError::Conflict(
            "GitHub CI ref does not equal --head; no write was attempted".into(),
        ));
    }
    repo.fetch_ref(
        &remotes.buzz_url,
        RemoteAuth::Buzz,
        "Buzz source",
        source_ref,
        BUZZ_SOURCE_TRACKING_REF,
        head,
    )?;
    repo.fetch_ref(
        &remotes.buzz_url,
        RemoteAuth::Buzz,
        "Buzz main",
        MAIN_REF,
        BUZZ_TRACKING_REF,
        expected_buzz_main,
    )?;
    if !repo.is_ancestor(base, head)? {
        return Err(CliError::Conflict(
            "--base is not an ancestor of --head in the Buzz-fetched object graph".into(),
        ));
    }
    let checks = github_check_runs(&remotes.github, &github_auth, head).await?;
    evaluate_required_checks(required_checks, &checks, head)?;

    // Checks may take long enough for refs to move. Re-read every lease input
    // immediately before the first mutation.
    let buzz_ready = repo.ls_remote(&remotes.buzz_url, RemoteAuth::Buzz, "Buzz")?;
    require_exact_head(&buzz_ready, expected_buzz_main)?;
    if repo
        .remote_ref(
            &remotes.buzz_url,
            RemoteAuth::Buzz,
            "Buzz source",
            source_ref,
        )?
        .as_deref()
        != Some(head)
        || repo
            .remote_ref(
                &remotes.github.clone_url,
                RemoteAuth::GitHub,
                "GitHub CI",
                ci_ref,
            )?
            .as_deref()
            != Some(head)
        || repo.github_main(&remotes.github.clone_url)?.as_deref() != Some(base)
    {
        return Err(CliError::Conflict(
            "a Buzz or GitHub ref moved after checks were evaluated; no write was attempted".into(),
        ));
    }

    let buzz_main_changed = if start == PromoteStart::Initial {
        let changed = repo.push_ref(
            &remotes.buzz_url,
            RemoteAuth::Buzz,
            "Buzz main",
            MAIN_REF,
            head,
            Some(base),
        )?;
        if !changed {
            return Err(partial_success(
                head,
                CliError::Conflict(
                    "Buzz main reached --head without exercising the --base lease".into(),
                ),
            ));
        }
        true
    } else {
        false
    };
    let buzz_after = repo
        .ls_remote(&remotes.buzz_url, RemoteAuth::Buzz, "Buzz")
        .map_err(|error| partial_success(head, error))?;
    require_exact_head(&buzz_after, head).map_err(|error| partial_success(head, error))?;

    let github_main_changed = repo
        .push_ref(
            &remotes.github.clone_url,
            RemoteAuth::GitHub,
            "GitHub main",
            MAIN_REF,
            head,
            Some(base),
        )
        .map_err(|error| partial_success(head, error))?;
    if !github_main_changed {
        return Err(partial_success(
            head,
            CliError::Conflict(
                "GitHub main reached --head without exercising the --base lease".into(),
            ),
        ));
    }
    let github_after = repo
        .github_main(&remotes.github.clone_url)
        .map_err(|error| partial_success(head, error))?;
    if github_after.as_deref() != Some(head) {
        return Err(partial_success(
            head,
            CliError::Conflict("GitHub main did not read back at --head".into()),
        ));
    }
    let buzz_final = repo
        .ls_remote(&remotes.buzz_url, RemoteAuth::Buzz, "Buzz")
        .map_err(|error| partial_success(head, error))?;
    require_exact_head(&buzz_final, head).map_err(|error| partial_success(head, error))?;

    Ok(PromoteOutput {
        repo_id: remotes.repo_id.clone(),
        direction: "buzz-to-github",
        base: base.to_owned(),
        head: head.to_owned(),
        source_ref: source_ref.to_owned(),
        github_ci_ref: ci_ref.to_owned(),
        required_checks: required_checks.to_vec(),
        resumed_after_buzz_advance: start == PromoteStart::ResumeAfterBuzzAdvance,
        buzz_main_changed,
        github_main_changed,
        buzz_main: buzz_final
            .main
            .ok_or_else(|| CliError::Other("Buzz main missing after promotion".into()))?,
        buzz_head: buzz_final
            .head
            .ok_or_else(|| CliError::Other("Buzz HEAD missing after promotion".into()))?,
        github_main: github_after
            .ok_or_else(|| CliError::Other("GitHub main missing after promotion".into()))?,
    })
}

pub async fn cmd_status(client: &BuzzClient, announcement: &Event) -> Result<(), CliError> {
    let remotes = derive_remotes(client, announcement)?;
    let repo = GitRepo::new(auth_from_client(client), github_auth_from_env()?)?;
    let buzz = repo.ls_remote(&remotes.buzz_url, RemoteAuth::Buzz, "Buzz")?;
    let buzz_main = buzz
        .main
        .as_deref()
        .ok_or_else(|| CliError::NotFound("Buzz canonical main is absent".into()))?;
    let github_main = repo.github_main(&remotes.github.clone_url)?;
    let output = StatusOutput {
        repo_id: &remotes.repo_id,
        direction: "buzz-to-github",
        github_url: &remotes.github.clone_url,
        buzz_url: &remotes.buzz_url,
        buzz_main,
        buzz_head: buzz.head.as_deref(),
        github_main: github_main.as_deref(),
        in_sync: github_main.as_deref() == Some(buzz_main)
            && buzz.head.as_deref() == Some(buzz_main)
            && buzz.head_target.as_deref() == Some(MAIN_REF),
    };
    println!(
        "{}",
        serde_json::to_string(&output)
            .map_err(|_| CliError::Other("failed to serialize repository status".into()))?
    );
    Ok(())
}

pub async fn cmd_import_main(
    client: &BuzzClient,
    announcement: &Event,
    commit: &str,
) -> Result<(), CliError> {
    let commit = exact_oid(commit, "--commit")?;
    let remotes = derive_remotes(client, announcement)?;
    let output = execute_import(
        &remotes,
        auth_from_client(client),
        github_auth_from_env()?,
        &commit,
    )?;
    println!(
        "{}",
        serde_json::to_string(&output)
            .map_err(|_| CliError::Other("failed to serialize repository sync result".into()))?
    );
    Ok(())
}

pub async fn cmd_stage_ci(
    client: &BuzzClient,
    announcement: &Event,
    source_ref: &str,
    commit: &str,
    expected_github_ci: &str,
) -> Result<(), CliError> {
    let commit = exact_oid(commit, "--commit")?;
    let source_ref = validate_branch_ref(source_ref, "--source-ref")?;
    let expected = expected_ref(expected_github_ci, "--expected-github-ci")?;
    let remotes = derive_remotes(client, announcement)?;
    let output = execute_stage(
        &remotes,
        auth_from_client(client),
        github_auth_from_env()?,
        &source_ref,
        &commit,
        expected.as_deref(),
    )?;
    println!(
        "{}",
        serde_json::to_string(&output)
            .map_err(|_| CliError::Other("failed to serialize repository sync result".into()))?
    );
    Ok(())
}

pub async fn cmd_promote(
    client: &BuzzClient,
    announcement: &Event,
    base: &str,
    head: &str,
    source_ref: &str,
    ci_ref: &str,
    required_checks: &[String],
) -> Result<(), CliError> {
    let base = exact_oid(base, "--base")?;
    let head = exact_oid(head, "--head")?;
    if base == head {
        return Err(CliError::Usage("--base and --head must differ".into()));
    }
    let source_ref = validate_branch_ref(source_ref, "--source-ref")?;
    let ci_ref = validate_branch_ref(ci_ref, "--ci-ref")?;
    if ci_ref != ci_ref_for(&head) {
        return Err(CliError::Usage(format!(
            "--ci-ref must be the deterministic exact-head ref {}",
            ci_ref_for(&head)
        )));
    }
    let remotes = derive_remotes(client, announcement)?;
    let output = execute_promote(
        &remotes,
        auth_from_client(client),
        github_auth_from_env()?,
        PromoteRequest {
            base: &base,
            head: &head,
            source_ref: &source_ref,
            ci_ref: &ci_ref,
            required_checks,
        },
    )
    .await?;
    println!(
        "{}",
        serde_json::to_string(&output)
            .map_err(|_| CliError::Other("failed to serialize repository sync result".into()))?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::{Keys, Tag};
    use std::path::Path;

    fn git<I, S>(cwd: &Path, args: I) -> String
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let output = Command::new("git")
            .current_dir(cwd)
            .args(args)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .expect("run fixture git");
        assert!(
            output.status.success(),
            "fixture git failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    }

    struct Fixture {
        _temp: TempDir,
        github: String,
        buzz: String,
        work: std::path::PathBuf,
        first: String,
    }

    impl Fixture {
        fn new() -> Self {
            let temp = tempfile::tempdir().expect("fixture tempdir");
            let github = temp.path().join("github.git");
            let buzz = temp.path().join("buzz.git");
            let work = temp.path().join("work");
            git(temp.path(), ["init", "--bare", github.to_str().unwrap()]);
            git(temp.path(), ["init", "--bare", buzz.to_str().unwrap()]);
            git(&github, ["symbolic-ref", "HEAD", MAIN_REF]);
            git(&buzz, ["symbolic-ref", "HEAD", MAIN_REF]);
            git(temp.path(), ["init", work.to_str().unwrap()]);
            git(&work, ["config", "user.name", "Buzz Test"]);
            git(&work, ["config", "user.email", "buzz-test@example.invalid"]);
            git(&work, ["checkout", "-b", "main"]);
            std::fs::write(work.join("file.txt"), "one\n").expect("write fixture");
            git(&work, ["add", "file.txt"]);
            git(&work, ["commit", "-m", "one"]);
            let first = git(&work, ["rev-parse", "HEAD"]);
            git(
                &work,
                ["push", github.to_str().unwrap(), "HEAD:refs/heads/main"],
            );
            Self {
                github: github.to_string_lossy().into_owned(),
                buzz: buzz.to_string_lossy().into_owned(),
                work,
                first,
                _temp: temp,
            }
        }

        fn remotes(&self) -> RepoRemotes {
            RepoRemotes {
                repo_id: "fixture".into(),
                buzz_url: self.buzz.clone(),
                github: GitHubRepo {
                    clone_url: self.github.clone(),
                    owner: "fixture-owner".into(),
                    repo: "fixture-repo".into(),
                },
            }
        }

        fn auth() -> GitAuth {
            GitAuth {
                private_key: "1".repeat(64),
                auth_tag: None,
            }
        }

        fn github_auth() -> GitHubAuth {
            GitHubAuth {
                variable: "GH_TOKEN",
                token: "fixture-secret-token".into(),
            }
        }

        fn next_commit(&self) -> String {
            std::fs::write(self.work.join("file.txt"), "two\n").expect("write fixture");
            git(&self.work, ["add", "file.txt"]);
            git(&self.work, ["commit", "-m", "two"]);
            git(&self.work, ["rev-parse", "HEAD"])
        }
    }

    fn lifecycle_refs(oid: &str) -> LifecycleRefSnapshot {
        LifecycleRefSnapshot {
            buzz: RemoteState {
                main: Some(oid.to_string()),
                head: Some(oid.to_string()),
                head_target: Some(MAIN_REF.to_string()),
            },
            buzz_source: Some(oid.to_string()),
            github_main: Some(oid.to_string()),
            github_ci: Some(oid.to_string()),
        }
    }

    #[test]
    fn lifecycle_readback_requires_consistent_buzz_head_and_detects_movement() {
        let oid = "a".repeat(40);
        let before = lifecycle_refs(&oid);
        assert_eq!(
            require_consistent_head(&before.buzz).expect("consistent Buzz HEAD"),
            oid
        );
        assert!(require_unchanged_lifecycle_refs(&before, &before).is_ok());

        let mut moved = before.clone();
        moved.github_ci = Some("b".repeat(40));
        assert!(matches!(
            require_unchanged_lifecycle_refs(&before, &moved),
            Err(CliError::Conflict(message)) if message.contains("moved during")
        ));

        let mut detached = before.buzz.clone();
        detached.head_target = None;
        assert!(matches!(
            require_consistent_head(&detached),
            Err(CliError::Conflict(_))
        ));
    }

    #[test]
    fn lifecycle_head_object_uses_exact_source_then_exact_main() {
        let head = "a".repeat(40);
        let mut refs = lifecycle_refs(&head);
        assert_eq!(
            buzz_ref_for_head(&refs, "refs/heads/work", &head).expect("source ref at head"),
            "refs/heads/work"
        );

        refs.buzz_source = None;
        assert_eq!(
            buzz_ref_for_head(&refs, "refs/heads/work", &head).expect("main ref at head"),
            MAIN_REF
        );

        refs.buzz.main = Some("b".repeat(40));
        assert!(matches!(
            buzz_ref_for_head(&refs, "refs/heads/work", &head),
            Err(CliError::Conflict(message)) if message.contains("neither Buzz source")
        ));
    }

    #[test]
    fn lifecycle_snapshot_serialization_contains_no_auth_material() {
        let oid = "a".repeat(40);
        let snapshot = LifecycleSnapshot {
            repo_id: "fixture".into(),
            buzz_url: "https://relay.example/git/owner/fixture".into(),
            github_url: "https://github.com/owner/fixture.git".into(),
            github_owner: "owner".into(),
            github_repo: "fixture".into(),
            base: "b".repeat(40),
            head: oid.clone(),
            source_ref: "refs/heads/work".into(),
            github_ci_ref: ci_ref_for(&oid),
            buzz_main: oid.clone(),
            buzz_head: oid.clone(),
            buzz_head_target: MAIN_REF.into(),
            buzz_source: Some(oid.clone()),
            github_main: Some(oid.clone()),
            github_ci_commit: Some(oid),
            base_is_ancestor_of_head: true,
            required_checks: vec!["test".into()],
        };
        let value = serde_json::to_value(snapshot).expect("serialize lifecycle snapshot");
        let object = value.as_object().expect("snapshot object");
        assert!(!object.keys().any(|key| {
            key.contains("token") || key.contains("private") || key.contains("credential")
        }));
    }

    #[test]
    fn lifecycle_ref_snapshot_reads_each_exact_hosted_ref() {
        let fixture = Fixture::new();
        execute_import(
            &fixture.remotes(),
            Fixture::auth(),
            Fixture::github_auth(),
            &fixture.first,
        )
        .expect("bootstrap Buzz main");
        let head = fixture.next_commit();
        let source_ref = "refs/heads/work/fixture";
        let source_refspec = format!("HEAD:{source_ref}");
        git(
            &fixture.work,
            ["push", fixture.buzz.as_str(), source_refspec.as_str()],
        );
        let staged = execute_stage(
            &fixture.remotes(),
            Fixture::auth(),
            Fixture::github_auth(),
            source_ref,
            &head,
            None,
        )
        .expect("stage deterministic CI ref");

        let repo = GitRepo::new(Fixture::auth(), Fixture::github_auth())
            .expect("create read-only repository");
        let refs = read_lifecycle_refs(
            &repo,
            &fixture.remotes(),
            source_ref,
            &staged.github_ci_ref,
        )
        .expect("read exact lifecycle refs");
        assert_eq!(refs.buzz.main.as_deref(), Some(fixture.first.as_str()));
        assert_eq!(refs.buzz.head.as_deref(), Some(fixture.first.as_str()));
        assert_eq!(refs.buzz_source.as_deref(), Some(head.as_str()));
        assert_eq!(refs.github_main.as_deref(), Some(fixture.first.as_str()));
        assert_eq!(refs.github_ci.as_deref(), Some(head.as_str()));
    }

    #[test]
    fn exact_oid_requires_full_commit() {
        assert!(exact_oid(&"a".repeat(40), "--commit").is_ok());
        assert!(exact_oid(&"a".repeat(39), "--commit").is_err());
        assert!(exact_oid(&"z".repeat(40), "--commit").is_err());
    }

    #[test]
    fn announcement_requires_caller_owned_canonical_buzz_then_github() {
        let keys = Keys::generate();
        let owner = keys.public_key().to_hex();
        let relay = "https://relay.example";
        let buzz = format!("{relay}/git/{owner}/fixture");
        let client = BuzzClient::new(relay.into(), keys.clone(), None, None).expect("client");
        let event = buzz_sdk::build_repo_announcement(
            "fixture",
            None,
            None,
            &[&buzz, "https://github.com/block/buzz.git"],
            None,
            &[],
        )
        .expect("announcement")
        .sign_with_keys(&keys)
        .expect("sign announcement");
        let remotes = derive_remotes(&client, &event).expect("canonical remotes");
        assert_eq!(remotes.buzz_url, buzz);
        assert_eq!(
            remotes.github.clone_url,
            "https://github.com/block/buzz.git"
        );
        assert_eq!(remotes.github.owner, "block");
        assert_eq!(remotes.github.repo, "buzz");

        let wrong_order = buzz_sdk::build_repo_announcement(
            "fixture",
            None,
            None,
            &["https://github.com/block/buzz.git", &buzz],
            None,
            &[],
        )
        .expect("announcement")
        .sign_with_keys(&keys)
        .expect("sign announcement");
        assert!(matches!(
            derive_remotes(&client, &wrong_order),
            Err(CliError::Usage(_))
        ));

        let duplicate_clone = nostr::EventBuilder::new(nostr::Kind::Custom(30617), "")
            .tags([
                Tag::parse(["d", "fixture"]).unwrap(),
                Tag::parse(["clone", &buzz, "https://github.com/block/buzz.git"]).unwrap(),
                Tag::parse(["clone", &buzz, "https://github.com/block/buzz.git"]).unwrap(),
            ])
            .sign_with_keys(&keys)
            .expect("sign announcement");
        assert!(matches!(
            derive_remotes(&client, &duplicate_clone),
            Err(CliError::Usage(message)) if message.contains("multiple clone tags")
        ));
    }

    #[test]
    fn delegated_auth_owner_does_not_replace_repository_event_author() {
        let keys = Keys::generate();
        let auth_owner = Keys::generate().public_key().to_hex();
        let auth_tag = Tag::parse(["auth", auth_owner.as_str(), "", &"0".repeat(128)])
            .expect("syntactically valid auth tag");
        let relay = "https://relay.example";
        let repo_owner = keys.public_key().to_hex();
        let buzz = format!("{relay}/git/{repo_owner}/fixture");
        let client = BuzzClient::new(
            relay.into(),
            keys.clone(),
            Some(auth_tag),
            Some("[]".into()),
        )
        .expect("client");
        let event = buzz_sdk::build_repo_announcement(
            "fixture",
            None,
            None,
            &[&buzz, "https://github.com/block/buzz.git"],
            None,
            &[],
        )
        .expect("announcement")
        .sign_with_keys(&keys)
        .expect("sign announcement");

        let remotes = derive_remotes(&client, &event).expect("signing key owns repository");
        assert_eq!(remotes.buzz_url, buzz);
    }

    #[test]
    fn import_is_bootstrap_only_and_stage_sources_buzz_without_moving_mains() {
        let fixture = Fixture::new();
        let imported = execute_import(
            &fixture.remotes(),
            Fixture::auth(),
            Fixture::github_auth(),
            &fixture.first,
        )
        .expect("import main");
        assert!(imported.changed);
        assert_eq!(imported.direction, "github-to-buzz-bootstrap-only");
        assert_eq!(
            git(Path::new(&fixture.buzz), ["show-ref"]),
            format!("{} refs/heads/main", fixture.first)
        );

        let second = fixture.next_commit();
        git(
            &fixture.work,
            ["push", fixture.buzz.as_str(), "HEAD:refs/heads/pr/9"],
        );
        let staged = execute_stage(
            &fixture.remotes(),
            Fixture::auth(),
            Fixture::github_auth(),
            "refs/heads/pr/9",
            &second,
            None,
        )
        .expect("stage Buzz commit");
        assert!(staged.changed);
        assert_eq!(staged.direction, "buzz-to-github-ci");
        assert_eq!(staged.github_ci_ref, ci_ref_for(&second));
        assert_eq!(
            git(Path::new(&fixture.github), ["rev-parse", MAIN_REF]),
            fixture.first
        );
        assert_eq!(
            git(Path::new(&fixture.buzz), ["rev-parse", MAIN_REF]),
            fixture.first
        );
        assert_eq!(
            git(
                Path::new(&fixture.github),
                ["rev-parse", ci_ref_for(&second).as_str()]
            ),
            second
        );
    }

    #[test]
    fn import_refuses_populated_buzz_and_stage_refuses_stale_lease() {
        let fixture = Fixture::new();
        git(
            &fixture.work,
            ["push", fixture.buzz.as_str(), "HEAD:refs/heads/main"],
        );
        assert!(matches!(
            execute_import(
                &fixture.remotes(),
                Fixture::auth(),
                Fixture::github_auth(),
                &fixture.first
            ),
            Err(CliError::Conflict(_))
        ));

        let second = fixture.next_commit();
        git(
            &fixture.work,
            ["push", fixture.buzz.as_str(), "HEAD:refs/heads/pr/9"],
        );
        execute_stage(
            &fixture.remotes(),
            Fixture::auth(),
            Fixture::github_auth(),
            "refs/heads/pr/9",
            &second,
            None,
        )
        .expect("initial stage");
        assert!(matches!(
            execute_stage(
                &fixture.remotes(),
                Fixture::auth(),
                Fixture::github_auth(),
                "refs/heads/pr/9",
                &second,
                Some(&"f".repeat(40))
            ),
            Err(CliError::Conflict(_))
        ));

        std::fs::write(fixture.work.join("file.txt"), "three\n").expect("write fixture");
        git(&fixture.work, ["add", "file.txt"]);
        git(&fixture.work, ["commit", "-m", "three"]);
        git(
            &fixture.work,
            [
                "push",
                "--force",
                fixture.buzz.as_str(),
                "HEAD:refs/heads/pr/9",
            ],
        );
        assert!(matches!(
            execute_stage(
                &fixture.remotes(),
                Fixture::auth(),
                Fixture::github_auth(),
                "refs/heads/pr/9",
                &second,
                Some(&second)
            ),
            Err(CliError::Conflict(message)) if message.contains("Buzz source")
        ));
    }

    #[test]
    fn import_reports_policy_decline_as_auth_not_conflict() {
        // The relay's push ACL is a pre-receive hook (buzz-relay
        // api/git/hook.rs): a non-200 policy decision writes the reason to
        // stderr and exits 1, which git reports as `[remote rejected]`. That
        // must surface as an auth failure carrying the real reason, NOT as a
        // Conflict -- a Conflict would misreport an authorization failure as
        // an ordinary ref lease race.
        let fixture = Fixture::new();
        let hook = Path::new(&fixture.buzz).join("hooks").join("pre-receive");
        std::fs::create_dir_all(hook.parent().unwrap()).expect("hooks dir");
        std::fs::write(
            &hook,
            "#!/bin/sh\necho 'error: push denied by policy (HTTP 403)' >&2\nexit 1\n",
        )
        .expect("write hook");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755))
                .expect("chmod hook");
        }
        match execute_import(
            &fixture.remotes(),
            Fixture::auth(),
            Fixture::github_auth(),
            &fixture.first,
        ) {
            Err(CliError::Other(msg)) => assert!(
                msg.contains("push denied by policy"),
                "auth decline must carry the real reason; got: {msg}"
            ),
            other => {
                panic!("policy decline must be Other (auth), never Conflict; got: {other:?}")
            }
        }
    }

    #[test]
    fn parse_remote_state_requires_exact_main_and_head() {
        let oid = "a".repeat(40);
        let state = parse_remote_state(&format!(
            "ref: refs/heads/main\tHEAD\n{oid}\tHEAD\n{oid}\trefs/heads/main\n"
        ))
        .expect("parse refs");
        assert_eq!(state.main.as_deref(), Some(oid.as_str()));
        assert_eq!(state.head.as_deref(), Some(oid.as_str()));
        assert_eq!(state.head_target.as_deref(), Some(MAIN_REF));
    }

    #[test]
    fn github_url_and_branch_ref_validation_fail_closed() {
        let parsed = github_repo("https://github.com/block/buzz.git").expect("valid URL");
        assert_eq!(
            (parsed.owner.as_str(), parsed.repo.as_str()),
            ("block", "buzz")
        );
        for invalid in [
            "http://github.com/block/buzz.git",
            "https://token@github.com/block/buzz.git",
            "https://github.com/block/.git",
            "https://github.com/block/buzz/extra",
            "https://github.com/block%2Fother/buzz.git",
        ] {
            assert!(github_repo(invalid).is_err(), "accepted {invalid}");
        }
        assert!(validate_branch_ref("refs/heads/pr/9", "--source-ref").is_ok());
        for invalid in [
            "main",
            "refs/tags/v1",
            "refs/heads/../main",
            "refs/heads/a:main",
            "refs/heads/a.lock",
        ] {
            assert!(validate_branch_ref(invalid, "--source-ref").is_err());
        }
    }

    fn run(name: &str, status: &str, conclusion: Option<&str>, head: &str) -> CheckRun {
        CheckRun {
            name: name.into(),
            status: status.into(),
            conclusion: conclusion.map(str::to_owned),
            head_sha: head.into(),
            app: CheckApp {
                id: GITHUB_ACTIONS_APP_ID,
            },
        }
    }

    #[test]
    fn exact_required_checks_must_be_unique_completed_and_successful() {
        let head = "a".repeat(40);
        let required = vec!["test".to_owned(), "lint".to_owned()];
        let passing = vec![
            run("test", "completed", Some("success"), &head),
            run("lint", "completed", Some("success"), &head),
            run("unrelated", "completed", Some("failure"), &head),
        ];
        assert!(evaluate_required_checks(&required, &passing, &head).is_ok());

        let missing = &passing[..1];
        assert!(matches!(
            evaluate_required_checks(&required, missing, &head),
            Err(CliError::Conflict(message)) if message.contains("missing")
        ));
        let duplicate = vec![passing[0].clone(), passing[0].clone(), passing[1].clone()];
        assert!(matches!(
            evaluate_required_checks(&required, &duplicate, &head),
            Err(CliError::Conflict(message)) if message.contains("not unique")
        ));
        for bad in [
            run("test", "queued", None, &head),
            run("test", "completed", Some("failure"), &head),
            run("test", "completed", Some("success"), &"b".repeat(40)),
        ] {
            assert!(evaluate_required_checks(&["test".into()], &[bad], &head).is_err());
        }
        let mut untrusted = run("test", "completed", Some("success"), &head);
        untrusted.app.id = 1;
        assert!(evaluate_required_checks(&["test".into()], &[untrusted], &head).is_err());
        assert!(matches!(
            evaluate_required_checks(&["test".into(), "test".into()], &passing, &head),
            Err(CliError::Usage(_))
        ));
    }

    #[test]
    fn partial_success_retry_state_is_narrow() {
        let base = "a".repeat(40);
        let head = "b".repeat(40);
        assert_eq!(
            classify_promote_start(Some(&base), Some(&base), &base, &head).unwrap(),
            PromoteStart::Initial
        );
        assert_eq!(
            classify_promote_start(Some(&head), Some(&base), &base, &head).unwrap(),
            PromoteStart::ResumeAfterBuzzAdvance
        );
        assert!(classify_promote_start(Some(&base), Some(&head), &base, &head).is_err());
        assert!(classify_promote_start(Some(&head), Some(&head), &base, &head).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn github_auth_helper_and_argv_never_contain_the_token() {
        use std::os::unix::fs::PermissionsExt;

        let secret = "fixture-secret-token";
        let repo = GitRepo::new(Fixture::auth(), Fixture::github_auth()).expect("git repo");
        let helper = std::fs::read_to_string(&repo.askpass).expect("read helper");
        assert_eq!(helper, GITHUB_ASKPASS);
        assert!(!helper.contains(secret));
        assert_eq!(
            std::fs::metadata(&repo.askpass)
                .expect("helper metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        let command = repo.command(RemoteAuth::GitHub);
        assert!(!command
            .get_args()
            .any(|argument| argument.to_string_lossy().contains(secret)));
    }
}
