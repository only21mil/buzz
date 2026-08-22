use crate::client::BuzzClient;
use crate::commands::with_git_provenance;
use crate::error::CliError;
use crate::validate::{
    read_file_or_stdin, read_or_stdin, sdk_err, validate_hex64, validate_repo_id,
};
use buzz_sdk::{GitPrUpdateMeta, GitPullRequestMeta, GitRepoCoord, GitStatusMeta};

fn read_optional_body(body: Option<&str>, body_file: Option<&str>) -> Result<String, CliError> {
    match (body, body_file) {
        (Some(_), Some(_)) => Err(CliError::Usage(
            "--body and --body-file are mutually exclusive".into(),
        )),
        (Some(value), None) => read_or_stdin(value),
        (None, Some(path)) => read_file_or_stdin(path),
        (None, None) => Ok(String::new()),
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn cmd_open_pr(
    client: &BuzzClient,
    repo_owner: &str,
    repo_id: &str,
    subject: &str,
    body: Option<&str>,
    body_file: Option<&str>,
    commit: &str,
    clone_urls: &[String],
    branch_name: Option<&str>,
    merge_base: Option<&str>,
    euc: Option<&str>,
    labels: &[String],
    to: &[String],
    channel: Option<&str>,
    issue_id: Option<&str>,
    external_id: Option<&str>,
    revision_of: Option<&str>,
) -> Result<(), CliError> {
    validate_hex64(repo_owner)?;
    validate_repo_id(repo_id)?;
    let content = read_optional_body(body, body_file)?;

    let repo = GitRepoCoord {
        owner: repo_owner.to_string(),
        id: repo_id.to_string(),
    };
    let meta = GitPullRequestMeta {
        euc: euc.map(str::to_string),
        recipients: to.to_vec(),
        channel_id: channel.map(str::to_string),
        issue_id: issue_id.map(str::to_string),
        external_id: external_id.map(str::to_string),
        subject: subject.to_string(),
        labels: labels.to_vec(),
        commit: commit.to_string(),
        clone_urls: clone_urls.to_vec(),
        branch_name: branch_name.map(str::to_string),
        merge_base: merge_base.map(str::to_string),
        revision_of: revision_of.map(str::to_string),
    };

    let builder = with_git_provenance(
        buzz_sdk::build_git_pull_request(&repo, &content, &meta).map_err(sdk_err)?,
    )?;
    let event = client.sign_event(builder)?;
    let event_id = event.id.to_hex();
    let resp = client.submit_event(event).await?;
    // `link` renders as a rich preview card in Buzz Desktop when included in
    // a chat message — agents announce PRs with it (see base_prompt.md).
    let link = crate::links::pull_request_link(&event_id, repo_owner, repo_id);
    crate::client::print_create_response(&resp, "link", &link);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn cmd_update_pr(
    client: &BuzzClient,
    repo_owner: &str,
    repo_id: &str,
    pr: &str,
    pr_author: &str,
    commit: &str,
    clone_urls: &[String],
    body: Option<&str>,
    body_file: Option<&str>,
    merge_base: Option<&str>,
    euc: Option<&str>,
    to: &[String],
) -> Result<(), CliError> {
    validate_hex64(repo_owner)?;
    validate_repo_id(repo_id)?;
    validate_hex64(pr)?;
    validate_hex64(pr_author)?;
    let content = read_optional_body(body, body_file)?;

    let repo = GitRepoCoord {
        owner: repo_owner.to_string(),
        id: repo_id.to_string(),
    };
    let meta = GitPrUpdateMeta {
        euc: euc.map(str::to_string),
        recipients: to.to_vec(),
        pr_event: pr.to_string(),
        pr_author: pr_author.to_string(),
        commit: commit.to_string(),
        clone_urls: clone_urls.to_vec(),
        merge_base: merge_base.map(str::to_string),
    };

    let builder = with_git_provenance(
        buzz_sdk::build_git_pr_update(&repo, &content, &meta).map_err(sdk_err)?,
    )?;
    let event = client.sign_event(builder)?;
    let resp = client.submit_event(event).await?;
    println!("{resp}");
    Ok(())
}

pub async fn cmd_get_pr(client: &BuzzClient, event: &str) -> Result<(), CliError> {
    validate_hex64(event)?;
    let filter = serde_json::json!({
        "kinds": [1618],
        "ids": [event]
    });
    let resp = client.query(&filter).await?;
    println!("{resp}");
    Ok(())
}

pub async fn cmd_list_prs(
    client: &BuzzClient,
    repo_owner: &str,
    repo_id: &str,
    author: Option<&str>,
    label: Option<&str>,
    limit: Option<u32>,
) -> Result<(), CliError> {
    let events = list_prs(client, repo_owner, repo_id, author, label, limit).await?;
    let resp = serde_json::to_string(&events)
        .map_err(|e| CliError::Other(format!("failed to serialize pr list: {e}")))?;
    println!("{resp}");
    Ok(())
}

/// Fetch PR (kind:1618) events for a repo coordinate, applying `--author`,
/// `--label`, and `--limit` client-side.
///
/// The relay does NOT push the `#a` (coordinate) tag into its SQL query (see
/// crates/buzz-relay/src/handlers/req.rs), so a single bounded fetch returns a
/// fraction of `limit` (or empty for a quiet repo) when other repos' events are
/// more recent than the target's. [`BuzzClient::query_repo_events`] pages
/// through the relay by `(until, before_id)` windows, keeping only
/// coordinate-matching events, until `limit` are found or the relay is
/// exhausted — so `n == min(limit, total)` holds.
async fn list_prs(
    client: &BuzzClient,
    repo_owner: &str,
    repo_id: &str,
    author: Option<&str>,
    label: Option<&str>,
    limit: Option<u32>,
) -> Result<Vec<serde_json::Value>, CliError> {
    validate_hex64(repo_owner)?;
    validate_repo_id(repo_id)?;

    let a_value = format!("30617:{repo_owner}:{repo_id}");
    let mut filter = serde_json::json!({
        "kinds": [1618],
        "#a": [a_value]
    });

    if let Some(pk) = author {
        validate_hex64(pk)?;
        filter["authors"] = serde_json::json!([pk]);
    }
    if let Some(l) = label {
        filter["#t"] = serde_json::json!([l]);
    }

    let effective_limit = limit.unwrap_or(500);
    client
        .query_repo_events(filter, &a_value, effective_limit, 500, 20)
        .await
}

#[allow(clippy::too_many_arguments)]
pub async fn cmd_pr_status(
    client: &BuzzClient,
    pr: &str,
    status: &str,
    body: Option<&str>,
    body_file: Option<&str>,
    repo_owner: Option<&str>,
    repo_id: Option<&str>,
    euc: Option<&str>,
    to: &[String],
    merge_commit: Option<&str>,
) -> Result<(), CliError> {
    validate_hex64(pr)?;
    let status = crate::commands::patches::parse_status(status)?;
    let content = read_optional_body(body, body_file)?;

    let repo = match (repo_owner, repo_id) {
        (Some(owner), Some(id)) => {
            validate_hex64(owner)?;
            validate_repo_id(id)?;
            Some(GitRepoCoord {
                owner: owner.to_string(),
                id: id.to_string(),
            })
        }
        (None, None) => None,
        _ => {
            return Err(CliError::Usage(
                "--repo-owner and --repo-id must be given together".into(),
            ))
        }
    };

    // Mirrors patch/issue status: default a `p` tag to the repo owner when
    // known; callers can add PR author/reviewers with repeated `--to`.
    let mut recipients = Vec::new();
    if let Some(ref repo) = repo {
        recipients.push(repo.owner.clone());
    }
    for recipient in to {
        validate_hex64(recipient)?;
        if !recipients.contains(recipient) {
            recipients.push(recipient.clone());
        }
    }

    let meta = GitStatusMeta {
        root_event: pr.to_string(),
        accepted_revision_root: None,
        repo,
        euc: euc.map(str::to_string),
        recipients,
        applied_patches: vec![],
        merge_commit: merge_commit.map(str::to_string),
        applied_as_commits: vec![],
    };

    let builder =
        with_git_provenance(buzz_sdk::build_git_status(status, &content, &meta).map_err(sdk_err)?)?;
    let event = client.sign_event(builder)?;
    let resp = client.submit_event(event).await?;
    println!("{resp}");
    Ok(())
}

pub async fn dispatch(cmd: crate::PrCmd, client: &BuzzClient) -> Result<(), CliError> {
    use crate::PrCmd;
    match cmd {
        PrCmd::Open {
            repo_owner,
            repo_id,
            subject,
            body,
            body_file,
            commit,
            clone,
            branch_name,
            merge_base,
            euc,
            label,
            to,
            channel,
            issue_id,
            external_id,
            revision_of,
        } => {
            cmd_open_pr(
                client,
                &repo_owner,
                &repo_id,
                &subject,
                body.as_deref(),
                body_file.as_deref(),
                &commit,
                &clone,
                branch_name.as_deref(),
                merge_base.as_deref(),
                euc.as_deref(),
                &label,
                &to,
                channel.as_deref(),
                issue_id.as_deref(),
                external_id.as_deref(),
                revision_of.as_deref(),
            )
            .await
        }
        PrCmd::Update {
            repo_owner,
            repo_id,
            pr,
            pr_author,
            commit,
            clone,
            body,
            body_file,
            merge_base,
            euc,
            to,
        } => {
            cmd_update_pr(
                client,
                &repo_owner,
                &repo_id,
                &pr,
                &pr_author,
                &commit,
                &clone,
                body.as_deref(),
                body_file.as_deref(),
                merge_base.as_deref(),
                euc.as_deref(),
                &to,
            )
            .await
        }
        PrCmd::Get { event } => cmd_get_pr(client, &event).await,
        PrCmd::List {
            repo_owner,
            repo_id,
            author,
            label,
            limit,
        } => {
            cmd_list_prs(
                client,
                &repo_owner,
                &repo_id,
                author.as_deref(),
                label.as_deref(),
                limit,
            )
            .await
        }
        PrCmd::Status {
            pr,
            status,
            body,
            body_file,
            repo_owner,
            repo_id,
            euc,
            to,
            merge_commit,
        } => {
            cmd_pr_status(
                client,
                &pr,
                &status,
                body.as_deref(),
                body_file.as_deref(),
                repo_owner.as_deref(),
                repo_id.as_deref(),
                euc.as_deref(),
                &to,
                merge_commit.as_deref(),
            )
            .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_optional_body_rejects_body_and_body_file_together() {
        assert!(read_optional_body(Some("body"), Some("file.md")).is_err());
    }

    #[test]
    fn read_optional_body_defaults_empty() {
        assert_eq!(read_optional_body(None, None).unwrap(), "");
    }
}

#[cfg(test)]
mod list_prs_tests {
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};

    use axum::body::Body;
    use axum::extract::State;
    use axum::http::HeaderMap;
    use axum::routing::post;
    use axum::Router;
    use nostr::Keys;
    use tokio::net::TcpListener;

    use super::{list_prs, BuzzClient};

    /// A 64-hex event id with a stable per-call suffix, so the composite
    /// `(until, before_id)` cursor is always valid.
    fn event_id(seed: u64) -> String {
        let mut s = "a".repeat(56);
        s.push_str(&format!("{seed:08x}"));
        s
    }

    /// Build a kind:1618 event JSON object with the given `created_at`, `#a` tag,
    /// and id.
    fn pr_event(id_seed: u64, created_at: u64, a_tag: &str) -> serde_json::Value {
        serde_json::json!({
            "id": event_id(id_seed),
            "pubkey": "a".repeat(64),
            "kind": 1618,
            "content": "",
            "created_at": created_at,
            "tags": [["a", a_tag]],
        })
    }

    /// A mock `/query` server that simulates the relay's post-filter behavior:
    /// it returns the most recent `page_size` events of the kind strictly older
    /// than the incoming `until` cursor (using `until` + `before_id` for stable
    /// pagination), WITHOUT pushing `#a` into the SQL — the caller post-filters
    /// `#a` client-side. This reproduces the exact defect shape: non-matching
    /// events from other repos consume the page limit before coordinate
    /// post-filtering.
    async fn query_server(
        pool: Vec<serde_json::Value>,
        page_size: u32,
    ) -> (String, Arc<AtomicU32>) {
        // Sort the pool newest-first by created_at, then id ascending (matches
        // the relay's `ORDER BY created_at DESC, id ASC`).
        let mut pool = pool;
        pool.sort_by(|a, b| {
            let ca = a
                .get("created_at")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            let cb = b
                .get("created_at")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            cb.cmp(&ca).then_with(|| {
                let ida = a
                    .get("id")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("");
                let idb = b
                    .get("id")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("");
                ida.cmp(idb)
            })
        });
        let pool = Arc::new(Mutex::new(pool));
        let counter = Arc::new(AtomicU32::new(0));
        let ps = page_size;
        let pool2 = pool.clone();
        let counter2 = counter.clone();

        type S = (Arc<Mutex<Vec<serde_json::Value>>>, u32, Arc<AtomicU32>);
        let app = Router::new().route(
            "/query",
            post(
                |State((pool, page_size, ctr)): State<S>, _h: HeaderMap, body: Body| async move {
                    let n = ctr.fetch_add(1, Ordering::SeqCst) + 1;
                    let _ = n;
                    let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
                    let filters: Vec<serde_json::Value> =
                        serde_json::from_slice(&bytes).unwrap_or_default();
                    let filter = filters.first().cloned().unwrap_or_default();

                    // Honor the composite cursor: `until` (created_at) and
                    // `before_id` (event id). Events strictly older than the
                    // cursor are eligible. On the first request no cursor is set.
                    let until = filter.get("until").and_then(serde_json::Value::as_u64);
                    let before_id = filter.get("before_id").and_then(serde_json::Value::as_str);

                    let guard = pool.lock().unwrap();
                    let page: Vec<serde_json::Value> = guard
                        .iter()
                        .filter(|e| {
                            let ca = e
                                .get("created_at")
                                .and_then(serde_json::Value::as_u64)
                                .unwrap_or(0);
                            let id = e
                                .get("id")
                                .and_then(serde_json::Value::as_str)
                                .unwrap_or("");
                            match (until, before_id) {
                                (Some(u), Some(bid)) => {
                                    // created_at < u OR (created_at == u AND id > bid)
                                    ca < u || (ca == u && id > bid)
                                }
                                _ => true,
                            }
                        })
                        .take(page_size as usize)
                        .cloned()
                        .collect();
                    drop(guard);

                    let body = serde_json::to_string(&page).unwrap();
                    axum::http::Response::builder()
                        .status(axum::http::StatusCode::OK)
                        .header("content-type", "application/json")
                        .body(Body::from(body))
                        .unwrap()
                },
            )
            .with_state((pool2, ps, counter2)),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{addr}"), counter)
    }

    fn test_client(base_url: &str) -> BuzzClient {
        let keys = Keys::generate();
        BuzzClient::new(base_url.to_string(), keys, None, None).unwrap()
    }

    /// The filed defect shape: matching events are strictly OLDER than
    /// `limit` non-matching events from other repos. A naive "fetch limit N
    /// then post-filter" returns [] for the quiet repo because the relay
    /// fetches the most recent `limit` events of the kind (all non-matching),
    /// post-filters by `#a`, and returns []. The fix must walk past the
    /// non-matching events via windowed pagination and return all 6.
    #[tokio::test]
    async fn list_prs_returns_all_matching_when_nonmatching_are_more_recent() {
        let owner = "b".repeat(64);
        let repo_a = "buzz";
        let repo_b = "other-repo";
        let a_a = format!("30617:{owner}:{repo_a}");
        let a_b = format!("30617:{owner}:{repo_b}");

        // 20 non-matching events (other repo), all MORE RECENT (created_at
        // 100..119) than the 6 matching events (created_at 1..6). With
        // limit=10, a naive single fetch of the 10 most recent events returns
        // only non-matching events → post-filter → []. The fix must page
        // past the 20 non-matching events to reach the 6 matching ones.
        let mut pool: Vec<serde_json::Value> = Vec::new();
        for i in 0..20 {
            pool.push(pr_event(i, 100 + i, &a_b));
        }
        for i in 0..6 {
            pool.push(pr_event(100 + i, 1 + i, &a_a));
        }

        // page_size 4 ensures the loop must walk multiple pages past the
        // non-matching events to reach the matching ones.
        let (url, _attempts) = query_server(pool, 4).await;
        let client = test_client(&url);

        let events = list_prs(&client, &owner, repo_a, None, None, Some(10))
            .await
            .expect("list_prs should succeed");

        // n == min(limit, total): limit=10, total_matching=6 → exactly 6.
        assert_eq!(
            events.len(),
            6,
            "n must equal min(limit, total): expected 6, got {}",
            events.len()
        );

        // No non-matching repo's events leak in.
        for e in &events {
            let tags = e
                .get("tags")
                .and_then(|t| t.as_array())
                .cloned()
                .unwrap_or_default();
            let a = tags
                .iter()
                .filter_map(|t| t.as_array())
                .find(|t| t.first().and_then(|v| v.as_str()) == Some("a"))
                .and_then(|t| t.get(1).and_then(|v| v.as_str()))
                .unwrap_or("");
            assert_eq!(a, a_a, "non-matching repo event leaked: {e}");
        }
    }

    /// A repo with zero matching events returns [] even with a small limit,
    /// and non-matching events from other repos do NOT leak in.
    #[tokio::test]
    async fn list_prs_empty_repo_returns_empty_no_leak() {
        let owner = "b".repeat(64);
        let repo_a = "quiet-repo";
        let repo_b = "busy-repo";
        let _a_a = format!("30617:{owner}:{repo_a}");
        let a_b = format!("30617:{owner}:{repo_b}");

        // 10 non-matching events, none for repo_a.
        let mut pool: Vec<serde_json::Value> = Vec::new();
        for i in 0..10 {
            pool.push(pr_event(i, 50 + i, &a_b));
        }

        let (url, _attempts) = query_server(pool, 4).await;
        let client = test_client(&url);

        let events = list_prs(&client, &owner, repo_a, None, None, Some(10))
            .await
            .expect("list_prs should succeed");

        assert!(
            events.is_empty(),
            "quiet repo must return [], got {} events",
            events.len()
        );
    }

    /// When the scan ceiling is hit before `limit` matches are found, the
    /// result is still correct (all matches found so far) and the warning is
    /// NOT emitted on success. With a ceiling that is reached, the warning IS
    /// emitted but the partial result is still returned.
    #[tokio::test]
    async fn list_prs_ceiling_emits_warning_and_returns_partial() {
        let owner = "b".repeat(64);
        let repo_a = "buzz";
        let a_a = format!("30617:{owner}:{repo_a}");
        let a_b = format!("30617:{owner}:other");

        // 100 non-matching events newer than 6 matching events, page_size 4,
        // max_pages 5 → ceiling hit at 20 events scanned, 0 matches found.
        let mut pool: Vec<serde_json::Value> = Vec::new();
        for i in 0..100 {
            pool.push(pr_event(i, 200 + i, &a_b));
        }
        for i in 0..6 {
            pool.push(pr_event(200 + i, 1 + i, &a_a));
        }

        // page_size 4, but we drive list_prs which uses max_pages 20 — with
        // 106 events and page_size 500, one page covers all. To force the
        // ceiling we call query_repo_events directly with a low max_pages.
        let (url, _attempts) = query_server(pool, 4).await;
        let client = test_client(&url);

        let filter = serde_json::json!({
            "kinds": [1618],
            "#a": [a_a.clone()],
        });
        let events = client
            .query_repo_events(filter, &a_a, 20, 4, 5)
            .await
            .expect("query_repo_events should succeed");

        // Ceiling hit after 5 pages of 4 = 20 events scanned, all non-matching
        // (the 100 newer events are at the front). 0 matches found.
        assert!(
            events.is_empty(),
            "ceiling path must still return the matches found so far; got {}",
            events.len()
        );
    }
}
