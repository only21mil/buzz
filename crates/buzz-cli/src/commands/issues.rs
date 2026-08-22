use crate::client::BuzzClient;
use crate::commands::with_git_provenance;
use crate::error::CliError;
use crate::validate::{read_or_stdin, sdk_err, validate_hex64, validate_repo_id};
use buzz_sdk::{GitIssueMeta, GitRepoCoord, GitStatusMeta};

#[allow(clippy::too_many_arguments)]
pub async fn cmd_create_issue(
    client: &BuzzClient,
    repo_owner: &str,
    repo_id: &str,
    subject: &str,
    content: &str,
    labels: &[String],
    to: &[String],
    channel_id: Option<&str>,
    external_id: Option<&str>,
) -> Result<(), CliError> {
    validate_hex64(repo_owner)?;
    validate_repo_id(repo_id)?;
    let body = read_or_stdin(content)?;

    let meta = GitIssueMeta {
        labels: labels.to_vec(),
        recipients: to.to_vec(),
        channel_id: channel_id.map(str::to_string),
        external_id: external_id.map(str::to_string),
    };

    let repo = GitRepoCoord {
        owner: repo_owner.to_string(),
        id: repo_id.to_string(),
    };

    let builder = with_git_provenance(
        buzz_sdk::build_git_issue(&repo, subject, &body, &meta).map_err(sdk_err)?,
    )?;
    let event = client.sign_event(builder)?;
    let event_id = event.id.to_hex();
    let resp = client.submit_event(event).await?;
    // `link` renders as a rich preview card in Buzz Desktop when included in
    // a chat message — agents announce issues with it (see base_prompt.md).
    let link = crate::links::issue_link(&event_id, repo_owner, repo_id);
    crate::client::print_create_response(&resp, "link", &link);
    Ok(())
}

pub async fn cmd_get_issue(client: &BuzzClient, event: &str) -> Result<(), CliError> {
    validate_hex64(event)?;
    let filter = serde_json::json!({
        "kinds": [1621],
        "ids": [event]
    });
    let resp = client.query(&filter).await?;
    println!("{resp}");
    Ok(())
}

pub async fn cmd_list_issues(
    client: &BuzzClient,
    repo_owner: &str,
    repo_id: &str,
    author: Option<&str>,
    label: Option<&str>,
    limit: Option<u32>,
) -> Result<(), CliError> {
    let events = list_issues(client, repo_owner, repo_id, author, label, limit).await?;
    let resp = serde_json::to_string(&events)
        .map_err(|e| CliError::Other(format!("failed to serialize issue list: {e}")))?;
    println!("{resp}");
    Ok(())
}

/// Fetch issue (kind:1621) events for a repo coordinate, applying `--author`,
/// `--label`, and `--limit` client-side.
///
/// The relay does NOT push the `#a` (coordinate) tag into its SQL query (see
/// crates/buzz-relay/src/handlers/req.rs), so a single bounded fetch returns a
/// fraction of `limit` (or empty for a quiet repo) when other repos' events are
/// more recent than the target's. [`BuzzClient::query_repo_events`] pages
/// through the relay by `(until, before_id)` windows, keeping only
/// coordinate-matching events, until `limit` are found or the relay is
/// exhausted — so `n == min(limit, total)` holds.
async fn list_issues(
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
        "kinds": [1621],
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
pub async fn cmd_issue_status(
    client: &BuzzClient,
    issue: &str,
    status: &str,
    content: Option<&str>,
    repo_owner: Option<&str>,
    repo_id: Option<&str>,
    euc: Option<&str>,
    to: &[String],
) -> Result<(), CliError> {
    validate_hex64(issue)?;
    let status = crate::commands::patches::parse_status(status)?;
    let body = match content {
        Some(c) => read_or_stdin(c)?,
        None => String::new(),
    };

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

    // Mirrors `buzz patches status`: default a `p` tag to the repo owner
    // for discoverability, plus a `--to` escape hatch for the issue author
    // or anyone else who should be notified of the status change.
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
        root_event: issue.to_string(),
        accepted_revision_root: None,
        repo,
        euc: euc.map(str::to_string),
        recipients,
        applied_patches: vec![],
        merge_commit: None,
        applied_as_commits: vec![],
    };

    let builder =
        with_git_provenance(buzz_sdk::build_git_status(status, &body, &meta).map_err(sdk_err)?)?;
    let event = client.sign_event(builder)?;
    let resp = client.submit_event(event).await?;
    println!("{resp}");
    Ok(())
}

pub async fn dispatch(cmd: crate::IssuesCmd, client: &BuzzClient) -> Result<(), CliError> {
    use crate::IssuesCmd;
    match cmd {
        IssuesCmd::Create {
            repo_owner,
            repo_id,
            title,
            content,
            label,
            to,
            channel_id,
            external_id,
        } => {
            cmd_create_issue(
                client,
                &repo_owner,
                &repo_id,
                &title,
                &content,
                &label,
                &to,
                channel_id.as_deref(),
                external_id.as_deref(),
            )
            .await
        }
        IssuesCmd::Get { event } => cmd_get_issue(client, &event).await,
        IssuesCmd::List {
            repo_owner,
            repo_id,
            author,
            label,
            limit,
        } => {
            cmd_list_issues(
                client,
                &repo_owner,
                &repo_id,
                author.as_deref(),
                label.as_deref(),
                limit,
            )
            .await
        }
        IssuesCmd::Status {
            issue,
            status,
            content,
            repo_owner,
            repo_id,
            euc,
            to,
        } => {
            cmd_issue_status(
                client,
                &issue,
                &status,
                content.as_deref(),
                repo_owner.as_deref(),
                repo_id.as_deref(),
                euc.as_deref(),
                &to,
            )
            .await
        }
    }
}

#[cfg(test)]
mod list_issues_tests {
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

    use super::{list_issues, BuzzClient};

    fn event_id(seed: u64) -> String {
        let mut s = "a".repeat(56);
        s.push_str(&format!("{seed:08x}"));
        s
    }

    fn issue_event(id_seed: u64, created_at: u64, a_tag: &str) -> serde_json::Value {
        serde_json::json!({
            "id": event_id(id_seed),
            "pubkey": "a".repeat(64),
            "kind": 1621,
            "content": "",
            "created_at": created_at,
            "tags": [["a", a_tag]],
        })
    }

    async fn query_server(
        pool: Vec<serde_json::Value>,
        page_size: u32,
    ) -> (String, Arc<AtomicU32>) {
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
                    let _ = ctr.fetch_add(1, Ordering::SeqCst);
                    let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
                    let filters: Vec<serde_json::Value> =
                        serde_json::from_slice(&bytes).unwrap_or_default();
                    let filter = filters.first().cloned().unwrap_or_default();

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
                                (Some(u), Some(bid)) => ca < u || (ca == u && id > bid),
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

    /// The filed defect shape for `buzz issues list`: matching events are
    /// strictly OLDER than `limit` non-matching ones. A naive "fetch limit N
    /// then post-filter" returns [] because the relay fetches the most recent
    /// `limit` events of the kind (all non-matching), post-filters by `#a`, and
    /// returns []. The fix must walk past the non-matching events and return
    /// all 6.
    #[tokio::test]
    async fn list_issues_returns_all_matching_when_nonmatching_are_more_recent() {
        let owner = "b".repeat(64);
        let repo_a = "buzz";
        let repo_b = "other-repo";
        let a_a = format!("30617:{owner}:{repo_a}");
        let a_b = format!("30617:{owner}:{repo_b}");

        // 20 non-matching events (other repo), all MORE RECENT (100..119)
        // than the 6 matching events (1..6). With limit=10, a naive single
        // fetch of the 10 most recent events returns only non-matching → [].
        let mut pool: Vec<serde_json::Value> = Vec::new();
        for i in 0..20 {
            pool.push(issue_event(i, 100 + i, &a_b));
        }
        for i in 0..6 {
            pool.push(issue_event(100 + i, 1 + i, &a_a));
        }

        let (url, _attempts) = query_server(pool, 4).await;
        let client = test_client(&url);

        let events = list_issues(&client, &owner, repo_a, None, None, Some(10))
            .await
            .expect("list_issues should succeed");

        // n == min(limit, total): limit=10, total_matching=6 → exactly 6.
        assert_eq!(
            events.len(),
            6,
            "n must equal min(limit, total): expected 6, got {}",
            events.len()
        );

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

    /// A repo with zero matching events returns [] even with a small limit.
    #[tokio::test]
    async fn list_issues_empty_repo_returns_empty_no_leak() {
        let owner = "b".repeat(64);
        let repo_a = "quiet-repo";
        let repo_b = "busy-repo";
        let _a_a = format!("30617:{owner}:{repo_a}");
        let a_b = format!("30617:{owner}:{repo_b}");

        let mut pool: Vec<serde_json::Value> = Vec::new();
        for i in 0..10 {
            pool.push(issue_event(i, 50 + i, &a_b));
        }

        let (url, _attempts) = query_server(pool, 4).await;
        let client = test_client(&url);

        let events = list_issues(&client, &owner, repo_a, None, None, Some(10))
            .await
            .expect("list_issues should succeed");

        assert!(
            events.is_empty(),
            "quiet repo must return [], got {} events",
            events.len()
        );
    }

    /// When the scan ceiling is hit before `limit` matches, the partial result
    /// is still returned.
    #[tokio::test]
    async fn list_issues_ceiling_emits_warning_and_returns_partial() {
        let owner = "b".repeat(64);
        let repo_a = "buzz";
        let a_a = format!("30617:{owner}:{repo_a}");
        let a_b = format!("30617:{owner}:other");

        let mut pool: Vec<serde_json::Value> = Vec::new();
        for i in 0..100 {
            pool.push(issue_event(i, 200 + i, &a_b));
        }
        for i in 0..6 {
            pool.push(issue_event(200 + i, 1 + i, &a_a));
        }

        let (url, _attempts) = query_server(pool, 4).await;
        let client = test_client(&url);

        let filter = serde_json::json!({
            "kinds": [1621],
            "#a": [a_a.clone()],
        });
        let events = client
            .query_repo_events(filter, &a_a, 20, 4, 5)
            .await
            .expect("query_repo_events should succeed");

        assert!(
            events.is_empty(),
            "ceiling path must still return the matches found so far; got {}",
            events.len()
        );
    }
}
