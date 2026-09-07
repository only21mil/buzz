use serde::Serialize;
use serde_json::Value;

use crate::client::BuzzClient;
use crate::error::CliError;
use crate::validate::validate_hex64;

const MAX_STATUS_EVENTS: u32 = 10_000;
const STATUS_KINDS: [u32; 4] = [1630, 1631, 1632, 1633];

pub async fn fetch_event(client: &BuzzClient, event_id: &str) -> Result<Value, CliError> {
    validate_hex64(event_id)?;
    let raw = client
        .query(&serde_json::json!({"ids": [event_id], "limit": 1}))
        .await?;
    let mut events: Vec<Value> = serde_json::from_str(&raw)
        .map_err(|error| CliError::Other(format!("failed to parse event response: {error}")))?;
    events
        .pop()
        .ok_or_else(|| CliError::NotFound(format!("event not found: {event_id}")))
}

pub async fn cmd_get_event(client: &BuzzClient, event_id: &str) -> Result<(), CliError> {
    let event = fetch_event(client, event_id).await?;
    let output = serde_json::to_string(&event)
        .map_err(|error| CliError::Other(format!("failed to serialize event: {error}")))?;
    println!("{output}");
    Ok(())
}

#[derive(Debug, Serialize)]
struct StatusView {
    event: Value,
    signer: String,
    trusted: bool,
}

fn repo_owner(root: &Value) -> Option<String> {
    root.get("tags")?
        .as_array()?
        .iter()
        .filter_map(Value::as_array)
        .find_map(|tag| {
            if tag.first().and_then(Value::as_str) != Some("a") {
                return None;
            }
            let address = tag.get(1)?.as_str()?;
            let mut parts = address.splitn(3, ':');
            let _kind = parts.next()?;
            let owner = parts.next()?;
            let _identifier = parts.next()?;
            (owner.len() == 64 && owner.chars().all(|ch| ch.is_ascii_hexdigit()))
                .then(|| owner.to_ascii_lowercase())
        })
}

fn annotate_statuses(root: &Value, statuses: Vec<Value>) -> Vec<StatusView> {
    let root_author = root
        .get("pubkey")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let owner = repo_owner(root);

    statuses
        .into_iter()
        .map(|event| {
            let signer = event
                .get("pubkey")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_ascii_lowercase();
            let trusted = signer == root_author || owner.as_ref() == Some(&signer);
            StatusView {
                event,
                signer,
                trusted,
            }
        })
        .collect()
}

async fn list_statuses(
    client: &BuzzClient,
    root_id: &str,
    expected_root_kind: u32,
    root_label: &str,
) -> Result<Vec<StatusView>, CliError> {
    let root = fetch_event(client, root_id).await?;
    if root.get("kind").and_then(Value::as_u64) != Some(expected_root_kind as u64) {
        return Err(CliError::Usage(format!(
            "event {root_id} is not a {root_label} root"
        )));
    }

    let statuses = client
        .query_all_bounded(
            serde_json::json!({"kinds": STATUS_KINDS, "#e": [root_id]}),
            MAX_STATUS_EVENTS,
        )
        .await?;
    Ok(annotate_statuses(&root, statuses))
}

pub async fn cmd_list_statuses(
    client: &BuzzClient,
    root_id: &str,
    expected_root_kind: u32,
    root_label: &str,
) -> Result<(), CliError> {
    let statuses = list_statuses(client, root_id, expected_root_kind, root_label).await?;
    let output = serde_json::to_string(&statuses)
        .map_err(|error| CliError::Other(format!("failed to serialize statuses: {error}")))?;
    println!("{output}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    use axum::{extract::State, routing::post, Json, Router};
    use nostr::Keys;
    use tokio::net::TcpListener;

    use super::*;

    #[derive(Clone)]
    struct QueryState {
        root: Value,
        statuses: Vec<Value>,
        filters: Arc<Mutex<Vec<Value>>>,
    }

    async fn query_handler(
        State(state): State<QueryState>,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        state
            .filters
            .lock()
            .expect("query capture lock")
            .push(body.clone());
        let filter = body
            .as_array()
            .and_then(|filters| filters.first())
            .cloned()
            .unwrap_or_default();
        if filter.get("ids").is_some() {
            if state.root.is_null() {
                Json(Value::Array(Vec::new()))
            } else {
                Json(serde_json::json!([state.root]))
            }
        } else {
            Json(Value::Array(state.statuses))
        }
    }

    async fn query_server(root: Value, statuses: Vec<Value>) -> (String, Arc<Mutex<Vec<Value>>>) {
        let filters = Arc::new(Mutex::new(Vec::new()));
        let state = QueryState {
            root,
            statuses,
            filters: filters.clone(),
        };
        let app = Router::new()
            .route("/query", post(query_handler))
            .with_state(state);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address: SocketAddr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{address}"), filters)
    }

    fn test_client(url: String) -> BuzzClient {
        BuzzClient::new(url, Keys::generate(), None, None).unwrap()
    }

    #[test]
    fn status_trust_accepts_only_root_author_and_repo_owner() {
        let author = "a".repeat(64);
        let owner = "b".repeat(64);
        let outsider = "c".repeat(64);
        let root = serde_json::json!({
            "pubkey": author,
            "tags": [["a", format!("30617:{owner}:buzz")]]
        });
        let statuses = vec![
            serde_json::json!({"id": "1".repeat(64), "pubkey": author}),
            serde_json::json!({"id": "2".repeat(64), "pubkey": owner}),
            serde_json::json!({"id": "3".repeat(64), "pubkey": outsider}),
        ];

        let annotated = annotate_statuses(&root, statuses);
        assert!(annotated[0].trusted);
        assert!(annotated[1].trusted);
        assert!(!annotated[2].trusted);
        assert_eq!(annotated[2].signer, outsider);
    }

    #[tokio::test]
    async fn event_lookup_returns_the_exact_signed_event() {
        let id = "d".repeat(64);
        let event = serde_json::json!({
            "id": id,
            "pubkey": "a".repeat(64),
            "kind": 1631,
            "content": "resolved",
            "created_at": 42,
            "tags": [["e", "b".repeat(64), "", "root"]],
            "sig": "c".repeat(128)
        });
        let (url, filters) = query_server(event.clone(), Vec::new()).await;

        let fetched = fetch_event(&test_client(url), &id).await.unwrap();

        assert_eq!(fetched, event);
        assert_eq!(
            filters.lock().unwrap()[0][0],
            serde_json::json!({"ids": [id], "limit": 1})
        );
    }

    #[tokio::test]
    async fn event_lookup_reports_not_found() {
        let id = "d".repeat(64);
        let (url, _) = query_server(Value::Null, Vec::new()).await;
        let error = fetch_event(&test_client(url), &id).await.unwrap_err();
        assert!(matches!(error, CliError::NotFound(_)));
    }

    #[tokio::test]
    async fn statuses_query_all_lifecycle_kinds_and_annotate_trust() {
        let root_id = "d".repeat(64);
        let author = "a".repeat(64);
        let owner = "b".repeat(64);
        let outsider = "c".repeat(64);
        let root = serde_json::json!({
            "id": root_id,
            "pubkey": author,
            "kind": 1621,
            "tags": [["a", format!("30617:{owner}:buzz")]],
            "sig": "e".repeat(128)
        });
        let statuses = vec![
            serde_json::json!({"id": "1".repeat(64), "pubkey": owner, "kind": 1631}),
            serde_json::json!({"id": "2".repeat(64), "pubkey": outsider, "kind": 1632}),
        ];
        let (url, filters) = query_server(root, statuses).await;

        let result = list_statuses(&test_client(url), &root_id, 1621, "issue")
            .await
            .unwrap();

        assert_eq!(result.len(), 2);
        assert!(result[0].trusted);
        assert!(!result[1].trusted);
        let filters = filters.lock().unwrap();
        assert_eq!(filters[1][0]["kinds"], serde_json::json!(STATUS_KINDS));
        assert_eq!(filters[1][0]["#e"], serde_json::json!([root_id]));
    }
}
