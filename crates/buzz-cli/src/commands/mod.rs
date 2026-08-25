pub mod agents;
pub mod channel_templates;
pub mod channels;
pub mod ci;
pub mod dms;
pub mod emoji;
pub mod feed;
pub mod issues;
pub mod mem;
pub mod messages;
pub mod moderation;
pub mod notes;
pub mod pack;
pub mod patches;
pub mod pr;
pub mod projects;
pub mod reactions;
pub mod repo_sync;
pub mod repos;
pub mod social;
pub mod upload;
pub mod users;
pub mod workflows;

use crate::{
    client::{normalize_write_response, BuzzClient},
    error::CliError,
};
use nostr::{EventBuilder, Tag};
use serde_json::Value;

const REPO_QUERY_PAGE_SIZE: u32 = 1_000;
const REPO_QUERY_MAX_PAGES: u32 = 20;

const GIT_ORIGIN_CHANNEL_ENV: &str = "BUZZ_GIT_ORIGIN_CHANNEL_ID";
const GIT_ORIGIN_AGENT_ENV: &str = "BUZZ_GIT_ORIGIN_AGENT_NAME";

/// Add trusted, session-scoped provenance supplied by the ACP harness.
///
/// Public channels use the standard NIP-29 `h` tag. Private conversations
/// intentionally omit their channel coordinate and retain only the agent's
/// display name.
pub(crate) fn with_git_provenance(builder: EventBuilder) -> Result<EventBuilder, CliError> {
    apply_git_provenance(
        builder,
        std::env::var(GIT_ORIGIN_CHANNEL_ENV).ok().as_deref(),
        std::env::var(GIT_ORIGIN_AGENT_ENV).ok().as_deref(),
    )
}

fn apply_git_provenance(
    builder: EventBuilder,
    channel_id: Option<&str>,
    agent_name: Option<&str>,
) -> Result<EventBuilder, CliError> {
    if let Some(channel_id) = channel_id {
        let channel_id = channel_id.trim();
        uuid::Uuid::parse_str(channel_id)
            .map_err(|_| CliError::Other("invalid git origin channel ID".into()))?;
        let origin_tag = Tag::parse(["h", channel_id])
            .map_err(|error| CliError::Other(format!("invalid git origin tag: {error}")))?;
        return Ok(builder.tag(origin_tag));
    }

    if let Some(agent_name) = agent_name {
        let agent_name = agent_name.trim();
        if agent_name.is_empty()
            || agent_name.len() > 256
            || agent_name.chars().any(char::is_control)
        {
            return Err(CliError::Other(
                "invalid private-conversation agent name".into(),
            ));
        }
        let origin_tag = Tag::parse(["buzz-origin-agent", agent_name])
            .map_err(|error| CliError::Other(format!("invalid git origin tag: {error}")))?;
        return Ok(builder.tag(origin_tag));
    }

    Ok(builder)
}

/// Query repo-scoped Git events without letting relay-side post-filtering
/// consume the user's result limit.
///
/// The relay cannot push generic `#a` or `#t` tags into SQL. Sending either
/// tag with a small limit can therefore return an empty page even when older
/// matching events exist. Keep only SQL-pushable predicates in the relay
/// filter, walk full `(created_at, id)` pages, then apply the repo and label
/// predicates before truncating to the requested result count.
pub(crate) async fn query_repo_events(
    client: &BuzzClient,
    mut filter: Value,
    repo_coordinate: &str,
    label: Option<&str>,
    limit: Option<u32>,
) -> Result<Vec<Value>, CliError> {
    // No query is needed for the NIP-01 limit-zero case.
    let result_limit = limit.unwrap_or(REPO_QUERY_PAGE_SIZE);
    if result_limit == 0 {
        return Ok(Vec::new());
    }

    let filter_object = filter
        .as_object_mut()
        .ok_or_else(|| CliError::Other("repo query filter must be a JSON object".into()))?;
    // These are deliberately local predicates. Leaving them in the request
    // causes the relay to post-filter after applying its SQL LIMIT.
    filter_object.remove("#a");
    filter_object.remove("#t");

    let mut matches = Vec::new();
    for page_number in 1..=REPO_QUERY_MAX_PAGES {
        filter["limit"] = serde_json::json!(REPO_QUERY_PAGE_SIZE);

        let raw = client.query(&filter).await?;
        let page: Vec<Value> = serde_json::from_str(&raw)
            .map_err(|e| CliError::Other(format!("failed to parse query response: {e}")))?;

        if page.is_empty() {
            break;
        }

        for event in &page {
            if event_has_tag(event, "a", repo_coordinate)
                && label.is_none_or(|wanted| event_has_tag(event, "t", wanted))
            {
                matches.push(event.clone());
                if matches.len() >= result_limit as usize {
                    break;
                }
            }
        }

        if matches.len() >= result_limit as usize {
            break;
        }

        // Because #a/#t are absent from the relay request, a short page is a
        // real end-of-data signal. A full page needs a composite cursor.
        if page.len() < REPO_QUERY_PAGE_SIZE as usize {
            break;
        }
        if page_number == REPO_QUERY_MAX_PAGES {
            return Err(CliError::Other(format!(
                "repo query exceeded the bounded scan of {} events",
                REPO_QUERY_PAGE_SIZE as u64 * REPO_QUERY_MAX_PAGES as u64
            )));
        }
        advance_repo_query_cursor(&mut filter, &page)?;
    }

    matches.truncate(result_limit as usize);
    Ok(matches)
}

fn event_has_tag(event: &Value, name: &str, wanted: &str) -> bool {
    event
        .get("tags")
        .and_then(Value::as_array)
        .is_some_and(|tags| {
            tags.iter().any(|tag| {
                let Some(tag) = tag.as_array() else {
                    return false;
                };
                tag.first().and_then(Value::as_str) == Some(name)
                    && tag.get(1).and_then(Value::as_str) == Some(wanted)
            })
        })
}

fn advance_repo_query_cursor(filter: &mut Value, page: &[Value]) -> Result<(), CliError> {
    let last = page
        .last()
        .ok_or_else(|| CliError::Other("cannot advance an empty repo query page".into()))?;
    let created_at = last
        .get("created_at")
        .and_then(Value::as_u64)
        .ok_or_else(|| CliError::Other("query event missing created_at".into()))?;
    let id = last
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit()))
        .ok_or_else(|| CliError::Other("query event missing valid id".into()))?;
    filter["until"] = serde_json::json!(created_at);
    filter["before_id"] = serde_json::json!(id);
    Ok(())
}

/// Parse a relay write-response JSON blob, mapping a duplicate (dominated)
/// write to [`CliError::Conflict`] with the caller-supplied message.
///
/// Used by every command that publishes an NIP-33 addressable event and
/// needs to tell accepted from duplicate/dominated.
pub fn parse_write_response(raw: &str, conflict_msg: &str) -> Result<String, CliError> {
    let response: serde_json::Value = serde_json::from_str(raw)
        .map_err(|e| CliError::Other(format!("relay response is not JSON: {e} ({raw})")))?;
    let accepted = response
        .get("accepted")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let message = response
        .get("message")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if !accepted {
        return Err(CliError::Other(format!("relay rejected event: {message}")));
    }
    if message == "duplicate" || message.starts_with("duplicate:") {
        return Err(CliError::Conflict(conflict_msg.to_string()));
    }
    Ok(normalize_write_response(raw))
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    use super::*;
    use axum::extract::State;
    use axum::routing::post;
    use axum::{Json, Router};
    use nostr::{Keys, Kind};
    use tokio::net::TcpListener;

    fn event_with_origin(channel_id: Option<&str>, agent_name: Option<&str>) -> nostr::Event {
        apply_git_provenance(
            EventBuilder::new(Kind::Custom(1621), "issue"),
            channel_id,
            agent_name,
        )
        .expect("apply provenance")
        .sign_with_keys(&Keys::generate())
        .expect("sign event")
    }

    #[test]
    fn public_channel_origin_uses_h_tag_and_suppresses_agent_name() {
        let channel_id = "9a1657ac-f7aa-5db0-b632-d8bbeb6dfb50";
        let event = event_with_origin(Some(channel_id), Some("Builder"));
        assert!(event
            .tags
            .iter()
            .any(|tag| tag.as_slice() == ["h", channel_id]));
        assert!(!event
            .tags
            .iter()
            .any(|tag| tag.as_slice().first().map(String::as_str) == Some("buzz-origin-agent")));
    }

    #[test]
    fn private_origin_exposes_only_agent_name() {
        let event = event_with_origin(None, Some("Builder"));
        assert!(event
            .tags
            .iter()
            .any(|tag| tag.as_slice() == ["buzz-origin-agent", "Builder"]));
        assert!(!event
            .tags
            .iter()
            .any(|tag| tag.as_slice().first().map(String::as_str) == Some("h")));
    }

    fn query_event(seed: u64, created_at: u64, repo: &str, label: Option<&str>) -> Value {
        let mut tags = vec![serde_json::json!(["a", repo])];
        if let Some(label) = label {
            tags.push(serde_json::json!(["t", label]));
        }
        serde_json::json!({
            "id": format!("{seed:064x}"),
            "created_at": created_at,
            "tags": tags,
        })
    }

    fn sort_query_events(events: &mut [Value]) {
        events.sort_by(|left, right| {
            let left_created_at = left.get("created_at").and_then(Value::as_u64).unwrap_or(0);
            let right_created_at = right.get("created_at").and_then(Value::as_u64).unwrap_or(0);
            right_created_at.cmp(&left_created_at).then_with(|| {
                left.get("id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .cmp(right.get("id").and_then(Value::as_str).unwrap_or(""))
            })
        });
    }

    #[derive(Clone)]
    struct QueryState {
        events: Arc<Vec<Value>>,
        saw_unfiltered_request: Arc<AtomicBool>,
    }

    async fn query_handler(
        State(state): State<QueryState>,
        Json(filters): Json<Vec<Value>>,
    ) -> Json<Value> {
        let filter = filters.first().cloned().unwrap_or_default();
        if filter.get("#a").is_none() && filter.get("#t").is_none() {
            state.saw_unfiltered_request.store(true, Ordering::SeqCst);
        }

        let limit = filter
            .get("limit")
            .and_then(Value::as_u64)
            .unwrap_or(REPO_QUERY_PAGE_SIZE as u64) as usize;
        let until = filter.get("until").and_then(Value::as_u64);
        let before_id = filter.get("before_id").and_then(Value::as_str);
        let page = state
            .events
            .iter()
            .filter(|event| {
                let created_at = event.get("created_at").and_then(Value::as_u64).unwrap_or(0);
                let id = event.get("id").and_then(Value::as_str).unwrap_or("");
                match (until, before_id) {
                    (Some(until), Some(before_id)) => {
                        created_at < until || (created_at == until && id > before_id)
                    }
                    _ => true,
                }
            })
            .take(limit)
            .cloned()
            .collect();
        Json(Value::Array(page))
    }

    async fn query_server(mut events: Vec<Value>) -> (String, Arc<AtomicBool>) {
        sort_query_events(&mut events);
        let saw_unfiltered_request = Arc::new(AtomicBool::new(false));
        let state = QueryState {
            events: Arc::new(events),
            saw_unfiltered_request: saw_unfiltered_request.clone(),
        };
        let app = Router::new()
            .route("/query", post(query_handler))
            .with_state(state);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address: SocketAddr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{address}"), saw_unfiltered_request)
    }

    fn test_client(url: &str) -> BuzzClient {
        BuzzClient::new(url.to_string(), Keys::generate(), None, None).unwrap()
    }

    #[tokio::test]
    async fn repo_limit_finds_quiet_repo_after_newer_foreign_events() {
        let owner = "a".repeat(64);
        let coordinate = format!("30617:{owner}:quiet-repo");
        let foreign = format!("30617:{owner}:busy-repo");
        let mut events = Vec::new();
        for seed in 0..1_200 {
            events.push(query_event(seed, 2_000 + seed, &foreign, None));
        }
        for seed in 0..6 {
            events.push(query_event(2_000 + seed, 100 + seed, &coordinate, None));
        }

        let (url, saw_unfiltered_request) = query_server(events).await;
        let client = test_client(&url);
        let result = query_repo_events(
            &client,
            serde_json::json!({
                "kinds": [1618],
                "#a": [coordinate.clone()],
                "#t": ["ignored-by-relay"],
            }),
            &coordinate,
            None,
            Some(10),
        )
        .await
        .unwrap();

        assert_eq!(result.len(), 6);
        assert_eq!(
            result
                .iter()
                .filter_map(|event| event.get("created_at").and_then(Value::as_u64))
                .collect::<Vec<_>>(),
            vec![105, 104, 103, 102, 101, 100]
        );

        let unbounded = query_repo_events(
            &client,
            serde_json::json!({"kinds": [1618]}),
            &coordinate,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(unbounded.len(), 6);
        assert!(saw_unfiltered_request.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn repo_limit_returns_first_busy_matches_after_label_filter() {
        let owner = "b".repeat(64);
        let coordinate = format!("30617:{owner}:busy-repo");
        let foreign = format!("30617:{owner}:other-repo");
        let mut events = Vec::new();
        for seed in 0..12 {
            let label = if seed % 2 == 0 { "bug" } else { "feature" };
            events.push(query_event(seed, 3_000 - seed, &coordinate, Some(label)));
        }
        for seed in 0..12 {
            events.push(query_event(100 + seed, 4_000 - seed, &foreign, Some("bug")));
        }

        let (url, _) = query_server(events).await;
        let client = test_client(&url);
        let result = query_repo_events(
            &client,
            serde_json::json!({"kinds": [1617]}),
            &coordinate,
            Some("bug"),
            Some(5),
        )
        .await
        .unwrap();

        assert_eq!(result.len(), 5);
        assert_eq!(
            result
                .iter()
                .filter_map(|event| event.get("created_at").and_then(Value::as_u64))
                .collect::<Vec<_>>(),
            vec![3_000, 2_998, 2_996, 2_994, 2_992]
        );
        assert!(result
            .iter()
            .all(|event| event_has_tag(event, "a", &coordinate)));
        assert!(result.iter().all(|event| event_has_tag(event, "t", "bug")));
    }
}
