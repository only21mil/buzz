use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::client::{
    extract_d_tag, extract_relay_response_field, normalize_write_response, print_create_response,
    BuzzClient,
};
use crate::error::CliError;
use crate::validate::{parse_uuid, read_or_stdin, sdk_err, validate_uuid};

// TODO(phase-4): Replace raw nostr::EventBuilder usage with buzz-sdk builder functions

/// List workflows in a channel — query kind:30620 workflow definition events.
pub async fn cmd_list_workflows(client: &BuzzClient, channel_id: &str) -> Result<(), CliError> {
    validate_uuid(channel_id)?;
    let filter = serde_json::json!({
        "kinds": [30620],
        "#h": [channel_id]
    });
    let resp = client.query(&filter).await?;
    let events: Vec<serde_json::Value> = serde_json::from_str(&resp).unwrap_or_default();
    let workflows: Vec<serde_json::Value> = events
        .iter()
        .map(|e| {
            serde_json::json!({
                "workflow_id": extract_d_tag(e),
                "content": e.get("content").and_then(|v| v.as_str()).unwrap_or(""),
                "created_at": e.get("created_at").and_then(|v| v.as_u64()).unwrap_or(0),
                "pubkey": e.get("pubkey").and_then(|v| v.as_str()).unwrap_or(""),
            })
        })
        .collect();
    let output = serde_json::to_string(&workflows).unwrap_or_default();
    println!("{output}");
    Ok(())
}

/// Get a single workflow definition.
pub async fn cmd_get_workflow(client: &BuzzClient, workflow_id: &str) -> Result<(), CliError> {
    validate_uuid(workflow_id)?;
    let filter = serde_json::json!({
        "kinds": [30620],
        "#d": [workflow_id]
    });
    let resp = client.query(&filter).await?;
    let events: Vec<serde_json::Value> = serde_json::from_str(&resp).unwrap_or_default();
    if let Some(e) = events.first() {
        let normalized = serde_json::json!({
            "workflow_id": extract_d_tag(e),
            "content": e.get("content").and_then(|v| v.as_str()).unwrap_or(""),
            "created_at": e.get("created_at").and_then(|v| v.as_u64()).unwrap_or(0),
            "pubkey": e.get("pubkey").and_then(|v| v.as_str()).unwrap_or(""),
        });
        println!("{normalized}");
    } else {
        println!("null");
    }
    Ok(())
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum WorkflowRunStatus {
    Pending,
    Running,
    WaitingApproval,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Deserialize, Serialize)]
struct WorkflowRun {
    id: uuid::Uuid,
    workflow_id: uuid::Uuid,
    status: WorkflowRunStatus,
    current_step: i32,
    execution_trace: Vec<serde_json::Value>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    error_message: Option<String>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    started_at: Option<i64>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    completed_at: Option<i64>,
    created_at: i64,
}

fn deserialize_required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

fn parse_workflow_runs_response(response: &str) -> Result<Vec<WorkflowRun>, CliError> {
    serde_json::from_str(response)
        .map_err(|error| CliError::Other(format!("invalid workflow runs response: {error}")))
}

fn workflow_runs_limit(limit: Option<u32>) -> u32 {
    limit.unwrap_or(20).min(100)
}

fn workflow_runs_path(workflow_id: &str, limit: Option<u32>) -> String {
    format!(
        "/workflows/{workflow_id}/runs?limit={}",
        workflow_runs_limit(limit)
    )
}

async fn fetch_workflow_runs_json(
    client: &BuzzClient,
    workflow_id: &str,
    limit: Option<u32>,
) -> Result<String, CliError> {
    validate_uuid(workflow_id)?;
    let response = client
        .get_authed(&workflow_runs_path(workflow_id, limit))
        .await?;
    let runs = parse_workflow_runs_response(&response)?;
    serde_json::to_string(&runs)
        .map_err(|error| CliError::Other(format!("workflow runs serialization failed: {error}")))
}

/// Get authoritative workflow run history from the relay database.
pub async fn cmd_get_workflow_runs(
    client: &BuzzClient,
    workflow_id: &str,
    limit: Option<u32>,
) -> Result<(), CliError> {
    let output = fetch_workflow_runs_json(client, workflow_id, limit).await?;
    println!("{output}");
    Ok(())
}

/// Create a workflow — sign and submit a kind:30620 event.
pub async fn cmd_create_workflow(
    client: &BuzzClient,
    channel_id: &str,
    yaml: &str,
) -> Result<(), CliError> {
    let channel_uuid = parse_uuid(channel_id)?;
    let yaml_definition = read_or_stdin(yaml)?;

    let workflow_id = uuid::Uuid::new_v4();
    let builder = buzz_sdk::build_workflow_def(channel_uuid, workflow_id, &yaml_definition)
        .map_err(sdk_err)?;
    let event = client.sign_event(builder)?;

    let resp = client.submit_event(event).await?;
    let final_workflow_id = extract_relay_response_field(&resp, "workflow_id")
        .unwrap_or_else(|| workflow_id.to_string());
    print_create_response(&resp, "workflow_id", &final_workflow_id);
    Ok(())
}

/// Update a workflow — sign and submit an updated kind:30620 event with same d-tag.
pub async fn cmd_update_workflow(
    client: &BuzzClient,
    channel_id: &str,
    workflow_id: &str,
    yaml: &str,
) -> Result<(), CliError> {
    let channel_uuid = parse_uuid(channel_id)?;
    let wf_uuid = parse_uuid(workflow_id)?;
    let yaml_definition = read_or_stdin(yaml)?;

    let builder = buzz_sdk::build_workflow_update(channel_uuid, wf_uuid, &yaml_definition)
        .map_err(sdk_err)?;
    let event = client.sign_event(builder)?;

    let resp = client.submit_event(event).await?;
    println!("{}", normalize_write_response(&resp));
    Ok(())
}

/// Delete a workflow — sign and submit a kind:5 deletion event.
pub async fn cmd_delete_workflow(client: &BuzzClient, workflow_id: &str) -> Result<(), CliError> {
    let wf_uuid = parse_uuid(workflow_id)?;
    let keys = client.keys();

    let builder =
        buzz_sdk::build_workflow_delete(&keys.public_key().to_hex(), wf_uuid).map_err(sdk_err)?;
    let event = client.sign_event(builder)?;

    let resp = client.submit_event(event).await?;
    println!("{}", normalize_write_response(&resp));
    Ok(())
}

/// Trigger a workflow — sign and submit a kind:46020 event.
///
/// When `inputs` is provided, it is parsed as a JSON object and used as the
/// event content (MCP parity). When omitted, the event content is `{}`.
pub async fn cmd_trigger_workflow(
    client: &BuzzClient,
    workflow_id: &str,
    inputs: Option<&str>,
) -> Result<(), CliError> {
    let wf_uuid = parse_uuid(workflow_id)?;

    if let Some(raw) = inputs {
        // Parse and validate it is a JSON object, then build the event manually
        // so we can embed the inputs as the event content.
        let parsed: serde_json::Value = serde_json::from_str(raw)
            .map_err(|e| CliError::Usage(format!("--inputs is not valid JSON: {e}")))?;
        if !parsed.is_object() {
            return Err(CliError::Usage("--inputs must be a JSON object".into()));
        }
        let content = serde_json::to_string(&parsed).unwrap_or_default();
        use nostr::{EventBuilder, Kind, Tag};
        let tags = vec![Tag::parse(["d", &wf_uuid.to_string()])
            .map_err(|e| CliError::Other(format!("tag error: {e}")))?];
        let builder = EventBuilder::new(
            Kind::Custom(buzz_sdk::kind::KIND_WORKFLOW_TRIGGER as u16),
            &content,
        )
        .tags(tags);
        let event = client.sign_event(builder)?;
        let resp = client.submit_event(event).await?;
        println!("{}", normalize_write_response(&resp));
    } else {
        let builder = buzz_sdk::build_workflow_trigger(wf_uuid).map_err(sdk_err)?;
        let event = client.sign_event(builder)?;
        let resp = client.submit_event(event).await?;
        println!("{}", normalize_write_response(&resp));
    }
    Ok(())
}

/// Approve or deny a workflow step — sign and submit a kind:46030 (grant) or 46031 (deny) event.
pub async fn cmd_approve_step(
    client: &BuzzClient,
    approval_token: &str,
    approved: bool,
    note: Option<&str>,
) -> Result<(), CliError> {
    validate_uuid(approval_token)?;

    let content = note.unwrap_or("");

    // The relay expects d-tag = hex(SHA256(token)), not the raw token UUID.
    let token_hash = hex::encode(Sha256::digest(approval_token.as_bytes()));
    let builder =
        buzz_sdk::build_workflow_approval(&token_hash, approved, content).map_err(sdk_err)?;
    let event = client.sign_event(builder)?;

    let resp = client.submit_event(event).await?;
    println!("{}", normalize_write_response(&resp));
    Ok(())
}

pub async fn dispatch(cmd: crate::WorkflowsCmd, client: &BuzzClient) -> Result<(), CliError> {
    use crate::WorkflowsCmd;
    match cmd {
        WorkflowsCmd::List { channel } => cmd_list_workflows(client, &channel).await,
        WorkflowsCmd::Get { workflow } => cmd_get_workflow(client, &workflow).await,
        WorkflowsCmd::Create { channel, yaml } => {
            cmd_create_workflow(client, &channel, &yaml).await
        }
        WorkflowsCmd::Update {
            channel,
            workflow,
            yaml,
        } => cmd_update_workflow(client, &channel, &workflow, &yaml).await,
        WorkflowsCmd::Delete { workflow } => cmd_delete_workflow(client, &workflow).await,
        WorkflowsCmd::Trigger { workflow, inputs } => {
            cmd_trigger_workflow(client, &workflow, inputs.as_deref()).await
        }
        WorkflowsCmd::Runs { workflow, limit } => {
            cmd_get_workflow_runs(client, &workflow, limit).await
        }
        WorkflowsCmd::Approve {
            token,
            approved,
            note,
        } => {
            // approved is already a bool — no parse_bool_flag needed
            cmd_approve_step(client, &token, approved, note.as_deref()).await
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::{extract::OriginalUri, http::HeaderMap, routing::get, Router};
    use nostr::Keys;
    use tokio::net::TcpListener;

    use super::*;

    #[derive(Clone)]
    struct RunServerState {
        response: String,
        requests: Arc<Mutex<Vec<(String, bool)>>>,
    }

    async fn run_history_response(
        axum::extract::State(state): axum::extract::State<RunServerState>,
        OriginalUri(uri): OriginalUri,
        headers: HeaderMap,
    ) -> String {
        state.requests.lock().expect("request log").push((
            uri.path_and_query()
                .map(|value| value.as_str())
                .unwrap_or_else(|| uri.path())
                .to_owned(),
            headers.contains_key(axum::http::header::AUTHORIZATION),
        ));
        state.response
    }

    async fn run_history_server(response: String) -> (BuzzClient, Arc<Mutex<Vec<(String, bool)>>>) {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let state = RunServerState {
            response,
            requests: requests.clone(),
        };
        let app = Router::new()
            .fallback(get(run_history_response))
            .with_state(state);
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind run history test relay");
        let address = listener.local_addr().expect("test relay address");
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("run history test relay");
        });

        let client = BuzzClient::new(format!("http://{address}"), Keys::generate(), None, None)
            .expect("test client");
        (client, requests)
    }

    fn valid_run() -> serde_json::Value {
        serde_json::json!({
            "id": "10000000-0000-0000-0000-000000000001",
            "workflow_id": "30000000-0000-0000-0000-000000000003",
            "status": "failed",
            "current_step": 2,
            "execution_trace": [{"step_id": "notify", "status": "failed"}],
            "error_message": "webhook failed",
            "started_at": 1700000001,
            "completed_at": null,
            "created_at": 1700000000
        })
    }

    #[test]
    fn workflow_runs_response_accepts_a_bare_typed_array() {
        let response = serde_json::to_string(&vec![valid_run()]).expect("serialize fixture");
        let runs = parse_workflow_runs_response(&response).expect("parse workflow runs");
        let output = serde_json::to_value(runs).expect("serialize parsed runs");

        assert!(output.is_array());
        assert_eq!(output[0]["id"], valid_run()["id"]);
        assert_eq!(output[0]["status"], "failed");
        assert_eq!(output[0]["current_step"], 2);
        assert_eq!(output[0]["execution_trace"], valid_run()["execution_trace"]);
        assert_eq!(output[0]["error_message"], "webhook failed");
        assert_eq!(output[0]["started_at"], 1_700_000_001i64);
        assert!(output[0]["completed_at"].is_null());
    }

    #[tokio::test]
    async fn workflow_runs_fetch_uses_nip98_get_and_default_limit() {
        let response = serde_json::to_string(&vec![valid_run()]).expect("serialize fixture");
        let (client, requests) = run_history_server(response).await;
        let workflow_id = "30000000-0000-0000-0000-000000000003";

        let output = fetch_workflow_runs_json(&client, workflow_id, None)
            .await
            .expect("fetch workflow runs");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&output).expect("output json")[0]
                ["error_message"],
            "webhook failed"
        );
        assert_eq!(
            requests.lock().expect("request log").as_slice(),
            &[(format!("/workflows/{workflow_id}/runs?limit=20"), true)]
        );
    }

    #[tokio::test]
    async fn workflow_runs_fetch_caps_limit_and_preserves_a_real_empty_array() {
        let (client, requests) = run_history_server("[]".to_owned()).await;
        let workflow_id = "30000000-0000-0000-0000-000000000003";

        let output = fetch_workflow_runs_json(&client, workflow_id, Some(101))
            .await
            .expect("fetch empty workflow runs");
        assert_eq!(output, "[]");
        assert_eq!(
            requests.lock().expect("request log").as_slice(),
            &[(format!("/workflows/{workflow_id}/runs?limit=100"), true)]
        );
    }

    #[test]
    fn genuine_empty_workflow_runs_response_stays_an_empty_array() {
        let runs = parse_workflow_runs_response("[]").expect("parse empty response");
        assert_eq!(
            serde_json::to_string(&runs).expect("serialize empty runs"),
            "[]"
        );
    }

    #[test]
    fn malformed_or_enveloped_workflow_runs_responses_fail() {
        assert!(parse_workflow_runs_response("not json").is_err());
        assert!(parse_workflow_runs_response(r#"{"runs": []}"#).is_err());
        assert!(parse_workflow_runs_response(r#"[{"id": ]"#).is_err());
    }

    #[test]
    fn workflow_runs_response_rejects_every_missing_required_field() {
        for field in [
            "id",
            "workflow_id",
            "status",
            "current_step",
            "execution_trace",
            "error_message",
            "started_at",
            "completed_at",
            "created_at",
        ] {
            let mut run = valid_run();
            run.as_object_mut()
                .expect("run object")
                .remove(field)
                .expect("fixture field");
            let response = serde_json::to_string(&vec![run]).expect("serialize fixture");
            assert!(
                parse_workflow_runs_response(&response).is_err(),
                "missing {field} must fail"
            );
        }
    }

    #[test]
    fn workflow_runs_response_requires_execution_trace_to_be_an_array() {
        let mut run = valid_run();
        run["execution_trace"] = serde_json::json!({"step_id": "notify"});
        let response = serde_json::to_string(&vec![run]).expect("serialize fixture");

        assert!(parse_workflow_runs_response(&response).is_err());
    }
}
