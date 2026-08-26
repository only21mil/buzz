//! `buzz events` — arbitrary event retrieval by ID.
//!
//! Reviewer-instrument gap (issue db589e3e): terminal review could not
//! independently verify relay-side state because the CLI had no way to fetch
//! an arbitrary signed event by ID. `buzz pr get`/`buzz issues get` filter to
//! root kinds and return `[]` for status IDs. This module adds the generic
//! `events get --id <64-hex>` verb: raw signed event JSON out, with a
//! distinct not-found error.

use crate::client::BuzzClient;
use crate::error::CliError;
use crate::validate::validate_hex64;
use crate::EventsCmd;

/// Dispatch for the top-level `buzz events` subcommand.
pub async fn dispatch(cmd: EventsCmd, client: &BuzzClient) -> Result<(), CliError> {
    match cmd {
        EventsCmd::Get { id } => cmd_events_get(client, &id).await,
    }
}

/// Fetch an arbitrary stored event by ID (raw signed JSON out).
pub async fn cmd_events_get(client: &BuzzClient, event_id: &str) -> Result<(), CliError> {
    let id = event_id.trim();
    if id.is_empty() {
        return Err(CliError::Usage(
            "event ID is required (--id <64-hex>)".into(),
        ));
    }
    validate_hex64(id)?;
    let filter = serde_json::json!({ "ids": [id] });
    let resp = client.query(&filter).await?;
    // query resolves to a JSON array of signed events; empty means not found.
    let body = resp.trim();
    if body == "[]" || body.is_empty() {
        return Err(CliError::NotFound(format!("event {id} not found")));
    }
    println!("{resp}");
    Ok(())
}
