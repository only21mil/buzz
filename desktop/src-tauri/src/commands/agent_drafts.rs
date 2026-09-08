//! Owner/community scoped encrypted queue and recoverable reviewed operations.
//! Only explicit prepare/apply/confirm commands may send or mutate definitions.
use crate::{
    app_state::AppState,
    managed_agents::{
        self,
        retention::{active_retention_scope, RetentionScope},
        AgentDefinition, CreatePersonaRequest, UpdatePersonaRequest,
    },
};
use buzz_core_pkg::agent_drafts::{validate_decision, validate_request};
use nostr::{Event, JsonUtil};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tauri::{AppHandle, Manager};

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DraftOperation {
    request_event_id: String,
    target_id: String,
    action: String,
    state: String,
    claim_event: Event,
    outcome_event: Option<Event>,
    persona: Option<AgentDefinition>,
    error: Option<String>,
    instance: Option<Value>,
    input: Value,
    expected_content: Option<Value>,
    instance_input: Option<Value>,
    publication: Option<Event>,
    #[serde(default)]
    channel_event: Option<Event>,
    #[serde(default)]
    channel_attached: bool,
    publish_shared: bool,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DraftQueue {
    events: Vec<Event>,
    operations: Vec<DraftOperation>,
}
fn scope(app: &AppHandle, owner: &str, relay_url: &str) -> Result<RetentionScope, String> {
    let state = app.state::<AppState>();
    let scope = active_retention_scope(app, &state)?;
    if scope.owner_keys.public_key().to_hex() != owner
        || scope.relay_url.trim_end_matches('/') != relay_url.trim_end_matches('/')
    {
        return Err("draft cancelled: identity or community changed".into());
    }
    Ok(scope)
}
fn db(scope: &RetentionScope) -> Result<Connection, String> {
    let path = scope.db_path.with_extension("drafts.sqlite");
    let conn = Connection::open(&path).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| e.to_string())?;
    }
    conn.busy_timeout(std::time::Duration::from_secs(5))
        .map_err(|e| e.to_string())?;
    conn.execute_batch("PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS draft_events(id TEXT PRIMARY KEY,event TEXT NOT NULL); CREATE TABLE IF NOT EXISTS draft_operations(id TEXT PRIMARY KEY,ciphertext TEXT NOT NULL);").map_err(|e|e.to_string())?;
    Ok(conn)
}
fn encrypt(scope: &RetentionScope, value: &impl Serialize) -> Result<String, String> {
    buzz_core_pkg::observer::encrypt_observer_payload(
        &scope.owner_keys,
        &scope.owner_keys.public_key(),
        value,
    )
    .map_err(|e| e.to_string())
}
fn put_operation(scope: &RetentionScope, operation: &DraftOperation) -> Result<(), String> {
    db(scope)?.execute("INSERT INTO draft_operations VALUES (?1,?2) ON CONFLICT(id) DO UPDATE SET ciphertext=excluded.ciphertext",params![operation.request_event_id,encrypt(scope,operation)?]).map_err(|e|e.to_string())?;
    Ok(())
}
fn read_operation(scope: &RetentionScope, id: &str) -> Result<Option<DraftOperation>, String> {
    let ciphertext: Option<String> = db(scope)?
        .query_row(
            "SELECT ciphertext FROM draft_operations WHERE id=?1",
            [id],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    ciphertext
        .map(|c| {
            let text = nostr::nips::nip44::decrypt(
                scope.owner_keys.secret_key(),
                &scope.owner_keys.public_key(),
                c,
            )
            .map_err(|e| e.to_string())?;
            serde_json::from_str(&text).map_err(|e| e.to_string())
        })
        .transpose()
}
fn stored_request(scope: &RetentionScope, id: &str) -> Result<Event, String> {
    let text: String = db(scope)?
        .query_row("SELECT event FROM draft_events WHERE id=?1", [id], |r| {
            r.get(0)
        })
        .map_err(|e| e.to_string())?;
    let event = Event::from_json(text).map_err(|e| e.to_string())?;
    validate_request(&event)?;
    Ok(event)
}
fn store_event(scope: &RetentionScope, event: &Event) -> Result<(), String> {
    event.verify().map_err(|e| e.to_string())?;
    let owner = match u32::from(event.kind.as_u16()) {
        buzz_core_pkg::kind::KIND_AGENT_DRAFT => {
            let route = validate_request(event)?;
            if route.owner != scope.owner_keys.public_key() {
                return Err("draft owner mismatch".into());
            }
            route.owner
        }
        buzz_core_pkg::kind::KIND_AGENT_DRAFT_DECISION => validate_decision(event)?.owner,
        _ => return Err("not a durable draft event".into()),
    };
    if owner != scope.owner_keys.public_key() {
        return Err("draft owner mismatch".into());
    }
    db(scope)?
        .execute(
            "INSERT OR IGNORE INTO draft_events VALUES (?1,?2)",
            params![event.id.to_hex(), event.as_json()],
        )
        .map_err(|e| e.to_string())?;
    Ok(())
}
// Retention accepts signed owner-scoped ciphertext even when the private body
// is unavailable. Only reviewed mutations require a valid decrypted binding.
fn request_body(scope: &RetentionScope, event: &Event) -> Result<Value, String> {
    let route = validate_request(event)?;
    let body: Value = buzz_core_pkg::observer::decrypt_observer_payload(&scope.owner_keys, event)
        .map_err(|e| e.to_string())?;
    if body["version"] != 1
        || body["payload"]["requestId"] != route.request_id.to_string()
        || body["channelId"] != route.channel.to_string()
        || body["payload"]["request"]["channelId"] != route.channel.to_string()
        || body["payload"]["type"] != "agent_management_request"
        || !matches!(
            body["payload"]["action"].as_str(),
            Some("create" | "update")
        )
    {
        return Err("draft encrypted binding mismatch".into());
    }
    Ok(body)
}
fn terminal_or_claimed(scope: &RetentionScope, id: &str) -> Result<bool, String> {
    let conn = db(scope)?;
    let mut stmt = conn
        .prepare("SELECT event FROM draft_events")
        .map_err(|e| e.to_string())?;
    for row in stmt
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(|e| e.to_string())?
    {
        let event = Event::from_json(row.map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        if let Ok(d) = validate_decision(&event) {
            if d.request_event.to_hex() == id {
                return Ok(true);
            }
        }
    }
    Ok(false)
}
#[tauri::command]
pub fn agent_draft_receive(
    owner: String,
    relay_url: String,
    event: Event,
    app: AppHandle,
) -> Result<(), String> {
    store_event(&scope(&app, &owner, &relay_url)?, &event)
}
#[tauri::command]
pub fn agent_draft_queue(
    owner: String,
    relay_url: String,
    app: AppHandle,
) -> Result<DraftQueue, String> {
    let s = scope(&app, &owner, &relay_url)?;
    let conn = db(&s)?;
    let mut stmt = conn
        .prepare("SELECT event FROM draft_events ORDER BY id")
        .map_err(|e| e.to_string())?;
    let events = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(|e| e.to_string())?
        .map(|r| Event::from_json(r.map_err(|e| e.to_string())?).map_err(|e| e.to_string()))
        .collect::<Result<Vec<_>, String>>()?;
    let mut stmt = conn
        .prepare("SELECT id FROM draft_operations ORDER BY id")
        .map_err(|e| e.to_string())?;
    let mut operations = Vec::new();
    for id in stmt
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(|e| e.to_string())?
    {
        if let Some(op) = read_operation(&s, &id.map_err(|e| e.to_string())?)? {
            operations.push(op);
        }
    }
    scope(&app, &owner, &relay_url)?;
    Ok(DraftQueue { events, operations })
}
#[tauri::command]
pub async fn agent_draft_backfill(
    owner: String,
    relay_url: String,
    until: Option<u64>,
    before_id: Option<String>,
    limit: Option<u64>,
    app: AppHandle,
) -> Result<Vec<Event>, String> {
    let s = scope(&app, &owner, &relay_url)?;
    let state = app.state::<AppState>();
    let mut filter =
        json!({"kinds":[14201,14202],"#p":[owner],"limit":limit.unwrap_or(100).min(500)});
    if let Some(until) = until {
        filter["until"] = until.into();
    }
    if let Some(id) = before_id {
        filter["before_id"] = id.into();
    }
    let events = crate::relay::query_relay_at_with_keys(
        &state,
        &crate::relay::relay_api_base_url_with_override(&state),
        &[filter],
        &s.owner_keys,
        None,
    )
    .await?;
    scope(&app, &owner, &relay_url)?;
    for e in &events {
        store_event(&s, e)?;
    }
    Ok(events)
}
fn validate_registered(app: &AppHandle, s: &RetentionScope, request: &Event) -> Result<(), String> {
    let route = validate_request(request)?;
    let records = managed_agents::load_managed_agents(app)?;
    if !records.iter().any(|a| {
        a.pubkey == route.agent.to_hex()
            && a.relay_url.trim_end_matches('/') == s.relay_url.trim_end_matches('/')
            && a.auth_tag.as_deref().is_some_and(|tag| {
                buzz_sdk_pkg::nip_oa::verify_auth_tag(tag, &route.agent).ok()
                    == Some(s.owner_keys.public_key())
            })
    }) {
        return Err(
            "unavailable: sender is not a registered managed agent in this community".into(),
        );
    }
    Ok(())
}
async fn validate_membership(
    app: &AppHandle,
    s: &RetentionScope,
    request: &Event,
) -> Result<(), String> {
    validate_registered(app, s, request)?;
    let route = validate_request(request)?;
    let state = app.state::<AppState>();
    let events = crate::relay::query_relay_at_with_keys(
        &state,
        &crate::relay::relay_api_base_url_with_override(&state),
        &[json!({"kinds":[39002],"#d":[route.channel.to_string()],"limit":1})],
        &s.owner_keys,
        None,
    )
    .await?;
    let members = events
        .first()
        .ok_or("unavailable: current channel membership not found")?;
    for key in [route.agent, route.owner] {
        if !members.tags.iter().any(|t| {
            t.as_slice().first().is_some_and(|n| n == "p")
                && t.content() == Some(key.to_hex().as_str())
        }) {
            return Err(
                "unavailable: sender and owner must still share the originating channel".into(),
            );
        }
    }
    Ok(())
}
fn edited_persona(
    input: &Value,
    target: &str,
    previous: Option<&AgentDefinition>,
) -> Result<AgentDefinition, String> {
    let now = crate::util::now_iso();
    let mut persona = if let Some(previous) = previous {
        let i: UpdatePersonaRequest =
            serde_json::from_value(input.clone()).map_err(|e| e.to_string())?;
        if i.id != target {
            return Err("review target changed".into());
        }
        let mut p = previous.clone();
        p.display_name = i.display_name;
        p.avatar_url = i.avatar_url;
        p.system_prompt = i.system_prompt;
        p.runtime = i.runtime;
        p.model = i.model;
        p.provider = i.provider;
        p.name_pool = i.name_pool;
        if let Some(env) = i.env_vars {
            p.env_vars = env;
        }
        managed_agents::apply_persona_behavior(&mut p, i.behavior)?;
        p
    } else {
        let i: CreatePersonaRequest =
            serde_json::from_value(input.clone()).map_err(|e| e.to_string())?;
        let mut p = AgentDefinition {
            id: target.into(),
            display_name: i.display_name,
            avatar_url: i.avatar_url,
            system_prompt: i.system_prompt,
            runtime: i.runtime,
            model: i.model,
            provider: i.provider,
            name_pool: i.name_pool,
            is_builtin: false,
            is_active: true,
            shared: false,
            source_team: None,
            source_team_persona_slug: None,
            catalog_source: None,
            team_catalog_source: None,
            env_vars: i.env_vars,
            respond_to: None,
            respond_to_allowlist: Vec::new(),
            parallelism: None,
            created_at: now.clone(),
            updated_at: now.clone(),
        };
        managed_agents::apply_persona_behavior(&mut p, i.behavior)?;
        p
    };
    persona.display_name = persona.display_name.trim().into();
    if persona.display_name.is_empty() {
        return Err("display name is required".into());
    }
    managed_agents::validate_user_env_keys(&persona.env_vars)?;
    persona.updated_at = now;
    Ok(persona)
}
fn decision(
    s: &RetentionScope,
    request: &str,
    previous: &str,
    generation: u64,
    state: &str,
    content: &impl Serialize,
) -> Result<Event, String> {
    buzz_sdk_pkg::build_agent_draft_decision(
        &s.owner_keys.public_key().to_hex(),
        request,
        previous,
        generation,
        state,
        &encrypt(s, content)?,
    )?
    .sign_with_keys(&s.owner_keys)
    .map_err(|e| e.to_string())
}

#[tauri::command]
pub fn agent_draft_prepare(
    owner: String,
    relay_url: String,
    request_event_id: String,
    action: String,
    input: Value,
    expected_content: Option<Value>,
    instance_input: Option<Value>,
    publish_shared: Option<bool>,
    app: AppHandle,
) -> Result<DraftOperation, String> {
    let state = app.state::<AppState>();
    let _epoch = state.publication_epoch.lock().map_err(|e| e.to_string())?;
    let _guard = state
        .managed_agents_store_lock
        .lock()
        .map_err(|e| e.to_string())?;
    let s = scope(&app, &owner, &relay_url)?;
    let publish_shared = publish_shared.unwrap_or(false);
    if !matches!(action.as_str(), "save" | "create" | "start" | "reject") {
        return Err("invalid reviewed action".into());
    }
    if let Some(op) = read_operation(&s, &request_event_id)? {
        if op.action != action
            || op.input != input
            || op.expected_content != expected_content
            || op.instance_input != instance_input
            || op.publish_shared != publish_shared
        {
            return Err("review content/action conflict: inspect the retained operation".into());
        }
        return Ok(op);
    }
    if terminal_or_claimed(&s, &request_event_id)? {
        return Err("request already has an owner decision; inspect its outcome".into());
    }
    let request = stored_request(&s, &request_event_id)?;
    if action != "reject" {
        validate_registered(&app, &s, &request)?;
    }
    let body = if action == "reject" {
        Value::Null
    } else {
        request_body(&s, &request)?
    };
    let request_action = body["payload"]["action"].as_str();
    let mut personas = managed_agents::load_personas(&app)?;
    super::personas::pending::project_active_persona_sharing(&app, &state, &mut personas);
    let previous = if request_action == Some("update") && action != "reject" {
        let target = input["id"]
            .as_str()
            .ok_or("update requires pinned persona ID")?;
        let p = personas
            .iter()
            .find(|p| p.id == target)
            .ok_or("target persona removed")?;
        let name = body["payload"]["request"]["agentName"]
            .as_str()
            .ok_or("missing requested agent name")?;
        let matches = personas
            .iter()
            .filter(|p| p.id == name || p.display_name.eq_ignore_ascii_case(name))
            .count();
        if matches != 1 || !(p.id == name || p.display_name.eq_ignore_ascii_case(name)) {
            return Err("draft target is missing or ambiguous".into());
        }
        if expected_content.is_none()
            || input["expectedUpdatedAt"].as_str().is_none()
            || input["expectedShared"].as_bool().is_none()
        {
            return Err(
                "update requires complete reviewed content, revision and sharing snapshot".into(),
            );
        }
        validate_preimage(&input, expected_content.as_ref(), p)?;
        if p.shared && !publish_shared {
            return Err("shared persona requires explicit Save and publish review".into());
        }
        Some(p)
    } else {
        None
    };
    if matches!(action.as_str(), "create" | "start") && instance_input.is_none() {
        return Err("reviewed instance input required".into());
    }
    if matches!(action.as_str(), "save" | "reject") && instance_input.is_some() {
        return Err("save/reject cannot authorize an instance".into());
    }
    let target_id = previous
        .map(|p| p.id.clone())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let persona = if action == "reject" {
        None
    } else {
        Some(edited_persona(&input, &target_id, previous)?)
    };
    let claim_state = if action == "reject" {
        "rejected"
    } else {
        "applying"
    };
    let claim_event = decision(
        &s,
        &request_event_id,
        &request_event_id,
        1,
        claim_state,
        &json!({"version":1,"requestEventId":request_event_id,"targetId":target_id,"action":action,"input":input,"expectedContent":expected_content,"instanceInput":instance_input,"publishShared":publish_shared}),
    )?;
    let op = DraftOperation {
        request_event_id,
        target_id,
        action,
        state: "prepared".into(),
        claim_event,
        outcome_event: None,
        persona,
        error: None,
        instance: None,
        input,
        expected_content,
        instance_input,
        publication: None,
        channel_event: None,
        channel_attached: false,
        publish_shared,
    };
    put_operation(&s, &op)?;
    Ok(op)
}
fn validate_preimage(
    input: &Value,
    expected: Option<&Value>,
    current: &AgentDefinition,
) -> Result<(), String> {
    let content: Option<managed_agents::PersonaReviewContent> = expected
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|e| e.to_string())?;
    super::personas::review_revision::validate_review_revision(
        input["expectedUpdatedAt"].as_str(),
        content.as_ref(),
        input["expectedShared"].as_bool(),
        current,
    )
}
async fn send(
    app: &AppHandle,
    owner: &str,
    relay_url: &str,
    _s: &RetentionScope,
    event: &Event,
) -> Result<(), String> {
    scope(app, owner, relay_url)?;
    let state = app.state::<AppState>();
    let expected = crate::relay::ExpectedPublicationScope {
        pubkey: owner.into(),
        relay_url: relay_url.into(),
        native_epoch: None,
    };
    let publication = crate::relay::MessagePublication::capture(&state, Some(&expected))?;
    let result = crate::relay::submit_retained_event_in_scope(event, &state, publication).await?;
    if u32::from(event.kind.as_u16()) == 14202
        && !result.message.starts_with("stored: agent-draft-v1")
    {
        return Err("relay did not confirm durable claim/outcome support".into());
    }
    scope(app, owner, relay_url)?;
    Ok(())
}
#[tauri::command]
pub async fn agent_draft_apply(
    owner: String,
    relay_url: String,
    request_event_id: String,
    app: AppHandle,
) -> Result<DraftOperation, String> {
    let s = scope(&app, &owner, &relay_url)?;
    let transaction = crate::relay::MessagePublication::capture(&app.state::<AppState>(), None)?;
    let mut op =
        read_operation(&s, &request_event_id)?.ok_or("review operation was not prepared")?;
    if matches!(op.state.as_str(), "applied" | "rejected" | "uncertain") {
        return Ok(op);
    }
    let request = stored_request(&s, &request_event_id)?;
    if op.action != "reject" {
        request_body(&s, &request)?;
        validate_membership(&app, &s, &request).await?;
    }
    scope(&app, &owner, &relay_url)?;
    transaction.validate()?;
    send(&app, &owner, &relay_url, &s, &op.claim_event).await?;
    transaction.validate()?;
    if op.action != "reject" {
        validate_membership(&app, &s, &request).await?;
    }
    // Serialize local retries after the network claim; reload because another
    // invocation may already have saved this exact local operation.
    {
        let state = app.state::<AppState>();
        let _epoch = transaction.lock_validated()?;
        let _guard = state
            .managed_agents_store_lock
            .lock()
            .map_err(|e| e.to_string())?;
        scope(&app, &owner, &relay_url)?;
        op = read_operation(&s, &request_event_id)?.ok_or("operation missing")?;
        if matches!(op.state.as_str(), "applied" | "rejected" | "uncertain") {
            return Ok(op);
        }
        if op.action == "reject" {
            store_event(&s, &op.claim_event)?;
            op.state = "rejected".into();
            op.outcome_event = Some(op.claim_event.clone());
            put_operation(&s, &op)?;
            return Ok(op);
        }
        validate_registered(&app, &s, &request)?;
        let mut personas = managed_agents::load_personas(&app)?;
        super::personas::pending::project_active_persona_sharing(&app, &state, &mut personas);
        persist_prepared_persona(
            &mut op,
            &mut personas,
            |op| put_operation(&s, op),
            |personas| managed_agents::save_personas(&app, personas),
        )?;
        let desired = op
            .persona
            .as_ref()
            .ok_or("operation missing prepared persona")?;
        op.error = None;
        if op.publication.is_none() {
            let conn = managed_agents::retention::open_retention_db(&s.db_path)?;
            let prior = managed_agents::retention::get_retained_event(
                &conn,
                buzz_core_pkg::kind::KIND_PERSONA,
                &owner,
                &managed_agents::persona_events::persona_d_tag(desired),
            )?;
            if desired.shared && !op.publish_shared {
                return Err("shared publication was not explicitly reviewed".into());
            }
            op.publication = Some(
                managed_agents::persona_events::build_persona_event(desired)?
                    .custom_created_at(managed_agents::persona_events::monotonic_created_at(
                        prior.map(|r| r.created_at),
                    ))
                    .sign_with_keys(&s.owner_keys)
                    .map_err(|e| e.to_string())?,
            );
        }
        put_operation(&s, &op)?;
    }
    if let Some(mut input) = op.instance_input.clone() {
        if op.instance.is_none() {
            input["personaId"] = op.target_id.clone().into();
            input["relayUrl"] = relay_url.clone().into();
            input["spawnAfterCreate"] = (op.action == "start").into();
            input["startOnAppLaunch"] = false.into();
            let input: managed_agents::CreateManagedAgentRequest =
                serde_json::from_value(input).map_err(|e| e.to_string())?;
            {
                let state = app.state::<AppState>();
                let _guard = state
                    .managed_agents_store_lock
                    .lock()
                    .map_err(|e| e.to_string())?;
                let latest = read_operation(&s, &request_event_id)?.ok_or("operation missing")?;
                if latest.state == "uncertain" || latest.instance.is_some() {
                    return Ok(latest);
                }
                scope(&app, &owner, &relay_url)?;
                op.state = "uncertain".into();
                op.error=Some("Instance creation/start may have run. Recovery never repeats an uncertain side effect.".into());
                put_operation(&s, &op)?;
            }
            let state = app.state::<AppState>();
            match super::agents::create_managed_agent(input, app.clone(), state).await {
                Ok(instance) => {
                    let failed =
                        instance.spawn_error.is_some() || instance.profile_sync_error.is_some();
                    if !failed && op.action == "start" {
                        let route = validate_request(&request)?;
                        op.channel_event = Some(
                            crate::events::build_add_member(
                                route.channel,
                                &instance.agent.pubkey,
                                None,
                            )?
                            .sign_with_keys(&s.owner_keys)
                            .map_err(|e| e.to_string())?,
                        );
                    }
                    op.instance = Some(
                        json!({"pubkey":instance.agent.pubkey,"status":instance.agent.status,"profileSyncError":instance.profile_sync_error,"spawnError":instance.spawn_error}),
                    );
                    op.state = if failed { "uncertain" } else { "saved" }.into();
                    op.error=failed.then(||"Instance exists but requested start/profile publication did not finish. Inspect the instance; this operation will not repeat side effects.".into());
                    put_operation(&s, &op)?;
                    if failed {
                        return Ok(op);
                    }
                }
                Err(error) => {
                    op.error = Some(format!("Instance result uncertain: {error}"));
                    put_operation(&s, &op)?;
                    return Ok(op);
                }
            }
        }
    }
    transaction.validate()?;
    finish(&app, &owner, &relay_url, &s, op).await
}
// Own relay echoes normalize timestamps to seconds. Recovery binds stable ID
// and exact editable content/sharing rather than mistaking that for a new edit.
fn same_saved_persona(current: &AgentDefinition, desired: &AgentDefinition) -> bool {
    managed_agents::PersonaReviewContent::from(current)
        == managed_agents::PersonaReviewContent::from(desired)
        && current.shared == desired.shared
        && current.source_team == desired.source_team
        && current.source_team_persona_slug == desired.source_team_persona_slug
}
// Caller holds the persona store lock. Persist the exact result before save;
// recovery compares full saved bytes and never allocates another target.
fn persist_prepared_persona(
    op: &mut DraftOperation,
    personas: &mut Vec<AgentDefinition>,
    persist: impl Fn(&DraftOperation) -> Result<(), String>,
    save: impl Fn(&[AgentDefinition]) -> Result<(), String>,
) -> Result<(), String> {
    let desired = op
        .persona
        .as_ref()
        .ok_or("operation missing prepared persona")?;
    let existing = personas.iter().position(|p| p.id == op.target_id);
    // The prepared exact result is the write-ahead record. A crash after
    // save but before journal completion is recognized by bytes, not time.
    let already_saved = existing.is_some_and(|i| same_saved_persona(&personas[i], desired));
    if !already_saved && op.state != "saved" {
        if let Some(i) = existing {
            if op.expected_content.is_none() {
                return Err("allocated target ID already exists".into());
            }
            validate_preimage(&op.input, op.expected_content.as_ref(), &personas[i])?;
            personas[i] = desired.clone();
        } else {
            if op.expected_content.is_some() {
                return Err("reviewed persona was removed".into());
            }
            personas.push(desired.clone());
        }
        op.state = "claimed".into();
        persist(op)?;
        save(personas)?;
    }
    if op.state == "saved" && !already_saved {
        return Err("saved draft result changed; explicit reconciliation required".into());
    }
    op.state = "saved".into();
    Ok(())
}

// Only an explicit apply/confirm reaches this path. Once accepted, journal the
// attachment so later publication/outcome retries cannot re-add a removed member.
async fn attach_started_instance(
    app: &AppHandle,
    owner: &str,
    relay_url: &str,
    s: &RetentionScope,
    transaction: &crate::relay::MessagePublication,
    op: &mut DraftOperation,
) -> Result<(), String> {
    let event = op
        .channel_event
        .as_ref()
        .ok_or("missing channel attachment")?;
    let stale = event.created_at.as_secs().saturating_add(600) < nostr::Timestamp::now().as_secs();
    let mut attached = false;
    if stale {
        // An interrupted send may have succeeded. Read membership before
        // renewing the approved event's timestamp; never repeat Create/Start.
        let route = validate_request(&stored_request(s, &op.request_event_id)?)?;
        let pubkey = op
            .instance
            .as_ref()
            .and_then(|i| i["pubkey"].as_str())
            .ok_or("missing started instance")?;
        let state = app.state::<AppState>();
        let events = crate::relay::query_relay_at_with_keys(
            &state,
            &transaction.api_base_url,
            &[json!({"kinds":[39002],"#d":[route.channel.to_string()],"limit":1})],
            &s.owner_keys,
            None,
        )
        .await?;
        transaction.validate()?;
        attached = events.first().is_some_and(|members| {
            members.tags.iter().any(|tag| {
                tag.as_slice().first().is_some_and(|name| name == "p")
                    && tag.content() == Some(pubkey)
            })
        });
        if !attached {
            op.channel_event = Some(
                nostr::EventBuilder::new(event.kind, &event.content)
                    .tags(event.tags.clone())
                    .allow_self_tagging()
                    .sign_with_keys(&s.owner_keys)
                    .map_err(|e| e.to_string())?,
            );
            let state = app.state::<AppState>();
            let _epoch = transaction.lock_validated()?;
            let _guard = state
                .managed_agents_store_lock
                .lock()
                .map_err(|e| e.to_string())?;
            let mut latest = read_operation(s, &op.request_event_id)?.ok_or("operation missing")?;
            if latest.channel_attached {
                *op = latest;
                return Ok(());
            }
            latest.channel_event = op.channel_event.clone();
            put_operation(s, &latest)?;
            *op = latest;
        }
    }
    if !attached {
        send(
            app,
            owner,
            relay_url,
            s,
            op.channel_event
                .as_ref()
                .ok_or("missing channel attachment")?,
        )
        .await?;
    }
    let state = app.state::<AppState>();
    let _epoch = transaction.lock_validated()?;
    let _guard = state
        .managed_agents_store_lock
        .lock()
        .map_err(|e| e.to_string())?;
    let mut latest = read_operation(s, &op.request_event_id)?.ok_or("operation missing")?;
    latest.channel_attached = true;
    put_operation(s, &latest)?;
    *op = latest;
    Ok(())
}

async fn finish(
    app: &AppHandle,
    owner: &str,
    relay_url: &str,
    s: &RetentionScope,
    mut op: DraftOperation,
) -> Result<DraftOperation, String> {
    let transaction = crate::relay::MessagePublication::capture(&app.state::<AppState>(), None)?;
    if op.channel_event.is_some() && !op.channel_attached {
        let result = attach_started_instance(app, owner, relay_url, s, &transaction, &mut op).await;
        if let Err(error) = result {
            let state = app.state::<AppState>();
            let _guard = state
                .managed_agents_store_lock
                .lock()
                .map_err(|e| e.to_string())?;
            let mut latest = read_operation(s, &op.request_event_id)?.ok_or("operation missing")?;
            if latest.state == "applied" {
                return Ok(latest);
            }
            latest.error = Some(format!(
                "Instance started; originating channel attachment pending: {error}"
            ));
            put_operation(s, &latest)?;
            return Ok(latest);
        }
    }

    if op.publication.is_some() {
        let state = app.state::<AppState>();
        let _epoch = transaction.lock_validated()?;
        let _guard = state
            .managed_agents_store_lock
            .lock()
            .map_err(|e| e.to_string())?;
        scope(app, owner, relay_url)?;
        let mut personas = managed_agents::load_personas(app)?;
        super::personas::pending::project_active_persona_sharing(app, &state, &mut personas);
        let current = personas
            .iter()
            .find(|p| p.id == op.target_id)
            .ok_or("saved persona removed; publication requires new review")?;
        if !same_saved_persona(current, op.persona.as_ref().ok_or("missing saved persona")?) {
            return Err("saved persona changed; publication requires new review".into());
        }
        // An explicit retry may refresh only the signature timestamp. Owner,
        // destination, tags and approved content remain byte-identical.
        if let Some(event) = &op.publication {
            if event.created_at.as_secs() + 600 < nostr::Timestamp::now().as_secs() {
                op.publication = Some(
                    nostr::EventBuilder::new(event.kind, &event.content)
                        .tags(event.tags.clone())
                        .sign_with_keys(&s.owner_keys)
                        .map_err(|e| e.to_string())?,
                );
                put_operation(s, &op)?;
            }
        }
    }
    if let Some(event) = &op.publication {
        if let Err(error) = send(app, owner, relay_url, s, event).await {
            let state = app.state::<AppState>();
            let _guard = state
                .managed_agents_store_lock
                .lock()
                .map_err(|e| e.to_string())?;
            let mut latest = read_operation(s, &op.request_event_id)?.ok_or("operation missing")?;
            if latest.state == "applied" {
                return Ok(latest);
            }
            latest.error = Some(format!("Definition saved; publication pending: {error}"));
            put_operation(s, &latest)?;
            return Ok(latest);
        }
    }
    if let Some(event) = &op.publication {
        let state = app.state::<AppState>();
        let _guard = state
            .managed_agents_store_lock
            .lock()
            .map_err(|e| e.to_string())?;
        let conn = managed_agents::retention::open_retention_db(&s.db_path)?;
        managed_agents::retention::retain_event(
            &conn,
            &managed_agents::retention::RetainedEvent {
                kind: buzz_core_pkg::kind::KIND_PERSONA,
                pubkey: owner.into(),
                d_tag: managed_agents::persona_events::persona_d_tag(
                    op.persona.as_ref().ok_or("missing persona")?,
                ),
                content: event.content.clone(),
                created_at: event.created_at.as_secs() as i64,
                raw_event: event.as_json(),
                pending_sync: false,
            },
        )?;
    }
    transaction.validate()?;
    {
        let state = app.state::<AppState>();
        let _guard = state
            .managed_agents_store_lock
            .lock()
            .map_err(|e| e.to_string())?;
        op = read_operation(s, &op.request_event_id)?.ok_or("operation missing")?;
        if matches!(op.state.as_str(), "applied" | "rejected" | "uncertain") {
            return Ok(op);
        }
        if op.outcome_event.is_none() {
            op.outcome_event = Some(decision(
                s,
                &op.request_event_id,
                &op.claim_event.id.to_hex(),
                2,
                "applied",
                &json!({"version":1,"targetId":op.target_id,"action":op.action,"instance":op.instance,"published":op.publication.is_some()}),
            )?);
            put_operation(s, &op)?;
        }
    }
    let event = op.outcome_event.as_ref().ok_or("missing outcome")?;
    let result = send(app, owner, relay_url, s, event).await;
    let state = app.state::<AppState>();
    let _guard = state
        .managed_agents_store_lock
        .lock()
        .map_err(|e| e.to_string())?;
    let latest = read_operation(s, &op.request_event_id)?.ok_or("operation missing")?;
    if latest.state == "applied" {
        return Ok(latest);
    }
    if let Err(error) = result {
        op.error = Some(format!("Saved; owner outcome pending: {error}"));
        put_operation(s, &op)?;
        return Ok(op);
    }
    store_event(s, event)?;
    op.state = "applied".into();
    op.error = None;
    put_operation(s, &op)?;
    Ok(op)
}
#[tauri::command]
pub async fn agent_draft_confirm(
    owner: String,
    relay_url: String,
    request_event_id: String,
    app: AppHandle,
) -> Result<DraftOperation, String> {
    let s = scope(&app, &owner, &relay_url)?;
    let op = read_operation(&s, &request_event_id)?.ok_or("operation not found")?;
    if op.state != "saved" {
        return Err("only a saved operation can retry its exact publication/outcome; inspect uncertain operations".into());
    }
    if op.instance_input.is_some() && op.instance.is_none() {
        return Err("instance outcome unresolved; cannot report applied".into());
    }
    finish(&app, &owner, &relay_url, &s, op).await
}

#[cfg(test)]
mod tests;
