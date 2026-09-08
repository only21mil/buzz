//! Owner-reviewed agent draft requests published through Buzz observer frames.

use buzz_core::observer::{encrypt_observer_payload, OBSERVER_FRAME_TELEMETRY};
use nostr::{Event, Keys, PublicKey};
use serde::Serialize;

use crate::error::CliError;

const AGENT_REQUEST_KIND: &str = "agent_management_request";
const PROJECT_CHANNEL_REQUEST_KIND: &str = "project_channel_request";
const MAX_NAME_CHARS: usize = 120;
const MAX_PROMPT_CHARS: usize = 20_000;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAgentDraft {
    pub channel_id: String,
    pub display_name: String,
    pub system_prompt: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateAgentDraft {
    pub channel_id: String,
    pub agent_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_prompt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub respond_to: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateProjectChannelDraft {
    pub home_channel_id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub visibility: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template_name: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ManagementRequest<T> {
    #[serde(rename = "type")]
    request_type: &'static str,
    action: &'static str,
    request_id: String,
    request: T,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ObserverEvent<T> {
    version: u8,
    seq: u64,
    timestamp: String,
    kind: &'static str,
    agent_index: Option<usize>,
    channel_id: Option<String>,
    session_id: Option<String>,
    turn_id: Option<String>,
    payload: ManagementRequest<T>,
}

#[derive(Debug)]
pub struct BuiltDraftRequest {
    pub event: Event,
    pub request_id: String,
    pub action: &'static str,
}

fn required(value: String, label: &str, max: usize) -> Result<String, CliError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(CliError::Usage(format!("{label} is required")));
    }
    if value.chars().count() > max {
        return Err(CliError::Usage(format!(
            "{label} is too long (max {max} characters)"
        )));
    }
    Ok(value.to_owned())
}

fn optional(value: Option<String>, label: &str) -> Result<Option<String>, CliError> {
    value.map(|value| required(value, label, 300)).transpose()
}

fn build<T: Serialize>(
    keys: &Keys,
    owner: &PublicKey,
    channel_id: String,
    request_kind: &'static str,
    action: &'static str,
    request: T,
) -> Result<BuiltDraftRequest, CliError> {
    let request_id = uuid::Uuid::new_v4().to_string();
    let payload = ObserverEvent {
        version: 1,
        seq: 0,
        timestamp: chrono::Utc::now().to_rfc3339(),
        kind: request_kind,
        agent_index: None,
        channel_id: Some(channel_id.clone()),
        session_id: None,
        turn_id: None,
        payload: ManagementRequest {
            request_type: request_kind,
            action,
            request_id: request_id.clone(),
            request,
        },
    };
    let encrypted = encrypt_observer_payload(keys, owner, &payload)
        .map_err(|error| CliError::Other(format!("could not encrypt draft request: {error}")))?;
    let builder = if request_kind == AGENT_REQUEST_KIND {
        buzz_sdk::build_agent_draft(
            &owner.to_hex(),
            &keys.public_key().to_hex(),
            &request_id,
            &channel_id,
            &encrypted,
        )
        .map_err(|error| CliError::Other(error.to_string()))
    } else {
        buzz_sdk::build_agent_observer_frame(
            &owner.to_hex(),
            &keys.public_key().to_hex(),
            OBSERVER_FRAME_TELEMETRY,
            &encrypted,
        )
        .map_err(|error| CliError::Other(error.to_string()))
    };
    let event = builder
        .map_err(|error| CliError::Other(format!("could not build draft request: {error}")))?
        .sign_with_keys(keys)
        .map_err(|error| CliError::Other(format!("could not sign draft request: {error}")))?;
    Ok(BuiltDraftRequest {
        event,
        request_id,
        action,
    })
}

pub fn build_create(
    keys: &Keys,
    owner: &PublicKey,
    draft: CreateAgentDraft,
) -> Result<BuiltDraftRequest, CliError> {
    let channel_id = required(draft.channel_id, "channel", 128)?;
    uuid::Uuid::parse_str(&channel_id)
        .map_err(|_| CliError::Usage(format!("invalid channel UUID: {channel_id}")))?;
    let request = CreateAgentDraft {
        channel_id: channel_id.clone(),
        display_name: required(draft.display_name, "display name", MAX_NAME_CHARS)?,
        system_prompt: required(draft.system_prompt, "system prompt", MAX_PROMPT_CHARS)?,
    };
    build(
        keys,
        owner,
        channel_id,
        AGENT_REQUEST_KIND,
        "create",
        request,
    )
}

pub fn build_update(
    keys: &Keys,
    owner: &PublicKey,
    draft: UpdateAgentDraft,
) -> Result<BuiltDraftRequest, CliError> {
    let channel_id = required(draft.channel_id, "channel", 128)?;
    uuid::Uuid::parse_str(&channel_id)
        .map_err(|_| CliError::Usage(format!("invalid channel UUID: {channel_id}")))?;
    let respond_to = optional(draft.respond_to, "respond-to")?;
    if respond_to
        .as_deref()
        .is_some_and(|value| value != "owner-only" && value != "anyone")
    {
        return Err(CliError::Usage(
            "respond-to must be owner-only or anyone".into(),
        ));
    }
    let request = UpdateAgentDraft {
        channel_id: channel_id.clone(),
        agent_name: required(draft.agent_name, "agent name", MAX_NAME_CHARS)?,
        display_name: optional(draft.display_name, "display name")?,
        system_prompt: draft
            .system_prompt
            .map(|value| required(value, "system prompt", MAX_PROMPT_CHARS))
            .transpose()?,
        runtime: optional(draft.runtime, "runtime")?,
        provider: optional(draft.provider, "provider")?,
        model: optional(draft.model, "model")?,
        respond_to,
    };
    if request.display_name.is_none()
        && request.system_prompt.is_none()
        && request.runtime.is_none()
        && request.provider.is_none()
        && request.model.is_none()
        && request.respond_to.is_none()
    {
        return Err(CliError::Usage(
            "include at least one field to update".into(),
        ));
    }
    build(
        keys,
        owner,
        channel_id,
        AGENT_REQUEST_KIND,
        "update",
        request,
    )
}

pub fn build_project_channel(
    keys: &Keys,
    owner: &PublicKey,
    draft: CreateProjectChannelDraft,
) -> Result<BuiltDraftRequest, CliError> {
    let home_channel_id = required(draft.home_channel_id, "home channel", 128)?;
    uuid::Uuid::parse_str(&home_channel_id)
        .map_err(|_| CliError::Usage(format!("invalid channel UUID: {home_channel_id}")))?;
    let visibility = required(draft.visibility, "visibility", 16)?;
    if visibility != "open" && visibility != "private" {
        return Err(CliError::Usage("visibility must be open or private".into()));
    }
    if draft.ttl_seconds == Some(0) {
        return Err(CliError::Usage("ttl must be greater than zero".into()));
    }
    let request = CreateProjectChannelDraft {
        home_channel_id: home_channel_id.clone(),
        name: required(draft.name, "name", MAX_NAME_CHARS)?,
        description: draft
            .description
            .map(|value| required(value, "description", 2_048))
            .transpose()?,
        visibility,
        ttl_seconds: draft.ttl_seconds,
        template_name: optional(draft.template_name, "template")?,
    };
    build(
        keys,
        owner,
        home_channel_id,
        PROJECT_CHANNEL_REQUEST_KIND,
        "create",
        request,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use buzz_core::observer::{decrypt_observer_payload, OBSERVER_AGENT_TAG};

    const CHANNEL: &str = "7c07e659-3610-42f4-9a5e-1e9973c09da9";

    #[test]
    fn create_is_owner_encrypted_and_matches_desktop_contract() {
        let agent = Keys::generate();
        let owner = Keys::generate();
        let built = build_create(
            &agent,
            &owner.public_key(),
            CreateAgentDraft {
                channel_id: CHANNEL.into(),
                display_name: "Research helper".into(),
                system_prompt: "Find sources.".into(),
            },
        )
        .unwrap();

        assert_eq!(built.event.kind.as_u16(), 14_201);
        let tags: Vec<Vec<String>> = built
            .event
            .tags
            .iter()
            .map(|tag| tag.as_slice().to_vec())
            .collect();
        assert!(tags
            .iter()
            .any(|tag| tag == &["p", &owner.public_key().to_hex()]));
        assert!(tags
            .iter()
            .any(|tag| tag == &[OBSERVER_AGENT_TAG, &agent.public_key().to_hex()]));
        assert!(tags.iter().any(|tag| tag == &["h", CHANNEL]));
        assert!(tags.iter().any(|tag| tag == &["r", &built.request_id]));
        assert!(tags.iter().any(|tag| tag == &["v", "1"]));
        buzz_core::agent_drafts::validate_request(&built.event).unwrap();

        let payload: serde_json::Value = decrypt_observer_payload(&owner, &built.event).unwrap();
        assert_eq!(payload["kind"], AGENT_REQUEST_KIND);
        assert_eq!(payload["channelId"], CHANNEL);
        assert_eq!(payload["payload"]["type"], AGENT_REQUEST_KIND);
        assert_eq!(payload["payload"]["action"], "create");
        assert_eq!(
            payload["payload"]["request"]["displayName"],
            "Research helper"
        );
        assert!(payload["payload"]["request"].get("runtime").is_none());
        assert!(payload["payload"]["request"].get("respondTo").is_none());
    }

    #[test]
    fn update_requires_a_change() {
        let error = build_update(
            &Keys::generate(),
            &Keys::generate().public_key(),
            UpdateAgentDraft {
                channel_id: CHANNEL.into(),
                agent_name: "Scout".into(),
                display_name: None,
                system_prompt: None,
                runtime: None,
                provider: None,
                model: None,
                respond_to: None,
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("at least one field"));
    }

    #[test]
    fn create_rejects_invalid_channel() {
        let error = build_create(
            &Keys::generate(),
            &Keys::generate().public_key(),
            CreateAgentDraft {
                channel_id: "general".into(),
                display_name: "Scout".into(),
                system_prompt: "Help".into(),
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("invalid channel UUID"));
    }

    #[test]
    fn project_channel_request_is_owner_encrypted() {
        let agent = Keys::generate();
        let owner = Keys::generate();
        let built = build_project_channel(
            &agent,
            &owner.public_key(),
            CreateProjectChannelDraft {
                home_channel_id: CHANNEL.into(),
                name: "release-planning".into(),
                description: Some("Coordinate the next release.".into()),
                visibility: "open".into(),
                ttl_seconds: None,
                template_name: Some("Release team".into()),
            },
        )
        .unwrap();

        let payload: serde_json::Value = decrypt_observer_payload(&owner, &built.event).unwrap();
        assert_eq!(payload["kind"], PROJECT_CHANNEL_REQUEST_KIND);
        assert_eq!(payload["channelId"], CHANNEL);
        assert_eq!(payload["payload"]["type"], PROJECT_CHANNEL_REQUEST_KIND);
        assert_eq!(payload["payload"]["action"], "create");
        assert_eq!(payload["payload"]["request"]["homeChannelId"], CHANNEL);
        assert_eq!(
            payload["payload"]["request"]["templateName"],
            "Release team"
        );
    }
}

fn outbox_path(
    relay: &str,
    keys: &Keys,
    owner: &PublicKey,
    request_id: &str,
) -> Result<std::path::PathBuf, CliError> {
    use sha2::{Digest, Sha256};
    let id = uuid::Uuid::parse_str(request_id).map_err(|e| CliError::Usage(e.to_string()))?;
    let scope = format!(
        "{}:{}:{}",
        relay.trim_end_matches('/'),
        keys.public_key().to_hex(),
        owner.to_hex()
    );
    let digest = hex::encode(Sha256::digest(scope.as_bytes()));
    let root =
        dirs::data_local_dir().ok_or_else(|| CliError::Other("no local data directory".into()))?;
    Ok(root
        .join("buzz/draft-outbox")
        .join(digest)
        .join(format!("{id}.json")))
}

/// Retain only owner-encrypted signed bytes, before any network request.
pub fn retain_outbox(
    relay: &str,
    keys: &Keys,
    owner: &PublicKey,
    built: &BuiltDraftRequest,
) -> Result<(), CliError> {
    let path = outbox_path(relay, keys, owner, &built.request_id)?;
    retain_outbox_at(&path, &built.event)
}
fn retain_outbox_at(path: &std::path::Path, event: &Event) -> Result<(), CliError> {
    use std::io::Write;
    let parent = path
        .parent()
        .ok_or_else(|| CliError::Other("invalid outbox path".into()))?;
    std::fs::create_dir_all(parent).map_err(|e| CliError::Other(e.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| CliError::Other(e.to_string()))?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&path)
        .map_err(|e| CliError::Other(e.to_string()))?;
    let bytes = serde_json::to_vec(event).map_err(|e| CliError::Other(e.to_string()))?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|e| CliError::Other(e.to_string()))?;
    std::fs::File::open(parent)
        .and_then(|f| f.sync_all())
        .map_err(|e| CliError::Other(e.to_string()))?;
    Ok(())
}

/// Reload the exact signed ciphertext in the current relay, agent and owner scope.
pub fn load_outbox(
    relay: &str,
    keys: &Keys,
    owner: &PublicKey,
    request_id: &str,
) -> Result<Event, CliError> {
    let bytes = std::fs::read(outbox_path(relay, keys, owner, request_id)?)
        .map_err(|e| CliError::Other(e.to_string()))?;
    let event: Event =
        serde_json::from_slice(&bytes).map_err(|e| CliError::Other(e.to_string()))?;
    event.verify().map_err(|e| CliError::Other(e.to_string()))?;
    let route = buzz_core::agent_drafts::validate_request(&event).map_err(CliError::Other)?;
    if route.owner != *owner
        || route.agent != keys.public_key()
        || route.request_id.to_string() != request_id
    {
        return Err(CliError::Other("outbox request scope mismatch".into()));
    }
    Ok(event)
}

#[cfg(test)]
mod outbox_tests {
    use super::*;
    #[test]
    fn retained_ciphertext_survives_restart_and_retries_are_identical() {
        let agent = Keys::generate();
        let owner = Keys::generate();
        let built = build_create(
            &agent,
            &owner.public_key(),
            CreateAgentDraft {
                channel_id: uuid::Uuid::new_v4().to_string(),
                display_name: "Fixture".into(),
                system_prompt: "synthetic-private-prompt".into(),
            },
        )
        .unwrap();
        let dir = std::env::temp_dir().join(format!("buzz-draft-test-{}", uuid::Uuid::new_v4()));
        let path = dir.join("request.json");
        retain_outbox_at(&path, &built.event).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let replay: Event = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(replay, built.event);
        assert_eq!(serde_json::to_vec(&replay).unwrap(), bytes);
        assert!(!String::from_utf8(bytes)
            .unwrap()
            .contains("synthetic-private-prompt"));
        assert!(retain_outbox_at(&path, &built.event).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}
