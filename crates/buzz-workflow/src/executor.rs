//! Sequential workflow executor.
//!
//! Responsibilities:
//! - Template variable resolution (`{{trigger.X}}`, `{{steps.ID.output.X}}`)
//! - Condition evaluation (`if:` expressions via `evalexpr`)
//! - Sequential step dispatch
//! - Execution trace updates in DB
//!
//! Action dispatch uses placeholder implementations that log intent.
//! Real event emission is wired in WF-07/08 (relay integration).

use std::collections::HashMap;

use buzz_core::tenant::CommunityId;
use buzz_db::workflow_approval::{
    ApprovalActionSummary, ApprovalRequestPayload, ApprovalRole, CanonicalApprovalPolicy,
};
use chrono::{DateTime, TimeDelta, Utc};
use evalexpr::HashMapContext;
use nostr::ToBech32;
use serde_json::Value as JsonValue;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::error::WorkflowError;
use crate::schema::{ActionDef, Step, WorkflowDef};
use crate::WorkflowEngine;

/// Data extracted from the triggering event, passed to every step.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct TriggerContext {
    /// Message content (message_posted trigger).
    pub text: String,
    /// Pubkey of the event author (hex string).
    pub author: String,
    /// Channel UUID as string.
    pub channel_id: String,
    /// Unix timestamp of the triggering event (as string for template use).
    pub timestamp: String,
    /// Emoji name (reaction_added trigger).
    pub emoji: String,
    /// Event ID of the triggering message (hex string).
    pub message_id: String,
    /// Arbitrary webhook body fields (webhook trigger). Top-level fields,
    /// flattened to strings.
    pub webhook_fields: HashMap<String, String>,
    /// Full parsed webhook body preserved for nested access by dotted path.
    /// `None` for non-webhook triggers.
    #[serde(default)]
    pub webhook_body: Option<JsonValue>,
}

impl TriggerContext {
    /// Look up a trigger field by name.
    ///
    /// Returns `Some` for known fields; for webhook triggers, also checks
    /// `webhook_fields`, then walks the preserved body for dotted paths
    /// (`trigger.commit.sha`). `None` for unknown names.
    ///
    /// Exact top-level webhook fields keep first claim, including names that
    /// contain dots. The body walk is the fallback when no literal flattened
    /// field exists, preserving definitions written before nested access.
    ///
    /// Returns an owned `String` (not a `&str`) because a nested body walk
    /// must stringify numbers and booleans that are not stored as text.
    pub fn get_field(&self, name: &str) -> Option<String> {
        match name {
            "text" => Some(self.text.clone()),
            "author" => Some(self.author.clone()),
            "channel_id" => Some(self.channel_id.clone()),
            "timestamp" => Some(self.timestamp.clone()),
            "emoji" => Some(self.emoji.clone()),
            "message_id" => Some(self.message_id.clone()),
            other => {
                if let Some(v) = self.webhook_fields.get(other) {
                    return Some(v.clone());
                }
                if other.contains('.') {
                    if let Some(body) = &self.webhook_body {
                        return json_path_to_str(body, other);
                    }
                }
                None
            }
        }
    }
}

/// Resolve a dotted path against a JSON tree and stringify the value at it.
///
/// Segments are split on `.`. Object keys are looked up by exact name; array
/// segments must be ASCII digits and index into the array. Returns `None` for
/// a missing segment, a non-object/non-array intermediate, or an out-of-range
/// index. The final value uses the same string conversion as the rest of the
/// trigger context.
fn json_path_to_str(body: &JsonValue, dotted: &str) -> Option<String> {
    json_path_to_value(body, dotted).map(json_to_string)
}

/// Resolve a dotted path against a JSON tree and return the raw value at it.
///
/// Shares the walking rules with [`json_path_to_str`]; the caller decides
/// whether to stringify (templates) or convert to an evalexpr value
/// (conditions).
fn json_path_to_value<'a>(body: &'a JsonValue, dotted: &str) -> Option<&'a JsonValue> {
    let mut current = body;
    for key in dotted.split('.') {
        if key.is_empty() {
            return None;
        }
        match current {
            JsonValue::Object(map) => {
                let next = map.get(key)?;
                current = next;
            }
            JsonValue::Array(items) => {
                if !key.chars().all(|c| c.is_ascii_digit()) {
                    return None;
                }
                let idx = key.parse().unwrap_or(usize::MAX);
                if idx < items.len() {
                    current = &items[idx];
                } else {
                    return None;
                }
            }
            _other => return None,
        }
    }
    Some(current)
}

/// Convert a dotted-path body value to an evalexpr value (for `body_path`).
fn json_path_to_eval(body: &JsonValue, dotted: &str) -> Option<evalexpr::Value> {
    json_path_to_value(body, dotted).map(json_value_to_eval)
}

/// Resolve `{{trigger.X}}` and `{{steps.ID.output.X}}` placeholders in a string.
///
/// Supports filters:
/// - `| truncate(N)` — truncate to N characters
/// - `| npub` — encode a hex pubkey as its full bech32 `npub` (non-pubkey
///   values pass through unchanged); `truncate_pubkey` is a legacy alias
///
/// Unknown `{{keys}}` are left as literal text (no error, no substitution).
pub fn resolve_template(
    template: &str,
    trigger_ctx: &TriggerContext,
    step_outputs: &HashMap<String, JsonValue>,
) -> Result<String, WorkflowError> {
    if !template.contains("{{") {
        return Ok(template.to_owned());
    }

    let mut result = String::with_capacity(template.len());
    let mut remaining = template;

    while let Some(start) = remaining.find("{{") {
        result.push_str(&remaining[..start]);
        remaining = &remaining[start + 2..];

        let end = match remaining.find("}}") {
            Some(e) => e,
            None => {
                // Unclosed `{{` — emit literally and stop.
                result.push_str("{{");
                result.push_str(remaining);
                return Ok(result);
            }
        };

        let expr = remaining[..end].trim();
        remaining = &remaining[end + 2..];

        // Split on `|` to extract filters.
        let mut parts = expr.splitn(2, '|');
        let var_path = parts.next().unwrap_or("").trim();
        let filter = parts.next().map(|s| s.trim());

        let raw_value = resolve_variable(var_path, trigger_ctx, step_outputs);

        let value = match (raw_value, filter) {
            (Some(v), Some(f)) => apply_filter(v, f)?,
            (Some(v), None) => v,
            (None, _) => {
                // Unknown variable — emit the original `{{expr}}` literally.
                result.push_str("{{");
                result.push_str(expr);
                result.push_str("}}");
                continue;
            }
        };

        result.push_str(&value);
    }

    result.push_str(remaining);
    Ok(result)
}

/// Resolve a single variable path to its string value.
fn resolve_variable(
    path: &str,
    trigger_ctx: &TriggerContext,
    step_outputs: &HashMap<String, JsonValue>,
) -> Option<String> {
    if let Some(field) = path.strip_prefix("trigger.") {
        return trigger_ctx.get_field(field);
    }

    // Pattern: `steps.STEP_ID.output.FIELD`
    if let Some(rest) = path.strip_prefix("steps.") {
        let mut parts = rest.splitn(3, '.');
        let step_id = parts.next()?;
        let middle = parts.next()?; // must be "output"
        let field = parts.next()?;

        if middle != "output" {
            return None;
        }

        let output = step_outputs.get(step_id)?;
        return json_get_str(output, field);
    }

    None
}

/// Navigate a JSON value by a single key and return it as a string.
fn json_get_str(value: &JsonValue, key: &str) -> Option<String> {
    match value {
        JsonValue::Object(map) => {
            let v = map.get(key)?;
            Some(json_to_string(v))
        }
        _ => None,
    }
}

/// Convert a JSON value to a plain string for template substitution.
fn json_to_string(v: &JsonValue) -> String {
    match v {
        JsonValue::String(s) => s.clone(),
        JsonValue::Bool(b) => b.to_string(),
        JsonValue::Number(n) => n.to_string(),
        JsonValue::Null => String::new(),
        other => other.to_string(),
    }
}

/// Apply a filter expression to a resolved value.
fn apply_filter(value: String, filter: &str) -> Result<String, WorkflowError> {
    let filter = filter.trim();

    if let Some(inner) = filter
        .strip_prefix("truncate(")
        .and_then(|s| s.strip_suffix(')'))
    {
        let n: usize = inner.trim().parse().map_err(|_| {
            WorkflowError::TemplateError(format!("truncate() requires a number, got: {inner}"))
        })?;
        let truncated: String = value.chars().take(n).collect();
        return Ok(truncated);
    }

    // `npub` (alias `truncate_pubkey`): full bech32 npub — truncated prefixes are grindable.
    if filter == "npub" || filter == "truncate_pubkey" {
        if let Ok(pk) = nostr::PublicKey::from_hex(&value) {
            return Ok(pk.to_bech32().unwrap_or(value));
        }
        return Ok(value);
    }

    Err(WorkflowError::TemplateError(format!(
        "unknown filter: {filter}"
    )))
}

/// Build an `evalexpr::HashMapContext` from trigger context and step outputs.
///
/// Variable names use underscores (not dots) because `evalexpr` does not
/// support dotted identifiers:
///
/// | YAML reference                    | evalexpr variable         |
/// |-----------------------------------|---------------------------|
/// | `trigger.text`                    | `trigger_text`            |
/// | `trigger.author`                  | `trigger_author`          |
/// | `trigger.channel_id`              | `trigger_channel_id`      |
/// | `trigger.timestamp`               | `trigger_timestamp`       |
/// | `trigger.emoji`                   | `trigger_emoji`           |
/// | `trigger.message_id`              | `trigger_message_id`      |
/// | `steps.STEP_ID.output.FIELD`      | `steps_STEP_ID_output_FIELD` |
///
/// Also registers string helper functions that the `cron` crate's `evalexpr` v11
/// does not include by default:
/// - `str_contains(haystack, needle)` → bool
/// - `str_starts_with(s, prefix)` → bool
/// - `str_ends_with(s, suffix)` → bool
/// - `str_len(s)` → int
pub fn build_eval_context(
    trigger_ctx: &TriggerContext,
    step_outputs: &HashMap<String, JsonValue>,
) -> Result<HashMapContext, WorkflowError> {
    use evalexpr::*;

    let mut ctx = HashMapContext::new();

    // evalexpr v11 does not ship str_contains / str_starts_with / str_ends_with.
    // Register them as custom functions so workflow YAML can use them.

    ctx.set_function(
        "str_contains".into(),
        Function::new(|args| {
            let args = args.as_fixed_len_tuple(2)?;
            let haystack = args[0].as_string()?;
            let needle = args[1].as_string()?;
            Ok(Value::Boolean(haystack.contains(needle.as_str())))
        }),
    )
    .map_err(|e| WorkflowError::ConditionError(e.to_string()))?;

    ctx.set_function(
        "str_starts_with".into(),
        Function::new(|args| {
            let args = args.as_fixed_len_tuple(2)?;
            let s = args[0].as_string()?;
            let prefix = args[1].as_string()?;
            Ok(Value::Boolean(s.starts_with(prefix.as_str())))
        }),
    )
    .map_err(|e| WorkflowError::ConditionError(e.to_string()))?;

    ctx.set_function(
        "str_ends_with".into(),
        Function::new(|args| {
            let args = args.as_fixed_len_tuple(2)?;
            let s = args[0].as_string()?;
            let suffix = args[1].as_string()?;
            Ok(Value::Boolean(s.ends_with(suffix.as_str())))
        }),
    )
    .map_err(|e| WorkflowError::ConditionError(e.to_string()))?;

    ctx.set_function(
        "str_len".into(),
        Function::new(|arg| {
            let s = arg.as_string()?;
            Ok(Value::Int(s.len() as i64))
        }),
    )
    .map_err(|e| WorkflowError::ConditionError(e.to_string()))?;

    // Register webhook fields first as `trigger_FIELD` so that standard trigger
    // fields inserted below always take precedence and cannot be spoofed.
    for (key, val) in &trigger_ctx.webhook_fields {
        // Skip any key that would collide with a standard trigger_ or steps_ variable.
        if key.starts_with("trigger_") || key.starts_with("steps_") {
            continue;
        }
        let var_name = format!("trigger_{key}");
        ctx.set_value(var_name, Value::String(val.clone()))
            .map_err(|e| WorkflowError::ConditionError(e.to_string()))?;
    }

    // Register a `body_path()` helper so conditions can read nested webhook
    // fields. Templates refer to the same data as `{{trigger.a.b.c}}` (dotted
    // path); evalexpr cannot name dotted identifiers, so the condition
    // spelling is a function call: `body_path("a.b.c")`. Both spellings walk
    // the same preserved body tree, and the docs in this file state that
    // contract so the two languages do not drift. The helper reads only
    // `webhook_body`, never the standard trigger fields, so a nested object
    // named `trigger` or `steps` can never shadow the standard trigger_ or
    // steps_ variables.
    let body_snapshot = trigger_ctx
        .webhook_body
        .clone()
        .unwrap_or(serde_json::json!(null));
    // The flat fields snapshot lets body_path mirror get_field's precedence:
    // an exact top-level key wins, the tree is the fallback. This keeps one
    // webhook meaning the same thing in both languages.
    let flat_snapshot = trigger_ctx.webhook_fields.clone();
    ctx.set_function(
        "body_path".into(),
        Function::new(move |arg| {
            // Single-argument function: evalexpr passes the argument directly,
            // not as a one-element tuple, so match the str_len pattern.
            let path = arg.as_string()?;
            // Mirror get_field: check the flat map for the literal key first,
            // then walk the tree. A bare key keeps winning so existing
            // definitions that read a flattened dotted key are unchanged.
            let flat_value = flat_snapshot
                .get(path.as_str())
                .map(|v| Value::String(v.clone()));
            let value = flat_value.unwrap_or_else(|| {
                json_path_to_eval(&body_snapshot, path.as_str())
                    .unwrap_or(Value::String(String::new()))
            });
            Ok(value)
        }),
    )
    .map_err(|e| WorkflowError::ConditionError(e.to_string()))?;

    let trigger_fields = [
        ("trigger_text", trigger_ctx.text.as_str()),
        ("trigger_author", trigger_ctx.author.as_str()),
        ("trigger_channel_id", trigger_ctx.channel_id.as_str()),
        ("trigger_timestamp", trigger_ctx.timestamp.as_str()),
        ("trigger_emoji", trigger_ctx.emoji.as_str()),
        ("trigger_message_id", trigger_ctx.message_id.as_str()),
    ];

    for (name, val) in &trigger_fields {
        ctx.set_value((*name).into(), Value::String((*val).to_owned()))
            .map_err(|e| WorkflowError::ConditionError(e.to_string()))?;
    }

    for (step_id, output) in step_outputs {
        if let JsonValue::Object(map) = output {
            for (field, val) in map {
                let var_name = format!("steps_{step_id}_output_{field}");
                let eval_val = json_value_to_eval(val);
                ctx.set_value(var_name, eval_val)
                    .map_err(|e| WorkflowError::ConditionError(e.to_string()))?;
            }
        }
    }

    Ok(ctx)
}

/// Convert a `serde_json::Value` to an `evalexpr::Value`.
fn json_value_to_eval(v: &JsonValue) -> evalexpr::Value {
    use evalexpr::Value as EV;
    match v {
        JsonValue::String(s) => EV::String(s.clone()),
        JsonValue::Bool(b) => EV::Boolean(*b),
        JsonValue::Number(n) => {
            if let Some(i) = n.as_i64() {
                EV::Int(i)
            } else if let Some(f) = n.as_f64() {
                EV::Float(f)
            } else {
                EV::String(n.to_string())
            }
        }
        JsonValue::Null => EV::Empty,
        other => EV::String(other.to_string()),
    }
}

/// Maximum wall-clock time allowed for a single `evalexpr` evaluation.
///
/// `evalexpr` is not designed for adversarial input — a deeply nested or
/// recursive expression can spin indefinitely. We run the evaluation on a
/// blocking thread and impose a hard timeout.
const EVAL_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(100);

/// Evaluate a boolean `if:` expression against the current execution context.
///
/// Returns `true` if the step should run, `false` if it should be skipped.
///
/// The evaluation is wrapped in a [`tokio::time::timeout`] to prevent a
/// malicious or pathological expression from blocking a Tokio worker thread.
pub async fn evaluate_condition(
    expr: &str,
    trigger_ctx: &TriggerContext,
    step_outputs: &HashMap<String, JsonValue>,
) -> Result<bool, WorkflowError> {
    let ctx = build_eval_context(trigger_ctx, step_outputs)?;
    let expr_owned = expr.to_owned();

    // Bound expression complexity to prevent pathological evaluation times.
    // The spawn_blocking thread cannot be cancelled by tokio::time::timeout —
    // it will run to completion even after timeout. Length-limiting the expression
    // prevents worst-case O(2^n) evaluation paths.
    const MAX_EXPR_LEN: usize = 4096;
    if expr_owned.len() > MAX_EXPR_LEN {
        return Err(WorkflowError::ConditionError(format!(
            "condition expression exceeds {} byte limit",
            MAX_EXPR_LEN
        )));
    }

    let result = tokio::time::timeout(
        EVAL_TIMEOUT,
        tokio::task::spawn_blocking(move || evalexpr::eval_boolean_with_context(&expr_owned, &ctx)),
    )
    .await
    .map_err(|_| {
        WorkflowError::ConditionError(format!(
            "'{expr}': evaluation timed out after {}ms",
            EVAL_TIMEOUT.as_millis()
        ))
    })?
    .map_err(|e| WorkflowError::ConditionError(format!("'{expr}': eval task panicked: {e}")))?
    .map_err(|e| WorkflowError::ConditionError(format!("'{expr}': {e}")))?;

    Ok(result)
}

/// Resolve all template variables in a step's action fields.
///
/// Returns a new `ActionDef` with all `{{...}}` placeholders substituted.
pub fn resolve_step_templates(
    step: &Step,
    trigger_ctx: &TriggerContext,
    step_outputs: &HashMap<String, JsonValue>,
) -> Result<ActionDef, WorkflowError> {
    use ActionDef::*;

    let t = |s: &str| resolve_template(s, trigger_ctx, step_outputs);
    let t_opt = |s: &Option<String>| -> Result<Option<String>, WorkflowError> {
        match s {
            Some(v) => Ok(Some(t(v)?)),
            None => Ok(None),
        }
    };

    match &step.action {
        SendMessage { text, channel } => Ok(SendMessage {
            text: t(text)?,
            channel: t_opt(channel)?,
        }),
        SendDm { to, text } => Ok(SendDm {
            to: t(to)?,
            text: t(text)?,
        }),
        SetChannelTopic { topic } => Ok(SetChannelTopic { topic: t(topic)? }),
        AddReaction { emoji } => Ok(AddReaction { emoji: t(emoji)? }),
        CallWebhook {
            url,
            method,
            headers,
            body,
        } => {
            let resolved_headers = match headers {
                Some(h) => {
                    let mut out = std::collections::HashMap::new();
                    for (k, v) in h {
                        out.insert(k.clone(), t(v)?);
                    }
                    Some(out)
                }
                None => None,
            };
            Ok(CallWebhook {
                url: t(url)?,
                method: method.clone(),
                headers: resolved_headers,
                body: t_opt(body)?,
            })
        }
        RequestApproval {
            from,
            message,
            timeout,
        } => Ok(RequestApproval {
            from: t(from)?,
            message: t(message)?,
            timeout: timeout.clone(),
        }),
        Delay { duration } => Ok(Delay {
            duration: duration.clone(),
        }),
        Extract { from, matchers } => Ok(Extract {
            from: t(from)?,
            matchers: matchers.clone(),
        }),
        ReadState { key } => Ok(ReadState { key: t(key)? }),
        WriteState {
            key,
            value,
            expires_in,
            expected_revision,
        } => Ok(WriteState {
            key: t(key)?,
            value: t(value)?,
            expires_in: t(expires_in)?,
            expected_revision: t_opt(expected_revision)?,
        }),
    }
}

/// Result of dispatching a single step action.
#[derive(Debug)]
pub enum StepResult {
    /// Step completed normally. Output is stored in `step_outputs`.
    Completed(JsonValue),
    /// Step requests suspension (approval gate). Execution must pause.
    Suspended {
        /// Opaque compatibility handle for the pending in-process suspension.
        approval_token: String,
    },
    /// Step was skipped due to `if:` condition being false.
    Skipped,
}

fn resolve_send_message_channel(
    explicit_channel: Option<&str>,
    trigger_channel: &str,
    workflow_channel_id: Option<Uuid>,
) -> Result<String, WorkflowError> {
    let explicit_channel = explicit_channel
        .map(str::trim)
        .filter(|value| !value.is_empty());

    if let Some(workflow_channel_id) = workflow_channel_id {
        if let Some(explicit_channel) = explicit_channel {
            let override_channel_id = explicit_channel.parse::<Uuid>().map_err(|e| {
                WorkflowError::InvalidDefinition(format!(
                    "SendMessage: invalid channel override UUID: {e}"
                ))
            })?;
            if override_channel_id != workflow_channel_id {
                return Err(WorkflowError::InvalidDefinition(format!(
                    "SendMessage: channel override must match the workflow channel ({workflow_channel_id})"
                )));
            }
        }
        return Ok(workflow_channel_id.to_string());
    }

    if let Some(explicit_channel) = explicit_channel {
        let override_channel_id = explicit_channel.parse::<Uuid>().map_err(|e| {
            WorkflowError::InvalidDefinition(format!(
                "SendMessage: invalid channel override UUID: {e}"
            ))
        })?;
        return Ok(override_channel_id.to_string());
    }

    if trigger_channel.trim().is_empty() {
        return Err(WorkflowError::InvalidDefinition(
            "SendMessage: no channel_id available (trigger has no channel context and no channel override was specified)"
                .into(),
        ));
    }

    Ok(trigger_channel.trim().to_string())
}

/// Dispatch a resolved action and return its output.
///
/// For MVP, most actions log their intent and return a success output.
/// Real event emission is wired in WF-07/08 (relay integration).
///
/// `RequestApproval` returns `StepResult::Suspended` — the caller must
/// persist state and stop the execution loop.
///
/// `step_outputs` carries prior step outputs so the `Extract` action can
/// resolve its `from` field against variables from earlier steps.
pub async fn dispatch_action(
    step_id: &str,
    action: &ActionDef,
    engine: &WorkflowEngine,
    community_id: CommunityId,
    run_id: Uuid,
    trigger_ctx: &TriggerContext,
    step_outputs: &HashMap<String, JsonValue>,
) -> Result<StepResult, WorkflowError> {
    use ActionDef::*;

    match action {
        SendMessage { text, channel } => {
            // Look up workflow metadata for destination validation and
            // attribution, scoped to the run's community — the same run/workflow
            // UUID may exist in another community, so a bare-id lookup could
            // load the wrong row and drive a side effect under it.
            let wf_run = engine
                .db
                .get_workflow_run(community_id, run_id)
                .await
                .map_err(|e| {
                    WorkflowError::WebhookError(format!(
                        "SendMessage: failed to load workflow run {run_id}: {e}"
                    ))
                })?;
            let workflow = engine
                .db
                .get_workflow(community_id, wf_run.workflow_id)
                .await
                .map_err(|e| {
                    WorkflowError::WebhookError(format!(
                        "SendMessage: failed to load workflow {}: {e}",
                        wf_run.workflow_id
                    ))
                })?;
            let channel_id = resolve_send_message_channel(
                channel.as_deref(),
                &trigger_ctx.channel_id,
                workflow.channel_id,
            )?;
            let owner_pubkey_hex = hex::encode(&workflow.owner_pubkey);

            info!(
                run_id = %run_id,
                step = step_id,
                channel = %channel_id,
                "SendMessage → {channel_id}: {text}"
            );

            let event_id = engine
                .action_sink()?
                .send_message(community_id, &channel_id, text, &owner_pubkey_hex)
                .await
                .map_err(WorkflowError::from)?;

            Ok(StepResult::Completed(serde_json::json!({
                "sent": true,
                "event_id": event_id,
            })))
        }

        SendDm { to, text: _ } => {
            warn!(run_id = %run_id, step = step_id, "SendDm not yet implemented (to={to})");
            // TODO (WF-07): emit DM event.
            Err(WorkflowError::NotImplemented("SendDm".into()))
        }

        SetChannelTopic { topic: _ } => {
            warn!(run_id = %run_id, step = step_id, "SetChannelTopic not yet implemented");
            // TODO (WF-07): update channel topic via DB.
            Err(WorkflowError::NotImplemented("SetChannelTopic".into()))
        }

        AddReaction { emoji } => {
            info!(run_id = %run_id, step = step_id, "AddReaction → :{emoji}:");
            if trigger_ctx.message_id.is_empty() {
                return Err(WorkflowError::InvalidDefinition(
                    "AddReaction: no trigger.message_id available".into(),
                ));
            }

            let wf_run = engine
                .db
                .get_workflow_run(community_id, run_id)
                .await
                .map_err(|e| {
                    WorkflowError::WebhookError(format!(
                        "AddReaction: failed to load workflow run {run_id}: {e}"
                    ))
                })?;
            let workflow = engine
                .db
                .get_workflow(community_id, wf_run.workflow_id)
                .await
                .map_err(|e| {
                    WorkflowError::WebhookError(format!(
                        "AddReaction: failed to load workflow {}: {e}",
                        wf_run.workflow_id
                    ))
                })?;
            let channel_id =
                resolve_send_message_channel(None, &trigger_ctx.channel_id, workflow.channel_id)?;
            let owner_pubkey_hex = hex::encode(&workflow.owner_pubkey);

            let result = add_reaction_via_sink(
                engine.action_sink()?,
                community_id,
                &channel_id,
                &trigger_ctx.message_id,
                emoji,
                &owner_pubkey_hex,
            )
            .await?;
            Ok(StepResult::Completed(result))
        }

        CallWebhook {
            url,
            method,
            headers,
            body,
        } => {
            let method_str = method.as_deref().unwrap_or("POST");
            info!(run_id = %run_id, step = step_id, "CallWebhook → {method_str} {url}");

            #[cfg(feature = "reqwest")]
            {
                let result = call_webhook_impl(url, method_str, headers, body).await?;
                Ok(StepResult::Completed(result))
            }

            #[cfg(not(feature = "reqwest"))]
            {
                // reqwest not enabled — log and return placeholder.
                warn!(
                    run_id = %run_id, step = step_id,
                    "CallWebhook: reqwest feature not enabled, skipping HTTP call"
                );
                let _ = (headers, body); // suppress unused warnings
                Ok(StepResult::Completed(serde_json::json!({
                    "status": 0,
                    "body": null,
                    "skipped": true
                })))
            }
        }

        RequestApproval {
            from,
            message,
            timeout,
        } => {
            let expected_generation = engine
                .db
                .get_workflow_run(community_id, run_id)
                .await
                .map_err(|_| {
                    WorkflowError::Database("RequestApproval run state is unavailable".to_owned())
                })?
                .generation;
            let suspension = build_approval_suspension(
                step_id,
                from,
                message,
                timeout.as_deref(),
                expected_generation,
                Utc::now(),
            )?;
            info!(
                run_id = %run_id,
                step = step_id,
                timeout_seconds = suspension.timeout_secs,
                "RequestApproval"
            );
            let approval_token = Uuid::new_v4().to_string();
            engine.store_approval_suspension(
                approval_token.clone(),
                community_id,
                run_id,
                suspension,
            )?;
            Ok(StepResult::Suspended { approval_token })
        }

        Delay { duration } => {
            let secs = parse_duration_secs(duration)?;
            // Cap delay at 270 seconds (4.5 minutes) — must be less than default_timeout_secs (300s)
            // to avoid non-deterministic StepTimeout. Long delays (hours/days)
            // should use the scheduled resume pattern (future work: WF-09).
            const MAX_DELAY_SECS: u64 = 270;
            if secs > MAX_DELAY_SECS {
                return Err(WorkflowError::InvalidDefinition(format!(
                    "delay exceeds maximum of {MAX_DELAY_SECS} seconds (got {secs}s); \
                     use the scheduled resume pattern for long delays"
                )));
            }
            info!(run_id = %run_id, step = step_id, "Delay {duration} ({secs}s)");
            tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
            Ok(StepResult::Completed(
                serde_json::json!({ "slept_secs": secs }),
            ))
        }

        Extract { from, matchers } => {
            let out = run_extract_output(from, matchers, trigger_ctx, step_outputs)?;
            Ok(StepResult::Completed(serde_json::Value::Object(out)))
        }

        ReadState { key } => {
            validate_state_key(key)?;
            let entry = engine
                .db
                .read_workflow_state_for_run(community_id, run_id, key)
                .await?;

            Ok(StepResult::Completed(read_state_output(entry)))
        }

        WriteState {
            key,
            value,
            expires_in,
            expected_revision,
        } => {
            validate_state_key(key)?;
            validate_state_value(value)?;
            let expires_in_secs = parse_state_expiry(expires_in)?;
            let expected_revision = parse_expected_revision(expected_revision.as_deref())?;
            let outcome = engine
                .db
                .write_workflow_state(
                    community_id,
                    run_id,
                    step_id,
                    key,
                    value,
                    expires_in_secs as i64,
                    expected_revision,
                )
                .await?;

            Ok(StepResult::Completed(write_state_output(outcome)?))
        }
    }
}

const STATE_KEY_MAX_BYTES: usize = 512;
const STATE_VALUE_MAX_BYTES: usize = 64 * 1024;
const STATE_EXPIRY_MAX_SECS: u64 = 365 * 24 * 60 * 60;

fn validate_state_key(key: &str) -> Result<(), WorkflowError> {
    if key.is_empty() || key.len() > STATE_KEY_MAX_BYTES {
        return Err(WorkflowError::InvalidDefinition(format!(
            "state key must be 1..={STATE_KEY_MAX_BYTES} bytes (got {})",
            key.len()
        )));
    }
    Ok(())
}

fn validate_state_value(value: &str) -> Result<(), WorkflowError> {
    if value.len() > STATE_VALUE_MAX_BYTES {
        return Err(WorkflowError::InvalidDefinition(format!(
            "state value must be <={STATE_VALUE_MAX_BYTES} bytes (got {})",
            value.len()
        )));
    }
    Ok(())
}

fn parse_state_expiry(expires_in: &str) -> Result<u64, WorkflowError> {
    let expires_in = expires_in.trim();
    let seconds = if let Some(days) = expires_in.strip_suffix('d') {
        days.trim()
            .parse::<u64>()
            .map_err(|_| {
                WorkflowError::InvalidDefinition(format!(
                    "WriteState: invalid expires_in: {expires_in}"
                ))
            })?
            .checked_mul(24 * 60 * 60)
            .ok_or_else(|| {
                WorkflowError::InvalidDefinition(format!(
                    "WriteState: expires_in overflow: {expires_in}"
                ))
            })?
    } else {
        parse_duration_secs(expires_in)?
    };
    if !(1..=STATE_EXPIRY_MAX_SECS).contains(&seconds) {
        return Err(WorkflowError::InvalidDefinition(format!(
            "WriteState: expires_in must be 1s..=365d (got {seconds}s)"
        )));
    }
    Ok(seconds)
}

fn parse_expected_revision(revision: Option<&str>) -> Result<Option<&str>, WorkflowError> {
    let Some(revision) = revision else {
        return Ok(None);
    };
    let revision = revision.trim();
    if revision == "0" {
        return Ok(Some(revision));
    }

    let (incarnation, counter) = revision.split_once(':').ok_or_else(|| {
        WorkflowError::InvalidDefinition(
            "WriteState: expected_revision must be 0 or <uuid>:<counter>".into(),
        )
    })?;
    let incarnation = Uuid::parse_str(incarnation).map_err(|_| {
        WorkflowError::InvalidDefinition(
            "WriteState: expected_revision must contain a valid UUID".into(),
        )
    })?;
    let counter = counter.parse::<i64>().map_err(|_| {
        WorkflowError::InvalidDefinition(
            "WriteState: expected_revision counter must be a positive integer".into(),
        )
    })?;
    if counter <= 0 {
        return Err(WorkflowError::InvalidDefinition(
            "WriteState: expected_revision counter must be greater than zero".into(),
        ));
    }
    if format!("{incarnation}:{counter}") != revision {
        return Err(WorkflowError::InvalidDefinition(
            "WriteState: expected_revision must use canonical <uuid>:<counter> form".into(),
        ));
    }
    Ok(Some(revision))
}

fn read_state_output(entry: Option<buzz_db::WorkflowStateEntry>) -> JsonValue {
    match entry {
        Some(entry) => serde_json::json!({
            "found": true,
            "value": entry.value,
            "revision": entry.revision.to_string(),
        }),
        None => serde_json::json!({
            "found": false,
            "value": null,
            "revision": "0",
        }),
    }
}

fn write_state_output(
    outcome: buzz_db::WorkflowStateWriteOutcome,
) -> Result<JsonValue, WorkflowError> {
    use buzz_db::WorkflowStateWriteOutcome;

    match outcome {
        WorkflowStateWriteOutcome::Written { value, revision } => Ok(serde_json::json!({
            "written": true,
            "value": value,
            "revision": revision.to_string(),
        })),
        WorkflowStateWriteOutcome::Conflict {
            current_value,
            current_revision,
        } => Ok(serde_json::json!({
            "written": false,
            "value": current_value,
            "revision": current_revision
                .map(|revision| revision.to_string())
                .unwrap_or_else(|| "0".to_owned()),
        })),
        WorkflowStateWriteOutcome::LimitExceeded { limit } => Err(WorkflowError::Database(
            format!("WriteState: state limit exceeded: {limit:?}"),
        )),
        WorkflowStateWriteOutcome::RequestConflict => Err(WorkflowError::Database(
            "WriteState: this run and step were retried with different inputs".into(),
        )),
    }
}

/// Build the flat output map for an `extract` step.
///
/// Emits three flat keys per matcher: `<name>`, `<name>_found`,
/// `<name>_count`. Both consumers (build_eval_context for conditions,
/// json_get_str for templates) read exactly one level, so a nested
/// {value,found,count} object would never surface the flag where a condition
/// can test it. Flat keys keep the shared evaluators untouched and make
/// `steps_ID_output_<name>_found` reachable.
///
/// This is the production code path the dispatch arm calls; the unit test
/// calls it directly so the assertion depends on the real arm, not a copy.
fn run_extract_output(
    from: &str,
    matchers: &HashMap<String, String>,
    trigger_ctx: &TriggerContext,
    step_outputs: &HashMap<String, JsonValue>,
) -> Result<serde_json::Map<String, serde_json::Value>, WorkflowError> {
    let field_value = resolve_variable(from, trigger_ctx, step_outputs).unwrap_or_default();
    let mut out: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
    for (out_name, matcher_name) in matchers {
        let result = run_matcher(matcher_name, &field_value)?;
        out.insert(
            out_name.clone(),
            serde_json::to_value(&result.value).unwrap_or_default(),
        );
        out.insert(
            format!("{out_name}_found"),
            serde_json::to_value(result.found).unwrap_or_default(),
        );
        out.insert(
            format!("{out_name}_count"),
            serde_json::to_value(result.count).unwrap_or_default(),
        );
    }
    Ok(out)
}

/// A single matcher result: the captured value (empty if no match) plus a
/// boolean presence flag. The flag is what makes the handoff linter safe:
/// a step that finds nothing must not fail the run; the next step's
/// condition can test `<name>_found` and decide the correction path.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MatchResult {
    /// First match, or empty string when nothing matched.
    pub value: String,
    /// True when at least one match was found.
    pub found: bool,
    /// Total number of matches in the scanned field.
    pub count: usize,
}

/// Run a named purpose-built matcher against a field value.
///
/// Matchers are finite-state single passes over the input, never a general
/// regex engine. No backreferences, no alternation, no user-supplied pattern
/// — the inputs are bounded strings and the scanners terminate in linear
/// time. This is deliberate: a user-supplied regex against arbitrary message
/// text is a denial-of-service waiting to happen, and the conditions engine
/// already caps expression length and runs with a timeout.
fn run_matcher(name: &str, field: &str) -> Result<MatchResult, WorkflowError> {
    match name {
        // `wf_sha`: exactly 40 lowercase hex characters, matching the fleet
        // handoff protocol. Accepts nothing else (no uppercase, no prefixes),
        // because a linter that accepts what the watchdog rejects is worse
        // than no linter.
        "wf_sha" => {
            let count = count_sha_matches(field);
            let mut value = String::new();
            if count > 0 {
                value = find_first_sha(field).unwrap_or_default();
            }
            Ok(MatchResult {
                value,
                found: count > 0,
                count,
            })
        }
        // `wf_word`: a bounded word token (ASCII letters and digits, no
        // separators). First match plus count, matching the same shape.
        "wf_word" => {
            let count = count_word_matches(field);
            let mut value = String::new();
            if count > 0 {
                value = find_first_word(field).unwrap_or_default();
            }
            Ok(MatchResult {
                value,
                found: count > 0,
                count,
            })
        }
        other => Err(WorkflowError::InvalidDefinition(format!(
            "extract: unknown matcher '{other}' (expected wf_sha or wf_word)"
        ))),
    }
}

/// A lowercase-hex byte check: `0-9` or `a-f`. Used for SHA tokens.
fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
}

/// A token is a SHA candidate when it is exactly 40 lowercase hex bytes.
///
/// The fleet protocol is 40 lowercase hex. Uppercase does not match; a
/// linter that accepted what the watchdog rejects would be worse than none.
fn is_sha_token(token: &str) -> bool {
    token.len() == 40 && token.bytes().all(is_lower_hex)
}

/// Count SHA tokens in a field. Tokens are whitespace-delimited so a FROZEN
/// post carrying two 40-hex runs (one in prose, one in a pasted command)
/// counts both.
fn count_sha_matches(s: &str) -> usize {
    s.split_whitespace().filter(|t| is_sha_token(t)).count()
}

/// First SHA token, or `None` when the field has none.
fn find_first_sha(s: &str) -> Option<String> {
    s.split_whitespace().find_map(|t| {
        if is_sha_token(t) {
            Some(t.to_owned())
        } else {
            None
        }
    })
}

/// Count word tokens (whitespace-delimited, non-empty).
fn count_word_matches(s: &str) -> usize {
    s.split_whitespace().filter(|w| !w.is_empty()).count()
}

/// First word token, or `None` when the field is empty.
fn find_first_word(s: &str) -> Option<String> {
    s.split_whitespace().next().map(|w| w.to_owned())
}

const DEFAULT_APPROVAL_TIMEOUT: &str = "24h";

/// Bounded suspension state handed to run finalization.
#[derive(Debug, Clone, PartialEq)]
pub struct ApprovalSuspension {
    /// Stable identifier of the frozen approval step.
    pub(crate) step_id: String,
    /// Resolved caller-reviewed action summary.
    pub(crate) message: String,
    /// Run generation held before the gate transaction advances it.
    pub(crate) expected_generation: i64,
    /// Canonical immutable approval policy.
    pub(crate) policy: CanonicalApprovalPolicy,
    /// Parsed positive timeout used to derive `expires_at`.
    pub(crate) timeout_secs: u64,
    /// Clock instant used to derive the fixed expiry.
    pub(crate) created_at: DateTime<Utc>,
    /// Fixed expiry retained across an exact finalization replay.
    pub(crate) expires_at: DateTime<Utc>,
    /// Bounded summary safe to copy into the request outbox payload.
    pub(crate) action_summary: ApprovalActionSummary,
    /// Safe caller-owned portion of the request outbox payload.
    pub(crate) request_payload: ApprovalRequestPayload,
}

fn invalid_approval_policy() -> WorkflowError {
    WorkflowError::InvalidDefinition(
        "RequestApproval policy must be owner, admin, or a lowercase 64-hex pubkey".to_owned(),
    )
}

pub(crate) fn parse_approval_policy(
    policy: &str,
) -> Result<CanonicalApprovalPolicy, WorkflowError> {
    let (pubkeys, roles) = match policy {
        "owner" => (Vec::new(), vec![ApprovalRole::Owner]),
        "admin" => (Vec::new(), vec![ApprovalRole::Admin]),
        exact
            if exact.len() == 64
                && exact
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()) =>
        {
            let pubkey = hex::decode(exact).map_err(|_| invalid_approval_policy())?;
            (vec![pubkey], Vec::new())
        }
        _ => return Err(invalid_approval_policy()),
    };
    CanonicalApprovalPolicy::new(pubkeys, roles).map_err(|_| invalid_approval_policy())
}

fn approval_timeout_secs(timeout: Option<&str>) -> Result<u64, WorkflowError> {
    let timeout = timeout.unwrap_or(DEFAULT_APPROVAL_TIMEOUT);
    let seconds = parse_duration_secs(timeout).map_err(|_| {
        WorkflowError::InvalidDefinition(
            "RequestApproval timeout must be a positive duration".to_owned(),
        )
    })?;
    if seconds == 0 {
        return Err(WorkflowError::InvalidDefinition(
            "RequestApproval timeout must be a positive duration".to_owned(),
        ));
    }
    Ok(seconds)
}

fn approval_expires_at(
    now: DateTime<Utc>,
    timeout_secs: u64,
) -> Result<DateTime<Utc>, WorkflowError> {
    let seconds = i64::try_from(timeout_secs).map_err(|_| {
        WorkflowError::InvalidDefinition("RequestApproval timeout is out of range".to_owned())
    })?;
    let delta = TimeDelta::try_seconds(seconds).ok_or_else(|| {
        WorkflowError::InvalidDefinition("RequestApproval timeout is out of range".to_owned())
    })?;
    now.checked_add_signed(delta).ok_or_else(|| {
        WorkflowError::InvalidDefinition("RequestApproval expiry is out of range".to_owned())
    })
}

fn approval_request_payload(timeout_secs: u64) -> Result<ApprovalRequestPayload, WorkflowError> {
    ApprovalRequestPayload::new(serde_json::json!({
        "class": "approval_requested",
        "timeout_seconds": timeout_secs,
    }))
    .map_err(|_| WorkflowError::InvalidDefinition("RequestApproval payload is invalid".to_owned()))
}

fn build_approval_suspension(
    step_id: &str,
    policy: &str,
    message: &str,
    timeout: Option<&str>,
    expected_generation: i64,
    now: DateTime<Utc>,
) -> Result<ApprovalSuspension, WorkflowError> {
    let policy = parse_approval_policy(policy)?;
    let timeout_secs = approval_timeout_secs(timeout)?;
    let expires_at = approval_expires_at(now, timeout_secs)?;
    let action_summary = ApprovalActionSummary::new(message).map_err(|_| {
        WorkflowError::InvalidDefinition("RequestApproval message is invalid".to_owned())
    })?;
    let request_payload = approval_request_payload(timeout_secs)?;

    Ok(ApprovalSuspension {
        step_id: step_id.to_owned(),
        message: action_summary.as_str().to_owned(),
        expected_generation,
        policy,
        timeout_secs,
        created_at: now,
        expires_at,
        action_summary,
        request_payload,
    })
}

pub(crate) fn waiting_approval_trace(step_id: &str, step_index: i32) -> JsonValue {
    serde_json::json!({
        "step_id": step_id,
        "step_index": step_index,
        "status": "waiting_approval",
    })
}

pub(crate) fn validate_frozen_approval_step(
    def: &WorkflowDef,
    step_index: usize,
    trigger_ctx: &TriggerContext,
    step_outputs: &HashMap<String, JsonValue>,
    suspension: &ApprovalSuspension,
) -> Result<(), WorkflowError> {
    let step = def.steps.get(step_index).ok_or_else(|| {
        WorkflowError::InvalidDefinition(
            "RequestApproval suspension does not match the frozen definition".to_owned(),
        )
    })?;
    if step.id != suspension.step_id {
        return Err(WorkflowError::InvalidDefinition(
            "RequestApproval suspension does not match the frozen definition".to_owned(),
        ));
    }
    let resolved_action = resolve_step_templates(step, trigger_ctx, step_outputs)?;
    let ActionDef::RequestApproval {
        from,
        message,
        timeout,
    } = resolved_action
    else {
        return Err(WorkflowError::InvalidDefinition(
            "RequestApproval suspension does not match the frozen definition".to_owned(),
        ));
    };
    let policy = parse_approval_policy(&from)?;
    let timeout_secs = approval_timeout_secs(timeout.as_deref())?;
    let expires_at = approval_expires_at(suspension.created_at, timeout_secs)?;
    let request_payload = approval_request_payload(timeout_secs)?;
    if message != suspension.message
        || suspension.action_summary.as_str() != suspension.message
        || policy != suspension.policy
        || timeout_secs != suspension.timeout_secs
        || expires_at != suspension.expires_at
        || request_payload != suspension.request_payload
    {
        return Err(WorkflowError::InvalidDefinition(
            "RequestApproval suspension does not match the frozen definition".to_owned(),
        ));
    }
    Ok(())
}

/// Parse a duration string like "5m", "1h", "30s" into seconds.
///
/// Exposed as `pub(crate)` so `schema.rs` can use it for interval validation.
pub(crate) fn parse_duration_secs(duration: &str) -> Result<u64, WorkflowError> {
    let duration = duration.trim();
    if let Some(n) = duration.strip_suffix('h') {
        let hours: u64 = n.trim().parse().map_err(|_| {
            WorkflowError::InvalidDefinition(format!("invalid duration: {duration}"))
        })?;
        return hours.checked_mul(3600).ok_or_else(|| {
            WorkflowError::InvalidDefinition(format!("duration overflow: {duration}"))
        });
    }
    if let Some(n) = duration.strip_suffix('m') {
        let mins: u64 = n.trim().parse().map_err(|_| {
            WorkflowError::InvalidDefinition(format!("invalid duration: {duration}"))
        })?;
        return mins.checked_mul(60).ok_or_else(|| {
            WorkflowError::InvalidDefinition(format!("duration overflow: {duration}"))
        });
    }
    if let Some(n) = duration.strip_suffix('s') {
        let secs: u64 = n.trim().parse().map_err(|_| {
            WorkflowError::InvalidDefinition(format!("invalid duration: {duration}"))
        })?;
        return Ok(secs);
    }
    // Plain number — assume seconds.
    duration
        .parse()
        .map_err(|_| WorkflowError::InvalidDefinition(format!("invalid duration: {duration}")))
}

// is_private_ip is provided by buzz_core::network::is_private_ip

/// Resolve `host` to IP addresses and reject if any are private/reserved.
///
/// Uses the OS resolver (blocking, run on a threadpool via `spawn_blocking`).
/// Rejects the request if DNS resolution fails or returns zero addresses.
///
/// Returns the first validated IP address so the caller can pin DNS resolution
/// in the HTTP client, preventing DNS rebinding TOCTOU attacks.
#[cfg(feature = "reqwest")]
async fn check_ssrf(host: &str, port: u16) -> Result<std::net::IpAddr, WorkflowError> {
    let addr_str = format!("{host}:{port}");
    let addrs: Vec<std::net::IpAddr> = tokio::task::spawn_blocking(move || {
        use std::net::ToSocketAddrs;
        addr_str
            .to_socket_addrs()
            .map(|iter| iter.map(|sa| sa.ip()).collect::<Vec<_>>())
    })
    .await
    .map_err(|e| WorkflowError::WebhookError(format!("SSRF check task failed: {e}")))?
    .map_err(|e| WorkflowError::WebhookError(format!("DNS resolution failed: {e}")))?;

    if addrs.is_empty() {
        return Err(WorkflowError::WebhookError(
            "DNS resolution returned no addresses".into(),
        ));
    }

    debug!("Resolved webhook host '{}' → {:?}", host, addrs);

    for ip in &addrs {
        if buzz_core::network::is_private_ip(ip) {
            return Err(WorkflowError::WebhookError(format!(
                "SSRF blocked: '{host}' resolved to private/reserved address {ip}"
            )));
        }
    }

    Ok(addrs[0])
}

/// Maximum response body size for webhook calls (1 MiB).
#[cfg(feature = "reqwest")]
const WEBHOOK_MAX_RESPONSE_BYTES: usize = 1024 * 1024;

#[cfg(feature = "reqwest")]
async fn call_webhook_impl(
    url: &str,
    method: &str,
    headers: &Option<std::collections::HashMap<String, String>>,
    body: &Option<String>,
) -> Result<JsonValue, WorkflowError> {
    use reqwest::Client;
    use std::time::Duration;

    let parsed_url = reqwest::Url::parse(url)
        .map_err(|e| WorkflowError::WebhookError(format!("invalid URL: {e}")))?;

    let host = parsed_url
        .host_str()
        .ok_or_else(|| WorkflowError::WebhookError("URL has no host".into()))?;

    // Default ports: 443 for https, 80 for http.
    let port = parsed_url.port_or_known_default().unwrap_or(80);

    let safe_ip = check_ssrf(host, port).await?;

    // Client is built per-request because `resolve()` pins DNS for a specific host.
    // This disables connection pooling but is required for SSRF safety: without
    // pinning, reqwest performs its own DNS resolution which could return a
    // different address than the one validated above (DNS rebinding TOCTOU).
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        // A system proxy would resolve the original hostname itself, bypassing
        // the validated and pinned address above.
        .no_proxy()
        // Disable redirects — a redirect to an internal host bypasses the SSRF check.
        .redirect(reqwest::redirect::Policy::none())
        .resolve(host, std::net::SocketAddr::new(safe_ip, port))
        .build()
        .map_err(|e| WorkflowError::WebhookError(e.to_string()))?;

    let method_parsed = reqwest::Method::from_bytes(method.as_bytes())
        .map_err(|e| WorkflowError::WebhookError(e.to_string()))?;

    let mut req = client.request(method_parsed, url);

    if let Some(hdrs) = headers {
        for (k, v) in hdrs {
            req = req.header(k, v);
        }
    }

    if let Some(b) = body {
        req = req.body(b.clone());
    }

    let resp = req
        .send()
        .await
        .map_err(|e| WorkflowError::WebhookError(e.to_string()))?;

    let status = resp.status().as_u16();

    // Read incrementally to prevent OOM from a malicious server returning a
    // multi-GB payload. `resp.bytes()` would buffer the entire body before we
    // could check the size; chunked reading lets us abort early.
    let mut body_bytes = Vec::new();
    let mut resp = resp;
    loop {
        let chunk = resp
            .chunk()
            .await
            .map_err(|e| WorkflowError::WebhookError(format!("reading response body: {e}")))?;
        match chunk {
            Some(bytes) => {
                body_bytes.extend_from_slice(&bytes);
                if body_bytes.len() > WEBHOOK_MAX_RESPONSE_BYTES {
                    return Err(WorkflowError::WebhookError(format!(
                        "response body exceeds {} byte limit",
                        WEBHOOK_MAX_RESPONSE_BYTES
                    )));
                }
            }
            None => break,
        }
    }

    let body_text = String::from_utf8_lossy(&body_bytes).into_owned();

    Ok(serde_json::json!({
        "status": status,
        "body": body_text,
    }))
}

async fn add_reaction_via_sink(
    sink: &dyn crate::ActionSink,
    community_id: CommunityId,
    channel_id: &str,
    target_event_id: &str,
    emoji: &str,
    author_pubkey: &str,
) -> Result<JsonValue, WorkflowError> {
    let event_id = sink
        .add_reaction(
            community_id,
            channel_id,
            target_event_id,
            emoji,
            author_pubkey,
        )
        .await
        .map_err(WorkflowError::from)?;

    Ok(match event_id {
        Some(event_id) => serde_json::json!({
            "added": true,
            "event_id": event_id,
        }),
        None => serde_json::json!({
            "added": false,
            "duplicate": true,
        }),
    })
}

/// Rich return type from `execute_run` / `execute_from_step`.
///
/// Carries enough information for the caller to:
/// - Persist an immutable approval gate when suspended at a `RequestApproval` step.
/// - Update the run's execution trace and current step in the DB.
/// - Resume execution from the correct step after approval.
#[derive(Debug)]
pub struct ExecutionResult {
    /// Set when execution suspended at a `RequestApproval` step.
    /// `None` means the run completed normally.
    pub approval_token: Option<String>,
    /// Index of the step that suspended (or the total step count on completion).
    pub step_index: usize,
    /// Accumulated step outputs at the point of suspension or completion.
    pub step_outputs: HashMap<String, JsonValue>,
    /// Execution trace: one entry per completed/skipped step.
    pub trace: Vec<JsonValue>,
}

/// Execute a workflow run sequentially.
///
/// Steps run in order. Each step:
/// 1. Evaluates `if:` condition (skip if false).
/// 2. Resolves template variables in action fields.
/// 3. Dispatches the action.
/// 4. Stores the step output for use by later steps.
///
/// On `RequestApproval`: returns `ExecutionResult` with an opaque compatibility
/// handle. Caller must finalize the durable gate transaction.
///
/// Returns `ExecutionResult` with `approval_token = None` on normal completion.
///
/// Enforces `engine.config.max_concurrent` via a semaphore — returns
/// [`WorkflowError::CapacityExceeded`] immediately if all permits are taken.
/// Transitions the run to `Running` after acquiring a permit.
pub async fn execute_run(
    engine: &WorkflowEngine,
    community_id: CommunityId,
    run_id: Uuid,
    def: &WorkflowDef,
    trigger_ctx: &TriggerContext,
) -> Result<ExecutionResult, (WorkflowError, crate::error::PartialProgress)> {
    // Fail fast if all concurrency permits are in use — no queuing.
    let _permit = engine.run_semaphore.try_acquire().map_err(|_| {
        (
            WorkflowError::CapacityExceeded,
            crate::error::PartialProgress::default(),
        )
    })?;

    engine
        .db
        .update_workflow_run(
            community_id,
            run_id,
            buzz_db::workflow::RunStatus::Running,
            0,
            &serde_json::json!([]),
            None,
        )
        .await
        .map_err(|e| {
            (
                WorkflowError::from(e),
                crate::error::PartialProgress::default(),
            )
        })?;

    execute_steps(engine, community_id, run_id, def, trigger_ctx, 0, None).await
}

/// Resume execution from a specific step index (used for approval resume).
///
/// Acquires a concurrency permit from `engine.run_semaphore` before executing —
/// returns [`WorkflowError::CapacityExceeded`] immediately if all permits are
/// taken.
///
/// Transitions the run to `Running` after acquiring a permit, so that
/// approval-resumed runs correctly reflect their active state.
///
/// `initial_outputs` should be reconstructed from the execution trace before
/// calling this function on resume, so that steps after the resume point can
/// reference `{{steps.PREV_STEP.output.X}}` correctly.
pub async fn execute_from_step(
    engine: &WorkflowEngine,
    community_id: CommunityId,
    run_id: Uuid,
    def: &WorkflowDef,
    trigger_ctx: &TriggerContext,
    start_index: usize,
    initial_outputs: Option<HashMap<String, JsonValue>>,
) -> Result<ExecutionResult, (WorkflowError, crate::error::PartialProgress)> {
    // Fail fast if all concurrency permits are in use — no queuing.
    let _permit = engine.run_semaphore.try_acquire().map_err(|_| {
        (
            WorkflowError::CapacityExceeded,
            crate::error::PartialProgress::default(),
        )
    })?;

    // Mark run as Running now that we have a permit (resume from approval).
    // Preserve the existing execution trace from pre-approval steps.
    let existing_trace = match engine.db.get_workflow_run(community_id, run_id).await {
        Ok(r) => r.execution_trace,
        Err(e) => {
            warn!(
                run_id = %run_id,
                "Failed to read existing trace for resume — pre-approval trace will be lost: {e}"
            );
            serde_json::json!([])
        }
    };
    engine
        .db
        .update_workflow_run(
            community_id,
            run_id,
            buzz_db::workflow::RunStatus::Running,
            start_index as i32,
            &existing_trace,
            None,
        )
        .await
        .map_err(|e| {
            (
                WorkflowError::from(e),
                crate::error::PartialProgress::default(),
            )
        })?;

    execute_steps(
        engine,
        community_id,
        run_id,
        def,
        trigger_ctx,
        start_index,
        initial_outputs,
    )
    .await
}

/// Continue a run that a durable resume worker already claimed as `Running`.
///
/// The caller must acquire the run with the database status-and-generation
/// fence before calling this function. Unlike [`execute_from_step`], this does
/// not write the run status again, so a second worker cannot bypass that claim.
pub async fn execute_claimed_from_step(
    engine: &WorkflowEngine,
    community_id: CommunityId,
    run_id: Uuid,
    def: &WorkflowDef,
    trigger_ctx: &TriggerContext,
    start_index: usize,
    initial_outputs: HashMap<String, JsonValue>,
) -> Result<ExecutionResult, (WorkflowError, crate::error::PartialProgress)> {
    let _permit = engine.run_semaphore.try_acquire().map_err(|_| {
        (
            WorkflowError::CapacityExceeded,
            crate::error::PartialProgress::default(),
        )
    })?;

    execute_steps(
        engine,
        community_id,
        run_id,
        def,
        trigger_ctx,
        start_index,
        Some(initial_outputs),
    )
    .await
}

/// Internal: execute workflow steps starting from `start_index`, without
/// acquiring the semaphore. Called by both [`execute_run`] and
/// [`execute_from_step`] after they have already acquired a permit.
///
/// On error, returns `(WorkflowError, PartialProgress)` so callers can persist
/// the trace of steps completed before the failure.
async fn execute_steps(
    engine: &WorkflowEngine,
    community_id: CommunityId,
    run_id: Uuid,
    def: &WorkflowDef,
    trigger_ctx: &TriggerContext,
    start_index: usize,
    initial_outputs: Option<HashMap<String, JsonValue>>,
) -> Result<ExecutionResult, (WorkflowError, crate::error::PartialProgress)> {
    let mut step_outputs: HashMap<String, JsonValue> = initial_outputs.unwrap_or_default();
    let mut trace: Vec<JsonValue> = Vec::new();

    for (i, step) in def.steps.iter().enumerate() {
        if i < start_index {
            debug!(run_id = %run_id, step = %step.id, "Skipping already-executed step");
            continue;
        }

        if let Some(expr) = &step.if_expr {
            match evaluate_condition(expr, trigger_ctx, &step_outputs).await {
                Ok(true) => {
                    debug!(run_id = %run_id, step = %step.id, "Condition true — running step");
                }
                Ok(false) => {
                    info!(run_id = %run_id, step = %step.id, "Condition false — skipping step");
                    trace.push(serde_json::json!({
                        "step_id": step.id,
                        "status": "skipped",
                    }));
                    continue;
                }
                Err(e) => {
                    warn!(run_id = %run_id, step = %step.id, "Condition error: {e}");
                    let progress = crate::error::PartialProgress {
                        step_index: i,
                        trace,
                    };
                    return Err((e, progress));
                }
            }
        }

        let resolved_action = match resolve_step_templates(step, trigger_ctx, &step_outputs) {
            Ok(a) => a,
            Err(e) => {
                let progress = crate::error::PartialProgress {
                    step_index: i,
                    trace,
                };
                return Err((e, progress));
            }
        };

        let timeout_secs = step
            .timeout_secs
            .unwrap_or(engine.config.default_timeout_secs);
        let dispatch_result = tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs),
            dispatch_action(
                &step.id,
                &resolved_action,
                engine,
                community_id,
                run_id,
                trigger_ctx,
                &step_outputs,
            ),
        )
        .await;

        let result = match dispatch_result {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                let progress = crate::error::PartialProgress {
                    step_index: i,
                    trace,
                };
                return Err((e, progress));
            }
            Err(_timeout) => {
                let progress = crate::error::PartialProgress {
                    step_index: i,
                    trace,
                };
                return Err((
                    WorkflowError::StepTimeout {
                        step_id: step.id.clone(),
                        timeout_secs,
                    },
                    progress,
                ));
            }
        };

        match result {
            StepResult::Completed(output) => {
                debug!(run_id = %run_id, step = %step.id, "Step completed");
                trace.push(serde_json::json!({
                    "step_id": step.id,
                    "status": "completed",
                    "output": output,
                }));
                step_outputs.insert(step.id.clone(), output);
            }
            StepResult::Suspended { approval_token } => {
                info!(
                    run_id = %run_id, step = %step.id,
                    "Step suspended — awaiting approval"
                );
                return Ok(ExecutionResult {
                    approval_token: Some(approval_token),
                    step_index: i,
                    step_outputs,
                    trace,
                });
            }
            StepResult::Skipped => {
                debug!(run_id = %run_id, step = %step.id, "Step skipped");
                trace.push(serde_json::json!({
                    "step_id": step.id,
                    "status": "skipped",
                }));
            }
        }
    }

    info!(run_id = %run_id, "Workflow run completed");
    Ok(ExecutionResult {
        approval_token: None,
        step_index: def.steps.len(),
        step_outputs,
        trace,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action_sink::{ActionSink, ActionSinkError};
    use serde_json::json;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Mutex;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct ReactionCall {
        community_id: CommunityId,
        channel_id: String,
        target_event_id: String,
        emoji: String,
        author_pubkey: String,
    }

    #[derive(Default)]
    struct RecordingActionSink {
        reactions: Mutex<Vec<ReactionCall>>,
    }

    impl ActionSink for RecordingActionSink {
        fn send_message(
            &self,
            _community_id: CommunityId,
            _channel_id: &str,
            _text: &str,
            _author_pubkey: &str,
        ) -> Pin<Box<dyn Future<Output = Result<String, ActionSinkError>> + Send + '_>> {
            Box::pin(async { unreachable!("send_message is not part of this regression") })
        }

        fn add_reaction(
            &self,
            community_id: CommunityId,
            channel_id: &str,
            target_event_id: &str,
            emoji: &str,
            author_pubkey: &str,
        ) -> Pin<Box<dyn Future<Output = Result<Option<String>, ActionSinkError>> + Send + '_>>
        {
            self.reactions
                .lock()
                .expect("recording sink lock")
                .push(ReactionCall {
                    community_id,
                    channel_id: channel_id.to_owned(),
                    target_event_id: target_event_id.to_owned(),
                    emoji: emoji.to_owned(),
                    author_pubkey: author_pubkey.to_owned(),
                });
            Box::pin(async { Ok(Some("reaction-event-id".to_owned())) })
        }
    }

    #[test]
    fn public_result_compatibility_shapes_are_preserved() {
        let step_result = StepResult::Suspended {
            approval_token: "compatibility-handle".to_owned(),
        };
        let StepResult::Suspended { approval_token } = step_result else {
            panic!("expected suspended result");
        };
        let result = ExecutionResult {
            approval_token: Some(approval_token),
            step_index: 2,
            step_outputs: HashMap::new(),
            trace: Vec::new(),
        };
        assert_eq!(
            result.approval_token.as_deref(),
            Some("compatibility-handle")
        );
    }

    fn make_trigger() -> TriggerContext {
        TriggerContext {
            text: "P1 incident in production".to_owned(),
            author: "abc123def456".to_owned(),
            channel_id: "channel-uuid-here".to_owned(),
            timestamp: "1700000000".to_owned(),
            emoji: "fire".to_owned(),
            message_id: "event-id-hex".to_owned(),
            webhook_fields: HashMap::new(),
            webhook_body: None,
        }
    }

    #[tokio::test]
    async fn add_reaction_dispatches_to_action_sink_without_http() {
        let sink = RecordingActionSink::default();
        let community_id = CommunityId::from_uuid(Uuid::nil());

        let result = add_reaction_via_sink(
            &sink,
            community_id,
            "11111111-1111-1111-1111-111111111111",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "👍",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .await
        .expect("reaction should reach action sink");

        assert_eq!(
            result,
            json!({ "added": true, "event_id": "reaction-event-id" })
        );
        assert_eq!(
            sink.reactions
                .lock()
                .expect("recording sink lock")
                .as_slice(),
            &[ReactionCall {
                community_id,
                channel_id: "11111111-1111-1111-1111-111111111111".to_owned(),
                target_event_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_owned(),
                emoji: "👍".to_owned(),
                author_pubkey: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .to_owned(),
            }]
        );
    }

    #[test]
    fn resolve_trigger_text() {
        let ctx = make_trigger();
        let out = resolve_template("Alert: {{trigger.text}}", &ctx, &HashMap::new()).unwrap();
        assert_eq!(out, "Alert: P1 incident in production");
    }

    #[test]
    fn resolve_trigger_author() {
        let ctx = make_trigger();
        let out = resolve_template("By {{trigger.author}}", &ctx, &HashMap::new()).unwrap();
        assert_eq!(out, "By abc123def456");
    }

    #[test]
    fn resolve_step_output() {
        let ctx = make_trigger();
        let mut outputs = HashMap::new();
        outputs.insert("ask".to_owned(), json!({ "replied": "yes" }));
        let out = resolve_template("Reply: {{steps.ask.output.replied}}", &ctx, &outputs).unwrap();
        assert_eq!(out, "Reply: yes");
    }

    #[test]
    fn resolve_unknown_variable_left_literal() {
        let ctx = make_trigger();
        let out = resolve_template("{{unknown.var}}", &ctx, &HashMap::new()).unwrap();
        assert_eq!(out, "{{unknown.var}}");
    }

    #[test]
    fn resolve_truncate_filter() {
        let ctx = make_trigger();
        let out =
            resolve_template("{{trigger.text | truncate(5)}}", &ctx, &HashMap::new()).unwrap();
        assert_eq!(out, "P1 in");
        assert_eq!(out.chars().count(), 5);
    }

    #[test]
    fn resolve_npub_filter_encodes_hex_pubkey() {
        let mut ctx = make_trigger();
        ctx.author = "e17e5abf7b1dbd363f0ed6fbda2455609727b2555428dea251388c542cd2f03f".to_owned();
        let out = resolve_template("{{trigger.author | npub}}", &ctx, &HashMap::new()).unwrap();
        assert_eq!(
            out,
            "npub1u9l940mmrk7nv0cw6maa5fz4vztj0vj42s5dagj38zx9gtxj7qls94fpux"
        );
    }

    #[test]
    fn resolve_truncate_pubkey_is_alias_for_npub() {
        let mut ctx = make_trigger();
        ctx.author = "e17e5abf7b1dbd363f0ed6fbda2455609727b2555428dea251388c542cd2f03f".to_owned();
        let out = resolve_template(
            "{{trigger.author | truncate_pubkey}}",
            &ctx,
            &HashMap::new(),
        )
        .unwrap();
        assert_eq!(
            out,
            "npub1u9l940mmrk7nv0cw6maa5fz4vztj0vj42s5dagj38zx9gtxj7qls94fpux"
        );
    }

    #[test]
    fn resolve_no_templates_fast_path() {
        let ctx = make_trigger();
        let out = resolve_template("no templates here", &ctx, &HashMap::new()).unwrap();
        assert_eq!(out, "no templates here");
    }

    #[test]
    fn resolve_multiple_templates_in_one_string() {
        let ctx = make_trigger();
        let out = resolve_template(
            "{{trigger.author}} said: {{trigger.text}}",
            &ctx,
            &HashMap::new(),
        )
        .unwrap();
        assert_eq!(out, "abc123def456 said: P1 incident in production");
    }

    #[test]
    fn resolve_webhook_field() {
        let mut ctx = make_trigger();
        ctx.webhook_fields
            .insert("service".to_owned(), "api-gateway".to_owned());
        let out = resolve_template("Service: {{trigger.service}}", &ctx, &HashMap::new()).unwrap();
        assert_eq!(out, "Service: api-gateway");
    }

    #[tokio::test]
    async fn condition_true_when_text_contains_p1() {
        let ctx = make_trigger(); // text = "P1 incident in production"
        let result =
            evaluate_condition("str_contains(trigger_text, \"P1\")", &ctx, &HashMap::new())
                .await
                .unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn condition_false_when_text_does_not_contain_p1() {
        let mut ctx = make_trigger();
        ctx.text = "normal message".to_owned();
        let result =
            evaluate_condition("str_contains(trigger_text, \"P1\")", &ctx, &HashMap::new())
                .await
                .unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn condition_or_expression() {
        let ctx = make_trigger(); // text contains "P1"
        let result = evaluate_condition(
            "str_contains(trigger_text, \"P1\") || str_contains(trigger_text, \"SEV1\")",
            &ctx,
            &HashMap::new(),
        )
        .await
        .unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn condition_step_output_bool() {
        let ctx = make_trigger();
        let mut outputs = HashMap::new();
        outputs.insert("request".to_owned(), json!({ "approved": true }));
        let result = evaluate_condition("steps_request_output_approved == true", &ctx, &outputs)
            .await
            .unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn condition_step_output_bool_false() {
        let ctx = make_trigger();
        let mut outputs = HashMap::new();
        outputs.insert("request".to_owned(), json!({ "approved": false }));
        let result = evaluate_condition("steps_request_output_approved == false", &ctx, &outputs)
            .await
            .unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn condition_invalid_expression_returns_error() {
        let ctx = make_trigger();
        let err = evaluate_condition("this is not valid evalexpr @@@@", &ctx, &HashMap::new())
            .await
            .unwrap_err();
        assert!(matches!(err, WorkflowError::ConditionError(_)));
    }

    #[tokio::test]
    async fn condition_exceeding_max_expr_len_is_rejected() {
        let ctx = make_trigger();
        // Construct an expression that exceeds MAX_EXPR_LEN (4096 bytes).
        let long_expr = "true || ".repeat(625); // 8 * 625 = 5000 bytes
        let err = evaluate_condition(&long_expr, &ctx, &HashMap::new())
            .await
            .unwrap_err();
        match &err {
            WorkflowError::ConditionError(msg) => {
                assert!(
                    msg.contains("exceeds") || msg.contains("limit"),
                    "expected 'exceeds' or 'limit' in error message, got: {msg}"
                );
            }
            other => panic!("expected ConditionError, got: {other:?}"),
        }
    }

    #[test]
    fn parse_duration_hours() {
        assert_eq!(parse_duration_secs("1h").unwrap(), 3600);
        assert_eq!(parse_duration_secs("2h").unwrap(), 7200);
    }

    #[test]
    fn parse_duration_minutes() {
        assert_eq!(parse_duration_secs("5m").unwrap(), 300);
        assert_eq!(parse_duration_secs("30m").unwrap(), 1800);
    }

    #[test]
    fn parse_duration_seconds() {
        assert_eq!(parse_duration_secs("10s").unwrap(), 10);
        assert_eq!(parse_duration_secs("60s").unwrap(), 60);
    }

    #[test]
    fn parse_duration_plain_number() {
        assert_eq!(parse_duration_secs("42").unwrap(), 42);
    }

    #[test]
    fn parse_duration_invalid() {
        assert!(parse_duration_secs("not-a-duration").is_err());
    }

    #[test]
    fn approval_policy_accepts_only_canonical_forms() {
        let owner = parse_approval_policy("owner").unwrap();
        assert_eq!(owner.roles(), &[ApprovalRole::Owner]);
        let admin = parse_approval_policy("admin").unwrap();
        assert_eq!(admin.roles(), &[ApprovalRole::Admin]);

        let exact_hex = "ab".repeat(32);
        let exact = parse_approval_policy(&exact_hex).unwrap();
        assert_eq!(exact.exact_pubkeys(), &[exact_hex]);

        let invalid = vec![
            String::new(),
            "Owner".to_owned(),
            " owner".to_owned(),
            "@release-manager".to_owned(),
            "release-manager".to_owned(),
            "moderator".to_owned(),
            "npub1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq".to_owned(),
            "AB".repeat(32),
            "a".repeat(63),
        ];
        for invalid in invalid {
            assert!(
                parse_approval_policy(&invalid).is_err(),
                "unexpectedly accepted {invalid:?}"
            );
        }
    }

    #[test]
    fn approval_timeout_defaults_and_fails_closed() {
        let now = DateTime::parse_from_rfc3339("2026-08-23T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let defaulted =
            build_approval_suspension("approve", "owner", "Ship release", None, 7, now).unwrap();
        assert_eq!(defaulted.timeout_secs, 24 * 60 * 60);
        assert_eq!(defaulted.expires_at, now + TimeDelta::hours(24));

        assert!(
            build_approval_suspension("approve", "owner", "Ship release", Some("0s"), 7, now)
                .is_err()
        );
        assert!(build_approval_suspension(
            "approve",
            "owner",
            "Ship release",
            Some("18446744073709551615h"),
            7,
            now,
        )
        .is_err());
        assert!(approval_expires_at(now, u64::MAX).is_err());
        assert!(approval_expires_at(DateTime::<Utc>::MAX_UTC, 1).is_err());
    }

    #[test]
    fn approval_request_payload_and_summary_are_safe() {
        let now = DateTime::parse_from_rfc3339("2026-08-23T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let suspension = build_approval_suspension(
            "approve_release",
            "admin",
            "Deploy release 2026.08.23",
            Some("1h"),
            3,
            now,
        )
        .unwrap();
        assert_eq!(suspension.message, "Deploy release 2026.08.23");
        assert_eq!(
            suspension.action_summary.as_str(),
            "Deploy release 2026.08.23"
        );
        assert_eq!(
            suspension.request_payload.as_value(),
            &json!({
                "class": "approval_requested",
                "timeout_seconds": 3_600,
            })
        );
        let changed_timeout = build_approval_suspension(
            "approve_release",
            "admin",
            "Deploy release 2026.08.23",
            Some("2h"),
            3,
            now,
        )
        .expect("valid approval suspension");
        assert_ne!(changed_timeout.request_payload, suspension.request_payload);
        let published = format!(
            "{} {}",
            suspension.action_summary.as_str(),
            suspension.request_payload.as_value()
        )
        .to_ascii_lowercase();
        for forbidden in [
            "token",
            "definition",
            "header",
            "secret",
            "credential",
            "step_outputs",
            "outputs",
        ] {
            assert!(!published.contains(forbidden));
        }
        assert!(build_approval_suspension(
            "approve_release",
            "admin",
            &"x".repeat(2_001),
            Some("1h"),
            3,
            now,
        )
        .is_err());
    }

    #[test]
    fn waiting_trace_has_only_the_bound_display_fields() {
        assert_eq!(
            waiting_approval_trace("approve_release", 2),
            json!({
                "step_id": "approve_release",
                "step_index": 2,
                "status": "waiting_approval",
            })
        );
    }

    #[test]
    fn structured_approval_suspension_matches_frozen_step() {
        let now = DateTime::parse_from_rfc3339("2026-08-23T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let suspension = build_approval_suspension(
            "approve",
            "owner",
            "Deploy P1 fix for abc123def456",
            Some("30m"),
            11,
            now,
        )
        .unwrap();
        assert_eq!(suspension.step_id, "approve");
        assert_eq!(suspension.expected_generation, 11);
        assert_eq!(suspension.timeout_secs, 1_800);
        assert_eq!(suspension.expires_at, now + TimeDelta::minutes(30));

        let (def, _) = crate::schema::parse_yaml(
            "name: Approval\ntrigger:\n  on: webhook\nsteps:\n  - id: approve\n    action: request_approval\n    from: owner\n    message: Deploy P1 fix for {{trigger.author}}\n    timeout: 30m\n",
        )
        .unwrap();
        let trigger = make_trigger();
        let outputs = HashMap::new();
        validate_frozen_approval_step(&def, 0, &trigger, &outputs, &suspension).unwrap();

        let changed_message = build_approval_suspension(
            "approve",
            "owner",
            "Deploy a different fix",
            Some("30m"),
            11,
            now,
        )
        .unwrap();
        assert!(
            validate_frozen_approval_step(&def, 0, &trigger, &outputs, &changed_message).is_err()
        );

        let changed_policy = build_approval_suspension(
            "approve",
            "admin",
            "Deploy P1 fix for abc123def456",
            Some("30m"),
            11,
            now,
        )
        .unwrap();
        assert!(
            validate_frozen_approval_step(&def, 0, &trigger, &outputs, &changed_policy).is_err()
        );

        let changed_timeout = build_approval_suspension(
            "approve",
            "owner",
            "Deploy P1 fix for abc123def456",
            Some("31m"),
            11,
            now,
        )
        .unwrap();
        assert!(
            validate_frozen_approval_step(&def, 0, &trigger, &outputs, &changed_timeout).is_err()
        );

        let mut changed_summary = suspension.clone();
        changed_summary.action_summary =
            ApprovalActionSummary::new("Deploy a different fix").expect("valid bounded summary");
        assert!(
            validate_frozen_approval_step(&def, 0, &trigger, &outputs, &changed_summary).is_err()
        );

        let mut changed_expiry = suspension.clone();
        changed_expiry.expires_at += TimeDelta::seconds(1);
        assert!(
            validate_frozen_approval_step(&def, 0, &trigger, &outputs, &changed_expiry).is_err()
        );

        let mut changed_payload = suspension.clone();
        changed_payload.request_payload = ApprovalRequestPayload::new(json!({
            "class": "approval_requested",
            "timeout_seconds": 1_801,
        }))
        .expect("safe bounded payload");
        assert!(
            validate_frozen_approval_step(&def, 0, &trigger, &outputs, &changed_payload).is_err()
        );
    }

    #[test]
    fn state_key_uses_utf8_byte_limits() {
        assert!(validate_state_key("a").is_ok());
        assert!(validate_state_key(&"a".repeat(STATE_KEY_MAX_BYTES)).is_ok());
        assert!(validate_state_key("").is_err());
        assert!(validate_state_key(&"a".repeat(STATE_KEY_MAX_BYTES + 1)).is_err());
        assert!(validate_state_key(&"é".repeat(STATE_KEY_MAX_BYTES / 2)).is_ok());
        assert!(validate_state_key(&"é".repeat(STATE_KEY_MAX_BYTES / 2 + 1)).is_err());
    }

    #[test]
    fn state_value_enforces_64_kib_bytes() {
        assert!(validate_state_value(&"a".repeat(STATE_VALUE_MAX_BYTES)).is_ok());
        assert!(validate_state_value(&"a".repeat(STATE_VALUE_MAX_BYTES + 1)).is_err());
        assert!(validate_state_value(&"é".repeat(STATE_VALUE_MAX_BYTES / 2)).is_ok());
        assert!(validate_state_value(&"é".repeat(STATE_VALUE_MAX_BYTES / 2 + 1)).is_err());
    }

    #[test]
    fn state_expiry_accepts_only_one_second_through_365_days() {
        assert_eq!(parse_state_expiry("1s").unwrap(), 1);
        assert_eq!(parse_state_expiry("365d").unwrap(), STATE_EXPIRY_MAX_SECS);
        assert!(parse_state_expiry("0s").is_err());
        assert!(parse_state_expiry("366d").is_err());
    }

    #[test]
    fn expected_revision_accepts_create_only_and_canonical_tokens() {
        let token = "11111111-2222-4333-8444-555555555555:42";
        assert_eq!(parse_expected_revision(None).unwrap(), None);
        assert_eq!(parse_expected_revision(Some("0")).unwrap(), Some("0"));
        assert_eq!(parse_expected_revision(Some(token)).unwrap(), Some(token));
        assert!(parse_expected_revision(Some("")).is_err());
        assert!(parse_expected_revision(Some("11111111-2222-4333-8444-555555555555:0")).is_err());
        assert!(parse_expected_revision(Some("11111111-2222-4333-8444-555555555555:-1")).is_err());
        assert!(parse_expected_revision(Some("11111111-2222-4333-8444-555555555555:042")).is_err());
    }

    #[test]
    fn state_action_templates_resolve_all_runtime_fields() {
        let trigger = make_trigger();
        let step = Step {
            id: "write".into(),
            name: None,
            if_expr: None,
            timeout_secs: None,
            action: ActionDef::WriteState {
                key: "counter/{{trigger.author}}".into(),
                value: "{{trigger.text}}".into(),
                expires_in: "{{trigger.timestamp}}s".into(),
                expected_revision: Some("{{steps.read.output.revision}}".into()),
            },
        };
        let outputs = HashMap::from([(
            "read".into(),
            json!({ "revision": "11111111-2222-4333-8444-555555555555:7" }),
        )]);

        let resolved = resolve_step_templates(&step, &trigger, &outputs).unwrap();
        assert!(matches!(
            resolved,
            ActionDef::WriteState {
                key,
                value,
                expires_in,
                expected_revision: Some(expected_revision),
            } if key == "counter/abc123def456"
                && value == "P1 incident in production"
                && expires_in == "1700000000s"
                && expected_revision == "11111111-2222-4333-8444-555555555555:7"
        ));
    }

    #[test]
    fn state_outputs_are_flat_and_cas_conflict_is_data() {
        let revision: buzz_db::WorkflowStateRevision =
            serde_json::from_str("\"11111111-2222-4333-8444-555555555555:7\"").unwrap();
        let read = read_state_output(Some(buzz_db::WorkflowStateEntry {
            value: "old".into(),
            revision,
            expires_at: chrono::Utc::now(),
        }));
        assert_eq!(
            read,
            json!({
                "found": true,
                "value": "old",
                "revision": "11111111-2222-4333-8444-555555555555:7",
            })
        );
        assert_eq!(
            read_state_output(None),
            json!({ "found": false, "value": null, "revision": "0" })
        );

        let written = write_state_output(buzz_db::WorkflowStateWriteOutcome::Written {
            value: "new".into(),
            revision,
        })
        .unwrap();
        assert_eq!(
            written,
            json!({
                "written": true,
                "value": "new",
                "revision": "11111111-2222-4333-8444-555555555555:7",
            })
        );

        let conflict = write_state_output(buzz_db::WorkflowStateWriteOutcome::Conflict {
            current_value: Some("old".into()),
            current_revision: Some(revision),
        })
        .expect("CAS conflict is a completed output");
        assert_eq!(
            conflict,
            json!({
                "written": false,
                "value": "old",
                "revision": "11111111-2222-4333-8444-555555555555:7",
            })
        );

        let absent_conflict = write_state_output(buzz_db::WorkflowStateWriteOutcome::Conflict {
            current_value: None,
            current_revision: None,
        })
        .expect("absent CAS conflict is a completed output");
        assert_eq!(
            absent_conflict,
            json!({ "written": false, "value": null, "revision": "0" })
        );
    }

    #[test]
    fn resolve_unclosed_template_emits_literally() {
        // An unclosed `{{` should be emitted literally without panicking.
        let ctx = make_trigger();
        let out = resolve_template("Hello {{trigger.text", &ctx, &HashMap::new()).unwrap();
        // The unclosed `{{` and remaining text are emitted as-is.
        assert!(
            out.contains("{{"),
            "unclosed {{ should appear literally in output"
        );
    }

    #[test]
    fn resolve_empty_template_string() {
        let ctx = make_trigger();
        let out = resolve_template("", &ctx, &HashMap::new()).unwrap();
        assert_eq!(out, "");
    }

    #[test]
    fn resolve_template_with_only_literal_text() {
        let ctx = make_trigger();
        let out = resolve_template("no placeholders at all", &ctx, &HashMap::new()).unwrap();
        assert_eq!(out, "no placeholders at all");
    }

    #[test]
    fn resolve_multiple_different_trigger_fields() {
        let ctx = make_trigger();
        let out = resolve_template(
            "channel={{trigger.channel_id}} ts={{trigger.timestamp}} emoji={{trigger.emoji}}",
            &ctx,
            &HashMap::new(),
        )
        .unwrap();
        assert_eq!(out, "channel=channel-uuid-here ts=1700000000 emoji=fire");
    }

    #[test]
    fn resolve_trigger_message_id() {
        let ctx = make_trigger();
        let out = resolve_template("msg={{trigger.message_id}}", &ctx, &HashMap::new()).unwrap();
        assert_eq!(out, "msg=event-id-hex");
    }

    #[test]
    fn resolve_step_output_boolean_value() {
        let ctx = make_trigger();
        let mut outputs = HashMap::new();
        outputs.insert("gate".to_owned(), json!({ "approved": true }));
        let out =
            resolve_template("Approved: {{steps.gate.output.approved}}", &ctx, &outputs).unwrap();
        assert_eq!(out, "Approved: true");
    }

    #[test]
    fn resolve_step_output_number_value() {
        let ctx = make_trigger();
        let mut outputs = HashMap::new();
        outputs.insert("count".to_owned(), json!({ "total": 42 }));
        let out = resolve_template("Total: {{steps.count.output.total}}", &ctx, &outputs).unwrap();
        assert_eq!(out, "Total: 42");
    }

    #[test]
    fn resolve_step_output_null_value_is_empty_string() {
        let ctx = make_trigger();
        let mut outputs = HashMap::new();
        outputs.insert("step".to_owned(), json!({ "val": null }));
        let out = resolve_template("Val: {{steps.step.output.val}}", &ctx, &outputs).unwrap();
        assert_eq!(out, "Val: ");
    }

    #[test]
    fn resolve_unknown_step_id_left_literal() {
        let ctx = make_trigger();
        let out =
            resolve_template("{{steps.nonexistent.output.field}}", &ctx, &HashMap::new()).unwrap();
        assert_eq!(out, "{{steps.nonexistent.output.field}}");
    }

    #[test]
    fn resolve_step_output_missing_field_left_literal() {
        let ctx = make_trigger();
        let mut outputs = HashMap::new();
        outputs.insert("step".to_owned(), json!({ "other": "value" }));
        let out = resolve_template("{{steps.step.output.missing}}", &ctx, &outputs).unwrap();
        assert_eq!(out, "{{steps.step.output.missing}}");
    }

    #[test]
    fn resolve_truncate_zero_chars() {
        let ctx = make_trigger();
        let out =
            resolve_template("{{trigger.text | truncate(0)}}", &ctx, &HashMap::new()).unwrap();
        assert_eq!(out, "");
    }

    #[test]
    fn resolve_truncate_longer_than_string() {
        let ctx = make_trigger(); // text = "P1 incident in production" (25 chars)
        let out =
            resolve_template("{{trigger.text | truncate(1000)}}", &ctx, &HashMap::new()).unwrap();
        // Truncating to more than the string length returns the full string.
        assert_eq!(out, "P1 incident in production");
    }

    #[test]
    fn resolve_pubkey_filter_non_pubkey_passes_through() {
        // Values that are not valid hex pubkeys are returned unchanged.
        let mut ctx = make_trigger();
        ctx.author = "short".to_owned();
        let out = resolve_template(
            "{{trigger.author | truncate_pubkey}}",
            &ctx,
            &HashMap::new(),
        )
        .unwrap();
        assert_eq!(out, "short");
    }

    #[test]
    fn resolve_npub_filter_passes_npub_through() {
        // Already-encoded npubs are not valid hex, so they pass through intact.
        let mut ctx = make_trigger();
        ctx.author = "npub1u9l940mmrk7nv0cw6maa5fz4vztj0vj42s5dagj38zx9gtxj7qls94fpux".to_owned();
        let out = resolve_template("{{trigger.author | npub}}", &ctx, &HashMap::new()).unwrap();
        assert_eq!(out, ctx.author);
    }

    #[test]
    fn resolve_unknown_filter_returns_error() {
        let ctx = make_trigger();
        let err = resolve_template(
            "{{trigger.text | nonexistent_filter}}",
            &ctx,
            &HashMap::new(),
        )
        .unwrap_err();
        assert!(matches!(err, WorkflowError::TemplateError(_)));
    }

    #[test]
    fn resolve_truncate_invalid_number_returns_error() {
        let ctx = make_trigger();
        let err = resolve_template("{{trigger.text | truncate(abc)}}", &ctx, &HashMap::new())
            .unwrap_err();
        assert!(matches!(err, WorkflowError::TemplateError(_)));
    }

    #[test]
    fn resolve_adjacent_templates_no_separator() {
        let ctx = make_trigger();
        let out =
            resolve_template("{{trigger.author}}{{trigger.emoji}}", &ctx, &HashMap::new()).unwrap();
        assert_eq!(out, "abc123def456fire");
    }

    #[tokio::test]
    async fn condition_and_expression_both_true() {
        let ctx = make_trigger(); // text = "P1 incident in production"
        let result = evaluate_condition(
            "str_contains(trigger_text, \"P1\") && str_contains(trigger_text, \"production\")",
            &ctx,
            &HashMap::new(),
        )
        .await
        .unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn condition_and_expression_one_false() {
        let ctx = make_trigger(); // text = "P1 incident in production"
        let result = evaluate_condition(
            "str_contains(trigger_text, \"P1\") && str_contains(trigger_text, \"staging\")",
            &ctx,
            &HashMap::new(),
        )
        .await
        .unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn condition_not_expression() {
        let ctx = make_trigger(); // text = "P1 incident in production"
        let result =
            evaluate_condition("!str_contains(trigger_text, \"P2\")", &ctx, &HashMap::new())
                .await
                .unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn condition_str_starts_with() {
        let ctx = make_trigger(); // text = "P1 incident in production"
        let result = evaluate_condition(
            "str_starts_with(trigger_text, \"P1\")",
            &ctx,
            &HashMap::new(),
        )
        .await
        .unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn condition_str_ends_with() {
        let ctx = make_trigger(); // text = "P1 incident in production"
        let result = evaluate_condition(
            "str_ends_with(trigger_text, \"production\")",
            &ctx,
            &HashMap::new(),
        )
        .await
        .unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn condition_str_len() {
        let ctx = make_trigger(); // text = "P1 incident in production" (25 chars)
        let result = evaluate_condition("str_len(trigger_text) > 10", &ctx, &HashMap::new())
            .await
            .unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn condition_str_len_exact() {
        let mut ctx = make_trigger();
        ctx.text = "hello".to_owned(); // exactly 5 chars
        let result = evaluate_condition("str_len(trigger_text) == 5", &ctx, &HashMap::new())
            .await
            .unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn condition_emoji_field() {
        let ctx = make_trigger(); // emoji = "fire"
        let result = evaluate_condition("trigger_emoji == \"fire\"", &ctx, &HashMap::new())
            .await
            .unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn condition_author_field() {
        let ctx = make_trigger(); // author = "abc123def456"
        let result = evaluate_condition(
            "str_starts_with(trigger_author, \"abc\")",
            &ctx,
            &HashMap::new(),
        )
        .await
        .unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn condition_webhook_field_registered() {
        let mut ctx = make_trigger();
        ctx.webhook_fields
            .insert("severity".to_owned(), "critical".to_owned());
        let result = evaluate_condition("trigger_severity == \"critical\"", &ctx, &HashMap::new())
            .await
            .unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn condition_step_output_string_comparison() {
        let ctx = make_trigger();
        let mut outputs = HashMap::new();
        outputs.insert("fetch".to_owned(), json!({ "status": "ok" }));
        let result = evaluate_condition("steps_fetch_output_status == \"ok\"", &ctx, &outputs)
            .await
            .unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn condition_step_output_integer_comparison() {
        let ctx = make_trigger();
        let mut outputs = HashMap::new();
        outputs.insert("count".to_owned(), json!({ "n": 5 }));
        let result = evaluate_condition("steps_count_output_n >= 5", &ctx, &outputs)
            .await
            .unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn condition_complex_nested_boolean() {
        let ctx = make_trigger(); // text = "P1 incident in production"
        let result = evaluate_condition(
            "(str_contains(trigger_text, \"P1\") || str_contains(trigger_text, \"P2\")) && str_contains(trigger_text, \"production\")",
            &ctx,
            &HashMap::new(),
        )
        .await.unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn condition_false_literal() {
        let ctx = make_trigger();
        let result = evaluate_condition("false", &ctx, &HashMap::new())
            .await
            .unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn condition_true_literal() {
        let ctx = make_trigger();
        let result = evaluate_condition("true", &ctx, &HashMap::new())
            .await
            .unwrap();
        assert!(result);
    }

    #[test]
    fn trigger_context_get_field_known_fields() {
        let ctx = make_trigger();
        assert_eq!(
            ctx.get_field("text"),
            Some("P1 incident in production".to_owned())
        );
        assert_eq!(ctx.get_field("author"), Some("abc123def456".to_owned()));
        assert_eq!(
            ctx.get_field("channel_id"),
            Some("channel-uuid-here".to_owned())
        );
        assert_eq!(ctx.get_field("timestamp"), Some("1700000000".to_owned()));
        assert_eq!(ctx.get_field("emoji"), Some("fire".to_owned()));
        assert_eq!(ctx.get_field("message_id"), Some("event-id-hex".to_owned()));
    }

    #[test]
    fn trigger_context_get_field_unknown_returns_none() {
        let ctx = make_trigger();
        assert!(ctx.get_field("nonexistent").is_none());
        assert!(ctx.get_field("").is_none());
    }

    #[test]
    fn trigger_context_get_field_webhook_field() {
        let mut ctx = make_trigger();
        ctx.webhook_fields
            .insert("repo".to_owned(), "buzz".to_owned());
        assert_eq!(ctx.get_field("repo"), Some("buzz".to_owned()));
    }

    #[test]
    fn trigger_context_default_has_empty_fields() {
        let ctx = TriggerContext::default();
        assert_eq!(ctx.text, "");
        assert_eq!(ctx.author, "");
        assert_eq!(ctx.channel_id, "");
        assert_eq!(ctx.timestamp, "");
        assert_eq!(ctx.emoji, "");
        assert_eq!(ctx.message_id, "");
        assert!(ctx.webhook_fields.is_empty());
        assert!(ctx.webhook_body.is_none());
    }

    #[test]
    fn send_message_uses_bound_workflow_channel_by_default() {
        let workflow_channel_id = Uuid::new_v4();
        let resolved = resolve_send_message_channel(None, "", Some(workflow_channel_id))
            .expect("bound channel should be used");
        assert_eq!(resolved, workflow_channel_id.to_string());
    }

    #[test]
    fn send_message_rejects_cross_channel_override_for_bound_workflow() {
        let workflow_channel_id = Uuid::new_v4();
        let other_channel_id = Uuid::new_v4();
        let err = resolve_send_message_channel(
            Some(&other_channel_id.to_string()),
            "",
            Some(workflow_channel_id),
        )
        .unwrap_err();
        assert!(matches!(err, WorkflowError::InvalidDefinition(_)));
        assert!(
            err.to_string().contains("channel override must match"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn send_message_canonicalizes_valid_explicit_override_for_global_workflow() {
        let override_channel_id = Uuid::new_v4();
        let resolved =
            resolve_send_message_channel(Some(&override_channel_id.to_string()), "", None)
                .expect("override should be accepted");
        assert_eq!(resolved, override_channel_id.to_string());
    }

    // ─── Extract action matchers ──────────────────────────────────────────

    #[test]
    fn extract_wf_sha_matches_exactly_40_lower_hex() {
        let sha = "6407ed82b9869a112e234a19b328511c90db6647";
        let result = run_matcher("wf_sha", &format!("FROZEN {sha}").to_owned())
            .expect("valid wf_sha should match");
        assert!(result.found);
        assert_eq!(result.count, 1);
        assert_eq!(result.value, sha);
    }

    #[test]
    fn extract_wf_sha_rejects_uppercase_and_short() {
        let upper = "6407ED82B9869A112E234A19B328511C90DB6647";
        let result = run_matcher("wf_sha", upper).expect("no match should not error");
        assert!(!result.found);
        assert_eq!(result.count, 0);
        assert_eq!(result.value, "");

        let short = "6407ed82";
        let result = run_matcher("wf_sha", short).expect("short sha should not error");
        assert!(!result.found);
    }

    #[test]
    fn extract_wf_sha_counts_multiple_matches() {
        let sha = "6407ed82b9869a112e234a19b328511c90db6647";
        let other = "992d18c93aff34be5572f8b3bf656b679d823c36";
        let field = format!("{sha} and also {other}");
        let result = run_matcher("wf_sha", &field).expect("two shas should match");
        assert!(result.found);
        assert_eq!(result.count, 2);
        // First match is the first token in the field.
        assert_eq!(result.value, sha);
    }

    #[test]
    fn extract_wf_sha_no_match_emits_empty_with_found_false() {
        let field = "no SHA here just words";
        let result = run_matcher("wf_sha", field).expect("no match should not error");
        assert!(!result.found);
        assert_eq!(result.count, 0);
        assert_eq!(result.value, "");
    }

    #[test]
    fn extract_wf_word_first_and_count() {
        let field = "alpha beta gamma";
        let result = run_matcher("wf_word", field).expect("words should match");
        assert!(result.found);
        assert_eq!(result.count, 3);
        assert_eq!(result.value, "alpha");
    }

    #[test]
    fn extract_wf_word_empty_field_returns_empty() {
        let result = run_matcher("wf_word", "").expect("empty field should not error");
        assert!(!result.found);
        assert_eq!(result.count, 0);
        assert_eq!(result.value, "");
    }

    #[test]
    fn extract_unknown_matcher_rejected() {
        let err = run_matcher("bogus", "anything").unwrap_err();
        assert!(matches!(err, WorkflowError::InvalidDefinition(_)));
    }

    // End-to-end path test: the exact failure the reviewer caught. The
    // extract step emits flat keys, and both consumers must see them.
    // We build the step_outputs map exactly as the Extract dispatch arm does,
    // then run a real condition on <name>_found and a real template on the
    // value. If extract ever emits a nested object again, this test fails
    // because steps_extract_output_sha_found will not exist (condition) and
    // {{steps.extract.output.sha.value}} will resolve verbatim (template).
    #[tokio::test]
    async fn extract_output_reaches_condition_and_template() {
        let sha = "050ac722106c2e04fba83315ef0bd498472ae99b";
        let mut ctx = make_trigger();
        ctx.text = format!("FROZEN {sha}").to_owned();

        // Call the production helper the dispatch arm uses, not a copy. If
        // extract ever changes (e.g. back to a nested object), this
        // test fails because the assertion depends on the real arm.
        let mut matchers: HashMap<String, String> = HashMap::new();
        matchers.insert("sha".to_owned(), "wf_sha".to_owned());
        let out = run_extract_output("trigger.text", &matchers, &ctx, &HashMap::new())
            .expect("extract should not fail");

        let mut step_outputs: HashMap<String, JsonValue> = HashMap::new();
        step_outputs.insert("extract".to_owned(), serde_json::Value::Object(out));

        // Condition sees the flat flag from the real arm's output.
        let cond_ok = evaluate_condition(
            "steps_extract_output_sha_found == true && steps_extract_output_sha_count == 1",
            &ctx,
            &step_outputs,
        )
        .await
        .expect("condition must evaluate");
        assert!(cond_ok);

        // Template resolves the value from the real arm's flat key.
        let template_out =
            resolve_template("sha={{steps.extract.output.sha}}", &ctx, &step_outputs)
                .expect("template must resolve");
        assert_eq!(template_out, format!("sha={sha}"));
    }

    // Regression for the review-leg disagreement: when a webhook body carries
    // both a top-level key literally named "a.b" and a nested a.b, both
    // consumers must return the same value. Per the orchestrator's ruling the
    // flat top-level key wins (backward-compatible for existing definitions),
    // and body_path mirrors get_field so the languages agree.
    #[tokio::test]
    async fn dotted_name_flat_wins_and_consumers_agree() {
        let mut ctx = make_trigger();
        ctx.webhook_body = Some(serde_json::json!({
            "a.b": "flat",
            "a": { "b": "nested" },
        }));
        ctx.webhook_fields
            .insert("a.b".to_owned(), "flat".to_owned());
        ctx.webhook_fields
            .insert("a".to_owned(), "{\"b\":\"nested\"}".to_owned());

        // Template path: flat key wins.
        let template_value = ctx.get_field("a.b").expect("get_field should resolve");
        assert_eq!(template_value, "flat");

        // Condition path: body_path("a.b") must also return flat, proving the
        // two languages agree (equality is the invariant, flat is the policy).
        let condition_sees_flat =
            evaluate_condition("body_path(\"a.b\") == \"flat\"", &ctx, &HashMap::new())
                .await
                .expect("body_path expression evaluates");
        assert!(
            condition_sees_flat,
            "body_path must match get_field: flat wins"
        );

        let condition_sees_nested =
            evaluate_condition("body_path(\"a.b\") == \"nested\"", &ctx, &HashMap::new())
                .await
                .expect("body_path expression evaluates");
        assert!(
            !condition_sees_nested,
            "body_path must not see nested when flat key exists"
        );
    }
}
