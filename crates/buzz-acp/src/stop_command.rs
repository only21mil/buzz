//! `/stop` and `/stop all`: stop a lane and the sibling agents it dispatched.
//!
//! A lane is `(agent pubkey, SessionScope)`. The tagged agent is the parent.
//! Stopping means cancel, not kill: the in-flight turn gets
//! [`ControlSignal::Cancel`] (in-process children die with the turn, or with
//! the drain-timeout respawn), queued batches for the lane are dropped so it
//! does not resume, and every sibling this lane dispatched by relay message
//! since the turn started receives its own harness-authored `/stop` tagged
//! with the originating event id. Each child harness handles that under the
//! same rule with itself as the parent, so the stop recurses one hop at a
//! time; the origin id lets a harness ignore repeats and breaks cycles.
//!
//! The relay is the record: the parent's acknowledgement names the scope,
//! turn id, dropped count and notified children, and each fan-out reply is a
//! `/stop` event with a `stop-origin` tag, so the tree is reconstructible
//! from kind:9 alone. The observer also receives a `control_result` frame of
//! type `stop` for the desktop.
//!
//! Authorisation: the owner always; a sibling only when its `/stop` carries
//! the `stop-origin` tag, which is what harness fan-out adds and generated
//! text cannot. A sibling `/stop` without the tag is refused in-thread and
//! consumed, so "@A /stop all" in another agent's reply cannot halt A's
//! lanes. Anyone else's `/stop` falls through to the ordinary prompt path,
//! like a non-owner `!cancel`.
//!
//! A `/stop` that lands while the turn's control channel was already taken
//! by a steer or interrupt marks the scope stopped in the queue; the batch
//! that turn returns is discarded instead of re-dispatched, so the lane does
//! not resume.

use std::collections::{HashSet, VecDeque};

use nostr::{Alphabet, SingleLetterTag};
use uuid::Uuid;

use crate::pool::{
    post_harness_notice, reply_thread_ref, unix_now_secs, AgentPool, ControlSignal, SignalledTurn,
};
use crate::queue::slash::{route_command, CommandRoute, SlashCommand};
use crate::queue::{extract_slash_command, parse_thread_tags, EventQueue};
use crate::relay::RestClient;
use crate::scope::SessionScope;
use crate::sibling_auth::{OwnerCache, SiblingAuthorization};
use crate::{is_owner_or_sibling, observer, KIND_STREAM_MESSAGE};

/// Tag name a fan-out `/stop` carries to name the event that started it.
pub(crate) const STOP_ORIGIN_TAG: &str = "stop-origin";

/// Upper bound on remembered origin ids. Enough to cover any realistic burst
/// of stop trees; older ids age out in insertion order.
pub(crate) const MAX_REMEMBERED_ORIGINS: usize = 256;

/// Dispatch events a `/stop` inspects at most. Parents rarely dispatch more
/// than a handful of siblings per turn.
const DISPATCH_QUERY_LIMIT: usize = 200;

/// Distinct mentioned pubkeys checked for sibling status per `/stop`; each
/// uncached check is a profile query.
const MAX_SIBLING_CANDIDATES: usize = 32;

const RELAY_QUERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// A parsed `/stop` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StopRequest {
    /// `/stop all`: every lane of this agent in the channel.
    pub all: bool,
    /// The id that started this stop tree: the event's own `stop-origin` tag
    /// when it is itself a fan-out, otherwise the event id.
    pub origin: String,
    /// Whether the event carried a well-formed `stop-origin` tag, which only
    /// harness fan-out adds. Siblings need it; the owner does not.
    pub forwarded: bool,
}

/// Parse a `/stop` request out of a kind:9 event that mentions this agent.
///
/// Leading `@mention`s are stripped by [`extract_slash_command`], so the
/// desktop composer's `@Fizz /stop` matches. Only `/stop` and `/stop all`
/// qualify; other argument shapes are not a stop and fall through as prose.
pub(crate) fn parse_stop_command(
    event: &nostr::Event,
    kind_u32: u32,
    agent_pubkey_hex: &str,
    known_names: &[&str],
) -> Option<StopRequest> {
    if kind_u32 != KIND_STREAM_MESSAGE || !crate::event_mentions_agent(event, agent_pubkey_hex) {
        return None;
    }
    let command = extract_slash_command(&event.content, known_names)?;
    let cmd = SlashCommand::parse(&command)?;
    if route_command(&cmd) != CommandRoute::Stop {
        return None;
    }
    let all = match cmd.args.as_str() {
        "" => false,
        args if args.eq_ignore_ascii_case("all") => true,
        _ => return None,
    };
    let tagged_origin = event.tags.iter().find_map(|t| {
        let parts = t.as_slice();
        (parts.first().map(String::as_str) == Some(STOP_ORIGIN_TAG))
            .then(|| parts.get(1))
            .flatten()
            .filter(|id| id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit()))
            .map(|id| id.to_ascii_lowercase())
    });
    let forwarded = tagged_origin.is_some();
    let origin = tagged_origin.unwrap_or_else(|| event.id.to_hex());
    Some(StopRequest {
        all,
        origin,
        forwarded,
    })
}

/// What the authorisation gate decided for a parsed `/stop`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StopGate {
    /// The owner, or a sibling whose `/stop` carries the `stop-origin` tag
    /// (harness fan-out). Execute it.
    Authorised,
    /// A verified sibling without the tag: generated text, not fan-out. A
    /// refusal was posted in-thread; consume the event without prompting.
    Refused,
    /// Anyone else. Falls through as an ordinary prompt, like `!cancel`.
    NotAuthorised,
}

/// Decide whether `author` may stop this agent's lanes and post the refusal
/// when a sibling tries without the `stop-origin` tag.
///
/// The owner is always allowed. A sibling (same owner attestation, checked
/// through the cache the author gate just populated or the profile query)
/// is allowed only when the `/stop` was forwarded by a harness, which is
/// what the tag proves: a model cannot add tags to the text it posts, so
/// "@A /stop all" in a sibling's generated reply cannot halt A's lanes.
pub(crate) async fn gate_stop(
    request: &StopRequest,
    event: &nostr::Event,
    channel_id: Uuid,
    author: &str,
    owner_cache: &OwnerCache,
    rest: &RestClient,
) -> StopGate {
    if owner_cache.get() == Some(author) {
        return StopGate::Authorised;
    }
    if is_owner_or_sibling(author, owner_cache, rest).await != SiblingAuthorization::Authorized {
        tracing::debug!(
            channel_id = %channel_id,
            author = %author,
            "/stop from a non-owner, non-sibling author — forwarding as a prompt"
        );
        return StopGate::NotAuthorised;
    }
    if request.forwarded {
        return StopGate::Authorised;
    }
    tracing::warn!(
        channel_id = %channel_id,
        author = %author,
        "/stop from a sibling without a stop-origin tag — refused"
    );
    let thread_ref = reply_thread_ref(event);
    post_harness_notice(
        rest,
        channel_id,
        Some(&thread_ref),
        &sibling_refusal_text(author),
        &[],
        &[],
    )
    .await;
    StopGate::Refused
}

/// Text of the in-thread refusal for a sibling `/stop` without the tag.
pub(crate) fn sibling_refusal_text(author: &str) -> String {
    format!(
        "Ignored /stop from sibling agent {}: only the owner, or a harness fan-out \
         carrying a stop-origin tag, can stop this lane. Text in an agent's reply cannot.",
        short_pubkey(author)
    )
}

/// Bounded set of handled stop-origin ids, insertion ordered.
pub(crate) struct StopOriginSet {
    seen: HashSet<String>,
    order: VecDeque<String>,
    capacity: usize,
}

impl StopOriginSet {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            seen: HashSet::new(),
            order: VecDeque::new(),
            capacity: capacity.max(1),
        }
    }

    /// Record `origin`. Returns `false` when it was already handled.
    pub(crate) fn insert(&mut self, origin: String) -> bool {
        if self.seen.contains(&origin) {
            return false;
        }
        while self.order.len() >= self.capacity {
            if let Some(old) = self.order.pop_front() {
                self.seen.remove(&old);
            }
        }
        self.seen.insert(origin.clone());
        self.order.push_back(origin);
        true
    }
}

/// What a single-scope stop found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ScopeStop {
    /// No turn in flight for the scope.
    Idle,
    /// The in-flight turn's control oneshot was already consumed by an
    /// earlier signal; nothing more to send.
    AlreadyStopping { turn_id: String, started_at: u64 },
    /// Cancel delivered to the in-flight turn.
    Cancelled { turn_id: String, started_at: u64 },
}

/// Send `Cancel` to the in-flight turn of one exact scope, distinguishing
/// idle from already-stopping so the acknowledgement can say which.
pub(crate) fn stop_scope(pool: &mut AgentPool, scope: &SessionScope) -> ScopeStop {
    let Some(meta) = pool
        .task_map_mut()
        .values_mut()
        .find(|m| m.scope.as_ref() == Some(scope))
    else {
        return ScopeStop::Idle;
    };
    let turn_id = meta.turn_id.clone();
    let started_at = meta.started_at;
    match meta.control_tx.take() {
        Some(tx) => {
            let _ = tx.send(ControlSignal::Cancel);
            tracing::info!(
                channel = %scope.channel_id(),
                scope = %scope.telemetry_label(),
                turn_id = %turn_id,
                "/stop cancelled in-flight turn"
            );
            ScopeStop::Cancelled {
                turn_id,
                started_at,
            }
        }
        None => ScopeStop::AlreadyStopping {
            turn_id,
            started_at,
        },
    }
}

/// A sibling this agent dispatched by mentioning it, with the latest
/// dispatch event so the fan-out `/stop` lands in the same thread.
#[derive(Debug, Clone)]
pub(crate) struct DispatchedSibling {
    pub pubkey: String,
    pub dispatch_event: nostr::Event,
}

/// Find siblings this agent dispatched in `channel_id` since `since`.
///
/// One relay query: kind:9 authored by `parent_pubkey_hex` in the channel,
/// `since` the turn started. With `thread_root` set (thread policy), only
/// events in that thread count. Mentioned pubkeys are kept when they verify
/// as siblings; the owner, the parent itself and humans are skipped, so no
/// fan-out reply ever loops through a person.
pub(crate) async fn find_dispatched_siblings(
    rest: &RestClient,
    parent_pubkey_hex: &str,
    channel_id: Uuid,
    thread_root: Option<&str>,
    since: u64,
    owner_cache: &OwnerCache,
) -> Vec<DispatchedSibling> {
    let Ok(parent) = nostr::PublicKey::from_hex(parent_pubkey_hex) else {
        return Vec::new();
    };
    let filter = nostr::Filter::new()
        .kind(nostr::Kind::Custom(KIND_STREAM_MESSAGE as u16))
        .author(parent)
        .custom_tags(
            SingleLetterTag::lowercase(Alphabet::H),
            [channel_id.to_string()],
        )
        .since(nostr::Timestamp::from(since))
        .limit(DISPATCH_QUERY_LIMIT);
    let raw = match tokio::time::timeout(RELAY_QUERY_TIMEOUT, rest.query(&[filter])).await {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            tracing::warn!(channel = %channel_id, "/stop dispatch query failed: {e}");
            return Vec::new();
        }
        Err(_) => {
            tracing::warn!(channel = %channel_id, "/stop dispatch query timed out");
            return Vec::new();
        }
    };
    let mut events: Vec<nostr::Event> = raw
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| serde_json::from_value::<nostr::Event>(v.clone()).ok())
                .collect()
        })
        .unwrap_or_default();
    events.retain(|ev| {
        ev.pubkey.to_hex() == parent_pubkey_hex
            && thread_root.is_none_or(|root| {
                ev.id.to_hex() == root
                    || parse_thread_tags(ev).root_event_id.as_deref() == Some(root)
            })
    });
    // Newest first, so the first dispatch seen per pubkey is the latest.
    events.sort_by_key(|ev| std::cmp::Reverse(ev.created_at));

    let owner = owner_cache.get().map(str::to_owned);
    let mut candidates: Vec<DispatchedSibling> = Vec::new();
    for ev in events {
        for pk in parse_thread_tags(&ev).mentioned_pubkeys {
            let pk = pk.to_ascii_lowercase();
            if pk == parent_pubkey_hex
                || owner.as_deref() == Some(pk.as_str())
                || candidates.iter().any(|c| c.pubkey == pk)
            {
                continue;
            }
            if candidates.len() >= MAX_SIBLING_CANDIDATES {
                break;
            }
            candidates.push(DispatchedSibling {
                pubkey: pk,
                dispatch_event: ev.clone(),
            });
        }
    }
    let mut siblings = Vec::new();
    for candidate in candidates {
        if is_owner_or_sibling(&candidate.pubkey, owner_cache, rest).await
            == SiblingAuthorization::Authorized
        {
            siblings.push(candidate);
        }
    }
    siblings
}

/// Post one harness-authored `/stop` per sibling, in the thread of the
/// dispatch that reached it, mentioning only that sibling and tagged with
/// the stop origin. Returns the pubkeys whose reply the relay accepted.
pub(crate) async fn fan_out_stop(
    rest: &RestClient,
    channel_id: Uuid,
    siblings: &[DispatchedSibling],
    origin: &str,
) -> Vec<String> {
    let mut notified = Vec::new();
    for sibling in siblings {
        let thread_ref = reply_thread_ref(&sibling.dispatch_event);
        let posted = post_harness_notice(
            rest,
            channel_id,
            Some(&thread_ref),
            "/stop",
            &[sibling.pubkey.as_str()],
            &[vec![STOP_ORIGIN_TAG.to_string(), origin.to_string()]],
        )
        .await;
        match posted {
            Some(event_id) => {
                tracing::info!(
                    channel = %channel_id,
                    child = %sibling.pubkey,
                    event_id = %event_id,
                    origin = %origin,
                    "/stop forwarded to dispatched sibling"
                );
                notified.push(sibling.pubkey.clone());
            }
            None => tracing::warn!(
                channel = %channel_id,
                child = %sibling.pubkey,
                "/stop fan-out reply was not accepted"
            ),
        }
    }
    notified
}

/// Outcome for one lane, rendered into the acknowledgement and the observer
/// frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LaneOutcome {
    pub scope: SessionScope,
    pub status: ScopeStop,
}

impl LaneOutcome {
    fn status_label(&self) -> &'static str {
        match self.status {
            ScopeStop::Idle => "no_active_turn",
            ScopeStop::AlreadyStopping { .. } => "already_stopping",
            ScopeStop::Cancelled { .. } => "sent",
        }
    }

    fn turn_id(&self) -> Option<&str> {
        match &self.status {
            ScopeStop::Idle => None,
            ScopeStop::AlreadyStopping { turn_id, .. } | ScopeStop::Cancelled { turn_id, .. } => {
                Some(turn_id)
            }
        }
    }

    fn started_at(&self) -> Option<u64> {
        match &self.status {
            ScopeStop::Idle => None,
            ScopeStop::AlreadyStopping { started_at, .. }
            | ScopeStop::Cancelled { started_at, .. } => Some(*started_at),
        }
    }
}

fn lane_label(scope: &SessionScope) -> &'static str {
    if scope.is_thread() {
        "this thread"
    } else {
        "this channel"
    }
}

fn short_pubkey(pk: &str) -> &str {
    pk.get(..8).unwrap_or(pk)
}

/// Render the acknowledgement posted in the `/stop` thread.
///
/// One line per lane. Children are named by pubkey prefix on purpose: a `p`
/// tag would wake them with the acknowledgement as a prompt.
pub(crate) fn stop_ack_text(lanes: &[LaneOutcome], dropped: usize, notified: &[String]) -> String {
    let notified_text = if notified.is_empty() {
        String::new()
    } else {
        format!(
            ", notified {} sibling{} ({})",
            notified.len(),
            if notified.len() == 1 { "" } else { "s" },
            notified
                .iter()
                .map(|pk| short_pubkey(pk))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    let mut lines: Vec<String> = lanes
        .iter()
        .map(|lane| match &lane.status {
            ScopeStop::Idle => format!("Nothing running in {}.", lane_label(&lane.scope)),
            ScopeStop::AlreadyStopping { turn_id, .. } => format!(
                "Stop already in progress for {} (turn {turn_id}).",
                lane_label(&lane.scope)
            ),
            ScopeStop::Cancelled { turn_id, .. } => format!(
                "Stopped {}: cancelled turn {turn_id}.",
                lane_label(&lane.scope)
            ),
        })
        .collect();
    if lines.is_empty() {
        lines.push("Nothing running in this channel.".to_string());
    }
    let mut text = lines.join("\n");
    let trailer = format!("Dropped {dropped} queued{notified_text}.");
    text.push('\n');
    text.push_str(&trailer);
    text
}

/// Everything the main loop hands to [`execute_stop`].
pub(crate) struct StopContext<'a> {
    pub request: &'a StopRequest,
    pub event: &'a nostr::Event,
    pub channel_id: Uuid,
    pub scope: SessionScope,
    pub agent_pubkey_hex: &'a str,
    pub max_turn_duration_secs: u64,
}

/// Stop the lane (or every lane in the channel), drop its queued work, fan
/// out to dispatched siblings, acknowledge in-thread and notify the observer.
///
/// Returns the pubkeys notified, for the caller's log line.
pub(crate) async fn execute_stop(
    stop: StopContext<'_>,
    pool: &mut AgentPool,
    queue: &mut EventQueue,
    rest: &RestClient,
    owner_cache: &OwnerCache,
    observer: Option<&observer::ObserverHandle>,
) -> Vec<String> {
    let StopContext {
        request,
        event,
        channel_id,
        scope,
        agent_pubkey_hex,
        max_turn_duration_secs,
    } = stop;

    let (lanes, dropped_ids): (Vec<LaneOutcome>, Vec<String>) = if request.all {
        let lanes: Vec<LaneOutcome> = pool
            .signal_in_flight_tasks_for_channel(channel_id, ControlSignal::Cancel)
            .into_iter()
            .map(
                |SignalledTurn {
                     scope,
                     turn_id,
                     started_at,
                     sent,
                 }| LaneOutcome {
                    scope,
                    status: if sent {
                        ScopeStop::Cancelled {
                            turn_id,
                            started_at,
                        }
                    } else {
                        ScopeStop::AlreadyStopping {
                            turn_id,
                            started_at,
                        }
                    },
                },
            )
            .collect();
        let dropped = queue.drain_channel(channel_id);
        for lane in &lanes {
            mark_lane_stopped(queue, lane);
        }
        (lanes, dropped)
    } else {
        let status = stop_scope(pool, &scope);
        let dropped = queue.drop_pending_for_scope(&scope);
        let lane = LaneOutcome {
            scope: scope.clone(),
            status,
        };
        mark_lane_stopped(queue, &lane);
        (vec![lane], dropped)
    };

    // Reactions added at push time for the dropped events are now stale.
    if !dropped_ids.is_empty() {
        let rc = rest.clone();
        let ids = dropped_ids.clone();
        tokio::spawn(async move {
            for id in &ids {
                crate::pool::reaction_remove(&rc, id, "👀").await;
            }
        });
    }

    // Look back to the earliest running turn; when idle, one max turn.
    let since = lanes
        .iter()
        .filter_map(LaneOutcome::started_at)
        .min()
        .unwrap_or_else(|| unix_now_secs().saturating_sub(max_turn_duration_secs));
    let thread_root = if request.all {
        None
    } else {
        scope.root_event_id()
    };
    let siblings = find_dispatched_siblings(
        rest,
        agent_pubkey_hex,
        channel_id,
        thread_root,
        since,
        owner_cache,
    )
    .await;
    let notified = fan_out_stop(rest, channel_id, &siblings, &request.origin).await;

    let ack = stop_ack_text(&lanes, dropped_ids.len(), &notified);
    let thread_ref = reply_thread_ref(event);
    post_harness_notice(rest, channel_id, Some(&thread_ref), &ack, &[], &[]).await;

    if let Some(observer) = observer {
        let frames: Vec<&LaneOutcome> = lanes.iter().collect();
        if frames.is_empty() {
            emit_stop_frame(
                observer,
                channel_id,
                None,
                "no_active_turn",
                None,
                &notified,
                request,
            );
        }
        for lane in frames {
            emit_stop_frame(
                observer,
                channel_id,
                Some(&lane.scope),
                lane.status_label(),
                lane.turn_id(),
                &notified,
                request,
            );
        }
    }
    tracing::info!(
        channel = %channel_id,
        origin = %request.origin,
        all = request.all,
        lanes = lanes.len(),
        dropped = dropped_ids.len(),
        notified = notified.len(),
        "/stop handled"
    );
    notified
}

/// Mark a stopped lane so the batch its turn returns is discarded. Matters
/// when the turn's control channel was already taken (a steer or interrupt
/// signalled first): the pool then returns the batch as a carry-over and,
/// without the marker, the main loop would requeue it and the lane would
/// resume. Harmless for a clean `Cancel`, whose batch the pool drops anyway.
fn mark_lane_stopped(queue: &mut EventQueue, lane: &LaneOutcome) {
    if lane.status != ScopeStop::Idle {
        queue.mark_stopped(&lane.scope);
    }
}

fn emit_stop_frame(
    observer: &observer::ObserverHandle,
    channel_id: Uuid,
    scope: Option<&SessionScope>,
    status: &str,
    turn_id: Option<&str>,
    notified: &[String],
    request: &StopRequest,
) {
    observer.emit(
        "control_result",
        None,
        &observer::ObserverContext {
            channel_id: Some(channel_id.to_string()),
            session_id: None,
            turn_id: turn_id.map(str::to_owned),
            started_at: None,
        },
        serde_json::json!({
            "type": "stop",
            "status": status,
            "turnId": turn_id,
            "scope": scope.map(SessionScope::telemetry_label),
            "all": request.all,
            "origin": request.origin,
            "notified": notified,
        }),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::{EventBuilder, Keys, Kind, Tag, Timestamp};
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn signed(keys: &Keys, content: &str, tags: Vec<Tag>, created_at: u64) -> nostr::Event {
        EventBuilder::new(Kind::Custom(KIND_STREAM_MESSAGE as u16), content)
            .tags(tags)
            .custom_created_at(Timestamp::from(created_at))
            .sign_with_keys(keys)
            .unwrap()
    }

    fn p(hex: &str) -> Tag {
        Tag::parse(["p", hex]).unwrap()
    }

    /// NIP-10 markers for a direct reply to `root`, as Buzz clients post
    /// them: a lone `root` marker is top level under the shared resolver.
    fn e_root(root: &str) -> Vec<Tag> {
        vec![
            Tag::parse(["e", root, "", "root"]).unwrap(),
            Tag::parse(["e", root, "", "reply"]).unwrap(),
        ]
    }

    fn with_root(mut tags: Vec<Tag>, root: &str) -> Vec<Tag> {
        tags.extend(e_root(root));
        tags
    }

    /// Minimal HTTP stub: `/query` answers `query_body`, `/events` answers
    /// `{}` and records the submitted event JSON.
    struct Stub {
        rest: RestClient,
        submitted: Arc<Mutex<Vec<serde_json::Value>>>,
        queries: Arc<Mutex<Vec<serde_json::Value>>>,
        server: tokio::task::JoinHandle<()>,
    }

    async fn stub(query_body: serde_json::Value, keys: Keys) -> Stub {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let submitted = Arc::new(Mutex::new(Vec::new()));
        let queries = Arc::new(Mutex::new(Vec::new()));
        let (sub, qs) = (submitted.clone(), queries.clone());
        let server = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let mut buf = Vec::new();
                let mut chunk = [0u8; 8192];
                loop {
                    let n = socket.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    let text = String::from_utf8_lossy(&buf);
                    if let Some(idx) = text.find("\r\n\r\n") {
                        let head = &text[..idx];
                        let len = head
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                            })
                            .unwrap_or(0);
                        if buf.len() >= idx + 4 + len {
                            break;
                        }
                    }
                }
                let text = String::from_utf8_lossy(&buf).to_string();
                let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
                let path = head.split_whitespace().nth(1).unwrap_or("");
                let body_json: serde_json::Value =
                    serde_json::from_str(body).unwrap_or(serde_json::Value::Null);
                let response = if path.starts_with("/events") {
                    sub.lock().unwrap().push(body_json);
                    "{}".to_string()
                } else {
                    qs.lock().unwrap().push(body_json);
                    query_body.to_string()
                };
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    response.len(),
                    response
                );
                let _ = socket.write_all(reply.as_bytes()).await;
            }
        });
        Stub {
            rest: RestClient {
                http: reqwest::Client::new(),
                base_url,
                keys,
                auth_tag_json: None,
            },
            submitted,
            queries,
            server,
        }
    }

    fn cache(owner: &str, siblings: &[&str], humans: &[&str]) -> OwnerCache {
        let cache = OwnerCache::new(Some(owner.to_string()));
        for s in siblings {
            cache.cache_sibling(s.to_string(), true);
        }
        for h in humans {
            cache.cache_sibling(h.to_string(), false);
        }
        cache
    }

    #[test]
    fn parse_requires_kind_mention_and_exact_shape() {
        let keys = Keys::generate();
        let agent = "ab".repeat(32);
        let ev = |content: &str, tags: Vec<Tag>| signed(&keys, content, tags, 10);

        let plain = ev("/stop", vec![p(&agent)]);
        assert_eq!(
            parse_stop_command(&plain, KIND_STREAM_MESSAGE, &agent, &[]),
            Some(StopRequest {
                all: false,
                origin: plain.id.to_hex(),
                forwarded: false,
            })
        );
        let mentioned = ev("@Fizz Buzz /stop ALL", vec![p(&agent)]);
        assert_eq!(
            parse_stop_command(&mentioned, KIND_STREAM_MESSAGE, &agent, &["Fizz Buzz"])
                .map(|r| r.all),
            Some(true)
        );
        // Wrong kind, no mention, other args, other command: not a stop.
        assert!(parse_stop_command(&plain, 1, &agent, &[]).is_none());
        assert!(
            parse_stop_command(&ev("/stop", vec![]), KIND_STREAM_MESSAGE, &agent, &[]).is_none()
        );
        assert!(parse_stop_command(
            &ev("/stop now", vec![p(&agent)]),
            KIND_STREAM_MESSAGE,
            &agent,
            &[]
        )
        .is_none());
        assert!(parse_stop_command(
            &ev("/stopx", vec![p(&agent)]),
            KIND_STREAM_MESSAGE,
            &agent,
            &[]
        )
        .is_none());
        assert!(parse_stop_command(
            &ev("please /stop", vec![p(&agent)]),
            KIND_STREAM_MESSAGE,
            &agent,
            &[]
        )
        .is_none());
    }

    #[test]
    fn parse_prefers_stop_origin_tag_over_event_id() {
        let keys = Keys::generate();
        let agent = "cd".repeat(32);
        let origin = "9f".repeat(32);
        let fan_out = signed(
            &keys,
            "/stop",
            vec![
                p(&agent),
                Tag::parse([STOP_ORIGIN_TAG, &origin.to_ascii_uppercase()]).unwrap(),
            ],
            10,
        );
        let parsed = parse_stop_command(&fan_out, KIND_STREAM_MESSAGE, &agent, &[]).unwrap();
        assert_eq!(parsed.origin, origin);
        assert!(
            parsed.forwarded,
            "a well-formed tag marks the stop as fan-out"
        );
        // A malformed origin tag falls back to the event id.
        let bad = signed(
            &keys,
            "/stop",
            vec![p(&agent), Tag::parse([STOP_ORIGIN_TAG, "nope"]).unwrap()],
            10,
        );
        let parsed = parse_stop_command(&bad, KIND_STREAM_MESSAGE, &agent, &[]).unwrap();
        assert_eq!(parsed.origin, bad.id.to_hex());
        assert!(
            !parsed.forwarded,
            "a malformed tag does not count as fan-out"
        );
    }

    #[test]
    fn origin_set_dedups_and_stays_bounded() {
        let mut set = StopOriginSet::new(3);
        assert!(set.insert("a".into()));
        assert!(!set.insert("a".into()), "repeat is ignored");
        assert!(set.insert("b".into()));
        assert!(set.insert("c".into()));
        assert!(set.insert("d".into()), "fourth evicts the oldest");
        assert!(set.insert("a".into()), "evicted id is fresh again");
        assert_eq!(set.order.len(), 3);
        assert_eq!(set.seen.len(), 3);
    }

    #[tokio::test]
    async fn stop_scope_reports_idle_cancelled_and_already_stopping() {
        let mut pool = AgentPool::from_slots(vec![]);
        let ch = Uuid::new_v4();
        let scope = SessionScope::Conversation { channel_id: ch };
        let other = SessionScope::Thread {
            channel_id: ch,
            root_event_id: "e".repeat(64),
        };
        assert_eq!(stop_scope(&mut pool, &scope), ScopeStop::Idle);

        let (tx, rx) = tokio::sync::oneshot::channel();
        let abort = pool.join_set.spawn(async {});
        pool.task_map_mut().insert(
            abort.id(),
            crate::pool::TaskMeta {
                agent_index: 0,
                channel_id: Some(ch),
                scope: Some(scope.clone()),
                turn_id: "turn-1".into(),
                started_at: 42,
                recoverable_batch: None,
                control_tx: Some(tx),
                steer_tx: None,
                successful_steer_deliveries: HashSet::new(),
            },
        );
        assert_eq!(
            stop_scope(&mut pool, &other),
            ScopeStop::Idle,
            "sibling thread untouched"
        );
        assert_eq!(
            stop_scope(&mut pool, &scope),
            ScopeStop::Cancelled {
                turn_id: "turn-1".into(),
                started_at: 42
            }
        );
        assert_eq!(rx.await.unwrap(), ControlSignal::Cancel);
        assert_eq!(
            stop_scope(&mut pool, &scope),
            ScopeStop::AlreadyStopping {
                turn_id: "turn-1".into(),
                started_at: 42
            }
        );
    }

    #[tokio::test]
    async fn authorisation_matrix_owner_sibling_allowlist_stranger() {
        let owner = "11".repeat(32);
        let sibling = "22".repeat(32);
        let allowlisted_human = "33".repeat(32);
        let stranger = Keys::generate().public_key().to_hex();
        let agent = "ab".repeat(32);
        let cache = cache(&owner, &[&sibling], &[&allowlisted_human]);
        // Stranger lookups hit the relay: an empty profile result is a denial.
        let stub = stub(serde_json::json!([]), Keys::generate()).await;
        let ch = Uuid::new_v4();
        let author = Keys::generate();
        let plain = signed(&author, "/stop", vec![p(&agent)], 10);
        let fan_out = signed(
            &author,
            "/stop",
            vec![
                p(&agent),
                Tag::parse([STOP_ORIGIN_TAG, &"9f".repeat(32)]).unwrap(),
            ],
            10,
        );
        let untagged = parse_stop_command(&plain, KIND_STREAM_MESSAGE, &agent, &[]).unwrap();
        let tagged = parse_stop_command(&fan_out, KIND_STREAM_MESSAGE, &agent, &[]).unwrap();
        assert!(!untagged.forwarded);
        assert!(tagged.forwarded);

        // Owner: honoured with or without the tag.
        assert_eq!(
            gate_stop(&untagged, &plain, ch, &owner, &cache, &stub.rest).await,
            StopGate::Authorised
        );
        assert_eq!(
            gate_stop(&tagged, &fan_out, ch, &owner, &cache, &stub.rest).await,
            StopGate::Authorised
        );
        // Sibling with the tag: harness fan-out, honoured.
        assert_eq!(
            gate_stop(&tagged, &fan_out, ch, &sibling, &cache, &stub.rest).await,
            StopGate::Authorised
        );
        assert!(
            stub.submitted.lock().unwrap().is_empty(),
            "no refusal posted so far"
        );
        // Sibling without the tag: generated text, refused with a reply.
        assert_eq!(
            gate_stop(&untagged, &plain, ch, &sibling, &cache, &stub.rest).await,
            StopGate::Refused
        );
        let submitted = stub.submitted.lock().unwrap().clone();
        assert_eq!(submitted.len(), 1, "one refusal reply");
        let refusal: nostr::Event = serde_json::from_value(submitted[0].clone()).unwrap();
        assert_eq!(refusal.content, sibling_refusal_text(&sibling));
        assert!(refusal
            .content
            .contains("Ignored /stop from sibling agent 22222222"));
        assert!(refusal.content.contains("stop-origin"));
        assert!(
            !refusal.tags.iter().any(|t| t.as_slice()[0] == "p"),
            "the refusal mentions nobody"
        );
        assert_eq!(
            parse_thread_tags(&refusal).root_event_id.as_deref(),
            Some(plain.id.to_hex().as_str()),
            "refusal replies to the /stop"
        );
        // Allowlist humans and strangers fall through as prose either way.
        assert_eq!(
            gate_stop(
                &tagged,
                &fan_out,
                ch,
                &allowlisted_human,
                &cache,
                &stub.rest
            )
            .await,
            StopGate::NotAuthorised,
            "allowlist humans cannot stop (open question 4: follows !cancel)"
        );
        assert_eq!(
            gate_stop(&untagged, &plain, ch, &stranger, &cache, &stub.rest).await,
            StopGate::NotAuthorised
        );
        assert_eq!(
            stub.submitted.lock().unwrap().len(),
            1,
            "no further replies"
        );
        stub.server.abort();
    }

    #[tokio::test]
    async fn stop_after_a_steer_took_control_discards_the_returning_batch() {
        use crate::pool::{PromptOutcome, PromptResult, PromptSource};
        use crate::queue::CancelReason;

        let parent = Keys::generate();
        let parent_hex = parent.public_key().to_hex();
        let owner = "11".repeat(32);
        let ch = Uuid::new_v4();
        let scope = SessionScope::Conversation { channel_id: ch };
        let stub = stub(serde_json::json!([]), parent.clone()).await;
        let cache = cache(&owner, &[], &[]);

        // A turn is in flight for the scope and a mid-turn steer already
        // took its control channel, so the pool will hand the batch back as
        // a Steer carry-over when the turn returns.
        let mut queue = EventQueue::new(crate::config::DedupMode::Queue);
        let work = signed(&Keys::generate(), "do the thing", vec![p(&parent_hex)], 500);
        queue.push(crate::queue::QueuedEvent {
            channel_id: ch,
            scope: scope.clone(),
            event: work,
            received_at: std::time::Instant::now(),
            prompt_tag: "t".into(),
        });
        let mut batch = queue.flush_next().expect("turn dispatched");
        let mut pool = AgentPool::from_slots(vec![None]);
        let abort = pool.join_set.spawn(async {});
        pool.task_map_mut().insert(
            abort.id(),
            crate::pool::TaskMeta {
                agent_index: 0,
                channel_id: Some(ch),
                scope: Some(scope.clone()),
                turn_id: "turn-1".into(),
                started_at: 400,
                recoverable_batch: Some(batch.clone()),
                control_tx: None,
                steer_tx: None,
                successful_steer_deliveries: HashSet::new(),
            },
        );

        let stop_event = signed(&Keys::generate(), "/stop", vec![p(&parent_hex)], 700);
        let request = StopRequest {
            all: false,
            origin: stop_event.id.to_hex(),
            forwarded: false,
        };
        execute_stop(
            StopContext {
                request: &request,
                event: &stop_event,
                channel_id: ch,
                scope: scope.clone(),
                agent_pubkey_hex: &parent_hex,
                max_turn_duration_secs: 60,
            },
            &mut pool,
            &mut queue,
            &stub.rest,
            &cache,
            None,
        )
        .await;
        let submitted = stub.submitted.lock().unwrap().clone();
        let ack: nostr::Event = serde_json::from_value(submitted.last().unwrap().clone()).unwrap();
        assert!(ack
            .content
            .starts_with("Stop already in progress for this channel (turn turn-1)."));
        assert!(queue.is_stopped(&scope), "/stop marked the in-flight scope");

        // The steered turn returns with its batch, as pool::requeue_cancelled_batch
        // does for Steer/Interrupt.
        batch.cancel_reason = Some(CancelReason::Steer);
        let mut heartbeat = false;
        let mut history = vec![crate::SlotCircuit {
            crash_times: vec![],
            open_until: None,
            respawn_in_flight: false,
        }];
        let (respawn_tx, _rx) = tokio::sync::mpsc::channel(8);
        let mut tasks = tokio::task::JoinSet::new();
        crate::handle_prompt_result(
            &mut pool,
            &mut queue,
            &crate::error_outcome_emission_tests::test_config(),
            PromptResult {
                agent: crate::error_outcome_emission_tests::dummy_agent(0).await,
                source: PromptSource::Channel(scope.clone()),
                turn_id: "turn-1".into(),
                outcome: PromptOutcome::Cancelled,
                batch: Some(batch),
            },
            &mut heartbeat,
            &HashSet::new(),
            &mut history,
            &respawn_tx,
            &mut tasks,
            None,
            None,
            None,
        )
        .await;

        assert!(
            queue.flush_next().is_none(),
            "the returned batch is discarded, not re-dispatched"
        );
        assert!(!queue.is_stopped(&scope), "marker cleared with the turn");
        assert!(!queue.is_scope_in_flight(scope.clone()));
        // A later mention starts a fresh turn as usual.
        let later = signed(&Keys::generate(), "again", vec![p(&parent_hex)], 800);
        queue.push(crate::queue::QueuedEvent {
            channel_id: ch,
            scope: scope.clone(),
            event: later,
            received_at: std::time::Instant::now(),
            prompt_tag: "t".into(),
        });
        let fresh = queue.flush_next().expect("new work dispatches");
        assert_eq!(fresh.events.len(), 1);
        assert!(
            fresh.cancelled_events.is_empty(),
            "no carry-over from the stopped turn"
        );
        stub.server.abort();
    }

    #[tokio::test]
    async fn dispatched_siblings_keep_siblings_drop_humans_and_respect_thread() {
        let parent = Keys::generate();
        let parent_hex = parent.public_key().to_hex();
        let owner = "11".repeat(32);
        let sib_a = "aa".repeat(32);
        let sib_b = "bb".repeat(32);
        let human = "cc".repeat(32);
        let ch = Uuid::new_v4();
        let root = "ee".repeat(32);
        let other_root = "ff".repeat(32);
        let older = signed(&parent, "@A do x", with_root(vec![p(&sib_a)], &root), 100);
        let newer = signed(
            &parent,
            "@A @human @owner do y",
            with_root(vec![p(&sib_a), p(&human), p(&owner)], &root),
            200,
        );
        let elsewhere = signed(
            &parent,
            "@B do z",
            with_root(vec![p(&sib_b)], &other_root),
            300,
        );
        let stranger_authored = signed(
            &Keys::generate(),
            "@B not from the parent",
            with_root(vec![p(&sib_b)], &root),
            400,
        );
        let body = serde_json::json!([older, newer, elsewhere, stranger_authored]);
        let stub = stub(body, parent.clone()).await;
        let cache = cache(&owner, &[&sib_a, &sib_b], &[&human]);

        let in_thread =
            find_dispatched_siblings(&stub.rest, &parent_hex, ch, Some(&root), 50, &cache).await;
        assert_eq!(
            in_thread
                .iter()
                .map(|s| s.pubkey.as_str())
                .collect::<Vec<_>>(),
            vec![sib_a.as_str()],
            "only the sibling dispatched in this thread; human, owner and other thread skipped"
        );
        assert_eq!(
            in_thread[0].dispatch_event.id, newer.id,
            "latest dispatch wins"
        );

        let channel_wide =
            find_dispatched_siblings(&stub.rest, &parent_hex, ch, None, 50, &cache).await;
        let mut pks: Vec<&str> = channel_wide.iter().map(|s| s.pubkey.as_str()).collect();
        pks.sort();
        assert_eq!(pks, vec![sib_a.as_str(), sib_b.as_str()]);

        // The filter asked for the parent's kind:9 in this channel since 50.
        let query = stub.queries.lock().unwrap()[0].clone();
        let filter = &query[0];
        assert_eq!(filter["authors"], serde_json::json!([parent_hex]));
        assert_eq!(filter["kinds"], serde_json::json!([KIND_STREAM_MESSAGE]));
        assert_eq!(filter["#h"], serde_json::json!([ch.to_string()]));
        assert_eq!(filter["since"], serde_json::json!(50));
        stub.server.abort();
    }

    #[tokio::test]
    async fn fan_out_posts_one_tagged_stop_per_sibling_in_the_dispatch_thread() {
        let parent = Keys::generate();
        let sib_a = "aa".repeat(32);
        let sib_b = "bb".repeat(32);
        let ch = Uuid::new_v4();
        let root = "ee".repeat(32);
        let dispatch_a = signed(&parent, "@A go", with_root(vec![p(&sib_a)], &root), 100);
        let dispatch_b = signed(&parent, "@B go", vec![p(&sib_b)], 100);
        let stub = stub(serde_json::json!([]), parent.clone()).await;
        let origin = "9f".repeat(32);

        let notified = fan_out_stop(
            &stub.rest,
            ch,
            &[
                DispatchedSibling {
                    pubkey: sib_a.clone(),
                    dispatch_event: dispatch_a.clone(),
                },
                DispatchedSibling {
                    pubkey: sib_b.clone(),
                    dispatch_event: dispatch_b.clone(),
                },
            ],
            &origin,
        )
        .await;
        assert_eq!(notified, vec![sib_a.clone(), sib_b.clone()]);

        let submitted = stub.submitted.lock().unwrap().clone();
        assert_eq!(submitted.len(), 2);
        for (posted, sib, dispatch) in [
            (&submitted[0], &sib_a, &dispatch_a),
            (&submitted[1], &sib_b, &dispatch_b),
        ] {
            let event: nostr::Event = serde_json::from_value(posted.clone()).unwrap();
            assert!(event.verify().is_ok(), "signed with the parent's key");
            assert_eq!(event.pubkey, parent.public_key());
            assert_eq!(event.content, "/stop");
            let tags: Vec<Vec<String>> = event.tags.iter().map(|t| t.as_slice().to_vec()).collect();
            let p_tags: Vec<&str> = tags
                .iter()
                .filter(|t| t[0] == "p")
                .map(|t| t[1].as_str())
                .collect();
            assert_eq!(p_tags, vec![sib.as_str()], "mentions exactly one sibling");
            assert!(tags
                .iter()
                .any(|t| t[0] == STOP_ORIGIN_TAG && t[1] == origin));
            assert!(tags.iter().any(|t| t[0] == "h" && t[1] == ch.to_string()));
            let thread = parse_thread_tags(&event);
            assert_eq!(
                thread.parent_event_id.as_deref(),
                Some(dispatch.id.to_hex().as_str())
            );
            let expected_root = parse_thread_tags(dispatch)
                .root_event_id
                .unwrap_or_else(|| dispatch.id.to_hex());
            assert_eq!(
                thread.root_event_id.as_deref(),
                Some(expected_root.as_str())
            );
        }
        stub.server.abort();
    }

    #[test]
    fn ack_text_names_lanes_dropped_and_children() {
        let ch = Uuid::new_v4();
        let thread = SessionScope::Thread {
            channel_id: ch,
            root_event_id: "e".repeat(64),
        };
        let conv = SessionScope::Conversation { channel_id: ch };
        let idle = stop_ack_text(
            &[LaneOutcome {
                scope: thread.clone(),
                status: ScopeStop::Idle,
            }],
            0,
            &[],
        );
        assert_eq!(idle, "Nothing running in this thread.\nDropped 0 queued.");
        let busy = stop_ack_text(
            &[
                LaneOutcome {
                    scope: conv.clone(),
                    status: ScopeStop::Cancelled {
                        turn_id: "t1".into(),
                        started_at: 1,
                    },
                },
                LaneOutcome {
                    scope: thread.clone(),
                    status: ScopeStop::AlreadyStopping {
                        turn_id: "t2".into(),
                        started_at: 1,
                    },
                },
            ],
            2,
            &["aa".repeat(32), "bb".repeat(32)],
        );
        assert_eq!(
            busy,
            "Stopped this channel: cancelled turn t1.\nStop already in progress for this thread (turn t2).\nDropped 2 queued, notified 2 siblings (aaaaaaaa, bbbbbbbb)."
        );
        assert_eq!(
            stop_ack_text(&[], 0, &[]),
            "Nothing running in this channel.\nDropped 0 queued."
        );
    }

    #[tokio::test]
    async fn execute_stop_all_cancels_lanes_drops_queue_acks_and_emits_frames() {
        let parent = Keys::generate();
        let parent_hex = parent.public_key().to_hex();
        let owner = "11".repeat(32);
        let sib = "aa".repeat(32);
        let ch = Uuid::new_v4();
        let root_a = "aa".repeat(32);
        let lane_a = SessionScope::Thread {
            channel_id: ch,
            root_event_id: root_a.clone(),
        };
        let lane_b = SessionScope::Thread {
            channel_id: ch,
            root_event_id: "bb".repeat(32),
        };
        let dispatch = signed(&parent, "@sib go", with_root(vec![p(&sib)], &root_a), 500);
        let stub = stub(serde_json::json!([dispatch]), parent.clone()).await;
        let cache = cache(&owner, &[&sib], &[]);

        let mut pool = AgentPool::from_slots(vec![]);
        let (tx, rx) = tokio::sync::oneshot::channel();
        let abort = pool.join_set.spawn(async {});
        pool.task_map_mut().insert(
            abort.id(),
            crate::pool::TaskMeta {
                agent_index: 0,
                channel_id: Some(ch),
                scope: Some(lane_a.clone()),
                turn_id: "turn-a".into(),
                started_at: 400,
                recoverable_batch: None,
                control_tx: Some(tx),
                steer_tx: None,
                successful_steer_deliveries: HashSet::new(),
            },
        );
        let mut queue = EventQueue::new(crate::config::DedupMode::Queue);
        let queued = signed(&Keys::generate(), "later", vec![p(&parent_hex)], 600);
        queue.push(crate::queue::QueuedEvent {
            channel_id: ch,
            scope: lane_b.clone(),
            event: queued,
            received_at: std::time::Instant::now(),
            prompt_tag: "t".into(),
        });
        let stop_event = signed(&Keys::generate(), "/stop all", vec![p(&parent_hex)], 700);
        let request = StopRequest {
            all: true,
            origin: stop_event.id.to_hex(),
            forwarded: false,
        };
        let observer = observer::ObserverHandle::in_process();

        let notified = execute_stop(
            StopContext {
                request: &request,
                event: &stop_event,
                channel_id: ch,
                scope: SessionScope::Conversation { channel_id: ch },
                agent_pubkey_hex: &parent_hex,
                max_turn_duration_secs: 60,
            },
            &mut pool,
            &mut queue,
            &stub.rest,
            &cache,
            Some(&observer),
        )
        .await;

        assert_eq!(notified, vec![sib.clone()]);
        assert_eq!(rx.await.unwrap(), ControlSignal::Cancel);
        assert_eq!(queue.queued_event_count(&lane_b), 0, "queued lane dropped");

        // The since bound is the running turn's start.
        let query = stub.queries.lock().unwrap()[0].clone();
        assert_eq!(query[0]["since"], serde_json::json!(400));

        let submitted = stub.submitted.lock().unwrap().clone();
        assert_eq!(submitted.len(), 2, "one fan-out plus the acknowledgement");
        let fan_out: nostr::Event = serde_json::from_value(submitted[0].clone()).unwrap();
        assert_eq!(fan_out.content, "/stop");
        let ack: nostr::Event = serde_json::from_value(submitted[1].clone()).unwrap();
        assert!(ack
            .content
            .starts_with("Stopped this thread: cancelled turn turn-a."));
        assert!(ack
            .content
            .ends_with("Dropped 1 queued, notified 1 sibling (aaaaaaaa)."));
        assert!(
            !ack.tags.iter().any(|t| t.as_slice()[0] == "p"),
            "the acknowledgement mentions nobody"
        );
        assert_eq!(
            parse_thread_tags(&ack).root_event_id.as_deref(),
            Some(stop_event.id.to_hex().as_str()),
            "acknowledgement replies to the /stop"
        );

        let frames = observer.snapshot();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].payload["type"], "stop");
        assert_eq!(frames[0].payload["status"], "sent");
        assert_eq!(frames[0].payload["turnId"], "turn-a");
        assert_eq!(frames[0].payload["all"], true);
        assert_eq!(frames[0].payload["notified"], serde_json::json!([sib]));
        stub.server.abort();
    }
}
