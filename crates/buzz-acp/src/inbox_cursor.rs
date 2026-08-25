//! Durable inbox progress for relay-backed agent mentions.
//!
//! Relay delivery is at-least-once. This module persists the last terminally
//! handled event plus a bounded event-id dedup window. Receipt is tracked only
//! in memory; a process death before terminal handling therefore replays the
//! event on the next startup.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use nostr::{Alphabet, Event, Filter, Kind, SingleLetterTag, Timestamp};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::ChannelFilter;
use crate::relay::{BuzzEvent, RelayError, RestClient};

const STATE_VERSION: u32 = 2;
const RECENT_EVENT_ID_LIMIT: usize = 4_096;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) struct EventCursor {
    pub created_at: u64,
    pub event_id: String,
}

impl EventCursor {
    fn from_event(event: &Event) -> Self {
        Self {
            created_at: event.created_at.as_secs(),
            event_id: event.id.to_hex(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CursorFile {
    version: u32,
    last_processed: Option<EventCursor>,
    #[serde(default)]
    recent_event_ids: VecDeque<String>,
}

impl Default for CursorFile {
    fn default() -> Self {
        Self {
            version: STATE_VERSION,
            last_processed: None,
            recent_event_ids: VecDeque::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CursorLoadStatus {
    Loaded,
    Missing,
    Corrupt,
}

/// Per-process cursor handle. `seen_this_run` prevents the live subscription
/// from duplicating rows already returned by startup catch-up.
pub(crate) struct InboxCursorStore {
    path: PathBuf,
    state: CursorFile,
    persisted_ids: HashSet<String>,
    seen_this_run: HashSet<String>,
    pending: BTreeSet<EventCursor>,
    completed: BTreeSet<EventCursor>,
    fallback_since: u64,
    reorder_window_secs: u64,
    load_status: CursorLoadStatus,
}

impl InboxCursorStore {
    pub(crate) fn load(
        state_dir: &Path,
        agent_pubkey_hex: &str,
        fallback_since: u64,
        reorder_window_secs: u64,
    ) -> Self {
        let path = state_dir.join(format!("{agent_pubkey_hex}.inbox-cursor.json"));
        let (state, load_status) = match fs::read(&path) {
            Ok(bytes) => match serde_json::from_slice::<CursorFile>(&bytes) {
                Ok(state) if state.version == STATE_VERSION => (state, CursorLoadStatus::Loaded),
                Ok(mut state) if state.version == 1 => {
                    if let Some(cursor) = &mut state.last_processed {
                        cursor.created_at = cursor.created_at.saturating_sub(reorder_window_secs);
                    }
                    state.version = STATE_VERSION;
                    (state, CursorLoadStatus::Loaded)
                }
                Ok(_) | Err(_) => (CursorFile::default(), CursorLoadStatus::Corrupt),
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                (CursorFile::default(), CursorLoadStatus::Missing)
            }
            Err(_) => (CursorFile::default(), CursorLoadStatus::Corrupt),
        };
        let persisted_ids = state.recent_event_ids.iter().cloned().collect();
        Self {
            path,
            state,
            persisted_ids,
            seen_this_run: HashSet::new(),
            pending: BTreeSet::new(),
            completed: BTreeSet::new(),
            fallback_since,
            reorder_window_secs,
            load_status,
        }
    }

    pub(crate) fn load_status(&self) -> CursorLoadStatus {
        self.load_status
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn has_durable_cursor(&self) -> bool {
        self.load_status == CursorLoadStatus::Loaded && self.state.last_processed.is_some()
    }

    pub(crate) fn catchup_since(&self, now: u64, max_age_secs: u64) -> CatchupFloor {
        let age_floor = now.saturating_sub(max_age_secs);
        let Some(cursor) = self.state.last_processed.as_ref() else {
            return CatchupFloor {
                since: self.fallback_since,
                age_truncated_from: None,
            };
        };
        CatchupFloor {
            since: cursor.created_at.max(age_floor),
            age_truncated_from: (cursor.created_at < age_floor).then_some(cursor.created_at),
        }
    }

    /// Register a received event. Returns false for a startup/live duplicate or
    /// an event that a prior process already handled terminally.
    pub(crate) fn begin_event(&mut self, event: &Event) -> bool {
        let event_id = event.id.to_hex();
        if self.persisted_ids.contains(&event_id) {
            return false;
        }
        if self.seen_this_run.insert(event_id) {
            self.pending.insert(EventCursor::from_event(event));
            true
        } else {
            false
        }
    }

    /// Mark events terminal only after successful prompt completion or an
    /// intentional harness-side skip. A failed write leaves at-least-once
    /// behavior intact because the relay query will return the event again.
    pub(crate) fn mark_processed<'a>(&mut self, events: impl IntoIterator<Item = &'a Event>) {
        self.mark_processed_at(events, Timestamp::now().as_secs());
    }

    fn mark_processed_at<'a>(&mut self, events: impl IntoIterator<Item = &'a Event>, now: u64) {
        let mut changed = false;
        for event in events {
            let cursor = EventCursor::from_event(event);
            if self.persisted_ids.insert(cursor.event_id.clone()) {
                self.state
                    .recent_event_ids
                    .push_back(cursor.event_id.clone());
                changed = true;
            }
            self.pending.remove(&cursor);
            self.completed.insert(cursor);
        }
        changed |= self.advance_contiguous_cursor(now);
        while self.state.recent_event_ids.len() > RECENT_EVENT_ID_LIMIT {
            if let Some(evicted) = self.state.recent_event_ids.pop_front() {
                self.persisted_ids.remove(&evicted);
            }
        }
        if changed {
            if let Err(error) = self.persist() {
                tracing::error!(
                    path = %self.path.display(),
                    %error,
                    "failed to persist inbox cursor; restart may replay handled mentions"
                );
            }
        }
    }

    /// Mark a terminal event when only its ID remains available, as with an
    /// acknowledged non-cancelling steer. The timestamp cursor stays put, so
    /// the next query safely overlaps this event and the persisted ID removes
    /// the duplicate.
    pub(crate) fn mark_processed_id(&mut self, event_id: &str) {
        if !self.persisted_ids.insert(event_id.to_string()) {
            return;
        }
        self.state.recent_event_ids.push_back(event_id.to_string());
        if let Some(cursor) = self
            .pending
            .iter()
            .find(|cursor| cursor.event_id == event_id)
            .cloned()
        {
            self.pending.remove(&cursor);
            self.completed.insert(cursor);
            self.advance_contiguous_cursor(Timestamp::now().as_secs());
        }
        while self.state.recent_event_ids.len() > RECENT_EVENT_ID_LIMIT {
            if let Some(evicted) = self.state.recent_event_ids.pop_front() {
                self.persisted_ids.remove(&evicted);
            }
        }
        if let Err(error) = self.persist() {
            tracing::error!(
                path = %self.path.display(),
                %error,
                "failed to persist inbox cursor; restart may replay handled mentions"
            );
        }
    }

    /// Advance only past terminal events that precede every known unfinished
    /// event, while retaining `reorder_window_secs` of timestamp overlap behind
    /// that frontier. A delayed event within that window is replayed after a
    /// crash and the persisted ID set deduplicates events already handled.
    /// Events first exposed with a timestamp older than the retained floor can
    /// still be lost; long downtime is also bounded by the configured catch-up
    /// maximum age.
    fn advance_contiguous_cursor(&mut self, _now: u64) -> bool {
        let frontier = match self.pending.first() {
            Some(oldest_pending) => self.completed.range(..oldest_pending.clone()).next_back(),
            None => self.completed.last(),
        }
        .cloned();
        let Some(frontier) = frontier else {
            return false;
        };
        let candidate = EventCursor {
            created_at: frontier.created_at.saturating_sub(self.reorder_window_secs),
            event_id: frontier.event_id.clone(),
        };
        let advances = self
            .state
            .last_processed
            .as_ref()
            .is_none_or(|current| candidate > *current);
        if advances {
            self.state.last_processed = Some(candidate.clone());
        }
        self.completed.retain(|cursor| cursor > &frontier);
        advances
    }

    fn persist(&self) -> Result<(), String> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| "inbox cursor path has no parent".to_string())?;
        fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .map_err(|error| format!("chmod {}: {error}", parent.display()))?;
        }

        let payload = serde_json::to_vec_pretty(&self.state)
            .map_err(|error| format!("serialize cursor: {error}"))?;
        let temp_path = self.path.with_extension("json.tmp");
        let mut options = OpenOptions::new();
        options.create(true).truncate(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temp_path)
            .map_err(|error| format!("open {}: {error}", temp_path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|error| format!("chmod {}: {error}", temp_path.display()))?;
        }
        file.write_all(&payload)
            .map_err(|error| format!("write {}: {error}", temp_path.display()))?;
        file.sync_all()
            .map_err(|error| format!("sync {}: {error}", temp_path.display()))?;
        fs::rename(&temp_path, &self.path).map_err(|error| {
            format!(
                "rename {} to {}: {error}",
                temp_path.display(),
                self.path.display()
            )
        })?;
        #[cfg(unix)]
        {
            fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| format!("sync {}: {error}", parent.display()))?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct CatchupFloor {
    pub since: u64,
    pub age_truncated_from: Option<u64>,
}

#[derive(Debug, Default)]
pub(crate) struct CatchupBatch {
    pub events: VecDeque<BuzzEvent>,
    pub count_truncated: bool,
    pub skipped_filter_groups: usize,
}

/// Fetch a bounded, startup-only replay across the resolved channel filters.
/// The relay returns newest-first; callers receive chronological order.
pub(crate) async fn fetch_startup_catchup(
    rest: &RestClient,
    channel_filters: &HashMap<Uuid, ChannelFilter>,
    agent_pubkey_hex: &str,
    since: u64,
    max_events: usize,
) -> Result<CatchupBatch, RelayError> {
    let mut groups: BTreeMap<(Option<Vec<u32>>, bool), Vec<String>> = BTreeMap::new();
    for (channel_id, channel_filter) in channel_filters {
        let mut kinds = channel_filter.kinds.clone();
        if let Some(values) = &mut kinds {
            values.sort_unstable();
            values.dedup();
        }
        groups
            .entry((kinds, channel_filter.require_mention))
            .or_default()
            .push(channel_id.to_string());
    }
    for channels in groups.values_mut() {
        channels.sort_unstable();
    }

    let mut remaining_budget = max_events.saturating_add(1);
    let group_count = groups.len();
    let mut filters = Vec::new();
    let mut skipped_filter_groups = 0;
    let mut group_limits = HashMap::new();
    let mut channel_groups = HashMap::new();
    for (group_index, ((kinds, require_mention), channels)) in groups.into_iter().enumerate() {
        if remaining_budget == 0 {
            skipped_filter_groups += 1;
            continue;
        }
        let groups_left = group_count.saturating_sub(group_index).max(1);
        let limit = remaining_budget.div_ceil(groups_left).max(1);
        remaining_budget = remaining_budget.saturating_sub(limit);

        for channel in &channels {
            if let Ok(channel_id) = channel.parse::<Uuid>() {
                channel_groups.insert(channel_id, group_index);
            }
        }
        group_limits.insert(group_index, limit);

        let mut filter = Filter::new()
            .custom_tags(SingleLetterTag::lowercase(Alphabet::H), channels)
            .since(Timestamp::from(since))
            .limit(limit);
        if let Some(kinds) = kinds {
            filter = filter.kinds(kinds.into_iter().map(|kind| Kind::Custom(kind as u16)));
        }
        if require_mention {
            filter = filter.custom_tag(SingleLetterTag::lowercase(Alphabet::P), agent_pubkey_hex);
        }
        filters.push(filter);
    }

    if filters.is_empty() {
        return Ok(CatchupBatch {
            skipped_filter_groups,
            ..CatchupBatch::default()
        });
    }

    let value = rest.query(&filters).await?;
    let rows = value.as_array().ok_or_else(|| {
        RelayError::Http("expected JSON array from /query (inbox catch-up)".into())
    })?;
    let mut seen_ids = HashSet::new();
    let mut group_counts: HashMap<usize, usize> = HashMap::new();
    let mut events = Vec::new();
    for row in rows {
        let event: Event = serde_json::from_value(row.clone()).map_err(RelayError::Json)?;
        let Some(channel_id) = event.tags.iter().find_map(|tag| {
            let values = tag.as_slice();
            (values.first().map(|value| value.as_str()) == Some("h"))
                .then(|| values.get(1))
                .flatten()
                .and_then(|value| value.as_str().parse::<Uuid>().ok())
        }) else {
            tracing::warn!(event_id = %event.id, "inbox catch-up event missing valid h tag; skipping");
            continue;
        };
        if seen_ids.insert(event.id.to_hex()) {
            if let Some(group_index) = channel_groups.get(&channel_id) {
                *group_counts.entry(*group_index).or_default() += 1;
            }
            events.push(BuzzEvent { channel_id, event });
        }
    }
    events.sort_by(|left, right| {
        EventCursor::from_event(&left.event).cmp(&EventCursor::from_event(&right.event))
    });
    let group_may_be_truncated = group_counts
        .iter()
        .any(|(group_index, count)| *count >= group_limits.get(group_index).copied().unwrap_or(0));
    let count_truncated =
        events.len() > max_events || skipped_filter_groups > 0 || group_may_be_truncated;
    if events.len() > max_events {
        let drop_count = events.len() - max_events;
        events.drain(..drop_count);
    }

    Ok(CatchupBatch {
        events: events.into(),
        count_truncated,
        skipped_filter_groups,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::{EventBuilder, Keys, Tag};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    fn signed_event(keys: &Keys, channel_id: Uuid, created_at: u64, content: &str) -> Event {
        EventBuilder::new(Kind::TextNote, content)
            .tags([
                Tag::parse(["h", &channel_id.to_string()]).unwrap(),
                Tag::parse(["p", &keys.public_key().to_hex()]).unwrap(),
            ])
            .custom_created_at(Timestamp::from(created_at))
            .sign_with_keys(keys)
            .unwrap()
    }

    async fn mock_query_rest(keys: Keys, response: Vec<Event>) -> RestClient {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4096];
            loop {
                let read = socket.read(&mut buffer).await.unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let body = serde_json::to_vec(&response).unwrap();
            let reply = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            socket.write_all(reply.as_bytes()).await.unwrap();
            socket.write_all(&body).await.unwrap();
        });
        RestClient {
            http: reqwest::Client::new(),
            base_url: format!("http://{address}"),
            keys,
            auth_tag_json: None,
        }
    }

    #[tokio::test]
    async fn restart_catches_unfinished_mention_older_than_five_seconds_exactly_once() {
        let temp = std::env::temp_dir().join(format!("buzz-acp-inbox-{}", Uuid::new_v4()));
        let keys = Keys::generate();
        let channel_id = Uuid::new_v4();
        let now = 100_000;
        let previous = signed_event(&keys, channel_id, now - 20, "previous");
        let mention = signed_event(&keys, channel_id, now - 10, "unfinished");
        let pubkey = keys.public_key().to_hex();

        let mut first = InboxCursorStore::load(&temp, &pubkey, now - 5, 300);
        first.mark_processed([&previous]);
        assert!(first.begin_event(&mention));
        drop(first); // restart before the mention reaches a terminal result

        let filters = HashMap::from([(
            channel_id,
            ChannelFilter {
                kinds: Some(vec![1]),
                require_mention: true,
            },
        )]);
        let mut restarted = InboxCursorStore::load(&temp, &pubkey, now - 5, 300);
        let floor = restarted.catchup_since(now, 86_400);
        let rest = mock_query_rest(keys.clone(), vec![mention.clone()]).await;
        let caught = fetch_startup_catchup(&rest, &filters, &pubkey, floor.since, 10)
            .await
            .unwrap();
        assert_eq!(caught.events.len(), 1);
        assert!(restarted.begin_event(&caught.events[0].event));
        restarted.mark_processed([&caught.events[0].event]);
        drop(restarted);

        let mut third = InboxCursorStore::load(&temp, &pubkey, now - 5, 300);
        let rest = mock_query_rest(keys, vec![mention]).await;
        let caught = fetch_startup_catchup(&rest, &filters, &pubkey, floor.since, 10)
            .await
            .unwrap();
        let delivered = caught
            .events
            .iter()
            .filter(|event| third.begin_event(&event.event))
            .count();
        assert_eq!(delivered, 0, "processed replay must be deduplicated");

        std::fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn corrupt_cursor_falls_back_without_crashing() {
        let temp = std::env::temp_dir().join(format!("buzz-acp-inbox-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&temp).unwrap();
        let pubkey = "11".repeat(32);
        let path = temp.join(format!("{pubkey}.inbox-cursor.json"));
        std::fs::write(&path, b"not-json").unwrap();

        let store = InboxCursorStore::load(&temp, &pubkey, 95, 300);
        assert_eq!(store.load_status(), CursorLoadStatus::Corrupt);
        assert_eq!(store.catchup_since(100, 86_400).since, 95);

        std::fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn newer_completion_does_not_advance_past_older_unfinished_event() {
        let temp = std::env::temp_dir().join(format!("buzz-acp-inbox-{}", Uuid::new_v4()));
        let keys = Keys::generate();
        let channel_id = Uuid::new_v4();
        let previous = signed_event(&keys, channel_id, 80, "previous");
        let older = signed_event(&keys, channel_id, 90, "older unfinished");
        let newer = signed_event(&keys, channel_id, 100, "newer completed");
        let pubkey = keys.public_key().to_hex();

        let mut store = InboxCursorStore::load(&temp, &pubkey, 75, 10);
        store.mark_processed_at([&previous], 90);
        assert!(store.begin_event(&older));
        assert!(store.begin_event(&newer));
        store.mark_processed_at([&newer], 110);
        assert_eq!(store.catchup_since(110, 1_000).since, 70);

        store.mark_processed_at([&older], 110);
        assert_eq!(store.catchup_since(110, 1_000).since, 90);

        std::fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn old_frontier_keeps_replay_floor_behind_frontier() {
        let temp = std::env::temp_dir().join(format!("buzz-acp-inbox-{}", Uuid::new_v4()));
        let keys = Keys::generate();
        let channel_id = Uuid::new_v4();
        let frontier = signed_event(&keys, channel_id, 100, "old frontier");
        let pubkey = keys.public_key().to_hex();

        let mut store = InboxCursorStore::load(&temp, &pubkey, 995, 10);
        store.mark_processed_at([&frontier], 1_000);

        assert_eq!(store.catchup_since(1_000, 1_000).since, 90);

        std::fs::remove_dir_all(temp).unwrap();
    }

    #[tokio::test]
    async fn restart_replays_delayed_older_event_within_reorder_window_once() {
        let temp = std::env::temp_dir().join(format!("buzz-acp-inbox-{}", Uuid::new_v4()));
        let keys = Keys::generate();
        let channel_id = Uuid::new_v4();
        let now = 100_000;
        let newer = signed_event(&keys, channel_id, now - 10, "newer");
        let delayed = signed_event(&keys, channel_id, now - 100, "delayed older");
        let pubkey = keys.public_key().to_hex();
        let filters = HashMap::from([(
            channel_id,
            ChannelFilter {
                kinds: Some(vec![1]),
                require_mention: true,
            },
        )]);

        let mut first = InboxCursorStore::load(&temp, &pubkey, now - 5, 300);
        first.mark_processed_at([&newer], now);
        assert_eq!(first.catchup_since(now, 86_400).since, now - 310);
        drop(first);

        let mut restarted = InboxCursorStore::load(&temp, &pubkey, now - 5, 300);
        let floor = restarted.catchup_since(now, 86_400);
        let rest = mock_query_rest(keys.clone(), vec![delayed.clone()]).await;
        let caught = fetch_startup_catchup(&rest, &filters, &pubkey, floor.since, 10)
            .await
            .unwrap();
        assert_eq!(caught.events.len(), 1);
        assert!(restarted.begin_event(&caught.events[0].event));
        restarted.mark_processed_at([&caught.events[0].event], now + 1);
        drop(restarted);

        let mut third = InboxCursorStore::load(&temp, &pubkey, now - 5, 300);
        let rest = mock_query_rest(keys, vec![delayed]).await;
        let caught = fetch_startup_catchup(&rest, &filters, &pubkey, floor.since, 10)
            .await
            .unwrap();
        let delivered = caught
            .events
            .iter()
            .filter(|event| third.begin_event(&event.event))
            .count();
        assert_eq!(delivered, 0, "delayed replay must be deduplicated");

        std::fs::remove_dir_all(temp).unwrap();
    }
}
