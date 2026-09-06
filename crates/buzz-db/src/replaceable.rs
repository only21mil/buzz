//! Replaceable event persistence and coordinate-serialized repository tombstones.
//!
//! The fork NIP-RS watermark and repository deletion lock ordering are preserved.

use crate::{event, Db, DbError, Result};
use buzz_core::{CommunityId, StoredEvent};
use sqlx::Row;
use uuid::Uuid;

/// Result of atomically storing a repository deletion tombstone and applying it
/// to the current kind-30617 announcement head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepoDeletionOutcome {
    /// A live announcement at or before the tombstone timestamp was deleted.
    Deleted,
    /// The tombstone was an exact replay and no live announcement remains.
    AlreadyAbsent,
    /// A new tombstone named no live announcement, so the tombstone was rolled back.
    NotFound,
    /// The live announcement is newer than the tombstone, so no change was committed.
    StaleHead,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct RepoDeletionTarget {
    pub(crate) owner_pubkey: Vec<u8>,
    pub(crate) repo_id: String,
}

pub(crate) fn repo_deletion_target(tombstone: &nostr::Event) -> Result<RepoDeletionTarget> {
    const REPO_ANNOUNCEMENT_KIND: &str = "30617";

    if buzz_core::kind::event_kind_i32(tombstone) != 5 {
        return Err(DbError::InvalidData(format!(
            "repository deletion tombstone must be kind 5, got {}",
            buzz_core::kind::event_kind_i32(tombstone)
        )));
    }

    let mut coordinate: Option<&str> = None;
    for tag in tombstone.tags.iter() {
        let parts = tag.as_slice();
        match parts.first().map(String::as_str) {
            Some("a") => {
                if coordinate.is_some() || parts.len() != 2 {
                    return Err(DbError::InvalidData(
                        "repository deletion tombstone must contain exactly one canonical a tag"
                            .into(),
                    ));
                }
                coordinate = Some(parts[1].as_str());
            }
            Some("e") => {
                return Err(DbError::InvalidData(
                    "repository deletion tombstone must not contain e tags".into(),
                ));
            }
            _ => {}
        }
    }

    let coordinate = coordinate.ok_or_else(|| {
        DbError::InvalidData(
            "repository deletion tombstone must contain exactly one canonical a tag".into(),
        )
    })?;
    let mut parts = coordinate.splitn(3, ':');
    let (Some(kind), Some(owner_hex), Some(repo_id)) = (parts.next(), parts.next(), parts.next())
    else {
        return Err(DbError::InvalidData(
            "repository deletion target must be 30617:<lowercase-owner-hex>:<repo-id>".into(),
        ));
    };
    if kind != REPO_ANNOUNCEMENT_KIND
        || owner_hex.len() != 64
        || owner_hex
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
        || repo_id.is_empty()
        || repo_id.len() > event::D_TAG_MAX_LEN
    {
        return Err(DbError::InvalidData(
            "repository deletion target must be 30617:<lowercase-owner-hex>:<repo-id>".into(),
        ));
    }
    let owner = nostr::PublicKey::from_hex(owner_hex).map_err(|error| {
        DbError::InvalidData(format!(
            "repository deletion target contains an invalid owner pubkey: {error}"
        ))
    })?;

    Ok(RepoDeletionTarget {
        owner_pubkey: owner.to_bytes().to_vec(),
        repo_id: repo_id.to_owned(),
    })
}

pub(crate) fn event_replacement_lock_key(
    community_id: CommunityId,
    kind: i32,
    pubkey: &[u8],
    coordinate: Option<&[u8]>,
) -> i64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    let kind_bytes = kind.to_le_bytes();
    for bytes in [
        community_id.as_uuid().as_bytes().as_slice(),
        kind_bytes.as_slice(),
        pubkey,
    ] {
        for byte in bytes {
            hash ^= *byte as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
    }
    if let Some(coordinate) = coordinate {
        for byte in coordinate {
            hash ^= *byte as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
    }
    hash as i64
}

impl Db {
    /// Atomically replace a replaceable event: NIP-16 kinds (0, 3, 41, 10000–19999)
    /// and NIP-29 discovery state (39000–39002, called from side_effects.rs).
    ///
    /// Keeps only the event with the highest `created_at` per (kind, pubkey, channel_id).
    /// Same-second ties are broken by lowest event `id` (NIP-16 deterministic ordering).
    /// Returns `(event, false)` for stale writes and duplicate IDs — callers should
    /// skip fan-out/dispatch when `was_inserted` is false.
    pub async fn replace_addressable_event(
        &self,
        community_id: CommunityId,
        event: &nostr::Event,
        channel_id: Option<Uuid>,
    ) -> Result<(StoredEvent, bool)> {
        let kind_i32 = buzz_core::kind::event_kind_i32(event);
        let pubkey_bytes = event.pubkey.to_bytes();
        let created_at_secs = event.created_at.as_secs() as i64;
        let created_at = chrono::DateTime::from_timestamp(created_at_secs, 0)
            .ok_or(DbError::InvalidTimestamp(created_at_secs))?;

        // Collisions only cause extra serialization; they cannot change behavior.
        let lock_key = event_replacement_lock_key(
            community_id,
            kind_i32,
            pubkey_bytes.as_slice(),
            channel_id.as_ref().map(|id| id.as_bytes().as_slice()),
        );

        let mut tx = self.pool.begin().await?;

        // Serialize all writers for the same (kind, pubkey, channel_id) tuple.
        // Advisory lock is transaction-scoped — released on commit/rollback.
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(lock_key)
            .execute(&mut *tx)
            .await?;

        // Check for the newest existing event. ORDER BY + LIMIT 1 is defensive against
        // historical data where prior bugs may have left multiple live rows.
        let existing: Option<(chrono::DateTime<chrono::Utc>, Vec<u8>)> = sqlx::query_as(
            "SELECT created_at, id FROM events \
             WHERE community_id = $1 AND kind = $2 AND pubkey = $3 \
             AND channel_id IS NOT DISTINCT FROM $4 \
             AND deleted_at IS NULL \
             ORDER BY created_at DESC, id ASC LIMIT 1",
        )
        .bind(community_id.as_uuid())
        .bind(kind_i32)
        .bind(pubkey_bytes.as_slice())
        .bind(channel_id)
        .fetch_optional(&mut *tx)
        .await?;

        // Stale-write protection: reject if incoming is not newer.
        // NIP-16: created_at is second-resolution. On same-second tie, lowest
        // event id (lexicographic) wins — deterministic across relays.
        let incoming_id = event.id.as_bytes().as_slice();
        if let Some((existing_ts, existing_id)) = existing {
            let dominated = created_at < existing_ts
                || (created_at == existing_ts && incoming_id >= existing_id.as_slice());
            if dominated {
                tx.rollback().await?;
                let received_at = chrono::Utc::now();
                return Ok((
                    StoredEvent::with_received_at(event.clone(), received_at, channel_id, false),
                    false,
                ));
            }
        }

        // Soft-delete the old event (if any). IS NOT DISTINCT FROM for NULL safety.
        sqlx::query(
            "UPDATE events SET deleted_at = NOW() \
             WHERE community_id = $1 AND kind = $2 AND pubkey = $3 \
             AND channel_id IS NOT DISTINCT FROM $4 \
             AND deleted_at IS NULL",
        )
        .bind(community_id.as_uuid())
        .bind(kind_i32)
        .bind(pubkey_bytes.as_slice())
        .bind(channel_id)
        .execute(&mut *tx)
        .await?;

        // Insert the new event inside the same transaction.
        let sig_bytes = event.sig.serialize();
        let tags_json = serde_json::to_value(&event.tags)?;
        let received_at = chrono::Utc::now();
        let d_tag = crate::event::extract_d_tag(event);

        let insert_result = sqlx::query(
            "INSERT INTO events (community_id, id, pubkey, created_at, kind, tags, content, sig, received_at, channel_id, d_tag) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
             ON CONFLICT DO NOTHING",
        )
        .bind(community_id.as_uuid())
        .bind(event.id.as_bytes().as_slice())
        .bind(pubkey_bytes.as_slice())
        .bind(created_at)
        .bind(kind_i32)
        .bind(&tags_json)
        .bind(&event.content)
        .bind(sig_bytes.as_slice())
        .bind(received_at)
        .bind(channel_id)
        .bind(d_tag.as_deref())
        .execute(&mut *tx)
        .await?;

        let was_inserted = insert_result.rows_affected() > 0;
        if !was_inserted {
            // ON CONFLICT fired — the event ID already exists. Rollback the
            // soft-delete so we don't lose the previous replaceable event.
            tx.rollback().await?;
            return Ok((
                StoredEvent::with_received_at(event.clone(), received_at, channel_id, false),
                false,
            ));
        }

        tx.commit().await?;

        // Mentions are a denormalized index — safe outside the transaction.
        // insert_event() normally handles this, but we inlined the INSERT above.
        if let Err(e) = crate::insert_mentions(&self.pool, community_id, event, channel_id).await {
            tracing::warn!(event_id = %event.id, "Failed to insert mentions: {e}");
        }

        Ok((
            StoredEvent::with_received_at(event.clone(), received_at, channel_id, true),
            true,
        ))
    }

    /// Returns whether the relay-authored NIP-43 snapshot is absent or differs
    /// from the canonical membership rows for `community_id`.
    ///
    /// Snapshot and canonical rows are compared directly rather than by
    /// timestamp: relay membership events use whole-second Nostr timestamps,
    /// and multiple mutations within one second must still be repaired.
    pub async fn nip43_membership_snapshot_needs_reconciliation(
        &self,
        community_id: CommunityId,
        relay_pubkey: &nostr::PublicKey,
    ) -> Result<bool> {
        let snapshot = self
            .query_events(&crate::event::EventQuery {
                kinds: Some(vec![buzz_core::kind::KIND_NIP43_MEMBERSHIP_LIST as i32]),
                pubkey: Some(relay_pubkey.to_bytes().to_vec()),
                global_only: true,
                limit: Some(1),
                ..crate::event::EventQuery::for_community(community_id)
            })
            .await?
            .into_iter()
            .next();
        let members = self.list_relay_members(community_id).await?;

        let Some(snapshot) = snapshot else {
            return Ok(true);
        };
        let mut snapshot_members = snapshot
            .event
            .tags
            .iter()
            .filter_map(|tag| {
                let parts = tag.as_slice();
                (parts.first().map(String::as_str) == Some("member") && parts.len() >= 3)
                    .then(|| (parts[1].to_ascii_lowercase(), parts[2].clone()))
            })
            .collect::<Vec<_>>();
        let mut canonical_members = members
            .into_iter()
            .map(|member| (member.pubkey.to_ascii_lowercase(), member.role))
            .collect::<Vec<_>>();
        snapshot_members.sort_unstable();
        canonical_members.sort_unstable();

        Ok(snapshot_members != canonical_members)
    }

    /// Atomically publish a NIP-43 membership snapshot under a single
    /// transaction-scoped advisory lock.
    ///
    /// This method acquires the per-community snapshot lock, reads the
    /// current membership, builds the event, and replaces the prior snapshot
    /// — all inside one transaction on one database connection. This
    /// prevents the stale-snapshot race where a concurrent publication reads
    /// older state and overwrites a newer snapshot by arrival order.
    ///
    pub async fn publish_nip43_membership_locked(
        &self,
        community_id: CommunityId,
        relay_keypair: &nostr::Keys,
    ) -> Result<(StoredEvent, bool, usize)> {
        use nostr::{EventBuilder, Kind, Tag};

        let kind_i32 = buzz_core::kind::KIND_NIP43_MEMBERSHIP_LIST as i32;
        let pubkey_bytes = relay_keypair.public_key().to_bytes();

        let lock_key =
            event_replacement_lock_key(community_id, kind_i32, pubkey_bytes.as_slice(), None);

        let mut tx = self.pool.begin().await?;

        // Acquire the per-community snapshot lock BEFORE reading members.
        // This serializes the entire read-build-write cycle: a concurrent
        // publication will block here until our transaction commits, then
        // read the updated membership state.
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(lock_key)
            .execute(&mut *tx)
            .await?;

        // Read current members inside the locked transaction.
        let rows = sqlx::query(
            "SELECT pubkey, role FROM relay_members \
             WHERE community_id = $1 ORDER BY created_at ASC",
        )
        .bind(community_id.as_uuid())
        .fetch_all(&mut *tx)
        .await?;

        let member_count = rows.len();

        // Build the NIP-43 event from the locked member rows.
        let mut tags: Vec<Tag> = Vec::with_capacity(member_count + 1);
        // NIP-70 protected-event marker.
        tags.push(Tag::parse(["-"]).map_err(|e| {
            crate::error::DbError::InvalidData(format!("failed to build '-' tag: {e}"))
        })?);
        for row in &rows {
            let pubkey: String = row.try_get("pubkey")?;
            let role: String = row.try_get("role")?;
            tags.push(Tag::parse(["member", &pubkey, &role]).map_err(|e| {
                crate::error::DbError::InvalidData(format!("failed to build member tag: {e}"))
            })?);
        }

        let event = EventBuilder::new(Kind::Custom(kind_i32 as u16), "")
            .tags(tags)
            .sign_with_keys(relay_keypair)
            .map_err(|e| {
                crate::error::DbError::InvalidData(format!("failed to sign kind:13534: {e}"))
            })?;

        let created_at_secs = event.created_at.as_secs() as i64;
        let created_at = chrono::DateTime::from_timestamp(created_at_secs, 0)
            .ok_or(DbError::InvalidTimestamp(created_at_secs))?;
        let sig_bytes = event.sig.serialize();
        let tags_json = serde_json::to_value(&event.tags)?;
        let received_at = chrono::Utc::now();
        let d_tag = crate::event::extract_d_tag(&event);

        // Soft-delete prior snapshots — unconditional, the relay is authoritative.
        sqlx::query(
            "UPDATE events SET deleted_at = NOW() \
             WHERE community_id = $1 AND kind = $2 AND pubkey = $3 \
             AND channel_id IS NULL \
             AND deleted_at IS NULL",
        )
        .bind(community_id.as_uuid())
        .bind(kind_i32)
        .bind(pubkey_bytes.as_slice())
        .execute(&mut *tx)
        .await?;

        let insert_result = sqlx::query(
            "INSERT INTO events (community_id, id, pubkey, created_at, kind, tags, content, sig, received_at, channel_id, d_tag) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
             ON CONFLICT DO NOTHING",
        )
        .bind(community_id.as_uuid())
        .bind(event.id.as_bytes().as_slice())
        .bind(pubkey_bytes.as_slice())
        .bind(created_at)
        .bind(kind_i32)
        .bind(&tags_json)
        .bind(&event.content)
        .bind(sig_bytes.as_slice())
        .bind(received_at)
        .bind::<Option<Uuid>>(None)
        .bind(d_tag.as_deref())
        .execute(&mut *tx)
        .await?;

        let was_inserted = insert_result.rows_affected() > 0;
        if !was_inserted {
            tx.rollback().await?;
            return Ok((
                StoredEvent::with_received_at(event, received_at, None, false),
                false,
                member_count,
            ));
        }

        tx.commit().await?;

        if let Err(e) = crate::insert_mentions(&self.pool, community_id, &event, None).await {
            tracing::warn!(event_id = %event.id, "Failed to insert mentions: {e}");
        }

        Ok((
            StoredEvent::with_received_at(event, received_at, None, true),
            true,
            member_count,
        ))
    }

    /// Atomically replace a NIP-33 parameterized replaceable event (kind 30000–39999).
    ///
    /// Keeps only the event with the highest `created_at` per `(kind, pubkey, d_tag)`.
    /// Same-second ties are broken by lowest event `id` (deterministic ordering).
    /// The entire check → retire old payload → insert runs in a single transaction
    /// with an advisory lock to prevent concurrent-insert races. NIP-RS read-state
    /// coordinates hard-delete the superseded payload and preserve a compact
    /// ordering watermark. Buzz mesh status coordinates also hard-delete their
    /// superseded heartbeat payload because only the live head has product
    /// value; other NIP-33 kinds retain soft-deleted history.
    ///
    /// **Channel policy:** NIP-33 replacement keys on `(kind, pubkey, d_tag)` globally —
    /// `channel_id` is NOT part of the replacement key. This matches the Nostr spec:
    /// an author's parameterized replaceable event is a single global resource identified
    /// by its d-tag, regardless of which channel it was submitted to. The `channel_id`
    /// parameter is stored on the new row for query scoping but does not affect replacement.
    ///
    /// Note: `replace_addressable_event()` keys on `channel_id` because it serves
    /// relay-signed NIP-29 group metadata (kind 39000–39002) where the relay is the
    /// author and channel_id distinguishes groups. User-submitted NIP-33 events use
    /// this function instead, where the author's pubkey + d-tag is the natural key.
    pub async fn replace_parameterized_event(
        &self,
        community_id: CommunityId,
        event: &nostr::Event,
        d_tag: &str,
        channel_id: Option<Uuid>,
    ) -> Result<(StoredEvent, bool)> {
        let kind_i32 = buzz_core::kind::event_kind_i32(event);
        let pubkey_bytes = event.pubkey.to_bytes();
        let created_at_secs = event.created_at.as_secs() as i64;
        let created_at = chrono::DateTime::from_timestamp(created_at_secs, 0)
            .ok_or(DbError::InvalidTimestamp(created_at_secs))?;

        let lock_key = event_replacement_lock_key(
            community_id,
            kind_i32,
            pubkey_bytes.as_slice(),
            Some(d_tag.as_bytes()),
        );

        let mut tx = self.pool.begin().await?;

        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(lock_key)
            .execute(&mut *tx)
            .await?;

        let d_tag_count = event
            .tags
            .iter()
            .filter(|tag| tag.as_slice().first().is_some_and(|part| part == "d"))
            .count();
        let has_exact_d_tag = event.tags.iter().any(|tag| {
            let parts = tag.as_slice();
            parts.len() >= 2 && parts[0] == "d" && parts[1] == d_tag
        });
        let read_state_t_tag_count = event
            .tags
            .iter()
            .filter(|tag| {
                let parts = tag.as_slice();
                parts.len() == 2 && parts[0] == "t" && parts[1] == "read-state"
            })
            .count();
        let is_nip_rs = kind_i32 == buzz_core::kind::KIND_READ_STATE as i32
            && d_tag_count == 1
            && has_exact_d_tag
            && d_tag.strip_prefix("read-state:").is_some_and(|slot| {
                slot.len() == 32
                    && slot
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            })
            && read_state_t_tag_count == 1;
        let is_buzz_mesh_status = kind_i32 == buzz_core::kind::KIND_BOOKMARK_SET as i32
            && d_tag.starts_with("buzz-mesh-member-status:")
            && event.tags.iter().any(|tag| {
                let parts = tag.as_slice();
                parts.len() == 2 && parts[0] == "k" && parts[1] == "buzz-mesh-status"
            });
        let hard_delete_superseded = is_nip_rs || is_buzz_mesh_status;

        // Check the live head and, for NIP-RS, the compact historical ordering
        // watermark. The watermark remains after a NIP-09 coordinate deletion,
        // preventing a previously accepted signed blob from being resurrected.
        let existing: Option<(chrono::DateTime<chrono::Utc>, Vec<u8>)> = sqlx::query_as(
            "SELECT created_at, id FROM events \
             WHERE community_id = $1 AND kind = $2 AND pubkey = $3 AND d_tag = $4 AND deleted_at IS NULL \
             ORDER BY created_at DESC, id ASC LIMIT 1",
        )
        .bind(community_id.as_uuid())
        .bind(kind_i32)
        .bind(pubkey_bytes.as_slice())
        .bind(d_tag)
        .fetch_optional(&mut *tx)
        .await?;
        let watermark: Option<(chrono::DateTime<chrono::Utc>, Vec<u8>)> = if is_nip_rs {
            sqlx::query_as(
                "SELECT created_at, event_id FROM parameterized_event_watermarks \
                 WHERE community_id = $1 AND kind = $2 AND pubkey = $3 AND d_tag = $4",
            )
            .bind(community_id.as_uuid())
            .bind(kind_i32)
            .bind(pubkey_bytes.as_slice())
            .bind(d_tag)
            .fetch_optional(&mut *tx)
            .await?
        } else {
            None
        };

        // Stale-write protection: reject if either durable ordering source
        // dominates the incoming tuple. Equal timestamps use lowest event id.
        let incoming_id = event.id.as_bytes().as_slice();
        let dominated =
            existing
                .iter()
                .chain(watermark.iter())
                .any(|(accepted_ts, accepted_id)| {
                    created_at < *accepted_ts
                        || (created_at == *accepted_ts && incoming_id >= accepted_id.as_slice())
                });
        if dominated {
            tx.rollback().await?;
            let received_at = chrono::Utc::now();
            return Ok((
                StoredEvent::with_received_at(event.clone(), received_at, channel_id, false),
                false,
            ));
        }

        if existing.is_some() {
            if is_nip_rs {
                // Migration 0011 rejects regex-coordinate hard deletes from
                // pre-fix writers. Authorize only this corrected NIP-RS delete,
                // transaction-locally so pooled connections cannot leak it.
                sqlx::query("SELECT set_config('buzz.nip_rs_hard_delete', 'on', true)")
                    .execute(&mut *tx)
                    .await?;
            }
            let statement = if hard_delete_superseded {
                "DELETE FROM events \
                 WHERE community_id = $1 AND kind = $2 AND pubkey = $3 AND d_tag = $4 AND deleted_at IS NULL"
            } else {
                "UPDATE events SET deleted_at = NOW() \
                 WHERE community_id = $1 AND kind = $2 AND pubkey = $3 AND d_tag = $4 AND deleted_at IS NULL"
            };
            sqlx::query(statement)
                .bind(community_id.as_uuid())
                .bind(kind_i32)
                .bind(pubkey_bytes.as_slice())
                .bind(d_tag)
                .execute(&mut *tx)
                .await?;

            if hard_delete_superseded {
                if let Some((_, existing_id)) = &existing {
                    // Event first, mentions second: migration 0009's live-event
                    // fence uses this global lock order to avoid deadlocks.
                    sqlx::query(
                        "DELETE FROM event_mentions WHERE community_id = $1 AND event_id = $2",
                    )
                    .bind(community_id.as_uuid())
                    .bind(existing_id)
                    .execute(&mut *tx)
                    .await?;
                }
            }
        }

        // Insert the new event inside the transaction.
        let sig_bytes = event.sig.serialize();
        let tags_json = serde_json::to_value(&event.tags)?;
        let received_at = chrono::Utc::now();

        let insert_result = sqlx::query(
            "INSERT INTO events (community_id, id, pubkey, created_at, kind, tags, content, sig, received_at, channel_id, d_tag, not_before) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
             ON CONFLICT DO NOTHING",
        )
        .bind(community_id.as_uuid())
        .bind(event.id.as_bytes().as_slice())
        .bind(pubkey_bytes.as_slice())
        .bind(created_at)
        .bind(kind_i32)
        .bind(&tags_json)
        .bind(&event.content)
        .bind(sig_bytes.as_slice())
        .bind(received_at)
        .bind(channel_id)
        .bind(d_tag)
        .bind(event::extract_not_before(event))
        .execute(&mut *tx)
        .await?;

        let was_inserted = insert_result.rows_affected() > 0;
        if !was_inserted {
            tx.rollback().await?;
            return Ok((
                StoredEvent::with_received_at(event.clone(), received_at, channel_id, false),
                false,
            ));
        }

        if is_nip_rs {
            sqlx::query(
                "INSERT INTO parameterized_event_watermarks \
                     (community_id, kind, pubkey, d_tag, created_at, event_id) \
                 VALUES ($1, $2, $3, $4, $5, $6) \
                 ON CONFLICT (community_id, kind, pubkey, d_tag) DO UPDATE SET \
                     created_at = EXCLUDED.created_at, event_id = EXCLUDED.event_id",
            )
            .bind(community_id.as_uuid())
            .bind(kind_i32)
            .bind(pubkey_bytes.as_slice())
            .bind(d_tag)
            .bind(created_at)
            .bind(incoming_id)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;

        // Mentions are a denormalized index — safe outside the transaction.
        if let Err(e) = crate::insert_mentions(&self.pool, community_id, event, channel_id).await {
            tracing::warn!(event_id = %event.id, "Failed to insert mentions: {e}");
        }

        Ok((
            StoredEvent::with_received_at(event.clone(), received_at, channel_id, true),
            true,
        ))
    }

    /// Atomically store a kind-5 tombstone and delete its repository announcement.
    ///
    /// The target is derived from the tombstone's sole canonical `a` tag; callers
    /// cannot supply a different owner or repository id. Consequently the lock
    /// key is always `(community, 30617, a-tag owner, repository d-tag)`, never
    /// `(community, 5, tombstone signer, ...)`.
    ///
    /// The transaction takes the exact same advisory lock as
    /// [`Self::replace_parameterized_event`] for the target kind-30617 coordinate.
    /// This prevents a replacement and deletion from observing half of each
    /// other's work. Exact tombstone replays still execute the delete, repairing
    /// a legacy state where the tombstone committed before its side effect.
    ///
    /// A new tombstone is committed only when it deletes a live head. Missing
    /// targets and heads newer than the tombstone roll the insertion back. An
    /// exact replay after a successful deletion returns
    /// [`RepoDeletionOutcome::AlreadyAbsent`].
    pub async fn store_repo_deletion_tombstone(
        &self,
        community_id: CommunityId,
        tombstone: &nostr::Event,
        channel_id: Option<Uuid>,
    ) -> Result<(StoredEvent, RepoDeletionOutcome)> {
        const REPO_ANNOUNCEMENT_KIND: i32 = 30_617;

        let target = repo_deletion_target(tombstone)?;
        let owner_pubkey = target.owner_pubkey.as_slice();
        let repo_id = target.repo_id.as_str();
        let tombstone_kind = buzz_core::kind::event_kind_i32(tombstone);

        let tombstone_created_at_secs = tombstone.created_at.as_secs() as i64;
        let tombstone_created_at = chrono::DateTime::from_timestamp(tombstone_created_at_secs, 0)
            .ok_or(DbError::InvalidTimestamp(tombstone_created_at_secs))?;
        let lock_key = event_replacement_lock_key(
            community_id,
            REPO_ANNOUNCEMENT_KIND,
            owner_pubkey,
            Some(repo_id.as_bytes()),
        );

        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(lock_key)
            .execute(&mut *tx)
            .await?;

        let received_at = chrono::Utc::now();
        let tags_json = serde_json::to_value(&tombstone.tags)?;
        let sig_bytes = tombstone.sig.serialize();
        let insert_result = sqlx::query(
            "INSERT INTO events (community_id, id, pubkey, created_at, kind, tags, content, sig, received_at, channel_id, d_tag, not_before) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NULL, $11) \
             ON CONFLICT DO NOTHING",
        )
        .bind(community_id.as_uuid())
        .bind(tombstone.id.as_bytes().as_slice())
        .bind(tombstone.pubkey.to_bytes().as_slice())
        .bind(tombstone_created_at)
        .bind(tombstone_kind)
        .bind(&tags_json)
        .bind(&tombstone.content)
        .bind(sig_bytes.as_slice())
        .bind(received_at)
        .bind(channel_id)
        .bind(event::extract_not_before(tombstone))
        .execute(&mut *tx)
        .await?;
        let tombstone_inserted = insert_result.rows_affected() > 0;

        let live_head: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
            "SELECT created_at FROM events \
             WHERE community_id = $1 AND kind = $2 AND pubkey = $3 AND d_tag = $4 \
               AND deleted_at IS NULL \
             ORDER BY created_at DESC, id ASC LIMIT 1",
        )
        .bind(community_id.as_uuid())
        .bind(REPO_ANNOUNCEMENT_KIND)
        .bind(owner_pubkey)
        .bind(repo_id)
        .fetch_optional(&mut *tx)
        .await?;

        let stored = |was_inserted| {
            StoredEvent::with_received_at(tombstone.clone(), received_at, channel_id, was_inserted)
        };

        let Some(head_created_at) = live_head else {
            tx.rollback().await?;
            let outcome = if tombstone_inserted {
                RepoDeletionOutcome::NotFound
            } else {
                RepoDeletionOutcome::AlreadyAbsent
            };
            return Ok((stored(false), outcome));
        };

        if head_created_at > tombstone_created_at {
            tx.rollback().await?;
            return Ok((stored(false), RepoDeletionOutcome::StaleHead));
        }

        let delete_result = sqlx::query(
            "UPDATE events SET deleted_at = NOW() \
             WHERE community_id = $1 AND kind = $2 AND pubkey = $3 AND d_tag = $4 \
               AND deleted_at IS NULL AND created_at <= $5",
        )
        .bind(community_id.as_uuid())
        .bind(REPO_ANNOUNCEMENT_KIND)
        .bind(owner_pubkey)
        .bind(repo_id)
        .bind(tombstone_created_at)
        .execute(&mut *tx)
        .await?;
        debug_assert!(delete_result.rows_affected() > 0);

        tx.commit().await?;

        if tombstone_inserted {
            if let Err(error) =
                crate::insert_mentions(&self.pool, community_id, tombstone, channel_id).await
            {
                tracing::warn!(event_id = %tombstone.id, "Failed to insert mentions: {error}");
            }
        }

        Ok((stored(tombstone_inserted), RepoDeletionOutcome::Deleted))
    }
}
