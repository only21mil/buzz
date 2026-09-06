//! Channel membership reads and serialized role changes.
//!
//! Original channel module imports remain available through compatibility reexports.
use crate::channel::{row_to_channel_record, ChannelRecord};
use crate::{Db, DbError, Result};
/// Canonical channel membership role.
pub use buzz_core::channel::MemberRole;
use buzz_core::CommunityId;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

/// A channel membership row as returned from the database.
#[derive(Debug, Clone)]
pub struct MemberRecord {
    /// The channel this membership belongs to.
    pub channel_id: Uuid,
    /// Compressed public key bytes of the member.
    pub pubkey: Vec<u8>,
    /// Role string (e.g. `"owner"`, `"member"`, `"bot"`).
    pub role: String,
    /// When the member joined.
    pub joined_at: DateTime<Utc>,
    /// Who invited this member, if applicable.
    pub invited_by: Option<Vec<u8>>,
    /// When the member was removed, if applicable.
    pub removed_at: Option<DateTime<Utc>>,
}

/// Namespace for the per-channel membership advisory lock. Serializes the
/// role-authorization + last-owner-count + write sequences in [`add_member`]
/// and [`remove_member`] against each other.
///
/// Both functions read an owner COUNT and then write a *different* row than the
/// one they counted, so `READ COMMITTED` snapshot isolation alone permits two
/// concurrent demotions (or a demotion racing a removal) to each observe two
/// owners, each pass, and together leave zero — the exact governance loss the
/// guards exist to prevent. An advisory key rather than `SELECT ... FOR UPDATE`
/// on the channel row: membership is its own contention domain and must not
/// serialize against unrelated channel metadata writers (`update_channel`,
/// `set_topic`, the TTL transition). Distinct key domain from
/// `buzz_channel_ttl:`.
const CHANNEL_MEMBERSHIP_LOCK_NAMESPACE: &str = "buzz_channel_membership:";

/// Take the per-channel membership lock. MUST be the first statement in the
/// transaction that then reads roles/owner counts and writes membership, so the
/// whole check-then-write sequence is atomic against a concurrent one.
pub(crate) async fn acquire_channel_membership_lock(
    tx: &mut Transaction<'_, Postgres>,
    community_id: CommunityId,
    channel_id: Uuid,
) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!(
            "{CHANNEL_MEMBERSHIP_LOCK_NAMESPACE}{}:{}",
            community_id.as_uuid(),
            channel_id
        ))
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Add a member to a channel.
///
/// Role enforcement:
/// - Open channels: `invited_by` is optional; role is forced to `Member` regardless of
///   what the caller passes — callers cannot self-assign elevated roles.
/// - Private channels: requires an `invited_by` who is an active owner/admin, the channel
///   creator bootstrapping their own first membership, or the target adding themselves
///   (idempotent re-add — an active member's *role* still cannot change this way).
/// - Elevated roles (`Owner`, `Admin`) may only be granted by an existing owner/admin,
///   even on open channels.
///
/// The entire check-then-insert sequence runs inside a transaction to prevent TOCTOU
/// races (e.g. the inviter being removed between the role check and the INSERT).
pub async fn add_member(
    pool: &PgPool,
    community_id: CommunityId,
    channel_id: Uuid,
    pubkey: &[u8],
    role: MemberRole,
    invited_by: Option<&[u8]>,
) -> Result<MemberRecord> {
    if pubkey.len() != 32 {
        return Err(DbError::InvalidData(format!(
            "pubkey must be 32 bytes, got {}",
            pubkey.len()
        )));
    }

    let mut tx =
        crate::observability::begin(pool, crate::observability::Operation::Membership).await?;

    // First statement: serialize the whole role-check / owner-count / upsert
    // sequence against concurrent membership writes on this channel.
    acquire_channel_membership_lock(&mut tx, community_id, channel_id).await?;

    let channel = get_channel_tx(&mut tx, community_id, channel_id).await?;

    let effective_role = if channel.visibility == "private" {
        let inviter = invited_by.ok_or_else(|| {
            DbError::AccessDenied("private channel requires an invite".to_string())
        })?;

        // Bootstrap: channel creator may add themselves as the first member.
        let is_creator_bootstrap = inviter == pubkey && inviter == channel.created_by.as_slice();

        if !is_creator_bootstrap {
            let inviter_role_str = get_active_role_tx(&mut tx, community_id, channel_id, inviter)
                .await?
                .ok_or_else(|| {
                    DbError::AccessDenied("inviter is not an active member".to_string())
                })?;

            let inviter_role: MemberRole = inviter_role_str.parse().map_err(|_| {
                DbError::InvalidData(format!("invalid role in database: {inviter_role_str}"))
            })?;

            // Only owners/admins may extend private-channel access to another
            // identity. `inviter == pubkey` keeps a member's own idempotent
            // re-add working; it is not a role-escalation hole, because the
            // active-role-change guard below still rejects a self-targeted
            // promotion from any non-elevated caller.
            if !inviter_role.is_elevated() && inviter != pubkey {
                return Err(DbError::AccessDenied(
                    "only owners/admins may add private-channel members".to_string(),
                ));
            }
        }

        role
    } else {
        // Open channel: anyone may join, but only existing owners/admins may grant
        // elevated roles. Self-join always gets Member.
        if role.is_elevated() {
            let granter_role = match invited_by {
                Some(inv) => get_active_role_tx(&mut tx, community_id, channel_id, inv).await?,
                None => None,
            };
            match granter_role.as_deref() {
                Some("owner") | Some("admin") => role,
                _ => {
                    return Err(DbError::AccessDenied(
                        "only owners/admins may grant elevated roles".to_string(),
                    ))
                }
            }
        } else {
            role
        }
    };

    // Changing an *active* member's role is privileged in BOTH directions.
    // Demotion is as consequential as promotion: only owners/admins may grant
    // elevated roles, so a demoted owner cannot restore themselves. Guarding
    // only `role.is_elevated()` above therefore left owner→member demotion
    // unauthorized-by-anyone. Re-adding an active member with the role they
    // already hold stays idempotent and unguarded — the huddle bot-add and
    // kind:9021 join paths rely on that.
    //
    // Deliberately keyed on the *active* role. A soft-removed row's stored role
    // is history, not live authority: `removed_at` says it is no longer in
    // force. Reactivation therefore lands at whatever `effective_role` the
    // checks above already authorized — `Member` for any unprivileged caller,
    // elevated only when a currently-elevated granter asked for it. Inferring
    // current authority from a removed row would make soft-deleted ownership a
    // resurrection token: an owner removed by another owner could self-rejoin
    // via kind:9021 (`Member, None`) and silently regain ownership.
    let current_role = get_active_role_tx(&mut tx, community_id, channel_id, pubkey).await?;
    if let Some(current_role) = current_role.filter(|r| r != effective_role.as_str()) {
        let actor_role = match invited_by {
            Some(inviter) => get_active_role_tx(&mut tx, community_id, channel_id, inviter).await?,
            None => None,
        };
        let actor_role: Option<MemberRole> = actor_role.and_then(|r| r.parse().ok());
        if !actor_role.is_some_and(|r| r.is_elevated()) {
            return Err(DbError::AccessDenied(
                "only owners/admins may change an active member's role".to_string(),
            ));
        }

        // Defense-in-depth, mirroring `remove_member`: a demotion must not
        // strip the channel of its last owner, which would leave nobody able
        // to moderate, edit metadata, or re-grant ownership.
        if current_role == "owner" && effective_role != MemberRole::Owner {
            let row = sqlx::query(
                "SELECT COUNT(*) as cnt FROM channel_members \
                 WHERE community_id = $1 AND channel_id = $2 AND role = 'owner' AND removed_at IS NULL",
            )
            .bind(community_id.as_uuid())
            .bind(channel_id)
            .fetch_one(&mut *tx)
            .await?;
            let owner_count: i64 = row.try_get("cnt")?;
            if owner_count <= 1 {
                return Err(DbError::AccessDenied(
                    "cannot demote the last owner — transfer ownership first".to_string(),
                ));
            }
        }
    }

    sqlx::query(
        r#"
        INSERT INTO channel_members (community_id, channel_id, pubkey, role, invited_by)
        VALUES ($1, $2, $3, $4::member_role, $5)
        ON CONFLICT (community_id, channel_id, pubkey) DO UPDATE SET
            removed_at = NULL,
            removed_by = NULL,
            role = EXCLUDED.role
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(channel_id)
    .bind(pubkey)
    .bind(effective_role.as_str())
    .bind(invited_by)
    .execute(&mut *tx)
    .await?;

    let row = sqlx::query(
        r#"
        SELECT channel_id, pubkey, role::text AS role, joined_at, invited_by, removed_at
        FROM channel_members WHERE community_id = $1 AND channel_id = $2 AND pubkey = $3
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(channel_id)
    .bind(pubkey)
    .fetch_one(&mut *tx)
    .await?;

    let record = row_to_member_record(row)?;
    tx.commit().await?;
    Ok(record)
}

/// Remove a member from a channel (soft delete).
///
/// `actor_pubkey` must be an active owner/admin, the agent's owner, or the member
/// removing themselves.
///
/// Returns `Err(DbError::MemberNotFound)` if the target is not an active member.
///
/// The per-channel membership lock is the transaction's first statement, so the
/// actor's role check, the last-owner count, and the UPDATE are all serialized
/// against concurrent membership writes — otherwise a concurrent demotion of the
/// actor could commit after their role was read and this removal would proceed on
/// a stale elevated role.
///
/// The `is_agent_owner` lookup deliberately runs *before* the transaction opens:
/// it borrows a second connection from `pool`, and issuing it while holding the
/// lock could deadlock against ourselves on a small pool. That is safe because
/// `agent_owner_pubkey` is immutable — [`crate::user::set_agent_owner`] only
/// updates it when it `IS NULL` (first-mint-wins), so its value cannot change
/// under us and needs no serialization.
pub async fn remove_member(
    pool: &PgPool,
    community_id: CommunityId,
    channel_id: Uuid,
    pubkey: &[u8],
    actor_pubkey: &[u8],
) -> Result<()> {
    let is_self_remove = pubkey == actor_pubkey;

    // Immutable, and must not be queried while holding the lock (second pool
    // connection). Resolved up front so every *mutable* authorization read can
    // sit behind the serialization point below.
    let actor_is_agent_owner = if is_self_remove {
        false
    } else {
        crate::user::is_agent_owner(pool, community_id, pubkey, actor_pubkey).await?
    };

    let mut tx =
        crate::observability::begin(pool, crate::observability::Operation::Membership).await?;

    // First statement: serialize the actor-role check, the last-owner count and
    // the UPDATE against concurrent membership writes on this channel (same key
    // as `add_member`).
    acquire_channel_membership_lock(&mut tx, community_id, channel_id).await?;

    if !is_self_remove {
        let actor_role_str = get_active_role_tx(&mut tx, community_id, channel_id, actor_pubkey)
            .await?
            .ok_or_else(|| DbError::AccessDenied("actor is not an active member".to_string()))?;
        let actor_role: MemberRole = actor_role_str.parse().map_err(|_| {
            DbError::InvalidData(format!("invalid role in database: {actor_role_str}"))
        })?;
        if !actor_role.is_elevated() && !actor_is_agent_owner {
            return Err(DbError::AccessDenied(
                "only owners/admins or the agent's owner may remove other members".to_string(),
            ));
        }
    }

    // Defense-in-depth: prevent removing the last owner regardless of caller.
    // Callers (REST handlers, NIP-29 handlers) also check this, but the DB
    // layer enforces it as the final safety net.
    let target_role = get_active_role_tx(&mut tx, community_id, channel_id, pubkey).await?;
    if target_role.as_deref() == Some("owner") {
        let row = sqlx::query(
            "SELECT COUNT(*) as cnt FROM channel_members \
             WHERE community_id = $1 AND channel_id = $2 AND role = 'owner' AND removed_at IS NULL",
        )
        .bind(community_id.as_uuid())
        .bind(channel_id)
        .fetch_one(&mut *tx)
        .await?;
        let owner_count: i64 = row.try_get("cnt")?;
        if owner_count <= 1 {
            return Err(DbError::AccessDenied(
                "cannot remove the last owner — transfer ownership first".to_string(),
            ));
        }
    }

    let result = sqlx::query(
        r#"
        UPDATE channel_members
        SET removed_at = NOW(), removed_by = $1
        WHERE community_id = $2 AND channel_id = $3 AND pubkey = $4 AND removed_at IS NULL
        "#,
    )
    .bind(actor_pubkey)
    .bind(community_id.as_uuid())
    .bind(channel_id)
    .bind(pubkey)
    .execute(&mut *tx)
    .await?;

    if result.rows_affected() == 0 {
        return Err(DbError::MemberNotFound(channel_id));
    }

    tx.commit().await?;
    Ok(())
}

/// Returns `true` if the given pubkey is an active member of the channel.
pub async fn is_member(
    pool: &PgPool,
    community_id: CommunityId,
    channel_id: Uuid,
    pubkey: &[u8],
) -> Result<bool> {
    let row = sqlx::query(
        "SELECT COUNT(*) as cnt FROM channel_members cm \
         JOIN channels c ON cm.community_id = c.community_id AND cm.channel_id = c.id AND c.deleted_at IS NULL \
         WHERE cm.community_id = $1 AND cm.channel_id = $2 AND cm.pubkey = $3 AND cm.removed_at IS NULL",
    )
    .bind(community_id.as_uuid())
    .bind(channel_id)
    .bind(pubkey)
    .fetch_one(&mut *crate::observability::acquire(pool, crate::observability::PoolRole::Writer, crate::observability::Operation::Membership).await?)
    .await?;
    let cnt: i64 = row.try_get("cnt")?;
    Ok(cnt > 0)
}

/// Return which of the given (channel, pubkey) combinations are active
/// memberships, restricted to non-deleted channels — one statement for any
/// batch size (T2b). Semantics per pair match [`is_member`].
pub async fn membership_pairs(
    pool: &PgPool,
    community_id: CommunityId,
    channel_ids: &[Uuid],
    pubkeys: &[Vec<u8>],
) -> Result<Vec<(Uuid, Vec<u8>)>> {
    if channel_ids.is_empty() || pubkeys.is_empty() {
        return Ok(Vec::new());
    }
    let rows = sqlx::query(
        "SELECT cm.channel_id, cm.pubkey FROM channel_members cm \
         JOIN channels c ON cm.community_id = c.community_id AND cm.channel_id = c.id AND c.deleted_at IS NULL \
         WHERE cm.community_id = $1 AND cm.channel_id = ANY($2) AND cm.pubkey = ANY($3) AND cm.removed_at IS NULL",
    )
    .bind(community_id.as_uuid())
    .bind(channel_ids)
    .bind(pubkeys)
    .fetch_all(&mut *crate::observability::acquire(pool, crate::observability::PoolRole::Writer, crate::observability::Operation::Membership).await?)
    .await?;
    rows.into_iter()
        .map(|row| Ok((row.try_get("channel_id")?, row.try_get("pubkey")?)))
        .collect()
}

/// Returns all active members of the given channel.
///
/// Returns an empty list if the channel has been soft-deleted.
pub async fn get_members(
    pool: &PgPool,
    community_id: CommunityId,
    channel_id: Uuid,
) -> Result<Vec<MemberRecord>> {
    let rows = sqlx::query(
        r#"
        SELECT cm.channel_id, cm.pubkey, cm.role::text AS role, cm.joined_at, cm.invited_by, cm.removed_at
        FROM channel_members cm
        JOIN channels c ON cm.community_id = c.community_id AND cm.channel_id = c.id AND c.deleted_at IS NULL
        WHERE cm.community_id = $1 AND cm.channel_id = $2 AND cm.removed_at IS NULL
        ORDER BY cm.joined_at ASC
        LIMIT 1000
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(channel_id)
    .fetch_all(&mut *crate::observability::acquire(pool, crate::observability::PoolRole::Writer, crate::observability::Operation::Membership).await?)
    .await?;
    rows.into_iter().map(row_to_member_record).collect()
}

/// Returns active members for multiple channels in a single query.
///
/// Designed for small-batch use (e.g. DM participant resolution where each
/// channel has 2-9 members). For large channel sets, consider pagination.
/// Returns a flat `Vec<MemberRecord>` ordered by `joined_at`; callers should
/// group by `channel_id` if per-channel access is needed.
/// Returns an empty vec immediately when `channel_ids` is empty.
pub async fn get_members_bulk(
    pool: &PgPool,
    community_id: CommunityId,
    channel_ids: &[Uuid],
) -> Result<Vec<MemberRecord>> {
    if channel_ids.is_empty() {
        return Ok(Vec::new());
    }
    let rows = sqlx::query(
        r#"
        SELECT cm.channel_id, cm.pubkey, cm.role::text AS role, cm.joined_at, cm.invited_by, cm.removed_at
        FROM channel_members cm
        JOIN channels c ON cm.community_id = c.community_id AND cm.channel_id = c.id AND c.deleted_at IS NULL
        WHERE cm.community_id = $1 AND cm.channel_id = ANY($2) AND cm.removed_at IS NULL
        ORDER BY cm.joined_at ASC
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(channel_ids)
    .fetch_all(&mut *crate::observability::acquire(pool, crate::observability::PoolRole::Writer, crate::observability::Operation::Membership).await?)
    .await?;
    rows.into_iter().map(row_to_member_record).collect()
}

/// Get all channel IDs accessible to a pubkey.
///
/// Includes channels where the pubkey is an active member AND all open channels.
/// Open channels must be included in REQ filter resolution.
pub async fn get_accessible_channel_ids(
    pool: &PgPool,
    community_id: CommunityId,
    pubkey: &[u8],
) -> Result<Vec<Uuid>> {
    let rows = sqlx::query(
        r#"
        SELECT cm.channel_id
        FROM channel_members cm
        JOIN channels c ON cm.community_id = c.community_id AND cm.channel_id = c.id AND c.deleted_at IS NULL
        WHERE cm.community_id = $1 AND cm.pubkey = $2 AND cm.removed_at IS NULL
        UNION
        SELECT id AS channel_id
        FROM channels
        WHERE community_id = $1 AND visibility = 'open' AND deleted_at IS NULL
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(pubkey)
    .fetch_all(&mut *crate::observability::acquire(pool, crate::observability::PoolRole::Writer, crate::observability::Operation::Membership).await?)
    .await?;

    rows.into_iter()
        .map(|r| {
            let id: Uuid = r.try_get("channel_id")?;
            Ok(id)
        })
        .collect()
}

/// Transaction-aware variant of [`get_active_role_tx`].
async fn get_active_role_tx(
    tx: &mut Transaction<'_, Postgres>,
    community_id: CommunityId,
    channel_id: Uuid,
    pubkey: &[u8],
) -> Result<Option<String>> {
    let row = sqlx::query(
        "SELECT role::text AS role FROM channel_members \
         WHERE community_id = $1 AND channel_id = $2 AND pubkey = $3 AND removed_at IS NULL",
    )
    .bind(community_id.as_uuid())
    .bind(channel_id)
    .bind(pubkey)
    .fetch_optional(&mut **tx)
    .await?;
    Ok(row.map(|r| r.try_get("role")).transpose()?)
}

/// Transaction-aware variant of [`crate::channel::get_channel`].
async fn get_channel_tx(
    tx: &mut Transaction<'_, Postgres>,
    community_id: CommunityId,
    channel_id: Uuid,
) -> Result<ChannelRecord> {
    let row = sqlx::query(
        r#"
        SELECT id, name, channel_type::text AS channel_type, visibility::text AS visibility,
               description, canvas,
               created_by, created_at, updated_at, archived_at, deleted_at,
               nip29_group_id, topic_required, max_members,
               topic, topic_set_by, topic_set_at,
               purpose, purpose_set_by, purpose_set_at,
               ttl_seconds, ttl_deadline
        FROM channels WHERE community_id = $1 AND id = $2 AND deleted_at IS NULL
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(channel_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(DbError::ChannelNotFound(channel_id))?;
    row_to_channel_record(row)
}

/// A channel entry returned as part of a bot member record.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct BotChannelEntry {
    /// Channel display name.
    pub name: String,
    /// Channel UUID (as string from the DB).
    pub id: String,
}

/// Bot member record — a user with role=bot, with their channel memberships aggregated.
#[derive(Debug, Clone)]
pub struct BotMemberRecord {
    /// Compressed public key bytes of the bot user.
    pub pubkey: Vec<u8>,
    /// Optional display name for the bot.
    pub display_name: Option<String>,
    /// Optional agent type identifier.
    pub agent_type: Option<String>,
    /// Optional JSON capabilities descriptor.
    pub capabilities: Option<serde_json::Value>,
    /// Channel entries with both name and UUID, from json_agg.
    pub channels: Vec<BotChannelEntry>,
}

/// User record for bulk lookup.
#[derive(Debug, Clone)]
pub struct UserRecord {
    /// Compressed public key bytes of the user.
    pub pubkey: Vec<u8>,
    /// Optional display name.
    pub display_name: Option<String>,
    /// Optional avatar image URL.
    pub avatar_url: Option<String>,
    /// Optional NIP-05 identifier (e.g. `user@example.com`).
    pub nip05_handle: Option<String>,
}

/// A channel record paired with whether the querying user is an active member.
#[derive(Debug, Clone)]
pub struct AccessibleChannel {
    /// The channel record.
    pub channel: ChannelRecord,
    /// Whether the querying user is an active member of this channel.
    pub is_member: bool,
}

/// Returns full channel records for all channels a user can access:
/// open channels (visible to everyone) plus channels where the user is an active member.
///
/// Uses a LEFT JOIN on channel_members (PK: channel_id + pubkey) which produces at
/// most one row per channel. Results are ordered stream -> forum -> dm, then by name.
///
/// If `visibility_filter` is `Some("open")` or `Some("private")`, only channels with
/// that visibility value are returned. `None` returns all accessible channels.
pub async fn get_accessible_channels(
    pool: &PgPool,
    community_id: CommunityId,
    pubkey: &[u8],
    visibility_filter: Option<&str>,
    member_only: Option<bool>,
) -> Result<Vec<AccessibleChannel>> {
    // When `member_only` is `Some(true)`, restrict to channels where the user
    // has an active membership (cm.channel_id IS NOT NULL). This is a strict
    // subset of the default result set and is pushed into SQL so the LIMIT 1000
    // applies to the filtered set, not the pre-filter set.
    let membership_clause = if member_only == Some(true) {
        "AND cm.channel_id IS NOT NULL"
    } else {
        "AND (c.visibility = 'open' OR cm.channel_id IS NOT NULL)"
    };

    let base = format!(
        r#"
        SELECT c.id, c.name, c.channel_type::text AS channel_type,
               c.visibility::text AS visibility, c.description, c.canvas,
               c.created_by, c.created_at, c.updated_at, c.archived_at, c.deleted_at,
               c.nip29_group_id, c.topic_required, c.max_members,
               c.topic, c.topic_set_by, c.topic_set_at,
               c.purpose, c.purpose_set_by, c.purpose_set_at,
               c.ttl_seconds, c.ttl_deadline,
               (cm.channel_id IS NOT NULL) AS is_member
        FROM channels c
        LEFT JOIN channel_members cm
            ON c.community_id = cm.community_id AND c.id = cm.channel_id AND cm.pubkey = $2 AND cm.removed_at IS NULL
        WHERE c.community_id = $1 AND c.deleted_at IS NULL
          {membership_clause}
          AND (c.channel_type != 'dm' OR cm.hidden_at IS NULL)
    "#
    );

    let sql = if visibility_filter.is_some() {
        format!("{base}  AND c.visibility::text = $3\n        ORDER BY array_position(ARRAY['stream','forum','dm']::text[], c.channel_type::text), c.name\n        LIMIT 1000")
    } else {
        format!("{base}        ORDER BY array_position(ARRAY['stream','forum','dm']::text[], c.channel_type::text), c.name\n        LIMIT 1000")
    };

    let query = sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(community_id.as_uuid())
        .bind(pubkey);
    let query = if let Some(vis) = visibility_filter {
        query.bind(vis)
    } else {
        query
    };

    let rows = query
        .fetch_all(
            &mut *crate::observability::acquire(
                pool,
                crate::observability::PoolRole::Writer,
                crate::observability::Operation::Membership,
            )
            .await?,
        )
        .await?;
    rows.into_iter()
        .map(|row| {
            let is_member: bool = row.try_get("is_member").unwrap_or(false);
            let channel = row_to_channel_record(row)?;
            Ok(AccessibleChannel { channel, is_member })
        })
        .collect()
}

/// Returns all bot-role members with their channel memberships in one community.
///
/// Channels are returned as a JSON array of `{name, id}` objects via `json_agg`,
/// preserving the 1:1 name↔UUID pairing. No separate string_agg ordering issues.
/// Members with no active channel memberships are excluded (INNER JOIN on channels).
pub async fn get_bot_members(
    pool: &PgPool,
    community_id: CommunityId,
) -> Result<Vec<BotMemberRecord>> {
    let rows = sqlx::query(
        r#"
        SELECT cm.pubkey, u.display_name, u.agent_type, u.capabilities,
               COALESCE(json_agg(DISTINCT jsonb_build_object('name', c.name, 'id', c.id::text)), '[]') AS channels_json
        FROM channel_members cm
        LEFT JOIN users u ON cm.community_id = u.community_id AND cm.pubkey = u.pubkey
        JOIN channels c ON cm.community_id = c.community_id AND cm.channel_id = c.id AND c.deleted_at IS NULL
        WHERE cm.community_id = $1 AND cm.role = 'bot' AND cm.removed_at IS NULL
        GROUP BY cm.pubkey, u.display_name, u.agent_type, u.capabilities
        LIMIT 1000
        "#,
    )
    .bind(community_id.as_uuid())
    .fetch_all(&mut *crate::observability::acquire(pool, crate::observability::PoolRole::Writer, crate::observability::Operation::Membership).await?)
    .await?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let capabilities: Option<serde_json::Value> = row.try_get("capabilities")?;
        let channels_json: serde_json::Value = row
            .try_get::<serde_json::Value, _>("channels_json")
            .unwrap_or(serde_json::Value::Array(vec![]));
        let channels: Vec<BotChannelEntry> =
            serde_json::from_value(channels_json).unwrap_or_default();
        out.push(BotMemberRecord {
            pubkey: row.try_get("pubkey")?,
            display_name: row.try_get("display_name")?,
            agent_type: row.try_get("agent_type")?,
            capabilities,
            channels,
        });
    }
    Ok(out)
}

/// Returns the pubkeys of all agent identities in one community.
pub async fn get_agent_pubkeys(pool: &PgPool, community_id: CommunityId) -> Result<Vec<Vec<u8>>> {
    sqlx::query_scalar(
        r#"
        SELECT pubkey
        FROM users
        WHERE community_id = $1
          AND (agent_type IS NOT NULL OR agent_owner_pubkey IS NOT NULL)
        ORDER BY pubkey
        "#,
    )
    .bind(community_id.as_uuid())
    .fetch_all(
        &mut *crate::observability::acquire(
            pool,
            crate::observability::PoolRole::Writer,
            crate::observability::Operation::Membership,
        )
        .await?,
    )
    .await
    .map_err(Into::into)
}

/// Bulk-fetch user records by pubkey inside one community.
///
/// Returns only users that exist in the `users` table. Ordering matches input order
/// is NOT guaranteed — callers should index by pubkey if order matters.
/// Returns an empty vec immediately when `pubkeys` is empty (no query issued).
pub async fn get_users_bulk(
    pool: &PgPool,
    community_id: CommunityId,
    pubkeys: &[Vec<u8>],
) -> Result<Vec<UserRecord>> {
    if pubkeys.is_empty() {
        return Ok(Vec::new());
    }

    // Build a parameterised IN clause: ($2, $3, ...); $1 is community_id.
    let placeholders = (2..(pubkeys.len() + 2))
        .map(|i| format!("${i}"))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "SELECT pubkey, display_name, avatar_url, nip05_handle \
         FROM users WHERE community_id = $1 AND pubkey IN ({placeholders})"
    );

    let mut q = sqlx::query(sqlx::AssertSqlSafe(sql)).bind(community_id.as_uuid());
    for pk in pubkeys {
        q = q.bind(pk);
    }

    let rows = q
        .fetch_all(
            &mut *crate::observability::acquire(
                pool,
                crate::observability::PoolRole::Writer,
                crate::observability::Operation::Membership,
            )
            .await?,
        )
        .await?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push(UserRecord {
            pubkey: row.try_get("pubkey")?,
            display_name: row.try_get("display_name")?,
            avatar_url: row.try_get("avatar_url")?,
            nip05_handle: row.try_get("nip05_handle")?,
        });
    }
    Ok(out)
}

fn row_to_member_record(row: sqlx::postgres::PgRow) -> Result<MemberRecord> {
    let channel_id: Uuid = row.try_get("channel_id")?;

    Ok(MemberRecord {
        channel_id,
        pubkey: row.try_get("pubkey")?,
        role: row.try_get("role")?,
        joined_at: row.try_get("joined_at")?,
        invited_by: row.try_get("invited_by")?,
        removed_at: row.try_get("removed_at")?,
    })
}

/// Returns the count of active (non-removed) members in a channel.
pub async fn get_member_count(
    pool: &PgPool,
    community_id: CommunityId,
    channel_id: Uuid,
) -> Result<i64> {
    let row = sqlx::query(
        "SELECT COUNT(*) as cnt FROM channel_members WHERE community_id = $1 AND channel_id = $2 AND removed_at IS NULL",
    )
    .bind(community_id.as_uuid())
    .bind(channel_id)
    .fetch_one(&mut *crate::observability::acquire(pool, crate::observability::PoolRole::Writer, crate::observability::Operation::Membership).await?)
    .await?;
    Ok(row.try_get("cnt")?)
}

/// Bulk-fetch member counts for a set of channel IDs.
///
/// Returns a map of `channel_id -> count`. Channels with zero members are omitted.
/// Single query regardless of input size.
pub async fn get_member_counts_bulk(
    pool: &PgPool,
    community_id: CommunityId,
    channel_ids: &[Uuid],
) -> Result<std::collections::HashMap<Uuid, i64>> {
    if channel_ids.is_empty() {
        return Ok(std::collections::HashMap::new());
    }

    let mut qb: sqlx::QueryBuilder<sqlx::Postgres> = sqlx::QueryBuilder::new(
        "SELECT channel_id, COUNT(*) as cnt FROM channel_members \
         WHERE community_id = ",
    );
    qb.push_bind(community_id.as_uuid());
    qb.push(" AND removed_at IS NULL AND channel_id IN (");
    let mut sep = qb.separated(", ");
    for id in channel_ids {
        sep.push_bind(*id);
    }
    qb.push(") GROUP BY channel_id");

    let rows = qb
        .build()
        .fetch_all(
            &mut *crate::observability::acquire(
                pool,
                crate::observability::PoolRole::Writer,
                crate::observability::Operation::Membership,
            )
            .await?,
        )
        .await?;

    let mut map = std::collections::HashMap::with_capacity(rows.len());
    for row in rows {
        let id: Uuid = row.try_get("channel_id")?;
        let cnt: i64 = row.try_get("cnt")?;
        map.insert(id, cnt);
    }
    Ok(map)
}

/// Get the active role of a pubkey in a channel.
///
/// Returns `None` if the pubkey is not an active member.
pub async fn get_member_role(
    pool: &PgPool,
    community_id: CommunityId,
    channel_id: Uuid,
    pubkey: &[u8],
) -> Result<Option<String>> {
    let row = sqlx::query(
        "SELECT cm.role::text AS role FROM channel_members cm \
         JOIN channels c ON cm.community_id = c.community_id AND cm.channel_id = c.id AND c.deleted_at IS NULL \
         WHERE cm.community_id = $1 AND cm.channel_id = $2 AND cm.pubkey = $3 AND cm.removed_at IS NULL",
    )
    .bind(community_id.as_uuid())
    .bind(channel_id)
    .bind(pubkey)
    .fetch_optional(&mut *crate::observability::acquire(pool, crate::observability::PoolRole::Writer, crate::observability::Operation::Membership).await?)
    .await?;
    Ok(row.map(|r| r.try_get("role")).transpose()?)
}

impl Db {
    /// Adds a member to a channel.
    pub async fn add_member(
        &self,
        community_id: CommunityId,
        channel_id: Uuid,
        pubkey: &[u8],
        role: crate::channel_members::MemberRole,
        invited_by: Option<&[u8]>,
    ) -> Result<crate::channel_members::MemberRecord> {
        crate::observability::observe(crate::observability::Operation::Membership, async {
            crate::channel_members::add_member(
                &self.pool,
                community_id,
                channel_id,
                pubkey,
                role,
                invited_by,
            )
            .await
        })
        .await
    }

    /// Removes a member from a channel.
    pub async fn remove_member(
        &self,
        community_id: CommunityId,
        channel_id: Uuid,
        pubkey: &[u8],
        actor_pubkey: &[u8],
    ) -> Result<()> {
        crate::observability::observe(crate::observability::Operation::Membership, async {
            crate::channel_members::remove_member(
                &self.pool,
                community_id,
                channel_id,
                pubkey,
                actor_pubkey,
            )
            .await
        })
        .await
    }

    /// Returns `true` if the pubkey is an active member.
    pub async fn is_member(
        &self,
        community_id: CommunityId,
        channel_id: Uuid,
        pubkey: &[u8],
    ) -> Result<bool> {
        crate::observability::observe(crate::observability::Operation::Membership, async {
            crate::channel_members::is_member(&self.pool, community_id, channel_id, pubkey).await
        })
        .await
    }

    /// Return the active (channel, pubkey) membership pairs among the given
    /// sets, in one statement.
    pub async fn membership_pairs(
        &self,
        community_id: CommunityId,
        channel_ids: &[Uuid],
        pubkeys: &[Vec<u8>],
    ) -> Result<Vec<(Uuid, Vec<u8>)>> {
        crate::observability::observe(crate::observability::Operation::Membership, async {
            crate::channel_members::membership_pairs(&self.pool, community_id, channel_ids, pubkeys)
                .await
        })
        .await
    }

    /// Returns all active members of a channel.
    pub async fn get_members(
        &self,
        community_id: CommunityId,
        channel_id: Uuid,
    ) -> Result<Vec<crate::channel_members::MemberRecord>> {
        crate::observability::observe(crate::observability::Operation::Membership, async {
            crate::channel_members::get_members(&self.pool, community_id, channel_id).await
        })
        .await
    }

    /// Returns active members for multiple channels in a single query.
    pub async fn get_members_bulk(
        &self,
        community_id: CommunityId,
        channel_ids: &[Uuid],
    ) -> Result<Vec<crate::channel_members::MemberRecord>> {
        crate::observability::observe(crate::observability::Operation::Membership, async {
            crate::channel_members::get_members_bulk(&self.pool, community_id, channel_ids).await
        })
        .await
    }

    /// Get all channel IDs accessible to a pubkey.
    pub async fn get_accessible_channel_ids(
        &self,
        community_id: CommunityId,
        pubkey: &[u8],
    ) -> Result<Vec<Uuid>> {
        crate::observability::observe(crate::observability::Operation::Membership, async {
            crate::channel_members::get_accessible_channel_ids(&self.pool, community_id, pubkey)
                .await
        })
        .await
    }

    /// Returns full channel records for all channels a user can access.
    pub async fn get_accessible_channels(
        &self,
        community_id: CommunityId,
        pubkey: &[u8],
        visibility_filter: Option<&str>,
        member_only: Option<bool>,
    ) -> Result<Vec<crate::channel_members::AccessibleChannel>> {
        crate::observability::observe(crate::observability::Operation::Membership, async {
            crate::channel_members::get_accessible_channels(
                &self.pool,
                community_id,
                pubkey,
                visibility_filter,
                member_only,
            )
            .await
        })
        .await
    }

    /// Returns all bot-role members with their aggregated channel names in one community.
    pub async fn get_bot_members(
        &self,
        community_id: CommunityId,
    ) -> Result<Vec<crate::channel_members::BotMemberRecord>> {
        crate::observability::observe(crate::observability::Operation::Membership, async {
            crate::channel_members::get_bot_members(&self.pool, community_id).await
        })
        .await
    }

    /// Returns the pubkeys of all agent identities in one community.
    pub async fn get_agent_pubkeys(&self, community_id: CommunityId) -> Result<Vec<Vec<u8>>> {
        crate::observability::observe(crate::observability::Operation::Membership, async {
            crate::channel_members::get_agent_pubkeys(&self.pool, community_id).await
        })
        .await
    }

    /// Bulk-fetch user records by pubkey.
    pub async fn get_users_bulk(
        &self,
        community_id: CommunityId,
        pubkeys: &[Vec<u8>],
    ) -> Result<Vec<crate::channel_members::UserRecord>> {
        crate::observability::observe(crate::observability::Operation::Membership, async {
            crate::channel_members::get_users_bulk(&self.pool, community_id, pubkeys).await
        })
        .await
    }

    /// Returns the count of active members in a channel.
    pub async fn get_member_count(
        &self,
        community_id: CommunityId,
        channel_id: Uuid,
    ) -> Result<i64> {
        crate::observability::observe(crate::observability::Operation::Membership, async {
            crate::channel_members::get_member_count(&self.pool, community_id, channel_id).await
        })
        .await
    }

    /// Bulk-fetch member counts for a set of channel IDs.
    pub async fn get_member_counts_bulk(
        &self,
        community_id: CommunityId,
        channel_ids: &[Uuid],
    ) -> Result<std::collections::HashMap<Uuid, i64>> {
        crate::observability::observe(crate::observability::Operation::Membership, async {
            crate::channel_members::get_member_counts_bulk(&self.pool, community_id, channel_ids)
                .await
        })
        .await
    }

    /// Get the active role of a pubkey in a channel.
    pub async fn get_member_role(
        &self,
        community_id: CommunityId,
        channel_id: Uuid,
        pubkey: &[u8],
    ) -> Result<Option<String>> {
        crate::observability::observe(crate::observability::Operation::Membership, async {
            crate::channel_members::get_member_role(&self.pool, community_id, channel_id, pubkey)
                .await
        })
        .await
    }
}
