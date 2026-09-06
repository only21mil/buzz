//! Community lifecycle and host-map persistence.
//!
//! Db methods and record names remain available at their original paths.

use buzz_core::CommunityId;
use chrono::{DateTime, Utc};
use sqlx::Row;
use uuid::Uuid;

use crate::{relay_members, Db, Result};

/// Community host-map row returned by [`Db::lookup_community_by_host`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommunityRecord {
    /// Stable server-resolved community id.
    pub id: CommunityId,
    /// Normalized host that maps to this community.
    pub host: String,
}

/// Community row returned by idempotent community ensure/create operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnsuredCommunityRecord {
    /// Stable server-resolved community id.
    pub id: CommunityId,
    /// Normalized host that maps to this community.
    pub host: String,
    /// True only when this call inserted the `communities` row.
    pub created: bool,
}

/// Community row returned by an atomic create-with-owner operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedCommunityRecord {
    /// Stable server-resolved community id.
    pub id: CommunityId,
    /// Normalized host stored for the community.
    pub host: String,
}

/// Result of atomically creating a community with its initial owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateCommunityWithOwnerResult {
    /// The community was created, or an identical retried create found it.
    Created(CreatedCommunityRecord),
    /// The host already belongs to another owner.
    HostExists,
    /// The intended owner already owns the maximum number of communities.
    LimitReached,
}

/// Community row returned by operator-plane ownership reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedCommunityRecord {
    /// Stable server-resolved community id.
    pub id: CommunityId,
    /// Normalized host that maps to this community.
    pub host: String,
    /// When the community row was created.
    pub created_at: DateTime<Utc>,
    /// When the community was archived; absent while active.
    pub archived_at: Option<DateTime<Utc>>,
}

/// Community row returned by an owner-authorized archive operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchivedCommunityRecord {
    /// Stable server-resolved community id.
    pub id: CommunityId,
    /// Reserved canonical host.
    pub host: String,
    /// Durable first-archive timestamp.
    pub archived_at: DateTime<Utc>,
}

/// Community row returned by an owner-authorized unarchive operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnarchivedCommunityRecord {
    /// Stable server-resolved community id.
    pub id: CommunityId,
    /// Reserved canonical host restored to active admission.
    pub host: String,
}

impl Db {
    /// Returns the community mapped to a normalized request host, if one exists.
    ///
    /// The caller owns host normalization and turns `None` into the fail-closed
    /// request/connection error. buzz-db only reads the durable host map.
    pub async fn lookup_community_by_host(
        &self,
        normalized_host: &str,
    ) -> Result<Option<CommunityRecord>> {
        let row = sqlx::query(
            r#"
            SELECT id, host
            FROM communities
            WHERE lower(host) = lower($1)
              AND archived_at IS NULL
            "#,
        )
        .bind(normalized_host)
        .fetch_optional(&self.pool)
        .await?;

        row.map(|row| {
            let id: Uuid = row.try_get("id")?;
            let host: String = row.try_get("host")?;

            Ok(CommunityRecord {
                id: CommunityId::from_uuid(id),
                host,
            })
        })
        .transpose()
    }

    /// Returns whether a community id still exists in the active lifecycle state.
    pub async fn is_community_active(&self, community_id: CommunityId) -> Result<bool> {
        let active = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM communities WHERE id = $1 AND archived_at IS NULL)",
        )
        .bind(community_id.as_uuid())
        .fetch_one(&self.pool)
        .await?;
        Ok(active)
    }

    /// Returns a community by host regardless of lifecycle state. Operator-plane only.
    pub async fn lookup_community_by_host_for_management(
        &self,
        normalized_host: &str,
    ) -> Result<Option<CommunityRecord>> {
        let row = sqlx::query("SELECT id, host FROM communities WHERE lower(host) = lower($1)")
            .bind(normalized_host)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| {
            Ok(CommunityRecord {
                id: CommunityId::from_uuid(row.try_get("id")?),
                host: row.try_get("host")?,
            })
        })
        .transpose()
    }

    /// Lists communities where `owner_pubkey` currently holds the `owner` role.
    ///
    /// This is an operator-plane helper, not a tenant-scoped data-plane read:
    /// callers must gate it on deployment-level operator auth before exposing it.
    pub async fn list_communities_owned_by(
        &self,
        owner_pubkey: &str,
    ) -> Result<Vec<OwnedCommunityRecord>> {
        let owner_pubkey = owner_pubkey.to_ascii_lowercase();
        let rows = sqlx::query(
            r#"
            SELECT c.id, c.host, c.created_at, c.archived_at
            FROM communities c
            JOIN relay_members rm ON rm.community_id = c.id
            WHERE rm.pubkey = $1
              AND rm.role = 'owner'
            ORDER BY c.created_at ASC, c.host ASC
            "#,
        )
        .bind(owner_pubkey)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| {
                let id: Uuid = row.try_get("id")?;
                let host: String = row.try_get("host")?;
                let created_at: DateTime<Utc> = row.try_get("created_at")?;
                let archived_at: Option<DateTime<Utc>> = row.try_get("archived_at")?;
                Ok(OwnedCommunityRecord {
                    id: CommunityId::from_uuid(id),
                    host,
                    created_at,
                    archived_at,
                })
            })
            .collect()
    }

    /// Returns the normalized host mapped to a community id, if the community
    /// exists.
    ///
    /// The reverse of [`lookup_community_by_host`]: used by side-effect
    /// producers that already hold a server-resolved `CommunityId` (e.g. the
    /// workflow action sink running a run owned by some community) and need a
    /// fully-formed [`buzz_core::tenant::TenantContext`] — host included — to
    /// fan out under *that* community rather than the deployment default. The
    /// community is authoritative; the host is read back for labelling only and
    /// is never used to re-derive the community.
    pub async fn lookup_community_host(&self, community_id: CommunityId) -> Result<Option<String>> {
        let row = sqlx::query(
            r#"
            SELECT host
            FROM communities
            WHERE id = $1
              AND archived_at IS NULL
            "#,
        )
        .bind(community_id.as_uuid())
        .fetch_optional(&self.pool)
        .await?;

        row.map(|row| {
            let host: String = row.try_get("host")?;
            Ok(host)
        })
        .transpose()
    }

    /// Returns the community's workspace icon (NIP-11 `icon`), if set.
    ///
    /// Set by relay admins/owners via the kind:9033 command; the value is
    /// validated and size-capped at that write path.
    pub async fn get_community_icon(&self, community_id: CommunityId) -> Result<Option<String>> {
        let row = sqlx::query(
            r#"
            SELECT icon
            FROM communities
            WHERE id = $1
            "#,
        )
        .bind(community_id.as_uuid())
        .fetch_optional(&self.pool)
        .await?;

        Ok(row
            .map(|row| row.try_get::<Option<String>, _>("icon"))
            .transpose()?
            .flatten()
            .filter(|icon| !icon.is_empty()))
    }

    /// Sets or clears (`None`) the community's workspace icon.
    pub async fn set_community_icon(
        &self,
        community_id: CommunityId,
        icon: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE communities
            SET icon = $2
            WHERE id = $1
            "#,
        )
        .bind(community_id.as_uuid())
        .bind(icon)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Ensure a configured community host exists and return its row.
    ///
    /// This is the startup/config seeding path for N=1 deployments. Migrations
    /// create the schema only; deployment-specific hosts are not hardcoded into
    /// schema history.
    pub async fn ensure_configured_community(
        &self,
        normalized_host: &str,
    ) -> Result<EnsuredCommunityRecord> {
        let row = sqlx::query(
            r#"
            INSERT INTO communities (host)
            VALUES ($1)
            ON CONFLICT (lower(host)) DO UPDATE SET host = communities.host
            RETURNING id, host, (xmax = 0) AS created
            "#,
        )
        .bind(normalized_host)
        .fetch_one(&self.pool)
        .await?;

        let id: Uuid = row.try_get("id")?;
        let host: String = row.try_get("host")?;
        let created: bool = row.try_get("created")?;

        Ok(EnsuredCommunityRecord {
            id: CommunityId::from_uuid(id),
            host,
            created,
        })
    }

    /// Atomically creates a community and its initial owner.
    ///
    /// Holds a per-owner advisory lock while enforcing the ownership limit.
    /// Identical create retries return the original record; host collisions and
    /// limit failures remain distinguishable to the operator API.
    pub async fn create_community_with_owner(
        &self,
        normalized_host: &str,
        owner_pubkey: &str,
    ) -> Result<CreateCommunityWithOwnerResult> {
        let owner_pubkey = owner_pubkey.to_ascii_lowercase();
        let mut tx = self.pool.begin().await?;

        // Serialize on the owner pubkey so concurrent creates to the same
        // owner cannot both pass the ownership count check.
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(relay_members::owner_count_advisory_lock_key(&owner_pubkey))
            .execute(&mut *tx)
            .await?;

        let row = sqlx::query(
            r#"
            INSERT INTO communities (host)
            VALUES ($1)
            ON CONFLICT (lower(host)) DO NOTHING
            RETURNING id, host
            "#,
        )
        .bind(normalized_host)
        .fetch_optional(&mut *tx)
        .await?;

        let (id, host) = if let Some(row) = row {
            let id: Uuid = row.try_get("id")?;
            let host: String = row.try_get("host")?;

            // Enforce the limit before inserting the new owner row.
            let owned_count: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM relay_members WHERE pubkey = $1 AND role = 'owner'",
            )
            .bind(&owner_pubkey)
            .fetch_one(&mut *tx)
            .await?;

            if owned_count >= relay_members::max_communities_per_owner() {
                tx.rollback().await?;
                return Ok(CreateCommunityWithOwnerResult::LimitReached);
            }

            sqlx::query(
                "INSERT INTO relay_members (community_id, pubkey, role, added_by) VALUES ($1, $2, 'owner', NULL)",
            )
            .bind(id)
            .bind(&owner_pubkey)
            .execute(&mut *tx)
            .await?;
            (id, host)
        } else {
            let existing = sqlx::query(
                r#"
                SELECT c.id, c.host
                FROM communities c
                JOIN relay_members rm ON rm.community_id = c.id
                WHERE lower(c.host) = lower($1)
                  AND lower(rm.pubkey) = lower($2)
                  AND rm.role = 'owner'
                  AND c.archived_at IS NULL
                "#,
            )
            .bind(normalized_host)
            .bind(&owner_pubkey)
            .fetch_optional(&mut *tx)
            .await?;
            let Some(existing) = existing else {
                tx.rollback().await?;
                return Ok(CreateCommunityWithOwnerResult::HostExists);
            };
            (existing.try_get("id")?, existing.try_get("host")?)
        };

        tx.commit().await?;
        Ok(CreateCommunityWithOwnerResult::Created(
            CreatedCommunityRecord {
                id: CommunityId::from_uuid(id),
                host,
            },
        ))
    }

    /// Idempotently archives a community when the asserted pubkey is its current owner.
    pub async fn archive_community_owned_by(
        &self,
        normalized_host: &str,
        owner_pubkey: &str,
        protected_deployment_host: &str,
    ) -> Result<Option<ArchivedCommunityRecord>> {
        let row = sqlx::query(
            r#"UPDATE communities c
               SET archived_at = COALESCE(c.archived_at, now())
               FROM relay_members rm
               WHERE lower(c.host) = lower($1)
                 AND rm.community_id = c.id
                 AND lower(rm.pubkey) = lower($2)
                 AND rm.role = 'owner'
                 AND lower(c.host) <> lower($3)
               RETURNING c.id, c.host, c.archived_at"#,
        )
        .bind(normalized_host)
        .bind(owner_pubkey)
        .bind(protected_deployment_host)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| {
            Ok(ArchivedCommunityRecord {
                id: CommunityId::from_uuid(row.try_get("id")?),
                host: row.try_get("host")?,
                archived_at: row.try_get("archived_at")?,
            })
        })
        .transpose()
    }

    /// Idempotently restores a community when the asserted pubkey is its current owner.
    pub async fn unarchive_community_owned_by(
        &self,
        normalized_host: &str,
        owner_pubkey: &str,
    ) -> Result<Option<UnarchivedCommunityRecord>> {
        let row = sqlx::query(
            r#"UPDATE communities c
               SET archived_at = NULL
               FROM relay_members rm
               WHERE lower(c.host) = lower($1)
                 AND rm.community_id = c.id
                 AND lower(rm.pubkey) = lower($2)
                 AND rm.role = 'owner'
               RETURNING c.id, c.host"#,
        )
        .bind(normalized_host)
        .bind(owner_pubkey)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| {
            Ok(UnarchivedCommunityRecord {
                id: CommunityId::from_uuid(row.try_get("id")?),
                host: row.try_get("host")?,
            })
        })
        .transpose()
    }

    /// Returns the community that owns a channel, if the channel exists.
    ///
    /// Internal relay producers use this to derive tenant context from the row
    /// they are acting on, rather than falling back to an implicit default.
    pub async fn community_of_channel(&self, channel_id: Uuid) -> Result<Option<CommunityId>> {
        let row = sqlx::query(
            r#"
            SELECT community_id
            FROM channels
            WHERE id = $1
              AND deleted_at IS NULL
            "#,
        )
        .bind(channel_id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(|row| {
            let id: Uuid = row.try_get("community_id")?;
            Ok(CommunityId::from_uuid(id))
        })
        .transpose()
    }

    /// Batched version of [`Self::community_of_channel`]: given a list of
    /// channel UUIDs, returns a map from channel id → owning community
    /// for every channel that exists (soft-deletes excluded).
    ///
    /// Used by the runtime conformance read-seam emitters in `buzz-relay`:
    /// after a `query_events`/`get_events_by_ids` returns N rows, the
    /// emitter collects distinct `channel_id`s, calls this once, then
    /// projects each row's true community label independently of the
    /// fetch query's WHERE clause. That independence is what makes the
    /// `Inv_NonInterference` / `Inv_ReadConfinement` gate non-vacuous —
    /// a mutation that dropped `community_id = $X` from the fetch query
    /// would still let this helper return the row's true label, and the
    /// checker would see the mismatch.
    ///
    /// Channels missing from the result map (deleted or never existed)
    /// are intentionally not present rather than mapped to a default —
    /// callers MUST treat "channel-id not in map" as a coverage breach,
    /// never as "use the resolved community".
    pub async fn communities_of_channels(
        &self,
        channel_ids: &[Uuid],
    ) -> Result<std::collections::HashMap<Uuid, CommunityId>> {
        if channel_ids.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let rows = sqlx::query(
            r#"
            SELECT id, community_id
            FROM channels
            WHERE id = ANY($1)
              AND deleted_at IS NULL
            "#,
        )
        .bind(channel_ids)
        .fetch_all(&self.pool)
        .await?;

        let mut out = std::collections::HashMap::with_capacity(rows.len());
        for row in rows {
            let ch: Uuid = row.try_get("id")?;
            let cm: Uuid = row.try_get("community_id")?;
            out.insert(ch, CommunityId::from_uuid(cm));
        }
        Ok(out)
    }
}
