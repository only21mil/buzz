//! Deployment roster backing store.
//!
//! The operator/moderator roster has two layers. Config grants
//! (`RELAY_OPERATOR_PUBKEYS`, `RELAY_OWNER_PUBKEY` fallback) resolve in
//! [`super::auth`] without touching this store. Everything else — DB-backed
//! grants, the staffing endpoints, the roster listing — goes through
//! [`AdminRosterStore`].
//!
//! # P03 handoff contract
//!
//! Until P03 lands the roster migration and `Db` methods, the relay wires
//! [`NoDbRoster`]: config and owner-fallback roles work, DB lookups resolve
//! empty, and staffing writes fail with [`RosterError::Unavailable`].
//!
//! P03 owns this checklist; P04 must not write `crates/buzz-db/` or
//! `migrations/`:
//!
//! 1. Migration `00xx_relay_operators.sql` creating the deployment-global
//!    table (no `community_id`; operators span every tenant):
//!
//!    ```sql
//!    CREATE TABLE relay_operators (
//!        pubkey      BYTEA NOT NULL PRIMARY KEY CHECK (length(pubkey) = 32),
//!        role        TEXT NOT NULL CHECK (role IN ('operator', 'moderator')),
//!        added_by    BYTEA NOT NULL CHECK (length(added_by) = 32),
//!        created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
//!    );
//!    ```
//!
//!    Register it as a global table wherever the fork tracks
//!    tenant-scoped tables, so purges and conformance never treat it as
//!    tenant data. Config-backed operators are never seeded here; config
//!    always outranks the DB.
//! 2. `Db` methods with exactly these shapes (P04 calls only these):
//!
//!    ```text
//!    get_relay_operator(&self, pubkey: &[u8; 32]) -> Result<Option<RelayOperatorRow>, DbError>
//!    list_relay_operators(&self) -> Result<Vec<RelayOperatorRow>, DbError>
//!    upsert_relay_operator(&self, pubkey: &[u8; 32], role: &str, added_by: &[u8; 32])
//!        -> Result<Option<String /* prev_role */>, DbError>
//!    delete_relay_operator(&self, pubkey: &[u8; 32]) -> Result<bool /* existed */, DbError>
//!    ```
//!
//!    where `RelayOperatorRow { pubkey: Vec<u8>, role: String,
//!    added_by: Vec<u8> }`. Unknown `role` strings must be preserved verbatim
//!    so the relay can reject them closed instead of misreading them.
//! 3. Swap the store wired in `AppState::new` (`crates/buzz-relay/src/state.rs`)
//!    from [`NoDbRoster`] to the `Db`-backed implementation, and delete the
//!    `Unavailable` path in the staffing routes once writes work.
//!
//! Staffing mutations should additionally write an append-only audit row
//! (actor, target, grant/revoke, previous role, timestamp) in the same
//! transaction; see upstream `block/buzz#3777` migration `0039` for the shape.

use std::sync::Arc;

/// A roster entry as the admin API reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterEntry {
    /// Lowercase hex pubkey.
    pub pubkey_hex: String,
    /// `operator` or `moderator`.
    pub role: StoredAdminRole,
    /// Lowercase hex pubkey that granted this row, if recorded.
    pub added_by_hex: Option<String>,
}

/// Role stored for a DB roster row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoredAdminRole {
    /// Deployment-wide operator: reads, acts, and staffs the roster.
    Operator,
    /// Day-to-day triage: reads and acts, but never staffs.
    Moderator,
}

impl StoredAdminRole {
    /// Canonical wire string shared by the API, audit, and the DB contract.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Operator => "operator",
            Self::Moderator => "moderator",
        }
    }

    /// Parse a stored role string. Unknown values are rejected so a corrupt
    /// row fails closed instead of resolving to a weaker role.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "operator" => Some(Self::Operator),
            "moderator" => Some(Self::Moderator),
            _ => None,
        }
    }
}

/// Failure from the roster backing store.
#[derive(Debug)]
pub enum RosterError {
    /// The store is not wired yet (P03 migration pending). Callers map this
    /// to `503` with code `roster_unavailable`, never to an auth decision.
    Unavailable(&'static str),
    /// The store failed. Callers fail closed.
    Internal(String),
}

impl std::fmt::Display for RosterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(where_) => write!(f, "roster store unavailable: {where_}"),
            Self::Internal(message) => write!(f, "roster store failed: {message}"),
        }
    }
}

/// Backing store for DB-managed roster grants.
///
/// Config grants never reach this trait; it covers only the `relay_operators`
/// table. Implementations must be tenant-free: the roster is deployment-global
/// and no method takes a community id.
#[async_trait::async_trait]
pub trait AdminRosterStore: Send + Sync + std::fmt::Debug {
    /// Role granted to `pubkey` by a DB row, or `None` when there is no row.
    async fn role_for_pubkey(
        &self,
        pubkey: &[u8; 32],
    ) -> Result<Option<StoredAdminRole>, RosterError>;

    /// Every DB-managed grant, for the operator-only roster listing.
    async fn list_entries(&self) -> Result<Vec<RosterEntry>, RosterError>;

    /// Insert or replace the grant for `pubkey`. Returns the previous role
    /// string when a row already existed, so staffing responses can report
    /// whether the call created or updated the grant.
    async fn grant(
        &self,
        pubkey: &[u8; 32],
        role: StoredAdminRole,
        added_by: &[u8; 32],
    ) -> Result<Option<String>, RosterError>;

    /// Remove the grant for `pubkey`. Returns whether a row existed; removing
    /// a missing grant is a no-op that writes no audit row. `actor` is the
    /// authenticated operator performing the revocation.
    async fn revoke(&self, pubkey: &[u8; 32], actor: &[u8; 32]) -> Result<bool, RosterError>;
}

/// `Db`-backed roster store wired in production after the P08 migration tail.
#[derive(Debug, Clone)]
pub struct DbRoster {
    db: buzz_db::Db,
}

/// Build the production roster store backed by `relay_operators`.
pub fn db_roster(db: buzz_db::Db) -> Arc<dyn AdminRosterStore> {
    Arc::new(DbRoster { db })
}

#[async_trait::async_trait]
impl AdminRosterStore for DbRoster {
    async fn role_for_pubkey(
        &self,
        pubkey: &[u8; 32],
    ) -> Result<Option<StoredAdminRole>, RosterError> {
        let row = self
            .db
            .get_relay_operator(pubkey)
            .await
            .map_err(|err| RosterError::Internal(err.to_string()))?;
        Ok(row.and_then(|entry| StoredAdminRole::parse(&entry.role)))
    }

    async fn list_entries(&self) -> Result<Vec<RosterEntry>, RosterError> {
        let rows = self
            .db
            .list_relay_operators()
            .await
            .map_err(|err| RosterError::Internal(err.to_string()))?;
        rows.into_iter()
            .map(|row| {
                let role = StoredAdminRole::parse(&row.role).ok_or_else(|| {
                    RosterError::Internal(format!("unknown roster role: {}", row.role))
                })?;
                Ok(RosterEntry {
                    pubkey_hex: hex::encode(&row.pubkey),
                    role,
                    added_by_hex: Some(hex::encode(&row.added_by)),
                })
            })
            .collect()
    }

    async fn grant(
        &self,
        pubkey: &[u8; 32],
        role: StoredAdminRole,
        added_by: &[u8; 32],
    ) -> Result<Option<String>, RosterError> {
        self.db
            .upsert_relay_operator(pubkey, role.as_str(), added_by)
            .await
            .map_err(|err| RosterError::Internal(err.to_string()))
    }

    async fn revoke(&self, pubkey: &[u8; 32], actor: &[u8; 32]) -> Result<bool, RosterError> {
        self.db
            .remove_relay_operator(pubkey, actor)
            .await
            .map_err(|err| RosterError::Internal(err.to_string()))
    }
}

/// Placeholder store wired until P03 lands the roster migration.
///
/// Reads resolve empty (no DB grants); writes report [`RosterError::Unavailable`].
/// Config and owner-fallback roles are unaffected.
#[derive(Debug, Default)]
pub struct NoDbRoster;

/// Build the placeholder roster store for `AppState::new`.
pub fn no_db_roster() -> Arc<dyn AdminRosterStore> {
    Arc::new(NoDbRoster)
}

#[async_trait::async_trait]
impl AdminRosterStore for NoDbRoster {
    async fn role_for_pubkey(
        &self,
        _pubkey: &[u8; 32],
    ) -> Result<Option<StoredAdminRole>, RosterError> {
        Ok(None)
    }

    async fn list_entries(&self) -> Result<Vec<RosterEntry>, RosterError> {
        Ok(Vec::new())
    }

    async fn grant(
        &self,
        _pubkey: &[u8; 32],
        _role: StoredAdminRole,
        _added_by: &[u8; 32],
    ) -> Result<Option<String>, RosterError> {
        Err(RosterError::Unavailable(
            "relay_operators table pending (P03 migration)",
        ))
    }

    async fn revoke(&self, _pubkey: &[u8; 32], _actor: &[u8; 32]) -> Result<bool, RosterError> {
        Err(RosterError::Unavailable(
            "relay_operators table pending (P03 migration)",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_role_wire_strings_round_trip() {
        assert_eq!(
            StoredAdminRole::parse(StoredAdminRole::Operator.as_str()),
            Some(StoredAdminRole::Operator)
        );
        assert_eq!(
            StoredAdminRole::parse(StoredAdminRole::Moderator.as_str()),
            Some(StoredAdminRole::Moderator)
        );
        assert_eq!(StoredAdminRole::parse("admin"), None);
        assert_eq!(StoredAdminRole::parse(""), None);
    }

    #[tokio::test]
    async fn no_db_roster_reads_empty_and_writes_unavailable() {
        let store = NoDbRoster;
        assert_eq!(store.role_for_pubkey(&[7u8; 32]).await.unwrap(), None);
        assert!(store.list_entries().await.unwrap().is_empty());
        assert!(matches!(
            store
                .grant(&[7u8; 32], StoredAdminRole::Moderator, &[8u8; 32])
                .await,
            Err(RosterError::Unavailable(_))
        ));
        assert!(matches!(
            store.revoke(&[7u8; 32], &[8u8; 32]).await,
            Err(RosterError::Unavailable(_))
        ));
    }
}
