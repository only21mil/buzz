//! CI control-plane signer grants: durable authorization for kind 46101-46106.
//!
//! The relay's CI ingest gate calls [`get_active_ci_signers`] to load the
//! active grant set for `(community, channel, target_repo_a)` at the current
//! time, then passes it to `buzz_core::ci::validate_signed_ci_event` as the
//! `authorized_status_signers` set.  A grant is upserted by a channel
//! owner/admin via a kind 46107 grant event handled in the relay's ingest
//! pipeline.

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row as _};

use crate::error::Result;
use crate::CommunityId;

/// Upsert a CI signer grant into `ci_grants`.
///
/// A re-grant for the same `(community, channel, repo_a, signer)` is an
/// idempotent upsert: the validity window and `granted_by` are updated, and
/// `created_at` is preserved.
#[allow(clippy::too_many_arguments)]
pub async fn upsert_ci_grant(
    pool: &PgPool,
    community: CommunityId,
    channel_id: uuid::Uuid,
    target_repo_a: &str,
    signer_pubkey: &str,
    valid_from: DateTime<Utc>,
    valid_until: Option<DateTime<Utc>>,
    granted_by: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO ci_grants \
         (community_id, channel_id, target_repo_a, signer_pubkey, valid_from, valid_until, granted_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (community_id, channel_id, target_repo_a, signer_pubkey) \
         DO UPDATE SET valid_from = EXCLUDED.valid_from, \
                       valid_until = EXCLUDED.valid_until, \
                       granted_by = EXCLUDED.granted_by",
    )
    .bind(community.as_uuid())
    .bind(channel_id)
    .bind(target_repo_a)
    .bind(signer_pubkey)
    .bind(valid_from)
    .bind(valid_until)
    .bind(granted_by)
    .execute(pool)
    .await?;
    Ok(())
}

/// Return the active signer pubkeys (hex) for
/// `(community, channel, target_repo_a)` at `now`.
///
/// A grant is active when `valid_from <= now` and (`valid_until IS NULL` or
/// `valid_until > now`).  The returned set is the `authorized_status_signers`
/// set consumed by `buzz_core::ci::validate_signed_ci_event`.
pub async fn get_active_ci_signers(
    pool: &PgPool,
    community: CommunityId,
    channel_id: uuid::Uuid,
    target_repo_a: &str,
    now: DateTime<Utc>,
) -> Result<Vec<String>> {
    let rows = sqlx::query(
        "SELECT signer_pubkey FROM ci_grants \
         WHERE community_id = $1 AND channel_id = $2 AND target_repo_a = $3 \
         AND valid_from <= $4 \
         AND (valid_until IS NULL OR valid_until > $4)",
    )
    .bind(community.as_uuid())
    .bind(channel_id)
    .bind(target_repo_a)
    .bind(now)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|r| {
            r.try_get::<String, _>("signer_pubkey")
                .map_err(crate::error::DbError::from)
        })
        .collect::<Result<Vec<_>>>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    const TEST_DB_URL: &str = "postgres://buzz:buzz_dev@localhost:5432/buzz";

    async fn setup_pool() -> PgPool {
        let database_url = std::env::var("BUZZ_TEST_DATABASE_URL")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .unwrap_or_else(|_| TEST_DB_URL.to_owned());
        PgPool::connect(&database_url)
            .await
            .expect("connect to test DB")
    }

    async fn make_test_community(pool: &PgPool) -> CommunityId {
        let id = Uuid::new_v4();
        let host = format!("ci-grants-test-{}.example", id.simple());
        sqlx::query("INSERT INTO communities (id, host) VALUES ($1, $2)")
            .bind(id)
            .bind(host)
            .execute(pool)
            .await
            .expect("insert test community");
        CommunityId::from_uuid(id)
    }

    async fn make_test_channel(pool: &PgPool, community: CommunityId) -> Uuid {
        let channel_id = Uuid::new_v4();
        let owner: Vec<u8> = (0..32).collect();
        sqlx::query(
            "INSERT INTO channels (community_id, id, name, created_by) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(community.as_uuid())
        .bind(channel_id)
        .bind(format!("ci-grants-channel-{}", channel_id.simple()))
        .bind(&owner)
        .execute(pool)
        .await
        .expect("insert test channel");
        channel_id
    }

    fn pk() -> String {
        format!("{:064x}", Uuid::new_v4().as_u128())
    }

    fn repo_a() -> String {
        let owner = pk();
        format!("30617:{owner}:test-repo")
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn upsert_and_query_active_signers() {
        let pool = setup_pool().await;
        let community = make_test_community(&pool).await;
        let channel = make_test_channel(&pool, community).await;
        let repo_a = repo_a();
        let signer = pk();
        let now = Utc::now();

        upsert_ci_grant(
            &pool,
            community,
            channel,
            &repo_a,
            &signer,
            now - chrono::Duration::hours(1),
            None,
            "owner",
        )
        .await
        .expect("upsert grant");

        let signers = get_active_ci_signers(&pool, community, channel, &repo_a, now)
            .await
            .expect("query active signers");
        assert_eq!(signers, vec![signer]);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn expired_grant_is_not_active() {
        let pool = setup_pool().await;
        let community = make_test_community(&pool).await;
        let channel = make_test_channel(&pool, community).await;
        let repo_a = repo_a();
        let signer = pk();
        let now = Utc::now();

        upsert_ci_grant(
            &pool,
            community,
            channel,
            &repo_a,
            &signer,
            now - chrono::Duration::hours(2),
            Some(now - chrono::Duration::hours(1)),
            "owner",
        )
        .await
        .expect("upsert expired grant");

        let signers = get_active_ci_signers(&pool, community, channel, &repo_a, now)
            .await
            .expect("query");
        assert!(signers.is_empty(), "expired grant must not be active");
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn future_grant_is_not_active() {
        let pool = setup_pool().await;
        let community = make_test_community(&pool).await;
        let channel = make_test_channel(&pool, community).await;
        let repo_a = repo_a();
        let signer = pk();
        let now = Utc::now();

        upsert_ci_grant(
            &pool,
            community,
            channel,
            &repo_a,
            &signer,
            now + chrono::Duration::hours(1),
            None,
            "owner",
        )
        .await
        .expect("upsert future grant");

        let signers = get_active_ci_signers(&pool, community, channel, &repo_a, now)
            .await
            .expect("query");
        assert!(signers.is_empty(), "future grant must not be active yet");
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn upsert_is_idempotent_and_updates_window() {
        let pool = setup_pool().await;
        let community = make_test_community(&pool).await;
        let channel = make_test_channel(&pool, community).await;
        let repo_a = repo_a();
        let signer = pk();
        let now = Utc::now();

        upsert_ci_grant(
            &pool,
            community,
            channel,
            &repo_a,
            &signer,
            now - chrono::Duration::hours(1),
            Some(now + chrono::Duration::hours(1)),
            "owner",
        )
        .await
        .expect("first upsert");

        // Upsert again with a wider window.
        upsert_ci_grant(
            &pool,
            community,
            channel,
            &repo_a,
            &signer,
            now - chrono::Duration::hours(1),
            None,
            "admin",
        )
        .await
        .expect("second upsert");

        let signers = get_active_ci_signers(&pool, community, channel, &repo_a, now)
            .await
            .expect("query");
        assert_eq!(signers.len(), 1, "upsert must not duplicate the row");
        assert_eq!(signers[0], signer);
    }

    #[tokio::test]
    #[ignore = "requires Postgres"]
    async fn grants_are_scoped_per_repo() {
        let pool = setup_pool().await;
        let community = make_test_community(&pool).await;
        let channel = make_test_channel(&pool, community).await;
        let first_repo = repo_a();
        let second_repo = repo_a();
        let signer = pk();
        let now = Utc::now();

        upsert_ci_grant(
            &pool,
            community,
            channel,
            &first_repo,
            &signer,
            now - chrono::Duration::hours(1),
            None,
            "owner",
        )
        .await
        .expect("upsert for first repo");

        let signers = get_active_ci_signers(&pool, community, channel, &second_repo, now)
            .await
            .expect("query");
        assert!(
            signers.is_empty(),
            "grant for one repo must not authorize another"
        );
    }
}
