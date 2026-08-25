//! B1 CI signer grants contract — integration coverage for the `ci_grants`
//! table and the `buzz_db::ci_grants` upsert/query surface (objective 1).
//!
//! Requires a live Postgres (`BUZZ_TEST_DATABASE_URL`, else the standard dev
//! URL) with `0035_ci_grants` applied. Compile-gate: needs A2 to land
//! `migrations/0035_ci_grants.sql` and export `pub mod ci_grants` from
//! `buzz-db/src/lib.rs` (A1 graft `c83959052` carries the file but has not
//! wired the module export yet — assembly-phase dependency, see report).
//!
//! Deterministic and scoped: every test creates an isolated community +
//! channel, so runs never collide and never touch owner-configured rows.

use buzz_core::CommunityId;
use chrono::{Duration, Utc};
use sqlx::postgres::{PgPool, PgPoolOptions};
use uuid::Uuid;

use buzz_db::ci_grants::{get_active_ci_signers, upsert_ci_grant};

const TEST_DB_URL: &str = "postgres://buzz:buzz_dev@localhost:5432/buzz";

struct Fixture {
    pool: PgPool,
    community: CommunityId,
    channel: Uuid,
}

impl Fixture {
    async fn new() -> Self {
        let database_url = std::env::var("BUZZ_TEST_DATABASE_URL")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .unwrap_or_else(|_| TEST_DB_URL.to_owned());
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&database_url)
            .await
            .expect("connect to ci-grants test database");
        buzz_db::migration::run_migrations(&pool)
            .await
            .expect("apply migrations");

        let community_uuid = Uuid::new_v4();
        let community = CommunityId::from_uuid(community_uuid);
        sqlx::query("INSERT INTO communities (id, host) VALUES ($1, $2)")
            .bind(community_uuid)
            .bind(format!("ci-grants-{}.test", community_uuid.simple()))
            .execute(&pool)
            .await
            .expect("insert test community");

        let channel_id = Uuid::new_v4();
        let owner: Vec<u8> = (0..32).collect();
        sqlx::query(
            "INSERT INTO channels (community_id, id, name, created_by) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(community_uuid)
        .bind(channel_id)
        .bind(format!("ci-grants-{}", channel_id.simple()))
        .bind(&owner)
        .execute(&pool)
        .await
        .expect("insert test channel");

        Self {
            pool,
            community,
            channel: channel_id,
        }
    }

    fn repo_a(&self) -> String {
        format!("30617:{}:ci-contract", Uuid::new_v4().as_simple())
    }
}

fn signer_pk() -> String {
    format!("{:064x}", Uuid::new_v4().as_u128())
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn upsert_then_query_returns_the_active_signer() {
    let fixture = Fixture::new().await;
    let repo = fixture.repo_a();
    let signer = signer_pk();
    let now = Utc::now();

    upsert_ci_grant(
        &fixture.pool,
        fixture.community,
        fixture.channel,
        &repo,
        &signer,
        now - Duration::hours(1),
        None,
        "owner",
    )
    .await
    .expect("upsert open-ended grant");

    let signers = get_active_ci_signers(&fixture.pool, fixture.community, fixture.channel, &repo, now)
        .await
        .expect("query active signers");
    assert_eq!(signers, vec![signer], "open-ended grant must be active");
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn future_grant_is_not_active_yet() {
    let fixture = Fixture::new().await;
    let repo = fixture.repo_a();
    let signer = signer_pk();
    let now = Utc::now();

    upsert_ci_grant(
        &fixture.pool,
        fixture.community,
        fixture.channel,
        &repo,
        &signer,
        now + Duration::hours(1),
        None,
        "owner",
    )
    .await
    .expect("upsert future grant");

    let signers = get_active_ci_signers(&fixture.pool, fixture.community, fixture.channel, &repo, now)
        .await
        .expect("query active signers");
    assert!(signers.is_empty(), "future grant must not be active yet");
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn expired_grant_is_not_active() {
    let fixture = Fixture::new().await;
    let repo = fixture.repo_a();
    let signer = signer_pk();
    let now = Utc::now();

    upsert_ci_grant(
        &fixture.pool,
        fixture.community,
        fixture.channel,
        &repo,
        &signer,
        now - Duration::hours(2),
        Some(now - Duration::hours(1)),
        "owner",
    )
    .await
    .expect("upsert expired grant");

    let signers = get_active_ci_signers(&fixture.pool, fixture.community, fixture.channel, &repo, now)
        .await
        .expect("query active signers");
    assert!(signers.is_empty(), "expired grant must not be active");
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn validity_window_boundary_is_aware_of_now() {
    let fixture = Fixture::new().await;
    let repo = fixture.repo_a();
    let signer = signer_pk();
    let now = Utc::now();

    // A grant that started before `now` and ends exactly at `now`.
    upsert_ci_grant(
        &fixture.pool,
        fixture.community,
        fixture.channel,
        &repo,
        &signer,
        now - Duration::minutes(30),
        Some(now),
        "owner",
    )
    .await
    .expect("upsert boundary grant");

    // At `now - 1s` it is inside the window; at `now` it is already outside
    // (valid_until > now is the exclusive bound).
    let just_before = now - Duration::seconds(1);
    let active = get_active_ci_signers(
        &fixture.pool,
        fixture.community,
        fixture.channel,
        &repo,
        just_before,
    )
    .await
    .expect("query just before expiry");
    assert_eq!(active, vec![signer.clone()]);

    let at = get_active_ci_signers(&fixture.pool, fixture.community, fixture.channel, &repo, now)
        .await
        .expect("query at expiry");
    assert!(at.is_empty(), "valid_until == now must be exclusive (inactive)");
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn upsert_is_idempotent_and_updates_window() {
    let fixture = Fixture::new().await;
    let repo = fixture.repo_a();
    let signer = signer_pk();
    let now = Utc::now();

    upsert_ci_grant(
        &fixture.pool,
        fixture.community,
        fixture.channel,
        &repo,
        &signer,
        now - Duration::hours(1),
        Some(now + Duration::hours(1)),
        "owner",
    )
    .await
    .expect("first upsert");

    // Second upsert changes the window to open-ended and the grantor.
    upsert_ci_grant(
        &fixture.pool,
        fixture.community,
        fixture.channel,
        &repo,
        &signer,
        now - Duration::hours(1),
        None,
        "admin",
    )
    .await
    .expect("second upsert");

    let signers = get_active_ci_signers(&fixture.pool, fixture.community, fixture.channel, &repo, now)
        .await
        .expect("query active signers");
    assert_eq!(signers.len(), 1, "upsert must not duplicate the row");
    assert_eq!(signers[0], signer);
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn grants_are_scoped_to_the_exact_repo_and_channel() {
    let fixture = Fixture::new().await;
    let repo = fixture.repo_a();
    let other_repo = fixture.repo_a();
    let signer = signer_pk();
    let now = Utc::now();

    // A second channel in the same community.
    let other_channel_id = Uuid::new_v4();
    let owner: Vec<u8> = (0..32).collect();
    sqlx::query(
        "INSERT INTO channels (community_id, id, name, created_by) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(fixture.community.as_uuid())
    .bind(other_channel_id)
    .bind(format!("ci-grants-{}", other_channel_id.simple()))
    .bind(&owner)
    .execute(&fixture.pool)
    .await
    .expect("insert second test channel");

    upsert_ci_grant(
        &fixture.pool,
        fixture.community,
        fixture.channel,
        &repo,
        &signer,
        now - Duration::hours(1),
        None,
        "owner",
    )
    .await
    .expect("upsert grant in first channel");

    // Same signer in the same channel but a different repo -> no grant.
    let signers = get_active_ci_signers(
        &fixture.pool,
        fixture.community,
        fixture.channel,
        &other_repo,
        now,
    )
    .await
    .expect("query other repo");
    assert!(signers.is_empty(), "grant must be repo-scoped");

    // Same signer + repo in a different channel -> no grant.
    let signers = get_active_ci_signers(
        &fixture.pool,
        fixture.community,
        other_channel_id,
        &repo,
        now,
    )
    .await
    .expect("query other channel");
    assert!(signers.is_empty(), "grant must be channel-scoped");

    // The active set in the original scope still resolves the signer.
    let signers = get_active_ci_signers(
        &fixture.pool,
        fixture.community,
        fixture.channel,
        &repo,
        now,
    )
    .await
    .expect("query original scope");
    assert_eq!(signers, vec![signer]);
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn multiple_active_signers_are_all_returned() {
    let fixture = Fixture::new().await;
    let repo = fixture.repo_a();
    let now = Utc::now();

    let first = signer_pk();
    let second = signer_pk();
    let grantor = signer_pk();
    for signer in [&first, &second] {
        upsert_ci_grant(
            &fixture.pool,
            fixture.community,
            fixture.channel,
            &repo,
            signer,
            now - Duration::hours(1),
            None,
            &grantor,
        )
        .await
        .expect("upsert grant");
    }

    let mut signers = get_active_ci_signers(
        &fixture.pool,
        fixture.community,
        fixture.channel,
        &repo,
        now,
    )
    .await
    .expect("query active signers");
    let mut expected = vec![first, second];
    expected.sort();
    signers.sort();
    assert_eq!(signers, expected);
}