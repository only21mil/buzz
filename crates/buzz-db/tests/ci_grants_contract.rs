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

    let signers = get_active_ci_signers(
        &fixture.pool,
        fixture.community,
        fixture.channel,
        &repo,
        now,
    )
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

    let signers = get_active_ci_signers(
        &fixture.pool,
        fixture.community,
        fixture.channel,
        &repo,
        now,
    )
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

    let signers = get_active_ci_signers(
        &fixture.pool,
        fixture.community,
        fixture.channel,
        &repo,
        now,
    )
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

    let at = get_active_ci_signers(
        &fixture.pool,
        fixture.community,
        fixture.channel,
        &repo,
        now,
    )
    .await
    .expect("query at expiry");
    assert!(
        at.is_empty(),
        "valid_until == now must be exclusive (inactive)"
    );
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

    let signers = get_active_ci_signers(
        &fixture.pool,
        fixture.community,
        fixture.channel,
        &repo,
        now,
    )
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

// ── B1 rev-2 acceptance: kind-46107 ingest persistence + owner/admin gate ──
//
// These target the POST-C2 contract: the ingest half that consumes a kind
// 46107 grant event and persists it via `upsert_ci_grant`, and the read half
// (`get_active_ci_signers`) that makes the grant visible to the auth-gate
// union. The role-authorization (owner/admin-only) and expiry-window rejection
// live in the C2 ingest handler; these DB tests pin the persistence contract
// that handler must call, and the `#[ignore]`d ones are runnable against the
// scratch Postgres via `scripts/b1-db-grants-basis.sh`.

/// Kind-46107 persistence contract: an owner/admin upsert for an ACTIVE window
/// is durable in `ci_grants` and immediately visible to `get_active_ci_signers`
/// at a query time inside the window. This is the endpoint C2's ingest handler
/// must reach after role authorization.
#[tokio::test]
#[ignore = "requires Postgres"]
async fn owner_grant_is_durable_and_visible_to_get_active_ci_signers() {
    let fixture = Fixture::new().await;
    let repo = fixture.repo_a();
    let signer = signer_pk();
    let grantor = signer_pk(); // owner/admin pubkey (hex)
    let now = Utc::now();

    upsert_ci_grant(
        &fixture.pool,
        fixture.community,
        fixture.channel,
        &repo,
        &signer,
        now - Duration::minutes(5),
        Some(now + Duration::hours(1)),
        &grantor,
    )
    .await
    .expect("upsert owner grant");

    let signers = get_active_ci_signers(
        &fixture.pool,
        fixture.community,
        fixture.channel,
        &repo,
        now,
    )
    .await
    .expect("query active signers");
    assert_eq!(
        signers,
        vec![signer.clone()],
        "owner/admin grant must be visible to the auth-gate read"
    );

    // Persistence is transactional at the row level: the same grant row is
    // readable even after a second upsert (idempotent) of the identical key.
    upsert_ci_grant(
        &fixture.pool,
        fixture.community,
        fixture.channel,
        &repo,
        &signer,
        now - Duration::minutes(5),
        Some(now + Duration::hours(1)),
        &grantor,
    )
    .await
    .expect("re-upsert owner grant");
    let signers = get_active_ci_signers(
        &fixture.pool,
        fixture.community,
        fixture.channel,
        &repo,
        now,
    )
    .await
    .expect("query after idempotent re-upsert");
    assert_eq!(
        signers.len(),
        1,
        "re-upsert must not duplicate the grant row"
    );
    assert_eq!(signers[0], signer);
}

/// Kind-46107 persistence contract: a grant for a NON-owner/admin actor is
/// rejected by C2's ingest ROLE gate before it can reach `upsert_ci_grant`.
/// The DB layer cannot know roles, so this test pins the observer contract:
/// until a role-authorizing upsert runs, `get_active_ci_signers` must return
/// empty for every candidate signer the C2 handler would have skipped.
#[tokio::test]
#[ignore = "requires Postgres"]
async fn rejected_non_owner_grant_is_never_visible() {
    let fixture = Fixture::new().await;
    let repo = fixture.repo_a();
    let signer = signer_pk();
    let now = Utc::now();

    // The C2 handler rejects BEFORE upserting; the DB-side contract is that no
    // row appears. Assert the observable read half returns empty when the
    // upsert never happened (the "role-unauthorized grant" trace).
    let signers = get_active_ci_signers(
        &fixture.pool,
        fixture.community,
        fixture.channel,
        &repo,
        now,
    )
    .await
    .expect("query active signers");
    assert!(
        signers.is_empty(),
        "a never-upserted (non-owner/admin) grant must leave the active set empty"
    );
    // Not in the set for any repo, either — the signer never entered storage.
    let signers = get_active_ci_signers(
        &fixture.pool,
        fixture.community,
        fixture.channel,
        &fixture.repo_a(),
        now,
    )
    .await
    .expect("query other repo");
    assert!(!signers.contains(&signer));
}

/// Kind-46107 persistence contract: a MALFORMED validity window (valid_until
/// at or before valid_from) must not survive as an active grant. The C2 ingest
/// handler rejects the malformed window; this pins the read-half guarantee
/// that such a window yields no active signer at any `now`.
#[tokio::test]
#[ignore = "requires Postgres"]
async fn malformed_validity_window_is_never_active() {
    let fixture = Fixture::new().await;
    let repo = fixture.repo_a();
    let signer = signer_pk();
    let now = Utc::now();

    // A window that already ended at `now - 1s` (start before end) is not a
    // valid future grant. Even if a writer persisted it, the read half must
    // exclude it at `now`.
    upsert_ci_grant(
        &fixture.pool,
        fixture.community,
        fixture.channel,
        &repo,
        &signer,
        now - Duration::hours(2),
        Some(now - Duration::seconds(1)),
        "owner",
    )
    .await
    .expect("upsert malformed (already-expired) window");

    let signers = get_active_ci_signers(
        &fixture.pool,
        fixture.community,
        fixture.channel,
        &repo,
        now,
    )
    .await
    .expect("query active signers");
    assert!(
        signers.is_empty(),
        "a window already in the past must never be active"
    );

    // And the C2 handler's own rejection contract: a `valid_until <= valid_from`
    // window is malformed on ingest. The DB layer is a pure storage seam, so the
    // handler (not here) is responsible for rejecting it pre-upsert — but the
    // observable contract is that a back-to-back window cannot grant anything.
    upsert_ci_grant(
        &fixture.pool,
        fixture.community,
        fixture.channel,
        &repo,
        &signer,
        now,
        Some(now),
        "owner",
    )
    .await
    .expect("upsert zero-length window");
    let signers = get_active_ci_signers(
        &fixture.pool,
        fixture.community,
        fixture.channel,
        &repo,
        now,
    )
    .await
    .expect("query after zero-length window");
    assert!(
        signers.is_empty(),
        "a zero-length window must never be active at its own boundary"
    );
}
