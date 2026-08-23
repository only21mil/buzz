//! Contract tests for persisting a workflow definition's `enabled` flag.

use buzz_core::CommunityId;
use buzz_db::{workflow, DbError};
use sqlx::postgres::{PgPool, PgPoolOptions};
use uuid::Uuid;

const TEST_DB_URL: &str = "postgres://buzz:buzz_dev@localhost:5432/buzz";
const DEFINITION: &str = r#"{"trigger":{"on":"message_posted"},"steps":[]}"#;

struct Fixture {
    pool: PgPool,
    community: CommunityId,
    owner: [u8; 32],
    other_owner: [u8; 32],
    channel: Uuid,
    other_channel: Uuid,
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
            .expect("connect to workflow enabled test database");
        buzz_db::migration::run_migrations(&pool)
            .await
            .expect("apply workflow migrations");

        let community_uuid = Uuid::new_v4();
        let community = CommunityId::from_uuid(community_uuid);
        sqlx::query("INSERT INTO communities (id, host) VALUES ($1, $2)")
            .bind(community_uuid)
            .bind(format!("workflow-enabled-{}.test", community_uuid.simple()))
            .execute(&pool)
            .await
            .expect("insert test community");

        let owner = [0x71; 32];
        let other_owner = [0x72; 32];
        buzz_db::user::ensure_user(&pool, community, &owner)
            .await
            .expect("insert workflow owner");
        buzz_db::user::ensure_user(&pool, community, &other_owner)
            .await
            .expect("insert other workflow owner");

        let channel = insert_channel(&pool, community, &owner).await;
        let other_channel = insert_channel(&pool, community, &owner).await;

        Self {
            pool,
            community,
            owner,
            other_owner,
            channel,
            other_channel,
        }
    }
}

async fn insert_channel(pool: &PgPool, community: CommunityId, owner: &[u8]) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO channels (id, community_id, name, created_by) VALUES ($1, $2, $3, $4)",
    )
    .bind(id)
    .bind(community.as_uuid())
    .bind(format!("workflow-enabled-{}", id.simple()))
    .bind(owner)
    .execute(pool)
    .await
    .expect("insert test channel");
    id
}

async fn upsert(fixture: &Fixture, id: Uuid, owner: &[u8], channel: Uuid, enabled: bool) {
    workflow::upsert_workflow(
        &fixture.pool,
        fixture.community,
        id,
        Some(channel),
        owner,
        "enabled-contract",
        DEFINITION,
        &[0x73; 32],
        enabled,
    )
    .await
    .expect("upsert workflow");
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn workflow_enabled_create_preserves_disabled_state() {
    let fixture = Fixture::new().await;

    let workflow_id = workflow::create_workflow(
        &fixture.pool,
        fixture.community,
        Some(fixture.channel),
        &fixture.owner,
        "disabled-create",
        DEFINITION,
        &[0x70; 32],
        false,
    )
    .await
    .expect("create disabled workflow");

    let stored = workflow::get_workflow(&fixture.pool, fixture.community, workflow_id)
        .await
        .expect("read created workflow");
    assert!(!stored.enabled, "disabled create became enabled");
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn workflow_enabled_disabled_insert_is_persisted() {
    let fixture = Fixture::new().await;
    let workflow_id = Uuid::new_v4();

    upsert(
        &fixture,
        workflow_id,
        &fixture.owner,
        fixture.channel,
        false,
    )
    .await;

    let stored = workflow::get_workflow(&fixture.pool, fixture.community, workflow_id)
        .await
        .expect("read inserted workflow");
    assert!(
        !stored.enabled,
        "disabled definition became enabled on insert"
    );
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn workflow_enabled_updates_transition_and_keep_identity_guards() {
    let fixture = Fixture::new().await;
    let workflow_id = Uuid::new_v4();

    upsert(
        &fixture,
        workflow_id,
        &fixture.owner,
        fixture.channel,
        false,
    )
    .await;
    upsert(&fixture, workflow_id, &fixture.owner, fixture.channel, true).await;
    assert!(
        workflow::get_workflow(&fixture.pool, fixture.community, workflow_id)
            .await
            .expect("read enabled workflow")
            .enabled,
        "disabled-to-enabled update was not persisted"
    );

    upsert(
        &fixture,
        workflow_id,
        &fixture.owner,
        fixture.channel,
        false,
    )
    .await;
    upsert(
        &fixture,
        workflow_id,
        &fixture.owner,
        fixture.channel,
        false,
    )
    .await;
    assert!(
        !workflow::get_workflow(&fixture.pool, fixture.community, workflow_id)
            .await
            .expect("read disabled workflow")
            .enabled,
        "enabled-to-disabled update or same-owner retry was not persisted"
    );

    let wrong_owner = workflow::upsert_workflow(
        &fixture.pool,
        fixture.community,
        workflow_id,
        Some(fixture.channel),
        &fixture.other_owner,
        "wrong-owner",
        DEFINITION,
        &[0x74; 32],
        true,
    )
    .await;
    assert!(matches!(wrong_owner, Err(DbError::AccessDenied(_))));

    let wrong_channel = workflow::upsert_workflow(
        &fixture.pool,
        fixture.community,
        workflow_id,
        Some(fixture.other_channel),
        &fixture.owner,
        "wrong-channel",
        DEFINITION,
        &[0x75; 32],
        true,
    )
    .await;
    assert!(matches!(wrong_channel, Err(DbError::AccessDenied(_))));

    let stored = workflow::get_workflow(&fixture.pool, fixture.community, workflow_id)
        .await
        .expect("read guarded workflow");
    assert!(!stored.enabled, "rejected update mutated the enabled flag");
    assert_eq!(stored.name, "enabled-contract");
}
