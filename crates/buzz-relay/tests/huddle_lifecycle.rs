//! Executes Huddle authorization through the production ingest entry point.
//! Run with scripts/postgres-test-local.py --schema-mode desired.
use std::sync::Arc;

use buzz_auth::Scope;
use buzz_core::{
    kind::{KIND_HUDDLE_ENDED, KIND_HUDDLE_STARTED},
    tenant::TenantContext,
    CommunityId,
};
use buzz_relay::{
    config::Config,
    handlers::ingest::{ingest_event, IngestAuth, IngestError},
    state::AppState,
};
use nostr::{Event, EventBuilder, Keys, Kind, Tag};
use sqlx::PgPool;
use uuid::Uuid;

async fn community(pool: &PgPool) -> TenantContext {
    let id = Uuid::new_v4();
    let host = format!("huddle-{}.test", id.simple());
    sqlx::query("INSERT INTO communities(id,host) VALUES ($1,$2)")
        .bind(id)
        .bind(&host)
        .execute(pool)
        .await
        .expect("community");
    TenantContext::resolved(CommunityId::from_uuid(id), host)
}

async fn channel(pool: &PgPool, tenant: &TenantContext, owner: &Keys, backing: bool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO channels(community_id,id,name,created_by,visibility,ttl_seconds) VALUES ($1,$2,$3,$4,$5::channel_visibility,$6)")
        .bind(tenant.community().as_uuid()).bind(id).bind(format!("huddle-{id}"))
        .bind(owner.public_key().to_bytes().to_vec()).bind(if backing {"private"} else {"open"})
        .bind(backing.then_some(3600i32)).execute(pool).await.expect("channel");
    id
}

fn lifecycle(keys: &Keys, kind: u32, parent: Uuid, backing: Uuid) -> Event {
    EventBuilder::new(
        Kind::Custom(kind as u16),
        serde_json::json!({"ephemeral_channel_id":backing, "nonce":Uuid::new_v4()}).to_string(),
    )
    .tags([Tag::parse(["h".to_string(), parent.to_string()]).expect("h tag")])
    .sign_with_keys(keys)
    .expect("synthetic event")
}

async fn submit(
    pool: &PgPool,
    state: &Arc<AppState>,
    tenant: &TenantContext,
    event: Event,
    expected: Option<&str>,
) {
    let id = event.id.to_bytes().to_vec();
    let auth = IngestAuth::Nip42 {
        pubkey: event.pubkey,
        scopes: vec![Scope::MessagesWrite, Scope::ChannelsWrite],
        channel_ids: None,
        conn_id: Uuid::new_v4(),
    };
    let result = ingest_event(state, tenant, event, auth).await;
    match expected {
        None => assert!(result.expect("accepted lifecycle").accepted),
        Some(message) => assert!(
            matches!(&result, Err(IngestError::Rejected(actual)) if actual.contains(message)),
            "expected {message}: {:?}",
            result.err()
        ),
    }
    let stored: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM events WHERE community_id=$1 AND id=$2)")
            .bind(tenant.community().as_uuid())
            .bind(id)
            .fetch_one(pool)
            .await
            .expect("storage proof");
    assert_eq!(stored, expected.is_none(), "denials must not persist");
}

#[tokio::test]
#[ignore = "requires disposable Postgres via postgres-test-local.py"]
async fn huddle_lifecycle_ingest_postgres_acceptance() {
    assert_eq!(
        std::env::var("BUZZ_TEST_SCHEMA_MODE").as_deref(),
        Ok("desired")
    );
    let url = std::env::var("BUZZ_TEST_DATABASE_URL").expect("isolated runner required");
    let pool = PgPool::connect(&url).await.expect("owned database");
    let mut config = Config::from_env().expect("test config");
    config.database_url = url;
    config.require_relay_membership = false;
    config.require_auth_token = false;
    config.ephemeral_ttl_override = None;
    config.redis_url = "redis+unix:///nonexistent-buzz-huddle-test.sock".into();
    let redis = deadpool_redis::Config::from_url(&config.redis_url)
        .create_pool(Some(deadpool_redis::Runtime::Tokio1))
        .expect("lazy Redis pool");
    let pubsub = Arc::new(
        buzz_pubsub::PubSubManager::new(&config.redis_url, redis.clone())
            .await
            .expect("local pubsub"),
    );
    let db = buzz_db::Db::from_pool(pool.clone());
    let audit = buzz_audit::AuditService::new(pool.clone());
    let auth = buzz_auth::AuthService::new(config.auth.clone());
    let search = buzz_search::SearchService::new(pool.clone());
    let workflow = Arc::new(buzz_workflow::WorkflowEngine::new(
        db.clone(),
        Default::default(),
    ));
    let media = buzz_media::MediaStorage::new(&config.media).expect("media config");
    let (state, shutdown) = AppState::new(
        config,
        db,
        redis,
        audit,
        pubsub,
        auth,
        search,
        workflow,
        Keys::generate(),
        media,
    );
    let state = Arc::new(state);
    let tenant = community(&pool).await;
    let other = community(&pool).await;
    let owner = Keys::generate();
    let stranger = Keys::generate();
    let parent = channel(&pool, &tenant, &owner, false).await;
    let other_parent = channel(&pool, &tenant, &owner, false).await;
    let backing = channel(&pool, &tenant, &owner, true).await;
    submit(
        &pool,
        &state,
        &tenant,
        lifecycle(&owner, KIND_HUDDLE_STARTED, parent, backing),
        None,
    )
    .await;
    submit(
        &pool,
        &state,
        &tenant,
        lifecycle(&owner, KIND_HUDDLE_ENDED, parent, backing),
        None,
    )
    .await;
    let foreign = channel(&pool, &other, &owner, true).await;
    submit(
        &pool,
        &state,
        &tenant,
        lifecycle(&owner, KIND_HUDDLE_STARTED, parent, foreign),
        Some("backing channel not found"),
    )
    .await;
    submit(
        &pool,
        &state,
        &tenant,
        lifecycle(&stranger, KIND_HUDDLE_STARTED, parent, backing),
        Some("signer's active private ephemeral stream"),
    )
    .await;
    submit(
        &pool,
        &state,
        &tenant,
        lifecycle(&stranger, KIND_HUDDLE_ENDED, parent, backing),
        Some("only the Huddle creator"),
    )
    .await;
    submit(
        &pool,
        &state,
        &tenant,
        lifecycle(&owner, KIND_HUDDLE_ENDED, other_parent, backing),
        Some("does not match a creator-signed start"),
    )
    .await;
    let unstarted = channel(&pool, &tenant, &owner, true).await;
    submit(
        &pool,
        &state,
        &tenant,
        lifecycle(&owner, KIND_HUDDLE_ENDED, parent, unstarted),
        Some("does not match a creator-signed start"),
    )
    .await;
    // A stored start from another signer must not authorize the owner's end.
    state
        .db
        .insert_event(
            tenant.community(),
            &lifecycle(&stranger, KIND_HUDDLE_STARTED, parent, unstarted),
            Some(parent),
        )
        .await
        .expect("legacy foreign-signed start fixture");
    submit(
        &pool,
        &state,
        &tenant,
        lifecycle(&owner, KIND_HUDDLE_ENDED, parent, unstarted),
        Some("does not match a creator-signed start"),
    )
    .await;
    // Deleted starts cannot keep authorizing end messages.
    sqlx::query(
        "UPDATE events SET deleted_at=NOW() WHERE community_id=$1 AND channel_id=$2 AND kind=$3",
    )
    .bind(tenant.community().as_uuid())
    .bind(parent)
    .bind(KIND_HUDDLE_STARTED as i32)
    .execute(&pool)
    .await
    .expect("delete start fixture");
    submit(
        &pool,
        &state,
        &tenant,
        lifecycle(&owner, KIND_HUDDLE_ENDED, parent, backing),
        Some("does not match a creator-signed start"),
    )
    .await;
    for (ttl, channel_type, visibility, archived) in [
        (Some(60i32), "stream", "private", false),
        (None, "stream", "private", false),
        (Some(3600), "forum", "private", false),
        (Some(3600), "stream", "open", false),
        (Some(3600), "stream", "private", true),
    ] {
        let bad = channel(&pool, &tenant, &owner, true).await;
        sqlx::query("UPDATE channels SET ttl_seconds=$3, channel_type=$4::channel_type, visibility=$5::channel_visibility, archived_at=CASE WHEN $6 THEN NOW() ELSE NULL END WHERE community_id=$1 AND id=$2")
            .bind(tenant.community().as_uuid()).bind(bad).bind(ttl).bind(channel_type).bind(visibility).bind(archived)
            .execute(&pool).await.expect("invalid backing fixture");
        submit(
            &pool,
            &state,
            &tenant,
            lifecycle(&owner, KIND_HUDDLE_STARTED, parent, bad),
            Some("signer's active private ephemeral stream"),
        )
        .await;
    }
    sqlx::query("UPDATE channels SET archived_at=NOW() WHERE community_id=$1 AND id=$2")
        .bind(tenant.community().as_uuid())
        .bind(parent)
        .execute(&pool)
        .await
        .expect("archive parent");
    submit(
        &pool,
        &state,
        &tenant,
        lifecycle(&owner, KIND_HUDDLE_STARTED, parent, backing),
        Some("channel is archived"),
    )
    .await;
    shutdown.drain(std::time::Duration::from_secs(5)).await;
    drop(state);
    pool.close().await;
}
