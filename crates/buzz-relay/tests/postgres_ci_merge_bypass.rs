//! Kind 46109 merge bypass: ingest admission through the production entry
//! point, storage in `ci_merge_bypasses`, and one-time consumption.
//! Run with scripts/postgres-test-local.py.

use std::sync::Arc;

use buzz_auth::Scope;
use buzz_core::channel::{ChannelType, ChannelVisibility};
use buzz_core::ci::{merge_bypass_tags, CiMergeBypassEnvelope, CI_SCHEMA_VERSION};
use buzz_core::kind::KIND_CI_MERGE_BYPASS;
use buzz_core::tenant::TenantContext;
use buzz_core::CommunityId;
use buzz_db::channel_members::MemberRole;
use buzz_db::ci_merge_bypass::{
    consume_ci_merge_bypass, insert_ci_merge_bypass, list_ci_merge_bypasses,
};
use buzz_relay::config::Config;
use buzz_relay::handlers::ingest::{ingest_event, IngestAuth, IngestError};
use buzz_relay::state::AppState;
use nostr::{Event, EventBuilder, Keys, Kind, Tag};
use sqlx::PgPool;
use uuid::Uuid;

async fn pool() -> PgPool {
    let url = std::env::var("BUZZ_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .expect("explicit isolated test database URL required");
    let pool = PgPool::connect(&url).await.expect("owned database");
    buzz_db::migration::run_migrations(&pool)
        .await
        .expect("apply migrations");
    pool
}

async fn community(pool: &PgPool) -> TenantContext {
    let id = Uuid::new_v4();
    let host = format!("merge-bypass-{}.test", id.simple());
    sqlx::query("INSERT INTO communities(id,host) VALUES ($1,$2)")
        .bind(id)
        .bind(&host)
        .execute(pool)
        .await
        .expect("community");
    TenantContext::resolved(CommunityId::from_uuid(id), host)
}

/// Build relay state the way the Huddle acceptance test does: the loader
/// reads the runner's environment; Git paths are scoped to a temp dir.
async fn relay_state(pool: &PgPool) -> (Arc<AppState>, tempfile::TempDir) {
    let git_storage = tempfile::tempdir().expect("fixture Git storage");
    let git_root = git_storage.path().to_path_buf();
    let previous = [
        ("BUZZ_GIT_REPO_PATH", git_root.join("repos")),
        ("BUZZ_GIT_PACK_CACHE_PATH", git_root.join("pack-cache")),
    ]
    .map(|(name, path)| {
        let previous = std::env::var_os(name);
        std::env::set_var(name, path);
        (name, previous)
    });
    let config_result = Config::from_env();
    for (name, value) in previous {
        match value {
            Some(value) => std::env::set_var(name, value),
            None => std::env::remove_var(name),
        }
    }
    let mut config = config_result.expect("test config");
    config.require_relay_membership = false;
    config.require_auth_token = false;
    config.redis_url = "redis+unix:///nonexistent-buzz-merge-bypass-test.sock".into();
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
    let (state, _shutdown) = AppState::new(
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
    (Arc::new(state), git_storage)
}

fn envelope(owner: &Keys, issued_at: u64, window: u64) -> CiMergeBypassEnvelope {
    CiMergeBypassEnvelope {
        schema_version: CI_SCHEMA_VERSION,
        target_repo_a: format!("30617:{}:buzz", owner.public_key().to_hex()),
        ref_name: "refs/heads/main".into(),
        old_oid: "a".repeat(40),
        new_oid: "b".repeat(40),
        reason: "landing while the native plane is down".into(),
        issued_at,
        expires_at: issued_at + window,
    }
}

fn signed(signer: &Keys, channel: Uuid, envelope: &CiMergeBypassEnvelope) -> Event {
    let content = serde_json::to_string(envelope).expect("serialize");
    let tags = match merge_bypass_tags(&channel.to_string(), envelope) {
        Ok(tags) => tags,
        // An invalid envelope still needs index tags so the refusal under
        // test is the envelope's, not a missing channel.
        Err(_) => vec![
            Tag::parse(["h", &channel.to_string()]).expect("h"),
            Tag::parse(["a", &envelope.target_repo_a]).expect("a"),
        ],
    };
    EventBuilder::new(Kind::Custom(KIND_CI_MERGE_BYPASS as u16), content)
        .tags(tags)
        .sign_with_keys(signer)
        .expect("sign")
}

async fn submit(
    state: &Arc<AppState>,
    tenant: &TenantContext,
    event: Event,
) -> Result<bool, IngestError> {
    let auth = IngestAuth::Nip42 {
        pubkey: event.pubkey,
        scopes: vec![Scope::JobsWrite, Scope::MessagesWrite],
        channel_ids: None,
        conn_id: Uuid::new_v4(),
    };
    ingest_event(state, tenant, event, auth)
        .await
        .map(|result| result.accepted)
}

async fn stored_rows(pool: &PgPool, community: CommunityId, event: &Event) -> (bool, bool) {
    let event_row: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM events WHERE community_id=$1 AND id=$2)")
            .bind(community.as_uuid())
            .bind(event.id.as_bytes().to_vec())
            .fetch_one(pool)
            .await
            .expect("event row probe");
    let bypass_row: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM ci_merge_bypasses WHERE community_id=$1 AND event_id=$2)",
    )
    .bind(community.as_uuid())
    .bind(event.id.as_bytes().to_vec())
    .fetch_one(pool)
    .await
    .expect("bypass row probe");
    (event_row, bypass_row)
}

fn now_seconds() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp()).expect("current time")
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn merge_bypass_ingest_admits_the_repository_owner_and_refuses_others() {
    let pool = pool().await;
    let (state, _git) = relay_state(&pool).await;
    let tenant = community(&pool).await;
    let owner = Keys::generate();
    let admin = Keys::generate();
    let member = Keys::generate();
    let channel = state
        .db
        .create_channel(
            tenant.community(),
            "buzz",
            ChannelType::Stream,
            ChannelVisibility::Open,
            None,
            &owner.public_key().to_bytes(),
            None,
        )
        .await
        .expect("channel with owner")
        .id;
    let owner_bytes = owner.public_key().to_bytes().to_vec();
    state
        .db
        .add_member(
            tenant.community(),
            channel,
            &admin.public_key().to_bytes(),
            MemberRole::Admin,
            Some(&owner_bytes),
        )
        .await
        .expect("admin member");
    state
        .db
        .add_member(
            tenant.community(),
            channel,
            &member.public_key().to_bytes(),
            MemberRole::Member,
            None,
        )
        .await
        .expect("plain member");
    let now = now_seconds();

    // The repository owner, holding the channel owner role: accepted and
    // stored as a canonical event plus a bypass row.
    let accepted = signed(&owner, channel, &envelope(&owner, now, 900));
    assert!(submit(&state, &tenant, accepted.clone())
        .await
        .expect("owner bypass accepted"));
    assert_eq!(
        stored_rows(&pool, tenant.community(), &accepted).await,
        (true, true)
    );
    let rows = list_ci_merge_bypasses(
        &pool,
        tenant.community(),
        &format!("30617:{}:buzz", owner.public_key().to_hex()),
        "refs/heads/main",
        &"a".repeat(40),
        &"b".repeat(40),
    )
    .await
    .expect("list bypasses");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].event_id, accepted.id.as_bytes().to_vec());
    assert_eq!(rows[0].issuer_pubkey, owner.public_key().to_hex());
    assert_eq!(rows[0].channel_id, channel);
    assert!(rows[0].consumed_by.is_none());
    assert_eq!(rows[0].issued_at.timestamp(), now as i64);
    assert_eq!(rows[0].expires_at.timestamp(), (now + 900) as i64);

    // A replay of the same event is acknowledged and leaves one row.
    submit(&state, &tenant, accepted.clone())
        .await
        .expect("replay is not an error");
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM ci_merge_bypasses WHERE community_id=$1")
            .bind(tenant.community().as_uuid())
            .fetch_one(&pool)
            .await
            .expect("count");
    assert_eq!(count, 1);

    // A channel admin who is not the announcement owner: refused by the
    // envelope binding, nothing stored. The coordinate names the owner.
    let forged = signed(&admin, channel, &envelope(&owner, now, 900));
    let error = submit(&state, &tenant, forged.clone())
        .await
        .expect_err("admin signing the owner's coordinate is refused");
    assert!(
        matches!(&error, IngestError::Rejected(message) if message.contains("not the repository owner")),
        "unexpected refusal: {error:?}"
    );
    assert_eq!(
        stored_rows(&pool, tenant.community(), &forged).await,
        (false, false)
    );

    // A plain member naming themself as repository owner: the envelope
    // binds, but the channel role is neither owner nor admin.
    let self_owned = signed(&member, channel, &envelope(&member, now, 900));
    let error = submit(&state, &tenant, self_owned.clone())
        .await
        .expect_err("member role is refused");
    assert!(
        matches!(&error, IngestError::AuthFailed(message) if message.contains("owner or admin role")),
        "unexpected refusal: {error:?}"
    );
    assert_eq!(
        stored_rows(&pool, tenant.community(), &self_owned).await,
        (false, false)
    );

    // A window over one hour is refused before any role lookup.
    let long = signed(&owner, channel, &envelope(&owner, now, 3601));
    let error = submit(&state, &tenant, long.clone())
        .await
        .expect_err("window over one hour is refused");
    assert!(
        matches!(&error, IngestError::Rejected(message) if message.contains("one hour")),
        "unexpected refusal: {error:?}"
    );
    assert_eq!(
        stored_rows(&pool, tenant.community(), &long).await,
        (false, false)
    );

    // Without jobs:write the CI gate never opens.
    let unscoped = signed(&owner, channel, &envelope(&owner, now + 1, 900));
    let auth = IngestAuth::Nip42 {
        pubkey: unscoped.pubkey,
        scopes: vec![Scope::MessagesWrite],
        channel_ids: None,
        conn_id: Uuid::new_v4(),
    };
    let error = match ingest_event(&state, &tenant, unscoped.clone(), auth).await {
        Ok(_) => panic!("scope is enforced"),
        Err(error) => error,
    };
    assert!(
        matches!(&error, IngestError::AuthFailed(message) if message.contains("jobs:write")),
        "unexpected refusal: {error:?}"
    );
    assert_eq!(
        stored_rows(&pool, tenant.community(), &unscoped).await,
        (false, false)
    );
}

#[tokio::test]
#[ignore = "requires Postgres"]
async fn merge_bypass_storage_consumes_once_against_an_allowing_decision() {
    let pool = pool().await;
    let tenant = community(&pool).await;
    let community = tenant.community();
    let owner = Keys::generate();
    let channel = Uuid::new_v4();
    sqlx::query("INSERT INTO channels (community_id,id,name,created_by) VALUES ($1,$2,$3,$4)")
        .bind(community.as_uuid())
        .bind(channel)
        .bind("buzz")
        .bind(owner.public_key().to_bytes().to_vec())
        .execute(&pool)
        .await
        .expect("channel");
    let now = now_seconds();
    let envelope = envelope(&owner, now - 60, 600);
    let event = signed(&owner, channel, &envelope);
    let issuer = owner.public_key().to_hex();

    assert!(insert_ci_merge_bypass(
        &pool,
        community,
        channel,
        event.id.as_bytes(),
        &issuer,
        &envelope
    )
    .await
    .expect("insert bypass"));
    assert!(!insert_ci_merge_bypass(
        &pool,
        community,
        channel,
        event.id.as_bytes(),
        &issuer,
        &envelope
    )
    .await
    .expect("replay insert"));

    let lookup = |old: String, new: String| {
        let repo = envelope.target_repo_a.clone();
        let pool = pool.clone();
        async move {
            list_ci_merge_bypasses(&pool, community, &repo, "refs/heads/main", &old, &new)
                .await
                .expect("list")
        }
    };
    let rows = lookup("a".repeat(40), "b".repeat(40)).await;
    assert_eq!(rows.len(), 1);
    assert!(rows[0].is_usable_at(chrono::Utc::now()));
    assert!(!rows[0].is_usable_at(chrono::Utc::now() + chrono::Duration::seconds(600)));
    // Only the exact update matches.
    assert!(lookup("b".repeat(40), "a".repeat(40)).await.is_empty());
    assert!(lookup("a".repeat(40), "c".repeat(40)).await.is_empty());

    // The consuming decision row (written by the gate in D2; raw here).
    let decision: Uuid = sqlx::query_scalar(
        "INSERT INTO git_merge_gate_decisions \
         (community_id, target_repo_a, ref_name, old_oid, new_oid, candidate_oid, \
          classification, code, mode, pusher, bypass_event_id) \
         VALUES ($1, $2, 'refs/heads/main', $3, $4, $4, 'fast_forward', 'allow', 'enforce', $5, $6) \
         RETURNING id",
    )
    .bind(community.as_uuid())
    .bind(&envelope.target_repo_a)
    .bind("a".repeat(40))
    .bind("b".repeat(40))
    .bind(&issuer)
    .bind(event.id.as_bytes().to_vec())
    .fetch_one(&pool)
    .await
    .expect("decision row");

    // Consumed once; the second call changes nothing.
    assert!(
        consume_ci_merge_bypass(&pool, community, event.id.as_bytes(), decision)
            .await
            .expect("consume")
    );
    assert!(
        !consume_ci_merge_bypass(&pool, community, event.id.as_bytes(), decision)
            .await
            .expect("second consume")
    );
    let rows = lookup("a".repeat(40), "b".repeat(40)).await;
    assert_eq!(rows[0].consumed_by, Some(decision));
    assert!(!rows[0].is_usable_at(chrono::Utc::now()));

    // A foreign community cannot consume it, and a decision of another
    // community cannot be named (foreign key leads with community_id).
    let foreign = community_id_of(&pool).await;
    assert!(
        !consume_ci_merge_bypass(&pool, foreign, event.id.as_bytes(), decision)
            .await
            .expect("foreign consume is a no-op")
    );
    let other_envelope = CiMergeBypassEnvelope {
        new_oid: "c".repeat(40),
        ..envelope.clone()
    };
    let other = signed(&owner, channel, &other_envelope);
    assert!(insert_ci_merge_bypass(
        &pool,
        community,
        channel,
        other.id.as_bytes(),
        &issuer,
        &other_envelope
    )
    .await
    .expect("insert other"));
    let foreign_decision = Uuid::new_v4();
    assert!(
        consume_ci_merge_bypass(&pool, community, other.id.as_bytes(), foreign_decision)
            .await
            .is_err(),
        "an unknown decision row is refused by the foreign key"
    );

    // Decisions are append-only.
    let update = sqlx::query("UPDATE git_merge_gate_decisions SET code='refuse' WHERE id=$1")
        .bind(decision)
        .execute(&pool)
        .await;
    assert!(update.is_err(), "decision rows must not be updated");
    let delete = sqlx::query("DELETE FROM git_merge_gate_decisions WHERE id=$1")
        .bind(decision)
        .execute(&pool)
        .await;
    assert!(delete.is_err(), "decision rows must not be deleted");
}

async fn community_id_of(pool: &PgPool) -> CommunityId {
    community(pool).await.community()
}
