//! In-process channel-admin regressions using only a disposable Postgres fixture.
//! No relay server, live credentials, or Redis server is used.
//!
//! Set RELAY_AUTH_TEST_DATABASE_URL to a migrated disposable database and
//! BUZZ_GIT_REPO_PATH / BUZZ_GIT_PACK_CACHE_PATH to fixture directories, then:
//! cargo test -p buzz-test-client --test regression_channel_admin_bridge -- --ignored

use std::sync::Arc;

use buzz_core::tenant::{CommunityId, TenantContext};
use buzz_db::channel::{ChannelType, ChannelVisibility, MemberRole};
use buzz_relay::handlers::ingest::{ingest_event, HttpAuthMethod, IngestAuth};
use buzz_relay::AppState;
use nostr::{Event, EventBuilder, Keys, Kind, Tag};
use uuid::Uuid;

async fn fixture() -> (Arc<AppState>, sqlx::PgPool) {
    let url = std::env::var("RELAY_AUTH_TEST_DATABASE_URL").expect("isolated fixture URL");
    let parsed = url::Url::parse(&url).unwrap();
    assert_eq!(
        parsed.host_str(),
        Some("127.0.0.1"),
        "fixture must be loopback"
    );
    assert!(
        parsed.path().ends_with("_fixture"),
        "fixture database required"
    );
    assert!(std::env::var_os("BUZZ_GIT_REPO_PATH").is_some());
    assert!(std::env::var_os("BUZZ_GIT_PACK_CACHE_PATH").is_some());
    let mut config = buzz_relay::Config::from_env().unwrap();
    config.database_url = url.clone();
    config.require_relay_membership = false;
    config.redis_url = "redis://127.0.0.1:1".into();
    let pool = sqlx::PgPool::connect(&url).await.unwrap();
    let db = buzz_db::Db::from_pool(pool.clone());
    let redis_pool = deadpool_redis::Config::from_url(&config.redis_url)
        .create_pool(Some(deadpool_redis::Runtime::Tokio1))
        .unwrap();
    let pubsub = Arc::new(
        buzz_pubsub::PubSubManager::new(&config.redis_url, redis_pool.clone())
            .await
            .unwrap(),
    );
    let auth = buzz_auth::AuthService::new(config.auth.clone());
    let search = buzz_search::SearchService::new(pool.clone());
    let workflows = Arc::new(buzz_workflow::WorkflowEngine::new(
        db.clone(),
        Default::default(),
    ));
    let media = buzz_media::MediaStorage::new(&config.media).unwrap();
    let (state, _) = AppState::new(
        config,
        db,
        redis_pool,
        None,
        pubsub,
        auth,
        search,
        workflows,
        Keys::generate(),
        media,
    );
    (Arc::new(state), pool)
}

async fn community(
    state: &AppState,
    pool: &sqlx::PgPool,
    principals: &[(&Keys, &str)],
) -> TenantContext {
    let id = Uuid::new_v4();
    let host = format!("channel-admin-{id}.invalid");
    sqlx::query("INSERT INTO communities (id, host) VALUES ($1, $2)")
        .bind(id)
        .bind(&host)
        .execute(pool)
        .await
        .unwrap();
    let community = CommunityId::from_uuid(id);
    state
        .db
        .ensure_user(community, state.relay_keypair.public_key().as_bytes())
        .await
        .unwrap();
    for (keys, role) in principals {
        state
            .db
            .ensure_user(community, keys.public_key().as_bytes())
            .await
            .unwrap();
        state
            .db
            .add_relay_member(community, &keys.public_key().to_hex(), role, None)
            .await
            .unwrap();
    }
    TenantContext::resolved(community, host)
}

fn command(keys: &Keys, kind: u16, channel: Uuid, tags: Vec<Tag>) -> Event {
    EventBuilder::new(Kind::Custom(kind), "")
        .tags([
            Tag::parse(["h", &channel.to_string()]).unwrap(),
            Tag::parse(["nonce", &Uuid::new_v4().to_string()]).unwrap(),
        ])
        .tags(tags)
        .sign_with_keys(keys)
        .unwrap()
}

fn target(keys: &Keys) -> Tag {
    Tag::parse(["p", &keys.public_key().to_hex()]).unwrap()
}

async fn submit(state: &Arc<AppState>, tenant: &TenantContext, event: Event) -> Result<(), String> {
    let auth = IngestAuth::Http {
        pubkey: event.pubkey,
        scopes: buzz_auth::Scope::all_known(),
        auth_method: HttpAuthMethod::Nip98,
    };
    Box::pin(ingest_event(state, tenant, event, auth))
        .await
        .map(|_| ())
        .map_err(|e| format!("{e:?}"))
}

#[tokio::test]
#[ignore = "requires disposable migrated Postgres fixture"]
async fn community_admin_commands_preserve_tenant_owner_delegation_and_audit_guards() {
    let (state, pool) = fixture().await;
    let owner = Keys::generate();
    let channel_owner = Keys::generate();
    let admin = Keys::generate();
    let member = Keys::generate();
    let invited = Keys::generate();
    let delegate = Keys::generate();
    let tenant = community(
        &state,
        &pool,
        &[
            (&owner, "owner"),
            (&admin, "admin"),
            (&channel_owner, "member"),
            (&member, "member"),
            (&invited, "member"),
            (&delegate, "member"),
        ],
    )
    .await;
    let c = state
        .db
        .create_channel(
            tenant.community(),
            "fixture",
            ChannelType::Stream,
            ChannelVisibility::Private,
            None,
            channel_owner.public_key().as_bytes(),
            None,
        )
        .await
        .unwrap();
    state
        .db
        .add_member(
            tenant.community(),
            c.id,
            member.public_key().as_bytes(),
            MemberRole::Member,
            Some(channel_owner.public_key().as_bytes()),
        )
        .await
        .unwrap();
    assert!(!state
        .db
        .is_member(tenant.community(), c.id, admin.public_key().as_bytes())
        .await
        .unwrap());

    let owned = state
        .db
        .create_channel(
            tenant.community(),
            "admin-owned",
            ChannelType::Stream,
            ChannelVisibility::Private,
            None,
            channel_owner.public_key().as_bytes(),
            None,
        )
        .await
        .unwrap();
    sqlx::query("UPDATE relay_members SET role='admin' WHERE community_id=$1 AND pubkey=$2")
        .bind(tenant.community().as_uuid())
        .bind(channel_owner.public_key().to_hex())
        .execute(&pool)
        .await
        .unwrap();
    submit(
        &state,
        &tenant,
        command(&channel_owner, 9008, owned.id, vec![]),
    )
    .await
    .unwrap();
    assert!(state
        .db
        .get_channel(tenant.community(), owned.id)
        .await
        .is_err());
    sqlx::query("UPDATE relay_members SET role='member' WHERE community_id=$1 AND pubkey=$2")
        .bind(tenant.community().as_uuid())
        .bind(channel_owner.public_key().to_hex())
        .execute(&pool)
        .await
        .unwrap();

    for event in [
        command(&member, 9001, c.id, vec![target(&channel_owner)]),
        command(
            &member,
            9002,
            c.id,
            vec![Tag::parse(["name", "denied"]).unwrap()],
        ),
        command(&admin, 9001, c.id, vec![target(&channel_owner)]),
        command(&owner, 9001, c.id, vec![target(&channel_owner)]),
        command(&admin, 9008, c.id, vec![]),
    ] {
        assert!(submit(&state, &tenant, event).await.is_err());
    }
    let tenant_b = community(
        &state,
        &pool,
        &[(&owner, "owner"), (&admin, "member"), (&member, "member")],
    )
    .await;
    let b = state
        .db
        .create_channel(
            tenant_b.community(),
            "other",
            ChannelType::Stream,
            ChannelVisibility::Private,
            None,
            owner.public_key().as_bytes(),
            None,
        )
        .await
        .unwrap();
    assert!(submit(
        &state,
        &tenant_b,
        command(
            &admin,
            9002,
            b.id,
            vec![Tag::parse(["name", "cross-tenant"]).unwrap()]
        )
    )
    .await
    .is_err());
    assert!(submit(
        &state,
        &tenant,
        command(
            &admin,
            9002,
            b.id,
            vec![Tag::parse(["name", "wrong-channel"]).unwrap()]
        )
    )
    .await
    .is_err());

    submit(
        &state,
        &tenant,
        command(&admin, 9000, c.id, vec![target(&invited)]),
    )
    .await
    .unwrap();
    assert!(state
        .db
        .is_member(tenant.community(), c.id, invited.public_key().as_bytes())
        .await
        .unwrap());
    submit(
        &state,
        &tenant,
        command(&admin, 9001, c.id, vec![target(&invited)]),
    )
    .await
    .unwrap();
    assert!(!state
        .db
        .is_member(tenant.community(), c.id, invited.public_key().as_bytes())
        .await
        .unwrap());
    submit(
        &state,
        &tenant,
        command(
            &admin,
            9002,
            c.id,
            vec![Tag::parse(["name", "renamed"]).unwrap()],
        ),
    )
    .await
    .unwrap();
    assert_eq!(
        state
            .db
            .get_channel(tenant.community(), c.id)
            .await
            .unwrap()
            .name,
        "renamed"
    );

    // The audit store is required, not best-effort. A rejected audit insert
    // must leave both the channel and the signed command out of storage.
    sqlx::query("ALTER TABLE moderation_actions ADD CONSTRAINT fixture_audit_failure CHECK (action <> 'edit_metadata') NOT VALID")
        .execute(&pool).await.unwrap();
    let unaudited = command(
        &admin,
        9002,
        c.id,
        vec![Tag::parse(["name", "unaudited"]).unwrap()],
    );
    let unaudited_id = unaudited.id;
    let denied = submit(&state, &tenant, unaudited).await;
    sqlx::query("ALTER TABLE moderation_actions DROP CONSTRAINT fixture_audit_failure")
        .execute(&pool)
        .await
        .unwrap();
    assert!(denied.is_err(), "audit failure must reject the command");
    assert_eq!(
        state
            .db
            .get_channel(tenant.community(), c.id)
            .await
            .unwrap()
            .name,
        "renamed"
    );
    assert!(state
        .db
        .get_event_by_id(tenant.community(), unaudited_id.as_bytes())
        .await
        .unwrap()
        .is_none());

    let message = EventBuilder::new(Kind::Custom(9), "synthetic message")
        .tags([Tag::parse(["h", &c.id.to_string()]).unwrap()])
        .sign_with_keys(&member)
        .unwrap();
    state
        .db
        .insert_event(tenant.community(), &message, Some(c.id))
        .await
        .unwrap();
    let delete = command(
        &admin,
        9005,
        c.id,
        vec![Tag::parse(["e", &message.id.to_hex()]).unwrap()],
    );
    submit(&state, &tenant, delete).await.unwrap();
    assert!(state
        .db
        .get_event_by_id(tenant.community(), message.id.as_bytes())
        .await
        .unwrap()
        .is_none());

    state
        .db
        .set_agent_owner(
            tenant.community(),
            delegate.public_key().as_bytes(),
            owner.public_key().as_bytes(),
        )
        .await
        .unwrap();
    assert!(
        submit(
            &state,
            &tenant,
            command(&delegate, 9001, c.id, vec![target(&member)])
        )
        .await
        .is_err(),
        "durable ownership alone grants no authority"
    );
    let wrong_kind =
        buzz_sdk::nip_oa::compute_auth_tag(&owner, &delegate.public_key(), "kind=9002").unwrap();
    assert!(submit(
        &state,
        &tenant,
        command(
            &delegate,
            9001,
            c.id,
            vec![
                target(&member),
                buzz_sdk::nip_oa::parse_auth_tag(&wrong_kind).unwrap()
            ]
        )
    )
    .await
    .is_err());
    let grant =
        buzz_sdk::nip_oa::compute_auth_tag(&owner, &delegate.public_key(), "kind=9001").unwrap();
    submit(
        &state,
        &tenant,
        command(
            &delegate,
            9001,
            c.id,
            vec![
                target(&member),
                buzz_sdk::nip_oa::parse_auth_tag(&grant).unwrap(),
            ],
        ),
    )
    .await
    .unwrap();
    assert!(!state
        .db
        .is_member(tenant.community(), c.id, member.public_key().as_bytes())
        .await
        .unwrap());
    let delegated_audit: i64 = sqlx::query_scalar("SELECT count(*) FROM moderation_actions WHERE community_id=$1 AND actor_pubkey=$2 AND action='kick' AND matched_principal='owner'")
        .bind(tenant.community().as_uuid()).bind(delegate.public_key().as_bytes().to_vec()).fetch_one(&pool).await.unwrap();
    assert_eq!(delegated_audit, 1);
    // Revoking the owner's community role or restricting that owner must
    // remove the delegated seat's authority even though its mapping remains.
    submit(
        &state,
        &tenant,
        command(&owner, 9000, c.id, vec![target(&member)]),
    )
    .await
    .unwrap();
    sqlx::query("UPDATE relay_members SET role='member' WHERE community_id=$1 AND pubkey=$2")
        .bind(tenant.community().as_uuid())
        .bind(owner.public_key().to_hex())
        .execute(&pool)
        .await
        .unwrap();
    let revoked = command(
        &delegate,
        9001,
        c.id,
        vec![
            target(&member),
            buzz_sdk::nip_oa::parse_auth_tag(&grant).unwrap(),
        ],
    );
    assert!(submit(&state, &tenant, revoked).await.is_err());
    sqlx::query("UPDATE relay_members SET role='owner' WHERE community_id=$1 AND pubkey=$2")
        .bind(tenant.community().as_uuid())
        .bind(owner.public_key().to_hex())
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO community_bans (community_id, pubkey, banned, actor_pubkey) VALUES ($1,$2,true,$2)")
        .bind(tenant.community().as_uuid()).bind(owner.public_key().as_bytes().to_vec()).execute(&pool).await.unwrap();
    let restricted = command(
        &delegate,
        9001,
        c.id,
        vec![
            target(&member),
            buzz_sdk::nip_oa::parse_auth_tag(&grant).unwrap(),
        ],
    );
    assert!(submit(&state, &tenant, restricted).await.is_err());
    sqlx::query("DELETE FROM community_bans WHERE community_id=$1 AND pubkey=$2")
        .bind(tenant.community().as_uuid())
        .bind(owner.public_key().as_bytes().to_vec())
        .execute(&pool)
        .await
        .unwrap();
    assert!(state
        .db
        .is_member(tenant.community(), c.id, member.public_key().as_bytes())
        .await
        .unwrap());
    submit(&state, &tenant, command(&owner, 9008, c.id, vec![]))
        .await
        .unwrap();
    assert!(
        state
            .db
            .get_channel(tenant.community(), c.id)
            .await
            .is_err(),
        "channel deletion must execute"
    );
    for action in [
        "add_member",
        "kick",
        "edit_metadata",
        "delete_message",
        "delete_channel",
    ] {
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM moderation_actions WHERE community_id=$1 AND action=$2",
        )
        .bind(tenant.community().as_uuid())
        .bind(action)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(count > 0, "missing audit for {action}");
    }
    let foreign_audit: i64 =
        sqlx::query_scalar("SELECT count(*) FROM moderation_actions WHERE community_id=$1")
            .bind(tenant_b.community().as_uuid())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(foreign_audit, 0);
}
