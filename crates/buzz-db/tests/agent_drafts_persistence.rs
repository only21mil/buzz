//! Run only against a disposable fenced PostgreSQL fixture, never a live URL.
use buzz_core::{
    filter::reader_authorized_for_event,
    kind::{KIND_AGENT_DRAFT, KIND_AGENT_DRAFT_DECISION},
    CommunityId,
};
use buzz_db::{event::EventQuery, Db, DbError};
use nostr::{nips::nip44, Event, EventBuilder, Keys, Kind, SecretKey, Tag, Timestamp};
use serde_json::json;
use sqlx::{
    postgres::{PgPool, PgPoolOptions},
    Row,
};
use uuid::Uuid;

const STAMP: u64 = 1_788_800_000;
fn keys(byte: u8) -> Keys {
    Keys::new(SecretKey::from_slice(&[byte; 32]).unwrap())
}
fn sign(keys: &Keys, kind: u32, tags: Vec<Vec<String>>, content: String, stamp: u64) -> Event {
    EventBuilder::new(Kind::Custom(kind as u16), content)
        .allow_self_tagging()
        .tags(tags.into_iter().map(|t| Tag::parse(t).unwrap()))
        .custom_created_at(Timestamp::from(stamp))
        .sign_with_keys(keys)
        .unwrap()
}
fn encrypt(sender: &Keys, owner: &Keys, payload: serde_json::Value) -> String {
    nip44::encrypt(
        sender.secret_key(),
        &owner.public_key(),
        payload.to_string(),
        nip44::Version::V2,
    )
    .unwrap()
}
fn request(owner: &Keys, agent: &Keys, id: Uuid, channel: Uuid, prompt: &str) -> Event {
    sign(
        agent,
        KIND_AGENT_DRAFT,
        vec![
            vec!["p".into(), owner.public_key().to_hex()],
            vec!["agent".into(), agent.public_key().to_hex()],
            vec!["r".into(), id.to_string()],
            vec!["h".into(), channel.to_string()],
            vec!["v".into(), "1".into()],
        ],
        encrypt(
            agent,
            owner,
            json!({"version":1,"request_id":id,"channel_id":channel,"system_prompt":prompt}),
        ),
        STAMP,
    )
}
fn decision(
    owner: &Keys,
    request: &Event,
    previous: &Event,
    generation: u64,
    state: &str,
    device: &str,
    stamp: u64,
) -> Event {
    sign(
        owner,
        KIND_AGENT_DRAFT_DECISION,
        vec![
            vec!["p".into(), owner.public_key().to_hex()],
            vec!["e".into(), request.id.to_hex()],
            vec!["previous".into(), previous.id.to_hex()],
            vec!["generation".into(), generation.to_string()],
            vec!["state".into(), state.into()],
            vec!["v".into(), "1".into()],
        ],
        encrypt(
            owner,
            owner,
            json!({"version":1,"device_id":device,"operation_id":device,"request_event_id":request.id,"action":"save_definition"}),
        ),
        stamp,
    )
}
struct Fixture {
    db: Db,
    pool: PgPool,
    community: CommunityId,
    owner: Keys,
    agent: Keys,
    channel: Uuid,
    url: String,
}
impl Fixture {
    async fn new() -> Self {
        let url = std::env::var("BUZZ_TEST_DATABASE_URL")
            .expect("explicit disposable fixture URL required");
        let parsed = url::Url::parse(&url).unwrap();
        assert_eq!(
            parsed.host_str(),
            Some("buzz-test.invalid"),
            "refusing non-fixture database host"
        );
        assert!(
            parsed.path().starts_with("/buzz_nt_"),
            "refusing non-fixture database name"
        );
        assert!(
            parsed
                .query_pairs()
                .any(|(k, v)| k == "host" && v.starts_with("/work/")),
            "fixture must use private namespace socket"
        );
        let pool = PgPoolOptions::new()
            .max_connections(6)
            .connect(&url)
            .await
            .unwrap();
        buzz_db::migration::run_migrations(&pool).await.unwrap();
        let community = CommunityId::from_uuid(Uuid::new_v4());
        sqlx::query("INSERT INTO communities(id,host) VALUES($1,$2)")
            .bind(community.as_uuid())
            .bind(format!("draft-{}.test", community.as_uuid()))
            .execute(&pool)
            .await
            .unwrap();
        Self {
            db: Db::from_pool(pool.clone()),
            pool,
            community,
            owner: keys(1),
            agent: keys(2),
            channel: Uuid::from_u128(9),
            url,
        }
    }
    fn request(&self, id: u128, prompt: &str) -> Event {
        request(
            &self.owner,
            &self.agent,
            Uuid::from_u128(id),
            self.channel,
            prompt,
        )
    }
    async fn store(&self, event: &Event) -> bool {
        self.db
            .store_agent_draft(self.community, event)
            .await
            .unwrap()
            .1
    }
    async fn head(&self, event: &Event) -> (Vec<u8>, i64, String) {
        sqlx::query_as("SELECT head_event_id,generation,state FROM agent_drafts WHERE community_id=$1 AND request_event_id=$2")
            .bind(self.community.as_uuid()).bind(event.id.as_bytes().as_slice()).fetch_one(&self.pool).await.unwrap()
    }
    fn query(&self, owner: &Keys) -> EventQuery {
        let mut q = EventQuery::for_community(self.community);
        q.kinds = Some(vec![
            KIND_AGENT_DRAFT as i32,
            KIND_AGENT_DRAFT_DECISION as i32,
        ]);
        q.p_tag_hex = Some(owner.public_key().to_hex());
        q
    }
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL fixture"]
async fn identical_signed_retry_survives_reconnect_and_uuid_conflict_is_atomic() {
    let f = Fixture::new().await;
    let req = f.request(1, "PRIVATE_DRAFT_SENTINEL");
    assert!(f.store(&req).await);
    assert!(!f.store(&req).await);
    let replacement = f.request(1, "CHANGED_PRIVATE_DRAFT");
    assert_ne!(replacement.id, req.id);
    assert!(matches!(
        f.db.store_agent_draft(f.community, &replacement).await,
        Err(DbError::Conflict(_))
    ));
    let rerouted = request(
        &f.owner,
        &f.agent,
        Uuid::from_u128(1),
        Uuid::from_u128(999),
        "PRIVATE_DRAFT_SENTINEL",
    );
    assert!(
        matches!(
            f.db.store_agent_draft(f.community, &rerouted).await,
            Err(DbError::Conflict(_))
        ),
        "same request UUID cannot acquire a different channel binding"
    );
    let row=sqlx::query("SELECT (SELECT count(*) FROM agent_drafts WHERE community_id=$1) AS drafts,(SELECT count(*) FROM events WHERE community_id=$1) AS events,(SELECT count(*) FROM event_mentions WHERE community_id=$1) AS mentions")
        .bind(f.community.as_uuid()).fetch_one(&f.pool).await.unwrap();
    for column in ["drafts", "events", "mentions"] {
        assert_eq!(row.get::<i64, _>(column), 1, "{column}");
    }
    f.pool.close().await;
    let pool = PgPoolOptions::new().connect(&f.url).await.unwrap();
    let db = Db::from_pool(pool.clone());
    let events = db.query_events(&f.query(&f.owner)).await.unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].event, req,
        "all signed bytes survive connection restart"
    );
    events[0].event.verify().unwrap();
    assert!(!db.store_agent_draft(f.community, &req).await.unwrap().1);
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL fixture"]
async fn concurrent_devices_same_owner_same_clock_have_one_claim_and_no_takeover() {
    let f = Fixture::new().await;
    let req = f.request(2, "private");
    f.store(&req).await;
    let first = decision(&f.owner, &req, &req, 1, "applying", "device-a", STAMP);
    let second = decision(&f.owner, &req, &req, 1, "applying", "device-b", STAMP);
    assert_ne!(
        first.id, second.id,
        "devices must retain distinct signed claims"
    );
    let (a, b) = tokio::join!(
        f.db.store_agent_draft(f.community, &first),
        f.db.store_agent_draft(f.community, &second)
    );
    let (winner, loser) = match (a, b) {
        (Ok((_, true)), Err(DbError::Conflict(_))) => (&first, &second),
        (Err(DbError::Conflict(_)), Ok((_, true))) => (&second, &first),
        other => panic!("exactly one claim must commit: {other:?}"),
    };
    assert_eq!(
        f.head(&req).await,
        (winner.id.as_bytes().to_vec(), 1, "applying".into())
    );
    let stolen = decision(
        &f.owner,
        &req,
        &req,
        1,
        "applying",
        "device-after-clock-jump",
        STAMP + 86400,
    );
    assert!(matches!(
        f.db.store_agent_draft(f.community, &stolen).await,
        Err(DbError::Conflict(_))
    ));
    let wrong_predecessor = decision(&f.owner, &req, loser, 2, "applied", "losing-device", STAMP);
    assert!(matches!(
        f.db.store_agent_draft(f.community, &wrong_predecessor)
            .await,
        Err(DbError::Conflict(_))
    ));
    let applied = decision(
        &f.owner,
        &req,
        winner,
        2,
        "applied",
        "winning-device",
        STAMP,
    );
    assert!(f.store(&applied).await);
    assert!(
        !f.store(winner).await,
        "claim retry stays idempotent after terminal outcome"
    );
    assert!(!f.store(&applied).await);
    assert_eq!(
        f.head(&req).await,
        (applied.id.as_bytes().to_vec(), 2, "applied".into())
    );
    assert_eq!(f.db.count_events(&f.query(&f.owner)).await.unwrap(), 3);
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL fixture"]
async fn rejected_tombstone_blocks_replay_and_newer_clock_approval() {
    let f = Fixture::new().await;
    let req = f.request(3, "reject me");
    f.store(&req).await;
    let reject = decision(&f.owner, &req, &req, 1, "rejected", "device-a", STAMP);
    assert!(f.store(&reject).await);
    assert!(!f.store(&req).await);
    assert!(!f.store(&reject).await);
    for (generation, previous) in [(1, &req), (2, &reject)] {
        let attempted = decision(
            &f.owner,
            &req,
            previous,
            generation,
            "applying",
            "newer-clock",
            STAMP + 86400,
        );
        assert!(matches!(
            f.db.store_agent_draft(f.community, &attempted).await,
            Err(DbError::Conflict(_))
        ));
    }
    assert_eq!(
        f.head(&req).await,
        (reject.id.as_bytes().to_vec(), 1, "rejected".into())
    );
    assert_eq!(f.db.count_events(&f.query(&f.owner)).await.unwrap(), 2);
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL fixture"]
async fn forged_wrong_owner_wrong_community_and_wrong_request_decisions_never_mutate() {
    let f = Fixture::new().await;
    let req = f.request(4, "original");
    f.store(&req).await;
    let stranger = keys(3);
    let wrong_owner = decision(&stranger, &req, &req, 1, "rejected", "stranger", STAMP);
    assert!(matches!(
        f.db.store_agent_draft(f.community, &wrong_owner).await,
        Err(DbError::AccessDenied(_))
    ));
    let other_request = f.request(5, "not stored");
    let wrong_route = decision(
        &f.owner,
        &other_request,
        &req,
        1,
        "rejected",
        "owner",
        STAMP,
    );
    assert!(matches!(
        f.db.store_agent_draft(f.community, &wrong_route).await,
        Err(DbError::AccessDenied(_))
    ));
    let valid = decision(&f.owner, &req, &req, 1, "rejected", "owner", STAMP);
    assert!(matches!(
        f.db.store_agent_draft(CommunityId::from_uuid(Uuid::new_v4()), &valid)
            .await,
        Err(DbError::AccessDenied(_))
    ));
    let mut forged = valid;
    forged.content = encrypt(&f.owner, &f.owner, json!({"forged":true}));
    assert!(matches!(
        f.db.store_agent_draft(f.community, &forged).await,
        Err(DbError::InvalidData(_))
    ));
    let mut forged_request = f.request(6, "new");
    forged_request.content = f.request(6, "changed").content;
    assert!(matches!(
        f.db.store_agent_draft(f.community, &forged_request).await,
        Err(DbError::InvalidData(_))
    ));
    assert_eq!(
        f.head(&req).await,
        (req.id.as_bytes().to_vec(), 0, "pending".into())
    );
    assert_eq!(f.db.count_events(&f.query(&f.owner)).await.unwrap(), 1);
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL fixture"]
async fn owner_pages_counts_ids_result_gate_and_search_keep_private_history() {
    let f = Fixture::new().await;
    let other_owner = keys(3);
    let mut expected = Vec::new();
    for index in 100..109 {
        let req = f.request(index, "PRIVATE_DRAFT_SENTINEL");
        f.store(&req).await;
        expected.push(req.id);
    }
    let other = request(
        &other_owner,
        &f.agent,
        Uuid::from_u128(100),
        f.channel,
        "OTHER_OWNER_PRIVATE",
    );
    f.store(&other).await;
    let q = f.query(&f.owner);
    assert_eq!(f.db.count_events(&q).await.unwrap(), 9);
    assert_eq!(f.db.count_events(&f.query(&other_owner)).await.unwrap(), 1);
    assert_eq!(f.db.count_events(&f.query(&keys(4))).await.unwrap(), 0);
    let mut page = q.clone();
    page.limit = Some(2);
    let mut seen = Vec::new();
    loop {
        let events = f.db.query_events(&page).await.unwrap();
        if events.is_empty() {
            break;
        }
        for stored in &events {
            assert!(reader_authorized_for_event(
                &stored.event,
                &f.owner.public_key().to_hex()
            ));
            assert!(!reader_authorized_for_event(
                &stored.event,
                &f.agent.public_key().to_hex()
            ));
            assert!(!serde_json::to_string(&stored.event)
                .unwrap()
                .contains("PRIVATE_DRAFT_SENTINEL"));
            seen.push(stored.event.id);
        }
        let last = &events.last().unwrap().event;
        page.until =
            Some(chrono::DateTime::from_timestamp(last.created_at.as_secs() as i64, 0).unwrap());
        page.before_id = Some(last.id.as_bytes().to_vec());
    }
    seen.sort();
    expected.sort();
    assert_eq!(seen, expected, "same-clock keyset pages lose no requests");
    let mut ids = EventQuery::for_community(f.community);
    ids.ids = Some(expected.iter().map(|id| id.as_bytes().to_vec()).collect());
    let raw = f.db.query_events(&ids).await.unwrap();
    assert_eq!(raw.len(), 9);
    assert_eq!(
        raw.iter()
            .filter(|e| reader_authorized_for_event(&e.event, &other_owner.public_key().to_hex()))
            .count(),
        0,
        "COUNT fallback must authorize every IDs-only result"
    );
    ids.community_id = CommunityId::from_uuid(Uuid::new_v4());
    assert!(f.db.query_events(&ids).await.unwrap().is_empty());
    assert_eq!(f.db.count_events(&ids).await.unwrap(), 0);
    let searchable: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM events WHERE community_id=$1 AND search_tsv IS NOT NULL",
    )
    .bind(f.community.as_uuid())
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(
        searchable, 0,
        "ciphertext must not create any search lexemes"
    );
    let found:i64=sqlx::query_scalar("SELECT count(*) FROM events WHERE community_id=$1 AND search_tsv @@ plainto_tsquery('simple','PRIVATE_DRAFT_SENTINEL')").bind(f.community.as_uuid()).fetch_one(&f.pool).await.unwrap();
    assert_eq!(found, 0);
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL fixture"]
async fn event_write_failure_rolls_back_request_identity_and_decision_head() {
    let f = Fixture::new().await;
    let req = f.request(7, "original");
    f.store(&req).await;
    // Fault the real INSERT after sidecar/CAS work. Local fixture DDL is scoped by community.
    let function = format!("draft_fault_{}", f.community.as_uuid().simple());
    let ddl=format!("CREATE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.community_id='{}'::uuid THEN RAISE EXCEPTION 'draft fixture insert failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER {function} BEFORE INSERT ON events FOR EACH ROW EXECUTE FUNCTION {function}()",f.community.as_uuid());
    // Both interpolated values are typed UUIDs; no caller-provided SQL text enters DDL.
    sqlx::raw_sql(sqlx::AssertSqlSafe(ddl))
        .execute(&f.pool)
        .await
        .unwrap();
    let next = f.request(8, "fails after UUID reservation");
    assert!(f.db.store_agent_draft(f.community, &next).await.is_err());
    let reject = decision(&f.owner, &req, &req, 1, "rejected", "owner", STAMP);
    assert!(f.db.store_agent_draft(f.community, &reject).await.is_err());
    assert_eq!(
        f.head(&req).await,
        (req.id.as_bytes().to_vec(), 0, "pending".into())
    );
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM agent_drafts WHERE community_id=$1")
        .bind(f.community.as_uuid())
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(rows, 1);
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "DROP TRIGGER {function} ON events; DROP FUNCTION {function}()"
    )))
    .execute(&f.pool)
    .await
    .unwrap();
    assert!(
        f.store(&next).await,
        "rollback releases UUID for an exact retry"
    );
    assert!(f.store(&reject).await);
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL fixture with server restart checkpoint"]
async fn postgres_process_restart_retains_signed_pending_and_rejected_history() {
    let checkpoint = std::env::var("BUZZ_DRAFT_CHECKPOINT").expect("owned fixture checkpoint path");
    assert!(checkpoint.starts_with("/work/"));
    if std::env::var("BUZZ_DRAFT_RESTART_PHASE").as_deref() == Ok("read") {
        let (community, events): (Uuid, Vec<Event>) =
            serde_json::from_slice(&std::fs::read(checkpoint).unwrap()).unwrap();
        let url = std::env::var("BUZZ_TEST_DATABASE_URL").unwrap();
        let pool = PgPoolOptions::new().connect(&url).await.unwrap();
        let db = Db::from_pool(pool.clone());
        let community = CommunityId::from_uuid(community);
        // Inspect durable state before any replay can recreate a missing sidecar.
        for (request, head, generation, state) in [
            (&events[0], &events[0], 0_i64, "pending"),
            (&events[1], &events[2], 1_i64, "rejected"),
        ] {
            let actual: (Vec<u8>, i64, String) = sqlx::query_as(
                "SELECT head_event_id,generation,state FROM agent_drafts WHERE community_id=$1 AND request_event_id=$2",
            ).bind(community.as_uuid()).bind(request.id.as_bytes().as_slice())
                .fetch_one(&pool).await.unwrap();
            assert_eq!(
                actual,
                (head.id.as_bytes().to_vec(), generation, state.into())
            );
        }
        let searchable: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM events WHERE community_id=$1 AND search_tsv IS NOT NULL",
        )
        .bind(community.as_uuid())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            searchable, 0,
            "requests and terminal outcomes remain unsearchable after restart"
        );
        for expected in &events {
            let restored = db
                .get_event_by_id(community, expected.id.as_bytes())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(restored.event, *expected);
            restored.event.verify().unwrap();
            assert!(reader_authorized_for_event(
                &restored.event,
                &keys(1).public_key().to_hex()
            ));
            assert!(!reader_authorized_for_event(
                &restored.event,
                &keys(2).public_key().to_hex()
            ));
            assert!(!db.store_agent_draft(community, expected).await.unwrap().1);
        }
        let state: String = sqlx::query_scalar(
            "SELECT state FROM agent_drafts WHERE community_id=$1 AND request_event_id=$2",
        )
        .bind(community.as_uuid())
        .bind(events[1].id.as_bytes().as_slice())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(state, "rejected");
        let replay = decision(
            &keys(1),
            &events[1],
            &events[1],
            1,
            "applying",
            "restart-replay",
            STAMP + 86400,
        );
        assert!(matches!(
            db.store_agent_draft(community, &replay).await,
            Err(DbError::Conflict(_))
        ));
        println!("verified actual PostgreSQL restart: pending request and rejected history retain exact signatures and owner-only result gates");
    } else {
        let f = Fixture::new().await;
        let pending = f.request(10, "pending across restart");
        let rejected = f.request(11, "rejected across restart");
        f.store(&pending).await;
        f.store(&rejected).await;
        let outcome = decision(
            &f.owner, &rejected, &rejected, 1, "rejected", "owner", STAMP,
        );
        f.store(&outcome).await;
        std::fs::write(
            checkpoint,
            serde_json::to_vec(&(f.community.as_uuid(), vec![pending, rejected, outcome])).unwrap(),
        )
        .unwrap();
        f.pool.close().await;
    }
}
