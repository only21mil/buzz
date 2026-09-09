//! Exercise the standalone-child shape emitted by pgschema before CI attachment.

use sqlx::{AssertSqlSafe, PgPool};

const ATTACH: &str = include_str!("../../../scripts/attach-schema-partitions.sql");

async fn trigger_catalog(pool: &PgPool) -> Vec<(i64, String, String, bool, String)> {
    sqlx::query_as(
        "SELECT oid::bigint, tgrelid::regclass::text, tgname::text, tgparentid <> 0, \
         tgenabled::text FROM pg_trigger WHERE NOT tgisinternal \
         AND tgrelid IN (SELECT inhrelid FROM pg_inherits WHERE inhparent = 'events'::regclass) \
         ORDER BY 2, 3",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

async fn attachment_contract(migrated: bool) {
    let url = std::env::var("BUZZ_TEST_DATABASE_URL").expect("isolated fixture URL");
    let pool = PgPool::connect(&url).await.unwrap();
    if migrated {
        buzz_db::migration::run_migrations(&pool).await.unwrap();
    } else {
        sqlx::raw_sql(include_str!("../../../schema/schema.sql"))
            .execute(&pool)
            .await
            .unwrap();
    }
    sqlx::raw_sql(
        "INSERT INTO communities (id, host) VALUES ('11111111-1111-1111-1111-111111111111', 'attach.test');
         INSERT INTO events (community_id, id, pubkey, created_at, kind, tags, content, sig, d_tag)
         SELECT '11111111-1111-1111-1111-111111111111', decode(md5(t::text), 'hex'),
                decode(repeat('11', 32), 'hex'), t, 30078, '[]', 'retained', decode(repeat('22', 64), 'hex'),
                'read-state:11111111111111111111111111111111'
         FROM unnest(ARRAY['2025-12-15', '2026-01-15', '2026-02-15', '2026-03-15',
                          '2026-04-15', '2026-05-15', '2026-06-15', '2026-07-15']::timestamptz[]) t;",
    )
    .execute(&pool)
    .await
    .unwrap();
    // Dynamic identifiers and trigger DDL below come only from this isolated
    // fixture's PostgreSQL catalogs; regclass renders quoted identifiers.
    let partitions: Vec<String> = sqlx::query_scalar(
        "SELECT inhrelid::regclass::text FROM pg_inherits \
         WHERE inhparent = 'events'::regclass ORDER BY 1",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(partitions.len(), 8);
    // Every non-internal row-level trigger on the parent is cloned onto each
    // partition (tgtype bit 0 is TRIGGER_TYPE_ROW). Count the parent's own
    // triggers rather than a literal so a migration that adds one, such as
    // 0040's agent-draft history guard, keeps this contract honest.
    let parent_row_triggers: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_trigger \
         WHERE tgrelid = 'events'::regclass AND tgparentid = 0 \
         AND NOT tgisinternal AND (tgtype & 1) = 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        parent_row_triggers >= 7,
        "parent row triggers: {parent_row_triggers}"
    );
    let before = trigger_catalog(&pool).await;
    for child in &partitions {
        let triggers: Vec<String> = sqlx::query_scalar(
            "SELECT pg_get_triggerdef(oid) FROM pg_trigger \
             WHERE tgrelid = $1::regclass AND tgparentid <> 0 AND NOT tgisinternal ORDER BY tgname",
        )
        .bind(child)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(
            triggers.len() as i64,
            parent_row_triggers,
            "all current parent row triggers copied"
        );
        // DETACH removes inherited triggers. Recreate their actual definitions
        // as standalone triggers, as pgschema 1.7.4 does during fresh bootstrap.
        sqlx::raw_sql(AssertSqlSafe(format!(
            "ALTER TABLE events DETACH PARTITION {child}"
        )))
        .execute(&pool)
        .await
        .unwrap();
        for trigger in triggers {
            sqlx::raw_sql(AssertSqlSafe(trigger))
                .execute(&pool)
                .await
                .unwrap();
        }
    }
    // A child-local trigger must survive the targeted duplicate cleanup.
    sqlx::raw_sql(
        "CREATE FUNCTION attachment_local_guard() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN OLD; END $$;
         CREATE TRIGGER attachment_local_guard BEFORE DELETE ON events_p_past
         FOR EACH ROW EXECUTE FUNCTION attachment_local_guard()",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::raw_sql(ATTACH).execute(&pool).await.unwrap();
    let after = trigger_catalog(&pool).await;
    let inherited: Vec<_> = after
        .iter()
        .filter(|row| row.3)
        .map(|row| (&row.1, &row.2, row.3, &row.4))
        .collect();
    let original: Vec<_> = before
        .iter()
        .map(|row| (&row.1, &row.2, row.3, &row.4))
        .collect();
    assert_eq!(
        inherited, original,
        "every parent trigger is inherited and enabled"
    );
    assert!(after
        .iter()
        .any(|row| row.2 == "attachment_local_guard" && !row.3));
    sqlx::raw_sql(ATTACH).execute(&pool).await.unwrap();
    assert_eq!(
        after,
        trigger_catalog(&pool).await,
        "repeat attachment keeps trigger OIDs"
    );
    if migrated {
        buzz_db::migration::run_migrations(&pool).await.unwrap();
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM events WHERE content = 'retained'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        count, 8,
        "populated children remain visible through the parent"
    );
    for table in std::iter::once("events").chain(partitions.iter().map(String::as_str)) {
        let error = sqlx::raw_sql(AssertSqlSafe(format!("DELETE FROM {table}")))
            .execute(&pool)
            .await
            .expect_err("unapproved read-state hard delete must fail");
        assert_eq!(
            error.as_database_error().unwrap().code().as_deref(),
            Some("23514")
        );
    }
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT set_config('buzz.nip_rs_hard_delete', 'on', true)")
        .execute(&mut *tx)
        .await
        .unwrap();
    assert_eq!(
        sqlx::query("DELETE FROM events")
            .execute(&mut *tx)
            .await
            .unwrap()
            .rows_affected(),
        8
    );
    tx.commit().await.unwrap();
    pool.close().await;
}

#[tokio::test]
#[ignore = "requires isolated empty PostgreSQL database"]
async fn desired_schema_attachment_preserves_partition_guards() {
    attachment_contract(false).await;
}

#[tokio::test]
#[ignore = "requires isolated empty PostgreSQL database"]
async fn populated_migration_attachment_preserves_partition_guards() {
    attachment_contract(true).await;
}
