//! Catalog convergence for historical fork objects used by ordinary fixtures.

use sqlx::PgPool;

async fn retained_catalog(pool: &PgPool) -> Vec<(String, String)> {
    sqlx::query_as(
        r#"
        SELECT 'function:' || proname, pg_get_functiondef(oid) || ':' || coalesce(proacl::text, '')
        FROM pg_proc WHERE pronamespace = 'public'::regnamespace AND proname IN
          ('guard_nip_rs_watermark', 'guard_nip_rs_hard_delete', 'purge_soft_deleted_nip_rs',
           'guard_event_mention_live', 'purge_soft_deleted_buzz_mesh_status')
        UNION ALL
        SELECT 'trigger:' || tgname, pg_get_triggerdef(oid) FROM pg_trigger
        WHERE tgrelid IN ('events'::regclass, 'event_mentions'::regclass)
          AND tgname IN ('trg_events_nip_rs_watermark', 'trg_events_guard_nip_rs_hard_delete',
          'trg_events_purge_soft_deleted_nip_rs', 'trg_event_mentions_require_live_event',
          'trg_events_purge_soft_deleted_buzz_mesh_status')
        UNION ALL
        SELECT 'column:' || table_name || ':' || column_name,
          data_type || ':' || is_nullable || ':' || coalesce(column_default, '')
        FROM information_schema.columns WHERE table_schema = 'public'
          AND table_name IN ('parameterized_event_watermarks', 'product_feedback')
        UNION ALL
        SELECT 'constraint:' || conrelid::regclass::text || ':' || conname,
          pg_get_constraintdef(oid) FROM pg_constraint
        WHERE conrelid IN ('parameterized_event_watermarks'::regclass, 'product_feedback'::regclass)
        UNION ALL
        SELECT 'index:' || indexname, indexdef FROM pg_indexes WHERE schemaname = 'public'
          AND (tablename IN ('parameterized_event_watermarks', 'product_feedback')
               OR indexname = 'idx_event_mentions_community_event')
        UNION ALL
        SELECT 'acl:' || relname, coalesce(relacl::text, '') FROM pg_class
        WHERE oid IN ('parameterized_event_watermarks'::regclass, 'product_feedback'::regclass)
        UNION ALL
        SELECT 'operator-global:' || table_name, reason FROM _operator_global_tables
        WHERE table_name = 'product_feedback'
        ORDER BY 1, 2
        "#,
    )
    .fetch_all(pool)
    .await
    .expect("historical catalog")
}

#[tokio::test]
#[ignore = "requires isolated empty PostgreSQL database"]
async fn historical_fork_catalog_matches_fresh_migrations() {
    let url = std::env::var("BUZZ_TEST_DATABASE_URL").expect("isolated fixture URL");
    let pool = PgPool::connect(&url).await.expect("connect fixture");
    // Explicit migration mode supplies an empty database. Compare desired state
    // and fresh migration state in the same owned fixture, never a shared DB.
    sqlx::raw_sql(include_str!("../../../schema/schema.sql"))
        .execute(&pool)
        .await
        .expect("desired schema");
    let desired = retained_catalog(&pool).await;
    assert!(
        desired.len() >= 40,
        "catalog must contain every selected object"
    );
    sqlx::raw_sql("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
        .execute(&pool)
        .await
        .expect("reset isolated fixture");
    buzz_db::migration::run_migrations(&pool)
        .await
        .expect("fresh migrations");
    assert_eq!(desired, retained_catalog(&pool).await);
    pool.close().await;
}
