//! Disposable migration evidence for the independent gateway ledger.
use sqlx::{postgres::PgPoolOptions, AssertSqlSafe, PgPool};
use uuid::Uuid;

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

async fn isolated_pool() -> PgPool {
    // Never fall back to a developer or production database for migration tests.
    let url = std::env::var("BUZZ_TEST_DATABASE_URL").expect("private runner URL required");
    let schema = format!("push_migration_{}", Uuid::new_v4().simple());
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    sqlx::raw_sql(AssertSqlSafe(format!(
        "CREATE SCHEMA {schema}; SET search_path TO {schema}"
    )))
    .execute(&pool)
    .await
    .unwrap();
    pool
}

async fn seed_installation(pool: &PgPool, profile: &str, marker: u8) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO push_gateway_installations(id,app_attest_key_id,app_attest_public_key,assertion_counter,app_profile,token_ciphertext,token_fingerprint,endpoint_epoch,expires_at) VALUES($1,$2,$3,7,$4,$5,$6,3,now()+interval '1 day')")
        .bind(id).bind(vec![marker;32]).bind(vec![marker;33]).bind(profile)
        .bind(vec![marker;32]).bind(vec![marker;32]).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO push_gateway_delegations(id,installation_id,relay_pubkey,endpoint_epoch,generation,not_before,expires_at) VALUES($1,$2,$3,3,4,now(),now()+interval '1 hour')")
        .bind(Uuid::new_v4()).bind(id).bind(vec![marker;32]).execute(pool).await.unwrap();
    id
}

async fn assert_final_ledger(pool: &PgPool) {
    let actual: Vec<(i64, Vec<u8>)> = sqlx::query_as(
        "SELECT version,checksum FROM _sqlx_migrations WHERE success ORDER BY version",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    let expected: Vec<_> = MIGRATOR
        .iter()
        .map(|m| (m.version, m.checksum.to_vec()))
        .collect();
    assert_eq!(actual, expected);
    for profile in [
        "buzz-ios-production",
        "buzz-ios-sandbox",
        "buzz-ios-app-store",
    ] {
        let result=sqlx::query("INSERT INTO push_gateway_installations(id,app_attest_key_id,app_attest_public_key,assertion_counter,app_profile,token_ciphertext,token_fingerprint,endpoint_epoch,expires_at) VALUES($1,$2,$3,0,$4,$5,$6,1,now()+interval '1 day')")
            .bind(Uuid::new_v4()).bind(vec![90_u8;32]).bind(vec![90_u8;33]).bind(profile).bind(vec![90_u8;32]).bind(vec![90_u8;32]).execute(pool).await;
        assert_eq!(
            result
                .unwrap_err()
                .as_database_error()
                .unwrap()
                .code()
                .as_deref(),
            Some("23514")
        );
    }
    assert!(sqlx::query_scalar::<_, Option<String>>(
        "SELECT to_regclass('push_gateway_challenges_created_at')::text"
    )
    .fetch_one(pool)
    .await
    .unwrap()
    .is_some());
}

#[tokio::test]
#[ignore = "requires private PostgreSQL migration fixture"]
async fn fresh_gateway_ledger_accepts_only_dogfood() {
    let pool = isolated_pool().await;
    MIGRATOR.run(&pool).await.unwrap();
    seed_installation(&pool, "buzz-ios-dogfood", 1).await;
    assert_final_ledger(&pool).await;
}

#[tokio::test]
#[ignore = "requires private PostgreSQL migration fixture"]
async fn legacy_upgrade_retires_unmappable_authority_preserves_quota() {
    let pool = isolated_pool().await;
    MIGRATOR.run_to(1, &pool).await.unwrap();
    seed_installation(&pool, "buzz-ios-production", 1).await;
    seed_installation(&pool, "buzz-ios-sandbox", 2).await;
    sqlx::query("INSERT INTO push_gateway_endpoint_quotas(token_fingerprint,window_started_at,admitted) VALUES($1,now(),7)")
        .bind(vec![3_u8;32]).execute(&pool).await.unwrap();
    let before: serde_json::Value =
        sqlx::query_scalar("SELECT to_jsonb(q) FROM push_gateway_endpoint_quotas q")
            .fetch_one(&pool)
            .await
            .unwrap();
    MIGRATOR.run(&pool).await.unwrap();
    let counts:(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM push_gateway_installations),(SELECT count(*) FROM push_gateway_delegations)").fetch_one(&pool).await.unwrap();
    assert_eq!(
        counts,
        (0, 0),
        "retirement is explicit; no identity mapping"
    );
    let after: serde_json::Value =
        sqlx::query_scalar("SELECT to_jsonb(q) FROM push_gateway_endpoint_quotas q")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(before, after);
    assert_final_ledger(&pool).await;
}

#[tokio::test]
#[ignore = "requires private PostgreSQL migration fixture"]
async fn app_store_retirement_preserves_dogfood_authority_byte_for_byte() {
    let pool = isolated_pool().await;
    MIGRATOR.run_to(3, &pool).await.unwrap();
    let retained = seed_installation(&pool, "buzz-ios-dogfood", 1).await;
    seed_installation(&pool, "buzz-ios-app-store", 2).await;
    let snapshot="SELECT jsonb_build_array(to_jsonb(i),(SELECT to_jsonb(d) FROM push_gateway_delegations d WHERE d.installation_id=i.id)) FROM push_gateway_installations i WHERE id=$1";
    let before: serde_json::Value = sqlx::query_scalar(snapshot)
        .bind(retained)
        .fetch_one(&pool)
        .await
        .unwrap();
    MIGRATOR.run(&pool).await.unwrap();
    let after: serde_json::Value = sqlx::query_scalar(snapshot)
        .bind(retained)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(before, after);
    let counts:(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM push_gateway_installations),(SELECT count(*) FROM push_gateway_delegations)").fetch_one(&pool).await.unwrap();
    assert_eq!(counts, (1, 1));
    assert_final_ledger(&pool).await;
}
