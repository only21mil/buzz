use super::*;

#[test]
fn workflow_history_rejects_malformed_and_partial_cursors() {
    for suffix in [
        "before=garbage&before_id=garbage",
        "before=2026-09-06T00:00:00Z&before_id=bad",
        "before=&before_id=",
        "before_id=00000000-0000-0000-0000-000000000001",
        "page=true&limit=0",
        "before=2026-09-06T00:00:00Z",
        "before=2026-09-06T00:00:00Z&before=2026-09-07T00:00:00Z",
    ] {
        let uri = format!("/workflows/id/runs?{suffix}").parse().expect("uri");
        match Query::<WorkflowRunsQuery>::try_from_uri(&uri) {
            Ok(Query(query)) => assert!(workflow_runs_controls(&query).is_err(), "{suffix}"),
            Err(error) => assert_eq!(error.status(), StatusCode::BAD_REQUEST),
        }
    }
    let query = Query::<WorkflowRunsQuery>::try_from_uri(&"/runs?page=true&limit=101&before=2026-09-06T00:00:00.123456Z&before_id=00000000-0000-0000-0000-000000000001".parse().unwrap()).unwrap().0;
    assert_eq!(workflow_runs_controls(&query).unwrap(), (true, 100));
}

#[test]
fn workflow_history_legacy_array_and_precise_cursor_envelope() {
    let mut first = tests::workflow_run_record(None, None, None);
    first.created_at = "2026-09-06T10:00:00.123456Z".parse().unwrap();
    first.status = buzz_db::workflow::RunStatus::ResumePending;
    let second = tests::workflow_run_record(None, None, None);
    let legacy = workflow_runs_response(&mut vec![first.clone()], 20, false);
    assert!(legacy.is_array());
    assert_eq!(legacy[0]["status"], "resume_pending");
    let page = workflow_runs_response(&mut vec![first.clone(), second], 1, true);
    assert_eq!(page["runs"].as_array().unwrap().len(), 1);
    assert_eq!(page["next"]["before"], "2026-09-06T10:00:00.123456Z");
    assert_eq!(page["next"]["before_id"], first.id.to_string());
    assert!(page["runs"][0]["execution_trace"][0]
        .get("output")
        .is_none());
    assert!(workflow_runs_response(&mut vec![first], 1, true)["next"].is_null());
}

#[test]
fn workflow_history_approval_wire_has_only_display_evidence() {
    let approval = buzz_db::workflow::WorkflowApprovalHistoryRecord {
        approval_ref: uuid::Uuid::new_v4().to_string(),
        workflow_id: uuid::Uuid::new_v4(),
        run_id: uuid::Uuid::new_v4(),
        step_id: "review".into(),
        step_index: 1,
        approver_spec: "owner".into(),
        status: "granted".into(),
        approver_pubkey: Some(hex::encode([1u8; 32])),
        note: Some("approved".into()),
        expires_at: chrono::Utc::now(),
        created_at: chrono::Utc::now(),
    };
    let wire = workflow_approval_json(&approval);
    assert_eq!(wire["approval_ref"], approval.approval_ref);
    assert_eq!(wire["status"], "granted");
    for field in [
        "token",
        "approval_token",
        "definition_hash",
        "generation",
        "resolved_approver_set",
        "request_payload",
    ] {
        assert!(wire.get(field).is_none());
    }
}

#[tokio::test]
#[ignore = "requires disposable Postgres"]
async fn workflow_history_privacy_requires_owner_and_active_membership_in_same_community() {
    let url = std::env::var("BUZZ_TEST_DATABASE_URL").expect("explicit isolated database required");
    let pool = sqlx::PgPool::connect(&url).await.unwrap();
    let db = buzz_db::Db::from_pool(pool.clone());
    let community = buzz_core::CommunityId::from_uuid(uuid::Uuid::new_v4());
    let channel = uuid::Uuid::new_v4();
    let workflow = uuid::Uuid::new_v4();
    let owner = [17u8; 32];
    let other = [18u8; 32];
    sqlx::query("INSERT INTO communities (id,host) VALUES ($1,'workflow-history.test')")
        .bind(community.as_uuid())
        .execute(&pool)
        .await
        .unwrap();
    buzz_db::user::ensure_user(&pool, community, &owner)
        .await
        .unwrap();
    buzz_db::user::ensure_user(&pool, community, &other)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO channels (community_id,id,name,created_by) VALUES ($1,$2,'history',$3)",
    )
    .bind(community.as_uuid())
    .bind(channel)
    .bind(&owner[..])
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO channel_members (community_id,channel_id,pubkey,role) VALUES ($1,$2,$3,'owner'),($1,$2,$4,'member')").bind(community.as_uuid()).bind(channel).bind(&owner[..]).bind(&other[..]).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO workflows (community_id,id,channel_id,owner_pubkey,name,definition,definition_hash,status,enabled) VALUES ($1,$2,$3,$4,'history','{}',$5,'disabled',false)").bind(community.as_uuid()).bind(workflow).bind(channel).bind(&owner[..]).bind(vec![1u8;32]).execute(&pool).await.unwrap();
    assert!(
        authorize_workflow_history_rows(&db, community, &owner, workflow)
            .await
            .is_ok()
    );
    for (tenant, actor, id) in [
        (community, other, workflow),
        (
            buzz_core::CommunityId::from_uuid(uuid::Uuid::new_v4()),
            owner,
            workflow,
        ),
        (community, owner, uuid::Uuid::new_v4()),
    ] {
        let (status, body) = authorize_workflow_history_rows(&db, tenant, &actor, id)
            .await
            .unwrap_err();
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body.0, serde_json::json!({"error":"workflow not found"}));
    }
    sqlx::query("UPDATE channel_members SET removed_at=now() WHERE community_id=$1 AND channel_id=$2 AND pubkey=$3").bind(community.as_uuid()).bind(channel).bind(&owner[..]).execute(&pool).await.unwrap();
    assert_eq!(
        authorize_workflow_history_rows(&db, community, &owner, workflow)
            .await
            .unwrap_err()
            .0,
        StatusCode::NOT_FOUND
    );
}
