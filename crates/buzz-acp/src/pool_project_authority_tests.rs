// Included in pool::tests so the real provider-delivery path shares its fixtures.
#[tokio::test]
async fn missing_channel_metadata_requeues_without_provider_delivery() {
    for threaded in [false, true] {
        let channel_id = Uuid::new_v4();
        let scope = if threaded {
            SessionScope::Thread {
                channel_id,
                root_event_id: "a".repeat(64),
            }
        } else {
            conv(channel_id)
        };
        let capture =
            std::env::temp_dir().join(format!("buzz-project-metadata-{}", Uuid::new_v4()));
        let quoted = capture.to_string_lossy().replace('\'', "'\\''");
        let script = format!(
            r#"while IFS= read -r line; do
printf '%s\n' "$line" >> '{quoted}'
printf '%s\n' '{{"jsonrpc":"2.0","id":0,"result":{{"stopReason":"end_turn"}}}}'
done"#
        );
        let acp = AcpClient::spawn("bash", &["-c".into(), script], &[], false)
            .await
            .unwrap();
        let mut agent = OwnedAgent {
            index: 0,
            acp,
            state: SessionState::default(),
            model_capabilities: None,
            desired_model: None,
            model_overridden: false,
            agent_name: "legacy-test-agent".into(),
            goose_system_prompt_supported: None,
            protocol_version: 1,
        };
        agent
            .state
            .sessions
            .insert(scope.clone(), "live-session".into());
        let event = EventBuilder::new(Kind::Custom(9), "must remain queued")
            .sign_with_keys(&Keys::generate())
            .unwrap();
        let batch = FlushBatch {
            channel_id,
            scope: scope.clone(),
            events: vec![crate::queue::BatchEvent {
                event: event.clone(),
                prompt_tag: "test".into(),
                received_at: std::time::Instant::now(),
            }],
            cancelled_events: vec![],
            cancel_reason: None,
        };
        // A responsive local relay returning no channel metadata models a
        // transient classification failure without timeout-dependent assertions.
        let (resolver, _, server) = counting_resolver(json!([])).await;
        let mut ctx = make_prompt_context_no_owner();
        ctx.channel_info = resolver;
        assert!(matches!(ctx.dedup_mode, DedupMode::Drop));
        let (tx, mut rx) = mpsc::unbounded_channel();
        run_prompt_task(
            agent,
            Some(batch),
            None,
            Arc::new(ctx),
            tx,
            None,
            "metadata-failure".into(),
        )
        .await;
        let mut result = rx.recv().await.unwrap();
        result.agent.acp.shutdown().await;
        server.abort();
        let wire = std::fs::read_to_string(&capture).unwrap_or_default();
        let _ = std::fs::remove_file(&capture);
        assert!(
            wire.is_empty(),
            "metadata failure must not reach the provider: {wire}"
        );
        assert!(matches!(
            result.outcome,
            PromptOutcome::ProjectContextIndeterminate(_)
        ));
        assert!(matches!(result.source, PromptSource::Channel(ref actual) if actual == &scope));
        let retry = result
            .batch
            .take()
            .expect("even drop mode preserves a retry batch");
        assert_eq!(retry.events[0].event.id, event.id);
        let mut queue = crate::queue::EventQueue::new(DedupMode::Drop);
        assert!(queue.requeue(retry).is_none());
        assert_eq!(queue.queued_event_count(&scope), 1);
        assert!(
            !queue.has_flushable_work(),
            "bounded backoff must apply before retry"
        );
    }
}

#[tokio::test]
async fn channel_prompt_commits_delivery_state_only_after_acp_success() {
    let capture = std::env::temp_dir().join(format!(
        "buzz-acp-channel-delivery-lifecycle-{}.ndjson",
        Uuid::new_v4()
    ));
    let quoted_capture = capture.to_string_lossy().replace('\'', "'\\''");
    let script = format!(
        r#"count=0
while IFS= read -r line; do
  printf '%s\n' "$line" >> '{quoted_capture}'
  count=$((count + 1))
  if [ "$count" -eq 1 ]; then
    printf '%s\n' '{{"jsonrpc":"2.0","id":0,"error":{{"code":-32000,"message":"retry me"}}}}'
  else
    printf '%s\n' "{{\"jsonrpc\":\"2.0\",\"id\":$((count - 1)),\"result\":{{\"stopReason\":\"end_turn\"}}}}"
  fi
done"#
    );
    let acp = AcpClient::spawn("bash", &["-c".to_string(), script], &[], false)
        .await
        .expect("spawn channel lifecycle ACP script");
    let channel_id = Uuid::new_v4();
    let mut agent = OwnedAgent {
        index: 0,
        acp,
        state: SessionState::default(),
        model_capabilities: None,
        desired_model: None,
        model_overridden: false,
        agent_name: "legacy-test-agent".into(),
        goose_system_prompt_supported: None,
        protocol_version: 1,
    };
    agent
        .state
        .sessions
        .insert(conv(channel_id), "live-session".into());
    agent
        .state
        .deliveries
        .insert(conv(channel_id), ChannelDeliveryState::default());

    let mut ctx = make_prompt_context_no_owner();
    ctx.base_prompt = Some("standing-once".into());
    ctx.channel_info = ChannelInfoResolver::new(
        HashMap::from([(
            channel_id,
            crate::relay::ChannelInfo {
                name: "test-dm".into(),
                channel_type: "dm".into(),
            },
        )]),
        ctx.rest_client.clone(),
    );
    let ctx = Arc::new(ctx);
    let (result_tx, mut result_rx) = mpsc::unbounded_channel();

    for turn in 1..=3 {
        let event = EventBuilder::new(Kind::Custom(9), format!("channel-{turn}"))
            .sign_with_keys(&Keys::generate())
            .unwrap();
        let event_id = event.id.to_hex();
        let batch = FlushBatch {
            channel_id,
            scope: SessionScope::Conversation { channel_id },
            events: vec![crate::queue::BatchEvent {
                event,
                prompt_tag: "test".into(),
                received_at: std::time::Instant::now(),
            }],
            cancelled_events: vec![],
            cancel_reason: None,
        };
        run_prompt_task(
            agent,
            Some(batch),
            None,
            Arc::clone(&ctx),
            result_tx.clone(),
            None,
            format!("turn-{turn}"),
        )
        .await;
        let result = result_rx.recv().await.expect("prompt result");
        match turn {
            1 => assert!(matches!(result.outcome, PromptOutcome::Error(_))),
            _ => assert!(matches!(
                result.outcome,
                PromptOutcome::Ok(StopReason::EndTurn)
            )),
        }
        let delivery = &result.agent.state.deliveries[&conv(channel_id)];
        assert_eq!(
            delivery.standing_context_sent,
            turn >= 2,
            "failed channel delivery must not commit; first success must commit"
        );
        assert_eq!(
            delivery.delivered_event_ids.contains(&event_id),
            turn >= 2,
            "channel event IDs must commit only after ACP success"
        );
        agent = result.agent;
    }
    agent.acp.shutdown().await;

    let requests: Vec<serde_json::Value> = std::fs::read_to_string(&capture)
        .expect("read captured ACP requests")
        .lines()
        .map(|line| serde_json::from_str(line).expect("captured request is JSON"))
        .collect();
    std::fs::remove_file(&capture).expect("remove ACP capture");
    let prompt_text = |index: usize| {
        requests[index]["params"]["prompt"][0]["text"]
            .as_str()
            .expect("text prompt")
    };
    assert!(prompt_text(0).contains("<base>\nstanding-once"));
    assert!(
        prompt_text(1).contains("<base>\nstanding-once"),
        "retry after channel ACP failure must resend standing context"
    );
    assert!(
        !prompt_text(2).contains("<base>\nstanding-once"),
        "turn after channel ACP success must omit standing context"
    );
}
