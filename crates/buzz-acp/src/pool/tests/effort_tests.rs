use super::*;

async fn fake_agent() -> OwnedAgent {
    // The fixture validates ordering and exact IDs, returning fresh model-specific
    // effort options only after the model selection succeeds.
    let script = r#"import sys,json
deleted=0
for line in sys.stdin:
 r=json.loads(line); p=r.get('params',{}); m=r['method']; result={}
 if m=='session/new':
  result={'sessionId':'s','cleanupCount':deleted,'configOptions':[{'id':'model-choice','category':'model','options':[{'value':'target'}]},{'id':'old-effort','category':'thought_level','options':[{'value':'wrong'}]}]}
 elif m=='session/close': pass
 elif m=='session/delete': deleted+=1
 elif m=='session/set_config_option' and p['configId']=='model-choice':
  assert p['value']=='target'
  result={'configOptions':[{'id':'model-reasoning','category':'thought_level','options':[{'value':'high'}]}]}
 elif m=='session/set_config_option':
  assert p=={'sessionId':'s','configId':'model-reasoning','value':'high'},p
  result={'configOptions':[{'id':'model-reasoning','category':'thought_level','currentValue':'high','options':[{'value':'high'}]}]}
 else: raise Exception(m)
 print(json.dumps({'jsonrpc':'2.0','id':r['id'],'result':result}),flush=True)
"#;
    let acp = AcpClient::spawn("python3", &["-c".into(), script.into()], &[], false)
        .await
        .unwrap();
    OwnedAgent {
        index: 0,
        acp,
        state: SessionState::default(),
        model_capabilities: None,
        desired_model: Some("target".into()),
        model_overridden: false,
        agent_name: "test".into(),
        goose_system_prompt_supported: None,
        protocol_version: 2,
    }
}

#[tokio::test]
async fn startup_effort_uses_post_model_advertised_id_and_reapplies_per_session() {
    let mut agent = fake_agent().await;
    let mut ctx = make_prompt_context_no_owner();
    ctx.startup_effort = Some("high".into());
    for _ in 0..2 {
        assert_eq!(
            create_session_and_apply_model(&mut agent, &ctx, None, None, None, None, None)
                .await
                .unwrap(),
            "s"
        );
    }
    agent.acp.shutdown().await;
}

#[tokio::test]
async fn unsupported_effort_rejects_and_clear_makes_no_effort_request() {
    let mut agent = fake_agent().await;
    let mut ctx = make_prompt_context_no_owner();
    ctx.startup_effort = Some("wrong".into());
    assert!(matches!(
        create_session_and_apply_model(&mut agent, &ctx, None, None, None, None, None).await,
        Err(AcpError::AgentError { code: -32602, .. })
    ));
    let probe = agent
        .acp
        .session_new_full("/", vec![], None, None)
        .await
        .unwrap();
    assert_eq!(
        probe.raw["cleanupCount"], 1,
        "rejected unregistered session must be deleted"
    );
    ctx.startup_effort = None;
    assert!(
        create_session_and_apply_model(&mut agent, &ctx, None, None, None, None, None)
            .await
            .is_ok()
    );
    agent.acp.shutdown().await;
}
