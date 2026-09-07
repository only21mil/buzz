use super::*;

/// Response from `POST /events`.
#[derive(Debug, Deserialize, serde::Serialize)]
pub struct SubmitEventResponse {
    pub event_id: String,
    pub accepted: bool,
    pub message: String,
}

/// POST an already-signed event to an explicit relay with an explicit owner.
///
/// Deferred/scoped publication uses this form so a workspace or identity
/// switch cannot retarget either the event or its NIP-98 authentication after
/// the operation captured its `(relay, owner)` scope.
pub async fn submit_signed_event_at_with_keys(
    event: &nostr::Event,
    state: &AppState,
    api_base_url: &str,
    keys: &nostr::Keys,
) -> Result<SubmitEventResponse, String> {
    if event.pubkey != keys.public_key() {
        return Err("signed event does not match the publishing identity".to_string());
    }
    crate::relay_admission::wait_for_rate_limit().await;
    submit_signed_event_now(event, state, api_base_url, keys).await
}

async fn submit_signed_event_now(
    event: &nostr::Event,
    state: &AppState,
    api_base_url: &str,
    keys: &nostr::Keys,
) -> Result<SubmitEventResponse, String> {
    let url = format!("{}/events", api_base_url.trim_end_matches('/'));
    let body_bytes = event.as_json().into_bytes();
    crate::egress_guard::assert_no_key_backup_bytes(&body_bytes, "relay event submit")?;
    let auth_header = build_nip98_auth_header_for_keys(keys, &Method::POST, &url, &body_bytes)?;

    let response = state
        .http_client
        .post(&url)
        .header("Authorization", auth_header)
        .header("Content-Type", "application/json")
        .body(body_bytes)
        .send()
        .await
        .map_err(|e| classify_request_error(&e))?;

    if !response.status().is_success() {
        return Err(relay_error_message(response).await);
    }

    let result: SubmitEventResponse = parse_json_response(response).await?;
    if !result.accepted {
        return Err(format!("relay rejected event: {}", result.message));
    }

    Ok(result)
}

/// Sign with an explicit identity and POST the event to an explicit relay.
///
/// The caller owns the signer lifetime. This is important for deferred work:
/// an in-process identity swap cannot retarget the event or its NIP-98 auth
/// after the caller has validated which identity the operation belongs to.
pub async fn submit_event_at_with_keys(
    builder: nostr::EventBuilder,
    state: &AppState,
    api_base_url: &str,
    keys: &nostr::Keys,
) -> Result<SubmitEventResponse, String> {
    let event = builder
        .sign_with_keys(keys)
        .map_err(|e| format!("failed to sign event: {e}"))?;
    submit_signed_event_at_with_keys(&event, state, api_base_url, keys).await
}

/// Build and submit an event to the currently active workspace relay.
pub async fn submit_event(
    builder: nostr::EventBuilder,
    state: &AppState,
) -> Result<SubmitEventResponse, String> {
    let api_base_url = relay_api_base_url_with_override(state);
    let keys = state.signing_keys()?;
    submit_event_at_with_keys(builder, state, &api_base_url, &keys).await
}

/// Wait for admission before checking the expected scope and signing. The event,
/// destination and HTTP authentication all use the same immutable captured keys.
pub async fn submit_event_in_scope(
    builder: nostr::EventBuilder,
    state: &AppState,
    publication: MessagePublication,
) -> Result<SubmitEventResponse, String> {
    crate::relay_admission::wait_for_rate_limit().await;
    publication.validate()?;
    let keys = publication.keys;
    let relay = publication.api_base_url;
    let event = builder
        .sign_with_keys(&keys)
        .map_err(|e| format!("failed to sign event: {e}"))?;
    submit_signed_event_now(&event, state, &relay, &keys).await
}

#[cfg(test)]
mod publication_scope_tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn admission_wait_checks_actual_scope_before_signing_or_http() {
        let _serial = crate::relay_admission::TEST_SERIAL.lock().await;
        crate::relay_admission::reset_rate_limit_gate();
        let state = crate::app_state::build_app_state();
        let relay_url = "wss://old.example";
        *state.relay_url_override.lock().unwrap() = Some(relay_url.into());
        let expected = ExpectedPublicationScope {
            pubkey: state.signing_keys().unwrap().public_key().to_hex(),
            relay_url: relay_url.into(),
            native_epoch: None,
        };
        crate::relay_admission::activate_rate_limit(Some(1));
        let builder = nostr::EventBuilder::new(nostr::Kind::Custom(9), "captured message");
        let publication = MessagePublication::capture(&state, Some(&expected)).unwrap();
        let pending = submit_event_in_scope(builder, &state, publication);
        tokio::pin!(pending);
        // Poll the real submission into the admission wait before changing state.
        assert!(futures_util::poll!(&mut pending).is_pending());
        // An invalid destination guarantees even a regressed path cannot do network I/O.
        state
            .replace_publication_keys(nostr::Keys::generate(), None)
            .unwrap();
        *state.relay_url_override.lock().unwrap() = Some("not-a-relay-url".into());
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        let error = pending.await.unwrap_err();
        assert!(error.contains("identity or community changed"), "{error}");
        crate::relay_admission::reset_rate_limit_gate();
    }

    #[tokio::test(start_paused = true)]
    async fn queued_native_publication_rejects_workspace_and_identity_aba() {
        let _serial = crate::relay_admission::TEST_SERIAL.lock().await;
        crate::relay_admission::reset_rate_limit_gate();
        let state = crate::app_state::build_app_state();
        let keys = state.signing_keys().unwrap();
        // Port zero cannot contact a host service, even on the deliberately broken path.
        let relay_url = "ws://127.0.0.1:0";
        state
            .apply_publication_workspace(relay_url.into(), None)
            .unwrap();
        let snapshot = MessagePublication::capture(&state, None)
            .unwrap()
            .snapshot();
        let expected = ExpectedPublicationScope {
            pubkey: snapshot.pubkey,
            relay_url: snapshot.relay_url,
            native_epoch: Some(snapshot.native_epoch),
        };
        let publication = MessagePublication::capture(&state, Some(&expected)).unwrap();
        crate::relay_admission::activate_rate_limit(Some(1));
        let builder = nostr::EventBuilder::new(nostr::Kind::Custom(9), "captured message");
        let pending = submit_event_in_scope(builder, &state, publication);
        tokio::pin!(pending);
        assert!(futures_util::poll!(&mut pending).is_pending());
        state
            .apply_publication_workspace("ws://127.0.0.1:1".into(), Some(nostr::Keys::generate()))
            .unwrap();
        state
            .apply_publication_workspace(relay_url.into(), Some(keys))
            .unwrap();
        // Exact signer and relay match again; only the captured epoch revokes this send.
        expected
            .validate(&state.signing_keys().unwrap(), relay_url)
            .unwrap();
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        let error = pending.await.unwrap_err();
        assert!(error.contains("identity or community changed"), "{error}");
        crate::relay_admission::reset_rate_limit_gate();
    }

    #[test]
    fn renderer_snapshot_rejects_aba_before_native_command_dequeue() {
        let state = crate::app_state::build_app_state();
        let keys = state.signing_keys().unwrap();
        let relay_url = "ws://127.0.0.1:0";
        state
            .apply_publication_workspace(relay_url.into(), None)
            .unwrap();
        let snapshot = MessagePublication::capture(&state, None)
            .unwrap()
            .snapshot();
        let expected = ExpectedPublicationScope {
            pubkey: snapshot.pubkey,
            relay_url: snapshot.relay_url,
            native_epoch: Some(snapshot.native_epoch),
        };
        // Exercise the identity-import replacement seam as well as workspace application.
        state
            .replace_publication_keys(nostr::Keys::generate(), None)
            .unwrap();
        state.replace_publication_keys(keys, None).unwrap();
        assert!(MessagePublication::capture(&state, Some(&expected)).is_err());
    }

    #[test]
    fn same_scope_workspace_refresh_preserves_native_publication() {
        let state = crate::app_state::build_app_state();
        let keys = state.signing_keys().unwrap();
        state
            .apply_publication_workspace("wss://RELAY.example/Team/".into(), None)
            .unwrap();
        let publication = MessagePublication::capture(&state, None).unwrap();
        state
            .apply_publication_workspace("wss://relay.example/Team".into(), Some(keys.clone()))
            .unwrap();
        state.replace_publication_keys(keys, None).unwrap();
        assert!(publication.validate().is_ok());
    }
}
