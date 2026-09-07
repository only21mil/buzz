//! Scope and replay metadata captured by a publish-first agent wake.

use crate::app_state::AppState;

pub(crate) const REPLAY_FLOOR_ENV_VAR: &str = "BUZZ_ACP_REPLAY_FLOOR";

/// Captured invocation scope. Async launch work validates this again before
/// spawning and consumes its relay instead of rereading mutable workspace state.
#[derive(Clone)]
pub(crate) struct DeferredAgentStart {
    pub relay_url: String,
    pub signer_pubkey: String,
    pub replay_floor_unix: Option<u64>,
}

impl DeferredAgentStart {
    pub(crate) fn capture(
        state: &AppState,
        expected_relay: Option<&str>,
        expected_signer: Option<&str>,
        replay_floor_unix: Option<u64>,
    ) -> Result<Self, String> {
        // A replay floor identifies a deferred callback, which must carry its
        // complete send-time scope. Legacy explicit Start has no floor.
        if replay_floor_unix.is_some() && (expected_relay.is_none() || expected_signer.is_none()) {
            return Err("deferred agent start requires relay and signer scope".into());
        }
        let relay_url = crate::relay::relay_ws_url_with_override(state);
        let signer_pubkey = state
            .keys
            .lock()
            .map_err(|e| e.to_string())?
            .public_key()
            .to_hex();
        validate_scope(expected_relay, expected_signer, &relay_url, &signer_pubkey)?;
        Ok(Self {
            relay_url,
            signer_pubkey,
            replay_floor_unix,
        })
    }

    pub(crate) fn validate(&self, state: &AppState) -> Result<(), String> {
        let signer = state
            .keys
            .lock()
            .map_err(|e| e.to_string())?
            .public_key()
            .to_hex();
        validate_scope(
            Some(&self.relay_url),
            Some(&self.signer_pubkey),
            &crate::relay::relay_ws_url_with_override(state),
            &signer,
        )
    }

    pub(crate) fn validate_payload(&self, payload: &serde_json::Value) -> Result<(), String> {
        validate_scope(
            Some(&self.relay_url),
            Some(&self.signer_pubkey),
            payload["relay_url"]
                .as_str()
                .ok_or("provider payload missing relay scope")?,
            payload["launch"]["owner_pubkey"]
                .as_str()
                .ok_or("provider payload missing signer scope")?,
        )
    }
}

fn validate_scope(
    expected_relay: Option<&str>,
    expected_signer: Option<&str>,
    relay: &str,
    signer: &str,
) -> Result<(), String> {
    if let Some(expected) = expected_relay {
        let expected =
            buzz_core_pkg::relay::normalize_relay_url(expected).map_err(|e| e.to_string())?;
        let actual = buzz_core_pkg::relay::normalize_relay_url(relay).map_err(|e| e.to_string())?;
        if expected != actual {
            return Err(
                "agent start community changed; send again in the intended community".into(),
            );
        }
    }
    if let Some(expected) = expected_signer {
        let expected =
            nostr::PublicKey::from_hex(expected).map_err(|_| "invalid expected signer")?;
        if expected.to_hex() != signer {
            return Err(
                "agent start identity changed; send again with the intended identity".into(),
            );
        }
    }
    Ok(())
}

/// Remove inherited/descriptor floors and apply only this invocation's value.
pub(crate) fn apply_replay_floor_env(command: &mut std::process::Command, floor: Option<u64>) {
    let keys: Vec<_> = command
        .get_envs()
        .map(|(key, _)| key.to_os_string())
        .chain(std::env::vars_os().map(|(key, _)| key))
        .filter(|key| {
            key.to_string_lossy()
                .eq_ignore_ascii_case(REPLAY_FLOOR_ENV_VAR)
        })
        .collect();
    for key in keys {
        command.env_remove(key);
    }
    command.env_remove(REPLAY_FLOOR_ENV_VAR);
    if let Some(floor) = floor {
        command.env(REPLAY_FLOOR_ENV_VAR, floor.to_string());
    }
}

/// Provider equivalent of the local invocation-only projection.
pub(crate) fn apply_replay_floor_payload(
    payload: &mut serde_json::Value,
    floor: Option<u64>,
) -> Result<(), String> {
    let launch = payload
        .get_mut("launch")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or("provider payload missing launch contract")?;
    for layer in ["env", "policy_env"] {
        if let Some(env) = launch
            .get_mut(layer)
            .and_then(serde_json::Value::as_object_mut)
        {
            env.retain(|key, _| !key.eq_ignore_ascii_case(REPLAY_FLOOR_ENV_VAR));
        }
    }
    if let Some(floor) = floor {
        let env = launch
            .entry("policy_env")
            .or_insert_with(|| serde_json::json!({}));
        env.as_object_mut()
            .ok_or("invalid provider policy environment")?
            .insert(REPLAY_FLOOR_ENV_VAR.into(), floor.to_string().into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_or_incomplete_scope_fails_closed() {
        let signer = nostr::Keys::generate().public_key().to_hex();
        assert!(validate_scope(
            Some("wss://one.example"),
            Some(&signer),
            "wss://one.example/",
            &signer
        )
        .is_ok());
        assert!(validate_scope(
            Some("wss://one.example"),
            Some(&signer),
            "wss://two.example",
            &signer
        )
        .is_err());
        assert!(validate_scope(Some(""), Some(&signer), "wss://one.example", &signer).is_err());
        assert!(validate_scope(None, Some(""), "wss://one.example", &signer).is_err());
        assert!(validate_scope(
            None,
            Some(&nostr::Keys::generate().public_key().to_hex()),
            "wss://one.example",
            &signer
        )
        .is_err());
    }

    #[test]
    fn provider_floor_is_invocation_only_and_case_insensitive() {
        let mut payload = serde_json::json!({"launch":{"env":{"BUZZ_ACP_REPLAY_FLOOR":"1", "buzz_acp_replay_floor":"2", "KEEP":"yes"},"policy_env":{"BUZZ_ACP_REPLAY_FLOOR":"3"}}});
        apply_replay_floor_payload(&mut payload, Some(42)).unwrap();
        assert_eq!(payload["launch"]["env"], serde_json::json!({"KEEP":"yes"}));
        assert_eq!(payload["launch"]["policy_env"][REPLAY_FLOOR_ENV_VAR], "42");
        apply_replay_floor_payload(&mut payload, None).unwrap();
        assert_eq!(payload["launch"]["policy_env"], serde_json::json!({}));
        assert!(apply_replay_floor_payload(&mut serde_json::json!({}), Some(42)).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn real_child_receives_only_current_floor() {
        for (floor, expected) in [(Some(42), "42"), (None, "unset")] {
            let mut command = std::process::Command::new("/bin/sh");
            command.env_clear().env(REPLAY_FLOOR_ENV_VAR, "1").env("buzz_acp_replay_floor", "2")
                .args(["-c", "printf '%s' \"${BUZZ_ACP_REPLAY_FLOOR-unset}\"; test -z \"${buzz_acp_replay_floor-}\""]);
            apply_replay_floor_env(&mut command, floor);
            let result = command.output().unwrap();
            assert!(result.status.success());
            assert_eq!(String::from_utf8(result.stdout).unwrap(), expected);
        }
    }
}
