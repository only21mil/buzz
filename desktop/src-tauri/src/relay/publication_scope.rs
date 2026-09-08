use crate::app_state::AppState;
use nostr::Keys;
use std::sync::{Arc, Mutex, MutexGuard};

/// Renderer-captured relay and author required by delayed composer publication.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExpectedPublicationScope {
    pub pubkey: String,
    pub relay_url: String,
    pub native_epoch: Option<u64>,
}

impl ExpectedPublicationScope {
    /// Compare against the actual signing keys and destination, preserving relay path case.
    pub fn validate(&self, keys: &Keys, relay_url: &str) -> Result<(), String> {
        if keys.public_key().to_hex() != self.pubkey
            || canonical_relay(relay_url)? != canonical_relay(&self.relay_url)?
        {
            return Err("message cancelled because the identity or community changed".into());
        }
        Ok(())
    }
}

fn canonical_relay(value: &str) -> Result<String, String> {
    url::Url::parse(value.trim().trim_end_matches('/'))
        .map(|url| url.to_string().trim_end_matches('/').to_string())
        .map_err(|_| "invalid message publication relay".to_string())
}

impl AppState {
    /// Replace a signer under the same lock used by publication snapshots.
    pub(crate) fn replace_publication_keys(
        &self,
        keys: Keys,
        storage: Option<crate::app_state::IdentityStorage>,
    ) -> Result<(), String> {
        let mut epoch = self.publication_epoch.lock().map_err(|e| e.to_string())?;
        let mut active = self.keys.lock().map_err(|e| e.to_string())?;
        if active.public_key() != keys.public_key() {
            *epoch += 1;
        }
        *active = keys;
        if let Some(storage) = storage {
            self.set_identity_storage(storage);
        }
        Ok(())
    }

    /// Apply relay and optional signer as one publication scope transition.
    pub(crate) fn apply_publication_workspace(
        &self,
        relay_url: String,
        keys: Option<Keys>,
    ) -> Result<(), String> {
        let mut epoch = self.publication_epoch.lock().map_err(|e| e.to_string())?;
        let mut active = self.keys.lock().map_err(|e| e.to_string())?;
        let mut relay = self.relay_url_override.lock().map_err(|e| e.to_string())?;
        let previous_relay = relay.clone().unwrap_or_else(super::relay_ws_url);
        if canonical_relay(&previous_relay)? != canonical_relay(&relay_url)?
            || keys
                .as_ref()
                .is_some_and(|keys| keys.public_key() != active.public_key())
        {
            *epoch += 1;
        }
        *relay = Some(relay_url);
        if let Some(keys) = keys {
            *active = keys;
        }
        Ok(())
    }
}

/// Public metadata captured before the renderer starts asynchronous preparation.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicationSnapshot {
    pub pubkey: String,
    pub relay_url: String,
    pub native_epoch: u64,
}

/// Immutable signer/destination plus a revocable native scope epoch.
pub struct MessagePublication {
    pub keys: Keys,
    pub api_base_url: String,
    relay_url: String,
    epoch: u64,
    owner: Arc<Mutex<u64>>,
}

impl MessagePublication {
    /// Capture before command preparation and validate the renderer's earlier snapshot.
    pub fn capture(
        state: &AppState,
        expected: Option<&ExpectedPublicationScope>,
    ) -> Result<Self, String> {
        let epoch = state.publication_epoch.lock().map_err(|e| e.to_string())?;
        let keys = state.signing_keys()?;
        let relay_url = super::relay_ws_url_with_override(state);
        if let Some(expected) = expected {
            expected.validate(&keys, &relay_url)?;
            if expected
                .native_epoch
                .is_some_and(|expected| expected != *epoch)
            {
                return Err("message cancelled because the identity or community changed".into());
            }
        }
        Ok(Self {
            keys,
            api_base_url: super::relay_http_base_url(&relay_url),
            relay_url,
            epoch: *epoch,
            owner: state.publication_epoch.clone(),
        })
    }

    /// Reject pending preparation/signing/publication after any scope transition.
    pub fn validate(&self) -> Result<(), String> {
        self.lock_validated().map(drop)
    }

    /// Fence local mutations against identity changes without relocking the epoch.
    pub(crate) fn lock_validated(&self) -> Result<MutexGuard<'_, u64>, String> {
        let epoch = self.owner.lock().map_err(|e| e.to_string())?;
        if *epoch != self.epoch {
            return Err("message cancelled because the identity or community changed".into());
        }
        Ok(epoch)
    }

    /// Return public scope metadata; signing keys never cross IPC.
    pub fn snapshot(&self) -> PublicationSnapshot {
        PublicationSnapshot {
            pubkey: self.keys.public_key().to_hex(),
            relay_url: self.relay_url.clone(),
            native_epoch: self.epoch,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expected_scope_rejects_actual_signer_and_relay_changes() {
        let keys = Keys::generate();
        let scope = ExpectedPublicationScope {
            pubkey: keys.public_key().to_hex(),
            relay_url: "wss://relay.example/Team".into(),
            native_epoch: None,
        };
        assert!(scope.validate(&keys, "wss://RELAY.example/Team/").is_ok());
        assert!(scope
            .validate(&Keys::generate(), "wss://relay.example/Team")
            .is_err());
        assert!(scope.validate(&keys, "wss://relay.example/team").is_err());
        assert!(scope.validate(&keys, "wss://other.example/Team").is_err());
    }
}
