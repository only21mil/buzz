//! Bounded, relay/identity-local project authority reads for prompt context.
use crate::prompt_project::{pick_authoritative_project_home, PromptProjectInfo};
use crate::relay::RestClient;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use uuid::Uuid;

const FRESHNESS: Duration = Duration::from_secs(30);
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(6);
type Snapshot = (Instant, Option<PromptProjectInfo>);

/// Created with one signed REST client; snapshots never cross relay or identity.
#[derive(Debug, Clone)]
pub(crate) struct ProjectResolver {
    rest: RestClient,
    cache: Arc<RwLock<HashMap<Uuid, Snapshot>>>,
}

impl ProjectResolver {
    pub(crate) fn new(rest: RestClient) -> Self {
        Self {
            rest,
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub(crate) async fn resolve(&self, channel: Uuid) -> Result<Option<PromptProjectInfo>, String> {
        if let Some((fetched, value)) = self
            .cache
            .read()
            .ok()
            .and_then(|cache| cache.get(&channel).cloned())
        {
            if fetched.elapsed() < FRESHNESS {
                return Ok(value);
            }
        }
        let value = tokio::time::timeout(LOOKUP_TIMEOUT, self.fetch(channel))
            .await
            .map_err(|_| "project authority lookup timed out".to_string())??;
        if let Ok(mut cache) = self.cache.write() {
            // Bound long-running harnesses without retaining stale authority.
            cache.retain(|_, (fetched, _)| fetched.elapsed() < FRESHNESS);
            if cache.len() >= 256 {
                if let Some(oldest) = cache
                    .iter()
                    .min_by_key(|(_, (fetched, _))| *fetched)
                    .map(|(id, _)| *id)
                {
                    cache.remove(&oldest);
                }
            }
            cache.insert(channel, (Instant::now(), value.clone()));
        }
        Ok(value)
    }

    async fn fetch(&self, channel: Uuid) -> Result<Option<PromptProjectInfo>, String> {
        let query =
            |kind| serde_json::json!({"kinds": [kind], "#buzz-channel": [channel.to_string()]});
        let projects = self
            .rest
            .query_raw_all(query(30621))
            .await
            .map_err(|e| e.to_string())?;
        let repositories = self
            .rest
            .query_raw_all(query(30617))
            .await
            .map_err(|e| e.to_string())?;
        Ok(pick_authoritative_project_home(
            &projects,
            &repositories,
            &channel.to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn server(
        responses: Vec<serde_json::Value>,
    ) -> (
        ProjectResolver,
        Arc<AtomicUsize>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(AtomicUsize::new(0));
        let count = requests.clone();
        let task = tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let mut buffer = vec![0; 65536];
                let read = socket.read(&mut buffer).await.unwrap();
                assert!(String::from_utf8_lossy(&buffer[..read]).contains("#buzz-channel"));
                let index = count.fetch_add(1, Ordering::SeqCst);
                let body = responses
                    .get(index)
                    .unwrap_or(&serde_json::Value::Null)
                    .to_string();
                socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).as_bytes()).await.unwrap();
            }
        });
        (
            ProjectResolver::new(RestClient {
                http: reqwest::Client::new(),
                base_url,
                keys: nostr::Keys::generate(),
                auth_tag_json: None,
            }),
            requests,
            task,
        )
    }

    fn authoritative_events(channel: Uuid) -> Vec<serde_json::Value> {
        let owner = "a".repeat(64);
        vec![
            json!([{"kind":30621,"pubkey":owner,"tags":[["d","app"],["buzz-channel",channel],["a",format!("30617:{owner}:app")]]}]),
            json!([{"kind":30617,"pubkey":owner,"tags":[["d","app"],["buzz-channel",channel]]}]),
        ]
    }

    #[tokio::test]
    async fn fresh_authority_reuses_reads_but_failed_refresh_rejects_stale() {
        let channel = Uuid::new_v4();
        let (resolver, requests, task) = server(authoritative_events(channel)).await;
        assert_eq!(
            resolver.resolve(channel).await.unwrap().unwrap().slug,
            "app"
        );
        assert!(resolver.resolve(channel).await.unwrap().is_some());
        assert_eq!(requests.load(Ordering::SeqCst), 2);
        resolver.cache.write().unwrap().get_mut(&channel).unwrap().0 = Instant::now() - FRESHNESS;
        assert!(resolver.resolve(channel).await.is_err());
        task.abort();
    }

    #[tokio::test]
    async fn absence_is_cached_per_channel_and_not_shared_by_new_identity() {
        let channel = Uuid::new_v4();
        let (resolver, requests, task) = server(vec![json!([]); 8]).await;
        assert!(resolver.resolve(channel).await.unwrap().is_none());
        assert!(resolver.resolve(channel).await.unwrap().is_none());
        assert_eq!(requests.load(Ordering::SeqCst), 2);
        resolver.resolve(Uuid::new_v4()).await.unwrap();
        let mut rest = resolver.rest.clone();
        rest.keys = nostr::Keys::generate();
        ProjectResolver::new(rest).resolve(channel).await.unwrap();
        assert_eq!(requests.load(Ordering::SeqCst), 6);
        task.abort();
    }
}
