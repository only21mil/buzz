//! Bounded, receipt-authorized maintenance for durable CI evidence.

use serde::Serialize;

use crate::bucket_index::Page;
use crate::ci_evidence::{read_listed_ci_evidence_receipt, CiEvidenceRetentionAction};
use crate::error::MediaError;

/// The only storage namespace maintenance may enumerate.
pub const CI_EVIDENCE_PREFIX: &str = "_ci/v2/";
const RECEIPT_SUFFIX: &str = ".receipt.json";

/// Hard bounds for one storage page and its diagnostic output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CiEvidenceMaintenanceLimits {
    /// Maximum objects returned by the prefix listing.
    pub page_size: usize,
    /// Maximum receipt size accepted before buffering it.
    pub max_receipt_bytes: u64,
    /// Maximum per-receipt failures retained in the JSON result.
    pub max_reported_failures: usize,
}

impl CiEvidenceMaintenanceLimits {
    /// Reject zero or unreasonably large bounds before any storage call.
    pub fn validate(self) -> Result<Self, MediaError> {
        if !(1..=1_000).contains(&self.page_size)
            || !(1..=65_536).contains(&self.max_receipt_bytes)
            || self.max_reported_failures > 100
        {
            return Err(MediaError::StorageError(
                "invalid CI evidence maintenance limits".to_owned(),
            ));
        }
        Ok(self)
    }
}

/// One receipt that failed closed. Keys are bounded by the receipt schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CiEvidenceMaintenanceFailure {
    /// Listed receipt object key.
    pub receipt_key: String,
    /// Stable failure class without storage or credential detail.
    pub code: &'static str,
}

/// Result of one complete listing page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CiEvidenceMaintenancePage {
    /// Number of objects returned by the prefix listing.
    pub listed_objects: usize,
    /// Number of exact receipt-suffix objects inspected.
    pub inspected_receipts: usize,
    /// Receipts whose blobs are still retained.
    pub retained: usize,
    /// Blobs removed while their receipts remain as tombstones.
    pub tombstoned: usize,
    /// Receipts removed after their tombstone window.
    pub purged: usize,
    /// Receipt-free and unrelated objects ignored by design.
    pub ignored_objects: usize,
    /// Total failures, including failures omitted from `failures`.
    pub failure_count: usize,
    /// Bounded failure detail.
    pub failures: Vec<CiEvidenceMaintenanceFailure>,
    /// Next page token. `None` means the prefix cycle completed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_continuation_token: Option<String>,
}

/// Narrow storage operations needed by the maintenance caller.
#[allow(async_fn_in_trait)]
pub trait CiEvidenceMaintenanceStore: Sync {
    /// List one bounded page under the fixed CI evidence prefix.
    async fn list_ci_evidence_page(
        &self,
        continuation_token: Option<String>,
        max_keys: usize,
    ) -> Result<Page, MediaError>;

    /// Read one receipt after its listed size passed the bound.
    async fn get_ci_evidence_object(&self, key: &str) -> Result<Vec<u8>, MediaError>;

    /// Return whether an exact key exists.
    async fn ci_evidence_object_exists(&self, key: &str) -> Result<bool, MediaError>;

    /// Verify the full immutable size and digest before deletion.
    async fn verify_ci_evidence_object(
        &self,
        key: &str,
        expected_size: u64,
        expected_sha256: &str,
    ) -> Result<(), MediaError>;

    /// Delete one exact key.
    async fn delete_ci_evidence_object(&self, key: &str) -> Result<(), MediaError>;
}

/// Process one complete listing page.
///
/// The caller may persist the returned continuation token only after this
/// function returns. A crash therefore replays the whole page. Deletes are
/// idempotent, and no blob without a valid, self-bound receipt is touched.
pub async fn maintain_ci_evidence_page<S: CiEvidenceMaintenanceStore>(
    store: &S,
    continuation_token: Option<String>,
    now: u64,
    limits: CiEvidenceMaintenanceLimits,
) -> Result<CiEvidenceMaintenancePage, MediaError> {
    let limits = limits.validate()?;
    let page = store
        .list_ci_evidence_page(continuation_token, limits.page_size)
        .await?;
    if page.objects.len() > limits.page_size
        || page
            .next_continuation_token
            .as_deref()
            .is_some_and(|token| token.len() > 4_096)
    {
        return Err(MediaError::StorageError(
            "CI evidence listing exceeded its response bounds".to_owned(),
        ));
    }
    if page.is_truncated && page.next_continuation_token.is_none() {
        return Err(MediaError::StorageError(
            "CI evidence listing omitted its continuation token".to_owned(),
        ));
    }

    let mut result = CiEvidenceMaintenancePage {
        listed_objects: page.objects.len(),
        inspected_receipts: 0,
        retained: 0,
        tombstoned: 0,
        purged: 0,
        ignored_objects: 0,
        failure_count: 0,
        failures: Vec::new(),
        next_continuation_token: page.next_continuation_token,
    };

    for (receipt_key, listed_size) in page.objects {
        if !receipt_key.starts_with(CI_EVIDENCE_PREFIX) || !receipt_key.ends_with(RECEIPT_SUFFIX) {
            result.ignored_objects += 1;
            continue;
        }
        result.inspected_receipts += 1;
        if listed_size > limits.max_receipt_bytes {
            record_failure(&mut result, limits, receipt_key, "receipt_too_large");
            continue;
        }

        let receipt_bytes = match store.get_ci_evidence_object(&receipt_key).await {
            Ok(bytes) if bytes.len() as u64 <= limits.max_receipt_bytes => bytes,
            Ok(_) => {
                record_failure(&mut result, limits, receipt_key, "receipt_too_large");
                continue;
            }
            Err(_) => {
                record_failure(&mut result, limits, receipt_key, "receipt_read_failed");
                continue;
            }
        };
        let receipt = match read_listed_ci_evidence_receipt(&receipt_bytes, &receipt_key) {
            Ok(receipt) => receipt,
            Err(_) => {
                record_failure(&mut result, limits, receipt_key, "receipt_binding_invalid");
                continue;
            }
        };

        match receipt.retention_action(now) {
            CiEvidenceRetentionAction::Retain => result.retained += 1,
            CiEvidenceRetentionAction::Tombstone => {
                if remove_bound_blob(store, &receipt).await.is_ok() {
                    result.tombstoned += 1;
                } else {
                    record_failure(&mut result, limits, receipt_key, "blob_delete_failed");
                }
            }
            CiEvidenceRetentionAction::Purge => {
                if remove_bound_blob(store, &receipt).await.is_err() {
                    record_failure(&mut result, limits, receipt_key, "blob_delete_failed");
                    continue;
                }
                if store.delete_ci_evidence_object(&receipt_key).await.is_err()
                    || !matches!(
                        store.ci_evidence_object_exists(&receipt_key).await,
                        Ok(false)
                    )
                {
                    record_failure(&mut result, limits, receipt_key, "receipt_delete_failed");
                } else {
                    result.purged += 1;
                }
            }
        }
    }

    Ok(result)
}

async fn remove_bound_blob<S: CiEvidenceMaintenanceStore>(
    store: &S,
    receipt: &crate::ci_evidence::CiEvidenceReceipt,
) -> Result<(), MediaError> {
    if !store
        .ci_evidence_object_exists(&receipt.durable_object_key)
        .await?
    {
        return Ok(());
    }
    store
        .verify_ci_evidence_object(
            &receipt.durable_object_key,
            receipt.binding.byte_length,
            &receipt.binding.sha256,
        )
        .await?;
    store
        .delete_ci_evidence_object(&receipt.durable_object_key)
        .await?;
    if store
        .ci_evidence_object_exists(&receipt.durable_object_key)
        .await?
    {
        return Err(MediaError::StorageError(
            "CI evidence object remained after delete".to_owned(),
        ));
    }
    Ok(())
}

fn record_failure(
    result: &mut CiEvidenceMaintenancePage,
    limits: CiEvidenceMaintenanceLimits,
    receipt_key: String,
    code: &'static str,
) {
    result.failure_count += 1;
    if result.failures.len() < limits.max_reported_failures {
        result
            .failures
            .push(CiEvidenceMaintenanceFailure { receipt_key, code });
    }
}

impl CiEvidenceMaintenanceStore for crate::storage::MediaStorage {
    async fn list_ci_evidence_page(
        &self,
        continuation_token: Option<String>,
        max_keys: usize,
    ) -> Result<Page, MediaError> {
        self.list_prefix_page(CI_EVIDENCE_PREFIX, continuation_token, max_keys)
            .await
    }

    async fn get_ci_evidence_object(&self, key: &str) -> Result<Vec<u8>, MediaError> {
        self.get(key).await
    }

    async fn ci_evidence_object_exists(&self, key: &str) -> Result<bool, MediaError> {
        self.head(key).await
    }

    async fn verify_ci_evidence_object(
        &self,
        key: &str,
        expected_size: u64,
        expected_sha256: &str,
    ) -> Result<(), MediaError> {
        self.verify_exact_object(key, expected_size, expected_sha256)
            .await
    }

    async fn delete_ci_evidence_object(&self, key: &str) -> Result<(), MediaError> {
        self.delete(key).await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::ci_evidence::{prepare_ci_evidence, CiEvidenceBinding};

    #[derive(Default)]
    struct FakeStore {
        objects: Mutex<BTreeMap<String, Vec<u8>>>,
        listed: Mutex<Vec<(String, u64)>>,
    }

    impl FakeStore {
        fn insert(&self, key: String, bytes: Vec<u8>) {
            self.objects.lock().expect("objects").insert(key, bytes);
        }

        fn list(&self, key: String, size: u64) {
            self.listed.lock().expect("listed").push((key, size));
        }

        fn contains(&self, key: &str) -> bool {
            self.objects.lock().expect("objects").contains_key(key)
        }
    }

    impl CiEvidenceMaintenanceStore for FakeStore {
        async fn list_ci_evidence_page(
            &self,
            _continuation_token: Option<String>,
            max_keys: usize,
        ) -> Result<Page, MediaError> {
            let objects = self
                .listed
                .lock()
                .expect("listed")
                .iter()
                .take(max_keys)
                .cloned()
                .collect();
            Ok(Page {
                objects,
                next_continuation_token: None,
                is_truncated: false,
            })
        }

        async fn get_ci_evidence_object(&self, key: &str) -> Result<Vec<u8>, MediaError> {
            self.objects
                .lock()
                .expect("objects")
                .get(key)
                .cloned()
                .ok_or(MediaError::NotFound)
        }

        async fn ci_evidence_object_exists(&self, key: &str) -> Result<bool, MediaError> {
            Ok(self.contains(key))
        }

        async fn verify_ci_evidence_object(
            &self,
            key: &str,
            expected_size: u64,
            expected_sha256: &str,
        ) -> Result<(), MediaError> {
            let objects = self.objects.lock().expect("objects");
            let bytes = objects.get(key).ok_or(MediaError::NotFound)?;
            if bytes.len() as u64 != expected_size
                || hex::encode(Sha256::digest(bytes)) != expected_sha256
            {
                return Err(MediaError::StoredObjectIntegrityMismatch);
            }
            Ok(())
        }

        async fn delete_ci_evidence_object(&self, key: &str) -> Result<(), MediaError> {
            self.objects.lock().expect("objects").remove(key);
            Ok(())
        }
    }

    fn prepared(expires_at: u64, bytes: &[u8]) -> crate::ci_evidence::PreparedCiEvidence {
        prepare_ci_evidence(
            CiEvidenceBinding {
                community_id: "123e4567-e89b-12d3-a456-426614174099".to_owned(),
                target_repo_a: format!("30617:{}:buzz", "11".repeat(32)),
                workflow_id: "ci".to_owned(),
                tip_oid: "22".repeat(20),
                request_event_id: "33".repeat(32),
                run_id: "123e4567-e89b-12d3-a456-426614174011".to_owned(),
                job_id: "test_job".to_owned(),
                attempt: 2,
                object_id: None,
                sha256: hex::encode(Sha256::digest(bytes)),
                byte_length: bytes.len() as u64,
                request_expires_at: expires_at,
            },
            bytes,
        )
        .expect("prepared evidence")
    }

    fn limits() -> CiEvidenceMaintenanceLimits {
        CiEvidenceMaintenanceLimits {
            page_size: 100,
            max_receipt_bytes: 65_536,
            max_reported_failures: 2,
        }
    }

    #[tokio::test]
    async fn retain_tombstone_and_purge_are_idempotent() {
        let store = FakeStore::default();
        let retained = prepared(10_000_000, b"retain");
        let tombstone = prepared(1_000_000, b"tombstone");
        let purge = prepared(1, b"purge");
        for item in [&retained, &tombstone, &purge] {
            store.insert(item.receipt.durable_object_key.clone(), item.bytes.clone());
            store.insert(item.receipt.receipt_key.clone(), item.receipt_bytes.clone());
            store.list(
                item.receipt.receipt_key.clone(),
                item.receipt_bytes.len() as u64,
            );
        }
        let now = tombstone.receipt.retain_until + 1;
        assert!(now <= tombstone.receipt.tombstone_until);
        assert!(now > purge.receipt.tombstone_until);

        let first = maintain_ci_evidence_page(&store, None, now, limits())
            .await
            .expect("first pass");
        assert_eq!((first.retained, first.tombstoned, first.purged), (1, 1, 1));
        assert!(store.contains(&retained.receipt.durable_object_key));
        assert!(!store.contains(&tombstone.receipt.durable_object_key));
        assert!(store.contains(&tombstone.receipt.receipt_key));
        assert!(!store.contains(&purge.receipt.durable_object_key));
        assert!(!store.contains(&purge.receipt.receipt_key));

        let replay = maintain_ci_evidence_page(&store, None, now, limits())
            .await
            .expect("replay");
        assert_eq!(replay.failure_count, 1, "deleted receipt listing is stale");
        assert_eq!(
            replay.tombstoned, 1,
            "missing blob is an idempotent tombstone"
        );
    }

    #[tokio::test]
    async fn missing_or_invalid_receipt_never_authorizes_blob_deletion() {
        let store = FakeStore::default();
        let item = prepared(1, b"protected");
        store.insert(item.receipt.durable_object_key.clone(), item.bytes.clone());
        store.list(
            item.receipt.durable_object_key.clone(),
            item.bytes.len() as u64,
        );
        store.insert("_ci/v2/forged.receipt.json".to_owned(), item.receipt_bytes);
        store.list("_ci/v2/forged.receipt.json".to_owned(), 1);

        let result =
            maintain_ci_evidence_page(&store, None, item.receipt.tombstone_until + 1, limits())
                .await
                .expect("bounded pass");
        assert_eq!(result.ignored_objects, 1);
        assert_eq!(result.failure_count, 1);
        assert!(store.contains(&item.receipt.durable_object_key));
    }

    #[tokio::test]
    async fn digest_mismatch_fails_closed_and_failure_output_is_bounded() {
        let store = FakeStore::default();
        for attempt in 1..=3 {
            let mut item = prepared(1, b"expected");
            item.receipt.binding.attempt = attempt;
            let item = prepare_ci_evidence(item.receipt.binding, b"expected").expect("attempt");
            store.insert(
                item.receipt.durable_object_key.clone(),
                b"tampered".to_vec(),
            );
            store.insert(item.receipt.receipt_key.clone(), item.receipt_bytes.clone());
            store.list(item.receipt.receipt_key, item.receipt_bytes.len() as u64);
        }
        let result = maintain_ci_evidence_page(&store, None, u64::MAX, limits())
            .await
            .expect("bounded pass");
        assert_eq!(result.failure_count, 3);
        assert_eq!(result.failures.len(), 2);
        assert_eq!(store.objects.lock().expect("objects").len(), 6);
    }
}
