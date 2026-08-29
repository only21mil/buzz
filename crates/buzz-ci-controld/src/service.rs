//! Closed service state used before production capabilities are connected.

use std::thread;

use buzz_ci_controld::store::{DurableControlStore, StoreError};
use serde::Serialize;
use thiserror::Error;

use crate::config::DaemonConfig;

const STATUS_SCHEMA_VERSION: u32 = 1;

/// Machine-readable startup state for a validated, deliberately closed daemon.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct ServiceStatus {
    schema_version: u32,
    state: ServiceState,
    capacity: u32,
    reason: ClosedReason,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ServiceState {
    ReadyClosed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ClosedReason {
    ProductionProvidersUnwired,
}

/// A locally validated daemon which owns no production capability.
pub(crate) struct CapacityZeroService {
    status: ServiceStatus,
    _store: DurableControlStore,
}

impl CapacityZeroService {
    pub(crate) fn start(
        config: &DaemonConfig,
        expected_owner_uid: u32,
    ) -> Result<Self, ServiceError> {
        let store = DurableControlStore::open(config.store_root(), expected_owner_uid)?;
        Ok(Self {
            status: ServiceStatus {
                schema_version: STATUS_SCHEMA_VERSION,
                state: ServiceState::ReadyClosed,
                capacity: config.capacity(),
                reason: ClosedReason::ProductionProvidersUnwired,
            },
            _store: store,
        })
    }

    pub(crate) const fn status(&self) -> ServiceStatus {
        self.status
    }

    /// Remain alive without polling, dispatching, networking, or signing.
    pub(crate) fn run(self) -> ! {
        loop {
            thread::park();
        }
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum ServiceError {
    #[error("durable control store validation failed")]
    Store(#[from] StoreError),
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use tempfile::TempDir;

    use super::*;
    use crate::config::DaemonConfig;

    fn config_fixture(store_mode: u32) -> (TempDir, DaemonConfig, u32) {
        let root = tempfile::tempdir().expect("temporary directory");
        let store = root.path().join("store");
        fs::create_dir(&store).expect("create store");
        fs::set_permissions(&store, fs::Permissions::from_mode(store_mode))
            .expect("set store mode");
        let owner_uid = fs::metadata(&store).expect("store metadata").uid();
        let config: DaemonConfig = serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "capacity": 0,
            "store_root": store,
        }))
        .expect("configuration fixture");
        (root, config, owner_uid)
    }

    #[test]
    fn reports_ready_but_closed_after_store_validation() {
        let (_root, config, owner_uid) = config_fixture(0o700);

        let service = CapacityZeroService::start(&config, owner_uid).expect("service starts");
        let status = serde_json::to_value(service.status()).expect("serialize status");

        assert_eq!(
            status,
            serde_json::json!({
                "schema_version": 1,
                "state": "ready_closed",
                "capacity": 0,
                "reason": "production_providers_unwired",
            })
        );
    }

    #[test]
    fn refuses_an_insecure_store() {
        let (_root, config, owner_uid) = config_fixture(0o750);

        assert_eq!(
            CapacityZeroService::start(&config, owner_uid).map(|service| service.status()),
            Err(ServiceError::Store(StoreError::InsecureMetadata))
        );
    }
}
