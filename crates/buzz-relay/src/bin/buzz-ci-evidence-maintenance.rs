//! Run one bounded, resumable CI evidence maintenance cycle.

use std::fs::{self, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr as _;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use buzz_media::{
    maintain_ci_evidence_page, CiEvidenceMaintenanceFailure, CiEvidenceMaintenanceLimits,
    MediaConfig, MediaStorage, S3AddressingStyle,
};
use serde::{Deserialize, Serialize};

const CONFIG_PATH: &str = "/etc/buzzci/evidence-maintenance-v1.json";
const CURSOR_PATH: &str = "/var/lib/buzzci/evidence-maintenance/cursor-v1.json";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MaintenanceConfig {
    schema_version: u32,
    page_size: usize,
    max_pages: usize,
    max_listed_objects: usize,
    max_receipt_bytes: u64,
    max_reported_failures: usize,
    timeout_seconds: u64,
}

impl MaintenanceConfig {
    fn load(path: &Path) -> Result<Self, String> {
        let bytes = fs::read(path).map_err(|_| "configuration read failed".to_owned())?;
        let config: Self =
            serde_json::from_slice(&bytes).map_err(|_| "configuration is invalid".to_owned())?;
        if config.schema_version != 1
            || !(1..=1_000).contains(&config.page_size)
            || !(1..=100).contains(&config.max_pages)
            || !(1..=100_000).contains(&config.max_listed_objects)
            || !(1..=65_536).contains(&config.max_receipt_bytes)
            || config.max_reported_failures > 100
            || !(1..=900).contains(&config.timeout_seconds)
        {
            return Err("configuration limits are invalid".to_owned());
        }
        Ok(config)
    }
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    schema_version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    continuation_token: Option<String>,
}

impl Cursor {
    fn load(path: &Path) -> Result<Self, String> {
        match fs::read(path) {
            Ok(bytes) => {
                let cursor: Self = serde_json::from_slice(&bytes)
                    .map_err(|_| "cursor state is invalid".to_owned())?;
                if cursor.schema_version != 1 {
                    return Err("cursor schema is unsupported".to_owned());
                }
                Ok(cursor)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Self {
                schema_version: 1,
                continuation_token: None,
            }),
            Err(_) => Err("cursor state read failed".to_owned()),
        }
    }

    fn store(&self, path: &Path) -> Result<(), String> {
        let parent = path
            .parent()
            .ok_or_else(|| "cursor state path has no parent".to_owned())?;
        let temporary = parent.join(format!(".cursor-v1.{}.tmp", std::process::id()));
        let bytes = serde_json::to_vec(self).map_err(|_| "cursor encoding failed".to_owned())?;
        let mut options = OpenOptions::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|_| "cursor temporary file creation failed".to_owned())?;
        let result = (|| {
            file.write_all(&bytes)
                .map_err(|_| "cursor state write failed".to_owned())?;
            file.sync_all()
                .map_err(|_| "cursor state sync failed".to_owned())?;
            fs::rename(&temporary, path).map_err(|_| "cursor state replace failed".to_owned())?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }
}

#[derive(Debug, Default, Serialize)]
struct Summary {
    status: &'static str,
    completed_cycle: bool,
    pages: usize,
    listed_objects: usize,
    inspected_receipts: usize,
    retained: usize,
    tombstoned: usize,
    purged: usize,
    ignored_objects: usize,
    failure_count: usize,
    failures: Vec<CiEvidenceMaintenanceFailure>,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(summary) => {
            let code = if summary.failure_count == 0 { 0 } else { 2 };
            if serde_json::to_writer(io::stdout().lock(), &summary).is_err() {
                return ExitCode::from(3);
            }
            println!();
            ExitCode::from(code)
        }
        Err(reason) => {
            let _ = serde_json::to_writer(
                io::stderr().lock(),
                &serde_json::json!({"status": "failed", "reason": reason}),
            );
            eprintln!();
            ExitCode::from(1)
        }
    }
}

async fn run() -> Result<Summary, String> {
    let config_path = std::env::var_os("BUZZ_CI_EVIDENCE_MAINTENANCE_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(CONFIG_PATH));
    let cursor_path = std::env::var_os("BUZZ_CI_EVIDENCE_MAINTENANCE_CURSOR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(CURSOR_PATH));
    let config = MaintenanceConfig::load(&config_path)?;
    let mut cursor = Cursor::load(&cursor_path)?;
    let storage = MediaStorage::new(&media_config_from_env()?)
        .map_err(|_| "storage initialization failed".to_owned())?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is before Unix epoch".to_owned())?
        .as_secs();
    let started = Instant::now();
    let deadline = Duration::from_secs(config.timeout_seconds);
    let mut summary = Summary {
        status: "completed",
        ..Summary::default()
    };

    while summary.pages < config.max_pages
        && summary.listed_objects < config.max_listed_objects
        && started.elapsed() < deadline
    {
        let remaining_objects = config.max_listed_objects - summary.listed_objects;
        let page_size = config.page_size.min(remaining_objects);
        let remaining_time = deadline.saturating_sub(started.elapsed());
        let page = tokio::time::timeout(
            remaining_time,
            maintain_ci_evidence_page(
                &storage,
                cursor.continuation_token.clone(),
                now,
                CiEvidenceMaintenanceLimits {
                    page_size,
                    max_receipt_bytes: config.max_receipt_bytes,
                    max_reported_failures: config.max_reported_failures,
                },
            ),
        )
        .await
        .map_err(|_| "maintenance deadline exceeded".to_owned())?
        .map_err(|_| "storage maintenance page failed".to_owned())?;

        summary.pages += 1;
        summary.listed_objects += page.listed_objects;
        summary.inspected_receipts += page.inspected_receipts;
        summary.retained += page.retained;
        summary.tombstoned += page.tombstoned;
        summary.purged += page.purged;
        summary.ignored_objects += page.ignored_objects;
        summary.failure_count += page.failure_count;
        let remaining_failures = config
            .max_reported_failures
            .saturating_sub(summary.failures.len());
        summary
            .failures
            .extend(page.failures.into_iter().take(remaining_failures));

        cursor.continuation_token = page.next_continuation_token;
        cursor.store(&cursor_path)?;
        if cursor.continuation_token.is_none() {
            summary.completed_cycle = true;
            break;
        }
    }

    if !summary.completed_cycle {
        summary.status = "bounded";
    } else if summary.failure_count > 0 {
        summary.status = "completed_with_failures";
    }
    Ok(summary)
}

fn media_config_from_env() -> Result<MediaConfig, String> {
    fn required(name: &str) -> Result<String, String> {
        std::env::var(name).map_err(|_| format!("{name} is required"))
    }
    let addressing =
        std::env::var("BUZZ_S3_ADDRESSING_STYLE").unwrap_or_else(|_| "path".to_owned());
    Ok(MediaConfig {
        s3_endpoint: required("BUZZ_S3_ENDPOINT")?,
        s3_access_key: std::env::var("BUZZ_S3_ACCESS_KEY").unwrap_or_default(),
        s3_secret_key: std::env::var("BUZZ_S3_SECRET_KEY").unwrap_or_default(),
        s3_bucket: required("BUZZ_S3_BUCKET")?,
        s3_region: std::env::var("BUZZ_S3_REGION").unwrap_or_else(|_| "us-east-1".to_owned()),
        s3_addressing_style: S3AddressingStyle::from_str(&addressing)?,
        max_image_bytes: 1,
        max_gif_bytes: 1,
        max_video_bytes: 1,
        max_file_bytes: 1,
        public_base_url: "http://localhost/media".to_owned(),
        upload_records_enabled: false,
        upload_ip_header: None,
        upload_port_header: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_round_trip_uses_atomic_fake_root_file() {
        let root = tempfile::tempdir().expect("fake root");
        let path = root.path().join("cursor.json");
        let cursor = Cursor {
            schema_version: 1,
            continuation_token: Some("opaque-token".to_owned()),
        };
        cursor.store(&path).expect("store cursor");
        assert_eq!(
            Cursor::load(&path).expect("load cursor").continuation_token,
            cursor.continuation_token
        );
    }

    #[test]
    fn config_rejects_unbounded_values_and_unknown_fields() {
        let root = tempfile::tempdir().expect("fake root");
        let path = root.path().join("config.json");
        fs::write(
            &path,
            br#"{"schema_version":1,"page_size":1001,"max_pages":1,"max_listed_objects":1,"max_receipt_bytes":1,"max_reported_failures":0,"timeout_seconds":1}"#,
        )
        .expect("write config");
        assert!(MaintenanceConfig::load(&path).is_err());
        fs::write(
            &path,
            br#"{"schema_version":1,"page_size":1,"max_pages":1,"max_listed_objects":1,"max_receipt_bytes":1,"max_reported_failures":0,"timeout_seconds":1,"extra":true}"#,
        )
        .expect("write config");
        assert!(MaintenanceConfig::load(&path).is_err());
    }
}
