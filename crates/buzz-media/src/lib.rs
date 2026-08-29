//! Media storage, validation, and thumbnail generation for Buzz.
//!
//! Library crate — no Axum dependency for handlers. Axum handlers live in `buzz-relay`.

pub mod auth;
pub mod bucket_index;
pub mod ci_evidence;
pub mod ci_evidence_maintenance;
pub mod config;
pub mod error;
pub mod storage;
pub mod thumbnail;
pub mod types;
pub mod upload;
pub mod upload_record;
pub mod validation;

pub use bucket_index::{
    classify_key, fold_bucket_listing, BucketAggregate, BucketSnapshot, CommunityStorage, KeyClass,
    Page, SweepError,
};
pub use ci_evidence::{
    prepare_ci_evidence, read_ci_evidence_receipt, validate_ci_evidence_receipt, CiEvidenceBinding,
    CiEvidenceError, CiEvidenceOwner, CiEvidenceReceipt, CiEvidenceRetentionAction,
    PreparedCiEvidence, CI_EVIDENCE_RETENTION_SECONDS, CI_EVIDENCE_TOMBSTONE_SECONDS,
};
pub use ci_evidence_maintenance::{
    maintain_ci_evidence_page, CiEvidenceMaintenanceFailure, CiEvidenceMaintenanceLimits,
    CiEvidenceMaintenancePage, CiEvidenceMaintenanceStore,
};
pub use config::{MediaConfig, S3AddressingStyle};
pub use error::MediaError;
pub use storage::{BlobHeadMeta, BlobMeta, ByteStream, MediaStorage};
pub use types::BlobDescriptor;
pub use upload::{process_file_upload, process_upload, process_video_upload};
pub use upload_record::{
    parse_port, parse_public_ip, upload_record_key, UploadAttribution, UploadNetworkInfo,
    UploadRecord, UPLOAD_RECORD_VERSION,
};
pub use validation::{looks_like_iso_bmff, serve_inline, validate_video_file, VideoMeta};
