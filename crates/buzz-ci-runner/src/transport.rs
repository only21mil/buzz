//! Frozen version-1 socket frames shared by controld and the key-free runner.
//!
//! This module contains transport shape and ordering only. It does not grant a
//! peer authority, validate evidence paths, execute jobs, retry dispatches, or
//! publish evidence.

use std::collections::HashSet;
use std::fmt;
use std::io::{self, Read, Write};

pub use buzz_ci_controld::{RUNNER_CONTROL_SOCKET_PATH, RUNNER_OUTPUT_ROOT};
use buzz_core::ci::{
    CiJobState, CiRequestEnvelope, CiTeardownAttestationEnvelope, CI_MAX_SAFE_INTEGER,
};
use serde::de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const SYSTEMD_LISTEN_FD: i32 = 3;
pub const SYSTEMD_FD_NAME: &str = "buzz-ci-runner-control";
pub const RUNNER_TRANSPORT_SCHEMA_VERSION: u32 = 1;
pub const MAX_FRAME_BODY_BYTES: usize = 1024 * 1024;
pub const RECEIPT_SET_DIGEST_DOMAIN: &[u8] = b"buzz-ci-runner:receipt-set:v1\0";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum RunnerRequest {
    #[serde(rename = "execute_attempt")]
    ExecuteAttempt {
        schema_version: u32,
        dispatch_id: String,
        request_event_id: String,
        request_event: CiRequestEnvelope,
        signed_request_digest: String,
        assigned_at: u64,
        deadline_at: u64,
        jobs: Vec<ExecuteJob>,
    },
}

impl RunnerRequest {
    pub const fn schema_version(&self) -> u32 {
        match self {
            Self::ExecuteAttempt { schema_version, .. } => *schema_version,
        }
    }

    fn has_valid_transport_shape(&self) -> bool {
        match self {
            Self::ExecuteAttempt {
                dispatch_id,
                request_event_id,
                request_event,
                signed_request_digest,
                assigned_at,
                deadline_at,
                jobs,
                ..
            } => {
                let mut job_ids = HashSet::with_capacity(jobs.len());
                uuid::Uuid::parse_str(dispatch_id).is_ok()
                    && is_lower_hex(request_event_id, 64)
                    && is_lower_hex(signed_request_digest, 64)
                    && request_event.validate().is_ok()
                    && *assigned_at > 0
                    && *assigned_at <= CI_MAX_SAFE_INTEGER
                    && *deadline_at > *assigned_at
                    && *deadline_at <= CI_MAX_SAFE_INTEGER
                    && *deadline_at <= request_event.expires_at
                    && deadline_at.saturating_sub(*assigned_at) <= request_event.timeout_seconds
                    && !jobs.is_empty()
                    && jobs.iter().all(|job| {
                        !job.job_id.is_empty()
                            && job.attempt > 0
                            && !job.workflow_path.is_empty()
                            && !job.job_manifest.is_empty()
                            && is_lower_hex(&job.job_manifest_digest, 64)
                            && is_lower_hex(&job.audience_digest, 64)
                            && is_lower_hex(&job.isolation_profile_digest, 64)
                            && job_ids.insert(job.job_id.as_str())
                    })
                    && job_ids.len() == request_event.job_ids.len()
                    && request_event
                        .job_ids
                        .iter()
                        .all(|job_id| job_ids.contains(job_id.as_str()))
            }
        }
    }

    pub fn refusal_identity(&self) -> (&str, &str, &str, u32) {
        match self {
            Self::ExecuteAttempt {
                dispatch_id,
                request_event_id,
                request_event,
                ..
            } => (
                dispatch_id,
                request_event_id,
                request_event.run_id.as_str(),
                request_event.attempt,
            ),
        }
    }
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecuteJob {
    pub job_id: String,
    pub attempt: u32,
    pub parent_attempt: u32,
    pub workflow_path: String,
    pub job_manifest: String,
    pub job_manifest_digest: String,
    pub audience_digest: String,
    pub isolation_profile_digest: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalReason {
    InvalidRequest,
    Unauthorized,
    Expired,
    InvalidManifest,
    DeadlineExceeded,
    BackendUnavailable,
    BrokerRefused,
    ReconciliationFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptOutcome {
    Completed,
    InfrastructureFailure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptFailureReason {
    BackendUnavailable,
    ExecutionFailed,
    EvidenceInvalid,
    DeadlineExceeded,
    TeardownUnproven,
    ReconciliationFailed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogEvidence {
    pub relative_path: String,
    pub sha256: String,
    pub byte_length: u64,
    pub cap_bytes: u64,
    pub truncated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactEvidence {
    pub relative_path: String,
    pub sha256: String,
    pub byte_length: u64,
    pub media_type: String,
    pub logical_name: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedJobAttempt {
    pub job_id: String,
    pub attempt: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum RunnerReceipt {
    #[serde(rename = "accepted")]
    Accepted {
        schema_version: u32,
        dispatch_id: String,
        request_event_id: String,
        run_id: String,
        attempt: u32,
        receipt_sequence: u64,
        accepted_at: u64,
    },
    #[serde(rename = "refused")]
    Refused {
        schema_version: u32,
        dispatch_id: String,
        request_event_id: String,
        run_id: String,
        attempt: u32,
        receipt_sequence: u64,
        reason: RefusalReason,
    },
    #[serde(rename = "job_started")]
    JobStarted {
        schema_version: u32,
        dispatch_id: String,
        request_event_id: String,
        run_id: String,
        attempt: u32,
        receipt_sequence: u64,
        job_id: String,
        job_attempt: u32,
        started_at: u64,
    },
    #[serde(rename = "job_finished")]
    JobFinished {
        schema_version: u32,
        dispatch_id: String,
        request_event_id: String,
        run_id: String,
        attempt: u32,
        receipt_sequence: u64,
        job_id: String,
        job_attempt: u32,
        state: CiJobState,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
        started_at: u64,
        finished_at: u64,
        log: LogEvidence,
        artifacts: Vec<ArtifactEvidence>,
    },
    #[serde(rename = "attempt_finished")]
    AttemptFinished {
        schema_version: u32,
        dispatch_id: String,
        request_event_id: String,
        run_id: String,
        attempt: u32,
        receipt_sequence: u64,
        outcome: AttemptOutcome,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<AttemptFailureReason>,
        finished_at: u64,
        selected_job_attempts: Vec<SelectedJobAttempt>,
        #[serde(skip_serializing_if = "Option::is_none")]
        teardown_attestation: Option<CiTeardownAttestationEnvelope>,
        receipt_set_digest: String,
    },
}

impl RunnerReceipt {
    pub const fn schema_version(&self) -> u32 {
        match self {
            Self::Accepted { schema_version, .. }
            | Self::Refused { schema_version, .. }
            | Self::JobStarted { schema_version, .. }
            | Self::JobFinished { schema_version, .. }
            | Self::AttemptFinished { schema_version, .. } => *schema_version,
        }
    }

    pub const fn receipt_sequence(&self) -> u64 {
        match self {
            Self::Accepted {
                receipt_sequence, ..
            }
            | Self::Refused {
                receipt_sequence, ..
            }
            | Self::JobStarted {
                receipt_sequence, ..
            }
            | Self::JobFinished {
                receipt_sequence, ..
            }
            | Self::AttemptFinished {
                receipt_sequence, ..
            } => *receipt_sequence,
        }
    }

    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Refused { .. } | Self::AttemptFinished { .. })
    }

    fn has_safe_timestamps(&self) -> bool {
        match self {
            Self::Accepted { accepted_at, .. } => *accepted_at <= CI_MAX_SAFE_INTEGER,
            Self::Refused { .. } => true,
            Self::JobStarted { started_at, .. } => *started_at <= CI_MAX_SAFE_INTEGER,
            Self::JobFinished {
                started_at,
                finished_at,
                ..
            } => *started_at <= CI_MAX_SAFE_INTEGER && *finished_at <= CI_MAX_SAFE_INTEGER,
            Self::AttemptFinished { finished_at, .. } => *finished_at <= CI_MAX_SAFE_INTEGER,
        }
    }

    fn has_valid_terminal_shape(&self) -> bool {
        match self {
            Self::JobFinished { state, .. } => state.is_terminal(),
            Self::AttemptFinished {
                outcome,
                reason,
                teardown_attestation,
                ..
            } => match outcome {
                AttemptOutcome::Completed => reason.is_none() && teardown_attestation.is_some(),
                AttemptOutcome::InfrastructureFailure => reason.is_some(),
            },
            _ => true,
        }
    }
}

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("frame I/O failed")]
    Io(#[source] io::Error),
    #[error("frame body exceeds one MiB")]
    Oversized,
    #[error("frame body is not UTF-8")]
    InvalidUtf8,
    #[error("frame JSON is invalid")]
    InvalidJson(#[source] serde_json::Error),
    #[error("transport schema version is unsupported")]
    UnsupportedSchema,
    #[error("request transport shape is invalid")]
    InvalidRequestShape,
}

pub fn read_frame<T: DeserializeOwned>(reader: &mut impl Read) -> Result<T, FrameError> {
    let mut prefix = [0_u8; 4];
    reader.read_exact(&mut prefix).map_err(FrameError::Io)?;
    let body_length = u32::from_be_bytes(prefix) as usize;
    if body_length > MAX_FRAME_BODY_BYTES {
        return Err(FrameError::Oversized);
    }

    let mut body = vec![0_u8; body_length];
    reader.read_exact(&mut body).map_err(FrameError::Io)?;
    std::str::from_utf8(&body).map_err(|_| FrameError::InvalidUtf8)?;
    reject_duplicate_keys(&body)?;
    serde_json::from_slice(&body).map_err(FrameError::InvalidJson)
}

pub fn read_request_frame(reader: &mut impl Read) -> Result<RunnerRequest, FrameError> {
    let request: RunnerRequest = read_frame(reader)?;
    if request.schema_version() != RUNNER_TRANSPORT_SCHEMA_VERSION {
        return Err(FrameError::UnsupportedSchema);
    }
    if !request.has_valid_transport_shape() {
        return Err(FrameError::InvalidRequestShape);
    }
    Ok(request)
}

/// Read one request and return SHA-256 of the exact length-prefixed frame bytes.
pub fn read_request_frame_with_digest(
    reader: &mut impl Read,
) -> Result<(RunnerRequest, [u8; 32]), FrameError> {
    let mut reader = DigestReader {
        inner: reader,
        hasher: Sha256::new(),
    };
    let request = read_request_frame(&mut reader)?;
    Ok((request, reader.hasher.finalize().into()))
}

struct DigestReader<'a, R> {
    inner: &'a mut R,
    hasher: Sha256,
}

impl<R: Read> Read for DigestReader<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.hasher.update(&buffer[..read]);
        Ok(read)
    }
}

pub fn encode_frame(value: &impl Serialize) -> Result<Vec<u8>, FrameError> {
    let body = serde_json::to_vec(value).map_err(FrameError::InvalidJson)?;
    if body.len() > MAX_FRAME_BODY_BYTES {
        return Err(FrameError::Oversized);
    }
    let body_length = u32::try_from(body.len()).map_err(|_| FrameError::Oversized)?;
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&body_length.to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

pub fn write_frame(writer: &mut impl Write, value: &impl Serialize) -> Result<(), FrameError> {
    let frame = encode_frame(value)?;
    writer.write_all(&frame).map_err(FrameError::Io)?;
    writer.flush().map_err(FrameError::Io)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReceiptState {
    AwaitingFirst,
    Accepted,
    Terminal,
}

#[derive(Debug, Error)]
pub enum ReceiptWriteError {
    #[error(transparent)]
    Frame(#[from] FrameError),
    #[error("receipt schema version is unsupported")]
    UnsupportedSchema,
    #[error("receipt sequence is not contiguous")]
    Sequence,
    #[error("first receipt must be accepted or refused")]
    InvalidFirstReceipt,
    #[error("receipt cannot follow a terminal receipt")]
    AlreadyTerminal,
    #[error("refused receipt cannot follow acceptance")]
    RefusedAfterAccepted,
    #[error("attempt_finished receipt-set digest does not match prior frames")]
    ReceiptSetDigest,
    #[error("receipt timestamp exceeds the maximum safe integer")]
    Timestamp,
    #[error("receipt terminal fields do not match the frozen shape")]
    TerminalShape,
}

pub struct ReceiptWriter<W> {
    writer: W,
    state: ReceiptState,
    next_sequence: u64,
    receipt_set_hasher: Sha256,
}

impl<W: Write> ReceiptWriter<W> {
    pub fn new(writer: W) -> Self {
        let mut receipt_set_hasher = Sha256::new();
        receipt_set_hasher.update(RECEIPT_SET_DIGEST_DOMAIN);
        Self {
            writer,
            state: ReceiptState::AwaitingFirst,
            next_sequence: 1,
            receipt_set_hasher,
        }
    }

    pub fn expected_receipt_set_digest(&self) -> String {
        hex::encode(self.receipt_set_hasher.clone().finalize())
    }

    pub fn send(&mut self, receipt: &RunnerReceipt) -> Result<(), ReceiptWriteError> {
        if self.state == ReceiptState::Terminal {
            return Err(ReceiptWriteError::AlreadyTerminal);
        }
        if receipt.schema_version() != RUNNER_TRANSPORT_SCHEMA_VERSION {
            return Err(ReceiptWriteError::UnsupportedSchema);
        }
        if receipt.receipt_sequence() != self.next_sequence {
            return Err(ReceiptWriteError::Sequence);
        }
        if !receipt.has_safe_timestamps() {
            return Err(ReceiptWriteError::Timestamp);
        }
        if !receipt.has_valid_terminal_shape() {
            return Err(ReceiptWriteError::TerminalShape);
        }

        match (self.state, receipt) {
            (ReceiptState::AwaitingFirst, RunnerReceipt::Accepted { .. }) => {}
            (ReceiptState::AwaitingFirst, RunnerReceipt::Refused { .. }) => {}
            (ReceiptState::AwaitingFirst, _) => return Err(ReceiptWriteError::InvalidFirstReceipt),
            (ReceiptState::Accepted, RunnerReceipt::Refused { .. }) => {
                return Err(ReceiptWriteError::RefusedAfterAccepted)
            }
            (ReceiptState::Accepted, _) => {}
            (ReceiptState::Terminal, _) => return Err(ReceiptWriteError::AlreadyTerminal),
        }

        if let RunnerReceipt::AttemptFinished {
            receipt_set_digest, ..
        } = receipt
        {
            if *receipt_set_digest != self.expected_receipt_set_digest() {
                return Err(ReceiptWriteError::ReceiptSetDigest);
            }
        }

        let frame = encode_frame(receipt)?;
        self.writer.write_all(&frame).map_err(FrameError::Io)?;
        self.writer.flush().map_err(FrameError::Io)?;

        if receipt.is_terminal() {
            self.state = ReceiptState::Terminal;
        } else {
            self.state = ReceiptState::Accepted;
            self.receipt_set_hasher.update(&frame);
        }
        self.next_sequence += 1;
        Ok(())
    }

    pub fn into_inner(self) -> W {
        self.writer
    }
}

fn reject_duplicate_keys(body: &[u8]) -> Result<(), FrameError> {
    serde_json::from_slice::<UniqueJsonValue>(body)
        .map(|_| ())
        .map_err(FrameError::InvalidJson)
}

struct UniqueJsonValue;

impl<'de> Deserialize<'de> for UniqueJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueJsonVisitor)
    }
}

struct UniqueJsonVisitor;

impl<'de> Visitor<'de> for UniqueJsonVisitor {
    type Value = UniqueJsonValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue)
    }

    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue)
    }

    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue)
    }

    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue)
    }

    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue)
    }

    fn visit_string<E>(self, _: String) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        UniqueJsonValue::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element::<UniqueJsonValue>()?.is_some() {}
        Ok(UniqueJsonValue)
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(de::Error::custom(format_args!("duplicate JSON key: {key}")));
            }
            map.next_value::<UniqueJsonValue>()?;
        }
        Ok(UniqueJsonValue)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn frame_body(body: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(4 + body.len());
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        frame.extend_from_slice(body);
        frame
    }

    fn accepted(sequence: u64) -> RunnerReceipt {
        RunnerReceipt::Accepted {
            schema_version: 1,
            dispatch_id: "00000000-0000-0000-0000-000000000001".into(),
            request_event_id: "00".repeat(32),
            run_id: "00000000-0000-0000-0000-000000000002".into(),
            attempt: 1,
            receipt_sequence: sequence,
            accepted_at: 1,
        }
    }

    #[test]
    fn frame_prefix_is_big_endian_and_body_is_bounded() {
        let encoded = encode_frame(&serde_json::json!({"ok": true})).expect("encode frame");
        assert_eq!(&encoded[..4], &[0, 0, 0, 11]);
        assert_eq!(&encoded[4..], br#"{"ok":true}"#);

        let mut oversized = Cursor::new((MAX_FRAME_BODY_BYTES as u32 + 1).to_be_bytes());
        assert!(matches!(
            read_frame::<serde_json::Value>(&mut oversized),
            Err(FrameError::Oversized)
        ));
    }

    #[test]
    fn frame_reader_rejects_duplicate_keys_at_any_depth() {
        let body = br#"{"schema_version":1,"nested":{"job_id":"one","job_id":"two"}}"#;
        let mut frame = Cursor::new(frame_body(body));
        assert!(matches!(
            read_frame::<serde_json::Value>(&mut frame),
            Err(FrameError::InvalidJson(_))
        ));
    }

    #[test]
    fn receipt_writer_requires_first_and_contiguous_receipts() {
        let mut writer = ReceiptWriter::new(Vec::new());
        assert!(matches!(
            writer.send(&RunnerReceipt::JobStarted {
                schema_version: 1,
                dispatch_id: "dispatch".into(),
                request_event_id: "request".into(),
                run_id: "run".into(),
                attempt: 1,
                receipt_sequence: 1,
                job_id: "job".into(),
                job_attempt: 1,
                started_at: 1,
            }),
            Err(ReceiptWriteError::InvalidFirstReceipt)
        ));
        writer.send(&accepted(1)).expect("accepted receipt");
        assert!(matches!(
            writer.send(&accepted(3)),
            Err(ReceiptWriteError::Sequence)
        ));
    }

    #[test]
    fn terminal_receipt_binds_prior_exact_frames() {
        let mut writer = ReceiptWriter::new(Vec::new());
        writer.send(&accepted(1)).expect("accepted receipt");
        let digest = writer.expected_receipt_set_digest();
        let terminal = RunnerReceipt::AttemptFinished {
            schema_version: 1,
            dispatch_id: "00000000-0000-0000-0000-000000000001".into(),
            request_event_id: "00".repeat(32),
            run_id: "00000000-0000-0000-0000-000000000002".into(),
            attempt: 1,
            receipt_sequence: 2,
            outcome: AttemptOutcome::InfrastructureFailure,
            reason: Some(AttemptFailureReason::ExecutionFailed),
            finished_at: 2,
            selected_job_attempts: Vec::new(),
            teardown_attestation: None,
            receipt_set_digest: digest,
        };
        writer.send(&terminal).expect("terminal receipt");
        assert!(matches!(
            writer.send(&accepted(3)),
            Err(ReceiptWriteError::AlreadyTerminal)
        ));
        assert!(!writer.into_inner().is_empty());
    }

    #[test]
    fn receipt_writer_rejects_unsafe_timestamps_and_invalid_terminal_shape() {
        let mut writer = ReceiptWriter::new(Vec::new());
        let unsafe_timestamp = RunnerReceipt::Accepted {
            schema_version: 1,
            dispatch_id: "dispatch".into(),
            request_event_id: "request".into(),
            run_id: "run".into(),
            attempt: 1,
            receipt_sequence: 1,
            accepted_at: CI_MAX_SAFE_INTEGER + 1,
        };
        assert!(matches!(
            writer.send(&unsafe_timestamp),
            Err(ReceiptWriteError::Timestamp)
        ));

        writer.send(&accepted(1)).expect("accepted receipt");
        let invalid_terminal = RunnerReceipt::AttemptFinished {
            schema_version: 1,
            dispatch_id: "dispatch".into(),
            request_event_id: "request".into(),
            run_id: "run".into(),
            attempt: 1,
            receipt_sequence: 2,
            outcome: AttemptOutcome::Completed,
            reason: None,
            finished_at: 2,
            selected_job_attempts: Vec::new(),
            teardown_attestation: None,
            receipt_set_digest: writer.expected_receipt_set_digest(),
        };
        assert!(matches!(
            writer.send(&invalid_terminal),
            Err(ReceiptWriteError::TerminalShape)
        ));
    }
}
