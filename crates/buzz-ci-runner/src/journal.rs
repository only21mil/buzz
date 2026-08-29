//! Durable terminal receipt journal. A terminal set is synced before publication.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::handler::{JournalWrite, ReceiptJournal, ReceiptJournalError};
use crate::host::validate_private_directory;
use crate::transport::{ReceiptWriter, RunnerReceipt};

const JOURNAL_SCHEMA_VERSION: u32 = 2;
const MAX_JOURNAL_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct DurableReceiptJournal {
    directory: PathBuf,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalRecord {
    schema_version: u32,
    dispatch_id: String,
    request_frame_digest: [u8; 32],
    receipts: Vec<RunnerReceipt>,
}

impl DurableReceiptJournal {
    pub fn open(directory: PathBuf) -> Result<Self, ReceiptJournalError> {
        validate_private_directory(&directory).map_err(|_| ReceiptJournalError)?;
        let journal = Self { directory };
        journal.recover_linked_temps()?;
        Ok(journal)
    }

    fn path(&self, dispatch_id: &str) -> Result<PathBuf, ReceiptJournalError> {
        uuid::Uuid::parse_str(dispatch_id).map_err(|_| ReceiptJournalError)?;
        Ok(self.directory.join(format!("{dispatch_id}.json")))
    }

    fn read(
        &self,
        path: &Path,
        dispatch_id: &str,
        expected_request_frame_digest: Option<[u8; 32]>,
    ) -> Result<Option<Vec<RunnerReceipt>>, ReceiptJournalError> {
        let mut file = match OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(ReceiptJournalError),
        };
        let metadata = file.metadata().map_err(|_| ReceiptJournalError)?;
        if !metadata.is_file()
            || metadata.permissions().mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
            || metadata.uid() != nix::unistd::Uid::effective().as_raw()
            || metadata.len() > MAX_JOURNAL_BYTES
        {
            return Err(ReceiptJournalError);
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        Read::by_ref(&mut file)
            .take(MAX_JOURNAL_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| ReceiptJournalError)?;
        if bytes.len() as u64 > MAX_JOURNAL_BYTES {
            return Err(ReceiptJournalError);
        }
        let record: JournalRecord =
            serde_json::from_slice(&bytes).map_err(|_| ReceiptJournalError)?;
        if record.schema_version != JOURNAL_SCHEMA_VERSION
            || record.dispatch_id != dispatch_id
            || expected_request_frame_digest
                .is_some_and(|expected| expected != record.request_frame_digest)
        {
            return Err(ReceiptJournalError);
        }
        validate_receipts(&record.receipts)?;
        Ok(Some(record.receipts))
    }

    fn recover_linked_temps(&self) -> Result<(), ReceiptJournalError> {
        for entry in fs::read_dir(&self.directory).map_err(|_| ReceiptJournalError)? {
            let entry = entry.map_err(|_| ReceiptJournalError)?;
            let name = entry.file_name();
            let name = name.to_str().ok_or(ReceiptJournalError)?;
            let Some(dispatch_id) = name
                .strip_prefix('.')
                .and_then(|name| name.strip_suffix(".tmp"))
            else {
                continue;
            };
            let final_path = self.path(dispatch_id)?;
            let temp_meta = fs::symlink_metadata(entry.path()).map_err(|_| ReceiptJournalError)?;
            match fs::symlink_metadata(&final_path) {
                Ok(final_meta)
                    if (temp_meta.dev(), temp_meta.ino())
                        == (final_meta.dev(), final_meta.ino()) =>
                {
                    fs::remove_file(entry.path()).map_err(|_| ReceiptJournalError)?;
                }
                Ok(_) => return Err(ReceiptJournalError),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    // A crash after syncing the temp but before linking the final name
                    // must promote the already-durable terminal set, never re-execute it.
                    self.read(&entry.path(), dispatch_id, None)?
                        .ok_or(ReceiptJournalError)?;
                    fs::hard_link(entry.path(), &final_path).map_err(|_| ReceiptJournalError)?;
                    fs::remove_file(entry.path()).map_err(|_| ReceiptJournalError)?;
                }
                Err(_) => return Err(ReceiptJournalError),
            }
        }
        File::open(&self.directory)
            .and_then(|file| file.sync_all())
            .map_err(|_| ReceiptJournalError)
    }
}

impl ReceiptJournal for DurableReceiptJournal {
    fn load(
        &self,
        dispatch_id: &str,
        request_frame_digest: [u8; 32],
    ) -> Result<Option<Vec<RunnerReceipt>>, ReceiptJournalError> {
        self.read(
            &self.path(dispatch_id)?,
            dispatch_id,
            Some(request_frame_digest),
        )
    }

    fn store_if_absent(
        &mut self,
        dispatch_id: &str,
        request_frame_digest: [u8; 32],
        receipts: &[RunnerReceipt],
    ) -> Result<JournalWrite, ReceiptJournalError> {
        validate_receipts(receipts)?;
        let final_path = self.path(dispatch_id)?;
        if let Some(existing) = self.read(&final_path, dispatch_id, Some(request_frame_digest))? {
            return Ok(JournalWrite::Existing(existing));
        }
        let temp_path = self.directory.join(format!(".{dispatch_id}.tmp"));
        let record = JournalRecord {
            schema_version: JOURNAL_SCHEMA_VERSION,
            dispatch_id: dispatch_id.to_owned(),
            request_frame_digest,
            receipts: receipts.to_vec(),
        };
        let bytes = serde_json::to_vec(&record).map_err(|_| ReceiptJournalError)?;
        if bytes.len() as u64 > MAX_JOURNAL_BYTES {
            return Err(ReceiptJournalError);
        }
        let mut temp = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&temp_path)
            .map_err(|_| ReceiptJournalError)?;
        temp.write_all(&bytes)
            .and_then(|()| temp.sync_all())
            .map_err(|_| ReceiptJournalError)?;
        File::open(&self.directory)
            .and_then(|file| file.sync_all())
            .map_err(|_| ReceiptJournalError)?;
        match fs::hard_link(&temp_path, &final_path) {
            Ok(()) => {
                fs::remove_file(&temp_path).map_err(|_| ReceiptJournalError)?;
                File::open(&self.directory)
                    .and_then(|file| file.sync_all())
                    .map_err(|_| ReceiptJournalError)?;
                Ok(JournalWrite::Written)
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                fs::remove_file(&temp_path).map_err(|_| ReceiptJournalError)?;
                self.read(&final_path, dispatch_id, Some(request_frame_digest))?
                    .map(JournalWrite::Existing)
                    .ok_or(ReceiptJournalError)
            }
            Err(_) => Err(ReceiptJournalError),
        }
    }
}

fn validate_receipts(receipts: &[RunnerReceipt]) -> Result<(), ReceiptJournalError> {
    if receipts.is_empty() || !receipts.last().is_some_and(RunnerReceipt::is_terminal) {
        return Err(ReceiptJournalError);
    }
    let mut sink = Vec::new();
    let mut writer = ReceiptWriter::new(&mut sink);
    for receipt in receipts {
        writer.send(receipt).map_err(|_| ReceiptJournalError)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{RefusalReason, RUNNER_TRANSPORT_SCHEMA_VERSION};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use tempfile::tempdir;

    const REQUEST_FRAME_DIGEST: [u8; 32] = [0x42; 32];

    fn terminal(sequence: u64) -> RunnerReceipt {
        RunnerReceipt::Refused {
            schema_version: RUNNER_TRANSPORT_SCHEMA_VERSION,
            dispatch_id: "123e4567-e89b-12d3-a456-426614174010".into(),
            request_event_id: "11".repeat(32),
            run_id: "123e4567-e89b-12d3-a456-426614174011".into(),
            attempt: 1,
            receipt_sequence: sequence,
            reason: RefusalReason::Unauthorized,
        }
    }

    #[test]
    fn synced_terminal_set_replays_across_restart_and_is_idempotent() {
        let directory = tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let id = "123e4567-e89b-12d3-a456-426614174010";
        let receipts = vec![terminal(1)];
        let mut journal = DurableReceiptJournal::open(directory.path().to_owned()).unwrap();
        assert_eq!(
            journal
                .store_if_absent(id, REQUEST_FRAME_DIGEST, &receipts)
                .unwrap(),
            JournalWrite::Written
        );
        assert_eq!(
            journal
                .store_if_absent(id, REQUEST_FRAME_DIGEST, &receipts)
                .unwrap(),
            JournalWrite::Existing(receipts.clone())
        );
        drop(journal);
        let restarted = DurableReceiptJournal::open(directory.path().to_owned()).unwrap();
        assert_eq!(
            restarted.load(id, REQUEST_FRAME_DIGEST).unwrap(),
            Some(receipts)
        );
        assert_eq!(restarted.load(id, [0x43; 32]), Err(ReceiptJournalError));
        let metadata = fs::metadata(directory.path().join(format!("{id}.json"))).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
        assert_eq!(metadata.nlink(), 1);
    }

    #[test]
    fn invalid_sequence_is_never_persisted() {
        let directory = tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut journal = DurableReceiptJournal::open(directory.path().to_owned()).unwrap();
        assert_eq!(
            journal.store_if_absent(
                "123e4567-e89b-12d3-a456-426614174010",
                REQUEST_FRAME_DIGEST,
                &[terminal(2)]
            ),
            Err(ReceiptJournalError)
        );
    }

    #[test]
    fn restart_repairs_crash_between_link_and_temp_unlink() {
        let directory = tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let id = "123e4567-e89b-12d3-a456-426614174010";
        let mut journal = DurableReceiptJournal::open(directory.path().to_owned()).unwrap();
        journal
            .store_if_absent(id, REQUEST_FRAME_DIGEST, &[terminal(1)])
            .unwrap();
        let final_path = directory.path().join(format!("{id}.json"));
        let temp_path = directory.path().join(format!(".{id}.tmp"));
        fs::hard_link(&final_path, &temp_path).unwrap();
        assert_eq!(fs::metadata(&final_path).unwrap().nlink(), 2);
        let restarted = DurableReceiptJournal::open(directory.path().to_owned()).unwrap();
        assert_eq!(fs::metadata(&final_path).unwrap().nlink(), 1);
        assert!(restarted.load(id, REQUEST_FRAME_DIGEST).unwrap().is_some());
    }

    #[test]
    fn restart_promotes_synced_temp_before_final_link() {
        let directory = tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let id = "123e4567-e89b-12d3-a456-426614174010";
        let mut journal = DurableReceiptJournal::open(directory.path().to_owned()).unwrap();
        journal
            .store_if_absent(id, REQUEST_FRAME_DIGEST, &[terminal(1)])
            .unwrap();
        let final_path = directory.path().join(format!("{id}.json"));
        let temp_path = directory.path().join(format!(".{id}.tmp"));
        fs::rename(&final_path, &temp_path).unwrap();
        let restarted = DurableReceiptJournal::open(directory.path().to_owned()).unwrap();
        assert!(!temp_path.exists());
        assert_eq!(
            restarted.load(id, REQUEST_FRAME_DIGEST).unwrap(),
            Some(vec![terminal(1)])
        );
    }
}
