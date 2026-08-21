use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Component, Path, PathBuf};

use rustix::fs::{renameat_with, RenameFlags};
use sha2::{Digest, Sha256};

use crate::{MaterializationManifest, MaterializationReceipt, MaterializeError, Sha256Digest};

/// One raw Git tree entry, obtained from a bounded `ls-tree` parser.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TreeEntry {
    /// Git mode. Phase 1 accepts regular files only.
    pub mode: u32,
    /// Blob object ID.
    pub object_id: String,
    /// Declared blob length.
    pub size: u64,
    /// UTF-8 relative path.
    pub path: PathBuf,
}

/// Parse bounded `git ls-tree -r -z -l --full-tree` output.
///
/// Only blob entries are accepted. Gitlinks, symlinks, malformed records,
/// duplicate paths, and output beyond `maximum_output_bytes` fail closed.
pub fn parse_ls_tree(
    bytes: &[u8],
    maximum_output_bytes: u64,
    maximum_entries: u32,
) -> Result<Vec<TreeEntry>, MaterializeError> {
    if bytes.len() as u64 > maximum_output_bytes {
        return Err(MaterializeError::ResourceLimit(
            "ls-tree output bytes".into(),
        ));
    }
    let mut entries = Vec::new();
    for record in bytes
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        if entries.len() >= maximum_entries as usize {
            return Err(MaterializeError::ResourceLimit("file count".into()));
        }
        let separator = record
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or_else(|| {
                MaterializeError::InvalidManifest("ls-tree record lacks path separator".into())
            })?;
        let (metadata, path_with_separator) = record.split_at(separator);
        let path = &path_with_separator[1..];
        let metadata = std::str::from_utf8(metadata).map_err(|_| {
            MaterializeError::InvalidManifest("ls-tree metadata is not UTF-8".into())
        })?;
        let fields = metadata.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() != 4 || fields[1] != "blob" {
            return Err(MaterializeError::UnsupportedFeature(
                "ls-tree contains a non-blob entry".into(),
            ));
        }
        let mode = u32::from_str_radix(fields[0], 8).map_err(|_| {
            MaterializeError::InvalidManifest("ls-tree contains an invalid mode".into())
        })?;
        let size = fields[3].parse::<u64>().map_err(|_| {
            MaterializeError::InvalidManifest("ls-tree contains an invalid size".into())
        })?;
        let object_id = fields[2];
        if !matches!(object_id.len(), 40 | 64)
            || !object_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(MaterializeError::InvalidManifest(
                "ls-tree contains an invalid object ID".into(),
            ));
        }
        let path = std::str::from_utf8(path).map_err(|_| {
            MaterializeError::UnsupportedFeature("non-UTF-8 repository path".into())
        })?;
        entries.push(TreeEntry {
            mode,
            object_id: object_id.into(),
            size,
            path: path.into(),
        });
    }
    if !bytes.is_empty() && !bytes.ends_with(&[0]) {
        return Err(MaterializeError::InvalidManifest(
            "ls-tree output lacks a terminal NUL".into(),
        ));
    }
    Ok(entries)
}

/// Supplies raw, length-bounded Git blob bytes without executing repository
/// filters, hooks, LFS, or checkout machinery.
pub(crate) trait BlobSource {
    /// Read one exact object, refusing to return more than `maximum_bytes`.
    fn read_blob(
        &mut self,
        object_id: &str,
        maximum_bytes: u64,
    ) -> Result<Vec<u8>, MaterializeError>;
}

/// Inputs and limits for one atomic tree publication.
pub(crate) struct TreeMaterialization<'a> {
    /// Signed materialization manifest.
    pub manifest: &'a MaterializationManifest,
    /// Validated regular-file tree entries.
    pub entries: &'a [TreeEntry],
    /// Fresh private staging path.
    pub staging: &'a Path,
    /// Absent destination path on the same filesystem.
    pub destination: &'a Path,
    /// Maximum raw blob bytes.
    pub maximum_blob_bytes: u64,
    /// Maximum aggregate tree bytes.
    pub maximum_checkout_bytes: u64,
    /// Maximum file count.
    pub maximum_entries: u32,
    /// Maximum relative-path bytes.
    pub maximum_path_bytes: u32,
    /// Maximum relative-path depth.
    pub maximum_depth: u16,
    /// Trusted-base workflow bytes.
    pub trusted_workflow: &'a [u8],
    /// Exact trusted-base workflow blob object ID.
    pub workflow_blob_oid: &'a str,
    /// Canonical broker-supplied input bytes.
    pub canonical_inputs: &'a [u8],
    /// Trusted wall clock used to stop publication at lease expiry.
    pub now_unix_seconds: &'a dyn Fn() -> u64,
    /// Absolute lease expiry.
    pub expires_at_unix_seconds: u64,
}

#[derive(Debug)]
pub(crate) struct VerifiedPublication {
    pub receipt: MaterializationReceipt,
    pub directory: File,
    pub device: u64,
    pub inode: u64,
}

/// Materialize validated regular blobs and atomically publish the tree.
///
/// The caller must provide a fresh private staging directory and an absent
/// destination within the same quota-backed filesystem. This function never
/// follows or creates symlinks and strips executable mode in Phase 1.
pub(crate) fn materialize_tree(
    request: TreeMaterialization<'_>,
    source: &mut dyn BlobSource,
) -> Result<VerifiedPublication, MaterializeError> {
    check_publication_deadline(&request)?;
    request.manifest.validate()?;
    if request.entries.len() > request.maximum_entries as usize {
        return Err(MaterializeError::ResourceLimit("file count".into()));
    }
    if request.staging.exists() || request.destination.exists() {
        return Err(MaterializeError::InvalidPolicy(
            "staging and destination must both be absent".into(),
        ));
    }
    fs::create_dir(request.staging)?;
    fs::set_permissions(request.staging, fs::Permissions::from_mode(0o700))?;

    let result = materialize_into(&request, source);
    let (checkout_digest, bytes) = match result {
        Ok(result) => result,
        Err(error) => {
            let _ = fs::remove_dir_all(request.staging);
            return Err(error);
        }
    };

    let mut published = false;
    let finalize_result = (|| {
        check_publication_deadline(&request)?;
        verify_digest(
            "checkout_sha256",
            &request.manifest.checkout_sha256,
            &checkout_digest,
        )?;
        verify_bytes(
            "workflow_sha256",
            &request.manifest.workflow_sha256,
            request.trusted_workflow,
        )?;
        verify_bytes(
            "inputs_sha256",
            &request.manifest.inputs_sha256,
            request.canonical_inputs,
        )?;
        make_read_only(request.staging)?;
        check_publication_deadline(&request)?;
        publish_no_replace(request.staging, request.destination)?;
        published = true;
        let directory = File::open(request.destination)?;
        let metadata = directory.metadata()?;
        let pinned = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
        let published_digest = digest_tree_from_disk(request.entries, &pinned)?;
        verify_digest(
            "published_checkout_sha256",
            &request.manifest.checkout_sha256,
            &published_digest,
        )?;
        if let Some(parent) = request.destination.parent() {
            fs::File::open(parent)?.sync_all()?;
        }
        check_publication_deadline(&request)?;
        Ok::<_, MaterializeError>((directory, metadata.dev(), metadata.ino()))
    })();
    let (directory, device, inode) = match finalize_result {
        Ok(result) => result,
        Err(error) => {
            let cleanup = if published {
                request.destination
            } else {
                request.staging
            };
            let _ = make_writable_for_cleanup(cleanup);
            let _ = fs::remove_dir_all(cleanup);
            return Err(error);
        }
    };

    Ok(VerifiedPublication {
        receipt: MaterializationReceipt {
            request_event_id: request.manifest.request_event_id.clone(),
            run_id: request.manifest.run_id.clone(),
            repo_coordinate: request.manifest.repo_coordinate.clone(),
            source_sha: request.manifest.source_sha.clone(),
            tree_oid: request.manifest.tree_oid.clone(),
            workflow_blob_oid: request.workflow_blob_oid.to_owned(),
            trusted_base_sha: request.manifest.trusted_base_sha.clone(),
            workflow_id: request.manifest.workflow_id.clone(),
            job_id: request.manifest.job_id.clone(),
            attempt: request.manifest.attempt,
            lease_id: request.manifest.lease_id.clone(),
            checkout_sha256: checkout_digest,
            workflow_sha256: digest(request.trusted_workflow),
            inputs_sha256: digest(request.canonical_inputs),
            policy_sha256: request.manifest.policy_sha256.clone(),
            files: request.entries.len() as u32,
            bytes,
        },
        directory,
        device,
        inode,
    })
}

fn check_publication_deadline(request: &TreeMaterialization<'_>) -> Result<(), MaterializeError> {
    if (request.now_unix_seconds)() >= request.expires_at_unix_seconds {
        return Err(MaterializeError::InvalidPolicy(
            "attempt lease expired during publication".into(),
        ));
    }
    Ok(())
}

fn publish_no_replace(staging: &Path, destination: &Path) -> Result<(), MaterializeError> {
    let staging_parent = staging
        .parent()
        .ok_or_else(|| MaterializeError::InvalidPolicy("staging path lacks a parent".into()))?;
    let destination_parent = destination
        .parent()
        .ok_or_else(|| MaterializeError::InvalidPolicy("destination path lacks a parent".into()))?;
    if staging_parent != destination_parent {
        return Err(MaterializeError::InvalidPolicy(
            "staging and destination must share one broker workspace".into(),
        ));
    }
    let staging_name = staging.file_name().ok_or_else(|| {
        MaterializeError::InvalidPolicy("staging path lacks a final component".into())
    })?;
    let destination_name = destination.file_name().ok_or_else(|| {
        MaterializeError::InvalidPolicy("destination path lacks a final component".into())
    })?;
    let parent = fs::File::open(staging_parent)?;
    renameat_with(
        &parent,
        staging_name,
        &parent,
        destination_name,
        RenameFlags::NOREPLACE,
    )
    .map_err(|error| std::io::Error::from_raw_os_error(error.raw_os_error()))?;
    Ok(())
}

fn materialize_into(
    request: &TreeMaterialization<'_>,
    source: &mut dyn BlobSource,
) -> Result<(Sha256Digest, u64), MaterializeError> {
    let mut seen = BTreeSet::new();
    let mut canonical_entries = BTreeMap::new();
    let mut total = 0_u64;
    for entry in request.entries {
        if (request.now_unix_seconds)() >= request.expires_at_unix_seconds {
            return Err(MaterializeError::InvalidPolicy(
                "attempt lease expired while writing source tree".into(),
            ));
        }
        validate_entry(
            entry,
            request.maximum_blob_bytes,
            request.maximum_path_bytes,
            request.maximum_depth,
        )?;
        let folded = entry.path.to_string_lossy().to_lowercase();
        if !seen.insert(folded) {
            return Err(MaterializeError::UnsupportedFeature(
                "case-colliding paths".into(),
            ));
        }
        total = total
            .checked_add(entry.size)
            .ok_or_else(|| MaterializeError::ResourceLimit("checkout bytes".into()))?;
        if total > request.maximum_checkout_bytes {
            return Err(MaterializeError::ResourceLimit("checkout bytes".into()));
        }
        let bytes = source.read_blob(&entry.object_id, request.maximum_blob_bytes)?;
        if bytes.len() as u64 != entry.size {
            return Err(MaterializeError::DigestMismatch {
                field: "blob_size",
                expected: entry.size.to_string(),
                actual: bytes.len().to_string(),
            });
        }
        if bytes.starts_with(b"version https://git-lfs.github.com/spec/v1\n") {
            return Err(MaterializeError::UnsupportedFeature(
                "Git LFS pointer".into(),
            ));
        }
        let destination = request.staging.join(&entry.path);
        create_private_parents(request.staging, &entry.path)?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&destination)?;
        output.write_all(&bytes)?;
        output.sync_all()?;
        if (request.now_unix_seconds)() >= request.expires_at_unix_seconds {
            return Err(MaterializeError::InvalidPolicy(
                "attempt lease expired while writing source tree".into(),
            ));
        }
        canonical_entries.insert(entry.path.clone(), bytes);
    }

    Ok((digest_entries(canonical_entries)?, total))
}

fn digest_entries(
    canonical_entries: BTreeMap<PathBuf, Vec<u8>>,
) -> Result<Sha256Digest, MaterializeError> {
    let mut hasher = Sha256::new();
    for (path, bytes) in canonical_entries {
        let path = path.to_string_lossy();
        hasher.update((path.len() as u64).to_be_bytes());
        hasher.update(path.as_bytes());
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(&bytes);
    }
    Sha256Digest::parse(hex::encode(hasher.finalize()))
}

fn digest_tree_from_disk(
    entries: &[TreeEntry],
    root: &Path,
) -> Result<Sha256Digest, MaterializeError> {
    let expected_files = entries
        .iter()
        .map(|entry| entry.path.clone())
        .collect::<BTreeSet<_>>();
    let mut expected_directories = BTreeSet::new();
    for path in &expected_files {
        let mut parent = path.parent();
        while let Some(directory) = parent.filter(|directory| !directory.as_os_str().is_empty()) {
            expected_directories.insert(directory.to_path_buf());
            parent = directory.parent();
        }
    }
    let (actual_files, actual_directories) = enumerate_actual_tree(root)?;
    if actual_files != expected_files || actual_directories != expected_directories {
        return Err(MaterializeError::DigestMismatch {
            field: "published_tree_entries",
            expected: format!(
                "{} files/{} directories",
                expected_files.len(),
                expected_directories.len()
            ),
            actual: format!(
                "{} files/{} directories",
                actual_files.len(),
                actual_directories.len()
            ),
        });
    }
    let mut canonical_entries = BTreeMap::new();
    for entry in entries {
        let path = root.join(&entry.path);
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(MaterializeError::UnsupportedFeature(
                "published path is not a regular file".into(),
            ));
        }
        let bytes = fs::read(&path)?;
        if bytes.len() as u64 != entry.size {
            return Err(MaterializeError::DigestMismatch {
                field: "published_blob_size",
                expected: entry.size.to_string(),
                actual: bytes.len().to_string(),
            });
        }
        canonical_entries.insert(entry.path.clone(), bytes);
    }
    digest_entries(canonical_entries)
}

fn enumerate_actual_tree(
    root: &Path,
) -> Result<(BTreeSet<PathBuf>, BTreeSet<PathBuf>), MaterializeError> {
    let mut files = BTreeSet::new();
    let mut directories = BTreeSet::new();
    let mut pending = vec![PathBuf::new()];
    while let Some(relative_directory) = pending.pop() {
        let directory = root.join(&relative_directory);
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            let relative = relative_directory.join(entry.file_name());
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_symlink() {
                return Err(MaterializeError::UnsupportedFeature(
                    "published tree contains a symlink".into(),
                ));
            }
            if metadata.is_dir() {
                directories.insert(relative.clone());
                pending.push(relative);
            } else if metadata.is_file() {
                files.insert(relative);
            } else {
                return Err(MaterializeError::UnsupportedFeature(
                    "published tree contains a non-regular object".into(),
                ));
            }
        }
    }
    Ok((files, directories))
}

fn validate_entry(
    entry: &TreeEntry,
    maximum_blob_bytes: u64,
    maximum_path_bytes: u32,
    maximum_depth: u16,
) -> Result<(), MaterializeError> {
    if !matches!(entry.mode, 0o100644 | 0o100755) {
        let feature = match entry.mode {
            0o120000 => "symlink",
            0o160000 => "gitlink/submodule",
            _ => "non-regular Git mode",
        };
        return Err(MaterializeError::UnsupportedFeature(feature.into()));
    }
    if entry.size > maximum_blob_bytes {
        return Err(MaterializeError::ResourceLimit("blob bytes".into()));
    }
    let text = entry
        .path
        .to_str()
        .ok_or_else(|| MaterializeError::UnsupportedFeature("non-UTF-8 repository path".into()))?;
    if text.len() > maximum_path_bytes as usize || entry.path.is_absolute() {
        return Err(MaterializeError::ResourceLimit("path bytes".into()));
    }
    let mut depth = 0_u16;
    for component in entry.path.components() {
        match component {
            Component::Normal(component) if component != ".git" => {
                depth = depth.saturating_add(1);
            }
            _ => {
                return Err(MaterializeError::UnsupportedFeature(
                    "path traversal or .git alias".into(),
                ));
            }
        }
    }
    if depth == 0 || depth > maximum_depth {
        return Err(MaterializeError::ResourceLimit("path depth".into()));
    }
    Ok(())
}

fn create_private_parents(staging: &Path, relative: &Path) -> Result<(), MaterializeError> {
    let Some(parent) = relative.parent() else {
        return Ok(());
    };
    let mut current = staging.to_path_buf();
    for component in parent.components() {
        let Component::Normal(component) = component else {
            return Err(MaterializeError::UnsupportedFeature(
                "path traversal".into(),
            ));
        };
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => {
                return Err(MaterializeError::UnsupportedFeature(
                    "non-directory parent".into(),
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current)?;
                fs::set_permissions(&current, fs::Permissions::from_mode(0o700))?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn make_read_only(root: &Path) -> Result<(), MaterializeError> {
    let mut directories = vec![root.to_path_buf()];
    while let Some(directory) = directories.pop() {
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            let metadata = entry.file_type()?;
            if metadata.is_symlink() {
                return Err(MaterializeError::UnsupportedFeature(
                    "symlink appeared during publication".into(),
                ));
            }
            if metadata.is_dir() {
                directories.push(entry.path());
            } else if metadata.is_file() {
                fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o400))?;
            } else {
                return Err(MaterializeError::UnsupportedFeature(
                    "non-file appeared during publication".into(),
                ));
            }
        }
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o500))?;
    }
    Ok(())
}

fn make_writable_for_cleanup(root: &Path) -> Result<(), MaterializeError> {
    if !root.exists() {
        return Ok(());
    }
    let mut directories = vec![root.to_path_buf()];
    while let Some(directory) = directories.pop() {
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if file_type.is_dir() && !file_type.is_symlink() {
                directories.push(entry.path());
            } else if file_type.is_file() {
                fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o600))?;
            }
        }
    }
    Ok(())
}

fn verify_bytes(
    field: &'static str,
    expected: &Sha256Digest,
    bytes: &[u8],
) -> Result<(), MaterializeError> {
    verify_digest(field, expected, &digest(bytes))
}

fn verify_digest(
    field: &'static str,
    expected: &Sha256Digest,
    actual: &Sha256Digest,
) -> Result<(), MaterializeError> {
    if expected != actual {
        return Err(MaterializeError::DigestMismatch {
            field,
            expected: expected.as_str().into(),
            actual: actual.as_str().into(),
        });
    }
    Ok(())
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_sha256_bytes(Sha256::digest(bytes).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::collections::BTreeMap;

    struct FakeBlobs(BTreeMap<String, Vec<u8>>);

    impl BlobSource for FakeBlobs {
        fn read_blob(
            &mut self,
            object_id: &str,
            maximum_bytes: u64,
        ) -> Result<Vec<u8>, MaterializeError> {
            let bytes = self
                .0
                .get(object_id)
                .cloned()
                .ok_or_else(|| MaterializeError::InvalidManifest("missing fake blob".into()))?;
            if bytes.len() as u64 > maximum_bytes {
                return Err(MaterializeError::ResourceLimit("blob bytes".into()));
            }
            Ok(bytes)
        }
    }

    struct InjectingBlobs {
        staging: PathBuf,
    }

    impl BlobSource for InjectingBlobs {
        fn read_blob(
            &mut self,
            _object_id: &str,
            _maximum_bytes: u64,
        ) -> Result<Vec<u8>, MaterializeError> {
            fs::write(self.staging.join("unmeasured"), b"injected")?;
            Ok(b"run".to_vec())
        }
    }

    fn manifest(checkout: Sha256Digest) -> MaterializationManifest {
        let workflow = b"name: CI\n";
        let inputs = b"{}";
        MaterializationManifest {
            schema_version: 1,
            request_event_id: "f".repeat(64),
            run_id: "018f47a2-7f0f-7cc1-9a55-01f93e42b1e0".into(),
            source_sha: "a".repeat(40),
            job_id: "job".into(),
            attempt: 1,
            repo_coordinate: format!("30617:{}:buzz", "e".repeat(64)),
            workflow_id: "required-ci".into(),
            lease_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            tree_oid: "b".repeat(40),
            trusted_base_sha: "c".repeat(40),
            workflow_path: ".github/workflows/ci.yml".into(),
            workflow_sha256: digest(workflow),
            checkout_sha256: checkout,
            inputs_sha256: digest(inputs),
            policy_sha256: digest(b"policy"),
        }
    }

    fn entries() -> Vec<TreeEntry> {
        vec![TreeEntry {
            mode: 0o100755,
            object_id: "d".repeat(40),
            size: 3,
            path: "bin/run".into(),
        }]
    }

    fn test_now() -> u64 {
        1_000
    }

    fn request<'a>(
        manifest: &'a MaterializationManifest,
        entries: &'a [TreeEntry],
        staging: &'a Path,
        destination: &'a Path,
    ) -> TreeMaterialization<'a> {
        TreeMaterialization {
            manifest,
            entries,
            staging,
            destination,
            maximum_blob_bytes: 10,
            maximum_checkout_bytes: 10,
            maximum_entries: 10,
            maximum_path_bytes: 100,
            maximum_depth: 5,
            trusted_workflow: b"name: CI\n",
            workflow_blob_oid: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            canonical_inputs: b"{}",
            now_unix_seconds: &test_now,
            expires_at_unix_seconds: 2_000,
        }
    }

    #[test]
    fn executable_mode_is_stripped_and_tree_publishes_atomically() {
        let temporary = tempfile::tempdir().unwrap();
        let staging = temporary.path().join("staging");
        let destination = temporary.path().join("source");
        let expected = {
            let mut hasher = Sha256::new();
            hasher.update(7_u64.to_be_bytes());
            hasher.update(b"bin/run");
            hasher.update(3_u64.to_be_bytes());
            hasher.update(b"run");
            Sha256Digest::parse(hex::encode(hasher.finalize())).unwrap()
        };
        let manifest = manifest(expected);
        let entries = entries();
        let publication = materialize_tree(
            request(&manifest, &entries, &staging, &destination),
            &mut FakeBlobs(BTreeMap::from([("d".repeat(40), b"run".to_vec())])),
        )
        .unwrap();
        assert_eq!(publication.receipt.files(), 1);
        assert!(!staging.exists());
        let mode = fs::metadata(destination.join("bin/run"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o400);
    }

    #[test]
    fn unmeasured_files_prevent_publication_receipt() {
        let temporary = tempfile::tempdir().unwrap();
        let staging = temporary.path().join("staging");
        let destination = temporary.path().join("source");
        let expected = {
            let mut hasher = Sha256::new();
            hasher.update(7_u64.to_be_bytes());
            hasher.update(b"bin/run");
            hasher.update(3_u64.to_be_bytes());
            hasher.update(b"run");
            Sha256Digest::parse(hex::encode(hasher.finalize())).unwrap()
        };
        let manifest = manifest(expected);
        let entries = entries();
        let error = materialize_tree(
            request(&manifest, &entries, &staging, &destination),
            &mut InjectingBlobs {
                staging: staging.clone(),
            },
        )
        .unwrap_err();
        assert!(matches!(error, MaterializeError::DigestMismatch { .. }));
    }

    #[test]
    fn expiry_after_rename_removes_the_published_tree() {
        let temporary = tempfile::tempdir().unwrap();
        let staging = temporary.path().join("staging");
        let destination = temporary.path().join("source");
        let expected = {
            let mut hasher = Sha256::new();
            hasher.update(7_u64.to_be_bytes());
            hasher.update(b"bin/run");
            hasher.update(3_u64.to_be_bytes());
            hasher.update(b"run");
            Sha256Digest::parse(hex::encode(hasher.finalize())).unwrap()
        };
        let manifest = manifest(expected);
        let entries = entries();
        let checks = Cell::new(0_u32);
        let clock = || {
            let check = checks.get().saturating_add(1);
            checks.set(check);
            if check >= 6 {
                2_000
            } else {
                1_000
            }
        };
        let error = materialize_tree(
            TreeMaterialization {
                manifest: &manifest,
                entries: &entries,
                staging: &staging,
                destination: &destination,
                maximum_blob_bytes: 10,
                maximum_checkout_bytes: 10,
                maximum_entries: 10,
                maximum_path_bytes: 100,
                maximum_depth: 5,
                trusted_workflow: b"name: CI\n",
                workflow_blob_oid: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                canonical_inputs: b"{}",
                now_unix_seconds: &clock,
                expires_at_unix_seconds: 2_000,
            },
            &mut FakeBlobs(BTreeMap::from([("d".repeat(40), b"run".to_vec())])),
        )
        .unwrap_err();
        assert!(matches!(error, MaterializeError::InvalidPolicy(_)));
        assert!(!destination.exists());
        assert!(!staging.exists());
    }

    #[test]
    fn ls_tree_parser_accepts_only_bounded_regular_blob_records() {
        let record = format!("100644 blob {} 3\tfile.txt\0", "a".repeat(40));
        let entries = parse_ls_tree(record.as_bytes(), 1024, 2).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, PathBuf::from("file.txt"));
        for bad in [
            format!("160000 commit {} -\tmodule\0", "a".repeat(40)).into_bytes(),
            format!("100644 blob {} 3\tfile", "a".repeat(40)).into_bytes(),
        ] {
            assert!(parse_ls_tree(&bad, 1024, 2).is_err());
        }
    }

    #[test]
    fn lfs_pointer_is_rejected_without_execution() {
        let temporary = tempfile::tempdir().unwrap();
        let staging = temporary.path().join("staging");
        let destination = temporary.path().join("source");
        let bytes = b"version https://git-lfs.github.com/spec/v1\n".to_vec();
        let entries = [TreeEntry {
            mode: 0o100644,
            object_id: "d".repeat(40),
            size: bytes.len() as u64,
            path: "large.bin".into(),
        }];
        let manifest = manifest(digest(b"wrong"));
        let error = materialize_tree(
            TreeMaterialization {
                manifest: &manifest,
                entries: &entries,
                staging: &staging,
                destination: &destination,
                maximum_blob_bytes: 1024,
                maximum_checkout_bytes: 1024,
                maximum_entries: 10,
                maximum_path_bytes: 100,
                maximum_depth: 5,
                trusted_workflow: b"name: CI\n",
                workflow_blob_oid: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                canonical_inputs: b"{}",
                now_unix_seconds: &test_now,
                expires_at_unix_seconds: 2_000,
            },
            &mut FakeBlobs(BTreeMap::from([("d".repeat(40), bytes)])),
        )
        .unwrap_err();
        assert!(matches!(error, MaterializeError::UnsupportedFeature(_)));
        assert!(!destination.exists());
    }

    #[test]
    fn symlink_gitlink_and_traversal_never_publish() {
        for (mode, path) in [
            (0o120000, PathBuf::from("link")),
            (0o160000, PathBuf::from("module")),
            (0o100644, PathBuf::from("../escape")),
        ] {
            let temporary = tempfile::tempdir().unwrap();
            let staging = temporary.path().join("staging");
            let destination = temporary.path().join("source");
            let manifest = manifest(digest(b"wrong"));
            let entries = [TreeEntry {
                mode,
                object_id: "d".repeat(40),
                size: 3,
                path,
            }];
            let error = materialize_tree(
                request(&manifest, &entries, &staging, &destination),
                &mut FakeBlobs(BTreeMap::from([("d".repeat(40), b"run".to_vec())])),
            )
            .unwrap_err();
            assert!(matches!(error, MaterializeError::UnsupportedFeature(_)));
            assert!(!destination.exists());
        }
    }

    #[test]
    fn digest_mismatch_leaves_destination_absent() {
        let temporary = tempfile::tempdir().unwrap();
        let staging = temporary.path().join("staging");
        let destination = temporary.path().join("source");
        let manifest = manifest(digest(b"wrong"));
        let entries = entries();
        let error = materialize_tree(
            request(&manifest, &entries, &staging, &destination),
            &mut FakeBlobs(BTreeMap::from([("d".repeat(40), b"run".to_vec())])),
        )
        .unwrap_err();
        assert!(matches!(error, MaterializeError::DigestMismatch { .. }));
        assert!(!destination.exists());
        assert!(!staging.exists());
        assert!(!temporary.path().join("staging").exists());
    }
}
