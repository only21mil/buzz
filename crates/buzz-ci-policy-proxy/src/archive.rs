use std::{
    collections::BTreeMap,
    io::{self, Cursor, Read, Write},
    path::{Component, Path, PathBuf},
};

use flate2::read::MultiGzDecoder;
use tar::{Archive, Builder, EntryType, Header};

use crate::{ArchiveGrant, ProxyError};

const TAR_BLOCK_BYTES: usize = 512;

/// Validate every tar entry and rebuild a deterministic archive before any
/// destination receives bytes. Gzip is accepted only under the grant's hard
/// decoded-byte and expansion-ratio limits. The rebuilt archive is always an
/// uncompressed ustar stream containing regular files and directories only.
pub(crate) fn mediate_archive(
    grant: &ArchiveGrant,
    input: &[u8],
    wire_limit: usize,
) -> Result<Vec<u8>, ProxyError> {
    let limits = ArchiveLimits::from_grant(grant, wire_limit)?;
    if input.is_empty() || input.len() > limits.stream_bytes {
        return Err(archive_refusal(
            "archive stream is empty or exceeds its byte cap",
        ));
    }

    let compressed = input.starts_with(&[0x1f, 0x8b]);
    if compressed {
        sanitize_reader(
            MultiGzDecoder::new(Cursor::new(input)),
            input.len(),
            true,
            limits,
        )
    } else {
        sanitize_reader(Cursor::new(input), input.len(), false, limits)
    }
}

#[derive(Clone, Copy)]
struct ArchiveLimits {
    stream_bytes: usize,
    entries: usize,
    total_bytes: usize,
    decompression_ratio: usize,
}

impl ArchiveLimits {
    fn from_grant(grant: &ArchiveGrant, wire_limit: usize) -> Result<Self, ProxyError> {
        if grant.max_bytes == 0
            || grant.max_entries == 0
            || grant.max_total_bytes == 0
            || grant.max_decompression_ratio == 0
            || wire_limit == 0
        {
            return Err(archive_refusal("archive grant contains a zero limit"));
        }
        Ok(Self {
            stream_bytes: grant.max_bytes.min(wire_limit),
            entries: grant.max_entries,
            total_bytes: grant.max_total_bytes.min(wire_limit),
            decompression_ratio: grant.max_decompression_ratio,
        })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum CanonicalEntryType {
    File,
    Directory,
}

fn sanitize_reader<R: Read>(
    reader: R,
    encoded_bytes: usize,
    compressed: bool,
    limits: ArchiveLimits,
) -> Result<Vec<u8>, ProxyError> {
    let mut source = BoundedReader::new(reader, limits.stream_bytes);
    let mut output = Builder::new(BoundedVec::new(limits.stream_bytes));
    let mut paths = BTreeMap::<PathBuf, CanonicalEntryType>::new();
    let mut total_bytes = 0_usize;
    let mut entry_count = 0_usize;

    {
        let mut archive = Archive::new(&mut source);
        let entries = archive
            .entries()
            .map_err(|error| archive_io("tar entry scan failed", error))?;
        for entry in entries {
            let mut entry = entry.map_err(|error| archive_io("tar entry read failed", error))?;
            entry_count = entry_count
                .checked_add(1)
                .ok_or_else(|| archive_refusal("archive entry count overflowed"))?;
            if entry_count > limits.entries {
                return Err(archive_refusal("archive entry count exceeds its cap"));
            }

            let entry_type = match entry.header().entry_type() {
                entry_type if entry_type.is_file() => CanonicalEntryType::File,
                entry_type if entry_type.is_dir() => CanonicalEntryType::Directory,
                _ => {
                    return Err(archive_refusal(
                        "archive entry type is not a regular file or directory",
                    ));
                }
            };
            let path = canonical_entry_path(&entry)?;
            validate_path_hierarchy(&paths, &path, entry_type)?;
            if paths.insert(path.clone(), entry_type).is_some() {
                return Err(archive_refusal("archive contains a duplicate path"));
            }

            let declared_size = usize::try_from(entry.size())
                .map_err(|_| archive_refusal("archive entry size does not fit this host"))?;
            if entry_type == CanonicalEntryType::Directory && declared_size != 0 {
                return Err(archive_refusal("archive directory carries file data"));
            }
            total_bytes = total_bytes
                .checked_add(declared_size)
                .ok_or_else(|| archive_refusal("archive content size overflowed"))?;
            if total_bytes > limits.total_bytes {
                return Err(archive_refusal(
                    "archive content exceeds its total byte cap",
                ));
            }

            let mut data = Vec::new();
            data.try_reserve_exact(declared_size)
                .map_err(|_| archive_refusal("archive entry allocation was refused"))?;
            entry
                .read_to_end(&mut data)
                .map_err(|error| archive_io("archive entry payload read failed", error))?;
            if data.len() != declared_size {
                return Err(archive_refusal(
                    "archive entry payload differs from its declared size",
                ));
            }

            append_canonical_entry(&mut output, &path, entry_type, &data, entry.header())?;
        }
    }

    source
        .drain_zero_padding()
        .map_err(|error| archive_io("archive trailing data read failed", error))?;
    if compressed {
        let ratio_cap = encoded_bytes
            .checked_mul(limits.decompression_ratio)
            .ok_or_else(|| archive_refusal("archive ratio bound overflowed"))?;
        if source.bytes_read() > ratio_cap {
            return Err(archive_refusal(
                "archive decompression ratio exceeds its cap",
            ));
        }
    }

    output
        .finish()
        .map_err(|error| archive_io("canonical tar finalization failed", error))?;
    output
        .into_inner()
        .map(BoundedVec::into_inner)
        .map_err(|error| archive_io("canonical tar write failed", error))
}

fn canonical_entry_path<R: Read>(entry: &tar::Entry<'_, R>) -> Result<PathBuf, ProxyError> {
    let raw = entry.path_bytes();
    if raw.is_empty()
        || raw.len() > 255
        || raw.starts_with(b"/")
        || raw.contains(&b'\\')
        || raw.iter().any(|byte| *byte == 0 || byte.is_ascii_control())
    {
        return Err(archive_refusal(
            "archive entry path is empty, absolute, oversized, or contains unsafe bytes",
        ));
    }
    let path = entry
        .path()
        .map_err(|error| archive_io("archive entry path decode failed", error))?;
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(component) => normalized.push(component),
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(archive_refusal(
                    "archive entry path escapes its relative root",
                ));
            }
        }
    }
    if normalized.as_os_str().is_empty() || normalized.to_str().is_none() {
        return Err(archive_refusal(
            "archive entry path is empty or is not valid UTF-8",
        ));
    }
    Ok(normalized)
}

fn validate_path_hierarchy(
    paths: &BTreeMap<PathBuf, CanonicalEntryType>,
    path: &Path,
    entry_type: CanonicalEntryType,
) -> Result<(), ProxyError> {
    for ancestor in path
        .ancestors()
        .skip(1)
        .filter(|ancestor| !ancestor.as_os_str().is_empty())
    {
        if paths.get(ancestor) == Some(&CanonicalEntryType::File) {
            return Err(archive_refusal(
                "archive path descends through a regular file",
            ));
        }
    }
    if entry_type == CanonicalEntryType::File
        && paths
            .keys()
            .any(|known| known != path && known.starts_with(path))
    {
        return Err(archive_refusal(
            "archive regular file conflicts with an existing descendant",
        ));
    }
    Ok(())
}

fn append_canonical_entry<W: Write>(
    output: &mut Builder<W>,
    path: &Path,
    entry_type: CanonicalEntryType,
    data: &[u8],
    source: &Header,
) -> Result<(), ProxyError> {
    let mut header = Header::new_ustar();
    header
        .set_path(path)
        .map_err(|error| archive_io("canonical archive path does not fit ustar", error))?;
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    match entry_type {
        CanonicalEntryType::File => {
            let source_mode = source
                .mode()
                .map_err(|error| archive_io("archive entry mode is invalid", error))?;
            header.set_entry_type(EntryType::Regular);
            header.set_mode(if source_mode & 0o111 == 0 {
                0o644
            } else {
                0o755
            });
            header.set_size(data.len() as u64);
        }
        CanonicalEntryType::Directory => {
            header.set_entry_type(EntryType::Directory);
            header.set_mode(0o755);
            header.set_size(0);
        }
    }
    header.set_cksum();
    output
        .append(&header, data)
        .map_err(|error| archive_io("canonical archive entry write failed", error))
}

struct BoundedReader<R> {
    inner: R,
    limit: usize,
    bytes_read: usize,
}

impl<R> BoundedReader<R> {
    fn new(inner: R, limit: usize) -> Self {
        Self {
            inner,
            limit,
            bytes_read: 0,
        }
    }

    fn bytes_read(&self) -> usize {
        self.bytes_read
    }
}

impl<R: Read> BoundedReader<R> {
    fn drain_zero_padding(&mut self) -> io::Result<()> {
        let mut buffer = [0_u8; 8192];
        let mut padding_bytes = 0_usize;
        loop {
            let count = self.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            if buffer[..count].iter().any(|byte| *byte != 0) {
                return Err(io::Error::other(
                    "archive contains nonzero data after its terminator",
                ));
            }
            padding_bytes = padding_bytes
                .checked_add(count)
                .ok_or_else(|| io::Error::other("archive padding size overflowed"))?;
        }
        if padding_bytes < TAR_BLOCK_BYTES || !padding_bytes.is_multiple_of(TAR_BLOCK_BYTES) {
            return Err(io::Error::other(
                "archive lacks a canonical two-block zero terminator",
            ));
        }
        Ok(())
    }
}

impl<R: Read> Read for BoundedReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.bytes_read == self.limit {
            let mut probe = [0_u8; 1];
            return match self.inner.read(&mut probe)? {
                0 => Ok(0),
                _ => Err(io::Error::other("decoded archive exceeds its byte cap")),
            };
        }
        let remaining = self.limit - self.bytes_read;
        let read_cap = output.len().min(remaining);
        let count = self.inner.read(&mut output[..read_cap])?;
        self.bytes_read += count;
        Ok(count)
    }
}

struct BoundedVec {
    bytes: Vec<u8>,
    limit: usize,
}

impl BoundedVec {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
        }
    }

    fn into_inner(self) -> Vec<u8> {
        self.bytes
    }
}

impl Write for BoundedVec {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        let new_len = self
            .bytes
            .len()
            .checked_add(input.len())
            .ok_or_else(|| io::Error::other("canonical archive size overflowed"))?;
        if new_len > self.limit {
            return Err(io::Error::other("canonical archive exceeds its byte cap"));
        }
        self.bytes.extend_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn archive_refusal(message: impl Into<String>) -> ProxyError {
    ProxyError::InvalidRequest(message.into())
}

fn archive_io(context: &str, error: io::Error) -> ProxyError {
    archive_refusal(format!("{context}: {error}"))
}

#[cfg(test)]
mod tests {
    use flate2::{write::GzEncoder, Compression};

    use super::*;
    use crate::ArchiveDirection;

    fn grant() -> ArchiveGrant {
        ArchiveGrant {
            lease_id: "lease".into(),
            container_id: "owned".into(),
            container_path: "/workspace".into(),
            direction: ArchiveDirection::Upload,
            max_bytes: 2 * 1024 * 1024,
            max_entries: 64,
            max_total_bytes: 1024 * 1024,
            max_decompression_ratio: 100,
        }
    }

    fn archive_with(entries: &[(&str, EntryType, &[u8], u32)]) -> Vec<u8> {
        let mut builder = Builder::new(Vec::new());
        for (path, entry_type, data, mode) in entries {
            let mut header = Header::new_gnu();
            header.set_path(path).unwrap();
            header.set_entry_type(*entry_type);
            header.set_mode(*mode);
            header.set_uid(1234);
            header.set_gid(5678);
            header.set_mtime(1_700_000_000);
            header.set_size(data.len() as u64);
            header.set_cksum();
            builder.append(&header, *data).unwrap();
        }
        builder.into_inner().unwrap()
    }

    fn archive_with_raw_path(path: &[u8]) -> Vec<u8> {
        let mut builder = Builder::new(Vec::new());
        let mut header = Header::new_gnu();
        header.as_mut_bytes()[..100].fill(0);
        header.as_mut_bytes()[..path.len()].copy_from_slice(path);
        header.set_entry_type(EntryType::Regular);
        header.set_mode(0o644);
        header.set_size(1);
        header.set_cksum();
        builder.append(&header, b"x".as_slice()).unwrap();
        builder.into_inner().unwrap()
    }

    #[test]
    fn valid_entries_are_rebuilt_with_normalized_metadata() {
        let input = archive_with(&[
            ("dir", EntryType::Directory, b"", 0o7777),
            ("dir/tool", EntryType::Regular, b"ok", 0o6755),
            ("plain", EntryType::Regular, b"data", 0o666),
        ]);
        let output = mediate_archive(&grant(), &input, 2 * 1024 * 1024).unwrap();
        let mut archive = Archive::new(output.as_slice());
        let mut entries = archive.entries().unwrap();

        let directory = entries.next().unwrap().unwrap();
        assert_eq!(directory.path().unwrap(), Path::new("dir"));
        assert!(directory.header().entry_type().is_dir());
        assert_eq!(directory.header().mode().unwrap(), 0o755);
        assert_eq!(directory.header().uid().unwrap(), 0);
        assert_eq!(directory.header().gid().unwrap(), 0);
        assert_eq!(directory.header().mtime().unwrap(), 0);

        let executable = entries.next().unwrap().unwrap();
        assert_eq!(executable.header().mode().unwrap(), 0o755);
        assert_eq!(executable.header().uid().unwrap(), 0);
        let plain = entries.next().unwrap().unwrap();
        assert_eq!(plain.header().mode().unwrap(), 0o644);
        assert!(entries.next().is_none());
    }

    #[test]
    fn hostile_entry_types_are_refused() {
        for entry_type in [
            EntryType::Symlink,
            EntryType::Link,
            EntryType::Char,
            EntryType::Block,
            EntryType::Fifo,
            EntryType::new(b's'),
            EntryType::GNUSparse,
        ] {
            let input = archive_with(&[("hostile", entry_type, b"", 0o644)]);
            assert!(mediate_archive(&grant(), &input, 2 * 1024 * 1024).is_err());
        }
    }

    #[test]
    fn traversal_absolute_and_duplicate_paths_are_refused() {
        for path in [b"../escape".as_slice(), b"/absolute".as_slice()] {
            assert!(
                mediate_archive(&grant(), &archive_with_raw_path(path), 2 * 1024 * 1024).is_err()
            );
        }
        let duplicate = archive_with(&[
            ("same", EntryType::Regular, b"one", 0o644),
            ("same", EntryType::Regular, b"two", 0o644),
        ]);
        assert!(mediate_archive(&grant(), &duplicate, 2 * 1024 * 1024).is_err());
    }

    #[test]
    fn entry_count_total_bytes_and_gzip_ratio_are_bounded() {
        let two_entries = archive_with(&[
            ("one", EntryType::Regular, b"1", 0o644),
            ("two", EntryType::Regular, b"2", 0o644),
        ]);
        let mut one_entry = grant();
        one_entry.max_entries = 1;
        assert!(mediate_archive(&one_entry, &two_entries, 2 * 1024 * 1024).is_err());

        let too_large = archive_with(&[("large", EntryType::Regular, b"12345", 0o644)]);
        let mut four_bytes = grant();
        four_bytes.max_total_bytes = 4;
        assert!(mediate_archive(&four_bytes, &too_large, 2 * 1024 * 1024).is_err());

        let zeros = vec![0_u8; 1024 * 1024];
        let bomb = archive_with(&[("zeros", EntryType::Regular, zeros.as_slice(), 0o644)]);
        let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&bomb).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut strict_ratio = grant();
        strict_ratio.max_decompression_ratio = 10;
        assert!(mediate_archive(&strict_ratio, &compressed, 2 * 1024 * 1024).is_err());
    }

    #[test]
    fn truncated_or_trailing_nonzero_archives_are_refused() {
        let mut truncated = archive_with(&[("file", EntryType::Regular, b"x", 0o644)]);
        truncated.truncate(truncated.len() - TAR_BLOCK_BYTES * 2);
        assert!(mediate_archive(&grant(), &truncated, 2 * 1024 * 1024).is_err());

        let mut trailing = archive_with(&[("file", EntryType::Regular, b"x", 0o644)]);
        *trailing.last_mut().unwrap() = 1;
        assert!(mediate_archive(&grant(), &trailing, 2 * 1024 * 1024).is_err());

        let mut concatenated = archive_with(&[("visible", EntryType::Regular, b"x", 0o644)]);
        concatenated.extend(archive_with(&[(
            "hidden",
            EntryType::Regular,
            b"payload",
            0o644,
        )]));
        assert!(mediate_archive(&grant(), &concatenated, 2 * 1024 * 1024).is_err());
    }
}
