//! Secret-safe CI status signer and NIP-98 authorizer.

use std::fmt;
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, PathBuf};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use nostr::{EventBuilder, Keys, Kind, Tag};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::production::{CiSigner, SignedCiEvent};
use crate::source::{HttpMethod, Nip98Authorizer, Nip98Binding};

const KEY_MODE: u32 = 0o600;
const MAX_KEY_BYTES: u64 = 256;

/// Immutable descriptor for one dedicated CI status key.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyDescriptor {
    pub path: PathBuf,
    pub expected_owner_uid: u32,
    pub expected_pubkey: String,
}

impl KeyDescriptor {
    pub fn validate(&self) -> Result<(), KeyholderError> {
        if !self.path.is_absolute()
            || self.path.components().any(|component| {
                matches!(
                    component,
                    Component::CurDir | Component::ParentDir | Component::Prefix(_)
                )
            })
            || !is_lower_hex(&self.expected_pubkey, 64)
        {
            return Err(KeyholderError::InvalidDescriptor);
        }
        Ok(())
    }
}

/// Errors deliberately omit paths, key bytes, parser details, and OS messages.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum KeyholderError {
    #[error("CI key descriptor is invalid")]
    InvalidDescriptor,
    #[error("CI key file is unavailable")]
    Unavailable,
    #[error("CI key file metadata is insecure")]
    InsecureFile,
    #[error("CI key file changed while opening")]
    ReplacedFile,
    #[error("CI key file exceeds the byte limit")]
    Oversized,
    #[error("CI key material is invalid")]
    InvalidKey,
    #[error("CI key public identity does not match its descriptor")]
    WrongPubkey,
    #[error("CI event signing failed")]
    Signing,
    #[error("CI NIP-98 binding is invalid")]
    InvalidAuthBinding,
}

/// Loaded keyholder. Debug output exposes only its public identity.
pub struct KeyholderSigner {
    keys: Keys,
    pubkey: String,
}

impl fmt::Debug for KeyholderSigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyholderSigner")
            .field("pubkey", &self.pubkey)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

impl KeyholderSigner {
    /// Load one bounded key without following a final symlink.
    #[cfg(target_os = "linux")]
    pub fn load(descriptor: &KeyDescriptor) -> Result<Self, KeyholderError> {
        use nix::fcntl::{open, OFlag};
        use nix::sys::stat::Mode;

        descriptor.validate()?;
        let before =
            fs::symlink_metadata(&descriptor.path).map_err(|_| KeyholderError::Unavailable)?;
        validate_metadata(&before, descriptor.expected_owner_uid)?;
        if fs::canonicalize(&descriptor.path).map_err(|_| KeyholderError::Unavailable)?
            != descriptor.path
        {
            return Err(KeyholderError::InsecureFile);
        }

        let descriptor_fd = open(
            descriptor.path.as_path(),
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| KeyholderError::Unavailable)?;
        let file = File::from(descriptor_fd);
        let opened = file.metadata().map_err(|_| KeyholderError::Unavailable)?;
        validate_metadata(&opened, descriptor.expected_owner_uid)?;
        if (before.dev(), before.ino()) != (opened.dev(), opened.ino()) {
            return Err(KeyholderError::ReplacedFile);
        }
        if opened.len() > MAX_KEY_BYTES {
            return Err(KeyholderError::Oversized);
        }

        let mut secret = Zeroizing::new(Vec::with_capacity(opened.len() as usize));
        file.take(MAX_KEY_BYTES + 1)
            .read_to_end(&mut secret)
            .map_err(|_| KeyholderError::Unavailable)?;
        if secret.len() as u64 > MAX_KEY_BYTES {
            return Err(KeyholderError::Oversized);
        }
        let secret = std::str::from_utf8(secret.as_slice())
            .map_err(|_| KeyholderError::InvalidKey)?
            .trim();
        if secret.is_empty() || secret.as_bytes().contains(&0) {
            return Err(KeyholderError::InvalidKey);
        }
        let keys = Keys::parse(secret).map_err(|_| KeyholderError::InvalidKey)?;
        let pubkey = keys.public_key().to_hex();
        if pubkey != descriptor.expected_pubkey {
            return Err(KeyholderError::WrongPubkey);
        }
        Ok(Self { keys, pubkey })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn load(_descriptor: &KeyDescriptor) -> Result<Self, KeyholderError> {
        Err(KeyholderError::Unavailable)
    }

    fn sign_event(
        &self,
        kind: Kind,
        content: &str,
        tags: Vec<Tag>,
    ) -> Result<nostr::Event, KeyholderError> {
        EventBuilder::new(kind, content)
            .tags(tags)
            .sign_with_keys(&self.keys)
            .map_err(|_| KeyholderError::Signing)
    }
}

impl CiSigner for KeyholderSigner {
    type Error = KeyholderError;

    fn pubkey(&self) -> &str {
        &self.pubkey
    }

    fn sign(
        &mut self,
        kind: u32,
        content: &str,
        tags: serde_json::Value,
    ) -> Result<SignedCiEvent, Self::Error> {
        let kind = u16::try_from(kind).map_err(|_| KeyholderError::Signing)?;
        let tags: Vec<Tag> = serde_json::from_value(tags).map_err(|_| KeyholderError::Signing)?;
        let event = self.sign_event(Kind::Custom(kind), content, tags)?;
        Ok(SignedCiEvent {
            event_id: event.id.to_hex(),
            kind: kind.into(),
            content: content.to_owned(),
            tags: serde_json::to_value(&event.tags).map_err(|_| KeyholderError::Signing)?,
            signed_event: serde_json::to_value(event).map_err(|_| KeyholderError::Signing)?,
        })
    }
}

impl Nip98Authorizer for KeyholderSigner {
    type Error = KeyholderError;

    fn authorization(&mut self, binding: &Nip98Binding) -> Result<String, Self::Error> {
        binding
            .validate()
            .map_err(|_| KeyholderError::InvalidAuthBinding)?;
        let method = match binding.method {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
        };
        let nonce = Uuid::new_v4().to_string();
        let mut tags = vec![
            Tag::parse(["u", binding.url.as_str()])
                .map_err(|_| KeyholderError::InvalidAuthBinding)?,
            Tag::parse(["method", method]).map_err(|_| KeyholderError::InvalidAuthBinding)?,
            Tag::parse(["nonce", nonce.as_str()])
                .map_err(|_| KeyholderError::InvalidAuthBinding)?,
        ];
        if let Some(payload) = binding.payload_sha256.as_deref() {
            tags.push(
                Tag::parse(["payload", payload]).map_err(|_| KeyholderError::InvalidAuthBinding)?,
            );
        }
        let event = self.sign_event(Kind::HttpAuth, "", tags)?;
        let json = serde_json::to_vec(&event).map_err(|_| KeyholderError::Signing)?;
        Ok(format!("Nostr {}", BASE64.encode(json)))
    }
}

fn validate_metadata(
    metadata: &fs::Metadata,
    expected_owner_uid: u32,
) -> Result<(), KeyholderError> {
    if !metadata.file_type().is_file()
        || metadata.permissions().mode() & 0o7777 != KEY_MODE
        || metadata.uid() != expected_owner_uid
        || metadata.nlink() != 1
    {
        return Err(KeyholderError::InsecureFile);
    }
    Ok(())
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{symlink, PermissionsExt};

    use nostr::Keys;

    use super::*;

    fn fixture() -> (tempfile::TempDir, KeyDescriptor, String) {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("ci-status.key");
        let keys = Keys::generate();
        let secret = keys.secret_key().to_secret_hex();
        fs::write(&path, secret.as_bytes()).expect("write synthetic key");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("set key mode");
        let uid = fs::metadata(&path).expect("metadata").uid();
        let descriptor = KeyDescriptor {
            path,
            expected_owner_uid: uid,
            expected_pubkey: keys.public_key().to_hex(),
        };
        (directory, descriptor, secret)
    }

    #[test]
    fn synthetic_key_loads_and_debug_output_is_redacted() {
        let (_directory, descriptor, secret) = fixture();
        let mut signer = KeyholderSigner::load(&descriptor).expect("load synthetic key");
        let debug = format!("{signer:?}");
        assert!(debug.contains(&descriptor.expected_pubkey));
        assert!(!debug.contains(&secret));
        assert!(!debug.contains(descriptor.path.to_string_lossy().as_ref()));

        for kind in 46101..=46106 {
            let signed = signer
                .sign(kind, "{}", serde_json::json!([]))
                .expect("sign CI event");
            let event: nostr::Event =
                serde_json::from_value(signed.signed_event).expect("signed event");
            event.verify().expect("valid signature");
            assert_eq!(event.kind.as_u16() as u32, kind);
            assert_eq!(event.pubkey.to_hex(), descriptor.expected_pubkey);
        }

        let binding = Nip98Binding {
            method: HttpMethod::Post,
            url: url::Url::parse("https://relay.example/events").expect("url"),
            payload_sha256: Some("22".repeat(32)),
        };
        let authorization = signer.authorization(&binding).expect("authorize");
        let encoded = authorization.strip_prefix("Nostr ").expect("scheme");
        let event: nostr::Event =
            serde_json::from_slice(&BASE64.decode(encoded).expect("base64 authorization"))
                .expect("NIP-98 event");
        event.verify().expect("valid NIP-98 signature");
        let tags = serde_json::to_value(&event.tags).expect("tags");
        let tags = tags.as_array().expect("tag array");
        assert!(tags.contains(&serde_json::json!(["u", binding.url.as_str()])));
        assert!(tags.contains(&serde_json::json!(["method", "POST"])));
        assert!(tags.contains(&serde_json::json!(["payload", "22".repeat(32)])));
    }

    #[test]
    fn broad_mode_symlink_wrong_owner_and_unknown_fields_fail_closed() {
        let (directory, mut descriptor, _secret) = fixture();
        fs::set_permissions(&descriptor.path, fs::Permissions::from_mode(0o640))
            .expect("set broad mode");
        assert_eq!(
            KeyholderSigner::load(&descriptor).unwrap_err(),
            KeyholderError::InsecureFile
        );

        fs::set_permissions(&descriptor.path, fs::Permissions::from_mode(0o600))
            .expect("restore mode");
        descriptor.expected_owner_uid = descriptor.expected_owner_uid.saturating_add(1);
        assert_eq!(
            KeyholderSigner::load(&descriptor).unwrap_err(),
            KeyholderError::InsecureFile
        );

        let linked = directory.path().join("linked.key");
        symlink(&descriptor.path, &linked).expect("symlink");
        descriptor.path = linked;
        assert_eq!(
            KeyholderSigner::load(&descriptor).unwrap_err(),
            KeyholderError::InsecureFile
        );

        let json = serde_json::json!({
            "path": "/secret/key",
            "expected_owner_uid": 1000,
            "expected_pubkey": "11".repeat(32),
            "secret": "must-not-be-accepted"
        });
        assert!(serde_json::from_value::<KeyDescriptor>(json).is_err());
    }
}
