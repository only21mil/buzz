use std::fmt;
use std::path::Path;

use nostr::secp256k1::{Keypair, Message, SecretKey, SECP256K1};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::KeySelector;

/// Secret-bearing signing boundary used by the keyholder service.
pub trait SigningBackend {
    /// Return the public key for a fixed selector.
    fn public_key(&self, selector: KeySelector) -> Result<[u8; 32], BackendError>;

    /// Deterministically sign one already-validated 32-byte digest.
    fn sign_digest(
        &self,
        selector: KeySelector,
        digest: [u8; 32],
    ) -> Result<[u8; 64], BackendError>;
}

/// Sanitized backend failure. It never contains credential names, paths, or key bytes.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum BackendError {
    /// The systemd credential directory is missing or unsafe.
    #[error("credential directory is unavailable")]
    CredentialDirectory,
    /// A required fixed credential is missing or unsafe.
    #[error("required credential is unavailable")]
    Credential,
    /// Credential bytes do not encode a valid secp256k1 secret key.
    #[error("required credential is invalid")]
    InvalidKey,
    /// The signing operation failed.
    #[error("signing backend is unavailable")]
    Signing,
}

struct SigningKey(Keypair);

impl SigningKey {
    fn from_bytes(bytes: Zeroizing<[u8; 32]>) -> Result<Self, BackendError> {
        let mut secret =
            SecretKey::from_slice(bytes.as_ref()).map_err(|_| BackendError::InvalidKey)?;
        let keypair = Keypair::from_secret_key(SECP256K1, &secret);
        secret.non_secure_erase();
        Ok(Self(keypair))
    }

    fn public_key(&self) -> [u8; 32] {
        self.0.x_only_public_key().0.serialize()
    }

    fn sign(&self, digest: [u8; 32]) -> Result<[u8; 64], BackendError> {
        let message = Message::from_digest(digest);
        Ok(SECP256K1
            .sign_schnorr_no_aux_rand(&message, &self.0)
            .serialize())
    }
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        self.0.non_secure_erase();
    }
}

/// Production deterministic BIP-340 backend loaded from fixed systemd credentials.
pub struct Secp256k1Backend {
    ci_event: SigningKey,
    nip98: SigningKey,
    manifest: SigningKey,
}

impl fmt::Debug for Secp256k1Backend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Secp256k1Backend")
            .field("credentials", &"[REDACTED]")
            .finish()
    }
}

impl Secp256k1Backend {
    /// Load the three exact 32-byte raw secret-key credentials.
    ///
    /// The directory is opened once without following its final component.
    /// Each fixed credential is then opened relative to that descriptor with
    /// `O_NOFOLLOW`, checked as a single-link regular file, and read to an exact
    /// 32-byte bound.
    #[cfg(target_os = "linux")]
    pub fn from_systemd_credentials(directory: &Path) -> Result<Self, BackendError> {
        use nix::fcntl::{open, openat, OFlag};
        use nix::sys::stat::{fstat, Mode, SFlag};
        use std::fs::File;
        use std::io::Read;

        if !directory.is_absolute() {
            return Err(BackendError::CredentialDirectory);
        }
        let descriptor = open(
            directory,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| BackendError::CredentialDirectory)?;
        let stat = fstat(&descriptor).map_err(|_| BackendError::CredentialDirectory)?;
        if SFlag::from_bits_truncate(stat.st_mode) != SFlag::S_IFDIR || stat.st_mode & 0o022 != 0 {
            return Err(BackendError::CredentialDirectory);
        }

        let read_key = |selector: KeySelector| -> Result<SigningKey, BackendError> {
            let key_fd = openat(
                &descriptor,
                selector.credential_name(),
                OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| BackendError::Credential)?;
            let stat = fstat(&key_fd).map_err(|_| BackendError::Credential)?;
            if SFlag::from_bits_truncate(stat.st_mode) != SFlag::S_IFREG
                || stat.st_nlink != 1
                || stat.st_size != 32
                || stat.st_mode & 0o022 != 0
            {
                return Err(BackendError::Credential);
            }
            let mut bytes = Zeroizing::new([0_u8; 32]);
            let mut file = File::from(key_fd);
            file.read_exact(bytes.as_mut())
                .map_err(|_| BackendError::Credential)?;
            let mut trailing = [0_u8; 1];
            if file
                .read(&mut trailing)
                .map_err(|_| BackendError::Credential)?
                != 0
            {
                return Err(BackendError::Credential);
            }
            SigningKey::from_bytes(bytes)
        };

        Ok(Self {
            ci_event: read_key(KeySelector::CiEvent)?,
            nip98: read_key(KeySelector::Nip98)?,
            manifest: read_key(KeySelector::Manifest)?,
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn from_systemd_credentials(_directory: &Path) -> Result<Self, BackendError> {
        Err(BackendError::CredentialDirectory)
    }

    fn key(&self, selector: KeySelector) -> &SigningKey {
        match selector {
            KeySelector::CiEvent => &self.ci_event,
            KeySelector::Nip98 => &self.nip98,
            KeySelector::Manifest => &self.manifest,
        }
    }
}

impl SigningBackend for Secp256k1Backend {
    fn public_key(&self, selector: KeySelector) -> Result<[u8; 32], BackendError> {
        Ok(self.key(selector).public_key())
    }

    fn sign_digest(
        &self,
        selector: KeySelector,
        digest: [u8; 32],
    ) -> Result<[u8; 64], BackendError> {
        self.key(selector).sign(digest)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use nostr::secp256k1::{schnorr::Signature, XOnlyPublicKey};
    use tempfile::tempdir;

    use super::*;

    #[test]
    #[cfg(target_os = "linux")]
    fn fixed_credentials_load_and_sign_deterministically() {
        let directory = tempdir().expect("credential directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("credential directory mode");
        for (selector, scalar) in [
            (KeySelector::CiEvent, 1_u8),
            (KeySelector::Nip98, 2),
            (KeySelector::Manifest, 3),
        ] {
            let mut bytes = [0_u8; 32];
            bytes[31] = scalar;
            let path = directory.path().join(selector.credential_name());
            fs::write(&path, bytes).expect("write synthetic key");
            fs::set_permissions(path, fs::Permissions::from_mode(0o400)).expect("credential mode");
        }

        let backend = Secp256k1Backend::from_systemd_credentials(directory.path())
            .expect("load synthetic credentials");
        let digest = [7_u8; 32];
        let first = backend
            .sign_digest(KeySelector::CiEvent, digest)
            .expect("first signature");
        let second = backend
            .sign_digest(KeySelector::CiEvent, digest)
            .expect("second signature");
        assert_eq!(first, second);

        let public = XOnlyPublicKey::from_slice(
            &backend
                .public_key(KeySelector::CiEvent)
                .expect("public key"),
        )
        .expect("valid public key");
        let signature = Signature::from_slice(&first).expect("valid signature");
        SECP256K1
            .verify_schnorr(&signature, &Message::from_digest(digest), &public)
            .expect("signature verifies");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn linked_or_wrong_sized_credentials_fail_closed() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().expect("credential directory");
        let target = directory.path().join("target");
        fs::write(&target, [1_u8; 32]).expect("write target");
        symlink(&target, directory.path().join("ci-event.key")).expect("link credential");
        fs::write(directory.path().join("nip98.key"), [2_u8; 31]).expect("short credential");
        fs::write(directory.path().join("manifest.key"), [3_u8; 32]).expect("manifest credential");
        assert_eq!(
            Secp256k1Backend::from_systemd_credentials(directory.path()).unwrap_err(),
            BackendError::Credential
        );
    }
}
