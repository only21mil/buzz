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

    /// Return the dedicated acceptance actor public key when provisioned.
    fn acceptance_public_key(&self) -> Result<[u8; 32], BackendError> {
        Err(BackendError::Credential)
    }

    /// Sign one already policy-selected acceptance event ID.
    fn sign_acceptance_digest(&self, _digest: [u8; 32]) -> Result<[u8; 64], BackendError> {
        Err(BackendError::Credential)
    }
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

struct SigningKey(Zeroizing<[u8; 32]>);

impl SigningKey {
    fn from_bytes(bytes: Zeroizing<[u8; 32]>) -> Result<Self, BackendError> {
        let mut secret =
            SecretKey::from_slice(bytes.as_ref()).map_err(|_| BackendError::InvalidKey)?;
        secret.non_secure_erase();
        Ok(Self(bytes))
    }

    fn keypair(&self) -> Result<Keypair, BackendError> {
        let mut secret =
            SecretKey::from_slice(self.0.as_ref()).map_err(|_| BackendError::InvalidKey)?;
        let keypair = Keypair::from_secret_key(SECP256K1, &secret);
        secret.non_secure_erase();
        Ok(keypair)
    }

    fn public_key(&self) -> Result<[u8; 32], BackendError> {
        let mut keypair = self.keypair()?;
        let public_key = keypair.x_only_public_key().0.serialize();
        keypair.non_secure_erase();
        Ok(public_key)
    }

    fn sign(&self, digest: [u8; 32]) -> Result<[u8; 64], BackendError> {
        let message = Message::from_digest(digest);
        let mut keypair = self.keypair()?;
        let signature = SECP256K1
            .sign_schnorr_no_aux_rand(&message, &keypair)
            .serialize();
        keypair.non_secure_erase();
        Ok(signature)
    }
}

/// Production deterministic BIP-340 backend loaded from fixed systemd credentials.
pub struct Secp256k1Backend {
    ci_event: SigningKey,
    nip98: SigningKey,
    manifest: SigningKey,
    acceptance_actor: Option<SigningKey>,
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
    /// Load the three compatibility-profile 32-byte raw secret-key credentials.
    ///
    /// The directory is opened once without following its final component.
    /// Each fixed credential is then opened relative to that descriptor with
    /// `O_NOFOLLOW`, checked as a single-link regular file, and read to an exact
    /// 32-byte bound.
    #[cfg(target_os = "linux")]
    pub fn from_systemd_credentials(directory: &Path) -> Result<Self, BackendError> {
        use nix::fcntl::{open, openat, OFlag};
        use nix::sys::stat::{fstat, Mode};
        use nix::unistd::{getegid, geteuid};
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
        let owner_uid = geteuid().as_raw();
        let owner_gid = getegid().as_raw();
        if !credential_directory_is_secure(
            stat.st_mode,
            stat.st_uid,
            stat.st_gid,
            owner_uid,
            owner_gid,
        ) {
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
            if !credential_metadata_is_secure(
                stat.st_mode,
                stat.st_uid,
                stat.st_gid,
                stat.st_nlink,
                stat.st_size,
                owner_uid,
                owner_gid,
            ) {
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
            acceptance_actor: None,
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn from_systemd_credentials(_directory: &Path) -> Result<Self, BackendError> {
        Err(BackendError::CredentialDirectory)
    }

    /// Load the compatibility credentials plus the distinct acceptance actor key.
    #[cfg(target_os = "linux")]
    pub fn from_systemd_credentials_with_acceptance(
        directory: &Path,
    ) -> Result<Self, BackendError> {
        use nix::fcntl::{open, openat, OFlag};
        use nix::sys::stat::{fstat, Mode};
        use nix::unistd::{getegid, geteuid};
        use std::fs::File;
        use std::io::Read;

        let mut backend = Self::from_systemd_credentials(directory)?;
        let descriptor = open(
            directory,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| BackendError::CredentialDirectory)?;
        let stat = fstat(&descriptor).map_err(|_| BackendError::CredentialDirectory)?;
        let owner_uid = geteuid().as_raw();
        let owner_gid = getegid().as_raw();
        if !credential_directory_is_secure(
            stat.st_mode,
            stat.st_uid,
            stat.st_gid,
            owner_uid,
            owner_gid,
        ) {
            return Err(BackendError::CredentialDirectory);
        }
        let key_fd = openat(
            &descriptor,
            "acceptance-actor.key",
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| BackendError::Credential)?;
        let stat = fstat(&key_fd).map_err(|_| BackendError::Credential)?;
        if !credential_metadata_is_secure(
            stat.st_mode,
            stat.st_uid,
            stat.st_gid,
            stat.st_nlink,
            stat.st_size,
            owner_uid,
            owner_gid,
        ) {
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
        backend.acceptance_actor = Some(SigningKey::from_bytes(bytes)?);
        Ok(backend)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn from_systemd_credentials_with_acceptance(
        _directory: &Path,
    ) -> Result<Self, BackendError> {
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

/// systemd delivers `$CREDENTIALS_DIRECTORY` in one of two shapes. Older
/// managers chown the directory and every file to the service account
/// (`0500`, `0400`). systemd 259 (259.5 on the clean host) keeps them root
/// owned with no world bits and grants the service read access through an ACL:
/// directory `0550`, files `0440`, both `root:root`. Both shapes are accepted.
/// Any group or world write bit, any world bit, any setuid, setgid, or sticky
/// bit, and any owner other than root or the service account fail closed.
#[cfg(target_os = "linux")]
fn credential_directory_is_secure(
    mode: u32,
    owner_uid: u32,
    owner_gid: u32,
    service_uid: u32,
    service_gid: u32,
) -> bool {
    use nix::sys::stat::SFlag;

    if SFlag::from_bits_truncate(mode) != SFlag::S_IFDIR {
        return false;
    }
    let permissions = mode & 0o7777;
    (owner_uid == service_uid && matches!(permissions, 0o500 | 0o700))
        || (owner_uid == 0
            && (owner_gid == 0 || owner_gid == service_gid)
            && matches!(permissions, 0o500 | 0o550))
}

/// One credential file: a single-link regular file of exactly 32 bytes in
/// either delivery shape (see [`credential_directory_is_secure`]).
#[cfg(target_os = "linux")]
fn credential_metadata_is_secure(
    mode: u32,
    owner_uid: u32,
    owner_gid: u32,
    link_count: u64,
    size: i64,
    service_uid: u32,
    service_gid: u32,
) -> bool {
    use nix::sys::stat::SFlag;

    if SFlag::from_bits_truncate(mode) != SFlag::S_IFREG || link_count != 1 || size != 32 {
        return false;
    }
    let permissions = mode & 0o7777;
    (owner_uid == service_uid && permissions == 0o400)
        || (owner_uid == 0
            && (owner_gid == 0 || owner_gid == service_gid)
            && matches!(permissions, 0o400 | 0o440))
}

impl SigningBackend for Secp256k1Backend {
    fn public_key(&self, selector: KeySelector) -> Result<[u8; 32], BackendError> {
        self.key(selector).public_key()
    }

    fn sign_digest(
        &self,
        selector: KeySelector,
        digest: [u8; 32],
    ) -> Result<[u8; 64], BackendError> {
        self.key(selector).sign(digest)
    }

    fn acceptance_public_key(&self) -> Result<[u8; 32], BackendError> {
        self.acceptance_actor
            .as_ref()
            .ok_or(BackendError::Credential)?
            .public_key()
    }

    fn sign_acceptance_digest(&self, digest: [u8; 32]) -> Result<[u8; 64], BackendError> {
        self.acceptance_actor
            .as_ref()
            .ok_or(BackendError::Credential)?
            .sign(digest)
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
    fn acceptance_profile_requires_and_uses_the_distinct_fixed_credential() {
        let directory = tempdir().expect("credential directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("credential directory mode");
        for (name, scalar) in [
            ("ci-event.key", 1_u8),
            ("nip98.key", 2),
            ("manifest.key", 3),
            ("acceptance-actor.key", 4),
        ] {
            let mut bytes = [0_u8; 32];
            bytes[31] = scalar;
            let path = directory.path().join(name);
            fs::write(&path, bytes).expect("write synthetic key");
            fs::set_permissions(path, fs::Permissions::from_mode(0o400)).expect("credential mode");
        }
        let backend = Secp256k1Backend::from_systemd_credentials_with_acceptance(directory.path())
            .expect("load acceptance credentials");
        let digest = [8; 32];
        let signature = backend
            .sign_acceptance_digest(digest)
            .expect("acceptance signature");
        let public = XOnlyPublicKey::from_slice(
            &backend
                .acceptance_public_key()
                .expect("acceptance public key"),
        )
        .expect("valid acceptance public key");
        let signature = Signature::from_slice(&signature).expect("valid signature");
        SECP256K1
            .verify_schnorr(&signature, &Message::from_digest(digest), &public)
            .expect("acceptance signature verifies");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn linked_or_wrong_sized_credentials_fail_closed() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().expect("credential directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("credential directory mode");
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

    #[test]
    #[cfg(target_os = "linux")]
    fn loose_mode_and_wrong_owner_are_rejected_without_detail() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        use nix::sys::stat::SFlag;
        use nix::unistd::{getegid, geteuid};

        let regular = SFlag::S_IFREG.bits();
        let owner = geteuid().as_raw();
        let group = getegid().as_raw();
        assert!(!credential_metadata_is_secure(
            regular | 0o444,
            owner,
            group,
            1,
            32,
            owner,
            group,
        ));
        assert!(!credential_metadata_is_secure(
            regular | 0o400,
            owner,
            group,
            1,
            32,
            owner.wrapping_add(1),
            group,
        ));
        assert_eq!(
            BackendError::Credential.to_string(),
            "required credential is unavailable"
        );
        assert!(!BackendError::Credential.to_string().contains("owner"));
        assert!(!BackendError::Credential.to_string().contains("mode"));

        let directory = tempdir().expect("credential directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("credential directory mode");
        for (selector, mode) in [
            (KeySelector::CiEvent, 0o444),
            (KeySelector::Nip98, 0o400),
            (KeySelector::Manifest, 0o400),
        ] {
            let mut bytes = [0_u8; 32];
            bytes[31] = selector as u8;
            let path = directory.path().join(selector.credential_name());
            fs::write(&path, bytes).expect("write credential");
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("credential mode");
        }
        assert_eq!(
            Secp256k1Backend::from_systemd_credentials(directory.path()).unwrap_err(),
            BackendError::Credential
        );
    }
    /// Shape recorded on the clean host (systemd 259.5, boot 5): the
    /// credentials directory is `dr-xr-x---+ root root` and each file is
    /// `-r--r-----+ root root`, 32 bytes, one link, with an ACL granting the
    /// service account read access. The service-owned `0500`/`0400` shape stays
    /// accepted; every writable, world-readable, special-bit, or third-party
    /// variant is rejected.
    #[test]
    #[cfg(target_os = "linux")]
    fn systemd_root_owned_acl_credentials_are_accepted_and_loose_variants_rejected() {
        use nix::sys::stat::SFlag;

        let directory = SFlag::S_IFDIR.bits();
        let regular = SFlag::S_IFREG.bits();
        let (service_uid, service_gid) = (1202, 1202);
        let other = 1203;

        for (mode, uid, gid, expected) in [
            (0o550, 0, 0, true),
            (0o500, 0, 0, true),
            (0o550, 0, service_gid, true),
            (0o500, service_uid, service_gid, true),
            (0o700, service_uid, service_gid, true),
            (0o555, 0, 0, false),
            (0o570, 0, 0, false),
            (0o750, 0, 0, false),
            (0o770, 0, 0, false),
            (0o1550, 0, 0, false),
            (0o2550, 0, 0, false),
            (0o550, 0, other, false),
            (0o550, other, other, false),
            (0o550, service_uid, service_gid, false),
            (0o400, 0, 0, false),
        ] {
            assert_eq!(
                credential_directory_is_secure(
                    directory | mode,
                    uid,
                    gid,
                    service_uid,
                    service_gid
                ),
                expected,
                "directory {mode:o} {uid}:{gid}"
            );
        }
        assert!(!credential_directory_is_secure(
            regular | 0o550,
            0,
            0,
            service_uid,
            service_gid
        ));

        for (mode, uid, gid, expected) in [
            (0o440, 0, 0, true),
            (0o400, 0, 0, true),
            (0o440, 0, service_gid, true),
            (0o400, service_uid, service_gid, true),
            (0o444, 0, 0, false),
            (0o460, 0, 0, false),
            (0o640, 0, 0, false),
            (0o4440, 0, 0, false),
            (0o440, 0, other, false),
            (0o440, other, other, false),
            (0o440, service_uid, service_gid, false),
            (0o600, service_uid, service_gid, false),
        ] {
            assert_eq!(
                credential_metadata_is_secure(
                    regular | mode,
                    uid,
                    gid,
                    1,
                    32,
                    service_uid,
                    service_gid
                ),
                expected,
                "file {mode:o} {uid}:{gid}"
            );
        }
        assert!(!credential_metadata_is_secure(
            regular | 0o440,
            0,
            0,
            2,
            32,
            service_uid,
            service_gid
        ));
        assert!(!credential_metadata_is_secure(
            regular | 0o440,
            0,
            0,
            1,
            33,
            service_uid,
            service_gid
        ));
        assert!(!credential_metadata_is_secure(
            directory | 0o440,
            0,
            0,
            1,
            32,
            service_uid,
            service_gid
        ));
    }
}
