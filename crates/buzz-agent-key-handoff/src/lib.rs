#![forbid(unsafe_code)]

use anyhow::{anyhow, bail, Context, Result};
use nostr::{FromBech32, Keys, SecretKey};
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::os::fd::{AsRawFd, BorrowedFd};
use zeroize::{Zeroize, Zeroizing};

pub mod parity_signature;

/// Versioned schema identifier for the root-owned public enrollment map.
pub const ENROLLMENT_SCHEMA: &str = "buzz-agent-enrollment-keys-v1";
pub const MAX_KEYRING_BLOB_BYTES: usize = 1024 * 1024;
pub const MAX_ENROLLMENT_MAP_BYTES: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Slug {
    Mempool,
    Genesis,
}

impl Slug {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "mempool" => Ok(Self::Mempool),
            "genesis" => Ok(Self::Genesis),
            _ => bail!("unsupported agent slug"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mempool => "mempool",
            Self::Genesis => "genesis",
        }
    }
}

pub fn parse_public_key_hex(value: &str) -> Result<String> {
    if value.len() != 64
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        bail!("public key must be 64 lowercase hexadecimal characters");
    }
    nostr::PublicKey::from_hex(value).context("invalid Nostr public key")?;
    Ok(value.to_owned())
}

pub fn secret_hex_and_public_key(value: &str) -> Result<(Zeroizing<String>, String)> {
    let secret = if value.starts_with("nsec1") {
        SecretKey::from_bech32(value).context("invalid nsec")?
    } else {
        if value.len() != 64 || !value.as_bytes().iter().all(u8::is_ascii_hexdigit) {
            bail!("secret must be nsec or 64 hexadecimal characters");
        }
        SecretKey::from_hex(value).context("invalid secret key")?
    };
    let keys = Keys::new(secret);
    let public_key = keys.public_key().to_hex();
    let secret_hex = Zeroizing::new(keys.secret_key().to_secret_hex());
    Ok((secret_hex, public_key))
}

pub fn validate_secret_binding(secret: &str, expected_pubkey: &str) -> Result<Zeroizing<String>> {
    let expected_pubkey = parse_public_key_hex(expected_pubkey)?;
    let (secret_hex, actual_pubkey) = secret_hex_and_public_key(secret)?;
    if actual_pubkey != expected_pubkey {
        bail!("secret does not match reviewed public key");
    }
    Ok(secret_hex)
}

pub struct UniqueStringMap(pub BTreeMap<String, Zeroizing<String>>);

impl<'de> Deserialize<'de> for UniqueStringMap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = UniqueStringMap;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an object with unique string keys and string values")
            }
            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut values = BTreeMap::new();
                while let Some((key, value)) = map.next_entry::<String, String>()? {
                    if values.insert(key, Zeroizing::new(value)).is_some() {
                        return Err(de::Error::custom("duplicate secret-map key"));
                    }
                }
                Ok(UniqueStringMap(values))
            }
        }
        deserializer.deserialize_map(UniqueVisitor)
    }
}

pub fn parse_unique_string_map(blob: &str) -> Result<UniqueStringMap> {
    if blob.len() > MAX_KEYRING_BLOB_BYTES {
        bail!("secret map is too large");
    }
    let mut deserializer = serde_json::Deserializer::from_str(blob);
    let map = UniqueStringMap::deserialize(&mut deserializer).context("invalid secret map")?;
    deserializer.end().context("trailing JSON data")?;
    Ok(map)
}

#[derive(Debug, Eq, PartialEq)]
pub struct EnrollmentKeys {
    pub mempool: String,
    pub genesis: String,
}

struct StrictKeys(BTreeMap<String, String>);

impl<'de> Deserialize<'de> for StrictKeys {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StrictKeysVisitor;
        impl<'de> Visitor<'de> for StrictKeysVisitor {
            type Value = StrictKeys;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("exact mempool and genesis public keys")
            }
            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut values = BTreeMap::new();
                while let Some((key, value)) = map.next_entry::<String, String>()? {
                    if key != "mempool" && key != "genesis" {
                        return Err(de::Error::custom("unknown enrollment slug"));
                    }
                    if values.insert(key, value).is_some() {
                        return Err(de::Error::custom("duplicate enrollment slug"));
                    }
                }
                if values.len() != 2
                    || !values.contains_key("mempool")
                    || !values.contains_key("genesis")
                {
                    return Err(de::Error::custom("both enrollment slugs are required"));
                }
                Ok(StrictKeys(values))
            }
        }
        deserializer.deserialize_map(StrictKeysVisitor)
    }
}

struct EnrollmentDocument {
    keys: StrictKeys,
}

impl<'de> Deserialize<'de> for EnrollmentDocument {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct EnrollmentVisitor;
        impl<'de> Visitor<'de> for EnrollmentVisitor {
            type Value = EnrollmentDocument;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an exact enrollment document")
            }
            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut schema = None;
                let mut keys = None;
                while let Some(field) = map.next_key::<String>()? {
                    match field.as_str() {
                        "schema" if schema.is_none() => schema = Some(map.next_value::<String>()?),
                        "keys" if keys.is_none() => keys = Some(map.next_value::<StrictKeys>()?),
                        "schema" | "keys" => return Err(de::Error::custom("duplicate field")),
                        _ => return Err(de::Error::unknown_field(&field, &["schema", "keys"])),
                    }
                }
                if schema.as_deref() != Some(ENROLLMENT_SCHEMA) {
                    return Err(de::Error::custom("invalid enrollment schema"));
                }
                Ok(EnrollmentDocument {
                    keys: keys.ok_or_else(|| de::Error::missing_field("keys"))?,
                })
            }
        }
        deserializer.deserialize_map(EnrollmentVisitor)
    }
}

pub fn parse_enrollment_map(input: &str) -> Result<EnrollmentKeys> {
    if input.len() > MAX_ENROLLMENT_MAP_BYTES {
        bail!("enrollment map is too large");
    }
    let mut deserializer = serde_json::Deserializer::from_str(input);
    let document =
        EnrollmentDocument::deserialize(&mut deserializer).context("invalid enrollment map")?;
    deserializer.end().context("trailing enrollment map data")?;
    let mempool = document
        .keys
        .0
        .get("mempool")
        .context("missing mempool public key")?;
    let genesis = document
        .keys
        .0
        .get("genesis")
        .context("missing genesis public key")?;
    if mempool == genesis {
        bail!("enrollment public keys must be distinct");
    }
    Ok(EnrollmentKeys {
        mempool: parse_public_key_hex(mempool)?,
        genesis: parse_public_key_hex(genesis)?,
    })
}

pub fn harden_process() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        use rustix::process::{
            set_dumpable_behavior, setrlimit, DumpableBehavior, Resource, Rlimit,
        };

        setrlimit(
            Resource::Core,
            Rlimit {
                current: Some(0),
                maximum: Some(0),
            },
        )
        .context("setrlimit RLIMIT_CORE")?;
        set_dumpable_behavior(DumpableBehavior::NotDumpable).context("prctl PR_SET_DUMPABLE")?;
    }
    Ok(())
}

pub fn require_anonymous_pipe(fd: BorrowedFd<'_>) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        use rustix::fs::{fstat, FileType};

        let stat = fstat(fd).context("fstat pipe descriptor")?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::Fifo {
            bail!("descriptor is not a pipe");
        }
        let target = fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd()))
            .context("resolve pipe descriptor")?;
        if !target.to_string_lossy().starts_with("pipe:[") {
            bail!("descriptor is not an anonymous pipe");
        }
    }
    Ok(())
}

pub fn wipe_string(value: &mut String) {
    value.zeroize();
}

pub fn exact_secret_line(input: &[u8]) -> Result<Zeroizing<String>> {
    if input.len() != 65 || input[64] != b'\n' {
        bail!("secret input must be exactly 64 lowercase hex characters plus newline");
    }
    if !input[..64]
        .iter()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        bail!("secret input must be lowercase hexadecimal");
    }
    Ok(Zeroizing::new(
        String::from_utf8(input[..64].to_vec())
            .map_err(|_| anyhow!("secret input is not UTF-8"))?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::pipe::{pipe_with, PipeFlags};
    use std::os::fd::AsFd;

    const SK1: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const PK1: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const PK2: &str = "c6047f9441ed7d6d3045406e95c07cd85a9e8b036e67d4073b95c709ee5bcc86";

    #[test]
    fn rejects_duplicate_secret_map_keys() {
        assert!(parse_unique_string_map(r#"{"a":"one","a":"two"}"#).is_err());
    }

    #[test]
    fn derives_known_public_keys() {
        let (secret, public) = secret_hex_and_public_key(SK1).unwrap();
        assert_eq!(secret.as_str(), SK1);
        assert_eq!(public, PK1);
    }

    #[test]
    fn validates_secret_binding() {
        assert_eq!(validate_secret_binding(SK1, PK1).unwrap().as_str(), SK1);
        assert!(validate_secret_binding(SK1, PK2).is_err());
    }

    #[test]
    fn parses_exact_enrollment_map() {
        let input = format!(
            r#"{{"schema":"{ENROLLMENT_SCHEMA}","keys":{{"mempool":"{PK1}","genesis":"{PK2}"}}}}"#
        );
        let parsed = parse_enrollment_map(&input).unwrap();
        assert_eq!(parsed.mempool, PK1);
        assert_eq!(parsed.genesis, PK2);
    }

    #[test]
    fn rejects_shared_enrollment_identity() {
        let input = format!(
            r#"{{"schema":"{ENROLLMENT_SCHEMA}","keys":{{"mempool":"{PK1}","genesis":"{PK1}"}}}}"#
        );
        assert!(parse_enrollment_map(&input).is_err());
    }

    #[test]
    fn rejects_duplicate_or_extra_enrollment_fields() {
        let duplicate = format!(
            r#"{{"schema":"{ENROLLMENT_SCHEMA}","schema":"{ENROLLMENT_SCHEMA}","keys":{{"mempool":"{PK1}","genesis":"{PK2}"}}}}"#
        );
        let extra = format!(
            r#"{{"schema":"{ENROLLMENT_SCHEMA}","keys":{{"mempool":"{PK1}","genesis":"{PK2}"}},"extra":true}}"#
        );
        assert!(parse_enrollment_map(&duplicate).is_err());
        assert!(parse_enrollment_map(&extra).is_err());
    }

    #[test]
    fn enforces_exact_secret_framing() {
        let valid = format!("{SK1}\n");
        assert_eq!(exact_secret_line(valid.as_bytes()).unwrap().as_str(), SK1);
        assert!(exact_secret_line(SK1.as_bytes()).is_err());
        assert!(exact_secret_line(format!("{SK1}\nX").as_bytes()).is_err());
        let mixed = "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";
        assert!(exact_secret_line(format!("{}\n", mixed.to_uppercase()).as_bytes()).is_err());
    }

    #[test]
    fn accepts_only_anonymous_pipe_descriptors() {
        let (read_end, write_end) = pipe_with(PipeFlags::CLOEXEC).unwrap();
        assert!(require_anonymous_pipe(read_end.as_fd()).is_ok());
        assert!(require_anonymous_pipe(write_end.as_fd()).is_ok());

        let regular = tempfile::tempfile().unwrap();
        assert!(require_anonymous_pipe(regular.as_fd()).is_err());
    }
}
