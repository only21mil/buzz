use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use nostr::secp256k1::XOnlyPublicKey;
use serde::Deserialize;
use thiserror::Error;

use crate::{
    Operation, OperationSet, PeerPolicy, PublicIdentity, SelectorSet, SigningPolicy,
    ACCEPTANCE_BINDING_PATH,
};

/// Exact production configuration schema.
pub const CONFIG_SCHEMA_VERSION: u32 = 1;
const MAX_CONFIG_SIZE: u64 = 16 * 1024;

/// Validated public service configuration. It contains no secret material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyholderConfig {
    /// Exact peer credentials and granted operations.
    pub peer_policy: PeerPolicy,
    /// Closed public key selectors and generations.
    pub selectors: SelectorSet,
    /// Exact HTTPS origin accepted for NIP-98 authorization.
    pub nip98_origin: String,
    /// Optional static locator and credential selector for acceptance authority.
    pub acceptance: Option<AcceptanceBindingConfig>,
}

/// Static acceptance authority configuration. Dynamic activation values are
/// loaded only from the post-freeze root-owned receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptanceBindingConfig {
    /// Fixed public receipt shared with controld.
    pub binding_receipt_path: std::path::PathBuf,
    /// Fixed systemd credential selector for the dedicated actor key.
    pub credential_selector: String,
}

/// Exact fixed systemd credential name for acceptance signing.
pub const ACCEPTANCE_CREDENTIAL_SELECTOR: &str = "acceptance-actor.key";

impl KeyholderConfig {
    /// Load a bounded JSON configuration file.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let file = File::open(path).map_err(ConfigError::Read)?;
        let length = file.metadata().map_err(ConfigError::Read)?.len();
        if length == 0 || length > MAX_CONFIG_SIZE {
            return Err(ConfigError::Invalid);
        }
        let mut bytes = Vec::with_capacity(length as usize);
        file.take(MAX_CONFIG_SIZE + 1)
            .read_to_end(&mut bytes)
            .map_err(ConfigError::Read)?;
        if bytes.len() as u64 != length {
            return Err(ConfigError::Invalid);
        }
        Self::from_slice(&bytes)
    }

    /// Parse and validate bounded public configuration bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ConfigError> {
        if bytes.is_empty() || bytes.len() as u64 > MAX_CONFIG_SIZE {
            return Err(ConfigError::Invalid);
        }
        let raw: RawConfig = serde_json::from_slice(bytes).map_err(|_| ConfigError::Invalid)?;
        if raw.schema_version != CONFIG_SCHEMA_VERSION {
            return Err(ConfigError::Invalid);
        }
        let mut operations = OperationSet::NONE;
        for operation in raw.peer.allowed_operations {
            let operation = operation.protocol_operation();
            if operations.contains(operation) {
                return Err(ConfigError::Invalid);
            }
            operations = operations.union(OperationSet::only(operation));
        }
        if operations == OperationSet::NONE {
            return Err(ConfigError::Invalid);
        }
        let selectors = SelectorSet::new(
            raw.selectors.ci_event.identity()?,
            raw.selectors.nip98.identity()?,
            raw.selectors.manifest.identity()?,
        )
        .ok_or(ConfigError::Invalid)?;
        SigningPolicy::validate_nip98_origin(&raw.nip98_origin)
            .map_err(|_| ConfigError::Invalid)?;
        let acceptance = raw.acceptance.map(RawAcceptance::binding).transpose()?;
        if operations.contains(Operation::SignAcceptanceMutation) != acceptance.is_some()
            || operations.contains(Operation::DescribeAcceptance) != acceptance.is_some()
        {
            return Err(ConfigError::Invalid);
        }
        Ok(Self {
            peer_policy: PeerPolicy {
                uid: raw.peer.uid,
                gid: raw.peer.gid,
                allowed_operations: operations,
            },
            selectors,
            nip98_origin: raw.nip98_origin,
            acceptance,
        })
    }
}

/// Public configuration failure. Parse details and file paths are omitted.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// The configuration file could not be read.
    #[error("keyholder configuration is unavailable")]
    Read(#[source] io::Error),
    /// The configuration is malformed or violates the closed schema.
    #[error("keyholder configuration is invalid")]
    Invalid,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    schema_version: u32,
    peer: RawPeer,
    selectors: RawSelectors,
    nip98_origin: String,
    #[serde(default)]
    acceptance: Option<RawAcceptance>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPeer {
    uid: u32,
    gid: u32,
    allowed_operations: Vec<RawOperation>,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RawOperation {
    Describe,
    SignCiEvent,
    Nip98Authorize,
    SignManifest,
    DescribeAcceptance,
    SignAcceptanceMutation,
}

impl RawOperation {
    const fn protocol_operation(self) -> Operation {
        match self {
            Self::Describe => Operation::Describe,
            Self::SignCiEvent => Operation::SignCiEvent,
            Self::Nip98Authorize => Operation::Nip98Authorize,
            Self::SignManifest => Operation::SignManifest,
            Self::DescribeAcceptance => Operation::DescribeAcceptance,
            Self::SignAcceptanceMutation => Operation::SignAcceptanceMutation,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSelectors {
    ci_event: RawIdentity,
    nip98: RawIdentity,
    manifest: RawIdentity,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIdentity {
    public_key: String,
    generation: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAcceptance {
    binding_receipt_path: String,
    credential_selector: String,
}

impl RawAcceptance {
    fn binding(self) -> Result<AcceptanceBindingConfig, ConfigError> {
        if self.binding_receipt_path != ACCEPTANCE_BINDING_PATH
            || self.credential_selector != ACCEPTANCE_CREDENTIAL_SELECTOR
        {
            return Err(ConfigError::Invalid);
        }
        Ok(AcceptanceBindingConfig {
            binding_receipt_path: self.binding_receipt_path.into(),
            credential_selector: self.credential_selector,
        })
    }
}

impl RawIdentity {
    fn identity(self) -> Result<PublicIdentity, ConfigError> {
        if self.public_key.len() != 64
            || !self
                .public_key
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ConfigError::Invalid);
        }
        let bytes = hex::decode(self.public_key).map_err(|_| ConfigError::Invalid)?;
        let public_key: [u8; 32] = bytes.try_into().map_err(|_| ConfigError::Invalid)?;
        XOnlyPublicKey::from_slice(&public_key).map_err(|_| ConfigError::Invalid)?;
        if self.generation == 0 {
            return Err(ConfigError::Invalid);
        }
        Ok(PublicIdentity {
            public_key,
            generation: self.generation,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CI_KEY: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const NIP98_KEY: &str = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
    const MANIFEST_KEY: &str = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";

    fn config(operations: &str, origin: &str) -> Vec<u8> {
        format!(
            r#"{{
                "schema_version": 1,
                "peer": {{"uid": 1000, "gid": 1001, "allowed_operations": {operations}}},
                "selectors": {{
                    "ci_event": {{"public_key": "{CI_KEY}", "generation": 1}},
                    "nip98": {{"public_key": "{NIP98_KEY}", "generation": 2}},
                    "manifest": {{"public_key": "{MANIFEST_KEY}", "generation": 3}}
                }},
                "nip98_origin": "{origin}"
            }}"#
        )
        .into_bytes()
    }

    #[test]
    fn valid_config_builds_closed_peer_and_selector_state() {
        let parsed = KeyholderConfig::from_slice(&config(
            r#"["describe", "sign_ci_event", "nip98_authorize", "sign_manifest"]"#,
            "https://relay.example.test",
        ))
        .expect("valid config");
        let compatibility_operations = OperationSet::only(Operation::Describe)
            .union(OperationSet::only(Operation::SignCiEvent))
            .union(OperationSet::only(Operation::Nip98Authorize))
            .union(OperationSet::only(Operation::SignManifest));
        assert_eq!(
            parsed.peer_policy.allowed_operations,
            compatibility_operations
        );
        assert_eq!(
            parsed
                .selectors
                .identity(crate::KeySelector::Nip98)
                .generation,
            2
        );
    }

    #[test]
    fn duplicate_operations_invalid_keys_and_non_origin_urls_are_rejected() {
        assert!(KeyholderConfig::from_slice(&config(
            r#"["describe", "describe"]"#,
            "https://relay.example.test"
        ))
        .is_err());
        assert!(KeyholderConfig::from_slice(&config(
            r#"["describe"]"#,
            "http://relay.example.test"
        ))
        .is_err());
        assert!(KeyholderConfig::from_slice(&config(
            r#"["describe"]"#,
            "https://relay.example.test/path"
        ))
        .is_err());
        let uppercase = String::from_utf8(config(r#"["describe"]"#, "https://relay.example.test"))
            .expect("UTF-8 config")
            .replace(CI_KEY, &CI_KEY.to_uppercase());
        assert!(KeyholderConfig::from_slice(uppercase.as_bytes()).is_err());
        assert!(KeyholderConfig::from_slice(&config(
            r#"["sign_acceptance_mutation"]"#,
            "https://relay.example.test"
        ))
        .is_err());
    }

    #[test]
    fn acceptance_config_contains_only_fixed_receipt_and_credential_selectors() {
        let mut value: serde_json::Value = serde_json::from_slice(&config(
            r#"["describe", "describe_acceptance", "sign_acceptance_mutation"]"#,
            "https://relay.example.test",
        ))
        .expect("config");
        value.as_object_mut().expect("config object").insert(
            "acceptance".to_owned(),
            serde_json::json!({
                "binding_receipt_path": ACCEPTANCE_BINDING_PATH,
                "credential_selector": ACCEPTANCE_CREDENTIAL_SELECTOR
            }),
        );
        let parsed =
            KeyholderConfig::from_slice(&serde_json::to_vec(&value).expect("config bytes"))
                .expect("static acceptance config");
        let acceptance = parsed.acceptance.expect("acceptance binding");
        assert_eq!(
            acceptance.binding_receipt_path,
            Path::new(ACCEPTANCE_BINDING_PATH)
        );
        assert_eq!(
            acceptance.credential_selector,
            ACCEPTANCE_CREDENTIAL_SELECTOR
        );

        value["acceptance"]["binding_receipt_path"] = serde_json::json!("/tmp/forbidden");
        assert!(
            KeyholderConfig::from_slice(&serde_json::to_vec(&value).expect("config bytes"))
                .is_err()
        );
        value["acceptance"]["binding_receipt_path"] = serde_json::json!(ACCEPTANCE_BINDING_PATH);
        value["acceptance"]["scenario_sha256"] = serde_json::json!("09".repeat(32));
        assert!(
            KeyholderConfig::from_slice(&serde_json::to_vec(&value).expect("config bytes"))
                .is_err()
        );
    }

    #[test]
    fn socket_and_secret_descriptor_fields_are_not_part_of_the_daemon_schema() {
        let valid = config(r#"["describe"]"#, "https://relay.example.test");
        let mut value: serde_json::Value = serde_json::from_slice(&valid).expect("config value");
        value.as_object_mut().expect("config object").insert(
            "socket".to_owned(),
            serde_json::json!(crate::KEYHOLDER_SOCKET_PATH),
        );
        assert!(
            KeyholderConfig::from_slice(&serde_json::to_vec(&value).expect("config bytes"))
                .is_err()
        );

        value
            .as_object_mut()
            .expect("config object")
            .remove("socket");
        value
            .as_object_mut()
            .expect("config object")
            .insert("key_descriptor".to_owned(), serde_json::json!("/forbidden"));
        assert!(
            KeyholderConfig::from_slice(&serde_json::to_vec(&value).expect("config bytes"))
                .is_err()
        );
    }
}
