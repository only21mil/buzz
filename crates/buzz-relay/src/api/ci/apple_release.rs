//! Apple release request profile: the `apple_release` object carried inside a
//! kind-46100 CI request, and the fail-closed validator that admits or refuses
//! it before any executor, credential, or App Store Connect call exists.
//!
//! Contract: `docs/ci/apple-release-request.md`. Shape:
//! `deploy/native-ci/apple-release/apple-release-request.schema.json`. The
//! fixtures under `deploy/native-ci/apple-release/fixtures/` are shared by the
//! Python schema tests and the unit tests below, so the two validators cannot
//! drift on an accepted or refused example without a test failing.
//!
//! The base envelope (`buzz_core::ci::CiRequestEnvelope`) ignores unknown
//! content fields, so an `apple_release` object rides inside an otherwise
//! ordinary request. This module validates it only when present. Refusals are
//! deterministic and ordered: requester scope, secret material, target,
//! profile shape, commit pin, executor capability.

use std::collections::HashSet;
use std::fmt;

use buzz_auth::Scope;
use buzz_core::ci::CiRequestEnvelope;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Top-level content key that marks a kind-46100 request as an Apple release.
pub const APPLE_RELEASE_PROFILE_KEY: &str = "apple_release";
/// Profile schema version implemented by this module.
pub const APPLE_RELEASE_SCHEMA_VERSION: u32 = 1;
/// The only executor class an Apple release may name.
pub const APPLE_EXECUTOR_CLASS: &str = "apple-mbp";

/// Executor can compile and archive the Apple targets from exact source.
pub const CAPABILITY_BUILD: &str = "apple-build";
/// Executor can sign with a keyholder-resident identity.
pub const CAPABILITY_CODESIGN: &str = "apple-codesign";
/// Executor can submit to and staple from Apple notary service.
pub const CAPABILITY_NOTARIZE: &str = "apple-notarize";
/// Executor can upload a build to App Store Connect for TestFlight.
pub const CAPABILITY_TESTFLIGHT_UPLOAD: &str = "apple-testflight-upload";
/// Every capability name an operator may advertise for the Apple executor.
pub const KNOWN_CAPABILITIES: [&str; 4] = [
    CAPABILITY_BUILD,
    CAPABILITY_CODESIGN,
    CAPABILITY_NOTARIZE,
    CAPABILITY_TESTFLIGHT_UPLOAD,
];

const MAX_BUNDLE_IDENTIFIERS: usize = 8;
const MAX_BUNDLE_IDENTIFIER_LEN: usize = 155;
const MAX_BETA_GROUP_REFS: usize = 16;
const MAX_WHAT_TO_TEST_CHARS: usize = 4000;
const MIN_WAIT_SECONDS: u64 = 60;
const MAX_WAIT_SECONDS: u64 = 7200;
const MAX_RETENTION_DAYS: u64 = 90;
const SECRET_KEY_FRAGMENTS: [&str; 12] = [
    "private_key",
    "privatekey",
    "password",
    "passphrase",
    "secret",
    "token",
    "api_key",
    "apikey",
    "p8",
    "p12",
    "pkcs",
    "mobileprovision",
];
const SECRET_VALUE_MARKERS: [&str; 2] = ["-----BEGIN", "AuthKey_"];
const OPAQUE_BLOB_MIN_LEN: usize = 80;

/// Closed set of Apple release outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AppleReleaseTarget {
    /// Developer ID signed, notarized, stapled macOS app and DMG.
    MacosNotarized,
    /// App Store distribution signed IPA uploaded to TestFlight.
    IosTestflight,
}

impl AppleReleaseTarget {
    /// Parse the wire name; `None` for anything outside the closed set.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "macos-notarized" => Some(Self::MacosNotarized),
            "ios-testflight" => Some(Self::IosTestflight),
            _ => None,
        }
    }

    /// Wire name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MacosNotarized => "macos-notarized",
            Self::IosTestflight => "ios-testflight",
        }
    }

    /// Executor capabilities the target needs, all of them.
    pub const fn required_capabilities(self) -> &'static [&'static str] {
        match self {
            Self::MacosNotarized => &[CAPABILITY_BUILD, CAPABILITY_CODESIGN, CAPABILITY_NOTARIZE],
            Self::IosTestflight => &[
                CAPABILITY_BUILD,
                CAPABILITY_CODESIGN,
                CAPABILITY_TESTFLIGHT_UPLOAD,
            ],
        }
    }
}

/// Closed set of build architectures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AppleArchitecture {
    /// Apple silicon.
    #[serde(rename = "arm64")]
    Arm64,
    /// Intel.
    #[serde(rename = "x86_64")]
    X86_64,
}

/// Notary service parameters for `macos-notarized`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppleNotarization {
    /// Keyholder entry name for the notary credential. Never the credential.
    pub credential_ref: String,
    /// Staple the ticket to the app and DMG after acceptance.
    pub staple: bool,
    /// Upper bound on waiting for the notary verdict.
    pub wait_timeout_seconds: u64,
}

/// App Store Connect and TestFlight parameters for `ios-testflight`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppleTestflight {
    /// App Store Connect app record ID (decimal string).
    pub asc_app_id: String,
    /// Keyholder entry name for the App Store Connect API credential.
    pub credential_ref: String,
    /// Beta group names to add the build to; empty means upload only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub beta_group_refs: Vec<String>,
    /// TestFlight "What to Test" notes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what_to_test: Option<String>,
    /// Upper bound on waiting for build processing.
    pub wait_for_processing_seconds: u64,
}

/// The `apple_release` profile after shape validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppleReleaseRequest {
    /// Profile schema version.
    pub schema_version: u32,
    /// Release outcome.
    pub target: AppleReleaseTarget,
    /// Executor class; only `apple-mbp` exists.
    pub executor_class: String,
    /// Exact Buzz source commit; must equal the envelope `tip_oid`.
    pub source_commit: String,
    /// Exact controller (Budget) commit when a controller is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller_commit: Option<String>,
    /// Marketing version `X.Y.Z`.
    pub version: String,
    /// Build number; required for TestFlight.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_number: Option<String>,
    /// App bundle identifier first, then any extension identifiers.
    pub bundle_identifiers: Vec<String>,
    /// Apple developer team.
    pub team_id: String,
    /// Keyholder entry name for the signing identity. Never the identity.
    pub signing_identity_ref: String,
    /// Expected leaf certificate fingerprint, when pinned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_certificate_sha256: Option<String>,
    /// Architectures to build and sign.
    pub architectures: Vec<AppleArchitecture>,
    /// Notarization parameters; present only for `macos-notarized`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notarization: Option<AppleNotarization>,
    /// TestFlight parameters; present only for `ios-testflight`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub testflight: Option<AppleTestflight>,
    /// Signed approval event that authorized this release.
    pub approval_event_id: String,
    /// Days the executor keeps artifacts and logs.
    pub artifact_retention_days: u64,
}

/// Closed refusal reasons, in evaluation order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppleReleaseRefusalReason {
    /// Requester lacks `jobs:write`.
    UnauthorizedRequester,
    /// A key or value in the profile looks like credential material.
    SecretMaterial,
    /// `target` is outside the closed set.
    UnknownTarget,
    /// The profile does not match the v1 shape.
    MalformedProfile,
    /// `source_commit` is not a full lowercase OID equal to the envelope tip.
    UnpinnedCommit,
    /// No advertised executor covers the target.
    MissingCapability,
}

impl AppleReleaseRefusalReason {
    /// Wire name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnauthorizedRequester => "unauthorized_requester",
            Self::SecretMaterial => "secret_material",
            Self::UnknownTarget => "unknown_target",
            Self::MalformedProfile => "malformed_profile",
            Self::UnpinnedCommit => "unpinned_commit",
            Self::MissingCapability => "missing_capability",
        }
    }
}

impl fmt::Display for AppleReleaseRefusalReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A refusal with its reason and a value-free detail string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppleReleaseRefusal {
    /// Closed reason code.
    pub reason: AppleReleaseRefusalReason,
    /// Names the failing field or bound. Never echoes a rejected value.
    pub detail: String,
}

impl AppleReleaseRefusal {
    fn new(reason: AppleReleaseRefusalReason, detail: impl Into<String>) -> Self {
        Self {
            reason,
            detail: detail.into(),
        }
    }

    fn malformed(detail: impl Into<String>) -> Self {
        Self::new(AppleReleaseRefusalReason::MalformedProfile, detail)
    }
}

impl fmt::Display for AppleReleaseRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "apple release request refused ({}): {}",
            self.reason, self.detail
        )
    }
}

impl std::error::Error for AppleReleaseRefusal {}

/// Return the `apple_release` profile from kind-46100 content, if the request
/// names one.
pub fn apple_release_profile(content: &Value) -> Option<&Value> {
    content.get(APPLE_RELEASE_PROFILE_KEY)
}

/// Admit or refuse an Apple release profile against its validated envelope,
/// the requester's granted scopes, and the executor capabilities the relay
/// operator has advertised.
///
/// Checks run in the order of [`AppleReleaseRefusalReason`]; the first failure
/// is the refusal. Success returns the typed profile and grants nothing else:
/// scheduling, custody, and App Store Connect access are later deliverables.
pub fn validate_apple_release_request(
    envelope: &CiRequestEnvelope,
    profile: &Value,
    requester_scopes: &[Scope],
    offered_capabilities: &HashSet<String>,
) -> Result<AppleReleaseRequest, AppleReleaseRefusal> {
    if !requester_scopes.contains(&Scope::JobsWrite) {
        return Err(AppleReleaseRefusal::new(
            AppleReleaseRefusalReason::UnauthorizedRequester,
            "requester lacks jobs:write",
        ));
    }
    scan_for_secret_material(profile, APPLE_RELEASE_PROFILE_KEY)?;
    let object = profile
        .as_object()
        .ok_or_else(|| AppleReleaseRefusal::malformed("apple_release must be an object"))?;
    let target = match object.get("target") {
        None => return Err(AppleReleaseRefusal::malformed("target is required")),
        Some(Value::String(name)) => AppleReleaseTarget::parse(name).ok_or_else(|| {
            AppleReleaseRefusal::new(
                AppleReleaseRefusalReason::UnknownTarget,
                "target is not macos-notarized or ios-testflight",
            )
        })?,
        Some(_) => return Err(AppleReleaseRefusal::malformed("target must be a string")),
    };
    let request: AppleReleaseRequest = serde_json::from_value(profile.clone())
        .map_err(|error| AppleReleaseRefusal::malformed(scrub_serde_error(&error)))?;
    debug_assert_eq!(request.target, target);
    request.validate_shape()?;
    request.validate_pin(envelope)?;
    request.validate_capability(offered_capabilities)?;
    Ok(request)
}

impl AppleReleaseRequest {
    fn validate_shape(&self) -> Result<(), AppleReleaseRefusal> {
        if self.schema_version != APPLE_RELEASE_SCHEMA_VERSION {
            return Err(AppleReleaseRefusal::malformed("schema_version must be 1"));
        }
        if !is_marketing_version(&self.version) {
            return Err(AppleReleaseRefusal::malformed("version must be X.Y.Z"));
        }
        if let Some(build_number) = &self.build_number {
            if !is_build_number(build_number) {
                return Err(AppleReleaseRefusal::malformed(
                    "build_number must be a positive decimal of at most ten digits",
                ));
            }
        }
        if self.bundle_identifiers.is_empty()
            || self.bundle_identifiers.len() > MAX_BUNDLE_IDENTIFIERS
            || !all_unique(&self.bundle_identifiers)
        {
            return Err(AppleReleaseRefusal::malformed(
                "bundle_identifiers must be one to eight unique entries",
            ));
        }
        if !self
            .bundle_identifiers
            .iter()
            .all(|id| is_bundle_identifier(id))
        {
            return Err(AppleReleaseRefusal::malformed(
                "bundle_identifiers entries must be reverse-DNS identifiers",
            ));
        }
        if !is_team_id(&self.team_id) {
            return Err(AppleReleaseRefusal::malformed(
                "team_id must be ten uppercase alphanumerics",
            ));
        }
        if !is_credential_ref(&self.signing_identity_ref) {
            return Err(AppleReleaseRefusal::malformed(
                "signing_identity_ref must be a keyholder entry name",
            ));
        }
        if let Some(fingerprint) = &self.signing_certificate_sha256 {
            if !is_lower_hex(fingerprint, 64) || fingerprint.bytes().all(|b| b == b'0') {
                return Err(AppleReleaseRefusal::malformed(
                    "signing_certificate_sha256 must be a non-zero lowercase SHA-256",
                ));
            }
        }
        if self.architectures.is_empty()
            || self.architectures.len() > 2
            || !all_unique(&self.architectures)
        {
            return Err(AppleReleaseRefusal::malformed(
                "architectures must be one or two unique entries",
            ));
        }
        if !is_lower_hex(&self.approval_event_id, 64) {
            return Err(AppleReleaseRefusal::malformed(
                "approval_event_id must be a lowercase 64-hex event ID",
            ));
        }
        if self.artifact_retention_days == 0 || self.artifact_retention_days > MAX_RETENTION_DAYS {
            return Err(AppleReleaseRefusal::malformed(
                "artifact_retention_days must be between 1 and 90",
            ));
        }
        match self.target {
            AppleReleaseTarget::MacosNotarized => {
                if self.testflight.is_some() {
                    return Err(AppleReleaseRefusal::malformed(
                        "testflight is not allowed for macos-notarized",
                    ));
                }
                let notarization = self.notarization.as_ref().ok_or_else(|| {
                    AppleReleaseRefusal::malformed("notarization is required for macos-notarized")
                })?;
                notarization.validate_shape()
            }
            AppleReleaseTarget::IosTestflight => {
                if self.notarization.is_some() {
                    return Err(AppleReleaseRefusal::malformed(
                        "notarization is not allowed for ios-testflight",
                    ));
                }
                if self.build_number.is_none() {
                    return Err(AppleReleaseRefusal::malformed(
                        "build_number is required for ios-testflight",
                    ));
                }
                if self.architectures != [AppleArchitecture::Arm64] {
                    return Err(AppleReleaseRefusal::malformed(
                        "architectures must be exactly [\"arm64\"] for ios-testflight",
                    ));
                }
                let testflight = self.testflight.as_ref().ok_or_else(|| {
                    AppleReleaseRefusal::malformed("testflight is required for ios-testflight")
                })?;
                testflight.validate_shape()
            }
        }
    }

    fn validate_pin(&self, envelope: &CiRequestEnvelope) -> Result<(), AppleReleaseRefusal> {
        if !is_lower_hex(&self.source_commit, 40) {
            return Err(AppleReleaseRefusal::new(
                AppleReleaseRefusalReason::UnpinnedCommit,
                "source_commit must be a full lowercase 40-hex commit",
            ));
        }
        if self.source_commit != envelope.tip_oid {
            return Err(AppleReleaseRefusal::new(
                AppleReleaseRefusalReason::UnpinnedCommit,
                "source_commit must equal the request tip_oid",
            ));
        }
        if let Some(controller_commit) = &self.controller_commit {
            if !is_lower_hex(controller_commit, 40) {
                return Err(AppleReleaseRefusal::new(
                    AppleReleaseRefusalReason::UnpinnedCommit,
                    "controller_commit must be a full lowercase 40-hex commit",
                ));
            }
        }
        Ok(())
    }

    fn validate_capability(
        &self,
        offered_capabilities: &HashSet<String>,
    ) -> Result<(), AppleReleaseRefusal> {
        if self.executor_class != APPLE_EXECUTOR_CLASS {
            return Err(AppleReleaseRefusal::new(
                AppleReleaseRefusalReason::MissingCapability,
                "executor_class is not a registered Apple executor class",
            ));
        }
        let missing: Vec<&str> = self
            .target
            .required_capabilities()
            .iter()
            .copied()
            .filter(|capability| !offered_capabilities.contains(*capability))
            .collect();
        if !missing.is_empty() {
            return Err(AppleReleaseRefusal::new(
                AppleReleaseRefusalReason::MissingCapability,
                format!(
                    "no advertised executor offers {} for {}",
                    missing.join(", "),
                    self.target.as_str()
                ),
            ));
        }
        Ok(())
    }
}

impl AppleNotarization {
    fn validate_shape(&self) -> Result<(), AppleReleaseRefusal> {
        if !is_credential_ref(&self.credential_ref) {
            return Err(AppleReleaseRefusal::malformed(
                "notarization.credential_ref must be a keyholder entry name",
            ));
        }
        if !is_wait_seconds(self.wait_timeout_seconds) {
            return Err(AppleReleaseRefusal::malformed(
                "notarization.wait_timeout_seconds must be between 60 and 7200",
            ));
        }
        Ok(())
    }
}

impl AppleTestflight {
    fn validate_shape(&self) -> Result<(), AppleReleaseRefusal> {
        if !is_asc_app_id(&self.asc_app_id) {
            return Err(AppleReleaseRefusal::malformed(
                "testflight.asc_app_id must be a positive decimal of at most twenty digits",
            ));
        }
        if !is_credential_ref(&self.credential_ref) {
            return Err(AppleReleaseRefusal::malformed(
                "testflight.credential_ref must be a keyholder entry name",
            ));
        }
        if self.beta_group_refs.len() > MAX_BETA_GROUP_REFS
            || !all_unique(&self.beta_group_refs)
            || !self
                .beta_group_refs
                .iter()
                .all(|name| is_credential_ref(name))
        {
            return Err(AppleReleaseRefusal::malformed(
                "testflight.beta_group_refs must be at most sixteen unique group names",
            ));
        }
        if let Some(notes) = &self.what_to_test {
            let chars = notes.chars().count();
            if chars == 0 || chars > MAX_WHAT_TO_TEST_CHARS {
                return Err(AppleReleaseRefusal::malformed(
                    "testflight.what_to_test must be 1 to 4000 characters",
                ));
            }
        }
        if !is_wait_seconds(self.wait_for_processing_seconds) {
            return Err(AppleReleaseRefusal::malformed(
                "testflight.wait_for_processing_seconds must be between 60 and 7200",
            ));
        }
        Ok(())
    }
}

/// Walk the raw profile and refuse anything that looks like credential
/// material: a key naming a secret, a PEM or `AuthKey_` marker, or a single
/// opaque token of eighty or more characters. The detail names the JSON path
/// only.
fn scan_for_secret_material(value: &Value, path: &str) -> Result<(), AppleReleaseRefusal> {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if key_names_secret(key) {
                    return Err(AppleReleaseRefusal::new(
                        AppleReleaseRefusalReason::SecretMaterial,
                        format!("{path}.{key} names credential material"),
                    ));
                }
                scan_for_secret_material(child, &format!("{path}.{key}"))?;
            }
            Ok(())
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                scan_for_secret_material(child, &format!("{path}[{index}]"))?;
            }
            Ok(())
        }
        Value::String(text) => {
            if value_looks_secret(text) {
                return Err(AppleReleaseRefusal::new(
                    AppleReleaseRefusalReason::SecretMaterial,
                    format!("{path} carries credential material"),
                ));
            }
            Ok(())
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(()),
    }
}

fn key_names_secret(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase().replace('-', "_");
    SECRET_KEY_FRAGMENTS
        .iter()
        .any(|fragment| normalized.contains(fragment))
}

fn value_looks_secret(text: &str) -> bool {
    if SECRET_VALUE_MARKERS
        .iter()
        .any(|marker| text.contains(marker))
    {
        return true;
    }
    text.split_whitespace().any(|token| {
        token.len() >= OPAQUE_BLOB_MIN_LEN
            && token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'_' | b'-'))
    })
}

/// serde's message can quote an offending value; keep only the field/path
/// portion so a refusal never echoes request content.
fn scrub_serde_error(error: &serde_json::Error) -> String {
    let message = error.to_string();
    let head = message.split(" at line ").next().unwrap_or("").trim();
    if head.starts_with("unknown field") {
        "profile carries a field outside schema v1".to_owned()
    } else if let Some(field) = head.strip_prefix("missing field ") {
        format!("missing field {}", field.trim_matches('`'))
    } else if head.starts_with("unknown variant") {
        "profile carries a value outside a closed set".to_owned()
    } else if head.starts_with("invalid type") || head.starts_with("invalid value") {
        "profile field has the wrong type or value".to_owned()
    } else {
        "profile does not match schema v1".to_owned()
    }
}

fn all_unique<T: Eq + std::hash::Hash>(items: &[T]) -> bool {
    let mut seen = HashSet::with_capacity(items.len());
    items.iter().all(|item| seen.insert(item))
}

fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn is_decimal_no_leading_zero(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value.bytes().all(|b| b.is_ascii_digit())
        && !value.starts_with('0')
}

fn is_marketing_version(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.bytes().all(|b| b.is_ascii_digit())
                && (*part == "0" || !part.starts_with('0'))
        })
}

fn is_build_number(value: &str) -> bool {
    is_decimal_no_leading_zero(value, 10)
}

fn is_asc_app_id(value: &str) -> bool {
    is_decimal_no_leading_zero(value, 20)
}

fn is_bundle_identifier(value: &str) -> bool {
    if value.len() > MAX_BUNDLE_IDENTIFIER_LEN {
        return false;
    }
    let labels: Vec<&str> = value.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

fn is_team_id(value: &str) -> bool {
    value.len() == 10
        && value
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

/// Keyholder entry name: `^[a-z0-9][a-z0-9-]{0,63}$`.
pub fn is_credential_ref(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

fn is_wait_seconds(value: u64) -> bool {
    (MIN_WAIT_SECONDS..=MAX_WAIT_SECONDS).contains(&value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use buzz_core::ci::{CiRequestType, CI_SCHEMA_VERSION};

    const ACCEPTED_MACOS: &str = include_str!(
        "../../../../../deploy/native-ci/apple-release/fixtures/accepted-macos-notarized.json"
    );
    const ACCEPTED_IOS: &str = include_str!(
        "../../../../../deploy/native-ci/apple-release/fixtures/accepted-ios-testflight.json"
    );
    const REFUSED_UNKNOWN_TARGET: &str = include_str!(
        "../../../../../deploy/native-ci/apple-release/fixtures/refused-unknown-target.json"
    );
    const REFUSED_UNPINNED_COMMIT: &str = include_str!(
        "../../../../../deploy/native-ci/apple-release/fixtures/refused-unpinned-commit.json"
    );
    const REFUSED_SECRET_MATERIAL: &str = include_str!(
        "../../../../../deploy/native-ci/apple-release/fixtures/refused-secret-material.json"
    );
    const REFUSED_MALFORMED_PROFILE: &str = include_str!(
        "../../../../../deploy/native-ci/apple-release/fixtures/refused-malformed-profile.json"
    );

    fn profile(fixture: &str) -> Value {
        serde_json::from_str(fixture).expect("fixture parses")
    }

    fn envelope_for(profile: &Value) -> CiRequestEnvelope {
        let tip = profile["source_commit"]
            .as_str()
            .filter(|commit| is_lower_hex(commit, 40))
            .unwrap_or("d9abae67a7d9dfab3d693e968477561456694898")
            .to_owned();
        CiRequestEnvelope {
            schema_version: CI_SCHEMA_VERSION,
            request_type: CiRequestType::Run,
            target_repo_a: format!("30617:{}:buzz", "73".repeat(32)),
            pr_root_event_id: "11".repeat(32),
            pr_update_event_id: None,
            source_clone_url: "https://relay.example/git/owner/buzz".to_owned(),
            immutable_source_ref: format!("refs/nostr/{}", "11".repeat(32)),
            tip_oid: tip,
            source_branch: "release/apple".to_owned(),
            base_ref: "refs/heads/main".to_owned(),
            base_oid: "33".repeat(20),
            workflow_id: "apple-release".to_owned(),
            workflow_digest: "44".repeat(32),
            job_ids: vec!["apple_release".to_owned()],
            run_id: "123e4567-e89b-12d3-a456-426614174000".to_owned(),
            attempt: 1,
            parent_attempt: None,
            parent_run_id: None,
            trigger_event_id: "11".repeat(32),
            actor: "55".repeat(32),
            timeout_seconds: 3600,
            idempotency_key: "apple-release-1".to_owned(),
            issued_at: 1_700_000_000,
            expires_at: 1_700_000_600,
        }
    }

    fn all_capabilities() -> HashSet<String> {
        KNOWN_CAPABILITIES.iter().map(|c| (*c).to_owned()).collect()
    }

    fn jobs_write() -> Vec<Scope> {
        vec![Scope::JobsWrite]
    }

    fn refuse(
        profile: &Value,
        scopes: &[Scope],
        capabilities: &HashSet<String>,
    ) -> AppleReleaseRefusal {
        let envelope = envelope_for(profile);
        validate_apple_release_request(&envelope, profile, scopes, capabilities)
            .expect_err("profile must be refused")
    }

    #[test]
    fn accepts_macos_notarized_fixture() {
        let profile = profile(ACCEPTED_MACOS);
        let envelope = envelope_for(&profile);
        let request =
            validate_apple_release_request(&envelope, &profile, &jobs_write(), &all_capabilities())
                .expect("macOS fixture is admitted");
        assert_eq!(request.target, AppleReleaseTarget::MacosNotarized);
        assert_eq!(request.source_commit, envelope.tip_oid);
        assert_eq!(request.bundle_identifiers, ["xyz.block.buzz.app"]);
        assert_eq!(
            request.architectures,
            [AppleArchitecture::Arm64, AppleArchitecture::X86_64]
        );
        assert!(request.notarization.as_ref().is_some_and(|n| n.staple));
        assert!(request.testflight.is_none());
    }

    #[test]
    fn accepts_ios_testflight_fixture() {
        let profile = profile(ACCEPTED_IOS);
        let envelope = envelope_for(&profile);
        let request =
            validate_apple_release_request(&envelope, &profile, &jobs_write(), &all_capabilities())
                .expect("iOS fixture is admitted");
        assert_eq!(request.target, AppleReleaseTarget::IosTestflight);
        assert_eq!(request.build_number.as_deref(), Some("1"));
        let testflight = request.testflight.expect("testflight block");
        assert_eq!(testflight.asc_app_id, "6809565361");
        assert_eq!(testflight.beta_group_refs, ["internal"]);
        assert!(request.notarization.is_none());
    }

    #[test]
    fn refuses_requester_without_jobs_write() {
        let profile = profile(ACCEPTED_MACOS);
        for scopes in [Vec::new(), vec![Scope::MessagesWrite, Scope::JobsRead]] {
            let refusal = refuse(&profile, &scopes, &all_capabilities());
            assert_eq!(
                refusal.reason,
                AppleReleaseRefusalReason::UnauthorizedRequester
            );
        }
    }

    #[test]
    fn refuses_secret_material_by_key_name() {
        let refusal = refuse(
            &profile(REFUSED_SECRET_MATERIAL),
            &jobs_write(),
            &all_capabilities(),
        );
        assert_eq!(refusal.reason, AppleReleaseRefusalReason::SecretMaterial);
        assert_eq!(
            refusal.detail,
            "apple_release.testflight.asc_private_key names credential material"
        );
        assert!(
            !refusal.detail.contains("BEGIN"),
            "detail must not echo values"
        );
    }

    #[test]
    fn refuses_secret_material_by_value_marker_and_opaque_blob() {
        let mut pem = profile(ACCEPTED_IOS);
        pem["testflight"]["what_to_test"] =
            Value::String("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----".into());
        let refusal = refuse(&pem, &jobs_write(), &all_capabilities());
        assert_eq!(refusal.reason, AppleReleaseRefusalReason::SecretMaterial);
        assert_eq!(
            refusal.detail,
            "apple_release.testflight.what_to_test carries credential material"
        );

        let mut auth_key = profile(ACCEPTED_IOS);
        auth_key["testflight"]["credential_ref"] = Value::String("AuthKey_ABC123.p8".into());
        let refusal = refuse(&auth_key, &jobs_write(), &all_capabilities());
        assert_eq!(refusal.reason, AppleReleaseRefusalReason::SecretMaterial);

        let mut blob = profile(ACCEPTED_MACOS);
        blob["notarization"]["credential_ref"] = Value::String("A".repeat(OPAQUE_BLOB_MIN_LEN));
        let refusal = refuse(&blob, &jobs_write(), &all_capabilities());
        assert_eq!(refusal.reason, AppleReleaseRefusalReason::SecretMaterial);
    }

    #[test]
    fn secret_scan_treats_hyphenated_keys_like_underscored_keys() {
        let mut hyphenated = profile(ACCEPTED_MACOS);
        hyphenated["notarization"]["app-specific-password"] = Value::String("x".into());
        let refusal = refuse(&hyphenated, &jobs_write(), &all_capabilities());
        assert_eq!(refusal.reason, AppleReleaseRefusalReason::SecretMaterial);
        assert_eq!(
            refusal.detail,
            "apple_release.notarization.app-specific-password names credential material"
        );
    }

    #[test]
    fn refuses_unknown_target() {
        let refusal = refuse(
            &profile(REFUSED_UNKNOWN_TARGET),
            &jobs_write(),
            &all_capabilities(),
        );
        assert_eq!(refusal.reason, AppleReleaseRefusalReason::UnknownTarget);
        assert!(
            !refusal.detail.contains("watchos"),
            "detail must not echo values"
        );

        let mut missing = profile(ACCEPTED_MACOS);
        missing.as_object_mut().unwrap().remove("target");
        let refusal = refuse(&missing, &jobs_write(), &all_capabilities());
        assert_eq!(refusal.reason, AppleReleaseRefusalReason::MalformedProfile);
        assert_eq!(refusal.detail, "target is required");
    }

    #[test]
    fn refuses_malformed_profile() {
        let refusal = refuse(
            &profile(REFUSED_MALFORMED_PROFILE),
            &jobs_write(),
            &all_capabilities(),
        );
        assert_eq!(refusal.reason, AppleReleaseRefusalReason::MalformedProfile);
        assert_eq!(
            refusal.detail,
            "testflight is not allowed for macos-notarized"
        );

        let cases: Vec<(Value, &str)> = vec![
            (
                {
                    let mut v = profile(ACCEPTED_MACOS);
                    v["extra"] = Value::Bool(true);
                    v
                },
                "profile carries a field outside schema v1",
            ),
            (
                {
                    let mut v = profile(ACCEPTED_MACOS);
                    v["schema_version"] = Value::from(2);
                    v
                },
                "schema_version must be 1",
            ),
            (
                {
                    let mut v = profile(ACCEPTED_MACOS);
                    v["version"] = Value::String("0.5".into());
                    v
                },
                "version must be X.Y.Z",
            ),
            (
                {
                    let mut v = profile(ACCEPTED_MACOS);
                    v["team_id"] = Value::String("lowercase1".into());
                    v
                },
                "team_id must be ten uppercase alphanumerics",
            ),
            (
                {
                    let mut v = profile(ACCEPTED_MACOS);
                    v["signing_identity_ref"] = Value::String("Developer ID Application".into());
                    v
                },
                "signing_identity_ref must be a keyholder entry name",
            ),
            (
                {
                    let mut v = profile(ACCEPTED_MACOS);
                    v["bundle_identifiers"] = serde_json::json!(["buzz"]);
                    v
                },
                "bundle_identifiers entries must be reverse-DNS identifiers",
            ),
            (
                {
                    let mut v = profile(ACCEPTED_MACOS);
                    v["artifact_retention_days"] = Value::from(365);
                    v
                },
                "artifact_retention_days must be between 1 and 90",
            ),
            (
                {
                    let mut v = profile(ACCEPTED_MACOS);
                    v["notarization"]["wait_timeout_seconds"] = Value::from(5);
                    v
                },
                "notarization.wait_timeout_seconds must be between 60 and 7200",
            ),
            (
                {
                    let mut v = profile(ACCEPTED_IOS);
                    v["architectures"] = serde_json::json!(["arm64", "x86_64"]);
                    v
                },
                "architectures must be exactly [\"arm64\"] for ios-testflight",
            ),
            (
                {
                    let mut v = profile(ACCEPTED_IOS);
                    v.as_object_mut().unwrap().remove("build_number");
                    v
                },
                "build_number is required for ios-testflight",
            ),
            (
                {
                    let mut v = profile(ACCEPTED_IOS);
                    v["testflight"]["asc_app_id"] = Value::String("0123".into());
                    v
                },
                "testflight.asc_app_id must be a positive decimal of at most twenty digits",
            ),
            (
                {
                    let mut v = profile(ACCEPTED_IOS);
                    v["testflight"]["what_to_test"] = Value::String("x ".repeat(2001));
                    v
                },
                "testflight.what_to_test must be 1 to 4000 characters",
            ),
            (
                {
                    let mut v = profile(ACCEPTED_IOS);
                    v["testflight"]["beta_group_refs"] =
                        serde_json::json!(["internal", "internal"]);
                    v
                },
                "testflight.beta_group_refs must be at most sixteen unique group names",
            ),
        ];
        for (candidate, expected) in cases {
            let refusal = refuse(&candidate, &jobs_write(), &all_capabilities());
            assert_eq!(
                refusal.reason,
                AppleReleaseRefusalReason::MalformedProfile,
                "{expected}"
            );
            assert_eq!(refusal.detail, expected);
        }
    }

    #[test]
    fn refuses_unpinned_commit() {
        let refusal = refuse(
            &profile(REFUSED_UNPINNED_COMMIT),
            &jobs_write(),
            &all_capabilities(),
        );
        assert_eq!(refusal.reason, AppleReleaseRefusalReason::UnpinnedCommit);
        assert_eq!(
            refusal.detail,
            "source_commit must be a full lowercase 40-hex commit"
        );

        let profile_value = profile(ACCEPTED_MACOS);
        let mut envelope = envelope_for(&profile_value);
        envelope.tip_oid = "ab".repeat(20);
        let refusal = validate_apple_release_request(
            &envelope,
            &profile_value,
            &jobs_write(),
            &all_capabilities(),
        )
        .expect_err("tip drift is refused");
        assert_eq!(refusal.reason, AppleReleaseRefusalReason::UnpinnedCommit);
        assert_eq!(
            refusal.detail,
            "source_commit must equal the request tip_oid"
        );

        let mut uppercase = profile(ACCEPTED_MACOS);
        uppercase["source_commit"] =
            Value::String("D9ABAE67A7D9DFAB3D693E968477561456694898".into());
        let refusal = refuse(&uppercase, &jobs_write(), &all_capabilities());
        assert_eq!(refusal.reason, AppleReleaseRefusalReason::UnpinnedCommit);

        let mut controller = profile(ACCEPTED_MACOS);
        controller["controller_commit"] = Value::String("3db2d0f".into());
        let refusal = refuse(&controller, &jobs_write(), &all_capabilities());
        assert_eq!(refusal.reason, AppleReleaseRefusalReason::UnpinnedCommit);
        assert_eq!(
            refusal.detail,
            "controller_commit must be a full lowercase 40-hex commit"
        );
    }

    #[test]
    fn refuses_missing_capability() {
        let macos = profile(ACCEPTED_MACOS);
        let refusal = refuse(&macos, &jobs_write(), &HashSet::new());
        assert_eq!(refusal.reason, AppleReleaseRefusalReason::MissingCapability);
        assert_eq!(
            refusal.detail,
            "no advertised executor offers apple-build, apple-codesign, apple-notarize for macos-notarized"
        );

        let mut without_notarize = all_capabilities();
        without_notarize.remove(CAPABILITY_NOTARIZE);
        let refusal = refuse(&macos, &jobs_write(), &without_notarize);
        assert_eq!(refusal.reason, AppleReleaseRefusalReason::MissingCapability);
        assert_eq!(
            refusal.detail,
            "no advertised executor offers apple-notarize for macos-notarized"
        );

        let ios = profile(ACCEPTED_IOS);
        let mut without_upload = all_capabilities();
        without_upload.remove(CAPABILITY_TESTFLIGHT_UPLOAD);
        let refusal = refuse(&ios, &jobs_write(), &without_upload);
        assert_eq!(refusal.reason, AppleReleaseRefusalReason::MissingCapability);
        assert_eq!(
            refusal.detail,
            "no advertised executor offers apple-testflight-upload for ios-testflight"
        );

        let mut other_class = profile(ACCEPTED_MACOS);
        other_class["executor_class"] = Value::String("linux-x86".into());
        let refusal = refuse(&other_class, &jobs_write(), &all_capabilities());
        assert_eq!(refusal.reason, AppleReleaseRefusalReason::MissingCapability);
        assert_eq!(
            refusal.detail,
            "executor_class is not a registered Apple executor class"
        );
    }

    #[test]
    fn refusal_order_is_scope_then_secret_then_target_then_shape() {
        let mut everything_wrong = profile(REFUSED_SECRET_MATERIAL);
        everything_wrong["target"] = Value::String("tvos".into());
        everything_wrong["source_commit"] = Value::String("HEAD".into());

        let refusal = refuse(&everything_wrong, &[], &HashSet::new());
        assert_eq!(
            refusal.reason,
            AppleReleaseRefusalReason::UnauthorizedRequester
        );
        let refusal = refuse(&everything_wrong, &jobs_write(), &HashSet::new());
        assert_eq!(refusal.reason, AppleReleaseRefusalReason::SecretMaterial);

        everything_wrong["testflight"]
            .as_object_mut()
            .unwrap()
            .remove("asc_private_key");
        let refusal = refuse(&everything_wrong, &jobs_write(), &HashSet::new());
        assert_eq!(refusal.reason, AppleReleaseRefusalReason::UnknownTarget);

        everything_wrong["target"] = Value::String("ios-testflight".into());
        let refusal = refuse(&everything_wrong, &jobs_write(), &HashSet::new());
        assert_eq!(refusal.reason, AppleReleaseRefusalReason::UnpinnedCommit);

        everything_wrong["source_commit"] =
            Value::String("038e8ae4f33387f2b5a299c1af54b1a4404c5f94".into());
        let refusal = refuse(&everything_wrong, &jobs_write(), &HashSet::new());
        assert_eq!(refusal.reason, AppleReleaseRefusalReason::MissingCapability);
    }

    #[test]
    fn profile_key_detection_and_display_shape() {
        let content =
            serde_json::json!({"tip_oid": "x", "apple_release": {"target": "ios-testflight"}});
        assert!(apple_release_profile(&content).is_some());
        assert!(apple_release_profile(&serde_json::json!({"tip_oid": "x"})).is_none());

        let refusal = AppleReleaseRefusal::new(
            AppleReleaseRefusalReason::UnknownTarget,
            "target is not macos-notarized or ios-testflight",
        );
        assert_eq!(
            refusal.to_string(),
            "apple release request refused (unknown_target): target is not macos-notarized or ios-testflight"
        );
        for reason in [
            AppleReleaseRefusalReason::UnauthorizedRequester,
            AppleReleaseRefusalReason::SecretMaterial,
            AppleReleaseRefusalReason::UnknownTarget,
            AppleReleaseRefusalReason::MalformedProfile,
            AppleReleaseRefusalReason::UnpinnedCommit,
            AppleReleaseRefusalReason::MissingCapability,
        ] {
            let wire = serde_json::to_value(reason).expect("serialize reason");
            assert_eq!(wire, Value::String(reason.as_str().to_owned()));
        }
    }

    #[test]
    fn required_capabilities_are_within_the_known_set() {
        for target in [
            AppleReleaseTarget::MacosNotarized,
            AppleReleaseTarget::IosTestflight,
        ] {
            for capability in target.required_capabilities() {
                assert!(KNOWN_CAPABILITIES.contains(capability));
            }
            assert_eq!(AppleReleaseTarget::parse(target.as_str()), Some(target));
        }
        assert_eq!(AppleReleaseTarget::parse("macos"), None);
    }
}
