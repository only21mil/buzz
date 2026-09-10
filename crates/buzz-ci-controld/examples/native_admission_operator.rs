//! Explicit operator admission through the existing authenticated keyholder.
//! No credential loading, relay publication, or runner execution occurs here.
#![forbid(unsafe_code)]

use buzz_ci_broker_protocol::v2;
use buzz_ci_controld::{
    keyholder::{KeyholderClientConfig, UnixKeyholderClient},
    production::AcceptedRequest,
    runner_v2::{
        prepare_job_intent_registration, prepare_signed_admission, StaticAdmissionBindings,
        StaticArtifactBinding,
    },
};
use buzz_ci_execd::production_binding::{
    LaneActivationManifestV1, LANE_ACTIVATION_MANIFEST_SCHEMA_V1,
};
use buzz_core::ci::{validate_signed_ci_event, CiRequestType, ValidatedCiEnvelope};
use nostr::Event;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Lane {
    lane_id: String,
    lane_epoch: u64,
    broker_build_identity: String,
    host_profile_digest: String,
    suite_identity: String,
    isolation_profile_digest: String,
    not_before: u64,
    expires_at: u64,
    max_wall_timeout_seconds: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Authority {
    schema_version: u32,
    actor_pubkey: String,
    channel_id: String,
    target_repo_a: String,
    source_clone_url: String,
    // First-PR qualification only. An update requires a separately reviewed adapter.
    source_pin_event_id: String,
    candidate_oid: String,
    trusted_base_oid: String,
    workflow_digest: String,
    #[serde(default)]
    driver_file_sha256: Option<String>,
    workflow_id: String,
    job_id: String,
    audience_digest: String,
    lane: Lane,
    keyholder: KeyholderClientConfig,
}

fn hash(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid public digest".into());
    }
    let mut out = [0; 32];
    hex::decode_to_slice(value, &mut out)?;
    if out == [0; 32] {
        return Err("zero public digest".into());
    }
    Ok(out)
}

fn read(path: &Path) -> Result<Vec<u8>> {
    let file = fs::File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err("regular input file required".into());
    }
    let mut bytes = Vec::new();
    file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 1024 * 1024 {
        return Err("input exceeds limit".into());
    }
    Ok(bytes)
}

fn load_authority(path: &Path, expected: &str, signing: bool) -> Result<Authority> {
    let bytes = read(path)?;
    if <[u8; 32]>::from(Sha256::digest(&bytes)) != hash(expected)? {
        return Err("authority differs from reviewed SHA256".into());
    }
    if signing {
        if !path.is_absolute() || fs::canonicalize(path)? != path {
            return Err("canonical authority path required".into());
        }
        let meta = fs::symlink_metadata(path)?;
        if meta.uid() != 0 || meta.gid() != 0 || meta.mode() & 0o777 != 0o444 || meta.nlink() != 1 {
            return Err("authority must be root:root 0444 with one link".into());
        }
        for parent in path.ancestors().skip(1) {
            let meta = fs::symlink_metadata(parent)?;
            if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
                return Err(
                    "authority ancestors must be root-owned and not writable by others".into(),
                );
            }
        }
    }
    let authority: Authority = serde_json::from_slice(&bytes)?;
    authority.validate()?;
    Ok(authority)
}

impl Authority {
    fn lane_manifest(&self) -> Result<LaneActivationManifestV1> {
        Ok(LaneActivationManifestV1 {
            schema_version: LANE_ACTIVATION_MANIFEST_SCHEMA_V1,
            lane_id: hash(&self.lane.lane_id)?,
            lane_epoch: self.lane.lane_epoch,
            admission_signature_algorithm: v2::AdmissionSignatureAlgorithm::Bip340Secp256k1Sha256,
            admission_verifying_key: hash(&self.keyholder.keyholder_selectors.manifest.public_key)?,
            admission_key_generation: self.keyholder.keyholder_selectors.manifest.generation,
            broker_build_identity: hash(&self.lane.broker_build_identity)?,
            host_profile_digest: hash(&self.lane.host_profile_digest)?,
            suite_identity: hash(&self.lane.suite_identity)?,
            isolation_profile_digest: hash(&self.lane.isolation_profile_digest)?,
            not_before: self.lane.not_before,
            expires_at: self.lane.expires_at,
            max_wall_timeout_seconds: self.lane.max_wall_timeout_seconds,
        })
    }

    fn validate(&self) -> Result<()> {
        self.keyholder.validate()?;
        self.lane_manifest()?;
        hash(&self.actor_pubkey)?;
        hash(&self.source_pin_event_id)?;
        hash(&self.audience_digest)?;
        hash(&self.workflow_digest)?;
        match (self.workflow_id.as_str(), &self.driver_file_sha256) {
            ("native-macos", Some(driver)) => {
                hash(driver)?;
            }
            ("CI", None) => {}
            _ => return Err("driver binding differs from workflow".into()),
        }
        let oid_valid = |s: &str| {
            s.len() == 40
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        if self.schema_version != 1
            || !matches!(
                (self.workflow_id.as_str(), self.job_id.as_str()),
                ("CI", "dead-token-guard") | ("native-macos", "desktop-build-macos-unsigned")
            )
            || self.lane.lane_epoch == 0
            || self.lane.not_before == 0
            || self.lane.expires_at <= self.lane.not_before
            || self.lane.max_wall_timeout_seconds == 0
            || self.lane.max_wall_timeout_seconds
                != if self.workflow_id == "CI" { 300 } else { 2700 }
            || self.lane.suite_identity != self.workflow_digest
            || !oid_valid(&self.candidate_oid)
            || !oid_valid(&self.trusted_base_oid)
            || self.keyholder.keyholder_transport_attempts != 1
        {
            return Err("authority outside native qualification contract".into());
        }
        Ok(())
    }

    fn bindings(&self) -> Result<StaticAdmissionBindings> {
        Ok(StaticAdmissionBindings {
            audience_digest: hash(&self.audience_digest)?,
            isolation_profile_digest: hash(&self.lane.isolation_profile_digest)?,
            lane_manifest_digest: self.lane_manifest()?.digest(),
            lane_epoch: self.lane.lane_epoch,
            admission_key_generation: self.keyholder.keyholder_selectors.manifest.generation,
            workflow_id: self.workflow_id.clone(),
            workflow_digest: hash(&self.workflow_digest)?,
            job_ids: vec![self.job_id.clone()],
            artifacts: vec![StaticArtifactBinding {
                artifact_id: "result".into(),
                name: "result.json".into(),
                media_type: "application/json".into(),
                relative_name: "result.json".into(),
                max_bytes: 32768,
            }],
        })
    }

    fn policy(&self) -> Result<Value> {
        Ok(json!({
            "admission_pubkey": self.keyholder.keyholder_selectors.manifest.public_key,
            "actor_pubkey": self.actor_pubkey, "audience_digest": self.audience_digest,
            "lane_manifest_digest": hex::encode(self.lane_manifest()?.digest()),
            "lane_epoch": self.lane.lane_epoch,
            "not_before": self.lane.not_before, "expires_at": self.lane.expires_at,
            "max_wall_timeout_seconds": self.lane.max_wall_timeout_seconds,
            "driver_file_sha256": self.driver_file_sha256,
            "admission_key_generation": self.keyholder.keyholder_selectors.manifest.generation,
            "workflow_digest": self.workflow_digest, "workflow_id": self.workflow_id,
            "job_id": self.job_id, "isolation_profile_digest": self.lane.isolation_profile_digest,
            "workflow_path": if self.workflow_id == "CI" { ".github/workflows/ci.yml" } else { ".buzz/workflows/native-macos.yml" },
            "trusted_base_oid": self.trusted_base_oid, "workflow_file_sha256": self.workflow_digest,
            "artifacts": [{"artifact_id":"result","name":"result.json","media_type":"application/json","relative_name":"result.json","max_bytes":32768}]
        }))
    }
}

fn unique_tag<'a>(event: &'a Event, name: &str) -> Result<&'a str> {
    let mut values = event
        .tags
        .iter()
        .filter(|tag| tag.as_slice().first().map(String::as_str) == Some(name));
    let value = values
        .next()
        .and_then(|tag| tag.as_slice().get(1))
        .ok_or("source tag missing")?;
    if values.next().is_some() {
        return Err("source tag ambiguous".into());
    }
    Ok(value)
}

fn validate_inputs(
    authority: &Authority,
    event: &Event,
    source: &Event,
    now: u64,
) -> Result<AcceptedRequest> {
    let ValidatedCiEnvelope::Request(envelope) =
        validate_signed_ci_event(event, &authority.channel_id, &HashSet::new())?
    else {
        return Err("signed CI request required".into());
    };
    source.verify()?;
    if source.kind.as_u16() != 1618
        || source.pubkey.to_hex() != authority.actor_pubkey
        || source.id.to_hex() != authority.source_pin_event_id
        || unique_tag(source, "c")? != authority.candidate_oid
        || unique_tag(source, "a")? != authority.target_repo_a
        || unique_tag(source, "clone")? != authority.source_clone_url
        || envelope.pr_update_event_id.is_some()
        || envelope.pr_root_event_id != authority.source_pin_event_id
        || envelope.trigger_event_id != authority.source_pin_event_id
        || envelope.actor != authority.actor_pubkey
        || envelope.target_repo_a != authority.target_repo_a
        || envelope.source_clone_url != authority.source_clone_url
        || envelope.source_branch != unique_tag(source, "branch-name")?
        || envelope.immutable_source_ref != format!("refs/nostr/{}", authority.source_pin_event_id)
        || envelope.base_ref != "refs/heads/main"
        || envelope.base_oid != authority.trusted_base_oid
        || envelope.tip_oid != authority.candidate_oid
        || envelope.workflow_id != authority.workflow_id
        || envelope.workflow_digest != authority.workflow_digest
        || envelope.job_ids != [authority.job_id.clone()]
        || envelope.request_type != CiRequestType::Run
        || envelope.issued_at > now
        || envelope.expires_at <= now
        || envelope.expires_at - envelope.issued_at > 2700
        || event.created_at.as_secs() != envelope.issued_at
        || envelope.timeout_seconds > u64::from(authority.lane.max_wall_timeout_seconds)
        || now < authority.lane.not_before
        || now >= authority.lane.expires_at
        || envelope.expires_at > authority.lane.expires_at
    {
        return Err("request or canonical source pin differs from reviewed authority".into());
    }
    Ok(AcceptedRequest {
        channel_id: authority.channel_id.clone(),
        watch_cursor: 0,
        event_id: event.id.to_hex(),
        envelope,
    })
}

fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() < 4 || !matches!(args[1].as_str(), "policy" | "check" | "sign") {
        return Err("usage: native_admission_operator policy|check|sign AUTHORITY REVIEWED_SHA256 [SIGNED_REQUEST SOURCE_PIN]".into());
    }
    let signing = args[1] == "sign";
    let authority = load_authority(Path::new(&args[2]), &args[3], signing)?;
    if args[1] == "policy" && args.len() == 4 {
        println!("{}", serde_json::to_string(&authority.policy()?)?);
        return Ok(());
    }
    if args.len() != 6 || args[1] == "policy" {
        return Err("request and source pin paths required".into());
    }
    let event: Event = serde_json::from_slice(&read(Path::new(&args[4]))?)?;
    let source: Event = serde_json::from_slice(&read(Path::new(&args[5]))?)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let accepted = validate_inputs(&authority, &event, &source, now)?;
    if !signing {
        println!(
            "{}",
            json!({"validated":true,"signed_request_digest":event.id.to_hex(),"source_pin_event_id":source.id.to_hex(),"candidate_oid":authority.candidate_oid})
        );
        return Ok(());
    }
    let mut signer = UnixKeyholderClient::connect(authority.keyholder.clone())?;
    let bindings = authority.bindings()?;
    let admission = prepare_signed_admission(&accepted, &bindings, &mut signer)?;
    let (header, registration) = prepare_job_intent_registration(admission, &accepted, &bindings)?;
    let frame = v2::encode_request(
        header.request_id,
        v2::Request::RegisterJobIntent(registration),
    );
    std::io::stdout().lock().write_all(frame.as_bytes())?;
    Ok(())
}

fn main() {
    if run().is_err() {
        // Inputs and credentials are never included in error diagnostics.
        eprintln!("native admission operator refused; check reviewed public inputs and keyholder availability");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use buzz_core::ci::{request_tags, CiRequestEnvelope, CI_SCHEMA_VERSION};
    use nostr::{EventBuilder, Keys, Kind, Tag, Timestamp};

    fn fixture() -> (Authority, Keys, Event, CiRequestEnvelope) {
        // Only deterministic offline test keys. No fixture output is operational evidence.
        let keys = Keys::parse(&"01".repeat(32)).unwrap();
        let actor = keys.public_key().to_hex();
        let repo = format!("30617:{actor}:buzz");
        let source = EventBuilder::new(Kind::Custom(1618), "qualification")
            .tags([
                Tag::parse(["a", &repo]).unwrap(),
                Tag::parse(["c", &"aa".repeat(20)]).unwrap(),
                Tag::parse(["clone", "https://github.com/only21mil/buzz.git"]).unwrap(),
                Tag::parse(["branch-name", "qualification"]).unwrap(),
            ])
            .custom_created_at(Timestamp::from(90))
            .sign_with_keys(&keys)
            .unwrap();
        let selector = |byte: &str| json!({"public_key":Keys::parse(&byte.repeat(32)).unwrap().public_key().to_hex(),"generation":1});
        let authority: Authority = serde_json::from_value(json!({
            "schema_version":1,"actor_pubkey":actor,"channel_id":"12345678-1234-4234-8234-123456789aaa",
            "target_repo_a":repo,"source_clone_url":"https://github.com/only21mil/buzz.git",
            "source_pin_event_id":source.id.to_hex(),"candidate_oid":"aa".repeat(20),
            "trusted_base_oid":"bb".repeat(20),"workflow_digest":"cc".repeat(32),
            "workflow_id":"CI","job_id":"dead-token-guard","audience_digest":"dd".repeat(32),
            "lane":{"lane_id":"01".repeat(32),"lane_epoch":1,"broker_build_identity":"02".repeat(32),
                "host_profile_digest":"03".repeat(32),"suite_identity":"cc".repeat(32),
                "isolation_profile_digest":"05".repeat(32),"not_before":1,"expires_at":1000,"max_wall_timeout_seconds":300},
            "keyholder":{"keyholder_socket":"/run/buzzci/keyholder.sock","keyholder_uid":1202,"keyholder_gid":1202,
                "keyholder_selectors":{"ci_event":selector("02"),"nip98":selector("03"),"manifest":selector("04")},
                "keyholder_timeout_millis":5000,"keyholder_transport_attempts":1}
        })).unwrap();
        let envelope = CiRequestEnvelope {
            schema_version: CI_SCHEMA_VERSION,
            request_type: CiRequestType::Run,
            target_repo_a: authority.target_repo_a.clone(),
            pr_root_event_id: source.id.to_hex(),
            pr_update_event_id: None,
            source_clone_url: authority.source_clone_url.clone(),
            immutable_source_ref: format!("refs/nostr/{}", source.id),
            tip_oid: authority.candidate_oid.clone(),
            source_branch: "qualification".into(),
            base_ref: "refs/heads/main".into(),
            base_oid: authority.trusted_base_oid.clone(),
            workflow_id: authority.workflow_id.clone(),
            workflow_digest: authority.workflow_digest.clone(),
            job_ids: vec![authority.job_id.clone()],
            run_id: "12345678-1234-4234-8234-123456789abc".into(),
            attempt: 1,
            parent_attempt: None,
            parent_run_id: None,
            trigger_event_id: source.id.to_hex(),
            actor: authority.actor_pubkey.clone(),
            timeout_seconds: 300,
            idempotency_key: "12345678-1234-4234-8234-123456789abd".into(),
            issued_at: 100,
            expires_at: 400,
        };
        (authority, keys, source, envelope)
    }

    fn sign(keys: &Keys, envelope: &CiRequestEnvelope) -> Event {
        EventBuilder::new(
            Kind::Custom(46100),
            serde_json::to_string(envelope).unwrap(),
        )
        .tags(request_tags("12345678-1234-4234-8234-123456789aaa", envelope).unwrap())
        .custom_created_at(Timestamp::from(envelope.issued_at))
        .sign_with_keys(keys)
        .unwrap()
    }

    #[test]
    fn accepts_exact_signed_request_and_source_then_reuses_canonical_registration() {
        let (authority, keys, source, envelope) = fixture();
        authority.validate().unwrap();
        let accepted = validate_inputs(&authority, &sign(&keys, &envelope), &source, 101).unwrap();
        struct TestSigner;
        impl buzz_ci_controld::runner_v2::AdmissionSigner for TestSigner {
            type Error = ();
            fn sign_admission(
                &mut self,
                request: &mut v2::AdmitAttemptRequest,
            ) -> std::result::Result<(), ()> {
                request.admission_signature = [42; 64];
                Ok(())
            }
        }
        let bindings = authority.bindings().unwrap();
        let admission = prepare_signed_admission(&accepted, &bindings, &mut TestSigner).unwrap();
        let (header, registration) =
            prepare_job_intent_registration(admission, &accepted, &bindings).unwrap();
        let frame = v2::encode_request(
            header.request_id,
            v2::Request::RegisterJobIntent(registration),
        );
        assert_eq!(frame.as_bytes().len(), 992);
        assert_eq!(
            v2::decode_request(frame.as_bytes()).unwrap().1,
            v2::Request::RegisterJobIntent(registration)
        );
        assert_eq!(
            registration.request_event_id,
            hash(&accepted.event_id).unwrap()
        );
    }

    #[test]
    fn refuses_resigned_request_with_other_source_base_job_or_time() {
        let (authority, keys, source, envelope) = fixture();
        for change in 0..6 {
            let mut changed = envelope.clone();
            match change {
                0 => changed.tip_oid = "99".repeat(20),
                1 => changed.base_oid = "99".repeat(20),
                2 => changed.job_ids = vec!["desktop-build-macos-unsigned".into()],
                3 => changed.workflow_digest = "99".repeat(32),
                4 => changed.timeout_seconds = 301,
                _ => changed.source_clone_url = "https://example.com/untrusted.git".into(),
            }
            assert!(validate_inputs(&authority, &sign(&keys, &changed), &source, 101).is_err());
        }
        for now in [99, 400, 1000] {
            assert!(validate_inputs(&authority, &sign(&keys, &envelope), &source, now).is_err());
        }
    }

    #[test]
    fn refuses_unverifiable_event_and_wrong_pin() {
        let (mut authority, keys, source, envelope) = fixture();
        let mut bad = sign(&keys, &envelope);
        bad.content.push(' ');
        assert!(validate_inputs(&authority, &bad, &source, 101).is_err());
        authority.source_pin_event_id = "99".repeat(32);
        assert!(validate_inputs(&authority, &sign(&keys, &envelope), &source, 101).is_err());
    }

    #[test]
    fn authority_bytes_must_equal_independently_reviewed_hash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("authority.json");
        fs::write(&path, b"{}").unwrap();
        assert!(load_authority(&path, &"01".repeat(32), false).is_err());
    }
    #[test]
    fn policy_is_reusable_and_keeps_lane_window_artifact_and_workflow() {
        let (authority, _, _, _) = fixture();
        let policy = authority.policy().unwrap();
        assert!(policy.get("job_intent_digest").is_none());
        assert_eq!(policy["workflow_id"], "CI");
        assert_eq!(policy["workflow_path"], ".github/workflows/ci.yml");
        assert_eq!(policy["max_wall_timeout_seconds"], 300);
        assert_eq!(policy["not_before"], 1);
        assert_eq!(policy["expires_at"], 1000);
        assert_eq!(policy["artifacts"][0]["max_bytes"], 32768);
    }

    #[test]
    fn refuses_driver_or_lane_policy_drift() {
        let (mut authority, _, _, _) = fixture();
        authority.driver_file_sha256 = Some("11".repeat(32));
        assert!(authority.validate().is_err());
        authority.driver_file_sha256 = None;
        authority.lane.max_wall_timeout_seconds = 301;
        assert!(authority.validate().is_err());
        authority.lane.max_wall_timeout_seconds = 300;
        authority.lane.suite_identity = "11".repeat(32);
        assert!(authority.validate().is_err());
    }
}
