//! Portable verifier for the existing signed v2 admission frame.
#![forbid(unsafe_code)]

use buzz_ci_broker_protocol::{v2, GitOid, TrustClass};
use nostr::secp256k1::{schnorr::Signature, Message, Secp256k1, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::Read,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    admission_pubkey: String,
    actor_pubkey: String,
    audience_digest: String,
    lane_manifest_digest: String,
    lane_epoch: u64,
    admission_key_generation: u64,
    workflow_digest: String,
    job_intent_digest: String,
    isolation_profile_digest: String,
    trusted_base_oid: String,
    // The public workflow is a trusted-base artifact, not candidate code.
    workflow_file_sha256: String,
}

#[derive(Serialize)]
struct Verified {
    schema_version: u16,
    admission_message_digest: String,
    signed_request_digest: String,
    source_pin_event_id: String,
    candidate_sha: String,
    base_sha: String,
    workflow_digest: String,
    workflow_file_sha256: String,
    job_intent_digest: String,
    isolation_profile_digest: String,
    lane_manifest_digest: String,
    lane_epoch: u64,
    run_id: String,
    attempt: u32,
    expires_at: u64,
    wall_timeout_seconds: u32,
}

fn hash(value: &str) -> Result<[u8; 32], &'static str> {
    let mut result = [0; 32];
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err("invalid policy digest");
    }
    hex::decode_to_slice(value, &mut result).map_err(|_| "invalid policy digest")?;
    Ok(result)
}

fn oid(value: GitOid) -> Result<String, &'static str> {
    match value {
        GitOid::Sha1(bytes) => Ok(hex::encode(bytes)),
        _ => Err("SHA-1 repository required"),
    }
}

fn verify(frame: &[u8], policy: &Policy, now: u64, live: bool) -> Result<Verified, &'static str> {
    let (_, request) = v2::decode_request(frame).map_err(|_| "invalid v2 frame")?;
    let v2::Request::AdmitAttempt(value) = request else {
        return Err("admission required");
    };
    if value.actor_pubkey != hash(&policy.actor_pubkey)?
        || value.audience_digest != hash(&policy.audience_digest)?
        || value.lane_manifest_digest != hash(&policy.lane_manifest_digest)?
        || value.workflow_digest != hash(&policy.workflow_digest)?
        || value.job_intent_digest != hash(&policy.job_intent_digest)?
        || value.isolation_profile_digest != hash(&policy.isolation_profile_digest)?
        || value.lane_epoch != policy.lane_epoch
        || value.admission_key_generation != policy.admission_key_generation
        || oid(value.base_oid)? != policy.trusted_base_oid
        || value.trust_class != TrustClass::AcceptedReviewed
        || value.wall_timeout_seconds == 0
        || value.wall_timeout_seconds > 2700
        || value.issued_at > value.expires_at
        || value.expires_at.saturating_sub(value.issued_at) > 2700
        || (live && (value.issued_at > now || value.expires_at <= now))
    {
        return Err("admission outside installed policy");
    }
    hash(&policy.workflow_file_sha256)?;
    let digest: [u8; 32] = Sha256::digest(v2::admission_signature_message(&value)).into();
    let signature =
        Signature::from_slice(&value.admission_signature).map_err(|_| "invalid signature")?;
    let public = XOnlyPublicKey::from_slice(&hash(&policy.admission_pubkey)?)
        .map_err(|_| "invalid public key")?;
    Secp256k1::verification_only()
        .verify_schnorr(&signature, &Message::from_digest(digest), &public)
        .map_err(|_| "invalid admission signature")?;
    Ok(Verified {
        schema_version: 2,
        admission_message_digest: hex::encode(digest),
        signed_request_digest: hex::encode(value.signed_request_digest),
        source_pin_event_id: hex::encode(value.source_pin_event_id),
        candidate_sha: oid(value.tip_oid)?,
        base_sha: oid(value.base_oid)?,
        workflow_digest: hex::encode(value.workflow_digest),
        workflow_file_sha256: policy.workflow_file_sha256.clone(),
        job_intent_digest: hex::encode(value.job_intent_digest),
        isolation_profile_digest: hex::encode(value.isolation_profile_digest),
        lane_manifest_digest: hex::encode(value.lane_manifest_digest),
        lane_epoch: value.lane_epoch,
        run_id: hex::encode(value.run_id),
        attempt: value.attempt,
        expires_at: value.expires_at,
        wall_timeout_seconds: value.wall_timeout_seconds,
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 || !matches!(args[2].as_str(), "live" | "retained") {
        return Err("usage: verifier POLICY live|retained".into());
    }
    let bytes = std::fs::read(&args[1])?;
    if bytes.len() > 16384 {
        return Err("policy too large".into());
    }
    let policy: Policy = serde_json::from_slice(&bytes)?;
    let mut frame = Vec::new();
    std::io::stdin().take(513).read_to_end(&mut frame)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let verified = verify(&frame, &policy, now, args[2] == "live")?;
    println!("{}", serde_json::to_string(&verified)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::secp256k1::{Keypair, SecretKey};

    fn fixture() -> (v2::AdmitAttemptRequest, Policy) {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[42; 32]).unwrap();
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let mut value = v2::AdmitAttemptRequest {
            signed_request_digest: [1; 32],
            actor_pubkey: [2; 32],
            audience_digest: [3; 32],
            idempotency_digest: [4; 32],
            source_pin_event_id: [5; 32],
            workflow_digest: [6; 32],
            job_intent_digest: [7; 32],
            isolation_profile_digest: [8; 32],
            lane_manifest_digest: [9; 32],
            admission_signature: [0; 64],
            run_id: [11; 16],
            tip_oid: GitOid::Sha1([12; 20]),
            base_oid: GitOid::Sha1([13; 20]),
            issued_at: 100,
            expires_at: 200,
            lane_epoch: 3,
            admission_key_generation: 4,
            wall_timeout_seconds: 60,
            attempt: 1,
            parent_attempt: 0,
            trust_class: TrustClass::AcceptedReviewed,
            admission_signature_algorithm: v2::AdmissionSignatureAlgorithm::Bip340Secp256k1Sha256,
        };
        let digest = Sha256::digest(v2::admission_signature_message(&value)).into();
        value.admission_signature = *secp
            .sign_schnorr_no_aux_rand(&Message::from_digest(digest), &keypair)
            .as_ref();
        let policy = Policy {
            admission_pubkey: keypair.x_only_public_key().0.to_string(),
            actor_pubkey: hex::encode([2; 32]),
            audience_digest: hex::encode([3; 32]),
            lane_manifest_digest: hex::encode([9; 32]),
            lane_epoch: 3,
            admission_key_generation: 4,
            workflow_digest: hex::encode([6; 32]),
            job_intent_digest: hex::encode([7; 32]),
            isolation_profile_digest: hex::encode([8; 32]),
            trusted_base_oid: hex::encode([13; 20]),
            workflow_file_sha256: hex::encode([14; 32]),
        };
        (value, policy)
    }

    fn frame(value: v2::AdmitAttemptRequest) -> v2::EncodedFrame {
        v2::encode_request([1; 16], v2::Request::AdmitAttempt(value))
    }

    #[test]
    fn accepts_protocol_signature_and_preserves_identity() {
        let (value, policy) = fixture();
        let result = verify(frame(value).as_bytes(), &policy, 101, true).unwrap();
        assert_eq!(result.candidate_sha, hex::encode([12; 20]));
        assert_eq!(
            result.admission_message_digest,
            hex::encode(Sha256::digest(v2::admission_signature_message(&value)))
        );
        assert_eq!(result.attempt, 1);
    }

    #[test]
    fn refuses_changed_candidate_and_bad_signature() {
        let (mut value, policy) = fixture();
        value.tip_oid = GitOid::Sha1([15; 20]);
        assert!(verify(frame(value).as_bytes(), &policy, 101, true).is_err());
        let (mut value, policy) = fixture();
        value.admission_signature[0] ^= 1;
        assert!(verify(frame(value).as_bytes(), &policy, 101, true).is_err());
    }

    #[test]
    fn refuses_policy_and_time_drift() {
        let (value, mut policy) = fixture();
        for now in [99, 200, 201] {
            assert!(verify(frame(value).as_bytes(), &policy, now, true).is_err());
        }
        assert!(verify(frame(value).as_bytes(), &policy, 201, false).is_ok());
        policy.job_intent_digest = hex::encode([15; 32]);
        assert!(verify(frame(value).as_bytes(), &policy, 101, true).is_err());
    }

    #[test]
    fn refuses_trailing_bytes_and_wrong_operation() {
        let (value, policy) = fixture();
        let mut bytes = frame(value).as_bytes().to_vec();
        bytes.push(0);
        assert!(verify(&bytes, &policy, 101, true).is_err());
        bytes.truncate(511);
        assert!(verify(&bytes, &policy, 101, true).is_err());
    }
}
