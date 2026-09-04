//! Keyholder adapter for the shared post-freeze acceptance binding.

pub use buzz_ci_acceptance_ctl::acceptance_binding::{
    AcceptanceActorBinding as AcceptanceReceiptIdentity,
    AcceptanceAuthorityBinding as AcceptanceReceiptPolicy, AcceptanceBindingError as ReceiptError,
    AcceptanceBindingReceipt, ACCEPTANCE_BINDING_PATH, ACCEPTANCE_BINDING_SCHEMA,
};

use sha2::Digest;
use std::collections::BTreeSet;

use crate::{AcceptanceSigningPolicy, PeerPolicy, PublicIdentity};

/// Convert one shared validated receipt into the keyholder's closed signing policy.
pub fn acceptance_signing_policy(
    receipt: &AcceptanceBindingReceipt,
    expected_peer: PeerPolicy,
    nip98_identity: PublicIdentity,
    nip98_origin: &str,
) -> Result<AcceptanceSigningPolicy, ReceiptError> {
    let validated = receipt.validate()?;
    if (receipt.keyholder_peer_uid, receipt.keyholder_peer_gid)
        != (expected_peer.uid, expected_peer.gid)
    {
        return Err(ReceiptError::Invalid);
    }
    let origin = url::Url::parse(nip98_origin).map_err(|_| ReceiptError::Invalid)?;
    if origin.scheme() != "https"
        || origin.host_str().is_none()
        || !origin.username().is_empty()
        || origin.password().is_some()
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
        || nip98_identity.generation == 0
        || receipt.fixture.export_subject != hex::encode(nip98_identity.public_key)
        || receipt.fixture.export_generation != nip98_identity.generation
        || receipt.fixture.expected_artifacts.len() != 1
        || receipt.fixture.expected_log.name != "job.log"
        || receipt.fixture.expected_artifacts[0].name != "result.json"
    {
        return Err(ReceiptError::Invalid);
    }
    let run_bytes = hex::decode(&receipt.fixture.run_id).map_err(|_| ReceiptError::Invalid)?;
    let run_id = uuid::Uuid::from_slice(&run_bytes).map_err(|_| ReceiptError::Invalid)?;
    let origin = origin.origin().ascii_serialization();
    let plans = [
        (
            "log",
            receipt.fixture.expected_log.name.as_str(),
            receipt.fixture.expected_log.sha256.as_str(),
            receipt.fixture.expected_log.bytes,
            format!(
                "{origin}/ci/logs/{}/{}/{}/1/{}",
                receipt.fixture.request_digest,
                run_id.hyphenated(),
                receipt.fixture.job_id,
                receipt.fixture.expected_log.sha256,
            ),
        ),
        (
            "artifact",
            receipt.fixture.expected_artifacts[0].name.as_str(),
            receipt.fixture.expected_artifacts[0].sha256.as_str(),
            receipt.fixture.expected_artifacts[0].bytes,
            format!(
                "{origin}/ci/artifacts/{}/{}/{}/1/result/{}",
                receipt.fixture.request_digest,
                run_id.hyphenated(),
                receipt.fixture.job_id,
                receipt.fixture.expected_artifacts[0].sha256,
            ),
        ),
    ];
    let mut transcript = Vec::from(b"buzz-ci-acceptance-export-authority:v1\0".as_slice());
    let generation = nip98_identity.generation.to_string();
    let run_id_string = run_id.hyphenated().to_string();
    for (kind, name, sha256, bytes, url) in &plans {
        let attempt = "1";
        let byte_length = bytes.to_string();
        for field in [
            "GET",
            url.as_str(),
            receipt.fixture.export_subject.as_str(),
            generation.as_str(),
            receipt.fixture.request_digest.as_str(),
            run_id_string.as_str(),
            receipt.fixture.job_id.as_str(),
            attempt,
            *kind,
            *name,
            *sha256,
            byte_length.as_str(),
        ] {
            transcript.extend_from_slice(&(field.len() as u64).to_be_bytes());
            transcript.extend_from_slice(field.as_bytes());
        }
    }
    if receipt.fixture.export_authorization_digest != hex::encode(sha2::Sha256::digest(transcript))
    {
        return Err(ReceiptError::Invalid);
    }
    let paths = plans
        .iter()
        .map(|(_, _, _, _, url)| url::Url::parse(url).map(|url| url.path().to_owned()))
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(|_| ReceiptError::Invalid)?;
    Ok(AcceptanceSigningPolicy::from_validated(
        PublicIdentity {
            public_key: validated.actor_public_key(),
            generation: validated.actor_generation(),
        },
        validated,
        paths,
    ))
}

#[cfg(test)]
mod tests {
    use buzz_ci_acceptance_ctl::acceptance_binding::AcceptanceBindingError;
    use buzz_ci_acceptance_ctl::acceptance_binding_test_support::{
        acceptance_binding_mutation_corpus, canonical_acceptance_binding,
        CANONICAL_QUALIFICATION_GID, CANONICAL_QUALIFICATION_UID,
    };

    use super::*;

    fn peer_policy(uid: u32, gid: u32) -> PeerPolicy {
        let allowed_operations = crate::OperationSet::only(crate::Operation::Describe)
            .union(crate::OperationSet::only(
                crate::Operation::DescribeAcceptance,
            ))
            .union(crate::OperationSet::only(
                crate::Operation::SignAcceptanceMutation,
            ));
        PeerPolicy {
            uid,
            gid,
            allowed_operations,
        }
    }

    fn nip98_identity(receipt: &AcceptanceBindingReceipt) -> PublicIdentity {
        PublicIdentity {
            public_key: hex::decode(&receipt.fixture.export_subject)
                .unwrap()
                .try_into()
                .unwrap(),
            generation: receipt.fixture.export_generation,
        }
    }

    fn bind_export(mut receipt: AcceptanceBindingReceipt) -> AcceptanceBindingReceipt {
        let identity = nip98_identity(&receipt);
        let run = uuid::Uuid::from_slice(&hex::decode(&receipt.fixture.run_id).unwrap()).unwrap();
        let origin = "https://relay.example.test";
        let urls = [
            format!(
                "{origin}/ci/logs/{}/{}/{}/1/{}",
                receipt.fixture.request_digest,
                run.hyphenated(),
                receipt.fixture.job_id,
                receipt.fixture.expected_log.sha256
            ),
            format!(
                "{origin}/ci/artifacts/{}/{}/{}/1/result/{}",
                receipt.fixture.request_digest,
                run.hyphenated(),
                receipt.fixture.job_id,
                receipt.fixture.expected_artifacts[0].sha256
            ),
        ];
        let specs = [
            ("log", &receipt.fixture.expected_log),
            ("artifact", &receipt.fixture.expected_artifacts[0]),
        ];
        let mut transcript = Vec::from(b"buzz-ci-acceptance-export-authority:v1\0".as_slice());
        let generation = identity.generation.to_string();
        let run_id = run.hyphenated().to_string();
        for ((kind, object), url) in specs.into_iter().zip(urls) {
            let byte_length = object.bytes.to_string();
            for field in [
                "GET",
                url.as_str(),
                receipt.fixture.export_subject.as_str(),
                generation.as_str(),
                receipt.fixture.request_digest.as_str(),
                run_id.as_str(),
                receipt.fixture.job_id.as_str(),
                "1",
                kind,
                object.name.as_str(),
                object.sha256.as_str(),
                byte_length.as_str(),
            ] {
                transcript.extend_from_slice(&(field.len() as u64).to_be_bytes());
                transcript.extend_from_slice(field.as_bytes());
            }
        }
        let digest = hex::encode(sha2::Sha256::digest(transcript));
        receipt
            .fixture
            .export_authorization_digest
            .clone_from(&digest);
        receipt
            .acceptance
            .export_subject
            .clone_from(&receipt.fixture.export_subject);
        receipt.acceptance.export_generation = receipt.fixture.export_generation;
        receipt.acceptance.export_authorization_digest = digest;
        receipt
    }

    #[test]
    fn keyholder_accepts_the_shared_canonical_fixture() {
        let expected = bind_export(canonical_acceptance_binding());
        let bytes = serde_json::to_vec(&expected).expect("canonical receipt");
        let receipt = AcceptanceBindingReceipt::from_canonical_bytes(&bytes).expect("receipt");
        let peer_policy = peer_policy(expected.keyholder_peer_uid, expected.keyholder_peer_gid);
        let policy = acceptance_signing_policy(
            &receipt,
            peer_policy,
            nip98_identity(&receipt),
            "https://relay.example.test",
        )
        .expect("signing policy");
        assert_eq!(
            policy.actor().generation,
            expected.acceptance.actor.generation
        );
        assert_eq!(
            hex::encode(policy.event_ids()[0]),
            expected.fixture.request_digest
        );
        assert_eq!(
            hex::encode(policy.event_ids()[1]),
            expected.fixture.grant_event_id
        );
        let public_key = |value: &str| {
            hex::decode(value)
                .expect("public key hex")
                .try_into()
                .expect("public key length")
        };
        let selectors = crate::SelectorSet::new(
            PublicIdentity {
                public_key: public_key(
                    "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
                ),
                generation: 7,
            },
            PublicIdentity {
                public_key: public_key(&expected.fixture.export_subject),
                generation: expected.fixture.export_generation,
            },
            PublicIdentity {
                public_key: public_key(
                    "e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13",
                ),
                generation: 9,
            },
        )
        .expect("selectors");
        crate::SigningPolicy::new_with_acceptance(
            peer_policy,
            selectors,
            "https://relay.example.test".to_owned(),
            policy,
        )
        .expect("full keyholder policy");
    }

    #[test]
    fn keyholder_rejects_every_shared_receipt_mutation() {
        for mutation in acceptance_binding_mutation_corpus() {
            let result = AcceptanceBindingReceipt::from_canonical_bytes(&mutation.bytes).and_then(
                |receipt| {
                    acceptance_signing_policy(
                        &receipt,
                        peer_policy(receipt.keyholder_peer_uid, receipt.keyholder_peer_gid),
                        nip98_identity(&receipt),
                        "https://relay.example.test",
                    )
                },
            );
            assert_eq!(
                result,
                Err(AcceptanceBindingError::Invalid),
                "mutation {}",
                mutation.name
            );
        }
    }

    #[test]
    fn keyholder_rejects_a_receipt_for_another_client_identity() {
        let receipt = bind_export(canonical_acceptance_binding());
        assert!(acceptance_signing_policy(
            &receipt,
            peer_policy(receipt.keyholder_peer_uid, receipt.keyholder_peer_gid),
            nip98_identity(&receipt),
            "https://relay.example.test",
        )
        .is_ok());
        assert_eq!(
            acceptance_signing_policy(
                &receipt,
                peer_policy(CANONICAL_QUALIFICATION_UID, CANONICAL_QUALIFICATION_GID),
                nip98_identity(&receipt),
                "https://relay.example.test",
            ),
            Err(AcceptanceBindingError::Invalid),
        );
        assert_eq!(
            acceptance_signing_policy(
                &receipt,
                peer_policy(receipt.acceptance_peer_uid, receipt.keyholder_peer_gid),
                nip98_identity(&receipt),
                "https://relay.example.test",
            ),
            Err(AcceptanceBindingError::Invalid),
        );
        assert_eq!(
            acceptance_signing_policy(
                &receipt,
                peer_policy(receipt.keyholder_peer_uid, receipt.acceptance_peer_gid),
                nip98_identity(&receipt),
                "https://relay.example.test",
            ),
            Err(AcceptanceBindingError::Invalid),
        );
    }

    #[test]
    fn keyholder_binds_export_authority_to_origin_selector_and_transcript() {
        let receipt = bind_export(canonical_acceptance_binding());
        let peer = peer_policy(receipt.keyholder_peer_uid, receipt.keyholder_peer_gid);
        let identity = nip98_identity(&receipt);

        assert_eq!(
            acceptance_signing_policy(&receipt, peer, identity, "http://relay.example.test"),
            Err(AcceptanceBindingError::Invalid)
        );
        assert_eq!(
            acceptance_signing_policy(&receipt, peer, identity, "https://other.example.test"),
            Err(AcceptanceBindingError::Invalid)
        );

        let mut other_generation = identity;
        other_generation.generation += 1;
        assert_eq!(
            acceptance_signing_policy(
                &receipt,
                peer,
                other_generation,
                "https://relay.example.test"
            ),
            Err(AcceptanceBindingError::Invalid)
        );

        let mut other_subject = identity;
        other_subject.public_key = [0x55; 32];
        assert_eq!(
            acceptance_signing_policy(&receipt, peer, other_subject, "https://relay.example.test"),
            Err(AcceptanceBindingError::Invalid)
        );

        let mut bad_digest = receipt.clone();
        bad_digest.fixture.export_authorization_digest = "00".repeat(32);
        assert_eq!(
            acceptance_signing_policy(&bad_digest, peer, identity, "https://relay.example.test"),
            Err(AcceptanceBindingError::Invalid)
        );
    }
}
