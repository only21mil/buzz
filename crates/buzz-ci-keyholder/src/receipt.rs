//! Keyholder adapter for the shared post-freeze acceptance binding.

pub use buzz_ci_acceptance_ctl::acceptance_binding::{
    AcceptanceActorBinding as AcceptanceReceiptIdentity,
    AcceptanceAuthorityBinding as AcceptanceReceiptPolicy, AcceptanceBindingError as ReceiptError,
    AcceptanceBindingReceipt, ACCEPTANCE_BINDING_PATH, ACCEPTANCE_BINDING_SCHEMA,
};

use crate::{AcceptanceSigningPolicy, PeerPolicy, PublicIdentity};

/// Convert one shared validated receipt into the keyholder's closed signing policy.
pub fn acceptance_signing_policy(
    receipt: &AcceptanceBindingReceipt,
    expected_peer: PeerPolicy,
) -> Result<AcceptanceSigningPolicy, ReceiptError> {
    let validated = receipt.validate()?;
    if (receipt.keyholder_peer_uid, receipt.keyholder_peer_gid)
        != (expected_peer.uid, expected_peer.gid)
    {
        return Err(ReceiptError::Invalid);
    }
    Ok(AcceptanceSigningPolicy::from_validated(
        PublicIdentity {
            public_key: validated.actor_public_key(),
            generation: validated.actor_generation(),
        },
        validated,
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

    #[test]
    fn keyholder_accepts_the_shared_canonical_fixture() {
        let expected = canonical_acceptance_binding();
        let bytes = serde_json::to_vec(&expected).expect("canonical receipt");
        let receipt = AcceptanceBindingReceipt::from_canonical_bytes(&bytes).expect("receipt");
        let peer_policy = peer_policy(expected.keyholder_peer_uid, expected.keyholder_peer_gid);
        let policy = acceptance_signing_policy(&receipt, peer_policy).expect("signing policy");
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
                public_key: public_key(
                    "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
                ),
                generation: 8,
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
        let receipt = canonical_acceptance_binding();
        assert!(acceptance_signing_policy(
            &receipt,
            peer_policy(receipt.keyholder_peer_uid, receipt.keyholder_peer_gid),
        )
        .is_ok());
        assert_eq!(
            acceptance_signing_policy(
                &receipt,
                peer_policy(CANONICAL_QUALIFICATION_UID, CANONICAL_QUALIFICATION_GID),
            ),
            Err(AcceptanceBindingError::Invalid),
        );
        assert_eq!(
            acceptance_signing_policy(
                &receipt,
                peer_policy(receipt.acceptance_peer_uid, receipt.keyholder_peer_gid),
            ),
            Err(AcceptanceBindingError::Invalid),
        );
        assert_eq!(
            acceptance_signing_policy(
                &receipt,
                peer_policy(receipt.keyholder_peer_uid, receipt.acceptance_peer_gid),
            ),
            Err(AcceptanceBindingError::Invalid),
        );
    }
}
