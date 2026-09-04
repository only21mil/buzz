use buzz_ci_keyholder::{
    decode_request, decode_response, encode_request, encode_response, AcceptanceMutation,
    CanonicalPayload, DecodeError, DescribeAcceptanceRequest, DescribeAcceptanceResponse,
    DescribeRequest, DescribeResponse, EncodeError, ErrorCode, ErrorResponse, FrameHeader,
    HttpMethod, KeyholderClient, KeyholderServer, ManifestKind, Nip98AuthorizeRequest, Nip98Signer,
    Operation, OperationSet, PeerIdentity, PeerPolicy, PublicIdentity, QueryFilter, Request,
    Response, SignAcceptanceMutationRequest, SignCiEventRequest, SignManifestRequest,
    SignatureResponse, Url, HEADER_SIZE, MAX_BODY_SIZE, MAX_CANONICAL_PAYLOAD_SIZE, MAX_FRAME_SIZE,
    PROTOCOL_VERSION,
};
use proptest::prelude::*;

fn payload(byte: u8) -> CanonicalPayload {
    CanonicalPayload::new(vec![byte; 17]).expect("bounded nonempty fixture")
}

fn url() -> Url {
    Url::new("https://ci.example.test/upload?run=42".to_owned()).expect("valid fixture URL")
}

fn identity(byte: u8, generation: u64) -> PublicIdentity {
    PublicIdentity {
        public_key: [byte; 32],
        generation,
    }
}

fn signature(byte: u8, generation: u64) -> SignatureResponse {
    SignatureResponse {
        identity: identity(byte, generation),
        signed_digest: [byte + 1; 32],
        signature: [byte + 2; 64],
    }
}

fn requests() -> Vec<Request> {
    vec![
        Request::Describe(DescribeRequest),
        Request::DescribeAcceptance(DescribeAcceptanceRequest),
        Request::SignCiEvent(SignCiEventRequest {
            expected_generation: 7,
            event_kind: 46_100,
            canonical_event: payload(1),
        }),
        Request::Nip98Authorize(Nip98AuthorizeRequest {
            expected_generation: 8,
            method: HttpMethod::Post,
            url: url(),
            payload_digest: Some([2; 32]),
            created_at: 1_800_000_000,
            nonce: [3; 16],
            signer: Nip98Signer::CiEvent,
            query_filter: Some(QueryFilter::new(b"[{}]".to_vec()).expect("filter")),
        }),
        Request::SignManifest(SignManifestRequest {
            expected_generation: 9,
            manifest_kind: ManifestKind::JobIntentV2,
            canonical_manifest: payload(4),
        }),
        Request::SignAcceptanceMutation(SignAcceptanceMutationRequest {
            expected_generation: 10,
            scenario_sha256: [5; 32],
            mutation: AcceptanceMutation::Run,
        }),
    ]
}

fn describe_response() -> DescribeResponse {
    DescribeResponse {
        ci_event: identity(1, 7),
        nip98: identity(2, 8),
        manifest: identity(3, 9),
        peer_policy: PeerPolicy {
            uid: 1000,
            gid: 1001,
            allowed_operations: OperationSet::ALL,
        },
    }
}

#[test]
fn every_request_has_one_canonical_round_trip() {
    for request in requests() {
        let encoded = encode_request([42; 16], &request).expect("valid fixture request");
        assert!(encoded.as_bytes().len() <= MAX_FRAME_SIZE);
        assert_eq!(&encoded.as_bytes()[..4], b"BZKH");
        assert_eq!(
            u16::from_be_bytes([encoded.as_bytes()[4], encoded.as_bytes()[5]]),
            PROTOCOL_VERSION
        );
        assert_eq!(
            decode_request(encoded.as_bytes()),
            Ok((
                FrameHeader {
                    operation: request.operation(),
                    request_id: [42; 16],
                },
                request
            ))
        );
    }
}

#[test]
fn successful_and_error_responses_round_trip_and_bind_the_request() {
    let responses = [
        Response::Describe(describe_response()),
        Response::DescribeAcceptance(DescribeAcceptanceResponse {
            actor: identity(4, 10),
            scenario_sha256: [5; 32],
            event_ids: [[6; 32], [7; 32], [8; 32], [9; 32]],
        }),
        Response::SignCiEvent(signature(4, 7)),
        Response::Nip98Authorize(signature(7, 8)),
        Response::SignManifest(signature(10, 9)),
        Response::SignAcceptanceMutation(signature(13, 10)),
    ];
    for response in responses {
        let header = FrameHeader {
            operation: response.operation(),
            request_id: [11; 16],
        };
        let encoded = encode_response(header, &response).expect("valid fixture response");
        assert_eq!(decode_response(header, encoded.as_bytes()), Ok(response));

        let wrong = FrameHeader {
            operation: header.operation,
            request_id: [12; 16],
        };
        assert_eq!(
            decode_response(wrong, encoded.as_bytes()),
            Err(DecodeError::ResponseMismatch)
        );
    }

    let header = FrameHeader {
        operation: Operation::SignManifest,
        request_id: [13; 16],
    };
    let response = Response::Error {
        operation: Operation::SignManifest,
        error: ErrorResponse {
            code: ErrorCode::StaleGeneration,
            current_generation: 12,
        },
    };
    let encoded = encode_response(header, &response).expect("valid public error");
    assert_eq!(decode_response(header, encoded.as_bytes()), Ok(response));
}

#[test]
fn fields_are_length_prefixed_and_strictly_ordered() {
    let request = Request::SignCiEvent(SignCiEventRequest {
        expected_generation: 7,
        event_kind: 46_100,
        canonical_event: payload(1),
    });
    let encoded = encode_request([42; 16], &request).expect("valid fixture request");
    let bytes = encoded.as_bytes();
    assert_eq!(&bytes[HEADER_SIZE..HEADER_SIZE + 2], &[0, 1]);
    assert_eq!(&bytes[HEADER_SIZE + 2..HEADER_SIZE + 6], &[0, 0, 0, 8]);

    let second_tag = HEADER_SIZE + 6 + 8;
    let mut duplicate = bytes.to_vec();
    duplicate[second_tag..second_tag + 2].copy_from_slice(&1_u16.to_be_bytes());
    assert_eq!(
        decode_request(&duplicate),
        Err(DecodeError::NonCanonicalFieldOrder)
    );

    let mut unknown = bytes.to_vec();
    unknown.extend_from_slice(&4_u16.to_be_bytes());
    unknown.extend_from_slice(&0_u32.to_be_bytes());
    let body_len = u32::try_from(unknown.len() - HEADER_SIZE).expect("fixture body fits");
    unknown[12..16].copy_from_slice(&body_len.to_be_bytes());
    assert_eq!(decode_request(&unknown), Err(DecodeError::UnknownField));
}

#[test]
fn header_version_kind_flags_lengths_and_identifiers_fail_closed() {
    let encoded = encode_request([42; 16], &Request::Describe(DescribeRequest))
        .expect("valid describe request");

    let mut version = encoded.as_bytes().to_vec();
    version[4..6].copy_from_slice(&2_u16.to_be_bytes());
    assert_eq!(
        decode_request(&version),
        Err(DecodeError::UnsupportedVersion)
    );

    let mut kind = encoded.as_bytes().to_vec();
    kind[6] = 9;
    assert_eq!(decode_request(&kind), Err(DecodeError::UnknownMessageKind));

    let mut operation = encoded.as_bytes().to_vec();
    operation[7] = 9;
    assert_eq!(
        decode_request(&operation),
        Err(DecodeError::UnknownOperation)
    );

    let mut flags = encoded.as_bytes().to_vec();
    flags[8..12].copy_from_slice(&1_u32.to_be_bytes());
    assert_eq!(decode_request(&flags), Err(DecodeError::UnknownFlags));

    let mut zero_id = encoded.as_bytes().to_vec();
    zero_id[16..32].fill(0);
    assert_eq!(decode_request(&zero_id), Err(DecodeError::ZeroField));

    let mut trailing = encoded.as_bytes().to_vec();
    trailing.push(0);
    assert_eq!(decode_request(&trailing), Err(DecodeError::TrailingBytes));

    let mut oversized = encoded.into_bytes();
    let declared = u32::try_from(MAX_BODY_SIZE + 1).expect("limit fits u32");
    oversized[12..16].copy_from_slice(&declared.to_be_bytes());
    assert_eq!(decode_request(&oversized), Err(DecodeError::LimitExceeded));
}

#[test]
fn bounded_values_and_required_coordinates_reject_hostile_input() {
    assert!(CanonicalPayload::new(Vec::new()).is_err());
    assert!(CanonicalPayload::new(vec![1; MAX_CANONICAL_PAYLOAD_SIZE + 1]).is_err());
    assert!(Url::new("https://example.test/\nheader".to_owned()).is_err());

    let zero_generation = Request::SignManifest(SignManifestRequest {
        expected_generation: 0,
        manifest_kind: ManifestKind::LaneActivationV1,
        canonical_manifest: payload(1),
    });
    assert_eq!(
        encode_request([1; 16], &zero_generation),
        Err(EncodeError::ZeroField)
    );

    let zero_selector = Response::SignCiEvent(SignatureResponse {
        identity: PublicIdentity {
            public_key: [0; 32],
            generation: 1,
        },
        signed_digest: [1; 32],
        signature: [2; 64],
    });
    let header = FrameHeader {
        operation: Operation::SignCiEvent,
        request_id: [1; 16],
    };
    assert_eq!(
        encode_response(header, &zero_selector),
        Err(EncodeError::ZeroField)
    );
}

#[test]
fn peer_policy_requires_exact_credentials_and_closed_operation_bits() {
    let policy = PeerPolicy {
        uid: 1000,
        gid: 1001,
        allowed_operations: OperationSet::only(Operation::Describe)
            .union(OperationSet::only(Operation::SignManifest)),
    };
    assert!(policy.authorizes(
        PeerIdentity {
            uid: 1000,
            gid: 1001
        },
        Operation::Describe
    ));
    assert!(policy.authorizes(
        PeerIdentity {
            uid: 1000,
            gid: 1001
        },
        Operation::SignManifest
    ));
    assert!(!policy.authorizes(
        PeerIdentity {
            uid: 1000,
            gid: 1002
        },
        Operation::Describe
    ));
    assert!(!policy.authorizes(
        PeerIdentity {
            uid: 1000,
            gid: 1001
        },
        Operation::SignCiEvent
    ));
    assert!(OperationSet::from_bits(0b100_0000).is_none());
}

#[test]
fn response_encoder_rejects_cross_operation_reinterpretation() {
    let header = FrameHeader {
        operation: Operation::SignManifest,
        request_id: [1; 16],
    };
    assert_eq!(
        encode_response(header, &Response::SignCiEvent(signature(1, 1))),
        Err(EncodeError::OperationMismatch)
    );
}

#[test]
fn client_and_server_traits_are_transport_neutral() {
    fn client_contract<T: KeyholderClient>() {}
    fn server_contract<T: KeyholderServer>() {}
    let _ = client_contract::<NeverClient>;
    let _ = server_contract::<NeverServer>;
}

struct NeverClient;

impl KeyholderClient for NeverClient {
    type Error = ();

    fn describe(&mut self, _: DescribeRequest) -> Result<DescribeResponse, Self::Error> {
        Err(())
    }

    fn sign_ci_event(&mut self, _: SignCiEventRequest) -> Result<SignatureResponse, Self::Error> {
        Err(())
    }

    fn nip98_authorize(
        &mut self,
        _: Nip98AuthorizeRequest,
    ) -> Result<SignatureResponse, Self::Error> {
        Err(())
    }

    fn sign_manifest(&mut self, _: SignManifestRequest) -> Result<SignatureResponse, Self::Error> {
        Err(())
    }
}

struct NeverServer;

impl KeyholderServer for NeverServer {
    type Error = ();

    fn describe(
        &self,
        _: PeerIdentity,
        _: DescribeRequest,
    ) -> Result<DescribeResponse, Self::Error> {
        Err(())
    }

    fn sign_ci_event(
        &self,
        _: PeerIdentity,
        _: SignCiEventRequest,
    ) -> Result<SignatureResponse, Self::Error> {
        Err(())
    }

    fn nip98_authorize(
        &self,
        _: PeerIdentity,
        _: Nip98AuthorizeRequest,
    ) -> Result<SignatureResponse, Self::Error> {
        Err(())
    }

    fn sign_manifest(
        &self,
        _: PeerIdentity,
        _: SignManifestRequest,
    ) -> Result<SignatureResponse, Self::Error> {
        Err(())
    }

    fn public_error(&self, _: &Self::Error) -> ErrorResponse {
        ErrorResponse {
            code: ErrorCode::Unavailable,
            current_generation: 0,
        }
    }
}

proptest! {
    #[test]
    fn arbitrary_request_frames_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..100_000)) {
        let _ = decode_request(&bytes);
    }

    #[test]
    fn arbitrary_response_frames_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..100_000)) {
        let header = FrameHeader {
            operation: Operation::Describe,
            request_id: [1; 16],
        };
        let _ = decode_response(header, &bytes);
    }
}
