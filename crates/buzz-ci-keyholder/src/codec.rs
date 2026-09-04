use std::fmt;

use crate::types::{
    AcceptanceMutation, CanonicalPayload, DescribeAcceptanceRequest, DescribeAcceptanceResponse,
    DescribeRequest, DescribeResponse, ErrorCode, ErrorResponse, HttpMethod, ManifestKind,
    Nip98AuthorizeRequest, Nip98Signer, Operation, OperationSet, PeerPolicy, PublicIdentity,
    QueryFilter, Request, Response, SignAcceptanceMutationRequest, SignCiEventRequest,
    SignManifestRequest, SignatureResponse, Url, ValueError,
};

/// Keyholder frame magic.
pub const MAGIC: [u8; 4] = *b"BZKH";
/// Exact protocol version accepted by this codec.
pub const PROTOCOL_VERSION: u16 = 2;
/// Fixed frame header size.
pub const HEADER_SIZE: usize = 32;
/// Maximum encoded body size.
pub const MAX_BODY_SIZE: usize = 64 * 1024;
/// Maximum encoded field value size.
pub const MAX_FIELD_SIZE: usize = 48 * 1024;
/// Maximum number of fields in one body.
pub const MAX_FIELD_COUNT: usize = 16;
/// Maximum complete frame size.
pub const MAX_FRAME_SIZE: usize = HEADER_SIZE + MAX_BODY_SIZE;

const REQUEST_KIND: u8 = 1;
const RESPONSE_KIND: u8 = 2;
const RESPONSE_ERROR_FLAG: u32 = 1;
const FIELD_HEADER_SIZE: usize = 6;

/// Request header coordinates used to bind a response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameHeader {
    /// Closed operation identifier.
    pub operation: Operation,
    /// Caller-selected nonzero replay identifier.
    pub request_id: [u8; 16],
}

/// Bounded canonical frame bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncodedFrame(Vec<u8>);

impl EncodedFrame {
    /// Borrow the exact encoded frame.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consume the frame and return its exact bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// Canonical encoding failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncodeError {
    /// A required coordinate is zero.
    ZeroField,
    /// A bounded field or body is too large.
    LimitExceeded,
    /// Response operation does not match its request header.
    OperationMismatch,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ZeroField => "required field is zero",
            Self::LimitExceeded => "protocol encoding limit exceeded",
            Self::OperationMismatch => "response operation does not match request",
        })
    }
}

impl std::error::Error for EncodeError {}

/// Strict decoding failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    /// Frame does not contain a complete header.
    FrameTooShort,
    /// Frame magic does not match the keyholder protocol.
    BadMagic,
    /// Frame version is not exactly supported.
    UnsupportedVersion,
    /// Message kind is unknown or does not match the decoder.
    UnknownMessageKind,
    /// Operation is outside the closed set.
    UnknownOperation,
    /// Header flags are not canonical for this message.
    UnknownFlags,
    /// Declared body size is invalid or does not match the frame.
    WrongBodyLength,
    /// Frame contains bytes after the declared body.
    TrailingBytes,
    /// A global field or body limit was exceeded.
    LimitExceeded,
    /// A field tag is zero or not part of the operation schema.
    UnknownField,
    /// Fields are duplicated or not in strictly increasing tag order.
    NonCanonicalFieldOrder,
    /// A required field is missing.
    MissingField,
    /// A fixed-width field has the wrong size.
    WrongFieldLength,
    /// A required identifier, key, generation, digest, or signature is zero.
    ZeroField,
    /// A closed enum contains an unknown value.
    UnknownEnum,
    /// Text is not canonical UTF-8 or contains forbidden characters.
    InvalidText,
    /// Response does not bind the expected operation and request identifier.
    ResponseMismatch,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::FrameTooShort => "frame is shorter than the header",
            Self::BadMagic => "invalid keyholder frame magic",
            Self::UnsupportedVersion => "unsupported keyholder protocol version",
            Self::UnknownMessageKind => "unknown keyholder message kind",
            Self::UnknownOperation => "unknown keyholder operation",
            Self::UnknownFlags => "unknown keyholder frame flags",
            Self::WrongBodyLength => "declared body length does not match frame",
            Self::TrailingBytes => "trailing keyholder frame bytes",
            Self::LimitExceeded => "keyholder protocol limit exceeded",
            Self::UnknownField => "unknown keyholder field",
            Self::NonCanonicalFieldOrder => "fields are not in canonical order",
            Self::MissingField => "required keyholder field is missing",
            Self::WrongFieldLength => "keyholder field has the wrong length",
            Self::ZeroField => "required keyholder field is zero",
            Self::UnknownEnum => "unknown keyholder enum value",
            Self::InvalidText => "invalid keyholder text field",
            Self::ResponseMismatch => "response does not match request header",
        })
    }
}

impl std::error::Error for DecodeError {}

/// Encode one canonical request frame.
pub fn encode_request(
    request_id: [u8; 16],
    request: &Request,
) -> Result<EncodedFrame, EncodeError> {
    require_nonzero(&request_id)?;
    let mut body = BodyEncoder::new();
    match request {
        Request::Describe(_) => {}
        Request::DescribeAcceptance(_) => {}
        Request::SignCiEvent(value) => encode_sign_ci_event(&mut body, value)?,
        Request::Nip98Authorize(value) => encode_nip98(&mut body, value)?,
        Request::SignManifest(value) => encode_sign_manifest(&mut body, value)?,
        Request::SignAcceptanceMutation(value) => encode_acceptance_mutation(&mut body, value)?,
    }
    encode_frame(
        REQUEST_KIND,
        request.operation(),
        0,
        request_id,
        body.finish(),
    )
}

/// Decode one exact canonical request frame.
pub fn decode_request(frame: &[u8]) -> Result<(FrameHeader, Request), DecodeError> {
    let decoded = decode_frame(frame)?;
    if decoded.kind != REQUEST_KIND {
        return Err(DecodeError::UnknownMessageKind);
    }
    if decoded.flags != 0 {
        return Err(DecodeError::UnknownFlags);
    }
    let fields = decode_fields(decoded.body)?;
    let request = match decoded.header.operation {
        Operation::Describe => {
            expect_tags(&fields, &[])?;
            Request::Describe(DescribeRequest)
        }
        Operation::DescribeAcceptance => {
            expect_tags(&fields, &[])?;
            Request::DescribeAcceptance(DescribeAcceptanceRequest)
        }
        Operation::SignCiEvent => Request::SignCiEvent(decode_sign_ci_event(&fields)?),
        Operation::Nip98Authorize => Request::Nip98Authorize(decode_nip98(&fields)?),
        Operation::SignManifest => Request::SignManifest(decode_sign_manifest(&fields)?),
        Operation::SignAcceptanceMutation => {
            Request::SignAcceptanceMutation(decode_acceptance_mutation(&fields)?)
        }
    };
    Ok((decoded.header, request))
}

/// Encode a canonical response bound to one exact request header.
pub fn encode_response(
    request_header: FrameHeader,
    response: &Response,
) -> Result<EncodedFrame, EncodeError> {
    require_nonzero(&request_header.request_id)?;
    if request_header.operation != response.operation() {
        return Err(EncodeError::OperationMismatch);
    }
    let mut body = BodyEncoder::new();
    let flags = match response {
        Response::Describe(value) => {
            encode_describe(&mut body, value)?;
            0
        }
        Response::DescribeAcceptance(value) => {
            encode_describe_acceptance(&mut body, value)?;
            0
        }
        Response::SignCiEvent(value)
        | Response::Nip98Authorize(value)
        | Response::SignManifest(value)
        | Response::SignAcceptanceMutation(value) => {
            encode_signature(&mut body, value)?;
            0
        }
        Response::Error { error, .. } => {
            body.field(1, &(error.code as u16).to_be_bytes())?;
            body.field(2, &error.current_generation.to_be_bytes())?;
            RESPONSE_ERROR_FLAG
        }
    };
    encode_frame(
        RESPONSE_KIND,
        request_header.operation,
        flags,
        request_header.request_id,
        body.finish(),
    )
}

/// Decode a canonical response bound to one exact request header.
pub fn decode_response(expected: FrameHeader, frame: &[u8]) -> Result<Response, DecodeError> {
    let decoded = decode_frame(frame)?;
    if decoded.kind != RESPONSE_KIND {
        return Err(DecodeError::UnknownMessageKind);
    }
    if decoded.header != expected {
        return Err(DecodeError::ResponseMismatch);
    }
    if decoded.flags & !RESPONSE_ERROR_FLAG != 0 {
        return Err(DecodeError::UnknownFlags);
    }
    let fields = decode_fields(decoded.body)?;
    if decoded.flags == RESPONSE_ERROR_FLAG {
        expect_tags(&fields, &[1, 2])?;
        return Ok(Response::Error {
            operation: expected.operation,
            error: ErrorResponse {
                code: ErrorCode::try_from(read_u16(fields[0].value)?)
                    .map_err(|_| DecodeError::UnknownEnum)?,
                current_generation: read_u64(fields[1].value)?,
            },
        });
    }
    match expected.operation {
        Operation::Describe => decode_describe(&fields).map(Response::Describe),
        Operation::DescribeAcceptance => {
            decode_describe_acceptance(&fields).map(Response::DescribeAcceptance)
        }
        Operation::SignCiEvent => decode_signature(&fields).map(Response::SignCiEvent),
        Operation::Nip98Authorize => decode_signature(&fields).map(Response::Nip98Authorize),
        Operation::SignManifest => decode_signature(&fields).map(Response::SignManifest),
        Operation::SignAcceptanceMutation => {
            decode_signature(&fields).map(Response::SignAcceptanceMutation)
        }
    }
}

fn encode_acceptance_mutation(
    body: &mut BodyEncoder,
    value: &SignAcceptanceMutationRequest,
) -> Result<(), EncodeError> {
    require_nonzero_number(value.expected_generation)?;
    require_nonzero(&value.scenario_sha256)?;
    body.field(1, &value.expected_generation.to_be_bytes())?;
    body.field(2, &value.scenario_sha256)?;
    body.field(3, &[value.mutation as u8])
}

fn decode_acceptance_mutation(
    fields: &[Field<'_>],
) -> Result<SignAcceptanceMutationRequest, DecodeError> {
    expect_tags(fields, &[1, 2, 3])?;
    let mutation = AcceptanceMutation::try_from(read_u8(fields[2].value)?)
        .map_err(|_| DecodeError::UnknownEnum)?;
    Ok(SignAcceptanceMutationRequest {
        expected_generation: nonzero_u64(fields[0].value)?,
        scenario_sha256: nonzero_array(fields[1].value)?,
        mutation,
    })
}

fn encode_sign_ci_event(
    body: &mut BodyEncoder,
    value: &SignCiEventRequest,
) -> Result<(), EncodeError> {
    require_nonzero_number(value.expected_generation)?;
    require_nonzero_number(value.event_kind)?;
    body.field(1, &value.expected_generation.to_be_bytes())?;
    body.field(2, &value.event_kind.to_be_bytes())?;
    body.field(3, value.canonical_event.as_bytes())
}

fn decode_sign_ci_event(fields: &[Field<'_>]) -> Result<SignCiEventRequest, DecodeError> {
    expect_tags(fields, &[1, 2, 3])?;
    let expected_generation = nonzero_u64(fields[0].value)?;
    let event_kind = nonzero_u32(fields[1].value)?;
    let canonical_event = decode_payload(fields[2].value)?;
    Ok(SignCiEventRequest {
        expected_generation,
        event_kind,
        canonical_event,
    })
}

fn encode_nip98(body: &mut BodyEncoder, value: &Nip98AuthorizeRequest) -> Result<(), EncodeError> {
    require_nonzero_number(value.expected_generation)?;
    require_nonzero_number(value.created_at)?;
    require_nonzero(&value.nonce)?;
    if let Some(digest) = value.payload_digest {
        require_nonzero(&digest)?;
    }
    body.field(1, &value.expected_generation.to_be_bytes())?;
    body.field(2, &[value.method as u8])?;
    body.field(3, value.url.as_str().as_bytes())?;
    body.field(4, value.payload_digest.as_ref().map_or(&[], |value| value))?;
    body.field(5, &value.created_at.to_be_bytes())?;
    body.field(6, &value.nonce)?;
    body.field(7, &[value.signer as u8])?;
    body.field(
        8,
        value
            .query_filter
            .as_ref()
            .map_or(&[], QueryFilter::as_bytes),
    )
}

fn decode_nip98(fields: &[Field<'_>]) -> Result<Nip98AuthorizeRequest, DecodeError> {
    expect_tags(fields, &[1, 2, 3, 4, 5, 6, 7, 8])?;
    let method =
        HttpMethod::try_from(read_u8(fields[1].value)?).map_err(|_| DecodeError::UnknownEnum)?;
    let signer =
        Nip98Signer::try_from(read_u8(fields[6].value)?).map_err(|_| DecodeError::UnknownEnum)?;
    let url_text = std::str::from_utf8(fields[2].value).map_err(|_| DecodeError::InvalidText)?;
    let url = Url::new(url_text.to_owned()).map_err(map_value_error)?;
    let payload_digest = match fields[3].value.len() {
        0 => None,
        32 => Some(nonzero_array(fields[3].value)?),
        _ => return Err(DecodeError::WrongFieldLength),
    };
    let query_filter = if fields[7].value.is_empty() {
        None
    } else {
        Some(QueryFilter::new(fields[7].value.to_vec()).map_err(map_value_error)?)
    };
    Ok(Nip98AuthorizeRequest {
        expected_generation: nonzero_u64(fields[0].value)?,
        method,
        url,
        payload_digest,
        created_at: nonzero_u64(fields[4].value)?,
        nonce: nonzero_array(fields[5].value)?,
        signer,
        query_filter,
    })
}

fn encode_sign_manifest(
    body: &mut BodyEncoder,
    value: &SignManifestRequest,
) -> Result<(), EncodeError> {
    require_nonzero_number(value.expected_generation)?;
    body.field(1, &value.expected_generation.to_be_bytes())?;
    body.field(2, &[value.manifest_kind as u8])?;
    body.field(3, value.canonical_manifest.as_bytes())
}

fn decode_sign_manifest(fields: &[Field<'_>]) -> Result<SignManifestRequest, DecodeError> {
    expect_tags(fields, &[1, 2, 3])?;
    let manifest_kind =
        ManifestKind::try_from(read_u8(fields[1].value)?).map_err(|_| DecodeError::UnknownEnum)?;
    Ok(SignManifestRequest {
        expected_generation: nonzero_u64(fields[0].value)?,
        manifest_kind,
        canonical_manifest: decode_payload(fields[2].value)?,
    })
}

fn encode_describe(body: &mut BodyEncoder, value: &DescribeResponse) -> Result<(), EncodeError> {
    encode_public_identity(body, 1, 2, value.ci_event)?;
    encode_public_identity(body, 3, 4, value.nip98)?;
    encode_public_identity(body, 5, 6, value.manifest)?;
    if value.peer_policy.allowed_operations == OperationSet::NONE {
        return Err(EncodeError::ZeroField);
    }
    body.field(7, &value.peer_policy.uid.to_be_bytes())?;
    body.field(8, &value.peer_policy.gid.to_be_bytes())?;
    body.field(9, &[value.peer_policy.allowed_operations.bits()])
}

fn decode_describe(fields: &[Field<'_>]) -> Result<DescribeResponse, DecodeError> {
    expect_tags(fields, &[1, 2, 3, 4, 5, 6, 7, 8, 9])?;
    let operations = OperationSet::from_bits(read_u8(fields[8].value)?)
        .filter(|value| *value != OperationSet::NONE)
        .ok_or(DecodeError::UnknownEnum)?;
    Ok(DescribeResponse {
        ci_event: decode_public_identity(fields[0].value, fields[1].value)?,
        nip98: decode_public_identity(fields[2].value, fields[3].value)?,
        manifest: decode_public_identity(fields[4].value, fields[5].value)?,
        peer_policy: PeerPolicy {
            uid: read_u32(fields[6].value)?,
            gid: read_u32(fields[7].value)?,
            allowed_operations: operations,
        },
    })
}

fn encode_describe_acceptance(
    body: &mut BodyEncoder,
    value: &DescribeAcceptanceResponse,
) -> Result<(), EncodeError> {
    encode_public_identity(body, 1, 2, value.actor)?;
    require_nonzero(&value.scenario_sha256)?;
    body.field(3, &value.scenario_sha256)?;
    for (tag, event_id) in (4_u16..=8).zip(value.event_ids) {
        require_nonzero(&event_id)?;
        body.field(tag, &event_id)?;
    }
    Ok(())
}

fn decode_describe_acceptance(
    fields: &[Field<'_>],
) -> Result<DescribeAcceptanceResponse, DecodeError> {
    expect_tags(fields, &[1, 2, 3, 4, 5, 6, 7, 8])?;
    Ok(DescribeAcceptanceResponse {
        actor: decode_public_identity(fields[0].value, fields[1].value)?,
        scenario_sha256: nonzero_array(fields[2].value)?,
        event_ids: [
            nonzero_array(fields[3].value)?,
            nonzero_array(fields[4].value)?,
            nonzero_array(fields[5].value)?,
            nonzero_array(fields[6].value)?,
            nonzero_array(fields[7].value)?,
        ],
    })
}

fn encode_public_identity(
    body: &mut BodyEncoder,
    key_tag: u16,
    generation_tag: u16,
    value: PublicIdentity,
) -> Result<(), EncodeError> {
    require_nonzero(&value.public_key)?;
    require_nonzero_number(value.generation)?;
    body.field(key_tag, &value.public_key)?;
    body.field(generation_tag, &value.generation.to_be_bytes())
}

fn decode_public_identity(key: &[u8], generation: &[u8]) -> Result<PublicIdentity, DecodeError> {
    Ok(PublicIdentity {
        public_key: nonzero_array(key)?,
        generation: nonzero_u64(generation)?,
    })
}

fn encode_signature(body: &mut BodyEncoder, value: &SignatureResponse) -> Result<(), EncodeError> {
    encode_public_identity(body, 1, 2, value.identity)?;
    require_nonzero(&value.signed_digest)?;
    require_nonzero(&value.signature)?;
    body.field(3, &value.signed_digest)?;
    body.field(4, &value.signature)
}

fn decode_signature(fields: &[Field<'_>]) -> Result<SignatureResponse, DecodeError> {
    expect_tags(fields, &[1, 2, 3, 4])?;
    Ok(SignatureResponse {
        identity: decode_public_identity(fields[0].value, fields[1].value)?,
        signed_digest: nonzero_array(fields[2].value)?,
        signature: nonzero_array(fields[3].value)?,
    })
}

fn decode_payload(value: &[u8]) -> Result<CanonicalPayload, DecodeError> {
    CanonicalPayload::new(value.to_vec()).map_err(map_value_error)
}

const fn map_value_error(error: ValueError) -> DecodeError {
    match error {
        ValueError::Empty => DecodeError::ZeroField,
        ValueError::TooLarge => DecodeError::LimitExceeded,
        ValueError::InvalidText => DecodeError::InvalidText,
    }
}

fn encode_frame(
    kind: u8,
    operation: Operation,
    flags: u32,
    request_id: [u8; 16],
    body: Vec<u8>,
) -> Result<EncodedFrame, EncodeError> {
    if body.len() > MAX_BODY_SIZE {
        return Err(EncodeError::LimitExceeded);
    }
    let body_len = u32::try_from(body.len()).map_err(|_| EncodeError::LimitExceeded)?;
    let mut frame = Vec::with_capacity(HEADER_SIZE + body.len());
    frame.extend_from_slice(&MAGIC);
    frame.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    frame.push(kind);
    frame.push(operation as u8);
    frame.extend_from_slice(&flags.to_be_bytes());
    frame.extend_from_slice(&body_len.to_be_bytes());
    frame.extend_from_slice(&request_id);
    frame.extend_from_slice(&body);
    Ok(EncodedFrame(frame))
}

struct DecodedFrame<'a> {
    header: FrameHeader,
    kind: u8,
    flags: u32,
    body: &'a [u8],
}

fn decode_frame(frame: &[u8]) -> Result<DecodedFrame<'_>, DecodeError> {
    if frame.len() < HEADER_SIZE {
        return Err(DecodeError::FrameTooShort);
    }
    if frame[..4] != MAGIC {
        return Err(DecodeError::BadMagic);
    }
    if read_u16(&frame[4..6])? != PROTOCOL_VERSION {
        return Err(DecodeError::UnsupportedVersion);
    }
    let kind = frame[6];
    if kind != REQUEST_KIND && kind != RESPONSE_KIND {
        return Err(DecodeError::UnknownMessageKind);
    }
    let operation = Operation::try_from(frame[7]).map_err(|_| DecodeError::UnknownOperation)?;
    let flags = read_u32(&frame[8..12])?;
    let body_len =
        usize::try_from(read_u32(&frame[12..16])?).map_err(|_| DecodeError::WrongBodyLength)?;
    if body_len > MAX_BODY_SIZE {
        return Err(DecodeError::LimitExceeded);
    }
    let expected_len = HEADER_SIZE
        .checked_add(body_len)
        .ok_or(DecodeError::WrongBodyLength)?;
    if frame.len() < expected_len {
        return Err(DecodeError::WrongBodyLength);
    }
    if frame.len() > expected_len {
        return Err(DecodeError::TrailingBytes);
    }
    let request_id = nonzero_array(&frame[16..32])?;
    Ok(DecodedFrame {
        header: FrameHeader {
            operation,
            request_id,
        },
        kind,
        flags,
        body: &frame[HEADER_SIZE..],
    })
}

struct BodyEncoder {
    bytes: Vec<u8>,
    field_count: usize,
    last_tag: u16,
}

impl BodyEncoder {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            field_count: 0,
            last_tag: 0,
        }
    }

    fn field(&mut self, tag: u16, value: &[u8]) -> Result<(), EncodeError> {
        if tag == 0 || tag <= self.last_tag {
            return Err(EncodeError::OperationMismatch);
        }
        if self.field_count >= MAX_FIELD_COUNT || value.len() > MAX_FIELD_SIZE {
            return Err(EncodeError::LimitExceeded);
        }
        let length = u32::try_from(value.len()).map_err(|_| EncodeError::LimitExceeded)?;
        let next_len = self
            .bytes
            .len()
            .checked_add(FIELD_HEADER_SIZE)
            .and_then(|size| size.checked_add(value.len()))
            .ok_or(EncodeError::LimitExceeded)?;
        if next_len > MAX_BODY_SIZE {
            return Err(EncodeError::LimitExceeded);
        }
        self.bytes.extend_from_slice(&tag.to_be_bytes());
        self.bytes.extend_from_slice(&length.to_be_bytes());
        self.bytes.extend_from_slice(value);
        self.field_count += 1;
        self.last_tag = tag;
        Ok(())
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

#[derive(Clone, Copy)]
struct Field<'a> {
    tag: u16,
    value: &'a [u8],
}

fn decode_fields(body: &[u8]) -> Result<Vec<Field<'_>>, DecodeError> {
    let mut fields = Vec::new();
    let mut cursor = 0_usize;
    let mut last_tag = 0_u16;
    while cursor < body.len() {
        if fields.len() >= MAX_FIELD_COUNT {
            return Err(DecodeError::LimitExceeded);
        }
        let header_end = cursor
            .checked_add(FIELD_HEADER_SIZE)
            .ok_or(DecodeError::WrongBodyLength)?;
        if header_end > body.len() {
            return Err(DecodeError::WrongBodyLength);
        }
        let tag = read_u16(&body[cursor..cursor + 2])?;
        if tag == 0 {
            return Err(DecodeError::UnknownField);
        }
        if tag <= last_tag {
            return Err(DecodeError::NonCanonicalFieldOrder);
        }
        let length = usize::try_from(read_u32(&body[cursor + 2..header_end])?)
            .map_err(|_| DecodeError::WrongFieldLength)?;
        if length > MAX_FIELD_SIZE {
            return Err(DecodeError::LimitExceeded);
        }
        let value_end = header_end
            .checked_add(length)
            .ok_or(DecodeError::WrongFieldLength)?;
        if value_end > body.len() {
            return Err(DecodeError::WrongFieldLength);
        }
        fields.push(Field {
            tag,
            value: &body[header_end..value_end],
        });
        cursor = value_end;
        last_tag = tag;
    }
    Ok(fields)
}

fn expect_tags(fields: &[Field<'_>], expected: &[u16]) -> Result<(), DecodeError> {
    if fields.len() < expected.len() {
        return Err(DecodeError::MissingField);
    }
    if fields.len() > expected.len() {
        return Err(DecodeError::UnknownField);
    }
    for (field, tag) in fields.iter().zip(expected) {
        if field.tag != *tag {
            return Err(if field.tag > *tag {
                DecodeError::MissingField
            } else {
                DecodeError::UnknownField
            });
        }
    }
    Ok(())
}

fn read_u8(value: &[u8]) -> Result<u8, DecodeError> {
    if value.len() != 1 {
        return Err(DecodeError::WrongFieldLength);
    }
    Ok(value[0])
}

fn read_u16(value: &[u8]) -> Result<u16, DecodeError> {
    let bytes: [u8; 2] = value
        .try_into()
        .map_err(|_| DecodeError::WrongFieldLength)?;
    Ok(u16::from_be_bytes(bytes))
}

fn read_u32(value: &[u8]) -> Result<u32, DecodeError> {
    let bytes: [u8; 4] = value
        .try_into()
        .map_err(|_| DecodeError::WrongFieldLength)?;
    Ok(u32::from_be_bytes(bytes))
}

fn read_u64(value: &[u8]) -> Result<u64, DecodeError> {
    let bytes: [u8; 8] = value
        .try_into()
        .map_err(|_| DecodeError::WrongFieldLength)?;
    Ok(u64::from_be_bytes(bytes))
}

fn nonzero_u32(value: &[u8]) -> Result<u32, DecodeError> {
    let value = read_u32(value)?;
    if value == 0 {
        return Err(DecodeError::ZeroField);
    }
    Ok(value)
}

fn nonzero_u64(value: &[u8]) -> Result<u64, DecodeError> {
    let value = read_u64(value)?;
    if value == 0 {
        return Err(DecodeError::ZeroField);
    }
    Ok(value)
}

fn nonzero_array<const N: usize>(value: &[u8]) -> Result<[u8; N], DecodeError> {
    let bytes: [u8; N] = value
        .try_into()
        .map_err(|_| DecodeError::WrongFieldLength)?;
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(DecodeError::ZeroField);
    }
    Ok(bytes)
}

fn require_nonzero(value: &[u8]) -> Result<(), EncodeError> {
    if value.iter().all(|byte| *byte == 0) {
        return Err(EncodeError::ZeroField);
    }
    Ok(())
}

fn require_nonzero_number<T>(value: T) -> Result<(), EncodeError>
where
    T: PartialEq + From<u8>,
{
    if value == T::from(0) {
        return Err(EncodeError::ZeroField);
    }
    Ok(())
}
